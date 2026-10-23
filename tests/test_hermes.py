"""The Hermes Agent plugin (integrations/hermes/) and its hooks (tracekit.integrations.hermes), against a stand-in for
Hermes's plugin hook dispatch as hermes-agent v0.22.5 defines it (Hermes is not a test dependency), on a real signer:
the plugin is loaded and registered as Hermes loads it, and every tool call goes through its pre_tool_call and
post_tool_call as Hermes runs them."""
import contextvars
import importlib.util
import json
import os
import sys
import threading
import time
import types
import unittest
import warnings
from unittest import mock

import yaml

import adapter_contract as ac
from tracekit.integrations import hermes
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable
from tracekit.signer.service import SignerService

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "integrations", "hermes")
HERMES_VERSION, HERMES_COMMIT = "0.22.5", "bf0203a794a07aac3ff764972ab9087baa4e4f4e"   # what the stand-in follows
TIMED_OUT = "pre_tool_call plugin callback timed out or is still running"   # hermes_cli/plugins_dispatch.py


def tool(name, args):
    """A Hermes tool: always a JSON string, an error as {"error": ...} (tools/registry.py tool_error)."""
    ac.RAN.append(name)
    return json.dumps({"error": "boom"} if name == "fail" else {"tool": name, **args})


class Hermes:
    """One Hermes process's plugin hooks as hermes-agent v0.22.5 runs them: PluginContext.register_hook;
    PluginDispatchMixin.invoke_hook (each callback on a worker thread in a copy of the context, waited on for
    plugins.hook_callback_timeout; for pre_tool_call a timeout or an exception is a block); the directives of
    _get_pre_tool_call_directive_details (the first block wins, modify merges over the arguments); and
    model_tools.handle_function_call (post_tool_call after the tool, or with status "blocked" instead of it)."""

    def __init__(self, config):
        self.config, self.hooks = config, {}

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)

    def invoke(self, name, **payload):
        timeout, results = float(self.config["plugins"]["hook_callback_timeout"]), []
        for cb in self.hooks.get(name, []):
            out, done = {}, threading.Event()

            def runner(cb=cb, out=out, done=done):
                try:
                    out["value"] = cb(**payload)
                except BaseException as e:
                    out["exc"] = e
                finally:
                    done.set()
            threading.Thread(target=contextvars.copy_context().run, args=(runner,), daemon=True).start()
            if not done.wait(timeout or None):
                if name == "pre_tool_call":
                    results.append({"action": "block", "message": TIMED_OUT})
                continue
            if "exc" in out:
                if name == "pre_tool_call":
                    e = out["exc"]
                    results.append({"action": "block", "message": f"pre_tool_call plugin callback {cb.__name__} "
                                                                  f"raised {type(e).__name__}: {str(e)[:200]}"})
            elif out["value"] is not None:
                results.append(out["value"])
        return results

    def call(self, name, args, tool_call_id="call-1", session_id="s1", run=tool):
        """One tool call, the tool run by `run`: (what the model reads, whether the tool ran)."""
        ids = {"task_id": "", "session_id": session_id, "tool_call_id": tool_call_id, "turn_id": "turn-1",
               "api_request_id": "req-1", "middleware_trace": [], "telemetry_schema_version": 1}
        block, modified = None, None
        for r in self.invoke("pre_tool_call", tool_name=name, args=args, **ids):
            if r.get("action") == "modify" and isinstance(r.get("args"), dict) and r["args"]:
                modified = {**(args if modified is None else modified), **r["args"]}
            elif r.get("action") == "block" and r.get("message"):
                block = r["message"]
                break
        args = args if modified is None else modified
        if block is not None:
            result = json.dumps({"error": block})
            self.invoke("post_tool_call", tool_name=name, args=args, result=result, duration_ms=0, status="blocked",
                        error_type="plugin_block", error_message=block, **ids)
            return result, False
        result = run(name, args)
        error = json.loads(result).get("error")
        self.invoke("post_tool_call", tool_name=name, args=args, result=result, duration_ms=1,
                    status="error" if error else "ok", error_type="tool_error" if error else None, error_message=error,
                    **ids)
        return result, True


def load(config, secret=lambda name, default=None: None, secret_scope=True):
    """A Hermes with the plugin loaded as Hermes loads a directory plugin (hermes_plugins.<name>) and registered, with
    the public Hermes modules it imports (agent.secret_scope, hermes_cli.config) standing in."""
    stubs = {n: types.ModuleType(n) for n in ("agent", "agent.secret_scope", "hermes_cli", "hermes_cli.config")}
    if secret_scope:
        stubs["agent.secret_scope"].get_secret = secret
    stubs["hermes_cli.config"].load_config_readonly = lambda: config
    h = Hermes(config)
    with mock.patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location("hermes_plugins.tracekit", os.path.join(PLUGIN, "__init__.py"),
                                                      submodule_search_locations=[PLUGIN])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.register(h)
    return h


class Plugin(unittest.TestCase):
    def setUp(self):
        ac.RAN.clear()
        self.service = s = SignerService(ac.tmpdir(self), policy=Engine({
            "ask": [{"id": "R-PAY", "tool": "^pay$", "pattern": "^", "approval": {"executor": "t2"}}],
            "deny": [{"id": "R-WIPE", "tool": "^wipe$", "pattern": "^"}], "untrusted": ["echo"]}))
        self.addCleanup(s.close)
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, lambda identity, frame: s.handle_frame(identity,
                                                                                               ac._approved(self, frame)))
        self.client = Client()
        self.addCleanup(self.client.close)
        self.config = {"plugins": {"hook_callback_timeout": 60}}
        self.hermes = load(self.config)
        self.made, self.completed = [], []   # each run the plugin registered; (tool_call_id, status, error) completed
        run, complete = Client.run, RunHandle.complete

        def registering(client, agent, **fields):
            self.made.append(run(client, agent, **fields))
            return self.made[-1]

        def completing(handle, tool_call_id, status="ok", **fields):
            self.completed.append((tool_call_id, status, fields.get("error")))
            return complete(handle, tool_call_id, status, **fields)
        for patch in (mock.patch.object(Client, "run", registering),
                      mock.patch.object(RunHandle, "complete", completing)):
            patch.start()
            self.addCleanup(patch.stop)

    def runs(self):
        return [r.run_id for r in self.made]

    def events(self, typ):
        return [r["event"]["data"] for run in self.runs() for r in self.service.log.storage.iter_run("default", run)
                if r["event"]["type"] == typ]

    def held(self, tool_call_id="call-1"):
        """Calls pay in a thread of its own; (the approval id it waits for, the thread, its outcome)."""
        out = []
        t = threading.Thread(target=lambda: out.append(self.hermes.call("pay", {"to": "acct-42"}, tool_call_id)))
        t.start()
        for _ in range(500):
            waiting = [a for a in self.client.approval_list({"state": "requested"})["approvals"]
                       if a["tool_call_id"] == tool_call_id]
            if waiting:
                return waiting[0]["approval_id"], t, out
            time.sleep(0.02)
        self.fail("no approval was requested")

    def test_an_allowed_call_runs_and_is_recorded(self):
        seen, ran = self.hermes.call("echo", {"text": "hi"})
        self.assertEqual((ran, json.loads(seen)), (True, {"tool": "echo", "text": "hi"}))
        [d] = self.events("policy.decision")
        [r] = self.events("tool.result")
        self.assertEqual((d["decision"], d["tool_use_id"], r["tool_use_id"], r["decision_id"], r["ok"]),
                         ("allow", "call-1", "call-1", d["decision_id"], True))
        self.assertEqual(len(self.runs()), 1)

    def test_an_untrusted_tools_result_goes_to_the_signer_for_the_provenance_index(self):
        self.hermes.call("echo", {"text": "mail audit@vendor.example"})
        [run] = self.runs()
        prov = self.service.log.runs[("default", run)]["prov"]
        self.assertEqual(prov["state"], "complete", prov.get("reason"))   # partial when only a digest came
        self.assertIn(self.service._key("email", "audit@vendor.example"), prov["index"])

    def test_a_denied_call_is_blocked_and_the_model_reads_why(self):
        seen, ran = self.hermes.call("wipe", {"path": "/"})
        self.assertEqual((ran, ac.RAN), (False, []))
        self.assertEqual(json.loads(seen)["error"], "Tool call blocked by Tracekit policy: R-WIPE")
        self.assertEqual(self.events("tool.result"), [])
        self.assertEqual(self.hermes.call("echo", {"text": "next"}, "call-2")[1], True)

    def test_a_held_call_waits_for_a_person_and_runs_once_approved(self):
        aid, t, out = self.held()
        self.assertEqual(ac.RAN, [])
        self.client.approval_decide({"approval_id": aid, "decision": "approve"})
        t.join(30)
        self.assertEqual((out[0][1], ac.RAN), (True, ["pay"]))
        self.assertEqual(len(self.events("approval.consumed")), 1)
        [r] = self.events("tool.result")
        self.assertTrue(r["ok"])

    def test_a_held_call_a_person_rejects_is_blocked(self):
        aid, t, out = self.held()
        self.client.approval_decide({"approval_id": aid, "decision": "reject"})
        t.join(30)
        self.assertEqual((out[0][1], ac.RAN), (False, []))
        self.assertIn("held by Tracekit policy (R-PAY) and not approved: rejected", json.loads(out[0][0])["error"])
        self.assertEqual(self.events("tool.result"), [])

    def test_a_t2_approval_of_other_arguments_blocks_the_call(self):
        """Hermes's `modify` merges over the arguments, so the hook can't run the signer's copy exactly."""
        self.approved = {"to": "acct-42", "cents": 7}   # what the signer decides and approves (adapter_contract)
        aid, t, out = self.held()
        self.client.approval_decide({"approval_id": aid, "decision": "approve"})
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            t.join(30)
        self.assertEqual((out[0][1], ac.RAN), (False, []))
        self.assertIn("the arguments the signer approved are not the call's", json.loads(out[0][0])["error"])

    def test_an_unanswered_hold_is_blocked_and_withdrawn_before_hermes_gives_up(self):
        self.config["plugins"]["hook_callback_timeout"] = 2
        with mock.patch.object(hermes, "MARGIN_S", 1.5):
            seen, ran = self.hermes.call("pay", {"to": "acct-42"})
        self.assertFalse(ran)
        self.assertIn("not approved: requested", json.loads(seen)["error"])   # Tracekit's answer, not TIMED_OUT
        self.assertEqual(len(self.events("approval.abandoned")), 1)

    def test_the_hold_lasts_as_long_as_hermes_lets_the_hook_run(self):
        self.assertEqual([hermes.hook_timeout_s(c) for c in (
            None, {}, {"plugins": None}, {"plugins": {"hook_callback_timeout": None}},
            {"plugins": {"hook_callback_timeout": "soon"}}, {"plugins": {"hook_callback_timeout": -1}},
            {"plugins": {"hook_callback_timeout": 0}}, {"plugins": {"hook_callback_timeout": 120}},
            {"plugins": {"hook_callback_timeout": 900}})], [30, 30, 30, 30, 30, 30, 0, 120, 600])

    def test_a_signer_that_cannot_be_reached_blocks_the_call(self):
        self.hermes.call("echo", {"text": "hi"})   # its session's run is registered
        os.environ["TRACEKIT_SIGNER"] = os.path.join(ac.tmpdir(self), "none.sock")
        seen, ran = load(self.config).call("echo", {"text": "hi"})   # none can be
        self.assertFalse(ran)
        self.assertIn("Tracekit could not decide it (SignerUnavailable", json.loads(seen)["error"])
        with mock.patch.object(Client, "call", side_effect=SignerUnavailable("down")), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            seen, ran = self.hermes.call("echo", {"text": "hi"}, "call-2")
        self.assertFalse(ran)
        self.assertIn("refused by Tracekit: signer unavailable", json.loads(seen)["error"])

    def test_a_failed_tool_is_recorded_as_an_error(self):
        self.assertTrue(self.hermes.call("fail", {"why": "x"})[1])
        [r] = self.events("tool.result")
        self.assertFalse(r["ok"])
        self.assertEqual(self.completed, [("call-1", "error", "boom")])

    def test_a_call_another_plugin_blocks_after_tracekit_allowed_it_is_recorded_as_not_run(self):
        self.hermes.register_hook("pre_tool_call", lambda **_: {"action": "block", "message": "not today"})
        self.assertFalse(self.hermes.call("echo", {"text": "hi"})[1])
        [r] = self.events("tool.result")
        self.assertFalse(r["ok"])
        self.assertEqual(self.completed, [("call-1", "error", "not run: not today")])

    def test_arguments_another_plugin_changes_are_recorded_as_changed(self):
        def modify(**_):
            return {"action": "modify", "args": {"text": "other"}}

        def edit(args, **_):   # in place: Hermes hands every pre_tool_call the same dict
            args["text"] = "other"
        for i, other in enumerate((modify, edit)):
            h = load(self.config)
            h.register_hook("pre_tool_call", other)
            self.assertTrue(h.call("echo", {"text": "hi"}, f"call-{i}")[1])
        self.assertEqual([r["ok"] for r in self.events("tool.result")], [False, False])
        self.assertEqual(self.completed, [(f"call-{i}", "error", "the call's arguments changed after the decision")
                                          for i in range(2)])

    def test_a_call_without_a_tool_call_id_is_blocked(self):
        seen, ran = self.hermes.call("echo", {"text": "hi"}, tool_call_id="")
        self.assertFalse(ran)
        self.assertIn("no tool_call_id", json.loads(seen)["error"])

    def test_each_session_is_a_run_and_a_run_the_signer_closed_is_replaced(self):
        self.hermes.call("echo", {"text": "a"}, "call-1", session_id="s1")
        self.hermes.call("echo", {"text": "b"}, "call-2", session_id="s2")
        self.made[0].close()   # as the signer closes a run left idle
        self.assertTrue(self.hermes.call("echo", {"text": "c"}, "call-3", session_id="s1")[1])
        self.assertEqual(len(self.made), 3)
        self.assertEqual([len([e for e in self.service.log.storage.iter_run("default", r)
                               if e["event"]["type"] == "tool.result"]) for r in self.runs()], [1, 1, 1])

    def test_two_sessions_calls_under_one_id_are_recorded_apart(self):
        """A provider may number its calls per response: one session's call_0 doesn't complete another's."""
        started, release = threading.Event(), threading.Event()

        def slow(name, args):
            started.set()
            release.wait(30)
            return tool(name, args)
        t = threading.Thread(target=self.hermes.call, args=("echo", {"text": "slow"}, "call_0", "s1", slow))
        t.start()
        started.wait(30)
        self.hermes.call("echo", {"text": "fast"}, "call_0", session_id="s2")
        release.set()
        t.join(30)
        self.assertEqual([r["ok"] for r in self.events("tool.result")], [True, True])

    def test_concurrent_first_calls_of_a_session_share_one_run(self):
        threads = [threading.Thread(target=self.hermes.call, args=("echo", {"text": str(i)}, f"call-{i}"))
                   for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(len(self.runs()), 1)
        self.assertEqual(len(self.events("tool.result")), 6)

    def test_the_signer_token_comes_from_hermess_secret_scope(self):
        with mock.patch.object(hermes, "Client", side_effect=RuntimeError("stop")) as made:
            seen, _ = load(self.config, secret=lambda name, default=None: f"secret:{name}").call("echo", {"text": "hi"})
        made.assert_called_once_with(token="secret:TRACEKIT_SIGNER_TOKEN")
        self.assertIn("could not decide it (RuntimeError: stop)", json.loads(seen)["error"])


class Package(unittest.TestCase):
    def manifest(self):
        with open(os.path.join(PLUGIN, "plugin.yaml"), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_the_manifest_declares_what_register_registers_and_nothing_else(self):
        """`hermes plugins validate` fails a plugin whose registrations differ from what plugin.yaml declares."""
        m, h = self.manifest(), load({"plugins": {"hook_callback_timeout": 30}})
        self.assertTrue(all(m.get(k) for k in ("name", "version", "description")))
        self.assertEqual(sorted(h.hooks), sorted(m["provides_hooks"]), ["post_tool_call", "pre_tool_call"])
        self.assertFalse(m.get("provides_tools") or m.get("provides_middleware") or m.get("capabilities"))
        self.assertEqual(m["requires_hermes"], f">={HERMES_VERSION}")
        self.assertEqual([(e["name"], e["secret"]) for e in m["requires_env"]], [("TRACEKIT_SIGNER_TOKEN", True)])
        [dep] = m["python_dependencies"]
        self.assertRegex(dep, r"^tracekit-ai>=[\d.]+,<[\d.]+$")   # a floor and an upper bound (catalog rule 10)

    def test_a_plugin_that_cannot_load_tracekit_blocks_every_call(self):
        h = load({"plugins": {"hook_callback_timeout": 30}}, secret_scope=False)
        seen, ran = h.call("echo", {"text": "hi"})
        self.assertFalse(ran)
        self.assertIn("the Tracekit plugin can't load (ImportError", json.loads(seen)["error"])

    def test_the_docs_name_the_hermes_release_the_stand_in_follows(self):
        for path in (os.path.join(ROOT, "docs", "integrations", "hermes.md"), hermes.__file__):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertIn(HERMES_VERSION, text, path)
            self.assertIn(HERMES_COMMIT, text, path)


if __name__ == "__main__":
    unittest.main()
