"""The Hermes Agent plugin (integrations/hermes/) and its hooks (tracekit.integrations.hermes), against a stand-in for
the sequential path of Hermes's agent loop as hermes-agent v0.22.5 defines it (Hermes is not a test dependency), on a
real signer: the plugin is loaded and registered as Hermes loads it, and every tool call goes through its pre_tool_call
and post_tool_call as that path runs them."""
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
PAY = {"to": "acct-42"}


def tool(name, args):
    """A Hermes tool: always a JSON string, an error as {"error": ...} (tools/registry.py tool_error)."""
    ac.RAN.append(name)
    return json.dumps({"error": "boom"} if name == "fail" else {"tool": name, **args})


class Hermes:
    """One Hermes process's plugin hooks as hermes-agent v0.22.5 runs them on its agent loop's sequential path:
    - PluginContext.register_hook, and PluginDispatchMixin.invoke_hook (hermes_cli/plugins_dispatch.py): each callback on
      a worker thread in a copy of the context, waited on for plugins.hook_callback_timeout; for pre_tool_call a timeout
      or an exception is a block;
    - agent/tool_executor.py: _run_sequential_tool_execution_middleware runs the call on a worker thread and waits for
      it until the tool deadline (timeouts.tools.sequential_call, else concurrent_batch, else 420 s) or a /stop, then
      emits post_tool_call with status timeout or cancelled and leaves the worker running, which reports nothing more
      unless it is blocked; on the worker, _dispatch_authorized_once applies pre_tool_call's directives
      (_get_pre_tool_call_directive_details: the first block wins, modify merges over the arguments) and emits
      post_tool_call with status blocked for a blocked call, else runs the tool; _publish_sequential_result emits
      post_tool_call for a call that finished, with the arguments it ran with and the status read from its result."""

    def __init__(self, config):
        self.config, self.hooks, self.workers = config, {}, []

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

    def deadline(self):
        tools = self.config.get("timeouts", {}).get("tools", {})
        t = tools.get("sequential_call", tools.get("concurrent_batch", 420))
        return t if t > 0 else None

    def call(self, name, args, tool_call_id="call-1", session_id="s1", run=tool, stop=None):
        """One tool call, the tool run by `run`; `stop` (an Event) is the person's /stop. (what the model reads, whether
        the tool ran by then)."""
        ids = {"task_id": "", "session_id": session_id, "tool_call_id": tool_call_id, "turn_id": "turn-1",
               "api_request_id": "req-1", "middleware_trace": [], "telemetry_schema_version": 1}
        out, done = {}, threading.Event()

        def post(result, call_args, **outcome):
            self.invoke("post_tool_call", tool_name=name, args=call_args, result=result, **outcome, **ids)

        def dispatch():
            block, modified = None, None
            for r in self.invoke("pre_tool_call", tool_name=name, args=args, **ids):
                if r.get("action") == "modify" and isinstance(r.get("args"), dict) and r["args"]:
                    modified = {**(args if modified is None else modified), **r["args"]}
                elif r.get("action") == "block" and r.get("message"):
                    block = r["message"]
                    break
            out["args"] = args if modified is None else modified
            if block is not None:
                out["result"], out["ran"] = json.dumps({"error": block}), False
                post(out["result"], out["args"], status="blocked", error_type="plugin_block", error_message=block)
            else:
                out["result"], out["ran"] = run(name, out["args"]), True
            done.set()
        worker = threading.Thread(target=dispatch, daemon=True)
        worker.start()
        self.workers.append(worker)
        end = time.monotonic() + self.deadline() if self.deadline() else None
        while not done.wait(0.02):
            if stop is not None and stop.is_set():
                message = f"[Tool execution cancelled — {name} was abandoned: interrupt requested]"
                post(message, args, status="cancelled", error_type="tool_interrupted",
                     error_message="Tool execution cancelled: interrupt requested")
                return message, False
            if end is not None and time.monotonic() > end:
                message = f"Error executing tool '{name}': timed out after {self.deadline():.1f}s"
                post(message, args, status="timeout", error_type="tool_timeout", error_message=message)
                return message, False
        if out["ran"]:
            error = json.loads(out["result"]).get("error")
            post(out["result"], out["args"], duration_ms=1, status="error" if error else "ok",
                 error_type="tool_error" if error else None, error_message=error)
        return out["result"], out["ran"]

    def join(self):
        for w in self.workers:
            w.join(60)


def load(config, secret=lambda name, default=None: os.environ.get(name, default), secret_scope=True, coerce=None):
    """A Hermes with the plugin loaded as Hermes loads a directory plugin (hermes_plugins.<name>) and registered, with
    the Hermes modules it imports (agent.secret_scope, hermes_cli.config, and with `coerce` tools.arg_coercion)
    standing in."""
    stubs = {n: types.ModuleType(n) for n in ("agent", "agent.secret_scope", "hermes_cli", "hermes_cli.config")}
    if coerce is not None:
        stubs["tools"], stubs["tools.arg_coercion"] = types.ModuleType("tools"), types.ModuleType("tools.arg_coercion")
        stubs["tools.arg_coercion"].coerce_tool_args = coerce
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
        self.addCleanup(self.hermes.join)
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

    def held(self, tool_call_id="call-1", stop=None):
        """Calls pay in a thread of its own; (the approval id it waits for, the thread, its outcome)."""
        out = []
        t = threading.Thread(target=lambda: out.append(self.hermes.call("pay", PAY, tool_call_id, stop=stop)))
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
        for limit in ({"plugins": {"hook_callback_timeout": 2}}, {"timeouts": {"tools": {"sequential_call": 2}}}):
            with self.subTest(limit=limit):
                self.config.update(limit)
                with mock.patch.object(hermes, "MARGIN_S", 1.5):
                    seen, ran = self.hermes.call("pay", PAY, f"call-{len(self.events('approval.abandoned'))}")
                self.assertFalse(ran)
                self.assertIn("not approved: requested", json.loads(seen)["error"])   # not Hermes's timeout
                self.config.update({"plugins": {"hook_callback_timeout": 60}, "timeouts": {}})
        self.assertEqual(len(self.events("approval.abandoned")), 2)

    def test_a_hold_hermes_stopped_waiting_for_never_runs_even_once_approved(self):
        stop = threading.Event()
        with mock.patch.object(hermes, "POLL_S", 30):   # the approval, not the poll, ends the wait
            aid, t, out = self.held(stop=stop)
            stop.set()
            t.join(30)   # the loop moved on: post_tool_call says cancelled; the hook still waits
            self.client.approval_decide({"approval_id": aid, "decision": "approve"})
            self.hermes.join()
        self.assertEqual((out[0][1], ac.RAN), (False, []))
        self.assertEqual((len(self.events("approval.abandoned")), self.events("approval.consumed")), (1, []))

    def test_a_hold_hermes_stopped_waiting_for_is_withdrawn_at_once(self):
        stop = threading.Event()
        with mock.patch.object(hermes, "POLL_S", 0.2):
            aid, t, out = self.held(stop=stop)
            started = time.monotonic()
            stop.set()
            self.hermes.join()
        self.assertLess(time.monotonic() - started, 10)   # not the 55 s left of Hermes's limits
        self.assertEqual((ac.RAN, len(self.events("approval.abandoned"))), ([], 1))

    def test_a_call_hermes_gave_up_on_before_its_hook_ran_is_blocked_undecided(self):
        """A /stop while the call waited behind another call's hold: Hermes's post_tool_call comes first."""
        [post] = self.hermes.hooks["post_tool_call"]
        post(tool_name="echo", args={"text": "hi"}, result="[cancelled]", tool_call_id="call-9", session_id="s1",
             status="cancelled", error_message="Tool execution cancelled.")
        seen, ran = self.hermes.call("echo", {"text": "hi"}, "call-9")
        self.assertEqual((ran, ac.RAN), (False, []))
        self.assertEqual(json.loads(seen)["error"], f"Tool call blocked by Tracekit: {hermes.GONE}")
        self.assertEqual(self.events("policy.decision"), [])

    def test_a_call_hermes_gives_up_on_during_its_consume_does_not_run(self):
        [post] = self.hermes.hooks["post_tool_call"]
        consume = RunHandle.approval_consume

        def late(handle, tool_call_id, *a, **kw):
            post(tool_name="echo", args={"text": "hi"}, result="timed out", tool_call_id=tool_call_id, session_id="s1",
                 status="timeout", error_message="timed out")
            return consume(handle, tool_call_id, *a, **kw)
        with mock.patch.object(RunHandle, "approval_consume", late):
            seen, ran = self.hermes.call("echo", {"text": "hi"})
        self.assertEqual((ran, ac.RAN), (False, []))
        self.assertEqual(json.loads(seen)["error"], f"Tool call blocked by Tracekit: {hermes.GONE}")
        self.assertEqual(self.completed, [("call-1", "error", f"not run: {hermes.GONE}")])

    def test_the_hold_lasts_as_long_as_hermes_lets_the_hook_run(self):
        def limit(hook=None, sequential=None, batch=None, env=None):
            config = {"plugins": {} if hook is None else {"hook_callback_timeout": hook},
                      "timeouts": {"tools": {k: v for k, v in (("sequential_call", sequential),
                                                               ("concurrent_batch", batch)) if v is not None}}}
            return hermes.hook_timeout_s(config, {} if env is None else {"HERMES_CONCURRENT_TOOL_TIMEOUT_S": env})
        self.assertEqual([hermes.hook_timeout_s(c, {}) for c in (
            None, {}, {"plugins": None, "timeouts": None}, {"timeouts": {"tools": []}})], [30, 30, 30, 30])
        self.assertEqual([
            limit("soon"), limit(-1), limit(True), limit(120), limit(600), limit(900),   # the hook's own limit
            limit(600, 600, 600), limit(600, batch=500), limit(600, 500, 600), limit(600, env="300"),
            limit(600, batch=0, sequential=450), limit(0), limit(0, batch=0), limit(600, "x", 0),
            limit(600, env="later")], [
            30, 30, 1, 120, 420, 420,
            600, 500, 500, 300,
            450, 420, 0, 600,
            420])

    def test_a_signer_that_cannot_be_reached_blocks_the_call(self):
        self.hermes.call("echo", {"text": "hi"})   # its session's run is registered
        os.environ["TRACEKIT_SIGNER"] = os.path.join(ac.tmpdir(self), "none.sock")
        seen, ran = load(self.config).call("echo", {"text": "hi"})   # none can be: blocked, whatever the fail mode
        self.assertFalse(ran)
        self.assertIn("Tracekit could not decide it (SignerUnavailable", json.loads(seen)["error"])
        with mock.patch.object(Client, "call", side_effect=SignerUnavailable("down")), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            seen, ran = self.hermes.call("echo", {"text": "hi"}, "call-2")
            self.assertFalse(ran)
            self.assertIn("refused by Tracekit: signer unavailable", json.loads(seen)["error"])
            self.made[0].registered["fail_modes"] = {"default": "open"}   # as the signer's policy may say
            self.assertTrue(self.hermes.call("echo", {"text": "hi"}, "call-3")[1])   # runs, unrecorded
        self.assertEqual([c[0] for c in self.completed], ["call-1"])

    def test_a_failed_tool_is_recorded_as_an_error(self):
        self.assertTrue(self.hermes.call("fail", {"why": "x"})[1])
        [r] = self.events("tool.result")
        self.assertFalse(r["ok"])
        self.assertEqual(self.completed, [("call-1", "error", "error: boom")])

    def test_a_call_hermes_times_out_or_stops_while_it_runs_is_recorded_as_an_error(self):
        started, release, stop = threading.Event(), threading.Event(), threading.Event()

        def slow(name, args):
            started.set()
            release.wait(30)
            return tool(name, args)
        self.config["timeouts"] = {"tools": {"sequential_call": 2}}   # the decision takes well under that
        self.assertFalse(self.hermes.call("echo", {"text": "a"}, "call-1", run=slow)[1])
        del self.config["timeouts"]
        started.clear()
        t = threading.Thread(target=self.hermes.call, args=("echo", {"text": "b"}, "call-2", "s1", slow, stop))
        t.start()
        started.wait(30)
        stop.set()
        t.join(30)
        release.set()
        self.hermes.join()
        self.assertEqual([(c[0], c[1], c[2].split(":")[0]) for c in self.completed],
                         [("call-1", "error", "timeout"), ("call-2", "error", "cancelled")])
        self.assertEqual([r["ok"] for r in self.events("tool.result")], [False, False])

    def test_a_refused_consume_of_an_allowed_call_is_recorded_as_not_run(self):
        refused = {"ok": False, "rule_ids": ["TK-HOLD"], "reason": "held by an incident"}
        with mock.patch.object(RunHandle, "approval_consume", return_value=refused):
            seen, ran = self.hermes.call("echo", {"text": "hi"})
        self.assertEqual((ran, ac.RAN), (False, []))
        self.assertIn("held by an incident", json.loads(seen)["error"])
        self.assertEqual(self.completed, [("call-1", "error", "not run: held by an incident")])
        self.assertEqual([r["ok"] for r in self.events("tool.result")], [False])

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

    def test_a_call_hermes_repaired_the_argument_types_of_is_recorded_as_run(self):
        """A concurrent batch's call runs with Hermes's repair of the model's argument types, which its post_tool_call
        reports; its pre_tool_call saw the model's own."""
        h = load(self.config, coerce=lambda tool, args: {k: int(v) if str(v).isdigit() else v for k, v in args.items()})
        ids = {"tool_call_id": "call-1", "session_id": "s1"}
        self.assertEqual(h.invoke("pre_tool_call", tool_name="search", args={"n": "5"}, **ids), [])
        h.invoke("post_tool_call", tool_name="search", args={"n": 5}, result="{}", status="ok", **ids)
        self.assertEqual(self.completed, [("call-1", "ok", None)])

    def test_a_call_hermes_blocked_once_its_hook_outlived_the_callback_timeout_is_recorded_as_not_run(self):
        decide = RunHandle.decide

        def slow(*a, **k):
            time.sleep(1.5)
            return decide(*a, **k)
        self.config["plugins"]["hook_callback_timeout"] = 0.5
        with mock.patch.object(RunHandle, "decide", slow):
            seen, ran = self.hermes.call("echo", {"text": "hi"})
            self.assertEqual((ran, json.loads(seen)["error"]), (False, TIMED_OUT))
            for _ in range(250):   # the hook goes on deciding after Hermes's block
                if self.completed:
                    break
                time.sleep(0.02)
        self.assertEqual((ac.RAN, self.completed), ([], [("call-1", "error", f"not run: {hermes.GONE}")]))

    def test_a_hold_whose_wait_fails_is_withdrawn(self):
        call = RunHandle.call

        def failing(handle, method, **fields):
            if method == "approval_wait":
                raise ConnectionError("the signer went away")
            return call(handle, method, **fields)
        with mock.patch.object(RunHandle, "call", failing):
            seen, ran = self.hermes.call("pay", PAY)
        self.assertFalse(ran)
        self.assertIn("could not decide it (ConnectionError", json.loads(seen)["error"])
        self.assertEqual(len(self.events("approval.abandoned")), 1)

    def test_a_call_without_a_tool_call_id_is_blocked(self):
        """execute_code's scripts call tools with no tool_call_id (tools/code_execution_rpc.py)."""
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
        asked = []

        def secret(name, default=None):
            asked.append((name, default))
            return f"secret:{name}"
        with mock.patch.object(hermes, "Client", side_effect=RuntimeError("stop")) as made:
            seen, _ = load(self.config, secret=secret).call("echo", {"text": "hi"})
        made.assert_called_once_with(token="secret:TRACEKIT_SIGNER_TOKEN")
        self.assertEqual(asked, [("TRACEKIT_SIGNER_TOKEN", "")])   # "": none, never the process environment's
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
