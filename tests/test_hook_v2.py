"""The v2 Claude Code hook (tracekit/integrations/claude_code.py) against the real dev signer, auto-spawned in a temp
runtime dir, invoked through the command `tracekit init --v2` wires."""
import contextlib
import hmac
import io
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from tracekit import cli, install, privacy
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.format import checkpoint
from tracekit.format.checkpoint import ED25519
from tracekit.integrations import claude_code
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable
from tracekit.signer import service
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = install._hook_command(install.V2_HOOK)


@unittest.skipUnless(os.name == "posix", "POSIX paths, signals and shells; DevSignerOverTcp (test_signer_dev.py) runs everywhere")
class HookV2(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": os.path.join(self.dir, "run"),
                                           "TRACEKIT_DEV_IDLE": "60", "PYTHONPATH": ROOT,
                                           "HOME": os.path.join(self.dir, "home"),
                                           "XDG_DATA_HOME": os.path.join(self.dir, "data")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("TRACEKIT_SIGNER", "TRACEKIT_FAIL_CLOSED", "TRACEKIT_POLICY"):
            os.environ.pop(k, None)
        self.addCleanup(autospawn.down)
        # the hook runs from a cwd with a decoy `tracekit` package: `python -I` must not import it
        self.cwd = os.path.join(self.dir, "cwd")
        os.makedirs(os.path.join(self.cwd, "tracekit"))
        with open(os.path.join(self.cwd, "tracekit", "__init__.py"), "w") as f:
            f.write("raise SystemExit(7)\n")

    def hook(self, event, sid="s1", wait=True, **fields):
        payload = {"hook_event_name": event, **({"session_id": sid} if sid else {}), **fields}
        proc = subprocess.Popen(HOOK, shell=True, cwd=self.cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        proc.stdin.write(json.dumps(payload))
        proc.stdin.close()
        if not wait:
            return proc
        err = proc.stderr.read()
        proc.wait(60)
        proc.stdout.close()
        proc.stderr.close()
        return proc.returncode, err

    def pre(self, command, tid="t1", **kw):
        return self.hook("PreToolUse", tool_name="Bash", tool_input={"command": command}, tool_use_id=tid, **kw)

    def post(self, command, tid="t1", event="PostToolUse"):
        return self.hook(event, tool_name="Bash", tool_input={"command": command}, tool_use_id=tid,
                         tool_response={"stdout": "ok"})

    def run_handle(self, sid="s1"):
        with open(claude_code._state(sid)) as f:
            return RunHandle(Client(), json.load(f))

    def events(self, sid="s1"):
        return self.run_handle(sid).call("read")["events"]

    def approve_next(self, decision, command):
        proc = self.pre(command, wait=False)
        line = proc.stderr.readline()
        self.assertIn("waiting for approval", line)
        aid = line.split()[4]
        Client().approval_decide({"approval_id": aid, "decision": decision})
        err = proc.stderr.read()
        proc.wait(60)
        proc.stdout.close()
        proc.stderr.close()
        return proc.returncode, err

    def test_allow_then_post_completes_with_the_binding(self):
        self.assertEqual(self.hook("SessionStart")[0], 0)
        self.assertEqual(self.pre("ls"), (0, ""))
        self.assertEqual(self.post("ls"), (0, ""))
        evs = self.events()
        self.assertEqual([e["type"] for e in evs], ["run.registered", "policy.decision", "tool.result"])
        self.assertEqual(evs[0]["data"]["agent"]["name"], "claude-code")
        self.assertEqual(evs[1]["data"]["decision"], "allow")
        self.assertEqual(evs[2]["data"]["decision_id"], evs[1]["data"]["decision_id"])
        self.assertFalse(os.path.exists(claude_code._state("s1", "t1")))

    def test_first_event_registers_and_failure_completes_as_error(self):
        self.assertEqual(self.pre("ls"), (0, ""))
        self.assertEqual(self.post("ls", event="PostToolUseFailure"), (0, ""))
        evs = self.events()
        self.assertEqual([e["type"] for e in evs], ["run.registered", "policy.decision", "tool.result"])
        self.assertFalse(evs[2]["data"]["ok"])

    def test_output_goes_through_privacy_per_content_capture(self):
        resp = {"stdout": "API_KEY=abc123def456ghi\nCOLOR=blue"}
        policy = os.path.join(self.dir, "full.yaml")
        with open(policy, "w") as f:
            f.write("extends: default\nversion: full-capture\ncontent_capture: full\n")
        for tid, cc in (("t1", "hashed"), ("t2", "full")):
            if cc == "full":
                os.environ["TRACEKIT_POLICY"] = policy
            self.pre("cat .env", tid=tid)
            self.assertEqual(self.hook("PostToolUse", tool_name="Bash", tool_input={"command": "cat .env"},
                                       tool_use_id=tid, tool_response=resp), (0, ""))
            data = self.events()[-1]["data"]
            with open(os.path.join(service.dev_data_dir(), "store", "records.jsonl"), "rb") as f:
                [seq] = [e["seq"] for e in (json.loads(line)["event"] for line in f)
                         if e["data"].get("decision_id") == data["decision_id"] and e["type"] == "tool.result"]
            salt = bytes.fromhex(service.reveal(service.dev_data_dir(), seq)["salt"])
            digest = event_hash({"result": privacy.content(resp, cc, True)})   # the hook redacted it all already
            self.assertEqual(data["output"]["hash"], "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest())
            self.assertEqual(data["redaction"]["count"], 0, cc)

    def test_deny(self):
        code, err = self.pre("pkill tracekitd")
        self.assertEqual(code, 2)
        # the reason, not only the rule id: it tells the model why (the v1 hook did; the v2 one printed ids only)
        self.assertIn("TK-D007: touching Tracekit's own files or signer", err)
        self.assertEqual(self.events()[-1]["data"]["decision"], "deny")
        self.assertIn("no decision", self.post("pkill tracekitd")[1])   # nothing to complete

    def test_ask_approved_runs_and_completes(self):
        self.assertEqual(self.approve_next("approve", 'echo "open')[0], 0)
        self.assertEqual(self.post('echo "open'), (0, ""))
        types = [e["type"] for e in self.events()]
        self.assertEqual(types[-4:], ["approval.request", "approval", "approval.consumed", "tool.result"])

    def test_ask_rejected_blocks(self):
        code, err = self.approve_next("reject", 'echo "open')
        self.assertEqual(code, 2)
        self.assertIn("TK-SHELL-PARSE", err)
        self.assertIn("rejected", err)

    def test_the_waiting_line_names_the_commands_that_answer_the_call(self):
        """`tracekit approve ID`, the v1 command, is what a person guessed (#420). The line names the v2 ones, with
        --signer when the hook's signer is a named one, quoted: pasted into the person's shell (here, for the named
        one, a shell whose own default is another signer), each answers the call."""
        named_sock = os.path.join(self.dir, "a b;x.sock")
        for tid, decision, state, code in (("t1", "approve", "approved", 0), ("t2", "reject", "rejected", 2),
                                           ("t3", "approve", "approved", 0)):
            named, person = "", None
            if tid == "t3":   # the dev signer, now running, named as `tracekit init --remote --v2` names a signer
                os.symlink(os.path.join(self.dir, "run", autospawn.SOCK), named_sock)
                os.environ["TRACEKIT_SIGNER"] = named_sock
                named, person = f" --signer '{named_sock}'", dict(os.environ, TRACEKIT_SIGNER=self.dir + "/x.sock")
            proc = self.pre('echo "open', tid=tid, wait=False)
            line = proc.stderr.readline()
            aid = line.split()[4]
            self.assertIn(f"; a person approves it from another terminal with `tracekit approvals{named} approve {aid}` "
                          f"or rejects it with `tracekit approvals{named} reject {aid}`", line)
            cmd = dict(zip(("approve", "reject"), re.findall(r"`tracekit ([^`]+)`", line)))[decision]
            out = subprocess.run(f"{shlex.quote(sys.executable)} -m tracekit {cmd}", shell=True, capture_output=True,
                                 text=True, timeout=60, env=person)
            self.assertEqual((out.returncode, out.stdout.strip()), (0, f"{state}: {aid} (self-approved: dev mode only)"),
                             out.stderr)
            err = proc.stderr.read()
            proc.wait(60)
            proc.stdout.close()
            proc.stderr.close()
            self.assertEqual(proc.returncode, code, err)

    def test_a_prompt_is_recorded_and_its_constraints_hold_the_call_that_breaks_them(self):
        """UserPromptSubmit adds what the prompt keeps away as a live constraint, then records the harness's copy of
        the prompt: the edit of that file waits for a person, who is told why; the agent reads it on stderr; others
        run."""
        prompt = "Fix src/pager.py. Don't touch billing.py."
        self.assertEqual(self.hook("UserPromptSubmit", prompt=prompt), (0, ""))
        evs = self.events()
        self.assertEqual([e["type"] for e in evs], ["run.registered", "constraint.added", "input.observed"])
        self.assertEqual((evs[2]["data"]["source"], evs[2]["data"]["trust"]), ("claude-code:UserPromptSubmit", "trusted"))
        self.assertEqual(evs[1]["data"]["kind"], "keep_away")
        self.assertNotIn("billing", json.dumps(evs))
        edit = {"file_path": os.path.join(self.dir, "billing.py"), "old_string": "a", "new_string": "b"}
        proc = self.hook("PreToolUse", tool_name="Edit", tool_input=edit, tool_use_id="t1", wait=False)
        line = proc.stderr.readline()
        self.assertIn("(TK-CONSTRAINT): the person's request in this run said not to modify billing.py; ask the "
                      "person", line)
        self.assertEqual(line.count("TK-CONSTRAINT"), 1, line)
        Client().approval_decide({"approval_id": line.split()[4], "decision": "reject"})
        err = proc.stderr.read()
        proc.wait(60)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("said not to modify billing.py", err)
        other = dict(edit, file_path=os.path.join(self.dir, "pager.py"))
        self.assertEqual(self.hook("PreToolUse", tool_name="Edit", tool_input=other, tool_use_id="t2"), (0, ""))

    def held_edit(self, name, tid):
        """A PreToolUse Edit of `name`, held: -> the line the agent reads; the person rejects it."""
        edit = {"file_path": os.path.join(self.dir, name), "old_string": "a", "new_string": "b"}
        proc = self.hook("PreToolUse", tool_name="Edit", tool_input=edit, tool_use_id=tid, wait=False)
        line = proc.stderr.readline()
        if "waiting for approval" in line:
            Client().approval_decide({"approval_id": line.split()[4], "decision": "reject"})
        proc.stderr.read()
        proc.wait(60)
        proc.stdout.close()
        proc.stderr.close()
        return line

    def test_a_later_run_of_the_session_holds_the_earlier_prompts_constraints(self):
        """After the signer closes a session's run (idle), the session's next event registers a new run: it gets every
        constraint the session's prompts stated, once each, and an equal one stated again adds nothing."""
        for prompt in ("Don't touch billing.py.", "Never push. Don't touch billing.py."):
            self.assertEqual(self.hook("UserPromptSubmit", prompt=prompt), (0, ""))
        first = self.run_handle()
        first.call("close_run", reason="idle")   # as the signer's idle close
        self.assertIn("said not to modify billing.py", self.held_edit("billing.py", "t1"))
        self.assertNotEqual(self.run_handle().run_id, first.run_id)
        for run in (first, self.run_handle()):
            self.assertEqual([e["data"]["kind"] for e in run.call("read")["events"] if e["type"] == "constraint.added"],
                             ["keep_away", "no_push"])

    def test_a_prompt_too_large_to_record_still_adds_its_constraints(self):
        code, err = self.hook("UserPromptSubmit", prompt="Don't touch billing.py. " + "x" * (1 << 20))
        self.assertIn("over the signer's limit", err)   # an error the harness shows (exit 1 as `tracekit init` wires it)
        self.assertEqual([e["type"] for e in self.events()], ["run.registered", "constraint.added"])
        self.assertIn("said not to modify billing.py", self.held_edit("billing.py", "t1"))

    def test_a_constraint_past_the_signers_cap_is_told_to_the_person_and_every_write_is_held(self):
        prompt = "Don't touch " + " or ".join(f"f{i}.py" for i in range(service.MAX_CONSTRAINTS)) + " or billing.py."
        self.assertIn(claude_code.FULL, self.hook("UserPromptSubmit", prompt=prompt)[1])   # exit 1 as init wires it
        self.assertIn("so every write is held", self.held_edit("pager.py", "t1"))

    def test_a_prompts_constraints_outlive_a_signer_it_could_not_reach(self):
        """The session state keeps a prompt's constraints before they are sent: a signer unreachable at that
        UserPromptSubmit (after an earlier prompt's constraint went) loses none; the next event sends them."""
        added, down = [], [False]

        class Fake:
            def register_run(self, agent):
                return {"run_id": "r1", "run_token": "tok", "fail_modes": {}}

            def call(self, method, req=None, **fields):
                if down[0]:
                    raise SignerUnavailable("connection refused")
                added.append({**(req or {}), **fields}["constraint"])
                return {"run_seq": len(added)}
        claude_code._run(Fake(), "s9", stated=claude_code._live("Don't push."))
        down[0] = True
        with self.assertRaises(SignerUnavailable):
            claude_code._run(Fake(), "s9", stated=claude_code._live("Don't touch billing.py."))
        down[0] = False
        claude_code._run(Fake(), "s9")   # the session's next event
        self.assertEqual(added, [{"kind": "no_push"}, {"kind": "keep_away", "object": "billing.py"}])

    def test_each_constraint_goes_on_its_own_past_a_refusal(self):
        sent = []

        def call(method, constraint):
            sent.append(constraint["kind"])
            if constraint["kind"] == "keep_away":
                raise RPCError("invalid_request", "refused")
            return {"run_seq": len(sent)}
        st = {"run_id": "r1", "constraints": [["keep_away", "billing.py"], ["no_push", None], ["no_network", None]]}
        path = os.path.join(self.dir, "st.json")
        with mock.patch.object(claude_code, "RunHandle", lambda client, st: mock.Mock(call=call)):
            with self.assertRaises(RPCError):
                claude_code._constrain(None, path, st)
            self.assertEqual((sent, st["sent"]), (["keep_away", "no_push", "no_network"], ["r1", 3]))
            claude_code._constrain(None, path, dict(st, constraints=[*st["constraints"], ["read_only", None]]))
            self.assertEqual(sent[3:], ["read_only"])   # only what the run has not had
            sent.clear()
            with self.assertRaises(RPCError):
                claude_code.prompted(mock.Mock(call=call), "Don't touch billing.py. Never push.")
            self.assertEqual(sent, ["keep_away", "no_push"])

    def test_session_end_closes_the_run_and_it_verifies(self):
        self.pre("ls")
        self.post("ls")
        run = self.run_handle()
        self.assertEqual(self.hook("SessionEnd", reason="exit"), (0, ""))
        self.assertEqual([f for f in os.listdir(os.path.join(self.dir, "run")) if f.startswith("claude-code-")], [])
        deadline = time.monotonic() + 20
        while run.call("read")["events"][-1]["type"] != "run.final":   # after the grace window
            self.assertLess(time.monotonic(), deadline, "no run.final")
            time.sleep(0.25)
        autospawn.down()
        store = FileStorage(os.path.join(service.dev_data_dir(), "store"))
        self.addCleanup(store.close)
        text = checkpoint.body(ORIGIN, store.tree.size, store.tree.root_at(store.tree.size))
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, "run.tkb")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        export(store, "default", run.run_id, text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET), out)
        rep, code = v2.verify(out, trust)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)

    def test_a_call_that_gets_no_post_tool_use_completes_as_an_error_at_session_end(self):
        # declined in the harness's own prompt, or interrupted; at Stop a background sub-agent's call may still run
        self.assertEqual(self.pre("ls"), (0, ""))
        for event in ("Stop", "UserPromptSubmit"):
            self.assertEqual(self.hook(event), (0, ""))
        run = self.run_handle()
        self.assertEqual(run.call("read")["events"][-1]["type"], "policy.decision")
        self.assertEqual(self.hook("SessionEnd", reason="exit"), (0, ""))
        types = [e["type"] for e in run.call("read")["events"]]
        self.assertEqual(types[-3:], ["policy.decision", "tool.result", "run.closing"])
        result = run.call("read")["events"][-2]["data"]
        self.assertEqual((result["ok"], result["tool_use_id"]), (False, "t1"))

    def test_closed_run_continues_in_a_new_one(self):
        self.pre("ls")
        old = self.run_handle()
        old.close()
        self.assertEqual(self.pre("ls", tid="t2"), (0, ""))
        self.assertNotEqual(self.run_handle().run_id, old.run_id)

    def test_session_end_after_the_signer_closed_the_run(self):
        self.pre("ls")
        self.run_handle().close()
        self.assertEqual(self.hook("SessionEnd", reason="exit"), (0, ""))
        self.assertEqual([f for f in os.listdir(os.path.join(self.dir, "run")) if f.startswith("claude-code-")], [])

    def test_missing_ids_are_never_defaulted(self):
        code, err = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(code, 2)
        self.assertIn("no tool_use_id", err)
        self.assertEqual(self.pre("ls", sid=None)[0], 2)
        code, err = self.hook("PostToolUse", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(code, 0)
        self.assertIn("no tool_use_id", err)
        self.assertEqual(self.hook("SessionStart", sid=None)[0], 0)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "run", autospawn.SOCK)))   # nothing was sent

    def test_signer_unreachable_follows_the_runs_fail_mode(self):
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nowhere.sock")
        os.environ["TRACEKIT_FAIL_CLOSED"] = "0"   # the v1 hook's setting does not apply
        code, err = self.pre("ls", sid="unregistered")
        self.assertEqual(code, 2)
        self.assertIn("blocking (fail-closed)", err)
        del os.environ["TRACEKIT_SIGNER"]
        self.assertEqual(self.hook("SessionStart")[0], 0)
        with open(claude_code._state("s1")) as f:
            st = json.load(f)
        self.assertEqual(st["fail_modes"], {"default": "closed"})   # the signer's
        with open(claude_code._state("s1"), "w") as f:
            json.dump(dict(st, fail_modes={"default": "closed", "fs": "open"}), f)
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nowhere.sock")
        self.assertEqual(self.pre("ls")[0], 2)
        code, err = self.hook("PreToolUse", tool_name="Read", tool_input={"file_path": "a"}, tool_use_id="t2")
        self.assertEqual(code, 0)
        self.assertIn("allowing (fail-open)", err)

    def test_the_plugin_decides_through_the_dev_signer(self):
        os.environ.update(CLAUDE_PLUGIN_ROOT=os.path.join(ROOT, "plugin"), TRACEKIT_PYTHON=sys.executable)
        with open(os.path.join(ROOT, "plugin", "hooks", "hooks.json")) as f:
            cmd = json.load(f)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        for tid, command, code in (("t1", "pkill tracekitd", 2), ("t2", "ls", 0)):   # no hook_event_name: hooks.json names it
            p = subprocess.run(cmd, shell=True, cwd=self.cwd, capture_output=True, text=True, timeout=60, input=json.dumps(
                {"session_id": "s1", "tool_use_id": tid, "tool_name": "Bash", "tool_input": {"command": command}}))
            self.assertEqual(p.returncode, code, p.stderr)
            if code == 2:
                self.assertIn("TK-D007", p.stderr)
        self.assertEqual([e["data"]["decision"] for e in self.events() if e["type"] == "policy.decision"], ["deny", "allow"])
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nowhere.sock")
        for event, code in (("PreToolUse", 2), ("UserPromptSubmit", 1), ("Stop", 1)):   # 2 erases a prompt, loops Stop
            p = subprocess.run(cmd.replace("PreToolUse", event), shell=True, cwd=self.cwd, capture_output=True,
                               text=True, timeout=60, input=json.dumps({"session_id": "s2", "tool_use_id": "t3",
                                                                        "tool_name": "Bash", "tool_input": {}}))
            self.assertEqual(p.returncode, code, (event, p.stderr))
            self.assertIn("signer unreachable", p.stderr.splitlines()[0])

    def test_only_a_tool_call_is_blocked_by_the_hooks_init_writes(self):
        """A hook that could not finish exited 2 on every event: an unreachable signer erased each prompt and sent
        Claude back to work at every Stop."""
        settings = os.path.join(self.dir, "settings.json")
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, module=install.V2_HOOK)
        with open(settings) as f:
            cmds = {ev: gs[0]["hooks"][0]["command"] for ev, gs in json.load(f)["hooks"].items()}
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nowhere.sock")
        for event in ["PreToolUse"] + install.OTHER_EVENTS[:-1]:   # each registers the session's run first
            p = subprocess.run(cmds[event], shell=True, cwd=self.cwd, capture_output=True, text=True, timeout=60,
                               input=json.dumps({"session_id": "s1", "tool_use_id": "t1", "tool_name": "Bash",
                                                 "tool_input": {"command": "ls"}}))
            self.assertEqual(p.returncode, 2 if event == "PreToolUse" else 1, (event, p.stderr))
            self.assertIn("signer unreachable", p.stderr)

    def test_overhead(self):
        self.pre("ls", tid="warm")
        times = []
        for i in range(20):
            t = time.perf_counter()
            self.assertEqual(self.pre("ls", tid=f"t{i}")[0], 0)
            times.append(time.perf_counter() - t)
        print(f"\nv2 hook PreToolUse median over 20, warm signer: {statistics.median(times) * 1000:.0f} ms")


class InitV2(unittest.TestCase):
    def setUp(self):   # init reads the user's Claude Code settings and makes the dev signer's data dir
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        env = mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home,   # USERPROFILE: Windows' ~
                                           "CLAUDE_CONFIG_DIR": "",
                                           "XDG_DATA_HOME": os.path.join(self.home, "data")})
        env.start()
        self.addCleanup(env.stop)

    def init(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(err):
            code = cli.main(["init", *argv])
        self.out = out.getvalue()
        return code, err.getvalue()

    def enable_installed_plugin(self, key, source, version=2, marketplace_repo="community/marketplace"):
        settings_dir = os.path.join(self.home, ".claude")
        plugins_dir = os.path.join(settings_dir, "plugins")
        marketplace_dir = os.path.join(plugins_dir, "marketplaces", "community")
        os.makedirs(os.path.join(marketplace_dir, ".claude-plugin"), exist_ok=True)
        with open(os.path.join(settings_dir, "settings.json"), "w") as f:
            json.dump({"enabledPlugins": {key: True}}, f)
        record = {"scope": "user", "installPath": os.path.join(plugins_dir, "cache", "community", "tracekit", "1")}
        installed = [record] if version == 2 else {"version": "1", "installedAt": "now",
                                                   "installPath": record["installPath"]}
        state = {"version": version, "plugins": {key: installed}}
        with open(os.path.join(plugins_dir, "installed_plugins.json"), "w") as f:
            json.dump(state, f)
        with open(os.path.join(plugins_dir, "known_marketplaces.json"), "w") as f:
            json.dump({"community": {"source": {"source": "github", "repo": marketplace_repo},
                                      "installLocation": marketplace_dir}}, f)
        with open(os.path.join(marketplace_dir, ".claude-plugin", "marketplace.json"), "w") as f:
            json.dump({"plugins": [{"name": "tracekit", "source": source}]}, f)
        return os.path.join(settings_dir, "settings.json")

    def test_plugin_enabled_checks_the_installed_source_and_path(self):
        key = "tracekit@community"
        path = self.enable_installed_plugin(key, {"source": "git-subdir", "url": "Cygnux-Labs/Tracekit",
                                                   "path": "plugin/"})
        self.assertEqual(install.plugin_enabled([path]), (path, key))
        path = self.enable_installed_plugin(key, "./plugin", marketplace_repo="Cygnux-Labs/Tracekit")
        self.assertEqual(install.plugin_enabled([path]), (path, key))

        project = os.path.join(self.home, "project")
        project_settings = os.path.join(project, ".claude", "settings.json")
        os.makedirs(os.path.dirname(project_settings))
        with open(project_settings, "w") as f:
            json.dump({"enabledPlugins": {key: False}}, f)
        with mock.patch("os.getcwd", return_value=project):
            self.assertIsNone(install.plugin_enabled([path]))

        path = self.enable_installed_plugin(key, {"source": "git-subdir", "url": "someone-else/Tracekit",
                                                   "path": "plugin"}, version=1)
        self.assertIsNone(install.plugin_enabled([path]))
        path = self.enable_installed_plugin(key, {"source": "git-subdir", "url": "someone-else/Tracekit",
                                                   "path": "plugin"})
        self.assertIsNone(install.plugin_enabled([path]))   # another vendor's, in the v2 record format
        path = self.enable_installed_plugin(key, {"source": "git-subdir", "url": "Cygnux-Labs/Tracekit",
                                                   "path": "plugins/other"})
        self.assertIsNone(install.plugin_enabled([path]))   # our repo, another directory

        path = os.path.join(self.home, ".claude", "legacy.json")
        with open(path, "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        self.assertEqual(install.plugin_enabled([path]), (path, install.PLUGIN))

    def test_a_repos_own_plugin_state_and_a_relative_catalog_are_not_read(self):
        # a repo can plant .claude/plugins/* beside its settings; Claude Code never writes plugin state there
        repo = os.path.join(self.home, "repo")
        plugins = os.path.join(repo, ".claude", "plugins")
        os.makedirs(os.path.join(plugins, "m", ".claude-plugin"))
        for name, data in (("settings.json", {"enabledPlugins": {"tracekit@evil": True}}),
                           ("plugins/installed_plugins.json",
                            {"version": 2, "plugins": {"tracekit@evil": [{"scope": "user", "installPath": "/x"}]}}),
                           ("plugins/known_marketplaces.json",
                            {"evil": {"source": {"source": "github", "repo": "Cygnux-Labs/Tracekit"},
                                      "installLocation": os.path.join(plugins, "m")}}),
                           ("plugins/m/.claude-plugin/marketplace.json",
                            {"plugins": [{"name": "tracekit", "source": "./plugin"}]})):
            with open(os.path.join(repo, ".claude", name), "w") as f:
                json.dump(data, f)
        with mock.patch("os.getcwd", return_value=repo):
            self.assertIsNone(install.plugin_enabled())
        # a relative installLocation would resolve against the working directory
        path = self.enable_installed_plugin("tracekit@community", "./plugin", marketplace_repo="Cygnux-Labs/Tracekit")
        known = os.path.join(self.home, ".claude", "plugins", "known_marketplaces.json")
        with open(known) as f:
            data = json.load(f)
        data["community"]["installLocation"] = os.path.join("plugins", "marketplaces", "community")
        with open(known, "w") as f:
            json.dump(data, f)
        with mock.patch("os.getcwd", return_value=os.path.join(self.home, ".claude")):
            self.assertIsNone(install.plugin_enabled([path]))

    def test_init_installs_no_hooks_while_the_plugin_is_enabled(self):
        """Plugin and init hooks both decided every call, and one consumed each approval the other waited on, so
        every approved call was blocked (TK-APPROVAL-CONSUMED)."""
        settings = os.path.join(self.home, ".claude", "settings.json")
        os.makedirs(os.path.dirname(settings))
        for enabled in (True, False):
            with open(settings, "w") as f:
                json.dump({"enabledPlugins": {install.PLUGIN: enabled}}, f)
            with mock.patch("os.getcwd", return_value=self.home):
                self.assertEqual(self.init("--dev", "--v2")[0], 0)
            with open(settings) as f:
                self.assertEqual("hooks" in json.load(f), not enabled)
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, uninstall=True)
        with open(settings, "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        with mock.patch("os.getcwd", return_value=self.home):
            self.init("--dev", "--v2")
        self.assertIn(f"/plugin disable {install.PLUGIN}", self.out)
        self.assertTrue(os.path.isdir(service.dev_data_dir()))   # the plugin's hook now blocks calls it can't record

        key = "tracekit@community"
        settings = self.enable_installed_plugin(key, {"source": "git-subdir", "url": "Cygnux-Labs/Tracekit",
                                                       "path": "plugin"})
        with mock.patch("os.getcwd", return_value=self.home):
            self.assertEqual(self.init("--dev", "--v2")[0], 0)
        with open(settings) as f:
            self.assertNotIn("hooks", json.load(f))
        self.assertIn(f"/plugin disable {key}", self.out)

    def test_init_turns_thinking_summaries_on_for_the_plugins_users_and_uninstall_off(self):
        """With the plugin, init returned before it set showThinkingSummaries, though doctor's fix said init does."""
        settings = os.path.join(self.home, ".claude", "settings.json")
        os.makedirs(os.path.dirname(settings))
        with open(settings, "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        with mock.patch("os.getcwd", return_value=self.home):
            self.assertEqual(self.init("--dev", "--v2")[0], 0)
        with open(settings) as f:
            s = json.load(f)
        self.assertEqual((s[install.THINKING], "hooks" in s), (True, False))
        self.assertIn("thinking summaries: on", self.out)
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, uninstall=True)
        with open(settings) as f:
            self.assertEqual(json.load(f), {"enabledPlugins": {install.PLUGIN: True}})

    def test_uninstall_leaves_a_persons_own_thinking_setting(self):
        settings = os.path.join(self.home, "settings.json")
        for before in ({}, {install.THINKING: True}, {install.THINKING: False}):
            with open(settings, "w") as f:
                json.dump(before, f)
            with contextlib.redirect_stdout(io.StringIO()):
                install.install_hooks(settings, module=install.V2_HOOK, thinking=True)
                install.install_hooks(settings, uninstall=True)
            with open(settings) as f:
                self.assertEqual(json.load(f), before)
        with contextlib.redirect_stdout(io.StringIO()):   # turned off after init: the person's now
            install.install_hooks(settings, module=install.V2_HOOK, thinking=True)
        with open(settings) as f:
            s = json.load(f)
        with open(settings, "w") as f:
            json.dump(dict(s, **{install.THINKING: False}), f)
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, uninstall=True)
        with open(settings) as f:
            self.assertEqual(json.load(f), {install.THINKING: False})

    def test_a_project_can_turn_the_plugin_off_and_managed_settings_on(self):
        user, project = os.path.join(self.home, "user.json"), os.path.join(self.home, "project")
        local, managed = os.path.join(project, ".claude", "settings.local.json"), os.path.join(self.home, "managed.json")
        os.makedirs(os.path.dirname(local))
        for path, enabled in ((user, True), (local, False), (managed, True)):
            with open(path, "w") as f:
                json.dump({"enabledPlugins": {install.PLUGIN: enabled}}, f)
        with mock.patch("os.getcwd", return_value=project), \
                mock.patch.dict(install.MANAGED_SETTINGS, darwin=os.path.join(self.home, "none"),
                                linux=os.path.join(self.home, "none")):
            self.assertIsNone(install.plugin_enabled([user]))
            self.assertIsNone(install.plugin_enabled([os.path.join(self.home, "missing.json")]))
        with mock.patch("os.getcwd", return_value=project), \
                mock.patch.dict(install.MANAGED_SETTINGS, darwin=managed, linux=managed):
            self.assertEqual(install.plugin_enabled([user]), (managed, install.PLUGIN))

    def test_init_dev_v2_writes_the_hook(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch("os.getcwd", return_value=d):
            self.assertEqual(self.init("--dev", "--v2", "--project")[0], 0)
        with open(os.path.join(d, ".claude", "settings.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertEqual(set(hooks), set(install.TOOL_EVENTS + install.OTHER_EVENTS))
        cmd = hooks["PreToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(cmd, install._hook_command(install.V2_HOOK, args=("PreToolUse",)))
        self.assertEqual(hooks["Stop"][0]["hooks"][0]["command"],   # never blocks: Stop would send Claude back to work
                         install._hook_command(install.V2_HOOK, args=("Stop",), pre=False))
        self.assertIn(" -I ", cmd)
        self.assertTrue(os.path.isabs(shlex.split(cmd)[0]), cmd)
        self.assertTrue(all(install._is_ours(g) for gs in hooks.values() for g in gs))

    @unittest.skipUnless(os.name == "posix", "a POSIX shell wraps the hook")
    def test_a_dev_v2_hook_that_cannot_run_blocks_the_call(self):
        with mock.patch.object(install, "_dev_hook_command", return_value="false"):   # exits 1, as when tracekit is gone
            for module in install.V2_HOOKS:
                p = subprocess.run(install._hook_command(module), shell=True, capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 2, module)
                self.assertIn("call blocked (fail-closed)", p.stderr)
                for run in ("false", "sh -c 'exit 2'", "sh -c 'exit 9'"):   # any other event: never blocked (Stop)
                    with mock.patch.object(install, "_dev_hook_command", return_value=run):
                        p = subprocess.run(install._hook_command(module, pre=False), shell=True, capture_output=True,
                                           text=True, timeout=30)
                    self.assertEqual(p.returncode, 1, (module, run))
                self.assertIn("event not recorded", p.stderr)
            self.assertEqual(install._hook_command(), "false")   # the v1 dev hook keeps its own fail mode

    def test_v2_without_the_policy_engine_is_refused(self):
        from tracekit.policy2 import engine
        with mock.patch.object(engine, "_backend", side_effect=ImportError("no regex")):
            for argv in (["init", "--dev", "--v2", "--no-hooks"], ["up"]):
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(cli.main(argv), 2, argv)
                self.assertIn("pip install tracekit-ai", err.getvalue())

    def test_replacing_hooks_of_the_other_version_is_reported(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, ".claude", "settings.json")
        install.install_hooks(settings)   # v1
        with mock.patch("os.getcwd", return_value=d), mock.patch.dict(os.environ, {"HOME": d}):
            self.assertEqual([h["versions"] for h in install.status()["hooks"]], [["v1"]])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["init", "--dev", "--v2", "--project"]), 0)
            self.assertIn(f"Tracekit v1 hooks replaced by v2 hooks in {settings}", out.getvalue())
            self.assertEqual([h["versions"] for h in install.status()["hooks"]], [["v2"]])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                install.install_hooks(settings, uninstall=True)
            self.assertIn(f"Tracekit v2 hooks removed from {settings}", out.getvalue())

    def test_init_turns_thinking_summaries_on_unless_told_or_already_set(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, ".claude", "settings.json")

        def init(*extra):
            out = io.StringIO()
            with mock.patch("os.getcwd", return_value=d), mock.patch.dict(os.environ, {"HOME": d}), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["init", "--dev", "--v2", "--project", *extra]), 0)
            with open(settings) as f:
                return json.load(f).get(install.THINKING), out.getvalue()
        on, out = init()
        self.assertIs(on, True)
        self.assertIn("thinking summaries: on", out)
        self.assertIn("claude -p --thinking-display summarized", out)
        with open(settings) as f:
            s = json.load(f)
        with open(settings, "w") as f:
            json.dump(dict(s, **{install.THINKING: False}), f)
        on, out = init()   # a person's own choice stays, and init says what it costs
        self.assertIs(on, False)
        self.assertIn("thinking summaries: off", out)
        os.remove(settings)
        on, out = init("--no-thinking-summaries")
        self.assertIsNone(on)
        self.assertNotIn("thinking summaries", out)
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, uninstall=True, thinking=True)   # uninstall leaves the setting
        self.assertIsNone(init("--no-thinking-summaries")[0])

    def test_v2_option_refusals(self):
        code, err = self.init("--v2")
        self.assertEqual(code, 2)
        self.assertIn("needs --user AGENT", err)
        code, err = self.init("--dev", "--v2", "--approver", "root")
        self.assertEqual(code, 2)
        self.assertIn("for --v2 system mode", err)
        code, err = self.init("--dev", "--v2", "--fail-closed")
        self.assertEqual(code, 2)
        self.assertIn("don't apply with --v2", err)


if __name__ == "__main__":
    unittest.main()


class HoldLine(unittest.TestCase):
    def hold_lines(self, reason):
        """Return the waiting line and the not-approved follow-up from one ask that is rejected."""
        client = mock.Mock(timeout=30.0, signer=None)
        run = mock.Mock(run_id="r1")

        def call(method, **fields):
            return {"approval_request": {"approval_id": "apr-1"},
                    "approval_wait": {"state": "rejected"}}[method]

        run.call = call
        run.approval_consume = mock.Mock(return_value=None)

        def decide(*a, **kw):
            return run, {"decision": "ask", "rule_ids": ["TK-A003"], "decision_id": "d1",
                         "reason": reason}

        err = io.StringIO()
        with mock.patch.object(claude_code, "_run", decide), mock.patch.object(claude_code, "files"), \
                contextlib.redirect_stderr(err):
            self.assertEqual(claude_code._pre(client, {"tool_name": "Bash", "tool_input": {"command": "x"}}, "s1", "t1"), 2)
        lines = err.getvalue().splitlines()
        waiting = next(l for l in lines if "waiting for approval" in l)
        not_approved = next(l for l in lines if "not approved" in l)
        return waiting, not_approved

    def test_hold_line_drops_a_trailing_period_from_the_reason(self):
        """A rule's reason ends with a period (often from the joined remedy). The hold line joins it to the approval
        hint with `;`, so a trailing period would print as `.;` (#444)."""
        waiting, not_approved = self.hold_lines("force push. Push without --force.")
        self.assertIn("(TK-A003): force push. Push without --force; a person approves it", waiting)
        self.assertNotIn(".;", waiting)
        self.assertIn("(TK-A003: force push. Push without --force) and not approved:", not_approved)
        self.assertNotIn(".;", not_approved)

    def test_hold_line_keeps_ellipsis_dots_when_dropping_one_period(self):
        """Only one trailing period is removed (`removesuffix`), so a reason ending in `...` still shows `..`
        before the approval hint (#444)."""
        waiting, not_approved = self.hold_lines("Hold for review...")
        self.assertIn("(TK-A003): Hold for review..; a person approves it", waiting)
        self.assertNotIn("Hold for review...;", waiting)
        self.assertNotRegex(waiting, r"(?<!\.)\.;")   # a lone period before `;` would be the #444 bug
        self.assertIn("(TK-A003: Hold for review..) and not approved:", not_approved)
        self.assertNotIn(".;", not_approved)


class PreBudget(unittest.TestCase):
    def test_a_held_call_is_answered_within_the_hooks_budget(self):
        """Every signer call takes all the time it may, and the approval comes on the last wait: the hook still
        answers within APPROVAL_WAIT_S, below its timeout."""
        now, calls = [0.0], []
        client = mock.Mock(timeout=30.0, signer=None)

        def call(method, **fields):
            calls.append(method)
            now[0] += client.timeout + fields.get("timeout_ms", 0) / 1000
            return {"approval_request": {"approval_id": "a1"}, "approval_consume": {"ok": True}}.get(method) or \
                {"state": "requested" if fields.get("timeout_ms") == 300_000 else "approved"}
        run = mock.Mock(run_id="r1", call=call, approval_consume=lambda *a, **kw: call("approval_consume"))

        def decide(*a, **kw):
            call("decide")
            return run, {"decision": "ask", "rule_ids": ["R1"], "decision_id": "d1"}
        with mock.patch.object(claude_code, "_run", decide), mock.patch.object(claude_code, "files"), \
                mock.patch.object(claude_code, "time", mock.Mock(monotonic=lambda: now[0])), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(claude_code._pre(client, {"tool_name": "pay", "tool_input": {}}, "s1", "t1"), 0)
        self.assertEqual(calls[-1], "approval_consume")
        self.assertLessEqual(now[0], claude_code.APPROVAL_WAIT_S)


class V1SystemMode(unittest.TestCase):
    def test_the_hook_names_the_v2_init_on_a_v1_system_mode_host(self):
        """A v1 system mode host (client.json names tracekitd's socket, no v2 signer) blocked every call with "signer
        unreachable (dev auto-spawn is off ...)", which named no fix."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": os.path.join(d, "run")}), \
                mock.patch.object(claude_code, "system_config", return_value={"socket": "/var/lib/tracekit/t.sock"}), \
                mock.patch.object(claude_code, "Client"), contextlib.redirect_stderr(err), \
                mock.patch.object(claude_code, "_handle", side_effect=autospawn.SignerUnavailable("dev auto-spawn is off")):
            os.environ.pop("TRACEKIT_SIGNER", None)
            self.assertEqual(claude_code.handle({"hook_event_name": "PreToolUse", "session_id": "s", "tool_use_id": "t",
                                                 "tool_name": "Bash"}), 2)
            self.assertEqual(claude_code.handle({"hook_event_name": "Stop", "session_id": "s"}), 1)
        self.assertEqual(err.getvalue().count("v1 system mode"), 2)
        self.assertEqual(err.getvalue().count("sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user>"), 2)


class StateReads(unittest.TestCase):
    def test_a_state_file_being_replaced_is_read_again_on_windows(self):
        """On Windows, open() fails while a parallel hook replaces the file: the hook waits instead of blocking the call."""
        from unittest import mock
        from tracekit.integrations import claude_code
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "s.json")
        with open(path, "w") as f:
            json.dump({"run_id": "r"}, f)
        real, tries = open, []

        def flaky(*a, **kw):
            tries.append(1)
            if len(tries) < 3:
                raise PermissionError(13, "in use")
            return real(*a, **kw)
        with mock.patch.object(claude_code.os, "name", "nt"), mock.patch("builtins.open", flaky):
            self.assertEqual(claude_code._load(path), {"run_id": "r"})
        self.assertEqual(len(tries), 3)
