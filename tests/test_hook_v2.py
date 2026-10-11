"""The v2 Claude Code hook (tracekit/integrations/claude_code.py) against the real dev signer, auto-spawned in a temp
runtime dir, invoked through the command `tracekit init --v2` wires."""
import contextlib
import hmac
import io
import json
import os
import shlex
import shutil
import statistics
import subprocess
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
from tracekit.sdk.client import Client, RunHandle
from tracekit.signer import service
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
        self.assertIn("TK-D007", err)
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

    def test_overhead(self):
        self.pre("ls", tid="warm")
        times = []
        for i in range(20):
            t = time.perf_counter()
            self.assertEqual(self.pre("ls", tid=f"t{i}")[0], 0)
            times.append(time.perf_counter() - t)
        print(f"\nv2 hook PreToolUse median over 20, warm signer: {statistics.median(times) * 1000:.0f} ms")


class InitV2(unittest.TestCase):
    def init(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            return cli.main(["init", *argv]), err.getvalue()

    def test_init_dev_v2_writes_the_hook(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch("os.getcwd", return_value=d):
            self.assertEqual(self.init("--dev", "--v2", "--project")[0], 0)
        with open(os.path.join(d, ".claude", "settings.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertEqual(set(hooks), set(install.TOOL_EVENTS + install.OTHER_EVENTS))
        cmd = hooks["PreToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(cmd, HOOK)
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


class PreBudget(unittest.TestCase):
    def test_a_held_call_is_answered_within_the_hooks_budget(self):
        """Every signer call takes all the time it may, and the approval comes on the last wait: the hook still
        answers within APPROVAL_WAIT_S, below its timeout."""
        now, calls = [0.0], []
        client = mock.Mock(timeout=30.0)

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
