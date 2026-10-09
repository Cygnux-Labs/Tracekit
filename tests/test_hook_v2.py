"""The v2 Claude Code hook (tracekit/integrations/claude_code.py) against the real dev signer, auto-spawned in a temp
runtime dir, invoked through the command `tracekit init --v2` wires."""
import contextlib
import io
import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from tracekit import cli, install
from tracekit.bundle_v2 import export
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


@unittest.skipUnless(os.name == "posix", "the v2 client speaks Unix sockets only")
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
        self.assertEqual(types[-4:], ["approval", "policy.decision", "approval.consumed", "tool.result"])

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

    def test_signer_unreachable_follows_the_fail_mode(self):
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nowhere.sock")
        code, err = self.pre("ls")
        self.assertEqual(code, 0)
        self.assertIn("allowing (fail-open)", err)
        os.environ["TRACEKIT_FAIL_CLOSED"] = "1"
        code, err = self.pre("ls")
        self.assertEqual(code, 2)
        self.assertIn("blocking (fail-closed)", err)

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
        self.assertTrue(cmd.startswith(("/", "'/")), cmd)
        self.assertTrue(all(install._is_ours(g) for gs in hooks.values() for g in gs))

    def test_v2_refuses_system_mode(self):
        code, err = self.init("--v2")
        self.assertEqual(code, 2)
        self.assertIn("dev mode only", err)


if __name__ == "__main__":
    unittest.main()
