"""v2 Python client (tracekit/sdk/client.py) and dev auto-spawn (tracekit/sdk/autospawn.py), against
tracekit.testing.serve_fake running as a real detached process."""
import asyncio
import contextlib
import io
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tracekit import __version__, cli
from tracekit.sdk import autospawn, client
from tracekit.sdk.client import AsyncClient, Client, Incompatible, current_run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE_CMD = shlex.join([sys.executable, "-m", "tracekit.testing"])
SAY_PID = "from tracekit.sdk.client import Client; c = Client(); c.status(); print(c.hello['pid'])"


@unittest.skipUnless(os.name == "posix", "the v2 client speaks Unix sockets only")
class DevSigner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        self.env = {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_SIGNER_CMD": FAKE_CMD, "TRACEKIT_DEV_IDLE": "60",
                    "PYTHONPATH": ROOT}
        os.environ.pop("TRACEKIT_SIGNER", None)
        os.environ.update(self.env)
        self.addCleanup(autospawn.down)

    def python(self, code, **env):
        return subprocess.run([sys.executable, "-c", code], env={**os.environ, **env}, capture_output=True, text=True,
                              timeout=60)

    def log(self):
        with open(os.path.join(self.run_dir, autospawn.LOG)) as f:
            return f.read()

    def test_concurrent_clients_start_one_signer(self):
        procs = [subprocess.Popen([sys.executable, "-c", SAY_PID], stdout=subprocess.PIPE, text=True) for _ in range(10)]
        pids = {p.communicate(timeout=60)[0].strip() for p in procs}
        self.assertEqual([p.returncode for p in procs], [0] * 10)
        self.assertEqual(len(pids), 1, pids)
        self.assertEqual(self.log().count("SERVING"), 1)

    def test_kernels_reuse_the_signer(self):
        first, second = self.python(SAY_PID), self.python(SAY_PID)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_recovers_after_sigkill(self):
        c = Client()
        old = c.status() and c.hello["pid"]
        os.kill(old, signal.SIGKILL)
        deadline = time.monotonic() + 10
        while autospawn._held(os.path.join(self.run_dir, autospawn.LOCK)):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        self.assertTrue(os.path.exists(os.path.join(self.run_dir, autospawn.ENDPOINT)))   # left behind by the kill
        self.assertEqual(c.status()["rpc_version"], 1)   # the same client reconnects to a new signer
        self.assertNotEqual(c.hello["pid"], old)
        self.assertEqual(self.python(SAY_PID).stdout.strip(), str(c.hello["pid"]))

    def test_incompatible_signer_is_refused_and_left_running(self):
        os.makedirs(self.run_dir, 0o700)
        p = subprocess.Popen(shlex.split(FAKE_CMD) + ["--proto", "2-3", "--version", "9.9.9"], start_new_session=True,
                             stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait, 10)
        while autospawn._pid(self.run_dir) is None:
            self.assertIsNone(p.poll())
            time.sleep(0.02)
        with self.assertRaises(Incompatible) as cm:
            Client().status()
        for text in ("9.9.9", __version__, f"pid {p.pid}", "tracekit up --replace"):
            self.assertIn(text, str(cm.exception))
        self.assertIsNone(p.poll())
        self.assertIn(f"dev signer {__version__} running", self.cli("up", "--replace", "--wait"))
        self.assertEqual(p.wait(10), 0)
        self.assertEqual(Client().status()["rpc_version"], 1)

    def test_read_only_home_with_tracekit_signer(self):
        hello = json.loads(self.cli("up", "--json"))   # --json waits for the signer it starts
        home = os.path.join(self.dir, "home")
        os.mkdir(home, 0o500)
        self.addCleanup(os.chmod, home, 0o700)
        r = self.python("from tracekit.sdk.client import Client\n"
                        "with Client().run('ro') as run:\n"
                        "    assert run.decide('c1', 'Bash', '{\"command\": \"ls\"}')['decision'] == 'allow'\n"
                        "    run.complete('c1')\n",
                        HOME=home, TRACEKIT_SIGNER=os.path.join(self.run_dir, autospawn.SOCK), TRACEKIT_RUNTIME_DIR="",
                        XDG_RUNTIME_DIR=os.path.join(home, "xdg"), TRACEKIT_DEV_SIGNER_CMD="false")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.listdir(home), [])
        self.assertEqual(hello["pid"], autospawn._pid(self.run_dir))

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(list(argv)), 0)
        return out.getvalue()

    def test_cli_up_status_down(self):
        self.assertIn(f"dev signer {__version__} running", self.cli("up", "--wait"))
        status = json.loads(self.cli("status"))
        self.assertIn("client_config", status)   # the v1 sections are still there
        self.assertTrue(status["signer_v2"]["running"])
        self.assertIn("dev signer stopped", self.cli("down"))
        self.assertFalse(json.loads(self.cli("status"))["signer_v2"]["running"])
        self.assertIn("no dev signer running", self.cli("down"))

    def test_status_survives_an_unusable_runtime_dir(self):
        with mock.patch.object(autospawn, "runtime_dir", side_effect=PermissionError("read-only")):
            status = json.loads(self.cli("status"))
        self.assertIn("client_config", status)
        self.assertFalse(status["signer_v2"]["running"])

    def test_approval_wait_does_not_hold_up_other_calls(self):
        from tracekit.transport.unix import UnixServer
        release = threading.Event()

        def handle(identity, frame):
            if frame["method"] == "hello":
                return {"proto": [1, 1], "version": __version__, "pid": os.getpid()}
            if frame["method"] == "approval_wait":
                release.wait(10)   # a real signer blocks up to timeout_ms
                return {"approval_id": frame["approval_id"], "state": "approved"}
            return {"rpc_version": 1}
        path = os.path.join(self.dir, "s.sock")
        server = UnixServer(path, handle)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        c, waited = Client(path, timeout=5), []
        c.status()
        waiter = threading.Thread(target=lambda: waited.append(c.approval_wait(
            {"run_id": "r1", "run_token": "t", "approval_id": "a1", "timeout_ms": 60000})))
        waiter.start()
        self.assertEqual(c.status(), {"rpc_version": 1})   # answered while the wait is still blocked
        self.assertTrue(waiter.is_alive())
        release.set()
        waiter.join(10)
        self.assertEqual(waited, [{"approval_id": "a1", "state": "approved"}])

    def test_run_handle_and_current_run(self):
        c = Client()
        with c.run("agent", run_id="r1") as run:
            self.assertIs(current_run.get(), run)
            self.assertEqual(run.decide("c1", "Bash", {"command": "ls"})["decision"], "allow")
            run.complete("c1", "error", error="boom")
            run.call("state_write", key="k", value_digest="sha256:" + "0" * 64)
        self.assertIsNone(current_run.get())
        self.assertTrue(run.closed)
        types = [e["type"] for e in run.call("read")["events"]]
        self.assertEqual(types, ["run.registered", "policy.decision", "tool.result", "state.write", "run.closing"])
        with self.assertRaises(client.RPCError) as cm:
            c.decide({"run_id": "r1"})   # refused before sending
        self.assertEqual(cm.exception.code, "invalid_request")

    def test_retry_after_lost_reply_reuses_the_request_id(self):
        c = Client()
        real, dropped = client.read_frame, []

        def drop_first_registration(rfile):
            frame = real(rfile)
            if frame and "run_token" in frame and not dropped:
                dropped.append(frame)
                return None   # the signer registered the run; the reply is lost with the connection
            return frame
        with mock.patch.object(client, "read_frame", drop_first_registration):
            run = c.run("agent", run_id="r1", request_id="req-1")   # without reuse the resend would be run_exists
        self.assertEqual(run.registered, dropped[0])
        self.assertEqual(c.register_run({"request_id": "req-1", "run_id": "r1", "agent": {"name": "agent"}}),
                         dropped[0])
        with self.assertRaises(client.RPCError) as cm:
            c.register_run({"request_id": "req-1", "run_id": "r2", "agent": {"name": "agent"}})
        self.assertEqual(cm.exception.code, "conflict")

    def test_run_ids_sharing_a_prefix_stay_separate(self):
        c = Client()
        a, b = c.run("agent", run_id="a" * 120 + "-1"), c.run("agent", run_id="a" * 120 + "-2")
        self.assertNotEqual(a.run_token, b.run_token)
        a.decide("c1", "Bash", "{}")
        a.close()
        b.decide("c2", "Bash", "{}")
        self.assertEqual([e["data"].get("tool_call_id") for e in a.call("read")["events"]], [None, "c1", None])
        self.assertEqual([e["data"].get("tool_call_id") for e in b.call("read")["events"]], [None, "c2"])
        with self.assertRaises(client.RPCError) as cm:
            b.call("decide", tool_call_id="c3", tool="Bash", args="{}", args_source="raw", run_token=a.run_token)
        self.assertEqual(cm.exception.code, "run_token_invalid")

    def test_async_api(self):
        async def main():
            ac = AsyncClient()
            async with await ac.run("agent") as run:
                self.assertIs(current_run.get(), run)
                outs = await asyncio.gather(*(run.decide(f"c{i}", "Bash", "{}") for i in range(20)))
                await run.complete("c0")
            return run, outs
        run, outs = asyncio.run(main())
        self.assertEqual({o["decision"] for o in outs}, {"allow"})
        self.assertEqual(len({o["run_seq"] for o in outs}), 20)
        self.assertTrue(run.closed)

    def test_runtime_dir_must_be_private(self):
        os.makedirs(self.run_dir, 0o700)
        os.chmod(self.run_dir, 0o755)
        with self.assertRaises(client.SignerUnavailable):
            Client().status()
        self.assertEqual(stat.S_IMODE(os.stat(self.run_dir).st_mode), 0o755)
        os.chmod(self.run_dir, 0o700)

    def test_no_auto_spawn_with_tracekit_signer_or_in_system_mode(self):
        with mock.patch.object(autospawn, "SYSTEM_CONFIG", ROOT):
            with self.assertRaises(client.SignerUnavailable):
                Client().status()
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "nothing.sock")
        with self.assertRaises(client.SignerUnavailable):
            Client().status()
        self.assertFalse(os.path.exists(self.run_dir))


if __name__ == "__main__":
    unittest.main()
