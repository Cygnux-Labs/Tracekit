"""v2 Python client (tracekit/sdk/client.py) and dev auto-spawn (tracekit/sdk/autospawn.py), against
tracekit.testing.serve_fake running as a real detached process."""
import asyncio
import collections
import contextlib
import datetime
import io
import json
import os
import random
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tracekit import __version__, cli
from tracekit.signer.rpc_schema import RPC_VERSION  # noqa: E402
from tracekit.sdk import autospawn, client
from tracekit.sdk.client import AsyncClient, Client, Incompatible, current_run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE_ARGV = [sys.executable, "-m", "tracekit.testing"]
USE_FAKE = f"from tracekit.sdk import autospawn; autospawn.SIGNER_ARGV = {FAKE_ARGV!r}\n"   # the test-only hook
SAY_PID = USE_FAKE + "from tracekit.sdk.client import Client; c = Client(); c.status(); print(c.hello['pid'])"


@unittest.skipUnless(os.name == "posix", "POSIX paths, signals and shells; DevSignerOverTcp (test_signer_dev.py) runs everywhere")
class DevSigner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        self.env = {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_IDLE": "60",
                    "PYTHONPATH": ROOT}
        os.environ.pop("TRACEKIT_SIGNER", None)
        os.environ.update(self.env)
        fake = mock.patch.object(autospawn, "SIGNER_ARGV", FAKE_ARGV)
        fake.start()
        self.addCleanup(fake.stop)
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
        self.assertEqual(c.status()["rpc_version"], RPC_VERSION)   # the same client reconnects to a new signer
        self.assertNotEqual(c.hello["pid"], old)
        self.assertEqual(self.python(SAY_PID).stdout.strip(), str(c.hello["pid"]))

    def test_incompatible_signer_is_refused_and_left_running(self):
        os.makedirs(self.run_dir, 0o700)
        p = subprocess.Popen(FAKE_ARGV + ["--proto", f"{RPC_VERSION + 1}-{RPC_VERSION + 2}", "--version", "9.9.9"],
                             start_new_session=True,
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
        self.assertEqual(Client().status()["rpc_version"], RPC_VERSION)

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
                        XDG_RUNTIME_DIR=os.path.join(home, "xdg"))
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
                return {"proto": [RPC_VERSION, RPC_VERSION], "version": __version__, "pid": os.getpid()}
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

    def test_an_event_the_signer_never_saw_uses_up_its_client_seq(self):
        from tracekit.transport.unix import UnixServer
        seqs = []

        def handle(identity, frame):
            if frame["method"] == "hello":
                return {"proto": [RPC_VERSION, RPC_VERSION], "version": __version__, "pid": os.getpid()}
            seqs.append(frame["client_seq"])
            return {"rpc_version": 1}
        path = os.path.join(self.dir, "s.sock")
        c = Client(path, timeout=5)
        req = {"run_id": "r1", "run_token": "t", "tool": "Bash", "args_source": "raw", "args": "{}"}
        with self.assertRaises(client.SignerUnavailable):   # no signer yet: the caller's fail mode decides
            c.decide({**req, "tool_call_id": "c1"})
        server = UnixServer(path, handle)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        c.decide({**req, "tool_call_id": "c2"})
        self.assertEqual(seqs, [1])   # the skipped 0 is the signer's client_counter_gap

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


class Transports(unittest.TestCase):
    def test_tcp_signer_must_be_on_loopback(self):
        with mock.patch.object(client.tcp_dev, "dial", side_effect=OSError("refused")) as dial:
            for host in ("10.0.0.5", "example.org", "0.0.0.0"):
                with self.assertRaisesRegex(client.SignerUnavailable, "must be on loopback"):
                    client.connect(f"tcp://{host}:7000", token="t")
            for host in ("127.0.0.1", "::1", "localhost"):
                with self.assertRaisesRegex(client.SignerUnavailable, "refused"):
                    client.connect(f"tcp://{host}:7000", token="t")
        self.assertEqual(dial.call_count, 3)

    def test_missing_token_file_is_signer_unavailable(self):
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN_FILE": os.path.join(tempfile.gettempdir(), "no-such")}):
            c = Client("https://127.0.0.1:1", timeout=1)
        with self.assertRaisesRegex(client.SignerUnavailable, "token file"):
            c.status()

    def https(self, answer, timeout=5):
        """A Client of an HTTPS signer whose requests `answer(frame)` answers, in place of the network."""
        def post(_, body, timeout, host=None):
            frame = json.loads(body) if isinstance(body, bytes) else body
            return HELLO if frame["method"] == "hello" else answer(frame)
        patch = mock.patch.object(client._Https, "post", post)
        patch.start()
        self.addCleanup(patch.stop)
        return Client("https://signer.test:8443", timeout=timeout)

    def test_a_runs_events_reach_an_https_signer_in_client_seq_order(self):
        arrived = collections.defaultdict(list)

        def answer(frame):
            time.sleep(random.random() / 200)   # the network: requests sent in order may arrive out of it
            arrived[frame["run_id"]].append(frame["client_seq"])
            return {"ok": True}
        c = self.https(answer)

        def work(run):
            for i in range(10):
                c.decide({**EVENT, "run_id": run, "tool_call_id": f"c{i}", "args": {}})
        threads = [threading.Thread(target=work, args=(f"r{t % 2}",)) for t in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(arrived, {"r0": list(range(30)), "r1": list(range(30))})

    def test_an_event_waiting_behind_an_unanswered_one_gives_up_in_time_and_uses_its_client_seq(self):
        release, arrived = threading.Event(), []

        def answer(frame):
            arrived.append(frame["client_seq"])
            if frame["tool_call_id"] == "slow":
                release.wait(10)
            return {"ok": True}
        c = self.https(answer, timeout=0.3)
        slow = threading.Thread(target=c.decide, args=({**EVENT, "tool_call_id": "slow", "args": {}},))
        slow.start()
        while not arrived:
            time.sleep(0.01)
        t = time.monotonic()
        with self.assertRaises(client.SignerUnavailable):
            c.decide({**EVENT, "tool_call_id": "waits", "args": {}})
        self.assertLess(time.monotonic() - t, 2)
        release.set()
        slow.join(10)
        c.decide({**EVENT, "tool_call_id": "next", "args": {}})
        self.assertEqual(arrived, [0, 2])   # 1, the call that gave up, is the signer's client_counter_gap

    def test_close_closes_every_threads_https_connection(self):
        conns, answers = [], iter([json.dumps(HELLO).encode(), b"{}", b"{}"])

        def connection(*_, **__):
            conns.append(mock.Mock(sock=None))
            conns[-1].getresponse.return_value.read.side_effect = lambda: next(answers)
            return conns[-1]
        with mock.patch.object(client.http.client, "HTTPSConnection", connection):
            c = Client("https://signer.test:8443", timeout=5)
            c.status()
            t = threading.Thread(target=c.status)
            t.start()
            t.join(10)
            c.close()
        self.assertEqual([conn.close.call_count for conn in conns], [1, 1])


HELLO = {"proto": [RPC_VERSION, RPC_VERSION], "version": __version__, "pid": os.getpid()}
EVENT = {"run_id": "r1", "run_token": "t", "tool": "Bash", "args_source": "parsed"}


@unittest.skipUnless(os.name == "posix", "Unix sockets")
class FakeSigners(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "s.sock")

    def serve(self, answer):
        """A signer whose requests `answer(frame)` answers."""
        from tracekit.transport.unix import UnixServer
        server = UnixServer(self.path, lambda _, f: HELLO if f["method"] == "hello" else answer(f))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def stalled(self, read=True):
        """A signer that answers hello, then reads one request per connection (with `read`) and answers nothing. -> the
        requests it read."""
        srv, frames, held = socket.socket(socket.AF_UNIX), [], []
        srv.bind(self.path)
        srv.listen()

        def serve():
            with contextlib.suppress(OSError):   # closed by the cleanup
                while True:
                    conn, _ = srv.accept()
                    held.append(conn)
                    rfile = conn.makefile("rb")
                    rfile.readline()
                    conn.sendall((json.dumps(HELLO) + "\n").encode())
                    if read:
                        frames.append(json.loads(rfile.readline() or "null"))
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(lambda: [s.close() for s in held + [srv]])
        return frames

    def test_a_request_that_is_not_json_takes_no_answer_and_no_client_seq(self):
        seen = []

        def answer(frame):
            seen.append(frame.get("client_seq"))
            return {"method": frame["method"], "tool_call_id": frame.get("tool_call_id")}
        self.serve(answer)
        c = Client(self.path, timeout=2)
        with self.assertRaises(client.RPCError) as cm:
            c.decide({**EVENT, "tool_call_id": "bad", "args": {"when": datetime.date(2026, 1, 1)}})
        self.assertEqual(cm.exception.code, "invalid_request")
        self.assertEqual(c.status(), {"method": "status", "tool_call_id": None})
        self.assertEqual(c.decide({**EVENT, "tool_call_id": "c2", "args": {}})["tool_call_id"], "c2")
        self.assertEqual(seen, [None, 0])

    def test_a_request_over_the_frame_limit_is_refused_before_it_is_sent(self):
        seen = []
        self.serve(lambda frame: seen.append(frame["client_seq"]) or {"ok": True})
        c = Client(self.path, timeout=2)
        with self.assertRaisesRegex(client.RPCError, r"quota_exceeded: the decide request is \d+ bytes, over the "
                                                     r"signer's limit of 1048576 bytes per request"):
            c.decide({**EVENT, "tool_call_id": "big", "args": {"content": "x" * client.MAX_LINE}})
        c.decide({**EVENT, "tool_call_id": "c2", "args": {}})
        self.assertEqual(seen, [0])

    def test_a_signer_that_stops_reading_fails_every_waiting_call_in_time(self):
        self.stalled(read=False)
        c, took = Client(self.path, timeout=0.5), {}

        def call(run, size):
            t = time.monotonic()
            try:
                c.decide({**EVENT, "run_id": run, "tool_call_id": run, "args": {"content": "x" * size}})
            except client.SignerUnavailable:
                took[run] = time.monotonic() - t
        threads = [threading.Thread(target=call, args=("big", 900_000), daemon=True),
                   threading.Thread(target=call, args=("small", 10), daemon=True)]
        for t in threads:
            t.start()
            time.sleep(0.1)
        for t in threads:
            t.join(5)
        self.assertEqual(sorted(took), ["big", "small"])
        self.assertLess(max(took.values()), 3)
        closer = threading.Thread(target=c.close, daemon=True)
        closer.start()
        closer.join(2)
        self.assertFalse(closer.is_alive())

    def test_a_long_poll_without_an_answer_is_not_sent_again(self):
        frames = self.stalled()
        c = Client(self.path, timeout=0.3)
        with self.assertRaises(client.SignerUnavailable):
            c.approval_wait({"run_id": "r1", "run_token": "t", "approval_id": "a1", "timeout_ms": 0})
        self.assertEqual([f["method"] for f in frames], ["approval_wait"])

    def test_a_forked_child_does_not_inherit_a_held_lock(self):
        code = f"""if 1:
            import os, signal, threading
            from tracekit.sdk.client import Client, SignerUnavailable
            c, held, done = Client({os.path.join(self.dir, "none.sock")!r}, timeout=1), threading.Event(), threading.Event()
            threading.Thread(target=lambda: (c._lock.acquire(), held.set(), done.wait())).start()   # mid-call
            held.wait()
            pid = os.fork()
            if pid == 0:
                signal.alarm(5)
                try:
                    c.status()
                except SignerUnavailable:
                    os._exit(0)
                os._exit(3)
            done.set()
            print(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))"""
        p = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": ROOT}, capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(p.stdout.strip(), "0", p.stderr)


if __name__ == "__main__":
    unittest.main()
