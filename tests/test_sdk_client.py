"""v2 Python client (tracekit/sdk/client.py) and dev auto-spawn (tracekit/sdk/autospawn.py), against
tracekit.testing.serve_fake running as a real detached process."""
import asyncio
import collections
import contextlib
import datetime
import http.server
import io
import json
import os
import random
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import gc
import threading
import time
import unittest
import warnings
from unittest import mock

from tracekit import __version__, cli
from tracekit.signer.rpc_schema import RPC_VERSION  # noqa: E402
from tracekit.sdk import autospawn, client
from tracekit.sdk.client import AsyncClient, AsyncRunHandle, Client, Incompatible, RunHandle, current_run
from tracekit.signer.rpc_schema import INSTEAD, RPCError

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

    def test_a_client_dropped_without_close_leaves_no_threads_or_connections(self):
        Client().status()   # the dev signer is up
        gc.collect()
        before = threading.active_count()
        for i in range(30):   # the documented `with Client().run(...)`, once per conversation
            with Client().run(agent="a") as run:
                run.decide(f"c{i}", "Bash", {"command": "ls"})
        gc.collect()
        deadline = time.monotonic() + 5
        while threading.active_count() > before + 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertLessEqual(threading.active_count(), before + 2)

    def test_a_client_that_reconnects_keeps_no_dead_connection_open(self):
        """Review of 1.5.3: a lost connection's socket stayed open (its reader was never closed, and a finalizer per
        connection kept it alive), one fd for each reconnection; the signer drops a connection idle READ_TIMEOUT_S,
        so a heartbeating tailer reconnected and leaked nearly every beat."""
        c = Client()
        self.addCleanup(c.close)
        c.status()
        gc.collect()
        before = len(os.listdir("/dev/fd"))
        for _ in range(20):
            conn = c._conn
            conn.drop()
            conn.threads[0].join(5)
            c.status()
        gc.collect()
        self.assertLessEqual(len(os.listdir("/dev/fd")), before + 1)

    def test_close_returns_after_the_connection_threads_end(self):
        """A hook closes its client and exits at once; a connection thread still waking then can crash the process
        (#481: a hook segfaulted on CI's macOS runners under Python 3.13)."""
        before = set(threading.enumerate())
        c = Client()
        c.status()
        threads = [t for t in set(threading.enumerate()) - before if t.name.startswith("tracekit-client")]
        self.assertEqual(len(threads), 2)
        c.close()
        self.assertEqual([t.name for t in threads if t.is_alive()], [])

    def test_a_client_never_closed_ends_its_threads_in_its_finalizer(self):
        """srt-decider, instrument() and `with Client().run(...)` never call close(): the finalizer, run when the client
        is collected or at exit, waits for the threads too (#481)."""
        before = set(threading.enumerate())
        c = Client()
        c.status()
        threads = [t for t in set(threading.enumerate()) - before if t.name.startswith("tracekit-client")]
        self.assertEqual(len(threads), 2)
        del c
        gc.collect()
        self.assertEqual([t.name for t in threads if t.is_alive()], [])

    def test_closing_a_connection_stops_its_writer_without_its_reader(self):
        """The finalizer can run in gc on the connection's own reader, which then cannot hand the writer the stop it
        waits for: closing gives it one rather than waiting JOIN_S for nothing (#481)."""
        a, b = socket.socketpair()
        rfile = a.makefile("rb")
        for f in (a, b, rfile):
            self.addCleanup(f.close)
        conn = client._Conn(a, rfile)
        conn.threads = (threading.Thread(target=conn.write, daemon=True),)
        conn.threads[0].start()
        start = time.monotonic()
        conn.close()
        self.assertLess(time.monotonic() - start, client.JOIN_S / 2)
        self.assertFalse(conn.threads[0].is_alive())

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

    def test_an_older_signer_is_replaced_with_a_plain_notice(self):
        """QA of 1.6.0: the notice was a Python warning, `.../sdk/client.py:456: UserWarning: tracekit: stopped the dev
        signer ...` and the source line under it; it is one plain line."""
        os.makedirs(self.run_dir, 0o700)   # what an upgrade leaves running: hooks would otherwise all fail closed
        p = subprocess.Popen(FAKE_ARGV + ["--proto", f"{RPC_VERSION - 2}-{RPC_VERSION - 1}", "--version", "0.0.1"],
                             start_new_session=True, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait, 10)
        while autospawn._pid(self.run_dir) is None:
            self.assertIsNone(p.poll())
            time.sleep(0.02)
        with contextlib.redirect_stderr(io.StringIO()) as err, warnings.catch_warnings():
            warnings.simplefilter("error")
            self.assertEqual(Client().status()["rpc_version"], RPC_VERSION)
        self.assertEqual(err.getvalue(), f"tracekit: stopped the dev signer from an older Tracekit (pid {p.pid}) to start "
                                         f"this one's ({__version__})\n")
        self.assertEqual(p.wait(10), 0)

    def test_an_older_signer_is_kept_when_the_one_we_would_start_is_older_too(self):
        os.makedirs(self.run_dir, 0o700)   # else every client would stop the shared signer and start another old one
        p = subprocess.Popen(FAKE_ARGV + ["--proto", f"{RPC_VERSION - 2}-{RPC_VERSION - 1}"], start_new_session=True,
                             stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait, 10)
        self.addCleanup(p.terminate)
        while autospawn._pid(self.run_dir) is None:
            self.assertIsNone(p.poll())
            time.sleep(0.02)
        older_install = [sys.executable, "-c", f"print({RPC_VERSION - 2}, {RPC_VERSION - 1})"]   # what it answers
        with mock.patch.object(autospawn, "PYTHON", older_install), \
                self.assertRaisesRegex(Incompatible, "runs an older Tracekit than this process imports"):
            Client().status()
        self.assertIsNone(p.poll())

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
        status = json.loads(self.cli("status", "--json"))
        self.assertIn("client_config", status)   # the v1 sections are still there
        self.assertTrue(status["signer_v2"]["running"])
        self.assertIn("dev signer stopped", self.cli("down"))
        self.assertFalse(json.loads(self.cli("status", "--json"))["signer_v2"]["running"])
        self.assertIn("no dev signer running", self.cli("down"))

    def test_status_survives_an_unusable_runtime_dir(self):
        with mock.patch.object(autospawn, "runtime_dir", side_effect=PermissionError("read-only")):
            status = json.loads(self.cli("status", "--json"))
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

    def test_a_tcp_signers_token_given_to_the_client_is_the_one_it_proves(self):
        """The Hermes plugin hands the client the token it reads from Hermes's secret scope; "" when that has none, so
        a profile without one never proves the process environment's (another profile's) token."""
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN": "from-env"}), \
                mock.patch.object(client.tcp_dev, "dial", side_effect=OSError("refused")) as dial:
            for token, proved in (("given", "given"), (None, "from-env")):
                with self.assertRaises(client.SignerUnavailable):
                    Client("tcp://127.0.0.1:7000", timeout=1, token=token).status()
                self.assertEqual(dial.call_args.args[2], proved)
            with self.assertRaisesRegex(client.SignerUnavailable, "need TRACEKIT_SIGNER_TOKEN"):
                Client("tcp://127.0.0.1:7000", timeout=1, token="").status()
        self.assertEqual(dial.call_count, 2)

    def test_missing_token_file_is_signer_unavailable(self):
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN_FILE": os.path.join(tempfile.gettempdir(), "no-such")}):
            c = Client("https://127.0.0.1:1", timeout=1)
        with self.assertRaisesRegex(client.SignerUnavailable, "token file"):
            c.status()

    def test_an_outage_decides_by_the_fail_mode_of_the_tools_class(self):
        run = client.RunHandle(Client("https://127.0.0.1:1", timeout=1),
                               {"run_id": "r1", "run_token": "t", "fail_modes": {"default": "closed", "fs": "open"}})
        with mock.patch.object(client._Https, "post", side_effect=client.SignerUnavailable("down")), \
                warnings.catch_warnings():
            warnings.simplefilter("ignore")
            read = run.decide("c1", "Read", {"file_path": "a.txt"})   # fs in the default policy: open
            bash = run.decide("c2", "Bash", {"command": "ls"})        # shell: the default, closed
            hinted = run.decide("c3", "Read", {"file_path": "a.txt"}, tool_class_hint="shell")
        self.assertEqual([(d["decision"], d["unavailable"]) for d in (read, bash, hinted)],
                         [("allow", True), ("deny", True), ("deny", True)])

    def https(self, answer, timeout=5):
        """A Client of an HTTPS signer whose requests `answer(frame)` answers, in place of the network."""
        def post(_, body, timeout, host=None):
            frame = json.loads(body) if isinstance(body, bytes) else body
            return HELLO if frame["method"] == "hello" else answer(frame)
        patch = mock.patch.object(client._Https, "post", post)
        patch.start()
        self.addCleanup(patch.stop)
        return Client("https://signer.test:8443", timeout=timeout)

    def test_refusals_and_lost_connections_are_counted_apart(self):
        """Two rate limits and a lost connection are not three lost connections: the signer's refusals that run out
        are its RPCError, as before retries, not SignerUnavailable (which would apply the fail mode)."""
        answers, sent = iter([LIMIT, LIMIT, client._ConnectionLost("reset"), LIMIT]), []

        def answer(frame):
            sent.append(frame)
            a = next(answers)
            if isinstance(a, Exception):
                raise a
            return a
        with self.assertRaises(RPCError) as cm:
            self.https(answer).decide({**EVENT, "tool_call_id": "c1", "args": {}})
        self.assertEqual((cm.exception.code, len(sent)), ("quota_exceeded", 4))
        self.assertEqual(len({(f["request_id"], f["stream"], f["client_seq"]) for f in sent}), 1)   # one request

    def test_a_retry_refused_as_already_recorded_raises_the_first_tries_outage(self):
        """The try the signer answered unavailable was written after all, so its retry is client_seq_reused: the caller
        gets that unavailable, its outage path, as without retries. Without an outage before it, the refusal stands."""
        for answers, code in (([OUTAGE, REUSED], "unavailable"), ([REUSED], "client_seq_reused")):
            it = iter(answers)
            with self.subTest(code), self.assertRaises(RPCError) as cm:
                self.https(lambda f: next(it)).decide({**EVENT, "tool_call_id": "c1", "args": {}})
            self.assertEqual((cm.exception.code, cm.exception.message), (code, {
                "unavailable": "storage refused writes", "client_seq_reused": "s/0"}[code]))

    def test_complete_says_whether_its_result_was_recorded(self):
        """A retry refused client_seq_reused after an outage was recorded: no warning. Three lost connections leave it
        unknown: "may not have been recorded", and where to look. A refusal was not recorded, as before."""
        lost = client._ConnectionLost("reset")
        for answers, warning in (
                ([OUTAGE, REUSED], None),
                ([lost] * 3, r"the result of call-1 may not have been recorded \(lost the connection .*\)\. Once the run "
                             r"closes, its bundle has call-1's tool.result if it was, or a decided_not_completed gap"),
                ([MISMATCH], r"the result of call-1 was not recorded: args_mismatch: no\. Once the run closes, its "
                             r"bundle shows call-1 as decided and not completed")):
            it = iter(answers)

            def answer(frame):
                a = next(it)
                if isinstance(a, Exception):
                    raise a
                return a
            run = RunHandle(self.https(answer), {"run_id": "r1", "run_token": "t"})
            with self.subTest(warning), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertIsNone(run.complete("call-1", **DONE))
                said = [str(w.message) for w in caught if "recorded" in str(w.message)]
                if warning:
                    self.assertEqual(len(said), 1, said)
                    self.assertRegex(said[0], warning)
                else:
                    self.assertEqual(said, [])

    def test_a_signer_refusing_connections_records_nothing(self):
        """A fresh client's hello that can't connect sent nothing: the write was not recorded, as the spec's "no signer
        at the first connect" says, and no "may have been recorded"."""
        with socket.socket() as s:   # a port nothing listens on
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        c = Client(f"http://127.0.0.1:{port}", timeout=2)
        with self.assertRaises(client.SignerUnavailable) as cm:
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertIs(cm.exception.recorded, False)
        self.assertNotIn(client.UNKNOWN, str(cm.exception))
        # Windows retries a refused loopback connect for about 2 s: the connect times out instead
        with self.assertWarnsRegex(UserWarning, r"the result of call-1 was not recorded: (lost the connection|could not "
                                                r"connect|no answer from the signer within)"):
            self.assertIsNone(RunHandle(c, {"run_id": "r1", "run_token": "t"}).complete("call-1", **DONE))

    def test_a_connection_a_handler_thread_opened_is_closed_when_the_thread_ends(self):
        """A gateway answers each request on a thread of its own and calls the signer from it: that thread's kept-alive
        connection must not be left for the garbage collector."""
        class Signer(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                frame = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps(HELLO if frame["method"] == "hello" else {}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Signer)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}", timeout=2)
        self.addCleanup(c.close)
        gc.collect()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            for _ in range(3):
                t = threading.Thread(target=c.status)
                t.start()
                t.join()
            gc.collect()
        self.assertEqual([str(x.message) for x in w if issubclass(x.category, ResourceWarning)], [])

    def test_a_signer_gone_after_the_hello_records_nothing_it_refused(self):
        """Once the hello is answered, a connect the signer refuses still sends nothing: not recorded, not "may have
        been". The signer keeps connections alive and closes idle ones, as the real one does: the kept connection it
        closed is not written into."""
        import http.server

        class Signer(http.server.BaseHTTPRequestHandler):
            protocol_version, timeout = "HTTP/1.1", 0.1   # keep-alive; an idle connection is closed after 0.1 s

            def do_POST(self):
                frame = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps(HELLO if frame["method"] == "hello" else {}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Signer)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}", timeout=2)
        self.addCleanup(c.close)
        c.status()   # the hello is cached
        srv.shutdown()
        srv.server_close()   # gone: every connect is refused
        (conns,) = c._https.conns
        (conn,) = conns.by_host.values()   # wait for the signer to close the kept connection
        deadline = time.monotonic() + 5
        while not client._readable(conn.sock) and time.monotonic() < deadline:
            time.sleep(0.05)
        with self.assertRaises(client.SignerUnavailable) as cm:
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertIs(cm.exception.recorded, False)
        self.assertNotIn(client.UNKNOWN, str(cm.exception))
        # Windows retries a refused loopback connect for about 2 s: the connect times out instead
        with self.assertWarnsRegex(UserWarning, r"the result of call-1 was not recorded: (lost the connection|could not "
                                                r"connect|no answer from the signer within)"):
            self.assertIsNone(RunHandle(c, {"run_id": "r1", "run_token": "t"}).complete("call-1", **DONE))

    def test_a_connect_that_times_out_after_the_hello_records_nothing(self):
        """A connect (or TLS handshake) that times out sent nothing: not recorded, not "may have been"."""
        c = Client("http://127.0.0.1:9", timeout=1)
        self.addCleanup(c.close)
        c._https.hello = HELLO   # the hello is cached
        with mock.patch("http.client.HTTPConnection.connect", side_effect=socket.timeout("timed out")):
            with self.assertRaises(client.SignerUnavailable) as cm:
                c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertIs(cm.exception.recorded, False)
        self.assertNotIn(client.UNKNOWN, str(cm.exception))

    def test_a_connection_lost_after_the_request_went_out_may_have_recorded_it(self):
        """A keep-alive signer that answers the hello, then reads the write and closes without answering: the write went
        out, so it may have been recorded (`recorded` None, and the message says so)."""
        import http.server

        class Signer(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"   # keep-alive

            def do_POST(self):
                frame = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if frame["method"] != "hello":
                    self.close_connection = True   # read, never answered
                    return
                body = json.dumps(HELLO).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Signer)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}", timeout=2)
        self.addCleanup(c.close)
        with self.assertRaises(client.SignerUnavailable) as cm:
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertIsNone(cm.exception.recorded)
        self.assertTrue(str(cm.exception).endswith(client.UNKNOWN), str(cm.exception))

    def test_a_write_that_times_out_after_it_went_out_may_have_recorded_it(self):
        """A keep-alive signer that answers the hello, then reads the write and answers only after the client's timeout:
        the write went out, so it may have been recorded (`recorded` None, and the message says so)."""
        import http.server

        class Signer(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"   # keep-alive

            def do_POST(self):
                frame = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if frame["method"] != "hello":
                    time.sleep(1.5)   # read, answered too late
                body = json.dumps(HELLO if frame["method"] == "hello" else {}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Signer)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}", timeout=0.5)
        self.addCleanup(c.close)
        with self.assertRaises(client.SignerUnavailable) as cm:
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertIsNone(cm.exception.recorded)
        self.assertTrue(str(cm.exception).endswith(client.UNKNOWN), str(cm.exception))

    def test_approval_consumes_reason_has_no_unknown_sentence(self):
        """approval_consume's reason goes to the model: no "may have been recorded" sentence; `recorded` stays None."""
        def answer(frame):
            raise client._ConnectionLost("reset")
        run = RunHandle(self.https(answer), {"run_id": "r1", "run_token": "t"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            r = run.approval_consume("c1", "Bash", {"command": "ls"})
        self.assertEqual((r["ok"], r["reason"]), (False, "approval_consume failed: lost the connection to the signer 3 "
                                                         "times (last: reset)"))
        self.assertFalse([w for w in caught if "may have been recorded" in str(w.message)])

    def test_decides_outage_path_is_worded_as_before(self):
        """A decide with no answer may have been recorded (`recorded` None), but its fail mode's warning and reason,
        which integrations hand the agent, carry no "may have been recorded" sentence."""
        def answer(frame):
            raise client._ConnectionLost("reset")
        run = RunHandle(self.https(answer), {"run_id": "r1", "run_token": "t", "fail_modes": {"default": "closed"}})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            d = run.decide("c1", "Bash", {"command": "ls"})
        self.assertEqual((d["decision"], d["reason"]), ("deny", "signer unavailable: lost the connection to the signer "
                                                                "3 times (last: reset)"))
        self.assertFalse([w for w in caught if "may have been recorded" in str(w.message)])

    def test_only_a_write_is_left_unknown(self):
        """`recorded` None means a write's unknown outcome only: a call that writes nothing is False."""
        def answer(frame):
            raise client._unanswered(1)
        with self.assertRaises(client.SignerUnavailable) as cm:
            self.https(answer).status({})
        self.assertIs(cm.exception.recorded, False)
        self.assertNotIn(client.UNKNOWN, str(cm.exception))

    def test_an_error_code_this_client_doesnt_know_is_an_rpc_error(self):
        """A newer signer can answer with an error code this client's ERROR_CODES lacks: the client raised
        AssertionError, which callers that catch RPCError don't handle. It is an RPCError with that code; the signer's
        own errors are still held to ERROR_CODES when they are sent."""
        c = self.https(lambda frame: {"error": {"code": "a_newer_signers_code", "message": "no", "retry_after_ms": 5}})
        with self.assertRaises(RPCError) as raised:
            c.decide({**EVENT, "run_id": "r1", "tool_call_id": "c1", "args": {}})
        self.assertEqual((raised.exception.code, raised.exception.retry_after_ms), ("a_newer_signers_code", 5))
        with self.assertRaises(AssertionError):
            RPCError("a_newer_signers_code", "no").wire()

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
        with mock.patch("http.client.HTTPSConnection", connection):
            c = Client("https://signer.test:8443", timeout=5)
            c.status()
            t = threading.Thread(target=c.status)
            t.start()
            t.join(10)
            c.close()
        self.assertEqual([conn.close.call_count for conn in conns], [1, 1])

    def test_retry_after_lost_connection_stops_at_call_timeout(self):
        sent = []

        def answer(frame):
            sent.append(frame)
            time.sleep(0.18)
            raise client._ConnectionLost("reset")
        c = self.https(answer, timeout=0.1)
        t = time.monotonic()
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 0\.1s"):
            c.decide({**EVENT, "tool_call_id": "c1", "args": {}})
        self.assertEqual(len(sent), 1)
        self.assertLess(time.monotonic() - t, 0.5)

    def test_timed_out_call_before_first_try_uses_its_client_seq(self):
        seen = []
        c = self.https(lambda frame: seen.append(frame["client_seq"]) or {"ok": True}, timeout=0)
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 0s"):
            c.decide({**EVENT, "tool_call_id": "c1", "args": {}})
        c.timeout = 2
        c.decide({**EVENT, "tool_call_id": "c2", "args": {}})
        self.assertEqual(seen, [1])

    def test_slow_http_hello_bounds_call_and_reports_call_timeout(self):
        calls, done = [], threading.Event()
        self.addCleanup(done.set)

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if req["method"] == "hello":
                    done.wait(0.5)
                    body = json.dumps(HELLO).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    calls.append(req["method"])
                    done.wait(5)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}", timeout=2.0)
        self.addCleanup(c.close)
        t = time.monotonic()
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 2s"):
            c.status()
        self.assertLess(time.monotonic() - t, 2.5)
        self.assertEqual(calls, ["status"])

    def test_slow_dial_does_not_send_past_deadline(self):
        from tracekit.identity.token import DevToken
        from tracekit.signer.rpc_schema import REQUESTS
        from tracekit.transport.tcp_dev import TcpDevServer
        seen = []
        ep = os.path.join(tempfile.mkdtemp(), "ep.json")
        self.addCleanup(shutil.rmtree, os.path.dirname(ep), True)
        srv = TcpDevServer(ep, DevToken("dev", [*REQUESTS, "hello"], ttl_s=600),
                           lambda _, f: HELLO if f["method"] == "hello"
                           else seen.append(f.get("client_seq")) or {"ok": True})
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port = json.load(open(ep))["port"]
        real_connect = client.connect

        def slow_connect(path, timeout=client.CONNECT_TIMEOUT_S, token=None):
            out = real_connect(path, timeout=timeout, token=token)
            time.sleep(0.25)
            return out

        c = Client(f"tcp://127.0.0.1:{port}", timeout=0.15, token=srv.token.secret)
        self.addCleanup(c.close)
        with mock.patch.object(client, "connect", side_effect=slow_connect):
            with self.assertRaisesRegex(client.SignerUnavailable, r"within 0\.15s"):
                c.decide({**EVENT, "tool_call_id": "c1", "args": {}})
        self.assertIsNotNone(c._conn)
        self.assertEqual(list(c._conn.pending), [])
        self.assertEqual(seen, [])
        c.timeout = 2
        c.decide({**EVENT, "tool_call_id": "c2", "args": {}})
        self.assertEqual(seen, [1])

    def _silent_tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        self.addCleanup(srv.close)
        held = []

        def accept_all():
            with contextlib.suppress(OSError):
                while True:
                    conn, _ = srv.accept()
                    held.append(conn)
        threading.Thread(target=accept_all, daemon=True).start()
        self.addCleanup(lambda: [s.close() for s in held])
        return f"tcp://127.0.0.1:{srv.getsockname()[1]}"

    def test_stalled_tcp_connect_stops_within_call_timeout(self):
        c = Client(self._silent_tcp(), timeout=0.12, token="0" * 32)
        t = time.monotonic()
        with self.assertRaises(client.SignerUnavailable):
            c.status()
        self.assertLess(time.monotonic() - t, 1.0)

    def test_hung_tcp_signer_reports_signer_address_at_connect_timeout(self):
        _assert_hung_connect_reports_address(self, self._silent_tcp(), token="0" * 32)

    def test_parallel_tcp_calls_share_deadline_behind_dial(self):
        _assert_parallel_calls_share_deadline(self, self._silent_tcp(), token="0" * 32)

    def test_expired_deadline_in_send_does_not_format_negative_timeout(self):
        c = Client("tcp://127.0.0.1:1", timeout=1, token="0" * 32)
        self.addCleanup(c.close)
        with self.assertRaisesRegex(client._TimeoutUnavailable, r"^no time left after waiting for another call$"):
            c._send(
                "decide",
                {**EVENT, "request_id": "req-1", "tool_call_id": "c1", "args": {}},
                1,
                time.monotonic() - 0.3,
            )
        self.assertEqual(c._seqs.get("r1"), 1)


def _assert_hung_connect_reports_address(test, addr, **kwargs):
    c = Client(addr, timeout=5, **kwargs)
    test.addCleanup(c.close)
    errs = {}

    def run(name, fn):
        try:
            fn()
        except BaseException as e:
            errs[name] = e

    t = time.monotonic()
    threads = [
        threading.Thread(target=run, args=("status", lambda: c.status({}))),
        threading.Thread(target=run, args=("wait", lambda: c.approval_wait(
            {"run_id": "r1", "run_token": "t", "approval_id": "a1", "timeout_ms": 0}))),
    ]
    for th in threads:
        th.start()
    for th in threads:
        th.join(6)
    test.assertLess(time.monotonic() - t, 3.5)
    for name in ("status", "wait"):
        e = errs.get(name)
        test.assertIsInstance(e, client.SignerUnavailable, f"{name}: {e!r}")
        test.assertRegex(str(e), rf"^no signer answering at {re.escape(addr)}: timed out$")


def _assert_parallel_calls_share_deadline(test, addr, **kwargs):
    c = Client(addr, timeout=1, **kwargs)
    test.addCleanup(c.close)
    res = [None] * 4
    start = time.monotonic()

    def run(i):
        try:
            c.status({})
        except BaseException as e:
            res[i] = (e, time.monotonic() - start)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(6)
    for i, item in enumerate(res):
        test.assertIsNotNone(item, f"thread {i} did not finish")
        e, elapsed = item
        test.assertIsInstance(e, client.SignerUnavailable, f"thread {i}: {e!r}")
        test.assertRegex(str(e), r"within 1s")
        test.assertLess(elapsed, 1.5, f"thread {i} took {elapsed:.2f}s")


HELLO = {"proto": [RPC_VERSION, RPC_VERSION], "version": __version__, "pid": os.getpid()}
EVENT = {"run_id": "r1", "run_token": "t", "tool": "Bash", "args_source": "parsed"}
LIMIT = {"error": {"code": "quota_exceeded", "message": "event rate limit", "retry_after_ms": 5}}
OUTAGE = {"error": {"code": "unavailable", "message": "storage refused writes"}}
REUSED = {"error": {"code": "client_seq_reused", "message": "s/0"}}
MISMATCH = {"error": {"code": "args_mismatch", "message": "no"}}
DONE = {"decision_id": "d1", "args_digest": "sha256:" + "0" * 64}


class RunExit(unittest.TestCase):
    """The end of a `with` block of a run: a signer that can't be reached warns (it closes the run after its idle
    timeout), and the block's own exception is never masked."""

    def handle(self):
        return RunHandle(Client(signer="/nonexistent/tracekit.sock"), {"run_id": "r", "run_token": "t"})

    def test_an_unreachable_signer_warns(self):
        with self.assertWarnsRegex(UserWarning, "run r was not closed: the signer can't be reached .* idle timeout"):
            with self.handle():
                pass

    def test_a_close_that_may_have_been_recorded_says_so(self):
        e = client._unanswered(1)   # went out, no answer: `recorded` None
        with mock.patch.object(Client, "call", side_effect=e), self.assertWarns(UserWarning) as cm:
            with self.handle():
                pass
        self.assertRegex(str(cm.warning), r"^tracekit: run r may not have been closed: the signer can't be reached "
                                          r"\(no answer .*\); it closes the run after its idle timeout$")

    def test_the_blocks_exception_is_never_masked(self):
        for refusal in (None, RPCError("run_closed", "r")):
            patch = mock.patch.object(Client, "call", side_effect=refusal) if refusal else contextlib.nullcontext()
            with self.subTest(refusal=refusal), patch, self.assertWarns(UserWarning), self.assertRaises(KeyError):
                with self.handle():
                    raise KeyError("the app's own")

        async def go():
            async with AsyncRunHandle(self.handle()):
                raise KeyError("the app's own")
        with self.assertWarns(UserWarning), self.assertRaises(KeyError):
            asyncio.run(go())

    def test_a_refusal_without_an_exception_still_raises(self):
        with mock.patch.object(Client, "call", side_effect=RPCError("forbidden", "no")), self.assertRaises(RPCError):
            with self.handle():
                pass


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

    def drops_the_first(self, retry=None):
        """A signer that answers hello, reads each request and shuts its connection down; then it stops listening
        (`retry` None) or answers the request's retry with `retry`. -> the requests it read."""
        srv, frames, held = socket.socket(socket.AF_UNIX), [], []
        srv.bind(self.path)
        srv.listen()

        def serve():
            with contextlib.suppress(OSError):   # closed by the cleanup, or by itself
                while True:
                    conn, _ = srv.accept()
                    held.append(conn)
                    rfile = conn.makefile("rb")
                    rfile.readline()
                    conn.sendall((json.dumps(HELLO) + "\n").encode())
                    for line in iter(rfile.readline, b""):
                        frames.append(json.loads(line))
                        if [f["request_id"] for f in frames].count(frames[-1]["request_id"]) > 1:
                            conn.sendall((json.dumps(retry) + "\n").encode())
                            continue
                        if retry is None:
                            srv.close()
                        conn.shutdown(socket.SHUT_RDWR)   # close() alone: rfile keeps the descriptor open, no drop seen
                        break
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(lambda: [s.close() for s in held + [srv]])
        return frames

    def test_a_signer_gone_after_reading_complete_may_have_recorded_it(self):
        self.drops_the_first()
        run = RunHandle(Client(self.path, timeout=2), {"run_id": "r1", "run_token": "t"})
        with self.assertWarnsRegex(UserWarning, r"the result of call-1 may not have been recorded \(no signer answering "
                                                r"at .*\)\. Once the run closes, its bundle has call-1's tool.result if "
                                                r"it was, or a decided_not_completed gap if it wasn't\.$"):
            self.assertIsNone(run.complete("call-1", **DONE))

    def test_a_retry_refused_as_already_recorded_after_a_drop_was_recorded(self):
        frames = self.drops_the_first(REUSED)
        c = Client(self.path, timeout=2)
        run = RunHandle(c, {"run_id": "r1", "run_token": "t"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertIsNone(run.complete("call-1", **DONE))
        self.assertEqual([str(w.message) for w in caught if "recorded" in str(w.message)], [])
        with self.assertRaises(RPCError) as cm:   # the next event: its first try dropped, its retry refused
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-2", "status": "ok", **DONE})
        self.assertEqual((cm.exception.code, cm.exception.recorded), ("client_seq_reused", True))
        self.assertEqual([(f["tool_call_id"], f["client_seq"]) for f in frames],   # each request sent twice, as it was
                         [("call-1", 0), ("call-1", 0), ("call-2", 1), ("call-2", 1)])

    def test_a_write_that_times_out_after_it_went_out_may_have_recorded_it(self):
        """A signer that reads complete and never answers: the write went out, so it may have been recorded (`recorded`
        None, and the message says so)."""
        frames = self.stalled()
        c = Client(self.path, timeout=0.5)
        self.addCleanup(c.close)
        with self.assertRaises(client.SignerUnavailable) as cm:
            c.complete({"run_id": "r1", "run_token": "t", "tool_call_id": "call-1", "status": "ok", **DONE})
        self.assertEqual([f["tool_call_id"] for f in frames], ["call-1"])
        self.assertIsNone(cm.exception.recorded)
        self.assertTrue(str(cm.exception).endswith(client.UNKNOWN), str(cm.exception))

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

    def test_close_run_names_the_last_client_seq_used_even_one_the_signer_never_saw(self):
        c, frames = Client(self.path, timeout=2), []
        with self.assertRaises(client.SignerUnavailable):   # no signer yet: client_seq 0 is used up, never received
            c.decide({**EVENT, "tool_call_id": "lost", "args": {}})
        self.serve(lambda frame: frames.append(frame) or {"ok": True})
        c.close_run({"run_id": "r1", "run_token": "t"})
        c.close_run({"run_id": "r2", "run_token": "t"})   # a run with no events names none
        self.assertEqual([f.get("last_client_seq") for f in frames],
                         [[{"stream": c.stream, "client_seq": 0}], None])

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
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 0\.3s"):
            c.approval_wait({"run_id": "r1", "run_token": "t", "approval_id": "a1", "timeout_ms": 0})
        self.assertEqual([f["method"] for f in frames], ["approval_wait"])

    def test_retry_after_dropped_unix_connection_stops_on_slow_reconnect_hello(self):
        srv, frames, held, done = socket.socket(socket.AF_UNIX), [], [], threading.Event()
        srv.bind(self.path)
        srv.listen()
        self.addCleanup(lambda: [s.close() for s in held + [srv]])

        def serve():
            try:
                for idx in (1, 2):
                    conn, _ = srv.accept()
                    held.append(conn)
                    with conn.makefile("rb") as rfile:
                        rfile.readline()
                        if idx == 2:
                            time.sleep(1.5)
                        conn.sendall((json.dumps(HELLO) + "\n").encode())
                        conn.settimeout(0.2)
                        line = rfile.readline()
                        if line:
                            frames.append(json.loads(line))
                        if idx == 1:
                            conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                done.set()
        threading.Thread(target=serve, daemon=True).start()
        c = Client(self.path, timeout=0.5)
        self.addCleanup(c.close)
        t = time.monotonic()
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 0\.5s"):
            c.status({})
        self.assertLess(time.monotonic() - t, 1.0)
        done.wait(3)
        self.assertEqual(len(frames), 1)

    def test_reconnect_after_slow_hello_bounds_answer_wait(self):
        srv, held, stop = socket.socket(socket.AF_UNIX), [], threading.Event()
        srv.bind(self.path)
        srv.listen()
        self.addCleanup(lambda: [s.close() for s in held + [srv]])

        def serve():
            with contextlib.suppress(OSError):
                for idx in (1, 2):
                    conn, _ = srv.accept()
                    held.append(conn)
                    with conn.makefile("rb") as rfile:
                        rfile.readline()
                        if idx == 2:
                            stop.wait(0.35)
                        conn.sendall((json.dumps(HELLO) + "\n").encode())
                        rfile.readline()
                        if idx == 1:
                            conn.shutdown(socket.SHUT_RDWR)
                        else:
                            stop.wait(5)
        threading.Thread(target=serve, daemon=True).start()
        c = Client(self.path, timeout=0.5)
        self.addCleanup(c.close)
        self.addCleanup(stop.set)
        t = time.monotonic()
        with self.assertRaisesRegex(client.SignerUnavailable, r"within 0\.5s"):
            c.status({})
        self.assertLess(time.monotonic() - t, 0.75)

    def _silent_unix(self):
        srv, held, stop = socket.socket(socket.AF_UNIX), [], threading.Event()
        srv.bind(self.path)
        srv.listen(8)
        self.addCleanup(lambda: [s.close() for s in held + [srv]])
        self.addCleanup(stop.set)

        def serve():
            with contextlib.suppress(OSError):
                while not stop.is_set():
                    conn, _ = srv.accept()
                    held.append(conn)
        threading.Thread(target=serve, daemon=True).start()
        return self.path

    def test_hung_unix_signer_reports_signer_address_at_connect_timeout(self):
        _assert_hung_connect_reports_address(self, self._silent_unix())

    def test_parallel_unix_calls_share_deadline_behind_dial(self):
        _assert_parallel_calls_share_deadline(self, self._silent_unix())

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


class Stops(unittest.TestCase):
    def test_a_stop_is_the_clients_and_the_claude_code_hook_names_it_too(self):
        """stopped and stop_rules are the client's, for every adapter's stop; the Claude Code hook's names for them
        (claude_code.stopped, _rules) are the same functions."""
        from tracekit.integrations import claude_code
        self.assertIs(claude_code.stopped, client.stopped)
        self.assertIs(claude_code._rules, client.stop_rules)
        self.assertEqual(client.stop_rules(["TK-UNKNOWN-TOOL"]), "")
        said = client.stopped(f"BLOCKED, nothing ran{client.stop_rules(['R1', 'TK-UNKNOWN-TOOL'])}.",
                              "why" + INSTEAD + "do x")
        self.assertEqual(said.splitlines()[:3], ["[tracekit] BLOCKED, nothing ran (R1).", "Why: why", "Instead: do x"])


if __name__ == "__main__":
    unittest.main()
