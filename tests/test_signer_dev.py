"""`tracekit signer serve --dev` auto-spawned by the v2 client, end to end with no fakes."""
import contextlib
import io
import json
import os
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

from factories import wait_for
from tracekit import __version__, cli
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import service
from tracekit.signer.rpc_schema import RPC_VERSION
from tracekit.storage.file import FileReader
from tracekit.transport import tcp_dev, read_frame, write_frame

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(os.name == "posix", "POSIX paths, signals and shells; DevSignerOverTcp (test_signer_dev.py) runs everywhere")
class DevSignerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_IDLE": "60",
                                           "PYTHONPATH": ROOT, "HOME": os.path.join(self.dir, "home"),
                                           "XDG_DATA_HOME": os.path.join(self.dir, "data")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("TRACEKIT_SIGNER", None)
        self.addCleanup(autospawn.down)

    def path(self, name):
        return os.path.join(self.run_dir, name)

    def held(self):
        return autospawn._held(self.path(autospawn.LOCK))

    def wait_released(self, timeout=20):
        deadline = time.monotonic() + timeout
        while self.held():
            self.assertLess(time.monotonic(), deadline, "the signer did not exit")
            time.sleep(0.05)

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(list(argv)), 0)
        return out.getvalue()

    def one_run(self, client):
        with client.run("e2e") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            events = run.call("read")["events"]
        self.assertEqual(events[0]["data"]["signer_isolation"], "same-user")
        return client.hello["pid"]

    def test_autospawn_reuse_down_sigkill_and_verify(self):
        first = Client()
        pid = self.one_run(first)
        first.close()
        self.assertEqual(autospawn._pid(self.run_dir), pid)
        data_dir = service.dev_data_dir()
        self.assertEqual(os.stat(data_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(data_dir, "keys", "record.key")).st_mode & 0o777, 0o600)
        second = Client()
        self.assertEqual(self.one_run(second), pid)   # reuses the running signer
        second.close()

        self.assertIn(f"dev signer stopped (pid {pid})", self.cli("down"))
        self.assertFalse(os.path.exists(self.path(autospawn.SOCK)))
        self.assertFalse(os.path.exists(self.path(autospawn.ENDPOINT)))

        third = Client()
        killed = self.one_run(third)
        self.assertNotEqual(killed, pid)
        os.kill(killed, signal.SIGKILL)
        self.wait_released()
        fourth = Client()
        self.assertNotIn(self.one_run(fourth), (pid, killed))   # stale socket and endpoint replaced
        fourth.close()
        third.close()
        self.cli("down")
        self.assertEqual(service.fsck(data_dir), [])   # one chain across all three signers, every signature valid

    def test_dev_run_exports_and_verifies_while_the_signer_runs(self):
        c = Client()
        self.addCleanup(c.close)
        with c.run("e2e") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            self.assertEqual(run.decide("c2", "tracekit_demo_denied", "{}")["decision"], "deny")
        store = os.path.join(service.dev_data_dir(), "store")
        self.assertTrue(wait_for(lambda: list(FileReader(store).iter_run("default", run.run_id))[-1]["event"]["type"]
                                 == "run.final", 20), "no run.final after the grace window")
        vkey = self.cli("signer", "vkey", "--dev").strip()
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, "run.tkb")
        self.cli("signer", "trust", "--dev", "-o", trust)
        with open(trust) as f:
            self.assertEqual(json.load(f), {"logs": [vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0})
        self.cli("export", "--v2", "--run", run.run_id, "--dev", "-o", out)
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev;", self.cli("verify", out, "--trust", trust))
        self.assertTrue(self.held())   # the signer kept running throughout

    def test_idle_exit(self):
        os.environ["TRACEKIT_DEV_IDLE"] = "1"
        c = Client()
        c.status()
        time.sleep(1.5)
        self.assertTrue(self.held())   # an open connection keeps it alive
        c.close()
        self.wait_released()
        self.assertFalse(os.path.exists(self.path(autospawn.SOCK)))
        self.assertFalse(os.path.exists(self.path(autospawn.ENDPOINT)))

    def test_up_wait_json(self):
        hello = json.loads(self.cli("up", "--wait", "--json"))
        self.assertEqual(hello["proto"], [RPC_VERSION, RPC_VERSION])
        self.assertEqual(hello["version"], __version__)
        with open(self.path(autospawn.ENDPOINT)) as f:
            self.assertEqual(json.load(f), hello)

    def test_hello_over_tcp(self):
        os.makedirs(self.run_dir, 0o700)
        ep = self.path("tcp.json")
        svc = service.SignerService(os.path.join(self.dir, "tcp-data"))
        self.addCleanup(svc.close)
        (server,) = service.serve({"tcp_endpoint": ep}, svc)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        sock, rfile = tcp_dev.connect(ep)
        with sock:
            write_frame(sock, {"method": "hello"})
            self.assertEqual(read_frame(rfile)["proto"], [RPC_VERSION, RPC_VERSION])


class DevSignerOverTcp(unittest.TestCase):
    """The loopback TCP transport (Windows, decision S3), forced on every OS by hiding AF_UNIX from both sides."""
    NO_UNIX = "import socket, sys; socket.__dict__.pop('AF_UNIX', None); from tracekit.cli import main; sys.exit(main())"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        for p in (mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_IDLE": "60",
                                               "PYTHONPATH": ROOT, "HOME": os.path.join(self.dir, "home"),
                                               "XDG_DATA_HOME": os.path.join(self.dir, "data"),
                                               "LOCALAPPDATA": os.path.join(self.dir, "data")}),
                  mock.patch.dict(socket.__dict__),
                  mock.patch.object(autospawn, "SIGNER_ARGV", [sys.executable, "-c", self.NO_UNIX, "signer", "serve", "--dev"])):
            p.start()
            self.addCleanup(p.stop)
        socket.__dict__.pop("AF_UNIX", None)
        os.environ.pop("TRACEKIT_SIGNER", None)
        self.addCleanup(autospawn.down)

    def test_autospawned_dev_signer(self):
        c = Client()
        with c.run("tcp") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            self.assertEqual(run.call("read")["events"][0]["data"]["signer_isolation"], "same-user")
        c.close()
        out, trust = os.path.join(self.dir, "run.tkb"), os.path.join(self.dir, "trust.json")
        DevSignerEndToEnd.cli(self, "export", "--v2", "--run", run.run_id, "-o", out)   # nudges the signer over TCP
        DevSignerEndToEnd.cli(self, "signer", "trust", "-o", trust)
        self.assertIn("Integrity: VERIFIED", DevSignerEndToEnd.cli(self, "verify", out, "--trust", trust))
        endpoint = os.path.join(self.run_dir, autospawn.ENDPOINT)
        with open(endpoint) as f:
            self.assertEqual(json.load(f)["pid"], c.hello["pid"])
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, autospawn.SOCK)))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(endpoint).st_mode), 0o600)
            os.chmod(endpoint, 0o644)
            with self.assertRaisesRegex(SignerUnavailable, "readable by no one else"):
                Client().status()

    def test_named_signer_with_a_token(self):
        ep = os.path.join(self.dir, "tcp.json")
        svc = service.SignerService(os.path.join(self.dir, "tcp-data"))
        self.addCleanup(svc.close)
        (server,) = service.serve({"tcp_endpoint": ep}, svc)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with open(ep) as f:
            published = json.load(f)
        os.environ["TRACEKIT_SIGNER"] = f"tcp://127.0.0.1:{published['port']}"
        with self.assertRaisesRegex(SignerUnavailable, "need TRACEKIT_SIGNER_TOKEN"):
            Client().status()
        os.environ["TRACEKIT_SIGNER_TOKEN"] = "0" * 64
        with self.assertRaisesRegex(SignerUnavailable, "proof mismatch"):
            Client().status()
        os.environ["TRACEKIT_SIGNER_TOKEN"] = published["token"]
        c = Client()
        self.addCleanup(c.close)
        self.assertEqual(c.status()["identity"]["scheme"], "token")


if __name__ == "__main__":
    unittest.main()
