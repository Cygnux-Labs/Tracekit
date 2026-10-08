import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import client, ingest, install  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from factories import ledger_records, patch_env  # noqa: E402


class Sanitize(unittest.TestCase):
    def ok(self, **kw):
        ev = {"run_id": "r1", "source": "sdk", "type": "tool.call", "data": {}}
        ev.update(kw)
        return ingest.sanitize({"op": "append", "event": ev, "cseq": 3}, "bot", "10.0.0.9")

    def test_namespaces_the_run_and_forces_sdk_stream(self):
        req, err = self.ok()
        self.assertIsNone(err)
        self.assertEqual(req["event"]["run_id"], "remote:bot:r1")
        self.assertEqual((req["stream"], req["cseq"]), ("sdk", 3))

    def test_run_start_host_names_the_remote_client(self):
        req, _ = self.ok(type="run.start", data={"host": "i-claim-to-be-root", "os_user": "root"})
        self.assertEqual(req["event"]["data"]["host"], "remote:bot@10.0.0.9")
        self.assertEqual(req["event"]["data"]["signer_isolation"], "same-user")  # the signer's real isolation, not the client's claim

    def test_refuses_what_a_remote_client_may_not_write(self):
        for bad in ({"source": "hook"}, {"source": "proxy"}, {"type": "capture.gap"}, {"type": "trace.tamper"},
                    {"type": "checkpoint"}, {"transcript": {"path": "/x"}}, {"run_id": "../../x"}, {"run_id": ""},
                    {"run_id": "a" * 200}, {"run_id": 5}):
            self.assertIsNotNone(self.ok(**bad)[1], bad)
        for op in ("approve", "approval_request", "checkpoint", "export", None):
            self.assertIsNotNone(ingest.sanitize({"op": op}, "bot", "x")[1], op)
        self.assertIsNotNone(ingest.sanitize([], "bot", "x")[1])

    def test_attach_only_carries_policy(self):
        req, _ = ingest.sanitize({"op": "append", "event": {"run_id": "r", "source": "sdk", "type": "run.end", "data": {}},
                                  "attach": {"policy": {"a": 1}, "evil": 1}}, "bot", "x")
        self.assertEqual(req["attach"], {"policy": {"a": 1}})


class Tokens(unittest.TestCase):
    def test_token_is_stored_hashed_and_authenticates(self):
        d = tempfile.mkdtemp()
        token = ingest.add_token(d, "build-1")
        raw = open(os.path.join(d, ingest.TOKENS_FILE)).read()
        self.assertNotIn(token, raw)
        self.assertEqual(ingest.authenticate(ingest.load_tokens(d), "Bearer " + token), "build-1")
        self.assertIsNone(ingest.authenticate(ingest.load_tokens(d), "Bearer nope"))
        self.assertIsNone(ingest.authenticate(ingest.load_tokens(d), token))
        with self.assertRaises(ValueError):
            ingest.add_token(d, "build-1")
        with self.assertRaises(ValueError):
            ingest.add_token(d, "bad name!")
        if os.name != "nt":  # Windows has no POSIX permission bits
            self.assertEqual(oct(os.stat(os.path.join(d, ingest.TOKENS_FILE)).st_mode & 0o777), "0o600")
        shutil.rmtree(d)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        patch_env(self)
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "gateway-client")
        install.init_dev(self.home, [], start=True)
        self.token = ingest.add_token(self.home, "agent-box")
        local_cfg = client.client_config()  # the gateway process's own view: it forwards to the local signer
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), ingest.make_handler(self.home, forward=lambda req: client._rpc(req, config=local_cfg)))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]
        self.gateway_client_home = os.environ["TRACEKIT_CLIENT_HOME"]

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()
        install.stop_dev_daemon(self.home)
        shutil.rmtree(self.d, ignore_errors=True)

    def as_remote(self):
        """Switch this process's client config to the remote agent's view (the gateway's forward is already bound)."""
        home = os.path.join(self.d, "remote-client")
        os.makedirs(home)
        with open(os.path.join(home, "config.json"), "w") as f:
            json.dump({"socket": f"http://127.0.0.1:{self.port}", "socket_token": self.token, "mode": "remote"}, f)
        os.environ["TRACEKIT_CLIENT_HOME"] = home

    def events(self):
        return [r["event"] for r in ledger_records(self.home) if not r.get("elided")]

    def test_remote_sdk_run_lands_in_the_ledger_namespaced_and_policy_still_applies(self):
        self.as_remote()
        ran = []
        with Tracer(agent="remote-bot", session_id="job-7", cwd=self.d) as t:
            with t.tool("Bash", {"command": "ls"}) as call:
                ran.append("ls"); call.result({"ok": True})
            with self.assertRaises(PermissionError):
                with t.tool("Bash", {"command": "sudo id"}):
                    ran.append("sudo")
        self.assertEqual(ran, ["ls"])
        evs = [e for e in self.events() if e["run_id"].startswith("remote:")]
        self.assertTrue(evs and all(e["run_id"] == "remote:agent-box:job-7" and e["source"] == "sdk" for e in evs))
        start = next(e for e in evs if e["type"] == "run.start")
        self.assertTrue(start["data"]["host"].startswith("remote:agent-box@"))
        self.assertEqual(sum(1 for e in evs if e["type"] == "run.end"), 1)
        self.assertFalse(any(e["type"] == "capture.gap" for e in self.events()), "counters must stay in step through the gateway")

    def post(self, body, token=None, path="/v1/rpc"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        c.request("POST", path, body=body if isinstance(body, bytes) else json.dumps(body), headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"{}")

    def test_http_level_rejections(self):
        self.assertEqual(self.post({"op": "status"})[0], 401)
        self.assertEqual(self.post({"op": "status"}, token="wrong")[0], 401)
        self.assertEqual(self.post({"op": "approve"}, self.token)[0], 400)
        self.assertEqual(self.post(b"{nope", self.token)[0], 400)
        self.assertEqual(self.post({"op": "status"}, self.token, path="/other")[0], 404)
        try:  # the server refuses an oversize body before reading it, so the client may see 413 or a closed connection
            self.assertEqual(self.post(b"x" * (ingest.MAX_BODY + 1), self.token)[0], 413)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def test_rate_limit(self):
        # no refill during the test: on a slow machine 100/s refill could otherwise keep the bucket from emptying
        old = ingest.RATE_PER_S
        ingest.RATE_PER_S = 0.0
        try:
            codes = {self.post({"op": "bogus"}, self.token)[0] for _ in range(int(ingest.BURST) + 40)}
        finally:
            ingest.RATE_PER_S = old
        self.assertIn(429, codes)

    def test_ask_rules_are_refused_remotely(self):
        self.as_remote()
        pol = os.path.join(self.d, "ask.yaml")
        with open(pol, "w") as f:
            f.write("extends: default\nask:\n  - id: X-ASK\n    tool: Bash\n    pattern: '^deploy'\n    reason: deploys need a human\n")
        os.environ["TRACEKIT_POLICY"] = pol
        try:
            with Tracer(agent="remote-bot", session_id="job-8", cwd=self.d) as t:
                with self.assertRaises(PermissionError) as cm:
                    with t.tool("Bash", {"command": "deploy prod"}):
                        self.fail("must not run")
            self.assertIn("not available for remote", str(cm.exception))
        finally:
            os.environ.pop("TRACEKIT_POLICY", None)


class ClientConfig(unittest.TestCase):
    def test_plain_http_to_a_remote_host_is_refused(self):
        with self.assertRaises(client.SignerUnavailable):
            client._http_rpc("http://example.com", {"socket_token": "t"}, {"op": "status"}, 1)

    def test_init_remote_writes_a_private_config(self):
        import argparse
        from tracekit import cli
        d = tempfile.mkdtemp()
        patch_env(self)
        os.environ["TRACEKIT_CLIENT_HOME"] = d
        try:
            tf = os.path.join(d, "tok")
            open(tf, "w").write("tk_abc\n")
            rc = cli._init_remote(argparse.Namespace(remote="https://tk.example:8443/", token_file=tf))
            self.assertEqual(rc, 0)
            cfg = json.load(open(os.path.join(d, "config.json")))
            self.assertEqual((cfg["socket"], cfg["socket_token"]), ("https://tk.example:8443", "tk_abc"))
            if os.name != "nt":  # Windows has no POSIX permission bits
                self.assertEqual(oct(os.stat(os.path.join(d, "config.json")).st_mode & 0o777), "0o600")
            self.assertEqual(cli._init_remote(argparse.Namespace(remote="http://evil.example", token_file=tf)), 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
