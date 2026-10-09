"""Witness service (#17): signer publishes checkpoints, verifiers check inclusion and consistency, forks are refused,
and a witness that rewrites its own log is caught.  python3 -m pytest tests/test_witness_server.py -q"""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import bundle, install, witness_server  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from tracekit.witness import HttpWitness, from_spec  # noqa: E402
from factories import patch_env  # noqa: E402


class Service(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        patch_env(self)
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        self.whome = os.path.join(self.d, "witness")
        self.wpub, _ = witness_server.init(self.whome)
        self.srv = witness_server.serve(self.whome, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        # register the signer's key with the witness before the signer starts publishing to it
        self.home = os.path.join(self.d, "signer")
        from tracekit.ledger import Keys
        self.signer_pub = Keys.load_or_create(os.path.join(self.home, "keys")).public
        tok = witness_server.add_token(self.whome, "box", self.signer_pub)
        self.tok = os.path.join(self.d, "w.token")
        open(self.tok, "w").write(tok)
        self.spec = f"{self.url}#token={self.tok}&key={self.wpub}"
        install.init_dev(self.home, [self.spec], start=True, checkpoint_every=3)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.d, ignore_errors=True)

    def run_agent(self, sid="w-1"):
        with Tracer(agent="bot", session_id=sid, cwd=self.d) as t:
            for i in range(4):
                with t.tool("Bash", {"command": f"echo {i}"}) as c:
                    c.result("ok")

    def test_publish_verify_against_the_service(self):
        self.run_agent()
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out, run="w-1")
        read_spec = f"{self.url}#key={self.wpub}&state={os.path.join(self.d, 'sth.json')}"
        self.assertTrue(from_spec(read_spec).read(), "checkpoints reached the witness")
        rep, code = bundle.verify(out, [read_spec])
        self.assertEqual(code, 0, rep.failures)
        self.assertTrue(any(c["check"] == "trust root" and c["status"] == "pass" for c in rep.checks))

    def test_fork_is_refused_and_recorded(self):
        self.run_agent()
        w = HttpWitness(self.spec)
        cps = w.read()
        forged = dict(cps[-1], head_hash="f" * 64)
        from tracekit.ledger import Keys
        from tracekit.witness import make_checkpoint
        keys = Keys.load_or_create(os.path.join(self.home, "keys"))  # an attacker holding the real signing key
        fork = make_checkpoint(forged["head_seq"], forged["head_hash"], keys, ts=forged["ts"])
        with self.assertRaises(RuntimeError) as cm:
            w.publish(fork)
        self.assertIn("409", str(cm.exception))
        code, r = w._http("GET", "/v1/conflicts")
        self.assertEqual(r["conflicts"][-1]["offered_hash"], "f" * 64)

    def test_wrong_signer_and_no_token_are_rejected(self):
        from tracekit import crypto
        from tracekit.witness import make_checkpoint
        secret, public = crypto.generate()

        class K:
            pass
        k = K()
        k.secret, k.kid = secret, crypto.kid(public)
        cp = make_checkpoint(0, "a" * 64, k)
        w = HttpWitness(self.spec)
        self.assertEqual(w._http("POST", "/v1/checkpoints", cp, open(self.tok).read())[0], 403)
        self.assertEqual(w._http("POST", "/v1/checkpoints", cp, "tkw_nope")[0], 401)

    def test_unpinned_reads_are_refused(self):
        with self.assertRaises(ValueError):
            HttpWitness(self.url).read()
        with self.assertRaises(ValueError):
            HttpWitness("http://example.com")  # plain http off-loopback
        for url in ("http://localhost.example", "http://127.0.0.1@example.com"):
            with self.assertRaises(ValueError, msg=url):
                HttpWitness(url)

    def test_redirects_are_not_followed(self):
        import http.server

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/v1/sth")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        self.assertEqual(HttpWitness(f"http://127.0.0.1:{srv.server_address[1]}")._http("GET", "/v1/sth", token="t")[0], 302)

    def test_a_witness_that_rewrites_its_log_is_caught(self):
        self.run_agent("w-a")
        state = os.path.join(self.d, "sth.json")
        reader = HttpWitness(f"{self.url}#key={self.wpub}&state={state}")
        reader.read()  # remember the current tree head
        self.srv.shutdown()
        self.srv.server_close()
        logp = os.path.join(self.whome, "log.jsonl")
        lines = open(logp).read().splitlines()
        e = json.loads(lines[0])
        e["cp"]["ts"] = "2000-01-01T00:00:00.000000Z"  # the operator quietly edits history
        lines[0] = json.dumps(e, sort_keys=True)
        open(logp, "w").write("\n".join(lines) + "\n")
        self.srv = witness_server.serve(self.whome, "127.0.0.1", int(self.url.rsplit(":", 1)[1]))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        with self.assertRaises(ValueError) as cm:
            reader.read()
        self.assertIn("not consistent", str(cm.exception))


class LogWrites(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        witness_server.init(self.d)

    def test_failed_write_leaves_no_partial_entry(self):
        log = witness_server.Log(self.d)
        self.addCleanup(log.close)
        log.add("box", {"kid": "ed25519:k", "head_seq": 1, "head_hash": "a" * 64})
        logp = os.path.join(self.d, "log.jsonl")
        size = os.path.getsize(logp)
        with mock.patch("os.fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                log.add("box", {"kid": "ed25519:k", "head_seq": 2, "head_hash": "b" * 64})
        self.assertEqual(os.path.getsize(logp), size)
        self.assertEqual(len(log.entries), 1)

    def test_second_instance_is_refused_while_one_runs(self):
        log = witness_server.Log(self.d)
        with self.assertRaises(RuntimeError):
            witness_server.Log(self.d)
        log.close()
        witness_server.Log(self.d).close()

    def test_serve_binds_before_touching_the_log(self):
        logp = os.path.join(self.d, "log.jsonl")
        with open(logp, "w") as f:
            f.write('{"cp": {"kid"')  # torn tail that loading the log would set aside
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        self.addCleanup(busy.close)
        with self.assertRaises(OSError):
            witness_server.serve(self.d, "127.0.0.1", busy.getsockname()[1])
        self.assertFalse(os.path.exists(logp + ".torn"))


class TornLog(unittest.TestCase):
    def test_witness_starts_when_the_last_line_is_torn(self):
        d = tempfile.mkdtemp()
        try:
            witness_server.init(d)
            log = witness_server.Log(d)
            log.add("box", {"kid": "ed25519:k", "head_seq": 1, "head_hash": "a" * 64})
            logp = os.path.join(d, "log.jsonl")
            with open(logp, "a") as f:
                f.write('{"cp": {"kid": "ed25519:k", "head_se')  # a write cut short
            log.close()
            log = witness_server.Log(d)
            self.assertEqual(len(log.entries), 1)
            self.assertTrue(os.path.exists(logp + ".torn"))
            log.add("box", {"kid": "ed25519:k", "head_seq": 2, "head_hash": "b" * 64})
            log.close()
            self.assertEqual([e["cp"]["head_seq"] for e in witness_server.Log(d).entries], [1, 2])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
