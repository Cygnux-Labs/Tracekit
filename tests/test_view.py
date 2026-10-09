"""`tracekit view`: the v2 signer's runs, each verified by verify.v2, served with the observer's page and security."""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import unittest

import test_signer_service as ts
from factories import wait_for
from test_observe_render import XSS, script_of, unescaped
from tracekit import view
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage

POLICY = Engine({"deny": [{"id": "T-DENY", "tool": "rm", "pattern": "^"}],
                 "ask": [{"id": "T-PAY", "tool": "pay", "pattern": "^"}]})


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class View(unittest.TestCase):
    def setUp(self):
        self.d = ts.tmpdir(self)
        cfg = {"data_dir": self.d, "socket": os.path.join(self.d, "s.sock"), "grace_s": 0}
        self.service = svc.open_service(cfg, policy=POLICY)
        self.addCleanup(self.service.close)
        for srv in svc.serve(cfg, self.service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.client = Client(cfg["socket"])
        self.addCleanup(self.client.close)

    def finished_run(self):
        """allow, deny, ask -> approve -> run, complete, close; returns the run id once a note covers run.final."""
        run = self.client.run(agent="e2e")
        self.assertEqual(run.decide("c1", "Bash", {"command": "ls"})["decision"], "allow")
        run.complete("c1")
        self.assertEqual(run.decide("c2", "rm", {"path": "x"})["decision"], "deny")
        self.assertEqual(run.decide("c3", "pay", {"cents": 5})["decision"], "ask")
        aid = run.call("approval_request", tool_call_id="c3")["approval_id"]
        self.client.call("approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertTrue(run.approval_consume("c3", "pay", {"cents": 5})["ok"])
        run.complete("c3")
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] == "run.final"
                                 and storage.checkpoint_latest()[0] == storage.tree.size, 20))
        return run.run_id

    def rows(self, feed, run_id):
        with feed.lock:
            return [r for r in feed.records if r["session_id"] == run_id]

    def report(self, feed, run_id):
        wait_for(lambda: any(r.get("title", "").startswith(f"RUN {run_id}") for r in self.rows(feed, run_id)), 15)
        return [r for r in self.rows(feed, run_id) if r.get("title", "").startswith(f"RUN {run_id}")]

    def test_dev_run_is_listed_with_its_counts_and_verified_while_the_signer_holds_the_lock(self):
        run_id = self.finished_run()
        with self.assertRaises(OSError):
            FileStorage(os.path.join(self.d, "store"))   # the signer still holds the store
        feed = view.StoreFeed(self.d)
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity VERIFIED · Assurance dev")
        self.assertIn("tenant default · agent e2e · final · decisions allow 1, ask 1, deny 1 · approvals 1 · gaps 0",
                      rep["text"])
        self.assertIn("same user as the dev signer", rep["text"])
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev;", rep["text"])   # verify.v2's own report
        rows = self.rows(feed, run_id)
        self.assertEqual([r["tool_name"] for r in rows if r["event"] == "PreToolUse"], ["Bash", "rm", "pay"])
        self.assertEqual((rows[0]["event"], rows[-1]["title"]), ("SessionStart", rep["title"]))
        self.assertEqual(feed.verify()[1], [])

    def test_tampered_record_shows_only_the_failure(self):
        run_id = self.finished_run()
        self.service.close()
        path = os.path.join(self.d, "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data.count('"tool":"Bash"'), 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
        feed = view.StoreFeed(self.d)
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity FAILED")
        self.assertEqual(self.rows(feed, run_id), [rep])   # none of its events
        self.assertEqual(feed.verify()[1], [f"run {run_id} of tenant default: FAILED"])

    def serve(self, feed, token=None, tls=None):
        srv = view.server(feed, "127.0.0.1", 0, token, tls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_hostile_tool_names_are_data_and_the_page_escapes_every_sink(self):
        run = self.client.run(agent="a")
        run.decide("c1", XSS, {"q": XSS})
        self.client.call("checkpoint_nudge", {})
        feed = view.StoreFeed(self.d)
        self.report(feed, run.run_id)
        port = self.serve(feed)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/")
        r = c.getresponse()
        page = r.read().decode()
        self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy"))
        self.assertNotIn("<img", page)
        self.assertEqual(unescaped(script_of(page)), [])
        c.request("GET", "/api/snapshot")
        snap = json.loads(c.getresponse().read())
        self.assertIn(XSS, [x.get("tool_name") for x in snap["records"]])

    def test_sse_shows_a_new_record(self):
        feed = view.StoreFeed(self.d)
        c = http.client.HTTPConnection("127.0.0.1", self.serve(feed), timeout=15)
        c.request("GET", "/api/snapshot")
        start = json.loads(c.getresponse().read())["next"]
        c.request("GET", f"/api/stream?from={start}")
        stream = c.getresponse()
        run = self.client.run(agent="late")
        run.decide("c1", "Bash", {"command": "ls"})
        self.client.call("checkpoint_nudge", {})
        while True:
            line = stream.fp.readline()
            if line.startswith(b"data: ") and json.loads(line[6:]).get("tool_name") == "Bash":
                break

    def test_beyond_loopback_needs_https(self):
        self.assertEqual(view.main(["--host", "0.0.0.0", "--data-dir", self.d]), 2)

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a certificate")
    def test_https_serves_with_a_secure_cookie(self):
        cert, key = os.path.join(self.d, "c.pem"), os.path.join(self.d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days",
                        "1", "-keyout", key, "-out", cert], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        port = self.serve(view.StoreFeed(self.d), "s3cret", tls)
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ssl._create_unverified_context())
        c.request("GET", "/?token=s3cret")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        self.assertIn("; Secure", r.getheader("Set-Cookie"))


if __name__ == "__main__":
    unittest.main()
