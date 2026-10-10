"""`tracekit why serve`: the token, cookie and Host conventions of the local pages, ingest integrity (401/409/422),
allow-listed replay, the live stream and Find the cause.

    python3 -m pytest tests/test_why_server.py -q
"""
import contextlib
import http.client
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.request

from tracekit.why.core import GENESIS, HttpSink, event_hash
from tracekit.why.demo import EXFIL_TARGET, SYSTEM
from tracekit.why.graph import target_hits
from tracekit.why.server import IngestError, serve

TOKEN = "why-test-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}


class Server(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.httpd, self.store = serve(os.path.join(self.tmp, "srv"), "127.0.0.1", 0, token=TOKEN,
                                       allow_programs=["tracekit.why.demo:SYSTEM"])
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(setattr, self.store, "_watching", False)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def get(self, path):
        status, _, body = self.request("GET", path, AUTH)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def post(self, path, body, headers=JSON):
        status, _, out = self.request("POST", path, headers, json.dumps(body).encode())
        return status, json.loads(out)

    def stream(self, n_msgs=1000, timeout=10):
        """Collect data messages from /api/stream until a run finishes (or n_msgs arrive)."""
        out, ready = [], threading.Event()

        def read():
            req = urllib.request.Request(self.base + "/api/stream", headers=AUTH)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ready.set()
                for line in r:
                    if line.startswith(b"data: "):
                        out.append(json.loads(line[6:]))
                        if len(out) >= n_msgs or out[-1].get("finished"):
                            return

        t = threading.Thread(target=read, daemon=True)
        t.start()
        ready.wait(timeout)
        return out, t


class Ingest(Server):
    def test_remote_ingest_then_investigate_and_test(self):
        for s in range(3):
            SYSTEM.run(seed=s, run_id=f"remote-{s}", sink=HttpSink(self.base, TOKEN, batch=7))
        ws = self.get("/api/workspace")
        self.assertEqual({r["run_id"] for r in ws["runs"]}, {"remote-0", "remote-1", "remote-2"})
        self.assertTrue(all(r["integrity"] == "ok" for r in ws["runs"]))
        self.assertEqual(self.get("/api/runs/remote-0")["summary"]["alerts"]["high"], 1)
        code, r = self.post("/api/runs/remote-0/tests", {"intervention": "input:vendor:*", "target": EXFIL_TARGET,
                                                         "n": 20})
        self.assertEqual((code, r["verdict"]), (200, "causal"))
        d = self.get("/api/runs/remote-0")
        send = [k for k, v in d["actions"].items() if "vendor-compliance" in v["target"]][0]
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")

    def test_rejects_bad_token_tamper_and_gaps(self):
        run = SYSTEM.run(seed=0, run_id="t1")
        evs, blobs = run.events, run.blobs
        ingest = lambda events, blobs, token=TOKEN: self.post(  # noqa: E731
            "/v1/ingest", {"events": events, "blobs": blobs},
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})[0]
        self.assertEqual(ingest(evs, blobs, "wrong"), 401)
        self.assertEqual(self.request("POST", "/v1/ingest", {"Cookie": f"tracekit_why={TOKEN}"}, b"{}")[0], 401)
        bad = json.loads(json.dumps(evs[:3]))
        bad[2]["agent"] = "mallory"
        self.assertEqual(ingest(bad, blobs), 422)
        self.assertEqual(ingest(evs[1:4], blobs), 409)
        fake = dict(blobs)
        fake[next(iter(fake))] = "forged"
        self.assertEqual(ingest(evs[:3], fake), 422)
        self.assertEqual(ingest(evs[:3], blobs), 200)
        self.assertEqual(ingest(evs[:3], blobs), 409)  # replayed batch

    def test_malformed_ingest_is_rejected_and_cannot_break_the_workspace(self):
        ev = {"schema": "tracekit.why.event.v1", "seq": 0, "id": "x", "prev_hash": GENESIS, "run_id": "poison",
              "agent": "run", "type": "decision", "ts": "2026-10-09T00:00:00.000000Z"}
        ev["hash"] = event_hash(ev)
        self.assertEqual(self.post("/v1/ingest", {"events": [ev], "blobs": {}})[0], 422)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "abc"}, b"{}")[0], 400)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "99999999"})[0], 413)
        self.assertEqual(self.request("POST", "/v1/ingest", JSON, b"[1]")[0], 400)
        os.makedirs(os.path.join(self.store.root, "broken"))  # a broken run written straight to disk is skipped
        with open(os.path.join(self.store.root, "broken", "events.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        SYSTEM.run(seed=1, out_dir=self.store.root, run_id="fine")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual([x["run_id"] for x in self.get("/api/workspace")["runs"]], ["fine"])

    def test_replay_refused_for_unlisted_program(self):
        httpd, store = serve(os.path.join(self.tmp, "srv2"), "127.0.0.1", 0, watch=False)
        httpd.server_close()
        SYSTEM.run(seed=0, out_dir=store.root, run_id="r")
        with self.assertRaises(IngestError) as e:
            store.test("r", {"intervention": "untrusted", "target": "tool=send_email"})
        self.assertEqual(e.exception.status, 403)


class Live(Server):
    def test_stream_announces_runs_written_to_disk_with_their_alerts(self):
        msgs, t = self.stream()
        SYSTEM.run(seed=0, out_dir=self.store.root, run_id="disk-0")  # a local Runtime, no sink
        t.join(10)
        self.assertTrue(msgs and msgs[0]["run_id"] == "disk-0" and msgs[-1]["finished"])
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("send_email", highs[0]["title"])

    def test_stream_announces_ingested_runs(self):
        msgs, t = self.stream()
        SYSTEM.run(seed=0, run_id="remote-live", sink=HttpSink(self.base, TOKEN))
        t.join(10)
        self.assertEqual(msgs[0]["run_id"], "remote-live")
        self.assertGreaterEqual(len(msgs), 3)  # flushed per tool call, not only at the end
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertGreaterEqual(len(highs), 1)
        self.assertEqual(len(highs), len({(a["title"], a["node"]) for a in highs}))

    def test_find_the_cause_endpoint(self):
        run = next(r for r in (SYSTEM.run(seed=s, out_dir=self.store.root, run_id=f"fc-{s}") for s in range(8))
                   if target_hits(r, EXFIL_TARGET))
        code, out = self.post(f"/api/runs/{run.run_id}/attribute", {"target": EXFIL_TARGET, "n": 10, "n_max": 40})
        self.assertEqual(code, 200)
        self.assertEqual((out["causes"][0]["intervention"], out["causes"][0]["role"]),
                         ("input:vendor:portal/notes.md", "primary"))
        d = self.get(f"/api/runs/{run.run_id}")
        send = next(k for k, v in d["actions"].items() if "vendor-compliance" in v["target"])
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")


class Page(Server):
    def test_token_is_exchanged_for_a_cookie_and_the_page_has_a_strict_csp(self):
        self.assertEqual(self.request("GET", "/")[0], 401)
        self.assertEqual(self.request("GET", "/api/workspace")[0], 401)
        self.assertEqual(self.request("GET", "/?token=wrong")[0], 401)
        status, h, _ = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(status, 303)
        self.assertNotIn(TOKEN, h["Location"])
        cookie = h["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn(TOKEN, cookie)
        session = {"Cookie": cookie.split(";")[0]}
        status, h, page = self.request("GET", "/", session)
        self.assertEqual(status, 200)
        nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]{16,})';", h["Content-Security-Policy"]).group(1)
        for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, h["Content-Security-Policy"])
        self.assertEqual(re.findall(r"<script[^>]*>", page.decode()), [f'<script nonce="{nonce}">'])
        self.assertEqual((h["X-Content-Type-Options"], h["Referrer-Policy"]), ("nosniff", "no-referrer"))
        self.assertIn(b"<title>tracekit why</title>", page)
        self.assertEqual(self.request("GET", "/api/workspace", session)[0], 200)

    def test_foreign_host_is_refused_without_the_token(self):
        self.assertEqual(self.request("GET", "/api/workspace", {"Host": "evil.example:7788"})[0], 403)
        self.assertEqual(self.request("GET", "/api/workspace", {**AUTH, "Host": "evil.example:7788"})[0], 200)
        session = {"Cookie": self.request("GET", f"/?token={TOKEN}")[1]["Set-Cookie"].split(";")[0]}
        self.assertEqual(self.request("POST", "/api/runs/x/tests", {
            **session, "Content-Type": "application/json", "Host": "evil.example"}, b"{}")[0], 403)
        self.assertEqual(self.request("POST", "/v1/ingest", {"Host": "evil.example"}, b"{}")[0], 403)
        # remote agents reach the server by its DNS name: the bearer token is enough
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Host": "why.example.com"}, b"{}")[0], 400)

    def test_replay_posts_need_the_token_and_a_same_origin_json_body(self):
        SYSTEM.run(seed=0, out_dir=self.store.root, run_id="r")
        body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, "n": 2}).encode()
        for headers, status in (({"Content-Type": "application/json"}, 401),
                                ({**AUTH, "Content-Type": "text/plain"}, 403),
                                ({**AUTH}, 403),
                                ({**JSON, "Origin": "http://evil.example"}, 403),
                                ({**JSON, "Content-Length": "99999999"}, 413)):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/api/runs/r/tests", headers, body)[0], status)
        for bad in ({"n": "x"}, {"n": None}, {"n_max": [1]}):
            with self.subTest(bad=bad):
                bad_body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, **bad}).encode()
                self.assertEqual(self.request("POST", "/api/runs/r/tests", JSON, bad_body)[0], 400)
                self.assertEqual(self.request("POST", "/api/runs/r/attribute", JSON, bad_body)[0], 400)
        self.assertEqual(self.request("POST", "/api/runs/r/tests", JSON, body)[0], 200)
        self.assertEqual(self.request("POST", "/api/runs/no-such/tests", JSON, body)[0], 404)


if __name__ == "__main__":
    unittest.main()
