"""The signer's OCSF webhook (tracekit/signer/webhook.py, docs/webhooks.md): a real signer posts its decisions, denies,
approvals, gaps and tamper records to a local receiver, each event valid against the vendored OCSF subset
(tests/data/ocsf/), each body HMAC-signed, no agent content in clear; retries with backoff and counted drops."""
import hashlib
import hmac
import json
import os
import queue
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import test_signer_service as ts
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.schema import _check
from tracekit.signer import metrics, webhook
from tracekit.signer import service as svc

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ocsf", "ocsf-1.3-subset.json")
KEY = b"webhook-test-secret"
APPROVER = CallerIdentity("uid", "999999", True)
POLICY = Engine({"deny": [{"id": "NO-RM", "tool": "^shell$", "pattern": "rm -rf"}],
                 "ask": [{"id": "PAY", "tool": "^pay$", "pattern": "^"}]})


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        status = self.server.statuses.pop(0) if self.server.statuses else 200
        self.server.got.put((status, dict(self.headers), body))
        self.server.release.wait(10)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def ocsf_errors(event):
    with open(SCHEMA, encoding="utf-8") as f:
        schema = json.load(f)
    errs = []
    _check(event, schema, schema, "$", errs)
    return errs


class Case(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.srv.daemon_threads, self.srv.statuses, self.srv.got = True, [], queue.Queue()
        self.srv.release = threading.Event()
        self.srv.release.set()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.release.set)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"

    def bodies(self, until):
        """Events received (status 2xx) until one satisfies `until`."""
        out = []
        while not any(until(e) for e in out):
            status, headers, body = self.srv.got.get(timeout=10)
            sig = dict(x.split("=", 1) for x in headers["X-Tracekit-Signature"].split(","))
            t = sig["t"]
            self.assertEqual(sig["v1"], hmac.new(KEY, f"{t}.".encode() + body, hashlib.sha256).hexdigest())
            self.assertLess(abs(time.time() - int(t)), 60)
            self.assertNotIn(b"acct-42", body)   # arguments leave as commitments only
            if 200 <= status < 300:
                out += json.loads(body)
        return out


class TestSigner(Case):
    def test_decisions_denies_approvals_gaps_and_tamper(self):
        d = ts.tmpdir(self)
        s = svc.SignerService(d, policy=POLICY, approvals={"approvers": [f"uid:{APPROVER.subject}"]},
                              webhooks=[{"url": self.url, "events": list(webhook.EVENTS), "secret": KEY}])
        self.addCleanup(s.close)
        run = s.register_run({"request_id": "r", "agent": {"name": "a"}})
        r = {"run_id": run["run_id"], "run_token": run["run_token"], "stream": "s"}
        s.decide({"request_id": "d1", **r, "client_seq": 0, "tool_call_id": "t1", "tool": "shell",
                  "args_source": "parsed", "args": {"command": "rm -rf /"}})
        s.decide({"request_id": "d2", **r, "client_seq": 1, "tool_call_id": "t2", "tool": "pay",
                  "args_source": "parsed", "args": {"to": "acct-42"}})
        r.pop("stream")
        aid = s.approval_request({"request_id": "a", **r, "tool_call_id": "t2"})["approval_id"]
        s.call(APPROVER, "approval_decide", {"request_id": "h", "approval_id": aid, "decision": "approve"})
        s.log.write(lambda tx: tx.gap("degraded_unanchored", "test"))
        s._tamper("rollback", "records", {"length": 9}, {"length": 1}, True, "test")
        events = self.bodies(lambda e: e["message"] == "trace.tamper")
        for e in events:
            self.assertEqual(ocsf_errors(e), [], e)
        by = {(e["message"], e["unmapped"]["tracekit"].get("decision")): e for e in events}
        deny, ask = by[("policy.decision", "deny")], by[("policy.decision", "ask")]
        self.assertEqual((deny["class_uid"], deny["severity_id"]), (2004, 3))
        self.assertEqual(deny["unmapped"]["tracekit"]["rule_ids"], ["NO-RM"])
        self.assertEqual((ask["class_uid"], ask["activity_id"]), (6003, 99))
        self.assertRegex(ask["unmapped"]["tracekit"]["args_commitment"], "^hmac-sha256:[0-9a-f]{64}$")
        answer = by[("approval", "approve")]
        self.assertEqual((answer["class_uid"], answer["actor"]["user"]["uid"]), (6003, f"uid:{APPROVER.subject}"))
        gap, tamper = by[("capture.gap", None)], by[("trace.tamper", None)]
        self.assertEqual((gap["class_uid"], gap["finding_info"]["title"]), (2004, "capture.gap degraded_unanchored"))
        self.assertNotIn("reason", gap["unmapped"]["tracekit"])   # free text stays in the log
        self.assertEqual((tamper["class_uid"], tamper["severity_id"]), (2004, 5))
        self.assertEqual(by[("approval.request", None)]["activity_id"], 1)

    def test_events_filter(self):
        s = svc.SignerService(ts.tmpdir(self), policy=POLICY,
                              webhooks=[{"url": self.url, "events": ["deny", "gap"], "secret": KEY}])
        self.addCleanup(s.close)
        run = s.register_run({"request_id": "r", "agent": {"name": "a"}})
        r = {"run_id": run["run_id"], "run_token": run["run_token"], "stream": "s"}
        for i, (tool, args) in enumerate((("pay", {"to": "acct-42"}), ("shell", {"command": "rm -rf /"}))):
            s.decide({"request_id": f"d{i}", **r, "client_seq": i, "tool_call_id": f"t{i}", "tool": tool,
                      "args_source": "parsed", "args": args})
        s.log.write(lambda tx: tx.gap("degraded_unanchored", "test"))
        events = self.bodies(lambda e: e["message"] == "capture.gap")
        self.assertEqual([e["message"] for e in events], ["policy.decision", "capture.gap"])
        self.assertEqual(events[0]["unmapped"]["tracekit"]["decision"], "deny")


def record(i=0):
    return {"hash": "sha256:" + "0" * 64, "event": {
        "id": f"e{i}", "ts": "2026-10-10T00:00:00.000000Z", "type": "capture.gap", "run_id": "signer", "tenant": "t",
        "log_id": "l", "run_seq": i, "seq": i, "data": {"kind": "witness_failed", "reason": "x"}}}


class TestSender(Case):
    def sender(self):
        dropped = metrics.Counter("d", "d", "reason")
        w = webhook.Sender(self.url, ["gap"], KEY, dropped)
        self.addCleanup(w.close)
        return w, dropped

    @mock.patch.object(webhook, "BACKOFF_S", (0.01, 0.01))
    def test_retries_with_backoff_until_delivered(self):
        self.srv.statuses = [503, 429]
        w, dropped = self.sender()
        w.put([record()])
        self.assertEqual([self.srv.got.get(timeout=10)[0] for _ in range(3)], [503, 429, 200])
        self.assertEqual(dropped._values, {})

    @mock.patch.object(webhook, "BACKOFF_S", (0.01, 0.01))
    def test_drops_are_counted(self):
        self.srv.statuses = [500] * webhook.RETRIES + [400]
        w, dropped = self.sender()
        w.put([record(0)])
        for _ in range(webhook.RETRIES):
            self.srv.got.get(timeout=10)
        w.put([record(1)])
        self.assertEqual(self.srv.got.get(timeout=10)[0], 400)   # refused: not tried again
        w.put([record(2)])
        self.assertEqual(self.srv.got.get(timeout=10)[0], 200)
        self.assertEqual(dropped._values, {"failed": 2})

    def test_full_queue_drops_without_blocking_the_writer(self):
        self.srv.release.clear()   # the receiver holds the first post
        with mock.patch.object(webhook, "QUEUE", 2):
            w, dropped = self.sender()
        w.put([record(0)])
        self.srv.got.get(timeout=10)
        w.put([record(i) for i in range(1, 6)])
        self.assertEqual(dropped._values, {"queue_full": 3})
        self.srv.release.set()


class TestObserverFailure(unittest.TestCase):
    def test_a_failing_observer_never_fails_a_write(self):
        s = svc.SignerService(ts.tmpdir(self))
        self.addCleanup(s.close)
        s.log.observers.append(mock.Mock(side_effect=RuntimeError("webhook bug")))
        with self.assertLogs("tracekit.signer.pipeline", "ERROR"):
            run = s.call(ts.ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        s.call(ts.ME, "register_run", {"request_id": "r2", "agent": {"name": "a"}})   # the writer carries on
        self.assertTrue(run["run_id"])


class TestConfig(unittest.TestCase):
    def test_load(self):
        d = ts.tmpdir(self)
        with open(os.path.join(d, "s"), "w", encoding="utf-8") as f:
            f.write("k\n")
        ok = {"url": "https://siem.example.org/x", "format": "ocsf", "events": ["deny"], "secret_file": "s"}
        self.assertEqual(webhook.load([ok], d, "signer.yaml"),
                         [{"url": ok["url"], "events": ["deny"], "secret": b"k"}])
        for bad in (dict(ok, format="cef"), dict(ok, url="http://siem.example.org/x"), dict(ok, events=[]),
                    dict(ok, events=["everything"]), {k: v for k, v in ok.items() if k != "secret_file"}, ok):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                webhook.load(bad if bad is ok else [bad], d, "signer.yaml")


if __name__ == "__main__":
    unittest.main()
