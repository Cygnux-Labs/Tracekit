"""Agent-to-agent traffic: the A2A gateway (tracekit/a2a_gateway.py) in front of a fake A2A server, deciding and
recording through an in-process v2 signer as source gateway (tier T2); RunHandle.transfer, a non-text exchange
recorded and gated by its digest; and the policy's a2a class (policy2/classes.a2a_fields)."""
import hashlib
import http.client
import http.server
import json
import os
import threading
import time
import unittest

from adapter_contract import _serve, tmpdir
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from test_signer_service import records
from tracekit import a2a_gateway
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS
from tracekit.verify import v2

GW = CallerIdentity("mtls", "spiffe://acme/a2a", True)
UPSTREAM_KEY = "Bearer a2a-upstream-0123456789"
CARD = {"name": "researcher", "url": "http://researcher.example/a2a", "skills": [{"id": "search"}]}
# only token:http (the agent the gateway authenticates) to researcher, and one (sender, receiver, projector) triple
POLICY = {"tools": {"a2a:*": "a2a"},
          "deny": [{"id": "R-ROUTE", "class": "a2a", "field": "route", "pattern": ".",
                    "unless": "^(token:http->researcher|qwen-7b@1->llama-1b@2 via c2c@0\\.1)$"},
                   {"id": "R-SIZE", "class": "a2a", "field": "size", "pattern": "^[0-9]{5,}$"}],   # 10,000 bytes up
          "ask": [{"id": "R-FILE", "class": "a2a", "field": "kinds", "pattern": "file"}]}
TEXT = {"role": "user", "messageId": "m1", "parts": [{"kind": "text", "text": "find the Q3 report"}]}
FILE = {"role": "user", "messageId": "m2", "parts": [{"kind": "file", "file": {"uri": "https://files.example/q3.pdf"}}]}


class A2aServer(http.server.BaseHTTPRequestHandler):
    """Serves the Agent Card; answers message/send with a completed task whose artifact echoes the authorization header
    it got (a server that echoes its credential)."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, obj):
        out = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self._send(CARD)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        self.server.seen.append((self.path, req))
        self._send({"jsonrpc": "2.0", "id": req["id"], "result": {
            "kind": "task", "id": "task-1", "status": {"state": "completed"},
            "artifacts": [{"parts": [{"kind": "text", "text": f"done as {self.headers.get('authorization')}"}]}]}})


class Gateway(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), gateways=["mtls:spiffe://acme/*"], grace_s=0,
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/a2a": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume"]})
        self.closed = False
        self.addCleanup(self.close)
        self.a2a = http.server.ThreadingHTTPServer(("127.0.0.1", 0), A2aServer)
        self.a2a.seen = []
        port = serve(self, self.a2a)
        for name, value in (("bearer", SECRET), ("up.header", UPSTREAM_KEY)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        cfg = os.path.join(self.dir, "a2a-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused", "approval_wait_s": 5,
                       "upstreams": [{"name": "researcher", "url": f"http://127.0.0.1:{port}/researcher",
                                      "headers": {"authorization": "up.header"}},
                                     {"name": "billing", "url": f"http://127.0.0.1:{port}/billing"}]}, f)
        self.signer = InProcess(self.s, GW)
        self.srv = a2a_gateway.serve(a2a_gateway.load_config(cfg), self.signer)
        self.port = serve(self, self.srv)
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "planner"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def send(self, to, message=TEXT, method="message/send"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        self.addCleanup(c.close)
        c.request("POST", f"/a2a/{to}", json.dumps({"jsonrpc": "2.0", "id": 7, "method": method,
                                                    "params": {"message": message}}),
                  {"authorization": "Bearer " + SECRET, "content-type": "application/json",
                   "x-tracekit-run": f"{self.run['run_id']}.{self.run['run_token']}"})
        return json.loads(c.getresponse().read())

    def events(self):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run["run_id"]]

    def test_an_allowed_pair_is_decided_sent_completed_t2_and_its_bundle_verifies(self):
        out = self.send("researcher")
        self.assertEqual((out["id"], out["result"]["id"]), (7, "task-1"))
        self.assertEqual(out["result"]["artifacts"][0]["parts"][0]["text"], "done as [REDACTED:executor_secret]")
        [(path, req)] = self.a2a.seen
        self.assertEqual((path, req["method"], req["params"]), ("/researcher", "message/send", {"message": TEXT}))
        self.s.call(AGENT, "close_run", {"request_id": "cl", **self.run})
        self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", self.run["run_id"], self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, [c for c in rep.checks if c["status"] != "ok"])
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"]) for e in evs],
                         [("policy.decision", "gateway", "T2"), ("tool.result", "gateway", "T2")])
        d = evs[0]["data"]
        self.assertEqual((d["tool"], d["decision"], d["caller"]), ("a2a:researcher/message/send", "allow", "token:http"))
        # the signed decision commits to who sent what to whom, and to the receiver's Agent Card as it was served
        card = "sha256:" + hashlib.sha256(json.dumps(CARD).encode()).hexdigest()
        args = {"sender": "token:http", "receiver": "researcher", "agent_card": card, "params": {"message": TEXT}}
        self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                      event_hash({"tool": d["tool"], "args": args})))
        self.assertTrue(evs[1]["data"]["ok"])
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("a2a-upstream-0123456789", f.read())

    def test_a_pair_the_policy_does_not_list_never_reaches_the_receiver(self):
        out = self.send("billing")
        self.assertEqual(out["error"]["code"], -32000)
        self.assertIn("R-ROUTE", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])
        [d] = [e["data"] for e in self.events() if e["type"] == "policy.decision"]
        self.assertEqual((d["tool"], d["decision"]), ("a2a:billing/message/send", "deny"))

    def test_a_message_over_the_size_rule_never_reaches_the_receiver(self):
        out = self.send("researcher", dict(TEXT, parts=[{"kind": "text", "text": "x" * 10000}]))
        self.assertIn("R-SIZE", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])

    def test_a_held_message_is_sent_only_once_a_person_approves(self):
        got = {}
        t = threading.Thread(target=lambda: got.update(out=self.send("researcher", FILE)))
        t.start()
        for _ in range(500):
            aids = [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {"run_id": self.run["run_id"]})["approvals"]]
            if aids:
                break
            time.sleep(0.01)
        self.assertEqual(self.a2a.seen, [])   # held: nothing sent yet
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": aids[0], "decision": "approve"})
        t.join(20)
        self.assertEqual(got["out"]["result"]["id"], "task-1")
        self.assertEqual([r["params"]["message"] for _, r in self.a2a.seen], [FILE])

    def test_the_signer_unreachable_fails_closed(self):
        self.signer.down = True
        out = self.send("researcher")
        self.assertIn("signer is unreachable", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])

    def test_a_stream_is_refused_not_relayed_unrecorded(self):
        out = self.send("researcher", method="message/stream")
        self.assertEqual(out["error"]["code"], -32004)
        self.assertEqual(self.a2a.seen, [])

    def test_an_unknown_upstream_is_not_found(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("POST", "/a2a/nope", "{}", {"authorization": "Bearer " + SECRET, "content-type": "application/json",
                                              "x-tracekit-run": f"{self.run['run_id']}.{self.run['run_token']}"})
        self.assertEqual(c.getresponse().status, 404)


class Transfer(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), grace_s=0)
        self.addCleanup(self.s.close)
        self.run = Client(_serve(self, self.s.handle_frame)).run("fuser")

    def test_an_allowed_transfer_is_signed_by_its_digest_never_its_payload(self):
        payload = b"KV-CACHE-PAYLOAD-" * 64
        out = self.run.transfer("qwen-7b@1", "llama-1b@2", payload, "kv-cache", projector="c2c@0.1")
        self.assertEqual((out["ok"], out["decision"]), (True, "allow"))
        self.run.close()
        self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", self.run.run_id, self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, [c for c in rep.checks if c["status"] != "ok"])
        evs = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run.run_id]
        [d] = [e["data"] for e in evs if e["type"] == "policy.decision"]
        self.assertEqual((d["tool"], d["decision"]), ("a2a:transfer", "allow"))
        self.assertTrue([e for e in evs if e["type"] == "tool.result" and e["data"]["ok"]])
        args = {"sender": "qwen-7b@1", "receiver": "llama-1b@2", "modality": "kv-cache", "size": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "projector": "c2c@0.1",
                "claimed": ["modality", "projector", "receiver", "sender"], "measured": ["digest", "size"]}
        self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                      event_hash({"tool": "a2a:transfer", "args": args})))
        for root, _, files in os.walk(self.dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    self.assertNotIn(b"KV-CACHE-PAYLOAD-", f.read(), name)

    def test_a_transfer_through_an_unlisted_projector_is_denied(self):
        out = self.run.transfer("qwen-7b@1", "llama-1b@2", b"state", "kv-cache", projector="c2c@0.2")
        self.assertEqual((out["ok"], out["decision"], out["rule_ids"]), (False, "deny", ["R-ROUTE"]))


class Policy(unittest.TestCase):
    def test_the_a2a_class_lints_and_reads_the_message(self):
        self.assertEqual(policy_compile._lint(dict(POLICY), "p.yaml"), [])
        bad = dict(POLICY, flag=[{"id": "R-X", "class": "a2a", "field": "skill", "pattern": "x"}])
        self.assertIn("p.yaml: flag rule R-X: can never fire: class a2a has no field 'skill'",
                      policy_compile._lint(bad, "p.yaml"))
        e = Engine(POLICY)
        args = {"sender": "token:http", "receiver": "researcher", "params": {"message": FILE}}
        self.assertEqual(e.decide("a2a:researcher/message/send", args)["rule_ids"], ["R-FILE"])
        self.assertEqual(e.decide("a2a:researcher/message/send", dict(args, sender="token:other"))["rule_ids"],
                         ["R-ROUTE", "R-FILE"])
