"""Agent-to-agent traffic: the A2A gateway (tracekit/a2a_gateway.py) in front of a fake A2A server, deciding and
recording through an in-process v2 signer as source gateway (tier T2), with the security checklist's API-surface items
probed on it (docs/security-checklist.md); RunHandle.transfer, a non-text exchange recorded and gated by its digest;
and the policy's a2a class (policy2/classes.a2a_fields)."""
import contextlib
import hashlib
import http.client
import importlib.util
import http.server
import io
import json
import os
import socket
import shutil
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from adapter_contract import _serve, tmpdir
from test_executor import InProcess
from test_gateway import AGENT, OTHER, SECRET, serve
from test_signer_service import records
from tracekit import a2a_gateway
from tracekit.bundle_v2 import export
from tracekit.deploy import files as tkfiles
from tracekit.format.canon import canonical, event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

HAVE_RE2 = importlib.util.find_spec("re2") is not None
from tracekit.verify import v2

GW = CallerIdentity("mtls", "spiffe://acme/a2a", True)
UPSTREAM_KEY = "Bearer a2a-upstream-0123456789"
CARD = {"name": "researcher", "url": "http://researcher.example/a2a", "skills": [{"id": "search"}]}
PAYER_CARD = {"name": "payer", "skills": [{"id": "search"}, {"id": "payments"}]}
# only token:http (the agent the gateway authenticates) to researcher or payer, and one (sender, receiver, projector)
# triple; only receivers whose Agent Card lists no skill but search
POLICY = {"tools": {"a2a:*": "a2a"},
          "deny": [{"id": "R-ROUTE", "class": "a2a", "field": "route", "pattern": ".",
                    "unless": "^(token:http->(researcher|payer)|qwen-7b@1->llama-1b@2 via c2c@0\\.1)$"},
                   {"id": "R-SKILL", "class": "a2a", "field": "skills", "pattern": ".",
                    "unless": '^\\[("search",?)*\\]$'},   # the card's skill ids, one JSON list
                   {"id": "R-SIZE", "class": "a2a", "field": "size", "pattern": "^[0-9]{5,}$"}],   # 10,000 bytes up
          "ask": [{"id": "R-FILE", "class": "a2a", "field": "kinds", "pattern": "file"}]}
TEXT = {"role": "user", "messageId": "m1", "parts": [{"kind": "text", "text": "find the Q3 report"}]}
FILE = {"role": "user", "messageId": "m2", "parts": [{"kind": "file", "file": {"uri": "https://files.example/q3.pdf"}}]}
# a message/stream's events: the task, two updates and the final one; AUTH is the authorization header the server got
TRIPLE = {"sender": "qwen-7b@1", "receiver": "llama-1b@2", "projector": "c2c@0.1", "modality": "kv-cache", "size": 5}


def spellings(name):
    """Other spellings of `name` (lower-case ASCII holding an a, c, e or o): its case, space around it, a fullwidth or
    a Cyrillic look-alike letter, a zero-width or a control character."""
    look = next(c for c in name if c in "aceo")
    return {"case": name.upper(), "space": f" {name} ", "fullwidth": chr(ord(name[0]) + 0xFEE0) + name[1:],
            "cyrillic": name.replace(look, {"a": "а", "c": "с", "e": "е", "o": "о"}[look], 1),
            "zero-width": name[:2] + "​" + name[2:], "control": name + "\x00"}


STREAM = [{"kind": "task", "id": "task-1", "contextId": "ctx-1", "status": {"state": "submitted"}},
          {"kind": "status-update", "taskId": "task-1", "status": {"state": "working"}, "final": False},
          {"kind": "artifact-update", "taskId": "task-1", "artifact": {"parts": [{"kind": "text", "text": "AUTH"}]}},
          {"kind": "status-update", "taskId": "task-1", "status": {"state": "completed"}, "final": True}]


class A2aServer(http.server.BaseHTTPRequestHandler):
    """Serves the Agent Card (PAYER_CARD at /payer-card); answers message/send and tasks/get with a completed task
    (task-1, in context ctx-1) whose artifact echoes the authorization header it got (a server that echoes its
    credential), and message/stream with the events of server.stream ("pause": a second without a byte), then closes;
    `big`: 4,000 more bytes in each artifact."""
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
        self.server.cards.append(self.path)
        self._send(PAYER_CARD if self.path == "/payer-card" else CARD)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        self.server.seen.append((self.path, req))
        echo = f"done as {self.headers.get('authorization')}" + "x" * 4000 * self.server.big
        if req["method"] != "message/stream":
            return self._send({"jsonrpc": "2.0", "id": req["id"], "result": {
                "kind": "task", "id": "task-1", "contextId": "ctx-1", "status": {"state": "completed"},
                "artifacts": [{"parts": [{"kind": "text", "text": echo}]}]}})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        try:
            for ev in self.server.stream:
                if ev == "pause":
                    time.sleep(1)
                    continue
                data = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": ev}).replace("AUTH", echo)
                self.wfile.write(f"data: {data}\n\n".encode())
                self.wfile.flush()
        except OSError:   # the gateway gave up on the stream
            pass


class Gateway(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        policy = dict(POLICY, deny=[dict(rule, unless="^(token:(http|other)->(researcher|payer)|"
                                                "qwen-7b@1->llama-1b@2 via c2c@0\\.1)$")
                                         if rule["id"] == "R-ROUTE" else rule for rule in POLICY["deny"]])
        self.s = svc.SignerService(self.dir, policy=Engine(policy), gateways=["mtls:spiffe://acme/*"], grace_s=0,
                                   tenants={f"{OTHER.scheme}:{OTHER.subject}": "beta"},
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "token:other": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/a2a": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume",
                                                                         "observe"]})
        self.closed = False
        self.addCleanup(self.close)
        self.a2a = http.server.ThreadingHTTPServer(("127.0.0.1", 0), A2aServer)
        self.a2a.seen, self.a2a.cards, self.a2a.stream, self.a2a.big = [], [], STREAM, False
        port = serve(self, self.a2a)
        for name, value in (("bearer", SECRET), ("up.header", UPSTREAM_KEY)):   # 0600, as a real token file is
            tkfiles.write(self.dir, name, value.encode("utf-8"))
        self.cfg = {"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                             "token_file": "bearer"}, "signer": "unused", "approval_wait_s": 5,
                    "upstreams": [{"name": "researcher", "url": f"http://127.0.0.1:{port}/researcher",
                                   "headers": {"authorization": "up.header"}},
                                  {"name": "billing", "url": f"http://127.0.0.1:{port}/billing"},
                                  {"name": "payer", "url": f"http://127.0.0.1:{port}/payer",
                                   "card": f"http://127.0.0.1:{port}/payer-card"}]}
        self.signer = InProcess(self.s, GW)
        self.srv = a2a_gateway.serve(a2a_gateway.load_config(self.config(self.cfg)), self.signer)
        self.port = serve(self, self.srv)
        self.run = self.register(AGENT)

    def config(self, cfg):
        path = os.path.join(self.dir, f"a2a-{uuid.uuid4().hex}.yaml")
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def register(self, who):
        out = self.s.call(who, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "planner"}})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def post(self, to, method="message/send", params=None, run=None, headers=None):
        """(status, content type, body): a cut stream's body is what came before the connection broke."""
        run = run or self.run
        h = {"authorization": "Bearer " + SECRET, "content-type": "application/json",
             "x-tracekit-run": f"{run['run_id']}.{run['run_token']}", **(headers or {})}
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        self.addCleanup(c.close)
        c.request("POST", f"/a2a/{to}", json.dumps({"jsonrpc": "2.0", "id": 7, "method": method,
                                                    "params": {"message": TEXT} if params is None else params}),
                  {k: v for k, v in h.items() if v is not None})
        r = c.getresponse()
        try:
            body = r.read()
        except http.client.IncompleteRead as e:   # a cut stream ends without its last chunk
            body = e.partial
        return r.status, r.getheader("content-type"), body

    def send(self, to, message=TEXT, method="message/send", **kw):
        """The answer, or a stream's events, each a JSON-RPC response."""
        status, ctype, body = self.post(to, method, {"message": message}, **kw)
        self.assertEqual(status, 200, body)
        if ctype == "text/event-stream":
            return [json.loads(line[6:]) for line in body.split(b"\n") if line.startswith(b"data: ")]
        return json.loads(body)

    def as_other(self):
        """As token:other: the gateway authenticates every request as that caller."""
        authenticated = a2a_gateway._Handler._authenticated

        def other_caller(handler, max_body):
            got = authenticated(handler, max_body)
            return ((got[0][0], got[0][1], "token:other"), got[1], got[2]) if got else None
        return mock.patch.object(a2a_gateway._Handler, "_authenticated", other_caller)

    def events(self, run=None):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == (run or self.run)["run_id"]]

    def verified(self):
        """The run's records, once it is final (past the wait for calls a gateway holds) and its bundle verified."""
        self.s.call(AGENT, "close_run", {"request_id": "cl", **self.run})
        self.s.sweep(time.monotonic() + self.s.gateway_wait_s + 1)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", self.run["run_id"], self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, [c for c in rep.checks if c["status"] != "ok"])
        return self.events()

    def test_an_allowed_pair_is_decided_sent_completed_t2_and_its_bundle_verifies(self):
        out = self.send("researcher")
        self.assertEqual((out["id"], out["result"]["id"]), (7, "task-1"))
        self.assertEqual(out["result"]["artifacts"][0]["parts"][0]["text"], "done as [REDACTED:executor_secret]")
        [(path, req)] = self.a2a.seen
        self.assertEqual((path, req["method"], req["params"]), ("/researcher", "message/send", {"message": TEXT}))
        evs = [e for e in self.verified() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"]) for e in evs],
                         [("policy.decision", "gateway", "T2"), ("tool.result", "gateway", "T2")])
        d = evs[0]["data"]
        self.assertEqual((d["tool"], d["decision"], d["caller"]), ("a2a:researcher/message/send", "allow", "token:http"))
        # the signed decision commits to who sent what to whom, and to the receiver's Agent Card as it was served
        card = "sha256:" + hashlib.sha256(json.dumps(CARD).encode()).hexdigest()
        args = {"sender": "token:http", "receiver": "researcher", "agent_card": card, "skills": ["search"],
                "params": {"message": TEXT}}
        self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                      event_hash({"tool": d["tool"], "args": args})))
        self.assertTrue(evs[1]["data"]["ok"])
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("a2a-upstream-0123456789", f.read())

    def test_tasks_get_is_decided_sent_and_completed(self):
        self.send("researcher")
        status, _, body = self.post("researcher", "tasks/get", {"id": "task-1"})
        self.assertEqual(json.loads(body)["result"]["status"]["state"], "completed")
        self.assertEqual([(p, r["method"], r["params"]) for p, r in self.a2a.seen],
                         [("/researcher", "message/send", {"message": TEXT}),
                          ("/researcher", "tasks/get", {"id": "task-1"})])
        evs = self.events()
        self.assertEqual([e["data"]["tool"] for e in evs if e["type"] == "policy.decision"],
                         ["a2a:researcher/message/send", "a2a:researcher/tasks/get"])
        self.assertEqual([e["data"]["ok"] for e in evs if e["type"] == "tool.result"], [True, True])

    def test_task_ids_belong_to_the_caller_that_created_them(self):
        self.send("researcher")
        other_run = self.register(CallerIdentity("token", "other", True))
        refs = {-32001: [{"taskId": "task-1"}, {"contextId": "task-1"}, {"referenceTaskIds": ["task-1"]}],
                # other spellings a receiver may read too (a2a-python's snake_case, any case in Go's encoding/json)
                -32602: [{"task_id": "task-1"}, {"context_id": "task-1"}, {"reference_task_ids": ["task-1"]},
                         {"TaskID": "task-1"}]}
        cases = [("tasks/get", {"id": "task-1"}, -32001), ("tasks/get", {"ID": "task-1"}, -32602),
                 ("message/send", {"Message": dict(TEXT, taskId="task-1")}, -32602)] + \
                [(method, {"message": dict(TEXT, **ref)}, code) for method in ("message/send", "message/stream")
                 for code in refs for ref in refs[code]]
        for method, params, code in cases:
            with self.subTest(method=method, params=params):
                with self.as_other():
                    _, _, body = self.post("researcher", method, params, run=other_run)
                self.assertEqual(json.loads(body)["error"]["code"], code)
        self.assertEqual(len(self.a2a.seen), 1)
        self.assertFalse(self.srv.a2a["tasks"].owns("token:other", "task-1"))
        self.assertEqual([e for e in self.events(other_run) if e["type"] == "policy.decision"], [])

    def test_malformed_task_references_are_refused_before_a_decision_or_send(self):
        long = "x" * (a2a_gateway.MAX_TASK_ID + 1)
        messages = {
            "taskId": (None, "", 1, [], long),
            "contextId": (None, "", 1, [], long),
            "referenceTaskIds": (None, "", {}, [None], [""], [["task-1"]], ["task-1", "task-1"],
                                 [str(i) for i in range(a2a_gateway.MAX_REFERENCE_TASK_IDS + 1)], [long]),
        }
        for method in ("message/send", "message/stream"):
            for field, values in messages.items():
                for value in values:
                    with self.subTest(method=method, field=field, value=value):
                        _, _, body = self.post("researcher", method, {"message": dict(TEXT, **{field: value})})
                        self.assertEqual(json.loads(body)["error"]["code"], -32602)
        for value in (None, "", 1, [], long):
            with self.subTest(method="tasks/get", value=value):
                _, _, body = self.post("researcher", "tasks/get", {"id": value})
                self.assertEqual(json.loads(body)["error"]["code"], -32602)
        self.assertEqual(self.a2a.seen, [])
        self.assertEqual([e for e in self.events() if e["type"] == "policy.decision"], [])

    def test_a_message_with_a_push_notification_config_is_refused_before_a_decision(self):
        push = {"url": "http://169.254.169.254/latest/meta-data/"}
        for method in ("message/send", "message/stream"):
            for config in ({"pushNotificationConfig": push}, {"push_notification_config": push},
                           {"PushNotificationConfig": {}},
                           {"pushNotificationConfig": None, "push_notification_config": push}):
                with self.subTest(method=method, config=config):
                    _, _, body = self.post("researcher", method, {"message": TEXT, "configuration": config})
                    self.assertEqual(json.loads(body)["error"]["code"], -32602)
        self.assertEqual(self.a2a.seen, [])
        self.assertEqual([e for e in self.events() if e["type"] == "policy.decision"], [])

    def test_a_rule_on_part_kinds_or_hosts_is_not_hidden_by_another_spelling(self):
        uri = FILE["parts"][0]["file"]["uri"]
        for message in ({"Message": FILE}, {"message": dict(TEXT, Parts=FILE["parts"])},
                        {"message": dict(FILE, parts=[{"Kind": "file", "File": {"URI": uri}}])},
                        {"message": dict(FILE, parts=[{"kind": "file", "file": {"URI": uri}}])},
                        {"message": dict(FILE, parts=[{"kind": "file", "file": {"uri": uri}, "mime_type": "x"}])},
                        {"message": dict(FILE, parts=[{"kind": "file", "file": {"uri": uri, "mime-type": "x"}}])},
                        {"message": dict(FILE, parts=[{"kınd": "file", "file": {"uri": uri}}])}):
            with self.subTest(message=message):
                _, _, body = self.post("researcher", params=message)
                self.assertEqual(json.loads(body)["error"]["code"], -32602)
        self.assertEqual(self.a2a.seen, [])
        # metadata and a data part's data are free-form: any keys pass
        free = dict(TEXT, metadata={"Kind": "file", "task_id": "x"},
                    parts=[{"kind": "data", "data": {"Message": {"URI": uri}}}])
        self.assertIn("result", self.send("researcher", free))
        self.assertEqual([e["data"]["decision"] for e in self.events() if e["type"] == "policy.decision"], ["allow"])

    def test_a_conversation_goes_on_in_the_context_the_receiver_named(self):
        other_run = self.register(CallerIdentity("token", "other", True))
        reply = {"kind": "message", "role": "agent", "messageId": "r1", "contextId": "ctx-2",
                 "parts": [{"kind": "text", "text": "which quarter?"}]}
        for method, follow_up in (("message/send", {"taskId": "task-1", "contextId": "ctx-1"}),
                                  ("message/stream", {"taskId": "task-1", "contextId": "ctx-1"}),
                                  ("message/stream", {"contextId": "ctx-2"})):
            with self.subTest(method=method, follow_up=follow_up):
                self.srv.a2a["tasks"] = a2a_gateway._Tasks()
                self.a2a.stream = [reply] if follow_up["contextId"] == "ctx-2" else STREAM
                self.send("researcher", method=method)   # task-1 in context ctx-1, or a reply in context ctx-2
                self.assertIn("result", self.send("researcher", dict(TEXT, **follow_up)))
                with self.as_other():   # the context is the caller's, as its tasks are
                    _, _, body = self.post("researcher", params={"message": dict(TEXT, contextId=follow_up[
                        "contextId"])}, run=other_run)
                self.assertEqual(json.loads(body)["error"]["code"], -32001)

    def test_a_pair_the_policy_does_not_list_never_reaches_the_receiver(self):
        for method in ("message/send", "message/stream", "tasks/get"):
            with self.subTest(method):
                out = self.send("billing", method=method)
                self.assertEqual(out["error"]["code"], -32000)
                self.assertIn("R-ROUTE", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])
        self.assertEqual([(e["data"]["tool"], e["data"]["decision"]) for e in self.events()
                          if e["type"] == "policy.decision"],
                         [("a2a:billing/message/send", "deny"), ("a2a:billing/message/stream", "deny"),
                          ("a2a:billing/tasks/get", "deny")])

    def test_a_receiver_whose_card_lists_an_unlisted_skill_never_gets_the_message(self):
        out = self.send("payer")
        self.assertIn("R-SKILL", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])
        [d] = [e["data"] for e in self.events() if e["type"] == "policy.decision"]
        card = "sha256:" + hashlib.sha256(json.dumps(PAYER_CARD).encode()).hexdigest()
        args = {"sender": "token:http", "receiver": "payer", "agent_card": card, "skills": ["payments", "search"],
                "params": {"message": TEXT}}
        self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                      event_hash({"tool": "a2a:payer/message/send", "args": args})))

    def test_a_message_over_the_size_rule_never_reaches_the_receiver(self):
        out = self.send("researcher", dict(TEXT, parts=[{"kind": "text", "text": "x" * 10000}]))
        self.assertIn("R-SIZE", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])

    def test_a_held_message_is_sent_only_once_a_person_approves(self):
        for decision, sent in (("reject", []), ("approve", [FILE])):
            with self.subTest(decision):
                got = {}
                t = threading.Thread(target=lambda: got.update(out=self.send("researcher", FILE)))
                t.start()
                for _ in range(500):
                    aids = [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {
                        "run_id": self.run["run_id"], "state": "requested"})["approvals"]]
                    if aids:
                        break
                    time.sleep(0.01)
                self.assertEqual(self.a2a.seen, [])   # held: nothing sent yet
                self.s.call(AGENT, "approval_decide", {"request_id": uuid.uuid4().hex, "approval_id": aids[0],
                                                       "decision": decision})
                t.join(20)
                self.assertEqual([r["params"]["message"] for _, r in self.a2a.seen], sent)
                if sent:
                    self.assertEqual(got["out"]["result"]["id"], "task-1")
                else:
                    self.assertIn("R-FILE: approval rejected", got["out"]["error"]["message"])

    def test_the_signer_unreachable_fails_closed(self):
        self.signer.down = True
        for method in ("message/send", "message/stream"):
            with self.subTest(method):
                out = self.send("researcher", method=method)
                self.assertIn("signer is unreachable", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])

    def test_a_stream_is_recorded_event_by_event_and_completed_at_its_final_event(self):
        got = self.send("researcher", method="message/stream")
        self.assertEqual([e["id"] for e in got], [7] * 4)
        self.assertEqual([e["result"] for e in got[:2] + got[3:]], STREAM[:2] + STREAM[3:])
        self.assertEqual(got[2]["result"]["artifact"]["parts"][0]["text"], "done as [REDACTED:executor_secret]")
        [(_, req)] = self.a2a.seen
        self.assertEqual((req["method"], req["params"]), ("message/stream", {"message": TEXT}))
        evs = [e for e in self.verified() if e["type"] in ("policy.decision", "input.observed", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"]) for e in evs],
                         [("policy.decision", "gateway", "T2")] + [("input.observed", "gateway", "T2")] * 4
                         + [("tool.result", "gateway", "T2")])
        d, tcid = evs[0]["data"], evs[0]["tool_call_id"]
        self.assertEqual((d["tool"], d["decision"]), ("a2a:researcher/message/stream", "allow"))
        self.assertEqual({(e["data"]["source"], e["data"]["trust"]) for e in evs[1:5]},
                         {(f"a2a:researcher/message/stream#{tcid}", "untrusted")})
        # the call's result is every event the client got, in order
        out = evs[5]["data"]
        events = [{"result": e["result"]} for e in got]
        self.assertTrue(out["ok"])
        self.assertTrue(self.s._opens(out["output"]["hash"], "result:" + d["decision_id"],
                                      "sha256:" + hashlib.sha256(canonical({"result": events})).hexdigest()))
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("a2a-upstream-0123456789", f.read())

    def test_a_stream_cut_mid_way_ends_in_an_error_and_a_signed_gap(self):
        self.a2a.stream = STREAM[:2]   # the upstream goes away before its final event
        got = self.send("researcher", method="message/stream")
        self.assertEqual([e["result"] for e in got[:2]], STREAM[:2])
        self.assertEqual(got[2]["error"]["code"], -32603)
        self.assertIn("the stream was cut after 2 event(s): the upstream ended it before its final event",
                      got[2]["error"]["message"])
        evs = self.verified()
        [tcid] = [e["tool_call_id"] for e in evs if e["type"] == "policy.decision"]
        self.assertEqual(len([e for e in evs if e["type"] == "input.observed"]), 2)
        self.assertEqual([e for e in evs if e["type"] == "tool.result"], [])
        self.assertEqual([(e["data"]["kind"], e["source"]) for e in evs if e["type"] == "capture.gap"
                          and e["data"].get("tool_use_id") == tcid], [("held_call_unresolved", "signer")])

    def test_an_event_the_signer_cannot_record_is_never_passed_on(self):
        observe, seen = self.signer.observe, []

        def flaky(req):   # the signer goes away after the stream's second event
            if len(seen) == 2:
                raise SignerUnavailable("down")
            seen.append(req)
            return observe(req)
        self.signer.observe = flaky
        got = self.send("researcher", method="message/stream")
        self.assertEqual([e.get("result") for e in got[:2]], STREAM[:2])
        self.assertEqual(len(got), 3)
        self.assertIn("an event could not be recorded, so it was not passed on", got[2]["error"]["message"])
        evs = self.events()
        self.assertEqual(len([e for e in evs if e["type"] == "input.observed"]), 2)
        self.assertEqual([e for e in evs if e["type"] == "tool.result"], [])

    def test_any_other_method_is_refused_and_nothing_is_decided_or_sent(self):
        for method in ("tasks/cancel", "tasks/resubscribe", "tasks/pushNotificationConfig/set", "nope"):
            with self.subTest(method):
                out = self.send("researcher", method=method)
                self.assertEqual(out["error"]["code"], -32601)
                self.assertIn("relays message/send, message/stream, tasks/get", out["error"]["message"])
        self.assertEqual(self.a2a.seen, [])
        self.assertEqual([e for e in self.events() if e["type"] == "policy.decision"], [])

    def test_an_unknown_upstream_is_not_found(self):
        self.assertEqual(self.post("nope")[0], 404)
        self.assertEqual(self.post("Researcher")[0], 404)

    def test_upstream_names_are_lower_case(self):   # the policy reads names in any case: one name, one upstream
        for name in ("Researcher", "x" * 65):
            bad = dict(self.cfg, upstreams=[dict(self.cfg["upstreams"][0], name=name)])
            with self.assertRaisesRegex(ValueError, r"name is unique, \[a-z0-9-\]\{1,64\}"):
                a2a_gateway.load_config(self.config(bad))

    # the checklist's API-surface items (docs/security-checklist.md), on this surface

    def test_refusals_never_reach_the_upstream(self):   # 9, 11: credentials on every request; a run's own token only
        other = self.register(OTHER)
        for case, status, kw in (
                ("no identity", 401, {"headers": {"authorization": None}}),
                ("a wrong token", 401, {"headers": {"authorization": "Bearer " + "w" * 40}}),
                ("no run", 401, {"headers": {"x-tracekit-run": None}}),
                ("a malformed run", 401, {"headers": {"x-tracekit-run": "run-1"}}),
                ("an unknown run", 200, {"run": {**self.run, "run_id": "nope"}}),
                ("another run's token", 200, {"run": {**self.run, "run_token": self.register(AGENT)["run_token"]}}),
                ("another tenant's run", 200, {"run": other})):
            with self.subTest(case):
                code, _, body = self.post("researcher", **kw)
                self.assertEqual(code, status)
                if code == 200:
                    self.assertIn("the signer refused the call", json.loads(body)["error"]["message"])
        self.assertEqual(self.a2a.seen, [])

    def test_failed_authentications_are_limited_per_address(self):   # 15
        for _ in range(25):
            code, _, body = self.post("researcher", headers={"authorization": "Bearer " + "w" * 40})
            self.assertEqual(code, 401)
        self.assertIn(b"too many failed authentications", body)
        self.assertNotIn(b"w" * 40, body)
        self.assertIn("result", self.send("researcher"))   # a valid credential still gets in
        self.assertEqual(len(self.a2a.seen), 1)

    def test_a_slow_client_is_cut_off(self):   # 15
        self.srv.read_timeout = 0.5
        run = f"{self.run['run_id']}.{self.run['run_token']}".encode()
        for partial in (b"POST /a2a/researcher HTTP/1.1\r\nHost: x\r\n",
                        b"POST /a2a/researcher HTTP/1.1\r\nAuthorization: Bearer " + SECRET.encode() +
                        b"\r\nX-Tracekit-Run: " + run + b"\r\nContent-Length: 50\r\n\r\n{"):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            self.addCleanup(s.close)
            s.sendall(partial)
            t = time.monotonic()
            self.assertEqual(s.recv(65536), b"")   # closed by the gateway after its read timeout
            self.assertLess(time.monotonic() - t, 3)
        self.assertEqual(self.a2a.seen, [])

    def test_plain_http_beyond_loopback_is_refused_before_any_card_is_read(self):   # 17
        cards = list(self.a2a.cards)
        wide = dict(self.cfg, http=dict(self.cfg["http"], listen="0.0.0.0:0"))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(a2a_gateway.main(["serve", "--config", self.config(wide)]), 2)
        self.assertRegex(err.getvalue(), "plain HTTP only with insecure_loopback on a loopback address")
        self.assertEqual(self.a2a.cards, cards)

    def test_an_upstream_that_is_down_gets_nothing_and_the_call_says_so(self):   # 16: errors without internals
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        down = f"http://127.0.0.1:{s.getsockname()[1]}/a2a"
        s.close()
        up = self.srv.a2a["upstreams"]["researcher"]
        up["url"] = up["action"]["url_template"] = down
        for method in ("message/send", "message/stream"):
            with self.subTest(method):
                err = self.send("researcher", method=method)["error"]
                self.assertEqual(err["code"], -32603)
                self.assertIn("upstream unreachable, the message was not sent", err["message"])
                for leak in ("Traceback", 'File "', UPSTREAM_KEY):
                    self.assertNotIn(leak, err["message"])
        self.assertEqual([e["data"]["ok"] for e in self.events() if e["type"] == "tool.result"], [False, False])

    def test_answers_and_streams_over_max_body_are_cut(self):   # 14: response sizes too
        self.srv.a2a["max_body"], self.a2a.big = 1024, True
        err = self.send("researcher")["error"]
        self.assertIn("the message was sent but its answer could not be read (upstream response over 1024 bytes)",
                      err["message"])
        got = self.send("researcher", method="message/stream")
        self.assertIn("it broke (over 1024 bytes in all)", got[-1]["error"]["message"])
        self.assertEqual(len(got), 3)   # the task and the first update, then the error: the artifact passed max_body

    def test_a_stream_idle_past_its_timeout_is_cut(self):   # timeouts
        self.a2a.stream = STREAM[:1] + ["pause"] + STREAM[1:]
        with mock.patch.object(a2a_gateway, "STREAM_IDLE_S", 0.3):
            got = self.send("researcher", method="message/stream")
        self.assertEqual(got[0]["result"], STREAM[0])
        self.assertIn("the stream was cut after 1 event(s): it broke (timed out)", got[1]["error"]["message"])


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
        self.s.close()   # every file it keeps, closed (Windows won't read one the signer holds locked)
        for root, _, files in os.walk(self.dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    self.assertNotIn(b"KV-CACHE-PAYLOAD-", f.read(), name)

    def test_a_transfer_through_an_unlisted_projector_is_denied(self):
        out = self.run.transfer("qwen-7b@1", "llama-1b@2", b"state", "kv-cache", projector="c2c@0.2")
        self.assertEqual((out["ok"], out["decision"], out["rule_ids"]), (False, "deny", ["R-ROUTE"]))

    def test_measured_cannot_replace_the_transfer_commitments(self):
        for key in ("sender", "size", "digest", "claimed"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "measured.*reserved"):
                    self.run.transfer("qwen-7b@1", "llama-1b@2", b"state", "kv-cache", measured={key: "x"})

    def test_the_signer_matches_a_names_spellings_and_signs_the_callers(self):
        """In the signer: a case variant of the listed triple is that triple, a look-alike is refused (TK-A2A-NAME)
        with its fixed reason and remedy, and each decision commits to the names as the caller spelt them."""
        fixed = policy_compile.ENGINE_REASONS["TK-A2A-NAME"]
        self.assertEqual(policy_compile._lint_remedy(fixed["remedy"], "deny"), [])
        for sender, ok, rule_ids in (("QWEN-7b@1", True, []), ("qwеn-7b@1", False, ["TK-A2A-NAME"])):
            with self.subTest(sender=sender):
                out = self.run.transfer(sender, "llama-1b@2", b"state", "kv-cache", projector="c2c@0.1")
                self.assertEqual((out["ok"], out["rule_ids"]), (ok, rule_ids))
                self.assertEqual(out.get("reason"), None if ok else f"{fixed['reason']}. {fixed['remedy']}")
                d = [r["event"]["data"] for r in self.s.log.storage.iter_run("default", self.run.run_id)
                     if r["event"]["type"] == "policy.decision"][-1]
                args = {"sender": sender, "receiver": "llama-1b@2", "modality": "kv-cache", "size": 5,
                        "digest": "sha256:" + hashlib.sha256(b"state").hexdigest(), "projector": "c2c@0.1",
                        "claimed": ["modality", "projector", "receiver", "sender"], "measured": ["digest", "size"]}
                self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                              event_hash({"tool": "a2a:transfer", "args": args})))


class Policy(unittest.TestCase):
    def test_server_and_strict_hold_a2a_calls_and_scan_their_params_as_targets(self):
        packs = os.path.join(os.path.dirname(policy_compile.__file__), "packs")
        metadata = {"sender": "token:http", "receiver": "researcher", "params": {"message": {
            "parts": [{"kind": "file", "file": {"uri": "http://169.254.169.254/latest/meta-data/iam/"}}]}}}
        text = {"sender": "token:http", "receiver": "researcher", "params": {"message": TEXT}}
        transfer = dict(TRIPLE)
        for pack in ("server.yaml", "strict.yaml"):
            e = Engine(policy_compile.build(os.path.join(packs, pack))[0])
            with self.subTest(pack=pack, call="metadata"):
                self.assertEqual((e.decide("a2a:researcher/message/send", metadata)["verdict"],
                                  e.decide("a2a:researcher/message/send", metadata)["rule_ids"]),
                                 ("deny", ["TK-S001", "TK-S011", "TK-F012"]))
            for tool, args in (("a2a:researcher/message/send", text), ("a2a:transfer", transfer)):
                with self.subTest(pack=pack, call=tool):
                    self.assertEqual((e.decide(tool, args)["verdict"], e.decide(tool, args)["rule_ids"]),
                                     ("ask", ["TK-S011"]))

    def test_a_deployment_redefines_tk_s011_to_allow_its_a2a_pairs_unattended(self):
        packs = os.path.join(os.path.dirname(policy_compile.__file__), "packs")
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(packs, os.path.join(d, "packs"))
            for pack in ("server.yaml", "strict.yaml"):
                path = os.path.join(d, f"{pack[:-5]}-a2a.yaml")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("extends: packs/" + pack + "\nask:\n"
                            "  - id: TK-S011\n    class: a2a\n    field: route\n    pattern: '.'\n"
                            "    unless: '^mtls:spiffe://acme\\.org/planner->(researcher|writer)$'\n")
                policy, errors = policy_compile.build(path)
                self.assertEqual(errors, [])
                decision = Engine(policy).decide("a2a:researcher/message/send", {
                    "sender": "mtls:spiffe://acme.org/planner", "receiver": "researcher",
                    "params": {"message": TEXT}})
                with self.subTest(pack=pack):
                    self.assertEqual((decision["verdict"], decision["rule_ids"]), ("allow", []))

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

    def test_a2a_size_covers_all_params(self):
        e = Engine({"tools": {"a2a:*": "a2a"}, "deny": [{"id": "R-SIZE", "class": "a2a", "field": "size",
                                                               "pattern": "^[0-9]{5,}$"}]})
        args = {"sender": "token:http", "receiver": "researcher",
                "params": {"message": TEXT, "metadata": "x" * 10000}}
        self.assertEqual(e.decide("a2a:researcher/message/send", args)["rule_ids"], ["R-SIZE"])

    def test_a2a_policy_can_deny_task_like_metadata(self):
        e = Engine({"tools": {"a2a:*": "a2a"}, "deny": [{"id": "R-METADATA-TASK", "class": "a2a",
                                                                  "field": "target",
                                                                  "pattern": '"metadata":.*"(taskId|contextId|referenceTaskIds)":'}]})
        args = {"sender": "token:http", "receiver": "researcher",
                "params": {"message": TEXT, "metadata": {"taskId": "task-1"}}}
        self.assertEqual(e.decide("a2a:researcher/message/send", args)["rule_ids"], ["R-METADATA-TASK"])

    def test_a_rule_for_a_name_sees_every_spelling_of_it(self):
        """A deny rule and an allow-list written for a name's logical spelling: its case matches either way, and a
        spelling no rule could match (space, a look-alike, a zero-width or control character) is denied, TK-A2A-NAME,
        on both regex engines."""
        deny = {"tools": {"a2a:*": "a2a"}, "deny": [
            {"id": "R-BAD", "class": "a2a", "field": "projector", "pattern": "^bad-fuser@1$"},
            {"id": "R-UPPER", "class": "a2a", "field": "sender", "pattern": "^Evil-7B@1$"}]}   # a rule in upper case
        for backend in ("re2", "regex") if HAVE_RE2 else ("regex",):
            e = Engine(deny, backend=backend)
            self.assertEqual(e.decide("a2a:transfer", dict(TRIPLE, projector="bad-fuser@1"))["rule_ids"], ["R-BAD"])
            self.assertEqual(e.decide("a2a:transfer", dict(TRIPLE, sender="evil-7b@1"))["rule_ids"], ["R-UPPER"])
            for how, spelt in spellings("bad-fuser@1").items():
                with self.subTest(backend=backend, rule="deny", spelling=how):
                    d = e.decide("a2a:transfer", dict(TRIPLE, projector=spelt))
                    self.assertEqual((d["verdict"], d["rule_ids"]),
                                     ("deny", ["R-BAD"] if how == "case" else ["TK-A2A-NAME"]))
            a = Engine(POLICY, backend=backend)   # R-ROUTE lets only the listed triples through
            self.assertEqual(a.decide("a2a:transfer", TRIPLE)["rule_ids"], [])
            self.assertEqual(a.decide("a2a:transfer", dict(TRIPLE, sender="QWEN-8B@1"))["rule_ids"], ["R-ROUTE"])
            for field in ("sender", "receiver", "projector"):
                for how, spelt in spellings(TRIPLE[field]).items():
                    with self.subTest(backend=backend, rule="allow-list", field=field, spelling=how):
                        d = a.decide("a2a:transfer", dict(TRIPLE, **{field: spelt}))
                        self.assertEqual((d["verdict"], d["rule_ids"]),
                                         ("allow", []) if how == "case" else ("deny", ["TK-A2A-NAME"]))
        msg = {"sender": "token:http", "receiver": "researcher", "skills": ["search"], "params": {"message": TEXT}}
        e = Engine(POLICY)
        for field, value, rule_ids in (("skills", ["SEARCH"], []), ("skills", ["se​arch"], ["TK-A2A-NAME"]),
                                       ("modality", "kv‐cache", ["TK-A2A-NAME"])):
            with self.subTest(field=field, value=value):
                self.assertEqual(e.decide("a2a:researcher/message/send", dict(msg, **{field: value}))["rule_ids"],
                                 rule_ids)
        for kind, rule_ids in (("FILE", ["R-FILE"]), ("fіle", ["TK-A2A-NAME"])):   # a part's kind, either way
            part = {"kind": kind, "file": {"uri": "https://files.example/q3.pdf"}}
            with self.subTest(kind=kind):
                self.assertEqual(e.decide("a2a:researcher/message/send", dict(msg, params={"message": dict(
                    FILE, parts=[part])}))["rule_ids"], rule_ids)
        self.assertIn("p.yaml: flag rule TK-A2A-NAME: the engine or the signer gives a decision this id itself",
                      "\n".join(policy_compile._lint(dict(POLICY, flag=[{"id": "TK-A2A-NAME", "pattern": "x"}]),
                                                     "p.yaml")))

    def test_every_pack_a_signer_runs_maps_a2a_calls_to_the_a2a_class(self):
        packs = os.path.join(os.path.dirname(policy_compile.__file__), "packs")
        whole = {"coding.yaml", "dev.yaml", "server.yaml", "strict.yaml"}   # coding.yaml maps a2a:*; the rest extend it
        parts = {"browser.yaml", "server-cloud.yaml", "server-comms.yaml", "server-data.yaml", "server-net.yaml"}
        self.assertEqual(set(os.listdir(packs)), whole | parts)   # a new pack is one or the other (server.yaml's parts)
        for name in sorted(whole):
            e = Engine(policy_compile.build(os.path.join(packs, name))[0])
            for tool in ("a2a:researcher/message/send", "a2a:researcher/message/stream", "a2a:researcher/tasks/get",
                         "a2a:transfer"):
                with self.subTest(pack=name, tool=tool):
                    self.assertEqual(e.tool_class(tool), "a2a")

    def test_skills_from_the_receivers_card_meet_an_allow_list(self):
        e = Engine(POLICY)
        args = {"sender": "token:http", "receiver": "researcher", "params": {"message": TEXT}}
        for skills, rule_ids in ((["search"], []), (["payments", "search"], ["R-SKILL"]), ([], [])):
            with self.subTest(skills):
                self.assertEqual(e.decide("a2a:researcher/message/send", dict(args, skills=skills))["rule_ids"],
                                 rule_ids)
