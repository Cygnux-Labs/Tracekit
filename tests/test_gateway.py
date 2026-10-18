"""The LLM gateway (tracekit/gateway.py) in front of a fake OpenAI-compatible upstream, recording into an in-process v2
signer as source gateway; and gateway L3 in reconciliation (tracekit/signer/reconcile.py)."""
import hashlib
import hmac
import http.client
import http.server
import json
import os
import threading
import time
import unittest
from unittest import mock
import uuid

from adapter_contract import tmpdir
from test_reconcile import use
from test_signer_service import records
from tracekit import gateway
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.sdk import client
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import pipeline, service as svc
from tracekit.storage import file as file_storage
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.transport import parse_frame

GW = CallerIdentity("mtls", "spiffe://acme/gateway", True)
AGENT = CallerIdentity("token", "http", True)        # what the gateway's token authenticator establishes
OTHER = CallerIdentity("uid", "999003", True)         # tenant beta
SECRET = "s" * 40
CALL = {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": '{"path": "a"}'}}
COMPLETION = {"id": "chatcmpl-1", "model": "gpt-x", "choices": [
    {"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "tool_calls": [CALL]}}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 2}}


def sse(*events):
    return b"".join(b"data: " + (e if isinstance(e, bytes) else json.dumps(e).encode()) + b"\n\n" for e in events)


STREAM = sse({"id": "chatcmpl-2", "model": "gpt-x", "choices": [{"index": 0, "delta": {"tool_calls": [
    {"index": 0, "id": "call_2", "type": "function", "function": {"name": "read_file", "arguments": ""}}]}}]},
             {"id": "chatcmpl-2", "choices": [{"index": 0, "delta": {"tool_calls": [
                 {"index": 0, "function": {"arguments": '{"path": "a"}'}}]}}]},
             {"id": "chatcmpl-2", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}, b"[DONE]")


class Upstream(http.server.BaseHTTPRequestHandler):
    """Answers with the server's `reply`: ("json", obj[, status]), ("sse", bytes) or ("cut", bytes): a chunked stream
    that breaks after `bytes`; ("redirect", location); a list of those: one per request, in order."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.server.seen.append((dict(self.headers), self.rfile.read(int(self.headers["content-length"]))))
        time.sleep(self.server.delay)
        reply = self.server.reply
        how, data, *status = reply.pop(0) if isinstance(reply, list) else reply
        if how == "redirect":
            self.send_response(302)
            self.send_header("location", data)
            self.send_header("content-length", "0")
            return self.end_headers()
        self.send_response(*status or [200])
        if how == "json":
            body = json.dumps(data).encode()
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        if how == "cut":
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(b"0\r\n\r\n")


class InProcess:
    """The gateway's signer client: the in-process service, called as the gateway's identity."""

    def __init__(self, s):
        self.s, self.down, self.refuse, self.sent = s, False, False, []

    def model_event(self, req):
        if self.down:
            raise SignerUnavailable("down")
        if self.refuse and req["phase"] == "response":
            raise RPCError("run_closed", req["run_id"])
        self.sent.append(req)
        return self.s.call(GW, "model_event", {"request_id": uuid.uuid4().hex, **req})

    def status(self, req):
        return self.s.call(GW, "status", req)


def serve(case, srv):
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv.server_address[1]


class Gateway(unittest.TestCase):
    mandatory, content, verify = False, None, None

    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, tenants={OTHER.scheme + ":" + OTHER.subject: "beta"},
                                   gateways=["mtls:spiffe://acme/*"], gateway_mandatory=self.mandatory,
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/gateway": ["model_event", "status"]},
                                   grace_s=60, idle_s=600, content=self.content, verify_tool_results=self.verify)
        self.closed = False
        self.addCleanup(self.close)
        self.up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.up.seen, self.up.reply, self.up.delay = [], ("json", COMPLETION), 0
        up_port = serve(self, self.up)
        with open(os.path.join(self.dir, "provider.key"), "w") as f:
            f.write("provider-key\n")
        with open(os.path.join(self.dir, "bearer"), "w") as f:
            f.write(SECRET)
        with open(os.path.join(self.dir, "gateway.yaml"), "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"},
                       "upstream": f"http://127.0.0.1:{up_port}", "api_key_file": "provider.key",
                       "signer": "unused", "max_body": 4096}, f)
        self.signer = InProcess(self.s)
        self.gw = gateway.serve(gateway.load_config(os.path.join(self.dir, "gateway.yaml")), self.signer)
        self.port = serve(self, self.gw)
        self.run = self.register(AGENT)

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def register(self, who):
        out = self.s.call(who, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "a"}})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def post(self, body=None, run=None, headers=None, path="/v1/chat/completions"):
        """(status, body); body is the bytes read before the connection broke, if it did."""
        run = run or self.run
        h = {"Authorization": "Bearer " + SECRET, "X-Tracekit-Run": f"{run['run_id']}.{run['run_token']}",
             "Content-Type": "application/json"}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("POST", path, json.dumps({"model": "gpt-x", "messages": []} if body is None else body).encode(),
                  {k: v for k, v in h.items() if v is not None})
        r = c.getresponse()
        try:
            return r.status, r.read()
        except http.client.IncompleteRead as e:
            return r.status, b"BROKEN:" + e.partial

    def events(self, run=None):
        self.close()
        rid = (run or self.run)["run_id"]
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == rid]

    def exchanges(self, run=None):
        return [(e["source"], e["data"]["phase"], e["data"].get("error")) for e in self.events(run)
                if e["type"] == "model.exchange"]

    def agent_l3(self, seq, uses):
        self.s.call(AGENT, "model_event", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent",
                                           "client_seq": seq, "provider": "openai", "model": "m", "phase": "response",
                                           "tool_uses": uses})

    def decide(self, seq, tcid, args=None):
        self.s.call(AGENT, "decide", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent", "client_seq": seq,
                                      "tool_call_id": tcid, "tool": "read_file", "args_source": "parsed",
                                      "args": args or {}})

    def final(self, run=None):
        """The run's reconcile records (type, tool_call_id) after its grace window."""
        run = run or self.run
        self.s.call(AGENT, "close_run", {"request_id": uuid.uuid4().hex, **run})
        self.s.sweep(time.monotonic() + 61)
        return [(e["type"], e["tool_call_id"]) for e in self.events(run) if e["type"].startswith("reconcile.")]


class RunTable(unittest.TestCase):
    """The gateway's run table holds runs the signer took, and stopping doesn't wait on an unreachable signer."""

    def gw(self, side_effect):
        c = type("C", (), {})()
        c.model_event = c.close_run = lambda req: side_effect(req)
        return gateway.Gateway("https://up.example", "k", client=c)

    def test_a_run_the_signer_refused_is_not_kept(self):
        def refuse(req):
            raise RPCError("run_token_invalid", "not one this signer issued")
        g = self.gw(refuse)
        for i in range(50):
            with self.assertRaises(RPCError):
                g.record((f"run-{i}", "forged.mac", "token:x"), "x", phase="request")
        self.assertEqual(len(g.runs), 0)

    def test_stopping_gives_up_at_the_first_unreachable_signer(self):
        calls = []

        def down(req):
            calls.append(req)
            raise SignerUnavailable("down")
        g = self.gw(down)
        for i in range(20):
            run = g._run((f"run-{i}", "t.mac", "token:x"))
            run.seq = 3   # exchanges the signer never acknowledged
        calls.clear()
        g.close()
        self.assertEqual(len(calls), 1)


class TestAuth(Gateway):
    def test_refusals_never_reach_the_upstream(self):
        other = self.register(OTHER)
        for case, status, kw in (
                ("no identity", 401, {"headers": {"Authorization": None}}),
                ("no run", 401, {"headers": {"X-Tracekit-Run": None}}),
                ("malformed run", 401, {"headers": {"X-Tracekit-Run": "run-1"}}),
                ("unknown run", 403, {"run": {**self.run, "run_id": "nope"}}),
                ("another run's token", 403, {"run": {**self.run, "run_token": self.register(AGENT)["run_token"]}}),
                ("another tenant's token", 403, {"run": other})):
            with self.subTest(case):
                self.assertEqual(self.post(**kw)[0], status)
        self.assertEqual(self.up.seen, [])
        self.assertEqual(self.exchanges(), [])

    def test_a_denied_provider_tool_is_refused_with_a_clear_error(self):
        self.gw.gateway.provider_tools = {"deny": ["web_search_preview"]}
        status, body = self.post({"model": "gpt-x", "input": "hi", "tools": [{"type": "web_search_preview"}]},
                                 path="/v1/responses")
        self.assertEqual(status, 403)
        self.assertIn("provider tool(s) web_search_preview not allowed by this gateway's provider_tools",
                      json.loads(body)["error"]["message"])
        self.assertEqual(self.up.seen, [])
        self.assertEqual(self.post()[0], 200)   # a request without it goes through

    def test_caller_needs_its_own_model_event_grant(self):
        self.s.authorize["token:http"] = ["register_run"]
        self.assertEqual(self.post()[0], 403)
        self.assertEqual(self.up.seen, [])

    def test_only_a_configured_gateway_may_name_a_caller(self):
        req = {"request_id": "r", **self.run, "stream": "s", "client_seq": 0, "provider": "openai", "model": "m",
               "phase": "request", "caller": "token:http"}
        with self.assertRaises(RPCError) as cm:
            self.s.call(AGENT, "model_event", req)
        self.assertEqual(cm.exception.code, "forbidden")


class TestContentVault(Gateway):
    content = {"retain": True}

    def test_bodies_are_kept_with_the_vault_on(self):
        for reply, stream in ((("json", COMPLETION), False), (("sse", STREAM), True)):
            self.up.reply = reply
            self.assertEqual(self.post({"model": "gpt-x", "messages": [], "stream": stream})[0], 200)
        seqs = [r["event"]["run_seq"] for r in self.s.log.storage.iter_run("default", self.run["run_id"])
                if r["event"]["type"] == "model.exchange"]
        self.s.authorize["token:http"] = sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR) + ["content_read"]
        items = self.s.call(AGENT, "content_get", {"run_id": self.run["run_id"], "seqs": seqs, "purpose": "t"})["items"]
        got = [i["content"] for i in items]
        self.assertEqual(got[:3], [{"model": "gpt-x", "messages": [], "stream": False}, COMPLETION,
                                   {"model": "gpt-x", "messages": [], "stream": True}])
        self.assertEqual(got[3]["choices"][0]["message"]["tool_calls"][0]["id"], "call_2")   # the stream, assembled


class Wire(InProcess):
    """model_event as the real Client frames it, then as the signer parses that frame."""

    def model_event(self, req):
        frame = parse_frame(client._encode("model_event", req))
        frame.pop("method")
        return super().model_event(frame)


ODD = {"integer past 2^53": 12345678901234567890, "non-finite": float("inf"), "lone surrogate": "\ud800"}


class TestOddBodiesVaultOff(Gateway):
    """Bodies a frame cannot carry (the client's real frames): answered as with the vault off; with it on, recorded
    without a body (the raw bytes' digest)."""

    def setUp(self):
        super().setUp()
        self.signer = self.gw.gateway.client = Wire(self.s)

    def test_bodies_a_frame_cannot_carry_are_answered(self):
        usage = dict(COMPLETION["usage"])
        for name, odd in ODD.items():
            for side, body, reply in (
                    ("request", {"model": "gpt-x", "messages": [], "x": odd}, ("json", COMPLETION)),
                    ("response", None, ("json", dict(COMPLETION, x=odd))),
                    ("stream", {"model": "gpt-x", "messages": [], "stream": True},
                     ("sse", sse({"id": "c", "model": "gpt-x", "usage": dict(usage, x=odd), "choices": [
                         {"index": 0, "delta": {}, "finish_reason": "stop"}]}, b"[DONE]")))):
                with self.subTest(name, side=side):
                    self.signer.sent.clear()
                    self.up.reply = reply
                    self.assertEqual(self.post(body)[0], 200)
                    odd_phase = "request" if side == "request" else "response"
                    self.assertEqual([("body" in r) for r in self.signer.sent if r["phase"] == odd_phase], [False])
                    self.assertEqual([("body" in r) for r in self.signer.sent if r["phase"] != odd_phase],
                                     [bool(self.content)])


class TestOddBodiesVaultOn(TestOddBodiesVaultOff):
    content = {"retain": True}

    def test_not_retained_and_the_raw_digest_recorded(self):
        raw = json.dumps({"model": "gpt-x", "messages": [], "x": ODD["integer past 2^53"]}).encode()
        self.assertEqual(self.post(json.loads(raw))[0], 200)
        [req] = [r["event"] for r in self.s.log.storage.iter_run("default", self.run["run_id"])
                 if r["event"]["type"] == "model.exchange" and r["event"]["data"]["phase"] == "request"]
        self.s.authorize["token:http"] = sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR) + ["content_read"]
        [item] = self.s.call(AGENT, "content_get", {"run_id": self.run["run_id"], "seqs": [req["run_seq"]],
                                                    "purpose": "t"})["items"]
        self.assertEqual(item, {"seq": req["run_seq"], "state": "not_retained"})
        e = svc.reveal(self.dir, req["seq"])
        self.assertEqual(req["data"]["content_digest"], "hmac-sha256:" + hmac.new(
            bytes.fromhex(e["salt"]), ("sha256:" + hashlib.sha256(raw).hexdigest()).encode(), "sha256").hexdigest())


class TestExchange(Gateway):
    def test_no_body_leaves_the_gateway_without_the_content_vault(self):
        self.assertEqual(self.post({"model": "gpt-x", "messages": []})[0], 200)
        self.assertEqual([("body" in r) for r in self.signer.sent], [False, False])

    def test_response_recorded_as_gateway_l3_with_the_gateways_credential(self):
        status, body = self.post({"model": "gpt-x", "messages": [{"role": "tool", "tool_call_id": "call_0"}]})
        self.assertEqual((status, json.loads(body)), (200, COMPLETION))
        headers, _ = self.up.seen[0]
        self.assertEqual(headers.get("Authorization"), "Bearer provider-key")
        self.assertNotIn("X-Tracekit-Run", headers)
        req, resp = [e for e in self.events() if e["type"] == "model.exchange"]
        self.assertEqual((req["source"], req["data"]["phase"], req["data"]["tool_results_sent"]),
                         ("gateway", "request", ["call_0"]))
        self.assertEqual((resp["source"], resp["data"]["phase"], resp["data"]["stop_reason"]),
                         ("gateway", "response", "tool_calls"))
        [t] = resp["data"]["tool_uses"]
        self.assertEqual((t["id"], t["name"], t["executed_by"]), ("call_1", "read_file", "client"))
        self.assertTrue(t["args_commitment"].startswith("hmac-sha256:"))
        self.assertEqual(resp["data"]["usage"]["input_tokens"], 3)

    def test_run_in_the_bearer_needs_a_certificate(self):
        run = f"{self.run['run_id']}.{self.run['run_token']}"
        self.assertEqual(self.post(headers={"X-Tracekit-Run": None, "Authorization": "Bearer " + run})[0], 401)

    def test_stream_passes_through_and_is_recorded(self):
        self.up.reply = ("sse", STREAM)
        status, body = self.post({"model": "gpt-x", "messages": [], "stream": True})
        self.assertEqual((status, body), (200, STREAM))
        self.assertEqual(self.exchanges(), [("gateway", "request", None), ("gateway", "response", None)])
        [resp] = [e for e in self.events() if e["data"].get("phase") == "response"]
        self.assertEqual([t["id"] for t in resp["data"]["tool_uses"]], ["call_2"])

    def test_a_slow_upstream_is_not_cut_by_the_request_deadline(self):
        self.gw.deadline, self.up.delay = 0.2, 0.5   # the request is in at once; its answer takes longer
        self.assertEqual(self.post()[0], 200)

    def test_upstream_cut_mid_stream_is_an_error_for_the_client_and_the_record(self):
        for case, data in (("broken", STREAM[:60]), ("no terminal event", STREAM[:-len(sse(b"[DONE]"))])):
            with self.subTest(case):
                self.up.reply = ("cut" if case == "broken" else "sse", data)
                status, body = self.post({"model": "gpt-x", "messages": [], "stream": True})
                self.assertEqual(status, 200)
                self.assertTrue(body.startswith(b"BROKEN:" + data), body)
                self.assertIn(b"event: error", body)
        self.assertEqual([x[:2] for x in self.exchanges()], [("gateway", "request"), ("gateway", "response")] * 2)
        errors = [err for _, phase, err in self.exchanges() if phase == "response"]
        self.assertIn("stream broke", errors[0])
        self.assertIn("before its terminal event", errors[1])

    def test_upstream_errors_are_passed_on_as_errors_and_recorded(self):
        failed = sse({"type": "response.created", "response": {"id": "r1", "model": "gpt-x"}},
                     {"type": "response.failed", "response": {"id": "r1", "error": {"message": "boom"}}})
        for case, reply, path, want in (
                ("status", ("json", {"error": {"message": "boom"}}, 500), "/v1/chat/completions", 500),
                ("error event", ("sse", failed), "/v1/responses", 200),
                ("redirect", ("redirect", "/elsewhere"), "/v1/chat/completions", 502)):
            with self.subTest(case):
                self.up.reply = reply
                status, body = self.post({"model": "gpt-x", "input": [], "stream": case == "error event"}, path=path)
                self.assertEqual(status, want)
                if case == "error event":
                    self.assertTrue(body.startswith(b"BROKEN:" + failed), body)
                    self.assertIn(b"event: error", body)
        self.assertEqual(len(self.up.seen), 3)
        errors = [err for _, phase, err in self.exchanges() if phase == "response"]
        self.assertEqual([e and e.split(":")[0] for e in errors],
                         ["upstream status 500", "upstream error event", "upstream status 302"])

    def test_bodies_are_capped(self):
        self.assertEqual(self.post({"model": "gpt-x", "messages": [], "pad": "x" * 5000})[0], 413)
        self.assertEqual(self.up.seen, [])
        self.up.reply = ("json", dict(COMPLETION, pad="x" * 5000))
        self.assertEqual(self.post()[0], 502)
        [(_, _, err)] = [x for x in self.exchanges() if x[1] == "response"]
        self.assertIn("over 4096 bytes", err)

    def test_signer_down_fails_closed(self):
        self.signer.down = True
        self.assertEqual(self.post()[0], 503)
        self.assertEqual(self.up.seen, [])


class TestFailOpen(Gateway):
    def setUp(self):
        super().setUp()
        self.s.fail_modes = {"default": "closed", "model": "open"}

    def test_open_only_for_a_run_the_signer_answered_for(self):
        self.signer.down = True
        self.assertEqual(self.post()[0], 503)   # never answered: closed
        self.signer.down = False
        self.assertEqual(self.post()[0], 200)
        self.signer.down = True
        self.assertEqual(self.post()[0], 200)
        self.assertEqual(len(self.up.seen), 2)

    def test_a_refused_response_record_is_an_error_whatever_the_fail_mode(self):
        self.signer.refuse = True
        self.assertEqual(self.post()[0], 503)
        self.up.reply = ("sse", STREAM)
        status, body = self.post({"model": "gpt-x", "messages": [], "stream": True})
        self.assertEqual(status, 200)
        self.assertNotIn(b"[DONE]", body)
        self.assertIn(b"event: error", body)

    def test_exchanges_forwarded_while_the_signer_was_down_leave_a_gap(self):
        self.post()
        self.signer.down = True
        self.post()
        self.signer.down = False
        self.post()
        [gap] = [e for e in self.events() if e["type"] == "capture.gap"]
        self.assertEqual((gap["data"]["kind"], gap["data"]["missed_events"]), ("client_counter_gap", 2))


class TestHiddenCall(Gateway):
    def test_a_tool_the_model_asked_for_through_the_gateway_and_ran_without_a_decide(self):
        self.post()   # the model asks for call_1; the agent runs it without a decide
        self.assertEqual(self.final(), [("reconcile.hook_missing", "call_1")])

    def test_decided_call_is_reconciled_and_gateway_l3_wins_over_the_agents(self):
        self.post()
        self.agent_l3(0, [use("call_1", "write_file")])
        self.decide(1, "call_1", {"path": "a"})
        self.assertEqual(self.final(), [])


class TestMandatory(Gateway):
    mandatory = True

    def test_agent_reported_l3_does_not_cover_a_decide_the_gateway_never_saw(self):
        self.agent_l3(0, [use("tc-x")])
        self.decide(1, "tc-x")
        self.assertEqual(self.final(), [("reconcile.fabricated", "tc-x")])

    def test_run_without_any_gateway_record_still_has_its_decides_checked(self):
        self.decide(0, "tc-y")
        self.assertEqual(self.final(), [("reconcile.fabricated", "tc-y")])

    def test_a_tool_named_agent_output_needs_a_decide_under_the_server_pack(self):
        """The packs don't name Browser Use's output tool structured_output: else any agent could call a tool of its own
        AgentOutput and run it with no decide, unseen."""
        self.s.policy = svc.load_policy(os.path.join(os.path.dirname(svc.DEFAULT_POLICY), "server.yaml"))
        self.assertFalse(self.s.policy.is_structured_output("AgentOutput"))
        self.up.reply = ("json", dict(COMPLETION, choices=[{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "tool_calls": [dict(CALL, function={"name": "AgentOutput", "arguments": "{}"})]}}]))
        self.assertEqual(self.post()[0], 200)
        self.assertEqual(self.final(), [("reconcile.hook_missing", "call_1")])

    def test_browser_use_actions_are_not_fabricated_under_the_browser_pack(self):
        """Browser Use's actions come in the model's structured output, which carries no tool use: the browser pack
        names them structured_output, so the gateway's exchanges without tool uses don't make them fabricated."""
        self.s.policy = svc.load_policy(os.path.join(os.path.dirname(svc.DEFAULT_POLICY), "browser.yaml"))
        self.up.reply = ("json", dict(COMPLETION, choices=[{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant", "content": '{"action": [{"click": {"index": 3}}]}'}}]))
        self.assertEqual(self.post()[0], 200)
        self.s.call(AGENT, "decide", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent", "client_seq": 0,
                                      "tool_call_id": "bu-1", "tool": "browser_use:click", "args_source": "parsed",
                                      "args": {"index": 3, "page_url": "https://shop.example/"}})
        self.assertEqual(self.final(), [])


def tool_message(content, tcid="call_7"):
    return {"model": "gpt-x", "messages": [{"role": "tool", "tool_call_id": tcid, "content": content}]}


class TestVerifiedToolResults(Gateway):
    """verify_tool_results: the signer compares each tool result a request sends the model with the call's tool.result,
    by the digests the gateway gives of the values the result may have been recorded as."""
    verify = "record"

    def setUp(self):
        super().setUp()
        self.seq = 0

    def decided(self, tcid="call_7", tool="read_file", attempt=0):
        self.seq += 1
        return self.s.call(AGENT, "decide", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent",
                                             "client_seq": self.seq - 1, "tool_call_id": tcid, "tool": tool,
                                             "args_source": "parsed", "args": {}, "attempt": attempt})

    def completed(self, result, tcid="call_7", status="ok", attempt=0):
        """`result` ... (Ellipsis): an ok complete that sends no result, as the quickstart's run.complete("call-1")."""
        d = self.decided(tcid, attempt=attempt)
        self.seq += 1
        out = {} if result is ... else {"result": result} if status == "ok" else {"error": result}
        self.s.call(AGENT, "complete", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent",
                                        "client_seq": self.seq - 1, "tool_call_id": tcid, "attempt": attempt,
                                        "decision_id": d["decision_id"],
                                        "args_digest": event_hash({"tool": "read_file", "args": {}}), "status": status,
                                        **out})

    def mismatches(self):
        return [(e["tool_call_id"], e["data"]["layers"]) for e in self.events() if e["type"] == "reconcile.result_mismatch"]

    def unchecked(self):
        return [e["tool_call_id"] for e in self.events()
                if e["type"] == "capture.gap" and e["data"]["kind"] == "result_unchecked"]

    def reopen(self, drop_snapshots=True):
        """The signer closed and opened again on its data dir; with `drop_snapshots`, rebuilt from the records alone."""
        self.close()
        if drop_snapshots:
            for _, path in file_storage._snapshots(os.path.join(self.dir, "store")):
                os.unlink(path)
        self.s = svc.SignerService(self.dir, gateways=["mtls:spiffe://acme/*"], verify_tool_results="record",
                                   authorize={"token:http": ["model_event"], "mtls:spiffe://acme/gateway": ["model_event"]})
        self.closed = False

    def gateway_sends(self, content, tcid="call_7", seq=0):
        self.s.call(GW, "model_event", {"request_id": uuid.uuid4().hex, **self.run, "caller": "token:http",
                                        "stream": "gx2", "client_seq": seq, "provider": "openai", "model": "m",
                                        "phase": "request",
                                        "tool_results": [{"id": tcid, "forms": gateway.result_forms(content)}]})

    def test_a_result_passed_on_unchanged_matches_in_either_recorded_form(self):
        cases = (("the value", "hello", "hello"), ("its digest", event_hash("hello"), "hello"),
                 ("text blocks", "hello", [{"type": "text", "text": "hel"}, {"type": "text", "text": "lo"}]),
                 ("a JSON string", {"a": 1}, '{"a": 1}'),
                 ("text blocks carrying JSON", {"a": 1}, [{"type": "text", "text": '{"a": 1}'}]))
        for i, (case, recorded, sent) in enumerate(cases):
            with self.subTest(case):
                self.completed(recorded, tcid=f"call_{i}")
                self.assertEqual(self.post(tool_message(sent, tcid=f"call_{i}"))[0], 200)
        self.assertEqual(self.mismatches(), [])
        self.assertEqual(len(self.up.seen), len(cases))

    def test_an_anthropic_tool_result_with_no_content_matches_an_empty_result(self):
        self.completed("", tcid="toolu_1")
        body = {"model": "claude-x", "max_tokens": 10, "messages": [
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1"}]}]}
        self.assertEqual(self.post(body, path="/v1/messages")[0], 200)
        self.assertEqual(self.mismatches(), [])

    def test_an_edited_result(self):
        """A signed mismatch, once per call; record mode forwards. Fails without the check: nothing is written."""
        self.completed("hello")
        self.assertEqual(self.post(tool_message("HELLO"))[0], 200)
        self.assertEqual(self.post(tool_message("HELLO"))[0], 200)   # the history repeats: one record per call
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])
        self.assertEqual(len(self.up.seen), 2)

    def test_a_result_sent_before_the_call_completed_is_recorded_not_refused(self):
        """Its complete may have been lost (the client gave up on it): refusing would stop the run for good, since every
        later request sends the result again. Under refuse it failed with 403 on every request."""
        self.decided("call_9")   # allowed, never completed: whatever the request says it returned, it didn't yet
        for _ in range(2):
            self.assertEqual(self.post(tool_message("made up", tcid="call_9"))[0], 200)
        self.assertEqual(len(self.up.seen), 2)
        [e] = [e for e in self.events() if e["type"] == "reconcile.result_mismatch"]
        self.assertEqual(e["tool_call_id"], "call_9")
        self.assertIn("before the call's result was recorded", e["data"]["detail"])

    def test_no_content_matches_a_result_recorded_as_none_empty_or_no_blocks(self):
        """Pydantic AI sends a tool's None or [] to OpenAI as ""; an empty LlamaIndex result reaches Anthropic as no
        blocks. A result that had content never matches none."""
        for i, (recorded, sent) in enumerate(((None, ""), ([], ""), ("", []), ("", None))):
            with self.subTest(recorded=recorded, sent=sent):
                self.completed(recorded, tcid=f"call_{i}")
                self.assertEqual(self.post(tool_message(sent, tcid=f"call_{i}"))[0], 200)
        self.completed("sent", tcid="call_x")
        self.assertEqual(self.post(tool_message("", tcid="call_x"))[0], 403 if self.verify == "refuse" else 200)
        self.assertEqual(self.mismatches(), [("call_x", ["L2", "L3"])])

    def test_a_result_jcs_cant_encode_is_compared_as_its_json_text(self):
        """A lone surrogate gave no digest, so a forged result carrying one went unchecked. Now it is compared as its
        JSON text, as result_field records such a result."""
        self.completed(client.result_field(False, "caf\u00e9 \ud800"), tcid="call_ok")
        self.completed("hello")
        self.assertEqual(self.post(tool_message("caf\u00e9 \ud800", tcid="call_ok"))[0], 200)
        self.assertEqual(self.post(tool_message("FORGED \ud800"))[0], 403 if self.verify == "refuse" else 200)
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])

    def test_a_resent_history_is_digested_once(self):
        self.completed("hello")
        forms = mock.Mock(wraps=gateway.result_forms)
        with mock.patch.object(gateway, "result_forms", forms):
            for _ in range(2):
                self.assertEqual(self.post(tool_message("hello"))[0], 200)
        self.assertEqual(forms.call_count, 1)   # the second request's copy cost a hash
        first, second = [r["tool_results"] for r in self.signer.sent if r["phase"] == "request"]
        self.assertEqual(first, second)

    def test_a_result_the_gateway_gave_no_digests_of_is_signed_unchecked(self):
        """An edit padded past MAX_DIGESTED, pushed past it by newer results of the agent's own, or sent twice under one
        id with a correct copy got no digests: it was forwarded, under refuse too, with nothing signed. Now each such
        call's first is a signed capture.gap result_unchecked; never refused."""
        for tcid in ("call_7", "call_8", "call_9"):
            self.completed(event_hash("hello"), tcid=tcid)   # its digest, as result_field records a trusted tool's
        padded = "HELLO" + " " * 1200
        with mock.patch.object(gateway, "MAX_DIGESTED", 1000):
            for _ in range(2):   # sent again: one record per call
                self.assertEqual(self.post(tool_message(padded, tcid="call_7"))[0], 200)
            self.assertEqual(self.post({"model": "gpt-x", "messages": [   # the newer result uses up the budget
                {"role": "tool", "tool_call_id": "call_8", "content": "HELLO"},
                {"role": "tool", "tool_call_id": "junk_1", "content": "j" * 995}]})[0], 200)
            self.assertEqual(self.post({"model": "gpt-x", "messages": [
                {"role": "tool", "tool_call_id": "call_9", "content": padded},
                {"role": "tool", "tool_call_id": "call_9", "content": "hello"}]})[0], 200)
        self.assertEqual(self.mismatches(), [])
        self.assertEqual(self.unchecked(), ["call_7", "call_8", "call_9"])
        [gap] = [e for e in self.events() if e["type"] == "capture.gap"][:1]
        self.assertEqual((gap["source"], gap["data"]["tool_use_id"]), ("signer", "call_7"))

    def test_a_gateway_that_sends_no_digests_leaves_signed_unchecked_results(self):
        """As a gateway older than 1.3 does (tool_results_sent only); once per call, a restart included."""
        self.completed("hello")

        def sends(seq):
            self.s.call(GW, "model_event", {"request_id": uuid.uuid4().hex, **self.run, "caller": "token:http",
                                            "stream": "gx2", "client_seq": seq, "provider": "openai", "model": "m",
                                            "phase": "request", "tool_results_sent": ["call_7", "call_unknown"]})
        sends(0)
        self.reopen()
        sends(1)
        self.assertEqual(self.unchecked(), ["call_7"])   # call_unknown was never decided: nothing to compare

    def test_a_resent_edit_costs_the_writer_no_hmac(self):
        """The salt is derived once per tool.result, and a form that opened none is remembered."""
        self.completed("hello")
        salts = mock.Mock(wraps=svc._salt)
        with mock.patch.object(svc, "_salt", salts):
            self.gateway_sends("HELLO")
            first = salts.call_count
            self.gateway_sends("HELLO", seq=1)
        self.assertEqual((first, salts.call_count), (1, 1))
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])

    def test_a_denied_calls_refusal_sent_back_is_not_a_mismatch(self):
        self.decided("call_d", tool="tracekit_demo_denied")   # denied: the model gets the refusal as its result
        self.assertEqual(self.post(tool_message("refused by policy", tcid="call_d"))[0], 200)
        self.assertEqual(self.mismatches(), [])

    def test_a_call_completed_with_no_result_is_not_checked(self):
        """The quickstart's run.complete("call-1"): its commitment is over {}, which no result the model sees is."""
        self.completed(..., tcid="call-1")
        self.assertEqual(self.post(tool_message("whatever the tool printed", tcid="call-1"))[0], 200)
        self.reopen()   # also once a restart rebuilt the results from the records
        self.gateway_sends("whatever the tool printed", tcid="call-1")
        self.assertEqual(self.mismatches(), [])

    def test_a_reused_tool_call_id_matches_any_of_its_results(self):
        self.completed("first", tcid="call_0")
        self.completed("second", tcid="call_0")   # the same id again, later in the run
        self.completed("timeout", tcid="call_r", status="error")
        self.completed("retried", tcid="call_r", attempt=1)   # a second attempt that worked
        body = {"model": "gpt-x", "messages": [{"role": "tool", "tool_call_id": "call_0", "content": "first"},
                                               {"role": "tool", "tool_call_id": "call_0", "content": "second"},
                                               {"role": "tool", "tool_call_id": "call_r", "content": "retried"}]}
        self.assertEqual(self.post(body)[0], 200)
        self.assertEqual(self.mismatches(), [])

    def test_not_checked_without_a_comparable_result(self):
        self.completed("timeout", tcid="call_e", status="error")   # an error result: what the model sees varies
        self.completed("key " + "sk-ant-" + "Zq8" * 10, tcid="call_s")   # redaction changed it: no commitment to test
        for tcid in ("call_e", "call_s", "call_unknown"):
            self.assertEqual(self.post(tool_message("something else", tcid=tcid))[0], 200)
        self.assertEqual(self.mismatches(), [])

    def test_only_a_gateways_digests_are_checked(self):
        self.completed("hello")
        self.s.call(AGENT, "model_event", {"request_id": uuid.uuid4().hex, **self.run, "stream": "agent-l3",
                                           "client_seq": 0, "provider": "openai", "model": "m", "phase": "request",
                                           "tool_results": [{"id": "call_7", "forms": gateway.result_forms("HELLO")}]})
        self.assertEqual(self.mismatches(), [])

    def test_the_results_are_rebuilt_from_the_records_after_a_restart(self):
        self.completed("hello")
        self.reopen()
        self.gateway_sends("HELLO")
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])

    def test_a_mismatch_before_a_restart_is_not_written_again(self):
        self.completed("hello")
        self.gateway_sends("HELLO")
        self.reopen()
        self.gateway_sends("HELLO", seq=1)
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])

    def test_a_snapshot_written_before_1_3_has_no_results(self):
        self.completed("hello", tcid="call_a")
        state = pipeline.RecordLog._state

        def old_snapshot(log):   # as a 1.2 signer wrote it: its runs have no `results`
            st = state(log)
            for r in st["runs"]:
                r.pop("results", None)
            return st
        with mock.patch.object(pipeline.RecordLog, "_state", old_snapshot):
            self.s.snapshot()
        store = os.path.join(self.dir, "store")
        [(size, _)] = file_storage._snapshots(store)
        self.completed("hello", tcid="call_b")
        self.close()
        for n, path in file_storage._snapshots(store):   # any newer snapshot: open from the old one, then the records
            if n > size:
                os.unlink(path)
        self.reopen(drop_snapshots=False)
        self.gateway_sends("HELLO", tcid="call_a")   # completed before the snapshot: not checked, never flagged
        self.gateway_sends("HELLO", tcid="call_b", seq=1)   # recorded after it: checked
        self.assertEqual(self.mismatches(), [("call_b", ["L2", "L3"])])

    def test_run_final_counts_the_mismatches(self):
        self.completed("hello")
        self.post(tool_message("HELLO"))
        self.final()
        [final] = [e for e in self.events() if e["type"] == "run.final"]
        self.assertEqual(final["data"]["coverage"]["unreconciled"]["result_mismatch"], 1)


class TestVerifiedToolResultsRefused(TestVerifiedToolResults):
    verify = "refuse"

    def test_an_edited_result(self):
        self.completed("hello")
        status, body = self.post(tool_message("HELLO"))
        self.assertEqual(status, 403)
        self.assertIn("not what the tool returned", json.loads(body)["error"]["message"])
        self.assertEqual(self.up.seen, [])   # never sent to the model
        self.assertEqual(self.mismatches(), [("call_7", ["L2", "L3"])])
        [(_, _, err)] = [x for x in self.exchanges() if x[1] == "response"]
        self.assertTrue(err.startswith("not forwarded: "), err)


class TestVerifiedToolResultsOff(Gateway):
    def test_off_unless_set_and_the_gateway_stops_sending_digests(self):
        self.assertEqual(self.post(tool_message("anything"))[0], 200)
        self.assertEqual(self.post(tool_message("anything"))[0], 200)
        self.assertEqual([e for e in self.events() if e["type"] == "reconcile.result_mismatch"], [])
        first, second = [r for r in self.signer.sent if r["phase"] == "request"]
        self.assertEqual(first["tool_results"], [{"id": "call_7", "forms": gateway.result_forms("anything")}])
        self.assertNotIn("tool_results", second)   # the signer said it doesn't check them


class ToolResultParsing(unittest.TestCase):
    def test_each_provider_shape(self):
        from tracekit import parsers
        self.assertEqual(parsers.tool_results("openai:chat", tool_message("x")), [("call_7", "x")])
        self.assertEqual(parsers.tool_results("openai:responses", {"input": [
            {"type": "function_call_output", "call_id": "c1", "output": "y"}, {"type": "message", "content": "hi"}]}),
            [("c1", "y")])
        self.assertEqual(parsers.tool_results("anthropic:messages", {"messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "tu_1", "content": [{"type": "text", "text": "z"}]}]}]}),
            [("tu_1", [{"type": "text", "text": "z"}])])

    def test_forms_cover_both_ways_complete_records_a_result(self):
        [form, parsed] = gateway.result_forms('{"a": 1}')
        self.assertEqual(form, {"digest": event_hash('{"a": 1}'), "result_digest": event_hash({"result": '{"a": 1}'})})
        self.assertEqual(parsed["digest"], event_hash({"a": 1}))
        self.assertEqual(len(gateway.result_forms("plain")), 1)
        self.assertEqual(len(gateway.result_forms([{"type": "text", "text": '{"a": 1}'}])), 3)   # REQUESTS' maxItems
        self.assertEqual(parsed["result_digest"], event_hash({"result": {"a": 1}}))
        empty = [event_hash(None), event_hash(""), event_hash([])]
        for v in (None, "", []):
            self.assertEqual(sorted(f["digest"] for f in gateway.result_forms(v)), sorted(empty))
        self.assertEqual([f["digest"] for f in gateway.result_forms(2 ** 60)], [event_hash(str(2 ** 60))])   # its text

    def test_results_newest_first_within_the_budget_and_cached_for_the_runs_next_request(self):
        g, key = gateway.Gateway("https://up.example", "k"), ("run", "t.mac", "token:x")
        sent = [("old", "a" * 60), ("new", "b" * 60)]
        with mock.patch.object(gateway, "MAX_DIGESTED", 100):
            self.assertEqual([r["id"] for r in g.results(key, sent)], ["new"])   # the older one is past it: unchecked
            self.assertEqual([r["id"] for r in g.results(key, sent)], ["old", "new"])   # "new" cost a hash
            self.assertEqual(g.results(key, [("big", "c" * 200)]), [])   # one result over it is never checked


if __name__ == "__main__":
    unittest.main()
