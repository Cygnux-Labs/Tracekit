"""The LLM gateway (tracekit/gateway.py) in front of a fake OpenAI-compatible upstream, recording into an in-process v2
signer as source gateway; and gateway L3 in reconciliation (tracekit/signer/reconcile.py)."""
import http.client
import http.server
import json
import os
import threading
import time
import unittest
import uuid

from adapter_contract import tmpdir
from test_reconcile import use
from test_signer_service import records
from tracekit import gateway
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS, RPCError

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
    that breaks after `bytes`; ("redirect", location)."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.server.seen.append((dict(self.headers), self.rfile.read(int(self.headers["content-length"]))))
        how, data, *status = self.server.reply
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
        self.s, self.down, self.refuse = s, False, False

    def model_event(self, req):
        if self.down:
            raise SignerUnavailable("down")
        if self.refuse and req["phase"] == "response":
            raise RPCError("run_closed", req["run_id"])
        return self.s.call(GW, "model_event", {"request_id": uuid.uuid4().hex, **req})


def serve(case, srv):
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv.server_address[1]


class Gateway(unittest.TestCase):
    mandatory = False

    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, tenants={OTHER.scheme + ":" + OTHER.subject: "beta"},
                                   gateways=["mtls:spiffe://acme/*"], gateway_mandatory=self.mandatory,
                                   authorize={"token:http": list(REQUESTS), "mtls:spiffe://acme/gateway": ["model_event"]},
                                   grace_s=60, idle_s=600)
        self.closed = False
        self.addCleanup(self.close)
        self.up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.up.seen, self.up.reply = [], ("json", COMPLETION)
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
        self.port = serve(self, gateway.serve(gateway.load_config(os.path.join(self.dir, "gateway.yaml")), self.signer))
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


class TestExchange(Gateway):
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


if __name__ == "__main__":
    unittest.main()
