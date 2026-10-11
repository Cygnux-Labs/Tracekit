"""The tool executor (tracekit/executor.py) in front of a fake HTTP API, deciding and recording through an in-process v2
signer as source gateway (tier T2); and `caller` on the signer's per-call RPCs."""
import asyncio
import http.client
import importlib.util
import http.server
import json
import os
import threading
import time
import types
import unittest
import uuid
from unittest import mock

from adapter_contract import tmpdir
from test_gateway import AGENT, SECRET, serve
from test_signer_service import records
from tracekit import executor
from tracekit.identity.base import CallerIdentity
from tracekit.integrations import executor_tools
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS, RPCError

EX = CallerIdentity("mtls", "spiffe://acme/executor", True)
API_KEY = "Bearer sk-live-executor-0123456789"
POLICY = Engine({"ask": [{"id": "R-PAY", "tool": "^pay$", "pattern": "^", "approval": {"executor": "t2"}}],
                 "deny": [{"id": "R-WIPE", "tool": "^wipe$", "pattern": "^"}]})
HAVE = {m: importlib.util.find_spec(m) is not None for m in ("agents", "langchain_core", "claude_agent_sdk")}
PAID = {"to": "acct-42", "cents": 5}
ARGS = {"type": "object", "required": ["to", "cents"], "additionalProperties": False,
        "properties": {"to": {"type": "string"}, "cents": {"type": "integer", "minimum": 1}}}


class API(http.server.BaseHTTPRequestHandler):
    """Records each request; answers with its JSON body and the authorization header it got (an API that echoes it)."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        self.server.seen.append((self.path, dict(self.headers), json.loads(body)))
        out = json.dumps({"paid": json.loads(body), "auth": self.headers.get("authorization")}).encode()
        self.send_response(201)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class InProcess:
    """The executor's signer client: the in-process service, called as the executor's identity."""

    def __init__(self, s, identity=EX):
        self.s, self.down, self.identity = s, False, identity

    def __getattr__(self, method):
        def call(req):
            if self.down:
                raise SignerUnavailable("down")
            if "request_id" in REQUESTS[method]["properties"]:
                req = {"request_id": uuid.uuid4().hex, **req}
            if "client_seq" in REQUESTS[method]["properties"]:
                req = {"stream": "ex", "client_seq": self.s.log.runs[("default", req["run_id"])]["streams"].get("ex", -1)
                       + 1, **req}
            return self.s.call(self.identity, method, req)
        return call


class Executor(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"}),
                                              "mtls:spiffe://acme/executor": ["decide", "complete", "approval_request",
                                                                              "approval_wait", "approval_consume"]})
        self.closed = False
        self.addCleanup(self.close)
        self.api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
        self.api.seen = []
        api = serve(self, self.api)
        for name, value in (("bearer", SECRET), ("pay.header", API_KEY + "\n")):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        actions = [{"name": n, "method": "POST", "url_template": f"http://127.0.0.1:{api}/v1/{n}/{{to}}",
                    "headers": {"authorization": "pay.header"}, "args": ARGS} for n in ("pay", "wipe", "refund")]
        self.cfg = os.path.join(self.dir, "executor.yaml")
        with open(self.cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"},
                       "signer": "unused", "approval_wait_s": 5, "actions": actions}, f)
        self.signer = InProcess(self.s)
        self.port = serve(self, executor.serve(executor.load_config(self.cfg), self.signer))
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def post(self, action, body):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        self.addCleanup(c.close)
        c.request("POST", f"/v1/actions/{action}", json.dumps(body).encode(),
                  {"Authorization": "Bearer " + SECRET, "X-Tracekit-Run": f"{self.run['run_id']}.{self.run['run_token']}",
                   "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def events(self):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run["run_id"]]

    def test_an_allowed_action_runs_with_the_executors_credential_and_is_recorded_t2(self):
        status, out = self.post("refund", {"args": {"to": "acct-42", "cents": 5}, "tool_call_id": "call-1"})
        self.assertEqual((status, out["status"], out["result"]["paid"]), (200, 201, {"to": "acct-42", "cents": 5}))
        [(path, headers, _)] = self.api.seen
        self.assertEqual((path, headers["Authorization"]), ("/v1/refund/acct-42", API_KEY))
        self.assertNotIn(API_KEY, json.dumps(out))   # the API echoed it: cut before the agent gets the response
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["tool_call_id"]) for e in evs],
                         [("policy.decision", "gateway", "T2", "call-1"), ("tool.result", "gateway", "T2", "call-1")])
        self.assertTrue(evs[1]["data"]["ok"])
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("sk-live-executor", f.read())

    def test_held_then_approved_runs_once_approved(self):
        got = {}
        t = threading.Thread(target=lambda: got.update(out=self.post("pay", {"args": {"to": "acct-42", "cents": 1500}})))
        t.start()
        for _ in range(500):
            aids = [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {"run_id": self.run["run_id"]})["approvals"]]
            if aids:
                break
            time.sleep(0.01)
        self.assertEqual(self.api.seen, [])   # held: nothing ran yet
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": aids[0], "decision": "approve"})
        t.join(20)
        self.assertEqual(got["out"][0], 200)
        self.assertEqual([b for _, _, b in self.api.seen], [{"to": "acct-42", "cents": 1500}])
        types = [(e["type"], e["source"]) for e in self.events()]
        for t in [("approval.request", "gateway"), ("approval.consumed", "signer"), ("tool.result", "gateway")]:
            self.assertIn(t, types)

    def test_a_denied_action_never_reaches_the_api(self):
        status, out = self.post("wipe", {"args": {"to": "acct-42", "cents": 1}})
        self.assertEqual(status, 403)
        self.assertIn("R-WIPE", out["error"]["message"])
        self.assertEqual(self.api.seen, [])

    def test_the_signer_unreachable_fails_closed(self):
        self.signer.down = True
        status, out = self.post("refund", {"args": {"to": "acct-42", "cents": 5}})
        self.assertEqual(status, 503)
        self.assertIn("nothing ran", out["error"]["message"])
        self.assertEqual(self.api.seen, [])

    def test_arguments_off_the_schema_or_out_of_their_url_segment_are_refused(self):
        for args in ({"to": "acct-42"}, {"to": "x", "cents": 5, "host": "evil"}, {"to": "..", "cents": 5}):
            with self.subTest(args):
                self.assertEqual(self.post("refund", {"args": args})[0], 400)
        self.assertEqual(self.post("refund", {"args": {"to": "a/../../admin", "cents": 5}})[0], 200)
        self.assertEqual(self.api.seen[0][0], "/v1/refund/a%2F..%2F..%2Fadmin")

    def test_config_refuses_an_argument_in_the_host_or_an_optional_one_in_the_url(self):
        for tpl in ("https://{to}.example.com/x", "https://api.example.com/{memo}"):
            with self.subTest(tpl):
                with open(self.cfg, "w") as f:
                    json.dump({"http": {}, "signer": "s", "actions": [
                        {"name": "a", "method": "POST", "url_template": tpl, "args": ARGS}]}, f)
                with self.assertRaises(ValueError):
                    executor.load_config(self.cfg)

    def actions(self):
        return {a.name: a for a in executor_tools.actions(f"http://127.0.0.1:{self.port}", self.run,
                                                          {"authorization": "Bearer " + SECRET})}

    def test_client_helpers_list_and_call_the_actions(self):
        acts = self.actions()
        self.assertEqual((sorted(acts), acts["refund"].args), (["pay", "refund", "wipe"], ARGS))
        self.assertEqual(acts["refund"]({"to": "acct-42", "cents": 5}, "call-9")["status"], 201)
        with self.assertRaises(executor_tools.ExecutorRefused) as e:
            acts["wipe"]({"to": "x", "cents": 1})
        self.assertIn("R-WIPE", str(e.exception))
        self.assertIn("call-9", [e.get("tool_call_id") for e in self.events()])

    @unittest.skipUnless(HAVE["agents"], "openai-agents not installed")
    def test_an_openai_agents_tool(self):
        t = executor_tools.openai_agents(self.actions()["refund"])
        out = asyncio.run(t.on_invoke_tool(types.SimpleNamespace(tool_call_id="call-oa"), json.dumps(PAID)))
        self.assertEqual(json.loads(out)["status"], 201)
        self.assertIn("call-oa", [e.get("tool_call_id") for e in self.events()])

    @unittest.skipUnless(HAVE["langchain_core"], "langchain not installed")
    def test_a_langchain_tool(self):
        acts = self.actions()
        self.assertEqual(json.loads(executor_tools.langchain(acts["refund"]).invoke(PAID))["status"], 201)
        self.assertIn("R-WIPE", executor_tools.langchain(acts["wipe"]).invoke(PAID))   # the model gets the refusal

    @unittest.skipUnless(HAVE["claude_agent_sdk"], "claude-agent-sdk not installed")
    def test_a_claude_agent_sdk_server(self):
        with mock.patch("claude_agent_sdk.create_sdk_mcp_server", lambda name, tools: tools):
            tools = {t.name: t for t in executor_tools.claude_agent_sdk(list(self.actions().values()))}
        out = asyncio.run(tools["refund"].handler(PAID))
        self.assertEqual(json.loads(out["content"][0]["text"])["status"], 201)
        self.assertTrue(asyncio.run(tools["wipe"].handler(PAID))["is_error"])

    def test_only_a_configured_gateway_may_name_a_caller(self):
        req = {"request_id": "x", **self.run, "stream": "s", "client_seq": 0, "tool_call_id": "c", "tool": "refund",
               "args_source": "parsed", "args": {}, "caller": "token:http"}
        with self.assertRaises(RPCError) as e:
            self.s.call(AGENT, "decide", req)
        self.assertEqual(e.exception.code, "forbidden")
        with self.assertRaises(RPCError) as e:   # a gateway, but the run token is not the caller's
            self.s.call(EX, "decide", dict(req, caller="uid:4242"))
        self.assertEqual(e.exception.code, "run_token_invalid")


if __name__ == "__main__":
    unittest.main()
