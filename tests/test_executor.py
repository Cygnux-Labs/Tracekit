"""The tool executor (tracekit/executor.py) in front of a fake HTTP API, deciding and recording through an in-process v2
signer as source gateway (tier T2); and `caller` on the signer's per-call RPCs."""
import asyncio
import base64
import contextlib
import html
import http.client
import io
import importlib.util
import http.server
import json
import os
import shutil
import ssl
import threading
import time
import types
import unittest
import urllib.error
import urllib.parse
import uuid
from unittest import mock

from adapter_contract import tmpdir
from test_gateway import AGENT, SECRET, serve
from test_identity_mtls import Pki
from test_signer_service import records
from tracekit import executor
from tracekit.identity.base import CallerIdentity
from tracekit.format.canon import event_hash
from tracekit.integrations import executor_tools
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
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
        self.srv = executor.serve(executor.load_config(self.cfg), self.signer)
        self.port = serve(self, self.srv)
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
        for to in ("..", ".", "a/../../admin", "a\\..\\admin", "", "%2e%2e", "%2F", "a b", "é"):
            with self.subTest(to):
                self.assertEqual(self.post("refund", {"args": {"to": to, "cents": 5}})[0], 400)
        for args in ({"to": "acct-42"}, {"to": "x", "cents": 5, "host": "evil"}):
            with self.subTest(args):
                self.assertEqual(self.post("refund", {"args": args})[0], 400)
        self.assertEqual(self.api.seen, [])
        self.assertEqual(self.post("refund", {"args": {"to": "acct_4.2~x-y", "cents": 5}})[0], 200)
        self.assertEqual(self.api.seen[0][0], "/v1/refund/acct_4.2~x-y")

    def test_a_query_argument_is_quoted_whole(self):
        with open(self.cfg) as f:
            cfg = json.load(f)
        cfg["actions"][0].update(url_template=cfg["actions"][0]["url_template"] + "?memo={memo}", args=dict(
            ARGS, required=["to", "cents", "memo"], properties={**ARGS["properties"], "memo": {"type": "string"}}))
        with open(self.cfg, "w") as f:
            json.dump(cfg, f)
        a = executor.load_config(self.cfg)["actions"]["pay"]
        self.assertEqual(a["path_fields"], {"to"})
        self.assertEqual(executor._url(a, {"to": "acct-42", "cents": 1, "memo": "a/../b&c=d"}).split("/v1/")[1],
                         "pay/acct-42?memo=a%2F..%2Fb%26c%3Dd")

    def test_an_unknown_action_is_named_only_to_an_authenticated_caller(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        self.addCleanup(c.close)
        c.request("POST", "/v1/actions/nope", b"{}", {"Content-Type": "application/json"})
        r = c.getresponse()
        self.assertEqual((r.status, b"nope" in r.read()), (401, False))
        self.assertEqual(self.post("nope", {"args": {}})[0], 404)

    def test_a_credential_the_api_echoes_escaped_is_cut_from_the_decoded_response(self):
        key = "Basic Ym9iOnMzY3IzdD8/Pz8="   # base64 with "/", which a PHP API's json_encode echoes as \\/

        class Echo(API):
            def do_POST(self):
                self.rfile.read(int(self.headers["content-length"]))
                got = self.headers["authorization"]
                out = ('{"error": "bad credentials", "got": "%s", "u": "%s"}' % (
                    got.replace("/", "\\/"), "".join(f"\\u{ord(c):04x}" for c in got))).encode()
                self.send_response(401)
                self.send_header("content-length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
        api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        a = {"name": "x", "method": "POST", "url_template": f"http://127.0.0.1:{serve(self, api)}/x", "path_fields": set(),
             "headers": {"authorization": key}, "cut": executor.secret_values([key])}
        status, out = executor._send(a, {}, 1 << 20)
        self.assertEqual((status, out), (401, {"error": "bad credentials", "got": executor.REDACTED, "u": executor.REDACTED}))

    def test_a_credential_is_cut_in_the_forms_a_response_carries_it_and_a_short_value_or_a_key_is_not(self):
        key = "Basic " + base64.b64encode(b"bob:s3cr3t/pw?").decode()
        values = executor.secret_values([key, "Bearer abc", "info"])
        for p in (key, key.split()[1], "bob:s3cr3t/pw?", "s3cr3t/pw?"):
            esc = json.dumps(p)[1:-1]
            for form in (p, esc, esc.replace("/", "\\/"), "".join(f"\\u{ord(c):04x}" for c in p), urllib.parse.quote(p),
                         urllib.parse.quote(p, safe=""), urllib.parse.quote_plus(p), html.escape(p),
                         html.escape(p).replace("/", "&#x2F;")):
                with self.subTest(form):
                    self.assertEqual(executor.cut({"e": f"got {form}."}, values), {"e": f"got {executor.REDACTED}."})
        self.assertEqual(executor.cut({"Bearer abc": "abc, info"}, values), {"Bearer abc": "abc, info"})

    def test_settings_go_with_the_request_and_are_never_cut(self):
        with open(self.cfg) as f:
            cfg = json.load(f)
        cfg["actions"][0]["settings"] = {"x-api-version": "2022-06-28"}
        with open(self.cfg, "w") as f:
            json.dump(cfg, f)
        pay = executor.serve(executor.load_config(self.cfg), self.signer).executor["actions"]["pay"]
        self.assertEqual(pay["headers"], {"x-api-version": "2022-06-28", "authorization": API_KEY})
        self.assertNotIn("2022-06-28", pay["cut"])
        self.assertIn(API_KEY, pay["cut"])
        for bad in ({"authorization": "x"}, {"x-a": "1\n2"}, {"bad name": "1"}):
            with self.subTest(bad):
                cfg["actions"][0]["settings"] = bad
                with open(self.cfg, "w") as f:
                    json.dump(cfg, f)
                self.assertRaisesRegex(ValueError, "settings maps a header name", executor.load_config, self.cfg)

    def test_a_credential_in_an_error_is_cut(self):
        def refuse(req, timeout):   # an error that names the header the request carried
            raise urllib.error.URLError(f"refused {req.get_header('Authorization')}")
        with mock.patch.object(executor, "OPEN", refuse):
            status, out = self.post("refund", {"args": PAID})
        self.assertEqual(status, 502)
        self.assertIn("the request was not sent", out["error"]["message"])
        self.assertNotIn("sk-live-executor", json.dumps(out))
        [r] = [e for e in self.events() if e["type"] == "tool.result"]
        self.assertFalse(r["data"]["ok"])
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("sk-live-executor", f.read())

    def test_a_header_file_with_a_line_break_or_control_character_is_refused_at_start(self):
        for value in ("Bearer a\nb", "Bearer a\rb", "Bearer a\x00b", "Bearer é"):
            with self.subTest(repr(value)):
                with open(os.path.join(self.dir, "pay.header"), "w") as f:
                    f.write(value)
                with self.assertRaises(ValueError) as e:
                    executor.serve(executor.load_config(self.cfg), self.signer)
                self.assertIn("pay.header: a header value is one line of printable ASCII", str(e.exception))
                self.assertNotIn(value, str(e.exception))

    def test_a_request_not_sent_and_a_response_not_read_are_told_apart(self):
        recorded, complete = [], self.signer.complete
        self.signer.complete = lambda req: (recorded.append(req["error"]), complete(req))[1]
        refund = self.srv.executor["actions"]["refund"]
        api, refund["url_template"] = refund["url_template"], "http://127.0.0.1:9/v1/refund/{to}"   # nothing listens
        status, out = self.post("refund", {"args": PAID})
        self.assertEqual((status, self.api.seen), (502, []))
        refund["url_template"], self.srv.executor["max_body"] = api, 60   # the request fits; the API's answer doesn't
        self.assertEqual(self.post("refund", {"args": PAID})[0], 502)
        self.assertEqual(len(self.api.seen), 1)
        self.assertTrue(recorded[0].startswith("upstream unreachable, the request was not sent: "), recorded)
        self.assertEqual(recorded[1], "the request was sent but its response could not be read (upstream response over "
                                      "60 bytes): the action may have run; check before running it again")
        self.assertIn(recorded[0], out["error"]["message"])

    def test_an_outcome_is_recorded_on_a_second_try_or_said_on_stderr(self):
        complete, tries = self.signer.complete, []

        def flaky(lost, fails):
            def go(req):
                tries.append(req["request_id"])
                if len(tries) > fails:
                    return complete(req)
                if lost:   # recorded, its answer lost: the retry, under the same request_id, is answered `conflict`
                    complete(req)
                raise SignerUnavailable("down")
            return go
        for lost, fails, said in ((False, 1, ""), (True, 1, ""), (False, 2, "was not recorded: down")):
            with self.subTest(lost=lost, fails=fails):
                tries.clear()
                self.signer.complete = flaky(lost, fails)
                with mock.patch("tracekit.executor.time.sleep"), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(self.post("refund", {"args": PAID})[0], 200)   # it ran: the agent gets its result
                self.assertEqual((len(tries), len(set(tries))), (2, 1))
                self.assertIn(said, err.getvalue())
                self.assertEqual(bool(err.getvalue()), bool(said))
        self.assertIn("Check that the signer is reachable", err.getvalue())
        types = [e["type"] for e in self.events()]
        self.assertEqual((types.count("policy.decision"), types.count("tool.result")), (3, 2))

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

    def test_client_helpers_send_the_run_in_clear_only_to_loopback(self):
        for url in ("http://executor.internal:8090", "https://user:pw@executor.internal:8090"):
            with self.subTest(url), mock.patch.object(executor_tools, "_get") as get:
                with self.assertRaises(ValueError) as e:
                    executor_tools.actions(url, self.run, {"authorization": "Bearer " + SECRET})
                self.assertRegex(str(e.exception), "must use https|must not contain")
                get.assert_not_called()

    def test_client_helpers_use_the_given_tls_context(self):
        pki = Pki(self.dir)
        cert, key = pki.issue("executor")
        with open(self.cfg) as f:
            cfg = json.load(f)
        cfg["http"] = {"listen": "127.0.0.1:0", "cert": cert, "key": key, "authenticators": ["token"],
                       "token_file": "bearer"}
        with open(self.cfg, "w") as f:
            json.dump(cfg, f)
        port = serve(self, executor.serve(executor.load_config(self.cfg), self.signer))
        acts = executor_tools.actions(f"https://127.0.0.1:{port}", self.run, {"authorization": "Bearer " + SECRET},
                                      ssl.create_default_context(cafile=pki.path))
        self.assertEqual(sorted(a.name for a in acts), ["pay", "refund", "wipe"])

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

    @unittest.skipUnless(HAVE["agents"], "openai-agents not installed")
    def test_the_openai_agents_adapter_leaves_executor_tools_to_the_executor(self):
        from tracekit.integrations.openai_agents import TracekitAgents
        tk, t = TracekitAgents(InProcess(self.s, AGENT), self.run), executor_tools.openai_agents(self.actions()["refund"])
        self.assertIs(tk.tool(t), t)   # gated as well, its decide on the model's call id would hold the executor's off
        out = asyncio.run(tk.tool(t).on_invoke_tool(types.SimpleNamespace(tool_call_id="call-oa"), json.dumps(PAID)))
        self.assertEqual(json.loads(out)["status"], 201)

    @unittest.skipUnless(HAVE["langchain_core"], "langchain not installed")
    def test_the_langchain_middleware_leaves_executor_tools_to_the_executor(self):
        from langchain.agents.middleware.types import ToolCallRequest
        from tracekit.integrations.langchain import TracekitMiddleware
        mw = TracekitMiddleware(InProcess(self.s, AGENT), self.run["run_id"], self.run["run_token"])
        req = ToolCallRequest(tool_call={"id": "call-lc", "name": "refund", "args": PAID},
                              tool=executor_tools.langchain(self.actions()["refund"]), state=None, runtime=None)
        out = mw.wrap_tool_call(req, lambda r: r.tool.invoke(r.tool_call["args"]))
        self.assertEqual(json.loads(out)["status"], 201)
        [d] = [e for e in self.events() if e["type"] == "policy.decision"]
        self.assertEqual((d["source"], d["tier"]), ("gateway", "T2"))   # the executor's alone, not also the adapter's

    @unittest.skipUnless(HAVE["claude_agent_sdk"], "claude-agent-sdk not installed")
    def test_the_claude_agent_sdk_hooks_leave_executor_tools_to_the_executor(self):
        from tracekit.integrations.claude_agent_sdk import tracekit_hooks
        [pre] = tracekit_hooks(InProcess(self.s, AGENT), self.run)["PreToolUse"][0].hooks
        inp = {"tool_name": "mcp__tracekit-executor__refund", "tool_use_id": "tu-1", "tool_input": PAID}
        self.assertEqual(asyncio.run(pre(inp, "tu-1", None)), {})
        self.assertNotIn("policy.decision", [e["type"] for e in self.events()])

    @unittest.skipUnless(HAVE["claude_agent_sdk"], "claude-agent-sdk not installed")
    def test_a_claude_agent_sdk_server(self):
        with mock.patch("claude_agent_sdk.create_sdk_mcp_server", lambda name, tools: tools):
            tools = {t.name: t for t in executor_tools.claude_agent_sdk(list(self.actions().values()))}
        out = asyncio.run(tools["refund"].handler(PAID))
        self.assertEqual(json.loads(out["content"][0]["text"])["status"], 201)
        self.assertTrue(asyncio.run(tools["wipe"].handler(PAID))["is_error"])

    def test_only_a_configured_gateway_may_name_a_caller(self):
        event, digest = {"request_id": "x", **self.run, "stream": "s", "client_seq": 0}, "sha256:" + "0" * 64
        call = {"tool_call_id": "c", "tool": "refund", "args_source": "parsed", "args": {}}
        reqs = {"decide": {**event, **call}, "approval_consume": {"request_id": "x", **self.run, **call},
                "complete": {**event, "tool_call_id": "c", "decision_id": "dec-1", "args_digest": digest, "status": "ok"},
                "observe": {**event, "source": "mail", "trust": "untrusted", "value": "hi"},
                "model_event": {**event, "provider": "openai", "model": "m", "phase": "request"},
                "approval_request": {"request_id": "x", **self.run, "tool_call_id": "c"},
                "approval_wait": {**self.run, "approval_id": "apr-1"}}
        self.assertEqual(set(reqs), {m for m, r in REQUESTS.items() if "caller" in r["properties"]})
        for method, req in reqs.items():
            with self.subTest(method):
                with self.assertRaises(RPCError) as e:
                    self.s.call(AGENT, method, dict(req, caller="token:http"))
                self.assertEqual((e.exception.code, e.exception.message), ("forbidden", "token:http is not a configured gateway"))
        with self.assertRaises(RPCError) as e:   # a gateway, but the run token is not the caller's
            self.s.call(EX, "decide", dict(reqs["decide"], caller="uid:4242"))
        self.assertEqual(e.exception.code, "run_token_invalid")

    def call(self, who, method, **req):
        """`method` for the agent's run, as the agent (who=AGENT) or as the executor for it (who=EX)."""
        return getattr(InProcess(self.s, who), method)({**self.run, **({"caller": "token:http"} if who == EX else {}),
                                                        **req})

    def test_a_call_the_executor_decided_is_its_alone(self):
        pay, digest = {"tool": "pay", "args_source": "parsed", "args": PAID}, event_hash({"tool": "pay", "args": PAID})
        d = self.call(EX, "decide", tool_call_id="c1", **pay)
        self.assertEqual(d["decision"], "ask")
        steps = {"approval_request": {"tool_call_id": "c1", "reason": "routine, approve"},
                 "approval_consume": {"tool_call_id": "c1", **pay}, "decide": {"tool_call_id": "c1", **pay},
                 "complete": {"tool_call_id": "c1", "decision_id": d["decision_id"], "args_digest": digest,
                              "status": "error", "error": "upstream said no (forged)"}}

        def refused(method, **req):
            with self.assertRaises(RPCError) as e:
                self.call(AGENT, method, **req)
            self.assertEqual(e.exception.code, "forbidden")
            self.assertIn("is held by mtls:spiffe://acme/executor", e.exception.message)
        for method, req in steps.items():
            with self.subTest(method):
                refused(method, **req)
        aid = self.call(EX, "approval_request", tool_call_id="c1")["approval_id"]
        refused("approval_abandon", approval_id=aid)
        for restart in ("snapshot", "log"):   # the hold is the call's state: a restart rebuilds it from either
            with self.subTest(restart):
                self.s.close()
                if restart == "log":
                    shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
                self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                           authorize=self.s.authorize)
                self.assertEqual(self.s.log.runs[("default", self.run["run_id"])]["calls"]["c1"]["via"],
                                 "mtls:spiffe://acme/executor")
                refused("complete", **steps["complete"])
                refused("approval_consume", **steps["approval_consume"])
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": aid, "decision": "approve"})
        self.assertTrue(self.call(EX, "approval_consume", tool_call_id="c1", **pay)["ok"])
        self.call(EX, "complete", **dict(steps["complete"], status="ok", error="fine"))
        evs = [e for e in self.events() if e.get("tool_call_id") == "c1" and e["type"] in (
            "policy.decision", "approval.request", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["data"]["via"]) for e in evs],
                         [(t, "gateway", "T2", "mtls:spiffe://acme/executor")
                          for t in ("policy.decision", "approval.request", "tool.result")])

    def test_a_call_the_agent_decided_is_not_the_executors(self):
        self.call(AGENT, "decide", tool_call_id="call-x", tool="refund", args_source="parsed", args=PAID)
        status, out = self.post("refund", {"args": PAID, "tool_call_id": "call-x"})
        self.assertEqual(status, 403)
        self.assertIn("decided by the run's client, not through a gateway", out["error"]["message"])
        self.assertEqual(self.api.seen, [])

    def test_a_harness_bound_run_takes_its_executor_calls(self):
        self.s.log.runs[("default", self.run["run_id"])]["harness"] = (1, 1)   # its owner's calls: from that process
        with self.assertRaises(RPCError) as e:
            self.call(AGENT, "decide", tool_call_id="c2", tool="refund", args_source="parsed", args=PAID)
        self.assertIn("harness", e.exception.message)
        self.assertEqual(self.post("refund", {"args": PAID})[0], 200)   # the executor's own identity vouches for it

    def test_the_executors_events_are_its_own_to_pay_for(self):
        self.s.quotas.limits = Limits(events_per_s=0.001, burst=2)   # two events each, hardly refilled
        for i in range(2):   # the agent spends its own bucket
            self.call(AGENT, "observe", source="spam", trust="trusted", value=i)
        with self.assertRaises(RPCError) as e:
            self.call(AGENT, "observe", source="spam", trust="trusted", value=2)
        self.assertEqual(e.exception.code, "quota_exceeded")
        # the executor's decide and consume take its own two; the result of its own decision takes none
        self.assertEqual(self.post("refund", {"args": PAID})[0], 200)
        types = [e["type"] for e in self.events()]
        self.assertEqual((types.count("policy.decision"), types.count("tool.result")), (1, 1))

    def test_a_run_closed_while_the_executor_runs_a_call_waits_for_its_result_or_says_it_never_came(self):
        self.s.grace_s, self.s.gateway_wait_s = 0, 30
        key, refund = ("default", self.run["run_id"]), {"tool": "refund", "args_source": "parsed", "args": PAID}
        ds = {t: self.call(EX, "decide", tool_call_id=t, **refund) for t in ("c1", "c2")}
        for t in ds:   # each allowed and consumed: the executor is running it
            self.assertTrue(self.call(EX, "approval_consume", tool_call_id=t, **refund)["ok"])
        self.call(AGENT, "close_run")   # mid-call, as the agent may
        closing = self.s.log.runs[key]["closing_at"]
        self.s.sweep(now=closing + 1)
        self.assertFalse(self.s.log.runs[key]["final"])
        self.call(EX, "complete", tool_call_id="c1", decision_id=ds["c1"]["decision_id"], status="ok",
                  args_digest=event_hash({"tool": "refund", "args": PAID}), result={"paid": 5})   # late, still taken
        self.s.sweep(now=closing + 2)
        self.assertFalse(self.s.log.runs[key]["final"])   # c2 is still out
        self.s.sweep(now=closing + 31)
        self.assertTrue(self.s.log.runs[key]["final"])
        evs = self.events()
        self.assertEqual([(e["data"]["kind"], e["tool_call_id"]) for e in evs if e["type"] == "capture.gap"],
                         [("held_call_unresolved", "c2")])
        self.assertEqual([e["tool_call_id"] for e in evs if e["type"] == "tool.result"], ["c1"])

    def test_a_call_the_executor_decided_for_one_identity_is_not_anothers(self):
        self.s.authorize["token:other"] = ["decide", "complete", "approval_request", "approval_consume"]
        other = {**self.run, "caller": "token:other", "run_token": self.s.call(AGENT, "delegate_run", {
            **self.run, "identity": "token:other"})["run_token"]}
        refund = {"tool_call_id": "c1", "tool": "refund", "args_source": "parsed", "args": PAID}
        d = self.call(EX, "decide", **refund)
        ex = InProcess(self.s, EX)
        for method, req in (("decide", refund), ("approval_consume", refund), ("complete", {
                "tool_call_id": "c1", "decision_id": d["decision_id"], "status": "ok",
                "args_digest": event_hash({"tool": "refund", "args": PAID})})):
            with self.subTest(method), self.assertRaises(RPCError) as e:   # the same executor, for another identity
                getattr(ex, method)({**other, **req})
            self.assertIn("is held by mtls:spiffe://acme/executor for token:http", e.exception.message)

    def test_a_gateway_identity_is_at_most_256_characters(self):
        long = CallerIdentity("mtls", "spiffe://acme/" + "x" * 300, True)
        self.s.authorize[f"mtls:{long.subject}"] = ["decide"]
        with self.assertRaises(RPCError) as e:
            InProcess(self.s, long).decide({**self.run, "caller": "token:http", "tool_call_id": "c1", "tool": "refund",
                                            "args_source": "parsed", "args": PAID})
        self.assertIn("at most 256 characters", e.exception.message)
        path = os.path.join(self.dir, "signer.yaml")
        with open(path, "w") as f:
            json.dump({"data_dir": ".", "gateways": [f"mtls:{long.subject}"]}, f)
        self.assertRaisesRegex(ValueError, "gateways: an identity is at most 256 characters", svc.load_config, path)


if __name__ == "__main__":
    unittest.main()
