"""OpenTelemetry on the v2 signer (tracekit/signer/otel.py): OTLP/HTTP import on the HTTPS listener (authenticated,
authorized per identity, runs keyed by tenant and trace id, a dedupe that survives restarts and snapshots, idle
closing), the hardened wire decoder, and span export of v2 runs (`tracekit export --v2 --otel`, `otel_out`)."""
import http.client
import json
import os
import shutil
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_signer_service as ts
from factories import wait_for
from test_otlp import TRACE, agent_trace, payload, span
from tracekit import cli, otlp_wire, schema
from tracekit.identity.base import CallerIdentity
from tracekit.signer import otel as signer_otel
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError

APP = CallerIdentity("token", "http", True)
JSON = "application/json"
TOOL = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash",
        "gen_ai.tool.call.arguments": json.dumps({"command": "cat SECRET-ARG-MARKER"}),
        "gen_ai.tool.call.result": "SECRET-RESULT-MARKER"}


def body(*spans, service="svc-a"):
    return json.dumps(payload(*spans, service=service)).encode()


def ld(field, data):
    """One length-delimited protobuf field."""
    n, out = len(data), bytearray([field << 3 | 2])
    while True:
        out.append(n & 0x7F | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(out) + data


class Signer(unittest.TestCase):
    def open(self, **kw):
        kw.setdefault("authorize", {"token:http": ["otlp_import", "status"]})
        s = svc.SignerService(self.dir, policy=ts.PAY_ASKS, tenants={"token:http": "acme"}, **kw)
        self.addCleanup(s.close)
        return s

    def setUp(self):
        self.dir = ts.tmpdir(self)

    def post(self, s, data, ctype=JSON, identity=APP):
        status, _, out = s.otlp(identity, data, ctype, None)
        return status, json.loads(out or b"{}") if ctype == JSON else out

    def events(self, typ=None):
        return [r["event"] for r in ts.records(self.dir) if typ in (None, r["event"]["type"])]


class TestImport(Signer):
    def test_identity_without_otlp_import_is_refused(self):
        s = self.open(authorize={"token:http": ["status"]})
        for identity in (APP, ts.ME):   # an unconfigured uid keeps every RPC method, never otlp_import
            with self.assertRaises(RPCError) as cm:
                self.post(s, json.dumps(agent_trace()).encode(), identity=identity)
            self.assertEqual(cm.exception.code, "forbidden")
        self.assertEqual(self.events("run.registered"), [])

    def test_runs_are_keyed_by_tenant_and_trace_id_not_service_name(self):
        s = self.open()
        other = "6" * 32
        self.assertEqual(self.post(s, body(span("aaaaaaaaaaaaaaaa", "t", TOOL)))[0], 200)
        self.post(s, body(span("bbbbbbbbbbbbbbbb", "t", TOOL), service="svc-b"))   # another service, the same trace
        self.post(s, body(span("cccccccccccccccc", "t", TOOL, trace=other)))       # the same service, another trace
        regs = self.events("run.registered")
        self.assertEqual(sorted(e["run_id"] for e in regs), sorted([f"otel:{other}", f"otel:{TRACE}"]))
        for e in regs:
            self.assertEqual((e["tenant"], e["source"], e["tier"], e["data"]["fidelity"]), ("acme", "import", "T3", "none"))
        calls = [e for e in self.events("tool.call") if e["run_id"] == f"otel:{TRACE}"]
        self.assertEqual(sorted(e["span_id"] for e in calls), ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])
        for r in ts.records(self.dir):
            self.assertEqual(schema.validate(r["event"]), [], r["event"]["type"])

    def test_a_run_registered_over_rpc_is_never_written_to(self):
        s = self.open(authorize={"token:http": ["otlp_import", "register_run"]})
        s.call(APP, "register_run", {"request_id": "r", "run_id": f"otel:{TRACE}", "agent": {"name": "a"}})
        status, out = self.post(s, body(span("aaaaaaaaaaaaaaaa", "t", TOOL)))
        self.assertEqual((status, out["partialSuccess"]["rejectedSpans"]), (200, "1"))
        self.assertEqual(self.events("tool.call"), [])

    def test_an_import_run_takes_spans_from_the_identity_that_started_it_only(self):
        other = CallerIdentity("token", "other", True, {"tenant": "acme"})
        s = self.open(authorize={"token:http": ["otlp_import"], "token:other": ["otlp_import"]})
        self.post(s, body(span("aaaaaaaaaaaaaaaa", "t", TOOL)))
        status, out = self.post(s, body(span("bbbbbbbbbbbbbbbb", "t", TOOL)), identity=other)
        self.assertEqual((status, out["partialSuccess"]["rejectedSpans"]), (200, "1"))
        self.assertEqual([e["span_id"] for e in self.events("tool.call")], ["aaaaaaaaaaaaaaaa"])

    def test_a_resent_batch_writes_nothing_after_a_restart_or_from_a_snapshot(self):
        data = json.dumps(agent_trace()).encode()
        s = self.open()
        self.assertEqual(self.post(s, data), (200, {}))
        n = len(self.events())
        s.close()
        for snapshot in (True, False):
            if not snapshot:   # replay the log in full
                shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
            s = self.open()
            self.assertEqual(self.post(s, data), (200, {}))
            s.close()
            self.assertEqual(len(self.events()), n, snapshot)
        self.assertEqual(len(self.events("run.registered")), 1)
        self.assertEqual(len(self.events("tool.call")), 1)

    def test_an_idle_import_run_closes_and_goes_final(self):
        s = self.open(idle_s=0, grace_s=0)
        self.post(s, json.dumps(agent_trace()).encode())
        s.sweep(now=time.monotonic() + 1)
        s.sweep(now=time.monotonic() + 2)
        run = [e for e in self.events() if e["run_id"] == f"otel:{TRACE}"]
        self.assertEqual([e["type"] for e in run], ["run.registered", "model.exchange", "tool.call", "tool.result",
                                                    "run.closing", "run.final"])
        self.assertEqual(run[-2]["data"]["reason"], "idle_timeout")
        self.assertNotIn("coverage", run[-1]["data"])   # an import is not reconciled
        self.assertEqual(self.post(s, json.dumps(agent_trace()).encode())[1]["partialSuccess"]["rejectedSpans"], "2")

    def test_deep_json_is_a_400_and_writes_nothing(self):
        s = self.open()
        deep = b'{"resourceSpans":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
        with self.assertRaises(otlp_wire.WireError):
            otlp_wire.decode(deep, JSON)
        n = len(self.events())
        self.assertEqual(self.post(s, deep)[0], 400)
        self.assertEqual(self.post(s, b'{"resourceSpans": [{"resource": "x"}]}')[0], 400)   # an unexpected shape
        self.assertEqual(len(self.events()), n)

    def test_an_oversized_protobuf_array_is_refused(self):
        def request(n):
            values = b"".join(ld(1, ld(1, b"x")) for _ in range(n))   # ArrayValue.values: AnyValue{string_value}
            attr = ld(1, b"k") + ld(2, ld(5, values))                  # KeyValue{key, value: AnyValue{array_value}}
            sp = ld(1, bytes.fromhex(TRACE)) + ld(2, b"\x01" * 8) + ld(9, attr)
            return ld(1, ld(2, ld(2, sp)))                             # request.resource_spans.scope_spans.spans
        self.assertEqual(len(otlp_wire.decode(request(otlp_wire.MAX_ATTRS), "application/x-protobuf")[0]), 1)
        with self.assertRaisesRegex(otlp_wire.WireError, "array values"):
            otlp_wire.decode(request(otlp_wire.MAX_ATTRS + 1), "application/x-protobuf")
        s = self.open()
        n = len(self.events())
        self.assertEqual(self.post(s, request(otlp_wire.MAX_ATTRS + 1), "application/x-protobuf")[0], 400)
        self.assertEqual(len(self.events()), n)

    def test_span_count_cap(self):
        s = self.open(otlp={"max_spans": 1})
        status, out = self.post(s, json.dumps(agent_trace()).encode())
        self.assertEqual((status, out["partialSuccess"]["rejectedSpans"]), (200, "4"))
        self.assertEqual(self.events("run.registered"), [])


class TestHttp(Signer):
    def test_unauthenticated_and_ungranted_otlp_is_refused(self):
        token = os.path.join(self.dir, "bearer")
        with open(token, "w") as f:
            f.write("b" * 40)
        s = self.open(authorize={"token:http": ["otlp_import"], "token:dev": []})
        servers = svc.serve({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                      "token_file": token}, "otlp": {}}, s)
        for srv in servers:
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        port = servers[0].server_address[1]

        def post(headers):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                c.request("POST", "/v1/traces", json.dumps(agent_trace()), {"Content-Type": JSON, **headers})
                return c.getresponse().status
            finally:
                c.close()
        self.assertEqual(post({}), 401)
        self.assertEqual(post({"Authorization": "Bearer " + "x" * 40}), 401)
        self.assertEqual(self.events("run.registered"), [])
        self.assertEqual(post({"Authorization": "Bearer " + "b" * 40}), 200)
        self.assertEqual(len(self.events("run.registered")), 1)
        s.authorize["token:http"] = ["status"]
        self.assertEqual(post({"Authorization": "Bearer " + "b" * 40}), 403)
        with self.assertRaises(ValueError):   # only on the http listener
            svc.serve({"socket": os.path.join(self.dir, "s.sock"), "otlp": {}}, s)


class TestExport(Signer):
    def test_spans_carry_entry_hash_run_seq_and_tier_and_no_content(self):
        s = self.open()
        self.post(s, body(span("aaaaaaaaaaaaaaaa", "t", dict(TOOL, **{"gen_ai.tool.call.id": "call_9"}))))
        run = ts.TestService.register(self, s)
        req = {"run_id": run["run_id"], "run_token": run["run_token"], "stream": "s1"}
        d = s.decide(dict(req, request_id="d", client_seq=0, tool_call_id="tc", tool="t", args_source="parsed",
                          args={"q": "SECRET-ARG-MARKER"}))
        s.complete(dict(req, request_id="c", client_seq=1, tool_call_id="tc", decision_id=d["decision_id"],
                        args_digest=ts.event_hash({"tool": "t", "args": {"q": "SECRET-ARG-MARKER"}}), status="ok",
                        result="SECRET-RESULT-MARKER"))
        for tenant, run_id, tier, span_id in (("acme", f"otel:{TRACE}", "T3", "aaaaaaaaaaaaaaaa"),
                                              ("default", run["run_id"], "T1", None)):
            recs = list(s.log.storage.iter_run(tenant, run_id))
            doc = signer_otel.payload(recs)
            self.assertNotIn("SECRET", json.dumps(doc))
            root, tool = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
            attrs = {a["key"]: list(a["value"].values())[0] for a in tool["attributes"]}
            first = recs[1]   # the call's first record, after run.registered
            self.assertEqual((attrs["tracekit.entry_hash"], attrs["tracekit.run_seq"], attrs["tracekit.tier"]),
                             (first["hash"], "1", tier))
            self.assertEqual(attrs["gen_ai.operation.name"], "execute_tool")
            self.assertTrue(attrs["tracekit.args_commitment"].startswith("hmac-sha256:"))
            self.assertTrue(attrs["tracekit.result.hash"].startswith("hmac-sha256:"))
            self.assertEqual(root["name"].split(" ")[0], "invoke_agent")
            self.assertEqual(tool["parentSpanId"], root["spanId"])
            if span_id:
                self.assertEqual((tool["traceId"], tool["spanId"], attrs["tracekit.policy.decision"]),
                                 (TRACE, span_id, "none"))
            else:
                self.assertEqual(attrs["tracekit.policy.decision"], "allow")

    def test_export_v2_otel_writes_the_spans_next_to_the_bundle(self):
        s = self.open()
        self.post(s, json.dumps(agent_trace()).encode())
        s.checkpoint()
        cfg = os.path.join(self.dir, "signer.yaml")
        with open(cfg, "w") as f:
            f.write(f"data_dir: {self.dir}\ntenant: acme\n")
        out = os.path.join(self.dir, "run.tkb")
        self.assertEqual(cli.main(["export", "--v2", "--config", cfg, "--run", f"otel:{TRACE}", "--otel", "-o", out]), 0)
        with open(os.path.join(self.dir, "run.otel.json")) as f:
            spans = json.load(f)["resourceSpans"][0]["scopeSpans"][0]["spans"]
        self.assertEqual([x["name"] for x in spans], ["invoke_agent research-bot", "execute_tool Bash"])

    def test_otel_out_sends_final_runs_off_the_writer_and_counts_drops(self):
        got = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        s = self.open(idle_s=0, grace_s=0,
                      otel_out={"endpoint": f"http://127.0.0.1:{srv.server_address[1]}/v1/traces"})
        self.post(s, json.dumps(agent_trace()).encode())
        s.sweep(now=time.monotonic() + 1)
        s.sweep(now=time.monotonic() + 2)
        self.assertTrue(wait_for(lambda: got))
        names = [x["name"] for x in got[0]["resourceSpans"][0]["scopeSpans"][0]["spans"]]
        self.assertEqual(names, ["invoke_agent research-bot", "execute_tool Bash"])
        s._exporter.endpoint = "http://127.0.0.1:9/v1/traces"   # nothing listens there
        s._exporter.put(("acme", f"otel:{TRACE}"))
        self.assertTrue(wait_for(lambda: 'reason="failed"} 1' in s.metrics.render()))
        with self.assertRaises(ValueError):
            svc.SignerService(ts.tmpdir(self), otel_out={"endpoint": "http://example.org/v1/traces"})


if __name__ == "__main__":
    unittest.main()
