"""OpenTelemetry ingest (issue #4): wire decoding, GenAI span mapping, the HTTP receiver, the gateway path,
and the round trip OTel -> signed ledger -> verified bundle -> OTel with the original ids.
python3 -m pytest tests/test_otlp.py -q"""
import gzip
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, client, coverage, ingest, install, otlp, otlp_wire, schema  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402

try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    HAVE_OTEL = True
except ImportError:  # optional: the receiver itself has no dependencies
    HAVE_OTEL = False

TRACE = "5b8efff798038103d269b633813fc60c"
NS = 1_760_000_000_000_000_000
_SAVED = {}


def setUpModule():
    _SAVED["policy"] = os.environ.pop("TRACEKIT_POLICY", None)


def tearDownModule():
    if _SAVED.get("policy") is not None:
        os.environ["TRACEKIT_POLICY"] = _SAVED["policy"]


def kv(k, v):
    if isinstance(v, bool):
        val = {"boolValue": v}
    elif isinstance(v, int):
        val = {"intValue": str(v)}
    elif isinstance(v, float):
        val = {"doubleValue": v}
    elif isinstance(v, list):
        val = {"arrayValue": {"values": [{"stringValue": x} for x in v]}}
    else:
        val = {"stringValue": v}
    return {"key": k, "value": val}


def span(sid, name, attrs, parent="1111111111111111", start=0, end=1, status=0, trace=TRACE, events=()):
    s = {"traceId": trace, "spanId": sid, "name": name, "kind": 1, "startTimeUnixNano": str(NS + start * 1_000_000),
         "endTimeUnixNano": str(NS + end * 1_000_000), "attributes": [kv(k, v) for k, v in attrs.items()],
         "status": {"code": status}, "events": list(events)}
    if parent:
        s["parentSpanId"] = parent
    return s


def payload(*spans, service="research-bot"):
    return {"resourceSpans": [{"resource": {"attributes": [kv("service.name", service), kv("service.version", "1.4.2")]},
                               "scopeSpans": [{"scope": {"name": "test"}, "spans": list(spans)}]}]}


def agent_trace():
    """invoke_agent root -> chat (asks for a tool) -> execute_tool (runs it) -> an HTTP span (not an agent action)."""
    out = json.dumps([{"role": "assistant", "parts": [{"type": "tool_call", "id": "call_1", "name": "Bash",
                                                       "arguments": {"command": "ls -la"}}], "finish_reason": "tool_call"}])
    return payload(
        span("2222222222222222", "chat gpt-4o", {"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
                                                 "gen_ai.request.model": "gpt-4o",
                                                 "gen_ai.input.messages": json.dumps([{"role": "user", "parts": [{"type": "text", "content": "list files"}]}]),
                                                 "gen_ai.output.messages": out, "gen_ai.response.finish_reasons": ["tool_call"]},
             start=1, end=20),
        span("3333333333333333", "execute_tool Bash", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash",
                                                       "gen_ai.tool.call.id": "call_1",
                                                       "gen_ai.tool.call.arguments": json.dumps({"command": "ls -la"}),
                                                       "gen_ai.tool.call.result": "a.txt\nb.txt"}, start=21, end=25),
        span("4444444444444444", "GET /health", {"http.request.method": "GET"}, start=26, end=27),
        span("1111111111111111", "invoke_agent research-bot", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "research-bot"},
             parent=None, start=0, end=30))


class FakeSink:
    def __init__(self):
        self.events, self.down, self.reject = [], False, set()

    def __call__(self, ev, attach):
        if self.down:
            raise client.SignerUnavailable("down")
        if ev["type"] in self.reject:
            return {"ok": False, "error": "nope"}
        errs = schema.validate(ev)
        assert not errs, errs
        self.events.append((ev, attach))
        return {"ok": True}


def mapper():
    return otlp.Mapper(cwd="/work", host="box")


class Wire(unittest.TestCase):
    def test_json_decodes_ids_times_and_typed_attributes(self):
        spans, fmt = otlp_wire.decode(json.dumps(agent_trace()).encode(), "application/json")
        self.assertEqual(fmt, "json")
        self.assertEqual(len(spans), 4)
        s = spans[0]
        self.assertEqual((s["trace_id"], s["span_id"], s["parent_span_id"]), (TRACE, "2222222222222222", "1111111111111111"))
        self.assertEqual(s["attrs"]["gen_ai.response.finish_reasons"], ["tool_call"])
        self.assertEqual(s["resource"]["service.name"], "research-bot")
        self.assertIsNone(spans[3]["parent_span_id"])

    def test_snake_case_base64_ids_and_enum_names_are_accepted(self):
        import base64
        body = {"resource_spans": [{"scope_spans": [{"spans": [{
            "trace_id": base64.b64encode(bytes.fromhex(TRACE)).decode(), "span_id": base64.b64encode(b"\x01" * 8).decode(),
            "name": "x", "kind": "SPAN_KIND_CLIENT", "status": {"code": "STATUS_CODE_ERROR"}}]}]}]}
        s = otlp_wire.decode(json.dumps(body).encode(), "application/json; charset=utf-8")[0][0]
        self.assertEqual((s["trace_id"], s["span_id"], s["kind"], s["status_code"]), (TRACE, "01" * 8, 3, 2))

    def test_gzip_and_deflate(self):
        raw = json.dumps(agent_trace()).encode()
        import zlib
        self.assertEqual(len(otlp_wire.decode(gzip.compress(raw), "application/json", "gzip")[0]), 4)
        self.assertEqual(len(otlp_wire.decode(zlib.compress(raw), "application/json", "deflate")[0]), 4)

    def test_hostile_input_is_refused_cleanly(self):
        bomb = gzip.compress(b"{" + b" " * (otlp_wire.MAX_DECODED + 10) + b"}")
        cases = [(bomb, "application/json", "gzip"), (b"\xff\xff\xff", "application/x-protobuf", None),
                 (b"not json", "application/json", None), (b"[]", "application/json", None),
                 (b"{}", "text/plain", None), (b"abc", "application/json", "br"),
                 (json.dumps(payload(span("zz", "x", {}))).encode(), "application/json", None),
                 (json.dumps(payload(span("2222222222222222", "x", {}, trace="0" * 32))).encode(), "application/json", None),
                 (b"\x0a\x05\x12\x03\x12\x01", "application/x-protobuf", None)]
        for body, ct, enc in cases:
            with self.assertRaises(otlp_wire.WireError, msg=(body[:20], ct, enc)):
                otlp_wire.decode(body, ct, enc)

    def test_deep_nesting_is_capped_not_recursed(self):
        v = {"stringValue": "leaf"}
        for _ in range(200):
            v = {"arrayValue": {"values": [v]}}
        body = payload(span("2222222222222222", "x", {}))
        body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"] = [{"key": "deep", "value": v}]
        s = otlp_wire.decode(json.dumps(body).encode(), "application/json")[0][0]
        x = s["attrs"]["deep"]
        for _ in range(otlp_wire.MAX_DEPTH + 1):
            x = x[0]
        self.assertEqual(x, "[truncated: nesting too deep]")

    def test_too_many_spans(self):
        many = [span("%016x" % (i + 1), "x", {}) for i in range(otlp_wire.MAX_SPANS + 1)]
        with self.assertRaises(otlp_wire.WireError):
            otlp_wire.decode(json.dumps(payload(*many)).encode(), "application/json")

    @unittest.skipUnless(HAVE_OTEL, "opentelemetry-proto not installed")
    def test_protobuf_matches_json(self):
        from google.protobuf import json_format
        doc = agent_trace()
        msg = trace_service_pb2.ExportTraceServiceRequest()
        pbdoc = json.loads(json.dumps(doc))
        import base64
        for rs in pbdoc["resourceSpans"]:  # proto3's JSON mapping uses base64 for bytes ids
            for ss in rs["scopeSpans"]:
                for s in ss["spans"]:
                    for k in ("traceId", "spanId", "parentSpanId"):
                        if k in s:
                            s[k] = base64.b64encode(bytes.fromhex(s[k])).decode()
        json_format.ParseDict(pbdoc, msg)
        from_pb = otlp_wire.decode(msg.SerializeToString(), "application/x-protobuf")[0]
        from_json = otlp_wire.decode(json.dumps(doc).encode(), "application/json")[0]
        self.assertEqual(from_pb, from_json)

    @unittest.skipUnless(HAVE_OTEL, "opentelemetry-proto not installed")
    def test_protobuf_response_encoding(self):
        r = trace_service_pb2.ExportTraceServiceResponse()
        r.ParseFromString(otlp_wire.encode_response_protobuf(3, "bad span"))
        self.assertEqual((r.partial_success.rejected_spans, r.partial_success.error_message), (3, "bad span"))
        self.assertEqual(otlp_wire.encode_response_protobuf(), b"")


class Mapping(unittest.TestCase):
    def plan(self, doc, m=None):
        spans = otlp_wire.decode(json.dumps(doc).encode(), "application/json")[0]
        items, skipped = (m or mapper()).plan(spans)
        for _, ev, _, _ in items:
            self.assertEqual(schema.validate(ev), [], ev)
        return [ev for _, ev, _, _ in items], skipped, items

    def test_agent_trace_becomes_one_signed_run(self):
        evs, skipped, items = self.plan(agent_trace())
        self.assertEqual(skipped, 1)  # the HTTP span
        self.assertEqual([e["type"] for e in evs], ["run.start", "model.exchange", "model.exchange", "tool.call",
                                                    "policy.decision", "tool.result", "run.end"])
        self.assertTrue(all(e["run_id"] == f"otel:research-bot:{TRACE}" and e["source"] == "sdk" for e in evs))
        start = evs[0]["data"]
        self.assertEqual((start["agent"]["name"], start["agent"]["version"], start["model"]), ("research-bot", "1.4.2", "gpt-4o"))
        self.assertEqual(items[0][2].keys(), {"policy"})  # the policy snapshot travels with run.start
        resp = evs[2]["data"]
        self.assertEqual((resp["phase"], resp["stop_reason"], resp["upstream"]), ("response", "tool_call", "otel:openai"))
        self.assertEqual(resp["tool_uses"], [{"id": "call_1", "name": "Bash"}])
        self.assertTrue(resp["response"]["hash"].startswith("sha256:"))  # hashed by default
        call, dec, res = evs[3]["data"], evs[4]["data"], evs[5]["data"]
        self.assertEqual((call["tool_use_id"], call["name"]), ("call_1", "Bash"))
        self.assertEqual(call["input"]["command"], {"value": "ls -la", "redacted": False})  # clear per docs/privacy.md
        self.assertEqual(dec["decision"], "allow")
        self.assertEqual(dec["reasons"][0], otlp.POST_HOC)
        self.assertEqual((res["ok"], res["duration_ms"]), (True, 4))
        self.assertEqual(evs[-1]["data"]["reason"], "done")
        self.assertEqual(evs[3]["id"][:16], "3333333333333333")  # event ids carry the span id for exports
        self.assertEqual(evs[1]["ts"], "2025-10-09T08:53:20.001000Z")

    def test_policy_violations_are_flagged_not_pretended_blocked(self):
        doc = payload(span("2222222222222222", "execute_tool Bash", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash",
                                                                     "gen_ai.tool.call.arguments": json.dumps({"command": "sudo rm -rf /"})}))
        evs, _, _ = self.plan(doc)
        dec = next(e["data"] for e in evs if e["type"] == "policy.decision")
        self.assertEqual(dec["decision"], "flag")
        self.assertIn("policy would have returned deny before execution", dec["reasons"])
        self.assertTrue(dec["rule_ids"])

    def test_secrets_are_redacted_before_hashing(self):
        doc = payload(span("2222222222222222", "execute_tool Bash", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash",
                                                                     "gen_ai.tool.call.arguments": json.dumps({"command": "echo sk-ant-abcdefghijklmnopqrstuvwxyz"})}))
        evs, _, _ = self.plan(doc)
        cmd = next(e["data"]["input"]["command"] for e in evs if e["type"] == "tool.call")
        self.assertNotIn("sk-ant-abc", json.dumps(cmd))
        self.assertTrue(cmd["redacted"])

    def test_failed_spans(self):
        exc = {"name": "exception", "timeUnixNano": str(NS), "attributes": [kv("exception.message", "rate limited")]}
        doc = payload(span("2222222222222222", "chat m", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m"}, status=2, events=[exc]),
                      span("3333333333333333", "execute_tool T", {"gen_ai.operation.name": "execute_tool"}, status=2),
                      span("1111111111111111", "root", {}, parent=None, status=2))
        evs, _, _ = self.plan(doc)
        self.assertEqual(next(e for e in evs if e["data"].get("phase") == "response")["data"]["error"], "rate limited")
        self.assertFalse(next(e for e in evs if e["type"] == "tool.result")["data"]["ok"])
        self.assertTrue(evs[-1]["data"]["reason"].startswith("error"))

    def test_openllmetry_and_openinference_shapes(self):
        doc = payload(
            span("2222222222222222", "openai.chat", {"llm.request.type": "chat", "gen_ai.system": "openai", "gen_ai.request.model": "gpt-4o-mini",
                                                    "gen_ai.prompt.0.role": "user", "gen_ai.prompt.0.content": "hi",
                                                    "gen_ai.completion.0.role": "assistant", "gen_ai.completion.0.finish_reason": "tool_calls",
                                                    "gen_ai.completion.0.tool_calls.0.id": "c9", "gen_ai.completion.0.tool_calls.0.name": "search"}),
            span("3333333333333333", "search.tool", {"traceloop.span.kind": "tool", "traceloop.entity.name": "search",
                                                     "traceloop.entity.input": json.dumps({"args": [], "kwargs": {"q": "x"}})}),
            span("5555555555555555", "LLM", {"openinference.span.kind": "LLM", "llm.model_name": "claude-x", "llm.provider": "anthropic",
                                             "input.value": "q", "output.value": "a"}),
            span("6666666666666666", "lookup", {"openinference.span.kind": "TOOL", "tool.name": "lookup", "input.value": "{\"id\": 3}"}))
        evs, skipped, _ = self.plan(doc)
        self.assertEqual(skipped, 0)
        resp = [e["data"] for e in evs if e["data"].get("phase") == "response"]
        self.assertEqual((resp[0]["model"], resp[0]["stop_reason"], resp[0]["tool_uses"]), ("gpt-4o-mini", "tool_calls", [{"id": "c9", "name": "search"}]))
        self.assertEqual((resp[1]["model"], resp[1]["upstream"]), ("claude-x", "otel:anthropic"))
        names = [e["data"]["name"] for e in evs if e["type"] == "tool.call"]
        self.assertEqual(names, ["search", "lookup"])

    def test_run_start_once_per_trace_across_batches_and_policy_reattached_on_change(self):
        m = mapper()
        doc = agent_trace()
        first = payload(*doc["resourceSpans"][0]["scopeSpans"][0]["spans"][:2])
        evs1, _, items1 = self.plan(first, m)
        for key, ev, _, upd in items1:
            m.commit(key, ev, upd)
        evs2, _, items2 = self.plan(payload(*doc["resourceSpans"][0]["scopeSpans"][0]["spans"][2:]), m)
        self.assertEqual(sum(e["type"] == "run.start" for e in evs1 + evs2), 1)
        self.assertEqual(evs2[-1]["type"], "run.end")
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "p.yaml")
            with open(p, "w") as f:
                f.write("extends: default\nversion: changed\n")
            os.environ["TRACEKIT_POLICY"] = p
            tool = payload(span("7777777777777777", "execute_tool Bash", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash"}))
            _, _, items3 = self.plan(tool, m)
            dec = next(i for i in items3 if i[1]["type"] == "policy.decision")
            self.assertIsNotNone(dec[2], "a decision under a new policy must carry its snapshot")
        finally:
            os.environ.pop("TRACEKIT_POLICY", None)
            shutil.rmtree(d)

    def test_run_ids_are_safe(self):
        self.assertEqual(otlp.run_id_for("my svc/../x" * 10, TRACE)[:12], "otel:my-svc-")
        self.assertLessEqual(len(otlp.run_id_for("x" * 500, TRACE)), 120)
        self.assertEqual(otlp.run_id_for(None, TRACE), f"otel:unknown:{TRACE}")
        self.assertEqual(otlp.trace_id_of(f"remote:box:otel:svc:{TRACE}"), TRACE)
        self.assertIsNone(otlp.trace_id_of("sess_abc"))


class ReceiverSemantics(unittest.TestCase):
    def test_retries_do_not_duplicate_evidence(self):
        sink = FakeSink()
        r = otlp.Receiver(sink, mapper())
        spans = otlp_wire.decode(json.dumps(agent_trace()).encode(), "application/json")[0]
        a = r.export(spans)
        b = r.export(spans)
        self.assertEqual((a["accepted"], a["duplicate"]), (7, 0))
        self.assertEqual((b["accepted"], b["duplicate"]), (0, 6))  # run.start is not even planned again
        self.assertEqual(len(sink.events), 7)

    def test_outage_mid_batch_is_retryable_and_resumes_without_duplicates(self):
        sink = FakeSink()
        r = otlp.Receiver(sink, mapper())
        spans = otlp_wire.decode(json.dumps(agent_trace()).encode(), "application/json")[0]
        orig = sink.__call__
        calls = {"n": 0}

        def flaky(ev, attach):
            calls["n"] += 1
            if calls["n"] == 4:
                raise client.SignerUnavailable("restarting")
            return orig(ev, attach)
        r.sink = flaky
        res = r.export(spans)
        self.assertTrue(res["retryable"])
        self.assertEqual(res["accepted"], 3)
        res = r.export(spans)
        self.assertFalse(res["retryable"])
        self.assertEqual([e["type"] for e, _ in sink.events], ["run.start", "model.exchange", "model.exchange", "tool.call",
                                                               "policy.decision", "tool.result", "run.end"])

    def test_permanent_rejection_is_a_partial_success(self):
        sink = FakeSink()
        sink.reject = {"tool.result"}
        r = otlp.Receiver(sink, mapper())
        code, headers, body = otlp.handle_traces(r, json.dumps(agent_trace()).encode(), "application/json", None)
        self.assertEqual(code, 200)
        ps = json.loads(body)["partialSuccess"]
        self.assertEqual(ps["rejectedSpans"], "1")
        self.assertIn("tool.result", ps["errorMessage"])

    def test_http_status_codes(self):
        r = otlp.Receiver(FakeSink(), mapper())
        self.assertEqual(otlp.handle_traces(r, b"{}", "application/json", None)[0], 200)
        self.assertEqual(otlp.handle_traces(r, b"{", "application/json", None)[0], 400)
        self.assertEqual(otlp.handle_traces(r, b"{}", "text/plain", None)[0], 415)
        down = FakeSink()
        down.down = True
        code, headers, _ = otlp.handle_traces(otlp.Receiver(down, mapper()), json.dumps(agent_trace()).encode(), "application/json", None)
        self.assertEqual((code, headers.get("Retry-After")), (503, "2"))


class Signed(unittest.TestCase):
    """Against a real dev signer: OTLP/HTTP in, signed ledger, verified bundle, OTLP back out."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = {k: os.environ.get(k) for k in ("TRACEKIT_CLIENT_HOME",)}
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)
        self.srv = otlp.serve("127.0.0.1", 0, otlp.Receiver(otlp.local_sink, otlp.Mapper(cwd=self.d)))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        install.stop_dev_daemon(self.home)
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.d, ignore_errors=True)

    def events(self):
        return [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r and not r.get("elided")]

    def post(self, body, ct="application/json", enc=None, path="/v1/traces"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Content-Type": ct}
        if enc:
            h["Content-Encoding"] = enc
        c.request("POST", path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read()

    def export_and_verify(self, run):
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out, run=run, otel=True)
        rep, code = bundle.verify(out)
        self.assertEqual(code, 0, rep.failures)
        with zipfile.ZipFile(out) as z:
            return json.loads(z.read("otel.json")), json.loads(z.read("coverage.json"))

    def test_json_over_http_lands_signed_and_verifies(self):
        status, _ = self.post(gzip.compress(json.dumps(agent_trace()).encode()), enc="gzip")
        self.assertEqual(status, 200)
        self.assertEqual(self.post(json.dumps(agent_trace()).encode())[0], 200)  # exporter retry: no duplicates
        run = f"otel:research-bot:{TRACE}"
        evs = [e for e in self.events() if e["run_id"] == run]
        self.assertEqual([e["type"] for e in evs], ["run.start", "model.exchange", "model.exchange", "tool.call",
                                                    "policy.decision", "tool.result", "run.end"])
        self.assertFalse([e for e in self.events() if e["type"] == "capture.gap"], "no false gaps for an OTel run")
        otel, cov = self.export_and_verify(run)
        spans = {s["spanId"]: s for rs in otel["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]}
        self.assertEqual({s["traceId"] for s in spans.values()}, {TRACE})
        self.assertEqual(set(spans), {"1111111111111111", "2222222222222222", "3333333333333333"})
        chat = {a["key"]: a["value"] for a in spans["2222222222222222"]["attributes"]}
        self.assertEqual(chat["gen_ai.provider.name"], {"stringValue": "openai"})
        self.assertEqual(chat["gen_ai.request.model"], {"stringValue": "gpt-4o"})
        tool = {a["key"]: a["value"] for a in spans["3333333333333333"]["attributes"]}
        self.assertEqual(tool["gen_ai.tool.call.id"], {"stringValue": "call_1"})
        recs = {r["hash"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r}
        self.assertIn(tool["tracekit.entry_hash"]["stringValue"], recs)  # every span points at a signed entry
        self.assertTrue(any("OpenTelemetry" in o for o in cov["observed"]))
        self.assertTrue(any("not proxy-observed" in o for o in cov["observed"]))

    def test_bad_requests_over_http(self):
        self.assertEqual(self.post(b"{", path="/v1/traces")[0], 400)
        self.assertEqual(self.post(b"{}", path="/v1/logs")[0], 404)
        self.assertEqual(self.post(b"{}", ct="text/plain")[0], 415)

    @unittest.skipUnless(HAVE_OTEL, "opentelemetry-sdk not installed")
    def test_real_opentelemetry_sdk_protobuf_exporter(self):
        provider = TracerProvider(resource=Resource.create({"service.name": "sdk-agent"}))
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"http://127.0.0.1:{self.port}/v1/traces")))
        tracer = provider.get_tracer("t")
        with tracer.start_as_current_span("invoke_agent sdk-agent", attributes={"gen_ai.operation.name": "invoke_agent",
                                                                                "gen_ai.agent.name": "sdk-agent"}) as root:
            with tracer.start_as_current_span("chat claude", attributes={"gen_ai.operation.name": "chat",
                                                                         "gen_ai.provider.name": "anthropic",
                                                                         "gen_ai.request.model": "claude-x",
                                                                         "gen_ai.response.finish_reasons": ("end_turn",)}):
                pass
            with tracer.start_as_current_span("execute_tool Read", attributes={"gen_ai.operation.name": "execute_tool",
                                                                               "gen_ai.tool.name": "Read",
                                                                               "gen_ai.tool.call.arguments": '{"file_path": "/etc/hosts"}'}):
                time.sleep(0.01)
            trace_id = format(root.get_span_context().trace_id, "032x")
        provider.shutdown()
        run = f"otel:sdk-agent:{trace_id}"
        types = [e["type"] for e in self.events() if e["run_id"] == run]
        self.assertEqual(types.count("run.start"), 1)
        self.assertEqual(types[-1], "run.end")
        self.assertIn("tool.result", types)
        otel, _ = self.export_and_verify(run)
        self.assertEqual({s["traceId"] for rs in otel["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]}, {trace_id})


class Gateway(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "gw")
        install.init_dev(self.home, [], start=True)
        self.token = ingest.add_token(self.home, "box-1")
        cfg = client.client_config()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), ingest.make_handler(self.home, forward=lambda req: client._rpc(req, config=cfg)))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def post(self, token):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=10)
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        c.request("POST", "/v1/traces", body=json.dumps(agent_trace()), headers=h)
        r = c.getresponse()
        return r.status, r.read()

    def test_authenticated_namespaced_and_counted(self):
        self.assertEqual(self.post(None)[0], 401)
        self.assertEqual(self.post("wrong")[0], 401)
        self.assertEqual(self.post(self.token)[0], 200)
        evs = [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r and not r.get("elided")]
        mine = [e for e in evs if e["run_id"] == f"remote:box-1:otel:research-bot:{TRACE}"]
        self.assertEqual(len(mine), 7)
        self.assertTrue(mine[0]["data"]["host"].startswith("remote:box-1@"))
        self.assertFalse([e for e in evs if e["type"] == "capture.gap"], "counters stay in step through the gateway")

    def test_model_exchange_is_accepted_only_as_sdk_evidence(self):
        req, err = ingest.sanitize({"op": "append", "event": {"run_id": "r", "source": "sdk", "type": "model.exchange", "data": {}}}, "c", "x")
        self.assertIsNone(err)
        self.assertEqual(req["event"]["source"], "sdk")
        _, err = ingest.sanitize({"op": "append", "event": {"run_id": "r", "source": "proxy", "type": "model.exchange", "data": {}}}, "c", "x")
        self.assertIsNotNone(err)


class CoverageWording(unittest.TestCase):
    def test_reported_exchanges_are_not_called_proxy_observed(self):
        ev = lambda t, d, src="sdk": {"run_id": f"otel:s:{TRACE}", "type": t, "data": d, "source": src, "seq": 1}  # noqa: E731
        rep = coverage.report([ev("model.exchange", {"phase": "response"})])
        self.assertFalse(any("at the proxy" in o for o in rep["observed"]))
        self.assertIn("no model proxy: disabled hooks can only be inferred from missing run.end, not detected", rep["warnings"])


if __name__ == "__main__":
    unittest.main()
