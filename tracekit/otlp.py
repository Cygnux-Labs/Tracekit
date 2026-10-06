"""OpenTelemetry ingest: receive OTLP traces and record the agent-relevant spans as signed ledger events.

    tracekit otel serve                        # OTLP/HTTP on 127.0.0.1:4318, forwards to the configured signer
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces python my_agent.py

Remote agents send to the authenticated ingest gateway instead (`tracekit ingest serve` also serves
/v1/traces; docs/remote-ingest.md).

What is recorded
* One Tracekit run per OTel trace: run_id ``otel:<service.name>:<trace_id>``.
* Model calls (gen_ai chat / text_completion / generate_content, OpenLLMetry ``llm.request.type``,
  OpenInference ``LLM``) become ``model.exchange`` request + response events.
* Tool executions (gen_ai ``execute_tool``, OpenLLMetry ``tool``, OpenInference ``TOOL``) become
  ``tool.call`` + ``policy.decision`` + ``tool.result``.
* Other spans (HTTP, DB, framework internals) are counted and skipped: they are not agent actions.

What it means (and does not)
* Events enter as ``source=sdk``: the application reported them. Nothing proves they are complete or true.
* Spans arrive after the work is done, so policy is evaluated retrospectively and nothing is gated. A call a
  deny or ask rule would have stopped is recorded as ``flag`` with the would-be decision in its reasons.
* Content follows the active policy's privacy rules exactly as for hooks and the SDK (hashed unless
  content_capture=full, secrets redacted first).

Robustness
* Exporters retry: every (trace, span, event kind) is written at most once per receiver process, so a retried
  batch is acknowledged without duplicating evidence.
* A signer outage returns 503 (retryable), so the exporter keeps the batch; events already written are not
  written again on retry.
* An event the signer rejects is reported as an OTLP partial success; the rest of the batch still lands.
* Event ids embed the original span id, so `tracekit export --otel` reproduces the original trace and span ids."""
import argparse
import collections
import datetime as _dt
import hashlib
import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import client, policy, privacy
from .core import GENESIS, SCHEMA_VERSION, jsonable, now_ts
from .otlp_wire import MAX_BODY, WireError, decode, encode_response_protobuf

LLM_OPS = {"chat", "text_completion", "generate_content", "completion"}
TOOL_OPS = {"execute_tool"}
AGENT_OPS = {"invoke_agent", "create_agent"}
POST_HOC = "post-hoc: recorded from OpenTelemetry after the call ran; not gated"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
DEDUPE_CAP = 200_000
RUN_CAP = 50_000


def run_id_for(service, trace_id):
    svc = _SAFE.sub("-", str(service or "unknown"))[:48].strip("-.") or "unknown"
    return f"otel:{svc}:{trace_id}"


def trace_id_of(run_id):
    """The original trace id of an OTel-ingested run (also through the remote gateway's namespace), else None."""
    if ":otel:" not in ":" + run_id:
        return None
    tid = run_id.rsplit(":", 1)[-1]
    return tid if re.fullmatch(r"[0-9a-f]{32}", tid) else None


def _ts(ns):
    if not ns or ns <= 0:
        return now_ts()
    try:
        return _dt.datetime.fromtimestamp(ns // 1000 / 1_000_000, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return now_ts()


def _event_id(span_id, kind):
    """32 hex: the original span id followed by a per-kind suffix, so exports can recover the span id."""
    return span_id + hashlib.sha256(f"{span_id}|{kind}".encode()).hexdigest()[:16]


def _maybe_json(v):
    if isinstance(v, str) and v[:1] in "[{":
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _indexed(attrs, prefix):
    """OpenLLMetry / OpenInference flatten lists: gen_ai.prompt.0.role, gen_ai.prompt.0.content ... -> [{...}]."""
    rows = {}
    pre = prefix + "."
    for k, v in attrs.items():
        if not k.startswith(pre):
            continue
        idx, _, rest = k[len(pre):].partition(".")
        if idx.isdigit() and rest:
            rows.setdefault(int(idx), {})[rest] = v
    return [rows[i] for i in sorted(rows)]


def classify(sp):
    a = sp["attrs"]
    op = str(a.get("gen_ai.operation.name") or "").lower()
    if op in TOOL_OPS:
        return "tool"
    if op in LLM_OPS:
        return "llm"
    if op in AGENT_OPS:
        return "agent"
    oi = str(a.get("openinference.span.kind") or "").upper()
    if oi == "TOOL":
        return "tool"
    if oi == "LLM":
        return "llm"
    if oi == "AGENT":
        return "agent"
    tl = str(a.get("traceloop.span.kind") or "").lower()
    if tl == "tool":
        return "tool"
    if tl == "agent":
        return "agent"
    if a.get("llm.request.type") in ("chat", "completion") or (a.get("gen_ai.system") and a.get("gen_ai.request.model")):
        return "llm"
    return None


def _provider(a):
    return str(a.get("gen_ai.provider.name") or a.get("gen_ai.system") or a.get("llm.provider") or a.get("llm.system") or "unknown")


def _model(a):
    return a.get("gen_ai.response.model") or a.get("gen_ai.request.model") or a.get("llm.model_name") or None


def _input_messages(a, sp):
    if a.get("gen_ai.input.messages") is not None:
        msgs = _maybe_json(a["gen_ai.input.messages"])
        sysi = _maybe_json(a.get("gen_ai.system_instructions"))
        return {"system": sysi, "messages": msgs} if sysi is not None else msgs
    for prefix in ("gen_ai.prompt", "llm.input_messages"):
        rows = _indexed(a, prefix)
        if rows:
            return rows
    if a.get("input.value") is not None:
        return _maybe_json(a["input.value"])
    ev = [{"event": e["name"], **e["attrs"]} for e in sp["events"] if e["name"].startswith("gen_ai.") and
          e["name"] != "gen_ai.choice"]
    return ev or None


def _output_messages(a, sp):
    if a.get("gen_ai.output.messages") is not None:
        return _maybe_json(a["gen_ai.output.messages"])
    for prefix in ("gen_ai.completion", "llm.output_messages"):
        rows = _indexed(a, prefix)
        if rows:
            return rows
    if a.get("output.value") is not None:
        return _maybe_json(a["output.value"])
    ev = [{"event": e["name"], **e["attrs"]} for e in sp["events"] if e["name"] == "gen_ai.choice"]
    return ev or None


def _tool_uses(out):
    """Tool calls the model asked for, from any of the common output shapes."""
    found = []

    def add(i, n):
        if i and n and len(found) < 128:
            found.append({"id": str(i)[:200], "name": str(n)[:200]})

    def walk(x, depth=0):
        if depth > 8:
            return
        if isinstance(x, list):
            for y in x:
                walk(y, depth + 1)
        elif isinstance(x, dict):
            if x.get("type") in ("tool_call", "tool_use", "function_call") and (x.get("name") or (x.get("function") or {}).get("name")):
                add(x.get("id") or x.get("call_id"), x.get("name") or x["function"]["name"])
                return
            if isinstance(x.get("function"), dict) and x.get("id"):
                add(x["id"], x["function"].get("name"))
                return
            for k in ("parts", "content", "tool_calls", "message", "messages"):
                if k in x:
                    walk(_maybe_json(x[k]), depth + 1)
            for row in _indexed(x, "tool_calls"):  # flattened OpenLLMetry: tool_calls.0.id / tool_calls.0.name
                add(row.get("id"), row.get("name"))

    walk(out)
    seen, uniq = set(), []
    for t in found:
        if t["id"] not in seen:
            seen.add(t["id"])
            uniq.append(t)
    return uniq


def _finish(a, out):
    fr = a.get("gen_ai.response.finish_reasons")
    if isinstance(fr, list) and fr:
        return str(fr[0])
    if isinstance(fr, str):
        return fr
    if isinstance(out, list):
        for m in out:
            if isinstance(m, dict) and (m.get("finish_reason") or m.get("finish_reasons")):
                v = m.get("finish_reason") or m.get("finish_reasons")
                return str(v[0] if isinstance(v, list) and v else v)
    return None


def _error(sp):
    if sp["status_code"] != 2:
        return None
    a = sp["attrs"]
    msg = sp["status_message"] or a.get("error.type") or ""
    for e in sp["events"]:
        if e["name"] == "exception":
            msg = msg or e["attrs"].get("exception.message") or e["attrs"].get("exception.type") or ""
    return (str(msg) or "error")[:500]


def _tool_name(a, sp):
    return str(a.get("gen_ai.tool.name") or a.get("tool.name") or a.get("traceloop.entity.name") or
               (sp["name"][len("execute_tool "):] if sp["name"].startswith("execute_tool ") else sp["name"]) or "tool")[:200]


def _tool_args(a):
    for k in ("gen_ai.tool.call.arguments", "tool.parameters", "traceloop.entity.input", "input.value"):
        if a.get(k) is not None:
            v = _maybe_json(a[k])
            if isinstance(v, dict) and set(v) == {"args", "kwargs"} and isinstance(v.get("kwargs"), dict):
                v = v["kwargs"] or {"args": v["args"]}  # OpenLLMetry wraps python calls as {"args": [...], "kwargs": {...}}
            return v if isinstance(v, dict) else {"arguments": v}
    return {}


def _tool_result(a):
    for k in ("gen_ai.tool.call.result", "traceloop.entity.output", "output.value"):
        if a.get(k) is not None:
            return _maybe_json(a[k])
    return None


class _LRU:
    def __init__(self, cap):
        self.cap, self.d = cap, collections.OrderedDict()

    def __contains__(self, k):
        return k in self.d

    def get(self, k, default=None):
        return self.d.get(k, default)

    def put(self, k, v=True):
        self.d[k] = v
        self.d.move_to_end(k)
        while len(self.d) > self.cap:
            self.d.popitem(last=False)


class Mapper:
    """Stateful span -> event mapper. Not thread-safe; the receiver serialises calls."""

    def __init__(self, cwd=None, host=None, policy_loader=policy.load):
        self.cwd = os.path.abspath(cwd or os.getcwd())
        self.host = host or socket.gethostname()
        self.policy_loader = policy_loader
        self.written = _LRU(DEDUPE_CAP)   # (trace, span, kind) -> True once the signer accepted it
        self.runs = _LRU(RUN_CAP)         # run_id -> {"started": bool, "policy_hash": str, "ended": bool}

    def _base(self, run_id, ts, eid, typ, data, agent_id="main"):
        return {"schema_version": SCHEMA_VERSION, "id": eid, "seq": 0, "prev_hash": GENESIS, "ts": ts, "run_id": run_id,
                "agent_id": agent_id, "parent_id": None, "source": "sdk", "type": typ, "data": data}

    def plan(self, spans):
        """-> (items, skipped). items: list of (dedupe_key, event, attach, run_state_update) in send order."""
        pol, raw = self.policy_loader()
        phash = policy.policy_hash(pol)
        capture = pol.get("content_capture", "hashed")
        by_trace = collections.OrderedDict()
        skipped = 0
        for sp in spans:
            kind = classify(sp)
            if kind is None and sp["parent_span_id"] is not None:
                skipped += 1
                continue
            by_trace.setdefault(sp["trace_id"], []).append((kind, sp))
        items = []
        for tid, group in by_trace.items():
            group.sort(key=lambda x: (x[1]["start_ns"], x[1]["end_ns"]))
            first = group[0][1]
            service = first["resource"].get("service.name")
            rid = run_id_for(service, tid)
            st = self.runs.get(rid) or {"started": False, "policy_hash": None, "ended": False}
            agent_names = [sp["attrs"].get("gen_ai.agent.name") for k, sp in group if sp["attrs"].get("gen_ai.agent.name")]
            if not st["started"]:
                items.append(((tid, "run", "start"), self._base(rid, _ts(first["start_ns"]), _event_id(first["span_id"], "run.start"), "run.start", {
                    "agent": {"name": str(agent_names[0] if agent_names else service or "otel-agent")[:200],
                              "version": (str(first["resource"]["service.version"])[:200]
                                          if first["resource"].get("service.version") is not None else None)},
                    "model": next((_model(sp["attrs"]) for k, sp in group if k == "llm" and _model(sp["attrs"])), None),
                    "cwd": None, "host": f"otel:{self.host}", "os_user": "otel", "fail_mode": pol.get("fail_mode", "open"),
                    "policy": {"version": str(pol.get("version", "unversioned")), "hash": phash},
                    "capture_sources": ["sdk"], "sandbox": "unknown", "content_capture": capture,
                    "reasoning_capture": bool(pol.get("reasoning_capture", False)), "signer_isolation":
                        client.client_config().get("signer_isolation", "same-user")}), {"policy": raw}, ("started", phash)))
            policy_attached = st["policy_hash"] == phash or not st["started"]
            root = None
            for kind, sp in group:
                if sp["parent_span_id"] is None:
                    root = sp
                if kind == "tool":
                    items.extend(self._tool(rid, sp, pol, raw, phash, capture, not policy_attached))
                    policy_attached = True
                elif kind == "llm":
                    items.extend(self._llm(rid, sp, capture))
            if root is not None:
                why = _error(root)
                items.append(((tid, root["span_id"], "run.end"), self._base(
                    rid, _ts(root["end_ns"]), _event_id(root["span_id"], "run.end"), "run.end",
                    {"reason": ("error: " + why) if why else "done"}), None, ("ended", None)))
        return items, skipped

    def _tool(self, rid, sp, pol, raw, phash, capture, attach_policy):
        a, tid, sid = sp["attrs"], sp["trace_id"], sp["span_id"]
        name, args = _tool_name(a, sp), jsonable(_tool_args(a))
        if not isinstance(args, dict):
            args = {"arguments": args}
        use_id = str(a.get("gen_ai.tool.call.id") or a.get("tool_call.id") or f"otel_{sid}")[:200]
        d = policy.evaluate(pol, name, args, self.cwd)
        would = d["decision"]
        decision = "flag" if would in ("deny", "ask") else would
        reasons = [POST_HOC] + ([f"policy would have returned {would} before execution"] if would in ("deny", "ask") else []) + \
            d["reasons"] + d["flags"]
        start, end = _ts(sp["start_ns"]), _ts(sp["end_ns"])
        err = _error(sp)
        result = {"error": err} if err else jsonable(_tool_result(a))
        dotenv = privacy.mentions_dotenv(args.get("command"), args.get("file_path"), args.get("path"), args.get("pattern"))
        dur = max(0, (sp["end_ns"] - sp["start_ns"]) // 1_000_000) if sp["end_ns"] and sp["start_ns"] else None
        return [
            ((tid, sid, "tool.call"), self._base(rid, start, _event_id(sid, "tool.call"), "tool.call", {
                "tool_use_id": use_id, "name": name, "input": privacy.tool_input(name, args, capture)}), None, None),
            ((tid, sid, "policy.decision"), self._base(rid, start, _event_id(sid, "policy.decision"), "policy.decision", {
                "tool_use_id": use_id, "decision": decision, "rule_ids": d["rule_ids"], "reasons": reasons,
                "policy_hash": phash, "policy_version": str(pol.get("version", "unversioned"))}),
             {"policy": raw} if attach_policy else None, ("policy", phash)),
            ((tid, sid, "tool.result"), self._base(rid, end, _event_id(sid, "tool.result"), "tool.result", {
                "tool_use_id": use_id, "ok": err is None, "output": privacy.content(result, capture, dotenv),
                "duration_ms": dur}), None, None),
        ]

    def _llm(self, rid, sp, capture):
        a, tid, sid = sp["attrs"], sp["trace_id"], sp["span_id"]
        model = _model(a)
        model = str(model)[:200] if model is not None else None
        inp, out = _input_messages(a, sp), _output_messages(a, sp)
        streamed = bool(a.get("gen_ai.request.stream") or a.get("llm.is_streaming"))
        req = {"exchange_id": sid, "phase": "request", "model": model, "streamed": streamed,
               "upstream": "otel:" + _provider(a)[:100], "attribution": "none"}
        if inp is not None:
            req["request"] = privacy.content(jsonable(inp), capture)
        err = _error(sp)
        resp = {"exchange_id": sid, "phase": "response", "model": model, "streamed": streamed, "status": None,
                "duration_ms": max(0, (sp["end_ns"] - sp["start_ns"]) // 1_000_000) if sp["end_ns"] and sp["start_ns"] else None,
                "stop_reason": _finish(a, out), "tool_uses": _tool_uses(out), "error": err,
                "upstream": "otel:" + _provider(a)[:100], "attribution": "none"}
        if out is not None:
            resp["response"] = privacy.content(jsonable(out), capture)
        return [((tid, sid, "model.request"), self._base(rid, _ts(sp["start_ns"]), _event_id(sid, "model.request"),
                                                         "model.exchange", req), None, None),
                ((tid, sid, "model.response"), self._base(rid, _ts(sp["end_ns"]), _event_id(sid, "model.response"),
                                                          "model.exchange", resp), None, None)]

    def commit(self, key, event, update):
        self.written.put(key)
        rid = event["run_id"]
        st = dict(self.runs.get(rid) or {"started": False, "policy_hash": None, "ended": False})
        if update:
            what, val = update
            if what == "started":
                st.update(started=True, policy_hash=val)
            elif what == "policy":
                st["policy_hash"] = val
            elif what == "ended":
                st["ended"] = True
        self.runs.put(rid, st)


class Receiver:
    """Decode -> map -> send. `sink(event, attach)` returns the signer's response or raises client.SignerUnavailable."""

    def __init__(self, sink, mapper=None):
        self.sink = sink
        self.mapper = mapper or Mapper()
        self.lock = threading.Lock()
        self.stats = collections.Counter()

    def export(self, spans):
        """-> dict(accepted, duplicate, skipped, rejected, errors, retryable). Never raises SignerUnavailable."""
        with self.lock:
            try:
                items, skipped = self.mapper.plan(spans)
            except policy.PolicyError as e:
                return {"accepted": 0, "duplicate": 0, "skipped": 0, "rejected": len(spans), "errors": [f"policy: {e}"],
                        "retryable": False}
            res = {"accepted": 0, "duplicate": 0, "skipped": skipped, "rejected": 0, "errors": [], "retryable": False}
            for key, ev, attach, update in items:
                if key in self.mapper.written:
                    res["duplicate"] += 1
                    continue
                try:
                    r = self.sink(ev, attach)
                except client.SignerUnavailable as e:
                    res["retryable"] = True
                    res["errors"].append(f"signer unavailable: {e}")
                    break
                if r and r.get("ok"):
                    self.mapper.commit(key, ev, update)
                    res["accepted"] += 1
                elif r and r.get("retryable"):
                    res["retryable"] = True
                    res["errors"].append(str(r.get("error") or "signer could not write")[:300])
                    break
                else:
                    self.mapper.commit(key, ev, None)  # a permanent rejection must not be retried forever
                    res["rejected"] += 1
                    res["errors"].append(f"{ev['type']} for span {key[1]}: {(r or {}).get('error', 'rejected')}"[:300])
            for k in ("accepted", "duplicate", "skipped", "rejected"):
                self.stats[k] += res[k]
            return res


def local_sink(event, attach):
    return client.send(event, attach=attach, stream="sdk")


def handle_traces(receiver, body, content_type, content_encoding):
    """HTTP-agnostic OTLP/HTTP handling. -> (status, headers, body_bytes)."""
    proto = (content_type or "").split(";")[0].strip().lower() in ("application/x-protobuf", "application/protobuf")
    ctype = "application/x-protobuf" if proto else "application/json"

    def reply(code, rejected=0, message="", extra=None):
        if proto:
            if code == 200:
                data = encode_response_protobuf(rejected, message)
            else:  # google.rpc.Status: code (1), message (2)
                m = message.encode("utf-8")[:4096]
                data = b"\x08" + bytes([3 if code == 400 else 14]) + (b"\x12" + _varint(len(m)) + m if m else b"")
        else:
            obj = ({"partialSuccess": {"rejectedSpans": str(rejected), "errorMessage": message}} if (rejected or message) else {}) \
                if code == 200 else {"code": 3 if code == 400 else 14, "message": message}
            data = json.dumps(obj).encode()
        h = {"Content-Type": ctype}
        h.update(extra or {})
        return code, h, data

    try:
        spans, _ = decode(body, content_type, content_encoding)
    except WireError as e:
        code = 415 if "Content-Type" in str(e) else (413 if "exceeds" in str(e) else 400)
        return reply(code, message=str(e))
    res = receiver.export(spans)
    if res["retryable"]:
        return reply(503, message="; ".join(res["errors"])[:1000], extra={"Retry-After": "2"})
    return reply(200, rejected=res["rejected"], message="; ".join(res["errors"])[:1000])


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def make_handler(receiver):
    class H(BaseHTTPRequestHandler):
        server_version = "tracekit-otlp"
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _out(self, code, headers, data):
            self.send_response(code)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path.split("?")[0].rstrip("/") != "/v1/traces":
                self.close_connection = True
                return self._out(404, {"Content-Type": "application/json"}, b'{"message":"not found"}')
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if not 0 <= n <= MAX_BODY:
                self.close_connection = True
                return self._out(413, {"Content-Type": "application/json"},
                                 json.dumps({"message": f"body must be 0..{MAX_BODY} bytes with a Content-Length"}).encode())
            body = self.rfile.read(n)
            self._out(*handle_traces(receiver, body, self.headers.get("Content-Type"), self.headers.get("Content-Encoding")))
    return H


def serve(host="127.0.0.1", port=4318, receiver=None):
    srv = ThreadingHTTPServer((host, port), make_handler(receiver or Receiver(local_sink)))
    srv.daemon_threads = True
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit otel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="receive OTLP/HTTP traces (protobuf or JSON) on loopback and record agent spans")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=4318)
    s.add_argument("--cwd", help="directory path rules are evaluated against (default: the current directory)")
    a = ap.parse_args(argv)
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print("tracekit otel: the local receiver only listens on loopback; for other machines use "
              "`tracekit ingest serve` (TLS + per-client tokens), which also serves /v1/traces", file=sys.stderr)
        return 2
    try:
        client.status()
    except client.SignerUnavailable as e:
        print(f"tracekit otel: warning: signer not reachable yet ({e}); exporters will be told to retry", file=sys.stderr)
    srv = serve(a.host, a.port, Receiver(local_sink, Mapper(cwd=a.cwd)))
    print(f"tracekit otel: listening on http://{a.host}:{srv.server_address[1]}/v1/traces", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
