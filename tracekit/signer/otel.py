"""OpenTelemetry on the v2 signer (04-design §10, docs/otel.md).

In: with an `otlp` section in signer.yaml, the HTTPS listener (transport/http.py) also answers OTLP/HTTP
`POST /v1/traces` (`SignerService.otlp`). Each trace is one run of the caller's tenant, keyed by its trace id
(run_id `otel:<trace id>`), registered by the signer with source `import`, tier T3 and fidelity none. `records` maps
one span, classified as tracekit.otlp does, to the records of that run: a tool span to tool.call + tool.result, a model
span to one model.exchange; arguments, results and messages only as commitments. Each record names its span
(`span_id`), so a span id and record type is written once per run, across restarts too.

Out: `payload` is the OTLP/JSON of one run: an invoke_agent root span and an execute_tool span per call, each with
tracekit.entry_hash, tracekit.run_seq and tracekit.tier; v2 records hold no argument or result content, so only their
digests and commitments leave. `Exporter` sends each run that reaches run.final from its own thread (`otel_out`).
"""
import collections
import hashlib
import math
import queue
import re
import secrets
import threading

from tracekit import otel, otlp, privacy
from tracekit.format.canon import MAX_SAFE_INT
from tracekit.usage import from_otel

TIER = "T3"
QUEUE = 1000   # runs waiting for the exporter; more are dropped and counted
_attr = otel._attr


def run_id(trace_id):
    return "otel:" + trace_id


def plain(v):
    """`v` with what canonical JSON refuses (NaN, infinities, integers past 2**53) as strings."""
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    if (isinstance(v, float) and not math.isfinite(v)
            or isinstance(v, int) and not isinstance(v, bool) and abs(v) > MAX_SAFE_INT):
        return str(v)
    return v


def records(kind, sp, content):
    """[(type, data)] of span `sp` that otlp.classify called `kind` ("tool" or "llm"). `content(value, label, dotenv)`
    -> (the {hash, size, redacted} of `value` redacted and committed under the salt of `label`, its redaction
    manifest)."""
    a, sid = sp["attrs"], sp["span_id"]
    err = otlp._error(sp)
    dur = max(0, (sp["end_ns"] - sp["start_ns"]) // 1_000_000) if sp["end_ns"] and sp["start_ns"] else None
    if kind == "tool":
        name, args = otlp._tool_name(a, sp), plain(otlp._tool_args(a))
        dotenv = privacy.mentions_dotenv(*(args.get(k) for k in privacy.ACTION_FIELDS))
        use, c, r = otlp.tool_use_id(a, sid), secrets.token_hex(16), secrets.token_hex(16)
        out, manifest = content(plain({"error": err} if err else otlp._tool_result(a)), f"tool.result:{r}", dotenv)
        return [("tool.call", {"tool_use_id": use, "name": name, "salt_id": c,
                               "input": {"args": content({"tool": name, "args": args}, f"tool.call:{c}", dotenv)[0]}}),
                ("tool.result", {"tool_use_id": use, "ok": err is None, "output": out, "duration_ms": dur,
                                 "redaction": manifest, "salt_id": r})]
    m, model, out = secrets.token_hex(16), otlp._model(a), otlp._output_messages(a, sp)
    d = {"exchange_id": sid, "phase": "response", "model": None if model is None else str(model)[:200],
         "streamed": bool(a.get("gen_ai.request.stream") or a.get("llm.is_streaming") or sp["name"].endswith(".doStream")),
         "upstream": "otel:" + otlp._provider(a)[:100], "attribution": "none", "duration_ms": dur, "error": err,
         "stop_reason": (otlp._finish(a, out) or "")[:100] or None, "tool_uses": otlp._tool_uses(out), "salt_id": m,
         "content_digest": content(plain({"request": otlp._input_messages(a, sp), "response": out}),
                                   f"model.exchange:{m}", False)[0]["hash"]}
    usage = {k: v for k, v in (from_otel(a) or {}).items() if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
    if {"input_tokens", "output_tokens"} <= usage.keys():
        d["usage"] = usage
    return [("model.exchange", d)]


def _hex(text, n):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def payload(recs):
    """OTLP/JSON of one run's v2 records, in run_seq order: an invoke_agent root span and one execute_tool span per
    (tool_use_id, attempt). An imported run keeps its trace id and its tool spans their span ids."""
    first = recs[0]["event"]
    rid, key = first["run_id"], f"{first['tenant']}/{first['run_id']}"
    trace = rid[5:] if first["source"] == "import" and re.fullmatch(r"otel:[0-9a-f]{32}", rid) else _hex(key, 32)
    root = _hex(key + "/root", 16)

    def marks(r):
        e = r["event"]
        return [_attr("tracekit.entry_hash", r["hash"]), _attr("tracekit.run_seq", e["run_seq"]),
                _attr("tracekit.tier", e.get("tier", "T1"))]
    agent = first["data"]["agent"]["name"] if first["type"] == "run.registered" else "agent"
    spans = [{"traceId": trace, "spanId": root, "name": f"invoke_agent {agent}", "kind": 1,
              "startTimeUnixNano": otel._ns(first["ts"]), "endTimeUnixNano": otel._ns(recs[-1]["event"]["ts"]),
              "attributes": [_attr("gen_ai.operation.name", "invoke_agent"), _attr("gen_ai.agent.name", agent),
                             _attr("tracekit.run_id", rid), _attr("tracekit.tenant", first["tenant"]),
                             _attr("tracekit.source", first["source"]), *marks(recs[0])],
              "status": {"code": 1}}]
    calls = collections.OrderedDict()
    for r in recs:
        e = r["event"]
        if e["type"] in ("policy.decision", "tool.call", "tool.result"):
            calls.setdefault((e["data"]["tool_use_id"], e.get("attempt", 0)), []).append(r)
    for (use, attempt), rs in calls.items():
        by = {r["event"]["type"]: r["event"]["data"] for r in rs}
        dec, call, res = by.get("policy.decision"), by.get("tool.call"), by.get("tool.result")
        name = (dec or {}).get("tool") or (call or {}).get("name") or "tool"
        attrs = [_attr("gen_ai.operation.name", "execute_tool"), _attr("gen_ai.tool.name", name),
                 _attr("gen_ai.tool.call.id", use), *marks(rs[0]),
                 _attr("tracekit.policy.decision", dec["decision"] if dec else "none"),
                 _attr("tracekit.policy.rule_ids", dec["rule_ids"] if dec else [])]
        commitment = (dec or {}).get("args_commitment") or (call or {}).get("input", {}).get("args", {}).get("hash")
        if commitment:
            attrs.append(_attr("tracekit.args_commitment", commitment))
        if res:
            attrs += [_attr("tracekit.result.ok", res["ok"]), _attr("tracekit.result.hash", res["output"].get("hash", ""))]
        status = {"code": 1} if res and res["ok"] else {"code": 2, "message": "error" if res else "blocked by policy"
                                                        if dec and dec["decision"] == "deny" else "no result recorded"}
        spans.append({"traceId": trace, "spanId": rs[0]["event"].get("span_id") or _hex(f"{key}/{use}/{attempt}", 16),
                      "parentSpanId": root, "name": f"execute_tool {name}", "kind": 1,
                      "startTimeUnixNano": otel._ns(rs[0]["event"]["ts"]),
                      "endTimeUnixNano": otel._ns(rs[-1]["event"]["ts"]), "attributes": attrs, "status": status})
    return {"resourceSpans": [{"resource": {"attributes": [_attr("service.name", "tracekit")]},
                               "scopeSpans": [{"scope": {"name": "tracekit"}, "spans": spans}]}]}


class Exporter:
    """Sends the run of each key given to `put` (its records from `read(key)`) to an OTLP/HTTP endpoint, one at a time
    on its own thread. `dropped`: a metrics Counter by reason (queue_full, failed, shutdown)."""

    def __init__(self, endpoint, headers, read, dropped):
        self.endpoint, self.headers, self.read, self.dropped = endpoint, dict(headers), read, dropped
        self._q = queue.Queue(QUEUE)
        self._thread = threading.Thread(target=self._loop, name="tracekit-signer-otel", daemon=True)
        self._thread.start()

    def put(self, key):
        try:
            self._q.put_nowait(key)
        except queue.Full:
            self.dropped.inc("queue_full")

    def _loop(self):
        while (key := self._q.get()) is not None:
            try:
                if otel.push(self.endpoint, payload(self.read(key)), headers=self.headers)[0] >= 300:
                    self.dropped.inc("failed")
            except Exception:   # unreachable, refused or unreadable: this run is not sent again
                self.dropped.inc("failed")

    def close(self):
        # lean: runs still queued at shutdown are dropped (counted); persist the queue if exports must survive restarts
        n = 0
        while True:
            try:
                self._q.get_nowait()
                n += 1
            except queue.Empty:
                break
        if n:
            self.dropped.inc("shutdown", n)
        self._q.put(None)
        self._thread.join()
