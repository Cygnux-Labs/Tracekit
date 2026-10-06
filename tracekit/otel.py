"""OpenTelemetry export (C10): `tracekit export --otel` writes otel.json (OTLP/JSON) into the
bundle; `--otel-endpoint http://host:4318` also POSTs it to an OTLP/HTTP collector.

One trace per run:
  invoke_agent <agent>              root span, run.start -> run.end
    chat <model>                    one span per model exchange recorded by the proxy
    execute_tool <tool>             one span per tool call (tool.call -> tool.result)
Attributes follow the OpenTelemetry GenAI semantic conventions (gen_ai.*) where they exist;
Tracekit's security fields are under tracekit.*. capture.gap, trace.tamper and approval events
become span events on the root span, so they show up in trace views. Content is never exported:
only what the bundle already holds (hashes, clear operational fields per docs/privacy.md)."""
import datetime as _dt
import hashlib
import json
import urllib.request


def _ns(ts):
    d = _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)
    return str(int(d.timestamp() * 1_000_000) * 1000)


def _attr(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    if isinstance(v, float):
        return {"key": k, "value": {"doubleValue": v}}
    if isinstance(v, (list, tuple)):
        return {"key": k, "value": {"arrayValue": {"values": [{"stringValue": str(x)} for x in v]}}}
    return {"key": k, "value": {"stringValue": str(v)}}


def _sid(*parts):
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _clear(inp, k):
    v = (inp or {}).get(k) or {}
    return v.get("value") if "value" in v else None


def _provider(d):
    up = d.get("upstream") or ""
    return up[5:] if up.startswith("otel:") else "anthropic"  # the proxy only fronts the Anthropic API


def to_otlp_json(events, kid=None, hashes=None):
    """hashes: optional {seq: record hash}. Each span then carries tracekit.entry_hash, so any span in any
    backend can be traced back to the signed ledger entry it came from (and checked with `tracekit verify`)."""
    from .otlp import trace_id_of
    hashes = hashes or {}

    def ev_attrs(e):
        out = [_attr("tracekit.seq", e["seq"])]
        if e["seq"] in hashes:
            out.append(_attr("tracekit.entry_hash", hashes[e["seq"]]))
        return out
    runs = {}
    for e in events:
        r = runs.setdefault(e["run_id"], {"start": None, "end": None, "first": e, "last": e, "calls": {}, "dec": {}, "spans": [],
                                          "events": [], "ex": {}})
        r["last"] = e
        d = e["data"]
        if e["type"] == "run.start":
            r["start"] = e
        elif e["type"] == "run.end":
            r["end"] = e
        elif e["type"] == "tool.call":
            r["calls"][d["tool_use_id"]] = e
        elif e["type"] == "policy.decision":
            r["dec"][d["tool_use_id"]] = d
        elif e["type"] == "tool.result" and d["tool_use_id"] in r["calls"]:
            r["spans"].append(("tool", r["calls"].pop(d["tool_use_id"]), e))
        elif e["type"] == "model.exchange":
            if d.get("phase") == "request":
                r["ex"][d["exchange_id"]] = e
            else:
                r["spans"].append(("chat", r["ex"].pop(d["exchange_id"], e), e))
        elif e["type"] in ("capture.gap", "trace.tamper", "approval", "error"):
            r["events"].append(e)
    rs = []
    for rid, r in runs.items():
        if rid.startswith("_"):
            continue
        orig = trace_id_of(rid)  # ingested from OpenTelemetry: give the spans back their original ids
        trace = orig or hashlib.sha256(rid.encode()).hexdigest()[:32]
        root = (r["end"]["id"][:16] if orig and r["end"] else _sid(rid, "root"))
        st = (r["start"] or {}).get("data", {})
        agent = (st.get("agent") or {}).get("name", "agent")
        spans = []
        provs = sorted({_provider(b["data"]) for k, a, b in r["spans"] if k == "chat"}) or (["unknown"] if orig else ["anthropic"])
        root_attrs = [_attr("gen_ai.operation.name", "invoke_agent"), _attr("gen_ai.agent.name", agent),
                      _attr("gen_ai.conversation.id", rid), _attr("gen_ai.provider.name", provs[0])]
        if r["start"]:
            root_attrs += ev_attrs(r["start"])
        for k in ("model", "repo", "commit", "os_user", "fail_mode", "signer_isolation", "sandbox", "content_capture"):
            if st.get(k) is not None:
                root_attrs.append(_attr(("gen_ai.request.model" if k == "model" else f"tracekit.{k}"), st[k]))
        if st.get("policy"):
            root_attrs += [_attr("tracekit.policy.version", st["policy"]["version"]), _attr("tracekit.policy.hash", st["policy"]["hash"])]
        if st.get("capture_sources"):
            root_attrs.append(_attr("tracekit.capture_sources", st["capture_sources"]))
        if kid:
            root_attrs.append(_attr("tracekit.signer.kid", kid))
        span_events = [{"timeUnixNano": _ns(e["ts"]), "name": e["type"],
                        "attributes": [_attr("tracekit.seq", e["seq"])] +
                                      [_attr(f"tracekit.{k}", v if isinstance(v, (str, int, bool, float)) else json.dumps(v, sort_keys=True))
                                       for k, v in e["data"].items() if v is not None]} for e in r["events"]]
        bad = any(e["type"] in ("trace.tamper",) for e in r["events"])
        spans.append({"traceId": trace, "spanId": root, "name": f"invoke_agent {agent}", "kind": 1,
                      "startTimeUnixNano": _ns((r["start"] or r["first"])["ts"]), "endTimeUnixNano": _ns((r["end"] or r["last"])["ts"]),
                      "attributes": root_attrs, "events": span_events,
                      "status": {"code": 2, "message": "trace tampering detected"} if bad else {"code": 1}})
        for kind, a, b in r["spans"]:
            if kind == "tool":
                d, dec = b["data"], r["dec"].get(a["data"]["tool_use_id"], {})
                attrs = [_attr("gen_ai.operation.name", "execute_tool"), _attr("gen_ai.tool.name", a["data"]["name"]),
                         _attr("gen_ai.tool.call.id", d["tool_use_id"]), _attr("tracekit.agent_id", a["agent_id"]),
                         _attr("tracekit.source", a["source"]), *ev_attrs(a),
                         _attr("tracekit.policy.decision", dec.get("decision", "unknown")),
                         _attr("tracekit.policy.rule_ids", dec.get("rule_ids", [])), _attr("tracekit.result.ok", bool(d["ok"]))]
                for k in ("command", "file_path", "url"):
                    v = _clear(a["data"]["input"], k)
                    if v is not None:
                        attrs.append(_attr(f"tracekit.tool.{k}", v))
                spans.append({"traceId": trace, "spanId": a["id"][:16], "parentSpanId": root, "name": f"execute_tool {a['data']['name']}",
                              "kind": 1, "startTimeUnixNano": _ns(a["ts"]), "endTimeUnixNano": _ns(b["ts"]), "attributes": attrs,
                              "status": {"code": 1 if d["ok"] else 2}})
            else:
                d = b["data"]
                attrs = [_attr("gen_ai.operation.name", "chat"), _attr("gen_ai.provider.name", _provider(d)),
                         _attr("tracekit.source", b["source"]), *ev_attrs(b), _attr("tracekit.exchange_id", d["exchange_id"])]
                if d.get("model"):
                    attrs.append(_attr("gen_ai.request.model", d["model"]))
                if d.get("stop_reason"):
                    attrs.append(_attr("gen_ai.response.finish_reasons", [d["stop_reason"]]))
                if d.get("tool_uses"):
                    attrs.append(_attr("tracekit.tool_use_ids", [t["id"] for t in d["tool_uses"]]))
                for k in ("status", "added_latency_ms", "first_byte_ms"):
                    if d.get(k) is not None:
                        attrs.append(_attr(f"tracekit.{k}", d[k]))
                sid = d["exchange_id"] if orig and len(d["exchange_id"]) == 16 else _sid(rid, d["exchange_id"])
                spans.append({"traceId": trace, "spanId": sid, "parentSpanId": root,
                              "name": f"chat {d.get('model') or ''}".strip(), "kind": 3, "startTimeUnixNano": _ns(a["ts"]),
                              "endTimeUnixNano": _ns(b["ts"]), "attributes": attrs,
                              "status": {"code": 1 if (d.get("status") or 0) < 400 and not d.get("error") else 2}})
        for tid, c in r["calls"].items():  # denied, held or unfinished calls
            dec = r["dec"].get(tid, {})
            spans.append({"traceId": trace, "spanId": c["id"][:16], "parentSpanId": root, "name": f"execute_tool {c['data']['name']}",
                          "kind": 1, "startTimeUnixNano": _ns(c["ts"]), "endTimeUnixNano": _ns(c["ts"]),
                          "attributes": [_attr("gen_ai.operation.name", "execute_tool"), _attr("gen_ai.tool.name", c["data"]["name"]),
                                         _attr("gen_ai.tool.call.id", tid), *ev_attrs(c),
                                         _attr("tracekit.policy.decision", dec.get("decision", "unknown")),
                                         _attr("tracekit.policy.rule_ids", dec.get("rule_ids", []))],
                          "status": {"code": 2, "message": "blocked by policy" if dec.get("decision") == "deny" else "no result recorded"}})
        rs.append({"resource": {"attributes": [_attr("service.name", "tracekit"), _attr("tracekit.run_id", rid)]},
                   "scopeSpans": [{"scope": {"name": "tracekit", "version": "0.2"}, "spans": spans}]})
    return {"resourceSpans": rs}


def push(endpoint, payload, timeout=10):
    """POST OTLP/JSON to an OTLP/HTTP collector (e.g. http://localhost:4318)."""
    url = endpoint.rstrip("/") + ("" if endpoint.rstrip("/").endswith("/v1/traces") else "/v1/traces")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers={"content-type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")
