"""v2 signer records -> why runs, and why content checked against the signer's commitments.

    tracekit why import --store DATA_DIR --out runs                  # a signer's store, read-only
    tracekit why import --bundle run.tkb --trust trust.json --out runs
    tracekit why verify runs/tk-<run> --salts salts.jsonl            # `tracekit signer reveal` lines

One why run per v2 run (tk-<run id>), each event citing the signed record it came from (`tracekit`: log_id, seq,
run_id, run_seq, the record's hash and, where it has one, its commitment). The signer keeps commitments, never
content: observed inputs and tool results import as "content committed, not in the log", model exchanges as
decisions over what the run had observed so far, and each decision's provenance as observed edges from the record
that brought a value into the run to the call that used it.

A why log under --out that cites v2 runs (the signer-backed runtime wrote it) is merged with them instead, into
tk-<why run id>: content from the why log, citations, verdicts and provenance from the signed records. An event whose
citation does not match its record is flagged (`tracekit_mismatch`) and raised as a high evidence alert. Whether the
content matches what the signer committed to is checked only with the record's salt (`verify --salts`).
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from typing import Any, Dict, List, Optional

from .. import privacy
from ..format.canon import event_hash as jcs_hash
from .core import GENESIS, SCHEMA, Run, content_hash, event_hash, load_run, verify
from .evals import list_runs

COMMITTED = "content committed, not in the log"
CHECK_FILE = "content-check.json"


# --------------------------------------------------------------------------- sources

def store_records(data_dir: str) -> Dict[str, List[Dict[str, Any]]]:
    """run_id -> records of every client run in the store of signer data dir `data_dir`, read without its lock."""
    from ..signer.pipeline import SIGNER_RUN
    from ..signer.service import reader
    r = reader({"data_dir": data_dir})
    # lean: keyed by run id alone, tenants dropped (run ids are random); key by (tenant, run_id) if ids may collide
    try:
        return {key[1]: list(r.iter_run(*key)) for key in list(r.runs) if key != SIGNER_RUN}
    finally:
        r.close()


def bundle_records(path: str, trust: str):
    """(run_id -> records, report, exit code) of a v2 bundle; no records unless it verifies against `trust`."""
    from ..verify import v2
    rep, code = v2.verify(path, trust)
    if code:
        return {}, rep, code
    out = {}
    for name, data in v2.read_zip(path).items():
        if name.startswith("runs/"):
            recs = [json.loads(line) for line in data.splitlines() if line.strip()]
            out[recs[0]["event"]["run_id"]] = recs
    return out, rep, code


# --------------------------------------------------------------------------- records

def cite(rec: Dict[str, Any]) -> Dict[str, Any]:
    e, d = rec["event"], rec["event"]["data"]
    c = {"log_id": e["log_id"], "seq": e["seq"], "run_id": e["run_id"], "run_seq": e["run_seq"], "type": e["type"],
         "hash": rec["hash"]}
    commitment = ((d.get("output") or {}).get("hash") if e["type"] in ("input.observed", "tool.result")
                  else d.get("args_commitment") if e["type"] == "policy.decision"
                  else d.get("content_digest") if e["type"] == "model.exchange" else None)
    if commitment:
        c["commitment"] = commitment
    return c


def _calls(recs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """tool_call_id -> {"decision", "result": records, "approval": {decision, approver, self_approved}}."""
    calls: Dict[str, Dict[str, Any]] = {}
    for r in recs:
        t, d = r["event"]["type"], r["event"]["data"]
        if t == "policy.decision":
            calls[d["tool_use_id"]] = {"decision": r}   # a later attempt replaces an earlier one
        elif t == "tool.result" and d["tool_use_id"] in calls:
            calls[d["tool_use_id"]]["result"] = r
        elif t == "approval" and d.get("tool_use_id") in calls:
            calls[d["tool_use_id"]]["approval"] = {k: d.get(k) for k in ("decision", "approver", "self_approved")}
    return calls


def _policy(call: Dict[str, Any], reasons: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    d = call["decision"]["event"]["data"]
    known = reasons.get(d["policy_hash"], {})
    p = {"decision": d["decision"], "rule_ids": d["rule_ids"], "policy_hash": d["policy_hash"],
         "reasons": [known.get(i, "") for i in d["rule_ids"]]}
    if "approval" in call:
        p["approval"] = call["approval"]
    return p


def _provenance(call: Dict[str, Any], event_of) -> List[Dict[str, Any]]:
    """The decision's provenance entries, each with the why event of the record that brought the value."""
    e = call["decision"]["event"]
    return [{"field": p["field"], "kind": p["kind"], "record": p["source"]["run_seq"],
             **({"tool": p["source"]["tool"]} if p["source"].get("tool") else {}),
             "from_event": event_of(e["run_id"], p["source"]["run_seq"])} for p in e["data"].get("provenance") or []]


def _blocked(policy: Dict[str, Any]) -> Dict[str, Any]:
    return {"error": "blocked by policy: " + (", ".join(policy["rule_ids"]) or policy["decision"]), **policy}


def _evidence(recs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    out = []
    for r in recs:
        e, d = r["event"], r["event"]["data"]
        where = f"run {e['run_id']} record {e['run_seq']}, log {e['log_id']} seq {e['seq']}"
        if e["type"] == "capture.gap":
            out.append({"title": "The signer recorded a capture gap: events may be missing",
                        "detail": f"{d.get('kind', '')}: {d.get('reason', '')} ({where})"})
        elif e["type"] == "trace.tamper":
            out.append({"title": "The signer recorded tampering", "detail": f"{d.get('kind', '')} ({where})"})
    return out


class _Writer:
    """A new why run under out_dir: hash-chained events and content-addressed blobs."""

    def __init__(self, out_dir: str, run_id: str):
        self.run_id = "tk-" + "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:100]
        self.path = os.path.join(out_dir, self.run_id)
        if os.path.exists(os.path.join(self.path, "events.jsonl")):
            raise FileExistsError(f"{self.path} already exists; remove it to re-import")
        os.makedirs(os.path.join(self.path, "blobs"), exist_ok=True)
        self.events: List[Dict[str, Any]] = []

    def blob(self, v: Any) -> str:
        ref = content_hash(v)
        with open(os.path.join(self.path, "blobs", ref[7:] + ".json"), "w", encoding="utf-8") as f:
            json.dump({"v": v}, f, sort_keys=True, ensure_ascii=False, default=str)
        return ref

    def emit(self, agent: str, etype: str, ts: str, rec: Optional[Dict[str, Any]] = None, **body: Any):
        ev = {"schema": SCHEMA, "seq": len(self.events), "id": body.pop("id", None) or secrets.token_hex(16),
              "prev_hash": self.events[-1]["hash"] if self.events else GENESIS, "ts": ts, "run_id": self.run_id,
              "agent": agent, "type": etype, **body}
        if rec is not None:
            ev["tracekit"] = cite(rec)
        ev["hash"] = event_hash(ev)
        self.events.append(ev)
        return ev

    def close(self) -> str:
        with open(os.path.join(self.path, "events.jsonl"), "w", encoding="utf-8") as f:
            for ev in self.events:
                f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
        return self.path


# --------------------------------------------------------------------------- one v2 run

def convert(recs: List[Dict[str, Any]], out_dir: str, reasons: Dict[str, Dict[str, str]]) -> str:
    first = recs[0]["event"]
    w = _Writer(out_dir, first["run_id"])
    agent = (first["data"].get("agent") or {}).get("name") if first["type"] == "run.registered" else None
    agent = agent or "main"
    calls = _calls(recs)
    exchanges: Dict[str, List[Dict[str, Any]]] = {}
    for r in recs:
        if r["event"]["type"] == "model.exchange":
            exchanges.setdefault(r["event"]["data"]["exchange_id"], []).append(r)
    w.emit("run", "run.start", first["ts"], program="", seed=0, interventions=[], models=[], tools=[],
           sensitive_tools=[], untrusted_tools=[],
           meta={"source": "tracekit", "tracekit_runs": [first["run_id"]], "tenant": first["tenant"],
                 "agent": agent, "evidence_alerts": _evidence(recs)})
    by_seq: Dict[int, str] = {}
    seen: List[Dict[str, Any]] = []        # what the run had observed so far: a model exchange's context
    decision_of: Dict[str, str] = {}       # tool_use id -> the decision event of the exchange that asked for it
    for r in recs:
        e, d, t = r["event"], r["event"]["data"], r["event"]["type"]
        ev = None
        if t == "run.registered":
            ev = w.emit(agent, "agent.start", e["ts"], r, parent=None, role="")
        elif t == "input.observed":
            kind = "task" if d["source"] == "task" else "input"
            ev = w.emit(agent, "input", e["ts"], r, ref=w.blob({"content": COMMITTED, **d["output"]}),
                        source=d["source"], trust=d["trust"], kind=kind)
            seen.append({"ref": ev["ref"], "kind": kind, "source": d["source"], "trust": d["trust"],
                         "from_event": ev["id"]})
        elif t == "model.exchange" and exchanges[d["exchange_id"]][0] is r:
            ex = [x["event"]["data"] for x in exchanges[d["exchange_id"]]]
            uses = [u for x in ex for u in x.get("tool_uses") or []]
            ev = w.emit(agent, "decision", e["ts"], r, model=d["model"], purpose="", params={}, seed=None,
                        context=list(seen), ablated=[], output=w.blob({"content": COMMITTED, "tool_uses": uses}),
                        usage=next((x["usage"] for x in ex if x.get("usage")), {}),
                        status="error" if any(x.get("error") for x in ex) else "ok", duration_ms=None,
                        context_mode="reconstructed")
            decision_of.update({u["id"]: ev["id"] for u in uses})
        elif t in ("policy.decision", "tool.result") and (call := calls.get(d["tool_use_id"])) and \
                (call.get("result") or call["decision"]) is r:   # at its result, or at its decision if it never ran
            dd, pol = call["decision"]["event"]["data"], _policy(call, reasons)
            ran = t == "tool.result"
            res = {"content": COMMITTED, **d["output"]} if ran else _blocked(pol)
            extra = {} if ran else {"guard": {"verdict": "block", "alerts": [],
                                              "reason": "Tracekit policy " + ", ".join(dd["rule_ids"])}}
            ev = w.emit(agent, "action", e["ts"], r, tool=dd["tool"],
                        args_ref=w.blob({"content": COMMITTED, "commitment": dd.get("args_commitment")}),
                        result_ref=w.blob(res), decision=decision_of.get(d["tool_use_id"]),
                        status=("ok" if d["ok"] else "error") if ran else "blocked", mode="live" if ran else "blocked",
                        sensitive=dd["decision"] in ("deny", "ask") or bool(dd.get("provenance")), duration_ms=None,
                        policy=pol, provenance=_provenance(call, lambda _, seq: by_seq.get(seq)), **extra)
        elif t == "run.final":
            w.emit("run", "run.end", e["ts"], r, outcome=None)
        if ev is not None:
            by_seq[e["run_seq"]] = ev["id"]
    return w.close()


# --------------------------------------------------------------------------- merge with a why log

def _mismatch(ev: Dict[str, Any], t: Dict[str, Any], rec: Optional[Dict[str, Any]],
              calls: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Why the record `t` cites does not back event `ev`, or None."""
    if rec is None:
        return f"no record {t['run_seq']} in Tracekit run {t['run_id']}"
    e, d = rec["event"], rec["event"]["data"]
    if e["type"] != t["type"]:
        return f"record {t['run_seq']} is a {e['type']}, not a {t['type']}"
    if ev["type"] == "agent.start" and (d.get("agent") or {}).get("name") != ev["agent"]:
        return f"the run was registered for agent {(d.get('agent') or {}).get('name')!r}"
    if ev["type"] in ("input", "message") and d["trust"] != ev["trust"]:
        return f"the record says {d['trust']}, the log {ev['trust']}"
    if ev["type"] == "input" and d["source"] != ev["source"][:256]:
        return f"the record's source is {d['source']!r}"
    if ev["type"] == "decision" and d["model"] != ev["model"][:128]:
        return f"the record's model is {d['model']!r}"
    if ev["type"] == "action":
        call = calls.get(t.get("tool_call_id") or "")
        if call is None or d.get("tool_use_id") != t.get("tool_call_id"):
            return f"the record is not about tool call {t.get('tool_call_id')}"
        if call["decision"]["event"]["data"]["tool"] != ev["tool"]:
            return f"the record's tool is {call['decision']['event']['data']['tool']!r}"
        if ("result" in call) == (ev["status"] == "blocked"):
            return "the record says the call " + ("ran" if "result" in call else "did not run")
    return None


def merge(run: Run, records: Dict[str, List[Dict[str, Any]]], out_dir: str,
          reasons: Dict[str, Dict[str, str]]) -> str:
    """The why log `run` with each citation checked against `records` and the signed verdicts filled in."""
    w = _Writer(out_dir, run.run_id)
    index = {(r["event"]["run_id"], r["event"]["run_seq"]): r for recs in records.values() for r in recs}
    calls = {rid: _calls(recs) for rid, recs in records.items()}
    event_of = {(ev["tracekit"]["run_id"], ev["tracekit"]["run_seq"]): ev["id"]
                for ev in run.events if ev.get("tracekit")}
    cited = sorted({ev["tracekit"]["run_id"] for ev in run.events if ev.get("tracekit")})
    # the merged log is chained anew: a break in the original's chain must not vanish with it
    alerts = [{"title": "The why log failed its integrity check", "detail": p} for p in verify(run)[:5]]
    alerts += [a for rid in cited for a in _evidence(records.get(rid, []))]
    alerts += [{"title": "A Tracekit run this log cites is not in the import",
                "detail": f"run {rid}: import the store or bundle that holds it"} for rid in cited if rid not in records]
    out = []
    for ev in run.events:
        ev = {k: v for k, v in ev.items() if k not in ("schema", "seq", "prev_hash", "hash", "run_id")}
        t = ev.get("tracekit")
        if t:
            rec = index.get((t["run_id"], t["run_seq"]))
            problem = _mismatch(ev, t, rec, calls.get(t["run_id"], {}))
            if problem:
                ev["tracekit_mismatch"] = problem
                alerts.append({"title": f"{ev['type']} #{len(out)} does not match the signed record it cites",
                               "detail": f"{problem} (run {t['run_id']} record {t['run_seq']})"})
            else:
                ev["tracekit"] = {**cite(rec), **({"tool_call_id": t["tool_call_id"]} if "tool_call_id" in t else {})}
                if ev["type"] == "action":
                    call = calls[t["run_id"]][t["tool_call_id"]]
                    ev["policy"] = _policy(call, reasons)
                    ev["provenance"] = _provenance(call, lambda rid, seq: event_of.get((rid, seq)))
        out.append(ev)
    for v in run.blobs.values():
        w.blob(v)
    for ev in out:
        if ev["type"] == "run.start":
            ev["meta"] = {**(ev.get("meta") or {}), "source": "tracekit", "tracekit_runs": cited,
                          "merged_from": run.path, "evidence_alerts": alerts}
        w.emit(ev.pop("agent"), ev.pop("type"), ev.pop("ts"), **ev)
    return w.close()


def import_records(records: Dict[str, List[Dict[str, Any]]], out_dir: str) -> List[str]:
    """Merge every why log under out_dir that cites one of these runs; convert the others. Returns the run paths."""
    from ..view import policy_reasons
    reasons = policy_reasons()
    os.makedirs(out_dir, exist_ok=True)
    paths, merged = [], set()
    for p in list_runs(out_dir):
        run = load_run(p)
        if (run.start.get("meta") or {}).get("source") == "tracekit":
            continue   # an import already
        cites = {ev["tracekit"]["run_id"] for ev in run.events if ev.get("tracekit")}
        if cites & records.keys():
            paths.append(merge(run, records, out_dir, reasons))
            merged |= cites
    return paths + [convert(recs, out_dir, reasons) for rid, recs in records.items() if rid not in merged]


# --------------------------------------------------------------------------- content vs commitments

def _digest(ev: Dict[str, Any], t: Dict[str, Any], run: Run) -> str:
    """The digest the signer committed to for event `ev`, recomputed from the why log's content."""
    if t["type"] == "input.observed":
        return jcs_hash(privacy.redact(run.value(ev["ref"]))[0])
    args = run.value(ev.get("args_ref"))
    if t["type"] == "tool.result":
        dotenv = isinstance(args, dict) and privacy.mentions_dotenv(*(args.get(k) for k in privacy.ACTION_FIELDS))
        return jcs_hash(privacy.redact({"result": run.value(ev["result_ref"])}, dotenv)[0])
    if t["type"] == "policy.decision":
        return jcs_hash({"tool": ev["tool"], "args": args})
    return jcs_hash([run.value(c["ref"]) for c in ev["context"]])   # model.exchange: the exact context


def check_content(run: Run, salts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """For each event citing a record with a commitment: matched, mismatched or not revealed (no salt for its
    record). Written to the run's content-check.json, where a mismatch becomes a high evidence alert."""
    salt = {s["seq"]: s["salt"] for s in salts}
    out = []
    for ev in run.events:
        t = ev.get("tracekit") or {}
        if "commitment" not in t:
            continue
        r = {"event": ev["id"], "seq": t["seq"], "type": t["type"], "agent": ev["agent"], "kind": ev["type"]}
        if t["seq"] not in salt:
            r["verdict"] = "not revealed"
        else:
            try:
                digest = _digest(ev, t, run)
            except ValueError as e:   # content JCS can't encode: it cannot be what the signer committed to
                digest, r["detail"] = "", str(e)
            mac = hmac.new(bytes.fromhex(salt[t["seq"]]), digest.encode(), "sha256").hexdigest()
            r["verdict"] = "matched" if digest and hmac.compare_digest(t["commitment"], "hmac-sha256:" + mac) \
                else "mismatched"
        out.append(r)
    if run.path:
        with open(os.path.join(run.path, CHECK_FILE), "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1)
    return out


def content_checks(run: Run) -> List[Dict[str, Any]]:
    p = os.path.join(run.path, CHECK_FILE) if run.path else ""
    if not p or not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)
