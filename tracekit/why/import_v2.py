"""v2 signer records -> why runs, and why content checked against the signer's commitments.

    tracekit why import --store DATA_DIR --out runs                  # a signer's store, read-only
    tracekit why import --bundle run.tkb --trust trust.json --out runs
    tracekit why verify runs/tk-<run>-<hash> --salts salts.jsonl     # `tracekit signer reveal` lines

One why run per v2 run (tk-<run id>-<hash>: _target), each event citing the signed record it came from (`tracekit`: log_id, seq,
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

import hashlib
import hmac
import io
import json
import os
import re
from typing import Any, Dict, List, Optional

from .. import privacy
from ..format.canon import event_hash as jcs_hash
from .core import COMMITTED, GENESIS, SCHEMA, UNFINISHED, Run, content_hash, event_hash, load_run, verify
from .evals import list_runs

NO_OUTCOME = "the signer recorded no outcome: the call may have run"
CHECK_FILE = "content-check.json"


# --------------------------------------------------------------------------- sources

def _store(data_dir: str):
    from ..signer.service import reader
    if not os.path.isdir(os.path.join(data_dir, "store")):
        raise FileNotFoundError(f"{data_dir} is not a signer data dir: it has no store/")
    return reader({"data_dir": data_dir})


def store_runs(data_dir: str) -> Dict[str, int]:
    """run_id -> number of records of every client run in the store of signer data dir `data_dir`."""
    from ..signer.pipeline import SIGNER_RUN
    r = _store(data_dir)
    try:
        return {key[1]: run["run_seq"] + 1 for key, run in list(r.runs.items()) if key != SIGNER_RUN}
    finally:
        r.close()


def store_records(data_dir: str, run: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """run_id -> records of every client run (or only run `run`) in the store of signer data dir `data_dir`, read
    without its lock."""
    from ..signer.pipeline import SIGNER_RUN
    r = _store(data_dir)
    # lean: keyed by run id alone, tenants dropped (run ids are random); key by (tenant, run_id) if ids may collide
    try:
        return {key[1]: list(r.iter_run(*key)) for key in list(r.runs)
                if key != SIGNER_RUN and run in (None, key[1])}
    finally:
        r.close()


def bundle_records(path: str, trust: str, memo=None):
    """(run_id -> records, report, exit code) of a v2 bundle; no records unless it verifies against `trust`. The file
    is read once, so the records are the ones verified, and they are parsed as the verifier parses them. `memo`:
    verify.v2's (tracekit view's watcher keeps one: records it checked are not checked for signature and schema
    again)."""
    from ..bundle_v2 import run_files
    from ..verify import v2
    with open(path, "rb") as f:
        mine = io.BytesIO(f.read())
    rep, code = v2.verify(mine, trust, memo=memo)
    if code:
        return {}, rep, code
    out, files = {}, v2.read_zip(mine)
    for parts in run_files(files).values():
        recs = [r for n in parts for r in v2._jsonl(files[n])]
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
    """tool_call_id -> {"decision", "result": records, "approval": {decision, approver, self_approved}}; an approval
    that expired, was abandoned or revoked before anyone answered it is that decision ("expired", ...)."""
    calls: Dict[str, Dict[str, Any]] = {}
    asked: Dict[str, str] = {}   # approval id -> its call (a later approval record may not name the call)
    for r in recs:
        t, d = r["event"]["type"], r["event"]["data"]
        if t == "policy.decision":
            calls[d["tool_use_id"]] = {"decision": r}   # a later attempt replaces an earlier one
        elif t == "tool.result" and d["tool_use_id"] in calls:
            calls[d["tool_use_id"]]["result"] = r
        elif t == "approval" and d.get("tool_use_id") in calls:
            calls[d["tool_use_id"]]["approval"] = {k: d.get(k) for k in ("decision", "approver", "self_approved")}
        elif t == "approval.request":
            asked[d.get("approval_id")] = (d.get("binding") or {}).get("tool_call_id")
        elif t in ("approval.expired", "approval.abandoned", "approval.revoked"):
            call = calls.get(r["event"].get("tool_call_id") or asked.get(d.get("approval_id")))
            if call is not None and (call.get("approval") or {}).get("decision") in (None, "approve"):
                call["approval"] = {"decision": t.split(".")[1], "approver": None, "self_approved": False}
    return calls


def _policy(call: Dict[str, Any], reasons: Dict[str, Dict[str, Dict[str, str]]]) -> Dict[str, Any]:
    d = call["decision"]["event"]["data"]
    known = reasons.get(d["policy_hash"], {})
    p = {"decision": d["decision"], "rule_ids": d["rule_ids"], "policy_hash": d["policy_hash"],
         "reasons": [known.get(i, {}).get("reason", "") for i in d["rule_ids"]]}
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


def _target(out_dir: str, run_id: str, tenant: str = "") -> str:
    """The folder of the why run of `run_id` of `tenant`: readable, and unique however the id is spelled (the readable
    part is cut and sanitized; the hash covers the tenant and the whole id)."""
    tag = hashlib.sha256(f"{tenant}\0{run_id}".encode()).hexdigest()[:16]
    return os.path.join(out_dir, "tk-" + "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:80] + "-" + tag)


class _Writer:
    """A new why run under out_dir: hash-chained events and content-addressed blobs."""

    def __init__(self, out_dir: str, run_id: str, tenant: str = ""):
        self.path = _target(out_dir, run_id, tenant)
        self.run_id = os.path.basename(self.path)
        if os.path.exists(os.path.join(self.path, "events.jsonl")):
            raise FileExistsError(f"{self.path} already exists; remove it to re-import")
        os.makedirs(os.path.join(self.path, "blobs"), exist_ok=True)
        self.events: List[Dict[str, Any]] = []

    def blob(self, v: Any) -> str:
        ref = content_hash(v)
        with open(os.path.join(self.path, "blobs", ref[7:] + ".json"), "w", encoding="utf-8") as f:
            json.dump({"v": v}, f, sort_keys=True, ensure_ascii=False, default=str)
        return ref

    def emit(self, agent: str, etype: str, ts: str, rec: Optional[Dict[str, Any]] = None,
             also: Optional[Dict[str, Any]] = None, **body: Any):
        # an imported event's id is its run's, seq and type: the same on every import of a growing run
        eid = body.pop("id", None) or hashlib.sha256(f"{self.run_id}|{len(self.events)}|{etype}".encode()).hexdigest()[:32]
        ev = {"schema": SCHEMA, "seq": len(self.events), "id": eid,
              "prev_hash": self.events[-1]["hash"] if self.events else GENESIS, "ts": ts, "run_id": self.run_id,
              "agent": agent, "type": etype, **body}
        if rec is not None:
            ev["tracekit"] = {**cite(rec), **(also or {})}
        ev["hash"] = event_hash(ev)
        self.events.append(ev)
        return ev

    def close(self) -> str:
        with open(os.path.join(self.path, "events.jsonl"), "w", encoding="utf-8") as f:
            for ev in self.events:
                f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
        return self.path


# --------------------------------------------------------------------------- one v2 run

def convert(recs: List[Dict[str, Any]], out_dir: str, reasons: Dict[str, Dict[str, Dict[str, str]]]) -> str:
    first = recs[0]["event"]
    w = _Writer(out_dir, first["run_id"], first["tenant"])
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
    final = recs[-1]["event"]["type"] == "run.final"   # an open run's newest calls may still be running
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
        # a model call: an exchange with a response (a transcript's prompt line is a request alone, no model call;
        # the prompt itself is the run's observed input)
        elif t == "model.exchange" and exchanges[d["exchange_id"]][0] is r and \
                any(x["event"]["data"].get("phase") != "request" for x in exchanges[d["exchange_id"]]):
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
            # a call allowed (or approved) that has no result may have run: the signer recorded no outcome
            refused = dd["decision"] == "deny" or (dd["decision"] == "ask"
                                                   and (call.get("approval") or {}).get("decision") != "approve")
            if not (ran or refused or final):   # still running, or its result not yet recorded: shown once it is
                continue
            res = {"content": COMMITTED, **d["output"]} if ran else _blocked(pol) if refused else {"error": NO_OUTCOME}
            extra = {} if ran or not refused else {"guard": {"verdict": "block", "alerts": [],
                                                             "reason": "Tracekit policy " + ", ".join(dd["rule_ids"])}}
            ev = w.emit(agent, "action", e["ts"], r, {"tool_call_id": d["tool_use_id"],
                                                      **({"decision": cite(call["decision"])} if ran else {})},
                        tool=dd["tool"], args_ref=w.blob({"content": COMMITTED, "commitment": dd.get("args_commitment")}),
                        result_ref=w.blob(res), decision=decision_of.get(d["tool_use_id"]),
                        status=("ok" if d["ok"] else "error") if ran else "blocked" if refused else "error",
                        mode="live" if ran else "blocked" if refused else "unrecorded",
                        sensitive=dd["decision"] in ("deny", "ask") or bool(dd.get("provenance")), duration_ms=None,
                        policy=pol, provenance=_provenance(call, lambda _, seq: by_seq.get(seq)), **extra)
        elif t == "run.final":
            w.emit("run", "run.end", e["ts"], r, outcome=None)
        if ev is not None:
            by_seq[e["run_seq"]] = ev["id"]
    return w.close()


# --------------------------------------------------------------------------- a why log against its records

_CITING = ("agent.start", "input", "decision", "action", "message")   # the events the runtime gives a citation


def _agent(recs: List[Dict[str, Any]]) -> str:
    first = recs[0]["event"] if recs else {}
    return ((first.get("data") or {}).get("agent") or {}).get("name") or "main" \
        if first.get("type") == "run.registered" else "main"


def _is_task(ev: Dict[str, Any]) -> bool:
    """The run's task: one why event, observed in each agent's run as that run registers."""
    return ev["type"] == "input" and ev["agent"] == "run" and ev.get("kind") == "task"


def _task_rec(r: Dict[str, Any]) -> bool:
    d = r["event"]["data"]
    return r["event"]["type"] == "input.observed" and d["source"] == "task" and d["trust"] == "trusted"


def _owed(recs: List[Dict[str, Any]], has_task: bool):
    """The records of a cited run that some why event must cite: every decision, result and observed input (the
    task's go to the log's task event), and the request of every model call the runtime made (a gateway's are its own)."""
    exchanges = set()
    for r in recs:
        t, d = r["event"]["type"], r["event"]["data"]
        if t in ("policy.decision", "tool.result") or (t == "input.observed" and not (has_task and _task_rec(r))):
            yield r
        elif t == "model.exchange" and d.get("upstream") == "tracekit-why" and d["exchange_id"] not in exchanges:
            exchanges.add(d["exchange_id"])
            yield r


def _same(t: Dict[str, Any], rec: Dict[str, Any]) -> Optional[str]:
    """Which field an imported citation `t` gives otherwise than record `rec`, or None."""
    c = cite(rec)
    return next((k for k in ("log_id", "seq", "hash", "commitment") if k in t and t[k] != c.get(k)), None)


def _mismatch(ev: Dict[str, Any], t: Dict[str, Any], index: Dict[tuple, Dict[str, Any]],
              calls: Dict[str, Dict[str, Any]], agent: Optional[str], results: set) -> Optional[str]:
    """Why the record `t` cites does not back event `ev`, or None. `results`: (run, tool call) of every cited result."""
    rec = index.get((t["run_id"], t["run_seq"]))
    if rec is None:
        return f"no record {t['run_seq']} in Tracekit run {t['run_id']}"
    e, d = rec["event"], rec["event"]["data"]
    if e["type"] != t["type"]:
        return f"record {t['run_seq']} is a {e['type']}, not a {t['type']}"
    if _same(t, rec):
        return f"its {_same(t, rec)} is not the record's"
    owner = ev.get("to") if ev["type"] == "message" else ev["agent"]   # a message is observed in the recipient's run
    if ev["type"] not in ("run.start", "run.end") and agent != owner:
        return f"run {t['run_id']} is agent {agent!r}'s, not {owner!r}'s"
    if ev["type"] == "agent.start" and (d.get("agent") or {}).get("name") != ev["agent"]:
        return f"the run was registered for agent {(d.get('agent') or {}).get('name')!r}"
    if ev["type"] in ("input", "message") and d["trust"] != ev["trust"]:
        return f"the record says {d['trust']}, the log {ev['trust']}"
    if ev["type"] == "input" and d["source"] != ev["source"][:256]:
        return f"the record's source is {d['source']!r}"
    if ev["type"] == "decision" and d["model"] != ev["model"][:128]:
        return f"the record's model is {d['model']!r}"
    if ev["type"] == "action":
        tcid = t.get("tool_call_id") or ""
        call = calls.get(tcid)
        if call is None or d.get("tool_use_id") != tcid:
            return f"the record is not about tool call {tcid}"
        if call["decision"]["event"]["data"]["tool"] != ev["tool"]:
            return f"the record's tool is {call['decision']['event']['data']['tool']!r}"
        if e["type"] == "tool.result":
            dc = t.get("decision") or {}
            if ev["status"] == "blocked":
                return "the record says the call ran"
            if (dc.get("run_id"), dc.get("run_seq")) != (t["run_id"], call["decision"]["event"]["run_seq"]):
                return "it does not cite the decision the call ran under"
            if _same(dc, call["decision"]):
                return f"its decision's {_same(dc, call['decision'])} is not the record's"
            if "error" in t and d["ok"]:
                return "the record says the call succeeded"
        elif ev["status"] != "blocked":
            return "the record says the call ran, and the log cites only its decision" if "result" in call \
                else "the signer recorded no outcome of the call"
        elif "result" in call and (t["run_id"], tcid) not in results:
            return "the record says the call ran"
    return None


def check(run: Run, records: Dict[str, List[Dict[str, Any]]]):
    """The why log `run` against the signed records of the runs it cites: (problem per event index, alerts on the log
    as a whole, the citations of the task's records). Each event's citation must match its record, belong to the
    agent the event is about and be cited once (a call held again, under the same tool call, cites its decision
    each time); an event the runtime cites must cite; every decision, result, observed input and model call of a
    cited run must be cited, so a log that drops one is caught."""
    index = {(r["event"]["run_id"], r["event"]["run_seq"]): r for recs in records.values() for r in recs}
    calls = {rid: _calls(recs) for rid, recs in records.items()}
    cited = sorted({ev["tracekit"]["run_id"] for ev in run.events if ev.get("tracekit")})
    has_task = any(_is_task(ev) for ev in run.events)
    task = [cite(r) for rid in cited for r in records.get(rid, []) if _task_rec(r)] if has_task else []
    gateway = any(r["event"]["type"] == "model.exchange" and r["event"]["data"].get("upstream") != "tracekit-why"
                  for rid in cited for r in records.get(rid, []))
    results = {(ev["tracekit"]["run_id"], ev["tracekit"].get("tool_call_id")) for ev in run.events
               if (ev.get("tracekit") or {}).get("type") == "tool.result"}
    # the merged log is chained anew: a break in the original's chain must not vanish with it
    alerts = [{"title": "The why log failed its integrity check", "detail": p}
              for p in [p for p in verify(run) if not p.startswith(UNFINISHED)][:5]]
    alerts += [{"title": "A Tracekit run this log cites is not in the import",
                "detail": f"run {rid}: import the store or bundle that holds it"} for rid in cited if rid not in records]
    problems: Dict[int, str] = {}
    citers: Dict[tuple, List[int]] = {}
    for i, ev in enumerate(run.events):
        t = ev.get("tracekit")
        if "tracekit_task" in ev and ev["tracekit_task"] != task:
            problems[i] = "its citations are not the task's records"
        if not t:
            # lean: a decision is excused when a gateway recorded the run's model calls; match them by digest if needed
            if ev["type"] in _CITING and not _is_task(ev) and not (ev["type"] == "decision" and gateway):
                problems[i] = "it cites no signed record"
            continue
        for c in [t] + ([t["decision"]] if isinstance(t.get("decision"), dict) else []):
            citers.setdefault((c.get("run_id"), c.get("run_seq")), []).append(i)
        problem = _mismatch(ev, t, index, calls.get(t["run_id"], {}), _agent(records.get(t["run_id"], [])), results)
        if problem:
            problems[i] = problem
    for (rid, seq), idx in citers.items():
        evs = [run.events[i] for i in idx]
        retried = all(e["type"] == "action" for e in evs) and len({e["tracekit"].get("tool_call_id") for e in evs}) == 1 \
            and sum(e["status"] != "blocked" for e in evs) <= 1
        if len(idx) > 1 and not retried:
            for i in idx:
                problems.setdefault(i, f"record {seq} of run {rid} is cited by {len(idx)} events")
    for rid in cited:
        for r in _owed(records.get(rid, []), has_task):
            e, d = r["event"], r["event"]["data"]
            if (rid, e["run_seq"]) not in citers:
                what = d.get("tool") or d.get("source") or d.get("model") or d.get("tool_use_id", "")
                alerts.append({"title": "A signed record no event of the why log cites",
                               "detail": f"{e['type']} {what} (run {rid} record {e['run_seq']}, log seq {e['seq']}): "
                                         "the why log leaves it out"})
    for i, p in sorted(problems.items()):
        ev = run.events[i]
        alerts.append({"title": f"{ev['type']} #{i} " + ("does not match the signed record it cites" if ev.get("tracekit")
                                                         else "cites no signed record"),
                       "detail": p + (f" (run {ev['tracekit']['run_id']} record {ev['tracekit']['run_seq']})"
                                      if ev.get("tracekit") else "")})
    return problems, alerts, task


def merge(run: Run, records: Dict[str, List[Dict[str, Any]]], out_dir: str,
          reasons: Dict[str, Dict[str, Dict[str, str]]]) -> str:
    """The why log `run` with each citation checked against `records` and the signed verdicts filled in."""
    problems, alerts, task = check(run, records)
    w = _Writer(out_dir, run.run_id)
    index = {(r["event"]["run_id"], r["event"]["run_seq"]): r for recs in records.values() for r in recs}
    calls = {rid: _calls(recs) for rid, recs in records.items()}
    event_of = {(ev["tracekit"]["run_id"], ev["tracekit"]["run_seq"]): ev["id"]
                for ev in run.events if ev.get("tracekit")}
    cited = sorted({ev["tracekit"]["run_id"] for ev in run.events if ev.get("tracekit")})
    alerts = [a for rid in cited for a in _evidence(records.get(rid, []))] + alerts
    out = []
    for i, ev in enumerate(run.events):
        ev = {k: v for k, v in ev.items() if k not in ("schema", "seq", "prev_hash", "hash", "run_id")}
        t = ev.get("tracekit")
        if i in problems:
            ev["tracekit_mismatch"] = problems[i]
        elif t:
            rec = index[(t["run_id"], t["run_seq"])]
            ev["tracekit"] = {**cite(rec), **{k: t[k] for k in ("tool_call_id", "error") if k in t}}
            if ev["type"] == "action":
                call = calls[t["run_id"]][t["tool_call_id"]]
                if rec["event"]["type"] == "tool.result":
                    ev["tracekit"]["decision"] = cite(call["decision"])
                ev["policy"] = _policy(call, reasons)
                ev["provenance"] = _provenance(call, lambda rid, seq: event_of.get((rid, seq)))
        if _is_task(ev) and task:
            ev["tracekit_task"] = task
        out.append(ev)
    for v in run.blobs.values():
        w.blob(v)
    for ev in out:
        if ev["type"] == "run.start":
            ev["meta"] = {**(ev.get("meta") or {}), "source": "tracekit", "tracekit_runs": cited,
                          "merged_from": run.path, "evidence_alerts": alerts}
        w.emit(ev.pop("agent"), ev.pop("type"), ev.pop("ts"), **ev)
    return w.close()


def _plan(records: Dict[str, List[Dict[str, Any]]], out_dir: str):
    """(why logs to merge, runs to convert, imports already under out_dir that cite these records)."""
    merge_, rechecks, merged = [], [], set()
    for p in list_runs(out_dir) if os.path.isdir(out_dir) else []:
        run = load_run(p)
        cites = {ev["tracekit"]["run_id"] for ev in run.events if ev.get("tracekit")}
        if not cites & records.keys():
            continue
        if (run.start.get("meta") or {}).get("source") == "tracekit":
            rechecks.append(run)
        else:
            merge_.append(run)
            merged |= cites
    return merge_, [recs for rid, recs in records.items() if rid not in merged], rechecks


def recheck(records: Dict[str, List[Dict[str, Any]]], out_dir: str) -> List[tuple]:
    """(path, alerts) of each earlier import under out_dir (a log that says it is one) that cites these records,
    checked against them as a merge would: its citations are not taken on its word."""
    return [(run.path, a) for run in _plan(records, out_dir)[2] if (a := check(run, records)[1])]


def import_records(records: Dict[str, List[Dict[str, Any]]], out_dir: str,
                   reasons: Optional[Dict[str, Dict[str, Dict[str, str]]]] = None) -> List[str]:
    """Merge every why log under out_dir that cites one of these runs; convert the others. Returns the run paths.
    Writes nothing when a run it would write exists (FileExistsError). `reasons`: view.policy_reasons(), computed here
    when not given (it compiles every shipped pack)."""
    if reasons is None:
        from ..view import policy_reasons
        reasons = policy_reasons()
    merge_, convert_, _ = _plan(records, out_dir)
    targets = [_target(out_dir, r.run_id) for r in merge_] + [_target(out_dir, recs[0]["event"]["run_id"],
                                                                       recs[0]["event"]["tenant"]) for recs in convert_]
    there = [t for t in targets if os.path.exists(os.path.join(t, "events.jsonl"))]
    if there:
        raise FileExistsError(f"{', '.join(there)} already exist{'s' if len(there) == 1 else ''}: remove "
                              f"{'it' if len(there) == 1 else 'them'} to re-import; nothing imported")
    os.makedirs(out_dir, exist_ok=True)
    return [merge(run, records, out_dir, reasons) for run in merge_] + [convert(recs, out_dir, reasons)
                                                                        for recs in convert_]


# --------------------------------------------------------------------------- content vs commitments

def _commitments(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The citations of event `ev` that hold a commitment: its record's, an executed call's decision's (its
    arguments) and the task's records."""
    t = ev.get("tracekit") or {}
    out = [t] + ([t["decision"]] if isinstance(t.get("decision"), dict) else []) + list(ev.get("tracekit_task") or [])
    return [c for c in out if "commitment" in c]


def _digest(ev: Dict[str, Any], t: Dict[str, Any], run: Run) -> str:
    """The digest the signer committed to in the record `t` of event `ev`, recomputed from the why log's content."""
    if t["type"] == "input.observed":
        return jcs_hash(privacy.redact(run.value(ev["ref"]))[0])
    args = run.value(ev.get("args_ref"))
    if t["type"] == "tool.result":
        dotenv = isinstance(args, dict) and privacy.mentions_dotenv(*(args.get(k) for k in privacy.ACTION_FIELDS))
        sent = {"error": t["error"]} if "error" in t else {"result": run.value(ev["result_ref"])}
        return jcs_hash(privacy.redact(sent, dotenv)[0])
    if t["type"] == "policy.decision":
        return jcs_hash({"tool": ev["tool"], "args": args})
    return jcs_hash([run.value(c["ref"]) for c in ev["context"]])   # model.exchange: the exact context


def _salts(rows: List[Any]) -> Dict[int, Dict[str, Any]]:
    """log seq -> row of `tracekit signer reveal` rows; ValueError on a row that is not one."""
    out = {}
    for n, r in enumerate(rows, 1):
        if not (isinstance(r, dict) and type(r.get("seq")) is int and isinstance(r.get("type"), str)
                and isinstance(r.get("salt"), str) and re.fullmatch("[0-9a-f]{64}", r["salt"])):
            raise ValueError(f"salt row {n} is not a `tracekit signer reveal` line "
                             '({"seq": int, "type": record type, "salt": 64 hex digits})')
        out[r["seq"]] = r
    return out


def check_content(run: Run, salts: List[Any]) -> List[Dict[str, Any]]:
    """For each citation of a record with a commitment: matched, mismatched (content or salt does not match), not
    revealed (no salt for its record) or bad salt row (the row is for another type of record). Written to the run's
    content-check.json, where a mismatch becomes a high evidence alert. ValueError on a malformed row."""
    salt = _salts(salts)
    out = []
    for ev in run.events:
        for t in _commitments(ev):
            r = {"event": ev["id"], "seq": t["seq"], "type": t["type"], "agent": ev["agent"], "kind": ev["type"]}
            row = salt.get(t["seq"])
            if row is None:
                r["verdict"] = "not revealed"
            elif row["type"] != t["type"]:
                r["verdict"], r["detail"] = "bad salt row", f"the row is for a {row['type']} record"
            else:
                try:
                    digest = _digest(ev, t, run)
                except ValueError as e:   # content JCS can't encode: it cannot be what the signer committed to
                    digest, r["detail"] = "", str(e)
                mac = hmac.new(bytes.fromhex(row["salt"]), digest.encode(), "sha256").hexdigest()
                r["verdict"] = "matched" if digest and hmac.compare_digest(t["commitment"], "hmac-sha256:" + mac) \
                    else "mismatched"
                if r["verdict"] == "mismatched":
                    r.setdefault("detail", "content or salt does not match")
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
