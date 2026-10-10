"""v1 Tracekit ledger -> why run.

Tracekit (https://github.com/Cygnux-Labs/Tracekit) proves *what* an agent did: events signed by a
separate signer, hash-chained and witnessed. This importer turns one Tracekit run into a why run so
the investigation app can say *why*: alerts, lineage across agents, candidate causes, and decision-level
tests on model calls whose request was captured. Every why event cites the signed Tracekit
records it came from (tracekit-map.json), so a causal claim points at evidence nobody could quietly alter.

    tracekit why import --v1 ~/.tracekit --run <session id> --out runs --sensitive send_email

Mapping
    user.prompt                       input (kind=task, trusted)
    model.exchange request+response   decision; context rebuilt block by block from the recorded request
                                      ("exact"), or from what the agent had seen so far when the request
                                      was hashed ("reconstructed")
    tool.call + tool.result           action, linked to the decision whose response asked for it
    result of an untrusted tool       also an untrusted input (source tool:<name>), as the adapters do
    Agent/Task tool (subagents)       messages parent->child (the task) and child->parent (the answer)
    policy deny / ask not approved    action with status "blocked" and Tracekit's rule ids
    policy flag / ask                 action marked sensitive
    capture.gap / trace.tamper        high "evidence" alerts on the run

What tracekit why needs from Tracekit: `content_capture: full` (at least for untrusted tools) so values can
be traced, and model calls recorded (autotrace, the SDK, or the model proxy) so there are decisions.
With hashed content the run still imports, but argument provenance reports "hashed" instead of a source.
"""
from __future__ import annotations

import fnmatch
import json
import os
import secrets
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..observe import verify_ledger
from .core import GENESIS, SCHEMA, content_hash, event_hash

SUBAGENT_TOOLS = ("Agent", "Task")


def ledger_path(src: str) -> str:
    """A Tracekit home (…/ledger/ledger.jsonl inside it), a ledger directory, or the ledger file."""
    for p in (os.path.join(src, "ledger", "ledger.jsonl"), os.path.join(src, "ledger.jsonl"), src):
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(f"no Tracekit ledger at {src}")


def read_ledger(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # torn line; verify_signatures reports it
            if isinstance(rec, dict) and isinstance(rec.get("event"), dict) and not rec.get("elided"):
                out.append(rec)
    return out


def verify_signatures(path: str) -> Tuple[bool, List[str]]:
    """Chain and Ed25519 signatures of the v1 ledger (tracekit.observe.verify_ledger)."""
    _, problems, _ = verify_ledger(path)
    return (not problems), list(problems)


def runs_in(records: Iterable[Dict[str, Any]]) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for r in records:
        rid = r["event"].get("run_id")
        if rid and not str(rid).startswith(("findings:", "anchors:")):
            counts[rid] = counts.get(rid, 0) + 1
    return sorted(counts.items())


def _clear(content: Any) -> Tuple[Any, bool]:
    """(value, captured in clear?) from a Tracekit content object."""
    if isinstance(content, dict) and "value" in content:
        return content["value"], True
    if isinstance(content, dict) and "hash" in content:
        return {"tracekit_hash": content["hash"], "size": content.get("size")}, False
    return content, content is not None


def convert(records: Sequence[Dict[str, Any]], run_id: str, out_dir: str, *,
            untrusted_tools: Sequence[str] = ("*",), trusted_tools: Sequence[str] = SUBAGENT_TOOLS,
            sensitive_tools: Sequence[str] = (), signatures: Tuple[Optional[bool], List[str]] = (None, []),
            ledger: str = "") -> str:
    """Write the why run for Tracekit run `run_id` under out_dir; returns its path.
    untrusted_tools: globs of tools whose results are outside content (default: all but subagents)."""
    recs = [r for r in records if r["event"].get("run_id") == run_id]
    if not recs:
        raise ValueError(f"no Tracekit run {run_id!r} in the ledger")
    rid = "tk-" + "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:100]
    path = os.path.join(out_dir, rid)
    if os.path.exists(os.path.join(path, "events.jsonl")):
        raise FileExistsError(f"{path} already exists; remove it to re-import")
    os.makedirs(os.path.join(path, "blobs"), exist_ok=True)
    events: List[Dict[str, Any]] = []
    blobs: Dict[str, Any] = {}
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    prev = [GENESIS]

    def blob(v: Any) -> str:
        ref = content_hash(v)
        if ref not in blobs:
            blobs[ref] = v
            with open(os.path.join(path, "blobs", ref[7:] + ".json"), "w", encoding="utf-8") as f:
                json.dump({"v": v}, f, sort_keys=True, ensure_ascii=False, default=str)
        return ref

    def emit(agent: str, etype: str, src: Optional[Dict[str, Any]], **body: Any) -> Dict[str, Any]:
        ev = {"schema": SCHEMA, "seq": len(events), "id": secrets.token_hex(16), "prev_hash": prev[0],
              "ts": (src or recs[0])["event"]["ts"], "run_id": rid, "agent": agent, "type": etype}
        ev.update(body)
        ev["hash"] = event_hash(ev)
        prev[0] = ev["hash"]
        events.append(ev)
        if src:
            mapping.setdefault(ev["id"], []).append(_cite(src))
        return ev

    def untrusted(tool: str) -> bool:
        return any(fnmatch.fnmatch(tool, p) for p in untrusted_tools) and \
            not any(fnmatch.fnmatch(tool, p) for p in trusted_tools)

    kind_of = lambda r: r["event"]["type"]
    data = lambda r: r["event"].get("data") or {}
    start = next((r for r in recs if kind_of(r) == "run.start"), recs[0])
    sd = data(start)
    head = records[-1]
    calls = {data(r)["tool_use_id"]: r for r in recs if kind_of(r) == "tool.call" and data(r).get("tool_use_id")}
    policy = {data(r)["tool_use_id"]: r for r in recs if kind_of(r) == "policy.decision" and data(r).get("tool_use_id")}
    results = {data(r).get("tool_use_id") for r in recs if kind_of(r) == "tool.result"}
    approvals = {data(r).get("tool_use_id"): data(r).get("decision") for r in recs if kind_of(r) == "approval"}
    flagged = {t for t, p in policy.items() if data(p).get("decision") in ("flag", "ask")}

    evidence: List[Dict[str, Any]] = []
    for r in recs:
        if kind_of(r) == "capture.gap":
            evidence.append({"title": "Tracekit reported a capture gap: events may be missing",
                             "detail": f"{data(r).get('reason', '')} ({data(r).get('missed_events', '?')} events, "
                                       f"Tracekit seq {r['event']['seq']})"})
        elif kind_of(r) == "trace.tamper":
            evidence.append({"title": "Tracekit detected tampering with the agent's own transcript",
                             "detail": f"{data(r).get('kind', '')} {data(r).get('path', '')} (Tracekit seq {r['event']['seq']})"})
    ok, problems = signatures
    if ok is False:
        evidence.append({"title": "Tracekit ledger failed signature or chain verification", "detail": problems[0]})

    sensitive = set(sensitive_tools)
    emit("run", "run.start", start, program="", seed=0, interventions=[],
         models=sorted({data(r).get("model") for r in recs if kind_of(r) == "model.exchange"} - {None}),
         tools=sorted({data(r).get("name") for r in calls.values()} - {None}),
         sensitive_tools=sorted(sensitive), untrusted_tools=list(untrusted_tools),
         meta={"source": "tracekit", "tracekit_run": run_id, "ledger": ledger,
               "agent": (sd.get("agent") or {}).get("name"), "content_capture": sd.get("content_capture"),
               "ledger_head": {"seq": head["event"]["seq"], "hash": head["hash"]}, "kid": head.get("kid"),
               "signatures": {"verified": ok, "problems": problems[:5]}, "evidence_alerts": evidence})

    by_content: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (agent, ref or "tr:"+tool_use_id) -> context item
    seen_agents: set = set()
    pending_req: Dict[str, Dict[str, Any]] = {}
    seen_so_far: Dict[str, List[Dict[str, Any]]] = {}       # agent -> context items, for hashed requests
    decision_for_tool: Dict[str, str] = {}
    child_of_call: Dict[str, str] = {}
    last_decision: Dict[str, Dict[str, Any]] = {}
    child_final: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = {}
    tainted: Dict[str, str] = {}                            # agent -> "untrusted" once it saw untrusted content

    def item(agent: str, value: Any, kind: str, source: str, trust: str, ev_id: str) -> Dict[str, Any]:
        it = {"ref": blob(value), "kind": kind, "source": source, "trust": trust, "from_event": ev_id}
        by_content[(agent, it["ref"])] = it
        seen_so_far.setdefault(agent, []).append(it)
        return it

    def ensure_agent(e: Dict[str, Any], rec: Dict[str, Any]) -> str:
        a = e.get("agent_id") or "main"
        if a not in seen_agents:
            seen_agents.add(a)
            emit(a, "agent.start", rec, parent=e.get("parent_id"), role="")
        return a

    def request_items(agent: str, msgs: List[Any], rec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """One context item per block of an Anthropic-style request, linked to the event that produced it."""
        out = []
        for i, m in enumerate(msgs):
            if not isinstance(m, dict):
                continue
            content = m.get("content")
            blocks = [{"type": "text", "text": content}] if isinstance(content, str) else (content or [])
            for j, b in enumerate(blocks):
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_result" and (agent, "tr:" + str(b.get("tool_use_id"))) in by_content:
                    out.append(by_content[(agent, "tr:" + str(b["tool_use_id"]))])
                    continue
                if b.get("type") == "tool_use" and b.get("id") in decision_for_tool:
                    out.append({"ref": blob(b), "kind": "output", "source": "assistant",
                                "trust": tainted.get(agent, "trusted"), "from_event": decision_for_tool[b["id"]]})
                    continue
                text = b.get("text") if b.get("type") == "text" else None
                hit = by_content.get((agent, content_hash(text))) if text is not None else None
                if hit:
                    out.append(hit)
                    continue
                # the parent pasted a subagent's answer into its own prompt: link it to that message
                fin = next(((mev, t) for mev, t in child_final.values() if text and t and t in text), None)
                if fin:
                    out.append({"ref": fin[0]["ref"], "kind": "message", "source": f"{fin[0]['agent']}->{agent}",
                                "trust": fin[0]["trust"], "from_event": fin[0]["id"]})
                    continue
                trust = "trusted" if m.get("role") in ("user", "assistant", "system") else "untrusted"
                ev = emit(agent, "input", rec, ref=blob(b), source=f"{m.get('role')}#{i}.{j}", trust=trust, kind="input")
                out.append(item(agent, b, "input", ev["source"], trust, ev["id"]))
        return out

    for r in recs:
        e, d, t = r["event"], data(r), kind_of(r)
        if t in ("run.start", "run.end", "policy.decision", "checkpoint", "approval", "capture.gap", "trace.tamper"):
            continue
        if t == "tool.call" and not _is_spawn(d):
            continue
        agent = ensure_agent(e, r)
        if t == "user.prompt":
            v, _ = _clear(d.get("content"))
            ev = emit(agent, "input", r, ref=blob(v), source="user", trust="trusted", kind="task")
            item(agent, v, "task", "user", "trusted", ev["id"])
        elif t == "tool.call":  # a subagent spawn
            inp = d.get("input") or {}
            child = _clear(inp.get("child_agent_id"))[0]
            if not isinstance(child, str) or not child:  # hashed or missing: still a distinct agent
                child = f"{agent}.sub{len(child_of_call)}"
            desc = _clear(inp.get("description") or inp.get("prompt"))[0] or ""
            child_of_call[d["tool_use_id"]] = child
            m = emit(agent, "message", r, to=child, ref=blob(desc), decision=decision_for_tool.get(d["tool_use_id"]),
                     trust=tainted.get(agent, "trusted"))
            it = {"ref": m["ref"], "kind": "message", "source": f"{agent}->{child}", "trust": m["trust"],
                  "from_event": m["id"]}
            by_content[(child, m["ref"])] = it
            if isinstance(desc, str):
                by_content[(child, content_hash(desc))] = it
            seen_so_far.setdefault(child, []).append(it)
        elif t == "model.exchange" and d.get("phase") == "request":
            pending_req[d.get("exchange_id")] = r
        elif t == "model.exchange" and d.get("phase") == "response":
            req = pending_req.pop(d.get("exchange_id"), None)
            body, exact = _clear(data(req).get("request")) if req else (None, False)
            if exact and isinstance(body, dict) and isinstance(body.get("messages"), list):
                ctx, mode = request_items(agent, body["messages"], req), "exact"
            else:
                ctx, mode = list(seen_so_far.get(agent, [])), "reconstructed"
            out, _ = _clear(d.get("response"))
            dec = emit(agent, "decision", r, model=d.get("model"), purpose="", params={}, seed=None, context=ctx,
                       ablated=[], output=blob(out if out is not None else {"stop_reason": d.get("stop_reason")}),
                       usage=d.get("usage") or {}, status="error" if d.get("error") else "ok",
                       duration_ms=d.get("duration_ms"), context_mode=mode)
            if req:
                mapping[dec["id"]].insert(0, _cite(req))
            if any(c["trust"] == "untrusted" for c in ctx):
                tainted[agent] = "untrusted"
            for tu in d.get("tool_uses") or []:
                if isinstance(tu, dict) and tu.get("id"):
                    decision_for_tool[tu["id"]] = dec["id"]
            last_decision[agent] = dec
        elif t == "tool.result":
            call = calls.get(d.get("tool_use_id"))
            if call is None:
                continue
            name = data(call).get("name", "?")
            args = {k: _clear(v)[0] for k, v in (data(call).get("input") or {}).items()}
            res, _ = _clear(d.get("output"))
            pol = policy.get(d["tool_use_id"])
            spawn = _is_spawn(data(call))
            extra = {}
            if spawn and tainted.get(child_of_call.get(d["tool_use_id"], "")) == "untrusted":
                extra["trust"] = "untrusted"  # the subagent's answer carries what it read
            act = emit(agent, "action", r, tool=name, args_ref=blob(args), result_ref=blob(res),
                       decision=decision_for_tool.get(d["tool_use_id"]), status="ok" if d.get("ok", True) else "error",
                       mode="live", sensitive=name in sensitive or d["tool_use_id"] in flagged,
                       duration_ms=d.get("duration_ms"), policy=_policy(pol), **extra)
            mapping[act["id"]].insert(0, _cite(call))
            if pol:
                mapping[act["id"]].append(_cite(pol))
            if spawn:
                child = child_of_call.get(d["tool_use_id"], "")
                final = res.get("final", res) if isinstance(res, dict) else res
                src = last_decision.get(child)
                m = emit(child, "message", r, to=agent, ref=blob(final), decision=src and src["id"],
                         trust=tainted.get(child, "trusted"))
                child_final[child] = (m, final if isinstance(final, str) else None)
                it = {"ref": m["ref"], "kind": "message", "source": f"{child}->{agent}", "trust": m["trust"],
                      "from_event": m["id"]}
                by_content[(agent, "tr:" + d["tool_use_id"])] = it
                seen_so_far.setdefault(agent, []).append(it)
            elif untrusted(name):
                inp = emit(agent, "input", r, ref=blob(res), source=f"tool:{name}", trust="untrusted", kind="input")
                it = item(agent, res, "input", f"tool:{name}", "untrusted", inp["id"])
                by_content[(agent, "tr:" + d["tool_use_id"])] = it
            else:
                by_content[(agent, "tr:" + d["tool_use_id"])] = item(agent, res, "result", name, "trusted", act["id"])
    # calls that never ran: denied by policy, or held for approval and not approved
    for tid, call in calls.items():
        if tid in results:
            continue
        pol = policy.get(tid)
        pd = data(pol) if pol else {}
        e = call["event"]
        agent = ensure_agent(e, call)
        args = {k: _clear(v)[0] for k, v in (data(call).get("input") or {}).items()}
        act = emit(agent, "action", call, tool=data(call).get("name", "?"), args_ref=blob(args),
                   result_ref=blob({"error": "blocked by Tracekit policy", "decision": pd.get("decision"),
                                    "rule_ids": pd.get("rule_ids"), "reasons": pd.get("reasons"),
                                    "approval": approvals.get(tid)}),
                   decision=decision_for_tool.get(tid), status="blocked", mode="blocked", sensitive=True,
                   duration_ms=None, policy=_policy(pol),
                   guard={"verdict": "block", "reason": "Tracekit policy " + ", ".join(pd.get("rule_ids") or []),
                          "alerts": []})
        if pol:
            mapping[act["id"]].append(_cite(pol))
    end = next((r for r in recs if kind_of(r) == "run.end"), None)
    if end:
        emit("run", "run.end", end, outcome=data(end).get("reason"))
    with open(os.path.join(path, "events.jsonl"), "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(path, "tracekit-map.json"), "w", encoding="utf-8") as f:
        json.dump({"tracekit_run": run_id, "ledger": ledger, "kid": head.get("kid"), "events": mapping}, f,
                  indent=1, sort_keys=True)
    return path


def _is_spawn(d: Dict[str, Any]) -> bool:
    return d.get("name") in SUBAGENT_TOOLS and isinstance(d.get("input"), dict) and \
        ("child_agent_id" in d["input"] or "description" in d["input"] or "prompt" in d["input"])


def _cite(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {"seq": rec["event"]["seq"], "hash": rec["hash"], "type": rec["event"]["type"]}


def _policy(rec: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not rec:
        return None
    d = rec["event"].get("data") or {}
    return {k: d.get(k) for k in ("decision", "rule_ids", "policy_hash")}


def import_ledger(src: str, out_dir: str, *, run: Optional[str] = None, **kw: Any) -> List[str]:
    """Import one run (or every run) from a Tracekit home or ledger file. Returns the run paths."""
    path = ledger_path(src)
    records = read_ledger(path)
    sig = verify_signatures(path)
    ids = [run] if run else [r for r, _ in runs_in(records)]
    return [convert(records, r, out_dir, signatures=sig, ledger=os.path.abspath(path), **kw) for r in ids]
