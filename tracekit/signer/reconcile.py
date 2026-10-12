"""Reconciliation of a run's tool calls across capture layers (04-design §6).

The single writer feeds every record of a run to `observe` as it is written (and replay feeds the log after the
snapshot), so the matcher keeps a per-run index and never reads the log again: L2 is the run's decides
(policy.decision), L3 the client-executed tool uses and the results sent back in its model.exchange records, L1 its
state.write records. When the run's grace window ends, `finish` writes the discrepancies as signed reconcile.* records
of the run, just before run.final, and returns the coverage that run.final states; final_run then drops the index.

For each L3 tool use the client runs: no decide with its id → hook_missing (written at once when a gateway request sends
its result back, so a detector sees it mid-run); raw arguments that failed strict parsing → args_unparseable; another
tool name, or (neither side coerced, both digests known) other arguments → args_mismatch. Tool uses the provider ran
itself (executed_by provider) are counted for run.final's `provider_executed`, never matched against a decide. Each
decide with neither an L3 tool use nor a provider one → fabricated; each id in tool_results_sent with neither a decide
nor an L3 tool use → result_without_call. A run with no L3 record gets none of these: its coverage says L3 is absent. The internal args
digests live in the run's `digests`, which no snapshot holds.

L3 from the LLM gateway (source gateway, tier T2) takes precedence over agent-reported L3 for the same tool use id. With
`gateway_mandatory` (signer.yaml) only gateway L3 counts, provider-run tool uses included, and a run with none still
has its decides checked: each decide the gateway did not see is fabricated, whatever the agent reported. A tool the
policy's `structured_output` names is not compared with L3 at all: its calls come in the model's structured output,
which carries no tool use id.

Decisions other systems made (policy.external, from decision_import) are indexed by tool call and system; each that
disagrees with the signer's last decision for that call (flag counts as allow), names another tool, or names a call
the signer never decided is a signed
`capture.gap{decision_mismatch}` at the same point. The signer's decision stays the one that applied.
"""

LAYERS = {"state.write": "L1", "policy.decision": "L2", "tool.result": "L2", "model.exchange": "L3"}


def new():
    return {"layers": {}, "l2": {}, "l3": {}, "sent": {}}


def _sub(put, rec, k):
    """rec[k], a dict, made on first use (an index restored from an older snapshot has none)."""
    if k not in rec:
        put(rec, k, {})
    return rec[k]


def observe(put, run, e, digests=None, handoff=lambda tool: False):
    """Index event `e` just written to `run`; `put(d, k, v)` sets d[k] (undoably on the writer). `digests`: the
    internal args digests the writer knew, by tool_call_id; none on replay, so a call that straddles a restart is
    compared by name only. Returns the discrepancies to write now, as `_found` gives them: a gateway request sending
    back the result of a gateway tool use that has no decide (and is not one of the policy's handoffs, `handoff(tool)`)
    is a hook_missing at once, not only at run.final."""
    # lean: the digests of a run's calls are lost on a restart; keep them in the sealed approvals store if runs often
    # outlive a signer restart
    rec, layer = run.get("rec"), LAYERS.get(e["type"])
    if rec is not None and e["type"] == "policy.external":
        d = e["data"]
        tcid = d["tool_use_id"]
        put(_sub(put, rec, "ext"), tcid, {**rec["ext"].get(tcid, {}), d["system"]: [d["decision"], d["tool"]]})
    if rec is not None and e["type"] == "reconcile.hook_missing":   # written live: finish does not write it again
        put(_sub(put, rec, "live"), e["tool_call_id"], True)
    if rec is None or layer is None:
        return []
    digests, now = digests or {}, []
    if layer not in rec["layers"]:
        put(rec["layers"], layer, True)
    if e["type"] == "policy.decision":
        tcid = e["tool_call_id"]
        put(rec["l2"], tcid, {"name": e["data"]["tool"], "coerced": e.get("args_source") == "coerced",
                              "decision": e["data"]["decision"]})
        put(run["digests"], "l2:" + tcid, digests.get(tcid))
    elif e["type"] == "model.exchange":
        gw = e["source"] == "gateway"
        for t in e["data"].get("tool_uses", ()):
            if t["executed_by"] == "provider":
                if gw or not rec.get("provider", {}).get(t["id"], {}).get("gw"):
                    put(_sub(put, rec, "provider"), t["id"], {"gw": gw})
            elif gw or not rec["l3"].get(t["id"], {}).get("gw"):
                put(rec["l3"], t["id"], {"name": t["name"], "coerced": t.get("args_source") == "coerced",
                                         "unparseable": t.get("args_unparseable", False), "gw": gw})
                put(run["digests"], "l3:" + t["id"], digests.get(t["id"]))
        for tcid in e["data"].get("tool_results_sent", ()):
            put(rec["sent"], tcid, True)
            u = rec["l3"].get(tcid)
            if gw and u and u["gw"] and tcid not in rec["l2"] and tcid not in rec.get("live", {}) and tcid not in {
                    x[1] for x in now} and not handoff(u["name"]):
                now.append(("hook_missing", tcid, ["L2", "L3"], f"the model asked for {u['name'][:200]}; its result "
                            "went back to the model with no decide: the call ran with no hook or adapter gating it, or "
                            "one refused it before deciding (then the result is that refusal); check the agent's hooks "
                            f"or adapter (`tracekit doctor`){_hint(u['name'])}"))
    return now


def _hint(tool):
    """What a hook_missing detail adds for a tool that looks like a handoff the policy does not name."""
    return "; if it is a handoff to another agent, name it in the policy's handoffs:" if tool.startswith(
        "transfer_to_") else ""


def counted(rec, mandatory, k="l3"):
    """The tool uses of index `k` (l3, or provider) that count: with gateway_mandatory, the gateway's only."""
    return {t: u for t, u in rec.get(k, {}).items() if u.get("gw") or not mandatory}


def _found(run, mandatory, handoff=lambda tool: False, structured=lambda tool: False):
    """[(kind, tool_call_id, layers, detail)] of the run's discrepancies; `handoff(tool)`: the policy's handoffs;
    `structured(tool)`: its structured_output, which are never compared with L3."""
    rec, digests, out, l3 = run["rec"], run["digests"], [], counted(run["rec"], mandatory)
    provider = counted(rec, mandatory, "provider")
    if "L3" not in rec["layers"] and not mandatory:
        return out
    for tcid, u in l3.items():
        d = rec["l2"].get(tcid)
        if d is None and not handoff(u["name"]) and not structured(u["name"]):
            out.append(("hook_missing", tcid, ["L2", "L3"],
                        f"the model asked for {u['name'][:200]}; no decide{_hint(u['name'])}"))
        if u["unparseable"]:
            out.append(("args_unparseable", tcid, ["L3"], "the model's raw arguments failed strict parsing"))
        if d is None:
            continue
        a, b = digests.get("l2:" + tcid), digests.get("l3:" + tcid)
        if d["name"] != u["name"]:
            out.append(("args_mismatch", tcid, ["L2", "L3"], f"decided {d['name'][:200]}, the model asked for "
                                                             f"{u['name'][:200]}"))
        elif not (u["unparseable"] or d["coerced"] or u["coerced"]) and a and b and a != b:
            out.append(("args_mismatch", tcid, ["L2", "L3"], "decided other arguments than the model asked for"))
    for tcid, d in rec["l2"].items():
        if tcid not in l3 and tcid not in provider and not structured(d["name"]):
            out.append(("fabricated", tcid, ["L2", "L3"], f"a decide for {d['name'][:200]} the model never asked for"
                        if tcid not in rec["l3"] else   # gateway_mandatory: only the agent reported the model asking
                        f"a decide for {d['name'][:200]} that no gateway exchange asked for: the agent reported the "
                        "model asking for it, from a model call that went around the gateway"))
    for tcid in rec["sent"]:
        if tcid not in rec["l2"] and tcid not in l3:
            out.append(("result_without_call", tcid, ["L2", "L3"], "a result sent to the model for a call no layer "
                                                                   "reported"))
    return out


def finish(tx, run, mandatory=False, handoff=lambda tool: False, structured=lambda tool: False):
    """Write the run's reconcile.* records; returns the coverage for its run.final (None for a run restored from a
    snapshot written before reconciliation, which has no index, for an imported run, or for a `tracekit why` replay run,
    whose model exchanges have no decisions by design). `mandatory`:
    gateway_mandatory; `handoff`, `structured`: as for _found."""
    if run.get("rec") is None:
        return None
    rec = run["rec"]
    for tcid, systems in rec.get("ext", {}).items():
        l2 = rec["l2"].get(tcid)
        mine = l2 and ("allow" if l2.get("decision") == "flag" else l2.get("decision"))
        for system, (theirs, tool) in systems.items():
            if not l2:
                reason = f"{system[:64]} decided {theirs} on {tool[:256]}; the signer decided nothing on this call"
            elif tool != l2["name"]:
                reason = f"{system[:64]} decided {theirs} on {tool[:256]}; the signer decided {mine} on {l2['name']}"
            elif theirs != mine:
                reason = f"{system[:64]} decided {theirs}; the signer decided {mine}"
            else:
                continue
            tx.emit(run, "capture.gap", {"kind": "decision_mismatch", "tool_use_id": tcid, "reason": reason},
                    source="signer", tool_call_id=tcid)
    live = rec.get("live", {})
    found = [x for x in _found(run, mandatory, handoff, structured) if x[0] != "hook_missing" or x[1] not in live]
    unreconciled = {"hook_missing": len(live)} if live else {}
    for kind, tcid, layers, detail in found:
        tx.emit(run, "reconcile." + kind, {"layers": layers, "detail": detail}, source="signer", tool_call_id=tcid)
        unreconciled[kind] = unreconciled.get(kind, 0) + 1
    flagged = {tcid for _, tcid, _, _ in found} | set(live)
    return {"layers": sorted(rec["layers"]), "unreconciled": unreconciled,
            "reconciled": sum(t in rec["l2"] and t not in flagged for t in counted(rec, mandatory))}
