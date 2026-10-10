"""Reconciliation of a run's tool calls across capture layers (04-design §6).

The single writer feeds every record of a run to `observe` as it is written (and replay feeds the log after the
snapshot), so the matcher keeps a per-run index and never reads the log again: L2 is the run's decides
(policy.decision), L3 the client-executed tool uses and the results sent back in its model.exchange records, L1 its
state.write records. When the run's grace window ends, `finish` writes the discrepancies as signed reconcile.* records
of the run, just before run.final, and returns the coverage that run.final states; final_run then drops the index.

For each L3 tool use (provider-executed ones are not indexed): no decide with its id → hook_missing; raw arguments that
failed strict parsing → args_unparseable; another tool name, or (neither side coerced, both digests known) other
arguments → args_mismatch. Each decide with no L3 tool use → fabricated; each id in tool_results_sent with neither →
result_without_call. A run with no L3 record gets none of these: its coverage says L3 is absent. The internal args
digests live in the run's `digests`, which no snapshot holds.

L3 from the LLM gateway (source gateway, tier T2) takes precedence over agent-reported L3 for the same tool use id. With
`gateway_mandatory` (signer.yaml) only gateway L3 counts, and a run with none still has its decides checked: each
decide the gateway did not see is fabricated, whatever the agent reported.

Decisions other systems made (policy.external, from decision_import) are indexed by tool call and system; each that
disagrees with the signer's last decision for that call (flag counts as allow) is a signed
`capture.gap{decision_mismatch}` at the same point. The signer's decision stays the one that applied.
"""

LAYERS = {"state.write": "L1", "policy.decision": "L2", "tool.result": "L2", "model.exchange": "L3"}


def new():
    return {"layers": {}, "l2": {}, "l3": {}, "sent": {}}


def observe(put, run, e, digests=None):
    """Index event `e` just written to `run`; `put(d, k, v)` sets d[k] (undoably on the writer). `digests`: the
    internal args digests the writer knew, by tool_call_id; none on replay, so a call that straddles a restart is
    compared by name only."""
    # lean: the digests of a run's calls are lost on a restart; keep them in the sealed approvals store if runs often
    # outlive a signer restart
    rec, layer = run.get("rec"), LAYERS.get(e["type"])
    if rec is not None and e["type"] == "policy.external":
        if "ext" not in rec:
            put(rec, "ext", {})
        tcid = e["data"]["tool_use_id"]
        put(rec["ext"], tcid, {**rec["ext"].get(tcid, {}), e["data"]["system"]: e["data"]["decision"]})
    if rec is None or layer is None:
        return
    digests = digests or {}
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
            if t["executed_by"] == "client" and (gw or not rec["l3"].get(t["id"], {}).get("gw")):
                put(rec["l3"], t["id"], {"name": t["name"], "coerced": t.get("args_source") == "coerced",
                                         "unparseable": t.get("args_unparseable", False), "gw": gw})
                put(run["digests"], "l3:" + t["id"], digests.get(t["id"]))
        for tcid in e["data"].get("tool_results_sent", ()):
            put(rec["sent"], tcid, True)


def _l3(rec, mandatory):
    return {t: u for t, u in rec["l3"].items() if u.get("gw") or not mandatory}


def _found(run, mandatory):
    """[(kind, tool_call_id, layers, detail)] of the run's discrepancies."""
    rec, digests, out, l3 = run["rec"], run["digests"], [], _l3(run["rec"], mandatory)
    if "L3" not in rec["layers"] and not mandatory:
        return out
    for tcid, u in l3.items():
        d = rec["l2"].get(tcid)
        if d is None:
            out.append(("hook_missing", tcid, ["L2", "L3"], f"the model asked for {u['name'][:200]}; no decide"))
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
        if tcid not in l3:
            out.append(("fabricated", tcid, ["L2", "L3"], f"a decide for {d['name'][:200]} the model never asked for"))
    for tcid in rec["sent"]:
        if tcid not in rec["l2"] and tcid not in l3:
            out.append(("result_without_call", tcid, ["L2", "L3"], "a result sent to the model for a call no layer "
                                                                   "reported"))
    return out


def finish(tx, run, mandatory=False):
    """Write the run's reconcile.* records; returns the coverage for its run.final (None for a run restored from a
    snapshot written before reconciliation, which has no index, or for an imported run). `mandatory`:
    gateway_mandatory."""
    if run.get("rec") is None:
        return None
    rec = run["rec"]
    for tcid, systems in rec.get("ext", {}).items():
        mine = rec["l2"].get(tcid, {}).get("decision")
        mine = "allow" if mine == "flag" else mine
        for system, theirs in systems.items():
            if mine and theirs != mine:
                tx.emit(run, "capture.gap", {"kind": "decision_mismatch", "tool_use_id": tcid,
                                             "reason": f"{system[:64]} decided {theirs}; the signer decided {mine}"},
                        source="signer", tool_call_id=tcid)
    found, unreconciled = _found(run, mandatory), {}
    for kind, tcid, layers, detail in found:
        tx.emit(run, "reconcile." + kind, {"layers": layers, "detail": detail}, source="signer", tool_call_id=tcid)
        unreconciled[kind] = unreconciled.get(kind, 0) + 1
    flagged = {tcid for _, tcid, _, _ in found}
    return {"layers": sorted(rec["layers"]), "unreconciled": unreconciled,
            "reconciled": sum(t in rec["l2"] and t not in flagged for t in _l3(rec, mandatory))}
