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

A framework that hands its hooks no tool-call id (CrewAI, an MCP session under mcp-agent) decides each call under an id
of the adapter's own. A tool use with no decide of its id and a decide with no tool use of its id are paired when both
belong to the same model turn (the decide follows the model exchange that asked for the call, before the next one
that asks for any), their internal args digests are equal (so are the tool and its arguments), and no other unpaired
tool use or decide of that turn has that digest: they count as reconciled, and run.final's `paired_by_args` says how
many were. Never across turns, never when ambiguous, never without both digests (after a restart).

L3 from the LLM gateway (source gateway, tier T2) takes precedence over agent-reported L3 for the same tool use id. With
`gateway_mandatory` (signer.yaml) only gateway L3 counts, provider-run tool uses included, and a run with none still
has its decides checked: each decide the gateway did not see is fabricated, whatever the agent reported. A tool the
policy's `structured_output` names is not compared with L3 at all: its calls come in the model's structured output,
which carries no tool use id.

Effects (an egress observer's effect.observed, written by SignerService._observe_effect): a host is explained by an
http or browser call to it the run decided (not denied; `hosts`, which the decide sets, memory and snapshot only) or a
model call to its provider's API host (PROVIDER_HOSTS), or by an entry of the policy's `explains` whose hosts match
it, for a tool the run called or a rule label its decisions carry (`explained`). A host nothing explains is one
reconcile.unexplained_effect, written at once (`effects`), and counted in run.final's coverage. `matrix` is run.final's
coverage per action class, from the sources of the run's records (`models`, `tools`), the deployment's posture and
the observers that covered the run throughout.

A tool result an LLM gateway saw a request send that is not the call's tool.result (SignerService._results_checked) is
one reconcile.result_mismatch, written at once (`mismatched`, rebuilt from the records on replay), and counted in
run.final's coverage; one it gave no digests of is one capture.gap result_unchecked (`unchecked`, likewise).

Decisions other systems made (policy.external, from decision_import) are indexed by tool call and system; each that
disagrees with the signer's last decision for that call (flag counts as allow), names another tool, or names a call
the signer never decided is a signed
`capture.gap{decision_mismatch}` at the same point. The signer's decision stays the one that applied.
"""

import fnmatch

LAYERS = {"state.write": "L1", "policy.decision": "L2", "tool.result": "L2", "model.exchange": "L3"}
NAMES = {"sdk": "adapter"}   # a record source as the coverage matrix names its layer
# lean: each provider's public API host; a model endpoint elsewhere (Bedrock, Azure, a self-hosted one) is explained by
# the LLM gateway that calls it, or not at all
PROVIDER_HOSTS = {"anthropic": "api.anthropic.com", "openai": "api.openai.com"}


def new():
    return {"layers": {}, "l2": {}, "l3": {}, "sent": {}, "turn": 0}


def sub(put, rec, k):
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
        put(sub(put, rec, "ext"), tcid, {**rec["ext"].get(tcid, {}), d["system"]: [d["decision"], d["tool"]]})
    if rec is not None and e["type"] == "reconcile.hook_missing":   # written live: finish does not write it again
        put(sub(put, rec, "live"), e["tool_call_id"], True)
    if rec is not None and e["type"] == "reconcile.result_mismatch":   # written live, once per call; counted by finish
        put(sub(put, rec, "mismatched"), e["tool_call_id"], True)
    if rec is not None and e["type"] == "capture.gap" and e["data"].get("kind") == "result_unchecked":   # once per call
        put(sub(put, rec, "unchecked"), e["tool_call_id"], True)
    if rec is None or layer is None:
        return []
    digests, now = digests or {}, []
    if layer not in rec["layers"]:
        put(rec["layers"], layer, True)
    if e["type"] == "policy.decision":
        tcid = e["tool_call_id"]
        put(rec["l2"], tcid, {"name": e["data"]["tool"], "coerced": e.get("args_source") == "coerced",
                              "decision": e["data"]["decision"], "rules": e["data"]["rule_ids"], "turn": rec.get("turn")})
        put(sub(put, rec, "tools"), NAMES.get(e["source"], e["source"]), True)
        put(run["digests"], "l2:" + tcid, digests.get(tcid))
        _index(put, rec, rec.get("turn"), digests.get(tcid), 1, tcid)
    elif e["type"] == "model.exchange":
        gw = e["source"] == "gateway"
        put(sub(put, rec, "models"), NAMES.get(e["source"], e["source"]), True)
        if e["data"].get("upstream") in PROVIDER_HOSTS:   # the provider the exchange went to
            put(sub(put, rec, "providers"), PROVIDER_HOSTS[e["data"]["upstream"]], True)
        # a model answer with tool uses not seen before starts a turn; another layer's copy of one doesn't
        if "turn" in rec and any(t["executed_by"] != "provider" and t["id"] not in rec["l3"]
                                 for t in e["data"].get("tool_uses", ())):
            put(rec, "turn", rec["turn"] + 1)
        for t in e["data"].get("tool_uses", ()):
            if t["executed_by"] == "provider":
                if gw or not rec.get("provider", {}).get(t["id"], {}).get("gw"):
                    put(sub(put, rec, "provider"), t["id"], {"gw": gw})
            elif gw or not rec["l3"].get(t["id"], {}).get("gw"):
                put(rec["l3"], t["id"], {"name": t["name"], "coerced": t.get("args_source") == "coerced",
                                         "unparseable": t.get("args_unparseable", False), "gw": gw,
                                         "turn": rec.get("turn")})
                put(run["digests"], "l3:" + t["id"], digests.get(t["id"]))
                _index(put, rec, rec.get("turn"), digests.get(t["id"]), 0, t["id"])
        for tcid in e["data"].get("tool_results_sent", ()):
            put(rec["sent"], tcid, True)
            u = rec["l3"].get(tcid)
            if gw and u and u["gw"] and tcid not in rec["l2"] and tcid not in rec.get("live", {}) and tcid not in {
                    x[1] for x in now} and not handoff(u["name"]) and not _paired_live(run, tcid):
                now.append(("hook_missing", tcid, ["L2", "L3"], f"the model asked for {u['name'][:200]}; its result "
                            "went back to the model with no decide: the call ran with no hook or adapter gating it, or "
                            "one refused it before deciding (then the result is that refusal); check the agent's hooks "
                            f"or adapter (`tracekit doctor`){_hint(u['name'])}"))
    return now


# What a framework shows the model for the tool `t` of MCP server `s`, decided as `mcp:<s>/<t>`. Each form holds the
# whole tool name; a server-prefixed form holds the decided server too.
MCP_NAMES = ("{t}",              # OpenAI Agents JS, the Vercel AI SDK, the mcp Python client
             "mcp__{s}__{t}",    # Claude Code
             "mcp_{s}__{t}")     # OpenAI Agents JS with mcpConfig.includeServerInToolNames


def model_names(tool):
    """The names the model may have asked for decided `tool`: the name itself, and for `mcp:<server>/<tool>` the
    MCP_NAMES forms that parse back to exactly that server and tool. A server or tool with an edge `_` or a `__` could
    share the separator (`mcp:_prod/t` spells `mcp__prod__t`), and a tool named like a prefixed form
    (`mcp:z/mcp__prod__t`) could stand for another server's tool: those get no alias."""
    if not tool.startswith("mcp:") or "/" not in tool:
        return (tool,)
    server, name = tool[4:].split("/", 1)
    exact = lambda part: part and not (part.startswith("_") or part.endswith("_") or "__" in part)
    forms = [] if name.startswith("mcp_") and "__" in name else ["{t}"]
    if exact(server) and exact(name):
        forms += MCP_NAMES[1:]
    return (tool,) + tuple(f.format(s=server, t=name) for f in forms)


def _hint(tool):
    """What a hook_missing detail adds for a tool that looks like a handoff the policy does not name."""
    return "; if it is a handoff to another agent, name it in the policy's handoffs:" if tool.startswith(
        "transfer_to_") else ""


def explained(rec, host, explains, labels):
    """What explains `host` for the run of index `rec`: "call", "explains" (`explains`: the policy's entries; `labels`:
    rule id -> label), or None."""
    if host in rec.get("hosts", {}) or host in rec.get("providers", {}):
        return "call"
    # lean: scans the run's decisions for each observed host; index tool names and labels if runs make ~10k calls
    called = [(d["name"], d.get("rules", ())) for d in rec["l2"].values()
              if d["decision"] in ("allow", "flag") or d.get("approved")]   # an ask explains once approved
    for x in explains:
        if any(fnmatch.fnmatchcase(host, h) for h in x["hosts"]) and any(
                fnmatch.fnmatchcase(name, x["tool"]) if "tool" in x else x["label"] in {labels.get(r) for r in rules}
                for name, rules in called):
            return "explains"
    return None


def matrix(rec, posture, observed):
    """run.final's coverage matrix of the run of index `rec`; `posture`: signer.yaml's; `observed`: whether an egress
    observer covered the run and heartbeat throughout. Processes and services: none until an observer covers them."""
    def cls(status, layers, asserted=False):
        return {"status": status, "layers": sorted(layers), **({"asserted": True} if asserted else {})}
    models, tools, gw = rec.get("models", {}), rec.get("tools", {}), posture.get("gateway_mandatory", False)
    enforced = posture.get("network") == "enforced"
    custody = posture.get("tool_calls") == "enforced" and set(tools) == {"gateway"}   # every decision a gateway's
    return {"model_calls": cls("enforced" if gw else "observed", models, gw) if "gateway" in models else
            cls("reported" if models else "none", models),
            "tool_calls": cls("enforced", tools, True) if custody else cls("reported" if tools else "none", tools),
            "network": cls("enforced" if enforced else "observed", ["egress"], enforced) if observed else
            cls("reported", tools) if rec.get("hosts") else cls("none", ()),
            "processes": cls("none", ()), "services": cls("none", ())}


def counted(rec, mandatory, k="l3"):
    """The tool uses of index `k` (l3, or provider) that count: with gateway_mandatory, the gateway's only."""
    return {t: u for t, u in rec.get(k, {}).items() if u.get("gw") or not mandatory}


def _index(put, rec, turn, digest, side, tcid):
    """Files call `tcid` (side 0: a tool use, 1: a decide) under its turn and args digest, so the live check reads one
    turn's candidates, not the whole run."""
    if turn is None or not isinstance(digest, str):
        return
    pairs, key = sub(put, rec, "pairs"), f"{turn} {digest}"
    entry = pairs.get(key, [[], []])
    if tcid not in entry[side]:
        put(pairs, key, [entry[0] + [tcid], entry[1]] if side == 0 else [entry[0], entry[1] + [tcid]])


def _paired_live(run, tcid):
    """Whether tool use `tcid`, with no decide of its own, pairs by arguments: paired()'s rule (not gateway_mandatory)
    over the candidates of its own turn and digest only."""
    rec, digests = run["rec"], run["digests"]
    turn, digest = rec["l3"][tcid].get("turn"), digests.get("l3:" + tcid)
    uses, decides = rec.get("pairs", {}).get(f"{turn} {digest}", ([], []))
    uses = [t for t in uses if t not in rec["l2"] and rec["l3"].get(t, {}).get("turn") == turn
            and digests.get("l3:" + t) == digest]
    decides = [t for t in decides if t not in rec["l3"] and t not in rec.get("provider", {})
               and rec["l2"][t].get("turn") == turn and digests.get("l2:" + t) == digest]
    return uses == [tcid] and len(decides) == 1


def paired(run, mandatory):
    """{tool use id: decide id} of the run's calls paired by arguments (module docstring)."""
    rec, digests, l3 = run["rec"], run["digests"], counted(run["rec"], mandatory)
    provider, by = counted(rec, mandatory, "provider"), {}
    for side, (k, lone) in enumerate((("l3", {t: u for t, u in l3.items() if t not in rec["l2"]}),
                                      ("l2", {t: d for t, d in rec["l2"].items() if t not in l3 and t not in provider}))):
        for tcid, x in lone.items():
            digest = digests.get(f"{k}:{tcid}")
            if digest and x.get("turn") is not None:
                by.setdefault((x["turn"], digest), ([], []))[side].append(tcid)
    return {uses[0]: decides[0] for uses, decides in by.values() if len(uses) == 1 and len(decides) == 1}


def _found(run, mandatory, handoff=lambda tool: False, structured=lambda tool: False):
    """[(kind, tool_call_id, layers, detail)] of the run's discrepancies; `handoff(tool)`: the policy's handoffs;
    `structured(tool)`: its structured_output, which are never compared with L3."""
    rec, digests, out, l3 = run["rec"], run["digests"], [], counted(run["rec"], mandatory)
    provider = counted(rec, mandatory, "provider")
    if "L3" not in rec["layers"] and not mandatory:
        return out
    pairs = paired(run, mandatory)
    for tcid, u in l3.items():
        d = rec["l2"].get(tcid)
        if d is None and tcid not in pairs and not handoff(u["name"]) and not structured(u["name"]):
            out.append(("hook_missing", tcid, ["L2", "L3"],
                        f"the model asked for {u['name'][:200]}; no decide: it ran with no hook or adapter gating it, "
                        "or the framework turned it down before any hook (arguments that failed its validation) and "
                        f"asked the model again{_hint(u['name'])}"))
        if u["unparseable"]:
            out.append(("args_unparseable", tcid, ["L3"], "the model's raw arguments failed strict parsing"))
        if d is None:
            continue
        a, b = digests.get("l2:" + tcid), digests.get("l3:" + tcid)
        if isinstance(a, dict):   # an MCP call: the signer's digest under each name the model may have used
            a = a.get(u["name"])
        if u["name"] not in model_names(d["name"]):
            out.append(("args_mismatch", tcid, ["L2", "L3"], f"decided {d['name'][:200]}, the model asked for "
                                                             f"{u['name'][:200]}"))
        elif not (u["unparseable"] or d["coerced"] or u["coerced"]) and a and b and a != b:
            out.append(("args_mismatch", tcid, ["L2", "L3"], "decided other arguments than the model asked for"))
    for tcid, d in rec["l2"].items():
        if tcid not in l3 and tcid not in provider and tcid not in pairs.values() and not structured(d["name"]):
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
    if rec.get("effects"):
        unreconciled["unexplained_effect"] = len(rec["effects"])
    if rec.get("mismatched"):
        unreconciled["result_mismatch"] = len(rec["mismatched"])
    for kind, tcid, layers, detail in found:
        tx.emit(run, "reconcile." + kind, {"layers": layers, "detail": detail}, source="signer", tool_call_id=tcid)
        unreconciled[kind] = unreconciled.get(kind, 0) + 1
    flagged = {tcid for _, tcid, _, _ in found} | set(live)
    pairs = paired(run, mandatory) if "L3" in rec["layers"] or mandatory else {}
    return {"layers": sorted(rec["layers"]), "unreconciled": unreconciled,
            "reconciled": sum(t in rec["l2"] and t not in flagged for t in counted(rec, mandatory)) + len(pairs),
            **({"paired_by_args": len(pairs)} if pairs else {})}
