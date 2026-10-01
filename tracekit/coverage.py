"""Coverage report (C6, first version). Labels what the capture path observed, what it only
inferred from harness-reported data, and what it does not cover at all.
Wording rule: never "complete". Clean means clean on observed paths only."""

UNSUPPORTED_ALWAYS = [
    "network and file activity inside subprocesses (only the command line is observed)",
    "processes that keep running in the background after the tool call returns",
    "activity after the last hook of the run (including transcript edits after it)",
    "faked command output (tool results are whatever the harness reports)",
]


def report(events):
    """events: list of full v1 events (selection only)."""
    runs, calls, results, denied = {}, {}, set(), set()
    gaps, tampers, bg, net, sources = [], [], [], [], set()
    exchanges, shadow, envt, approvals = 0, [], [], []
    for e in events:
        sources.add(e["source"])
        d = e["data"]
        r = runs.setdefault(e["run_id"], {"start": None, "end": False})
        if e["type"] == "run.start":
            r["start"] = d
        elif e["type"] == "run.end":
            r["end"] = True
        elif e["type"] == "tool.call":
            calls[d["tool_use_id"]] = e
        elif e["type"] == "tool.result":
            results.add(d["tool_use_id"])
        elif e["type"] == "capture.gap":
            gaps.append({"seq": e["seq"], "run_id": e["run_id"], "reason": d.get("reason")})
        elif e["type"] == "trace.tamper":
            tampers.append({"seq": e["seq"], "path": d.get("path"), "kind": d.get("kind")})
        elif e["type"] == "model.exchange" and d.get("phase") == "response":
            exchanges += 1
        elif e["type"] == "approval":
            approvals.append({"seq": e["seq"], "tool_use_id": d.get("tool_use_id"), "decision": d.get("decision"),
                              "approver": d.get("approver")})
        elif e["type"] == "policy.decision":
            if d.get("decision") == "deny":
                denied.add(d["tool_use_id"])
            rs = d.get("reasons") or []
            if "background_spawn" in rs:
                bg.append(e["seq"])
            if "network" in rs:
                net.append(e["seq"])
            if "shell_shadowing" in rs:
                shadow.append(e["seq"])
            if "env_tamper" in rs:
                envt.append(e["seq"])
    warnings = []
    for rid, r in runs.items():
        if rid == "_signer":
            continue
        if not r["start"]:
            warnings.append(f"run {rid}: no run.start in the selection")
        if not r["end"]:
            warnings.append(f"run {rid}: no run.end (hooks may have been disabled, or the run is still going)")
        if r["start"] and r["start"].get("signer_isolation") == "same-user":
            warnings.append(f"run {rid}: signer ran as the agent's own user (dev mode): the agent could have rewritten the ledger")
        if r["start"] and r["start"].get("fail_mode") == "open":
            warnings.append(f"run {rid}: fail_mode=open: tool calls made while the signer was down are not recorded")
    unmatched = [tid for tid in calls if tid not in results and tid not in denied]
    if unmatched:
        warnings.append(f"{len(unmatched)} tool call(s) with no recorded result")
    if gaps:
        warnings.append(f"{len(gaps)} capture.gap event(s)")
    if tampers:
        warnings.append(f"{len(tampers)} trace.tamper event(s)")
    unsupported_used = []
    if bg:
        unsupported_used.append(f"background processes were started (policy flags at seq {bg[:10]})")
    if net:
        unsupported_used.append(f"subprocess network activity (network commands at seq {net[:10]}; payloads not observed)")
    if shadow:
        unsupported_used.append(f"shell functions or aliases shadowing common commands (seq {shadow[:10]}): later command output may be spoofed")
    if envt:
        unsupported_used.append(f"environment changes that alter later commands (seq {envt[:10]})")
    sandboxes = sorted({(r["start"] or {}).get("sandbox", "unknown") for rid, r in runs.items() if rid != "_signer"})
    proxy_runs = [rid for rid, r in runs.items() if r["start"] and "proxy" in r["start"].get("capture_sources", [])]
    observed = []
    if "hook" in sources:
        observed.extend(["tool calls and policy decisions reported by the Claude Code hook",
                         "tool results as reported by the Claude Code harness",
                         "user prompts reported by the Claude Code hook"])
    if "sdk" in sources:
        observed.extend(["agent-reported prompts and tool calls explicitly sent through the SDK",
                         "policy decisions and results for SDK-wrapped tool calls; unwrapped calls are not observed"])
    if "transcript" in sources:
        observed.append("harness transcript prefix hashes at every hook (edits, truncation, deletion between hooks)")
    if proxy_runs or exchanges:
        observed.append(f"model API requests and responses at the proxy ({exchanges} exchanges), cross-checked against hooks")
    else:
        warnings.append("no model proxy: disabled hooks can only be inferred from missing run.end, not detected")
    return {
        "observed": observed,
        "approvals": approvals,
        "inferred": ["model text read from the harness transcript (source=transcript, lower trust)"] if "transcript" in sources else [],
        "unsupported": UNSUPPORTED_ALWAYS,
        "unsupported_used": unsupported_used,
        "sources": sorted(sources),
        "sandbox": sandboxes,
        "gaps": gaps, "tamper": tampers, "warnings": warnings,
        "summary": "clean on observed paths" if not (gaps or tampers or unmatched) else "issues on observed paths",
    }
