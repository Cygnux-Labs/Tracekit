"""Causeway integration: Tracekit as the trust root for Causeway's causal logs, in both directions.

    tracekit-causeway anchor runs/demo-seed0            # sign + witness the Causeway run's chain head, blobs and tests
    tracekit-causeway verify runs/demo-seed0            # unchanged since a signed anchor? (and what came after it)
    tracekit-causeway import-tests runs/demo-seed0      # counterfactual verdicts -> signed Tracekit findings
    tracekit-causeway export --run R -o runs/           # a Tracekit run as a Causeway run (lineage, alerts, graph views)

Causeway hash-chains its events but does not sign them: anyone who can rewrite the run directory can rebuild a
consistent chain. An anchor is a signed, checkpointed (and witnessed, if configured) Tracekit record of the run's chain
head, the digest of all its blobs and the digest of its test results. After anchoring, editing any event, blob or test
result, or dropping events, makes `tracekit-causeway verify` fail; appending events is reported as an unanchored tail.

Anchors and imported findings live in companion runs (``anchors:causeway:<run>``, ``findings:causeway:<run>``) that the
signer accepts only `review` events for. Causeway's formats are read from its documented spec (docs/architecture.md);
the Causeway package is not needed."""
import argparse
import hashlib
import json
import os
import sys

GENESIS = "0" * 64
ANCHOR_PREFIX = "anchors:causeway:"
FINDINGS_RUN = "findings:causeway:"


# ------------------------------------------------------------------ Causeway formats (docs/architecture.md)

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def cw_event_hash(ev):
    return hashlib.sha256(_canonical({k: v for k, v in ev.items() if k != "hash"})).hexdigest()


def cw_content_hash(value):
    return "sha256:" + hashlib.sha256(_canonical({"v": value})).hexdigest()


def load(path):
    """-> (events, blobs, tests, raw_tests_bytes)."""
    with open(os.path.join(path, "events.jsonl"), encoding="utf-8") as f:
        events = [json.loads(x) for x in f if x.strip()]
    blobs = {}
    bdir = os.path.join(path, "blobs")
    if os.path.isdir(bdir):
        for name in sorted(os.listdir(bdir)):
            if name.endswith(".json"):
                with open(os.path.join(bdir, name), encoding="utf-8") as f:
                    blobs["sha256:" + name[:-5]] = json.load(f)["v"]
    raw = b""
    tp = os.path.join(path, "tests.jsonl")
    if os.path.exists(tp):
        with open(tp, "rb") as f:
            raw = f.read()
    tests = [json.loads(x) for x in raw.decode("utf-8").splitlines() if x.strip()]
    return events, blobs, tests, raw


def chain_problems(events, blobs):
    probs, prev = [], GENESIS
    for i, ev in enumerate(events):
        if ev.get("seq") != i:
            probs.append(f"event {i}: seq {ev.get('seq')} not contiguous")
        if ev.get("prev_hash") != prev:
            probs.append(f"event {i}: prev_hash does not link")
        if cw_event_hash(ev) != ev.get("hash"):
            probs.append(f"event {i}: hash mismatch (edited)")
        prev = ev.get("hash", "")
    for ref, val in blobs.items():
        if cw_content_hash(val) != ref:
            probs.append(f"blob {ref[:20]}: content does not match its hash")
    return probs


def digest(path):
    events, blobs, tests, raw = load(path)
    return {"system": "causeway", "run_id": events[0]["run_id"] if events else os.path.basename(path.rstrip("/")),
            "events": len(events), "head_hash": events[-1]["hash"] if events else GENESIS,
            "blobs_sha256": hashlib.sha256("\n".join(sorted(blobs)).encode()).hexdigest(), "blobs": len(blobs),
            "tests_sha256": hashlib.sha256(raw).hexdigest(), "tests": len(tests)}, events, blobs, tests


# ------------------------------------------------------------------ ledger access

def _home(a):
    from tracekit import client
    return a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"


def _records(home):
    from tracekit.ledger import read_records
    return [r for _, r, _ in read_records(os.path.join(home, "ledger", "ledger.jsonl")) if r and not r.get("elided")]


def _review_event(run_id, verdict, reviewer):
    from tracekit.core import GENESIS as TG, SCHEMA_VERSION, new_id, now_ts
    return {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": TG, "ts": now_ts(), "run_id": run_id,
            "agent_id": "analyzer", "parent_id": None, "source": "sdk", "type": "review",
            "data": {"reviewer": reviewer, "verdict": verdict}}


def anchors_for(records, cw_run):
    return [(r["event"]["seq"], r["hash"], r["event"]["data"]["verdict"]) for r in records
            if r["event"]["run_id"] == ANCHOR_PREFIX + cw_run and r["event"]["type"] == "review"
            and (r["event"]["data"].get("verdict") or {}).get("kind") == "anchor"]


def anchor(home, path):
    """Sign an anchor for a Causeway run. -> (status, verdict, signed_seq_or_None)."""
    from tracekit import client
    d, events, blobs, _ = digest(path)
    probs = chain_problems(events, blobs)
    if probs:
        return "refused", {"problems": probs[:10]}, None
    for seq, h, v in anchors_for(_records(home), d["run_id"]):
        if all(v.get(k) == d[k] for k in d):
            return "unchanged", v, seq
    verdict = {"kind": "anchor", **d}
    resp = client.send(_review_event(ANCHOR_PREFIX + d["run_id"], verdict, "tracekit-causeway/1"), stream="analyzer")
    if not resp.get("ok"):
        raise RuntimeError(f"signer refused the anchor: {resp.get('error')}")
    return "anchored", verdict, resp.get("seq")


def check(records, path):
    """-> (ok, lines). ok is False if the run changed since its latest anchor or was never anchored."""
    d, events, blobs, _ = digest(path)
    lines, probs = [], chain_problems(events, blobs)
    if probs:
        return False, ["Causeway chain broken: " + "; ".join(probs[:5])]
    anchors = anchors_for(records, d["run_id"])
    if not anchors:
        return False, [f"run {d['run_id']}: no signed anchor in the ledger (run `tracekit-causeway anchor`)"]
    seq, h, v = anchors[-1]
    if v["events"] > len(events):
        return False, [f"anchored with {v['events']} events, now {len(events)}: events were removed"]
    if events[v["events"] - 1]["hash"] != v["head_hash"] if v["events"] else v["head_hash"] != GENESIS:
        return False, [f"event {v['events'] - 1} no longer matches the anchored head (history rewritten after anchoring)"]
    if v["events"] == len(events) and v["blobs_sha256"] != d["blobs_sha256"]:
        return False, ["blob set changed since anchoring"]
    ok = True
    if v["tests_sha256"] != d["tests_sha256"]:
        lines.append("tests.jsonl changed since anchoring (re-anchor if results were only added)")
        ok = False
    lines.insert(0, f"run {d['run_id']}: anchored at ledger seq {seq} (record {h[:12]}), {v['events']} events, {v['blobs']} blobs, "
                    f"{v['tests']} test results")
    if len(events) > v["events"]:
        lines.append(f"{len(events) - v['events']} event(s) after the anchor are not covered (append-only growth; re-anchor)")
    return ok, lines


# ------------------------------------------------------------------ tests -> findings

def import_tests(home, path):
    """Counterfactual verdicts as signed findings citing the run's anchor. Requires a current anchor."""
    from tracekit import client
    from tracekit.findings import fingerprint
    records = _records(home)
    ok, lines = check(records, path)
    if not ok:
        raise RuntimeError("anchor the run first (tests must be covered by a signed anchor): " + "; ".join(lines))
    d, events, _, tests = digest(path)
    seq, h, _ = anchors_for(records, d["run_id"])[-1]
    have = {r["event"]["data"]["verdict"].get("fingerprint") for r in records if r["event"]["run_id"] == FINDINGS_RUN + d["run_id"]}
    rules = {"causal": ("TK-C001", "high"), "suppressive": ("TK-C002", "medium"), "no-detectable-effect": ("TK-C003", "info"),
             "not-applied": ("TK-C004", "low")}
    wrote = []
    for i, t in enumerate(tests):
        rule, sev = rules.get(t.get("verdict"), ("TK-C009", "low"))
        ev = [(seq, h)]
        title = {"TK-C001": "confirmed cause", "TK-C002": "removing it made the action more likely",
                 "TK-C003": "ruled out (no detectable effect)", "TK-C004": "intervention never applied"}.get(rule, "test result")
        ci = t.get("ci") or [None, None]
        verdict = {"kind": "finding", "rule": rule, "severity": sev, "title": f"{t.get('intervention')} -> {t.get('target')}: {title}",
                   "detail": f"effect {t.get('effect')} (95% CI {ci[0]}..{ci[1]}), P(with)={t.get('p_with')} P(without)={t.get('p_without')}, "
                             f"n={t.get('n')}, {t.get('method')}. Test #{i} of tests.jsonl, covered by the signed anchor.",
                   "run_id": "causeway:" + d["run_id"], "detector": "causeway-counterfactual (imported by tracekit-causeway/1)",
                   "fingerprint": fingerprint(rule, d["run_id"] + f"#{i}", ev), "evidence": [{"seq": seq, "hash": h}],
                   "causeway_test": t}
        if verdict["fingerprint"] in have:
            continue
        resp = client.send(_review_event(FINDINGS_RUN + d["run_id"], verdict, "tracekit-causeway/1"), stream="analyzer")
        if not resp.get("ok"):
            raise RuntimeError(f"signer refused a finding: {resp.get('error')}")
        wrote.append(verdict)
    return wrote


# ------------------------------------------------------------------ Tracekit run -> Causeway run

def export(home, run_id, out_dir):
    """Write a Causeway run directory for a Tracekit run, plus tracekit-map.json (Causeway event id -> Tracekit seq, hash).

    Tracekit records what crossed the capture path, not the exact context each model call saw, so decision context is
    reconstructed as every earlier input and tool result of the same agent; meta.context says so. Content Tracekit kept
    only as a hash is exported as {"tracekit_hash": ...}. Replays need a Causeway program and are not possible from this."""
    import secrets
    recs = [r for r in _records(home) if r["event"]["run_id"] == run_id]
    if not recs:
        raise ValueError(f"no run {run_id!r} in the ledger")
    path = os.path.join(out_dir, "tk-" + "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:100])
    os.makedirs(os.path.join(path, "blobs"), exist_ok=True)
    events, blobs, mapping = [], {}, {}
    prev = [GENESIS]

    def blob(content):
        if isinstance(content, dict) and "value" in content:
            v = content["value"]
        elif isinstance(content, dict) and "hash" in content:
            v = {"tracekit_hash": content["hash"], "size": content.get("size"), "redacted": content.get("redacted")}
        else:
            v = content
        ref = cw_content_hash(v)
        if ref not in blobs:
            blobs[ref] = v
            with open(os.path.join(path, "blobs", ref[7:] + ".json"), "w", encoding="utf-8") as f:
                json.dump({"v": v}, f, sort_keys=True, ensure_ascii=False, default=str)
        return ref

    def emit(agent, etype, src=None, **body):
        ev = {"schema": "causeway.event.v1", "seq": len(events), "id": secrets.token_hex(16), "prev_hash": prev[0],
              "ts": (src or {}).get("ts") or recs[0]["event"]["ts"], "run_id": path.rsplit(os.sep, 1)[-1], "agent": agent, "type": etype}
        ev.update(body)
        ev["hash"] = cw_event_hash(ev)
        prev[0] = ev["hash"]
        events.append(ev)
        return ev

    start = next((r["event"] for r in recs if r["event"]["type"] == "run.start"), recs[0]["event"])
    sd = start["data"] if start["type"] == "run.start" else {}
    models = sorted({r["event"]["data"].get("model") for r in recs if r["event"]["type"] == "model.exchange" and r["event"]["data"].get("model")})
    tools = sorted({r["event"]["data"]["name"] for r in recs if r["event"]["type"] == "tool.call"})
    denied_or_flagged = {r["event"]["data"]["tool_use_id"] for r in recs if r["event"]["type"] == "policy.decision"
                         and r["event"]["data"]["decision"] in ("deny", "flag", "ask")}
    e0 = emit("run", "run.start", start, program="", seed=0, interventions=[], models=models or [sd.get("model") or "unknown"], tools=tools,
              sensitive_tools=[], meta={"source": "tracekit", "tracekit_run": run_id, "agent": (sd.get("agent") or {}).get("name"),
                                        "context": "reconstructed: every earlier input and tool result of the same agent"})
    mapping[e0["id"]] = {"seq": start["seq"], "hash": next(r["hash"] for r in recs if r["event"] is start)}
    seen_agents, ctx = set(), {}
    pending_calls, decision_for_tool = {}, {}
    for r in recs:
        e, d = r["event"], r["event"]["data"]
        agent = e.get("agent_id") or "main"
        if e["type"] in ("run.start", "run.end", "policy.decision"):
            continue
        if agent not in seen_agents:
            seen_agents.add(agent)
            emit(agent, "agent.start", e, parent=e.get("parent_id"), role="")
        out = None
        if e["type"] == "user.prompt":
            ref = blob(d.get("content"))
            out = emit(agent, "input", e, ref=ref, source="user", trust="trusted", kind="task")
            ctx.setdefault(agent, []).append({"ref": ref, "kind": "task", "source": "user", "trust": "trusted", "from_event": out["id"]})
        elif e["type"] == "model.exchange" and d.get("phase") == "response":
            out = emit(agent, "decision", e, model=d.get("model"), purpose="", params={}, seed=0, context=list(ctx.get(agent, [])),
                       ablated=[], output=blob(d.get("response") if d.get("response") is not None else {"stop_reason": d.get("stop_reason")}),
                       usage=d.get("usage") or {}, status="error" if d.get("error") else "ok", duration_ms=d.get("duration_ms"))
            for t in d.get("tool_uses") or []:
                decision_for_tool[t["id"]] = out["id"]
        elif e["type"] == "tool.call":
            pending_calls[d["tool_use_id"]] = (e, r["hash"])
            continue
        elif e["type"] == "tool.result":
            call = pending_calls.pop(d["tool_use_id"], None)
            if call is None:
                continue
            ce, ch = call
            args = {k: (v.get("value") if isinstance(v, dict) and "value" in v else {"tracekit_hash": (v or {}).get("hash")})
                    for k, v in (ce["data"].get("input") or {}).items()}
            res_ref = blob(d.get("output"))
            out = emit(agent, "action", e, tool=ce["data"]["name"], args_ref=blob(args), result_ref=res_ref,
                       decision=decision_for_tool.get(d["tool_use_id"]), status="ok" if d.get("ok") else "error", mode="live",
                       sensitive=d["tool_use_id"] in denied_or_flagged, duration_ms=d.get("duration_ms"))
            mapping[out["id"] + ":call"] = {"seq": ce["seq"], "hash": ch}
            ctx.setdefault(agent, []).append({"ref": res_ref, "kind": "result", "source": ce["data"]["name"], "trust": "untrusted",
                                              "from_event": out["id"]})
        if out is not None:
            mapping[out["id"]] = {"seq": e["seq"], "hash": r["hash"]}
    end = next((r for r in recs if r["event"]["type"] == "run.end"), None)
    if end:
        ee = emit("run", "run.end", end["event"], outcome=end["event"]["data"].get("reason"))
        mapping[ee["id"]] = {"seq": end["event"]["seq"], "hash": end["hash"]}
    with open(os.path.join(path, "events.jsonl"), "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(path, "tracekit-map.json"), "w", encoding="utf-8") as f:
        json.dump({"tracekit_run": run_id, "events": mapping}, f, indent=1, sort_keys=True)
    return path, len(events)


# ------------------------------------------------------------------ CLI

def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit-causeway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("anchor", "verify", "import-tests"):
        p = sub.add_parser(name)
        p.add_argument("run_dirs", nargs="+")
        p.add_argument("--home")
    e = sub.add_parser("export")
    e.add_argument("--run", required=True)
    e.add_argument("-o", "--out", default="runs")
    e.add_argument("--home")
    a = ap.parse_args(argv)
    home = _home(a)
    if a.cmd == "export":
        try:
            path, n = export(home, a.run, a.out)
        except ValueError as err:
            print(f"tracekit-causeway: {err}", file=sys.stderr)
            return 2
        print(f"wrote {path} ({n} Causeway events); open with: causeway report {a.out}")
        return 0
    code = 0
    for path in a.run_dirs:
        try:
            if a.cmd == "anchor":
                status, v, seq = anchor(home, path)
                if status == "refused":
                    print(f"{path}: refused, the Causeway chain is already broken: {'; '.join(v['problems'])}", file=sys.stderr)
                    code = 1
                else:
                    print(f"{path}: {status} at ledger seq {seq} ({v['events']} events, head {v['head_hash'][:12]}, {v['tests']} tests)")
            elif a.cmd == "verify":
                ok, lines = check(_records(home), path)
                print(f"{path}: {'OK' if ok else 'FAILED'}")
                for line in lines:
                    print("  " + line)
                code = code or (0 if ok else 1)
            else:
                wrote = import_tests(home, path)
                print(f"{path}: {len(wrote)} test result(s) signed as findings")
                for v in wrote:
                    print(f"  [{v['severity']}] {v['rule']} {v['title']}")
        except (OSError, ValueError, RuntimeError) as err:
            print(f"{path}: {err}", file=sys.stderr)
            code = code or 2
    return code


if __name__ == "__main__":
    sys.exit(main())
