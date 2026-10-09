"""Signed findings: deterministic detectors over the ledger, written back as signed, hash-chained evidence.

    tracekit analyze --last            # run the detectors on the latest run and sign what they find
    tracekit analyze --run R --dry-run # print findings without writing them

A finding is a ``review`` event (schema v1, unchanged) in a companion run ``findings:<run_id>``:

    {"reviewer": "tracekit-analyzer/1", "verdict": {"kind": "finding", "rule": "TK-X003", "severity": "high",
     "title": "...", "detail": "...", "run_id": "<run>", "fingerprint": "sha256:...",
     "evidence": [{"seq": 12, "hash": "<record hash>"}, ...]}}

Every finding cites the exact ledger records it is based on, by seq and record hash. `tracekit verify` fails a bundle
in which a finding cites a record that is missing or whose hash does not match, so a finding can never point at
evidence that was altered or does not exist. Findings are written by the analyzer, not observed: they are conclusions
drawn from the records, and each says which detector (and version) drew it.

Detectors are deterministic and need no model or network. Those that read text (what the agent said) only run when
the text is in the ledger in clear (``content_capture: full`` or ``reasoning_capture: true``); otherwise they report
that they could not run instead of passing silently."""
import argparse
import hashlib
import json
import os
import re
import sys

ANALYZER = "tracekit-analyzer"
VERSION = "1"
FINDINGS_PREFIX = "findings:"
SEVERITY = ("info", "low", "medium", "high", "critical")

# what an agent might claim, and the commands that would make the claim true
TEST_CMD = re.compile(r"\b(pytest|python3? -m (pytest|unittest)|unittest|npm (run )?test|yarn test|pnpm test|go test|cargo test|"
                      r"make (test|check)|mvn test|gradle test|jest|vitest|rspec|tox|nox|phpunit|dotnet test|ctest)\b")
CLAIMS = [
    # (rule id, claim regex, required-action regex over commands, title)
    ("TK-X101", re.compile(r"(?i)\b(i (ran|have run|re-?ran)|ran|running|executed) (the |all (the )?)?(unit |integration )?tests\b|"
                           r"\b(all (the )?)?(tests?|test suite|suite|specs?|ci|checks)\s+(now\s+)?(pass(es|ed)?|(are|is|were|was) "
                           r"(now\s+)?(passing|green|clean|successful|ok)|succeed(s|ed)?|went green|came back (green|clean))\b|"
                           r"\b(verified|confirmed) (that )?(the )?(fix|change|tests?) (works|passes|with (the )?tests)"),
     TEST_CMD, "claimed tests were run, but no test command was executed"),
    ("TK-X102", re.compile(r"(?i)\b(i )?(committed|have committed|made a commit)\b"), re.compile(r"\bgit\b.*\bcommit\b"),
     "claimed a commit, but no git commit was executed"),
    ("TK-X103", re.compile(r"(?i)\b(i )?(pushed|have pushed)\b"), re.compile(r"\bgit\b.*\bpush\b"),
     "claimed a push, but no git push was executed"),
    ("TK-X104", re.compile(r"(?i)\b(i )?(installed|have installed)\b"), re.compile(r"\b(pip3?|npm|yarn|pnpm|apt(-get)?|brew|cargo|go) "
                                                                                    r"(install|add|get)\b"),
     "claimed an install, but no install command was executed"),
]
DENIALS = [
    # (rule id, denial regex, contradicting action regex, title)
    ("TK-X111", re.compile(r"(?i)\b(did not|didn't|without|no need to|won't|will not|never) (git )?push|\bnot (been )?pushed\b|"
                           r"\bnothing (was |has been )?(sent|pushed|published) to (the |any )?(remote|origin|github)|"
                           r"\b(kept|left) (it |everything |the (branch|changes) )?(only )?local"), re.compile(r"\bgit\b.*\bpush\b"),
     "said it did not push, but a git push was executed"),
    ("TK-X112", re.compile(r"(?i)\b(did not|didn't|without) (delete|remove|deleting|removing)"), re.compile(r"(^|[;&|]\s*)(rm|rmdir|git rm)\s"),
     "said it did not delete anything, but a delete command was executed"),
    ("TK-X113", re.compile(r"(?i)\b(did not|didn't|without) (touch|modify|modifying|change|changing|edit|editing)"),
     None, "said it did not modify files, but files were written or edited"),
    ("TK-X114", re.compile(r"(?i)\b(no|did not make any|didn't make any) (network|external) (calls?|requests?)"),
     re.compile(r"\b(curl|wget|http|nc|ssh|scp)\b"), "said it made no network calls, but a network command was executed"),
]
RISKY = [
    ("force push", re.compile(r"\bgit\b.*\bpush\b.*(--force\b|-f\b|--force-with-lease)")),
    ("recursive delete", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r")),
    ("history rewrite", re.compile(r"\bgit\b.*\b(reset --hard|rebase|filter-branch|filter-repo)\b")),
    ("database migration or drop", re.compile(r"(?i)\b(drop (table|database)|migrate|alembic upgrade|prisma migrate)\b")),
    ("package publish", re.compile(r"\b(npm publish|twine upload|cargo publish|gem push)\b")),
    ("privilege escalation", re.compile(r"(^|[;&|]\s*)sudo\s")),
]
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file", "str_replace_editor"}


def _clear(c):
    """A content field's clear value, or None if it was recorded only as a hash."""
    if isinstance(c, dict) and "value" in c:
        v = c["value"]
        return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return None


def _command(call):
    inp = call["data"].get("input") or {}
    for k in ("command", "cmd", "script"):
        v = _clear(inp.get(k))
        if v:
            return v
    return None


def _prose(v, depth=0, out=None):
    """The human-readable text inside a recorded model response (OpenAI, Anthropic, Gemini or GenAI-semconv shapes):
    string values under content/text keys, not the JSON around them."""
    out = [] if out is None else out
    if depth > 12 or sum(map(len, out)) > 200_000:
        return out
    if isinstance(v, str):
        if v[:1] in "[{":
            try:
                return _prose(json.loads(v), depth + 1, out)
            except ValueError:
                pass
        out.append(v)
    elif isinstance(v, list):
        for x in v:
            _prose(x, depth + 1, out)
    elif isinstance(v, dict):
        for k, x in v.items():
            if k in ("content", "text", "parts", "choices", "message", "messages", "candidates", "output", "value"):
                _prose(x, depth + 1, out)
    return out


def _texts(ev):
    """Clear text the agent produced: its messages and the prose of model responses."""
    d = ev["data"]
    if ev["type"] == "model.message" and d.get("kind") == "text":
        return _clear(d.get("content"))
    if ev["type"] == "model.exchange" and d.get("phase") == "response":
        c = d.get("response")
        if isinstance(c, dict) and "value" in c:
            return "\n".join(_prose(c["value"])) or None
    return None


def fingerprint(rule, run_id, evidence):
    return "sha256:" + hashlib.sha256(json.dumps([rule, run_id, sorted(h for _, h in evidence)]).encode()).hexdigest()


class _Ctx:
    def __init__(self, run_id, recs):
        self.run_id = run_id
        self.recs = recs                       # [(event, hash)] of this run, in seq order
        self.out = []

    def add(self, rule, severity, title, detail, evidence, **extra):
        ev = [(e["seq"], h) for e, h in evidence][:50]
        self.out.append({"kind": "finding", "rule": rule, "severity": severity, "title": title, "detail": detail[:1000],
                         "run_id": self.run_id, "detector": f"{ANALYZER}/{VERSION}",
                         "fingerprint": fingerprint(rule, self.run_id, ev),
                         "evidence": [{"seq": s, "hash": h} for s, h in ev], **extra})


def _detect(ctx):
    recs = ctx.recs
    calls = {e["data"]["tool_use_id"]: (e, h) for e, h in recs if e["type"] == "tool.call"}
    results = {e["data"]["tool_use_id"]: (e, h) for e, h in recs if e["type"] == "tool.result"}
    decisions = {e["data"]["tool_use_id"]: (e, h) for e, h in recs if e["type"] == "policy.decision"}
    responses = [(e, h) for e, h in recs if e["type"] == "model.exchange" and e["data"].get("phase") == "response"]
    requested = {}
    for e, h in responses:
        for t in e["data"].get("tool_uses") or []:
            requested.setdefault(t["id"], (e, h, t["name"]))

    # TK-X001 / TK-X002: what the model asked for vs what was executed (needs model exchanges and tool calls)
    if responses and calls:
        for tid, (e, h, name) in requested.items():
            if tid not in calls:
                ctx.add("TK-X001", "medium", f"model requested {name} ({tid}) but no execution was recorded",
                        "The model asked for this tool call and no tool.call with the same id exists in the run. The call was skipped, "
                        "ran outside the capture path, or the agent did not report it.", [(e, h)], tool_use_id=tid)
        for tid, (c, ch) in calls.items():
            # ids Tracekit made up itself (an SDK call with no model id passed, an OTel span with no call id) cannot be matched
            if tid in requested or tid.startswith(("tk_", "otel_")):
                continue
            verb = "issued (blocked by policy)" if tid in {t for t, (d, _) in decisions.items() if d["data"].get("decision") == "deny"} else "executed"
            ctx.add("TK-X002", "high", f"{c['data']['name']} ({tid}) {verb} without a matching model request",
                    "A tool call ran whose id never appeared in any recorded model response. Either that model exchange was not "
                    "captured, or something other than the model issued the call (injected or fabricated).", [(c, ch)], tool_use_id=tid)
    elif calls and not responses:
        first = next(iter(calls.values()))
        ctx.add("TK-X000", "info", "model calls not captured: request/execution cross-checks could not run",
                "This run has tool calls but no model exchanges. Enable the model proxy, tracekit_sdk.init() or OpenTelemetry "
                "model spans to check executions against what the model asked for.", [first])

    # TK-X003: retrospective policy violations (OTel / after-the-fact capture)
    for tid, (d, dh) in decisions.items():
        if any("policy would have returned" in r for r in d["data"].get("reasons") or []):
            c = calls.get(tid)
            ev = [c, (d, dh)] if c else [(d, dh)]
            ctx.add("TK-X003", "high", f"policy violation executed: {', '.join(d['data']['rule_ids']) or 'rule'}",
                    "This call was reported after it ran, and the policy would have blocked or held it. " +
                    "; ".join(r for r in d["data"].get("reasons") or [] if "would have" in r), ev, tool_use_id=tid)

    # TK-X004: secrets showed up in tool output or input (redaction fired)
    for tid, (r, rh) in results.items():
        out = r["data"].get("output") or {}
        if out.get("redacted"):
            c = calls.get(tid)
            ctx.add("TK-X004", "medium", f"secret material in the output of {c[0]['data']['name'] if c else 'a tool'}",
                    "Tracekit redacted credentials from this tool's output before recording it. The agent saw the secret.",
                    ([c] if c else []) + [(r, rh)], tool_use_id=tid)

    # TK-X005: risky actions (independent of policy): surfaced so a reviewer sees them even if allowed
    blocked = {tid for tid, (d, _) in decisions.items() if d["data"].get("decision") == "deny"}
    risky_hits = []
    for tid, (c, ch) in calls.items():
        if tid in blocked:  # stopped by policy before it ran
            continue
        cmd = _command(c)
        if not cmd:
            continue
        for label, rx in RISKY:
            if rx.search(cmd):
                res = results.get(tid)
                ok = res[0]["data"].get("ok") if res else None
                risky_hits.append((label, c, ch, res))
                ctx.add("TK-X005", "medium" if ok is not False else "low", f"risky action: {label}",
                        f"`{cmd[:200]}` ({'succeeded' if ok else 'failed' if ok is False else 'no result recorded'})",
                        [(c, ch)] + ([res] if res else []), tool_use_id=tid)
                break

    # say vs do: needs what the agent said, in clear
    texts = [(e, h, t) for e, h in recs for t in [_texts(e)] if t]
    cmds = [(c, ch, _command(c)) for tid, (c, ch) in calls.items() if tid not in blocked]
    cmds = [(c, ch, x) for c, ch, x in cmds if x]
    wrote = [(c, ch) for tid, (c, ch) in calls.items() if c["data"]["name"] in WRITE_TOOLS and tid not in blocked]
    said_text = [e for e, h in recs if e["type"] in ("model.message", "model.exchange")]
    if said_text and not texts:
        e0 = said_text[0]
        ctx.add("TK-X100", "info", "agent text recorded only as hashes: say-vs-do checks could not run",
                "Set content_capture: full to keep text in plain form (with reasoning_capture: true to record agent messages at all) to check claims against actions.",
                [(e0, {e["seq"]: h for e, h in recs}[e0["seq"]])])
    seen_claims = set()
    for e, h, text in texts:
        key = " ".join(text.split()).lower()
        if key in seen_claims:  # the same words recorded twice (model response and the agent's message)
            continue
        seen_claims.add(key)
        later = [(c, ch, x) for c, ch, x in cmds if c["seq"] < e["seq"]]
        for rule, rx, need, title in CLAIMS:
            m = rx.search(text)
            if m and not any(need.search(x) for _, _, x in later):
                ctx.add(rule, "high", title, f"The agent said: “{_snippet(text, m)}”. No executed command before this "
                                           "message matches.", [(e, h)])
        if CLAIMS[0][1].search(text):  # claimed tests pass after the last test run failed
            tests = [(c, ch, x) for c, ch, x in later if TEST_CMD.search(x)]
            if tests:
                c, ch, x = tests[-1]
                res = results.get(c["data"]["tool_use_id"])
                if res and res[0]["data"].get("ok") is False:
                    m = CLAIMS[0][1].search(text)
                    ctx.add("TK-X105", "critical", "claimed tests pass, but the last test run failed",
                            f"Last test command `{x[:160]}` failed; the agent then said “{_snippet(text, m)}”.",
                            [(c, ch), res, (e, h)])
        for rule, rx, contra, title in DENIALS:
            m = rx.search(text)
            if not m:
                continue
            hits = [(c, ch) for c, ch in wrote] if contra is None else [(c, ch) for c, ch, x in cmds if contra.search(x)]
            hits = [x for x in hits if x[0]["seq"] < e["seq"]]
            if hits:
                ctx.add(rule, "critical", title, f"The agent said: “{_snippet(text, m)}”.", [(e, h)] + hits[:5])

    # TK-X120: risky actions the agent never mentioned in what it said afterwards
    if texts and risky_hits:
        final_text = " ".join(t for e, h, t in texts if e["seq"] > min(c["seq"] for _, c, _, _ in risky_hits)).lower()
        if final_text:
            for label, c, ch, res in risky_hits:
                if res and res[0]["data"].get("ok") is False:
                    continue
                words = {"force push": ("force", "--force"), "recursive delete": ("delet", "remov", "rm -"),
                         "history rewrite": ("reset", "rebase", "rewr"), "database migration or drop": ("migrat", "drop"),
                         "package publish": ("publish", "upload"), "privilege escalation": ("sudo", "root")}[label]
                if not any(w in final_text for w in words):
                    later_texts = [(e, h) for e, h, t in texts if e["seq"] > c["seq"]]
                    ctx.add("TK-X120", "high", f"{label} not mentioned in the agent's account",
                            f"`{(_command(c) or '')[:200]}` ran, and nothing the agent said afterwards mentions it.",
                            [(c, ch)] + later_texts[-1:], tool_use_id=c["data"]["tool_use_id"])


def _snippet(text, m, pad=60):
    a, b = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return ("…" if a else "") + text[a:b].replace("\n", " ") + ("…" if b < len(text) else "")


def analyze(records, run_id):
    """records: ledger records (dicts with event + hash). -> list of finding verdicts for run_id."""
    recs = [(r["event"], r["hash"]) for r in records if r and not r.get("elided") and r["event"]["run_id"] == run_id]
    recs.sort(key=lambda x: x[0]["seq"])
    ctx = _Ctx(run_id, recs)
    if recs:
        _detect(ctx)
    seen, out = set(), []
    for f in ctx.out:
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            out.append(f)
    order = {s: i for i, s in enumerate(reversed(SEVERITY))}
    out.sort(key=lambda f: (order[f["severity"]], f["evidence"][0]["seq"] if f["evidence"] else 0))
    return out


def existing(records, run_id):
    return {r["event"]["data"]["verdict"].get("fingerprint") for r in records
            if r and not r.get("elided") and r["event"]["run_id"] == FINDINGS_PREFIX + run_id and r["event"]["type"] == "review"}


def finding_event(verdict):
    from .core import GENESIS, SCHEMA_VERSION, new_id, now_ts
    return {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": GENESIS, "ts": now_ts(),
            "run_id": FINDINGS_PREFIX + verdict["run_id"], "agent_id": "analyzer", "parent_id": None, "source": "sdk",
            "type": "review", "data": {"reviewer": f"{ANALYZER}/{VERSION}", "verdict": verdict}}


def check_bundle(events, hashes):
    """Verifier side: every finding's evidence must exist in the bundle with the cited hash. -> list of problems."""
    probs = []
    for e in events:
        if e.get("type") != "review" or not str(e.get("run_id", "")).startswith(FINDINGS_PREFIX):
            continue
        v = (e.get("data") or {}).get("verdict") or {}
        if v.get("kind") != "finding":
            continue
        for ref in v.get("evidence") or []:
            s, h = ref.get("seq"), ref.get("hash")
            if s not in hashes:
                probs.append(f"seq {e.get('seq')}: finding {v.get('rule')} cites seq {s}, which is not in the bundle")
            elif hashes[s] != h:
                probs.append(f"seq {e.get('seq')}: finding {v.get('rule')} cites seq {s} with hash {str(h)[:12]}, "
                             f"but that record's hash is {str(hashes[s])[:12]} (evidence altered)")
        if v.get("run_id") and FINDINGS_PREFIX + v["run_id"] != e.get("run_id"):
            probs.append(f"seq {e.get('seq')}: finding is filed under {e.get('run_id')} but describes run {v.get('run_id')}")
    return probs


def _fmt(f):
    sev = f["severity"].upper()
    seqs = ",".join(str(x["seq"]) for x in f["evidence"][:6])
    return f"[{sev:8}] {f['rule']}  {f['title']}\n           {f['detail'][:300]}\n           evidence: seq {seqs}"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit analyze", description="Run detectors over a run and sign the findings into the ledger.")
    ap.add_argument("--home", help="signer home (default: from the client config)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--run")
    g.add_argument("--last", action="store_true", help="the most recent run (default)")
    g.add_argument("--all", action="store_true", help="every run in the ledger")
    ap.add_argument("--dry-run", action="store_true", help="print findings, write nothing")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from . import client
    from .ledger import read_records
    home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
    recs = [r for _, r, _ in read_records(os.path.join(home, "ledger", "ledger.jsonl")) if r]
    starts = [r["event"]["run_id"] for r in recs if not r.get("elided") and r["event"]["type"] == "run.start"]
    runs = sorted(set(starts)) if a.all else ([a.run] if a.run else starts[-1:])
    if not runs:
        print("tracekit analyze: no runs in the ledger", file=sys.stderr)
        return 2
    report, wrote = [], 0
    for run in runs:
        found = analyze(recs, run)
        have = existing(recs, run)
        new = [f for f in found if f["fingerprint"] not in have]
        if not a.dry_run:
            for f in new:
                try:
                    resp = client.send(finding_event(f), stream="analyzer")
                except client.SignerUnavailable as e:
                    print(f"tracekit analyze: signer unavailable: {e}", file=sys.stderr)
                    return 2
                if not resp.get("ok"):
                    print(f"tracekit analyze: signer refused a finding: {resp.get('error')}", file=sys.stderr)
                    return 1
                f["signed"] = {"seq": resp.get("seq"), "hash": resp.get("hash")}
                wrote += 1
        report.append({"run_id": run, "findings": found, "new": len(new), "already_signed": len(found) - len(new)})
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            print(f"run {r['run_id']}: {len(r['findings'])} finding(s), {r['new']} new" +
                  ("" if a.dry_run else f", {r['new']} signed") + (f", {r['already_signed']} already in the ledger" if r["already_signed"] else ""))
            for f in r["findings"]:
                print(_fmt(f))
    worst = max((SEVERITY.index(f["severity"]) for r in report for f in r["findings"]), default=-1)
    return 4 if worst >= SEVERITY.index("high") else 0


if __name__ == "__main__":
    sys.exit(main())
