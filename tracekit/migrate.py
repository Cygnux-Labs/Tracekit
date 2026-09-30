"""Read or convert v0.1 ledgers (hash-chained, unsigned) into schema-v1 events.

The v0.1 chain is verified first and the result is reported. Converted events carry
source="migrated": they are only as trustworthy as the v0.1 file was, and signing them
later proves only that they have not changed *since migration*."""
import hashlib
import json
import sys

from . import privacy
from .core import GENESIS, SCHEMA_VERSION, canon, new_id
from . import schema as schema_mod

LEGACY_POLICY_HASH = "sha256:" + hashlib.sha256(b"tracekit v0.1 policy (not recorded)").hexdigest()


def _ts(t):
    import datetime as dt
    return dt.datetime.fromtimestamp(float(t), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def verify_v01(path):
    prev, n, problems = GENESIS, 0, []
    recs = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                problems.append(f"line {i}: not JSON"); continue
            body = {k: v for k, v in r.items() if k != "hash"}
            if hashlib.sha256(canon(body).encode()).hexdigest() != r.get("hash"):
                problems.append(f"line {i}: hash mismatch")
            if r.get("prev") != prev or r.get("seq") != n:
                problems.append(f"line {i}: chain/seq break")
            prev, n = r.get("hash"), n + 1
            recs.append(r)
    return recs, problems


def convert(records, cc="hashed"):
    out = []
    started = set()
    for r in records:
        ev0 = r.get("event")
        base = {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": GENESIS, "ts": _ts(r["ts"]),
                "run_id": r.get("session_id") or "unknown", "agent_id": r.get("agent_id") or "main",
                "parent_id": "main" if r.get("agent_id") else None, "source": "migrated"}
        def run_start():
            return {**base, "id": new_id(), "agent_id": "main", "parent_id": None, "type": "run.start", "data": {
                "agent": {"name": r.get("agent") or "claude-code", "version": None}, "model": None, "repo": None, "commit": None,
                "cwd": r.get("cwd"), "host": "unknown (v0.1)", "os_user": "unknown (v0.1)", "fail_mode": "open",
                "policy": {"version": "v0.1", "hash": LEGACY_POLICY_HASH}, "capture_sources": ["hook", "transcript"],
                "sandbox": "unknown", "content_capture": cc, "reasoning_capture": True, "signer_isolation": "same-user"}}
        if base["run_id"] not in started and ev0 not in ("judge_verdict",):
            started.add(base["run_id"]); out.append(run_start())
            if ev0 == "SessionStart":
                continue
        if ev0 == "UserPromptSubmit":
            out.append({**base, "type": "user.prompt", "data": {"content": privacy.content(r.get("prompt") or "", cc)}})
        elif ev0 == "PreToolUse":
            tid = r.get("tool_use_id") or ("v01-" + str(r["seq"]))
            pol = r.get("policy") or {}
            out.append({**base, "type": "tool.call", "data": {"tool_use_id": tid, "name": r.get("tool_name") or "?",
                                                               "input": privacy.tool_input(r.get("tool_name"), r.get("tool_input") or {}, cc)}})
            out.append({**base, "id": new_id(), "type": "policy.decision", "data": {
                "tool_use_id": tid, "decision": "deny" if pol.get("decision") == "deny" else ("flag" if pol.get("flags") else "allow"),
                "rule_ids": [], "reasons": list(pol.get("reasons", [])) + list(pol.get("flags", []))}})
        elif ev0 == "PostToolUse":
            resp = r.get("tool_response")
            ok = not r.get("failed") and not (isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted")))
            out.append({**base, "type": "tool.result", "data": {"tool_use_id": r.get("tool_use_id") or "unknown", "ok": bool(ok),
                                                                 "output": privacy.content(resp if resp is not None else "", cc),
                                                                 "duration_ms": r.get("duration_ms")}})
        elif ev0 == "model_turn":
            for b in r.get("blocks", []):
                if b.get("kind") in ("thinking", "text", "thinking_redacted"):
                    kind = {"thinking_redacted": "thinking_withheld"}.get(b["kind"], b["kind"])
                    out.append({**base, "id": new_id(), "type": "model.message",
                                "data": {"kind": kind, "message_id": r.get("message_id"), "content": privacy.content(b.get("text", ""), cc)}})
        elif ev0 == "SessionEnd":
            out.append({**base, "agent_id": "main", "parent_id": None, "type": "run.end", "data": {"reason": str(r.get("reason") or "session end")}})
        elif ev0 == "judge_verdict":
            out.append({**base, "type": "review", "data": {"reviewer": r.get("judge_model") or "judge", "verdict": r.get("verdict") or {}}})
    for i, e in enumerate(out):
        errs = schema_mod.validate(e)
        if errs:
            raise ValueError(f"converted event {i} invalid: {errs[:3]}")
    return out


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="tracekit migrate")
    ap.add_argument("ledger")
    ap.add_argument("--out", help="write v1 events (unsigned) as JSONL")
    ap.add_argument("--send", action="store_true", help="send the converted events to tracekitd to be signed")
    ap.add_argument("--full-content", action="store_true", help="keep v0.1 content in clear (default: hash it, per docs/privacy.md)")
    a = ap.parse_args(argv)
    recs, problems = verify_v01(a.ledger)
    print(f"v0.1 ledger: {len(recs)} records; chain " + ("intact" if not problems else f"BROKEN ({len(problems)} problems, e.g. {problems[0]})"))
    evs = convert(recs, "full" if a.full_content else "hashed")
    print(f"converted to {len(evs)} v1 events (source=migrated)")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            for e in evs:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print("wrote", a.out)
    if a.send:
        from . import client
        for e in evs:
            e = {k: v for k, v in e.items() if k not in ("seq", "prev_hash")}
            client.send(e)
        print("sent to tracekitd")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
