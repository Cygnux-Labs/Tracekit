"""tracekit audit: replay local coding-agent transcripts through the policy engine.

Read-only. Never starts a signer, never writes, never follows a symlink. A replay against today's policy, not a signed
record.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .core import scrub
from .graph import _open_regular
from .hook import transcript_entries
from .report import DECISIONS, _counts, _days, call_text, share_rules, when
from .signer.service import DEFAULT_POLICY, _dotenv, _escaped, _shown, load_policy
from .view import ENGINE_RULES


def default_root():
    """Claude Code's transcripts' folder: projects/ in $CLAUDE_CONFIG_DIR when set (Claude Code's own setting for
    another config dir), else in ~/.claude, as install.user_settings finds its settings."""
    return os.path.join(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude"),
                        "projects")


def _session_from_path(path: str) -> str:
    """Best-effort session id from a Claude Code transcript's path under the root: a subagent's file
    (<session>/subagents/agent-*.jsonl, a workflow's agents' in <session>/subagents/workflows/<workflow>/) counts under
    its session."""
    folders = os.path.dirname(path).split(os.sep)
    if "subagents" in folders[1:]:
        return folders[folders.index("subagents", 1) - 1]
    base = os.path.basename(path)
    if base.endswith(".jsonl"):
        return base[:-6]
    return base


def _entry_time(entry: dict) -> datetime | None:
    """Time of a transcript entry if present (Claude Code uses 'timestamp'), UTC unless it says."""
    ts = entry.get("timestamp")
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
        except (ValueError, OverflowError):   # not a time, or one UTC can't hold (0001-01-01T00:00+05:00)
            pass
    return None


def _safe_open(path: str) -> tuple[Any, str | None]:
    """Open a regular file without following a symlink (graph._open_regular). Returns (file, error)."""
    try:
        return os.fdopen(_open_regular(path), "rb"), None
    except OSError as e:
        return None, str(e)


def _iter_transcripts(root: str, unreadable: list):
    """Yield (path, session) for each .jsonl under root, at any depth (a session's subagent files too). Follows no
    symlink; a folder it can't list goes into `unreadable`."""
    root = os.path.realpath(root)   # a root reached through a symlink (macOS /var, a linked ~/.claude) is still the root

    def failed(e):
        unreadable.append({"path": e.filename, "error": f"cannot list: {e}"})
    for dirpath, dirnames, filenames in os.walk(root, onerror=failed, followlinks=False):
        # in order: which file a copied call counts in (the first) is the same on every filesystem
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if not name.endswith(".jsonl") or os.path.islink(path):
                continue
            try:   # stay inside root: a Windows directory junction is no symlink to islink, and the walk enters it
                if os.path.commonpath([root, os.path.realpath(path)]) != root:
                    continue
            except ValueError:   # another drive
                continue
            yield path, _session_from_path(os.path.relpath(path, root))


def audit(root: str, policy_path: str | None = None, since: str | None = None, show: bool = False) -> dict:
    """Replay tool calls under root. Returns the report dict.

    Counts malformed lines and unreadable files. Never writes.
    """
    now = time.time()
    try:
        since_ts = when(since, now) if since else 0.0
    except argparse.ArgumentTypeError as e:   # report's --since type: here an unreadable --since is a ValueError
        raise ValueError(str(e)) from None
    if since_ts >= now:
        raise ValueError(f"--since {since[:40]!r} is not in the past")
    engine = load_policy(policy_path or DEFAULT_POLICY)

    counts = {"allow": 0, "ask": 0, "deny": 0, "flag": 0}
    by_rule: dict[str, int] = {}
    # lean: every call is kept in memory (about 1 KB each, 2 KB with --json, measured on 158k calls; --show text is
    # capped at report.CALL_WIDTH); stream the report's lines instead if a real transcript folder outgrows that
    calls: list[dict] = []
    skipped_malformed = 0
    unreadable: list[dict] = []
    seen: set[bytes] = set()   # calls by id and content: a resumed or forked session's file repeats those it copied

    for path, session in _iter_transcripts(root, unreadable):
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        try:
            for _n, entry in transcript_entries(f, final=True):
                if entry is None:
                    skipped_malformed += 1
                    continue
                if entry.get("type") != "assistant":
                    continue
                at = _entry_time(entry)
                if at is not None and at.timestamp() < since_ts:
                    continue
                msg = entry.get("message") if isinstance(entry.get("message"), dict) else {}
                content = msg.get("content")
                blocks = content if isinstance(content, list) else []
                for b in blocks:
                    if not isinstance(b, dict) or b.get("type") != "tool_use":
                        continue
                    tool = b.get("name") if isinstance(b.get("name"), str) else ""
                    args = b.get("input") if isinstance(b.get("input"), dict) else {}
                    try:   # the same id and call: a copy (a backend may reuse an id for another call)
                        key = isinstance(b.get("id"), str) and hashlib.sha256(json.dumps(
                            [b["id"], tool, args], sort_keys=True, default=str).encode()).digest()
                    except (RecursionError, ValueError):   # arguments the encoder can't take: counted
                        key = None
                    if key in seen:
                        continue
                    if key:
                        seen.add(key)
                    try:
                        decision = engine.decide(tool, args)
                    except Exception:   # the signer denies a call its engine fails on (signer.service._evaluate)
                        decision = {"verdict": "deny", "rule_ids": ["TK-ENGINE-ERROR"]}
                    verdict = decision.get("verdict", "allow")
                    counts[verdict] = counts.get(verdict, 0) + 1
                    for rid in decision.get("rule_ids") or []:
                        by_rule[rid] = by_rule.get(rid, 0) + 1
                    rec = {
                        "session": session,
                        "time": at.isoformat() if at else None,
                        "tool": tool,
                        "verdict": verdict,
                        "rule_ids": decision.get("rule_ids") or [],
                    }
                    if show:   # what an approver sees: redacted as the signer redacts it (.env content too)
                        rec["text"] = call_text(tool, _shown(scrub(args), _dotenv(args)))
                    calls.append(rec)
        except OSError as e:   # a read that fails (a line nested past what json.loads takes is malformed)
            unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
        finally:
            f.close()

    report = {
        "disclaimer": "a replay against today's policy, not a signed record",
        "policy": policy_path or DEFAULT_POLICY,
        "policy_hash": engine.policy_hash,
        "since": since,
        "sessions": len({c["session"] for c in calls}),
        "counts": counts,
        "by_rule": by_rule,
        "reasons": {**{i: ENGINE_RULES[i] for i in by_rule if i in ENGINE_RULES},   # what each rule is, as the viewer says it
                    **{r["id"]: r.get("reason") or r.get("label", "") for _, r, *_ in engine.rules if r["id"] in by_rule}},
        # the policy's section of each rule: an engine check has none
        "sections": {r["id"]: sec for sec, r, *_ in engine.rules if r["id"] in by_rule},
        "skipped_malformed": skipped_malformed,
        "unreadable": unreadable,
        "calls": calls,
    }
    return report


def format_report(report: dict, as_json: bool = False, every: bool = False) -> str:
    """The report as text: what Tracekit would have stopped first, then each denied or held call (every call with
    `every`); or the whole report as JSON."""
    if as_json:
        return json.dumps(report, indent=2, sort_keys=True)
    n, s = report["counts"], report["sessions"]
    total = sum(n.values())
    window = f" since {report['since']}" if report["since"] else ""
    lines = [
        report["disclaimer"],
        f"policy: {report['policy']} ({report['policy_hash']})",
        "",
        f"{total} tool call{'s' * (total != 1)} in {s} session{'s' * (s != 1)}{window}: Tracekit would have denied "
        f"{n.get('deny', 0)} and held {n.get('ask', 0)} for a person; it would have flagged {n.get('flag', 0)} "
        f"and allowed {n.get('allow', 0)}.",
        "",
        "counts:",
    ]
    for v in ("deny", "ask", "flag", "allow"):
        lines.append(f"  {v}: {n.get(v, 0)}")
    if report["by_rule"]:
        lines.append("")
        lines.append("by rule:")
        for rid, k in sorted(report["by_rule"].items(), key=lambda x: (-x[1], x[0])):
            reason = report["reasons"].get(rid, "")
            lines.append(f"  {rid}: {k}" + (f"  ({reason})" if reason else ""))
    lines.append("")
    lines.append(f"skipped malformed lines: {report['skipped_malformed']}")
    lines.append(f"unreadable files: {len(report['unreadable'])}")
    shown = [c for c in report["calls"] if every or c["verdict"] in ("deny", "ask")]
    if shown:
        lines.append("")
        lines.append("calls:" if every else "denied and held calls (--all for every call):")
        for c in shown:
            t = c["time"] or "unknown-time"
            extra = f"  text={c['text']!r}" if "text" in c else ""
            lines.append(f"  {c['session']}  {t}  {c['tool']}  {c['verdict']}  rules={','.join(c['rule_ids'])}{extra}")
    # a transcript the agent wrote can hold control characters: print them as text, as tracekit report does
    return "\n".join(_escaped(line) for line in lines) + "\n"


def share(report: dict) -> str:
    """The report's counts alone, for a person to post as a field report (docs/field-reports.md), as tracekit report
    --share gives them: of --since, the window's length; no session, path, policy file, time, call or rule
    description, and no rule id but Tracekit's own (report.share_rules). A rule is why its call was decided when its
    section is the call's decision; an engine check, which has no section, is not placed."""
    n, s, secs = report["counts"], report["sessions"], report["sections"]
    by_rule = collections.Counter((c["verdict"], rid, secs[rid] == c["verdict"] if rid in secs else None)
                                  for c in report["calls"] for rid in c["rule_ids"])
    window = _days(time.time() - when(report["since"])) if report["since"] else "every transcript"
    lines = [f"Tracekit {__version__} field report (tracekit audit --share): {window}",
             f"{report['disclaimer']}: {s:,} Claude Code session{'s' * (s != 1)}",
             f"Tool calls: {sum(n.values()):,}   " + _counts({k: n.get(k, 0) for k in DECISIONS}),
             "Calls by decision and rule (one call can match several rules):" + " none" * (not by_rule),
             *share_rules(by_rule)]
    return "\n".join(_escaped(line) for line in lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit audit", description="replay the tool calls in your coding agents' "
                                 "transcripts (Claude Code) through the policy and count what it would have held or "
                                 "denied. Read-only, local, and a replay against today's policy, not a signed record.")
    ap.add_argument("root", nargs="?", default=default_root(), help="the transcripts' folder (default: "
                    "$CLAUDE_CONFIG_DIR/projects when it is set, else ~/.claude/projects)")
    ap.add_argument("--policy", help="a policy file (default: the dev pack, tracekit/policy2/packs/dev.yaml)")
    ap.add_argument("--since", help="7d, 24h, 30m, or an ISO date or time (UTC unless it says)")
    ap.add_argument("--show", action="store_true", help="also print each call, with secrets redacted")
    ap.add_argument("--all", action="store_true", help="list every call, not only the denied and held ones")
    o = ap.add_mutually_exclusive_group()
    o.add_argument("--json", action="store_true", help="print the report as JSON (every call)")
    o.add_argument("--share", action="store_true", help="print its counts alone, to post as a field report: no "
                                                       "session, path, time or call")
    a = ap.parse_args(argv)
    root = os.path.expanduser(a.root)
    if not os.path.isdir(root):
        print(f"tracekit audit: no such folder: {root} (Claude Code keeps its transcripts in "
              "$CLAUDE_CONFIG_DIR/projects when it is set, else ~/.claude/projects)", file=sys.stderr)
        return 2
    try:
        report = audit(root, a.policy, a.since, a.show)
    except (ValueError, OSError) as e:   # an unreadable --since; a policy file that's missing or doesn't lint
        print(f"tracekit audit: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(share(report) if a.share else format_report(report, as_json=a.json, every=a.all))
    return 0
