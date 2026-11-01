"""tracekit audit: replay local coding-agent transcripts through the policy engine.

Read-only. Never starts a signer, never writes, never follows a symlink. A replay against today's policy, not a signed
record.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from typing import Any

from .core import scrub
from .hook import transcript_entries
from .report import call_text
from .signer.service import DEFAULT_POLICY, _dotenv, _escaped, _shown, load_policy

DEFAULT_ROOT = os.path.join("~", ".claude", "projects")


def _parse_since(s: str) -> float:
    """Return epoch seconds for --since (e.g. 7d, 24h, 30m, or an ISO date or time, UTC unless it says)."""
    s = s.strip().lower()
    if s.endswith("d") and s[:-1].isdigit():
        return time.time() - int(s[:-1]) * 86400
    if s.endswith("h") and s[:-1].isdigit():
        return time.time() - int(s[:-1]) * 3600
    if s.endswith("m") and s[:-1].isdigit():
        return time.time() - int(s[:-1]) * 60
    try:
        dt = datetime.fromisoformat(s.replace("z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        raise ValueError(f"unrecognised --since {s!r} (use Nd, Nh, Nm or ISO-8601)")


def _session_from_path(path: str) -> str:
    """Best-effort session id from a Claude Code transcript path."""
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
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _safe_open(path: str) -> tuple[Any, str | None]:
    """Open a regular file without following a symlink (as graph._secure_source does). Returns (file, error)."""
    try:
        seen = os.lstat(path)
    except OSError as e:
        return None, f"cannot stat: {e}"
    if not stat.S_ISREG(seen.st_mode):
        return None, "not a regular file or is a symlink"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        return None, f"cannot open: {e}"
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (seen.st_dev, seen.st_ino):
        os.close(fd)
        return None, "changed while it was opened"
    return os.fdopen(fd, "rb"), None


def _iter_transcripts(root: str, unreadable: list):
    """Yield (path, session) for each .jsonl under root, at any depth (a session's subagent files too). Follows no
    symlink; a folder it can't list goes into `unreadable`."""
    root = os.path.realpath(root)   # a root reached through a symlink (macOS /var, a linked ~/.claude) is still the root

    def failed(e):
        unreadable.append({"path": e.filename, "error": f"cannot list: {e}"})
    for dirpath, dirnames, filenames in os.walk(root, onerror=failed, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not name.endswith(".jsonl") or os.path.islink(path):
                continue
            try:   # stay inside root: a Windows directory junction is no symlink to islink, and the walk enters it
                if os.path.commonpath([root, os.path.realpath(path)]) != root:
                    continue
            except ValueError:   # another drive
                continue
            yield path, _session_from_path(path)


def audit(root: str, policy_path: str | None = None, since: str | None = None, show: bool = False) -> dict:
    """Replay tool calls under root. Returns the report dict.

    Counts malformed lines and unreadable files. Never writes.
    """
    since_ts = _parse_since(since) if since else 0.0
    engine = load_policy(policy_path or DEFAULT_POLICY)

    counts = {"allow": 0, "ask": 0, "deny": 0, "flag": 0}
    by_rule: dict[str, int] = {}
    # lean: every call is kept in memory (about 0.5 KB each; --show text is capped at report.CALL_WIDTH); stream the
    # report's lines instead if a real transcript folder outgrows that
    calls: list[dict] = []
    skipped_malformed = 0
    unreadable: list[dict] = []

    for path, session in _iter_transcripts(root, unreadable):
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        try:
            for _n, entry in transcript_entries(f):
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
                        "time": at.astimezone(timezone.utc).isoformat() if at else None,
                        "tool": tool,
                        "verdict": verdict,
                        "rule_ids": decision.get("rule_ids") or [],
                    }
                    if show:   # what an approver sees: redacted as the signer redacts it (.env content too)
                        rec["text"] = call_text(tool, _shown(scrub(args), _dotenv(args)))
                    calls.append(rec)
        except (OSError, RecursionError) as e:   # a read that fails, or a line nested past what json.loads takes
            unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
        finally:
            f.close()

    report = {
        "disclaimer": "a replay against today's policy, not a signed record",
        "policy": policy_path or DEFAULT_POLICY,
        "policy_hash": engine.policy_hash,
        "since": since,
        "counts": counts,
        "by_rule": by_rule,
        "skipped_malformed": skipped_malformed,
        "unreadable": unreadable,
        "calls": calls,
    }
    return report


def format_report(report: dict, as_json: bool = False) -> str:
    if as_json:
        return json.dumps(report, indent=2, sort_keys=True)
    lines = [
        report["disclaimer"],
        f"policy: {report['policy']}",
        f"policy_hash: {report['policy_hash']}",
        "",
        "counts:",
    ]
    for v in ("deny", "ask", "flag", "allow"):
        lines.append(f"  {v}: {report['counts'].get(v, 0)}")
    if report["by_rule"]:
        lines.append("")
        lines.append("by rule:")
        for rid, n in sorted(report["by_rule"].items()):
            lines.append(f"  {rid}: {n}")
    lines.append("")
    lines.append(f"skipped malformed lines: {report['skipped_malformed']}")
    lines.append(f"unreadable files: {len(report['unreadable'])}")
    if report["calls"]:
        lines.append("")
        lines.append("calls:")
        for c in report["calls"]:
            t = c["time"] or "unknown-time"
            extra = f"  text={c['text']!r}" if "text" in c else ""
            lines.append(f"  {c['session']}  {t}  {c['tool']}  {c['verdict']}  rules={','.join(c['rule_ids'])}{extra}")
    # a transcript the agent wrote can hold control characters: print them as text, as tracekit report does
    return "\n".join(_escaped(line) for line in lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit audit", description="replay the tool calls in your coding agents' "
                                 "transcripts (Claude Code) through the policy and count what it would have held or "
                                 "denied. Read-only, local, and a replay against today's policy, not a signed record.")
    ap.add_argument("root", nargs="?", default=DEFAULT_ROOT, help="the transcripts' folder (default: ~/.claude/projects)")
    ap.add_argument("--policy", help="a policy file (default: the dev pack, tracekit/policy2/packs/dev.yaml)")
    ap.add_argument("--since", help="7d, 24h, 30m, or an ISO date or time (UTC unless it says)")
    ap.add_argument("--show", action="store_true", help="also print each call, with secrets redacted")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)
    root = os.path.expanduser(a.root)
    if not os.path.isdir(root):
        print(f"tracekit audit: no such folder: {root} (Claude Code keeps its transcripts in ~/.claude/projects)",
              file=sys.stderr)
        return 2
    try:
        report = audit(root, a.policy, a.since, a.show)
    except (ValueError, OSError) as e:   # an unreadable --since; a policy file that's missing or doesn't lint
        print(f"tracekit audit: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(format_report(report, as_json=a.json))
    return 0
