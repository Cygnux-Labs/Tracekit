"""tracekit audit: replay local coding-agent transcripts through the policy engine.

Read-only. Never starts a signer, never writes, never follows symlinks out of the
transcript folders. A replay against today's policy, not a signed record.
"""
from __future__ import annotations

import json
import os
import stat
import time
from datetime import datetime, timezone
from typing import Any

from .core import scrub
from .hook import transcript_entries
from .signer.service import DEFAULT_POLICY, load_policy


def _parse_since(s: str) -> float:
    """Return epoch seconds for --since (e.g. 7d, 24h, 30m, or ISO date)."""
    if not s:
        return 0.0
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


def _entry_time(entry: dict) -> float | None:
    """Timestamp of a transcript entry if present (Claude Code uses 'timestamp')."""
    ts = entry.get("timestamp")
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return None


def _safe_open(path: str) -> tuple[Any, str | None]:
    """Open a regular file without following symlinks. Returns (file, error)."""
    try:
        st = os.lstat(path)
    except OSError as e:
        return None, f"cannot stat: {e}"
    if not stat.S_ISREG(st.st_mode) or os.path.islink(path):
        return None, "not a regular file or is a symlink"
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        f = os.fdopen(fd, "rb")
        return f, None
    except OSError as e:
        return None, f"cannot open: {e}"


def _iter_transcripts(root: str):
    """Yield (path, session) for Claude Code style transcripts under root.

    Does not follow symlinks that leave the root. Skips unreadable paths.
    """
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # prune symlink dirs
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            # stay inside root
            try:
                if not os.path.commonpath([root, os.path.realpath(path)]).startswith(root):
                    continue
            except ValueError:
                continue
            yield path, _session_from_path(path)


def audit(root: str, policy_path: str | None = None, since: str | None = None,
          show: bool = False, as_json: bool = False) -> dict:
    """Replay tool calls under root. Returns the report dict.

    Counts malformed lines and unreadable files. Never writes.
    """
    since_ts = _parse_since(since) if since else 0.0
    engine = load_policy(policy_path or DEFAULT_POLICY)

    counts = {"allow": 0, "ask": 0, "deny": 0, "flag": 0}
    by_rule: dict[str, int] = {}
    calls: list[dict] = []
    skipped_malformed = 0
    unreadable: list[dict] = []

    for path, session in _iter_transcripts(root):
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
                ts = _entry_time(entry)
                if ts is not None and ts < since_ts:
                    continue
                msg = entry.get("message") if isinstance(entry.get("message"), dict) else {}
                content = msg.get("content")
                blocks = content if isinstance(content, list) else []
                for b in blocks:
                    if not isinstance(b, dict) or b.get("type") != "tool_use":
                        continue
                    tool = b.get("name") or ""
                    args = b.get("input") if isinstance(b.get("input"), dict) else {}
                    try:
                        decision = engine.decide(tool, args)
                    except Exception:
                        skipped_malformed += 1
                        continue
                    verdict = decision.get("verdict", "allow")
                    counts[verdict] = counts.get(verdict, 0) + 1
                    for rid in decision.get("rule_ids") or []:
                        by_rule[rid] = by_rule.get(rid, 0) + 1
                    rec = {
                        "session": session,
                        "time": datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None,
                        "tool": tool,
                        "verdict": verdict,
                        "rule_ids": decision.get("rule_ids") or [],
                    }
                    if show:
                        cmd = args.get("command") or args.get("cmd") or json.dumps(args)
                        rec["text"] = scrub(cmd) if isinstance(cmd, str) else scrub(json.dumps(cmd))
                    calls.append(rec)
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
    return "\n".join(lines) + "\n"
