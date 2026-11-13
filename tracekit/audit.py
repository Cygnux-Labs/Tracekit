"""tracekit audit: replay local coding-agent transcripts through the policy engine.

Read-only. Never starts a signer, never writes, never follows a symlink. A replay against today's policy, not a signed
record.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .agent_hooks import AGENT_NAMES, UnreadableCall, _blocked, tool as hook_tool
from .core import scrub
from .graph import _open_regular
from .hook import transcript_entries
from .report import DECISIONS, _counts, _days, _wait, call_text, share_rules, when
from .signer.service import DEFAULT_POLICY, _dotenv, _escaped, _shown, evaluate, load_policy
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


def _entry_time(entry: dict, key: str = "timestamp") -> datetime | None:
    """Time of a transcript entry if present (Claude Code uses 'timestamp'), UTC unless it says."""
    ts = entry.get(key)
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


def _not_regular(path: str) -> str | None:
    """What `path` is, when it is no regular file (_safe_open refuses it), else None. A symlink is followed to say
    what it names: Linux's <(...) gives one to a pipe."""
    try:
        if stat.S_ISREG(os.lstat(path).st_mode):
            return None
        mode = os.stat(path).st_mode
    except OSError:   # missing (the open's own error says so), or a symlink to nothing
        return "a symlink, which audit doesn't follow" if os.path.islink(path) else None
    return ("a pipe (as <(...) gives); send it to --calls -" if stat.S_ISFIFO(mode) else
            "a symlink, which audit doesn't follow" if os.path.islink(path) else
            "a directory" if stat.S_ISDIR(mode) else "not a regular file")


def gemini_root():
    """Gemini CLI's sessions' folder: .gemini/tmp in $GEMINI_CLI_HOME when set (Gemini CLI's own setting for another
    home), else in ~ (gemini-cli 0.68: utils/paths.ts homedir, config/storage.ts getGlobalTempDir)."""
    return os.path.join(os.environ.get("GEMINI_CLI_HOME") or os.path.expanduser("~"), ".gemini", "tmp")


def _iter_transcripts(root: str, unreadable: list, suffixes: tuple = (".jsonl",)):
    """Yield (path, Claude Code session) for each file under root ending in one of `suffixes`, at any depth (a
    session's subagent files too). Follows no symlink; a folder it can't list goes into `unreadable`."""
    root = os.path.realpath(root)   # a root reached through a symlink (macOS /var, a linked ~/.claude) is still the root

    def failed(e):
        unreadable.append({"path": e.filename, "error": f"cannot list: {e}"})
    for dirpath, dirnames, filenames in os.walk(root, onerror=failed, followlinks=False):
        # in order: which file a copied call counts in (the first) is the same on every filesystem
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if not name.endswith(suffixes) or os.path.islink(path):
                continue
            try:   # stay inside root: a Windows directory junction is no symlink to islink, and the walk enters it
                if os.path.commonpath([root, os.path.realpath(path)]) != root:
                    continue
            except ValueError:   # another drive
                continue
            yield path, _session_from_path(os.path.relpath(path, root))


def _tool_uses(entry: dict):
    """(block, tool, args) for each tool_use block in a transcript line's message, as Claude Code and Cursor write it."""
    msg = entry.get("message") if isinstance(entry.get("message"), dict) else {}
    content = msg.get("content")
    for b in content if isinstance(content, list) else []:
        if isinstance(b, dict) and b.get("type") == "tool_use":
            yield (b, b.get("name") if isinstance(b.get("name"), str) else "",
                   b.get("input") if isinstance(b.get("input"), dict) else {})


def _claude_code(root: str, since_ts: float, unreadable: list):
    """Claude Code's reader: (time, session, tool, args) for each tool use in the transcripts under root, None for a
    line that isn't JSON. A tool use whose id and call were read already (a resumed or forked session's file repeats
    those it copied) is yielded once."""
    seen: set[bytes] = set()
    for path, session in _iter_transcripts(root, unreadable):
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        try:
            for _n, entry in transcript_entries(f, final=True):
                if entry is None:
                    yield None
                    continue
                if entry.get("type") != "assistant":
                    continue
                at = _entry_time(entry)
                if at is not None and at.timestamp() < since_ts:
                    continue
                for b, tool, args in _tool_uses(entry):
                    try:   # the same id and call: a copy (a backend may reuse an id for another call)
                        key = isinstance(b.get("id"), str) and hashlib.sha256(json.dumps(
                            [b["id"], tool, args], sort_keys=True, default=str).encode()).digest()
                    except (RecursionError, ValueError):   # arguments the encoder can't take: counted
                        key = None
                    if key in seen:
                        continue
                    if key:
                        seen.add(key)
                    yield at, session, tool, args
        except OSError as e:   # a read that fails (a line nested past what json.loads takes is malformed)
            unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
        finally:
            f.close()


def _gemini_calls(entry: dict):
    """(time, call) for each tool call a Gemini CLI session record holds: a message line's own, those of a $set's full
    history (an older checkpoint) or of a pre-v0.39 session's messages. None for a record whose messages or tool calls
    aren't the lists and objects Gemini CLI writes."""
    holder = entry["$set"] if isinstance(entry.get("$set"), dict) else entry
    held = holder.get("messages", [entry])
    if not isinstance(held, list):
        yield None
        return
    for msg in held:
        if not isinstance(msg, dict):
            yield None
        elif msg.get("type") == "gemini" and "toolCalls" in msg:
            if not isinstance(msg["toolCalls"], list):
                yield None
                continue
            for c in msg["toolCalls"]:
                yield (_entry_time(c) or _entry_time(msg), c) if isinstance(c, dict) else None


def _gemini_layout(real: str):
    """(folder to walk, what stands above it in <project>/chats/...) for a ROOT that is Gemini CLI's tmp folder, the
    .gemini folder or a home that holds it, one project's folder or its chats folder; a ValueError for any other."""
    def has(*p):
        return os.path.isdir(os.path.join(real, *p))
    if has(".gemini", "tmp"):
        return os.path.join(real, ".gemini", "tmp"), []
    if os.path.basename(real) == ".gemini" and has("tmp"):
        return os.path.join(real, "tmp"), []
    if has("chats") and not has("chats", "chats"):   # a project: a project named chats holds one, a tmp holds that
        return real, [""]
    if os.path.basename(real) == "chats" and not has("chats"):
        return real, ["", "chats"]
    try:
        if os.path.basename(real) == "tmp" or any(os.path.isdir(os.path.join(real, d, "chats"))
                                                   for d in os.listdir(real)):
            return real, []
    except OSError:   # a folder it can't list: _iter_transcripts reports it
        return real, []
    raise ValueError(f"{real} is not a Gemini CLI folder: give its tmp folder (~/.gemini/tmp, or .gemini/tmp in "
                     "$GEMINI_CLI_HOME), a project's folder in it, or that project's chats folder")


def _gemini(root: str, since_ts: float, unreadable: list):
    """Gemini CLI's reader: (time, session, tool, args) for each tool call in the session files under root, its tmp
    folder, a project's or its chats folder (<project>/chats/session-*.jsonl, a subagent's chats/<parent session id>/<id>.jsonl, and the session-*.json
    and <id>.json written before v0.39), None for a record that isn't what Gemini CLI writes. A message is written
    again on each update: a call counts once in its session, by its id, as its last copy has it, and stays counted
    after a $rewindTo drops it."""
    seen: set[bytes] = set()
    folder, above = _gemini_layout(os.path.realpath(root))
    for path, _ in _iter_transcripts(folder, unreadable, (".jsonl", ".json")):
        parts = above + os.path.relpath(path, folder).split(os.sep)   # by depth: a project may be named chats
        own = len(parts) == 3 and parts[1] == "chats" and parts[2].startswith("session-")
        sub = len(parts) == 4 and parts[1] == "chats"
        if not own and not sub:
            continue   # the project's other files (logs.json, checkpoints, an activity log)
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        session = parts[2] if sub else None   # a subagent's counts under its parent's session
        calls: dict = {}   # call id -> (time, tool, args), its last copy
        try:
            if path.endswith(".json"):
                try:
                    entries = [json.loads(f.read())]
                except (ValueError, RecursionError):
                    entries = [None]
            else:
                entries = (e for _n, e in transcript_entries(f, final=True))
            for entry in entries:
                if not isinstance(entry, dict):
                    yield None
                    continue
                if session is None and isinstance(entry.get("sessionId"), str):
                    session = entry["sessionId"]
                for item in _gemini_calls(entry):
                    if item is None:
                        yield None
                        continue
                    at, c = item
                    cid = c.get("id") if isinstance(c.get("id"), str) else (None, len(calls))   # no id: its own call
                    calls[cid] = (at, c.get("name") if isinstance(c.get("name"), str) else "",
                                  c.get("args") if isinstance(c.get("args"), dict) else {})
        except OSError as e:
            unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
        finally:
            f.close()
        session = session or parts[2].rsplit(".", 1)[0]
        for cid, (at, tool, args) in calls.items():
            if at is not None and at.timestamp() < since_ts:
                continue
            try:   # the same id and call in another file of the session (a resumed pre-v0.39 session's .jsonl
                # repeats its .json's): a copy
                key = isinstance(cid, str) and hashlib.sha256(json.dumps(
                    [session, cid, tool, args], sort_keys=True, default=str).encode()).digest()
            except (RecursionError, ValueError):   # arguments the encoder can't take: counted
                key = None
            if key in seen:
                continue
            if key:
                seen.add(key)
            yield at, session, tool, args


def cursor_root():
    """Cursor's transcripts' folder, for both its IDE's agent and the cursor-agent CLI."""
    return os.path.join(os.path.expanduser("~"), ".cursor", "projects")


def _cursor(root: str, since_ts: float, unreadable: list):
    """Cursor's reader: (None, session, tool, args) for each tool use in the agent transcripts under root, which is
    the projects folder, one project's folder or its agent-transcripts folder (<project>/agent-transcripts/<id>/
    <id>.jsonl, an older build's flat <id>.jsonl, a subagent's in <id>/subagents/, which counts under <id>), None for
    a line that isn't JSON. A line has no time and no id: a file
    last written before since_ts is skipped and one written since counts whole, and every line counts, copies too."""
    real = os.path.realpath(root)
    # root may be the projects folder, one project's folder, or that project's agent-transcripts folder
    if os.path.basename(real) == "agent-transcripts":
        above = ["", "agent-transcripts"]
    elif os.path.isdir(os.path.join(real, "agent-transcripts")):
        above = [""]
    else:
        above = []
    for path, _ in _iter_transcripts(root, unreadable):
        folders = above + os.path.relpath(path, real).split(os.sep)
        if len(folders) < 3 or folders[1] != "agent-transcripts":
            continue
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        try:
            if os.fstat(f.fileno()).st_mtime < since_ts:
                continue
            for _n, entry in transcript_entries(f, final=True):
                if entry is None:
                    yield None
                elif entry.get("role") == "assistant":
                    for _b, tool, args in _tool_uses(entry):
                        yield None, folders[2].removesuffix(".jsonl"), tool, args
        except OSError as e:
            unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
        finally:
            f.close()


def cline_root():
    """Cline's sessions' folder (v4 and later), as the Cline SDK resolves it: $CLINE_SESSION_DATA_DIR, else sessions/
    in $CLINE_DATA_DIR, else data/sessions in $CLINE_DIR or ~/.cline."""
    data = os.environ.get("CLINE_DATA_DIR", "").strip() or os.path.join(
        os.environ.get("CLINE_DIR", "").strip() or os.path.join(os.path.expanduser("~"), ".cline"), "data")
    return os.environ.get("CLINE_SESSION_DATA_DIR", "").strip() or os.path.join(data, "sessions")


def cline_roots():
    """Cline's default folders: its sessions' folder (cline_root), and the tasks' folder that releases before 4.0 kept
    in VS Code's global storage, which Cline 4 reads but doesn't move: on macOS, Linux and Windows."""
    home = os.path.expanduser("~")
    storage = [os.path.join(home, "Library", "Application Support", "Code"), os.path.join(home, ".config", "Code")]
    if os.environ.get("APPDATA", "").strip():
        storage.append(os.path.join(os.environ["APPDATA"].strip(), "Code"))
    return [cline_root(), *(os.path.join(s, "User", "globalStorage", "saoudrizwan.claude-dev", "tasks")
                            for s in storage)]


def _cline(root: str, since_ts: float, unreadable: list):
    """Cline's reader: (time, task, tool, args) for each tool_use block of an assistant message in the tasks under
    root, a v4 sessions folder (<id>/<id>.messages.json, {"messages": [...]}) or a pre-v4 tasks folder
    (<id>/api_conversation_history.json, a list of messages). A message's time is its `ts` (ms), else the file's
    modification time; a file that isn't JSON of that shape is one malformed entry. Follows no symlink, and stays
    inside root as Claude Code's reader does."""
    root = os.path.realpath(root)
    try:
        tasks = sorted(os.listdir(root))
    except OSError as e:
        unreadable.append({"path": root, "error": f"cannot list: {e}"})
        return
    for task in tasks:
        if os.path.islink(os.path.join(root, task)):
            continue
        for path in (os.path.join(root, task, f"{task}.messages.json"),
                     os.path.join(root, task, "api_conversation_history.json")):
            if not os.path.lexists(path):
                continue
            try:   # a Windows directory junction is no symlink to islink
                if os.path.commonpath([root, os.path.realpath(path)]) != root:
                    continue
            except ValueError:   # another drive
                continue
            f, err = _safe_open(path)
            if err:
                unreadable.append({"path": path, "error": err})
                continue
            try:
                with f:
                    mtime, doc = os.fstat(f.fileno()).st_mtime, json.load(f)
            except OSError as e:
                unreadable.append({"path": path, "error": f"cannot read: {type(e).__name__}: {e}"})
                continue
            except (ValueError, RecursionError):   # not JSON (or not UTF-8), or nested past what json.load takes
                yield None
                continue
            messages = doc.get("messages") if isinstance(doc, dict) else doc
            if not isinstance(messages, list):
                yield None
                continue
            for m in messages:
                if not isinstance(m, dict) or m.get("role") != "assistant" or not isinstance(m.get("content"), list):
                    continue
                ts = m.get("ts")
                try:
                    at = datetime.fromtimestamp(ts / 1000 if type(ts) in (int, float) else mtime, timezone.utc)
                except (OverflowError, OSError, ValueError):   # a ts no date holds
                    at = datetime.fromtimestamp(mtime, timezone.utc)
                if at.timestamp() < since_ts:
                    continue
                for b in m["content"]:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        yield (at, task, b.get("name") if isinstance(b.get("name"), str) else "",
                               b.get("input") if isinstance(b.get("input"), dict) else {})


# one entry per agent: its name, its default folder or folders (read when audit runs, so the env var that moves one
# counts), where they are as a person reads it, and its reader (root, since_ts, unreadable) -> iterable of
# (time, session, tool, args), None for a line it counts as malformed
READERS = {"claude": (default_root, "$CLAUDE_CONFIG_DIR/projects when it is set, else ~/.claude/projects",
                      _claude_code),
           "cursor": (cursor_root, "~/.cursor/projects", _cursor),
           "cline": (cline_roots, "$CLINE_SESSION_DATA_DIR, else $CLINE_DATA_DIR/sessions, else "
                     "~/.cline/data/sessions ($CLINE_DIR moves ~/.cline); and before 4.0, saoudrizwan.claude-dev/tasks "
                     "in VS Code's global storage", _cline),
           "gemini": (gemini_root, "$GEMINI_CLI_HOME/.gemini/tmp when it is set, else ~/.gemini/tmp", _gemini)}


def _defaults(default) -> list[str]:
    """The folders a READERS entry's default gives (one, or a list), those that exist, each once (an env var can name
    another default's folder)."""
    folders, seen, found = default(), set(), []
    for f in [folders] if isinstance(folders, str) else folders:
        if os.path.isdir(f) and os.path.realpath(f) not in seen:
            seen.add(os.path.realpath(f))
            found.append(f)
    return found


def _agent(name: str | None) -> str | None:
    """An agent's name as init --agent takes it: claude-code is the name Claude Code's reader had before it took
    init's (claude)."""
    return "claude" if name == "claude-code" else name


def _no_reader(agent: str) -> str:
    """What to do with an agent's sessions when no reader reads them: a ROOT can't help."""
    return f"no reader for {agent}'s sessions yet; turn them into a calls file and use --calls FILE --agent {agent}"


def _calls(f, name: str, since_ts: float, unreadable: list):
    """The reader of a plain calls file, open as f (binary): one JSON object a line, with `tool` (a string) and `args`
    (an object), and optionally `time` (ISO-8601) and `session` (else the call counts under `name`). A line without
    `tool` and `args`, or with a `time` that isn't one, is malformed."""
    try:
        for _n, entry in transcript_entries(f, final=True):
            if entry is None or not isinstance(entry.get("tool"), str) or not isinstance(entry.get("args"), dict):
                yield None
                continue
            at = _entry_time(entry, "time")
            if at is None and entry.get("time") is not None:   # an epoch number, or text no date reads
                yield None
                continue
            if at is not None and at.timestamp() < since_ts:
                continue
            session = entry.get("session")
            yield at, session if isinstance(session, str) else name, entry["tool"], entry["args"]
    except OSError as e:
        unreadable.append({"path": name, "error": f"cannot read: {type(e).__name__}: {e}"})
    finally:
        if f is not getattr(sys.stdin, "buffer", None):
            f.close()


def audit(root: str | None = None, policy_path: str | None = None, since: str | None = None, show: bool = False,
          agent: str | None = None, calls: str | None = None) -> dict:
    """Replay tool calls and return the report dict: those of a calls file (`calls`, mapped as `agent`'s hook maps
    them), else those under root (Claude Code's folder, or `agent`'s reader's), else those in every reader's default
    folder that exists.

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
    unreadable: list[dict] = []
    agent = _agent(agent)
    if calls is not None:
        if calls == "-":
            if sys.stdin is None:   # started with stdin closed (<&-)
                raise OSError("--calls -: there is no standard input to read")
            f, label = sys.stdin.buffer, "stdin"
        else:
            f, err = _safe_open(calls)
            if err:
                what = _not_regular(calls)
                raise OSError(f"cannot read the calls file: {f'{calls} is {what}' if what else err}")
            label = os.path.basename(calls)
        sources = [(agent or "other", calls, _calls(f, label, since_ts, unreadable))]
    elif agent is not None and (root is None or agent not in READERS):
        raise ValueError(f"--agent {agent} needs a ROOT or --calls FILE" if agent in READERS else _no_reader(agent))
    elif root is not None:
        name = agent or "claude"
        sources = [(name, root, READERS[name][2](root, since_ts, unreadable))]
    else:
        sources = [(name, folder, read(folder, since_ts, unreadable))
                   for name, (default, _, read) in READERS.items() for folder in _defaults(default)]

    counts = {"allow": 0, "ask": 0, "deny": 0, "flag": 0}
    by_rule: dict[str, int] = {}
    # lean: every call is kept in memory (about 1 KB each, 2 KB with --json, measured on 158k calls; --show text is
    # capped at report.CALL_WIDTH); stream the report's lines instead if a real transcript folder outgrows that
    calls_out: list[dict] = []
    skipped_malformed = 0
    agents: dict[str, dict] = {}

    for name, folder, read in sources:
        start = len(calls_out)
        hook = name if name in AGENT_NAMES else None   # map the calls' names as that agent's hook does
        for item in read:
            if item is None:
                skipped_malformed += 1
                continue
            at, session, tool, args = item
            blocked = None
            if hook:
                try:   # as the live hook: a call it denies before mapping (a tool whose calls it can't see),
                    # then mapped
                    blocked = _blocked(hook, {"tool_name": tool, "tool_input": args}, json.dumps(
                        {"tool_name": tool, "tool_input": args, "toolCall": {"name": tool, "args": args}}))
                    tool, args = hook_tool(hook, tool, args)
                except RecursionError:   # nested past what the mapping takes, as json.loads counts such a line
                    skipped_malformed += 1
                    continue
                except UnreadableCall:   # a call the mapping can't read (Cline's; goose's, which its v2 hook blocks)
                    blocked = True
            try:   # as the signer decides it: an MCP tool also as mcp:<server>/<tool> and under its bare name,
                # PowerShell also as a shell line; a shell command its parser can't read is held (TK-SHELL-PARSE)
                decision = {"verdict": "deny", "rule_ids": ["TK-HOOK-BLOCKED"]} if blocked else \
                    evaluate(engine, tool, args)[0]
            except RecursionError:   # nesting the signer refuses (it denies an engine error itself)
                decision = {"verdict": "deny", "rule_ids": ["TK-ENGINE-ERROR"]}
            verdict = decision.get("verdict", "allow")
            counts[verdict] = counts.get(verdict, 0) + 1
            for rid in decision.get("rule_ids") or []:
                by_rule[rid] = by_rule.get(rid, 0) + 1
            rec = {
                "agent": name,
                "session": session,
                "time": at.isoformat() if at else None,
                "tool": tool,
                "verdict": verdict,
                "rule_ids": decision.get("rule_ids") or [],
            }
            if show:   # what an approver sees: redacted as the signer redacts it (.env content too)
                rec["text"] = call_text(tool, _shown(scrub(args), _dotenv(args)))
            calls_out.append(rec)
        mine = calls_out[start:]
        if name in agents:   # an agent's second default folder: its counts add to the first's
            a = agents[name]
            a["folder"] = [*([a["folder"]] if isinstance(a["folder"], str) else a["folder"]), folder]
            a["calls"] += len(mine)
            a["session_ids"] |= {c["session"] for c in mine}
        else:
            agents[name] = {"folder": folder, "calls": len(mine), "session_ids": {c["session"] for c in mine}}
    for a in agents.values():
        a["sessions"] = len(a.pop("session_ids"))
    calls_file, calls = calls is not None, calls_out

    times = [datetime.fromisoformat(c["time"]).timestamp() for c in calls if c["time"]]
    first = min(times, default=None)
    span = now - max(since_ts, first or since_ts) if since else max(times) - first if times else 0
    report = {
        "span_s": round(span),
        "holds_a_day": round(counts["ask"] * 86400 / span, 1) if span >= 86400 else None,
        "disclaimer": "a replay against today's policy, not a signed record",
        "policy": policy_path or DEFAULT_POLICY,
        "policy_hash": engine.policy_hash,
        "since": since,
        # --since's window in seconds since the epoch: --share counts each day of it from its start, never printed
        "window": [since_ts, now] if since else None,
        "sessions": len({(c["agent"], c["session"]) for c in calls}),
        "agents": agents,
        "calls_file": calls_file,
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
        "read: " + ("; ".join(f"{a} ({', '.join([v['folder']] if isinstance(v['folder'], str) else v['folder'])}): "
                             f"{v['calls']} call{'s' * (v['calls'] != 1)} in {v['sessions']} "
                             f"session{'s' * (v['sessions'] != 1)}" for a, v in report["agents"].items()) or "nothing"),
        f"{total} tool call{'s' * (total != 1)} in {s} session{'s' * (s != 1)}{window}: Tracekit would have denied "
        f"{n.get('deny', 0)} and held {n.get('ask', 0)} for a person; it would have flagged {n.get('flag', 0)} "
        f"and allowed {n.get('allow', 0)}.",
        "",
        "counts:",
    ]
    for v in ("deny", "ask", "flag", "allow"):
        lines.append(f"  {v}: {n.get(v, 0)}")
    if n.get("ask") and report["span_s"] >= 1:
        rate = f"{report['holds_a_day']:g} a day" if report["holds_a_day"] is not None else \
            f"{n['ask']} in {_wait(report['span_s'])}"
        lines.append(f"  held calls: {rate}. Who answered them, and how fast, is in the signed approval records: "
                     "tracekit report")
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
    # the same counts once more, last, for a newcomer: the rules that stopped a call (of the call's own decision's
    # section, or an engine check, which has none; not a flag that also matched), most first
    stopped = collections.Counter(r for c in report["calls"] if c["verdict"] in ("ask", "deny") for r in c["rule_ids"]
                                  if report["sections"].get(r, c["verdict"]) == c["verdict"])
    window = "week" if report["since"] == "7d" else _days(report["window"][1] - report["window"][0]) \
        if report["since"] else "calls file" if report["calls_file"] else "transcripts"
    agent = next(iter(report["agents"])) if len(report["agents"]) == 1 else None
    init = "tracekit init --dev --v2" + (f" --agent {agent}" if agent in AGENT_NAMES else "")   # claude: init's default
    lines += ["", f"your agent's {window}: {total:,} tool call{'s' * (total != 1)}; Tracekit would have held "
              f"{n.get('ask', 0):,} and blocked {n.get('deny', 0):,}",
              *(["  top: " + ", ".join(f"{r} {report['reasons'][r]} ({k})" if report["reasons"].get(r) else f"{r} ({k})"
                                       for r, k in sorted(stopped.items(), key=lambda x: (-x[1], x[0]))[:3])]
                if stopped else []),
              "  to guard from now on: " + (init if shutil.which("tracekit") else f"pip install tracekit-ai, then {init}")]
    # a transcript the agent wrote can hold control characters: print them as text, as tracekit report does
    return "\n".join(_escaped(line) for line in lines) + "\n"


def _by_day(report: dict) -> list[str]:
    """--share's day lines, with --since: the calls by decision for each 24 hours of the window, numbered from its
    start, a day with none too, then those with no time, if any. A day number, never a date: without --since there are
    none, as day 1 would be the first call's and say how far back the transcripts go."""
    if report["window"] is None:
        return []
    start, end = report["window"]
    # lean: one line a day however long the window (a --since of a year prints 365); fold them into weeks if people
    # post windows that long
    days = [collections.Counter() for _ in range(max(1, math.ceil((end - start) / 86400)))]
    no_time = collections.Counter()
    for c in report["calls"]:
        i = None if c["time"] is None else int((datetime.fromisoformat(c["time"]).timestamp() - start) // 86400)
        if i is None or i >= 0:   # a call before the window is on no day
            (no_time if i is None else days[min(i, len(days) - 1)])[c["verdict"]] += 1
    return ["Calls by decision and day (24 hours each, day 1 from the window's start):",
            *(f"  Day {i}: " + _counts({k: d[k] for k in DECISIONS}) for i, d in enumerate(days, 1)),
            *["  No time: " + _counts({k: no_time[k] for k in DECISIONS})] * bool(no_time)]


def share(report: dict) -> str:
    """The report's counts alone, for a person to post as a field report (docs/field-reports.md), as tracekit report
    --share gives them: of --since, the window's length and each day's calls by decision (_by_day); no session, path,
    policy file, date, time, call or rule description, and no rule id but Tracekit's own (report.share_rules). A rule
    is why its call was decided when its section is the call's decision; an engine check, which has no section, is not
    placed."""
    n, s, secs = report["counts"], report["sessions"], report["sections"]
    by_rule = collections.Counter((c["verdict"], rid, secs[rid] == c["verdict"] if rid in secs else None)
                                  for c in report["calls"] for rid in c["rule_ids"])
    window = _days(report["window"][1] - report["window"][0]) if report["since"] else \
        "the whole calls file" if report["calls_file"] else "every transcript"
    kind = "Claude Code" if set(report["agents"]) == {"claude"} else "coding-agent"
    lines = [f"Tracekit {__version__} field report (tracekit audit --share): {window}",
             f"{report['disclaimer']}: {s:,} {kind} session{'s' * (s != 1)}",
             f"Tool calls: {sum(n.values()):,}   " + _counts({k: n.get(k, 0) for k in DECISIONS}),
             *_by_day(report),
             "Calls by decision and rule (one call can match several rules):" + " none" * (not by_rule),
             *share_rules(by_rule)]
    return "\n".join(_escaped(line) for line in lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit audit", description="replay the tool calls in your coding agents' "
                                 "transcripts (Claude Code, Cursor, Cline and Gemini CLI), or in a calls file any agent's log can be "
                                 "turned into, through the policy and count what it would have held or denied. "
                                 "Read-only, local, and a replay against today's policy, not a signed record.")
    ap.add_argument("root", nargs="?", help="a transcripts' folder: Claude Code's, or --agent's reader's (default: "
                    "every known agent's folder that exists: " + "; ".join(f"{n}: {w}" for n, (_, w, _) in
                                                                          READERS.items()) + ")")
    ap.add_argument("--calls", metavar="FILE", help="read the calls from FILE (- for stdin) instead: one JSON object "
                    'a line, {"tool": ..., "args": {...}}, with "time" and "session" if known')
    ap.add_argument("--agent", type=_agent, choices=sorted({*READERS, *AGENT_NAMES}), help="with --calls, map each "
                    "call's tool names as that agent's hook does (its name as init --agent takes it); with ROOT, read "
                    "it with that agent's reader")
    ap.add_argument("--policy", help="a policy file (default: the dev pack, tracekit/policy2/packs/dev.yaml)")
    ap.add_argument("--since", help="7d, 24h, 30m, or an ISO date or time (UTC unless it says)")
    ap.add_argument("--show", action="store_true", help="also print each call, with secrets redacted")
    ap.add_argument("--all", action="store_true", help="list every call, not only the denied and held ones")
    o = ap.add_mutually_exclusive_group()
    o.add_argument("--json", action="store_true", help="print the report as JSON (every call)")
    o.add_argument("--share", action="store_true", help="print its counts alone, to post as a field report: no "
                                                       "session, path, time or call")
    a = ap.parse_args(argv)
    if a.calls is not None and a.root is not None:
        ap.error("give ROOT or --calls, not both")
    root = os.path.expanduser(a.root) if a.root is not None else None
    where = "; ".join(f"{n}: {w}" for n, (_, w, _) in READERS.items())
    # a calls file is opened once, in audit(): what it can't open, and --agent claude with neither ROOT nor --calls,
    # exit 2 there
    if a.calls is None and a.agent is not None and a.agent not in READERS:   # before ROOT's folder: one can't help
        print(f"tracekit audit: {_no_reader(a.agent)}", file=sys.stderr)
        return 2
    if a.calls is None and root is not None:
        if not os.path.isdir(root):
            print(f"tracekit audit: no such folder: {root} ({where})", file=sys.stderr)
            return 2
    elif a.calls is None and a.agent is None and not any(_defaults(d) for d, _, _ in READERS.values()):
        print(f"tracekit audit: no agent's folder found ({where}); give a ROOT, or --calls FILE", file=sys.stderr)
        return 2
    try:
        report = audit(root, a.policy, a.since, a.show, agent=a.agent, calls=a.calls)
    except (ValueError, OSError) as e:   # an unreadable --since; a policy file that's missing or doesn't lint
        print(f"tracekit audit: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(share(report) if a.share else format_report(report, as_json=a.json, every=a.all))
    return 0
