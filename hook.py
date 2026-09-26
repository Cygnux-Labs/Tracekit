#!/usr/bin/env python3
"""Claude Code hook: records every event into the tamper-evident ledger,
enforces policy before tool calls, and captures the model's reasoning from
the session transcript.

Wired into ~/.claude/settings.json by install.py. Reads the hook payload on stdin.
Never breaks the agent: on any internal error it exits 0 (allow) and logs to stderr.
Only a deliberate policy denial exits 2 (which blocks the tool call).
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

FIELD_FOR_TOOL = {"Bash": "command", "Write": "file_path", "Edit": "file_path",
                  "MultiEdit": "file_path", "Read": "file_path", "NotebookEdit": "notebook_path",
                  "WebFetch": "url", "WebSearch": "query", "Glob": "pattern", "Grep": "pattern"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def subject(tool, tool_input, field=None):
    field = field or FIELD_FOR_TOOL.get(tool)
    if field and isinstance(tool_input, dict) and field in tool_input:
        return str(tool_input[field])
    return common.canon(tool_input)


def evaluate_policy(tool, tool_input, cwd):
    policy = common.load_json(common.POLICY, {})
    decision, reasons, flags = "allow", [], []
    for rule in policy.get("deny", []):
        if re.fullmatch(rule.get("tool", ".*"), tool) and \
                re.search(rule["pattern"], subject(tool, tool_input, rule.get("field"))):
            decision = "deny"
            reasons.append(rule.get("reason", rule["pattern"]))
    for rule in policy.get("flag", []):
        if re.fullmatch(rule.get("tool", ".*"), tool) and \
                re.search(rule["pattern"], subject(tool, tool_input, rule.get("field"))):
            flags.append(rule.get("label", "flag"))
    scope = policy.get("scope", {})
    if scope.get("flag_writes_outside_cwd", True) and tool in WRITE_TOOLS and cwd:
        path = str((tool_input or {}).get("file_path") or (tool_input or {}).get("notebook_path") or "")
        if path:
            ap = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
            if not (ap + os.sep).startswith(os.path.realpath(cwd) + os.sep):
                flags.append("out_of_scope_write")
    return decision, reasons, sorted(set(flags))


def subagent_transcript(main_path, agent_id):
    """Claude Code stores subagent transcripts at <session>/subagents/agent-<id>.jsonl."""
    if not main_path or not agent_id:
        return None
    return os.path.join(main_path[:-6] if main_path.endswith(".jsonl") else main_path,
                        "subagents", f"agent-{agent_id}.jsonl")


def ingest_transcript(session_id, transcript_path, agent_id=None, agent_type=None):
    """Pull new assistant turns (thinking, text, tool_use) from a transcript.
    Runs under a lock so parallel agents never ingest the same lines twice."""
    if not transcript_path or not os.path.exists(transcript_path):
        return []
    with common.locked("state"):
        return _ingest(session_id, transcript_path, agent_id, agent_type)


def _ingest(session_id, transcript_path, agent_id, agent_type):
    state = common.load_json(common.STATE, {})
    key = f"{session_id}:{transcript_path}"
    offset = state.get(key, 0)
    events = []
    with open(transcript_path, encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for line in f:
            if not line.endswith("\n"):
                break  # partial line still being written; pick up next time
            offset += len(line.encode("utf-8"))
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if entry.get("type") != "assistant":
                continue
            msg = entry.get("message") or {}
            blocks = []
            for b in msg.get("content") or []:
                t = b.get("type")
                if t == "thinking":
                    txt = b.get("thinking", "")
                    if txt.strip():
                        blocks.append({"kind": "thinking", "text": txt})
                    else:  # signature only: the provider kept the reasoning text back
                        blocks.append({"kind": "thinking_redacted", "text": "[reasoning withheld by provider]"})
                elif t == "redacted_thinking":
                    blocks.append({"kind": "thinking_redacted", "text": "[reasoning withheld by provider]"})
                elif t == "text":
                    blocks.append({"kind": "text", "text": b.get("text", "")})
                elif t == "tool_use":
                    blocks.append({"kind": "tool_use", "tool_use_id": b.get("id"),
                                   "tool_name": b.get("name"), "tool_input": b.get("input")})
            if blocks:
                events.append({"event": "model_turn", "session_id": session_id,
                               "agent_id": agent_id, "agent_type": agent_type,
                               "transcript_uuid": entry.get("uuid"), "message_id": msg.get("id"),
                               "model": msg.get("model"),
                               "usage": msg.get("usage"), "blocks": blocks})
    state[key] = offset
    common.save_json(common.STATE, state)
    return events


def main():
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    name = payload.get("hook_event_name", "Unknown")
    sid = payload.get("session_id")
    aid, atype = payload.get("agent_id"), payload.get("agent_type")
    base = {"event": name, "session_id": sid, "cwd": payload.get("cwd"),
            "agent": os.environ.get("TRACEKIT_AGENT", "claude-code"),
            "agent_id": aid, "agent_type": atype, "prompt_id": payload.get("prompt_id")}
    events, exit_code, stderr_msg = [], 0, ""
    main_tx = payload.get("transcript_path")

    # Reasoning that led up to this point (so it sits in the ledger before the action).
    if name in ("PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop", "SubagentStop",
                "PreCompact", "SessionEnd"):
        if aid:  # a subagent: read its own transcript
            sub = payload.get("agent_transcript_path") or subagent_transcript(main_tx, aid)
            events += ingest_transcript(sid, sub, aid, atype)
        events += ingest_transcript(sid, main_tx)
    if name in ("Stop", "SessionEnd") and main_tx:  # catch up every subagent
        d = os.path.join(main_tx[:-6], "subagents")
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                if fn.startswith("agent-") and fn.endswith(".jsonl"):
                    events += ingest_transcript(sid, os.path.join(d, fn), fn[6:-6])

    if name == "PreToolUse":
        tool, ti = payload.get("tool_name", ""), payload.get("tool_input", {})
        decision, reasons, flags = evaluate_policy(tool, ti, payload.get("cwd"))
        events.append({**base, "tool_name": tool, "tool_input": ti,
                       "tool_use_id": payload.get("tool_use_id"),
                       "policy": {"decision": decision, "reasons": reasons, "flags": flags}})
        if decision == "deny":
            exit_code = 2
            stderr_msg = "Blocked by tracekit policy: " + "; ".join(reasons)
    elif name in ("PostToolUse", "PostToolUseFailure"):
        resp = payload.get("tool_response")
        if name == "PostToolUseFailure":
            resp = {"is_error": True, "error": payload.get("error"), "response": resp}
        events.append({**base, "event": "PostToolUse", "failed": name == "PostToolUseFailure",
                       "tool_name": payload.get("tool_name"),
                       "tool_input": payload.get("tool_input"),
                       "tool_use_id": payload.get("tool_use_id"),
                       "duration_ms": payload.get("duration_ms"),
                       "tool_response": resp})
    elif name == "UserPromptSubmit":
        events.append({**base, "prompt": payload.get("prompt")})
    else:
        extra = {k: v for k, v in payload.items()
                 if k not in ("session_id", "cwd", "hook_event_name", "transcript_path",
                              "scratchpad_dir", "agent_id", "agent_type", "prompt_id")}
        events.append({**base, **extra})

    common.append(events)
    if stderr_msg:
        print(stderr_msg, file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # never break the agent because logging failed
        if os.environ.get("TRACEKIT_FAIL_CLOSED") == "1":
            print(f"[tracekit] error, blocking because TRACEKIT_FAIL_CLOSED=1: {e}", file=sys.stderr)
            sys.exit(2)
        print(f"[tracekit] logging error (action allowed): {e}", file=sys.stderr)
        sys.exit(0)
