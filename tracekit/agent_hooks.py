"""Hooks for Codex CLI, Cursor and Gemini CLI, on the same pipeline as the Claude Code hook.

    tracekit init --dev --agent codex        # ~/.codex/hooks.json
    tracekit init --dev --agent cursor       # ~/.cursor/hooks.json
    tracekit init --dev --agent gemini       # ~/.gemini/settings.json
    (add --project to write the project-level file instead)

Each harness's hook payload is translated into the Claude Code hook shape, then handled by tracekit.hook: the same
policy gate before the tool runs (deny blocks, ask holds for approval), the same signed events, the same transcript
prefix hashing where the harness passes a transcript path. Only the reply to the harness differs.

Tool names are mapped onto Tracekit's policy vocabulary so the default rules apply unchanged:

    harness            -> Tracekit
    Codex   Bash, write_stdin, apply_patch, mcp__s__t     Bash, Bash (command = chars), Edit (paths: every file the
                                                          patch adds, updates, deletes or moves to), mcp__s__t
    Cursor  Shell, Read, Write, Grep, Delete, MCP:t   Bash, Read, Write, Grep, Delete, mcp__cursor__t
    Gemini  run_shell_command, read_file, write_file, replace, glob, search_file_content, web_fetch, google_web_search
            -> Bash, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch

What each harness exposes decides what Tracekit can see: Gemini CLI does not give tool calls an id, so pre and post
events are paired by (tool, arguments) in order; Cursor reports failures through postToolUseFailure. Reasoning
capture reads Claude Code's transcript format only and is off for these harnesses."""
import hashlib
import io
import json
import os
import re
import sys

from . import hook as H
from .core import canon
from .locking import lock_file, unlock_file

HARNESSES = ("codex", "cursor", "gemini")
AGENT_NAMES = {"codex": "codex", "cursor": "cursor", "gemini": "gemini-cli"}
V2_MODULE = "tracekit.integrations.harness_hooks"

GEMINI_TOOLS = {"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "write_file": "Write", "replace": "Edit",
                "glob": "Glob", "search_file_content": "Grep", "list_directory": "LS", "web_fetch": "WebFetch",
                "google_web_search": "WebSearch", "save_memory": "Memory"}
CURSOR_TOOLS = {"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep", "Delete": "Delete", "Task": "Task", "Edit": "Edit"}
PATCH_FILE = re.compile(r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$", re.M)


def _input(v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {"value": v}
    return v if isinstance(v, dict) else ({} if v is None else {"value": v})


def tool(harness, name, ti):
    """-> (tracekit tool name, normalised input)."""
    ti = dict(_input(ti))
    if harness == "codex":
        if name == "apply_patch":
            patch = ti.get("patch") or ti.get("input") or ti.get("command") or ""
            if isinstance(patch, list):
                patch = "\n".join(map(str, patch))
            files = [f.strip() for f in PATCH_FILE.findall(str(patch))]
            if files:
                ti.setdefault("file_path", files[0])
                ti["paths"] = files
            return "Edit", ti
        if name == "write_stdin":   # keystrokes into a running exec_command session: shell input
            if isinstance(ti.get("chars"), str):
                ti["command"] = ti["chars"]
            return "Bash", ti
        if name in ("shell", "local_shell", "exec_command"):
            cmd = ti.get("command")
            if isinstance(cmd, list):
                ti["command"] = " ".join(cmd[2:] if cmd[:2] in (["bash", "-lc"], ["bash", "-c"], ["sh", "-c"]) else cmd)
            return "Bash", ti
        return name, ti
    if harness == "cursor":
        if name.startswith("MCP:"):
            return "mcp__cursor__" + re.sub(r"[^A-Za-z0-9_-]+", "_", name[4:]), ti
        for k in ("path", "target_file", "filePath"):
            if k in ti and "file_path" not in ti:
                ti["file_path"] = ti[k]
        return CURSOR_TOOLS.get(name, name), ti
    if harness == "gemini":
        if "absolute_path" in ti and "file_path" not in ti:
            ti["file_path"] = ti["absolute_path"]
        if name == "web_fetch" and "url" not in ti and isinstance(ti.get("prompt"), str):
            m = re.search(r"https?://\S+", ti["prompt"])
            if m:
                ti["url"] = m.group(0)
        return GEMINI_TOOLS.get(name, name), ti
    return name, ti


def _gemini_ids(run_id, tool_name, ti, phase):
    """Gemini CLI tool events carry no call id: pair BeforeTool/AfterTool by (tool, arguments), first in first out."""
    from . import client
    key = hashlib.sha256((tool_name + "|" + canon(ti)).encode()).hexdigest()[:16]
    path = os.path.join(client.client_dir(), "runs", "gemini-" + hashlib.sha256(run_id.encode()).hexdigest()[:16] + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".lock", "a") as lk:
        lock_file(lk)
        try:
            try:
                with open(path, encoding="utf-8") as f:
                    st = json.load(f)
            except (OSError, ValueError):
                st = {"n": 0, "pending": {}}
            if phase == "pre":
                st["n"] += 1
                tid = f"gem_{key}_{st['n']}"
                st["pending"].setdefault(key, []).append(tid)
            else:
                q = st["pending"].get(key) or []
                tid = q.pop(0) if q else f"gem_{key}_unpaired"
                if not q:
                    st["pending"].pop(key, None)
            with open(path + ".tmp", "w", encoding="utf-8") as f:
                json.dump(st, f)
            os.replace(path + ".tmp", path)
        finally:
            unlock_file(lk)
    return tid


def normalise(harness, p):
    """Harness payload -> Claude Code-shaped payload for tracekit.hook, or None for events Tracekit ignores."""
    ev = p.get("hook_event_name") or ""
    out = {"cwd": p.get("cwd") or (p.get("workspace_roots") or [None])[0], "transcript_path": p.get("transcript_path"),
           "model": p.get("model")}
    if harness == "codex":
        out["session_id"] = p.get("session_id")
        m = {"PreToolUse": "PreToolUse", "PostToolUse": "PostToolUse", "UserPromptSubmit": "UserPromptSubmit",
             "SessionStart": "SessionStart", "SessionEnd": "SessionEnd"}
        if ev not in m:
            return None
        out["hook_event_name"] = m[ev]
        if ev in ("PreToolUse", "PostToolUse"):
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_use_id")
            if ev == "PostToolUse":
                out["tool_response"] = p.get("tool_response")
        if ev == "UserPromptSubmit":
            out["prompt"] = p.get("prompt")
        if ev == "SessionEnd":
            out["reason"] = p.get("reason") or "session end"
        return out
    if harness == "cursor":
        out["session_id"] = p.get("conversation_id") or p.get("session_id")
        if ev in ("preToolUse", "postToolUse", "postToolUseFailure"):
            out["hook_event_name"] = {"preToolUse": "PreToolUse", "postToolUse": "PostToolUse",
                                      "postToolUseFailure": "PostToolUseFailure"}[ev]
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_use_id")
            out["tool_response"] = p.get("tool_output")
            out["error"] = p.get("error_message")
            if isinstance(p.get("duration"), (int, float)):
                out["duration_ms"] = int(p["duration"])
            return out
        if ev == "beforeSubmitPrompt":
            return dict(out, hook_event_name="UserPromptSubmit", prompt=p.get("prompt"))
        if ev == "sessionStart":
            return dict(out, hook_event_name="SessionStart")
        if ev == "sessionEnd":
            return dict(out, hook_event_name="SessionEnd", reason=p.get("reason") or p.get("final_status") or "session end")
        return None
    if harness == "gemini":
        out["session_id"] = p.get("session_id") or os.environ.get("GEMINI_SESSION_ID")
        if ev in ("BeforeTool", "AfterTool"):
            name, ti = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out.update(hook_event_name="PreToolUse" if ev == "BeforeTool" else "PostToolUse", tool_name=name, tool_input=ti,
                       tool_use_id=out["session_id"] and _gemini_ids(out["session_id"], name, ti,
                                                                     "pre" if ev == "BeforeTool" else "post"))
            if ev == "AfterTool":
                r = p.get("tool_response")
                out["tool_response"] = r
                if isinstance(r, dict) and r.get("error"):
                    out["hook_event_name"], out["error"] = "PostToolUseFailure", r.get("error")
            return out
        if ev == "BeforeAgent":
            return dict(out, hook_event_name="UserPromptSubmit", prompt=p.get("prompt"))
        if ev == "SessionStart":
            return dict(out, hook_event_name="SessionStart")
        if ev == "SessionEnd":
            return dict(out, hook_event_name="SessionEnd", reason=p.get("reason") or "session end")
        return None
    raise ValueError(f"unknown harness {harness!r}")


class Tee(io.StringIO):
    """The user must see "waiting for approval <id>" live; the harness gets the final message too."""
    def __init__(self, out):
        super().__init__()
        self.out = out

    def write(self, s):
        self.out.write(s)
        self.out.flush()
        return super().write(s)


def run(harness, raw, stdout=None, stderr=None):
    """Handle one hook invocation. -> exit code. Writes the harness's expected stdout."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        p = json.loads(raw) if raw.strip() else {}
    except ValueError:
        p = {}
    is_pre = p.get("hook_event_name") in ("PreToolUse", "preToolUse", "BeforeTool")
    q = normalise(harness, p) if isinstance(p, dict) else None
    if q is None:
        _reply(harness, stdout, True, "", is_pre)
        return 0
    H.AGENT_NAME = AGENT_NAMES[harness]
    err = Tee(stderr)
    real_stdin, real_stderr = sys.stdin, sys.stderr
    sys.stdin, sys.stderr = io.StringIO(json.dumps(q)), err
    try:
        code = H.main(harness_reasoning=False)
    finally:
        sys.stdin, sys.stderr = real_stdin, real_stderr
    msg = err.getvalue().strip()
    _reply(harness, stdout, code == 0, msg, is_pre)
    return 2 if code else 0


def _reply(harness, stdout, allowed, msg, is_pre):
    if harness == "cursor":
        if is_pre:
            stdout.write(json.dumps({"permission": "allow"} if allowed else
                                    {"permission": "deny", "user_message": msg[:500], "agent_message": msg[:500]}))
        else:
            stdout.write("{}")
    elif harness == "gemini":
        stdout.write(json.dumps({} if allowed else {"decision": "deny", "reason": msg[:500]}))  # stdout must be JSON only
    elif harness == "codex" and not allowed and is_pre:
        stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                        "permissionDecisionReason": msg[:500]}}))
    stdout.flush()


# ------------------------------------------------------------------ installer

def config_path(harness, project=None):
    base = project if project else os.path.expanduser("~")
    return {"codex": os.path.join(base, ".codex", "hooks.json"), "cursor": os.path.join(base, ".cursor", "hooks.json"),
            "gemini": os.path.join(base, ".gemini", "settings.json")}[harness]


def _version(cmd):
    """"v2" for the v2 hook's command, "v1" for the v1 hook's, else None."""
    cmd = cmd if isinstance(cmd, str) else ""
    return "v2" if V2_MODULE in cmd else "v1" if "tracekit.agent_hooks" in cmd else None


def install(harness, project=None, uninstall=False, v2=False, python=None, path=None):
    """Add (or remove) Tracekit's hooks, v1 or the v2 hook (python: see install._hook_command), in the harness's
    config file (path, or config_path), replacing those of the other version. -> the file's path."""
    from .install import SettingsError, _atomic_write_json, _backup, _hook_command
    path = path or config_path(harness, project)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    s = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                txt = f.read()
            s = json.loads(txt) if txt.strip() else {}
        except (OSError, ValueError) as e:
            raise SettingsError(f"{path} is not valid JSON ({e}); Tracekit did not change it.") from e
        if not isinstance(s, dict):
            raise SettingsError(f"{path} must contain a JSON object; Tracekit did not change it.")
        _backup(path, txt.encode("utf-8"))
    hooks = s.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {path} must be an object; Tracekit did not change it.")
    new, removed = "v2" if v2 else "v1", set()
    cmd = _hook_command(V2_MODULE if v2 else "tracekit.agent_hooks", "entry", (harness,), python)

    def ours(cmds):
        vs = {_version(c) for c in cmds} - {None}
        removed.update(vs)
        return bool(vs)
    if harness == "cursor":
        s.setdefault("version", 1)
        closed = v2 or H.fail_closed()   # v2: a hook that cannot run blocks, as the v2 hook does
        events = {"preToolUse": 600, "postToolUse": 30, "postToolUseFailure": 30, "beforeSubmitPrompt": 30, "sessionStart": 30,
                  "sessionEnd": 30}
        for ev, timeout in events.items():
            lst = [h for h in hooks.get(ev, []) if not (isinstance(h, dict) and ours([h.get("command")]))]
            if not uninstall:
                lst.append({"command": cmd, "type": "command", "timeout": timeout, "failClosed": closed})
            if lst:
                hooks[ev] = lst
            else:
                hooks.pop(ev, None)
    else:
        events = (["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"] if harness == "codex"
                  else ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart", "SessionEnd"])
        tools = {"PreToolUse", "PostToolUse", "BeforeTool", "AfterTool"}
        for ev in events:
            groups = [g for g in hooks.get(ev, []) if not (isinstance(g, dict) and ours(
                [h.get("command") for h in g.get("hooks", []) if isinstance(h, dict)]))]
            if not uninstall:
                h = {"type": "command", "command": cmd}
                if harness == "gemini":
                    h.update(name="tracekit", timeout=600_000 if ev == "BeforeTool" else 30_000)  # ms; holds wait for approval
                else:
                    h["timeout"] = 600 if ev == "PreToolUse" else 30
                groups.append({"matcher": "*", "hooks": [h]} if ev in tools else {"hooks": [h]})
            if groups:
                hooks[ev] = groups
            else:
                hooks.pop(ev, None)
    if not hooks:
        s.pop("hooks", None)
    _atomic_write_json(path, s)
    old = " and ".join(sorted(removed if uninstall else removed - {new}))
    if old:
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else f"Tracekit {old} hooks replaced by {new} hooks in {path}")
    return path


def entry(harness=None):
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness not in HARNESSES:
        closed = H.fail_closed()
        print(f"usage: python -m tracekit.agent_hooks {{{'|'.join(HARNESSES)}}}; "
              + ("blocking (fail-closed)" if closed else "allowing (fail-open)"), file=sys.stderr)
        return 2 if closed else 0
    try:
        return run(harness, sys.stdin.read())
    except Exception as e:
        closed = H.fail_closed()
        print(f"[tracekit] {harness} hook error ({e}); " + ("blocking (fail-closed)" if closed else "allowing (fail-open)"), file=sys.stderr)
        _reply(harness, sys.stdout, not closed, str(e), True)
        return 2 if closed else 0


if __name__ == "__main__":
    sys.exit(entry())
