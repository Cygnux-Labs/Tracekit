"""Hooks for Codex CLI, Cursor, Gemini CLI and OpenCode, on the same pipeline as the Claude Code hook.

    tracekit init --dev --agent codex        # ~/.codex/hooks.json
    tracekit init --dev --agent cursor       # ~/.cursor/hooks.json
    tracekit init --dev --agent gemini       # ~/.gemini/settings.json
    tracekit init --dev --agent opencode     # ~/.config/opencode/plugin/tracekit.js
    (add --project to write the project-level file instead)

Each harness's hook payload is translated into the Claude Code hook shape, then handled by tracekit.hook: the same
policy gate before the tool runs (deny blocks, ask holds for approval), the same signed events, the same transcript
prefix hashing where the harness passes a transcript path. Only the reply to the harness differs.

Tool names are mapped onto Tracekit's policy vocabulary so the default rules apply unchanged:

    harness            -> Tracekit
    Codex   Bash, write_stdin, apply_patch, mcp__s__t     Bash, Bash (command = chars), Edit (paths: every file the
                                                          patch adds, updates, deletes or moves to), mcp__s__t
    Cursor  Shell, Read, Write, Grep, Delete, MCP:t   Bash, Read, Write, Grep, Edit, mcp__cursor__t
    Gemini  run_shell_command, read_file, write_file, replace, glob, search_file_content, web_fetch, google_web_search
            -> Bash, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch

What each harness exposes decides what Tracekit can see: Gemini CLI does not give tool calls an id, so pre and post
events are paired by (tool, arguments) in order; Cursor reports failures through postToolUseFailure. Reasoning
capture reads Claude Code's transcript format only and is off for these harnesses."""
import contextlib
import hashlib
import io
import json
import os
import re
import sys

from . import hook as H
from .core import canon
from .locking import lock_file, unlock_file

HARNESSES = ("codex", "cursor", "gemini", "opencode")
AGENT_NAMES = {"codex": "codex", "cursor": "cursor", "gemini": "gemini-cli", "opencode": "opencode"}
V2_MODULE = "tracekit.integrations.harness_hooks"
CURSOR_SAID = ("afterAgentThought", "afterAgentResponse")   # Cursor's events with what its model said (v2 records them)

GEMINI_TOOLS = {"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "write_file": "Write", "replace": "Edit",
                "glob": "Glob", "search_file_content": "Grep", "list_directory": "LS", "web_fetch": "WebFetch",
                "google_web_search": "WebSearch", "save_memory": "Memory"}
# a Delete is an Edit, as a Codex patch's Delete File is: the file rules (a credentials file, the transcripts) read it
CURSOR_TOOLS = {"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep", "Delete": "Edit", "Task": "Task", "Edit": "Edit"}
OPENCODE_TOOLS = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "apply_patch": "Edit",
                  "glob": "Glob", "grep": "Grep", "webfetch": "WebFetch", "websearch": "WebSearch", "task": "Task",
                  "todowrite": "TodoWrite"}
# Codex reads a hunk header from the line with its Unicode whitespace trimmed (codex-rs/apply-patch), so one may be indented
# lean: an indented header line inside an Update hunk is context to Codex but a path here: decided too, never missed
PATCH_FILE = re.compile(r"^[^\S\n]*\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$", re.M)
OPENCODE_PATH_ARG = {"read": "filePath", "write": "filePath", "edit": "filePath", "glob": "path", "grep": "path"}
# OpenCode's patch parser takes any header line starting with the marker and trims the rest as JS trim() does
OPENCODE_PATCH_FILE = re.compile(r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to):(.*)$", re.M)
JS_TRIM = re.compile(r"^[\s\ufeff]+|[\s\ufeff]+$")


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
    if harness == "opencode":
        # the path the tool itself reads decides, never another path key the model sent beside it (OpenCode drops
        # unknown keys before the tool runs, so a decoy `file_path` would be decided but never used)
        if name in OPENCODE_PATH_ARG:
            ti["file_path"] = ti.get(OPENCODE_PATH_ARG[name])
        if name == "apply_patch":   # every file OpenCode's parser finds, whatever paths the model sent; releases of
            # 2026-01-18 to 2026-02-23 (1.2.0) read a header only up to its next ':' (split(":", 2)): both are decided
            files = [JS_TRIM.sub("", g) for f in OPENCODE_PATCH_FILE.findall(str(ti.get("patchText") or ""))
                     for g in dict.fromkeys((f, f.split(":")[0]))]
            ti["paths"] = files
            ti["file_path"] = files[0] if files else None
        return OPENCODE_TOOLS.get(name, name), ti
    return name, ti


def _gemini_ids(run_id, tool_name, ti, phase, drop=None):
    """Gemini CLI tool events carry no call id: pair BeforeTool/AfterTool by (tool, arguments), first in first out.
    drop: the id of a blocked BeforeTool, which gets no AfterTool; it leaves the queue."""
    from . import client
    key = drop.split("_")[1] if drop else hashlib.sha256((tool_name + "|" + canon(ti)).encode()).hexdigest()[:16]
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
            if drop:
                tid = drop
                q = st["pending"].get(key) or []
                if drop in q:
                    q.remove(drop)
                if not q:
                    st["pending"].pop(key, None)
            elif phase == "pre":
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
    if harness == "opencode":
        out["session_id"] = p.get("session_id")
        if ev in ("tool.execute.before", "tool.execute.after"):
            out["hook_event_name"] = "PreToolUse" if ev == "tool.execute.before" else "PostToolUse"
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_use_id")
            if ev == "tool.execute.after":
                out["tool_response"] = p.get("tool_response")
            return out
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


PRE = ("PreToolUse", "preToolUse", "BeforeTool", "tool.execute.before")


def run(harness, raw, stdout=None, stderr=None):
    """Handle one hook invocation. -> exit code. Writes the harness's expected stdout. A payload that is not a JSON
    object raises: entry answers it."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = json.loads(raw) if raw.strip() else {}
    if not isinstance(p, dict):
        raise ValueError("the hook payload is not a JSON object")
    is_pre = p.get("hook_event_name") in PRE
    q = normalise(harness, p)
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
    if code and harness == "gemini" and is_pre and q.get("tool_use_id"):   # a blocked call gets no AfterTool
        with contextlib.suppress(Exception):   # bookkeeping: never in the way of the answer
            _gemini_ids(q["session_id"], None, None, "pre", drop=q["tool_use_id"])
    msg = err.getvalue().strip()
    _reply(harness, stdout, code == 0, msg, is_pre)
    return _exit(harness, 2 if code else 0, is_pre)


def _exit(harness, code, is_pre):
    """The exit status that carries a hook's answer (code: 0 allowed, else blocked). Codex blocks a pre-tool call at
    exit 2 with a reason on stderr, whatever a shell startup file printed to stdout; on Windows its hooks run under
    PowerShell, which hands it 2 as 1, so there the JSON deny _reply writes carries the block, at exit 0, the only
    status at which Codex reads it."""
    return 0 if harness == "codex" and is_pre and os.name == "nt" else code


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
                                                        "permissionDecisionReason": msg[:500] or "Blocked by tracekit"}}))
    stdout.flush()


# ------------------------------------------------------------------ installer

def config_path(harness, project=None, home=None):
    """The hook config of `harness`: a project's (project) or a user's (home, default ~), which differ for OpenCode,
    whose 1.0 releases load plugins from plugin/ only (plugins/ from 1.1.1)."""
    base = project or home or os.path.expanduser("~")
    return {"codex": os.path.join(base, ".codex", "hooks.json"), "cursor": os.path.join(base, ".cursor", "hooks.json"),
            "gemini": os.path.join(base, ".gemini", "settings.json"),
            "opencode": os.path.join(base, ".opencode", "plugin", "tracekit.js") if project else
                        os.path.join((None if home else os.environ.get("XDG_CONFIG_HOME")) or
                                     os.path.join(base, ".config"), "opencode", "plugin", "tracekit.js")}[harness]


CODEX_SUMMARY = "model_reasoning_summary"   # Codex's reasoning.summary for the Responses API: auto|concise|detailed|none
_TOML_KEY = re.compile(r"^\s*model_reasoning_summary\s*=\s*([^#]*)")
_TOML_TABLE = re.compile(r"^\[\[?[^\]]+\]\]?\s*(#.*)?$")


def codex_summary(text):
    """The top-level model_reasoning_summary a Codex config.toml's text sets (its value, unquoted), else None."""
    # lean: a line scan, not a TOML parser (Python 3.9 has none): a profile's own setting and a key inside a
    # multi-line string are not read; parse the file if configs that tangled show up
    for line in text.splitlines():
        if _TOML_TABLE.match(line):
            return None
        m = _TOML_KEY.match(line)
        if m:
            return m.group(1).strip().strip("'\"")
    return None


CODEX_LINE = f'{CODEX_SUMMARY} = "auto"   # set by tracekit init; tracekit uninstall removes this line\n'


def _check_toml(text, path):
    """SettingsError unless `text`, config.toml with CODEX_LINE added, parses and sets it at the top level."""
    # lean: Python 3.9 and 3.10 have no TOML parser, so there codex_summary's line scan alone decides; a top-level key
    # after a multi-line array line that looks like a table header gets a second one; require 3.11 to close it
    try:
        import tomllib
    except ImportError:
        return
    try:
        ok = tomllib.loads(text).get(CODEX_SUMMARY) == "auto"
    except tomllib.TOMLDecodeError:
        ok = False
    if not ok:
        from .install import SettingsError
        raise SettingsError(f"{path} is TOML Tracekit can't add {CODEX_SUMMARY} to safely; Tracekit did not change "
                            f"it. Set {CODEX_SUMMARY} = \"auto\" at its top level yourself, or run init again with "
                            "--no-thinking-summaries.")


def codex_reasoning(hooks_path, uninstall=False):
    """Turn Codex's reasoning summaries on: CODEX_LINE as the first line of the config.toml beside `hooks_path` (a
    top-level key wherever the file's tables and arrays are; the file created if missing), unless the file sets one,
    whatever its value. Unset, Codex uses its model catalog's default, `none` for its current models. uninstall: remove
    CODEX_LINE again, if it is still there unchanged. -> [config path, the value set now, whether init changed it]."""
    from .deploy import files
    from .install import SettingsError
    path = os.path.join(os.path.dirname(os.path.abspath(hooks_path)), "config.toml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        d = files.open_dir(os.path.dirname(path))
        try:
            raw = files.read(d, "config.toml")
            txt = "" if raw is None else raw.decode("utf-8")
            value, lines = codex_summary(txt), txt.splitlines(keepends=True)
            if uninstall:
                if CODEX_LINE not in lines:
                    return [path, value, False]
                lines.remove(CODEX_LINE)
            elif value is not None:
                return [path, value, False]
            else:
                lines.insert(0, CODEX_LINE)
                _check_toml("".join(lines), path)
            mode = os.stat(path).st_mode & 0o777 if raw is not None else 0o600
            if raw is not None:
                files.backup(d, "config.toml", raw)
            files.write(d, "config.toml", "".join(lines).encode("utf-8"), mode)
        finally:
            files.close(d)
    except files.UnsafePath as e:
        raise SettingsError(f"{path}: {e}. Set {CODEX_SUMMARY} = \"auto\" at the top of the config.toml Codex reads, "
                            "or run init again with --no-thinking-summaries.") from e
    except (OSError, UnicodeDecodeError) as e:
        raise SettingsError(f"{path} can't be read ({e}); Tracekit did not change it.") from e
    return [path, None if uninstall else "auto", True]


def reasoning_line(path, value, changed):
    """What init says about Codex's reasoning summaries (codex_reasoning's answer)."""
    if value != "none":
        return (f"Codex reasoning summaries: on ({CODEX_SUMMARY} = \"{value}\" in {path}"
                + (", set by init" if changed else "") + "), so `tracekit analyze --v2` can read the model's reasoning; "
                "init --no-thinking-summaries leaves the setting alone")
    return (f"Codex reasoning summaries: off ({path} sets {CODEX_SUMMARY} to \"none\"): `tracekit analyze --v2` can't read "
            "the model's reasoning; set it to \"auto\" to check it")


def _version(cmd):
    """"v2" for the v2 hook's command, "v1" for the v1 hook's, else None."""
    cmd = cmd if isinstance(cmd, str) else ""
    return "v2" if V2_MODULE in cmd else "v1" if "tracekit.agent_hooks" in cmd else None


OPENCODE_MARKER = "// Installed by Tracekit; tracekit uninstall --agent opencode removes this file."


def _opencode_plugin(python, v2):
    """The local OpenCode plugin. OpenCode runs plugins with Bun, whose synchronous child process API lets a
    before hook wait for Tracekit's allow/deny (or a person's approval) before returning to the tool executor. Each
    event's command names the event, and runs the hook as install._hook_command does (python, or this interpreter)."""
    from .install import _dev_hook_argv
    module = V2_MODULE if v2 else "tracekit.agent_hooks"
    commands = {ev: [python, "-I", "-m", module, "opencode", ev] if python else
                _dev_hook_argv(module, "entry", ("opencode", ev)) for ev in ("tool.execute.before", "tool.execute.after")}
    return f'''{OPENCODE_MARKER}
const commands = {json.dumps(commands)};
const decoder = new TextDecoder();

function tracekit(event, input, toolInput, toolResponse) {{
  const payload = {{
    hook_event_name: event,
    session_id: input.sessionID,
    tool_use_id: input.callID,
    tool_name: input.tool,
    tool_input: toolInput,
    tool_response: toolResponse,
    cwd: input.cwd,
  }};
  try {{
    const result = Bun.spawnSync({{
      cmd: commands[event],
      cwd: input.cwd,
      stdin: new TextEncoder().encode(JSON.stringify(payload)),
      stdout: "pipe",
      stderr: "pipe",
    }});
    return {{ code: result.exitCode, message: decoder.decode(result.stderr).trim() }};
  }} catch (error) {{
    return {{ code: 1, message: `[tracekit] OpenCode hook error (${{error}})` }};
  }}
}}

export const TracekitPlugin = async ({{ directory }}) => ({{
  "tool.execute.before": async (input, output) => {{
    if (input.tool === "batch") {{   // OpenCode runs the calls inside a batch with no plugin hooks
      throw new Error("Blocked by Tracekit: OpenCode's experimental batch tool runs its calls without plugin hooks, " +
        "so Tracekit can't decide them. Turn it off (experimental.batch_tool in opencode.json) and make each call itself.");
    }}
    const result = tracekit("tool.execute.before", {{ ...input, cwd: directory }}, output.args);
    if (result.code !== 0) {{   // blocked (2), or the hook could not decide the call: it doesn't run
      throw new Error(result.message || "Blocked by Tracekit: the hook could not decide this call");
    }}
  }},
  "tool.execute.after": async (input, output) => {{
    const result = tracekit("tool.execute.after", {{ ...input, cwd: directory }}, input.args, output);
    if (result.code !== 0) console.error(result.message);
  }},
}});
'''


def _install_opencode(path, uninstall=False, v2=False, python=None):
    """Install one owned local plugin without overwriting an OpenCode plugin that is not Tracekit's."""
    from .deploy import files
    from .install import SettingsError
    path = os.path.abspath(path)
    if uninstall and not os.path.lexists(path):   # nothing to remove: no directory made for it either
        return path
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        d = files.open_dir(os.path.dirname(path))
        try:
            name = os.path.basename(path)
            raw = files.read(d, name)
            try:
                text = raw.decode("utf-8") if raw is not None else ""
            except UnicodeDecodeError as e:
                raise SettingsError(f"{path} is not UTF-8; Tracekit did not change it.") from e
            if raw is not None and OPENCODE_MARKER not in text:
                raise SettingsError(f"{path} is not Tracekit's plugin; Tracekit did not change it.")
            old = _version(text)
            if raw is not None:
                files.backup(d, name, raw)
            if uninstall:
                if raw is not None:
                    target = name if isinstance(d, int) else path
                    os.unlink(target, **({"dir_fd": d} if isinstance(d, int) else {}))
            else:
                files.write(d, name, _opencode_plugin(python, v2).encode("utf-8"), 0o600)
        finally:
            files.close(d)
    except (files.UnsafePath, OSError) as e:
        raise SettingsError(f"{path}: {e}") from e
    new = "v2" if v2 else "v1"
    if old and (uninstall or old != new):
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else
              f"Tracekit {old} hooks replaced by {new} hooks in {path}")
    return path


def install(harness, project=None, uninstall=False, v2=False, python=None, path=None):
    """Add (or remove) Tracekit's hooks, v1 or the v2 hook (python: see install._hook_command), in the harness's
    config file (path, or config_path), replacing those of the other version. -> the file's path."""
    from .install import SettingsError, _atomic_write_json, _backup, _hook_command
    path = path or config_path(harness, project)
    if harness == "opencode":
        return _install_opencode(path, uninstall, v2, python)
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

    def cmd(ev):   # the v2 hook names its event, so it can block a pre-tool payload it cannot read
        c = _hook_command(V2_MODULE if v2 else "tracekit.agent_hooks", "entry", (harness, ev) if v2 else (harness,),
                          python, ev in PRE)
        # on Windows, Codex and Gemini CLI run a hook's command under PowerShell (Codex under cmd.exe when PowerShell
        # isn't found or the session has no single local environment). PowerShell runs a quoted program path only
        # through its call operator, which cmd.exe can't parse: an interpreter path that needs no quotes goes bare,
        # which both run
        if os.name != "nt" or harness == "cursor":
            return c
        m = re.match(r'"([A-Za-z0-9_.:\\-]+)"', c)   # cmd.exe ends a program word at /
        return m.group(1) + c[m.end():] if m else f"& {c}"

    def ours(cmds):
        vs = {_version(c) for c in cmds} - {None}
        removed.update(vs)
        return bool(vs)

    def entries(ev):
        lst = hooks.get(ev, [])
        if not isinstance(lst, list):
            raise SettingsError(f"hooks.{ev} in {path} must be a list; Tracekit did not change it.")
        return lst
    if harness == "cursor":
        s.setdefault("version", 1)
        closed = v2 or H.fail_closed()   # v2: a hook that cannot run blocks, as the v2 hook does
        events = {"preToolUse": 600, "postToolUse": 30, "postToolUseFailure": 30, "beforeSubmitPrompt": 30, "sessionStart": 30,
                  "sessionEnd": 30, **dict.fromkeys(CURSOR_SAID, 30)}
        for ev, timeout in events.items():
            lst = [h for h in entries(ev) if not (isinstance(h, dict) and ours([h.get("command")]))]
            if not uninstall and (v2 or ev not in CURSOR_SAID):   # the v1 hook records no model text
                lst.append({"command": cmd(ev), "type": "command", "timeout": timeout, "failClosed": closed})
            if lst:
                hooks[ev] = lst
            else:
                hooks.pop(ev, None)
    else:
        events = (["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"] if harness == "codex"
                  else ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart", "SessionEnd"])
        tools = {"PreToolUse", "PostToolUse", "BeforeTool", "AfterTool"}
        for ev in events:
            groups = [g for g in entries(ev) if not (isinstance(g, dict) and ours(
                [h.get("command") for h in g.get("hooks", []) if isinstance(h, dict)]))]
            if not uninstall:
                h = {"type": "command", "command": cmd(ev)}
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
    if uninstall and harness == "codex":   # init's reasoning summaries line goes with its hooks
        try:
            codex_reasoning(path, uninstall=True)
        except SettingsError:   # a config.toml init can't have written to
            pass
    old = " and ".join(sorted(removed if uninstall else removed - {new}))
    if old:
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else f"Tracekit {old} hooks replaced by {new} hooks in {path}")
    return path


def stdin_text():
    """A hook's payload, UTF-8 JSON (a byte order mark before it is dropped): read as bytes where stdin has them, since
    Windows decodes a pipe with its ANSI code page."""
    return sys.stdin.buffer.read().decode("utf-8-sig", "replace") if hasattr(sys.stdin, "buffer") else sys.stdin.read()


def entry(harness=None, event=None):
    """event: the hook event the command names (OpenCode's plugin does), or None."""
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness not in HARNESSES:
        closed = H.fail_closed()
        print(f"usage: python -m tracekit.agent_hooks {{{'|'.join(HARNESSES)}}} [EVENT]; "
              + ("blocking (fail-closed)" if closed else "allowing (fail-open)"), file=sys.stderr)
        return 2 if closed else 0
    raw = ""
    try:
        raw = stdin_text()
        return run(harness, raw)
    except Exception as e:
        try:
            pre = (event or json.loads(raw).get("hook_event_name")) in PRE
        except Exception:
            pre = True   # unreadable: answered as a tool call
        # OpenCode's plugin passes the model's arguments unchecked: a call its hook can't decide doesn't run, as when
        # the hook can't start; nor, in any hook, one whose payload nests too deep to read
        closed = event in PRE or isinstance(e, RecursionError) or H.fail_closed()
        print(f"[tracekit] {harness} hook error ({e}); " + ("blocking" if closed else "allowing (fail-open)"), file=sys.stderr)
        _reply(harness, sys.stdout, not closed, str(e), pre)
        return _exit(harness, 2 if closed else 0, pre)


if __name__ == "__main__":
    sys.exit(entry(*sys.argv[1:3]))
