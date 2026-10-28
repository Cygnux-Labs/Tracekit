"""Hooks for Codex CLI, Cursor, Gemini CLI, OpenCode, goose, Qwen Code, Factory Droid and Antigravity CLI, on the Claude
Code pipeline.

    tracekit init --dev --agent codex        # ~/.codex/hooks.json
    tracekit init --dev --agent cursor       # ~/.cursor/hooks.json
    tracekit init --dev --agent gemini       # ~/.gemini/settings.json
    tracekit init --dev --agent opencode     # ~/.config/opencode/plugin/tracekit.js
    tracekit init --dev --agent goose        # ~/.agents/plugins/tracekit/hooks/hooks.json
    tracekit init --dev --agent qwen         # ~/.qwen/settings.json
    tracekit init --dev --agent droid        # ~/.factory/hooks.json
    tracekit init --dev --agent antigravity  # ~/.gemini/config/hooks.json (project: .agents/hooks.json)
    (add --project to write the project-level file instead)

Each harness's hook payload is translated into the Claude Code hook shape, then handled by tracekit.hook: the same
policy gate before the tool runs (deny blocks, ask holds for approval), the same signed events, the same transcript
prefix hashing where the harness passes a transcript path. Only the reply to the harness differs.

Tool names are mapped onto Tracekit's policy vocabulary so the default rules apply unchanged:

    harness            -> Tracekit
    Codex   Bash, write_stdin, apply_patch, mcp__s__t     Bash, Bash (command = chars), Edit (paths: every file the
                                                          patch adds, updates, deletes or moves to), mcp__s__t
    Cursor  Shell, Read, Write, Grep, Delete, MCP:t   Bash, Read, Write, Grep, Edit, mcp__cursor__t
    Gemini  run_shell_command, read_file, read_many_files, write_file, replace, glob, search_file_content,
            list_directory, web_fetch, google_web_search
            -> Bash, Read, Read, Write, Edit, Glob, Grep, LS, WebFetch, WebSearch (every path a file tool reads, under
            any release's name for it, in file_path or paths: file_path, absolute_path, dir_path, path, and
            read_many_files' paths and include)
    goose   shell, write, edit, tree, read_image, <extension>__<tool>
            -> Bash, Write, Edit, LS, Read (WebFetch for an http(s) source), mcp__<extension>__<tool> (goose's
            payload names its event `event` and its
            working directory `working_dir`, and sends no tool result or error text: see docs/limits.md)
    Qwen Code (a Gemini CLI fork) sends Claude Code's payloads and names its events as Claude Code does, with Gemini's
            tool names and its own edit, grep_search and agent -> Edit, Grep, Task
    Droid   Execute, Create, ApplyPatch, FetchUrl -> Bash, Write, Edit (all patch file headers in paths), WebFetch
    agy     run_command, view_file, write_to_file, replace_file_content, multi_replace_file_content, list_dir,
            find_by_name, grep_search, read_url_content, search_web, invoke_subagent, manage_task send_input
            -> Bash (BypassSandbox as dangerouslyDisableSandbox), Read, Write, Edit, Edit, LS, Glob, Grep, WebFetch,
            WebSearch, Task, Bash (command = Input) (each decided on the argument the tool itself reads)

What each harness exposes decides what Tracekit can see: Gemini CLI and Droid do not give tool calls an id, so pre and post
events are paired by (tool, arguments) in order, and Antigravity CLI's by (step index, tool, arguments); Cursor and
Qwen Code report failures through postToolUseFailure.
Reasoning capture reads Claude Code's transcript format only and is off for these harnesses."""
import contextlib
import hashlib
import io
import json
import os
import posixpath
import re
import sys
import urllib.parse

from . import __version__, hook as H
from .core import canon
from .locking import lock_file, unlock_file
from .policy2.classes import PATH_KEYS, first

HARNESSES = ("codex", "cursor", "gemini", "opencode", "goose", "qwen", "droid", "antigravity")
AGENT_NAMES = {"codex": "codex", "cursor": "cursor", "gemini": "gemini-cli", "opencode": "opencode", "goose": "goose",
               "qwen": "qwen-code", "droid": "droid", "antigravity": "antigravity"}
V2_MODULE = "tracekit.integrations.harness_hooks"
CURSOR_SAID = ("afterAgentThought", "afterAgentResponse")   # Cursor's events with what its model said (v2 records them)

GEMINI_TOOLS = {"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "write_file": "Write", "replace": "Edit",
                "glob": "Glob", "search_file_content": "Grep", "list_directory": "LS", "web_fetch": "WebFetch",
                "google_web_search": "WebSearch", "save_memory": "Memory"}
# Qwen Code keeps Gemini CLI's names, except where it renamed a tool (its docs: tools/file-system, tools/introduction)
# (monitor runs its `command` in a shell, as run_shell_command does; notebook_edit writes `notebook_path`)
QWEN_TOOLS = {**GEMINI_TOOLS, "edit": "Edit", "grep_search": "Grep", "web_search": "WebSearch", "todo_write": "TodoWrite",
              "agent": "Task", "monitor": "Bash", "notebook_edit": "NotebookEdit"}
# each release's name for the path a Gemini CLI or Qwen Code file tool reads: Gemini CLI renamed read_file's
# absolute_path to file_path, the directory tools' path to dir_path and read_many_files' paths to include; Qwen Code
# kept the old names
GEMINI_PATH_ARGS = ("file_path", "absolute_path", "notebook_path", "dir_path", "path")
# a URL in Gemini CLI's web_fetch prompt: its scheme in any case (WHATWG URL parsing), up to a character JavaScript's
# \s matches (the prompt is split on them)
WEB_FETCH_URL = re.compile(r"https?://[^\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+", re.I)
# a Delete is an Edit, as a Codex patch's Delete File is: the file rules (a credentials file, the transcripts) read it
CURSOR_TOOLS = {"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep", "Delete": "Edit", "Task": "Task", "Edit": "Edit"}
OPENCODE_TOOLS = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "apply_patch": "Edit",
                  "patch": "Edit", "glob": "Glob", "grep": "Grep", "webfetch": "WebFetch", "websearch": "WebSearch",
                  "task": "Task", "todowrite": "TodoWrite"}
# goose's hooks guide, Tool Input Keys: the path a tool itself reads decides, as for OpenCode (read_image reads
# `source`, not `path`: a decoy `path` beside it must not move the decision)
GOOSE_TOOLS = {"shell": "Bash", "write": "Write", "edit": "Edit", "tree": "LS", "read_image": "Read"}
GOOSE_PATH_ARG = {"write": "path", "edit": "path", "tree": "path", "read_image": "source"}
DROID_TOOLS = {"Execute": "Bash", "Create": "Write", "ApplyPatch": "Edit", "FetchUrl": "WebFetch"}
DROID_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd")
# Antigravity CLI's hooks reference (antigravity.google/docs/hooks): each Tracekit key is set from the argument the
# tool itself reads, so a decoy key the model sends beside it never moves the decision. BypassSandbox runs a
# run_command outside agy's terminal sandbox (google-antigravity/antigravity-cli#1304): TK-A003 holds it
AGY_TOOLS = {"run_command": "Bash", "view_file": "Read", "write_to_file": "Write", "replace_file_content": "Edit",
             "multi_replace_file_content": "Edit", "list_dir": "LS", "find_by_name": "Glob", "grep_search": "Grep",
             "read_url_content": "WebFetch", "search_web": "WebSearch", "invoke_subagent": "Task"}
AGY_ARGS = {"run_command": {"command": "CommandLine", "dangerouslyDisableSandbox": "BypassSandbox"},
            "view_file": {"file_path": "AbsolutePath"}, "write_to_file": {"file_path": "TargetFile"},
            "replace_file_content": {"file_path": "TargetFile"}, "multi_replace_file_content": {"file_path": "TargetFile"},
            "list_dir": {"file_path": "DirectoryPath"}, "find_by_name": {"file_path": "SearchDirectory", "pattern": "Pattern"},
            "grep_search": {"file_path": "SearchPath", "pattern": "Query"}, "read_url_content": {"url": "Url"}}
AGY_HOOK = "tracekit"   # the name Tracekit's hook has in agy's hooks.json, which maps each hook's name to its events
AGY_EVENTS = ("PreToolUse", "PostToolUse")
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
    if harness == "droid":
        if name == "ApplyPatch":
            def strings(value):
                if isinstance(value, str):
                    yield value
                elif isinstance(value, dict):
                    for child in value.values():
                        yield from strings(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from strings(child)

            text = "\n".join(strings(ti))
            files = [f.strip() for f in PATCH_FILE.findall(text)]
            ti["paths"] = files
            ti["file_path"] = files[0] if files else None
        return DROID_TOOLS.get(name, name), ti
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
    if harness in ("gemini", "qwen"):
        mapped = (QWEN_TOOLS if harness == "qwen" else GEMINI_TOOLS).get(name, name)
        if mapped != "Bash":   # a shell command's dir_path is where it runs, not a file it reads
            lists = [ti.get(k) for k in (("paths", "include") if name == "read_many_files" else ("paths",))]
            files = list(dict.fromkeys(f for f in [ti.get(k) for k in GEMINI_PATH_ARGS] + [
                f for v in lists if isinstance(v, list) for f in v] if isinstance(f, str)))
            for k in ("absolute_path", "notebook_path", "dir_path"):
                if k in ti and "file_path" not in ti:
                    ti["file_path"] = ti[k]
            # every path the tool may read is decided (the policy reads the first path key and `paths`), so a key one
            # release ignores never replaces the one another reads
            decided = [first(ti, *PATH_KEYS), *(ti["paths"] if isinstance(ti.get("paths"), list) else ())]
            if any(f not in decided for f in files):
                ti["paths"] = files
        if name == "web_fetch":   # Gemini CLI fetches every URL its prompt names, Qwen Code its `url`: each is decided
            # lean: a URL Qwen Code's prompt only names is decided as if fetched; read the prompt for Gemini CLI alone
            # if that stops a fetch a person needs
            prompt = ti.get("prompt")
            urls = list(dict.fromkeys([u for u in [ti.get("url")] if isinstance(u, str)]
                                      + (WEB_FETCH_URL.findall(prompt) if isinstance(prompt, str) else [])))
            if urls:
                ti.setdefault("url", urls[0])
                if urls != [ti["url"]]:
                    ti["urls"] = urls
        return mapped, ti
    if harness == "opencode":
        # the path the tool itself reads decides, never another path key the model sent beside it (OpenCode drops
        # unknown keys before the tool runs, so a decoy `file_path` would be decided but never used)
        if name in OPENCODE_PATH_ARG:
            ti["file_path"] = ti.get(OPENCODE_PATH_ARG[name])
        if name in ("apply_patch", "patch"):   # every file OpenCode's parser finds, whatever paths the model sent (patch:
            # 1.0's tool, off by default, with the same parser and argument); releases of 2026-01-18 to 2026-02-23
            # (1.2.0) read a header only up to its next ':' (split(":", 2)): both are decided
            files = [JS_TRIM.sub("", g) for f in OPENCODE_PATCH_FILE.findall(str(ti.get("patchText") or ""))
                     for g in dict.fromkeys((f, f.split(":")[0]))]
            ti["paths"] = files
            ti["file_path"] = files[0] if files else None
        return OPENCODE_TOOLS.get(name, name), ti
    if harness == "goose":
        if name == "read_image":
            # decided by scheme, as goose's url::Url::parse reads the source: tabs and newlines dropped, outer spaces and
            # controls trimmed, backslashes read as slashes in a web URL (https:x.example/a, HTTPS:\\x.example\a)
            src = re.sub(r"[\t\n\r]", "", str(ti.get("source") or "")).strip("".join(map(chr, range(33))))
            parts = urllib.parse.urlsplit(src.replace("\\", "/"))
            if parts.scheme.lower() in ("http", "https"):
                return "WebFetch", {**ti, "url": src.replace("\\", "/")}
            if parts.scheme.lower() == "file":   # goose reads a file: URL's path, made absolute (file:etc/x is /etc/x)
                ti["file_path"] = posixpath.normpath("/" + urllib.parse.unquote(parts.path).lstrip("/"))
                return GOOSE_TOOLS[name], ti
        if name in GOOSE_PATH_ARG:
            ti["file_path"] = ti.get(GOOSE_PATH_ARG[name])
        if "__" in name and not name.startswith("mcp__"):   # an extension/MCP tool, as goose namespaces it
            return "mcp__" + name, ti
        return GOOSE_TOOLS.get(name, name), ti
    if harness == "antigravity":
        if name == "manage_task" and ti.get("Action") == "send_input":   # input typed into a background run_command
            ti["command"] = ti.get("Input")
            return "Bash", ti
        ti.update({ours: ti.get(theirs) for ours, theirs in AGY_ARGS.get(name, {}).items()})
        return AGY_TOOLS.get(name, name), ti
    return name, ti


def _paired_ids(harness, run_id, tool_name, ti, phase, drop=None):
    """Tool events without a call id: pair pre/post by (tool, arguments), first in first out, per harness and session.
    drop: the id of a blocked pre-tool call, which gets no post-tool event; it leaves the queue."""
    from . import client
    key = drop.split("_")[1] if drop else hashlib.sha256((tool_name + "|" + canon(ti)).encode()).hexdigest()[:16]
    prefix = "gem" if harness == "gemini" else harness
    path = os.path.join(client.client_dir(), "runs", harness + "-" + hashlib.sha256(run_id.encode()).hexdigest()[:16] + ".json")
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
                tid = f"{prefix}_{key}_{st['n']}"
                st["pending"].setdefault(key, []).append(tid)
            else:
                q = st["pending"].get(key) or []
                tid = q.pop(0) if q else f"{prefix}_{key}_unpaired"
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
    out = {"cwd": p.get("cwd") or (p.get("workspace_roots") or [None])[0],
           "transcript_path": p.get("transcript_path"), "model": p.get("model")}
    if harness in ("codex", "qwen", "droid"):   # Claude Code's payloads; Qwen Code adds PostToolUseFailure
        out["session_id"] = p.get("session_id")
        m = {"PreToolUse": "PreToolUse", "PostToolUse": "PostToolUse", "UserPromptSubmit": "UserPromptSubmit",
             "SessionStart": "SessionStart", "SessionEnd": "SessionEnd"}
        if harness == "qwen":
            m["PostToolUseFailure"] = "PostToolUseFailure"
        if ev not in m:
            return None
        out["hook_event_name"] = m[ev]
        if ev in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_use_id")
            if harness == "droid":   # Droid's documented stdin carries no call id
                out["tool_use_id"] = out["session_id"] and _paired_ids(
                    harness, out["session_id"], out["tool_name"], out["tool_input"], "pre" if ev == "PreToolUse" else "post")
            if ev != "PreToolUse":
                out["tool_response"] = p.get("tool_response")
            if ev == "PostToolUseFailure":
                out["error"] = p.get("error")
        if ev == "UserPromptSubmit":
            out["prompt"] = p.get("prompt")
            if harness == "qwen":
                # Qwen Code also fires it as it continues after tool results (prompt "") and with a Stop hook's reason;
                # only a prompt the person submitted carries submitted_prompt (0.21.1 on; 0.21.12 for qwen -p), before
                # @file expansion (handle reads the live constraints from this out['prompt'] too, not the raw payload)
                typed = p.get("submitted_prompt")
                if not isinstance(typed, str) or not typed.strip():
                    return None
                out["prompt"] = typed
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
                       tool_use_id=out["session_id"] and _paired_ids(harness, out["session_id"], name, ti,
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
    if harness == "goose":
        # goose names its event `event`, not `hook_event_name` (the v2 hook's command-line event arrives as the
        # latter, so it wins when both are present); its payload carries no tool result or error text
        ev = p.get("hook_event_name") or p.get("event") or ""
        out["cwd"] = out["cwd"] or p.get("working_dir")
        out["session_id"] = p.get("session_id")
        if ev in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            out["hook_event_name"] = ev
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_call_id")
            out["tool_response"] = p.get("tool_response")
            out["error"] = p.get("error")
            return out
        return None
    if harness == "antigravity":
        # agy's payload names no event (its hook's command line does) and gives a call no id: the stepIdx, tool and
        # arguments it sends with a call's PreToolUse and PostToolUse pair them (a step can hold more than one call),
        # and a result that matches no call exactly stays unpaired, its call a gap, never guessed; a result is not
        # sent, only its error text (empty if it ran)
        # lean: the same stepIdx and toolCall on both is agy's documented contract, not yet seen in a live session
        if ev not in AGY_EVENTS:
            return None
        call = p.get("toolCall") if isinstance(p.get("toolCall"), dict) else {}
        raw = str(call.get("name") or "?")
        name, ti = tool(harness, raw, call.get("args"))
        sid, step = p.get("conversationId"), p.get("stepIdx")
        out.update(cwd=(p.get("workspacePaths") or [None])[0], transcript_path=p.get("transcriptPath"),
                   model=p.get("modelName"), session_id=sid, hook_event_name=ev, tool_name=name, tool_input=ti,
                   tool_use_id=sid and type(step) is int and _paired_ids(
                       harness, sid, f"{step}|{raw}", ti, "pre" if ev == "PreToolUse" else "post"))
        if ev == "PostToolUse" and p.get("error"):
            out.update(hook_event_name="PostToolUseFailure", error=p["error"])
        return out
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
PAIRED = ("gemini", "droid", "antigravity")   # the harnesses whose call ids _paired_ids makes


# goose's Code Mode tools: execute_typescript and execute_bash before goose 1.56, execute_javascript since, also
# as code_execution__<name>; each runs tool calls through dispatch_tool, which runs no hooks
GOOSE_CODE_MODE = ("execute_javascript", "execute_typescript", "execute_bash")


def _blocked_goose_tool(tool_name):
    """The reason a goose tool is denied in the hook itself (it runs calls the hook never sees), else None.
    tool_name: goose's own name for the tool, before it is mapped."""
    name = tool_name.removeprefix("code_execution__")
    if name in GOOSE_CODE_MODE:
        return (f"Blocked by Tracekit: goose's {name} (Code Mode) runs tool calls through dispatch_tool with no "
                "PreToolUse hook, so Tracekit can't decide them; make each call itself instead.")
    return None


def run(harness, raw, stdout=None, stderr=None, event=None):
    """Handle one hook invocation (`event`: the hook event from the command line, or None). -> exit code. Writes the
    harness's expected stdout. A payload that is not a JSON object raises: entry answers it."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = json.loads(raw) if raw.strip() else {}
    if not isinstance(p, dict):
        raise ValueError("the hook payload is not a JSON object")
    p = dict(p, hook_event_name=event) if event else p
    is_pre = p.get("hook_event_name") in PRE or (harness == "goose" and p.get("event") in PRE)
    q = normalise(harness, p)
    if q is None:
        _reply(harness, stdout, True, "", is_pre)
        return 0
    reason = _blocked_goose_tool(str(p.get("tool_name") or "")) if harness == "goose" and is_pre else None
    if reason is not None:
        print(reason, file=stderr)
        _reply(harness, stdout, False, reason, is_pre)
        return _exit(harness, 2, is_pre)
    H.AGENT_NAME = AGENT_NAMES[harness]
    err = Tee(stderr)
    real_stdin, real_stderr = sys.stdin, sys.stderr
    sys.stdin, sys.stderr = io.StringIO(json.dumps(q)), err
    try:
        code = H.main(harness_reasoning=False)
    finally:
        sys.stdin, sys.stderr = real_stdin, real_stderr
    if code and harness in PAIRED and is_pre and q.get("tool_use_id"):   # a blocked call gets no post-tool event
        with contextlib.suppress(Exception):   # bookkeeping: never in the way of the answer
            _paired_ids(harness, q["session_id"], None, None, "pre", drop=q["tool_use_id"])
    msg = err.getvalue().strip()
    _reply(harness, stdout, code == 0, msg, is_pre)
    return _exit(harness, 2 if code else 0, is_pre)


def _exit(harness, code, is_pre):
    """The exit status that carries a hook's answer (code: 0 allowed, else blocked). Codex blocks a pre-tool call at
    exit 2 with a reason on stderr, whatever a shell startup file printed to stdout; on Windows its hooks run under
    PowerShell, which hands it 2 as 1, so there the JSON deny _reply writes carries the block, at exit 0, the only
    status at which Codex reads it. Only a tool call is blocked: a failed prompt or result exits 1, since at 2 Gemini
    CLI erases the prompt or hides the result, and Codex and Cursor block them. Antigravity CLI reads an answer only
    from the JSON of a hook that exits 0 (any other status is a hook that failed, and a failed PostToolUse hook replaced
    the call's result with an error before agy 1.4.7): its hooks always exit 0."""
    if harness == "antigravity":
        return 0
    if code and not is_pre:
        return 1
    return 0 if harness == "codex" and is_pre and os.name == "nt" else code


def _reply(harness, stdout, allowed, msg, is_pre):
    if harness == "cursor":
        if is_pre:
            stdout.write(json.dumps({"permission": "allow"} if allowed else
                                    {"permission": "deny", "user_message": msg[:500], "agent_message": msg[:500]}))
        else:
            stdout.write("{}")
    elif harness == "gemini":
        # stdout must be JSON only; a deny only for a tool call
        stdout.write(json.dumps({} if allowed or not is_pre else {"decision": "deny", "reason": msg[:500]}))
    elif harness == "antigravity":
        # agy reads stdout as its hook result message: only documented fields (another fails the hook), on every event.
        # `allow` leaves the call to agy's own permissions, as the other hooks' exit 0 does
        stdout.write(json.dumps({} if not is_pre else {"decision": "allow"} if allowed else
                                {"decision": "deny", "reason": msg[:500] or "Blocked by Tracekit"}))
    elif harness in ("codex", "droid") and not allowed and is_pre:
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
            "goose": os.path.join(base, ".agents", "plugins", "tracekit", "hooks", "hooks.json"),
            "qwen": os.path.join(base, ".qwen", "settings.json"),
            "droid": os.path.join(base, ".factory", "hooks.json"),
            "antigravity": os.path.join(base, ".agents", "hooks.json") if project else
                           os.path.join(base, ".gemini", "config", "hooks.json"),
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
            plugin = None if uninstall else _opencode_plugin(python, v2).encode("utf-8")
            if raw not in (None, plugin):
                files.backup(d, name, raw)
            if uninstall:
                if raw is not None:
                    target = name if isinstance(d, int) else path
                    os.unlink(target, **({"dir_fd": d} if isinstance(d, int) else {}))
            elif raw != plugin:
                files.write(d, name, plugin, 0o600)
        finally:
            files.close(d)
    except (files.UnsafePath, OSError) as e:
        raise SettingsError(f"{path}: {e}") from e
    new = "v2" if v2 else "v1"
    if old and (uninstall or old != new):
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else
              f"Tracekit {old} hooks replaced by {new} hooks in {path}")
    return path


GOOSE_PLUGIN = {"name": "tracekit", "version": __version__,
                "description": "Tracekit hooks: policy gates and signed records for goose tool calls."}
GOOSE_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")


def _install_goose(path, uninstall=False, v2=False, python=None):
    """Install one owned goose plugin without overwriting a plugin that is not Tracekit's. goose runs a rule with no
    matcher for every tool (a bare "*" matcher is an invalid regex goose silently skips), its timeout is in seconds,
    and only a PreToolUse action carries on_failure: block."""
    from .install import SettingsError, _atomic_write_json, _backup_changed, _hook_command
    path = os.path.abspath(path)
    plugin_dir = os.path.dirname(os.path.dirname(path))   # <plugin>/hooks/hooks.json
    manifest = os.path.join(plugin_dir, "plugin.json")
    if uninstall and not os.path.lexists(path) and not os.path.lexists(manifest):   # nothing made for it either
        return path
    if os.path.exists(manifest):   # collision first, before changing anything
        try:
            with open(manifest, encoding="utf-8") as f:
                owned = json.load(f)
        except (OSError, ValueError) as e:
            raise SettingsError(f"{manifest} is not valid JSON ({e}); Tracekit did not change it.") from e
        if not isinstance(owned, dict) or owned.get("name") != "tracekit":
            raise SettingsError(f"{manifest} is not Tracekit's plugin; Tracekit did not change it.")
    s, txt = {}, None
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                txt = f.read()
            s = json.loads(txt) if txt.strip() else {}
        except (OSError, ValueError) as e:
            raise SettingsError(f"{path} is not valid JSON ({e}); Tracekit did not change it.") from e
        if not isinstance(s, dict):
            raise SettingsError(f"{path} must contain a JSON object; Tracekit did not change it.")
    hooks = s.get("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {path} must be an object; Tracekit did not change it.")
    new, removed = "v2" if v2 else "v1", set()

    def ours(cmds):
        vs = {_version(c) for c in cmds} - {None}
        removed.update(vs)
        return bool(vs)

    def cmd(ev):
        return _hook_command(V2_MODULE if v2 else "tracekit.agent_hooks", "entry",
                             ("goose", ev) if v2 else ("goose",), python, ev == "PreToolUse")
    for ev in GOOSE_EVENTS:
        lst = hooks.get(ev)
        if lst is not None and not isinstance(lst, list):
            raise SettingsError(f"hooks.{ev} in {path} must be a list; Tracekit did not change it.")
        kept = [g for g in (lst or []) if not (isinstance(g, dict) and ours(
            [h.get("command") for h in (g.get("hooks") or []) if isinstance(h, dict)]))]
        if not uninstall:
            action = {"type": "command", "command": cmd(ev), "timeout": 600 if ev == "PreToolUse" else 30}
            if ev == "PreToolUse":   # a hook that can't run blocks the call; other events ignore on_failure
                action["on_failure"] = "block"
            kept.append({"hooks": [action]})   # no matcher: goose matches every tool of the event
        if kept:
            hooks[ev] = kept
        else:
            hooks.pop(ev, None)
    if hooks:
        s["hooks"] = hooks
    else:
        s.pop("hooks", None)
    changed = _backup_changed(path, txt, s)
    if uninstall and not s:
        # the only content was Tracekit's hooks: remove the plugin's files, not other content (a file with other
        # keys falls through to the write below, and its manifest stays)
        if os.path.lexists(path):
            os.unlink(path)
        if os.path.exists(manifest):   # validated above as Tracekit's, when present
            os.unlink(manifest)
        old = " and ".join(sorted(removed))
        if old:
            print(f"Tracekit {old} hooks removed from {path}")
        return path
    if not uninstall:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(manifest):
            _atomic_write_json(manifest, GOOSE_PLUGIN)
    if changed:
        _atomic_write_json(path, s)
    old = " and ".join(sorted(removed if uninstall else removed - {new}))
    if old:
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else f"Tracekit {old} hooks replaced by {new} hooks in {path}")
    return path


def install(harness, project=None, uninstall=False, v2=False, python=None, path=None):
    """Add (or remove) Tracekit's hooks, v1 or the v2 hook (python: see install._hook_command), in the harness's
    config file (path, or config_path), replacing those of the other version. -> the file's path."""
    from .install import SettingsError, _atomic_write_json, _backup_changed, _hook_command
    path = path or config_path(harness, project)
    if harness == "opencode":
        return _install_opencode(path, uninstall, v2, python)
    if harness == "goose":
        return _install_goose(path, uninstall, v2, python)
    if harness == "droid" and uninstall and not os.path.exists(path):
        return path
    if harness == "droid" and not uninstall and not os.path.exists(path):
        legacy = os.path.join(os.path.dirname(path), "hooks", "hooks.json")
        if os.path.exists(legacy):
            raise SettingsError(f"{legacy} is Droid's legacy hooks file: save once in Droid's /hooks so Droid moves it "
                                f"to {path}, then run init again. Tracekit did not change it.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    s, txt = {}, None
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                txt = f.read()
            s = json.loads(txt) if txt.strip() else {}
        except (OSError, ValueError) as e:
            raise SettingsError(f"{path} is not valid JSON ({e}); Tracekit did not change it.") from e
        if not isinstance(s, dict):
            raise SettingsError(f"{path} must contain a JSON object; Tracekit did not change it.")
    if harness == "droid" and not uninstall and not os.path.exists(path):
        settings = os.path.join(os.path.dirname(path), "settings.json")
        if os.path.exists(settings):
            try:
                with open(settings, encoding="utf-8") as f:
                    fallback = json.load(f)
                fallback = fallback.get("hooks", {})
                if not isinstance(fallback, dict):
                    raise ValueError("hooks must be an object")
            except (OSError, ValueError, AttributeError) as e:
                raise SettingsError(f"{settings}: {e}; Tracekit did not change it.") from e
            # Droid reads settings hooks only while the standalone file is absent; preserve them when creating it.
            s = dict(fallback)
    # Droid's standalone hooks.json is the event map; only its settings.json nests that map under `hooks`. agy's maps
    # each hook's name to its event map: Tracekit's is AGY_HOOK
    key = AGY_HOOK if harness == "antigravity" else "hooks"
    hooks = s if harness == "droid" else s.setdefault(key, {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'{key}' in {path} must be an object; Tracekit did not change it.")
    new, removed = "v2" if v2 else "v1", set()

    def cmd(ev):   # the v2 hook names its event, so it can block a pre-tool payload it cannot read; agy's payload names
        # none, so its v1 hook does too
        c = _hook_command(V2_MODULE if v2 else "tracekit.agent_hooks", "entry",
                          (harness, ev) if v2 or harness == "antigravity" else (harness,), python, ev in PRE,
                          harness == "antigravity")
        # on Windows, Codex and Gemini CLI run a hook's command under PowerShell (Codex under cmd.exe when PowerShell
        # isn't found or the session has no single local environment). PowerShell runs a quoted program path only
        # through its call operator, which cmd.exe can't parse: an interpreter path that needs no quotes goes bare,
        # which both run
        # assume Droid runs hooks under cmd.exe; Qwen Code does, so a path that needs quotes keeps cmd.exe's form there,
        # and one that doesn't goes bare, which either shell runs
        if os.name != "nt" or harness in ("cursor", "droid"):
            return c
        m = re.match(r'"([A-Za-z0-9_.:\\-]+)"', c)   # cmd.exe ends a program word at /
        return m.group(1) + c[m.end():] if m else c if harness == "qwen" else f"& {c}"

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
                lst.append({"command": cmd(ev), "type": "command", "timeout": timeout,
                            "failClosed": closed and ev in PRE})   # on another event Cursor blocks a prompt too
            if lst:
                hooks[ev] = lst
            else:
                hooks.pop(ev, None)
    else:
        events = (DROID_EVENTS if harness == "droid" else AGY_EVENTS if harness == "antigravity" else
                  ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"] if harness == "codex"
                  else ["PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "SessionEnd"]
                  if harness == "qwen" else ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart", "SessionEnd"])
        tools = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "BeforeTool", "AfterTool"}
        for ev in events:
            groups = [g for g in entries(ev) if not (isinstance(g, dict) and ours(
                [h.get("command") for h in g.get("hooks", []) if isinstance(h, dict)]))]
            if not uninstall:
                h = {"type": "command", "command": cmd(ev)}
                # ms for Gemini CLI; newer Qwen Code reads seconds, but 1000 or more still as ms, so 600 s in both
                if harness in ("gemini", "qwen"):   # holds wait for approval (Qwen Code's default is 60 s)
                    h.update(name="tracekit", timeout=600_000 if ev in PRE else 30_000)
                else:
                    h["timeout"] = 600 if ev == "PreToolUse" else 30
                groups.append({"matcher": "*", "hooks": [h]} if ev in tools else {"hooks": [h]})
            if groups:
                hooks[ev] = groups
            else:
                hooks.pop(ev, None)
    if harness == "antigravity":   # Tracekit's named hook holds only its own two entries, rewritten whole: agy loads a
        # named hook with "enabled": false and never runs it
        if not uninstall:
            s[key] = {ev: hooks[ev][-1:] for ev in AGY_EVENTS}
        elif removed:
            s.pop(key)
    if not hooks and harness != "droid":
        s.pop(key, None)
    changed = _backup_changed(path, txt, s)
    if uninstall and harness == "droid" and not s:
        os.unlink(path)
    elif changed:
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
        return run(harness, raw, event=event)
    except Exception as e:
        try:
            parsed = json.loads(raw)
            pre = (event or parsed.get("hook_event_name")
                   or (parsed.get("event") if harness == "goose" else None)) in PRE
        except Exception:
            pre = True   # unreadable: answered as a tool call
        # OpenCode's plugin passes the model's arguments unchecked: a call its hook can't decide doesn't run, as when
        # the hook can't start; nor, in any hook, one whose payload nests too deep to read
        closed = event in PRE or isinstance(e, RecursionError) or H.fail_closed()
        print(f"[tracekit] {harness} hook error ({e}); "
              + ("allowing (fail-open)" if not closed else "blocking" if pre else "event not recorded"), file=sys.stderr)
        _reply(harness, sys.stdout, not closed, str(e), pre)
        return _exit(harness, 2 if closed else 0, pre)


if __name__ == "__main__":
    sys.exit(entry(*sys.argv[1:3]))
