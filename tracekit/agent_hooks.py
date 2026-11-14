"""Hooks for Codex CLI, Cursor, Gemini CLI, OpenCode, Kilo Code, goose, Qwen Code, Factory Droid, Antigravity CLI, Crush,
Devin (CLI and Desktop), Cline (CLI and VS Code extension), GitHub Copilot CLI and CodeBuddy Code, on the Claude
Code pipeline.

    tracekit init --dev --agent codex        # ~/.codex/hooks.json
    tracekit init --dev --agent cursor       # ~/.cursor/hooks.json
    tracekit init --dev --agent gemini       # ~/.gemini/settings.json
    tracekit init --dev --agent opencode     # ~/.config/opencode/plugin/tracekit.js
    tracekit init --dev --agent kilo         # ~/.config/kilo/plugin/tracekit.js (project: .kilo/plugin/tracekit.js)
    tracekit init --dev --agent goose        # ~/.agents/plugins/tracekit/hooks/hooks.json
    tracekit init --dev --agent qwen         # ~/.qwen/settings.json
    tracekit init --dev --agent droid        # ~/.factory/hooks.json
    tracekit init --dev --agent antigravity  # ~/.gemini/config/hooks.json (project: .agents/hooks.json)
    tracekit init --dev --agent crush        # ~/.config/crush/crush.json (project: crush.json)
    tracekit init --dev --agent devin        # ~/.config/devin/config.json (project: .devin/hooks.v1.json)
    tracekit init --dev --agent cline        # ~/Documents/Cline/Hooks/<event> (project: .clinerules/hooks/<event>)
    tracekit init --dev --agent copilot      # ~/.copilot/hooks/tracekit.json (project: .github/hooks/tracekit.json)
    tracekit init --dev --agent codebuddy    # ~/.codebuddy/settings.json (project: .codebuddy/settings.json)
    (add --project to write the project-level file instead)

Each harness's hook payload is translated into the Claude Code hook shape, then handled by tracekit.hook: the same
policy gate before the tool runs (deny blocks, ask holds for approval), the same signed events, the same transcript
prefix hashing where the harness passes a transcript path. Only the reply to the harness differs.

Tool names are mapped onto Tracekit's policy vocabulary so the default rules apply unchanged:

    harness            -> Tracekit
    Codex   Bash, write_stdin, apply_patch, mcp__s__t     Bash, Bash (command = chars), Edit (paths: every file the
                                                          patch adds, updates, deletes or moves to), mcp__s__t
    Cursor  Shell, Read, Write, Grep, Delete, MCP:t   Bash, Read, Write, Grep, Edit, mcp__cursor__t (its hook sends an
            edit as a Write of the file); its transcripts' StrReplace, ApplyPatch, EditNotebook, search_replace, write,
            delete_file, edit_notebook -> Edit, Edit (all patch file headers in paths), NotebookEdit, Edit, Write, Edit,
            NotebookEdit
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
    Kilo    OpenCode's tools, names and arguments, and OpenCode's plugin; its own background_process, notebook_read,
            notebook_edit, send_file, generate_image -> Bash, Read, NotebookEdit, Read, Write (decided on their `path`;
            generate_image with an `image` as a Read of it and the `path`); notebook_execute is blocked in the hook
    Crush   bash, view, write, edit, multiedit, lsp_replace_symbol, lsp_rename, ls, grep, glob, fetch, download,
            mcp_<server>_<tool>
            -> Bash, Read, Write, Edit, Edit, Edit, Edit, LS, Grep, Glob, WebFetch, Write, mcp__<server>_<tool>
            (lsp_rename, ls, grep and glob decided on the `path` they read; its payload is Claude Code's shape);
            agent, agentic_fetch and Docker MCP Gateway's code-mode tools are denied in the hook (the calls they make
            run no hooks), and so is a built-in tool's input with argument names Crush may read otherwise
    Devin   exec, write_to_process, read, write, edit, apply_patch, grep, glob, webfetch, mcp__s__t
            -> Bash, Bash (command = all its text), Read, Write, Edit (every path under a key ending in path, paths or
            file, case and _ ignored), Edit (all patch and diff file headers in paths), Grep, Glob, WebFetch, mcp__s__t
            (its payload is Claude Code's shape); a read, write, edit, apply_patch or webfetch with nothing to decide
            it on, or a url spelled other than `url`, is denied in the hook; init turns off its reading of Claude
            Code's hooks, which would decide each call a second time
    Cline   run_commands, read_files, editor, apply_patch, fetch_web_content
            -> Bash (every command line, one per line, in any shape Cline takes), Read (every file), Edit (its `path`;
            it creates a missing file), Edit (every file the patch names), WebFetch (every URL); a call Tracekit can't
            read a command, file or URL from is denied. Its hook blocks by answering a cancel, which stops Cline's
            task; the VS Code extension's payload carries no call id
    Copilot bash, powershell, write_bash, write_powershell, apply_patch, create, edit, str_replace_editor, view, glob,
            grep, rg, web_fetch, task, write_agent, web_search, <server>-<tool>
            -> Bash, PowerShell, Bash and PowerShell (command = the typed input), Edit (every file the patch adds,
            updates, deletes or moves to), Write, Edit, Read, Write or Edit (by its command), Read, Glob, Grep, Grep,
            WebFetch, Task, Task, mcp:github-mcp-server/web_search, mcp__<server>-<tool> (Copilot CLI 1.0.107's names;
            an earlier release sends no toolCallId, and its calls are blocked; each file tool decided on the `path`
            or `paths` it reads). The preToolUse payload doesn't say which tools are MCP
            ones, and joins a server's name and its tool's with a `-` either may hold: any other name with a `-` is
            decided as an MCP tool under every split and as an unknown tool, and the strictest decision stands. Every
            custom MCP tool captured on 1.0.107 arrived as <server>-<tool> (server tracekit-alpha's probe_note as
            tracekit-alpha-probe_note), none under a bare name. Copilot turns a space or a dot in either name into
            `-` before the hook sees it (server `tracekit space`, tool `read.note`: tracekit-space-read-note), so a
            rule that names a server or tool with one doesn't match, while the rules on a tool's words do; it cuts
            the joined name at 64 characters, and a name that long is denied in the hook
    CodeBuddy Code sends Claude Code's payloads, event names and tool names; its own NotebookRead and ViewImage
            -> Read (of the path each reads), LibraryUpload decided as an upload of its file, and DeferExecuteTool as
            the call it runs

    OpenHands  terminal, file_editor, apply_patch, glob, grep, MCP tools
            -> Bash (is_input: text typed into the running command, later), Read (view), Write (create) or Edit (the
            rest) on `path`, Edit (every patch file header in paths), Glob, Grep, MCP names as they are; its payload
            is Claude Code's under other keys (event_type, working_dir, message), and tool_input's `kind` is dropped;
            a file_editor with no path or an apply_patch with no file header is denied in the hook


What each harness exposes decides what Tracekit can see: Gemini CLI, Droid, Devin, OpenHands and Cline's VS Code
extension do not give tool calls an id, so pre and post events are paired by (tool, arguments) in order, and Antigravity
CLI's by (step index, tool, arguments); Cursor and Qwen Code report failures through postToolUseFailure, and OpenHands
with is_error in its tool_response.
Reasoning capture reads Claude Code's transcript format only and is off for these harnesses."""
import contextlib
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import sys
import urllib.parse

from . import __version__, hook as H
from .core import canon
from .locking import lock_file, unlock_file
from .policy2.classes import PATH_KEYS, first

# each harness, with the agent name its runs record: the one list init, uninstall and doctor take theirs from
AGENT_NAMES = {"codex": "codex", "cursor": "cursor", "gemini": "gemini-cli", "opencode": "opencode", "kilo": "kilo",
               "goose": "goose", "qwen": "qwen-code", "droid": "droid", "antigravity": "antigravity", "crush": "crush",
               "devin": "devin", "cline": "cline", "gptme": "gptme", "openhands": "openhands",
               "copilot": "copilot", "codebuddy": "codebuddy-code"}
HARNESSES = tuple(AGENT_NAMES)
V2_MODULE = "tracekit.integrations.harness_hooks"
CURSOR_SAID = ("afterAgentThought", "afterAgentResponse")   # Cursor's events with what its model said (v2 records them)


# Copilot CLI 1.0.107's own tools. bash, apply_patch, view, glob, rg, web_fetch, task and web_search are as its
# preToolUse payloads name them (the tools it gives a GPT model); the others, which it gives other models, and every
# tool's arguments are as its bundle parses them (cli-main.js: view {path}, create {path, file_text}, edit and
# str_replace {path, old_str, new_str}, glob and grep {pattern, paths: a string or a list}, write_bash and
# write_powershell {shellId, input}). web_search is a tool of its built-in MCP server (its preMcpToolCall payload:
# serverName github-mcp-server), sent under its bare name; write_agent messages a sub-agent, as task starts one
COPILOT_TOOLS = {
    "bash": "Bash", "write_bash": "Bash", "powershell": "PowerShell", "write_powershell": "PowerShell",
    "apply_patch": "Edit", "edit": "Edit", "str_replace": "Edit", "create": "Write", "view": "Read",
    "glob": "Glob", "grep": "Grep", "rg": "Grep",
    "web_fetch": "WebFetch",
    "web_search": "mcp:github-mcp-server/web_search",
    "task": "Task", "write_agent": "Task",
}
COPILOT_EDITOR = {"view": "view", "create": "create"}   # str_replace_editor's commands; any other edits the file
COPILOT_PATH_TOOLS = ("view", "create", "edit", "str_replace")   # they read `path`
COPILOT_SEARCH_TOOLS = ("glob", "grep", "rg")   # they read `paths`
COPILOT_EVENTS = {"preToolUse": 600, "postToolUse": 30, "postToolUseFailure": 30}   # each with its hook's timeout, s
COPILOT_NAME_MAX = 64   # Copilot cuts a longer MCP tool name to this many characters
GEMINI_TOOLS = {"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "write_file": "Write", "replace": "Edit",
                "glob": "Glob", "search_file_content": "Grep", "grep_search": "Grep", "list_directory": "LS",
                "web_fetch": "WebFetch", "google_web_search": "WebSearch", "save_memory": "Memory"}
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
# what JavaScript's trim() takes off a string's ends: str.strip(JS_SPACE) does the same, in linear time
JS_SPACE = "\t\n\v\f\r \u00a0\u1680" + "".join(map(chr, range(0x2000, 0x200b))) + "\u2028\u2029\u202f\u205f\u3000\ufeff"
# Cursor's hooks name a call by what it does on the computer: an edit by any of its tools reaches preToolUse as a Read and
# then a Write of the whole file (file_path, content).
# A Delete is an Edit, as a Codex patch's Delete File is: the file rules (a credentials file, the transcripts) read it
CURSOR_TOOLS = {"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep", "Delete": "Edit", "Task": "Task", "Edit": "Edit"}
# Its transcripts name the model's edit tools (Cursor 3.29.15): StrReplace, EditNotebook, and an older prompt's
# search_replace, write, delete_file and edit_notebook, each with the argument its file is in. Cursor refuses a call
# without a string there; Tracekit then leaves the name unmapped, an unknown tool, as it does an ApplyPatch with no
# file header, rather than decide an edit of no file
CURSOR_EDITS = {"StrReplace": ("Edit", "path"), "search_replace": ("Edit", "file_path"), "write": ("Write", "file_path"),
                "delete_file": ("Edit", "target_file"), "EditNotebook": ("NotebookEdit", "target_notebook"),
                "edit_notebook": ("NotebookEdit", "target_notebook")}
CURSOR_PATH_ARGS = ("file_path", "path", "target_file", "filePath", "target_notebook")
OPENCODE_TOOLS = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "apply_patch": "Edit",
                  "patch": "Edit", "glob": "Glob", "grep": "Grep", "webfetch": "WebFetch", "websearch": "WebSearch",
                  "task": "Task", "todowrite": "TodoWrite"}
# goose's hooks guide, Tool Input Keys: the path a tool itself reads decides, as for OpenCode (read_image reads
# `source`, not `path`: a decoy `path` beside it must not move the decision)
GOOSE_TOOLS = {"shell": "Bash", "write": "Write", "edit": "Edit", "tree": "LS", "read_image": "Read"}
GOOSE_PATH_ARG = {"write": "path", "edit": "path", "tree": "path", "read_image": "source"}
# harness tools mapped to Bash whose effect comes after their post-tool hook: input typed into another running session
# (Codex's write_stdin, agy's manage_task send_input, Devin's write_to_process) or a command left running (Qwen Code's
# monitor, Kilo's background_process); normalise marks their payload `later`, and the hook takes no receipt of what
# they write (tracekit.model_receipt)
LATER = frozenset((("codex", "write_stdin"), ("qwen", "monitor"), ("antigravity", "manage_task"),
                   ("devin", "write_to_process"), ("kilo", "background_process"), ("copilot", "write_bash"),
                   ("copilot", "write_powershell")))
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
# Crush's built-in tools (internal/agent/tools/*.go): its payload and event names are Claude Code's, its tool names are
# lower case, and its file tools send `file_path`. download writes its `file_path`, so the file rules decide it as a
# Write, not as a fetch
# lean: a download's URL meets no fetch rule (TK-F002, TK-F012); decide it as a fetch too if a URL rule must see it
CRUSH_TOOLS = {"bash": "Bash", "view": "Read", "write": "Write", "edit": "Edit", "multiedit": "Edit",
               "lsp_replace_symbol": "Edit", "lsp_rename": "Edit", "ls": "LS", "grep": "Grep", "glob": "Glob",
               "fetch": "WebFetch", "download": "Write"}
CRUSH_PATH_TOOLS = ("lsp_rename", "ls", "grep", "glob")   # they read `path`, the directory they search, not `file_path`
# Devin's tools (docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks): its payload and event names are Claude Code's.
# lean: only exec's input (command, shell_id) is documented; read, write and edit are decided on every path under a
# key that may name one, apply_patch on every file a patch or diff header names, write_to_process on its one argument
# besides shell_id (the text it writes), until a recorded session names their fields
DEVIN_TOOLS = {"exec": "Bash", "write_to_process": "Bash", "read": "Read", "write": "Write", "edit": "Edit",
               "apply_patch": "Edit", "grep": "Grep", "glob": "Glob", "webfetch": "WebFetch"}
DEVIN_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd")
# a key Devin's read, write or edit may read its path from. Devin is closed source, and its decoder may match a key
# ignoring case, as Go's encoding/json does (K and ſ fold to k and s; so does str.casefold): the key casefolded and
# without `_` ends in path, paths or file
DEVIN_PATH_KEY = re.compile(r"(?:path|paths|file)$")
# a unified diff's file names: --- a/x and +++ b/x (up to a tab, where diff -u puts the time), and diff --git a/x b/x
DIFF_FILE = re.compile(r"^(?:(?:---|\+\+\+) ([^\t\n]+)|diff --git (.+)$)", re.M)


class UnreadableCall(ValueError):
    """A call a harness's mapping can't read on purpose (tool()): its hook blocks it (Cline's; goose's, which its v2
    hook blocks), and tracekit audit reports it as TK-HOOK-BLOCKED; any other ValueError is a bug."""


def _diff_names(name):
    """A unified diff's file name, without git's a/ or b/. git writes a name with a space, a quote, a backslash or a
    byte past ASCII in "…" with C escapes (\\" \\\\ \\t, \\303\\251): both the name with its quotes dropped and the
    unescaped one are decided."""
    names = [name]
    if len(name) > 1 and name[0] == name[-1] == '"':
        names = [name[1:-1]]
        try:
            names.append(name[1:-1].encode("latin-1").decode("unicode_escape").encode("latin-1").decode("utf-8"))
        except (UnicodeError, ValueError, DeprecationWarning):   # a bad escape (\q) warns, or raises under -W error
            pass
    return [re.sub(r"^[ab]/", "", n) for n in names]
# what each of these Devin tools is decided on: a call that sends none of it is denied in the hook (_blocked)
DEVIN_DECIDED_ON = {**dict.fromkeys(("read", "write", "edit"),
                                    "path under a key ending in path, paths or file (case and _ ignored)"),
                    "apply_patch": "file header (*** Add, Update or Delete File:, or a diff's ---, +++ or diff --git)",
                    "webfetch": "url under one key spelled url",
                    "write_to_process": "text under its one argument besides shell_id",
                    "exec": "command under a key spelled command (case ignored)"}
# what Tracekit can't read as it runs in text typed into a live terminal (write_to_process), and in an exec command,
# should Devin type one: a control character, which the line editor acts on (DEL and ^H erase, ^U discards the line,
# ^C drops it, tab completes, ESC starts a key sequence: an arrow recalls history; C1 too), and in typed text interactive
# bash's history expansion: a ! before anything but a blank, a line end, = or ( (bash leaves those), and a ^ starting a
# line (quick substitution). \n ends a line, and so does \r, which tool() reads as \n. exec keeps a tab (a heredoc's)
# lean: exec's ! isn't denied (git commit -m 'fix!', wait $!): an exec Devin types into bash may expand one
TYPED = {"write_to_process": re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]|!(?![ \t\n=(])|^[ \t]*\^", re.M),
         "exec": re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")}
# what a line typed into a running shell (write_to_process) may set or replay there that changes what a later line
# runs, which the policy, deciding one call at a time, can't see: history replay (fc; history -s, -r or -n), an alias
# defined, a key binding, a trap, a loaded builtin, the exec builtin (it can make the shell read commands from a file, or
# replace it), a shell option (set -o, +H …; shopt), a hashed path, a sourced file, a function, and the variables bash
# runs at each prompt (PROMPT_COMMAND, PS0 to PS4), finds commands by (PATH, BASH_ENV, BASH_CMDS: hash's table), or
# expands aliases from (BASH_ALIASES), or the loader loads code by, and a nameref (declare, typeset or local -n), which
# sets a variable under another name
# lean: exec isn't read so (a script there sources a venv or defines a function), though Devin may run it in that shell
SHELL_STATE = {"fc", "bind", "trap", "enable", "exec", "shopt", "hash", "source", "."}
STATE_VARS = re.compile(r"(?:PROMPT_COMMAND|PS[0124]|PATH|BASH_ENV|BASH_CMDS|BASH_ALIASES|LD_PRELOAD|LD_LIBRARY_PATH|"
                        r"LD_AUDIT|DYLD_\w+)(?:$|[\[=+])")
# OpenHands' tools (software-agent-sdk openhands-tools): tool_input is the Action's model_dump(), with a `kind` key and
# every optional field (null when unset); file_editor's tool name depends on its `command` (tool())
# the gemini preset's file tools (openhands/tools/gemini) read `file_path`, list_directory `dir_path`
OPENHANDS_TOOLS = {"terminal": "Bash", "apply_patch": "Edit", "glob": "Glob", "grep": "Grep", "write_file": "Write",
                   "edit": "Edit", "read_file": "Read", "list_directory": "LS"}
OPENHANDS_PATH_ARG = {"file_editor": "path", "write_file": "file_path", "edit": "file_path", "read_file": "file_path",
                      "list_directory": "dir_path"}
# task (TaskToolSet, in the CLI's default tools) and delegate (DelegateTool) run a sub-conversation with
# hook_config=None for the built-in agents (tools/task/manager.py, delegate/impl.py): its calls run no hook
OPENHANDS_SUBAGENTS = ("task", "task_tool_set", "delegate")
# what the terminal sends as keystrokes, not a command, even with is_input false (terminal/interface.py
# SUPPORTED_SPECIAL_KEYS and parse_ctrl_key; tmux_terminal.send_keys): matched on the text stripped and upper-cased
OPENHANDS_KEYS = re.compile(r"ENTER|TAB|BS|ESC|UP|DOWN|LEFT|RIGHT|HOME|END|PGUP|PGDN|(?:C-|CTRL[-+])[A-Z]")
# a key typed in a terminal command: a control character, a tab too (Tab completes the word before it in interactive
# bash: ~/.ss<TAB>authorized_keys is ~/.ssh/authorized_keys), as in TYPED["write_to_process"] but without its history
# parts, since the terminal starts bash with `set +H`; \n ends a line, and only it
OPENHANDS_KEY_CHAR = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")
# a line bash continues on the next call: it ends in an odd number of backslashes (the terminal sends Enter after it)
OPENHANDS_OPEN_LINE = re.compile(r"(?<!\\)(?:\\\\)*\\$")
OPENHANDS_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd")
# HookConfig reads hooks.json in three forms: {"hooks": {...}}, or the event map itself with Claude Code's names, or with
# its own field names (HookConfig.save's); a file with both names for one event doesn't load (_normalize_hooks_input)
OPENHANDS_FIELDS = {ev: re.sub(r"(?<!^)(?=[A-Z])", "_", ev).lower() for ev in (*OPENHANDS_EVENTS, "Stop")}
# what each of these OpenHands tools is decided on: a call that sends none of it is denied in the hook (_blocked)
OPENHANDS_DECIDED_ON = {**{t: k for t, k in OPENHANDS_PATH_ARG.items()},
                        "apply_patch": "file header (*** Add, Update or Delete File:)"}
# Codex reads a hunk header from the line with its Unicode whitespace trimmed (codex-rs/apply-patch), so one may be indented
# lean: an indented header line inside an Update hunk is context to Codex but a path here: decided too, never missed
PATCH_FILE = re.compile(r"^[^\S\n]*\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$", re.M)
OPENCODE_PATH_ARG = {"read": "filePath", "write": "filePath", "edit": "filePath", "glob": "path", "grep": "path"}
# OpenCode's patch parser takes any header line starting with the marker and trims the rest as JS trim() does
OPENCODE_PATCH_FILE = re.compile(r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to):(.*)$", re.M)
# Kilo Code is built on OpenCode and loads the same plugin. Its tools are OpenCode's, with the same names and arguments,
# plus its own; those that run a command or read or write a file are mapped here (packages/opencode/src/kilocode/tool)
KILO_TOOLS = {**OPENCODE_TOOLS, "background_process": "Bash", "notebook_read": "Read", "notebook_edit": "NotebookEdit",
              "send_file": "Read", "generate_image": "Write"}
KILO_PATH_ARG = {**OPENCODE_PATH_ARG, **dict.fromkeys(("notebook_read", "notebook_edit", "send_file", "generate_image"),
                                                      "path")}
# Kilo's notebook_execute (VS Code, experimental.native_notebook_tools) runs a cell in the live kernel: the cell's code
# is in the notebook, not the call, so no rule reads it, and the hook blocks the tool (kilocode/tool/notebook-host.ts)
KILO_BLOCKED = ("notebook_execute",)
# the harnesses that load Tracekit's OpenCode plugin: their tool names and the argument each file tool reads
PLUGIN_TOOLS = {"opencode": (OPENCODE_TOOLS, OPENCODE_PATH_ARG), "kilo": (KILO_TOOLS, KILO_PATH_ARG)}
# Cline's tools that run a command, read or write a file or fetch a URL (sdk/packages/core/src/extensions/tools). Its
# PreToolUse hook sees a call before Cline checks the input against the tool's schema, which takes several shapes
# (schemas.ts: run_commands a list, one command, {command, args} run without a shell, or cmd; read_files files, paths
# or file_paths, as strings or {path | file_path | filePath}): every command or file in any of them is decided
CLINE_TOOLS = {"run_commands": "Bash", "read_files": "Read", "editor": "Edit", "apply_patch": "Edit",
               "fetch_web_content": "WebFetch"}
# no TaskCancel: a cancel, Tracekit's own included, stops a task the person resumes once they approve the held call, in
# the same run; a task left cancelled closes at the signer's idle timeout
CLINE_EVENTS = ("PreToolUse", "PostToolUse", "TaskStart", "TaskComplete", "UserPromptSubmit")
CLINE_FILE = "PreToolUse.ps1" if os.name == "nt" else "PreToolUse"
CLINE_PATH_KEYS = ("path", "file_path", "filePath")
CLINE_HEREDOC = re.compile(r"""(?<![<])<<-?\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_./-]+))""")   # getHeredocDelimiter
# CodeBuddy Code's tools are Claude Code's by name and arguments (its bundled code, @tencent-ai/codebuddy-code
# 2.183.0); of its own, these read a file: each is a Read of the path it reads, never of a decoy beside it
CODEBUDDY_READS = {"NotebookRead": "notebook_path", "ViewImage": "image_path"}


def _each(v, *keys):
    """v's items: v itself, or the items of the list it is; for an object and `keys`, those of each of them it has."""
    if isinstance(v, dict) and keys:
        return [x for k in keys if k in v for x in _each(v[k])]
    return v if isinstance(v, list) else [v]


def _cline_commands(v):
    """The commands a run_commands input runs, each in its own shell, as Cline reads it (helpers.ts
    normalizeRunCommandsInput, definitions.ts coalesceAdjacentStringHeredocs): `commands` (a list or one), else
    `command` (with `args` a list of strings, an argv run without a shell; with no such `args`, the line as written),
    else `cmd`; a list, or a string. Adjacent strings are joined only from a here-doc's line to its delimiter's: an
    object entry ends a run of them and runs in a shell of its own."""
    if isinstance(v, dict):
        v = v["commands"] if "commands" in v else [v] if "command" in v else v.get("cmd")
    out, lines = [], []   # lines: the run of plain strings since the last object, which a here-doc may join
    for c in [*(v if isinstance(v, list) else [v]), None]:
        if isinstance(c, str) and c.strip():
            lines.append(c)
            continue
        while lines:
            m, end = CLINE_HEREDOC.search(lines[0]), 0
            if m:
                end = next((i for i, x in enumerate(lines[1:], 1)
                            if x.strip(JS_SPACE) == next(filter(None, m.groups()))), 0)
            out.append("\n".join(lines[:end + 1]))
            lines = lines[end + 1:]
        if c is None:
            continue
        line = c.get("command") if isinstance(c, dict) else None
        if not isinstance(line, str) or not line.strip():
            raise UnreadableCall("a Cline run_commands entry Tracekit can't read as a command")
        args = c.get("args")
        argv = isinstance(args, list) and bool(args) and all(isinstance(a, str) for a in args)
        out.append(shlex.join([line, *args]) if argv else line)   # an argv, else the line as written
    if not out:
        raise UnreadableCall("Cline's run_commands names no command")
    return out


def _cline_paths(v):
    """Every path a read_files entry names: a string, or each of its path keys."""
    return [v] if isinstance(v, str) else [v[k] for k in CLINE_PATH_KEYS if isinstance(v, dict) and k in v]


def _unstringified(params):
    """The VS Code extension's tool parameters, whose non-string values it sends JSON-encoded (toStringRecord).
    lean: a string argument that is itself a JSON list or object is read as one; Cline's file and command arguments
    that hold a string are decided as a path or a command line either way"""
    out = {}
    for k, v in (params if isinstance(params, dict) else {}).items():
        try:
            parsed = json.loads(v) if isinstance(v, str) else v
        except ValueError:
            parsed = v
        out[k] = parsed if isinstance(parsed, (list, dict)) else v
    return out


def _named(harness, name):
    """A harness's name for a tool as Tracekit reads it: Devin may match a tool's name ignoring case, as it may an
    argument's (DEVIN_PATH_KEY), so a name that is one of its tools in another case is read as that tool."""
    return name.casefold() if harness == "devin" and name.casefold() in DEVIN_TOOLS else name


def _input(v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {"value": v}
    return v if isinstance(v, dict) else ({} if v is None else {"value": v})


def _strings(value):
    """Every string in a JSON value, at any depth."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _gptme_tool(name, ti):
    args, content, kwargs = ti.get("args"), ti.get("content"), ti.get("kwargs")
    if kwargs is not None:
        if not isinstance(kwargs, dict) or args is not None or content is not None:
            raise UnreadableCall("gptme native calls must carry only a kwargs object")
    elif not isinstance(args, list) or not all(isinstance(arg, str) for arg in args) or not isinstance(content, str):
        raise UnreadableCall("gptme markdown calls must carry an args list and text content")

    if name == "tmux":
        operations = ti.get("operations")
        if not isinstance(operations, list) or not operations or not all(isinstance(op, str) for op in operations):
            raise UnreadableCall("gptme tmux requires the parsed operations")
        commands, pane_input = [], False
        for op in operations:
            parts = op.split(maxsplit=1)
            if len(parts) == 2 and parts[0] == "new-session":
                commands.append(parts[1])
            elif len(parts) == 2 and parts[0] == "send-keys":
                pane = parts[1].split(maxsplit=1)
                if len(pane) != 2:
                    continue   # gptme rejects the missing keys
                keys = pane[1]
                # A pane can already contain partial input or run another program. Inspect the new text and
                # require approval even when it looks harmless.
                pane_input = True
                try:
                    tokens = shlex.split(keys)
                except ValueError:
                    tokens = [keys]
                commands.append("".join({"Space": " ", "Enter": "\n", "C-m": "\n"}.get(k, k) for k in tokens))
        if commands:
            result = {"commands": commands, "tmux_operations": operations}
            if pane_input:
                result["gptme_tmux_input"] = True
            return "Bash", result
        return name, {"operations": operations}

    if name == "patch_many":
        patches = ti.get("patches")
        if not isinstance(patches, list) or not patches or not all(
                isinstance(p, list) and len(p) == 2 and all(isinstance(v, str) and v for v in p) for p in patches):
            raise UnreadableCall("gptme patch_many requires the prepared patches")
        return "Edit", {"paths": [path for path, _ in patches], "patches": [patch for _, patch in patches]}

    if name == "mcp":
        command = kwargs.get("command") if kwargs is not None else content
        if isinstance(command, str) and command.lstrip().startswith("load"):
            return "mcp__gptme__load", {"command": command}

    if name in ("shell", "ipython"):
        key = "command" if name == "shell" else "code"
        value = kwargs.get(key) if kwargs is not None else content.strip()
        if name == "shell" and kwargs is None:
            if args:
                raise UnreadableCall("gptme markdown shell takes no positional arguments")
            value = value.removeprefix("$ ")
        if not isinstance(value, str):
            raise UnreadableCall(f"gptme {name} requires text {key}")
        if name == "ipython":
            return name, {key: value}
        result = {"command": value}
        background = kwargs.get("background") if kwargs is not None else None
        if background is True or isinstance(background, str) and background.lower() in ("1", "true", "yes", "on"):
            result["run_in_background"] = True
        return "Bash", result

    if name in ("save", "append", "patch", "read", "morph", "hashline_edit"):
        mapped = {"save": "Write", "append": "Edit", "patch": "Edit", "read": "Read",
                  "morph": "Edit", "hashline_edit": "Edit"}[name]
        if name == "read" and kwargs is None and not args:
            paths = [line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        else:
            path = kwargs.get("path") if kwargs is not None else " ".join(args)
            if kwargs is None and name != "read" and path.startswith(("save ", "append ", "patch ")):
                path = path.split(" ", 1)[1]
            paths = [path]
        if not paths or not all(isinstance(path, str) and path for path in paths):
            raise UnreadableCall(f"gptme {name} requires a file path")
        result = {"file_path": os.path.expanduser(paths[0])}
        if name == "read":
            if len(paths) > 1:
                result["paths"] = [os.path.expanduser(path) for path in paths]
        else:
            key = "patch" if name == "patch" else "content"
            native_key = "edit" if name in ("morph", "hashline_edit") else key
            value = kwargs.get(native_key) if kwargs is not None else content
            if not isinstance(value, str):
                raise UnreadableCall(f"gptme {name} requires text {key}")
            result[key] = value
        return mapped, result

    if "." in name:
        server, _, command = name.partition(".")
        try:
            params = kwargs if kwargs is not None else json.loads(content)
        except ValueError:
            raise UnreadableCall("gptme MCP call content isn't JSON") from None
        if not server or not command or not isinstance(params, dict):
            raise UnreadableCall("gptme MCP calls require a qualified tool name and an arguments object")
        return f"mcp__{server}__{command}", params
    return name, kwargs if kwargs is not None else ti


def tool(harness, name, ti):
    """-> (tracekit tool name, normalised input)."""
    ti = dict(_input(ti))
    if harness == "gptme":
        return _gptme_tool(name, ti)
    if harness == "openhands":
        if ti.get("kind") == "MCPToolAction" and isinstance(ti.get("data"), dict):   # an MCP call's arguments
            return name, dict(ti["data"])
        ti.pop("kind", None)   # the Action class's name, not an argument
        if name in OPENHANDS_PATH_ARG:
            path = ti.get(OPENHANDS_PATH_ARG[name])
            ti["paths"] = [path] if isinstance(path, str) and path else []
            ti["file_path"] = ti["paths"][0] if ti["paths"] else None
            if name == "file_editor":
                return {"view": "Read", "create": "Write"}.get(ti.get("command"), "Edit"), ti
        if name == "terminal" and isinstance(ti.get("command"), str):
            # the terminal is interactive (bash in tmux): text typed into the command running, a key, and a line left
            # open run with what comes before or after them, which this call alone doesn't show; the engine holds a
            # call marked `typed` (TK-SHELL-PARSE), and holds an unclosed quote or heredoc as a line it can't read
            # tmux types a command as keys (send_keys literal), so a control character in it is one too: ^U erases what
            # came before it on the line, \r is an Enter (`echo hi\x15git push --force` runs the push), a tab completes
            # the word before it
            c = ti["command"]
            if ti.get("is_input") is True or OPENHANDS_KEYS.fullmatch(c.strip().upper()) or \
                    OPENHANDS_OPEN_LINE.search(c) or OPENHANDS_KEY_CHAR.search(c):
                ti["typed"] = True
        if name == "apply_patch":   # Codex's patch format
            files = [f.strip() for f in PATCH_FILE.findall(str(ti.get("patch") or ""))]
            ti["paths"], ti["file_path"] = files, files[0] if files else None
        return OPENHANDS_TOOLS.get(name, name), ti
    if harness in ("droid", "devin"):
        name, files = _named(harness, name), None
        if name == ("ApplyPatch" if harness == "droid" else "apply_patch"):   # every file a patch header names,
            text = "\n".join(_strings(ti))   # whichever argument holds it
            files = [f.strip() for f in PATCH_FILE.findall(text)]
            if harness == "devin":   # its patch format isn't documented: a unified diff's files are decided too
                files = list(dict.fromkeys(files + [n for a, b in DIFF_FILE.findall(text)
                                                    for f in ([a.strip()] if a else b.split())
                                                    if f not in ("", "/dev/null") for n in _diff_names(f)]))
        elif harness == "devin" and name in ("read", "write", "edit"):
            # every path under a key Devin's tool may read (v2 decides the first path key and `paths`, v1 `file_path`
            # and `paths`), so a decoy `file_path` beside the path the tool reads never replaces it
            files = list(dict.fromkeys(f for k in (*PATH_KEYS, "paths", *ti)
                                       if DEVIN_PATH_KEY.search(k.casefold().replace("_", ""))
                                       for f in _strings(ti.get(k)) if f))
        elif harness == "devin" and name == "write_to_process":   # input typed into a running exec shell: the text
            # of its one argument besides shell_id, whatever its name; any other shape is denied in _blocked
            text = [ti[k] for k in ti if k.casefold() != "shell_id"]
            ti["command"] = text[0].replace("\r", "\n") if len(text) == 1 and isinstance(text[0], str) else None
        elif harness == "devin" and name == "exec":   # its command under any spelling Devin's decoder may read (_blocked
            # denies a call that sends a name twice); \r ends a line, should Devin type it into a terminal
            keys = [k for k in ti if k.casefold() == "command"]
            if len(keys) == 1:
                ti["command"] = ti[keys[0]].replace("\r", "\n") if isinstance(ti[keys[0]], str) else ti[keys[0]]
        if files is not None:
            ti["paths"] = files
            ti["file_path"] = files[0] if files else None
        return (DROID_TOOLS if harness == "droid" else DEVIN_TOOLS).get(name, name), ti
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
            if isinstance(cmd, list) and all(isinstance(w, str) for w in cmd):   # Codex's argv: a list of strings
                ti["command"] = " ".join(cmd[2:] if cmd[:2] in (["bash", "-lc"], ["bash", "-c"], ["sh", "-c"]) else cmd)
            return "Bash", ti
        return name, ti
    if harness == "cursor":
        if name.startswith("MCP:"):
            return "mcp__cursor__" + re.sub(r"[^A-Za-z0-9_-]+", "_", name[4:]), ti
        # Cursor doesn't document which of these its tools read: every path they name is decided, so a decoy
        # `file_path` beside the `path` a tool reads never replaces it (read before a tool's own file is set below)
        paths = [f for f in ti["paths"] if isinstance(f, str)] if isinstance(ti.get("paths"), list) else []
        files = [ti[k] for k in CURSOR_PATH_ARGS if isinstance(ti.get(k), str)]
        if name == "ApplyPatch":   # every file a patch header names, in whichever argument holds it, as Cursor reads it:
            # a {"patch": ...} in JSON unwrapped, \r and \r\n read as \n, each line trimmed as JavaScript trims it
            texts, unread = list(_strings(ti)), False
            for s in texts[:]:
                if s.strip(JS_SPACE).startswith("{"):
                    try:
                        j = json.loads(s.strip(JS_SPACE))
                    except json.JSONDecodeError:   # not JSON: Cursor reads the text as it is
                        continue
                    except (ValueError, RecursionError):   # JSON Tracekit can't read: decided as an unknown tool, as
                        unread = True                       # before
                        break
                    if isinstance(j, dict) and list(j) == ["patch"] and isinstance(j["patch"], str):
                        texts.append(j["patch"])
            lines = "\n".join(x.strip(JS_SPACE) for x in re.sub(r"\r\n?", "\n", "\n".join(texts)).split("\n"))
            headers = [f for f in (g.strip(JS_SPACE) for g in PATCH_FILE.findall(lines)) if f]
            if headers and not unread:
                ti["paths"], ti["file_path"] = list(dict.fromkeys(headers + files + paths)), headers[0]
                return "Edit", ti
        edit = CURSOR_EDITS.get(name)
        if edit and not isinstance(ti.get(edit[1]), str):   # no file to decide it on: left unmapped (CURSOR_EDITS)
            edit = None
        if edit and edit[0] == "NotebookEdit":   # v1 decides a NotebookEdit on its file_path and notebook_path
            ti["file_path"] = ti["notebook_path"] = ti["target_notebook"]
        for k in CURSOR_PATH_ARGS[1:]:
            if k in ti and "file_path" not in ti:
                ti["file_path"] = ti[k]
        if any(f not in [ti["file_path"], *paths] for f in files):
            ti["paths"] = list(dict.fromkeys(files + paths))
        return edit[0] if edit else CURSOR_TOOLS.get(name, name), ti
    if harness == "gemini" and name.startswith("mcp_"):   # mcp_<server>_<tool> (packages/core/src/tools/mcp-tool.ts)
        return "mcp__" + name[4:], ti
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
    if harness in PLUGIN_TOOLS:
        tools, path_arg = PLUGIN_TOOLS[harness]
        # the path the tool itself reads decides, never another path key the model sent beside it (OpenCode drops
        # unknown keys before the tool runs, so a decoy `file_path` would be decided but never used)
        if name in path_arg:
            ti["file_path"] = ti.get(path_arg[name])
        if harness == "kilo" and name == "notebook_edit":   # v1 decides a NotebookEdit on its notebook_path
            ti["notebook_path"] = ti["file_path"]
        if harness == "kilo" and name == "generate_image":
            ti["paths"] = []   # a `paths` sent beside it is dropped, as Kilo drops it
            if isinstance(ti.get("image"), str):   # its `image`, an existing file, is read and sent to the image
                # provider: decided as a Read of it, with the `path` it writes (Kilo gives that an image extension)
                ti["file_path"] = ti["image"]
                ti["paths"] = [ti["image"]] + ([ti["path"]] if isinstance(ti.get("path"), str) else [])
                return "Read", ti
        if name in ("apply_patch", "patch"):   # every file OpenCode's parser finds, whatever paths the model sent (patch:
            # 1.0's tool, off by default, with the same parser and argument); releases of 2026-01-18 to 2026-02-23
            # (1.2.0) read a header only up to its next ':' (split(":", 2)): both are decided
            files = [g.strip(JS_SPACE) for f in OPENCODE_PATCH_FILE.findall(str(ti.get("patchText") or ""))
                     for g in dict.fromkeys((f, f.split(":")[0]))]
            ti["paths"] = files
            ti["file_path"] = files[0] if files else None
        return tools.get(name, name), ti
    if harness == "goose":
        if name == "read_image":
            # decided by scheme, as goose's url::Url::parse reads the source: tabs and newlines dropped, outer spaces and
            # controls trimmed, backslashes read as slashes in a web URL (https:x.example/a, HTTPS:\\x.example\a)
            src = re.sub(r"[\t\n\r]", "", str(ti.get("source") or "")).strip("".join(map(chr, range(33))))
            try:
                parts = urllib.parse.urlsplit(src.replace("\\", "/"))
            except ValueError:   # urlsplit refuses it (an unclosed bracket: http://[::1/cat.png)
                raise UnreadableCall("goose's read_image source isn't a URL Tracekit can read") from None
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
        # agy is a Go binary that may match a tool's name, as its arguments, ignoring case: a known name is read so.
        # manage_task's send_input is input typed into a background run_command
        name = name.casefold() if name.casefold() in (*AGY_TOOLS, "manage_task") else name
        if name == "manage_task" and str(ti.get("Action")).casefold() == "send_input":
            ti["command"] = ti.get("Input")
            return "Bash", ti
        ti.update({ours: ti.get(theirs) for ours, theirs in AGY_ARGS.get(name, {}).items()})
        return AGY_TOOLS.get(name, name), ti
    if harness == "crush":
        if name.startswith("mcp_"):   # Crush names an MCP tool mcp_<server>_<tool> (internal/agent/tools/mcp-tools.go)
            return "mcp__" + name[4:], ti
        if name in CRUSH_PATH_TOOLS:   # the path the tool itself reads decides, never a decoy `file_path` beside it
            ti.pop("file_path", None)
            if "path" in ti:
                ti["file_path"] = ti["path"]
        return CRUSH_TOOLS.get(name, name), ti
    if harness == "cline":
        v = ti["value"] if list(ti) == ["value"] else ti   # a list or a string the model sent as the whole input
        one = [v] if isinstance(v, dict) else []
        if "__" in name and not name.startswith("mcp__"):   # an MCP tool, <server>__<tool> (name-transform.ts)
            return "mcp__" + name, ti
        if name == "run_commands":   # one command as `command`, several as `commands`, which v2 reads each on its own
            # (v1 reads a call with no `command` as its whole input)
            cmds = _cline_commands(v)
            ti = {k: x for k, x in ti.items() if k not in ("command", "cmd", "commands", "args", "value")}
            ti.update(command=cmds[0]) if len(cmds) == 1 else ti.update(commands=cmds)
        elif name == "read_files":
            files = [p for e in _each(v, "files", "paths", "file_paths") + one for p in _cline_paths(e)]
            if not files or not all(isinstance(f, str) and f for f in files):
                raise UnreadableCall("Cline's read_files names a file Tracekit can't read as a path")
            for k in PATH_KEYS:   # its own paths decide, never a decoy beside them
                ti.pop(k, None)
            ti["file_path"], ti["paths"] = files[0], list(dict.fromkeys(files))
        elif name == "editor":   # decided on its `path`: with no old_text or insert_line it creates a missing file, a
            # Write; else an Edit
            path = v.get("path") if one else None
            if not isinstance(path, str) or not path:
                raise UnreadableCall("Cline's editor names no path")
            for k in PATH_KEYS:
                ti.pop(k, None)
            ti["path"] = ti["file_path"] = path
            new = v.get("new_text")   # its content, as a Write's or an Edit's
            if v.get("old_text") is None and v.get("insert_line") is None:
                return "Write", {**ti, "content": new} if isinstance(new, str) else ti
            if isinstance(new, str):
                ti["new_string"] = new
        elif name == "apply_patch":   # the patch is its `input`, or the whole input as a string
            files = [f.strip(JS_SPACE) for f in PATCH_FILE.findall(str(v.get("input") if one else v))]   # JS trim()
            if not files or not all(files):
                raise UnreadableCall("Cline's apply_patch names no file")
            ti["file_path"], ti["paths"] = files[0], files
        elif name == "fetch_web_content":
            urls = [r.get("url") if isinstance(r, dict) else None for r in _each(v, "requests")]
            if not urls or not all(isinstance(u, str) and u for u in urls):
                raise UnreadableCall("Cline's fetch_web_content names no URL")
            ti["url"] = urls[0]
            if len(set(urls)) > 1:
                ti["urls"] = list(dict.fromkeys(urls))
        return CLINE_TOOLS.get(name, name), ti
    if harness == "copilot":
        if name == "str_replace_editor":   # one tool for viewing, creating and editing: decided as the one it does
            name = COPILOT_EDITOR.get(ti.get("command"), "edit")
        if name == "apply_patch":   # the patch is the arguments, or their `input` or `patch`
            files = [f.strip() for f in PATCH_FILE.findall("\n".join(_strings(ti)))]
            if not files or not all(files):
                raise ValueError("Copilot's apply_patch names no file")
            ti["file_path"], ti["paths"] = files[0], files
        elif name in COPILOT_PATH_TOOLS or name in COPILOT_SEARCH_TOOLS:
            # the path the tool itself reads decides, never a decoy `file_path` beside it; a search's `paths` is one
            # path or a list
            own = ti.get("path") if name in COPILOT_PATH_TOOLS else ti.get("paths")
            own = [x for x in (own if isinstance(own, list) else [own]) if isinstance(x, str)]
            for k in PATH_KEYS:
                ti.pop(k, None)
            if name in COPILOT_SEARCH_TOOLS:
                ti["paths"] = own
            if own:
                ti["file_path"] = own[0]
        elif name in ("write_bash", "write_powershell"):   # input typed into a running command, as Codex's write_stdin;
            # \r ends a line, as a terminal reads it (as Devin's write_to_process); input that isn't text: _blocked
            v = ti.get("input")
            ti["command"] = v.replace("\r", "\n") if isinstance(v, str) else None
        if name in COPILOT_TOOLS:
            return COPILOT_TOOLS[name], ti
        # the payload doesn't say which tools are MCP ones: Copilot names them <server>-<tool>, so any other name with
        # a `-` is decided as one under every split (the signer's _evaluate), and one without as the unknown tool it is
        # lean: a name that also holds `__` is split there alone, as Claude Code's mcp__<server>__<tool>; try its `-`
        # too if an MCP server ever names a tool with `__`
        return ("mcp__" + name if "-" in name else name), ti
    if harness == "codebuddy":
        if name == "DeferExecuteTool" and isinstance(ti.get("toolName"), str):
            # it runs the deferred tool `toolName` with `params` (an object, or one as a JSON string): decided as that
            # call, so the call never runs on a reading of the wrapper. That tool's own PreToolUse, under the same call
            # id, decides it again: the signer takes the decision the call completes as the call's and the other as
            # superseded, so no gap (service._finish_run).
            # lean: such a call has two decision records; one needs the signer to answer a repeated decide of an open,
            # allowed decision with the same arguments from it (it writes one per decide)
            return tool(harness, ti["toolName"], ti.get("params"))
        if name in CODEBUDDY_READS:
            ti["file_path"] = ti.get(CODEBUDDY_READS[name])
            return "Read", ti
        if name == "LibraryUpload":   # it sends the file at `path` off the machine: the packs decide it as the upload it
            # is (TK-D022, TK-F024), on that file, never on a decoy beside it. CodeBuddy parses no URL
            # (PathUtils.resolveFilePathToWorkDir): it takes `file://`, else `file:`, off the front and opens the rest,
            # `~/` in the home folder and a relative path in its cwd (`@x` as itself, else as x), decoding nothing. Each
            # form it may open is decided, and each percent-decoded too
            path = ti.get("path")
            if isinstance(path, str):
                path = path[7:] if path.startswith("file://") else path[5:] if path.startswith("file:") else path
            forms = [path] if isinstance(path, str) else []
            forms += [f[1:] for f in forms if f.startswith("@")]
            forms = list(dict.fromkeys(forms + [urllib.parse.unquote(f) for f in forms]))
            ti.pop("paths", None)
            ti["file_path"] = path
            if len(forms) > 1:
                ti["paths"] = forms
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
    if harness == "openhands":   # HookEvent (openhands/sdk/hooks/types.py): Claude Code's fields under other names
        p = {**p, "hook_event_name": p.get("hook_event_name") or p.get("event_type"), "cwd": p.get("working_dir"),
             "prompt": p.get("message")}
    ev = p.get("hook_event_name") or ""
    out = {"cwd": p.get("cwd") or (p.get("workspace_roots") or [None])[0],
           "transcript_path": p.get("transcript_path"), "model": p.get("model")}
    if harness == "gptme" and ev in ("PromptObserved", "UserPromptSubmit"):
        return dict(out, hook_event_name="PromptObserved", session_id=p.get("session_id"), prompt=p.get("prompt"))
    if harness == "gptme" and ev == "ToolObserved":
        name, args = p.get("tool_name") or "?", _input(p.get("tool_input"))
        try:
            name, args = tool(harness, name, args)
        except (ValueError, TypeError):
            pass   # an undecided tool may have run without a confirmation preview
        return dict(out, hook_event_name=ev, session_id=p.get("session_id"), tool_use_id=p.get("tool_use_id"),
                    tool_name=name, tool_input=args, tool_response=p.get("tool_response"))
    if harness in ("codex", "qwen", "droid", "crush", "devin", "gptme", "openhands", "codebuddy"):   # Claude Code's
        # payloads; Qwen Code, Crush and CodeBuddy Code add PostToolUseFailure (Crush's and CodeBuddy's payloads are
        # Claude Code's own: same field and event names)
        out["session_id"] = p.get("session_id")
        m = {"PreToolUse": "PreToolUse", "PostToolUse": "PostToolUse", "UserPromptSubmit": "UserPromptSubmit",
             "SessionStart": "SessionStart", "SessionEnd": "SessionEnd"}
        if harness in ("qwen", "crush", "codebuddy"):
            m["PostToolUseFailure"] = "PostToolUseFailure"
        if ev not in m:
            return None
        out["hook_event_name"] = m[ev]
        if ev in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"] = p.get("tool_use_id")
            out["later"] = (harness, _named(harness, str(p.get("tool_name")))) in LATER
            if harness == "openhands":   # terminal with is_input: text typed into the command already running
                out["later"] = p.get("tool_name") == "terminal" and out["tool_input"].get("is_input") is True
            if harness in ("droid", "devin", "openhands"):   # their payloads carry no call id
                out["tool_use_id"] = out["session_id"] and _paired_ids(
                    harness, out["session_id"], out["tool_name"], out["tool_input"], "pre" if ev == "PreToolUse" else "post")
            if ev != "PreToolUse":
                out["tool_response"] = r = p.get("tool_response")
                if harness == "devin" and isinstance(r, dict) and r.get("success") is False:   # {success, output, error}
                    out["hook_event_name"], out["error"] = "PostToolUseFailure", r.get("error")
                if harness == "openhands" and isinstance(r, dict) and r.get("is_error") is True:   # an Observation
                    text = "\n".join(c.get("text", "") for c in r.get("content") or [] if isinstance(c, dict))
                    out["hook_event_name"], out["error"] = "PostToolUseFailure", text or "error"
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
    if harness in PLUGIN_TOOLS:
        out["session_id"] = p.get("session_id")
        if ev in ("tool.execute.before", "tool.execute.after"):
            out["hook_event_name"] = "PreToolUse" if ev == "tool.execute.before" else "PostToolUse"
            out["tool_name"], out["tool_input"] = tool(harness, p.get("tool_name") or "?", p.get("tool_input"))
            out["tool_use_id"], out["later"] = p.get("tool_use_id"), (harness, str(p.get("tool_name"))) in LATER
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
                   later=(harness, raw.casefold()) in LATER,
                   tool_use_id=sid and type(step) is int and _paired_ids(
                       harness, sid, f"{step}|{raw}", ti, "pre" if ev == "PreToolUse" else "post"))
        if ev == "PostToolUse" and p.get("error"):
            out.update(hook_event_name="PostToolUseFailure", error=p["error"])
        return out
    if harness == "cline":
        # the event is the hook file's name, on its command line. The CLI sends the call's id and the model's input
        # (tool_call, tool_result) beside the extension's shape (preToolUse, postToolUse: toolName and the parameters,
        # its non-string values JSON-encoded, and no id): the extension's calls are paired by (tool, arguments)
        # A run is one task, TaskStart to TaskComplete (the CLI fires both for each prompt), keyed on the CLI's session,
        # the id `cline --id` resumes (sessionContext.rootSessionId; its taskId is the conversation's), else the
        # extension's taskId, which a resumed task keeps: a cancelled task the person resumes goes on in its run. A
        # subagent's calls are in its root's run, which only the root agent's task starts and ends (parent_agent_id null)
        ctx = p.get("sessionContext") if isinstance(p.get("sessionContext"), dict) else {}
        out.update(session_id=ctx.get("rootSessionId") or p.get("taskId"), cwd=(p.get("workspaceRoots") or [None])[0],
                   hook_event_name=ev)
        if ev in ("PreToolUse", "PostToolUse"):
            call = p.get("tool_call" if ev == "PreToolUse" else "tool_result")
            ext = p.get("preToolUse" if ev == "PreToolUse" else "postToolUse")
            call, ext = (call if isinstance(call, dict) else None), (ext if isinstance(ext, dict) else {})
            name = call.get("name") if call else ext.get("toolName")
            out["tool_name"], out["tool_input"] = tool(harness, str(name or "?"), call.get("input") if call else
                                                       _unstringified(ext.get("parameters")))
            out["tool_use_id"] = call.get("id") if call else out["session_id"] and _paired_ids(
                harness, out["session_id"], out["tool_name"], out["tool_input"], "pre" if ev == "PreToolUse" else "post")
            if ev == "PostToolUse":
                # the extension 4.1.26 sends a result as String() of it, "[object Object]" for each entry joined with
                # commas: no result is recorded
                r = call.get("output") if call else ext.get("result")
                out["tool_response"] = r = None if isinstance(r, str) and re.fullmatch(
                    r"\[object Object\](?:,\[object Object\])*", r) else r
                if call and call.get("error") or not call and ext.get("success") is False:
                    out.update(hook_event_name="PostToolUseFailure", error=r.get("error") if isinstance(r, dict) and
                               r.get("error") else r or "the call failed")
            return out
        if ev == "UserPromptSubmit":
            prompt = (p.get("userPromptSubmit") or {}).get("prompt")
            # lean: the CLI also fires it with its own nudge to finish a run ("[SYSTEM] This run is not complete ..."),
            # which isn't the person's prompt
            if not isinstance(prompt, str) or prompt.startswith("[SYSTEM] "):
                return None
            return dict(out, prompt=prompt)
        if p.get("parent_agent_id"):
            return None
        if ev == "TaskStart":
            return dict(out, hook_event_name="SessionStart")
        if ev == "TaskComplete":
            return dict(out, hook_event_name="SessionEnd", reason="task complete")
        return None

    if harness == "copilot":
        if ev not in COPILOT_EVENTS:
            return None

        tool_call_id = p.get("toolCallId")
        if not isinstance(tool_call_id, str) or not tool_call_id.strip():
            raise ValueError("Copilot CLI 1.0.107 or later is required; toolCallId must be a non-empty string")

        name = p.get("toolName")
        if not isinstance(name, str) or not name:
            raise ValueError("Copilot's toolName must be a non-empty string")
        out["session_id"] = p.get("sessionId")
        out["hook_event_name"] = ev[0].upper() + ev[1:]
        out["tool_name"], out["tool_input"] = tool(harness, name, p.get("toolArgs"))
        out["tool_use_id"], out["later"] = tool_call_id, (harness, name) in LATER

        if ev == "postToolUse":
            result = p.get("toolResult")
            out["tool_response"] = result.get("textResultForLlm") if isinstance(result, dict) else result
        elif ev == "postToolUseFailure":
            out["error"] = p.get("error")
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
STOPPED_LINES = ("Why: ", "Instead: ", "Person: ", "Agent: ")   # how the lines after a stop's first go on (stopped)
PAIRED = ("gemini", "droid", "antigravity", "devin", "cline", "openhands")   # the harnesses whose call ids _paired_ids makes


# goose's Code Mode tools: execute_typescript and execute_bash before goose 1.56, execute_javascript since, also
# as code_execution__<name>; each runs tool calls through dispatch_tool, which runs no hooks
GOOSE_CODE_MODE = ("execute_javascript", "execute_typescript", "execute_bash")
# Crush's sub-agent tools: a sub-agent's own calls (view, grep, sourcegraph, web_fetch, ...) run no hooks
# (internal/agent/hooked_tool.go, wrapToolsWithHooks)
CRUSH_SUBAGENTS = ("agent", "agentic_fetch")
# Docker MCP Gateway's code-mode makes a tool, code-mode-<name>, whose script calls MCP tools inside the gateway, where
# no hook sees them (docker/mcp-gateway pkg/gateway/codemode.go); Crush names them mcp_<server>_code-mode[-<name>]
CRUSH_CODE_MODE = re.compile(r"mcp_.+_code-mode(-.+)?", re.S)
# Crush decodes a built-in tool's input into a Go struct (encoding/json): a name matches its field ignoring case
# (Unicode folding: U+017F is s), a later repeat wins, and a null keeps the earlier value, while json.loads keeps exact
# names and a repeat's last value. Every built-in tool's argument names, nested ones too, are lower-case snake_case, so
# an input with any other name or a repeat is denied. An MCP tool's input is decoded into a map (mcp/tools.go RunTool):
# exact names, a repeat's last value, null kept, as json.loads reads it
CRUSH_ARG_NAME = re.compile(r"[a-z0-9_]+")


class _Pairs(list):
    """A JSON object as its (name, value) pairs, in order, repeats kept (json's object_pairs_hook)."""


def _odd_arg_name(v):
    """A name in v (a JSON value read with _Pairs), at any depth, that repeats in its object or isn't lower-case
    snake_case, else None."""
    todo = [v]
    while todo:
        v = todo.pop()
        if isinstance(v, _Pairs):
            seen = set()
            for k, x in v:
                if k in seen or not CRUSH_ARG_NAME.fullmatch(k):
                    return k
                seen.add(k)
                todo.append(x)
        elif isinstance(v, list):
            todo.extend(v)
    return None


def _blocked_tool(harness, tool_name, raw=""):
    """The reason a tool call is denied in the hook itself, else None: a tool that runs calls the hook never sees, or
    a Crush input the tool may read otherwise than Tracekit. tool_name: the harness's own name for the tool, before it
    is mapped; raw: the hook payload as received."""
    name = tool_name.removeprefix("code_execution__")
    if harness == "openhands" and tool_name in OPENHANDS_SUBAGENTS:
        return (f"Blocked by Tracekit: OpenHands' {tool_name} runs a sub-agent whose tool calls run no hooks, so "
                "Tracekit can't decide them; make each call itself instead.")
    if harness == "goose" and name in GOOSE_CODE_MODE:
        return (f"Blocked by Tracekit: goose's {name} (Code Mode) runs tool calls through dispatch_tool with no "
                "PreToolUse hook, so Tracekit can't decide them; make each call itself instead.")
    if harness == "kilo" and tool_name in KILO_BLOCKED:
        return (f"Blocked by Tracekit: Kilo's {tool_name} runs a notebook cell in the live kernel, and the cell's code "
                "isn't in the call, so Tracekit can't decide what it runs. It is on only with "
                '"experimental": {"native_notebook_tools": true} in kilo.json; leave that off and run code through '
                "bash instead.")
    if harness != "crush":
        return None
    if tool_name.casefold() in CRUSH_SUBAGENTS:   # as its argument names, Crush may match a tool's name ignoring case
        return (f"Blocked by Tracekit: Crush's {tool_name} runs a sub-agent whose tool calls run no hooks, so Tracekit "
                "can't decide them; make each call itself instead. To stop Crush offering it, put "
                '"permissions deny agent agentic_fetch" in crushrc (in crush.json: '
                '"options": {"disabled_tools": ["agent", "agentic_fetch"]}).')
    if CRUSH_CODE_MODE.fullmatch(tool_name):
        return (f"Blocked by Tracekit: {tool_name} is Docker MCP Gateway's code-mode, whose script calls MCP tools "
                "inside the gateway with no hook, so Tracekit can't decide them; make each call itself instead. "
                "`docker mcp feature disable dynamic-tools` turns it off.")
    if not tool_name.startswith("mcp_") and raw.strip():
        v = dict(json.loads(raw, object_pairs_hook=_Pairs)).get("tool_input")
        if isinstance(v, str):   # an input sent as a JSON string, as _input reads it
            try:
                v = json.loads(v, object_pairs_hook=_Pairs)
            except ValueError:
                v = None
        odd = _odd_arg_name(v)
        if odd is not None:
            return (f"Blocked by Tracekit: Crush's {tool_name} input repeats an argument name or has one that isn't "
                    f"lower-case snake_case ({odd!r}). Crush matches argument names ignoring case and lets a later "
                    "repeat win unless it is null, so Tracekit can't be sure it decides the arguments the tool runs "
                    "with; send each argument once, by its lower-case name.")
    return None


def _blocked_agy_args(name, args):
    """The reason an agy call is denied in the hook itself, else None. args: its arguments read with _Pairs. agy is a
    Go binary: a decoder like Go's encoding/json fills a field from any key that folds to its name (the last one; a
    null, or a value of another type, keeps the value before it), where tool() reads the exact name and json.loads a
    repeat's last value. So: a key outside ASCII, two keys with one name ignoring case (an exact repeat too), or a
    field tool() reads spelled in another case. A lone null is read as absent by both."""
    if isinstance(args, str):   # arguments sent as a JSON string, as _input reads them
        try:
            args = json.loads(args, object_pairs_hook=_Pairs)
        except ValueError:
            return None
    read = {f.casefold(): f for f in (*AGY_ARGS.get(name.casefold(), {}).values(),
                                      *(("Action", "Input") if name.casefold() == "manage_task" else ()))}
    seen = set()
    for k, _ in args if isinstance(args, _Pairs) else ():
        f = k.casefold()
        why = ("isn't ASCII" if not k.isascii() else "repeats an earlier argument's name (case ignored)" if f in seen
               else f"is {read[f]} in another case" if read.get(f, k) != k else None)
        if why:
            return (f"Blocked by Tracekit: the argument {k[:64]!r} of agy's {name[:64]} {why}, so agy may run the call "
                    "with other arguments than Tracekit decides; send each argument once, by its exact name.")
        seen.add(f)
    return None


def _sets_state(text):
    """The word of typed text that sets or replays state of the running shell (SHELL_STATE), read as the policy's
    shell parser reads the line, else None. Text the parser can't read (it holds a state variable set to text it
    can't name, a nameref to one, `hash -p`) is read as the engine reads such a line, each piece's words as written,
    with an assignment as its first word; text with none goes to the signer, which holds it."""
    from .policy2 import engine, shell
    try:
        cmds, *_, learned = shell.analyse(text)
    except RecursionError:
        return None
    except shell.ParseError:
        words = [w for p in engine._PIECE.finditer(text) if (w := p.group().split())]
        cmds, learned = [{"argv": w} for w in words], {"assigned": [(w[0], w[0]) for w in words], "functions": []}
    for a in (c["argv"] for c in cmds):
        if a[0] in SHELL_STATE or a[0] == "set" and any(w.startswith(("-", "+")) for w in a[1:]) or \
                a[0] == "alias" and any(re.match(r"[^=]+=", w) for w in a[1:]) or a[0] == "history" and any(
                re.fullmatch(r"-[a-z]*[nrs][a-z]*", w) for w in a[1:]) or a[0] in ("declare", "typeset", "local") and \
                any(re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", w) for w in a[1:]):
            return a[0]
        hit = next((w for w in a[1:] if STATE_VARS.match(w)), None)
        if hit and (a[0] in shell._SETS_ANY or shell._sets_with_v(a)):   # export, declare, read, printf -v …
            return hit
    return next((n for n, _ in learned["assigned"] if STATE_VARS.match(n)), None) or next(iter(learned["functions"]),
                                                                                        None)


def _repeated(args):
    """The first argument name in `args` (a tool's input read with _Pairs, or a JSON string of one) that an earlier one
    has, ignoring case (as str.casefold folds it: K and ſ too), else None."""
    if isinstance(args, str):
        try:
            args = json.loads(args, object_pairs_hook=_Pairs)
        except ValueError:
            return None
    seen = set()
    for k, _ in args if isinstance(args, _Pairs) else ():
        if k.casefold() in seen:
            return k
        seen.add(k.casefold())
    return None


def _blocked(harness, p, raw=""):
    """The reason a pre-tool call is denied in the hook itself, before it is mapped, else None. raw: the payload as
    received."""
    if harness == "antigravity":
        call = dict(json.loads(raw, object_pairs_hook=_Pairs)).get("toolCall") if raw.strip() else None
        call = dict(call) if isinstance(call, _Pairs) else {}
        return _blocked_agy_args(str(call.get("name") or "?"), call.get("args"))
    name = _named(harness, str(p.get("tool_name") or ""))
    twice = _repeated(dict(json.loads(raw, object_pairs_hook=_Pairs)).get("tool_input")) if harness == "devin" and \
        raw.strip() else None
    if twice is not None:
        return (f"Blocked by Tracekit: Devin's {name[:64]} call sends an argument more than once (case ignored): "
                f"{twice[:64]!r}. json.loads keeps its last value and Devin's decoder may keep another, so Tracekit "
                "can't be sure it decides the arguments the tool runs with; send each argument once.")
    if harness == "openhands" and name in OPENHANDS_DECIDED_ON and not tool(harness, name, p.get("tool_input"))[1].get(
            "file_path"):
        sent = ", ".join(k for k, v in _input(p.get("tool_input")).items() if v is not None and k != "kind")[:200]
        return (f"Blocked by Tracekit: OpenHands' {name} call names no {OPENHANDS_DECIDED_ON[name]}, which Tracekit "
                f"decides it on, so it can't decide this call (its arguments: {sent or 'none'}). Please report it on "
                "https://github.com/Cygnux-Labs/Tracekit/issues/563.")
    if harness == "devin" and name in DEVIN_DECIDED_ON:   # Devin documents none of these tools' arguments: one sent
        # under a name Tracekit doesn't read would leave the call decided on nothing
        ti = tool(harness, name, p.get("tool_input"))[1]
        v = ti.get({"webfetch": "url", "write_to_process": "command", "exec": "command"}.get(name, "file_path"))
        # a url under another spelling (URL) may be the one Devin's decoder reads, and v1 decides `url` alone
        if not (isinstance(v, str) and v) or name == "webfetch" and [k for k in ti if k.casefold() == "url"] != ["url"]:
            sent = ", ".join(map(str, _input(p.get("tool_input"))))[:200] or "none"
            return (f"Blocked by Tracekit: Devin's {name} call names no {DEVIN_DECIDED_ON[name]}, which Tracekit "
                    f"decides it on, so it can't decide this call (its arguments: {sent})."
                    + (" Send it as {\"command\": \"...\"}." if name == "exec" else " Devin doesn't document them: "
                       "please report their names on https://github.com/Cygnux-Labs/Tracekit/issues/566 so Tracekit "
                       "can read them."))
        if name in TYPED:
            reason = _typed(f"Devin's {name}", v, name == "write_to_process")
            if reason:
                return reason
    elif harness == "copilot":
        cname = str(p.get("toolName") or "")
        if len(cname) >= COPILOT_NAME_MAX:
            # a cut name may have lost the words a rule reads (send_money as send_mon): no split of it can be trusted
            return (f"Blocked by Tracekit: Copilot's tool name is {COPILOT_NAME_MAX} characters or longer and may have "
                    "been truncated. Shorten the server name in Copilot's MCP config.")
        if cname in ("write_bash", "write_powershell"):   # typed into a running shell, as Devin's write_to_process
            # lean: write_powershell's text is read as bash's: a ! or a bash state word denies more than PowerShell
            # needs; read PowerShell's own line editing if that stops real work
            v = tool(harness, cname, p.get("toolArgs"))[1]["command"]
            if not (isinstance(v, str) and v):
                return (f"Blocked by Tracekit: Copilot's {cname} call types no text (its `input` isn't a non-empty "
                        "string), so Tracekit can't decide what it runs.")
            reason = _typed(f"Copilot's {cname}", v)
            if reason:
                return reason
    return _blocked_tool(harness, name, raw)


def _typed(who, v, typing=True):
    """Why the text `who` (a harness's tool: "Devin's exec") types into a running shell (typing), or sends as a command,
    is denied, else None: a control character the line editor acts on, typed history expansion (TYPED), or a typed line
    that sets or replays the shell's state (_sets_state)."""
    typed = TYPED["write_to_process" if typing else "exec"].search(v)
    if typed and typed.group().strip(" \t") in ("!", "^"):
        return (f"Blocked by Tracekit: {who} types {typed.group().strip()!r}, which interactive bash expands from its "
                "history (a ! before a word, a ^ starting a line), so Tracekit can't read the line that runs; type the "
                "command itself.")
    state = _sets_state(v) if typing and not typed else None
    if state:
        return (f"Blocked by Tracekit: {who} types {state[:64]!r}, which sets or replays state of the running shell "
                "(history, an alias, a function, a prompt string, a trap, a key binding, a builtin, a shell option, "
                "PATH or a sourced file) that changes what a later line runs, and Tracekit decides each call alone; "
                "type the commands themselves.")
    if typed:
        return (f"Blocked by Tracekit: {who} {'types' if typing else 'sends'} a control character ({typed.group()!r}), "
                "which a terminal's line editor acts on (erasing, discarding or completing text), so Tracekit can't "
                "read the line that runs; send plain text, each line ending in \\n.")
    return None


def _not_text(q):
    """The v1 hook's reason to deny a mapped call `q` whose shell command isn't text, else None: the v1 policy would
    match its rules against the value's repr, not the line that runs. Codex's argv of strings is a line once mapped
    (tool); an argv with an item that isn't a string no agent sends, and the v2 signer holds it (TK-SHELL-PARSE)."""
    cmd = q["tool_input"].get("command") if q.get("tool_name") == "Bash" else None
    if cmd is None or isinstance(cmd, str):
        return None
    return (f"Blocked by Tracekit: the shell command isn't text ({json.dumps(cmd)[:200]}), so the policy can't read "
            "the line it runs; send the command as text.")


def run(harness, raw, stdout=None, stderr=None, event=None):
    """Handle one hook invocation (`event`: the hook event from the command line, or None). -> exit code. Writes the
    harness's expected stdout. A payload that is not a JSON object raises: entry answers it."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = json.loads(raw) if raw.strip() else {}
    if not isinstance(p, dict):
        raise ValueError("the hook payload is not a JSON object")
    p = dict(p, hook_event_name=event) if event else p
    is_pre = p.get("hook_event_name") in PRE or (harness == "goose" and p.get("event") in PRE) or (
        harness == "openhands" and not p.get("hook_event_name") and p.get("event_type") in PRE)
    q = normalise(harness, p)
    if harness == "gptme" and q and q["hook_event_name"] == "PromptObserved":
        q = None   # v1 has no untrusted prompt observation
    if q is None:
        _reply(harness, stdout, True, "", is_pre)
        return 0
    reason = (_blocked(harness, p, raw) or _not_text(q)) if is_pre else None
    if reason is None and is_pre and harness == "openhands" and (q.get("tool_input") or {}).get("typed") is True:
        # the v2 engine holds a call marked typed for a person (TK-SHELL-PARSE); the v1 policy doesn't read the mark
        reason = ("Blocked by Tracekit: this OpenHands terminal call is text typed into a command already running, a "
                  "key, a control character or a line left open, which runs with what came before or comes after it, "
                  "and Tracekit's v1 hook can't hold it for a person. Send the whole command in one call, or use the "
                  "v2 hook (tracekit init --dev --v2 --agent openhands), which holds it for approval.")
    err = Tee(stderr)
    if reason is not None:   # a call the hook can't decide as it runs: denied before the pipeline
        print(reason, file=err)
        code = 2
    else:
        H.AGENT_NAME = AGENT_NAMES[harness]
        H.APPROVAL_CAP_S = CLINE_WAIT_S if harness == "cline" else None   # Cline runs a call whose hook is late
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
    the call's result with an error before agy 1.4.7): its hooks always exit 0. Cline reads a hook's answer only from
    its JSON (the CLI never reads the status; the extension runs the call when a hook exits otherwise without JSON):
    its hooks always exit 0 too."""
    if harness in ("antigravity", "cline"):
        return 0
    if code and not is_pre:
        return 1
    return 0 if harness == "codex" and is_pre and os.name == "nt" else code


def _reply(harness, stdout, allowed, msg, is_pre):
    # a block message in at most 500 characters. The hook's outcome, its last line and the lines that go on from it
    # (claude_code.stopped's), goes first (before a waiting line), and in it the person's commands right after its first
    # line, which names the rule ids: a longer one loses the end of its reasons and of the agent's line, marked
    lines = msg.split("\n")
    start = max((i for i, x in enumerate(lines) if not x.startswith(STOPPED_LINES)), default=0)
    head, *rest = lines[start:]
    rest = sorted(rest, key=lambda x: not x.startswith("Person: "))   # stable: the rest keep their order
    msg = "\n".join([head, *rest, *lines[:start]])
    msg = msg if len(msg) <= 500 else msg[:499] + "…"
    if harness == "cursor":
        if is_pre:
            stdout.write(json.dumps({"permission": "allow"} if allowed else
                                    {"permission": "deny", "user_message": msg, "agent_message": msg}))
        else:
            stdout.write("{}")
    elif harness == "gemini":
        # stdout must be JSON only; a deny only for a tool call
        stdout.write(json.dumps({} if allowed or not is_pre else {"decision": "deny", "reason": msg}))
    elif harness == "antigravity":
        # agy reads stdout as its hook result message: only documented fields (another fails the hook), on every event.
        # `allow` leaves the call to agy's own permissions, as the other hooks' exit 0 does
        stdout.write(json.dumps({} if not is_pre else {"decision": "allow"} if allowed else
                                {"decision": "deny", "reason": msg or "Blocked by Tracekit"}))
    elif harness == "cline":
        # a cancel stops Cline's whole task, not only the call (the CLI and the extension both turn it into a stop)
        stdout.write(json.dumps({} if allowed or not is_pre else
                                {"cancel": True, "errorMessage": msg or "Blocked by Tracekit"}))
    elif harness == "copilot" and not allowed and is_pre:
        # Copilot denies the call at any exit but 0, and shows the reason only from this JSON (1.0.107)
        stdout.write(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": msg or "Blocked by Tracekit"}))
    elif harness in ("codex", "droid", "codebuddy") and not allowed and is_pre:
        stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                        "permissionDecisionReason": msg or "Blocked by tracekit"}}))
    stdout.flush()


# ------------------------------------------------------------------ installer

def config_path(harness, project=None, home=None):
    """The hook config of `harness`: a project's (project) or a user's (home, default ~), which differ for OpenCode,
    whose 1.0 releases load plugins from plugin/ only (plugins/ from 1.1.1). This user's Codex reads $CODEX_HOME in place
    of ~/.codex, by its real path (codex-rs find_codex_home_from_env), which keys the hooks' trust; ~/.codex as it is.
    lean: another user's (home) is ~/.codex: their CODEX_HOME isn't known here"""
    base = project or home or os.path.expanduser("~")
    if harness == "gptme":
        return os.path.join(home or os.path.expanduser("~"), ".config", "gptme", "config.toml")
    codex = os.path.realpath(os.environ["CODEX_HOME"]) if not (project or home) and os.environ.get("CODEX_HOME") \
        else os.path.join(base, ".codex")
    xdg = (None if home else os.environ.get("XDG_CONFIG_HOME")) or os.path.join(base, ".config")
    # CodeBuddy Code reads its user settings from $CODEBUDDY_CONFIG_DIR, and a project's from
    # $CODEBUDDY_PROJECT_CONFIG_DIR (absolute, or in the project), when each is set to more than blanks
    moved = os.environ.get("CODEBUDDY_PROJECT_CONFIG_DIR" if project else "CODEBUDDY_CONFIG_DIR", "")
    codebuddy = os.path.join(project, moved.strip()) if project and moved.strip() else moved \
        if not home and moved.strip() else os.path.join(base, ".codebuddy")
    return {"codex": os.path.join(codex, "hooks.json"), "cursor": os.path.join(base, ".cursor", "hooks.json"),
            "codebuddy": os.path.join(codebuddy, "settings.json"),
            "gemini": os.path.join(base, ".gemini", "settings.json"),
            "goose": os.path.join(base, ".agents", "plugins", "tracekit", "hooks", "hooks.json"),
            "qwen": os.path.join(base, ".qwen", "settings.json"),
            "droid": os.path.join(base, ".factory", "hooks.json"),
            "antigravity": os.path.join(base, ".agents", "hooks.json") if project else
                           os.path.join(base, ".gemini", "config", "hooks.json"),
            "opencode": os.path.join(base, ".opencode", "plugin", "tracekit.js") if project else
                        os.path.join(xdg, "opencode", "plugin", "tracekit.js"),
            # Kilo reads the plugin/ folder of each of its config directories: a project's .kilo (or .kilocode), and
            # $XDG_CONFIG_HOME (else ~/.config)/kilo; not OpenCode's (packages/opencode/src/config/paths.ts)
            "kilo": os.path.join(base, ".kilo", "plugin", "tracekit.js") if project else
                    os.path.join(xdg, "kilo", "plugin", "tracekit.js"),
            # Crush reads ./crush.json in a project, else its GlobalConfig(): $CRUSH_GLOBAL_CONFIG/crush.json, or
            # $XDG_CONFIG_HOME (else ~/.config; Windows %USERPROFILE%\.config)/crush/crush.json
            "crush": os.path.join(base, "crush.json") if project else
                     os.path.join((None if home else os.environ.get("CRUSH_GLOBAL_CONFIG")) or
                                  os.path.join(xdg, "crush"), "crush.json"),
            # Devin's project hooks file is the event map itself; its user config (Windows: %APPDATA%\devin) nests
            # them under `hooks`
            "devin": os.path.join(base, ".devin", "hooks.v1.json") if project else
                     os.path.join(os.environ["APPDATA"], "devin", "config.json")
                     if os.name == "nt" and not home and os.environ.get("APPDATA") else
                     os.path.join(base, ".config", "devin", "config.json"),
            # Cline's CLI and VS Code extension both read ~/Documents/Cline/Hooks and a workspace's .clinerules/hooks: a
            # hook is a file named after its event (on Windows the extension runs <event>.ps1). Its PreToolUse stands
            # for the set _install_cline writes
            "cline": os.path.join(base, ".clinerules", "hooks", CLINE_FILE) if project else
                     os.path.join(base, "Documents", "Cline", "Hooks", CLINE_FILE),
            # the OpenHands CLI (1.16.0 as released, on SDK 1.21.0; its main is on 1.28.1) reads
            # <working dir>/.openhands/hooks.json, else
            # ~/.openhands/hooks.json, the first that exists (HookConfig.load); $OH_PERSISTENCE_DIR is honoured on SDK
            # main only, so it isn't followed here
            "openhands": os.path.join(base, ".openhands", "hooks.json"),
            # Copilot CLI runs every hooks file in a repository's .github/hooks and in its home's hooks/ ($COPILOT_HOME,
            # else ~/.copilot): Tracekit's own file
            "copilot": os.path.join(base, ".github", "hooks", "tracekit.json") if project else
                       os.path.join((None if home else os.environ.get("COPILOT_HOME")) or
                                    os.path.join(base, ".copilot"), "hooks", "tracekit.json")}[harness]


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


def codex_trust_store(home=None):
    """The config.toml where Codex records which hooks a person trusted (in /hooks): this user's Codex home's
    ($CODEX_HOME, else ~/.codex), or that of the user whose home is `home`."""
    return os.path.join(os.path.dirname(config_path("codex", home=home)), "config.toml")


def codex_trust_line(user=None, home=None):
    """What init says last for Codex: it runs a hook only once a person trusted it as it is now, and skips it until
    then; interactive codex asks at startup, `codex exec` says nothing (learn.chatgpt.com/docs/hooks; codex-rs tui
    startup_hooks_review.rs); doctor's D-CODEX-HOOK-TRUST checks. user, home: system mode's agent user."""
    run = f"As {user}, run" if user else "Run"
    if not user and os.environ.get("CODEX_HOME"):   # the Codex that reads it, not one that reads ~/.codex
        run += f" codex with CODEX_HOME={os.environ['CODEX_HOME']}"
    else:
        run += " codex"
    return ("next, trust these hooks in Codex: it runs none of them until a person has, so until then no Codex call is "
            f"recorded or decided. {run} in a terminal, type /hooks and trust Tracekit's hooks (Codex records that in "
            f"{codex_trust_store(home)}). Interactive codex also asks at startup whenever they are new or changed (as "
            "after tracekit init); `codex exec` never asks and skips them without a word. `tracekit doctor` says "
            "whether they are trusted")


def _version(cmd):
    """"v2" for the v2 hook's command, "v1" for the v1 hook's, else None."""
    cmd = cmd if isinstance(cmd, str) else ""
    return "v2" if V2_MODULE in cmd else "v1" if "tracekit.agent_hooks" in cmd else None


def _plugin_marker(harness):
    return f"// Installed by Tracekit; tracekit uninstall --agent {harness} removes this file."


def _opencode_plugin(python, v2, harness="opencode"):
    """The local OpenCode plugin (Kilo's too: harness). OpenCode runs plugins with Bun and awaits a before hook, so the
    hook's process, spawned without blocking OpenCode's event loop (parallel calls are decided at once), holds the call
    until Tracekit allows or denies it (or a person approves it); one that doesn't answer in time is killed and its call
    blocked. Each event's command names the event, and runs the hook as install._hook_command does (python, or this
    interpreter)."""
    from .install import _dev_hook_argv
    module = V2_MODULE if v2 else "tracekit.agent_hooks"
    commands = {ev: [python, "-I", "-m", module, harness, ev] if python else
                _dev_hook_argv(module, "entry", (harness, ev)) for ev in ("tool.execute.before", "tool.execute.after")}
    agent, config = ("Kilo Code", "kilo.json") if harness == "kilo" else ("OpenCode", "opencode.json")
    return f'''{_plugin_marker(harness)}
const commands = {json.dumps(commands)};
// above the most a hook takes to answer, a held call's approval wait included (Tracekit's APPROVAL_WAIT_S), as the
// other coding agents' pre-tool timeout: a hook still running then hung, so it is killed and its call blocked
const KILL_MS = 600000;

async function tracekit(event, input, toolInput, toolResponse) {{
  const payload = {{
    hook_event_name: event,
    session_id: input.sessionID,
    tool_use_id: input.callID,
    tool_name: input.tool,
    tool_input: toolInput,
    tool_response: toolResponse,
    cwd: input.cwd,
  }};
  let timer, killed = false;
  try {{
    const hook = Bun.spawn({{
      cmd: commands[event],
      cwd: input.cwd,
      stdin: new TextEncoder().encode(JSON.stringify(payload)),
      stdout: "ignore",
      stderr: "pipe",
    }});
    timer = setTimeout(() => {{ killed = true; hook.kill("SIGKILL"); }}, KILL_MS);
    const [message] = await Promise.all([new Response(hook.stderr).text(), hook.exited]);
    return killed ? {{ code: 1, message: `[tracekit] the hook did not answer in ${{KILL_MS / 1000}} s: stopped` }}
      : {{ code: hook.exitCode, message: message.trim() }};
  }} catch (error) {{
    return {{ code: 1, message: `[tracekit] hook error (${{error}})` }};
  }} finally {{
    clearTimeout(timer);
  }}
}}

export const TracekitPlugin = async ({{ directory }}) => ({{
  "tool.execute.before": async (input, output) => {{
    if (input.tool === "batch") {{   // OpenCode runs the calls inside a batch with no plugin hooks
      throw new Error("Blocked by Tracekit: {agent}'s experimental batch tool runs its calls without plugin hooks, " +
        "so Tracekit can't decide them. Turn it off (experimental.batch_tool in {config}) and make each call itself.");
    }}
    const result = await tracekit("tool.execute.before", {{ ...input, cwd: directory }}, output.args);
    if (result.code !== 0) {{   // blocked (2), or the hook could not decide the call: it doesn't run
      throw new Error(result.message || "Blocked by Tracekit: the hook could not decide this call");
    }}
  }},
  "tool.execute.after": async (input, output) => {{
    const result = await tracekit("tool.execute.after", {{ ...input, cwd: directory }}, input.args, output);
    if (result.code !== 0) console.error(result.message);
  }},
}});
'''


def _install_opencode(path, uninstall=False, v2=False, python=None, harness="opencode"):
    """Install one owned local plugin without overwriting an OpenCode (or Kilo) plugin that is not Tracekit's."""
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
            if raw is not None and _plugin_marker(harness) not in text:
                raise SettingsError(f"{path} is not Tracekit's plugin; Tracekit did not change it.")
            old = _version(text)
            plugin = None if uninstall else _opencode_plugin(python, v2, harness).encode("utf-8")
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
    _said(path, {old} - {None}, uninstall, v2)
    return path


GPTME_MARKER = "# Installed by Tracekit; tracekit uninstall --agent gptme removes this file."
GPTME_HOOK = "bridge.py"


def _gptme_hook_path(config):
    return os.path.join(os.path.dirname(config), "plugins", "tracekit", "hooks", GPTME_HOOK)


def _gptme_plugin(python, v2):
    from .install import _dev_hook_argv
    module = V2_MODULE if v2 else "tracekit.agent_hooks"
    argv = [python, "-I", "-m", module, "gptme"] if python else _dev_hook_argv(module, "entry", ("gptme",))
    with open(os.path.join(os.path.dirname(__file__), "_gptme_plugin.py"), encoding="utf-8") as f:
        source = f.read()
    return GPTME_MARKER + "\n" + source.replace("COMMAND = ()", "COMMAND = " + json.dumps(argv), 1).replace(
        "V2 = False", f"V2 = {v2}", 1)


def _gptme_config(directory, path):
    from .deploy import files
    from .install import SettingsError
    name = os.path.basename(path)
    raw = files.read(directory, name)
    text = raw.decode("utf-8") if raw is not None else ""
    standard = "~/.config/gptme/plugins"
    paths = f'paths = ["{standard}"]'
    enabled_hint = None
    try:
        import tomllib
    except ImportError:
        # lean: on Python 3.9/3.10 detect the table by its header or key; use a TOML parser if older interpreters
        # need to read more elaborate plugin config.
        has_plugins = bool(re.search(r'(?m)^\s*(?:\[+\s*["\']?plugins\b|["\']?plugins["\']?\s*[.=])', text))
        configured = any(line.strip() == paths for line in text.splitlines())
        top, *tables = re.split(r"(?m)^[ \t]*(?=\[)", text)
        table = next((section for section in tables
                      if re.match(r'''\[[ \t]*(?:plugins|"plugins"|'plugins')[ \t]*\][ \t]*(?:#[^\n]*)?\r?\n''',
                                  section)), "")
        key = r'''(?:enabled|"enabled"|'enabled')[ \t]*='''
        if re.search(r"(?m)^[ \t]*" + key, table) or re.search(
                r'''(?m)^[ \t]*(?:plugins|"plugins"|'plugins')[ \t]*\.[ \t]*''' + key, top):
            enabled_hint = 'If [plugins].enabled is nonempty, include "tracekit" in the list.'
    else:
        try:
            config = tomllib.loads(text)
        except ValueError as e:
            raise SettingsError(f"{path} is not valid TOML; Tracekit did not change it: {e}") from e
        has_plugins = "plugins" in config
        plugins = config.get("plugins")
        entries = plugins.get("paths", ()) if isinstance(plugins, dict) else ()
        configured = isinstance(entries, list) and any(
            isinstance(entry, str) and (entry == standard or os.path.realpath(os.path.expanduser(entry)) ==
                                        os.path.realpath(os.path.join(os.path.dirname(path), "plugins")))
            for entry in entries
        )
        if isinstance(entries, list) and all(isinstance(entry, str) for entry in entries):
            paths = "paths = " + json.dumps([*entries, standard], ensure_ascii=False)
        enabled = plugins.get("enabled") if isinstance(plugins, dict) else None
        if isinstance(enabled, list) and enabled and "tracekit" not in enabled and all(isinstance(p, str) for p in enabled):
            enabled_hint = "enabled = " + json.dumps([*enabled, "tracekit"], ensure_ascii=False)
    if has_plugins:
        # lean: print changes for existing tables; use a TOML editor if automatic merges are needed.
        if not configured:
            print(f"Add the Tracekit plugin directory to [plugins] in {path}: {paths}")
        if enabled_hint:
            print(f"Enable the Tracekit plugin in [plugins] in {path}: {enabled_hint}")
        return
    if raw is not None:
        files.backup(directory, name, raw)
    prefix = text.rstrip("\r\n") + "\n\n" if text else ""
    files.write(directory, name, (prefix + "[plugins]\n" + paths + "\n").encode("utf-8"))


def _install_gptme(path, uninstall, v2, python):
    from .deploy import files
    from .install import SettingsError
    path = os.path.abspath(path)
    plugin = os.path.dirname(os.path.dirname(_gptme_hook_path(path)))
    if uninstall and not os.path.lexists(plugin):
        return path
    marker = (GPTME_MARKER + "\n").encode("utf-8")
    removed = set()
    try:
        with contextlib.ExitStack() as stack:
            def entered(directory):
                stack.callback(files.close, directory)
                return directory

            parent = os.path.dirname(path)
            os.makedirs(parent, exist_ok=True)
            root = entered(files.open_dir(parent))
            plugins = entered(files.subdir(root, "plugins"))
            existed = os.path.lexists(plugin)
            package = entered(files.subdir(plugins, "tracekit"))
            raw = files.read(package, "__init__.py")
            if existed and (raw is None or not raw.startswith(marker)):
                raise SettingsError(f"{plugin} is not Tracekit's plugin; Tracekit did not change it.")
            hook_path = os.path.join(plugin, "hooks")
            hooks = entered(files.subdir(package, "hooks")) if not uninstall or os.path.lexists(hook_path) else None
            entries = [(package, "__init__.py", marker)]
            if hooks is not None:
                entries.extend(((hooks, "__init__.py", marker + b"from .bridge import register\n"),
                                (hooks, GPTME_HOOK, b"" if uninstall else _gptme_plugin(python, v2).encode("utf-8"))))
            for directory, name, _ in entries:
                existing = files.read(directory, name)
                if existing is not None and not existing.startswith(marker):
                    raise SettingsError(f"{plugin}/{name} is not Tracekit's plugin; Tracekit did not change it.")
                if name == GPTME_HOOK and existing:
                    version = _version(existing.decode("utf-8", "replace"))
                    if version:
                        removed.add(version)
            if uninstall:
                for directory, name, _ in reversed(entries[1:]):
                    with contextlib.suppress(FileNotFoundError):
                        files.remove(directory, name)
                if hooks is not None:
                    with contextlib.suppress(OSError):
                        os.rmdir(hook_path)
                # Keep ownership if gptme left bytecode or the user added files to the package.
                if os.listdir(plugin) == ["__init__.py"]:
                    files.remove(package, "__init__.py")
            else:
                for directory, name, contents in entries:
                    if files.read(directory, name) != contents:
                        files.write(directory, name, contents)
                _gptme_config(root, path)
    except (OSError, UnicodeDecodeError) as e:
        raise SettingsError(f"{path}: {e}") from e
    if uninstall:
        for directory in (os.path.join(plugin, "hooks"), plugin):
            with contextlib.suppress(OSError):
                os.rmdir(directory)
    _said(path, removed, uninstall, v2)
    return path


def _read(path):
    """(the JSON object in the hook config `path`, its text), or ({}, None) when there is no file."""
    from .install import SettingsError
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as f:
            txt = f.read()
        s = json.loads(txt) if txt.strip() else {}
    except (OSError, ValueError) as e:
        raise SettingsError(f"{path} is not valid JSON ({e}); Tracekit did not change it.") from e
    if not isinstance(s, dict):
        raise SettingsError(f"{path} must contain a JSON object; Tracekit did not change it.")
    return s, txt


def _command(harness, ev, v2, python):
    """The command of Tracekit's hook for `ev` (python: see install._hook_command). The v2 hook names its event, so it
    can block a pre-tool payload it cannot read; agy's and Copilot's payloads name none, so their v1 hooks do too
    (without it a v1 hook reads no event from the payload, and lets the call run undecided)."""
    from .install import _hook_command
    c = _hook_command(V2_MODULE if v2 else "tracekit.agent_hooks", "entry",
                      (harness, ev) if v2 or harness in ("antigravity", "copilot") else (harness,), python, ev in PRE,
                      harness == "antigravity")
    # on Windows, Codex and Gemini CLI run a hook's command under PowerShell (Codex under cmd.exe when PowerShell
    # isn't found or the session has no single local environment), and Qwen Code under the PowerShell its hook's
    # "shell" names (install). PowerShell runs a quoted program path only through its call operator, which cmd.exe
    # can't parse: an interpreter path that needs no quotes goes bare, which both run
    # assume Droid runs hooks under cmd.exe. goose (sh -c), Crush and CodeBuddy Code (Git Bash where it finds one, as
    # Claude Code) keep _hook_command's form, and so does OpenHands (subprocess.run(shell=True): cmd.exe). Devin
    # doesn't document its Windows shell: a path that needs quotes keeps cmd.exe's form, and one that doesn't goes
    # bare, which both run
    if os.name != "nt" or harness in ("cursor", "droid", "goose", "crush", "openhands", "codebuddy"):
        return c
    m = re.match(r'"([A-Za-z0-9_.:\\-]+)"', c)   # cmd.exe ends a program word at /
    c = m.group(1) + c[m.end():] if m else c if harness == "devin" else f"& {c}"
    # Windows PowerShell hands a native exit 2 back as 1, and Qwen Code blocks a call only at 2; a PreToolUse hook whose
    # Python didn't run or failed exits 2 ($LASTEXITCODE isn't enough: the profile Qwen Code doesn't skip may set it)
    if harness != "qwen":
        return c
    return c + ("; if ($?) { exit $LASTEXITCODE } else { exit 2 }" if ev in PRE else "; exit $LASTEXITCODE")


def _merge(hooks, path, events, entry, uninstall, flat=False):
    """Take Tracekit's hooks, v1 and v2, out of each event's list in `hooks` (the event map of the config at `path`),
    keeping a person's, then add entry(ev) unless uninstalling or it is None; an event left with none is dropped. flat:
    each list holds hooks ({command, ...}), not groups of them ({hooks: [...]}). -> the versions taken out."""
    from .install import SettingsError
    removed = set()
    for ev in events:
        lst = hooks.get(ev, [])
        if not isinstance(lst, list):
            raise SettingsError(f"hooks.{ev} in {path} must be a list; Tracekit did not change it.")
        kept = []
        for h in lst:
            cmds = ([h.get("command")] if flat else [x.get("command") for x in h.get("hooks") or ()
                                                     if isinstance(x, dict)]) if isinstance(h, dict) else []
            ours = {_version(c) for c in cmds} - {None}
            removed |= ours
            if not ours:
                kept.append(h)
        new = None if uninstall else entry(ev)
        if new is not None:
            kept.append(new)
        if kept:
            hooks[ev] = kept
        else:
            hooks.pop(ev, None)
    return removed


def _said(path, removed, uninstall, v2):
    """Say which of Tracekit's hooks in `path` (`removed`: the versions taken out) init replaced or uninstall
    removed."""
    new = "v2" if v2 else "v1"
    old = " and ".join(sorted(removed if uninstall else removed - {new}))
    if old:
        print(f"Tracekit {old} hooks removed from {path}" if uninstall else
              f"Tracekit {old} hooks replaced by {new} hooks in {path}")


GOOSE_PLUGIN = {"name": "tracekit", "version": __version__,
                "description": "Tracekit hooks: policy gates and signed records for goose tool calls."}
GOOSE_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")


def _install_goose(path, uninstall=False, v2=False, python=None):
    """Install one owned goose plugin without overwriting a plugin that is not Tracekit's. goose runs a rule with no
    matcher for every tool (a bare "*" matcher is an invalid regex goose silently skips), its timeout is in seconds,
    and only a PreToolUse action carries on_failure: block."""
    from .install import SettingsError, _atomic_write_json, _backup_changed
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
    s, txt = _read(path)
    hooks = s.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {path} must be an object; Tracekit did not change it.")

    def entry(ev):
        action = {"type": "command", "command": _command("goose", ev, v2, python),
                  "timeout": 600 if ev == "PreToolUse" else 30}
        if ev == "PreToolUse":   # a hook that can't run blocks the call; other events ignore on_failure
            action["on_failure"] = "block"
        return {"hooks": [action]}   # no matcher: goose matches every tool of the event
    removed = _merge(hooks, path, GOOSE_EVENTS, entry, uninstall)
    if not hooks:
        s.pop("hooks")
    changed = _backup_changed(path, txt, s)
    if uninstall and not s:
        # the only content was Tracekit's hooks: remove the plugin's files, not other content (a file with other
        # keys falls through to the write below, and its manifest stays)
        if os.path.lexists(path):
            os.unlink(path)
        if os.path.exists(manifest):   # validated above as Tracekit's, when present
            os.unlink(manifest)
        _said(path, removed, uninstall, v2)
        return path
    if not uninstall:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(manifest):
            _atomic_write_json(manifest, GOOSE_PLUGIN)
    if changed:
        _atomic_write_json(path, s)
    _said(path, removed, uninstall, v2)
    return path


CRUSH_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd")


def _install_crush(path, uninstall=False, v2=False, python=None):
    """Install Tracekit's hooks in Crush's JSON config. Each event is a flat list of
    {name, command, timeout} entries (no nested `hooks` array), and no matcher: it matches every tool, and Crush
    rejects a matcher on an event that carries no tool name. A person's hooks are kept."""
    from .install import SettingsError, _atomic_write_json, _backup_changed
    path = os.path.abspath(path)
    if uninstall and not os.path.exists(path):
        return path
    if not uninstall:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    s, txt = _read(path)
    hooks = s.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {path} must be an object; Tracekit did not change it.")
    # seconds; 600 leaves a person time to approve a held call (Crush's default is 30)
    removed = _merge(hooks, path, CRUSH_EVENTS, lambda ev: {
        "name": "tracekit", "command": _command("crush", ev, v2, python), "timeout": 600 if ev == "PreToolUse" else 30},
        uninstall, flat=True)
    if not hooks:
        s.pop("hooks")
    if _backup_changed(path, txt, s):
        _atomic_write_json(path, s)
    _said(path, removed, uninstall, v2)
    return path


CLINE_WAIT_S = 20   # most a Cline hook waits for an approval: the extension runs a call whose hook takes over 30 s


def _cline_hook(argv, ev):
    """Tracekit's hook file for Cline's `ev`, a script that runs argv: a POSIX shell script, or PowerShell on Windows.
    Cline runs a call whose hook fails, prints nothing or doesn't answer in time (the CLI 120 s, the extension 30 s),
    so the script answers a cancel when the hook printed nothing (cline_cap_wait keeps the hook's wait under them)."""
    fallback = json.dumps({"cancel": True, "errorMessage": "Blocked by Tracekit: its hook could not run, so the call "
                           "can't be decided"} if ev in PRE else {})
    if os.name == "nt":
        cmd = " ".join("'" + a.replace("'", "''") + "'" for a in argv)
        return f'''# {_plugin_marker("cline")[3:]}
$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$out = ([Console]::In.ReadToEnd() | & {cmd}) -join "`n"
if ($out) {{ $out }} else {{ '{fallback.replace("'", "''")}' }}
'''
    return f'''#!/bin/sh
# {_plugin_marker("cline")[3:]}
out=$({shlex.join(argv)})
if [ -n "$out" ]; then printf '%s\\n' "$out"; else printf '%s\\n' {shlex.quote(fallback)}; fi
'''


def cline_cap_wait():
    """$TRACEKIT_APPROVAL_WAIT at most CLINE_WAIT_S, as the v2 hook reads it (float(): 1e3, 1_000 and inf too), so a held
    call's hook answers before Cline's timeout runs the call."""
    with contextlib.suppress(ValueError):
        if float(os.environ.get("TRACEKIT_APPROVAL_WAIT") or 0) > CLINE_WAIT_S:
            os.environ["TRACEKIT_APPROVAL_WAIT"] = str(CLINE_WAIT_S)


def cline_argv(text):
    """The argv a Cline hook file `text` (_cline_hook's) runs, else None."""
    m = re.search(r"^out=\$\((.*)\)$", text, re.M)
    if m:
        return shlex.split(m.group(1))
    # one space between the quoted arguments, as _cline_hook writes them: a quote then ends an argument or doubles one
    m = re.search(r"\| & ('(?:[^']|'')*'(?: '(?:[^']|'')*')*)\) -join", text)
    return [a.replace("''", "'") for a in re.findall(r"'((?:[^']|'')*)'(?: |$)", m.group(1))] if m else None


def cline_documents():
    """The Documents folder Cline's VS Code extension reads Cline/Hooks in (documents-path.ts): Windows' own (OneDrive
    may have moved it), on Linux `xdg-user-dir DOCUMENTS` (the home folder itself when none is set up), else
    ~/Documents, the one Cline's CLI always reads."""
    docs = os.path.join(os.path.expanduser("~"), "Documents")
    with contextlib.suppress(Exception):
        if os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                return os.path.expandvars(winreg.QueryValueEx(k, "Personal")[0]) or docs
        if sys.platform.startswith("linux"):
            import subprocess
            out = subprocess.run(["xdg-user-dir", "DOCUMENTS"], capture_output=True, text=True, timeout=5).stdout
            return out.strip() or docs
    return docs


def cline_dirs(home=None, cwd=None):
    """Every directory Cline's CLI or VS Code extension runs hooks from (paths.ts, disk.ts): the user's
    ~/Documents/Cline/Hooks (the extension's Documents: cline_documents) and $CLINE_DIR/hooks (else ~/.cline/hooks), a
    workspace's .cline/hooks and .clinerules/hooks. Each runs every hook in it, so a second copy of Tracekit's records
    each call twice."""
    home, cwd = home or os.path.expanduser("~"), cwd or os.getcwd()
    return list(dict.fromkeys([os.path.join(home, "Documents", "Cline", "Hooks"),
                               *([os.path.join(cline_documents(), "Cline", "Hooks")] if home == os.path.expanduser("~")
                                 else []),
                               os.path.join(os.environ.get("CLINE_DIR") or os.path.join(home, ".cline"), "hooks"),
                               os.path.join(cwd, ".cline", "hooks"), os.path.join(cwd, ".clinerules", "hooks")]))


def _install_cline(path, uninstall=False, v2=False, python=None):
    """Write (or remove) Tracekit's hook file for each of CLINE_EVENTS in the directory of `path` (its PreToolUse),
    each named after its event, executable, never over a file that isn't Tracekit's."""
    from .deploy import files
    from .install import SettingsError, _dev_hook_argv
    folder, suffix = os.path.split(os.path.abspath(path))[0], os.path.splitext(path)[1]
    if uninstall and not os.path.isdir(folder):
        return path
    module = V2_MODULE if v2 else "tracekit.agent_hooks"
    old, wrote = set(), False
    try:
        os.makedirs(folder, exist_ok=True)
        d = files.open_dir(folder)
        try:
            for ev in CLINE_EVENTS:
                name = ev + suffix
                raw = files.read(d, name)
                text = raw.decode("utf-8", "replace") if raw is not None else ""
                if raw is not None and _plugin_marker("cline")[3:] not in text:
                    raise SettingsError(f"{os.path.join(folder, name)} is not Tracekit's hook; Tracekit did not "
                                        "change it.")
                old |= {_version(text)} - {None}
                if uninstall:
                    if raw is not None:
                        os.unlink(name if isinstance(d, int) else os.path.join(folder, name),
                                  **({"dir_fd": d} if isinstance(d, int) else {}))
                    continue
                argv = [python, "-I", "-m", module, "cline", ev] if python else \
                    _dev_hook_argv(module, "entry", ("cline", ev))
                hook = _cline_hook(argv, ev).encode("utf-8")
                if raw != hook:   # Tracekit's own file: no backup, which the CLI would run as a hook too
                    files.write(d, name, hook, 0o700)
                    wrote = True
        finally:
            files.close(d)
    except (files.UnsafePath, OSError) as e:
        raise SettingsError(f"{folder}: {e}") from e
    _said(path, old, uninstall, v2)
    if wrote:
        ext = os.path.join(cline_documents(), "Cline", "Hooks")
        user = folder == os.path.dirname(os.path.abspath(config_path("cline")))
        if user and os.path.normcase(ext) != os.path.normcase(folder):
            print(f"Cline's VS Code extension reads its hooks in {ext}, not {folder}, on this machine (where your "
                  "Documents folder is): for the extension, install them in each workspace with --project")
    return path


def install(harness, project=None, uninstall=False, v2=False, python=None, path=None):
    """Add (or remove) Tracekit's hooks, v1 or the v2 hook (python: see install._hook_command), in the harness's
    config file (path, or config_path), replacing those of the other version. -> the file's path."""
    from .install import SettingsError, _atomic_write_json, _backup_changed
    path = path or config_path(harness, project)
    if harness == "gptme":
        return _install_gptme(path, uninstall, v2, python)
    if harness in PLUGIN_TOOLS:
        return _install_opencode(path, uninstall, v2, python, harness)
    if harness == "goose":
        return _install_goose(path, uninstall, v2, python)
    if harness == "crush":
        return _install_crush(path, uninstall, v2, python)
    if harness == "cline":
        return _install_cline(path, uninstall, v2, python)
    if harness in ("droid", "copilot") and uninstall and not os.path.exists(path):   # nothing to remove: no file made
        return path
    if harness == "droid" and not uninstall and not os.path.exists(path):
        legacy = os.path.join(os.path.dirname(path), "hooks", "hooks.json")
        if os.path.exists(legacy):
            raise SettingsError(f"{legacy} is Droid's legacy hooks file: save once in Droid's /hooks so Droid moves it "
                                f"to {path}, then run init again. Tracekit did not change it.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    s, txt = _read(path)
    if harness == "droid" and not uninstall and txt is None:
        # Droid reads settings hooks only while the standalone file is absent; preserve them when creating it.
        s = dict(_droid_settings_hooks(path) or {})
    # Droid's standalone hooks.json is the event map, and so is a Devin project's hooks.v1.json; Droid's settings.json
    # and Devin's config.json nest that map under `hooks`. agy's maps each hook's name to its event map: Tracekit's is
    # AGY_HOOK
    key = AGY_HOOK if harness == "antigravity" else "hooks"
    bare = harness == "droid" or harness == "devin" and os.path.basename(path) == "hooks.v1.json" or \
        harness == "openhands" and "hooks" not in s and any(k in OPENHANDS_FIELDS or k in OPENHANDS_FIELDS.values()
                                                           for k in s)   # its direct form: merged as it is written
    fields = harness == "openhands" and bare and any(k in OPENHANDS_FIELDS.values() for k in s)   # snake_case keys
    hooks = s if bare else s.setdefault(key, {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'{key}' in {path} must be an object; Tracekit did not change it.")
    if harness == "cursor":
        s.setdefault("version", 1)
        closed = v2 or H.fail_closed()   # v2: a hook that cannot run blocks, as the v2 hook does
        events = {"preToolUse": 600, "postToolUse": 30, "postToolUseFailure": 30, "beforeSubmitPrompt": 30, "sessionStart": 30,
                  "sessionEnd": 30, **dict.fromkeys(CURSOR_SAID, 30)}

        def entry(ev):
            if v2 or ev not in CURSOR_SAID:   # the v1 hook records no model text
                return {"command": _command(harness, ev, v2, python), "type": "command", "timeout": events[ev],
                        "failClosed": closed and ev in PRE}   # on another event Cursor blocks a prompt too
        removed = _merge(hooks, path, events, entry, uninstall, flat=True)
    elif harness == "copilot":
        s.setdefault("version", 1)

        def entry(ev):   # `command` and `timeout` (s), which Copilot CLI 1.0.107 reads as its `bash` and `timeoutSec`
            return {"type": "command", "command": _command(harness, ev, v2, python), "timeout": COPILOT_EVENTS[ev]}
        removed = _merge(hooks, path, COPILOT_EVENTS, entry, uninstall, flat=True)
    else:
        events = (DROID_EVENTS if harness == "droid" else AGY_EVENTS if harness == "antigravity" else
                  DEVIN_EVENTS if harness == "devin" else OPENHANDS_EVENTS if harness == "openhands" else
                  ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"] if harness == "codex"
                  else ["PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "SessionEnd"]
                  if harness in ("qwen", "codebuddy") else
                  ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart", "SessionEnd"])
        tools = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "BeforeTool", "AfterTool"}

        def entry(ev):
            h = {"type": "command", "command": _command(harness, ev, v2, python)}
            # ms for Gemini CLI; newer Qwen Code reads seconds, but 1000 or more still as ms, so 600 s in both
            if harness in ("gemini", "qwen"):   # holds wait for approval (Qwen Code's default is 60 s)
                h.update(name="tracekit", timeout=600_000 if ev in PRE else 30_000)
                if harness == "qwen" and os.name == "nt":
                    # Qwen Code otherwise runs it under cmd.exe or Git Bash, by how it was started; Node's quoting
                    # of the command for cmd.exe leaves a quoted program path it can't run
                    h["shell"] = "powershell"
            else:
                h["timeout"] = 600 if ev == "PreToolUse" else 30
            # Devin's matcher is a regex, which "*" isn't: a group with none matches every tool
            return {"matcher": "*", "hooks": [h]} if ev in tools and harness != "devin" else {"hooks": [h]}
        if fields:   # a file in OpenHands' own field names keeps them: Tracekit's hooks go under pre_tool_use, ...
            named = {OPENHANDS_FIELDS[ev]: ev for ev in events}
            removed = _merge(hooks, path, list(named), lambda k: entry(named[k]), uninstall)
        else:
            removed = _merge(hooks, path, events, entry, uninstall)
    if harness == "antigravity":   # Tracekit's named hook holds only its own two entries, rewritten whole: agy loads a
        # named hook with "enabled": false and never runs it
        if not uninstall:
            s[key] = {ev: hooks[ev][-1:] for ev in AGY_EVENTS}
        elif removed:
            s.pop(key)
    if not hooks and not bare:
        s.pop(key, None)
    # Devin also runs Claude Code's hooks (read_config_from.claude, on by default), so with Tracekit's Claude Code hook
    # installed it would decide each Devin call a second time (that hook blocks them: they carry no tool_use_id). A
    # project keeps the setting in .devin/config.json, beside hooks.v1.json
    devin_rc = os.path.join(os.path.dirname(path), "config.json") if bare else path
    if harness == "devin" and not uninstall:
        c, ctxt = _read(devin_rc) if bare else (s, None)
        if _devin_claude_off(c, devin_rc) and bare and _backup_changed(devin_rc, ctxt, c):
            _atomic_write_json(devin_rc, c)
    # what is left of a Droid hooks.json once Tracekit's hooks are out can be the copy of settings.json's hooks init
    # made it with: gone, Droid reads those again. Any other stays (`kept`: why), and is named
    kept, settings = None, os.path.join(os.path.dirname(path), "settings.json")
    if uninstall and harness == "droid" and s and removed:
        try:
            kept = _droid_settings_hooks(path) != s and f"the hooks left in it aren't those in {settings}"
        except SettingsError as e:   # Tracekit's hooks still go: what is left can't be told from a person's
            kept = f"{settings} can't be read ({e.__cause__})"
    changed = _backup_changed(path, txt, s)
    if uninstall and (harness == "droid" and (not s or kept is False)
                      or harness == "copilot" and set(s) <= {"version"}):   # Tracekit's own file, left with no hooks
        os.unlink(path)
    elif changed:
        _atomic_write_json(path, s)
    if uninstall and harness == "codex":   # init's reasoning summaries line goes with its hooks
        try:
            codex_reasoning(path, uninstall=True)
        except SettingsError:   # a config.toml init can't have written to
            pass
    _said(path, removed, uninstall, v2)
    if harness == "copilot" and project and changed and not uninstall:   # said when the file is written
        print(f"{path} names this machine's Python, and .github/ is usually committed: on another machine, or in "
              "Copilot's cloud agent, the hook can't start, so Copilot denies every call there. Keep the file out of "
              "the commit (add .github/hooks/tracekit.json to .git/info/exclude), or install the hooks for your user "
              "instead (the same command without --project)")
    if kept:
        print(f"{path} kept: {kept}. Droid runs the hooks in it, and those in {settings} only once it is gone: move "
              f"any you want into {settings}, then delete it")
    if harness == "devin" and uninstall:
        with contextlib.suppress(SettingsError):   # a line of advice, never in the way of the uninstall
            rc = (_read(devin_rc)[0] if bare else s).get("read_config_from")
            if isinstance(rc, dict) and rc.get("claude") is False:
                print(f"read_config_from.claude stays false in {devin_rc}: set it to true there for Devin to read "
                      "Claude Code's hooks, rules, skills, commands and MCP servers again")
    return path


def _devin_claude_off(s, path):
    """Set read_config_from.claude to false in `s`, the Devin config at `path`, and say what that costs. -> whether `s`
    changed."""
    from .install import SettingsError
    rc = s.setdefault("read_config_from", {})
    if not isinstance(rc, dict):
        raise SettingsError(f"'read_config_from' in {path} must be an object; Tracekit did not change it.")
    if rc.get("claude") is False:
        return False
    rc["claude"] = False
    print(f"read_config_from.claude set to false in {path}: Devin no longer runs Claude Code's hooks (Tracekit's would "
          "decide each call a second time), nor reads its rules, skills, commands or MCP servers; set it back to true "
          "for those (uninstall leaves it)")
    return True


def _droid_settings_hooks(path):
    """The hooks in the settings.json beside Droid's hooks.json `path`, which Droid reads only while that is absent;
    None without a settings.json."""
    from .install import SettingsError
    settings = os.path.join(os.path.dirname(path), "settings.json")
    if not os.path.exists(settings):
        return None
    try:
        with open(settings, encoding="utf-8") as f:
            hooks = json.load(f).get("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("hooks must be an object")
    except (OSError, ValueError, AttributeError) as e:
        raise SettingsError(f"{settings}: {e}; Tracekit did not change it.") from e
    return hooks


def stdin_text():
    """A hook's payload, UTF-8 JSON (a byte order mark before it is dropped): read as bytes where stdin has them, since
    Windows decodes a pipe with its ANSI code page."""
    return sys.stdin.buffer.read().decode("utf-8-sig", "replace") if hasattr(sys.stdin, "buffer") else sys.stdin.read()


def entry(harness=None, event=None):
    """event: the hook event the command names (OpenCode's plugin does), or None."""
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness.endswith(";"):   # Qwen Code before 0.15.0 runs the Windows command under cmd.exe, which hands PowerShell's
        harness, event = harness[:-1], None   # tail (_command) to the hook as arguments: `qwen;`, then the tail's words
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
        closed = event in PRE or (harness == "gptme" and pre) or isinstance(e, RecursionError) or H.fail_closed()
        print(f"[tracekit] {harness} hook error ({e}); "
              + ("allowing (fail-open)" if not closed else "blocking" if pre else "event not recorded"), file=sys.stderr)
        _reply(harness, sys.stdout, not closed, str(e), pre)
        return _exit(harness, 2 if closed else 0, pre)


if __name__ == "__main__":
    sys.exit(entry(*sys.argv[1:3]))
