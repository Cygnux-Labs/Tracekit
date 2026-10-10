# Coding agents other than Claude Code

```bash
tracekit init --dev --agent codex      # ~/.codex/hooks.json
tracekit init --dev --agent cursor     # ~/.cursor/hooks.json
tracekit init --dev --agent gemini     # ~/.gemini/settings.json
# --project writes the project-level file (.codex/, .cursor/, .gemini/) instead; tracekit uninstall --agent X removes it
tracekit demo --agent codex            # the scripted demo, sent as Codex's own hook payloads (also cursor, gemini)
```

The installer merges into existing files: other hooks and settings are kept, a backup is written first, and running it
twice changes nothing. Every hook calls `python -I -m tracekit.agent_hooks <agent>`, which translates the harness's payload
into the Claude Code hook shape and runs the same pipeline as the Claude Code hook.

| | Codex CLI | Cursor | Gemini CLI |
|---|---|---|---|
| Hook events used | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | preToolUse, postToolUse, postToolUseFailure, beforeSubmitPrompt, sessionStart, sessionEnd | BeforeTool, AfterTool, BeforeAgent, SessionStart, SessionEnd |
| Run id | `session_id` | `conversation_id` | `session_id` |
| Blocking a call | exit 2 + `permissionDecision: deny` | exit 2 + `{"permission": "deny"}` | exit 2 + `{"decision": "deny"}` |
| Tool call ids | from the harness | from the harness | none: paired by tool and arguments, first in first out |
| Tool names | `Bash`; `write_stdin` → `Bash` (`command` = the typed `chars`); `apply_patch` → `Edit` (`paths`: every file the patch adds, updates, deletes or moves to); MCP as `mcp__server__tool` | `Shell` → `Bash`; `Read`, `Write`, `Grep`, `Delete`; `MCP:x` → `mcp__cursor__x` | `run_shell_command` → `Bash`; `read_file` → `Read`; `write_file` → `Write`; `replace` → `Edit`; `glob`, `search_file_content`, `web_fetch`, `google_web_search` |

What is the same as Claude Code: the policy gate runs before the tool (deny blocks; ask holds the call until someone
approves it from another terminal), events are signed by the same signer, and the harness's transcript is hashed at
every hook when the harness passes `transcript_path`, so edits and truncation are detected.

What is different: reasoning capture reads Claude Code's transcript format and is off for these harnesses; the model
proxy fronts the Anthropic API only, so model-side cross-checks need `tracekit_sdk.init()` or OpenTelemetry instead.
Hook formats come from each harness's published documentation (October 2026); a harness that changes its payload may
need an update here.

Broken input never blocks an agent: an unparseable payload or an unknown harness name is reported on stderr and the
call is allowed, unless `TRACEKIT_FAIL_CLOSED=1` or the policy says `fail_mode: closed`.

## On the v2 signer

```bash
tracekit init --dev --v2 --agent codex                   # or cursor, gemini; replaces a v1 hook
sudo tracekit init --v2 --user AGENT --agent codex       # system mode: the signer as its own user
```

The hooks run `python -I -m tracekit.integrations.harness_hooks <agent>`: the same mapping as above, then the v2 Claude
Code hook's core (the signer decides; approvals; the run's fail mode, closed by default and always closed in system
mode). Unlike v1, a payload without a session or tool call id blocks the call, and so does any hook error.
