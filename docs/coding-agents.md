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

The hooks run `python -I -m tracekit.integrations.harness_hooks <agent> <event>`: the same mapping as above, then the
v2 Claude Code hook's core (the signer decides; approvals; the run's fail mode, closed by default and always closed in
system mode). Unlike v1, a payload without a session or tool call id blocks the call, and so does any hook error.

### Hooks name their event (1.2)

`tracekit init` writes each hook command with the event it's configured for as its last argument (the Claude Code
hook: `... -m tracekit.integrations.claude_code PreToolUse`; Codex `PreToolUse`, Cursor `preToolUse`, Gemini CLI
`BeforeTool`, and so on for every event). So a payload that can't be parsed at all is still known to be a pre-tool
event: the call is blocked, with the reason on stderr. On any other event it is reported on stderr and not recorded;
an allowed call whose post-tool payload was lost is completed as an error at the session's next Stop, prompt or end
(below).

Hooks installed before 1.2 have no event argument and keep working as before: an unparseable payload passes,
unrecorded. `tracekit doctor` warns `D-HOOKS-EVENT` for Claude Code's; for Codex, Cursor and Gemini CLI it doesn't
check, so re-run `tracekit init --agent NAME` after upgrading.

### What the signer records as a gap (1.2)

Without anything else installed, the signer turns what it saw and then never heard about into signed gaps
([format](format-v2.md#3-events), [limits](limits.md#signer-and-capture)):

- a call the policy allowed, or whose approval was consumed, and that never completed (`decided_not_completed`, at the
  end of the run). A call you decline in the harness's own permission prompt runs no post-call hook, nor does one you
  interrupt: the hook completes such calls as errors ("no PostToolUse came") when the session ends, so they get no
  gap (a session that never ends, such as a killed harness, leaves them as gaps);
- with harness binding (Linux system mode), a second run started from inside the same harness process while another
  session's run is open there, once both have recorded events since (`concurrent_run`; an older session left open and
  idle gets none). Two harness windows side by side are separate processes and get none. A sub-agent's run started
  with `parent` from a bound harness process is a `run.child` record in its parent;
- in system mode, a transcript tailer that stops calling the signer while the run is open, killed, crashed or never
  started, from the moment the hook took its token (`tailer_lost`), and a second tailer token for the same run
  (`tailer_redelegated`);
- writes after the run ended (`late_activity`, in a run-set), apart from each client's first one, from which it learns
  that the run ended (an idle close) and moves to a new run.
