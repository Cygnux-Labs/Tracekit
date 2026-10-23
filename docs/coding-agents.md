# Coding agents other than Claude Code

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

```bash
tracekit init --dev --agent codex      # ~/.codex/hooks.json
tracekit init --dev --agent cursor     # ~/.cursor/hooks.json
tracekit init --dev --agent gemini     # ~/.gemini/settings.json
tracekit init --dev --agent opencode   # ~/.config/opencode/plugins/tracekit.js
# --project writes the project-level file instead; tracekit uninstall --agent X removes it
tracekit demo --agent codex            # the scripted demo, sent as Codex's own hook payloads (also cursor, gemini)
```

For Codex, Cursor and Gemini CLI the installer merges into existing settings: other hooks and settings are kept, a
backup is written first, and running it twice changes nothing. For OpenCode it writes its own `tracekit.js` local
plugin and refuses to overwrite a file it did not install. Every hook calls `python -I -m tracekit.agent_hooks
<agent>`, which translates the harness's payload into the Claude Code hook shape and runs the same pipeline as the
Claude Code hook.

| | Codex CLI | Cursor | Gemini CLI | OpenCode |
|---|---|---|---|---|
| Hook events used | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | preToolUse, postToolUse, postToolUseFailure, beforeSubmitPrompt, sessionStart, sessionEnd | BeforeTool, AfterTool, BeforeAgent, SessionStart, SessionEnd | tool.execute.before, tool.execute.after |
| Run id | `session_id` | `conversation_id` | `session_id` | `sessionID` |
| Blocking a call | exit 2 + a reason on stderr (and `permissionDecision: deny`); on Windows exit 0 + the JSON deny, since PowerShell turns 2 into 1 and Codex reads the JSON only at 0 | exit 2 + `{"permission": "deny"}` | exit 2 + `{"decision": "deny"}` | the plugin throws before execution when Tracekit exits 2 |
| Tool call ids | from the harness | from the harness | none: paired by tool and arguments, first in first out | `callID` |
| Tool names | `Bash`; `write_stdin` → `Bash` (`command` = the typed `chars`); `apply_patch` → `Edit` (`paths`: every file the patch adds, updates, deletes or moves to); MCP as `mcp__server__tool` | `Shell` → `Bash`; `Read`, `Write`, `Grep`, `Delete`; `MCP:x` → `mcp__cursor__x` | `run_shell_command` → `Bash`; `read_file` → `Read`; `write_file` → `Write`; `replace` → `Edit`; `glob`, `search_file_content`, `web_fetch`, `google_web_search` | `bash` → `Bash`; `read`, `write`, `edit`, `apply_patch`, `glob`, `grep`, `list`, `webfetch`, `websearch`, `task` |

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
tracekit init --dev --v2 --agent codex                   # or cursor, gemini, opencode; replaces a v1 hook
sudo tracekit init --v2 --user AGENT --agent codex       # system mode: the signer as its own user
```

The hooks run `python -I -m tracekit.integrations.harness_hooks <agent> <event>`: the same mapping as above, then the
v2 Claude Code hook's core (the signer decides; approvals; the run's fail mode, closed by default and always closed in
system mode). Unlike v1, a payload without a session or tool call id blocks the call, and so does any hook error.
On any other event (a prompt, a tool result, a session event) a hook that fails exits 1, not 2, which
would block a prompt, and the event isn't recorded.

A session is one run, open until the session ends. To watch it, `tracekit view --dev` (each call with what it ran);
to verify it as it stands, `tracekit last --open`.

### What was asked and said

For Claude Code, the transcript tailer records every line the model writes (thinking, text, tool use) and every prompt
as a model exchange: a commitment to the whole line, and the line itself when the signer keeps content (the dev signer
does). `tracekit init --v2` also sets `"showThinkingSummaries": true` in the Claude Code settings it writes the hooks
to, or with the plugin enabled in the user's settings (unless they set it; `--no-thinking-summaries` leaves it alone;
`tracekit uninstall` removes it again while it's still `true`): without it Claude Code keeps the model's thinking
only sealed. For headless runs pass `claude -p --thinking-display summarized`. `tracekit analyze --v2`
([findings](findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)) and `tracekit view --dev` read
them. **Codex, Gemini CLI and Cursor:** each v2 hook first records what the model said since the session's last hook:
Codex's reasoning summaries (and the sealed `encrypted_content`), messages and tool calls from its rollout file, linked
to the calls by `call_id`; Gemini CLI's thought summaries and text from its chat recording; Cursor's thinking and
response text from its `afterAgentThought` and `afterAgentResponse` hooks (init installs them). Gemini CLI and Cursor
give a call no id, so their text is not linked to a call, and Gemini CLI writes its thoughts after the calls ran.
`tracekit init --v2 --agent codex` also sets `model_reasoning_summary = "auto"` as the first line of Codex's
`config.toml` (unless it sets one; `--no-thinking-summaries` leaves it alone; `tracekit uninstall --agent codex` removes
the line while it's unchanged): Codex's current models default to `none`, which keeps the
reasoning sealed. Per agent, what is readable and how to turn it on: [reasoning](reasoning.md). A session's later run
(after the signer closed an idle one, or a resumed session) records from where the earlier run left off, not from the
transcript's start: the hook notes how far the transcript was written while that run was open
([limits](limits.md#signer-and-capture)).

At each prompt (`UserPromptSubmit`; Cursor's `beforeSubmitPrompt`, Gemini CLI's `BeforeAgent`) the hook also records
the prompt as the harness handed it over (`input.observed`, source `<agent>:UserPromptSubmit`: `claude-code`, `codex`,
`cursor` or `gemini-cli`; its text in the content vault). `tracekit analyze --v2` takes a prompt line of the transcript as the person's only when the hook
recorded the same text: a line the agent appended to its own transcript is flagged (TK-X208) and clears nothing. A
paste or an image Claude Code writes as a placeholder (`[Pasted text #1 +40 lines]`) pairs with the hook's prompt that
holds the rest of the line, whose full text is read; a hook prompt with no line (one the tailer missed) is read on its
own. Hooks before this release record no prompt, and TK-X208 says `no_hook`.

The hook also sends what the prompt says not to do ("don't touch billing.py", "read-only", "don't push", "no network")
to the signer as [live constraints](policy-v2.md#live-constraints): a later call that breaks one waits for your
approval, and the agent reads why on stderr: `[tracekit] waiting for approval apr-…
(TK-CONSTRAINT): the person's request in this run said not to modify billing.py; ask the person (TK-CONSTRAINT)`. Answer it from another terminal as any
held call: `tracekit approvals list`, then `tracekit approvals approve <id>` (or `reject`). `tracekit view --dev` lists
the run's constraints at the top of its review. The grammar reads instructions, not descriptions: "add a read-only mode
to client.py", "don't change the public API of client.py, just fix the timeout bug in it", "don't push to main" and
"we don't use the network in unit tests" hold nothing. If a run already has the most file constraints the signer
takes (32: an agent can add its own), a further one is refused, the hook says so at that prompt, and every write of the
run waits for your approval from then on. A scope ("only change src/pager.py") is never held: `tracekit analyze --v2`
checks it after the run (TK-X204).

### Hooks name their event

`tracekit init` writes each hook command with the event it's configured for as its last argument (the Claude Code
hook: `... -m tracekit.integrations.claude_code PreToolUse`; Codex `PreToolUse`, Cursor `preToolUse`, Gemini CLI
`BeforeTool`, and so on for every event). So a payload that can't be parsed at all is still known to be a pre-tool
event: the call is blocked, with the reason on stderr. On any other event it is reported on stderr and not recorded;
an allowed call whose post-tool payload was lost is completed as an error at the session's next Stop, prompt or end
(below).

Hooks installed before 1.2 have no event argument and keep working as before: an unparseable payload passes,
unrecorded. `tracekit doctor` warns `D-HOOKS-EVENT` for Claude Code's; for Codex, Cursor and Gemini CLI it doesn't
check, so re-run `tracekit init --agent NAME` after upgrading.

### What the signer records as a gap

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

The LLM gateway's verified tool results (signer.yaml `verify_tool_results`) can't be used with the Claude Code hooks: they record a digest of each tool's raw output, not what the model is sent, so every result would mismatch ([gateway](gateway.md#verified-tool-results)).
