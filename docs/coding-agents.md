# Coding agents other than Claude Code

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

```bash
tracekit init --dev --v2 --agent codex      # ~/.codex/hooks.json ($CODEX_HOME/hooks.json when it is set)
tracekit init --dev --v2 --agent cursor     # ~/.cursor/hooks.json
tracekit init --dev --v2 --agent gemini     # ~/.gemini/settings.json
tracekit init --dev --v2 --agent qwen       # ~/.qwen/settings.json
tracekit init --dev --v2 --agent droid      # ~/.factory/hooks.json
tracekit init --dev --v2 --agent opencode   # $XDG_CONFIG_HOME (or ~/.config)/opencode/plugin/tracekit.js; system mode: the agent's ~/.config
tracekit init --dev --v2 --agent goose      # ~/.agents/plugins/tracekit/hooks/hooks.json (plus plugin.json beside it)
tracekit init --dev --v2 --agent antigravity   # ~/.gemini/config/hooks.json (see Antigravity CLI below)
# --project writes the project-level file instead; tracekit uninstall --agent X removes Tracekit's hooks and keeps your other settings
sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT --agent codex   # system mode: the signer as its own user
```

These hooks record to the v2 signer ([below](#on-the-v2-signer)), and a v2 hook replaces a v1 one. System mode's init
runs as root from a root-owned Python and puts no `tracekit` command on root's `PATH`. It writes these agents' hooks
into the agent user's own config, which that user can edit: `--managed` (hooks in admin-managed settings the agent can't
edit or turn off) is for Claude Code only, and init refuses it with these agents
([limits](limits.md#dev-mode-vs-system-mode)). The system-mode line is for Python
3.11 or later, after [laptop system mode](deploy.md#laptop-system-mode)'s install; that page also gives the commands for
3.9 and 3.10. The v1 hooks, for the older laptop path (the `tracekitd` signer), are the same dev commands without
`--v2` and write the same files:

```bash
tracekit init --dev --agent codex      # v1; or cursor, gemini, qwen, droid, opencode, goose, antigravity
tracekit demo --agent codex            # the scripted v1 demo, sent as Codex's own hook payloads (also cursor, gemini, opencode, goose)
```

**Codex runs these hooks only once you trust them.** Codex skips a hook that isn't managed until a person has reviewed
and trusted it, and says nothing when it does: until then no Codex call is recorded or decided. After init, run `codex`
in a terminal, type `/hooks`, and trust Tracekit's hooks; Codex asks again whenever they change, as after another
init. Codex keeps that trust in your `~/.codex/config.toml` (`$CODEX_HOME/config.toml` when it is set; then init
writes the hooks there too, and you run Codex with the same `CODEX_HOME`) as
`[hooks.state."<hooks.json path>:<event>:<group>:<handler>"]` with a `trusted_hash`
([Codex hooks](https://learn.chatgpt.com/docs/hooks)). Init ends by saying so, v1 and v2, and `tracekit doctor` checks
that each of Tracekit's Codex hooks, v1 or v2, is trusted and not turned off (`D-CODEX-HOOK-TRUST`); it can't
recompute Codex's hash, and with Python 3.9 or 3.10 it can't read the file, so it says it can't confirm
([limits](limits.md#signer-and-capture)).

For Codex, Cursor, Gemini CLI and Qwen Code the installer merges into existing settings: other hooks and settings are kept, a
backup is written first, and running it twice changes nothing. For Droid it writes a standalone `.factory/hooks.json`; if
the legacy `.factory/hooks/hooks.json` exists, init refuses to proceed until you save once in Droid's `/hooks` UI to migrate
it. For OpenCode it writes its own `tracekit.js` local
plugin and refuses to overwrite a file it did not install (in `plugin/`, which every OpenCode 1.x loads; 1.0 doesn't
read `plugins/`). For goose it writes its own plugin directory (`plugin.json` plus `hooks/hooks.json`) and refuses
to install into a plugin whose `plugin.json` is not Tracekit's. A goose rule carries no matcher (goose silently skips
a rule whose matcher is a bare `*`, which is an invalid regex); the PreToolUse action carries `timeout: 600` and
`on_failure: block`, the post-tool actions `timeout: 30`. For Antigravity CLI it adds a hook named `tracekit` to agy's `hooks.json` ([below](#antigravity-cli)). Every v1 hook calls `python -I -m tracekit.agent_hooks <agent>` (OpenCode's plugin and Antigravity CLI's commands add the event),
which translates the harness's payload into the Claude Code hook shape and runs the same pipeline as the Claude Code
hook ([v2 hooks](#on-the-v2-signer)).

| | Codex CLI | Cursor | Gemini CLI | OpenCode | goose | Qwen Code | Factory Droid |
|---|---|---|---|---|---|---|---|
| Hook events used | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | preToolUse, postToolUse, postToolUseFailure, beforeSubmitPrompt, sessionStart, sessionEnd | BeforeTool, AfterTool, BeforeAgent, SessionStart, SessionEnd | tool.execute.before, tool.execute.after | PreToolUse, PostToolUse, PostToolUseFailure | PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd |
| Run id | `session_id` | `conversation_id` | `session_id` | `sessionID` | `session_id` | `session_id` | `session_id` |
| Blocking a call | exit 2 + a reason on stderr (and `permissionDecision: deny`); on Windows exit 0 + the JSON deny, since PowerShell turns 2 into 1 and Codex reads the JSON only at 0 | exit 2 + `{"permission": "deny"}` | exit 2 + `{"decision": "deny"}` | the plugin throws before the tool runs when Tracekit blocks the call (exit 2) or the hook can't decide it (any other exit, or Python can't start) | exit 2 + a reason on stderr, stdout empty (a stray stdout line reads as no decision to goose) | exit 2 + a reason on stderr (Qwen Code ignores stdout at exit 2 and sends stderr to the model); nothing on stdout | exit 2 + a reason on stderr and `hookSpecificOutput.permissionDecision: "deny"` |
| Tool call ids | from the harness | from the harness | none: paired by tool and arguments, first in first out | `callID` | `tool_call_id`, from the harness | `tool_use_id`, from the harness | none in documented stdin: paired by tool and arguments, first in first out |
| Tool names | `Bash`; `write_stdin` → `Bash` (`command` = the typed `chars`); `apply_patch` → `Edit` (`paths`: every file the patch adds, updates, deletes or moves to, its file headers read as Codex reads them, indented ones too); `apply_patch` run from the shell stays a `Bash` call, which the v2 coding pack holds for a person (`TK-A034`); MCP as `mcp__server__tool` | `Shell` → `Bash`; `Read`, `Write`, `Grep`; `Delete` → `Edit`, so the file rules read it; `MCP:x` → `mcp__cursor__x` | `run_shell_command` → `Bash`; `read_file` and `read_many_files` → `Read`; `write_file` → `Write`; `replace` → `Edit`; `glob`, `search_file_content`, `list_directory`, `web_fetch`, `google_web_search`; every path a file tool reads is decided, under each release's name for it (`file_path`, `absolute_path`, `dir_path`, `path`, and `read_many_files`' `paths` and `include`); `web_fetch` is decided on every URL its prompt names (`urls`) and on a `url` beside it | `bash` → `Bash`; `read`, `write`, `edit` (path: `filePath`); `apply_patch` (and 1.0's `patch`) → `Edit` (`paths`: every file its headers name, and a path with a `:` also up to it, as OpenCode 1.2 reads it); `batch` (experimental; OpenCode 1.x before 1.4 only: later releases and OpenCode 2 have none) is blocked: OpenCode runs the calls in it without plugin hooks; `glob`, `grep` (path: `path`); `webfetch`, `websearch`, `task`; MCP tools under OpenCode's `<server>_<tool>` names, which the policy treats as unknown tools | `shell` → `Bash`; `write` → `Write` (path: `path`); `edit` → `Edit` (path: `path`); `tree` → `LS` (path: `path`); `read_image` → `Read` (path: `source`, not `path`); `<extension>__<tool>` → `mcp__<extension>__<tool>`; other names pass through unchanged, which the policy treats as unknown tools | `run_shell_command` and `monitor` → `Bash`; `read_file` → `Read` (path: `file_path`, `absolute_path` before 0.13); `write_file` → `Write`; `edit` (and Gemini's `replace`) → `Edit`; `notebook_edit` → `NotebookEdit` (path: `notebook_path`); `grep_search` → `Grep`; `glob`, `list_directory`, `web_fetch`, `web_search`, `todo_write`; `agent` → `Task`; any other tool, MCP tools included, under its own name; file paths as for Gemini CLI; `web_fetch` is decided on its `url` and also on every URL its prompt names (Qwen Code fetches only the `url`) | `Execute` → `Bash`; `Create` → `Write`; `ApplyPatch` → `Edit` (`input`: complete patch; `paths`: all file headers); `FetchUrl` → `WebFetch`; other names, including `mcp__server__tool`, pass through |

What is the same as Claude Code: the policy gate runs before the tool (deny blocks; ask blocks the call until someone
approves it from another terminal, then the agent's retry runs: [held calls](#held-calls-approve-then-retry)), events
are signed by the same signer, and the harness's transcript is hashed at every hook when the harness passes
`transcript_path`, so edits and truncation are detected.

What is different: reasoning capture reads Claude Code's transcript format and is off for these harnesses; the model
proxy fronts the Anthropic API only, so model-side cross-checks need `tracekit_sdk.init()` or OpenTelemetry instead.
Hook formats come from each harness's published documentation (October 2026); a harness that changes its payload may
need an update here. Qwen Code's are from its [hooks documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/):
it sends Claude Code's payloads and event names (with `tool_use_id`), reads exit 2 as a block, takes hook timeouts in
milliseconds (versions since September 2026 in seconds, but 1000 or more still as milliseconds; 60 s unless set; `init` writes 600000, 600 s
either way, for `PreToolUse`, so a person has time to approve a held call), and
runs a project's hooks only in a trusted folder. On Windows it runs hooks under `cmd.exe`, so the interpreter path
stays quoted when it contains spaces, as for Droid.

A call on several files (a patch's `paths`, the files of a Gemini CLI or Qwen Code `read_many_files`) or URLs (a
`web_fetch`'s `urls`) is decided on each: a rule that matches any of them applies.

Droid's [hooks reference](https://docs.factory.com/harness/hooks) documents Claude Code's event names and stdin fields.
Its standalone `hooks.json` is keyed directly by event name, with no `hooks` wrapper (that wrapper is for declarations
inside `settings.json`). When creating it, the installer copies the effective hooks from `settings.json`. If the legacy
`.factory/hooks/hooks.json` exists, init refuses to proceed until you save once in Droid's `/hooks` UI to migrate it.
On Windows Droid
is assumed to run hooks under `cmd.exe`; the interpreter path stays quoted when it contains spaces.
The documented stdin carries no tool-call id. Tracekit pairs its tool events by tool and arguments, first in first out, in a queue separate
from Gemini CLI's. An allowed call with no `PostToolUse` (declined in Droid's permission prompt, blocked by another hook, or failed; Droid has no `PostToolUseFailure`) stays queued, so the next identical call's result can be paired to it and the call that ran closes as an error at session end. The pre-tool timeout is 600 seconds so a person can answer a held call. Factory CLI 0.249.0's
`droid exec --list-tools --output-format json` describes `Execute` as a shell command and `ApplyPatch` as a complete
patch in `input`; that field and format come from the tool listing, not a captured hook payload. The minimum Droid version is unknown, and it is unknown whether `Task`-started sub-droids fire hooks. Native Windows and live authenticated Droid sessions are untested; its transcript format is
not read for model text or reasoning.

With a v1 hook, an unparseable payload or an unknown harness name is reported on stderr and the call is allowed, unless
`TRACEKIT_FAIL_CLOSED=1` or the policy says `fail_mode: closed`. Three exceptions block the call whatever the fail mode:
an OpenCode call its hook can't decide (the plugin passes the model's arguments before OpenCode checks them), an
Antigravity CLI pre-tool call its hook can't decide (its command names the event), and, in every hook, a payload
nested too deep to read.

## On the v2 signer

The v2 hooks (the commands at the top of this page) run `python -I -m tracekit.integrations.harness_hooks <agent> <event>`: the same mapping as above, then the
v2 Claude Code hook's core (the signer decides; approvals; the run's fail mode, closed by default and always closed in
system mode). Unlike v1, a payload without a session or tool call id blocks the call, and so does any hook error.
On any other event (a prompt, a tool result, a session event) a hook that fails exits 1, not 2, which
would block a prompt, and the event isn't recorded.

OpenCode (1.x) sends no session or prompt events to plugins: its run closes at the signer's idle timeout, and no prompts, live constraints or model text are recorded. A call that fails, that you decline in OpenCode's own permission prompt, or that you abort runs no `tool.execute.after`, so it stays a `decided_not_completed` gap. With `TRACEKIT_APPROVAL_WAIT` set, while a call waits for a person OpenCode waits too: list the held call with `tracekit approvals list` ([limits](limits.md#signer-and-capture)).

goose support is experimental: tested through goose's hook payloads and Tracekit's installer, not yet in a live goose
session. It needs goose 1.48.0 or later (when `on_failure` arrived). goose runs hooks with `sh -c` on every platform,
so on Windows it needs `sh` on PATH (Git Bash); without it every call is blocked. Code Mode (`execute_javascript`,
and `execute_typescript` or `execute_bash` before goose 1.56) is denied: it runs tool calls no goose hook sees.

goose's installed hooks likewise carry no session or prompt events (only PreToolUse, PostToolUse and PostToolUseFailure are installed), so no prompts, live constraints or model text are recorded for goose, and goose sends no tool result or error text with its post-tool events ([limits](limits.md#signer-and-capture)).

A session is one run, open until the session ends. To watch it, `tracekit view --dev` (each call with what it ran);
to verify it as it stands, `tracekit last --open`.

### Held calls: approve, then retry

A call the policy holds (`ask`) is blocked at once, in Claude Code and every harness above, with the approval's id and
the command that approves it, as the harness's block message (in Claude Code also a `systemMessage`, which it shows
you, and the deny reason, which the model reads):

```text
[tracekit] held for approval apr-… (TK-A032): to let it run, approve it with `tracekit approvals approve apr-…`, then ask the agent to try the same call again, with exactly the same arguments (to refuse it: `tracekit approvals reject apr-…`). Why: uploading to cloud storage. Have a person approve the held call, or write the files locally and let a person upload them.
```

Run the command from another terminal, then tell the agent to make the same call again, with exactly the same
arguments: the signer lets that call run under your approval, once ([approve, then retry](approvals.md#approve-then-retry)).
The same call a third time, or one with other arguments, is held again, with a new approval. In Claude Code a Bash
call's arguments include its free-text `description`: a retry that rewords it is another call, held with a new
approval. The agent can't approve its own call: the policy denies the command when the agent runs it (`TK-D012`), and in
system mode the signer refuses its user.

Until 1.5.1 the hook waited 8 minutes for an answer before it blocked the call. No harness shows a hook's output
while the hook runs, so you saw the approval id only once the wait was over, and the call was blocked anyway. Where
someone answers without seeing that message (Slack approvals, the viewer's approval pages, an agent approver, or you
watching `tracekit approvals list`), set `TRACEKIT_APPROVAL_WAIT` (seconds) in the agent's environment, and the hook
waits that long for the answer before it blocks the call, up to about 480 s: it answers within 540 s and keeps two
signer calls' time (60 s) for the answer and the approval's use, so a longer setting waits no longer. Export it before
you start the agent (a hook inherits the harness's environment), or in Claude Code put it in `settings.json`:
`"env": {"TRACEKIT_APPROVAL_WAIT": "480"}`. The hook can't tell whether a bridge or an agent approver will answer, so
this is your setting. What each harness shows while a hook runs, from its documentation or source (October 2026), and
so why none waits by default:

| Harness | While the hook runs | The block's message, once it returns |
|---|---|---|
| Claude Code | a spinner; the hook's output is read when it exits | the deny reason to the model, the `systemMessage` to you |
| Codex CLI | "Running hook" (stderr is read when the hook exits) | to the model, and a "Blocked" cell to you |
| Cursor | not documented (closed source; a Hooks output channel for debugging) | `user_message` to you, `agent_message` to the model |
| Gemini CLI | "Executing Hook: <name>" (stderr is collected and read on exit) | "Tool execution blocked: …" to both |
| Qwen Code | a fixed `statusMessage`, if configured (stderr is read on exit) | to the model, and shown to you |
| OpenCode 1.x | nothing: the plugin runs the hook synchronously | the error the plugin throws |
| goose | nothing (stdout and stderr are read on exit) | to the model |
| Factory Droid | not documented | to Droid (the model) |
| Antigravity CLI | not known to show anything ([#893](https://github.com/google-antigravity/antigravity-cli/issues/893)) | the `reason` of its JSON deny |

### Calls that move money

Stripe holds an agent's refunds, payouts and outbound payments for a person only when the agent uses an agent-tagged
API key ([approval rules](https://docs.stripe.com/account/approvals)); a coding agent with your own key gets no hold.
The v2 coding pack holds these calls for a person whatever the key:

- the Stripe CLI's money commands: `stripe refunds create`, `payouts create`, `transfers create`, `topups create`,
  `transfer_reversals create`, `charges create` or `capture`, `payment_intents create`, `confirm` or `capture`, `invoices pay`, `treasury
  outbound_payments create` or `outbound_transfers create`, and `stripe post` to those endpoints (`TK-A043`);
- a POST to those endpoints on `api.stripe.com`, to PayPal's payouts, captures and refunds on `api-m.paypal.com` or
  `api.paypal.com`, or to Square's payments and refunds on `connect.squareup.com`, through `curl`, `wget`, HTTPie or
  `xh` (`TK-A043`);
- Stripe's MCP money tools, `send_money`, `transfer_money`, `convert_currency` and `create_refund` (`TK-A044`), and its
  `stripe_api_write` tool when the call names a refund or one of those endpoints (`TK-A045`).

The hold says what to check:

```text
[tracekit] held for approval apr-… (TK-A043): to let it run, approve it with `tracekit approvals approve apr-…`, then ask the agent to try the same call again, with exactly the same arguments (to refuse it: `tracekit approvals reject apr-…`). Why: moving money (a Stripe, PayPal or Square charge, payout, transfer or refund). Check the amount, currency and payee in the command or the file it sends before approving it; a refund with no amount refunds in full, and a confirm, capture or pay moves the amount set earlier
```

Read the command before you approve it, and the file it sends (`-d @body.json`): the approval covers that exact
command, so its amount and payee can't change afterwards, but a file's content can. A call with no amount moves what was set earlier: a refund with no amount refunds the whole charge, and a
confirm, capture or invoice pay takes the amount the payment intent or invoice was created with, so look that up
first. A Stripe test-mode call is held too: the command doesn't show whether the key is live. Not held: `stripe
listen`, `stripe trigger`, `stripe logs tail`, `stripe login`, listing, retrieving and cancelling, `stripe refunds
create --help`, a GET (Stripe's documented `curl -G … -d limit=3` list form too), and PayPal's and Square's sandbox
hosts.

Turn on Stripe's approval rules with an agent-tagged key as well: Stripe enforces them on its side, outside anything
the agent runs, and Tracekit adds a signed record of who approved which exact call, for PayPal and Square too. What
these rules don't see (a script that calls a payment SDK, another provider): [limits](limits.md#policy).

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
what the person typed (`input.observed`, trusted, source `<agent>:UserPromptSubmit`: `claude-code`, `codex`, `cursor`,
`gemini-cli`, `qwen-code` or `droid`; its text in the content vault). Text the harness added to the prompt is recorded apart, as untrusted
input under its own source, so a value in it keeps its provenance: in Claude Code a paste block, a skill's body, a
message from another session, agent, teammate, plugin, observer or channel, a task or system notification, a scheduled
task, uploads and command output (`claude-code:paste`, `claude-code:task-notification`, ...); in Gemini CLI its referenced files block
(`gemini-cli:referenced-file`). A whole Claude Code turn its payload says no person typed (a `source` other than `user`
or `sdk`: a plugin's prompt, a notice, a wake-up or a poll event) is recorded that way too (`claude-code:poll_event`,
...), and none of its constraints are live. `tracekit analyze --v2` takes a prompt line of the transcript as the person's only when
the hook recorded the same typed text: a line the agent appended to its own transcript is flagged (TK-X208) and clears nothing. A
paste or an image Claude Code writes as a placeholder (`[Pasted text #1 +40 lines]`) pairs with the hook's prompt that
holds the rest of the line, whose full text is read; a hook prompt with no line (one the tailer missed) is read on its
own. Hooks before this release record no prompt, and TK-X208 says `no_hook`.

The hook also sends what the typed text says not to do ("don't touch billing.py", "read-only", "don't push", "no
network") to the signer as [live constraints](policy-v2.md#live-constraints) (one stated only in text you pasted or the
harness added is recorded but not made live, and Claude Code shows a notice naming it; one typed after a wrapper's name
in a sentence is live, though the text from that name on is recorded as untrusted): a later call that breaks one is
held for your approval ([held calls](#held-calls-approve-then-retry)), and you and the agent read why:

```text
[tracekit] held for approval apr-… (TK-CONSTRAINT): to let it run, approve it with `tracekit approvals approve apr-…`, then ask the agent to try the same call again, with exactly the same arguments (to refuse it: `tracekit approvals reject apr-…`). Why: the person's request in this run said not to modify billing.py; ask the person
```

Answer it from another terminal with the command the line names (`tracekit approvals list` shows every held call), then
ask the agent to make the call again; the agent's own `approve` or `reject` is denied (`TK-D012`). When the hook's signer is a named one (system mode,
`tracekit init --remote --v2` or `TRACEKIT_SIGNER`), the command includes `--signer ADDR`. In system mode, run it from
the approver's account as `/opt/tracekit/bin/python -I -m tracekit approvals …` (init puts no `tracekit` command on the
PATH). On your default signer,
`tracekit approve apr-…` and `tracekit reject apr-…` work too. `tracekit view --dev` lists
the run's constraints at the top of its review. The grammar reads instructions, not descriptions: "add a read-only mode
to client.py", "don't change the public API of client.py, just fix the timeout bug in it", "don't push to main" and
"we don't use the network in unit tests" hold nothing. If a run already has the most file constraints the signer
takes (32: an agent can add its own), a further one is refused, the hook says so at that prompt, and every write of the
run waits for your approval from then on. A scope ("only change src/pager.py") is never held: `tracekit analyze --v2`
checks it after the run (TK-X204).

### Hooks name their event

`tracekit init` writes each hook command with the event it's configured for as its last argument (the Claude Code
hook: `... -m tracekit.integrations.claude_code PreToolUse`; Codex `PreToolUse`, Cursor `preToolUse`, Gemini CLI
`BeforeTool`, goose `PreToolUse`, and so on for every event). So a payload that can't be parsed at all is still known to be a pre-tool
event: the call is blocked, with the reason on stderr. On any other event it is reported on stderr and not recorded;
an allowed call whose post-tool payload was lost is completed as an error at the session's next Stop, prompt or end
(below).

Hooks installed before 1.2 have no event argument and keep working as before: an unparseable payload passes,
unrecorded. `tracekit doctor` warns `D-HOOKS-EVENT` for Claude Code, Codex, Cursor, Gemini CLI, goose, Qwen Code,
Factory Droid and Antigravity CLI when a command doesn't name its configured event or, on any event but the pre-tool
one, blocks that event when the hook can't run (a command init wrote before 1.3, or a Cursor hook written up to 1.4.2), and
`D-HOOKS-TIMEOUT` when a pre-tool timeout is shorter than the 540 s the hook may take to answer (milliseconds for
Gemini CLI and Qwen Code; a held call waits, up to about 480 s, only with `TRACEKIT_APPROVAL_WAIT` set). Re-run init for the active mode to repair the other coding agents' hooks
(`tracekit init --dev --v2 --agent NAME` in dev, or `sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT
--agent NAME` in system mode; with Python 3.9 or 3.10, [laptop system mode](deploy.md#laptop-system-mode)'s command). `tracekit doctor` also checks Droid's and Antigravity CLI's hook presence and timeout, and warns when agy would
load its hooks and run none (`D-AGY-HOOKS-RUN`, [below](#antigravity-cli)). OpenCode's JavaScript plugin isn't checked; re-run init after upgrading.

For the other coding agents (Antigravity CLI too, not OpenCode, whose plugin doctor doesn't read), `D-HOOKS-EVENT` also warns when a call can run that no hook
decided: no Tracekit v2 hook is on the pre-tool event, Cursor's `preToolUse` hook has no `failClosed: true`, or goose's
`PreToolUse` hook has no `on_failure: "block"`. Without those two, Cursor and goose let a call through when its hook
can't run. Re-run init to put them back.

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

## Antigravity CLI

Antigravity CLI (`agy`) support is experimental: tested through agy's documented hook payloads
([hooks reference](https://antigravity.google/docs/hooks)) and Tracekit's installer, not yet in a live agy session
([limits](limits.md#signer-and-capture)). It needs agy 1.3.0 or later (1.2.1 to 1.2.3 ran no hooks on some machines,
[#1008](https://github.com/google-antigravity/antigravity-cli/issues/1008)).

```bash
tracekit init --dev --v2 --agent antigravity               # ~/.gemini/config/hooks.json; --project: .agents/hooks.json
sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT --agent antigravity   # system mode (Python 3.11+)
tracekit uninstall --agent antigravity                     # removes Tracekit's hook only
```

agy's `hooks.json` maps each hook's name to its events. Init adds one named `tracekit`, with a `PreToolUse` hook
(timeout 600 s, so a person has time to approve a held call) and a `PostToolUse` hook (30 s), both with matcher `*`.
Other named hooks in the file are kept, and a backup is written first. Init rewrites Tracekit's hook whole, so an
`"enabled": false` left on it is removed. The v1 hook (`tracekit init --dev --agent antigravity`) works in dev mode
only: v1 system mode installs Claude Code's hooks only, so it refuses `--agent antigravity`. agy runs a hook in the
folder that holds its `hooks.json`; the hook reads the workspace from the payload's `workspacePaths`. The global
`hooks.json` also runs in the Antigravity IDE app
([#1329](https://github.com/google-antigravity/antigravity-cli/issues/1329)), whose calls are then decided and recorded
too, as agent `antigravity`. While a call waits for a person, agy waits too and may show nothing: list the held call
with `tracekit approvals list`.

agy's payload doesn't name its event, so each hook command names it, the v1 one too. agy reads a hook's answer only
from JSON on stdout at exit 0, so Tracekit's hook always exits 0: `{"decision": "allow"}` leaves the call to agy's own
permissions, `{"decision": "deny", "reason": ...}` blocks it, and the post-tool hook answers `{}`. A hook that can't
start (its Python or Tracekit is gone) gives the same answers through a shell wrapper: the pre-tool hook denies the
call, and the post-tool hook answers `{}` (before agy 1.4.7, a post-tool hook that failed replaced the call's result
with an error). On Windows, dev mode has no such wrapper ([limits](limits.md#signer-and-capture)).

**What is recorded.** A conversation (`conversationId`) is one run. Each tool call is decided on the argument the tool
itself reads, so a decoy key the model sends beside it never moves the decision:

| agy tool | Decided as | On |
|---|---|---|
| `run_command` | `Bash` | `CommandLine`; `BypassSandbox` (run outside agy's terminal sandbox) as `dangerouslyDisableSandbox`, which the v2 coding pack holds for a person (`TK-A003`) |
| `manage_task` with `Action: send_input` | `Bash` | `Input`, the text typed into a background command |
| `view_file` | `Read` | `AbsolutePath` |
| `write_to_file` | `Write` | `TargetFile` |
| `replace_file_content`, `multi_replace_file_content` | `Edit` | `TargetFile` |
| `list_dir` | `LS` | `DirectoryPath` |
| `find_by_name` | `Glob` | `SearchDirectory`, `Pattern` |
| `grep_search` | `Grep` | `SearchPath`, `Query` |
| `read_url_content` | `WebFetch` | `Url` |
| `search_web`, `invoke_subagent` | `WebSearch`, `Task` | their arguments as sent |

Any other tool passes under its own name, which the policy treats as an unknown tool. agy gives a call no id: Tracekit
pairs a call's `PreToolUse` and `PostToolUse` by the step index (`stepIdx`), tool and arguments agy sends with both.
On the v2 signer, a pre-tool payload with no `conversationId` or `stepIdx` is blocked. A result that matches no call
exactly stays unpaired, and its call is left a `decided_not_completed` gap, never guessed. agy sends a failed call's
error text with `PostToolUse`, which records the call as failed, but not a call's output. Tracekit installs only agy's
tool hooks and doesn't read its transcript, so no prompts, live constraints or model text are recorded, and the run
closes at the signer's idle timeout.

**Doctor.** `tracekit doctor` finds agy's hooks in the user's and the working directory's `hooks.json` and checks them
as the other agents' (`D-HOOKS-PRESENT`, `D-HOOKS-EVENT`, `D-HOOKS-TIMEOUT` in seconds; a hook with no timeout
counts as agy's default, 30 s). It also warns
`D-AGY-HOOKS-RUN` when agy would load the hooks and never run them: Tracekit's hook is `"enabled": false` (in the file
init wrote, the user's `hooks.json` or the workspace's), or agy signs in with a Gemini API key (`"modelProvider":
"gemini"` in `~/.gemini/antigravity-cli/settings.json`) or with Application Default Credentials (`"enableAdc": true`
under `userSettings` in `~/.gemini/config/config.json`, or `AGY_ADC_AUTH=true`). agy says nothing when it skips the
hooks. Doctor reads `AGY_ADC_AUTH` and the workspace from the shell it runs in, so run it from agy's shell
([doctor](doctor.md#v2-checks)).
