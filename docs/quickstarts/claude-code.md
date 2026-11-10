# Quickstart: Claude Code

Every tool call Claude Code makes is decided by the v2 signer before it runs and recorded after, as a signed event.
This page sets it up on your own machine with the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)). No API key: Claude Code uses its own sign-in.

## 1. Install and wire the hooks

```sh
pip install tracekit-ai          # or pipx install tracekit-ai, uv tool install tracekit-ai
tracekit init --dev --v2
```

Init adds Tracekit's hooks to Claude Code's user settings (`~/.claude/settings.json`, or the `settings.json` in
`$CLAUDE_CONFIG_DIR`) and leaves your other settings and hooks alone. `--project` writes them to
`./.claude/settings.json` instead. The hooks run the Python you ran init with. Init also turns on Claude Code's
thinking summaries (`showThinkingSummaries`) unless your settings set them, so `tracekit analyze --v2` can read the
model's reasoning; `--no-thinking-summaries` leaves the setting alone.

You don't start a signer: the first hook starts the dev signer in the background (`tracekit up` and `tracekit down`
do it by hand). `tracekit doctor` checks the setup and ends with `dev setup OK` when everything checks out.

The [Claude Code plugin](../../plugin/README.md) is the other way in: the same hooks, from the plugin instead of
init's entries in your settings. Use one, not both: with the plugin enabled, init installs no hooks and says so.

## 2. Start a new Claude Code session

Hooks are read when a session starts, so a session that was already open records nothing: start a new one. From then
on each tool call is decided before it runs: most are allowed, some are denied, and some are held for you.

A denied call never runs, and Claude sees why:

```text
[tracekit] BLOCKED, nothing ran, and no one can approve it (TK-D001, TK-D004, TK-F003).
Why: privilege escalation; recursive delete of root or home
Instead: Run the command as the agent's own user, without sudo; ...
```

A held call doesn't run either, until you approve it. Claude Code shows the hold in the session:

```text
[tracekit] HELD, nothing ran: apr-6f0c… (TK-SHELL-PARSE), expires 14:26 UTC.
Why: a quote on the line is never closed
Instead: Close the quote.
Person: look with `! tracekit approvals show apr-6f0c…`; allow once with `! tracekit approvals approve apr-6f0c…`; refuse with `! tracekit approvals reject apr-6f0c…`.
Agent: tell the person what this call was for and pass on these commands, then wait for their answer; ...
```

## 3. Answer it

Paste the `! tracekit approvals approve <id>` line into the session before the hold expires, an hour after it was
held. A line that starts with `!` runs as your own user, not as a tool call of Claude's, so it is your answer. Then ask
Claude to make the same call again: the retry, with exactly the same arguments, runs once. `! tracekit approvals reject
<id>` refuses it. `tracekit approvals show <id>` prints why it was held and the signer's copy of the arguments; from
another terminal, run the same commands without the `!`. `tracekit approvals list` (or `tracekit pending`) lists every
held call.

Claude itself can't approve its own calls: the policy denies a `tracekit approvals approve` that the agent runs
(`TK-D012`). In dev mode the signer can't tell you from your agent, so your approval is recorded as a self-approval and
the run's assurance stays `dev`.

To have Claude follow the hold message every time, paste [these
lines](https://github.com/Cygnux-Labs/Tracekit/blob/main/plugin/skills/tracekit-holds/SKILL.md) into your
`CLAUDE.md` (the plugin ships them as a skill).

## 4. See what it did

```sh
tracekit last          # the most recent finished run: exported, its key pinned, verified
tracekit last --open   # the session still open, verified up to its last checkpointed record
tracekit view --dev    # every run in the browser, replayed and reviewed
```

A session's run stays open until the session ends (`/exit`), so until then `tracekit last` says it is still open and
shows the session before it. In your first session there is none before it: use `tracekit last --open`, or end the
session first. `tracekit last` prints `VERIFIED` and writes the bundle and its trust config to the current directory
(`-o` picks the path); [the v2 quickstart](../quickstart-v2.md#3-see-it-verified) explains each line. `tracekit status`
shows where the hooks and the signer are.

## Remove it

```sh
tracekit uninstall
```

It removes Tracekit's hooks from Claude Code's settings and keeps your other settings; a settings file init made
that holds nothing else is deleted. It then lists what it kept, the dev signer's keys and signed runs and Tracekit's
client config, with the commands that delete them and Tracekit too (`tracekit down`, `rm -rf …`, `pip uninstall
tracekit-ai`). A bundle you exported verifies without them.

## Next steps

- **Other coding agents**: Codex, Cursor, Gemini CLI, OpenCode and others take `--agent NAME`
  ([coding agents](../coding-agents.md)).
- **System mode** runs the signer as its own OS user, so Claude Code can't reach its keys or answer its own holds:
  [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Wait for the answer instead**: with `TRACEKIT_APPROVAL_WAIT` set (seconds, up to about 480), a held call's hook
  waits for an answer from Slack, the viewer or an agent approver before it blocks the call
  ([held calls](../coding-agents.md#held-calls-approve-then-retry)).
