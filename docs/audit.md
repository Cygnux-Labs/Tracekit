# `tracekit audit`

`tracekit audit` is a read-only command that replays the tool calls found in local coding-agent transcripts through the policy engine and reports what the current policy would have held or denied.

It does not start a signer, does not write anything, and does not make network calls. It is a replay against today's policy, not a signed record. Tracekit never recorded these calls, so nothing here is evidence.

It is experimental ([support](support.md)): it works and is tested, but may change.

## Usage

```
tracekit audit [ROOT] [--policy PATH] [--since 7d] [--show] [--json]
```

- `ROOT` defaults to `~/.claude/projects`; a folder that doesn't exist is an error (exit 2).
- `--policy` selects a policy file (default: the dev pack, `tracekit/policy2/packs/dev.yaml`).
- `--since` limits the replay (e.g. `7d`, `24h`, `30m`, or an ISO-8601 time, UTC unless it gives an offset); a call
  without a timestamp is kept.
- `--show` includes each call as an approver sees it: its secrets redacted as the signer redacts them (`.env` content
  too), cut to 72 characters.
- `--json` emits a machine-readable report.

The report always begins with the disclaimer: "a replay against today's policy, not a signed record".

## What it reads

Every `.jsonl` file under ROOT, at any depth: each Claude Code session's transcript and its subagents' files (each
file's session is its name). Each line is a JSON object; assistant messages may contain `tool_use` blocks. The reader
reuses `tracekit.hook.transcript_entries` and the policy engine from `tracekit.policy2.engine`.

It follows no symlink. Files and folders it can't read are counted and skipped, and so is a line that isn't JSON.

## Output

- Counts per verdict (`deny`, `ask` / held, `flag`, `allow`). A call the policy engine fails on counts as a deny
  (`TK-ENGINE-ERROR`), as the signer would decide it.
- Counts per rule id.
- Session and timestamp of each call.
- Optional redacted text (`--show`).

## Limitations

It sees only the tool calls the transcript holds, decided by today's policy. A transcript the agent could edit is not evidence. See [limits](limits.md#audit-tracekit-audit).
