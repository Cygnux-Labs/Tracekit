# `tracekit audit`

`tracekit audit` is a read-only command that replays the tool calls found in local coding-agent transcripts through the policy engine and reports what the current policy would have held or denied.

It does not start a signer, does not write anything, and does not make network calls. It is a replay against today's policy, not a signed record. Tracekit never recorded these calls, so nothing here is evidence.

## Usage

```
tracekit audit [ROOT] [--policy PATH] [--since 7d] [--show] [--json]
```

- `ROOT` defaults to `~/.claude/projects`.
- `--policy` selects a policy pack (default: the development pack).
- `--since` limits the replay (e.g. `7d`, `24h`, or an ISO-8601 timestamp).
- `--show` includes the scrubbed command text.
- `--json` emits a machine-readable report.

The report always begins with the disclaimer: "a replay against today's policy, not a signed record".

## What it reads

Claude Code transcripts (`~/.claude/projects/*/*.jsonl`). Each line is a JSON object; assistant messages may contain `tool_use` blocks. The reader reuses `tracekit.hook.transcript_entries` and the policy engine from `tracekit.policy2.engine`.

Unreadable files are counted and skipped. Symlinks that leave the transcript folders are not followed.

## Output

- Counts per verdict (`deny`, `ask` / held, `flag`, `allow`).
- Counts per rule id.
- Session and timestamp of each call.
- Optional scrubbed text (`--show`).

## Limitations

A transcript the agent could edit is not evidence. See the corresponding row in [limits.md](limits.md).
