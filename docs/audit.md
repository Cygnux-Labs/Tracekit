# `tracekit audit`

`tracekit audit` is a read-only command that replays the tool calls found in local coding-agent transcripts through the policy engine and reports what the current policy would have held or denied.

It does not start a signer, does not write anything, and does not make network calls. It is a replay against today's policy, not a signed record. Tracekit never recorded these calls, so nothing here is evidence.

It is experimental ([support](support.md)): it works and is tested, but may change.

## Usage

```
tracekit audit [ROOT] [--policy PATH] [--since 7d] [--show] [--all] [--json]
```

```
$ tracekit audit --since 7d --show
a replay against today's policy, not a signed record
policy: …/tracekit/policy2/packs/dev.yaml (sha256:…)

1204 tool calls in 31 sessions since 7d: Tracekit would have denied 2 and held 9 for a person; it would have flagged 57 and allowed 1136.
…
by rule:
  TK-F003: 41  (destructive)
  TK-A002: 3  (deleting a remote Git ref)
  TK-D004: 1  (recursive delete of root or home)
…
denied and held calls (--all for every call):
  4f1c…  2026-10-28T14:02:11+00:00  Bash  deny  rules=TK-D004,TK-F003  text='Bash rm -rf ~/'
```

(The numbers above are an example, not a measurement.)

- `ROOT` defaults to `~/.claude/projects`; a folder that doesn't exist is an error (exit 2).
- `--policy` selects a policy file (default: the dev pack, `tracekit/policy2/packs/dev.yaml`).
- `--since` limits the replay (e.g. `7d`, `24h`, `30m`, or an ISO-8601 time, UTC unless it gives an offset); a call
  without a timestamp is kept.
- `--show` includes each call as an approver sees it: its secrets redacted as the signer redacts them (`.env` content
  too), cut to 72 characters.
- `--all` lists every call; without it, only the calls Tracekit would have denied or held for a person.
- `--json` emits a machine-readable report, with every call.

The report always begins with the disclaimer: "a replay against today's policy, not a signed record".

## What it reads

Every `.jsonl` file under ROOT, at any depth: each Claude Code session's transcript and its subagents' files (each
file's session is its name). Each line is a JSON object; assistant messages may contain `tool_use` blocks. The reader
reuses `tracekit.hook.transcript_entries` and the policy engine from `tracekit.policy2.engine`.

It follows no symlink. Files and folders it can't read are counted and skipped, and so is a line that isn't JSON.

## Output

- One line first: how many calls in how many sessions, and how many Tracekit would have denied, held, flagged and
  allowed.
- Counts per verdict (`deny`, `ask` / held, `flag`, `allow`). A call the policy engine fails on counts as a deny
  (`TK-ENGINE-ERROR`), as the signer would decide it.
- Counts per rule id, most first, each with what the rule is (its `reason` or `label`, or the viewer's words for the
  engine's own rules).
- The session and timestamp of each denied or held call (every call with `--all`), and its redacted text with
  `--show`.

## Limitations

It sees only the tool calls the transcript holds, decided by today's policy. A transcript the agent could edit is not evidence. See [limits](limits.md#audit-tracekit-audit).
