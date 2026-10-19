# nono and Tracekit

> **Experimental:** `tracekit follow` works and is tested, but may change and gets less hardening than the
> [stable core](../support.md).

[nono](https://github.com/nolabs-ai/nono) runs an agent in a kernel sandbox (Landlock and seccomp on Linux, Seatbelt on
macOS), brokers per-tool sandboxes and credentials, and its supervisor writes an audit log of each session. nono limits
what the agent can do. Tracekit proves what it did: `tracekit follow nono` reads nono's log while the session runs and
has Tracekit's signer sign each decision nono logged, as it arrives, in a run of its own.

| | nono | Tracekit |
|---|---|---|
| What it does | Sandboxes the agent; decides each capability request, mediated command, URL open and proxied connection | Signs each of nono's decisions as nono's word, and a gap wherever the stream breaks |
| Where | nono's supervisor, the unsandboxed parent of the agent | A signer outside the agent, called by a follower with its own identity |
| When it's sealed | At the end of the session: nono stores the chain head and Merkle root of the session's events, and with `--audit-sign-key` signs the finished session once ([nono's audit docs](https://github.com/nolabs-ai/nono/blob/main/docs/cli/features/audit.mdx)) | Per decision, when the follower reads it: each record signed, hash-chained and checkpointed, exported as a `.tkb` bundle verified offline |

## How it works

nono's supervisor appends every audit event of a session to
`$XDG_STATE_HOME/nono/audit/<session>/audit-events.ndjson` (default `~/.local/state/nono/audit/`) as it happens, and
flushes it on every mediated decision. Each line carries a `sequence` number and nono's hash chain. `tracekit follow
nono` watches that directory and follows each session's log from its first line. nono's
[audit delivery protocol](https://github.com/nolabs-ai/nono/blob/main/docs/protocols/audit-delivery-v1.md) sends a
session only once it has finished, so Tracekit reads the log instead, which is written while the session runs.

For each line the follower:

1. checks that its `sequence` is the one after the last line's, and asks the signer for a signed gap when it isn't;
2. sends a decision to the signer as a `decision_import`: nono's verdict, what it was about, nono's reason, and the line
   exactly as nono wrote it;
3. closes the run at nono's `session_ended`.

The signer writes each decision as a `policy.external` record (source `import`, tier T3) in a run the follower
registered for the session, naming the follower's identity. The follower reads only nono's log, which nono's
supervisor writes outside the sandbox, and the signer's own policy isn't applied to these records: they record what
nono says it decided, and when Tracekit received it.

## Setup

Give the follower its own identity, one the agent can't present: for example a signer token
([remote callers](../remote-ingest.md)) kept in a file the nono profile doesn't grant. In signer.yaml, list it under
`importers` (its runs are imported runs, which the signer doesn't reconcile and watches for the follower's heartbeats)
and grant it these calls:

```yaml
importers: ["token:nono-follow"]
authorize:
  "token:nono-follow": [register_run, decision_import, tailer_heartbeat, tailer_lost, close_run]
```

Without `importers`, the follower's runs are ordinary runs: the signer reconciles them and flags every imported
decision as a `decision_mismatch`, a call it never decided.

Then run the follower as the user nono runs as (nono's audit directory is that user's), before you start sessions:

```bash
tracekit signer token add nono-follow --config signer.yaml   # once, on the signer's host
TRACEKIT_SIGNER=https://signer.internal:8443 TRACEKIT_SIGNER_TOKEN_FILE=~/.config/tracekit/nono-follow.token \
  tracekit follow nono
nono run --profile nolabs-ai/claude --allow-cwd -- claude   # in another terminal
```

`--root DIR` names another audit directory, and `--quiet S` how long a session may write nothing before Tracekit stops
following it (default 1800 seconds). At start, the follower takes the sessions still running (no `session.json`, which
nono writes when a session finishes, and a log written to within `--quiet` seconds); after that, every new session as
it appears. It prints each session's run id.
Use nono's default supervised mode (`nono run`): direct mode (`nono wrap`) and `--no-audit` write no audit log.

## What Tracekit records

| nono event | Decision | `tool` |
|---|---|---|
| `capability_decision` | `Granted`: allow; `Denied`, `Timeout`: deny | `capability_decision/<capability_type>` |
| `command_policy` | `allowed`, `exec`, `capture…`, `respond`, `approve_granted`, `invocation_allowed`, `invocation_approve_granted`: allow; `denied`, `approve_denied`, `invocation_denied`, `invocation_approve_denied`: deny | `command_policy/<command>` |
| `network` | `allow`, `approve_granted`: allow; `approve_requested`: ask; `deny`, `approve_denied`, `approve_timeout`, `approve_error`: deny | `network` |
| `url_open` | succeeded: allow; failed: deny | `url_open` |
| `session_ended` | closes the run | |
| `session_started`, `sandbox_runtime` | none: their sequence is checked, nothing more is recorded | |

Each decision's `tool_use_id` is `<session>:<sequence>`, so it names the line in nono's log. Its reason is nono's
(for a capability decision, the approval backend and its reason), redacted like any reason. The line itself is kept
only as a salted commitment: given nono's log and the record's salt, which the signer's operator can reveal, anyone
can check that a record is that line ([format v2](../format-v2.md#2-hashes-over-agent-content)).

The signer signs a `capture.gap` (`tailer_lost`) in the session's run, each reason saying where to look, when:

- a `sequence` isn't the one after the last (records missing, repeated or out of order);
- a line isn't a record of nono's log format, or carries an event or decision this follower doesn't map;
- the log is truncated, replaced or removed under the follower;
- nothing new is written for `--quiet` seconds and there's no `session_ended` (nono stopped before it finished the
  session, or the session is idle);
- the follower is stopped (SIGTERM, Ctrl-C) before the session ends;
- the follower is killed: its heartbeats stop, and the signer writes the gap itself after 90 seconds.

The last four end the following of that session. While the signer can't be reached, the follower waits and carries
on from the same line: the log on disk is the queue, and each line is recorded once.

## What Tracekit sees and doesn't

- **Sees:** what nono writes to the session's log, from the follower's first read, signed as it arrives.
- **Doesn't see when it happens:** proxied connections. nono writes `network` events to the log when the session
  ends, so Tracekit signs them then, and doesn't get them at all if nono is stopped first. For connections recorded as
  they happen, route the agent's traffic through Tracekit's [egress observer](../egress.md) as well.
- **Doesn't check:** whether nono logged everything, or nono's hash chain. A record is nono's word, signed when it
  arrived; `nono audit verify` checks nono's own chain.
- **Doesn't record:** the session's start event, the sandbox runtime event, nono's exit code or its rollback
  snapshots. A session that finished before the follower started isn't imported; one already running is read from its
  first line.

[Limits](../limits.md) lists these with what to do.
