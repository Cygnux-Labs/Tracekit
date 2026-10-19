# agentsh and Tracekit

> **Experimental:** `tracekit follow` works and is tested, but may change and gets less hardening than the
> [stable core](../support.md).

[agentsh](https://github.com/canyonroad/agentsh) sits under an agent and its tools, intercepts file, network, process
and signal activity, and decides each operation against your policy (`allow`, `deny`, `approve`, `redirect`, `audit`,
`soft_delete`). Its server writes every event to a JSONL audit log (`audit.output`), with an HMAC chain over the lines
when `audit.integrity` is on. agentsh limits what the agent can do. Tracekit proves what it did: `tracekit follow
agentsh` reads that log as agentsh writes it and has Tracekit's signer sign each decision, as it arrives.

| | agentsh | Tracekit |
|---|---|---|
| What it does | Decides each file, network, process, signal, command and service operation against its policy | Signs each of agentsh's decisions as agentsh's word, and a gap wherever the stream breaks |
| Where | The agentsh server, under the agent | A signer outside the agent, called by a follower with its own identity |
| How lines are protected | With `audit.integrity` on, an HMAC chain over the lines, keyed from a file, the environment or a KMS; `agentsh audit verify` checks it ([agentsh's integrity docs](https://github.com/canyonroad/agentsh/blob/main/docs/vaults.md)) | Each record signed when it arrives, hash-chained and checkpointed, exported as a `.tkb` bundle verified offline |

## How it works

`tracekit follow agentsh --log PATH` follows agentsh's audit log from its end: what agentsh writes from then on. For
each line it:

1. checks, when `audit.integrity` is on, that the line's `integrity.sequence` is the one after the last line's, and
   asks the signer for a signed gap when it isn't;
2. sends a decision (an event with a `policy`) to the signer as a `decision_import`: what agentsh applied, the event
   type, the rule, agentsh's message, and the line exactly as agentsh wrote it.

The signer writes each decision as a `policy.external` record (source `import`, tier T3) in a run the follower
registered (agent `agentsh`), naming the follower's identity. The signer's own policy isn't applied to these records:
they record what agentsh says it decided, and when Tracekit received it. When agentsh rotates the log (`audit.rotation`,
renaming it to `PATH.1`), the follower reads the old file to its end and goes on in the new one.

## Setup

In agentsh's config, write the log and turn integrity on, so each line carries a sequence:

```yaml
audit:
  enabled: true
  output: "/var/log/agentsh/audit.jsonl"
  integrity:
    enabled: true
    algorithm: hmac-sha256
    key_source: file
    key_file: /etc/agentsh/audit-hmac.key
```

Give the follower its own identity, one the agent can't present: for example a signer token
([remote callers](../remote-ingest.md)) readable only by the user the follower runs as. In signer.yaml, list it under
`importers` (its runs are imported runs, which the signer doesn't reconcile and watches for the follower's heartbeats)
and grant it these calls:

```yaml
importers: ["token:agentsh-follow"]
authorize:
  "token:agentsh-follow": [register_run, decision_import, tailer_heartbeat, tailer_lost, close_run]
```

Then, as a user that can read agentsh's log:

```bash
tracekit signer token add agentsh-follow --config signer.yaml   # once, on the signer's host
TRACEKIT_SIGNER=https://signer.internal:8443 TRACEKIT_SIGNER_TOKEN_FILE=/etc/tracekit/agentsh-follow.token \
  tracekit follow agentsh --log /var/log/agentsh/audit.jsonl
```

All of the log goes into one run, which the follower prints; once the signer closes it after its `idle_s` without a
decision, the next decision starts a new one.

## What Tracekit records

| agentsh `policy` (the effective decision, else the decision) | Decision |
|---|---|
| `allow`, `audit` | allow |
| `approve` | ask |
| `deny`, `redirect`, `soft_delete` | deny: what ran wasn't what was asked (another command or path, the trash) |

Each record's `tool` is the event's `type` (`file_read`, `net_connect`, `command_policy`, …), its `rule_ids` the
event's `rule`, its reason agentsh's (with what the policy said when the effective decision differs), and its
`tool_use_id` the event's `id`, else `line-<n>`. Events without a `policy` (`session_created`, `command_started`, …)
carry no decision, and only their sequence is checked. The line itself is kept only as a salted commitment: given
agentsh's log and the record's salt, which the signer's operator can reveal, anyone can check that a record is that line
([format v2](../format-v2.md#2-hashes-over-agent-content)).

The signer signs a `capture.gap` (`tailer_lost`) in the run, each reason saying where to look, when:

- `integrity.sequence` isn't the one after the last (records missing, repeated or out of order);
- agentsh starts a new integrity chain for any reason other than `initial` (its `integrity_chain_rotated` record:
  `sidecar_missing`, `sidecar_corrupt`, `key_rotated`, `legacy_archived`, `manual_reset`, `post_tamper_recovery`); the
  gap carries agentsh's reason, the last sequence agentsh says the old chain had, and the last one Tracekit read;
- a line isn't a record of agentsh's log format, or carries a decision this follower doesn't map;
- the log is truncated under the follower, or the follower is stopped (SIGTERM, Ctrl-C): either ends the following;
- the follower is killed: its heartbeats stop, and the signer writes the gap itself after 90 seconds.

While the signer can't be reached, the follower waits and carries on from the same line: the log on disk is the
queue, and each line is recorded once.

## What Tracekit sees and doesn't

- **Sees:** what agentsh writes to the log from the follower's start, signed as it arrives.
- **Doesn't check:** without `audit.integrity`, lines carry no sequence, so a missing line isn't seen; with it, the
  follower checks the sequence, not agentsh's HMAC (it doesn't hold agentsh's key). A record is agentsh's word, signed
  when it arrived; `agentsh audit verify` checks agentsh's own chain.
- **Doesn't read:** what agentsh wrote before the follower started, its other sinks (SQLite, webhook, OpenTelemetry),
  or its stream to its Watchtower control plane, which carries agentsh's own loss markers.

[Limits](../limits.md) lists these with what to do.
