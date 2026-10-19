# Policy

The signer decides every tool call with a policy you write: deny it, hold it for a person, flag it, or allow it. The
signer evaluates the policy itself, over the raw arguments, and records which rules matched and which policy decided,
so anyone can recompute every decision later. This page explains the model; exact syntax is in the
[policy reference](../policy-v2.md).

## The model

1. **Classify the tool.** The policy's `tools` map assigns each tool name (or glob) a class: `shell`, `fs`, `http`,
   `sql`, `payment`, `email`, `mcp`, `browser`, or `app` for an application's own tools. A tool the map doesn't cover is
   `unknown`, and `unknown_tools` decides what happens to it.
2. **Read its fields.** Each class exposes fields parsed from the arguments, for example `shell.command`, `sql.verb`,
   `http.host` or `payment.payee`.
3. **Match rules.** A rule names a class and field (or a tool name pattern) and a regular expression. Rules sit in
   `deny`, `ask` and `flag` sections.
4. **Decide.** Deny beats ask, ask beats flag, and a call no rule matches is allowed.

```yaml
tools:
  run_sql: sql
  transfer_funds: payment
  search_flights: app
unknown_tools: ask
deny:
  - id: TK-DB003
    class: sql
    field: code
    pattern: '\b[Dd][Ee][Ll][Ee][Tt][Ee]\s+[Ff][Rr][Oo][Mm]\s+[^\s;]+\s*(;|$)'
    reason: deleting every row of a table
ask:
  - id: TK-M001
    class: payment
    field: amount
    pattern: '.'
    reason: sending money
```

(Simplified from the shipped packs. Case-insensitive matching is written with character classes, because inline flags
aren't allowed: see determinism below.)

## Tool classes and fields

| Class | Fields | Typical tools |
|---|---|---|
| `shell` | `command`, `argv`, `line` | Bash, run_command |
| `fs` | `path`, `op`, `content_digest` | Read, Write, Edit |
| `http` | `method`, `url`, `host`, `internal`, `sends_to` | fetch, WebFetch |
| `sql` | `statement`, `code`, `verb`, `db` | run_sql, query |
| `payment` | `amount`, `currency`, `payee`, `new_payee`, `payees` | transfer_funds, create_refund |
| `email` | `to`, `domains`, `attachments`, `recipients` | send_email |
| `mcp` | `server`, `tool`, `args` | any MCP tool |
| `browser` | `action`, `url`, `scheme`, `host`, `internal`, `sends_to` | Browser Use actions |
| `app` | none | your business tools: known, so not held as unknown |

## How commands, SQL and addresses are read

Matching a regex against raw text is easy to fool, so each class parses its subject first.

- **Shell.** Tracekit's own tokenizer follows `bash -c`, `eval`, `ssh host '…'`, `find -exec`, `python -c`, heredocs and
  wrappers such as `sudo`, `env` and `xargs`, and matches each command it finds. A line it can't read becomes
  ask `TK-SHELL-PARSE`: when in doubt, a person decides.
- **SQL.** The `code` field blanks comments and string literals for PostgreSQL, MySQL, SQLite and SQL Server, so
  `SELECT 'DROP TABLE x'` isn't mistaken for a drop. Unparseable SQL becomes ask `TK-SQL-PARSE`.
- **URLs and hosts.** Hosts are read the way a browser reads them (Unicode-normalised, with odd IP notations
  canonicalised), so `0xa9.0xfe.0xa9.0xfe` is recognised as the cloud metadata address `169.254.169.254`.
- **Size and validity.** Arguments that aren't strict JSON are denied (`TK-ARGS-INVALID`); a subject over 64 KiB is
  decided by `TK-OVERSIZE`.

## Determinism

Every decision must be recomputable from the record: the same policy, engine and arguments always give the same answer.

- The compiled policy has a hash; each decision records it and the engine used. Bundles carry the policy snapshots
  their records cite, named by their own SHA-256.
- Tracekit parses policy YAML with its own strict parser (no anchors, aliases or duplicate keys), so a policy means the
  same on every signer.
- Two regex engines exist: RE2, which runs in linear time, and the `regex` module as a fallback where RE2 can't be
  installed. The linter only allows patterns both engines read identically (no lookaround, backreferences, inline flags
  or super-linear nesting). The fallback gets one second per decision; on timeout it denies and marks the decision
  `nondeterministic`.

## Why the signer decides

Anything inside the agent's process can be changed by the agent, including a policy check. So the signer decides, over
the raw arguments, and computes the arguments' digest itself. A result is bound to its decision, and the signer records
disagreement as signed gaps:

| Gap | When |
|---|---|
| `executed_against_policy` | A call ran after a deny, or after an ask with no consumed approval |
| `decision_flip` | An allow after a deny for the same arguments |
| `class_mismatch` | The client's class hint disagrees with the policy |

## Shipped packs

| Pack | For | Examples |
|---|---|---|
| `coding` | Coding agents on a laptop | Deny privilege escalation, force pushes, recursive deletes of root or home, touching Tracekit's own files. Unknown tools are flagged |
| `browser` | Browser agents | Deny `file:` URLs and internal addresses; ask before uploads |
| `server` | Server agents (extends the others) | Deny cloud metadata access and secrets in arguments; unknown tools are held for a person |
| `server-data` | SQL tools | Deny DROP, TRUNCATE, DELETE without WHERE, privilege changes |
| `server-net` | HTTP tools | Deny internal addresses and data sent to hosts off the allowlist |
| `server-cloud` | Cloud CLIs | Deny IAM changes; ask before deleting resources |
| `server-comms` | Payments and messaging | Ask before payments, mass email and @channel |
| `dev` | The default | `coding` plus a demo deny and a demo ask |

Extend a pack with `extends:` and add your own rules; a rule with the same id replaces the pack's.

## Commands

```sh
tracekit policy lint policy.yaml        # every error at once
tracekit policy compile policy.yaml     # the canonical form and its hash
tracekit policy backtest --policy policy.yaml --store DATA_DIR   # replay detection over stored decisions
```

## Where rules stop

Rules are tripwires, not a sandbox. A determined agent can phrase a command so no rule matches: the
[evaluation](../evaluation.md#e3-policy-gate) lists misses such as `X=rm; $X -rf ~` and a base64 payload piped to a
shell. On the shipped packs' own test corpus (462 harmful and 668 benign calls across 11 classes, written by the
project) every harmful call is denied or held, with one false alarm. The protection that doesn't depend on wording is
the signer's isolation and the witnesses: a call that slips past the rules is still recorded, and the record can't be
hidden.

## Reference

[Policy reference](../policy-v2.md) · the engine and packs: [`tracekit/policy2/`](../../tracekit/policy2)

---

Previous: [Witnesses and monitoring](witnesses-and-monitoring.md) · [All concepts](README.md) · Next:
[Approvals](approvals.md)
