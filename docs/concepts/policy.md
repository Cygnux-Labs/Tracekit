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

Every class also has `target`: what the call acts on rather than what it carries (a command's words without its data,
its redirection targets, a path, a URL).

## How commands, SQL and addresses are read

Matching a regex against raw text is easy to fool, so each class parses its subject first.

- **Shell.** Tracekit's own tokenizer follows `bash -c`, `eval`, `ssh host '…'`, `find -exec`, `python -c`, heredocs and
  wrappers such as `sudo`, `env` and `xargs`, and matches each command it finds. Program names are read in any case
  and without `.exe`. A line it can't read becomes ask `TK-SHELL-PARSE` (deny, with `on_parse_error: deny`): when in
  doubt, a person decides.
- **One command at a time.** Rules on what a command does read each command on its own: its words and its redirection
  targets, also inside a wrapper, `find -exec` or a nested shell. So `git push && ls -f` isn't a force push, and a
  commit message or a `grep` pattern that names one isn't either.
- **SQL.** The `code` field blanks comments and string literals for PostgreSQL, MySQL, SQLite and SQL Server, so
  `SELECT 'DROP TABLE x'` isn't mistaken for a drop. Unparseable SQL becomes ask `TK-SQL-PARSE`.
- **URLs and hosts.** Hosts are read the way a browser reads them (Unicode-normalised, with odd IP notations
  canonicalised), so `0xa9.0xfe.0xa9.0xfe` is recognised as the cloud metadata address `169.254.169.254`.
- **Size and validity.** Arguments that aren't strict JSON are denied (`TK-ARGS-INVALID`); a subject over 64 KiB is
  decided by `TK-OVERSIZE`, in its rule's own section. If the engine itself fails on a call, the call is denied and
  recorded (`TK-ENGINE-ERROR`).

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
- Each rule gets a prefilter: a few strings one of which every match contains. A subject that holds none of them isn't
  searched. It only skips searches that can't match, so it never changes a decision.

## Why the signer decides

Anything inside the agent's process can be changed by the agent, including a policy check. So the signer decides, over
the raw arguments, and computes the arguments' digest itself. A result is bound to its decision, and the signer records
disagreement as signed gaps:

| Gap | When |
|---|---|
| `executed_against_policy` | A call ran after a deny, or after an ask with no consumed approval |
| `decision_flip` | An allow after a deny for the same arguments |
| `class_mismatch` | The client's class hint disagrees with the policy |

## Remedies

A deny or ask rule can carry a `remedy`: one sentence saying what to do instead, and what a person can do. The signer
sends it to the agent with the rule's reason, so the model can change course rather than retry, and `tracekit view`
shows it under the rule. The signed record names only the rule ids; the text lives in the policy, under its hash. The
deny and ask rules of the coding pack, and those the server and strict packs add, carry one:

```text
Push without --force, --mirror or a + refspec (rebase onto the remote branch, or push a new branch); a person rewrites
shared history themselves.
```

## Live constraints

A policy is written ahead of time, but a person's request often adds a limit for one task: "don't touch billing.py",
"read-only", "don't push". The coding-agent hooks read such limits from each prompt with a small fixed grammar and send
them to the signer (`constraint_add`), which signs a `constraint.added` record (the kind, and for a file only a
commitment to its name) and holds the limit for the rest of the run.

| Kind | Holds |
|---|---|
| `keep_away` | a call that writes the named file, or under the named directory |
| `only_change` | a call that writes any other file, when a client adds it; the coding-agent hooks don't, and `tracekit analyze --v2` checks a scope after the run (TK-X204) |
| `read_only` | any call that writes, commits or installs |
| `no_push` | a `git push` |
| `no_network` | an http or browser call, a network command, a package install |

After the policy has decided, a call that breaks a constraint is raised to ask (`TK-CONSTRAINT`), and a person answers
it, never an agent approver. A constraint never lowers a decision, so any client of the run may add one: a made-up
constraint only makes the agent wait (past the 32 file constraints a run takes, a further one is refused and every
write of the run is held). The agent is told which request it broke, and `tracekit verify` checks that every
such hold follows a constraint. The grammar reads only some ways of saying a limit; `tracekit analyze --v2` checks the
same constraints after the run ([what was asked, said and done](provenance-and-why.md#what-was-asked-said-and-done)).
Live constraints are experimental.

## Shipped packs

| Pack | For | Examples |
|---|---|---|
| `coding` | Coding agents on a laptop | Deny privilege escalation, force pushes, recursive deletes of root or home, writing credential files, touching Tracekit's own files. Ask before destroying a deployment or database, deleting a remote Git branch, leaving the agent's sandbox, and adding autostart entries or Git hooks. Unknown tools are flagged |
| `browser` | Browser agents | Deny `file:` URLs and internal addresses; ask before uploads, typing on sites off the allowlist and running the agent's own page JavaScript |
| `server` | Server agents (extends the others) | Deny cloud metadata access, secrets in arguments and credential files; unknown tools are held for a person; detection in shadow mode |
| `strict` | Server agents where a person sees every change first | `server`, plus: pushes, installs, publishes, `docker run`, applies, network commands and environment changes ask, and a shell command the parser can't read is denied |
| `server-data` | SQL tools | Deny DROP, TRUNCATE, DELETE without WHERE, privilege changes, SQL that reaches the server's shell or files |
| `server-net` | HTTP tools | Deny internal addresses and data sent to hosts off the allowlist |
| `server-cloud` | Cloud CLIs | Deny IAM changes; ask before deleting resources |
| `server-comms` | Payments and messaging | Ask before payments, mass email and @channel |
| `dev` | The default | `coding` plus a demo deny and a demo ask |

Extend a pack with `extends:` and add your own rules; a rule with the same id replaces the pack's. The strict pack adds
no patterns: it raises three of the server pack's flags to asks, so it holds more ordinary work (10% of developer
session calls in E21, against 1.5% for `server`). Use it where a person answers holds promptly.

## Commands

```sh
tracekit policy lint policy.yaml        # every error at once
tracekit policy compile policy.yaml     # the canonical form and its hash
tracekit policy backtest --policy policy.yaml --store DATA_DIR/store   # replay detection over stored decisions
```

## Where rules stop

Rules are tripwires, not a sandbox. A determined agent can phrase a command so no rule matches: the
[evaluation](../evaluation.md#e3-policy-gate) lists misses such as `X=rm; $X -rf ~` and a base64 payload piped to a
shell. On the shipped packs' own test corpus (699 harmful and 797 benign calls across 11 classes, written by the
project) every harmful call is denied or held, with one false alarm. On E21's held-out pool (420 harmful and 432
benign calls, written blind to the rules), the only blind run caught 211 harmful calls (50.2%) with the server pack and
246 (58.6%) with the strict pack. With rules added since, written while the misses were known, they catch 245 (58.3%)
and 274 (65.2%), while holding 4.2% and 10.9% of the benign ones ([evaluation](../evaluation.md#e21-policy-robustness)).
The protection
that doesn't depend on wording is the signer's isolation and the witnesses: a call that slips past the rules is still
recorded, and the record can't be hidden.

## Reference

[Policy reference](../policy-v2.md) · the engine and packs: [`tracekit/policy2/`](../../tracekit/policy2)

---

Previous: [Witnesses and monitoring](witnesses-and-monitoring.md) · [All concepts](README.md) · Next:
[Approvals](approvals.md)
