# Tracekit in depth

How Tracekit works, from the idea to the bytes, and the questions a security engineer or an auditor asks about it. Each
answer is short and links to the page with the detail. Everything here describes 1.2.0. Parts marked experimental work
and are tested, but may change ([what's stable](support.md)).

Contents: [the idea](#the-idea) · [one tool call](#one-tool-call-end-to-end) ·
[the evidence format](#the-evidence-format) · [verification](#verification-and-assurance) ·
[witnesses](#witnesses-and-the-monitor) · [policy](#policy) · [approvals](#approvals) ·
[agent approvers](#agent-approvers) · [containment](#detection-and-containment) · [custody](#custody) ·
[completeness](#completeness-gaps-and-reconciliation) · [provenance and why](#provenance-and-tracekit-why) ·
[deployment](#deployment-and-isolation) · [storage and speed](#storage-durability-and-speed) ·
[integrations](#integrations) · [hard questions](#hard-questions) · [design decisions](#design-decisions) ·
[evaluation](#evaluation) · [history](#history) · [neighbours](#how-it-relates-to-other-tools) ·
[not done yet](#not-done-yet)

## The idea

### What is Tracekit?

A flight recorder for AI agents that can't be quietly edited. A separate process, the signer, sits between the agent
and its tools. Before each tool call runs, the signer checks it against your policy and allows it, denies it, or holds
it for a person. It signs every call, decision and result into a hash chain inside a Merkle log that independent
witnesses cosign. Each run exports as one `.tkb` file that anyone can verify offline, with keys they pinned themselves.

### What problem does it solve?

An agent's log is written by the agent's own process. When a prompt injection or a bug makes it do damage, the same
process can edit or skip that log. Teams also have to show what happened to someone else: a security team, an
auditor, a customer. Tracekit keeps the record outside the agent's control and lets a third party check it without
trusting whoever ran the agent.

### What exactly does it prove?

What its capture path recorded, and that the record has not changed since it was signed and checkpointed. It does not
prove intent, that the capture was complete, or that a tool result the agent reported is true. It is tamper-evident,
not tamper-proof: it detects tampering rather than preventing it. Integrity (the chain, signatures and witnesses) and
completeness (the capture paths) are kept apart; completeness is reported, never proven, and the verifier never prints
"complete". More: [FAQ](faq.md#what-cant-tracekit-prove).

## One tool call, end to end

### What happens when an agent calls a tool?

1. `register_run` gives the client a `run_id` and a run token. The signer writes `run.registered` with the isolation
   it measured, the fail modes and the caller's identity.
2. `decide` sends the tool name and arguments. The signer parses the arguments strictly, classifies the tool itself
   (a client's class hint can only make things stricter), evaluates its policy and signs a `policy.decision` with a
   fresh `decision_id`, the matching rule ids, the policy hash, the regex engine and a commitment to the arguments. It
   answers allow, deny or ask.
3. For ask: `approval_request`, `approval_wait`, a person's `approval_decide`, then `approval_consume` just before
   the call runs.
4. The tool runs.
5. `complete` sends the result with the `decision_id` and the arguments' digest. The signer checks the digest opens the
   decision's commitment, redacts the result, commits to it and writes `tool.result`. A call that ran against a deny or
   an unapproved ask is also signed as `capture.gap{executed_against_policy}`.
6. `close_run` (or the idle timeout) writes `run.closing`. After a short grace window for late records, the signer
   writes completeness gaps, then reconciliation findings, then `run.final`.
7. The signer signs a checkpoint of the log after each `run.final` and every 10 seconds while the log grows, sends it
   to witnesses, and anchors it in Rekor at most hourly.
8. `tracekit export --v2 --run R` writes the bundle; `tracekit verify` checks it. `tracekit last` does both for the
   dev signer's latest run.

More: [architecture](architecture.md), [quickstart](quickstart-v2.md).

### If the agent doesn't hold a key, what does it hold?

A run token: an HMAC capability for one run, bound to the identity that registered it. In system mode only that OS
user can use it. It uses a different key from the evidence signatures, so it can never stand in for a signature. A
run that has gone final refuses every write.

### Who assigns sequence numbers?

Only the signer's single writer thread. It keeps two chains: the log chain (`seq`, `prev_hash`) and a chain per run
(`run_seq`, `run_prev_hash`). Because the agent never numbers or links records, a missing or reordered record shows.

## The evidence format

### What does a record look like?

One line with six keys: `{"v":2, "event", "hash", "alg", "kid", "sig"}`. `hash` is SHA-256 over the event in RFC 8785
canonical JSON (JCS). `kid` is the SHA-256 of the public key, which also binds its algorithm.

### What exactly is signed?

Ed25519 signs a canonical object that binds the record's hash to its place in both chains:

```text
JCS({alg, kid, log_id, seq, prev_hash, tenant, run_id, run_seq, run_prev_hash, hash, "t":"tracekit.record.v2"})
```

The `t` value separates signing purposes: checkpoints, approvals, certificates, key retirements and exports each
have their own, so a signature made for one can't be replayed as another. Verification is strict Ed25519 (canonical
`S`, no small-order keys), and `alg` must be both allowed by your trust config and the key's own algorithm.
More: [format v2](format-v2.md).

### Why canonical JSON?

Signatures need the same bytes in every language. The strict parser refuses duplicate keys, NaN and Infinity, integers
past 2^53−1, lone surrogates and invalid UTF-8. Arguments that fail it are denied (`TK-ARGS-INVALID`). Test vectors
pin the encoding: [tests/vectors](../tests/vectors).

### Why a hash chain, a Merkle tree and witnesses?

- The chain catches edits, deletions and reordering inside a run.
- The Merkle tree (RFC 6962) gives inclusion proofs, so one run's bundle anchors to a checkpoint of the whole log, and
  consistency proofs, so a witness can refuse a tree that doesn't extend the one it saw.
- Witnesses catch the two things a log can't see about itself: its own tail being cut off, and a rewrite by someone
  holding the key. In the [evaluation](evaluation.md#e1-tamper-detection) both are missed in 60 of 60 trials without a
  witness and caught in 60 of 60 with one.

### A bundle proves only each run's first and last record are in the tree. Is that enough?

Yes. Every event holds `run_prev_hash`, so the last record's hash commits to the whole run. Key records, and records a
registry entry points to, get proofs too.

### What is a checkpoint?

A C2SP signed note: origin, tree size and root hash, signed by the log key. A witness adds a cosignature that carries
its own timestamp. Because the format is a standard one, existing witness software can cosign Tracekit logs without
knowing anything about agents.

### How is sensitive content kept out of published records?

Records hold keyed commitments, not plain hashes: `hmac-sha256(salt, sha256(JCS({tool, args})))` with a salt per
record derived from a key only the signer holds. A plain hash of a short value (a PIN, "yes") could be guessed. One salt
opens exactly one record, so `tracekit signer reveal --record N` lets you show an auditor one record and nothing else.
Policy decides on the real arguments; only the records hold commitments. More: [privacy](privacy.md).

### Where does the content itself go?

Into the optional content vault, if you turn it on: AES-256-GCM under a key per run, bound to its record so a blob
can't be moved to another one. Every read needs a grant agents never get, and writes a signed `content.accessed`.
Erasing a run deletes its key. Bundles never contain vault content.

### What keys are there?

- **The log key** signs checkpoints. It is stable and can live in AWS KMS.
- **Record keys** sign records. A key is announced in the log (`signer.epoch`) and ended with `key.retire`; a record
  signed by a retired key after its last valid position fails.
- **The record-key issuer** (experimental) gives signers short-lived certified keys. Each certificate is logged and
  witnessed before the signer receives it, so a secretly issued key can't verify. More: [issuer](issuer.md).
- **Hybrid checkpoints** (experimental) add an SLH-DSA signature line (FIPS 205) next to Ed25519.

### What is in a `.tkb` bundle?

A zip in one strict layout holding the run's records, the key records, inclusion proofs, checkpoints and the policy
snapshots the records cite (plus registry files for a run-set). It holds no verification code, and no trust
configuration: the person verifying brings their own. A bundle that breaks the layout is `UNUSABLE BUNDLE`.

### How do old bundles keep verifying?

Formats only grow, and each format's verifier is frozen; the v1 verifier and its test bundles never change. Schemas are
closed, so an older verifier would otherwise fail a record type it has never seen. Instead every bundle names the
minimum verifier it needs, and an older verifier says `UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`.

## Verification and assurance

### What does `tracekit verify` check?

The trust config, then the bundle layout and its minimum version, the manifest, the checkpoint's signature against
your pinned log key, the witness quorum, a Rekor anchor and a monitor report when you pin them, the key records, every
record's signature, each run's chain, inclusion, the policy snapshots, the run-set, and the incidents and agent
approvals it can recompute. It also reports gaps, capture coverage, isolation and fail-open classes.
More: [reading a verify report](verdicts.md).

### What verdicts and exit codes can it give?

| Verdict | Exit |
|---|---|
| `VERIFIED` (or `VERIFIED TO HEAD n (open)` for a run still open) | 0 |
| `FAILED` | 1 |
| `UNUSABLE BUNDLE`, `UNVERIFIABLE (...)` | 2 |
| any warning, with `--strict` | 3 |

### What is the assurance level?

Who vouches for the checkpoint. It is separate from how the signer was isolated.

| Level | When |
|---|---|
| `dev` | no pinned cosignature or anchor, or any self-approval in the run |
| `local` | only witnesses of class `operator` |
| `witnessed` | enough cosignatures or anchors from witnesses the operator doesn't control |
| `witnessed+monitored` | witnessed, plus a fresh, conflict-free report from a pinned independent monitor |

### Why are there two verifiers?

So a bug in one doesn't decide an audit. The TypeScript verifier was written from [format v2](format-v2.md), not from
the Python code: its own canonical JSON, zip reader, schema checks and Merkle code, on Web Crypto, in Node or a
browser. Tests require both to give the same verdict and exit code on every test bundle and on about 45 tampered ones.
The TypeScript verifier doesn't check SLH-DSA, Rekor, issuer certificates or why findings; bundles that rely on them come
out `UNVERIFIABLE` there, never `VERIFIED`.

## Witnesses and the monitor

### What does a witness check?

The signer sends a checkpoint and a consistency proof from the size the witness last cosigned. The witness checks the
log's signature and that the new tree extends the old one, so it never cosigns a fork or a rollback. It never sees
records. At startup the signer asks its witnesses for their last cosigned size; a local log behind it is a signed
`trace.tamper{rollback}`, and writes stop until someone acknowledges it. Witnesses are experimental, and the public
witness isn't deployed yet. More: [witnesses](witnesses.md).

### What does the monitor add?

Witnesses check that the tree only grows; they don't read it. `tracekit monitor` (experimental) reads it: rollbacks and
forks, both chains, exactly one `run.registered` and one `run.final` per run, nothing after final, keys nobody
announced. It publishes a signed report. Two different forks shown to two verifiers are only caught with a monitor.
More: [monitor](monitor.md).

### Isn't this a blockchain?

No consensus, no token, no mining. It is transparency logging in the line of Certificate Transparency and Sigstore: one
writer, a Merkle tree, signed checkpoints, and independent witnesses and monitors. What differs is that the party being
logged (the agent) never holds the key, and the operator is treated as a separate adversary.

## Policy

### How is policy written?

YAML, read by Tracekit's own strict parser (no anchors, aliases or duplicate keys). A policy maps tool names to classes
(`shell`, `fs`, `http`, `sql`, `payment`, `email`, `mcp`, `browser`, `app`) and has `deny`, `ask` and `flag` rules over
each class's fields, such as `shell.command`, `sql.verb` or `http.host`. Deny beats ask, ask beats flag, and a call no
rule matches is allowed. Each decision records the policy's hash; bundles carry the policy snapshots they cite.
More: [policy reference](policy-v2.md).

### Why does the signer decide, and not the agent?

Anything inside the agent's process can be changed by the agent. The signer decides over the raw arguments, computes
their digest itself, and binds the result to the decision. Running a denied call is signed as
`executed_against_policy`; an allow after a deny for the same arguments is a signed `decision_flip`.

### How does it read shell commands, SQL and URLs?

Its own shell tokenizer follows `bash -c`, `eval`, `ssh host '…'`, `find -exec`, `python -c`, heredocs and wrappers
like `sudo`, `env` and `xargs`. A command it can't read becomes ask `TK-SHELL-PARSE`, so a person decides. SQL
comments and string literals are blanked per dialect, so `SELECT 'DROP TABLE x'` is allowed. Hosts are read the way a
browser reads them, so `0xa9.0xfe.0xa9.0xfe` is `169.254.169.254`.

### Why two regex engines?

RE2 runs in linear time, but it is a native build that may be missing; the `regex` module is the fallback. The linter
keeps patterns in a subset both engines read the same way, so a decision doesn't depend on the engine; the policy
corpus is decided by both with no differences. The fallback gets one second per decision and denies on timeout.

### What policy packs ship?

`coding` (laptop agents: privilege escalation, force pushes, recursive deletes of root or home, touching Tracekit's own
files), `browser`, and for servers `server`, which adds `server-data` (DROP, TRUNCATE, DELETE without WHERE),
`server-net` (internal addresses, data sent off the allowlist), `server-cloud` (IAM changes) and `server-comms`
(payments, mass email, @channel). Unknown tools are flagged on a laptop and held for a person on a server.

### Can't an agent reword a command around the rules?

Yes. Rules are tripwires, not a sandbox, and the [evaluation](evaluation.md#e3-policy-gate) lists real misses such as
`X=rm; $X -rf ~` and a base64 payload piped to a shell. The protection is the signer's isolation and the witnesses: a
call that gets past the rules is still recorded, and the record can't be hidden.

## Approvals

### How does holding a call for a person work?

The signer signs an `approval.request` whose binding covers the run, the call id and attempt, the tool, the commitment
to the arguments, the policy hash, a nonce and an expiry. It keeps its own encrypted copy of the arguments, so the
approver sees what will actually run. `approval_consume` recomputes the digest and requires an unexpired approval
that matches; different arguments are refused (`TK-APPROVAL-MISMATCH`). Each approval is used once, and a retry needs a
new decision and a new approval. More: [approvals](approvals.md).

### What stops the agent changing the arguments after approval?

On in-process paths, the binding check at consume. On a T2 path (`approval: {executor: t2}`) the consume hands back
the signer's own copy of the arguments, and the [tool executor](executor.md) runs exactly that.

### Who may approve?

The approvers listed in the signer's config. The requester, the run's owner and its principal can't approve their own
calls by default, and one person's identities on different channels are joined so they can't approve from Slack what
they couldn't approve on the command line. Break-glass approvals need a reason and show as a verify warning. The dev
signer allows self-approval, records it, and caps the run's assurance at `dev`.

### Which channels can approvers use?

The command line (`tracekit approvals`), which is stable. Experimental: a web page with OIDC sign-in, passkeys (a
WebAuthn signature over the approval's binding), and Slack.

## Agent approvers

### Can an agent approve another agent's calls?

Experimental, and only inside hard bounds; people answer everything else. Every argument must be named with an exact
type and checked against allowed values. People answer whenever the bounds fail, an argument came only from untrusted
content, the rule is one Tracekit synthesised (an unknown tool, an unreadable command), the run is a replay, or a
budget is spent. Once a call is rejected or escalated, the same call goes to a person for the rest of the run, and an
agent can review at most ten calls per run. A veto delay gives people time to revoke. Shadow mode records the agent's
answers without acting on them, and a kill switch revokes and escalates everything at once.
More: [agent approvers](approvals.md#agent-approvers).

### How do you know the bounds hold?

E18 points a reviewer that approves everything at seven attacks: arguments out of bounds, an untrusted memo, retrying
with a new attempt or call id, fifty near-identical calls, budget exhaustion, answering after an escalation, and the
kill switch. All seven are caught.

## Detection and containment

### How are patterns across calls detected?

Experimental. A policy can declare `sequences` (for example secrets access followed by egress within ten minutes),
`limits` (for example more than 300 calls a minute) and responses. Detection is a pure function of the signed records,
using the rule ids and labels each decision already carries, so replay, backtest and the verifier get the same answer.
Only calls that were allowed, or approved and consumed, count. More: [incidents](incidents.md).

### What do hold and quarantine do?

A hold expires the run's live approvals and turns every later call into an ask that only a person can answer. A
quarantine is permanent: calls are denied, the LLM gateway stops forwarding the run's model requests, and the run
closes. New runs of the same owner and principal inherit a hold for a cooldown, one hour by default, so starting a
fresh run doesn't escape it. Holds on in-process paths are recorded but enforced only if the adapter obeys; on T2
paths (the executor and gateways) they are enforced.

### Can an operator fake containment?

The verifier recomputes run-level incidents from the bundled policy. An allow after a hold, without a person's approval
citing a live incident, fails verification, in both verifiers.

## Custody

### What are tiers T1, T2 and T3?

T1 is capture inside the agent's process (hooks, adapters): it proves what the agent reported. T2 is capture outside it
(the tool executor, the MCP gateway, the LLM gateway): it proves what crossed a boundary the agent doesn't control. T3
is imported telemetry: it proves only receipt.

### What is the tool executor?

A service (experimental) that runs tool calls with credentials the agent never holds. Actions are declared with a
schema for their arguments, redirects are never followed, secrets are removed from responses in raw, JSON, URL
and HTML encodings, and it always fails closed. More: [executor](executor.md), [MCP gateway](mcp-gateway.md).

### What does the LLM gateway add?

It records model calls outside the agent's process, holding the provider key itself. With `gateway_mandatory: true`,
a tool use the model asked for with no matching decision is a signed `reconcile.hook_missing`, and a decision no model
call asked for is `reconcile.fabricated`. More: [gateway](gateway.md).

### What is the egress observer?

A forward proxy (experimental) that never intercepts TLS. It attributes traffic to a run, refuses a CONNECT whose SNI
doesn't match the host, raw IP addresses, public DNS-over-HTTPS and names that resolve to private addresses, and
reports hosts per minute. A host no recorded call explains is a signed `reconcile.unexplained_effect`.
More: [egress](egress.md).

### What is the coverage matrix?

Every `run.final` states, for model calls, tool calls, network, processes and services, whether each was enforced,
observed, only reported, or not covered. Processes and services are not covered yet.

## Completeness: gaps and reconciliation

### What happens to an event that never arrives?

It becomes a signed gap, never silence, and only the signer can write one. Examples: a skipped client counter, a
decision with no result, a second run from the same harness session, a transcript tailer or egress observer that went
quiet, writes after a run ended, a witness that stopped answering, a storage outage.

### What happens when the signer is down?

Each tool class has a fail mode, closed by default: the call is blocked. A class you set open runs unrecorded, and the
signer later writes a gap covering exactly the missed calls, which the verifier warns about. System mode, the executor
and the MCP gateway always fail closed. More: [FAQ](faq.md#what-happens-when-the-signer-is-down).

### What are capture layers?

L1 is saved agent state (for example LangGraph checkpoints), L2 the decide-and-complete path, L3 what the model asked
for (from in-process tracing, the transcript tailer or the LLM gateway), L6 network traffic from the egress observer.
L4 and L5 (processes, services) are not built yet. Reconciliation compares the layers: in the
[evaluation](evaluation.md) it flags 12 of 12 seeded discrepancies with no false positives when L3 is present, and
nothing when it is absent.

### What if the agent never calls the hook at all?

Then nothing records it. The answer is a layer outside the agent's process: a mandatory LLM gateway with network
rules, the executor or MCP gateway holding the credentials, or the egress observer.

## Provenance and tracekit why

### What is argument provenance?

Results from tools the policy marks untrusted (fetched pages, email, tickets, MCP) are indexed by value: addresses,
URLs, hosts, paths, long numbers and strings. A rule with `from: untrusted` matches only if a value in the call came
only from untrusted content, for example an email recipient (`TK-P001`), a payee (`TK-P002`) or a host data is sent to
(`TK-P003`). When the index is incomplete, such a rule matches whenever its pattern does. It matches values verbatim, so
a paraphrase evades it: it is a tripwire, not information-flow control.
More: [provenance](policy-v2.md#provenance-untrusted-and-from-untrusted).

### What does `tracekit why` do?

Experimental. It asks whether an action would still happen without a given input, by replaying the run with that input
removed and tools served from the recording, so replays never repeat real side effects. It first tests all upstream
untrusted inputs together, then narrows down, and reports the effect with a confidence interval and a verdict: causal,
suppressive, ruled out, or inconclusive. On signed runs each replay is itself a signed run, and the results are signed
findings the verifier recomputes. It began as a separate project, Causeway, and joined Tracekit in 1.1.
More: [tracekit why](why.md).

### Does it find the right cause?

On a small local model (Qwen 2.5 7B), where the planted document really caused the harm, it named exactly that cause in
6 of 6 harmful runs with no false blames. The sample is small. An attribution took 320 to 540 model calls.

## Deployment and isolation

### How does the signer know how isolated the agent is?

It measures it from the connection, and no request field exists for the agent to claim one. On a Unix socket it reads
the peer's credentials (on Linux with every message, so a socket handed to another process can't speak for you): the
same user as the signer is `same-user`, another is `separate-user`. HTTPS identities (Kubernetes service accounts,
mTLS, OIDC, tokens) are `remote`.

### Where can the signer run?

| Mode | Who can reach the keys and log | Recorded isolation |
|---|---|---|
| Laptop dev | the agent's own user | `same-user` |
| Linux system mode | root and the signer's OS user | `separate-user` |
| Container or Kubernetes sidecar | the signer's uid and the node's administrator | `separate-user` |
| Central signer over HTTPS | the signer host's administrators | `remote` |

System mode installs the signer under its own user with a hardened service unit and a root-owned client config, so an
agent can't point its hooks at a decoy. Harness binding (Linux) checks that writes come from the registered program's
process tree. More: [deployment](deploy.md).

### What does dev mode protect?

Nothing against an agent that runs as you: it can read the key, stop the signer and re-sign the log. Dev runs say
`isolation: same-user` and their assurance stays `dev`. Dev mode is for trying Tracekit and catching honest mistakes.

### What does `tracekit doctor` check?

Whether a setup does what it claims: it switches to the agent's user and tries to reach the keys and store, and checks
key file modes, a Postgres role that can't update or delete, durability, witness freshness, clock skew and (for
Kubernetes) security contexts and shared volumes. Its output is advice, not evidence. More: [doctor](doctor.md).

## Storage, durability and speed

### How are records written?

One writer thread takes batches of up to 512 requests, each in an undo log, assigns sequence numbers, hashes, signs,
and appends records and Merkle leaves together. On a disk error the batch rolls back, callers get `unavailable`, and
recovery writes a signed gap. Storage is a file store or Postgres with an insert-only role and a lock that allows one
writer.

### What survives a crash?

With `ack-on-fsync`, a call returns only after the data is on disk; the default `ack-on-write` is faster and can lose
acknowledged records on power loss. In the durability test (`kill -9`, 30 rounds of 8 clients) no acknowledged record
was lost and nothing went missing silently. Power loss itself isn't tested. A background check runs daily and turns any
edit it finds into a signed `trace.tamper`.

### How much time does it add?

| Measurement | Result |
|---|---|
| v2 signer, file storage | 0.45 ms median, 0.91 ms p99 per call; 5,356 events a second |
| v2 signer, Postgres | 0.59 ms median, 5.17 ms p99 |
| v1 hooks | about 70 ms per hook, mostly process start |
| a real agent app | 1.6% more wall time |

The signer numbers are a short run on one macOS machine and are informational; the performance gates are enforced on
Linux. More: [FAQ](faq.md#how-much-does-it-slow-an-agent-down), [evaluation](evaluation.md).

## Integrations

### How do framework integrations work?

Every adapter follows one contract: decide; for ask, request and wait; consume before every gated call; run the
arguments the consume returns; complete. A shared test suite runs each adapter against a fake signer and the real one,
including replayed snapshots, edited saved state, another run's approval and a rewritten call id, all of which must be
refused. `tracekit.instrument()` wires up the frameworks it finds and starts a dev signer if none is running.
More: [quickstart](quickstart-v2.md).

### What has running real agents taught?

Running two open-source agents ([case study](case-study-oss-agents.md)) showed that CrewAI swallows a hook's exception
and runs the tool anyway: a denied `close_account` ran while the signer was down. Hooks now block by returning a
refusal, never by raising, and a gate must block on any error. It also showed streamed model responses weren't
captured, since fixed.

### How do the Claude Code hooks work?

`PreToolUse` asks the signer to decide: a deny exits with code 2, which blocks the call; an ask waits up to nine
minutes for a person; an allow runs. `PostToolUse` records the result and `SessionEnd` closes the run. Any hook error or
unreadable payload also exits 2. The Codex CLI, Cursor and Gemini CLI hooks are experimental.
More: [coding agents](coding-agents.md).

## Hard questions

### Who watches the signer?

Witnesses the operator doesn't control, a monitor on a host the operator doesn't run, and Rekor anchors. That detects a
dishonest signer; preventing one would need attested hardware, which Tracekit doesn't claim.

### What if the operator is malicious?

Whoever holds the key can rewrite or fork the log, and records after the last cosigned checkpoint are unproven.
Detection needs an independent witness and a monitor, plus run-sets to show which runs exist. Without a witness, an
operator rewriting its own log is expected, not a vulnerability ([SECURITY.md](../SECURITY.md)).

### Can the agent forge events?

With its own run token it can send well-formed calls that never happened, and the signer can't tell them apart. Only
reconciliation against a record kept outside the agent's process catches them (`reconcile.fabricated` from the LLM
gateway).

### Isn't a regex gate weak?

As prevention, yes. It is deterministic, so a verifier can recompute every decision, which a model-based classifier
doesn't allow. Tracekit's contribution is evidence that the gate ran and what it saw; pair it with a sandbox to prevent
effects.

### Can the timestamps be trusted?

Record times come from the signer host's clock. Independent time comes from witness cosignatures and the RFC 3161
timestamps on Rekor anchors, which the verify report shows as the earliest independent anchor. Clock skew is a signed
gap.

### What leaks?

Arguments and results are commitments, but timing, sizes, counts and checkpoint cadence still show, Rekor entries are
public and permanent, and redaction works by pattern. More: [privacy](privacy.md#what-hashes-and-metadata-still-leak).

### Has it been reviewed?

Not externally yet ([review packet](review-packet.md)). The experiments are small, synthetic and written by the
authors.

## Design decisions

| Decision | Why |
|---|---|
| A separate signer process | Who can rewrite the log decides what a run is worth. Only the signer holds keys, sequence numbers and chain heads |
| Certificate Transparency's design and C2SP formats | A proven design, existing witness software, and a format precise enough for an independent verifier |
| Keyed commitments instead of plain hashes | Short values can't be guessed, and one record can be opened on its own |
| Regex rules instead of a model judge | The same policy, engine and arguments always give the same decision, so the verifier can recompute it |
| Fail closed by default | An early insider test showed an agent could stop the signer and act unrecorded (fixed in 0.2.1) |
| No verifier inside a bundle | The party being checked must not supply the checker or the trust config |
| Frozen verifiers and a version gate | Evidence must stay checkable for years; an old verifier says "needs newer", never "failed" |
| Run tokens instead of keys | A capability for one run, in a key domain apart from the evidence signatures |
| A chain per run and one for the log | The log chain orders everything; the run chain makes one run's bundle provable with two inclusion proofs |

## Evaluation

Every experiment, its setup and what isn't measured: [evaluation](evaluation.md) and the
[technical report](../report/tracekit-v2.md). Headlines:

| Experiment | Result |
|---|---|
| E1 tamper detection (8 attacks × 60 trials) | 6 of 8 caught by the signed log alone; truncating the tail and re-signing with the key need a witness; 8 of 8 with one |
| E3 the v1 regex gate, a rougher test set | 12 of 16 caught, 1 false alarm in 20 |
| E8 insider attacks, as real users against Linux system mode | 8 of 8 caught; runs on every pull request |
| E9 signer speed | p99 0.91 ms (file), 5.17 ms (Postgres) |
| E10 reconciliation | 12 of 12 flagged with model-call records, 0 false positives |
| E11 tampering with saved agent state | 21 of 21 caught |
| E12 tenant isolation | every attack refused, no leaks under concurrency |
| E14 outages | closed classes blocked, open classes gapped, partitions cost the client timeout |
| E15 `kill -9` | no acknowledged record lost, nothing lost silently |
| E17 policy packs (our corpus) | 462 of 462 harmful calls stopped, 1 false alarm in 668; containment 8 of 8, detection 10 of 10 |
| E18 agent approvers | 7 of 7 attacks caught |
| E19 egress | 7 of 7 |

## History

| Version | What it added |
|---|---|
| 0.1 (September 2026) | The paper ([paper/](../paper)), Claude Code hooks, a hash-chained ledger, a regex gate |
| 0.2 | A separate signer, Ed25519, `.tkb` bundles, witnesses; 0.2.1 closed the insider attacks E8 found |
| 0.3 | First PyPI release, harness binding, no verifier inside bundles |
| 0.4 | The v2 signer: format v2, approvals bound to arguments, C2SP witnesses, run-sets |
| 1.0 | Containers, Kubernetes, Postgres, KMS, the issuer, Rekor v2, the monitor, doctor, the LLM gateway, reconciliation, the viewer; the format became stable |
| 1.1 | `tracekit why`, signed provenance, the content vault, the TypeScript verifier |
| 1.2 | The executor and MCP gateway, detection and containment, agent approvers, completeness gaps, the egress observer |

Every change: [CHANGELOG](../CHANGELOG.md).

## How it relates to other tools

- **Observability (Langfuse, LangSmith, Phoenix, OpenTelemetry).** Their traces are kept by whoever runs the agent and
  aren't signed or witnessed, so they convince only people who trust that party. Tracekit imports OpenTelemetry and
  exports spans that carry each record's hash; use them for debugging and Tracekit for evidence.
  More: [OpenTelemetry](otel.md).
- **Guardrails and classifiers.** They judge content inside the agent's process and leave no evidence. Tracekit's
  gate is simpler but deterministic, outside the agent, and every decision is signed.
- **Sandboxes.** They prevent effects and see system calls; Tracekit does neither, and gives records a third party can
  check. Use both.
- **Cloud audit logs.** They are kept by the operator and don't know what an agent's tool call is.
- **What others do that Tracekit doesn't:** judge meaning with a model, dashboards and evaluations at scale, hosted
  plans, containment at the operating-system level.

## Not done yet

- An external review of the threat models.
- A deployed public witness, so independent witnessing needs no setup.
- Capture of processes and services (layers L4 and L5).
- Adversarial evaluation with real models, beyond the scripted attacks.
- The TypeScript SDK on npm.
- System mode validated on macOS and Windows.
- Performance numbers for separate-user and HTTPS signers on Linux.

Every known limit, with what to do about it: [limits](limits.md).
