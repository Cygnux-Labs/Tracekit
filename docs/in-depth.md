# Tracekit in depth

How Tracekit works, from the idea to the bytes, and the questions a security engineer or an auditor asks about it. Each
answer explains the idea simply, then gives the technical detail and links to the page with more. Everything here
describes 1.2.0. Parts marked experimental work and are tested, but may change ([what's stable](support.md)).

Contents: [words used here](#words-used-here) · [the idea](#the-idea) · [one tool call](#one-tool-call-end-to-end) ·
[the evidence format](#the-evidence-format) · [verification](#verification-and-assurance) ·
[witnesses](#witnesses-and-the-monitor) · [policy](#policy) · [approvals](#approvals) ·
[agent approvers](#agent-approvers) · [containment](#detection-and-containment) · [custody](#custody) ·
[completeness](#completeness-gaps-and-reconciliation) · [provenance and why](#provenance-and-tracekit-why) ·
[deployment](#deployment-and-isolation) · [storage and speed](#storage-durability-and-speed) ·
[integrations](#integrations) · [hard questions](#hard-questions) · [design decisions](#design-decisions) ·
[evaluation](#evaluation) · [history](#history) · [neighbours](#how-it-relates-to-other-tools) ·
[not done yet](#not-done-yet)

## Words used here

The answers below explain each idea simply first, then give the technical detail. These words come up throughout.

| Word | Meaning |
|---|---|
| Signer | Tracekit's guard program. The only one that holds the keys and writes the log |
| Run | One job by an agent, from start to finish |
| Run token | The agent's pass for one run. It can ask the signer to record things, but can't sign anything |
| Hash | A fingerprint of data. Change one letter and the fingerprint changes completely |
| Signature | A seal only the key holder can make, which anyone can check with the public key |
| Hash chain | Each record includes the fingerprint of the one before it, like links in a chain. Break one and it shows |
| Merkle tree | A tree of fingerprints that sums up a whole log in one fingerprint, and proves one record is in it cheaply |
| Checkpoint | A signed snapshot: "the log has N records and its fingerprint is X" |
| Witness | An outside notary that cosigns checkpoints after checking the log only grew |
| Monitor | An outside auditor that reads the log and reports anything odd |
| Bundle (`.tkb`) | The file you share: one run's records plus proofs, checkable offline |
| Trust config | Your own list of the keys and witnesses you trust, used when checking |
| Commitment | A sealed fingerprint that hides content but can be opened for one record |
| Gap | A signed note that something is missing |
| Tier T1 / T2 / T3 | Where evidence came from: the agent itself, a component outside it, or an import |
| Assurance | How many independent parties vouch for the log |
| Fail closed / fail open | When the signer is down: block the action, or allow it and note it later |

## The idea

### What is Tracekit?

Think of the black box on a plane: Tracekit is that for AI agents. Every time an agent wants to do something (run a
command, change a database, send an email), a separate guard program checks it against your rules first, then writes it
into a logbook the agent can't secretly change. Later, anyone can check that logbook on their own computer and see
whether it was tampered with.

A flight recorder for AI agents that can't be quietly edited. A separate process, the signer, sits between the agent
and its tools. Before each tool call runs, the signer checks it against your policy and allows it, denies it, or holds
it for a person. It signs every call, decision and result into a hash chain inside a Merkle log that independent
witnesses cosign. Each run exports as one `.tkb` file that anyone can verify offline, with keys they pinned themselves.

### What problem does it solve?

Today an agent's log is like a diary the agent keeps about itself. If something goes wrong, whatever is controlling the
agent can tear out pages. Tracekit hands the diary to someone else and seals every page, so you can trust it and show it
to others.

An agent's log is written by the agent's own process. When a prompt injection or a bug makes it do damage, the same
process can edit or skip that log. Teams also have to show what happened to someone else: a security team, an
auditor, a customer. Tracekit keeps the record outside the agent's control and lets a third party check it without
trusting whoever ran the agent.

### What exactly does it prove?

It proves the logbook is genuine and nothing was changed after it was written. It does not prove the agent meant well,
that every single action was captured, or that what a tool said back was true. Think of a sealed security-camera tape:
it shows nobody edited the tape, not that the camera saw every room.

What its capture path recorded, and that the record has not changed since it was signed and checkpointed. It does not
prove intent, that the capture was complete, or that a tool result the agent reported is true. It is tamper-evident,
not tamper-proof: it detects tampering rather than preventing it. Integrity (the chain, signatures and witnesses) and
completeness (the capture paths) are kept apart; completeness is reported, never proven, and the verifier never prints
"complete". More: [FAQ](faq.md#what-cant-tracekit-prove).

## One tool call, end to end

### What happens when an agent calls a tool?

Picture a bank teller guarding a vault. The agent says "I want to do X". The guard (the signer) checks the rules and
says yes, no, or "let me ask a human". If yes, the action happens and the result is written down. Every step becomes a
numbered, sealed entry. At the end the run is closed, sealed, stamped by outside notaries, and you can download one file
with the whole story.

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

A visitor badge, not the master key. The badge (a run token) only lets the agent ask the guard to record things for its
own run. It can't seal anything, can't touch other runs, and stops working when the run ends.

A run token: an HMAC capability for one run, bound to the identity that registered it. In system mode only that OS
user can use it. It uses a different key from the evidence signatures, so it can never stand in for a signature. A
run that has gone final refuses every write.

### Who assigns sequence numbers?

Only the guard numbers the pages. If the agent numbered them, it could quietly skip page 7. Because the guard numbers
every page and links each one to the page before, a missing or shuffled page is obvious.

Only the signer's single writer thread. It keeps two chains: the log chain (`seq`, `prev_hash`) and a chain per run
(`run_seq`, `run_prev_hash`). Because the agent never numbers or links records, a missing or reordered record shows.

## The evidence format

### What does a record look like?

Each entry is one line: what happened, a fingerprint of it (the hash), which key sealed it, and the seal itself (the
signature).

One line with six keys: `{"v":2, "event", "hash", "alg", "kid", "sig"}`. `hash` is SHA-256 over the event in RFC 8785
canonical JSON (JCS). `kid` is the SHA-256 of the public key, which also binds its algorithm.

### What exactly is signed?

The seal covers not just what happened but also where the entry sits in the logbook: its page number and the fingerprint
of the page before. So nobody can cut a genuine entry out and paste it somewhere else. A label inside the seal says what
kind of seal it is, so a seal made for one job can't be reused for another.

Ed25519 signs a canonical object that binds the record's hash to its place in both chains:

```text
JCS({alg, kid, log_id, seq, prev_hash, tenant, run_id, run_seq, run_prev_hash, hash, "t":"tracekit.record.v2"})
```

The `t` value separates signing purposes: checkpoints, approvals, certificates, key retirements and exports each
have their own, so a signature made for one can't be replayed as another. Verification is strict Ed25519 (canonical
`S`, no small-order keys), and `alg` must be both allowed by your trust config and the key's own algorithm.
More: [format v2](format-v2.md).

### Why canonical JSON?

A signature only checks out if everyone turns the data into exactly the same bytes. JSON can be written many ways
(spacing, key order, number formats). JCS is one agreed way to write it, so Python, TypeScript and anyone else get
identical bytes.

Signatures need the same bytes in every language. The strict parser refuses duplicate keys, NaN and Infinity, integers
past 2^53−1, lone surrogates and invalid UTF-8. Arguments that fail it are denied (`TK-ARGS-INVALID`). Test vectors
pin the encoding: [tests/vectors](../tests/vectors).

### Why a hash chain, a Merkle tree and witnesses?

Three layers. The chain links each page to the one before, so editing or removing a page breaks a link. The Merkle tree
is a compact summary of the whole logbook that lets you prove one page is in it without handing over the whole book.
Witnesses are outside notaries who keep stamping that summary, which catches the two tricks the book can't catch on its
own: tearing off the last pages, and rewriting everything with a stolen key.

- The chain catches edits, deletions and reordering inside a run.
- The Merkle tree (RFC 6962) gives inclusion proofs, so one run's bundle anchors to a checkpoint of the whole log, and
  consistency proofs, so a witness can refuse a tree that doesn't extend the one it saw.
- Witnesses catch the two things a log can't see about itself: its own tail being cut off, and a rewrite by someone
  holding the key. In the [evaluation](evaluation.md#e1-tamper-detection) both are missed in 60 of 60 trials without a
  witness and caught in 60 of 60 with one.

### A bundle proves only each run's first and last record are in the tree. Is that enough?

No. Every page contains the fingerprint of the page before it, so the last page of a run vouches for every earlier page
in that run. Proving the last page is in the book proves the whole run is.

Yes. Every event holds `run_prev_hash`, so the last record's hash commits to the whole run. Key records, and records a
registry entry points to, get proofs too.

### What is a checkpoint?

A signed snapshot that says "the logbook has N pages and its summary fingerprint is X". Witnesses add their own stamp
and the time. It uses a standard format, so existing notary software can stamp it.

A C2SP signed note: origin, tree size and root hash, signed by the log key. A witness adds a cosignature that carries
its own timestamp. Because the format is a standard one, existing witness software can cosign Tracekit logs without
knowing anything about agents.

### How is sensitive content kept out of published records?

Records don't contain the raw data, only a sealed fingerprint of it mixed with a secret that differs per record. Nobody
can guess the content (for example by trying every 4-digit PIN), but if an auditor needs to see one particular record,
you can open just that one.

Records hold keyed commitments, not plain hashes: `hmac-sha256(salt, sha256(JCS({tool, args})))` with a salt per
record derived from a key only the signer holds. A plain hash of a short value (a PIN, "yes") could be guessed. One salt
opens exactly one record, so `tracekit signer reveal --record N` lets you show an auditor one record and nothing else.
Policy decides on the real arguments; only the records hold commitments. More: [privacy](privacy.md).

### Where does the content itself go?

If you switch on the vault, the real content is stored encrypted, with one key per run. Reading it needs special
permission and leaves a signed note that someone read it. Deleting a run's key makes its content unreadable for good.
The file you share never includes it.

Into the optional content vault, if you turn it on: AES-256-GCM under a key per run, bound to its record so a blob
can't be moved to another one. Every read needs a grant agents never get, and writes a signed `content.accessed`.
Erasing a run deletes its key. Bundles never contain vault content.

### What keys are there?

One long-lived key stamps the logbook snapshots (it can live in a cloud key safe). Other keys seal individual entries;
they are announced and retired inside the logbook itself, so a retired key can't be used to seal new pages. Optionally,
a key authority hands out short-lived keys, and a future-proof (post-quantum) signature can be added to snapshots.

- **The log key** signs checkpoints. It is stable and can live in AWS KMS.
- **Record keys** sign records. A key is announced in the log (`signer.epoch`) and ended with `key.retire`; a record
  signed by a retired key after its last valid position fails.
- **The record-key issuer** (experimental) gives signers short-lived certified keys. Each certificate is logged and
  witnessed before the signer receives it, so a secretly issued key can't verify. More: [issuer](issuer.md).
- **Hybrid checkpoints** (experimental) add an SLH-DSA signature line (FIPS 205) next to Ed25519.

### What is in a `.tkb` bundle?

A `.tkb` file is a zip of everything needed to check one run: the entries, the proofs, the snapshots and the rules that
were applied. It deliberately leaves out the checking software and the list of trusted keys. The person checking brings
their own, so the file can't vouch for itself.

A zip in one strict layout holding the run's records, the key records, inclusion proofs, checkpoints and the policy
snapshots the records cite (plus registry files for a run-set). It holds no verification code, and no trust
configuration: the person verifying brings their own. A bundle that breaks the layout is `UNUSABLE BUNDLE`.

### How do old bundles keep verifying?

Like a file format that only ever adds features. Old checkers stay frozen and keep working on old files. If an old
checker meets a newer file, it says "I need a newer version", never "this is fake".

Formats only grow, and each format's verifier is frozen; the v1 verifier and its test bundles never change. Schemas are
closed, so an older verifier would otherwise fail a record type it has never seen. Instead every bundle names the
minimum verifier it needs, and an older verifier says `UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`.

## Verification and assurance

### What does `tracekit verify` check?

It works through a checklist. Is the file intact? Is the snapshot signed by a key I trust? Did enough outside witnesses
stamp it? Is every entry sealed by a valid key? Are the pages in order with none missing? Are this run's pages really in
the snapshot? Then it adds notes about gaps and how well the guard was isolated.

The trust config, then the bundle layout and its minimum version, the manifest, the checkpoint's signature against
your pinned log key, the witness quorum, a Rekor anchor and a monitor report when you pin them, the key records, every
record's signature, each run's chain, inclusion, the policy snapshots, the run-set, and the incidents and agent
approvals it can recompute. It also reports gaps, capture coverage, isolation and fail-open classes.
More: [reading a verify report](verdicts.md).

### What verdicts and exit codes can it give?

Three kinds of answer: VERIFIED (all good), FAILED (something was changed or doesn't add up), and UNVERIFIABLE or
UNUSABLE (the checker can't judge, for example a broken file or one that needs a newer checker). The exit codes let
scripts react automatically.

| Verdict | Exit |
|---|---|
| `VERIFIED` (or `VERIFIED TO HEAD n (open)` for a run still open) | 0 |
| `FAILED` | 1 |
| `UNUSABLE BUNDLE`, `UNVERIFIABLE (...)` | 2 |
| any warning, with `--strict` | 3 |

### What is the assurance level?

How many independent parties vouch for the logbook. dev: nobody outside. local: only the operator's own notary.
witnessed: at least one independent notary. witnessed+monitored: an independent auditor also read the logbook and found
nothing wrong.

Who vouches for the checkpoint. It is separate from how the signer was isolated.

| Level | When |
|---|---|
| `dev` | no pinned cosignature or anchor, or any self-approval in the run |
| `local` | only witnesses of class `operator` |
| `witnessed` | enough cosignatures or anchors from witnesses the operator doesn't control |
| `witnessed+monitored` | witnessed, plus a fresh, conflict-free report from a pinned independent monitor |

### Why are there two verifiers?

Two different people adding up the same column of figures. The TypeScript checker was written from the published spec,
not copied from the Python code, so a bug in one is unlikely to be in the other.

So a bug in one doesn't decide an audit. The TypeScript verifier was written from [format v2](format-v2.md), not from
the Python code: its own canonical JSON, zip reader, schema checks and Merkle code, on Web Crypto, in Node or a
browser. Tests require both to give the same verdict and exit code on every test bundle and on about 45 tampered ones.
The TypeScript verifier doesn't check SLH-DSA, Rekor, issuer certificates or why findings; bundles that rely on them
come
out `UNVERIFIABLE` there, never `VERIFIED`.

## Witnesses and the monitor

### What does a witness check?

A witness is an outside notary. Each time it sees a new snapshot, it checks that the logbook only grew (nothing
rewritten or removed) and then stamps it. It never reads the entries. If the guard's logbook ever goes backwards
compared with what a witness saw, that is caught.

The signer sends a checkpoint and a consistency proof from the size the witness last cosigned. The witness checks the
log's signature and that the new tree extends the old one, so it never cosigns a fork or a rollback. It never sees
records. At startup the signer asks its witnesses for their last cosigned size; a local log behind it is a signed
`trace.tamper{rollback}`, and writes stop until someone acknowledges it. Witnesses are experimental, and the public
witness isn't deployed yet. More: [witnesses](witnesses.md).

### What does the monitor add?

Witnesses only check that the logbook grew. The monitor actually reads it, like an auditor: every run started and ended
exactly once, nothing was written after a run ended, no surprise keys appeared. It signs a report you can check.

Witnesses check that the tree only grows; they don't read it. `tracekit monitor` (experimental) reads it: rollbacks and
forks, both chains, exactly one `run.registered` and one `run.final` per run, nothing after final, keys nobody
announced. It publishes a signed report. Two different forks shown to two verifiers are only caught with a monitor.
More: [monitor](monitor.md).

### Isn't this a blockchain?

No: no mining, no coins, no consensus. It's the same idea as Certificate Transparency, the public logs that keep website
certificates honest: one writer, a tamper-evident log, and independent notaries watching it.

No consensus, no token, no mining. It is transparency logging in the line of Certificate Transparency and Sigstore: one
writer, a Merkle tree, signed checkpoints, and independent witnesses and monitors. What differs is that the party being
logged (the agent) never holds the key, and the operator is treated as a separate adversary.

## Policy

### How is policy written?

Rules in a YAML file: deny anything that does X, ask a human before Y, flag Z. Each tool is put in a category (shell,
database, web, payment and so on), and rules look at that category's details, such as the command, the SQL verb or the
website. Deny beats ask, ask beats flag, and anything else is allowed.

YAML, read by Tracekit's own strict parser (no anchors, aliases or duplicate keys). A policy maps tool names to classes
(`shell`, `fs`, `http`, `sql`, `payment`, `email`, `mcp`, `browser`, `app`) and has `deny`, `ask` and `flag` rules over
each class's fields, such as `shell.command`, `sql.verb` or `http.host`. Deny beats ask, ask beats flag, and a call no
rule matches is allowed. Each decision records the policy's hash; bundles carry the policy snapshots they cite.
More: [policy reference](policy-v2.md).

### Why does the signer decide, and not the agent?

You don't let the suspect mark their own exam. If the agent checked its own rules, it could cheat. The guard checks the
actual request and records what it decided, so "it ran anyway" or "it suddenly changed its mind" are both caught.

Anything inside the agent's process can be changed by the agent. The signer decides over the raw arguments, computes
their digest itself, and binds the result to the decision. Running a denied call is signed as
`executed_against_policy`; an allow after a deny for the same arguments is a signed `decision_flip`.

### How does it read shell commands, SQL and URLs?

Tracekit reads commands the way the computer would, including commands hidden inside other commands. If it can't
understand one, it doesn't guess: it asks a human. In SQL it ignores text inside quotes, so a harmless query that
mentions DROP TABLE isn't blocked. It reads web addresses the way browsers do, so odd spellings of internal addresses
are still caught.

Its own shell tokenizer follows `bash -c`, `eval`, `ssh host '…'`, `find -exec`, `python -c`, heredocs and wrappers
like `sudo`, `env` and `xargs`. A command it can't read becomes ask `TK-SHELL-PARSE`, so a person decides. SQL
comments and string literals are blanked per dialect, so `SELECT 'DROP TABLE x'` is allowed. Hosts are read the way a
browser reads them, so `0xa9.0xfe.0xa9.0xfe` is `169.254.169.254`.

### Why two regex engines?

Two pattern-matching engines: a fast, safe one, and a backup for when the fast one isn't installed. Rules may only use
features both understand the same way, so the decision is identical either way. If the backup ever takes too long, the
answer is no.

RE2 runs in linear time, but it is a native build that may be missing; the `regex` module is the fallback. The linter
keeps patterns in a subset both engines read the same way, so a decision doesn't depend on the engine; the policy
corpus is decided by both with no differences. The fallback gets one second per decision and denies on timeout.

### What policy packs ship?

Ready-made rulebooks. One for coding agents on a laptop (no sudo, no force-push, no deleting your home folder), one for
browsers, and several for server agents: dangerous SQL, internal network addresses, cloud permission changes, payments
and mass emails.

`coding` (laptop agents: privilege escalation, force pushes, recursive deletes of root or home, touching Tracekit's own
files), `browser`, and for servers `server`, which adds `server-data` (DROP, TRUNCATE, DELETE without WHERE),
`server-net` (internal addresses, data sent off the allowlist), `server-cloud` (IAM changes) and `server-comms`
(payments, mass email, @channel). Unknown tools are flagged on a laptop and held for a person on a server.

### Can't an agent reword a command around the rules?

Yes, a clever agent can phrase a command so no rule notices. Rules are tripwires, not walls. The real protection is that
the guard is out of the agent's reach and outsiders stamp the logbook: even if a bad call slips past the rules, it's
recorded and can't be erased.

Yes. Rules are tripwires, not a sandbox, and the [evaluation](evaluation.md#e3-policy-gate) lists real misses such as
`X=rm; $X -rf ~` and a base64 payload piped to a shell. The protection is the signer's isolation and the witnesses: a
call that gets past the rules is still recorded, and the record can't be hidden.

## Approvals

### How does holding a call for a person work?

When a call needs approval, the guard writes down exactly what is being approved (this call, these exact details, this
rule, this expiry) and seals it. The approval works once, only for exactly those details, and only before it expires.

The signer signs an `approval.request` whose binding covers the run, the call id and attempt, the tool, the commitment
to the arguments, the policy hash, a nonce and an expiry. It keeps its own encrypted copy of the arguments, so the
approver sees what will actually run. `approval_consume` recomputes the digest and requires an unexpired approval
that matches; different arguments are refused (`TK-APPROVAL-MISMATCH`). Each approval is used once, and a retry needs a
new decision and a new approval. More: [approvals](approvals.md).

### What stops the agent changing the arguments after approval?

Two layers. Normally the guard re-checks the details at the moment of use and refuses if anything changed. With the
executor, the guard hands over its own saved copy, so what runs is exactly what the human approved.

On in-process paths, the binding check at consume. On a T2 path (`approval: {executor: t2}`) the consume hands back
the signer's own copy of the arguments, and the [tool executor](executor.md) runs exactly that.

### Who may approve?

Only the people listed in the guard's settings. By default you can't approve your own agent's request, and a person's
accounts are linked so they can't dodge that by switching to Slack. Emergency (break-glass) approvals are possible but
flagged. In dev mode you can approve yourself, but it's marked and lowers the trust level.

The approvers listed in the signer's config. The requester, the run's owner and its principal can't approve their own
calls by default, and one person's identities on different channels are joined so they can't approve from Slack what
they couldn't approve on the command line. Break-glass approvals need a reason and show as a verify warning. The dev
signer allows self-approval, records it, and caps the run's assurance at `dev`.

### Which channels can approvers use?

The command line, which is stable. Experimental: a web page with sign-in, passkeys (approve with your fingerprint or a
security key), and Slack.

The command line (`tracekit approvals`), which is stable. Experimental: a web page with OIDC sign-in, passkeys (a
WebAuthn signature over the approval's binding), and Slack.

## Agent approvers

### Can an agent approve another agent's calls?

Only for small, routine things inside strict limits, like "refunds under $100 to known customers". Anything outside the
limits, anything influenced by untrusted content, anything unusual, or anything over budget goes to a human. There's a
cooling-off window where a human can overrule, a practice mode, and an off switch.

Experimental, and only inside hard bounds; people answer everything else. Every argument must be named with an exact
type and checked against allowed values. People answer whenever the bounds fail, an argument came only from untrusted
content, the rule is one Tracekit synthesised (an unknown tool, an unreadable command), the run is a replay, or a
budget is spent. Once a call is rejected or escalated, the same call goes to a person for the rest of the run, and an
agent can review at most ten calls per run. A veto delay gives people time to revoke. Shadow mode records the agent's
answers without acting on them, and a kill switch revokes and escalates everything at once.
More: [agent approvers](approvals.md#agent-approvers).

### How do you know the bounds hold?

E18 tests them with a deliberately reckless AI approver that says yes to everything, then tries seven ways to abuse it:
amounts out of range, retries, splitting one big payment into many small ones, blowing the budget, and the off switch.
All seven are stopped.

E18 points a reviewer that approves everything at seven attacks: arguments out of bounds, an untrusted memo, retrying
with a new attempt or call id, fifty near-identical calls, budget exhaustion, answering after an escalation, and the
kill switch. All seven are caught.

## Detection and containment

### How are patterns across calls detected?

Some dangers only show up as a pattern, like "read the secrets, then send data to the internet", or "deleting things
very fast". You describe such patterns in the rules, and the guard watches for them using what it has already signed, so
anyone replaying the records later gets the same answer.

Experimental. A policy can declare `sequences` (for example secrets access followed by egress within ten minutes),
`limits` (for example more than 300 calls a minute) and responses. Detection is a pure function of the signed records,
using the rule ids and labels each decision already carries, so replay, backtest and the verifier get the same answer.
Only calls that were allowed, or approved and consumed, count. More: [incidents](incidents.md).

### What do hold and quarantine do?

Hold: pause, and a human must approve every next step. Quarantine: stop the run for good. Suspend: an operator blocks an
identity entirely. And if a run is on hold, starting a fresh run doesn't escape it for a while.

A hold expires the run's live approvals and turns every later call into an ask that only a person can answer. A
quarantine is permanent: calls are denied, the LLM gateway stops forwarding the run's model requests, and the run
closes. New runs of the same owner and principal inherit a hold for a cooldown, one hour by default, so starting a
fresh run doesn't escape it. Holds on in-process paths are recorded but enforced only if the adapter obeys; on T2
paths (the executor and gateways) they are enforced.

### Can an operator fake containment?

No. The checker redoes the containment logic from the rules saved in the file. If something was allowed while the run
was supposed to be on hold, verification fails.

The verifier recomputes run-level incidents from the bundled policy. An allow after a hold, without a person's approval
citing a live incident, fails verification, in both verifiers.

## Custody

### What are tiers T1, T2 and T3?

Where the evidence came from. T1: the agent told us, like a witness statement. T2: something outside the agent saw it
happen, like a camera at the door. T3: imported from another system; we only know we received it.

T1 is capture inside the agent's process (hooks, adapters): it proves what the agent reported. T2 is capture outside it
(the tool executor, the MCP gateway, the LLM gateway): it proves what crossed a boundary the agent doesn't control. T3
is imported telemetry: it proves only receipt.

### What is the tool executor?

A trusted assistant who holds the keys to the real systems. The agent asks the executor to do something; the executor
checks with the guard and does it with its own credentials. The agent never sees the passwords.

A service (experimental) that runs tool calls with credentials the agent never holds. Actions are declared with a
schema for their arguments, redirects are never followed, secrets are removed from responses in raw, JSON, URL
and HTML encodings, and it always fails closed. More: [executor](executor.md), [MCP gateway](mcp-gateway.md).

### What does the LLM gateway add?

A recorder between the agent and the AI model. Because it sees what the model told the agent to do, Tracekit can
compare: "the model asked for X but the agent never reported X" (a hidden action), or "the agent reported Y but the
model never asked for it" (a made-up action).

It records model calls outside the agent's process, holding the provider key itself. With `gateway_mandatory: true`,
a tool use the model asked for with no matching decision is a signed `reconcile.hook_missing`, and a decision no model
call asked for is `reconcile.fabricated`. More: [gateway](gateway.md).

### What is the egress observer?

A doorman for the internet. It doesn't open your encrypted traffic, but it sees which sites each run talks to, blocks
common tricks for sneaking data out, and flags any site no recorded action explains.

A forward proxy (experimental) that never intercepts TLS. It attributes traffic to a run, refuses a CONNECT whose SNI
doesn't match the host, raw IP addresses, public DNS-over-HTTPS and names that resolve to private addresses, and
reports hosts per minute. A host no recorded call explains is a signed `reconcile.unexplained_effect`.
More: [egress](egress.md).

### What is the coverage matrix?

A report card at the end of each run. For model calls, tool calls, network, processes and services, it says whether each
was enforced, watched, only self-reported, or not covered at all.

Every `run.final` states, for model calls, tool calls, network, processes and services, whether each was enforced,
observed, only reported, or not covered. Processes and services are not covered yet.

## Completeness: gaps and reconciliation

### What happens to an event that never arrives?

A missing record is never quietly ignored. The guard writes a signed note saying "something is missing here, and this is
what". Only the guard can write those notes.

It becomes a signed gap, never silence, and only the signer can write one. Examples: a skipped client counter, a
decision with no result, a second run from the same harness session, a transcript tailer or egress observer that went
quiet, writes after a run ended, a witness that stopped answering, a storage outage.

### What happens when the signer is down?

By default, if the guard is down the agent is blocked: no guard, no action. You can relax this for low-risk tool types.
Then actions run unrecorded, but afterwards the guard notes exactly how many were missed.

Each tool class has a fail mode, closed by default: the call is blocked. A class you set open runs unrecorded, and the
signer later writes a gap covering exactly the missed calls, which the verifier warns about. System mode, the executor
and the MCP gateway always fail closed. More: [FAQ](faq.md#what-happens-when-the-signer-is-down).

### What are capture layers?

Different vantage points on the same run: the agent's saved state, the agent's own reports, what the AI model asked for,
and network traffic. Comparing them catches lies, because an agent can only fake one viewpoint at a time.

L1 is saved agent state (for example LangGraph checkpoints), L2 the decide-and-complete path, L3 what the model asked
for (from in-process tracing, the transcript tailer or the LLM gateway), L6 network traffic from the egress observer.
L4 and L5 (processes, services) are not built yet. Reconciliation compares the layers: in the
[evaluation](evaluation.md) it flags 12 of 12 seeded discrepancies with no false positives when L3 is present, and
nothing when it is absent.

### What if the agent never calls the hook at all?

Then that action isn't recorded; nothing can record what it never sees. The fix is to put something outside the agent
that it has to go through: the model gateway, the executor holding the credentials, or the internet doorman.

Then nothing records it. The answer is a layer outside the agent's process: a mandatory LLM gateway with network
rules, the executor or MCP gateway holding the credentials, or the egress observer.

## Provenance and tracekit why

### What is argument provenance?

Tracekit remembers where values came from. If an email address, account number or website first appeared in an untrusted
web page or email, and the agent then tries to send money or data there, Tracekit can stop and ask a human. It only
spots exact copies, so it's a tripwire, not a guarantee.

Results from tools the policy marks untrusted (fetched pages, email, tickets, MCP) are indexed by value: addresses,
URLs, hosts, paths, long numbers and strings. A rule with `from: untrusted` matches only if a value in the call came
only from untrusted content, for example an email recipient (`TK-P001`), a payee (`TK-P002`) or a host data is sent to
(`TK-P003`). When the index is incomplete, such a rule matches whenever its pattern does. It matches values verbatim, so
a paraphrase evades it: it is a tripwire, not information-flow control.
More: [provenance](policy-v2.md#provenance-untrusted-and-from-untrusted).

### What does `tracekit why` do?

It answers "which input made the agent do that?" by re-running the agent's decision many times with one input taken out,
using recorded tool answers so nothing real happens again. If the bad action disappears when an input is removed, that
input caused it. It also says how sure it is.

Experimental. It asks whether an action would still happen without a given input, by replaying the run with that input
removed and tools served from the recording, so replays never repeat real side effects. It first tests all upstream
untrusted inputs together, then narrows down, and reports the effect with a confidence interval and a verdict: causal,
suppressive, ruled out, or inconclusive. On signed runs each replay is itself a signed run, and the results are signed
findings the verifier recomputes. It began as a separate project, Causeway, and joined Tracekit in 1.1.
More: [tracekit why](why.md).

### Does it find the right cause?

In a small test with a local AI model it pointed at the right cause every time (6 of 6) and never blamed the wrong
input. It's expensive: a few hundred AI calls per investigation.

On a small local model (Qwen 2.5 7B), where the planted document really caused the harm, it named exactly that cause in
6 of 6 harmful runs with no false blames. The sample is small. An attribution took 320 to 540 model calls.

## Deployment and isolation

### How does the signer know how isolated the agent is?

The guard asks the operating system who is connecting, like checking ID at the door instead of asking "who are you?".
The agent has no way to claim to be someone else.

It measures it from the connection, and no request field exists for the agent to claim one. On a Unix socket it reads
the peer's credentials (on Linux with every message, so a socket handed to another process can't speak for you): the
same user as the signer is `same-user`, another is `separate-user`. HTTPS identities (Kubernetes service accounts,
mTLS, OIDC, tokens) are `remote`.

### Where can the signer run?

Four places to put the guard, from least to most protected: on your laptop as you (fine for trying it), as a separate
user on the same machine, in a side container next to the agent, or on a separate server. The further it is from the
agent, the more the evidence is worth.

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

Nothing, if the agent is hostile. On a laptop the guard runs as you, and so does the agent, so the agent could reach the
guard's keys. Dev mode is for trying Tracekit and catching honest mistakes, and every file it makes says so.

Nothing against an agent that runs as you: it can read the key, stop the signer and re-sign the log. Dev runs say
`isolation: same-user` and their assurance stays `dev`. Dev mode is for trying Tracekit and catching honest mistakes.

### What does `tracekit doctor` check?

A health check for your setup. It even pretends to be the agent and tries to reach the keys, to prove they're really out
of reach. It gives advice, not evidence.

Whether a setup does what it claims: it switches to the agent's user and tries to reach the keys and store, and checks
key file modes, a Postgres role that can't update or delete, durability, witness freshness, clock skew and (for
Kubernetes) security contexts and shared volumes. Its output is advice, not evidence. More: [doctor](doctor.md).

## Storage, durability and speed

### How are records written?

One worker writes everything, in order, in batches. If the disk fails mid-batch, nothing half-written is kept, and once
it recovers the guard writes a note about the outage.

One writer thread takes batches of up to 512 requests, each in an undo log, assigns sequence numbers, hashes, signs,
and appends records and Merkle leaves together. On a disk error the batch rolls back, callers get `unavailable`, and
recovery writes a signed gap. Storage is a file store or Postgres with an insert-only role and a lock that allows one
writer.

### What survives a crash?

You choose: confirm once it's written (faster) or confirm once it's safely on disk (safest). In a test that killed the
guard 30 times under load, nothing confirmed was ever lost, and nothing went missing without a note.

With `ack-on-fsync`, a call returns only after the data is on disk; the default `ack-on-write` is faster and can lose
acknowledged records on power loss. In the durability test (`kill -9`, 30 rounds of 8 clients) no acknowledged record
was lost and nothing went missing silently. Power loss itself isn't tested. A background check runs daily and turns any
edit it finds into a signed `trace.tamper`.

### How much time does it add?

In the test, the guard adds under a millisecond per call, which you won't normally notice. The older laptop hooks cost
about 70 ms each, mostly starting Python. A real app ran about 1.6% slower.

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

Every framework plugs in with the same steps: ask, wait if needed, use the approval, run, report. A shared test suite
tries to trick every integration (old approvals, edited saved state, swapped ids), and all of them must refuse. One
line, tracekit.instrument(), wires up whatever frameworks you have installed.

Every adapter follows one contract: decide; for ask, request and wait; consume before every gated call; run the
arguments the consume returns; complete. A shared test suite runs each adapter against a fake signer and the real one,
including replayed snapshots, edited saved state, another run's approval and a rewritten call id, all of which must be
refused. `tracekit.instrument()` wires up the frameworks it finds and starts a dev signer if none is running.
More: [quickstart](quickstart-v2.md).

### What has running real agents taught?

Running real agents through Tracekit found real bugs. CrewAI quietly swallowed an error from the guard and ran a blocked
action anyway (closing a customer account) while the guard was down. The integration now says no directly instead of
raising an error, and any error now means block.

Running two open-source agents ([case study](case-study-oss-agents.md)) showed that CrewAI swallows a hook's exception
and runs the tool anyway: a denied `close_account` ran while the signer was down. Hooks now block by returning a
refusal, never by raising, and a gate must block on any error. It also showed streamed model responses weren't
captured, since fixed.

### How do the Claude Code hooks work?

Claude Code calls Tracekit before and after each tool. Before: Tracekit decides, and exit code 2 tells Claude Code to
block. After: the result is recorded. If anything goes wrong inside the hook, it blocks rather than letting the action
through.

`PreToolUse` asks the signer to decide: a deny exits with code 2, which blocks the call; an ask waits up to nine
minutes for a person; an allow runs. `PostToolUse` records the result and `SessionEnd` closes the run. Any hook error or
unreadable payload also exits 2. The Codex CLI, Cursor and Gemini CLI hooks are experimental.
More: [coding agents](coding-agents.md).

## Hard questions

### Who watches the signer?

Outside notaries (witnesses), an outside auditor (the monitor) and a public log (Rekor). They catch a dishonest guard
after the fact. Stopping one beforehand would need special secure hardware, which Tracekit doesn't claim.

Witnesses the operator doesn't control, a monitor on a host the operator doesn't run, and Rekor anchors. That detects a
dishonest signer; preventing one would need attested hardware, which Tracekit doesn't claim.

### What if the operator is malicious?

Whoever runs the guard holds its key, so they could rewrite their own logbook. That's only caught if an independent
notary and auditor are watching. Without them, the evidence is only as good as your trust in the operator, and Tracekit
says so openly.

Whoever holds the key can rewrite or fork the log, and records after the last cosigned checkpoint are unproven.
Detection needs an independent witness and a monitor, plus run-sets to show which runs exist. Without a witness, an
operator rewriting its own log is expected, not a vulnerability ([SECURITY.md](../SECURITY.md)).

### Can the agent forge events?

Yes, the agent can report things that never happened. Tracekit catches that only by comparing with a record kept outside
the agent, such as the model gateway's log.

With its own run token it can send well-formed calls that never happened, and the signer can't tell them apart. Only
reconciliation against a record kept outside the agent's process catches them (`reconcile.fabricated` from the LLM
gateway).

### Isn't a regex gate weak?

As a wall, yes. But it's predictable: anyone can re-check every decision later, which you can't do with an AI judge.
Tracekit's job is the evidence, not being the strongest wall. Use a sandbox as well.

As prevention, yes. It is deterministic, so a verifier can recompute every decision, which a model-based classifier
doesn't allow. Tracekit's contribution is evidence that the gate ran and what it saw; pair it with a sandbox to prevent
effects.

### Can the timestamps be trusted?

Times come from the guard's own clock, so treat them as approximate. Independent time comes from the witnesses' stamps
and the public timestamp on the hourly Rekor anchors.

Record times come from the signer host's clock. Independent time comes from witness cosignatures and the RFC 3161
timestamps on Rekor anchors, which the verify report shows as the earliest independent anchor. Clock skew is a signed
gap.

### What leaks?

The actual content is hidden behind sealed fingerprints. Some things still show: when things happened, how big they
were, how many there were. And the public Rekor anchors are permanent.

Arguments and results are commitments, but timing, sizes, counts and checkpoint cadence still show, Rekor entries are
public and permanent, and redaction works by pattern. More: [privacy](privacy.md#what-hashes-and-metadata-still-leak).

### Has it been reviewed?

Not by anyone outside yet, and the experiments were designed by the team itself.

Not externally yet ([review packet](review-packet.md)). The experiments are small, synthetic and written by the
authors.

## Design decisions

Each row is a choice the project made, and the simple reason behind it.

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

In short: tampering is caught every time once witnesses are used, the insider tricks tried were all caught, the guard is
fast, and the misses are reported openly.

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

Tracekit grew from a research paper in September 2026 to the 1.2 release in mid-October 2026.

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

Other tools help you watch agents or protect against them. Tracekit is the record that someone who doesn't trust you can
check. It works alongside them.

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

Nobody outside has reviewed it yet, the free public witness isn't switched on, it can't yet watch processes and
services, and some platforms are untested.

- An external review of the threat models.
- A deployed public witness, so independent witnessing needs no setup.
- Capture of processes and services (layers L4 and L5).
- Adversarial evaluation with real models, beyond the scripted attacks.
- The TypeScript SDK on npm.
- System mode validated on macOS and Windows.
- Performance numbers for separate-user and HTTPS signers on Linux.

Every known limit, with what to do about it: [limits](limits.md).
