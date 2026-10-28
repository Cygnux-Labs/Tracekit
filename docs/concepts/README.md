# How Tracekit works

These pages explain Tracekit's concepts, one topic per page, in an order that builds up. They are written for teams
adopting, running or auditing Tracekit: read them in order the first time, then come back to a page when you need it.
Each page starts with what the part is for, explains how it works, says where it stops, and links to the reference
pages and code with the full detail.

Everything here describes Tracekit 1.5.0. Parts marked experimental work and are tested, but may change between
releases and get less hardening than the stable core ([what's stable](../support.md)).

| | Page | What it explains |
|---|---|---|
| 1 | [Overview](overview.md) | The problem, the moving parts, and what a verified run proves |
| 2 | [The life of a tool call](tool-call-lifecycle.md) | Runs, deciding and completing a call, closing a run, checkpoints, export, the RPC surface |
| 3 | [The evidence format](evidence-format.md) | Records, signatures, the two chains, the Merkle tree, commitments, keys, bundles, format versions and the `ext` slot |
| 4 | [Verification and assurance](verification.md) | What `tracekit verify` checks, verdicts, assurance levels, trust configs, the browser page |
| 5 | [Witnesses and monitoring](witnesses-and-monitoring.md) | Independent cosigners, rollback detection, Rekor anchors, the monitor |
| 6 | [Policy](policy.md) | Rules, tool classes, how commands are read, per-command rules, packs (the strict pack among them), remedies, determinism |
| 7 | [Approvals](approvals.md) | Holding a call for a person, argument binding, channels, agent approvers |
| 8 | [Detection and containment](containment.md) | Patterns across calls, holds, quarantine, cooldowns, alerts |
| 9 | [Capture and completeness](capture-and-completeness.md) | Tiers, capture layers, reconciliation, verified tool results, kernel sensors and sandboxes, gaps, fail modes, the coverage matrix |
| 10 | [Custody](custody.md) | The tool executor, MCP gateway, LLM gateway and egress observer |
| 11 | [Provenance and `tracekit why`](provenance-and-why.md) | Values from untrusted content, what was asked, said and done, and finding the input that caused an action |
| 12 | [Deployment and isolation](deployment.md) | Where the signer runs, how isolation is measured, `tracekit doctor` |
| 13 | [Storage, durability and performance](storage-and-performance.md) | The single writer, backends, crash behaviour, speed |
| 14 | [Integrations](integrations.md) | The adapter contract, `tracekit.instrument()`, frameworks, coding-agent hooks |
| 15 | [Security model](security-model.md) | Adversaries, invariants, hard questions, design decisions, what isn't done |

## Words these pages use

| Word | Meaning |
|---|---|
| Agent | Your program: a model plus the tools it can call |
| Signer | Tracekit's service that decides each tool call and writes the log. The only component that holds signing keys |
| Run | One job by an agent, from start to finish. Every record belongs to a run |
| Run token | What the agent's client holds for one run: it can ask the signer to record things, but can't sign anything |
| Record | One signed entry in the log: a decision, a result, a gap, an approval |
| Hash | A fingerprint of data (SHA-256). Changing one byte changes it completely |
| Signature | A seal only the private key can make and anyone can check with the public key (Ed25519) |
| Hash chain | Each record carries the hash of the one before it, so a removed or edited record breaks the chain |
| Merkle tree | A tree of hashes that sums up the whole log in one root hash, and proves a record is in it cheaply |
| Checkpoint | A signed statement: "the log has N records and its root is R" |
| Witness | An independent party that cosigns checkpoints after checking the log only grew |
| Monitor | An independent reader that checks the log's content and signs a report |
| Bundle (`.tkb`) | One run's records and proofs in a zip, verifiable offline |
| Trust config | The keys and witnesses the person verifying chooses to trust. Never inside a bundle |
| Commitment | A keyed hash that hides a value but can be opened for a single record |
| Gap | A signed record saying something is missing, and what |
| Tier (T1, T2, T3) | Where evidence came from: inside the agent's process, outside it, or imported |
| Effect | Something the agent's processes did that an observer or kernel sensor saw: a host reached, a process started, a file written |
| Finding | A signed opinion about a run, such as an action nobody asked for. Never part of the run's integrity |
| Assurance | Who vouches for a run's checkpoint: no one, the operator, independent witnesses, plus a monitor |
| Isolation | Who could reach the signer's keys and log, as the signer measured it |

## Reference pages

The concept pages link into these for exact syntax and fields: [architecture](../architecture.md),
[format v2](../format-v2.md), [reading a verify report](../verdicts.md), [policy reference](../policy-v2.md),
[approvals](../approvals.md), [incidents](../incidents.md), [findings](../findings.md), [deployment](../deploy.md),
[guarantees](../guarantees.md), [evaluation](../evaluation.md), [threat model (laptop)](../threat-model-laptop.md),
[threat model (server)](../threat-model-server.md) and [every known limit](../limits.md).
