# Threat model (v0.2)

Tracekit makes one claim:

> **Tracekit proves what its capture path recorded, and that the record has not changed since it was signed and checkpointed.**

It does **not** prove intent, complete coverage, or that a reported tool result is real. Every verifier report ends with that sentence.

Scope: Claude Code on **Linux**. System mode (separate signer user) is Linux-only in v0.2 because caller identity comes from `SO_PEERCRED`; dev mode runs anywhere but gives integrity checks only, not isolation.

## Two properties, kept apart

| Property | Question | What provides it |
|---|---|---|
| **Integrity** | Has the stored record changed since it was signed? | Hash chain, Ed25519 signatures, witnessed checkpoints |
| **Fidelity** | Does the record match what actually happened? | Only the capture paths: hooks, the model proxy (opt-in) and transcript prefix hashes. Partial, and labelled per path in `coverage.json` |

A bundle can pass every integrity check and still miss things. The verifier never prints "complete"; the best coverage summary is "clean on observed paths".

**The signer cannot tell a real event from a well-formed fake.** The agent's OS user can write to the signer's socket, so it can submit fabricated events and they will be signed. A valid signature means "tracekitd accepted this record from a caller with this OS user, at this position, and nobody has changed it since". It does not mean the hook produced it or that it describes something that happened. What makes fabrication visible is cross-checking independent paths (C4: tool calls with no matching model exchange raise `capture.gap` when the proxy is on), not the signature.

## Attacker levels (as defined in issue #1)

| Level | Can forge | Can hide | Can alter | Tracekit still guarantees |
|---|---|---|---|---|
| **L1 Compromised agent** (a prompt-injected or misaligned model acting through its tools, as the agent's OS user) | Well-formed events sent straight to the socket (signed as coming from the agent's user); fake command output by shadowing commands (flagged `shell_shadowing` / `env_tamper`, not detected) | Activity inside subprocesses and background processes (flagged `background_spawn`, `network`); anything after the last hook | The harness transcript (detected at the next hook as `trace.tamper`: deleted, truncated or edited); nothing already signed | Records it accepted cannot be edited, deleted, reordered or truncated without detection (signer-owned files, tested in `Isolation`); the key cannot be read; the signer cannot be stopped (Linux, separate user); policy denies run before the tool; approvals cannot come from its own OS user outside dev mode; fabricated tool calls surface as `proxy_missing` when the proxy is on |
| **L2 Compromised Tracekit hook process** (the hook runs as the agent's user, so this is reachable from L1 or by editing hook settings) | Any event the hook would send, including false tool inputs, results and transcript marks | Tool calls, by not reporting them or by removing the hooks (edits to harness config are flagged `harness_config`) | Its own client state (counters, transcript acks), which produces `capture.gap` / `prefix_unverifiable` rather than silence | With the proxy on, a tool call the model requested but no hook reported raises `hook_missing`; a hook event with no model exchange raises `proxy_missing`. Without the proxy, a disabled hook shows only as a run with no `run.end` (`stale_run`). Already-signed records stay protected |
| **L3 Compromised user OS account** (the human's account the agent runs under, including anything that can run as that user) | Same as L2, plus same-user approvals in dev mode (labelled "not trustworthy") | Same as L2; can also change Claude Code user/project settings (use `--managed` so hooks sit in admin-managed settings it cannot override) | Nothing owned by the `tracekit` user | Same as L1: the ledger, key and signer are out of reach of that account; checkpoints on an independent witness pin history. Approvals must come from a different OS user or a configured approver |
| **L4 Compromised host (root)** | Anything: it can read the key and sign arbitrary records | Anything not yet witnessed | The whole local ledger, re-signed with the real key | Only what was already published to a witness it cannot rewrite: rewriting history before the last witnessed checkpoint fails verification ("chain rebuilt after checkpointing"); records after that checkpoint, or runs with no checkpoint, are not protected. Pin the key with `verify --key` and keep the witness off this host |

## Trust roots for verification

A `.tkb` bundle carries its own public key and checkpoints, so on its own it only proves **internal consistency**. `tracekit verify` reports a `trust root` check and prints `UNANCHORED` when nothing outside the bundle vouches for it. Anchor it with either:

- `--key <signer.pub>` (or `--key ed25519:<kid>`): the key you expect, obtained out of band;
- `--witness <copy>`: an independent witness holding checkpoints by that key.

Without either, a whole bundle forged with a fresh key verifies as consistent.

## Invariants (Phase 1)

| ID | Invariant | Where |
|---|---|---|
| I1 | The agent never holds the signing key | `tracekitd` owns `keys/signer.key` (0600, separate user) |
| I2 | The agent's OS user cannot change the ledger | ledger owned by the signer user; clients only talk over a Unix socket |
| I3 | Every record is signed; the signature covers `(hash, prev_hash, seq)` | `ledger.py`, `core.sig_message` |
| I4 | The head is published outside the machine | checkpoints to git / file witnesses (Rekor off, not implemented) |
| I5 | Lost events are visible, not silent | per-run, per-stream counters; `capture.gap` on jumps, regressions, out-of-order lifecycle, late witnesses |
| I6 | Fail mode is explicit and recorded | `fail_mode` in policy and every `run.start`; `closed` blocks tool calls while the signer is down |

## README claims, mapped

| README claim | Row above |
|---|---|
| Written by a signer running as a separate OS user | L1/L3 guarantees; I1, I2 (Linux system mode only) |
| Hash-chained, Ed25519-signed, checkpointed to an external witness | I3, I4; L4 (witness must be off-host) |
| Anyone can verify offline | Trust roots: needs `--key` or `--witness` to be anchored |
| Blocks listed dangerous actions before they run | L1 guarantees; rules are evadable tripwires (`policy/default.yaml`) |
| Detects edits to the agent's transcript | L1 "can alter"; not after the last hook |
| Detects disabled hooks / proxy bypass | L2 row; needs the proxy |
| Held actions need approval from outside the session | L1/L3: only a different OS user counts outside dev mode |
| Reasoning is self-reported, optional, off by default | Fidelity: `source=transcript` is harness-reported, lower trust |

## Open problems

1. **Faked command output.** Tool results are whatever the harness reports; shell-function or PATH tricks can spoof them. Needs OS-level capture (sandbox, audit) — deferred to v0.3+.
2. **Actions inside subprocesses and background processes.** Only the command line is observed.
3. **Activity after the last hook**, including transcript edits after it.
4. **Host compromise (L4).** Needs key storage outside the OS (TPM / remote signer) or the proxy on another machine.
5. **Unsigned manifest.** `manifest.json` is an index, not evidence; the verifier recomputes everything from signed records and checkpoints.
6. **Witness independence.** A witness the attacker can also rewrite adds nothing against L4.
7. **Clock.** Timestamps come from the host; `seq` and the chain give order, `ts` does not prove when.
8. **Not externally reviewed yet.** Issue #1 asks for a reviewer outside the project to read this document.
