# Threat model: laptop coding agents (v0.3)

Tracekit makes one claim:

> **Tracekit proves what its capture path recorded, and that the record has not changed since it was signed and checkpointed.**

It does **not** prove intent, complete coverage, or that a reported tool result is real. Every verifier report ends with that sentence.

Scope: coding agents on a developer's machine. Capture paths: Claude Code, Codex CLI, Cursor and Gemini CLI hooks;
the Python and TypeScript SDKs and the adapters built on them (calls made through the wrapper only); the model proxy and
the OpenTelemetry receiver (both experimental, opt-in). Platforms: dev mode (same-user signer) on Linux, macOS and
Windows; system mode (separate signer user) on Linux, with an experimental macOS port, because caller identity comes from
kernel peer credentials (`SO_PEERCRED`, `LOCAL_PEERCRED`). Dev mode gives integrity checks only, not isolation; on
Windows it also has no caller attestation.

## Two properties, kept apart

| Property | Question | What provides it |
|---|---|---|
| **Integrity** | Has the stored record changed since it was signed? | Hash chain, Ed25519 signatures, witnessed checkpoints |
| **Fidelity** | Does the record match what actually happened? | Only the capture paths: hooks, explicitly wrapped SDK calls, the model proxy (opt-in) and transcript prefix hashes. Partial, and labelled per path in `coverage.json` |

A bundle can pass every integrity check and still miss things. The verifier never prints "complete"; the best coverage summary is "clean on observed paths".

**The signer cannot tell a real event from a well-formed fake.** The agent's OS user can write to the signer's socket, so it can submit fabricated events and they will be signed. A valid signature means "tracekitd accepted this record from a caller with this OS user, at this position, and nobody has changed it since". It does not mean the hook produced it or that it describes something that happened. What makes fabrication visible is cross-checking independent paths (tool calls with no matching model exchange raise `capture.gap` when the proxy is on), not the signature.

**Harness binding narrows this (0.3).** With a registered harness (`tracekit init --harness`, Linux), the signer also checks which *program* sent each hook event, from the kernel's process tree (`/proc/<pid>/exe` of the sender's ancestors, which needs `CAP_SYS_PTRACE` for the signer), and binds each run to one harness instance (pid + start time). A run started, or an event written, by anything outside that harness instance is refused and recorded. A process the agent starts *from inside* the harness session (its own Bash tool) is a descendant of the real harness and is not refused. The registered binary must be root-owned; an agent CLI installed in the user's home directory cannot be registered, because the agent could replace it.

**SDK capture is opt-in per call.** `source: sdk` means an adapter submitted the event; it does not attest that the agent framework produced it or that every action was wrapped. SDK policy checks can block only operations executed inside `Tracer.tool()` (Python) or `tk.tool()` (TypeScript).

## Attackers

| Id | Attacker | Reach |
|---|---|---|
| **A1** | Compromised agent: a prompt-injected or misaligned model acting through its tools | The agent's OS user, from inside the harness session |
| **A2** | Compromised Tracekit hook process or SDK client | Runs as the agent's user, so reachable from A1 or by editing hook settings; controls everything the client sends |
| **A3** | Any non-root local account, including the human's account the agent runs under | Same as A2, plus that account's settings and other users' sockets |
| **A4** | Root on the signer host | Everything on the machine, including the signing key |
| **E** | The bundle exporter: whoever runs `tracekit export` and hands the bundle over | Chooses which runs and records go into a bundle and can edit the bundle file |

## What each attack comes to

**Detected**: the verifier fails, or reports a signed gap, tamper record or warning naming it. **Not detected**: a bundle
can verify without showing it. **Out of scope**: Tracekit does not try.

| Attacker | Attack | Result | How, and where it is tested |
|---|---|---|---|
| A1 | Edit, delete or reorder records already signed | detected | Chain and signatures (E1, E4); in system mode the ledger is not writable by the agent's user (`Isolation` tests) |
| A1 | Dev mode: rewrite or delete the whole ledger and key, with an independent witness holding checkpoints | detected | History up to the last witnessed checkpoint fails `--witness` ("chain rebuilt after checkpointing") |
| A1 | Dev mode: rewrite or delete the whole ledger and key, with no witness the agent cannot write | not detected | The same user can read the key and the ledger; a local git witness in the agent's reach adds nothing |
| A1 | Run a tool call that a deny rule matches | detected | Blocked before it runs, with a signed `policy.decision` (E3) |
| A1 | Reword a command so no deny rule matches | not detected | Rules are regex tripwires; E3 lists the misses |
| A1 | Fabricate events into the live run from inside the harness session, with the model proxy on | detected | `capture.gap` `proxy_missing` |
| A1 | Fabricate events into the live run from inside the harness session, without the proxy | not detected | Signed as coming from the agent's user |
| A1 | Start a second fabricated run from inside the harness session | detected | `concurrent_run` gap (E8.7) |
| A1 | Start a run, or write into the live run, from a process outside the registered harness | detected | Refused and recorded (E8.6, E8.8; Linux system mode with `--harness`) |
| A1 | Fake command output by shadowing commands (shell functions, `PATH`) | not detected | Tool results are whatever the harness reports; visible shadowing is flagged `shell_shadowing` / `env_tamper` |
| A1 | Act inside subprocesses or background processes | not detected | Only the command line is observed (flagged `background_spawn`, `network`) |
| A1 | Edit, truncate or delete the harness transcript before the session's last hook | detected | `trace.tamper` (`deleted`, `truncated`, `edited`) at the next hook |
| A1 | Anything after the session's last hook, including transcript edits | not detected | Nothing runs to see it |
| A1 | Approve its own held call outside dev mode | detected | Refused: the approver must be a different OS user or a configured approver |
| A1 | Approve its own held call in dev mode | detected | Allowed (`init --dev` sets `allow_same_user_approval`), recorded with `same_user`, and the verifier's "approvals" check warns |
| A1 | Execute a held call with arguments other than the approved ones | not detected | An approval is recorded against the held call's id; it is not yet bound to the exact arguments |
| A1 | Disable or remove the hooks, with the model proxy on | detected | `capture.gap` `hook_missing` |
| A1 | Disable or remove the hooks, without the proxy | not detected | Shows only as a run with no `run.end` (`stale_run` gap after `stale_after_s`) |
| A1 | Stop the signer, `fail_mode: closed` | detected | Tool calls are blocked while the signer is down (E8.4) |
| A1 | Stop the signer, `fail_mode: open` | not detected | Calls made meanwhile are not recorded; `run.start` records `fail_mode=open` and the verifier warns |
| A2 | Send false tool inputs, results or transcript marks | not detected | The signer records what the client sends; only the proxy cross-check covers calls the model requested |
| A2 | Tamper with its own client state (counters, transcript acks) | detected | `capture.gap` / `prefix_unverifiable` |
| A2 | System mode: redirect events to a decoy signer, or swap the policy through the environment | detected | Only the root-owned `/etc/tracekit/client.json` is read (E8.1, E8.2, E8.5) |
| A3 | Write events into another user's run | detected | The run is bound to the uid that started it; refusals are recorded and `verify` reports `VERIFIED WITH GAPS` (E8.3, `tests/test_hotfix_021.py`) |
| A3 | System mode: read the key or change the ledger | detected | Both are owned by the `tracekit` user; any change that gets through fails the chain or signatures |
| A3 | Remove the hooks from Claude Code user or project settings | not detected | As "disable the hooks" above; `init --managed` puts them in admin-managed settings this account cannot edit |
| A4 | Re-sign history before the last checkpoint on a witness it cannot rewrite | detected | `--witness` ("chain rebuilt after checkpointing"); pin the key with `--key` |
| A4 | Re-sign records after the last witnessed checkpoint, or any run with no independent witness | not detected | Root holds the key |
| A4 | Other host compromise (reading memory, replacing the signer, faking the clock) | out of scope | Needs key storage outside the OS (`--signer-cmd`) or the proxy on another machine |
| E | Edit, drop or reorder records inside a bundle | detected | Chain, signatures, contiguous `seq` |
| E | Cut a run's tail, with `--witness` and a witnessed checkpoint after `run.end` | detected | "run tail witnessed" / "records truncated" |
| E | Cut a run's tail, without a witness | not detected | The verdict warns that the tail is unwitnessed or has no `run.end` |
| E | Replace a selected record with an elided stub | not detected | v1 stubs are not bound to a run; the verifier warns "run completeness unproven" |
| E | Edit `manifest.json` or a policy snapshot | detected | "files match manifest", "policy hash consistent" |
| E | Replace `replay.html` | detected | Warned; the verdict never uses it |
| E | Forge a whole bundle with a fresh key, verified with `--key` or `--witness` | detected | Wrong key, or no checkpoints from the pinned key |
| E | Forge a whole bundle with a fresh key, verified without either | not detected | The verdict says `UNANCHORED` (internally consistent only) |
| E | Never export a run | out of scope | A bundle covers the runs it contains |
| any | Intent, the model's internal reasoning, when something happened | out of scope | `ts` comes from the host; `seq` and the chain prove order only |

## Trust roots for verification

A `.tkb` bundle carries its own public key and checkpoints, so on its own it only proves **internal consistency**. `tracekit verify` reports a `trust root` check and prints `UNANCHORED` when nothing outside the bundle vouches for it. Anchor it with either:

- `--key <signer.pub>` (or `--key ed25519:<kid>`): the key you expect, obtained out of band;
- `--witness <copy>`: an independent witness holding checkpoints by that key.

Without either, a whole bundle forged with a fresh key verifies as consistent.

## Invariants

| ID | Invariant | Where |
|---|---|---|
| I1 | The agent never holds the signing key | System mode: `tracekitd` owns `keys/signer.key` (0600, separate user). Dev mode: not held |
| I2 | The agent's OS user cannot change the ledger | System mode: ledger owned by the signer user. Dev mode: not held |
| I3 | Every record is signed; the signature covers `(hash, prev_hash, seq)` | `ledger.py`, `core.sig_message` |
| I4 | The head is checkpointed to witnesses | git / file / HTTP witnesses (Rekor is experimental and off by default). Only a witness the attacker cannot rewrite counts |
| I5 | Lost events are visible, not silent | per-run, per-stream counters; `capture.gap` on jumps, regressions, out-of-order lifecycle, late witnesses |
| I6 | Fail mode is explicit and recorded | `fail_mode` in policy and every `run.start`; `closed` blocks tool calls while the signer is down |

## README claims, mapped

| README claim | Where above |
|---|---|
| Signer as a separate OS user | A3 rows; I1, I2 (Linux system mode, experimental on macOS) |
| Hash-chained, Ed25519-signed, checkpointed to a witness | I3, I4; A4 and dev-mode A1 rows (the witness must be out of the attacker's reach) |
| Anyone can verify offline | Trust roots: needs `--key` or `--witness` to be anchored |
| Blocks listed dangerous actions before they run | A1 deny rows; rules are evadable tripwires (`policy/default.yaml`) |
| Detects edits to the agent's transcript | A1 transcript rows; not after the last hook |
| Detects disabled hooks / proxy bypass | A1 hook rows; needs the proxy |
| Held actions need approval from outside the session | A1 approval rows; not bound to the exact arguments yet |
| Reasoning is self-reported, optional, off by default | Fidelity: `source=transcript` is harness-reported, lower trust |

## Remote SDK clients

[Remote ingestion](remote-ingest.md) adds a trust boundary: a client on another machine, authenticated by a bearer
token. It is treated like the local SDK, trusted only for what it sends. The gateway forces `source=sdk`, namespaces
the run id, accepts only the SDK's event types, ignores the client's claims about host and isolation, and refuses
approvals. A stolen token lets an attacker write plausible `sdk` events into that client's runs until it is revoked;
it does not let them forge hook, proxy or transcript evidence or touch existing records.

## Open problems

1. **Faked command output.** Needs OS-level capture (sandbox, audit).
2. **Actions inside subprocesses and background processes.** Only the command line is observed.
3. **Activity after the last hook**, including transcript edits after it.
4. **Host compromise (A4).** Needs key storage outside the OS (TPM / remote signer) or the proxy on another machine.
5. **Unsigned manifest.** `manifest.json` is an index, not evidence; the verifier recomputes everything from signed records and checkpoints.
6. **Witness independence.** A witness the attacker can also rewrite adds nothing against A4, or against A1 in dev mode.
7. **Approvals are not bound to arguments.** An approval names the held call, not its exact input.
8. **Not externally reviewed yet.** Issue #1 asks for a reviewer outside the project to read this document.
