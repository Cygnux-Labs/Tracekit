# Signing (v0.2)

## Where the key lives

| Mode | Command | Key | Runs as |
|---|---|---|---|
| System (Linux; macOS experimental) | `sudo tracekit init --user <agent-user>` (macOS: add `--experimental-macos`) | `/var/lib/tracekit/keys/signer.key` (0600, dir 0700) | OS user `tracekit` under systemd (macOS: `_tracekit` under launchd) |
| Dev (any OS) | `tracekit init --dev` | `~/.tracekit-signer/keys/signer.key` | your own user. **Bundles record `signer_isolation: same-user` and the verifier warns** |

The public key is `keys/signer.pub`; it is copied into every bundle. The key id is `ed25519:` + the first 16 hex characters of `sha256(pubkey)`.

**Why a separate OS user and not the OS keychain.** A keychain protects the key's bytes, but it signs whatever a process in the user's session asks it to. An agent running in that session could ask it to sign forged or rewritten records, and could still delete or rewrite the ledger file. A separate user owns both the key and the ledger, so the agent's user can only append through the socket and can never rewrite what is there.

**Why system mode needs kernel peer credentials.** The signer identifies each caller with `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` and `LOCAL_PEERPID` (macOS): that is how it attests `os_user`, refuses `source=proxy` events from anyone but its own user, and checks approvers. System-mode installation is refused on platforms without them (Windows), and on macOS it needs `--experimental-macos` until it is validated on hardware ([platforms](portability.md)). Where there are no peer credentials, dev mode uses an authenticated loopback TCP transport, but caller identity remains unattested and proxy events and approvals are explicitly untrusted. A manually configured Unix socket is refused when peer credentials are unavailable.

## Keys in hardware (external signers)

```bash
tracekit init --dev --signer-cmd "/usr/local/bin/tk-hsm-signer --slot 0" --signer-pub hsm-signer.pub --key-assurance hsm
```

With an external signer the private key never enters tracekitd: a helper process (TPM, HSM, smart card, enclave, KMS)
signs. The protocol is one line per request on the helper's stdin, `sign <hex>`, answered with `ok <hex signature>` or
`err <reason>`; the helper is started once and kept running. Every signature is verified against the configured public
key before use, so a helper that signs with another key or returns garbage stops the signer instead of corrupting the
ledger, and a failed signature is reported to clients as a retryable write failure with the ledger unchanged.
`examples/ext_signer.py` is a reference helper; replace its two marked lines with calls to your device.

`--key-assurance` (tpm, hsm, tee, kms, smartcard) is signed into every checkpoint and shown by `tracekit verify` as the
**signing key** check; a file key is reported as a warning. The assurance is the operator's statement: Tracekit cannot
attest where a key lives, so pair it with the device's own attestation where it offers one. Re-running `init` keeps a
configured external signer (dropping it would silently switch to a new file key and fork the chain).

`--key-attestation FILE` attaches that attestation: a TPM quote, an enclave (Nitro, TDX, SEV-SNP) attestation document,
or a KMS key's metadata export, up to 1 MiB. Its SHA-256 is signed into every checkpoint, `tracekit export` puts the
document in the bundle as `attestation/<sha256>.bin`, and `verify` reports it under **signing key**, warning if a
checkpoint names a document the bundle does not carry. Tracekit checks only that it is the document the checkpoints
name. Whether it is genuine and binds this public key is checked with the vendor's tools (certificate chain, PCR or
measurement values, the key in the user data); the run and the evidence for it now travel together.

```bash
tracekit init --dev --signer-cmd "/usr/local/bin/tk-nitro-signer" --signer-pub /etc/tracekit/signer.pub \
  --key-assurance tee --key-attestation /etc/tracekit/nitro-attestation.cbor
```

## Cryptography

Signing and key generation use the [`cryptography`](https://cryptography.io) package (a required dependency; constant-time, widely reviewed). Verification uses it too when installed, and otherwise a small pure-Python RFC 8032 verifier, so `tracekit verify` runs with only the standard library. Verification handles public data only, so the fallback's lack of timing hardening does not matter there. Tracekit never signs with the pure-Python code; it is kept only to check the RFC 8032 test vectors.

## Record format

```json
{"v": 1, "event": {...}, "hash": "<sha256(canon(event))>", "sig": "<b64 Ed25519>", "kid": "ed25519:…"}
```

- `canon` = JSON with sorted keys, compact separators, UTF-8 (no ASCII escaping).
- The signature covers `canon({"hash": H, "prev_hash": P, "seq": N})`, not the event body. That lets a bundle **elide** records from other runs (keeping only `seq`, `hash`, `prev_hash`, `sig`) while the verifier still checks the full chain and counter.

## What the signer checks before signing

The socket accepts `status`, `append`, `checkpoint` (adds a checkpoint, nothing else) and the approval operations. There is no delete, rewrite or key export. On `append` it:

1. validates the event against `tracekit/schema/tracekit.event.v1.json`; failures are rejected **and** recorded as an `error` event;
2. refuses `source: signer` from any client; system mode accepts `source: proxy` only from its own OS user, while dev mode's authenticated local transport is explicitly same-user and untrusted;
3. sets `seq`, `prev_hash` and `ts_signed` itself (the client cannot choose them), and an `id` if the client sent none;
4. on `run.start`, replaces `os_user` with the caller's user from `SO_PEERCRED` and sets `os_user_attested: true`;
5. checks the per-run, per-stream client counter and writes `capture.gap` on a jump, a regression, events before `run.start` or after `run.end`;
6. stores any attached policy under its hash, after checking it matches the hash the event claims (`run.start.policy.hash`, or `policy.decision.policy_hash` when the policy changed mid-run); a decision naming a policy that was never recorded gets a `capture.gap` (`policy_unrecorded`);
7. compares the attached transcript mark with the previous one and writes `trace.tamper` on deletion, truncation or edits;
8. appends under an exclusive lock, fsyncs, and checkpoints every N records and at `run.end`.

**It cannot tell a real event from a well-formed fake.** Anything that can write to the socket as the agent's user can submit plausible events and they will be signed. Ordering, counters and schema checks catch sloppy forgeries; independent capture paths (proxy vs hook cross-check) are what catch careful ones.

**Generic SDK events are agent-reported.** The signer records `source: sdk` and can attest the connecting OS user when peer credentials are available, but it cannot verify which framework produced the event or whether every tool call was wrapped. An SDK integration that omits a call creates no event; policy enforcement applies only to calls routed through `Tracer.tool()`.

## What a signature proves, per attacker level

(levels as in [threat-model.md](threat-model.md))

| Level | A valid signature + a checkpoint on an independent witness means |
|---|---|
| L1 compromised agent / L2 compromised hook / L3 compromised user account (system mode) | tracekitd accepted this record from a caller with the recorded OS user, at this position, and nobody has changed, removed or reordered it since. It does **not** mean the event is true: the agent's user could have sent it. A tool call backed by a matching proxy-recorded model exchange is much stronger evidence than one without |
| Same, dev mode (signer is the agent's user) | Only that the file has not changed since signing by someone without the key. The agent could have held the key, so it proves little |
| L4 root | Records up to the latest witnessed checkpoint are unchanged. Later records, or runs with no checkpoint, could have been fabricated with the real key |
| Harness itself lying | Nothing about whether the harness told the truth |

## Key lifecycle

- **Create**: at `init`, as the signer user. Never printed or sent anywhere.
- **Distribute**: publish `signer.pub` (or its key id) where reviewers can get it independently of any bundle, e.g. in the witness repository's README. Reviewers pin it with `tracekit verify --key <signer.pub>`; without a pinned key or an independent witness the verifier reports the bundle as `UNANCHORED`.
- **Rotate**: stop the service, move `keys/` aside, restart. A new `kid` appears in checkpoints; old bundles still verify against the old public key. Keep and publish old public keys so a verifier can tell a rotation from a forgery.
- **Revoke**: publish the revoked key id and the last checkpoint seq you trust for it (commit it to the witness repository). Treat any record signed by that key after that checkpoint as untrusted. There is no online revocation check in v0.2; the verifier trusts exactly the key you pin.
- **Backup**: optional; losing the key does not affect existing bundles.
