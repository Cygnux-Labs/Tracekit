# Threat-model review packet

For an outside reviewer. The goal is to find where Tracekit's claims are wrong or overstated, not to approve it.
[Issue #1](https://github.com/Cygnux-Labs/Tracekit/issues/1) tracks the review.

## What to read, in order

1. `README.md`: the claims as a user reads them, and the "Limits" section.
2. `docs/threat-model-laptop.md`: attackers A1-A4 and the bundle exporter, trust roots, invariants, the claim-to-invariant table.
3. `docs/signing.md`, `docs/witnesses.md`, `docs/privacy.md`, `docs/remote-ingest.md`.
4. Code: `tracekit/daemon.py` (the signer), `tracekit/ledger.py`, `tracekit/bundle.py` (the verifier),
   `tracekit/policy.py`, `tracekit/hook.py`, `tracekit/ingest.py`, `tracekit/rekor.py`.
5. `tests/test_v02.py`, `tests/test_hardening.py`: what is claimed to be tested.

## The claims to attack

| # | Claim | Where to look |
|---|---|---|
| 1 | In system mode a user who is not the signer's user cannot write, rewrite or delete ledger records | `ledger.py` ownership, `install.py init_system`, threat model A1/A3 |
| 2 | Records are hash-chained and signed, so edits, deletions, reordering and forgery are detected | `core.event_hash`, `ledger.make_record`, `bundle._verify` |
| 3 | An off-host witness detects truncation and a full re-sign by a key holder | `witness.py`, `bundle._verify` step 4, eval E1 |
| 4 | Tool calls matching a deny rule never execute (hook mode) | `hook.py`, `policy.py`, fail modes |
| 5 | Held calls cannot be approved from inside the agent's own session | `daemon._self_approval_reason` |
| 6 | The verifier reports what it could not check (unanchored, coverage gaps) instead of passing | `bundle.Report`, `coverage.py` |
| 7 | The canonical JSON in Python and in the replay page agree | `core.canon`, `replay.py`, `ui/terminal.html` |
| 8 | A remote SDK client cannot forge hook/proxy/transcript evidence or write into another run | `ingest.sanitize`, daemon source rules |
| 9 | Redaction keeps secrets out of recorded content under the default settings | `privacy.py`, `docs/privacy.md` |

## Questions we most want answered

- What can an attacker at each of A1-A3 do that the document says they cannot?
- Which claim fails if the signer's user and the agent's user share a group, a container or a sudo rule?
- Is any verdict wording stronger than what was checked?
- What in the replay page or bundle format could mislead a non-expert reading it?
- Are the policy rules worth keeping as a default, given the evasions listed in `docs/evaluation.md`?

## Known limits you do not need to rediscover

The README's "Limits and not done yet" and the threat model's "Open problems": faked command output, actions
inside subprocesses, activity after the last hook, host compromise (A4), unsigned manifest, witness independence,
host clocks. macOS system mode and the Rekor witness are experimental and not validated on real services.

## How to report

Privately, per `SECURITY.md`. A short written finding with the claim number, the scenario and a reproduction
(a bundle or a command sequence) is ideal.
