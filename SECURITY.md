# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/Cygnux-Labs/Tracekit/security/advisories/new)
rather than a public issue. Include the Tracekit version (`tracekit --version`), your platform, and
steps to reproduce. You can expect an acknowledgement within a few days.

## What Tracekit does and does not protect

Tracekit proves what its capture path recorded and that the record has not changed since it was signed
and checkpointed. It does not prove intent, complete coverage, or that a reported tool result is real.
The full claim-by-claim analysis is in [docs/threat-model.md](docs/threat-model.md); the threat model has
not yet had an external review, so findings against it are especially welcome.

In scope: bypasses of the signer, ledger, witness, bundle verification, policy gate, approval flow,
observer server and redaction. Out of scope: an attacker who already has root on the signer host
(documented in the threat model), and dev mode's same-user signer (labelled weaker in every bundle).

## Supported versions

Only the latest release candidate or release receives fixes.
