# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/Cygnux-Labs/Tracekit/security/advisories/new)
rather than a public issue. Include the Tracekit version (`tracekit --version`), your platform, and
steps to reproduce.

## Disclosure timeline

- **3 business days**: we acknowledge the report.
- **10 business days**: we confirm or reject it and share an initial severity assessment.
- **90 days** from the report: the default limit for a fix and coordinated public disclosure. We will
  agree an earlier date for a fix that ships sooner, or a later one if a fix needs it and you agree.
- Once a fix is released we publish a GitHub security advisory and credit you, unless you ask us not to.

If a vulnerability is being actively exploited we may disclose sooner, and will tell you first.

## Supported versions

| Version | Supported |
|---|---|
| Latest stable release (0.x, newest minor) | Yes: security fixes |
| Older stable releases | No: upgrade to the latest stable release |
| Release candidates and pre-releases | No: test builds only; fixes land in the next release |
| `main` | Development branch: reports welcome, no backported fixes |

Until the first stable release ships, fixes land on `main` and in the next release; no older line is
patched.

## Scope

Tracekit proves what its capture path recorded and that the record has not changed since it was signed
and checkpointed. It does not prove intent, complete coverage, or that a reported tool result is real.
The full claim-by-claim analysis is in [docs/threat-model.md](docs/threat-model.md); the threat model has
not yet had an external review, so findings against it are especially welcome.

In scope: bypasses of the signer, ledger, witness, bundle verification, policy gate, approval flow,
observer server and redaction; anything an agent-controlled process can do to make a bundle verify that
should not, or to hide a gap.

Out of scope:
- **The operator.** Whoever runs the signer host (root, or the `tracekit` service account) holds the
  signing key and can sign any history. Tracekit gives no protection against the operator unless
  checkpoints go to an independent witness the operator cannot rewrite, and then only for history that
  was already witnessed. A report that the operator can forge records without such a witness is
  expected behaviour, not a vulnerability.
- An attacker who already has root on the signer host (the same caveat; see L4 in the threat model).
- Dev mode's same-user signer, which is labelled weaker in every bundle.
- Denial of service against a local signer by a user who can already stop it.

## Safe harbour

We will not pursue or support legal action against you for security research done in good faith that:

- stays within the scope above and targets your own installations or test systems;
- avoids privacy violations, data destruction and service disruption;
- does not access, keep or share data that is not yours beyond what is needed to show the problem;
- gives us reasonable time to fix the issue before any public disclosure, following the timeline above.

If legal action is started by a third party against you for such research, we will make it known that
your work was authorised under this policy.
