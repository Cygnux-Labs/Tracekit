# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/Cygnux-Labs/Tracekit/security/advisories/new)
rather than a public issue. Include the Tracekit version (`tracekit --version`), your platform, and
steps to reproduce: the smallest ledger, bundle or command sequence that shows the problem.

## Supported versions

Security fixes are made for a release line, not a single build. A fix lands on `main` and is released as a
patch on every supported line.

| Version | Supported |
|---|---|
| 0.3.x (unreleased, `main`) | yes |
| 0.2.x | yes, until 90 days after 0.3.0 is released |
| < 0.2 | no |

Release candidates (`rcN`) are covered only until the final release of their line ships; upgrade to the
final release or a later patch. Bundles are a different matter: a bundle produced by any version must keep
verifying with every supported version, and a verifier that rejects or wrongly accepts an old bundle is a
security bug.

## Disclosure timeline

- **3 business days**: we acknowledge the report.
- **10 business days**: we confirm or dispute the issue and give a severity and a planned fix date.
- **90 days** from the report (or earlier, once a fix is released): coordinated public disclosure through a
  GitHub security advisory, crediting the reporter unless they ask otherwise.

If a fix needs longer, we agree a new date with the reporter before the 90 days run out. If the issue is
being actively exploited, we may publish an advisory with mitigations before a fix is ready.

## Safe harbour

We will not pursue or support legal action against anyone who, in good faith, researches and reports a
vulnerability under this policy. Good faith means: you test only against your own installation or data you
are authorised to use, you do not degrade service for others or access, modify or keep other people's data
beyond what is needed to show the issue, and you give us a reasonable chance to fix it before disclosing.
If a third party brings action over research that followed this policy, we will make it known that your
work was authorised.

## Scope

Tracekit proves what its capture path recorded and that the record has not changed since it was signed
and checkpointed. It does not prove intent, complete coverage, or that a reported tool result is real.
The full claim-by-claim analysis is in [docs/threat-model.md](docs/threat-model.md); the threat model has
not yet had an external review, so findings against it are especially welcome.

**In scope:** anything that lets an agent, or a process running as the agent's user, defeat the product's
security invariants:

- obtain or use the signing key, or assign or skip sequence numbers;
- make the signer or verifier trust something the agent supplies (isolation level, fail mode, gap or tamper
  records, approval identity, harness identity);
- lose events silently instead of producing a signed gap;
- make a tampered, truncated or fabricated ledger or bundle verify as `VERIFIED`;
- bypass the policy gate or the approval flow, or leak data the redaction should have removed;
- attacks on the witness, checkpoint, observer server, remote ingest, OTLP receiver and proxy code.

**Out of scope:**

- **The operator.** Whoever runs the signer host (root, or the `tracekit` service account) holds the key and
  can sign whatever they like. Tracekit gives **no protection against the operator unless checkpoints go to
  an independent witness** the operator cannot rewrite, and even then only for history before the last
  witnessed checkpoint. A report that the operator can forge or rewrite unwitnessed records is expected
  behaviour, not a vulnerability; a way to rewrite *witnessed* history without detection is in scope.
- Dev mode's same-user signer, which is labelled weaker in every bundle it produces.
- Vulnerabilities in the agent itself, its model provider, or its tools, unless they let the agent defeat
  one of the invariants above.
- Denial of service by a party that already controls the host.
