## What and why

## Checklist
- [ ] `make check` passes (lint, tests, build); `make test-ts` too if `sdk/typescript/` changed
- [ ] a regression test covers the change
- [ ] user-visible changes are described above (release notes are written at release time; don't edit `CHANGELOG.md`)
- [ ] docs updated if behaviour or a security claim changed (`docs/threat-model-laptop.md`,
      `docs/threat-model-server.md`)
- [ ] every commit is signed off (`git commit -s`, see `CONTRIBUTING.md`)

## Security invariants
- [ ] the agent still never holds a signing key or assigns sequence numbers
- [ ] nothing an agent-controlled process supplies (isolation level, fail mode, gap/tamper records,
      approval identity) is newly trusted by the signer or verifier
- [ ] gaps are still signed, never silent; a check that cannot run warns instead of passing
- [ ] no verification code is shipped inside a bundle

## Evidence format
- [ ] this change does not touch the frozen formats: v1 (`core.sig_message`, `ledger.make_record`, the v1 schema, how
      the verifier treats existing bundles) or the published v2 format
- [ ] or, if it does: the issue explicitly asks for it, existing bundles (including `docs/sample/` and
      `tests/fixtures/`) still verify, and the change is called out above
