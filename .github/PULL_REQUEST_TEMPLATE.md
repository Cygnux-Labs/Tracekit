## What and why

## Checklist
- [ ] `make check` passes (lint, tests, build)
- [ ] a regression test covers the change, and fails without it
- [ ] `CHANGELOG.md` updated under "Unreleased" for user-visible changes
- [ ] docs updated if behaviour or a security claim changed (`docs/threat-model.md`)
- [ ] every commit is signed off (`git commit -s`, see `CONTRIBUTING.md`)

## Security invariants
Tick each that still holds, or explain below why the change affects it.
- [ ] the agent never holds a signing key or assigns sequence numbers
- [ ] nothing an agent-controlled process supplies (isolation level, fail mode, gap or tamper records,
      approval identity, harness identity) is trusted by the signer or verifier
- [ ] lost events produce a signed gap, never a silent one
- [ ] no verification code is shipped inside a bundle

## Evidence format
- [ ] this change does not touch the evidence format (`core.sig_message`, `ledger.make_record`, the v1
      schema, bundle layout, or how the verifier treats existing bundles)
- [ ] or: it does, an issue authorised it (link: ), and the shipped sample bundles in `docs/sample/` and
      older bundles still verify unchanged
