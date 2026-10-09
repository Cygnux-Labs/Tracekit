# Sample evidence bundle

A real bundle from `tracekit demo` (scripted agent, dev-mode signer), so you can try verification without
installing a signer or running an agent.

| File | What it is |
|---|---|
| `demo-run.tkb` | the evidence bundle: manifest, signed records, checkpoints, policy, coverage, replay |
| `demo-run-tampered.tkb` | the same bundle with one recorded command edited |
| `signer.pub` | the signer's public key, to pin with `--key` |
| `demo-run-replay.html` | the bundle's replay viewer, extracted; open it in a browser (works offline) |

```bash
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # FAILED: hash mismatch, exit 1
```

The first one ends with:

```
Integrity: VERIFIED.
Assurance: dev (signer ran as the agent's own user: the agent could have rewritten the ledger).
```

Read the two lines together: the records are intact and signed by the pinned key, but a dev-mode signer shares the
agent's user, so this proves the format and the checks, not tamper-proof custody. Both commands also print
`warning: replay.html differs from the viewer this verifier would generate`: these samples were made with an earlier
viewer. The verdict never uses `replay.html`, so the warning does not change it.

What you are looking at: an agent asked to fix a failing test reads a README carrying a planted prompt
injection that tells it to upload `.env`. The hooks record each tool call the (scripted) agent made, and the policy
blocks the upload (rule TK-D006). The bundle carries only its own checkpoints, no witness copy, and the verifier
also warns that the key is a file on the signer host, that no harness was registered, and that the run used a path
Tracekit cannot see into (the payload of a network command). Real deployments use system mode and a witness outside
the agent host ([docs/witnesses.md](../witnesses.md)).

Regenerate with `tracekit demo --keep` and copy `run.tkb`, `tampered.tkb` and `signer/keys/signer.pub` from the
folder it prints. `tests/test_hardening.py` checks that the sample still verifies and the tampered copy still fails.
