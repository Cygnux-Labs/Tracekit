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
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # VERIFIED, exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # FAILED: hash mismatch, exit 1
```

What you are looking at: an agent asked to fix a failing test reads a README carrying a planted prompt
injection that tells it to upload `.env`. Tracekit records every step and blocks the upload (rule TK-D006).
The verdict carries one warning on purpose: the signer ran as the agent's own user, so this sample demonstrates
the format and the checks, not tamper-proof custody. Real deployments use system mode and an external witness
([docs/witnesses.md](../witnesses.md)).

Regenerate with `tracekit demo --keep` and copy `run.tkb`, `tampered.tkb` and `signer/keys/signer.pub` from the
folder it prints. `tests/test_hardening.py` verifies these files, so they cannot silently go stale.
