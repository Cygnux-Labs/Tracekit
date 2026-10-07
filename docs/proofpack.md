# Proof packs

```bash
tracekit analyze --run R                                  # optional: include signed findings
tracekit proofpack --run R -o pack.zip --key signer.pub   # or: tracekit proofpack run.tkb -o pack.zip
tracekit report run.tkb > REPORT.md                       # the report alone
```

`pack.zip` holds:

| File | What it is |
|---|---|
| `run.tkb` | the evidence bundle, unchanged |
| `REPORT.md` | the run (agent, model, policy, capture sources, signer isolation, tool and model calls, tokens), every verification check with its result, signed findings, coverage (observed, not observed by design, warnings), and the evidence-to-control map |
| `verify.pyz` | Tracekit's verifier as one file. `python3 verify.pyz run.tkb --key signer.pub` runs with only the standard library: signature checks fall back to pure-Python Ed25519 when `cryptography` is missing |
| `controls.json` | the control map, machine-readable |
| `SHA256SUMS` | hashes of the files above |

## Auditor walkthrough

What a reviewer does with a pack they were sent, on their own machine:

1. `sha256sum -c SHA256SUMS` (or `shasum -a 256 -c`): the files are the ones the pack was built with.
2. `python3 verify.pyz run.tkb --key signer.pub`, with the signer's public key obtained separately (from the team's
   key registry, a ticket, a signed email), or `--witness URL` with a pinned witness key. Exit 0 and `VERIFIED` mean
   every record is signed by that key, the chain is unbroken, checkpoints match, findings cite intact evidence. Without
   `--key` or `--witness` the verdict is `VERIFIED BUT UNANCHORED`: consistent, but nothing outside the pack vouches
   for the signer.
3. Read `REPORT.md`: what ran, which checks passed or warned and why, the findings with the records they cite, what
   the capture path did not observe, and which control each piece of evidence is relevant to (`controls.json` has the
   same map for tooling).
4. Spot-check: pick a row in the report and find its seq and hash in `run.tkb` (`unzip -p run.tkb records.jsonl`), or
   open `replay.html` inside the bundle, which re-runs the chain and signature checks in the browser.

Checked on a clean machine (Linux arm64, Python 3.10, no Tracekit installed, `python3 -I` with an empty environment):
`sha256sum -c SHA256SUMS` passed and `verify.pyz` returned exit 0, using only the files in the pack.

## The control map

For each requirement the report lists the evidence in this bundle that is relevant to it and what the bundle does not
cover. It is guidance for a reviewer, not a compliance determination.

| Framework | Control |
|---|---|
| EU AI Act (Regulation (EU) 2024/1689) | Art. 12 Record-keeping (automatic recording of events over the system's lifetime). Retention periods (Art. 19, Art. 26(6)) are the operator's responsibility |
| SOC 2 (Trust Services Criteria 2017) | CC7.2 System monitoring |
| ISO/IEC 42001:2023 | Annex A, A.6.2.8 AI system recording of event logs |

## Anchoring the result

Without `--key` (a signer public key obtained independently) or `--witness`, the report says the result is
unanchored: the bundle is internally consistent, but nothing outside it vouches for who signed it. Give auditors the
signer's public key through a separate channel, or point them at a witness.
