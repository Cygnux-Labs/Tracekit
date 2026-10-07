# Findings

`tracekit analyze` runs deterministic detectors over a run and signs what they find into the ledger, next to the
evidence. A finding is not a log line or a dashboard alert: it is a signed, hash-chained record that cites the exact
ledger entries it rests on, and `tracekit verify` fails a bundle in which a finding points at evidence that is missing or
altered.

```bash
tracekit analyze --last              # detectors on the latest run; new findings are signed
tracekit analyze --run R --dry-run   # print only
tracekit analyze --all --json        # every run, machine-readable; exit code 4 if anything high or critical
tracekit export --run R -o r.tkb     # the bundle carries findings:R with the run
tracekit verify r.tkb                # [PASS] findings cite intact evidence
tracekit sql "SELECT rule, severity, title FROM findings WHERE run_id='R'"
```

Findings also appear live in `tracekit observe` (Alerts panel, tape entry `FINDING`).

## Detectors

| Rule | Severity | What it checks | Needs |
|---|---|---|---|
| TK-X001 | medium | the model requested a tool call that was never executed | model exchanges + tool calls |
| TK-X002 | high | a tool call ran whose id never appeared in any model response (injected or fabricated) | model exchanges + tool calls |
| TK-X003 | high | a call reported after the fact (OpenTelemetry) that the policy would have blocked or held | - |
| TK-X004 | medium | credentials appeared in a tool's output (redaction fired: the agent saw the secret) | - |
| TK-X005 | medium | risky action: force push, recursive delete, history rewrite, migration or drop, publish, sudo | commands in clear |
| TK-X101..104 | high | the agent claimed tests, a commit, a push or an install that no executed command supports | agent text in clear |
| TK-X105 | critical | the agent said tests pass after the last test run failed | agent text in clear |
| TK-X111..114 | critical | the agent denied pushing, deleting, editing or network calls that it made | agent text in clear |
| TK-X120 | high | a risky action that nothing the agent said afterwards mentions | agent text in clear |
| TK-X006 | critical | an onchain transaction was signed without a recorded guard verdict | `adapters.onchain` |
| TK-X007 | critical | an onchain transaction was executed although the guard denied it | `adapters.onchain` |
| TK-X008 | medium | an onchain transaction was blocked by the guard | `adapters.onchain` |
| TK-C001..C004 | high..low | imported Causeway counterfactual verdicts: confirmed cause, suppressive, ruled out, not applied | `tracekit causeway import-tests` |
| TK-X000, TK-X100 | info | a check could not run (no model exchanges captured / agent text only hashed) | - |

Detectors never pass silently: when the ledger holds only hashes of what the agent said, TK-X100 says the text checks
could not run. Agent text is in clear with `content_capture: full` (model output) or `reasoning_capture: true` (agent
messages). Ids Tracekit made up itself (`tk_...` from the SDK without a model id, `otel_...` from a span without one)
are not treated as unrequested executions.

## Format

A finding is a schema-v1 `review` event in the companion run `findings:<run_id>` (the signer accepts only `review`
events there). The verdict:

```json
{"kind": "finding", "rule": "TK-X105", "severity": "critical", "title": "claimed tests pass, but the last test run failed",
 "detail": "...", "run_id": "job-1", "detector": "tracekit-analyzer/1", "fingerprint": "sha256:...",
 "evidence": [{"seq": 4, "hash": "9c1e..."}, {"seq": 6, "hash": "51ab..."}, {"seq": 8, "hash": "07fd..."}]}
```

Re-running the analyzer is idempotent: a finding with the same fingerprint (rule, run, cited hashes) is never signed twice.

## Accuracy

E6 in [evaluation](evaluation.md) measures the detectors on 2,000 synthetic sessions with spliced misbehaviour. The
structural detectors are exact on ground truth, and no honest session produced a finding. The text detectors catch the
phrasings they were written for and miss most held-out paraphrases (29% and 40% recall): they are regexes. A model-based
judge would raise recall; its findings would be signed and evidence-checked the same way.
