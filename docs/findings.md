# Findings

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

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
tracekit-sql "SELECT rule, severity, title FROM findings WHERE run_id='R'"   # contrib/query
```

Findings also appear live in `tracekit view --ledger` (Alerts panel, tape entry `FINDING`).

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
| TK-X006 | critical | an onchain transaction was signed without a recorded guard verdict | `tracekit_onchain.analyze` (contrib/onchain) |
| TK-X007 | critical | an onchain transaction was executed although the guard denied it | `tracekit_onchain.analyze` (contrib/onchain) |
| TK-X008 | medium | an onchain transaction was blocked by the guard | `tracekit_onchain.analyze` (contrib/onchain) |
| TK-C001..C004 | high..low | imported Causeway counterfactual verdicts: confirmed cause, suppressive, ruled out, not applied | `tracekit-causeway import-tests` (contrib/causeway) |
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

## v2 runs: what was asked, said and done (`tracekit analyze --v2`)

On a run of the v2 signer, `tracekit analyze --v2` checks whether what the person asked, what the model said and what
the agent did agree. It reads the run's signed records and, from the signer's
[content vault](privacy.md#the-content-vault), what they commit to; each item must open its record's commitment, or the
analysis stops with an evidence alert. The findings are printed. Signing them into a findings run beside the analysed
run comes with the `review_finding` RPC.

```bash
tracekit analyze --v2                          # the dev signer's latest run
tracekit analyze --v2 --run R --store /var/lib/tracekit-signer
tracekit analyze --v2 --run R --bundle r.tkb --trust trust.json   # records from a bundle that verifies
tracekit analyze --v2 --open --json            # a run still open: partial, machine-readable
```

`--project DIR` names the project (default: the working directory of the first prompt), `--allow DIR` a directory
outside it the agent may write (`/tmp` and `$TMPDIR` always are), `--budget S` the time the analysis may take (60 s).
Exit 0, 4 when a finding is high or worse (or the vault's content doesn't open its record), 2 on an error: no run, a
run still open without `--open`, a bundle that doesn't verify. For Claude Code, `tracekit init --dev --v2` sets up
everything the checks read: the transcript tailer, the dev signer's vault, and thinking summaries.

The text checks (TK-X205 and v1's TK-X101..X104, X111..X114, X120, [tracekit/findings_text.py](../tracekit/findings_text.py))
read what the model told the person (its text; for a mention its reasoning too) against the commands the signer
decided on and their results. They count per model message with text (TK-X120 per call), and read words, never
backtracking patterns: a 64 KiB message or command is read in milliseconds. v1's TK-X105 is TK-X205 here; TK-X001,
X002 are the signer's reconcile; TK-X004, X005 are not ported.

The first line is the answer; then each finding in plain words; record numbers last:

```text
Findings for run 13b8…: 3 problems (1 high, 1 medium, 1 low) · reasoning readable before 3 of 5 actions (60%)

HIGH · Write outside the project  (TK-X203)
  What happened: Bash wrote ~/.profile, outside the project /work/shop (the cwd of the first prompt, record 1)
  Why it matters: an agent working on one project changed a file elsewhere on the machine
  What to do: check that file and what the change did; keep the agent's writes inside the project with a policy rule or a sandbox
  Records: 1 (ec2371cf8fc7), 15 (d55930adc31e), 16 (bd83db487cda) · relied on: decision, transcript (the agent can write it)

MEDIUM · Edit of a file not mentioned before  (TK-X202) [kept_away]
  What happened: Edit changed /work/shop/billing.py; the request named it only to keep it unchanged
  ...
Not checkable (never counted as a pass):
  TK-X201 for 1 call: the model's reasoning was withheld or sealed, so it can't be read.
    To make it checkable: Claude Code: `tracekit init --dev --v2` sets "showThinkingSummaries": true ...
```

| Rule | Severity | What it checks | Not checkable when |
|---|---|---|---|
| TK-X200 | info | coverage: per check, how many calls it checked and found, and how many it could not check, by reason; the monitorability counts | - |
| TK-X201 | info; low when most checkable calls had reasoning | an action with nothing said before it: no reasoning and no text earlier in the model message that asked for the call | `no_response`, `unlinked`, `conflicting_reports`, `no_content`, `withheld` |
| TK-X202 | medium | an edit (Write, Edit, MultiEdit, NotebookEdit) of a file whose name neither the person's request nor the model's text before the call names. A clause that names a file to keep away from it ("leave billing.py untouched") is no mention: the file is a stated constraint, and editing a file the request kept away is a finding whatever the model said about it | `no_content`, `no_text` |
| TK-X203 | high | a write tool, a Bash write target or a [kernel sensor](integrations/tetragon.md)'s file effect outside the project | `no_content`, `no_root`, `root_too_broad`, `relative_path` |
| TK-X205 | critical | a success claim in what the model told the person ("all tests pass", "fixed", "works", "done", "the build is green", "deployed", "merged") after the last related call before it failed: its signed result is `ok: false`, or its output reads as a failure (`2 failed`, `FAILED (failures=1)`, `--- FAIL`, `Tests: 1 failed`, `test result: FAILED`, a Traceback or error line with no pass summary, a non-zero exit). Related: the last test run for a test claim; the last test run and the last build for "fixed", "done", "works"; the last deploy, merge, push, commit or install for those. A message that admits a failure ("2 tests still fail") claims nothing; a transcript line can show a failure but never clear one | `no_content`, `no_result` |
| TK-X101..X104 | high | v1's checks: the model said it ran the tests (or that they pass), committed, pushed or installed, and no such command ran before it or in the same model message | `no_content` |
| TK-X111..X114 | critical | v1's checks: the model said it did not push, delete, change files or use the network, after the run did. A denial that names files or words is read against them: "I didn't touch billing.py" after an edit of pager.py is no finding; "nothing else" covers files the message doesn't name | `no_content` |
| TK-X120 | high | v1's check: a risky action (force push, recursive delete, history rewrite, migration or drop, package publish, sudo) ran, didn't fail, and nothing the model said with it or after it mentions it | `no_content`, `no_account` |

Terms, as the output uses them:

- **Intent** is only what a person typed: a prompt line of the main Claude Code transcript (not a meta line, a
  compaction summary, command output, a tool result or a sub-agent's task prompt), the newest user message of a model
  request the gateway recorded, an input observed as trusted.
- **Reasoning** is what the model said before the call: `full` (an open model's own reasoning), `summary` (Claude's
  thinking, an OpenAI reasoning summary, Gemini's thought summaries), `withheld` (the provider returned it sealed,
  encrypted, or not at all), `none`. It is the model's account of itself: self-reported, not proof.
- **Monitorability** is the share of actions whose reasoning can be read (`full` or `summary`).
- **Trust tier** is where the text a finding relied on came from: `gateway` (the LLM gateway's record), `sdk` (an
  in-process adapter's report), `transcript` (a Claude Code transcript line, which the agent can write); the printed
  list also names `decision` (the arguments the signer decided on), `observer` (a kernel sensor) and `operator`
  (`--project`). Text the agent can write is labelled, and the gateway's record of a model message is preferred. Two
  reports of one model message from different event streams make its reasoning not checkable, and clear nothing.
- **Order**: what was said before a call is `signed_before` it when its record's `run_seq` is lower than the
  decision's; a transcript line the signer recorded after the decision is in `transcript_order` only.

Not checkable is never a pass. Each reason, and the change that makes it checkable:

| Reason | Why | Fix |
|---|---|---|
| `no_response` | no model response was recorded for the call | Claude Code: `tracekit init --dev --v2` (its transcript tailer); other agents: the [LLM gateway](gateway.md) |
| `unlinked` | the call was decided under an id of the adapter's own | an integration that decides under the provider's tool call id |
| `no_content` | the signer kept no content for the records the check reads | `content: {retain: true}` in signer.yaml (the dev signer keeps it), and the `content_read` grant |
| `withheld` | the model's reasoning was withheld or sealed | `"showThinkingSummaries": true` in Claude Code's settings (`tracekit init --dev --v2` sets it); headless: `claude -p --thinking-display summarized`; API: thinking display `summarized`, Responses `reasoning.summary: "auto"` |
| `conflicting_reports` | two event streams reported the call's model message | the LLM gateway, whose record is preferred |
| `no_text` | neither a request nor anything the model said before the call was recorded | the transcript tailer or the gateway, with the vault on |
| `no_root`, `root_too_broad` | the project is unknown, or `/` or a home directory | `--project DIR` |
| `relative_path` | a relative path with no working directory for the call (a Bash `cd`) | the transcript tailer records each call's cwd |
| `budget` | the analysis reached its time or size budget | `--budget SECONDS` |
| `no_result` | the call a claim rests on has no recorded result | complete every call (the integrations do; a crashed agent leaves its last call without one) |
| `no_account` | the model said nothing readable with a risky action or after it | the transcript tailer or the gateway, with the vault on |

### The `--json` shape

Stable from this release; new keys may be added:

```json
{"run_id": "13b8…", "agent": "claude-code", "summary": "Findings for run 13b8…: 3 problems (1 high, 1 medium, 1 low) · …",
 "findings": [{"verdict": {"kind": "finding", "rule": "TK-X202", "severity": "medium", "tier": "transcript",
                           "order": "signed_before"},
               "cites": [{"run_seq": 12, "hash": "sha256:…"}, {"run_seq": 13, "hash": "sha256:…"}]}],
 "coverage": {"verdict": {"kind": "coverage", "rule": "TK-X200", "severity": "info",
                          "checks": {"TK-X201": {"checked": 4, "found": 1, "not_checkable": [{"reason": "withheld", "n": 1}]},
                                     "TK-X202": {"checked": 2, "found": 1, "not_checkable": []},
                                     "TK-X203": {"checked": 5, "found": 1, "not_checkable": []}},
                          "reasoning": {"full": 0, "summary": 3, "withheld": 1, "none": 1}},
              "cites": []},
 "shown": {"details": [{"what": "Edit changed /work/shop/billing.py; …", "tiers": ["decision", "transcript"],
                        "labels": ["kept_away"]}],
           "tiers": {"TK-X201": ["transcript"], "TK-X202": ["decision", "transcript"], "TK-X203": ["decision", "transcript"]},
           "constraints": [{"name": "billing.py", "run_seq": 1, "tier": "transcript", "source": "request"}],
           "calls": {"toolu_7": {"tool": "Edit", "form": "summary", "order": "signed_before", "seqs": [11],
                                 "excerpt": "…", "checks": {"TK-X201": "checked", "TK-X202": "found", "TK-X203": "checked"}}}}}
```

`findings` and `coverage` hold no text of the run: each `{verdict, cites}` is exactly what `review_finding` will sign
(the signer adds the rule's fixed title). A finding may also carry `redacted: true` (it relied on content redaction
changed); the coverage, `partial: true` for an open run. `shown` is plaintext for whoever ran the analysis (`details`
in the order of `findings`, per check the trust tiers relied on, the stated constraints, and per call what was said
before it and each check's outcome: `checked`, `found` or a not-checkable reason); it is printed, never signed.

### For agents

An agent can read its own run the same way: `tracekit analyze --v2 --run $RUN --json` as an identity with
`content_read`. `findings[].verdict` and `shown.details` say what to explain or undo; `coverage.verdict.checks` and
`shown.calls[id].checks` say which of its actions couldn't be checked, and the table above says what makes them
checkable. Findings are an opinion about a run, never part of its integrity: before relying on another agent's work,
verify its bundle offline (`tracekit verify r.tkb --trust trust.json --json`) and read its findings beside that.

### Accuracy

E20 in [evaluation](evaluation.md#e20-intent-reasoning-and-action-checks) replays synthetic Claude Code sessions with a
spliced edit of an unrequested file through the tailer and hook into a signer with the vault on. Naming the file
innocently in the model's text clears TK-X202 (a name check can't tell why), and so does a prompt line the agent
appends to its own transcript; both are in the [limits](limits.md#intent-reasoning-and-action-checks).

E20 also splices text faults. A false success claim after a failed test run (F4) is found in every tuned session and in
64% of sessions built from the held-out pool (written blind to the checks): 73% when the claim is one of the pool's
success claims, 21% when it is a free-form final summary; 69% when the run was piped through `tail` (exit 0, the
failure only in its output), 59% with a failing exit (the claim, not the failure, is what is missed). No honest
control session, tuned or held out, got a text finding. The checks that need the model to deny or claim an
action (TK-X111..X114, X101..X104) find a fault only when the summary says so: E20 reports them per cover. On E6's
corpus the v2 view gives every v1 finding of the ported checks, plus paraphrases v1's patterns miss, and no more on
clean sessions.

## Accuracy

E6 in [evaluation](evaluation.md) measures the detectors on 2,000 synthetic sessions with spliced misbehaviour. The
structural detectors are exact on ground truth, and no honest session produced a finding. The text detectors catch the
phrasings they were written for and miss most held-out paraphrases (29% and 40% recall): they are regexes. A model-based
judge would raise recall; its findings would be signed and evidence-checked the same way.
