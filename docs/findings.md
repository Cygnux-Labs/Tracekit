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
For a run a [kernel sensor](integrations/tetragon.md) covered: `--effect-grace S` (2 s) and `--clock-skew S` (0.5 s)
set each call's window, and `--sensor-skip DIR` names a directory the sensor's file policy leaves out (see
[effects](#effects-what-a-kernel-sensor-saw)).
Exit 0, 4 when a finding is high or worse (or the vault's content doesn't open its record), 2 on an error: no run, a
run still open without `--open`, a bundle that doesn't verify. For Claude Code, `tracekit init --dev --v2` sets up
everything the checks read: the transcript tailer, the dev signer's vault, and thinking summaries.

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
| TK-X206 | high | an effect with no action: a process, connection or file write a kernel sensor saw that no call explains, or that names a call it doesn't fit (a call the run never ran, outside that call's window, or of a tool that doesn't cause it: a process named by a Read call) | `no_sensor`, `agent_process`, `hook_like`, `call_unfinished` |
| TK-X207 | medium | an action with no effect: a call that returned ok without what it should have caused in its window (a Bash command's programs, and curl's or wget's connection; a fetch tool's connection; a write tool's file where the sensor selects writes) | `no_sensor`, `no_content`, `sensor_paths`, `relative_path`, `kind_not_recorded`, `hook_binary` |

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
| `no_sensor` | run.final's coverage matrix doesn't say a kernel sensor observed the run's processes throughout, or the run is open | `tracekit sensor import` for the run ([Tetragon](integrations/tetragon.md), [Falco](integrations/falco.md)) |
| `agent_process` | a process running before the run (the agent's harness: its model calls, its own files) did it, and nothing names a call | Codex: keep `CODEX_TOOL_CALL_ID` in the sensor; for hosts, the [egress observer](egress.md) |
| `hook_like` | a shell or Python process started outside any call, not by a call's process: Tracekit's own hooks look the same | none for Tracekit's hooks; review hooks and status lines of your own |
| `call_unfinished` | only a call with no recorded result could explain it | the hook reports each call's result (PostToolUse) |
| `sensor_paths` | which files the sensor's policy selects is not in the run | `--sensor-skip DIR` per directory it leaves out; `--sensor-skip ''` when it selects every write |
| `kind_not_recorded` | the sensor recorded no effect of this kind in the run: its policy may not select them | the sample TracingPolicy or Falco rules |
| `hook_binary` | the only processes that could be the command's ran the same program as Tracekit's hooks (a shell or Python) | Codex: keep `CODEX_TOOL_CALL_ID` in the sensor, so a command's processes name their call |

### Effects: what a kernel sensor saw

With a kernel sensor's records in the run (`tracekit sensor import`), TK-X206 and TK-X207 compare them with the calls.
A call's window runs from its decision to its result, on the signer's clock, widened by `--clock-skew` both ways and
`--effect-grace` after the result; each effect carries the sensor's own time. A process the run started is the call's
when:

1. its environment names the call (`tool_call_id`: Codex's `CODEX_TOOL_CALL_ID`, the agent's claim), and that call
   ran, the effect is in its window, and its tool causes that kind of effect: a shell any; a search tool (Grep, Glob)
   processes; a write tool a file; a fetch tool a connection; Read, LS, WebSearch, Task none; an MCP or unknown tool
   any. The signer's `explained_by: call` is this claim, re-checked;
2. the process that started it is the call's (`parent_exec_id`, from Tetragon): a server a Bash call left running, and
   what it starts later, are that call's, whatever the time;
3. or it started in the window of a call whose tool runs processes.

Its connections and writes go with it. The agent's harness itself runs from before the run: its model calls and its
own files are `agent_process`, except a file a write call named in its window. Each finding shows the window it used.
When an effect reached the signer before its own sensor time, the sensor's clock is ahead; when every effect reached it
later than the import's one-second flush, the sensor's clock may be behind. Either way each finding is labelled
`clock_skew` with the `--clock-skew` that covers it.

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
before it and each check's outcome: `checked`, `found` or a not-checkable reason); it is printed, never signed. With
a sensor's records, `shown.effects` maps each effect's `run_seq` to `{call, how, status}` (`how`: `claim`, `ancestry`,
`window`, `process` or `path`; `status`: `explained`, `found` or a not-checkable reason), and `shown.effect_window` holds
`grace_s`, `skew_s`, `skips` and, when the clocks disagree, `skew_seen` (`ahead_s` or `behind_s`, `record`,
`suggest_s`).

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

E20's effects arm replays synthetic sensor runs (Claude Code-like, Codex-like) with Tracekit's hook processes and the
harness's own traffic, into a signer on a synthetic clock: a process no call started, one of the wrong kind for its
call, calls whose effect never happened, a daemon's late child, and clock skew. On a held-out set written before the
checks, every fault was found or not checkable, none passed, and no honest effect or call was flagged; a Python process
started outside any call reads as `hook_like`, so a Python exfiltration there is not checkable.

## Accuracy

E6 in [evaluation](evaluation.md) measures the detectors on 2,000 synthetic sessions with spliced misbehaviour. The
structural detectors are exact on ground truth, and no honest session produced a finding. The text detectors catch the
phrasings they were written for and miss most held-out paraphrases (29% and 40% recall): they are regexes. A model-based
judge would raise recall; its findings would be signed and evidence-checked the same way.
