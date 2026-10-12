# Demos

![Tracekit in a terminal: guardrails, a prompt injection held, a tampered bundle failing verification, and tracekit why](highlights.gif)

The full tour as a video: [tracekit-tour.mp4](tracekit-tour.mp4) (3 min 44 s), each demo below running in a
terminal and `tracekit verify` on each bundle; the GIF above is an 85 s highlights reel. Both are recorded with
[VHS](https://github.com/charmbracelet/vhs) from [tour.tape](tour.tape) and [highlights.tape](highlights.tape):
`vhs docs/demos/tour.tape` from the repo root.

Recorded runs of Tracekit's main use cases, offline: mock models, scripted approvals, and every "outside" host on
this machine. Each folder holds what the scenario is (`README.md`), the terminal session (`transcript.txt`), the run's
bundle (`run.tkb`), the trust config that pins its signer's key (`trust.json`) and the `tracekit verify` report
(`verify.txt`); the why demo has only the first two (its log is hash-chained, not signed).

In story order: what the agent did, how it is controlled, the proof, and why it happened.

| | Demo | What it proves |
|---|---|---|
| What | [Guardrails](guardrails/README.md) | A coding agent's shell calls are allowed, denied or held for a person, each decision signed before the call runs |
| What | [MCP tools](mcp/README.md) | MCP tool calls go through the same policy, approvals and signed record as the agent's own tools |
| Control | [Prompt injection](prompt-injection/README.md) | A planted instruction to email data out is held because its recipient came only from a fetched page (provenance) |
| Control | [Agent approvers](agent-approvers/README.md) | A reviewer agent clears only calls within its bounds; people answer the rest, and a person's reject sticks |
| Control | [Detection and containment](containment/README.md) | A secret read then an upload opens a signed incident; the run is held until a person resumes it |
| Proof | [Completeness and tamper evidence](completeness/README.md) | A call decided but never completed becomes a signed gap; one byte changed in the bundle fails verification |
| Proof | [Network coverage](egress/README.md) | An egress observer outside the agent records the hosts a run reached; one no call explains is flagged |
| Why | [Why](why/README.md) | Of three untrusted inputs that all reached an exfiltration email, replays show which one caused it |

Check a saved bundle yourself, offline, with nothing but the verifier:

```sh
cd docs/demos/containment && tracekit verify run.tkb --trust trust.json
```

Run a demo yourself: the command is in its README (from a checkout, after `pip install -e .`, which needs pip 21.3 or newer). The demos that start a
signer from their own `signer.yaml` (prompt injection, agent approvers, containment, egress) need macOS or Linux: you
reach that signer as your uid on a Unix socket.

Regenerate every folder, each demo against a fresh signer in a temp dir (never your own), or check them without
writing anything (`tests/test_demos.py` runs the check):

```sh
make demos                                  # python scripts/record_demos.py [NAME ...]
python scripts/record_demos.py --check      # each run.tkb still verifies as verify.txt says; each demo still runs
```

Every bundle here verifies at `Assurance: dev`: no witness cosigned its checkpoint
([what dev means](../quickstart-v2.md#what-dev-assurance-means)).
