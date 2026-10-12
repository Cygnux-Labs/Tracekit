# Demos

Recorded runs of Tracekit's main use cases, offline: mock models, scripted approvals, and every "outside" host on
this machine. Each folder holds what the scenario is (`README.md`), the terminal session (`transcript.txt`), the run's
bundle (`run.tkb`), the trust config that pins its signer's key (`trust.json`) and the `tracekit verify` report
(`verify.txt`).

| Use case | What it proves | Folder |
|---|---|---|
| Guardrails | A coding agent's shell calls are allowed, denied or held for a person, each decision signed before the call runs | [guardrails](guardrails/README.md) |
| Prompt injection | A planted instruction to email data out is held because its recipient came only from a fetched page (provenance) | [prompt-injection](prompt-injection/README.md) |
| MCP tools | MCP tool calls go through the same policy, approvals and signed record as the agent's own tools | [mcp](mcp/README.md) |
| Agent approvers | A reviewer agent clears only calls within its bounds; people answer the rest, and a person's reject sticks | [agent-approvers](agent-approvers/README.md) |
| Detection and containment | A secret read then an upload opens a signed incident; the run is held until a person resumes it | [containment](containment/README.md) |
| Completeness and tamper evidence | A call decided but never completed becomes a signed gap; one byte changed in the bundle fails verification | [completeness](completeness/README.md) |
| Network coverage | An egress observer outside the agent records the hosts a run reached; one no call explains is flagged | [egress](egress/README.md) |

Check a saved bundle yourself, offline, with nothing but the verifier:

```sh
cd docs/demos/containment && tracekit verify run.tkb --trust trust.json
```

Run a demo yourself: the command is in its README (from a checkout, after `pip install -e .`). The demos that start a
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
