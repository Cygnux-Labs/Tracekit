# Case study: Tracekit on two open-source agents

On 2026-10-12 we integrated Tracekit into two real open-source agent projects. We followed the docs a customer would
read, and used a real model (gpt-5.6-luna) on fixed sets of tasks. We ran each task set without Tracekit, then with it,
and compared the signed records with each project's own logs.

This page covers what the integration took, what the signed record caught, what it cost, and how to check the
evidence yourself.

| | OpenAI customer-service agents demo | CrewAI |
|---|---|---|
| Project | `openai-cs-agents-demo` at `bd7bfca`: a FastAPI airline support app on the OpenAI Agents SDK 0.23, with a triage agent, five specialists and guardrails | CrewAI 1.15.27: sequential and hierarchical crews, with manager delegation |
| Tracekit path | `tracekit.instrument()` (the OpenAI Agents adapter and model-call capture) | no adapter: CrewAI's global tool hooks, following the [custom quickstart](quickstarts/custom.md), plus `tracekit.instrument()` for model calls |
| Tasks | 10 conversations | 9 crews (33 tool calls) |
| Integration | 4 lines, plus about 12 to give each conversation its own run | about 60 lines of hook glue |
| Overhead | +1.6% wall time | 73.8 s → 81.9 s for the 9 crews (own call ids); 85.9 s with the model's ids, including 4 approval waits of about 3 s |
| Result | every tool call and model response recorded; 0 false reconcile findings; 0 gaps; bundle `VERIFIED` offline | 33/33 calls decided and reconciled; deny, ask and reject held; Python and TypeScript verifiers agree on all 25 bundles |

## The customer-service demo

**Integration.**

- `tracekit.instrument()` at startup records every tool call through the OpenAI Agents adapter. It also records every
  model response through the model SDK's capture.
- A chat server has many conversations in one process, so each conversation gets its own run, kept open across
  requests. Each turn enters it with `with conversation.current():`.

**What the signed record caught.** These were bugs in Tracekit, found by its own records, and fixed before this page
was written:

- **Lost streamed responses.** On the first pass, verify reported 12 of 12 honest tool calls as `fabricated`: calls with
  no model response asking for them. The OpenAI Agents SDK streams through a call path that our model-call capture
  missed. The records were right to complain: no recorded response asked for those calls. After the fix, a rerun shows
  0 fabricated calls.
- **One run per server.** `instrument()` opened one run per process, so a long-running server mixed every conversation
  into one run. The signer then closed it after an hour idle. Fixed: work follows the current run, and docs say to use a
  run per conversation.
- **Approvals with a typed context.** An `ask` failed when the app's run context was a pydantic model rather than a
  dict, which is how real apps write it. Fixed.

**What it can't show.** Two tools here don't name their target:

- `cancel_flight()` takes the flight from the conversation's context;
- `issue_compensation(reason)` has no amount.

A signed decision records the arguments it was given, so for these tools it has nothing to show or for a rule to
match. Design consequential tools so that their arguments name what they act on.

**Result.** After the fixes, the rerun had a run per conversation: 10 conversation runs, all finalised, even across a
signer restart. It had 0 reconcile findings, 0 gaps and +1.6% wall time, and the exported bundle verified offline.

## CrewAI

**Integration.**

- CrewAI 1.15 has global tool hooks: `before_tool_call` can block a call by returning `False`, and `after_tool_call`
  sees the result. The gate from the [custom quickstart](quickstarts/custom.md) goes in them:
  - `before_tool_call` calls `decide` on the tool and its input. On an `ask`, it calls `approval_request` and
    `approval_wait`, and the crew waits in the hook. It then calls `approval_consume`, and returns `False` unless the
    call may run.
  - `after_tool_call` records the outcome with `complete`, with `status="error"` when CrewAI reports a tool error.
- `tracekit.instrument()` records the model calls, including the manager agent's.

**What the signed record caught.**

- **A denied tool ran while the signer was down.** CrewAI swallows any exception a hook raises, and then runs the tool.
  The Python client's `decide` raised `SignerUnavailable` when the signer couldn't be reached. So with the signer
  stopped between two calls, `close_account` ran, although the policy denies it.
  - The record showed it: the run held a decision for the call before, and nothing for `close_account`. The bundle
    verified only `TO HEAD 1 (open)`.
  - The rule that follows: **a gate in a framework hook must block on any exception.** The glue catches everything in
    `before_tool_call` and returns `False`, so an outage blocks the call (the run's fail mode is `closed`).
- **No call ids in the hooks.** CrewAI's hook context has the tool name and input but not the model's tool-call id.
  With invented ids, the signer couldn't pair a single decision with the model response that asked for it: 33 calls,
  66 false reconcile findings. Passing the model's id into the hook (a small wrapper around CrewAI's executor) paired
  33 out of 33, with zero findings.
- **Policy and provenance held.**
  - A deny rule kept `close_account` from running, and the model was told the rule ids.
  - An `ask` on `refund_order` waited for an approval given with `tracekit approvals approve`. The refund then ran
    exactly once.
  - A rejected `delete_customer` never ran.
  - `send_email` after the agent read an untrusted ticket was held, with the ticket recorded as the source of the
    address.
- **Mandatory gateway.** With `gateway_mandatory: true`, 4 crews produced zero reconcile records.

## Check the evidence yourself

Export a run and verify it with a trust config built from sources you trust, not from the bundle:

```sh
tracekit export --v2 --config signer.yaml --run RUN_ID -o run.tkb
tracekit signer trust --config signer.yaml -o trust.json
tracekit verify run.tkb --trust trust.json
npx --package ./cygnuxlabs-tracekit-<version>.tgz tracekit verify run.tkb --trust trust.json   # the TypeScript verifier must agree
```

- `Integrity: VERIFIED.` says that the run's records are the ones the signer signed, complete from registration to
  `run.final`.
- The `tiers` and `coverage` lines say what was observed. Calls captured in the agent's own process are tier T1; calls
  a [gateway](gateway.md) or [executor](executor.md) saw are tier T2.
- Any gap or reconcile record names what the signer saw but wasn't told, or was told and didn't see.

[Verdicts](verdicts.md) explains each line, and [known limits](limits.md) lists what a verified bundle doesn't prove.

## Try it offline

The [custom agent example](../examples/v2/custom/README.md) runs the same gate with a scripted model: no API key, no
network.

```sh
python examples/v2/custom/agent.py --scripted
```

It starts a dev signer and runs three calls:

- `ls` is allowed;
- `sudo rm -rf /` is denied, and the agent goes on;
- an unparsable command waits for an approval, which `--scripted` gives from a second process.

It then exports the run and prints the `tracekit verify` report.
