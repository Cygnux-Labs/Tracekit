# Quickstart: a custom agent

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
pip install tracekit-ai
```

## 2. A few lines in your agent

Without a framework for `tracekit.instrument()` to wire, your agent asks the signer itself, once per tool call:

```python
from tracekit.sdk.client import Client, result_field

with Client().run(agent="my-agent") as run:      # one run; starts the dev signer if none answers
    for call_id, tool, args in my_agent_tool_calls():
        d = run.decide(call_id, tool, args)      # before it runs: allow, deny or ask
        if d["decision"] == "allow" and (d.get("unavailable") or run.approval_consume(call_id, tool, args)["ok"]):
            result = run_tool(tool, args)        # your tool, with exactly those arguments
            # its outcome, bound to the decision: the result itself for a tool the policy calls untrusted (provenance)
            run.complete(call_id, result=result_field(d.get("send_result"), result))
        else:
            result = "refused: " + (", ".join(d["rule_ids"]) or d.get("reason", ""))   # the model gets the refusal
```

Pass the model's raw arguments string as `args` when you have it: the signer records which form it saw. `decide`
doesn't raise when the signer can't be reached: the run's fail mode answers, with `"unavailable": True` (an open fail
mode lets the call run unrecorded, with a warning). Since 1.2, `decide` returns the run's fail-mode decision with
`unavailable: True` instead of raising `SignerUnavailable`: a loop that caught that exception to block the call now
gets `{"decision": "deny", ...}` and blocks by the decision. `complete` never raises either: the call already ran, so a result
the signer can't take is a warning, and the signer records the call as decided and not completed. To record
the OpenAI, Anthropic or Google Gen AI calls made inside the `with` block into its run as well, add `from tracekit
import autotrace; autotrace.instrument(None)` before it.

## Frameworks that catch exceptions

Block a call by what your hook returns, never by raising: some frameworks run the tool, or turn the error into an empty
answer, when a hook raises. Everything Tracekit refuses on its own (a model call under a closed fail mode, autotrace's
refusals) raises `tracekit.Refused`, a `PermissionError`: let it through your own error handling.

| Framework | What it does with an exception | With Tracekit |
|---|---|---|
| CrewAI | runs the tool when a `before_tool_call` hook raises | `instrument()` wires hooks that block by returning `False` ([CrewAI](../integrations/crewai.md)) |
| LangGraph / LangChain | `ToolNode`'s `handle_tool_errors` turns a tool's exception into a message | the middleware returns its refusal as a tool message, and pauses an `ask` whatever `handle_tool_errors` says |
| mcp-agent | `generate_str` logs an exception from the model call at debug level and returns `""` | a fail-closed model refusal reads as an empty answer: treat `""` as a failure, or run with `fail_modes: {model: open}` |
| Your own loop | whatever your `except` does | re-raise `tracekit.Refused`, or return the refusal to the model |

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals

An `ask` waits for a person; this is the loop with that step:

```python
from tracekit.sdk.client import Client

with Client().run(agent="my-agent") as run:
    d, aid = run.decide(call_id, "Bash", args), None          # before the call runs: allow, deny or ask (an outage:
                                                                # the fail mode, "unavailable": True)
    if d["decision"] == "ask":
        aid = run.call("approval_request", tool_call_id=call_id)["approval_id"]
        run.call("approval_wait", approval_id=aid, timeout_ms=300000)
    if d["decision"] != "deny" and (d.get("unavailable") or
                                    run.approval_consume(call_id, "Bash", args, approval_id_hint=aid)["ok"]):
        ...                                                     # run the call, with exactly those arguments
        run.complete(call_id)                                   # its outcome, bound to the decision
```

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/custom/agent.py --scripted`
from a checkout.

## Read the verify report

```text
[PASS] checkpoint — tracekit.local/... at tree size 12, signed by its pinned log key
[PASS] witness quorum — 0 pinned cosignature(s), 0 required
[PASS] signatures — 11 record(s), keys valid at their position
[PASS] run chain — run '...' of tenant 'default', contiguous from run_seq 0
...
Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint Ed25519 only (...); no witness cosignature; approvals: self; ...
```

`Integrity: VERIFIED` means every record was signed by the log key in `trust.json`, the run is one unbroken chain, and a
checkpoint signed by that key includes it: nothing was edited, dropped or reordered after signing. Change one byte of
the bundle and it reads `Integrity: FAILED`, naming the check (`tracekit demo --server` shows this). `Assurance: dev`
says no pinned witness cosigned the checkpoint and the approval was a self-approval. [The v2
quickstart](../quickstart-v2.md#export-and-verify-by-hand) explains every line.

## Next steps

- **System mode** runs the signer as its own OS user, so the agent can't reach its keys, store or policy, and approvals
  come from another account: [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Witnesses** cosign the signer's checkpoints from another host, so a rolled-back or forked log shows:
  [witnesses](../witnesses.md). Pin them in the trust config and the report reads `Assurance: witnessed`.
- **Your own policy**: the dev signer uses the coding pack plus two demo rules (`tracekit/policy2/packs/dev.yaml`); a
  configured signer takes `policy:` in `signer.yaml`.
