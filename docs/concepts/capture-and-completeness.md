# Capture and completeness

Signatures prove the records weren't changed. They can't prove the records are everything that happened: an action
that never reaches Tracekit leaves nothing to sign. Tracekit treats completeness as something to measure and report,
never to claim. It records where each piece of evidence came from, watches the same run from several vantage points,
compares them, and writes a signed gap whenever something is missing.

## Tiers: where evidence came from

| Tier | Captured by | What it proves |
|---|---|---|
| T1 | Hooks, adapters and the SDK, inside the agent's process | What the agent *reported* |
| T2 | The tool executor, MCP gateway and LLM gateway, outside the agent's process | What crossed a boundary the agent doesn't control |
| T3 | Imported telemetry (OpenTelemetry, external decisions) | Only that the signer received it |

The verify report lists the tier of every call and warns when a call's decision and result arrived by different paths.
Hook and adapter calls carry no tier field and show as `untiered`.

## Capture layers

The same run can be seen from several layers. Comparing them catches an agent that lies in one of them.

| Layer | What it sees | Source |
|---|---|---|
| L1 | Saved agent state (for example LangGraph checkpoints, Claude Agent SDK sessions) | `state_write` digests |
| L2 | The decide and complete path | Every client |
| L3 | What the model asked for: its tool uses | In-process tracing, the framework integrations' record of each model message, the transcript tailer, Codex's rollout file, or the LLM gateway |
| L4, L5 | Processes and services | Not built as reconciled layers. A kernel sensor import records processes, connections and file writes ([below](#kernel-sensors-and-sandboxes)) |
| L6 | Network traffic, by host | The [egress observer](custody.md#the-egress-observer) |

## Reconciliation

Just before `run.final`, the signer compares the layers and signs what doesn't match.

| Finding | Meaning |
|---|---|
| `reconcile.hook_missing` | The model asked for a tool call (L3), but no decision was ever requested for it: the agent skipped its hook |
| `reconcile.fabricated` | A decision was requested (L2) that no model call asked for: the agent invented a call |
| `reconcile.args_mismatch` | The tool or the arguments differ between what the model asked for and what was decided |
| `reconcile.args_unparseable` | The arguments the model asked with failed strict parsing |
| `reconcile.result_without_call` | A result was sent back to the model for a call with no decision and no tool use |
| `reconcile.unexplained_effect` | Network traffic to a host no recorded call explains (L6) |
| `reconcile.result_mismatch` | A tool result the LLM gateway saw go to the model isn't the one the signer recorded, or was sent before its call completed (experimental: [verified tool results](custody.md#the-llm-gateway)) |

With `gateway_mandatory: true`, only the LLM gateway's record of model calls counts as L3, and a skipped hook is
reported mid-run, as soon as the gateway sees the tool's result go back to the model. A `result_mismatch` is also
written at once. A message recorded `said_only` (Gemini CLI's and Cursor's, whose hooks name no call) is no L3 record,
so it never makes a call `fabricated`. Without any L3, nothing can be compared, and the report says so (`L3 absent`). In the reconciliation experiment, 12 of 12 seeded discrepancies were
flagged with no false positives when L3 was present, and none when it wasn't.

## Gaps

When the signer knows something is missing, it writes a signed `capture.gap` saying what. Gaps are never silent, and
only the signer can write them: no request field can carry a gap.

| Gap | When it's written |
|---|---|
| `client_counter_gap` | The client's counter skipped values: calls happened that weren't reported |
| `decided_not_completed` | A call was allowed or approved but never completed |
| `executed_against_policy` | A call ran against a deny, or without its approval |
| `concurrent_run` | A second run came from the same harness session |
| `state_tamper` | Saved agent state changed between being written and being read back (L1) |
| `tailer_lost`, `observer_lost` | The transcript tailer, the egress observer or a sensor import went quiet for 90 seconds or restarted, or a sensor reported lost events |
| `result_unchecked` | The LLM gateway sent a tool result it gave no digests of (past its 512-result or 1 MiB cap), so it wasn't compared |
| `held_call_unresolved` | A call the executor or a gateway decided got no result before its run ended |
| `late_activity`, `effect_outside_run` | Activity after a run ended, or traffic no open run covers |
| `witness_failed`, `degraded_unanchored` | Witnesses stopped cosigning, or none was reachable |
| `signer_unavailable` | A storage outage interrupted the signer |
| `clock_skew`, `decision_flip`, `class_mismatch`, `reask_after_reject`, `decision_mismatch`, `constraint_refused` | Other inconsistencies the signer noticed, such as another policy system's imported decision disagreeing with the signer's |

## Fail modes

What happens to a tool call when the signer can't be reached is set per tool class, in the signer's config, and
recorded in `run.registered`:

- **Closed (the default).** The call is blocked. No signer, no action.
- **Open.** The call runs unrecorded. When the client reaches the signer again, its counter shows exactly how many calls
  were missed, and the signer writes a `client_counter_gap`. The verifier warns about any open class.

System mode, the tool executor and the MCP gateway always fail closed. A refusal from the signer is never treated as an
outage: only an unreachable signer triggers a fail mode. In the outage experiment, closed classes blocked 20 of 20
calls, and open classes ran 20 calls followed by one gap covering them.

## The coverage matrix

Every `run.final` states, for each kind of action, how well it was covered:

| | `enforced` | `observed` | `reported` | `none` |
|---|---|---|---|---|
| Meaning | The signer controlled it (T2 path, or a mandatory gateway) | Seen from outside, not controlled | Only the agent's own report | Not covered |

The kinds are model calls, tool calls, network, processes and services. Processes are `observed` when a Tetragon or
Falco import covered the run throughout, and `none` otherwise; services are always `none`. An `enforced` status rests
on the operator's declared posture and is marked as asserted.

## Kernel sensors and sandboxes

Much of what an agent does happens beneath its tool calls: a command starts other programs, opens connections, writes
files. Tracekit can import what tools outside the agent saw of it (experimental, format 1.4). Each item becomes a signed
`effect.observed` record in the agent's run, written by the signer under the importer's own identity, which the agent
never holds. It is the sensor's word, not something the signer checked.

| Source | What it reports | Recorded as |
|---|---|---|
| Tetragon or Falco, through `tracekit sensor import` on each node (Linux) | Processes started (and, from Tetragon, ended), connections, file writes | `effect.observed{kind: exec, exit, connect or file, sensor}` in the run of the agent identity the import maps the process to (its `callers`); a process that names a Codex tool call carries its `tool_call_id` |
| NVIDIA OpenShell's OCSF export, taken by `tracekit openshell-middleware` | Each connection the sandbox's network policy allowed or blocked, the start and end of the sandbox's entrypoint, each change of its policy | `effect.observed{sensor: openshell}`, with `denied: true` for a block; a policy change as an `ext` record `openshell.policy` |

Losses are on the record: drops a sensor reports, OpenShell's own gap records, and an import that goes quiet for 90
seconds or restarts each become a signed `observer_lost` gap naming the sensor. An event for an identity with no open
run is an `effect_outside_run` gap in the tenant's signer run.

The signer records these effects but doesn't reconcile them. `tracekit analyze --v2` compares them with the run's calls:
TK-X206 flags a process, connection or file write no call explains, and TK-X207 a call that returned ok without the
effect it should have caused ([findings](../findings.md#effects-what-a-kernel-sensor-saw)). OpenShell reports only the
entrypoint's process, so only a Tetragon or Falco import makes processes `observed`. Each import is tested against
events built as the source's code writes them, not yet against a live sensor or a released OpenShell. Setup:
[Tetragon](../integrations/tetragon.md), [Falco](../integrations/falco.md), [OpenShell](../integrations/openshell.md);
what each misses: [limits](../limits.md#kernel-sensor-import).

## When the agent never calls the hook

Then that action leaves no record: nothing can sign what it never sees. The way to close the gap is to put a layer
outside the agent's process that it has to go through: a mandatory LLM gateway with network rules (a hidden call
becomes `hook_missing`), the tool executor or MCP gateway holding the credentials, or the egress observer. A kernel
sensor import sees what the hidden action did on the machine, and `tracekit analyze --v2` reports what no call
explains.

## Reference

[FAQ: what can't Tracekit prove](../faq.md#what-cant-tracekit-prove) · reconciliation:
[`tracekit/signer/reconcile.py`](../../tracekit/signer/reconcile.py) · the sensor import:
[`tracekit/sensor.py`](../../tracekit/sensor.py) · [every known limit](../limits.md)

---

Previous: [Detection and containment](containment.md) · [All concepts](README.md) · Next: [Custody](custody.md)
