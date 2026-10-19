# Detection and containment

Some dangers only show as a pattern across calls: reading secrets and then sending data out, or deleting things very
fast. Detection lets a policy describe such patterns, and containment decides what happens when one trips: an alert, a
hold that hands every next step to a person, or a quarantine that stops the run. This is experimental.
Configuration and operator commands: [incidents](../incidents.md).

## What a policy can describe

```yaml
sequences:
  - id: TK-Q001
    steps: [secrets_access, egress]   # rule ids or labels, in order
    scope: session
    window: 600                       # seconds from the first step
limits:
  - id: TK-L002
    match: destructive                # a rule id, a label, or * for every call
    count: true                       # or sum: {field: cents, currency_field: currency}
    max: 30
    window: 60
    scope: session
respond:
  - {trigger: TK-Q001, mode: enforce, action: hold}
  - {trigger: executed_against_policy, mode: enforce, action: quarantine}
  - {trigger: denied_calls, mode: enforce, action: notify, max: 5, window: 300}
```

- **Sequences** are steps in order within a window, for example a call labelled `secrets_access` followed by one
  labelled `egress`.
- **Counts and sums** fire when calls matching a rule or label pass a maximum in a window, such as more than 300 calls
  a minute or a total payment amount.
- **Built-in triggers** include `executed_against_policy`, repeated denials, provenance holds and network traffic no
  call explains (from the [egress observer](custody.md#the-egress-observer)). What a kernel sensor reports
  (processes, file writes, connections) opens no incident: `tracekit analyze --v2` checks it against the calls after
  the run ([what was asked, said and done](provenance-and-why.md#what-was-asked-said-and-done)).
- **Scopes** are the run, the session (a run and its sub-agents), the owner or the principal.
- **Modes** are `off`, `shadow` (record what would have happened) and `enforce`. The server pack ships its detections
  in shadow mode.

## How detection runs

Detection is a pure function of the signed records, run by the signer's single writer as each record is written. It
reads the rule ids and labels each decision already carries, and runs no new regular expressions. Replaying the records,
backtesting a policy, and the verifier therefore all reach the same incidents.

Only calls that actually ran count: allowed calls, flagged calls, and asks whose approval was consumed. Denied calls
and unused asks don't. A tool of unknown class matches every step, so an unmapped tool can't slip between steps.

If the signer can't vouch for what came before (a restart that lost the detector's state) and the policy enforces a
hold or quarantine, the decision's run is held under a `detector_unavailable` incident: detection fails closed.

## Responses

| Action | What happens |
|---|---|
| `notify` | An alert goes to the incident webhook. Nothing is blocked |
| `hold` | The run's live approvals expire, and every later call becomes ask `TK-HOLD`, answerable only by a person (never an agent approver, the run's owner, principal or requester). The call that triggered the hold is decided again, held. With no person approvers configured, a hold becomes a quarantine |
| `quarantine` | Permanent. Calls are denied (`TK-QUARANTINE`), approvals can't be consumed, the LLM gateway stops forwarding the run's model requests, and the run closes |
| `suspend` | An operator action only (`tracekit signer incidents suspend`): blocks an identity entirely. A policy can't trigger it |

**Cooldown inheritance.** For `cooldown_s` (default one hour) after a hold or quarantine, new runs of the same owner
and principal, and child runs of a held run, start held or quarantined too. Starting a fresh run doesn't escape
containment.

## Incidents

Each trigger opens a signed `incident.opened` record with the trigger, the rules, the scope, the records it cites, the
mode and what it did (or, in shadow mode, would have done). Updates and resolutions are signed too. Per-run and
per-tenant caps stop a noisy pattern from flooding the log.

## Alerts

The webhook outbox sends incidents as OCSF 1.3 findings or Slack messages. Each OCSF body carries an HMAC signature,
so a receiver can tell real alerts from forged ones (a Slack webhook's URL is its secret). Incident alerts are
delivered at least once: the outbox only moves past an alert after a successful response, and retries with backoff for
as long as it takes (a 4xx refusal other than 408 or 429 skips the batch). Setup: [webhooks](../webhooks.md).

## Verifying containment

An operator could claim a run was contained when it wasn't. The verifier recomputes run-scope incidents from the
records and the bundled policy snapshot, and checks that a hold was followed by `run.held`, that nothing was allowed
after a hold without a person's approval citing the incident, and that only denials followed a quarantine. An allow
after a hold fails verification, in both verifiers. Session-, owner- and principal-scope incidents span other runs, so
the verifier counts them as stated by the signer.

## Where enforcement stops

A hold or quarantine is always recorded. It is enforced for certain only where the signer controls execution: the
tool executor, the MCP gateway and the LLM gateway (T2). On in-process paths (T1), the adapter obeys the signer's
answers, but an agent that bypasses its adapter isn't stopped, only recorded as far as any layer sees it.

## Reference

[Incidents](../incidents.md) · [webhooks](../webhooks.md) · detection:
[`tracekit/signer/detect.py`](../../tracekit/signer/detect.py)

---

Previous: [Approvals](approvals.md) · [All concepts](README.md) · Next:
[Capture and completeness](capture-and-completeness.md)
