# Incidents and containment

Detection ([policy](policy-v2.md#detection-sequences-limits-and-respond)) opens an incident when a trigger fires. In
`mode: shadow` that is all: the incident is recorded with the action it `would` take. In `mode: enforce` the signer
acts on it, in the same writer step as the record that fired it, so no call slips in between. This page says what each
response does, who can end it, and what the verifier checks.

```yaml
# policy
respond:
  - {trigger: TK-Q001, mode: enforce, action: hold}                 # a secret read, then egress: hold the session
  - {trigger: executed_against_policy, mode: enforce, action: quarantine, suspend: true}
  - {trigger: denied_calls, mode: enforce, action: notify, max: 5, window: 300}
```

## What each response does

| Response | Effect | Ends |
|---|---|---|
| `notify` | The incident goes to every webhook subscribed to `incident` events, at least once ([webhooks](webhooks.md)). The signer refuses to start with an enforced `notify` and no such webhook. | — |
| `hold` | In every live run the incident's scope reaches (`run`, `session`, `owner` or `principal`): the run's live approvals expire (`approval.expired{reason: hold}`) and waiters wake; `run.held` records the hold, with `in_flight`, the calls allowed and not completed then. Each further call is an `ask` (`TK-HOLD`, carrying the `incident_id`) that only a person answers: never an agent approver, never the run's owner, principal or requester, even with `self_approval: allow`. A consume is refused unless its approval is such a person's (`TK-HOLD`). The call whose decision fired the hold is decided again, held. A held run's approvals and waits use a budget of the run's own, so its owner's healthy runs keep theirs. With no person approver configured, a hold is a quarantine. | A person resumes the run, or resolves the incident (`run.resumed`). |
| `quarantine` | In every live run the scope reaches: live approvals expire (`reason: quarantine`), `run.quarantined` records it, each further call is a deny (`TK-QUARANTINE`; past 100 of them the signer refuses unrecorded), every consume is refused, a gateway's model request is refused (the LLM loop stops), and the run closes with `run.closing{reason: quarantine}`. | Never: a quarantine is final. |
| `suspend: true` | Only with `executed_against_policy`, the one trigger no content the agent reads can steer: the run's owner goes on the suspension list (below). Lint refuses it on any other trigger. | An operator unsuspends. |

What the caller of a held or quarantined run is told says what happened and what to do, for example:

```text
forbidden: run tk-0.4f… is quarantined by incident inc-9a…: its calls are denied for good; an operator reviews it
(tracekit signer incidents show inc-9a…)
```

and a held call's decide answers `ask` with `incident_id` and a `reason` naming who ends the hold.

**Evasion.** For `cooldown_s` (default 3600) after a hold or quarantine, a new run of the same owner and attested
principal starts held or quarantined (`run.held{inherited: true}`), as does a child run of a held one. Closing a held
run does not resolve its incident.

**State.** Holds, quarantines, cooldowns, the paused flag and the suspensions a signer enforces are rebuilt from the
records on restart, from a snapshot, and after a storage recovery. When the detector can't vouch for a decision (its
state is `unavailable` after a restart that lost it) and the policy enforces a hold or quarantine, the decision's run
is held under a `detector_unavailable` incident: fail closed.

## Operators

The operator calls are `authorize` grants, never defaults, and act in the caller's tenant. An identity that owns open
runs (an agent's own) is refused whatever it is granted. Each writes a signed record.

```sh
tracekit signer incidents list [--state open] --signer https://tk-0.signer:8443 --signer https://tk-1.signer:8443
tracekit signer incidents show inc-…
tracekit signer incidents resolve inc-… [--reason "case 812"]   # resumes the runs it holds; quarantines stay
tracekit signer incidents hold RUN | quarantine RUN | resume RUN
tracekit signer incidents pause | unpause      # the response engine of each replica named; detection keeps recording
tracekit signer incidents suspend uid:1001 | unsuspend uid:1001
```

| Call (RPC) | Record |
|---|---|
| `incident_list`, `incident_show` | none |
| `incident_resolve` | `run.resumed` in each run it still holds, then `incident.resolved` in the tenant's signer run |
| `run_hold`, `run_quarantine` | `incident.opened{trigger: operator}` and `run.held` / `run.quarantined` in the run |
| `run_resume` | `run.resumed` (the incident stays open) |
| `response_pause`, `response_resume` | `incident.response{enabled}` in the tenant's signer run |
| `suspend`, `unsuspend` | `identity.suspension{state: suspended \| lifted}` in the tenant's signer run |

**Who resolves.** Resolving an incident or resuming a run needs a person (an identity `approvals.persons` maps, or an
OIDC person) who is an approver, or break-glass with a `--reason`; never the owner, principal or requester of a run it
concerns. Resolving is not undoing: it ends holds, never a quarantine, and records who did it. Notes (`--reason`) are
redacted and never leave in a webhook.

**Suspension list.** `suspensions:` in signer.yaml names a JSON file every replica reads on each call (default
`<data_dir>/suspensions.json`): `{tenant: {identity or prefix: {by, at, reason?, incident_id?}}}`. A suspended identity's
calls (register_run and every per-run call, any identity scheme, also as `person:` or `group:`) are refused, in the entry's tenant only: an operator's `token:*` reaches only their own tenant's tokens, and an operator can suspend
or lift only their own tenant's entries. Each
replica writes its own `identity.suspension{state: enforced}` the first time it sees an entry, and `lifted` when it is
gone. No token is revoked: revoke it yourself if the identity is lost.

## What the verifier checks

`tracekit verify` (and the TypeScript verifier) adds an `incidents` line when a bundle holds containment records
([format](format-v2.md#11-verification-algorithm)): every cited record in the bundle exists and is one that fires a
trigger; an incident of scope `run` citing only its run is recomputed from the run's records under the compiled policy
`tracekit export --v2` bundles for the run's `policy_hash` (`policies/<hex>.json`, SHA-256 = the hash); a
`detector_unavailable` incident cites a decision whose detection state was unavailable; and every response was
honoured: no allow after a hold without a person's approval carrying the incident id, only denies after a quarantine,
no result after a hold but of a call in flight then or approved by a person for it. Incidents of other scopes, operator
incidents, runs decided under several policies and runs whose policy is not in the bundle (an `incident policies`
warning: export with the signer's config) are counted signer-asserted; a `run.held` of an incident opened in
another run is its pointer in this one.

## Metrics

`tracekit_signer_incidents_total{trigger,action,mode}`, `tracekit_signer_held_runs`,
`tracekit_signer_quarantined_runs`, `tracekit_signer_suspended_identities`, `tracekit_signer_detector_unavailable`
and `tracekit_signer_incident_outbox_failures_total` ([observability](observability.md)). The viewer marks incidents,
holds, quarantines and resumes on the timeline and lists a run's incidents in its review (read-only).

## Limits

See [limits](limits.md#detection-12): enforcement on T1 paths, per-replica state, listing across replicas, the verifier's
signer-asserted incidents, at-least-once delivery.
