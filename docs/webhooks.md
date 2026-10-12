# Webhooks (OCSF)

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

The v2 signer can send its security-relevant records to a SIEM or any HTTPS endpoint as
[OCSF](https://schema.ocsf.io) 1.3 events:

```yaml
# signer.yaml
webhook:
  - url: https://siem.example.org/tracekit   # https, or http to loopback
    format: ocsf
    events: [deny, approval, gap, tamper]    # any of decision, deny, approval, gap, tamper, incident
    secret_file: webhook.secret              # relative paths are from signer.yaml
  - format: slack                            # incidents as Slack messages
    events: [incident]
    secret_file: slack.url                   # holds the Slack incoming-webhook URL (https)
```

| `events` | Records | OCSF class |
|---|---|---|
| `decision` | every `policy.decision` (a deny too) | API Activity (6003, activity Other); a deny is a Detection Finding |
| `deny` | `policy.decision` with `decision: deny` | Detection Finding (2004), severity Medium |
| `approval` | `approval.request`, `approval`, `approval.consumed`, `approval.expired`, `approval.abandoned`; `approval.refused`, `approval.binding_mismatch` | API Activity (Create for a request, Update for the rest); refusals and mismatches are Detection Findings |
| `gap` | `capture.gap` | Detection Finding, severity Medium, titled `capture.gap <kind>` |
| `tamper` | `trace.tamper` | Detection Finding, severity Critical |
| `incident` | `incident.opened`, `incident.updated`, `incident.capped`, `incident.resolved`, `incident.response`, `run.held`, `run.resumed`, `run.quarantined`, `identity.suspension` ([incidents](incidents.md)) | Incident Finding (2005): `finding_info_list[0].uid` the incident id, `related_events` the record and the records it cites, each with its `event_hash` as `uid`; activity Create (opened), Close (resolved) or Update; severity High for a hold or quarantine |

Each POST carries a JSON array of events (up to 100). Every event has `time`, `metadata` (`uid`: the record's event
id, `correlation_uid`: the run id, `log_name`: the log id, `product`) and `unmapped.tracekit`: the tenant, run id,
run_seq, log seq, event type and `event_hash` (the record's hash, to find it in a bundle), plus the ids, verdicts,
identities, rule ids, digests and commitments the record holds. Agent content (arguments, results, reasons) never
leaves: arguments only as their salted commitment (`args_commitment`).

## Checking the signature

Every body is signed with the secret in `secret_file`:

```text
X-Tracekit-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>
```

Recompute the HMAC over the raw body, compare in constant time, and refuse a `t` far from your clock to stop replays.

## Delivery

The signer's writer only queues events; one thread per webhook sends them. A post that fails (unreachable, 5xx, 408
or 429) is retried up to 5 times with backoff from 0.5 s to 30 s; another 4xx is not retried. Events not delivered are
dropped and counted in `tracekit_signer_webhook_dropped_total` by reason: `queue_full` (more than 10000 waiting),
`failed`, `shutdown` (still queued when the signer stopped) ([observability](observability.md)). Delivery is best
effort: the signed log, not the webhook, is the evidence.

## Incidents: at least once

`incident` events don't go through that queue. Each webhook subscribed to them has an outbox: a cursor over the
signer's log (`<data_dir>/outbox-<id>.json`) that moves past a batch only once the endpoint answered 2xx, so an outage
or a restart resends rather than loses. Receivers deduplicate by incident id and record uid. A failed post is retried
with backoff from 0.5 s to 30 s for as long as it takes (`tracekit_signer_incident_outbox_failures_total{reason="retry"}`);
a 4xx other than 408 or 429 skips the batch (`reason="refused"`); a log it can't read or a record it can't map is
tried again every second (`reason="error"`: a rising count means delivery is stalled). A new webhook starts at the
log's end. Operator notes never leave: `reason` is not in any event.

A Slack webhook gets one message per batch, a line per record (incident id, trigger, rules, scope, run, actions, and
the tools of the records it cites), every value escaped so that a tool name or principal can't mention, link or format.

Tested in `tests/test_webhook.py`: events from a real signer validated against the OCSF subset they use
(`tests/data/ocsf/`), the signature, retries and drops.
