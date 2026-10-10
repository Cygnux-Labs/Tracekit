# Webhooks (OCSF)

The v2 signer can send its security-relevant records to a SIEM or any HTTPS endpoint as
[OCSF](https://schema.ocsf.io) 1.3 events:

```yaml
# signer.yaml
webhook:
  - url: https://siem.example.org/tracekit   # https, or http to loopback
    format: ocsf
    events: [deny, approval, gap, tamper]    # any of decision, deny, approval, gap, tamper
    secret_file: webhook.secret              # relative paths are from signer.yaml
```

| `events` | Records | OCSF class |
|---|---|---|
| `decision` | every `policy.decision` (a deny too) | API Activity (6003, activity Other); a deny is a Detection Finding |
| `deny` | `policy.decision` with `decision: deny` | Detection Finding (2004), severity Medium |
| `approval` | `approval.request`, `approval`, `approval.consumed`, `approval.expired`, `approval.abandoned`; `approval.refused`, `approval.binding_mismatch` | API Activity (Create for a request, Update for the rest); refusals and mismatches are Detection Findings |
| `gap` | `capture.gap` | Detection Finding, severity Medium, titled `capture.gap <kind>` |
| `tamper` | `trace.tamper` | Detection Finding, severity Critical |

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

Tested in `tests/test_webhook.py`: events from a real signer validated against the OCSF subset they use
(`tests/data/ocsf/`), the signature, retries and drops.
