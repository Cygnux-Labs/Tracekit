# Signer observability

The v2 signer serves Prometheus metrics (text exposition format 0.0.4) on a port of its own:

```yaml
# signer.yaml
metrics: {listen: 127.0.0.1:9464}
```

`GET /metrics` and `GET /logs/v0` (the signer's logs list for witnesses, see below) are served there. The default and any loopback address need nothing more; a non-loopback listen
(for example `0.0.0.0:9464` in a pod) needs `allow_remote: true` and refuses to start without it.

No metric carries a run id, tenant, identity, key or argument. Label values come from fixed signer-defined sets (event
types, gap kinds, RPC error codes, verdicts); past 64 distinct values a label is counted as `other`.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tracekit_signer_batch_size` | histogram | | Items the writer took in one batch. |
| `tracekit_signer_ack_seconds` | histogram | | Seconds from a client write's submit to its answer (includes the queue wait and, with `ack-on-fsync`, the sync). |
| `tracekit_signer_fsync_seconds` | histogram | | Seconds one sync of a log took (background syncs with `ack-on-write`, every batch with `ack-on-fsync`). |
| `tracekit_signer_records_total` | counter | `type` | Records written, by event type. |
| `tracekit_signer_gaps_total` | counter | `kind` | `capture.gap` records written, by gap kind (`client_counter_gap`, `signer_unavailable`, ...). |
| `tracekit_signer_refusals_total` | counter | `code` | RPC calls refused, by error code (`quota_exceeded`, `unavailable`, ...). |
| `tracekit_signer_auth_failures_total` | counter | | Failed authentications on the HTTP transport (bad, expired or revoked credentials). |
| `tracekit_signer_policy_decisions_total` | counter | `verdict` | `policy.decision` records written, by verdict (`allow`, `flag`, `ask`, `deny`). |
| `tracekit_signer_policy_nondeterministic_total` | counter | | Policy decisions where a regex ran out of time (the call is denied and the record marked `nondeterministic`). |
| `tracekit_signer_queue_depth` | gauge | | Items waiting for the writer. |
| `tracekit_signer_fsync_lag_seconds` | gauge | | Seconds the oldest written but not yet synced record has waited; 0 with `ack-on-fsync`. |
| `tracekit_signer_open_runs` | gauge | | Runs registered and not yet closing. |
| `tracekit_signer_pending_approvals` | gauge | | Approvals requested and not yet answered. |
| `tracekit_signer_checkpoints_total` | counter | | Signed checkpoint notes of the record tree written. |
| `tracekit_signer_checkpoint_age_seconds` | gauge | | Seconds since this signer last wrote a checkpoint note (since start when it has written none). Alert when it grows well past the 10 s cadence while records are written. |
| `tracekit_signer_witness_publish_failures_total` | counter | `witness` | Checkpoint notes a configured witness did not cosign (unreachable, refused, bad cosignature), by witness name. |
| `tracekit_signer_witness_lag_records` | gauge | `witness` | Records in the latest record tree note that the witness has not cosigned yet; it should return to 0 within seconds. |
| `tracekit_signer_anchor_lag_records` | gauge | `anchor` | Records in the latest record tree note not anchored in Rekor yet; it grows between anchors (at most hourly) and should drop after each. |
| `tracekit_signer_log_key_failures_total` | counter | | Checkpoint notes the log key (file or KMS) failed to sign; the note is retried next round, and a long outage writes a signed gap. |
| `tracekit_signer_loop_errors_total` | counter | `loop` | Unexpected errors of a background loop (`ticker`, `checkpointer`, `publisher`), which logs it and carries on. Any increase is a bug to report. |
| `tracekit_signer_otel_export_dropped_total` | counter | `reason` | Runs the OTLP exporter (`otel_out`) did not deliver: `queue_full` (more than 1000 runs waiting), `failed` (the endpoint was unreachable or refused), `shutdown` (still queued when the signer stopped). |
| `tracekit_signer_webhook_dropped_total` | counter | `reason` | Events a [webhook](webhooks.md) did not deliver: `queue_full` (more than 10000 waiting), `failed` (refused, or still failing after 5 tries), `shutdown` (still queued when the signer stopped). |

`witness` values are the names of the witnesses in signer.yaml. The metrics port also serves `GET /logs/v0`, the
signer's logs list for witnesses (docs/witnesses.md).
