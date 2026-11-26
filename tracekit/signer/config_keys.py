"""The top-level keys of signer.yaml. No third-party imports: `tracekit init` reads them on a system Python that has
none."""

CONFIG_KEYS = {"data_dir", "socket", "socket_mode", "tcp_endpoint", "http", "durability", "tenant", "tenants",
               "authorize", "limits", "acknowledge_rollback", "policy", "multi_tenant_apps", "migrators", "analyzers",
               "importers", "fail_modes", "grace_s", "idle_s", "origin", "metrics", "witnesses", "contact", "approvals",
               "lock_timeout_s", "fsck_every_s", "clock_skew_s", "anchors", "otlp", "otel_out", "storage", "gateways",
               "gateway_mandatory", "log_key", "harness_binding", "record_key", "route", "view", "decision_keys",
               "webhook", "content", "gateway_wait_s", "suspensions", "posture", "observe_grace_s",
               "verify_tool_results", "box_daemons", "grants"}
