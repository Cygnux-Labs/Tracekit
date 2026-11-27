"""The top-level keys of signer.yaml. No third-party imports: `tracekit init` reads them on a system Python that has
none."""

CONFIG_KEYS = {"data_dir", "socket", "socket_mode", "tcp_endpoint", "http", "durability", "tenant", "tenants",
               "authorize", "limits", "acknowledge_rollback", "policy", "multi_tenant_apps", "migrators", "analyzers",
               "importers", "fail_modes", "grace_s", "idle_s", "origin", "metrics", "witnesses", "contact", "approvals",
               "lock_timeout_s", "fsck_every_s", "clock_skew_s", "anchors", "otlp", "otel_out", "storage", "gateways",
               "gateway_mandatory", "log_key", "harness_binding", "record_key", "route", "view", "decision_keys",
               "webhook", "content", "gateway_wait_s", "suspensions", "posture", "observe_grace_s",
               "verify_tool_results", "box_daemons", "grants"}

ON_BEHALF = "approval_decide_on_behalf"   # an `authorize` grant, never a default: a bridge answers for its people
DECISION_IMPORT = "decision_import"   # an `authorize` grant, never a default: an external policy system's decisions
OPERATOR = frozenset({"incident_list", "incident_show", "incident_resolve", "run_hold", "run_quarantine", "run_resume",
                      "response_pause", "response_resume", "suspend", "unsuspend",
                      "run_label_clear"})   # containment's operator calls, and clearing a run label
# tailer_heartbeat: only an identity granted it (TAILER_METHODS), so the agent can't keep a killed tailer's
# heartbeats going with its own token; observe_effect: an egress observer's own identity, never an agent's;
# channel_open: a box_daemons identity's alone, whatever `authorize` lists; export_run: any run of the caller's tenant
NEVER_DEFAULT = frozenset({DECISION_IMPORT, ON_BEHALF, "content_get", "content_erase", "approval_review",
                           "approval_agents", "tailer_heartbeat", "observe_effect", "channel_open",
                           "export_run"}) | OPERATOR
DEFAULT_GRANTS = frozenset({
    "register_run", "decide", "complete", "observe", "state_write", "model_event", "approval_request",
    "approval_decide", "approval_wait", "approval_consume", "approval_get", "approval_list", "approval_abandon",
    "approval_revoke", "approver", "close_run", "delegate_run", "tailer_lost", "status", "read", "checkpoint_nudge",
    "passkey_register", "why_finding", "review_finding", "constraint_add", "pcm_sign", "pcm_grant", "pcm_delegate",
    "pcm_evidence", "grant_issue", "grant_list", "grant_revoke", "call_state", "call_claim"})
