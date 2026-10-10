# Approvals (v2 signer)

An `ask` rule ([policy](policy-v2.md)) holds a tool call until a person answers it. The approval lives in the signer,
is bound to the exact arguments of one call attempt, and is consumed once. The v1 daemon's `tracekit pending` /
`approve` / `reject` are described in the [README](../README.md#policy-and-approvals).

## Flow

1. The adapter calls `decide`; the signer answers `ask` and signs a `policy.decision`.
2. The adapter calls `approval_request(tool_call_id, attempt)`. The signer signs an `approval.request` with a random
   `approval_id`, the rule ids, the policy hash, the requester's identity, an expiry and a **binding**:

   ```text
   {"v": 1, "approval_id", "tenant", "run_id", "tool_call_id", "attempt", "tool",
    "args_commitment", "args_source", "policy_hash", "nonce", "expires_at"}
   binding_digest = "sha256:" + hex(SHA-256(JCS(binding)))
   ```

   The arguments are bound through `args_commitment` ([format v2](format-v2.md#2-hashes-over-agent-content)). The
   signer keeps its own copy of them, redacted for display and encrypted at rest under `keys/approval_args.key`. Asking
   again for the same call attempt returns the same approval, whatever its state.
3. An approver answers from another terminal:

   ```sh
   tracekit approvals list                 # pending and recent approvals you may see
   tracekit approvals show apr-…           # the signer's copy of the arguments, in full
   tracekit approvals approve apr-… --reason "checked the target"
   tracekit approvals reject apr-…
   ```

   `--signer` names the signer's socket or `tcp://host:port` (default: the same-user dev signer). The signer signs an
   `approval` record with the decision, the approver's identity as its transport established it, the channel, the
   reason, `self_approved` and, when it applies, `break_glass`. What the approver sees is the signer's copy, never
   what the agent shows; a reason the agent gave is printed as unverified.
4. Before the call runs, the adapter calls `approval_consume(tool_call_id, attempt, tool, args)`. The signer recomputes
   the arguments' digest and lets the call run only if the approval for that exact call attempt is `approved`, not
   expired, and opens the bound commitment. It then signs `approval.consumed`; the call runs once.

Refusals are signed too: `approval.binding_mismatch` when the arguments differ from the approved ones
(`TK-APPROVAL-MISMATCH`), and `approval.refused` for everything else: `TK-APPROVAL-UNBOUND` (the adapter's
`approval_id_hint` names another approval), `TK-APPROVAL-REQUIRED` (none was requested), `TK-APPROVAL-REQUESTED` /
`-REJECTED` / `-CONSUMED` / `-EXPIRED` (its state), `TK-ARGS-INVALID` (arguments that are not strict JSON). A call
that `decide` allowed or flagged needs no approval and consumes nothing.

States: `requested → approved | rejected | expired`, `approved → consumed | expired`.

## Consume once, per attempt

- One approval per `(tenant, run, tool_call_id, attempt)`. A consumed approval is never consumed again; a retry with
  `attempt + 1` needs a new `decide` and a new approval.
- The signer's index is the authority. A framework's saved state (LangGraph `interrupt()`, OpenAI `RunState`) may
  carry the `approval_id` as a hint, but an adapter must call `approval_consume` on every gated execution; the
  signer resolves the approval from its own index and refuses a hint that names a different one.
- A tool call that ran without a consumed approval (or against a deny) is signed by the signer as
  `capture.gap{executed_against_policy}` and shows as a `policy` warning in the verify report.

## Tiers: T1 and T2 executors

- **T1** (default): the approval binds the arguments the agent reported. The adapter runs the call in the agent's
  process after the consume.
- **T2**: an ask rule with `approval: {executor: t2}` makes `approval_consume` return the approved arguments from the
  signer's copy. The caller, a gateway or worker outside the agent, runs exactly those, so an agent can't run one
  thing after getting approval for another. The unredacted copy is used for execution only; approvers see the
  redacted one.

## Who may answer

Configured in `signer.yaml`:

```yaml
approvals:
  self_approval: deny                      # or allow
  approvers: ["uid:1001", "mtls:spiffe://acme/ops/*"]   # identities, or prefixes ending in :* or /*
  break_glass: ["uid:0"]                   # may answer any approval, with a reason
  persons:                                 # optional: identities of one person, across channels
    "slack:T0123/U0456": alice
    "mtls:spiffe://acme/ops/alice": alice
```

- With an `approvals` section, only an approver whose identity maps to the run's tenant (`tenants`) may answer. The
  requester, the run's owner and its principal (`register_run`'s `principal`) may not, unless
  `self_approval: allow`. Identities `persons` maps to the same person id count as that one person, so Alice can't
  approve from Slack what her own agent asked for. The `approval` record carries the approver's `person`.
- **Break-glass** identities may answer any approval, of any tenant, and must give a reason. The `approval` record
  carries `break_glass: true`; the verify report lists every such answer as a warning.
- **Without** an `approvals` section (the dev signer), any identity of the run's tenant may answer, including the
  requester. Such an answer is recorded `self_approved: true`, the report says `approvals: self`, and assurance is
  capped at `dev`.
- Approvals are listed and shown only to the run's owner and to those who may answer them; another tenant never sees
  them.
- OIDC identities are compared by person id, and a run's attested principal never answers its run's approvals
  ([identity.md](identity.md)).

`tracekit init --v2` (system mode) refuses an approver that is the agent's own user, and refuses to install without
one.

## Web approvals and passkeys

`tracekit view` with a `view.signer` ([identity.md](identity.md#viewer-login)) serves approval pages to approvers
who signed in with OIDC: `/approvals` lists their tenant's pending approvals and shows one from the signer's copy (tool,
rule, run, requester, expiry, arguments with redaction markers), with approve and reject and a reason. The pages call
the signer as a **bridge**: the viewer's own identity, granted `approval_decide_on_behalf` in `authorize` (never a default),
passes `on_behalf` (the person's subject, person id, groups and tenant from the login) on `approval_list`,
`approval_get` and `approval_decide`. The signer applies the rules above to that person, so the requester, the run's
principal (by person id) and other tenants are refused as they are on the CLI. The `approval` record carries the person
as `approver_identity` (`attested: false`: the bridge vouches for them), the bridge as `via`, and channel `web`.
Every `POST` needs the session's CSRF token ([security-checklist.md](security-checklist.md)).

A bridge acts for people of its own tenant (`tenants`) only: an `on_behalf` person of another tenant is refused
(`forbidden`), and one without a tenant is in the bridge's. A viewer that serves the approvers of several tenants (each
session's tenant comes from the issuer's tenant claim) is listed in `multi_tenant_apps`, which lets it name the
person's tenant.

```yaml
authorize: {"mtls:spiffe://corp/viewer": [approval_list, approval_get, approval_decide, passkey_register,
                                          approval_decide_on_behalf]}
multi_tenant_apps: ["mtls:spiffe://corp/viewer"]   # only when it serves more than its own tenant
approvals:
  approvers: ["group:corp/approvers"]
  break_glass: ["group:corp/oncall"]
  webauthn: {rp_id: view.corp.example, origin: "https://view.corp.example"}   # the viewer's host and origin
```

An ask rule with `approval: {passkey: required}` marks a high-risk call (`passkey: true` on its `approval.request`).
Approving it needs a WebAuthn assertion from the approver's passkey over
`SHA-256(JCS({"v": 1, "approval_id", "binding_digest", "decision": "approve"}))`. The binding digest covers the call's
arguments, so the assertion can't approve another approval, other arguments or another run. The signer checks it
(`tracekit/identity/webauthn.py`): clientDataJSON type `webauthn.get`, the challenge and `webauthn.origin`;
authenticatorData's rpIdHash for `webauthn.rp_id`, user present and user verified, and a signCount that grows; the
ES256 or EdDSA signature under the registered key. The record carries `passkey: {credential_id, user_verified: true}`.
An approval without one is refused, on every channel, so such calls are approved on the web only. Rejecting needs no
passkey.

An approver registers a passkey once from the page ("Register a passkey"), stored by person id in the signer's
`data_dir/passkeys.json`. A person keeps the first passkey they register: to replace it, an operator removes their
entry from that file.

Trust assumption: the signer takes the bridge's word for who is registering. It has no proof of its own that the
person behind the session is the person named, so whoever controls the bridge, or a session of that person, before
their first registration can enrol a passkey for them. The viewer narrows this to a fresh sign-in: it registers a
passkey only within 5 minutes of the session's OIDC login, else the page asks to sign in again. Have each approver
register right after onboarding, and check `passkeys.json` against the approver list.

## Slack

`tracekit approvals slack serve --config slack.yaml` runs a bridge that posts each pending approval it may see to a
Slack channel and answers the Approve and Reject buttons:

```yaml
# slack.yaml (relative paths are from this file)
signer: https://signer.internal:8443       # credentials as for any client: TRACEKIT_SIGNER_TOKEN_FILE, _CERT/_KEY, _CA
channel: C0123456789
bot_token_file: slack-bot-token            # the app's bot token (scopes chat:write, usergroups:read)
signing_secret_file: slack-signing-secret  # the app's signing secret
listen: 127.0.0.1:3000                     # POST /slack/interactivity: the app's interactivity Request URL
tls: {cert: tls.crt, key: tls.key}         # beyond loopback; or insecure_http: true when TLS ends in front of it
groups: [S0123456789]                      # user groups signer.yaml names as approvers
poll_s: 5
```

Each message shows the tool, the run, the call, the rule ids, the requester, the expiry and the signer's redacted copy
of the arguments, as plain text (an agent's `<!channel>` or link stays text). When the approval is answered, consumed or
expires, the bridge replaces the buttons with its state.

In `signer.yaml`, the bridge's identity gets three methods and nothing else, and the Slack users who may answer are
approvers like any other, as `slack:<team id>/<user id>`, `slack:<team id>/<user group id>` or `slack:<team id>/*`:

```yaml
authorize:
  "k8s_sa:system:serviceaccount:ops:slack-bridge": [approval_list, approval_get, approval_decide_on_behalf]
tenants: {"k8s_sa:system:serviceaccount:ops:slack-bridge": acme}   # the tenant whose approvals it posts
approvals:
  approvers: ["slack:T0123/U0456", "slack:T0123/S0789"]
  persons: {"slack:T0123/U0456": alice}
```

- A click is answered only when Slack's v0 signature over the body checks out under the signing secret, its timestamp
  is within 5 minutes, and the same signature was not seen before (a replayed callback is refused).
- The bridge calls `approval_decide_on_behalf` with the clicking user (`slack:<team>/<user>`) and the configured user
  groups Slack lists them in. `approval_decide_on_behalf` is an `authorize` grant only, never a default: a uid caller
  keeps every other method but not this one. The signer checks the Slack user (or one of those groups) against its
  approvers and its self-approval rule exactly as for an RPC answer; break-glass is not available through Slack.
- The `approval` record names both: `approver` and `approver_identity` are the Slack user (`attested: false`, since
  the bridge vouches for it), `via` is the bridge as the signer's transport authenticated it, `channel` is `slack`, and
  `groups` lists the groups the bridge reported.
- A refusal (not an approver, self-approval, already answered) is shown to the clicker only, as an ephemeral message.
- The bridge keeps which messages it posted in memory: after a restart it posts the approvals still pending again.

## Expiry and abandon

An approval expires, with a signed `approval.expired`:

- one hour after it was requested (`APPROVAL_TTL_S`); a consume or answer after `expires_at` is refused even before
  the sweep records it;
- when its run goes final, since nothing could consume it afterwards.

The adapter can give up on one at once with `approval_abandon` (for example, when the user cancelled the run): the
signer signs `approval.abandoned` and the approval can never be consumed. While an approval is pending, the run's idle
timeout is paused. The signer's copy of the arguments is deleted once the approval is consumed, rejected, expired or
abandoned.

## Where this is tested

`tests/test_signer_approvals.py` (replay, edited arguments, another run's approval, resume without a human, retries,
abandon, expiry, restart, encryption at rest, self-approval, tenant visibility), `tests/test_e13_approvals.py`
(a signer with an approver config, answered from the CLI and from the viewer's approval pages: arguments changed after
approval, a replayed assertion, expiry, self-approval by person id, another tenant, a passkey rule without a passkey,
break-glass without a reason), `tests/test_webauthn.py` (the assertion checks, with a software authenticator),
`tests/test_slack_approvals.py` (the Slack bridge against a real signer: signatures, replays, approve and reject, groups,
self-approval, message updates), and `eval/e8_insider_v2.py` case E8v2.5 (the agent approving its own call in system mode).
