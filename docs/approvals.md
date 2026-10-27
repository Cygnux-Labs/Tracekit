# Approvals (v2 signer)

> **Experimental:** agent approvers, the reference reviewer, Slack approvals and passkey approvals work and are tested, but may change and get less hardening than the [stable core](support.md), which includes approvals from the command line.

An `ask` rule ([policy](policy-v2.md)) holds a tool call until a person answers it. The approval lives in the signer,
is bound to the exact arguments of one call attempt, and is consumed once. The v1 daemon's `tracekit pending` /
`approve` / `reject` and their v2 equivalents are listed in [migrating](migration.md#what-changes).

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
   tracekit approvals list --json          # all pages as one JSON array; [] when empty
   tracekit approvals show apr-… --json    # redacted arguments decoded in one JSON object, no pager
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

To use T2, mark the rules whose calls must run exactly as approved:

```yaml
ask:
  - id: PAY
    tool: "^pay$"
    pattern: "^"
    approval: {executor: t2}
```

Who runs the call then:

- The [tool executor](executor.md) and the [MCP gateway](mcp-gateway.md) run it outside the agent, with credentials
  the agent never holds, and run the arguments the consume returns. Their records are tier T2 and name the service in
  `via`. This is the strong form: the agent can neither run the call itself nor change what runs, and the signer takes
  the call's approval request, consume and completion from that service alone, so the agent can't answer for it.
- Every shipped adapter (Python and TypeScript) also runs the arguments the consume returns, not the framework's, so
  arguments changed after the approval don't run. The call still runs in the agent's process (T1), which could run it
  around the adapter.

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

- A signer started from `signer.yaml` (`tracekit signer serve --config`) follows these rules, with or without an
  `approvals` section: only an approver whose identity maps to the run's tenant (`tenants`) may answer. The
  requester, the run's owner and its principal (`register_run`'s `principal`) may not, unless
  `self_approval: allow` (refused with "may not answer its own run's approval"). Without the section nobody is an
  approver, so only break-glass identities can answer: list approvers, or set `self_approval: allow` for a
  single-user setup (assurance stays `dev`). Identities `persons` maps to the same person id count as that one person, so Alice can't
  approve from Slack what her own agent asked for. The `approval` record carries the approver's `person`.
- **Break-glass** identities may answer any approval, of any tenant, and must give a reason. The `approval` record
  carries `break_glass: true`; the verify report lists every such answer as a warning.
- The **dev signer** (`tracekit up`, or started by the SDK; it has no config) lets any identity of the run's tenant
  answer, including the requester. Such an answer is recorded `self_approved: true`, the report says `approvals:
  self`, and assurance is capped at `dev`. A signer started with `self_approval: allow` records a self-approval the
  same way.
- Approvals are listed and shown only to the run's owner and to those who may answer them; another tenant never sees
  them. `tracekit approvals list` names the identity it asked as when it shows none.
- OIDC identities are compared by person id, and a run's attested principal never answers its run's approvals
  ([identity.md](identity.md)).

`tracekit init --v2` (system mode) refuses an approver that is the agent's own user, and refuses to install without
one.

## Web approvals and passkeys

`tracekit view` with a `view.signer` ([identity.md](identity.md#viewer-login)) serves approval pages to approvers
who signed in with OIDC: `/approvals` lists their tenant's pending approvals and shows one from the signer's copy (tool,
rule, run, requester, expiry, arguments with redaction markers), with approve and reject and a reason. The list
refreshes every 5 seconds and shows each waiting approval's arguments in one line, when it expires ("in 12 min") and
a link to its run; an approval already answered offers no approve or reject. The pages call
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

## Agent approvers

A reviewer agent may clear routine held calls (format 1.2, RPC 16). Its judgment is model output, and under prompt
injection the requesting agent controls every argument it reviews, so the guarantees come from the signer: an agent
answers only calls inside bounds the policy sets, people answer everything else, and an agent can only narrow what the
bounds allow.

**Identities.** In `signer.yaml`:

```yaml
authorize:
  "mtls:spiffe://acme/reviewer": [approval_list, approval_review, approval_decide, status]
  "mtls:spiffe://acme/ops/oncall": [approval_agents]      # the kill switch
approvals:
  approvers: ["oidc:alice", "group:acme/payments"]       # people: with agents, each one a person
  persons: {"slack:T0123/U0456": alice}
  agents: ["mtls:spiffe://acme/reviewer"]                # exact identities: no prefix, no group
  agent_consume_s: 300      # an agent's approval is consumed within this, or never (default 300)
  agent_timeout_s: 600      # no agent answer by then: the signer escalates to people (default 600)
  ttl_s: 3600               # every approval's lifetime (default 3600)
```

The signer refuses to start when an agent is also an approver (directly or by a prefix), break-glass, in `persons`,
in `multi_tenant_apps` or granted `approval_decide_on_behalf`; when `agents` is set without `approvers`; and when an
approver is not a person (mapped in `persons`, an OIDC person or group). An agent is an agent on every path: never
break-glass, never covered by `self_approval: allow`, never answered for by a bridge. It may call only
`approval_list`, `approval_review`, `approval_decide` and `status`, and only with an `authorize` entry (no default
grant). It never answers an approval of a run it requested or owns, or whose attested principal is its own person.

**Bounds.** An ask rule says what agents may answer ([policy](policy-v2.md#agent-approvers-approvalagent)):

```yaml
ask:
  - id: PAY-SMALL
    class: payment
    pattern: "^"
    approval:
      executor: t2
      agent:
        mode: enforce                     # or shadow
        allow:
          fields:
            amount: {type: integer, min: 1, max: 10000}
            payee: {type: string, enum: [acct-1, acct-2]}
            memo: {type: string, pattern: "[A-Za-z0-9 ]{0,64}"}
        budget: {count: 20, sum: {field: amount, max: 50000}, window: 86400, scope: tenant}   # or scope: requester
        veto_s: 60                        # optional: people may revoke for this long before it runs
```

The bounds are a closed world, checked by the signer on the arguments it decided: every argument must be named, and
every named one present and not null; a value has exactly its JSON type (the string `"100"`, `1e2`, `99.9` and `true`
are no integer); a list passes only when it has elements and each one does, and an integer list only when its total
is within `max` too; two arguments the class reads as one
(`amount` and `amount_cents`, `payee` and `to`) fail; so do arguments over 16 KiB and a pattern that runs out of time.

**The floor: people answer** unless every rule the call was held by (flags aside) has `approval.agent` and its bounds
pass; the tool is one `tools` names exactly; no argument carries a value only untrusted content brought into the run
and the run's provenance is complete; the run is no replay or findings run; agent approvals are on; and the budget has
room. Synthetic rules (`TK-UNKNOWN-TOOL`, `TK-SQL-PARSE`, `TK-SHELL-PARSE`, `TK-OVERSIZE`) always need a person.
`approval.request` records the outcome as `agent: {eligible, reason, rules, conditions_hash, args_key}` (only when a
rule has `approval.agent`, so person-only bundles stay readable by a 1.1 verifier).

**Budgets** count the agent approvals the signed records hold (rebuilt on restart), by rule, per tenant or per
requesting identity (never an app-asserted principal). An approval under a `sum` budget records what it took
(`spent`). An answer that would exceed a budget is escalated to people instead.

**Anti-shopping.** Once an agent rejects or escalates a call (or the adapter abandons it after an escalation), or a
person rejects or revokes it, the same tool with the same arguments, or the same tool call id in any attempt, is a
person's to answer for the rest of the run; asking again writes a signed `capture.gap{reask_after_reject}`. A run
gets at most 10 agent reviews and a tenant 1000 an hour; past them, people answer.

**What the reviewer sees.** `approval_review {approval_id}`: the tool, the rule ids with the policy's `reason` and
`rationale`, each bound and whether it passed, the budget left, the signer's redacted copy of the arguments with control
and bidirectional-override characters escaped (`\u202e`), the arguments redaction changed, the expiry and a
`view_digest` (SHA-256 of JCS of the rest). Never the requesting agent's reason, the run id, the tool call id or where
a value came from. Agents can't call `approval_get`, and their `approval_list` leaves out the run id, tool call id,
attempt and requester. `approval_list` takes `state`, `escalated` and `for`: `agent` lists what an agent may still
answer (shadow mode included), `person` what an agent's answer can't decide.

**Answers.** `approval_decide` with `approve`, `reject` or `escalate` (agents only), optionally `asserted: {model,
version, prompt_hash}` (recorded `attested: false`). The `approval` record carries `approver_kind: agent`; an approval
carries `not_before` (after `veto_s`) and `consume_by` (`agent_consume_s` later): `approval_wait` answers `requested`
until `not_before`, a consume before it is refused `TK-APPROVAL-VETO`, and one after `consume_by` expires
(`approval.expired{reason: consume_window}`). `escalate` writes `approval.escalated`; the approval stays `requested`
(`approval_wait` adds `escalated: true`) and only people answer it, across restarts. The signer escalates on its own
after `agent_timeout_s` and when a budget is used up. In **shadow** mode an agent's answer is an `approval.suggested`
record and changes nothing: compare suggestions with what people decide before you enforce.

**Revocation and the kill switch.** A person revokes an agent's approval that is not consumed yet with
`approval_revoke` (`approval.revoked`; the call never runs). `approval_agents {enabled: false}` (an `authorize` grant,
never a default) writes a signed `approval.agents`, revokes every agent approval not consumed yet, escalates every
pending one agents could answer (`approval.escalated` by the signer, so it stays with people after agents are switched
on again) and sends every new approval to people until then.

**Adapters** keep waiting while an approval is `requested`, escalated or not, until their own deadline; none abandons
an escalated approval (`tracekit why` leaves it to expire with its run).

Metrics: `tracekit_signer_agent_approvals_total{decision}`, `tracekit_signer_agent_budget_spent_total{rule}`, and
`tracekit_signer_records_total{type="approval.escalated"|"approval.suggested"}`.

**What people see.** `approval_list` and `approval_get` show people `answered: {by, kind}` (`kind: agent` is model
output) and, once escalated, `escalation: {by: agent|signer, reason}`; an agent sees neither. Their `agent: true` means
an agent's answer can still decide the approval: it is agent-eligible, not escalated, agent approvals are on, the
policy is the one it was requested under, no agent said no to the same call, and no rule of it is in shadow mode. The
Slack bridge posts every approval without it (person-only, escalated, shadow mode, agents switched off) and leaves the
rest with the agent until it is escalated, at the latest after `agent_timeout_s`. Its messages name who answered and
show an agent's escalation reason labelled as model output over arguments the requesting agent supplied. The viewer's
approval desk filters for people, with an agent approver (`agent: true`), or escalated; a person revokes an agent's
approval not consumed yet from it. The
timeline labels agent approvals (`AGENT APPROVED`), shadow suggestions (`AGENT SUGGESTED`), escalations and
revocations, and a person's answer to a call an agent answered in shadow mode shows whether they agreed and the
agreement rate per rule so far. Verifiers count approvals by people and by agents on separate lines
([verdicts](verdicts.md#approvals-in-the-report)).

## The reference reviewer

`tracekit reviewer` is an agent approver you can run as it is: it polls `approval_list {state: requested, for: agent}`
on every signer replica it is given, and for each approval reads `approval_review` and makes one model call through
the [LLM gateway](gateway.md), with no batching and no memory across approvals. Its fixed system prompt treats the
view as data and asks for `{decision: approve|reject|escalate, reason}` (500 characters at most). An error, a timeout,
a refusal or a malformed answer escalates (and logs a warning: check the gateway URL, run token and model), and so does
a view in which a condition did not pass: it never asks the model about those. When the signer answers `unavailable`
or `quota_exceeded`, it tries that approval again at the next poll. It takes the conditions from `approval_review` (it
has no allowlist of its own) and sends `asserted: {model, version, prompt_hash}`. The signer checks every answer
again.

```yaml
# reviewer.yaml (relative paths are from this file)
signer: [https://tracekit-0.signer.internal:8443, https://tracekit-1.signer.internal:8443]   # or one URL
gateway: https://gateway.internal:8080     # the LLM gateway in front of Anthropic (api_key_header: x-api-key)
model: claude-opus-5-5                      # the default
poll_s: 5
timeout_s: 120                              # one model call; past it the reviewer escalates
tenants:                                    # it serves these tenants and no other
  acme: {token_file: acme-reviewer.token, run_token_file: acme-reviewer-runs.token}
```

```
tracekit reviewer serve --config reviewer.yaml
```

Per tenant, `token_file` is the bearer token of the identity listed in that tenant's `approvals.agents` (with the
`authorize` entry above); the reviewer refuses a Unix socket or `tcp://` signer, since an agent approver is never a
uid, and a `gateway` other than https (plain http only to localhost, 127.0.0.1 or ::1), since it sends the run token
there. `run_token_file` is an ordinary identity that registers the reviewer's runs and calls the gateway (signer.yaml
`gateways` lists the gateway as usual). Each review is a run of its own, agent `tracekit-reviewer`, whose first record
links it to the approval id and the view's digest, followed by the gateway's `model_event` records of the exchange.
The reviewer sends the redacted arguments of the tenants it serves to the model provider
([privacy](privacy.md#what-leaves-the-machine)).

**Before you enforce: eval, then shadow.**

1. `tracekit reviewer eval --config reviewer.yaml --store /var/lib/tracekit` (a signer's data_dir) or `--bundle
   run.tkb` replays the approvals people answered (approve or reject) of the configured tenants through the reviewer,
   sending no decision, and prints `{approvals, agree, false_approve, false_reject, escalate}` (a false approve: it
   approved what a person rejected). The records hold no arguments, so these views have the tool and rules only.
2. Set `mode: shadow` on the rules and run `tracekit reviewer serve`: its answers are `approval.suggested` records,
   people answer every call, and the viewer shows the agreement per rule. Compare until false approves are what you
   accept.
3. Switch the rules to `mode: enforce`, with `veto_s` if people should be able to revoke before a call runs.

## Expiry and abandon

An approval expires, with a signed `approval.expired` (on an approval agents may answer, with its `reason`):

- `approvals.ttl_s` (default one hour) after it was requested; a consume or answer after `expires_at` is refused even
  before the sweep records it (`ttl`);
- when its run goes final, since nothing could consume it afterwards (`run_final`);
- an agent's approval, `agent_consume_s` after it may be consumed (`consume_window`).

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
self-approval, message updates), `eval/e8_insider_v2.py` case E8v2.5 (the agent approving its own call in system mode),
`tests/test_agent_approvers.py` (bounds, lint, config, eligibility, budgets, anti-shopping, escalation across a
restart, revocation, the kill switch, shadow mode, the reviewer's view), `tests/test_reviewer.py` (the reference
reviewer with fake models that always approve, answer garbage, refuse or time out; the gateway run; eval; what the
Slack bridge posts; the desk's revoke; the timeline labels and shadow agreement), `tests/test_bundle_v2.py` and
`tests/test_ts_verifier.py` (the verifiers' agent-approval checks, with and without the policy snapshot) and `eval/e18_agent_approvers.py` (a reviewer
that approves anything, against every guarantee above).
