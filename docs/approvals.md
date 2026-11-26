# Approvals (v2 signer)

> **Experimental:** agent approvers, the reference reviewer, Slack approvals and passkey approvals work and are tested, but may change and get less hardening than the [stable core](support.md), which includes approvals from the command line.

An `ask` rule ([policy](policy-v2.md)) holds a tool call until a person answers it. The approval lives in the signer,
is bound to the exact tool and arguments of one call in one run, and is consumed once: by that call, or by the agent's
retry of the same call after a person approved it ([approve, then retry](#approve-then-retry)). The v1 daemon's
`tracekit pending` / `approve` / `reject` and their v2 equivalents are listed in [migrating](migration.md#what-changes).

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
   again for the same call attempt returns the same approval, whatever its state. A new call of the same tool and
   arguments in the run gets an earlier call's approval once a person has approved it ([below](#approve-then-retry)).
3. An approver answers from another terminal:

   ```sh
   tracekit approvals list                 # those you may see: waiting ones first, newest first, with what each runs
   tracekit approvals list --all           # the expired ones too
   tracekit approvals show apr-…           # why, what to do instead, the answer commands, the arguments in full
   tracekit view --approval apr-…          # the link that opens the held call in the viewer
   tracekit approvals list --json          # all pages as one JSON array, every approval; [] when empty
   tracekit approvals show apr-… --json    # redacted arguments decoded in one JSON object, no pager
   tracekit approvals approve apr-… --reason "checked the target"
   tracekit approvals reject apr-…
   ```

   `--signer` names the signer: its socket, `tcp://host:port`, or `https://host:port` (`http://` on a loopback
   address) with the approver's token in `TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_API_KEY`
   ([remote clients](remote-ingest.md#on-the-agents-machine)). The default is `$TRACEKIT_SIGNER` (the system signer in
   system mode), else the same-user dev signer, so a central signer's approver can run:

   ```bash
   TRACEKIT_SIGNER=https://signer.internal:8443 TRACEKIT_SIGNER_TOKEN_FILE=~/approver.token \
     tracekit approvals list
   ```

   The signer signs an `approval` record with the decision, the approver's identity as its transport established it, the channel, the
   reason, `self_approved` and, when it applies, `break_glass`. What the approver sees is the signer's copy, never
   what the agent shows; a reason the agent gave is printed as unverified.
4. Before the call runs, the adapter calls `approval_consume(tool_call_id, attempt, tool, args)`. The signer recomputes
   the arguments' digest and lets the call run only if the approval for that exact call attempt is `approved`, not
   expired, and opens the bound commitment. It then signs `approval.consumed`; the call runs once.

Refusals are signed too: `approval.binding_mismatch` when the arguments differ from the approved ones
(`TK-APPROVAL-MISMATCH`), and `approval.refused` for everything else: `TK-APPROVAL-UNBOUND` (the adapter's
`approval_id_hint` names another approval; when another attempt of the same call already used it, as when two retries
race for one approval, the reason says so), `TK-APPROVAL-REQUIRED` (none was requested), `TK-APPROVAL-REQUESTED` /
`-REJECTED` / `-CONSUMED` / `-EXPIRED` (its state), `TK-ARGS-INVALID` (arguments that are not strict JSON). A call
that `decide` allowed or flagged needs no approval and consumes nothing.

States: `requested → approved | rejected | expired`, `approved → consumed | expired`.

## Consume once, per attempt

- One approval per `(tenant, run, tool_call_id, attempt)`. A consumed approval is never consumed again; a retry with
  `attempt + 1` needs a new `decide` and, unless a person approved an earlier attempt that nothing consumed yet
  ([approve, then retry](#approve-then-retry)), a new approval.
- The signer's index is the authority. A framework's saved state (LangGraph `interrupt()`, OpenAI `RunState`) may
  carry the `approval_id` as a hint, but an adapter must call `approval_consume` on every gated execution; the
  signer resolves the approval from its own index and refuses a hint that names a different one.
- A tool call that ran without a consumed approval (or against a deny) is signed by the signer as
  `capture.gap{executed_against_policy}` and shows as a `policy` warning in the verify report.

## Approve, then retry

A held call is often blocked before anyone has answered: the coding-agent hooks block it at once by default, since no
harness shows a hook's output while the hook runs ([held calls](coding-agents.md#held-calls-approve-then-retry)), and
other adapters stop waiting at their deadline. The approval stays `requested` until it expires. When a person approves
it, the agent sends the same call again, under a new tool call id, and that call runs:

1. The retry is decided like any call: a `policy.decision`, `ask`.
2. Its `approval_request` returns the earlier call's approval, `approved`, instead of a new one, when that approval:
   - is of the same run, the same tool and exactly the same arguments (its `args_commitment` opens with the retry's
     args digest), asked through the same gateway or none;
   - was asked under the same policy, for every rule the retry's decision names: a live constraint or a hold added
     since asks again;
   - is not older than a no: when the latest answer to the same call was a reject or a revoke (of another of its
     approvals), an earlier yes isn't used by a retry (a call decided again under its own id and attempt, as an SDK may
     do, still uses its own approval once);
   - is `approved`, by a person or an agent approver under [who may answer](#who-may-answer), and not yet consumed. A
     `requested`, `rejected`, revoked, `expired` or abandoned approval is never used, nor one past its `expires_at`
     (or an agent approval past its `consume_by`), nor one whose blocked call ran anyway (its result is recorded: the
     approval let one call run already). An agent's approval reads `requested` until its veto delay has
     passed, as `approval_wait` reads it: the retry is held until then, and the hook says it is approved and how many
     seconds to wait before trying again.

   Otherwise it asks as before, with a new approval. The signer decides this; nothing the agent sends can name an
   approval into use. If the latest answer to the same call in the run was a no (a person or an agent approver
   rejected it, or its agent approval was revoked; a later approval clears it), the decision's reason says so first,
   with the approval and who said no
   (`a person rejected this exact call (apr-…, by uid:501); ask them before trying again`), so the agent asks before
   it tries again; the new approval lets a person change their mind.
3. Its `approval_consume` consumes that approval, once: the signer signs `approval.consumed` with the approval's id and,
   from format 1.8, `ext.approval.decision`, the `policy.decision` it checked the use against, under the retry's
   `tool_call_id`; the approval's `approval.request` and `approval` records name the blocked attempt's. A T2 approval is
   consumed with the `approval_id_hint` that `approval_request` returned, and the consume returns the signer's copy of
   the arguments as for any T2 call.
4. The retry completes as an approved call (no `executed_against_policy` gap), once: a second result on the same
   approval, under another decision of the same call, is signed with that gap. If it never completes, the retry, not
   the blocked attempt, is the run's `decided_not_completed` gap. The blocked attempt never ran under the approval: if
   it ran anyway (an SDK agent that ran it despite `ask`), its result, before or after the retry's, is signed with an
   `executed_against_policy` gap.

Sent again before anyone answered, the call asks on its own, with a new approval each time; approving any of them lets
the next retry run. After a retry ran, the same call is held again: one approval runs one call. The records are the
ones every approval writes. A consume from this signer also carries `ext.approval.decision`, the decision it ran
under, when the signer can name one (the call's latest decision with the approved arguments, or the approval's own
decision for its attempt), so a bundle with a used approval needs a 1.4 verifier at least, as any bundle with an
`ext` name does: 1.2 and 1.3 answer `UNVERIFIABLE (needs tracekit >= 1.4.0)`. A verifier from 1.4 that doesn't read
the name still verifies the bundle and warns that it did not interpret it, so `--strict` exits 3.
A held or quarantined run follows [its own rules](incidents.md).

In Claude Code a Bash call's arguments include a free-text `description`, which the model rewords on almost every
retry. A person approves a command, not its caption, so the Claude Code hook keeps the session's last 32 held Bash
calls, each as digests of its arguments (with and without the description) and its approval's id: only which
approvals to try. A retry that differs from held calls of the same command only in its `description` is matched with
the answered ones. Approved, and none of them rejected: the hook reads the newest approved call's arguments from the
signer (`approval_get`), checks them against the retry's but the description, and decides and consumes the retry with
them, so the record is the call that was approved, description included; Claude Code runs the retry as the model sent
it, the same command with only its caption reworded (the hook returns no `updatedInput`, which could change how Claude
Code asks you). One of them rejected: the signer keeps no copy of a rejected call's arguments and doesn't say which
answer came last, so the retry is decided as the model sent it and held, and the first reason after `Why:` in its block
(`[tracekit] HELD, nothing ran: apr-…`) is `a person rejected this command (with another description) as apr-…`, adding
`, and it was approved (with another description) as apr-…` when one was. Each `(with another description)` is left
out where that wording is the retry's own, and a retry exactly as rejected, never approved, gets the signer's own
reason (`a person rejected this exact call …`). One the hook can't read (a signer whose `authorize` doesn't grant it
`approval_get`, or one restarting) runs nothing in place of the retry either, and neither does any retry once the
session has held more than 32 Bash calls: the oldest one dropped may be a rejected wording.
Any other key that differs (`command`, `run_in_background`, `dangerouslyDisableSandbox`, `timeout`, ...), or an
approval still unanswered, expired or used, and the retry is decided as the model sent it. The signer's rule above is
unchanged: the hook only chooses which arguments the retry is decided with, and the signer still checks them against
the approval. So a retry exactly as approved, description included, runs under that approval even when another
wording of the command was rejected: the person approved that call. It runs once; the approval is used up then.

## Approve calls like this one: grants

For a held payment, `tracekit approvals approve ID --grant --payee … --max '200 USDC' --total '500 USDC' --for 1h`
approves the call and grants the run more payments like it, within those limits: they run without a stop, and
anything outside them is held with the reason. `tracekit approvals show ID` says how a grant reads the call. See
[intent grants](intent-grants.md).

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
  same way. The approval counts, and `tracekit approvals approve` says so:

  ```text
  approved: apr-…, by you. It counts: the dev signer runs as your own user and can't tell you from your agent, so it
  records this as self-approved, and the run's assurance stays dev. A signer started from signer.yaml refuses an
  approval from the call's own requester unless that file sets approvals: {self_approval: allow}.
  ```

  With `--signer` (or `TRACEKIT_SIGNER`) it can't tell a dev signer from one whose signer.yaml allows it, and says
  "this signer lets the call's own requester answer (a dev signer, or approvals: {self_approval: allow} in its
  signer.yaml)" instead. A rejection from the requester is recorded the same way and caps the run's assurance at `dev`
  too: `tracekit approvals reject` says so.
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
        veto_s: 60                        # optional: people may revoke for this long before it runs (`tracekit approvals revoke`)
```

The bounds are a closed world, checked by the signer on the arguments it decided: every argument must be named, and
every named one present and not null; a value has exactly its JSON type (the string `"100"`, `1e2`, `99.9` and `true`
are no integer); a list passes only when it has elements and each one does, and an integer list only when its total
is within `max` too; two arguments the class reads as one
(`amount` and `amount_cents`, `payee` and `to`) fail; so do arguments over 16 KiB and a pattern that runs out of time.

**The floor: people answer** unless every rule the call was held by (flags aside) has `approval.agent` and its bounds
pass; the tool is one `tools` names exactly; no argument carries a value only untrusted content brought into the run
and the run's provenance is complete; the run is no replay or findings run; agent approvals are on; and the budget has
room. Synthetic rules (`TK-UNKNOWN-TOOL`, `TK-SQL-PARSE`, `TK-SHELL-PARSE`, `TK-SOURCE-PARSE`, `TK-OVERSIZE`) always need a person, but
`TK-SHELL-PARSE` and an unmapped tool's `TK-UNKNOWN-TOOL` flag through [the AI approver](#the-ai-approver).
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
until `not_before`, with a `reason` that says it is approved and how many seconds are left, a consume before it is
refused `TK-APPROVAL-VETO`, and one after `consume_by` expires
(`approval.expired{reason: consume_window}`). `escalate` writes `approval.escalated`; the approval stays `requested`
(`approval_wait` adds `escalated: true`) and only people answer it, across restarts. The signer escalates on its own
after `agent_timeout_s` and when a budget is used up. In **shadow** mode an agent's answer is an `approval.suggested`
record and changes nothing: compare suggestions with what people decide before you enforce.

**Revocation and the kill switch.** A person revokes an agent's approval that is not consumed yet with
`approval_revoke` (`approval.revoked`; the call never runs): `tracekit approvals revoke apr-… --reason …` (or `reject`
of it), never as the identity an agent session is open as. `approval_agents {enabled: false}` (an `authorize` grant,
never a default) writes a signed `approval.agents`, revokes every agent approval not consumed yet, escalates every
pending one agents could answer (`approval.escalated` by the signer, so it stays with people after agents are switched
on again) and sends every new approval to people until then.

**Adapters** keep waiting while an approval is `requested`, escalated or not, until their own deadline; none abandons
an escalated approval (`tracekit why` leaves it to expire with its run).

Metrics: `tracekit_signer_agent_approvals_total{decision}`, `tracekit_signer_agent_budget_spent_total{rule}`, and
`tracekit_signer_records_total{type="approval.escalated"|"approval.suggested"}`.

**What people see.** `approval_list` and `approval_get` show people `answered: {by, kind}` (`kind: agent` is model
output), once escalated, `escalation: {by: agent|signer, reason}`, and `ai`: whether an agent may answer it now and
why, and its latest answer ([the AI approver](#the-ai-approver)); an agent sees none of them. Their `agent: true` means
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
on every signer replica it is given, and for each approval reads `approval_review` and asks the model through the
[LLM gateway](gateway.md) or, with `url`, the model's own endpoint with your key, with no batching and no memory across
approvals. Its fixed system prompt treats the view as data and asks for `{decision: approve|reject|escalate, reason}`
(a reason of 500 characters at most). A yes needs two answers that approve (two keys: `model: [a, b]`,
or one model asked twice); a no or an escalation needs one, and the second call is made only after a first yes. An
error, a timeout, a refusal or a malformed answer escalates (and logs a warning: check the gateway URL or endpoint, the
run token or key file, and the model), and so does a view in which a condition did not pass: it never asks the model
about those. When the signer answers `unavailable`
or `quota_exceeded`, it tries that approval again at the next poll. It takes the conditions from `approval_review` (it
has no allowlist of its own) and sends `asserted: {model, version, prompt_hash}`, `ai: {answers}` and the
`view_digest` of the view it read. The signer checks every answer again. One approval it can't review (an error it
didn't expect) is logged and left to people; the poll goes on to the next.

```yaml
# reviewer.yaml (relative paths are from this file)
signer: [https://tracekit-0.signer.internal:8443, https://tracekit-1.signer.internal:8443]   # or one URL
gateway: https://gateway.internal:8080     # the LLM gateway in front of Anthropic (api_key_header: x-api-key)
model: claude-opus-5-5                      # the default
poll_s: 5
timeout_s: 120                              # one model call; past it the reviewer escalates
state_file: reviewer.state                  # optional: answered approval ids, kept across a restart
tenants:                                    # it serves these tenants and no other
  acme: {token_file: acme-reviewer.token, run_token_file: acme-reviewer-runs.token}
```

```
tracekit reviewer serve --config reviewer.yaml
```

Per tenant, `token_file` is the bearer token of the identity listed in that tenant's `approvals.agents` (with the
`authorize` entry above); the reviewer refuses a `tcp://` signer, the dev transport a process of the agent's own user
can use, takes a Unix socket only as [the AI approver on a laptop](#the-ai-approver) does, and refuses a `signer`,
`gateway` or `url` other than https (plain http only to localhost, 127.0.0.1 or ::1, as a signer's `insecure_loopback`
listener serves), since it sends its tokens there. `run_token_file` is an ordinary identity that registers the reviewer's runs and calls the gateway (signer.yaml
`gateways` lists the gateway as usual). Each review is a run of its own, agent `tracekit-reviewer`, whose first record
links it to the approval id and the view's digest, followed by the gateway's `model_event` records of the exchange.
The reviewer sends the redacted arguments of the tenants it serves to the model provider
([privacy](privacy.md#what-leaves-the-machine)).

`state_file` is optional. Without it the reviewer remembers the approvals it answered only in memory, so after a
restart a shadow-mode approval, which stays listed, gets a second model call and a second `approval.suggested`. With
it the ids are written there (a JSON list, replaced whole on each change, mode 0600) and read back at start; a
missing, unreadable or malformed file starts empty, and so does a symlink or anything but a regular file, which the
reviewer neither reads nor writes (it says so once, in its log).

**Before you enforce: eval, then shadow.**

1. `tracekit reviewer eval --config reviewer.yaml --store /var/lib/tracekit` (a signer's data_dir) or `--bundle
   run.tkb` replays the approvals people answered (approve or reject) of the configured tenants through the reviewer,
   sending no decision, and prints `{approvals, agree, false_approve, false_reject, escalate}` (a false approve: it
   approved what a person rejected). The records hold no arguments, so these views have the tool and rules only.
2. Set `mode: shadow` on the rules and run `tracekit reviewer serve`: its answers are `approval.suggested` records,
   people answer every call, and the viewer shows the agreement per rule. Compare until false approves are what you
   accept.
3. Switch the rules to `mode: enforce`, with `veto_s` if people should be able to revoke before a call runs.

## The AI approver

An AI reviewer can answer some of your coding agent's routine holds for you, in seconds: only kinds of call a person
already approved. It is off until your policy turns it on.

**What it answers.** You list the rules it may answer: an install from a package index you chose, a line the policy
can't read, or an unmapped tool given a command line. For a call held by one of them, it looks for a call like it that
a person approved in the last 30 days: the same rules, tool and target (for an install, the same package source),
the same project and the same agent. It approves only then, and only when two model answers both say yes. It never
answers a call in a session that read a secret (or untrusted content, when you list it), a call like one a person
rejected, or a call any other rule also holds. A person decides those.

**Installs it can answer.** A person's approval vouches for the index its line names, so the AI reviewer answers an
install only when the line names the index and switches every config file off. Otherwise a config file (`pip.conf`,
`.npmrc`, the global one or the virtual environment's) could add another index, and a person decides:

```
PIP_CONFIG_FILE=/dev/null pip install --isolated --index-url https://pypi.internal/simple requests   # alone on its line
npm install --registry https://npm.internal/ --userconfig /dev/null --globalconfig /dev/null left-pad   # unscoped only
```

pip's `--isolated` skips your user config and the `PIP_` variables but still reads the global and the virtual
environment's `pip.conf`; `PIP_CONFIG_FILE=/dev/null`, set for pip itself (before it, on a line of that one command),
turns them all off. npm's `--registry` doesn't turn off the user and global `.npmrc`; the two options do.

Never: an install that reads a requirements or config file (`-r requirements.txt`, `-c`, `--config-settings`, a
`PIP_CONFIG_FILE` or npm `--userconfig` other than `/dev/null`, an `npm_config_…` variable on the line, a `.npmrc` or
`pip.conf` on the line, a working tree npm changes to), a scoped npm package (`@acme/x`: its registry comes from the
project's `.npmrc`), uv (`--no-config` leaves `UV_INDEX`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL` and `UV_FIND_LINKS`
on), pnpm and yarn (they read `.npmrc` and their own config files, which no option turns off), bun, poetry, cargo and gem
installs, and a change to a package manager's config (`pip config set`). `tracekit approvals show` says which, and how
to pin the line.

**What you see.** `tracekit approvals show` and `list` say what it did, or why it won't answer:

```
ai          approved by the AI reviewer: it matched the call alice approved on 11-22 (pip --index-url https://pypi.internal/…)
ai          the AI reviewer won't answer this: the session read a secret: a person decides
```

They still say it for a day after the agent's session ends (the signer keeps the approvals of a finished run that
long, across a restart; `list --all` lists them). After that the run's records have it: `tracekit view --approval
apr-…`, run where the signer's data dir can be read.

**On and off.** A person switches it: `tracekit reviewer on` (or `on --rules TK-A025` for some rules only) and
`tracekit reviewer off`, each a signed record that names them. `off` withdraws its approvals not yet used and hands its
waiting calls to people at once. With no switch, the policy and `signer.yaml` decide alone; `tracekit init` sets up no
AI reviewer, so a new install starts without one. Only a person who answers approvals switches it, and never as the
identity an agent session is open as: the signer refuses that, and the policy denies the agent's own `tracekit
reviewer` changes (TK-D012). `tracekit reviewer status` says whether it is on, who switched it and when, what it may
answer, what it never answers, and how often people agreed with it per rule.

**Taking one back.** You can take back an AI approval before the agent's retry runs it: `tracekit approvals revoke
apr-… --reason …` (`reject` of it does the same, and so does the viewer's approvals desk). `approvals show` and `list`,
and the hook's Person line during `veto_s`, name the command while the approval is not yet used. Only a person takes one
back: the signer refuses the identity an agent session is open as. The AI reviewer then only suggests for that rule,
and a person decides, until you run `tracekit reviewer enable TK-A025`. `tracekit reviewer status` lists those rules and
why, and `approvals show` says who took it back and when:

```
ai          approved by the AI reviewer: it matched the call alice approved on 11-22 (pip --index-url https://pypi.internal/…), then revoked by alice at 2026-11-23 09:14 UTC ("not this package")
```

**It learns from you, and you decide what it learns.** Each time a person goes against it (rejects a call it would
have approved, takes back one it approved, or approves one it wouldn't), the signer drafts a lesson in plain words,
with the records it comes from:

```
$ tracekit reviewer lessons
proposed (`tracekit reviewer accept ID` puts one in force, `tracekit reviewer drop ID` drops it):
  L-3f…  don't approve pip --index-url https://pypi.internal/… (TK-A025) without a person: alice rejected one on 11-23 that the AI would have approved (that package is new to us)
      once accepted it binds: the signer holds calls like it for a person and asks no model
      from the records 76d0…, 9a1c…
```

Only a lesson a person accepts counts, as a signed record; `drop` drops one for good. A lesson that says people said
no to a kind of call ("don't approve … without a person", or "rejected 4 of 4") binds: from the accept on, the signer
holds every call with its key (the same key precedents match by) for a person, asks no model, and says why in the
approval ("an accepted lesson L-3f… says a person decides calls like this"); a call that was waiting for the AI goes
to people, and an AI approval of one not yet used is withdrawn. A lesson that says people approved a kind of call is
advice: the AI reviewer reads it, and it never widens a bound (a yes still needs a person's yes to a call like it).
`lessons`, `status` and `accept` say which a lesson is. When a person later decides a call like an accepted lesson the
other way, `lessons` flags it for review; `retire` ends it. Accepting or retiring a lesson is your own decision, so it
doesn't trip the circuit breaker: the rules keep answering as they did. `tracekit reviewer status` shows how often
people agreed with it per rule, over its recent answers too, so you can see whether it is getting better.

The rest of this section is the precise version: the bounds, the run labels, precedents, two keys, the circuit
breaker, the view the reviewer answers, the records and what the verifiers check. The AI reviewer is an agent approver
as above (format 1.8, RPC 28) with these bounds added.

**Rules: an allowlist you opt into.** Your policy lists the rules it may answer:

```yaml
extends: dev.yaml
approval_agent:
  mode: shadow                     # or enforce
  rules: [TK-SHELL-PARSE, TK-A062, TK-A025]
  run: {clean: [untrusted_content, secrets_access]}
  veto_s: 60                       # optional: people may take back an AI approval (`tracekit approvals revoke`) for this long before it runs
```

Only these three may be listed: a line the policy can't read, an unmapped tool given a command line, and a package
from a chosen index. Lint errors name what is never eligible: a deny rule, a `from: untrusted` rule, a credential or
secret read (`TK-A020`, `TK-A021`, `TK-A035` to `TK-A038`, `TK-A052`, `TK-A053`), a payment rule, Tracekit's own
guardrails, a push or merge to main or master (`TK-A033`, `TK-A056`), a passkey rule, a rule with an `approval.agent`
of its own, and `TK-SHELL-PARSE` where `on_parse_error` denies. A call also held by any other rule (flags aside) is a
person's, and so is one that sets a label of the run bound itself when it runs, by any rule it matched, flags too (a
line the policy can't read that also reads `.env`: `TK-F034`'s flag). On a laptop the signer also refuses to start with an `approval.agent` on a payment rule without
`executor: t2` (a warning on a server).

**The run.** While the run carries a label `run.clean` names, people answer every hold. These are the run labels of
[run conditions](policy-v2.md#run-conditions): a call that ran sets them (`secrets_access`: a read of a secret file,
a stored secret printed; `untrusted_content`: a web page, a mail, a download), and so do events the signer lost,
since what they did is unknown; the policy records them whenever its run bound names them. They belong to the run's
requesters (its client, each identity it was delegated to, a gateway's caller) and to the identity that asks for the
approval (counted even when it never wrote the run) across all of their runs, in any tenant and under any principal, while the run that took one is open and for `label_inherit_s` after it ends (an hour
by default, at most a day), so a run the agent registers afresh or is handed is no way around them. A run that continues an earlier run of its session, whose calls it can't see, carries every label of the
bound. For this bound alone, a call the policy denied or held that a rule labelled `secrets_access` matched sets
`secrets_access` too, carried the same way (the session tried to read a secret; whether it may is a person's to say),
and the AI's reasons say "the session tried to read a secret"; no run condition counts it, as nothing ran. No
`clear-label` ends this one: it lasts while the run that tried is open and for `label_inherit_s` after. The bound is as
wide as the rules that set a label: a script that opens a secret file itself labels nothing
([limits](limits.md#approvals)).

**Precedent.** The AI approves only a call like one a person approved: the same rules, the same tool, the same target,
the same project and the same requesting identity. The target: for `TK-A025`, each package source and how it was
selected (`pip --index-url`, `pip --extra-index-url`, `pip --find-links`, a config key or a variable are each their
own), the default index too when the line names it (pypi.org as an extra index adds where a package may come from),
any package, and a source that isn't an http(s) URL (a path the agent can write) is people's; for `TK-A062` and
`TK-SHELL-PARSE`, the same call, exactly: every argument as sent, so SQL with other literals or identifiers, another
database, host or working folder, a run in the background, a sandbox escalation or another program of the same name is
another call. The one argument left out is the Bash tool's `description`: a caption Claude Code's model rewords on
almost every retry and nothing runs, so a call that differs from a precedent in its description alone is the same call
(another tool's `description` still counts). The person's answer counts when the run was clean both when the
call was asked and when they answered (`run_clean` in their record), in the last 30 days; under a policy without
`approval_agent` (a restart under another) it is no precedent, and an AI approval not yet used doesn't run. With no such answer, people answer
it. A person's rejection of a call like it lets the AI reject, never approve; when people answered both ways, people
answer it. Only people's own answers count: never an agent's, a self-approval or a break-glass answer. A precedent
stops counting when a person revokes it (`tracekit reviewer revoke apr-… --reason reverted`), when an incident opens in
its run, or when a `why` finding is written about its run. Before an AI-approved call runs, the signer reads its
precedents again: a person's rejection of a call like it since, or no precedent left, withdraws the approval. The
project is the folder the agent's client names (the hook sends the nearest folder above the session's that holds a
`.git`): the agent's own word, so it only narrows a match, and the record says so (`asserted: [project]`).

**Two keys.** A yes needs two answers that approve, from two models or one asked twice; a no needs one. The signer
escalates a yes that doesn't carry two.

**Circuit breaker.** A rule drops to shadow in its tenant when a person revokes an AI approval of it, when a precedent of
it goes bad, when the AI agreed with people on fewer than 9 in 10 of the last calls both answered (at least 10, in
shadow mode), or when an answer comes from another model, version or prompt than the rule's last one (each answer's
`asserted` is pinned), or from a model whose identity changed under the same name (each
answer carries the model's identity as its server gives it: for an Ollama model the digest of what `/api/show` says it
is, its weights, template, system prompt and parameters; otherwise the answer's `model` and `system_fingerprint`): a
change runs in shadow before it decides. Its AI answers are then suggestions, and an AI approval of it not yet run never runs. A person turns it
back on: `tracekit reviewer enable TK-A025`, which also measures its agreement afresh. A person's change to the
playbook is no such change: it is their own signed decision, a lesson that binds is kept by the signer itself, and one
that is advice can't widen a bound.

**Playbook.** `tracekit reviewer status` lists the rules dropped to shadow, the playbook in force, and entries proposed
from people's answers of the last week: a kind of call with 3 or more answers, all one way ("TK-A025 by Bash, TK-A025
pip --index-url https://pypi.internal/…, in api (1a2b3c4d): approved 4 of 4 (latest reason: our mirror)"). Text an
agent wrote is shown with control and hidden characters escaped, there and in the reviewer's view. Lessons (`L-…`)
are proposed with them: each from one disagreement of a person with the AI (a person's answer against its shadow
suggestion, or a revoke of its approval), with the two records' ids as evidence. `tracekit reviewer accept ID`, `drop
ID` and `retire ID` change it, each a signed `playbook.entry` record (a dropped proposal isn't proposed again). An
entry in force whose people said no (`decision: reject`) binds: the signer holds a call with its precedent key for a
person (its request's `agent.reason` names the entry), escalates such calls still waiting when it is accepted and
withdraws AI approvals of them not yet used, and refuses such a consume after. The reviewer reads the rest as advice; it
never widens a bound. A person's later answer to a call with an accepted entry's precedent key, the other way, flags
the entry for review.

**What the reviewer sees.** `approval_review` adds `ai`: the precedent key, the run's labels, each precedent (the
answer, when, the person's reason), the playbook in force (each entry as its id, people's answer and the precedent
key it is about: what the agent wrote is only ever a field's value, never read into the entry's text), and the run's
last 10 calls (tool, decision, rules). The
reviewer reads nothing else: no file of the project, which the agent can write. It answers the view it read:
`approval_decide` names that view's `view_digest`, and the signer takes an AI answer only to the view it served that
reviewer for that approval, and only while what the view showed of it (its precedents, the run's labels, the
playbook) still holds and no run label reaching the run's requesters or the approval's was added or cleared since: a
label that came and went is a new state, and another identity's label changes nothing. Otherwise it answers `conflict`, and the reviewer reads the view again at its next poll.

**The record.** The `approval.request` carries `ai`: the key as shown, its digest (a commitment under the tenant's
own salt), the run's labels, whether the run was clean, and the precedents that counted. The key shows a `TK-A025`
source's scheme, host and port only (a path can hold a token), and the other rules' calls (their arguments as JSON)
redacted as the approver's copy is;
in a run that isn't clean it shows no target at all. A person's answer carries `run_clean`. Each AI answer
(`approval`, `approval.suggested`, `approval.escalated`) carries `relied_on`: the precedents, the playbook's version
and digest, the policy hash, the run's labels, a commitment to the view it answered (`view`), whether it decided
(`enforce`) or was a suggestion and why (`demoted`), and the reviewer's word: each model's answer. The verifiers' `AI
approvals` line checks each AI yes against the precedents its bundle holds and against any person's rejection of a
call like it there. When an AI yes's run carried a label, by its `relied_on` or by the run's own `run.label` records
replayed up to the yes and up to its consume, their `AI run bound` line checks it against the run bound of the policy
snapshot it names (which must be its request's policy), and fails when the bundle doesn't hold that snapshot: export with the policy snapshots
([verdicts](verdicts.md)).

**What people see.** `tracekit approvals show` says what the AI reviewer did, in plain words, and a `details` line
keeps the precise terms:

```
ai          approved by the AI reviewer: it matched the call alice approved on 11-22 (pip --index-url https://pypi.internal/…); take it back before its call runs: `tracekit approvals revoke apr-7c1e…`
details     model output "same internal index"; answers "claude-opus-5-5" approve, "gpt-5" approve; by "uid:990299"; view_digest sha256:5838c1aa…; matched apr-59d3…
```

The model's reason is printed JSON-escaped. The view is the `view_digest` of the view it answered; after a restart
with no snapshot, the signer no longer holds that view, and shows its record's commitment to it instead. While a call
waits, it says whether the AI may answer it and, when it won't, why:

```
ai          the AI reviewer won't answer this: the session read a secret, and TK-Q001 also matched this call (this sends data off the machine after the session read a secret): a person decides
```

`tracekit approvals list` adds the same, shorter. `--json` prints every field.

A rule that joins a call on the signer (a run condition, such as TK-Q001 after a secret read) makes it a person's,
and its `agent.reason` says which. `approval_get` and `approval_list` carry the same as `ai`: `mode` (enforce, shadow,
or null when only people answer it), `reason`, and `answer` (decision, mode, by, reason, view, `matched`: the
person's approval a yes matched, who gave it, when and what it was of, `answers`: each model's answer, and `revoked`:
who took a yes back, when and why), to people who answer
approvals only (`approvals.approvers`, `break_glass`, a bridge acting for them). The requesting agent and agent
approvers see none of it: the agent's own summary has no `agent` flag (it would say a person approved a call like it)
and an escalation without its reason, and its run's records, read with its run token (`read`), come without an
approval request's `agent` and `ai` and without an AI answer's reason and `relied_on`. The records themselves, and a
bundle export, keep them.

**On a laptop, in system mode.** The reviewer runs as a user of its own: not the agent's, which must not answer its
own holds or read your provider key, and not the signer's, which holds the signer's keys. The signer refuses to start
when a `uid:` in `approvals.agents` is its own user, root or in an admin group (as `D-AGENT-PRIV` reads them), or can
open its data dir, its `keys` folder or a key by their owner and mode, or when any of them carries an ACL (Linux and
macOS) or is a symbolic link; `tracekit doctor` fails `D-REVIEWER-USER` then, and run as root it also tries each as
the reviewer's own uid.
Make the user once, as root.

macOS (an id that `dscl . -list /Users UniqueID` and `dscl . -list /Groups PrimaryGroupID` don't list, in 200-399, as
`tracekit init` picks the signer's):

```
sudo dscl . -create /Groups/_tkreviewer
sudo dscl . -create /Groups/_tkreviewer PrimaryGroupID 398
sudo dscl . -create /Users/_tkreviewer
sudo dscl . -create /Users/_tkreviewer UniqueID 398
sudo dscl . -create /Users/_tkreviewer PrimaryGroupID 398
sudo dscl . -create /Users/_tkreviewer UserShell /usr/bin/false
sudo dscl . -create /Users/_tkreviewer NFSHomeDirectory "/Library/Application Support/tracekit-reviewer"
sudo dscl . -create /Users/_tkreviewer IsHidden 1
sudo mkdir -m 700 "/Library/Application Support/tracekit-reviewer"
sudo chown _tkreviewer:_tkreviewer "/Library/Application Support/tracekit-reviewer"
```

Linux:

```
sudo useradd --system --create-home --home-dir /var/lib/tracekit-reviewer --shell /usr/sbin/nologin --user-group tracekit-reviewer
sudo chmod 700 /var/lib/tracekit-reviewer
```

Add these lines to the `signer.yaml` that `tracekit init --v2` wrote (the reviewer's uid from `id -u _tkreviewer` or
`id -u tracekit-reviewer`), restart the signer, and run `tracekit doctor`:

```yaml
tenants:
  "uid:<reviewer>": "<the agent's tenant>"     # the reviewer sees the agent's approvals
approvals:
  persons: {"uid:<approver>": "<your name>"}    # with agents, every approver is a person
  agents: ["uid:<reviewer>"]
authorize:
  "uid:<reviewer>": [approval_list, approval_review, approval_decide, status]
```

Then put these files in the reviewer's home, owned by it. The reviewer refuses `reviewer.yaml`, its folder,
`state_file`, its folder and `key_file` when another user than its own (or root) owns one or group or others can write
it: the agent's user could point it at a server of its own.

```yaml
# reviewer.yaml
signer: /run/tracekit-signer/signer.sock   # the system signer's socket (macOS: /Library/Application Support/tracekit-signer/signer.sock)
url: https://api.anthropic.com/v1/messages # or https://api.openai.com/v1/chat/completions, or a local server
key_file: anthropic.key                    # your own key, chmod 600, owned by the reviewer's user
model: [claude-opus-5-5, gpt-5]            # two keys from two model families; one name is asked twice
```

```
sudo -u _tkreviewer /opt/tracekit/bin/python -m tracekit reviewer serve --config "/Library/Application Support/tracekit-reviewer/reviewer.yaml"
```

(On Linux: `sudo -u tracekit-reviewer /opt/tracekit/bin/python -m tracekit reviewer serve --config
/var/lib/tracekit-reviewer/reviewer.yaml`.) The view goes to that endpoint only. In dev mode the signer is the agent's
own user, which can read its keys: the AI approver needs system mode.

**A local model.** `url: http://127.0.0.1:11434/v1/chat/completions` (an OpenAI-compatible server on this machine's
loopback, named by its address; the only kind of endpoint that may take no key file). The model server and its model
files belong to the reviewer's user: the agent runs as your account, and a server of your account, or files it can
write, let it answer as the model. Run the server as the reviewer, with its models in the reviewer's home (Ollama:
`sudo -u _tkreviewer env HOME="/Library/Application Support/tracekit-reviewer" ollama serve`, or on Linux the same as
`tracekit-reviewer`), and stop the copy that runs as you. At start and before each call the reviewer checks that the
port's listener is its own user's or root's, and refuses the endpoint otherwise (Linux reads `/proc/net/tcp`; macOS
asks `lsof`, which shows a user only its own processes, so there the server must run as the reviewer); where it can't
tell (neither Linux nor macOS), use an endpoint off this machine with a key. Ollama takes model changes from any local
user over its port: each answer carries the model's identity (above), so a model recreated under the same name, with
another system prompt, answers in shadow until you run `tracekit reviewer enable`, and a model changed during a call
escalates. Check it all, as the reviewer's user: `sudo -u _tkreviewer /opt/tracekit/bin/python -m tracekit doctor
--reviewer "/Library/Application Support/tracekit-reviewer/reviewer.yaml"` (`D-REVIEWER-CONFIG`, `D-REVIEWER-MODEL`).

**Before you enforce.** Run a week with `mode: shadow`, then `tracekit reviewer friction --store
/var/lib/tracekit-signer` (no model call): the holds, how many a precedent let the AI answer, how many a person
approved, how many the AI cleared and its share of those, its agreement with people, its false approves, the
revocations, and the median seconds to an answer. Switch to `enforce` once false approves are none and agreement holds.

## Expiry and abandon

An approval expires, with a signed `approval.expired` (on an approval agents may answer, with its `reason`):

- `approvals.ttl_s` (default one hour) after it was requested; a consume or answer after `expires_at` is refused even
  before the sweep records it (`ttl`);
- when its run goes final, since nothing could consume it afterwards (`run_final`);
- an agent's approval, `agent_consume_s` after it may be consumed (`consume_window`).

The adapter can give up on one at once with `approval_abandon` (for example, when the user cancelled the run): the
signer signs `approval.abandoned` and the approval can never be consumed. The coding-agent hooks don't: a call they
blocked keeps its approval `requested`, for the agent's [retry](#approve-then-retry). While an approval is pending, the run's idle
timeout is paused. The signer's copy of the arguments is deleted once the approval is consumed, rejected, expired or
abandoned.

## How much oversight is real

An approval nobody reads is no oversight. `tracekit report` shows, under Holds, what the signed approval records say
about the window it covers:

- holds a day (under a day of records, the count over the window, not a rate scaled up from it);
- the share of held calls a person approved, rejected, or left with no answer (expired, abandoned or still waiting).
  An answer from an [agent approver](#agent-approvers) is model output, and one the run's own user gave to its own
  call (the only kind a dev signer takes: the agent runs as that user), approved or rejected, is no check by another
  person. Both are counted apart and never as a person's;
- the median and 90th-percentile time from hold to a person's first answer;
- approvals answered in under 2 seconds, which were likely not read.

With 20 or more approvals by a person and no rejection, it adds one line: approvals may not be read. Run
`tracekit audit` to find the calls that keep being held, and decide whether they should be allowed, denied or narrowed
by a rule.

`tracekit audit` replays transcripts, which hold no signed approvals, so it can't say who answered. It shows only the
held calls a day (or the count over the window when it is under a day), as a replay against today's policy, and points
to `tracekit report` for the answers. `--json` carries the same numbers (`holds.oversight` in the report, `holds_a_day` in the audit).

## Where this is tested

`tests/test_signer_approvals.py` (replay, edited arguments, another run's approval, resume without a human, retries,
abandon, expiry, restart, encryption at rest, self-approval, tenant visibility; approve, then retry: once, the same
arguments only, never a rejected, abandoned, expired or another run's approval, only a person's in system mode),
`tests/test_signer_completeness.py` (a retry's gaps, after a replay too), `tests/test_hook_v2.py` and
`tests/test_contract_claude_code.py` (the Claude Code hook: blocked at once, then the retry; the agent's own approve
denied; the waiting setting), `tests/test_e13_approvals.py`
(a signer with an approver config, answered from the CLI and from the viewer's approval pages: arguments changed after
approval, a replayed assertion, expiry, self-approval by person id, another tenant, a passkey rule without a passkey,
break-glass without a reason), `tests/test_webauthn.py` (the assertion checks, with a software authenticator),
`tests/test_slack_approvals.py` (the Slack bridge against a real signer: signatures, replays, approve and reject, groups,
self-approval, message updates), `eval/e8_insider_v2.py` case E8v2.5 (the agent approving its own call in system mode),
`tests/test_agent_approvers.py` (bounds, lint, config, eligibility, budgets, anti-shopping, escalation across a
restart, revocation, the kill switch, shadow mode, the reviewer's view), `tests/test_reviewer.py` (the reference
reviewer with fake models that always approve, answer garbage, refuse or time out; the gateway run; eval; what the
Slack bridge posts; the desk's revoke; the timeline labels and shadow agreement), `tests/test_bundle_v2.py` and
`tests/test_ts_verifier.py` (the verifiers' agent-approval checks, with and without the policy snapshot),
`tests/test_ts_verifier.py` (a retry's bundle in both verifiers), `tests/test_approver.py` (the AI approver: the
allowlist and its lint, targets, the run bound, precedents, two keys, the circuit breaker, the playbook, replay, both
verifiers' `AI approvals` line, the view an answer names, the reviewer's own user, your own key and the friction
harness) and
`eval/e18_agent_approvers.py` (a reviewer that approves anything, against every guarantee above, on a server and on a
laptop in system mode, and the harmful-approvals gate over E17's and E21's harmful calls).
