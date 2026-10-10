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
```

- With an `approvals` section, only an approver whose identity maps to the run's tenant (`tenants`) may answer. The
  requester and the run's owner may not, unless
  `self_approval: allow`.
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
(a signer with an approver config, answered from the CLI), and `eval/e8_insider_v2.py` case E8v2.5 (the agent approving its own call in system mode).
