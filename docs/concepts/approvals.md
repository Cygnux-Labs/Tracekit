# Approvals

When a policy rule says `ask`, the call waits for a person. An approval is a signed record bound to the exact call it
approves: the same tool, the same arguments, once, before it expires. This page explains how that binding works, who
may answer, and how agent approvers answer routine requests inside hard bounds. Configuration:
[approvals](../approvals.md).

## How a held call flows

1. `decide` returns `ask`, and the signer signs the decision.
2. The client calls `approval_request`. The signer signs an `approval.request` with a fresh `approval_id`, the rule
   ids, the requester, an expiry and a **binding**:

   ```text
   {approval_id, tenant, run_id, tool_call_id, attempt, tool, args_commitment, args_source, policy_hash, nonce, expires_at}
   ```

   The binding's SHA-256 (`binding_digest`) is what an approver signs off on.
3. The signer keeps its own copy of the arguments, redacted for display and encrypted at rest, so approvers see what
   will actually run. The copy is deleted once the approval is used, rejected, expired or abandoned.
4. An approver answers (`approval_decide`), and the signer signs the answer.
5. Just before running the call, the client calls `approval_consume` with the tool and arguments. The signer
   recomputes the digest and requires an approved, unexpired approval whose binding matches. It signs
   `approval.consumed`, and the approval can't be used again.

| Refusal | Reason |
|---|---|
| `TK-APPROVAL-MISMATCH` | The arguments differ from the approved ones |
| `TK-APPROVAL-REJECTED`, `-EXPIRED`, `-CONSUMED` | Rejected, expired, or already used |
| `TK-APPROVAL-REQUIRED`, `-UNBOUND` | No approval for this call, or one for another call |
| `TK-APPROVAL-VETO` | An agent's approval is still inside its veto window |

A retry (`attempt+1`) needs a new decision and a new approval. Approvals expire after an hour by default, and when the
run ends.

## In-process and executor approvals

On an in-process (T1) path, the binding check at consume time stops the agent changing the arguments after approval.
On a T2 path (`approval: {executor: t2}` on the rule), the consume returns the **signer's own copy** of the arguments,
and the [tool executor](custody.md#the-tool-executor) runs exactly that copy. What runs is byte for byte what was
approved.

## Who may answer

| Setting | Effect |
|---|---|
| `approvers` | The identities that may answer (exact, or prefixes such as `oidc:corp/*`) |
| `self_approval: deny` (default) | The requester, the run's owner and its principal can't approve their own call |
| `persons` | Joins one person's identities across channels, so they can't approve from Slack what they couldn't on the command line |
| `break_glass` | Identities that may approve anything, with a reason; shown as a verify warning |

The dev signer lets anyone in the tenant answer, including the requester. Such answers are recorded as self-approved,
the report says `approvals: self`, and the run's assurance stays `dev`.

## Channels

| Channel | Status | How it's checked |
|---|---|---|
| Command line (`tracekit approvals`) | Stable | The caller's identity on the signer's socket or HTTPS connection |
| Web page (`tracekit view` with OIDC sign-in) | Experimental | OIDC login with PKCE; the viewer answers on the person's behalf and the record names both |
| Passkeys | Experimental | A WebAuthn signature over the approval's binding digest: origin, relying party, user present and verified, increasing counter |
| Slack | Experimental | Slack's request signature, a 5-minute timestamp window and replay protection |

## How integrations wait

| Integration | While held |
|---|---|
| OpenAI Agents SDK | Interrupts the run; resume with the decisions applied |
| LangGraph / LangChain | `interrupt()`, resumed with `Command(resume=...)`; denied at once without a checkpointer |
| Claude Agent SDK and coding-agent hooks | Waits up to 9 minutes, under the hook's 10-minute timeout |
| MCP client, CrewAI | Waits up to 5 minutes |
| Browser Use | Waits up to 150 seconds |
| Vercel AI SDK | The SDK's own tool-approval flow |

An approval nobody answers in time is abandoned, and the call doesn't run.

## Agent approvers (experimental)

A reviewer agent may answer routine requests, inside bounds the policy sets. People still answer everything else.

- **Bounds.** A rule's `approval.agent.allow` names every argument the call may have and the values each may take.
  Types are exact (the string `"100"` is not the integer 100), an argument the bounds don't name fails, and so does a
  call over 16 KiB.
- **The floor.** People answer whenever the bounds fail, an argument's value came only from untrusted content, the
  hold came from a synthetic rule (an unknown tool, an unreadable command), the run is a replay, or a budget is spent.
- **Budgets.** A count and a sum (for example, 5 approvals and 300 in total) per window, rebuilt from signed records
  after a restart.
- **No shopping.** Once a call is rejected or escalated, the same tool and arguments go to a person for the rest of
  the run, and asking again is a signed gap. An agent reviews at most ten calls per run.
- **Veto window.** An agent's approval can't be consumed until its `veto_s` has passed, so a person can revoke it.
- **Shadow mode.** The agent's answers are recorded as suggestions only, with the agreement rate per rule, before you
  let it decide.
- **Kill switch.** Turning agent approvers off revokes every unused agent approval and escalates every pending one.

The reference reviewer (`tracekit reviewer`) makes one model call per approval through the LLM gateway, keeps no
memory between approvals, and escalates on any error, timeout or malformed answer. `tracekit reviewer eval` replays
past human answers to measure it first.

In the agent-approver experiment (E18), a reviewer that approves everything is attacked seven ways: arguments out of
bounds, an untrusted memo, retrying under a new attempt or call id, fifty near-identical calls, budget exhaustion,
answering after an escalation, and the kill switch. All seven are caught.

## Reference

[Approvals](../approvals.md) · [identity](../identity.md) · the signer:
[`tracekit/signer/service.py`](../../tracekit/signer/service.py)

---

Previous: [Policy](policy.md) · [All concepts](README.md) · Next: [Detection and containment](containment.md)
