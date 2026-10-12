# Agent approvers within bounds

A support agent issues refunds. The policy lets a reviewer agent clear refunds of at most $50 to an `A-` order in USD
(`approval.agent` on the server pack's TK-M001); people answer the rest. The reviewer approves whatever it is shown,
as a steered reviewer would. A $15 refund: it approves, the refund runs. A $2,500 refund: it isn't shown, is refused
even when told the approval's id, and a person rejects it. A repeat of the $15 refund: a person rejects it, and when
the agent asks again the reviewer still can't approve it.

```sh
python examples/v2/demos/agent_approvers.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** Each `approval.request` carries `agent: {eligible, reason}`. The reviewer's `approval` has
`approver_kind: agent`, its unattested `asserted` model and the budget it `spent`; the people's carry `person: alice`.
The re-ask is a signed `capture.gap{reask_after_reject}`, a warning in [verify.txt](verify.txt).

**Why it matters.** A reviewer's judgment is model output an attacker can steer; the signer bounds what it may answer,
and a person's "no" can't be shopped around to it. Recording this demo found that a person's reject did not stick on
a re-ask; the signer now holds it as a veto ([anti-shopping](../../approvals.md#agent-approvers)).

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/agent_approvers.py)
