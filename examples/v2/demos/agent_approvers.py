"""Agent approvers: a support agent issues refunds; the policy lets a reviewer agent clear refunds of up to $50 and
leaves everything else to people. A refund within the bounds is approved by the reviewer and runs; one outside them
the reviewer can't answer even when told its id, and a person rejects it; one a person rejected first stays a
person's when the agent asks again. Offline, scripted: the reviewer approves whatever it may see, as a reviewer whose
judgment was steered would. Then the run is exported and verified.

    python examples/v2/demos/agent_approvers.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import AGENT, Signer, export_and_verify, person, show, wait   # noqa: E402

from tracekit.signer.rpc_schema import RPCError   # noqa: E402

POLICY = """extends: packs/server.yaml
tools: {issue_refund: payment}
ask:
  - id: TK-M001   # the server pack's rule for moving money, redefined: a reviewer agent may clear small refunds
    class: payment
    field: amount
    pattern: '.'
    reason: sending money
    approval:
      executor: t2
      agent:
        mode: enforce
        allow:
          fields:
            order: {type: string, pattern: 'A-[0-9]{4}'}
            amount: {type: integer, min: 1, max: 5000}
            currency: {type: string, enum: [usd]}
        budget: {count: 10, sum: {field: amount, max: 20000}, window: 86400, scope: tenant}
"""
REVIEWER = ["approval_list", "approval_review", "approval_decide", "status"]


def ask(run, call_id, order, cents, attempt=0):
    args = {"order": order, "amount": cents, "currency": "usd"}
    d = run.decide(call_id, "issue_refund", args, attempt=attempt)
    aid = run.call("approval_request", tool_call_id=call_id, attempt=attempt)["approval_id"]
    print(f"\n{call_id} issue_refund {order} ${cents / 100:.2f}: {d['decision']} ({', '.join(d['rule_ids'])})")
    return args, aid


def review(reviewer):
    """The reviewer agent approves every approval it may see."""
    approvals = reviewer.approval_list({"for": "agent", "state": "requested"})["approvals"]
    if not approvals:
        print("  reviewer: none it may answer")
    for a in approvals:
        r = reviewer.approval_review({"approval_id": a["approval_id"]})
        print(f"  reviewer sees {r['tool']} {r['args']}, bounds passed: {all(c['passed'] for c in r['conditions'])}")
        out = reviewer.approval_decide({"approval_id": a["approval_id"], "decision": "approve",
                                        "asserted": {"model": "mock-reviewer", "version": "1"}})
        print(f"  reviewer: {out['state']}")


def try_review(reviewer, aid):
    """The reviewer, told the approval's id, tries to approve it."""
    try:
        reviewer.approval_decide({"approval_id": aid, "decision": "approve"})
    except RPCError as e:
        print(f"  reviewer, told its id: refused ({e})")


def run_if_approved(run, call_id, args, aid, attempt=0):
    state = wait(run, aid)
    c = run.approval_consume(call_id, "issue_refund", args, approval_id_hint=aid, attempt=attempt)
    if c["ok"]:
        print(f"  {state}: refunded {c['args']['order']} (the signer's approved copy of the arguments)")
        run.complete(call_id, attempt=attempt)
    else:
        print(f"  {state}: not run ({', '.join(c['rule_ids'])})")


with Signer(POLICY, {"agent": AGENT, "reviewer": REVIEWER}, reviewers=["reviewer"]) as signer:
    reviewer = signer.client("reviewer")
    with signer.client("agent").run(agent="refund-agent") as run:
        args, aid = ask(run, "call-1", "A-1001", 1500)   # within the bounds: the reviewer's to answer
        review(reviewer)
        run_if_approved(run, "call-1", args, aid)

        args, aid = ask(run, "call-2", "A-1002", 250000)   # outside them: people answer
        review(reviewer)
        try_review(reviewer, aid)
        person("approvals", "reject", aid, "--reason", "over the refund limit")
        run_if_approved(run, "call-2", args, aid)

        args, aid = ask(run, "call-3", "A-1001", 1500)   # within the bounds, but a person says no first
        person("approvals", "reject", aid, "--reason", "A-1001 was refunded already")
        run_if_approved(run, "call-3", args, aid)
        args, aid = ask(run, "call-3", "A-1001", 1500, attempt=1)   # the agent asks again
        review(reviewer)
        try_review(reviewer, aid)
        print("  call-3 attempt 1 waits for a person; the run ends and its approval expires with it")
    code = export_and_verify(run.run_id, signer.config)
print("\nwho answered, and what the signer recorded about each request:")
show(f"{run.run_id}.tkb", "approval.request", "approval", "capture.gap")
sys.exit(code)
