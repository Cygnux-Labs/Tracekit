"""Spending limits and a receipt for an OpenAI Agents SDK agent, offline: a mock model pays through a `send_payment`
tool. The dev signer holds the first payment; the person approves it with a payment grant (two payees, at most 50 USD
each, 120 USD in all, for an hour); the next two payments run within the grant; one past the total is held with the
reason, and the person rejects it. Then the run is exported and verified, and its signed payment decisions are
printed: the bundle is the receipt. docs/quickstarts/agent-spending.md walks through it.

    python examples/v2/openai_agents/spending.py [--scripted]

`--scripted` plays the person: it runs their `tracekit approvals` commands as a second process. Without it, the
example prints those commands and waits for you to run them from another terminal.
"""
import asyncio
import json
import os
import shlex
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import SCRIPTED, export_and_verify, person, show, wait   # noqa: E402

from agents import Agent, Model, ModelResponse, Runner, function_tool, set_tracing_disabled   # noqa: E402
from agents.usage import Usage   # noqa: E402
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText   # noqa: E402

from tracekit.integrations.openai_agents import TracekitAgents   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402

PRINTS, HOSTING = "acct-print-shop", "acct-hosting"
GRANT = ["--grant", "--payee", PRINTS, "--payee", HOSTING, "--max", "50 USD", "--total", "120 USD", "--for", "1h",
         "--note", "the print and hosting bills"]


def pay(n, payee, cents):
    return [ResponseFunctionToolCall(id=f"fc_{n}", call_id=f"call-{n}", type="function_call", name="send_payment",
                                     arguments=json.dumps({"payee": payee, "amount": cents, "currency": "USD"}),
                                     status="completed")]


REPLIES = [   # the mock model's replies, in order: four payments, one at a time, then its answer
    pay(1, PRINTS, 3000), pay(2, HOSTING, 4500), pay(3, PRINTS, 2500), pay(4, HOSTING, 4000),
    [ResponseOutputMessage(id="msg_1", type="message", role="assistant", status="completed", content=[
        ResponseOutputText(type="output_text", annotations=[],
                           text="Paid 100 USD of the bills; the last 40 USD needs your approval.")])],
]


class MockModel(Model):
    async def get_response(self, *args, **kw):
        return ModelResponse(output=REPLIES.pop(0), usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kw):
        raise NotImplementedError


@function_tool
def send_payment(payee: str, amount: int, currency: str) -> str:
    """Pay `amount` (in cents) of `currency` to `payee`."""
    return f"(pretend) paid {amount / 100:.2f} {currency} to {payee}"


def decide(run, approval_id, answer):
    """The person's answer to a held payment: with --scripted, their commands run here as they would type them;
    else they are printed for you to run in another terminal, and the example waits."""
    if SCRIPTED:
        person("approvals", "show", approval_id)
        person("approvals", *answer)
    else:
        print(f"In another terminal:\n  tracekit approvals show {approval_id}\n  tracekit approvals "
              f"{shlex.join(answer)}", flush=True)
    wait(run, approval_id)


async def main(run):
    tk = TracekitAgents(run.client, run.registered)
    agent = Agent(name="bills", model=MockModel(), tools=[tk.tool(send_payment)])
    result = await Runner.run(agent, "pay this month's print and hosting bills", context={}, hooks=tk)
    first = True
    while result.interruptions:   # a held payment: the run is paused until the person decides in the signer
        approvals = result.context_wrapper.context["tracekit"]["approvals"]   # call id -> approval id
        for item in result.interruptions:
            aid = approvals[item.raw_item.call_id]
            print(f"\n{item.raw_item.call_id} send_payment {item.raw_item.arguments}: held, {aid}")
            # the first: approved with a grant for the payments like it; one outside the grant: rejected
            await asyncio.to_thread(decide, run, aid, ["approve", aid, *GRANT] if first else ["reject", aid])
            first = False
        state = result.to_state()
        await tk.apply_decisions(state)
        result = await Runner.run(agent, state, hooks=tk)
    print()
    for item in result.new_items:
        if item.type == "tool_call_output_item":
            print(f"{item.raw_item['call_id']}: {item.output}")
    print(result.final_output)


set_tracing_disabled(True)   # offline: no traces sent to OpenAI
with Client().run(agent="spending-example") as run:
    asyncio.run(main(run))
    print()
    person("grant", "list", "--run", run.run_id)
code = export_and_verify(run.run_id)
print("\nThe receipt's signed decisions:")
show(f"{run.run_id}.tkb", "policy.decision")
sys.exit(code)
