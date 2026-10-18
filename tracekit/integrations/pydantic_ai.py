"""Tracekit for Pydantic AI (docs/integrations/pydantic-ai.md): a capability whose `wrap_tool_execute` hook asks the
signer to decide every tool call before it runs (an `ask` waits for a person) and records its outcome after.

    from tracekit.integrations.pydantic_ai import Tracekit
    agent = Agent("openai:gpt-5", tools=[...], capabilities=[Tracekit(run)])

The hook runs after Pydantic AI validated the arguments, so the signer decides the model's own arguments (`call.args`,
its raw JSON or dict) and the call runs with the arguments validated from them. A refused call never runs: the model
gets Tracekit's reason as the tool's result (SkipToolExecution) and the run goes on. A tool's exception is recorded as
an error and reaches Pydantic AI unchanged, so its retries and `ModelRetry` work as before; each retry is a new call id
and a new decision.
"""
import asyncio
import warnings

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import SkipToolExecution

from tracekit.sdk.client import named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer


class Tracekit(AbstractCapability):
    """Gates and records every tool call of the agent it is given to. `run` is a RunHandle (`Client().run(...)`, or
    `tracekit.instrument()`'s, which routes to the current run)."""

    def __init__(self, run):
        self.run = run

    @classmethod
    def get_serialization_name(cls):
        return None   # holds a live run: built in code, never from an agent spec

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        call_id, tool, raw = call.tool_call_id, call.tool_name, call.args if call.args is not None else {}
        d, why = await asyncio.to_thread(self._gate, call_id, tool, raw)
        if why is not None:
            raise SkipToolExecution(why)
        try:
            out = await handler(args)
        except Exception as e:
            if d is not None:
                await asyncio.to_thread(self._complete, call_id, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        if d is not None:
            await asyncio.to_thread(self._complete, call_id, "ok", result=result_field(d.get("send_result"), out))
        return out

    def _gate(self, call_id, tool, args):
        """(decision, None) when the call may run now (decision None: an outage the fail mode let through, nothing to
        complete), else (None, the reason the model reads). Never raises: a call Tracekit can't decide doesn't run."""
        run = self.run
        try:
            d = run.decide(call_id, tool, args)
            rules = named_rules(d["rule_ids"]) or d.get("reason") or d["decision"]
            if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
                return (None, None) if d["decision"] == "allow" else (None, f"Tool call refused by Tracekit: {d['reason']}")
            if d["decision"] == "deny":
                return None, f"Tool call blocked by Tracekit policy: {rules}"
            hint = None
            if d["decision"] == "ask":
                hint = run.call("approval_request", tool_call_id=call_id)["approval_id"]
                state = run.call("approval_wait", approval_id=hint, timeout_ms=WAIT_MS)["state"]
                if state != "approved":
                    if state == "requested":   # unanswered: withdrawn, so no one approves a call that is gone
                        run.call("approval_abandon", approval_id=hint, reason="no answer within the hook's wait")
                    return None, f"Tool call held by Tracekit policy ({rules}) and not approved: {state}"
            c = run.approval_consume(call_id, tool, args, approval_id_hint=hint)
            if not c["ok"]:
                return None, f"Tool call blocked by Tracekit policy: {c.get('reason') or rules}"
            return d, None
        except Exception as e:
            return None, f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})"[:4096]

    def _complete(self, call_id, status, **fields):
        try:
            self.run.complete(call_id, status, **fields)
        except Exception as e:   # the tool already ran: its result or exception reaches Pydantic AI unchanged
            warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)
