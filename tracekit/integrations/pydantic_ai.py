"""Tracekit for Pydantic AI (docs/integrations/pydantic-ai.md): a capability that asks the signer to decide every tool
call, and every output function the model calls through an output tool, before it runs (an `ask` waits for a person),
and records the outcome after.

    from tracekit.integrations.pydantic_ai import Tracekit
    agent = Agent("openai:gpt-5", tools=[...], capabilities=[Tracekit(run)])

The signer decides the model's own arguments (`call.args`, its raw JSON or dict). A refused tool call never runs: the
model gets Tracekit's reason as a denied tool result and the run goes on. A refused output function never runs either:
the model gets the reason as a retry prompt. A tool's exception is recorded as an error and reaches Pydantic AI
unchanged, so its retries and `ModelRetry` work as before; each retry is a new call id and a new decision, and a call
that runs again under the same id (a deferral resumed) is decided as its next attempt.
"""
import asyncio
import warnings

from pydantic_ai import ToolDenied
from pydantic_ai.capabilities import AbstractCapability, CapabilityOrdering
from pydantic_ai.exceptions import ApprovalRequired, CallDeferred, ModelRetry, SkipToolExecution
from pydantic_core import to_jsonable_python

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.format.canon import loads_strict
from tracekit.sdk.client import AsyncRunHandle, named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer


class Tracekit(AbstractCapability):
    """Gates and records every tool call of the agent it is given to. `run` is a RunHandle (`Client().run(...)`, or
    `tracekit.instrument()`'s, which routes to the current run); an AsyncRunHandle works too."""

    def __init__(self, run):
        if isinstance(run, AsyncRunHandle):   # it wraps the RunHandle that does the work
            run = run._sync
        if not callable(getattr(run, "decide", None)):
            raise TypeError(f"Tracekit(run) needs a run handle, Client().run(...) or tracekit.instrument()'s, not {run!r}"
                            + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                               "installed, so use Client().run(...)" if run is None else ""))
        self.run = run
        # lean: one entry per call the capability ran, for its life; prune them at run end if agents run for days
        self._attempts = {}   # tool_call_id -> the attempt its next execution is (a resumed deferral runs it again)
        self._ran = {}   # tool_call_id -> the arguments the tool ran with, from after_tool_execute

    @classmethod
    def get_serialization_name(cls):
        return None   # holds a live run: built in code, never from an agent spec

    def get_ordering(self):
        # outermost: any other capability that changes a call's arguments does it inside this one, where
        # after_tool_execute sees the arguments the tool really ran with
        return CapabilityOrdering(position="outermost")

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        return await self._gated(call, lambda: handler(args), lambda why: SkipToolExecution(ToolDenied(why)), args)

    async def after_tool_execute(self, ctx, *, call, tool_def, args, result):
        self._ran[call.tool_call_id] = args   # after every capability's before_tool_execute: what really ran
        return result

    async def wrap_output_process(self, ctx, *, output_context, output, handler):
        call = output_context.tool_call
        if not output_context.has_function or call is None:   # data only, or a text output function (not gated)
            return await handler(output)
        if ctx.partial_output:   # streaming: an output function runs only on the final output, once it is decided
            return output
        return await self._gated(call, lambda: handler(output), ModelRetry)

    async def _gated(self, call, run_it, refused, args=None):
        call_id, tool, raw = call.tool_call_id, call.tool_name, call.args or {}   # Pydantic AI reads "" as {}
        attempt = self._attempts.get(call_id, 0)
        d, why = await self._gate(call_id, attempt, tool, raw)
        if why is not None:
            raise refused(why)
        upstream = DECIDED_UPSTREAM.set(True)   # an MCP session instrument() wired doesn't decide this call again
        try:
            out = await run_it()
        except (ApprovalRequired, CallDeferred):   # Pydantic AI's own deferral: not run now; resumed, the next attempt
            raise
        except Exception as e:
            await self._complete(d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            if args is not None and self._ran.get(call_id, args) != args:
                await self._complete(d, call_id, attempt, "error", error="the call's arguments changed after the decision")
            else:
                await self._complete(d, call_id, attempt, "ok", result=result_field(d and d.get("send_result"),
                                                                                    _as_the_model_reads(out)))
            return out
        finally:
            DECIDED_UPSTREAM.reset(upstream)
            self._ran.pop(call_id, None)
            self._attempts[call_id] = attempt + 1

    async def _gate(self, call_id, attempt, tool, args):
        """(decision, None) when the call may run now (decision None: an outage the fail mode let through, nothing to
        complete), else (None, the reason the model reads). Raises nothing but CancelledError: a call Tracekit can't
        decide doesn't run, and an agent run cancelled while it waits for a person withdraws the approval."""
        run, at = self.run, {"attempt": attempt}
        # lean: each signer call, and an ask's wait of up to 5 minutes, holds a thread of asyncio's default executor;
        # many asks pending at once can starve it, so use an async signer client once one exists
        try:
            d = await asyncio.to_thread(run.decide, call_id, tool, args, **at)
            rules = named_rules(d["rule_ids"]) or d.get("reason") or d["decision"]
            if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
                return (None, None) if d["decision"] == "allow" else (None, f"Tool call refused by Tracekit: {d['reason']}")
            if d["decision"] == "deny":
                return None, f"Tool call blocked by Tracekit policy: {rules}"
            hint = None
            if d["decision"] == "ask":
                request = asyncio.ensure_future(asyncio.to_thread(run.call, "approval_request", tool_call_id=call_id, **at))
                try:
                    hint = (await asyncio.shield(request))["approval_id"]   # a cancel lets it finish, to withdraw it
                    state = (await asyncio.to_thread(run.call, "approval_wait", approval_id=hint,
                                                     timeout_ms=WAIT_MS))["state"]
                except asyncio.CancelledError:   # the agent run was cancelled: so is the approval, before anyone uses it
                    if hint is None:
                        hint = (await request)["approval_id"]
                    await asyncio.to_thread(self._abandon, hint, "the agent run was cancelled while it waited")
                    raise
                if state != "approved":
                    if state == "requested":   # unanswered: withdrawn, so no one approves a call that is gone
                        await asyncio.to_thread(self._abandon, hint, "no answer within the hook's wait")
                    return None, f"Tool call held by Tracekit policy ({rules}) and not approved: {state}"
            c = await asyncio.to_thread(run.approval_consume, call_id, tool, args, approval_id_hint=hint, **at)
            if not c["ok"]:
                return None, f"Tool call blocked by Tracekit policy: {c.get('reason') or rules}"
            if "args" in c and c["args"] != (loads_strict(args) if isinstance(args, str) else args):
                return None, "Tool call blocked by Tracekit: the arguments the signer approved are not the call's"
            return d, None
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return None, f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})"[:4096]

    def _abandon(self, approval_id, reason):
        try:
            self.run.call("approval_abandon", approval_id=approval_id, reason=reason)
        except Exception as e:   # it then expires with the run
            warnings.warn(f"tracekit: approval {approval_id} not withdrawn: {type(e).__name__}: {e}", stacklevel=2)

    async def _complete(self, d, call_id, attempt, status, **fields):
        if d is None:   # ran unrecorded: the signer was unreachable and the run fails open
            return
        try:
            await asyncio.to_thread(self.run.complete, call_id, status, attempt=attempt, **fields)
        except Exception as e:   # the tool already ran: its result or exception reaches Pydantic AI unchanged
            warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)


def _as_the_model_reads(value):
    """A tool's return as the JSON Pydantic AI sends the model (a BaseModel or dataclass as its fields), so an untrusted
    tool's values reach the signer's provenance index; a value it can't convert goes as it is."""
    try:
        return to_jsonable_python(value)
    except Exception:
        return value
