"""Tracekit for Microsoft Agent Framework (docs/integrations/microsoft-agent-framework.md): a function middleware that
asks the signer to decide every function call an agent makes before it runs (an `ask` waits for a person), and
records the outcome after.

    from tracekit.integrations.agent_framework import Tracekit
    agent = Agent(client=client, tools=[...], middleware=[Tracekit(run)])

The decision names the model's own call id (`context.metadata["call_id"]`) and the arguments Agent Framework parsed
from the model's JSON and validated against the function: the ones it runs with (no arguments or an empty string are
{}). A refused call never runs: the model gets Tracekit's reason as the call's result and the run goes on. A
function's exception is recorded as an error and reaches Agent Framework unchanged, which hands the model its error
result; a call that runs again under the same id (a model that reuses an id) is decided as its next attempt.
"""
import asyncio
import json
import warnings

from agent_framework import Content, FunctionMiddleware, MiddlewareTermination
from pydantic_core import to_jsonable_python

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.sdk.client import AsyncRunHandle, named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer


class Tracekit(FunctionMiddleware):
    """Gates and records every function call of the agent, run or chat client it is given to. `run` is a RunHandle
    (`Client().run(...)`); an AsyncRunHandle works too."""

    def __init__(self, run):
        if isinstance(run, AsyncRunHandle):   # it wraps the RunHandle that does the work
            run = run._sync
        if not callable(getattr(run, "decide", None)):
            raise TypeError(f"Tracekit(run) needs a run handle, Client().run(...), not {run!r}"
                            + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                               "installed, so use Client().run(...)" if run is None else ""))
        self.run = run
        # lean: one entry per call id the middleware decided, for its life; prune them at run end if agents run for days
        self._attempts = {}   # call id -> the attempt its next decision is (a model may send an id again)

    async def process(self, context, call_next):
        call_id, tool = context.metadata.get("call_id"), context.function.name
        attempt = self._attempts.get(call_id, 0)
        self._attempts[call_id] = attempt + 1
        # lean: the validated arguments, not the model's JSON text, which function middleware never sees, so they go
        # as `coerced` (reconcile doesn't hold them to the model's tool use); pair a chat middleware that keeps each
        # response's function_call arguments by call id if the record needs the raw text
        args = _as_json(context.arguments)
        d, why = await self._gate(call_id, attempt, tool, args)
        if why is not None:
            context.result = why   # not calling call_next: the function never runs and the model reads this
            return
        upstream = DECIDED_UPSTREAM.set(True)   # an MCP session instrument() wired doesn't decide this call again
        try:
            await call_next()
        except MiddlewareTermination as e:   # a later middleware ended the loop: with the call's result (a handoff)?
            out = e.result if context.result is None else context.result
            if out is None:
                await self._complete(d, call_id, attempt, "error", error="a later middleware ended the loop instead")
            else:
                await self._finish(d, call_id, attempt, args, context.arguments, out)
            raise
        except Exception as e:
            await self._complete(d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            await self._finish(d, call_id, attempt, args, context.arguments, context.result)
        finally:
            DECIDED_UPSTREAM.reset(upstream)

    async def _finish(self, d, call_id, attempt, args, ran_with, out):
        """Complete a call a later middleware returned `out` for: an error when it is Agent Framework's approval request
        (the call waits for its approver, not run) or the call ran with arguments other than the decided ones."""
        if isinstance(out, Content) and out.type == "function_approval_request":
            await self._complete(d, call_id, attempt, "error", error="held for Agent Framework's approval, not run")
        elif _as_json(ran_with) != args:   # a later middleware rewrote them
            await self._complete(d, call_id, attempt, "error", error="the call's arguments changed after the decision")
        else:
            await self._complete(d, call_id, attempt, "ok",
                                 result=result_field(d and d.get("send_result"), _as_the_model_reads(out)))

    async def _gate(self, call_id, attempt, tool, args):
        """(decision, None) when the call may run now (decision None: an outage the fail mode let through, nothing to
        complete), else (None, the reason the model reads). Raises nothing but CancelledError: a call Tracekit can't
        decide doesn't run, and an agent run cancelled while it waits for a person withdraws the approval."""
        run, at = self.run, {"attempt": attempt}
        # lean: each signer call, and an ask's wait of up to 5 minutes, holds a thread of asyncio's default executor;
        # many asks pending at once can starve it, so use an async signer client once one exists
        try:
            d = await asyncio.to_thread(run.decide, call_id, tool, args, args_source="coerced", **at)
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
                        await asyncio.to_thread(self._abandon, hint, "no answer within the middleware's wait")
                    return None, f"Tool call held by Tracekit policy ({rules}) and not approved: {state}"
            c = await asyncio.to_thread(run.approval_consume, call_id, tool, args, approval_id_hint=hint,
                                        args_source="coerced", **at)
            if not c["ok"]:
                return None, f"Tool call blocked by Tracekit policy: {c.get('reason') or rules}"
            if "args" in c and c["args"] != args:
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
        except Exception as e:   # the function already ran: its result or exception reaches Agent Framework unchanged
            warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)


def _as_json(value):
    """Arguments as JSON (a datetime as its ISO text, a model as its fields); a value it can't convert goes as it is,
    and the signer client refuses it."""
    try:
        return to_jsonable_python(value)
    except Exception:
        return value


def _as_the_model_reads(result):
    """A function's result as the JSON the model reads: each text item as the JSON it holds (Agent Framework sends a
    returned object as its JSON text) or as its text, any other item (an image, a file) as its fields, one item alone
    as itself; so an untrusted tool's values reach the signer's provenance index. Anything else goes as it is."""
    try:
        items = [Content.from_text(result)] if isinstance(result, str) else result
        if not isinstance(items, list) or not all(isinstance(c, Content) for c in items):
            return result
        out = [_parsed(c.text) if c.type == "text" else c.to_dict() for c in items]
        return out[0] if len(out) == 1 else out
    except Exception:
        return result


def _parsed(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text
