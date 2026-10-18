"""Tracekit for Google ADK (docs/integrations/google-adk.md): a plugin that asks the signer to decide every tool call
of every agent its Runner runs, sub-agents and agents run as tools included, before the tool runs (an `ask` waits for
a person), and records the outcome after.

    from tracekit.integrations.google_adk import Tracekit
    app = App(name="support", root_agent=agent, plugins=[Tracekit(run)])   # first in the list

The signer decides the call's arguments as the model sent them (`{}` for none), under ADK's call id
(`tool_context.function_call_id`). A refused call never runs: the model gets Tracekit's reason as the tool's error
result (`{"error": ...}`) and the run goes on. A tool's exception is recorded as an error and reaches ADK unchanged. A
call ADK pauses for the user (its tool confirmation, or credentials) is not completed; run again under the same id once
the user answers, it is decided as its next attempt.
"""
import asyncio
import copy
import warnings

from google.adk.plugins.base_plugin import BasePlugin
from pydantic_core import to_jsonable_python

from tracekit.sdk.client import AsyncRunHandle, named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer


class Tracekit(BasePlugin):
    """Gates and records every tool call of the Runner (or App) it is registered on; register it first, so no other
    plugin answers a call's error or result before Tracekit records it. `run` is a RunHandle (`Client().run(...)`);
    an AsyncRunHandle works too."""

    def __init__(self, run):
        if isinstance(run, AsyncRunHandle):   # it wraps the RunHandle that does the work
            run = run._sync
        if not callable(getattr(run, "decide", None)):
            raise TypeError(f"Tracekit(run) needs a run handle, Client().run(...), not {run!r}"
                            + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                               "installed, so use Client().run(...)" if run is None else ""))
        super().__init__(name="tracekit")
        self.run, self._warned = run, False
        # lean: one entry per call the plugin decided, for its life; prune them at run end if agents run for days
        self._attempts = {}   # function_call_id -> the attempt its next execution is
        self._open = {}   # function_call_id -> (decision, attempt, the arguments decided) of a call let run

    async def before_run_callback(self, *, invocation_context):
        first = invocation_context.plugin_manager.plugins[0]
        if first is not self and not self._warned:
            self._warned = True
            warnings.warn(f"tracekit: Tracekit is not the first plugin ({first.name!r} is), so that plugin can answer "
                          "a tool call's error or result before Tracekit records it: list Tracekit first in plugins",
                          stacklevel=2)

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        call_id = tool_context.function_call_id
        attempt = self._attempts.get(call_id, 0)
        self._attempts[call_id] = attempt + 1
        args = copy.deepcopy(tool_args)   # a later plugin, or the agent's before_tool_callback, may change tool_args
        d, why = await self._gate(call_id, attempt, tool.name, args)
        if why is not None:
            return {"error": why}   # ADK skips the tool and the model reads this as its result
        if d is not None:
            self._open[call_id] = d, attempt, args
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        call = self._open.pop(tool_context.function_call_id, None)
        if call is not None:
            await self._complete(tool_context.function_call_id, call, "error",
                                 error=f"{type(error).__name__}: {error}"[:4096])

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        call_id, actions = tool_context.function_call_id, tool_context.actions
        call = self._open.pop(call_id, None)
        if call is None or call_id in actions.requested_tool_confirmations or call_id in actions.requested_auth_configs:
            return None   # not Tracekit's to record (refused, or answered before it), or paused for the user
        if tool_args != call[2]:
            await self._complete(call_id, call, "error", error="the call's arguments changed after the decision")
        elif result == {"error": "This tool call is rejected."} and tool_context.tool_confirmation is not None \
                and not tool_context.tool_confirmation.confirmed:   # ADK's own answer: the tool didn't run
            await self._complete(call_id, call, "error", error="rejected in ADK's tool confirmation")
        else:
            await self._complete(call_id, call, "ok", result=result_field(call[0].get("send_result"),
                                                                          _as_the_model_reads(result)))

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

    async def _complete(self, call_id, call, status, **fields):
        try:
            await asyncio.to_thread(self.run.complete, call_id, status, attempt=call[1], **fields)
        except Exception as e:   # the tool already ran: its result or exception reaches ADK unchanged
            warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)


def _as_the_model_reads(value):
    """A tool's return as the JSON ADK sends the model: a dict as it is, anything else as {"result": value}, a
    BaseModel or dataclass as its fields; so an untrusted tool's values reach the signer's provenance index. A value it
    can't convert goes as it is."""
    try:
        return to_jsonable_python(value if isinstance(value, dict) else {"result": value})
    except Exception:
        return value
