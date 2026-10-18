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
import copy
import warnings

from google.adk.plugins.base_plugin import BasePlugin
from pydantic_core import to_jsonable_python

from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field


class Tracekit(BasePlugin):
    """Gates and records every tool call of the Runner (or App) it is registered on; register it first, so no other
    plugin answers a call's error or result before Tracekit records it. `run` is a RunHandle (`Client().run(...)`);
    an AsyncRunHandle works too."""

    def __init__(self, run):
        run = run_handle(run)
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
        d, why = await gate_call(self.run, call_id, attempt, tool.name, args)
        if why is not None:
            return {"error": why}   # ADK skips the tool and the model reads this as its result
        if d is not None:
            self._open[call_id] = d, attempt, args
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        call_id = tool_context.function_call_id
        call = self._open.pop(call_id, None)
        if call is not None:
            await complete(self.run, call[0], call_id, call[1], "error",
                           error=f"{type(error).__name__}: {error}"[:4096])

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        call_id, actions = tool_context.function_call_id, tool_context.actions
        call = self._open.pop(call_id, None)
        if call is None or call_id in actions.requested_tool_confirmations or call_id in actions.requested_auth_configs:
            return None   # not Tracekit's to record (refused, or answered before it), or paused for the user
        d, attempt, decided = call
        if tool_args != decided:
            await complete(self.run, d, call_id, attempt, "error",
                           error="the call's arguments changed after the decision")
        elif result == {"error": "This tool call is rejected."} and tool_context.tool_confirmation is not None \
                and not tool_context.tool_confirmation.confirmed:   # ADK's own answer: the tool didn't run
            await complete(self.run, d, call_id, attempt, "error", error="rejected in ADK's tool confirmation")
        else:
            await complete(self.run, d, call_id, attempt, "ok",
                           result=result_field(d.get("send_result"), _as_the_model_reads(result)))


def _as_the_model_reads(value):
    """A tool's return as the JSON ADK sends the model: a dict as it is, anything else as {"result": value}, a
    BaseModel or dataclass as its fields; so an untrusted tool's values reach the signer's provenance index. A value it
    can't convert goes as it is."""
    try:
        return to_jsonable_python(value if isinstance(value, dict) else {"result": value})
    except Exception:
        return value
