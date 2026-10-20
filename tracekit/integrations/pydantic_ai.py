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

Each model response is recorded too (tracekit.integrations.said): its thinking (with the provider's signature) and
text, and each of its calls, under the id it is decided by, as a call of that response only once the capability
decides it: a call Pydantic AI never runs (arguments that failed validation, a data-only output, a tool waiting for
approval) is not recorded, so the signer reads it neither as a decided call the model didn't ask for nor as one that
ran with no decision. An approved call resumed by a capability that never saw its response is recorded from the
call itself just before its decision. A response that can't be recorded only warns.
"""
import asyncio

from pydantic_ai import ToolDenied, ToolReturn
from pydantic_ai.capabilities import AbstractCapability, CapabilityOrdering
from pydantic_ai.exceptions import ApprovalRequired, CallDeferred, ModelRetry, SkipToolExecution
from pydantic_ai.messages import TextPart, ThinkingPart, ToolCallPart
from pydantic_core import to_jsonable_python

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.integrations import said
from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field


class Tracekit(AbstractCapability):
    """Gates and records every tool call of the agent it is given to. `run` is a RunHandle (`Client().run(...)`, or
    `tracekit.instrument()`'s, which routes to the current run); an AsyncRunHandle works too."""

    def __init__(self, run):
        self.run = run_handle(run, instrument=True)
        # lean: one entry per call the capability ran, for its life; prune them at run end if agents run for days
        self._attempts = {}   # tool_call_id -> the attempt its next execution is (a resumed deferral runs it again)
        self._ran = {}   # tool_call_id -> the arguments the tool ran with, from after_tool_execute
        self.said = said.Said(lambda **f: self.run.call("model_event", **f), lambda: self.run.client.status({}))

    @classmethod
    def get_serialization_name(cls):
        return None   # holds a live run: built in code, never from an agent spec

    def get_ordering(self):
        # outermost: any other capability that changes a call's arguments does it inside this one, where
        # after_tool_execute sees the arguments the tool really ran with
        return CapabilityOrdering(position="outermost")

    async def after_model_request(self, ctx, *, request_context, response):
        await asyncio.to_thread(self.said, _said(response), response.model_name, response.provider_name)
        return response

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        return await self._gated(call, lambda: handler(args), lambda why: SkipToolExecution(ToolDenied(why)), args,
                                 approved=ctx.tool_call_approved)

    async def after_tool_execute(self, ctx, *, call, tool_def, args, result):
        self._ran[call.tool_call_id] = args   # after every capability's before_tool_execute: what really ran
        return result

    async def wrap_output_process(self, ctx, *, output_context, output, handler):
        call = output_context.tool_call
        if not output_context.has_function or call is None:   # data only, or a text output function (not gated)
            return await handler(output)
        if ctx.partial_output:   # streaming: an output function runs only on the final output, once it is decided
            return output
        return await self._gated(call, lambda: handler(output), ModelRetry, output=True)

    async def _gated(self, call, run_it, refused, args=None, output=False, approved=False):
        call_id, tool, raw = call.tool_call_id, call.tool_name, call.args or {}   # Pydantic AI reads "" as {}
        attempt = self._attempts.get(call_id, 0)
        if call_id in self.said.later:   # a call its recorded response left out: recorded as its call now
            await asyncio.to_thread(self.said.decided, call_id)
        elif approved and call_id not in self._attempts:   # resumed by a capability that never saw its response
            await asyncio.to_thread(self.said, [said.call(call_id, tool, raw)])
        d, why = await gate_call(self.run, call_id, attempt, tool, raw, json_text=True)
        if why is not None:
            raise refused(why)
        upstream = DECIDED_UPSTREAM.set(True)   # an MCP session instrument() wired doesn't decide this call again
        try:
            out = await run_it()
        except (ApprovalRequired, CallDeferred):   # Pydantic AI's own deferral: not run now; resumed, the next attempt
            raise
        except Exception as e:
            await complete(self.run, d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            if args is not None and self._ran.get(call_id, args) != args:
                await complete(self.run, d, call_id, attempt, "error",
                               error="the call's arguments changed after the decision")
            elif output:   # the model reads "Final result processed.", not what the output function returned
                await complete(self.run, d, call_id, attempt, "ok")
            else:   # a ToolReturn's return_value is the tool result; its content goes to the model as a user message
                value = out.return_value if isinstance(out, ToolReturn) else out
                await complete(self.run, d, call_id, attempt, "ok", result=result_field(d and d.get("send_result"),
                                                                                        _as_the_model_reads(value)))
            return out
        finally:
            DECIDED_UPSTREAM.reset(upstream)
            self._ran.pop(call_id, None)
            self._attempts[call_id] = attempt + 1


def _said(response):
    """What the model said in a ModelResponse, in order, its calls as `later`: the capability decides one only if it
    runs."""
    for p in response.parts:
        if isinstance(p, ThinkingPart):
            yield said.thought(p.content, p.signature)
        elif isinstance(p, TextPart):
            yield said.text(p.content)
        elif isinstance(p, ToolCallPart):
            yield said.later(said.call(p.tool_call_id, p.tool_name, p.args or {}))


def _as_the_model_reads(value):
    """A tool's return as the JSON Pydantic AI sends the model (a BaseModel or dataclass as its fields), so an untrusted
    tool's values reach the signer's provenance index; a value it can't convert goes as it is."""
    try:
        return to_jsonable_python(value)
    except Exception:
        return value
