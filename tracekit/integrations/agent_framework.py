"""Tracekit for Microsoft Agent Framework (docs/integrations/microsoft-agent-framework.md): a function middleware that
asks the signer to decide every function call an agent makes before it runs (an `ask` waits for a person), and
records the outcome after.

    from tracekit.integrations.agent_framework import Tracekit
    tk = Tracekit(run)
    agent = Agent(client=client, tools=[...], middleware=[tk, tk.chat])   # tk.chat: optional, records the model's words

The decision names the model's own call id (`context.metadata["call_id"]`) and the arguments Agent Framework parsed
from the model's JSON and validated against the function: the ones it runs with (no arguments or an empty string are
{}). A refused call never runs: the model gets Tracekit's reason as the call's result and the run goes on. A
function's exception is recorded as an error and reaches Agent Framework unchanged, which hands the model its error
result; a call that runs again under the same id (a model that reuses an id) is decided as its next attempt.

Function middleware sees no model response: `tk.chat`, a chat middleware, records each one (tracekit.integrations.said):
its reasoning (with its protected_data, sealed), text and function calls, under the call ids the function middleware
decides them by; streamed, once the stream ends. A response that can't be recorded only warns.
"""
import asyncio

from agent_framework import ChatMiddleware, Content, FunctionMiddleware, MiddlewareTermination
from pydantic_core import to_jsonable_python

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.format.canon import loads_strict
from tracekit.integrations import said, version_check
from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field


class Tracekit(FunctionMiddleware):
    """Gates and records every function call of the agent, run or chat client it is given to. `run` is a RunHandle
    (`Client().run(...)`); an AsyncRunHandle works too."""

    def __init__(self, run):
        version_check.warn_untested("Agent Framework", "agent-framework-core", (1, 22), (1, 23),
                                    "agent-framework-core>=1.22,<1.23")
        self.run = run_handle(run)
        # lean: one entry per call id the middleware decided, for its life; prune them at run end if agents run for days
        self._attempts = {}   # call id -> the attempt its next decision is (a model may send an id again)
        self.chat = _Said(said.Said(lambda **f: self.run.call("model_event", **f), lambda: self.run.client.status({})))

    async def process(self, context, call_next):
        call_id, tool = context.metadata.get("call_id"), context.function.name
        attempt = self._attempts.get(call_id, 0)
        self._attempts[call_id] = attempt + 1
        # lean: the validated arguments, not the model's JSON text, which function middleware never sees, so they go
        # as `coerced` (reconcile doesn't hold them to the model's tool use); pair a chat middleware that keeps each
        # response's function_call arguments by call id if the record needs the raw text
        args = _as_json(context.arguments)
        d, why = await gate_call(self.run, call_id, attempt, tool, args, args_source="coerced", waiter="middleware")
        if why is not None:
            context.result = why   # not calling call_next: the function never runs and the model reads this
            return
        upstream = DECIDED_UPSTREAM.set(True)   # an MCP session instrument() wired doesn't decide this call again
        try:
            await call_next()
        except MiddlewareTermination as e:   # a later middleware ended the loop: with the call's result (a handoff)?
            out = e.result if context.result is None else context.result
            if out is None:
                await complete(self.run, d, call_id, attempt, "error",
                               error="a later middleware ended the loop instead")
            else:
                await self._finish(d, call_id, attempt, args, context.arguments, out)
            raise
        except Exception as e:
            await complete(self.run, d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            await self._finish(d, call_id, attempt, args, context.arguments, context.result)
        finally:
            DECIDED_UPSTREAM.reset(upstream)

    async def _finish(self, d, call_id, attempt, args, ran_with, out):
        """Complete a call a later middleware returned `out` for: an error when it is Agent Framework's approval request
        (the call waits for its approver, not run) or the call ran with arguments other than the decided ones."""
        if isinstance(out, Content) and out.type == "function_approval_request":
            await complete(self.run, d, call_id, attempt, "error", error="held for Agent Framework's approval, not run")
        elif _as_json(ran_with) != args:   # a later middleware rewrote them
            await complete(self.run, d, call_id, attempt, "error",
                           error="the call's arguments changed after the decision")
        else:
            await complete(self.run, d, call_id, attempt, "ok",
                           result=result_field(d and d.get("send_result"), _as_the_model_reads(out)))


class _Said(ChatMiddleware):
    """`Tracekit(run).chat`: records the assistant messages of each chat response."""

    def __init__(self, record):
        self.record = record

    async def process(self, context, call_next):
        if context.stream:   # the finalized response, once the stream is consumed
            context.stream_result_hooks.append(self._said)
        await call_next()
        if not context.stream and context.result is not None:
            await self._said(context.result)

    async def _said(self, response):
        for m in response.messages:
            if m.role == "assistant":
                await asyncio.to_thread(self.record, _said(m.contents), response.model)


def _said(contents):
    for c in contents:
        if c.type == "text_reasoning":
            yield said.thought(c.text, c.protected_data)
        elif c.type == "text":
            yield said.text(c.text)
        elif c.type == "function_call":
            yield said.call(c.call_id, c.name, c.arguments or {})


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
        return loads_strict(text)
    except (TypeError, ValueError):
        return text
