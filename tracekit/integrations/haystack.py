"""Tracekit for Haystack (docs/integrations/haystack.md): an Agent hook that asks the signer to decide every tool call
before it runs (an `ask` waits for a person) and records each call's outcome after it ran.

    from tracekit.integrations.haystack import Tracekit
    tk = Tracekit(run)
    agent = Agent(chat_generator=..., tools=[...], hooks={"before_tool": [tk], "after_tool": [tk]})

At `before_tool` the signer decides each ToolCall the model asked for, under its id (a call without one is given one)
and with the arguments the model sent. A refused call never runs: as with a call Haystack's ConfirmationHook rejects,
the model reads an error tool result in its place, Tracekit's reason, and the run goes on. At `after_tool` the result
of each call that ran is recorded as the model reads it; an error result (the tool raised) as `error`. A call id the
model uses again, in the same step or a later one, is decided as that call's next attempt and recorded on its own.
At `before_tool` the message itself is recorded first (tracekit.integrations.said): its reasoning, text and tool calls,
under the ids they are decided by. A message that can't be recorded only warns.
"""
import asyncio
import collections
import contextvars
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from haystack.components.agents.state import replace_values
from haystack.dataclasses import ChatMessage

from tracekit.format.canon import event_hash, loads_strict
from tracekit.integrations import said, version_check
from tracekit.integrations.gate import gate_call, run_handle
from tracekit.sdk.client import result_field


class Tracekit:
    """The `before_tool` and `after_tool` hook that gates and records every tool call of the Agent it is given to;
    list it last at both. `run` is a RunHandle (`Client().run(...)`); an AsyncRunHandle works too."""

    def __init__(self, run):
        version_check.warn_untested("Haystack", "haystack-ai", (3, 4), (3, 5), "haystack-ai>=3.4,<3.5")
        self.handle = run_handle(run, instrument=True)
        self.said = said.Said(lambda **f: self.handle.call("model_event", **f), lambda: self.handle.client.status({}))
        # lean: one entry per call id for the hook's life; prune them at run end if agents run for days
        self._attempts = {}   # tool call id -> the attempt its next decision is
        self._ran = {}   # tool call id -> [(decision, attempt, ToolCall)] of the calls let run, in call order, until
        # their results are recorded (a model may give two calls of a step one id)

    def run(self, state):
        """The hook in a sync Agent.run: run_async on an event loop of its own, in a thread (the caller's thread may
        be running a loop already), in the caller's context."""
        with ThreadPoolExecutor(1) as pool:
            pool.submit(contextvars.copy_context().run, asyncio.run, self.run_async(state)).result()

    async def run_async(self, state):
        messages = state.data.get("messages") or []
        if messages and messages[-1].tool_calls:   # before_tool: the calls the model asked for, still to run
            msg = messages[-1]
            calls = [c if c.id else replace(c, id=f"haystack-{uuid.uuid4().hex}") for c in msg.tool_calls]
            await asyncio.to_thread(self.said, _said(msg, calls), msg.meta.get("model"))
            turns = collections.defaultdict(asyncio.Lock)   # the signer takes one call per id at a time: calls a
            # model gave one id are decided one after the other, in call order

            async def gate(c):
                async with turns[c.id]:
                    return await self._gate(c)
            gated = await asyncio.gather(*map(gate, calls))   # (refusal, (decision, attempt) to record)
            refused = [m for c, (why, _) in zip(calls, gated) if why is not None
                       for m in (_assistant(msg, [c]), ChatMessage.from_tool(why, origin=c, error=True))]
            kept = [c for c, (why, _) in zip(calls, gated) if why is None]
            for c, (_, ran) in zip(calls, gated):
                if ran:
                    self._ran.setdefault(c.id, []).append((*ran, c))
            if refused or kept != msg.tool_calls:   # Haystack runs the calls on the last message
                state.set("messages", messages[:-1] + refused + ([_assistant(msg, kept)] if kept else []),
                          handler_override=replace_values)
        else:   # after_tool: every result after the step's calls, wherever the after_tool hooks before this one put it
            step = max((i for i, m in enumerate(messages) if m.tool_calls), default=-1)
            for m in messages[step + 1:]:
                if m.tool_call_result:
                    await self._record(m.tool_call_result)

    async def _gate(self, call):
        """(the reason the model reads, None) for a call that may not run, else (None, (decision, attempt) to complete
        it under; None for an outage the fail mode let through)."""
        attempt = self._attempts.get(call.id, 0)
        self._attempts[call.id] = attempt + 1
        d, why = await gate_call(self.handle, call.id, attempt, call.tool_name, call.arguments or {})
        return why, ((d, attempt) if why is None and d is not None else None)

    async def _record(self, result):
        """Complete the first open call of the id `result` (a ToolCallResult) is the outcome of, under its own decision
        and attempt (the client's defaults are the id's last decision)."""
        open_calls = self._ran.get(result.origin.id)
        if not open_calls:   # a call this hook refused or recorded already, or one Haystack found no tool for
            return
        d, attempt, call = open_calls.pop(0)
        if not open_calls:
            del self._ran[call.id]
        if result.error:   # the tool raised: Haystack hands the model the error as the result
            status, fields = "error", {"error": str(result.result)[:4096]}
        elif (result.origin.tool_name, result.origin.arguments or {}) != (call.tool_name, call.arguments or {}):
            status, fields = "error", {"error": "the call's tool or arguments changed after the decision"}
        else:
            status, fields = "ok", {"result": result_field(d.get("send_result"), _as_the_model_reads(result))}
        try:
            digest = event_hash({"tool": call.tool_name, "args": call.arguments or {}})
            await asyncio.to_thread(self.handle.complete, call.id, status, attempt=attempt,
                                    decision_id=d["decision_id"], args_digest=digest, **fields)
        except Exception as e:   # the tool already ran: its result reaches the model unchanged
            warnings.warn(f"tracekit: the outcome of {result.origin.id} was not recorded: {type(e).__name__}: {e}",
                          stacklevel=2)


def _said(msg, calls):
    """What the model said in `msg`, its calls under the ids they are decided by. OpenAI Responses' sealed reasoning
    is in `extra` (haystack/components/generators/chat/openai_responses.py, the reasoning item as a dict)."""
    for r in msg.reasonings:
        yield said.thought(r.reasoning_text, r.extra.get("encrypted_content"))
    for t in msg.texts:
        yield said.text(t)
    for c in calls:
        yield said.call(c.id, c.tool_name, c.arguments or {})


def _assistant(msg, calls):
    """The assistant message `msg` with only `calls`, as Haystack's ConfirmationHook splits one."""
    return ChatMessage.from_assistant(text=msg.text, meta=msg.meta, name=msg.name, tool_calls=calls,
                                      reasoning=msg.reasoning)


def _as_the_model_reads(result):
    """A tool's result as JSON: Haystack hands the model a tool's return as text, JSON text for a dict or a list, which
    is parsed back so an untrusted tool's values reach the signer's provenance index; content parts (a tool's
    `raw_result`) as their dicts."""
    try:
        value = result.to_dict()["result"]
    except Exception:
        return result.result
    try:
        parsed = loads_strict(value) if isinstance(value, str) else value
    except ValueError:   # not JSON as the gateway parses it (duplicate keys, NaN): the text
        return value
    return parsed if isinstance(parsed, (dict, list)) else value
