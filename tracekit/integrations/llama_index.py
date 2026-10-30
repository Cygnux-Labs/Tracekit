"""Tracekit for LlamaIndex agents (docs/integrations/llamaindex.md): every tool call an agent workflow makes
(FunctionAgent, ReActAgent, CodeActAgent, an AgentWorkflow and its handoffs) is decided by the signer before it runs (an
`ask` waits for a person) and recorded after.

    from tracekit.integrations.llama_index import Tracekit
    workflow = Tracekit(run).gate(AgentWorkflow(agents=[triage, billing], root_agent="triage"))

`gate` switches the object to a subclass of its own class that overrides `call_tool`, the step every tool call of
the workflow runs through (LlamaIndex's way to customise a workflow: subclass it and override a step). The signer
decides the call's `tool_id` (a fresh id where the model integration gives none, or the tool's name, as Ollama and
Google's do) and the model's arguments as LlamaIndex parsed them (`tool_kwargs`). A refused call never runs: the model
reads Tracekit's reason as an error tool result and the run goes on. A result is recorded as the text the model reads;
an untrusted tool's structured value is observed too, for provenance. A tool's exception, which LlamaIndex turns into an
error result, is recorded as an error. A tool that waits for an event (`ctx.wait_for_event`) runs again from its start
when the event comes: it is decided again then, as the call's next attempt.
Each model message (the AgentOutput a workflow parses) is recorded first (tracekit.integrations.said): its thinking,
text and tool calls, under the ids they are decided by. A message that can't be recorded only warns.
"""
import asyncio
import copy
import uuid
import warnings
from typing import Union

from llama_index.core.agent.workflow import (AgentInput, AgentOutput, AgentWorkflow, BaseWorkflowAgent, ToolCall,
                                             ToolCallResult)
from llama_index.core.base.llms.types import TextBlock, ThinkingBlock
from llama_index.core.tools import ToolOutput
from llama_index.core.workflow import Context, StopEvent, step
from pydantic_core import to_jsonable_python
from workflows.runtime.types.results import WaitingForEvent

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.integrations import said, version_check
from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field


class Tracekit:
    """Gates and records every tool call of the agents and workflows it gates. `run` is a RunHandle
    (`Client().run(...)`, or `tracekit.instrument()`'s, which routes to the current run); an AsyncRunHandle works
    too."""

    def __init__(self, run):
        version_check.warn_untested("LlamaIndex", "llama-index-core", (0, 14, 25), (0, 15),
                                    "llama-index-core>=0.14.25,<0.15")
        self.run = run_handle(run, instrument=True)
        # lean: one entry per call this object ran, for its life; prune them at run end if agents run for days
        self._attempts = {}   # tool_id -> the attempt its next execution is (a step LlamaIndex runs again)
        self._classes = {}   # a gated object's own class -> its subclass that overrides call_tool
        self.said = said.Said(lambda **f: self.run.call("model_event", **f), lambda: self.run.client.status({}))

    def gate(self, workflow):
        """`workflow`, the agent or AgentWorkflow you run, with every tool call it makes gated; returned for chaining.
        Inside an AgentWorkflow the workflow runs every agent's tools (the handoff tool too): gate the workflow."""
        if not isinstance(workflow, (BaseWorkflowAgent, AgentWorkflow)):
            raise TypeError(f"Tracekit.gate needs a LlamaIndex agent or AgentWorkflow, not {workflow!r}")
        if isinstance(workflow, _Gated):
            raise ValueError(f"{type(workflow).__name__} {getattr(workflow, 'name', '')!r} is gated already")
        takes = sorted(n for n, f in workflow._get_steps().items() if ToolCall in f._step_config.accepted_events)
        if takes != ["call_tool"]:   # a LlamaIndex that runs tools elsewhere would run them ungated
            raise TypeError(f"Tracekit.gate: {type(workflow).__name__} takes tool calls in the steps {takes}, not in "
                            "call_tool alone, so it can't gate them; this llama-index-core is not the one it was "
                            "tested with (0.14)")
        cls = type(workflow)
        if cls not in self._classes:
            sub = type(cls.__name__, (_Gated, cls), {"__module__": cls.__module__, "__tracekit__": self})
            sub._step_functions = cls._step_functions   # free-function steps added to the class (add_step) stay
            self._classes[cls] = sub
        workflow.__class__ = self._classes[cls]
        return workflow

    async def _call(self, call_tool, ctx, ev):
        tool, args = ev.tool_name, ev.tool_kwargs   # a dict, {} for no arguments
        call_id = _id(ev) or str(uuid.uuid4())
        attempt = self._attempts.get(call_id, 0)
        d, why = await gate_call(self.run, call_id, attempt, tool, args, who="the workflow")
        if why is not None:   # as call_tool reports a tool the agent doesn't have: an error result, and the run goes on
            ctx.write_event_to_stream(ToolCall(tool_name=tool, tool_kwargs=args, tool_id=ev.tool_id))
            refused = ToolCallResult(tool_name=tool, tool_kwargs=args, tool_id=ev.tool_id, return_direct=False,
                                     tool_output=ToolOutput(content=why, tool_name=tool, raw_input=args, raw_output=why,
                                                            is_error=True))
            ctx.write_event_to_stream(refused)
            return refused
        decided = copy.deepcopy(args)   # a call_tool of the object's own class runs inside this one: it may change them
        upstream = DECIDED_UPSTREAM.set(True)   # an MCP session instrument() wired doesn't decide this call again
        try:
            result = await call_tool(ctx, ev)
        except WaitingForEvent:   # LlamaIndex runs the step again once the event comes: the call's next attempt
            raise
        except Exception as e:
            await complete(self.run, d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            out = result.tool_output
            if result.tool_kwargs != decided:
                await complete(self.run, d, call_id, attempt, "error",
                               error="the call's arguments changed after the decision")
            elif out.is_error:   # the tool raised (LlamaIndex made its exception the result) or isn't the agent's
                e = out.exception
                await complete(self.run, d, call_id, attempt, "error",
                               error=(f"{type(e).__name__}: {e}" if e else str(out.content))[:4096])
            else:
                send = d and d.get("send_result")
                await complete(self.run, d, call_id, attempt, "ok", result=result_field(send, out.content))
                if send:
                    await self._observe(tool, call_id, out.raw_output)
            return result
        finally:
            DECIDED_UPSTREAM.reset(upstream)
            self._attempts[call_id] = attempt + 1

    async def _observe(self, tool, call_id, value):
        """An untrusted tool's returned structure (a dict, list, model or dataclass) as JSON, observed as untrusted, so
        the provenance index has each of its values: the model reads LlamaIndex's text of it, which `complete` records
        and whose values inside the text the index doesn't read one by one."""
        try:
            value = to_jsonable_python(value)
        except Exception:   # nothing JSON can carry: the text the model read is what there is
            return
        if not isinstance(value, (dict, list)):
            return
        try:
            await asyncio.to_thread(self.run.observe, value, f"llama_index:{tool}:{call_id}"[:256])
        except Exception as e:   # the tool already ran: its result reaches LlamaIndex unchanged
            warnings.warn(f"tracekit: the result of {call_id} was not observed: {type(e).__name__}: {e}", stacklevel=2)


def _id(ev):
    """The id a call is decided under, or None for one of the gate's own: Ollama's and Google's integrations name the
    call by its tool (and some by nothing), so two calls of one tool would share an id."""
    return ev.tool_id if ev.tool_id and ev.tool_id != ev.tool_name else None


def _said(ev):
    """What the model said in an AgentOutput: its message's thinking and text blocks, then its tool calls."""
    for b in ev.response.blocks:
        if isinstance(b, ThinkingBlock):
            yield said.thought(b.content)
        elif isinstance(b, TextBlock):
            yield said.text(b.text)
    for t in ev.tool_calls:
        yield said.call(_id(t), t.tool_name, t.tool_kwargs)


class _Gated:
    """Put ahead of a gated object's own class by Tracekit.gate."""

    @step
    async def parse_agent_output(self, ctx: Context, ev: AgentOutput) -> Union[StopEvent, AgentInput, ToolCall, None]:
        tk = self.__tracekit__
        await asyncio.to_thread(tk.said, _said(ev), getattr(ev.raw, "model", None))
        return await super().parse_agent_output(ctx, ev)

    @step
    async def call_tool(self, ctx: Context, ev: ToolCall) -> ToolCallResult:
        return await self.__tracekit__._call(super().call_tool, ctx, ev)

