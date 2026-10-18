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
"""
import asyncio
import copy
import uuid
import warnings

from llama_index.core.agent.workflow import AgentWorkflow, BaseWorkflowAgent, ToolCall, ToolCallResult
from llama_index.core.tools import ToolOutput
from llama_index.core.workflow import Context, step
from pydantic_core import to_jsonable_python
from workflows.runtime.types.results import WaitingForEvent

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.sdk.client import AsyncRunHandle, named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer


class Tracekit:
    """Gates and records every tool call of the agents and workflows it gates. `run` is a RunHandle
    (`Client().run(...)`, or `tracekit.instrument()`'s, which routes to the current run); an AsyncRunHandle works
    too."""

    def __init__(self, run):
        if isinstance(run, AsyncRunHandle):   # it wraps the RunHandle that does the work
            run = run._sync
        if not callable(getattr(run, "decide", None)):
            raise TypeError(f"Tracekit(run) needs a run handle, Client().run(...) or tracekit.instrument()'s, not {run!r}"
                            + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                               "installed, so use Client().run(...)" if run is None else ""))
        self.run = run
        # lean: one entry per call this object ran, for its life; prune them at run end if agents run for days
        self._attempts = {}   # tool_id -> the attempt its next execution is (a step LlamaIndex runs again)
        self._classes = {}   # a gated object's own class -> its subclass that overrides call_tool

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
        # Ollama's and Google's integrations name the call by its tool (and some by nothing): two calls of one tool
        # would share an id, so the signer gets one of its own
        call_id = ev.tool_id if ev.tool_id and ev.tool_id != tool else str(uuid.uuid4())
        attempt = self._attempts.get(call_id, 0)
        d, why = await self._gate(call_id, attempt, tool, args)
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
            await self._complete(d, call_id, attempt, "error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        else:
            out = result.tool_output
            if result.tool_kwargs != decided:
                await self._complete(d, call_id, attempt, "error", error="the call's arguments changed after the decision")
            elif out.is_error:   # the tool raised (LlamaIndex made its exception the result) or isn't the agent's
                e = out.exception
                await self._complete(d, call_id, attempt, "error",
                                     error=(f"{type(e).__name__}: {e}" if e else str(out.content))[:4096])
            else:
                send = d and d.get("send_result")
                await self._complete(d, call_id, attempt, "ok", result=result_field(send, out.content))
                if send:
                    await self._observe(tool, call_id, out.raw_output)
            return result
        finally:
            DECIDED_UPSTREAM.reset(upstream)
            self._attempts[call_id] = attempt + 1

    async def _gate(self, call_id, attempt, tool, args):
        """(decision, None) when the call may run now (decision None: an outage the fail mode let through, nothing to
        complete), else (None, the reason the model reads). Raises nothing but CancelledError: a call Tracekit can't
        decide doesn't run, and a workflow cancelled while it waits for a person withdraws the approval."""
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
                except asyncio.CancelledError:   # the workflow was cancelled: so is the approval, before anyone uses it
                    if hint is None:
                        hint = (await request)["approval_id"]
                    await asyncio.to_thread(self._abandon, hint, "the workflow was cancelled while it waited")
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

    async def _complete(self, d, call_id, attempt, status, **fields):
        if d is None:   # ran unrecorded: the signer was unreachable and the run fails open
            return
        try:
            await asyncio.to_thread(self.run.complete, call_id, status, attempt=attempt, **fields)
        except Exception as e:   # the tool already ran: its result reaches LlamaIndex unchanged
            warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)


class _Gated:
    """Put ahead of a gated object's own class by Tracekit.gate."""

    @step
    async def call_tool(self, ctx: Context, ev: ToolCall) -> ToolCallResult:
        return await self.__tracekit__._call(super().call_tool, ctx, ev)

