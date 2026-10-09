"""OpenAI Agents SDK (Python): every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.openai_agents import TracekitAgents
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    tk = TracekitAgents(signer, run)
    agent = Agent(name="payer", model="gpt-5", tools=[tk.tool(transfer_funds)])
    result = await Runner.run(agent, "pay acct-42 $15", context={}, hooks=tk)

`deny` gives the model a refusal as the tool output and the run goes on. `ask` interrupts the run; once a person has
decided in the signer, `await tk.apply_decisions(state)` approves or rejects the paused calls and the app resumes with
`Runner.run(agent, state, hooks=tk)`. The RunState JSON is not authenticated, so it carries the approval id only as a
hint in `context["tracekit"]["approvals"]`: every call that is not denied runs only after the signer's
`approval_consume` agrees, and the SDK does not call `needs_approval` again on resume. The run context must be a dict.

Gated: FunctionTools (a tool input guardrail consumes on the model's raw arguments string), ShellTool with a local
executor, LocalShellTool and ApplyPatchTool (gated in the executor or editor). LocalShellTool and ApplyPatchTool cannot
wait for an approval (the SDK has no approval hook for the first and does not tell the editor its call id), so an
`ask` for them is refused. Not gated: hosted tools (web and file search, code interpreter, hosted MCP, hosted shell),
ComputerTool and handoffs run outside these hooks; they are recorded (T3) only inside the signed model exchange that
`hooks=tk` records for each model response.
"""
import asyncio
import copy
import dataclasses
import functools
import inspect
import itertools
import threading
import uuid

from agents import (ApplyPatchTool, FunctionTool, LocalShellTool, RunHooks, ShellTool, ToolGuardrailFunctionOutput,
                    function_tool, tool_input_guardrail)
from agents.editor import ApplyPatchResult
from agents.tool import maybe_invoke_function_tool_failure_error_function, set_function_tool_failure_error_function

from tracekit import parsers
from tracekit.format.canon import event_hash, loads_strict
from tracekit.signer.rpc_schema import RPCError

BLOCKED = "Tool call blocked by policy: "
_EVENTS = ("decide", "complete", "model_event")


def _source(args):
    return "raw" if isinstance(args, str) else "parsed"


class TracekitAgents(RunHooks):
    def __init__(self, signer, run):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`)."""
        self.signer, self.run = signer, {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._lock = "openai-agents-" + uuid.uuid4().hex, itertools.count(), threading.Lock()
        self._decided = {}   # tool_call_id -> its decision, from needs_approval to the gate in this process
        self._passed = {}    # tool_call_id -> (decision, tool, args) of a call the gate let run, until it completes
        # lean: an operation whose call never reaches the editor stays here; prune per run if agents run for days
        self._patches = {}   # id(operation) -> (operation, call_id): the SDK does not tell the editor the call id

    async def _call(self, method, req):
        def call():
            # lean: one signer call at a time per adapter, so client_seq arrives in order; pipeline if it gets slow
            with self._lock:
                if method in _EVENTS:
                    req.update(stream=self.stream, client_seq=next(self._seq))
                return getattr(self.signer, method)(req)
        return await asyncio.to_thread(call)

    async def _rpc(self, method, **req):
        return await self._call(method, {"request_id": uuid.uuid4().hex, **self.run, **req})

    async def _decide(self, call_id, tool, args):
        return await self._rpc("decide", tool_call_id=call_id, tool=tool, args_source=_source(args), args=args)

    async def _ask(self, ctx, call_id, tool, args):
        """needs_approval: decide; on ask open an approval and keep its id in the run context as a hint."""
        d = self._decided[call_id] = await self._decide(call_id, tool, args)
        if d["decision"] != "ask":
            return False   # a deny is refused by the gate, before the call runs
        if not isinstance(ctx.context, dict):
            raise TypeError("TracekitAgents needs a dict run context: Runner.run(agent, input, context={})")
        apr = await self._rpc("approval_request", tool_call_id=call_id)
        ctx.context.setdefault("tracekit", {}).setdefault("approvals", {})[call_id] = apr["approval_id"]
        return True

    async def _gate(self, ctx, call_id, tool, args, can_wait=True):
        """The refusal the model gets instead of the result, or None when the call may run now."""
        d = self._decided.pop(call_id, None) or await self._decide(call_id, tool, args)   # resumed elsewhere
        if d["decision"] == "deny":
            return BLOCKED + (", ".join(d["rule_ids"]) or "deny")
        if d["decision"] == "ask" and not can_wait:
            return BLOCKED + "approval required, and this tool cannot wait for one"
        try:
            hint = ctx.context["tracekit"]["approvals"][call_id]
        except (AttributeError, KeyError, TypeError, IndexError):
            hint = None   # the signer finds the approval itself
        # every call, allowed or approved: the saved run state can't vouch that no approval is needed
        try:
            c = await self._rpc("approval_consume", tool_call_id=call_id, tool=tool, args_source=_source(args),
                                args=args, **({"approval_id_hint": hint} if hint is not None else {}))
        except RPCError as e:   # e.g. a hint that is not an id at all
            c = {"ok": False, "rule_ids": [], "reason": e.message}
        if not c["ok"]:
            return BLOCKED + ", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else "")
        self._passed[call_id] = d, tool, args
        return None

    async def _body(self, call_id, fn, *a):
        """Run a call the gate let through and complete it with its outcome."""
        d, tool, args = self._passed.pop(call_id)
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": loads_strict(args) if isinstance(args, str) else args})}
        try:
            out = fn(*a)
            if inspect.isawaitable(out):
                out = await out
        except Exception as e:
            await self._rpc("complete", **req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        await self._rpc("complete", **req, status="ok", result=event_hash(str(out)))   # a commitment, not the result itself
        return out

    async def _run(self, ctx, call_id, tool, args, fn, *a, can_wait=True):
        why = await self._gate(ctx, call_id, tool, args, can_wait)
        return why if why is not None else await self._body(call_id, fn, *a)

    def tool(self, t):
        """The tool gated by the signer: a function, FunctionTool, ShellTool, LocalShellTool or ApplyPatchTool.
        The signer's policy decides approvals: the tool's own `needs_approval` is replaced."""
        if isinstance(t, ShellTool):
            if t.executor is None:
                raise TypeError("a hosted ShellTool runs outside this process; Tracekit records it from the model "
                                "response only")

            async def needs_approval(ctx, action, call_id):
                return await self._ask(ctx, call_id, t.name, dataclasses.asdict(action))

            async def executor(req):
                return await self._run(req.ctx_wrapper, req.data.call_id, t.name, dataclasses.asdict(req.data.action),
                                       t.executor, req)
            return dataclasses.replace(t, executor=executor, needs_approval=needs_approval)
        if isinstance(t, LocalShellTool):
            async def executor(req):
                return await self._run(req.ctx_wrapper, req.data.call_id, t.name, req.data.action.model_dump(mode="json"),
                                       t.executor, req, can_wait=False)
            return dataclasses.replace(t, executor=executor)
        if isinstance(t, ApplyPatchTool):
            async def needs_approval(ctx, op, call_id):
                self._patches[id(op)] = op, call_id   # the SDK hands the editor this very object next
                return False   # the gate in the editor decides
            return dataclasses.replace(t, editor=_Editor(self, t.name, t.editor), needs_approval=needs_approval)
        if not isinstance(t, FunctionTool):
            if not callable(t):
                raise TypeError(f"{type(t).__name__} runs outside this process; Tracekit records it from the model "
                                "response only")
            t = function_tool(t)
        inner, outer = copy.copy(t), copy.copy(t)
        set_function_tool_failure_error_function(inner, None)   # its exceptions reach `invoke`

        async def needs_approval(ctx, params, call_id):
            return await self._ask(ctx, call_id, outer.name, params)

        @tool_input_guardrail
        async def guard(data):   # last, so the approval is consumed only once the app's own guardrails let it pass
            why = await self._gate(data.context, data.context.tool_call_id, outer.name, data.context.tool_arguments)
            return ToolGuardrailFunctionOutput.allow() if why is None else ToolGuardrailFunctionOutput.reject_content(why)

        async def invoke(ctx, raw):
            try:
                return await self._body(ctx.tool_call_id, inner.on_invoke_tool, ctx, raw)
            except Exception as e:   # the tool's own failure policy, as without Tracekit
                out = await maybe_invoke_function_tool_failure_error_function(function_tool=outer, context=ctx, error=e)
                if out is None:
                    raise
                return out
        outer.on_invoke_tool, outer.needs_approval = invoke, needs_approval
        outer.tool_input_guardrails = [*(t.tool_input_guardrails or []), guard]
        return outer

    async def _patch(self, tool, fn, op):
        op_, call_id = self._patches.pop(id(op), (None, None))
        if op_ is not op:   # approved earlier (the SDK skipped needs_approval), so the call id is unknown
            return ApplyPatchResult(status="failed", output=BLOCKED + "approval required, and this tool cannot wait "
                                                                      "for one")
        args = {"type": op.type, "path": op.path, "diff": op.diff, "move_to": op.move_to}
        why = await self._gate(op.ctx_wrapper, call_id, tool, args, can_wait=False)
        return ApplyPatchResult(status="failed", output=why) if why is not None else await self._body(call_id, fn, op)

    async def apply_decisions(self, state):
        """Approve or reject the paused calls in a RunState as the signer's approvers decided; returns the calls
        still waiting. Resuming with a call approved some other way runs nothing: the signer refuses it."""
        listed = await self._call("approval_list", {"run_id": self.run["run_id"]})
        decided = {}
        for a in listed["approvals"]:
            decided.setdefault(a["tool_call_id"], a["state"])
        waiting = []
        for item in state.get_interruptions():
            raw = item.raw_item
            s = decided.get(raw.get("call_id") if isinstance(raw, dict) else getattr(raw, "call_id", None))
            if s == "approved":
                state.approve(item)
            elif s in ("rejected", "expired"):
                state.reject(item, rejection_message=f"Tool call {s} in Tracekit")
            else:
                waiting.append(item)
        return waiting

    async def on_llm_end(self, context, agent, response):
        """T3: each model response as a commitment, hosted tool calls, computer actions and handoffs included."""
        out = parsers.parse("openai:responses", {"output": response.output, "usage": response.usage})
        model = agent.model if isinstance(agent.model, str) else getattr(agent.model, "model", None)
        fields = {"usage": out["usage"], "tool_uses": out["tool_uses"][:128]}   # lean: the RPC's cap, as autotrace
        await self._rpc("model_event", provider="openai", phase="response", model=str(model or "")[:128],
                        content_digest=event_hash([i.model_dump(mode="json") for i in response.output]),
                        **{k: v for k, v in fields.items() if v})


class _Editor:
    """An ApplyPatchEditor whose operations run only after the signer agrees."""

    def __init__(self, tk, tool, editor):
        self._tk, self._tool, self._editor = tk, tool, editor

    def __getattr__(self, name):   # create_file, update_file, delete_file
        return functools.partial(self._tk._patch, self._tool, getattr(self._editor, name))
