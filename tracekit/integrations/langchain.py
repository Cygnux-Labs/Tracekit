"""LangChain v1 middleware: every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.langchain import TracekitMiddleware
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"],
                                                        fail_modes=run.get("fail_modes"))])

`deny` replaces the call with an error ToolMessage and the run goes on. `ask` pauses the run with LangGraph
`interrupt()`; resume it with `Command(resume={"approval_id": ...})`. The pause comes first in every pass of its node,
so a tool's own interrupt() gets the person's answer. A ToolNode with several calls of one message plans them together
first and pauses once when any asks (the payload's `approvals` lists them); a call that ended isn't run again, and in
another process the gate reads what each did from the signer (call_state). Every call that is not denied runs only
after the signer's `approval_consume` agrees, once, so an approval is checked by the signer, never by the saved state;
an approval with a T2 executor runs the arguments the consume returns. `ask` needs a checkpointer: without one the call
is denied.

A signer that cannot be reached when a call is decided: the call runs unrecorded if register_run's `fail_modes` say
`open` for the tool's class (as the signer's default policy classes it), else it is refused. Any other failure to
decide or approve (a refusal, a run the signer closed after its idle timeout: register a new run for a long-idle agent)
refuses the call. A failure to record the outcome warns and leaves
the tool's result as it was. Put TracekitMiddleware last in `middleware=`: a middleware after it could hand the tool a
call other than the one decided.
A graph built on `ToolNode` without `create_agent` uses `tracekit_tool_node(tools, signer, run)`, the same gate.
Its `ask` pauses whatever the node's `handle_tool_errors`, and through `.with_fallbacks()`: neither hands the pause to
the error handling or the fallbacks. Any other wrapper that catches the interrupt (GraphInterrupt) swallows the pause:
the call does not run and its approval expires.
`TracekitCheckpointer(saver, signer, run)` commits every checkpoint the saver writes to the signer (L1).
Each model response under `create_agent` is recorded too (tracekit.integrations.said): its reasoning blocks (with the
provider's signature or encrypted content), an open model's `reasoning_content` and text, and each call of the agent's
tools, under the id it is decided by, as a call of that response only once it reaches the gate (or a tool executor's
tool): a call another middleware stops first (a person's reject in HumanInTheLoopMiddleware, ToolCallLimitMiddleware,
the graph's recursion limit) is not recorded, so the signer never reads it as one that ran with no decision. A call a
person edited there is recorded as the model asked for it and decided as edited: reconcile reads it as args_mismatch.
A response that can't be recorded only warns. A `tracekit_tool_node` graph has no model hook: its model calls are
recorded by `tracekit.instrument()` or the LLM gateway.
"""
import asyncio
import contextvars
import copy
import hashlib
import itertools
import threading
import uuid
import warnings
from typing import Union

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool
from langchain_core.runnables.fallbacks import RunnableWithFallbacks
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph._internal._constants import CONFIG_KEY_SCRATCHPAD
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.constants import CONFIG_KEY_CHECKPOINTER
from langgraph.errors import GraphBubbleUp
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import _handle_tool_error, _infer_handled_types
from langgraph.types import interrupt

from tracekit.format.canon import event_hash
from tracekit.integrations import said
from tracekit.integrations.claude_code import _tool_class
from tracekit.integrations.executor_tools import CALL_ID, EXECUTOR
from tracekit.sdk.client import SignerUnavailable, fail_open, refusal, result_field
from tracekit.signer.rpc_schema import RPCError


# the held pass a ToolNode task runs (TracekitMiddleware._pass): `ns`, the task's checkpoint namespace (a tool may run a
# graph of its own), `plans`, {tool_call_id: its plan}; under ainvoke, `node`, `left`, the node's calls not ended yet,
# and `done`, set once none is (pass_arun_one)
_PASS = contextvars.ContextVar("tracekit_tool_node_pass", default=None)


class TracekitMiddleware(AgentMiddleware):
    def __init__(self, signer, run_id, run_token, fail_modes=None):
        """`signer` is any `SignerAPI`; `run_id`/`run_token` (and `fail_modes`) come from its `register_run`."""
        super().__init__()
        self.signer, self.run = signer, {"run_id": run_id, "run_token": run_token}
        self.fail_modes = fail_modes
        # lean: a new stream per middleware, so each process that resumes the run opens one (the signer allows 64 per
        # run); persist the stream and its counter with the run if runs resume that often
        self.stream, self._seq, self._lock = "langchain-" + uuid.uuid4().hex, itertools.count(), threading.Lock()
        # lean: one entry per executed tool call for the middleware's life; prune at run end if agents run for days
        self._attempts = {}   # tool_call_id -> the attempt its next execution is (a retry runs the same call again)
        # (checkpoint_ns of its node task, tool_call_id) -> a call's plan (_new) while its task may run again: each
        # call of a held pass until its node ends, a single call whose tool paused the run until it goes on. What this
        # process did; a resume in another process reads what the signer recorded (_recorded)
        # lean: a task never run again (a thread left paused, a node that raised for good) keeps its entries for the
        # middleware's life; drop them by age if agents leave many threads that way
        self._plans = {}
        self.said = said.Said(lambda **f: self._send("model_event", **f), lambda: signer.status({}))

    def _send(self, method, **kw):
        # lean: one event call at a time per middleware (ToolNode runs sync tools in threads), so client_seq arrives in
        # order; pipeline if it gets slow
        with self._lock:
            return getattr(self.signer, method)({
                "request_id": uuid.uuid4().hex, **self.run, "stream": self.stream, "client_seq": next(self._seq), **kw})

    def _event(self, method, call, attempt, **kw):
        return self._send(method, tool_call_id=call["id"], attempt=attempt, **kw)

    def wrap_model_call(self, request, handler):
        out = handler(request)
        self.said(*_said(request, out))
        return out

    async def awrap_model_call(self, request, handler):
        out = await handler(request)
        await asyncio.to_thread(self.said, *_said(request, out))
        return out

    def _new(self, call, config, attempt):
        """A call's plan, decided now: `decide`, and `approval_request` when it asks. A plan's `state`: `decide` (the
        signer's approval_consume comes before it runs), `run` (consumed, or unrecorded: the signer unreachable and the
        run failing open), `paused` (its tool paused the run after its consume: it goes on, consumed once), `open`
        (consumed and not ended, as the signer recorded it: paused, or cut off), `done` (`out` is what the model reads),
        `raised` (its tool raised: a retry runs it as a new attempt)."""
        digest = event_hash({"tool": call["name"], "args": call["args"]})
        p = {"attempt": attempt, "d": None, "digest": digest, "entry": None, "state": "decide", "out": None}
        self.said.decided(call["id"])   # the call its recorded response left for now
        try:   # LangChain hands over JSON-decoded args, never the model's raw string
            d = self._event("decide", call, attempt, tool=call["name"], args_source="parsed", args=call["args"])
        except SignerUnavailable as e:   # the run's fail mode for the tool's class
            if fail_open(self.fail_modes, _tool_class(call["name"])):
                p["state"] = "run"
                return p
            return _done(p, self._refusal(call, f"signer unavailable: {e}"))
        except RPCError as e:
            return _done(p, self._refusal(call, f"signer refused the call: {e}"))
        p["d"], d["args_digest"] = d, digest
        if d["decision"] == "deny":
            return _done(p, self._refusal(call, refusal(d) or "deny"))
        if d["decision"] == "ask":
            if config["configurable"].get(CONFIG_KEY_CHECKPOINTER) is None:
                why = "approval required, and the agent has no checkpointer to wait for it"
                return _done(p, self._refusal(call, why))
            try:   # the signer keeps one approval per call attempt: the re-run on resume, in any process, gets it back
                apr = self.signer.approval_request({"request_id": uuid.uuid4().hex, **self.run,
                                                    "tool_call_id": call["id"], "attempt": attempt})
            except (RPCError, SignerUnavailable) as e:
                return _done(p, self._refusal(call, str(e)))
            p["entry"] = _entry(call, d, apr["approval_id"])
        return p

    def _consume(self, call, p, hint):
        """approval_consume, the signer's last word before the call runs (every call, allowed or approved: the saved
        state can't vouch that no approval is needed): `p` runs, or is done with the refusal. An approval with a T2
        executor runs the arguments the consume returns."""
        try:
            c = self.signer.approval_consume({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                              "attempt": p["attempt"], "tool": call["name"], "args_source": "parsed",
                                              "args": call["args"], **({"approval_id_hint": hint} if hint else {})})
        except (RPCError, SignerUnavailable) as e:   # e.g. a hint that is not an id at all
            c = {"ok": False, "rule_ids": [], "reason": str(e)}
        if not c["ok"]:
            return _done(p, self._refusal(call, refusal(c, c.get("approval_id"))))
        if "args" in c:   # T2: the signer's copy is what runs
            p["d"]["args"], p["d"]["args_digest"] = c["args"], event_hash({"tool": call["name"], "args": c["args"]})
        p["state"] = "run"
        return p

    def _recorded(self, call):
        """The plan of a call as the signer recorded its latest attempt (call_state), for its node task run again after
        a resume, in this process or another; None when the signer never decided it, can't say, or the call raised (a
        retry runs it as a new attempt). A result comes back as a stand-in: the signer keeps a commitment to it, not
        the result."""
        digest = event_hash({"tool": call["name"], "args": call["args"]})
        try:
            s = self.signer.call_state({**self.run, "tool_call_id": call["id"], "args_digest": digest})
        except (RPCError, SignerUnavailable):   # decided again (_new), and judged by the signer then
            return None
        if "attempt" not in s:
            return None
        if "result" in s and not s["result"]["ok"]:
            self._attempts[call["id"]] = s["attempt"] + 1
            return None
        d = {k: s[k] for k in ("decision", "decision_id", "rule_ids", "reason", "send_result") if k in s}
        p = {"attempt": s["attempt"], "d": dict(d, args_digest=digest), "digest": digest, "state": "decide",
             "out": None, "entry": _entry(call, d, s["approval_id"]) if "approval_id" in s else None}
        if "result" in s:
            return _done(p, ToolMessage(f"ran; its result is recorded at run_seq {s['result']['run_seq']}",
                                        tool_call_id=call["id"], name=call["name"]))
        if d["decision"] == "deny":
            return _done(p, self._refusal(call, refusal(d) or "deny"))
        if "refused" in s:
            return _done(p, self._refusal(call, refusal({"rule_ids": s["refused"]}, s.get("approval_id"))))
        if s.get("consumed") and s.get("same_args"):
            p["state"] = "open"
        return p

    @staticmethod
    def _opened(plans, answered, asked):
        """A call consumed and not ended (`open`) goes on, consumed once, when the run answered a tool's own pause since
        (`answered`, the task's answers, counts more than the gate's pause, when any call `asked`): its tool paused the
        run. Else it was cut off, and the signer refuses it (approval_consume: TK-APPROVAL-CONSUMED)."""
        for p in plans:
            if p["state"] == "open":
                p["state"] = "paused" if answered > bool(asked) else "decide"

    @staticmethod
    def _pause(entries):
        """interrupt() for the approvals of `entries`, the first one's at the top and all in `approvals`."""
        return interrupt({"tracekit": {**entries[0], "approvals": entries}})

    def _pass(self, calls, config):
        """{tool_call_id: plan} of a held pass: a ToolNode running several calls of one model message in one node task,
        which LangGraph runs again from its start on each resume (and RetryPolicy retry) and whose interrupt() calls it
        pairs with resume values by the order they are reached. Each call's plan is established first: what this
        process planned, else what the signer recorded (a resume, maybe in another process), else decided now. Then the
        pass pauses once, before any tool runs, when any call asked, answered or not, so a tool's own interrupt() comes
        after it and gets the person's answer. Then each call allowed or approved is consumed (approval_consume, under
        its own approval) and one refused is done. A call that ended isn't decided, consumed or run again."""
        ns, answered, plans = _ns(config), _answered(config), {}
        for call in calls:
            p = self._plans.get((ns, call["id"]))
            if p is None and answered:
                p = self._recorded(call)
            if p is None or p["state"] == "raised":
                p = self._new(call, config, self._attempts.get(call["id"], 0))
            plans[call["id"]] = self._plans[ns, call["id"]] = p
        asked = [p["entry"] for p in plans.values() if p["entry"]]
        self._opened(plans.values(), answered, asked)
        if asked:
            self._pause(asked)   # raises until the run resumes; the resume value is not used
        for call in calls:
            if plans[call["id"]]["state"] == "decide":
                p = plans[call["id"]]
                self._consume(call, p, p["entry"] and p["entry"]["approval_id"])
        return plans

    def _forget(self, config):
        """The node task of `config` ended: none of its calls runs again."""
        ns = _ns(config)
        for key in [k for k in list(self._plans) if k[0] == ns]:
            del self._plans[key]

    def _gate(self, request):
        """(the ToolMessage that replaces the call, None when it may run; its plan). A call of a held pass has its plan
        (_pass). A single call is decided, paused for when it asks, and consumed in each pass of its node, as the
        resume hint names its approval; one whose tool paused the run after its consume goes on, consumed once."""
        call, config = request.tool_call, request.runtime.config
        held = _PASS.get()
        if held is not None and held["ns"] == _ns(config) and call["id"] in held["plans"]:
            p = held["plans"][call["id"]]
            if p["state"] != "done" and event_hash({"tool": call["name"], "args": call["args"]}) != p["digest"]:
                _done(p, self._refusal(call, "the call's arguments changed after the decision"))   # an outer wrapper's
            return p["out"], p
        key, answered = (_ns(config), call["id"]), _answered(config)
        p = self._plans.pop(key, None)
        if p is None and answered:
            p = self._recorded(call)
            if p is not None:
                self._opened([p], answered, [p["entry"]] if p["entry"] else [])
                p = p if p["state"] == "paused" else None
        if p is None:
            p = self._new(call, config, self._attempts.get(call["id"], 0))
        hint = None
        if p["entry"] is not None:   # in every pass of its node, so a tool's own interrupt() comes after it
            resume = self._pause([p["entry"]])
            hint = resume.get("approval_id") if isinstance(resume, dict) else None
        if p["state"] == "decide":
            self._consume(call, p, hint)
        return p["out"], p

    def _refusal(self, call, why):
        return ToolMessage(f"Tool call blocked by policy: {why}", tool_call_id=call["id"], name=call["name"],
                           status="error")

    def _paused(self, request, p):
        """The call's tool paused the run (interrupt(), a handoff): it goes on when its node runs again, an approved
        call under its one consume, an allowed one consumed again."""
        if p["d"] is not None:
            p["state"] = "decide" if p["d"]["decision"] == "allow" else "paused"
        self._plans[_ns(request.runtime.config), request.tool_call["id"]] = p

    def _complete(self, call, p, out=None, exc=None):
        """Records the outcome; never raises, so the tool's result or exception reaches the framework unchanged."""
        if exc is None:
            _done(p, out)
        else:
            p["state"] = "raised"
        decision = p["d"]
        if decision is None:   # ran unrecorded: the signer was unreachable and the run fails open
            return
        fields = {"status": "ok"}
        if exc is not None:
            fields.update(status="error", error=f"{type(exc).__name__}: {exc}"[:4096])
        elif isinstance(out, ToolMessage):
            fields["result"] = result_field(decision.get("send_result"), out.content)
            if out.status == "error":
                fields["status"] = "error"
        if event_hash({"tool": call["name"], "args": call["args"]}) != decision["args_digest"]:
            fields.update(status="error", error="the call's arguments changed after the decision")
        try:
            self._event("complete", call, p["attempt"], decision_id=decision["decision_id"],
                        args_digest=decision["args_digest"], **fields)
        except Exception as e:
            warnings.warn(f"tracekit: outcome of tool call {call['id']} not recorded: {e}", stacklevel=2)
        self._attempts[call["id"]] = p["attempt"] + 1

    # lean: wrap_tool_call's signer calls block; awrap_tool_call runs them in a worker thread (issue #680)
    def wrap_tool_call(self, request, handler):
        if _executor(request.tool):   # the executor decides it, under the model's id for the call
            self.said.decided(request.tool_call["id"])
            token = CALL_ID.set(request.tool_call["id"])
            try:
                return handler(request)
            finally:
                CALL_ID.reset(token)
        blocked, p = self._gate(request)
        if blocked is not None:
            return blocked
        if p["d"] is not None and "args" in p["d"]:
            request = request.override(tool_call={**request.tool_call, "args": p["d"]["args"]})
        try:
            out = handler(request)
        except GraphBubbleUp:   # interrupt() or a handoff inside the tool: control flow, not an outcome
            self._paused(request, p)
            raise
        except Exception as e:
            self._complete(request.tool_call, p, exc=e)
            raise
        self._complete(request.tool_call, p, out)
        return out

    async def awrap_tool_call(self, request, handler):
        if _executor(request.tool):
            await asyncio.to_thread(self.said.decided, request.tool_call["id"])
            token = CALL_ID.set(request.tool_call["id"])
            try:
                return await handler(request)
            finally:
                CALL_ID.reset(token)
        blocked, p = await asyncio.to_thread(self._gate, request)
        if blocked is not None:
            return blocked
        if p["d"] is not None and "args" in p["d"]:
            request = request.override(tool_call={**request.tool_call, "args": p["d"]["args"]})
        try:
            out = await handler(request)
        except GraphBubbleUp:   # interrupt() or a handoff inside the tool: control flow, not an outcome
            self._paused(request, p)
            raise
        except Exception as e:
            await asyncio.to_thread(self._complete, request.tool_call, p, exc=e)
            raise
        await asyncio.to_thread(self._complete, request.tool_call, p, out)
        return out


def _done(p, out):
    """Plan `p` is done: the model reads `out` (a refusal, or what the call gave) in each pass of its node."""
    p.update(state="done", out=out)
    return p


def _entry(call, d, approval_id):
    """A call's approval as the pause shows it (TracekitMiddleware._pause)."""
    return {"approval_id": approval_id, "tool_call_id": call["id"], "tool": call["name"], "rule_ids": d["rule_ids"]}


def _ns(config):
    """The checkpoint namespace of the node task `config` runs, the same in each pass of it."""
    return config.get("configurable", {}).get("checkpoint_ns")


def _answered(config):
    """How many interrupt() calls of the node task the run has answered: its resume values, which LangGraph pairs with
    the task's interrupt() calls by their order when it runs the task again from its start; 0 if it never paused."""
    s = config.get("configurable", {}).get(CONFIG_KEY_SCRATCHPAD)
    return len(s.resume) + (s.get_null_resume() is not None) if s is not None else 0


def _said(request, out):
    """(the items of what the model said, its model, its provider) in a model call's response: the calls of the
    agent's tools, which the gate or a tool executor decides under their ids (not a structured-output tool's), as
    `later`: recorded once they reach it."""
    msgs = [m for m in getattr(out, "result", [out]) if isinstance(m, AIMessage)]
    meta = msgs[0].response_metadata if msgs else {}
    tools = {t.name for t in request.tools if isinstance(t, BaseTool)}

    def items():
        for m in msgs:
            if isinstance(m.additional_kwargs.get("reasoning_content"), str):   # an open model's own reasoning
                yield said.thought(m.additional_kwargs["reasoning_content"], full=True)
            for b in m.content_blocks:   # LangChain's standard blocks; a provider's it can't map are non_standard
                v = (b.get("value") or {}) if b["type"] == "non_standard" else b
                if b["type"] == "reasoning":
                    yield said.thought(b.get("reasoning"), b.get("encrypted_content")
                                       or (b.get("extras") or {}).get("signature"))
                elif v.get("type") == "thinking":   # an Anthropic block of a message no provider is named for
                    yield said.thought(v.get("thinking"), v.get("signature"))
                elif v.get("type") == "redacted_thinking":
                    yield said.thought(sealed=v.get("data"))
                elif b["type"] == "text":
                    yield said.text(b.get("text"))
            for c in m.tool_calls:   # the calls ToolNode runs (content_blocks shows them only for some providers)
                if c["name"] in tools:
                    yield said.later(said.call(c.get("id"), c["name"], c.get("args") or {}))
    return items(), meta.get("model_name"), meta.get("model_provider")


def _executor(tool):
    """Whether `tool` is a tool executor's (executor_tools), whose calls the executor decides and records (T2)."""
    return bool((getattr(tool, "metadata", None) or {}).get(EXECUTOR))


def pausing(flag):
    """A ToolNode `handle_tool_errors` that handles the exceptions `flag` handles, as `flag` does, but re-raises a pause
    (GraphBubbleUp: the gate's approval interrupt), which ToolNode turns into an error message for any `flag` but its
    default. Which exceptions those are is read as ToolNode reads it, here, when the node is built: a handler whose
    annotation names no exception type fails now, not at the tool's first error."""
    if not flag:
        return flag
    types = ((flag,) if isinstance(flag, type) and issubclass(flag, Exception) else flag if isinstance(flag, tuple) else
             _infer_handled_types(flag) if callable(flag) and not isinstance(flag, type) else (Exception,))

    def handle(e):
        if isinstance(e, GraphBubbleUp):
            raise e
        return _handle_tool_error(e, flag=flag)
    handle.__annotations__ = {"e": Union[types]}   # ToolNode reads what a handler handles from its annotation
    return handle


class _Fallbacks(RunnableWithFallbacks):
    """`with_fallbacks` of a gated ToolNode: a pause the node raises (GraphBubbleUp) reaches LangGraph, which
    RunnableWithFallbacks would hand to the fallbacks as an error."""

    @property
    def runnables(self):   # one generator per invocation: `paused` is that invocation's
        paused = []
        yield _Pausing(self.runnable, paused)
        if not paused:
            yield from self.fallbacks


class _Pausing:
    """The node, noting a pause it raises. LangGraph runs a node with invoke or ainvoke."""

    def __init__(self, node, paused):
        self.node, self.paused = node, paused

    def __getattr__(self, name):   # lean: batch and stream run the fallbacks on a pause too; LangGraph never uses them
        return getattr(self.node, name)

    def invoke(self, *a, **kw):
        try:
            return self.node.invoke(*a, **kw)
        except GraphBubbleUp as e:
            self.paused.append(e)
            raise

    async def ainvoke(self, *a, **kw):
        try:
            return await self.node.ainvoke(*a, **kw)
        except GraphBubbleUp as e:
            self.paused.append(e)
            raise


def with_fallbacks(self, fallbacks, **kw):
    """Runnable.with_fallbacks for a gated ToolNode (_Fallbacks)."""
    return _Fallbacks(runnable=self, fallbacks=fallbacks, **kw)


def _held(node, input):
    """(the gate, the calls) of a pass of ToolNode `node` its gate holds (TracekitMiddleware._pass): two or more calls
    of one model message that aren't a tool executor's, while the node's wrapper is still the gate's (`tracekit why`'s
    replay copy serves recorded results instead); else (None, None)."""
    gate, wrap = getattr(node, "_tracekit", (None, None))
    if gate is None or node._wrap_tool_call is not wrap:
        return None, None
    calls = [c for c in node._parse_input(input)[0] if not _executor(node.tools_by_name.get(c["name"]))]
    return (gate, calls) if len(calls) > 1 else (None, None)


_TOOL_NODE = ToolNode._func, ToolNode._afunc, ToolNode._arun_one


def pass_func(self, input, config, runtime):
    """ToolNode._func, a held pass's calls planned together first (_held); each call's gate finds its plan in _PASS.
    Its threads all end before it raises a call's pause or error."""
    gate, calls = _held(self, input)
    if gate is None:
        return _TOOL_NODE[0](self, input, config, runtime)
    token, ended = _PASS.set({"ns": _ns(config), "plans": gate._pass(calls, config)}), False
    try:
        out, ended = _TOOL_NODE[0](self, input, config, runtime), True
    finally:
        _PASS.reset(token)
        if ended or not _ns(config):   # the node ended, or ran outside a graph: none of its calls runs again
            gate._forget(config)
    return out


async def pass_afunc(self, input, config, runtime):
    """ToolNode._afunc, as pass_func; the signer calls in a worker thread."""
    gate, calls = _held(self, input)
    if gate is None:
        return await _TOOL_NODE[1](self, input, config, runtime)
    plans = await asyncio.to_thread(gate._pass, calls, config)
    token, ended = _PASS.set({"ns": _ns(config), "plans": plans, "node": self, "left": len(self._parse_input(input)[0]),
                              "done": asyncio.Event()}), False
    try:
        out, ended = await _TOOL_NODE[1](self, input, config, runtime), True
    finally:
        _PASS.reset(token)
        if ended or not _ns(config):
            gate._forget(config)
    return out


async def pass_arun_one(self, call, input_type, tool_runtime):
    """ToolNode._arun_one; in a held pass, a call that raises (a pause, an error) waits until every call of the node
    has ended, so asyncio.gather cuts none of them off mid-run."""
    held, raised = _PASS.get(), None
    if held is None or held.get("node") is not self:
        return await _TOOL_NODE[2](self, call, input_type, tool_runtime)
    try:
        out = await _TOOL_NODE[2](self, call, input_type, tool_runtime)
    except Exception as e:
        raised = e
    finally:
        held["left"] -= 1
        if not held["left"]:
            held["done"].set()
    if raised is not None:
        await held["done"].wait()
        raise raised
    return out


class _GatedToolNode(ToolNode):
    with_fallbacks = with_fallbacks
    _func, _afunc, _arun_one = pass_func, pass_afunc, pass_arun_one


def tracekit_tool_node(tools, signer, run, **kw):
    """A `ToolNode` for graphs built without `create_agent`, every call through the `TracekitMiddleware` gate. `run` is
    the signer's `register_run` response; `kw` goes to ToolNode."""
    gate = TracekitMiddleware(signer, run["run_id"], run["run_token"], run.get("fail_modes"))
    if "handle_tool_errors" in kw:
        kw["handle_tool_errors"] = pausing(kw["handle_tool_errors"])
    node = _GatedToolNode(tools, wrap_tool_call=gate.wrap_tool_call, awrap_tool_call=gate.awrap_tool_call, **kw)
    node._tracekit = gate, node._wrap_tool_call   # the gate holds the node's passes while this is its wrapper (_held)
    return node


_SERDE = JsonPlusSerializer()


def _sha(value):
    return hashlib.sha256(_SERDE.dumps_typed(value)[1]).hexdigest()


def checkpoint_digest(t):
    """The digest of a CheckpointTuple: canonical JSON over the hashes of its serialised parts, the checkpoint's own
    fields, each channel value (`__pregel_tasks` among them: the pending tool calls a resumed run executes) and each
    pending write (results of finished tasks, interrupts, resume values). Not covered: metadata and parent_config.
    Each part is hashed alone, so the order a saver gives channels and writes back in does not count."""
    c = dict(t.checkpoint)
    values = c.pop("channel_values")
    return event_hash({"checkpoint": _sha(c), "channel_values": {k: _sha(v) for k, v in values.items()},
                       "pending_writes": sorted(_sha(list(w)) for w in t.pending_writes or ())})


def _key(config):
    c = config["configurable"]
    return f"langgraph:{c['thread_id']}" + (f"/{c['checkpoint_ns']}" if c.get("checkpoint_ns") else "")


def _latest(config):
    """The config that reads the thread's latest checkpoint, whichever checkpoint `config` names."""
    c = config["configurable"]
    return {"configurable": {"thread_id": c["thread_id"], "checkpoint_ns": c.get("checkpoint_ns", "")}}


class TracekitCheckpointer(BaseCheckpointSaver):
    """A BaseCheckpointSaver that commits what the wrapped saver holds to the signer (L1): after each checkpoint or
    pending-writes write, a `state_write` of `checkpoint_digest` of the thread's latest checkpoint (key
    `langgraph:<thread_id>[/<checkpoint_ns>]`), from the digest the signer last recorded for it. A checkpoint changed
    in the saver between two writes (seen when a run loads it to resume) makes the next write start from another
    digest than the signer's last, which the signer records as a `state_tamper` gap."""

    def __init__(self, saver, signer, run):
        super().__init__(serde=saver.serde)
        self.saver, self.signer, self.run = saver, signer, {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._reads = "langgraph-" + uuid.uuid4().hex, itertools.count(), itertools.count()
        self._lock = threading.Lock()   # LangGraph writes from several threads or tasks at once
        # one entry per thread (and namespace) until the thread is deleted (delete_thread)
        self._seen = {}    # key -> (checkpoint_id, digest) of the thread's latest checkpoint as this process last saw it
        self._acked = {}   # key -> the digest the signer last recorded: the next state_write's prev_digest
        self._read = {}    # key -> the number of the read the last commitment came from

    def get_tuple(self, config):
        return self._loaded(self.saver.get_tuple(config))

    async def aget_tuple(self, config):
        return await asyncio.to_thread(self._loaded, await self.saver.aget_tuple(config))   # the lock waits on a signer call

    def _loaded(self, t):
        if t is not None:
            k, cid = _key(t.config), t.config["configurable"]["checkpoint_id"]
            with self._lock:
                seen = self._seen.get(k)
                # lean: a new process can't tell an older checkpoint (time travel) from the latest, so resuming one
                # reads as state_tamper; commit per checkpoint_id if apps resume from history
                if seen is None or seen[0] == cid:   # not an older checkpoint of the thread (history)
                    d = checkpoint_digest(t)
                    if seen != (cid, d):   # changed since this process last saw it: the next write starts from it
                        self._seen[k], self._acked[k] = (cid, d), d
        return t

    def put(self, config, *args, **kw):
        config = self.saver.put(config, *args, **kw)
        self._wrote(config)
        return config

    async def aput(self, config, *args, **kw):
        config = await self.saver.aput(config, *args, **kw)
        await self._awrote(config)
        return config

    def put_writes(self, config, writes, task_id, task_path=""):   # LangGraph passes task_path only if named
        self.saver.put_writes(config, writes, task_id, task_path)
        self._wrote(config)

    async def aput_writes(self, config, writes, task_id, task_path=""):
        await self.saver.aput_writes(config, writes, task_id, task_path)
        await self._awrote(config)

    # the saver has written: raising would fail the run after it. The next commitment starts from the last digest the
    # signer recorded, so a lost one never reads as tampering.
    def _wrote(self, config):
        try:
            n = next(self._reads)   # numbered after the write, so any later-numbered read includes it
            self._commit(n, self.saver.get_tuple(_latest(config)))
        except Exception as e:
            warnings.warn(f"tracekit: checkpoint commitment for {_key(config)} not recorded: {e}", stacklevel=3)

    async def _awrote(self, config):
        try:
            n = next(self._reads)
            t = await self.saver.aget_tuple(_latest(config))
            await asyncio.to_thread(self._commit, n, t)   # the signer client blocks
        except Exception as e:
            warnings.warn(f"tracekit: checkpoint commitment for {_key(config)} not recorded: {e}", stacklevel=3)

    def _commit(self, n, t):
        """Commit `t`, the thread's latest checkpoint as read `n` found it, unless a later read is committed already
        (it includes this write). `t` is None before the thread's first checkpoint."""
        if t is None:
            return
        k = _key(t.config)
        with self._lock:
            if n < self._read.get(k, -1):
                return
            d = checkpoint_digest(t)
            self._read[k], self._seen[k] = n, (t.config["configurable"]["checkpoint_id"], d)
            self.signer.state_write({"request_id": uuid.uuid4().hex, **self.run, "stream": self.stream,
                                     "client_seq": next(self._seq), "key": k, "value_digest": d,
                                     "prev_digest": self._acked.get(k)})
            self._acked[k] = d

    def with_allowlist(self, extra_allowlist):
        saver = self.saver.with_allowlist(extra_allowlist)
        if saver is self.saver:
            return self
        clone = copy.copy(self)   # shares what this one saw and committed
        clone.saver, clone.serde = saver, saver.serde
        return clone

    config_specs = property(lambda self: self.saver.config_specs)

    def _forget(self, thread_id):
        """Drop what this process remembers of a deleted thread (each of its namespaces)."""
        key = f"langgraph:{thread_id}"
        with self._lock:
            for d in (self._seen, self._acked, self._read):
                for k in [k for k in d if k == key or k.startswith(key + "/")]:
                    del d[k]

    def delete_thread(self, thread_id):
        self.saver.delete_thread(thread_id)
        self._forget(thread_id)

    async def adelete_thread(self, thread_id):
        await self.saver.adelete_thread(thread_id)
        self._forget(thread_id)


def _wrapped(name):
    return lambda self, *args, **kw: getattr(self.saver, name)(*args, **kw)


for _name in ("list", "alist", "delete_for_runs", "adelete_for_runs", "copy_thread",
              "acopy_thread", "prune", "aprune", "get_delta_channel_history", "aget_delta_channel_history",
              "get_next_version"):
    setattr(TracekitCheckpointer, _name, _wrapped(_name))
