"""LangChain v1 middleware: every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.langchain import TracekitMiddleware
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"],
                                                        fail_modes=run.get("fail_modes"))])

`deny` replaces the call with an error ToolMessage and the run goes on. `ask` pauses the run with LangGraph
`interrupt()`; resume it with `Command(resume={"approval_id": ...})`. Every call that is not denied runs only after the
signer's `approval_consume` agrees, so an approval is checked by the signer, never by the saved state. `ask` needs a
checkpointer: without one the call is denied.

A signer that cannot be reached when a call is decided: the call runs unrecorded if register_run's `fail_modes` say
`open`, else it is refused. Any other failure to decide or approve (a refusal, a run the signer closed after its idle
timeout: register a new run for a long-idle agent) refuses the call. A failure to record the outcome warns and leaves
the tool's result as it was. Put TracekitMiddleware last in `middleware=`: a middleware after it could hand the tool a
call other than the one decided.
"""
import itertools
import threading
import uuid
import warnings

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.constants import CONFIG_KEY_CHECKPOINTER
from langgraph.errors import GraphBubbleUp
from langgraph.types import interrupt

from tracekit.format.canon import event_hash
from tracekit.sdk.client import SignerUnavailable, fail_open
from tracekit.signer.rpc_schema import RPCError


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

    def _event(self, method, call, **kw):
        # lean: one event call at a time per middleware (ToolNode runs sync tools in threads), so client_seq arrives in
        # order; pipeline if it gets slow
        with self._lock:
            return getattr(self.signer, method)({
                "request_id": uuid.uuid4().hex, **self.run, "stream": self.stream, "client_seq": next(self._seq),
                "tool_call_id": call["id"], "attempt": self._attempts.get(call["id"], 0), **kw})

    def _gate(self, request):
        """(the error ToolMessage that replaces a refused call or None when it may run, the decision or None)"""
        call, hint = request.tool_call, None
        attempt = self._attempts.get(call["id"], 0)
        try:   # LangChain hands over JSON-decoded args, never the model's raw string
            d = self._event("decide", call, tool=call["name"], args_source="parsed", args=call["args"])
        except SignerUnavailable as e:
            return (None if fail_open(self.fail_modes) else self._refusal(call, f"signer unavailable: {e}")), None
        except RPCError as e:
            return self._refusal(call, f"signer refused the call: {e}"), None
        if d["decision"] == "deny":
            return self._refusal(call, ", ".join(d["rule_ids"]) or "deny"), d
        d["args_digest"] = event_hash({"tool": call["name"], "args": call["args"]})
        try:
            if d["decision"] == "ask":
                if request.runtime.config["configurable"].get(CONFIG_KEY_CHECKPOINTER) is None:
                    return self._refusal(call, "approval required, and the agent has no checkpointer to wait for it"), d
                # the signer keeps one approval per call attempt, so the re-run on resume (even in another process)
                # gets the same approval back
                apr = self.signer.approval_request({"request_id": uuid.uuid4().hex, **self.run,
                                                    "tool_call_id": call["id"], "attempt": attempt})
                resume = interrupt({"tracekit": {"approval_id": apr["approval_id"], "tool_call_id": call["id"],
                                                 "tool": call["name"], "rule_ids": d["rule_ids"]}})
                hint = resume.get("approval_id") if isinstance(resume, dict) else None
            # every call, allowed or approved: the saved state can't vouch that no approval is needed
            c = self.signer.approval_consume({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                              "attempt": attempt, "tool": call["name"], "args_source": "parsed",
                                              "args": call["args"], **({"approval_id_hint": hint} if hint else {})})
        except (RPCError, SignerUnavailable) as e:   # e.g. a hint that is not an id at all
            c = {"ok": False, "rule_ids": [], "reason": str(e)}
        if c["ok"]:
            return None, d
        return self._refusal(call, ", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else "")), d

    def _refusal(self, call, why):
        return ToolMessage(f"Tool call blocked by policy: {why}", tool_call_id=call["id"], name=call["name"],
                           status="error")

    def _complete(self, call, decision, out=None, exc=None):
        """Records the outcome; never raises, so the tool's result or exception reaches the framework unchanged."""
        if decision is None:   # ran unrecorded: the signer was unreachable and the run fails open
            return
        fields = {"status": "ok"}
        if exc is not None:
            fields.update(status="error", error=f"{type(exc).__name__}: {exc}"[:4096])
        elif isinstance(out, ToolMessage):
            fields["result"] = event_hash(out.content)   # a commitment, not the result itself
            if out.status == "error":
                fields["status"] = "error"
        if event_hash({"tool": call["name"], "args": call["args"]}) != decision["args_digest"]:
            fields.update(status="error", error="the call's arguments changed after the decision")
        try:
            self._event("complete", call, decision_id=decision["decision_id"], args_digest=decision["args_digest"],
                        **fields)
        except Exception as e:
            warnings.warn(f"tracekit: outcome of tool call {call['id']} not recorded: {e}", stacklevel=2)
        self._attempts[call["id"]] = self._attempts.get(call["id"], 0) + 1

    # lean: signer calls are blocking in both paths; use the async client in awrap_tool_call once it exists
    def wrap_tool_call(self, request, handler):
        blocked, d = self._gate(request)
        if blocked is not None:
            return blocked
        try:
            out = handler(request)
        except GraphBubbleUp:   # interrupt() or a handoff inside the tool: control flow, not an outcome
            raise
        except Exception as e:
            self._complete(request.tool_call, d, exc=e)
            raise
        self._complete(request.tool_call, d, out)
        return out

    async def awrap_tool_call(self, request, handler):
        blocked, d = self._gate(request)
        if blocked is not None:
            return blocked
        try:
            out = await handler(request)
        except GraphBubbleUp:   # interrupt() or a handoff inside the tool: control flow, not an outcome
            raise
        except Exception as e:
            self._complete(request.tool_call, d, exc=e)
            raise
        self._complete(request.tool_call, d, out)
        return out
