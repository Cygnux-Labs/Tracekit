"""LangChain v1 middleware: every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.langchain import TracekitMiddleware
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])

`deny` replaces the call with an error ToolMessage and the run goes on. `ask` pauses the run with LangGraph
`interrupt()`; resume it with `Command(resume={"approval_id": ...})`. Every call that is not denied runs only after the
signer's `approval_consume` agrees, so an approval is checked by the signer, never by the saved state. `ask` needs a
checkpointer: without one the call is denied.
"""
import itertools
import uuid

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.constants import CONFIG_KEY_CHECKPOINTER
from langgraph.errors import GraphBubbleUp
from langgraph.types import interrupt

from tracekit.format.canon import event_hash
from tracekit.signer.rpc_schema import RPCError


class TracekitMiddleware(AgentMiddleware):
    def __init__(self, signer, run_id, run_token):
        """`signer` is any `SignerAPI`; `run_id`/`run_token` come from its `register_run`."""
        super().__init__()
        self.signer, self.run = signer, {"run_id": run_id, "run_token": run_token}
        self.stream, self._seq = "langchain-" + uuid.uuid4().hex, itertools.count()

    def _event(self, call, **kw):
        return {"request_id": uuid.uuid4().hex, **self.run, "stream": self.stream, "client_seq": next(self._seq),
                # lean: attempt is always 0; count per tool_call_id once retry middleware is supported
                "tool_call_id": call["id"], "attempt": 0, **kw}

    def _decide(self, call, **kw):
        # LangChain hands over JSON-decoded args, never the model's raw string
        return self.signer.decide(self._event(call, tool=call["name"], args_source="parsed", args=call["args"], **kw))

    def _gate(self, request):
        """(the error ToolMessage that replaces a refused call or None when it may run, the decision)"""
        call, hint = request.tool_call, None
        d = self._decide(call)
        if d["decision"] == "deny":
            return self._refusal(call, ", ".join(d["rule_ids"]) or "deny"), d
        if d["decision"] == "ask":
            if request.runtime.config["configurable"].get(CONFIG_KEY_CHECKPOINTER) is None:
                return self._refusal(call, "approval required, and the agent has no checkpointer to wait for it"), d
            # the signer keeps one approval per call attempt, so the re-run on resume (even in another process) gets
            # the same approval back
            apr = self.signer.approval_request({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                                "attempt": 0})
            resume = interrupt({"tracekit": {"approval_id": apr["approval_id"], "tool_call_id": call["id"],
                                             "tool": call["name"], "rule_ids": d["rule_ids"]}})
            hint = resume.get("approval_id") if isinstance(resume, dict) else None
        # every call, allowed or approved: the saved state can't vouch that no approval is needed
        try:
            c = self.signer.approval_consume({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                              "attempt": 0, "tool": call["name"], "args_source": "parsed",
                                              "args": call["args"], **({"approval_id_hint": hint} if hint else {})})
        except RPCError as e:   # e.g. a hint that is not an id at all
            c = {"ok": False, "rule_ids": [], "reason": e.message}
        if c["ok"]:
            return None, d
        return self._refusal(call, ", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else "")), d

    def _refusal(self, call, why):
        return ToolMessage(f"Tool call blocked by policy: {why}", tool_call_id=call["id"], name=call["name"],
                           status="error")

    def _complete(self, call, decision, out=None, exc=None):
        req = self._event(call, status="ok", decision_id=decision["decision_id"],
                          args_digest=event_hash({"tool": call["name"], "args": call["args"]}))
        if exc is not None:
            req.update(status="error", error=f"{type(exc).__name__}: {exc}"[:4096])
        elif isinstance(out, ToolMessage):
            req["result"] = event_hash(out.content)   # a commitment, not the result itself
            if out.status == "error":
                req["status"] = "error"
        self.signer.complete(req)

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
