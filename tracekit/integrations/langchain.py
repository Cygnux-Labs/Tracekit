"""LangChain v1 middleware: every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.langchain import TracekitMiddleware
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])

`deny` replaces the call with an error ToolMessage and the run goes on. `ask` pauses the run with LangGraph
`interrupt()`; on resume the approval is checked by the signer, never by the saved state. `ask` needs a checkpointer:
without one the call is denied.
"""
import hashlib
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
        """(the error ToolMessage that replaces a refused call or None when it may run, the last decision)"""
        call = request.tool_call
        d = self._decide(call)
        if d["decision"] == "ask":
            if request.runtime.config["configurable"].get(CONFIG_KEY_CHECKPOINTER) is None:
                return self._refusal(call, "approval required, and the agent has no checkpointer to wait for it"), d
            # a fixed request_id, so the re-run on resume (even in another process) gets the same approval back
            key = hashlib.sha256(f"{self.run['run_id']}\0{call['id']}".encode()).hexdigest()[:32]
            apr = self.signer.approval_request({"request_id": "approval:" + key, **self.run, "tool_call_id": call["id"]})
            resume = interrupt({"tracekit": {"approval_id": apr["approval_id"], "tool_call_id": call["id"],
                                             "tool": call["name"], "rule_ids": d["rule_ids"]}})
            # the resume value is only a hint: the signer re-checks the call against its own approval record
            hint = resume.get("approval_id") if isinstance(resume, dict) else None
            try:
                d = self._decide(call, approval_id=hint or apr["approval_id"])
            except RPCError as e:
                d = {"decision": "deny", "rule_ids": [], "reason": e.message}
        if d["decision"] == "allow":
            return None, d
        return self._refusal(call, d.get("reason") or ", ".join(d["rule_ids"]) or d["decision"]), d

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
