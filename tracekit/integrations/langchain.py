"""LangChain v1 middleware: every tool call is decided by the signer before it runs and recorded after.

    from tracekit.integrations.langchain import TracekitMiddleware
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])

`deny` replaces the call with an error ToolMessage and the run goes on. `ask` pauses the run with LangGraph
`interrupt()`; resume it with `Command(resume={"approval_id": ...})`. Every call that is not denied runs only after the
signer's `approval_consume` agrees, so an approval is checked by the signer, never by the saved state. `ask` needs a
checkpointer: without one the call is denied.

A graph built on `ToolNode` without `create_agent` uses `tracekit_tool_node(tools, signer, run)`, the same gate.
`TracekitCheckpointer(saver, signer, run)` commits every checkpoint the saver writes to the signer (L1).
"""
import asyncio
import copy
import hashlib
import itertools
import threading
import uuid
import warnings

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.constants import CONFIG_KEY_CHECKPOINTER
from langgraph.errors import GraphBubbleUp
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt

from tracekit.format.canon import event_hash
from tracekit.signer.rpc_schema import RPCError


class TracekitMiddleware(AgentMiddleware):
    def __init__(self, signer, run_id, run_token):
        """`signer` is any `SignerAPI`; `run_id`/`run_token` come from its `register_run`."""
        super().__init__()
        self.signer, self.run = signer, {"run_id": run_id, "run_token": run_token}
        self.stream, self._seq = "langchain-" + uuid.uuid4().hex, itertools.count()
        # lean: one entry per executed tool call for the middleware's life; prune at run end if agents run for days
        self._attempts = {}   # tool_call_id -> the attempt its next execution is (a retry runs the same call again)

    def _event(self, call, **kw):
        return {"request_id": uuid.uuid4().hex, **self.run, "stream": self.stream, "client_seq": next(self._seq),
                "tool_call_id": call["id"], "attempt": self._attempts.get(call["id"], 0), **kw}

    def _decide(self, call, **kw):
        # LangChain hands over JSON-decoded args, never the model's raw string
        return self.signer.decide(self._event(call, tool=call["name"], args_source="parsed", args=call["args"], **kw))

    def _gate(self, request):
        """(the error ToolMessage that replaces a refused call or None when it may run, the decision)"""
        call, hint = request.tool_call, None
        attempt = self._attempts.get(call["id"], 0)
        d = self._decide(call)
        if d["decision"] == "deny":
            return self._refusal(call, ", ".join(d["rule_ids"]) or "deny"), d
        if d["decision"] == "ask":
            if request.runtime.config["configurable"].get(CONFIG_KEY_CHECKPOINTER) is None:
                return self._refusal(call, "approval required, and the agent has no checkpointer to wait for it"), d
            # the signer keeps one approval per call attempt, so the re-run on resume (even in another process) gets
            # the same approval back
            apr = self.signer.approval_request({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                                "attempt": attempt})
            resume = interrupt({"tracekit": {"approval_id": apr["approval_id"], "tool_call_id": call["id"],
                                             "tool": call["name"], "rule_ids": d["rule_ids"]}})
            hint = resume.get("approval_id") if isinstance(resume, dict) else None
        # every call, allowed or approved: the saved state can't vouch that no approval is needed
        try:
            c = self.signer.approval_consume({"request_id": uuid.uuid4().hex, **self.run, "tool_call_id": call["id"],
                                              "attempt": attempt, "tool": call["name"], "args_source": "parsed",
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
        self._attempts[call["id"]] = req["attempt"] + 1
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


def tracekit_tool_node(tools, signer, run, **kw):
    """A `ToolNode` for graphs built without `create_agent`, every call through the `TracekitMiddleware` gate. `run` is
    the signer's `register_run` response; `kw` goes to ToolNode."""
    gate = TracekitMiddleware(signer, run["run_id"], run["run_token"])
    return ToolNode(tools, wrap_tool_call=gate.wrap_tool_call, awrap_tool_call=gate.awrap_tool_call, **kw)


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


class TracekitCheckpointer(BaseCheckpointSaver):
    """A BaseCheckpointSaver that commits what the wrapped saver holds to the signer (L1): after each checkpoint or
    pending-writes write, a `state_write` of `checkpoint_digest` of the thread's checkpoint (key
    `langgraph:<thread_id>[/<checkpoint_ns>]`), from the digest the signer last recorded for it. A checkpoint changed
    in the saver between two writes (seen when a run loads it to resume) makes the next write start from another
    digest than the signer's last, which the signer records as a `state_tamper` gap."""

    def __init__(self, saver, signer, run):
        super().__init__(serde=saver.serde)
        self.saver, self.signer, self.run = saver, signer, {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._reads = "langgraph-" + uuid.uuid4().hex, itertools.count(), itertools.count()
        self._lock = threading.Lock()   # LangGraph writes from several threads or tasks at once
        # lean: one entry per thread for the saver's life; prune on delete_thread if one process serves many threads
        self._seen = {}    # key -> (checkpoint_id, digest) of the thread's latest checkpoint as this process last saw it
        self._acked = {}   # key -> the digest the signer last recorded: the next state_write's prev_digest
        self._read = {}    # key -> the number of the read the last commitment came from

    def get_tuple(self, config):
        return self._loaded(self.saver.get_tuple(config))

    async def aget_tuple(self, config):
        return self._loaded(await self.saver.aget_tuple(config))

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

    def put_writes(self, config, *args, **kw):
        self.saver.put_writes(config, *args, **kw)
        self._wrote(config)

    async def aput_writes(self, config, *args, **kw):
        await self.saver.aput_writes(config, *args, **kw)
        await self._awrote(config)

    # the saver has written: raising would fail the run after it. The next commitment starts from the last digest the
    # signer recorded, so a lost one never reads as tampering.
    def _wrote(self, config):
        try:
            n = next(self._reads)   # numbered after the write, so any later-numbered read includes it
            self._commit(n, self.saver.get_tuple(config))
        except Exception as e:
            warnings.warn(f"tracekit: checkpoint commitment for {_key(config)} not recorded: {e}", stacklevel=3)

    async def _awrote(self, config):
        try:
            n = next(self._reads)
            t = await self.saver.aget_tuple(config)
            await asyncio.to_thread(self._commit, n, t)   # the signer client blocks
        except Exception as e:
            warnings.warn(f"tracekit: checkpoint commitment for {_key(config)} not recorded: {e}", stacklevel=3)

    def _commit(self, n, t):
        """Commit `t`, from read `n`, unless a later read is committed already (it includes this write). `t` is None
        for writes to a checkpoint not saved yet: its own commitment comes after them."""
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


def _wrapped(name):
    return lambda self, *args, **kw: getattr(self.saver, name)(*args, **kw)


for _name in ("list", "alist", "delete_thread", "adelete_thread", "delete_for_runs", "adelete_for_runs", "copy_thread",
              "acopy_thread", "prune", "aprune", "get_delta_channel_history", "aget_delta_channel_history",
              "get_next_version"):
    setattr(TracekitCheckpointer, _name, _wrapped(_name))
