"""Record Anthropic Messages API calls without restructuring your agent.

    from anthropic import Anthropic
    from tracekit.why import Runtime
    from tracekit.why.adapters.anthropic import TracedMessages

    rt = Runtime({}, out_dir="runs", task="Resolve ticket 881")
    msgs = TracedMessages(Anthropic().messages, rt.agent("support"), untrusted_tools={"web_fetch"})
    resp = msgs.create(model=..., max_tokens=..., messages=[...], tools=[...])
    for block in resp.content:
        if block.type == "tool_use":
            results.append(msgs.run_tool(block, my_tools[block.name]))  # guard check, run, record
    ...
    rt.finish()

`run_tool` asks the runtime's guard (Runtime(..., guard=Guard("block"))) before running a tool, so a
send_email whose address only came from a fetched page is refused while the agent runs. If you run
tools yourself, call `msgs.tool_result(block.id, result)` instead (no guard check).

Every system prompt, message block and tool result the request carries becomes a content-addressed
context item, so the graph gets observed edges with no manual `decide([...])` lists. A tool_result
block is linked back to the action recorded with `tool_result()`; results of tools listed in
`untrusted_tools` are also marked untrusted so taint and alerts see them.

Each decision also records the request's layout (which context item sat where), so a recorded call
can be re-sent without one of its inputs: `decision_test(run, seq, "input:tool:web_fetch",
models={"<model id>": replay_model(Anthropic().messages)}, contains="audit@")`, or
`tracekit why test RUN --decision SEQ --remove ... --anthropic`. Real models ignore seeds, so tests
compare against a no-removal control.

Not covered yet: streaming.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..core import Agent, ModelOutput, Ref, content_hash

API_PARAMS = ("max_tokens", "temperature", "top_p", "top_k", "tool_choice", "stop_sequences")


def _plain(obj: Any) -> Any:
    """SDK objects -> plain JSON-able data."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True)
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return {k: _plain(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj


class TracedMessages:
    def __init__(self, messages_api: Any, agent: Agent, *, user_trust: str = "untrusted",
                 untrusted_tools: Iterable[str] = (), sensitive_tools: Iterable[str] = (),
                 purpose: str = "", trust_fn: Optional[Callable[[str, Any], Optional[str]]] = None):
        self._api = messages_api
        self.agent = agent
        self.user_trust = user_trust
        self.untrusted_tools = set(untrusted_tools)
        self.sensitive_tools = set(sensitive_tools)
        self.purpose = purpose
        self.trust_fn = trust_fn
        self._known: Dict[str, Ref] = {}           # content hash -> Ref already in the run
        self._tool_uses: Dict[str, Tuple[str, Any, Ref]] = {}  # tool_use_id -> (name, input, decision)
        self._results: Dict[str, Ref] = {}         # tool_use_id -> Ref used for its tool_result block

    # -- context building
    def _ref(self, value: Any, source: str, trust: str) -> Ref:
        h = content_hash(value)
        if h in self._known:
            return self._known[h]
        if self.trust_fn:
            trust = self.trust_fn(source, value) or trust
        r = self.agent.observe(value, source=source, trust=trust)
        self._known[h] = r
        return r

    def _context(self, kw: Dict[str, Any]) -> Tuple[List[Ref], Dict[str, Any]]:
        """Context items, plus the request layout: where each item sat, by content hash, so
        replay_model can rebuild the request with some items removed."""
        ctx: List[Ref] = []
        layout: Dict[str, Any] = {"model": str(kw.get("model")), "messages": []}
        if kw.get("system"):
            r = self._ref(_plain(kw["system"]), "system", "trusted")
            ctx.append(r)
            layout["system"] = r.ref
        if kw.get("tools"):
            r = self._ref(_plain(kw["tools"]), "tools", "trusted")
            ctx.append(r)
            layout["tools"] = r.ref
        for i, m in enumerate(kw.get("messages", [])):
            m = _plain(m)
            role, content = m.get("role"), m.get("content")
            blocks = [{"type": "text", "text": content}] if isinstance(content, str) else (content or [])
            slots = []
            for j, b in enumerate(blocks):
                if b.get("type") == "tool_result":
                    r = self._results.get(b.get("tool_use_id")) or \
                        self._ref(b.get("content"), f"tool_result#{i}.{j}", self.user_trust)
                    slots.append({"ref": r.ref, "as": "tool_result", "id": b.get("tool_use_id"),
                                  "is_error": bool(b.get("is_error"))})
                elif role == "assistant":
                    r = self._ref(b, f"assistant#{i}.{j}", "trusted")
                    slots.append({"ref": r.ref, "as": "block"})
                else:
                    r = self._ref(b, f"user#{i}.{j}", self.user_trust)
                    slots.append({"ref": r.ref, "as": "block"})
                ctx.append(r)
            layout["messages"].append({"role": role, "blocks": slots})
        return ctx, layout

    # -- API
    def create(self, **kw: Any) -> Any:
        ctx, layout = self._context(kw)
        t0 = time.perf_counter()
        try:
            resp = self._api.create(**kw)
        except Exception as e:
            self.agent.record_decision(ctx, {"error": f"{type(e).__name__}: {e}"}, model=str(kw.get("model")),
                                       purpose=self.purpose, status="error",
                                       duration_ms=(time.perf_counter() - t0) * 1000)
            raise
        dur = (time.perf_counter() - t0) * 1000
        content = _plain(getattr(resp, "content", []))
        usage = _plain(getattr(resp, "usage", None)) or {}
        params = {k: _plain(kw[k]) for k in API_PARAMS if k in kw}
        params["request"] = layout
        dec = self.agent.record_decision(ctx, {"content": content, "stop_reason": getattr(resp, "stop_reason", None)},
                                         model=str(kw.get("model")), purpose=self.purpose, params=params,
                                         usage={k: usage.get(k) for k in ("input_tokens", "output_tokens")
                                                if usage.get(k) is not None}, duration_ms=dur)
        for j, b in enumerate(content):
            # each assistant block, when sent back in the next request, should link to this decision
            ref = self.agent.rt._blob(b)  # stored, so the next request's context can point at it
            self._known[ref] = Ref(ref, b, "output", self.agent.name, self.purpose or "assistant", dec.trust, dec.event_id)
            if b.get("type") == "tool_use":
                self._tool_uses[b["id"]] = (b["name"], b.get("input", {}), dec)
        return resp

    def _sensitive(self, name: str, sensitive: Optional[bool]) -> Optional[bool]:
        return sensitive if sensitive is not None else (name in self.sensitive_tools or None)

    def check(self, block: Any, *, sensitive: Optional[bool] = None) -> Any:
        """Ask the runtime's guard about a tool_use block before running it. None without a guard."""
        b = _plain(block)
        name, args, dec = self._tool_uses[b["id"]]
        return self.agent.check(name, args if isinstance(args, dict) else {"input": args}, decision=dec,
                                sensitive=self._sensitive(name, sensitive))

    def run_tool(self, block: Any, fn: Callable[..., Any], *, sensitive: Optional[bool] = None) -> Dict[str, Any]:
        """Guard check, run fn(**input), record it. Returns the tool_result block to send back.
        A blocked call is not executed; the model gets an error result saying why."""
        b = _plain(block)
        check = self.check(b, sensitive=sensitive)
        if check is not None and check.blocked:
            msg = "blocked by tracekit why guard: " + check.reason
            self.tool_result(b["id"], {"error": msg}, sensitive=sensitive, check=check)
            return {"type": "tool_result", "tool_use_id": b["id"], "content": msg, "is_error": True}
        args = b.get("input") or {}
        t0 = time.perf_counter()
        try:
            out = fn(**args) if isinstance(args, dict) else fn(args)
        except Exception as e:  # recorded and returned to the model, like any tool error
            out = {"error": f"{type(e).__name__}: {e}"}
        self.tool_result(b["id"], out, duration_ms=(time.perf_counter() - t0) * 1000, sensitive=sensitive,
                         check=check)
        res = {"type": "tool_result", "tool_use_id": b["id"],
               "content": out if isinstance(out, str) else json.dumps(out, default=str)}
        if isinstance(out, dict) and out.get("error"):
            res["is_error"] = True
        return res

    def tool_result(self, tool_use_id: str, result: Any, *, duration_ms: Optional[float] = None,
                    sensitive: Optional[bool] = None, check: Any = None) -> Ref:
        """Record the tool call your code executed for a tool_use block."""
        if tool_use_id not in self._tool_uses:
            raise KeyError(f"unknown tool_use_id {tool_use_id!r}")
        name, args, dec = self._tool_uses[tool_use_id]
        act = self.agent.record_action(name, args if isinstance(args, dict) else {"input": args}, result,
                                       decision=dec, duration_ms=duration_ms,
                                       sensitive=self._sensitive(name, sensitive), check=check)
        ref = act
        if name in self.untrusted_tools and not (check is not None and check.blocked):
            # same content -> the graph links action -> input with a same-content edge
            ref = self.agent.observe(result, source=f"tool:{name}", trust="untrusted")
        self._results[tool_use_id] = ref
        self._known[content_hash(result)] = ref
        return ref


# --------------------------------------------------------------------------- decision replay

def replay_model(messages_api: Any) -> Callable[..., Any]:
    """A model function for decision_test that re-sends a call recorded by TracedMessages, minus the
    context items an intervention removed. A removed tool result is replaced by "[removed]" so the
    tool_use / tool_result pairing the API requires still holds; a message left empty is dropped and
    neighbouring messages from the same role are merged."""

    def fn(context: List[Any], *, purpose: str, seed: int, params: Dict[str, Any], agent: str) -> Any:
        req = (params or {}).get("request")
        if not req:
            raise ValueError("this decision was not recorded by TracedMessages; no request layout to rebuild")
        vals = {content_hash(v): v for v in context}
        kw: Dict[str, Any] = {k: params[k] for k in API_PARAMS if k in params}
        kw["model"] = req["model"]
        for k in ("system", "tools"):
            if req.get(k) in vals:
                kw[k] = vals[req[k]]
        msgs: List[Dict[str, Any]] = []
        for m in req["messages"]:
            blocks = []
            for s in m["blocks"]:
                if s["as"] == "tool_result":
                    v = vals.get(s["ref"], "[removed]")
                    blk = {"type": "tool_result", "tool_use_id": s["id"],
                           "content": v if isinstance(v, str) else json.dumps(v, default=str)}
                    if s.get("is_error"):
                        blk["is_error"] = True
                    blocks.append(blk)
                elif s["ref"] in vals:
                    blocks.append(vals[s["ref"]])
            if not blocks:
                continue
            if msgs and msgs[-1]["role"] == m["role"]:
                msgs[-1]["content"].extend(blocks)
            else:
                msgs.append({"role": m["role"], "content": blocks})
        if not msgs or msgs[0]["role"] != "user":
            msgs.insert(0, {"role": "user", "content": [{"type": "text", "text": "(content removed)"}]})
        resp = messages_api.create(messages=msgs, **kw)
        usage = _plain(getattr(resp, "usage", None)) or {}
        return ModelOutput({"content": _plain(getattr(resp, "content", [])),
                            "stop_reason": getattr(resp, "stop_reason", None)},
                           {k: usage.get(k) for k in ("input_tokens", "output_tokens") if usage.get(k) is not None})

    return fn
