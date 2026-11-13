"""MCP client (python `mcp` package): every `call_tool` and `get_prompt` on a ClientSession is decided by the signer
before it is sent to the server and recorded after, and `read_resource` records what it returns as an observed input.

    from tracekit.integrations.mcp import TracekitSession
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    session = TracekitSession(session, signer, run)   # an initialized ClientSession
    result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue

The server name comes from the session's initialize result (mcp 2: the session's server_info). An mcp 1.x session
doesn't keep it: pass `server=` (instrument() takes it from the initialize() calls made after it). With no name the
calls are recorded as mcp:unknown/<tool>, with a warning. `deny` returns a CallToolResult with `isError: true` and
the refusal as its text (`get_prompt` raises `RuntimeError`), and the run goes on. `ask` requests an approval and waits
up to `approval_wait_s` for a person to decide in the signer; with `approval_wait_s=0` the call is refused instead.
Every call that is not denied is sent only after the signer's `approval_consume` agrees, with the arguments it returns
for an approval with a T2 executor. Multi-round input-required calls (MCP 2.3) with a `request_state` under an allowed
decision are decided and completed once across rounds: a round continues the call its own asyncio task left waiting (as
mcp's Client.call_tool drives them), so concurrent calls never share one, whatever `request_state` the server returns.
A waiting call whose task calls a tool or gets a prompt on the session first, or ends, is never completed: the
signer's decided_not_completed gap at run close. Rounds without `request_state`, or whose decision isn't `allow` (a
flag or an ask), are decided as calls of their own. A result with `isError: true` completes as an error; an exception from the session
propagates unchanged and completes as an error.
`read_resource`, `list_tools`, `list_resources` and `list_prompts` are recorded as untrusted observed input
(`mcp:<server>/resource`, `/tools`, `/resources`, `/prompts`; a result over half a signer frame as its digest) and
returned once recorded. A resource or list the signer cannot reach is withheld unless the run fails open for this
class, when it is returned with a warning; a refusal is withheld either way. The list mcp itself asks for inside
`call_tool` (to check a result against the tool's output schema) never reaches the model and isn't recorded. Only
those calls made through the wrapped session are seen.
"""
import asyncio
import functools
import re
import uuid
import warnings
import weakref

from mcp.types import CallToolResult, TextContent

from tracekit.autowire import DECIDED_UPSTREAM
from tracekit.format.canon import event_hash
from tracekit.integrations.held import HeldCalls
from tracekit.sdk.client import SignerUnavailable, fail_open, refusal, result_field
from tracekit.signer.rpc_schema import RPCError

BLOCKED = "Tool call blocked by policy: "
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")
_UNNAMED = ("MCP: the session doesn't name its server, so its calls are recorded as mcp:unknown/<tool>: "
            "pass TracekitSession(..., server=<name>), or call tracekit.instrument() before the "
            "session's initialize() (mcp 1.x)")


class TracekitSession(HeldCalls):
    CLASS = "mcp"

    def __init__(self, session, signer, run, approval_wait_s=300, server=None):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`, `fail_modes`);
        `server`: the server's name, else the session's server_info."""
        super().__init__(signer, run, approval_wait_s)
        self._session, self._server = session, server
        # the asyncio task -> the multi-round call it left waiting for its next round
        self._pending = weakref.WeakKeyDictionary()

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def call_tool(self, name, arguments=None, *a, **kw):
        return await self._call("call_tool", "", name, arguments, *a, **kw)

    async def get_prompt(self, name, arguments=None, *a, **kw):
        return await self._call("get_prompt", "prompt:", name, arguments, *a, **kw)

    async def read_resource(self, uri, *a, **kw):
        return await self._observed("read_resource", "resource", uri, *a, **kw)

    async def list_tools(self, *a, **kw):
        return await self._observed("list_tools", "tools", *a, **kw)

    async def list_resources(self, *a, **kw):
        return await self._observed("list_resources", "resources", *a, **kw)

    async def list_prompts(self, *a, **kw):
        return await self._observed("list_prompts", "prompts", *a, **kw)

    def _server_name(self):
        """(the name the session gave, or None; the `mcp:<name>` component, `unknown` when it gave none)."""
        raw = self._server or getattr(getattr(self._session, "server_info", None), "name", None)
        return raw, _UNSAFE.sub("_", raw or "") or "unknown"

    async def _observed(self, method, kind, *a, **kw):
        """What the session's `method` returned (a resource, a list's page), once recorded as untrusted input the model
        reads (`mcp:<server>/<kind>`). An unreachable signer returns it only when the run fails open for this class; a
        refusal is withheld either way."""
        out = await getattr(self._session, method)(*a, **kw)
        raw, server = self._server_name()
        if not raw:
            warnings.warn(_UNNAMED, stacklevel=4)   # list_* -> _observed -> warn: the caller's line, as _call's warning
        try:
            await self._rpc("observe", source=f"mcp:{server}/{kind}", trust="untrusted",
                            value=result_field(True, out.model_dump(mode="json", by_alias=True, exclude_none=True)))
        except SignerUnavailable as e:   # unreachable: the run's fail mode for this class, as _gate
            if not fail_open(self.fail_modes, self.CLASS):
                raise
            warnings.warn(f"tracekit: MCP {kind} not recorded: {e}", stacklevel=2)
        return out

    async def _send(self, method, *a, **kw):
        """The session's `method`. mcp's call_tool lists the tools itself to check a result against the tool's output
        schema: that list never reaches the model, so instrument()'s session lets it through unrecorded."""
        upstream = DECIDED_UPSTREAM.set(True)
        try:
            return await getattr(self._session, method)(*a, **kw)
        finally:
            DECIDED_UPSTREAM.reset(upstream)

    async def _call(self, method, prefix, name, arguments, *a, **kw):
        raw, server = self._server_name()
        if not raw:
            warnings.warn(_UNNAMED, stacklevel=3)
        tool = f"mcp:{server}/{prefix}{name}"
        args = arguments or {}
        caller_args_digest = event_hash({"tool": tool, "args": args})
        task = asyncio.current_task()
        # a call this task left waiting and doesn't continue now is never completed: its caller may have seen an
        # exception (mcp's elicitation callback, its round cap), so it ends as the signer's decided_not_completed gap
        held = self._pending.pop(task, None)
        if held is not None and held[0] == (tool, caller_args_digest, kw.get("request_state")):
            _, call_id, req, d, args = held
            try:
                c = await self._rpc("approval_consume", tool_call_id=call_id, tool=tool, args_source="parsed", args=args)
            except (RPCError, SignerUnavailable) as e:
                c = {"ok": False, "rule_ids": [], "reason": str(e)}
            if not c["ok"]:
                why = refusal(c) or "refused"
                await self._complete(call_id, req, status="error", error=why[:4096])
                if method == "get_prompt":
                    raise RuntimeError(BLOCKED + why)
                return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], isError=True)
            args = c.get("args", args)
            req["args_digest"] = event_hash({"tool": tool, "args": args})
        else:
            call_id = uuid.uuid4().hex
            why, d, args = await self._gate(call_id, tool, args)
            if why is not None:
                if method == "get_prompt":
                    raise RuntimeError(BLOCKED + why)
                # isError: mcp 1.x's field name, and mcp 2.x's alias of is_error (1.x ignores is_error=)
                return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], isError=True)
            req = None if d is None else {"tool_call_id": call_id, "decision_id": d["decision_id"],
                                          "args_digest": event_hash({"tool": tool, "args": args})}
        send = functools.partial(self._send, method)
        if d is None:   # the signer unreachable and the run fails open: the call runs unrecorded
            return await send(name, arguments, *a, **kw)
        try:
            out = await send(name, args, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        if getattr(out, "result_type", None) == "input_required":
            dump = out.model_dump(mode="json", by_alias=True, exclude_none=True)
            input_requests = dump.get("inputRequests", [])
            if input_requests:
                try:
                    await self._rpc("observe", source=f"mcp:{server}/input_required", trust="untrusted",
                                    value=result_field(True, input_requests))
                except SignerUnavailable as e:
                    if not fail_open(self.fail_modes, self.CLASS):
                        await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
                        raise
                    warnings.warn(f"tracekit: MCP input_required not recorded: {e}", stacklevel=2)
                except Exception as e:
                    await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
                    raise
            next_state = getattr(out, "request_state", None)
            if next_state is not None and d.get("decision") == "allow":
                self._pending[task] = ((tool, caller_args_digest, next_state), call_id, req, d, args)
            else:
                await self._complete(call_id, req, status="ok",
                                     result=result_field(d.get("send_result"), dump))
            return out
        failed = getattr(out, "is_error", getattr(out, "isError", False))   # mcp 2.x, mcp 1.x
        await self._complete(call_id, req, status="error" if failed else "ok",
                             result=result_field(d.get("send_result"),
                                                 out.model_dump(mode="json", by_alias=True, exclude_none=True)))
        return out
