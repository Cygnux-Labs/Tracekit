"""`tracekit.instrument()`: one line wires Tracekit into the agent this process runs.

    import tracekit
    tracekit.instrument()     # first, before the agent builds its agents, tools, graphs or sessions

It registers one run with the signer (the same-user dev signer, started if none answers; in system mode the system
signer; else $TRACEKIT_SIGNER), closes it when the process exits, and wires every adapter whose framework is installed:

* OpenAI Agents SDK: the tools of every Agent built from now on are gated (TracekitAgents.tool);
* LangGraph and LangChain: every ToolNode built from now on (create_agent builds one) gates its calls with
  TracekitMiddleware, innermost, after any middleware's own wrap_tool_call; its `ask` pauses whatever the node's
  `handle_tool_errors`, and through `.with_fallbacks()`;
* Claude Agent SDK: every ClaudeAgentOptions built from now on gets the PreToolUse and PostToolUse hooks
  (tracekit_hooks);
* MCP client: every ClientSession.call_tool goes through TracekitSession;
* Browser Use: the actions of every Tools built from now on (an Agent builds one) are gated (trace_tools);
* CrewAI: global tool hooks decide every tool call and block by return value (tracekit.integrations.crewai);
* Pydantic AI: every Agent built from now on gets the Tracekit capability (tracekit.integrations.pydantic_ai), unless
  it was given one;
* the Anthropic, OpenAI and Google Gen AI clients: every model call (tracekit.autotrace).

Idempotent: a second call returns the same run. Calls addressed to its run go to the current run while one is
open (`with run.client.run(...)`, a run per request), and a run the signer closed is replaced on the next call. With
none of these installed it warns and returns None. A framework
whose adapter cannot be wired is skipped with a warning naming the versions Tracekit is tested with. It raises only
when no signer answers: no call could be recorded, and a run's fail mode is closed until its signer says otherwise.
Don't also wire an adapter by hand in the same process: the call would be decided twice.
"""
import atexit
import collections
import contextvars
import functools
import logging
import os
import sys
import threading
import types
import warnings
import weakref
from importlib import metadata

from .wiki import wiki_url

_STATE = {"run": None}
# True while an adapter that already decided a call runs it (the Pydantic AI capability around an MCP toolset's call):
# the MCP session wired below then doesn't decide that call a second time
DECIDED_UPSTREAM = contextvars.ContextVar("tracekit_decided_upstream", default=False)


NEW_WORK = {"decide", "model_event", "observe", "state_write", "approval_list"}   # go to the current run
BY_CALL = {"complete", "approval_request", "approval_consume"}   # go where their call was decided
BY_APPROVAL = {"approval_wait", "approval_abandon"}   # go where their approval was opened
KEEP = 65536   # lean: tool calls, approvals, exchanges and resent events remembered; raise it for very busy servers


def _process_client(Client, RPCError, current_run, schemas):
    class Process(Client):
        """The client every adapter instrument() wires gets. New work addressed to the process run (decide,
        model_event, observe, state_write, approval_list) goes to the current run while one is set (a run per
        conversation: `with conversation.current()`), and to a newly registered process run once the signer has
        closed it after it was idle. A call's complete and approvals, and a model exchange's response, go to the run
        the call was decided or the exchange begun in; anything else goes where it is addressed. Events are numbered
        per run, the same number for a resend, so no run sees a gap the adapter's own counter would leave."""
        process, agent, ids = None, None, set()   # the process RunHandle, its name, every id it has had

        def start(self, agent):
            """Register the process run."""
            # OrderedDicts: dropping the oldest of a full dict stays O(1) (a dict's leading deleted slots don't)
            self._calls, self._approvals, self._exchanges, self._numbers, self._next = (
                collections.OrderedDict() for _ in range(5))
            self._made = 0
            self.process, self.agent = self.run(agent=agent), agent
            self.ids = {self.process.run_id}
            return self.process

        def _current(self):
            cur = current_run.get()
            return cur if cur is not None and cur.run_id not in self.ids else self.process

        def call(self, method, req=None, **fields):
            req, p = {**(req or {}), **fields}, self.process
            if method == "close_run":   # the adapters' streams it renumbered end where it numbered them
                with _LOCK:
                    ends = [{"stream": name, "client_seq": n - 1} for (rid, _), (name, n) in getattr(self, "_next", {}).items()
                            if rid == req.get("run_id") and n > 0]
                if ends:
                    req["last_client_seq"] = [*req.get("last_client_seq", ()), *ends][:64]
            if p is None or req.get("run_id") not in self.ids:
                return super().call(method, req)
            cur = self._current()
            with _LOCK:
                if method in BY_CALL:
                    target = (self._calls.get((cur.run_id, req.get("tool_call_id")))
                              or self._calls.get(req.get("tool_call_id")) or cur)
                elif method in BY_APPROVAL:
                    target = self._approvals.get(req.get("approval_id")) or cur
                elif method == "model_event" and req.get("phase") == "response":
                    target = self._exchanges.get(req.get("exchange_id")) or cur
                elif method in NEW_WORK or "client_seq" in req:   # an event: numbered by this client, as every other
                    target = cur
                else:
                    target = None
            if target is None:
                return super().call(method, req)
            addressed = target.run_id
            try:
                out, sent = self._route(method, req, target)
            except RPCError as e:
                if e.code != "run_closed" or target is not p or method not in NEW_WORK or p.closed:
                    raise
                self._renew(e, addressed)
                out, sent = self._route(method, req, p)
            with _LOCK:
                if method == "decide":
                    _keep(self._calls, (cur.run_id, req["tool_call_id"]), sent)
                    _keep(self._calls, req["tool_call_id"], sent)
                elif method == "approval_request" and "approval_id" in out:
                    _keep(self._approvals, out["approval_id"], sent)
                elif method == "model_event" and req.get("phase") == "request" and req.get("exchange_id"):
                    _keep(self._exchanges, req["exchange_id"], sent)
            return out

        def _route(self, method, req, target):
            """(the answer, the run it went to): `target` is a RunHandle or such a run."""
            with _LOCK:   # a renewal swaps the id and the token together
                sent = types.SimpleNamespace(run_id=target.run_id, run_token=target.run_token, client=target.client)
                req = {**req, "run_id": sent.run_id}
                if "run_token" in schemas[method]["properties"]:
                    req["run_token"] = sent.run_token
                if "client_seq" in req:
                    key = (sent.run_id, req["stream"], req["client_seq"])
                    if key not in self._numbers:
                        if (sent.run_id, req["stream"]) not in self._next:
                            self._made += 1   # a new stream name: a forgotten one is never numbered from 0 again
                            _keep(self._next, (sent.run_id, req["stream"]), [f"{req['stream'][:100]}.{self._made}", 0])
                        stream = self._next[(sent.run_id, req["stream"])]
                        _keep(self._numbers, key, (stream[0], stream[1]))
                        stream[1] += 1
                    req["stream"], req["client_seq"] = self._numbers[key]
            send = super().call if sent.client is self else sent.client.call
            return send(method, req), sent

        def _renew(self, e, closed):
            p = self.process
            with _LOCK:
                old, token = p.run_id, p.run_token
                if closed != old:
                    return   # another thread's call renewed it already
                agent = {"agent": {"name": self.agent}}
                try:   # linked to the closed run while it is still closing
                    new = super().call("register_run", {**agent, "parent": {"run_id": old, "run_token": token}})
                except RPCError:
                    new = super().call("register_run", agent)
                p.registered, p.run_id, p.run_token = new, new["run_id"], new["run_token"]
                self.ids.add(p.run_id)
            logging.getLogger("tracekit").warning(
                "tracekit: the signer closed run %s (%s); recording in a new run %s. A server should open a run per "
                "conversation: " + wiki_url("docs/quickstart-v2.md"), old, e.message, p.run_id)
    return Process


def _keep(d, k, v):
    """Under _LOCK."""
    d[k] = v
    if len(d) > KEEP:
        d.popitem(last=False)


_LOCK = threading.RLock()   # re-entered when wiring imports a module that calls instrument() itself
MODEL_SDKS = ("openai", "anthropic", "google-genai")


def _openai_agents(run):
    from agents import Agent

    from .integrations.openai_agents import TracekitAgents
    tk = TracekitAgents(run.client, run.registered)

    def gate(t):
        if getattr(t, "_tracekit", False):   # Agent.clone builds the agent again from its gated tools
            return t
        try:
            t = tk.tool(t)
        except TypeError:   # a hosted tool: recorded only in the signed model responses
            return t
        t._tracekit = True
        return t

    post_init = Agent.__post_init__

    @functools.wraps(post_init)
    def gated(self):
        post_init(self)
        self.tools = [gate(t) for t in self.tools]
    Agent.__post_init__ = gated


def _langgraph(run):
    from langgraph.prebuilt.tool_node import ToolNode

    from .integrations.langchain import TracekitMiddleware, pausing, with_fallbacks
    gate = TracekitMiddleware(run.client, run.run_id, run.run_token, run.registered.get("fail_modes"))
    init = ToolNode.__init__

    @functools.wraps(init)
    def gated(self, tools, *a, wrap_tool_call=None, awrap_tool_call=None, **kw):
        w, aw = wrap_tool_call, awrap_tool_call
        if not isinstance(getattr(w, "__self__", None), TracekitMiddleware):   # tracekit_tool_node gates already
            wrap_tool_call = gate.wrap_tool_call if w is None else (
                lambda req, h: w(req, lambda r: gate.wrap_tool_call(r, h)))
            # no async wrapper of its own: ToolNode runs the sync one, gate included, for async calls too
            awrap_tool_call = (gate.awrap_tool_call if w is None else None) if aw is None else (
                lambda req, h: aw(req, lambda r: gate.awrap_tool_call(r, h)))
            if "handle_tool_errors" in kw:   # an ask pauses whatever the node's error handling
                kw["handle_tool_errors"] = pausing(kw["handle_tool_errors"])
        init(self, tools, *a, wrap_tool_call=wrap_tool_call, awrap_tool_call=awrap_tool_call, **kw)
    ToolNode.__init__ = gated
    ToolNode.with_fallbacks = with_fallbacks   # and through the fallbacks the node is wrapped in


def _claude_agent_sdk(run):
    from claude_agent_sdk import ClaudeAgentOptions

    from .integrations.claude_agent_sdk import tracekit_hooks
    ours = tracekit_hooks(run.client, run.registered)
    del ours["SessionEnd"]   # the run is the process's: closed at exit, not when its first session ends
    init = ClaudeAgentOptions.__init__

    @functools.wraps(init)
    def hooked(self, *a, **kw):
        init(self, *a, **kw)
        hooks = dict(self.hooks or {})
        for event, matchers in ours.items():   # dataclasses.replace builds options again from hooked ones
            hooks[event] = [*hooks.get(event, []), *(m for m in matchers if m not in hooks.get(event, []))]
        self.hooks = hooks
    ClaudeAgentOptions.__init__ = hooked


class _Unpatched:
    """A ClientSession as TracekitSession sees it: its call_tool is the one instrument() replaced."""

    def __init__(self, session, call_tool):
        self._session, self._call_tool = session, call_tool

    def __getattr__(self, name):
        return getattr(self._session, name)

    def call_tool(self, *a, **kw):
        return self._call_tool(self._session, *a, **kw)


def _mcp(run):
    from mcp import ClientSession

    from .integrations.mcp import TracekitSession
    call_tool = ClientSession.call_tool
    gates, stream, servers = weakref.WeakKeyDictionary(), {}, weakref.WeakKeyDictionary()

    @functools.wraps(call_tool)
    async def gated(self, *a, **kw):
        if DECIDED_UPSTREAM.get():
            return await call_tool(self, *a, **kw)
        if self not in gates:   # every session shares one signer stream: a run allows 64 (quotas.streams_per_run)
            # the gate holds its session weakly: a strong one would keep every session (the dict's key) alive
            g = gates[self] = TracekitSession(_Unpatched(weakref.proxy(self), call_tool), run.client, run.registered,
                                              server=servers.get(self))
            g.stream, g._seq, g._lock = stream.setdefault("s", (g.stream, g._seq, g._lock))
        return await gates[self].call_tool(*a, **kw)
    ClientSession.call_tool = gated
    if hasattr(ClientSession, "server_info"):
        return
    initialize = ClientSession.initialize   # mcp 1.x: only initialize()'s result names the server

    @functools.wraps(initialize)
    async def named(self, *a, **kw):
        out = await initialize(self, *a, **kw)
        servers[self] = out.serverInfo.name
        return out
    ClientSession.initialize = named


def _browser_use(run):
    from browser_use import Tools

    from .integrations import browser_use
    init = Tools.__init__
    # every Tools shares one signer stream: a run allows 64 (quotas.streams_per_run)
    actions = browser_use._actions(run.client, run.registered)

    @functools.wraps(init)
    def gated(self, *a, **kw):
        init(self, *a, **kw)
        browser_use._wrap(self, actions)
    Tools.__init__ = gated


def _pydantic_ai(run):
    from pydantic_ai import Agent

    from .integrations.pydantic_ai import Tracekit
    init = Agent.__init__

    @functools.wraps(init)
    def wired(self, *a, capabilities=None, **kw):
        if not any(isinstance(c, Tracekit) for c in capabilities or ()):   # one given by hand decides alone
            capabilities = [*(capabilities or ()), Tracekit(run)]
        init(self, *a, capabilities=capabilities, **kw)
    Agent.__init__ = wired


def _crewai(run):
    from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook

    from .integrations.crewai import hooks
    before, after = hooks(run)
    register_before_tool_call_hook(before)
    register_after_tool_call_hook(after)


# name, distribution, tested versions [lo, hi), the pip requirement, its page under docs/, wire(run)
FRAMEWORKS = (
    ("OpenAI Agents SDK", "openai-agents", (0, 23, 1), (0, 24), "openai-agents>=0.23.1,<0.24",
     "quickstarts/openai-agents", _openai_agents),
    ("LangGraph", "langgraph", (1, 2), (1, 3), "langchain>=1.4,<1.5 langgraph>=1.2,<1.3", "quickstarts/langchain",
     _langgraph),
    ("Claude Agent SDK", "claude-agent-sdk", (0, 2, 165), (0, 3), "claude-agent-sdk>=0.2.165,<0.3",
     "quickstarts/claude-agent-sdk", _claude_agent_sdk),
    ("MCP client", "mcp", (2, 3), (2, 4), "mcp>=2.3,<2.4", "quickstarts/mcp", _mcp),
    ("Browser Use", "browser-use", (0, 13, 11), (0, 14), "browser-use>=0.13.11,<0.14", "integrations/browser-use",
     _browser_use),
    ("CrewAI", "crewai", (1, 15, 27), (1, 16), "crewai>=1.15.27,<1.16", "integrations/crewai", _crewai),
    ("Pydantic AI", "pydantic-ai-slim", (2, 57), (2, 58), "pydantic-ai-slim>=2.57,<2.58", "integrations/pydantic-ai",
     _pydantic_ai),
)


def _version(dist):
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def _release(version):
    """(major, minor, ...) of a version string, up to its first part that is not a number."""
    out = []
    for part in version.split("."):
        num = part[:len(part) - len(part.lstrip("0123456789"))]
        if num:
            out.append(int(num))
        if num != part:
            break
    return tuple(out)


def _untested_warning(label, version, req):
    """The warning a framework outside the version Tracekit is tested with gets. The wording is shared, so the
    integrations built by hand and instrument() say the same thing about the same fact."""
    return f"{label} {version} is wired but untested; Tracekit is tested with {req}"


def _close(run):
    """Close the run at exit, unless approvals of it are still waiting (requested, or approved and not yet consumed):
    then it stays open for another process to resume (a durable checkpointer) until the signer's idle timeout."""
    from . import autotrace
    try:
        autotrace.flush()
        try:
            waiting = any(run.call("approval_list", state=state, limit=1)["approvals"] for state in ("requested",
                                                                                                    "approved"))
        except Exception:   # a listing that fails (no grant) waits for nothing
            waiting = False
        if waiting:
            logging.getLogger("tracekit").warning("tracekit: run %s left open: approvals of it are waiting for a "
                                                  "person or to be resumed", run.run_id)
        else:
            run.close("process exit")
    except Exception:   # exiting: nothing left to tell
        pass


def instrument(agent=None):
    """Wire Tracekit into this process (see the module docstring); the run handle, or None when nothing is installed.
    `agent` names the run (default: $TRACEKIT_AGENT, else the script's name)."""
    from . import autotrace
    from .client import SYSTEM_CONFIG
    from .sdk.client import Client, SignerUnavailable, current_run
    from .signer.rpc_schema import REQUESTS, RPCError
    if agent is not None and not isinstance(agent, str):
        raise TypeError("tracekit.instrument(agent) takes the run's name. For v1 model-call tracing with a Tracer, "
                        "call tracekit.autotrace.instrument(tracer)")
    with _LOCK:
        if _STATE["run"] is not None:
            return _STATE["run"]
        found = [(f, v) for f in FRAMEWORKS if (v := _version(f[1]))]
        if not found and not any(map(_version, MODEL_SDKS)):
            warnings.warn("tracekit.instrument(): none of the frameworks or model SDKs it wires is installed (OpenAI "
                          "Agents SDK, LangGraph, Claude Agent SDK, MCP, Browser Use, CrewAI, Pydantic AI, OpenAI, Anthropic, "
                          "Google Gen AI); nothing is recorded. Record calls yourself: "
                          + wiki_url("docs/quickstarts/custom.md"), stacklevel=2)
            return None
        script = sys.argv[0] if sys.argv and sys.argv[0] not in ("", "-c") else "python"
        name = agent or os.environ.get("TRACEKIT_AGENT") or os.path.splitext(os.path.basename(script))[0]
        try:
            run = _process_client(Client, RPCError, current_run, REQUESTS)().start(name)
        except SignerUnavailable as e:
            fix = ("dev auto-spawn is off while TRACEKIT_SIGNER is set: start the signer it names, or unset it for a "
                   "same-user dev signer" if os.environ.get("TRACEKIT_SIGNER") else
                   "system mode: start the system signer (`sudo /opt/tracekit/bin/python -I -m tracekit doctor` says "
                   "what is wrong)"
                   if os.path.exists(SYSTEM_CONFIG) else "`tracekit doctor` says what is wrong")
            raise SignerUnavailable(f"tracekit.instrument(): {e}; {fix}") from None
        atexit.register(_close, run)
        _STATE["run"] = run   # before wiring: an instrument() called while a framework is imported gets this run
        for (label, dist, lo, hi, req, page, wire), version in found:
            try:
                wire(run)
            except Exception as e:
                warnings.warn(f"tracekit.instrument(): {label} {version} not wired ({type(e).__name__}: {e}). "
                              f"Tracekit is tested with {req}: install those, or wire it by hand "
                              f"({wiki_url(f'docs/{page}.md')})", stacklevel=2)
                continue
            if not lo <= _release(version) < hi:
                warnings.warn(f"tracekit.instrument(): {_untested_warning(label, version, req)}", stacklevel=2)
        autotrace.instrument(run)
        return run
