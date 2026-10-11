"""`tracekit.instrument()`: one line wires Tracekit into the agent this process runs.

    import tracekit
    tracekit.instrument()     # first, before the agent builds its agents, tools, graphs or sessions

It registers one run with the signer (the same-user dev signer, started if none answers; in system mode the system
signer; else $TRACEKIT_SIGNER), closes it when the process exits, and wires every adapter whose framework is installed:

* OpenAI Agents SDK: the tools of every Agent built from now on are gated (TracekitAgents.tool), and a Runner call
  without a context gets `context={}`;
* LangGraph and LangChain: every ToolNode built from now on (create_agent builds one) gates its calls with
  TracekitMiddleware, innermost, after any middleware's own wrap_tool_call;
* Claude Agent SDK: every ClaudeAgentOptions built from now on gets the PreToolUse and PostToolUse hooks
  (tracekit_hooks);
* MCP client: every ClientSession.call_tool goes through TracekitSession;
* the Anthropic, OpenAI and Google Gen AI clients: every model call (tracekit.autotrace).

Idempotent: a second call returns the same run. With none of these installed it warns and returns None. A framework
whose adapter cannot be wired is skipped with a warning naming the versions Tracekit is tested with. It raises only
when no signer answers: no call could be recorded, and a run's fail mode is closed until its signer says otherwise.
Don't also wire an adapter by hand in the same process: the call would be decided twice.
"""
import atexit
import functools
import os
import sys
import threading
import warnings
import weakref
from importlib import metadata

_STATE = {"run": None}
_LOCK = threading.RLock()   # re-entered when wiring imports a module that calls instrument() itself
MODEL_SDKS = ("openai", "anthropic", "google-genai")


def _openai_agents(run):
    from agents import Agent, Runner

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

    for name in ("run", "run_sync", "run_streamed"):   # an ask keeps its approval id in a dict run context
        def with_context(cls, *a, _orig=getattr(Runner, name), **kw):
            if kw.get("context") is None:
                kw["context"] = {}
            return _orig(*a, **kw)
        setattr(Runner, name, classmethod(functools.wraps(getattr(Runner, name))(with_context)))


def _langgraph(run):
    from langgraph.prebuilt.tool_node import ToolNode

    from .integrations.langchain import TracekitMiddleware
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
        init(self, tools, *a, wrap_tool_call=wrap_tool_call, awrap_tool_call=awrap_tool_call, **kw)
    ToolNode.__init__ = gated


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
    gates, stream = weakref.WeakKeyDictionary(), {}

    @functools.wraps(call_tool)
    async def gated(self, *a, **kw):
        if self not in gates:   # every session shares one signer stream: a run allows 64 (quotas.streams_per_run)
            g = gates[self] = TracekitSession(_Unpatched(self, call_tool), run.client, run.registered)
            g.stream, g._seq, g._lock = stream.setdefault("s", (g.stream, g._seq, g._lock))
        return await gates[self].call_tool(*a, **kw)
    ClientSession.call_tool = gated


# name, distribution, tested versions [lo, hi), the pip requirement, its quickstart, wire(run)
FRAMEWORKS = (
    ("OpenAI Agents SDK", "openai-agents", (0, 23, 1), (0, 24), "openai-agents>=0.23.1,<0.24", "openai-agents",
     _openai_agents),
    ("LangGraph", "langgraph", (1, 2), (1, 3), "langchain>=1.4,<1.5 langgraph>=1.2,<1.3", "langchain", _langgraph),
    ("Claude Agent SDK", "claude-agent-sdk", (0, 2, 165), (0, 3), "claude-agent-sdk>=0.2.165,<0.3", "claude-agent-sdk",
     _claude_agent_sdk),
    ("MCP client", "mcp", (2, 3), (2, 4), "mcp>=2.3,<2.4", "mcp", _mcp),
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


def _close(run):
    from . import autotrace
    try:
        autotrace.flush()
        run.close("process exit")
    except Exception:   # exiting: nothing left to tell
        pass


def instrument(agent=None):
    """Wire Tracekit into this process (see the module docstring); the run handle, or None when nothing is installed.
    `agent` names the run (default: $TRACEKIT_AGENT, else the script's name)."""
    from . import autotrace
    from .client import SYSTEM_CONFIG
    from .sdk.client import Client, SignerUnavailable
    if agent is not None and not isinstance(agent, str):
        raise TypeError("tracekit.instrument(agent) takes the run's name. For v1 model-call tracing with a Tracer, "
                        "call tracekit.autotrace.instrument(tracer)")
    with _LOCK:
        if _STATE["run"] is not None:
            return _STATE["run"]
        found = [(f, v) for f in FRAMEWORKS if (v := _version(f[1]))]
        if not found and not any(map(_version, MODEL_SDKS)):
            warnings.warn("tracekit.instrument(): none of the frameworks or model SDKs it wires is installed (OpenAI "
                          "Agents SDK, LangGraph, Claude Agent SDK, MCP, OpenAI, Anthropic, Google Gen AI); nothing "
                          "is recorded. Record calls yourself: docs/quickstarts/custom.md", stacklevel=2)
            return None
        script = sys.argv[0] if sys.argv and sys.argv[0] not in ("", "-c") else "python"
        name = agent or os.environ.get("TRACEKIT_AGENT") or os.path.splitext(os.path.basename(script))[0]
        try:
            run = Client().run(agent=name)
        except SignerUnavailable as e:
            fix = ("dev auto-spawn is off while TRACEKIT_SIGNER is set: start the signer it names, or unset it for a "
                   "same-user dev signer" if os.environ.get("TRACEKIT_SIGNER") else
                   "system mode: start the system signer (`sudo tracekit doctor` says what is wrong)"
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
                              f"(docs/quickstarts/{page}.md)", stacklevel=2)
                continue
            if not lo <= _release(version) < hi:
                warnings.warn(f"tracekit.instrument(): {label} {version} is wired but untested; Tracekit is tested "
                              f"with {req}", stacklevel=2)
        autotrace.instrument(run)
        return run
