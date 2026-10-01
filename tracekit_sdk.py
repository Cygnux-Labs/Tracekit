"""Trace explicitly instrumented custom agents (LangGraph, CrewAI, Pi, or your own code).

When a v0.2 signer is configured, ``Tracer`` writes signed ``source=sdk`` events to its ledger.
Without one, a source checkout retains the legacy v0.1 behavior. This SDK does not discover
agents or observe calls that are not routed through its methods.

    from tracekit_sdk import Tracer
    t = Tracer(agent="research-bot")                 # one session per Tracer
    t.prompt("Summarise the Q3 filings")
    worker = t.subagent("fetcher", "Download filings")   # appears as a child lane
    worker.think("Need the 10-Q first")
    with worker.tool("http_get", {"url": "https://example.com/10q"}) as call:
        call.result({"status": 200, "bytes": 18234})
    worker.done("Fetched 3 filings")
    t.say("Summary: ...")
    t.end()

The legacy v0.1 observer endpoint remains available with ``endpoint=...``. Remote ingestion
into v0.2 signed ledgers is not implemented. In either mode, ``tool()`` must wrap the real call
for Tracekit to record it or enforce policy before it runs.
"""
import json
import os
import time
import urllib.request
import uuid


class _Call:
    def __init__(self, tracer, name, args):
        self.t, self.name, self.args, self.id = tracer, name, args, "call_" + uuid.uuid4().hex[:12]
        self._res, self._start = None, None

    def __enter__(self):
        from hook import evaluate_policy
        decision, reasons, flags = evaluate_policy(self.name, self.args, self.t.cwd)
        self.t._emit({"event": "PreToolUse", "tool_name": self.name, "tool_input": self.args,
                      "tool_use_id": self.id,
                      "policy": {"decision": decision, "reasons": reasons, "flags": flags}})
        if decision == "deny":
            raise PermissionError("Blocked by tracekit policy: " + "; ".join(reasons))
        self._start = time.time()
        return self

    def result(self, value):
        self._res = value

    def __exit__(self, et, ev, tb):
        failed = et is not None
        resp = {"is_error": True, "error": repr(ev)} if failed else self._res
        self.t._emit({"event": "PostToolUse", "tool_name": self.name, "tool_input": self.args,
                      "tool_use_id": self.id, "failed": failed, "tool_response": resp,
                      "duration_ms": int((time.time() - self._start) * 1000)})
        return False


class _LegacyTracer:
    def __init__(self, agent="custom-agent", session_id=None, agent_id=None, agent_type=None,
                 cwd=None, endpoint=None, token=None, _parent=None):
        self.agent, self.session_id = agent, session_id or "sess_" + uuid.uuid4().hex[:12]
        self.agent_id, self.agent_type = agent_id, agent_type
        self.cwd, self.endpoint, self.token = cwd or os.getcwd(), endpoint, token
        if _parent is None:
            self._emit({"event": "SessionStart", "source": agent})

    def _emit(self, ev):
        ev = {"session_id": self.session_id, "agent": self.agent, "cwd": self.cwd,
              "agent_id": self.agent_id, "agent_type": self.agent_type, **ev}
        if not self.endpoint:
            import common
            return common.append([ev])
        req = urllib.request.Request(self.endpoint.rstrip("/") + "/api/ingest", data=json.dumps(ev).encode(),
                                     headers={"Content-Type": "application/json",
                                              **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        urllib.request.urlopen(req, timeout=5).read()

    def _turn(self, kind, text):
        self._emit({"event": "model_turn", "message_id": "m_" + uuid.uuid4().hex[:10],
                    "blocks": [{"kind": kind, "text": text}]})

    def prompt(self, text):
        self._emit({"event": "UserPromptSubmit", "prompt": text})

    def think(self, text):
        self._turn("thinking", text)

    def say(self, text):
        self._turn("text", text)

    def tool(self, name, args=None):
        return _Call(self, name, args or {})

    def subagent(self, agent_type, description):
        """Spawn a child agent: shows as its own lane, linked to this agent."""
        child_id = uuid.uuid4().hex[:16]
        pre = _Call(self, "Agent", {"description": description, "subagent_type": agent_type})
        pre.__enter__()
        child = _LegacyTracer(self.agent, self.session_id, child_id, agent_type, self.cwd, self.endpoint, self.token, _parent=self)
        child._spawn_call = pre
        child._emit({"event": "SubagentStart"})
        return child

    def done(self, final_message=""):
        """Finish a subagent (or a turn for the main agent)."""
        if self.agent_id:
            self._emit({"event": "SubagentStop", "last_assistant_message": final_message})
            call = getattr(self, "_spawn_call", None)
            if call:
                call.result({"final": final_message})
                call.__exit__(None, None, None)
        else:
            if final_message:
                self.say(final_message)
            self._emit({"event": "Stop"})

    def end(self):
        self._emit({"event": "SessionEnd", "reason": "done"})


def _configured_v2_signer():
    try:
        from tracekit import client
        cfg = client.client_config()
        return cfg.get("mode") in ("dev", "system") and bool(cfg.get("signer_home"))
    except (ImportError, OSError, ValueError):
        return False


def _legacy_runtime_available():
    try:
        from importlib.util import find_spec
        return find_spec("common") is not None and find_spec("hook") is not None
    except (ImportError, ValueError):
        return False


class Tracer(_LegacyTracer):
    """Compatibility constructor: prefer v0.2 when configured, retain v0.1 otherwise."""

    def __new__(cls, *args, **kwargs):
        if cls is Tracer:
            endpoint = kwargs.get("endpoint") or (args[5] if len(args) > 5 else None)
            if endpoint is None and _configured_v2_signer():
                from tracekit.agent_sdk import Tracer as SignedTracer
                return SignedTracer(*args, **kwargs)
            if not _legacy_runtime_available():
                raise RuntimeError("initialize a v0.2 signer with `tracekit init --dev` before using Tracer")
        return super().__new__(cls)


LegacyTracer = _LegacyTracer
