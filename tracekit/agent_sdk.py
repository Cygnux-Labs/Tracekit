"""Agent-side SDK for recording custom agents in the v0.2 signed ledger.

The SDK records only calls explicitly sent through its API. It is not an OS-level
monitor; tool calls must use ``Tracer.tool`` to be policy-checked before execution.
"""
import getpass
import os
import socket
import sys
import threading
import time
import uuid

from . import client, policy, privacy
from .core import GENESIS, SCHEMA_VERSION, jsonable, new_id, now_ts


class TracekitSDKError(RuntimeError):
    pass


class _ToolCall:
    def __init__(self, tracer, name, args, tool_use_id=None):
        if not isinstance(args, dict):
            raise TypeError("tool arguments must be a mapping")
        self.tracer = tracer
        self.name = str(name)[:200]
        self.args = jsonable(args)  # sets, bytes, datetimes, NaN...: recording must never raise inside the agent
        # pass the model's own tool-call id to link this execution to the model.exchange that asked for it
        self.tool_use_id = str(tool_use_id)[:200] if tool_use_id else "tk_" + uuid.uuid4().hex[:24]
        self.result_value = None
        self.started = None

    def __enter__(self):
        self.tracer._ensure_active()
        current_policy, raw_policy = policy.load()
        decision = policy.evaluate(current_policy, self.name, self.args, self.tracer.cwd)
        policy_hash = policy.policy_hash(current_policy)
        tool_event = self.tracer._event("tool.call", {
            "tool_use_id": self.tool_use_id,
            "name": self.name,
            "input": privacy.tool_input(self.name, self.args, current_policy.get("content_capture", "hashed")),
        })
        decision_event = self.tracer._event("policy.decision", {
            "tool_use_id": self.tool_use_id,
            "decision": decision["decision"],
            "rule_ids": decision["rule_ids"],
            "reasons": decision["reasons"] + decision["flags"],
            "policy_hash": policy_hash,
            "policy_version": str(current_policy.get("version", "unversioned")),
        })
        changed = policy_hash != self.tracer._policy_hash
        try:
            self.tracer._send(tool_event)
            self.tracer._send(decision_event, {"policy": raw_policy} if changed else None)
        except client.SignerUnavailable as error:
            if current_policy.get("fail_mode", "open") == "closed":
                raise PermissionError(f"signer unavailable; fail_mode=closed blocks {self.name}: {error}") from error
        self.tracer._policy = current_policy
        self.tracer._policy_raw = raw_policy
        self.tracer._policy_hash = policy_hash

        if decision["decision"] == "deny":
            raise PermissionError("Blocked by Tracekit policy: " + "; ".join(decision["reasons"]))
        if decision["decision"] == "ask" and client.is_remote():
            raise PermissionError("Held by Tracekit policy: approvals are not available for remote ingestion, so the call is refused")
        if decision["decision"] == "ask":
            from .hook import wait_for_approval
            approved, message = wait_for_approval(tool_event, decision, current_policy)
            if not approved:
                raise PermissionError("Held by Tracekit policy and not approved: " + message)

        self.started = time.monotonic()
        return self

    def result(self, value):
        self.result_value = value

    def __exit__(self, exception_type, exception, _traceback):
        content_capture = self.tracer._policy.get("content_capture", "hashed")
        dotenv = privacy.mentions_dotenv(
            self.args.get("command"), self.args.get("file_path"), self.args.get("path"), self.args.get("pattern"))
        output = ({"error": repr(exception)} if exception_type else jsonable(self.result_value))
        event = self.tracer._event("tool.result", {
            "tool_use_id": self.tool_use_id,
            "ok": exception_type is None,
            "output": privacy.content(output, content_capture, dotenv),
            "duration_ms": int((time.monotonic() - self.started) * 1000),
        })
        try:
            self.tracer._send(event)
        except client.SignerUnavailable:
            if self.tracer._policy.get("fail_mode", "open") == "closed":
                raise
        return False


class Tracer:
    """Trace a custom agent through a configured v0.2 signer.

    ``prompt``, ``say`` and ``think`` record explicit messages. Wrap every real tool
    invocation in ``with tracer.tool(name, args)`` to get policy checks and results.
    """

    def __init__(self, agent="custom-agent", session_id=None, agent_id=None, agent_type=None,
                 cwd=None, endpoint=None, token=None, _parent=None):
        if endpoint is not None or token is not None:
            raise ValueError("v0.2 SDK uses the configured local signer; remote ingest remains a separate integration")
        self.agent = str(agent)[:200]
        self.session_id = session_id or "sess_" + uuid.uuid4().hex[:12]
        if not isinstance(self.session_id, str) or not self.session_id or len(self.session_id) > 200:
            raise ValueError("session_id must be a non-empty string of at most 200 characters")
        self.agent_id = str(agent_id or "main")[:200]
        self.parent_id = _parent.agent_id if _parent else None
        self.agent_type = str(agent_type)[:200] if agent_type else None
        self.cwd = os.path.abspath(cwd or os.getcwd())
        self._parent = _parent
        self._spawn_call = None
        self._ended = False
        self._done = False
        self._warned_signer_down = False
        self._lock = threading.RLock()
        self._policy, self._policy_raw = policy.load()
        self._policy_hash = policy.policy_hash(self._policy)
        if _parent is None:
            self._start_run()

    def _event(self, event_type, data):
        return {
            "schema_version": SCHEMA_VERSION,
            "id": new_id(),
            "seq": 0,
            "prev_hash": GENESIS,
            "ts": now_ts(),
            "run_id": self.session_id,
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "source": "sdk",
            "type": event_type,
            "data": data,
        }

    def _send(self, event, attach=None):
        with self._lock:
            try:
                response = client.send(event, attach=attach, stream="sdk")
            except client.SignerUnavailable as error:
                if self._policy.get("fail_mode", "open") == "closed":
                    raise
                if not self._warned_signer_down:
                    print(f"[tracekit-sdk] signer unavailable; events may be missing: {error}",
                          file=sys.stderr, flush=True)
                    self._warned_signer_down = True
                return None
            if not response.get("ok"):
                raise TracekitSDKError(f"signer rejected SDK event: {response.get('error', 'unknown error')}")
            return response

    def _start_run(self):
        event = self._event("run.start", {
            "agent": {"name": self.agent, "version": None},
            "model": None,
            "cwd": self.cwd,
            "host": socket.gethostname(),
            "os_user": getpass.getuser(),
            "fail_mode": self._policy.get("fail_mode", "open"),
            "policy": {"version": str(self._policy.get("version", "unversioned")), "hash": self._policy_hash},
            "capture_sources": ["sdk"],
            "sandbox": "unknown",
            "content_capture": self._policy.get("content_capture", "hashed"),
            "reasoning_capture": bool(self._policy.get("reasoning_capture", False)),
            "signer_isolation": client.client_config().get("signer_isolation", "same-user"),
        })
        try:
            self._send(event, {"policy": self._policy_raw})
        except client.SignerUnavailable:
            if self._policy.get("fail_mode", "open") == "closed":
                raise

    def _ensure_active(self):
        if self._ended or self._done:
            raise RuntimeError("this Tracekit tracer has already finished")

    def prompt(self, text):
        self._ensure_active()
        self._send(self._event("user.prompt", {
            "content": privacy.content(jsonable(text), self._policy.get("content_capture", "hashed")),
        }))

    def _message(self, kind, text):
        self._ensure_active()
        if not self._policy.get("reasoning_capture", False):
            return
        self._send(self._event("model.message", {
            "kind": kind,
            "message_id": "m_" + uuid.uuid4().hex[:16],
            "content": privacy.content(jsonable(text), self._policy.get("content_capture", "hashed")),
        }))

    def think(self, text):
        self._message("thinking", text)

    def say(self, text):
        self._message("text", text)

    def tool(self, name, args=None, tool_use_id=None):
        self._ensure_active()
        return _ToolCall(self, name, args if args is not None else {}, tool_use_id)

    def subagent(self, agent_type, description):
        self._ensure_active()
        child_id = uuid.uuid4().hex[:16]
        call = self.tool("Agent", {"description": description, "subagent_type": agent_type,
                                   "child_agent_id": child_id})
        call.__enter__()
        child = Tracer(self.agent, self.session_id, child_id, agent_type, self.cwd, _parent=self)
        child._spawn_call = call
        return child

    def done(self, final_message=""):
        if self._done:
            return
        if final_message:
            self.say(final_message)
        self._done = True
        if self._parent and self._spawn_call:
            self._spawn_call.result({"final": final_message})
            self._spawn_call.__exit__(None, None, None)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, _traceback):
        """`with Tracer(...) as t:` always records run.end, even when the agent raises."""
        try:
            self.end("error: " + repr(exception)[:400] if exception_type else "done")
        except Exception:
            if exception_type is None:
                raise
        return False

    def end(self, reason="done"):
        if self._ended:
            return
        if self._parent:
            self.done(reason)
            self._ended = True
            return
        from . import autotrace  # lazy: autotrace.init imports this module
        autotrace.flush()  # streams abandoned during the run are recorded before run.end, not as late
        self._send(self._event("run.end", {"reason": str(reason)[:500]}))
        self._ended = True