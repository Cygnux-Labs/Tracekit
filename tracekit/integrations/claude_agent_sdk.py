"""Claude Agent SDK (Python): every tool call is decided by the signer before it runs and recorded after.

    from claude_agent_sdk import ClaudeAgentOptions, query
    from tracekit.integrations.claude_agent_sdk import TracekitSessionStore, tracekit_hooks
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    options = ClaudeAgentOptions(hooks=tracekit_hooks(signer, run),
                                 session_store=TracekitSessionStore(my_store, signer, run))   # the store is optional

The gate is the PreToolUse hook, not `can_use_tool`: the CLI skips `can_use_tool` for every call its permission mode or
allow rules approve, while PreToolUse runs for every call. `deny` blocks the call with the reason, which the model
gets as the tool's error result, and the session goes on. `ask` holds the call in the hook until a person decides in
the signer, for at most APPROVAL_WAIT_S, below the hook's own timeout (HOOK_TIMEOUT_S, set on the matcher); a call not
approved by then is blocked. Every call that is not denied runs only after the signer's `approval_consume` agrees.
PostToolUse and PostToolUseFailure complete the call against its decision; SessionEnd closes the run.
"""
import itertools
import threading
import time
import uuid
import warnings

import anyio
from claude_agent_sdk import HookMatcher

from tracekit.format.canon import event_hash
from tracekit.signer import rpc_schema
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer.rpc_schema import RPCError

BLOCKED = "Tool call blocked by policy: "
HOOK_TIMEOUT_S = 600     # the SDK's default (60 s) is too short to wait for a person
APPROVAL_WAIT_S = 540    # below HOOK_TIMEOUT_S, so the hook answers before the CLI gives up on it


class _Run:
    """Signer calls for one run, with request ids and one stream whose client_seq values go out in order."""

    def __init__(self, signer, run):
        self.signer, self.ids = signer, {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._lock = "claude-agent-sdk-" + uuid.uuid4().hex, itertools.count(), threading.Lock()

    async def __call__(self, method, **req):
        props = rpc_schema.REQUESTS[method]["properties"]
        req.update(self.ids, **({"request_id": uuid.uuid4().hex} if "request_id" in props else {}))

        def call():
            if "client_seq" not in props:   # approval_wait among them: it must not hold up the events
                return getattr(self.signer, method)(req)
            # lean: one event call at a time per run, so client_seq arrives in order; pipeline if it gets slow
            with self._lock:
                req.update(stream=self.stream, client_seq=next(self._seq))
                return getattr(self.signer, method)(req)
        return await anyio.to_thread.run_sync(call)


def _deny(why):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": BLOCKED + why}}


def tracekit_hooks(signer, run):
    """The `hooks=` mapping for ClaudeAgentOptions. `signer` is a tracekit Client or any `SignerAPI`; `run` is its
    `register_run` response (`run_id`, `run_token`). To add hooks of your own, extend the lists."""
    rpc, calls = _Run(signer, run), {}   # calls: tool_use_id -> (decision_id, args_digest), from Pre to PostToolUse

    async def pre(inp, tool_use_id, ctx):
        tid, tool, args = inp.get("tool_use_id") or tool_use_id, inp.get("tool_name") or "?", inp.get("tool_input")
        if not tid:   # never defaulted: a result could not be bound to its decision
            return _deny("the hook got no tool_use_id")
        try:
            d = await rpc("decide", tool_call_id=tid, tool=tool, args_source="parsed", args=args)
            if d["decision"] == "deny":
                return _deny(", ".join(d["rule_ids"]) or "deny")
            aid = None
            if d["decision"] == "ask":
                aid = (await rpc("approval_request", tool_call_id=tid))["approval_id"]
                state, deadline = "requested", time.monotonic() + APPROVAL_WAIT_S
                while state == "requested" and deadline > time.monotonic():
                    left_ms = int(min(deadline - time.monotonic(), 300) * 1000)
                    state = (await rpc("approval_wait", approval_id=aid, timeout_ms=left_ms))["state"]
                if state != "approved":
                    return _deny(f"{', '.join(d['rule_ids'])} not approved: {state}")
            # every call, allowed or approved: nothing the SDK holds vouches that no approval is needed
            c = await rpc("approval_consume", tool_call_id=tid, tool=tool, args_source="parsed", args=args,
                          **({"approval_id_hint": aid} if aid else {}))
            if not c["ok"]:
                return _deny(", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else ""))
        except Exception as e:
            # lean: always fail closed; honour register_run's fail_modes per tool class if an app needs fail-open
            return _deny(f"signer error ({type(e).__name__}: {e})")
        calls[tid] = d["decision_id"], event_hash({"tool": tool, "args": args})
        return {}

    async def post(inp, tool_use_id, ctx):
        call = calls.pop(inp.get("tool_use_id") or tool_use_id, None)
        if call is None:   # not let through by `pre`: nothing to bind the result to
            return {}
        resp = inp.get("tool_response")
        if inp["hook_event_name"] == "PostToolUseFailure":
            out = {"status": "error", "error": str(inp.get("error") or "")[:4096]}
        else:
            failed = isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted"))
            out = {"status": "error" if failed else "ok", "result": event_hash(resp)}   # a commitment, not the result
        await rpc("complete", tool_call_id=inp.get("tool_use_id") or tool_use_id, decision_id=call[0],
                  args_digest=call[1], **out)
        return {}

    async def end(inp, tool_use_id, ctx):
        try:
            await rpc("close_run", reason=str(inp.get("reason") or "session end")[:256])
        except RPCError as e:
            if e.code != "run_closed":   # closed already (idle)
                raise
        return {}

    return {"PreToolUse": [HookMatcher(hooks=[pre], timeout=HOOK_TIMEOUT_S)],
            "PostToolUse": [HookMatcher(hooks=[post])], "PostToolUseFailure": [HookMatcher(hooks=[post])],
            "SessionEnd": [HookMatcher(hooks=[end])]}


def _chain(entries, digest=event_hash([])):
    """The digest of a transcript after `entries`, from its digest before them (default: empty). Canonical JSON per
    entry, as a store may give entries back with their keys reordered."""
    for e in entries:
        digest = event_hash([digest, e])
    return digest


class TracekitSessionStore:
    """A SessionStore that commits each saved transcript to the signer (L1): after every append a `state_write` of
    the transcript's digest, from the digest it had when this process last saw it. A transcript changed in the store
    between two writes (seen on `load`, when a session resumes) makes the signer record a `state_tamper` gap."""

    def __init__(self, store, signer, run):
        self._store, self._rpc = store, _Run(signer, run)
        # lean: one digest per transcript for the store's life; prune at session end if one process serves many
        self._digests = {}   # what the store holds now
        self._acked = {}     # what the signer last recorded: the next state_write's prev_digest

    def __getattr__(self, name):   # list_sessions, delete, ...: the wrapped store's
        return getattr(self._store, name)

    @staticmethod
    def _key(key):
        return "claude-agent-sdk:" + key["session_id"] + ("/" + key["subpath"] if key.get("subpath") else "")

    async def load(self, key):
        entries = await self._store.load(key)
        k = self._key(key)
        self._digests[k] = self._acked[k] = _chain(entries or [])
        return entries

    async def append(self, key, entries):
        k = self._key(key)
        if k not in self._digests:   # the first write this process makes to it: from what the store holds
            await self.load(key)
        await self._store.append(key, entries)
        digest = self._digests[k] = _chain(entries, self._digests[k])
        try:
            await self._rpc("state_write", key=k, value_digest=digest, prev_digest=self._acked[k])
        except (RPCError, SignerUnavailable) as e:
            # the store has the entries: raising would make the SDK append them again. The next state_write chains
            # from the last digest the signer recorded, so a lost write never reads as tampering.
            warnings.warn(f"tracekit: transcript commitment for {k} not recorded: {e}", stacklevel=2)
            return
        self._acked[k] = digest
