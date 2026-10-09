"""Claude Code hook on the v2 signer RPC: a thin client. The signer decides with its policy packs, signs and stores;
this process holds no key, evaluates no policy and writes no ledger.

    python -I -m tracekit.integrations.claude_code   (wired by `tracekit init --dev --v2`, or as root by
                                                      `tracekit init --v2 --user AGENT`: system mode)

Each hook is a new process, so the run (id and token) of a Claude Code session and the decision binding of a tool
call are kept in the runtime dir between hooks. Exit 0 lets the call proceed, exit 2 blocks it (reason on stderr).
The signer unreachable or any other failure: the fail mode configured for the v1 hook (`tracekit.hook.fail_closed`;
closed in system mode).

System mode: the signer runs as its own user and the hook reaches it only through the socket the root-owned
/etc/tracekit/client.json names (a TRACEKIT_SIGNER naming another is refused). The run token stays in the agent's own
0700 runtime dir, and the signer accepts it only from the uid that registered the run: another local user can neither
read it nor use it. The agent never holds the signing keys, assigns sequence numbers, chooses the policy (the signer
decides), or answers its own approvals (signer.yaml names a different approver uid). Its own uid can still use its run
token, from any process it runs.
"""
import glob
import hashlib
import json
import os
import sys
import time

from tracekit import privacy
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.locking import lock_file
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle
from tracekit.signer.rpc_schema import RPCError

AGENT = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
APPROVAL_WAIT_S = 540   # below the PreToolUse hook timeout (install.HOOK_TIMEOUT)


def _state(*ids):
    """State file in the runtime dir (0700, ours) for a session, or for one tool call of it."""
    names = [hashlib.sha256(i.encode("utf-8", "surrogatepass")).hexdigest() for i in ids]
    return os.path.join(autospawn.runtime_dir(), "claude-code-" + ".".join(names) + ".json")


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _run(client, sid, register=True, stale=None):
    """The session's run, registered on its first event (or again when `stale` is the stored, closed one)."""
    path = _state(sid)
    with open(path[:-len(".json")] + ".lock", "a") as lk:   # parallel tool calls must not register two runs
        lock_file(lk)
        st = _load(path)
        if register and (st is None or st == stale):
            version = os.environ.get("CLAUDE_CODE_VERSION")
            out = client.register_run({"agent": {"name": AGENT, **({"version": version[:64]} if version else {})}})
            # lean: any process of the agent's uid can read and use this token (another uid cannot); binding runs to
            # the harness's processes (a root-owned harness helper) narrows that
            st ={"run_id": out["run_id"], "run_token": out["run_token"]}
            files.write_json(path, st)
    return st and RunHandle(client, st)


def _pre(client, p, sid, tid):
    tool, args = p.get("tool_name") or "?", p.get("tool_input")
    run = _run(client, sid)
    try:
        d = run.call("decide", tool_call_id=tid, tool=tool, args=args, args_source="parsed")
    except RPCError as e:
        if e.code not in ("run_closed", "unknown_run"):
            raise
        run = _run(client, sid, stale=run.registered)   # the signer closed the run (idle): continue in a new one
        d = run.call("decide", tool_call_id=tid, tool=tool, args=args, args_source="parsed")
    if d["decision"] == "ask":
        aid = run.call("approval_request", tool_call_id=tid)["approval_id"]
        print(f"[tracekit] waiting for approval {aid} ({'; '.join(d['rule_ids'])})", file=sys.stderr, flush=True)
        state, deadline = "requested", time.monotonic() + APPROVAL_WAIT_S
        while state == "requested" and deadline > time.monotonic():
            left_ms = int(min(deadline - time.monotonic(), 300) * 1000)
            state = run.call("approval_wait", approval_id=aid, timeout_ms=left_ms)["state"]
        if state != "approved":
            print(f"Held by tracekit policy ({'; '.join(d['rule_ids'])}) and not approved: {state}", file=sys.stderr)
            return 2
        c = run.approval_consume(tid, tool, args, approval_id_hint=aid)   # once, and only for the approved args
        if not c["ok"]:
            print(f"Held by tracekit policy: {'; '.join(c['rule_ids'])} {c.get('reason', '')}".rstrip(), file=sys.stderr)
            return 2
    elif d["decision"] != "allow":
        print(f"Blocked by tracekit policy: {'; '.join(d['rule_ids'])} {d.get('reason', '')}".rstrip(), file=sys.stderr)
        return 2
    files.write_json(_state(sid, tid), {"run_id": run.run_id, "decision_id": d["decision_id"],
                                        "args_digest": event_hash({"tool": tool, "args": args})})
    return 0


def _post(client, p, sid, tid):
    path = _state(sid, tid)
    call, run = _load(path), _run(client, sid, register=False)
    if not call or not run or call["run_id"] != run.run_id:
        print(f"[tracekit] no decision for tool call {tid}; result not recorded", file=sys.stderr)
        return 0
    from tracekit import policy as policy_mod
    cc = policy_mod.load()[0].get("content_capture", "hashed")
    failed = p["hook_event_name"] == "PostToolUseFailure"
    resp = p.get("tool_response") if not failed else {"error": p.get("error"), "response": p.get("tool_response")}
    ok = not failed and not (isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted")))
    ti = p.get("tool_input") if isinstance(p.get("tool_input"), dict) else {}
    dotenv = privacy.mentions_dotenv(ti.get("command"), ti.get("file_path"), ti.get("path"), ti.get("pattern"))
    run.call("complete", tool_call_id=tid, decision_id=call["decision_id"], args_digest=call["args_digest"],
             status="ok" if ok else "error", result=privacy.content(resp if resp is not None else "", cc, dotenv))
    os.remove(path)
    return 0


def main():
    raw = sys.stdin.read()
    try:
        p = json.loads(raw) if raw.strip() else {}
    except ValueError:
        p = {}
    p = p if isinstance(p, dict) else {}
    name, sid, tid = p.get("hook_event_name"), p.get("session_id"), p.get("tool_use_id")
    missing = [k for k, v in (("session_id", sid), ("tool_use_id", tid if name in TOOL_EVENTS else "-"))
               if not isinstance(v, str) or not v]
    if missing:   # never defaulted: the signer records the gap from what it did not receive
        pre = name == "PreToolUse"
        print(f"[tracekit] hook payload has no {', '.join(missing)}; "
              + ("tool call blocked" if pre else "event not recorded"), file=sys.stderr)
        return 2 if pre else 0
    client = Client()
    if name == "PreToolUse":
        return _pre(client, p, sid, tid)
    if name in TOOL_EVENTS:
        return _post(client, p, sid, tid)
    if name == "SessionEnd":
        run = _run(client, sid, register=False)
        try:
            if run:
                run.close(str(p.get("reason") or "session end")[:256])
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):   # closed already (idle): only the state is left
                raise
        for f in glob.glob(glob.escape(_state(sid)[:-len(".json")]) + "*"):
            os.remove(f)
        return 0
    # lean: UserPromptSubmit and transcript reasoning have no v2 RPC yet and are not recorded; the L1 transcript tailer
    # (M1b-07) and model events (M2) record them
    _run(client, sid)   # SessionStart, or any other first event of the session, registers the run
    return 0


def _entry():
    try:
        return main()
    except Exception as e:  # the signer unreachable, or a crash: follow the configured fail mode
        from tracekit.hook import fail_closed
        closed = fail_closed()
        print(f"[tracekit] hook error ({e}); " + ("blocking (fail-closed)" if closed else "allowing (fail-open)"),
              file=sys.stderr)
        return 2 if closed else 0


if __name__ == "__main__":
    sys.exit(_entry())
