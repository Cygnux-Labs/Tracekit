"""Claude Code hook on the v2 signer RPC: a thin client. The signer decides with its policy packs, signs and stores;
this process holds no key, evaluates no policy and writes no ledger.

    python -I -m tracekit.integrations.claude_code   (wired by `tracekit init --dev --v2`, or as root by
                                                      `tracekit init --v2 --user AGENT`: system mode)

Each hook is a new process, so the run of a Claude Code session (id, token, fail modes, and the one event stream and
next client_seq all its hooks share) and the decision binding of a tool call are kept in the runtime dir between hooks.
Exit 0 lets the call proceed, exit 2 blocks it (reason on stderr). The signer unreachable: the run's fail mode for the
tool's class, from register_run (closed before a run is registered). A signer refusal, a failure while a call waits for
its approval, or any other error: blocked.

SessionStart starts the run's transcript tailer (tracekit.tailer), once per run: it records the model's tool uses and
the user's prompts (as commitments) from the transcript, which no hook payload carries.

System mode: the signer runs as its own user and the hook reaches it only through the socket the root-owned
/etc/tracekit/client.json names (a TRACEKIT_SIGNER naming another is refused, and the call blocked); the signer
unreachable is always fail-closed there, whatever the agent-writable state says. The run token stays in the agent's
own 0700 runtime dir, and the signer accepts it only from the uid that registered the run: another local user can
neither read it nor use it. The agent never holds the signing keys, assigns sequence numbers, chooses the policy (the
signer decides), or answers its own approvals (signer.yaml names a different approver uid). Its own uid can still use
its run token, from any process it runs.
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid

from tracekit import privacy
from tracekit.client import system_config
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.locking import lock_file
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, fail_open
from tracekit.signer.rpc_schema import RPCError

AGENT = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
APPROVAL_WAIT_S = 540   # below the PreToolUse hook timeout (install.HOOK_TIMEOUT)


def _state(*ids):
    """State file in the runtime dir (0700, ours) for a session, or for one tool call of it."""
    names = [hashlib.sha256(i.encode("utf-8", "surrogatepass")).hexdigest() for i in ids]
    return os.path.join(autospawn.runtime_dir(), "claude-code-" + ".".join(names) + ".json")


def _load(path):
    for i in range(20):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except PermissionError:   # Windows: a parallel hook is replacing the file this instant
            if os.name != "nt" or i == 19:
                raise
            time.sleep(0.05)


def _run(client, sid, register=True, send=None, tailer=None, **fields):
    """(the session's run, registered on its first event; with `send`, the signer's reply to that event call, sent with
    the session's stream and next client_seq under the session lock so parallel hooks reach the signer in client_seq
    order, and sent again on a new run when the signer has closed the stored one (idle)). `tailer`: the transcript to
    start the run's tailer on, unless it has one."""
    path = _state(sid)
    with open(path[:-len(".json")] + ".lock", "a") as lk:   # parallel tool calls must not register two runs
        lock_file(lk)
        st = _load(path)
        if register and st is None:
            st = _register(client, path)
        if tailer and st and st.get("tailer") != st["run_id"]:
            _start_tailer(client, path, st, tailer)
        if not (st and send):
            return st and RunHandle(client, st), None
        try:
            return _send(client, path, st, send, fields)
        except RPCError as e:
            if not register or e.code not in ("run_closed", "unknown_run"):
                raise
            return _send(client, path, _register(client, path), send, fields)


def _register(client, path):
    version = os.environ.get("CLAUDE_CODE_VERSION")
    out = client.register_run({"agent": {"name": AGENT, **({"version": version[:64]} if version else {})}})
    # lean: any process of the agent's uid can read and use this token (another uid cannot); binding runs to the
    # harness's processes (a root-owned harness helper) narrows that
    st = {"run_id": out["run_id"], "run_token": out["run_token"], "fail_modes": out.get("fail_modes") or {},
          "stream": uuid.uuid4().hex, "seq": 0}
    files.write_json(path, st)
    return st


def _start_tailer(client, path, st, transcript):
    """Start tracekit.tailer for the run, detached. System mode: through sudo as the tailer's own user (the root-owned
    system config names it), with a token the signer issued to that user's uid for this run."""
    if os.name == "nt":   # the tailer needs O_NOFOLLOW and uids: POSIX only
        return
    handle = {"run_id": st["run_id"], "run_token": st["run_token"], "path": transcript}
    t = (system_config() or {}).get("tailer")
    if t:
        # lean: this tailer cannot see SessionEnd (the session state is the agent's); it exits once a call finds the run
        # final or after IDLE_S without a new line. A run-closed notice from the signer if idle tailers pile up
        handle["run_token"] = RunHandle(client, st).call("delegate_run", identity=f"uid:{t['uid']}")["run_token"]
        argv = ["sudo", "-n", "-u", t["user"], t["python"], "-I", "-m", "tracekit.tailer"]
    else:   # exits once SessionEnd removes the session state
        handle["until"] = path
        argv = [sys.executable, "-I", "-m", "tracekit.tailer"]
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    p.stdin.write(json.dumps(handle).encode())
    p.stdin.close()
    st["tailer"] = st["run_id"]
    files.write_json(path, st)


def _send(client, path, st, method, fields):
    run = RunHandle(client, st)
    files.write_json(path, dict(st, seq=st["seq"] + 1))
    return run, run.call(method, stream=st["stream"], client_seq=st["seq"], **fields)


def _pre(client, p, sid, tid):
    tool, args = p.get("tool_name") or "?", p.get("tool_input")
    run, d = _run(client, sid, send="decide", tool_call_id=tid, tool=tool, args=args, args_source="parsed")
    if d["decision"] == "deny":
        print(f"Blocked by tracekit policy: {'; '.join(d['rule_ids'])} {d.get('reason', '')}".rstrip(), file=sys.stderr)
        return 2
    if d["decision"] == "ask":
        try:
            aid = run.call("approval_request", tool_call_id=tid)["approval_id"]
            print(f"[tracekit] waiting for approval {aid} ({'; '.join(d['rule_ids'])})", file=sys.stderr, flush=True)
            state, deadline = "requested", time.monotonic() + APPROVAL_WAIT_S
            while state == "requested" and deadline > time.monotonic():
                left_ms = int(min(deadline - time.monotonic(), 300) * 1000)
                state = run.call("approval_wait", approval_id=aid, timeout_ms=left_ms)["state"]
            c = run.approval_consume(tid, tool, args, approval_id_hint=aid) if state == "approved" else None
        except Exception as e:   # no fail mode once the policy asked: a call nobody approved never runs
            state, c = f"{type(e).__name__}: {e}", None
        if c is None:
            print(f"Held by tracekit policy ({'; '.join(d['rule_ids'])}) and not approved: {state}", file=sys.stderr)
            return 2
    else:
        c = run.approval_consume(tid, tool, args)   # every call that runs: once, for the decided args
    if not c["ok"]:
        print(f"Held by tracekit policy: {'; '.join(c['rule_ids'])} {c.get('reason', '')}".rstrip(), file=sys.stderr)
        return 2
    files.write_json(_state(sid, tid), {"run_id": run.run_id, "decision_id": d["decision_id"],
                                        "args_digest": event_hash({"tool": tool, "args": args})})
    return 0


def _post(client, p, sid, tid):
    path = _state(sid, tid)
    call, st = _load(path), _load(_state(sid))
    if not call or not st or call["run_id"] != st["run_id"]:
        print(f"[tracekit] no decision for tool call {tid}; result not recorded", file=sys.stderr)
        return 0
    from tracekit import policy as policy_mod
    cc = policy_mod.load()[0].get("content_capture", "hashed")
    failed = p["hook_event_name"] == "PostToolUseFailure"
    resp = p.get("tool_response") if not failed else {"error": p.get("error"), "response": p.get("tool_response")}
    ok = not failed and not (isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted")))
    ti = p.get("tool_input") if isinstance(p.get("tool_input"), dict) else {}
    dotenv = privacy.mentions_dotenv(ti.get("command"), ti.get("file_path"), ti.get("path"), ti.get("pattern"))
    _run(client, sid, register=False, send="complete", tool_call_id=tid, decision_id=call["decision_id"],
         args_digest=call["args_digest"], status="ok" if ok else "error",
         result=privacy.content(resp if resp is not None else "", cc, dotenv))
    os.remove(path)
    return 0


def _prune():
    """Removes session and tool call state no hook has written for longer than the signer's default run idle timeout:
    the signer has closed those runs, and a call that never got its PostToolUse leaves its state behind."""
    from tracekit.signer.service import IDLE_S
    old = time.time() - IDLE_S
    for f in sorted(glob.glob(os.path.join(glob.escape(autospawn.runtime_dir()), "claude-code-*")),
                    key=lambda f: f.endswith(".lock")):   # the state first, then the locks it no longer needs
        # lean: a lock goes only once its session state has; a hook that resumes that very session at this instant
        # could lock a fresh file beside one still held, so two runs get registered, rare enough for dev mode
        if f.endswith(".lock") and os.path.exists(f[:-len(".lock")] + ".json"):
            continue
        try:
            if os.path.getmtime(f) < old:
                os.remove(f)
        except OSError:   # removed by a parallel hook
            pass


def _tool_class(tool):
    # lean: the class in the dev signer's default policy; a signer with another policy may class the tool otherwise
    from tracekit.signer.service import load_policy
    return load_policy().tool_class(tool)


def _handle(client, p, name, sid, tid):
    if name == "PreToolUse":
        return _pre(client, p, sid, tid)
    if name in TOOL_EVENTS:
        return _post(client, p, sid, tid)
    if name == "SessionEnd":
        run, _ = _run(client, sid, register=False)
        try:
            if run:
                run.close(str(p.get("reason") or "session end")[:256])
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):   # closed already (idle): only the state is left
                raise
        for f in glob.glob(glob.escape(_state(sid)[:-len(".json")]) + "*"):
            os.remove(f)
        return 0
    tailer = None
    if name == "SessionStart":
        _prune()
        tailer = p.get("transcript_path") if isinstance(p.get("transcript_path"), str) else None
    _run(client, sid, tailer=tailer)   # SessionStart, or any other first event of the session, registers the run
    return 0


def _entry():
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
    try:
        client = Client()
    except Exception as e:   # a TRACEKIT_SIGNER that is not the system signer, or an unreadable system config
        print(f"[tracekit] {e}; blocking", file=sys.stderr)
        return 2
    try:
        return _handle(client, p, name, sid, tid)
    except (SignerUnavailable, OSError) as e:   # the signer unreachable: the run's fail mode for the tool's class
        try:
            closed = bool((system_config() or {}).get("signer")) or not fail_open(   # system mode: always closed
                (_load(_state(sid)) or {}).get("fail_modes"), _tool_class(p.get("tool_name") or "?"))
        except Exception:
            closed = True
        print(f"[tracekit] signer unreachable ({e}); " + ("blocking (fail-closed)" if closed else "allowing (fail-open)"),
              file=sys.stderr)
        return 2 if closed else 0
    except Exception as e:   # a signer refusal or a crash: never a reason to let the call run
        print(f"[tracekit] hook error ({type(e).__name__}: {e}); blocking", file=sys.stderr)
        return 2
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(_entry())
