"""Claude Code hook on the v2 signer RPC: a thin client. The signer decides with its policy packs, signs and stores;
this process holds no key, evaluates no policy and writes no ledger.

    python -I -m tracekit.integrations.claude_code EVENT   (wired by `tracekit init --dev --v2`, or as root by
                                                            `tracekit init --v2 --user AGENT`: system mode)

EVENT is the hook event `tracekit init` configured this command for (PreToolUse, PostToolUse, ...): a payload that is
not a JSON object still blocks a PreToolUse call (on a PostToolUse, its call is completed as an error later, below).
Without it (hooks installed before 1.2) the event comes from the payload alone.

Each hook is a new process, so the run of a Claude Code session (id, token, fail modes, and the one event stream and
next client_seq all its hooks share) and the decision binding of a tool call are kept in the runtime dir between hooks.
Exit 0 lets the call proceed, exit 2 blocks it (reason on stderr); only a PreToolUse is blocked: another event whose
hook fails exits 1, an error the harness shows without blocking. An approval with a T2 executor runs the arguments the
consume returns: the hook prints them as `updatedInput` (Claude Code only; the other harnesses run the arguments the
signer consumed, which it checked against the approved ones). The signer unreachable: the run's fail mode for the
tool's class, from register_run (closed before a run is registered). A rate limit (quota_exceeded with retry_after_ms)
is waited out within the client's timeout (HookClient). A signer refusal, a failure while a call waits for its
approval, or any other error: blocked. A call allowed here that gets no PostToolUse (declined in the harness's own
permission prompt, interrupted, or an unreadable payload) is completed as an error at SessionEnd; one that is never
completed is the signer's decided_not_completed gap.

Each run of a session gets one transcript tailer (tracekit.tailer) on the transcript SessionStart names: it records the
model's tool uses, thinking and text, and the user's prompts (as commitments, with their content when the signer keeps
content) from the transcript, which no hook payload carries. A later run of the session (after an idle close) has its
tailer start where the hook last saw the transcripts while the earlier run was open (_seen), and a resumed session's
first run where its transcript ended at SessionStart: the lines before are an earlier run's.

At UserPromptSubmit the prompt as the harness submitted it is recorded too (`observe`, source <agent>:UserPromptSubmit,
trusted): `tracekit analyze --v2` reads a transcript prompt line as the person's only when one of these has its text
(TK-X208 flags a line none has). Each constraint the prompt states (tracekit.constraints: "don't touch X", "read-only",
"don't push", ...) goes to the signer first, each on its own, as a live constraint (`constraint_add`), which holds a
later call that breaks it for a person's approval; the agent reads why on stderr. A scope ("only change X") is no live
constraint (_live): holding every other write (tests, lockfiles) would ask too often; `tracekit analyze --v2` checks
it. The session state keeps them (written before they are sent, so an unreachable signer loses none), and a later run
of the session (after an idle close) gets them all again. A constraint can only hold more calls, so the agent's own
identity adding one (it could add its own) weakens nothing: past the signer's cap of file constraints a further one is
refused and every write of the run is held from then on, which the hook tells the person (exit 1, FULL on stderr).

System mode: the signer runs as its own user and the hook reaches it only through the socket the root-owned
/etc/tracekit/client.json names (a TRACEKIT_SIGNER naming another is refused, and the call blocked); the signer
unreachable is always fail-closed there, whatever the agent-writable state says. The run token stays in the agent's
own 0700 runtime dir, and the signer accepts it only from the uid that registered the run: another local user can
neither read it nor use it. The agent never holds the signing keys, assigns sequence numbers, chooses the policy (the
signer decides), or answers its own approvals (signer.yaml names a different approver uid). Its own uid can still use
its run token, from any process it runs.
"""
import functools
import glob
import hashlib
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import uuid

from tracekit import constraints, privacy
from tracekit.client import system_config
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.locking import lock_file
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, fail_open, named_rules, sendable
from tracekit.signer.rpc_schema import RPCError

AGENT = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
# the error a call that got no PostToolUse is completed with (_unfinished)
NO_POST = ("no PostToolUse came by the end of the session: declined (the harness's permission prompt, another hook), "
           "interrupted, or its payload was unreadable")
RESUMED = ("resume", "fork")   # SessionStart sources whose transcript already holds the session's earlier history
FULL = ("[tracekit] the run has the most file constraints the signer takes: what this prompt says not to change was "
        "not added, so every write of the run is now held for your approval")
APPROVAL_WAIT_S = 540   # a PreToolUse hook, approval wait included, answers within this: below its timeout (install.HOOK_TIMEOUT)


class HookClient(Client):
    """The hooks' client: a call the signer rate-limits (quota_exceeded with retry_after_ms) is sent again once that has
    passed, within the client's timeout, as the tailer's lines are. In dev mode the hooks and the tailer share the
    agent's uid, and so its event rate: a tailer reading a long transcript must not have the hook's decide refused."""

    def call(self, method, req=None, **fields):
        end = time.monotonic() + self.timeout
        while True:
            try:
                return super().call(method, req, **fields)
            except RPCError as e:
                wait = (e.retry_after_ms or 0) / 1000
                if e.code != "quota_exceeded" or e.retry_after_ms is None or time.monotonic() + wait > end:
                    raise
                time.sleep(wait)


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


def _run(client, sid, register=True, send=None, transcript=None, resumed=False, stated=(), **fields):
    """(the session's run, registered on its first event; with `send`, the signer's reply to that event call, sent with
    the session's stream and next client_seq under the session lock so parallel hooks reach the signer in client_seq
    order, and sent again on a new run when the signer has closed the stored one (idle); without `register`, the stored
    run is marked ended instead, and the session's next event that registers starts the new one). `transcript`
    (SessionStart): kept in the session state; each run of the session gets a tailer on it, which starts where the
    session's earlier run was last seen open (_seen; `resumed`: a resumed session's transcript as it is now).
    `stated`: the constraints a prompt states, kept in the session state; each run gets the session's (_constrain)."""
    path = _state(sid)
    with open(path[:-len(".json")] + ".lock", "a") as lk:   # parallel tool calls must not register two runs
        lock_file(lk)
        st = _load(path)
        if register and (st is None or st.get("ended")):
            st = _register(client, path, st, _seen(transcript) if resumed else None)
        if st and transcript:
            st["transcript"] = transcript
        if st and stated:
            st["constraints"] = [*dict.fromkeys(map(tuple, [*st.get("constraints", ()), *stated]))]
            files.write_json(path, st)   # kept if the signer can't be reached now: the next event sends them
        full = False
        if st and not st.get("ended"):
            try:
                full = _constrain(client, path, st)
            except RPCError as e:
                if e.code not in ("run_closed", "unknown_run"):
                    raise
                if not register:   # as for a send below
                    files.write_json(path, dict(st, ended=True))
                    raise
                st = _register(client, path, st)   # the signer closed the stored run (idle): a new one gets them all
                full = _constrain(client, path, st)
        _tail(client, path, st)
        seen = _seen(st and st.get("transcript"))   # before this event's call: lines its run's tailer reports there
        if not (st and send):
            if seen and not st.get("ended"):
                # lean: no call says the run is still open at this event (Stop, ...); it closes only after an hour
                # with none, which a turn spends making calls
                files.write_json(path, dict(st, offsets=seen))
            return st and RunHandle(client, st), {"refused": True} if full else None
        if st.get("ended"):   # the signer said so already: asking again would only count as a late write
            raise RPCError("run_closed", f"run {st['run_id']} ended")
        try:
            return _send(client, path, st, send, fields, seen)
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):
                raise
            if not register:   # the session's next event registers a new run instead of trying this one again
                files.write_json(path, dict(st, ended=True))
                raise
            st = _register(client, path, st)
            _constrain(client, path, st)
            _tail(client, path, st)
            return _send(client, path, st, send, fields, seen)


def _register(client, path, prev=None, offsets=None):
    """A new run for the session whose state was `prev` (None: its first), keeping its transcript and where the
    earlier run was last seen open in it (`offsets` in place of that)."""
    version = os.environ.get("CLAUDE_CODE_VERSION") if AGENT == "claude-code" else None
    out = client.register_run({"agent": {"name": AGENT, **({"version": version[:64]} if version else {})}})
    # lean: any process of the agent's uid can read and use this token (another uid cannot); binding runs to the
    # harness's processes (a root-owned harness helper) narrows that
    st = {"run_id": out["run_id"], "run_token": out["run_token"], "fail_modes": out.get("fail_modes") or {},
          "stream": uuid.uuid4().hex, "seq": 0,
          **{k: v for k, v in (prev or {}).items() if k in ("transcript", "offsets", "constraints")},
          **({"offsets": offsets} if offsets else {})}
    files.write_json(path, st)
    return st


def _constrain(client, path, st):
    """Send the run the session's constraints it has not had (all of them to a new run), each on its own: one the
    signer refuses stops none of the others, and the first refusal is raised after. The signer unreachable, or the run
    closed, stops it; the next event (or a new run) sends the rest. -> whether the signer took one only as a refusal
    past its cap (`refused`: every write of the run is held from then on), which it says on stderr."""
    sent = st.get("sent") or [None, 0]
    done = sent[1] if sent[0] == st["run_id"] else 0
    refused, full = [], False
    try:
        for kind, obj in (st.get("constraints") or ())[done:]:
            try:
                full = RunHandle(client, st).call("constraint_add", constraint={
                    "kind": kind, **({"object": obj} if obj else {})}).get("refused") is True or full
            except RPCError as e:
                if e.code in ("run_closed", "unknown_run"):
                    raise
                refused.append(e)
            done += 1
    finally:
        if done != sent[1] or sent[0] != st["run_id"]:
            st["sent"] = [st["run_id"], done]
            files.write_json(path, st)
    if full:
        print(FULL, file=sys.stderr)
    if refused:
        raise refused[0]
    return full


def _end(path):
    """The offset just past the last complete line of the regular file `path` (0: none, or it can't be read)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)   # a FIFO in its place must not block the hook
    except OSError:
        return 0
    with os.fdopen(fd, "rb") as f:
        pos = f.seek(0, os.SEEK_END) if stat.S_ISREG(os.fstat(fd).st_mode) else 0
        while pos > 0:
            n = min(pos, 1 << 16)
            pos -= n
            f.seek(pos)
            i = f.read(n).rfind(b"\n")
            if i >= 0:
                return pos + i + 1
    return 0


def _seen(transcript):
    """{path: _end(path)} of the session's transcript and its subagents' as they are now, which the tailer of the
    session's next run (after an idle close) starts from: their lines so far are the earlier run's. None for a harness
    without a tailer."""
    if AGENT != "claude-code" or not transcript or os.name == "nt":
        return None
    subs = os.path.join(glob.escape(os.path.splitext(transcript)[0]), "subagents", "agent-*.jsonl")
    return {p: _end(p) for p in [transcript, *sorted(glob.glob(subs))]}


def _tail(client, path, st):
    """Start tracekit.tailer for the run, detached, unless it has one. System mode: through sudo as the tailer's own
    user (the root-owned system config names it), with a token the signer issued to that user's uid for this run; with
    no tailer installed, the signer records a tailer_lost gap for the run instead."""
    if (AGENT != "claude-code" or not (st and st.get("transcript")) or st.get("tailer") == st["run_id"]
            or os.name == "nt"):   # Claude Code transcripts only; POSIX only
        return
    handle = {"run_id": st["run_id"], "run_token": st["run_token"], "path": st["transcript"],
              **({"offsets": st["offsets"]} if st.get("offsets") else {})}
    sc = system_config() or {}
    t = sc.get("tailer")
    argv = None   # a tailer that dies or is killed stops its heartbeats: the signer writes the tailer_lost gap
    if t:
        # this tailer cannot see SessionEnd (the session state is the agent's): it exits once a call finds the run
        # final, or with a tailer_lost after tailer.IDLE_TAILER_S without a new line
        handle["run_token"] = RunHandle(client, st).call("delegate_run", identity=f"uid:{t['uid']}")["run_token"]
        argv = ["sudo", "-n", "-u", t["user"], t["python"], "-I", "-m", "tracekit.tailer"]
    elif sc.get("signer"):   # system mode, but init could not give the tailer access
        RunHandle(client, st).call("tailer_lost", reason="no transcript tailer is installed", offset=0)
    else:   # exits once SessionEnd removes the session state
        handle["until"] = path
        argv = [sys.executable, "-I", "-m", "tracekit.tailer"]
    if argv:
        try:
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
            p.stdin.write(json.dumps(handle).encode())
            p.stdin.close()
        except OSError as e:   # no tailer could start: a signed gap says so, once, and the call goes on
            RunHandle(client, st).call("tailer_lost", reason=f"the transcript tailer did not start: {e}"[:1024],
                                       offset=0)
    st["tailer"] = st["run_id"]
    files.write_json(path, st)


def _send(client, path, st, method, fields, seen=None):
    """`seen`: _seen before the call; once the run has taken it, the run was open with those lines written."""
    run = RunHandle(client, st)
    files.write_json(path, dict(st, seq=st["seq"] + 1))
    out = run.call(method, stream=st["stream"], client_seq=st["seq"], **fields)
    if seen:
        files.write_json(path, dict(st, seq=st["seq"] + 1, offsets=seen))
    return run, out


def _pre(client, p, sid, tid):
    end, per_call = time.monotonic() + APPROVAL_WAIT_S, client.timeout   # every signer call is capped to the time left

    def cap(wait_s=0.0):
        client.timeout = max(min(per_call, end - time.monotonic() - wait_s), 0.001)

    tool, args = p.get("tool_name") or "?", p.get("tool_input")
    cap()
    run, d = _run(client, sid, send="decide", tool_call_id=tid, tool=tool, args=args, args_source="parsed")
    if d["decision"] == "deny":
        print("Blocked by tracekit policy: " + named_rules(d["rule_ids"]) + (f": {d['reason']}" if d.get("reason") else ""),
              file=sys.stderr)
        return 2
    if d["decision"] == "ask":
        why = f": {d['reason']}" if d.get("reason") else ""   # a live constraint's says which and what to do
        try:
            cap()
            aid = run.call("approval_request", tool_call_id=tid)["approval_id"]
            # a named signer (system mode's, or $TRACEKIT_SIGNER's) may not be the person's default; quoted: outside
            # system mode the agent may have set it
            cmd = "tracekit approvals" + (f" --signer {shlex.quote(client.signer)}" if client.signer else "")
            print(f"[tracekit] waiting for approval {aid} ({'; '.join(d['rule_ids'])}){why}; a person approves it "
                  f"from another terminal with `{cmd} approve {aid}` or rejects it with `{cmd} reject {aid}`",
                  file=sys.stderr, flush=True)
            state, deadline = "requested", end - 2 * per_call   # time left for the last wait's answer and the consume
            while state == "requested" and deadline > time.monotonic():
                left_s = min(deadline - time.monotonic(), 300)
                cap(left_s)
                state = run.call("approval_wait", approval_id=aid, timeout_ms=int(left_s * 1000))["state"]
            cap()
            c = run.approval_consume(tid, tool, args, approval_id_hint=aid) if state == "approved" else None
        except Exception as e:   # no fail mode once the policy asked: a call nobody approved never runs
            state, c = f"{type(e).__name__}: {e}", None
        if c is None:
            print(f"Held by tracekit policy ({'; '.join(d['rule_ids'])}{why}) and not approved: {state}",
                  file=sys.stderr)
            return 2
    else:
        cap()
        c = run.approval_consume(tid, tool, args)   # every call that runs: once, for the decided args
    if not c["ok"]:
        why = " ".join(x for x in ("; ".join(c["rule_ids"]), c.get("reason", "")) if x)
        print(f"Held by tracekit policy: {why}", file=sys.stderr)
        return 2
    if "args" in c and AGENT == "claude-code":   # T2: the signer's copy is what runs
        args = c["args"]
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": args}}))
    files.write_json(_state(sid, tid), {"run_id": run.run_id, "tool_call_id": tid, "decision_id": d["decision_id"],
                                        "args_digest": event_hash({"tool": tool, "args": args}),
                                        "send_result": d.get("send_result", False)})
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
    value = resp if resp is not None else ""
    if not (call.get("send_result") and sendable(value)):   # an untrusted tool's result goes itself, for provenance
        value = privacy.content(value, cc, dotenv)
    _run(client, sid, register=False, send="complete", tool_call_id=tid, decision_id=call["decision_id"],
         args_digest=call["args_digest"], status="ok" if ok else "error", result=value)
    os.remove(path)
    return 0


def _live(prompt):
    """The constraints `prompt` states that the signer holds calls for: all but a scope (only_change)."""
    return [(kind, obj and obj[:256]) for kind, obj in constraints.extract(prompt) if kind != "only_change"]


def prompted(run, prompt):
    """Each live constraint `prompt` states (_live), as a live constraint of `run`, each on its own (module
    docstring). -> whether the signer took one only as a refusal past its cap (_constrain)."""
    refused, full = [], False
    for kind, obj in _live(prompt):
        try:
            full = run.call("constraint_add", constraint={"kind": kind, **({"object": obj} if obj else {})}).get(
                "refused") is True or full
        except RPCError as e:
            refused.append(e)
    if refused:
        raise refused[0]
    return full


def _unfinished(client, sid):
    """Complete the session's calls that never got their PostToolUse (declined in the harness's own permission prompt
    or by another hook, interrupted, or a payload this hook couldn't read) as errors at SessionEnd, when none can still
    be running, so the signer doesn't write a decided_not_completed gap for each."""
    for path in glob.glob(glob.escape(_state(sid)[:-len(".json")]) + ".*.json"):
        call, st = _load(path), _load(_state(sid))
        if call and st and call.get("run_id") == st["run_id"] and "tool_call_id" in call:
            try:
                _run(client, sid, register=False, send="complete", tool_call_id=call["tool_call_id"],
                     decision_id=call["decision_id"], args_digest=call["args_digest"], status="error", error=NO_POST)
            except SignerUnavailable:   # the next of these events tries again
                return
            except RPCError:   # its run ended, or its PostToolUse came meanwhile
                pass
        try:
            os.remove(path)
        except FileNotFoundError:   # its PostToolUse removed it
            pass


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


@functools.lru_cache(maxsize=256)
def _tool_class(tool):
    # lean: the class in the dev signer's default policy; a signer with another policy may class the tool otherwise
    from tracekit.signer.service import load_policy
    return load_policy().tool_class(tool)


def _handle(client, p, name, sid, tid):
    if name == "PreToolUse":
        return _pre(client, p, sid, tid)
    if name in TOOL_EVENTS:
        return _post(client, p, sid, tid)
    if name == "SessionEnd":   # not at Stop: a background subagent's call may still be running then
        _unfinished(client, sid)
        run, _ = _run(client, sid, register=False)
        try:
            if run:   # each hook is a process of its own: the session's stream and counter are in its state
                st = run.registered
                last = [{"stream": st["stream"], "client_seq": st["seq"] - 1}] if st.get("seq") else []
                run.call("close_run", reason=str(p.get("reason") or "session end")[:256],
                         **({"last_client_seq": last} if last else {}))
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):   # closed already (idle): only the state is left
                raise
        for f in glob.glob(glob.escape(_state(sid)[:-len(".json")]) + "*"):
            os.remove(f)
        return 0
    transcript, prompt = None, p.get("prompt") if name == "UserPromptSubmit" else None
    if name == "SessionStart":
        _prune()
        transcript = p.get("transcript_path") if isinstance(p.get("transcript_path"), str) else None
    if isinstance(prompt, str) and prompt:   # the harness's own copy of what the person typed
        try:   # its constraints first: a prompt too large for one observe frame still adds them
            refused = _run(client, sid, stated=_live(prompt))[1]
        finally:
            _run(client, sid, send="observe", source=f"{AGENT}:UserPromptSubmit", trust="trusted", value=prompt)
        return 1 if refused else 0   # shown to the person (FULL, on stderr), never blocking the prompt
    # SessionStart, or any other first event of the session, registers the run; a resumed (or forked) session's
    # transcript holds its earlier history, which earlier runs recorded
    _run(client, sid, transcript=transcript, resumed=name == "SessionStart" and p.get("source") in RESUMED)
    return 0


def _entry(event=None):
    """`event`: the hook event from the command line, or None."""
    # UTF-8 JSON, read as bytes where stdin has them (as agent_hooks.stdin_text): Windows decodes a pipe with its ANSI
    # code page
    raw = sys.stdin.buffer.read().decode("utf-8", "replace") if hasattr(sys.stdin, "buffer") else sys.stdin.read()
    try:
        p = json.loads(raw) if raw.strip() else {}
    except (ValueError, RecursionError):   # nested too deep to read
        p = None
    if not isinstance(p, dict) and event:
        pre = event == "PreToolUse"
        print(f"[tracekit] the {event} hook payload is not a JSON object; "
              + ("tool call blocked" if pre else "event not recorded"), file=sys.stderr)
        return 2 if pre else 0
    return handle(dict(p, hook_event_name=event) if event else p if isinstance(p, dict) else {})


def handle(p):
    """One hook event in Claude Code's payload shape (tracekit.integrations.harness_hooks maps the other harnesses'
    onto it). -> exit code: 0 lets the call proceed, 2 blocks it; the reason is on stderr. Only a PreToolUse is ever
    blocked: any other event that fails returns 1, a non-blocking error the harness shows (2 would erase a prompt, or
    send the agent back to work at Stop), and its tool calls are still decided at PreToolUse."""
    name, sid, tid = p.get("hook_event_name"), p.get("session_id"), p.get("tool_use_id")
    pre = name == "PreToolUse"
    missing = [k for k, v in (("session_id", sid), ("tool_use_id", tid if name in TOOL_EVENTS else "-"))
               if not isinstance(v, str) or not v]
    if missing:   # never defaulted: the signer records the gap from what it did not receive
        print(f"[tracekit] hook payload has no {', '.join(missing)}; "
              + ("tool call blocked" if pre else "event not recorded"), file=sys.stderr)
        return 2 if pre else 0
    failed, code = ("blocking", 2) if pre else ("event not recorded", 1)
    try:
        client = HookClient()
    except Exception as e:   # a TRACEKIT_SIGNER that is not the system signer, or an unreadable system config
        print(f"[tracekit] {e}; {failed}", file=sys.stderr)
        return code
    try:
        return _handle(client, p, name, sid, tid)
    except SignerUnavailable as e:   # the signer unreachable: the run's fail mode for the tool's class (a local
        # OSError, a full disk, is no outage: it blocks below, as the call could not be counted)
        fix = ""
        try:
            sc = system_config() or {}
            if sc and not sc.get("signer") and not os.environ.get("TRACEKIT_SIGNER"):   # v1 system mode: no v2 signer
                fix = (". This host is in v1 system mode (the system config names no v2 signer): set up v2 system "
                       "mode, sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> (--no-hooks with the "
                       "Claude Code plugin)")
            closed = bool(sc.get("signer")) or not fail_open(   # system mode: always closed
                (_load(_state(sid)) or {}).get("fail_modes"), _tool_class(p.get("tool_name") or "?"))
        except Exception:
            closed = True
        if pre:
            failed, code = ("blocking (fail-closed)", 2) if closed else ("allowing (fail-open)", 0)
        print(f"[tracekit] signer unreachable ({e}); {failed}{fix}", file=sys.stderr)
        return code
    except Exception as e:   # a signer refusal or a crash: never a reason to let the call run
        print(f"[tracekit] hook error ({type(e).__name__}: {e}); {failed}", file=sys.stderr)
        return code
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(_entry(*sys.argv[1:2]))
