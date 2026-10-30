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

Each run of a session gets one transcript tailer (tracekit.tailer) on the transcript the hook payloads name, from the
run's first event: it records the model's tool uses, thinking and text, and the user's prompts (as commitments, with
their content when the signer keeps content) from the transcript, which no hook payload carries. A new session's run
reads it from its first line; a later run of the session (after an idle close) has its tailer start where the hook last
saw the transcripts while the earlier run was open (_seen), and a resumed session's first run, or one a session with no
state left starts (Claude Code went on after a SessionEnd with no SessionStart), where its transcript ended then: the
lines before are an earlier run's.

At UserPromptSubmit, the typed part of the harness's prompt is recorded (`observe`, source <agent>:UserPromptSubmit,
trusted); harness-wrapped parts are separate untrusted observations, and so is the whole of a turn Claude Code's payload
says no person typed (a `source` other than user or sdk; recorded as <agent>:<source>). `tracekit analyze --v2` reads a
transcript prompt line as the person's only when one of these has its typed text (TK-X208 flags a line none has). Each
constraint the typed part states (tracekit.constraints: "don't touch X", "read-only", "don't push", ...), and each a
wrapped part states whose wrapper follows other text on its line (midline_live), goes to the signer first, each on its
own, as a live constraint (`constraint_add`), which holds a later call that breaks it for a person's approval; the agent
reads why on stderr. A scope ("only change X") is no live constraint (_live): holding every other write (tests,
lockfiles) would ask too often; `tracekit analyze --v2` checks it. The session state keeps them (written before they are
sent, so an unreachable signer loses none), and a later run of the session (after an idle close) gets them all again. A
constraint can only hold more calls, so the agent's own identity adding one (it could add its own) weakens nothing: past
the signer's cap of file constraints a further one is refused and every write of the run is held from then on, which the
hook tells the person (exit 1, FULL on stderr, and in the prompt's notice when it prints one).

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
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid
from collections import deque

from tracekit import constraints, privacy
from tracekit.client import system_config
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.locking import lock_file
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, fail_open, named_rules, sendable
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError

AGENT = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
# the error a call that got no PostToolUse is completed with (_unfinished)
NO_POST = ("no PostToolUse came by the end of the session: declined (the harness's permission prompt, another hook), "
           "interrupted, or its payload was unreadable")
RESUMED = ("resume", "fork")   # SessionStart sources whose transcript already holds the session's earlier history
FRESH = ("startup", "clear")   # SessionStart sources of a new transcript
FULL = ("[tracekit] the run has the most file constraints the signer takes: what this prompt says not to change was "
        "not added, so every write of the run is now held for your approval")
APPROVAL_WAIT_S = 540   # a PreToolUse hook, approval wait included, answers within this: below its timeout (install.HOOK_TIMEOUT)
# lean: a session's state is kept this long after its last hook event (Claude Code's default cleanupPeriodDays, after
# which it deletes the transcript); a session continued later starts without its constraints; keep the state while
# its transcript exists if sessions are continued later than that
SESSION_KEEP_S = 30 * 86400


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


def _transcript(p):
    """The session's transcript, which every Claude Code hook payload names (a subagent's too: the session's own)."""
    return p.get("transcript_path") if isinstance(p.get("transcript_path"), str) else None


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


def _run(client, sid, register=True, send=None, transcript=None, start=None, stated=(), skip=0, **fields):
    """(the session's run, registered on its first event; with `send`, the signer's reply to that event call, sent with
    the session's stream and next client_seq under the session lock so parallel hooks reach the signer in client_seq
    order, and sent again on a new run when the signer has closed the stored one (idle); without `register`, the stored
    run is marked ended instead, and the session's next event that registers starts the new one). `transcript` (the
    payload's): kept in the session state; each run of the session gets a tailer on it, which starts at the first line
    of a new session's (`start`, the SessionStart source: startup or clear), at where it ends at registration for a
    resumed or forked session or one with no state left, else where the session's earlier run was last seen open
    (_seen; _tail for a run registered before its transcript was known).
    `stated`: the constraints a prompt states, kept in the session state; each run gets the session's (_constrain).
    `skip`: client_seq values left unsent before `send` (_send)."""
    path = _state(sid)
    with open(path[:-len(".json")] + ".lock", "a") as lk:   # parallel tool calls must not register two runs
        lock_file(lk)
        st = _load(path)
        if register and (st is None or st.get("ended")):
            # where its tailer starts, kept in the state so a retried start (_tail) reads from the same place
            st = _register(client, path, st, {transcript: 0} if transcript and st is None and start in FRESH else
                           _seen(transcript) if st is None or start in RESUMED else None)
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
            return _send(client, path, st, send, fields, seen, skip)
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):
                raise
            if not register:   # the session's next event registers a new run instead of trying this one again
                files.write_json(path, dict(st, ended=True))
                raise
            st = _register(client, path, st)
            _constrain(client, path, st)
            _tail(client, path, st)
            return _send(client, path, st, send, fields, seen, skip)


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
    """{path: _end(path)} of the session's transcript and its subagents' (a workflow's agents' too) as they are now,
    which the tailer of the session's next run (after an idle close) starts from: their lines so far are the earlier
    run's. None for a harness without a tailer."""
    if AGENT != "claude-code" or not transcript or os.name == "nt":
        return None
    subs = os.path.join(glob.escape(os.path.splitext(transcript)[0]), "subagents")
    return {p: _end(p) for p in [transcript, *sorted(glob.glob(os.path.join(subs, "agent-*.jsonl"))),
                                 *sorted(glob.glob(os.path.join(subs, "workflows", "*", "agent-*.jsonl")))]}


def _tail(client, path, st):
    """Start tracekit.tailer for the run, detached, unless it has one. System mode: through sudo as the tailer's own
    user (the root-owned system config names it), with a token the signer issued to that user's uid for this run; with
    no tailer installed, the signer records a tailer_lost gap for the run instead. A run whose state names no offsets
    (registered before its transcript was known, by an earlier hook) starts where the transcripts end the first time
    this runs, kept in the state so a retry after a failed start reads from the same place."""
    if (AGENT != "claude-code" or not (st and st.get("transcript")) or st.get("tailer") == st["run_id"]
            or os.name == "nt"):   # Claude Code transcripts only; POSIX only
        return
    # lean: a run a session goes on with after a SessionEnd (no SessionStart: a message to the session, a usage limit's
    # reset) starts where the transcripts end at its first event; what Claude Code wrote between the SessionEnd and
    # then (the new prompt, the first call's tool use: then a fabricated gap) is read by no run, as the earlier run's
    # tailer stopped at the SessionEnd; keep the transcript's end in the state at SessionEnd if sessions often go on
    if not st.get("offsets"):
        st["offsets"] = _seen(st["transcript"])
        files.write_json(path, st)
    handle = {"run_id": st["run_id"], "run_token": st["run_token"], "path": st["transcript"], "offsets": st["offsets"]}
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


def _send(client, path, st, method, fields, seen=None, skip=0):
    """`seen`: _seen before the call; once the run has taken it, the run was open with those lines written. `skip`:
    client_seq values left unsent before this event, events the hook could not send: the signer records the gap and
    marks the run's provenance index partial, so `from: untrusted` rules fail closed."""
    run, seq = RunHandle(client, st), st["seq"] + skip
    files.write_json(path, dict(st, seq=seq + 1))
    out = run.call(method, stream=st["stream"], client_seq=seq, **fields)
    if seen:
        files.write_json(path, dict(st, seq=seq + 1, offsets=seen))
    return run, out


def _pre(client, p, sid, tid):
    end, per_call = time.monotonic() + APPROVAL_WAIT_S, client.timeout   # every signer call is capped to the time left

    def cap(wait_s=0.0):
        client.timeout = max(min(per_call, end - time.monotonic() - wait_s), 0.001)

    tool, args = p.get("tool_name") or "?", p.get("tool_input")
    cap()
    run, d = _run(client, sid, send="decide", transcript=_transcript(p), tool_call_id=tid, tool=tool, args=args,
                  args_source="parsed")
    if d["decision"] == "deny":
        print("Blocked by tracekit policy: " + named_rules(d["rule_ids"]) + (f": {d['reason']}" if d.get("reason") else ""),
              file=sys.stderr)
        return 2
    if d["decision"] == "ask":
        reason = d.get("reason") or ""   # a live constraint's says which and what to do
        why = f": {reason if reason.endswith('..') else reason.removesuffix('.')}" if reason else ""   # keeps a ...
        try:
            cap()
            aid = run.call("approval_request", tool_call_id=tid)["approval_id"]
            # a named signer (system mode's, or $TRACEKIT_SIGNER's) may not be the person's default; quoted: outside
            # system mode the agent may have set it. On Windows (cmd.exe reads no single quotes) in double quotes,
            # which cmd.exe and PowerShell both read as written but for a quote (PowerShell's curly ones too), $, a
            # backtick, cmd.exe's %VAR% or a line break: a name holding one is left for the person to fill in
            named = client.signer and (
                shlex.quote(client.signer) if os.name != "nt" else
                "<TRACEKIT_SIGNER>" if re.search(r'["\u201c-\u201e$`%\x00-\x1f\x7f]', client.signer) else
                f'"{client.signer}"')
            cmd = "tracekit approvals" + (f" --signer {named}" if named else "")
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


_LINE_START = re.compile(r"\n[^\S\n]*")   # where a line's text starts, as _midline reads it


def _midline(prompt, start):
    """Whether the wrapper prompt_parts found at `start` follows other text on its line. Claude Code puts its own at the
    start of a line (the ultraplan handoff's sentence aside, _states)."""
    while start and prompt[start - 1] != "\n" and prompt[start - 1].isspace():
        start -= 1
    return start > 0 and prompt[start - 1] != "\n"


def _handoff(prompt, source, start):
    """Whether the part at `start` is Claude Code's ultraplan handoff, whose tag continues its own sentence."""
    return source == "ultraplan" and prompt[:start].lower().endswith("remote agent content enclosed in ")


def _states(prompt, source, value, start):
    """The live constraints (_live) a part of prompt_parts(prompt) states, read without its tags; none for an ultraplan
    handoff (_handoff)."""
    if _handoff(prompt, source, start):
        return []
    return _live(re.sub(r"<[^<>]*>", "", value[:constraints.MAX_TEXT]))


def midline_live(prompt, wrapped):
    """The live constraints of each part of `wrapped` (prompt_parts(prompt)) whose wrapper follows other text on its
    line (_midline): a wrapper's name the person typed in a sentence. They are live as well; the part stays untrusted,
    and a constraint only holds more calls."""
    return [c for source, value, start in wrapped if _midline(prompt, start)
            for c in _states(prompt, source, value, start)]


_WRAPPER_SOURCES = {
    "agent-message": "agent-message",
    "artifact-file-content": "artifact-file-content",
    "artifact-origin-notes": "artifact-origin-notes",
    "artifact-stored-declaration": "artifact-stored-declaration",
    "artifact-type-instructions": "artifact-type-instructions",
    "bash-exit-code": "bash-output",
    "bash-input": "person-command",
    "bash-stderr": "bash-output",
    "bash-stdout": "bash-output",
    "channel": "channel",
    "command-args": "command",
    "command-message": "command",
    "command-name": "command",
    "coordinator-relay": "coordinator-relay",
    "cowritten-artifact-html": "cowritten-artifact-html",
    "cross-session-message": "session-message",
    "fetched-web-content": "fetched-web-content",
    "function_results": "function-results",
    "local-command-caveat": "local-command-caveat",
    "local-command-stderr": "local-command-stderr",
    "local-command-stdout": "bash-output",
    "persisted-output": "persisted-output",
    "remote-review": "remote-review",
    "sandbox_violations": "sandbox-violations",
    "slack-ping": "slack-ping",
    "slack-tag-message": "slack-tag-message",
    "system-reminder": "system-reminder",
    "system_reminder": "system-reminder",
    "task-notification": "task-notification",
    "teammate-message": "teammate-message",
    "tick": "tick",
    "tool_use_error": "tool-use-error",
    "total_tokens": "total-tokens",
    "ultraplan": "ultraplan",
    "user-prompt-submit-hook": "user-prompt-submit-hook",
    "untrusted-uploads": "uploads",
    "wake": "external-event",
}
FRAME_TEXT = MAX_LINE - 4112
MAX_HARNESS_TEXT = FRAME_TEXT * 48
FRAME_OVERLAP = 2048
# lean: Wrapper spellings are harness details. An unrecognised wrapper is recorded as typed; Claude Code's paste-tag
# scrub, not its 16-bit session-shared paste id, keeps a pasted body from forging this boundary. Add observed spellings
# when a harness changes; upgrade to a signed harness-provided trust boundary if that stops being sufficient.


@functools.lru_cache(maxsize=2)
def _wrapped(agent):
    if agent == "claude-code":
        tags = "|".join(re.escape(tag) for tag in _WRAPPER_SOURCES)
        return re.compile(
            r'<pasted_content\s+id="([^"\s>]{1,128})">'
            r'|<pasted_content\b'
            r'|\[SYSTEM NOTIFICATION - NOT USER INPUT\]'
            r'|\[SCHEDULED TASK - AUTOMATED FIRING OF A CONFIGURED PROMPT\]'
            r'|\[MESSAGE FROM NON-USER SOURCE - NOT USER INPUT\]'
            r'|(?:(?:(?:Another Claude session|A peer session|The coordinator) sent a message'
            r'|A message arrived from \S{1,64})(?: while you were working)?:\s*)?'
            rf'<({tags})[\s>]'
            r'|(?:Another Claude session|A peer session|The coordinator|The \S{1,64} plugin) sent a message'
            r'(?: while you were working)?:'
            r'|Your background observer \([\w:-]{0,64}\) sent a report(?: while you were working)?:'
            r'|Base directory for this skill:', re.IGNORECASE | re.ASCII)
    if agent == "gemini-cli":
        return re.compile(r'--- Content from referenced files ---')
    return re.compile(r'(?!)')


def prompt_parts(prompt, agent=None):
    """Return (person-typed text, [(source, untrusted text, start)]) from a harness prompt. A wrapper other than a
    closed paste makes the rest of the prompt untrusted; one that follows other text on its line (_midline) is a part
    only up to the next wrapper that starts a line, where the next part (to the end) begins."""
    agent = AGENT if agent is None else agent
    typed, parts, pos, rest = [], [], 0, False   # rest: all from pos on is untrusted, past a mid-line wrapper's part
    wrapped = _wrapped(agent)
    while match := wrapped.search(prompt, pos):
        start = match.start()
        tag = (match.group(2) if match.lastindex and match.lastindex >= 2 else "") or ""
        tag = tag.lower()
        typed.append(prompt[pos:start])
        ident = match.group(1) if match.lastindex and not rest else None
        if ident:
            # Claude Code's scrub prevents a pasted body or typed text from forging its 16-bit session-shared id.
            close = f'</pasted_content id="{ident}">'
            at = prompt.find(close, match.end())
            if at >= 0:
                end = at + len(close)
                parts.append(("paste", prompt[start:end], start))
                pos = end
                continue
        if tag:
            source = _WRAPPER_SOURCES[tag]
        elif match.group(0).lower().startswith("<pasted_content"):
            source = "paste"
        elif match.group(0).lower().startswith("base directory"):
            source = "skill"
        elif agent == "gemini-cli":
            source = "referenced-file"
        elif "plugin sent a message" in match.group(0).lower():
            source = "plugin-message"
        elif "sent a message" in match.group(0).lower():
            source = "peer-message"
        elif match.group(0).lower().startswith("your background observer"):
            source = "observer-report"
        elif match.group(0).lower().startswith("[message from"):
            source = "non-user-message"
        else:
            source = "scheduled-task" if match.group(0).lower().startswith("[scheduled") else "system-notification"
        if not rest and _midline(prompt, start) and not _handoff(prompt, source, start):   # a name the person typed:
            # harness text after it starts a line
            # each line start in turn: a lead at the end of the person's line ("... sent a message:") would run on into
            # the wrapper on the next one, which a search for whole matches would then skip
            pos = next((n.end() for n in _LINE_START.finditer(prompt, start) if wrapped.match(prompt, n.end())), None)
            if pos is not None:
                parts.append((source, prompt[start:pos], start))
                rest = True
                continue
        parts.append((source, prompt[start:], start))
        break
    else:
        typed.append(prompt[pos:])
    return "".join(typed), parts


def _observe_value(values):
    """The largest prefix of untrusted `values` that leaves room for the observe frame."""
    limit = MAX_LINE - 4096  # run token, stream and source leave a small, bounded envelope

    def fits(value):
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) <= limit

    if fits(values):
        return values
    lo, hi = 0, len(values)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(values[:mid]):
            lo = mid
        else:
            hi = mid - 1
    if lo:
        return values[:lo]
    value = values[0]
    lo, hi = 0, len(value)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits([value[:mid]]):
            lo = mid
        else:
            hi = mid - 1
    return [value[:lo]]


def _observe_values(values, limit=MAX_HARNESS_TEXT):
    """Yield bounded observe frames, cutting long values at whitespace where possible."""
    values = deque(values)
    while values and limit > 0:
        frame, size = [], 0
        while values and limit > 0:
            value = values.popleft()
            room = min(FRAME_TEXT - size, limit)
            if not room:
                values.appendleft(value)
                break
            end = min(len(value), room)
            split = end < len(value)
            if split:
                boundary = max(value.rfind(c, 0, end) for c in " \t\n")
                if boundary >= end // 2:
                    end = boundary + 1
            frame.append(value[:end])
            size, limit = size + end, limit - end
            if value[end:]:   # the overlap is sent again, uncharged under the cap: a part's whole text fits its share
                back = min(FRAME_OVERLAP, end // 2)
                values.appendleft(value[end - back:])
                if limit > 0:
                    limit += back
                break
            if split or size == FRAME_TEXT or not limit:
                break
        chunk = _observe_value(frame)   # cut to the frame's bytes: text that isn't ASCII takes more than one each
        rest = frame[len(chunk):]
        if chunk and len(chunk[-1]) < len(frame[len(chunk) - 1]):   # its last item was cut: the rest goes back, with
            kept = len(chunk[-1])                                     # an overlap so a value across the cut stays whole
            rest.insert(0, frame[len(chunk) - 1][kept - min(FRAME_OVERLAP, kept // 2):])
        values.extendleft(reversed(rest))
        limit += sum(map(len, rest))
        yield chunk


def prompted(run, prompt):
    """Each live constraint the harness prompt `prompt` states as the hook reads it (its typed text, then midline_live),
    as a live constraint of `run`, each on its own (module docstring). -> whether the signer took one only as a refusal
    past its cap (_constrain)."""
    typed, wrapped = prompt_parts(prompt)
    refused, full = [], False
    for kind, obj in dict.fromkeys(_live(typed) + midline_live(prompt, wrapped)):
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
    """Removes the runtime state no hook has written for a while: a session's after SESSION_KEEP_S, as it carries the
    session's constraints and transcript to its later runs (after an idle close, or a resume); any other (a tool
    call's, which one that never got its PostToolUse leaves behind, or a lock no state needs) after the signer's
    default run idle timeout, when the signer has closed its run."""
    from tracekit.signer.service import IDLE_S
    now = time.time()
    for f in sorted(glob.glob(os.path.join(glob.escape(autospawn.runtime_dir()), "claude-code-*")),
                    key=lambda f: f.endswith(".lock")):   # the state first, then the locks it no longer needs
        # lean: a lock goes only once its session state has; a hook that resumes that very session at this instant
        # could lock a fresh file beside one still held, so two runs get registered, rare enough for dev mode
        if f.endswith(".lock") and os.path.exists(f[:-len(".lock")] + ".json"):
            continue
        session = f.endswith(".json") and os.path.basename(f).count(".") == 1   # not claude-code-<sid>.<call>.json
        try:
            if os.path.getmtime(f) < now - (SESSION_KEEP_S if session else IDLE_S):
                os.remove(f)
        except OSError:   # removed by a parallel hook
            pass


@functools.lru_cache(maxsize=256)
def _tool_class(tool):
    # lean: the class in the dev signer's default policy; a signer with another policy may class the tool otherwise
    from tracekit.signer.service import load_policy
    return load_policy().tool_class(tool)


def _handle(client, p, event, sid, tid):
    if event == "PreToolUse":
        return _pre(client, p, sid, tid)
    if event in TOOL_EVENTS:
        return _post(client, p, sid, tid)
    if event == "SessionEnd":   # not at Stop: a background subagent's call may still be running then
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
    transcript, prompt = _transcript(p), p.get("prompt") if event == "UserPromptSubmit" else None
    if event == "SessionStart":
        _prune()
    if isinstance(prompt, str) and prompt:   # the harness's submitted prompt, including harness wrappers
        source = p.get("source") if AGENT == "claude-code" else None
        if source in (None, "user", "sdk"):
            typed, wrapped = prompt_parts(prompt)
        else:   # a turn no person typed (system, loop_wakeup, schedule_wakeup, poll_event): untrusted as a whole
            name = source if isinstance(source, str) and re.fullmatch(r"[a-z_]{1,64}", source) else "non-user"
            typed, wrapped = "", [(name, prompt, 0)]
        stated = [*dict.fromkeys(_live(typed) + (midline_live(prompt, wrapped) if AGENT == "claude-code" else []))]
        live = set(stated)
        unexpected = {}
        if AGENT == "claude-code":
            for source, value, start in wrapped:
                if not _midline(prompt, start):
                    for constraint in _states(prompt, source, value, start):
                        if constraint not in live:
                            unexpected.setdefault(constraint, source)
        try:   # its constraints first: a prompt too large for one observe frame still adds them
            refused = _run(client, sid, transcript=transcript, stated=stated)[1]
        finally:
            errors = []
            try:
                _run(client, sid, send="observe", transcript=transcript, source=f"{AGENT}:UserPromptSubmit",
                     trust="trusted", value=typed)
            except Exception as e:
                errors.append(e)
            grouped = {}
            for source, value, _ in wrapped:
                grouped.setdefault(source, []).append(value)
            cut, sources = [], list(grouped.items())
            for index, (source, values) in enumerate(sources):
                text_size = sum(map(len, values))
                share, extra = divmod(MAX_HARNESS_TEXT, len(sources))
                recorded = min(text_size, share + (index < extra))
                for value in _observe_values(values, recorded):
                    try:
                        _run(client, sid, send="observe", transcript=transcript, source=f"{AGENT}:{source}",
                             trust="untrusted", value=value)
                    except Exception as e:
                        errors.append(e)
                if recorded < text_size:
                    cut.append(source)
            if errors:
                raise errors[0]
        messages = []
        if unexpected and AGENT == "claude-code":
            sources = ", ".join(sorted(set(unexpected.values())))
            names = sorted(f"keep away from {obj}" if kind == "keep_away" else
                           {"read_only": "read-only", "no_push": "don't push", "no_network": "no network"}[kind]
                           for kind, obj in unexpected)
            shown, more = names[:3], len(names) - 3
            detail = ", ".join(shown) + (f" and {more} more" if more > 0 else "")
            messages.append(f"[tracekit] {len(unexpected)} constraint(s) in text you pasted or the harness added "
                            f"({sources}: {detail}) were recorded, not made live")
        if cut:   # the cut text is an observation the signer never gets: one client_seq skipped says so (_send)
            _run(client, sid, send="observe", skip=1, transcript=transcript, source=f"{AGENT}:harness-cut",
                 trust="untrusted",
                 value=f"Harness text was cut after {MAX_HARNESS_TEXT} characters ({', '.join(cut)}).")
            messages.append(f"[tracekit] oversized untrusted text was cut after {MAX_HARNESS_TEXT} characters "
                            f"({', '.join(cut)}); for the rest of the run a from: untrusted rule applies to every "
                            f"call its pattern matches, whatever the value's source")
        if messages and AGENT == "claude-code":   # Claude Code then shows this, not stderr: FULL goes here too
            print(json.dumps({"systemMessage": "\n".join([FULL] * bool(refused) + messages)}))
        return 1 if refused else 0   # shown to the person (FULL, on stderr), never blocking the prompt
    # SessionStart, or any other first event of the session, registers the run; a resumed (or forked) session's
    # transcript holds its earlier history, which earlier runs recorded
    _run(client, sid, transcript=transcript, start=p.get("source") if event == "SessionStart" else None)
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
                from tracekit.doctor import REINIT   # system mode's init (docs/deploy.md); a rare path, loaded here
                fix = (". This host is in v1 system mode (the system config names no v2 signer): set up v2 system "
                       f"mode, {REINIT} (--no-hooks with the Claude Code plugin)")
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
