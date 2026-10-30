"""L1 transcript tailer (04-design §6): follows one Claude Code session transcript and reports it to the signer.

    python -I -m tracekit.tailer   (started by the v2 hook at SessionStart; the run handle comes on stdin as JSON:
                                    {"run_id", "run_token", "path", "until"?, "offsets"?})

`offsets` ({path: offset}): where to start reading the session's transcripts, for a run after the session's first (an
idle close, a resumed session): the lines before are an earlier run's (the hook measures them, as it names the path).

Dev mode: a detached process of the agent's own user, which exits once the hook's session state (`until`) is gone
(SessionEnd). System mode (`tracekit init --v2`): run through sudo as the tracekit-tailer user, which reads the agent's
~/.claude/projects through an ACL and nothing of the signer's. It calls the signer as its own uid with a token the hook
delegated (`delegate_run`), and signer.yaml lets that uid call only model_event, state_write, tailer_lost,
tailer_heartbeat and status.

The transcript is opened once, with O_NOFOLLOW, and must be a regular file of the agent's uid (the root-owned system
config names the agent; dev mode: our own uid); the fd is kept. On every wake (inotify on the transcript's directory on
Linux, else a poll) its size may not go backwards, the path must still be that same file, of that uid, the bytes
already read may not have changed (rehashed whenever the file's ctime moves), and each new complete line must be a JSON
object. Otherwise the tailer sends `tailer_lost` (the signer writes the signed gap, the
tailer never writes one) and exits. Every assistant line (Claude Code writes one per content block: thinking, text,
tool use) becomes a model_event response (exchange id: the message id; a tool_use line's tool uses with the digest of
their arguments, and the tool results sent since the last one); a user prompt becomes a model_event request. Each
carries the digest of the line as read, {"transcript": "main" or the subagent file's name, "entry": the whole line,
its cwd, isMeta, isSidechain and isCompactSummary included}, which the signer publishes as a salted commitment, and
that as its `body` when the signer keeps content (the content vault, docs/privacy.md); without the vault the text
stays in the transcript. A rate limit (quota_exceeded with retry_after_ms) sends the line again once it has passed.
It exits once the signer says the run is over, or (dev mode) once `until` is gone. A transcript that never
appears or cannot be reached, and a tailer that stops after IDLE_TAILER_S without a new line, are a tailer_lost too.
Every HEARTBEAT_S it sends `tailer_heartbeat` (another refusal, e.g. a quota, is tried again at the next); a tailer that
is killed stops them, and the signer writes the tailer_lost gap itself (a signer that does not know the call, or a token
not granted it, just gets none).
The session's subagents' transcripts (<session>/subagents/agent-*.jsonl, next to the session's, and a workflow's agents'
in <session>/subagents/workflows/<workflow>/) are followed the same way, with the same checks, from the wake they
appear on: a call one of them makes is decided under the session's run.
"""
import ctypes
import hashlib
import io
import json
import os
import select
import stat
import sys
import time
import uuid

from tracekit.client import system_config
from tracekit.format.canon import event_hash
from tracekit.hook import transcript_entries
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, VaultBody
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import HEARTBEAT_S, IDLE_S

POLL_S = 1.0
# lean: twice the signer's default run idle timeout, so a quiet run has closed before the tailer gives up on it; ask the
# signer for the run's state instead if signers run with a longer idle_s
IDLE_TAILER_S = 2 * IDLE_S
ENDED = ("run_closed", "unknown_run", "run_token_invalid")
IN_EVENTS = 0x2 | 0x4 | 0x40 | 0x80 | 0x100 | 0x200   # MODIFY, ATTRIB, MOVED_FROM, MOVED_TO, CREATE, DELETE


class Lost(Exception):
    pass


def _open(path, uid):
    """The transcript, kept open; None while it does not exist (Claude Code may create it only after SessionStart)."""
    try:   # O_NONBLOCK: a FIFO put in its place must not block the open
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:   # e.g. EACCES: no read access, or no search on a directory above it
        raise Lost(f"cannot open the transcript: {e.strerror}") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid:
        os.close(fd)
        raise Lost(f"the transcript is not a regular file of uid {uid}")
    return os.fdopen(fd, "rb")


def _check(f, path, uid, off):
    st = os.fstat(f.fileno())
    if st.st_size < off:
        raise Lost(f"the transcript shrank to {st.st_size} bytes (truncated)")
    if st.st_uid != uid:
        raise Lost(f"the transcript's owner changed to uid {st.st_uid}")
    try:
        now = os.lstat(path)
    except OSError as e:
        raise Lost(f"the transcript path is gone: {e.strerror}") from None
    if stat.S_ISLNK(now.st_mode):
        raise Lost("a symlink replaced the transcript")
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
        raise Lost("another file replaced the transcript")


def _sha256(f, n, h=None):
    """`h` (a new sha256) updated with the transcript's first n bytes."""
    h = h or hashlib.sha256()
    f.seek(0)
    while n > 0 and (b := f.read(min(n, 1 << 20))):
        h.update(b)
        n -= len(b)
    return h


def _waiter(path):
    """wait(): returns on a change in the transcript's directory (inotify, Linux) or after POLL_S."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    except (OSError, AttributeError):   # no inotify here
        fd = -1
    if fd >= 0 and libc.inotify_add_watch(fd, os.fsencode(os.path.dirname(os.path.abspath(path))), IN_EVENTS) < 0:
        os.close(fd)
        fd = -1
    if fd < 0:
        return lambda: time.sleep(POLL_S)

    def wait():
        if select.select([fd], [], [], POLL_S)[0]:
            os.read(fd, 65536)
    return wait


class _Sender:
    """The tailer's model_events, on an event stream of its own: a line the signer rate-limits (quota_exceeded with
    retry_after_ms) is sent again with the same client_seq once that has passed, which leaves no client_counter_gap.
    `body(read)`: the line's body when the signer keeps content (`status()`: its status answer; VaultBody)."""

    def __init__(self, run, status=None):
        self.run, self.vault, self.stream, self.seq = run, VaultBody(status) if status else None, uuid.uuid4().hex, 0

    def body(self, read):
        return self.vault(read) if self.vault else {}

    def __call__(self, **fields):
        while True:
            try:
                out = self.run.call("model_event", stream=self.stream, client_seq=self.seq, **fields)
            except RPCError as x:
                if x.code == "quota_exceeded" and x.retry_after_ms is not None:
                    time.sleep(min(x.retry_after_ms, 5000) / 1000)
                    continue
                self.seq += 1
                raise
            except SignerUnavailable:   # the signer may have it: the next event takes the next value
                self.seq += 1
                raise
            self.seq += 1
            return out


def _report(send, e, sent, name="main"):
    """The model_event of one transcript entry, if it has one (`send`, a _Sender); `sent` collects tool result ids
    between responses; `name`: the transcript it came from."""
    msg = e.get("message") if isinstance(e.get("message"), dict) else {}
    content = msg.get("content")
    blocks = [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []
    read = {"transcript": name, "entry": e}
    if e.get("type") == "assistant" and blocks:
        uses = [b for b in blocks if b.get("type") == "tool_use"]
        mid = msg.get("id")
        send(provider="anthropic", model=str(msg.get("model") or "unknown")[:128], phase="response",
             **({"exchange_id": mid} if uses or isinstance(mid, str) else {}), content_digest=event_hash(read),
             **send.body(read), **({"tool_uses": [{"id": b.get("id"), "name": b.get("name"), "executed_by": "client",
                                                   "args_source": "parsed",
                                                   "args_digest": event_hash({"tool": b.get("name"),
                                                                              "args": b.get("input")})}
                                                  for b in uses], "tool_results_sent": list(sent)} if uses else {}))
        if uses:
            sent.clear()
    elif e.get("type") == "user":
        if isinstance(content, str) or any(b.get("type") == "text" for b in blocks):
            send(provider="anthropic", model="unknown", phase="request", exchange_id=e.get("uuid"),
                 content_digest=event_hash(read), **send.body(read))
        sent += [b.get("tool_use_id") for b in blocks if b.get("type") == "tool_result"]


class _Transcript:
    """One transcript being followed: its kept file, how far it was read, and the digest of the bytes before that."""

    def __init__(self, path, name="main", off=0):
        self.path, self.name, self.f, self.off, self.sent = path, name, None, off, []
        self.read, self.checked = hashlib.sha256(), None   # the bytes before `off`; the ctime they were last checked at


def _listed(*dirs):
    """The sorted names in the last of `dirs`, none of which may be a symlink; none while one does not exist or is no
    directory."""
    try:
        for p in dirs:
            if stat.S_ISLNK(os.lstat(p).st_mode):
                raise Lost(f"a symlink is in place of {p}")
        return sorted(os.listdir(dirs[-1]))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:
        raise Lost(f"cannot list the subagent transcripts: {e.strerror}") from None


def _subagents(path):
    """The paths of the session's subagent transcripts: Claude Code writes them to <session>/subagents/agent-*.jsonl,
    and those of a workflow's agents to <session>/subagents/workflows/<workflow>/agent-*.jsonl."""
    d = os.path.join(os.path.splitext(path)[0], "subagents")
    w = os.path.join(d, "workflows")
    found = [os.path.join(d, n) for n in _listed(os.path.dirname(d), d)]
    found += [os.path.join(w, x, n) for x in _listed(w) for n in _listed(os.path.join(w, x))]
    return [p for p in found if os.path.basename(p).startswith("agent-") and p.endswith(".jsonl")]


def _follow(send, t, uid):
    """Report transcript t's new complete lines (`send`, a _Sender). -> whether it grew."""
    if t.f is None:
        t.f = _open(t.path, uid)
        if t.f is None:
            return False
        _sha256(t.f, t.off, t.read)   # an earlier run's lines, from here on checked as the ones it reads
    _check(t.f, t.path, uid, t.off)
    ctime = os.fstat(t.f.fileno()).st_ctime_ns   # any write moves it, and no user can set it back
    if ctime != t.checked:
        # lean: rehashes all it has read on every change to the file; keep per-block hashes and re-read
        # only the blocks whose bytes changed if transcripts reach hundreds of MB
        if _sha256(t.f, t.off).digest() != t.read.digest():
            raise Lost("a line already read changed in place")
        # a ctime this recent may not move for a change in the same clock tick: check it again next wake
        t.checked = ctime if time.time_ns() - ctime > 1_000_000_000 else None
    t.f.seek(t.off)
    data, start = t.f.read(), t.off
    try:
        for n, e in transcript_entries(io.BytesIO(data)):
            if e is None:
                raise Lost(f"the line at offset {t.off} is not a JSON object")
            try:
                _report(send, e, t.sent, t.name)
            except SignerUnavailable:
                raise
            except RPCError as x:
                if x.code in ENDED:
                    raise
                raise Lost(f"the line at offset {t.off} was refused: {x.message[:256]}") from None
            except Exception as x:   # e.g. a number canonical JSON cannot hold
                raise Lost(f"the line at offset {t.off} is unreadable ({type(x).__name__})") from None
            t.off += n
    except SignerUnavailable:   # read again from `off` on the next wake
        pass
    t.read.update(data[:t.off - start])
    return t.off > start


def _heartbeat(run):
    """tailer_heartbeat; -> when it was sent (or tried: a signer that can't take it now gets the next), or None when
    this token is not granted heartbeats or the signer doesn't know them (stop sending)."""
    try:
        run.call("tailer_heartbeat")
    except SignerUnavailable:
        pass
    except RPCError as e:
        if e.code in ENDED:
            raise
        if e.code in ("forbidden", "invalid_request"):   # not granted, or a signer before 1.2 (unknown method)
            return None
    return time.monotonic()


def tail(run, path, uid, until=None, wait=None, status=None, offsets=None):
    """Follow `path`, and its subagents' transcripts, for `run` until the run ends, `until` is gone, or a transcript is
    lost (reported). `status()`: the signer's status answer, which says whether it keeps content (VaultBody);
    `offsets` {path: offset}: where to start each (module docstring)."""
    wait, grew, beat = wait or _waiter(path), time.monotonic(), -HEARTBEAT_S
    send = _Sender(run, status)
    # lean: keeps one file open per subagent transcript; close quiet ones and reopen them by (dev, inode) if sessions
    # run more subagents than the tailer's file limit
    start = {p: o for p, o in (offsets.items() if isinstance(offsets, dict) else ()) if type(o) is int and o >= 0}
    main = cur = _Transcript(path, off=start.get(path, 0))
    ts = {path: main}
    try:
        while True:
            gone, idle = until is not None and not os.path.exists(until), time.monotonic() - grew > IDLE_TAILER_S
            cur = main
            for p in _subagents(path) if main.f is not None else ():
                ts.setdefault(p, _Transcript(p, os.path.basename(p), start.get(p, 0)))
            for cur in ts.values():
                if _follow(send, cur, uid):
                    grew = time.monotonic()
            cur = main
            if main.f is None and (gone or idle):
                raise Lost("the transcript never appeared")
            if idle:
                raise Lost(f"no new transcript line for {IDLE_TAILER_S:.0f}s: the tailer stopped")
            if gone:
                return
            if beat is not None and time.monotonic() - beat >= HEARTBEAT_S:
                beat = _heartbeat(run)
            wait()
    except Lost as e:
        name = "" if cur is main else f"subagent transcript {os.path.basename(cur.path)}: "
        run.call("tailer_lost", reason=name + str(e), offset=cur.off)
    except RPCError as e:
        if e.code not in ENDED:
            raise
    finally:
        for t in ts.values():
            if t.f is not None:
                t.f.close()


def main():
    h = json.loads(sys.stdin.read())
    sc = system_config() or {}
    import pwd   # POSIX only, as the tailer is
    uid = pwd.getpwnam(sc["hooks"]["user"]).pw_uid if sc.get("signer") else os.getuid()
    client = Client()
    try:
        tail(RunHandle(client, h), h["path"], uid, h.get("until"), status=lambda: client.status({}),
             offsets=h.get("offsets"))
    except RPCError as e:   # the run ended while the loss was being reported
        if e.code not in ENDED:
            raise
    finally:
        client.close()


if __name__ == "__main__":
    main()
