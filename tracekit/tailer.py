"""L1 transcript tailer (04-design §6): follows one Claude Code session transcript and reports it to the signer.

    python -I -m tracekit.tailer   (started by the v2 hook at SessionStart; the run handle comes on stdin as JSON:
                                    {"run_id", "run_token", "path", "until"?})

Dev mode: a detached process of the agent's own user, which exits once the hook's session state (`until`) is gone
(SessionEnd). System mode (`tracekit init --v2`): run through sudo as the tracekit-tailer user, which reads the agent's
~/.claude/projects through an ACL and nothing of the signer's. It calls the signer as its own uid with a token the hook
delegated (`delegate_run`), and signer.yaml lets that uid call only model_event, state_write, tailer_lost and status.

The transcript is opened once, with O_NOFOLLOW, and must be a regular file of the agent's uid (the root-owned system
config names the agent; dev mode: our own uid); the fd is kept. On every wake (inotify on the transcript's directory on
Linux, else a poll) its size may not go backwards, the path must still be that same file, of that uid, and each new
complete line must be a JSON object. Otherwise the tailer sends `tailer_lost` (the signer writes the signed gap, the
tailer never writes one) and exits. An assistant line with tool_use blocks becomes a model_event response (exchange id:
the message id; each tool use with the digest of its arguments; the tool results sent since the last one); a user
prompt becomes a model_event request carrying only the prompt's digest, which the signer publishes as a salted
commitment. It also exits once the signer says the run is over, or after IDLE_S without a new line.
"""
import ctypes
import json
import os
import select
import stat
import sys
import time

from tracekit.client import system_config
from tracekit.format.canon import event_hash
from tracekit.hook import transcript_entries
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import IDLE_S

POLL_S = 1.0
ENDED = ("run_closed", "unknown_run", "run_token_invalid")
IN_EVENTS = 0x2 | 0x4 | 0x40 | 0x80 | 0x100 | 0x200   # MODIFY, ATTRIB, MOVED_FROM, MOVED_TO, CREATE, DELETE


class Lost(Exception):
    pass


def _open(path, uid):
    try:   # O_NONBLOCK: a FIFO put in its place must not block the open
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
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


def _report(run, e, sent):
    """The model_event of one transcript entry, if it has one; `sent` collects tool result ids between responses."""
    msg = e.get("message") if isinstance(e.get("message"), dict) else {}
    content = msg.get("content")
    blocks = [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []
    if e.get("type") == "assistant":
        uses = [b for b in blocks if b.get("type") == "tool_use"]
        if uses:
            run.call("model_event", provider="anthropic", model=str(msg.get("model") or "unknown")[:128],
                     phase="response", exchange_id=msg.get("id"),
                     tool_uses=[{"id": b.get("id"), "name": b.get("name"), "executed_by": "client",
                                 "args_source": "parsed",
                                 "args_digest": event_hash({"tool": b.get("name"), "args": b.get("input")})}
                                for b in uses], tool_results_sent=list(sent))
            sent.clear()
    elif e.get("type") == "user":
        if isinstance(content, str) or any(b.get("type") == "text" for b in blocks):
            run.call("model_event", provider="anthropic", model="unknown", phase="request",
                     exchange_id=e.get("uuid"), content_digest=event_hash(content))
        sent += [b.get("tool_use_id") for b in blocks if b.get("type") == "tool_result"]


def tail(run, path, uid, until=None, wait=None):
    """Follow `path` for `run` until the run ends, `until` is gone, or the transcript is lost (reported)."""
    wait, f, off, sent, grew = wait or _waiter(path), None, 0, [], time.monotonic()
    try:
        while True:
            ending = (until is not None and not os.path.exists(until)) or time.monotonic() - grew > IDLE_S
            if f is None and os.path.lexists(path):   # Claude Code may create it only after SessionStart
                f = _open(path, uid)
            if f is not None:
                _check(f, path, uid, off)
                f.seek(off)
                try:
                    for n, e in transcript_entries(f):
                        if e is None:
                            raise Lost(f"the line at offset {off} is not a JSON object")
                        try:
                            _report(run, e, sent)
                        except SignerUnavailable:
                            raise
                        except RPCError as x:
                            if x.code in ENDED:
                                raise
                            raise Lost(f"the line at offset {off} was refused: {x.message[:256]}") from None
                        except Exception as x:   # e.g. a number canonical JSON cannot hold
                            raise Lost(f"the line at offset {off} is unreadable ({type(x).__name__})") from None
                        off += n
                        grew = time.monotonic()
                except SignerUnavailable:   # read again from `off` on the next wake
                    pass
            if ending:
                return
            wait()
    except Lost as e:
        run.call("tailer_lost", reason=str(e), offset=off)
    except RPCError as e:
        if e.code not in ENDED:
            raise
    finally:
        if f is not None:
            f.close()


def main():
    h = json.loads(sys.stdin.read())
    sc = system_config() or {}
    import pwd   # POSIX only, as the tailer is
    uid = pwd.getpwnam(sc["hooks"]["user"]).pw_uid if sc.get("signer") else os.getuid()
    client = Client()
    try:
        tail(RunHandle(client, h), h["path"], uid, h.get("until"))
    except RPCError as e:   # the run ended while the loss was being reported
        if e.code not in ENDED:
            raise
    finally:
        client.close()


if __name__ == "__main__":
    main()
