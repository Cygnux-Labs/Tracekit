"""Find or start the same-user dev signer (decision S3).

The runtime dir (0700, ours) holds `signer.lock`, which the signer locks for its whole life before it touches anything
else (the kernel drops the lock when the process dies, so liveness never depends on pids); `spawn.lock`, which a
client holds while it decides whether to start one; `signer.sock`; `endpoint.json` ({"pid", "data_dir", ...}, written
by the signer after it binds; without Unix sockets also the loopback port and token, decision S3) and `signer.log`. A
dev signer whose protocol range ends below this client's (one from before an upgrade) is stopped and replaced, with a
warning; a newer one is refused and left running, so an old client never downgrades it: only `tracekit up --replace`
stops that one.

The data dir is per HOME, the runtime dir per user where it can't be (macOS's /tmp fallback for a long HOME, Linux's
$XDG_RUNTIME_DIR): a client uses the dev signer of its own data dir only, the one whose `data_dir` (hello and
endpoint.json) is this HOME's; a signer from before 1.4 names none, and is this HOME's when this data dir's store is
held. While the runtime dir's signer serves another data dir, this one's runs in the sibling `<runtime dir>-<12 hex of
the data dir's path>` (signer_dir).

Off in system mode and when TRACEKIT_SIGNER is set: an agent must not be able to substitute its own signer there.
"""
import hashlib
import json
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import warnings

from tracekit import __version__
from tracekit.client import SYSTEM_CONFIG
from tracekit.locking import lock_file, unlock_file
from tracekit.sdk.client import Incompatible, SignerUnavailable, _default_signer, connect
from tracekit.signer.rpc_schema import RPC_VERSION

SOCK, LOCK, SPAWN_LOCK, ENDPOINT, LOG = "signer.sock", "signer.lock", "spawn.lock", "endpoint.json", "signer.log"
# -P (3.11+) keeps the working directory off sys.path; before 3.11 it is there, and spawn() makes it the private runtime
# dir. Not -I, which also drops the PYTHONPATH a checkout without an install needs.
PYTHON = [sys.executable, *(["-P"] if sys.version_info >= (3, 11) else [])]
SIGNER_ARGV = [*PYTHON, "-m", "tracekit", "signer", "serve", "--dev"]
_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "LOCALAPPDATA",
        "SYSTEMROOT", "PYTHONPATH")   # SYSTEMROOT: Windows sockets need it


class Hung(SignerUnavailable):
    pass


class _Theirs(Exception):
    """The runtime dir's dev signer serves another data dir: another HOME of this user's."""


def _short(d):
    """`d`, or when its socket path is too long to bind (macOS caps socket paths at 104 bytes) a short dir of its own,
    /tmp/tk-<uid>.<12 hex of its path>: the same for every client and signer given `d`, and never another dir's (a
    side dir is `<dir>-<hex>`)."""
    if not hasattr(socket, "AF_UNIX") or len(os.path.join(d, SOCK).encode()) <= 103:
        return d
    return f"/tmp/tk-{os.getuid()}.{hashlib.sha256(os.path.realpath(d).encode()).hexdigest()[:12]}"


def runtime_dir(create=True):
    """The per-user runtime dir ($TRACEKIT_RUNTIME_DIR overrides; one too long for a socket path gives way to a short
    one of its own, _short), created 0700 (with create=False, OSError while it does not exist); refused unless it is
    ours and private (on POSIX; Windows has no uid, so it relies on the user-only profile ACL as S3 decides)."""
    d = os.environ.get("TRACEKIT_RUNTIME_DIR")
    if not d and os.name == "nt":
        d = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "tracekit", "run")
    elif not d and sys.platform == "darwin":
        d = os.path.expanduser("~/Library/Application Support/tracekit/run")
        if len(os.path.join(d, SOCK).encode()) > 103:   # macOS caps socket paths at 104 bytes
            d = f"/tmp/tk-{os.getuid()}"
    elif not d:
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        d = os.path.join(xdg, "tracekit") if xdg else f"/tmp/tracekit-{os.getuid()}"
    return _private(_short(d), create)


def _private(d, create):
    """`d`, created 0700 with `create`, once it is a directory that is ours and private."""
    if create:
        os.makedirs(d, 0o700, exist_ok=True)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or os.name == "posix" and (st.st_uid != os.getuid() or st.st_mode & 0o077):
        raise SignerUnavailable(f"{d} must be a directory owned by you with mode 0700")
    return d


def data_dir():
    """The dev signer's data dir (keys and store) for this HOME; the signer's dev_data_dir creates it."""
    if os.name == "nt":
        return os.path.join(os.environ["LOCALAPPDATA"], "tracekit")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/tracekit/data")
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "tracekit")


def _side(d):
    """This data dir's own sibling of runtime dir `d`: short, as macOS caps socket paths."""
    return _short(f"{d}-{hashlib.sha256(os.path.realpath(data_dir()).encode()).hexdigest()[:12]}")


def _ours(published):
    """Whether data dir `published` (a signer's) is this HOME's."""
    return os.path.realpath(str(published)) == os.path.realpath(data_dir())


def _theirs(d):
    """Whether the live dev signer of runtime dir `d` serves another data dir than this HOME's. One still starting
    (no endpoint.json yet) isn't known to; one from before 1.4 names none, and holds this data dir's store if it is
    this HOME's."""
    try:
        with open(os.path.join(d, ENDPOINT)) as f:
            ep = json.load(f)
    except (OSError, ValueError):
        return False
    if not isinstance(ep, dict) or not _held(os.path.join(d, LOCK)):
        return False
    return not _ours(ep["data_dir"]) if "data_dir" in ep else not _held(os.path.join(data_dir(), "store", "lock"))


def signer_dir(create=True):
    """The runtime dir of this HOME's dev signer: the per-user one, or its sibling (_side) while this data dir's
    signer runs there or the per-user one's serves another data dir."""
    d = runtime_dir(create)
    side = _side(d)
    return _private(side, create) if _held(os.path.join(side, LOCK)) or _theirs(d) else d


def _held(path):
    """True while some process holds the lock on `path`."""
    if not os.path.exists(path):   # its holder creates it first
        return False
    with open(path, "a") as f:
        try:
            lock_file(f, blocking=False)
        except OSError:
            return True
        unlock_file(f)
        return False


def address(d):
    """(path, token) for `connect` to the dev signer of runtime dir `d`: its Unix socket, or where there are none the
    loopback port and token it published in endpoint.json, which must be ours and private. OSError or ValueError while
    nothing is published."""
    if hasattr(socket, "AF_UNIX"):
        return os.path.join(d, SOCK), None
    with open(os.path.join(d, ENDPOINT)) as f:
        st = os.fstat(f.fileno())
        if os.name == "posix" and (st.st_uid != os.getuid() or st.st_mode & 0o077):
            raise SignerUnavailable(f"{f.name} must be owned by you and readable by no one else")
        ep = json.load(f)
    if not isinstance(ep, dict) or not isinstance(ep.get("port"), int) or not isinstance(ep.get("token"), str):
        raise ValueError(f"{f.name} has no port and token yet")
    return f"tcp://127.0.0.1:{ep['port']}", ep["token"]


def _try(d):
    """A connection to the dev signer of runtime dir `d`, or None while none answers. _Theirs when it serves another
    data dir than this HOME's."""
    try:
        path, token = address(d)
    except (OSError, ValueError):
        return None
    try:
        conn = connect(path, token=token)
    except SignerUnavailable:
        return None
    except Incompatible:
        if _theirs(d):   # another HOME's: never stopped or refused for this one
            raise _Theirs() from None
        raise
    if "data_dir" in conn[2] and not _ours(conn[2]["data_dir"]):
        conn[0].close()
        raise _Theirs()
    return conn


def _published(d):
    """endpoint.json's fields, {} while there is none."""
    try:
        with open(os.path.join(d, ENDPOINT)) as f:
            ep = json.load(f)
    except (OSError, ValueError):
        return {}
    return ep if isinstance(ep, dict) else {}


def _pid(d):
    """endpoint.json's pid; None while it names none, or one no signal may go to: 0 and a negative pid signal a
    process group or every process of the user, and 1 is init."""
    pid = _published(d).get("pid")
    return pid if type(pid) is int and pid > 1 else None


def _env(d):
    env = {k: v for k, v in os.environ.items() if k in _ENV or k.startswith(("LC_", "TRACEKIT_"))}
    env["TRACEKIT_RUNTIME_DIR"] = d
    return env


def _starts_ours(d):
    """True when the signer spawn(d) starts would serve this client. Not when `python -m tracekit` there runs an older
    Tracekit than this process imports (a checkout over an older install, a downgrade under a running process): that
    signer would be refused too, and every client would stop the shared one again."""
    try:
        lo, hi = map(int, subprocess.run([*PYTHON, "-c", "from tracekit.signer.rpc_schema import RPC_MIN, RPC_VERSION; "
                                          "print(RPC_MIN, RPC_VERSION)"], capture_output=True, text=True, cwd=d,
                                         env=_env(d), timeout=30, check=True).stdout.split())
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return lo <= RPC_VERSION <= hi


def spawn(d):
    """Start a detached `tracekit signer serve --dev` for runtime dir `d`."""
    env = _env(d)
    with open(os.path.join(d, LOG), "ab") as log:
        p = subprocess.Popen(SIGNER_ARGV, stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=d, env=env,
                             start_new_session=True, umask=0o077)
    threading.Thread(target=p.wait, daemon=True).start()   # reap it if it exits while we live
    return p


def ensure(wait=True, timeout=10):
    """A connection (socket, rfile, hello) to a compatible dev signer of this HOME's data dir, starting one if none
    runs. With wait=False, None once a new signer has been started. Raises Incompatible, Hung or SignerUnavailable."""
    if os.environ.get("TRACEKIT_SIGNER") or os.path.exists(SYSTEM_CONFIG):
        raise SignerUnavailable("dev auto-spawn is off when TRACEKIT_SIGNER is set or in system mode")
    d = signer_dir()
    try:
        return _ensure(d, wait, timeout)
    except _Theirs:   # another HOME's signer took the runtime dir meanwhile
        return _ensure(_private(_side(d), True), wait, timeout)


def _ensure(d, wait, timeout):
    lock = os.path.join(d, LOCK)
    try:
        conn = _try(d)
    except Incompatible as e:
        if not e.older:
            raise
        conn = None
    if conn:
        return conn
    with open(os.path.join(d, SPAWN_LOCK), "a") as spawn_lock:
        lock_file(spawn_lock)
        try:
            conn = _try(d)
        except Incompatible as e:
            if not e.older:   # newer than this client: an old client never downgrades it
                raise
            if not _starts_ours(d):
                raise Incompatible(f"{e}. `{sys.executable} -m tracekit` runs an older Tracekit than this process "
                                   "imports: install this version") from None
            warnings.warn(f"tracekit: stopped the dev signer from an older Tracekit (pid {down(timeout, d, show_log=False)}) to "
                          f"start this one's ({__version__})", stacklevel=3)
            conn = None
        if conn:
            return conn
        p, deadline = None, time.monotonic() + timeout
        while True:
            # nothing alive (or the signer that was stopping has exited): whatever is left belongs to a dead signer
            if p is None and not _held(lock):
                for f in (os.path.join(d, SOCK), os.path.join(d, ENDPOINT)):
                    pathlib.Path(f).unlink(missing_ok=True)
                p, deadline = spawn(d), time.monotonic() + timeout
                if not wait:   # once it holds signer.lock, so a `tracekit down` straight after finds it starting
                    while not _held(lock) and p.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    return None
            conn = _try(d)
            if conn:
                return conn
            exited = p is not None and p.poll() is not None
            if time.monotonic() > deadline or (exited and not _held(lock)):
                break
            time.sleep(0.02)
    if _held(lock):
        raise Hung(f"a dev signer (pid {_pid(d)}) holds {lock} but does not answer; see {os.path.join(d, LOG)}")
    raise SignerUnavailable(f"the dev signer did not start ({_last_line(os.path.join(d, LOG))}); see "
                            f"{os.path.join(d, LOG)}")


def _tail(path, size=4096):
    """The last `size` bytes of a signer's log, as text; None when it can't be read."""
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - size))
            return f.read().decode("utf-8", "replace").strip()
    except OSError:
        return None


def _last_line(path):
    """The last line of a signer's log: the reason it gave for exiting."""
    tail = _tail(path)
    return "no log" if tail is None else (tail.splitlines() or ["no output"])[-1][:512]


def down(timeout=10, d=None, show_log=True):
    """Stop this HOME's dev signer, or the one of runtime dir `d` (SIGTERM to the pid in endpoint.json while it holds
    signer.lock). Its pid, or None. One that doesn't stop is Hung, ending with the end of its log when `show_log` (the
    stacks it wrote there; a hook replacing it leaves them out of what the agent reads)."""
    d = d or signer_dir()
    lock = os.path.join(d, LOCK)
    deadline = time.monotonic() + timeout
    while (pid := _pid(d)) is None:   # one still starting (`tracekit up` without --wait) publishes its pid shortly
        if not _held(lock):
            return None
        if time.monotonic() > deadline:
            raise Hung(f"a dev signer holds {lock} but never published {ENDPOINT}; see {os.path.join(d, LOG)}")
        time.sleep(0.05)
    if not _held(lock):   # the endpoint of a signer that has exited
        return None
    # read before it unpublishes on stopping
    stacks = _published(d).get("stacks") == "SIGUSR1" and hasattr(signal, "SIGUSR1")
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while _held(lock):
        if os.name == "posix":   # on Windows, signal 0 is CTRL_C_EVENT
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):   # it has exited: the lock is a signer's started since
                return pid
        if time.monotonic() > deadline:
            log = os.path.join(d, LOG)
            # where it is stuck: every thread's stack, which it writes to its stderr; not to a pid its endpoint no
            # longer names, which may be another process's by now
            if show_log and stacks and _pid(d) in (pid, None):   # None: a stop that hangs after unpublishing
                try:
                    os.kill(pid, signal.SIGUSR1)
                except ProcessLookupError:   # it has just exited
                    pass
                time.sleep(0.5)
            tail = _tail(log, 16384) or ""
            start = tail.rfind("SERVING pid ")   # a foreground signer logs elsewhere: this log is another's
            if not show_log or start >= 0 and tail[start:].split("\n", 1)[0].strip() != f"SERVING pid {pid}":
                raise Hung(f"the dev signer (pid {pid}) did not stop within {timeout}s; see {log}")
            raise Hung(f"the dev signer (pid {pid}) did not stop within {timeout}s; the end of {log}:\n"
                       f"{tail or 'nothing'}")
        time.sleep(0.05)
    return pid


def status():
    """The v2 signer section of `tracekit status`: of the signer a client here uses ($TRACEKIT_SIGNER, in system mode
    the one the root-owned config names, else the dev signer). Starts and creates nothing."""
    path, token, dev = None, None, False
    try:
        path = _default_signer()
        if not path:
            dev = True
            d = signer_dir(create=False)
            path = os.path.join(d, SOCK if hasattr(socket, "AF_UNIX") else ENDPOINT)
            path, token = address(d)
        sock, _, hello = connect(path, token=token)
    except (SignerUnavailable, Incompatible, OSError, ValueError) as e:
        # a dev signer not started yet has no runtime dir or no socket in it: say how it starts, not the missing file
        # (a runtime dir refused for its owner or mode keeps that error)
        unstarted = dev and not isinstance(e, Incompatible) and (
            isinstance(e, FileNotFoundError) or path is not None and not os.path.exists(path))
        return {"socket": path, "running": isinstance(e, Incompatible),
                "error": "not started: the dev signer starts at an agent's first call, or with `tracekit up`"
                if unstarted else str(e)}
    sock.close()
    return {"socket": path, "running": True, **hello}
