"""Find or start the same-user dev signer (decision S3).

The runtime dir (0700, ours) holds `signer.lock`, which the signer locks for its whole life before it touches anything
else (the kernel drops the lock when the process dies, so liveness never depends on pids); `spawn.lock`, which a
client holds while it decides whether to start one; `signer.sock`; `endpoint.json` ({"pid", ...}, written by the
signer after it binds; without Unix sockets also the loopback port and token, decision S3) and `signer.log`. A
signer that answers `hello` with a protocol range that excludes this client is refused and left running: only
`tracekit up --replace` stops it.

Off in system mode and when TRACEKIT_SIGNER is set: an agent must not be able to substitute its own signer there.
"""
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

from tracekit.client import SYSTEM_CONFIG
from tracekit.locking import lock_file, unlock_file
from tracekit.sdk.client import Incompatible, SignerUnavailable, connect

SOCK, LOCK, SPAWN_LOCK, ENDPOINT, LOG = "signer.sock", "signer.lock", "spawn.lock", "endpoint.json", "signer.log"
SIGNER_ARGV = [sys.executable, "-m", "tracekit", "signer", "serve", "--dev"]
_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "LOCALAPPDATA",
        "SYSTEMROOT", "PYTHONPATH")   # SYSTEMROOT: Windows sockets need it


class Hung(SignerUnavailable):
    pass


def runtime_dir():
    """The per-user runtime dir ($TRACEKIT_RUNTIME_DIR overrides), created 0700; refused unless it is ours and private
    (on POSIX; Windows has no uid, so it relies on the user-only profile ACL as S3 decides)."""
    d = os.environ.get("TRACEKIT_RUNTIME_DIR")
    if not d and os.name == "nt":
        d = os.path.join(os.environ["LOCALAPPDATA"], "tracekit", "run")
    elif not d and sys.platform == "darwin":
        d = os.path.expanduser("~/Library/Application Support/tracekit/run")
        if len(os.path.join(d, SOCK).encode()) > 103:   # macOS caps socket paths at 104 bytes
            d = f"/tmp/tk-{os.getuid()}"
    elif not d:
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        d = os.path.join(xdg, "tracekit") if xdg else f"/tmp/tracekit-{os.getuid()}"
    os.makedirs(d, 0o700, exist_ok=True)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or os.name == "posix" and (st.st_uid != os.getuid() or st.st_mode & 0o077):
        raise SignerUnavailable(f"{d} must be a directory owned by you with mode 0700")
    return d


def _held(path):
    """True while some process holds the lock on `path`."""
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
    try:
        path, token = address(d)
    except (OSError, ValueError):
        return None
    try:
        return connect(path, token=token)
    except SignerUnavailable:
        return None


def _pid(d):
    try:
        with open(os.path.join(d, ENDPOINT)) as f:
            return json.load(f)["pid"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def spawn(d):
    """Start a detached `tracekit signer serve --dev` for runtime dir `d`."""
    env = {k: v for k, v in os.environ.items() if k in _ENV or k.startswith(("LC_", "TRACEKIT_"))}
    env["TRACEKIT_RUNTIME_DIR"] = d
    with open(os.path.join(d, LOG), "ab") as log:
        p = subprocess.Popen(SIGNER_ARGV, stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd="/", env=env,
                             start_new_session=True, umask=0o077)
    threading.Thread(target=p.wait, daemon=True).start()   # reap it if it exits while we live
    return p


def ensure(wait=True, timeout=10):
    """A connection (socket, rfile, hello) to a compatible dev signer, starting one if none runs. With wait=False,
    None once a new signer has been started. Raises Incompatible, Hung or SignerUnavailable."""
    if os.environ.get("TRACEKIT_SIGNER") or os.path.exists(SYSTEM_CONFIG):
        raise SignerUnavailable("dev auto-spawn is off when TRACEKIT_SIGNER is set or in system mode")
    d = runtime_dir()
    lock = os.path.join(d, LOCK)
    conn = _try(d)
    if conn:
        return conn
    with open(os.path.join(d, SPAWN_LOCK), "a") as spawn_lock:
        lock_file(spawn_lock)
        conn = _try(d)
        if conn:
            return conn
        p = None
        if not _held(lock):   # nothing alive: whatever is left belongs to a dead signer
            for f in (os.path.join(d, SOCK), os.path.join(d, ENDPOINT)):
                pathlib.Path(f).unlink(missing_ok=True)
            p = spawn(d)
            if not wait:
                return None
        deadline = time.monotonic() + timeout
        while True:
            conn = _try(d)
            if conn:
                return conn
            exited = p is not None and p.poll() is not None
            if time.monotonic() > deadline or (exited and not _held(lock)):
                break
            time.sleep(0.02)
    if _held(lock):
        raise Hung(f"a dev signer (pid {_pid(d)}) holds {lock} but does not answer; see {os.path.join(d, LOG)}")
    raise SignerUnavailable(f"the dev signer did not start; see {os.path.join(d, LOG)}")


def down(timeout=10):
    """Stop the dev signer (SIGTERM to the pid in endpoint.json while it holds signer.lock). Its pid, or None."""
    d = runtime_dir()
    lock = os.path.join(d, LOCK)
    if not _held(lock):
        return None
    pid = _pid(d)
    if pid is None:
        raise Hung(f"a dev signer holds {lock} but never published {ENDPOINT}; see {os.path.join(d, LOG)}")
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while _held(lock):
        if time.monotonic() > deadline:
            raise Hung(f"the dev signer (pid {pid}) did not stop within {timeout}s")
        time.sleep(0.05)
    return pid


def status():
    """The v2 signer section of `tracekit status`. Starts nothing."""
    path, token = os.environ.get("TRACEKIT_SIGNER"), None
    try:
        if not path:
            d = runtime_dir()
            path = os.path.join(d, SOCK if hasattr(socket, "AF_UNIX") else ENDPOINT)
            path, token = address(d)
        sock, _, hello = connect(path, token=token)
    except (SignerUnavailable, Incompatible, OSError, ValueError) as e:
        return {"socket": path, "running": isinstance(e, Incompatible), "error": str(e)}
    sock.close()
    return {"socket": path, "running": True, **hello}
