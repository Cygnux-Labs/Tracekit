"""Harness helper (04-design §9): the one process that reads other users' /proc/<pid>/exe, so neither signer needs
CAP_SYS_PTRACE.

    python -I -m tracekit.harness_helper --allow-uid UID [--socket PATH]

Under systemd it is socket-activated (install.helper_units: a root service whose capability bounding set is
CAP_SYS_PTRACE CAP_DAC_READ_SEARCH, no network). With --socket it binds PATH itself, owned by UID, mode 0600 (launchd
on macOS, tests). A connection from any uid but UID is closed unanswered. A request is one line, {"pid": N}; the answer
is one line, {"chain": [...]}: N and its ancestors, nearest first, each {"pid", "exe", "start_time", "script"} (exe
None where it can't be read or the binary was replaced; script: the first non-option argument, which an interpreter
harness runs). It never takes a path or a command. Matching the chain against the registered harnesses is the
signer's (find, match).
"""
import argparse
import json
import os
import socket
import socketserver
import struct
import sys

from . import peercred

LINUX = os.path.isdir("/proc/self")
MAX_REQUEST = 256
HELPER_CAPS = "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH"


def _darwin_info(pid):
    """(ppid, start time in µs since the epoch) through proc_pidinfo(PROC_PIDTBSDINFO), or None."""
    import ctypes
    buf = ctypes.create_string_buffer(136)   # struct proc_bsdinfo
    if _libproc().proc_pidinfo(pid, 3, ctypes.c_uint64(0), buf, 136) != 136:
        return None
    f = struct.unpack("<12I16s32s5Ii2Q", buf.raw)
    return f[4], f[20] * 1_000_000 + f[21]


def _libproc():
    import ctypes
    return ctypes.CDLL("/usr/lib/libproc.dylib")


def _stat(pid):
    """(ppid, start time) of pid, or None. Linux: clock ticks since boot, from /proc/<pid>/stat."""
    if not LINUX:
        return _darwin_info(pid) if sys.platform == "darwin" else None
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        rest = s[s.rindex(")") + 2:].split()
        return int(rest[1]), int(rest[19])
    except (OSError, ValueError, IndexError):
        return None


def start_time(pid):
    """Kernel start time of pid: with the pid, it names one process instance."""
    st = _stat(pid)
    return st and st[1]


def _exe(pid):
    """Resolved executable of pid, or None. A replaced or deleted binary never matches."""
    if not LINUX:
        if sys.platform != "darwin":
            return None
        import ctypes
        buf = ctypes.create_string_buffer(4096)
        n = _libproc().proc_pidpath(pid, buf, 4096)
        return buf.value.decode(errors="replace") if n > 0 else None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    return None if exe.endswith(" (deleted)") else exe


def _script(pid):
    """The script an interpreter process runs: its first non-option argument, resolved against the process's cwd."""
    if not LINUX:
        return None   # lean: macOS reports no script, so an interpreter harness never matches there; add KERN_PROCARGS2 if needed
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return None
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        if not os.path.isabs(a):
            try:
                a = os.path.join(os.readlink(f"/proc/{pid}/cwd"), a)
            except OSError:
                return None
        return os.path.realpath(a)
    return None


def chain(pid, limit=64):
    """pid and its ancestors, nearest first, as the helper answers them."""
    out = []
    while pid and pid > 1 and len(out) < limit:
        st = _stat(pid)
        if st is None:
            break
        out.append({"pid": pid, "exe": _exe(pid), "start_time": st[1], "script": _script(pid)})
        pid = st[0]
    return out


def ask(sock, pid, timeout=2):
    """The helper's chain for pid; OSError or ValueError when it does not answer one."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock)
        s.sendall(json.dumps({"pid": pid}).encode() + b"\n")
        line = s.makefile("rb").readline(1 << 20)
    out = json.loads(line or b"null")
    procs = out.get("chain") if isinstance(out, dict) else None
    if not (isinstance(procs, list) and all(isinstance(p, dict) and type(p.get("pid")) is int for p in procs)):
        raise ValueError(str(out.get("error") if isinstance(out, dict) else "no answer")[:200])
    return procs


def trusted_file(path):
    """Problem with trusting `path` as a harness binary, or None. The agent must not be able to replace it: the file
    and every directory above it must be root-owned and not group- or world-writable."""
    if not os.path.isabs(path):
        return "not an absolute path"
    p = os.path.realpath(path)
    while True:
        try:
            st = os.stat(p)
        except OSError as e:
            return f"{p}: {e.strerror}"
        if st.st_uid != 0:
            return f"{p} is not owned by root"
        if st.st_mode & 0o022:
            return f"{p} is group- or world-writable"
        if p == "/":
            return None
        p = os.path.dirname(p)


def normalize_harnesses(spec):
    """Validate registered harnesses: [{"name", "exe", "script"?}]. `script` is for harnesses that are interpreter
    scripts (an npm-installed CLI runs as node): the process's executable is the interpreter, and its first non-option
    argument must resolve to the registered script."""
    out = []
    for h in spec or []:
        if not isinstance(h, dict) or not isinstance(h.get("exe"), str) or not os.path.isabs(h["exe"]):
            continue
        sc = h.get("script")
        out.append({"name": str(h.get("name") or os.path.basename(h["exe"]))[:64], "exe": os.path.realpath(h["exe"]),
                    "script": os.path.realpath(sc) if isinstance(sc, str) and os.path.isabs(sc) else None})
    return out


def match(procs, harnesses):
    """The registered harness instance among the ancestors in procs (a chain): (instance, None) or (None, why).

    The hook process is spawned by the harness (usually through a shell), so this takes the nearest ancestor whose
    executable (not its name, which any process can set) is a registered, root-owned harness binary. A process the
    agent detaches (double fork, setsid) is reparented to init and has no harness above it."""
    ancestors = procs[1:]
    for p in ancestors:
        for h in harnesses:
            if p.get("exe") != h["exe"] or h["script"] and p.get("script") != h["script"]:
                continue
            for f in (h["exe"], h["script"]):
                bad = f and trusted_file(f)
                if bad:
                    return None, f"registered harness file {f} can be replaced by a non-root user: {bad}"
            return {"name": h["name"], "exe": h["exe"], "pid": p["pid"], "start_time": p.get("start_time")}, None
    if ancestors and not any(p.get("exe") for p in ancestors):
        return None, "cannot read process executables (is the harness helper running? docs/threat-model-laptop.md)"
    return None, "no registered harness among the sender's ancestor processes"


def find(pid, harnesses, sock=None):
    """match() over pid's chain: from the helper at `sock`, or read here when there is none (a same-user signer)."""
    if not pid:
        return None, "no peer pid"
    try:
        procs = ask(sock, pid) if sock else chain(pid)
    except (OSError, ValueError) as e:
        return None, f"harness helper unavailable ({e})"
    return match(procs, harnesses)


class _Conn(socketserver.BaseRequestHandler):
    def handle(self):
        if peercred.peer(self.request)[1] != self.server.allow_uid:
            return
        self.request.settimeout(5)
        try:
            req = json.loads(self.request.makefile("rb").readline(MAX_REQUEST + 1))
            pid = req["pid"]
            if set(req) != {"pid"} or type(pid) is not int or pid < 1:
                raise ValueError
            out = {"chain": chain(pid)}
        except (OSError, ValueError, KeyError, TypeError):
            out = {"error": 'a request is one line: {"pid": N}'}
        try:
            self.request.sendall(json.dumps(out).encode() + b"\n")
        except OSError:
            pass


# without AF_UNIX (Windows) there is no helper, but the signers still import match and normalize_harnesses from here
class Server(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", object)):
    daemon_threads = True

    def __init__(self, path, allow_uid):
        """Serve on the socket systemd passed (path None) or bind path, for allow_uid only."""
        self.allow_uid = allow_uid
        super().__init__(path, _Conn, bind_and_activate=path is not None)
        if path is None:
            self.socket.close()
            self.socket = socket.socket(fileno=3)   # sd_listen_fds: the first passed fd


def serve(path, allow_uid):
    if path is None:
        return Server(None, allow_uid)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    old = os.umask(0o177)
    try:
        srv = Server(path, allow_uid)
    finally:
        os.umask(old)
    os.chown(path, allow_uid, -1)
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m tracekit.harness_helper", description=__doc__.split("\n\n")[0])
    ap.add_argument("--allow-uid", type=int, required=True, help="the signer's uid, the only one answered")
    ap.add_argument("--socket", help="bind this path (default: the socket systemd passes)")
    a = ap.parse_args(argv)
    activated = os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1"
    if not (a.socket or activated):
        ap.error("--socket PATH, or run socket-activated")
    serve(None if activated else a.socket, a.allow_uid).serve_forever()


if __name__ == "__main__":
    main()
