"""Who is on the other end of a Unix socket? Linux gives (pid, uid, gid) through SO_PEERCRED; macOS and
the BSDs give the uid through LOCAL_PEERCRED (a struct xucred) and the pid through LOCAL_PEERPID.

The macOS path follows <sys/un.h> and <sys/ucred.h>: it is exercised here with packed structs, and
needs confirmation on real hardware (docs/portability.md). Where neither exists the daemon cannot
attest callers and says so; it never guesses."""
import socket
import struct
import subprocess
import sys
import zlib

SOL_LOCAL = 0
LOCAL_PEERCRED = 0x001
LOCAL_PEERPID = 0x002
XUCRED_VERSION = 0
_XUCRED_FMT = "IIh16I"  # cr_version, cr_uid, cr_ngroups, cr_groups[16]  (NGROUPS == 16)


def _darwinish():
    return sys.platform == "darwin" or sys.platform.startswith(("freebsd", "openbsd", "netbsd"))


def has_peer_credentials():
    return hasattr(socket, "SO_PEERCRED") or (_darwinish() and hasattr(socket, "AF_UNIX"))


def parse_xucred(raw):
    """-> uid, or None when the structure is not the version we understand."""
    if len(raw) < struct.calcsize(_XUCRED_FMT):
        return None
    fields = struct.unpack(_XUCRED_FMT, raw[:struct.calcsize(_XUCRED_FMT)])
    return fields[1] if fields[0] == XUCRED_VERSION else None


def peer(conn):
    """(pid, uid) of the connected process, or (None, None) when it cannot be attested."""
    try:
        if hasattr(socket, "SO_PEERCRED"):
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            return pid, uid
        if _darwinish():
            uid = parse_xucred(conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize(_XUCRED_FMT)))
            try:
                pid = struct.unpack("i", conn.getsockopt(SOL_LOCAL, LOCAL_PEERPID, struct.calcsize("i")))[0]
            except OSError:
                pid = None
            return (pid, uid) if uid is not None else (None, None)
    except (AttributeError, OSError, struct.error):
        pass
    return None, None


def ps_stat(pid):
    """(comm, ppid, tty_number) through ps(1), for platforms without /proc. tty_number is 0 for no tty."""
    try:
        out = subprocess.run(["ps", "-o", "ppid=,tty=,comm=", "-p", str(int(pid))], capture_output=True, text=True, timeout=3).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return parse_ps_line(out)


def parse_ps_line(out):
    parts = out.split(None, 2)
    if len(parts) < 3:
        return None
    try:
        ppid = int(parts[0])
    except ValueError:
        return None
    tty = parts[1]
    comm = parts[2].strip().rsplit("/", 1)[-1]
    return comm, ppid, 0 if tty in ("?", "??", "-") else (zlib.crc32(tty.encode()) or 1)
