"""Peer credentials of a Unix socket: Linux SO_PEERCRED, macOS LOCAL_PEERCRED (what getpeereid reads).

The caller is the effective uid of the connecting process: what both record at connect(). They never change, so they
are read once per connection. On Linux each frame is then tied to that same uid by SCM_CREDENTIALS: with SO_PASSCRED
set, the kernel stamps every chunk with credentials of its sender (an unprivileged sender can't claim a uid other than
its real, effective or saved one), and CredentialReader refuses a chunk whose uid is not the connecting effective uid.
A socket fd handed to another user's process therefore can't speak with the connecting user's identity.

A sender that attaches no credentials of its own is stamped with its real uid. So a process whose real and effective
uids differ (a setuid program, or one that changed only its effective uid) is refused on every frame unless it attaches
SCM_CREDENTIALS carrying its effective uid itself: fail-safe, never a frame accepted under the wrong uid.
"""
import socket
import struct

from tracekit import peercred
from tracekit.identity.base import CallerIdentity
from tracekit.signer.rpc_schema import RPCError

# lean: macOS has no per-message credentials, so identity is fixed at connect time there (macOS system mode is
# experimental); add a per-frame check if it ever gets one or system mode becomes supported on macOS.
PER_FRAME = hasattr(socket, "SO_PASSCRED")
_UCRED = struct.calcsize(peercred.UCRED_FMT)


class UidAuthenticator:
    """One per connection: the uid the kernel recorded at connect()."""

    def __init__(self, conn):
        pid, uid = peercred.peer(conn)
        if uid is None:
            raise RPCError("unauthenticated", "peer credentials unavailable on this socket")
        self.uid = uid
        self.identity = CallerIdentity("uid", str(uid), True, {"pid": pid})

    def authenticate(self, conn, frame):
        return self.identity


def scm_uid(ancdata):
    """uid in the SCM_CREDENTIALS message of a recvmsg result, or None when there is none."""
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) >= _UCRED:
            return peercred.parse_ucred(data[:_UCRED])[1]
    return None


class CredentialReader:
    """readline() over recvmsg for a socket with SO_PASSCRED: every chunk must carry `uid` in SCM_CREDENTIALS."""

    def __init__(self, sock, uid):
        self.sock, self.uid, self.buf = sock, uid, b""

    def readline(self, limit):
        while b"\n" not in self.buf and len(self.buf) < limit:
            data, anc, _flags, _addr = self.sock.recvmsg(65536, socket.CMSG_SPACE(_UCRED))
            if not data:
                break
            sender = scm_uid(anc)
            if sender != self.uid:
                raise RPCError("unauthenticated", f"frame sent as uid {sender}, not the connecting effective uid "
                                                  f"{self.uid} (real and effective uids must match)")
            self.buf += data
        end = self.buf.find(b"\n", 0, limit)
        n = limit if end < 0 else end + 1
        line, self.buf = self.buf[:n], self.buf[n:]
        return line
