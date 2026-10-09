"""Peer credentials of a Unix socket: Linux SO_PEERCRED, macOS LOCAL_PEERCRED (what getpeereid reads)."""
from tracekit import peercred
from tracekit.identity.base import CallerIdentity
from tracekit.signer.rpc_schema import RPCError


class UidAuthenticator:
    """Reads the credentials again for every frame instead of caching them per connection."""

    def authenticate(self, conn, frame):
        pid, uid = peercred.peer(conn)
        if uid is None:
            raise RPCError("unauthenticated", "peer credentials unavailable on this socket")
        return CallerIdentity("uid", str(uid), True, {"pid": pid})
