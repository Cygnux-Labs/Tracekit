"""Dev tokens: a random secret the signer writes to a user-only file, with an expiry and a set of allowed methods.

The secret never goes on the wire: each side proves it holds it with an HMAC over the other side's fresh nonce
(transport/tcp_dev.py), compared in constant time.
"""
import hashlib
import hmac
import secrets
import time

from tracekit.identity.base import CallerIdentity
from tracekit.signer.rpc_schema import RPCError


def proof(secret, label, nonce):
    return hmac.new(secret.encode(), f"{label}\n{nonce}".encode(), hashlib.sha256).hexdigest()


def check_proof(secret, presented, label, nonce):
    if not hmac.compare_digest(str(presented).encode(), proof(secret, label, nonce).encode()):
        raise RPCError("unauthenticated", "dev token proof mismatch")


class DevToken:
    def __init__(self, subject, scope, ttl_s, secret=None, clock=time.time):
        self.secret = secret or secrets.token_hex(32)
        self.subject, self.scope, self.clock = subject, frozenset(scope), clock
        self.expires_at = clock() + ttl_s

    def authenticate(self, conn, frame):
        """Per frame, after the connection's proof: refuses once the token has expired or for a method out of scope."""
        if self.clock() >= self.expires_at:
            raise RPCError("unauthenticated", "dev token expired")
        method = frame.get("method")
        if method not in self.scope:
            raise RPCError("forbidden", f"dev token not scoped for {str(method)[:64]}")
        return CallerIdentity("token", self.subject, True, {"expires_at": self.expires_at})
