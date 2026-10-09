"""Dev tokens: a random secret the signer writes to a user-only file, with an expiry and a set of allowed methods.

The secret never goes on the wire: each side proves it holds it with an HMAC over the other side's fresh nonce
(transport/tcp_dev.py), compared in constant time. Over HTTPS (transport/http.py) a BearerToken is sent as is: TLS
protects it there.
"""
import hashlib
import hmac
import secrets
import time

from tracekit.identity.base import CallerIdentity, bearer
from tracekit.signer.rpc_schema import RPCError

MIN_SECRET = 32


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
        if not isinstance(method, str) or method not in self.scope:
            raise RPCError("forbidden", f"dev token not scoped for {str(method)[:64]}")
        return CallerIdentity("token", self.subject, True, {"expires_at": self.expires_at})


class BearerToken:
    """HTTP transport: a bearer secret the operator writes to `path`, compared in constant time. Identity token:http;
    what it may call comes from the signer's `authorize` config."""

    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            self.secret = f.read().strip().encode()
        if len(self.secret) < MIN_SECRET:
            raise ValueError(f"{path}: a bearer token needs at least {MIN_SECRET} characters")

    def authenticate(self, conn, frame):
        """None when the request carries no bearer token or another one (a k8s_sa token, say)."""
        token = bearer(conn)
        if token is None or not hmac.compare_digest(token.encode(), self.secret):
            return None
        return CallerIdentity("token", "http", True)
