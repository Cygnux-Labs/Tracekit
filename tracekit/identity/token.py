"""Dev tokens: a random secret the signer writes to a user-only file, with an expiry and a set of allowed methods.

The secret never goes on the wire: each side proves it holds it with an HMAC over the other side's fresh nonce
(transport/tcp_dev.py), compared in constant time. Over HTTPS (transport/http.py) a BearerToken or a TokenStore token
is sent as is: TLS protects it there.
"""
import hashlib
import hmac
import json
import re
import secrets
import time

from tracekit.deploy import files
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


NAME_RE = re.compile(r"[a-z0-9_-]{1,64}")
RESERVED = {"dev", "http"}   # token:dev (the dev transport) and token:http (BearerToken)
PREFIX = "tk2_"   # one dot in the whole token, so k8s_sa never takes it for a JWT
TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_ttl(text):
    """Seconds of a TTL such as 3600s, 90m, 12h or 30d."""
    m = re.fullmatch(r"([1-9][0-9]{0,5})([smhd])", text or "")
    if not m:
        raise ValueError(f"ttl {text!r}: a number and one of s, m, h, d (30d)")
    return int(m[1]) * TTL_UNITS[m[2]]


class TokenStore:
    """Named bearer tokens for the HTTP transport, in a 0600 JSON file the signer reads on every request, so adding,
    revoking or rotating a token needs no restart. A token is `tk2_<name>.<secret>`; the file keeps only a salted hash
    of the secret with its created and expires times and an optional tenant. Identity token:<name>."""

    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        if not isinstance(data, dict):
            raise ValueError(f"{self.path}: not a token store")
        return data

    @staticmethod
    def _hash(salt, secret):
        return hashlib.sha256(bytes.fromhex(salt) + secret.encode()).hexdigest()

    def add(self, name, ttl_s, tenant=None):
        """A new token for `name`, returned once. A name is never reused, revoked or not."""
        if not NAME_RE.fullmatch(name or "") or name in RESERVED:
            raise ValueError(f"token name {name!r}: 1-64 of a-z 0-9 _ -, not {' or '.join(sorted(RESERVED))}")
        tokens = self.load()
        if name in tokens:
            raise ValueError(f"token {name!r} exists; add one under a new name, then revoke {name!r}")
        secret, salt, now = secrets.token_urlsafe(32), secrets.token_hex(16), self.clock()
        tokens[name] = {"salt": salt, "sha256": self._hash(salt, secret), "created": now, "expires": now + ttl_s,
                        "tenant": tenant, "revoked": None}
        # lean: read-modify-write without a lock; two admins adding tokens at the same instant can lose one
        files.write_json(self.path, tokens)
        return f"{PREFIX}{name}.{secret}"

    def revoke(self, name):
        tokens = self.load()
        if name not in tokens:
            raise ValueError(f"no token {name!r}")
        tokens[name]["revoked"] = tokens[name]["revoked"] or self.clock()
        files.write_json(self.path, tokens)

    def authenticate(self, conn, frame):
        """None for a request without a tk2 bearer token; refuses an unknown, expired or revoked one."""
        token = bearer(conn)
        if token is None or not token.startswith(PREFIX):
            return None
        name, _, secret = token[len(PREFIX):].partition(".")
        # lean: re-reads the store per request; cache it by mtime if it ever shows in a profile
        try:
            rec = self.load().get(name) if NAME_RE.fullmatch(name) else None
            ok = rec and (hmac.compare_digest(self._hash(rec["salt"], secret), rec["sha256"])
                          and rec["revoked"] is None and self.clock() < rec["expires"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise RPCError("unavailable", "token store unreadable") from e
        if not ok:
            raise RPCError("unauthenticated", "unknown, expired or revoked token")
        return CallerIdentity("token", name, True, {"expires_at": rec["expires"], "tenant": rec["tenant"]})


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
