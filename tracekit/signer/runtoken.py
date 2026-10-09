"""Run capability tokens: `register_run` returns one; every later call for that run presents it with the caller's
identity. A token names (tenant, run_id, the registering identity) and an expiry.

HMAC-SHA256 with a signer-held secret, not the Ed25519 signing key: only the signer that issued a token ever checks it,
so nothing needs a public key; and keeping the evidence key out of it means a token can never be mistaken for, or used
to obtain, a signature over evidence.
"""
import base64
import hashlib
import hmac
import json
import time

from tracekit.signer.rpc_schema import RPCError

_DOMAIN = b"tracekit.run_token.v1\n"


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sub(identity):
    return f"{identity.scheme}:{identity.subject}"


class RunTokens:
    def __init__(self, secret, ttl_s=24 * 3600, clock=time.time):
        self.secret, self.ttl_s, self.clock = secret, ttl_s, clock

    def _mac(self, payload):
        return hmac.new(self.secret, _DOMAIN + payload, hashlib.sha256).digest()

    def issue(self, tenant, run_id, identity):
        payload = json.dumps({"tenant": tenant, "run_id": run_id, "sub": _sub(identity), "exp": int(self.clock() + self.ttl_s)},
                             separators=(",", ":"), sort_keys=True).encode()
        return _b64(payload) + "." + _b64(self._mac(payload))

    def verify(self, token, tenant, run_id, identity):
        """Refuses a token that is malformed, tampered, expired, or issued for another run or identity."""
        try:
            p, m = token.split(".")
            payload, mac = _unb64(p), _unb64(m)
        except (AttributeError, ValueError):
            raise RPCError("run_token_invalid", "malformed run token") from None
        if not hmac.compare_digest(mac, self._mac(payload)):
            raise RPCError("run_token_invalid", "run token signature mismatch")
        claims = json.loads(payload)
        if (claims["tenant"], claims["run_id"], claims["sub"]) != (tenant, run_id, _sub(identity)):
            raise RPCError("run_token_invalid", "run token belongs to another run or identity")
        if self.clock() >= claims["exp"]:
            raise RPCError("run_token_invalid", "run token expired")
