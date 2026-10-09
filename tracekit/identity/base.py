"""Who is calling the signer. The transport establishes it for every frame; nothing in a request can set it."""
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class CallerIdentity:
    scheme: str      # "uid", "token", ...
    subject: str     # unique within the scheme
    attested: bool   # established by the OS or a verified secret, not asserted by the caller
    claims: dict = field(default_factory=dict, hash=False)


def bearer(conn):
    """The bearer token of an HTTP request handler's Authorization header, or None."""
    scheme, _, token = conn.headers.get("Authorization", "").partition(" ")
    return (token.strip() or None) if scheme.lower() == "bearer" else None


class Authenticator(Protocol):
    def authenticate(self, conn, frame: dict) -> CallerIdentity:
        """Identity for one frame read from `conn`; raises RPCError("unauthenticated") or RPCError("forbidden")."""
