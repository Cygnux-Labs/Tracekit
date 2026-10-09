"""mTLS: the client certificate of the TLS session, already verified by the handshake against the configured CA(s)
(transport/http.py). The subject is the SPIFFE ID in its URI SAN; a certificate with none, or more than one, is refused."""
from tracekit.identity.base import CallerIdentity
from tracekit.signer.rpc_schema import RPCError


class MtlsAuthenticator:
    def authenticate(self, conn, frame):
        """`conn` is the HTTP request handler; None when the client sent no certificate."""
        cert = conn.connection.getpeercert()
        if not cert:
            return None
        ids = [v for k, v in cert.get("subjectAltName", ()) if k == "URI" and v.startswith("spiffe://")]
        if len(ids) != 1:
            raise RPCError("unauthenticated", f"client certificate needs exactly one spiffe:// URI SAN, has {len(ids)}")
        return CallerIdentity("mtls", ids[0], True)
