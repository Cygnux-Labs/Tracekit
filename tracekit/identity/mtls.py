"""mTLS: the client certificate of the TLS session, already verified by the handshake against every configured CA
(transport/http.py). The subject is the SPIFFE ID in its URI SAN; a certificate with none, or more than one, is refused.
The ID's trust domain must be configured, and the certificate issued by a CA of that trust domain's bundle, so one
trust domain's CA cannot vouch for another's IDs."""
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from tracekit.identity.base import CallerIdentity
from tracekit.signer.rpc_schema import RPCError


class MtlsAuthenticator:
    def __init__(self, client_ca):
        """`client_ca` maps each SPIFFE trust domain to the path of its CA bundle (PEM)."""
        self.cas = {}
        for domain, path in client_ca.items():
            with open(path, "rb") as f:
                self.cas[domain] = x509.load_pem_x509_certificates(f.read())

    def authenticate(self, conn, frame):
        """`conn` is the HTTP request handler; None when the client sent no certificate."""
        cert = conn.connection.getpeercert()
        if not cert:
            return None
        ids = [v for k, v in cert.get("subjectAltName", ()) if k == "URI" and v.startswith("spiffe://")]
        if len(ids) != 1:
            raise RPCError("unauthenticated", f"client certificate needs exactly one spiffe:// URI SAN, has {len(ids)}")
        domain = ids[0][len("spiffe://"):].split("/", 1)[0]
        leaf = x509.load_der_x509_certificate(conn.connection.getpeercert(binary_form=True))
        # lean: the leaf must be issued directly by a CA of its trust domain (no intermediates); verify the whole chain
        # against the domain's bundle once ssl exposes it (Python 3.13 get_verified_chain) or SVIDs come via intermediates
        if not any(_issued_by(leaf, ca) for ca in self.cas.get(domain, ())):
            raise RPCError("unauthenticated", f"client certificate not issued by a CA of trust domain {domain[:255]!r}")
        return CallerIdentity("mtls", ids[0], True)


def _issued_by(leaf, ca):
    try:
        leaf.verify_directly_issued_by(ca)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
