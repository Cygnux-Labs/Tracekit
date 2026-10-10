"""HTTPS transport for a central signer: `POST /v2/rpc` carries one JSON frame and answers with one.

signer.yaml:
    http:
      listen: 0.0.0.0:8443
      cert: tls/server.pem
      key: tls/server.key
      client_ca:                                 # mtls: SPIFFE trust domain -> the CA bundle its IDs must chain to
        example.org: tls/example-ca.pem
      authenticators: [oidc, k8s_sa, mtls, token]
      k8s_sa: {audience: tracekit-signer, ...}  # tracekit/identity/k8s_sa.py
      oidc: {corp: {issuer: https://..., audience: tracekit-signer, ...}}   # tracekit/identity/oidc.py; also checks
                                                 # register_run's principal_token when not an authenticator
      token_file: tls/bearer                     # token: a bearer secret (identity token:http)
      tokens: tokens.json                        # token: named, expiring tokens (identity token:NAME), managed with
                                                 # `tracekit signer token add|list|revoke` (identity/token.TokenStore)
      insecure_loopback: false                   # plain HTTP, only on a loopback address

Every request is authenticated again (no session state): the authenticators are asked in order and the first that
recognises its credential decides. Failed authentications are limited per source address and in total
(FAILED_PER_ADDR, FAILED_TOTAL: token buckets in a fixed-size LRU). Past either limit failures are refused as over it,
while a valid credential still gets in, so clients behind one address are not locked out by another's failures; past
an address's limit only the credentials checked locally (a client certificate, a token) are looked at, never one that
needs another service (a TokenReview, an OIDC issuer's keys). Refusals carry only the error, never log state. Bodies
over MAX_LINE are refused; reads time out like the other transports; connections are served by tracekit.netserver
(bounded threads, overall and per address; each request must arrive within its deadline, and so must the next one on a
kept-alive connection, while answering one, such as an approval_wait, has none). RPC refusals are answered with status
200 and the error frame.

With `otlp` (the signer's `otlp` config section), `POST /v1/traces` takes OTLP/HTTP (protobuf or JSON, bodies up to
otlp_wire.MAX_BODY) from the same authenticators: the caller is authenticated before its body is read, and answered
401 without a credential this signer accepts, 429 past the failed-authentication limit and 403 without the otlp_import
grant.
"""
import ipaddress
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler

from tracekit.identity.k8s_sa import K8sSaAuthenticator
from tracekit.identity.mtls import MtlsAuthenticator
from tracekit.identity.oidc import OidcAuthenticator
from tracekit.identity.token import BearerToken, TokenStore
from tracekit.netserver import Server
from tracekit.otlp_wire import MAX_BODY as OTLP_MAX_BODY
from tracekit.signer.quotas import MAX_LINE, Limits, Quotas
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import READ_TIMEOUT_S, parse_frame

PATH = "/v2/rpc"
OTLP_PATH = "/v1/traces"
KEYS = {"listen", "cert", "key", "client_ca", "authenticators", "k8s_sa", "oidc", "token_file", "tokens",
        "insecure_loopback"}
AUTHENTICATORS = {"k8s_sa", "mtls", "oidc", "token"}
FAILED_PER_ADDR = Limits(events_per_s=1, burst=20, buckets=4096)   # failed authentications per source address
FAILED_TOTAL = Limits(events_per_s=50, burst=500, buckets=1)
LOCAL = (MtlsAuthenticator, TokenStore, BearerToken)   # checked without asking another service
# lean: fixed connection limits; an http.max_connections setting once a deployment needs more behind one address
MAX_THREADS, MAX_PER_IP = 1024, 256


def configure(cfg, oidc=None):
    """((host, port), authenticators, TLS context or None) for the `http` section of signer.yaml, its paths absolute.
    ValueError for anything missing, unknown or unsafe. `oidc`: the OidcAuthenticator to use (default: a new one)."""
    if not isinstance(cfg, dict) or set(cfg) - KEYS:
        raise ValueError(f"http: a mapping of {sorted(KEYS)}")
    host, _, port = str(cfg.get("listen", "")).rpartition(":")
    # lean: host:port with an IPv4 address or a name; bracketed IPv6 when a deployment needs it
    if not host or not port.isdigit():
        raise ValueError("http.listen: host:port")
    names = cfg.get("authenticators")
    if not isinstance(names, list) or not names or len(set(names)) != len(names) or set(names) - AUTHENTICATORS:
        raise ValueError(f"http.authenticators: a list of {', '.join(sorted(AUTHENTICATORS))}")
    cas = cfg.get("client_ca")
    if cas is not None and not (isinstance(cas, dict) and cas and all(
            isinstance(k, str) and k and isinstance(v, str) and v for k, v in cas.items())):
        raise ValueError("http.client_ca: a mapping of SPIFFE trust domain to CA bundle path")
    tls = None
    if cfg.get("cert") and cfg.get("key"):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cfg["cert"], cfg["key"])
        if cfg.get("client_ca"):
            for path in cfg["client_ca"].values():
                tls.load_verify_locations(path)
            tls.verify_mode = ssl.CERT_OPTIONAL   # a presented certificate must verify; mtls refuses a missing one
    elif cfg.get("cert") or cfg.get("key") or cfg.get("insecure_loopback") is not True or not _loopback(host):
        raise ValueError("http: needs cert and key (plain HTTP only with insecure_loopback on a loopback address)")
    if oidc is None and cfg.get("oidc") is not None:
        oidc = OidcAuthenticator(cfg["oidc"])
    auths = []
    for name in names:
        if name == "mtls":
            if not (tls and cfg.get("client_ca")):
                raise ValueError("http: mtls needs cert, key and client_ca")
            auths.append(MtlsAuthenticator(cfg["client_ca"]))
        elif name == "token":
            if not (cfg.get("token_file") or cfg.get("tokens")):
                raise ValueError("http: token needs token_file and/or tokens")
            if cfg.get("tokens"):
                auths.append(TokenStore(cfg["tokens"]))
            if cfg.get("token_file"):
                auths.append(BearerToken(cfg["token_file"]))
        elif name == "oidc":
            if oidc is None:
                raise ValueError("http: oidc needs the oidc section")
            auths.append(oidc)
        else:
            try:
                auths.append(K8sSaAuthenticator(**cfg.get("k8s_sa", {})))
            except TypeError as e:
                raise ValueError(f"http.k8s_sa: {e}") from None
    return (host, int(port)), auths, tls


def resolve(cfg, base):
    """The `http` section `cfg` with its paths made absolute from `base`, in place."""
    for section in (cfg, cfg.get("k8s_sa")) if isinstance(cfg, dict) else ():
        for k in ("cert", "key", "token_file", "tokens", "ca"):
            if isinstance(section, dict) and isinstance(section.get(k), str) and section[k]:
                section[k] = os.path.join(base, section[k])
    for section in (cfg.get("oidc") or {}).values() if isinstance(cfg, dict) and isinstance(cfg.get("oidc"), dict) else ():
        if isinstance(section, dict) and isinstance(section.get("ca"), str) and section["ca"]:
            section["ca"] = os.path.join(base, section["ca"])
    if isinstance(cfg, dict) and isinstance(cfg.get("client_ca"), dict):
        cfg["client_ca"] = {td: os.path.join(base, p) if isinstance(p, str) else p for td, p in cfg["client_ca"].items()}


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # keep-alive

    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle_one_request(self):
        self.server.restart_deadline()
        super().handle_one_request()

    def do_POST(self):
        otlp = self.path == OTLP_PATH and self.server.otlp
        if self.path != PATH and not otlp:
            return self._reply(404, RPCError("invalid_request", f"POST {PATH}").wire(), close=True)
        n, limit = self.headers.get("Content-Length", ""), OTLP_MAX_BODY if otlp else MAX_LINE
        if not n:
            return self._reply(411, RPCError("invalid_request", "Content-Length required").wire(), close=True)
        if not (n.isascii() and n.isdigit() and len(n) <= 8):
            return self._reply(400, RPCError("invalid_request", "Content-Length: at most 8 ASCII digits").wire(),
                               close=True)
        if int(n) > limit:
            return self._reply(413, RPCError("quota_exceeded", f"body longer than {limit} bytes").wire(), close=True)
        if otlp:
            try:   # who asks, before reading what they send
                identity = self.server.authenticate(self, {"method": "otlp_import"})
            except RPCError as e:
                return self._reply({"unauthenticated": 401, "quota_exceeded": 429}.get(e.code, 403), e.wire(), close=True)
        try:
            body = self.rfile.read(int(n))
        except OSError:   # the read timeout, or the peer went away
            body = b""
        if len(body) < int(n):
            self.close_connection = True
            return
        self.server.stop_deadline()   # the request is in; answering it may wait (approval_wait)
        if otlp:
            try:
                return self._send(*otlp(identity, body, self.headers.get("Content-Type"),
                                        self.headers.get("Content-Encoding")))
            except RPCError as e:
                return self._reply(403, e.wire(), close=True)
        try:
            frame = parse_frame(body)
            out = self.server.handle_frame(self.server.authenticate(self, frame), frame)
        except RPCError as e:
            out = e.wire()
        self._reply(200, out)

    def _reply(self, status, obj, close=False):
        self._send(status, {"Content-Type": "application/json"},
                   json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(), close)

    def _send(self, status, headers, data, close=False):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class HttpServer(Server):
    def __init__(self, address, authenticators, tls, handle_frame, read_timeout=READ_TIMEOUT_S, otlp=None,
                 handler=_Handler, on_auth_failure=lambda: None, failed=(FAILED_PER_ADDR, FAILED_TOTAL)):
        """`otlp(identity, body, content type, content encoding)` -> (status, headers, body) answers POST /v1/traces;
        None: not served. `handler`: the request handler class (tracekit.gateway serves its own). `on_auth_failure()`
        is called for each failed authentication; `failed`: the Limits per source address and in total."""
        self.authenticators, self.tls, self.handle_frame, self.read_timeout = authenticators, tls, handle_frame, read_timeout
        self.otlp, self.on_auth_failure = otlp, on_auth_failure
        self.failed = [Quotas(lim) for lim in failed]
        super().__init__(address, handler, tls, read_timeout, MAX_THREADS, max_per_ip=MAX_PER_IP)

    def authenticate(self, conn, frame):
        per_addr, total = self.failed
        addr = conn.client_address[0]
        try:
            per_addr.take(addr, "", spend=0)
            over = False
        except RPCError:
            over = True
        try:
            for a in self.authenticators:
                if over and not isinstance(a, LOCAL):   # past the address's limit nothing is sent to another service
                    continue
                identity = a.authenticate(conn, frame)
                if identity is not None:
                    return identity
            raise RPCError("unauthenticated", "no credential this signer accepts")
        except RPCError as e:
            if e.code == "unauthenticated":
                per_addr.take(addr, "too many failed authentications")
                self.on_auth_failure()
                total.take(None, "too many failed authentications")
            raise
