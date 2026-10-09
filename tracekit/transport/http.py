"""HTTPS transport for a central signer: `POST /v2/rpc` carries one JSON frame and answers with one.

signer.yaml:
    http:
      listen: 0.0.0.0:8443
      cert: tls/server.pem
      key: tls/server.key
      client_ca: tls/clients-ca.pem             # mtls: client certificates are verified against these CAs
      authenticators: [k8s_sa, mtls, token]
      k8s_sa: {audience: tracekit-signer, ...}  # tracekit/identity/k8s_sa.py
      token_file: tls/bearer                     # token: a bearer secret (identity token:http)
      insecure_loopback: false                   # plain HTTP, only on a loopback address

Every request is authenticated again (no session state): the authenticators are asked in order and the first that
recognises its credential decides. Bodies over MAX_LINE are refused; reads time out like the other transports; the
connection is kept alive between requests. RPC refusals are answered with status 200 and the error frame.
"""
import ipaddress
import json
import socketserver
import ssl
from http.server import BaseHTTPRequestHandler

from tracekit.identity.k8s_sa import K8sSaAuthenticator
from tracekit.identity.mtls import MtlsAuthenticator
from tracekit.identity.token import BearerToken
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import READ_TIMEOUT_S, parse_frame

PATH = "/v2/rpc"
KEYS = {"listen", "cert", "key", "client_ca", "authenticators", "k8s_sa", "token_file", "insecure_loopback"}


def configure(cfg):
    """((host, port), authenticators, TLS context or None) for the `http` section of signer.yaml, its paths absolute.
    ValueError for anything missing, unknown or unsafe."""
    if not isinstance(cfg, dict) or set(cfg) - KEYS:
        raise ValueError(f"http: a mapping of {sorted(KEYS)}")
    host, _, port = str(cfg.get("listen", "")).rpartition(":")
    # lean: host:port with an IPv4 address or a name; bracketed IPv6 when a deployment needs it
    if not host or not port.isdigit():
        raise ValueError("http.listen: host:port")
    names = cfg.get("authenticators")
    if not isinstance(names, list) or not names or len(set(names)) != len(names) or set(names) - {"k8s_sa", "mtls", "token"}:
        raise ValueError("http.authenticators: a list of k8s_sa, mtls, token")
    tls = None
    if cfg.get("cert") and cfg.get("key"):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cfg["cert"], cfg["key"])
        if cfg.get("client_ca"):
            tls.load_verify_locations(cfg["client_ca"])
            tls.verify_mode = ssl.CERT_OPTIONAL   # a presented certificate must verify; mtls refuses a missing one
    elif cfg.get("cert") or cfg.get("key") or cfg.get("insecure_loopback") is not True or not _loopback(host):
        raise ValueError("http: needs cert and key (plain HTTP only with insecure_loopback on a loopback address)")
    auths = []
    for name in names:
        if name == "mtls":
            if not (tls and cfg.get("client_ca")):
                raise ValueError("http: mtls needs cert, key and client_ca")
            auths.append(MtlsAuthenticator())
        elif name == "token":
            if not cfg.get("token_file"):
                raise ValueError("http: token needs token_file")
            auths.append(BearerToken(cfg["token_file"]))
        else:
            try:
                auths.append(K8sSaAuthenticator(**cfg.get("k8s_sa", {})))
            except TypeError as e:
                raise ValueError(f"http.k8s_sa: {e}") from None
    return (host, int(port)), auths, tls


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

    def do_POST(self):
        if self.path != PATH:
            return self._reply(404, RPCError("invalid_request", f"POST {PATH}").wire(), close=True)
        n = self.headers.get("Content-Length", "")
        if not n.isdigit():
            return self._reply(411, RPCError("invalid_request", "Content-Length required").wire(), close=True)
        if int(n) > MAX_LINE:
            return self._reply(413, RPCError("quota_exceeded", f"body longer than {MAX_LINE} bytes").wire(), close=True)
        try:
            body = self.rfile.read(int(n))
        except OSError:   # the read timeout, or the peer went away
            body = b""
        if len(body) < int(n):
            self.close_connection = True
            return
        try:
            frame = parse_frame(body)
            out = self.server.handle_frame(self.server.authenticate(self, frame), frame)
        except RPCError as e:
            out = e.wire()
        self._reply(200, out)

    def _reply(self, status, obj, close=False):
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class HttpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # lean: one thread per connection, and the read timeout is per recv, not per request; a bounded pool and a request
    # deadline when the signer service needs a connection cap
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, authenticators, tls, handle_frame, read_timeout=READ_TIMEOUT_S):
        self.authenticators, self.tls, self.handle_frame, self.read_timeout = authenticators, tls, handle_frame, read_timeout
        super().__init__(address, _Handler)

    def finish_request(self, request, client_address):
        """In the connection's thread: the TLS handshake (under the read timeout), then the requests."""
        request.settimeout(self.read_timeout)
        if self.tls is None:
            return super().finish_request(request, client_address)
        try:
            conn = self.tls.wrap_socket(request, server_side=True)
        except OSError:   # the read timeout, not TLS, or a certificate the client CAs don't vouch for
            return
        try:
            super().finish_request(conn, client_address)
        finally:
            conn.close()

    def authenticate(self, conn, frame):
        for a in self.authenticators:
            identity = a.authenticate(conn, frame)
            if identity is not None:
                return identity
        raise RPCError("unauthenticated", "no credential this signer accepts")
