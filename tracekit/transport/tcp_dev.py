"""Loopback TCP transport for dev signers where Unix sockets are missing (Windows).

The signer binds 127.0.0.1 on port 0, then writes `endpoint.json` (port and token, user-only). Each connection
starts with mutual proof of the token: the client sends a nonce; the signer answers HMAC(token, "signer", nonce_c) and
its own nonce; only after checking that does the client send HMAC(token, "client", nonce_s). Neither side sends the
token, so a process squatting the port learns nothing it can replay.
"""
import json
import os
import secrets
import socket
import socketserver

from tracekit.identity.token import check_proof, proof
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import READ_TIMEOUT_S, read_frame, serve, write_frame

HOST = "127.0.0.1"


def _nonce(frame):
    n = (frame or {}).get("nonce")
    if not isinstance(n, str) or not 16 <= len(n) <= 128:
        raise RPCError("unauthenticated", "handshake needs a nonce of 16-128 characters")
    return n


class _Conn(socketserver.StreamRequestHandler):
    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle(self):
        token = self.server.token
        try:
            nonce_c = _nonce(read_frame(self.rfile))
            nonce_s = secrets.token_hex(16)
            write_frame(self.request, {"proof": proof(token.secret, "signer", nonce_c), "nonce": nonce_s})
            check_proof(token.secret, (read_frame(self.rfile) or {}).get("proof"), "client", nonce_s)
        except RPCError as e:
            try:
                write_frame(self.request, e.wire())
            except OSError:
                pass
            return
        except OSError:
            return
        serve(self.request, self.rfile, token.authenticate, self.server.handle_frame)


class TcpDevServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # lean: one thread per connection, and the read timeout is per recv, not per frame; a bounded pool and a frame
    # deadline when the signer service needs a connection cap
    daemon_threads = True

    def __init__(self, endpoint_path, token, handle_frame, read_timeout=READ_TIMEOUT_S, publish=None):
        """Binds, then writes `endpoint_path`: the port and token, plus the fields of `publish`."""
        self.token, self.handle_frame, self.read_timeout = token, handle_frame, read_timeout
        super().__init__((HOST, 0), _Conn)
        tmp = endpoint_path + ".tmp"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({**(publish or {}), "port": self.server_address[1], "token": token.secret}, f)
        os.replace(tmp, endpoint_path)


def connect(endpoint_path, timeout=READ_TIMEOUT_S):
    """(socket, rfile) to the dev signer in `endpoint_path`, after it has proved it holds the token."""
    with open(endpoint_path) as f:
        ep = json.load(f)
    return dial(HOST, ep["port"], ep["token"], timeout)


def dial(host, port, token, timeout=READ_TIMEOUT_S):
    """(socket, rfile) to the signer at host:port, after it has proved it holds `token`; then we prove it too."""
    sock = socket.create_connection((host, port), timeout)
    try:
        rfile = sock.makefile("rb")
        nonce_c = secrets.token_hex(16)
        write_frame(sock, {"method": "hello", "nonce": nonce_c})
        reply = read_frame(rfile) or {}
        check_proof(token, reply.get("proof"), "signer", nonce_c)
        write_frame(sock, {"proof": proof(token, "client", _nonce(reply))})
    except BaseException:
        sock.close()
        raise
    return sock, rfile
