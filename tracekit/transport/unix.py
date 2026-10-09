"""Unix socket transport: the caller's identity is its peer uid; on Linux every frame must carry that uid in
SCM_CREDENTIALS (tracekit/identity/uid.py). Who may connect at all is up to the permissions of the socket's directory."""
import socket
import socketserver

from tracekit.identity import uid
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import READ_TIMEOUT_S, serve, write_frame


class _Conn(socketserver.StreamRequestHandler):
    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle(self):
        try:
            auth = uid.UidAuthenticator(self.request)
        except RPCError as e:
            try:
                write_frame(self.request, e.wire())
            except OSError:
                pass
            return
        rfile = uid.CredentialReader(self.request, auth.uid) if uid.PER_FRAME else self.rfile
        serve(self.request, rfile, auth.authenticate, self.server.handle_frame)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    # lean: one thread per connection, and the read timeout is per recv, not per frame; a bounded pool and a frame
    # deadline when the signer service needs a connection cap
    daemon_threads = True

    def __init__(self, path, handle_frame, read_timeout=READ_TIMEOUT_S):
        self.handle_frame, self.read_timeout = handle_frame, read_timeout
        super().__init__(path, _Conn)

    def server_bind(self):
        if uid.PER_FRAME:   # set before listen(): accepted sockets inherit it, so no frame arrives unstamped
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        super().server_bind()
