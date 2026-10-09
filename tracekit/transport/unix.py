"""Unix socket transport: the caller's identity is its peer uid, read again for every frame."""
import os
import socketserver

from tracekit.identity.uid import UidAuthenticator
from tracekit.transport import READ_TIMEOUT_S, serve


class _Conn(socketserver.StreamRequestHandler):
    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle(self):
        serve(self.request, self.rfile, self.server.authenticator.authenticate, self.server.handle_frame)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    # lean: one thread per connection; a bounded pool when the signer service needs a connection cap
    daemon_threads = True

    def __init__(self, path, handle_frame, authenticator=None, read_timeout=READ_TIMEOUT_S):
        self.handle_frame, self.read_timeout = handle_frame, read_timeout
        self.authenticator = authenticator or UidAuthenticator()
        super().__init__(path, _Conn)
        os.chmod(path, 0o600)
