"""HTTP(S) server for the network services that face other machines (witness, ingest gateway).

The TLS handshake runs in the connection's own thread under a timeout, never in accept() on the serving thread, so a
client that connects and says nothing holds one handler slot until it times out instead of stalling every client.
Each read has a timeout too, and the number of handler threads is bounded: connections over the limit are closed."""
import threading
from http.server import ThreadingHTTPServer

TIMEOUT_S = 10.0
MAX_THREADS = 64


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, ssl_context=None, timeout=TIMEOUT_S, max_threads=MAX_THREADS):
        super().__init__(addr, handler)
        self.ssl_context, self.conn_timeout = ssl_context, timeout
        self._slots = threading.BoundedSemaphore(max_threads)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(self.conn_timeout)  # handshake and every read or write after it
            if self.ssl_context:
                try:
                    request = self.ssl_context.wrap_socket(request, server_side=True)
                except OSError:  # failed or timed-out handshake: drop this connection only
                    return
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self._slots.release()
