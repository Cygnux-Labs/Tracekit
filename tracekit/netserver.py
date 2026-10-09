"""HTTP(S) server for the network services that face other machines (witness, ingest gateway).

The TLS handshake runs in the connection's own thread under a timeout, never in accept() on the serving thread, so a
client that connects and says nothing holds one handler slot until it times out instead of stalling every client.
Each read has a timeout, and each connection an overall deadline, so a client that sends one byte per read timeout is
closed too. Handler threads are bounded overall and per client IP: a connection over the per-IP limit is closed at once,
one over the overall limit waits briefly for a free slot and is then closed."""
import socket
import threading
from http.server import ThreadingHTTPServer

TIMEOUT_S = 10.0
DEADLINE_S = 30.0
MAX_THREADS = 64
MAX_PER_IP = 8
SLOT_WAIT_S = 1.0


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, ssl_context=None, timeout=TIMEOUT_S, max_threads=MAX_THREADS,
                 deadline=DEADLINE_S, max_per_ip=MAX_PER_IP):
        super().__init__(addr, handler)
        self.ssl_context, self.conn_timeout, self.deadline = ssl_context, timeout, deadline
        self._slots = threading.BoundedSemaphore(max_threads)
        self.max_per_ip, self._per_ip, self._ip_lock = max_per_ip, {}, threading.Lock()

    def _ip_release(self, ip):
        with self._ip_lock:
            self._per_ip[ip] -= 1
            if not self._per_ip[ip]:
                del self._per_ip[ip]

    def process_request(self, request, client_address):
        ip = client_address[0]
        with self._ip_lock:
            over = self._per_ip.get(ip, 0) >= self.max_per_ip
            if not over:
                self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
        if over:
            self.shutdown_request(request)
            return
        if not self._slots.acquire(timeout=SLOT_WAIT_S):  # the accept loop pauses while this waits
            self._ip_release(ip)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            self._ip_release(ip)
            raise

    def process_request_thread(self, request, client_address):
        raw = request.dup()  # wrap_socket detaches request; the dup still reaches the connection
        timer = threading.Timer(self.deadline, self._cut, (raw,))  # handshake, request line, headers and body
        timer.daemon = True
        timer.start()
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
            timer.cancel()
            raw.close()
            self.shutdown_request(request)
            self._slots.release()
            self._ip_release(client_address[0])

    @staticmethod
    def _cut(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)  # a blocked read returns at once and the handler ends
        except OSError:
            pass
