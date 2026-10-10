"""HTTP(S) server for the network services (signer, issuer, gateway, viewer, Slack bridge, metrics, witness, ingest).

The TLS handshake runs in the connection's own thread under a timeout, never in accept() on the serving thread, so a
client that connects and says nothing holds one handler slot until it times out instead of stalling every client.
Each read has a timeout, and each connection an overall deadline, so a client that sends one byte per read timeout is
closed too. Handler threads are bounded overall and per client IP: a connection over the per-IP limit is closed at once,
one over the overall limit waits briefly for a free slot and is then closed. A handler whose answers may take long (a
long-poll, an event stream) stops the deadline once it has read a request (stop_deadline) and, on a kept-alive
connection, starts it again before reading the next one (restart_deadline), so an idle connection is closed too."""
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
        self._conn = threading.local()   # the connection this handler thread serves, and its deadline timer

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
        raw = self._conn.raw = request.dup()  # wrap_socket detaches request; the dup still reaches the connection
        self.restart_deadline()  # handshake, request line, headers and body
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
            self.stop_deadline()
            raw.close()
            self.shutdown_request(request)
            self._slots.release()
            self._ip_release(client_address[0])

    def restart_deadline(self):
        """From the handler's thread: the connection is cut `deadline` seconds from now."""
        self.stop_deadline()
        timer = self._conn.timer = threading.Timer(self.deadline, self._cut, (self._conn.raw,))
        timer.daemon = True
        timer.start()

    def stop_deadline(self):
        """From the handler's thread: no deadline until restart_deadline(); every read and write still times out."""
        timer = getattr(self._conn, "timer", None)
        if timer:
            timer.cancel()

    @staticmethod
    def _cut(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)  # a blocked read returns at once and the handler ends
        except OSError:
            pass
