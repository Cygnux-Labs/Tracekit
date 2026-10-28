"""HTTP(S) server for the network services (signer, issuer, gateway, viewer, Slack bridge, metrics, witness, ingest)
and the loopback ones (OTLP receiver, proxy, `tracekit observe`).

The TLS handshake runs in the connection's own thread under a timeout, never in accept() on the serving thread, so a
client that connects and says nothing holds one handler slot until it times out instead of stalling every client.
Each read has a timeout, and each connection an overall deadline, so a client that sends one byte per read timeout is
closed too. Handler threads are bounded overall and per client IP: a connection over the per-IP limit is closed at once,
one over the overall limit waits briefly for a free slot and is then closed. A handler whose answers may take long (a
long-poll, an event stream) stops the deadline once it has read a request (stop_deadline) and, on a kept-alive
connection, starts it again before reading the next one (restart_deadline), so an idle connection is closed too. An
event stream also leaves the request limits for limits of its own (to_stream), so open pages never use up the
requests their address may make."""
import socket
import ssl
import sys
import threading
import time
from email import errors
from http.server import ThreadingHTTPServer

TIMEOUT_S = 10.0
DEADLINE_S = 30.0
MAX_THREADS = 64
MAX_PER_IP = 8
MAX_STREAMS, MAX_STREAMS_PER_IP = 64, 16
SLOT_WAIT_S = 1.0
DRAIN_BYTES, DRAIN_S = 1 << 20, 0.5


def drain(sock):
    """Before closing: read what the client already sent. A request answered without reading its body (a refused POST)
    leaves that body unread, and closing a socket with unread data resets the connection, so the client can lose the
    answer (on Windows, always). Up to DRAIN_BYTES, for at most DRAIN_S in all: a client trickling bytes can't keep
    its slot."""
    try:
        sock.shutdown(socket.SHUT_WR)   # the answer is complete: the client reads it, then closes its side
        end, left = time.monotonic() + DRAIN_S, DRAIN_BYTES
        while left > 0:
            wait = end - time.monotonic()
            if wait <= 0:
                return
            sock.settimeout(wait)
            got = len(sock.recv(min(left, 65536)))
            if not got:
                return
            left -= got
    except OSError:
        pass


# the defects of a header line; the parser also records defects of the body a multipart/* type says follows (no
# boundary), which no header line has
HEADER_DEFECTS = (errors.InvalidHeaderDefect, errors.MissingHeaderBodySeparatorDefect,
                  errors.FirstHeaderLineIsContinuationDefect, errors.MisplacedEnvelopeHeaderDefect)


def body_length(headers, digits=12):
    """(n, None): the request's body is the n bytes its one Content-Length says (n None: it declares none). (None, why):
    its framing is refused, with the connection closed. Every server here reads a body by Content-Length only; a proxy
    in front that frames it otherwise (by Transfer-Encoding, by another Content-Length, by a header line Python's parser
    dropped together with every one after it, folded into the one before it, or split at a bare CR: Lines)
    would forward the bytes past it as another request. A value is ASCII digits only: int() also takes `+1`, `1_0`
    and other scripts' digits, and raises past 4,300 of them."""
    if any(isinstance(d, HEADER_DEFECTS) for d in headers.defects) or any(
            "\r" in v or "\n" in v for v in headers.values()):
        return None, "a malformed header line"
    if "transfer-encoding" in headers:
        return None, "Transfer-Encoding isn't supported: send the body with Content-Length"
    n = headers.get_all("content-length") or []
    if len(n) > 1:
        return None, "more than one Content-Length"
    if n and not (n[0].isascii() and n[0].isdigit() and len(n[0]) <= digits):
        return None, f"Content-Length: at most {digits} ASCII digits"
    return (int(n[0]) if n else None), None


class Lines:
    """A mixin, before BaseHTTPRequestHandler, whose headers carry, as a defect body_length refuses, a CR that doesn't
    end its line: Python's parser takes it as a line end (`X-A: b\rContent-Length: 2` is two headers, `X-A: b\r\r\n`
    ends them), where a proxy in front may not, and the parsed headers keep no trace of it."""

    def parse_request(self):
        rfile, lines = self.rfile, [self.raw_requestline]

        class Kept:   # each line the header parser reads, as it came
            def readline(_, limit=-1):
                lines.append(rfile.readline(limit))
                return lines[-1]
        self.rfile = Kept()
        try:
            ok = super().parse_request()
        finally:
            self.rfile = rfile
        if ok and any(b"\r" in line.removesuffix(b"\n").removesuffix(b"\r") for line in lines):
            self.headers.defects.append(errors.InvalidHeaderDefect("a CR that doesn't end its line"))
        return ok


def read_body(handler, n):
    """The n bytes of the body `handler` (a BaseHTTPRequestHandler) reads, or None when fewer arrive (the deadline cut
    the connection, the client stopped sending): a part of a request is never acted on, and the connection closes."""
    try:
        body = handler.rfile.read(n)
    except OSError:   # the read timeout, or the peer went away
        body = b""
    if len(body) < n:
        handler.close_connection = True
        return None
    return body


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # socketserver's listen backlog of 5: on Linux a burst past it has its handshakes dropped, so a client waits a
    # second or more for a retransmit, or connects while the server doesn't see the connection for that long
    request_queue_size = 256

    def __init__(self, addr, handler, ssl_context=None, timeout=TIMEOUT_S, max_threads=MAX_THREADS,
                 deadline=DEADLINE_S, max_per_ip=MAX_PER_IP, max_streams=MAX_STREAMS,
                 max_streams_per_ip=MAX_STREAMS_PER_IP):
        super().__init__(addr, handler)
        self.ssl_context, self.conn_timeout, self.deadline = ssl_context, timeout, deadline
        self._slots = threading.BoundedSemaphore(max_threads)
        self.max_per_ip, self._per_ip, self._ip_lock = max_per_ip, {}, threading.Lock()
        self._conn = threading.local()   # the connection this handler thread serves, its deadline timer, its stream
        self.max_streams, self.max_streams_per_ip, self._streams = max_streams, max_streams_per_ip, {}

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
        self._conn.stream = False
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
            drain(request)
            self.shutdown_request(request)
            if self._conn.stream:
                self._stream_release(client_address[0])
            else:
                self._slots.release()
                self._ip_release(client_address[0])

    def handle_error(self, request, client_address):
        """A connection cut by its deadline, a timeout or the client, or a TLS record that doesn't open, is routine: no
        traceback for it."""
        if not isinstance(sys.exc_info()[1], (ConnectionError, socket.timeout, ssl.SSLError)):
            super().handle_error(request, client_address)

    def to_stream(self, ip):
        """From the handler's thread, before it answers with an event stream: the connection leaves the request limits
        for the stream limits (max_streams overall, max_streams_per_ip). False, and nothing changes, when those are
        reached."""
        with self._ip_lock:
            if sum(self._streams.values()) >= self.max_streams or self._streams.get(ip, 0) >= self.max_streams_per_ip:
                return False
            self._streams[ip] = self._streams.get(ip, 0) + 1
        self._conn.stream = True
        self._slots.release()
        self._ip_release(ip)
        return True

    def _stream_release(self, ip):
        with self._ip_lock:
            self._streams[ip] -= 1
            if not self._streams[ip]:
                del self._streams[ip]

    def restart_deadline(self, seconds=None):
        """From the handler's thread: the connection is cut `seconds` (default `deadline`) from now."""
        self.stop_deadline()
        timer = self._conn.timer = threading.Timer(seconds or self.deadline, self._cut, (self._conn.raw,))
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
