"""Egress observer: a forward and CONNECT proxy outside the agent that tells the v2 signer which hosts each run reached,
how many bytes each way and when, as the observer's own signer identity. No TLS interception: it sees hosts and ports,
never paths or content. docs/egress.md.

    tracekit egress serve --config egress.yaml

egress.yaml:
    http: {listen: 0.0.0.0:3128, cert: tls/egress.pem, key: tls/egress.key, client_ca: {acme.org: tls/acme-ca.pem},
           authenticators: [mtls, k8s_sa]}   # the signer's `http` section (tracekit/transport/http.py); or
    listen: 127.0.0.1:3128                 # plain HTTP on a loopback address (system mode: the agent's uid is read
                                           # from /proc)
    signer: https://signer.internal:8443   # the observer's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client),
                                           # granted observe_effect in signer.yaml authorize
    allow: [10.0.0.7, doh.internal]        # raw IPs, DNS-over-HTTPS endpoints and internal hosts the agents may
                                           # reach anyway

Attribution, per request: `Proxy-Authorization: Basic base64(<run_id>:<run token>)` (HTTPS_PROXY=
https://<run_id>:<run token>@egress:3128) is attribution by token once the signer confirms it issued that token for
that run (else 407; 503 while it can't be asked); else the identity the authenticators accept (a client certificate,
or `Proxy-Authorization: Bearer <token>`), or on Linux the uid that owns a loopback client's socket, is attribution by
identity: the signer gives it that identity's latest open run. Else 407. That identity, when there is one, goes with a
token too (`caller`): the signer attributes by it instead when the token was issued to another identity.
Relative paths are from the config file.

Either listener takes SOCKS5 too (inside TLS on the `http` one), as microsandbox's and E2B's outbound proxies speak it:
CONNECT, with a username and password that are a run id and its run token (attribution by token), or none (attribution
by identity). A host name is resolved and checked as CONNECT's. An address is reached only through the server name its
TLS ClientHello sends, which must resolve to it here, with the same checks; that name is the host recorded. An address
`allow` lists passes as itself, any protocol.

CONNECT host:port: the TLS ClientHello's SNI must be the host, else the tunnel is closed before anything reaches it;
a raw IP address, a DNS-over-HTTPS endpoint or a name that resolves to a loopback, private or link-local address is
refused (403) unless `allow` lists it (the proxy connects to the address it checked), and an allowed host needs no
SNI (any protocol). A host name observe_effect would not take (HOST) is refused (400). Plain HTTP requests in absolute form (GET http://host/path) are forwarded with Connection: close.
A client sends what attributes it (an HTTP request's head; SOCKS5's greeting and credentials) within PRE_AUTH_S, and
the ClientHello within the connection's deadline (netserver.DEADLINE_S) from then, else the connection is closed. A
loopback client's uid has at most MAX_TUNNELS connections open, counted from accept, and an attribution (its
connection's identity, else its run) at most MAX_TUNNELS tunnels: in system mode every agent connects from loopback,
which shares the transport's per-address limit, so no agent can hold every connection it gives.
Per (attribution, host, port, minute): bytes each way, connections opened, first and last activity. Each minute's
totals go to the signer (observe_effect) at the first heartbeat (every HEARTBEAT_S) after the minute ends, and a
heartbeat goes out with nothing to report too, so the signer knows the observer is alive. Totals the signer can't take
now wait for the next heartbeat, as does each one it refuses (a refused call is split until the refused totals are on
their own); on SIGTERM every total is sent, the current minute's included. Each call names this process (`instance`),
so the signer sees a restart.
"""
import argparse
import base64
import binascii
import datetime
import http.server
import ipaddress
import math
import os
import re
import select
import signal
import socket
import ssl
import sys
import threading
import time
import types
import urllib.parse
import uuid

from tracekit import yamlmini
from tracekit.netserver import Lines, body_length
from tracekit.proxy import HOP
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import HEARTBEAT_S, TAILER_LOST_S
from tracekit.transport import http as transport, loopback

KEYS = {"http", "listen", "signer", "allow"}
HOST = re.compile(r"[a-z0-9._:-]{1,253}")   # what observe_effect takes as a host
RUN_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,1024}")   # a run token: no escapes, so 256 totals fit one signer frame
# lean: the public DNS-over-HTTPS endpoints by name; DoH on any other host is HTTPS to it, recorded as such
DOH = {"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
       "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net",
       "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "dns.nextdns.io",
       "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com", "doh.dns.sb", "dns.alidns.com", "doh.pub",
       "dns.mullvad.net", "doh.mullvad.net", "freedns.controld.com"}
CONNECT_TIMEOUT_S, IDLE_S = 30, 600
MAX_BODY = 32 * 1024 * 1024   # a plain HTTP request's body, streamed through in CHUNK pieces, never held whole
CHUNK = 64 * 1024
# tunnels open at once per attribution (its connection's identity, else its run), below the transport's per-address
# limit (256): in system mode every agent reaches the proxy from loopback, so one agent can't hold all of them
MAX_TUNNELS = 64
PRE_AUTH_S = 5   # from a connection's accept (or its request's first byte) to what attributes it
MAX_EFFECTS = 256   # per observe_effect call
MAX_REFUSED = 10_000   # totals the signer refused, kept to send again; past it the oldest are dropped (and counted)


def _iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Observer:
    """The per-minute totals and their delivery to the signer."""

    def __init__(self, client, allow=()):
        self.client, self.allow = client, set(allow)
        self.totals, self.lock = {}, threading.Lock()
        self.conns = {}   # a loopback client's uid -> its connections open (_Handler.handle), under lock
        # lean: unsent totals wait in memory while the signer is unreachable (one per host, port and minute); spool
        # them to disk if outages outlast the observer's memory
        self.queue = []   # [(request_id, effects)] not yet acknowledged, oldest first
        self.instance = uuid.uuid4().hex   # this process, in every call: the signer sees a restart

    def refused(self, host):
        """Why the agents may not reach `host`, or None."""
        if host in self.allow:
            return None
        try:   # any form the resolver reads as an address: 8.8.8.8, 134744072, 0x08080808, 8.8.2056, ::1
            socket.inet_pton(socket.AF_INET6, host) if ":" in host else socket.inet_aton(host)
            return (f"{host} is an IP address: name the host, so the observer can record and check it (or add it to "
                    "allow in egress.yaml)")
        except OSError:
            pass
        if host in DOH:
            return (f"{host} is a DNS-over-HTTPS endpoint, which would hide the hosts resolved through it: use the "
                    "system resolver (or add it to allow in egress.yaml)")
        return None

    def resolve(self, host, port):
        """([address], None) to connect to for host:port, or (None, (status, why not)). A host `allow` doesn't list
        must resolve to public addresses only: the proxy would otherwise open the agents' way to what only it can
        reach."""
        why = self.refused(host)
        if why:
            return None, (403, why)
        try:
            addresses = [a[4][:2] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        except OSError as e:
            return None, (502, f"{host} could not be resolved: {e}")
        for ip, _ in addresses:
            if host not in self.allow and not _public(ip):
                return None, (403, f"{host} resolves to {ip}, a loopback, private or link-local address: add it to "
                                   "allow in egress.yaml if agents may reach it, or to NO_PROXY in the agent's "
                                   "environment for an internal service it reaches directly")
        return addresses, None

    def add(self, who, host, port, out=0, back=0, opened=False):
        now = time.time()
        with self.lock:
            t = self.totals.setdefault((who, host, port, int(now // 60)), {"bytes_out": 0, "bytes_in": 0,
                                                                            "connections": 0, "first": now})
            t["bytes_out"] += out
            t["bytes_in"] += back
            t["connections"] += opened
            t["last"] = now

    def check(self, run_id, token):
        """None when the signer issued `token` for run `run_id` of this observer's tenant, else (status, why not)."""
        # lean: one signer round trip per connection that names a run; cache checked tokens if it shows in latency
        try:
            self.client.observe_effect({"request_id": "eg-" + uuid.uuid4().hex, "instance": self.instance,
                                        "effects": [], "check": {"run_id": run_id, "run_token": token}})
        except RPCError as e:
            if e.code == "run_token_invalid":
                return 407, (f"{e.message}: send the run token register_run returned for run {run_id} (the SDKs' "
                             "run.proxy_env)")
            return 503, f"the signer could not check the run token ({e}): retry"
        except SignerUnavailable as e:
            return 503, f"the signer could not be reached to check the run token ({e}): retry"
        return None

    def flush(self, now=None):
        """Send the totals of every minute that ended before `now` (time.time(); math.inf: all), or a heartbeat with
        none. False when the signer could not be reached (they are sent with the next one). A call the signer refuses
        is split until each total it refuses is on its own; those are sent again with the next one, and past MAX_REFUSED
        the oldest are dropped, which it says on stderr."""
        now = time.time() if now is None else now
        with self.lock:
            done = [k for k in self.totals if (k[3] + 1) * 60 <= now]
            effects = [_effect(k, self.totals.pop(k)) for k in done]
        self.queue += [("eg-" + uuid.uuid4().hex, effects[i:i + MAX_EFFECTS])
                       for i in range(0, len(effects), MAX_EFFECTS)]
        if not self.queue:
            self.queue.append(("eg-" + uuid.uuid4().hex, []))
        refused = []
        while self.queue:
            rid, chunk = self.queue[0]
            try:
                self.client.observe_effect({"request_id": rid, "instance": self.instance, "effects": chunk})
            except (SignerUnavailable, RPCError) as e:
                # a rate limit (retry_after_ms) refuses the call, not its totals: keep them for the next heartbeat
                if isinstance(e, SignerUnavailable) or e.code == "unavailable" or e.retry_after_ms is not None:
                    self.queue[:0] = refused
                    return False
                self.queue.pop(0)
                if len(chunk) > 1:
                    half = len(chunk) // 2
                    self.queue[:0] = [("eg-" + uuid.uuid4().hex, c) for c in (chunk[:half], chunk[half:])]
                    continue
                why = e
                refused += [(rid, chunk)] if chunk else []
                continue
            self.queue.pop(0)
        if refused:   # one line per heartbeat, not one per total
            print(f"tracekit egress: the signer refused {len(refused)} observation(s) ({why.code}: {why.message}); sent "
                  "again with the next heartbeat" + ("; grant this observer observe_effect in signer.yaml authorize"
                                                     if why.code == "forbidden" else ""), file=sys.stderr)
        if len(refused) > MAX_REFUSED:   # a refusal that never changes must not grow without end
            print(f"tracekit egress: dropped the {len(refused) - MAX_REFUSED} oldest refused observation(s), past "
                  f"{MAX_REFUSED} kept", file=sys.stderr)
            refused = refused[-MAX_REFUSED:]
        self.queue = refused
        return True


def _effect(k, t):
    who, host, port, _ = k
    att = ({"run_id": who[1], "run_token": who[2], **({"caller": who[3]} if who[3] else {})} if who[0] == "token"
           else {"caller": who[1]})
    return {**att, "kind": "net", "host": host, "port": port, "bytes_out": t["bytes_out"], "bytes_in": t["bytes_in"],
            "connections": t["connections"], "first_ts": _iso(t["first"]), "last_ts": _iso(t["last"])}


def _target(authority):
    """(host, port) of a CONNECT authority host:port or [v6]:port, the host in lower case; (None, None) if malformed."""
    host, _, port = authority.rpartition(":")
    host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    host = host.lower().rstrip(".")
    if not (port.isascii() and port.isdigit() and 0 < int(port) < 65536 and HOST.fullmatch(host)):
        return None, None
    return host, int(port)


def _sni(record):
    """The server name of a TLS ClientHello record, or None."""
    # lean: the ClientHello must fit its first TLS record (16 KiB); one split across records reads as no SNI
    try:
        if record[0] != 0x16 or record[5] != 1:   # handshake, client_hello
            return None
        i = 9 + 2 + 32   # record and handshake headers, client_version, random
        i += 1 + record[i]   # session_id
        i += 2 + int.from_bytes(record[i:i + 2], "big")   # cipher_suites
        i += 1 + record[i]   # compression_methods
        end = i + 2 + int.from_bytes(record[i:i + 2], "big")
        i += 2
        while i + 4 <= end:
            typ, n = int.from_bytes(record[i:i + 2], "big"), int.from_bytes(record[i + 2:i + 4], "big")
            if typ == 0:   # server_name: list length, name_type 0 (host_name), name length, name
                return record[i + 9:i + 9 + int.from_bytes(record[i + 7:i + 9], "big")].decode("ascii").lower()
            i += 4 + n
    except (IndexError, UnicodeDecodeError):
        pass
    return None


def _proc(address):
    """(host, port) as /proc/net/tcp{,6} shows it: each 32-bit word of the address in host byte order, then the port."""
    raw = socket.inet_pton(socket.AF_INET6 if ":" in address[0] else socket.AF_INET, address[0])
    return "".join(f"{int.from_bytes(raw[i:i + 4], sys.byteorder):08X}" for i in range(0, len(raw), 4)) + \
        f":{address[1]:04X}"


def _peer_uid(client, server):
    """On Linux, the uid owning the established socket at `client` (address, port) connected to `server`, or None."""
    # lean: Linux only (/proc/net/tcp{,6}); elsewhere a client sends a run token or an identity the proxy accepts
    want = (_proc(client), _proc(server), "01")   # local, remote, ESTABLISHED
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="ascii") as f:
                rows = [line.split() for line in f.read().splitlines()[1:]]
        except OSError:
            continue
        for r in rows:
            if tuple(r[1:4]) == want:
                return int(r[7])
    return None


def _connect(addresses):
    """A connection to the first of `addresses` that answers."""
    for a in addresses:
        try:
            return socket.create_connection(a, CONNECT_TIMEOUT_S)
        except OSError as e:
            err = e
    raise err


NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _public(ip):
    """Whether address `ip` is public; an IPv4-mapped or NAT64 (64:ff9b::/96) address by the IPv4 address it carries,
    which on an IPv6-only network with DNS64 is where it really goes."""
    a = ipaddress.ip_address(ip.partition("%")[0])
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    elif a in NAT64:
        a = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
    return a.is_global


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), 1 << 20))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return bytes(data)


class _Unread:
    """A connection's reader with the byte read ahead of it put back in front; http.server reads lines from it."""

    def __init__(self, first, rest):
        self.first, self.rest = first, rest

    def readline(self, limit=-1):
        line, self.first = self.first, b""
        return line if line.endswith(b"\n") or len(line) == limit else line + self.rest.readline(limit - len(line))

    def __getattr__(self, name):
        return getattr(self.rest, name)


def _relay(a, b, count):
    """Copy both ways until either side closes or both are idle for IDLE_S; `count(out, back)` for each chunk (out:
    from `a`)."""
    while True:
        ready = [s for s in (a, b) if isinstance(s, ssl.SSLSocket) and s.pending()] or \
            select.select([a, b], [], [], IDLE_S)[0]
        if not ready:
            return
        for s in ready:
            data = s.recv(65536)
            if not data:
                return
            (b if s is a else a).sendall(data)
            count(len(data), 0) if s is a else count(0, len(data))


class _Handler(Lines, http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    rbufsize = 0   # unbuffered: after the headers, the tunnel's bytes are read from the socket itself

    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle_one_request(self):
        self.server.restart_deadline(PRE_AUTH_S)   # to its head; _who gives the rest the whole deadline
        super().handle_one_request()

    def log_message(self, *a):
        pass

    def _refuse(self, status, msg, headers=()):
        body = f"tracekit egress: {msg}\n".encode()
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _identity(self, auth):
        """scheme:subject of the identity the authenticators accept for this connection (`auth`: a bearer
        Proxy-Authorization, sent to them as Authorization), else None."""
        presented = auth or (isinstance(self.connection, ssl.SSLSocket) and self.connection.getpeercert())
        if not (self.server.authenticators and presented):   # no credential is no failed authentication
            return None
        conn = types.SimpleNamespace(headers={"Authorization": auth} if auth else {}, connection=self.connection,
                                     client_address=self.client_address)
        try:
            i = self.server.authenticate(conn, {"method": "observe_effect"})
        except RPCError:
            return None
        return f"{i.scheme}:{i.subject}"

    def _caller(self, auth=""):
        """The connection's identity: what the authenticators accept, else on Linux the uid owning a loopback client's
        socket; None."""
        caller = self._identity(auth)
        if caller is None and self.uid is not None:
            caller = f"uid:{self.uid}"
        return caller if caller and len(caller) <= 256 else None

    def _who(self):
        """The attribution of this request, or None once it is refused (407, or 503 when the signer can't check its
        run token): ("token", run_id, token, the connection's identity or None) or ("identity", identity)."""
        self.server.restart_deadline()   # its head is in: checking it and what follows have the whole deadline
        auth = self.headers.get("Proxy-Authorization", "")
        scheme, _, cred = auth.partition(" ")
        caller = self._caller(auth if scheme.lower() == "bearer" else "")
        if scheme.lower() == "basic":
            try:
                run_id, _, token = base64.b64decode(cred.strip(), validate=True).decode("utf-8").partition(":")
            except (binascii.Error, UnicodeDecodeError):
                run_id = token = ""
            why = self._checked(run_id, token) if RUN_ID.fullmatch(run_id) and TOKEN.fullmatch(token) else (
                407, "Proxy-Authorization names no run id and token a run could have (a token is 1 to 1024 of A-Z a-z "
                     "0-9 . _ ~ + / = -): send the run's own, as the SDKs' run.proxy_env does")
            if why is None:
                return "token", run_id, token, caller
        elif caller:
            return "identity", caller
        else:
            why = 407, ("no run: send Proxy-Authorization: Basic base64(<run_id>:<run token>) (HTTPS_PROXY="
                        "https://<run_id>:<run token>@<this proxy>), or an identity this proxy accepts")
        self._refuse(*why, [("Proxy-Authenticate", 'Basic realm="tracekit egress"')] if why[0] == 407 else [])
        return None

    def _checked(self, run_id, token):
        """observer.check, limited per client address: past its failed checks (the HTTP transport's per-address
        failed-authentication limit) the signer isn't asked, so one client can't spend what the checks of every run
        need."""
        per_addr, ip = self.server.failed[0], self.client_address[0]
        try:
            per_addr.take(ip, "", spend=0)
        except RPCError:
            return 429, "too many failed run token checks from this address: retry later"
        why = self.server.observer.check(run_id, token)
        if why and why[0] == 407:
            try:
                per_addr.take(ip, "failed run token checks")
            except RPCError:
                pass
        return why

    def handle(self):
        """SOCKS5 when the connection's first byte says so, else HTTP; a loopback client's uid holds at most
        MAX_TUNNELS connections."""
        srv, obs = self.server, self.server.observer
        self.uid = _peer_uid(self.client_address, self.connection.getsockname()) if ipaddress.ip_address(
            self.client_address[0]).is_loopback else None
        with obs.lock:
            n = obs.conns.get(self.uid, 0)
            if self.uid is not None and n < MAX_TUNNELS:
                obs.conns[self.uid] = n + 1
        if self.uid is not None and n >= MAX_TUNNELS:
            return print(f"tracekit egress: closed a connection of uid {self.uid} at once: it has {MAX_TUNNELS} open",
                         file=sys.stderr)
        try:
            srv.restart_deadline(PRE_AUTH_S)
            try:
                first = self.connection.recv(1)
            except OSError:
                return
            if first == b"\x05":
                return self._socks5()
            self.rfile = _Unread(first, self.rfile)
            super().handle()
        finally:
            with obs.lock:
                if self.uid is not None:
                    obs.conns[self.uid] -= 1
                    if not obs.conns[self.uid]:
                        del obs.conns[self.uid]

    def _socks5(self):
        """A SOCKS5 CONNECT (RFC 1928), its version byte read, as microsandbox's and E2B's outbound proxies send it: a
        username and password (RFC 1929) are a run id and its run token, attribution by token; with none, the
        connection's identity. SOCKS5 carries no reason for a refusal: it goes to stderr."""
        c, obs = self.connection, self.server.observer

        def reply(code):
            c.sendall(b"\x05" + bytes([code]) + b"\x00\x01" + bytes(6))
        try:
            methods = _recv_exact(c, _recv_exact(c, 1)[0])
            caller = self._caller()
            if 2 in methods:
                c.sendall(b"\x05\x02")
                run_id = _recv_exact(c, _recv_exact(c, 2)[1]).decode("latin-1")
                token = _recv_exact(c, _recv_exact(c, 1)[0]).decode("latin-1")
                self.server.restart_deadline()   # its credentials are in: checking them and its request have the rest
                why = self._checked(run_id, token) if RUN_ID.fullmatch(run_id) and TOKEN.fullmatch(token) else (
                    407, "the SOCKS5 username and password are no run id and run token a run could have")
                c.sendall(b"\x01\x00" if why is None else b"\x01\x01")
                who = "token", run_id, token, caller
            elif caller:
                c.sendall(b"\x05\x00")
                self.server.restart_deadline()
                who, why = ("identity", caller), None
            else:
                c.sendall(b"\x05\xff")
                why = 407, ("no run: give the SOCKS5 proxy the run id as its username and the run token as its "
                            "password, or connect with an identity this proxy accepts")
            if why:
                return print(f"tracekit egress: refused a SOCKS5 client: {why[1]}", file=sys.stderr)
            _, cmd, _, atyp = _recv_exact(c, 4)
            if cmd != 1 or atyp not in (1, 3, 4):
                reply(7 if cmd != 1 else 8)
                return print("tracekit egress: refused a SOCKS5 request: only CONNECT (TCP) is taken", file=sys.stderr)
            if atyp == 3:   # a host name, resolved and checked as CONNECT's
                host = _recv_exact(c, _recv_exact(c, 1)[0]).decode("latin-1").lower().rstrip(".")
            else:   # an address the client resolved: see _tunnel
                host = socket.inet_ntop(socket.AF_INET if atyp == 1 else socket.AF_INET6,
                                        _recv_exact(c, 4 if atyp == 1 else 16))
            port = int.from_bytes(_recv_exact(c, 2), "big")
            if atyp != 3:
                addresses, why = ([(host, port)] if host in obs.allow else None), None
            elif HOST.fullmatch(host):
                addresses, why = obs.resolve(host, port)
            else:
                addresses, why = None, (400, "not a host name observe_effect takes")
            if why:
                reply({403: 2, 502: 4}.get(why[0], 1))
                return print(f"tracekit egress: refused a SOCKS5 request for {host[:253]}:{port}: {why[1]}",
                             file=sys.stderr)
            reply(0)
        except OSError:
            return
        self._tunnel(who, host, port, addresses)

    def do_CONNECT(self):
        host, port = _target(self.path)
        if host is None:
            return self._refuse(400, "CONNECT host:port")
        who = self._who()
        if who is None:
            return
        addresses, why = self.server.observer.resolve(host, port)
        if why:
            return self._refuse(*why)
        self.send_response(200, "Connection established")
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        self._tunnel(who, host, port, addresses)

    def _tunnel(self, who, host, port, addresses):
        """Relay the client to host:port at `addresses` once its TLS ClientHello names `host`, unless `allow` lists it.
        `addresses` None: `host` is an address the client resolved itself, and the ClientHello's server name must
        resolve to it here (resolve's checks on a name included); that name is the host recorded."""
        obs, srv = self.server.observer, self.server
        whose = (who[3] or who[1]) if who[0] == "token" else who[1]
        with srv.observer.lock:
            n = srv.tunnels.get(whose, 0)
            if n < MAX_TUNNELS:
                srv.tunnels[whose] = n + 1
        if n >= MAX_TUNNELS:
            return print(f"tracekit egress: closed a tunnel to {host}:{port} before it reached it: {whose[:256]} has "
                         f"{MAX_TUNNELS} tunnels open; close some first", file=sys.stderr)
        try:
            hello = b""
            if host not in obs.allow:
                head = _recv_exact(self.connection, 5)
                if head[0] == 0x16:   # a TLS handshake record; anything else is closed at once
                    hello = head + _recv_exact(self.connection, int.from_bytes(head[3:5], "big"))
                name = _sni(hello)
                if addresses is None:
                    # lean: a name whose answers change between the client's lookup and this one closes the tunnel;
                    # share one caching resolver between them if that shows
                    found, why = obs.resolve(name, port) if name and HOST.fullmatch(name) else (None, None)
                    addresses = [a for a in found or () if ipaddress.ip_address(a[0]) == ipaddress.ip_address(host)]
                    if not addresses:
                        print(f"tracekit egress: closed a tunnel to {host}:{port} before it reached it: " + (
                            why[1] if why else (f"its TLS server name {name!r} does not resolve to it here" if name
                                                else "it sends no TLS server name") + "; an address is reached only "
                            "by a TLS server name that resolves to it, unless allow in egress.yaml lists it"),
                            file=sys.stderr)
                        return
                    host = name
                elif name != host:
                    print(f"tracekit egress: closed a tunnel to {host}:{port} before it reached it: its TLS server name "
                          f"is {name!r}, not {host!r}; clients must connect to the host they name", file=sys.stderr)
                    return
            srv.stop_deadline()   # the ClientHello came in time and names the host: the tunnel may stay open
            with _connect(addresses) as up:
                obs.add(who, host, port, len(hello), opened=True)
                up.sendall(hello)
                _relay(self.connection, up, lambda out, back: obs.add(who, host, port, out, back))
        except OSError:   # either side went away, the host can't be reached, or the deadline cut a slow ClientHello
            pass
        finally:
            with srv.observer.lock:
                srv.tunnels[whose] -= 1
                if not srv.tunnels[whose]:
                    del srv.tunnels[whose]

    def _forward(self):
        obs, url = self.server.observer, urllib.parse.urlsplit(self.path)
        try:
            host, port = (url.hostname or "").lower().rstrip("."), url.port or 80
        except ValueError:
            host = ""
        if url.scheme != "http" or not HOST.fullmatch(host):
            return self._refuse(400, "send http:// requests in absolute form, and CONNECT for https://")
        who = self._who()
        if who is None:
            return
        size, why = body_length(self.headers)
        if why:
            return self._refuse(411, "send the request body with a Content-Length")
        size = size or 0
        if size > MAX_BODY:
            return self._refuse(413, f"request body over {MAX_BODY} bytes: send large uploads over https (CONNECT)")
        addresses, why = obs.resolve(host, port)
        if why:
            return self._refuse(*why)
        path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
        head = [f"{self.command} {path} HTTP/1.1", f"Host: {url.netloc.rpartition('@')[2]}", "Connection: close"] + [
            f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in HOP | {"proxy-connection"}] + (
            [f"Content-Length: {size}"] if size else [])
        data = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1")
        self.close_connection = True
        try:
            with _connect(addresses) as up:
                obs.add(who, host, port, len(data), opened=True)
                up.sendall(data)
                self.server.restart_deadline()   # the body has the whole deadline, however long the connect took
                left = size
                while left:   # the body, streamed as it arrives
                    chunk = self.connection.recv(min(left, CHUNK))
                    if not chunk:   # the client went away or stopped sending
                        return
                    up.sendall(chunk)
                    obs.add(who, host, port, len(chunk))
                    left -= len(chunk)
                self.server.stop_deadline()
                while chunk := up.recv(CHUNK):
                    self.connection.sendall(chunk)
                    obs.add(who, host, port, back=len(chunk))
        except OSError as e:
            obs.add(who, host, port)
            try:
                self._refuse(502, f"{host}:{port} could not be reached: {e}")
            except OSError:
                pass

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _forward


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or "signer" not in cfg or ("http" in cfg) == ("listen" in cfg):
        raise ValueError(f"{path}: needs signer and one of http or listen; takes {sorted(KEYS)}")
    if not (isinstance(cfg.get("allow", []), list) and all(isinstance(h, str) for h in cfg.get("allow", []))):
        raise ValueError(f"{path}: allow lists host names and IP addresses")
    cfg["allow"] = [h.lower().rstrip(".") for h in cfg.get("allow", [])]
    if "http" in cfg:
        transport.resolve(cfg["http"], os.path.dirname(os.path.abspath(path)))
    return cfg


def serve(cfg, client=None):
    """The proxy's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    if "http" in cfg:
        address, auths, tls = transport.configure(cfg["http"])
    else:
        host, _, port = str(cfg["listen"]).rpartition(":")
        if not (port.isdigit() and loopback(host)):
            raise ValueError("listen: a loopback host:port (plain HTTP); anything else needs the http section")
        address, auths, tls = (host, int(port)), [], None
    srv = transport.HttpServer(address, auths, tls, None, handler=_Handler)
    srv.observer = Observer(client or Client(cfg["signer"]), cfg.get("allow", ()))
    srv.tunnels = {}   # attribution -> tunnels open (_tunnel)
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit egress")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the egress observer in the foreground").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        srv = serve(load_config(a.config))
    except (OSError, ValueError) as e:
        print(f"tracekit egress: {e}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"tracekit egress: {host}:{port}", flush=True)
    stop = threading.Event()

    def beat():
        while True:
            if not srv.observer.flush():
                print("tracekit egress: the signer is unreachable; the runs this observer covers record observer_lost "
                      f"after {TAILER_LOST_S:.0f} s without a heartbeat", file=sys.stderr)
            if stop.wait(HEARTBEAT_S):
                return
    t = threading.Thread(target=beat, name="tracekit-egress-heartbeat", daemon=True)
    t.start()
    signal.signal(signal.SIGTERM, signal.default_int_handler)   # systemd, docker, k8s: stop as on Ctrl-C, reporting
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        stop.set()
        t.join()
        srv.observer.flush(math.inf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
