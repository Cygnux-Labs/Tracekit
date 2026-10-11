"""Python client for the v2 signer: one persistent, pipelined connection, sync and asyncio.

    from tracekit.sdk.client import Client
    with Client().run(agent="my-agent") as run:
        d = run.decide("call-1", "Bash", '{"command": "ls"}')
        if d["decision"] == "allow":
            run.complete("call-1", "ok")

The signer is the Unix socket in `$TRACEKIT_SIGNER`, `tcp://host:port` with `$TRACEKIT_SIGNER_TOKEN` (the dev
transport), or an `https://host:port` URL (each call is one POST /v2/rpc; `$TRACEKIT_SIGNER_TOKEN_FILE` names a bearer
token file, re-read per call so a rotated service-account token is picked up; `$TRACEKIT_SIGNER_CERT`/`_KEY` a client
certificate for mTLS; `$TRACEKIT_SIGNER_CA` pins the signer's CA). In system mode (`tracekit init --v2`) the signer is
the one the root-owned /etc/tracekit/client.json names. Without either, a same-user dev signer is found or started
(tracekit/sdk/autospawn.py). Requests go out in order on one connection and the signer answers them in order, so any
number of threads can have calls in flight; a call that may block (`approval_wait`) gets a connection of its own so it
holds up no one. Every request is validated against the RPC contract, and its size against the signer's frame limit,
before it is sent. Calls that change state carry a `request_id`; a call whose connection drops is resent with the same
id, which the signer answers with its original response. Event calls carry this process's `stream` and a `client_seq`
that grows by one per event of a run; a run's events go out one at a time, each once the one before it is answered,
so they reach the signer in client_seq order on every transport and retry. The client writes nothing to disk.
"""
import asyncio
import collections
import concurrent.futures
import contextlib
import contextvars
import http.client
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
import warnings
import weakref

import rfc8785

from tracekit import __version__
from tracekit.format.canon import StrictJSONError, event_hash, loads_strict
from tracekit.signer import rpc_schema
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPC_VERSION, RPCError
from tracekit.transport import parse_frame, read_frame, tcp_dev, write_frame

CONNECT_TIMEOUT_S = 2
RETRIES = 3
_EVENT_METHODS = {m for m, s in rpc_schema.REQUESTS.items() if "client_seq" in s["properties"]}
_LONG_POLLS = {m for m, s in rpc_schema.REQUESTS.items() if "timeout_ms" in s["properties"]}

current_run = contextvars.ContextVar("tracekit_current_run", default=None)   # set inside `with client.run(...)`


class SignerUnavailable(Exception):
    pass


class Incompatible(Exception):
    """The signer answered but does not speak this client's protocol version. It is left running."""


class _ConnectionLost(Exception):
    pass


def _new_id():
    return uuid.uuid4().hex


def _encode(method, req):
    """The frame of `req` as sent; invalid_request when it is not JSON, quota_exceeded over the signer's frame limit."""
    try:
        data = json.dumps({"method": method, **req}, separators=(",", ":"), ensure_ascii=False).encode()
    except (TypeError, ValueError) as e:
        raise RPCError("invalid_request", f"the {method} request is not JSON: {e}") from None
    if len(data) > MAX_LINE:
        raise RPCError("quota_exceeded", f"the {method} request is {len(data)} bytes, over the signer's limit of "
                                         f"{MAX_LINE} bytes per request; it was not sent")
    return data


def connect(path, timeout=CONNECT_TIMEOUT_S, token=None):
    """(socket, rfile, hello) for the signer at `path`, after checking its protocol range. `path` is a Unix socket, or
    `tcp://host:port` for a signer on the loopback TCP transport, which must prove it holds `token`
    ($TRACEKIT_SIGNER_TOKEN by default) before we prove it too (transport/tcp_dev.py)."""
    sock = None
    try:
        if path.startswith("tcp://"):
            host, _, port = path[len("tcp://"):].rpartition(":")
            if host not in ("127.0.0.1", "::1", "localhost"):   # frames after the handshake are plaintext
                raise SignerUnavailable(f"{path}: tcp:// signers must be on loopback (127.0.0.1, ::1 or localhost)")
            token = token or os.environ.get("TRACEKIT_SIGNER_TOKEN")
            if not token:
                raise SignerUnavailable(f"{path}: tcp:// signers need TRACEKIT_SIGNER_TOKEN")
            sock, rfile = tcp_dev.dial(host, int(port), token, timeout)
        elif hasattr(socket, "AF_UNIX"):
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(timeout)
            sock.connect(path)
            rfile = sock.makefile("rb")
        else:
            raise SignerUnavailable(f"this platform has no Unix sockets: name the signer tcp://host:port, not {path}")
        write_frame(sock, {"method": "hello"})
        hello = read_frame(rfile)
    except (OSError, RPCError, ValueError) as e:
        if sock:
            sock.close()
        raise SignerUnavailable(f"no signer answering at {path}: {e}") from None
    sock.settimeout(None)
    try:
        _check(hello, path)
    except Incompatible:
        sock.close()
        raise
    return sock, rfile, hello


def _check(hello, where):
    """Refuses a signer whose `hello` names no protocol range holding this client's."""
    proto = (hello or {}).get("proto")
    if not (isinstance(proto, list) and len(proto) == 2 and proto[0] <= RPC_VERSION <= proto[1]):
        hello = hello or {}
        raise Incompatible(
            f"the Tracekit signer {hello.get('version', '?')} (pid {hello.get('pid', '?')}, protocol {proto}) at {where} "
            f"cannot serve this client {__version__} (protocol {RPC_VERSION}). It was left running. Stop it with "
            "`tracekit down`, or replace it with `tracekit up --replace`")
    if hello.get("version") != __version__:
        warnings.warn(f"Tracekit signer {hello.get('version')} serves client {__version__}", stacklevel=3)


class _Https:
    """POST /v2/rpc to an HTTPS signer: one kept-alive connection per thread and host, the bearer token re-read per
    call."""

    def __init__(self, url):
        u = urllib.parse.urlsplit(url)
        self.host, self.port = u.hostname, u.port or 443
        self.ctx = ssl.create_default_context(cafile=os.environ.get("TRACEKIT_SIGNER_CA"))
        if os.environ.get("TRACEKIT_SIGNER_CERT"):
            self.ctx.load_cert_chain(os.environ["TRACEKIT_SIGNER_CERT"], os.environ.get("TRACEKIT_SIGNER_KEY"))
        self.token_file, self.pid, self.hello = os.environ.get("TRACEKIT_SIGNER_TOKEN_FILE"), None, None
        self.conns = weakref.WeakSet()   # every thread's, for close()

    def _host(self, req):
        """The host of the run or approval `req` names. A central signer's replica (docs/deploy-kubernetes.md) prefixes
        its ids with its route, `<service>-<n>.`: such an id goes to host `<service>-<n>` in the signer's domain."""
        first, _, rest = self.host.partition(".")
        route, dot, _ = (req.get("run_id") or req.get("approval_id") or req.get("analyzes") or "").partition(".")
        if not (dot and re.fullmatch(re.escape(first) + r"-[0-9]+", route)):
            return self.host
        return f"{route}.{rest}" if rest else route

    def post(self, body, timeout, host=None):
        """The answer frame to `body` from `host` (default the signer's); _ConnectionLost when the request may not have
        arrived, SignerUnavailable on a timeout."""
        headers = {"Content-Type": "application/json"}
        if self.token_file:
            try:
                with open(self.token_file, encoding="utf-8") as f:
                    headers["Authorization"] = "Bearer " + f.read().strip()
            except OSError as e:
                raise SignerUnavailable(f"cannot read the signer token file: {e}") from None
        if self.pid != os.getpid():   # a forked child: its own connections
            self.pid, self.local, self.conns = os.getpid(), threading.local(), weakref.WeakSet()
        host = host or self.host
        if not hasattr(self.local, "conns"):
            self.local.conns = {}
        conn = self.local.conns.get(host)
        if conn is None:
            conn = self.local.conns[host] = http.client.HTTPSConnection(host, self.port, context=self.ctx)
            self.conns.add(conn)
        conn.timeout = timeout
        if conn.sock:
            conn.sock.settimeout(timeout)
        try:
            conn.request("POST", "/v2/rpc", body, headers)
            return parse_frame(conn.getresponse().read())
        except socket.timeout:
            conn.close()   # reopened by the next request
            raise SignerUnavailable(f"no answer from the signer within {timeout:g}s") from None
        except (OSError, http.client.HTTPException, RPCError):
            conn.close()
            raise _ConnectionLost() from None

    def rpc(self, req, body, timeout):
        if self.hello is None:
            hello = self.post(_encode("hello", {}), timeout)
            if "error" in hello:
                e = hello["error"]
                raise RPCError(e.get("code"), e.get("message", ""))
            _check(hello, f"https://{self.host}:{self.port}")
            self.hello = hello
        return self.post(body, timeout, self._host(req))

    def close(self):
        for conn in list(self.conns):
            conn.close()


class _Conn:
    def __init__(self, sock, rfile):
        self.sock, self.rfile, self.pending, self.out = sock, rfile, collections.deque(), queue.SimpleQueue()

    def write(self):
        """Sends the queued frames in order, so a signer that stops reading holds up this thread alone; drop() wakes it."""
        try:
            for data in iter(self.out.get, None):
                self.sock.sendall(data)
        except OSError:
            self.drop()

    def drop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # wakes the reader, which fails what is pending
        except OSError:
            pass


def _default_signer():
    """$TRACEKIT_SIGNER, or in system mode the signer the root-owned config names: there a $TRACEKIT_SIGNER that names
    another signer is refused, so an agent cannot point its hooks at a signer it runs itself."""
    from tracekit.client import system_config
    env, system = os.environ.get("TRACEKIT_SIGNER"), (system_config() or {}).get("signer")
    if system and env and env != system:
        raise SignerUnavailable(f"TRACEKIT_SIGNER={env[:256]} is not the system signer {system}; refused")
    return system or env


_clients = weakref.WeakSet()


def _after_fork():
    """A forked child starts with fresh locks: one that another thread of the parent held would never be released."""
    for c in list(_clients):
        c._lock, c._order = threading.Lock(), {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


class Client:
    """Thread-safe. Methods named after the RPCs (`decide`, `status`, ...) take the request dict and return the
    response dict, or raise RPCError; `request_id`, `stream` and `client_seq` are filled in when missing."""

    def __init__(self, signer=None, timeout=30.0):
        self.signer = signer or _default_signer()
        self.timeout, self.hello = timeout, None
        self._https = _Https(self.signer) if (self.signer or "").startswith("https://") else None
        self._lock = threading.Lock()
        self._pid = self._conn = None
        self._order = {}   # run_id -> the lock its event calls hold from taking their client_seq to their answer
        _clients.add(self)

    def run(self, agent, **fields):
        """Register a run (`agent` is a name or {"name", "version"}); the handle holds its run token."""
        req = {"agent": {"name": agent} if isinstance(agent, str) else agent, **fields}
        return RunHandle(self, self.register_run(req))

    def call(self, method, req=None):
        req = dict(req or {})
        if "request_id" in rpc_schema.REQUESTS[method]["properties"]:
            req.setdefault("request_id", _new_id())
        timeout = self.timeout + req.get("timeout_ms", 0) / 1000
        deadline = time.monotonic() + timeout   # for the whole call: its turn, every retry
        with self._turn(method, req, deadline):
            for _ in range(RETRIES):
                left = max(deadline - time.monotonic(), 0.001)
                try:
                    if self._https:
                        with self._lock:
                            body = self._prepare(method, req)
                        reply = self._https.rpc(req, body, left)
                        self.hello = self._https.hello
                    elif method in _LONG_POLLS:
                        reply = self._poll(method, req, left)
                    else:
                        reply = self._send(method, req).result(left)
                except _ConnectionLost:
                    continue
                except concurrent.futures.TimeoutError:
                    self.close()
                    raise SignerUnavailable(f"no answer from the signer within {timeout:g}s") from None
                if "error" in reply:
                    e = reply["error"]
                    if e.get("code") in ("run_closed", "unknown_run"):   # no more events for it: drop its counter
                        with self._lock:
                            self._seqs.pop(req.get("run_id"), None)
                            self._order.pop(req.get("run_id"), None)
                    raise RPCError(e.get("code"), e.get("message", ""), e.get("retry_after_ms"))
                return reply
            raise SignerUnavailable(f"lost the connection to the signer {RETRIES} times")

    def close(self):
        with self._lock:
            conn, self._conn = self._conn, None
        if conn:
            conn.drop()
        if self._https:
            self._https.close()

    @contextlib.contextmanager
    def _turn(self, method, req, deadline):
        """An event call that takes its client_seq here first waits until the run's event before it is answered, so a
        run's events reach the signer in client_seq order on every transport and retry. One that does not get its turn
        by `deadline` uses up a client_seq (the signer's client_counter_gap covers it) and is SignerUnavailable."""
        if method not in _EVENT_METHODS or "client_seq" in req:
            yield
            return
        with self._lock:
            turn = self._order.setdefault(req.get("run_id"), threading.Lock())
        if not turn.acquire(timeout=max(deadline - time.monotonic(), 0)):
            with self._lock:
                self._prepare(method, req)
            raise SignerUnavailable("no answer from the signer in time: the run's previous event is still unanswered")
        try:
            yield
        finally:
            turn.release()

    def _prepare(self, method, req, connect=lambda: None):
        """-> the frame to send. Fills in `stream` and `client_seq` and validates `req`; counts the event even when
        `connect()` raises, so the signer's client_counter_gap covers a call it never saw (one a caller then ran with
        its fail mode open). Call under self._lock."""
        if self._pid != os.getpid():   # new client, or a forked child: its own stream and connection
            # lean: one counter and order lock per run until it is closed or refused as closed; a run abandoned
            # without either keeps its entries for the client's life
            self._pid, self._conn, self.stream, self._seqs = os.getpid(), None, _new_id(), {}
        run_id = req.get("run_id")
        fresh = method in _EVENT_METHODS and "client_seq" not in req
        if fresh:
            req.update(stream=self.stream, client_seq=self._seqs.get(run_id, 0))
        _validate(method, req)
        data = _encode(method, req)
        if fresh:
            self._seqs[run_id] = req["client_seq"] + 1
        connect()
        if method == "close_run":   # no events after close: drop the counter
            self._seqs.pop(run_id, None)
            self._order.pop(run_id, None)
        return data

    def _send(self, method, req):
        with self._lock:
            data = self._prepare(method, req, self._ensure_conn)
            fut = concurrent.futures.Future()
            self._conn.pending.append(fut)
            self._conn.out.put(data + b"\n")
            return fut

    def _ensure_conn(self):
        if self._conn is None:
            self._conn = self._connect()

    def _poll(self, method, req, timeout):
        """One request on a connection of its own, closed after the answer."""
        _validate(method, req)
        data = _encode(method, req)
        sock, rfile = self._dial()
        sock.settimeout(timeout)
        try:
            sock.sendall(data + b"\n")
            reply = read_frame(rfile)
        except socket.timeout:
            raise SignerUnavailable(f"no answer from the signer within {timeout:g}s") from None
        except (OSError, RPCError):
            reply = None
        finally:
            sock.close()
        if reply is None:
            raise _ConnectionLost()
        return reply

    def _dial(self):
        if self.signer:
            sock, rfile, self.hello = connect(self.signer)
        else:
            from tracekit.sdk import autospawn
            sock, rfile, self.hello = autospawn.ensure()
        return sock, rfile

    def _connect(self):
        conn = _Conn(*self._dial())
        threading.Thread(target=self._read, args=(conn,), daemon=True, name="tracekit-client").start()
        threading.Thread(target=conn.write, daemon=True, name="tracekit-client-write").start()
        return conn

    def _read(self, conn):
        try:
            while True:
                frame = read_frame(conn.rfile)
                if frame is None:
                    break
                conn.pending.popleft().set_result(frame)
        except (OSError, RPCError, IndexError):   # IndexError: an answer nobody asked for
            pass
        with self._lock:
            if self._conn is conn:
                self._conn = None
            conn.out.put(None)   # the writer stops
            conn.sock.close()
            while conn.pending:
                conn.pending.popleft().set_exception(_ConnectionLost())


def fail_open(fail_modes, tool_class=None):
    """Whether a call of `tool_class` may run while the signer cannot be reached: the class's entry in register_run's
    `fail_modes`, else their `default`, else closed. A signer refusal is never a reason to fail open."""
    modes = fail_modes or {}
    return modes.get(tool_class, modes.get("default", "closed")) == "open"


def _validate(method, req):
    errs = rpc_schema.validate(rpc_schema.REQUESTS[method], req)
    if errs:
        raise RPCError("invalid_request", "; ".join(errs))


def _rpc_method(name):
    def method(self, req=None):
        return self.call(name, req)
    method.__name__ = name
    return method


for _name in rpc_schema.REQUESTS:
    setattr(Client, _name, _rpc_method(_name))


class RunHandle:
    """A registered run. As a context manager it is the current run (`current_run`) and is closed on exit."""

    def __init__(self, client, registered):
        self.client, self.registered = client, registered
        self.run_id, self.run_token = registered["run_id"], registered["run_token"]
        self.closed = False
        self._decided = {}   # tool_call_id -> the decision_id and args_digest its `complete` must name

    def call(self, method, **fields):
        """Any per-run RPC (`state_write`, `approval_wait`, `read`, ...) with this run's id and token."""
        return self.client.call(method, {"run_id": self.run_id, "run_token": self.run_token, **fields})

    def decide(self, tool_call_id, tool, args, **fields):
        """`args` is the model's raw arguments string, or an already parsed value."""
        d = self.call("decide", tool_call_id=tool_call_id, tool=tool, args=args,
                      **{"args_source": "raw" if isinstance(args, str) else "parsed", **fields})
        try:
            digest = event_hash({"tool": tool, "args": loads_strict(args) if isinstance(args, str) else args})
        except (StrictJSONError, rfc8785.CanonicalizationError):
            return d   # the signer has no args digest to bind either; complete needs explicit fields
        self._decided[tool_call_id] = {"decision_id": d["decision_id"], "args_digest": digest}
        return d

    def complete(self, tool_call_id, status="ok", **fields):
        """Defaults decision_id and args_digest to those of the last `decide` for this tool call."""
        return self.call("complete", tool_call_id=tool_call_id, status=status,
                         **{**self._decided.pop(tool_call_id, {}), **fields})

    def observe(self, value, source, trust="untrusted", **fields):
        """Record content that entered the run other than as a tool result (a mail, a ticket, a page the app fetched)
        so the signer's provenance index has it; the task or user prompt goes in with trust="trusted". The signer
        records a commitment, never the value."""
        return self.call("observe", value=value, source=source, trust=trust, **fields)

    def approval_consume(self, tool_call_id, tool, args, approval_id_hint=None, **fields):
        """Call right before running a call that was not denied: {"ok": True} when it may run now. `args` as for
        `decide`; `approval_id_hint` is the approval id the framework saved, if any."""
        hint = {"approval_id_hint": approval_id_hint} if approval_id_hint else {}
        return self.call("approval_consume", tool_call_id=tool_call_id, tool=tool, args=args,
                         **{"args_source": "raw" if isinstance(args, str) else "parsed", **hint, **fields})

    def close(self, reason=None):
        if not self.closed:
            self.call("close_run", **({"reason": reason} if reason else {}))
            self.closed = True

    def __enter__(self):
        self._ctx = current_run.set(self)
        return self

    def __exit__(self, *exc):
        current_run.reset(self._ctx)
        self.close()


class _Async:
    # lean: each awaited call holds a worker thread while it waits (the default executor caps how many are in flight);
    # await the connection's futures directly if agents need hundreds of concurrent calls
    def __init__(self, sync):
        self._sync = sync

    def __getattr__(self, name):
        attr = getattr(self._sync, name)
        if not callable(attr):
            return attr

        async def call(*args, **kwargs):
            return await asyncio.to_thread(attr, *args, **kwargs)
        return call


class AsyncClient(_Async):
    """`Client` with awaitable methods, over the same connection logic."""

    def __init__(self, signer=None, timeout=30.0):
        super().__init__(Client(signer, timeout))

    async def run(self, agent, **fields):
        return AsyncRunHandle(await asyncio.to_thread(self._sync.run, agent, **fields))


class AsyncRunHandle(_Async):
    async def __aenter__(self):
        self._ctx = current_run.set(self)
        return self

    async def __aexit__(self, *exc):
        current_run.reset(self._ctx)
        await self.close()
