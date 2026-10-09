"""Python client for the v2 signer: one persistent, pipelined connection, sync and asyncio.

    from tracekit.sdk.client import Client
    with Client().run(agent="my-agent") as run:
        d = run.decide("call-1", "Bash", '{"command": "ls"}')
        if d["decision"] == "allow":
            run.complete("call-1", "ok")

The signer is the Unix socket in `$TRACEKIT_SIGNER`; without it, a same-user dev signer is found or started
(tracekit/sdk/autospawn.py). Requests go out in order on one connection and the signer answers them in order, so any
number of threads can have calls in flight. Every request is validated against the RPC contract before it is sent.
Calls that change state carry a `request_id`; a call whose connection drops is resent with the same id, which the
signer answers with its original response. Event calls carry this process's `stream` and a `client_seq` that grows
by one per event of a run. The client writes nothing to disk.
"""
import asyncio
import collections
import concurrent.futures
import contextvars
import os
import socket
import threading
import uuid
import warnings

from tracekit import __version__
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import RPC_VERSION, RPCError
from tracekit.transport import read_frame, write_frame

CONNECT_TIMEOUT_S = 2
RETRIES = 3
_EVENT_METHODS = {m for m, s in rpc_schema.REQUESTS.items() if "client_seq" in s["properties"]}

current_run = contextvars.ContextVar("tracekit_current_run", default=None)   # set inside `with client.run(...)`


class SignerUnavailable(Exception):
    pass


class Incompatible(Exception):
    """The signer answered but does not speak this client's protocol version. It is left running."""


class _ConnectionLost(Exception):
    pass


def _new_id():
    return uuid.uuid4().hex


def connect(path, timeout=CONNECT_TIMEOUT_S):
    """(socket, rfile, hello) for the signer listening on Unix socket `path`, after checking its protocol range."""
    if not hasattr(socket, "AF_UNIX"):
        # lean: Unix sockets only; Windows dev signers need transport.tcp_dev here and in testing.serve_fake
        raise SignerUnavailable("this platform has no Unix sockets; the v2 client does not support it yet")
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        rfile = sock.makefile("rb")
        write_frame(sock, {"method": "hello"})
        hello = read_frame(rfile)
    except (OSError, RPCError) as e:
        sock.close()
        raise SignerUnavailable(f"no signer answering at {path}: {e}") from None
    proto = (hello or {}).get("proto")
    if not (isinstance(proto, list) and len(proto) == 2 and proto[0] <= RPC_VERSION <= proto[1]):
        sock.close()
        hello = hello or {}
        raise Incompatible(
            f"the Tracekit signer {hello.get('version', '?')} (pid {hello.get('pid', '?')}, protocol {proto}) at {path} "
            f"cannot serve this client {__version__} (protocol {RPC_VERSION}). It was left running. Stop it with "
            "`tracekit down`, or replace it with `tracekit up --replace`")
    if hello.get("version") != __version__:
        warnings.warn(f"Tracekit signer {hello.get('version')} serves client {__version__}", stacklevel=2)
    sock.settimeout(None)
    return sock, rfile, hello


class _Conn:
    def __init__(self, sock, rfile):
        self.sock, self.rfile, self.pending = sock, rfile, collections.deque()

    def drop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # wakes the reader, which fails what is pending
        except OSError:
            pass


class Client:
    """Thread-safe. Methods named after the RPCs (`decide`, `status`, ...) take the request dict and return the
    response dict, or raise RPCError; `request_id`, `stream` and `client_seq` are filled in when missing."""

    def __init__(self, signer=None, timeout=30.0):
        self.signer = signer or os.environ.get("TRACEKIT_SIGNER")
        self.timeout, self.hello = timeout, None
        self._lock = threading.Lock()
        self._pid = self._conn = None

    def run(self, agent, **fields):
        """Register a run (`agent` is a name or {"name", "version"}); the handle holds its run token."""
        req = {"agent": {"name": agent} if isinstance(agent, str) else agent, **fields}
        return RunHandle(self, self.register_run(req))

    def call(self, method, req=None):
        req = dict(req or {})
        if "request_id" in rpc_schema.REQUESTS[method]["properties"]:
            req.setdefault("request_id", _new_id())
        timeout = self.timeout + req.get("timeout_ms", 0) / 1000
        for _ in range(RETRIES):
            fut = self._send(method, req)
            try:
                reply = fut.result(timeout)
            except _ConnectionLost:
                continue
            except concurrent.futures.TimeoutError:
                self.close()
                raise SignerUnavailable(f"no answer from the signer within {timeout:g}s") from None
            if "error" in reply:
                e = reply["error"]
                raise RPCError(e.get("code"), e.get("message", ""), e.get("retry_after_ms"))
            return reply
        raise SignerUnavailable(f"lost the connection to the signer {RETRIES} times")

    def close(self):
        with self._lock:
            conn, self._conn = self._conn, None
        if conn:
            conn.drop()

    def _send(self, method, req):
        with self._lock:
            if self._pid != os.getpid():   # new client, or a forked child: its own stream and connection
                self._pid, self._conn, self.stream, self._seqs = os.getpid(), None, _new_id(), {}
            run_id = req.get("run_id")
            fresh = method in _EVENT_METHODS and "client_seq" not in req
            if fresh:
                req.update(stream=self.stream, client_seq=self._seqs.get(run_id, 0))
            errs = rpc_schema.validate(rpc_schema.REQUESTS[method], req)
            if errs:
                raise RPCError("invalid_request", "; ".join(errs))
            if self._conn is None:
                self._conn = self._connect()
            if fresh:
                self._seqs[run_id] = req["client_seq"] + 1
            elif method == "close_run":   # no events after close: drop the counter
                self._seqs.pop(run_id, None)
            fut = concurrent.futures.Future()
            self._conn.pending.append(fut)
            try:
                write_frame(self._conn.sock, {"method": method, **req})
            except OSError:
                self._conn.drop()
            return fut

    def _connect(self):
        if self.signer:
            sock, rfile, self.hello = connect(self.signer)
        else:
            from tracekit.sdk import autospawn
            sock, rfile, self.hello = autospawn.ensure()
        conn = _Conn(sock, rfile)
        threading.Thread(target=self._read, args=(conn,), daemon=True, name="tracekit-client").start()
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
            conn.sock.close()
            while conn.pending:
                conn.pending.popleft().set_exception(_ConnectionLost())


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

    def call(self, method, **fields):
        """Any per-run RPC (`state_write`, `approval_wait`, `read`, ...) with this run's id and token."""
        return self.client.call(method, {"run_id": self.run_id, "run_token": self.run_token, **fields})

    def decide(self, tool_call_id, tool, args, **fields):
        """`args` is the model's raw arguments string, or an already parsed value."""
        return self.call("decide", tool_call_id=tool_call_id, tool=tool, args=args,
                         **{"args_source": "raw" if isinstance(args, str) else "parsed", **fields})

    def complete(self, tool_call_id, status="ok", **fields):
        return self.call("complete", tool_call_id=tool_call_id, status=status, **fields)

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
