"""Python client for the v2 signer: one persistent, pipelined connection, sync and asyncio.

    from tracekit.sdk.client import Client
    with Client().run(agent="my-agent") as run:
        d = run.decide("call-1", "Bash", '{"command": "ls"}')
        if d["decision"] == "allow":
            run.complete("call-1", "ok")

The signer is the Unix socket in `$TRACEKIT_SIGNER`, `tcp://host:port` with `$TRACEKIT_SIGNER_TOKEN` (the dev
transport), or an `https://host:port` URL (each call is one POST /v2/rpc; `$TRACEKIT_SIGNER_TOKEN_FILE` names a bearer
token file, re-read per call so a rotated service-account token is picked up; `$TRACEKIT_SIGNER_CERT`/`_KEY` a client
certificate for mTLS; `$TRACEKIT_SIGNER_CA` pins the signer's CA), or `http://` on a loopback address, which the
signer's `insecure_loopback` listener serves. In system mode (`tracekit init --v2`) the signer is the one the
root-owned /etc/tracekit/client.json names. Without either, a same-user dev signer is found or started
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
import hashlib
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
from tracekit.core import jsonable
from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict
from tracekit.signer import rpc_schema
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPC_VERSION, RPCError
from tracekit.transport import loopback, parse_frame, read_frame, tcp_dev, write_frame

CONNECT_TIMEOUT_S = 2
KEEP_CALLS = 4096   # decided calls a RunHandle remembers for their `complete`, the oldest forgotten first
KEEP_RUNS = 65536   # runs a Client keeps an event counter for, the least recently used forgotten first
RETRIES = 3
TRANSFER = "a2a:transfer"   # the tool RunHandle.transfer decides
_EVENT_METHODS = {m for m, s in rpc_schema.REQUESTS.items() if "client_seq" in s["properties"]}
_LONG_POLLS = {m for m, s in rpc_schema.REQUESTS.items() if "timeout_ms" in s["properties"]}

current_run = contextvars.ContextVar("tracekit_current_run", default=None)   # set inside `with client.run(...)`


class SignerUnavailable(Exception):
    pass


class Refused(PermissionError):
    """Tracekit refused a call (a policy deny, an unapproved ask, a fail-closed outage). Frameworks that catch
    exceptions around tools or model calls must let it through, or the refusal turns into an empty answer or a call
    that runs anyway (docs/quickstarts/custom.md#frameworks-that-catch-exceptions)."""


class Incompatible(Exception):
    """The signer answered but does not speak this client's protocol version. It is left running. `older`: its protocol
    range ends below this client's, a signer from before an upgrade."""

    def __init__(self, message, older=False):
        super().__init__(message)
        self.older = older


class _ConnectionLost(Exception):
    """The request may not have arrived; its message says why."""


def _new_id():
    return uuid.uuid4().hex


def _encode(method, req):
    """The frame of `req` as sent; invalid_request when it is not JSON, quota_exceeded over the signer's frame limit.
    Arguments a frame can't carry (a lone surrogate) go as raw text with it escaped, which the signer decides as
    TK-ARGS-INVALID in a signed record."""
    try:
        data = json.dumps({"method": method, **req}, separators=(",", ":"), ensure_ascii=False).encode()
    except UnicodeEncodeError as e:
        if req.get("args_source") not in ("parsed", "coerced"):
            raise RPCError("invalid_request", f"the {method} request is not JSON: {e}") from None
        return _encode(method, {**req, "args_source": "raw", "args": json.dumps(req["args"], separators=(",", ":"))})
    except (TypeError, ValueError) as e:
        raise RPCError("invalid_request", f"the {method} request is not JSON: {e}") from None
    if len(data) > MAX_LINE:
        raise RPCError("quota_exceeded", f"the {method} request is {len(data)} bytes, over the signer's limit of "
                                         f"{MAX_LINE} bytes per request; it was not sent")
    return data


def connect(path, timeout=CONNECT_TIMEOUT_S, token=None):
    """(socket, rfile, hello) for the signer at `path`, after checking its protocol range. `path` is a Unix socket, or
    `tcp://host:port` for a signer on the loopback TCP transport, which must prove it holds `token`
    ($TRACEKIT_SIGNER_TOKEN when None; "" is none) before we prove it too (transport/tcp_dev.py)."""
    sock = None
    try:
        if path.startswith("tcp://"):
            host, _, port = path[len("tcp://"):].rpartition(":")
            if host not in ("127.0.0.1", "::1", "localhost"):   # frames after the handshake are plaintext
                raise SignerUnavailable(f"{path}: tcp:// signers must be on loopback (127.0.0.1, ::1 or localhost)")
            token = token if token is not None else os.environ.get("TRACEKIT_SIGNER_TOKEN")
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
            "`tracekit down`, or replace it with `tracekit up --replace`",
            older=isinstance(proto, list) and len(proto) == 2 and isinstance(proto[1], int) and proto[1] < RPC_VERSION)
    if hello.get("version") != __version__:
        warnings.warn(f"Tracekit signer {hello.get('version')} serves client {__version__}", stacklevel=3)


class _Https:
    """POST /v2/rpc to an HTTPS signer, or a plain HTTP one on a loopback address: one kept-alive connection per thread
    and host, the bearer token re-read per call."""

    def __init__(self, url, token_file=None):
        u = urllib.parse.urlsplit(url)
        self.url, self.plain = f"{u.scheme}://{u.netloc}", u.scheme == "http"
        self.host, self.port = u.hostname, u.port or (80 if self.plain else 443)
        self.ctx = None if self.plain else ssl.create_default_context(cafile=os.environ.get("TRACEKIT_SIGNER_CA"))
        if os.environ.get("TRACEKIT_SIGNER_CERT") and not self.plain:
            self.ctx.load_cert_chain(os.environ["TRACEKIT_SIGNER_CERT"], os.environ.get("TRACEKIT_SIGNER_KEY"))
        self.token_file, self.pid, self.hello = token_file or os.environ.get("TRACEKIT_SIGNER_TOKEN_FILE"), None, None
        self.conns = weakref.WeakSet()   # every thread's, for close()

    def _host(self, req):
        """The host of the run or approval `req` names. A central signer's replica (docs/deploy-kubernetes.md) prefixes
        its ids with its route, `<service>-<n>.`: such an id goes to host `<service>-<n>` in the signer's domain. Plain
        http stays on its loopback address: the ids are the caller's, and a route would name a host off it."""
        first, _, rest = self.host.partition(".")
        route, dot, _ = (req.get("run_id") or req.get("approval_id") or req.get("analyzes")
                         or req.get("parent", {}).get("run_id") or "").partition(".")
        if self.plain or not (dot and re.fullmatch(re.escape(first) + r"-[0-9]+", route)):
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
            conn = self.local.conns[host] = (http.client.HTTPConnection(host, self.port) if self.plain else
                                             http.client.HTTPSConnection(host, self.port, context=self.ctx))
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
        except ssl.SSLCertVerificationError as e:   # not a lost connection: no retry would verify
            conn.close()
            raise SignerUnavailable(f"the TLS certificate of the signer at {self.url} did not verify "
                                    f"({e.verify_message}); set TRACEKIT_SIGNER_CA to the CA that issued it") from None
        except (OSError, http.client.HTTPException, RPCError) as e:
            conn.close()
            raise _ConnectionLost(f"{type(e).__name__}: {e}") from None

    def rpc(self, req, body, timeout):
        if self.plain and not loopback(self.host):   # the token and the frames would cross the network in clear
            raise SignerUnavailable(f"{self.url}: plain http:// signers must be on a loopback address (127.0.0.1, "
                                    "::1); use https:// for any other")
        if self.hello is None:
            hello = self.post(_encode("hello", {}), timeout)
            if "error" in hello:
                e = hello["error"]
                raise RPCError(e.get("code"), e.get("message", ""))
            _check(hello, self.url)
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
    response dict, or raise RPCError; `request_id`, `stream` and `client_seq` are filled in when missing. `token_file`:
    an http(s) signer's bearer token file, in place of $TRACEKIT_SIGNER_TOKEN_FILE; `token`: a tcp:// signer's token,
    in place of $TRACEKIT_SIGNER_TOKEN ("": none, the environment's is not read)."""

    def __init__(self, signer=None, timeout=30.0, token_file=None, token=None):
        self.signer = signer or _default_signer()
        self.timeout, self.hello, self.token = timeout, None, token
        http = (self.signer or "").startswith(("https://", "http://"))
        self._https = _Https(self.signer, token_file) if http else None
        self._lock = threading.Lock()
        self._pid = self._conn = None
        # run_id -> its next client_seq, the least recently used first (a long poll answered run_closed may come
        # before any event)
        self._seqs = collections.OrderedDict()
        self._order = {}   # run_id -> the lock its event calls hold from taking their client_seq to their answer
        self.vault = VaultBody(lambda: self.status({}))   # vault(content): a model_event's body, if the signer keeps it
        _clients.add(self)

    def run(self, agent, parent=None, **fields):
        """Register a run (`agent` is a name or {"name", "version"}, `parent` the RunHandle of the run starting it);
        the handle holds its run token."""
        req = {"agent": {"name": agent} if isinstance(agent, str) else agent, **fields}
        return RunHandle(self, self.register_run(req, parent=parent))

    def register_run(self, req=None, parent=None):
        """`parent`: the RunHandle of the run that starts this one (a sub-agent's run); the signer records the link."""
        return self.call("register_run", {**(req or {}), **(
            {"parent": {"run_id": parent.run_id, "run_token": parent.run_token}} if parent else {})})

    def call(self, method, req=None, **fields):
        """`req` as a dict, or its fields as keywords (as RunHandle.call takes them)."""
        req = {**(req or {}), **fields}
        if "request_id" in rpc_schema.REQUESTS[method]["properties"]:
            req.setdefault("request_id", _new_id())
        timeout = self.timeout + req.get("timeout_ms", 0) / 1000
        deadline = time.monotonic() + timeout   # for the whole call: its turn, every retry
        lost = None
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
                except _ConnectionLost as e:
                    lost = e
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
            last = f" (last: {lost})" if str(lost) else ""
            raise SignerUnavailable(f"lost the connection to the signer {RETRIES} times{last}")

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
            self._pid, self._conn, self.stream, self._seqs = os.getpid(), None, _new_id(), collections.OrderedDict()
        run_id = req.get("run_id")
        fresh = method in _EVENT_METHODS and "client_seq" not in req
        if fresh:
            req.update(stream=self.stream, client_seq=self._seqs.get(run_id, 0))
        if method == "close_run" and run_id in self._seqs:
            # the last client_seq this stream used: one the signer never received becomes its client_counter_gap
            req["last_client_seq"] = [*req.get("last_client_seq", ()),
                                      {"stream": self.stream, "client_seq": self._seqs[run_id] - 1}][-64:]
        _validate(method, req)
        data = _encode(method, req)
        if fresh:
            self._seqs[run_id] = req["client_seq"] + 1
            self._seqs.move_to_end(run_id)
            # lean: a service serving many runs (an executor, an MCP gateway), forged run ids included, keeps
            # KEEP_RUNS of them; a run idle while that many others were used restarts its count and reads as a gap
            if len(self._seqs) > KEEP_RUNS:
                self._order.pop(self._seqs.popitem(last=False)[0], None)
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
            sock, rfile, self.hello = connect(self.signer, token=self.token)
        else:
            from tracekit.sdk import autospawn
            sock, rfile, self.hello = autospawn.ensure()
        return sock, rfile

    def _connect(self):
        conn = _Conn(*self._dial())
        # the threads hold the client weakly: a Client dropped without close() is collected, and its connection with it
        threading.Thread(target=Client._read, args=(weakref.ref(self), conn), daemon=True,
                         name="tracekit-client").start()
        threading.Thread(target=conn.write, daemon=True, name="tracekit-client-write").start()
        weakref.finalize(self, conn.drop)
        return conn

    @staticmethod
    def _read(ref, conn):
        try:
            while True:
                frame = read_frame(conn.rfile)
                if frame is None:
                    break
                conn.pending.popleft().set_result(frame)
        except (OSError, RPCError, IndexError):   # IndexError: an answer nobody asked for
            pass
        client = ref()
        with client._lock if client else contextlib.nullcontext():
            if client and client._conn is conn:
                client._conn = None
            conn.out.put(None)   # the writer stops
            conn.sock.close()
            while conn.pending:
                conn.pending.popleft().set_exception(_ConnectionLost())


def fail_open(fail_modes, tool_class=None):
    """Whether a call of `tool_class` may run while the signer cannot be reached: the class's entry in register_run's
    `fail_modes`, else their `default`, else closed. A signer refusal is never a reason to fail open."""
    modes = fail_modes or {}
    return modes.get(tool_class, modes.get("default", "closed")) == "open"


def sendable(out):
    """Whether a tool's result can go to the signer itself: JSON that fits in a frame."""
    try:
        # lean: half a frame leaves room for JSON escapes and the other fields; send larger results in parts if needed
        return len(canonical(out)) <= MAX_LINE // 2
    except rfc8785.CanonicalizationError:
        return False


class VaultBody:
    """`vault(content, size=None)`: {"body": content} for a model_event when the signer keeps content (`status()`, its
    status answer, names the vault's max_record_bytes), the content's `size` in bytes (default: its canonical JSON)
    fits that and half a frame, and `content` is strict JSON (no integer past 2^53, non-finite number or lone
    surrogate, which a frame cannot carry); else {}: the record keeps the digest and the vault notes the content as
    not retained. The LLM gateway's and the transcript tailer's."""

    def __init__(self, status):
        self.status, self.limit = status, None   # the largest body the signer's vault takes; 0: it keeps none

    def __call__(self, content, size=None):
        if self.limit is None:
            # lean: asked once per process, until the signer answers; restart it after turning the signer's vault on
            # or off
            try:
                self.limit = min((self.status().get("content") or {}).get("max_record_bytes", 0), MAX_LINE // 2)
            except SignerUnavailable:
                return {}
            except RPCError as e:   # not granted `status`: no body
                self.limit = 0
                if e.code == "forbidden":
                    warnings.warn(f"tracekit: the signer refused status ({e.message}): with its content vault on, it "
                                  "keeps none of the text this process records, only its digest; grant this identity "
                                  "status in signer.yaml authorize", stacklevel=2)
        if not self.limit or (size or 0) > self.limit:
            return {}
        try:
            c = canonical(content)
            loads_strict(c)
        except ValueError:   # CanonicalizationError, StrictJSONError
            return {}
        return {"body": content} if size is not None or len(c) <= self.limit else {}


def named_rules(rule_ids):
    """The rule ids a refusal names to the model: TK-UNKNOWN-TOOL only flags a tool the policy doesn't name, it never
    refuses one."""
    return ", ".join(r for r in rule_ids if r != "TK-UNKNOWN-TOOL")


def result_field(send, out):
    """What `complete` carries as a tool's `result`: the result itself when `send` (the decision's `send_result`: an
    untrusted tool, whose result the signer redacts, commits to and indexes for provenance) and it is sendable, else
    its digest (for an untrusted tool, the signer then marks the run's index partial). A result JSON can't carry as
    UTF-8 (a lone surrogate) is taken as its JSON text, escaped; one that isn't JSON (bytes, a datetime, a Decimal, a
    set, an object) as its nearest JSON (tracekit.core.jsonable). Never raises: it runs after the tool did."""
    try:
        json.dumps(out, ensure_ascii=False).encode()
    except UnicodeEncodeError:
        out = json.dumps(out)
    except (TypeError, ValueError):
        out = jsonable(out)
    try:
        return out if send and sendable(out) else event_hash(out)
    except (rfc8785.CanonicalizationError, ValueError):   # NaN, an integer past ±2^53: a digest of its JSON text
        return event_hash(json.dumps(jsonable(out)))


def _validate(method, req):
    errs = rpc_schema.validate(rpc_schema.REQUESTS[method], req)
    if errs:
        raise RPCError("invalid_request", "; ".join(errs))


def _rpc_method(name):
    def method(self, req=None):
        return self.call(name, req)
    method.__name__ = name
    return method


for _name in rpc_schema.REQUESTS.keys() - {"register_run"}:
    setattr(Client, _name, _rpc_method(_name))


def _close_at_exit(run, failed):
    """Close `run` as its `with` block ends. A signer that can't be reached only warns: it closes the run itself after
    its idle timeout. Nothing masks the exception the block raised (`failed`)."""
    try:
        run.close()
    except SignerUnavailable as e:
        warnings.warn(f"tracekit: run {run.run_id} was not closed: the signer can't be reached ({e}); it closes the "
                      "run after its idle timeout", stacklevel=3)
    except Exception as e:
        if not failed:
            raise
        warnings.warn(f"tracekit: run {run.run_id} was not closed: {e}", stacklevel=3)


def _class_of(tool):
    """The class the default policy gives `tool`, for a fail mode while the signer is unreachable (as the adapters and
    hooks do); None (the default fail mode) when it can't be read."""
    try:
        from tracekit.integrations.claude_code import _tool_class
        return _tool_class(tool)
    except Exception:   # an outage path never raises
        return None


class RunHandle:
    """A registered run. As a context manager it is the current run (`current_run`) and is closed on exit (see
    _close_at_exit)."""

    def __init__(self, client, registered):
        self.client, self.registered = client, registered
        self.run_id, self.run_token = registered["run_id"], registered["run_token"]
        self.closed = False
        self._decided = {}   # tool_call_id -> the decision_id and args_digest its `complete` must name
        self._untrusted = set()   # tool_call_ids whose decision asked for the result itself (send_result)

    @property
    def proxy_env(self):
        """With $TRACEKIT_EGRESS_PROXY set (an egress observer, docs/egress.md#attribution): HTTPS_PROXY and HTTP_PROXY,
        both cases, naming it with this run's id and token as credentials, for the commands the run starts
        (`subprocess.run(cmd, env={**os.environ, **run.proxy_env})`) or an HTTP client's proxy, so the observer
        attributes their connections to this run. {} without it. This process's own environment is left as it is."""
        proxy = os.environ.get("TRACEKIT_EGRESS_PROXY")
        if not proxy:
            return {}
        u = urllib.parse.urlsplit(proxy)
        cred = urllib.parse.quote(self.run_id, safe="") + ":" + urllib.parse.quote(self.run_token, safe="")
        url = u._replace(netloc=cred + "@" + u.netloc.rpartition("@")[2]).geturl()
        return dict.fromkeys(("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"), url)

    def call(self, method, **fields):
        """Any per-run RPC (`state_write`, `approval_wait`, `read`, `approval_list`, ...) with this run's id, and its
        token where the method takes one."""
        token = {"run_token": self.run_token} if "run_token" in rpc_schema.REQUESTS[method]["properties"] else {}
        return self.client.call(method, {"run_id": self.run_id, **token, **fields})

    def decide(self, tool_call_id, tool, args, **fields):
        """`args` is the model's raw arguments string, or an already parsed value. Never raises SignerUnavailable:
        while the signer can't be reached the run's fail mode for `tool_class_hint` (else the tool's class in the
        default policy) decides, `{"decision": "allow" or
        "deny", "unavailable": True, ...}` (as the TypeScript client), so a hook that blocks by return value blocks. A
        refusal raises RPCError."""
        try:
            d = self.call("decide", tool_call_id=tool_call_id, tool=tool, args=args,
                          **{"args_source": "raw" if isinstance(args, str) else "parsed", **fields})
        except SignerUnavailable as e:
            ok = fail_open(self.registered.get("fail_modes"), fields.get("tool_class_hint") or _class_of(tool))
            warnings.warn(f"tracekit: {tool} {'runs unrecorded (fail open)' if ok else 'is denied (fail closed)'}: {e}",
                          stacklevel=2)
            return {"decision": "allow" if ok else "deny", "rule_ids": [], "unavailable": True,
                    "reason": f"signer unavailable: {e}"[:1024]}
        try:
            digest = event_hash({"tool": tool, "args": loads_strict(args) if isinstance(args, str) else args})
        except (StrictJSONError, rfc8785.CanonicalizationError):
            return d   # the signer has no args digest to bind either; complete needs explicit fields
        if d["decision"] == "deny":   # never completed: nothing for `complete` to name
            return d
        self._decided[tool_call_id] = {"decision_id": d["decision_id"], "args_digest": digest}
        # lean: a call refused after its decide (not approved, a refused consume) keeps its entry until KEEP_CALLS
        # newer ones push it out; forget it there if adapters must hold none
        while len(self._decided) > KEEP_CALLS:
            old = next(iter(self._decided))
            del self._decided[old]
            self._untrusted.discard(old)
        if d.get("send_result"):
            self._untrusted.add(tool_call_id)
        return d

    def complete(self, tool_call_id, status="ok", **fields):
        """Defaults decision_id and args_digest to those of the last `decide` for this tool call. Never raises: the
        call already ran, so a result the signer can't take is a warning (None), and the signer records the call as
        decided and not completed when the run closes. A tool the policy marks untrusted should send its `result`
        (result_field): without it the run's provenance index goes partial, so a warning says so."""
        if tool_call_id in self._untrusted and "result" not in fields and status == "ok":
            warnings.warn(f"tracekit: {tool_call_id} completed without its result, which the policy reads for "
                          "provenance (an untrusted tool): pass result=result_field(d.get('send_result'), result)",
                          stacklevel=2)
        self._untrusted.discard(tool_call_id)
        try:
            return self.call("complete", tool_call_id=tool_call_id, status=status,
                             **{**self._decided.pop(tool_call_id, {}), **fields})
        except (SignerUnavailable, RPCError) as e:
            warnings.warn(f"tracekit: the result of {tool_call_id} was not recorded: {e}", stacklevel=2)
            return None

    def observe(self, value, source, trust="untrusted", **fields):
        """Record content that entered the run other than as a tool result (a mail, a ticket, a page the app fetched)
        so the signer's provenance index has it; the task or user prompt goes in with trust="trusted". The signer
        records a commitment, never the value."""
        return self.call("observe", value=value, source=source, trust=trust, **fields)

    def transfer(self, sender, receiver, payload, modality, projector=None, measured=None, keep=False):
        """Experimental: record and gate a transfer from `sender` to `receiver` before it happens: text, a tool call,
        or a model's internal state (`modality` kv-cache, embedding, activations) through `projector` (the adapter).
        Each is an id with its version ("qwen2.5-7b@<sha>"). `payload` (bytes or text) is hashed here: the signer gets
        its size and sha256 digest, never the payload. `measured`: more fields the calling code computed itself from
        what it sends (tracekit.integrations.c2c: the fuser's weights hash and layer map). The arguments name those,
        size and digest under `measured`, and the caller's word (the ids, the modality) under `claimed`; all of it
        comes from this process (tier T1), so the signer takes none of it on trust. Decided as tool a2a:transfer, of
        the class the policy maps it to (a2a: a rule on `route`, "sender->receiver via projector", allows listed
        triples); an ask waits up to 5 minutes for a person. Fails closed: with the signer unreachable the transfer may
        not happen, whatever the run's fail modes. Returns the decision with `ok`, whether the transfer may happen now;
        one that may is recorded as made before this returns. `keep`: its result is the payload (hex), which a signer
        keeping content (content.retain) encrypts in its vault for `tracekit why transfer`; the records hold only
        commitments. It proves who sent which bytes to whom, through which adapter, and when, not what the state
        meant; a transfer the code doesn't pass through here is not recorded."""
        data = payload.encode() if isinstance(payload, str) else bytes(payload)
        more = measured or {}
        reserved = {"sender", "receiver", "modality", "projector", "size", "digest", "claimed", "measured"}
        collision = sorted(set(more) & reserved)
        if collision:
            raise ValueError("measured keys replace reserved transfer fields: " + ", ".join(collision))
        args = {"sender": sender, "receiver": receiver, "modality": modality,
                **({"projector": projector} if projector else {})}
        args = {**args, "claimed": sorted(args), "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                **more, "measured": sorted({"size", "digest", *more})}
        tcid = "tx-" + uuid.uuid4().hex
        d = self.decide(tcid, TRANSFER, args)
        if d.get("unavailable") or d["decision"] == "deny":
            return {**d, "ok": False}
        hint = {}
        if d["decision"] == "ask":
            hint = {"approval_id_hint": self.call("approval_request", tool_call_id=tcid)["approval_id"]}
            state = self.call("approval_wait", approval_id=hint["approval_id_hint"], timeout_ms=300000)["state"]
            if state != "approved":
                if state == "requested":   # unanswered: withdrawn, so no one approves a transfer that is gone
                    self.call("approval_abandon", approval_id=hint["approval_id_hint"],
                              reason="no answer within run.transfer's wait")
                return {**d, "ok": False, "reason": f"approval {state}"}
        c = self.approval_consume(tcid, TRANSFER, args, **hint)
        if c["ok"]:
            kept = {"payload": data.hex()} if keep else None
            # lean: up to a quarter frame of payload (its hex in half a frame) is kept; send it in parts, each a
            # record of its own, once larger caches must be kept
            if kept and not sendable(kept):
                warnings.warn(f"tracekit: transfer {tcid} is recorded but not kept: its {len(data)} bytes are more "
                              f"than one frame carries (about {MAX_LINE // 4}); keep a smaller one", stacklevel=2)
                kept = None
            self.complete(tcid, **({"result": kept} if kept else {}))
        return {**d, "ok": c["ok"], **({"reason": c["reason"]} if c.get("reason") else {})}

    def review_finding(self, reviewer, verdict, cites):
        """Sign a finding in this findings run (`client.run(name, analyzes=<run id>)`, as an identity signer.yaml
        `analyzers` lists): `reviewer` the tool and version ("tracekit-analyze/1.4.0"), `verdict` {kind, rule,
        severity, ...} and `cites` [{run_seq, hash}] of records of the analysed run (rpc_schema.REVIEW: no text of the
        run; the signer adds the rule's fixed title). Returns {"run_seq"}."""
        return self.call("review_finding", review={"reviewer": reviewer, "verdict": verdict, "cites": cites})

    def approval_consume(self, tool_call_id, tool, args, approval_id_hint=None, **fields):
        """Call right before running a call that was not denied: {"ok": True} when it may run now. `args` as for
        `decide`; `approval_id_hint` is the approval id the framework saved, if any. Never raises: a signer that
        can't be reached or refuses is {"ok": False, "reason": ...} (once decided there is no fail mode: the call
        doesn't run), so a hook that blocks by return value blocks."""
        hint = {"approval_id_hint": approval_id_hint} if approval_id_hint else {}
        try:
            return self.call("approval_consume", tool_call_id=tool_call_id, tool=tool, args=args,
                             **{"args_source": "raw" if isinstance(args, str) else "parsed", **hint, **fields})
        except (SignerUnavailable, RPCError) as e:
            warnings.warn(f"tracekit: {tool} is blocked: approval_consume failed: {e}", stacklevel=2)
            return {"ok": False, "rule_ids": [], "reason": f"approval_consume failed: {e}"[:1024]}

    def close(self, reason=None):
        if not self.closed:
            self.call("close_run", **({"reason": reason} if reason else {}))
            self.closed = True

    def __enter__(self):
        self._ctx = current_run.set(self)
        return self

    def __exit__(self, *exc):
        current_run.reset(self._ctx)
        _close_at_exit(self, exc[0] is not None)

    @contextlib.contextmanager
    def current(self):
        """This run as the current run inside the block, without closing it: a run per conversation that a server keeps
        open across requests (`with conversation.current(): ...` in each)."""
        token = current_run.set(self)
        try:
            yield self
        finally:
            current_run.reset(token)


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
        await asyncio.to_thread(_close_at_exit, self._sync, exc[0] is not None)

    @contextlib.contextmanager
    def current(self):
        """As RunHandle.current: this run current inside the block, not closed after it."""
        token = current_run.set(self)
        try:
            yield self
        finally:
            current_run.reset(token)
