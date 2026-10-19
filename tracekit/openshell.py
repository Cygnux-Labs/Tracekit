"""NVIDIA OpenShell supervisor middleware: the gRPC service OpenShell's sandbox supervisor calls for each HTTP request
its network policy allows to a host the policy entry selects, before it injects credentials, and for the response
before the sandbox gets it. Each request is decided in the v2 signer for the sandbox's run and each response completes
the call. docs/integrations/openshell.md.

    tracekit openshell-middleware serve --config openshell-middleware.yaml

openshell-middleware.yaml (relative paths are from the file):
    listen: 0.0.0.0:50051                  # reached by the OpenShell gateway and every sandbox supervisor
    tls: {cert: tls/mw.pem, key: tls/mw.key}   # optional: without it plaintext gRPC (OpenShell's
                                           # allow_insecure_transport = true)
    gateway_jwt: {gateway_id: openshell, public_key: jwt/public.pem,   # the gateway's [openshell.gateway.gateway_jwt]
                  audience: "urn:openshell:extension:middleware:tracekit"}   # the registration's audience
    allow_unauthenticated: false           # true: listen beyond loopback without gateway_jwt
    signer: https://signer.internal:8443   # the middleware's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client);
                                           # signer.yaml lists it under `gateways`
    ocsf: {token_file: ocsf.token}         # optional: also take OpenShell's OCSF events (OTLP logs) on this port;
                                           # token_file: the bearer token OpenShell sends (needs tls), else {} on
                                           # loopback or with allow_unauthenticated

Callers: with gateway_jwt each call's OpenShell extension token (authorization: Bearer, typ openshell-ext+jwt, EdDSA
under the gateway's key, iss openshell-gateway:<gateway_id>, the audience, unexpired) is checked; a request or response
needs a supervisor's token, for the sandbox the message names. A refused request is DENY tracekit_unauthenticated;
another call, UNAUTHENTICATED. Without gateway_jwt (OpenShell's allow_insecure_transport) any caller is taken for
OpenShell, so `listen` must be a loopback address unless allow_unauthenticated is set. gateway_jwt needs tls.

Protocol openshell.middleware.v1 (OpenShell's proto/supervisor_middleware.proto), negotiated in Describe as extension
protocol 1.0 with capability openshell.supervisor-middleware.contract. Any other version, unmet capabilities, or a
gateway that sends no metadata (OpenShell before 0.1.0) is refused with FAILED_PRECONDITION, and the gateway doesn't
start. Messages are read and written by hand with otlp_wire's wire primitives, only the fields used here; unknown
fields are skipped. The service declares HTTP_REQUEST/PRE_CREDENTIALS and HTTP_RESPONSE/PRE_RETURN, not WebSocket
messages, and takes no policy-entry `config` (ValidateConfig refuses one).

Runs: a sandbox's first request (RequestContext.sandbox_id) registers its run, `openshell-<sandbox_id>-<8 hex>`, as the
middleware for `openshell:<sandbox_id>` (so it counts in the middleware's open runs for that sandbox), and delegates it
to `openshell:<sandbox_id>` (signer.yaml grants `openshell:*` the per-call methods). Each
call is decided, approved and completed with that `caller`, so the records are source gateway, tier T2, naming the
sandbox. The tokens stay in this process. Once the signer has closed a sandbox's run (idle_s), its next request
registers a new one.

Request: tool `http_request`, args {method, url, headers: [[name, value], ...], body}: `body` is the text of a UTF-8
body. A body that isn't UTF-8, or args over half a frame, is never decided on without it: DENY tracekit_body_unreadable.
allow: ALLOW. deny: DENY tracekit_denied. ask: approval_request and DENY tracekit_approval_required at once
(OpenShell waits at most its registration timeout, 30 s at most); the same request again (same run, tool and args)
reads the approval: requested, DENY tracekit_approval_pending; approved, consumed and ALLOW; else DENY
tracekit_approval_<state>, and the request after that is decided anew. The signer unreachable: DENY
tracekit_signer_unreachable; a signer refusal: tracekit_signer_refused; a request that doesn't decode:
tracekit_malformed_request. OpenShell enforces a DENY whatever the entry's on_error, and gives the sandbox the code,
never the reason; refusals and asks are printed on stderr.

Response (HttpResponsePreReturn.Evaluate): the preflight names its request (sandbox_id, request_id). The body is read
as STREAM_BYTES when OpenShell offers it, each unit passed through unchanged, and the call completed at the last unit
with {status, headers, body}: the body's text when it is UTF-8 and the result fits a frame (sent itself when the
decision says send_result), else the result's digest. A response OpenShell offers no body of (compressed, partial,
bodyless) is skipped and completed at once with the digest; a stream that ends, breaks or is cancelled before its
last unit, as an error. At most MAX_STREAMS responses stream at once (one more: RESOURCE_EXHAUSTED). A
response to a request this process didn't allow (it restarted) is skipped, unrecorded: its call ends as a
held_call_unresolved gap.

OCSF (`ocsf`): OpenShell's gateway and sandbox supervisors export their OCSF events as OTLP log records over gRPC
(openshell-otel/src/ocsf.rs) to `[openshell.gateway.otlp.ocsf] endpoint`, this port: LogsService.Export, decoded by
hand, each record's body one OCSF JSON event, its sandbox the attribute openshell.sandbox.id (the record's, else the
resource's: a supervisor's). The import is an observer (observe_effect, sensor openshell) under the middleware's own
identity, its one caller (`callers`, from the signer's status), so it covers only the runs it registered; each effect
is attributed to the sandbox's run by its run token (registered here on the sandbox's first event or request,
whichever comes first). Network and HTTP activity OpenShell allowed or denied: a connect effect (`denied` when
OpenShell blocked it); OpenShell's records of middleware decisions (firewall_rule type middleware) are skipped: the
middleware recorded those as calls. Process activity: exec (launch) and exit (terminate). Device config state change:
a policy effect, the signer's `ext` record openshell.policy (OpenShell's name for the change, its policy_hash, the
actor, the message's digest). Losses are signed gaps: OpenShell's gap records (openshell.ocsf.gap, records it dropped)
in the sandbox's run, or in every covered run when they name no sandbox (the gateway's); and a sandbox the middleware
decided a request of whose stream then sends nothing for STALE_S (OpenShell records each middleware decision as an OCSF
event), once until it sends again. Events delivered twice (OpenShell retries a batch) are dropped by ocsf.metadata.uid.
Anything else is counted by kind and printed on stderr. A batch the signer can't take is refused UNAVAILABLE, so
OpenShell sends it again. Every OCSF_CHECK_S the import checks the streams, and every HEARTBEAT_S calls observe_effect
empty: the signer's silence check of the observer.
"""
import argparse
import base64
import collections
import concurrent.futures
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import sys
import threading
import time
import uuid

from tracekit import __version__, yamlmini
from tracekit.executor import Custody
from tracekit.format.canon import event_hash
from tracekit.identity.k8s_sa import verify_jwt
from tracekit.otlp_wire import MAX_ATTRS, WireError, _fields, _kvs_pb, _repeated, _varint, varint
from tracekit.sdk.client import Client, SignerUnavailable, named_rules, result_field, sendable
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import REQUESTS, RPCError, validate
from tracekit.signer.service import HEARTBEAT_S
from tracekit.transport import loopback

KEYS = {"listen", "tls", "signer", "gateway_jwt", "allow_unauthenticated", "ocsf"}
JWT_KEYS = {"gateway_id", "public_key", "audience"}
JWT_TYP = "openshell-ext+jwt"   # the typ of OpenShell's extension tokens (openshell-extension-core/src/jwt.rs)
SERVICE, RESPONSES = "openshell.middleware.v1.SupervisorMiddleware", "openshell.middleware.v1.HttpResponsePreReturn"
PROTOCOL = (1, 0)
CONTRACT = "openshell.supervisor-middleware.contract"
TOOL = "http_request"
HTTP_REQUEST, HTTP_RESPONSE, PRE_CREDENTIALS, PRE_RETURN = 1, 3, 1, 2   # SupervisorMiddlewareOperation, ...Phase
ALLOW, DENY = 1, 2   # Decision
STREAM_BYTES = 3   # HttpResponseBodyMode
MAX_PAYLOAD = 4 * 1024 * 1024   # OpenShell's largest request body or response unit
MAX_MESSAGE = 5 * 1024 * 1024   # a payload and its envelope (OpenShell asks for at least 4.5 MiB)
MAX_TEXT = MAX_LINE // 2   # bytes of a response body kept to send as text (sdk.client.sendable)
MAX_RUNS = MAX_HELD = MAX_INFLIGHT = 10_000   # each least recently used dropped first
# lean: a thread per response stream, so at most MAX_STREAMS at once (one more is refused) and UNARY_WORKERS threads
# kept for evaluations; serve the streams with grpc.aio once more sandboxes stream responses at once
MAX_STREAMS, UNARY_WORKERS = 64, 32
SIGNER_TIMEOUT_S = 5
LOGS = "opentelemetry.proto.collector.logs.v1.LogsService"
GAP_EVENT = "openshell.ocsf.gap"   # OpenShell's record of OCSF records it dropped (openshell-otel/src/ocsf.rs)
STALE_S = 60   # after a request the middleware decided, how long its sandbox's OCSF stream may send nothing
OCSF_CHECK_S = 5
OCSF_EXPORTS = 8   # Export calls at once (each waits on the signer); one more is refused and OpenShell retries it
MAX_SEEN = 100_000   # OCSF event uids kept to drop the events of a batch OpenShell sends again
MAX_RECORDS = 10_000   # log records per Export (OpenShell sends at most 100 and a gap record)
ITEM = REQUESTS["observe_effect"]["properties"]["effects"]["items"]
SANDBOX = re.compile(r"[A-Za-z0-9._-]{1,100}")
DEFAULT_PORT = {"http": 80, "ws": 80, "https": 443, "wss": 443}

# the fields read, by number (OpenShell's proto/supervisor_middleware.proto and extension.proto): {n: (name, kind)},
# kind "int", "str", "bytes", a nested message's spec, or [kind] for a repeated field
_PEER = {1: ("version", {1: ("major", "int"), 2: ("minor", "int")}), 4: ("supported", ["str"]),
         5: ("required", ["str"])}
_CONTEXT = {1: ("request_id", "str"), 2: ("sandbox_id", "str"), 4: ("sandbox", "str")}
_HEADER = {1: ("name", "str"), 2: ("value", "str")}
_TARGET = {1: ("scheme", "str"), 2: ("host", "str"), 3: ("port", "int"), 4: ("method", "str"), 5: ("path", "str"),
           6: ("query", "str")}
_DESCRIBE = {1: ("gateway", _PEER)}
_VALIDATE = {1: ("config", {1: ("fields", ["bytes"])})}   # google.protobuf.Struct: its map entries
_REQUEST = {1: ("phase", "int"), 2: ("context", _CONTEXT), 4: ("target", _TARGET), 5: ("headers", [_HEADER]),
            6: ("body", "bytes")}
_EVENT = {1: ("preflight", {1: ("context", _CONTEXT), 3: ("status", "int"), 4: ("headers", [_HEADER]),
                            8: ("modes", ["int"])}),
          2: ("body", {1: ("sequence", "int"), 2: ("data", "bytes"), 3: ("end", "int")}),
          4: ("trailers", {}), 3: ("session_end", {1: ("reason", "int")})}


def decode(buf, spec):
    """{name: value} of `spec`'s fields in protobuf message `buf`; others are skipped. WireError when it doesn't
    decode."""
    out = {}
    for fn, wt, v in _fields(memoryview(buf)):
        if fn not in spec:
            continue
        name, kind = spec[fn]
        many = isinstance(kind, list)
        kind = kind[0] if many else kind
        if kind == "int" and many and wt == 2:   # packed
            i = 0
            while i < len(v):
                x, i = _varint(v, i)
                out.setdefault(name, []).append(x)
            continue
        if wt != (0 if kind == "int" else 2):
            raise WireError(f"{name}: wire type {wt}")
        if kind == "str":
            try:
                v = bytes(v).decode("utf-8")
            except UnicodeDecodeError:
                raise WireError(f"{name}: not UTF-8") from None
        elif kind == "bytes":
            v = bytes(v)
        elif kind != "int":
            v = decode(v, kind)
        if many:
            out.setdefault(name, []).append(v)
        else:
            out[name] = v
    return out


def _len(fn, b):
    b = b.encode() if isinstance(b, str) else b
    return varint(fn << 3 | 2) + varint(len(b)) + b


def _int(fn, n):
    return varint(fn << 3) + varint(n) if n else b""


def _str(fn, s):
    return _len(fn, s) if s else b""


# MiddlewareManifest: name, a binding per operation (operation, phase, max_payload_bytes), PeerMetadata (protocol
# version, implementation name and version, the contract supported and required)
BINDINGS = ((HTTP_REQUEST, PRE_CREDENTIALS), (HTTP_RESPONSE, PRE_RETURN))
MANIFEST = (_len(1, "tracekit") + b"".join(_len(3, _int(1, op) + _int(2, phase) + _int(3, MAX_PAYLOAD))
                                           for op, phase in BINDINGS)
            + _len(5, _len(1, _int(1, PROTOCOL[0]) + _int(2, PROTOCOL[1])) + _len(2, "tracekit/openshell-middleware")
                   + _len(3, __version__) + _len(4, CONTRACT) + _len(5, CONTRACT)))
SKIP = _len(1, _len(1, b""))   # HttpResponseEventResult: preflight_result {skip {}}
INSPECT = _len(1, _len(2, _int(1, STREAM_BYTES)))   # preflight_result {inspect {body_mode STREAM_BYTES}}
TRAILERS = _len(3, b"")   # trailers_result {}


def log_records(body):
    """(resource attributes, record attributes, body text or None, time in ns, event name) of each log record of
    ExportLogsServiceRequest `body` (opentelemetry/proto/collector/logs/v1/logs_service.proto, logs/v1/logs.proto).
    WireError when it doesn't decode."""
    out = []
    try:
        for rl in _repeated(memoryview(body), 1, MAX_RECORDS, "resource logs"):
            resource = {}
            for f, w, v in _fields(rl):
                if f == 1 and w == 2:
                    resource = _kvs_pb(_repeated(v, 1, MAX_ATTRS, "resource attributes"))
            for sl in _repeated(rl, 2, MAX_RECORDS, "scope logs"):
                for lr in _repeated(sl, 2, MAX_RECORDS - len(out), "log records"):
                    attrs, text, ns, event = [], None, 0, ""
                    for f, w, v in _fields(lr):
                        if f == 1 and w == 1:
                            ns = v
                        elif f == 5 and w == 2:   # AnyValue: its string_value
                            text = next((bytes(x).decode("utf-8", "replace") for f2, w2, x in _fields(v)
                                         if f2 == 1 and w2 == 2), None)
                        elif f == 6 and w == 2:
                            attrs.append(v)
                        elif f == 12 and w == 2:
                            event = bytes(v).decode("utf-8", "replace")
                    out.append((resource, _kvs_pb(attrs[:MAX_ATTRS]), text, ns, event))
    except WireError:
        raise
    except Exception as e:   # a shape the decoder didn't expect (a RecursionError among them)
        raise WireError(f"malformed logs request: {type(e).__name__}") from None
    return out


def _ts(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _process(p):
    p = p if isinstance(p, dict) else {}
    pid = p.get("pid")
    return {"pid": pid if isinstance(pid, int) and 0 <= pid < 1 << 32 else 0,
            "binary": str(p.get("name") or "unknown")[:4096]}


def ocsf_effect(ev, ts):
    """The observe_effect effect of OCSF event `ev` (OpenShell's JSON record: openshell-ocsf/src/events), or why it
    isn't imported (a str)."""
    cls, act, name = ev.get("class_uid"), ev.get("action_id"), ev.get("class_name") or f"class {ev.get('class_uid')}"
    denied = {"denied": True} if act == 2 else {}
    if cls in (4001, 4002):   # Network Activity, HTTP Activity
        if (ev.get("firewall_rule") or {}).get("type") == "middleware":
            return "the middleware's own decisions (recorded as its calls)"
        if act not in (1, 2):
            return f"{name} events that neither allow nor deny"
        dst, url = ev.get("dst_endpoint") or {}, (ev.get("http_request") or {}).get("url") or {}
        host = dst.get("domain") or dst.get("ip") or url.get("hostname")
        if not host:
            return f"{name} events with no destination"
        return {"kind": "connect", "ts": ts, **_process((ev.get("actor") or {}).get("process")),
                "host": str(host).lower().rstrip("."), "port": dst.get("port") or url.get("port") or 0, **denied}
    if cls == 1007 and ev.get("status_id") != 2 and ev.get("activity_id") in (1, 2):   # Process Activity: Launch,
        if ev["activity_id"] == 1:                                                    # Terminate
            return {"kind": "exec", "ts": ts, **_process(ev.get("process")), **denied}
        code = ev.get("exit_code")
        return {"kind": "exit", "ts": ts, **_process(ev.get("process")),
                **({"status": code} if isinstance(code, int) and 0 <= code < 1 << 32 else {})}
    if cls == 5019:   # Device Config State Change: the sandbox's policy or configuration
        u = ev.get("unmapped") if isinstance(ev.get("unmapped"), dict) else {}
        return {"kind": "policy", "ts": ts,
                "change": re.sub(r"[^a-z0-9_.-]", "_", str(ev.get("state") or "unknown").lower())[:64],
                **({"policy_hash": str(u["policy_hash"])[:128]} if u.get("policy_hash") else {}),
                **({"by": str(u["actor"])[:256]} if u.get("actor") else {}),
                **({"detail_digest": "sha256:" + hashlib.sha256(str(ev["message"]).encode("utf-8")).hexdigest()}
                   if ev.get("message") else {})}
    return f"{name} events other than a launch or an exit" if cls == 1007 else f"{name} events"


def _chunks(items):
    """`items` as observe_effect calls: at most 256 effects and about MAX_TEXT bytes each."""
    chunk, size = [], 0
    for x in items:
        n = len(json.dumps(x))
        if chunk and (len(chunk) == 256 or size + n > MAX_TEXT):
            yield chunk
            chunk, size = [], 0
        chunk.append(x)
        size += n
    if chunk:
        yield chunk


def negotiate(gateway):
    """Why the gateway's PeerMetadata `gateway` (decoded; None: absent) is refused, or None."""
    want = f"{PROTOCOL[0]}.{PROTOCOL[1]}"
    if gateway is None:
        return f"the gateway sent no protocol metadata (OpenShell before 0.1.0); Tracekit speaks protocol {want} only"
    v = gateway.get("version")
    got = None if v is None else f"{v.get('major', 0)}.{v.get('minor', 0)}"
    if got != want:
        return (f"the gateway speaks supervisor-middleware protocol {got or 'none'}; Tracekit speaks {want} only: "
                "use a Tracekit release that supports the gateway's version")
    if CONTRACT not in gateway.get("supported", []):
        return f"the gateway doesn't support {CONTRACT}"
    extra = sorted(set(gateway.get("required", [])) - {CONTRACT})
    if extra:
        return f"the gateway requires capabilities Tracekit's middleware doesn't have: {', '.join(extra)[:512]}"
    return None


def result(decision, why="", code=""):
    """HttpRequestResult: `why` is the diagnostic (OpenShell shows it to no one), `code` the reason_code."""
    return _int(1, decision) + _str(2, why.encode()[:4096].decode("utf-8", "ignore")) + _str(8, code)


def _url(t):
    host = f"[{t['host']}]" if ":" in t["host"] else t["host"]
    port = "" if t.get("port", 0) in (0, DEFAULT_PORT.get(t["scheme"])) else f":{t['port']}"
    return f"{t['scheme']}://{host}{port}{t.get('path') or '/'}" + (f"?{t['query']}" if t.get("query") else "")


class Unreadable(Exception):
    """A request whose body the policy can't read: denied, never decided on without it."""


def args_of(req):
    """The decided arguments of HttpRequestEvaluation `req` (decoded). Unreadable when its body isn't UTF-8 text or the
    arguments don't fit a signer frame."""
    t = req.get("target", {})
    if not all(t.get(k) for k in ("scheme", "host", "method")):
        raise WireError("the target has no scheme, host or method")
    args = {"method": t["method"], "url": _url(t),
            "headers": [[h.get("name", ""), h.get("value", "")] for h in req.get("headers", [])]}
    raw = req.get("body", b"")
    if raw:
        try:
            args["body"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Unreadable(f"its body ({len(raw)} bytes) isn't UTF-8 text (compressed or binary)") from None
    if not sendable(args):
        raise Unreadable(f"its body ({len(raw)} bytes) and headers are over the {MAX_TEXT // 1024} KiB the signer "
                         "takes")
    return args


class Middleware:
    """The sandboxes' runs and the calls they wait on, and the signer steps for each request and response."""

    def __init__(self, client, ocsf=False):
        self.client, self.custody = client, Custody(client)
        self.lock, self.registering = threading.Lock(), threading.Lock()
        self.runs = collections.OrderedDict()       # sandbox_id -> (run_id, token, caller)
        self.held = collections.OrderedDict()       # (run_id, args digest) -> (tool_call_id, decision, approval_id)
        self.inflight = collections.OrderedDict()   # (sandbox_id, request_id) -> (key, tool_call_id, decision, args)
        # the OCSF import: on or off, this process's instance, its last call, the event uids recorded, each sandbox's
        # first request still waiting for its stream (monotonic time), the sandboxes whose stream stopped, and what
        # wasn't imported (and how much of it was printed)
        self.ocsf, self.instance, self.beat = ocsf, "os-" + uuid.uuid4().hex, float("-inf")
        self.me = None   # this middleware's identity as the signer knows it: the import's one caller
        self.seen, self.watch, self.stalled = collections.OrderedDict(), {}, set()
        self.unmapped, self.reported = collections.Counter(), {}

    def _put(self, table, k, v, cap):
        with self.lock:
            table[k] = v
            table.move_to_end(k)
            while len(table) > cap:
                table.popitem(last=False)

    def _run(self, ctx):
        """(run_id, token, caller) of the sandbox `ctx` names, registered on its first request."""
        sid = ctx["sandbox_id"]
        with self.lock:
            key = self.runs.get(sid)
        if key is None:
            with self.registering:   # one run per sandbox, when its first requests arrive together too
                with self.lock:
                    key = self.runs.get(sid)
                if key is None:
                    caller, name = "openshell:" + sid, ctx.get("sandbox") or sid
                    r = self.client.register_run({"run_id": f"openshell-{sid}-{secrets.token_hex(4)}", "caller": caller,
                                                  "agent": {"name": f"openshell sandbox {name}"[:128]}})
                    key = (r["run_id"], self.client.delegate_run({"run_id": r["run_id"], "run_token": r["run_token"],
                                                                  "identity": caller})["run_token"], caller)
                    print(f"tracekit openshell-middleware: sandbox {name} ({sid}): run {r['run_id']}", file=sys.stderr,
                          flush=True)
        self._put(self.runs, sid, key, MAX_RUNS)
        return key

    def evaluate(self, body, sandbox=None):
        """HttpRequestResult for HttpRequestEvaluation `body`; `sandbox`: the sandbox the caller's OpenShell token
        names (gateway_jwt), else None."""
        try:
            req = decode(body, _REQUEST)
            ctx = req.get("context", {})
            if req.get("phase") != PRE_CREDENTIALS or not SANDBOX.fullmatch(ctx.get("sandbox_id", "")) \
                    or not ctx.get("request_id"):
                raise WireError("needs phase PRE_CREDENTIALS, a sandbox_id ([A-Za-z0-9._-]{1,100}) and a request_id")
            args = args_of(req)
        except WireError as e:
            return self._deny("tracekit_malformed_request", f"the request doesn't decode: {e}")
        except Unreadable as e:
            return self._deny("tracekit_body_unreadable", f"sandbox {ctx['sandbox_id']}: Tracekit's policy can't read "
                              f"the request, {e}: denied, never decided without its body")
        if sandbox is not None and sandbox != ctx["sandbox_id"]:
            return self._deny("tracekit_unauthenticated", f"a token for sandbox {sandbox[:100]} sent another "
                                                          "sandbox's request")
        if self.ocsf:   # OpenShell records the middleware's decision as an OCSF event of the sandbox
            with self.lock:
                if ctx["sandbox_id"] not in self.stalled:
                    self.watch.setdefault(ctx["sandbox_id"], time.monotonic())
        try:
            for attempt in (1, 2):
                key = self._run(ctx)
                try:
                    code, why, call = self._gate(key, args, ctx)
                    break
                except RPCError as e:
                    if attempt == 2 or e.code not in ("run_closed", "unknown_run"):
                        raise
                    with self.lock:   # the signer closed the sandbox's run (idle_s): a new run takes the request
                        if self.runs.get(ctx["sandbox_id"]) == key:
                            del self.runs[ctx["sandbox_id"]]
        except SignerUnavailable as e:
            return self._deny("tracekit_signer_unreachable", f"the signer is unreachable ({e}); denied")
        except RPCError as e:
            return self._deny("tracekit_signer_refused", f"the signer refused the call: {e}")
        if code:
            return result(DENY, why, code)
        self._put(self.inflight, (ctx["sandbox_id"], ctx["request_id"]), (key, *call, args), MAX_INFLIGHT)
        return result(ALLOW)

    @staticmethod
    def _deny(code, why):
        print(f"tracekit openshell-middleware: {code}: {why}", file=sys.stderr, flush=True)
        return result(DENY, why, code)

    def _gate(self, key, args, ctx):
        """(None, None, (tool_call_id, decision)) when the request may go, else (reason_code, why, None). Raises
        SignerUnavailable or RPCError."""
        run_id, token, caller = key
        base = {"run_id": run_id, "run_token": token, "caller": caller}
        h = (run_id, event_hash({"tool": TOOL, "args": args}))
        with self.lock:
            held = self.held.get(h)
        hint = {}
        if held is None:
            tcid = "os-" + uuid.uuid4().hex
            d = self.client.decide({**base, "tool_call_id": tcid, "tool": TOOL, "args_source": "parsed", "args": args})
            if d["decision"] == "deny":
                return "tracekit_denied", "denied by policy: " + (named_rules(d["rule_ids"]) or "deny"), None
            if d["decision"] == "ask":
                aid = self.client.approval_request({**base, "tool_call_id": tcid})["approval_id"]
                self._put(self.held, h, (tcid, d, aid), MAX_HELD)
                rules = ", ".join(d["rule_ids"])
                print(f"tracekit openshell-middleware: sandbox {ctx.get('sandbox') or ctx['sandbox_id']}: "
                      f"{args['method']} {args['url'].split('?', 1)[0][:200]} waits for approval {aid} ({rules}): "
                      f"tracekit approvals approve {aid}", file=sys.stderr, flush=True)
                return "tracekit_approval_required", f"approval {aid} requested ({rules}); the same request runs " \
                                                     "once a person approves it", None
        else:
            tcid, d, aid = held
            state = self.client.approval_wait({**base, "approval_id": aid, "timeout_ms": 0})["state"]
            if state == "requested":
                return "tracekit_approval_pending", f"approval {aid} is still requested", None
            with self.lock:
                self.held.pop(h, None)
            if state != "approved":
                return "tracekit_approval_" + state, f"approval {aid} {state}", None
            hint = {"approval_id_hint": aid}
        c = self.client.approval_consume({**base, "tool_call_id": tcid, "tool": TOOL, "args_source": "parsed",
                                          "args": args, **hint})
        if not c["ok"]:
            return "tracekit_denied", named_rules(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else ""), None
        return None, None, (tcid, d)

    def respond(self, events, abort, sandbox=None):
        """The HttpResponseEventResult of each HttpResponseEvent in `events`; `abort(why)` raises, ending the
        stream. `sandbox`: the sandbox the caller's OpenShell token names (gateway_jwt), else None. A stream that ends,
        breaks or is cancelled before its call's last body unit completes the call as an error."""
        call, seq, sha, text, size = None, 0, hashlib.sha256(), bytearray(), 0
        try:
            for raw in events:
                try:
                    ev = decode(raw, _EVENT)
                    if len(ev) != 1:
                        raise WireError("an event is one of preflight, body, trailers and session_end")
                except WireError as e:
                    abort(f"the response event doesn't decode: {e}")
                (kind, x), = ev.items()
                if kind == "preflight":
                    ctx = x.get("context", {})
                    if sandbox is not None and ctx.get("sandbox_id") != sandbox:
                        abort(f"a token for sandbox {sandbox[:100]} sent another sandbox's response")
                    with self.lock:
                        found = self.inflight.pop((ctx.get("sandbox_id"), ctx.get("request_id")), None)
                    if found is None:
                        print(f"tracekit openshell-middleware: a response to request {ctx.get('request_id', '?')[:64]}"
                              ", which this process didn't allow (it restarted?): not recorded", file=sys.stderr,
                              flush=True)
                        yield SKIP
                        continue
                    head = {"status": x.get("status", 0),
                            "headers": [[h.get("name", ""), h.get("value", "")] for h in x.get("headers", [])]}
                    if STREAM_BYTES in x.get("modes", []):
                        call = (found, head)
                        yield INSPECT
                    else:
                        self._complete(found, head, None)
                        yield SKIP
                elif kind == "body":
                    if call is None or x.get("sequence") != seq + 1:
                        abort("a body unit out of order")
                    seq, data = seq + 1, x.get("data", b"")
                    sha.update(data)
                    size += len(data)
                    if text is not None and len(text) + len(data) <= MAX_TEXT:
                        text += data
                    else:
                        text = None
                    if x.get("end"):
                        done, call = call, None
                        self._complete(*done, (text, {"digest": "sha256:" + sha.hexdigest(), "size": size}))
                    yield _len(2, _int(1, seq) + _len(2, b""))   # body_result {sequence, pass_through {}}
                elif kind == "trailers":
                    yield TRAILERS
        finally:
            if call is not None:
                key, tcid, d, args = call[0]
                self.custody.complete(key, tcid, d, TOOL, args, "error", error="OpenShell ended the response stream "
                                      "before its last body unit: the sandbox may not have received the whole response")

    def _complete(self, found, head, body):
        """Complete the call `found` with response `head`, and `body` ((its text or None, its digest); None: not
        read)."""
        key, tcid, d, args = found
        out, send = dict(head), False
        if body is not None:
            text, out["body"] = body
            if text is not None:
                try:
                    out["body"], send = bytes(text).decode("utf-8"), d.get("send_result", False)
                except UnicodeDecodeError:
                    pass
        self.custody.complete(key, tcid, d, TOOL, args, "ok" if head["status"] < 400 else "error",
                              result=result_field(send, out))

    def export(self, body):
        """Import OpenShell's ExportLogsServiceRequest `body` into the sandboxes' runs. Raises WireError,
        SignerUnavailable or RPCError; no event of a sandbox whose call failed counts as recorded, so the batch sent
        again records it."""
        sandboxes, lost = {}, []   # sandbox_id -> [its name, effects, their uids]; the losses no sandbox names
        for resource, attrs, text, ns, event in log_records(body):
            sid = attrs.get("openshell.sandbox.id") or resource.get("openshell.sandbox.id")
            sid = sid if isinstance(sid, str) and SANDBOX.fullmatch(sid) else None
            if sid:
                with self.lock:   # its stream is alive
                    self.watch.pop(sid, None)
                    self.stalled.discard(sid)
            if event == GAP_EVENT or "openshell.ocsf.gap.dropped" in attrs:
                since = attrs.get("openshell.ocsf.gap.since_unix_ms")
                why = (f"OpenShell dropped {attrs.get('openshell.ocsf.gap.dropped', 'some')} OCSF record(s) before "
                       "export" + (f" from {_ts(since)}" if isinstance(since, int) and 0 < since < 1 << 46 else "")
                       + (" (its sandbox supervisor's gap record)" if sid else " (its gateway's gap record: they may "
                                                                              "be of any sandbox)"))[:1024]
                if sid:
                    sandboxes.setdefault(sid, [sid, [], []])[1].append({"kind": "lost", "reason": why})
                else:
                    lost.append(why)
                continue
            try:
                ev = json.loads(text)
                uid = attrs.get("ocsf.metadata.uid") or ev["metadata"].get("uid")
                uid = uid if isinstance(uid, str) else None
                ms = ev.get("time") if isinstance(ev.get("time"), int) and 0 < ev["time"] < 1 << 46 else ns // 10 ** 6
                x = ocsf_effect(ev, _ts(ms or time.time() * 1000)) if isinstance(ev["class_uid"], int) else None
                name = str((ev.get("container") or {}).get("name") or sid)[:100]   # gone when downgraded to 1.1, 1.3
            except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
                x = None
            if x is None:
                self._unmapped("log records that aren't OCSF events OpenShell writes")
                continue
            with self.lock:
                if uid is not None and uid in self.seen:
                    continue
            if not sid:
                self._unmapped("events of no sandbox (the gateway's own)")
                continue
            if isinstance(x, str):
                self._unmapped(x)
                continue
            if validate(ITEM, x):   # one the signer would refuse would refuse its whole call
                x = {"kind": "lost", "reason": f"OpenShell reported a {x['kind']} event Tracekit could not record: a "
                                               "field past the signer's bounds"}
            box = sandboxes.setdefault(sid, [sid, [], []])
            box[0] = name
            box[1].append(x)
            box[2].append(uid)
        for sid, (name, effects, uids) in sandboxes.items():
            # lean: a run the signer closed (idle_s) stays this sandbox's until its next request opens another, so its
            # events meanwhile are effect_outside_run gaps; ask the signer whether the run is open if that matters
            run_id, token, _ = self._run({"sandbox_id": sid, "sandbox": name})
            for chunk in _chunks([{**x, "run_id": run_id, "run_token": token} for x in effects]):
                self._observe(chunk)
            with self.lock:
                self.seen.update((uid, True) for uid in uids if uid is not None)
                while len(self.seen) > MAX_SEEN:
                    self.seen.popitem(last=False)
        if lost:
            self._observe([], "; ".join(lost)[:1024])

    def _unmapped(self, why):
        with self.lock:
            self.unmapped[why] += 1

    def _observe(self, effects, lost=None):
        if self.me is None:   # the import covers only the runs this identity registered (the sandboxes')
            i = self.client.call("status")["identity"]
            self.me = f"{i['scheme']}:{i['subject']}"
        self.client.observe_effect({"request_id": "os-" + uuid.uuid4().hex, "instance": self.instance,
                                    "sensor": "openshell", "callers": [self.me], "effects": effects,
                                    **({"lost": lost} if lost else {})})
        self.beat = time.monotonic()

    def tick(self, now=None):
        """The OCSF import's checks: a sandbox the middleware decided a request of whose stream then sent nothing for
        STALE_S gets a signed loss in its run (once, until its stream sends again); a heartbeat when one is due; what
        wasn't imported, on stderr when it grew. Raises SignerUnavailable or RPCError: the next tick tries again."""
        now = time.monotonic() if now is None else now
        with self.lock:
            late = [(sid, self.runs.get(sid)) for sid, t in self.watch.items() if now - t >= STALE_S]
        for sid, key in late:
            if key:
                self._observe([{"kind": "lost", "run_id": key[0], "run_token": key[1], "reason": (
                    f"no OCSF event from OpenShell for sandbox {sid} in {STALE_S}s after the middleware decided a "
                    "request of it: its OCSF export stopped or doesn't reach the middleware, so OpenShell's blocks, "
                    "process events and policy changes of it from then on may be missing")}])
            with self.lock:
                self.watch.pop(sid, None)
                self.stalled.add(sid)
        if time.monotonic() - self.beat >= HEARTBEAT_S:
            self._observe([])
        with self.lock:
            grown = {k: n for k, n in self.unmapped.items() if self.reported.get(k) != n}
            self.reported.update(grown)
            shown = "; ".join(f"{n} x {k}" for k, n in sorted(self.unmapped.items()))
        if grown:
            print(f"tracekit openshell-middleware: OpenShell OCSF events not imported so far: {shown}", file=sys.stderr,
                  flush=True)


def validate_config(body):
    """ValidateConfigResponse: valid for an empty config only."""
    try:
        if not decode(body, _VALIDATE).get("config", {}).get("fields"):
            return _int(1, 1)
    except WireError:
        pass
    return _len(2, "Tracekit's middleware takes no config: leave config out of its network_middlewares entry")


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"listen", "signer"} <= set(cfg):
        raise ValueError(f"{path}: needs listen and signer; takes {sorted(KEYS)}")
    if not isinstance(cfg["listen"], str) or ":" not in cfg["listen"]:
        raise ValueError(f"{path}: listen is host:port")
    base, tls, jwt = os.path.dirname(os.path.abspath(path)), cfg.get("tls"), cfg.get("gateway_jwt")
    if tls is not None:
        if not (isinstance(tls, dict) and set(tls) == {"cert", "key"} and all(isinstance(v, str) for v in
                                                                             tls.values())):
            raise ValueError(f"{path}: tls is {{cert: <file>, key: <file>}}")
        cfg["tls"] = {k: os.path.join(base, v) for k, v in tls.items()}
    if cfg.get("allow_unauthenticated", False) not in (True, False):
        raise ValueError(f"{path}: allow_unauthenticated is true or false")
    if jwt is not None:
        if not (isinstance(jwt, dict) and set(jwt) == JWT_KEYS and all(isinstance(v, str) and v for v in jwt.values())):
            raise ValueError(f"{path}: gateway_jwt is {{gateway_id: <the gateway's gateway_jwt.gateway_id>, "
                             "public_key: <its public_key_path's file>, audience: <the registration's audience>}")
        if tls is None:
            raise ValueError(f"{path}: gateway_jwt needs tls: OpenShell sends its tokens to https:// endpoints only")
        cfg["gateway_jwt"] = dict(jwt, public_key=os.path.join(base, jwt["public_key"]))
    elif not (loopback(cfg["listen"].rpartition(":")[0].strip("[]")) or cfg.get("allow_unauthenticated")):
        raise ValueError(f"{path}: listen {cfg['listen']} needs gateway_jwt, so the middleware takes calls from the "
                         "OpenShell gateway and its sandboxes only (or allow_unauthenticated: true, on a network that "
                         "authenticates callers already)")
    if "ocsf" in cfg:
        ocsf = cfg["ocsf"]
        if not (isinstance(ocsf, dict) and set(ocsf) <= {"token_file"} and all(isinstance(v, str) and v
                                                                               for v in ocsf.values())):
            raise ValueError(f"{path}: ocsf is {{token_file: <the bearer token OpenShell's OCSF export sends>}} or "
                             "{}")
        if "token_file" in ocsf:
            if tls is None:
                raise ValueError(f"{path}: ocsf's token_file needs tls: without it the token crosses the network in "
                                 "the clear")
            cfg["ocsf"] = {"token_file": os.path.join(base, ocsf["token_file"])}
        elif not (loopback(cfg["listen"].rpartition(":")[0].strip("[]")) or cfg.get("allow_unauthenticated")):
            raise ValueError(f"{path}: ocsf needs token_file (the bearer token OpenShell sends with its OCSF events) "
                             f"when listen {cfg['listen']} is beyond loopback, or allow_unauthenticated: true")
    return cfg


def serve(cfg, client=None):
    """(the started grpc server, its port, its Middleware) for a loaded config; stop it with stop(None)."""
    try:
        import grpc
    except ImportError:
        raise ValueError("the OpenShell middleware needs grpcio: pip install 'tracekit-ai[grpc]'") from None
    ocsf, bearer, exports = cfg.get("ocsf"), None, threading.BoundedSemaphore(OCSF_EXPORTS)
    if ocsf and "token_file" in ocsf:
        with open(ocsf["token_file"], encoding="utf-8") as f:
            bearer = f.read().strip()
        if not bearer:
            raise ValueError(f"{ocsf['token_file']}: empty (ocsf.token_file: the bearer token OpenShell's OCSF export "
                             "sends)")
    mw = Middleware(client or Client(cfg["signer"], timeout=SIGNER_TIMEOUT_S), ocsf is not None)
    jwt, streams = cfg.get("gateway_jwt"), threading.BoundedSemaphore(MAX_STREAMS)
    if jwt:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        with open(jwt["public_key"], "rb") as f:
            key = load_pem_public_key(f.read())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"{jwt['public_key']}: not an Ed25519 public key (the gateway's gateway_jwt "
                             "public_key_path)")

    def token(context, supervisor=True):
        """(the sandbox the call's OpenShell token names, or None: a gateway's token, or no gateway_jwt; why the token
        is refused, or None). A supervisor's token is required for a request or a response."""
        if not jwt:
            return None, None
        scheme, _, tok = dict(context.invocation_metadata() or ()).get("authorization", "").partition(" ")
        try:
            if scheme.lower() != "bearer":
                raise ValueError("no bearer token")
            h64 = tok.split(".")[0]
            if json.loads(base64.urlsafe_b64decode(h64 + "=" * (-len(h64) % 4))).get("typ") != JWT_TYP:
                raise ValueError(f"not an {JWT_TYP} token")
            claims = verify_jwt(tok, lambda kid: ("EdDSA", key), ("EdDSA",), f"openshell-gateway:{jwt['gateway_id']}",
                                jwt["audience"], time.time(), ValueError)
            if supervisor and not (claims.get("caller_kind") == "supervisor" and isinstance(claims.get("sandbox_id"),
                                                                                              str)):
                raise ValueError("not a sandbox supervisor's token")
        except (ValueError, AttributeError, RecursionError) as e:
            why = f"OpenShell's token refused: {e}"
            print(f"tracekit openshell-middleware: {why}", file=sys.stderr, flush=True)
            return None, why
        return claims.get("sandbox_id"), None

    def describe(body, context):
        why = token(context, supervisor=False)[1]
        if why:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, why)
        try:
            why = negotiate(decode(body, _DESCRIBE).get("gateway"))
        except WireError as e:
            why = f"the Describe request doesn't decode: {e}"
        if why:
            print(f"tracekit openshell-middleware: Describe refused: {why}", file=sys.stderr, flush=True)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, why)
        return MANIFEST

    def validate(body, context):
        why = token(context, supervisor=False)[1]
        if why:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, why)
        return validate_config(body)

    def evaluate(body, context):
        sandbox, why = token(context)
        return result(DENY, why, "tracekit_unauthenticated") if why else mw.evaluate(body, sandbox)

    def respond(events, context):
        sandbox, why = token(context)
        if why:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, why)
        if not streams.acquire(blocking=False):   # each holds a thread: the rest stay free for evaluations
            why = f"{MAX_STREAMS} responses are streaming through the middleware already"
            print(f"tracekit openshell-middleware: a response refused: {why}", file=sys.stderr, flush=True)
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, why)
        try:
            yield from mw.respond(events, lambda why: context.abort(grpc.StatusCode.INVALID_ARGUMENT, why), sandbox)
        finally:
            streams.release()

    def logs(body, context):
        """LogsService.Export: OpenShell's OCSF events. An empty ExportLogsServiceResponse once the signer has them."""
        if bearer is not None:
            scheme, _, tok = dict(context.invocation_metadata() or ()).get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(tok.encode(), bearer.encode()):
                why = "OpenShell's OCSF export refused: no bearer token, or not ocsf.token_file's"
                print(f"tracekit openshell-middleware: {why}", file=sys.stderr, flush=True)
                context.abort(grpc.StatusCode.UNAUTHENTICATED, why)
        if not exports.acquire(blocking=False):   # each waits on the signer: the rest stay free for evaluations
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, f"{OCSF_EXPORTS} OCSF batches are being imported")
        try:
            mw.export(body)
        except WireError as e:
            print(f"tracekit openshell-middleware: an OCSF batch refused: {e}", file=sys.stderr, flush=True)
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"the OCSF batch doesn't decode: {e}")
        except (SignerUnavailable, RPCError) as e:
            why = f"the signer didn't take OpenShell's OCSF events ({e}); OpenShell sends the batch again" + (
                "; grant the middleware observe_effect in signer.yaml authorize" if getattr(e, "code", "") ==
                "forbidden" else "")
            print(f"tracekit openshell-middleware: {why}", file=sys.stderr, flush=True)
            context.abort(grpc.StatusCode.UNAVAILABLE, why)
        finally:
            exports.release()
        return b""

    unary = {"Describe": describe, "ValidateConfig": validate, "EvaluateHttpRequest": evaluate}
    srv = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=MAX_STREAMS + UNARY_WORKERS + OCSF_EXPORTS),
                      options=[("grpc.max_receive_message_length", MAX_MESSAGE)])
    srv.add_generic_rpc_handlers((
        grpc.method_handlers_generic_handler(SERVICE, {k: grpc.unary_unary_rpc_method_handler(f)
                                                       for k, f in unary.items()}),
        grpc.method_handlers_generic_handler(RESPONSES, {"Evaluate": grpc.stream_stream_rpc_method_handler(respond)}),
        *([grpc.method_handlers_generic_handler(LOGS, {"Export": grpc.unary_unary_rpc_method_handler(logs)})]
          if ocsf is not None else [])))
    tls = cfg.get("tls")
    try:
        if tls:
            with open(tls["key"], "rb") as k, open(tls["cert"], "rb") as c:
                port = srv.add_secure_port(cfg["listen"], grpc.ssl_server_credentials([(k.read(), c.read())]))
        else:
            port = srv.add_insecure_port(cfg["listen"])
    except RuntimeError as e:   # grpcio raises when it can't bind
        raise OSError(f"can't listen on {cfg['listen']}: {e}") from None
    if not port:
        raise OSError(f"can't listen on {cfg['listen']}")
    srv.start()

    def checks():
        said = None
        while True:
            try:
                mw.tick()
                said = None
            except (SignerUnavailable, RPCError) as e:
                if str(e) != said:
                    print(f"tracekit openshell-middleware: the OCSF import's check didn't reach the signer ({e}); it "
                          "tries again", file=sys.stderr, flush=True)
                said = str(e)
            if not srv.wait_for_termination(OCSF_CHECK_S):   # False once the server stopped
                return
    if ocsf is not None:
        threading.Thread(target=checks, daemon=True).start()
    return srv, port, mw


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit openshell-middleware")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run in the foreground").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
        srv, port, _ = serve(cfg)
    except (OSError, ValueError) as e:
        print(f"tracekit openshell-middleware: {e}", file=sys.stderr)
        return 2
    if not cfg.get("gateway_jwt"):
        print("tracekit openshell-middleware: no gateway_jwt: any peer that reaches the port is taken for OpenShell",
              file=sys.stderr, flush=True)
    if "ocsf" in cfg and "token_file" not in cfg["ocsf"]:
        print("tracekit openshell-middleware: no ocsf.token_file: any peer that reaches the port may send OCSF events",
              file=sys.stderr, flush=True)
    print(f"tracekit openshell-middleware: listening on port {port}", flush=True)
    signal.signal(signal.SIGTERM, signal.default_int_handler)   # stop as on Ctrl-C
    try:
        srv.wait_for_termination()
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop(None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
