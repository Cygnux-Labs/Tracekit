"""The NVIDIA OpenShell supervisor middleware (tracekit/openshell.py): a grpcio client plays OpenShell's supervisor and
gateway against the middleware, which decides and records through a real signer on a Unix socket. Messages are built
here field by field from OpenShell's proto/supervisor_middleware.proto, apart from the module's codec."""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import queue
import socket
import threading
import time
import unittest
import uuid
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adapter_contract import tmpdir
from test_signer_service import ME
from tracekit import openshell
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.otlp_wire import _fields, varint
from tracekit.policy2.compile import build
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService
from tracekit.transport import answering_hello, hello
from tracekit.verify import v2

HAVE_GRPC = importlib.util.find_spec("grpc") is not None
SANDBOX = "3f2b6c1e-0d4a-4b8e-9c1f-7a5e2d9b8c01"
CONTRACT = "openshell.supervisor-middleware.contract"
POLICY = Engine({"tools": {"http_request": "http"}, "untrusted": ["http"],
                 "deny": [{"id": "R-DENY", "tool": "^http_request$", "pattern": r"denied\.example"}],
                 "ask": [{"id": "R-ASK", "tool": "^http_request$", "pattern": r"ask\.example"}]})
PER_CALL = ["decide", "complete", "approval_request", "approval_wait", "approval_consume"]


def pb(fields):
    """A protobuf message of (field number, value): an int is a varint; str and bytes, and a list (a nested message's
    fields), are length-delimited."""
    out = b""
    for n, v in fields:
        if isinstance(v, int):
            out += varint(n << 3) + varint(v)
        else:
            b = pb(v) if isinstance(v, list) else v.encode() if isinstance(v, str) else v
            out += varint(n << 3 | 2) + varint(len(b)) + b
    return out


def fields(buf):
    """{field number: value} of one message (the last of a repeated field)."""
    return {n: v for n, _, v in _fields(memoryview(buf))}


def gateway(major=1, minor=0, supported=(CONTRACT,), required=(CONTRACT,)):
    """MiddlewareDescribeRequest with the gateway's PeerMetadata."""
    return pb([(1, [(1, [(1, major), (2, minor)]), (2, "openshell/gateway"), (3, "0.1.4")]
               + [(4, c) for c in supported] + [(5, c) for c in required])])


def context(request_id, sandbox=SANDBOX):
    return [(1, request_id), (2, sandbox), (3, [(1, "/usr/bin/curl"), (2, 57)]), (4, "demo"), (5, "default")]


def request(host, body=b"", request_id=None, method="POST", phase=1, sandbox=SANDBOX, query=None):
    """HttpRequestEvaluation."""
    return pb([(1, phase), (2, context(request_id or uuid.uuid4().hex, sandbox)),
               (4, [(1, "https"), (2, host), (3, 443), (4, method), (5, "/v1/send")] + ([(6, query)] if query else [])),
               (5, [(1, "content-type"), (2, "application/json")]), (6, body), (7, "tracekit")])


def preflight(request_id, status=200, modes=(1, 3), sandbox=SANDBOX):
    """HttpResponseEvent preflight (permitted_body_modes: 1 HEADERS_ONLY, 3 STREAM_BYTES)."""
    return pb([(1, [(1, context(request_id, sandbox)), (2, [(1, "https"), (2, "h"), (4, "GET")]), (3, status),
                    (4, [(1, "content-type"), (2, "text/plain")]), (5, "tracekit"), (7, 1 << 20)]
                + [(8, m) for m in modes])])


def unit(seq, data, end=False):
    return pb([(2, [(1, seq), (2, data)] + ([(3, 1)] if end else []))])


TRAILERS = pb([(4, [])])


class Codec(unittest.TestCase):
    def test_a_request_decodes_to_the_decided_arguments(self):
        req = openshell.decode(request("api.example", b'{"to": "x"}', "r-1"), openshell._REQUEST)
        self.assertEqual(openshell.args_of(req), {
            "method": "POST", "url": "https://api.example/v1/send", "headers": [["content-type", "application/json"]],
            "body": '{"to": "x"}'})
        for body in (b"\xff\x00", b"x" * (openshell.MAX_TEXT + 1)):   # binary, or past half a frame: never decided
            with self.subTest(size=len(body)), self.assertRaises(openshell.Unreadable):
                openshell.args_of(openshell.decode(request("h", body), openshell._REQUEST))

    def test_packed_body_modes_and_the_manifest(self):
        packed = pb([(1, [(8, varint(1) + varint(3))])])   # how protobuf encoders write a repeated enum
        self.assertEqual(openshell.decode(packed, openshell._EVENT)["preflight"]["modes"], [1, 3])
        manifest = fields(openshell.MANIFEST)
        peer = fields(manifest[5])
        self.assertEqual((fields(peer[1]), bytes(peer[4]).decode(), bytes(peer[5]).decode()),
                         ({1: 1}, CONTRACT, CONTRACT))   # protocol 1.0 (minor 0 is not written), the contract
        bindings = [fields(v) for n, _, v in _fields(memoryview(openshell.MANIFEST)) if n == 3]
        self.assertEqual([(b[1], b[2], b[3]) for b in bindings], [(1, 1, 4 << 20), (3, 2, 4 << 20)])


def serve_signer(case, service):
    """`service` on a Unix socket: (its path, the server)."""
    from tracekit.transport.unix import UnixServer
    path = os.path.join(tmpdir(case), "s.sock")
    srv = UnixServer(path, answering_hello(service.handle_frame, hello()))
    threading.Thread(target=srv.serve_forever, args=(0.2,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return path, srv


GATEWAY_KEY = Ed25519PrivateKey.generate()   # stands in for the OpenShell gateway's gateway_jwt signing key
AUDIENCE = "urn:openshell:extension:middleware:tracekit"


def token(sandbox=SANDBOX, key=GATEWAY_KEY, typ="openshell-ext+jwt", **claims):
    """An OpenShell extension token, as the gateway mints it (openshell-server/src/auth/sandbox_jwt.rs
    mint_extension_token): a supervisor's for `sandbox`, or with sandbox=None the gateway's own."""
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    now = int(time.time())
    body = {"iss": "openshell-gateway:openshell", "aud": AUDIENCE, "iat": now, "exp": now + 300,
            "jti": str(uuid.uuid4()), "caller_kind": "supervisor" if sandbox else "gateway",
            "sub": f"spiffe://openshell/sandbox/{sandbox}" if sandbox else "openshell-gateway:openshell",
            **({"sandbox_id": sandbox} if sandbox else {}), **claims}
    msg = f"{b64({'alg': 'EdDSA', 'typ': typ, 'kid': 'k1'})}.{b64(body)}"
    return msg + "." + base64.urlsafe_b64encode(key.sign(msg.encode())).rstrip(b"=").decode()


@unittest.skipUnless(HAVE_GRPC, "needs grpcio: pip install 'tracekit-ai[grpc]'")
@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "serves the signer on a Unix socket")
class Middleware(unittest.TestCase):
    """The middleware on loopback in front of a signer, and a grpcio client playing OpenShell."""
    config = {}   # the middleware's config besides listen and signer
    authorize = {"openshell:*": PER_CALL}
    policy = POLICY

    def setUp(self):
        import grpc
        self.grpc = grpc
        self.s = SignerService(tmpdir(self), policy=self.policy, gateways=["uid:*"], authorize=self.authorize,
                               observe_grace_s=0)
        self.addCleanup(self.s.close)
        path, self.signer = serve_signer(self, self.s)
        self.client = Client(path, timeout=5)
        self.addCleanup(self.client.close)
        srv, self.port, self.mw = openshell.serve({"listen": "127.0.0.1:0", "signer": path, **self.config}, self.client)
        self.addCleanup(srv.stop, None)
        channel = grpc.insecure_channel(f"127.0.0.1:{self.port}")
        self.addCleanup(channel.close)
        self.rpc = {m: channel.unary_unary(f"/{openshell.SERVICE}/{m}")
                    for m in ("Describe", "ValidateConfig", "EvaluateHttpRequest")}
        self.response = channel.stream_stream(f"/{openshell.RESPONSES}/Evaluate")

    def evaluate(self, body, auth=None):
        """(decision, reason_code) of the middleware's HttpRequestResult; `auth`: a token to send."""
        r = fields(self.rpc["EvaluateHttpRequest"](body, timeout=20, metadata=_bearer(auth)))
        return r.get(1), bytes(r.get(8, b"")).decode()

    def respond(self, *events, auth=None):
        return [fields(r) for r in self.response(iter(events), timeout=20, metadata=_bearer(auth))]

    def runs(self, sandbox=SANDBOX):
        return [k[1] for k in self.s.log.runs if k[1].startswith(f"openshell-{sandbox}-")]

    def events(self, run_id, *types):
        return [r["event"] for r in self.s.log.storage.iter_run("default", run_id) if r["event"]["type"] in types]


def _bearer(auth):
    return (("authorization", f"Bearer {auth}"),) if auth else None


class Supervisor(Middleware):
    def test_describe_pins_protocol_1_0(self):
        self.assertEqual(self.rpc["Describe"](gateway(), timeout=20), openshell.MANIFEST)
        for body in (gateway(2, 0), gateway(1, 1), gateway(0, 0), b"",   # b"": OpenShell 0.0.x sends Empty
                     gateway(supported=()), gateway(required=(CONTRACT, "openshell.supervisor-middleware.v2-bodies"))):
            with self.subTest(body=body), self.assertRaises(self.grpc.RpcError) as e:
                self.rpc["Describe"](body, timeout=20)
            self.assertEqual(e.exception.code(), self.grpc.StatusCode.FAILED_PRECONDITION)

    def test_validate_config_takes_none(self):
        self.assertEqual(fields(self.rpc["ValidateConfig"](pb([(2, "tracekit")]), timeout=20)), {1: 1})
        struct = pb([(1, [(1, [(1, "mode"), (2, [(3, "deny")])])]), (2, "tracekit")])
        self.assertNotIn(1, fields(self.rpc["ValidateConfig"](struct, timeout=20)))

    def test_allowed_request_and_its_response_are_one_t2_call_of_the_sandboxs_run(self):
        self.assertEqual(self.evaluate(request("allowed.example", b'{"q": 1}', "r-1")), (openshell.ALLOW, ""))
        out = self.respond(preflight("r-1"), unit(1, b"hello "), unit(2, b"world", end=True), TRAILERS)
        self.assertEqual([sorted(o) for o in out], [[1], [2], [2], [3]])
        self.assertEqual(fields(fields(out[0][1])[2]), {1: openshell.STREAM_BYTES})   # inspect, as a stream
        self.assertEqual([fields(o[2])[1] for o in out[1:3]], [1, 2])   # each unit passed through, in order
        [run_id] = self.runs()
        decision, done = self.events(run_id, "policy.decision", "tool.result")
        for e in (decision, done):
            self.assertEqual((e["source"], e["tier"], e["tool_call_id"]), ("gateway", "T2", decision["tool_call_id"]))
        self.assertEqual((decision["data"]["decision"], decision["data"]["caller"], decision["data"]["via"]),
                         ("allow", "openshell:" + SANDBOX, f"uid:{os.getuid()}"))
        self.assertTrue(done["data"]["ok"])
        self.assertEqual(self.s.log.runs[("default", run_id)]["prov"]["state"], "complete")   # the body was sent

    def test_a_response_without_its_body_is_completed_with_a_digest(self):
        self.evaluate(request("allowed.example", request_id="r-2", method="GET"))
        self.assertEqual(fields(self.respond(preflight("r-2", modes=(1,)))[0][1]), {1: b""})   # skip
        [run_id] = self.runs()
        [done] = self.events(run_id, "tool.result")
        self.assertTrue(done["data"]["ok"])
        self.assertEqual(self.s.log.runs[("default", run_id)]["prov"]["state"], "partial")   # what it couldn't read

    def test_an_error_status_or_a_stream_cut_before_its_last_unit_is_an_error(self):
        self.evaluate(request("allowed.example", request_id="r-3", method="GET"))
        self.respond(preflight("r-3", status=404), unit(1, b"not found", end=True), TRAILERS)
        self.evaluate(request("allowed.example", request_id="r-4", method="GET"))
        self.respond(preflight("r-4"), unit(1, b"half"))
        self.assertEqual([e["data"]["ok"] for e in self.events(self.runs()[0], "tool.result")], [False, False])

    def test_denied_never_reaches_upstream(self):
        self.assertEqual(self.evaluate(request("denied.example", b"x")), (openshell.DENY, "tracekit_denied"))
        [d] = self.events(self.runs()[0], "policy.decision")
        self.assertEqual((d["data"]["decision"], d["data"]["rule_ids"]), ("deny", ["R-DENY"]))

    def test_ask_is_denied_until_approved_then_the_same_request_runs_once(self):
        req = request("ask.example", b'{"amount": 5}', "r-5")
        self.assertEqual(self.evaluate(req), (openshell.DENY, "tracekit_approval_required"))
        self.assertEqual(self.evaluate(req), (openshell.DENY, "tracekit_approval_pending"))
        [run_id] = self.runs()
        [a] = self.s.call(ME, "approval_list", {"run_id": run_id})["approvals"]
        self.s.call(ME, "approval_decide", {"request_id": "d1", "approval_id": a["approval_id"], "decision": "approve"})
        other = request("ask.example", b'{"amount": 500}', "r-6")
        self.assertEqual(self.evaluate(other), (openshell.DENY, "tracekit_approval_required"))   # not the approved one
        self.assertEqual(self.evaluate(req), (openshell.ALLOW, ""))
        self.respond(preflight("r-5"), unit(1, b"ok", end=True), TRAILERS)
        self.assertEqual(self.evaluate(req), (openshell.DENY, "tracekit_approval_required"))   # used once
        consumed = self.events(run_id, "approval.consumed", "tool.result")
        self.assertEqual([e["type"] for e in consumed], ["approval.consumed", "tool.result"])
        self.assertTrue(consumed[1]["data"]["ok"])

    def test_signer_down_and_malformed_requests_are_denied(self):
        self.assertEqual(self.evaluate(request("allowed.example")), (openshell.ALLOW, ""))
        self.signer.shutdown()
        self.signer.server_close()
        self.client.close()
        self.assertEqual(self.evaluate(request("allowed.example")), (openshell.DENY, "tracekit_signer_unreachable"))
        for body in (b"\xff", request("h", phase=2), request("h", sandbox="../x"), pb([(1, 1)])):
            with self.subTest(body=body):
                self.assertEqual(self.evaluate(body), (openshell.DENY, "tracekit_malformed_request"))

    def test_a_run_the_signer_closed_is_replaced_and_its_bundle_verifies(self):
        self.evaluate(request("allowed.example", request_id="r-7", method="GET"))
        self.respond(preflight("r-7"), unit(1, b"ok", end=True), TRAILERS)
        [first] = self.runs()
        self.s.idle_s, self.s.grace_s = 0, 0
        self.s.sweep(now=time.monotonic() + 1)   # idle: closed
        self.s.sweep(now=time.monotonic() + 2)   # final
        self.assertEqual(self.evaluate(request("allowed.example")), (openshell.ALLOW, ""))
        self.assertEqual(len(self.runs()), 2)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.s.data_dir, "b.tkb"), os.path.join(self.s.data_dir, "trust.json")
        export(self.s.log.storage, "default", first, self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, rep.checks)

    def test_open_response_streams_leave_threads_for_evaluations(self):
        feeds = [queue.Queue() for _ in range(openshell.MAX_STREAMS)]   # slow downloads: streams that stay open
        calls = [self.response(iter(q.get, None), timeout=60) for q in feeds]
        self.addCleanup(lambda: [q.put(None) for q in feeds])
        time.sleep(0.5)
        t = time.monotonic()
        self.assertEqual(self.evaluate(request("allowed.example", sandbox="other-sandbox"))[0], openshell.ALLOW)
        self.assertLess(time.monotonic() - t, 1)
        with self.assertRaises(self.grpc.RpcError) as e:   # one stream more: refused at once, never queued
            self.respond(preflight("r-x"))
        self.assertEqual(e.exception.code(), self.grpc.StatusCode.RESOURCE_EXHAUSTED)
        for q in feeds:
            q.put(None)
        for c in calls:
            list(c)
        self.respond(preflight("r-y"))   # their threads are free again

    def test_each_sandbox_has_budgets_of_its_own(self):
        for i in range(101):   # the signer's default open_runs is 100: per sandbox now, not for the middleware
            self.assertEqual(self.evaluate(request("allowed.example", sandbox=f"sb-{i}", method="GET")),
                             (openshell.ALLOW, ""), i)
        self.s.quotas.limits = Limits(events_per_s=0.001, burst=3)   # its register and two decides
        for _ in range(2):
            self.assertEqual(self.evaluate(request("allowed.example", sandbox="noisy", method="GET"))[0],
                             openshell.ALLOW)
        self.assertEqual(self.evaluate(request("allowed.example", sandbox="noisy", method="GET")),
                         (openshell.DENY, "tracekit_signer_refused"))
        self.assertEqual(self.evaluate(request("allowed.example", sandbox="quiet", method="GET"))[0], openshell.ALLOW)

    def test_a_cancelled_response_stream_completes_its_call_as_an_error(self):
        self.evaluate(request("allowed.example", request_id="r-c", method="GET"))
        feed = queue.Queue()
        call = self.response(iter(feed.get, None), timeout=30)
        feed.put(preflight("r-c"))
        next(call)
        feed.put(unit(1, b"half"))
        next(call)
        call.cancel()
        [run] = self.runs()
        deadline = time.monotonic() + 5
        while not self.events(run, "tool.result") and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual([e["data"]["ok"] for e in self.events(run, "tool.result")], [False])

    def test_a_request_waiting_for_its_response_keeps_no_arguments(self):
        for i in range(3):   # responses that may never come (an upstream failure, a WebSocket upgrade)
            self.assertEqual(self.evaluate(request("allowed.example", b"A" * (60 * 1024), f"r-{i}"))[0], openshell.ALLOW)
        self.assertLess(len(repr(list(self.mw.inflight.values()))), 8192)
        self.respond(preflight("r-0"), unit(1, b"ok", end=True), TRAILERS)   # the signer checks the arguments' hash
        self.assertEqual([e["data"]["ok"] for e in self.events(self.runs()[0], "tool.result")], [True])

    def test_a_held_request_is_printed_without_its_query(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.evaluate(request("ask.example", b"{}", query="token=abc123"))
        self.assertIn("POST https://ask.example/v1/send waits for approval", err.getvalue())
        self.assertNotIn("abc123", err.getvalue())


class ServerPack(Middleware):
    """Under the shipped server pack: a body the policy can't read is denied, never decided without it."""
    policy = Engine(build(os.path.join(os.path.dirname(openshell.__file__), "policy2", "packs", "server.yaml"))[0])

    def test_a_body_the_policy_cannot_read_is_denied(self):
        secret = b'{"key": "AKIA' + b'IOSFODNN7EXAMPLE"}'
        self.assertEqual(self.evaluate(request("upload.example.com", b'{"q": 1}')), (openshell.ALLOW, ""))
        self.assertEqual(self.evaluate(request("upload.example.com", secret)), (openshell.DENY, "tracekit_denied"))
        decided = len(self.events(self.runs()[0], "policy.decision"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for body in (gzip.compress(secret), secret + b" " * (600 * 1024)):   # binary; past half a frame
                with self.subTest(size=len(body)):
                    self.assertEqual(self.evaluate(request("upload.example.com", body)),
                                     (openshell.DENY, "tracekit_body_unreadable"))
        self.assertEqual(len(self.events(self.runs()[0], "policy.decision")), decided)   # no decision without it
        self.assertIn("isn't UTF-8 text", err.getvalue())
        self.assertIn("over the 512 KiB the signer takes", err.getvalue())
        self.assertEqual(self.evaluate(request("upload.example.com", secret + b" " * (100 * 1024)))[0], openshell.DENY)


class Authenticated(Middleware):
    """With gateway_jwt: each call's OpenShell extension token is checked."""

    def setUp(self):
        d = tmpdir(self)
        pub = os.path.join(d, "gateway.pub")
        with open(pub, "wb") as f:
            f.write(GATEWAY_KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
        self.config = {"gateway_jwt": {"gateway_id": "openshell", "public_key": pub, "audience": AUDIENCE}}
        super().setUp()

    def test_a_supervisors_token_for_its_own_sandbox_is_taken(self):
        self.assertEqual(self.evaluate(request("allowed.example", request_id="r-1"), token()), (openshell.ALLOW, ""))
        self.respond(preflight("r-1"), unit(1, b"ok", end=True), TRAILERS, auth=token())
        self.assertEqual([e["data"]["ok"] for e in self.events(self.runs()[0], "tool.result")], [True])
        self.assertEqual(self.rpc["Describe"](gateway(), timeout=20, metadata=_bearer(token(None))), openshell.MANIFEST)

    def test_no_token_or_a_bad_one_is_refused(self):
        other = Ed25519PrivateKey.generate()
        for auth in (None, "not-a-jwt", token(key=other), token(typ="JWT"), token(aud="urn:other"),
                     token(iss="openshell-gateway:another"), token(exp=int(time.time()) - 600), token(None),
                     token("another-sandbox")):
            with self.subTest(auth=auth):
                self.assertEqual(self.evaluate(request("allowed.example"), auth),
                                 (openshell.DENY, "tracekit_unauthenticated"))
        self.assertEqual(self.runs(), [])   # nothing reached the signer
        with self.assertRaises(self.grpc.RpcError) as e:
            self.rpc["Describe"](gateway(), timeout=20)
        self.assertEqual(e.exception.code(), self.grpc.StatusCode.UNAUTHENTICATED)

    def test_a_peer_cannot_complete_another_sandboxs_call(self):
        self.assertEqual(self.evaluate(request("allowed.example", b'{"q": 1}', "r-2"), token())[0], openshell.ALLOW)
        for auth, code in ((None, "UNAUTHENTICATED"), (token("another-sandbox"), "INVALID_ARGUMENT")):
            with self.subTest(code), self.assertRaises(self.grpc.RpcError) as e:
                self.respond(preflight("r-2"), unit(1, b'{"forged": true}', end=True), TRAILERS, auth=auth)
            self.assertEqual(e.exception.code().name, code)
        self.respond(preflight("r-2"), unit(1, b"real", end=True), TRAILERS, auth=token())
        [done] = self.events(self.runs()[0], "tool.result")
        self.assertTrue(done["data"]["ok"])


# OpenShell's OCSF events as its OTLP log export sends them (openshell-otel/src/ocsf.rs log_record and gap_record): the
# body the OCSF JSON event (openshell-ocsf/src/events, shaped after docs/observability/ocsf-json-export.mdx), the
# attributes ocsf.class_uid, ocsf.activity_id, ocsf.severity_id, ocsf.metadata.uid and openshell.sandbox.id, a
# supervisor's resource naming its sandbox (openshell-supervisor/src/main.rs supervisor_resource_attributes)
OTHER = "9a1c0d2e-5b7f-4c3a-8e6d-1f2b3c4d5e6f"
SUPERVISOR = {"service.name": "openshell-sandbox", "openshell.gateway.name": "openshell"}
GATEWAY = {"service.name": "openshell-gateway", "openshell.gateway.name": "openshell"}


def ocsf_event(cls, activity=1, sandbox=SANDBOX, **fields):
    names = {4001: "Network Activity", 4002: "HTTP Activity", 1007: "Process Activity", 5019: "Device Config State "
             "Change", 4007: "SSH Activity", 3002: "Authentication"}
    return {"class_uid": cls, "class_name": names[cls], "category_uid": cls // 1000, "activity_id": activity,
            "severity_id": 1, "severity": "Informational", "status_id": 1, "status": "Success",
            "time": 1791996125789, "metadata": {"version": "1.8.0", "uid": str(uuid.uuid4()), "product": {
                "name": "OpenShell Sandbox Supervisor", "vendor_name": "OpenShell", "version": "0.1.4"}},
            "device": {"hostname": "node-1", "type_id": 99, "type": "Sandbox"},
            **({"container": {"name": "demo", "uid": sandbox}} if sandbox else {}), **fields}


def connect(host="api.example.com", denied=False, **fields):
    return ocsf_event(4001, **{
        "message": f"CONNECT {'denied' if denied else 'allowed'} {host}:443", "action_id": 2 if denied else 1,
        "action": "Denied" if denied else "Allowed", "disposition_id": 2 if denied else 1,
        "disposition": "Blocked" if denied else "Allowed", "dst_endpoint": {"domain": host, "port": 443},
        "src_endpoint": {"ip": "192.0.2.31", "port": 37494},
        "actor": {"process": {"name": "/usr/bin/curl", "pid": 2187, "cmd_line": f"curl https://{host}"}},
        "firewall_rule": {"name": "api_policy", "type": "opa"}, **fields})


LAUNCH = dict(cls=1007, message="Process started: pid=57", process={"name": "/usr/local/bin/agent", "pid": 57},
              launch_type_id=1, action_id=1, disposition_id=1)   # openshell-sandbox/src/delegated.rs
APPROVED = dict(cls=5019, state_id=99, state="approved", message="gateway approved draft chunk c-1: add-rule example",
                unmapped={"policy_version": "v7", "policy_hash": "3f" * 32, "actor": "user:dev@example.com"})


def kv(field, key, value):
    """A KeyValue as field `field`: an int as AnyValue int_value, else string_value."""
    return (field, [(1, key), (2, [(3, value)] if isinstance(value, int) else [(1, value)])])


def log_record(ev=None, attrs=None, event_name=None, ns=0):
    """A LogRecord: time_unix_nano (fixed64, written by hand), severity, the body, attributes, event_name."""
    if isinstance(ev, dict):
        attrs = {"ocsf.class_uid": ev["class_uid"], "ocsf.activity_id": ev["activity_id"], "ocsf.severity_id": 1,
                 "ocsf.metadata.uid": ev["metadata"]["uid"],
                 **({"openshell.sandbox.id": ev["container"]["uid"]} if "container" in ev else {}), **(attrs or {})}
    out = varint(1 << 3 | 1) + ns.to_bytes(8, "little") + pb(
        [(2, 9), (3, "INFO")] + ([(5, [(1, json.dumps(ev) if isinstance(ev, dict) else ev)])] if ev else [])
        + [kv(6, k, v) for k, v in (attrs or {}).items()] + ([(12, event_name)] if event_name else []))
    return out


def logs(*records, resource=SUPERVISOR, sandbox=SANDBOX):
    """ExportLogsServiceRequest of one resource (a supervisor's names its sandbox) and the openshell.ocsf scope."""
    res = {**resource, **({"openshell.sandbox.id": sandbox} if sandbox and resource is SUPERVISOR else {})}
    return pb([(1, [(1, [kv(1, k, v) for k, v in res.items()]),
                    (2, [(1, [(1, "openshell.ocsf")])] + [(2, r) for r in records])])])


def gap(dropped=12, since=1791996125000):
    return log_record(attrs={"openshell.ocsf.gap.dropped": dropped, "openshell.ocsf.gap.since_unix_ms": since},
                      event_name="openshell.ocsf.gap")


class OcsfCodec(unittest.TestCase):
    def test_a_batch_decodes_and_each_class_maps(self):
        ev = connect(denied=True)
        [(res, attrs, text, ns, name)] = openshell.log_records(logs(log_record(ev, ns=5 * 10 ** 18)))
        self.assertEqual((res["openshell.sandbox.id"], attrs["ocsf.metadata.uid"], json.loads(text), ns, name),
                         (SANDBOX, ev["metadata"]["uid"], ev, 5 * 10 ** 18, ""))
        ts = "2026-10-15T00:00:00.000000Z"
        self.assertEqual(openshell.ocsf_effect(ev, ts), {"kind": "connect", "ts": ts, "pid": 2187,
                                                         "binary": "/usr/bin/curl", "host": "api.example.com",
                                                         "port": 443, "denied": True})
        http = ocsf_event(4002, 99, action_id=2, http_request={"http_method": "POST", "url": {
            "scheme": "https", "hostname": "Upload.Example.com", "path": "/v1", "port": 8443}})
        self.assertEqual(openshell.ocsf_effect(http, ts), {"kind": "connect", "ts": ts, "pid": 0, "binary": "unknown",
                                                           "host": "upload.example.com", "port": 8443, "denied": True})
        self.assertEqual(openshell.ocsf_effect(ocsf_event(**LAUNCH), ts),
                         {"kind": "exec", "ts": ts, "pid": 57, "binary": "/usr/local/bin/agent"})
        ended = ocsf_event(1007, 2, process={"name": "/bin/sh", "pid": 9}, exit_code=3)
        self.assertEqual(openshell.ocsf_effect(ended, ts),
                         {"kind": "exit", "ts": ts, "pid": 9, "binary": "/bin/sh", "status": 3})
        policy = openshell.ocsf_effect(ocsf_event(**APPROVED), ts)
        self.assertEqual({k: policy[k] for k in ("kind", "change", "policy_hash", "by")},
                         {"kind": "policy", "change": "approved", "policy_hash": "3f" * 32,
                          "by": "user:dev@example.com"})
        self.assertRegex(policy["detail_digest"], "^sha256:[0-9a-f]{64}$")   # the message, never in clear
        for ev, why in ((connect(firewall_rule={"name": "p", "type": "middleware"}), "the middleware's own decisions"),
                        (ocsf_event(4001, 4, message="connection failed"), "Network Activity events that neither"),
                        (ocsf_event(4007), "SSH Activity events"),
                        (ocsf_event(1007, 2, status_id=2, message="Failed to send SIGTERM"), "Process Activity events "
                                                                                          "other than")):
            with self.subTest(why):
                self.assertTrue(openshell.ocsf_effect(ev, ts).startswith(why))

    def test_what_does_not_decode_is_refused(self):
        for body in (b"\x0a\x05\x12\x03\x12\x01", b"\xff"):
            with self.subTest(body=body), self.assertRaises(openshell.WireError):
                openshell.log_records(body)


class Ocsf(Middleware):
    """OpenShell's OCSF export into the middleware (LogsService.Export on its port), recorded in each sandbox's run."""
    config = {"ocsf": {}}
    authorize = {"openshell:*": PER_CALL, f"uid:{os.getuid()}": sorted(svc.DEFAULT_GRANTS | {"observe_effect"})}

    def setUp(self):
        super().setUp()
        channel = self.grpc.insecure_channel(f"127.0.0.1:{self.port}")
        self.addCleanup(channel.close)
        self.export = channel.unary_unary(f"/{openshell.LOGS}/Export")
        self.mw.tick()   # its first heartbeat (the server's own check thread sends one too): it covers runs from now

    def run_of(self, sandbox=SANDBOX):
        [run_id] = self.runs(sandbox)
        return run_id

    def test_each_class_goes_to_its_sandboxs_run_and_verifies_in_both_verifiers(self):
        allowed, denied, other = connect(), connect("blocked.example.com", denied=True), connect(sandbox=OTHER)
        launch, approved = ocsf_event(**LAUNCH), ocsf_event(**APPROVED)
        batch = logs(log_record(launch), log_record(allowed), log_record(denied))
        self.assertEqual(self.export(batch, timeout=20), b"")   # an empty ExportLogsServiceResponse: all taken
        self.export(logs(log_record(approved), resource=GATEWAY), timeout=20)   # the gateway's, naming the sandbox
        self.export(logs(log_record(other), sandbox=OTHER), timeout=20)
        self.assertEqual(self.evaluate(request("allowed.example", request_id="r-1", method="GET"))[0], openshell.ALLOW)
        run_id = self.run_of()   # the one run of the sandbox: its OCSF events' and its requests'
        self.assertEqual(len(self.runs(OTHER)), 1)
        effects = self.events(run_id, "effect.observed")
        self.assertEqual([(e["data"]["kind"], e["data"].get("host"), e["data"].get("denied")) for e in effects],
                         [("exec", None, None), ("connect", "api.example.com", None),
                          ("connect", "blocked.example.com", True)])
        for e in effects:
            self.assertEqual((e["source"], e["data"]["sensor"], e["data"]["observer"], e["data"]["attribution"]),
                             ("signer", "openshell", f"uid:{os.getuid()}", "token"))
        [ext] = self.events(run_id, "ext")
        self.assertEqual({k: ext["data"][k] for k in ("name", "change", "policy_hash", "by")},
                         {"name": "openshell.policy", "change": "approved", "policy_hash": "3f" * 32,
                          "by": "user:dev@example.com"})
        self.assertNotIn("draft chunk", json.dumps(ext))   # the message is committed, not stored
        self.assertTrue(ext["data"]["detail_commitment"])
        self.respond(preflight("r-1"), unit(1, b"ok", end=True), TRAILERS)
        self.s.idle_s, self.s.grace_s = 0, 0
        self.s.sweep(now=time.monotonic() + 1)
        self.s.sweep(now=time.monotonic() + 2)
        [final] = self.events(run_id, "run.final")
        self.assertEqual(final["data"]["matrix"]["processes"]["status"], "none")   # OpenShell's report isn't a sensor's
        bundle = self.bundle(run_id)
        rep, code = v2.verify(bundle, self.trust)
        self.assertEqual(code, 0, rep.checks)
        [line] = [c for c in rep.checks if c["check"] == "openshell policy"]
        self.assertEqual((line["status"], line["detail"]), ("pass", "OpenShell changed the sandbox policy or "
                                                                    "configuration 1 time(s) (approved: 1), as "
                                                                    "OpenShell reported it"))
        with mock.patch.dict(v2.EXT_CHECKS):   # a verifier that doesn't interpret it: VERIFIED, the name not read
            del v2.EXT_CHECKS["openshell.policy"]
            old, code = v2.verify(bundle, self.trust)
        self.assertEqual((code, old.integrity), (0, rep.integrity))
        [note] = [c for c in old.checks if c["check"] == "not interpreted"]
        self.assertEqual(note["status"], "warn")
        self.assertIn("1 record(s) carry ext.openshell.policy", note["detail"])
        try:
            from test_ts_verifier import SKIP, ts_verify
        except ImportError:
            SKIP = "no TypeScript verifier test helpers"
        if not SKIP:
            ts = ts_verify(bundle, self.trust)
            self.assertEqual((ts["exit_code"], ts["integrity"]), (code, rep.integrity))
            self.assertEqual([(c["check"], c["status"]) for c in ts["checks"]],
                             [(c["check"], c["status"]) for c in rep.checks])
            self.assertEqual([c for c in ts["checks"] if c["check"] == "openshell policy"], [line])

    def bundle(self, run_id):
        self.s.checkpoint()
        bundle, self.trust = os.path.join(self.s.data_dir, f"{run_id}.tkb"), os.path.join(self.s.data_dir, "t.json")
        export(self.s.log.storage, "default", run_id, self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(self.trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        return bundle

    def test_a_batch_sent_again_is_recorded_once(self):
        batch = logs(log_record(connect()), log_record(connect(denied=True)))
        self.export(batch, timeout=20)
        self.export(batch, timeout=20)   # OpenShell's retry of a batch the signer had (at least once delivery)
        self.assertEqual(len(self.events(self.run_of(), "effect.observed")), 2)

    def test_losses_are_signed_gaps(self):
        self.export(logs(log_record(connect()), gap()), timeout=20)   # a supervisor's: its own sandbox
        run_id = self.run_of()
        [lost] = [e["data"] for e in self.events(run_id, "capture.gap") if e["data"]["kind"] == "observer_lost"]
        self.assertIn("OpenShell dropped 12 OCSF record(s) before export from 2026-10-14T16:42:05.000000Z",
                      lost["reason"])
        self.assertIn("sandbox supervisor's gap record", lost["reason"])
        self.export(logs(gap(3), resource=GATEWAY), timeout=20)   # the gateway's: any sandbox, every covered run
        self.assertTrue(any("its gateway's gap record" in e["data"]["reason"]
                            for e in self.events(run_id, "capture.gap")))
        # a request decided, then nothing from the sandbox's stream for STALE_S: its export stopped, once
        self.evaluate(request("allowed.example", method="GET", sandbox=OTHER))
        later = time.monotonic() + openshell.STALE_S + 1
        self.mw.tick(later)
        self.mw.tick(later + 1)
        self.evaluate(request("allowed.example", method="GET", sandbox=OTHER))   # still stalled: no second gap
        self.mw.tick(later + openshell.STALE_S + 2)
        stopped = [e["data"]["reason"] for e in self.events(self.run_of(OTHER), "capture.gap")]
        self.assertEqual(len(stopped), 1, stopped)
        self.assertIn(f"no OCSF event from OpenShell for sandbox {OTHER} in {openshell.STALE_S}s", stopped[0])
        self.export(logs(log_record(connect(sandbox=OTHER)), sandbox=OTHER), timeout=20)   # it sends again: watched
        self.evaluate(request("allowed.example", method="GET", sandbox=OTHER))
        self.mw.tick(time.monotonic() + openshell.STALE_S + 1)
        self.assertEqual(len(self.events(self.run_of(OTHER), "capture.gap")), 2)

    def test_what_is_not_imported_is_counted_and_printed(self):
        self.export(logs(log_record(ocsf_event(4007)), log_record("not json", attrs={"openshell.sandbox.id": SANDBOX}),
                         log_record(connect(firewall_rule={"name": "p", "type": "middleware"}))), timeout=20)
        self.export(logs(log_record(ocsf_event(3002, sandbox=None)), resource=GATEWAY), timeout=20)
        self.assertEqual(self.runs(), [])   # nothing to record: no run
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.mw.tick()
        self.assertIn("OpenShell OCSF events not imported so far: 1 x SSH Activity events; 1 x events of no sandbox "
                      "(the gateway's own); 1 x log records that aren't OCSF events OpenShell writes; 1 x the "
                      "middleware's own decisions (recorded as its calls)", err.getvalue())

    def test_a_batch_the_signer_cannot_take_is_refused_for_openshell_to_send_again(self):
        batch = logs(log_record(connect()))
        self.signer.shutdown()
        self.signer.server_close()
        self.client.close()
        with self.assertRaises(self.grpc.RpcError) as e:
            self.export(batch, timeout=20)
        self.assertEqual(e.exception.code(), self.grpc.StatusCode.UNAVAILABLE)
        with self.assertRaises(self.grpc.RpcError) as e:
            self.export(b"\xff", timeout=20)
        self.assertEqual(e.exception.code(), self.grpc.StatusCode.INVALID_ARGUMENT)


class OcsfToken(Middleware):
    """ocsf.token_file: OpenShell's OCSF export sends it as its collector header (OTEL_EXPORTER_OTLP_LOGS_HEADERS)."""
    authorize = Ocsf.authorize

    def setUp(self):
        path = os.path.join(tmpdir(self), "ocsf.token")
        with open(path, "w") as f:
            f.write("s3cret-token\n")
        self.config = {"ocsf": {"token_file": path}}
        super().setUp()
        channel = self.grpc.insecure_channel(f"127.0.0.1:{self.port}")
        self.addCleanup(channel.close)
        self.export = channel.unary_unary(f"/{openshell.LOGS}/Export")

    def test_only_the_token_is_taken(self):
        batch = logs(log_record(connect()))
        for auth in (None, "wrong-token", "s3cret-token-2"):
            with self.subTest(auth=auth), self.assertRaises(self.grpc.RpcError) as e:
                self.export(batch, timeout=20, metadata=_bearer(auth))
            self.assertEqual(e.exception.code(), self.grpc.StatusCode.UNAUTHENTICATED)
        self.assertEqual(self.runs(), [])
        self.assertEqual(self.export(batch, timeout=20, metadata=_bearer("s3cret-token")), b"")
        self.assertEqual(len(self.events(self.run_of(), "effect.observed")), 1)

    run_of = Ocsf.run_of


class GatewayObserver(unittest.TestCase):
    def test_only_a_configured_gateway_observes_the_runs_it_registered(self):
        """An observer is never the run's agent: a run's owner is refused as its observer, unless it is a configured
        gateway, which registers runs for the clients it serves (the OpenShell middleware's OCSF import). Policy and
        lost effects are OpenShell's alone."""
        ids = {name: CallerIdentity("mtls", f"spiffe://acme.example/{name}", True) for name in ("agent", "gateway")}
        s = SignerService(tmpdir(self), policy=POLICY, gateways=["mtls:spiffe://acme.example/gateway"],
                          authorize={f"mtls:{i.subject}": ["register_run", "observe_effect"] for i in ids.values()})
        self.addCleanup(s.close)
        for name, who in ids.items():
            r = s.call(who, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": name}})
            at = {"run_id": r["run_id"], "run_token": r["run_token"], "ts": "2026-10-15T00:00:00.000000Z"}
            req = {"request_id": uuid.uuid4().hex, "instance": "i", "sensor": "openshell",
                   "callers": [f"mtls:{who.subject}"], "effects": [
                       {**at, "kind": "connect", "pid": 1, "binary": "/usr/bin/curl", "host": "blocked.example.com",
                        "port": 443, "denied": True}]}
            with self.subTest(name):
                if name == "gateway":
                    self.assertEqual(s.call(who, "observe_effect", req), {"recorded": 1})
                else:
                    with self.assertRaises(RPCError) as e:
                        s.call(who, "observe_effect", req)
                    self.assertEqual(e.exception.code, "forbidden")
            for kind in ({"kind": "policy", "change": "loaded"}, {"kind": "lost", "reason": "x"}):
                with self.subTest(kind=kind), self.assertRaises(RPCError) as e:
                    s.call(who, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i", "sensor": "falco",
                                                   "callers": [f"mtls:{who.subject}"], "effects": [{**at, **kind}]})
                self.assertEqual(e.exception.code, "invalid_request")

    def test_an_openshell_effect_lands_only_in_a_run_the_middleware_registered(self):
        """OpenShell's import observes as its own identity, its one caller: an effect it attributes to a run another
        identity owns (by that run's token) is an effect_outside_run gap, not a record of that run, and naming that
        identity among its callers is refused."""
        agent, gateway = (CallerIdentity("mtls", f"spiffe://acme.example/{n}", True) for n in ("agent", "gateway"))
        s = SignerService(tmpdir(self), policy=POLICY, gateways=[f"mtls:{gateway.subject}"],
                          authorize={f"mtls:{i.subject}": ["register_run", "observe_effect"] for i in (agent, gateway)})
        self.addCleanup(s.close)
        r = s.call(agent, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agent"}})
        effect = {"run_id": r["run_id"], "run_token": r["run_token"], "ts": "2026-10-15T00:00:00.000000Z",
                  "kind": "connect", "pid": 1, "binary": "/usr/bin/curl", "host": "api.example.com", "port": 443}

        def observe(callers):
            return s.call(gateway, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i",
                                                      "sensor": "openshell", "callers": callers, "effects": [effect]})
        observe([f"mtls:{gateway.subject}"])
        types = [x["event"]["type"] for x in s.log.storage.iter_run(r["tenant"], r["run_id"])]
        self.assertNotIn("effect.observed", types)
        [gap] = [x["event"]["data"] for x in s.log.storage.iter_run(r["tenant"], "tracekit/signer")
                 if x["event"]["type"] == "capture.gap"]
        self.assertEqual((gap["kind"], gap["run_id"]), ("effect_outside_run", r["run_id"]))
        self.assertIn("none of the import's callers", gap["reason"])
        with self.assertRaises(RPCError) as e:
            observe([f"mtls:{agent.subject}"])
        self.assertEqual(e.exception.code, "invalid_request")


class Config(unittest.TestCase):
    def load(self, **cfg):
        d = tmpdir(self)
        path = os.path.join(d, "openshell-middleware.yaml")
        with open(path, "w") as f:
            json.dump({"signer": "https://signer.example.com:8443", **cfg}, f)
        return openshell.load_config(path)

    def test_beyond_loopback_needs_gateway_jwt_and_gateway_jwt_needs_tls(self):
        jwt = {"gateway_id": "openshell", "public_key": "jwt/public.pem", "audience": AUDIENCE}
        tls = {"cert": "tls/mw.pem", "key": "tls/mw.key"}
        self.assertEqual(self.load(listen="127.0.0.1:50051")["listen"], "127.0.0.1:50051")
        self.assertEqual(self.load(listen="[::1]:50051")["listen"], "[::1]:50051")
        for bad in ({"listen": "0.0.0.0:50051"}, {"listen": "localhost:50051"},
                    {"listen": "0.0.0.0:50051", "gateway_jwt": jwt},
                    {"listen": "0.0.0.0:50051", "gateway_jwt": {**jwt, "audience": ""}, "tls": tls},
                    {"listen": "0.0.0.0:50051", "allow_unauthenticated": "yes"}):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.load(**bad)
        cfg = self.load(listen="0.0.0.0:50051", gateway_jwt=jwt, tls=tls)
        self.assertTrue(cfg["gateway_jwt"]["public_key"].endswith(os.path.join("jwt", "public.pem")))
        self.assertTrue(os.path.isabs(cfg["gateway_jwt"]["public_key"]))
        self.assertTrue(self.load(listen="0.0.0.0:50051", allow_unauthenticated=True)["allow_unauthenticated"])

    def test_ocsf_beyond_loopback_needs_a_token_and_the_token_needs_tls(self):
        jwt = {"gateway_id": "openshell", "public_key": "jwt/public.pem", "audience": AUDIENCE}
        tls = {"cert": "tls/mw.pem", "key": "tls/mw.key"}
        self.assertEqual(self.load(listen="127.0.0.1:50051", ocsf={})["ocsf"], {})
        for bad in ({"listen": "0.0.0.0:50051", "gateway_jwt": jwt, "tls": tls, "ocsf": {}},
                    {"listen": "127.0.0.1:50051", "ocsf": {"token_file": "ocsf.token"}},
                    {"listen": "127.0.0.1:50051", "ocsf": {"token_file": ""}},
                    {"listen": "127.0.0.1:50051", "ocsf": {"endpoint": "x"}},
                    {"listen": "127.0.0.1:50051", "ocsf": True}):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.load(**bad)
        cfg = self.load(listen="0.0.0.0:50051", gateway_jwt=jwt, tls=tls, ocsf={"token_file": "ocsf.token"})
        self.assertTrue(os.path.isabs(cfg["ocsf"]["token_file"]))
        self.assertEqual(self.load(listen="0.0.0.0:50051", allow_unauthenticated=True, ocsf={})["ocsf"], {})


if __name__ == "__main__":
    unittest.main()
