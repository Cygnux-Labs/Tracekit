"""The NVIDIA OpenShell supervisor middleware (tracekit/openshell.py): a grpcio client plays OpenShell's supervisor and
gateway against the middleware, which decides and records through a real signer on a Unix socket. Messages are built
here field by field from OpenShell's proto/supervisor_middleware.proto, apart from the module's codec."""
import importlib.util
import json
import os
import socket
import threading
import time
import unittest
import uuid

from adapter_contract import tmpdir
from test_signer_service import ME
from tracekit import openshell
from tracekit.bundle_v2 import export
from tracekit.otlp_wire import _fields, varint
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
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


def request(host, body=b"", request_id=None, method="POST", phase=1, sandbox=SANDBOX):
    """HttpRequestEvaluation."""
    return pb([(1, phase), (2, context(request_id or uuid.uuid4().hex, sandbox)),
               (4, [(1, "https"), (2, host), (3, 443), (4, method), (5, "/v1/send")]),
               (5, [(1, "content-type"), (2, "application/json")]), (6, body), (7, "tracekit")])


def preflight(request_id, status=200, modes=(1, 3)):
    """HttpResponseEvent preflight (permitted_body_modes: 1 HEADERS_ONLY, 3 STREAM_BYTES)."""
    return pb([(1, [(1, context(request_id)), (2, [(1, "https"), (2, "h"), (4, "GET")]), (3, status),
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
        binary = openshell.args_of(openshell.decode(request("h", b"\xff\x00"), openshell._REQUEST))["body"]
        self.assertEqual(binary["size"], 2)
        self.assertRegex(binary["digest"], "^sha256:[0-9a-f]{64}$")

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


@unittest.skipUnless(HAVE_GRPC, "needs grpcio: pip install 'tracekit-ai[grpc]'")
@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "serves the signer on a Unix socket")
class Supervisor(unittest.TestCase):
    def setUp(self):
        import grpc
        self.grpc = grpc
        self.s = SignerService(tmpdir(self), policy=POLICY, gateways=["uid:*"], authorize={"openshell:*": PER_CALL})
        self.addCleanup(self.s.close)
        path, self.signer = serve_signer(self, self.s)
        self.client = Client(path, timeout=5)
        self.addCleanup(self.client.close)
        srv, port = openshell.serve({"listen": "127.0.0.1:0", "signer": path}, self.client)
        self.addCleanup(srv.stop, None)
        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        self.addCleanup(channel.close)
        self.rpc = {m: channel.unary_unary(f"/{openshell.SERVICE}/{m}")
                    for m in ("Describe", "ValidateConfig", "EvaluateHttpRequest")}
        self.response = channel.stream_stream(f"/{openshell.RESPONSES}/Evaluate")

    def evaluate(self, body):
        """(decision, reason_code) of the middleware's HttpRequestResult."""
        r = fields(self.rpc["EvaluateHttpRequest"](body, timeout=20))
        return r.get(1), bytes(r.get(8, b"")).decode()

    def respond(self, *events):
        return [fields(r) for r in self.response(iter(events), timeout=20)]

    def runs(self):
        return [k[1] for k in self.s.log.runs if k[1].startswith(f"openshell-{SANDBOX}-")]

    def events(self, run_id, *types):
        return [r["event"] for r in self.s.log.storage.iter_run("default", run_id) if r["event"]["type"] in types]

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


if __name__ == "__main__":
    unittest.main()
