"""agentgateway's ext_mcp processor (tracekit/ext_mcp.py): a grpcio client plays agentgateway, its messages built by
protobuf from ext_mcp.proto's definitions (not by the processor's hand decoding); the processor decides through an
in-process v2 signer as source gateway (tier T2)."""
import json
import time
import unittest

from adapter_contract import tmpdir
from test_executor import InProcess
from test_gateway import AGENT
from test_signer_service import records
from tracekit import ext_mcp
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

try:
    import grpc
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, struct_pb2
except ImportError:   # optional: the grpc extra and the OTLP test dependencies install them
    HAVE = False
else:
    HAVE = True

AGW = CallerIdentity("mtls", "spiffe://acme/agw", True)
POLICY = Engine({"deny": [{"id": "R-WIPE", "tool": "^mcp:up/wipe$", "pattern": "^"}],
                 "ask": [{"id": "R-PAY", "tool": "^mcp:up/pay$", "pattern": "^"}]})


def messages():
    """The messages of agentgateway's crates/protos/proto/ext_mcp.proto, as protobuf classes."""
    F = descriptor_pb2.FieldDescriptorProto
    f = descriptor_pb2.FileDescriptorProto(name="ext_mcp.proto", package="agentgateway.dev.ext_mcp", syntax="proto3",
                                           dependency=["google/protobuf/struct.proto"])
    STRUCT = ".google.protobuf.Struct"

    def msg(name, *fields, oneof=()):
        m = f.message_type.add(name=name)
        if oneof:
            m.oneof_decl.add(name="result")
        for number, field, typ, ref, repeated in fields:
            fd = m.field.add(name=field, number=number, type=typ,
                             label=F.LABEL_REPEATED if repeated else F.LABEL_OPTIONAL)
            if ref:
                fd.type_name = ref
            if number in oneof:
                fd.oneof_index = 0
        return m
    S, B, M = F.TYPE_STRING, F.TYPE_BYTES, F.TYPE_MESSAGE
    own = ".agentgateway.dev.ext_mcp."
    msg("McpRequest", (1, "service_names", S, "", True), (2, "method", S, "", False),
        (3, "metadata_context", M, STRUCT, False), (4, "mcp_request", B, "", False), (5, "headers", M, own + "McpHeader", True))
    msg("McpResponse", (1, "service_names", S, "", True), (2, "method", S, "", False),
        (3, "metadata_context", M, STRUCT, False), (4, "mcp_response", B, "", False))
    result = ((1, "pass", M, own + "Pass", False), (2, "mutated", B, "", False), (3, "error", M, own + "AuthorizationError", False))
    msg("McpRequestResult", *result, (4, "header_mutation", M, own + "HeaderMutation", False),
        (5, "metadata", M, STRUCT, False), oneof=(1, 2, 3))
    msg("McpResponseResult", *result, oneof=(1, 2, 3))
    msg("HeaderMutation", (1, "set", M, own + "McpHeader", True), (2, "remove", S, "", True))
    msg("McpHeader", (1, "key", S, "", False), (2, "value", B, "", False))
    msg("Pass")
    err = msg("AuthorizationError", (1, "code", F.TYPE_ENUM, own + "AuthorizationError.Code", False),
              (2, "reason", S, "", False), (3, "mcp_error", B, "", False))
    err.enum_type.add(name="Code", value=[descriptor_pb2.EnumValueDescriptorProto(name=n, number=i) for i, n in enumerate(
        ("UNKNOWN", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "INVALID"))])
    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(struct_pb2.DESCRIPTOR.serialized_pb)
    pool.Add(f)
    return {m.name: message_factory.GetMessageClass(pool.FindMessageTypeByName("agentgateway.dev.ext_mcp." + m.name))
            for m in f.message_type}


@unittest.skipUnless(HAVE, "grpcio or protobuf not installed")
class ExtMcp(unittest.TestCase):
    def setUp(self):
        self.pb = messages()
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/agw": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume"]})
        self.closed = False
        self.addCleanup(self.close)
        self.signer = InProcess(self.s, AGW)
        srv, port = ext_mcp.serve("127.0.0.1:0", self.signer)
        self.addCleanup(srv.stop, None)
        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        self.addCleanup(channel.close)
        self.rpc = {n: channel.unary_unary(f"/{ext_mcp.SERVICE}/{n}") for n in ("CheckRequest", "CheckResponse")}
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run_id, self.token = out["run_id"], out["run_token"]
        self.run = f"{self.run_id}.{self.token}"

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def events(self):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run_id]

    def gaps_at_run_end(self):
        """Close the run, end its grace window and the gateways' wait: (kind, tool_call_id) of its capture gaps."""
        self.s.grace_s, self.s.gateway_wait_s = 0, 30
        self.s.call(AGENT, "close_run", {"request_id": "cl", "run_id": self.run_id, "run_token": self.token})
        self.s.sweep(now=self.s.log.runs[("default", self.run_id)]["closing_at"] + 31)
        return [(e["data"]["kind"], e.get("tool_call_id")) for e in self.events() if e["type"] == "capture.gap"]

    def check(self, req):
        return self.pb["McpRequestResult"].FromString(self.rpc["CheckRequest"](req.SerializeToString(), timeout=10))

    def call(self, tool, args, run=True, caller="token:http"):
        """CheckRequest as agentgateway sends it for a tools/call of server `up` from the agent of self.run."""
        req = self.pb["McpRequest"](service_names=["up"], method="tools/call",
                                    mcp_request=json.dumps({"name": tool, "arguments": args}).encode())
        req.headers.add(key=":authority", value=b"localhost:3000")
        if run:
            req.headers.add(key="x-tracekit-run", value=self.run.encode())
        if caller:
            req.metadata_context.fields["caller"].string_value = caller
        return self.check(req)

    def respond(self, tcid, result):
        """CheckResponse with the metadata agentgateway evaluates again: `tracekit_call` from the request's result."""
        res = self.pb["McpResponse"](service_names=["up"], method="tools/call", mcp_response=json.dumps(result).encode())
        res.metadata_context.fields["caller"].string_value = "token:http"
        res.metadata_context.fields[ext_mcp.CALL].string_value = tcid
        out = self.pb["McpResponseResult"].FromString(self.rpc["CheckResponse"](res.SerializeToString(), timeout=10))
        return out.WhichOneof("result")

    def test_an_allowed_call_passes_and_its_result_completes_it_t2(self):
        out = self.call("echo", {"text": "hi"})
        self.assertEqual(out.WhichOneof("result"), "pass")
        self.assertEqual(list(out.header_mutation.remove), ["x-tracekit-run"])   # the run token stays at agentgateway
        tcid = out.metadata.fields[ext_mcp.CALL].string_value
        self.assertEqual(self.respond(tcid, {"content": [{"type": "text", "text": "hi"}]}), "pass")
        failed = self.call("echo", {"text": "again"}).metadata.fields[ext_mcp.CALL].string_value
        self.assertEqual(self.respond(failed, {"content": [], "isError": True}), "pass")
        self.assertEqual(self.respond("agw-none", {"content": []}), "pass")   # no call it passed: not recorded
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["tool_call_id"]) for e in evs],
                         [("policy.decision", "gateway", "T2", tcid), ("tool.result", "gateway", "T2", tcid),
                          ("policy.decision", "gateway", "T2", failed), ("tool.result", "gateway", "T2", failed)])
        self.assertEqual((evs[0]["data"]["tool"], evs[0]["data"]["via"], evs[0]["data"]["caller"]),
                         ("mcp:up/echo", "mtls:spiffe://acme/agw", "token:http"))
        self.assertEqual([evs[1]["data"]["ok"], evs[3]["data"]["ok"]], [True, False])

    def test_a_denied_call_is_refused(self):
        out = self.call("wipe", {"path": "/"})
        self.assertEqual((out.WhichOneof("result"), out.error.code), ("error", 1))   # PERMISSION_DENIED
        self.assertIn("R-WIPE", out.error.reason)
        self.assertEqual(len(out.metadata.fields), 0)

    def test_an_ask_is_refused_then_an_approved_retry_with_the_same_arguments_passes(self):
        pay = {"to": "acct-42", "cents": 1500}
        t = time.monotonic()
        out = self.call("pay", pay)
        self.assertLess(time.monotonic() - t, 2)   # refused at once: no worker waits on a person, holding up others
        self.assertEqual(out.WhichOneof("result"), "error")
        self.assertIn("R-PAY: approval requested; make the same call again once a person approves it", out.error.reason)
        [a] = self.s.call(AGENT, "approval_list", {"run_id": self.run_id, "state": "requested"})["approvals"]
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": a["approval_id"], "decision": "approve"})
        other = self.call("pay", {**pay, "cents": 1})   # not the approved arguments: asked about again, still held
        self.assertIn("R-PAY: approval requested", other.error.reason)
        out = self.call("pay", pay)
        self.assertEqual(out.WhichOneof("result"), "pass")
        self.assertEqual(out.metadata.fields[ext_mcp.CALL].string_value, a["tool_call_id"])   # the call approved
        self.assertEqual(self.respond(a["tool_call_id"], {"content": []}), "pass")
        self.assertEqual(self.gaps_at_run_end(), [])   # completed with the approved arguments; the other ask never ran
        types = [(e["type"], e["source"]) for e in self.events()]
        for t in [("approval.request", "gateway"), ("approval.consumed", "signer"), ("tool.result", "gateway")]:
            self.assertIn(t, types)

    def test_a_result_past_grpcs_default_4_mib_is_recorded(self):
        tcid = self.call("echo", {"text": "big"}).metadata.fields[ext_mcp.CALL].string_value
        self.assertEqual(self.respond(tcid, {"content": [{"type": "text", "text": "x" * (5 << 20)}]}), "pass")
        self.assertEqual(self.gaps_at_run_end(), [])   # completed: no held_call_unresolved

    def test_a_passed_call_whose_result_never_comes_ends_its_run_with_a_gap(self):
        # agentgateway skips the response hook for a JSON-RPC error
        tcid = self.call("echo", {"text": "hi"}).metadata.fields[ext_mcp.CALL].string_value
        self.assertEqual(self.gaps_at_run_end(), [("held_call_unresolved", tcid)])

    def test_a_result_nested_deeper_than_json_reads_completes_the_call_as_an_error(self):
        tcid = self.call("echo", {"text": "hi"}).metadata.fields[ext_mcp.CALL].string_value
        res = self.pb["McpResponse"](service_names=["up"], method="tools/call",
                                     mcp_response=b"[" * 200_000 + b"]" * 200_000)
        res.metadata_context.fields[ext_mcp.CALL].string_value = tcid
        out = self.pb["McpResponseResult"].FromString(self.rpc["CheckResponse"](res.SerializeToString(), timeout=10))
        self.assertEqual(out.WhichOneof("result"), "pass")
        self.assertEqual(self.gaps_at_run_end(), [])
        [done] = [e for e in self.events() if e["type"] == "tool.result"]
        self.assertEqual((done["tool_call_id"], done["data"]["ok"]), (tcid, False))

    def test_the_signer_unreachable_fails_closed(self):
        self.signer.down = True
        out = self.call("echo", {"text": "hi"})
        self.assertEqual(out.WhichOneof("result"), "error")
        self.assertIn("the signer is unreachable", out.error.reason)

    def test_no_run_no_caller_or_a_message_that_does_not_parse_is_refused(self):
        for out in (self.call("echo", {}, run=False), self.call("echo", {}, caller=None)):
            self.assertIn("no run or caller", out.error.reason)
        for req in (self.pb["McpRequest"](service_names=["up"], method="tools/call", mcp_request=b"{not json"),
                    self.pb["McpRequest"](service_names=["up", "down"], method="tools/call", mcp_request=b'{"name": "x"}')):
            self.assertIn("doesn't parse", self.check(req).error.reason)
        out = self.pb["McpRequestResult"].FromString(self.rpc["CheckRequest"](b"\x0a\xff", timeout=10))
        self.assertIn("doesn't parse", out.error.reason)
        listing = self.pb["McpRequest"](service_names=["up", "down"], method="tools/list")
        self.assertEqual(self.check(listing).WhichOneof("result"), "pass")   # other methods: not decided
