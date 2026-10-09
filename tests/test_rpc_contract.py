"""Conformance suite for the signer RPC contract (tracekit/signer/rpc_schema.py).

Any SignerAPI implementation must pass `SignerContract`: subclass it with a `make_signer()` whose policy answers
`ask` for the tool "pay" and `allow` for everything else. It runs here against tracekit.testing.FakeSigner.
"""
import unittest

from tracekit.format.canon import event_hash
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import ERROR, REQUESTS, RESPONSES, RPCError, SignerAPI
from tracekit.testing import FakeSigner


def walk(schema, path="$"):
    yield path, schema
    for k, v in schema.items():
        if isinstance(v, dict):
            if k == "properties":
                for name, sub in v.items():
                    yield from walk(sub, f"{path}.{name}")
            else:
                yield from walk(v, f"{path}/{k}")


class TestSchemas(unittest.TestCase):
    def test_every_string_and_array_is_bounded(self):
        schemas = [(f"request {m}", s) for m, s in REQUESTS.items()] + [(f"response {m}", s) for m, s in RESPONSES.items()]
        for name, schema in schemas + [("error", ERROR)]:
            for path, s in walk(schema):
                types = s.get("type") if isinstance(s.get("type"), list) else [s.get("type")]
                if "string" in types:
                    self.assertIn("maxLength", s, f"{name} {path}")
                if "array" in types:
                    self.assertIn("maxItems", s, f"{name} {path}")
                if name.startswith("request") and s.get("type") == "object":   # clients can't add fields the signer would trust
                    self.assertIs(s.get("additionalProperties"), False, f"{name} {path}")

    def test_same_methods_everywhere(self):
        methods = {m for m in vars(SignerAPI) if not m.startswith("_")}
        self.assertEqual(methods, set(REQUESTS))
        self.assertEqual(methods, set(RESPONSES))

    def test_ids_reject_a_trailing_newline(self):
        self.assertTrue(rpc_schema.validate(rpc_schema.ID, "run-1\n"))
        self.assertEqual(rpc_schema.validate(rpc_schema.ID, "run-1"), [])


class SignerContract:
    def make_signer(self) -> SignerAPI:
        raise NotImplementedError

    def setUp(self):
        self.signer = self.make_signer()
        self.n = 0

    def call(self, method, req):
        """Call `method`; the response (or the refusal's wire form) must match the contract."""
        try:
            out = getattr(self.signer, method)(req)
        except RPCError as e:
            self.assertEqual(rpc_schema.validate(ERROR, e.wire()), [], e)
            raise
        self.assertEqual(rpc_schema.validate(RESPONSES[method], out), [], out)
        return out

    def refused(self, code, method, req):
        with self.assertRaises(RPCError) as cm:
            self.call(method, req)
        self.assertEqual(cm.exception.code, code, cm.exception)

    def rid(self):
        self.n += 1
        return f"req-{self.n}"

    def register(self, **kw):
        req = {"request_id": self.rid(), "agent": {"name": "test-agent"}, **kw}
        self.assertEqual(rpc_schema.validate(REQUESTS["register_run"], req), [])
        out = self.call("register_run", req)
        self.run_id, self.token, self.seq = out["run_id"], out["run_token"], 0
        return out

    def ev(self, **kw):
        """Fields of the next event call on stream s1 of the current run."""
        req = {"request_id": self.rid(), "run_id": self.run_id, "run_token": self.token, "stream": "s1",
               "client_seq": self.seq, **kw}
        self.seq += 1
        return req

    def decide(self, tool="read_file", args=None, tcid="tc-1", args_source="parsed", **kw):
        req = self.ev(tool_call_id=tcid, tool=tool, args_source=args_source,
                      args={"path": "a.txt"} if args is None else args, **kw)
        return req, self.call("decide", req)

    def read(self):
        return self.call("read", {"run_id": self.run_id, "run_token": self.token, "limit": 1000})["events"]

    def types(self):
        return [e["type"] for e in self.read()]

    def run_req(self, **kw):
        return {"request_id": self.rid(), "run_id": self.run_id, "run_token": self.token, **kw}

    # --- lifecycle ---

    def test_status(self):
        out = self.call("status", {})
        self.assertEqual(out["rpc_version"], rpc_schema.RPC_VERSION)
        self.call("checkpoint_nudge", {})

    def test_run_lifecycle(self):
        reg = self.register()
        self.assertTrue(reg["tenant_attested"])
        _, d = self.decide()
        self.assertEqual((d["decision"], d["rule_ids"]), ("allow", []))
        self.call("complete", self.ev(tool_call_id="tc-1", status="ok", result={"bytes": 3}))
        self.call("state_write", self.ev(key="memory/notes", value_digest="sha256:" + "0" * 64))
        self.call("model_event", self.ev(provider="openai", model="gpt", phase="response",
                                         usage={"input_tokens": 10, "output_tokens": 2}))
        self.call("close_run", self.run_req(reason="done"))
        events = self.read()
        self.assertEqual([e["run_seq"] for e in events], list(range(len(events))))
        for e in events:
            self.assertEqual(e["event_hash"], event_hash({k: e[k] for k in ("run_seq", "type", "data")}))
        self.assertEqual(events[0]["type"], "run.registered")
        self.assertEqual(events[-1]["type"], "run.closing")
        self.refused("run_closed", "decide", self.ev(tool_call_id="tc-2", tool="t", args_source="parsed", args={}))
        self.refused("run_closed", "close_run", self.run_req())

    def test_app_asserted_tenant_is_not_attested(self):
        out = self.register(tenant="acme", principal="user@example.com")
        self.assertEqual((out["tenant"], out["tenant_attested"], out["principal_attested"]), ("acme", False, False))

    def test_read_pages(self):
        self.register()
        for i in range(3):
            self.decide(tcid=f"tc-{i}")
        page = self.call("read", {"run_id": self.run_id, "run_token": self.token, "from_seq": 1, "limit": 2})
        self.assertEqual([e["run_seq"] for e in page["events"]], [1, 2])
        self.assertEqual(page["next_seq"], 3)

    # --- idempotency and counters ---

    def test_retry_returns_the_original_response(self):
        reg = {"request_id": "reg-1", "agent": {"name": "a"}}
        first = self.call("register_run", dict(reg))
        self.assertEqual(self.call("register_run", dict(reg)), first)
        self.run_id, self.token, self.seq = first["run_id"], first["run_token"], 0
        req, first = self.decide()
        self.assertEqual(self.call("decide", dict(req)), first)
        self.assertEqual(self.types().count("tool.decision"), 1)

    def test_request_id_reused_with_another_payload(self):
        self.register()
        req, _ = self.decide()
        self.refused("conflict", "decide", dict(req, args={"path": "b.txt"}))

    def test_client_seq_reused_under_a_new_request_id(self):
        self.register()
        req, _ = self.decide()
        self.refused("client_seq_reused", "decide", dict(req, request_id=self.rid()))

    def test_skipped_client_seq_is_a_signed_gap(self):
        self.register()
        self.decide()
        self.seq = 5
        self.decide(tcid="tc-2")
        gaps = [e for e in self.read() if e["type"] == "capture.gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["data"]["kind"], "client_counter_gap")

    def test_run_exists(self):
        self.register(run_id="run-x")
        self.refused("run_exists", "register_run", {"request_id": self.rid(), "run_id": "run-x", "agent": {"name": "a"}})

    # --- capability tokens ---

    def test_run_token_checks(self):
        self.register()
        own = self.run_id
        other = self.register()["run_token"]
        self.refused("run_token_invalid", "close_run", {"request_id": self.rid(), "run_id": own, "run_token": other})
        self.refused("run_token_invalid", "read", {"run_id": own, "run_token": "forged"})
        self.refused("unknown_run", "read", {"run_id": "no-such-run", "run_token": other})

    # --- request validation ---

    def test_malformed_requests(self):
        self.register()
        good = self.ev(tool_call_id="tc-1", tool="t", args_source="parsed", args={})
        for bad in ({k: v for k, v in good.items() if k != "tool_call_id"},
                    dict(good, decision="allow"),                 # a field the client may not supply
                    dict(good, tool="x" * 257),
                    dict(good, client_seq=-1),
                    dict(good, client_seq=True),
                    dict(good, run_id="run 1"),
                    dict(good, args_source="raw", args={"a": 1}),  # raw args must be the model's string
                    dict(good, args_source="guessed")):
            self.refused("invalid_request", "decide", bad)
        self.refused("invalid_request", "register_run", {"request_id": self.rid(), "agent": {"name": "a"},
                                                         "tenant_attested": True})
        self.refused("invalid_request", "model_event", self.ev(provider="p", model="m", phase="response",
                                                               type="capture.gap"))
        self.refused("invalid_request", "status", [])

    def test_raw_args_are_strictly_parsed(self):
        self.register()
        _, d = self.decide(args_source="raw", args='{"path": "a.txt"}')
        self.assertEqual(d["decision"], "allow")
        for i, raw in enumerate(('{"a":1,"a":2}', '{"n": NaN}', '{"id": 9007199254740993}', '{"a": ',
                                 "[" * 990 + "]" * 990)):
            _, d = self.decide(tcid=f"bad-{i}", args_source="raw", args=raw)
            self.assertEqual((d["decision"], d["rule_ids"]), ("deny", ["TK-ARGS-INVALID"]), raw)
        for i, args in enumerate(({"id": 2 ** 60}, {"\ud800": 1})):
            _, d = self.decide(tcid=f"parsed-{i}", args=args)
            self.assertEqual(d["rule_ids"], ["TK-ARGS-INVALID"])

    # --- approvals ---

    def ask(self, args=None):
        self.register()
        _, d = self.decide(tool="pay", args=args or {"amount": 5})
        self.assertEqual(d["decision"], "ask")
        out = self.call("approval_request", self.run_req(tool_call_id="tc-1"))
        self.assertEqual(out["state"], "requested")
        return out["approval_id"]

    def wait(self, aid):
        return self.call("approval_wait", {"run_id": self.run_id, "run_token": self.token, "approval_id": aid,
                                           "timeout_ms": 0})["state"]

    def approve(self, aid, decision="approve"):
        return self.call("approval_decide", {"request_id": self.rid(), "approval_id": aid, "decision": decision})

    def test_approval_approved_then_consumed_once(self):
        aid = self.ask()
        self.assertEqual(self.wait(aid), "requested")
        _, d = self.decide(tool="pay", args={"amount": 5}, approval_id=aid)
        self.assertEqual(d["decision"], "ask")
        self.assertEqual(self.approve(aid)["state"], "approved")
        self.refused("approval_not_pending", "approval_decide", {"request_id": self.rid(), "approval_id": aid,
                                                                 "decision": "reject"})
        _, d = self.decide(tool="pay", args={"amount": 5}, approval_id=aid)
        self.assertEqual((d["decision"], d["rule_ids"]), ("allow", ["TK-APPROVED"]))
        self.assertEqual(self.wait(aid), "consumed")
        _, d = self.decide(tool="pay", args={"amount": 5}, approval_id=aid)
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(self.types().count("approval.consumed"), 1)

    def test_approval_binds_the_arguments(self):
        aid = self.ask()
        self.approve(aid)
        _, d = self.decide(tool="pay", args={"amount": 5000}, approval_id=aid)
        self.assertEqual((d["decision"], d["rule_ids"]), ("deny", ["TK-APPROVAL-MISMATCH"]))
        _, d = self.decide(tool="pay", args={"amount": 5}, tcid="tc-other", approval_id=aid)
        self.assertEqual(d["decision"], "deny")

    def test_rejected_approval_denies(self):
        aid = self.ask()
        self.assertEqual(self.approve(aid, "reject")["state"], "rejected")
        _, d = self.decide(tool="pay", args={"amount": 5}, approval_id=aid)
        self.assertEqual(d["decision"], "deny")

    def test_approval_refusals(self):
        self.register()
        self.decide()   # allowed, so nothing to approve
        self.refused("unknown_tool_call", "approval_request", self.run_req(tool_call_id="tc-1"))
        self.refused("unknown_tool_call", "approval_request", self.run_req(tool_call_id="never"))
        self.refused("unknown_tool_call", "complete", self.ev(tool_call_id="never", status="ok"))
        self.refused("unknown_approval", "approval_decide", {"request_id": self.rid(), "approval_id": "apr-x",
                                                             "decision": "approve"})
        self.refused("unknown_approval", "approval_wait", {"run_id": self.run_id, "run_token": self.token,
                                                           "approval_id": "apr-x"})

    def test_no_approval_after_close(self):
        aid = self.ask()
        self.call("close_run", self.run_req())
        self.refused("run_closed", "approval_decide", {"request_id": self.rid(), "approval_id": aid,
                                                       "decision": "approve"})
        self.assertEqual(self.types()[-1], "run.closing")


def _pay_asks(tool, args):
    return ("ask", ["TEST-PAY"]) if tool == "pay" else ("allow", [])


class TestFakeSigner(SignerContract, unittest.TestCase):
    def make_signer(self):
        return FakeSigner(rule=_pay_asks)

    def test_request_id_is_scoped_to_the_identity(self):
        reg = {"request_id": "reg-1", "agent": {"name": "a"}}
        first = self.call("register_run", dict(reg))
        self.signer.identity = "someone-else"
        self.assertNotEqual(self.call("register_run", dict(reg))["run_token"], first["run_token"])


if __name__ == "__main__":
    unittest.main()
