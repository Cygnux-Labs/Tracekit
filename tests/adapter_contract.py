"""Adapter contract suite (04-design §7.3, decision S6): what every framework adapter must do with the v2 signer.

An adapter plugs in through a driver; subclass `Contract` with a `driver(case, signer_path)` and mix in `OnFake` or
`OnReal` (tests/test_contract_langchain.py). Each case runs against FakeSigner and the real signer, both served in
this process on a Unix socket (loopback TCP where there are none), so the adapter and its resumed processes reach them as they would a deployed signer.
The policy: `pay` asks (R-PAY, with a T2 executor), `wipe` is denied (R-WIPE), everything else is allowed; a
`<prefix>/` before the name (MCP's `mcp:<server>/pay`) is ignored.

A driver has:
- `run()`: {"run_id", "run_token"} of the run its calls went to;
- `call(tool, args, tcid="call-1", mode="sync")`: one tool call with that id through the framework, until it ends or
  pauses for an approval; returns an outcome
  {"ran": tool names executed, "seen": the tool result the model got, "is_error": it got it as an error,
   "continued": the model got its next turn, "raised": "Type: message" the framework got from the tool,
   "approval_id": set when the call paused};
- `resume(hint=HINT, replay=False)`: resume the paused call (with `hint` as the approval id the framework carries;
  None for none; `replay` from the snapshot saved at the pause) and return its outcome;
- `tamper(args=None, tool_call_id=None)`: edit the paused call in the framework's saved state;
- `retry(tool, args)`: one call whose first execution raises and which the framework retries under the same id;
- `modes`: the call modes beyond "sync" (async, streaming);
- `SKIP`: {capability: why it does not apply} for "retry", "saved_state" (resume in a new process, S6 B-G),
  "modes" and "l1" (a state wrapper that commits the framework's saved state).
"""
import os
import shutil
import socket
import tempfile
import threading

from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer.service import SignerService, _dev_token
from tracekit.testing import FakeSigner
from tracekit.transport import answering_hello, hello

PAY = {"to": "acct-42", "cents": 1500}
HINT = object()   # resume with the approval id the framework saved at the pause
RAN = []          # tool names executed in this process


def echo(text: str) -> str:
    """Echo the text."""
    RAN.append("echo")
    return text


def pay(to: str, cents: int) -> str:
    """Send money."""
    RAN.append("pay")
    return f"paid {cents}"


def wipe(path: str) -> str:
    """Delete a path."""
    RAN.append("wipe")
    return "wiped"


def fail(why: str) -> str:
    """Always raises."""
    RAN.append("fail")
    raise ValueError(why)


TOOLS = [echo, pay, wipe, fail]


def _rule(tool, args):
    return {"pay": ("ask", ["R-PAY"]), "wipe": ("deny", ["R-WIPE"])}.get(tool.rsplit("/", 1)[-1], ("allow", []))


def tmpdir(case):
    d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: macOS caps socket paths at 104 bytes
    case.addCleanup(shutil.rmtree, d, True)
    return d


def _serve(case, handle_frame):
    """The signer's address: a Unix socket, or tcp://127.0.0.1:port with its token in $TRACEKIT_SIGNER_TOKEN."""
    d, handle = tmpdir(case), answering_hello(handle_frame, hello())
    if hasattr(socket, "AF_UNIX"):
        from tracekit.transport.unix import UnixServer
        path = os.path.join(d, "s.sock")
        srv = UnixServer(path, handle)
    else:
        from tracekit.transport.tcp_dev import TcpDevServer
        token = _dev_token()
        srv = TcpDevServer(os.path.join(d, "endpoint.json"), token, handle)
        path = f"tcp://127.0.0.1:{srv.server_address[1]}"
        os.environ["TRACEKIT_SIGNER_TOKEN"] = token.secret   # tests/conftest.py restores the environment
    threading.Thread(target=srv.serve_forever, args=(0.2,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return path


class OnFake:
    def serve_signer(self):
        signer, mutex = FakeSigner(_rule, t2=["R-PAY"]), threading.Lock()

        def handle(identity, frame):
            with mutex:
                return getattr(signer, frame.pop("method"))(frame)
        return _serve(self, handle)

    def events(self, run):
        return self.client.read({**run, "limit": 1000})["events"]


class OnReal:
    def serve_signer(self):
        self.service = s = SignerService(tmpdir(self), policy=Engine({"ask": [{"id": "R-PAY", "tool": "^(.*/)?pay$", "pattern": "^",
                                                                               "approval": {"executor": "t2"}}],
                                                       "deny": [{"id": "R-WIPE", "tool": "^(.*/)?wipe$", "pattern": "^"}]}))
        self.addCleanup(s.close)
        return _serve(self, s.handle_frame)

    def events(self, run):
        """The signed records: `read` leaves out the top-level fields, `attempt` among them."""
        return [r["event"] for r in self.service.log.storage.iter_run("default", run["run_id"])]


def _norm(e):
    """The fields the suite checks, from either signer's event shape."""
    d = e["data"]
    return {"type": e["type"], "decision": d.get("decision"), "decision_id": d.get("decision_id"),
            "tool_call_id": d.get("tool_call_id", d.get("tool_use_id")), "attempt": d.get("attempt", e.get("attempt", 0)),
            "ok": d.get("ok", d.get("status") == "ok")}


class Contract:
    def driver(self, case, signer_path):
        raise NotImplementedError

    def setUp(self):
        RAN.clear()
        path = self.serve_signer()
        self.client = Client(path)
        self.addCleanup(self.client.close)
        self.d = self.driver(self, path)

    def needs(self, capability):
        if capability in self.d.SKIP:
            self.skipTest(self.d.SKIP[capability])

    def recorded(self, typ):
        return [_norm(e) for e in self.events(self.d.run()) if e["type"] == typ]

    def approve(self, aid, decision="approve"):
        self.client.approval_decide({"approval_id": aid, "decision": decision})

    def paused(self, tcid="call-1"):
        out = self.d.call("pay", PAY, tcid)
        self.assertEqual(out["ran"], [])
        self.assertTrue(out["approval_id"], out)
        return out["approval_id"]

    def refused(self, out, code):
        self.assertEqual(out["ran"], [])
        self.assertTrue(out["is_error"], out)
        self.assertIn(code, out["seen"])

    def assert_bound(self, n=1):
        """Each executed call completed once, against its own decision (the signer refuses a `complete` whose args
        digest differs from the decided one, so a recorded result is bound to both)."""
        decisions = {d["decision_id"]: d for d in self.recorded("policy.decision")}
        results = self.recorded("tool.result")
        self.assertEqual(len(results), n, results)
        for r in results:
            d = decisions[r["decision_id"]]
            self.assertEqual((r["tool_call_id"], r["attempt"]), (d["tool_call_id"], d["attempt"]))
        return results

    # --- decisions ---

    def test_allow_executes_once_and_completes_bound_to_the_decision(self):
        out = self.d.call("echo", {"text": "hi"})
        self.assertEqual((out["ran"], out["seen"], out["is_error"], out["raised"]), (["echo"], "hi", False, None))
        [d] = self.recorded("policy.decision")
        self.assertEqual(d["decision"], "allow")
        [r] = self.assert_bound()
        self.assertEqual((r["decision_id"], r["ok"]), (d["decision_id"], True))

    def test_deny_returns_an_error_result_and_the_run_continues(self):
        out = self.d.call("wipe", {"path": "/"})
        self.refused(out, "R-WIPE")
        self.assertTrue(out["continued"])
        self.assertEqual(self.recorded("tool.result"), [])
        self.assertEqual(self.d.call("echo", {"text": "next"}, "call-2")["ran"], ["echo"])

    def test_tool_exception_reaches_the_framework_and_completes_as_error(self):
        out = self.d.call("fail", {"why": "boom"})
        self.assertEqual((out["ran"], out["raised"]), (["fail"], "ValueError: boom"))
        [r] = self.assert_bound()
        self.assertFalse(r["ok"])

    def test_retry_of_the_same_call_is_a_new_decision(self):
        self.needs("retry")
        out = self.d.retry("echo", {"text": "again"})
        self.assertEqual(out["seen"], "again")
        ds = self.recorded("policy.decision")
        self.assertEqual([(d["tool_call_id"], d["attempt"]) for d in ds], [("call-1", 0), ("call-1", 1)])
        self.assertNotEqual(ds[0]["decision_id"], ds[1]["decision_id"])
        self.assertEqual([r["ok"] for r in self.assert_bound(2)], [False, True])

    # --- approvals (S6 scenarios A-G) ---

    def test_a_approved_call_executes_once(self):
        self.approve(self.paused())
        out = self.d.resume()
        self.assertEqual((out["ran"], out["seen"], out["is_error"]), (["pay"], "paid 1500", False))
        self.assertEqual(len(self.recorded("approval.consumed")), 1)
        self.assert_bound()

    def test_rejected_call_does_not_execute(self):
        self.approve(self.paused(), "reject")
        out = self.d.resume()
        self.assertEqual(out["ran"], [])
        self.assertTrue(out["is_error"])
        self.assertIn("REJECTED", out["seen"].upper())
        self.assertEqual(self.recorded("tool.result"), [])

    def test_b_replayed_snapshot_is_refused(self):
        self.needs("saved_state")
        self.approve(self.paused())
        self.assertEqual(self.d.resume()["ran"], ["pay"])
        self.refused(self.d.resume(replay=True), "TK-APPROVAL-CONSUMED")

    def test_c_args_edited_in_saved_state_are_refused(self):
        self.needs("saved_state")
        self.approve(self.paused())
        self.d.tamper(args=dict(PAY, cents=1500000))
        self.refused(self.d.resume(), "TK-APPROVAL-MISMATCH")
        self.assertEqual(len(self.recorded("approval.binding_mismatch")), 1)

    def test_d_another_runs_approval_id_is_refused(self):
        self.needs("saved_state")
        self.paused()
        r = self.client.register_run({"agent": {"name": "other"}})
        other = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.client.decide({**other, "tool_call_id": "call-1", "tool": "pay", "args_source": "parsed", "args": PAY})
        aid = self.client.approval_request({**other, "tool_call_id": "call-1"})["approval_id"]
        self.approve(aid)
        self.refused(self.d.resume(hint=aid), "TK-APPROVAL-UNBOUND")

    def test_e_resume_without_a_human_approval_is_refused(self):
        self.needs("saved_state")
        self.paused()
        self.refused(self.d.resume(), "TK-APPROVAL-REQUESTED")
        self.refused(self.d.resume(hint=None), "TK-APPROVAL-REQUESTED")

    def test_f_missing_hint_is_resolved_by_the_signer(self):
        self.needs("saved_state")
        self.approve(self.paused())
        self.assertEqual(self.d.resume(hint=None)["ran"], ["pay"])

    def test_g_rewritten_call_id_is_refused(self):
        self.needs("saved_state")
        self.approve(self.paused())
        self.d.tamper(args=dict(PAY, cents=9), tool_call_id="call-x")
        self.refused(self.d.resume(), "TK-APPROVAL-UNBOUND")

    def test_t2_executor_gets_only_the_approved_args(self):
        self.needs("saved_state")   # an adapter that holds the call consumes the approval itself the moment it lands
        aid = self.paused()
        self.approve(aid)
        a = self.client.approval_get({"approval_id": aid})

        def execute(args):   # a T2 gateway: consumes, then runs only what the signer returns
            return self.client.approval_consume({**self.d.run(), "tool_call_id": a["tool_call_id"], "attempt": a["attempt"],
                                                 "tool": "pay", "args_source": "parsed", "args": args})
        self.assertEqual(execute(dict(PAY, cents=1500000))["rule_ids"], ["TK-APPROVAL-MISMATCH"])
        out = execute(PAY)
        self.assertEqual((out["ok"], out["args"]), (True, PAY))
        self.refused(self.d.resume(), "TK-APPROVAL-CONSUMED")   # the agent's own resume runs nothing

    # --- modes and L1 ---

    def test_async_and_streaming(self):
        self.needs("modes")
        for i, mode in enumerate(self.d.modes):
            out = self.d.call("echo", {"text": mode}, f"ok-{i}", mode)
            self.assertEqual((out["ran"], out["seen"]), (["echo"], mode), mode)
            self.refused(self.d.call("wipe", {"path": "/"}, f"no-{i}", mode), "R-WIPE")
            self.assertEqual(self.d.call("fail", {"why": mode}, f"err-{i}", mode)["raised"], f"ValueError: {mode}")
        self.assertEqual([r["ok"] for r in self.assert_bound(2 * len(self.d.modes))], [True, False] * len(self.d.modes))

    def test_l1_state_wrapper_commits_saved_state(self):
        self.needs("l1")
        self.d.call("echo", {"text": "hi"})
        self.assertTrue(self.recorded("state.write"))

    def test_l1_saved_state_edited_between_pause_and_resume_is_a_state_tamper(self):
        self.needs("l1")
        self.needs("saved_state")
        if isinstance(self, OnFake):
            self.skipTest("FakeSigner does not check prev_digest")

        def gaps():
            return [e["data"]["kind"] for e in self.events(self.d.run()) if e["type"] == "capture.gap"]
        self.approve(self.paused("call-0"))
        self.assertEqual(self.d.resume()["ran"], ["pay"])
        self.assertEqual(gaps(), [])   # resumed in a new process from the state as saved
        self.approve(self.paused())
        self.d.tamper(args=dict(PAY, cents=1500000))
        self.refused(self.d.resume(), "TK-APPROVAL-MISMATCH")
        self.assertEqual(gaps(), ["state_tamper"])
