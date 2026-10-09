"""The adapter contract (tests/adapter_contract.py) for the MCP client adapter (tracekit/integrations/mcp.py), with an
in-process MCP server on the mcp package's in-memory transport (no network).

`call_tool` holds an `ask` while it waits for the approval, so the driver runs each call on a thread of its own and
returns once the approval is requested, as tests/test_contract_claude_code.py does.
"""
import asyncio
import threading
import time
import unittest

import adapter_contract as ac
from tracekit.sdk.client import Client

try:
    from mcp import Client as MCPClient
    from mcp import MCPError
    from mcp.server.mcpserver import MCPServer

    from tracekit.integrations.mcp import TracekitSession
except ImportError:   # optional: the dev extra installs it
    HAVE_MCP = False
else:
    HAVE_MCP = True
    SERVER = MCPServer("contract/mcp")   # recorded as mcp:contract_mcp/<tool>
    for f in ac.TOOLS:
        SERVER.tool()(f)

    @SERVER.tool()
    def broken() -> str:
        """Fails the request itself."""
        ac.RAN.append("broken")
        raise MCPError(-32603, "boom")


class Driver:
    SKIP = {"retry": "MCP has no tool call id: every call_tool is a call of its own",
            "saved_state": "call_tool holds the call while it waits for the approval: there is no saved state to "
                           "resume in a new process, replay or edit",
            "modes": "call_tool is async only, with no streaming path",
            "l1": "an MCP client keeps no agent state to commit"}

    def __init__(self, case, signer_path, **kw):
        self.signer, self.kw = Client(signer_path), kw
        case.addCleanup(self.signer.close)
        r = self.signer.register_run({"agent": {"name": "contract"}})
        self._run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def run(self):
        return self._run

    async def _call(self, tool, args):
        async with MCPClient(SERVER) as c:
            try:
                return await TracekitSession(c.session, self.signer, self._run, **self.kw).call_tool(tool, args)
            except Exception as e:   # raised here, not wrapped in the client's task group on the way out
                raised = e
        raise raised

    def call(self, tool, args, tcid="call-1", mode="sync"):
        ac.RAN.clear()
        self.out = {}

        def go():
            try:
                self.out["result"] = asyncio.run(self._call(tool, args))
            except Exception as e:
                self.out["raised"] = f"{type(e).__name__}: {e}"
        self.waiting = threading.Thread(target=go)
        self.waiting.start()
        while self.waiting.is_alive():
            aid = next((a["approval_id"] for a in self.signer.approval_list({"run_id": self._run["run_id"]})["approvals"]
                        if a["state"] == "requested"), None)
            if aid:
                return {"ran": [], "seen": None, "is_error": False, "continued": False, "raised": None,
                        "approval_id": aid}
            time.sleep(0.02)
        return self.finish()

    def resume(self, hint=ac.HINT, replay=False):
        self.waiting.join(60)
        return self.finish()

    def finish(self):
        r = self.out.get("result")
        return {"ran": list(ac.RAN), "seen": r and r.content[0].text, "is_error": bool(r and r.is_error),
                "continued": r is not None, "raised": self.out.get("raised"), "approval_id": None}


class MCPContract(ac.Contract):
    def test_tool_exception_reaches_the_framework_and_completes_as_error(self):
        """An MCP server reports a tool's exception as an isError result; an error of the request itself raises."""
        out = self.d.call("fail", {"why": "boom"})
        self.assertEqual((out["ran"], out["is_error"], out["raised"]), (["fail"], True, None))
        out = self.d.call("broken", {})
        self.assertEqual((out["ran"], out["raised"]), (["broken"], "MCPError: boom"))
        self.assertEqual([r["ok"] for r in self.assert_bound(2)], [False, False])

    def test_ask_is_refused_when_the_caller_cannot_wait_or_nobody_decides_in_time(self):
        self.d.kw["approval_wait_s"] = 0
        self.refused(self.d.call("pay", ac.PAY), "cannot wait")
        self.d.kw["approval_wait_s"] = 0.2
        self.paused()
        self.refused(self.d.resume(), "approval requested")


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class TestOnFakeSigner(MCPContract, ac.OnFake, unittest.TestCase):
    driver = Driver


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class TestOnRealSigner(MCPContract, ac.OnReal, unittest.TestCase):
    driver = Driver

    def test_recorded_as_an_mcp_tool(self):
        self.d.call("echo", {"text": "hi"})
        [e] = [e["data"] for e in self.events(self.d.run()) if e["type"] == "policy.decision"]
        self.assertEqual(e["tool"], "mcp:contract_mcp/echo")
        [gap] = [e["data"] for e in self.events(self.d.run()) if e["type"] == "capture.gap"]
        self.assertIn("class hint 'mcp'", gap["reason"])   # the contract policy has no tools map


class _StubSession:
    server_info = type("Info", (), {"name": "stub"})()

    def __init__(self):
        self.calls = 0

    async def call_tool(self, name, arguments=None):
        from mcp.types import CallToolResult, TextContent
        self.calls += 1
        return CallToolResult(content=[TextContent(type="text", text="done")], is_error=False)


class _Signer:
    """A signer that fails the way it is told: `decide` and `complete` raise `errors[method]` when set."""

    def __init__(self, **errors):
        self.errors = errors

    def __getattr__(self, method):
        def call(req):
            if method in self.errors:
                raise self.errors[method]
            return {"decide": {"decision": "allow", "decision_id": "dec-1", "rule_ids": []},
                    "approval_consume": {"ok": True, "rule_ids": []}}.get(method, {"run_seq": 0})
        return call


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class SignerFailures(unittest.TestCase):
    RUN = {"run_id": "r1", "run_token": "t"}

    def call(self, signer, **run):
        session = _StubSession()
        out = asyncio.run(TracekitSession(session, signer, {**self.RUN, **run}).call_tool("x", {}))
        return out, session.calls

    def test_unreachable_signer_refuses_unless_the_run_fails_open(self):
        from tracekit.sdk.client import SignerUnavailable
        out, calls = self.call(_Signer(decide=SignerUnavailable("down")))
        self.assertEqual((out.is_error, calls), (True, 0))   # fail_modes default: closed
        out, calls = self.call(_Signer(decide=SignerUnavailable("down")), fail_modes={"default": "open"})
        self.assertEqual((out.is_error, calls), (False, 1))

    def test_a_refusal_never_lets_the_call_run(self):
        from tracekit.signer.rpc_schema import RPCError
        out, calls = self.call(_Signer(decide=RPCError("run_closed", "closed")), fail_modes={"default": "open"})
        self.assertEqual((out.is_error, calls), (True, 0))
        self.assertIn("run_closed", out.content[0].text)

    def test_a_failed_complete_warns_and_keeps_the_result(self):
        from tracekit.signer.rpc_schema import RPCError
        with self.assertWarns(UserWarning):
            out, calls = self.call(_Signer(complete=RPCError("unavailable", "storage down")))
        self.assertEqual((out.is_error, out.content[0].text, calls), (False, "done", 1))
