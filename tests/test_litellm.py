"""The LiteLLM guardrail (tracekit/integrations/litellm.py) without LiteLLM: its hooks called with the arguments the
LiteLLM proxy passes (cited from BerriAI/litellm main, 2dfeb80), deciding and recording each MCP tool call through an
in-process v2 signer as LiteLLM's gateway identity (source gateway, tier T2)."""
import asyncio
import importlib.util
import sys
import threading
import time
import types
import unittest
from unittest import mock

from adapter_contract import tmpdir
from test_executor import InProcess
from test_gateway import AGENT
from test_signer_service import records
from tracekit.executor import Custody
from tracekit.identity.base import CallerIdentity
from tracekit.integrations import litellm as tk
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

HAVE_MCP = importlib.util.find_spec("mcp") is not None
LITELLM = CallerIdentity("mtls", "spiffe://acme/litellm", True)
POLICY = Engine({"ask": [{"id": "R-PAY", "tool": "^mcp:billing/pay$", "pattern": "^"}],
                 "deny": [{"id": "R-WIPE", "tool": "^mcp:files/wipe$", "pattern": "^"}]})


class Base:
    """Stands in for LiteLLM's CustomGuardrail (litellm/integrations/custom_guardrail.py:244), which the config loader
    builds with guardrail_name, event_hook, default_on and the guardrail's own litellm_params
    (litellm/proxy/guardrails/guardrail_registry.py:918-923)."""

    def __init__(self, **kwargs):
        self.init = kwargs


Guardrail = type("Guardrail", (tk.Hooks, Base), {})


class LiteLLMGuardrail(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:*": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/litellm": ["decide", "complete", "approval_request",
                                                                             "approval_wait", "approval_consume"]})
        self.closed = False
        self.addCleanup(self.close)
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}
        self.signer = InProcess(self.s, LITELLM)
        self.g = Guardrail(guardrail_name="tracekit", event_hook="pre_mcp_call", default_on=True, approval_wait_s=5)
        self.g.custody = Custody(self.signer, 5)
        # the authenticated key (UserAPIKeyAuth, litellm/types/proxy/auth/user_api_key_auth.py:129): its row's metadata
        # (litellm/models/verification_token.py:31)
        self.key = types.SimpleNamespace(token="hashed-key", metadata={"tracekit_caller": "token:http"})

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def events(self):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run["run_id"]]

    def call(self, server, tool, args, run=None, key=None):
        """The pre_mcp_call hook for one tools/call, as LiteLLM makes it: the request ProxyLogging builds for MCP calls
        (litellm/proxy/utils.py:1580-1611, headers as logging_safe_mcp_headers leaves them), the request's logger
        (litellm/proxy/_experimental/mcp_server/mcp_server_manager.py:6135) and call_type call_mcp_tool (:6139-6143);
        (what the hook returned, the data, the logger's model_call_details)."""
        log = types.SimpleNamespace(model_call_details={"litellm_call_id": "c-1", "litellm_trace_id": "t-1"})
        run = f"{self.run['run_id']}.{self.run['run_token']}" if run is None else run
        data = {"messages": [{"role": "user", "content": f"Tool: {tool}\nArguments: {args}"}], "model": "mcp-tool-call",
                "user_api_key_user_id": "u-1", "user_api_key_team_id": None, "user_api_key_end_user_id": None,
                "user_api_key_hash": "hashed-key", "user_api_key_request_route": None, "mcp_tool_name": tool,
                "mcp_arguments": args, "mcp_server_name": server, "incoming_bearer_token": None,
                "metadata": {"headers": {"content-type": "application/json", **({"x-tracekit-run": run} if run else {})},
                             "user_api_key_user_id": "u-1", "user_api_key_metadata": {}},
                "litellm_logging_obj": log}
        out = asyncio.run(self.g.async_pre_call_hook(self.key if key is None else key, None, data, "call_mcp_tool"))
        return out, data, log.model_call_details

    def ran(self, details, text="done", is_error=False):
        """LiteLLM's result hook for a call that ran: post_call put the CallToolResult in original_response
        (litellm/proxy/_experimental/mcp_server/operations.py:2522, litellm/litellm_core_utils/litellm_logging.py:1671),
        then async_post_mcp_tool_call_hook gets model_call_details as kwargs (operations.py:2523-2528)."""
        from mcp.types import CallToolResult, TextContent
        details["original_response"] = CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)
        asyncio.run(self.g.async_post_mcp_tool_call_hook(details, types.SimpleNamespace(mcp_tool_call_response=[]),
                                                         None, None))

    def calls(self):
        return [(e["type"], e["source"], e.get("tier"), e["data"].get("tool") or e["data"].get("ok"))
                for e in self.events() if e["type"] in ("policy.decision", "tool.result")]

    @unittest.skipUnless(HAVE_MCP, "mcp not installed")
    def test_an_allowed_call_runs_with_the_consumed_arguments_and_its_result_is_recorded_t2(self):
        out, data, details = self.call("notes", "search", {"q": "audit"})
        self.assertIs(out, data)
        self.assertEqual(data["modified_arguments"], {"q": "audit"})
        tcid = details[tk.CALL]
        self.ran(details, "3 notes")
        self.assertEqual(self.calls(), [("policy.decision", "gateway", "T2", "mcp:notes/search"),
                                        ("tool.result", "gateway", "T2", True)])
        decision = next(e for e in self.events() if e["type"] == "policy.decision")
        self.assertEqual((decision["tool_call_id"], decision["data"]["via"]), (tcid, "mtls:spiffe://acme/litellm"))

    @unittest.skipUnless(HAVE_MCP, "mcp not installed")
    def test_an_error_result_is_recorded_as_an_error(self):
        _, _, details = self.call("notes", "search", {"q": "audit"})
        self.ran(details, "upstream said no", is_error=True)
        self.assertEqual(self.calls()[-1], ("tool.result", "gateway", "T2", False))

    def test_a_call_that_raised_is_completed_as_an_error(self):
        _, _, details = self.call("notes", "search", {"q": "audit"})
        # the failure handlers set model_call_details["exception"] (litellm_logging.py:3951) and hand it to each
        # callback's async_log_failure_event (litellm_logging.py:4270-4275)
        details["exception"] = TimeoutError("upstream timed out")
        asyncio.run(self.g.async_log_failure_event(details, None, None, None))
        self.assertEqual(self.calls()[-1], ("tool.result", "gateway", "T2", False))

    def test_a_denied_call_never_runs(self):
        out, data, details = self.call("files", "wipe", {"path": "/"})
        # a string from async_pre_call_hook is LiteLLM's refusal: HTTP 400 for an MCP call (litellm/proxy/utils.py:1882-1891)
        self.assertEqual(out, tk.BLOCKED + "denied by policy: R-WIPE")
        self.assertNotIn("modified_arguments", data)
        self.assertNotIn(tk.CALL, details)

    def test_an_ask_is_held_until_a_person_approves_it(self):
        got = {}
        t = threading.Thread(target=lambda: got.update(out=self.call("billing", "pay", {"cents": 5})))
        t.start()
        for _ in range(500):
            aids = [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {"run_id": self.run["run_id"]})["approvals"]]
            if aids:
                break
            time.sleep(0.01)
        self.assertNotIn("out", got)   # held: LiteLLM has not run it
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": aids[0], "decision": "approve"})
        t.join(20)
        out, data, _ = got["out"]
        self.assertIs(out, data)
        self.assertEqual(data["modified_arguments"], {"cents": 5})

    def test_a_request_with_no_run_or_no_caller_is_refused_before_the_signer(self):
        self.assertIn("no run", self.call("notes", "search", {}, run="")[0])
        self.assertIn("no run", self.call("notes", "search", {}, run="not-a-run")[0])
        self.assertIn("tracekit_caller", self.call("notes", "search", {}, key=types.SimpleNamespace(metadata={}))[0])
        self.assertEqual(self.calls(), [])

    def test_a_run_token_presented_for_another_identity_is_refused(self):
        other = types.SimpleNamespace(metadata={"tracekit_caller": "token:other"})   # another key's agent, granted too
        out = self.call("notes", "search", {}, key=other)[0]
        self.assertIn("run token belongs to another run or identity", out)

    def test_an_unreachable_signer_refuses_the_call(self):
        self.signer.down = True
        self.assertIn("the signer is unreachable", self.call("notes", "search", {})[0])

    def test_other_calls_pass_untouched(self):
        data = {"mcp_tool_name": "search"}   # list_mcp_tools reaches pre_mcp_call guardrails too (types/utils.py:745)
        self.assertIsNone(asyncio.run(self.g.async_pre_call_hook(self.key, None, data, "list_mcp_tools")))
        asyncio.run(self.g.async_log_failure_event({"litellm_call_id": "c-2"}, None, None, None))   # not one it holds
        self.assertEqual(self.calls(), [])


class Loading(unittest.TestCase):
    def test_the_config_loader_gets_a_guardrail_on_litellms_base_class(self):
        # get_instance_fn imports the module and reads the class off it (litellm/proxy/types_utils/utils.py:58-61)
        base = types.ModuleType("litellm.integrations.custom_guardrail")
        base.CustomGuardrail = Base
        with mock.patch.dict(sys.modules, {"litellm": types.ModuleType("litellm"),
                                           "litellm.integrations": types.ModuleType("litellm.integrations"),
                                           "litellm.integrations.custom_guardrail": base}), \
                mock.patch.dict(tk.__dict__):
            cls = getattr(tk, "TracekitGuardrail")
            g = cls(guardrail_name="tracekit", event_hook="pre_mcp_call", default_on=True, approval_wait_s=30)
        self.assertEqual(cls.__mro__[1:3], (tk.Hooks, Base))
        self.assertEqual((g.init["supported_event_hooks"], g.custody.wait_s), (["pre_mcp_call"], 30))
        self.assertNotIn("approval_wait_s", g.init)

    @unittest.skipIf(importlib.util.find_spec("litellm") is not None, "litellm installed")
    def test_the_module_imports_without_litellm(self):
        with self.assertRaises(ImportError):
            tk.TracekitGuardrail
        with self.assertRaises(AttributeError):
            tk.Nothing
