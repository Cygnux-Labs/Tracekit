"""Pydantic AI's tool-execute hook (tracekit.integrations.pydantic_ai) on a real Agent with a FunctionModel and a mock
run: only an allow or an approved ask runs the tool, the model reads the reason for anything else and the run goes on,
and nothing Tracekit fails at raises into the agent."""
import importlib.util
import unittest
import warnings
from unittest import mock

HAVE = importlib.util.find_spec("pydantic_ai") is not None
if HAVE:
    from pydantic_ai import Agent, ModelRetry
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart, RetryPromptPart
    from pydantic_ai.models.function import FunctionModel

    from tracekit.integrations.pydantic_ai import Tracekit

from tracekit.signer.rpc_schema import RPCError


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return r


def agent(r, tool, args=None):
    """An agent whose model calls `tool` once (with `args`, default {"account": "ACC-9"}) and then answers with what
    the tool returned, or with the retry prompt it was given."""
    def model(messages, info):
        parts = [p for m in messages for p in m.parts]
        back = [p for p in parts if isinstance(p, (ToolReturnPart, RetryPromptPart))]
        if not back or isinstance(back[-1], RetryPromptPart) and len(back) < 2:
            return ModelResponse(parts=[ToolCallPart("close_account", args or {"account": "ACC-9"},
                                                     f"call-{len(back) + 1}")])
        return ModelResponse(parts=[TextPart(str(back[-1].content))])
    return Agent(FunctionModel(model), tools=[tool], capabilities=[Tracekit(r)])


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
class Hook(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        return close_account

    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                self.ran.clear()
                out = agent(r, self.tool()).run_sync("close it").output
                self.assertEqual(self.ran, ["ACC-9"] if runs else [])
                if runs:
                    self.assertEqual(out, "closed ACC-9")
                    r.complete.assert_called_once_with("call-1", "ok", result=mock.ANY)
                else:
                    self.assertIn("Tracekit policy", out)
                    r.complete.assert_not_called()

    def test_the_signer_decides_the_models_own_arguments(self):
        r = run()
        agent(r, self.tool(), '{"account": "ACC-9"}').run_sync("close it")
        r.decide.assert_called_once_with("call-1", "close_account", '{"account": "ACC-9"}')
        r.approval_consume.assert_called_once_with("call-1", "close_account", '{"account": "ACC-9"}',
                                                   approval_id_hint=None)

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        agent(r, self.tool()).run_sync("close it")
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1")

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", agent(r, self.tool()).run_sync("close it").output)
        self.assertEqual([c.args[0] for c in r.call.call_args_list][-1], "approval_abandon")

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        out = agent(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool()).run_sync("close it").output
        self.assertEqual(out, "Tool call blocked by Tracekit policy: TK-D001")

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", agent(r, self.tool()).run_sync("close it").output)
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(agent(r, self.tool()).run_sync("close it").output, "closed ACC-9")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = agent(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool()).run_sync("x").output
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(agent(r, self.tool()).run_sync("x").output, "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_a_retry_is_a_new_decision(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            if len(self.ran) == 1:
                raise ModelRetry("account is locked, try again")
            return f"closed {account}"
        r = run()
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            self.assertEqual(agent(r, close_account).run_sync("close it").output, "closed ACC-9")
        self.assertEqual([c.args[0] for c in r.decide.call_args_list], ["call-1", "call-2"])
        self.assertEqual([c.args[:2] for c in r.complete.call_args_list], [("call-1", "error"), ("call-2", "ok")])
        self.assertIn("account is locked", r.complete.call_args_list[0].kwargs["error"])


if __name__ == "__main__":
    unittest.main()
