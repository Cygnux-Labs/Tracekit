"""CrewAI's tool hooks (tracekit.integrations.crewai) and the client behaviour they rely on: CrewAI runs a tool when a
before hook raises, so every refusal must come back as False, and nothing may raise into the crew (dogfood CR-1)."""
import types
import unittest
import warnings
from unittest import mock

from tracekit.integrations import crewai
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, result_field
from tracekit.signer.rpc_schema import RPCError


def ctx(result=None):
    return types.SimpleNamespace(tool_name="close_account", tool_input={"account": "ACC-9"}, tool_result=result)


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return r


def hook(r, result="done"):
    """(before's answer, after's answer) of one call."""
    before, after = crewai.hooks(r)
    return before(ctx()), after(ctx(result))


class Hooks(unittest.TestCase):
    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                b, a = hook(r)
                self.assertEqual(b, None if runs else False)
                if runs:
                    self.assertIsNone(a)
                    r.complete.assert_called_once()
                else:
                    self.assertIn("Tracekit policy", a)
                    r.complete.assert_not_called()

    def test_nothing_raises_into_the_crew(self):
        for exc in (RPCError("run_closed", "r"), SignerUnavailable("down"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                b, a = hook(r)
                self.assertIs(b, False)
                self.assertIn("Tracekit could not decide it", a)
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(hook(r), (None, None))

    def test_an_outage_follows_the_runs_fail_mode(self):
        b, a = hook(run("deny", unavailable=True, reason="signer unavailable: down"))
        self.assertEqual((b, a), (False, "Tool call refused by Tracekit: signer unavailable: down"))
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(hook(r), (None, None))
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        self.assertEqual(hook(run("deny", ["CR-D001", "TK-UNKNOWN-TOOL"]))[1],
                         "Tool call blocked by Tracekit policy: CR-D001")

    def test_a_tool_error_is_recorded_as_an_error(self):
        r = run()
        hook(r, "Error executing tool: boom")
        r.complete.assert_called_once_with(mock.ANY, "error", error="Error executing tool: boom")


class RunHandleOutage(unittest.TestCase):
    def handle(self, modes):
        return RunHandle(Client(signer="/nonexistent/tracekit.sock"), {"run_id": "r", "run_token": "t",
                                                                       "fail_modes": modes})

    def test_decide_returns_the_fail_mode_instead_of_raising(self):
        for modes, hint, want in (({}, None, "deny"), ({"default": "open"}, None, "allow"),
                                  ({"default": "open", "payment": "closed"}, "payment", "deny")):
            with self.subTest(modes=modes, hint=hint), self.assertWarnsRegex(UserWarning, "signer|fail"):
                d = self.handle(modes).decide("c1", "pay", {}, **({"tool_class_hint": hint} if hint else {}))
                self.assertEqual((d["decision"], d["unavailable"]), (want, True))

    def test_complete_never_raises(self):
        with self.assertWarnsRegex(UserWarning, "the result of c1 was not recorded"):
            self.assertIsNone(self.handle({}).complete("c1"))
        with mock.patch.object(Client, "call", side_effect=RPCError("run_closed", "r")), \
                self.assertWarnsRegex(UserWarning, "run_closed"):
            self.assertIsNone(self.handle({}).complete("c1"))

    def test_a_method_without_a_run_token_gets_none_and_calls_take_keywords(self):
        with mock.patch.object(Client, "_turn", side_effect=RuntimeError("sent")) as sent:
            for f in (lambda: self.handle({}).call("approval_list", state="requested"),
                      lambda: Client(signer="/nonexistent/tracekit.sock").call("approval_list", run_id="r")):
                with self.assertRaisesRegex(RuntimeError, "sent"):
                    f()
        self.assertEqual([c.args[1] for c in sent.call_args_list],
                         [{"run_id": "r", "state": "requested"}, {"run_id": "r"}])

    def test_a_result_with_a_lone_surrogate_is_recorded_escaped(self):
        self.assertEqual(result_field(True, ["a\ud800"]), '["a\\ud800"]')
        self.assertTrue(result_field(False, "a\ud800").startswith("sha256:"))

    def test_completing_an_untrusted_tool_without_its_result_warns(self):
        answers = {"decide": {"decision": "allow", "decision_id": "dec-1", "rule_ids": [], "run_seq": 1,
                              "send_result": True}, "complete": {"run_seq": 2}}
        with mock.patch.object(Client, "call", side_effect=lambda m, req=None, **f: answers[m]):
            h = self.handle({})
            h.decide("c1", "fetch", {})
            with self.assertWarnsRegex(UserWarning, "completed without its result"):
                h.complete("c1")
            h.decide("c2", "fetch", {})
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                h.complete("c2", result="page text")

    def test_a_refusal_still_raises_from_decide(self):
        with mock.patch.object(Client, "call", side_effect=RPCError("forbidden", "no")), self.assertRaises(RPCError):
            self.handle({}).decide("c1", "pay", {})


if __name__ == "__main__":
    unittest.main()
