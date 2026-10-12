"""CrewAI's tool hooks (tracekit.integrations.crewai) and the client behaviour they rely on: CrewAI runs a tool when a
before hook raises, so every refusal must come back as False, and nothing may raise into the crew (dogfood CR-1)."""
import types
import unittest
import warnings
from unittest import mock

from tracekit.format.canon import event_hash
from tracekit.integrations import crewai
from tracekit.sdk import client
from tracekit.sdk.client import Client, RunHandle, SignerUnavailable, result_field
from tracekit.signer.rpc_schema import RPCError


def ctx(result=None):
    return types.SimpleNamespace(tool_name="close_account", tool_input={"account": "ACC-9"}, tool_result=result)


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
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

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIs(hook(r)[0], False)
        self.assertEqual([c.args[0] for c in r.call.call_args_list][-1], "approval_abandon")

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
        for text in ("Error executing tool: boom",   # native tool calls; then the text (ReAct) path's
                     "\nI encountered an error while trying to use the tool. This was the error: boom.\n Tool x "
                     "accepts these inputs: {}.\nMoving on then."):
            with self.subTest(text=text[:30]):
                r = run()
                hook(r, text)
                r.complete.assert_called_once_with(mock.ANY, "error", error=text)


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

    def test_refused_calls_leave_nothing_behind_on_a_long_lived_handle(self):
        answers = {"decide": {"decision": "deny", "decision_id": "dec-1", "rule_ids": ["D"], "run_seq": 1}}
        with mock.patch.object(Client, "call", side_effect=lambda m, req=None, **f: answers[m]):
            h = self.handle({})
            for i in range(10):
                h.decide(f"c{i}", "pay", {})
            self.assertEqual(len(h._decided), 0)
            answers["decide"] = dict(answers["decide"], decision="ask")   # asked, never approved: capped
            for i in range(client.KEEP_CALLS + 10):
                h.decide(f"a{i}", "pay", {})
            self.assertEqual(len(h._decided), client.KEEP_CALLS)

    def test_a_client_serving_many_runs_keeps_a_bounded_count_of_them(self):
        c = Client(signer="/nonexistent/tracekit.sock")   # an executor or MCP gateway: forged run ids too
        with mock.patch.object(client, "KEEP_RUNS", 50):
            for i in range(500):
                with c._lock:
                    c._prepare("decide", {"request_id": f"q{i}", "run_id": f"forged-{i}", "run_token": "t",
                                          "tool_call_id": "c1", "tool": "pay", "args_source": "parsed", "args": {}})
        self.assertEqual(len(c._seqs), 50)
        self.assertEqual(list(c._seqs)[-1], "forged-499")   # the most recent kept

    def test_a_fresh_clients_long_poll_on_a_closed_run_raises_the_refusal(self):
        with mock.patch.object(Client, "_poll", return_value={"error": {"code": "run_closed", "message": "r"}}), \
                self.assertRaises(RPCError):
            Client(signer="/nonexistent/tracekit.sock").call("approval_wait", run_id="r", run_token="t",
                                                            approval_id="a", timeout_ms=1)

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

    def test_result_field_never_raises_on_a_result_json_cannot_carry(self):
        import datetime
        import decimal
        for value in (datetime.datetime(2026, 1, 1), b"\x00\x01", decimal.Decimal("1.5"), {1, 2}, object(),
                      float("nan"), {"a": [float("inf")]}, 2 ** 60):
            with self.subTest(value=type(value).__name__):
                self.assertTrue(result_field(False, value).startswith("sha256:"))
                event_hash(result_field(True, value))   # what goes to the signer is JSON it can take

    def test_approval_consume_blocks_instead_of_raising(self):
        for exc in (SignerUnavailable("down"), RPCError("run_closed", "r")):
            with self.subTest(exc=exc), mock.patch.object(Client, "call", side_effect=exc), \
                    self.assertWarnsRegex(UserWarning, "is blocked"):
                out = self.handle({}).approval_consume("c1", "pay", {})
            self.assertFalse(out["ok"])
            self.assertIn("approval_consume failed", out["reason"])

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
