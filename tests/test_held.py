"""The held-call steps MCP and Browser Use share (tracekit.integrations.held)."""
import asyncio
import unittest

from tracekit.integrations.held import HeldCalls


class Escalated(unittest.TestCase):
    def test_an_approval_escalated_to_people_is_left_for_them_when_the_wait_ends(self):
        calls = []

        class Signer:
            def __getattr__(self, method):
                def call(req):
                    calls.append(method)
                    return {"decide": {"decision": "ask", "decision_id": "dec-1", "rule_ids": ["PAY"], "run_seq": 1},
                            "approval_request": {"approval_id": "apr-1", "state": "requested"},
                            "approval_wait": {"state": "requested", "escalated": True}}.get(method, {})
                return call
        why, _, _ = asyncio.run(HeldCalls(Signer(), {"run_id": "r", "run_token": "t"}, approval_wait_s=0.05)._gate(
            "c1", "pay", {}))
        self.assertIn("escalated the call to people", why)
        self.assertNotIn("approval_abandon", calls)


class Refusal(unittest.TestCase):
    """#587: a refused call lost the signer's reason (a deny named its rule ids only) and its approval id (a hold that
    ran out of time, or was rejected, named neither the approval nor why)."""

    def gate(self, decision, wait=None):
        class Signer:
            def __getattr__(self, method):
                return lambda req: {"decide": {"decision": decision, "decision_id": "dec-1", "rule_ids": ["PAY"],
                                               "run_seq": 1, "reason": "moving money. Instead: Check the payee."},
                                    "approval_request": {"approval_id": "apr-1", "state": "requested"},
                                    "approval_wait": wait}.get(method, {})
        return asyncio.run(HeldCalls(Signer(), {"run_id": "r", "run_token": "t"}, approval_wait_s=0.05)._gate(
            "c1", "pay", {}))[0]

    def test_a_deny_says_why_and_what_to_do_instead(self):
        self.assertEqual(self.gate("deny"), "PAY: moving money. Instead: Check the payee.")

    def test_a_hold_that_did_not_run_names_its_approval_and_why(self):
        for wait, said in (({"state": "requested"}, "no one approved the call within 0.05 s"),
                           ({"state": "rejected"}, "approval rejected")):
            with self.subTest(wait["state"]):
                why = self.gate("ask", wait)
                self.assertTrue(why.startswith(said), why)
                self.assertTrue(why.endswith("PAY (approval apr-1): moving money. Instead: Check the payee."), why)


if __name__ == "__main__":
    unittest.main()
