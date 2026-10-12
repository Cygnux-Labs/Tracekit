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


if __name__ == "__main__":
    unittest.main()
