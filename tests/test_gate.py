"""The signer steps the framework integrations share (tracekit.integrations.gate), with a mock run handle."""
import asyncio
import time
import unittest
from unittest import mock

from tracekit.integrations.gate import gate_call
from tracekit.signer.rpc_schema import RPCError


def run(decision="allow", consume=True, **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": [], "decision_id": "dec-1"}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": "approved"}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, **more}
    return r


class GateCall(unittest.TestCase):
    def test_a_cancel_while_the_approval_request_fails_still_cancels(self):
        """The request's error was raised in the cancel handler and turned into a refusal: the cancel was lost."""
        r = run("ask")

        def call(method, **f):
            time.sleep(0.3)
            raise RPCError("run_closed", "the run closed")
        r.call.side_effect = call

        async def go():
            t = asyncio.ensure_future(gate_call(r, "c1", 0, "pay", {}))
            await asyncio.sleep(0.1)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t
        asyncio.run(go())
        self.assertEqual([c.args[0] for c in r.call.call_args_list], ["approval_request"])   # nothing to withdraw
        r.approval_consume.assert_not_called()

    def test_an_allowed_call_whose_consume_is_refused_is_completed_as_not_run(self):
        """Left open, the refusal the model reads was signed as a result sent before the call's was recorded."""
        r = run(consume=False, reason="the run is held: incident inc-1")
        _, why = asyncio.run(gate_call(r, "c1", 0, "pay", {}))
        self.assertIn("the run is held", why)
        r.complete.assert_called_once_with("c1", "error", attempt=0, error="not run: " + why)
        r = run("ask", consume=False)   # an approved ask: completed, it would read as run without its approval
        self.assertIsNotNone(asyncio.run(gate_call(r, "c1", 0, "pay", {}))[1])
        r.complete.assert_not_called()

    def test_approved_arguments_other_than_the_calls_complete_it_as_not_run(self):
        r = run("ask", args={"to": "mallory"})
        _, why = asyncio.run(gate_call(r, "c1", 0, "pay", {"to": "bob"}))
        self.assertIn("arguments the signer approved", why)
        r.complete.assert_called_once_with("c1", "error", attempt=0, error="not run: " + why)


if __name__ == "__main__":
    unittest.main()
