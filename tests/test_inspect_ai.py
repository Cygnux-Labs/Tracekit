"""Inspect AI's approver and hook (tracekit.integrations.inspect_ai) on a real eval with the mockllm model and
FakeSigner: only a call the signer allows (or a person approves while it waits) runs, the model reads the reason for
the rest, and every call that ran is completed with its result or its error, and no other is."""
import asyncio
import importlib.util
import threading
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit.sdk.client import Client, RunHandle, result_field
from tracekit.signer.rpc_schema import RPCError
from tracekit.testing import FakeSigner

HAVE = importlib.util.find_spec("inspect_ai") is not None
if HAVE:
    from inspect_ai import Task, eval
    from inspect_ai.approval import ApprovalPolicy
    from inspect_ai.dataset import Sample
    from inspect_ai.model import ModelOutput, get_model
    from inspect_ai.solver import generate, use_tools
    from inspect_ai.tool import ToolError, tool

    from tracekit.integrations import inspect_ai as ti

    @tool
    def echo():
        async def execute(text: str):
            """Echo the text.

            Args:
                text: the text
            """
            ac.RAN.append("echo")
            return text
        return execute

    @tool
    def pay():
        async def execute(to: str, cents: int):
            """Send money.

            Args:
                to: the account
                cents: the amount
            """
            ac.RAN.append("pay")
            return f"paid {cents}"
        return execute

    @tool
    def wipe():
        async def execute(path: str):
            """Delete a path.

            Args:
                path: the path
            """
            ac.RAN.append("wipe")
            return "wiped"
        return execute

    @tool
    def fail():
        async def execute(why: str):
            """Always raises.

            Args:
                why: the reason
            """
            ac.RAN.append("fail")
            raise ToolError(why)
        return execute

    @tool
    def slow():
        async def execute(text: str):
            """Wait for a long time.

            Args:
                text: the text
            """
            ac.RAN.append("slow")
            await asyncio.sleep(60)
        return execute


@unittest.skipUnless(HAVE, "inspect-ai not installed")
class Approver(unittest.TestCase):
    def setUp(self):
        ac.RAN.clear()
        self.addCleanup(ti._allowed.clear)

    def serve(self, person_answers=False):
        """A FakeSigner for `ac._rule` (pay is held, wipe denied); with `person_answers`, a person approves a held call
        as the hook starts to wait for it (FakeSigner's wait doesn't block)."""
        signer, mutex, self.completed = FakeSigner(ac._rule), threading.Lock(), []

        def handle(identity, frame):
            method = frame.pop("method")
            if method == "complete":   # FakeSigner's tool.result event keeps no result
                self.completed.append(frame)
            with mutex:
                if person_answers and method == "approval_wait":
                    signer.approval_decide({"request_id": "person", "approval_id": frame["approval_id"],
                                            "decision": "approve"})
                return getattr(signer, method)(frame)
        self.client = Client(ac._serve(self, handle))
        self.addCleanup(self.client.close)
        self.run = self.client.run(agent="inspect")

    def sample(self, calls, run=None, **task):
        """The tool messages the model read after one sample in which it made `calls` ((tool, args), ...) and answered."""
        outs = [ModelOutput.for_tool_call("mockllm/model", t, a, tool_call_id=f"call-{i}")
                for i, (t, a) in enumerate(calls, 1)] + [ModelOutput.from_content("mockllm/model", "done")]
        t = Task(dataset=[Sample(input="go")], solver=[use_tools([echo(), pay(), wipe(), fail(), slow()]), generate()],
                 approval=[ApprovalPolicy(ti.tracekit(run or self.run), "*")], **task)
        [log] = eval(t, model=get_model("mockllm/model", custom_outputs=outs), display="none", log_dir=ac.tmpdir(self))
        self.assertEqual(log.status, "success", log.error)
        return [m for m in log.samples[0].messages if m.role == "tool"]

    def recorded(self, typ):
        events = self.client.read({"run_id": self.run.run_id, "run_token": self.run.run_token, "limit": 1000})["events"]
        return [e["data"] for e in events if e["type"] == typ]

    def test_an_allowed_call_runs_and_is_completed_with_its_result(self):
        self.serve()
        [msg] = self.sample([("echo", {"text": "hi"})])
        self.assertEqual((ac.RAN, msg.content, msg.error), (["echo"], "hi", None))
        [done] = self.recorded("tool.result")
        self.assertEqual((done["tool_call_id"], done["status"]), ("call-1", "ok"))
        [sent] = self.completed
        self.assertEqual((sent["tool_call_id"], sent["result"]), ("call-1", result_field(False, "hi")))

    def test_a_denied_call_does_not_run_and_the_model_reads_the_reason(self):
        self.serve()
        [msg] = self.sample([("wipe", {"path": "/"})])
        self.assertEqual((ac.RAN, msg.error.type), ([], "approval"))
        self.assertEqual(msg.error.message, "Tool call blocked by Tracekit policy: R-WIPE")
        self.assertEqual(self.recorded("tool.result"), [])   # the ToolEvent of a refused call completes nothing

    def test_a_held_call_that_a_person_approves_while_it_waits_runs(self):
        self.serve(person_answers=True)
        [msg] = self.sample([("pay", {"to": "acct-42", "cents": 1500})])
        self.assertEqual((ac.RAN, msg.content, msg.error), (["pay"], "paid 1500", None))
        [done] = self.recorded("tool.result")
        self.assertEqual((done["tool_call_id"], done["status"]), ("call-1", "ok"))

    def test_a_held_call_nobody_approves_does_not_run_and_is_never_completed(self):
        self.serve()
        [msg] = self.sample([("pay", {"to": "acct-42", "cents": 1500})])
        self.assertEqual((ac.RAN, msg.error.type), ([], "approval"))
        self.assertIn("held by Tracekit policy (R-PAY) and not approved: requested", msg.error.message)
        self.assertEqual(self.recorded("tool.result"), [])

    def test_a_signer_error_refuses_the_call(self):
        self.serve()
        with mock.patch.object(RunHandle, "decide", side_effect=RPCError("run_closed", "r")):
            [msg] = self.sample([("echo", {"text": "hi"})])
        self.assertEqual((ac.RAN, msg.error.type), ([], "approval"))
        self.assertIn("Tracekit could not decide it (RPCError", msg.error.message)
        self.assertEqual(self.recorded("tool.result"), [])

    def test_a_tool_that_raises_is_completed_as_an_error(self):
        self.serve()
        [msg] = self.sample([("fail", {"why": "boom"})])
        self.assertEqual((ac.RAN, msg.error.message), (["fail"], "boom"))
        [done] = self.recorded("tool.result")
        self.assertEqual((done["status"], done["error"]), ("error", "boom"))

    def test_each_call_is_completed_once_under_its_own_id(self):
        self.serve()
        self.sample([("echo", {"text": "a"}), ("wipe", {"path": "/"}), ("fail", {"why": "x"}), ("echo", {"text": "b"})])
        self.assertEqual([(d["tool_call_id"], d["status"]) for d in self.recorded("tool.result")],
                         [("call-1", "ok"), ("call-3", "error"), ("call-4", "ok")])
        self.assertEqual(ti._allowed, {})

    def test_a_call_cancelled_by_a_sample_limit_is_completed_as_cancelled(self):
        self.serve()
        self.sample([("slow", {"text": "x"})], time_limit=5)   # long enough that slow starts on a loaded runner
        self.assertEqual(ac.RAN, ["slow"])
        self.assertEqual([d["tool_call_id"] for d in self.recorded("policy.decision")], ["call-1"])
        [done] = self.recorded("tool.result")
        self.assertEqual((done["tool_call_id"], done["status"], done["error"]),
                         ("call-1", "error", "Tool call was cancelled."))
        self.assertEqual(ti._allowed, {})

    def test_it_needs_a_run_handle(self):
        with self.assertRaisesRegex(TypeError, "needs a run handle"):
            ti.tracekit(object())


if __name__ == "__main__":
    unittest.main()
