"""Inspect AI's approver and hook (tracekit.integrations.inspect_ai) on a real eval with the mockllm model and
FakeSigner: only a call the signer allows (or a person approves while it waits) runs, the model reads the reason for
the rest, and every call that ran is completed with its result or its error, and no other is."""
import asyncio
import collections
import importlib.util
import tempfile
import threading
import unittest
from unittest import mock

import adapter_contract as ac
from factories import wait_for
from tracekit.sdk.client import Client, RunHandle, result_field
from tracekit.signer.rpc_schema import RPCError
from tracekit.testing import FakeSigner

HAVE = importlib.util.find_spec("inspect_ai") is not None
if HAVE:
    from inspect_ai import Task, eval
    from inspect_ai.approval import ApprovalPolicy
    from inspect_ai.dataset import Sample
    from inspect_ai.event import ToolEvent
    from inspect_ai.hooks import SampleEvent
    from inspect_ai.model import ModelOutput, get_model
    from inspect_ai.solver import generate, use_tools
    from inspect_ai.tool import ToolCall, ToolCallError, ToolError, tool

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
    @classmethod
    def setUpClass(cls):
        # Inspect's first eval in a process loads its tool-calling path inside the sample (seconds on a loaded runner,
        # spent from a test's time limit): one eval with a tool call, and no Tracekit, takes it first
        log_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(log_dir.cleanup)
        outs = [ModelOutput.for_tool_call("mockllm/model", "echo", {"text": "warm"}, tool_call_id="warm-1"),
                ModelOutput.from_content("mockllm/model", "done")]
        eval(Task(dataset=[Sample(input="go")], solver=[use_tools([echo()]), generate()]),
             model=get_model("mockllm/model", custom_outputs=outs), display="none", log_dir=log_dir.name)

    def setUp(self):
        ac.RAN.clear()
        self.addCleanup(ti._allowed.clear)
        self.addCleanup(ti._twins.clear)
        self.addCleanup(ti._sample_runs.clear)
        self.addCleanup(setattr, ti, "_single", None)

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

    def serve_per_sample(self):
        """Like serve(), but records every run the approver opens and closes, and every completion, by run id."""
        signer, mutex, self.frames = FakeSigner(ac._rule), threading.Lock(), []

        def handle(identity, frame):
            method = frame.pop("method")
            with mutex:
                out = getattr(signer, method)(frame)
            if method == "register_run":
                self.frames.append(("register_run", out["run_id"], out["run_token"]))
            elif method == "close_run":
                self.frames.append(("close_run", frame.get("run_id"), None))
            elif method == "complete":
                self.frames.append(("complete", frame.get("run_id"), dict(frame)))
            return out
        self.client = Client(ac._serve(self, handle))
        self.addCleanup(self.client.close)

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
        self.assertIn("held by Tracekit policy and not approved: requested; R-PAY", msg.error.message)
        self.assertEqual(self.recorded("tool.result"), [])

    def test_a_held_call_whose_wait_a_time_limit_cancels_is_withdrawn_and_never_runs(self):
        """#571: Inspect doesn't suspend a sample's wall-clock time_limit while an approver waits, so the limit can
        cancel the wait (on the real signer, which waits for real). The approval is withdrawn, and the call never runs
        and has no result."""
        self.client = Client(ac.OnReal.serve_signer(self))
        self.addCleanup(self.client.close)
        self.run = self.client.run(agent="inspect")
        self.sample([("pay", {"to": "acct-42", "cents": 1500})], time_limit=3)
        types = lambda: [e["type"] for e in ac.OnReal.events(self, {"run_id": self.run.run_id})]  # noqa: E731
        self.assertTrue(wait_for(lambda: "approval.abandoned" in types()), types())
        self.assertEqual((ac.RAN, [t for t in types() if t == "tool.result"]), ([], []))

    def test_an_outage_follows_the_runs_fail_mode(self):
        self.serve()
        down = {"rule_ids": [], "unavailable": True, "reason": "signer unavailable: down"}
        with mock.patch.object(RunHandle, "decide", return_value={"decision": "deny", **down}):
            [msg] = self.sample([("echo", {"text": "hi"})])
        self.assertEqual((ac.RAN, msg.error.message), ([], "Tool call refused by Tracekit: signer unavailable: down"))
        with mock.patch.object(RunHandle, "decide", return_value={"decision": "allow", **down}), \
                mock.patch.object(RunHandle, "approval_consume") as consume:
            [msg] = self.sample([("echo", {"text": "hi"})])
        self.assertEqual((ac.RAN, msg.content, msg.error), (["echo"], "hi", None))
        consume.assert_not_called()
        self.assertEqual((self.completed, ti._allowed), ([], {}))

    def test_a_call_whose_id_is_still_open_is_refused(self):
        """Review of #586: one run spans the eval and a call is found by its id, so a second call decided under an id
        still open (Inspect's cache gives two samples one tool-call id) took the first's place: the first's result was
        signed under the second's decision, and the second's found nothing. It is refused, with a reason, and its
        refusal's ToolEvent leaves the open call alone."""
        self.serve()
        approve, hook = ti.tracekit(self.run), ti.Outcomes()

        async def both():   # the second is asked while the first is decided
            calls = [ToolCall(id="dup", function="echo", arguments={"text": t}) for t in ("a", "b")]
            return await asyncio.gather(*(approve(message="", call=c, view=None, history=[]) for c in calls))
        first, second = asyncio.run(both())
        self.assertEqual((first.decision, second.decision, second.explanation),
                         ("approve", "reject", "Tool call refused by Tracekit: another call with its id (dup) is still "
                                               "open in this run"))
        for ev in (ToolEvent(id="dup", function="echo", arguments={"text": "b"},
                             error=ToolCallError("approval", second.explanation)),
                   ToolEvent(id="dup", function="echo", arguments={"text": "a"}, result="a")):
            asyncio.run(hook.on_sample_event(SampleEvent(None, "run", "eval", "sample", ev)))
        self.assertEqual([d["tool_call_id"] for d in self.recorded("policy.decision")], ["dup"])
        [sent] = self.completed
        self.assertEqual((sent["tool_call_id"], sent["status"], sent["result"]), ("dup", "ok", result_field(False, "a")))
        self.assertEqual((ti._allowed, +ti._twins), ({}, collections.Counter()))

    def test_a_call_whose_arguments_changed_after_the_decision_is_completed_as_an_error(self):
        """Review of #586: an in-process sentinel's `modify` runs after the approvers, and the ToolEvent carries its
        arguments: the call was completed `ok` under the decision made for the model's."""
        self.serve()
        d = self.run.decide("call-1", "echo", {"text": "hi"})
        ti._single = self.run
        ti._allowed[(self.run.run_id, "call-1")] = (self.run, d, {"text": "hi"})
        ev = ToolEvent(id="call-1", function="echo", arguments={"text": "rm -rf /"}, result="rm -rf /")
        asyncio.run(ti.Outcomes().on_sample_event(SampleEvent(None, "run", "eval", "sample", ev)))
        [done] = self.recorded("tool.result")
        self.assertEqual((done["status"], done["error"]), ("error", "the call's arguments changed after the decision"))

    def test_two_samples_with_the_same_tool_call_ids_record_into_their_own_runs(self):
        """#1068: per_sample=True opens one run per sample (keyed by the sample's eval id and uuid), so two samples
        with the same input and the same tool-call ids each record into their own run, and each run closes when its
        sample ends."""
        self.serve_per_sample()
        # lean: a callable, not a shared list, so concurrent samples can't consume each other's outputs: a sample's
        # first generate (just its input) echoes once, later ones are done
        def outs(input, tools, tool_choice, config):
            if len(input) == 1:
                return ModelOutput.for_tool_call("mockllm/model", "echo", {"text": "hi"}, tool_call_id="call-1")
            return ModelOutput.from_content("mockllm/model", "done")
        t = Task(dataset=[Sample(input="go"), Sample(input="go")],
                 solver=[use_tools([echo()]), generate()],
                 approval=[ApprovalPolicy(ti.tracekit(client=self.client, per_sample=True), "*")])
        [log] = eval(t, model=get_model("mockllm/model", custom_outputs=outs), display="none",
                     log_dir=ac.tmpdir(self))
        self.assertEqual(log.status, "success", log.error)
        self.assertEqual(ac.RAN, ["echo", "echo"])
        runs = [f[1] for f in self.frames if f[0] == "register_run"]
        self.assertEqual((len(runs), len(set(runs))), (2, 2), self.frames)
        self.assertEqual(sorted(f[1] for f in self.frames if f[0] == "close_run"), sorted(runs))
        done = [(f[1], f[2]["tool_call_id"], f[2]["status"]) for f in self.frames if f[0] == "complete"]
        self.assertEqual(sorted(done), sorted((r, "call-1", "ok") for r in runs))
        self.assertEqual((ti._allowed, ti._twins, ti._sample_runs), ({}, collections.Counter(), {}))

    def test_a_call_with_no_running_sample_is_refused(self):
        """#1068: per-sample mode refuses a call it cannot attribute to a sample, instead of recording it against
        some other sample's run."""
        self.serve()
        approve = ti.tracekit(client=self.client, per_sample=True)
        out = asyncio.run(approve(message="", call=ToolCall(id="x", function="echo", arguments={"text": "hi"}),
                                  view=None, history=[]))
        self.assertEqual(out.decision, "reject")
        self.assertIn("could not be told", out.explanation)

    def test_per_sample_needs_a_client_not_a_run(self):
        self.serve()
        with self.assertRaisesRegex(TypeError, "needs client=Client"):
            ti.tracekit(per_sample=True)
        with self.assertRaisesRegex(TypeError, "not a run handle"):
            ti.tracekit(self.run, per_sample=True)
        with self.assertRaisesRegex(TypeError, "per_sample=True"):
            ti.tracekit(self.run, client=self.client)

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
