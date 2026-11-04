"""Tracekit for Inspect AI (docs/integrations/inspect-ai.md): an approver that asks the signer to decide every tool
call before it runs (an `ask` waits for a person), and a hook that records the outcome after.

    from inspect_ai import Task, eval
    from inspect_ai.approval import ApprovalPolicy
    from tracekit.integrations.inspect_ai import tracekit
    eval(Task(...), approval=[ApprovalPolicy(tracekit(run), "*")])

A call Tracekit refuses is rejected with its reason: it never runs and the model gets the reason as an `approval` tool
error. An allowed call is approved, which ends Inspect's approval chain, so list Tracekit's approver first (or alone) and
let an approver before it `escalate`. An approver never sees a call's result, so a hook completes each call it allowed
when Inspect emits its ToolEvent: `ok` with the result, or `error` with the event's message. A call that never gets a
ToolEvent (cancelled by a sample limit) is left open for the signer to close as a gap when the run ends.

Inspect registers a hook once per process, for every eval in it, and runs samples at once: the hook is enabled only
after a Tracekit approver was made, and finds a call by its id, which must be unique across the eval.
"""
from inspect_ai.approval import Approval, approver
from inspect_ai.hooks import Hooks, SampleEnd, SampleEvent, hooks
from pydantic_core import to_jsonable_python

from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field

# lean: a call stays here until its ToolEvent or its sample's end; a hook missing both leaves it for the process's life
_allowed = {}   # tool_call_id -> (run, the signer's decision): calls the approver let run
_made = False   # whether a Tracekit approver exists, so the hook records for this process's evals


@approver(name="tracekit")
def tracekit(run):
    """The approver for `ApprovalPolicy(tracekit(run), "*")`. `run` is a RunHandle (`Client().run(...)`; an AsyncRunHandle
    works too): one run for the whole eval."""
    global _made
    run = run_handle(run)
    _made = True

    async def approve(message, call, view, history):
        d, why = await gate_call(run, call.id, 0, call.function, call.arguments, waiter="approver", who="the sample")
        if why is not None:
            return Approval(decision="reject", explanation=why)
        if d is not None:   # none: the run's fail mode let it run unrecorded
            _allowed[call.id] = (run, d)
        return Approval(decision="approve")
    return approve


@hooks(name="tracekit", description="Records the outcome of each tool call Tracekit's approver let run")
class Outcomes(Hooks):
    def enabled(self):
        return _made

    async def on_sample_event(self, data: SampleEvent):
        ev = data.event
        if ev.event != "tool" or ev.pending:
            return
        allowed = _allowed.pop(ev.id, None)
        if allowed is None:   # a call Tracekit refused (an `approval` error) or never saw
            return
        run, d = allowed
        if ev.error:
            await complete(run, d, ev.id, 0, "error", error=ev.error.message[:4096])
        else:
            await complete(run, d, ev.id, 0, "ok", result=result_field(d.get("send_result"),
                                                                      to_jsonable_python(ev.result)))

    async def on_sample_end(self, data: SampleEnd):
        for m in data.sample.messages:
            for c in getattr(m, "tool_calls", None) or ():
                _allowed.pop(c.id, None)
