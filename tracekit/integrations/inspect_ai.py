"""Tracekit for Inspect AI (docs/integrations/inspect-ai.md): an approver that asks the signer to decide every tool
call before it runs (an `ask` waits for a person), and a hook that records the outcome after.

    from inspect_ai import Task, eval
    from inspect_ai.approval import ApprovalPolicy
    from tracekit.integrations.inspect_ai import tracekit
    eval(Task(...), approval=[ApprovalPolicy(tracekit(run), "*")])

A call Tracekit refuses is rejected with its reason: it never runs and the model gets the reason as an `approval` tool
error. An allowed call is approved, which ends Inspect's approval chain, so list Tracekit's approver first (or alone) and
let an approver before it `escalate`. An approver never sees a call's result, so a hook completes each call it allowed
when Inspect emits its ToolEvent: `ok` with the result, or `error` with the event's message (a call a sample limit cancels while it runs ends
as `error`). A call that never gets a ToolEvent is left open for the signer to close as a gap when the run ends.

Inspect registers a hook once per process, for every eval in it, and runs samples at once: the hook is enabled only
after a Tracekit approver was made, and finds a call by its id, which must be unique across the eval. A call whose id
is already being decided or still open is refused (Inspect's cache can give two samples one tool-call id), and one
whose arguments changed after the decision (an in-process sentinel's `modify`) is completed as `error`.
"""
import collections
import copy

from inspect_ai.approval import Approval, approver
from inspect_ai.hooks import Hooks, SampleEnd, SampleEvent, hooks
from pydantic_core import to_jsonable_python

from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field

# lean: a call stays here until its ToolEvent or its sample's end, and a twin's count until its ToolEvent; a hook
# missing both leaves them for the process's life
_allowed = {}   # tool_call_id -> (run, the signer's decision, the decided arguments), or None while it is decided
_twins = collections.Counter()   # tool_call_id -> the calls refused because one of that id was open: their ToolEvents
_made = False   # whether a Tracekit approver exists, so the hook records for this process's evals


@approver(name="tracekit")
def tracekit(run):
    """The approver for `ApprovalPolicy(tracekit(run), "*")`. `run` is a RunHandle (`Client().run(...)`; an AsyncRunHandle
    works too): one run for the whole eval."""
    global _made
    run = run_handle(run)
    _made = True

    async def approve(message, call, view, history):
        if call.id in _allowed:   # its decision and result are found by its id: the open one's would be overwritten
            _twins[call.id] += 1
            return Approval(decision="reject", explanation=f"Tool call refused by Tracekit: another call with its id "
                                                            f"({call.id}) is still open in this run")
        _allowed[call.id], d, why = None, None, None
        try:
            d, why = await gate_call(run, call.id, 0, call.function, call.arguments, waiter="approver",
                                     who="the sample")
        finally:
            if d is not None and why is None:
                _allowed[call.id] = (run, d, copy.deepcopy(call.arguments))
            else:   # refused, cancelled, or the run's fail mode let it run unrecorded
                _allowed.pop(call.id, None)
        return Approval(decision="approve") if why is None else Approval(decision="reject", explanation=why)
    return approve


@hooks(name="tracekit", description="Records the outcome of each tool call Tracekit's approver let run")
class Outcomes(Hooks):
    def enabled(self):
        return _made

    async def on_sample_event(self, data: SampleEvent):
        ev = data.event
        if ev.event != "tool" or ev.pending:
            return
        if ev.error and ev.error.type == "approval" and _twins[ev.id]:   # a twin's refusal, not the open call's
            _twins[ev.id] -= 1
            return
        if _allowed.get(ev.id) is None:   # a call Tracekit refused (an `approval` error) or never saw
            return
        run, d, decided = _allowed.pop(ev.id)
        if ev.arguments != decided:
            await complete(run, d, ev.id, 0, "error", error="the call's arguments changed after the decision")
        elif ev.error:
            await complete(run, d, ev.id, 0, "error", error=ev.error.message[:4096])
        else:
            await complete(run, d, ev.id, 0, "ok", result=result_field(d.get("send_result"),
                                                                      to_jsonable_python(ev.result)))

    async def on_sample_end(self, data: SampleEnd):
        for m in data.sample.messages:
            for c in getattr(m, "tool_calls", None) or ():
                _allowed.pop(c.id, None)
