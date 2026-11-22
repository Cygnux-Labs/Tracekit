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

`tracekit(run)` records the whole eval into the one run it was given. `tracekit(client, per_sample=True)` opens a run
per sample instead: the approver reads the running sample from `inspect_ai.log._samples.sample_active()` (a private
module; what is relied on is `sample_active()`, `ActiveSample.sample_uuid` and `ActiveSample.eval_id`, pinned to the
tested inspect-ai 0.3.x in pyproject), opens that sample's run on its first approved
call, and the hook closes it when the sample ends. A sample that retries keeps its run (a retry keeps the sample's uuid),
and each epoch is a separate sample execution with its own run. A call whose sample cannot be told is refused.

Inspect registers a hook once per process, for every eval in it, and runs samples at once: the hook is enabled only
after a Tracekit approver was made, and finds a call by its run and id, which must be unique within that run. A call whose id
is already being decided or still open in its run is refused (Inspect's cache can give two samples one tool-call id, but
with a run per sample each sample's twin lands in its own run), and one
whose arguments changed after the decision (an in-process sentinel's `modify`) is completed as `error`.
"""
import asyncio
import collections
import copy

from inspect_ai.approval import Approval, approver
from inspect_ai.hooks import Hooks, SampleEnd, SampleEvent, hooks
from inspect_ai.log._samples import sample_active
from pydantic_core import to_jsonable_python

from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import result_field

# lean: a call stays here until its ToolEvent or its sample's end, and a twin's count until its ToolEvent; a hook
# missing both leaves them for the process's life. Keys are (run id, tool-call id): two samples may share an id, and
# each sample's call belongs to its own run.
_allowed = {}   # (run_id, tool_call_id) -> (run, the signer's decision, the decided arguments), or None while decided
_twins = collections.Counter()   # (run_id, tool_call_id) -> the calls refused because one of that id was open
_made = False   # whether a Tracekit approver exists, so the hook records for this process's evals
_single = None   # the run tracekit(run) was given, for the hook's single-run lookups
_sample_runs = {}   # (eval_id, sample_id) -> the per-sample run, opened lazily by approve(), closed at sample end


@approver(name="tracekit")
def tracekit(run=None, *, client=None, per_sample=False, agent="inspect"):
    """The approver for `ApprovalPolicy(tracekit(run), "*")`. `run` is a RunHandle (`Client().run(...)`; an AsyncRunHandle
    works too): one run for the whole eval. `tracekit(client, per_sample=True)` opens a run per sample instead, with
    `client` a `Client` and `agent` the name the runs are registered under."""
    global _made, _single
    if per_sample:
        if run is not None:
            raise TypeError("tracekit(per_sample=True) takes client=..., not a run handle")
        if client is None or not callable(getattr(client, "run", None)):
            raise TypeError("tracekit(per_sample=True) needs client=Client()")
    else:
        if client is not None:
            raise TypeError("tracekit(run) takes a run handle, not client=... (use per_sample=True for a client)")
        run = run_handle(run)
        _single = run
    _made = True

    async def sample_run():
        """The run this call records into: the sample's own run in per-sample mode, opened on its first call."""
        active = sample_active()
        if active is None:   # no running sample to key the run by: refuse rather than guess
            return None
        key = (active.eval_id, active.sample_uuid)
        found = _sample_runs.get(key)
        if found is not None:
            return found
        # lean: two calls of one sample at once may both open a run; setdefault keeps the first, the spare is closed
        opened = await asyncio.to_thread(client.run, agent)
        kept = _sample_runs.setdefault(key, opened)
        if kept is not opened:
            try:
                opened.close()   # an empty spare that will not close still leaves the kept run recording the sample
            except Exception:
                pass
        return kept

    async def approve(message, call, view, history):
        call_run = run
        if per_sample:
            call_run = await sample_run()
            if call_run is None:
                return Approval(decision="reject", explanation="Tool call refused by Tracekit: the sample this call "
                                                                "belongs to could not be told")
        key = (call_run.run_id, call.id)
        if key in _allowed:   # its decision and result are found by its id: the open one's would be overwritten
            _twins[key] += 1
            return Approval(decision="reject", explanation=f"Tool call refused by Tracekit: another call with its id "
                                                            f"({call.id}) is still open in this run")
        _allowed[key], d, why = None, None, None
        try:
            d, why = await gate_call(call_run, call.id, 0, call.function, call.arguments, waiter="approver",
                                     who="the sample")
        finally:
            if d is not None and why is None:
                _allowed[key] = (call_run, d, copy.deepcopy(call.arguments))
            else:   # refused, cancelled, or the run's fail mode let it run unrecorded
                _allowed.pop(key, None)
        return Approval(decision="approve") if why is None else Approval(decision="reject", explanation=why)
    return approve


@hooks(name="tracekit", description="Records the outcome of each tool call Tracekit's approver let run")
class Outcomes(Hooks):
    def enabled(self):
        return _made

    def _run(self, data):
        """The run a sample's event belongs to: its per-sample run, else the single run the approver was given."""
        run = _sample_runs.get((data.eval_id, data.sample_id))
        return run if run is not None else _single

    async def on_sample_event(self, data: SampleEvent):
        ev = data.event
        if ev.event != "tool" or ev.pending:
            return
        run = self._run(data)
        if run is None:
            return
        key = (run.run_id, ev.id)
        if ev.error and ev.error.type == "approval" and _twins[key]:   # a twin's refusal, not the open call's
            _twins[key] -= 1
            return
        if _allowed.get(key) is None:   # a call Tracekit refused (an `approval` error) or never saw
            return
        run, d, decided = _allowed.pop(key)
        if ev.arguments != decided:
            await complete(run, d, ev.id, 0, "error", error="the call's arguments changed after the decision")
        elif ev.error:
            await complete(run, d, ev.id, 0, "error", error=ev.error.message[:4096])
        else:
            await complete(run, d, ev.id, 0, "ok", result=result_field(d.get("send_result"),
                                                                      to_jsonable_python(ev.result)))

    async def on_sample_end(self, data: SampleEnd):
        run = _sample_runs.pop((data.eval_id, data.sample_id), None)
        if run is not None:   # the sample's run ends with it: drop its open calls and twins, then close it
            for table in (_allowed, _twins):
                for key in [k for k in table if k[0] == run.run_id]:
                    table.pop(key, None)
            run.close()
            return
        if _single is None:
            return
        for m in data.sample.messages:
            for c in getattr(m, "tool_calls", None) or ():
                _allowed.pop((_single.run_id, c.id), None)
