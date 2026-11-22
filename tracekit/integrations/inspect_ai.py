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

`tracekit(run)` records the whole eval into the one run it was given. `tracekit(client=Client(), per_sample=True)`
opens a run per sample instead: the approver reads the running sample from `inspect_ai.log._samples.sample_active()` (a
private module, checked on inspect-ai 0.3.290; what is relied on is `sample_active()`, `ActiveSample.eval_id` and
`ActiveSample.sample_uuid`, the `sample_id` Inspect gives the hooks), opens that sample's run at its first tool call
(calls made at once wait for the one run), and the hook closes it when the sample ends, a sample cancelled while its run
opened too. A sample that retries keeps its run (a retry keeps the sample's uuid), and each epoch is a separate sample
with its own run. A call whose sample cannot be told, or whose sample's run did not open, is refused.

Inspect registers a hook once per process, for every eval in it, and runs samples at once: the hook is enabled only
after a Tracekit approver was made, and finds a call by its id, which must be unique across the eval, or with a run per
sample by its sample and id. A call whose id is already being decided or still open there is refused (Inspect's cache
can give two samples one tool-call id; with a run per sample each lands in its own run), and one
whose arguments changed after the decision (an in-process sentinel's `modify`) is completed as `error`.
"""
import asyncio
import collections
import copy

from inspect_ai.approval import Approval, approver
from inspect_ai.hooks import Hooks, SampleEnd, SampleEvent, hooks
from pydantic_core import to_jsonable_python

from tracekit.integrations.gate import complete, gate_call, run_handle
from tracekit.sdk.client import AsyncClient, Client, result_field

# lean: a call stays here until its ToolEvent or its sample's end, a twin's count until its ToolEvent, and a sample's
# run until its sample's end; a hook missing them leaves them for the process's life (the signer closes an idle run).
# A call's key: its tool-call id with one run for the eval, (eval id, sample uuid, tool-call id) with a run per sample.
_allowed = {}   # the call's key -> (run, the signer's decision, the decided arguments), or None while it is decided
_twins = collections.Counter()   # the call's key -> the calls refused because one with that key was open
_sample_runs = {}   # (eval id, sample uuid) -> the task that opens that sample's run, with per_sample=True
_made = False   # whether a Tracekit approver exists, so the hook records for this process's evals


@approver(name="tracekit")
def tracekit(run=None, *, client=None, per_sample=False, agent="inspect"):
    """The approver for `ApprovalPolicy(tracekit(run), "*")`. `run` is a RunHandle (`Client().run(...)`; an AsyncRunHandle
    works too): one run for the whole eval. `tracekit(client=Client(), per_sample=True)` opens a run per sample
    instead, registered as `agent` (an AsyncClient works too)."""
    global _made
    if per_sample:
        if run is not None:
            raise TypeError("tracekit(per_sample=True) takes client=..., not a run handle")
        client = client._sync if isinstance(client, AsyncClient) else client
        if not isinstance(client, Client):
            raise TypeError(f"tracekit(per_sample=True) needs client=Client(), not {client!r}")
        from inspect_ai.log._samples import sample_active   # private: what is relied on is in the module's doc
    else:
        if client is not None:
            raise TypeError("tracekit(run) takes a run handle, not client=... (use per_sample=True for a client)")
        run = run_handle(run)
    _made = True

    async def approve(message, call, view, history):
        key, call_run = call.id, run
        if per_sample:
            active = sample_active()
            if active is None:   # no running sample to key the run by: refused, never recorded in another's run
                return Approval(decision="reject", explanation="Tool call refused by Tracekit: the sample this call "
                                                                "belongs to could not be told")
            sample = (active.eval_id, active.sample_uuid)
            if sample not in _sample_runs:   # its first call opens it; a cancel leaves the task for the sample's end
                _sample_runs[sample] = asyncio.ensure_future(asyncio.to_thread(client.run, agent))
            opening = _sample_runs[sample]
            try:
                call_run = await asyncio.shield(opening)
            except Exception as e:   # nothing to record into: refused, and the sample's next call opens one again
                if _sample_runs.get(sample) is opening:
                    del _sample_runs[sample]
                return Approval(decision="reject", explanation=f"Tool call refused by Tracekit: the sample's run did "
                                                                f"not open: {type(e).__name__}: {e}")
            key = (*sample, call.id)
        if key in _allowed:   # its decision and result are found by its key: the open one's would be overwritten
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

    async def on_sample_event(self, data: SampleEvent):
        ev = data.event
        if ev.event != "tool" or ev.pending:
            return
        sample = (data.eval_id, data.sample_id)
        key = (*sample, ev.id) if sample in _sample_runs else ev.id
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
        sample = (data.eval_id, data.sample_id)
        opening = _sample_runs.pop(sample, None)
        if opening is None:   # one run for the eval: the sample's calls that got no ToolEvent are the signer's gaps
            for m in data.sample.messages:
                for c in getattr(m, "tool_calls", None) or ():
                    _allowed.pop(c.id, None)
            return
        for table in (_allowed, _twins):   # its run ends with it, and the signer closes its open calls as gaps
            for key in [k for k in table if isinstance(k, tuple) and k[:2] == sample]:
                del table[key]
        try:
            run = await opening
        except Exception:   # it never opened: its calls were refused
            return
        await asyncio.to_thread(run.close)
