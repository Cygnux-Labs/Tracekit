"""The signer steps the in-process framework integrations share (Pydantic AI, Google ADK, Agent Framework, Haystack,
Strands, LlamaIndex): check the run handle, decide a call (an `ask` waits for a person), consume, record the outcome.
Framework-free: what differs between the integrations comes in as arguments.
"""
import asyncio
import contextlib
import warnings

from tracekit.format.canon import loads_strict
from tracekit.sdk.client import AsyncRunHandle, named_rules

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer
POLL_S = 0.5   # how often a wait for a person checks the agent's cancel signal (Strands' agent.cancel())


def run_handle(run, instrument=False, unwired=""):
    """The RunHandle that does the work of `run` (an AsyncRunHandle wraps one), else a TypeError for `Tracekit(run)`:
    `instrument` names `tracekit.instrument()`'s handle among those it takes, `unwired` adds to the hint for None."""
    if isinstance(run, AsyncRunHandle):
        run = run._sync
    if not callable(getattr(run, "decide", None)):
        takes = "Client().run(...) or tracekit.instrument()'s" if instrument else "Client().run(...)"
        raise TypeError(f"Tracekit(run) needs a run handle, {takes}, not {run!r}"
                        + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                           f"installed{unwired}, so use Client().run(...)" if run is None else ""))
    return run


async def gate_call(run, call_id, attempt, tool, args, *, args_source=None, json_text=False, waiter="hook",
                    who="the agent run", cancelled=None):
    """(the signer's decision, None) when the call may run now, else (the decision, the reason the model reads); the
    decision is None when there is none to complete (an outage the run's fail mode decided, or none was made). Raises
    nothing but CancelledError: a call Tracekit can't decide doesn't run, and an approval whose wait is cancelled (the
    task, or `cancelled`, an Event such as Strands' cancel signal) is withdrawn.

    `args_source` goes to decide and consume when given; with `json_text`, `args` may be the model's JSON text, and the
    signer's approved arguments are compared with it parsed. `who` (what was cancelled) and `waiter` (whose wait ran
    out) name an approval's withdrawal."""
    at, d = {"attempt": attempt}, None
    src = {"args_source": args_source} if args_source else {}
    # lean: each signer call, and an ask's wait of up to 5 minutes, holds a thread of asyncio's default executor;
    # many asks pending at once can starve it, so use an async signer client once one exists
    try:
        d = await asyncio.to_thread(run.decide, call_id, tool, args, **src, **at)
        rules = named_rules(d["rule_ids"]) or d.get("reason") or d["decision"]
        if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
            return None, None if d["decision"] == "allow" else f"Tool call refused by Tracekit: {d['reason']}"
        if d["decision"] == "deny":
            return d, f"Tool call blocked by Tracekit policy: {rules}"
        hint = None
        if d["decision"] == "ask":
            request = asyncio.ensure_future(asyncio.to_thread(run.call, "approval_request", tool_call_id=call_id, **at))
            try:
                hint = (await asyncio.shield(request))["approval_id"]   # a cancel lets it finish, to withdraw it
                if cancelled is None:
                    state = (await asyncio.to_thread(run.call, "approval_wait", approval_id=hint,
                                                     timeout_ms=WAIT_MS))["state"]
                else:
                    wait = asyncio.ensure_future(asyncio.to_thread(run.call, "approval_wait", approval_id=hint,
                                                                   timeout_ms=WAIT_MS))
                    while not (await asyncio.wait({wait}, timeout=POLL_S))[0]:
                        if cancelled.is_set():   # e.g. agent.cancel(): the call won't run, so no one may approve it
                            await asyncio.to_thread(_abandon, run, hint, "the agent was cancelled while it waited")
                            return d, f"Tool call held by Tracekit policy ({rules}) and not approved: cancelled"
                    state = wait.result()["state"]
            except asyncio.CancelledError:   # the task was cancelled: so is the approval, before anyone uses it
                if hint is None:
                    with contextlib.suppress(Exception):   # no approval was requested: nothing to withdraw
                        hint = (await request)["approval_id"]
                if hint is not None:
                    await asyncio.to_thread(_abandon, run, hint, f"{who} was cancelled while it waited")
                raise
            if state != "approved":
                if state == "requested":   # unanswered: withdrawn, so no one approves a call that is gone
                    await asyncio.to_thread(_abandon, run, hint, f"no answer within the {waiter}'s wait")
                return d, f"Tool call held by Tracekit policy ({rules}) and not approved: {state}"
        c = await asyncio.to_thread(run.approval_consume, call_id, tool, args, approval_id_hint=hint, **src, **at)
        why = None
        if not c["ok"]:
            why = f"Tool call blocked by Tracekit policy: {c.get('reason') or rules}"
        elif "args" in c and c["args"] != (loads_strict(args) if json_text and isinstance(args, str) else args):
            why = "Tool call blocked by Tracekit: the arguments the signer approved are not the call's"
        # an allowed call (or a consumed approval) left open would read as a result sent before it was recorded; an
        # ask whose consume was refused stays open: completing it would sign it as run without an approval
        if why is not None and (c["ok"] or d["decision"] != "ask"):
            await complete(run, d, call_id, attempt, "error", error=f"not run: {why}"[:4096])
        return d, why
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return d, f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})"[:4096]


def _abandon(run, approval_id, reason):
    try:
        run.call("approval_abandon", approval_id=approval_id, reason=reason)
    except Exception as e:   # it then expires with the run
        warnings.warn(f"tracekit: approval {approval_id} not withdrawn: {type(e).__name__}: {e}", stacklevel=2)


async def complete(run, d, call_id, attempt, status, **fields):
    """Record the outcome of a call `gate_call` let run under decision `d`; warns, never raises."""
    if d is None:   # ran unrecorded: the signer was unreachable and the run fails open
        return
    try:
        await asyncio.to_thread(run.complete, call_id, status, attempt=attempt, **fields)
    except Exception as e:   # the tool already ran: its result or exception reaches the framework unchanged
        warnings.warn(f"tracekit: the outcome of {call_id} was not recorded: {type(e).__name__}: {e}", stacklevel=2)
