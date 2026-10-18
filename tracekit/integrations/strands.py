"""Tracekit for Strands Agents (docs/integrations/strands.md): a hook provider that asks the signer to decide every tool
call before it runs (an `ask` waits for a person) and records the outcome after.

    from tracekit.integrations.strands import Tracekit
    agent = Agent(model=..., tools=[...], hooks=[Tracekit(run)])

The signer decides the model's own call (its toolUseId and input) in a BeforeToolCallEvent callback that runs before
every other hook. A refused call never runs: `cancel_tool` gives the model Tracekit's reason as an error tool result and
the run goes on. A second callback, after every other hook, keeps that refusal if a hook cleared it, and refuses an
allowed call whose input or tool a hook changed after the decision. The AfterToolCallEvent callback, after every other
hook, records the result the model reads; a call a hook changed after Tracekit's last look is recorded as an error, and
one whose refusal it cleared as run against the decision (the signer signs `executed_against_policy`). A call that runs
again under the same toolUseId (a hook's `retry`, an interrupt resumed) is decided again as the call's next attempt.
"""
import asyncio
import copy
import math
import threading
import warnings

from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookProvider, MultiAgentInitializedEvent

from tracekit.format.canon import event_hash, loads_strict
from tracekit.sdk.client import AsyncRunHandle, named_rules, result_field

WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer
POLL_S = 0.5   # how often a wait for a person checks the agent's cancel signal (agent.cancel())
BACKGROUND = "_background_execution"   # the flag Strands strips from a call's input before it runs (background_tasks)


class Tracekit(HookProvider):
    """Gates and records every tool call of the agent it is given to (`Agent(hooks=[Tracekit(run)])`). `run` is a
    RunHandle (`Client().run(...)`); an AsyncRunHandle works too. One instance may serve several agents, in any threads."""

    def __init__(self, run):
        if isinstance(run, AsyncRunHandle):   # it wraps the RunHandle that does the work
            run = run._sync
        if not callable(getattr(run, "decide", None)):
            raise TypeError(f"Tracekit(run) needs a run handle, Client().run(...), not {run!r}"
                            + (": tracekit.instrument() returns None when none of the frameworks it wires is "
                               "installed, and doesn't wire Strands, so use Client().run(...)" if run is None else ""))
        self.run = run
        self._lock = threading.Lock()
        # lean: one entry per call id for the provider's life, and one per call interrupted and never resumed; prune
        # them at run end if agents run for days
        self._attempts = {}   # toolUseId -> the attempt its next decision is
        self._decided = {}   # id(BeforeToolCallEvent) -> the call as decided: (decision, attempt, refusal, use, tool)
        self._running = {}   # toolUseId -> the call as decided, until its AfterToolCallEvent; None: nothing decided

    def register_hooks(self, registry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self._decide, order=-math.inf)
        registry.add_callback(BeforeToolCallEvent, self._hold, order=math.inf)
        registry.add_callback(AfterToolCallEvent, self._record, order=math.inf)
        registry.add_callback(MultiAgentInitializedEvent, _not_an_orchestrator)

    async def _decide(self, event):
        use = event.tool_use
        call_id = use["toolUseId"]
        with self._lock:   # a sync tool's sub-agent, or agents in other threads, may share this provider
            attempt = self._attempts.get(call_id, 0)
            self._attempts[call_id] = attempt + 1
        d, why = await self._gate(call_id, attempt, use["name"], use.get("input") or {}, event.agent.cancel_signal)
        self._decided[id(event)] = d, attempt, why, copy.deepcopy(use) if d else None, event.selected_tool
        if why is not None:
            event.cancel_tool = why

    def _hold(self, event):
        call = self._decided.pop(id(event))
        d, _, why, use, tool = call
        if why is not None:
            event.cancel_tool = why   # a hook before this one doesn't undo Tracekit's refusal
        elif d is not None and not event.cancel_tool and (event.tool_use != use or event.selected_tool is not tool):
            event.cancel_tool = "Tool call blocked by Tracekit: a hook changed the call after Tracekit decided it"
        self._running[event.tool_use["toolUseId"]] = call if d else None

    async def _record(self, event):
        call = self._running.pop(event.tool_use["toolUseId"], None)
        if call is None:   # nothing decided: run unrecorded, the signer unreachable and the run failing open
            return
        d, _, why, use, tool = call
        r, e = event.result, event.exception
        if event.cancel_message is not None:   # not run
            if why is None:   # refused after the decision, by another hook or by Tracekit's own check
                await self._complete(call, "error", error=f"not run: {event.cancel_message}"[:4096])
        elif _plain(event.tool_use) != _plain(use) or event.selected_tool is not tool:   # after Tracekit's last look
            await self._complete(call, "error", error="the call's arguments changed after the decision")
        elif r.get("status") == "success":
            out = _as_the_model_reads(r.get("content", []))
            await self._complete(call, "ok", result=result_field(d.get("send_result"), out))
        else:
            out = f"{type(e).__name__}: {e}" if e else " ".join(c.get("text", "") for c in r.get("content", []))
            await self._complete(call, "error", error=out[:4096])

    async def _gate(self, call_id, attempt, tool, args, cancelled):
        """(the signer's decision, None) when the call may run now, else (the decision, the reason the model reads); the
        decision is None when there is none to complete (an outage the run's fail mode decided, or none was made).
        Raises nothing but CancelledError: a call Tracekit can't decide doesn't run, and an approval whose wait is
        cancelled (the task, or `cancelled`) is withdrawn."""
        run, at, d = self.run, {"attempt": attempt}, None
        # lean: each signer call, and an ask's wait of up to 5 minutes, holds a thread of asyncio's default executor;
        # many asks pending at once can starve it, so use an async signer client once one exists
        try:
            d = await asyncio.to_thread(run.decide, call_id, tool, args, **at)
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
                    wait = asyncio.ensure_future(asyncio.to_thread(run.call, "approval_wait", approval_id=hint,
                                                                   timeout_ms=WAIT_MS))
                    while not (await asyncio.wait({wait}, timeout=POLL_S))[0]:
                        if cancelled.is_set():   # agent.cancel(): the call won't run, so no one may approve it
                            await asyncio.to_thread(self._abandon, hint, "the agent was cancelled while it waited")
                            return d, f"Tool call held by Tracekit policy ({rules}) and not approved: cancelled"
                    state = wait.result()["state"]
                except asyncio.CancelledError:   # the agent's task was cancelled: so is the approval
                    if hint is None:
                        hint = (await request)["approval_id"]
                    await asyncio.to_thread(self._abandon, hint, "the agent run was cancelled while it waited")
                    raise
                if state != "approved":
                    if state == "requested":   # unanswered: withdrawn, so no one approves a call that is gone
                        await asyncio.to_thread(self._abandon, hint, "no answer within the hook's wait")
                    return d, f"Tool call held by Tracekit policy ({rules}) and not approved: {state}"
            c = await asyncio.to_thread(run.approval_consume, call_id, tool, args, approval_id_hint=hint, **at)
            if not c["ok"]:
                return d, f"Tool call blocked by Tracekit policy: {c.get('reason') or rules}"
            if "args" in c and c["args"] != args:
                return d, "Tool call blocked by Tracekit: the arguments the signer approved are not the call's"
            return d, None
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return d, f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})"[:4096]

    def _abandon(self, approval_id, reason):
        try:
            self.run.call("approval_abandon", approval_id=approval_id, reason=reason)
        except Exception as e:   # it then expires with the run
            warnings.warn(f"tracekit: approval {approval_id} not withdrawn: {type(e).__name__}: {e}", stacklevel=2)

    async def _complete(self, call, status, **fields):
        d, attempt, why, use, _ = call
        try:
            if why is not None:   # refused, and run all the same (a hook cleared the refusal): RunHandle keeps no
                # denied decision to name, so name it, and the signer signs the run as executed against policy
                fields.update(decision_id=d["decision_id"],
                              args_digest=event_hash({"tool": use["name"], "args": use.get("input") or {}}))
            await asyncio.to_thread(self.run.complete, use["toolUseId"], status, attempt=attempt, **fields)
        except Exception as e:   # the call is over: what the model reads is unchanged
            warnings.warn(f"tracekit: the outcome of {use['toolUseId']} was not recorded: {type(e).__name__}: {e}",
                          stacklevel=2)


def _plain(use):
    """A tool use without the flag Strands strips from its input before running it."""
    args = use.get("input")
    return {**use, "input": {k: v for k, v in args.items() if k != BACKGROUND}} if isinstance(args, dict) else use


def _as_the_model_reads(content):
    """A tool result's content as the model reads it: one text block as its text (a JSON object or array as that JSON:
    Strands sends a dict or model a tool returns as its JSON text), one json block as its value, else the blocks. So an
    untrusted tool's values reach the signer's provenance index as values, and the gateway's verified tool results
    find the value the model is sent."""
    if len(content) != 1:
        return content
    if "json" in content[0]:
        return content[0]["json"]
    text = content[0].get("text")
    try:
        v = loads_strict(text)
    except Exception:   # not a text block, or not JSON
        return content if text is None else text
    return v if isinstance(v, (dict, list)) else text


def _not_an_orchestrator(event):
    raise TypeError("Tracekit gates an Agent's tool calls, and a Swarm or Graph fires none: give hooks=[Tracekit(run)] "
                    "to each of its agents instead")
