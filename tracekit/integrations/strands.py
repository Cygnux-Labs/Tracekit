"""Tracekit for Strands Agents (docs/integrations/strands.md): a hook provider that asks the signer to decide every tool
call before it runs (an `ask` waits for a person) and records the outcome after.

    from tracekit.integrations.strands import Tracekit
    agent = Agent(model=..., tools=[...], hooks=[Tracekit(run)])

The signer decides the model's own call (its toolUseId and input) in a BeforeToolCallEvent callback that runs before
every other hook; a call to strands_tools' shell whose `command` it runs as several commands is decided as those
commands (_as_run). A refused call never runs: `cancel_tool` gives the model Tracekit's reason as an error tool result and
the run goes on. A second callback, after every other hook, keeps that refusal if a hook cleared it, and refuses an
allowed call whose input or tool a hook changed after the decision. The AfterToolCallEvent callback, after every other
hook, records the result the model reads; a call a hook changed after Tracekit's last look is recorded as an error, and
one whose refusal it cleared as run against the decision (the signer signs `executed_against_policy`). A call that runs
again under the same toolUseId (a hook's `retry`, an interrupt resumed) is decided again as the call's next attempt.
Each model message is recorded too (tracekit.integrations.said), at AfterModelCallEvent: its reasoning (with the
provider's signature or redacted content), text and tool uses, under their toolUseIds. A message that can't be
recorded only warns.
"""
import asyncio
import copy
import json
import math
import threading
import warnings

from strands.hooks import (AfterModelCallEvent, AfterToolCallEvent, BeforeToolCallEvent, HookProvider,
                           MultiAgentInitializedEvent)

from tracekit.format.canon import event_hash, loads_strict
from tracekit.integrations import said, version_check
from tracekit.integrations.gate import gate_call, run_handle
from tracekit.sdk.client import result_field

BACKGROUND = "_background_execution"   # the flag Strands strips from a call's input before it runs (background_tasks)


class Tracekit(HookProvider):
    """Gates and records every tool call of the agent it is given to (`Agent(hooks=[Tracekit(run)])`). `run` is a
    RunHandle (`Client().run(...)`); an AsyncRunHandle works too. One instance may serve several agents, in any threads."""

    def __init__(self, run):
        version_check.warn_untested("Strands Agents", "strands-agents>=1.61,<1.62")
        self.run = run_handle(run, unwired=", and doesn't wire Strands")
        self._lock = threading.Lock()
        # lean: one entry per call id for the provider's life, and one per call interrupted and never resumed; prune
        # them at run end if agents run for days
        self._attempts = {}   # toolUseId -> the attempt its next decision is
        self._decided = {}   # id(BeforeToolCallEvent) -> the call as decided: (decision, attempt, refusal, use, tool)
        self._running = {}   # toolUseId -> the call as decided, until its AfterToolCallEvent; None: nothing decided
        self.said = said.Said(lambda **f: self.run.call("model_event", **f), lambda: self.run.client.status({}))

    def register_hooks(self, registry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self._decide, order=-math.inf)
        registry.add_callback(BeforeToolCallEvent, self._hold, order=math.inf)
        registry.add_callback(AfterToolCallEvent, self._record, order=math.inf)
        registry.add_callback(AfterModelCallEvent, self._said)
        registry.add_callback(MultiAgentInitializedEvent, _not_an_orchestrator)

    async def _said(self, event):
        if event.stop_response is not None:
            await asyncio.to_thread(self.said, _said(event.stop_response.message.get("content") or ()))

    async def _decide(self, event):
        use = event.tool_use
        call_id = use["toolUseId"]
        with self._lock:   # a sync tool's sub-agent, or agents in other threads, may share this provider
            attempt = self._attempts.get(call_id, 0)
            self._attempts[call_id] = attempt + 1
        seen = copy.deepcopy(use)   # the call as decided: a later hook may change the event's
        args, source = _as_run(event.selected_tool, seen.get("input") or {})
        d, why = await gate_call(self.run, call_id, attempt, use["name"], args, cancelled=event.agent.cancel_signal,
                                 **source)
        self._decided[id(event)] = d, attempt, why, seen if d else None, event.selected_tool, args
        if why is not None:
            event.cancel_tool = why

    def _hold(self, event):
        call = self._decided.pop(id(event))
        d, _, why, use, tool, _ = call
        if why is not None:
            event.cancel_tool = why   # a hook before this one doesn't undo Tracekit's refusal
        elif d is not None and not event.cancel_tool and (event.tool_use != use or event.selected_tool is not tool):
            event.cancel_tool = "Tool call blocked by Tracekit: a hook changed the call after Tracekit decided it"
        self._running[event.tool_use["toolUseId"]] = call if d else None

    async def _record(self, event):
        call = self._running.pop(event.tool_use["toolUseId"], None)
        if call is None:   # nothing decided: run unrecorded, the signer unreachable and the run failing open
            return
        d, _, why, use, tool, _ = call
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

    async def _complete(self, call, status, **fields):
        d, attempt, why, use, _, args = call
        try:
            if why is not None:   # refused, and run all the same (a hook cleared the refusal): RunHandle keeps no
                # denied decision to name, so name it, and the signer signs the run as executed against policy
                fields.update(decision_id=d["decision_id"], args_digest=event_hash({"tool": use["name"], "args": args}))
            await asyncio.to_thread(self.run.complete, use["toolUseId"], status, attempt=attempt, **fields)
        except Exception as e:   # the call is over: what the model reads is unchanged
            warnings.warn(f"tracekit: the outcome of {use['toolUseId']} was not recorded: {type(e).__name__}: {e}",
                          stacklevel=2)


def _said(content):
    """What the model said in a message's content blocks, in order."""
    for b in content:
        r = b.get("reasoningContent")
        if r is not None:
            yield said.thought((r.get("reasoningText") or {}).get("text"),
                               (r.get("reasoningText") or {}).get("signature") or r.get("redactedContent"))
        elif "toolUse" in b:
            u = b["toolUse"]
            yield said.call(u.get("toolUseId"), u.get("name"), u.get("input") or {})
        elif b.get("text"):
            yield said.text(b["text"])


def _as_run(tool, args):
    """(the arguments the signer decides a call by, decide's args_source for them), for the selected tool `tool`.
    strands_tools' shell (0.1 to 0.8: its function's module, the name `shell` being Strands' vended shell's, Codex's
    and OpenAI Agents' too) runs a `command` list, or one {"command": ...}, as several commands, each in a shell of its
    own; a string that is a JSON array too, from 0.3 (0.1 and 0.2 run it as one line). Its call is decided as
    `commands`, which the policy reads each on its own and joined (Engine._parse), not as one argv: such a string as
    written among them, so no command hides from a rule whichever version runs it; labelled coerced (reconcile doesn't
    hold them to the model's tool use). An entry the shell can't run is left out. Any other call as it is: the vended
    shell runs its `command` string as one sh line."""
    command = args.get("command") if isinstance(args, dict) and \
        getattr(getattr(tool, "_tool_func", None), "__module__", None) == "strands_tools.shell" else None
    written = []
    if isinstance(command, str) and command.strip().startswith("[") and command.strip().endswith("]"):
        try:   # as strands_tools' shell reads it
            command, written = json.loads(command), [command]
        except (ValueError, RecursionError):
            pass
    if not isinstance(command, (list, dict)):
        return args, {}
    lines = written + [c if isinstance(c, str) else c.get("command") if isinstance(c, dict) else None
                       for c in (command if isinstance(command, list) else [command])]
    return ({**{k: v for k, v in args.items() if k != "command"}, "commands": [c for c in lines if isinstance(c, str)]},
            {"args_source": "coerced"})


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
