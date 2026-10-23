"""Tracekit for Hermes Agent (docs/integrations/hermes.md): the pre_tool_call and post_tool_call hooks of the Hermes
plugin in integrations/hermes/, checked against Hermes v0.22.5 (bf0203a794a07aac3ff764972ab9087baa4e4f4e).

Hermes's agent loop (agent/tool_executor.py) calls pre_tool_call before every tool call, built-in and plugin tools
alike, on a worker thread it waits on for at most `plugins.hook_callback_timeout`, and blocks the call when the callback
times out or raises; the hook also runs inside the call's own tool deadline (`timeouts.tools.*`). The hook decides the
call in the signer under the model's tool_call_id and never raises: it returns Hermes's
`{"action": "block", "message": ...}` for anything but an allowed call or an approved ask (a deny, an approval not given
in time, a refused consume, a signer refusal, a missing tool_call_id, an outage under a closed fail mode, an error of
its own). An `ask` waits for a person inside the callback until MARGIN_S before the earlier of the two limits
(hook_timeout_s); an approval still unanswered then is withdrawn. A call Hermes stopped waiting for (its
post_tool_call, timeout or cancelled, came before the hook let it through: a concurrent batch's deadline, a /stop,
before the hook started or while it ran) is blocked, its approval withdrawn, answered or not. It never answers
Hermes's `approve`: the approval stays with the signer.

post_tool_call completes a call pre_tool_call let through, by its session and tool_call_id: `ok` with the result the
tool returned; `error` for Hermes's error, timeout and cancelled statuses; as not run when another plugin blocked it
after Tracekit allowed it; as an error when the arguments it ran with are not the decided ones (another plugin's
`modify`, or an edit in place).

Each Hermes session is a run (agent "hermes"), registered at its first tool call and closed when Hermes exits; a run
the signer closed after it was idle is replaced at the next call.
"""
import atexit
import copy
import os
import threading
import time
import warnings

from tracekit.sdk.client import Client, named_rules, result_field
from tracekit.signer.rpc_schema import RPCError

AGENT = "hermes"
DEFAULT_TIMEOUT_S, MAX_TIMEOUT_S = 30.0, 600.0   # Hermes's plugins.hook_callback_timeout default and cap
TOOL_TIMEOUT_S = 420.0   # Hermes's default tool deadline (agent/tool_executor.py _DEFAULT_CONCURRENT_TOOL_TIMEOUT_S)
MARGIN_S = 5.0   # lean: what an ask leaves of Hermes's limits for the consume and the answer; raise for a slow signer
POLL_S = 5.0   # an ask looks this often whether Hermes stopped waiting for its call
MAX_OPEN_CALLS = 4096   # calls let through and not completed yet, kept for their post_tool_call
GONE = "Hermes stopped waiting for the call"


def _number(raw):
    """A config or environment value as Hermes reads a number of seconds; None when it falls through (absent, a bool,
    not a number, NaN)."""
    if isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return None if value != value else value


def hook_timeout_s(config, env=os.environ):
    """How long Hermes lets pre_tool_call run, from its config: the least of `plugins.hook_callback_timeout` (as
    hermes_cli.plugins._resolve_hook_callback_timeout reads it: 30 s unless set, at most 600 s, 0 for no bound) and the
    tool deadlines the agent loop runs the hook under (agent/tool_executor.py, agent/deadline.resolve_timeout:
    `timeouts.tools.sequential_call`, else `timeouts.tools.concurrent_batch`, else $HERMES_CONCURRENT_TOOL_TIMEOUT_S,
    else 420 s; 0 or less for none). 0 when nothing bounds it."""
    config = config if isinstance(config, dict) else {}
    plugins, timeouts = config.get("plugins"), config.get("timeouts")
    try:   # a plain float(): Hermes reads `true` here as 1 s
        hook = float(plugins["hook_callback_timeout"])
    except (TypeError, ValueError, KeyError):
        hook = DEFAULT_TIMEOUT_S
    hook = DEFAULT_TIMEOUT_S if hook < 0 else min(hook, MAX_TIMEOUT_S)
    tools = timeouts.get("tools") if isinstance(timeouts, dict) else None
    tools = tools if isinstance(tools, dict) else {}
    batch = _number(tools.get("concurrent_batch"))
    if batch is None:
        batch = _number(env.get("HERMES_CONCURRENT_TOOL_TIMEOUT_S", "").strip() or None)
    batch = TOOL_TIMEOUT_S if batch is None else batch
    sequential = _number(tools.get("sequential_call"))
    sequential = batch if sequential is None else sequential
    bounds = [t for t in (hook, sequential, batch) if t > 0]
    return min(bounds) if bounds else 0.0


def _block(message):
    return {"action": "block", "message": message[:4096]}


def hooks(token=lambda: None, timeout_s=lambda: DEFAULT_TIMEOUT_S):
    """(pre_tool_call, post_tool_call) for Hermes's `ctx.register_hook`. `token()`: a tcp:// signer's token (the plugin
    reads it from Hermes's secret scope at each run's registration), "" for none, None for $TRACEKIT_SIGNER_TOKEN;
    `timeout_s()`: how long Hermes lets the hook run (hook_timeout_s). The signer is the one tracekit.sdk.client.Client
    finds."""
    clients, runs, registering, lock = {}, {}, {}, threading.Lock()
    calls, gone = {}, {}   # (session, call id) -> (run, decision, args) let through; calls Hermes gave up on

    def run_of(session_id):
        with lock:
            if session_id in runs:
                return runs[session_id]
            mine = registering.setdefault(session_id, threading.Lock())
        with mine:   # one registration per session at a time; other sessions don't wait for it
            with lock:
                if session_id in runs:
                    return runs[session_id]
                t = token()
                client = clients[t] = clients.get(t) or Client(token=t)
            run = client.run(AGENT)
            with lock:
                runs[session_id] = run
                registering.pop(session_id, None)
            return run

    def decide(session_id, tool_call_id, tool, args):
        run = run_of(session_id)
        try:
            return run, run.decide(tool_call_id, tool, args)
        except RPCError as e:
            if e.code not in ("run_closed", "unknown_run"):
                raise
        with lock:   # closed after it was idle: the session goes on in a new run
            if runs.get(session_id) is run:
                del runs[session_id]
        run = run_of(session_id)
        return run, run.decide(tool_call_id, tool, args)

    def close():
        for run in list(runs.values()):
            try:
                run.close("Hermes exited")
            except Exception:   # exiting: the signer closes it after its idle timeout
                pass
    atexit.register(close)

    def pre_tool_call(tool_name="", args=None, tool_call_id="", session_id="", **_):
        start, key = time.monotonic(), (session_id, tool_call_id)
        if not tool_call_id:   # never made up: the call's result could not be bound to its decision
            return _block("Tool call blocked by Tracekit: Hermes gave the call no tool_call_id to decide it under")
        args = copy.deepcopy(args) if isinstance(args, dict) else {}   # as decided, whatever changes Hermes's dict
        # Hermes gave up on this very call before its hook ran (a /stop while it waited behind another call's hold):
        # tool_call_ids are unique in a session (agent/turn_tool_validation.py)
        # lean: should an id repeat (compaction dropped the call that used it first), that one call is blocked: fail
        # closed; key the marks by turn too if that happens in practice
        with lock:
            first = gone.pop(key, None)
        if first:
            return _block(f"Tool call blocked by Tracekit: {GONE}")
        try:
            end = start + (timeout_s() or MAX_TIMEOUT_S) - MARGIN_S
            run, d = decide(session_id, tool_call_id, tool_name, args)
            why = named_rules(d["rule_ids"]) or d.get("reason") or d["decision"]
            if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
                return None if d["decision"] == "allow" else _block(f"Tool call refused by Tracekit: {d['reason']}")
            if d["decision"] == "deny":
                return _block(f"Tool call blocked by Tracekit policy: {why}")
            aid = None
            if d["decision"] == "ask":
                r = run.call("approval_request", tool_call_id=tool_call_id)
                aid, state = r["approval_id"], r["state"]
                while state == "requested" and end > time.monotonic() and key not in gone:
                    left_ms = int(min(end - time.monotonic(), POLL_S) * 1000)
                    state = run.call("approval_wait", approval_id=aid, timeout_ms=max(left_ms, 0))["state"]
                if state not in ("requested", "approved"):   # rejected, expired
                    return _block(f"Tool call held by Tracekit policy ({why}) and not approved: {state}")
                if state == "requested" and key not in gone:   # unanswered: withdrawn, so no one approves it later
                    run.call("approval_abandon", approval_id=aid, reason="no answer within Hermes's limits")
                    return _block(f"Tool call held by Tracekit policy ({why}) and not approved: {state}")
            if key in gone:   # its post_tool_call came first (a deadline, a /stop): the call must not run now
                if aid is None:
                    run.complete(tool_call_id, "error", error=f"not run: {GONE}")
                else:   # withdrawn, answered or not, so no one consumes it
                    run.call("approval_abandon", approval_id=aid, reason=GONE)
                return _block(f"Tool call blocked by Tracekit: {GONE}")
            c = run.approval_consume(tool_call_id, tool_name, args, approval_id_hint=aid)
            if not c["ok"]:
                if d["decision"] != "ask":   # an allowed decision left open would read as a call that ran unrecorded
                    run.complete(tool_call_id, "error", error=f"not run: {c.get('reason') or why}"[:4096])
                return _block(f"Tool call blocked by Tracekit policy: {c.get('reason') or why}")
            if "args" in c and c["args"] != args:   # a T2 approval of other arguments: Hermes can't run the signer's copy
                run.complete(tool_call_id, "error", error="not run: the arguments the signer approved are not the call's")
                return _block("Tool call blocked by Tracekit: the arguments the signer approved are not the call's")
        except Exception as e:   # no decision: the call doesn't run
            return _block(f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})")
        with lock:   # with the registration: a post_tool_call during the consume finds the one or the other
            late = gone.pop(key, None)
            if not late:   # by session too: ids are unique only within one (some providers name every call call_0)
                calls[key] = run, d, args
                if len(calls) > MAX_OPEN_CALLS:   # lean: the oldest never got its post_tool_call; dropped, not recorded
                    calls.pop(next(iter(calls)))
        if late:
            run.complete(tool_call_id, "error", error=f"not run: {GONE}")
            return _block(f"Tool call blocked by Tracekit: {GONE}")
        return None

    def post_tool_call(args=None, result=None, tool_call_id="", session_id="", status="", error_message=None, **_):
        key = (session_id, tool_call_id)
        with lock:
            call = calls.pop(key, None)
            if call is None and status in ("timeout", "cancelled"):   # a decision still being made must not let it run
                gone[key] = True
                if len(gone) > MAX_OPEN_CALLS:
                    gone.pop(next(iter(gone)))
        if call is None:   # not let through by pre_tool_call: nothing to bind the result to
            return
        run, d, decided = call
        try:
            if status == "blocked":   # another plugin's block won over Tracekit's allow
                run.complete(tool_call_id, "error", error=f"not run: {error_message or 'blocked'}"[:4096])
            elif (args if isinstance(args, dict) else {}) != decided:   # another plugin's `modify`, or an edit in place
                run.complete(tool_call_id, "error", error="the call's arguments changed after the decision")
            elif status != "ok":   # error, and Hermes's own timeout and cancelled
                run.complete(tool_call_id, "error", error=f"{status}: {error_message or result}"[:4096])
            else:
                run.complete(tool_call_id, "ok", result=result_field(d.get("send_result"), result))
        except Exception as e:   # the tool ran: its result reaches the model either way
            warnings.warn(f"tracekit: the outcome of {tool_call_id} was not recorded: {type(e).__name__}: {e}",
                          stacklevel=2)

    return pre_tool_call, post_tool_call
