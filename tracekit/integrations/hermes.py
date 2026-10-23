"""Tracekit for Hermes Agent (docs/integrations/hermes.md): the pre_tool_call and post_tool_call hooks of the Hermes
plugin in integrations/hermes/, checked against Hermes v0.22.5 (bf0203a794a07aac3ff764972ab9087baa4e4f4e).

Hermes calls pre_tool_call before every tool call, built-in and plugin tools alike, on a worker thread it waits on for
at most `plugins.hook_callback_timeout` (30 s unless set, at most 600 s, 0 for no bound), and blocks the call when the
callback times out or raises. The hook decides the call in the signer under the model's tool_call_id and never raises:
it returns Hermes's `{"action": "block", "message": ...}` for anything but an allowed call or an approved ask (a deny,
an approval not given in time, a refused consume, a signer refusal, a missing tool_call_id, an outage under a closed
fail mode, an error of its own). An `ask` waits for a person inside the callback until MARGIN_S before Hermes's
timeout; an approval still unanswered then is withdrawn. It never answers Hermes's `approve`: the approval stays with
the signer.

post_tool_call completes a call pre_tool_call let through, by its tool_call_id: with Hermes's status and the result the
tool returned; as not run when another plugin blocked it after Tracekit allowed it; as an error when the arguments it
ran with are not the decided ones (another plugin's `modify`).

Each Hermes session is a run (agent "hermes"), registered at its first tool call and closed when Hermes exits; a run
the signer closed after it was idle is replaced at the next call.
"""
import atexit
import copy
import threading
import time
import warnings

from tracekit.sdk.client import Client, named_rules, result_field
from tracekit.signer.rpc_schema import RPCError

AGENT = "hermes"
DEFAULT_TIMEOUT_S, MAX_TIMEOUT_S = 30.0, 600.0   # Hermes's plugins.hook_callback_timeout default and cap
MARGIN_S = 5.0   # lean: what an ask leaves of Hermes's timeout for the consume and the answer; raise for a slow signer
MAX_OPEN_CALLS = 4096   # calls let through and not completed yet, kept for their post_tool_call


def hook_timeout_s(config):
    """`plugins.hook_callback_timeout` from Hermes's config as Hermes applies it (hermes_cli.plugins.
    _resolve_hook_callback_timeout): the default when unset, negative or not a number, capped at 600 s; 0: no bound."""
    try:
        t = float(((config or {}).get("plugins") or {}).get("hook_callback_timeout"))
    except (TypeError, ValueError, AttributeError):
        return DEFAULT_TIMEOUT_S
    return DEFAULT_TIMEOUT_S if t < 0 else min(t, MAX_TIMEOUT_S)


def _block(message):
    return {"action": "block", "message": message[:4096]}


def hooks(token=lambda: None, timeout_s=lambda: DEFAULT_TIMEOUT_S):
    """(pre_tool_call, post_tool_call) for Hermes's `ctx.register_hook`. `token()`: a tcp:// signer's token (the plugin
    reads it from Hermes's secret scope at each run's registration), None for $TRACEKIT_SIGNER_TOKEN; `timeout_s()`:
    Hermes's callback timeout (hook_timeout_s). The signer is the one tracekit.sdk.client.Client finds."""
    clients, runs, calls, lock = {}, {}, {}, threading.Lock()   # calls: tool_call_id -> (run, decision, args)

    def run_of(session_id):
        # lean: a run per Hermes session id for the process's life; drop closed ones if a gateway serves many sessions
        with lock:   # one registration at a time: two first calls of a session must not open two runs
            if session_id not in runs:
                t = token()
                client = clients[t] = clients.get(t) or Client(token=t)
                runs[session_id] = client.run(AGENT)
            return runs[session_id]

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
        start = time.monotonic()
        if not tool_call_id:   # never made up: the call's result could not be bound to its decision
            return _block("Tool call blocked by Tracekit: Hermes gave the call no tool_call_id to decide it under")
        args = copy.deepcopy(args) if isinstance(args, dict) else {}   # as decided, whatever changes Hermes's dict
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
                aid, state = run.call("approval_request", tool_call_id=tool_call_id)["approval_id"], "requested"
                while state == "requested" and end > time.monotonic():
                    left_ms = int(min(end - time.monotonic(), 300) * 1000)
                    state = run.call("approval_wait", approval_id=aid, timeout_ms=max(left_ms, 0))["state"]
                if state != "approved":
                    if state == "requested":   # unanswered: withdrawn, so no one approves a call that never ran
                        run.call("approval_abandon", approval_id=aid, reason="no answer within Hermes's hook timeout")
                    return _block(f"Tool call held by Tracekit policy ({why}) and not approved: {state}")
            c = run.approval_consume(tool_call_id, tool_name, args, approval_id_hint=aid)
            if not c["ok"]:
                return _block(f"Tool call blocked by Tracekit policy: {c.get('reason') or why}")
            if "args" in c and c["args"] != args:   # a T2 approval of other arguments: Hermes can't run the signer's copy
                run.complete(tool_call_id, "error", error="not run: the arguments the signer approved are not the call's")
                return _block("Tool call blocked by Tracekit: the arguments the signer approved are not the call's")
        except Exception as e:   # no decision: the call doesn't run
            return _block(f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})")
        with lock:
            calls[tool_call_id] = run, d, args
            if len(calls) > MAX_OPEN_CALLS:   # lean: the oldest call never got its post_tool_call; dropped, not recorded
                calls.pop(next(iter(calls)))
        return None

    def post_tool_call(args=None, result=None, tool_call_id="", status="", error_message=None, **_):
        with lock:
            call = calls.pop(tool_call_id, None)
        if call is None:   # not let through by pre_tool_call: nothing to bind the result to
            return
        run, d, decided = call
        try:
            if status == "blocked":   # another plugin's block won over Tracekit's allow
                run.complete(tool_call_id, "error", error=f"not run: {error_message or 'blocked'}"[:4096])
            elif (args if isinstance(args, dict) else {}) != decided:   # another plugin's `modify`
                run.complete(tool_call_id, "error", error="the call's arguments changed after the decision")
            elif status == "error":
                run.complete(tool_call_id, "error", error=str(error_message or result)[:4096])
            else:
                run.complete(tool_call_id, "ok", result=result_field(d.get("send_result"), result))
        except Exception as e:   # the tool ran: its result reaches the model either way
            warnings.warn(f"tracekit: the outcome of {tool_call_id} was not recorded: {type(e).__name__}: {e}",
                          stacklevel=2)

    return pre_tool_call, post_tool_call
