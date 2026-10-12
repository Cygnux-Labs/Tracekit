"""Tracekit for CrewAI (docs/integrations/crewai.md): CrewAI's global tool hooks decide every tool call before it runs
(an `ask` waits for a person) and record its outcome after. `tracekit.instrument()` registers them.

CrewAI runs the tool when a before hook raises, so these hooks never raise: the before hook blocks by returning False
on anything but an allow or an approved ask (a deny, a rejection, a refusal, an outage under a closed fail mode, an
error of its own), and the after hook gives the model Tracekit's reason instead of CrewAI's "blocked by hook". CrewAI's
hooks carry no tool-call id, so each call gets one of its own, which the after hook finds in a context variable (a
call's hooks run in one context). CrewAI hands the after hook a failed tool's exception as the text "Error executing
tool: ...": that is recorded as an error, the rest as the result the model reads.
"""
import contextvars
import uuid
import warnings

from tracekit.sdk.client import named_rules, result_field

ERROR = "Error executing tool:"
WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer
_call = contextvars.ContextVar("tracekit_crewai_call", default=None)


def hooks(run):
    """(before, after): CrewAI tool hooks recording into `run` (a RunHandle; instrument()'s routes to the current run).
    Register them with crewai.hooks.register_before_tool_call_hook / register_after_tool_call_hook."""

    def before(ctx):
        st = {"id": f"crewai-{uuid.uuid4().hex}", "decision": None, "blocked": None}
        _call.set(st)
        try:
            tool, args = ctx.tool_name, dict(ctx.tool_input or {})
            d = run.decide(st["id"], tool, args)
            why = named_rules(d["rule_ids"]) or d.get("reason") or d["decision"]
            if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
                if d["decision"] == "allow":
                    return None
                st["blocked"] = f"Tool call refused by Tracekit: {d['reason']}"
                return False
            st["decision"], aid = d, None
            if d["decision"] == "deny":
                st["blocked"] = f"Tool call blocked by Tracekit policy: {why}"
                return False
            if d["decision"] == "ask":
                aid = run.call("approval_request", tool_call_id=st["id"])["approval_id"]
                state = run.call("approval_wait", approval_id=aid, timeout_ms=WAIT_MS)["state"]
                if state != "approved":
                    st["blocked"] = f"Tool call held by Tracekit policy ({why}) and not approved: {state}"
                    return False
            c = run.approval_consume(st["id"], tool, args, approval_id_hint=aid)
            if not c["ok"]:
                st["blocked"] = f"Tool call blocked by Tracekit policy: {c.get('reason') or why}"
                return False
            return None
        except Exception as e:   # CrewAI would run the tool over a raised exception
            st["blocked"] = f"Tool call refused: Tracekit could not decide it ({type(e).__name__}: {e})"[:4096]
            return False

    def after(ctx):
        st = _call.get()
        if st is None:
            return None
        _call.set(None)
        if st["blocked"]:
            return st["blocked"]
        if st["decision"] is not None:
            out = ctx.tool_result
            try:
                if isinstance(out, str) and out.startswith(ERROR):
                    run.complete(st["id"], "error", error=out[:4096])
                else:
                    run.complete(st["id"], result=result_field(st["decision"].get("send_result"), out))
            except Exception as e:   # complete never raises for the signer; anything else is ours: never the crew's
                warnings.warn(f"tracekit: the result of {st['id']} was not recorded: {type(e).__name__}: {e}",
                              stacklevel=2)
        return None
    return before, after
