"""Tracekit for CrewAI (docs/integrations/crewai.md): CrewAI's global tool hooks decide every tool call before it runs
(an `ask` waits for a person) and record its outcome after. `tracekit.instrument()` registers them.

CrewAI runs the tool when a before hook raises, so these hooks never raise: the before hook blocks by returning False
on anything but an allow or an approved ask (a deny, a rejection, a refusal, an outage under a closed fail mode, an
error of its own), and the after hook gives the model Tracekit's reason instead of CrewAI's "blocked by hook". CrewAI's
hooks carry no tool-call id, so each call gets one of its own, which the after hook finds in a context variable (a
call's hooks run in one context). CrewAI hands the after hook a failed tool's exception as text: "Error executing
tool: ..." on native tool calls, "I encountered an error while trying to use the tool. ..." on its text (ReAct) path.
Either is recorded as an error, the rest as the result the model reads. On the text path CrewAI retries a failing
tool inside one call of its hooks, so the retries run under the call's one decision (docs/limits.md).
"""
import contextvars
import uuid
import warnings

from tracekit.sdk.client import refusal, result_field
from tracekit.integrations import version_check

ERRORS = ("Error executing tool:",                                   # native tool calls
          "I encountered an error while trying to use the tool.")        # the text path (its tool_usage_exception)
WAIT_MS = 300000   # lean: one wait of the signer's cap (5 minutes) for an `ask`; loop to a deadline if people need longer
_call = contextvars.ContextVar("tracekit_crewai_call", default=None)


def hooks(run):
    """(before, after): CrewAI tool hooks recording into `run` (a RunHandle; instrument()'s routes to the current run).
    Register them with crewai.hooks.register_before_tool_call_hook / register_after_tool_call_hook."""
    version_check.warn_untested("CrewAI", "crewai>=1.15.27,<1.16")

    def before(ctx):
        st = {"id": f"crewai-{uuid.uuid4().hex}", "decision": None, "blocked": None}
        _call.set(st)
        try:
            tool, args = ctx.tool_name, dict(ctx.tool_input or {})
            d = run.decide(st["id"], tool, args)
            why = refusal(d) or d["decision"]
            if d.get("unavailable"):   # the run's fail mode decided: nothing to consume or complete
                if d["decision"] == "allow":
                    return None
                st["blocked"] = why
                return False
            if why == "ask":
                w = run.approval_wait(d["approval_request"]["approval_id"], WAIT_MS)
                if w.get("state") == "approved":
                    if not run.approval_consume(d["approval_request"]["approval_id"], st["id"]).get("ok"):
                        st["blocked"] = "approval consumed by another call"
                        return False
                    why = "allow"
                else:
                    st["blocked"] = w.get("reason") or "not approved"
                    return False
            if why != "allow":
                st["blocked"] = why
                return False
            st["decision"] = d
            return None
        except Exception as e:
            st["blocked"] = f"{type(e).__name__}: {e}"
            return False

    def after(ctx):
        st = _call.get()
        if st is None or st["id"] is None:
            return
        try:
            if st["blocked"]:
                run.complete(st["id"], "error", error=st["blocked"])
                ctx.tool_output = st["blocked"]
            else:
                out = ctx.tool_output
                if isinstance(out, str) and any(out.startswith(e) for e in ERRORS):
                    run.complete(st["id"], "error", error=out)
                else:
                    run.complete(st["id"], "result", result=result_field(out))
        except Exception:
            pass
        finally:
            _call.set(None)

    return before, after
