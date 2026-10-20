"""Tracekit for LiteLLM's MCP gateway (docs/integrations/litellm.md): a LiteLLM guardrail that asks the signer to decide
every MCP tool call the LiteLLM proxy runs, before it runs (an `ask` holds it for a person), and records its result.

config.yaml (LiteLLM proxy):
    guardrails:
      - guardrail_name: tracekit
        litellm_params:
          guardrail: tracekit.integrations.litellm.TracekitGuardrail
          mode: pre_mcp_call
          default_on: true
          approval_wait_s: 300

LiteLLM runs the call and holds the upstream credentials, so the guardrail is a gateway in the signer's terms (as
tracekit.mcp_gateway): it decides, consumes and completes each call as `mcp:<server>/<tool>` with `caller`, the agent's
Tracekit identity, under the agent's run token; records are source gateway, tier T2. The LiteLLM proxy's own signer
identity ($TRACEKIT_SIGNER_*, tracekit.sdk.client) is listed under signer.yaml `gateways`.

The run is the request's `X-Tracekit-Run: <run_id>.<run token>` header. The caller is `tracekit_caller` in the metadata
of the LiteLLM key that authenticated the request (set by whoever administers the keys, as LiteLLM's own guardrail
opt-outs are), never anything in the request: the signer accepts the run token only from the identity it was issued to.
A call with no run, no caller, or that the signer denies, refuses or can't be asked about doesn't run: LiteLLM answers
the agent with an error naming the reason (fail closed). An allowed call runs with the arguments the signer consumed
(an approval with a T2 executor: the signer's copy). Its result, or the exception that ended it, is recorded once
LiteLLM logs the call.
"""
import asyncio
import uuid

from tracekit.executor import APPROVAL_WAIT_S, Custody
from tracekit.sdk.client import Client, result_field

RUN_HEADER = "x-tracekit-run"
CALLER = "tracekit_caller"   # the LiteLLM key's metadata field naming the agent's Tracekit identity
CALL = "tracekit_tool_call_id"   # set on the request's logging record, where LiteLLM's result hooks find it
BLOCKED = "Tool call blocked by Tracekit: "


class Hooks:
    """The guardrail's hooks; TracekitGuardrail is these on LiteLLM's CustomGuardrail."""

    def __init__(self, approval_wait_s=APPROVAL_WAIT_S, **kwargs):
        kwargs.setdefault("supported_event_hooks", ["pre_mcp_call"])   # LiteLLM refuses any other `mode` at startup
        super().__init__(**kwargs)
        self.custody = Custody(Client(), approval_wait_s)
        # lean: a call LiteLLM never logs (an interim input-required answer) stays here until the process ends and
        # its run shows held_call_unresolved; expire entries if proxies run for weeks
        self._held = {}   # tool_call_id -> (key, tool_call_id, decision, tool, arguments) of a call let run

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if call_type != "call_mcp_tool":   # list_mcp_tools reaches pre_mcp_call guardrails too
            return None
        headers = (data.get("metadata") or {}).get("headers") or {}
        run = next((v for k, v in headers.items() if k.lower() == RUN_HEADER), "").rsplit(".", 2)
        caller = (getattr(user_api_key_dict, "metadata", None) or {}).get(CALLER)
        log, server, name = data.get("litellm_logging_obj"), data.get("mcp_server_name"), data.get("mcp_tool_name")
        if len(run) != 3 or not all(run):
            return BLOCKED + "no run: send X-Tracekit-Run: <run_id>.<run token> with the MCP request"
        if not caller:
            return BLOCKED + f"the LiteLLM key has no {CALLER} in its metadata: set it to the agent's Tracekit identity"
        if not (server and name and getattr(log, "model_call_details", None) is not None):
            return BLOCKED + "LiteLLM passed no server, tool or request log, so the call's result could not be recorded"
        key, tcid, tool = (run[0], f"{run[1]}.{run[2]}", caller), "litellm-" + uuid.uuid4().hex, f"mcp:{server}/{name}"
        # lean: an `ask` holds a thread of asyncio's default executor for up to approval_wait_s; many at once can starve
        # it, so use an async signer client once one exists
        why, d, args = await asyncio.to_thread(self.custody.gate, key, tcid, tool, data.get("mcp_arguments") or {})
        if why is not None:
            return BLOCKED + why[1]
        self._held[tcid] = (key, tcid, d, tool, args)
        log.model_call_details[CALL] = tcid
        data["modified_arguments"] = args   # what runs: the arguments the signer consumed
        return data

    async def async_post_mcp_tool_call_hook(self, kwargs, response_obj, start_time, end_time):
        held = self._held.pop(kwargs.get(CALL), None)
        if held:   # LiteLLM set original_response to the CallToolResult the agent gets, just before this hook
            res = kwargs.get("original_response")
            out = res.model_dump(mode="json", by_alias=True, exclude_none=True) if hasattr(res, "model_dump") else res
            await asyncio.to_thread(self.custody.complete, *held, "error" if getattr(res, "is_error", False) else "ok",
                                    result=result_field(True, out))
        return None

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        held = self._held.pop(kwargs.get(CALL), None)
        if held:   # the call raised, or a guardrail after this one refused it
            await asyncio.to_thread(self.custody.complete, *held, "error",
                                    error=str(kwargs.get("exception") or "the call failed")[:4096])


def __getattr__(name):
    """TracekitGuardrail, built on LiteLLM's CustomGuardrail when LiteLLM's config loader first asks for it, so this
    module imports without LiteLLM."""
    if name != "TracekitGuardrail":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from litellm.integrations.custom_guardrail import CustomGuardrail
    cls = globals()[name] = type(name, (Hooks, CustomGuardrail), {"__module__": __name__})
    return cls
