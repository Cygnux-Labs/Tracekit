"""Other policy systems' decision records as `decision_import` requests (tracekit.signer.rpc_schema).

The caller is an identity the signer's `authorize` grants decision_import. The record goes to the signer as the text the
system emitted, so a signature the system made over it still verifies; the signer stores it only as a salted commitment.
None of these systems documents a signature over its records: a deployment that signs them pins its key in the
signer's `decision_keys`.

- `agentcore`: an Amazon Bedrock AgentCore Policy `AuthorizeAction` span, as exported to the CloudWatch `aws/spans`
  log group with Gateway tracing on ("AgentCore generated Policy in AgentCore observability data",
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-policy-metrics.html, read 2026-10-10;
  the page shows no version): `attributes["aws.agentcore.policy.authorization_decision"]` ALLOW|DENY,
  `...authorization_reason`, `...determining_policies` (policy ids). The span names neither the tool nor the tool
  call, so the caller supplies both; the tool as Cedar names it, `<TargetName>___<ToolName>` ("Policy scope",
  .../devguide/policy-understanding-cedar.html).
- `verified_permissions`: an Amazon Verified Permissions IsAuthorized response (API version 2021-12-01,
  https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorized.html): `decision`,
  `determiningPolicies[].policyId`, `errors[].errorDescription`. The tool is the request's `action.actionId`, which
  the response does not carry: the caller supplies it and the tool call id.
- `vscode_hooks`: one Visual Studio Code agent hook (Preview, "Local" format; "Local hooks reference",
  https://code.visualstudio.com/docs/agents/reference/hooks-reference, dated 2026-10-07), whose PreToolUse stdin
  (`tool_name`, `tool_use_id`) and stdout (`hookSpecificOutput.permissionDecision` allow|deny|ask,
  `...permissionDecisionReason`) are separate documents, paired in Tracekit's wrapper {"input": ..., "output": ...}.
- `copilot_hooks`: one GitHub Copilot hook ("GitHub Copilot hooks reference",
  https://docs.github.com/en/copilot/reference/hooks-configuration, read 2026-10-10): stdin `toolName`, stdout flat
  `permissionDecision`, `permissionDecisionReason`, in the same wrapper; it names no tool call, so the caller supplies it.
"""
import json

SPAN = "aws.agentcore.policy."


def _request(record, run_id, request_id, signature, decision, tool_call_id, tool, rule_ids, reason, system):
    req = {"request_id": request_id, "run_id": run_id, "system": system, "decision": decision,
           "tool_call_id": tool_call_id, "tool": tool[:256], "rule_ids": [str(r)[:64] for r in rule_ids][:32],
           "record": record}
    if reason:
        req["reason"] = reason[:1024]
    if signature is not None:
        req["signature"] = signature
    return req


def agentcore(record, run_id, tool_call_id, tool, request_id, signature=None):
    a = json.loads(record)["attributes"]
    return _request(record, run_id, request_id, signature, a[SPAN + "authorization_decision"].lower(), tool_call_id,
                    tool, a.get(SPAN + "determining_policies") or (), a.get(SPAN + "authorization_reason"),
                    "aws-agentcore-policy")


def verified_permissions(record, run_id, tool_call_id, tool, request_id, signature=None):
    r = json.loads(record)
    return _request(record, run_id, request_id, signature, r["decision"].lower(), tool_call_id, tool,
                    [p["policyId"] for p in r.get("determiningPolicies", ())],
                    "; ".join(e["errorDescription"] for e in r.get("errors", ())), "aws-verified-permissions")


def vscode_hooks(record, run_id, request_id, signature=None):
    r = json.loads(record)
    out = r["output"]["hookSpecificOutput"]
    return _request(record, run_id, request_id, signature, out["permissionDecision"], r["input"]["tool_use_id"],
                    r["input"]["tool_name"], (), out.get("permissionDecisionReason"), "vscode-agent-hooks")


def copilot_hooks(record, run_id, tool_call_id, request_id, signature=None):
    r = json.loads(record)
    return _request(record, run_id, request_id, signature, r["output"]["permissionDecision"], tool_call_id,
                    r["input"]["toolName"], (), r["output"].get("permissionDecisionReason"), "github-copilot-hooks")
