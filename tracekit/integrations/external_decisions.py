"""Other policy systems' decision records as `decision_import` requests (tracekit.signer.rpc_schema).

The caller is an identity the signer's `authorize` grants decision_import. The record goes to the signer as the text the
system emitted, so a signature the system made over it still verifies; the signer stores it only as a salted commitment.

- `agentcore`: an Amazon Bedrock AgentCore Policy authorization decision log record (a Cedar decision on a tool call at
  an AgentCore Gateway): `decision` ALLOW|DENY, `action.actionId` the gateway tool, `determiningPolicies[].policyId`,
  `errors[].errorDescription`, modelled on the Amazon Verified Permissions IsAuthorized response. The record names no
  tool call id: the caller supplies the one it correlated.
- `ms_agent_hooks`: one PreToolUse hook's stdin and stdout, which the hook emits as separate documents, paired in
  Tracekit's own wrapper `{"input": {..., "tool_name", "tool_use_id"}, "output": {"hookSpecificOutput":
  {"permissionDecision": allow|deny|ask, "permissionDecisionReason"}}}`.

lean: both shapes, and the fixtures in tests/data/external/, follow no checked documentation version (written without
access to the AgentCore Policy or VS Code agent hooks docs); check them against the published docs before relying on
these mappers for real records.
"""
import json


def _request(record, run_id, request_id, signature, decision, tool_call_id, tool, rule_ids, reason, system):
    req = {"request_id": request_id, "run_id": run_id, "system": system, "decision": decision,
           "tool_call_id": tool_call_id, "tool": tool[:256], "rule_ids": [str(r)[:64] for r in rule_ids][:32],
           "record": record}
    if reason:
        req["reason"] = reason[:1024]
    if signature is not None:
        req["signature"] = signature
    return req


def agentcore(record, run_id, tool_call_id, request_id, signature=None):
    r = json.loads(record)
    return _request(record, run_id, request_id, signature, r["decision"].lower(), tool_call_id, r["action"]["actionId"],
                    [p["policyId"] for p in r.get("determiningPolicies", ())],
                    "; ".join(e["errorDescription"] for e in r.get("errors", ())), "aws-agentcore-policy")


def ms_agent_hooks(record, run_id, request_id, signature=None):
    r = json.loads(record)
    out = r["output"]["hookSpecificOutput"]
    return _request(record, run_id, request_id, signature, out["permissionDecision"], r["input"]["tool_use_id"],
                    r["input"]["tool_name"], [], out.get("permissionDecisionReason"), "ms-agent-hooks")
