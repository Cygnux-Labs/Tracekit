"""The signer RPC contract, version 4: one JSON Schema per request and response, the error shape, and `SignerAPI`.

Frozen: a change to any schema here is a new RPC_VERSION. The caller's identity comes from the transport (peer
credentials, token, mTLS), never from a request field. Calls that change state carry `request_id`, scoped to that
identity: a retry with the same id and payload gets the original response, the same id with another payload is refused
with `conflict`, and the same id from another identity is a different request.
Per-run calls carry the `run_token` that `register_run` returned. Event calls carry `stream` and `client_seq`
(one counter per client process); a skipped value becomes a signer-written gap record, a reused one is refused.
"""
from typing import Protocol

from tracekit.format.canon import MAX_SAFE_INT
from tracekit.schema import _check

RPC_VERSION = 4
MAX_RAW_ARGS = 1 << 20   # characters of a raw arguments string

ERROR_CODES = [
    "invalid_request",      # fails the request schema
    "unauthenticated",      # the transport could not establish an identity
    "forbidden",            # the identity may not make this call (e.g. an approver who is also the requester)
    "quota_exceeded",       # rate, open-run, pending-approval or size limit; see retry_after_ms
    "unavailable",          # the signer cannot write (disk error, storage lock); retry later
    "run_token_invalid",    # missing, wrong or another run's capability token
    "unknown_run",
    "run_exists",           # register_run with a run_id that is already registered
    "run_closed",           # close_run already accepted for this run
    "conflict",             # request_id reused with a different payload
    "client_seq_reused",    # client_seq at or below the stream's high-water mark, under a new request_id
    "unknown_tool_call",    # approval_request for a tool_call_id the run never decided
    "unknown_decision",     # complete with a decision_id that is not this call's, or already completed
    "args_mismatch",        # complete with arguments other than the decided ones
    "unknown_approval",
    "approval_not_pending",
]

# end of string in both Python and ECMAScript (Python's `$` also matches before a trailing newline)
_END = r"(?![\s\S])"


def _str(n, **kw):
    return {"type": "string", "maxLength": n, **kw}


def _obj(required, **props):
    return {"type": "object", "additionalProperties": False, "required": required, "properties": props}


ID = _str(128, minLength=1, pattern=r"^[A-Za-z0-9._:-]+" + _END)
SEQ = {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INT}
DIGEST = _str(71, pattern=r"^sha256:[0-9a-f]{64}" + _END)
TOKEN = _str(1024, minLength=1)
RULE_IDS = {"type": "array", "maxItems": 32, "items": _str(64)}
REASON = _str(1024)
ANY = {}   # any JSON value; bounded by the transport's line limit
APPROVAL_STATE = {"enum": ["requested", "approved", "rejected", "expired", "consumed"]}

_RUN = dict(request_id=ID, run_id=ID, run_token=TOKEN)
_EVENT = dict(_RUN, stream=ID, client_seq=SEQ)
_RUN_REQ = ["request_id", "run_id", "run_token"]
_EVENT_REQ = _RUN_REQ + ["stream", "client_seq"]
_SEQ_ONLY = _obj(["run_seq"], run_seq=SEQ)

_decide = _obj(_EVENT_REQ + ["tool_call_id", "tool", "args_source", "args"], **_EVENT,
               tool_call_id=ID, attempt=SEQ, tool=_str(256, minLength=1),
               tool_class_hint=_str(64),         # a hint only: the signer classifies the tool itself
               args_source={"enum": ["raw", "parsed", "coerced"]},
               args=ANY)                         # the raw model string when args_source is raw, else the value
_RAW = {"if": {"properties": {"args_source": {"const": "raw"}}}, "then": {"properties": {"args": _str(MAX_RAW_ARGS)}}}
_decide.update(_RAW)
_consume = _obj(_RUN_REQ + ["tool_call_id", "tool", "args_source", "args"], **_RUN, tool_call_id=ID, attempt=SEQ,
                tool=_str(256, minLength=1), args_source={"enum": ["raw", "parsed", "coerced"]}, args=ANY,
                approval_id_hint=ID)   # from the framework's saved state: checked against the signer's index, never trusted
_consume.update(_RAW)
_SUMMARY = _obj(["approval_id", "state", "run_id", "tool_call_id", "attempt", "tool", "rule_ids", "policy_hash",
                 "requester", "expires_at"],
                approval_id=ID, state=APPROVAL_STATE, run_id=ID, tool_call_id=ID, attempt=SEQ, tool=_str(256),
                rule_ids=RULE_IDS, policy_hash=DIGEST, requester=_str(256), expires_at=_str(40))

REQUESTS = {
    "register_run": _obj(["request_id", "agent"], request_id=ID, run_id=ID,
                         tenant=ID, principal=_str(256),   # app-asserted; recorded as not attested
                         source={"const": "migrated"},     # events imported from another log
                         analyzes=ID,                      # a findings run about this run of the same tenant
                         agent=_obj(["name"], name=_str(128, minLength=1), version=_str(64))),
    "decide": _decide,
    "complete": _obj(_EVENT_REQ + ["tool_call_id", "decision_id", "args_digest", "status"], **_EVENT,
                     tool_call_id=ID, attempt=SEQ, decision_id=ID,
                     args_digest=DIGEST,   # sha256(JCS({"tool", "args"})) of the args that ran
                     status={"enum": ["ok", "error"]}, result=ANY, error=_str(4096)),
    "state_write": _obj(_EVENT_REQ + ["key", "value_digest"], **_EVENT, key=_str(256, minLength=1), value_digest=DIGEST),
    "model_event": _obj(_EVENT_REQ + ["provider", "model", "phase"], **_EVENT, provider=_str(64), model=_str(128),
                        phase={"enum": ["request", "response"]}, content_digest=DIGEST,
                        usage=_obj([], input_tokens=SEQ, output_tokens=SEQ)),
    "approval_request": _obj(_RUN_REQ + ["tool_call_id"], **_RUN, tool_call_id=ID, attempt=SEQ,
                             reason=REASON),   # the agent's words: shown to the approver as such, never as the args
    "approval_decide": _obj(["request_id", "approval_id", "decision"], request_id=ID, approval_id=ID,
                            decision={"enum": ["approve", "reject"]}, reason=REASON),
    "approval_wait": _obj(["run_id", "run_token", "approval_id"], run_id=ID, run_token=TOKEN, approval_id=ID,
                          timeout_ms={"type": "integer", "minimum": 0, "maximum": 300000}),
    "approval_consume": _consume,
    "approval_get": _obj(["approval_id"], approval_id=ID),
    "approval_list": _obj([], run_id=ID),
    "close_run": _obj(_RUN_REQ, **_RUN, reason=_str(256)),
    "status": _obj([]),
    "read": _obj(["run_id", "run_token"], run_id=ID, run_token=TOKEN, from_seq=SEQ,
                 limit={"type": "integer", "minimum": 1, "maximum": 1000}),
    "checkpoint_nudge": _obj([]),
}

RESPONSES = {
    "register_run": _obj(["run_id", "run_token", "tenant", "tenant_attested", "principal_attested"],
                         run_id=ID, run_token=TOKEN, tenant=ID, tenant_attested={"type": "boolean"},
                         principal=_str(256), principal_attested={"type": "boolean"},
                         fail_modes={"type": "object", "additionalProperties": {"enum": ["open", "closed"]}}),
    "decide": _obj(["decision", "decision_id", "rule_ids", "run_seq"], decision={"enum": ["allow", "deny", "ask"]},
                   decision_id=ID,   # fresh for every decide; `complete` consumes it once
                   rule_ids=RULE_IDS, reason=REASON, run_seq=SEQ, expires_at=_str(40)),
    "complete": _SEQ_ONLY,
    "state_write": _SEQ_ONLY,
    "model_event": _SEQ_ONLY,
    "approval_request": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE,
                             expires_at=_str(40)),
    "approval_decide": _obj(["approval_id", "state", "self_approved"], approval_id=ID, state=APPROVAL_STATE,
                            self_approved={"type": "boolean"}),   # dev mode only; caps assurance at `dev`
    "approval_wait": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE, reason=REASON),
    # ok: the call may run now (an approval is consumed, or the call needed none); else rule_ids say why not
    "approval_consume": _obj(["ok", "rule_ids"], ok={"type": "boolean"}, rule_ids=RULE_IDS, approval_id=ID,
                             reason=REASON),
    # the signer's copy of the arguments, not the agent's description of them
    "approval_get": dict(_SUMMARY, required=_SUMMARY["required"] + ["args_source", "args", "binding_digest"],
                         properties=dict(_SUMMARY["properties"], args_source={"enum": ["raw", "parsed", "coerced"]},
                                         args=ANY, binding_digest=DIGEST, reason=REASON)),
    "approval_list": _obj(["approvals"], approvals={"type": "array", "maxItems": 1000, "items": _SUMMARY}),
    "close_run": _obj(["run_id", "state", "run_seq"], run_id=ID, state={"const": "closing"}, run_seq=SEQ),
    "status": _obj(["rpc_version", "signer", "identity"], rpc_version={"const": RPC_VERSION},
                   signer=_obj(["name", "version"], name=_str(128), version=_str(64)),
                   identity=_obj(["scheme", "subject", "attested"], scheme=_str(32), subject=_str(256),
                                 attested={"type": "boolean"})),
    "read": _obj(["events", "next_seq"], next_seq={"type": ["integer", "null"], "minimum": 0},
                 events={"type": "array", "maxItems": 1000,
                         "items": {"type": "object", "required": ["run_seq", "type", "event_hash", "data"],
                                   "properties": {"run_seq": SEQ, "type": _str(64), "event_hash": DIGEST,
                                                  "data": {"type": "object"}}}}),
    "checkpoint_nudge": _obj(["scheduled"], scheduled={"type": "boolean"}),
}

ERROR = _obj(["error"], error=_obj(["code", "message"], code={"enum": ERROR_CODES}, message=REASON,
                                   retry_after_ms=SEQ))


def validate(schema, value):
    """Error strings for `value` against one of the schemas above (empty when valid)."""
    errs = []
    _check(value, schema, schema, "$", errs)
    return errs


class RPCError(Exception):
    def __init__(self, code, message, retry_after_ms=None):
        assert code in ERROR_CODES, code
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retry_after_ms = code, message[:1024], retry_after_ms

    def wire(self):
        e = {"code": self.code, "message": self.message}
        if self.retry_after_ms is not None:
            e["retry_after_ms"] = self.retry_after_ms
        return {"error": e}


class SignerAPI(Protocol):
    """Each method takes the request dict for its schema and returns the response dict, or raises RPCError."""

    def register_run(self, req: dict) -> dict: ...
    def decide(self, req: dict) -> dict: ...
    def complete(self, req: dict) -> dict: ...
    def state_write(self, req: dict) -> dict: ...
    def model_event(self, req: dict) -> dict: ...
    def approval_request(self, req: dict) -> dict: ...
    def approval_decide(self, req: dict) -> dict: ...
    def approval_wait(self, req: dict) -> dict: ...
    def approval_consume(self, req: dict) -> dict: ...
    def approval_get(self, req: dict) -> dict: ...
    def approval_list(self, req: dict) -> dict: ...
    def close_run(self, req: dict) -> dict: ...
    def status(self, req: dict) -> dict: ...
    def read(self, req: dict) -> dict: ...
    def checkpoint_nudge(self, req: dict) -> dict: ...
