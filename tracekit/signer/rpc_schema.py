"""The signer RPC contract, version 20: one JSON Schema per request and response, the error shape, and `SignerAPI`.

Frozen: a change to any schema here is a new RPC_VERSION. Version 20 adds proof-carrying messages (experimental):
`pcm_sign`, `pcm_grant`, `pcm_delegate` and `pcm_evidence`. Version 19 adds `review_finding` (a signed finding of
`tracekit analyze --v2`, in a findings run), `constraint_add` (a live constraint the person's request states; its
response's `refused` past the run's cap), model_event's `amended` (the fields an LLM gateway changed in a request),
its `said_only` (a response recorded without its calls), register_run's `caller` (a gateway registering the run of a
client it serves), observe_effect's `callers` (the identities whose runs a kernel sensor's import covers, required
with `sensor`) and its OpenShell import (sensor `openshell`, an effect's `denied`, and the `policy` and `lost` effects
of one run). Version 18 adds
observe_effect's kernel sensor events (its `sensor`, `lost`, and the exec, exit, connect and file effects). Version 17
(Tracekit 1.3) adds model_event's optional
`tool_results` (a gateway's digests of the tool results a request sends the model) and its response's `refused`.
Version 16 (all of Tracekit 1.2) adds register_run's optional
`parent`, close_run's optional `last_client_seq` (and a gateway's `caller`), `tailer_heartbeat`, args digests on tool uses
the provider ran, agent approvers (approval_review, approval_revoke, approval_agents, approval_decide's `escalate` and
`asserted`, approval_list's filters), containment's operator calls (incident_list, incident_show, incident_resolve,
run_hold, run_quarantine, run_resume, response_pause, response_resume, suspend, unsuspend; decide's `incident_id`) and
`observe_effect`; a signer serves RPC_MIN..RPC_VERSION (its `hello` `proto`), so a version 15 client keeps working
unchanged. Its responses may carry the optional fields version 16 added (an approval's `run_closing`, `escalated`,
`agent`; `status.rpc_version` is the signer's highest): a client ignores fields it doesn't know.
The caller's identity comes from the transport (peer credentials, token, mTLS), never from a request field. Calls that change state carry `request_id`, scoped to that
identity: a retry with the same id and payload gets the original response, the same id with another payload is refused
with `conflict`, and the same id from another identity is a different request.
Per-run calls carry the `run_token` that `register_run` returned. Event calls carry `stream` and `client_seq`
(one counter per client process); a skipped value becomes a signer-written gap record, a reused one is refused.
"""
from typing import Protocol

from tracekit.format.canon import MAX_SAFE_INT
from tracekit.schema import _check

RPC_VERSION = 20
RPC_MIN = 15   # the oldest client version a signer serves
MAX_RAW_ARGS = 1 << 20   # characters of a raw arguments string
MAX_EXTERNAL_RECORD = 1 << 16   # characters of an external system's own decision record
MAX_RESULTS_SENT = 1024
MAX_CALLERS = 256   # identities a kernel sensor's import maps processes to

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
    "conflict",             # request_id reused with a different payload; an observer process another took over from
    "client_seq_reused",    # client_seq at or below the stream's high-water mark, under a new request_id
    "unknown_tool_call",    # approval_request for a tool_call_id the run never decided
    "unknown_decision",     # complete with a decision_id that is not this call's, or already completed
    "args_mismatch",        # complete with arguments other than the decided ones
    "unknown_approval",
    "approval_not_pending",
    "unknown_incident",     # an operator call naming an incident its tenant does not have
]

# end of string in both Python and ECMAScript (Python's `$` also matches before a trailing newline)
_END = r"(?![\s\S])"


def _str(n, **kw):
    return {"type": "string", "maxLength": n, **kw}


def _obj(required, **props):
    return {"type": "object", "additionalProperties": False, "required": required, "properties": props}


ID = _str(128, minLength=1, pattern=r"^[A-Za-z0-9._:-]+" + _END)
SEQ = {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INT}
U32 = {"type": "integer", "minimum": 0, "maximum": 4294967295}
DIGEST = _str(71, pattern=r"^sha256:[0-9a-f]{64}" + _END)
TOKEN = _str(1024, minLength=1)
RULE_IDS = {"type": "array", "maxItems": 32, "items": _str(64)}
REASON = _str(1024)
IDENTITY = _str(256, pattern=r"^[a-z0-9_]+:.+" + _END)   # scheme:subject
HOST = _str(253, minLength=1, pattern=r"^[a-z0-9._:-]+" + _END)   # a host name or IP address, lower case
TS = _str(27, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z" + _END)
SLACK_ID = _str(64, pattern=r"^slack:[A-Z0-9]+/[A-Z0-9]+" + _END)   # slack:<team id>/<user or user group id>
ANY = {}   # any JSON value; bounded by the transport's line limit
APPROVAL_STATE = {"enum": ["requested", "approved", "rejected", "expired", "consumed"]}
B64URL = _str(4096, minLength=1, pattern=r"^[A-Za-z0-9_-]+" + _END)
# the person a bridge (an identity `authorize` grants approval_decide_on_behalf, such as the viewer) acts for, as its OIDC
# login established them; the signer records the bridge too
PERSON = _obj(["subject", "person"], subject=_str(256, minLength=1), person=_str(256, minLength=1),
              groups={"type": "array", "maxItems": 64, "items": _str(256)}, tenant=ID)
# a WebAuthn assertion (identity.webauthn) over webauthn.challenge(approval_id, binding_digest, decision)
PASSKEY = _obj(["credential_id", "client_data_json", "authenticator_data", "signature"], credential_id=B64URL,
               client_data_json=B64URL, authenticator_data=B64URL, signature=B64URL)

_RUN = dict(request_id=ID, run_id=ID, run_token=TOKEN)
_EVENT = dict(_RUN, stream=ID, client_seq=SEQ)
_RUN_REQ = ["request_id", "run_id", "run_token"]
_EVENT_REQ = _RUN_REQ + ["stream", "client_seq"]
_SEQ_ONLY = _obj(["run_seq"], run_seq=SEQ)
# a kernel sensor's event (observe_effect): process `pid` running `binary`, attributed like a net effect; `denied`:
# the sensor (OpenShell) blocked it
_ATTRIBUTED = dict(run_id=ID, run_token=TOKEN, caller=IDENTITY)
_OS = dict(_ATTRIBUTED, ts=TS, pid=U32, binary=_str(4096, minLength=1), exec_id=_str(256, minLength=1), tool_call_id=ID,
           denied={"const": True})
_OS_REQ = ["kind", "ts", "pid", "binary"]

# `caller`, from a `gateways` identity only: the client it authenticated, whose run token the call carries (tier T2)
_decide = _obj(_EVENT_REQ + ["tool_call_id", "tool", "args_source", "args"], **_EVENT, caller=IDENTITY,
               tool_call_id=ID, attempt=SEQ, tool=_str(256, minLength=1),
               tool_class_hint=_str(64),         # a hint only: the signer classifies the tool itself
               args_source={"enum": ["raw", "parsed", "coerced"]},
               args=ANY)                         # the raw model string when args_source is raw, else the value
_RAW = {"if": {"properties": {"args_source": {"const": "raw"}}}, "then": {"properties": {"args": _str(MAX_RAW_ARGS)}}}
_decide.update(_RAW)
_consume = _obj(_RUN_REQ + ["tool_call_id", "tool", "args_source", "args"], **_RUN, caller=IDENTITY, tool_call_id=ID,
                attempt=SEQ,
                tool=_str(256, minLength=1), args_source={"enum": ["raw", "parsed", "coerced"]}, args=ANY,
                approval_id_hint=ID)   # from the framework's saved state: checked against the signer's index, never trusted
_consume.update(_RAW)
# a tool the model asked for: one the client runs has its args digest, or args_unparseable when the raw string failed
# strict parsing; one the provider runs itself has its args digest where the provider returned its input
_TOOL_USE = dict(_obj(["id", "name", "executed_by"], id=ID, name=_str(256, minLength=1),
                      executed_by={"enum": ["client", "provider"]}, args_source={"enum": ["raw", "parsed", "coerced"]},
                      args_digest=DIGEST, args_unparseable={"const": True},
                      id_synthetic={"const": True}),   # the provider gave no id
                 oneOf=[{"additionalProperties": False,
                         "properties": {"id": {}, "name": {}, "executed_by": {"const": "provider"}, "id_synthetic": {}}},
                        {"required": ["args_source", "args_digest"], "additionalProperties": False,
                         "properties": {"id": {}, "name": {}, "executed_by": {"const": "provider"}, "id_synthetic": {},
                                        "args_source": {}, "args_digest": {}}},
                        {"required": ["args_source", "args_digest"], "properties": {"executed_by": {"const": "client"}}},
                        {"required": ["args_source", "args_unparseable"],
                         "properties": {"executed_by": {"const": "client"}}}])
RATE = {"type": "number", "minimum": 0, "maximum": 1}
DIFF = {"type": "number", "minimum": -1, "maximum": 1}
# a finished `tracekit why` test (tracekit/why/signed.py): its counts, what its verdict was decided on (looks, family,
# min_effect, applied, stopped), and the replay runs they came from; `uncounted`: replay runs of the investigation it
# does not count (the surrogate's ranking calls, arms a budget stop abandoned)
COUNT = {"type": "integer", "minimum": 1, "maximum": 4096}
FINDING = _obj(["target", "intervention", "n", "p_with", "p_without", "effect", "interval", "verdict", "replay_runs",
                "models", "rung", "off_tape", "investigation", "looks", "family", "min_effect", "applied", "stopped"],
               target=_str(1024), intervention=_str(1024), n=SEQ, p_with=RATE, p_without=RATE, effect=DIFF,
               interval={"type": "array", "minItems": 2, "maxItems": 2, "items": DIFF},
               verdict={"enum": ["causal", "suppressive", "ruled-out", "inconclusive", "not-applied"]},
               replay_runs={"type": "array", "maxItems": 4096, "items": _obj(
                   ["run_id", "arm", "hit"], run_id=ID, arm={"enum": ["control", "ablated"]}, hit={"type": "boolean"})},
               models={"type": "array", "maxItems": 32, "items": _str(128)}, rung={"enum": [1, 2]}, off_tape=SEQ,
               investigation=ID, looks=COUNT, family=COUNT, min_effect=RATE, applied={"type": "boolean"},
               stopped={"enum": ["decisive", "futility", "n_max", "budget"]},
               uncounted={"type": "array", "maxItems": 4096, "items": _obj(
                   ["run_id", "reason"], run_id=ID, reason={"enum": ["ranking", "budget"]})})
# a signed finding of `tracekit analyze --v2` (review_finding): no text of the run, only the check's rule (the signer
# writes its fixed title), severity, `cites` (records of the analysed run, by run_seq and hash) and digests copied from
# them. A finding names the trust tier of the text it relied on, where that text sits against the call it concerns
# (`order`) and whether redaction changed it; the coverage review (TK-X200) counts per check what it checked, found
# and could not check (by reason code), `partial` for an open run, and the calls by the reasoning readable before them.
# A reviewer model's finding (TK-X210) adds its answer's closed fields (alignment, reason code), what the analyzer
# asserts of the model ({model, version, prompt_hash}) and the model families of the reviewer and the agent; an effect
# check's (TK-X206, TK-X207) the window it joined effects to calls with ({grace_s, skew_s}). Never the explanation.
COVERAGE = "TK-X200"
ALIGNMENTS = ["ok", "drift", "misaligned"]
REVIEW_REASONS = ["none", "unrequested_action", "unexplained_action", "contradicted_reasoning", "scope_creep",
                  "workaround", "false_success", "followed_tool_output", "injection", "other"]
MODEL_FAMILIES = ["anthropic", "openai", "google", "meta", "mistral", "deepseek", "qwen", "xai"]
_NAME = _str(128, minLength=1, pattern=r"^[A-Za-z0-9._:/@+-]+" + _END)   # a model's or a version's name: no prose
_SECONDS = {"type": "number", "minimum": 0, "maximum": 86400}
FINDING_TITLES = {COVERAGE: "Check coverage", "TK-X201": "Action with no reasoning before it",
                  "TK-X202": "Edit of a file not mentioned before", "TK-X203": "Write outside the project",
                  "TK-X204": "Stated constraint broken", "TK-X205": "Success claimed after a failure",
                  "TK-X206": "Effect with no action", "TK-X207": "Action with no effect",
                  "TK-X208": "Prompt the harness never submitted", "TK-X210": "Flagged by the reviewer model",
                  "TK-X101": "Test run claimed, none ran",
                  "TK-X102": "Commit claimed, none ran", "TK-X103": "Push claimed, none ran",
                  "TK-X104": "Install claimed, none ran", "TK-X111": "Push denied, but it ran",
                  "TK-X112": "Deletion denied, but it ran", "TK-X113": "File changes denied, but files changed",
                  "TK-X114": "Network use denied, but it ran", "TK-X120": "Risky action not mentioned",
                  "TK-X211": "Sent, deleted or installed without saying so"}
_CHECKS = [r for r in FINDING_TITLES if r != COVERAGE]
_CHECKED = _obj(["checked", "found"], checked=SEQ, found=SEQ, not_checkable={"type": "array", "maxItems": 16,
                "items": _obj(["reason", "n"], reason=_str(32, minLength=1, pattern=r"^[a-z][a-z_]*" + _END), n=SEQ)})
REVIEW = _obj(["reviewer", "verdict", "cites"], reviewer=_str(128, minLength=1, pattern=r"^[A-Za-z0-9._/+-]+" + _END),
              cites={"type": "array", "maxItems": 256, "items": _obj(["run_seq", "hash"], run_seq=SEQ, hash=DIGEST)},
              verdict={"oneOf": [
                  _obj(["kind", "rule", "severity"], kind={"const": "finding"}, rule={"enum": _CHECKS},
                       severity={"enum": ["info", "low", "medium", "high", "critical"]},
                       tier={"enum": ["gateway", "harness", "transcript", "sdk"]},
                       order={"enum": ["signed_before", "transcript_order", "after"]}, redacted={"type": "boolean"},
                       lifted={"type": "boolean"},
                       digests={"type": "array", "maxItems": 32, "items": DIGEST},
                       alignment={"enum": ALIGNMENTS}, reason={"enum": REVIEW_REASONS},
                       asserted=_obj(["model", "version", "prompt_hash"], model=_NAME, version=_NAME, prompt_hash=DIGEST),
                       families=_obj(["reviewer", "agent"], reviewer={"enum": [*MODEL_FAMILIES, None]},
                                     agent={"type": "array", "maxItems": len(MODEL_FAMILIES),
                                            "items": {"enum": MODEL_FAMILIES}}),
                       window=_obj(["grace_s", "skew_s"], grace_s=_SECONDS, skew_s=_SECONDS)),
                  _obj(["kind", "rule", "severity", "checks"], kind={"const": "coverage"}, rule={"const": COVERAGE},
                       severity={"const": "info"}, checks=_obj([], **dict.fromkeys(_CHECKS, _CHECKED)),
                       partial={"type": "boolean"}, reasoning=_obj([], full=SEQ, summary=SEQ, withheld=SEQ, none=SEQ))]})
# a live constraint (constraint_add): what the person's request says not to do in the rest of the run; the signer
# commits `object` (a file name) and holds a later call that breaks it for a person's approval, never lowering a decision
CONSTRAINT_KINDS = ["keep_away", "only_change", "read_only", "no_push", "no_network"]
_SUMMARY = _obj(["approval_id", "state", "run_id", "tool_call_id", "attempt", "tool", "rule_ids", "policy_hash",
                 "requester", "expires_at"],
                approval_id=ID, state=APPROVAL_STATE, run_id=ID, tool_call_id=ID, attempt=SEQ, tool=_str(256),
                rule_ids=RULE_IDS, policy_hash=DIGEST, requester=_str(256), expires_at=_str(40),
                passkey={"const": True},   # approving needs a passkey assertion
                escalated={"const": True},   # an agent or the signer handed it to people: only people answer it
                agent={"const": True},   # an agent approver's answer (enforce mode) can still decide it
                # who answered (an agent's answer is model output) and, once escalated, by whom and why
                answered=_obj(["by", "kind"], by=_str(256), kind={"enum": ["person", "agent"]}),
                escalation=_obj(["by"], by={"enum": ["agent", "signer"]}, reason=REASON),
                run_closing={"const": True})   # still requested, but its run is closing: no answer can be acted on
# what approval_list shows an agent approver: nothing from the run or the requesting agent
_AGENT_SUMMARY = _obj(["approval_id", "state", "tool", "rule_ids", "policy_hash", "expires_at"],
                      **{k: _SUMMARY["properties"][k] for k in ("approval_id", "state", "tool", "rule_ids",
                                                                "policy_hash", "expires_at", "escalated", "agent",
                                                                "run_closing")})
# proof-carrying messages (tracekit.pcm, experimental): a message the signer signs as the sending run's own agent, with
# a typed intent (`SCHEMA_REF`: a schema document's name and hash), claims with evidence from the sender's run, and a
# chain of grants (root first). `pcm` and `pcm_grant` are integer 0, never `false` or `0.0`.
SCHEMA_REF = _str(136, pattern=r"^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}" + _END)
CLAIM_TYPES = ["tests_passed", "approved_by", "reached_host", "file_written"]
HEX16 = _str(32, pattern=r"^[0-9a-f]{32}" + _END)   # 16 random bytes
_PCM_SIG = _obj(["key", "sig"], key=_str(300, minLength=1), sig=_str(88))   # the log vkey's name+id, base64 Ed25519
_PCM_RECORD = _obj(["event", "hash", "proof"], event=ANY, hash=DIGEST,
                   proof={"type": "array", "maxItems": 64, "items": _str(44)},
                   salt=_str(64, pattern=r"^[0-9a-f]{64}" + _END), args=ANY)   # opens a policy.decision's commitment
_EVIDENCE = _obj(["checkpoint", "records"], checkpoint=_str(16384, minLength=1),
                 records={"type": "array", "minItems": 1, "maxItems": 16, "items": _PCM_RECORD})
_CLAIM = _obj(["type", "args"], type={"enum": CLAIM_TYPES}, args=ANY, evidence=_EVIDENCE)
_CAVEAT = _obj(["field", "op", "value"], field=_str(64, pattern=r"^[a-z][a-z0-9_]*" + _END),
               op={"enum": ["==", "<=", ">=", "<", ">", "in"]}, value=ANY)
_CAVEATS = {"type": "array", "maxItems": 16, "items": _CAVEAT}
# `delegable`: the subject may pass the grant on, only narrower (pcm_delegate); the approving person chose it
PCM_GRANT = _obj(["pcm_grant", "ts", "issuer", "subject", "intent", "caveats", "expires_at", "delegable", "parent",
                  "sig"],
                 pcm_grant={"type": "integer", "const": 0}, ts=TS,
                 issuer=_obj(["kind", "id", "run", "tenant"], kind={"enum": ["person", "agent"]}, id=_str(256),
                             person=_str(256), run=ID, tenant=ID, approval_id=ID),   # tenant: the issuing run's
                 subject=IDENTITY, intent=SCHEMA_REF, caveats=_CAVEATS, expires_at=TS, delegable={"type": "boolean"},
                 parent={"oneOf": [DIGEST, {"type": "null"}]},   # event_hash of the signed parent grant
                 sig=_PCM_SIG)
# the args of the tool call `pcm.grant`, which a person approves and pcm_grant turns into a root grant
GRANT_ARGS = _obj(["subject", "intent", "expires_at", "delegable"], subject=IDENTITY, intent=SCHEMA_REF,
                  caveats=_CAVEATS, expires_at=TS, delegable={"type": "boolean"})
PCM_BODY = _obj(["from", "to", "intent"], to=_obj(["agent"], agent=IDENTITY),
                intent=_obj(["type", "args"], type=SCHEMA_REF, args=ANY),
                claims={"type": "array", "maxItems": 8, "items": _CLAIM},
                grants={"type": "array", "maxItems": 8, "items": PCM_GRANT},
                payload={"oneOf": [_obj(["kind", "text"], kind={"const": "text"}, text=_str(65536)),
                                   _obj(["kind", "data"], kind={"const": "data"}, data=ANY)]},
                **{"from": _obj(["agent", "run", "tenant"], agent=IDENTITY, run=ID, tenant=ID)})
# the signer adds pcm, id, ts and nonce (its clock and randomness) and signs everything but `sig`
PCM_MESSAGE = _obj(["pcm", "id", "ts", "nonce", "sig", *PCM_BODY["required"]], **PCM_BODY["properties"],
                   pcm={"type": "integer", "const": 0}, id=HEX16, ts=TS, nonce=HEX16, sig=_PCM_SIG)

REQUESTS = {
    "register_run": _obj(["request_id", "agent"], request_id=ID, run_id=ID,
                         tenant=ID, principal=_str(256),   # app-asserted; recorded as not attested
                         principal_token=_str(16384),   # an end user's OIDC token: principal attested
                         source={"const": "migrated"},     # events imported from another log
                         analyzes=ID,                      # a findings run about this run of the same tenant
                         replay_of=ID,                     # a replay run (tracekit why) of this run of the same tenant
                         investigation=ID,                 # with replay_of: the investigation it is an arm of
                         # the run that starts this one (a sub-agent's), proven by its token: recorded with the session
                         parent=_obj(["run_id", "run_token"], run_id=ID, run_token=TOKEN),
                         # a gateway registering the run of a client it serves: counted in its open runs for that client
                         caller=IDENTITY,
                         agent=_obj(["name"], name=_str(128, minLength=1), version=_str(64))),
    "decide": _decide,
    "complete": _obj(_EVENT_REQ + ["tool_call_id", "decision_id", "args_digest", "status"], **_EVENT, caller=IDENTITY,
                     tool_call_id=ID, attempt=SEQ, decision_id=ID,
                     args_digest=DIGEST,   # sha256(JCS({"tool", "args"})) of the args that ran
                     status={"enum": ["ok", "error"]}, result=ANY, error=_str(4096),
                     # the client redacted result/error already; recorded as its claim, the signer redacts regardless
                     redacted={"const": True}, redaction=_obj([], rules=RULE_IDS, count=SEQ)),
    # content that entered the run other than as a tool result (the task, a mail, a ticket): recorded as its
    # commitment and indexed for provenance; `trust` is the caller's claim, about content it supplies itself
    "observe": _obj(_EVENT_REQ + ["source", "trust", "value"], **_EVENT, caller=IDENTITY, source=_str(256, minLength=1),
                    trust={"enum": ["trusted", "untrusted"]}, value=ANY),
    "state_write": _obj(_EVENT_REQ + ["key", "value_digest"], **_EVENT, key=_str(256, minLength=1), value_digest=DIGEST,
                        prev_digest={"oneOf": [DIGEST, {"type": "null"}]}),   # the state the write started from
    # agent-reported (L3): what the model asked to run, and the tool results the request sent back
    "model_event": _obj(_EVENT_REQ + ["provider", "model", "phase"], **_EVENT, provider=_str(64), model=_str(128),
                        phase={"enum": ["request", "response"]}, content_digest=DIGEST,
                        exchange_id=ID,   # the same on a call's request and response
                        streamed={"type": "boolean"}, stop_reason=_str(100), error=REASON,
                        usage=_obj([], input_tokens=SEQ, output_tokens=SEQ, cache_read_tokens=SEQ,
                                   cache_write_tokens=SEQ, reasoning_tokens=SEQ),
                        tool_uses={"type": "array", "maxItems": 128, "items": _TOOL_USE},
                        # what the model said, without the calls it asked for (a harness whose hooks name no call, or
                        # report a message's text apart from its calls): reconciliation reads no call from it
                        said_only={"const": True},
                        tool_results_sent={"type": "array", "maxItems": MAX_RESULTS_SENT, "items": ID},
                        # a gateway's: each tool result the request sends, as the values it may have been recorded as
                        # (`digest` event_hash(value), `result_digest` sha256(JCS({"result": value})))
                        tool_results={"type": "array", "maxItems": MAX_RESULTS_SENT, "items": _obj(
                            ["id", "forms"], id=ID, forms={"type": "array", "minItems": 1, "maxItems": 3, "items": _obj(
                                ["digest", "result_digest"], digest=DIGEST, result_digest=DIGEST)})},
                        caller=IDENTITY,   # from a `gateways` identity only: the client it authenticated (source gateway)
                        # with caller, on a request: the JSON pointers of the fields the gateway changed before sending
                        # it (to show reasoning), signed as the record's ext.amended
                        amended={"type": "array", "minItems": 1, "maxItems": 16,
                                 "items": _str(256, pattern=r"^(/([^~/]|~[01])*)+" + _END)},
                        body=ANY),   # the exchange's body, for the content vault when status says it is on
    "approval_request": _obj(_RUN_REQ + ["tool_call_id"], **_RUN, caller=IDENTITY, tool_call_id=ID, attempt=SEQ,
                             reason=REASON),   # the agent's words: shown to the approver as such, never as the args
    "approval_decide": _obj(["request_id", "approval_id", "decision"], request_id=ID, approval_id=ID,
                            decision={"enum": ["approve", "reject", "escalate"]},   # escalate: an agent approver's
                            reason=REASON, on_behalf=PERSON, passkey=PASSKEY,
                            # an agent approver's word for what it runs: recorded as unattested
                            asserted=_obj([], model=_str(128), version=_str(64), prompt_hash=DIGEST)),
    # a chat bridge answers for the person who clicked (`approver`, slack:<team>/<user>), who `groups` (user groups of
    # the same team, slack:<team>/<group>) the bridge found them in; an `authorize` grant, never a default
    "approval_decide_on_behalf": _obj(["request_id", "approval_id", "decision", "approver"], request_id=ID,
                                      approval_id=ID, decision={"enum": ["approve", "reject"]}, approver=SLACK_ID,
                                      groups={"type": "array", "maxItems": 32, "items": SLACK_ID}),
    "approval_wait": _obj(["run_id", "run_token", "approval_id"], run_id=ID, run_token=TOKEN, caller=IDENTITY,
                          approval_id=ID, timeout_ms={"type": "integer", "minimum": 0, "maximum": 300000}),
    "approval_consume": _consume,
    "approval_get": _obj(["approval_id"], approval_id=ID, on_behalf=PERSON),
    # a page of the approvals the caller may see, oldest first; `cursor` is the previous page's next_cursor
    "approval_list": _obj([], run_id=ID, cursor=ID, limit={"type": "integer", "minimum": 1, "maximum": 1000},
                          on_behalf=PERSON, state=APPROVAL_STATE, escalated={"type": "boolean"},
                          # agent: approvals an agent approver may answer now; person: every other one
                          **{"for": {"enum": ["agent", "person"]}}),
    # an agent approver's view of an approval it may answer (an `authorize` grant, never a default)
    "approval_review": _obj(["approval_id"], approval_id=ID),
    # a person vetoes an agent's approval before it is consumed
    "approval_revoke": _obj(["request_id", "approval_id"], request_id=ID, approval_id=ID, reason=REASON,
                            on_behalf=PERSON),
    # the operator's kill switch for agent approvals (an `authorize` grant, never a default)
    "approval_agents": _obj(["request_id", "enabled"], request_id=ID, enabled={"type": "boolean"}, reason=REASON),
    # the adapter will never resume this paused call: the approval ends at once and a later consume is refused
    "approval_abandon": _obj(_RUN_REQ + ["approval_id"], **_RUN, approval_id=ID, reason=REASON),
    # last_client_seq: the last client_seq each of the caller's streams sent; a value the signer never received becomes
    # a client_counter_gap. From a `gateways` identity with `caller` (as model_event): ends the gateway's stream only,
    # the run stays as it is, and a run already final takes it too (the gap goes in the tenant's signer run)
    "close_run": _obj(_RUN_REQ, **_RUN, reason=_str(256), caller=IDENTITY, last_client_seq={
        "type": "array", "maxItems": 64, "items": _obj(["stream", "client_seq"], stream=ID, client_seq=SEQ)}),
    # a token for this run that `identity` (scheme:subject, e.g. a transcript tailer's uid) presents instead of the
    # owner; what it may call is that identity's `authorize` entry
    "delegate_run": _obj(["run_id", "run_token", "identity"], run_id=ID, run_token=TOKEN,
                         identity=IDENTITY),
    # the transcript tailer lost the transcript at `offset` (bytes read): the signer writes the tailer_lost gap
    "tailer_lost": _obj(_RUN_REQ + ["reason", "offset"], **_RUN, reason=REASON, offset=SEQ),
    # the transcript tailer is alive (every service.HEARTBEAT_S); once they stop while the run is open, the signer writes
    # the tailer_lost gap
    "tailer_heartbeat": _obj(["run_id", "run_token"], run_id=ID, run_token=TOKEN),
    # an egress observer's network effects (tracekit.egress; an `authorize` grant, never a default), each attributed
    # by the run token the client presented (run_id, run_token) or by the identity the observer authenticated for the
    # connection (`caller`), which also goes with a token. Every call is the heartbeat of the observer's process
    # `instance`; `check`: refused with run_token_invalid unless the signer issued that token for that run
    # A kernel sensor's import (tracekit.sensor) names its `sensor` in every call: each of its effects is what that
    # sensor says process `pid` did (`tool_call_id`: the id the process's environment carried, the agent's claim);
    # `callers`, in every call: the identities its `runs` map processes to, whose runs it covers (no other run);
    # `lost`: events the sensor or the import dropped, a gap in each run it covers
    "observe_effect": _obj(["request_id", "instance", "effects"], request_id=ID, instance=ID, effects={
        "type": "array", "maxItems": 256, "items": {"oneOf": [_obj(
            ["kind", "host", "port", "bytes_out", "bytes_in", "connections", "first_ts", "last_ts"], run_id=ID,
            run_token=TOKEN, caller=IDENTITY, kind={"const": "net"}, host=HOST,
            port={"type": "integer", "minimum": 1, "maximum": 65535}, bytes_out=SEQ, bytes_in=SEQ, connections=SEQ,
            first_ts=TS, last_ts=TS),
            _obj(_OS_REQ, kind={"const": "exec"}, args_digest=DIGEST, parent_exec_id=_str(256, minLength=1), **_OS),
            _obj(_OS_REQ, kind={"const": "exit"}, status=U32, signal=_str(32), **_OS),
            _obj(_OS_REQ + ["host", "port"], kind={"const": "connect"}, host=HOST,
                 port={"type": "integer", "minimum": 0, "maximum": 65535}, **_OS),
            _obj(_OS_REQ + ["path"], kind={"const": "file"}, path=_str(4096, minLength=1), **_OS),
            # OpenShell's (sensor openshell): a change of the sandbox's policy or configuration, as OpenShell names it,
            # with its hash of the policy, who made it and the digest of its message; and a loss of one run's events
            _obj(["kind", "ts", "change"], kind={"const": "policy"}, ts=TS,
                 change=_str(64, minLength=1, pattern=r"^[a-z0-9_.-]+" + _END), policy_hash=_str(128, minLength=1),
                 by=_str(256, minLength=1), detail_digest=DIGEST, **_ATTRIBUTED),
            _obj(["kind", "reason"], kind={"const": "lost"}, reason=_str(1024, minLength=1), **_ATTRIBUTED)]}},
        check=_obj(["run_id", "run_token"], run_id=ID, run_token=TOKEN),
        sensor={"enum": ["tetragon", "falco", "openshell"]},
        callers={"type": "array", "maxItems": MAX_CALLERS, "items": IDENTITY}, lost=REASON),
    "status": _obj([]),
    "read": _obj(["run_id", "run_token"], run_id=ID, run_token=TOKEN, from_seq=SEQ,
                 limit={"type": "integer", "minimum": 1, "maximum": 1000}),
    "checkpoint_nudge": _obj([]),
    # another system's decision about a tool call of a run of the caller's tenant (an `authorize` grant, never a
    # default); `record` is that system's own record as it emitted it, `signature` its Ed25519 signature over the
    # record's UTF-8 bytes, base64
    "decision_import": _obj(["request_id", "run_id", "system", "decision", "tool_call_id", "tool", "record"],
                            request_id=ID, run_id=ID, system=_str(64, minLength=1),
                            decision={"enum": ["allow", "deny", "ask"]}, tool_call_id=ID, tool=_str(256, minLength=1),
                            rule_ids=RULE_IDS, reason=REASON, record=_str(MAX_EXTERNAL_RECORD, minLength=1),
                            signature=_str(128)),
    # a bridge registers the passkey of the person it acts for (once: a person with a passkey keeps it);
    # `public_key` is the credential's DER SubjectPublicKeyInfo (getPublicKey() in the browser), P-256 or Ed25519
    "passkey_register": _obj(["on_behalf", "credential_id", "public_key"], on_behalf=PERSON, credential_id=B64URL,
                             public_key=B64URL),
    # the content vault (docs/privacy.md): the retained content of records of a run of the caller's tenant, each read
    # recorded as `content.accessed`; `purpose` says why (a case id). The `content_read` grant, never a default
    "content_get": _obj(["run_id", "seqs", "purpose"], run_id=ID,
                        seqs={"type": "array", "maxItems": 1000, "items": SEQ},   # run_seqs
                        purpose=_str(512, minLength=1)),
    # delete a run's retained content for good (`content.erased`); an `authorize` grant, never a default
    "content_erase": _obj(["request_id", "run_id"], request_id=ID, run_id=ID, reason=REASON),
    # a `tracekit why` finding about the run a findings run (register_run `analyzes`) analyses: a why.finding record
    "why_finding": _obj(_RUN_REQ + ["finding"], **_RUN, finding=FINDING),
    # a signed finding of `tracekit analyze --v2` about the run a findings run analyses: a review record
    "review_finding": _obj(_RUN_REQ + ["review"], **_RUN, review=REVIEW),
    # a live constraint of the run (CONSTRAINT_KINDS; keep_away and only_change name the file, `object`): a
    # constraint.added record holding the object's commitment, never its name
    "constraint_add": _obj(_RUN_REQ + ["constraint"], **_RUN, constraint=_obj(
        ["kind"], kind={"enum": CONSTRAINT_KINDS}, object=_str(256, minLength=1))),
    # containment (docs/incidents.md): operator calls, `authorize` grants and never defaults, each in the caller's tenant
    "incident_list": _obj([], state={"enum": ["open", "resolved"]}, cursor=ID,
                          limit={"type": "integer", "minimum": 1, "maximum": 1000}),
    "incident_show": _obj(["incident_id"], incident_id=ID),
    # a person who is not the incident's runs' owner, principal or requester; break-glass with a reason
    "incident_resolve": _obj(["request_id", "incident_id"], request_id=ID, incident_id=ID, reason=REASON),
    **{m: _obj(["request_id", "run_id"], request_id=ID, run_id=ID, reason=REASON)
       for m in ("run_hold", "run_quarantine", "run_resume")},
    # pause the tenant's response engine on this signer (detection keeps recording), or resume it
    **{m: _obj(["request_id"], request_id=ID, reason=REASON) for m in ("response_pause", "response_resume")},
    # the shared suspension list: `identity` (scheme:subject, or a prefix ending in :* or /*) is refused every call
    **{m: _obj(["request_id", "identity"], request_id=ID, identity=IDENTITY, reason=REASON)
       for m in ("suspend", "unsuspend")},
    # proof-carrying messages (experimental), the run's own agent only: sign a message as it (the signer adds pcm, id,
    # ts, nonce and sig); a root grant from the consumed approval of its `pcm.grant` call with these args; a narrower
    # child of a grant held by the caller; and its run's records with inclusion proofs, for claim evidence
    "pcm_sign": _obj(_RUN_REQ + ["message"], **_RUN, message=PCM_BODY),
    "pcm_grant": _obj(_RUN_REQ + ["tool_call_id", "args"], **_RUN, tool_call_id=ID, attempt=SEQ, args=GRANT_ARGS),
    "pcm_delegate": _obj(_RUN_REQ + ["parent", "subject", "expires_at", "delegable"], **_RUN, parent=PCM_GRANT,
                         subject=IDENTITY, caveats=_CAVEATS, expires_at=TS, delegable={"type": "boolean"}),
    "pcm_evidence": _obj(["run_id", "run_token", "run_seqs"], run_id=ID, run_token=TOKEN,
                         run_seqs={"type": "array", "minItems": 1, "maxItems": 16, "items": SEQ}),
}

_FAIL_MODES = {"type": "object", "additionalProperties": {"enum": ["open", "closed"]}}
_INCIDENT = _obj(["incident_id", "run_id", "ts", "trigger", "rule_ids", "scope", "mode", "actions", "state", "runs"],
                 incident_id=ID, run_id=ID, ts=_str(40), trigger=_str(64),
                 rule_ids={"type": "array", "maxItems": 1024, "items": _str(256)},
                 scope=_obj(["kind", "id"], kind={"enum": ["run", "session", "owner", "principal"]}, id=_str(256)),
                 mode={"enum": ["shadow", "enforce"]}, actions={"type": "array", "maxItems": 4, "items": _str(16)},
                 state={"enum": ["open", "resolved"]},
                 # each run the incident held or quarantined, as it stands now
                 runs={"type": "array", "maxItems": 4096, "items": _obj(
                     ["run_id", "state"], run_id=ID, state={"enum": ["held", "quarantined", "resumed", "final"]})})
RESPONSES = {
    "register_run": _obj(["run_id", "run_token", "tenant", "tenant_attested", "principal_attested"],
                         run_id=ID, run_token=TOKEN, tenant=ID, tenant_attested={"type": "boolean"},
                         principal=_str(256), principal_attested={"type": "boolean"},
                         fail_modes=_FAIL_MODES),
    "decide": _obj(["decision", "decision_id", "rule_ids", "run_seq"], decision={"enum": ["allow", "deny", "ask"]},
                   decision_id=ID,   # fresh for every decide; `complete` consumes it once
                   rule_ids=RULE_IDS, reason=REASON, run_seq=SEQ, expires_at=_str(40),
                   # the policy lists the tool as untrusted: `complete` should carry the result itself (the signer
                   # redacts it, commits to it and indexes its values for provenance), not a digest of it
                   send_result={"const": True},
                   incident_id=ID),   # the call is held (ask: a person answers) or quarantined (deny) by this incident
    "complete": _SEQ_ONLY,
    "observe": _SEQ_ONLY,
    "state_write": _SEQ_ONLY,
    # to a gateway: fail_modes; check_results: whether the signer checks tool_results (verify_tool_results), so the
    # gateway sends none when it doesn't; refused: a tool result the request sends is not the one recorded and
    # verify_tool_results is refuse, so the gateway must not forward the request
    "model_event": _obj(["run_seq"], run_seq=SEQ, fail_modes=_FAIL_MODES, check_results={"type": "boolean"},
                        refused=REASON),
    "approval_request": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE,
                             expires_at=_str(40)),
    "approval_decide": _obj(["approval_id", "state", "self_approved"], approval_id=ID, state=APPROVAL_STATE,
                            self_approved={"type": "boolean"},   # dev mode only; caps assurance at `dev`
                            escalated={"const": True},   # an agent's answer handed it to people
                            suggested={"const": True}),   # a shadow-mode agent's answer: recorded, nothing changed
    "approval_decide_on_behalf": _obj(["approval_id", "state", "self_approved"], approval_id=ID, state=APPROVAL_STATE,
                                      self_approved={"type": "boolean"}),
    "approval_wait": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE, reason=REASON,
                          escalated={"const": True}),   # still requested, for people only: keep waiting
    # ok: the call may run now (an approval is consumed, or the call needed none); else rule_ids say why not
    "approval_consume": _obj(["ok", "rule_ids"], ok={"type": "boolean"}, rule_ids=RULE_IDS, approval_id=ID,
                             reason=REASON,
                             args=ANY),   # a T2 approval: the approved args from the signer's copy, to run exactly

    # the signer's copy of the arguments, not the agent's description of them
    "approval_get": dict(_SUMMARY, required=_SUMMARY["required"] + ["args_source", "args", "binding_digest"],
                         properties=dict(_SUMMARY["properties"], args_source={"enum": ["raw", "parsed", "coerced"]},
                                         args=ANY, binding_digest=DIGEST, reason=REASON)),
    "approval_list": _obj(["approvals", "next_cursor"], approvals={"type": "array", "maxItems": 1000,
                                                              "items": {"oneOf": [_SUMMARY, _AGENT_SUMMARY]}},
                          next_cursor={"oneOf": [ID, {"type": "null"}]}),
    "approval_abandon": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE),
    # view_digest: sha256(JCS(the rest of the answer))
    "approval_review": _obj(["approval_id", "tool", "expires_at", "rules", "conditions", "budget", "args", "redacted",
                             "view_digest"], approval_id=ID, tool=_str(256), expires_at=_str(40),
                            rules={"type": "array", "maxItems": 32, "items": _obj(
                                ["id"], id=_str(64), reason=REASON, rationale=REASON)},
                            conditions={"type": "array", "maxItems": 4096, "items": _obj(
                                ["rule", "condition", "passed"], rule=_str(64), condition=REASON,
                                passed={"type": "boolean"})},
                            budget={"type": "object"}, args=ANY,
                            redacted={"type": "array", "maxItems": 4096, "items": _str(4096)},
                            view_digest=DIGEST),
    "approval_revoke": _obj(["approval_id", "state"], approval_id=ID, state=APPROVAL_STATE),
    "approval_agents": _obj(["enabled", "revoked"], enabled={"type": "boolean"},
                            revoked={"type": "array", "maxItems": 100000, "items": ID}),   # the agent approvals revoked
    # open: a gateway's close_run, which ends its stream only
    "close_run": _obj(["run_id", "state", "run_seq"], run_id=ID, state={"enum": ["closing", "open"]}, run_seq=SEQ),
    "delegate_run": _obj(["run_token"], run_token=TOKEN),
    "tailer_lost": _SEQ_ONLY,
    "tailer_heartbeat": _obj([]),
    "observe_effect": _obj(["recorded"], recorded=SEQ),
    "status": _obj(["rpc_version", "signer", "identity"], rpc_version={"const": RPC_VERSION},
                   signer=_obj(["name", "version"], name=_str(128), version=_str(64)),
                   identity=_obj(["scheme", "subject", "attested"], scheme=_str(32), subject=_str(256),
                                 attested={"type": "boolean"}),
                   content=_obj(["max_record_bytes"], max_record_bytes=SEQ)),   # the content vault is on
    "read": _obj(["events", "next_seq"], next_seq={"type": ["integer", "null"], "minimum": 0},
                 events={"type": "array", "maxItems": 1000,
                         "items": {"type": "object", "required": ["run_seq", "type", "event_hash", "data"],
                                   "properties": {"run_seq": SEQ, "type": _str(64), "event_hash": DIGEST,
                                                  "data": {"type": "object"}}}}),
    "checkpoint_nudge": _obj(["scheduled"], scheduled={"type": "boolean"}),
    "decision_import": _obj(["run_seq", "signature"], run_seq=SEQ, signature={"enum": ["verified", "unverified"]}),
    "passkey_register": _obj(["credential_id"], credential_id=B64URL),
    # per seq, in request order: the content and the record's salt (as `tracekit signer reveal` gives it), the content
    # marked redacted (changed by redaction, so it opens no commitment: no salt), or why not
    "content_get": _obj(["items"], items={"type": "array", "maxItems": 1000, "items": dict(
        _obj(["seq"], seq=SEQ, content=ANY, salt=_str(64), redacted={"const": True},
             state={"enum": ["not_retained", "too_large", "erased"]}),
        oneOf=[{"required": ["content", "salt"]}, {"required": ["content", "redacted"]}, {"required": ["state"]}])}),
    "content_erase": _SEQ_ONLY,   # of the content.erased record, in the tenant's signer run (tracekit/signer)
    "why_finding": _SEQ_ONLY,
    "review_finding": _SEQ_ONLY,
    # refused: past the run's file constraint cap the constraint was not added (a constraint_refused gap, run_seq):
    # every write of the run is held from then on
    "constraint_add": _obj(["run_seq"], run_seq=SEQ, refused={"const": True}),
    "incident_list": _obj(["incidents", "next_cursor"], incidents={"type": "array", "maxItems": 1000, "items": _INCIDENT},
                          next_cursor={"oneOf": [ID, {"type": "null"}]}),
    "incident_show": _INCIDENT,
    "incident_resolve": _obj(["incident_id", "resumed"], incident_id=ID,
                             resumed={"type": "array", "maxItems": 4096, "items": ID}),
    **{m: _obj(["run_id", "incident_id", "state"], run_id=ID, incident_id=ID,
               state={"enum": ["held", "quarantined", "resumed"]}) for m in ("run_hold", "run_quarantine", "run_resume")},
    **{m: _obj(["enabled"], enabled={"type": "boolean"}) for m in ("response_pause", "response_resume")},
    **{m: _obj(["identity", "state"], identity=IDENTITY, state={"enum": ["suspended", "lifted"]})
       for m in ("suspend", "unsuspend")},
    "pcm_sign": _obj(["message", "run_seq"], message=PCM_MESSAGE, run_seq=SEQ),
    **{m: _obj(["grant", "run_seq"], grant=PCM_GRANT, run_seq=SEQ) for m in ("pcm_grant", "pcm_delegate")},
    # the latest checkpoint note and, for each record it covers, its inclusion proof under it (a policy.decision's salt
    # too, which opens its args commitment); `pending`: the run_seqs the next checkpoint will cover
    "pcm_evidence": _obj(["checkpoint", "records", "pending"],
                         checkpoint={"oneOf": [_str(16384, minLength=1), {"type": "null"}]},
                         records={"type": "array", "maxItems": 16, "items": _obj(
                             ["run_seq", "event", "hash", "proof"], run_seq=SEQ,
                             **{k: _PCM_RECORD["properties"][k] for k in ("event", "hash", "proof", "salt")})},
                         pending={"type": "array", "maxItems": 16, "items": SEQ}),
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
    def observe(self, req: dict) -> dict: ...
    def state_write(self, req: dict) -> dict: ...
    def model_event(self, req: dict) -> dict: ...
    def approval_request(self, req: dict) -> dict: ...
    def approval_decide(self, req: dict) -> dict: ...
    def approval_decide_on_behalf(self, req: dict) -> dict: ...
    def approval_wait(self, req: dict) -> dict: ...
    def approval_consume(self, req: dict) -> dict: ...
    def approval_get(self, req: dict) -> dict: ...
    def approval_list(self, req: dict) -> dict: ...
    def approval_abandon(self, req: dict) -> dict: ...
    def approval_review(self, req: dict) -> dict: ...
    def approval_revoke(self, req: dict) -> dict: ...
    def approval_agents(self, req: dict) -> dict: ...
    def close_run(self, req: dict) -> dict: ...
    def delegate_run(self, req: dict) -> dict: ...
    def tailer_lost(self, req: dict) -> dict: ...
    def tailer_heartbeat(self, req: dict) -> dict: ...
    def observe_effect(self, req: dict) -> dict: ...
    def status(self, req: dict) -> dict: ...
    def read(self, req: dict) -> dict: ...
    def checkpoint_nudge(self, req: dict) -> dict: ...
    def decision_import(self, req: dict) -> dict: ...
    def passkey_register(self, req: dict) -> dict: ...
    def content_get(self, req: dict) -> dict: ...
    def content_erase(self, req: dict) -> dict: ...
    def why_finding(self, req: dict) -> dict: ...
    def review_finding(self, req: dict) -> dict: ...
    def constraint_add(self, req: dict) -> dict: ...
    def incident_list(self, req: dict) -> dict: ...
    def incident_show(self, req: dict) -> dict: ...
    def incident_resolve(self, req: dict) -> dict: ...
    def run_hold(self, req: dict) -> dict: ...
    def run_quarantine(self, req: dict) -> dict: ...
    def run_resume(self, req: dict) -> dict: ...
    def response_pause(self, req: dict) -> dict: ...
    def response_resume(self, req: dict) -> dict: ...
    def suspend(self, req: dict) -> dict: ...
    def unsuspend(self, req: dict) -> dict: ...
    def pcm_sign(self, req: dict) -> dict: ...
    def pcm_grant(self, req: dict) -> dict: ...
    def pcm_delegate(self, req: dict) -> dict: ...
    def pcm_evidence(self, req: dict) -> dict: ...
