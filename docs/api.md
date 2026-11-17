# Signer API reference

The signer answers one request at a time. A request is one JSON object that names its RPC in the `method` field, sent
to `POST /v2/rpc` over HTTPS (or over the Unix socket on the same machine); the answer is one JSON object. This page
lists what each RPC takes and returns. The field tables are written from `tracekit/signer/rpc_schema.py` by
`scripts/api_doc.py`: edit the schema, run the script, never the tables. How callers connect and prove who they are is
under [Transport and auth](#transport-and-auth).

TODO: finish the introduction once the other sections are written.

## Versioning

TODO: `hello` and its answer; the contract version and the oldest version a signer serves; what each later version added.

## Errors

TODO: the error answer, the error codes, which to retry, and the HTTP statuses.

## Who may call what

TODO: the permission rule in short, and the special cases.

## Runs and calls

### `register_run`

Starts a run, which is one agent session, and returns its `run_id` and a run token. Every later call for the run
presents that token. The signer records the start as `run.registered`. A sub-agent sends its parent's run token in
`parent`, which links the two runs. The fields `tenant`, `source`, `analyzes`, `replay_of` and `box` are for special
callers: the signer refuses them unless its configuration allows the caller to use them.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `register_run`. A box's agent channel may call it too.

<!-- api-doc:begin register_run -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `principal` | text | no | up to 256 characters |
| `principal_token` | text | no | up to 16384 characters |
| `source` | always `migrated` | no |  |
| `analyzes` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `replay_of` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `investigation` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `parent` | object | no |  |
| `parent.run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `parent.run_token` | text | yes | 1 to 1024 characters |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `box` | object | no |  |
| `box.id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `box.image_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `box.channel` | always `agent` | no |  |
| `box.allow` | list of texts | yes | up to 256 items |
| `agent` | object | yes |  |
| `agent.name` | text | yes | 1 to 128 characters |
| `agent.version` | text | no | up to 64 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tenant_attested` | true or false | yes |  |
| `principal` | text | no | up to 256 characters |
| `principal_attested` | true or false | yes |  |
| `fail_modes` | object | no |  |

</details>
<!-- api-doc:end register_run -->

### `delegate_run`

Issues a second run token for the same run to another identity (`identity`, written `scheme:subject`), so that identity
can call the signer for the run instead of the run's owner. What that identity may call is its own `authorize` entry in
the signer's configuration, and a request for an identity with no entry is refused. It is how a transcript tailer gets
its token. A second tailer token for the same run is recorded as a `tailer_redelegated` gap.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `delegate_run`.

<!-- api-doc:begin delegate_run -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_token` | text | yes | 1 to 1024 characters |

</details>
<!-- api-doc:end delegate_run -->

### `decide`

Asks whether a tool call may run. The client sends the tool name and its arguments, how it got the arguments
(`args_source`: `raw`, `parsed` or `coerced`), and its own call id (`tool_call_id`) and attempt number. The signer
answers `allow`, `deny` or `ask`, with the ids of the rules that matched and a `decision_id`, and signs the decision. An
`ask` means a person must approve the call first: see the Approvals group. A deny or ask is remembered per call id and
attempt, so a retry of the same attempt gets the same answer.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `decide`. A box's agent channel may call it too.

<!-- api-doc:begin decide -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `client_seq` | whole number | yes |  |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | no |  |
| `tool` | text | yes | 1 to 256 characters |
| `tool_class_hint` | text | no | up to 64 characters |
| `args_source` | one of `raw`, `parsed`, `coerced` | yes |  |
| `args` | any value | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `decision` | one of `allow`, `deny`, `ask` | yes |  |
| `decision_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `rule_ids` | list of texts | yes | up to 32 items |
| `reason` | text | no | up to 1024 characters |
| `run_seq` | whole number | yes |  |
| `expires_at` | text | no | up to 40 characters |
| `send_result` | always `true` | no |  |
| `incident_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

</details>
<!-- api-doc:end decide -->

### `complete`

Reports the result of a tool call that was decided. The client sends the `decision_id`, the digest of the arguments it
actually ran, and the result or error. The signer checks that the digest matches the decision (otherwise
`args_mismatch`), removes secrets from the result, and records a commitment to it. If the call ran after a deny, or
after an ask with no consumed approval, the signer also records an `executed_against_policy` gap.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `complete`. A box's agent channel may call it too.

<!-- api-doc:begin complete -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `client_seq` | whole number | yes |  |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | no |  |
| `decision_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `args_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `status` | one of `ok`, `error` | yes |  |
| `result` | any value | no |  |
| `error` | text | no | up to 4096 characters |
| `redacted` | always `true` | no |  |
| `redaction` | object | no |  |
| `redaction.rules` | list of texts | no | up to 32 items |
| `redaction.count` | whole number | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end complete -->

### `observe`

Records content that entered the run other than as a tool result, such as the task, a mail or a ticket. The signer
records a commitment to the value, not the value itself, and indexes it so that later calls can be traced back to it.
`trust` (`trusted` or `untrusted`) is the caller's own claim about content it supplies itself.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `observe`. A box's agent channel may call it too.

<!-- api-doc:begin observe -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `client_seq` | whole number | yes |  |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `source` | text | yes | 1 to 256 characters |
| `trust` | one of `trusted`, `untrusted` | yes |  |
| `value` | any value | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end observe -->

### `observe_effect`

Reports effects seen from outside the agent: network connections from an egress observer, and process starts, exits and
connections from a kernel sensor. Each call also counts as a heartbeat of the observer's process (`instance`).

**Who may call:** only a caller whose `authorize` entry lists `observe_effect`. It is never granted by default.

<!-- api-doc:begin observe_effect -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `instance` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects` | list of objects | yes | up to 256 items |
| `check` | object | no |  |
| `check.run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `check.run_token` | text | yes | 1 to 1024 characters |
| `sensor` | one of `tetragon`, `falco`, `openshell` | no |  |
| `callers` | list of texts | no | up to 256 items |
| `lost` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `recorded` | whole number | yes |  |

</details>
<!-- api-doc:end observe_effect -->

### `state_write`

Records a digest of a piece of the agent's saved state under a `key`, so that tampering with the state can be detected.
If `prev_digest` says the write started from a state other than the one the agent's own earlier write recorded, the
signer records a `state_tamper` gap.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `state_write`. A box's agent channel may call it too.

<!-- api-doc:begin state_write -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `client_seq` | whole number | yes |  |
| `key` | text | yes | 1 to 256 characters |
| `value_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `prev_digest` | text or nothing | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end state_write -->

### `model_event`

Records a model call: its `phase` (`request` or `response`), the provider and model, token usage, and the tool calls the
model asked for. A client uses it when no gateway records the model calls for it. An LLM gateway sends it with `caller`,
naming the client it acts for, and its answer then also carries the signer's fail modes and whether the signer checks
tool results.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `model_event`. A box's agent channel may call it too.

<!-- api-doc:begin model_event -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `client_seq` | whole number | yes |  |
| `provider` | text | yes | up to 64 characters |
| `model` | text | yes | up to 128 characters |
| `phase` | one of `request`, `response` | yes |  |
| `content_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `exchange_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `streamed` | true or false | no |  |
| `stop_reason` | text | no | up to 100 characters |
| `error` | text | no | up to 1024 characters |
| `usage` | object | no |  |
| `usage.input_tokens` | whole number | no |  |
| `usage.output_tokens` | whole number | no |  |
| `usage.cache_read_tokens` | whole number | no |  |
| `usage.cache_write_tokens` | whole number | no |  |
| `usage.reasoning_tokens` | whole number | no |  |
| `tool_uses` | list of objects | no | up to 128 items |
| `tool_uses[].id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_uses[].name` | text | yes | 1 to 256 characters |
| `tool_uses[].executed_by` | one of `client`, `provider` | yes |  |
| `tool_uses[].args_source` | one of `raw`, `parsed`, `coerced` | no |  |
| `tool_uses[].args_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `tool_uses[].args_unparseable` | always `true` | no |  |
| `tool_uses[].id_synthetic` | always `true` | no |  |
| `said_only` | always `true` | no |  |
| `tool_results_sent` | list of texts | no | up to 1024 items |
| `tool_results` | list of objects | no | up to 1024 items |
| `tool_results[].id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_results[].forms` | list of objects | yes | up to 3 items |
| `tool_results[].forms[].digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `tool_results[].forms[].result_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `amended` | list of texts | no | up to 16 items |
| `body` | any value | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |
| `fail_modes` | object | no |  |
| `check_results` | true or false | no |  |
| `refused` | text | no | up to 1024 characters |

</details>
<!-- api-doc:end model_event -->

### `decision_import`

Records another system's decision about a tool call as a `policy.external` record: the system's name, its decision
(`allow`, `deny` or `ask`), and a commitment to that system's own record. If the signer is configured with the system's
public key, the record must carry a valid signature and the answer says `verified`; otherwise it says `unverified`. The
signer's own decision stays authoritative, and reconciliation compares the two.

**Who may call:** only a caller whose `authorize` entry lists `decision_import`. It is never granted by default.

<!-- api-doc:begin decision_import -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `system` | text | yes | 1 to 64 characters |
| `decision` | one of `allow`, `deny`, `ask` | yes |  |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool` | text | yes | 1 to 256 characters |
| `rule_ids` | list of texts | no | up to 32 items |
| `reason` | text | no | up to 1024 characters |
| `record` | text | yes | 1 to 65536 characters |
| `signature` | text | no | up to 128 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |
| `signature` | one of `verified`, `unverified` | yes |  |

</details>
<!-- api-doc:end decision_import -->

### `close_run`

Ends a run. The signer writes `run.closing`, allows a short grace window for late records, then writes the completeness
gaps, the reconciliation findings and `run.final`. `last_client_seq` gives the last `client_seq` each of the caller's
streams sent, and a number the signer never received becomes a `client_counter_gap`. A gateway that sends `caller` ends
only its own stream for that client.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `close_run`. A box's agent channel may call it too.

<!-- api-doc:begin close_run -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `reason` | text | no | up to 256 characters |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `last_client_seq` | list of objects | no | up to 64 items |
| `last_client_seq[].stream` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `last_client_seq[].client_seq` | whole number | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `closing`, `open` | yes |  |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end close_run -->

### `call_state`

Reads what the signer recorded about the latest attempt of a call: its decision, its approval and whether this attempt
consumed it, and its result. It answers with an empty object for a call that was never decided, and writes nothing.
Added in version 24. The LangChain adapter uses it to carry on with a call after a run resumes.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `call_state`.

<!-- api-doc:begin call_state -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `args_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `attempt` | whole number | no |  |
| `decision` | one of `allow`, `deny`, `ask` | no |  |
| `decision_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `rule_ids` | list of texts | no | up to 32 items |
| `reason` | text | no | up to 1024 characters |
| `send_result` | always `true` | no |  |
| `same_args` | true or false | no |  |
| `approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | no |  |
| `consumed` | true or false | no |  |
| `refused` | list of texts | no | up to 32 items |
| `result` | object | no |  |
| `result.run_seq` | whole number | yes |  |
| `result.ok` | true or false | yes |  |

</details>
<!-- api-doc:end call_state -->

### `call_claim`

Claims the one pass that goes on with an approved call after its tool paused the run itself. The first claim for a call,
attempt and `answers` count gets `ok: true`; any other gets `ok: false` with a `reason`, so two resumes of the same
thread never run the call twice. A claim is also refused when the attempt consumed no approval, when the call already
has a result, or when the signer restarted since the approval was used (a person then approves the call again). It
writes no record. Added in version 24.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `call_claim`.

<!-- api-doc:begin call_claim -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | yes |  |
| `answers` | whole number | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `ok` | true or false | yes |  |
| `reason` | text | no | up to 1024 characters |

</details>
<!-- api-doc:end call_claim -->

## Approvals

### `approval_request`

Asks for a person's approval of a call that `decide` answered with `ask`. The signer signs an `approval.request` with a
random `approval_id`, the rule ids, the requester's identity, an expiry, and a binding to the exact tool and arguments
of this one call. Asking again for the same call attempt returns the same approval, whatever its state. `reason` is the
agent's own words: the approver sees it marked as unverified, never as the arguments.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_request`. A box's agent channel may call it too.

<!-- api-doc:begin approval_request -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | no |  |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `expires_at` | text | no | up to 40 characters |

</details>
<!-- api-doc:end approval_request -->

### `approval_wait`

Waits up to `timeout_ms` (at most 300000, five minutes) for an approval to leave `requested`, then answers with its
state. An approval an agent approver has approved still reads `requested` until the delay in which a person may revoke
it has passed; its `reason` then says how many seconds to wait. A rejected approval's `reason` says who rejected or
revoked it, and `escalated` is true when an agent approver handed it to people.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_wait`. A box's agent channel may call it too.

<!-- api-doc:begin approval_wait -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `timeout_ms` | whole number | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `reason` | text | no | up to 1024 characters |
| `escalated` | always `true` | no |  |

</details>
<!-- api-doc:end approval_wait -->

### `approval_get`

Reads one approval: its state, the tool, the rule ids, the requester, the expiry, the signer's own redacted copy of the
arguments, and the binding digest. The caller sees only the approvals it may see, which are those of its own runs and
those it may answer; another tenant's are never shown. A bridge, such as the viewer, sends `on_behalf` to read as the
person who signed in.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_get`. A box's agent channel may call it too.

<!-- api-doc:begin approval_get -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `on_behalf` | object | no |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | yes |  |
| `tool` | text | yes | up to 256 characters |
| `rule_ids` | list of texts | yes | up to 32 items |
| `policy_hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `requester` | text | yes | up to 256 characters |
| `expires_at` | text | yes | up to 40 characters |
| `passkey` | always `true` | no |  |
| `escalated` | always `true` | no |  |
| `agent` | always `true` | no |  |
| `answered` | object | no |  |
| `answered.by` | text | yes | up to 256 characters |
| `answered.kind` | one of `person`, `agent` | yes |  |
| `escalation` | object | no |  |
| `escalation.by` | one of `agent`, `signer` | yes |  |
| `escalation.reason` | text | no | up to 1024 characters |
| `run_closing` | always `true` | no |  |
| `args_source` | one of `raw`, `parsed`, `coerced` | yes |  |
| `args` | any value | yes |  |
| `binding_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

</details>
<!-- api-doc:end approval_get -->

### `approval_list`

Lists the approvals the caller may see, a page at a time, oldest first. Send the previous answer's `next_cursor` as
`cursor` to get the next page. `state`, `escalated` and `for` narrow the list: `for: agent` gives the approvals an agent
approver may answer now, and `for: person` gives all the others. An agent approver lists without `run_id`, and the
signer refuses the request if it sends one.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_list`. An agent approver may call it too, with an `authorize` entry that lists it.

<!-- api-doc:begin approval_list -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `cursor` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `limit` | whole number | no | at least 1 |
| `on_behalf` | object | no |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | no |  |
| `escalated` | true or false | no |  |
| `for` | one of `agent`, `person` | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approvals` | list of objects | yes | up to 1000 items |
| `next_cursor` | text or nothing | yes |  |

</details>
<!-- api-doc:end approval_list -->

### `approval_decide`

Answers a held call: `approve` or `reject`. `escalate` is an agent approver's answer, and the signer refuses it from a
person. The signer records who answered as its transport established it, and whether the approver is the call's own
requester (`self_approved`). The requester, the run's owner and its principal may not answer unless the signer allows
self-approval, and a break-glass identity must give a `reason`. A call marked as high risk needs a `passkey` assertion
to be approved, and a rejection needs none. A bridge, such as the viewer, sends `on_behalf` to answer as the person who
signed in. An agent approver in shadow mode gets `suggested: true`, and its answer changes nothing.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_decide`. An agent approver may call it too, with an `authorize` entry that lists it. Whether the caller
may answer a given approval is decided by the signer's `approvals` configuration: see [who may
answer](approvals.md#who-may-answer).

<!-- api-doc:begin approval_decide -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `reason` | text | no | up to 1024 characters |
| `on_behalf` | object | no |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `passkey` | object | no |  |
| `passkey.credential_id` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |
| `passkey.client_data_json` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |
| `passkey.authenticator_data` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |
| `passkey.signature` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |
| `asserted` | object | no |  |
| `asserted.model` | text | no | up to 128 characters |
| `asserted.version` | text | no | up to 64 characters |
| `asserted.prompt_hash` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `self_approved` | true or false | yes |  |
| `escalated` | always `true` | no |  |
| `suggested` | always `true` | no |  |

</details>
<!-- api-doc:end approval_decide -->

### `approval_decide_on_behalf`

Answers a held call for the person a chat bridge acts for, such as a Slack user who clicked a button. `approver` names
the person (`slack:<team>/<user>`) and `groups` the user groups of the same team the bridge found them in. The decision
is `approve` or `reject`. The signer applies its rules to that person, not to the bridge, and the record names both. It
is refused for an agent approver.

**Who may call:** only a caller whose `authorize` entry lists `approval_decide_on_behalf`. It is never granted by
default.

<!-- api-doc:begin approval_decide_on_behalf -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `decision` | one of `approve`, `reject` | yes |  |
| `approver` | text | yes | up to 64 characters; matches `^slack:[A-Z0-9]+/[A-Z0-9]+(?![\s\S])` |
| `groups` | list of texts | no | up to 32 items |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `self_approved` | true or false | yes |  |

</details>
<!-- api-doc:end approval_decide_on_behalf -->

### `approval_review`

Shows an agent approver an approval it may answer: the tool, the rules with the policy's reason, whether each bound
passed, the budget left, the signer's redacted copy of the arguments, and a `view_digest` over all of it. It never shows
the requesting agent's reason, the run, the tool call id or where a value came from. A caller that is not an agent
approver is refused, and so is a request for an approval that is no longer pending.

**Who may call:** only an agent approver, and only with an `authorize` entry that lists `approval_review`. It is never
granted by default.

<!-- api-doc:begin approval_review -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool` | text | yes | up to 256 characters |
| `expires_at` | text | yes | up to 40 characters |
| `rules` | list of objects | yes | up to 32 items |
| `rules[].id` | text | yes | up to 64 characters |
| `rules[].reason` | text | no | up to 1024 characters |
| `rules[].rationale` | text | no | up to 1024 characters |
| `conditions` | list of objects | yes | up to 4096 items |
| `conditions[].rule` | text | yes | up to 64 characters |
| `conditions[].condition` | text | yes | up to 1024 characters |
| `conditions[].passed` | true or false | yes |  |
| `budget` | object | yes |  |
| `args` | any value | yes |  |
| `redacted` | list of texts | yes | up to 4096 items |
| `view_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

</details>
<!-- api-doc:end approval_review -->

### `approval_consume`

Asks to run a call under its approval, just before the adapter runs it. The signer recomputes the digest of the
arguments and answers `ok: true` only if the approval for this exact call attempt is approved, not expired and opens the
bound arguments. It then records `approval.consumed`, and the approval can never be used again. A refusal is an answer
with `ok: false`, a rule id and a `reason`, signed as `approval.refused` or `approval.binding_mismatch`, not an error. A
call that `decide` allowed needs no approval and gets `ok: true`. `approval_id_hint` is only a hint from the framework's
saved state: the signer uses its own index. For executors that run the signer's stored copy, the answer also carries the
approved `args` (see [tiers](approvals.md#tiers-t1-and-t2-executors)).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_consume`. A box's agent channel may call it too.

<!-- api-doc:begin approval_consume -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | no |  |
| `tool` | text | yes | 1 to 256 characters |
| `args_source` | one of `raw`, `parsed`, `coerced` | yes |  |
| `args` | any value | yes |  |
| `approval_id_hint` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `ok` | true or false | yes |  |
| `rule_ids` | list of texts | yes | up to 32 items |
| `approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |
| `args` | any value | no |  |

</details>
<!-- api-doc:end approval_consume -->

### `approval_revoke`

Lets a person veto an agent approver's approval before it is consumed. The signer records `approval.revoked`, and the
call never runs. Only an approval that an agent approved and nothing has consumed yet can be revoked: any other gets
`approval_not_pending`.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_revoke`. When the signer has an `approvals` configuration, the caller must also be one of its approvers
or a break-glass identity.

<!-- api-doc:begin approval_revoke -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |
| `on_behalf` | object | no |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |

</details>
<!-- api-doc:end approval_revoke -->

### `approval_abandon`

Tells the signer that the adapter will never resume a paused call, for example because the user cancelled the run. The
approval ends at once, the signer records `approval.abandoned`, and a later consume is refused. The coding-agent hooks
don't call it: a call they blocked keeps its approval `requested`, for the agent's retry.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `approval_abandon`. A box's agent channel may call it too.

<!-- api-doc:begin approval_abandon -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |

</details>
<!-- api-doc:end approval_abandon -->

### `approval_agents`

The operator's kill switch for agent approvals. `enabled: false` revokes every agent approval that is not consumed yet,
hands every pending approval an agent could answer to people, and leaves people to answer every approval from then on.
`enabled: true` switches agent approvals back on. The signer records it as `approval.agents`, and the answer lists the
approvals it revoked.

**Who may call:** only a caller whose `authorize` entry lists `approval_agents`. It is never granted by default.

<!-- api-doc:begin approval_agents -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `enabled` | true or false | yes |  |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `enabled` | true or false | yes |  |
| `revoked` | list of texts | yes | up to 100000 items |

</details>
<!-- api-doc:end approval_agents -->

### `passkey_register`

Registers the passkey of the person a bridge acts for, named in `on_behalf`: its `credential_id` and its `public_key`
(DER SubjectPublicKeyInfo, P-256 or Ed25519). A person keeps the first passkey registered: a second registration is
refused, and only an operator can remove one. The signer takes the bridge's word for who the person is. A passkey is
what a high-risk approval requires.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `passkey_register`. In practice a bridge, such as the viewer, calls it for the person it acts for.

<!-- api-doc:begin passkey_register -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `on_behalf` | object | yes |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `credential_id` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |
| `public_key` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `credential_id` | text | yes | 1 to 4096 characters; matches `^[A-Za-z0-9_-]+(?![\s\S])` |

</details>
<!-- api-doc:end passkey_register -->

## Reading the log

### `status`

Asks the signer what it is and who it takes the caller to be. The answer gives the contract version (`rpc_version`), the
signer's name and version, and the caller's identity as the signer sees it: `scheme`, `subject`, and `attested`, which
says whether the signer verified that identity itself. When the content vault is on, the answer also has
`content.max_record_bytes`, the largest record content the signer keeps. It takes no run token and writes nothing.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `status`. A box's agent channel may call it too.

<!-- api-doc:begin status -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `rpc_version` | always `25` | yes |  |
| `signer` | object | yes |  |
| `signer.name` | text | yes | up to 128 characters |
| `signer.version` | text | yes | up to 64 characters |
| `identity` | object | yes |  |
| `identity.scheme` | text | yes | up to 32 characters |
| `identity.subject` | text | yes | up to 256 characters |
| `identity.attested` | true or false | yes |  |
| `content` | object | no |  |
| `content.max_record_bytes` | whole number | yes |  |

</details>
<!-- api-doc:end status -->

### `read`

Reads the records of one run from the log, in order, starting at `from_seq` (default 0). It returns at most `limit`
records (default 100, at most 1000), each with its `run_seq`, `type`, `data` and `event_hash`. `next_seq` is the
`run_seq` to ask for next, or null when there are no more records. It needs the run's token, so it reads only that run,
and it writes nothing.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `read`.

<!-- api-doc:begin read -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `from_seq` | whole number | no |  |
| `limit` | whole number | no | at least 1 |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `next_seq` | whole number or nothing | yes |  |
| `events` | list of objects | yes | up to 1000 items |
| `events[].run_seq` | whole number | yes |  |
| `events[].type` | text | yes | up to 64 characters |
| `events[].event_hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `events[].data` | object | yes |  |

</details>
<!-- api-doc:end read -->

### `checkpoint_nudge`

Asks the signer to sign a new checkpoint soon, instead of waiting for its regular round (every 10 seconds while the log
grows). A checkpoint is a signed note over the log's records, and a record can be proved only once a checkpoint covers
it. The signer writes at most one per second. The answer is `scheduled: true` straight away, before the checkpoint
exists, so a caller that needs the checkpoint asks again for what it needs. The SDK does this while it waits for
`pcm_evidence` to stop saying `pending`. The call itself writes no record.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `checkpoint_nudge`.

<!-- api-doc:begin checkpoint_nudge -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `scheduled` | true or false | yes |  |

</details>
<!-- api-doc:end checkpoint_nudge -->

### `content_get`

Reads back the content the vault kept for records of a run of the caller's tenant: up to 1000 `seqs` per call. For each
`seq` the answer gives the content and the record's salt, so the caller can work out the record's commitment again. When
redaction changed the content, so that it no longer opens the commitment, the content comes back marked `redacted` and
with no salt. When there is no content, the item has a `state` instead: `not_retained`, `too_large` or `erased`. Each
item also says the record's `type` and, for an `input.observed` record, its `source` (both added in version 25).
`purpose`, such as a case id, is recorded. Every successful call writes a signed `content.accessed` record, and the
vault must be on, or the call is refused. If the content is too large for one answer, the call fails with
`quota_exceeded`: ask for fewer `seqs`. More: [the content vault](privacy.md#the-content-vault).

**Who may call:** only a caller whose `authorize` entry lists `content_read`, the name of the grant for this call
(`content_get` itself is not accepted there). It is never granted by default, except that the dev signer grants it to
your own user.

<!-- api-doc:begin content_get -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `seqs` | list of whole numbers | yes | up to 1000 items |
| `purpose` | text | yes | 1 to 512 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `items` | list of objects | yes | up to 1000 items |
| `items[].seq` | whole number | yes |  |
| `items[].content` | any value | no |  |
| `items[].salt` | text | no | up to 64 characters |
| `items[].redacted` | always `true` | no |  |
| `items[].type` | text | no | up to 64 characters |
| `items[].source` | text | no | up to 256 characters |
| `items[].state` | one of `not_retained`, `too_large`, `erased` | no |  |

</details>
<!-- api-doc:end content_get -->

### `content_erase`

Deletes for good the content the vault kept for a run of the caller's tenant: the run's key and its stored content. The
signer then writes a signed `content.erased` record with the `reason` (by default "erased on request") and who asked,
and the answer gives that record's `run_seq`. Records and commitments are untouched, so the run still verifies; only the
content is gone. The runs made to replay or analyse the run are erased with it, each with its own `content.erased`. If
the storage fails, no record is written and the call can be repeated. Copies taken before, such as a backup, are not
reached. The vault must be on, or the call is refused. More: [the content vault](privacy.md#the-content-vault).

**Who may call:** only a caller whose `authorize` entry lists `content_erase`. It is never granted by default.

<!-- api-doc:begin content_erase -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end content_erase -->

### `export_run`

Downloads one run of the caller's tenant as a `.tkb` bundle, the file `tracekit verify` checks, in chunks. The first
call names the `run_id` and gets the bundle's `digest`, its `size`, and the first chunk in `data` (base64, up to 783360
bytes of the bundle). Each later call sends the same `digest` and the next `offset`, until the offset reaches the size.
If the signer no longer holds that bundle, because a newer checkpoint came or it sat unused too long, it answers
`conflict` and the download starts again from its first chunk. A run still open is exported up to the latest checkpoint;
if none covers it yet, the signer writes one and the caller asks again. The signer builds one bundle at a time per
tenant, so a busy signer answers `unavailable` with `retry_after_ms`, and the clients wait that long. Added in version
23. More: [downloading a run](remote-ingest.md#downloading-a-run).

**Who may call:** only a caller whose `authorize` entry lists `export_run`. It is never granted by default. Only an
identity that otherwise reads, and writes nothing, may hold it: the signer refuses the call with `forbidden` for an
identity that is also granted a call that writes, or that has no tenant of its own. A run of another tenant answers as a
run that does not exist.

<!-- api-doc:begin export_run -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `offset` | whole number | no |  |
| `digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `size` | whole number | yes |  |
| `offset` | whole number | yes |  |
| `data` | text | yes | up to 1048576 characters; matches `^[A-Za-z0-9+/]*={0,2}(?![\s\S])` |

</details>
<!-- api-doc:end export_run -->

## Transcript tailer gaps

### `tailer_lost`

Reports that a transcript tailer has lost the thread of the agent's transcript. The signer records a `capture.gap` of
kind `tailer_lost` in the run, with the `reason` (secrets removed), the transcript `offset` and the identity that
reported it, and the answer gives that record's `run_seq`. The gap tells a reader that part of what the agent did may
not be recorded. The signer writes the same gap itself when a tailer goes silent. A tailer that reports its own loss is
no longer watched, so its silence afterwards is not a second gap. The call is also accepted while the run is closing.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `tailer_lost`. A box's agent channel may call it too.

<!-- api-doc:begin tailer_lost -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `reason` | text | yes | up to 1024 characters |
| `offset` | whole number | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end tailer_lost -->

### `tailer_heartbeat`

Tells the signer that a transcript tailer is still working. A tailer sends one every 30 seconds. If neither a heartbeat
nor any other call of the tailer comes for 90 seconds while the run is open, the signer records a `tailer_lost` gap. The
call takes the run's token and answers with an empty object. It is refused with `run_closed` once the run has ended. A
tailer gets its token from `delegate_run`.

**Who may call:** only a caller whose `authorize` entry lists `tailer_heartbeat`. It is never granted by default.
Holding it is what marks an identity as a transcript tailer, so the agent cannot keep a dead tailer's heartbeat going
with its own token.

<!-- api-doc:begin tailer_heartbeat -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|

</details>
<!-- api-doc:end tailer_heartbeat -->

## Findings and incidents

### `why_finding`

Records the result of a finished `tracekit why` test as a signed `why.finding` record. `tracekit why` replays a run
without a suspect input and measures whether an action still happens. The finding names the `target` and the
`intervention`, gives the counts and rates with and without it, the `effect` and its `interval`, and a `verdict`
(`causal`, `suppressive`, `ruled-out`, `inconclusive` or `not-applied`), and lists the replay runs it came from. The
record goes into the findings run, and nothing is written into the run that was analysed. The answer gives the new
record's `run_seq`. More: [why](why.md).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `why_finding`. It works only in a findings run, which is a run registered with `analyzes`, and only an identity
listed under `analyzers` in the signer's configuration may register one. In any other run the signer refuses it with
`forbidden`.

<!-- api-doc:begin why_finding -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `finding` | object | yes |  |
| `finding.target` | text | yes | up to 1024 characters |
| `finding.intervention` | text | yes | up to 1024 characters |
| `finding.n` | whole number | yes |  |
| `finding.p_with` | number | yes |  |
| `finding.p_without` | number | yes |  |
| `finding.effect` | number | yes | at least -1 |
| `finding.interval` | list of numbers | yes | up to 2 items |
| `finding.verdict` | one of `causal`, `suppressive`, `ruled-out`, `inconclusive`, `not-applied` | yes |  |
| `finding.replay_runs` | list of objects | yes | up to 4096 items |
| `finding.replay_runs[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `finding.replay_runs[].arm` | one of `control`, `ablated` | yes |  |
| `finding.replay_runs[].hit` | true or false | yes |  |
| `finding.models` | list of texts | yes | up to 32 items |
| `finding.rung` | one of `1`, `2` | yes |  |
| `finding.off_tape` | whole number | yes |  |
| `finding.investigation` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `finding.looks` | whole number | yes | at least 1 |
| `finding.family` | whole number | yes | at least 1 |
| `finding.min_effect` | number | yes |  |
| `finding.applied` | true or false | yes |  |
| `finding.stopped` | one of `decisive`, `futility`, `n_max`, `budget` | yes |  |
| `finding.uncounted` | list of objects | no | up to 4096 items |
| `finding.uncounted[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `finding.uncounted[].reason` | one of `ranking`, `budget` | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end why_finding -->

### `review_finding`

Records one signed finding of `tracekit analyze --v2` as a `review` record in a findings run. The finding names the
`reviewer`, gives a verdict, and lists in `cites` the records of the analysed run it rests on, each by `run_seq` and
hash (at most 256). The signer refuses a finding with `invalid_request` unless every cited record exists in the analysed
run with that hash. The verdict is a closed set of fields: a check (`rule`) with its severity, or a coverage summary of
what the analysis could and could not check. The signer writes the rule's fixed title, and no text of the run goes into
a signed record, because a signed record cannot be erased. Nothing is written into the analysed run. The answer gives
the new record's `run_seq`. More: [findings](findings.md).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `review_finding`. It works only in a findings run, which is a run registered with `analyzes`, and only an identity
listed under `analyzers` in the signer's configuration may register one. In any other run the signer refuses it with
`forbidden`.

<!-- api-doc:begin review_finding -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `review` | object | yes |  |
| `review.reviewer` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._/+-]+(?![\s\S])` |
| `review.cites` | list of objects | yes | up to 256 items |
| `review.cites[].run_seq` | whole number | yes |  |
| `review.cites[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `review.verdict` | object | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end review_finding -->

### `constraint_add`

Adds a live constraint to the run: a limit that a person's request put on the rest of the run, such as "don't touch
billing.py" or "don't push". The `kind` is `keep_away`, `only_change`, `read_only`, `no_push` or `no_network`.
`keep_away` and `only_change` name a file in `object`; the other kinds name none. The signer records `constraint.added`
with a salted commitment to the file name, never the name. After that, a call that breaks the constraint is raised to
`ask` with the rule `TK-CONSTRAINT`, and a person answers it like any other ask. A constraint never lowers a decision,
which is why any client of the run may add one. Adding one that the run already has returns that constraint's `run_seq`
and writes nothing. A run takes 32 file constraints. A further one is recorded as a `constraint_refused` gap, the answer
says `refused: true`, and every write of the run is held from then on. More: [live
constraints](policy-v2.md#live-constraints).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `constraint_add`. A box's agent channel may call it too.

<!-- api-doc:begin constraint_add -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `constraint` | object | yes |  |
| `constraint.kind` | one of `keep_away`, `only_change`, `read_only`, `no_push`, `no_network` | yes |  |
| `constraint.object` | text | no | 1 to 256 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |
| `refused` | always `true` | no |  |

</details>
<!-- api-doc:end constraint_add -->

### `incident_list`

Lists the incidents of the caller's tenant on this signer, in pages. `state` keeps only `open` or `resolved` ones, and
`limit` sets the page size (default 100, at most 1000). Each incident gives its `incident_id`, the `run_id` that opened
it, the time, what fired it (`trigger`, `rule_ids`), its `scope`, its `mode` (`shadow` or `enforce`), the `actions`
taken, its `state`, and each run it holds with that run's state now (`held`, `quarantined`, `resumed` or `final`).
`next_cursor` is the id to send as `cursor` for the next page, or null at the end. The call writes nothing.

**Who may call:** only a caller whose `authorize` entry lists `incident_list`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin incident_list -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `state` | one of `open`, `resolved` | no |  |
| `cursor` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `limit` | whole number | no | at least 1 |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `incidents` | list of objects | yes | up to 1000 items |
| `incidents[].incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].ts` | text | yes | up to 40 characters |
| `incidents[].trigger` | text | yes | up to 64 characters |
| `incidents[].rule_ids` | list of texts | yes | up to 1024 items |
| `incidents[].scope` | object | yes |  |
| `incidents[].scope.kind` | one of `run`, `session`, `owner`, `principal` | yes |  |
| `incidents[].scope.id` | text | yes | up to 256 characters |
| `incidents[].mode` | one of `shadow`, `enforce` | yes |  |
| `incidents[].actions` | list of texts | yes | up to 4 items |
| `incidents[].state` | one of `open`, `resolved` | yes |  |
| `incidents[].runs` | list of objects | yes | up to 4096 items |
| `incidents[].runs[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].runs[].state` | one of `held`, `quarantined`, `resumed`, `final` | yes |  |
| `next_cursor` | text or nothing | yes |  |

</details>
<!-- api-doc:end incident_list -->

### `incident_show`

Reads one incident of the caller's tenant by `incident_id`, with the same fields as an entry of `incident_list`. An id
that does not exist in the caller's tenant is refused with `unknown_incident`. The call writes nothing.

**Who may call:** only a caller whose `authorize` entry lists `incident_show`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin incident_show -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `ts` | text | yes | up to 40 characters |
| `trigger` | text | yes | up to 64 characters |
| `rule_ids` | list of texts | yes | up to 1024 items |
| `scope` | object | yes |  |
| `scope.kind` | one of `run`, `session`, `owner`, `principal` | yes |  |
| `scope.id` | text | yes | up to 256 characters |
| `mode` | one of `shadow`, `enforce` | yes |  |
| `actions` | list of texts | yes | up to 4 items |
| `state` | one of `open`, `resolved` | yes |  |
| `runs` | list of objects | yes | up to 4096 items |
| `runs[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `runs[].state` | one of `held`, `quarantined`, `resumed`, `final` | yes |  |

</details>
<!-- api-doc:end incident_show -->

### `incident_resolve`

Resolves an open incident. The signer ends the hold the incident put on each run that is still held, with a
`run.resumed` record in that run, and then writes `incident.resolved` in the tenant's signer run. The answer lists the
runs it resumed in `resumed`. A quarantine stays, because resolving is not undoing. An incident that is resolved already
is refused with `invalid_request`. The `reason` is redacted and recorded.

**Who may call:** only a caller whose `authorize` entry lists `incident_resolve`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators). The caller must also be a person: an identity mapped in
`approvals.persons`, or an OIDC person, who is an approver, or a break-glass identity giving a `reason`. It may not be
the owner, principal or requester of a run the incident concerns.

<!-- api-doc:begin incident_resolve -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `resumed` | list of texts | yes | up to 4096 items |

</details>
<!-- api-doc:end incident_resolve -->

## Holds and pauses

### `run_hold`

Holds a run because an operator says so. The signer opens an incident with the trigger `operator`, expires the run's
live approvals, and records `run.held` with the calls still in flight. From then on every call of the run is an `ask`
(rule `TK-HOLD`) that only a person answers, never the run's owner, principal or requester. For one hour, a new run of
the same owner and attested principal starts held too. The answer gives the `run_id`, the new `incident_id` and
`state: held`. A person ends the hold with `run_resume` or `incident_resolve`. The signer refuses with `invalid_request`
a run that is quarantined already, and refuses every hold when no person approver is configured (`approvals.approvers`),
because no one could answer a held call: quarantine the run instead. More: [what each response
does](incidents.md#what-each-response-does).

**Who may call:** only a caller whose `authorize` entry lists `run_hold`. It is never granted by default. The identity
must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`, or owns
open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin run_hold -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `held`, `quarantined`, `resumed` | yes |  |

</details>
<!-- api-doc:end run_hold -->

### `run_quarantine`

Quarantines a run because an operator says so, and nothing ends it. The signer opens an incident with the trigger
`operator`, expires the run's live approvals, and records `run.quarantined`. From then on every call of the run is
denied (rule `TK-QUARANTINE`), every approval consume is refused, a gateway's model request is refused, and the run
closes. After 100 recorded denies the signer refuses further calls without recording them. For one hour, a new run of
the same owner and attested principal starts quarantined too. The answer gives the `run_id`, the new `incident_id` and
`state: quarantined`. A run that is quarantined already is refused with `invalid_request`. More: [what each response
does](incidents.md#what-each-response-does).

**Who may call:** only a caller whose `authorize` entry lists `run_quarantine`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin run_quarantine -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `held`, `quarantined`, `resumed` | yes |  |

</details>
<!-- api-doc:end run_quarantine -->

### `run_resume`

Ends the holds on a run. The signer writes a `run.resumed` record for each incident that holds the run. The incidents
stay open: `incident_resolve` closes them. A run that is not held, and a quarantined run, is refused with
`invalid_request`, because a quarantine is final. The answer gives the `run_id`, `state: resumed`, and the `incident_id`
of the first incident that held it. The `reason` is redacted and recorded.

**Who may call:** only a caller whose `authorize` entry lists `run_resume`. It is never granted by default. The identity
must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`, or owns
open runs. More: [operators](incidents.md#operators). The caller must also be a person: an identity mapped in
`approvals.persons`, or an OIDC person, who is an approver, or a break-glass identity giving a `reason`. It may not be
the owner, principal or requester of the run.

<!-- api-doc:begin run_resume -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `held`, `quarantined`, `resumed` | yes |  |

</details>
<!-- api-doc:end run_resume -->

### `response_pause`

Pauses the response engine of the caller's tenant on this signer. Incidents are still detected and recorded, and the
signer takes no action on them: nothing is held or quarantined while the engine is paused. Holds and quarantines that
are already in place stay. The signer records `incident.response` with `enabled: false` in the tenant's signer run, and
the answer is `enabled: false`. A signer pauses only its own engine, so a deployment of several signers pauses each one.

**Who may call:** only a caller whose `authorize` entry lists `response_pause`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin response_pause -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `enabled` | true or false | yes |  |

</details>
<!-- api-doc:end response_pause -->

### `response_resume`

Starts the response engine of the caller's tenant on this signer again after `response_pause`. The signer records
`incident.response` with `enabled: true` in the tenant's signer run, and the answer is `enabled: true`. It does not go
back over incidents detected while the engine was paused.

**Who may call:** only a caller whose `authorize` entry lists `response_resume`. It is never granted by default. The
identity must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`,
or owns open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin response_resume -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `enabled` | true or false | yes |  |

</details>
<!-- api-doc:end response_resume -->

### `suspend`

Suspends an identity of the caller's tenant: from then on the signer refuses every call the identity makes. `identity`
is `scheme:subject`, or a prefix that ends in `:*` or `/*` to cover several. The entry goes into the suspension list
that every signer replica reads, and each replica writes an `identity.suspension` record when it first enforces the
entry. No token is revoked, so revoke a lost token yourself. The signer refuses with `forbidden` an identity that is not
of the caller's tenant, and with `invalid_request` one that is suspended already. The answer gives the `identity` and
`state: suspended`. The `reason` is redacted and recorded.

**Who may call:** only a caller whose `authorize` entry lists `suspend`. It is never granted by default. The identity
must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`, or owns
open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin suspend -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `state` | one of `suspended`, `lifted` | yes |  |

</details>
<!-- api-doc:end suspend -->

### `unsuspend`

Lifts the suspension of an identity of the caller's tenant, so that the signer accepts its calls again. `identity` names
the same entry that `suspend` was given. The signer writes `identity.suspension` with `state: lifted`, and the answer
gives the `identity` and `state: lifted`. An identity that is not suspended is refused with `invalid_request`.

**Who may call:** only a caller whose `authorize` entry lists `unsuspend`. It is never granted by default. The identity
must run no agent: the signer refuses the call with `forbidden` if the identity is also granted `register_run`, or owns
open runs. More: [operators](incidents.md#operators).

<!-- api-doc:begin unsuspend -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `state` | one of `suspended`, `lifted` | yes |  |

</details>
<!-- api-doc:end unsuspend -->

## Permission records

### `pcm_sign`

Signs a message as the run's own agent, for it to send to another agent. This is part of PCM, proof-carrying messages,
which are experimental. The request holds the message body: `from` (which must name the run's own agent, run and
tenant), `to`, the typed `intent`, and optionally `claims`, `grants` and a `payload`. The signer adds the protocol
number, an `id`, a time and a nonce, signs the whole message with its log key, and records `pcm.sent` in the run: ids
and digests, never the arguments. The answer gives the signed `message` and the `run_seq`. The signer refuses with
`forbidden` a `from` that names anyone else, and any call in a run that is held or quarantined. More: [PCM signer
calls](pcm.md#signer-calls).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `pcm_sign`. Only the run's own agent, the identity that registered the run, may use it: a tailer or observer
holding a delegated run token is refused with `forbidden`.

<!-- api-doc:begin pcm_sign -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `message` | object | yes |  |
| `message.to` | object | yes |  |
| `message.to.agent` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.intent` | object | yes |  |
| `message.intent.type` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.intent.args` | any value | yes |  |
| `message.claims` | list of objects | no | up to 8 items |
| `message.claims[].type` | one of `tests_passed`, `approved_by`, `reached_host`, `file_written` | yes |  |
| `message.claims[].args` | any value | yes |  |
| `message.claims[].evidence` | object | no |  |
| `message.claims[].evidence.checkpoint` | text | yes | 1 to 16384 characters |
| `message.claims[].evidence.records` | list of objects | yes | up to 16 items |
| `message.claims[].evidence.records[].event` | any value | yes |  |
| `message.claims[].evidence.records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].proof` | list of texts | yes | up to 64 items |
| `message.claims[].evidence.records[].salt` | text | no | up to 64 characters; matches `^[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].args` | any value | no |  |
| `message.grants` | list of objects | no | up to 8 items |
| `message.grants[].pcm_grant` | always `0` | yes |  |
| `message.grants[].ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `message.grants[].issuer` | object | yes |  |
| `message.grants[].issuer.kind` | one of `person`, `agent` | yes |  |
| `message.grants[].issuer.id` | text | yes | up to 256 characters |
| `message.grants[].issuer.person` | text | no | up to 256 characters |
| `message.grants[].issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.grants[].intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.grants[].caveats` | list of objects | yes | up to 16 items |
| `message.grants[].caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `message.grants[].caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `message.grants[].caveats[].value` | any value | yes |  |
| `message.grants[].expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `message.grants[].delegable` | true or false | yes |  |
| `message.grants[].parent` | text or nothing | yes |  |
| `message.grants[].sig` | object | yes |  |
| `message.grants[].sig.key` | text | yes | 1 to 300 characters |
| `message.grants[].sig.sig` | text | yes | up to 88 characters |
| `message.payload` | object | no |  |
| `message.from` | object | yes |  |
| `message.from.agent` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.from.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.from.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `message` | object | yes |  |
| `message.to` | object | yes |  |
| `message.to.agent` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.intent` | object | yes |  |
| `message.intent.type` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.intent.args` | any value | yes |  |
| `message.claims` | list of objects | no | up to 8 items |
| `message.claims[].type` | one of `tests_passed`, `approved_by`, `reached_host`, `file_written` | yes |  |
| `message.claims[].args` | any value | yes |  |
| `message.claims[].evidence` | object | no |  |
| `message.claims[].evidence.checkpoint` | text | yes | 1 to 16384 characters |
| `message.claims[].evidence.records` | list of objects | yes | up to 16 items |
| `message.claims[].evidence.records[].event` | any value | yes |  |
| `message.claims[].evidence.records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].proof` | list of texts | yes | up to 64 items |
| `message.claims[].evidence.records[].salt` | text | no | up to 64 characters; matches `^[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].args` | any value | no |  |
| `message.grants` | list of objects | no | up to 8 items |
| `message.grants[].pcm_grant` | always `0` | yes |  |
| `message.grants[].ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `message.grants[].issuer` | object | yes |  |
| `message.grants[].issuer.kind` | one of `person`, `agent` | yes |  |
| `message.grants[].issuer.id` | text | yes | up to 256 characters |
| `message.grants[].issuer.person` | text | no | up to 256 characters |
| `message.grants[].issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.grants[].subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.grants[].intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.grants[].caveats` | list of objects | yes | up to 16 items |
| `message.grants[].caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `message.grants[].caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `message.grants[].caveats[].value` | any value | yes |  |
| `message.grants[].expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `message.grants[].delegable` | true or false | yes |  |
| `message.grants[].parent` | text or nothing | yes |  |
| `message.grants[].sig` | object | yes |  |
| `message.grants[].sig.key` | text | yes | 1 to 300 characters |
| `message.grants[].sig.sig` | text | yes | up to 88 characters |
| `message.payload` | object | no |  |
| `message.from` | object | yes |  |
| `message.from.agent` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `message.from.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.from.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `message.pcm` | always `0` | yes |  |
| `message.id` | text | yes | up to 32 characters; matches `^[0-9a-f]{32}(?![\s\S])` |
| `message.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `message.nonce` | text | yes | up to 32 characters; matches `^[0-9a-f]{32}(?![\s\S])` |
| `message.sig` | object | yes |  |
| `message.sig.key` | text | yes | 1 to 300 characters |
| `message.sig.sig` | text | yes | up to 88 characters |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end pcm_sign -->

### `pcm_grant`

Turns a person's approval into a root grant: a signed statement that a person let this run's agent make a kind of
request, within limits, until a time. The request names the run's `pcm.grant` call (`tool_call_id` and `attempt`,
default 0) and the `args` of that call: the `subject`, the `intent`, the `caveats`, `expires_at` and `delegable`. The
signer issues the grant only if a person approved that call with exactly these arguments and the call consumed the
approval. The person must be one that `approvals.persons` names, and neither the run's agent nor the grant's subject.
One approval issues one grant, and the call must come before the `pcm.grant` call completes. A grant expires within 24
hours, and the signer needs `approvals` in its configuration. The answer gives the signed `grant` and the `run_seq` of
the `pcm.grant` record. The signer refuses with `forbidden`, or with `args_mismatch` when the approval was for other
arguments, and refuses any call in a run that is held or quarantined. More: [PCM signer calls](pcm.md#signer-calls).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `pcm_grant`. Only the run's own agent, the identity that registered the run, may use it: a tailer or observer
holding a delegated run token is refused with `forbidden`.

<!-- api-doc:begin pcm_grant -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `attempt` | whole number | no |  |
| `args` | object | yes |  |
| `args.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `args.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `args.caveats` | list of objects | no | up to 16 items |
| `args.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `args.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `args.caveats[].value` | any value | yes |  |
| `args.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `args.delegable` | true or false | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `grant` | object | yes |  |
| `grant.pcm_grant` | always `0` | yes |  |
| `grant.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.issuer` | object | yes |  |
| `grant.issuer.kind` | one of `person`, `agent` | yes |  |
| `grant.issuer.id` | text | yes | up to 256 characters |
| `grant.issuer.person` | text | no | up to 256 characters |
| `grant.issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `grant.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `grant.caveats` | list of objects | yes | up to 16 items |
| `grant.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `grant.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `grant.caveats[].value` | any value | yes |  |
| `grant.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.delegable` | true or false | yes |  |
| `grant.parent` | text or nothing | yes |  |
| `grant.sig` | object | yes |  |
| `grant.sig.key` | text | yes | 1 to 300 characters |
| `grant.sig.sig` | text | yes | up to 88 characters |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end pcm_grant -->

### `pcm_delegate`

Passes a grant on in a narrower form. `parent` is a grant this signer signed for the run's agent and that may be passed
on (`delegable`). The new grant goes to `subject`, with the same intent, `caveats` that only narrow the parent's, and an
`expires_at` that is in the future and not after the parent's. It needs no approval, because a child can only be
narrower. The answer gives the signed `grant` and the `run_seq`. The signer refuses with `invalid_request` a parent
whose signature is not its own or that has expired, an `expires_at` that is past or after the parent's, and caveats that
do not narrow, and with `forbidden` a grant issued in another tenant, a caller that is not the grant's subject, and a
grant that cannot be passed on. An intent grant, from `grant_issue`, can't be a parent. A held or quarantined run is
refused. More: [PCM signer calls](pcm.md#signer-calls).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `pcm_delegate`. Only the run's own agent, the identity that registered the run, may use it: a tailer or observer
holding a delegated run token is refused with `forbidden`.

<!-- api-doc:begin pcm_delegate -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `parent` | object | yes |  |
| `parent.pcm_grant` | always `0` | yes |  |
| `parent.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `parent.issuer` | object | yes |  |
| `parent.issuer.kind` | one of `person`, `agent` | yes |  |
| `parent.issuer.id` | text | yes | up to 256 characters |
| `parent.issuer.person` | text | no | up to 256 characters |
| `parent.issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `parent.issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `parent.issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `parent.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `parent.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `parent.caveats` | list of objects | yes | up to 16 items |
| `parent.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `parent.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `parent.caveats[].value` | any value | yes |  |
| `parent.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `parent.delegable` | true or false | yes |  |
| `parent.parent` | text or nothing | yes |  |
| `parent.sig` | object | yes |  |
| `parent.sig.key` | text | yes | 1 to 300 characters |
| `parent.sig.sig` | text | yes | up to 88 characters |
| `subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `caveats` | list of objects | no | up to 16 items |
| `caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `caveats[].value` | any value | yes |  |
| `expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `delegable` | true or false | yes |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `grant` | object | yes |  |
| `grant.pcm_grant` | always `0` | yes |  |
| `grant.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.issuer` | object | yes |  |
| `grant.issuer.kind` | one of `person`, `agent` | yes |  |
| `grant.issuer.id` | text | yes | up to 256 characters |
| `grant.issuer.person` | text | no | up to 256 characters |
| `grant.issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `grant.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `grant.caveats` | list of objects | yes | up to 16 items |
| `grant.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `grant.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `grant.caveats[].value` | any value | yes |  |
| `grant.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.delegable` | true or false | yes |  |
| `grant.parent` | text or nothing | yes |  |
| `grant.sig` | object | yes |  |
| `grant.sig.key` | text | yes | 1 to 300 characters |
| `grant.sig.sig` | text | yes | up to 88 characters |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end pcm_delegate -->

### `pcm_evidence`

Returns records of the run with proof that they are in the log, as evidence for the claims in a message. `run_seqs`
lists 1 to 16 records of the run. For each record the answer gives the event, its hash, and an inclusion proof under the
latest checkpoint. A `policy.decision` also comes with its salt, which opens the commitment to its arguments, and that
is why only the run's own agent may ask. A record the latest checkpoint does not cover yet is listed in `pending`: send
`checkpoint_nudge` and ask again. A `run_seq` the run does not have is refused with `invalid_request`. The call writes
nothing, and it still works in a held or quarantined run. More: [PCM signer calls](pcm.md#signer-calls).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `pcm_evidence`. Only the run's own agent, the identity that registered the run, may use it: a tailer or observer
holding a delegated run token is refused with `forbidden`.

<!-- api-doc:begin pcm_evidence -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `run_seqs` | list of whole numbers | yes | up to 16 items |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `checkpoint` | text or nothing | yes |  |
| `records` | list of objects | yes | up to 16 items |
| `records[].run_seq` | whole number | yes |  |
| `records[].event` | any value | yes |  |
| `records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `records[].proof` | list of texts | yes | up to 64 items |
| `records[].salt` | text | no | up to 64 characters; matches `^[0-9a-f]{64}(?![\s\S])` |
| `pending` | list of whole numbers | yes | up to 16 items |

</details>
<!-- api-doc:end pcm_evidence -->

## Grants and channels

### `grant_issue`

Lets a person give the run's agent an intent grant: leave to make a kind of costly call, such as `payment.send`, without
asking each time. The grant covers the `tools` named, within `caveats` (conditions on each call, such as who may be
paid) and `limits` (totals over every call that uses the grant: a sum of a field or a count of calls), until
`expires_at`, at most 24 hours ahead. A grant covers one run and can't be passed on. The signer signs it and writes an
`intent.grant` record into the run. With `approval_id`, the grant is issued from a call that the run has held and that
is still pending: the call must be held only by rules that opt into the intent and must fall within the grant, and it
counts as the grant's first use. The answer gives the `grant_id`, the signed `grant`, the `tools`, the totals so far in
`used`, `self_approved` and the `run_seq`. `self_approved` is true when the run's own user issued the grant, which the
verifiers read as a self-approval. The signer refuses with `invalid_request` a grant that breaks the intent's rules or
the signer's ceiling, and with `forbidden` or `run_closed` a run that is held, quarantined or ending. Added in version
22. More: [intent grants](intent-grants.md).

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `grant_issue`. The signer then applies the rules for who may answer the run's approvals. With `approvals`
configured, the issuer must be an approver of the run's tenant, and never the run's own user or principal unless
`self_approval: allow`. On the dev signer, any identity of the run's tenant may issue one. An agent approver never may.
More: [who may issue a grant](intent-grants.md#who-may-issue-a-grant).

<!-- api-doc:begin grant_issue -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `intent` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_.-]{0,63}(?![\s\S])` |
| `caveats` | list of objects | yes | up to 16 items |
| `caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `caveats[].value` | any value | yes |  |
| `limits` | list of objects | yes | up to 4 items |
| `limits[].op` | one of `sum`, `count` | yes |  |
| `limits[].field` | text | no | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `limits[].max` | whole number | yes | at least 1 |
| `expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `description` | text | no | up to 512 characters |
| `tools` | list of texts | no | up to 16 items |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `grant_id` | text | yes | up to 18 characters; matches `^g-[0-9a-f]{16}(?![\s\S])` |
| `grant` | object | yes |  |
| `grant.pcm_grant` | always `0` | yes |  |
| `grant.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.issuer` | object | yes |  |
| `grant.issuer.kind` | one of `person`, `agent` | yes |  |
| `grant.issuer.id` | text | yes | up to 256 characters |
| `grant.issuer.person` | text | no | up to 256 characters |
| `grant.issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `grant.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `grant.caveats` | list of objects | yes | up to 16 items |
| `grant.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `grant.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `grant.caveats[].value` | any value | yes |  |
| `grant.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grant.delegable` | true or false | yes |  |
| `grant.parent` | text or nothing | yes |  |
| `grant.sig` | object | yes |  |
| `grant.sig.key` | text | yes | 1 to 300 characters |
| `grant.sig.sig` | text | yes | up to 88 characters |
| `tools` | list of texts | yes | up to 16 items |
| `used` | list of whole numbers | yes | up to 4 items |
| `self_approved` | true or false | yes |  |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end grant_issue -->

### `grant_list`

Lists the intent grants of the open runs the caller may see, or of one run when `run_id` is given, at most 1000. Each
entry gives the `grant_id`, the `run_id`, the signed `grant`, its `tools`, `limits`, the totals so far in `used`,
`self_approved`, any `description`, and its `state`: `live`, `revoked`, `expired` or `used_up`, which says whether it
can still release a call. The call writes nothing.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `grant_list`. It lists only the runs the caller may see: the run's own user, a break-glass identity, or, with
`approvals` configured, an approver of the run's tenant.

<!-- api-doc:begin grant_list -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `grants` | list of objects | yes | up to 1000 items |
| `grants[].grant_id` | text | yes | up to 18 characters; matches `^g-[0-9a-f]{16}(?![\s\S])` |
| `grants[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grants[].grant` | object | yes |  |
| `grants[].grant.pcm_grant` | always `0` | yes |  |
| `grants[].grant.ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grants[].grant.issuer` | object | yes |  |
| `grants[].grant.issuer.kind` | one of `person`, `agent` | yes |  |
| `grants[].grant.issuer.id` | text | yes | up to 256 characters |
| `grants[].grant.issuer.person` | text | no | up to 256 characters |
| `grants[].grant.issuer.run` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grants[].grant.issuer.tenant` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grants[].grant.issuer.approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grants[].grant.subject` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `grants[].grant.intent` | text | yes | up to 136 characters; matches `^[a-z][a-z0-9_.-]{0,63}@sha256:[0-9a-f]{64}(?![\s\S])` |
| `grants[].grant.caveats` | list of objects | yes | up to 16 items |
| `grants[].grant.caveats[].field` | text | yes | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `grants[].grant.caveats[].op` | one of `==`, `<=`, `>=`, `<`, `>`, `in` | yes |  |
| `grants[].grant.caveats[].value` | any value | yes |  |
| `grants[].grant.expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `grants[].grant.delegable` | true or false | yes |  |
| `grants[].grant.parent` | text or nothing | yes |  |
| `grants[].grant.sig` | object | yes |  |
| `grants[].grant.sig.key` | text | yes | 1 to 300 characters |
| `grants[].grant.sig.sig` | text | yes | up to 88 characters |
| `grants[].tools` | list of texts | yes | up to 16 items |
| `grants[].limits` | list of objects | yes | up to 4 items |
| `grants[].limits[].op` | one of `sum`, `count` | yes |  |
| `grants[].limits[].field` | text | no | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `grants[].limits[].max` | whole number | yes | at least 1 |
| `grants[].used` | list of whole numbers | yes | up to 4 items |
| `grants[].state` | one of `live`, `revoked`, `expired`, `used_up` | yes |  |
| `grants[].self_approved` | true or false | yes |  |
| `grants[].description` | text | no | up to 512 characters |

</details>
<!-- api-doc:end grant_list -->

### `grant_revoke`

Ends an intent grant of an open run the caller may see. The signer writes an `intent.revoked` record, and from then on
every call the grant would have released is held again for a person. The answer gives the `grant_id`, the `run_id` and
the `run_seq`. The signer refuses with `invalid_request` a grant that is not in an open run the caller may see, and one
that is revoked already. Revoking only narrows what the agent may do, so the run's own user may do it too.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `grant_revoke`. It works only on runs the caller may see, as for `grant_list`.

<!-- api-doc:begin grant_revoke -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `grant_id` | text | yes | up to 18 characters; matches `^g-[0-9a-f]{16}(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `grant_id` | text | yes | up to 18 characters; matches `^g-[0-9a-f]{16}(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end grant_revoke -->

### `channel_open`

Opens the agent channel of one box, for a Tracekit Box daemon. Box is experimental. The daemon names its own open box
run, `run_id` and `run_token`. After that, the rest of the connection acts as the box's own identity,
`box:<uid>/<box id>`, in the box run's tenant, and may make only the calls a box's agent channel may make. The answer
gives that `identity`. The signer refuses with `run_closed` a box run that has closed, and with `invalid_request` a run
that was not registered with `box`. Added in version 21. More: [Tracekit Box](limits.md#tracekit-box-experimental).

**Who may call:** only an identity that `box_daemons` in the signer's configuration names, whatever its `authorize`
entry lists. It is never granted by default. A Box daemon reaches the signer over its Unix socket, never over HTTPS.

<!-- api-doc:begin channel_open -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `identity` | text | yes | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |

</details>
<!-- api-doc:end channel_open -->

## Transport and auth

TODO: written last. HTTPS, the four ways to prove who you are, the status header, `Request-Id`, the Unix socket and the dev TCP port.
