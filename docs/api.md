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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

Reads the content of records in a run: for each `seq` asked for, the content and its salt, the content marked redacted, or the reason there is none.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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

TODO: what this RPC is for.

TODO: who may call.

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
