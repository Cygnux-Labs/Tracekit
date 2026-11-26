# Signer API reference

A request is one JSON object that names its RPC in the `method` field, sent to `POST /v2/rpc` over HTTPS (or over the
Unix socket on the same machine); the answer is one JSON object. On one connection the signer answers requests in the
order it received them. This page lists what each RPC takes and returns. The field tables are written from
`tracekit/signer/rpc_schema.py` by `scripts/api_doc.py`: edit the schema, run the script, never the tables. How callers
connect and prove who they are is under [Transport and auth](#transport-and-auth).

The signer is the part of Tracekit that decides whether an agent's tool calls may run, and that signs and chains the
records of what happened. [Versioning](#versioning) says which versions of this contract a signer serves.

**Where to start.** If you are connecting a caller for the first time, read [Transport and auth](#transport-and-auth)
and [Who may call what](#who-may-call-what) first: they say how a caller proves who it is and what it may then call. A
normal agent session uses four calls in this order: `register_run` starts the run, `decide` asks whether a tool call may
run, `complete` reports what the call did, and `close_run` ends the run.

**How the page is arranged.** [Versioning](#versioning), [Errors](#errors) and [Who may call what](#who-may-call-what)
apply to every call. The RPCs follow in groups, and [Transport and auth](#transport-and-auth) comes last:

- [Runs and calls](#runs-and-calls): starting and ending a run, asking whether a tool call may run, and reporting what
  happened.
- [Approvals](#approvals): asking for, answering and using an approval.
- [Reading the log](#reading-the-log): reading a run's records, reading kept content, and downloading a run.
- [Transcript tailer gaps](#transcript-tailer-gaps): what a transcript tailer reports.
- [Findings and incidents](#findings-and-incidents): recording findings, adding a live constraint, and listing and
  resolving incidents.
- [Holds and pauses](#holds-and-pauses): an operator's holds, quarantines, pauses and suspensions.
- [Permission records](#permission-records): signing, granting and delegating permission records, and evidence.
- [Grants and channels](#grants-and-channels): intent grants, and a box's agent channel.

**Reading the field tables.** Each RPC has a request table and an answer table, with one row for each field. A dotted
name such as `parent.run_id` is a field inside an object, and `[]` in a name, as in `events[].type`, is a field of each
item in a list. Required says whether a request must carry the field, or an answer always does. Types are in plain
words: text, whole number, number, true or false, object, list of ..., and any value, which is any JSON. "Nothing" means
JSON null, so "text or nothing" is a text or null. "One of" lists the only values the field may have, and "always" with a
value means that is the only value it may have. The notes give limits: lengths are in characters, a whole number is at
most 9007199254740991 (2^53 - 1, the largest whole number JSON holds exactly) unless its note says less, and `matches`
gives a regular expression in which `(?![\s\S])` means the end of the text. "Each item" gives the limits on every
item of a list, and "each value" on every value of an object whose keys are free (`*` in a name, as in `a.*.b`, is a
field of each such value). A field whose Required is "depends" is
required by some shapes of its object and not others: the note on the object's own row lists the shapes, each with the
value that selects it, and "when `args_source` is `"raw"`" in a note means the limit applies only then. A request
field that a table does not list is refused, as Versioning says; the notes do not repeat that.

**Words this page uses.** These terms come up in several sections.

- **binding**: ties an approval to one exact tool call, the tool and its arguments, as a digest. The approval cannot be
  used for any other call.
- **break-glass**: an identity listed under `approvals.break_glass` may answer approvals and resolve incidents without
  being a regular approver. It must give a `reason`, and the record says so. See
  [Who may answer](approvals.md#who-may-answer).
- **bridge**: a program that acts for a person, such as the Slack bridge or the viewer. It calls with `on_behalf` to
  act as that person: the Slack bridge answers approvals with `approval_decide_on_behalf`, and the viewer sends
  `on_behalf` on `approval_get`, `approval_list`, `approval_decide`, `approval_revoke` and `passkey_register`. Every
  bridge needs the `approval_decide_on_behalf` grant, for either use. The signer applies its rules to the person, not
  to the bridge, and takes the bridge's word for who the person is.
- **commitment**: a digest of some content, made with a salt. A record holds the commitment, not the content, so the log
  can prove what was said without keeping it. With the content and the salt, anyone can work the commitment out again
  and compare.
- **escalate**: an agent approver does this to hand an approval it will not decide over to people.
- **gap**: a signed `capture.gap` record that the signer writes when it knows something is missing or went wrong in a
  run, such as a lost transcript tailer, a call that ran after a deny, or a saved state that was tampered with. Gaps are
  never silent, and only the signer writes them: a request can report a loss (`tailer_lost`), but no request supplies a
  gap record. See [Gaps](concepts/capture-and-completeness.md#gaps).
- **run token**: the secret that `register_run` returns for a run. Every later call for that run presents it.
  `delegate_run` issues a second one to another identity.

## Versioning

The contract has one version number, and this page describes version 29. A released version never changes: any change to
a request or an answer is a new version.

A signer serves a range of versions, from 15 up to its own highest. A client sends `hello` first, which is not one of
the calls on this page. Its answer gives `proto`, the lowest and highest version the signer serves, the signer's
Tracekit `version`, and its `pid`. A client checks that its own version is inside `proto`. If it is not, the SDK refuses
to go on and says so, and tells the person to stop the signer with `tracekit down` or replace it with
`tracekit up --replace`. Over HTTPS the SDK sends `hello` once, before its first call. `status` gives the signer's
highest version as `rpc_version`.

Two rules let older and newer clients work together:

- A signer refuses a request that has a field the contract does not name (`invalid_request`), so a client sends only the
  fields of the version it speaks.
- An answer may carry optional fields that a later version added. A client ignores fields it does not know.

A call or field that this page does not list below was already in version 15. These are the changes since:

| Version | What it added |
|---|---|
| 16 (all of Tracekit 1.2) | `register_run`'s `parent`; `close_run`'s `last_client_seq` and `caller`; args digests on the tool uses a provider ran; `tailer_heartbeat`; `observe_effect`; agent approvers (`approval_review`, `approval_revoke`, `approval_agents`, `approval_decide`'s `escalate` and `asserted`, filters on `approval_list`); the operator calls (`incident_list`, `incident_show`, `incident_resolve`, `run_hold`, `run_quarantine`, `run_resume`, `response_pause`, `response_resume`, `suspend`, `unsuspend`); `decide`'s `incident_id`; an approval's `run_closing`, `escalated` and `agent` |
| 17 (Tracekit 1.3) | `model_event`'s `tool_results` and the answer's `refused` |
| 18 | The kernel sensor's events in `observe_effect` |
| 19 | `review_finding`; `constraint_add`; `model_event`'s `amended` and `said_only`; `register_run`'s `caller`; `observe_effect`'s `callers` and its OpenShell import |
| 20 | `pcm_sign`, `pcm_grant`, `pcm_delegate`, `pcm_evidence` (experimental) |
| 21 | Tracekit Box's agent channel (experimental): `register_run`'s `box` and `channel_open` |
| 22 | Intent grants: `grant_issue`, `grant_list`, `grant_revoke` |
| 23 | `export_run` |
| 24 | `call_state`, `call_claim` |
| 25 | `content_get`'s `type` and `source` |
| 26 (Tracekit 1.7) | `register_run`'s `continues`: a later run of an agent session, whose provenance index starts `partial` |
| 27 | `decide`'s `agent_id`: the sub-agent that made the call, as the harness reported it |
| 28 (Tracekit 1.8) | `run_label_clear`, an operator call (on a dev signer, the run's own user's too): a person ends one of a run's labels ([run conditions](policy-v2.md#run-conditions)); `decide`'s `recorded`: the rules in shadow that would hold the call |
| 29 (Tracekit 1.8) | the [AI approver](approvals.md#the-ai-approver): `approval_request`'s `project`; `approval_decide`'s `ai` and `view_digest`; `approval_review`'s `ai`; `approver`, for people; an approval's `ai` on `approval_get` and `approval_list` |

## Errors

A call the signer refuses answers with an error frame instead of the answer described in its section:
`{"error": {"code": ..., "message": ..., "retry_after_ms": ...}}`. `message` is text for a person, up to 1024
characters. `retry_after_ms` is there only when the signer says when to try again. A client acts on `code`, and keeps a
code it does not know, because a later version may add one.

| Code | What it means | HTTP status |
|---|---|---|
| `invalid_request` | The request does not fit the call's schema, or breaks a rule the call's section states. | 400 |
| `unauthenticated` | The transport could not tell who the caller is. | 401 |
| `forbidden` | The caller may not make this call, or not in this state, for example an approver who is also the requester. | 403 |
| `run_token_invalid` | The run token is missing, wrong, or belongs to another run. | 403 |
| `unknown_run` | The run does not exist, as far as the caller can see. | 404 |
| `unknown_tool_call` | `approval_request` for a call attempt with no pending `ask`. | 404 |
| `unknown_decision` | `complete` with a `decision_id` that is not this call's, or that was completed already. | 404 |
| `unknown_approval` | No approval with that id. | 404 |
| `unknown_incident` | An operator call names an incident that the caller's tenant does not have. | 404 |
| `run_exists` | `register_run` with a `run_id` that is registered already. | 409 |
| `run_closed` | The run has ended, or is ending. | 409 |
| `conflict` | A `request_id` used again with a different payload; an observer that another process took over from; or, for `export_run`, a download whose bundle the signer no longer holds. | 409 |
| `client_seq_reused` | A `client_seq` at or below the last one of its stream, under a new `request_id`. | 409 |
| `args_mismatch` | `complete` with arguments other than the decided ones; also `pcm_grant` for a call that was approved with other arguments. | 409 |
| `approval_not_pending` | The approval is not waiting for an answer any more. | 409 |
| `quota_exceeded` | A rate, open-run, pending-approval or size limit. | 429 with `retry_after_ms`, 413 without |
| `unavailable` | The signer cannot do it now: a disk error, a storage lock, or, for `export_run`, a run that no checkpoint covers yet because the signer is still writing one. Try later. | 503 |

The HTTP status is sent only to a client that asks for it with the header `Tracekit-Errors: http-status`. Without the
header the answer is the same error frame with status 200, as the SDKs read it. A 429 or 503 that has `retry_after_ms` carries `Retry-After`,
which is `retry_after_ms` rounded up to whole seconds, and a 401 carries `WWW-Authenticate: Bearer`. More: [calling the
signer over HTTP](remote-ingest.md#calling-the-signer-over-http).

Some answers that say no are not errors. `decide` answers `allow`, `deny` or `ask` as an ordinary answer, and
`approval_consume` answers `ok: false` with a reason when it refuses.

Most calls that change state carry a `request_id`, which belongs to the caller's identity (the tables show which calls
have one). Sent again with the same payload, it gets the first answer. Sent with another payload, it gets `conflict`.
When the connection drops, the SDKs send a call again with the same `request_id`, up to three tries. When the signer
refuses a call, the SDKs send only the five event calls (`decide`, `complete`, `observe`, `state_write` and
`model_event`) again: after `unavailable`, or after `quota_exceeded` with `retry_after_ms`, up to three tries, waiting
at least `retry_after_ms`. They send no other refused call again, because the signer remembers a `request_id` only in
memory, and a retry after `unavailable` could record the call twice.

## Who may call what

The signer decides what a call may do from who is calling. The caller's identity comes from the transport (see
[Transport and auth](#transport-and-auth)), never from a field in the request. The line under each RPC says which of the
rules below applies to it.

Every call goes through these checks in order, and the first one that fails ends it:

1. The method must be an RPC on this page. Otherwise the answer is `invalid_request`.
2. The caller must be allowed to call it (the rules below). Otherwise the answer is `forbidden`. This check comes before
   the request itself is looked at, so a caller that is not allowed is never told what is wrong with its request.
3. The caller's identity must not be suspended (see `suspend`). Otherwise the answer is `forbidden`: a suspended
   identity's calls are all refused, except
   operator calls made by a break-glass identity.
4. The request must match the schema. Otherwise the answer is `invalid_request`.

**What a caller may call.** An `authorize` entry in the signer's configuration lists the RPCs an identity may call. An
entry names an identity as `scheme:subject`, or a prefix ending in `:*` or `/*`. Callers that sign in with OpenID
Connect can also be named by `person:` and `group:` (see [Identity](identity.md#oidc-issuers)). For its own name
a caller gets one entry: the exact one, else the one with the longest matching prefix. An OpenID Connect caller also
gets its `person:` and `group:` entries, and may call everything those entries list together. If at least one entry
matches, the caller may call exactly what the matching entries list and nothing else: the default grants below do not apply to it. If no entry
matches, a local user (scheme `uid`) and the dev token (`token:dev`) get the default grants, and every other caller may
call nothing, so each of its calls is `forbidden`.

**The default grants** are every RPC on this page except the ones in this table. The table lists the calls that are
never granted by default. Each one needs an `authorize` entry, or the rule in the right-hand column.

| Call | Who may use it |
|---|---|
| `incident_list`, `incident_show`, `incident_resolve`, `run_hold`, `run_quarantine`, `run_resume`, `response_pause`, `response_resume`, `suspend`, `unsuspend`, `run_label_clear` | The operator calls. See **Operator calls** below. |
| `content_get` | Granted as `content_read`, not under its own name. See **The content vault grant** below. |
| `content_erase`, `approval_agents`, `decision_import` | Only a caller whose `authorize` entry lists the call. |
| `approval_review` | Only an agent approver whose `authorize` entry lists it. See **Agent approvers** below. |
| `approval_decide_on_behalf` | Only a bridge whose `authorize` entry lists it. A chat bridge (for example Slack) needs it to answer for the people it serves, and any bridge, the viewer too, needs it to send `on_behalf` on `approval_get`, `approval_list`, `approval_decide`, `approval_revoke` and `passkey_register`. |
| `export_run` | Only a caller whose `authorize` entry lists it, and only with the extra rules under **Downloading runs** below. |
| `observe_effect` | Only an identity whose `authorize` entry lists it. Give it to the egress observer's or kernel sensor's own identity, never an agent's (the signer does not check this). |
| `tailer_heartbeat` | Only an identity whose `authorize` entry lists it. Holding the grant is what marks an identity as a transcript tailer, so an agent cannot keep a dead tailer's heartbeats going with its own token. |
| `channel_open` | Only an identity named in `box_daemons`, whatever `authorize` lists. |

**A default grant is not always enough.** Being on the default list means the signer accepts the call from that caller.
It does not mean the call will succeed, because these calls are checked again:

- `approval_decide`, `approval_revoke`, `grant_issue`, `grant_list` and `grant_revoke` follow the rules for who may
  answer a run's approvals: see [Who may answer](approvals.md#who-may-answer) and
  [Who may issue a grant](intent-grants.md#who-may-issue-a-grant).
- `pcm_sign`, `pcm_grant`, `pcm_delegate` and `pcm_evidence` work only for the run's own agent.
- `why_finding` and `review_finding` work only in a findings run: a run registered with `analyzes`, which only an
  identity listed under `analyzers` may do.

**Agent approvers.** An identity named in `approvals.agents` is an agent approver (see
[Agent approvers](approvals.md#agent-approvers)). It gets no default grants. It may call only `approval_list`,
`approval_review`, `approval_decide` and `status`, and only the ones an `authorize` entry lists for it. A call to
anything else is `forbidden`, even if its entry lists it.

**A box's agent channel.** A Tracekit Box daemon opens a channel with `channel_open` (see
[Tracekit Box](limits.md#tracekit-box-experimental)). The channel acts as the identity `box:<uid>/<box id>`, and it may
call only `register_run`, `decide`, `complete`, `observe`, `model_event`, `state_write`, `approval_request`,
`approval_wait`, `approval_consume`, `approval_get`, `approval_abandon`, `constraint_add`, `close_run`, `tailer_lost`
and `status`, whatever `authorize` lists. When its daemon is suspended, the channel stops with it.

**Operator calls.** `incident_list`, `incident_show`, `incident_resolve`, `run_hold`, `run_quarantine`, `run_resume`,
`response_pause`, `response_resume`, `suspend`, `unsuspend` and `run_label_clear` are for people who run containment (see
[Operators](incidents.md#operators)). An agent's identity cannot operate its own containment. The signer refuses to
start if one `authorize` entry lists `register_run` together with an operator call, and it checks again on every call,
because an identity can match several entries. A call is also refused with `forbidden` for an identity that may
`register_run` through all its entries together, or that owns open runs, so give operators an identity of their own.
`incident_resolve`, `run_resume` and `run_label_clear` apply a second check to the person who calls: see
[Operators](incidents.md#operators).

**Downloading runs.** `export_run` is for an identity that only reads. One `authorize` entry may list it together with
`status`, `read`, `approval_get`, `approval_list`, `grant_list`, `incident_list` and `incident_show` only, and the
signer refuses to start otherwise. An identity can match several entries, so every call checks them all together: if
they grant any call that writes, `export_run` is `forbidden`. The caller also needs a tenant of its own, named in
`tenants` or carried by its token or OpenID Connect issuer. The default tenant does not count.

**The content vault grant.** The grant for `content_get` is named `content_read`. Write `content_read` in an `authorize`
entry. The signer refuses to start if an entry lists `content_get`. The dev signer grants `content_read` to your own
user, unless `TRACEKIT_DEV_CONTENT=0`.

## Runs and calls

### `register_run`

Starts a run, which is one agent session, and returns its `run_id` and a run token. Every later call for the run
presents that token. The signer records the start as `run.registered`. A sub-agent sends its parent's run token in
`parent`, which links the two runs. The fields `tenant`, `source`, `analyzes`, `replay_of` and `box` are for special
callers: the signer refuses them unless its configuration allows the caller to use them. The answer's `fail_modes` says,
for each tool class and for `default`, whether a call may run when the client cannot reach the signer: `open` lets it
run unrecorded, and `closed` stops it. A tool class with no entry follows `default`; only with no `default` either does it fail closed.

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
| `source` | always `"migrated"` | no |  |
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
| `box.channel` | always `"agent"` | no |  |
| `box.allow` | list of texts | yes | up to 256 items; each item: 1 to 261 characters; matches `^[A-Za-z0-9.*:\[\]_-]+(?![\s\S])` |
| `continues` | always `true` | no |  |
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
| `fail_modes` | object | no | each value: one of `open`, `closed` |

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
attempt, so a retry of the same attempt with the same arguments gets the same answer.

`agent_id` names the sub-agent that made the call, as the harness reported it (Claude Code's subagent id). The signer
signs it as the decision's `agent_id` and its result's, with `parent_id` `main`; a call without one is the main
agent's. It is descriptive: the signer checks nothing against it, and the caller is still the run token's identity.

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
| `agent_id` | text | no | 1 to 200 characters |
| `args_source` | one of `raw`, `parsed`, `coerced` | yes |  |
| `args` | any value | yes | when `args_source` is `"raw"`: text; up to 1048576 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `decision` | one of `allow`, `deny`, `ask` | yes |  |
| `decision_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `rule_ids` | list of texts | yes | up to 32 items; each item: up to 64 characters |
| `reason` | text | no | up to 1024 characters |
| `run_seq` | whole number | yes |  |
| `expires_at` | text | no | up to 40 characters |
| `send_result` | always `true` | no |  |
| `recorded` | list of texts | no | up to 32 items; each item: up to 64 characters |
| `noted` | text | no | up to 1024 characters |
| `incident_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

</details>
<!-- api-doc:end decide -->

### `complete`

Reports the result of a tool call that was decided. The client sends the `decision_id`, an `args_digest` of the tool and
arguments it actually ran, and the result or error. The digest is `sha256:` and the SHA-256 of the canonical JSON (RFC
8785) of `{"tool": <name>, "args": <arguments>}`, in lowercase hexadecimal, with the `tool` name sent to `decide` and
the arguments as parsed JSON, also when `decide` got them as raw text. The signer checks that the digest matches the
decision (otherwise `args_mismatch`), removes secrets from the result, and records a commitment to it. If the call ran
after a deny, or after an ask with no consumed approval, the signer also records an `executed_against_policy` gap.

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
| `redaction.rules` | list of texts | no | up to 32 items; each item: up to 64 characters |
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
| `effects[] (kind net)` | object | no |  |
| `effects[] (kind net).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind net).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind net).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind net).kind` | always `"net"` | yes |  |
| `effects[] (kind net).host` | text | yes | 1 to 253 characters; matches `^[a-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind net).port` | whole number | yes | at least 1; at most 65535 |
| `effects[] (kind net).bytes_out` | whole number | yes |  |
| `effects[] (kind net).bytes_in` | whole number | yes |  |
| `effects[] (kind net).connections` | whole number | yes |  |
| `effects[] (kind net).first_ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind net).last_ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind exec)` | object | no |  |
| `effects[] (kind exec).kind` | always `"exec"` | yes |  |
| `effects[] (kind exec).args_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `effects[] (kind exec).parent_exec_id` | text | no | 1 to 256 characters |
| `effects[] (kind exec).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind exec).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind exec).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind exec).ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind exec).pid` | whole number | yes | at least 0; at most 4294967295 |
| `effects[] (kind exec).binary` | text | yes | 1 to 4096 characters |
| `effects[] (kind exec).exec_id` | text | no | 1 to 256 characters |
| `effects[] (kind exec).tool_call_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind exec).denied` | always `true` | no |  |
| `effects[] (kind exit)` | object | no |  |
| `effects[] (kind exit).kind` | always `"exit"` | yes |  |
| `effects[] (kind exit).status` | whole number | no | at least 0; at most 4294967295 |
| `effects[] (kind exit).signal` | text | no | up to 32 characters |
| `effects[] (kind exit).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind exit).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind exit).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind exit).ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind exit).pid` | whole number | yes | at least 0; at most 4294967295 |
| `effects[] (kind exit).binary` | text | yes | 1 to 4096 characters |
| `effects[] (kind exit).exec_id` | text | no | 1 to 256 characters |
| `effects[] (kind exit).tool_call_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind exit).denied` | always `true` | no |  |
| `effects[] (kind connect)` | object | no |  |
| `effects[] (kind connect).kind` | always `"connect"` | yes |  |
| `effects[] (kind connect).host` | text | yes | 1 to 253 characters; matches `^[a-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind connect).port` | whole number | yes | at least 0; at most 65535 |
| `effects[] (kind connect).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind connect).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind connect).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind connect).ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind connect).pid` | whole number | yes | at least 0; at most 4294967295 |
| `effects[] (kind connect).binary` | text | yes | 1 to 4096 characters |
| `effects[] (kind connect).exec_id` | text | no | 1 to 256 characters |
| `effects[] (kind connect).tool_call_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind connect).denied` | always `true` | no |  |
| `effects[] (kind file)` | object | no |  |
| `effects[] (kind file).kind` | always `"file"` | yes |  |
| `effects[] (kind file).path` | text | yes | 1 to 4096 characters |
| `effects[] (kind file).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind file).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind file).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind file).ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind file).pid` | whole number | yes | at least 0; at most 4294967295 |
| `effects[] (kind file).binary` | text | yes | 1 to 4096 characters |
| `effects[] (kind file).exec_id` | text | no | 1 to 256 characters |
| `effects[] (kind file).tool_call_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind file).denied` | always `true` | no |  |
| `effects[] (kind policy)` | object | no |  |
| `effects[] (kind policy).kind` | always `"policy"` | yes |  |
| `effects[] (kind policy).ts` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `effects[] (kind policy).change` | text | yes | 1 to 64 characters; matches `^[a-z0-9_.-]+(?![\s\S])` |
| `effects[] (kind policy).policy_hash` | text | no | 1 to 128 characters |
| `effects[] (kind policy).by` | text | no | 1 to 256 characters |
| `effects[] (kind policy).detail_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `effects[] (kind policy).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind policy).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind policy).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `effects[] (kind lost)` | object | no |  |
| `effects[] (kind lost).kind` | always `"lost"` | yes |  |
| `effects[] (kind lost).reason` | text | yes | 1 to 1024 characters |
| `effects[] (kind lost).run_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `effects[] (kind lost).run_token` | text | no | 1 to 1024 characters |
| `effects[] (kind lost).caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `check` | object | no |  |
| `check.run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `check.run_token` | text | yes | 1 to 1024 characters |
| `sensor` | one of `tetragon`, `falco`, `openshell` | no |  |
| `callers` | list of texts | no | up to 256 items; each item: up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
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
| `prev_digest` | text or nothing | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

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
| `tool_uses` | list of objects | no | up to 128 items; each item: one of (when `executed_by` is `"provider"`: allows only `id`, `name`, `executed_by`, `id_synthetic`) or (when `executed_by` is `"provider"`: requires `args_source` and `args_digest`, allows only `id`, `name`, `executed_by`, `id_synthetic`, `args_source`, `args_digest`) or (when `executed_by` is `"client"`: requires `args_source` and `args_digest`) or (when `executed_by` is `"client"`: requires `args_source` and `args_unparseable`) |
| `tool_uses[].id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_uses[].name` | text | yes | 1 to 256 characters |
| `tool_uses[].executed_by` | one of `client`, `provider` | yes |  |
| `tool_uses[].args_source` | one of `raw`, `parsed`, `coerced` | depends |  |
| `tool_uses[].args_digest` | text | depends | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `tool_uses[].args_unparseable` | always `true` | depends |  |
| `tool_uses[].id_synthetic` | always `true` | no |  |
| `said_only` | always `true` | no |  |
| `tool_results_sent` | list of texts | no | up to 1024 items; each item: 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_results` | list of objects | no | up to 1024 items |
| `tool_results[].id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `tool_results[].forms` | list of objects | yes | 1 to 3 items |
| `tool_results[].forms[].digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `tool_results[].forms[].result_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `caller` | text | no | up to 256 characters; matches `^[a-z0-9_]+:[^\n]+(?![\s\S])` |
| `amended` | list of texts | no | 1 to 16 items; each item: up to 256 characters; matches `^(/([^~/]\|~[01])*)+(?![\s\S])` |
| `body` | any value | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_seq` | whole number | yes |  |
| `fail_modes` | object | no | each value: one of `open`, `closed` |
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
| `rule_ids` | list of texts | no | up to 32 items; each item: up to 64 characters |
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
| `rule_ids` | list of texts | no | up to 32 items; each item: up to 64 characters |
| `reason` | text | no | up to 1024 characters |
| `send_result` | always `true` | no |  |
| `same_args` | true or false | no |  |
| `approval_id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approval` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | no |  |
| `consumed` | true or false | no |  |
| `refused` | list of texts | no | up to 32 items; each item: up to 64 characters |
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
| `project` | text | no | 1 to 1024 characters |

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
| `timeout_ms` | whole number | no | at least 0; at most 300000 |

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
those it may answer. A break-glass identity sees (and may answer) every tenant's approvals. A bridge granted
`approval_decide_on_behalf` sees its own tenant's, and sends `on_behalf` to read as the person who signed in; any other
caller never sees another tenant's.

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
| `on_behalf.groups` | list of texts | no | up to 64 items; each item: up to 256 characters |
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
| `rule_ids` | list of texts | yes | up to 32 items; each item: up to 64 characters |
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
| `ai` | object | no |  |
| `ai.mode` | one of `enforce`, `shadow`, `null` | yes |  |
| `ai.reason` | text | yes | up to 1024 characters |
| `ai.answer` | object | no |  |
| `ai.answer.decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `ai.answer.mode` | one of `enforce`, `shadow` | yes |  |
| `ai.answer.by` | text | yes | up to 256 characters |
| `ai.answer.reason` | text | no | up to 1024 characters |
| `ai.answer.view` | text | no | text: up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])`; text: up to 77 characters; matches `^hmac-sha256:[0-9a-f]{64}(?![\s\S])` |
| `ai.answer.matched` | object | no |  |
| `ai.answer.matched.approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `ai.answer.matched.by` | text | no | up to 256 characters |
| `ai.answer.matched.at` | text | no | up to 40 characters |
| `ai.answer.matched.target` | text | no | up to 1024 characters |
| `ai.answer.answers` | list of objects | no | 1 to 2 items |
| `ai.answer.answers[].model` | text | yes | 1 to 128 characters |
| `ai.answer.answers[].decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `ai.answer.answers[].identity` | text | no | 1 to 256 characters |
| `ai.answer.revoked` | object | no |  |
| `ai.answer.revoked.by` | text | yes | up to 256 characters |
| `ai.answer.revoked.at` | text | yes | up to 40 characters |
| `ai.answer.revoked.reason` | text | no | up to 1024 characters |
| `args_source` | one of `raw`, `parsed`, `coerced` | yes |  |
| `args` | any value | yes |  |
| `binding_digest` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

</details>
<!-- api-doc:end approval_get -->

### `approval_list`

Lists the approvals the caller may see, a page at a time, oldest first. Send the previous answer's `next_cursor` as
`cursor` to get the next page. `state`, `escalated` and `for` narrow the list: `for: agent` gives the approvals an agent
approver may answer now, and `for: person` gives all the others, including the approvals an agent reviews in shadow mode. An agent approver lists without `run_id`, and the
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
| `limit` | whole number | no | at least 1; at most 1000 |
| `on_behalf` | object | no |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items; each item: up to 256 characters |
| `on_behalf.tenant` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | no |  |
| `escalated` | true or false | no |  |
| `for` | one of `agent`, `person` | no |  |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approvals` | list of objects | yes | up to 1000 items |
| `approvals[] (variant 1)` | object | no |  |
| `approvals[] (variant 1).approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approvals[] (variant 1).state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `approvals[] (variant 1).run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approvals[] (variant 1).tool_call_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approvals[] (variant 1).attempt` | whole number | yes |  |
| `approvals[] (variant 1).tool` | text | yes | up to 256 characters |
| `approvals[] (variant 1).rule_ids` | list of texts | yes | up to 32 items; each item: up to 64 characters |
| `approvals[] (variant 1).policy_hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `approvals[] (variant 1).requester` | text | yes | up to 256 characters |
| `approvals[] (variant 1).expires_at` | text | yes | up to 40 characters |
| `approvals[] (variant 1).passkey` | always `true` | no |  |
| `approvals[] (variant 1).escalated` | always `true` | no |  |
| `approvals[] (variant 1).agent` | always `true` | no |  |
| `approvals[] (variant 1).answered` | object | no |  |
| `approvals[] (variant 1).answered.by` | text | yes | up to 256 characters |
| `approvals[] (variant 1).answered.kind` | one of `person`, `agent` | yes |  |
| `approvals[] (variant 1).escalation` | object | no |  |
| `approvals[] (variant 1).escalation.by` | one of `agent`, `signer` | yes |  |
| `approvals[] (variant 1).escalation.reason` | text | no | up to 1024 characters |
| `approvals[] (variant 1).run_closing` | always `true` | no |  |
| `approvals[] (variant 1).ai` | object | no |  |
| `approvals[] (variant 1).ai.mode` | one of `enforce`, `shadow`, `null` | yes |  |
| `approvals[] (variant 1).ai.reason` | text | yes | up to 1024 characters |
| `approvals[] (variant 1).ai.answer` | object | no |  |
| `approvals[] (variant 1).ai.answer.decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `approvals[] (variant 1).ai.answer.mode` | one of `enforce`, `shadow` | yes |  |
| `approvals[] (variant 1).ai.answer.by` | text | yes | up to 256 characters |
| `approvals[] (variant 1).ai.answer.reason` | text | no | up to 1024 characters |
| `approvals[] (variant 1).ai.answer.view` | text | no | text: up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])`; text: up to 77 characters; matches `^hmac-sha256:[0-9a-f]{64}(?![\s\S])` |
| `approvals[] (variant 1).ai.answer.matched` | object | no |  |
| `approvals[] (variant 1).ai.answer.matched.approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approvals[] (variant 1).ai.answer.matched.by` | text | no | up to 256 characters |
| `approvals[] (variant 1).ai.answer.matched.at` | text | no | up to 40 characters |
| `approvals[] (variant 1).ai.answer.matched.target` | text | no | up to 1024 characters |
| `approvals[] (variant 1).ai.answer.answers` | list of objects | no | 1 to 2 items |
| `approvals[] (variant 1).ai.answer.answers[].model` | text | yes | 1 to 128 characters |
| `approvals[] (variant 1).ai.answer.answers[].decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `approvals[] (variant 1).ai.answer.answers[].identity` | text | no | 1 to 256 characters |
| `approvals[] (variant 1).ai.answer.revoked` | object | no |  |
| `approvals[] (variant 1).ai.answer.revoked.by` | text | yes | up to 256 characters |
| `approvals[] (variant 1).ai.answer.revoked.at` | text | yes | up to 40 characters |
| `approvals[] (variant 1).ai.answer.revoked.reason` | text | no | up to 1024 characters |
| `approvals[] (variant 2)` | object | no |  |
| `approvals[] (variant 2).approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `approvals[] (variant 2).state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |
| `approvals[] (variant 2).tool` | text | yes | up to 256 characters |
| `approvals[] (variant 2).rule_ids` | list of texts | yes | up to 32 items; each item: up to 64 characters |
| `approvals[] (variant 2).policy_hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `approvals[] (variant 2).expires_at` | text | yes | up to 40 characters |
| `approvals[] (variant 2).escalated` | always `true` | no |  |
| `approvals[] (variant 2).agent` | always `true` | no |  |
| `approvals[] (variant 2).run_closing` | always `true` | no |  |
| `next_cursor` | text or nothing | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

</details>
<!-- api-doc:end approval_list -->

### `approval_decide`

Answers a held call: `approve` or `reject`. `escalate` is an agent approver's answer, and the signer refuses it from a
person. The signer records who answered as its transport established it, and whether the approver is the call's own
requester (`self_approved`). The run's principal never answers. The requester and the run's owner may answer only with
`self_approval: allow` (or on a signer with no `approvals` section), and never for a held call. A break-glass
identity must give a `reason`. A call marked as high risk needs a `passkey` assertion
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
| `on_behalf.groups` | list of texts | no | up to 64 items; each item: up to 256 characters |
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
| `ai` | object | no |  |
| `ai.answers` | list of objects | yes | 1 to 2 items |
| `ai.answers[].model` | text | yes | 1 to 128 characters |
| `ai.answers[].decision` | one of `approve`, `reject`, `escalate` | yes |  |
| `ai.answers[].identity` | text | no | 1 to 256 characters |
| `view_digest` | text | no | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |

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
| `groups` | list of texts | no | up to 32 items; each item: up to 64 characters; matches `^slack:[A-Z0-9]+/[A-Z0-9]+(?![\s\S])` |

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
| `redacted` | list of texts | yes | up to 4096 items; each item: up to 4096 characters |
| `ai` | object | no |  |
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
| `args` | any value | yes | when `args_source` is `"raw"`: text; up to 1048576 characters |
| `approval_id_hint` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `ok` | true or false | yes |  |
| `rule_ids` | list of texts | yes | up to 32 items; each item: up to 64 characters |
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
| `on_behalf.groups` | list of texts | no | up to 64 items; each item: up to 256 characters |
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
| `revoked` | list of texts | yes | up to 100000 items; each item: 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

</details>
<!-- api-doc:end approval_agents -->

### `approver`

The [AI approver](approvals.md#the-ai-approver), for people. `status` says whether a person switched it on or off
(`switch`), the rules and mode the policy gives it, how often people agreed with it per rule (`agreement`), the rules
its circuit breaker dropped to shadow, the playbook in force and the entries people's answers propose. `on` (for
`rules` only, when given) and `off` switch it; `off` withdraws its approvals not yet used and hands its waiting calls to
people (`revoked` lists the approvals withdrawn). `accept` puts a proposal in force (`id`: `L-…`, a lesson drafted
from a disagreement with a person, or `P-…`, from people's answers all one way), `drop` drops one, `retire` ends one in
force, `revoke` takes back a precedent (`id`: the approval id of a person's answer), and `enable` turns rules the
breaker dropped back on. Each change is a signed record in the tenant's signer run, and needs `request_id` (and, from a
break-glass identity, a `reason`). A signer without an AI approver (no `approvals.agents`, or no `approval_agent` in its policy) answers `invalid_request`.

**Who may call:** an approver of the caller's tenant (`approvals.approvers` or `break_glass`), with the default grants or
an `authorize` entry that lists `approver`, and for a change, no agent session open as that identity (unless
`self_approval: allow`). An agent approver can't.

<!-- api-doc:begin approver -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | depends | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `action` | one of `status`, `on`, `off`, `accept`, `retire`, `drop`, `revoke`, `enable` | yes |  |
| `id` | text | no | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `rules` | list of texts | no | 1 to 32 items; each item: up to 64 characters |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|

</details>
<!-- api-doc:end approver -->

### `passkey_register`

Registers the passkey of the person a bridge acts for, named in `on_behalf`: its `credential_id` and its `public_key`
(DER SubjectPublicKeyInfo, P-256 or Ed25519). A person keeps the first passkey registered: a second registration is
refused, and only an operator can remove one. The signer takes the bridge's word for who the person is. A passkey is
what a high-risk approval requires.

**Who may call:** any caller with the default grants (a local user, or the dev token), or one whose `authorize` entry
lists `passkey_register`. `on_behalf` is required, so only a bridge whose `authorize` entry lists both `passkey_register`
and `approval_decide_on_behalf` can call it, such as the viewer for the person it acts for.

<!-- api-doc:begin passkey_register -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `on_behalf` | object | yes |  |
| `on_behalf.subject` | text | yes | 1 to 256 characters |
| `on_behalf.person` | text | yes | 1 to 256 characters |
| `on_behalf.groups` | list of texts | no | up to 64 items; each item: up to 256 characters |
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
| `rpc_version` | always `29` | yes |  |
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
| `limit` | whole number | no | at least 1; at most 1000 |

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
your own user, unless `TRACEKIT_DEV_CONTENT=0`.

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
| `items` | list of objects | yes | up to 1000 items; each item: one of (requires `content` and `salt`) or (requires `content` and `redacted`) or (requires `state`) |
| `items[].seq` | whole number | yes |  |
| `items[].content` | any value | depends |  |
| `items[].salt` | text | depends | up to 64 characters |
| `items[].redacted` | always `true` | depends |  |
| `items[].type` | text | no | up to 64 characters |
| `items[].source` | text | no | up to 256 characters |
| `items[].state` | one of `not_retained`, `too_large`, `erased` | depends |  |

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
| `finding.p_with` | number | yes | at least 0; at most 1 |
| `finding.p_without` | number | yes | at least 0; at most 1 |
| `finding.effect` | number | yes | at least -1; at most 1 |
| `finding.interval` | list of numbers | yes | exactly 2 items; each item: at least -1; at most 1 |
| `finding.verdict` | one of `causal`, `suppressive`, `ruled-out`, `inconclusive`, `not-applied` | yes |  |
| `finding.replay_runs` | list of objects | yes | up to 4096 items |
| `finding.replay_runs[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `finding.replay_runs[].arm` | one of `control`, `ablated` | yes |  |
| `finding.replay_runs[].hit` | true or false | yes |  |
| `finding.models` | list of texts | yes | up to 32 items; each item: up to 128 characters |
| `finding.rung` | one of `1`, `2` | yes |  |
| `finding.off_tape` | whole number | yes |  |
| `finding.investigation` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `finding.looks` | whole number | yes | at least 1; at most 4096 |
| `finding.family` | whole number | yes | at least 1; at most 4096 |
| `finding.min_effect` | number | yes | at least 0; at most 1 |
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
| `review.verdict (kind finding)` | object | no |  |
| `review.verdict (kind finding).kind` | always `"finding"` | yes |  |
| `review.verdict (kind finding).rule` | one of `TK-X201`, `TK-X202`, `TK-X203`, `TK-X204`, `TK-X205`, `TK-X206`, `TK-X207`, `TK-X208`, `TK-X210`, `TK-X101`, `TK-X102`, `TK-X103`, `TK-X104`, `TK-X111`, `TK-X112`, `TK-X113`, `TK-X114`, `TK-X120`, `TK-X211`, `TK-X212` | yes |  |
| `review.verdict (kind finding).severity` | one of `info`, `low`, `medium`, `high`, `critical` | yes |  |
| `review.verdict (kind finding).tier` | one of `gateway`, `harness`, `transcript`, `sdk` | no |  |
| `review.verdict (kind finding).order` | one of `signed_before`, `transcript_order`, `after` | no |  |
| `review.verdict (kind finding).redacted` | true or false | no |  |
| `review.verdict (kind finding).lifted` | true or false | no |  |
| `review.verdict (kind finding).digests` | list of texts | no | up to 32 items; each item: up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `review.verdict (kind finding).alignment` | one of `ok`, `drift`, `misaligned` | no |  |
| `review.verdict (kind finding).reason` | one of `none`, `unrequested_action`, `unexplained_action`, `contradicted_reasoning`, `scope_creep`, `workaround`, `false_success`, `followed_tool_output`, `injection`, `other` | no |  |
| `review.verdict (kind finding).asserted` | object | no |  |
| `review.verdict (kind finding).asserted.model` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:/@+-]+(?![\s\S])` |
| `review.verdict (kind finding).asserted.version` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:/@+-]+(?![\s\S])` |
| `review.verdict (kind finding).asserted.prompt_hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `review.verdict (kind finding).families` | object | no |  |
| `review.verdict (kind finding).families.reviewer` | one of `anthropic`, `openai`, `google`, `meta`, `mistral`, `deepseek`, `qwen`, `xai`, `null` | yes |  |
| `review.verdict (kind finding).families.agent` | list of (one of `anthropic`, `openai`, `google`, `meta`, `mistral`, `deepseek`, `qwen`, `xai`) | yes | up to 8 items |
| `review.verdict (kind finding).window` | object | no |  |
| `review.verdict (kind finding).window.grace_s` | number | yes | at least 0; at most 86400 |
| `review.verdict (kind finding).window.skew_s` | number | yes | at least 0; at most 86400 |
| `review.verdict (kind coverage)` | object | no |  |
| `review.verdict (kind coverage).kind` | always `"coverage"` | yes |  |
| `review.verdict (kind coverage).rule` | always `"TK-X200"` | yes |  |
| `review.verdict (kind coverage).severity` | always `"info"` | yes |  |
| `review.verdict (kind coverage).checks` | object | yes |  |
| `review.verdict (kind coverage).checks.TK-X201` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X201.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X201.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X201.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X201.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X201.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X202` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X202.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X202.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X202.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X202.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X202.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X203` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X203.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X203.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X203.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X203.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X203.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X204` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X204.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X204.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X204.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X204.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X204.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X205` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X205.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X205.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X205.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X205.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X205.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X206` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X206.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X206.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X206.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X206.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X206.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X207` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X207.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X207.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X207.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X207.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X207.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X208` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X208.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X208.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X208.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X208.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X208.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X210` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X210.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X210.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X210.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X210.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X210.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X101` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X101.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X101.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X101.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X101.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X101.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X102` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X102.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X102.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X102.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X102.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X102.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X103` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X103.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X103.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X103.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X103.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X103.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X104` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X104.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X104.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X104.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X104.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X104.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X111` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X111.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X111.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X111.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X111.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X111.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X112` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X112.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X112.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X112.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X112.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X112.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X113` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X113.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X113.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X113.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X113.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X113.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X114` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X114.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X114.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X114.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X114.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X114.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X120` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X120.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X120.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X120.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X120.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X120.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X211` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X211.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X211.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X211.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X211.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X211.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X212` | object | no |  |
| `review.verdict (kind coverage).checks.TK-X212.checked` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X212.found` | whole number | yes |  |
| `review.verdict (kind coverage).checks.TK-X212.not_checkable` | list of objects | no | up to 16 items |
| `review.verdict (kind coverage).checks.TK-X212.not_checkable[].reason` | text | yes | 1 to 32 characters; matches `^[a-z][a-z_]*(?![\s\S])` |
| `review.verdict (kind coverage).checks.TK-X212.not_checkable[].n` | whole number | yes |  |
| `review.verdict (kind coverage).partial` | true or false | no |  |
| `review.verdict (kind coverage).reasoning` | object | no |  |
| `review.verdict (kind coverage).reasoning.full` | whole number | no |  |
| `review.verdict (kind coverage).reasoning.summary` | whole number | no |  |
| `review.verdict (kind coverage).reasoning.withheld` | whole number | no |  |
| `review.verdict (kind coverage).reasoning.none` | whole number | no |  |

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
| `limit` | whole number | no | at least 1; at most 1000 |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `incidents` | list of objects | yes | up to 1000 items |
| `incidents[].incident_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].ts` | text | yes | up to 40 characters |
| `incidents[].trigger` | text | yes | up to 64 characters |
| `incidents[].rule_ids` | list of texts | yes | up to 1024 items; each item: up to 256 characters |
| `incidents[].scope` | object | yes |  |
| `incidents[].scope.kind` | one of `run`, `session`, `owner`, `principal` | yes |  |
| `incidents[].scope.id` | text | yes | up to 256 characters |
| `incidents[].mode` | one of `shadow`, `enforce` | yes |  |
| `incidents[].actions` | list of texts | yes | up to 4 items; each item: up to 16 characters |
| `incidents[].state` | one of `open`, `resolved` | yes |  |
| `incidents[].runs` | list of objects | yes | up to 4096 items |
| `incidents[].runs[].run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `incidents[].runs[].state` | one of `held`, `quarantined`, `resumed`, `final` | yes |  |
| `next_cursor` | text or nothing | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

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
| `rule_ids` | list of texts | yes | up to 1024 items; each item: up to 256 characters |
| `scope` | object | yes |  |
| `scope.kind` | one of `run`, `session`, `owner`, `principal` | yes |  |
| `scope.id` | text | yes | up to 256 characters |
| `mode` | one of `shadow`, `enforce` | yes |  |
| `actions` | list of texts | yes | up to 4 items; each item: up to 16 characters |
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
| `resumed` | list of texts | yes | up to 4096 items; each item: 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |

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

### `run_label_clear`

Ends one of a run's labels ([run conditions](policy-v2.md#run-conditions)): the signer writes a `run.label` record
with `action: clear`, `by: person`, the caller's identity and person, and the redacted `reason`. The label also ends
for the run's client in the run's tenant, so a later run of theirs doesn't inherit it; an identity the run was
delegated to keeps its own runs' labels. A later call that sets the label sets it again. A label the run doesn't
carry is refused with `invalid_request`. The answer gives the `run_id`, the `label` and the `run_seq` of the record.

**Who may call:** only a caller whose `authorize` entry lists `run_label_clear`. It is never granted by default. As
for `run_resume`, the identity must run no agent, and the caller must be a person (an identity mapped in
`approvals.persons`, or an OIDC person, who is an approver, or a break-glass identity giving a `reason`) who is not
the owner, principal or requester of the run. More: [operators](incidents.md#operators). On a signer with no
`approvals` config (a dev signer), any identity of the run's tenant that may `register_run` clears it, the run's own
owner too, and the record says `self_cleared`.

<!-- api-doc:begin run_label_clear -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `label` | one of `secrets_access`, `untrusted_content` | yes |  |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `label` | one of `secrets_access`, `untrusted_content` | yes |  |
| `run_seq` | whole number | yes |  |

</details>
<!-- api-doc:end run_label_clear -->

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
| `message.claims[].evidence.records` | list of objects | yes | 1 to 16 items |
| `message.claims[].evidence.records[].event` | any value | yes |  |
| `message.claims[].evidence.records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].proof` | list of texts | yes | up to 64 items; each item: up to 44 characters |
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
| `message.grants[].parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.grants[].sig` | object | yes |  |
| `message.grants[].sig.key` | text | yes | 1 to 300 characters |
| `message.grants[].sig.sig` | text | yes | up to 88 characters |
| `message.payload` | object | no |  |
| `message.payload (kind text)` | object | no |  |
| `message.payload (kind text).kind` | always `"text"` | yes |  |
| `message.payload (kind text).text` | text | yes | up to 65536 characters |
| `message.payload (kind data)` | object | no |  |
| `message.payload (kind data).kind` | always `"data"` | yes |  |
| `message.payload (kind data).data` | any value | yes |  |
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
| `message.claims[].evidence.records` | list of objects | yes | 1 to 16 items |
| `message.claims[].evidence.records[].event` | any value | yes |  |
| `message.claims[].evidence.records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.claims[].evidence.records[].proof` | list of texts | yes | up to 64 items; each item: up to 44 characters |
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
| `message.grants[].parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `message.grants[].sig` | object | yes |  |
| `message.grants[].sig.key` | text | yes | 1 to 300 characters |
| `message.grants[].sig.sig` | text | yes | up to 88 characters |
| `message.payload` | object | no |  |
| `message.payload (kind text)` | object | no |  |
| `message.payload (kind text).kind` | always `"text"` | yes |  |
| `message.payload (kind text).text` | text | yes | up to 65536 characters |
| `message.payload (kind data)` | object | no |  |
| `message.payload (kind data).kind` | always `"data"` | yes |  |
| `message.payload (kind data).data` | any value | yes |  |
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
| `grant.parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
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
| `parent.parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
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
| `grant.parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
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
| `run_seqs` | list of whole numbers | yes | 1 to 16 items |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `checkpoint` | text or nothing | yes | 1 to 16384 characters |
| `records` | list of objects | yes | up to 16 items |
| `records[].run_seq` | whole number | yes |  |
| `records[].event` | any value | yes |  |
| `records[].hash` | text | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `records[].proof` | list of texts | yes | up to 64 items; each item: up to 44 characters |
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
configured, the issuer must be an approver of the run's tenant. The run's attested principal never may issue one, and
the requester and the run's owner may only with `self_approval: allow`, and never for a held call. On a signer with no
`approvals` section, any identity of the run's tenant may issue one. An agent approver never may.
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
| `limits` | list of objects | yes | 1 to 4 items |
| `limits[].op` | one of `sum`, `count` | yes |  |
| `limits[].field` | text | no | up to 64 characters; matches `^[a-z][a-z0-9_]*(?![\s\S])` |
| `limits[].max` | whole number | yes | at least 1 |
| `expires_at` | text | yes | up to 27 characters; matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])` |
| `description` | text | no | up to 512 characters |
| `tools` | list of texts | no | up to 16 items; each item: 1 to 256 characters |

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
| `grant.parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `grant.sig` | object | yes |  |
| `grant.sig.key` | text | yes | 1 to 300 characters |
| `grant.sig.sig` | text | yes | up to 88 characters |
| `tools` | list of texts | yes | up to 16 items; each item: 1 to 256 characters |
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
lists `grant_list`. It lists only the runs the caller may see: the run's own user, a break-glass identity, with
`approvals` configured an approver of the run's tenant, and a bridge granted `approval_decide_on_behalf`. On a signer
with no `approvals` section, any identity of the run's tenant may list them.

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
| `grants[].grant.parent` | text or nothing | yes | up to 71 characters; matches `^sha256:[0-9a-f]{64}(?![\s\S])` |
| `grants[].grant.sig` | object | yes |  |
| `grants[].grant.sig.key` | text | yes | 1 to 300 characters |
| `grants[].grant.sig.sig` | text | yes | up to 88 characters |
| `grants[].tools` | list of texts | yes | up to 16 items; each item: 1 to 256 characters |
| `grants[].limits` | list of objects | yes | 1 to 4 items |
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
lists `grant_revoke`. It works only on runs the caller may see, as for `grant_list`: on a signer with no `approvals` section that is any
identity of the run's tenant, and a bridge granted `approval_decide_on_behalf` may too.

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

A caller reaches the signer in one of three ways: over HTTPS, over a Unix socket on the same machine, or, for a dev
signer on Windows, over a loopback TCP port. All three carry the same JSON frames, and a client sends `hello` first (see
[Versioning](#versioning)). On every one the signer works out who the caller is from the connection or the credential,
never from anything the frame says. Over HTTPS it does so again for every request; the Unix socket and loopback TCP
paragraphs say what they do.

| Where the signer runs | How a caller reaches it | Who the signer takes the caller to be |
|---|---|---|
| Laptop, dev signer (Linux, macOS) | A Unix socket that the first client starts | `uid:<number>`, the caller's user id |
| Laptop, dev signer (Windows) | A loopback TCP port | The dev token, `token:dev` |
| Laptop, system mode | The Unix socket `/run/tracekit-signer/signer.sock` (Linux; on macOS `/Library/Application Support/tracekit-signer/signer.sock`) | `uid:<number>` |
| Container sidecar | A Unix socket in a directory shared with the agent | `uid:<number>` |
| Central signer, or Compose | HTTPS | `token:`, `k8s_sa:`, `mtls:` or `oidc:` and the name the credential gives |

The agent's code does not change between these. The environment variable `TRACEKIT_SIGNER` tells the client where the
signer is: a socket path, `tcp://host:port` on a loopback address (the Windows dev signer, whose token goes in
`TRACEKIT_SIGNER_TOKEN`), an `https://` URL, or, in the Python SDK only, `http://` on a loopback address. In system mode the client takes the
signer from the root-owned file `/etc/tracekit/client.json` and refuses a `TRACEKIT_SIGNER` that names another signer,
so an agent cannot point itself at a signer it runs. See [Deploying the signer](deploy.md).

**HTTPS.** A central signer listens on the address in the `http` section of its configuration. Each call is one
`POST /v2/rpc` whose body is one JSON frame, `{"method": ..., ...}`, and the answer is one JSON frame. The body must
come with exactly one `Content-Length` header (without it the answer is 411) and may be at most 1 MiB (1,048,576 bytes)
long; a longer one gets 413. The signer refuses a chunked body (`Transfer-Encoding`), two `Content-Length` headers and a
malformed header line with `invalid_request` (400), and closes the connection. Nothing is remembered between requests:
every request is authenticated again. A POST to any other path is a 404. `hello` is not an RPC on this page, but over
HTTPS it needs credentials like any other frame.

```bash
curl -si https://tracekit.example:8443/v2/rpc -H "Authorization: Bearer $TRACEKIT_API_KEY" \
  -H 'Content-Type: application/json' -H 'Tracekit-Errors: http-status' -d '{"method": "status"}'
```

This call succeeds only for a caller that may call `status` (see [Who may call what](#who-may-call-what)).

To reach a signer, the SDKs read `TRACEKIT_SIGNER` (the URL), `TRACEKIT_SIGNER_TOKEN_FILE` (a file holding the token,
read again on every call, so a rotated token is picked up), `TRACEKIT_SIGNER_CA` (the CA that the signer's certificate
must chain to) and, for `mtls`, `TRACEKIT_SIGNER_CERT` and `TRACEKIT_SIGNER_KEY` (the client certificate and, if it is
in another file, its key). Without a token file they use the token in `TRACEKIT_API_KEY`. The TypeScript SDK takes `https://` only. The Python SDK
also takes a plain `http://` URL, but refuses one whose host is not a loopback address. See [Remote clients](remote-ingest.md#calling-the-signer-over-http).

**Proving who you are over HTTPS.** The `authenticators` list in the `http` section turns on any of four ways to prove
identity. The signer asks them in the order listed, and the first one that recognises its credential decides. If none
does, the answer is `unauthenticated`. An authenticator passes on a request that carries no credential of its kind.
`k8s_sa` takes any token shaped like a JWT and refuses it if it is not its own, so when you use both, list `oidc` before
`k8s_sa`: `oidc` passes on a token whose issuer it does not know. What the identity may then call is under
[Who may call what](#who-may-call-what).

| Authenticator | What the caller sends | Identity |
|---|---|---|
| `token` | A secret the operator issued, as `Authorization: Bearer <token>`. | A named token (it looks like `tk2_<name>.<secret>`) from the `tokens` file is `token:<name>`. Named tokens expire (30 days unless the operator chose otherwise), can be revoked with no restart, and can carry a tenant. An unknown, expired or revoked one is `unauthenticated`. The one shared secret in `token_file` (at least 32 characters) is `token:http`. |
| `k8s_sa` | A Kubernetes service-account token (a JWT) as `Authorization: Bearer <token>`, made for the signer's audience. The signer checks it with the cluster's API server (a TokenReview), or against the issuer's published keys. | `k8s_sa:system:serviceaccount:<namespace>:<name>`, so `k8s_sa:system:serviceaccount:acme:*` matches every service account of the `acme` namespace. |
| `mtls` | A client TLS certificate with exactly one `spiffe://` ID. The ID's trust domain must be a key in `client_ca`, and a CA in that domain's bundle must have issued the certificate directly, with no intermediate CA. | `mtls:` and the SPIFFE ID, for example `mtls:spiffe://acme/investigator`. |
| `oidc` | An OpenID Connect token (a JWT) as `Authorization: Bearer <token>`, from an issuer the operator configured. | `oidc:<alias>/<sub>`. [Identity](identity.md) has the settings and what else the token gives. |

**Failed attempts are limited.** The signer counts failed authentications per source address and in total. Each address
may fail 20 times in a quick run and then once more every second. Across all addresses the signer allows a burst of 500
failures and then 50 a second. A failure past either limit is answered `quota_exceeded` with `retry_after_ms`, which
over HTTP with the status header is a 429 with `Retry-After`. Past the total limit a valid credential still gets in.
Past an address's limit the signer looks only at credentials it can check itself (a client certificate or a token),
never at one that needs another service (a Kubernetes check or an OpenID Connect issuer's keys), so a valid certificate
or token still gets in, and clients behind one address are not locked out by another's failures. A refusal carries only
the error: no sequence number, hash or run id. The operator can watch the count in `tracekit_signer_auth_failures_total`
on the metrics port.

**TLS.** The `http` section needs `cert` and `key`, and the signer accepts TLS 1.2 and later. Plain HTTP is allowed only
with `insecure_loopback: true` and a listen address that is a loopback IP address, not a name such as `localhost`. The
signer refuses to start otherwise. The `mtls` authenticator also needs `client_ca`, and a certificate that a client
presents must verify. A client without a certificate can still connect and use another authenticator.

**Errors and status codes.** A refusal is an error frame (see [Errors](#errors)). By default it comes with HTTP status
200, so that clients that read errors from the body only keep working. The SDKs do this, so a proxy in front of the
signer never sees their refusals and never retries or drops the signer. A client that sends the header
`Tracekit-Errors: http-status`, such as curl, gets the status that the table under [Errors](#errors) gives, with
`Retry-After` (whole seconds) on a 429 or 503 that has `retry_after_ms`, and `WWW-Authenticate: Bearer` on a 401. A
`quota_exceeded` without `retry_after_ms` is a size limit and gets 413. A decision, even a deny or an ask, is an answer
and always gets 200. Problems with the HTTP request itself get an HTTP status whatever the header says: 404 for a wrong
path, 400 or 411 for a bad or missing `Content-Length`, and 413 for a body over the limit (1 MiB for an RPC, 4 MiB for
OTLP).

**Request-Id.** Every answer carries a `Request-Id` header: `req_` and 24 hex digits, made by the signer for that
answer. It is not the `request_id` that a call sends. The signer writes one INFO line per answer, on the logger
`tracekit.transport.http`, with that id, the status, the method, the identity, the error code and the time taken. Quote
the `Request-Id` when you ask an operator about a call.

**Connections.** HTTPS connections are kept alive. The signer must receive each request, from the TLS handshake (or from
the end of the previous answer) to the last byte of the body, within 30 seconds. A slower client is cut off with no
answer. Each single read or write also times out after 30 seconds. Once a request is in, answering it has no deadline,
so a call such as `approval_wait` can take as long as it needs. The signer serves up to 1024 connections at once, and
256 from one source address. A connection past the address's limit is closed at once, and one past the overall limit
waits a second for a free place and is then closed.

**OTLP import.** When the signer's `otlp` setting is on (it needs the `http` listener), `POST /v1/traces` accepts
OpenTelemetry (OTLP/HTTP) data from the same authenticators. This is not an RPC. The body is OTLP protobuf
(`Content-Type: application/x-protobuf`) or OTLP JSON (`application/json`), plain or compressed with gzip or deflate
(`Content-Encoding`). It may be up to 4 MiB as sent, and a longer one gets 413. The unpacked body is limited to 16 MiB,
and to 32 times the size sent (but not below 1 MiB). A request may hold up to `otlp.max_spans` spans (512 by default):
with more, the whole request is rejected in `partialSuccess`. The wire decoder refuses more than 10,000 spans whatever
that setting says. The signer refuses a
request over the other limits, with another content type or encoding, or that cannot be read. The caller is authenticated
before its body is read: a request with no accepted credential gets 401, too many failed attempts get 429, and an
identity without the `otlp_import` grant gets 403.

**Unix socket.** On the same machine the caller connects to a Unix socket, and the signer takes the caller's identity
from the operating system: the effective user id of the process that connected, `uid:<number>`. A connection whose user
id the operating system cannot report gets `unauthenticated` and is closed. On Linux every frame must also carry that
user id (the operating system adds it to each frame), so a socket handed to another user's process cannot speak as the
first user: a frame from another user id gets `unauthenticated` and ends the connection. On macOS the user id is fixed
when the connection opens and frames are not checked again. Who may connect at all is decided by the permissions of the
socket's directory, and by the `socket_mode` setting when the operator sets one, which changes the permissions of the
socket file itself. A frame is one line: one JSON object per line in the request, and one per line in the answer. A line
that is not a JSON object gets `invalid_request` and the connection stays open. A line over 1 MiB (1,048,576 bytes) gets
`quota_exceeded` and the connection closes, because the signer cannot tell where the next frame starts. A failed
authentication (`unauthenticated`) also closes the connection. The signer closes a connection that sends nothing for 30
seconds. The signer answers the requests of one connection in the order it received them, so a client that makes a call
that can wait a long time, such as `approval_wait`, gives it a connection of its own, as the SDK does. After
`channel_open` succeeds, the rest of that connection is handled as the box's identity (see
[Who may call what](#who-may-call-what)), and each frame is still checked as before.

**Loopback TCP port (dev signer on Windows).** Where Unix sockets are missing, a dev signer listens on `127.0.0.1` on a
port the operating system picks. It writes the port and a secret token to a file named `endpoint.json` that only the
user can read. Each connection starts with a handshake in which both sides prove that they hold the token without
sending it. The client sends a random value, the signer answers with a proof over the client's value, made with the token, and a
random value of its own, and only after the client has checked that does it send its own proof, over the signer's
value. A process that squats on the port without
the token learns nothing it can replay. After the handshake the caller is the dev token (`token:dev`), and frames work
as they do on a Unix socket. The dev token is valid for one year, after which it gets `unauthenticated`. What it may
call is under [Who may call what](#who-may-call-what).
