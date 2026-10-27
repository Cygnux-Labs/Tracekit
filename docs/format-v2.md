# Evidence format v2

This page specifies `tracekit.bundle.v2` and the records, trees and checkpoints inside it. It aims to be precise enough
to write an independent verifier. The reference implementation is `tracekit/format/`, `tracekit/merkle/`,
`tracekit/bundle_v2.py` and `tracekit/verify/v2.py`; where this page and the code disagree, the code is right and
this page has a bug. v1 bundles (`tracekit.bundle.v1`) keep their own frozen format and verifier
([signing](signing.md)); nothing here changes how they verify.

Normative test vectors:

| Vectors | What they pin |
|---|---|
| `tests/vectors/jcs.jsonl` | canonical JSON: input, canonical bytes, SHA-256 |
| `tests/vectors/sig_v2.jsonl` | records (event, signature message, signed record) and the Ed25519 acceptance rules |
| `tests/vectors/c2sp_checkpoint.json` | a checkpoint note, its log signature and a witness cosignature |
| `tests/vectors/slh_dsa_note.json` | a hybrid checkpoint note: Ed25519 and SLH-DSA-SHA2-128s lines, keys, key ids |
| `tests/golden/v2/` | bundles (closed, open, approval, run-set) with `trust.json` and the expected report |
| `tests/golden/negative/` | one bundle per rejection, with the expected report in `expected.json` |

Every worked example on this page is checked against the code by `tests/test_format_doc_vectors.py`.

## 1. Canonical JSON

Everything hashed or signed is canonical JSON: [JCS, RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (keys sorted by
UTF-16 code units, no whitespace, ECMAScript number serialisation, minimal string escapes, UTF-8 output). Example:

```text
{"b":1,"a":[1.0,"é",1e21]}  →  {"a":[1,"é",1e+21],"b":1}
```

Every JSON text a verifier reads from a bundle or trust config, and the raw arguments a client sends, are parsed by a
strict parser (`format.canon.loads_strict`) that rejects input JCS could hash differently in different languages:

| Rejected | Error code |
|---|---|
| bytes that are not UTF-8 | `invalid_utf8` |
| anything that is not one JSON text | `syntax` |
| a key twice in one object | `duplicate_key` |
| `NaN`, `Infinity`, `-Infinity`, or a number that overflows to them | `non_finite` |
| an integer token (no `.` or exponent) above 2^53 − 1 in magnitude, or longer than 16 digits | `int_range` |
| a string or key with a lone UTF-16 surrogate (`"\ud800"`) | `lone_surrogate` |
| arrays and objects nested more than 128 deep (`[[1]]` is 2 deep) | `depth` |

Send larger integers as strings. A tool call whose raw arguments fail strict parsing is denied with rule
`TK-ARGS-INVALID` and gets no `args_commitment` ([policy](policy-v2.md)).

## 2. Hashes over agent content

The signer never publishes a plain hash of something the agent sent. It publishes a **commitment**, an HMAC that only
someone holding the record's salt can test a guess against.

- **Arguments digest:** `"sha256:" + hex(SHA-256(JCS({"tool": <tool name>, "args": <arguments>})))`, over the arguments
  as parsed (raw arguments are parsed strictly first).
- **Content digest:** `"sha256:" + hex(SHA-256(JCS(value)))` of a result, model exchange or state write, after the
  signer's redaction ([privacy](privacy.md)).
- **Salt:** `HMAC-SHA256(args_salt.key, label)`, where `args_salt.key` is the signer's secret (`keys/args_salt.key`) and
  `label` is fixed per record: `<type>:<salt_id>` when the record's `data` has a `salt_id` (current records), else
  the older labels in `pipeline.salt_label` (the `decision_id` for `policy.decision`, `"result:" + decision_id` for
  `tool.result`).
- **Commitment:** `"hmac-sha256:" + hex(HMAC-SHA256(salt, UTF-8 bytes of the digest string))`.

Worked example (salt = bytes `00 01 02 … 1f`):

```text
tool  Bash
args  {"command":"ls -la"}
JCS   {"args":{"command":"ls -la"},"tool":"Bash"}
digest      sha256:b7c38435fe712f5634b07e925ba451b8281b9c1480a7df201a2855d9ab409f64
commitment  hmac-sha256:b0793fcab9cccb7a6ae4a79f07a4b2d324f04e9fe51df1bd38fdeb0ff4e98d99
```

`tracekit signer reveal --record SEQ` prints the salt of one record ([auditor guide](auditor-guide.md)). One salt opens
one record's commitments and nothing else.

## 3. Events

An event is a `tracekit.event.v2` object, validated by `tracekit/schema/tracekit.event.v2.json` (JSON Schema 2020-12;
patterns are full-match ASCII; `maxLength` counts code points; every string and array is bounded). Unlike plain JSON
Schema, `integer` means a number token written without a fraction or exponent: `"seq": 1.0` is schema-invalid, though
its record hash is that of `"seq": 1`. It adds to v1:

| Field | Set by | Meaning |
|---|---|---|
| `log_id` | signer | the record log, 32 hex |
| `seq`, `prev_hash` | signer | position in the log and the previous record's `hash` (`sha256:` + 64 zeros at seq 0) |
| `tenant`, `run_id` | signer | the run; signer-level records use tenant `tracekit`, run `tracekit/signer`, and a tenant's own signer records (the content vault's) that tenant's run `tracekit/signer` |
| `run_seq`, `run_prev_hash` | signer | position in the run and the run's previous record hash (zeros at run_seq 0) |
| `tenant_attested`, `principal`, `principal_attested` | signer | whether tenant and principal came from the caller's verified identity |
| `request_id`, `stream`, `client_seq` | client | idempotency key and per-stream counter; a skipped `client_seq` becomes a signer gap |
| `tool_call_id`, `attempt` | client | the call a record is about |
| `tier` | signer | `T1`/`T2`/`T3` evidence tier, when known; OTLP imports are `T3` |
| `step`, `capture_layer` | — | defined by the schema; the signer does not write them yet |
| `args_commitment`, `args_source` | signer | the commitment (§2) and whether arguments were `raw`, `parsed` or `coerced` |
| `engine` | signer | the policy engine `id@version` |
| `span_id` | signer | the OTel span an imported record came from |

`source` is `hook`, `proxy`, `transcript`, `signer`, `sdk`, `gateway`, `migrated` or `import`. Gap and tamper records
(`capture.gap`, `trace.tamper`) are written only with `source: signer`; the `kind`s are listed in the schema's
`capture_gap` and `trace_tamper` definitions. A gap marked `tenant_level: true` (`witness_failed`, `witness_late`,
`clock_skew`, `degraded_unanchored`, and rollback tamper records) concerns every tenant (§7).

Lifecycle records: `run.registered` (agent, the caller identity, `signer_isolation` and `fail_modes` from the signer's
own measurement and config, and with harness binding the `harness{name, exe, pid, start_time, attested}` process the
caller descends from), `run.closing`, the run's `reconcile.*` records, then `run.final{head_run_seq, head_hash,
coverage}`. A run started by another run of the same tenant (a sub-agent's: `register_run` `parent`, whose run token
the caller presents, for a parent that is not final) has `parent_run` (that run) and `session` (the root of its chain of
parents) in its `run.registered` (format 1.2); a run without them is the root of its own session, whose id is its
`run_id`. A tool call the [tool executor](executor.md) or the [MCP gateway](mcp-gateway.md) decided, ran or received
for the run's client is recorded `source: gateway`, tier `T2`, its `policy.decision`, `approval.request`, `tool.result`
and `input.observed` naming that service's signer identity (`scheme:subject`) in `via`, and its `policy.decision` the
client it decided the call for in `caller` (format 1.2); the signer takes such a call's approval request, consume and
completion from that service, for that client, alone. A run that ends with such a call allowed (or approved and
consumed) and no result, after waiting `gateway_wait_s` for it, gets a signer `capture.gap{kind:
held_call_unresolved}` for it. Key records: `signer.epoch{keys:
[{kid, alg, spki, cert?}], bridge?}` (`cert`: the key's issuance entry from a record-key issuer, [issuer.md](issuer.md))
and `key.retire{kid, last_seq}`. The log's last record, if it is ever closed: `log.closed{final_seq}`.

Provenance (format 1.1, [policy](policy-v2.md#provenance-untrusted-and-from-untrusted)): `input.observed{source,
trust, output: {hash, size, redacted}, redaction, salt_id}` records content that entered the run through the
`observe` RPC (a mail, a ticket, the task), committed to as a tool result is (§2), never in clear; `source` is the
caller's name for it and `trust` its claim. `policy.decision` carries `provenance_state` (`complete`, `partial`,
`truncated`, `unavailable` or `timeout`; written only when it is not `complete` or `provenance` is non-empty, so a run
with nothing untrusted in its arguments needs no 1.1 verifier), `provenance_reason` (why it is not `complete`, at most
256 characters) and `provenance`: at most 16 `{field, kind, source: {run_seq, tool?, tool_call_id?}}`, the top-level
arguments whose values only untrusted content brought into the run, the kind of value (`email`, `url`, `host`, `path`,
`digits`, `string`) and the record that brought it — never the value.

Detection (format 1.2, [policy](policy-v2.md#detection-sequences-limits-and-respond)): under a policy with sequences
or limits, `policy.decision` carries `detect{sequences: [{id, step}], limits: [{id, count, window_start}], state,
rule_ids?, sums?}`. Signer records in the run whose record fired them: `incident.opened{incident_id, trigger, rule_ids,
scope: {kind, id}, cites: [{run_id, run_seq}], mode, actions, would}`, `incident.updated{incident_id, cites}` (another
match, at most once per window; for a session, owner or principal scope possibly in another run of that scope than
the one that opened it) and `incident.capped{cap, max, trigger, reason}`.

Containment (format 1.2, [incidents](incidents.md)): an enforced `incident.opened` (`mode: enforce`) lists the
`actions` taken (`hold`, `quarantine`, `notify`; none while paused, with `reason`) and `in_flight`: the
calls `{run_id, tool_call_id, decision_id}` allowed (or approved and consumed) and not completed then. Triggers
`operator` (an operator's run_hold or run_quarantine) and `detector_unavailable` (the detector could not vouch for the
cited decision) join the detection's. In each run the response reaches: `run.held{incident_id, scope, by, reason,
in_flight?, inherited?, inherit_until?}` or `run.quarantined{...the same}`, after an `approval.expired{reason: hold |
quarantine}` for each of its live approvals; `run.resumed{incident_id, by, person, reason?, break_glass?,
held_by}` ends that incident's hold; a run held by several incidents (a `run.held` each) stays held by those `held_by`
names.
A held run's calls are `policy.decision{decision: ask, rule_ids: [..., TK-HOLD], incident_id}`, their approvals carry
`incident_id` (`approval.request` and the person's `approval`); a quarantined run's are `decision: deny, rule_ids:
[TK-QUARANTINE]` and it closes with `run.closing{reason: quarantine}`. The call whose decision fired a hold gets a
second, signer-written decision right after the response. In the tenant's signer run: `incident.resolved{incident_id,
by, person, reason?, break_glass?, resumed}`, `incident.response{enabled, by, reason?}` and
`identity.suspension{identity, state: suspended | enforced | lifted, by, reason?}`.

Content vault (format 1.1, [privacy](privacy.md#the-content-vault)): `content.accessed{principal, run_id, seqs,
purpose}` records that the signer returned the retained content of records `seqs` (run_seqs) of run `run_id` to
`principal`, for `purpose`; `content.erased{run_id, reason, by}` records that it deleted that run's retained content.
Both are signer records (`source: signer`) in the run `tracekit/signer` of the tenant they concern, never in the run
itself, whose records stay unchanged. They hold no content. A bundle with either needs `verifier_min_version` 1.1.0.

`tracekit why` findings (format 1.1, [why](why.md#attribution-on-signed-runs)): a replay run's `run.registered` carries
`replay_of` (the run it replays) and `investigation`, and the signer does not reconcile it; `why.finding{target,
intervention, n, p_with, p_without, effect, interval: [lo, hi], verdict, replay_runs: [{run_id, arm: control|ablated,
hit}], models, rung, off_tape, investigation, looks, family, min_effect, applied, stopped, uncounted?: [{run_id,
reason: ranking|budget}]}`, written through the `why_finding` RPC in a findings run (`run.registered` `analyzes`),
records a finished test. A bundle of a run with its findings and replay runs (`tracekit export --v2 --run R
--with-findings`) holds those runs too; the verifier checks that every replay run a finding names is in the bundle,
once, as a replay run of the analysed run in the finding's investigation, holding its model calls as `source: gateway`
model.exchange request and response pairs (one pair for rung 1 and for `ranking`); that an `uncounted` run is `budget`
only in a finding `stopped: budget`; that with a target of `tool` clauses each `hit` has a response tool use those
clauses match and, with `tool` clauses alone, each miss has none; that the arms and outcomes count to its `n`,
`p_with`, `p_without` and `effect`; that `interval` is the Newcombe interval of those counts at z for `looks` ×
`family` comparisons (Bonferroni), rounded to 4 places, with lo ≤ hi; and that `verdict` follows from it, `applied`
and `min_effect` (`inconclusive` when `stopped` is `budget`); and that every replay run in the bundle of an
investigation with findings is named by one (`findings`, FAILED otherwise). Replay runs of an investigation with no
finding are a `replay runs` warning. In any other bundle (a findings run alone, a run-set) a finding whose replay runs
are absent is not counted (`findings counted`, a warning). A bundle with either needs `verifier_min_version` 1.1.0.

Signed findings (format 1.4, [findings](findings.md)): `tracekit analyze --v2`, run by an operator identity signer.yaml
`analyzers` lists, writes each finding through the `review_finding` RPC in a findings run (`run.registered`
`analyzes`; refused in any other run) as `review{reviewer, verdict, cites: [{run_seq, hash}]}`. `cites` are records of
the analysed run, by `run_seq` and record `hash`: the signer refuses a finding (`invalid_request`) unless each is.
The verdict holds no text of the run, only `{kind: finding, rule,
title, severity: info|low|medium|high|critical, tier?: gateway|harness|transcript|sdk (the text it relied on; harness:
a prompt the hook recorded and the transcript agree on), order?: signed_before|transcript_order|after (that text
against the call), redacted?, lifted?: true (TK-X204: a later request named what the constraint kept away, so the
finding is downgraded), digests?: [sha256:...], alignment?: ok|drift|misaligned, reason?: <a reason code> (TK-X210:
the reviewer model's answer), asserted?: {model, version, prompt_hash} (the reviewer model and prompt the analyzer
says it asked), families?: {reviewer, agent: [...]} (model families: anthropic, openai, google, meta, mistral,
deepseek, qwen, xai, or a null reviewer), window?: {grace_s, skew_s} (TK-X206, TK-X207: the window effects were
joined to calls with)}`, or once per
pass `{kind: coverage, rule: TK-X200, title, severity: info, checks: {<rule>: {checked, found, not_checkable?:
[{reason, n}]}}, partial?, reasoning?: {full, summary, withheld, none}}`. `title` is the rule's fixed title
(`rpc_schema.FINDING_TITLES`), written by the signer; `digests` are copied from the cited records, never a hash of
plaintext. The finding's author is the findings run's `run.registered` `identity`, as the signer measured it;
`reviewer` (the tool and its version) is the analyzer's claim. Excerpts, paths and reasons are shown when a person
reads the cited records (`content_get`), never signed. A `review` without `cites` (a v1 judge verdict carried over,
format 1.0) is imported, and never checked. A bundle with `cites` needs `verifier_min_version` 1.4.0.

Live constraints (format 1.4, experimental, [policy](policy-v2.md#live-constraints)): what a person's request said not
to do in the rest of a run, as a client of the run reported it (`constraint_add`; the Claude Code hook at
UserPromptSubmit): `constraint.added{kind: keep_away|only_change|read_only|no_push|no_network, object_commitment?,
salt_id?}` (`source`: the run's). `object_commitment`, for `keep_away` and `only_change` only, commits (§2, under the
record's `salt_id`) to `"sha256:" + hex(SHA-256(UTF-8 bytes of the file's name as constraints compare it))`: quotes
(`'`, `"`, `` ` ``) around it dropped, its base name (after the last `/` or `\`), trailing dots dropped, lower-cased
(`tracekit.constraints.norm`); the name is never in the record. From then on the signer raises each call of the run
that breaks a constraint to `ask` and adds the rule
id `TK-CONSTRAINT` to its `policy.decision`; it never lowers a decision. Every `policy.decision` whose `rule_ids` hold
`TK-CONSTRAINT` must be an `ask` after a `constraint.added` in its run (`constraints` fails otherwise). A constraint
equal to one the run has (the same kind; for a file, the same name) adds no record. A run takes 32 file constraints
(`keep_away`, `only_change`; the other kinds are always added): past them, a new one is a `capture.gap{kind:
constraint_refused, reason}` (`source: signer`, a `gaps` warning), so a constraint the run had no room for is never
dropped unrecorded, and the signer raises every later call of the run that writes to `ask` with `TK-CONSTRAINT`. A
directory's commitment is to its name and a slash (`legacy/`), and a call breaks it with a write under it. A bundle with `constraint.added` or `constraint_refused` needs
`verifier_min_version` 1.4.0.

Completeness (format 1.2, [limits](limits.md#signer-and-capture)): gaps for what the signer saw decided or reported
and then never heard about. All are `capture.gap` records with `source: signer`.

| `kind` | Where, when | Fields |
|---|---|---|
| `decided_not_completed` | in the run, at `run.final`: each open decision that let its call run (allowed, or asked with the call's approval consumed) and has no `complete`, unless a later decision of the call completed (for the decision a consumed approval names: with the approved arguments); a call a gateway or executor holds (`via`) gets `held_call_unresolved` instead; at most 100, then one counting the rest | `tool_use_id`, top-level `tool_call_id` and `attempt`; the last one `missed_events` |
| `concurrent_run` | in the newer run, for a run bound to a harness process: another run of the same owner, tenant and harness process, in another session, was open when it registered, and both have recorded an event since | `run_id`: the other run |
| `late_activity` | in the tenant's run `tracekit/signer`, with the refusal summaries: writes refused because their run was final (not a `close_run`, nor each identity's and stream's first one) | `run_id`: that run; `missed_events`: how many; `from_ts`, `to_ts` |
| `client_counter_gap` | also at `close_run` with `last_client_seq`: the values of a stream the closing identity wrote (or that never reached the signer) not received by then (the reason names that identity; values up to there that arrive later are recorded with no second gap). A gateway's report about a run already final goes in the tenant's run `tracekit/signer` | `missed_events`, top-level `stream`; in `tracekit/signer`, `run_id`: the run |
| `tailer_lost` | also when a transcript tailer (an identity a run was delegated to with the `tailer_heartbeat` grant) makes no call for 90 s while its run is open, counted from the delegation | — |
| `tailer_redelegated` | in the run, when a second tailer token is delegated for it | — |
| `observer_lost` | in each open run an egress observer (or a kernel sensor's import, format 1.4) covers, when it makes no `observe_effect` call for 90 s, or another process of it (`instance`) takes over; and when an import reports a loss (OpenShell's import: in the one run a loss names, when it names one) | `sensor` (format 1.4): `tetragon`, `falco` or `openshell`, when it is a sensor's import |
| `effect_outside_run` | in the tenant's run `tracekit/signer`: an egress observation no open run holds (after its `run.final` and `observe_grace_s`, a token the signer didn't issue for that run, an identity with no open run) | `run_id`: the run the client named or it was attributed to, when there is one |

Effects (format 1.2, [egress](egress.md)): an egress observer outside the agent reports the hosts each run reached
(`observe_effect`, its own identity's never-default grant); the signer writes `effect.observed{observer, kind: net,
host, port, bytes_out, bytes_in, connections, first_ts, last_ts, attribution: token|identity, explained_by?:
call|explains}` (`source: signer`, one per host, port and minute) in the run, and for a host no recorded http or model
call nor the policy's `explains` covers, once per host and run,
`reconcile.unexplained_effect{layers: [L6], observer, kind, host, port, detail}`, counted in `run.final`'s
`coverage.unreconciled`. `run.registered` carries the deployment's `posture{network: enforced|open, tool_calls:
enforced|open, gateway_mandatory, attested: false}` when signer.yaml sets `posture` or `gateway_mandatory`.
`run.final` carries `matrix`: per action class (`model_calls`, `tool_calls`, `network`, `processes`, `services`)
`{status: enforced|observed|reported|none, layers, asserted?}`, from the sources of the run's records, the posture and
the observers that covered the run throughout.

A run bound to a harness process that registers with `parent` writes a `run.child` record (`source: signer`,
`data: {run_id}`: the child) in its parent run.

A gap in a tenant's run `tracekit/signer` (`late_activity`, a gateway's `client_counter_gap`) has a leaf in that
tenant's registry (§7), so a run-set proves it; the verifier counts it with the tenant-level gaps. A
`reconcile.hook_missing` for a tool use the LLM gateway reported is written as soon as a gateway request sends its
result back with no decide, not only before `run.final`. A `model.exchange` tool use with `executed_by: provider`
carries an `args_commitment` when the provider returned its input; `run.final` carries `provider_executed`, the number
of such tool uses, which no decide covers and which are never `reconcile.fabricated` (with `gateway_mandatory`, only
those the gateway reported), and `paired_by_args`, the number of calls reconciled by pairing a decide with a tool use
of the same model turn by their arguments when the adapter had no tool-call id (never across turns, never when two
could match). A bundle with any of these kinds, fields or `run.child` needs `verifier_min_version` 1.2.0. A
`model.exchange` response with `said_only: true` (format 1.4) holds what the model said without the calls it asked for
(a harness whose hooks name no call: Gemini CLI, Cursor); reconciliation reads no call from it, so it never makes a
decide `reconcile.fabricated`.

Verified tool results (format 1.3, [gateway](gateway.md#verified-tool-results)): when signer.yaml sets
`verify_tool_results`, an LLM gateway's request record is checked against the run's tool results. For each tool result
the request sends, the gateway gives the digests of the values it may have been recorded as; the signer computes their
commitments under the salts of that call's `tool.result`s (§2). A result that matches none of a call's ok results that
carried a result (redaction having changed none of them), or a result sent for a call the run allowed and has not
completed, is a `reconcile.result_mismatch{layers: [L2, L3], detail}` (`source: signer`, `tool_call_id`), once per
call, counted in `run.final`'s `coverage.unreconciled`. A result the request names (`tool_results_sent`) that the
gateway gave no digests of (past what it digests per request, or a gateway older than 1.3), for a call with such a
result to compare, is a `capture.gap{kind: result_unchecked, tool_use_id, reason}` (`source: signer`, `tool_call_id`),
once per call. A bundle with either needs `verifier_min_version` 1.3.0.

Kernel sensor events (format 1.4, experimental, [Tetragon](integrations/tetragon.md), [Falco](integrations/falco.md)):
an import of a kernel sensor's export (`observe_effect` with `sensor`, the same grant) reports what an agent's
processes did, and names in every call the identities its configuration maps processes to (`callers`): it covers the
runs of those identities registered while it is alive, and no other run. The signer writes
`effect.observed{observer, sensor, kind: exec|exit|connect|file, ts, pid, binary, exec_id?, parent_exec_id?,
args_commitment?, salt_id?, status?, signal?, host?, port?, path?, tool_call_id?, attribution}` (`source: signer`,
one per event) in the run it is attributed to. `args_commitment` commits to `"sha256:" + hex(SHA-256(UTF-8 bytes of
the arguments string as the sensor reported it))` (§2). `tool_call_id` is the id the process's environment carried, the agent's claim, recorded as it
came: the signer never takes it as explaining the effect (`tracekit analyze --v2`'s TK-X206 checks it). An event no
open run of its callers holds is an `effect_outside_run` gap, as for the egress observer. A loss the import reports (`lost`) is an
`observer_lost` gap with `sensor` in each run it covers, or in the tenant's run `tracekit/signer` when it covers none,
and ends that coverage; so do 90 s of silence and a restart. `run.final`'s `matrix` says `processes: observed` with the sensor as
its layer when an import covered the run throughout; an import's coverage never makes `network` observed. A bundle
with these records needs `verifier_min_version` 1.4.0.

OpenShell's OCSF events (format 1.4, experimental, [OpenShell](integrations/openshell.md#openshells-ocsf-events)): the
OpenShell middleware's import is such an observer with `sensor: openshell` and its own identity as its one caller (the
signer refuses any other), so it covers only the runs it registered, attributing each event by the sandbox's run
token. Its effects are `connect` (`denied: true` when OpenShell's policy blocked it), `exec` and `exit`. A change of
the sandbox's policy or configuration is an `ext` record (§9) `{name: openshell.policy, observer, ts, change,
policy_hash?, by?, detail_commitment?, salt_id?, attribution}` (`source: signer`): `change` OpenShell's name for it
(`[a-z0-9_.-]{1,64}`), `policy_hash` and `by` OpenShell's, `detail_commitment` committing to `"sha256:" +
hex(SHA-256(UTF-8 bytes of OpenShell's message))` (§2). A loss it reports for one run is an `observer_lost` gap (with
`sensor`) in that run only, which ends no coverage. Its coverage never makes `processes` observed: OpenShell reports the processes
it starts, not each one. A configured gateway may observe the runs it registered for its clients (it is not their
agent).

Non-critical fields and records (format 1.4): any record may carry `ext`, an object of names to strict JSON values,
and a record of type `ext` holds `data: {name, ...}` with any other fields. They are signed, chained and included like
every record; a verifier that doesn't interpret a name says so and still verifies the bundle (§9).

`ext.amended` (format 1.4, [gateway](gateway.md#readable-reasoning)): on an LLM gateway's `model.exchange` request
record, the JSON pointers ([RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)) of the fields the gateway changed in
the client's request before sending it, to have the provider show the reasoning the request has the model do:
`["/thinking/display"]` (Anthropic Messages, set to `summarized`) or `["/reasoning/summary"]` (OpenAI Responses, set to
`auto`). The record's `content_digest` (and its vault body) is of the request as sent. The signer writes it only for a
gateway (`model_event` with `caller`), on a request record.

## 4. Records and the signature message

A record is one line of JSON:

```text
{"v": 2, "event": <event>, "hash": "sha256:<hex>", "alg": "ed25519", "kid": "sha256:<hex>", "sig": "<base64>"}
```

- exactly these six keys; `v` is the integer 2;
- `hash` = `"sha256:" + hex(SHA-256(JCS(event)))`;
- `kid` = `"sha256:" + hex(SHA-256(DER SubjectPublicKeyInfo))`, so it binds the key's algorithm too;
- `sig` = standard base64 of the signature over the **signature message**.

The signature message is JCS of an object holding the record's position fields, its `alg`, `kid` and `hash`, and the
domain tag `"t"`:

```text
JCS({alg, kid, log_id, seq, prev_hash, tenant, run_id, run_seq, run_prev_hash, hash, "t": "tracekit.record.v2"})
```

Each signature purpose has its own tag, so a signature made for one purpose never verifies as another. Only `record`
is used today; the others are reserved:

```text
{"t":"tracekit.record.v2"}
{"t":"tracekit.checkpoint.v2"}
{"t":"tracekit.approval.v2"}
{"t":"tracekit.cert.v2"}
{"t":"tracekit.retire.v2"}
{"t":"tracekit.export.v2"}
{"t":"pcm.message.v0"}
{"t":"pcm.grant.v0"}
```

`pcm` and `pcm-grant` are PCM 0.1 (proof-carrying messages) messages and grants, experimental, signed by the log key.
Their tags are PCM's own, not `tracekit.*`, because PCM is an open protocol that other implementations sign too.

Worked example: the first record of `tests/vectors/sig_v2.jsonl` (`record-signer-epoch`) has the signature message

```text
{"alg":"ed25519","hash":"sha256:db5045e1f08ce84b3f4af68706546c4db460adbef48568a7206ba5cc73f73dc6","kid":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9","log_id":"0123456789abcdef0123456789abcdef","prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","run_id":"run-1","run_prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","run_seq":0,"seq":0,"t":"tracekit.record.v2","tenant":"acme"}
```

**Algorithms.** `alg` must be in the verifier's pinned allow-list (`algs` in the trust config) **and** be the key's own
algorithm (`ed25519` for an Ed25519 SPKI); a mismatch is algorithm confusion and fails. Ed25519 is verified under strict
rules, identical on every backend: `S < L`, a canonically encoded public key that is not of small order, and the
cofactorless equation `[S]B = R + [k]A` (`crypto.verify_v2`; vectors `ed25519-*` in `sig_v2.jsonl`).

**Key epochs and positional retirement.** Record keys are declared by `signer.epoch` records in the log itself. A key
is valid from the seq of the `signer.epoch` that declares it up to `last_seq` of a later `key.retire{kid, last_seq}`
for it, inclusive; with no retirement, from then on. A record is valid only under a key valid at its own `seq`. A record
signed by a retired key after its `last_seq` fails, and the report names the retired key. The signer writes one
`signer.epoch` as the log's first record; with a record-key issuer, a `signer.epoch` and the previous key's
`key.retire` (`last_seq`: the record before the epoch) at every start and before the certificate expires
([issuer.md](issuer.md)).

## 5. Trees and tiles

Each log is an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) / RFC 9162 Merkle tree (`tracekit/merkle`):

```text
leaf hash  = SHA-256(0x00 ‖ data)
node hash  = SHA-256(0x01 ‖ left ‖ right)
empty tree = SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The **record tree**'s leaf `seq` has as data the 32 raw bytes of record `seq`'s `hash`. For `record-signer-epoch`:

```text
leaf hash = SHA-256(0x00 ‖ db5045e1…3dc6) = 252e000747132185f241d03274ef087f1eccb5d708dc18b49c9d990f21059060
```

Inclusion and consistency proofs are verified as in RFC 9162 §2.1.3.2 and §2.1.4.2.

The signer stores tree hashes as tiles, in the [tlog-tiles](https://c2sp.org/tlog-tiles) layout: tile (level L,
index N, width w ≤ 256) holds w consecutive hashes at tree height 8·L, starting at hash 256·N, as concatenated
32-byte hashes, at `<level>/<index>.<width>` (`merkle/tiles.py`). Full tiles never change. Tiles are storage, not
evidence: a bundle carries proofs, not tiles.

## 6. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) in the
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint) format, cosigned per
[tlog-cosignature](https://c2sp.org/tlog-cosignature) (all v1.1.0; `format/checkpoint.py`):

```text
<origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key id ‖ signature)>\n...
```

- The **log key** (`keys/log.key`, Ed25519, stable, signs notes only) is named after the origin (default
  `tracekit.local/<log_id>`). Its line is type 0x01: Ed25519 over the note text (everything up to and including the
  newline after the root).
- A **witness** cosigns with type 0x04: `8-byte big-endian timestamp ‖ Ed25519("cosignature/v1\ntime <t>\n" + text)`.
- **Key id** = first 4 bytes of `SHA-256(name ‖ 0x0A ‖ type ‖ public key)`. Keys are pinned as **vkeys**:
  `<name>+<hex key id>+<base64(type ‖ public key)>`.
- A verifier ignores signature lines of keys it does not pin (unknown types too) and rejects the note when a pinned
  key's signature fails, when one key signs twice, or when no pinned log key named after the origin signed it.
  Limits: 1 MiB note, 64 signature lines, canonical base64, tree size without leading zeros.

Worked example (`tests/vectors/c2sp_checkpoint.json`): note text

```text
tracekit.example.org/log/0190f3a0-test
13
Mi7CJiZLruMIePTlzHPx4mYt0B1o8dZ+0VjPECnCnOY=
```

signed by `tracekit.example.org/log/0190f3a0-test+070965d6+AZsfhHkc/HZjBFhU04netcqVRJ2HXydqg4QLBgqznPxx` (key id
`070965d6`) and cosigned by `witness.example.org/w1+257cc7f1+BGG3op9v3HIXXDPBmFc/0CioJHhGCXc+pyvvFPlBZdYO`.

The signer signs a record-tree note after each `run.final`, on `checkpoint_nudge`, every 10 s while the tree grows and
on close, then one note per tenant registry that grew. How witnesses are run and pinned: [witnesses](witnesses.md).

### Hybrid checkpoint signature

With `log_key: {slh_dsa: {file: keys/log-slh.key}}` in signer.yaml, every stored note (record tree and registries)
carries a second log line after the Ed25519 one, from a stateless hash-based key: SLH-DSA-SHA2-128s
([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)), pure mode, empty context, over the same note text
(`format/slh_dsa.py`, pure Python, no native dependency). Records stay Ed25519; a record is covered long-term through
the tree root the SLH-DSA line signs.

- The line has type **0xff** and the same key name as the log line. Its "public key" is
  `"tracekit/slh-dsa-sha2-128s" ‖ PK.seed ‖ PK.root` (26 + 32 bytes), so the key id is
  `SHA-256(origin ‖ 0x0A ‖ 0xff ‖ "tracekit/slh-dsa-sha2-128s" ‖ pub)[:4]` and the vkey
  `<origin>+<hex key id>+<base64(0xff ‖ "tracekit/slh-dsa-sha2-128s" ‖ pub)>`. The signature is 7856 bytes (a line of
  about 10.5 KB).
- **Never sent to witnesses** (litewitness caps requests at 10 KiB, omniwitness at 16 KiB) or to Rekor: they get the
  note text and the Ed25519 line only. It is in the stored note and in bundles.
- A verifier that does not pin the hybrid key ignores the line, so old verifiers read new notes. One that pins it
  (`tracekit signer trust` pins both keys, `tracekit signer vkey` prints both) requires **both** a valid Ed25519 line and
  a valid SLH-DSA line from the origin's pinned keys; a note without the line, or with either line bad, fails
  `checkpoint`. Notes signed before the key was configured have no line and fail against a trust config that pins it.
- Cost: signing takes about 1 s of CPU per note (pure Python; about 0.8 s on an Apple M-series core), once per tree that
  grew, at most once per second per tree; verifying takes about 1 ms. The signer signs notes off the writer thread.

Worked example (`tests/vectors/slh_dsa_note.json`): the note text above, signed by the Ed25519 key above and by
`tracekit.example.org/log/0190f3a0-test+b412f80c+/3RyYWNla2l0L3NsaC1kc2Etc2hhMi0xMjhzP2n4dHiz4830nh9Ilj+5EtFbGqwUwJGvStS72PP3Q7g=` (key id `b412f80c`).

## 7. Registry logs and run-sets

Each tenant has a **registry log**, a second tree whose leaves are fixed-width (89 bytes, `format/registry.py`):

```text
type u8 ‖ H(tenant_salt ‖ run_id) 32B ‖ record log_id 16B ‖ seq u64 big-endian ‖ record hash 32B
```

| type | record |
|---|---|
| 1 | `run.registered` |
| 2 | `run.final` |
| 3 | `log.closed` |
| 4 | `key.retire` |
| 5 | `capture.gap` (tenant-level only) |
| 6 | `trace.tamper` (tenant-level only) |

`run.registered` and `run.final` get a leaf in their run's tenant's registry; `log.closed`, `key.retire` and
tenant-level gaps get one in every tenant's registry. `tenant_salt = HMAC-SHA256(registry salt, tenant)`, `H` is
SHA-256. The registry's checkpoint origin is `<record log origin>/registry/<first 32 hex of SHA-256("registry " ‖
tenant_salt)>`, signed by the same log key, so the origin never carries the tenant's name. Worked example (registry
salt = 32 zero bytes, tenant `acme`, log origin `tracekit.example.org/log/1`):

```text
tenant_salt        c9a7e476bacbbf87e60c30ba2612595b5a1a0bd1dcb1ba8dbd37c30be1fec8a8
H(salt ‖ "run-1")  34bc0067fd0081b5c0324ba1e799cd769f8542cd42b0b2c699751ce63fb9d00f
registry origin    tracekit.example.org/log/1/registry/62d28187e34b4d26bb63c6d6f490e8b3
```

A **run-set** is the range of registry leaves `a..b−1` between two registry checkpoints. It proves which runs of the
tenant were registered and finalised in that window: a run deleted, a second `run.final`, or a withheld `key.retire`
shows as a missing or extra leaf. A bundle with a run-set carries the tenant salt, so its holder can test guessed run
ids against this tenant's leaves; other tenants' leaves stay opaque. In `registry/run-set.json` (§9), `from` and `to`
are integer tokens: a number with a fraction or exponent (`4.0`, `4e0`), or any other type, makes the run-set
INCOMPLETE.

## 8. Anchors

With `anchors.rekor` configured, the signer anchors record-tree notes in Rekor v2 at most once an hour: a
`hashedrekord` v0.0.2 entry over the note text and the log's signature line, signed with a P-256 publishing key
(`keys/rekor.key`), plus an RFC 3161 timestamp of the same bytes, which gives the anchor its time. The verifier checks
it offline against a pinned Sigstore `trusted_root` and publishing key (`tracekit.anchor.rekor2`). Setup:
[witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps).

## 9. Bundle layout

A bundle is a zip. The manifest is an index and is never trusted: every file it lists must hash as listed, and the
bundle may hold nothing else.

```text
manifest.json             {"format": "tracekit.bundle.v2", "verifier_min_version": "1.2.0", "verifier_version": "1.2.0",
                           "files": {name: sha256 hex}}
runs/<id>.jsonl           one run's records in run_seq order; id = first 32 hex of SHA-256("<tenant>/<run_id>")
runs/<id>.part-0001.jsonl from 1.4.0, a run whose records pass the 64 MiB a file limit: its records in parts
runs/<id>.part-0002.jsonl numbered from 0001 with four digits, each split at a record and at most 64 MiB (below)
keys/records.jsonl        every signer.epoch and key.retire record the checkpoint covers
proofs/records.json       {"checkpoint": "checkpoints/<size>.note", "tree_size": n,
                           "inclusion": {"<seq>": [base64 hash, ...]}}: inclusion of each run's first and last record,
                           every key record, and every record a registry leaf points to
checkpoints/<size>.note   the record-tree note the proofs are against
rekor/<size>.json         its Rekor v2 TransparencyLogEntry, when anchored
tsa/<size>.tsr            its RFC 3161 timestamp response, when anchored
policies/<sha256>.json    the compiled policies a verifier checks the records against, named by the SHA-256 of
                          their bytes (their policy_hash)
```

A run-set bundle adds:

```text
registry/run-set.json     {"tenant_salt": base64, "from": a, "to": b (integer tokens), "consistency": [base64 hash, ...],
                           "leaves": [{"leaf": base64, "inclusion": [base64 hash, ...]}, ...]}
registry/records.jsonl    the record each leaf points to, in leaf order
checkpoints/registry-<n>.note   the registry notes at a (none when a = 0) and b
runs/                     every run whose run.final is in the range, and the selected run, if any
```

JSON lines files end in a newline, one strict JSON text (§1) per line, each line at most 1 MiB and at least 256 bytes (no signed record is shorter: its hash, signature, ids and timestamp alone are longer), so a bundle's lines are counted and measured before any is parsed and can't outnumber 512 MiB / 256. Hashes and keys in
bundle files are standard base64 with padding (checkpoint notes and vkeys: canonical base64, §6). Zip limits: at most
10,000 entries, 64 MiB per entry, 512 MiB in total; entry names match `[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*`
with no `.` or `..` segment; no symlinks; no duplicate names. A bundle carries no code and no trust configuration.

A bundle has one zip layout, so every reader sees the same entries; anything else is `UNUSABLE BUNDLE`:

- the entries, in central-directory order, start at offset 0 and follow each other with no gap or overlap: each is a
  local header, its name and its data, and the next starts where that data ends;
- the central directory starts where the last entry ends and ends where the end-of-central-directory record starts
  (offset + size = the record's offset), and the record is the file's last 22 bytes: no archive comment, no bytes
  before the first entry or after the record;
- the record is for disk 0 only, and both of its entry counts equal the number of central directory entries;
- no zip64 record or locator, and no extra or comment field in any header;
- each local header repeats its central entry: name, general-purpose flags, method, CRC-32 and both sizes;
- general-purpose flags 0 (so no encryption and no data descriptor); method 0 (stored, with equal sizes) or 8 (deflate);
- each entry's data is exactly its stated size and matches its CRC-32.

`tracekit.bundle_v2` writes this layout (Python's `zipfile` writing a seekable file), and refuses a bundle past the
zip limits above, which no verifier would read.

**A run in parts** (from 1.4.0). A run whose records fit 64 MiB is one file, `runs/<id>.jsonl`, as before. A longer
one is written as `runs/<id>.part-0001.jsonl`, `runs/<id>.part-0002.jsonl`, ...: the run's file cut between records,
each part as full as the limit allows, so its parts, read in order, are that file, and a verifier checks them as it
(chain, signatures, inclusion of the run's first and last records). The proofs carry no inclusion of a part's own
first or last record. A run cut back, at a part boundary or anywhere, reads open (`VERIFIED TO HEAD n`), never
`VERIFIED`: the proofs file isn't signed, and from a run's records an inclusion proof of the record now last can often
be computed, so only the run's `run.final` or a run-set proves a run complete. A run can then hold up to the bundle's
512 MiB (about 190,000 tool calls of the server pack). Anything else about the parts fails the `run parts` line
([verdicts](verdicts.md)): a part missing between part-0001 and the last (a gap in the numbers), a name outside that
numbering (`part-0000`, `part-02`, five digits), a part with no records, a part whose first record's `run_prev_hash`
is not the hash of the last record of the part before it (parts out of order, an extra or repeated part), or the run
both in one file and in parts. Its last part missing leaves the run open, and fails `inclusion` while the proofs
include no proof of the record now last. A part over 64 MiB is, as any file, `UNUSABLE BUNDLE`. A bundle with a run in
parts declares `run parts` (below), so a 1.3 or older verifier, which would read each part as a run of its own,
reports it `UNVERIFIABLE (needs tracekit >= 1.4.0)`.

`verifier_min_version` is the newest version in the version table (`VERSIONS` in `tracekit/bundle_v2.py`) whose
critical entries a bundled record uses, else `1.0.0`, and at least 1.4.0 when a record has an `ext` field or is of type
`ext`. `verifier_version` (from 1.4.0; advisory, like the whole manifest) is the newest version whose entries, ext names
among them, the records use: the version that checks everything in the bundle. `tracekit export --v2` prints both, and
which records raised `verifier_min_version` (`raised_by`). A row is frozen once its version's first release candidate
ships (`test_shipped_rows_are_frozen`): an addition after that goes in a new row. Each version lists what it added:
record types, data fields per record type, and enum values per (record type, field), gap and tamper `kind`s among
them, all critical; from 1.4.0 the bundle layouts it reads, critical too (`layout`; `raised_by` names them); and from
1.4.0 the ext names it interprets, which are not:

| Version | Record types | Data fields | Enum values | Ext names (non-critical) |
|---|---|---|---|---|
| 1.1.0 | `input.observed`, `content.accessed`, `content.erased`, `why.finding` | `policy.decision`: `provenance`, `provenance_state`; `run.registered`: `replay_of` | — | — |
| 1.2.0 | `run.child`, `approval.escalated`, `approval.revoked`, `approval.suggested`, `approval.agents`, `incident.opened`, `incident.updated`, `incident.capped`, `run.held`, `run.resumed`, `run.quarantined`, `incident.resolved`, `incident.response`, `identity.suspension`, `effect.observed` | `run.registered`: `parent_run`, `session`, `posture`; `capture.gap`: `run_id`; `run.final`: `provider_executed`, `paired_by_args`, `matrix`; `policy.decision`: `via`, `caller`, `detect`, `incident_id`; `approval.request`: `agent`, `via`, `incident_id`, `passkey`; `tool.result`, `input.observed`: `via`; `approval`: `approver_kind`, `asserted`, `spent`, `not_before`, `consume_by`, `incident_id`; `approval.expired`: `reason`; `reconcile.unexplained_effect`: `observer`, `kind`, `host`, `port` | `capture.gap` `kind`: `decided_not_completed`, `late_activity`, `concurrent_run`, `tailer_redelegated`, `reask_after_reject`, `held_call_unresolved`, `observer_lost`, `effect_outside_run`; `run.closing` `reason`: `quarantine` | — |
| 1.3.0 | `reconcile.result_mismatch` | — | `capture.gap` `kind`: `result_unchecked` | — |
| 1.4.0 | `constraint.added` | `effect.observed`: `sensor`, `denied`; `review`: `cites`; `model.exchange`: `said_only`; `capture.gap`: `sensor` | `capture.gap` `kind`: `constraint_refused` | `amended`, `openshell.policy`; and the slot itself (`ext` fields, `ext` records: critical) |

Layouts (critical): 1.4.0 adds `run parts`, a run in parts (above).

Every v2 definition but `review`'s data and its `verdict`, `error`'s data, `run.start`'s `agent` and `trace.tamper`'s
`before` and `after` (open since format 1.0) and the `ext` record's (open by design) is closed (`additionalProperties:
false`), so an older verifier would fail a record that uses a newer critical entry; the version the manifest declares
makes it report `UNVERIFIABLE (needs tracekit >= x)` instead, never FAILED, and from 1.4.0 the `bundle readable` line
lists the commands that verify the bundle (§11 step 2). The open definitions are why the manifest's version matters
for `review.cites`: a 1.3 verifier given a signed finding under a manifest edited down to 1.3.0 passes its record's
schema and checks neither its citations nor its author, and prints no `Findings:` line. What it prints stays true, the
records being signed and included as any; the findings are left out, unchecked, so verify a bundle with signed
findings with 1.4.0 or later.

**Criticality.** From 1.4.0, an addition an older verifier can leave unread goes in the non-critical slot rather than
a new critical row, so a verifier from 1.4.0 on keeps verifying later bundles:

- `ext` on any record: `{name: value}`, each name `[a-z][a-z0-9_.-]*` and at most 64 characters, each value any strict
  JSON (§1) within the 1 MiB line limit; and the record type `ext`, `data: {name, ...}` with any other fields.
- The signer decides what is critical by where it writes it: a closed field is critical, `ext` is not. That choice is
  inside the signed record; the manifest, never trusted, only names versions.
- A verifier from 1.4.0 checks every record's schema, signature, chain and inclusion whatever its `ext` holds, so an
  ext value edited, added or removed fails `signatures`, and an `ext` record dropped fails `run chain`. It interprets
  the ext names its own rows list, each on lines of its own; every other name gets a `not interpreted` warning
  (`n record(s) carry ext.<name>: ...`, and `; tracekit >= <verifier_version> checks it` when the manifest's
  `verifier_version` is newer than the verifier; the first 20 names in code-point
  order, and one more line, `n more ext name(s), ...`, for the rest), exit 0 (3 with `--strict`), and the integrity
  stays `VERIFIED`: every check that verifier implements passed.
- **The rule.** A name may go in `ext` only if every line an older verifier prints stays true without its
  interpretation: with it off, the report is the full report minus that name's own lines, plus its `not interpreted`
  line (`test_an_ext_interpretation_adds_only_its_own_lines` checks each name a row lists).
- `amended` is non-critical: without it every line stays true (a request record's commitment is to the request as
  sent either way); a verifier that reads it adds a `gateway amendments` line.
- `openshell.policy` is non-critical: it is OpenShell's report of its own configuration, beside every record a
  verifier reads; without it every line stays true, and a verifier that reads it adds an `openshell policy` line.
- `review.cites` and `effect.observed.sensor` stay critical: a verifier that passed over a signed finding's citations
  would label it `imported`, a false line; and a sensor's effects are records of what the agent's own processes did,
  in its run, which a verifier must read to verify that run. So does `capture.gap.sensor`: a 1.3 verifier counts every
  `observer_lost` as an egress observer gone silent, a false line for a sensor's reported loss, so it reports such a
  bundle `UNVERIFIABLE (needs tracekit >= 1.4.0)`. So does `effect.observed.denied`: read without it, a connection
  OpenShell blocked would read as made.

`tests/test_released_verifiers.py` runs each released Python verifier (from its git tag) on bundles of today's signer:
those that declare its version or lower verify there with the same lines as here, the others are `UNVERIFIABLE`.

## 10. The trust config

The verifier pins its own trust, never the bundle's (`verify.v2.load_trust`):

```json
{"logs": ["<log vkey>", "<hybrid SLH-DSA log vkey, optional>"],
 "witnesses": [{"vkey": "<cosignature vkey>", "class": "public|customer|tracekit|operator"}],
 "algs": ["ed25519"],
 "witnesses_required": 0,
 "rekor": {"trusted_root": {}, "publishing_key": "<base64 SPKI>", "class": "public"},
 "monitors": [{"vkey": "<monitor vkey>", "class": "public|customer|tracekit|operator", "max_age_s": 3600}],
 "issuers": [{"vkey": "<issuer vkey>", "issuance_log_vkey": "<issuance log vkey>"}],
 "analyzers": ["<scheme:subject>"]}
```

`logs` and `algs` are required and non-empty; `witnesses`, `witnesses_required` (default 0, an integer token),
`rekor`, `monitors` ([monitor](monitor.md) reports the verifier is given), `issuers` (record-key issuers,
[issuer.md](issuer.md)) and `analyzers` (the identities, `scheme:subject` as `run.registered` records them, whose
signed findings you take as independent: your operator's `tracekit analyze --v2`, never the agent's) are optional. No
other key is allowed. `tracekit signer trust -o trust.json` writes one for a signer; an auditor should build theirs
from independent sources ([auditor guide](auditor-guide.md)).

## 11. Verification algorithm

`tracekit verify bundle.tkb --trust trust.json` (`verify.v2.verify`). Each step adds report lines; the meaning of each
line and verdict is in [verdicts](verdicts.md).

1. **Trust config.** Parse strictly; check the keys and types of §10; parse every vkey. Failure: exit 2.
2. **Read the zip** under the limits of §9. Parse `manifest.json`; `format` must be `tracekit.bundle.v2` and
   `verifier_min_version` a version number (one to three dot-separated runs of ASCII digits) not above the version of
   the format the verifier implements, else `UNVERIFIABLE (needs tracekit >= x)`, exit 2, the `bundle readable` line
   listing commands that verify it with the user's paths: `uvx --from "tracekit-ai>=x" tracekit verify <bundle>
   --trust <trust>`, `npx -y @cygnuxlabs/tracekit@latest verify <bundle> --trust <trust>` (the TypeScript verifier
   lists it first) and the browser page (§13). `verifier_version` is advisory: it only names the version on `not
   interpreted` lines (step 10). Failure: `UNUSABLE BUNDLE`, exit 2.
3. **Manifest.** The listed files and hashes must equal the files present, exactly (`manifest`).
4. **Checkpoint.** Open the note named by `proofs/records.json` (§6) with the pinned log keys (both lines when a hybrid
   key is pinned) and witness keys; its tree size must equal `tree_size` (`checkpoint`). Count the pinned cosignatures
   against `witnesses_required` (`witness quorum`). If the trust config pins `rekor` and the bundle has `rekor/<size>.json`, verify the anchor
   (`rekor anchor`).
5. **Keys.** Walk `keys/records.jsonl` in increasing seq: each must be a `signer.epoch` or `key.retire` record included
   in the checkpointed tree; each declared key's `kid` and `alg` must match its SPKI; each record must verify (§4)
   under the keys valid at its seq; a `key.retire` must name a declared key and sets its `last_seq`. All records must
   share the first key record's `log_id`. A key with `cert` is declared only if its certificate verifies under a
   pinned issuer, for that key and `log_id`, in the issuer's cosigned issuance log ([issuer.md](issuer.md)).
6. **Runs.** A bundle holds exactly one run, one run with its findings and replay runs (`--with-findings`), or any
   number with a run-set; a run is its `runs/<id>.jsonl` file or its parts read in order (§9), whose layout the `run
   parts` line checks when there are parts, and no two runs share a tenant and run_id (`run chain` fails otherwise:
   a run's records under a second name would count twice). For each run, every record must: verify under the keys
   valid at its seq (§4); be a schema-valid `tracekit.event.v2` event of this `log_id`; have `run_seq` = its index,
   `run_prev_hash` = the previous record's `hash` (zeros first), the first record's tenant and run_id, a seq above the
   previous record's; and follow no `run.final`. The run's first and last records must be included in the
   checkpointed tree.
7. **Run-set** (with `registry/run-set.json`). Open the registry notes at `a` and `b` with the pinned log key renamed
   to the registry origin of §7 and the pinned witnesses; each needs `witnesses_required` cosignatures, and caps the
   assurance level by the same rule as the checkpoint; check consistency `a → b`; require `b > 0` and exactly `b − a`
   leaves, each included in the registry tree at `b`, each pointing to a record in `registry/records.jsonl` with that hash, seq, type,
   log_id and run hash, included in the record tree. One `run.final` per run; every run final in the range present in
   the bundle from its `run.registered` (when in the range) to that `run.final`; every bundled run but one the target
   of a leaf; every bundled run of the tenant the range's run leaves name (the run-set line names it). Every
   `key.retire` leaf in the range must be among the key records. A `log.closed` in the range must be
   the checkpoint's last record, or later records were added after the log closed.
8. **Format bridge** (with `--v1-ledger`/`--v1-key`, §12).
   **Signed findings** (with `review` records): a `review` with `cites` must be in a findings run, and its verdict
   must have a signed finding's shape: a kind, a `TK-` rule and a severity, and each closed field above of the values
   it allows (other fields pass), whether or not the run it analyses is in the bundle; when that run is, each cite must
   be a record of it with that `run_seq` and `hash` (`reviews` fails otherwise); each finding is labelled by its
   author, the findings run's `run.registered` `identity`:
   `self-asserted` (a warning) when that is the analysed run's identity or either run's `signer_isolation` is
   `same-user`; else `independent` when the trust config's `analyzers` lists it, else `unpinned author <id>`. Without
   the analysed run, the findings are `author not checked` and their cites not counted (`reviews counted`, a warning).
   A `review` without `cites` is `imported`. The signed findings themselves are summed up on a `Findings:` line after
   `Integrity` and `Assurance`, never in them: by severity, the coverage reviews, and every review's label (an
   imported review's severity is not counted).
   **Live constraints**: each `policy.decision` whose `rule_ids` hold `TK-CONSTRAINT` is an `ask` after a
   `constraint.added` in its run, else `constraints` fails.
9. **Policy snapshots.** Each `policies/` file is named by its own SHA-256 (else `policy snapshot` fails and neither
   check below reads it). `tracekit export --v2` bundles, from the signer's `<data_dir>/policies`, the compiled policy
   (canonical JSON, so its SHA-256 is its `policy_hash`) of each `policy_hash` a verifier checks against, once: the
   one the `policy.decision` an agent's approval answered cites (`approvals by agents` checks its rules permit agents;
   without it, a warning) and the one policy a run with an `incident.opened` was decided under. No other is bundled.
   **Incidents** (with containment records): a record an incident cites must, when its run is in the bundle, exist
   and be one that fires a trigger; an incident of scope `run` citing only its own run is recomputed from that run's
   records under the bundled policy of the run's one `policy_hash` (not in the bundle: signer-asserted, with an
   `incident policies` warning), and must follow from them;
   a `detector_unavailable` incident must cite a decision whose `detect.state` is `unavailable`; the rest are counted
   signer-asserted. Each response must have been honoured: while held, no allow and no ask without the incident id;
   while quarantined, only deny; a held call approved only by a person (never `approver_kind: agent`, never
   self-approved) with the incident id; no consume under a hold but of such an approval, none under a quarantine; no
   `tool.result` while held or quarantined but of a call `in_flight` then or (held) consumed with such an approval
   (`incidents`).
10. **Ext** (records with an `ext` field or of type `ext`, §9). Each ext name the key and run records carry, in
    name order: the verifier's own check of it when it interprets it, else a `not interpreted` warning counting the
    records that carry it, for the first 20 such names; one more `not interpreted` warning counts the others. `amended` (1.4.0): `gateway amendments`, passing with `gateway amended n request(s) to show
    reasoning (<pointer>: <count>, ... the first 8 in code-point order); each record commits to the request as sent`,
    a warning listing the records (the first 20) where it is anything but a non-empty list of JSON pointers of at most
    256 characters on a `model.exchange` request record of source `gateway`. `openshell.policy` (1.4.0): `openshell
    policy`, passing with `OpenShell changed the sandbox policy or configuration n time(s) (<change>: <count>, ... the
    first 8 in code-point order), as OpenShell reported it`, a warning listing the records (the first 20) that carry it
    other than as an `ext` record of source `signer` with a `change` of `[a-z0-9_.-]{1,64}` and a non-empty
    `observer`.
11. **Verdict.** Any failed line: `FAILED`, exit 1. Otherwise `VERIFIED` (every check this verifier implements
    passed), `VERIFIED TO HEAD n (open)` for one open
    run, or `VERIFIED (k run(s) open)`. Then the informational lines (policy, gaps, coverage, tiers, args source,
    isolation, fail-open classes, key assurance, break-glass approvals) and the assurance level. Exit 0, or 3 with
    `--strict` when any line is a warning ([verdicts](verdicts.md#signed-gaps) lists the gap kinds that warn).

A malformed bundle never crashes the verifier: anything unexpected is a failed `bundle structure` line.

## 12. v1 → v2 bridge

`tracekit signer bridge` continues a v1 ledger in a v2 log without rewriting either (`signer/format_bridge.py`):

1. The v1 ledger gets two last records, signed with the v1 key: `capture.gap{kind: format_upgrade}`, then the key's
   retirement as a v1-valid `capture.gap{kind: key_retire, reason: "key.retire kid=<v1 kid> last_seq=<its seq>"}`.
2. The v2 log's first record is `signer.epoch{bridge: {v1_kid, v1_last_seq, v1_head}}`, where `v1_head` is the hash
   of step 1's last record.
3. The v1 signing key is overwritten and deleted.

`tracekit verify bundle.tkb --trust trust.json --v1-ledger ledger.jsonl --v1-key signer.pub` then checks that the v1
chain verifies by v1 rules up to `v1_last_seq`, that its last record is the retirement of `v1_kid` with hash `v1_head`,
and that no v1 record follows it. The frozen v1 verifier sees the two bridge records as ordinary signer gaps and can't
tell a later v1 record from a genuine one; only this check reports it.

## 13. Implementations

| Implementation | Where | Notes |
|---|---|---|
| Python, the reference | `tracekit/verify/v2.py` (`tracekit verify`) | everything on this page |
| TypeScript, independent | `sdk/typescript/src/verify` (`@cygnuxlabs/tracekit/verify`, `npx @cygnuxlabs/tracekit verify`) | written from this page; Node ≥ 20.12 and browsers, Web Crypto only |
| TypeScript, in a browser | `verify.html` (`make verify-page`; a release asset, in the npm package as `dist/verify.html`, hosted at https://cygnux-labs.github.io/Tracekit/verify/) | the TypeScript verifier in one self-contained page: file inputs for the bundle and the trust config, and a Content Security Policy (`default-src 'none'`, its one script and style by hash, `connect-src 'none'`) that lets it load and send nothing |

The TypeScript verifier does not implement SLH-DSA (§6, Web Crypto has none), Rekor anchors (§8) or record-key
certificates ([issuer.md](issuer.md)), nor `tracekit why` findings (a bundle with a `why.finding` or a replay run): a
bundle that relies on one is `UNVERIFIABLE (not checked by this verifier: ...)`, exit 2, never `VERIFIED`. It checks
signed findings (`reviews`, and the `Findings:` line) and live constraints (`constraints`) as the reference does. It
takes no monitor reports, revocations or v1 ledger. Both verifiers implement the non-critical slot and the upgrade
lines alike (§9, §11); the browser page reports exactly what the TypeScript CLI does. For evidence, check the page you
open against the release first: `gh attestation verify verify.html --repo Cygnux-Labs/Tracekit`
([releasing](RELEASING.md#verifying-a-release)).

**Agreement.** `tests/test_ts_verifier.py` builds bundles with the real signer (honest runs: dev, witnessed, with a
gap, with an approval, a run-set; and mutated copies: edited, dropped and reordered records, swapped signatures, a
foreign key, a missing cosignature, a quorum not met, a forged inclusion proof, a bad manifest hash, a newer
`verifier_min_version`, a schema-invalid field) and takes the golden corpus (`tests/golden/v2`, `tests/golden/negative`),
runs both verifiers on each and requires the same integrity, assurance, exit code and check lines:

```sh
make test-ts                                     # builds the TypeScript verifier; its suite runs the agreement tests too
python -m pytest tests/test_ts_verifier.py       # skipped without Node >= 20.12
```

**A third implementation** shows conformance the same way: reproduce every vector in `tests/vectors` (canonical JSON,
record hashes and signature messages, the Ed25519 acceptance rules, checkpoint notes and key ids) and the worked examples
on this page, then reach the reference's integrity, assurance and exit code on the differential corpus: the golden
bundles with their `trust.json`, and the bundles `tests/test_ts_verifier.py` builds.
