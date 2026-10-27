"""The v2 signer service: `SignerService` implements `SignerAPI` over the record log's single writer (pipeline.py).

    tracekit signer serve --config signer.yaml [--close-on-stop FILE]   # FILE there at SIGTERM: close the log first
    tracekit signer serve --dev               # the same-user dev signer clients auto-spawn (decision S3)
    tracekit signer fsck  --config signer.yaml
    tracekit signer migrate --config signer.yaml     # create the Postgres store's tables (as the migration role)
    tracekit signer close-log --config signer.yaml   # shut the log down for good (log.closed), signer stopped
    tracekit signer vkey  [--dev | --config signer.yaml]               # the log's verifier key
    tracekit signer trust [--dev | --config signer.yaml] -o trust.json  # a v2 trust config pinning it and the witnesses
    tracekit signer reveal --record SEQ [--dev | --config signer.yaml]  # the salt of one record's commitments
    tracekit signer token add NAME [--ttl 30d] [--tenant T] --config signer.yaml   # prints a token once (http.tokens)
    tracekit signer token list|revoke [NAME] --config signer.yaml
    tracekit signer content get --run R --seq N [N ...] --purpose P [--config signer.yaml]   # retained content (vault)
    tracekit signer content erase --run R [--reason TEXT] [--config signer.yaml]
    tracekit signer incidents list|show|resolve|hold|quarantine|resume|pause|unpause|suspend|unsuspend [ID]
                               [--signer URL ...] [--reason TEXT]   # containment's operator calls (docs/incidents.md)

signer.yaml:
    data_dir: /var/lib/tracekit-signer      # keys/ and store/; relative paths are from the config file
    socket: /run/tracekit/signer.sock        # Unix socket transport (peer uid, per frame on Linux)
    socket_mode: "0666"                      # chmod the socket after bind (default: as the umask leaves it)
    tcp_endpoint: /run/tracekit/endpoint.json   # loopback TCP dev transport (token, mutual HMAC)
    http: {listen: 0.0.0.0:8443, ...}        # HTTPS with k8s_sa, mtls, oidc or token identity (tracekit/transport/http.py)
                                             # port 0: a free one, named on the start line ("serving on host:port")
    durability: ack-on-write                 # or ack-on-fsync
    log_key: {aws_kms: {key_id: alias/tracekit-log, region: eu-west-1}}   # the log key in AWS KMS
                                             # (tracekit.signer.logkey); default keys/log.key
             {slh_dsa: {file: keys/log-slh.key}}   # and/or a hybrid SLH-DSA-SHA2-128s line on every stored note
                                             # (created on first start; tracekit.format.checkpoint), never sent to
                                             # witnesses; about 1 s of signing per note
    record_key: {issuer: {url: https://issuer.internal:8444, vkey: "...", issuance_log_vkey: "...", tenants: [acme],
                          ttl_s: 86400, cert: tls/c.pem, key: tls/c.key, ca: tls/ca.pem, token_file: ...}}
                                             # short-lived record keys certified by a record-key issuer
                                             # (tracekit.issuer, docs/issuer.md); default the file key keys/record.key
    storage: {postgres: {dsn_file: pg.dsn}}  # a Postgres store (tracekit.storage.postgres): the DSN is read from the
                                             # file, never inline (no dsn_file: the libpq PG* variables); default the
                                             # file store in data_dir/store
    tenant: default                          # tenant of callers not in `tenants`
    tenants: {"uid:1001": acme, "k8s_sa:system:serviceaccount:acme:*": acme}   # identity or prefix:* -> tenant (attested)
                                             # (identities, here and in authorize and approvals, also match as
                                             # person:<id> and group:<alias>/<name> when OIDC: tracekit.identity.oidc)
    authorize: {"mtls:spiffe://acme/agent": [register_run, decide, approval_consume, complete, close_run, model_event,
                                             approval_request, approval_wait]}   # identity or prefix:* -> methods
                                             # (docs/limits.md#deployment); uid and token:dev default to all, the
                                             # rest to none
    multi_tenant_apps: ["uid:1002"]          # may assert a tenant per run (recorded as not attested), or a
                                             # bridge's on_behalf person's tenant
    migrators: ["uid:1003"]                  # may register `migrated` runs
    analyzers: ["uid:1004"]                  # may register findings runs, each bound to the run it analyses (for
                                             # `tracekit analyze --v2` and `tracekit why` findings), and `tracekit
                                             # why` replay runs of it (replay_of); never the agent's identity
    importers: ["uid:1005"]                  # log followers (tracekit.follow): the runs they register are imported
                                             # runs (source import, tier T3, fidelity none, not reconciled), watched as
                                             # a transcript tailer's: silent for TAILER_LOST_S, a tailer_lost gap
    gateways: ["mtls:spiffe://acme/gateway"]  # LLM and MCP gateways, tool executors (tracekit.gateway, .mcp_gateway,
                                             # .executor): their calls name the client they authenticated (`caller`):
                                             # model_event, decide, complete, approval_request and observe are
                                             # recorded source gateway (tier T2, naming the gateway in `via`); a
                                             # call a gateway decided takes its later steps from it alone (_hold)
    gateway_mandatory: false                 # true: reconcile decides against gateway L3 only (tracekit.signer.reconcile)
    posture: {network: enforced, tool_calls: enforced}   # the deployment as the operator asserts it (run.registered
                                             # records it with gateway_mandatory, never attested): the agent reaches
                                             # the outside only through the egress proxy, and acts only through the
                                             # executor and the MCP gateway (the coverage matrix's enforced;
                                             # docs/egress.md#posture)
    observe_grace_s: 120                     # how long a closing run an egress observer covers waits for its last reports
    verify_tool_results: record              # an LLM gateway's digests of the tool results a request sends the model,
                                             # checked against each call's tool.result: one that differs is a signed
                                             # reconcile.result_mismatch; refuse: the gateway also doesn't forward the
                                             # request. Absent: not checked (docs/gateway.md#verified-tool-results)
    fail_modes: {default: closed, fs: open}     # tool class -> fail mode, recorded and returned by register_run
    grace_s: 5                               # reconciliation window between run.closing and run.final
    gateway_wait_s: 600                      # past grace_s, how long a closing run waits for the results of calls a
                                             # gateway holds (each one still open then: a held_call_unresolved gap)
    idle_s: 3600                             # a run without calls for this long is closed
    limits: {events_per_s: 200, burst: 400}  # tracekit.signer.quotas.Limits
    policy: /etc/tracekit/policy.yaml        # policy v2 (YAML or JSON); default tracekit/policy2/packs/dev.yaml
    origin: tracekit.example.org/log/1       # checkpoint origin, the log key's name; default tracekit.local/<log_id>
    route: tracekit-central-0                # one replica of a central signer (docs/deploy-kubernetes.md): its run and
                                             # approval ids start with `<route>.`, which clients route by; a client's
                                             # own run_id must start with it too
    metrics: {listen: 127.0.0.1:9464}        # Prometheus GET /metrics on its own port (tracekit.signer.metrics),
                                             # and GET /logs/v0: this signer's logs, for witnesses to poll, and
                                             # the logs' tiles and anchors, for monitors (SignerService.tlog);
                                             # serve_records: true adds the record entries a monitor of the record
                                             # log reads (every tenant's records: keep that port private)
    witnesses:                               # C2SP tlog-witnesses that cosign every new note (tracekit.tlog_witness);
                                             # `- public`: the public witness (tracekit.public_witness)
      - {url: https://witness.example.org, vkey: "witness.example.org/w1+1234abcd+BA...", class: customer}
    contact: ops@example.org                 # the logs list's contact line; default the origin
    anchors: {rekor: {signing_config: sigstage-signing_config.json, trusted_root: sigstage-trusted_root.json,
                      every_s: 3600}}        # Rekor v2 + RFC 3161 anchors of the record note (tracekit.anchor.rekor2)
    approvals: {self_approval: deny, approvers: ["uid:1001", "mtls:spiffe://acme/ops/*", "group:corp/approvers"],
                break_glass: ["uid:0", "group:corp/oncall"],   # may answer any approval, with a reason; recorded
                                             # break_glass
                webauthn: {rp_id: view.example, origin: "https://view.example"},   # where passkeys sign approvals
                persons: {"slack:T01/U02": alice, "mtls:spiffe://acme/ops/alice": alice}}   # identity -> person id,
                                             # so self-approval holds across channels (docs/approvals.md)
    view: {oidc: {issuer: corp, client_id: tracekit-viewer, redirect_uri: https://view.example/callback,
                  roles: {auditor: ["group:corp/auditors"], approver: ["group:corp/approvers"],
                         operator-admin: ["group:corp/sre"]}},
           signer: https://signer.internal:8443,   # `tracekit view` OIDC login and approval pages (tracekit.view)
           logs: [log-0.dsn, log-1.dsn]}           # a central viewer: each log's DSN file, a SELECT-only role
                                             # (docs/viewer.md)
    webhook: [{url: https://siem.example.org/tracekit, format: ocsf, events: [deny, approval, gap, tamper, incident],
               secret_file: webhook.secret}]  # OCSF events, HMAC-signed, off the writer (tracekit.signer.webhook);
                                             # incident records at least once, also to Slack ({format: slack})
    suspensions: /shared/suspensions.json    # the operator-managed suspension list, shared by replicas (default
                                             # data_dir/suspensions.json); read again whenever it changes
    content: {retain: false, retention_days: 30, max_record_bytes: 1048576}   # the content vault (below)
    acknowledge_rollback: false
    lock_timeout_s: 10                    # wait this long for the storage lock, then exit naming its holder's pid
    fsck_every_s: 86400                      # full-chain check in the background (0: off; the dev signer's is off)
    clock_skew_s: 300                        # a witness cosignature this far from the signer's clock: clock_skew gap
    otlp: {max_spans: 512}                   # OTLP/HTTP POST /v1/traces on the `http` listener, for identities
                                             # `authorize` grants otlp_import (tracekit.signer.otel; docs/otel.md)
    decision_keys: {vscode-agent-hooks: "<base64 Ed25519 public key>"}   # external policy systems whose record signatures
                                             # decision_import requires and verifies (others: unverified)
    otel_out: {endpoint: https://otel.example.org/v1/traces, headers: {x-api-key: "..."}}   # each final run's spans
    harness_binding:                         # runs of these identities must come from a registered harness process
      helper: /var/lib/tracekit-signer/harness-helper.sock   # tracekit.harness_helper (default: read /proc here)
      required: ["uid:1001"]                 # identity or prefix:*; other uid callers are attributed when they can be
      harnesses: {claude: /usr/local/bin/claude}   # name -> root-owned executable, or {exe, script} for an interpreter

Startup (04-design §2.6): the storage lock is taken before any socket is touched; the log is replayed, its chain
checked and its tail signatures verified; then the configured witnesses are asked for their latest cosigned checkpoint.
A witness is a `tlog_witness.TlogWitness` (or an object with its `name`, `vkey`, `add_checkpoint` and `latest`), and
`latest` raises when it is unreachable. A local log behind the witnessed one is a rollback: a signed `trace.tamper{rollback}`, then client writes are refused until it is
acknowledged. No witness reachable: a signed `degraded_unanchored` gap, and the signer runs. The store opens from its
latest snapshot (written every SNAPSHOT_RECORDS records and on close) and replays only the records after it.
Every `fsck_every_s` a background thread checks the whole store as `tracekit signer fsck` does; new problems are one
signed `trace.tamper{edited}` and refuse client writes (acknowledge_rollback does not cover them). Snapshots carry an
HMAC under keys/snapshot.key; one that fails it is ignored and the logs are replayed in full.

Tenant-level gaps (04-design §2.7): witness_failed, witness_late, clock_skew, degraded_unanchored gaps and rollback
tamper records are signer-level records with a leaf in every tenant's registry, so a run-set over the window shows them.

Run lifecycle (04-design §2.7): run.registered → events → close_run or the idle timeout (paused while an approval is
pending) → run.closing → grace window, where only late records (complete, state_write, model_event, tailer_lost) are
accepted → the run's reconcile.* records (tracekit.signer.reconcile) → run.final{head, coverage}.

Completeness (docs/limits.md): at run.final each open decision that let its call run (allowed, or its call's approval
consumed) with no `complete` is a signed `capture.gap{decided_not_completed}`, unless a later decision of the call
completed (never for the decision a consumed approval names, unless its call completed with the approved arguments);
DECIDED_GAPS_MAX per run, then one with the rest counted; a call a gateway holds gets held_call_unresolved instead. A
run bound to a harness process, registered while another run of the same owner, tenant and harness process is open in
another session (`parent`), gets a `capture.gap{concurrent_run}` naming it once both have recorded an event since: one
harness process drives one session at a time. Unbound runs (SDKs, servers) run several at once by design. A child run (`parent`) bound to a harness process
is a `run.child` record in its parent. close_run's `last_client_seq` turns the values not received by then of each
stream the closer wrote (or that never reached the signer) into a client_counter_gap naming it; values up to there
that arrive later are recorded with no new gap. A gateway's report about a final run goes in the tenant's signer run.
A run's transcript tailer (delegate_run to an identity granted `tailer_heartbeat`: system mode's tailer uid) is
watched from the delegation: TAILER_LOST_S with no call from it while the run is open is a tailer_lost gap, and a
second tailer token for the run a `capture.gap{tailer_redelegated}`. An egress observer (tracekit.egress; an identity
granted `observe_effect`, never the run's owner) is watched the same way: it covers each run of its tenant registered
while it is alive, a silence of TAILER_LOST_S or a restart (a new `instance`) is an `observer_lost` gap in each open
run it covers, and a covered run waits `observe_grace_s` after closing for its last reports (_observe_effect). Writes
refused because their run is final are counted per run (not a close_run, nor each identity's and stream's first one:
that is how a client learns its run ended) and written with the refusal summaries as a `capture.gap{late_activity}` in
the tenant's signer run, which (unlike the run's own records) gets a leaf in the tenant's registry, so a run-set shows
it.

run.registered and run.final also get a leaf in the tenant's registry log (tracekit.format.registry), log.closed and
key.retire one in every tenant's. Gap and tamper records are written by the signer only: no request can carry an event type, source,
isolation or fail mode.

Checkpoints (04-design §1.6, §2.9): a C2SP note of the record tree, signed by the log key (keys/log.key or AWS KMS,
Ed25519, named after the origin, signs notes only) and stored through the storage, after a run.final, on
`checkpoint_nudge` (at most one note per CHECKPOINT_MIN_S), every CHECKPOINT_S while the tree grows, and on close; then,
signed by the same key, a note of each tenant registry that grew, under origin `<origin>/registry/<id of the tenant's
salt>`. The log key's vkey (then the hybrid key's, when configured) is written to <data_dir>/log.vkey on start, and
the log key's through the storage for readers without that dir (Postgres: tracekit_meta); start is refused when the
stored notes were signed by another key. Notes are signed off the writer thread; the writer only reads the heads. A
note the log key fails to sign waits for the next round; an outage of LOG_KEY_GAP_S gets one signed
`capture.gap{degraded_unanchored}`.

Publishing (04-design §2.9, §8): one worker per configured witness sends each tree's latest note to it (add-checkpoint,
off the writer: the writer only computes consistency proofs) and merges the verified cosignature lines into the stored
note, whose body never changes. Per witness and tree, the store keeps the size the witness last cosigned and the retry
state (witness-queue.json), so a restart resumes where it left off; retries back off from BACKOFF_S[0] to BACKOFF_S[1]
(a refusal waits the longest). A log a witness has failed to cosign for WITNESS_GAP_S gets one signed
`capture.gap{witness_failed}` per outage. A cosignature whose timestamp is more than `clock_skew_s` from the signer's
clock starts a clock skew episode: one signed `capture.gap{clock_skew}` until a cosignature within it ends the episode.

Anchoring (04-design §2.9, decision S2): with `anchors.rekor`, one more worker of the same kind, named `rekor`, anchors
the latest record tree note in Rekor v2 with an RFC 3161 timestamp, at most once per `every_s` (>= 3600), signed with
keys/rekor.key (P-256, its public key written to <data_dir>/rekor.pub on start), and stores the anchor through the
storage (anchors.jsonl). It shares the retry queue, backoff and `witness_failed` gap.

Monitoring (04-design §2.9): the metrics port also serves each log read-only as C2SP tlog-tiles, for
`tracekit monitor` (SignerService.tlog).

Policy (04-design §4): the signer classifies the tool and decides with policy2; every decide gets a fresh decision_id
that one `complete` with the same arguments consumes. Only deny and ask are memoised, per (tool_call_id, attempt).

Approvals (04-design §5, decision S6): one per (tenant, run, tool_call_id, attempt), under a random id. The
approval.request record binds it to the call (binding_digest); `approval_consume` lets the call run once, only with the
approved arguments, and records every refusal. Approvals and the index are rebuilt from the log on start; the
signer's copy of a pending call's arguments (what the approver is shown) is kept encrypted under keys/approval_args.key
and deleted once the approval is consumed, rejected or expired. An approval expires after APPROVAL_TTL_S, when its
run ends, or at once when the adapter abandons it (`approval.abandoned`). An ask rule with `approval: {executor: t2}`
makes the consume return the approved arguments from that copy: its caller runs exactly those.
Who answers (design §5): with a config (`approvals`), only an approver of the run's tenant or a break-glass identity
(any tenant, a reason required, recorded `break_glass`), never the requester or the run's owner unless
`self_approval: allow`. Without one (the dev signer), any identity of the run's tenant, a self-approval labelled
(`self_approved`). The `approval` record carries the approver's identity as the transport established it. Approvals
are listed and shown only to the run's owner and to those who may answer them. The requester, the run's owner and its
principal count as one person with every identity `persons` maps to the same person id; OIDC identities are compared
by person id (an alias of the requester or the run's owner is the same person), and a run's attested principal never
answers its run's approvals, break-glass or not. A bridge granted `approval_decide_on_behalf` (never a default)
answers for someone else, and the record names both (`via`: the bridge): a chat bridge sees its tenant's approvals and
answers for the Slack user who clicked, who (or a user group the bridge found them in) must be an approver; the
viewer's approval pages (tracekit.view) list, show and answer approvals for the OIDC person their login established
(`on_behalf`), under the same rules as that person, of the bridge's own tenant unless the bridge is in
multi_tenant_apps.
Passkeys: an ask rule with `approval: {passkey: required}` is approved only with a WebAuthn assertion
(tracekit.identity.webauthn) over its approval_id, binding digest and the decision, by the passkey the person
registered through a bridge (`passkey_register`, kept in data_dir/passkeys.json), verified here against
`approvals.webauthn`; the record carries the credential id and that the user was verified.

Live constraints (docs/policy-v2.md#live-constraints): `constraint_add` (any client of the run: the Claude Code hook
sends what the person's prompt states at UserPromptSubmit, tracekit.constraints) writes a constraint.added record with
the kind and, for a file, only the file name's commitment. After the policy engine, a call of the run that breaks one
(the commitment of a file it writes opens it; a push; the network; any write) is raised to an ask (TK-CONSTRAINT) a
person answers as any ask; a deny stays a deny and nothing is ever lowered, so a made-up constraint can only hold more.
The agent is told why with the file name from its own arguments.

Containment (docs/incidents.md): an incident of a `respond: {mode: enforce}` trigger acts in the writer item of the
record that fired it (_respond): `hold` makes every further call of each live run its scope reaches an ask a person
answers (TK-HOLD, carrying the incident id: never an agent, never self-approval) and expires their live approvals;
`quarantine` denies them (TK-QUARANTINE, QUARANTINE_DENIES recorded, then refused), refuses consumes and a gateway's
model requests, and closes the run with reason quarantine. A run may be held by several incidents at once: it stays
held until a person resolves or resumes each. With no person approver configured a hold is a quarantine;
paused (response_pause), nothing acts. The call that fired a hold is decided again, held. New runs of the same owner
and attested principal (or of a held parent) inherit a hold for `cooldown_s`. A decision the detector can't vouch for
(state unavailable) holds its run when the policy enforces holds. Operators (never-default grants, in their tenant)
list, show and resolve incidents, hold, quarantine and resume runs, pause the response engine and suspend identities;
a resolve or resume needs a person who is not the runs' owner, principal or requester. The state is rebuilt from the
records (pipeline.contain_state). Incident records reach webhooks through a durable outbox (webhook.Outbox).

Principal (04-design §2.2): register_run's `principal` is app-asserted (principal_attested: false); its
`principal_token`, an end user's token that the `oidc` issuers (http.oidc) verify, records that user's person id with
principal_attested: true. The token itself is never recorded.

Privacy (04-design §1.2, §2.4; docs/privacy.md): a result and the approver's copy of the arguments go through
privacy.redact before they are committed or stored; a result's record carries a `redaction` manifest (the rules that
fired, never the values). A client may say it redacted already; the signer redacts again regardless and flags a secret
it still finds. Every published digest of agent content is an HMAC under a per-record salt derived from
keys/args_salt.key (`salt_label`), which `reveal` prints for one record. Policy decides on the unredacted arguments.

Content vault (docs/privacy.md): with `content.retain`, the signer also keeps what each record commits to, after its
redaction: a decision's arguments (redacted, as the approver sees them: `redacted` when that changed them, so they no
longer open args_commitment), a result, an observed input, a model exchange's `body`. Each is encrypted (AES-256-GCM)
under a random key per run, which keys/content.key wraps, with the record bound in as associated data ({log_id,
run_id, seq: the run_seq, commitment}), and stored through the storage; content over max_record_bytes is not kept, and
the vault says so. `content_get` (the `content_read` grant, never a default) returns it with each record's salt, so the
caller can open the commitment (no salt, `redacted`, for content redaction changed: it opens nothing, or for a model
exchange redaction changed whose tool_uses carry args_commitments, which the salt would open), and writes a signed
`content.accessed` into the tenant's signer run; `content_erase` and retention (runs whose key was stored more than
retention_days ago, checked at start and every CONTENT_SWEEP_S) delete a run's key and blobs, then write
`content.erased`. Records are never changed.

Provenance (docs/policy-v2.md): each run registered since the signer started has an index, in memory only, of the
values (tracekit.provenance) its untrusted tools' results (the policy's `untrusted` list) and its `observe` inputs
carried, keyed by an HMAC under a key drawn per process, each with the record that first brought it and whether that
content was trusted (an observed input is what the caller says; other tools' results are not indexed: they can echo
the agent's own arguments). Values are read before redaction (only their HMACs are kept). A value once observed as
trusted stays trusted. `decide` answers `send_result` for an untrusted tool, so its adapter completes it with the
result rather than a digest. `from: untrusted` rules match on the index, and every decision records which arguments
carry untrusted-only values (field, kind, source record; never the value). The index is `partial` once an untrusted
tool completes with a digest or no result, or a client's events skip a client_seq (a lost observe or result),
`truncated` once a result carries more values than are read or the run's index is full, `unavailable` after a restart
(a storage recovery keeps it), and a decision whose values take past its deadline is `timeout`; in each, `from:
untrusted` rules fail closed: they match whenever their pattern does.
"""
import argparse
import base64
import collections
import datetime
import functools
import hashlib
import hmac
import itertools
import json
import logging
import traceback
import math
import os
import pathlib
import re
import secrets
import signal
import socket
import sys
import threading
import time
import unicodedata
import types

import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tracekit import __version__, constraints, crypto, harness_helper, merkle, otlp, privacy, provenance, public_witness, \
    yamlmini
from tracekit.client import remote_url_error
from tracekit.anchor import rekor2
from tracekit.anchor.rekor2 import RekorAnchor
from tracekit.deploy import files
from tracekit.format import checkpoint, registry, slh_dsa
from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict
from tracekit.format.records import RecordSigner, verify_record
from tracekit.identity.base import CallerIdentity
from tracekit.identity import webauthn
from tracekit.identity.oidc import keys, person
from tracekit.locking import lock_file
from tracekit.policy2 import classes, compile as policy_compile, engine
from tracekit.policy2.engine import Engine
from tracekit.signer import detect, logkey, metrics, reconcile, rpc_schema, webhook
from tracekit.signer import otel as signer_otel
from tracekit.signer.pipeline import (EXPIRED, LOST, RESULTS_PER_CALL, RecordLog, approval, constraint_state,
                                      cooldown_key, degrade, epoch, final_run, owner, person_only_keys, salt_label,
                                      skipped, subject, writer)
from tracekit.signer.quotas import MAX_LINE, Limits, Quotas, key as quota_key
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.signer.runtoken import RunTokens
from tracekit.storage.base import ACK_ON_WRITE, RECORDS, StorageUnavailable, registry_tree
from tracekit.storage.file import FileStorage, _mkdir, _sync_dir, _write_all
from tracekit.storage.file import fsck as fsck_store
from tracekit.tlog_witness import TlogWitness, WitnessError, log_signed, signed_by
from tracekit.transport import answering_hello, hello
from tracekit.wiki import wiki_url

DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy2", "packs", "dev.yaml")
APPROVAL_TTL_S = 3600
DECISION_TTL_S = 300
REFUSAL_WINDOW_S = 60
STRICTNESS = ("allow", "flag", "ask", "deny")
LIVE = ("requested", "approved")   # approval states that may still lead to a consume
LIST_PAGE = 100
T2 = {"source": "gateway", "tier": "T2"}   # a call a gateway or executor decided, ran and completed for its client
TICK_S = 1.0
WITNESS_START_S = 30.0   # start-up: how long the witnesses, asked at once, have to say how far they cosigned
CLOSE_WAIT_S = 60.0   # serve --close-on-stop: how long the final notes wait for witnesses (within the pod's grace)
CHECKPOINT_S, CHECKPOINT_MIN_S = 10.0, 1.0
WITNESS_GAP_S, LOG_KEY_GAP_S, BACKOFF_S = 300.0, 300.0, (1.0, 300.0)
FSCK_S, CLOCK_SKEW_S, LOCK_TIMEOUT_S, RENEW_RETRY_S = 86400.0, 300.0, 10.0, 60.0
SNAPSHOT_RECORDS = 100_000
PROVENANCE_MAX, PROVENANCE_SHOWN = 20_000, 16   # index entries per run (then truncated); entries a decision records
PROVENANCE_S = engine.REGEX_TIMEOUT_S   # reading a decision's argument values: the same budget as its policy match
CLASSES = ("public", "customer", "tracekit", "operator")
GRACE_S, IDLE_S = 5.0, 3600.0
HEARTBEAT_S = 30.0   # how often a transcript tailer sends tailer_heartbeat, and an egress observer observe_effect
TAILER_LOST_S = 3 * HEARTBEAT_S   # a tailer or observer silent this long while its run is open is lost
OBSERVE_GRACE_S = 120.0   # an observer reports a minute's traffic once the minute ends, at its next heartbeat
SENSOR_SKEW_S = 5.0   # how far a kernel sensor's clock may run behind the signer's for an event to find its run
DECIDED_GAPS_MAX = 100   # decided_not_completed gaps per run, then one gap counting the rest
GATEWAY_WAIT_S = 600.0   # the MCP gateway's upstream timeout, the longest of the shipped gateways
FAIL_MODES = {"default": "closed"}
TLOG_PATH = re.compile(r"/(?:registry/([0-9a-f]{32})/)?(?:(checkpoint)|tile/(entries|[0-9]|[1-5][0-9]|6[0-3])/"
                       r"((?:x[0-9]{3}/)*[0-9]{3})(?:\.p/([1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))?)")
CONFIG_KEYS = {"data_dir", "socket", "socket_mode", "tcp_endpoint", "http", "durability", "tenant", "tenants",
               "authorize", "limits", "acknowledge_rollback", "policy", "multi_tenant_apps", "migrators", "analyzers",
               "importers", "fail_modes", "grace_s", "idle_s", "origin", "metrics", "witnesses", "contact", "approvals",
               "lock_timeout_s", "fsck_every_s", "clock_skew_s", "anchors", "otlp", "otel_out", "storage", "gateways",
               "gateway_mandatory", "log_key", "harness_binding", "record_key", "route", "view", "decision_keys",
               "webhook", "content", "gateway_wait_s", "suspensions", "posture", "observe_grace_s",
               "verify_tool_results"}
# signer.yaml sections whose features are experimental (docs/support.md)
EXPERIMENTAL_KEYS = ("http", "storage", "tenants", "multi_tenant_apps", "gateways", "witnesses", "anchors", "record_key",
                     "log_key", "webhook", "otlp", "otel_out", "harness_binding", "suspensions", "verify_tool_results",
                     "importers")
APPROVAL_KEYS = {"self_approval", "approvers", "break_glass", "persons", "webauthn", "agents", "ttl_s",
                 "agent_consume_s", "agent_timeout_s"}
# agent approvers (docs/approvals.md#agent-approvers): what an identity in approvals.agents may call, given an authorize
# entry (never by default); how long its approval may wait to be consumed, and an eligible approval for its answer
AGENT_METHODS = frozenset({"approval_list", "approval_review", "approval_decide", "status"})
AGENT_CONSUME_S, AGENT_TIMEOUT_S = 300, 600
# anti-shopping: approvals routed to agents per run, and per tenant per window; past them, people answer
# lean: fixed caps; make them approvals.* keys if deployments need others
AGENT_REVIEWS_PER_RUN, AGENT_REVIEWS_PER_TENANT, AGENT_REVIEWS_WINDOW_S = 10, 1000, 3600
# characters a person reading the reviewer view can't see but a model reads: control, format (bidi, zero-width, tags)
# and line/paragraph separators
_HIDDEN = ("Cc", "Cf", "Zl", "Zp")
OTLP_IMPORT = "otlp_import"   # an `authorize` grant, never a default: OTLP/HTTP import (otlp config section)
ON_BEHALF = "approval_decide_on_behalf"   # an `authorize` grant, never a default: a bridge answers for its people
OTLP_MAX_SPANS = 512
DECISION_IMPORT = "decision_import"   # an `authorize` grant, never a default: an external policy system's decisions
PASSKEYS = "passkeys.json"   # in data_dir: person id -> {id, key (base64 SPKI), count (last signCount)}
CONTENT_READ = "content_read"   # an `authorize` grant, never a default: content_get (the content vault)
# what an unconfigured uid peer or the dev token may call; every other method is an `authorize` grant only (NEVER_DEFAULT)
DEFAULT_GRANTS = frozenset({
    "register_run", "decide", "complete", "observe", "state_write", "model_event", "approval_request",
    "approval_decide", "approval_wait", "approval_consume", "approval_get", "approval_list", "approval_abandon",
    "approval_revoke", "close_run", "delegate_run", "tailer_lost", "status", "read", "checkpoint_nudge",
    "passkey_register", "why_finding", "review_finding", "constraint_add"})
OPERATOR = frozenset({"incident_list", "incident_show", "incident_resolve", "run_hold", "run_quarantine", "run_resume",
                      "response_pause", "response_resume", "suspend", "unsuspend"})   # containment's operator calls
# tailer_heartbeat: only an identity granted it (TAILER_METHODS), so the agent can't keep a killed tailer's
# heartbeats going with its own token; observe_effect: an egress observer's own identity, never an agent's
NEVER_DEFAULT = frozenset({DECISION_IMPORT, ON_BEHALF, "content_get", "content_erase", "approval_review",
                           "approval_agents", "tailer_heartbeat", "observe_effect"}) | OPERATOR
CONTENT = {"retain": False, "retention_days": 30, "max_record_bytes": 1 << 20}   # the `content` config section
DEV_RETENTION_DAYS = 7   # how long the dev signer keeps call content for its viewer (dev_content)
CONTENT_SWEEP_S = 3600.0
ERASED = object()   # _data_key of a run whose content was erased
QUARANTINE_DENIES = 100   # TK-QUARANTINE decisions a quarantined run records; later calls are refused unrecorded
MAX_CONSTRAINTS = 32   # live file constraints a run takes (constraint_add); past it every write is held
MAX_NAMES = 256   # distinct files of one call checked against a run's file constraints; past it, the call is held
COOLDOWN_S = 3600   # respond.cooldown_s default: how long new runs of a held owner and principal inherit the hold
MAX_UNMATCHED = 1 << 16   # (decision, result digest) pairs remembered as not matching; forgotten all at once past it


def load_policy(path=DEFAULT_POLICY, backend=None):
    """The policy2 Engine for a policy file; ValueError lists every lint error."""
    pol, errors = policy_compile.build(path)
    if errors:
        raise ValueError("; ".join(errors))
    return Engine(pol, backend)


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


MARK = re.compile(r"\[REDACTED:([a-z_]+)\]")


def _salt(key, label):
    return hmac.new(key, label.encode(), "sha256").digest()


def _commitment(salt, digest):
    return "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest()


def content_config(content):
    """The `content` config section (None: off) with its defaults filled in; ValueError when it is not valid."""
    c = {**CONTENT, **content} if isinstance(content, dict) else content or dict(CONTENT)
    if not (isinstance(c, dict) and set(c) == set(CONTENT) and isinstance(c["retain"], bool)
            and all(type(c[k]) is int and c[k] > 0 for k in ("retention_days", "max_record_bytes"))):
        raise ValueError("content takes retain (true or false), retention_days and max_record_bytes (positive integers)")
    return c


def _committed(e):
    """The commitment of record event `e` that its retained content opens, or None."""
    d = e["data"]
    return {"policy.decision": d.get("args_commitment"), "tool.result": (d.get("output") or {}).get("hash"),
            "input.observed": (d.get("output") or {}).get("hash"),
            "model.exchange": d.get("content_digest")}.get(e["type"])


def _redact(value, dotenv, claim=None):
    """(`value` through privacy.redact, its manifest). `claim`: the client's manifest when it says it redacted."""
    before = collections.Counter(MARK.findall(canonical(value).decode()))
    out = privacy.redact(value, dotenv)[0]
    fired = collections.Counter(MARK.findall(canonical(out).decode())) - before
    manifest = {"rules": sorted(fired), "count": sum(fired.values()), "client_claimed": claim is not None}
    if claim is not None:
        manifest["client"] = claim
        if fired:
            manifest["client_redaction_incomplete"] = True
    return out, manifest


def _dotenv(args):
    """Whether a call touched a .env path, as v1 decides it: from the fields that say which action ran."""
    return isinstance(args, dict) and privacy.mentions_dotenv(*(args.get(k) for k in privacy.ACTION_FIELDS))


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _shown(args, dotenv):
    """The approver's copy of parsed `args`: privacy.redact, and each digest under `typed_secrets` (a secret the
    Browser Use adapter typed) hidden, since an approver could test guesses of a weak secret against it."""
    shown = privacy.redact(args, dotenv)[0]
    if isinstance(shown, dict) and isinstance(shown.get("typed_secrets"), dict):
        shown = {**shown, "typed_secrets": {n: [d if not (isinstance(d, str) and _DIGEST.fullmatch(d))
                                                else "[REDACTED:typed_secret]" for d in v] if isinstance(v, list) else v
                                            for n, v in shown["typed_secrets"].items()}}
    return shown


def _write_new(path, data):
    """Create `path` (0600) holding all of `data`, or leave nothing there; FileExistsError when it exists."""
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, path)
    finally:
        os.unlink(tmp)
    _sync_dir(os.path.dirname(path))


def _snapshot_key(keys):
    """The key of the store's snapshots, or None before it exists (then the store replays its logs in full). Read
    before the storage lock is taken: a key cut short is ignored, and _secret then stops the start."""
    try:
        with open(os.path.join(keys, "snapshot.key"), "rb") as f:
            key = f.read()
    except FileNotFoundError:
        return None
    return key if len(key) == 32 else None


def _secret(path, make, size=32):
    """The `size`-byte secret in `path`, created (0600) on first use. Called under the storage lock, so never by two
    signers. A file of another size stops the start: a key is never used cut short."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = make()
        _write_new(path, data)
    if len(data) != size:
        raise ValueError(f"{path} holds {len(data)} bytes, not a {size}-byte key: restore it from a backup")
    logkey.mlock(data)
    return data


PREFIX_ENDS = (":*", "/*")


def lookup(table, sub, default=None):
    """table[sub], else the entry of the longest prefix key (ending in `:*` or `/*`) that `sub` starts with, else
    `default`."""
    if sub in table:
        return table[sub]
    # lean: scans every key per call; a prefix trie if maps grow past a few hundred entries
    best = max((k for k in table if k.endswith(PREFIX_ENDS) and sub.startswith(k[:-1])), key=len, default=None)
    return default if best is None else table[best]


def _agents(approvals, authorize, multi_tenant_apps):
    """approvals.agents as a set, after checking that an agent is nothing else: no prefix or group, in no approver,
    break-glass, persons or multi_tenant_apps entry, holding no approval_decide_on_behalf; and that people answer
    what agents can't: at least one approver, each one a person (persons, an OIDC person or group)."""
    agents = approvals.get("agents", [])
    if not agents:
        return frozenset()
    tables = {"approvers": {k: True for k in approvals.get("approvers", ())},
              "break_glass": {k: True for k in approvals.get("break_glass", ())},
              "persons": dict(approvals.get("persons", {})), "multi_tenant_apps": dict.fromkeys(multi_tenant_apps, True)}
    for a in agents:
        if not (isinstance(a, str) and re.fullmatch(r"[a-z0-9_]+:.+", a) and "*" not in a
                and not a.startswith(("group:", "person:"))):
            raise ValueError(f"approvals.agents: {a!r}: an agent is one exact identity (scheme:subject), no prefix or "
                             "group")
        where = [n for n, t in tables.items() if lookup(t, a, False)]
        if ON_BEHALF in (lookup(authorize, a) or ()):
            where.append(f"authorize ({ON_BEHALF})")
        if where:
            raise ValueError(f"approvals.agents: {a} is also in {', '.join(where)}: an agent identity is an agent only")
    people = approvals.get("approvers", [])
    if not people:
        raise ValueError("approvals.agents needs approvers: people answer every call an agent may not")
    for p in people:
        if p not in tables["persons"] and p.split(":")[0] not in ("oidc", "person", "group"):
            raise ValueError(f"approvals.approvers: {p}: with agents, every approver is a person: map it in persons, "
                             "or name an OIDC person or group")
    return frozenset(agents)


def _escaped(value):
    """`value` with control and bidirectional-override characters in its strings (and keys) written as \\uXXXX text."""
    if isinstance(value, str):
        return "".join(c if unicodedata.category(c) not in _HIDDEN else
                       f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}" for c in value)
    if isinstance(value, list):
        return [_escaped(v) for v in value]
    return {_escaped(k): _escaped(v) for k, v in value.items()} if isinstance(value, dict) else value


def _recorded(identity):
    """An identity as run.registered and approval records carry it."""
    who = person(identity)
    return {"scheme": identity.scheme, "subject": identity.subject[:256], "attested": identity.attested,
            **({"person": who} if who else {})}


def _holder(gw, req):
    """Who holds a call a request decides or answers: (the gateway, the caller it names), or (None, None) for the run's
    client itself (SignerService._hold)."""
    return (subject(gw), req["caller"]) if gw else (None, None)


def _process_identity():
    return CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


def _person_like(p, persons):
    """Whether approver entry `p` names a person: mapped in `persons`, or an OIDC person or group."""
    return p in persons or p.split(":")[0] in ("oidc", "person", "group")


class Suspensions:
    """The operator-managed suspension list a central signer's replicas share: a JSON file {tenant: {identity or prefix
    (`:*`, `/*`): {by, at, reason?}}}, read again whenever it changes (TokenStore's model). Unreadable:
    calls are refused (`unavailable`), never let through."""

    def __init__(self, path):
        self.path, self.entries, self._stamp, self._lock = path, {}, None, threading.Lock()

    def _read(self):
        try:
            data = json.loads(pathlib.Path(self.path).read_bytes())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise RPCError("unavailable", f"the suspension list is unreadable: {e}") from None
        if not isinstance(data, dict) or not all(isinstance(t, dict) and all(isinstance(v, dict) for v in t.values())
                                                 for t in data.values()):
            raise RPCError("unavailable", f"{self.path} is not a suspension list")
        return data

    def load(self):
        """(the entries, whether they changed since the last load)."""
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            stamp = None
        except OSError as e:
            raise RPCError("unavailable", f"the suspension list is unreadable: {e}") from None
        with self._lock:
            if stamp == self._stamp:
                return self.entries, False
            self.entries, self._stamp = self._read(), stamp
            return self.entries, True

    def forget(self):
        """Read the list again on the next load, as if it changed."""
        with self._lock:
            self._stamp = None

    def change(self, tenant, identity, entry):
        """Add (or with `entry` None, lift) the suspension of `identity` in `tenant`; whether the list changed."""
        # lean: read-modify-write under a per-process lock; two replicas changing the list at the same instant can lose
        # one change (the record of it stays): keep the list in Postgres if operators race
        with self._lock:
            data = self._read()
            mine = data.setdefault(tenant, {})
            if (identity in mine) == (entry is not None):
                return False
            if entry is None:
                del mine[identity]
                if not mine:
                    del data[tenant]
            else:
                mine[identity] = entry
            files.write_json(self.path, data)
            return True


class SignerService:
    def __init__(self, data_dir, policy=None, identity=None, tenant="default", tenants=None, limits=Limits(),
                 durability=ACK_ON_WRITE, witnesses=(), acknowledge_rollback=False, open_storage=None, isolation=None,
                 multi_tenant_apps=(), migrators=(), analyzers=(), importers=(), fail_modes=None, grace_s=GRACE_S,
                 idle_s=IDLE_S, bridge=None, origin=None, authorize=None, contact=None, approvals=None,
                 lock_timeout_s=0, fsck_every_s=FSCK_S, clock_skew_s=CLOCK_SKEW_S, rekor=None, otlp=None, otel_out=None,
                 storage_config=None, gateways=(), gateway_mandatory=False, log_key=None, slh_dsa_file=None,
                 harness_binding=None, record_key=None, route=None, oidc=None, decision_keys=None, webhooks=(),
                 content=None, gateway_wait_s=GATEWAY_WAIT_S, suspensions=None, posture=None,
                 observe_grace_s=OBSERVE_GRACE_S, verify_tool_results=None):
        """`identity` answers the in-process SignerAPI calls (default: this process's uid); transports call
        handle_frame with the identity they established. `policy` is a policy2 Engine (default: load_policy()).
        `open_storage()` defaults to the store `storage_config` (the `storage` config section) names, else file storage
        in data_dir/store. `origin` names the log in its checkpoints, `contact` its operator in the logs list.
        `witnesses` cosign its notes (see the module docstring).
        `multi_tenant_apps`, `migrators`, `analyzers` and `importers` are identities ("scheme:subject"); `tenants` and `authorize` map identities or prefixes (`...:*`, `.../*`) to a tenant and to the methods they may call.
        `isolation` fixes the signer_isolation label of every run (a dev signer: same-user). `bridge`: see RecordLog.
        `approvals`: who answers approvals (the `approvals` config section); None for the dev signer's rules.
        `lock_timeout_s`, `fsck_every_s` (0: no background check) and `clock_skew_s`: see the config keys.
        `rekor`: the `anchors.rekor` config section ({signing_config, trusted_root, every_s}), or None.
        `otlp` ({max_spans}) and `otel_out` ({endpoint, headers}): the config sections, or None.
        `gateways` (identities or prefixes), `gateway_mandatory` and `gateway_wait_s`: see the config keys.
        `log_key`: a signer.logkey key (default: the file key in keys/log.key); it must be the key of the log's notes.
        `slh_dsa_file`: the SLH-DSA secret key file (created on first use) that adds a hybrid line to every note.
        `harness_binding` ({helper, required, harnesses}): the config section, or None.
        `oidc`: the identity.oidc.OidcAuthenticator that checks register_run's principal_token, or None.
        `record_key`: the `record_key` config section: a fresh record key, certified by its issuer, at every start and
        once two thirds of its certificate's validity have passed (else the file key in keys/record.key).
        `route`: the prefix (before a dot) of this signer's run and approval ids, or None.
        `decision_keys`: external system -> its base64 Ed25519 public key (the `decision_keys` config section).
        `webhooks`: the `webhook` config section as webhook.load gives it ({url, events, secret, format?}).
        `content`: the `content` config section (the content vault; see the module docstring), or None (off).
        `suspensions`: the shared suspension list's path (default data_dir/suspensions.json).
        `posture` ({network, tool_calls}), `observe_grace_s` and `verify_tool_results`: see the config keys."""
        fail_modes = dict(fail_modes or FAIL_MODES)
        if not all(isinstance(k, str) and v in ("open", "closed") for k, v in fail_modes.items()):
            raise ValueError("fail_modes maps tool classes to open or closed")
        if approvals is not None and not (
                isinstance(approvals, dict) and set(approvals) <= APPROVAL_KEYS
                and approvals.get("self_approval", "deny") in ("allow", "deny")
                and all(isinstance(approvals.get(k, []), list) for k in ("approvers", "break_glass"))
                and isinstance(approvals.get("persons", {}), dict)
                and all(isinstance(v, str) for v in approvals.get("persons", {}).values())
                and isinstance(approvals.get("agents", []), list)
                and all(type(approvals.get(k, 1)) is int and approvals.get(k, 1) > 0
                        for k in ("ttl_s", "agent_consume_s", "agent_timeout_s"))):
            raise ValueError("approvals takes self_approval (allow|deny), approvers, break_glass and agents (identity "
                             "lists), persons (identity -> person id) and ttl_s, agent_consume_s, agent_timeout_s "
                             "(seconds)")
        self._agents = _agents(approvals or {}, dict(authorize or {}), set(multi_tenant_apps))
        policy = policy or load_policy()
        respond = policy.policy.get("respond", [])
        if any(r["mode"] == "enforce" and r["action"] == "notify" for r in respond) and \
                not any("incident" in w["events"] for w in webhooks):
            raise ValueError("the policy's respond notifies (action notify, mode enforce) but no webhook subscribes to "
                             f"incident events: add `incident` to a webhook's events ({wiki_url('docs/webhooks.md')})")
        # a hold no person can answer is a quarantine (_respond)
        self._people = any(_person_like(p, (approvals or {}).get("persons", {}))
                           for p in (approvals or {}).get("approvers", ()))
        self._fail_closed = any(r["mode"] == "enforce" and r["action"] in ("hold", "quarantine") for r in respond)
        if not self._agents and any("agent" in (r.get("approval") or {}) for _, r, *_ in policy.rules):
            raise ValueError("the policy lets agent approvers answer (approval.agent) but approvals.agents names none: "
                             "add the reviewer's identity there, or remove approval.agent from the policy")
        self._webauthn = (approvals or {}).get("webauthn")
        if self._webauthn is not None and not (
                isinstance(self._webauthn, dict) and set(self._webauthn) == {"rp_id", "origin"}
                and isinstance(self._webauthn["rp_id"], str) and isinstance(self._webauthn["origin"], str)
                and self._webauthn["origin"].startswith(("https://", "http://localhost"))):
            raise ValueError("approvals.webauthn takes rp_id and origin (https://, or http://localhost)")
        otlp = {} if otlp is None else otlp
        if not (isinstance(otlp, dict) and set(otlp) <= {"max_spans"} and isinstance(
                otlp.get("max_spans", 1), int) and otlp.get("max_spans", 1) > 0):
            raise ValueError("otlp takes max_spans (a positive integer)")
        if otel_out is not None and not (
                isinstance(otel_out, dict) and set(otel_out) <= {"endpoint", "headers"}
                and isinstance(otel_out.get("endpoint"), str) and not remote_url_error(otel_out["endpoint"])
                and isinstance(otel_out.get("headers", {}), dict)
                and all(isinstance(v, str) for v in otel_out.get("headers", {}).values())):
            raise ValueError("otel_out takes endpoint (https, or http to loopback) and headers (a string mapping)")
        hb = {} if harness_binding is None else harness_binding
        hs = hb.get("harnesses", {}) if isinstance(hb, dict) else None
        harnesses = harness_helper.normalize_harnesses(
            [{"name": n, **(h if isinstance(h, dict) else {"exe": h})} for n, h in hs.items()]
            if isinstance(hs, dict) else ())
        if not (isinstance(hs, dict) and set(hb) <= {"helper", "required", "harnesses"} and len(harnesses) == len(hs)
                and isinstance(hb.get("helper", ""), str) and isinstance(hb.get("required", []), list)):
            raise ValueError("harness_binding takes helper (a socket path), required (identities) and harnesses "
                             "(name -> an absolute executable path, or {exe, script})")
        try:
            self._decision_keys = {k: crypto.spki(base64.b64decode(v, validate=True))
                                   for k, v in (decision_keys or {}).items()}
        except (AttributeError, TypeError, ValueError):
            self._decision_keys = None
        if self._decision_keys is None or any(crypto.key_alg(v) != "ed25519" for v in self._decision_keys.values()):
            raise ValueError("decision_keys maps system names to base64 Ed25519 public keys")
        self.content = content_config(content)
        if posture is not None and not (isinstance(posture, dict) and set(posture) <= {"network", "tool_calls"}
                                        and all(v in ("enforced", "open") for v in posture.values())):
            raise ValueError("posture takes network and tool_calls, each enforced or open (gateway_mandatory is a "
                             "setting of its own)")
        # recorded in each run.registered when the operator asserts anything
        self.posture = {"network": "open", "tool_calls": "open", **(posture or {}), "gateway_mandatory": bool(
            gateway_mandatory)} if posture is not None or gateway_mandatory else None
        self.observe_grace_s = observe_grace_s
        if verify_tool_results not in (None, "record", "refuse"):
            raise ValueError("verify_tool_results is record or refuse")
        self.verify_tool_results = verify_tool_results
        self._unmatched = set()   # (decision_id, result_digest) of a gateway's forms that open no tool.result of it
        self.metrics = metrics.SignerMetrics()
        self._prov_key = os.urandom(32)   # the provenance index's key: per process, as the index is
        authorize = dict(authorize or {})
        grants = {*REQUESTS, OTLP_IMPORT, CONTENT_READ} - {"content_get"}
        if not all(isinstance(m, list) and set(m) <= grants for m in authorize.values()):
            raise ValueError(f"authorize maps identities to lists of methods out of {sorted(grants)} "
                             "(content_get is granted as content_read)")
        both = sorted(k for k, m in authorize.items() if "register_run" in m and OPERATOR & set(m))
        if both:
            raise ValueError(f"authorize grants {', '.join(both)} both register_run and containment's operator calls: "
                             "an agent's identity can't operate its own containment; give operators an identity of "
                             f"their own ({wiki_url('docs/incidents.md')})")
        keys = os.path.join(data_dir, "keys")
        if open_storage is None and storage_config:
            from tracekit.storage import postgres
            section = storage_config["postgres"]
            open_storage = lambda: postgres.PostgresStorage(postgres.read_dsn(section), durability,  # noqa: E731
                                                            lock_timeout_s, _snapshot_key(keys), self.content["retain"])
        open_storage = open_storage or (lambda: FileStorage(os.path.join(data_dir, "store"), durability,
                                                            self.metrics.fsync_seconds.observe, lock_timeout_s,
                                                            _snapshot_key(keys)))
        storage = open_storage()   # takes the storage lock before anything else
        try:
            _mkdir(keys)
            os.chmod(keys, 0o700)
            storage.snapshot_key = _secret(os.path.join(keys, "snapshot.key"), lambda: os.urandom(32))
            certify = None
            if record_key:
                from tracekit import issuer
                certify, sign = functools.partial(issuer.certify, record_key["issuer"]), None
            else:
                sign = RecordSigner(_secret(os.path.join(keys, "record.key"), lambda: crypto.generate()[0]))
            self.tokens = RunTokens(_secret(os.path.join(keys, "run_token.key"), lambda: os.urandom(32)))
            self._salt_key = _secret(os.path.join(keys, "args_salt.key"), lambda: os.urandom(32))
            self._args_key = AESGCM(_secret(os.path.join(keys, "approval_args.key"), lambda: os.urandom(32)))
            path = os.path.join(keys, "content.key")   # kept once made: what the vault holds stays readable and erasable
            self._content_key = AESGCM(_secret(path, lambda: os.urandom(32))) if (
                self.content["retain"] or os.path.exists(path)) else None
            self.quotas = Quotas(limits)
            salt = _secret(os.path.join(keys, "registry_salt.key"), lambda: os.urandom(32))
            self._log_key = log_key or logkey.FileKey(_secret(os.path.join(keys, "log.key"),
                                                              lambda: crypto.generate()[0]))
            self._slh = slh_dsa_file and _secret(slh_dsa_file, lambda: slh_dsa.keygen()[0], 2 * slh_dsa.PK_SIZE)
            self.anchors = [] if rekor is None else [RekorAnchor(
                rekor["signing_config"], rekor["trusted_root"],
                _secret(os.path.join(keys, "rekor.key"), rekor2.new_key), rekor.get("every_s", rekor2.MIN_EVERY_S))]
            self.log = RecordLog(storage, open_storage, sign, self.quotas, salt, self.metrics, bridge, certify,
                                 detect.Detector.of(policy))
        except BaseException:
            storage.close()
            raise
        self.log.respond = self._respond
        self._suspensions = Suspensions(suspensions or os.path.join(data_dir, "suspensions.json"))
        start = storage.tail_state()["tree_size"]
        self._webhooks = [webhook.Sender(w["url"], set(w["events"]) - {"incident"}, w["secret"],
                                         dropped=self.metrics.webhook_dropped) for w in webhooks
                          if set(w["events"]) - {"incident"}]
        self._webhooks += [webhook.Outbox(
            w["url"], w["secret"], w.get("format", "ocsf"),
            os.path.join(data_dir, f"outbox-{hashlib.sha256(w['url'].encode()).hexdigest()[:16]}.json"),
            lambda lo, hi: self.log.storage.iter_range(lo, hi), self._cited, start, self.metrics.outbox_failures)
            for w in webhooks if "incident" in w["events"]]
        # before the startup checks, so their records go out too; then the containment's own follow-up
        self.log.observers += [w.put for w in self._webhooks] + [self._after_write]
        self.policy, self.isolation = policy, isolation
        # neither a handoff nor a structured-output tool is a missing decide, live or at run.final
        self.log.handoff = lambda tool: self.policy.is_handoff(tool) or self.policy.is_structured_output(tool)
        self.identity = identity or _process_identity()
        self.tenant, self.tenants, self.authorize = tenant, dict(tenants or {}), authorize
        self.multi_tenant_apps, self.migrators, self.analyzers = set(multi_tenant_apps), set(migrators), set(analyzers)
        self.importers = set(importers)
        # run key -> monotonic time of its tailer's last heartbeat (a restart's open runs were tailed until now);
        # (*run key, observer) -> its observer's
        self._beats = {k: time.monotonic() for k in self.log.live if self.log.runs[k].get("tailed")}
        self._beats_lock = threading.Lock()
        # (tenant, observer) -> (monotonic time of its last observe_effect, its process `instance`, a sensor's name, the
        # identities whose runs a sensor covers), under _beats_lock
        self._observers = {}
        # (tenant, observer) -> the instances another took over from: one calling again is a second live process
        self._superseded = collections.defaultdict(lambda: collections.deque(maxlen=64))
        # (*run key, observer) -> whether a kernel sensor's import may say it observed the run: True once it recorded
        # an event of it (with an import per node, only the run's node's does), False for good once it reported a loss
        self._sensed = {}
        self._gateways, self.gateway_mandatory = {k: True for k in gateways}, bool(gateway_mandatory)
        self.gateway_wait_s = gateway_wait_s
        self.fail_modes, self.grace_s, self.idle_s = fail_modes, grace_s, idle_s
        self.otlp_max_spans = otlp.get("max_spans", OTLP_MAX_SPANS)
        self.approvals, self.data_dir, self.storage_config, self.oidc = approvals, data_dir, storage_config, oidc
        self.id_prefix = f"{route}." if route else ""
        self._harnesses, self._helper = harnesses, hb.get("helper")
        self._harness_required = {k: True for k in hb.get("required", ())}
        self._chains, self._chains_lock = {}, threading.Lock()   # pid -> (start time, its chain)
        self.record_key, self._renew_at = record_key, self._renewal()
        self.fsck_every_s, self.clock_skew_s, self._skewed, self._fsck_seen = fsck_every_s, clock_skew_s, set(), set()
        self._snapped = storage.tail_state()["tree_size"]
        self._approvers, self._break_glass = ({k: True for k in (approvals or {}).get(name, ())}
                                              for name in ("approvers", "break_glass"))
        self._persons = dict((approvals or {}).get("persons", {}))
        self.ttl_s, self.agent_consume_s, self.agent_timeout_s = (
            (approvals or {}).get(k, d) for k, d in (("ttl_s", APPROVAL_TTL_S), ("agent_consume_s", AGENT_CONSUME_S),
                                                     ("agent_timeout_s", AGENT_TIMEOUT_S)))
        veto = max((r["approval"]["agent"].get("veto_s", 0) for _, r, *_ in policy.rules
                    if "agent" in (r.get("approval") or {})), default=0)
        if veto >= self.ttl_s:
            raise ValueError(f"an approval.agent veto_s of {veto} s is not under approvals.ttl_s ({self.ttl_s} s): "
                             "every agent approval would expire before it may run")
        self._swept = self._noted = time.monotonic()
        self._args_dir = os.path.join(data_dir, "approvals")   # approval_id -> the encrypted args of a live approval
        # lean: passkeys live in this signer's data_dir; one store shared by replicas once a central signer has several
        self._passkeys = json.loads(files.read(data_dir, PASSKEYS) or "{}")
        self._passkeys_lock = threading.Lock()
        self._cond = threading.Condition()
        self._refusals, self._refusals_lock = {}, threading.Lock()
        self._stop, self._nudged, self._checkpointing = threading.Event(), threading.Event(), threading.Lock()
        self.origin = origin or f"tracekit.local/{self.log.log_id}"
        self.contact, self.witnesses = contact or self.origin, list(witnesses)
        self._queue, self._queue_lock = storage.witness_queue(), threading.Lock()
        self._anchor = next(((a.pop("size"), a) for a in storage.anchors()[-1:]), None)   # (size, the latest anchor)
        self._wake = {w.name: threading.Event() for w in self.witnesses + self.anchors}
        self._key_down = None   # (since, gapped) while the log key fails to sign
        try:
            self.vkey = checkpoint.vkey(self.origin, checkpoint.ED25519, self._log_key.public)
            vkeys = [self.vkey] + ([checkpoint.vkey(self.origin, checkpoint.HYBRID, self._slh_public)]
                                   if self._slh else [])
            latest = storage.checkpoint_latest()
            if latest:   # the log key is stable: another key (a backend switch, a replaced log.key) never takes over
                origin = latest[1].split("\n", 1)[0]   # signature checks of the note are the rollback check's job
                if (origin, checkpoint.key_id(origin, checkpoint.ED25519, self._log_key.public)) \
                        not in checkpoint.signers(latest[1]):
                    raise ValueError("the configured log key did not sign this log's notes: a log keeps its log key, "
                                     "so switch backends only to a key with the same public key")
                hybrid = [line for line in latest[1].partition("\n\n")[2].splitlines()
                          if len(line) > 4096 and line.startswith(f"{checkpoint.DASH}{origin} ")]   # SLH-DSA lines only
                mine = self._slh and checkpoint.key_id(origin, checkpoint.HYBRID, self._slh_public)
                if hybrid and not any(base64.b64decode(line.rsplit(" ", 1)[1])[:4] == mine for line in hybrid):
                    raise ValueError("this log's notes carry a hybrid line from another SLH-DSA key, or the hybrid key "
                                     "is no longer configured: restore the log's log-slh.key (pinned by verifiers)")
            d = files.open_dir(data_dir)
            try:
                files.write(d, "log.vkey", "".join(k + "\n" for k in vkeys).encode("ascii"), 0o644)
                storage.meta_put("log_vkey", self.vkey)
                if logkey.HYGIENE.get("core_limit") is not None:   # a serving signer (harden() ran), not a CLI command
                    files.write(d, "hygiene.json", json.dumps(logkey.HYGIENE).encode("ascii"), 0o644)
                for a in self.anchors:
                    files.write(d, "rekor.pub", (base64.b64encode(a.spki).decode("ascii") + "\n").encode("ascii"), 0o644)
            finally:
                files.close(d)
            _mkdir(self._args_dir)
            os.chmod(self._args_dir, 0o700)
            # the compiled policy, named by its policy_hash, for `tracekit export --v2` to bundle (the verifier
            # recomputes a run's incidents from it)
            _mkdir(os.path.join(data_dir, "policies"))
            try:
                _write_new(os.path.join(data_dir, "policies", policy.policy_hash[len("sha256:"):] + ".json"),
                           policy_compile.canonical(policy.policy).encode("utf-8"))
            except FileExistsError:
                pass
            for aid in os.listdir(self._args_dir):   # left by a crash, or by an approval_request that was rolled back
                if self.log.approvals.get(aid, {}).get("state") not in LIVE:
                    self._drop_args(aid)
            self._check_notes(acknowledge_rollback)
            self._check_witnesses(witnesses, acknowledge_rollback)
        except BaseException:
            self.log.close()
            for w in self._webhooks:
                w.close()
            raise
        for name, help, fn in (
                ("tracekit_signer_queue_depth", "Items waiting for the writer.", self.log.queue_depth),
                ("tracekit_signer_fsync_lag_seconds", "Seconds the oldest written but unsynced record has waited.",
                 lambda: self.log.storage.unsynced_s()),
                ("tracekit_signer_open_runs", "Runs registered and not yet closing.",
                 lambda: sum(list(self.log.open_runs.values()))),
                ("tracekit_signer_pending_approvals", "Approvals requested and not yet answered.",
                 lambda: sum(a["state"] == "requested" for a in list(self.log.approvals.values()))),
                ("tracekit_signer_checkpoint_age_seconds", "Seconds since this signer last wrote a checkpoint note "
                 "(since start when it has written none).", lambda: time.monotonic() - self._noted)):
            self.metrics.add(metrics.Gauge(name, help, fn))
        for name, help, fn in (
                ("tracekit_signer_held_runs", "Runs held by an incident (each call asked of a person).",
                 lambda: sum(bool(r.get("held")) for r in list(self.log.runs.values()) if not r["final"])),
                ("tracekit_signer_quarantined_runs", "Runs quarantined by an incident, not yet final.",
                 lambda: sum(bool(r.get("quarantined")) for r in list(self.log.runs.values()) if not r["final"])),
                ("tracekit_signer_suspended_identities", "Suspension list entries this signer enforces.",
                 lambda: sum(list(self.log.contain["enforcing"].values()))),
                ("tracekit_signer_detector_unavailable", "1 while the detector can't vouch for decisions (a restart "
                 "without its state, until the longest window has passed), else 0.",
                 lambda: int(bool(self.log.detector) and time.time() < self.log.det["until"]))):
            self.metrics.add(metrics.Gauge(name, help, fn))
        self.metrics.add(metrics.Gauge(
            "tracekit_signer_witness_lag_records", "Records in the latest record tree note that the witness has not "
            "cosigned yet.", lambda: self._lag(self.witnesses), "witness"))
        self.metrics.add(metrics.Gauge(
            "tracekit_signer_anchor_lag_records", "Records in the latest record tree note not anchored yet.",
            lambda: self._lag(self.anchors), "anchor"))
        self._exporter = otel_out and signer_otel.Exporter(
            otel_out["endpoint"], otel_out.get("headers", {}), lambda key: list(self.log.storage.iter_run(*key)),
            self.metrics.otel_dropped)
        self._ticker = threading.Thread(target=self._tick_loop, name="tracekit-signer-ticker", daemon=True)
        self._ticker.start()
        self._checkpointer = threading.Thread(target=self._checkpoint_loop, name="tracekit-signer-checkpointer",
                                              daemon=True)
        self._checkpointer.start()
        if fsck_every_s:
            self._fsck = threading.Thread(target=self._fsck_loop, name="tracekit-signer-fsck", daemon=True)
            self._fsck.start()
        self._publishers = [threading.Thread(target=self._publish_loop, args=(w,), name=f"tracekit-witness-{i}",
                                             daemon=True) for i, w in enumerate(self.witnesses + self.anchors)]
        for t in self._publishers:
            t.start()

    def _tamper(self, kind, path, before, after, acknowledged, why):
        """A signed trace.tamper (a rollback is tenant-level); unless acknowledged, client writes are refused."""
        data = {"path": path, "kind": kind, "before": before, "after": after,
                **({"tenant_level": True} if kind == "rollback" else {})}
        if not acknowledged:   # first: client writes stay refused even when the record can't be written now
            self.log.refuse_writes = why + ("; restart with acknowledge_rollback once investigated" if kind == "rollback"
                                            else "; repair the store (tracekit signer fsck) and restart")
        self.log.write(lambda tx: tx.emit(self.log.signer_run(tx), "trace.tamper", data, source="signer"))

    def _check_notes(self, acknowledged):
        """The latest stored note of each tree (the record tree, every registry tree) against the tree: a note of more
        leaves, or of another root at its size, means the log was rolled back or forked."""
        s = self.log.storage
        trees = [(RECORDS, s.tree)] + [(registry_tree(t), s.registry_merkle(t))
                                       for t in sorted(self.log.tenants | set(s.tail_state()["registry"]))]
        for name, tree in trees:
            latest = s.checkpoint_latest(name)
            if latest is None:
                continue
            size, note = latest
            origin, _, root = note.split("\n", 3)[:3]
            path, root = "records" if name == RECORDS else origin, base64.b64decode(root)   # no tenant name in clear
            local = tree.size if tree else 0
            if size > local or tree.root_at(size) != root:
                self._tamper("rollback", path, {"length": size, "hash": "sha256:" + root.hex()},
                               {"length": local, "hash": "sha256:" + (tree.root() if tree else merkle.root([])).hex()},
                               acknowledged, f"the local {path} log ({local} leaves) does not extend its stored "
                                             f"checkpoint ({size}): rolled back")

    def _check_witnesses(self, witnesses, acknowledged):
        if not witnesses:
            return
        text, heads = checkpoint.body(self.origin, 0, merkle.root([])), []
        try:
            empty = self._note(text, self.origin)
        except Exception:   # the log key can't sign now (KMS down): no witness can be asked, as when none answers
            witnesses = ()

        def ask(w):
            try:
                heads.append(w.latest(empty, self.vkey))
            except Exception:   # unreachable or unreadable: counted as no answer
                pass
        asks = [threading.Thread(target=ask, args=(w,), name="tracekit-witness-start", daemon=True) for w in witnesses]
        for t in asks:
            t.start()
        end = time.monotonic() + WITNESS_START_S
        for t in asks:   # one that has not answered by then counts as no answer
            t.join(max(0.0, end - time.monotonic()))
        heads = list(heads)
        if not heads:
            self.log.write(lambda tx: tx.gap("degraded_unanchored", "no configured witness answered at startup"))
            return
        size, root = max(heads, key=lambda h: h[0])
        local = self.log.storage.tail_state()
        if local["tree_size"] >= size:
            return
        self._tamper("rollback", "records", {"length": size, **({"hash": "sha256:" + root.hex()} if root else {})},
                       {"length": local["tree_size"], "hash": "sha256:" + local["tree_root"].hex()}, acknowledged,
                       f"the local log ({local['tree_size']} records) is behind the witnessed checkpoint ({size}): "
                       "rolled back")

    # --- dispatch ---

    def handle_frame(self, identity, frame):
        req = dict(frame)
        return self.call(identity, req.pop("method", None), req)

    def call(self, identity, method, req):
        try:
            if not isinstance(method, str) or method not in REQUESTS:
                raise RPCError("invalid_request", f"unknown method {str(method)[:64]}")
            if self._is_agent(identity) and method not in AGENT_METHODS:
                raise RPCError("forbidden", f"{subject(identity)[:256]} is an agent approver: it may call "
                                            f"{', '.join(sorted(AGENT_METHODS))} only")
            self._grant(identity, CONTENT_READ if method == "content_get" else method)
            if method not in OPERATOR or not self._in(self._break_glass, identity):   # break-glass can always unsuspend
                self._check_suspended(identity)
            errs = rpc_schema.validate(REQUESTS[method], req)
            if errs:
                raise RPCError("invalid_request", "; ".join(errs))
            self.quotas.check_strings(req)
            return getattr(self, "_" + method)(identity, req)
        except RecursionError:   # nested close to the parser's limit, which checking, hashing or copying exceeds
            e = RPCError("invalid_request", "the request nests too deeply")
            self._refused(identity, e)
            raise e from None
        except rfc8785.CanonicalizationError:   # hashing a record on the writer (rolled back): the same, one level deeper
            e = RPCError("invalid_request", "the request can't be canonicalized (nested too deeply, or a number out of "
                                            "range)")
            self._refused(identity, e)
            raise e from None
        except RPCError as e:
            self._refused(identity, e)
            raise

    def _grant(self, identity, method):
        if self._is_agent(identity) and method not in AGENT_METHODS:   # whatever its groups or prefixes are granted
            raise RPCError("forbidden", f"{subject(identity)[:256]} is an agent approver: it is not authorized for "
                                        f"{method}")
        found = [g for k in keys(identity) if (g := lookup(self.authorize, k)) is not None]
        granted = {m for g in found for m in g}
        if not found and not self._is_agent(identity):   # unconfigured: a uid or the dev token (scoped by DevToken)
            granted = DEFAULT_GRANTS if identity.scheme == "uid" or subject(identity) == "token:dev" else ()
        if method not in granted:
            raise RPCError("forbidden", f"{subject(identity)[:256]} is not authorized for {method}")

    def _is_agent(self, identity):
        return subject(identity) in self._agents

    def _refused(self, identity, e):
        """Count refusal `e` for the metrics and the next refusal.summary."""
        self.metrics.refusals.inc(e.code)
        now, k = time.time(), (identity.scheme, identity.subject, e.code)
        with self._refusals_lock:
            first, _, n = self._refusals.get(k, (now, now, 0))
            self._refusals[k] = (first, now, n + 1)

    def _loop_error(self, loop):
        """Count and log an unexpected error of a background loop, which carries on with its next round."""
        self.metrics.loop_errors.inc(loop)
        logging.getLogger(__name__).exception("tracekit signer: the %s loop failed; retrying", loop)

    def _renewal(self):
        """Unix time to replace a certified record key: two thirds into its certificate's validity (None: no issuer)."""
        c = self.log.cert and self.log.cert["certificate"]["cert"]
        return c and c["not_after"] - (c["not_after"] - c["not_before"]) / 3

    def rotate_key(self):
        """A fresh record key, certified by the issuer, takes over from the current one (signer.epoch, key.retire)."""
        sign, cert = self.log.certify(self.log.log_id)
        self.log.write(lambda tx: self.log.epoch(tx, sign, cert))
        self._renew_at = self._renewal()
        if self.log.refuse_writes == EXPIRED:   # writes refused only for the expiry resume with the new key
            self.log.refuse_writes = None

    def _renew(self):
        """Replace the record key; while the issuer can't, the current key stays, until its certificate expires: then
        client writes are refused until a renewal succeeds (a key never signs past its certificate)."""
        try:
            self.rotate_key()
        except Exception:   # issuer or storage down
            self._renew_at = time.time() + RENEW_RETRY_S
            self._loop_error("record key renewal")
            c = self.log.cert and self.log.cert["certificate"]["cert"]
            if c and time.time() >= c["not_after"] and not self.log.refuse_writes:
                self.log.refuse_writes = EXPIRED

    def _tick_loop(self):
        flushed, vaulted = time.monotonic(), -math.inf   # retention: on the first tick, then every CONTENT_SWEEP_S
        while not self._stop.wait(TICK_S):
            if self._content_key and time.monotonic() - vaulted >= CONTENT_SWEEP_S:
                vaulted = time.monotonic()
                try:
                    self.expire_content()
                except Exception:   # storage down: the next sweep retries
                    self._loop_error("content retention")
            try:
                self.sweep()
            except RPCError:   # storage down: the next tick retries
                pass
            except Exception:
                self._loop_error("ticker")
            if self._renew_at and time.time() >= self._renew_at:
                self._renew()
            if time.monotonic() - flushed >= REFUSAL_WINDOW_S:
                flushed = time.monotonic()
                try:
                    self.flush_refusals()
                except Exception:
                    self._loop_error("ticker")

    def _checkpoint_loop(self):
        """A note after each nudge (a run.final nudges too), at most one per CHECKPOINT_MIN_S, and every CHECKPOINT_S."""
        while True:
            self._nudged.wait(CHECKPOINT_S)
            if self._stop.is_set():   # close() writes the last note
                return
            self._nudged.clear()
            try:
                self.checkpoint()
                if self.log.storage.tree.size - self._snapped >= SNAPSHOT_RECORDS:
                    self.snapshot()
            except (RPCError, StorageUnavailable, OSError):   # storage down: the next round retries
                pass
            except Exception:
                self._loop_error("checkpointer")
            self._stop.wait(CHECKPOINT_MIN_S)

    def snapshot(self):
        """Snapshot the store and the run state, so the next start replays only the records after it."""
        with self._checkpointing:   # no note is stored while the storage snapshots its note index
            size = self.log.storage.tree.size
            self.log.snapshot()
            self._snapped = size

    def _fsck_loop(self):
        while not self._stop.wait(self.fsck_every_s):
            try:
                self.check_store()
            except Exception:
                self._loop_error("fsck")

    def check_store(self):
        """Check the store as `tracekit signer fsck` does, up to the records and registry leaves written so far; new
        problems get one signed trace.tamper{edited} and refuse client writes until a restart."""
        def written(tx):
            t = self.log.storage.tail_state()
            return {"records.jsonl": t["tree_size"], "registry.jsonl": sum(n for n, _ in t["registry"].values())}
        problems = fsck(self.data_dir, self.log.write(written), self.storage_config, record_key=self.record_key)
        new = [p for p in problems if p not in self._fsck_seen]
        if new:   # acknowledge_rollback covers the rollback found at start, never a later finding
            self._fsck_seen.update(new)
            self._tamper("edited", new[0].split(": ")[0][:256], {}, {}, False,
                         f"the background fsck found {len(new)} new problem(s), first: {new[0][:512]}")
        return problems

    def checkpoint(self):
        """Sign and store a note of the record tree when it grew since the latest stored one, then one of each
        tenant's registry tree that grew (its leaves point to records the record note covers). A log key that fails to
        sign leaves the rest unsigned until the next call. Returns whether every tree that grew got its note."""
        def heads(tx):
            s = self.log.storage
            return [(RECORDS, self.origin, s.tree.size, s.tree.root())] + [
                (registry_tree(t), registry.origin(self.origin, self.log.tenant_salt(t)), m.size, m.root())
                for t in sorted(self.log.tenants) if (m := s.registry_merkle(t))]
        with self._checkpointing:   # the checkpointer thread, close_log and close may all call this
            for tree, origin, size, root in self.log.write(heads):
                latest = self.log.storage.checkpoint_latest(tree)
                if size and (latest is None or size > latest[0]):
                    text = checkpoint.body(origin, size, root)
                    try:
                        note = self._note(text, origin)
                    except logkey.KeyUnavailable as e:
                        self._key_failed(e)
                        return False
                    self.log.storage.checkpoint_put(size, note, tree)
                    if tree == RECORDS:
                        self.metrics.checkpoints.inc()
                        self._noted = time.monotonic()
            self._key_down = None
        for wake in self._wake.values():
            wake.set()
        return True

    @property
    def _slh_public(self):
        return checkpoint.SLH_DSA + slh_dsa.public(self._slh)

    def _note(self, text, origin):
        data = text.encode("utf-8")
        note = text + "\n" + checkpoint.log_line(origin, self._log_key.public, self._log_key.sign(data))
        if self._slh:   # lean: pure-Python SLH-DSA, about 1 s per note and tree, one at a time; sign the trees in a
            # process pool (or a native FIPS 205 library) once many tenants' registries grow every round
            note += checkpoint.log_line(origin, self._slh_public, slh_dsa.sign(self._slh, data), checkpoint.HYBRID)
        return note

    def _key_failed(self, e):
        """Count a failed signature of the log key; an outage of LOG_KEY_GAP_S gets one signed degraded_unanchored gap
        (the records since the latest note are in no note)."""
        self.metrics.log_key_failures.inc()
        now = time.time()
        since, gapped = self._key_down or (now, False)
        if not gapped and now - since >= LOG_KEY_GAP_S:
            self.log.write(lambda tx: tx.gap("degraded_unanchored", f"the log key has signed no note since "
                                                                    f"{_iso(since)}: {e}"))
            gapped = True
        self._key_down = since, gapped

    # --- witness publishing ---

    def _publish_loop(self, w):
        wake = self._wake[w.name]
        while True:
            wake.wait(TICK_S)
            if self._stop.is_set():
                return
            wake.clear()
            try:
                trees = self.log.write(lambda tx: [(RECORDS, self.log.storage.tree)] + [
                    (registry_tree(t), self.log.storage.registry_merkle(t)) for t in sorted(self.log.tenants)])
                for tree, merkle_tree in trees[:1] if w in self.anchors else trees:   # anchors: the record tree only
                    self._publish(w, tree, merkle_tree)
            except (RPCError, StorageUnavailable, OSError):   # storage down: the next round retries
                pass
            except Exception:
                self._loop_error("publisher")

    def _check_skew(self, w, ts):
        now = time.time()
        if abs(ts - now) <= self.clock_skew_s:
            self._skewed.discard(w.name)
        elif w.name not in self._skewed:   # one gap per episode, however many notes it spans
            self.log.write(lambda tx: tx.gap("clock_skew", f"witness {w.name} cosigned at {_iso(ts)}, "
                                                           f"{abs(ts - now):.0f} s from the signer's clock ({_iso(now)})"))
            self._skewed.add(w.name)

    def _publish(self, w, tree, merkle_tree):
        latest = self.log.storage.checkpoint_latest(tree)
        with self._queue_lock:
            st = self._queue.setdefault(w.name, {}).setdefault(tree, {"size": 0, "attempts": 0, "next": 0,
                                                                      "since": None, "gapped": False})
            if latest is None or latest[0] <= st["size"] or time.time() < st["next"]:
                return
            old = st["size"]
        size, note = latest
        origin = note.split("\n", 1)[0]
        log_vkey = checkpoint.vkey(origin, checkpoint.ED25519, self._log_key.public)
        try:
            lines = w.add_checkpoint(note, log_vkey, old,
                                     lambda n: self.log.write(lambda tx: merkle_tree.consistency_proof(n, size)))
        except (RPCError, StorageUnavailable):   # storage down: the publish loop retries
            raise
        except Exception as e:   # any other failure is the witness's, and not worth a quick retry
            if not isinstance(e, WitnessError):
                e = WitnessError(f"{w.name}: {type(e).__name__}: {e}", False)
            self.metrics.witness_failures.inc(w.name)
            with self._queue_lock:
                st["attempts"] += 1
                st["since"] = st["since"] or time.time()
                st["next"] = time.time() + (w.every_s if getattr(e, "written", False)   # an anchor Rekor may hold
                                            else BACKOFF_S[1] if not e.retryable
                                            else min(BACKOFF_S[1], BACKOFF_S[0] * 2 ** (st["attempts"] - 1)))
                gap = not st["gapped"] and time.time() - st["since"] >= WITNESS_GAP_S
                reason = f"witness {w.name} has not cosigned {origin} since {_iso(st['since'])}: {str(e)[:512]}"
                self.log.storage.witness_queue_put(self._queue)
            if gap:
                self.log.write(lambda tx: tx.gap("witness_failed", reason))
                with self._queue_lock:
                    st["gapped"] = True
                    self.log.storage.witness_queue_put(self._queue)
            return
        with self._checkpointing:   # merged into the stored note unless a newer note replaced it meanwhile
            stored = self.log.storage.checkpoint_latest(tree)
            if w in self.anchors:   # the stored copy, with the cosignatures merged since
                self._anchor = size, {"note": stored[1] if stored and stored[0] == size else note, **lines}
                self.log.storage.anchor_put(*self._anchor)
            else:
                if stored and stored[0] == size and not signed_by(stored[1].split("\n\n", 1)[1], w.vkey):
                    self.log.storage.checkpoint_put(size, stored[1] + lines, tree)
                a = self._anchor   # and into the anchored copy, which exports use once a newer note replaces it
                if tree == RECORDS and a and a[0] == size and not signed_by(a[1]["note"].split("\n\n", 1)[1], w.vkey):
                    self._anchor = size, dict(a[1], note=a[1]["note"] + lines)
                    self.log.storage.anchor_put(*self._anchor)
        with self._queue_lock:
            st.update(size=size, attempts=0, next=time.time() + getattr(w, "every_s", 0), since=None, gapped=False)
            self.log.storage.witness_queue_put(self._queue)
        if w not in self.anchors:   # a Rekor anchor's time is its TSA's, checked by the verifier
            self._check_skew(w, checkpoint.open_note(log_signed(note, log_vkey) + lines, [log_vkey], [w.vkey])[3][0][1])
        self._wake[w.name].set()   # a newer note may be waiting

    def _lag(self, publishers):
        latest = self.log.storage.checkpoint_latest()
        with self._queue_lock:
            return {w.name: max(0, (latest[0] if latest else 0) - self._queue.get(w.name, {}).get(RECORDS, {}).get(
                "size", 0)) for w in publishers}

    def logs_list(self):
        """This signer's logs (the record log and each tenant's registry log) in the witness network's `logs/v0`
        format, for a witness to register them from."""
        tenants = sorted(self.log.tenants)   # a set of str: copied under the GIL, no writer needed
        public = self._log_key.public
        out = ["logs/v0", ""]
        for origin in [self.origin] + [registry.origin(self.origin, self.log.tenant_salt(t)) for t in tenants]:
            out += [f"vkey {checkpoint.vkey(origin, checkpoint.ED25519, public)}",
                    f"qpd {int(86400 / CHECKPOINT_MIN_S)}", f"contact {self.contact}", ""]
        return "".join(line + "\n" for line in out)

    def tlog(self, path, records=False):
        """The bytes at `path` of the logs' read-only C2SP tlog-tiles API, or None: the record log at /, each tenant's
        registry log at /registry/<id>/ (its origin's suffix), each with `checkpoint` (the latest note), hash tiles
        `tile/<L>/<N>[.p/<W>]` and entry bundles `tile/entries/<N>[.p/<W>]`; and /anchors, the stored Rekor anchors
        as JSON lines. A registry bundle is C2SP's (uint16 length ‖ leaf, per leaf); a record log bundle is JSON lines,
        one record per line, as a record can be longer than a uint16 length. The record log's entry bundles (every
        tenant's records: run ids, tool names, commitments) only with `records` (metrics.serve_records: true); its
        checkpoint and hash tiles, and the registry logs (salted leaves), always."""
        if path == "/anchors":
            return "".join(json.dumps(a) + "\n" for a in self.log.storage.anchors()).encode("utf-8")
        m = TLOG_PATH.fullmatch(path)
        if not m:
            return None
        reg, note, kind, index, width = m.groups()
        tenant = reg and next((t for t in sorted(self.log.tenants)
                               if registry.origin(self.origin, self.log.tenant_salt(t)).endswith("/" + reg)), None)
        if reg and tenant is None:
            return None
        if note:
            latest = self.log.storage.checkpoint_latest(RECORDS if tenant is None else registry_tree(tenant))
            return latest and latest[1].encode("utf-8")
        n, w = int(index.replace("x", "").replace("/", "")), int(width or 256)

        def read(tx):   # lean: on the writer thread, which owns the trees' edges; read tiles off it if monitors poll often
            s = self.log.storage
            tree, lo = s.tree if tenant is None else s.registry_merkle(tenant), n * 256
            level = 0 if kind == "entries" else int(kind)
            count = tree.size >> (8 * level)
            if count < lo + w:
                return None
            if kind == "entries" and tenant is None:
                if not records:
                    return None
                return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in s.iter_range(lo, lo + w)).encode()
            if kind == "entries":
                return b"".join(len(x).to_bytes(2, "big") + x for x in itertools.islice(s.registry_iter(tenant, lo), w))
            return (b"".join(tree.edge[level]) if n == count // 256 else tree.store.get(level, n, 256))[:32 * w]
        return self.log.write(read)

    def close_log(self, wait_s=0):
        """Close the log for good: a signed log.closed{final_seq: its own seq} (a leaf in every tenant's registry),
        then the final notes. Every later write is refused, after a restart too. Waits up to `wait_s` for every witness
        to cosign the final notes; returns whether they all did. A run still open gets a log_closed gap and ends
        first."""
        def fn(tx):
            expired, mine = [], self._approvals_by_run()
            for key in list(self.log.live):
                run = self.log.runs[key]
                tx.emit(run, "capture.gap", {"kind": "log_closed", "reason": "the log was closed while the run was "
                                                                             "open"}, source="signer")
                if not run["closed"]:
                    tx.closing(run, "close_run", source="signer")
                expired += self._finish_run(tx, key, run, mine.get(key, ()))
            tx.emit(self.log.signer_run(tx), "log.closed", {"final_seq": self.log.head["seq"]}, source="signer")
            return expired
        for aid in self.log.write(fn):
            self._drop_args(aid)
        if not self.checkpoint():
            raise RPCError("unavailable", "the log is closed but the log key signed no final note: start the signer once "
                                          "the log key is reachable, and it writes the note")
        deadline = time.monotonic() + wait_s
        while not self._cosigned():
            if time.monotonic() >= deadline:
                return False
            time.sleep(TICK_S / 10)
        return True

    def _cosigned(self):
        """Whether every witness has cosigned the latest note of every tree."""
        trees = [RECORDS] + [registry_tree(t) for t in sorted(self.log.tenants)]
        sizes = {tree: (self.log.storage.checkpoint_latest(tree) or (0,))[0] for tree in trees}
        with self._queue_lock:
            return all(self._queue.get(w.name, {}).get(tree, {}).get("size", 0) >= size
                       for w in self.witnesses for tree, size in sizes.items())

    def _approvals_by_run(self):
        """run key -> the ids of its approvals (on the writer)."""
        # lean: visits every approval on each tick; keep deadline heaps once a signer holds ~100k of them
        mine = {}
        for aid, a in self.log.approvals.items():
            mine.setdefault(a["run_key"], []).append(aid)
        return mine

    def _expire(self, tx, run, aid, reason="ttl"):
        """approval.expired; with why (`reason`) on an approval agents may answer or for a hold or quarantine, so a
        person-only one that expired otherwise stays readable by a 1.1 verifier."""
        a = self.log.approvals[aid]
        tx.set(a, "state", "expired")
        tx.emit(run, "approval.expired", {"approval_id": aid, **({"reason": reason} if a.get("agent") or reason in (
            "hold", "quarantine") else {})}, source="signer")
        return aid

    def _held_open(self, key, run):
        """The calls of `run` a gateway decided and may be running (_open_calls)."""
        return [c for c in self._open_calls(key, run) if c.get("via")]

    def _finish_run(self, tx, key, run, aids, now=None):
        """run.final for closing `run`, whose approvals are `aids`, after a gap for each call a gateway holds that has
        no result, one for each other call decided to run that never completed and one for each observer that went
        silent (`now`: a monotonic time); returns the ids of the approvals that expired with it."""
        consumed = {(a["tool_call_id"], a["attempt"]): a["decision_id"] for a in map(self.log.approvals.get, aids)
                    if a["state"] == "consumed"}
        held = self._held_open(key, run)
        for c in held[:DECIDED_GAPS_MAX]:
            tx.emit(run, "capture.gap", {
                "kind": "held_call_unresolved", "tool_use_id": c["tool_call_id"],
                "reason": f"{c['via'][:256]} decided {c['tool_call_id'][:128]} for {str(c.get('caller'))[:256]} and "
                          "recorded no result before the run ended: it may have run"},
                    source="signer", tool_call_id=c["tool_call_id"], attempt=c["attempt"])
        if len(held) > DECIDED_GAPS_MAX:
            n = len(held) - DECIDED_GAPS_MAX
            tx.emit(run, "capture.gap", {"kind": "held_call_unresolved", "missed_events": n,
                                         "reason": f"{n} more calls a gateway decided recorded no result before the "
                                                   f"run ended (the first {DECIDED_GAPS_MAX} have a gap each): they "
                                                   "may have run"}, source="signer")
        expired = [self._expire(tx, run, aid, "run_final") for aid in aids   # nothing consumes them once it is final
                   if self.log.approvals[aid]["state"] in LIVE]

        def superseded(did, c):   # a later decision of the same call completed
            # lean: only the call's latest decision counts as later, so an open decision before a completed one and
            # an open one after it is a gap too; keep each call's completed decisions if calls are decided that often
            last = (run["calls"].get(c["tool_call_id"]) or {}).get("decision_id")
            return last != did and last not in run["decisions"]
        # each open decision that let its call run (allowed, or its call's approval consumed) with no `complete`; the
        # decision a consumed approval names always counts. A call a gateway holds had its held_call_unresolved above
        open_calls = [c for did, c in run["decisions"].items() if c and not c.get("via") and (
            consumed.get((c["tool_call_id"], c["attempt"])) == did
            or (c["decision"] in ("allow", "flag") or (c["tool_call_id"], c["attempt"]) in consumed)
            and not superseded(did, c))]
        for c in open_calls[:DECIDED_GAPS_MAX]:
            tcid = c["tool_call_id"]
            tx.emit(run, "capture.gap", {
                "kind": "decided_not_completed", "tool_use_id": tcid,
                "reason": f"{tcid} ({str(c.get('tool') or '?')[:200]}) was "
                          f"{'approved' if c['decision'] == 'ask' else 'allowed'} and never completed: no result "
                          "reached the signer (the agent stopped or was interrupted, its post-call hook did not run, "
                          "or a client dropped the result); read the harness's transcript or the app's log for "
                          "whether it ran, and run `tracekit doctor` to check the hooks"},
                    source="signer", tool_call_id=tcid, attempt=c["attempt"])
        if len(open_calls) > DECIDED_GAPS_MAX:
            n = len(open_calls) - DECIDED_GAPS_MAX
            tx.emit(run, "capture.gap", {"kind": "decided_not_completed", "missed_events": n,
                                         "reason": f"{n} more allowed or approved calls never completed (the first "
                                                   f"{DECIDED_GAPS_MAX} have a gap each): read the run's decisions "
                                                   "with no tool.result next to the harness's transcript or the "
                                                   "app's log for whether they ran"},
                    source="signer")
        observed, sensors = False, set()   # an egress observer, the kernel sensors, covering the run throughout
        for obs, at in self._covering(key).items():
            if (time.monotonic() if now is None else now) - at >= TAILER_LOST_S:
                self._observer_lost(tx, run, obs, at, now)
            elif self._observers.get((key[0], obs), (0, None, None))[2] is None:
                observed = True
            elif self._observers[(key[0], obs)][2] != "openshell" and self._sensed.get((*key, obs)):
                sensors.add(self._observers[(key[0], obs)][2])   # OpenShell reports the sandbox's entrypoint only
        coverage = reconcile.finish(tx, run, self.gateway_mandatory, self.policy.is_handoff,
                                    self.policy.is_structured_output)
        provider = len(reconcile.counted(run["rec"], self.gateway_mandatory, "provider")) if run.get("rec") else 0
        paired = coverage and coverage.pop("paired_by_args", 0)
        tx.set(run, "final", True)
        tx.emit(run, "run.final", {"head_run_seq": run["run_seq"] - 1, "head_hash": run["head"],
                                   **({"coverage": coverage,
                                       "matrix": reconcile.matrix(run["rec"], self.posture or {}, observed,
                                                                  sorted(sensors))}
                                      if coverage else {}),
                                   **({"provider_executed": provider} if provider else {}),
                                   **({"paired_by_args": paired} if paired else {})}, source="signer")
        tx.set(self.log.runs, key, final_run(run))   # its calls, decisions and arguments go
        tx.pop(self.log.live, key)
        for aid in aids:   # all ended now: nothing can use them
            a = self.log.approvals[aid]
            tx.pop(self.log.approval_index, (*key, a["tool_call_id"], a["attempt"]))
            tx.pop(self.log.approvals, aid)
        return expired

    def sweep(self, now=None, wall=None):
        """Close idle runs, write run.final for runs whose grace window has passed, expire approvals and write the
        tailer_lost gap of runs whose tailer stopped its heartbeats. `now`: a monotonic time; `wall`: a time.time()
        for approval expiry."""
        finals, lost = [], []

        def fn(tx):
            t = time.monotonic() if now is None else now
            paused = max(0.0, t - self._swept)
            self._swept = max(self._swept, t)
            w = time.time() if wall is None else wall
            expired, mine, deadline = [], self._approvals_by_run(), _iso(w)
            for aid, u in list(self.log.agent["uses"].items()):   # past every budget's window
                if max(u["requested"], u["approved"] or 0) < w - policy_compile.MAX_WINDOW_S:
                    tx.pop(self.log.agent["uses"], aid)
            with self._beats_lock:
                beats = dict(self._beats)
            watched = {}   # run key -> {observer: its last heartbeat}
            for k, at in beats.items():
                if len(k) == 3:
                    watched.setdefault(k[:2], {})[k[2]] = at
            for key in list(self.log.live):
                run, live = self.log.runs[key], [aid for aid in mine.get(key, ())
                                                 if self.log.approvals[aid]["state"] in LIVE]
                waited = t - run["closing_at"] if run["closed"] else -1
                # a call a gateway holds may still complete: wait for it up to gateway_wait_s past the grace window;
                # an observer's last reports, up to observe_grace_s
                if waited >= self.grace_s and (waited >= self.grace_s + self.gateway_wait_s
                                               or not self._held_open(key, run)) and (
                        waited >= self.observe_grace_s or key not in watched):
                    expired += self._finish_run(tx, key, run, mine.get(key, ()), t)
                    finals.append(key)
                    continue
                for aid in live:
                    a = self.log.approvals[aid]
                    if a["expires_at"] <= deadline:
                        expired.append(self._expire(tx, run, aid))
                    elif a.get("consume_by", "~") <= deadline:
                        expired.append(self._expire(tx, run, aid, "consume_window"))
                    elif a["state"] == "requested" and (a.get("agent") or {}).get("eligible") and \
                            not a.get("escalated") and epoch(a["requested_at"]) + self.agent_timeout_s <= w:
                        tx.emit(run, "approval.escalated", {
                            "approval_id": aid, "by": "signer",
                            "reason": f"no agent answered within {self.agent_timeout_s} s (agent_timeout_s)"},
                                source="signer", tool_call_id=a["tool_call_id"])
                if run["closed"]:
                    continue
                if key in beats and t - beats[key] >= TAILER_LOST_S:
                    tx.emit(run, "capture.gap", {"kind": "tailer_lost", "reason": f"no tailer_heartbeat for "
                            f"{t - beats[key]:.0f}s while the run was open: " + (
                                "the log follower stopped or was killed; what the log says after that is not "
                                "recorded: read the log itself for it, and restart `tracekit follow`"
                                if run["source"] == "import" else
                                "the transcript tailer stopped, was killed or never started; what the transcript says "
                                "after that is not recorded: read the transcript itself for it, and run `sudo tracekit "
                                "doctor` to check the tailer")}, source="signer")
                    lost.append(key)
                for obs, at in watched.get(key, {}).items():
                    if t - at >= TAILER_LOST_S:
                        self._observer_lost(tx, run, obs, at, t)
                        lost.append((*key, obs))
                if any(self.log.approvals[aid]["state"] == "requested" for aid in live):
                    tx.set(run, "active", run["active"] + paused)   # the idle clock pauses while an approval is pending
                elif t - run["active"] >= self.idle_s:
                    tx.closing(run, "idle_timeout", source="signer")
            return expired
        expired = self.log.write(fn)
        with self._beats_lock:   # a lost tailer's or observer's run expects no more heartbeats, a final run none at all
            done = set(finals)
            for k in [k for k in self._beats if k in lost or k[:2] in done]:
                self._beats.pop(k)
            for k in [k for k in self._sensed if k[:2] in done]:
                self._sensed.pop(k)
        if finals:
            self._nudged.set()
        for key in finals if self._exporter else ():
            self._exporter.put(key)
        for aid in expired:
            self._drop_args(aid)
        if expired:
            with self._cond:
                self._cond.notify_all()

    def flush_refusals(self):
        """Write the refusals counted since the last flush as `refusal.summary` records, one per identity and code."""
        with self._refusals_lock:
            counted, self._refusals = self._refusals, {}
        if not counted and not self.log.late:
            return

        def write(tx):
            run = self.log.signer_run(tx)
            for (scheme, subj, code), (first, last, n) in counted.items():
                tx.emit(run, "refusal.summary", {"code": code, "count": n, "from_ts": _iso(first), "to_ts": _iso(last),
                                                 "identity": f"{scheme}:{subj}"[:256]}, source="signer")
            late = self.log.late
            tx.set(vars(self.log), "late", {})   # the writer's counts since the last flush (kept if this write fails)
            for (tenant, run_id), (first, last, by) in late.items():
                n = sum(by.values())
                tx.emit(self.log.signer_run(tx, tenant), "capture.gap", {
                    "kind": "late_activity", "run_id": run_id, "missed_events": n, "from_ts": _iso(first),
                    "to_ts": _iso(last), "reason": f"{n} write(s) to run {run_id} came after its run.final and were "
                    "refused, so the run does not hold them (" + ", ".join(f"{m} {k}" for m, k in sorted(by.items()))
                    + "; a client's first one, from which it learns that the run ended, is not counted): if this "
                    "recurs, check that each client registers a new run once its run ends"}, source="signer")
        try:
            self.log.write(write)
        except RPCError:   # storage down: keep the counts for the next flush
            with self._refusals_lock:
                for k, (first, last, n) in counted.items():
                    f2, l2, n2 = self._refusals.get(k, (first, last, 0))
                    self._refusals[k] = (min(first, f2), max(last, l2), n + n2)

    def close(self):
        if self._stop.is_set():
            return
        self._stop.set()
        self._nudged.set()
        for wake in self._wake.values():
            wake.set()
        self._ticker.join()
        if self._exporter:
            self._exporter.close()
        self._checkpointer.join()
        if self.fsck_every_s:
            self._fsck.join()
        for t in self._publishers:
            t.join()
        self.flush_refusals()
        try:
            self.checkpoint()
            self.snapshot()
        except (RPCError, StorageUnavailable, OSError):   # storage down: the next start's notes cover these records
            pass
        self.log.close()
        for w in self._webhooks:
            w.close()

    # --- helpers ---

    def _authorize(self, identity, req, gw=None):
        """The (tenant, run_id) of a per-run call, after checking its capability token. `gw`: the gateway making the
        call for `identity` (_as_caller), which its own authentication vouches for, so no harness process binds it."""
        tenant = self.tokens.claims(req["run_token"])["tenant"]
        key = (tenant, req["run_id"])
        if key not in self.log.runs:
            raise RPCError("unknown_run", req["run_id"])
        self.tokens.verify(req["run_token"], tenant, req["run_id"], identity)
        if gw is None:
            self._check_harness(identity, key)
            if key in self._beats and self._tailer(identity):   # any call of a watched run's tailer shows it alive
                with self._beats_lock:   # checked again here: a sweep that made the run final has dropped its beat
                    if key in self._beats and not self.log.runs[key]["final"]:
                        self._beats[key] = time.monotonic()
        return key

    def _covering(self, key):
        """{observer: its last heartbeat} of the egress observers covering run `key`."""
        # lean: scans the beat map; key it by run if a signer watches ~100k runs at once
        with self._beats_lock:
            return {k[2]: at for k, at in self._beats.items() if len(k) == 3 and k[:2] == key}

    def _observer_lost(self, tx, run, obs, at=None, now=None, lost=None):
        """An observer_lost gap in `run`: observer `obs` silent since `at` (monotonic) until `now`, restarted, or (a
        kernel sensor's import) reporting `lost` events."""
        t = time.monotonic() if now is None else now
        sensor = self._observers.get((run["tenant"], obs), (0, None, None))[2]
        if sensor:
            name = f"the {sensor} import {obs[:256]}"
            what, check = (("OpenShell's events of the sandbox", "Check OpenShell's OCSF export "
                            "([openshell.gateway.otlp.ocsf]), `tracekit openshell-middleware`") if sensor == "openshell"
                           else ("the run's processes, connections and file writes", "Its coverage says processes not "
                                 "observed. Check `tracekit sensor import`, the sensor"))
            why = (f"{name} reported lost events: {privacy.redact_text(lost)[0]}" if lost else
                   f"{name} restarted while the run was open: events its old process had not sent are not in the run"
                   if at is None else f"no observe_effect from {name} for {t - at:.0f}s while the run was open: it "
                   f"stopped or was killed, so {what} from then on are not in the run")
            tx.emit(run, "capture.gap", {"kind": "observer_lost", "sensor": sensor, "reason": (
                f"{why}. {check} and that the import's identity has the observe_effect grant")[:1024]},
                source="signer")
            return
        why = (f"egress observer {obs[:256]} restarted while the run was open: what the old process had not reported "
               "when it ended (up to a minute and a heartbeat of traffic if it was killed, none if it was stopped with "
               "SIGTERM) is not in the run, so its coverage says network not observed; find why the egress proxy "
               "(`tracekit egress serve`) restarted") if at is None else (
            f"no observe_effect from egress observer {obs[:256]} for {t - at:.0f}s while the run was open: it stopped "
            "or was killed, so the run's network traffic from then on was not observed and its coverage says network "
            "not observed; check the egress proxy (`tracekit egress serve`) and that its identity has the "
            "observe_effect grant")
        tx.emit(run, "capture.gap", {"kind": "observer_lost", "reason": why}, source="signer")

    def _tailer(self, identity):
        """Whether `identity` is a transcript tailer's: granted tailer_heartbeat."""
        return any("tailer_heartbeat" in (lookup(self.authorize, k) or ()) for k in keys(identity))

    def _approval(self, key, approval_id):
        a = self.log.approvals.get(approval_id)
        if a is None or a["run_key"] != key:
            raise RPCError("unknown_approval", approval_id)
        return a

    @staticmethod
    def _in(table, identity):
        """Whether any of the identity's keys is in `table` (approvers, break_glass)."""
        return any(lookup(table, k, False) for k in keys(identity))

    def _may_see(self, identity, a):
        """Whether `identity` may see approval `a`: the run's owner, a break-glass identity, or an identity of the
        run's tenant (with a config, only an approver of it or a bridge granted ON_BEHALF); an agent approver, only the
        agent-eligible approvals of its tenant."""
        if self._is_agent(identity):
            return bool((a.get("agent") or {}).get("eligible")) and a["run_key"][0] == self._tenant_of(identity)
        if owner(identity) == self.log.runs[a["run_key"]]["owner"] or self._in(self._break_glass, identity):
            return True
        return (self.approvals is None or self._in(self._approvers, identity)
                or any(ON_BEHALF in (lookup(self.authorize, k) or ()) for k in keys(identity))) and \
            a["run_key"][0] == self._tenant_of(identity)

    def _self_approval(self, a, *approver):
        """Whether one of the `approver` identities is approval `a`'s requester, its run's owner or principal, directly
        or as the same person (`persons`)."""
        run = self.log.runs[a["run_key"]]
        theirs = {a["requester"], run["owner"], run.get("principal")}
        theirs |= {self._persons.get(x) for x in theirs}
        return bool(({*approver} | {self._persons.get(x) for x in approver}) & theirs - {None})

    def _visible(self, identity, approval_id):
        a = self.log.approvals.get(approval_id)
        if a is None or not self._may_see(identity, a):
            raise RPCError("unknown_approval", approval_id)
        return a

    def _summary(self, approval_id, a):
        return {"approval_id": approval_id, "state": a["state"], "run_id": a["run_key"][1],
                **{k: a[k] for k in ("tool_call_id", "attempt", "tool", "rule_ids", "policy_hash", "requester",
                                     "expires_at")}, **({"passkey": True} if a.get("passkey") else {}),
                **({"escalated": True} if a.get("escalated") else {}),
                **({"agent": True} if self._agent_mode(a) == "enforce" else {}),
                **{k: a[k] for k in ("answered", "escalation") if a.get(k)}}

    def _agent_refusal(self, a):
        """Why an agent's answer to approval `a` is refused now (people answer it), or None."""
        return ("agent approvals are switched off: people answer it" if self.log.agent["off"] else
                "it was escalated: people answer it now" if a["escalated"] else
                "the policy changed since it was requested: people answer it"
                if a["policy_hash"] != self.policy.policy_hash else
                "an agent or a person did not approve this call in this run: people answer it"
                if any(k in self.log.runs[a["run_key"]].get("person_only", {}) for k in person_only_keys(a)) else None)

    def _agent_mode(self, a):
        """How an agent's answer to approval `a` counts now: "enforce" (it decides), "shadow" (an approval.suggested;
        people decide) or None (only people answer it)."""
        if not (a.get("agent") or {}).get("eligible") or self._agent_refusal(a):
            return None
        return "shadow" if any(r["approval"]["agent"]["mode"] == "shadow"
                               for r in self._agent_rules(a["agent"]["rules"])) else "enforce"

    def _on_behalf(self, identity, req):
        """The person a bridge acts for (`on_behalf`, for an identity granted approval_decide_on_behalf), else `identity`.
        The person acts within the bridge's tenant; only a bridge in multi_tenant_apps (a viewer serving several
        tenants) may name the person's tenant."""
        p = req.get("on_behalf")
        if p is None:
            return identity
        self._grant(identity, ON_BEHALF)
        mine = self._tenant_of(identity)
        them = CallerIdentity("oidc", p["subject"], False, {"person": p["person"], "groups": p.get("groups", []),
                                                            "tenant": p.get("tenant", mine)})
        if self._is_agent(them):
            raise RPCError("forbidden", f"{subject(them)[:256]} is an agent approver: no bridge acts for it")
        if self._tenant_of(them) != mine and subject(identity) not in self.multi_tenant_apps:
            raise RPCError("forbidden", f"{subject(identity)[:256]} acts for people of tenant {mine[:64]!r} only")
        self._check_suspended(them)
        return them

    def _passkey(self, identity, aid, a, assertion):
        """The credential id of a passkey assertion that approves `a` for `identity`; RPCError forbidden otherwise."""
        who = person(identity)
        if assertion is None or not who or self._webauthn is None:
            raise RPCError("forbidden", "approving this call needs a passkey assertion")
        with self._passkeys_lock:
            cred = self._passkeys.get(who)
            if cred is None or cred["id"] != assertion["credential_id"]:
                raise RPCError("forbidden", "not the passkey registered for this person")
            try:
                count = webauthn.verify(
                    base64.b64decode(cred["key"]), cred["count"], self._webauthn["rp_id"], self._webauthn["origin"],
                    webauthn.challenge(aid, a["binding_digest"], "approve"),
                    *(webauthn.unb64url(assertion[k]) for k in ("client_data_json", "authenticator_data", "signature")))
            except ValueError as e:
                raise RPCError("forbidden", f"passkey refused: {e}") from None
            self._save_passkeys(dict(self._passkeys, **{who: dict(cred, count=count)}))
        return cred["id"]

    def _save_passkeys(self, passkeys):
        """Replace passkeys.json (under _passkeys_lock), then the in-memory copy."""
        files.write(self.data_dir, PASSKEYS, json.dumps(passkeys).encode("utf-8"))
        self._passkeys = passkeys

    def _seal(self, approval_id, value):
        nonce = os.urandom(12)
        return nonce + self._args_key.encrypt(nonce, canonical(value), approval_id.encode())

    def _unseal(self, approval_id):
        """The signer's copy of an approval's arguments ({"args_source", "args", "reason"?}), None once deleted."""
        try:
            with open(os.path.join(self._args_dir, approval_id), "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return None
        try:
            return loads_strict(self._args_key.decrypt(blob[:12], blob[12:], approval_id.encode()))
        except InvalidTag:
            raise RPCError("unavailable", f"the stored arguments of {approval_id} do not decrypt") from None

    def _drop_args(self, approval_id):
        try:
            os.unlink(os.path.join(self._args_dir, approval_id))
        except OSError:   # gone already, or left for the next start's cleanup
            pass

    @staticmethod
    def _args(req):
        """(the arguments, their digest sha256(JCS({tool, args}))), or (None, None) when they are not canonical JSON."""
        try:
            args = loads_strict(req["args"]) if req["args_source"] == "raw" else req["args"]
            return args, event_hash({"tool": req["tool"], "args": args})
        except (StrictJSONError, rfc8785.CanonicalizationError):
            return None, None

    def _commit(self, label, digest):
        """A published commitment: HMAC of `digest` under the salt of `label` (a record's salt_label), which the signer
        can reveal to an auditor for that one record."""
        return _commitment(_salt(self._salt_key, label), digest)

    def _same(self, call, digest):
        """Whether `digest` is the args digest the decision `call` was made for."""
        return self._opens(call["commitment"], call["decision_id"], digest)

    def _opens(self, commitment, label, digest):
        return bool(commitment and digest) and hmac.compare_digest(commitment, self._commit(label, digest))

    def _evaluate(self, tool, args, hint, untrusted=None):
        """(policy decision, hint disagreed, the rule ids of both readings). A class hint that disagrees with the
        policy's class gets the stricter of the two decisions; detection sees the rules of both, so a mismatch can't
        hide a step. A tool the policy maps whose own reading is at least as strict as the hint's (an MCP adapter's
        generic `mcp` against the deployment's `sql`) is no disagreement worth a gap. An error of the engine itself on
        these arguments (a bug they reach) is a deny, TK-ENGINE-ERROR (`error`: its type), logged with its traceback,
        never an exception that drops the connection and lets the call run unrecorded; a RecursionError is the
        request's nesting, which call() refuses."""
        try:
            d, cls = self.policy.decide(tool, args, untrusted=untrusted), self.policy.tool_class(tool)
            if tool.startswith("mcp:") and "/" in tool:
                # an MCP tool is also checked under its bare name (the name the model may know it by), in its own class
                # if the policy maps it, else the MCP call's: a rule on that name can't be dodged by naming the call an
                # MCP one
                bare = tool.split("/", 1)[1]
                b = self.policy.decide(bare, args, None if self.policy.tool_class(bare) != "unknown" else cls, untrusted)
                d = {**max(d, b, key=lambda x: STRICTNESS.index(x["verdict"])),
                     "rule_ids": list(dict.fromkeys(d["rule_ids"] + b["rule_ids"]))}
            if hint is None or hint == cls:
                return d, False, d["rule_ids"]
            h = self.policy.decide(tool, args, hint if hint in policy_compile.CLASSES else "unknown", untrusted)
            strict = max(d, h, key=lambda x: STRICTNESS.index(x["verdict"]))   # d on a tie
            return strict, cls == "unknown" or strict is not d, list(dict.fromkeys(d["rule_ids"] + h["rule_ids"]))
        except RecursionError:
            raise
        except Exception as e:
            # the type and frames only: an exception message can carry argument text, which the signer otherwise
            # keeps committed or encrypted; %r keeps an agent-supplied tool name on one log line
            logging.getLogger(__name__).error("tracekit policy: the engine failed (%s) on a %r call\n%s", type(e).__name__,
                                              tool[:256], "".join(traceback.format_tb(e.__traceback__)))
            d = {"verdict": "deny", "rule_ids": ["TK-ENGINE-ERROR"], "policy_hash": self.policy.policy_hash,
                 "engine": self.policy.engine, "error": type(e).__name__}
            return d, False, d["rule_ids"]

    def _reasons(self, ids):
        """The reasons of the rules among `ids` that give one, in their order, joined by "; ", then their remedies (what
        to do instead), each once (at most 1024 chars); an id the engine gives itself, its fixed ENGINE_REASONS."""
        by = {**policy_compile.ENGINE_REASONS, **{r["id"]: r for _, r, *_ in self.policy.rules}}
        rules = [by[i] for i in ids if i != "TK-UNKNOWN-TOOL" and i in by]
        why = "; ".join(r.get("reason") or r["label"] for r in rules if r.get("reason") or r.get("label"))
        return ". ".join(filter(None, [why, " ".join(dict.fromkeys(r["remedy"] for r in rules if "remedy" in r))]))[:1024]

    def _agent_rules(self, ids):
        """The rules among rule ids `ids` with approval.agent."""
        return [r for _, r, *_ in self.policy.rules if r["id"] in ids and "agent" in (r.get("approval") or {})]

    def _eligibility(self, key, identity, tool, args, digest, d, prov):
        """The `agent` of the approval.request of call `d` (an `ask`) of run `key`: {eligible, reason, rules,
        conditions_hash, args_key (the person-only set's key of these arguments), spend (memory only: what an approval
        takes from each sum budget)}; None when none of its rules has approval.agent. Eligible only when every rule
        it asked by (flags aside) has approval.agent and its bounds pass, the tool is one the policy names exactly,
        no argument carries a value only untrusted content brought and provenance is complete, the run is no replay,
        agent approvals are on and each budget has room. Off the writer; the writer checks the run's state again."""
        rules = self._agent_rules(d["rule_ids"]) if self._agents else []
        if not rules:
            return None
        ids, flags = {r["id"] for r in rules}, {r["id"] for sec, r, *_ in self.policy.rules if sec == "flag"}
        other = next((i for i in d["rule_ids"] if i not in ids | flags), None)
        reason = (f"{other} is answered by people" if other else
                  "agent approvals are switched off" if self.log.agent["off"] else
                  "the policy does not name this tool exactly" if tool not in self.policy.policy.get("tools", {}) else
                  "a replay or findings run is answered by people" if self.log.runs[key].get("replay") else
                  "the decision is nondeterministic" if d.get("nondeterministic") else
                  "an argument carries a value only untrusted content brought into the run, or provenance is not "
                  "complete" if prov else None)
        spend = {}
        if reason is None:
            try:
                deadline = time.monotonic() + engine.REGEX_TIMEOUT_S
                failed = [c for r in rules for c, ok in self.policy.bounds(r, args, deadline) if not ok]
            except TimeoutError:
                failed = ["a bound's pattern ran out of time"]
            reason = "outside the bounds: " + "; ".join(failed) if failed else None
        if reason is None:
            spend = self._spend(rules, args)
            short = self._short(self._budgets(key[0], subject(identity), rules, time.time()), spend)
            reason = f"the budget of rule {short} is used up" if short else None
        return {"eligible": reason is None, "reason": (reason or f"within the bounds of {', '.join(sorted(ids))}")[:1024],
                "rules": sorted(ids), "args_key": self._commit(f"person_only:{key[0]}:{key[1]}", digest),
                "conditions_hash": "sha256:" + hashlib.sha256(canonical([r["approval"]["agent"] for r in rules])).hexdigest(),
                "spend": spend}

    def _capped(self, key, run, tool, tcid, agent):
        """Why the signer's state (on the writer) makes an eligible call of run `key` a person's to answer, or None:
        an agent or a person said no to the same call in this run, the run's or the tenant's agent reviews are used up,
        or agent approvals were switched off since the decision."""
        if any(k in run.get("person_only", {}) for k in person_only_keys({"tool": tool, "tool_call_id": tcid,
                                                                          "agent": agent})):
            return "reask_after_reject: an agent or a person did not approve this call in this run; people answer it"
        if run.get("agent_reviews", 0) >= AGENT_REVIEWS_PER_RUN:
            return f"the run has had {AGENT_REVIEWS_PER_RUN} agent reviews; people answer the rest"
        since = time.time() - AGENT_REVIEWS_WINDOW_S
        if sum(u["tenant"] == key[0] and u["requested"] > since for u in self.log.agent["uses"].values()) >= \
                AGENT_REVIEWS_PER_TENANT:
            return f"the tenant has had {AGENT_REVIEWS_PER_TENANT} agent reviews this hour; people answer the rest"
        return "agent approvals are switched off" if self.log.agent["off"] else None

    def _budgets(self, tenant, requester, rules, now):
        """rule id -> {count?, sum?}: what each budget of `rules` has left at `now` for `requester` in `tenant`,
        counted from the agent approvals the records hold."""
        # lean: scans every agent approval of the last MAX_WINDOW_S per check; index them by tenant and rule if a
        # signer holds ~100k
        out, uses = {}, list(self.log.agent["uses"].values())
        for r in rules:
            b = r["approval"]["agent"].get("budget")
            if b is None:
                continue
            used = [u for u in uses if u["approved"] and r["id"] in u["rules"] and u["tenant"] == tenant
                    and (b["scope"] == "tenant" or u["requester"] == requester) and u["approved"] > now - b["window"]]
            out[r["id"]] = {**({"count": b["count"] - len(used)} if "count" in b else {}),
                            **({"sum": b["sum"]["max"] - sum(u["spent"].get(r["id"], 0) for u in used)}
                               if "sum" in b else {})}
        return out

    @staticmethod
    def _spend(rules, args):
        """rule id -> what approving `args` (within the rules' bounds) takes from each rule's sum budget."""
        out = {}
        for r in rules:
            s = r["approval"]["agent"].get("budget", {}).get("sum")
            if s:
                v = args[s["field"]]
                out[r["id"]] = sum(v) if isinstance(v, list) else v
        return out

    @staticmethod
    def _short(left, spend):
        """The first rule whose budget (`left`, from _budgets) can't take `spend`, or None."""
        return next((i for i, b in left.items() if b.get("count", 1) < 1 or b.get("sum", math.inf) < spend.get(i, 0)),
                    None)

    def _key(self, kind, v):
        return hmac.new(self._prov_key, f"{kind}\0{v}".encode("utf-8", "surrogatepass"), "sha256").digest()

    def _keys(self, obj, email_hosts=True, deadline=None):
        """([(kind, provenance index key)] of the values `obj` carries, overflow) (provenance.values)."""
        pairs, overflow = provenance.values(obj, email_hosts, deadline)
        return [(kind, self._key(kind, v)) for kind, v in pairs], overflow

    def _index(self, tx, run, keys, source):
        """Index `keys` (from _keys) as brought into `run` by `source` ({run_seq, trust, tool?, tool_call_id?}), on the
        writer. Trusted content wins over untrusted, whichever came first; past PROVENANCE_MAX entries the index is
        truncated and takes no new values."""
        prov = run.get("prov")
        if prov is None:
            return
        idx = prov["index"]
        for _, k in keys:
            had = idx.get(k)
            if had is None and len(idx) >= PROVENANCE_MAX:
                degrade(tx, prov, "truncated", f"the run's index holds {PROVENANCE_MAX} values")
            elif had is None or had["trust"] == "untrusted" and source["trust"] == "trusted":
                tx.set(idx, k, source)

    def _provenance(self, key, args, req):
        """(`untrusted(subject, field)` for the policy, a function giving the decision's provenance fields) of a call
        with `args` in run `key`, decided by event `req`. Whenever the index is not complete (partial, truncated,
        unavailable, partial by the events `req` itself skips, or reading the values took past the decision's deadline:
        timeout) `untrusted` fails closed: every subject is a hit."""
        prov = self.log.runs[key].get("prov")
        # lean: read off the writer, which may be adding to it: a decide racing a batch the storage then refuses may
        # see that batch's values for that moment; read on the writer if that ever matters
        idx = prov["index"] if prov else {}
        st = ({"state": prov["state"], "reason": prov.get("reason")} if prov else
              {"state": "unavailable", "reason": "the index lives in memory and was lost in a signer restart, so from: "
                                                 "untrusted rules hold every call they match for the rest of this run: "
                                                 "answer the holds, or start the task again in a new run"})
        gap = st["state"] == "complete" and skipped(self.log.runs[key], req)
        if gap:   # a gap this decide reveals: the writer degrades the index with it
            st = {"state": "partial", "reason": (gap + LOST)[:256]}
        deadline, entries = time.monotonic() + PROVENANCE_S, []

        def timeout():
            st.update(state="timeout", reason="reading the call's values took past the decision's deadline")

        def hits(obj):
            keys, overflow = self._keys(obj, False, deadline)
            return [(kind, s) for kind, k in keys if (s := idx.get(k)) and s["trust"] == "untrusted"], overflow
        try:
            # only an index with entries can name an argument (and the record needs every argument's values)
            for field, v in ((args if isinstance(args, dict) else {"value": args}) if idx else {}).items():
                for kind, s in hits(v)[0]:
                    e = {"field": field[:256], "kind": kind,
                         "source": {k: s[k] for k in ("run_seq", "tool", "tool_call_id") if s.get(k) is not None}}
                    if e not in entries:
                        entries.append(e)
        except TimeoutError:
            timeout()

        def untrusted(subject, field=None):
            if st["state"] != "complete":
                return [st["state"]]
            if not idx:
                return []
            if field == "sends_to":   # a canonical host (classes.url_info): looked up as one
                s = idx.get(self._key("host", provenance.host(subject)))
                return [("host", s)] if s and s["trust"] == "untrusted" else []
            try:
                found, overflow = hits(subject)
            except TimeoutError:
                timeout()
                return ["timeout"]
            return found or (["overflow"] if overflow else [])

        def fields():
            # only when there is something to say, so a run with nothing untrusted in its arguments stays readable by
            # a 1.0 verifier (bundle_v2: these fields make a bundle need 1.1)
            if not entries and st["state"] == "complete":
                return {}
            out = {"provenance_state": st["state"]}
            if st["state"] != "complete":
                out["provenance_reason"] = st["reason"]
            if entries:
                out["provenance"] = entries[:PROVENANCE_SHOWN]
            return out
        return untrusted, fields

    def _chain(self, identity):
        """The caller's process chain (harness_helper.chain), [] when it can't be had. Cached per process instance:
        a pid with another start time is another process."""
        pid = identity.claims.get("pid") if identity.scheme == "uid" else None
        if not pid:
            return []
        st = harness_helper.start_time(pid)
        with self._chains_lock:
            hit = self._chains.get(pid)
        if hit and st is not None and hit[0] == st:
            return hit[1]
        try:
            procs = harness_helper.ask(self._helper, pid) if self._helper else harness_helper.chain(pid)
        except (OSError, ValueError):
            return []
        if procs and procs[0].get("start_time") == st:
            with self._chains_lock:
                if len(self._chains) >= 4096:   # lean: drops the whole cache when full; an LRU if hosts churn pids
                    self._chains.clear()
                self._chains[pid] = (st, procs)
        return procs

    def _check_harness(self, identity, key):
        """A call on a run bound to a harness process, from the run's owner, must come from below that process."""
        run = self.log.runs[key]
        bound = run.get("harness")
        if bound and owner(identity) == run["owner"] and tuple(bound) not in {
                (p["pid"], p.get("start_time")) for p in self._chain(identity)[1:]}:
            raise RPCError("forbidden", "not from the run's harness process")

    def _tenant_of(self, identity):
        """The identity's tenant: `tenants`, else the tenant its named token was issued for (or its OIDC issuer's
        tenant claim), else the default."""
        token = identity.claims.get("tenant") if identity.scheme in ("token", "oidc") else None
        return next((t for k in keys(identity) if (t := lookup(self.tenants, k))), None) or token or self.tenant

    def _certified(self, tenant):
        """RPCError forbidden for a tenant the record key's certificate does not cover: its records would not verify."""
        if self.log.cert and tenant not in self.log.cert["certificate"]["cert"]["tenants"]:
            raise RPCError("forbidden", f"tenant {tenant[:64]!r} is not among the record key's certified tenants")

    @staticmethod
    def _isolation(identity):
        if identity.scheme == "uid" and hasattr(os, "getuid"):
            return "same-user" if identity.subject == str(os.getuid()) else "separate-user"
        # k8s_sa, mtls and tokens other than the dev transport's authenticate over the HTTP transport only
        if identity.scheme in ("k8s_sa", "mtls", "oidc", "token") and subject(identity) != "token:dev":
            return "remote"
        return "unknown"

    # --- containment (docs/incidents.md) ---

    def _scope_keys(self, tenant, scope):
        """The live runs of `tenant` an incident's scope reaches, keyed as detect.Detector._scope keys them."""
        kind, val = scope["kind"], scope["id"]

        def of(r):
            return (r["run_id"] if kind == "run" else r.get("session", r["run_id"]) if kind == "session" else
                    r["owner"] if kind == "owner" else r["people"][1]) or ""
        return [k for k in self.log.live if k[0] == tenant and of(self.log.runs[k])[:256] == val]

    def _open_calls(self, key, run):
        """The calls of `run` (`key`) that may be running: allowed, or approved and consumed, and not completed."""
        def consumed(c):   # this decision's own approval: a retry decided again after a consume never ran
            a = self.log.approvals.get(self.log.approval_index.get((*key, c["tool_call_id"], c["attempt"])), {})
            return a.get("state") == "consumed" and a.get("decision_id") == c["decision_id"]
        return [c for c in run["decisions"].values() if c and (c["decision"] in ("allow", "flag") or consumed(c))]

    def _in_flight(self, key, run, skip=None):
        """A response's `in_flight`: the open calls of `run` but decision `skip`."""
        return [{"run_id": key[1], "tool_call_id": c["tool_call_id"], "decision_id": c["decision_id"]}
                for c in self._open_calls(key, run) if c["decision_id"] != skip][:1024]

    def _contain(self, tx, run, kind, iid, scope, by, reason, flight=(), cooldown=0, inherited=False):
        """Hold (`kind` held) or quarantine (quarantined) `run` for incident `iid`, `scope` its scope: its live
        approvals expire and a run.held or run.quarantined records it, with until when new runs of its owner and
        principal inherit it (`cooldown` seconds). A quarantined run stays as it is; a held one is held by `iid` too."""
        if run.get("quarantined") or iid in (run.get("held") or ()):
            return
        key = (run["tenant"], run["run_id"])
        # lean: visits every approval; index them by run (as sweep's _approvals_by_run) if holds become frequent
        for aid, a in list(self.log.approvals.items()):
            if a["run_key"] == key and a["state"] in LIVE:
                self._expire(tx, run, aid, "hold" if kind == "held" else "quarantine")
        until = cooldown and not inherited and _iso(time.time() + cooldown)
        tx.emit(run, "run.held" if kind == "held" else "run.quarantined", {
            "incident_id": iid, "scope": scope, "by": by[:256], "reason": reason[:1024],
            **({"in_flight": flight} if flight else {}), **({"inherited": True} if inherited else {}),
            **({"inherit_until": until} if until else {})}, source="signer")

    def _respond(self, tx, run, e, inc):
        """RecordLog.respond: on the writer, in the item of record `e` of `run`, write the enforced incident `inc` with
        what it does; with `inc` None (decision `e` says its detection state is unavailable) hold `run` under a
        detector_unavailable incident when the policy enforces holds (fail closed). A hold or quarantine reaches every
        live run of the incident's scope."""
        tenant = run["tenant"]
        if inc is None:
            if not self._fail_closed or run.get("held") or run.get("quarantined"):
                return
            inc, rule = {"incident_id": "inc-" + secrets.token_hex(16), "trigger": "detector_unavailable",
                         "rule_ids": [], "scope": {"kind": "run", "id": run["run_id"][:256]},
                         "cites": [{"run_id": e["run_id"], "run_seq": e["run_seq"]}], "mode": "enforce", "actions": [],
                         "would": ["hold"]}, {"action": "hold"}
        else:
            rule = self.log.detector.respond[inc["rule_ids"][0] if inc["trigger"] in ("sequence", "limit")
                                             else inc["trigger"]]
        action, why = rule["action"], None
        if self.log.contain["paused"].get(tenant):
            action, why = None, "the response engine is paused (response_pause): detection records, nothing acts"
        elif action == "hold" and not self._people:
            action, why = "quarantine", ("no person approver is configured (approvals.approvers): a hold no one may "
                                         "answer is a quarantine")
        keys = self._scope_keys(tenant, inc["scope"]) if action in ("hold", "quarantine") else []
        skip = e["data"].get("decision_id") if e["type"] == "policy.decision" else None   # held by _decide itself
        flight = {k: self._in_flight(k, self.log.runs[k], skip) for k in keys}
        actions = [action] if action else []
        every = [c for k in keys for c in flight[k]][:1024]
        iid = inc["incident_id"]
        tx.emit(run, "incident.opened", {**inc, "actions": actions, **({"reason": why[:1024]} if why else {}),
                                         **({"in_flight": every} if every else {})}, source="signer")
        text = f"incident {iid}: {inc['trigger']} {' '.join(inc['rule_ids'])}".strip()
        for k in keys:
            self._contain(tx, self.log.runs[k], "held" if action == "hold" else "quarantined", iid, inc["scope"],
                          "signer", text, flight[k], rule.get("cooldown_s", COOLDOWN_S))

    def _contained(self, run, verdict, rule_ids):
        """(verdict, rule ids, incident id or None) of a call of `run` under its hold or quarantine: quarantined, a
        deny (TK-QUARANTINE; past QUARANTINE_DENIES of them refused unrecorded); held, an ask (TK-HOLD) a person
        answers, unless the policy denies it."""
        if run.get("quarantined"):
            if run.get("quarantine_denies", 0) >= QUARANTINE_DENIES:
                raise RPCError("forbidden", f"{self._why_contained(run)} (past {QUARANTINE_DENIES} recorded denies, "
                                            "calls are refused unrecorded)")
            return "deny", ["TK-QUARANTINE"], run["quarantined"]
        if run.get("held") and verdict != "deny":
            return "ask", rule_ids + ["TK-HOLD"] * ("TK-HOLD" not in rule_ids), run["held"][0]
        return verdict, rule_ids, None

    @staticmethod
    def _why_contained(run):
        """What a caller of a held or quarantined run is told: what happened and what to do."""
        q, h = run.get("quarantined"), " and ".join(run.get("held") or ())
        return (f"run {run['run_id'][:128]} is quarantined by incident {q}: its calls are denied for good; an operator "
                f"reviews it (tracekit signer incidents show {q})" if q else
                f"run {run['run_id'][:128]} is held by incident {h}: each call waits for a person's approval; a person "
                f"ends the hold (tracekit signer incidents resume {run['run_id'][:128]}, or resolve each incident)")

    def _check_suspended(self, identity, tenant=None):
        """RPCError forbidden when the suspension list names one of the identity's keys in its tenant (`tenant`, else
        the identity's). A changed list first gets this signer's identity.suspension records (_enforce)."""
        entries, changed = self._suspensions.load()
        if changed:
            try:
                self.log.write(lambda tx: self._enforce(tx, entries))
            except Exception:
                self._suspensions.forget()   # read and recorded again by the next call
                raise
        mine = entries.get(tenant or self._tenant_of(identity), {})
        hit = next((x for k in keys(identity) if (x := lookup(mine, k)) is not None), None)
        if hit is not None:
            raise RPCError("forbidden", f"{subject(identity)[:256]} is suspended (by {str(hit.get('by'))[:256]} at "
                                        f"{str(hit.get('at'))[:40]}): its calls are refused until an operator lifts "
                                        "the suspension (tracekit signer incidents unsuspend)")

    def _enforce(self, tx, entries):
        """identity.suspension records for the suspension list's entries this signer starts (`enforced`) or stops
        (`lifted`) enforcing."""
        on = self.log.contain["enforcing"]
        mine = {f"{tenant}\0{ident[:256]}" for tenant, ids in entries.items() for ident in ids}
        for k in sorted(mine):
            if not on.get(k):
                tenant, ident = k.split("\0", 1)
                tx.emit(self.log.signer_run(tx, tenant), "identity.suspension",
                        {"identity": ident, "state": "enforced", "by": "signer"}, source="signer")
        for k, v in list(on.items()):
            if v and k not in mine:
                tenant, ident = k.split("\0", 1)
                tx.emit(self.log.signer_run(tx, tenant), "identity.suspension",
                        {"identity": ident, "state": "lifted", "by": "signer"}, source="signer")

    def _after_write(self, records):
        """Observer of written records: the argument copies of approvals a hold or quarantine expired go, and their
        waiters wake."""
        ended = [r["event"]["data"]["approval_id"] for r in records if r["event"]["type"] == "approval.expired"
                 and r["event"]["data"].get("reason") in ("hold", "quarantine")]
        for aid in ended:
            self._drop_args(aid)
        if ended:
            with self._cond:
                self._cond.notify_all()

    def _cited(self, r):
        """The records incident record `r` cites: its related events on a webhook (webhook.Outbox)."""
        # lean: reads each cited run from its start; index records by (run, run_seq) if incidents cite long runs
        return [x for c in r["event"]["data"].get("cites", ()) for x in itertools.islice(
            self.log.storage.iter_run(r["event"]["tenant"], c["run_id"]), c["run_seq"], c["run_seq"] + 1)]

    def _operator(self, identity):
        """The tenant an operator call acts in, the caller's. An identity that owns open runs, or that its keys together
        also grant register_run (the startup check sees each `authorize` entry alone), is an agent's: refused."""
        try:
            self._grant(identity, "register_run")
        except RPCError:
            pass
        else:
            raise RPCError("forbidden", f"{subject(identity)[:256]} is also granted register_run: containment is "
                                        "operated by an identity that runs no agent")
        if self.log.open_runs.get(owner(identity)):
            raise RPCError("forbidden", f"{subject(identity)[:256]} owns open runs: containment is operated by an "
                                        "identity that runs no agent")
        return self._tenant_of(identity)

    def _resolver(self, identity, tenant, run_ids, reason):
        """(person id, break-glass) of whoever resolves an incident or resumes a run for runs `run_ids` of `tenant`: a
        person (OIDC, or mapped in approvals.persons) who is an approver, or break-glass with a reason; never one of
        those runs' owner, principal or requester, directly or as the same person."""
        sub = subject(identity)
        who = person(identity) or self._persons.get(sub)
        if not who:
            raise RPCError("forbidden", f"{sub[:256]} is not a person: resolving and resuming is a person's call (map the "
                                        "identity in approvals.persons, or sign in as an OIDC person)")
        glass = not self._in(self._approvers, identity)
        if glass and not self._in(self._break_glass, identity):
            raise RPCError("forbidden", f"{sub[:256]} is not an approver (approvals.approvers) or break-glass")
        if glass and not (reason or "").strip():
            raise RPCError("forbidden", "a break-glass resolve or resume needs a reason")
        theirs = {a["requester"] for a in list(self.log.approvals.values())
                  if a["run_key"][0] == tenant and a["run_key"][1] in run_ids}
        for rid in run_ids:
            r = self.log.runs.get((tenant, rid)) or {}
            theirs |= {r.get("owner"), r.get("principal"), *r.get("people", ())}
        theirs |= {self._persons.get(x) for x in theirs}
        if {sub, owner(identity), who, self._persons.get(sub)} & (theirs - {None}):
            raise RPCError("forbidden", f"{sub[:256]} is the owner, principal or requester of a run this concerns: "
                                        "another person resolves or resumes it")
        return who, glass

    def _incident(self, tenant, iid):
        inc = self.log.contain["incidents"].get(iid)
        if inc is None or inc["tenant"] != tenant:
            raise RPCError("unknown_incident", iid)
        return inc

    def _incident_view(self, iid, inc):
        def state(rid):
            r = self.log.runs.get((inc["tenant"], rid), {})
            return ("final" if r.get("final") else "quarantined" if r.get("quarantined") else
                    "held" if iid in (r.get("held") or ()) else "resumed")
        return {"incident_id": iid, "run_id": inc["run_id"], "ts": inc["ts"], "state": inc["state"],
                **{k: inc[k] for k in ("trigger", "rule_ids", "scope", "mode", "actions")},
                "runs": [{"run_id": rid, "state": state(rid)} for rid in dict.fromkeys(inc["runs"])]}

    def _incident_list(self, identity, req):
        tenant = self._operator(identity)
        # copied on the writer, so only committed states are listed
        items = iter(self.log.write(lambda tx: [
            (iid, self._incident_view(iid, inc)) for iid, inc in self.log.contain["incidents"].items()
            if inc["tenant"] == tenant and req.get("state") in (None, inc["state"])]))
        page, cursor = [], req.get("cursor")
        if cursor is not None:
            for iid, _ in items:
                if iid == cursor:
                    break
        for iid, view in items:
            if len(page) == req.get("limit", LIST_PAGE):
                return {"incidents": page, "next_cursor": page[-1]["incident_id"]}
            page.append(view)
        return {"incidents": page, "next_cursor": None}

    def _incident_show(self, identity, req):
        tenant = self._operator(identity)
        return self.log.write(lambda tx: self._incident_view(req["incident_id"],
                                                             self._incident(tenant, req["incident_id"])))

    def _incident_resolve(self, identity, req):
        """A person resolves an incident: run.resumed in each run it still holds, then incident.resolved in the
        tenant's signer run. Quarantines stay: resolving is not undoing."""
        tenant, iid = self._operator(identity), req["incident_id"]
        reason = req.get("reason") and privacy.redact_text(req["reason"])[0]
        inc = self._incident(tenant, iid)
        who, glass = self._resolver(identity, tenant, [inc["run_id"], *inc["runs"]], reason)
        self.quotas.take_event(identity)
        done = {"incident_id": iid, "by": subject(identity)[:256], "person": who[:256],
                **({"reason": reason} if reason else {}), **({"break_glass": True} if glass else {})}

        def fn(tx, _):
            if self._incident(tenant, iid)["state"] != "open":
                raise RPCError("invalid_request", f"incident {iid} is resolved already")
            resumed = []
            for rid in dict.fromkeys(inc["runs"]):
                run = self.log.runs.get((tenant, rid))
                if run and not run["final"] and iid in (run.get("held") or ()):
                    self._resume(tx, run, iid, done)
                    resumed.append(rid)
            tx.emit(self.log.signer_run(tx, tenant), "incident.resolved", dict(done, resumed=resumed),
                    source="signer", request_id=req["request_id"])
            return {"incident_id": iid, "resumed": resumed}
        return self.log.submit(identity, "incident_resolve", req, fn)

    @staticmethod
    def _resume(tx, run, iid, data, **top):
        """run.resumed: incident `iid` no longer holds `run`; `held_by`, the incidents that still do."""
        tx.emit(run, "run.resumed", {**data, "held_by": [x for x in run["held"] if x != iid]}, source="signer", **top)

    def _run_hold(self, identity, req):
        return self._operator_contain(identity, req, "held")

    def _run_quarantine(self, identity, req):
        return self._operator_contain(identity, req, "quarantined")

    def _operator_contain(self, identity, req, kind):
        """An operator holds or quarantines a run: an incident of trigger `operator` in it, then the response."""
        tenant, method = self._operator(identity), "run_hold" if kind == "held" else "run_quarantine"
        if kind == "held" and not self._people:
            raise RPCError("invalid_request", "no person approver is configured (approvals.approvers), so no one could "
                                              "answer a held call: quarantine the run instead, or configure approvers")
        by, reason = subject(identity)[:256], req.get("reason") and privacy.redact_text(req["reason"])[0]
        self.quotas.take_event(identity)

        def fn(tx, run):
            if run.get("quarantined"):
                raise RPCError("invalid_request", self._why_contained(run))
            iid, scope = "inc-" + secrets.token_hex(16), {"kind": "run", "id": run["run_id"][:256]}
            flight = self._in_flight((tenant, run["run_id"]), run)
            tx.emit(run, "incident.opened", {
                "incident_id": iid, "trigger": "operator", "rule_ids": [], "scope": scope, "cites": [],
                "mode": "enforce", "actions": ["hold" if kind == "held" else "quarantine"], "would": [],
                **({"reason": reason} if reason else {}), **({"in_flight": flight} if flight else {})},
                    source="signer", request_id=req["request_id"])
            self._contain(tx, run, kind, iid, scope, by, reason or f"{method} by {by}", flight, COOLDOWN_S)
            return {"run_id": run["run_id"], "incident_id": iid, "state": kind}
        return self.log.submit(identity, method, req, fn, (tenant, req["run_id"]), late=True)

    def _run_resume(self, identity, req):
        """A person ends a run's holds (a run.resumed for each incident holding it); the incidents stay open. A
        quarantine is final."""
        tenant = self._operator(identity)
        reason = req.get("reason") and privacy.redact_text(req["reason"])[0]
        who, glass = self._resolver(identity, tenant, [req["run_id"]], reason)
        self.quotas.take_event(identity)

        def fn(tx, run):
            if not run.get("held"):
                raise RPCError("invalid_request", f"run {run['run_id'][:128]} is not held" +
                               ("; a quarantine is final" if run.get("quarantined") else ""))
            held = run["held"]
            for i, iid in enumerate(held):
                self._resume(tx, run, iid, {"incident_id": iid, "by": subject(identity)[:256], "person": who[:256],
                                            **({"reason": reason} if reason else {}),
                                            **({"break_glass": True} if glass else {})},
                             **({} if i else {"request_id": req["request_id"]}))
            return {"run_id": run["run_id"], "incident_id": held[0], "state": "resumed"}
        return self.log.submit(identity, "run_resume", req, fn, (tenant, req["run_id"]), late=True)

    def _response_pause(self, identity, req):
        return self._response(identity, req, False)

    def _response_resume(self, identity, req):
        return self._response(identity, req, True)

    def _response(self, identity, req, enabled):
        """Pause (or resume) the tenant's response engine on this signer: incidents are still detected and written,
        with no action (incident.response)."""
        tenant, by = self._operator(identity), subject(identity)[:256]
        self.quotas.take_event(identity)

        def fn(tx, _):
            tx.emit(self.log.signer_run(tx, tenant), "incident.response", {
                "enabled": enabled, "by": by,
                **({"reason": privacy.redact_text(req["reason"])[0]} if "reason" in req else {})},
                    source="signer", request_id=req["request_id"])
            return {"enabled": enabled}
        return self.log.submit(identity, "response_resume" if enabled else "response_pause", req, fn)

    def _suspend(self, identity, req, lift=False):
        """Add an identity of the caller's tenant to the shared suspension list (or lift it): every replica refuses
        its calls once it reads the list, each writing its own `enforced` record. No token is revoked."""
        tenant, target, method = self._operator(identity), req["identity"], "unsuspend" if lift else "suspend"
        # the entry applies only to identities of `tenant` (_check_suspended); refuse a target `tenants` maps elsewhere
        if lookup(self.tenants, target, tenant) != tenant:
            raise RPCError("forbidden", f"{target[:256]} is not an identity of tenant {tenant[:64]!r}")
        by, reason = subject(identity)[:256], req.get("reason") and privacy.redact_text(req["reason"])[0]
        self.quotas.take_event(identity)
        changed = self._suspensions.change(tenant, target, None if lift else {
            "by": by, "at": _iso(time.time()), **({"reason": reason} if reason else {})})
        if not changed and (identity.scheme, identity.subject, req["request_id"]) not in self.log.done:   # not a retry
            raise RPCError("invalid_request", f"{target[:256]} is {'not suspended' if lift else 'suspended already'}")

        def fn(tx, _):
            tx.emit(self.log.signer_run(tx, tenant), "identity.suspension", {
                "identity": target, "state": "lifted" if lift else "suspended", "by": by,
                **({"reason": reason} if reason else {})}, source="signer", request_id=req["request_id"])
            return {"identity": target, "state": "lifted" if lift else "suspended"}
        return self.log.submit(identity, method, req, fn)

    def _unsuspend(self, identity, req):
        return self._suspend(identity, req, lift=True)

    # --- methods ---

    def _register_run(self, identity, req):
        sub = subject(identity)
        for field, allowed in (("tenant", self.multi_tenant_apps), ("source", self.migrators),
                               ("analyzes", self.analyzers), ("replay_of", self.analyzers)):
            if field in req and sub not in allowed:
                raise RPCError("forbidden", f"{sub[:256]} is not configured to register runs with `{field}`")
        if ("replay_of" in req) != ("investigation" in req):
            raise RPCError("invalid_request", "a replay run names both `replay_of` and `investigation`")
        harness = None
        if self._harnesses:
            procs = self._chain(identity)
            harness, why = harness_helper.match(procs, self._harnesses) if procs else (
                None, "no process chain: no peer pid, or the harness helper did not answer")
            if harness is None and lookup(self._harness_required, sub, False):
                raise RPCError("forbidden", f"not from a registered harness ({why})")
        if "principal_token" in req:
            if "principal" in req:
                raise RPCError("invalid_request", "principal or principal_token, not both")
            if self.oidc is None:
                raise RPCError("invalid_request", "this signer has no oidc issuers to verify a principal_token")
            principal = person(self.oidc.validate(req["principal_token"]))
        else:
            principal = req.get("principal")
        tenant = req.get("tenant") or self._tenant_of(identity)
        self._certified(tenant)
        run_id = req.get("run_id") or self.id_prefix + secrets.token_hex(16)
        if not run_id.startswith(self.id_prefix):
            raise RPCError("invalid_request", f"this signer's run ids start with {self.id_prefix!r}")
        parent = req.get("parent")
        if parent:   # the caller holds the parent run's token, for a run of the same tenant
            try:
                self.tokens.verify(parent["run_token"], tenant, parent["run_id"], identity)
            except RPCError as e:
                raise RPCError(e.code, f"parent: {e.message}; pass the parent run's handle, as the identity it was "
                                       "issued to, for a child run of the same tenant") from None
        own, caller = owner(identity), req.get("caller")
        # a gateway registering the run of a client it serves (the OpenShell middleware's of a sandbox): the run counts
        # against the gateway's open runs for that client, as its calls do against its rate for that client, and
        # against its gateway_open_runs for all of them (a name it makes up is a fresh client)
        if caller is not None and not lookup(self._gateways, sub, False):
            raise RPCError("forbidden", f"{sub[:256]} is not a configured gateway")
        client = caller and CallerIdentity(*caller.split(":", 1), True)
        if client:
            self._check_suspended(client)
        count = own if caller is None else json.dumps([own, caller])   # the open_runs entry it counts in
        # another system's log, which tracekit.follow reads: no layer here gates or reports its calls (an OTLP import's)
        imported = sub in self.importers
        self.quotas.take_event(*((client, identity) if client else (identity,)))

        def fn(tx, _):
            if (tenant, run_id) in self.log.runs:
                raise RPCError("run_exists", run_id)
            for field in ("analyzes", "replay_of"):
                if field in req and (tenant, req[field]) not in self.log.runs:
                    raise RPCError("unknown_run", req[field])
                if field in req and self.log.runs[(tenant, req[field])].get("replay"):
                    raise RPCError("invalid_request", f"{req[field]} is a findings or replay run: name the run it is "
                                                      "about")
            up = parent and self.log.runs.get((tenant, parent["run_id"]))
            if parent and not up:
                raise RPCError("unknown_run", f"{parent['run_id']}: register the child run on its parent's signer")
            if up and up["final"]:
                raise RPCError("run_closed", f"parent run {parent['run_id']} is final: start the child run from an "
                                             "open run, or without `parent`")
            n = self.log.open_runs.get(count, 0)
            self.quotas.check_count("open_runs", n)
            if client:   # lean: sums the gateway's entries per run it registers; keep a total if that ever shows
                self.quotas.check_count("gateway_open_runs", sum(v for k, v in self.log.open_runs.items() if k == own
                                                                 or k.startswith(json.dumps([own])[:-1] + ",")))
            run = tx.new_run(tenant, run_id)
            tx.set(run, "owner", own)
            if caller is not None:
                # lean: the entry is run state (memory and snapshot), not in run.registered: a run replayed from the
                # log after the last snapshot counts in its owner's own entry until it closes; record the caller in
                # run.registered if gateways' runs must count exactly across restarts
                tx.set(run, "quota", count)
            tx.set(self.log.open_runs, count, n + 1)
            tx.set(run, "source", "import" if imported else req.get("source", "sdk"))
            tx.set(run, "people", (person(identity), principal if "principal_token" in req else None))
            tx.set(run, "prov", {"state": "complete", "index": {}})
            if "replay_of" in req:   # not reconciled: a replay run has model exchanges and, by design, no decisions
                tx.set(run, "rec", None)
            if imported:   # not reconciled (as pipeline replays it), and watched for the follower's heartbeats
                for k, v in (("rec", None), ("spans", {}), ("tailed", True)):
                    tx.set(run, k, v)
            if harness:
                tx.set(run, "harness", (harness["pid"], harness["start_time"]))
            if up:
                tx.set(run, "session", up.get("session", parent["run_id"]))
            if {"analyzes", "replay_of"} & req.keys():
                tx.set(run, "replay", True)
            attested = "principal_token" in req
            out = {"run_id": run_id, "run_token": self.tokens.issue(tenant, run_id, identity), "tenant": tenant,
                   "tenant_attested": "tenant" not in req, "principal_attested": attested, "fail_modes": self.fail_modes}
            top = {"tenant_attested": out["tenant_attested"], "principal_attested": attested}
            if principal is not None:
                out["principal"] = top["principal"] = principal
                tx.set(run, "principal", principal)
            data = {"agent": req["agent"], "signer_isolation": self.isolation or self._isolation(identity), "fail_modes": self.fail_modes,
                    "identity": _recorded(identity)}
            data.update({k: req[k] for k in ("analyzes", "replay_of", "investigation") if k in req})
            if up:
                data.update(parent_run=parent["run_id"], session=run["session"])
            if harness:
                data["harness"] = dict(harness, attested=True)
            if self.posture:
                data["posture"] = {**self.posture, "attested": False}
            if imported:
                data["fidelity"], top["tier"] = "none", "T3"
            tx.emit(run, "run.registered", data, request_id=req["request_id"], **top)
            # evasion: a new run of a held owner and principal, or of a held parent run, starts held
            now = _iso(time.time())
            had = [("quarantined", up["quarantined"], "the parent run")] if up and up.get("quarantined") else \
                [("held", i, "the parent run") for i in (up or {}).get("held") or ()]
            # a run with no attested principal inherits every principal's of its owner: dropping it gains nothing
            key, cool = cooldown_key(tenant, run), self.log.contain["cooldown"]
            mine = {i: v for k in ([key] if run["people"][1] else [k for k in cool if k.startswith(key)])
                    for i, v in (cool.get(k) or {}).items()}
            had += [(kind, i, f"its owner and principal (until {until})") for i, (until, kind) in mine.items()
                    if until > now]
            for kind, iid, whose in [h for h in had if h[0] == "quarantined"][:1] or had:
                self._contain(tx, run, kind, iid, {"kind": "run", "id": run_id[:256]}, "signer",
                              f"inherits incident {iid} from {whose}", inherited=True)
            if up and harness:   # the parent's records name a child its harness process started
                tx.emit(up, "run.child", {"run_id": run_id}, source="signer")
            other = harness and n and not req.keys() & {"analyzes", "replay_of", "source"} and self._overlapping(
                tenant, run_id, own, run["harness"], run.get("session", run_id))
            if other:   # the gap once both record events (Tx.event): an older session left open and idle is no overlap
                tx.set(run, "overlap", [other, False])
                o = self.log.runs[(tenant, other)]
                tx.set(o, "overlapped_by", [*o.get("overlapped_by", ()), run_id])
            return out
        out = self.log.submit(identity, "register_run", req, fn)
        # the observers alive now cover the run from its start (a sensor import only a run of an identity its `runs`
        # map processes to), a follower its own run
        with self._beats_lock:
            if imported:
                self._beats.setdefault((out["tenant"], out["run_id"]), time.monotonic())
            for (t, obs), (at, _, sensor, callers) in self._observers.items():
                if t == out["tenant"] and time.monotonic() - at < TAILER_LOST_S and (not sensor or own in callers):
                    self._beats.setdefault((t, out["run_id"], obs), at)
        return out

    def _overlapping(self, tenant, run_id, own, harness, session):
        """An open run of `own` in `tenant`, of the same harness process, in another session than run `run_id`'s, or
        None (on the writer)."""
        # lean: scans the open runs; index them by owner and harness if one harness process keeps thousands open
        for key in self.log.live:
            r = self.log.runs[key]
            if (key[0] == tenant and key[1] != run_id and r["owner"] == own and not r["closed"]
                    and (tuple(r["harness"]) if r.get("harness") else None) == harness
                    and r.get("session", key[1]) != session):
                return key[1]
        return None

    def _decide(self, identity, req):
        identity, gw = self._as_caller(identity, "decide", req)
        key, top, holder = self._authorize(identity, req, gw), T2 if gw else {}, _holder(gw, req)
        self.quotas.take_event(identity, gw)
        tool, tcid, attempt, hint = req["tool"], req["tool_call_id"], req.get("attempt", 0), req.get("tool_class_hint")
        args, digest = self._args(req)
        untrusted, prov = self._provenance(key, args, req)
        # matched here, off the writer thread; the writer picks a memoised deny/ask or this result
        ruled = self._evaluate(tool, args, hint, untrusted) if digest else None
        prov = prov()
        sums, unreadable = self.log.detector.prepare(tool, args, ruled[2]) if self.log.detector and ruled else ({}, False)
        agent = self._eligibility(key, identity, tool, args, digest, ruled[0], prov) if ruled and \
            ruled[0]["verdict"] == "ask" else None
        cls = self.policy.tool_class(tool)
        # read only where the engine read these arguments without failing (a host matters to no deny)
        host = classes.extract(cls, tool, args).get("host") if ruled and "error" not in ruled[0] and cls in (
            "http", "browser") and isinstance(args, dict) else None
        facts = self._facts(key, tool, args, cls) if digest else None   # what a live constraint looks at
        did = "dec-" + secrets.token_hex(16)
        # lean: expires_at is signed but `complete` does not enforce it; enforce once executors check it before running
        expires_at = _iso(time.time() + DECISION_TTL_S)
        # rule_ids say only TK-OVERSIZE: name the subjects it stands for
        reasons = [(f"TK-OVERSIZE: over {engine.MAX_SUBJECT // 1024} KiB, so never matched: "
                    + ", ".join(ruled[0]["oversize"]))[:4096]] if ruled and ruled[0].get("oversize") else []
        if ruled and ruled[0].get("nondeterministic"):   # the rule it was matching when time ran out is no match
            reasons.append(f"nondeterministic: the fallback regex engine ran out of its {engine.REGEX_TIMEOUT_S:g} s on "
                           "these arguments, so the call is denied; the rule it was matching then is among the rule ids "
                           "without having matched (install google-re2 on the signer)")
        if ruled and ruled[0].get("error"):   # the record and the response say why, as for TK-OVERSIZE
            reasons = [f"TK-ENGINE-ERROR: the policy engine failed on these arguments ({ruled[0]['error']}), "
                       "so the call is denied"]
        big = {"reasons": reasons} if reasons else {}
        written = []   # (run_seq, commitment) of each decision record this call (not a retry the cache answers) wrote

        def fn(tx, run):
            memo, gaps = run["calls"].get(tcid), []
            self._hold(memo, holder, tcid)
            data = {"tool_use_id": tcid, "tool": tool, "policy_hash": self.policy.policy_hash,
                    "engine": self.policy.engine, "expires_at": expires_at, **prov}
            counts = self.log.detector and self.log.detector.counts
            if gw:   # the call is the gateway's, for this caller: only it may answer for it (_hold), after a restart too
                data["via"], data["caller"] = holder
            if digest is None:
                verdict, rule_ids = "deny", ["TK-ARGS-INVALID"]
            elif memo and memo["attempt"] == attempt and memo["decision"] in ("deny", "ask") and self._same(memo, digest) \
                    and ("TK-HOLD" not in memo["rule_ids"] or run.get("held")):   # a hold's ask ends with the hold
                # the memo's decision as it was recorded: a retry keeps both readings' rule ids and nondeterminism
                verdict, rule_ids = memo["decision"], memo["rule_ids"]
                if counts and memo.get("detect_ids"):
                    data["detect"] = {"rule_ids": memo["detect_ids"]}
                if memo.get("nondeterministic"):
                    data["nondeterministic"] = True
            else:
                d, mismatch, both = ruled
                verdict, rule_ids = d["verdict"], d["rule_ids"]
                if counts and both != rule_ids:
                    data["detect"] = {"rule_ids": both}
                if d.get("nondeterministic"):
                    data["nondeterministic"] = True
                if mismatch:
                    gaps.append(("class_mismatch", f"class hint {hint!r} disagrees with the policy's class "
                                                   f"{self.policy.tool_class(tool)!r}; the stricter decision applies"))
                # lean: the deny set lives in memory, so a flip across a signer restart goes unflagged; keep it in the
                # run's snapshot if runs often span restarts
                if verdict == "deny":
                    tx.set(run["denied"], digest, True)
                elif verdict != "ask" and digest in run["denied"]:
                    gaps.append(("decision_flip", f"{verdict} after a deny for the same arguments in this run"))
            f = facts if facts is not None or not (digest and run.get("constraints")) else \
                self._facts(key, tool, args, cls, run)   # the run's first constraint came meanwhile
            held = f and verdict != "deny" and self._constrained(run, f)   # tighten only: never lowered
            if held:
                verdict, rule_ids = "ask", rule_ids + ["TK-CONSTRAINT"] * ("TK-CONSTRAINT" not in rule_ids)
            if unreadable and verdict in ("allow", "flag"):
                verdict, rule_ids = "ask", rule_ids + [detect.SUM_UNREADABLE]
            if sums:
                data["detect"] = {**data.get("detect", {}), **sums}
            names = reconcile.model_names(tool)   # an MCP call: its digest under each name the model may have used
            l2 = digest if digest is None or len(names) == 1 else {n: event_hash({"tool": n, "args": args}) for n in names}

            def record(did, verdict, rule_ids, again=False):
                """Write decision `did`, as the run's hold or quarantine leaves it, and make it the call's; `again`: the
                call's second decision, written by the signer after the first fired a hold or quarantine."""
                verdict, rule_ids, iid = self._contained(run, verdict, rule_ids)
                commitment = self._commit(did, digest) if digest else None
                d = dict(data, decision_id=did, nonce=secrets.token_hex(16), decision=verdict, rule_ids=rule_ids,
                         **({"args_commitment": commitment} if commitment else {}),
                         **({"incident_id": iid} if iid else {}), **big)
                call = {"tool_call_id": tcid, "attempt": attempt, "decision": verdict, "rule_ids": rule_ids,
                        "decision_id": did, "commitment": commitment, "dotenv": _dotenv(args), "tool": tool,
                        "via": holder[0], "caller": holder[1], "nondeterministic": bool(data.get("nondeterministic")),
                        "detect_ids": data.get("detect", {}).get("rule_ids"), "incident": iid}
                if verdict == "ask":   # the signer's copy, for the approval request (memory only: decide again after a restart)
                    call["pending"] = {"tool": tool, "args_source": req["args_source"], "args": req["args"]}
                    if agent and rule_ids == ruled[0]["rule_ids"]:
                        call["agent"] = agent
                tx.set(run["calls"], tcid, call)
                tx.set(run["decisions"], did, call)
                kw = dict(digests={tcid: l2}, tool_call_id=tcid, attempt=attempt, args_source=req["args_source"],
                          **top)
                seq = tx.emit(run, "policy.decision", d, **kw) if again else \
                    tx.event(run, req, "policy.decision", d, **kw)
                written.append((seq, commitment))
                return seq, d
            seq, d = record(did, verdict, rule_ids)
            if d["decision"] in ("allow", "flag") and (run.get("held") or run.get("quarantined")):
                tx.pop(run["decisions"], did)   # the call fired a hold or quarantine: it never runs on this decision
                seq, d = record("dec-" + secrets.token_hex(16), d["decision"], d["rule_ids"], again=True)
            if isinstance(host, str) and d["decision"] != "deny" and run.get("rec") is not None:   # explains its traffic
                # lean: hosts are memory and snapshot state; after a restart with no snapshot since, the run's earlier
                # http calls no longer explain an observed host (an unexplained_effect warning)
                h = host.lower().rstrip(".")
                if d["decision"] in ("allow", "flag"):
                    tx.set(reconcile.sub(tx.set, run["rec"], "hosts"), h, True)
                else:   # an ask explains its host once its approval is consumed: asking alone allows nothing
                    tx.set(reconcile.sub(tx.set, run["rec"], "asked_hosts"), tcid, h)
            for kind, reason in gaps:
                tx.emit(run, "capture.gap", {"kind": kind, "reason": reason, "tool_use_id": tcid}, source="signer",
                        tool_call_id=tcid)
            out = {"decision": "allow" if d["decision"] == "flag" else d["decision"], "decision_id": d["decision_id"],
                   "rule_ids": d["rule_ids"], "run_seq": seq, "expires_at": expires_at,
                   **({"reason": "; ".join(big["reasons"])[:1024]} if big else {})}
            if d["decision"] in ("deny", "ask") and not big and (why := "; ".join(x for x in (
                    held if "TK-CONSTRAINT" in d["rule_ids"] else None, self._reasons(d["rule_ids"])) if x)[:1024]):
                out["reason"] = why   # what the client tells the model or the person, after the rule ids
            if "incident_id" in d:
                out.update(incident_id=d["incident_id"], reason=self._why_contained(run))
            if self.policy.untrusted_results(tool):   # the result itself, for the provenance index
                out["send_result"] = True
            return out
        out = self.log.submit(identity, "decide", req, fn, key)
        if written and written[-1][1]:
            self._retain(key, *written[-1], _shown(args, _dotenv(args)))
        return out

    def _event(self, identity, method, req, typ, data, need_call=False, digests=None, out=None, keep=None, gw=None,
               check=None, after=None, **top):
        """`data(commit)`: the event's data, given `commit(digest)`, the commitment under this record's salt. `out`:
        more fields of the response. `keep`: (the content its content_digest commits to,) for the content vault.
        `gw`: the gateway making the call (_as_caller), whose events these are. `check(run)`: on the writer, raises to
        refuse the event. `after(tx, run)`: on the writer, once the event is written: more fields of the response."""
        key = self._authorize(identity, req, gw)
        self.quotas.take_event(identity, gw)
        sid = secrets.token_hex(16)
        label = salt_label({"type": typ, "data": {"salt_id": sid}})
        data = {**data(lambda digest: self._commit(label, digest)), "salt_id": sid}
        written = []

        def fn(tx, run):
            if need_call and req["tool_call_id"] not in run["calls"]:
                raise RPCError("unknown_tool_call", req["tool_call_id"])
            if check:
                check(run)
            written.append(tx.event(run, req, typ, data, digests, **top))
            return {"run_seq": written[0], **(out or {}), **(after(tx, run) if after else {})}
        res = self.log.submit(identity, method, req, fn, key, late=True)
        if written and keep:
            self._retain(key, written[0], data.get("content_digest"), keep[0])
        return res

    def _complete(self, identity, req):
        identity, gw = self._as_caller(identity, "complete", req)
        key, top, holder = self._authorize(identity, req, gw), T2 if gw else {}, _holder(gw, req)
        tcid, attempt, did = req["tool_call_id"], req.get("attempt", 0), req["decision_id"]
        # read off the writer thread, which checks the decision again; unknown after a restart (arguments are never
        # logged), so a replayed decision redacts as if the call touched a .env file
        dotenv = (self.log.runs[key].get("decisions", {}).get(did) or {}).get("dotenv", True)
        try:
            value, manifest = _redact({k: req[k] for k in ("result", "error") if k in req}, dotenv,
                                      req.get("redaction", {}) if req.get("redacted") else None)
            c = canonical(value)
        except rfc8785.CanonicalizationError as e:
            raise RPCError("invalid_request", f"result is not canonical JSON: {e}") from None
        output = {"hash": self._commit("result:" + did, "sha256:" + hashlib.sha256(c).hexdigest()), "size": len(c),
                  "redacted": manifest["count"] > 0 or manifest["client_claimed"]}
        # the provenance index: only an untrusted tool's results (any other tool may echo what the agent put in its
        # arguments, which would launder an injected value into trusted content), read before redaction (HMACs in
        # memory only), so a value next to a secret's label still counts. A digest instead of the result: partial.
        tool = (self.log.runs[key].get("decisions", {}).get(did) or {}).get("tool")   # None: decided before a restart
        keys, overflow, missing = [], False, False
        if tool and self.log.runs[key].get("prov") and self.policy.untrusted_results(tool):
            keys, overflow = self._keys({k: req[k] for k in ("result", "error") if k in req})
            r = req.get("result")
            missing = req["status"] == "ok" and ("result" not in req or isinstance(r, str) and _DIGEST.fullmatch(r)
                                                 or isinstance(r, dict) and {"hash", "size"} <= r.keys())
        open_call = self.log.runs[key].get("decisions", {}).get(did)
        if not (gw and open_call and (open_call.get("via"), open_call.get("caller")) == holder):
            self.quotas.take_event(identity, gw)   # a gateway's result for its own decision: its decide paid
        written = []

        def fn(tx, run):
            call = run["decisions"].get(did)
            if call is None or (call["tool_call_id"], call["attempt"]) != (tcid, attempt):
                raise RPCError("unknown_decision", f"{did} is not an open decision for {tcid} attempt {attempt}")
            self._hold(call, holder, tcid)
            if not self._same(call, req["args_digest"]):
                raise RPCError("args_mismatch", f"{tcid} ran with other arguments than decision {did}")
            tx.pop(run["decisions"], did)
            seq = tx.event(run, req, "tool.result", {"tool_use_id": tcid, "ok": req["status"] == "ok", "output": output,
                                                     "decision_id": did, "redaction": manifest,
                                                     **({"via": holder[0]} if gw else {})},
                           tool_call_id=tcid, attempt=attempt, **top)
            written.append(seq)
            comparable = req["status"] == "ok" and "result" in req and "error" not in req   # no result: nothing to compare
            tx.set(run["results"], tcid, run["results"].get(tcid, [])[1 - RESULTS_PER_CALL:] + [
                [did, output["hash"], comparable, output["redacted"], None]])
            if keys:
                self._index(tx, run, keys, {"run_seq": seq, "tool": call["tool"], "tool_call_id": tcid,
                                            "trust": "untrusted"})
            if overflow:
                degrade(tx, run.get("prov"), "truncated", f"the result of {tcid} carried more values than are read")
            if missing:
                degrade(tx, run.get("prov"), "partial", f"{tcid} ({call['tool'][:64]}) completed with a digest, "
                                                          "not its result")
            a = self.log.approvals.get(self.log.approval_index.get((*key, tcid, attempt)), {})
            approved = a.get("state") == "consumed" and self._opens(a["commitment"], a["label"], req["args_digest"])
            if approved and a["decision_id"] in run["decisions"]:   # the approved call completed under a later decision
                tx.pop(run["decisions"], a["decision_id"])
            if call["decision"] == "deny" or (call["decision"] == "ask" and not approved):
                tx.emit(run, "capture.gap", {"kind": "executed_against_policy", "tool_use_id": tcid,
                                             "reason": f"{tcid} ran after a {call['decision']} decision"
                                                       + (" with no consumed approval of these arguments"
                                                          if call["decision"] == "ask" else "")},
                        source="signer", tool_call_id=tcid)
            return {"run_seq": seq}
        res = self.log.submit(identity, "complete", req, fn, key, late=True)
        if written:
            self._retain(key, written[0], output["hash"], value)
        return res

    def _observe(self, identity, req):
        identity, gw = self._as_caller(identity, "observe", req)
        key, top = self._authorize(identity, req, gw), T2 if gw else {}
        try:
            value, manifest = _redact(req["value"], False)
            c = canonical(value)
        except rfc8785.CanonicalizationError as e:
            raise RPCError("invalid_request", f"value is not canonical JSON: {e}") from None
        sid = secrets.token_hex(16)
        label = salt_label({"type": "input.observed", "data": {"salt_id": sid}})
        data = {"source": req["source"], "trust": req["trust"], "redaction": manifest, "salt_id": sid,
                "output": {"hash": self._commit(label, "sha256:" + hashlib.sha256(c).hexdigest()), "size": len(c),
                           "redacted": manifest["count"] > 0}, **({"via": subject(gw)} if gw else {})}
        keys, overflow = self._keys(req["value"]) if self.log.runs[key].get("prov") else ([], False)   # before redaction
        self.quotas.take_event(identity, gw)
        written = []

        def fn(tx, run):
            written.append(tx.event(run, req, "input.observed", data, **top))
            self._index(tx, run, keys, {"run_seq": written[0], "trust": req["trust"]})
            if overflow and req["trust"] == "untrusted":   # trusted values left out only make more calls held
                degrade(tx, run.get("prov"), "truncated",
                              f"observed input {written[0]} carried more values than are read")
            return {"run_seq": written[0]}
        res = self.log.submit(identity, "observe", req, fn, key)
        if written:
            self._retain(key, written[0], data["output"]["hash"], value)
        return res

    def _state_write(self, identity, req):
        key, sk = self._authorize(identity, req), req["key"]
        self.quotas.take_event(identity)
        sid = secrets.token_hex(16)
        label = salt_label({"type": "state.write", "data": {"salt_id": sid}})
        digest = self._commit(label, req["value_digest"])

        def fn(tx, run):
            data = {"store": "default", "key": sk, "digest": digest, "salt_id": sid}
            prev = req.get("prev_digest", ...)
            if prev is not ...:
                data["prev_digest"] = prev and self._commit(label, prev)
            seq = tx.event(run, req, "state.write", data)
            last = run["states"].get(sk)   # (salt label, commitment) of the last write of this key
            if prev is not ... and last and self._commit(last[0], prev or "") != last[1]:
                # the agent's own earlier write says the state was something else: it changed outside its writes
                tx.emit(run, "capture.gap", {"kind": "state_tamper", "reason": f"state {sk[:200]} changed between "
                                             "writes: the write starts from another state than the last one written"},
                        source="signer")
            tx.set(run["states"], sk, (label, digest))
            return {"run_seq": seq}
        return self.log.submit(identity, "state_write", req, fn, key, late=True)

    def _as_caller(self, identity, method, req):
        """(the identity a call is made as, the gateway making it or None): a `gateways` identity (an LLM or MCP
        gateway, a tool executor) that names `caller` acts for the client it authenticated, under that client's run
        token and grants; the events are the gateway's, charged to its budget for that client (quotas.key)."""
        if "caller" not in req:
            return identity, None
        if not lookup(self._gateways, subject(identity), False):
            raise RPCError("forbidden", f"{subject(identity)[:256]} is not a configured gateway")
        if len(subject(identity)) > 256:   # each of its records names it in full (`via`)
            raise RPCError("forbidden", f"{subject(identity)[:64]}...: a gateway's identity is at most 256 characters")
        gw, identity = identity, CallerIdentity(*req["caller"].split(":", 1), True)
        self._grant(identity, method)
        self._check_suspended(identity)
        return identity, gw

    @staticmethod
    def _hold(call, holder, tcid):
        """Refuses a call about tool call `tcid` (its state `call`) from other than who decided it: the gateway for the
        caller `holder` names ((gateway, caller), _holder), or the run's client itself ((None, None)), so none
        answers for another's call."""
        if call is not None and (call.get("via"), call.get("caller")) != holder:
            raise RPCError("forbidden", (
                f"tool call {tcid[:128]} is held by {call['via']} for {call.get('caller')}, which decided it for this "
                "run: only it may decide, approve or complete it" if call.get("via") else
                f"tool call {tcid[:128]} was decided by the run's client, not through a gateway: a gateway call takes "
                "a tool_call_id of its own"))

    def _model_event(self, identity, req):
        top, out, gw = {}, None, None
        if "amended" in req and not ("caller" in req and req["phase"] == "request"):
            raise RPCError("invalid_request", "amended is an LLM gateway's, on a request it changed before sending it")
        if "said_only" in req and ("tool_uses" in req or req["phase"] != "response"):
            raise RPCError("invalid_request", "said_only is a response recorded without its calls: no tool_uses")
        if "caller" in req:   # an LLM gateway reports the exchange of the client it authenticated, under its run token
            identity, gw = self._as_caller(identity, "model_event", req)
            top, out = {"source": "gateway"}, {"fail_modes": self.fail_modes,
                                               "check_results": self.verify_tool_results is not None}
            if "amended" in req:   # non-critical (format-v2.md §9): an older verifier's lines stay true without it
                top["ext"] = {"amended": req["amended"]}
        keep, content_digest = None, req.get("content_digest")
        if "body" in req:   # committed to after redaction, as a result is; kept when the vault is on
            try:
                body = _redact(req["body"], False)[0]
                keep, content_digest = (body,), "sha256:" + hashlib.sha256(canonical(body)).hexdigest()
            except rfc8785.CanonicalizationError:   # an integer past 2^53, say: recorded as without a body
                pass

        def data(commit):
            d = {"exchange_id": req.get("exchange_id", req["request_id"]), "phase": req["phase"],
                 "streamed": req.get("streamed", False), "model": req["model"], "upstream": req["provider"]}
            for k in ("stop_reason", "tool_results_sent", "said_only"):
                if k in req:
                    d[k] = req[k]
            if "error" in req:
                d["error"] = privacy.redact_text(req["error"])[0]
            if content_digest:
                d["content_digest"] = commit(content_digest)
            if {"input_tokens", "output_tokens"} <= req.get("usage", {}).keys():   # the event schema needs both counts
                d["usage"] = req["usage"]
            if "tool_uses" in req:
                d["tool_uses"] = [{k: v for k, v in t.items() if k != "args_digest"} for t in req["tool_uses"]]
                for t, u in zip(req["tool_uses"], d["tool_uses"]):
                    if "args_digest" in t:
                        u["args_commitment"] = commit(t["args_digest"])
            return d

        def check(run):   # a quarantined run's model loop stops: no further request is recorded or forwarded
            if req["phase"] == "request" and run.get("quarantined"):
                raise RPCError("forbidden", self._why_contained(run))

        def after(tx, run):   # only a gateway's digests count: an agent's own report of its context proves nothing
            bad = self._results_checked(tx, run, req.get("tool_results", []), req.get("tool_results_sent", []))
            if bad and self.verify_tool_results == "refuse":
                return {"refused": (f"the tool result(s) {', '.join(bad[:5])}{' ...' if len(bad) > 5 else ''} sent to "
                                    "the model are not what the tool returned, as the signer recorded it "
                                    "(reconcile.result_mismatch); this signer refuses such requests "
                                    "(verify_tool_results: refuse)")[:1024]}
            return {}
        verify = gw and self.verify_tool_results and (req.get("tool_results") or req.get("tool_results_sent"))
        return self._event(identity, "model_event", req, "model.exchange", data,
                           digests={t["id"]: t.get("args_digest") for t in req.get("tool_uses", ())}, out=out, keep=keep,
                           gw=gw, check=check, after=after if verify else None, **top)

    def _results_checked(self, tx, run, results, sent=()):
        """The ids of the tool results a gateway saw a request send (`results`: model_event's `tool_results`) that are
        not what the call's tool.results committed to (any of them: a tool_call_id may be reused), by either form
        complete takes (the value, or its digest), under that result's salt. Each one's first time is a signed
        reconcile.result_mismatch, and so is a result sent for a call the run allowed before its result was recorded
        (the shipped clients complete a call before the next model request), whose id is not returned (not refused): a
        complete that was lost would otherwise refuse every later request of an honest run, as each resends it. A
        result the request sends (`sent`: its `tool_results_sent`) that the gateway gave no digests of (past its
        MAX_DIGESTED bytes or MAX_RESULTS_CHECKED results, or a gateway older than 1.3), for a call with a result to
        compare, is unchecked: its first time is a signed capture.gap result_unchecked, never refused (a gateway that
        restarted has no digests cached, so an honest long run would trip it). Not checked: a call the run never
        decided or didn't allow, a call whose results are all errors or carry no result, one redaction changed (its
        commitment is over the redacted value) and matching none, a run that is not reconciled (imported, a replay
        run)."""
        rec, bad = run.get("rec"), []
        if rec is None:
            return bad
        unformed = collections.Counter(sent) - collections.Counter(r["id"] for r in results)   # an id may be reused
        for r in results + [{"id": i, "forms": None} for i in unformed]:
            tcid, entries = r["id"], run.get("results", {}).get(r["id"])
            if entries is None:
                call = run.get("calls", {}).get(tcid)   # still open: decided, allowed, not completed
                if not call or call["decision"] not in ("allow", "flag") or call.get("decision_id") not in run.get(
                        "decisions", {}):
                    continue
                detail = (f"a request sent the model a result for {tcid[:128]} before the call's result was recorded: "
                          "a result the tool never returned, or a complete that was lost or comes late")
            else:
                ours = [x for x in entries if x[2]]
                if ours and r["forms"] is None:
                    if tcid not in rec.get("unchecked", {}):
                        tx.emit(run, "capture.gap", {
                            "kind": "result_unchecked", "tool_use_id": tcid,
                            "reason": f"a request sent the model a result for {tcid[:128]} that the gateway gave no "
                                      "digests of (past the 1 MiB or the newest 512 results it digests per request, "
                                      "or a gateway older than 1.3): not compared with its tool.result"},
                                source="signer", tool_call_id=tcid)
                    continue
                if not ours or self._matched(tx, run, tcid, entries, r["forms"]):
                    continue
                if any(x[3] for x in ours):   # one of them redaction changed: it can't be told apart from an edit
                    continue
                detail = (f"a request sent the model a result for {tcid[:128]} that is not what the tool returned "
                          "(its tool.result): the agent's context differs from the record")
                bad.append(tcid)
            if tcid not in rec.get("mismatched", {}):
                tx.emit(run, "reconcile.result_mismatch", {"layers": ["L2", "L3"], "detail": detail}, source="signer",
                        tool_call_id=tcid)
        return bad

    def _matched(self, tx, run, tcid, entries, forms):
        """Whether one of `forms` (a gateway's digests of a tool result as sent) is what a comparable one of the call's
        tool.results (`entries`) committed to; the form that matched is kept, and a form that matched none is remembered
        (`_unmatched`), so the next request that resends either costs no HMAC."""
        digests = {f["result_digest"] for f in forms}
        if any(x[2] and x[4] in digests for x in entries):
            return True
        as_digest = None
        for i, (did, commitment, comparable, _, _) in enumerate(entries):
            left = [f for f in forms if (did, f["result_digest"]) not in self._unmatched] if comparable else []
            if not left:
                continue
            if as_digest is None:   # complete's result was the value's digest
                as_digest = {f["result_digest"]: "sha256:" + hashlib.sha256(canonical({"result": f["digest"]}))
                             .hexdigest() for f in forms}
            salt = _salt(self._salt_key, "result:" + did)   # once per entry, not per form as _commit would
            for f in left:
                if commitment in ["hmac-sha256:" + hmac.new(salt, d.encode(), "sha256").hexdigest()
                                  for d in (f["result_digest"], as_digest[f["result_digest"]])]:
                    tx.set(run["results"], tcid, entries[:i] + [entries[i][:4] + [f["result_digest"]]] + entries[i + 1:])
                    return True
            if len(self._unmatched) > MAX_UNMATCHED:
                self._unmatched.clear()
            self._unmatched.update((did, f["result_digest"]) for f in left)
        return False

    def _approval_request(self, identity, req):
        identity, gw = self._as_caller(identity, "approval_request", req)
        key, top, holder = self._authorize(identity, req, gw), T2 if gw else {}, _holder(gw, req)
        tcid, sub = req["tool_call_id"], subject(identity)
        attempt = req.get("attempt", 0)
        self.quotas.take_event(identity, gw)
        aid, sid = f"{self.id_prefix}apr-{secrets.token_hex(16)}", secrets.token_hex(16)

        def fn(tx, run):
            call = run["calls"].get(tcid)
            self._hold(call, holder, tcid)
            had = self.log.approval_index.get((*key, tcid, attempt))
            if had:   # one approval per call attempt: asking again returns it, whatever its state
                a = self.log.approvals[had]
                return {"approval_id": had, "state": a["state"], "expires_at": a["expires_at"]}
            if call is None or call["attempt"] != attempt or not call.get("pending"):
                raise RPCError("unknown_tool_call", f"{tcid} attempt {attempt} has no pending `ask` decision")
            if run.get("quarantined"):
                raise RPCError("forbidden", self._why_contained(run))
            # a held run's approvals: answered by people only, on a budget of the run's own, not its owner's
            held = run.get("held") or []   # the hold a call was decided under, while it still holds the run
            iid = call.get("incident") if call.get("incident") in held else held[0] if held else None
            self.quotas.check_count("pending_approvals", sum(
                a["state"] == "requested" and bool(a.get("incident_id")) == bool(iid)
                and (a["run_key"] == key if iid else a["requester"] == sub) for a in self.log.approvals.values()))
            p = call["pending"]
            expires_at = _iso(time.time() + self.ttl_s)
            args, digest = self._args(p)
            binding = {"v": 1, "approval_id": aid, "tenant": key[0], "run_id": key[1], "tool_call_id": tcid,
                       "attempt": attempt, "tool": p["tool"], "args_commitment": self._commit("approval.request:" + sid, digest),
                       "args_source": p["args_source"],
                       "policy_hash": self.policy.policy_hash, "nonce": secrets.token_hex(16), "expires_at": expires_at}
            data = {"approval_id": aid, "decision_id": call["decision_id"], "policy_hash": self.policy.policy_hash,
                    "rule_ids": call["rule_ids"], "expires_at": expires_at, "requester": sub, "binding": binding,
                    "binding_digest": "sha256:" + hashlib.sha256(canonical(binding)).hexdigest(), "salt_id": sid}
            if person(identity):
                data["requester_person"] = person(identity)
            if gw:
                data["via"] = holder[0]
            if iid:
                data["incident_id"] = iid
            options = [r.get("approval") or {} for _, r, *_ in self.policy.rules if r["id"] in call["rule_ids"]]
            if any(o.get("executor") == "t2" for o in options):
                data["executor"] = "t2"
            if any(o.get("passkey") == "required" for o in options):
                data["passkey"] = True
            agent, reask = dict(call.get("agent") or {}), False
            spend = agent.pop("spend", {})
            if agent.get("eligible"):
                reason = f"held by incident {iid}: people answer it" if iid else \
                    self._capped(key, run, p["tool"], tcid, agent)
                if reason:
                    agent.update(eligible=False, reason=reason)
                    reask = reason.startswith("reask_after_reject")
            if agent:
                data["agent"] = agent
            shown = _shown(args, call["dotenv"])   # redact the parsed args, so a raw copy stays valid JSON
            if p["args_source"] == "raw":
                shown = p["args"] if shown == args else canonical(shown).decode()
            copy = {"args_source": p["args_source"], "args": shown}
            # what the executor runs (and an agent's bounds are shown against): the real arguments, never shown
            if data.get("executor") == "t2" or agent.get("eligible"):
                copy["exec_args"] = p["args"]
            if agent.get("eligible"):
                copy["spend"] = spend
            if "reason" in req:
                copy["reason"] = privacy.redact(req["reason"], call["dotenv"])[0]
            _write_new(os.path.join(self._args_dir, aid), self._seal(aid, copy))
            tx.set(self.log.approvals, aid, approval(*key, data, _iso(time.time())))
            tx.set(self.log.approval_index, (*key, tcid, attempt), aid)
            tx.set(call, "pending", None)   # the sealed copy on disk is what the approver sees from now on
            tx.emit(run, "approval.request", data, request_id=req["request_id"], tool_call_id=tcid, attempt=attempt, **top)
            if reask:
                tx.emit(run, "capture.gap", {"kind": "reask_after_reject", "tool_use_id": tcid, "reason": (
                    f"{tcid} asks again for a call an agent or a person did not approve in this run (approval {aid}): "
                    "people answer it")}, source="signer", tool_call_id=tcid)
            return {"approval_id": aid, "state": "requested", "expires_at": expires_at}
        try:
            return self.log.submit(identity, "approval_request", req, fn, key)
        except Exception:   # the item was rolled back: its copy goes too
            self._drop_args(aid)
            raise

    def _approval_decide(self, identity, req):
        if "on_behalf" in req:   # a bridge (the viewer) answers as the OIDC person its login established
            them = self._on_behalf(identity, req)
            return self._answer(them, req, subject(them), owner(them), bridge=identity)
        return self._answer(identity, req, subject(identity), owner(identity))

    def _approval_decide_on_behalf(self, identity, req):
        sub, groups = req["approver"], req.get("groups", [])
        if any(g.split("/")[0] != sub.split("/")[0] for g in groups):
            raise RPCError("invalid_request", "groups are user groups of the approver's own team")
        if sub in self._agents:
            raise RPCError("forbidden", f"{sub} is an agent approver: no bridge acts for it")
        scheme, _, rest = sub.partition(":")
        self._check_suspended(CallerIdentity(scheme, rest, False, {"groups": groups}), self._tenant_of(identity))
        return self._answer(identity, req, sub, sub, groups)

    def _answer(self, identity, req, sub, own, groups=None, bridge=None):
        """`identity` answers an approval as `sub` (`own`: as a run's owner would record it). `groups`: None when it
        answers for itself, else it is a bridge answering for `sub`, a member of `groups`. `bridge`: the identity that
        answers for the OIDC person `identity` (`on_behalf`)."""
        if self._is_agent(identity):
            return self._agent_answer(identity, req)
        if req["decision"] == "escalate":
            raise RPCError("invalid_request", "escalate is an agent approver's answer: a person approves or rejects")
        aid = req["approval_id"]
        a = self._visible(identity, aid)
        run_key = a["run_key"]
        who = self._persons.get(sub) if groups is not None else person(identity) or self._persons.get(sub)
        # read off the writer: a run gone final meanwhile keeps no people, and the writer refuses it (run_closed)
        owner_person, principal = self.log.runs[run_key].get("people", (None, None))
        if who and who == principal:
            raise RPCError("forbidden", f"{sub[:256]} is the run's principal and may not answer its approvals")
        same = self._self_approval(a, sub, own, *([who] if who else ())) or \
            bool(who) and who in (a.get("requester_person"), owner_person)
        held = a.get("incident_id")
        if held and not who:
            raise RPCError("forbidden", f"{a['tool_call_id'][:128]} is held by incident {held}: a person answers it (an "
                                        "identity approvals.persons maps, or an OIDC person)")
        if held and same:
            raise RPCError("forbidden", f"{sub[:256]} may not answer a held call of its own run, whatever self_approval "
                                        "says")
        glass = False
        if self.approvals is not None:
            if same:
                if self.approvals.get("self_approval") != "allow":
                    raise RPCError("forbidden", f"{sub[:256]} may not answer its own run's approval: answer as an "
                                                "identity signer.yaml's approvals.approvers lists, or set approvals: "
                                                "{self_approval: allow} there (assurance then stays dev)")
            elif not (self._in(self._approvers, identity) if groups is None else
                      any(lookup(self._approvers, x, False) for x in (sub, *groups))):
                glass = groups is None and self._in(self._break_glass, identity)
                if not glass:
                    raise RPCError("forbidden", f"{sub[:256]} is not an approver: signer.yaml's approvals.approvers "
                                                "lists who may answer")
                if not req.get("reason", "").strip():
                    raise RPCError("forbidden", "a break-glass answer needs a reason")
        # a retry of an answer is the writer's to answer from its request_id cache: its assertion's signCount is spent
        retry = (identity.scheme, identity.subject, req["request_id"]) in self.log.done
        credential = a.get("passkey") and req["decision"] == "approve" and not retry and \
            self._passkey(identity, aid, a, req.get("passkey"))
        self.quotas.take_event(identity)

        def fn(tx, run):
            a = self.log.approvals[aid]
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            if a["expires_at"] <= _iso(time.time()):
                raise RPCError("approval_not_pending", "expired")
            # checked here too: a retry that skipped the assertion, if the cache has since dropped its answer
            if a.get("passkey") and req["decision"] == "approve" and not credential:
                raise RPCError("forbidden", "approving this call needs a passkey assertion")
            tx.set(a, "state", "approved" if req["decision"] == "approve" else "rejected")
            data = {"tool_use_id": a["tool_call_id"], "approval_id": aid, "decision": req["decision"], "approver": sub,
                    "approver_identity": _recorded(identity),
                    "channel": "rpc", "self_approved": same}
            if groups is not None:   # the bridge vouches for the person; the record names both
                scheme, _, subj = sub.partition(":")
                data.update(approver_identity={"scheme": scheme, "subject": subj, "attested": False}, channel=scheme,
                            via=data["approver_identity"], **({"groups": groups} if groups else {}))
            if bridge is not None:
                data.update(channel="web", via=_recorded(bridge))
            if credential:
                data["passkey"] = {"credential_id": credential, "user_verified": True}
            if sub in self._persons:
                data["person"] = self._persons[sub]
            if glass:
                data["break_glass"] = True
            if "reason" in req:
                data["reason"] = req["reason"]
            if held:
                data["incident_id"] = held
            tx.emit(run, "approval", data, request_id=req["request_id"], tool_call_id=a["tool_call_id"])
            return {"approval_id": aid, "state": a["state"], "self_approved": same}
        out = self.log.submit(identity, "approval_decide" if groups is None else ON_BEHALF, req, fn, run_key)
        if out["state"] == "rejected":
            self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _agent_answer(self, identity, req):
        """Agent approver `identity` answers an agent-eligible approval: approve (within its rules' budgets, else the
        signer escalates it), reject, or escalate (people answer it from then on). In shadow mode its answer is an
        approval.suggested that changes nothing. Never a self-approval: an agent that is the requester, the run's
        owner or its attested principal is refused."""
        aid, sub, decision = req["approval_id"], subject(identity), req["decision"]
        a = self._visible(identity, aid)
        run = self.log.runs[a["run_key"]]
        if sub in (a["requester"], run["owner"]) or person(identity) and \
                person(identity) in (a.get("requester_person"), *run.get("people", (None, None))):
            raise RPCError("forbidden", f"{sub[:256]} may not answer its own run's approval")
        rules = self._agent_rules(a["agent"]["rules"])
        shadow = any(r["approval"]["agent"]["mode"] == "shadow" for r in rules)
        veto_s = max((r["approval"]["agent"].get("veto_s", 0) for r in rules), default=0)
        copy = self._unseal(aid) if decision == "approve" else {}
        if copy is None:   # its sum budget's spend is in the copy: an approval without one can't be counted
            raise RPCError("approval_not_pending",
                           f"{aid}: the signer's copy of its arguments is gone; people answer it")
        spend = copy.get("spend", {})
        self.quotas.take_event(identity)
        data = {"tool_use_id": a["tool_call_id"], "approval_id": aid, "decision": decision, "approver": sub,
                "approver_identity": _recorded(identity), "channel": "rpc", "approver_kind": "agent"}
        if "asserted" in req:   # what the agent says it runs: recorded as its claim
            data["asserted"] = dict(req["asserted"], attested=False)
        if "reason" in req:
            data["reason"] = privacy.redact_text(req["reason"])[0]
        top = {"request_id": req["request_id"], "tool_call_id": a["tool_call_id"]}

        def fn(tx, run):
            a, now = self.log.approvals[aid], time.time()
            if a["state"] != "requested" or a["expires_at"] <= _iso(now):
                raise RPCError("approval_not_pending", a["state"] if a["state"] != "requested" else "expired")
            why = self._agent_refusal(a)
            if why:
                raise RPCError("forbidden", why)
            if shadow:
                tx.emit(run, "approval.suggested", data, **top)
                return {"approval_id": aid, "state": "requested", "self_approved": False, "suggested": True}
            short = decision == "approve" and self._short(self._budgets(run["tenant"], a["requester"], rules, now), spend)
            if decision == "escalate" or short:
                esc = {"approval_id": aid, "by": "signer", "reason": f"the budget of rule {short} is used up"} if short \
                    else {"approval_id": aid, "by": "agent", "approver_identity": data["approver_identity"],
                          **({"reason": data["reason"]} if "reason" in data else {})}
                tx.emit(run, "approval.escalated", esc, **top)
                return {"approval_id": aid, "state": "requested", "self_approved": False, "escalated": True}
            d = dict(data)
            if decision == "approve":   # consumed within agent_consume_s after the veto delay, or never
                d.update(not_before=_iso(now + veto_s), consume_by=_iso(now + veto_s + self.agent_consume_s),
                         **({"spent": spend} if spend else {}))
            tx.set(a, "state", "approved" if decision == "approve" else "rejected")
            tx.emit(run, "approval", d, **top)
            return {"approval_id": aid, "state": a["state"], "self_approved": False}
        out = self.log.submit(identity, "approval_decide", req, fn, a["run_key"])
        if out["state"] == "rejected":
            self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _approval_review(self, identity, req):
        """What an agent approver reviews (docs/approvals.md#what-the-reviewer-sees): the tool, the rules with the
        policy's reason and rationale, each bound and whether it passed, the budget left, the signer's redacted
        arguments with control and bidi characters escaped and which arguments redaction changed, and a
        `view_digest` over all of it. Never the requesting agent's reason, the run, the tool call id or where a value
        came from."""
        if not self._is_agent(identity):
            raise RPCError("forbidden", "approval_review is for agent approvers (approvals.agents)")
        aid = req["approval_id"]
        a = self.log.write(lambda tx: dict(self._visible(identity, aid)))   # committed state only
        copy = self._unseal(aid)
        if a["state"] != "requested" or a["escalated"] or copy is None:
            raise RPCError("approval_not_pending", "escalated" if a["escalated"] else a["state"])
        real = loads_strict(copy["exec_args"]) if copy["args_source"] == "raw" else copy["exec_args"]
        shown = loads_strict(copy["args"]) if copy["args_source"] == "raw" else copy["args"]
        rules = self._agent_rules(a["agent"]["rules"])
        try:
            deadline = time.monotonic() + engine.REGEX_TIMEOUT_S
            conditions = [{"rule": r["id"], "condition": c[:1024], "passed": ok}
                          for r in rules for c, ok in self.policy.bounds(r, real, deadline)]
        except TimeoutError:
            conditions = [{"rule": "", "condition": "a bound's pattern ran out of time", "passed": False}]
        view = {"approval_id": aid, "tool": a["tool"], "expires_at": a["expires_at"],
                "rules": [{"id": r["id"], **{k: r[k][:1024] for k in ("reason", "rationale") if k in r}} for r in rules],
                "conditions": conditions, "budget": self._budgets(a["run_key"][0], a["requester"], rules, time.time()),
                "args": _escaped(shown),
                "redacted": sorted(_escaped(k)[:4096] for k, v in (shown.items() if isinstance(shown, dict) else ())
                                   if MARK.search(canonical(v).decode()))}
        return {**view, "view_digest": "sha256:" + hashlib.sha256(canonical(view)).hexdigest()}

    def _approval_revoke(self, identity, req):
        """A person vetoes an agent's approval that is not consumed yet (`approval.revoked`): the call never runs."""
        identity, aid = self._on_behalf(identity, req), req["approval_id"]
        a = self._visible(identity, aid)
        if self.approvals is not None and not (self._in(self._approvers, identity) or
                                               self._in(self._break_glass, identity)):
            raise RPCError("forbidden", f"{subject(identity)[:256]} is not an approver")
        self.quotas.take_event(identity)

        def fn(tx, run):
            a = self.log.approvals.get(aid, {})
            if a.get("kind") != "agent" or a["state"] != "approved":
                raise RPCError("approval_not_pending", "only an agent's approval not consumed yet is revoked")
            return self._revoke(tx, run, aid, subject(identity)[:256], req.get("reason"), req["request_id"])
        out = self.log.submit(identity, "approval_revoke", req, fn, a["run_key"], late=True)
        self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _revoke(self, tx, run, aid, by, reason=None, request_id=None):
        a = self.log.approvals[aid]
        tx.set(a, "state", "rejected")
        tx.emit(run, "approval.revoked", {"approval_id": aid, "by": by, **({"reason": privacy.redact_text(reason)[0]}
                                                                          if reason else {})},
                source="signer", tool_call_id=a["tool_call_id"], **({"request_id": request_id} if request_id else {}))
        return {"approval_id": aid, "state": "rejected"}

    def _approval_agents(self, identity, req):
        """The operator's kill switch: switch agent approvals off (every agent approval not consumed yet is revoked,
        every pending one an agent could answer is escalated, and people answer every approval from then on) or on
        again; a signed `approval.agents`."""
        by = subject(identity)[:256]
        self.quotas.take_event(identity)

        def fn(tx, _):
            revoked = []
            if not req["enabled"]:
                for aid, a in list(self.log.approvals.items()):
                    if a.get("kind") == "agent" and a["state"] == "approved":
                        self._revoke(tx, self.log.runs[a["run_key"]], aid, "signer", "agent approvals switched off")
                        revoked.append(aid)
                    elif a["state"] == "requested" and (a.get("agent") or {}).get("eligible") and not a["escalated"]:
                        tx.emit(self.log.runs[a["run_key"]], "approval.escalated", {
                            "approval_id": aid, "by": "signer", "reason": "agent approvals switched off"},
                                source="signer", tool_call_id=a["tool_call_id"])
            tx.emit(self.log.signer_run(tx), "approval.agents", {
                "enabled": req["enabled"], "by": by, **({"reason": privacy.redact_text(req["reason"])[0]}
                                                        if "reason" in req else {})}, source="signer",
                request_id=req["request_id"])
            return {"enabled": req["enabled"], "revoked": revoked}
        out = self.log.submit(identity, "approval_agents", req, fn)
        for aid in out["revoked"]:
            self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _approval_wait(self, identity, req):
        identity, gw = self._as_caller(identity, "approval_wait", req)
        aid = req["approval_id"]   # only waits for a state the run's records show anyway: no hold
        a = self._approval(self._authorize(identity, req, gw), aid)
        # a held run's waits use a budget of the run's own, so they don't starve its owner's healthy runs
        slot = ("held", "/".join(a["run_key"])) if a.get("incident_id") else quota_key(identity, gw)

        def waiting(a, now):   # an agent's approval waits out its veto delay: people may still revoke it
            return a["state"] == "requested" or a["state"] == "approved" and a.get("not_before", "") > _iso(now)
        end = time.monotonic() + req.get("timeout_ms", 0) / 1000
        with self.quotas.wait_slot(slot), self._cond:
            while ((a := self.log.approvals.get(aid)) is not None and waiting(a, time.time())
                   and end > time.monotonic()):
                self._cond.wait(min(end - time.monotonic(), TICK_S))

        # read on the writer, so only a committed state is answered; gone: its run went final, which expired it
        def state(tx):
            a = self.log.approvals.get(aid, {"state": "expired"})
            return {"state": "requested" if waiting(a, time.time()) else a["state"],
                    **({"escalated": True} if a.get("escalated") else {})}
        return {"approval_id": aid, **self.log.write(state)}

    def _approval_consume(self, identity, req):
        identity, gw = self._as_caller(identity, "approval_consume", req)
        key, tcid, attempt, hint = self._authorize(identity, req, gw), req["tool_call_id"], req.get("attempt", 0), \
            req.get("approval_id_hint")
        holder = _holder(gw, req)
        held = (self.log.runs[key].get("calls", {}).get(tcid) or {}) if gw else {}
        if not (held and (held.get("via"), held.get("caller")) == holder):   # a gateway's consume of its own call:
            self.quotas.take_event(identity, gw)                           # its decide paid, as for its result
        args, digest = self._args(req)
        bound = self.log.approval_index.get((*key, tcid, attempt))
        # read before the writer runs: the copy is deleted once the approval is consumed
        copy = self._unseal(bound) if bound and self.log.approvals.get(bound, {}).get("executor") == "t2" else None

        def fn(tx, run):
            aid = self.log.approval_index.get((*key, tcid, attempt))
            a, call, top = self.log.approvals.get(aid), run["calls"].get(tcid), {"tool_call_id": tcid, "attempt": attempt}
            self._hold(call, holder, tcid)
            if run.get("quarantined"):
                why = "TK-QUARANTINE", self._why_contained(run)
            elif run.get("held") and not (a and a.get("incident_id") in run["held"]):   # expired by the holds
                why = "TK-HOLD", self._why_contained(run)
            elif hint is not None and hint != aid:
                why = "TK-APPROVAL-UNBOUND", "approval_id not bound to this call"
            elif digest is None:
                why = "TK-ARGS-INVALID", "the arguments are not canonical JSON"
            elif a is None:
                if (call and call["attempt"] == attempt and call["decision"] in ("allow", "flag")
                        and self._same(call, digest)):
                    return {"ok": True, "rule_ids": []}   # needed no approval
                why = "TK-APPROVAL-REQUIRED", "approval required but none was requested for this call"
            elif not self._opens(a["commitment"], a["label"], digest):
                sid = secrets.token_hex(16)
                tx.emit(run, "approval.binding_mismatch", {
                    "approval_id": aid, "decision_id": a["decision_id"], "tool_use_id": tcid,
                    "approved_commitment": a["commitment"],
                    "args_commitment": self._commit("approval.binding_mismatch:" + sid, digest), "salt_id": sid},
                        source="signer", **top)
                return {"ok": False, "rule_ids": ["TK-APPROVAL-MISMATCH"], "approval_id": aid,
                        "reason": "the arguments differ from the approved ones"}
            elif a["state"] != "approved":
                why = "TK-APPROVAL-" + a["state"].upper(), f"not approved (state={a['state']})"
            elif a["expires_at"] <= _iso(time.time()) or a.get("consume_by", "~") <= _iso(time.time()):
                why = "TK-APPROVAL-EXPIRED", "the approval expired"
            elif a.get("not_before", "") > _iso(time.time()):
                why = "TK-APPROVAL-VETO", f"an agent's approval: people may revoke it until {a['not_before']}"
            else:
                out = {"ok": True, "rule_ids": ["TK-APPROVED"], "approval_id": aid}
                if a["executor"] == "t2":
                    if copy is None:
                        raise RPCError("unavailable", f"the stored arguments of {aid} are gone")
                    out["args"] = None   # filled in below: the request_id cache keeps no arguments
                tx.set(a, "state", "consumed")
                tx.emit(run, "approval.consumed", {"approval_id": aid}, source="signer", **top)
                rec = run.get("rec")
                if rec is not None:   # an approved call explains what it was decided for (reconcile.explained)
                    if tcid in rec["l2"]:
                        tx.set(rec["l2"][tcid], "approved", True)
                    if tcid in rec.get("asked_hosts", {}):
                        tx.set(reconcile.sub(tx.set, rec, "hosts"), rec["asked_hosts"][tcid], True)
                return out
            data = {"tool_use_id": tcid, "rule_ids": [why[0]], "reason": why[1]}
            if a is not None:
                data["approval_id"] = aid
            tx.emit(run, "approval.refused", data, source="signer", **top)
            return {"ok": False, **{k: v for k, v in data.items() if k != "tool_use_id"}}
        out = self.log.submit(identity, "approval_consume", req, fn, key)
        if "args" in out:   # T2: the approved copy; a retry, which the cache answers, opened the same commitment
            out["args"] = args if copy is None else \
                loads_strict(copy["exec_args"]) if copy["args_source"] == "raw" else copy["exec_args"]
        if out["ok"] and "approval_id" in out:
            self._drop_args(out["approval_id"])
        return out

    def _approval_get(self, identity, req):
        identity, aid = self._on_behalf(identity, req), req["approval_id"]
        a = self.log.write(lambda tx: dict(self._visible(identity, aid)))   # committed state only
        copy = self._unseal(aid) or {"args_source": a["args_source"], "args": None}
        copy.pop("exec_args", None)   # the approver sees the redacted copy only
        copy.pop("spend", None)
        return {**self._summary(aid, a), "binding_digest": a["binding_digest"], **copy}

    def _approval_list(self, identity, req):
        identity = self._on_behalf(identity, req)
        agent_view = self._is_agent(identity)
        if agent_view and "run_id" in req:   # an agent never learns which run an approval belongs to
            raise RPCError("forbidden", "an agent approver lists approvals without a run_id")
        # copied on the writer, so only committed states are listed
        items = iter(self.log.write(lambda tx: [
            (aid, {**a, "run_closing": a["state"] == "requested" and self.log.runs[a["run_key"]]["closed"]})
            for aid, a in self.log.approvals.items()]))
        page, cursor = [], req.get("cursor")
        # lean: every page scans the approvals from the first; index them by tenant once a signer holds ~100k
        if cursor is not None:
            for aid, _ in items:
                if aid == cursor:
                    break
        for aid, a in items:   # for: agent, those an agent may still answer (shadow too); person, those it can't decide
            if req.get("run_id") in (None, a["run_key"][1]) and req.get("state") in (None, a["state"]) and \
                    req.get("escalated") in (None, bool(a.get("escalated"))) and self._may_see(identity, a) and (
                    "for" not in req or req["for"] == "agent" and self._agent_mode(a) is not None
                    or req["for"] == "person" and self._agent_mode(a) != "enforce"):
                if len(page) == req.get("limit", LIST_PAGE):
                    return {"approvals": page, "next_cursor": page[-1]["approval_id"]}
                s = {**self._summary(aid, a), **({"run_closing": True} if a["run_closing"] else {})}
                page.append({k: v for k, v in s.items() if k not in ("run_id", "tool_call_id", "attempt", "requester",
                                                                     "passkey", "answered", "escalation")}
                            if agent_view else s)
        return {"approvals": page, "next_cursor": None}

    def _approval_abandon(self, identity, req):
        key, aid = self._authorize(identity, req), req["approval_id"]
        self._approval(key, aid)

        def fn(tx, run):
            a = self.log.approvals[aid]
            # takes no caller: an approval of a gateway's call expires on its own, or with its run
            self._hold(run["calls"].get(a["tool_call_id"]), (None, None), a["tool_call_id"])
            if a["state"] not in LIVE:
                raise RPCError("approval_not_pending", a["state"])
            tx.set(a, "state", "expired")
            data = {"approval_id": aid, **({"reason": privacy.redact_text(req["reason"])[0]} if "reason" in req else {})}
            tx.emit(run, "approval.abandoned", data, request_id=req["request_id"], tool_call_id=a["tool_call_id"],
                    attempt=a["attempt"])
            return {"approval_id": aid, "state": "expired"}
        out = self.log.submit(identity, "approval_abandon", req, fn, key)
        self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _close_run(self, identity, req):
        # a gateway (`caller`, for a client granted model_event) ends its stream of the client's run: the run stays as
        # it is
        identity, gw = self._as_caller(identity, "model_event", req)
        key = self._authorize(identity, req, gw)
        self.quotas.take_event(identity, gw)
        who = writer(identity, req)

        def fn(tx, run):
            # a gateway's report may come after run.final (it reports when it drops the run from memory or stops): its
            # gaps then go in the tenant's signer run
            run = run or self.log.runs[key]
            into = self.log.signer_run(tx, key[0]) if run["final"] else run
            streams, writers, tails = (run.get(k, {}) for k in ("streams", "writers", "tails"))   # {}: final before 1.2
            wrote = False
            for s in req.get("last_client_seq", ()):
                stream, end = s["stream"], s["client_seq"]
                last = max(streams.get(stream, -1), tails.get(stream, -1))
                # only the closer's own streams, one that never reached the signer, or one whose writer a restart
                # forgot (writers are not in the records): a gap then rather than none
                if writers.get(stream, who) != who or end <= last:
                    continue
                tx.emit(into, "capture.gap", {
                    "kind": "client_counter_gap", "missed_events": end - last,
                    **({"run_id": key[1]} if into is not run else {}),
                    "reason": f"{who[:256]} said stream {stream} of run {key[1]} ended at client_seq {end}; "
                              f"{last + 1}..{end} had not reached the signer then: the client stopped or lost them "
                              "before they were sent; read its log for what they were"},
                        source="signer", stream=stream)
                wrote = True
                if into is run:   # the counter stays: values that still arrive are taken as usual, with no new gap
                    tx.set(tails, stream, end)
            if run["closed"] and not gw and not wrote:
                raise RPCError("run_closed", key[1])
            if gw or run["closed"]:   # a run the signer closed meanwhile (idle, grace) still gets the client's gaps
                return {"run_id": req["run_id"], "state": "closing" if run["closed"] else "open",
                        "run_seq": run["run_seq"] - 1}
            return {"run_id": req["run_id"], "state": "closing",
                    "run_seq": tx.closing(run, "close_run", request_id=req["request_id"])}
        # not a write to the run but its end: no run check (a closed run's gaps are still taken), no activity
        return self.log.submit(identity, "close_run", req, fn)

    def _tailer_heartbeat(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)
        with self._beats_lock:   # final checked under the lock: a sweep drops a final run's beat under it
            if self.log.runs[key]["final"]:
                raise RPCError("run_closed", req["run_id"])
            self._beats[key] = time.monotonic()
        return {}

    def _delegate_run(self, identity, req):
        key = self._authorize(identity, req)
        if lookup(self.authorize, req["identity"]) is None:   # unconfigured, it would keep every method of the run
            raise RPCError("forbidden", f"{req['identity'][:256]} has no authorize entry to delegate the run to")
        to = CallerIdentity(*req["identity"].split(":", 1), True)
        if not self._tailer(to):
            return {"run_token": self.tokens.issue(*key, to)}

        watch = []

        def fn(tx, _):   # a transcript tailer's token: one per run, and watched from now (any state, as any delegation)
            run = self.log.runs[key]
            if not run["final"]:
                # lean: which runs have one is memory and snapshot state; a second token across a restart with no
                # snapshot after the first is not flagged
                if run.get("tailed"):
                    tx.emit(run, "capture.gap", {
                        "kind": "tailer_redelegated",
                        "reason": f"{subject(identity)[:256]} took a second transcript tailer token for this run (for "
                                  f"{req['identity'][:256]}): the run's transcript records and heartbeats may come "
                                  "from a tailer other than the one its hook started; compare them with the transcript "
                                  "itself"}, source="signer")
                tx.set(run, "tailed", True)
                watch.append(key)
            return {"run_token": self.tokens.issue(*key, to)}
        out = self.log.submit(identity, "delegate_run", req, fn)
        with self._beats_lock:   # a tailer killed before its first heartbeat is lost too
            for k in watch:
                self._beats.setdefault(k, time.monotonic())
        return out

    def _tailer_lost(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)

        def fn(tx, run):
            return {"run_seq": tx.emit(run, "capture.gap", {
                "kind": "tailer_lost",
                "reason": f"{privacy.redact_text(req['reason'])[0]} (at transcript offset {req['offset']}; "
                          f"reported by {subject(identity)[:256]})"},
                source="signer", request_id=req["request_id"])}
        out = self.log.submit(identity, "tailer_lost", req, fn, key, late=True)
        if self.log.runs[key]["source"] != "import":   # a transcript tailer's last call: its silence is no second loss;
            with self._beats_lock:                     # a log follower goes on after a gap, so it stays watched
                self._beats.pop(key, None)
        return out

    def _observe_effect(self, identity, req):
        """An egress observer's effects (tracekit.egress): each an effect.observed in the run it is attributed to while
        that run is open or closing, then reconciled (a host nothing explains is one reconcile.unexplained_effect);
        else a capture.gap{effect_outside_run} in the tenant's signer run, which a run-set shows. Every call is the
        observer's heartbeat: the runs of its tenant registered while it is alive are covered by it, until another
        process of it (`instance`) takes over, which is an observer_lost gap in each; the process taken over from is
        refused from then on (two live processes of one identity). `check`: refused unless this
        signer issued that run token for that run of the observer's tenant (the proxy asks before it connects).
        A kernel sensor's import (tracekit.sensor; `sensor` and `callers` in every call) is an observer the same way, of
        processes rather than network, covering only the runs of the identities its `runs` map processes to
        (`callers`): its effects (_sensor_effect) are recorded but not reconciled; it says it observed a run only once
        it recorded an event of it (with an import per node, the run's node's alone), and `lost` is an observer_lost gap
        in each run it covers (in the signer run when it covers none) after which it says so of none of them, though
        their watch of its silence goes on; an effect attributed to a run no caller owns is an effect_outside_run
        gap. OpenShell's import (tracekit.openshell, sensor openshell,
        its own identity its one caller) also sends a sandbox policy change (an `ext` record openshell.policy) and a
        loss of one run's events (an observer_lost gap in that run only). A configured gateway may observe the runs it
        registered for the clients it serves: it is not their agent."""
        obs, tenant, sensor = subject(identity), self._tenant_of(identity), req.get("sensor")
        callers = frozenset(req.get("callers", ()))
        if len(obs) > 256:   # each record names it in full
            raise RPCError("forbidden", f"{obs[:64]}...: an observer's identity is at most 256 characters")
        if any((x["kind"] == "net") == bool(sensor) or x["kind"] in ("policy", "lost") and sensor != "openshell"
               for x in req["effects"]) or bool(sensor) != ("callers" in req) or "lost" in req and not sensor:
            raise RPCError("invalid_request", "net effects go without `sensor`; a kernel sensor's events and `lost` "
                                              "go with it, and `callers` with every call of it; policy and lost "
                                              "effects are OpenShell's")
        if sensor == "openshell" and callers != {owner(identity)}:   # it observes the runs it registered, no other
            raise RPCError("invalid_request", f"OpenShell's import observes the runs it registered: its callers are "
                                              f"its own identity, [{owner(identity)[:256]}]")
        was = self._observers.get((tenant, obs))
        if was and was[2] != sensor:   # run.final classes its coverage by its kind (_finish_run)
            kind = f"the {was[2]} import" if was[2] else "an egress observer"
            raise RPCError("invalid_request", f"{obs[:256]} observes as {kind}: one identity is one observer; give "
                                              "each its own")
        if "check" in req:   # before anything is charged: a made-up token must not spend the observer's events
            why = self._attributed(tenant, req["check"])[2]
            if why:
                raise RPCError("run_token_invalid", why)
        if req["effects"] or "check" not in req:   # one token check per proxied connection costs no event
            self.quotas.take_event(identity)
        now = time.monotonic()
        # coverage ends only once the gap that ends it is written: until then the old process stays the one on record,
        # so a call sent again after a failed write still finds the runs it covered
        with self._beats_lock:
            if req["instance"] in self._superseded.get((tenant, obs), ()):
                raise RPCError("conflict", f"another process of observer {obs[:256]} took over from this one, which "
                                           "still sends: two processes share one identity (an import per node under "
                                           "one identity?); give each its own identity, or run one")
            before = self._observers.get((tenant, obs))
            self._observers[(tenant, obs)] = (now, before[1] if before else req["instance"], sensor, callers)
            covered = [k for k in self._beats if len(k) == 3 and k[0] == tenant and k[2] == obs]
            restarted = covered if before and before[1] != req["instance"] else []
            lost = covered if "lost" in req and not restarted else []
            for k in [] if restarted else covered:   # after a loss it stays watched: its silence is a gap still
                if sensor and self.log.runs[k[:2]]["owner"] not in callers:   # its runs map no longer names the owner
                    self._beats.pop(k)
                else:
                    self._beats[k] = now
        if restarted:
            self.log.write(lambda tx: [self._observer_lost(tx, self.log.runs[k[:2]], obs) for k in restarted
                                       if not self.log.runs[k[:2]]["final"]])
        with self._beats_lock:
            self._observers[(tenant, obs)] = (now, req["instance"], sensor, callers)
            if before and before[1] != req["instance"]:
                self._superseded[(tenant, obs)].append(before[1])
            for k in restarted:
                self._beats.pop(k, None)
        if not req["effects"] and "lost" not in req:
            return {"recorded": 0}
        labels = {r["id"]: r["label"] for _, r, *_ in self.policy.rules if "label" in r}
        explains = self.policy.policy.get("explains", ())
        gateway = lookup(self._gateways, obs, False)
        sensed = set()

        def fn(tx, _):
            if "lost" in req:
                for run in [self.log.runs[k[:2]] for k in lost if not self.log.runs[k[:2]]["final"]] or [
                        self.log.signer_run(tx, tenant)]:
                    self._observer_lost(tx, run, obs, lost=req["lost"])
            for x in req["effects"]:
                key, how, why = self._attributed(tenant, x)
                run = key and self.log.runs.get(key)
                if run and run["owner"] == owner(identity) and not gateway:
                    raise RPCError("forbidden", f"{obs[:256]} owns run {key[1]}: an observer is never the agent's "
                                                f"identity; give the {'sensor import' if sensor else 'egress proxy'} "
                                                "its own")
                if run and sensor and run["owner"] not in callers:   # an import covers its callers' runs alone
                    why, run = f"run {key[1]} is {run['owner'][:256]}'s, none of the import's callers", None
                if not run or run["final"]:
                    why = why or (f"run {key[1]} was final by then (raise observe_grace_s if the observer's reports "
                                  "often come this late)" if run else f"there is no run {key[1]}")
                    claimed = x.get("run_id") or key and key[1]
                    target = f" {x['host']}:{x['port']}" if "host" in x else f" {x['path'][:256]}" if "path" in x else ""
                    saw = (f"a loss: {privacy.redact_text(x['reason'])[0]}" if x["kind"] == "lost" else
                           f"a policy change ({x['change']}) at {x['ts']}" if x["kind"] == "policy" else
                           f"{x['kind']}{target} by pid {x['pid']} ({x['binary'][:256]}) at {x['ts']}" if sensor else
                           f"{x['host']}:{x['port']} ({x['bytes_out']} bytes out, {x['bytes_in']} in, "
                           f"{x['connections']} connection(s), {x['first_ts']} to {x['last_ts']})")
                    tx.emit(self.log.signer_run(tx, tenant), "capture.gap", {
                        "kind": "effect_outside_run", **({"run_id": claimed} if claimed else {}),
                        "reason": f"{sensor or 'egress observer'} {obs[:256]} saw {saw} that no open run holds: "
                                  f"{why}"}, source="signer")
                    continue
                if x["kind"] == "lost":
                    self._observer_lost(tx, run, obs, lost=x["reason"])
                    continue
                if x["kind"] == "policy":
                    tx.emit(run, "ext", self._policy_change(obs, x, how), source="signer")
                    continue
                if sensor:
                    tx.emit(run, "effect.observed", self._sensor_effect(obs, sensor, x, how), source="signer")
                    sensed.add((*key, obs))
                    continue
                rec = run.get("rec")
                by = rec is not None and reconcile.explained(rec, x["host"], explains, labels) or None
                tx.emit(run, "effect.observed", {"observer": obs, **{k: x[k] for k in (
                    "kind", "host", "port", "bytes_out", "bytes_in", "connections", "first_ts", "last_ts")},
                    "attribution": how, **({"explained_by": by} if by else {})}, source="signer")
                if by or rec is None or x["host"] in rec.get("effects", {}):   # once per host
                    continue
                tx.set(reconcile.sub(tx.set, rec, "effects"), x["host"], True)
                tx.emit(run, "reconcile.unexplained_effect", {
                    "layers": ["L6"], "observer": obs, "kind": x["kind"], "host": x["host"], "port": x["port"],
                    "detail": f"the run reached {x['host'][:253]}:{x['port']} and no http or model call to it nor "
                              "explains entry of the policy covers it: if one of the run's tools needs it (a CDN, a "
                              "package index), add it to the policy's explains; else find which call opened it"},
                        source="signer")
            return {"recorded": len(req["effects"])}
        out = self.log.submit(identity, "observe_effect", req, fn)
        with self._beats_lock:
            for k in sensed:
                self._sensed.setdefault(k, True)
            for k in lost:   # its loss ends what it may say of the run, not the watch of its silence
                self._sensed[k] = False
        return out

    def _sensor_effect(self, obs, sensor, x, how):
        """effect.observed of kernel sensor event `x`: the arguments' digest as a commitment. The tool call id the
        process's environment carried is the agent's claim, recorded as such: the agent sets that environment, so the
        signer never takes it as explaining the effect (tracekit analyze --v2's TK-X206 checks it against the call)."""
        # lean: an effect nothing explains is not reconciled (no reconcile.unexplained_effect, no count in run.final);
        # add it once runs carry a tool call id into every process (Codex does, Claude Code doesn't)
        d = {"observer": obs, "sensor": sensor, **{k: x[k] for k in (
            "kind", "ts", "pid", "binary", "exec_id", "parent_exec_id", "status", "signal", "host", "port", "path",
            "tool_call_id", "denied")
            if k in x}, "attribution": how}
        if "args_digest" in x:
            sid = secrets.token_hex(16)
            d.update(args_commitment=self._commit(salt_label({"type": "effect.observed", "data": {"salt_id": sid}}),
                                                  x["args_digest"]), salt_id=sid)
        return d

    def _policy_change(self, obs, x, how):
        """The `ext` record openshell.policy of OpenShell's sandbox policy change `x`: its message as a commitment."""
        d = {"name": "openshell.policy", "observer": obs, **{k: x[k] for k in ("ts", "change", "policy_hash", "by")
                                                             if k in x}, "attribution": how}
        if "detail_digest" in x:
            sid = secrets.token_hex(16)
            d.update(detail_commitment=self._commit(salt_label({"type": "ext", "data": {"salt_id": sid}}),
                                                    x["detail_digest"]), salt_id=sid)
        return d

    def _attributed(self, tenant, x):
        """(run key or None, attribution, why there is none) of effect `x` of an observer of `tenant` (on the writer):
        the run its run token names, unless this signer didn't issue that token for that run of `tenant`, or issued it
        to another identity than the client's (`caller`); else the latest open run of `caller` registered by the
        effect's `ts` (a kernel sensor's: an event read late goes to the run it happened in, an old one to none), or
        with none, its first registered up to SENSOR_SKEW_S after `ts`."""
        why = None
        if "run_token" in x:
            try:
                claims = self.tokens.claims(x["run_token"])
            except RPCError:
                claims = {}
            if (claims.get("tenant"), claims.get("run_id")) != (tenant, x.get("run_id")):
                why = "the run token the client presented is not one this signer issued for that run of its tenant"
            elif x.get("caller", claims["sub"]) != claims["sub"]:
                why = f"the run token the client presented was issued to {claims['sub'][:256]}, not {x['caller']}"
            else:
                return (tenant, claims["run_id"]), "token", None
        if "caller" not in x:
            return None, "token", why or "the client presented neither a run token nor an identity"
        why = why + ", and " if why else ""
        c = CallerIdentity(*x["caller"].split(":", 1), True)
        if self._tenant_of(c) != tenant:
            return None, "identity", f"{why}{x['caller'][:256]} is of another tenant than the observer"
        # lean: the owner's latest open run registered by the effect's time takes it, else its first registered within
        # SENSOR_SKEW_S after (the sensor's clock behind the signer's); with concurrent runs of one owner, send the run
        # token instead
        runs = [k for k in self.log.live if k[0] == tenant and self.log.runs[k]["owner"] == owner(c)]
        at = x.get("ts", "~")
        key = next((k for k in reversed(runs) if self.log.runs[k].get("registered", "") <= at), None) or next(
            (k for k in runs if "ts" in x and self.log.runs[k].get("registered", "") <= _iso(
                epoch(at) + SENSOR_SKEW_S)), None)
        return key, "identity", None if key else f"{why}{x['caller'][:256]} has no open run" + (
            f" registered by {at}" if "ts" in x else "")

    def _finding(self, identity, req, method, type_, data, cites=()):
        """Write a `type_` record of `data` in the caller's findings run (registered with `analyzes`, which only an
        identity signer.yaml `analyzers` lists may do); refused in any other run, and refused unless each of `cites`
        is a record of the analysed run with that hash (a verifier fails a bundle on one that isn't, so a made-up cite
        would turn an intact run's bundle FAILED)."""
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)   # before the reads: a refused call costs them too
        try:
            first = next(iter(self.log.storage.iter_run(*key)))["event"]
            if "analyzes" not in first["data"]:
                raise RPCError("forbidden", f"a {type_} goes in a findings run: register_run with `analyzes` "
                                            "(signer.yaml `analyzers` lists who may)")
            bad = self._bad_cite(key[0], first["data"]["analyzes"], cites)
        except (OSError, StorageUnavailable) as e:
            raise RPCError("unavailable", f"storage read failed: {e}") from None
        if bad:
            raise RPCError("invalid_request", f"cites {bad}: cite records of the analysed run, with their hashes")

        def fn(tx, run):
            return {"run_seq": tx.emit(run, type_, data, request_id=req["request_id"])}
        return self.log.submit(identity, method, req, fn, key)

    def _why_finding(self, identity, req):
        return self._finding(identity, req, "why_finding", "why.finding", req["finding"])

    def _constraint_add(self, identity, req):
        """A live constraint of the caller's run (module docstring): constraint.added, with the commitment of its file
        name under the record's own salt, never the name; tighten-only, so any client of the run may add one. One
        equal to a live constraint of the run (the same kind, and for a file the same name: its commitment opens) is
        that one: its run_seq, nothing written. Past MAX_CONSTRAINTS file constraints (keep_away, only_change; a kind
        that names no file has at most one each and is always added) a new file constraint is a signed capture.gap
        constraint_refused (its run_seq, and `refused` for the hook to warn), never dropped unrecorded, and the run
        fails closed: every later write is held (_constrained), so made-up constraints only make the agent wait."""
        key, c = self._authorize(identity, req), req["constraint"]
        if (c["kind"] in constraints.OBJECT_KINDS) != ("object" in c) or "object" in c and not constraints.norm(
                c["object"]):
            raise RPCError("invalid_request", "keep_away and only_change name the file (`object`); the other kinds "
                                              "name none")
        self.quotas.take_event(identity)
        data, name = {"kind": c["kind"]}, constraints.digest(c["object"]) if "object" in c else None
        if name:
            data["salt_id"] = secrets.token_hex(16)
            data["object_commitment"] = self._commit(salt_label({"type": "constraint.added", "data": data}), name)

        def fn(tx, run):
            have = run.get("constraints") or []
            same = next((seq for kind, label, commitment, seq in have if kind == c["kind"] and (
                not name or self._opens(commitment, label, name))), None)
            if same is not None:
                return {"run_seq": same}
            if name and sum(kind in constraints.OBJECT_KINDS for kind, *_ in have) >= MAX_CONSTRAINTS:
                tx.set(run, "constraints_full", True)
                return {"run_seq": tx.emit(run, "capture.gap", {"kind": "constraint_refused", "reason": (
                    f"the run has {MAX_CONSTRAINTS} live file constraints, the most it takes: a further {c['kind']} "
                    "constraint was not added, so every write of the run is held for a person's approval")},
                    source="signer"), "refused": True}
            seq = tx.emit(run, "constraint.added", data, request_id=req["request_id"])
            tx.set(run, "constraints", [*have, constraint_state({"type": "constraint.added", "data": data,
                                                                 "run_seq": seq})])
            return {"run_seq": seq}
        return self.log.submit(identity, "constraint_add", req, fn, key)

    def _facts(self, key, tool, args, cls, run=None):
        """What run `key`'s live constraints look at in a call (constraints.facts), or None when it has none: its
        distinct file names, at most MAX_NAMES (`many`: more), with `opens`, the names whose commitment under each file
        constraint's salt opens it, by salt label. Off the writer (`run` None: the run's state as it is now), so the
        writer only checks a constraint added since (_constrained)."""
        live = list((run or self.log.runs.get(key) or {}).get("constraints") or ())
        if not live:
            return None
        f = constraints.facts(tool, args, cls)
        names = list(dict.fromkeys(f["names"]))
        f.update(names=names[:MAX_NAMES], many=len(names) > MAX_NAMES, digests=None, opens={})
        for _, label, commitment, _ in live:
            if commitment and not f["many"]:
                f["opens"][label] = self._opened(f, label, commitment)
        return f

    def _opened(self, f, label, commitment):
        """The names of call facts `f` whose commitment under salt `label` is `commitment`: each name digested once,
        the salt derived once."""
        f["digests"] = f["digests"] or [constraints.digest(n) for n in f["names"]]
        salt = _salt(self._salt_key, label)
        return {n for n, d in zip(f["names"], f["digests"]) if hmac.compare_digest(commitment, _commitment(salt, d))}

    def _constrained(self, run, facts):
        """What the agent is told when a call (its _facts) breaks one of `run`'s live constraints, or None: a file it
        writes breaks a file constraint whose commitment its name opens (keep_away) or opens none of (only_change);
        a call writing more than MAX_NAMES files is held whenever the run has a file constraint, and any write once a
        file constraint was refused (constraints_full: past MAX_CONSTRAINTS)."""
        live = run.get("constraints") or ()
        if facts["many"] and any(kind in constraints.OBJECT_KINDS for kind, *_ in live):
            return constraints.held("many", MAX_NAMES)
        opens = facts["opens"]
        for _, label, commitment, _ in live:   # one added after _facts looked
            if commitment and label not in opens:
                opens[label] = self._opened(facts, label, commitment)
        only = [label for kind, label, *_ in live if kind == "only_change"]
        for kind, label, *_ in live:
            name = constraints.breaks(kind, facts, (lambda n: any(n in opens[lb] for lb in only))
                                      if kind == "only_change" else opens.get(label, ()).__contains__)
            if name is not None:
                return constraints.held(kind, name)
        return constraints.held("full", MAX_CONSTRAINTS) if run.get("constraints_full") and facts["write"] else None

    def _review_finding(self, identity, req):
        """A review record: the signed finding, with its rule's fixed title (format-v2.md §3: no text of the run)."""
        v = req["review"]["verdict"]
        return self._finding(identity, req, "review_finding", "review",
                             {**req["review"], "verdict": {**v, "title": rpc_schema.FINDING_TITLES[v["rule"]]}},
                             req["review"]["cites"])

    def _bad_cite(self, tenant, run_id, cites):
        """The first of `cites` that is no record of run `run_id` with that hash, in words, or None."""
        want = {}
        for c in cites:
            want.setdefault(c["run_seq"], set()).add(c["hash"])
        for r in self.log.storage.run_records(tenant, run_id, want) if want else ():   # by run_seq: no scan
            seq = r["event"]["run_seq"]
            if want.pop(seq) != {r["hash"]}:
                return f"run_seq {seq} of run {run_id[:128]}, whose hash differs"
        return f"run_seq {min(want)}, which run {run_id[:128]} does not have" if want else None

    def _status(self, identity, req):
        return {"rpc_version": rpc_schema.RPC_VERSION, "signer": {"name": "tracekit-signer", "version": __version__},
                "identity": {"scheme": identity.scheme, "subject": identity.subject[:256], "attested": identity.attested},
                **({"content": {"max_record_bytes": self.content["max_record_bytes"]}} if self.content["retain"] else {})}

    def _read(self, identity, req):
        key = self._authorize(identity, req)
        start, limit = req.get("from_seq", 0), req.get("limit", 100)
        events, next_seq = [], None
        try:
            # lean: reads the run from its first record for every page; index by run_seq if runs grow long
            for r in self.log.storage.iter_run(*key):
                e = r["event"]
                if e["run_seq"] < start:
                    continue
                if len(events) == limit:
                    next_seq = e["run_seq"]
                    break
                p = {"run_seq": e["run_seq"], "type": e["type"], "data": e["data"]}
                p["event_hash"] = event_hash(p)
                events.append(p)
        except (OSError, StorageUnavailable) as e:
            raise RPCError("unavailable", f"storage read failed: {e}") from None
        return {"events": events, "next_seq": next_seq}

    def _checkpoint_nudge(self, identity, req):
        self._nudged.set()
        return {"scheduled": True}

    def _decision_import(self, identity, req):
        """Record another system's decision about a tool call of a run of the caller's tenant as `policy.external`
        (source import, tier T3): its own record only as a salted commitment, its signature verified when
        `decision_keys` pins the system's key. reconcile compares it with the signer's decision, which stays
        authoritative."""
        key = (self._tenant_of(identity), req["run_id"])
        raw, sig = req["record"].encode("utf-8"), req.get("signature")
        signature = "unverified"
        if req["system"] in self._decision_keys:
            if sig is None:
                raise RPCError("invalid_request", f"{req['system'][:64]} has a pinned key: its records must be signed")
            try:
                ok = crypto.verify_v2("ed25519", self._decision_keys[req["system"]], raw, base64.b64decode(sig, validate=True))
            except ValueError:
                ok = False
            if not ok:
                raise RPCError("invalid_request", f"the signature does not verify under the pinned key of {req['system']}")
            signature = "verified"
        sid = secrets.token_hex(16)
        data = {"system": req["system"], "decision": req["decision"], "tool_use_id": req["tool_call_id"],
                "tool": req["tool"], "rule_ids": req.get("rule_ids", []), "signature": signature, "salt_id": sid,
                "record": {"hash": self._commit(f"policy.external:{sid}", "sha256:" + hashlib.sha256(raw).hexdigest()),
                           "size": len(raw)},
                "identity": {"scheme": identity.scheme, "subject": identity.subject[:256], "attested": identity.attested}}
        if "reason" in req:
            data["reason"] = privacy.redact_text(req["reason"])[0]
        self.quotas.take_event(identity)

        def fn(tx, run):
            return {"run_seq": tx.emit(run, "policy.external", data, source="import", tier="T3",
                                       request_id=req["request_id"]), "signature": signature}
        return self.log.submit(identity, DECISION_IMPORT, req, fn, key, late=True)

    def _passkey_register(self, identity, req):
        """Register the passkey of the person a bridge acts for; trust on first use: a person keeps the first one."""
        who = person(self._on_behalf(identity, req))
        try:
            spki = webauthn.unb64url(req["public_key"])
            webauthn.public_key(spki)
        except ValueError as e:
            raise RPCError("invalid_request", str(e)) from None
        with self._passkeys_lock:
            # lean: the first registration wins, on the bridge's word for the person (the viewer registers only within
            # minutes of a sign-in), and only an operator removes it (passkeys.json); enrol through an out-of-band
            # proof (an issuer-signed enrolment token) when a bridge must not be trusted with first enrolment, and
            # further passkeys with an assertion of the registered one when people need more than one
            if who in self._passkeys:
                raise RPCError("forbidden", f"{who[:256]} has a passkey already")
            self._save_passkeys(dict(self._passkeys, **{who: {"id": req["credential_id"],
                                                              "key": base64.b64encode(spki).decode(), "count": 0}}))
        return {"credential_id": req["credential_id"]}

    # --- the content vault (see the module docstring) ---

    def _aad(self, key, seq, commitment):
        return canonical({"log_id": self.log.log_id, "run_id": key[1], "seq": seq, "commitment": commitment})

    def _data_key(self, key, create=False):
        """Run `key`'s data key (an AESGCM), made and stored wrapped with `create`; None when it has none, ERASED once
        its content was erased. On the writer, so no two make one."""
        wrapped = self.log.storage.content_key(self.log.log_id, *key)
        if wrapped == b"":
            return ERASED
        aad = canonical({"log_id": self.log.log_id, "tenant": key[0], "run_id": key[1]})
        if wrapped is None:
            if not create:
                return None
            dk, nonce = os.urandom(32), os.urandom(12)
            self.log.storage.content_key_put(self.log.log_id, *key, nonce + self._content_key.encrypt(nonce, dk, aad))
            return AESGCM(dk)
        try:
            return AESGCM(self._content_key.decrypt(wrapped[:12], wrapped[12:], aad))
        except InvalidTag:
            raise RPCError("unavailable", f"the content key of run {key[1]} does not open under keys/content.key: "
                                          "restore that key from a backup") from None

    def _retain(self, key, seq, commitment, value):
        """Keep `value`, the redacted content run `key`'s record `seq` commits to (`commitment`), when the vault is
        on. The record is written by now: a failure here leaves that content not retained, never the call failed."""
        if not self.content["retain"] or commitment is None:
            return
        c = canonical(value)

        def put(tx):
            dk = self._data_key(key, create=True)
            if dk is ERASED:   # nothing more is kept for an erased run
                return
            nonce = os.urandom(12)
            blob = b"" if len(c) > self.content["max_record_bytes"] else \
                nonce + dk.encrypt(nonce, c, self._aad(key, seq, commitment))
            self.log.storage.content_put(self.log.log_id, *key, seq, blob)
        try:
            # lean: on the writer, one more item per kept record, which orders it against erasure; a vault thread of
            # its own if keeping content ever slows the writer
            self.log.write(put)
        except (RPCError, StorageUnavailable, OSError):
            self.metrics.loop_errors.inc("content vault")
            logging.getLogger(__name__).exception("tracekit signer: the content of run_seq %s of run %s was not "
                                                  "retained: check the store (on Postgres, after `tracekit signer "
                                                  "migrate`, grant the signer's role tracekit.storage.postgres.GRANTS "
                                                  "again)", seq, key[1])

    def _vault_run(self, identity, run_id):
        """The key of run `run_id` of the caller's tenant, once the vault exists."""
        if self._content_key is None:
            raise RPCError("invalid_request", "this signer keeps no content: set content: {retain: true} in signer.yaml "
                                              f"({wiki_url('docs/privacy.md')})")
        key = (self._tenant_of(identity), run_id)
        if key not in self.log.runs:
            raise RPCError("unknown_run", run_id)
        return key

    def _content_get(self, identity, req):
        key = self._vault_run(identity, req["run_id"])
        self.quotas.take_event(identity)
        wanted = set(req["seqs"])
        try:
            records = {r["event"]["run_seq"]: r["event"] for r in self.log.storage.run_records(*key, wanted)}
        except (OSError, StorageUnavailable) as e:
            raise RPCError("unavailable", f"storage read failed: {e}") from None
        purpose = privacy.redact_text(req["purpose"])[0][:512]

        def too_large():
            return RPCError("quota_exceeded", "the content of these records is too large for one answer: ask for "
                                              "fewer seqs at a time")

        def fn(tx, _):
            dk, items, size = self._data_key(key), [], 0
            for seq in req["seqs"]:
                e = records.get(seq)
                blob = None if dk in (None, ERASED) or e is None else \
                    self.log.storage.content_get(self.log.log_id, *key, seq)
                if dk is ERASED or not blob:
                    items.append({"seq": seq, "state": "erased" if dk is ERASED else
                                  "too_large" if blob == b"" else "not_retained"})
                    continue
                size += len(blob)
                if size > MAX_LINE - 4096:
                    raise too_large()
                commitment, label = _committed(e), salt_label(e)
                try:
                    value = loads_strict(dk.decrypt(blob[:12], blob[12:], self._aad(key, seq, commitment)))
                except InvalidTag:
                    raise RPCError("unavailable", f"the retained content of run_seq {seq} does not open against its "
                                                  "record: the vault was altered") from None
                digest = event_hash({"tool": e["data"]["tool"], "args": value}) if e["type"] == "policy.decision" \
                    else "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
                # the salt also opens a model exchange's args_commitments, over the arguments before redaction
                guessable = e["type"] == "model.exchange" and MARK.search(canonical(value).decode()) and any(
                    "args_commitment" in u for u in e["data"].get("tool_uses", ()))
                items.append({"seq": seq, "content": value} | (
                    {"salt": _salt(self._salt_key, label).hex()} if self._opens(commitment, label, digest)
                    and not guessable else {"redacted": True}))   # no salt: it would test guesses of what redaction removed
            out = {"items": items}
            if len(json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_LINE - 4096:
                raise too_large()
            tx.emit(self.log.signer_run(tx, key[0]), "content.accessed", {
                "principal": subject(identity)[:256], "run_id": key[1], "seqs": req["seqs"], "purpose": purpose},
                source="signer")
            return out
        return self.log.submit(identity, "content_get", req, fn)

    def _content_erase(self, identity, req):
        key = self._vault_run(identity, req["run_id"])
        self.quotas.take_event(identity)
        reason = privacy.redact_text(req.get("reason") or "erased on request")[0][:1024]
        return self._erase(key, reason, subject(identity)[:256],
                           lambda fn: self.log.submit(identity, "content_erase", req, fn))

    def _vault_replays(self, runs):
        """{(tenant, run_id): [(tenant, replay or findings run id)]}: of `runs` (content_runs), those whose
        run.registered names a run in `replay_of` (tracekit why) or `analyzes` (a findings run, whose reviewer model
        call keeps what it sent of that run), by that run."""
        # lean: reads the first record of every run with content in the vault per erasure or retention sweep; index runs
        # by replay_of and analyzes when vaults hold many runs
        out = {}
        for log_id, tenant, run_id, _ in runs:
            first = next(iter(self.log.storage.iter_run(tenant, run_id)), None) if log_id == self.log.log_id else None
            of = first and (first["event"]["data"].get("replay_of") or first["event"]["data"].get("analyzes"))
            if of:
                out.setdefault((tenant, of), []).append((tenant, run_id))
        return out

    def _erase(self, key, reason, by, submit=None, replays=None):
        """Delete run `key`'s data key (replaced by its tombstone) and blobs, and those of its replay and findings runs
        (`replays`, default: every one in the vault), each then a content.erased, in one writer item: a record is signed
        only once the key is gone. A storage failure writes no record and raises unavailable; a retry erases again (blobs a
        failure left behind stay inert: no key opens them)."""
        try:
            if replays is None:
                replays = self._vault_replays(self.log.write(lambda tx: self.log.storage.content_runs())).get(key, [])
        except (OSError, StorageUnavailable) as e:
            raise RPCError("unavailable", f"the content of run {key[1]} was not erased: {e}") from None

        def fn(tx, _=None):
            out = None
            for k in (key, *replays):
                try:
                    self.log.storage.content_erase(self.log.log_id, *k)
                except (OSError, StorageUnavailable) as e:
                    raise RPCError("unavailable", f"the content of run {k[1]} was not erased: {e}") from None
                why = reason if k == key else f"{reason} (a replay or findings run of run {key[1]})"[:1024]
                seq = tx.emit(self.log.signer_run(tx, k[0]), "content.erased", {"run_id": k[1], "reason": why, "by": by},
                              source="signer")
                out = out or {"run_seq": seq}
            return out
        return (submit or self.log.write)(fn)

    def expire_content(self, now=None):
        """Erase the content of every run whose data key was stored more than retention_days before `now`, with its
        replay and findings runs' (their content never outlives their run's)."""
        cutoff = (time.time() if now is None else now) - self.content["retention_days"] * 86400
        runs = self.log.write(lambda tx: self.log.storage.content_runs())
        replays, done = self._vault_replays(runs), set()
        for log_id, tenant, run_id, stored in runs:
            if log_id == self.log.log_id and stored < cutoff and (tenant, run_id) not in done:
                todo = [k for k in replays.get((tenant, run_id), []) if k not in done]
                self._erase((tenant, run_id), f"retention: kept {self.content['retention_days']} days", "signer",
                            replays=todo)
                done.update([(tenant, run_id), *todo])

    # --- OTLP import (tracekit.signer.otel) ---

    def otlp(self, identity, body, content_type, content_encoding):
        """(status, headers, body) of an OTLP/HTTP `POST /v1/traces` from `identity`, which the transport established;
        RPCError forbidden unless `authorize` grants it otlp_import."""
        try:
            self._grant(identity, OTLP_IMPORT)
            self._check_suspended(identity)
        except RPCError as e:
            self._refused(identity, e)
            raise
        return otlp.handle_traces(types.SimpleNamespace(export=lambda spans: self._import(identity, spans)), body,
                                  content_type, content_encoding)

    def _content(self, value, label, dotenv):
        value, manifest = _redact(value, dotenv)
        c = canonical(value)
        return {"hash": self._commit(label, "sha256:" + hashlib.sha256(c).hexdigest()), "size": len(c),
                "redacted": manifest["count"] > 0}, manifest

    def _import(self, identity, spans):
        """Write decoded spans as the records of their imported runs, all in one writer item (nothing on a refusal):
        a dict of counts for otlp.handle_traces. A trace's root span closes its run: its spans are all ended."""
        res = {"accepted": 0, "duplicate": 0, "skipped": 0, "rejected": 0, "errors": [], "retryable": False}
        if len(spans) > self.otlp_max_spans:
            return dict(res, rejected=len(spans), errors=[f"more than {self.otlp_max_spans} spans in one request"])
        traces, agents = {}, {}   # trace id -> [[(type, data, span id)] per span]; trace id -> agent name
        ended = {sp["trace_id"] for sp in spans if sp["parent_span_id"] is None}
        for sp in sorted(spans, key=lambda x: (x["start_ns"], x["end_ns"])):
            kind = otlp.classify(sp)
            if kind not in ("tool", "llm"):
                res["skipped"] += 1
                continue
            try:
                recs = [(typ, data, sp["span_id"]) for typ, data in signer_otel.records(kind, sp, self._content)]
            except Exception as e:   # values no record can hold (nesting past the recursion limit, say)
                res["rejected"] += 1
                res["errors"].append(f"span {sp['span_id']}: {type(e).__name__}")
                continue
            traces.setdefault(sp["trace_id"], []).append(recs)
            agents.setdefault(sp["trace_id"], str(sp["attrs"].get("gen_ai.agent.name") or
                                                  sp["resource"].get("service.name") or "otel")[:128] or "otel")
        own = owner(identity)
        tenant = self._tenant_of(identity)
        try:
            self._certified(tenant)
        except RPCError as e:
            return dict(res, rejected=len(spans) - res["skipped"], errors=res["errors"] + [e.message])

        def fn(tx, _):
            out = dict(res, errors=list(res["errors"]))
            for tid, per_span in traces.items():
                key = (tenant, signer_otel.run_id(tid))
                run = self.log.runs.get(key)
                if run is None:
                    n = self.log.open_runs.get(own, 0)
                    self.quotas.check_count("open_runs", n)
                    run = tx.new_run(*key)
                    for k, v in (("owner", own), ("source", "import"), ("rec", None), ("spans", {})):
                        tx.set(run, k, v)
                    tx.set(self.log.open_runs, own, n + 1)
                    tx.emit(run, "run.registered", {
                        "agent": {"name": agents[tid]}, "signer_isolation": "unknown", "fidelity": "none",
                        "identity": {"scheme": identity.scheme, "subject": identity.subject[:256],
                                     "attested": identity.attested}}, tier=signer_otel.TIER)
                elif run["source"] != "import" or run["final"] or run["owner"] != own:
                    out["rejected"] += len(per_span)
                    out["errors"].append(f"trace {tid}: " + ("its run is final" if run["final"] else
                                                             "a run of that id was registered over RPC"
                                                             if run["source"] != "import" else
                                                             "its run was imported by another identity"))
                    continue
                tx.set(run, "active", time.monotonic())
                for recs in per_span:
                    new = [(typ, data, sid) for typ, data, sid in recs if f"{sid}:{typ}" not in run["spans"]]
                    out["accepted" if new else "duplicate"] += 1
                    for typ, data, sid in new:
                        tx.emit(run, typ, data, tier=signer_otel.TIER, span_id=sid)
                        tx.set(run["spans"], f"{sid}:{typ}", True)
            for tid in ended:   # one open run per trace would spend the importer's open_runs (agentgateway: per call)
                run = self.log.runs.get((tenant, signer_otel.run_id(tid)))
                if run and run["source"] == "import" and run["owner"] == own and not run["closed"]:
                    tx.closing(run, "close_run")
            return out
        try:
            # lean: one event-rate token per request (at most max_spans spans); a token per span if imports need a
            # finer rate limit than events_per_s * max_spans
            self.quotas.take_event(identity)
            return self.log.submit(identity, OTLP_IMPORT, {}, fn)
        except RPCError as e:   # a quota or the storage: the exporter keeps the batch and retries
            self._refused(identity, e)
            return dict(res, retryable=True, errors=[e.message])


# the SignerAPI methods, answered for the in-process identity
for _m in REQUESTS:
    setattr(SignerService, _m, lambda self, req, _m=_m: self.call(self.identity, _m, req))


# --- tracekit signer serve | fsck ---

def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    unknown = set(cfg) - CONFIG_KEYS
    if unknown or "data_dir" not in cfg:
        raise ValueError(f"{path}: needs data_dir; unknown keys {sorted(unknown)}")
    if "socket_mode" in cfg and not re.fullmatch(r"0?[0-7]{3}", str(cfg["socket_mode"])):
        raise ValueError(f'{path}: socket_mode is an octal mode such as "0666"')
    base = os.path.dirname(os.path.abspath(path))
    for k in ("data_dir", "socket", "tcp_endpoint", "policy"):
        if cfg.get(k):
            cfg[k] = os.path.join(base, cfg[k])
    h = cfg.get("http")
    if h is not None:
        from tracekit.transport import http
        http.resolve(h, base)
        http.configure(h)   # validates the section now; serve() builds it again
    oidc = (cfg.get("view") or {}).get("oidc") if isinstance(cfg.get("view"), dict) else None
    if isinstance(oidc, dict) and isinstance(oidc.get("client_secret_file"), str):
        oidc["client_secret_file"] = os.path.join(base, oidc["client_secret_file"])
    if isinstance(cfg.get("view"), dict) and "logs" in cfg["view"]:
        logs = cfg["view"]["logs"]
        if not (isinstance(logs, list) and logs and all(isinstance(x, str) and x for x in logs)):
            raise ValueError(f"{path}: view.logs is a list of DSN files, one per log")
        cfg["view"]["logs"] = [os.path.join(base, x) for x in logs]
    if "storage" in cfg:
        pg = cfg["storage"].get("postgres") if isinstance(cfg["storage"], dict) and set(cfg["storage"]) == {"postgres"} else None
        if not (isinstance(pg, dict) and set(pg) <= {"dsn_file"} and isinstance(pg.get("dsn_file", ""), str)):
            raise ValueError(f"{path}: storage is {{postgres: {{dsn_file}}}} (the DSN in a file, never inline)")
        if pg.get("dsn_file"):
            pg["dsn_file"] = os.path.join(base, pg["dsn_file"])
    if "log_key" in cfg:
        # lean: AWS KMS only; GCP Cloud KMS (EC_SIGN_ED25519, software-protected) through its REST API once a
        # deployment asks for it
        lk = cfg["log_key"]
        ok = isinstance(lk, dict) and lk and set(lk) <= {"aws_kms", "slh_dsa"}
        kms, slh = (lk.get("aws_kms"), lk.get("slh_dsa")) if ok else (None, None)
        if not (ok and (kms is None or isinstance(kms, dict) and set(kms) == {"key_id", "region"}
                        and all(isinstance(v, str) and v for v in kms.values()))
                and (slh is None or isinstance(slh, dict) and set(slh) == {"file"} and isinstance(slh["file"], str)
                     and slh["file"])):
            raise ValueError(f"{path}: log_key is {{aws_kms: {{key_id, region}}}} and/or {{slh_dsa: {{file}}}} "
                             "(default: keys/log.key, no hybrid line)")
        if slh:
            slh["file"] = os.path.join(base, slh["file"])
    if "route" in cfg and not (isinstance(cfg["route"], str) and re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?",
                                                                              cfg["route"])):
        raise ValueError(f"{path}: route is a DNS label (the replica's host name)")
    if "record_key" in cfg:
        from tracekit import issuer
        issuer.check_signer_section(cfg["record_key"], path)
    if "webhook" in cfg:
        cfg["webhook"] = webhook.load(cfg["webhook"], base, path)
    approvals = cfg.get("approvals") if isinstance(cfg.get("approvals"), dict) else {}
    if any(len(str(k)) > 256 for k in cfg.get("gateways") or ()):   # each record names its gateway in full (`via`)
        raise ValueError(f"{path}: gateways: an identity is at most 256 characters")
    for table in (cfg.get("tenants"), cfg.get("authorize"), approvals.get("approvers"), approvals.get("break_glass"),
                  cfg.get("gateways")):
        for k in table or ():
            if "*" in str(k) and not (str(k).endswith(PREFIX_ENDS) and str(k).count("*") == 1):
                raise ValueError(f"{path}: {k!r}: a prefix key must end in :* or /*")
    names = set()
    if isinstance(cfg.get("witnesses"), list) and "public" in cfg["witnesses"]:
        try:
            cfg["witnesses"] = [public_witness.entry() if w == "public" else w for w in cfg["witnesses"]]
        except ValueError as e:
            raise ValueError(f"{path}: witnesses: public: {e}") from None
        if not public_witness.ORIGIN.fullmatch(str(cfg.get("origin", "tracekit.local/log"))):
            raise ValueError(f"{path}: origin: the public witness takes origins shaped {public_witness.ORIGIN_FORMAT}")
    for w in cfg.get("witnesses") or ():
        if not (isinstance(w, dict) and set(w) == {"url", "vkey", "class"} and w["class"] in CLASSES):
            raise ValueError(f"{path}: each witness is {{url, vkey, class}}, class one of {', '.join(CLASSES)}")
        name = TlogWitness(w["url"], w["vkey"]).name   # a cosignature vkey
        if name in names:
            raise ValueError(f"{path}: two witnesses named {name}")
        names.add(name)
    if "anchors" in cfg:
        r = cfg["anchors"].get("rekor") if isinstance(cfg["anchors"], dict) and set(cfg["anchors"]) == {"rekor"} else None
        if not (isinstance(r, dict) and {"signing_config", "trusted_root"} <= set(r) <= {"signing_config", "trusted_root",
                                                                                      "every_s"}
                and all(isinstance(r[k], str) and r[k] for k in ("signing_config", "trusted_root"))
                and isinstance(r.get("every_s", rekor2.MIN_EVERY_S), (int, float))
                and r.get("every_s", rekor2.MIN_EVERY_S) >= rekor2.MIN_EVERY_S):
            raise ValueError(f"{path}: anchors is {{rekor: {{signing_config, trusted_root, every_s}}}}, every_s at least "
                             f"{rekor2.MIN_EVERY_S:g}")
        r.update({k: os.path.join(base, r[k]) for k in ("signing_config", "trusted_root")})
    return cfg


def signer_config(path=None):
    """The config at `path`, or the same-user dev signer's (data_dir and socket)."""
    if path:
        return load_config(path)
    from tracekit.sdk.autospawn import SOCK, signer_dir
    return {"data_dir": dev_data_dir(), "socket": os.path.join(signer_dir(), SOCK)}


def reader(cfg):
    """A read-only view of the store of config `cfg`, safe while the signer writes it: a FileReader of data_dir/store,
    or a PostgresReader on the DSN of its storage section. Close it when done."""
    if cfg.get("storage"):
        from tracekit.storage import postgres
        return postgres.PostgresReader(postgres.read_dsn(cfg["storage"]["postgres"]))
    from tracekit.storage import file
    return file.FileReader(os.path.join(cfg["data_dir"], "store"))


def read_vkeys(data_dir):
    """The vkeys of the log key, then of the hybrid key when configured, the signer of `data_dir` wrote on start."""
    d = files.open_dir(data_dir)
    try:
        data = files.read(d, "log.vkey")
    finally:
        files.close(d)
    if data is None:
        raise ValueError(f"{data_dir} has no log.vkey yet: start the signer once")
    vkeys = data.decode("ascii").split()
    for k in vkeys:
        checkpoint.parse_vkey(k)
    return vkeys


def read_rekor_pub(data_dir):
    """The Rekor publishing key (base64 SPKI) the signer of `data_dir` wrote on start."""
    d = files.open_dir(data_dir)
    try:
        data = files.read(d, "rekor.pub")
    finally:
        files.close(d)
    if data is None:
        raise ValueError(f"{data_dir} has no rekor.pub yet: start the signer with anchors once")
    return data.decode("ascii").strip()


def open_service(cfg, **kw):
    if cfg.get("policy"):
        kw.setdefault("policy", load_policy(cfg["policy"]))
    kw.setdefault("witnesses", [TlogWitness(w["url"], w["vkey"]) for w in cfg.get("witnesses", ())])
    lk = cfg.get("log_key") or {}
    if lk.get("aws_kms") and "log_key" not in kw:
        kw["log_key"] = logkey.from_config(lk)
    if lk.get("slh_dsa"):
        kw.setdefault("slh_dsa_file", lk["slh_dsa"]["file"])
    if "oidc" not in kw:
        kw["oidc"] = _oidc(cfg)
    return SignerService(cfg["data_dir"], durability=cfg.get("durability", ACK_ON_WRITE),
                         tenant=cfg.get("tenant", "default"), tenants=cfg.get("tenants"),
                         limits=Limits(**cfg.get("limits", {})),
                         acknowledge_rollback=bool(cfg.get("acknowledge_rollback")),
                         multi_tenant_apps=cfg.get("multi_tenant_apps", ()), migrators=cfg.get("migrators", ()),
                         analyzers=cfg.get("analyzers", ()), importers=cfg.get("importers", ()),
                         fail_modes=cfg.get("fail_modes"),
                         grace_s=float(cfg.get("grace_s", GRACE_S)), idle_s=float(cfg.get("idle_s", IDLE_S)),
                         origin=cfg.get("origin"), contact=cfg.get("contact"), approvals=cfg.get("approvals") or {},
                         authorize=cfg.get("authorize"), lock_timeout_s=float(cfg.get("lock_timeout_s", LOCK_TIMEOUT_S)),
                         fsck_every_s=float(cfg.get("fsck_every_s", FSCK_S)),
                         clock_skew_s=float(cfg.get("clock_skew_s", CLOCK_SKEW_S)),
                         rekor=(cfg.get("anchors") or {}).get("rekor"), otlp=cfg.get("otlp"),
                         otel_out=cfg.get("otel_out"), storage_config=cfg.get("storage"), gateways=cfg.get("gateways", ()),
                         gateway_mandatory=cfg.get("gateway_mandatory") is True,
                         harness_binding=cfg.get("harness_binding"), record_key=cfg.get("record_key"),
                         route=cfg.get("route"), decision_keys=cfg.get("decision_keys"), webhooks=cfg.get("webhook", ()),
                         content=cfg.get("content"), gateway_wait_s=float(cfg.get("gateway_wait_s", GATEWAY_WAIT_S)),
                         posture=cfg.get("posture"), observe_grace_s=float(cfg.get("observe_grace_s", OBSERVE_GRACE_S)),
                         verify_tool_results=cfg.get("verify_tool_results"),
                         **kw)


def _oidc(cfg):
    """The OidcAuthenticator of the config's http.oidc section, or None."""
    section = (cfg.get("http") or {}).get("oidc")
    if section is None:
        return None
    from tracekit.identity.oidc import OidcAuthenticator
    return OidcAuthenticator(section)


def serve(cfg, service):
    """Bind the configured transports for `service` (whose storage lock is already held) and start answering.
    Returns the servers; stop each with shutdown() and server_close()."""
    if not (cfg.get("socket") or cfg.get("tcp_endpoint") or cfg.get("http")):
        raise ValueError("configure socket, tcp_endpoint and/or http")
    if "otlp" in cfg and not cfg.get("http"):
        raise ValueError("otlp is served on the http listener: configure http")
    servers = [metrics.server(cfg["metrics"], service.metrics, service.logs_list,
                              lambda p: service.tlog(p, cfg["metrics"].get("serve_records") is True))
               ] if "metrics" in cfg else []
    handle = answering_hello(service.handle_frame, hello())
    if cfg.get("socket"):
        from tracekit.transport.unix import UnixServer
        try:
            os.unlink(cfg["socket"])   # a dead signer's socket: safe to remove, this process holds the storage lock
        except FileNotFoundError:
            pass
        servers.append(UnixServer(cfg["socket"], handle))
        if cfg.get("socket_mode"):
            os.chmod(cfg["socket"], int(str(cfg["socket_mode"]), 8))
    if cfg.get("tcp_endpoint"):
        from tracekit.transport.tcp_dev import TcpDevServer
        servers.append(TcpDevServer(cfg["tcp_endpoint"], _dev_token(), handle))
    if cfg.get("http"):
        from tracekit.transport import http
        servers.append(http.HttpServer(*http.configure(cfg["http"], service.oidc), handle,
                                       otlp=service.otlp if "otlp" in cfg else None,
                                       on_auth_failure=service.metrics.auth_failures.inc))
    for s in servers:
        threading.Thread(target=s.serve_forever, args=(0.2,), daemon=True).start()
    return servers


def _dev_token():
    from tracekit.identity.token import DevToken
    return DevToken("dev", [*REQUESTS, "hello"], ttl_s=365 * 86400)


def dev_data_dir():
    """The dev signer's per-user data dir (keys and store), created 0700."""
    from tracekit.sdk.autospawn import data_dir
    d = data_dir()
    os.makedirs(d, 0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def serve_dev(runtime_dir, open_handler, proto=(rpc_schema.RPC_MIN, rpc_schema.RPC_VERSION), version=__version__,
              idle_s=900, data_dir=None):
    """Serve as the dev signer of `runtime_dir` (decision S3) until SIGTERM, or until `idle_s` seconds (0: never) pass
    with no connection open. Takes signer.lock before anything else (gives up after 1 s) and holds it for life; then
    `open_handler()` -> (handle_frame, close); then binds the socket (loopback TCP without Unix sockets) and publishes
    endpoint.json, which names `data_dir` as hello does (autospawn takes only its own HOME's); before returning,
    unpublishes both, then calls close(). Call it from the main thread; returns an exit code."""
    from tracekit.deploy import files
    from tracekit.sdk import autospawn

    lock = open(os.path.join(runtime_dir, autospawn.LOCK), "a")
    deadline = time.monotonic() + 1
    while True:
        try:
            lock_file(lock, blocking=False)
            break
        except OSError:
            if time.monotonic() > deadline:
                print("LOST: another dev signer holds signer.lock", file=sys.stderr)
                return 1
            time.sleep(0.05)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    sock, endpoint = os.path.join(runtime_dir, autospawn.SOCK), os.path.join(runtime_dir, autospawn.ENDPOINT)
    for p in (sock, endpoint):
        pathlib.Path(p).unlink(missing_ok=True)
    handle_frame, close = open_handler()
    info = {**hello(proto, version), **({"data_dir": data_dir} if data_dir else {})}
    handle = answering_hello(handle_frame, info)
    if hasattr(socket, "AF_UNIX"):
        from tracekit.transport.unix import UnixServer
        server = UnixServer(sock, handle)
        files.write_json(endpoint, info)
    else:
        from tracekit.transport.tcp_dev import TcpDevServer
        server = TcpDevServer(endpoint, _dev_token(), handle, publish=info)
    active, last, mutex = [0], [time.monotonic()], threading.Lock()

    def finish_request(request, address, inner=server.finish_request):   # counts the open connections
        with mutex:
            active[0] += 1
        try:
            inner(request, address)
        finally:
            with mutex:
                active[0] -= 1
                last[0] = time.monotonic()
    server.finish_request = finish_request
    threading.Thread(target=server.serve_forever, args=(0.2,), daemon=True).start()
    print(f"SERVING pid {os.getpid()}", file=sys.stderr, flush=True)
    try:
        while not stop.wait(0.1):
            with mutex:
                if idle_s and not active[0] and time.monotonic() - last[0] > idle_s:
                    break
    except KeyboardInterrupt:
        pass
    for p in (endpoint, sock):
        pathlib.Path(p).unlink(missing_ok=True)
    server.shutdown()
    server.server_close()
    close()
    return 0


def dev_content():
    """The dev signer's content vault and who may read it: it keeps each call's redacted arguments and results for
    DEV_RETENTION_DAYS, so `tracekit view --dev` can show what the agent ran, and grants this user (already the holder
    of every dev key) `content_read`. TRACEKIT_DEV_CONTENT=0 keeps nothing."""
    if os.environ.get("TRACEKIT_DEV_CONTENT", "1") == "0":
        return {}
    return {"content": {**CONTENT, "retain": True, "retention_days": DEV_RETENTION_DAYS},
            "authorize": {_dev_identity(): sorted(DEFAULT_GRANTS | {CONTENT_READ})}}


def _dev_identity():
    """The identity the dev signer sees its user as."""
    return "token:dev" if os.name == "nt" else f"uid:{os.getuid()}"


def _serve_dev():
    from tracekit.sdk.autospawn import runtime_dir

    logkey.harden()

    def open_handler():   # the user may sign findings about their own runs: they read self-asserted (docs/verdicts.md)
        service = SignerService(dev_data_dir(), isolation="same-user", fsck_every_s=0, analyzers=[_dev_identity()],
                                grace_s=float(os.environ.get("TRACEKIT_DEV_GRACE", GRACE_S)), **dev_content())
        return service.handle_frame, service.close
    try:
        return serve_dev(runtime_dir(), open_handler, idle_s=float(os.environ.get("TRACEKIT_DEV_IDLE", 900)),
                         data_dir=dev_data_dir())
    except BlockingIOError:
        print(f"tracekit signer: another signer holds {dev_data_dir()}", file=sys.stderr)
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
    return 1


def fsck(data_dir, upto=None, storage=None, record_key=None):
    """Every problem in the store (the `storage` config section's, else data_dir/store): the storage check (hashes,
    chains) plus every record's signature, under keys/record.key or, with `record_key` (the config section), the
    keys its issuer certified. `upto`: see storage.file.fsck (a Postgres check reads one consistent snapshot
    instead)."""
    keys = os.path.join(data_dir, "keys")
    if record_key:
        from tracekit import issuer
        verify = issuer.record_verifier(record_key["issuer"])
    else:
        with open(os.path.join(keys, "record.key"), "rb") as f:
            sign = RecordSigner(f.read())
        verify = functools.partial(verify_record, keys=[sign.spki], algs={sign.alg})
    if storage:
        from tracekit.storage import postgres
        return postgres.fsck(postgres.read_dsn(storage["postgres"]), _snapshot_key(keys), verify)
    return fsck_store(os.path.join(data_dir, "store"), upto, _snapshot_key(keys), verify)


def reveal(data_dir, seq, storage=None):
    """{"seq", "type", "salt"}: the salt of record `seq`'s commitments, for an auditor who holds that record's content.
    Only the owner of the signer's keys may ask. `storage`: the config's storage section, else the file store."""
    keys = os.path.join(data_dir, "keys")
    if hasattr(os, "getuid") and os.stat(keys).st_uid != os.getuid():
        raise PermissionError(f"{keys} belongs to another user: only the signer's owner reveals salts")
    r = reader({"data_dir": data_dir, "storage": storage})
    try:
        e = next((x["event"] for x in r.iter_range(seq, seq + 1)), None)
    finally:
        r.close()
    label = e and salt_label(e)
    if label is None:
        raise ValueError(f"record {seq} " + ("does not exist" if e is None else f"({e['type']}) has no commitments"))
    with open(os.path.join(keys, "args_salt.key"), "rb") as f:
        return {"seq": seq, "type": e["type"], "salt": _salt(f.read(), label).hex()}


def _token_cmd(a, cfg):
    from tracekit.identity.token import TokenStore, parse_ttl
    path = (cfg.get("http") or {}).get("tokens")
    if not path:
        raise ValueError("the config's http section names no tokens file (http.tokens)")
    store = TokenStore(path)
    if a.token_cmd == "add":
        print(store.add(a.name, parse_ttl(a.ttl), a.tenant))
        print(f"(identity token:{a.name}; this is the only time the token is shown)", file=sys.stderr)
    elif a.token_cmd == "revoke":
        store.revoke(a.name)
    else:
        print(json.dumps([{"name": name, **{k: rec[k] for k in ("tenant", "created", "expires", "revoked")}}
                          for name, rec in sorted(store.load().items())], indent=2))
    return 0


INCIDENT_CMDS = {"list": "incident_list", "show": "incident_show", "resolve": "incident_resolve", "hold": "run_hold",
                 "quarantine": "run_quarantine", "resume": "run_resume", "pause": "response_pause",
                 "unpause": "response_resume", "suspend": "suspend", "unsuspend": "unsuspend"}


def _incidents_cmd(a):
    """`tracekit signer incidents`: each call goes to every `--signer` named (default $TRACEKIT_SIGNER, else the dev
    signer). list merges what each replica holds, pause and unpause reach each replica's own response engine; the
    rest stop at the first replica that knows the incident or run."""
    from tracekit.sdk.client import Client
    method = INCIDENT_CMDS[a.action]
    key = {"show": "incident_id", "resolve": "incident_id", "hold": "run_id", "quarantine": "run_id",
           "resume": "run_id", "suspend": "identity", "unsuspend": "identity"}.get(a.action)
    if key and not a.target:
        raise ValueError(f"tracekit signer incidents {a.action} needs the {key.replace('_', ' ')}")
    req = {**({key: a.target} if key else {}), **({"reason": a.reason} if a.reason else {}),
           **({"state": a.state} if a.action == "list" and a.state else {})}
    out, last = [], None
    for url in a.signer or [None]:
        c = Client(url)
        try:
            out.append(c.call(method, req))
        except RPCError as e:
            if e.code not in ("unknown_incident", "unknown_run") or a.action in ("list", "pause", "unpause"):
                raise
            last = e
            continue
        finally:
            c.close()
        if a.action not in ("list", "pause", "unpause"):
            break
    if not out:
        raise last
    if a.action == "list":
        for x in [i for o in out for i in o["incidents"]]:
            print(f"{x['incident_id']}  {x['state']}  {x['trigger']} {','.join(x['rule_ids'])}  run={x['run_id']}  "
                  f"{x['mode']} {'+'.join(x['actions']) or 'no action'}  " +
                  " ".join(f"{r['run_id']}:{r['state']}" for r in x["runs"]))
    else:
        print(json.dumps(out if len(out) > 1 else out[0], indent=2))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit signer", description="the v2 signer service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("serve", help="run the signer in the foreground")
    q.add_argument("--close-on-stop", metavar="FILE",
                   help="on SIGTERM, when FILE exists, close the log for good first (a scaled-down central replica)")
    mode = q.add_mutually_exclusive_group(required=True)
    mode.add_argument("--config")
    mode.add_argument("--dev", action="store_true",
                      help="the same-user dev signer of the runtime dir ($TRACEKIT_RUNTIME_DIR); clients start it")
    sub.add_parser("fsck", help="check every record of the store").add_argument("--config", required=True)
    sub.add_parser("migrate", help="create or check the Postgres store's tables").add_argument("--config", required=True)
    sub.add_parser("close-log", help="close the log for good: write log.closed and the final notes (signer stopped)"
                   ).add_argument("--config", required=True)
    for name, text in (("vkey", "print the log key's verifier key (C2SP vkey), then the hybrid key's"),
                       ("trust", "write a v2 trust config that pins the log keys and the configured witnesses")):
        q = sub.add_parser(name, help=text)
        g = q.add_mutually_exclusive_group()
        g.add_argument("--config")
        g.add_argument("--dev", action="store_true", help="the same-user dev signer (the default)")
        if name == "trust":
            q.add_argument("-o", "--out", required=True)
    q = sub.add_parser("reveal", help="print the salt of one record's commitments (the signer's owner only)")
    q.add_argument("--record", type=int, required=True, metavar="SEQ")
    g = q.add_mutually_exclusive_group()
    g.add_argument("--config")
    g.add_argument("--dev", action="store_true", help="the same-user dev signer (the default)")
    t = sub.add_parser("token", help="named, expiring bearer tokens of the http transport (http.tokens)"
                       ).add_subparsers(dest="token_cmd", required=True)
    q = t.add_parser("add", help="create a token for identity token:NAME and print it (the only time it is shown)")
    q.add_argument("name")
    q.add_argument("--ttl", default="30d", help="lifetime: a number and s, m, h or d (default 30d)")
    q.add_argument("--tenant", help="the tenant of its runs (the config's `tenants` map wins)")
    t.add_parser("list", help="names, tenants, created, expires and revoked times (never the tokens)")
    t.add_parser("revoke", help="refuse the token from its next request").add_argument("name")
    for q in t.choices.values():
        q.add_argument("--config", required=True)
    c = sub.add_parser("content", help=f"the content vault: read or erase a run's retained content ({wiki_url('docs/privacy.md')})"
                       ).add_subparsers(dest="content_cmd", required=True)
    q = c.add_parser("get", help="print the retained content of records of a run, each with its salt (recorded as "
                                 "content.accessed)")
    q.add_argument("--seq", type=int, nargs="+", required=True, help="the records' run_seqs")
    q.add_argument("--purpose", required=True, help="why, e.g. a case id (recorded)")
    q = c.add_parser("erase", help="delete a run's retained content for good (recorded as content.erased)")
    q.add_argument("--reason")
    for q in c.choices.values():
        q.add_argument("--run", required=True)
        q.add_argument("--config", help="reach the signer on this config's socket (default: $TRACEKIT_SIGNER, else "
                                        "the dev signer)")
    q = sub.add_parser("incidents", help=f"containment's operator calls on the running signer ({wiki_url('docs/incidents.md')})")
    q.add_argument("action", choices=sorted(INCIDENT_CMDS))
    q.add_argument("target", nargs="?", help="the incident (show, resolve), run (hold, quarantine, resume) or "
                                              "identity (suspend, unsuspend)")
    q.add_argument("--signer", action="append", help="a replica to reach, repeatable (default: $TRACEKIT_SIGNER, else "
                                                     "the dev signer)")
    q.add_argument("--reason", help="recorded with the call (redacted); a break-glass resolve or resume needs one")
    q.add_argument("--state", choices=("open", "resolved"), help="list: only incidents in this state")
    p = sub.add_parser("bridge", help="continue a v1 ledger in this signer's log and destroy the v1 key")
    p.add_argument("--v1-home", required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--config")
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's data dir")
    a = ap.parse_args(argv)
    if a.cmd == "serve" and a.dev:
        return _serve_dev()
    if a.cmd == "reveal":
        try:
            cfg = signer_config(a.config)
            print(json.dumps(reveal(cfg["data_dir"], a.record, cfg.get("storage"))))
        except (OSError, ValueError, StorageUnavailable) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        return 0
    if a.cmd == "incidents":
        from tracekit.sdk.client import Incompatible, SignerUnavailable
        try:
            return _incidents_cmd(a)
        except (OSError, ValueError, RPCError, SignerUnavailable, Incompatible) as e:
            print(f"tracekit signer incidents: {e}", file=sys.stderr)
            return 1
    if a.cmd == "content":
        from tracekit.sdk.client import Client, Incompatible, SignerUnavailable
        try:
            sock = a.config and load_config(a.config).get("socket")
            if a.config and not sock:
                raise ValueError(f"{a.config} names no socket: reach the signer with $TRACEKIT_SIGNER instead")
            c = Client(sock or None)
            try:
                out = c.content_get({"run_id": a.run, "seqs": a.seq, "purpose": a.purpose}) if a.content_cmd == "get" \
                    else c.content_erase({"run_id": a.run, **({"reason": a.reason} if a.reason else {})})
            finally:
                c.close()
        except (OSError, ValueError, RPCError, SignerUnavailable, Incompatible) as e:
            print(f"tracekit signer content: {e}", file=sys.stderr)
            return 1
        print(json.dumps(out, indent=2))
        return 0
    if a.cmd in ("vkey", "trust"):
        from tracekit.sdk.client import SignerUnavailable
        try:
            cfg = signer_config(a.config)
            vkeys = read_vkeys(cfg["data_dir"])
            if a.cmd == "trust":
                witnesses = [{"vkey": w["vkey"], "class": w["class"]} for w in cfg.get("witnesses") or ()]
                rekor = (cfg.get("anchors") or {}).get("rekor")
                if rekor:
                    with open(rekor["trusted_root"], "rb") as f:
                        rekor = {"trusted_root": json.loads(f.read()), "publishing_key": read_rekor_pub(cfg["data_dir"]),
                                 "class": "public"}
                files.write_json(a.out, {"logs": vkeys, "witnesses": witnesses, "algs": [RecordSigner.alg],
                                         "witnesses_required": 0, **({"rekor": rekor} if rekor else {})}, 0o644)
        except (OSError, ValueError, SignerUnavailable) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        print("\n".join(vkeys) if a.cmd == "vkey" else f"wrote {a.out}: pins log {vkeys[0].split('+')[0]}"
              f"{' (Ed25519 + SLH-DSA)' if len(vkeys) > 1 else ''} and {len(witnesses) or 'no'} witness(es)")
        return 0
    from tracekit.signer import format_bridge
    try:
        cfg = {"data_dir": dev_data_dir()} if getattr(a, "dev", False) else load_config(a.config)
        if a.cmd == "token":
            return _token_cmd(a, cfg)
    except (OSError, ValueError) as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 2
    if a.cmd == "bridge":
        # lean: run by hand while v1 hooks still sign with the v1 key; run the bridge on first v2 start once the hook
        # speaks the RPC (M1a-14)
        try:
            print(json.dumps(format_bridge.bridge(a.v1_home, cfg["data_dir"], cfg.get("storage"))))
        except (OSError, ValueError, StorageUnavailable, format_bridge.BridgeError) as e:
            print(f"tracekit signer bridge: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "migrate":
        if not cfg.get("storage"):
            print("tracekit signer migrate: the config has no storage: {postgres: ...} section", file=sys.stderr)
            return 2
        from tracekit.storage import postgres
        try:
            print(f"schema version {postgres.migrate(postgres.read_dsn(cfg['storage']['postgres']))}")
        except (OSError, ValueError, StorageUnavailable) as e:
            print(f"tracekit signer migrate: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "fsck":
        try:
            problems = fsck(cfg["data_dir"], storage=cfg.get("storage"), record_key=cfg.get("record_key"))
        except (OSError, ValueError, StorageUnavailable) as e:
            print(f"tracekit signer fsck: {e}", file=sys.stderr)
            return 2
        for p in problems:
            print(p)
        print("ok" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if a.cmd == "serve":
        logkey.harden()   # before any key is read
        extra = [k for k in EXPERIMENTAL_KEYS if cfg.get(k)] + [
            f"approvals.{k}" for k in ("agents", "webauthn") if isinstance(cfg.get("approvals"), dict) and cfg["approvals"].get(k)]
        if extra:
            print(f"tracekit: the signer's {', '.join(extra)} setting(s) are experimental: they work and are tested, "
                  f"but may change ({wiki_url('docs/support.md')})", file=sys.stderr)
    try:
        service = open_service(cfg)
    except BlockingIOError as e:
        print(f"tracekit signer: {e.strerror}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 1
    if a.cmd == "close-log":
        try:
            service.close_log()
        except (RPCError, StorageUnavailable, OSError) as e:
            print(f"tracekit signer close-log: {e}", file=sys.stderr)
            return 1
        finally:
            service.close()
        print(f"log closed at seq {service.log.head['seq'] - 1}")
        return 0
    if service.log.head["closed"]:
        service.close()
        print("tracekit signer: the log is closed (log.closed) and takes no more records: give this signer a new log",
              file=sys.stderr)
        return 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        servers = serve(cfg, service)
    except Exception as e:
        service.close()
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 1
    where = ""
    if cfg.get("http"):   # the address it bound: http.listen may ask for port 0, and a script reads the port here
        from tracekit.transport.http import HttpServer
        host, port = next(s for s in servers if isinstance(s, HttpServer)).server_address[:2]
        where = f" on {host}:{port}"
    print(f"tracekit signer {__version__} serving{where}", flush=True)
    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    for s in servers:
        s.shutdown()
        s.server_close()
    if cfg.get("socket"):
        try:
            os.unlink(cfg["socket"])
        except FileNotFoundError:
            pass
    if a.close_on_stop and os.path.exists(a.close_on_stop):
        try:
            if not service.close_log(CLOSE_WAIT_S):
                print(f"tracekit signer: the log is closed; a witness did not cosign its final notes within "
                      f"{CLOSE_WAIT_S:g}s", file=sys.stderr)
        except (RPCError, StorageUnavailable, OSError) as e:
            print(f"tracekit signer close-log: {e}", file=sys.stderr)
    service.close()
    return 0
