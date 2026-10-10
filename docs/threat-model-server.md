# Threat model: the v2 signer

The claim is the same as for laptops ([threat model: laptop](threat-model-laptop.md)):

> **Tracekit proves what its capture path recorded, and that the record has not changed since it was signed and
> checkpointed.**

It does not prove intent, complete coverage, or that a reported tool result is real. This page covers the v2 signer
(`tracekit signer serve`) and the agents that reach it over its RPC, for each way of deploying it. How to read the
resulting report: [verdicts](verdicts.md).

## Deployments

| Deployment | How | Who can reach the signer's keys and store |
|---|---|---|
| **dev** | `tracekit up`, or auto-spawned by the first client; same OS user as the agent | the agent's user |
| **laptop system mode** | `sudo tracekit init --v2`: the signer runs as its own OS user from a root-owned install (Linux; macOS experimental) | root and the signer's user |
| **signer on another host** | `tracekit signer serve --config signer.yaml` with `http:` (k8s service account, mTLS or token identity) | whoever administers that host and its storage |

In every deployment the agent's process holds no signing key and assigns no sequence number (I1), and only the signer
writes gap and tamper records (I6). What differs is whether the agent's identity can reach the signer's files (I0):
in dev mode it can, by design, and every dev report says so (`isolation: same-user`, usually `Assurance: dev`).

## Adversaries

| Id | Adversary | Reach |
|---|---|---|
| **S1** | Prompt-injected or misaligned agent | Acts through the framework's tools, with the agent's identity |
| **S2** | Compromised application code or dependency | Runs inside the agent's process: can skip or fake adapter calls and holds the run token |
| **S3** | Insider with deploy or database rights | Can edit, delete or restore the signer's store and restart the signer |
| **S4** | The operator organisation, including whoever exports bundles | Runs the signer and chooses what to export; can fork or rewrite the log with its own key |
| **S5** | Malicious end user or tenant | Another tenant's caller, or another local user, using the signer's RPC |
| **S6** | Cloud provider | Out of scope |

Laptop attackers map onto these: A1 is S1, A2 is S2, A3 is S5 on a shared machine, A4 (root on the signer host) is
S3/S4, and the laptop's exporter E is S4.

### S1: prompt-injected agent

| | dev | laptop system mode | signer on another host |
|---|---|---|---|
| Can | run commands as the signer's user: read its keys, stop it, rewrite and re-sign the store. The coding pack's `TK-D007`/`TK-D013` deny the obvious attempts; they are tripwires | call the tools the policy allows; ask for approvals | same as system mode |
| Cannot | forge a record through the RPC, change the policy the signer decides with, or edit a checkpoint a witness already cosigned without it showing | reach the signer's keys, store or policy; approve its own calls; run a held call without a consumed approval unrecorded; run calls unrecorded by stopping the signer (fail closed) | same, and nothing on the agent's machine holds the evidence |

Invariants: I0 (system mode and remote only), I1, I2 (the signer decides over the raw arguments with its own policy
and classes), I3 (approvals bound to the exact arguments, consumed once). Covered by `tests/test_signer_policy.py`,
`tests/test_signer_approvals.py`, `tests/test_signer_lifecycle.py::TestSignerOnlyRecords`, `tests/test_system_v2.py`,
and `eval/e8_insider_v2.py` (E8v2.1 decoy signer, E8v2.3 signer down, E8v2.4 policy swap, E8v2.5 self-approval).

### S2: compromised application code

| | every deployment |
|---|---|
| Can | skip the adapter for some calls (they are then unrecorded at T1); report false results; send whatever the client may send for its run |
| Cannot | forge, reorder or delete signed records; write gap, tamper or reconcile records; claim the signer's isolation or fail mode; reuse an approval for other arguments or another call |
| Caught by | reconciliation across capture layers: a model call that requested a tool with no matching `decide` is `reconcile.hook_missing`, a decide no model call requested is `reconcile.fabricated`, other arguments are `reconcile.args_mismatch` (the `coverage` warning). An approval with `executor: t2` makes the executor outside the agent run the approved arguments, not the agent's |

Limits: in-process autotrace (L3) runs in the same process as S2, so S2 can suppress it too; the report shows
`(L3 absent)`. The [LLM gateway](gateway.md) captures L3 outside the agent; layers L4–L6 are not shipped yet, so
without the gateway, coverage is what the agent's process reported. All limits: [limits.md](limits.md). Invariants: I1, I2, I6. Covered by `tests/test_reconcile.py`, `eval/e10_reconcile.py`,
`tests/test_signer_lifecycle.py` (`test_client_forged_gap_or_tamper_is_refused_and_summarised`,
`test_client_isolation_and_fail_mode_claims_have_no_effect`) and `tests/test_known_gaps_v2.py::test_kg11_signer_isolation_not_taken_from_client`.

### S3: insider with deploy or database rights

| | dev, system mode or another host |
|---|---|
| Can | edit, truncate or delete store files; restore an old backup; stop and restart the signer; with the key file, re-sign a rewritten log |
| Detected | a damaged tail stops startup; the background `fsck` turns an edited record into a signed `trace.tamper{edited}` and refuses writes; at startup, a log behind what a witness cosigned is a signed `trace.tamper{rollback}` and writes stop until acknowledged; an edited or rebuilt bundle fails verification |
| Not detected | a rewrite of records no independent witness has cosigned yet, by someone holding the key |

Requires an external witness ([witnesses](witnesses.md)) and the startup rollback check. Invariants: I6, I7, I8.
Covered by `tests/test_signer_startup.py`, `tests/test_signer_service.py` (`test_a_damaged_tail_signature_stops_startup`,
`test_rollback_against_a_witness`, `test_unreachable_witness_starts_degraded`), `tests/test_bundle_v2.py`
(`test_e1_mutations_fail`, `test_rebuilt_chain_with_the_real_key_fails`) and the bundles in `tests/golden/negative/`.

### S4: the operator organisation and the exporter

| | every deployment |
|---|---|
| Can | choose which runs and records to export; hand over an edited bundle; fork or rewrite its log with its own keys; withhold a key retirement |
| Detected | an edited bundle (manifest, signatures, chain, inclusion); a missing, spliced or doubly-finalised run, or a withheld `key.retire`, against a run-set of the tenant's registry log; a fork or rewrite after an independent pinned witness cosigned or Rekor anchored the checkpoint (`Assurance: witnessed`) |
| Not detected | a log never shown to an independent witness (`Assurance: dev` or `local` says so); two forks shown to two verifiers, unless a pinned monitor's report of the same tree size shows the other root (`witnessed+monitored`, [monitor.md](monitor.md)); anything beyond detection: nothing prevents it |

The verifier and its trust config must come from somewhere other than the operator (I9): bundles carry no code or
trust ([auditor guide](auditor-guide.md)). Invariants: I4, I7, I9. Covered by `tests/test_registry_runset.py`,
`tests/test_bundle_v2.py::test_assurance_levels`, `tests/test_witness_publish.py`, `tests/test_rekor_anchor.py` and
`tests/golden/v2/run-set.tkb`.

### S5: malicious end user or tenant

| | every deployment |
|---|---|
| Can | call the RPC with its own identity, within its quotas |
| Cannot | write into another run (run tokens are bound to tenant, run and identity); choose its tenant unless configured as a multi-tenant app (then recorded `tenant_attested: false`); see or answer another tenant's approvals; read other tenants' registry leaves from a run-set bundle (each tenant has its own salt); exhaust the signer (rate limits and counts, refusals summarised in signed records) |

Invariant: I5. Covered by `tests/test_signer_limits.py`, `tests/test_signer_service.py`
(`test_request_id_and_tokens_are_scoped_to_the_identity`, `test_quotas_and_refusal_summaries`),
`tests/test_signer_lifecycle.py::test_tenant_is_attested_unless_a_configured_app_asserts_it`,
`tests/test_signer_approvals.py::test_another_tenant_does_not_see_the_approval` and E8v2.2 (another local user writing
into the agent's run).

### S6: cloud provider

Out of scope. A provider that controls the hosts and storage of the signer and its witnesses can do anything S3 and
S4 can. Witnesses run by other parties on other infrastructure and Rekor anchors still show a rewrite after they saw
the log.

## Invariants

The invariants (I0–I10) every change is checked against:

| | Invariant |
|---|---|
| I0 | The agent's identity can't write the record store, read signing keys, write witnesses or change the signer's code, config or policy. Dev mode breaks this by design and says so |
| I1 | No signing key, chain head or sequence assignment in the agent's process |
| I2 | The signer evaluates policy over the raw arguments with its own classes; decisions are deterministic in `(policy_hash, engine, canonical args)` |
| I3 | Approvals bind to exact arguments and are consumed once |
| I4 | Runs are registered before their first action and closed by a signed `run.final` |
| I5 | Identity proves the workload, not the tenant or user; tenant and principal are labelled attested or asserted |
| I6 | Gaps are signed, never silent; clients can't forge gap or tamper records |
| I7 | A stable log key signs checkpoints; `alg` and `kid` are signed; messages are domain-separated; key retirement is positional; time comes from witnesses or timestamps |
| I8 | Old evidence stays verifiable: frozen per-version verifiers, additive formats, golden bundles never regenerated |
| I9 | The verifier and its trust config don't come from the party being verified |
| I10 | Canonical JSON is JCS; out-of-range integers, non-finite numbers, duplicate keys and lone surrogates are rejected |

How they are met in the format: [format v2](format-v2.md).

## Known limits

All limits, across every doc: [limits.md](limits.md).

- **Harness binding is opt-in and Linux-only:** without it (`tracekit init --v2 --harness NAME=PATH`), a process
  outside the agent's harness, running as the agent's user, can register a run of its own (E8v2.6). The run is
  labelled with the identity that registered it. With it, see [what binding does not stop](faq.md#what-does-harness-binding-not-stop).
- **Monitor reports cover one view:** `tracekit monitor` sees the log the signer serves it; a bundle's checkpoint
  smaller than the report's tree is not proven consistent with it, so a split view shows only at equal sizes or to
  witnesses.
- **Key assurance is `asserted`** unless a [record-key issuer](issuer.md) certifies the keys: the log declares its own
  record keys.
- **Fail-open classes:** tool classes configured `fail_modes: {<class>: open}` run when the signer is down, unrecorded;
  the report lists them.
- **Windows:** dev mode only.
