# Compliance mapping

These pages are for a security, risk or compliance reviewer, for an auditor, and for the engineer who answers their
questionnaire. Each one takes the requirements of one framework that concern what an AI agent does, and says, for
each: what Tracekit provides as a technical measure, what evidence you can show, and what stays your responsibility.

> **Not legal advice.** These pages describe what Tracekit records and checks. They are not legal advice and not a
> certification. Using Tracekit doesn't make a system compliant with any law or standard, and it doesn't meet any
> requirement on its own. It is one control among several. Whether it is enough for a requirement in your setting is
> for you, your auditor and your counsel to decide.

## The pages

| Framework | What it is | Who it binds | Page |
|---|---|---|---|
| EU AI Act, Regulation (EU) 2024/1689 | EU law | Providers and deployers of AI systems in the EU. The obligations mapped apply to high-risk AI systems only | [EU AI Act](eu-ai-act.md) |
| ISO/IEC 42001:2023 | International standard for an AI management system | Organisations that adopt it, or whose customers ask for it; certifiable | [ISO/IEC 42001](iso-42001.md) |
| NIST AI RMF 1.0 (NIST AI 100-1) and its Generative AI Profile (NIST AI 600-1) | US voluntary framework | Organisations that adopt it | [NIST AI RMF](nist-ai-rmf.md) |
| OWASP Top 10 for LLM Applications 2025 and OWASP Top 10 for Agentic Applications for 2026 | Community lists of security risks | Nobody; security reviews and questionnaires use them | [OWASP](owasp.md) |

Every requirement identifier on these pages was checked against the primary text on 2026-10-18, except the titles of
ISO/IEC 42001's Annex A controls, which were checked against public sources (see that page). Each page lists its
sources. Laws and standards change: check the current text before you rely on a row.

## What Tracekit produces

| Evidence | What it holds | Specified in |
|---|---|---|
| Signed records | Every tool call, policy decision, approval and result the capture path reports, in one hash chain per run. The signer signs each record (Ed25519); the agent holds no key and assigns no sequence number | [format v2](../format-v2.md#3-events) |
| Decisions with rule ids | `policy.decision`: allow, flag, ask or deny, every rule id that matched, the hash of the policy that decided (`policy_hash`) and a commitment to the arguments | [policy](../policy-v2.md#decisions) |
| Approvals | `approval.request`, `approval` and `approval.consumed`: the held call, who answered (the identity the signer's transport established), the reason, and whether it was a self-approval or break-glass. Each is bound to the call's exact arguments and consumed once | [approvals](../approvals.md#flow) |
| Signed gaps and tamper records | `capture.gap`, `trace.tamper` and `reconcile.*`: an outage, a call that ran against its decision, an edited store, a call one capture layer saw and another didn't. Only the signer writes them | [verdicts](../verdicts.md#signed-gaps) |
| Checkpoints and cosignatures | Signed notes over the log's Merkle tree (C2SP), cosigned by witnesses and optionally anchored in Rekor. Witness cosignatures and Rekor anchors are experimental; checkpoints are part of the stable v2 format | [witnesses](../witnesses.md#v2-c2sp-tlog-witnesses) |
| Bundles (`.tkb`) | One run, or a tenant's run-set (every run registered in a range, so a run left out shows), with inclusion proofs, checkpoints and the policy snapshots a verifier needs. A bundle holds no code | [format v2](../format-v2.md#9-bundle-layout) |
| Verify reports | The output of `tracekit verify`, as text or JSON: integrity, assurance, isolation, gaps, coverage and approvals | [verdicts](../verdicts.md) |
| Incident and containment records (experimental) | `incident.opened`, `run.held`, `run.quarantined`, `run.resumed`, `incident.resolved` and `identity.suspension` | [incidents](../incidents.md) |
| Content access records (experimental) | With the content vault on: `content.accessed` (who read retained content, and for what purpose) and `content.erased` | [privacy](../privacy.md#the-content-vault) |

A v2 record keeps a call's arguments and result only as salted commitments, not as content. The content vault keeps
redacted content encrypted for investigations. It is off by default on a signer started from `signer.yaml`; the dev
signer keeps content for 7 days, so `tracekit view --dev` can show what each call ran
([privacy](../privacy.md#the-content-vault)).

## Handing evidence to an auditor

The [auditor guide](../auditor-guide.md) is the full procedure. In short:

1. The operator gives the auditor the log's verifier key once, through a channel it can be held to (a signed letter,
   a contract annex):

   ```sh
   tracekit signer vkey --config signer.yaml
   ```

2. After the next checkpoint covers the records, the operator exports the runs the auditor samples, and the tenant's
   run-set, which shows that no run was left out:

   ```sh
   tracekit export --v2 --run <run id> --config signer.yaml -o run.tkb
   tracekit export --v2 --run-set --tenant <tenant> --config signer.yaml -o run-set.tkb
   ```

3. The auditor installs a verifier at a pinned version from PyPI or from source they reviewed, builds `trust.json`
   from independent sources (the log key from the operator, each witness key from the witness's operator), and
   verifies offline:

   ```sh
   pip install 'tracekit-ai==<version>'
   tracekit verify run.tkb --trust trust.json --strict
   tracekit verify run-set.tkb --trust trust.json --strict --json > run-set.report.json
   ```

   The JSON report is the static record of the check, for the working papers. A second verifier, written in
   TypeScript from the format spec, reaches the same verdicts ([auditor guide](../auditor-guide.md#4-verify)).

4. To check that arguments from another source (an application's own log, say) are the ones a decision was made on,
   the operator reveals that one record's salt with `tracekit signer reveal --record <seq> --config signer.yaml`, and
   the auditor recomputes the commitment ([auditor guide](../auditor-guide.md#6-check-content-against-a-commitment)).

In the report, look at least at: `Integrity: VERIFIED` (not `open`) for finished runs; `Assurance: witnessed`, with
witnesses you class as independent; `run-set: COMPLETE`; `isolation: separate-user` or `remote`; and the `gaps`,
`policy`, `coverage` and approval lines ([verdicts](../verdicts.md)).

Operator-side views are not evidence. The verdicts `tracekit view` shows are computed on the operator's side, and
`tracekit doctor` output is advice about the host ([limits](../limits.md#viewer)). The evidence is the bundle,
checked by a verifier and a trust config the auditor chose.

## How the deployment changes the evidence

The same records mean different things depending on who could have rewritten them. [Guarantees](../guarantees.md)
says, per deployment, what you can rely on and what you can't.

| Deployment | Who can reach the keys and the log | `isolation` in the report | What the evidence supports | Status |
|---|---|---|---|---|
| Dev mode (`tracekit up`, `tracekit.instrument()`, `tracekit init --dev --v2`) | The agent's own OS user | `same-user` | Tamper evidence against edits made after export. Nothing against the agent itself: it can read the key and re-sign the log. Not evidence of an agent's behaviour for an audit | Stable |
| Linux system mode (`tracekit init --v2 --user AGENT` as root) | Root and the signer's OS user | `separate-user` | The agent can't read the key or rewrite the store; an edit to the store becomes a signed tamper record. It doesn't show that every action was reported: the agent can remove its own hook | Stable |
| Container sidecar | The signer's uid and whoever administers the node | `separate-user` | As system mode, against the agent. Nothing against the node's administrator | Experimental |
| Docker Compose stack (`deploy/compose/`) | Whoever administers the Docker host | `separate-user` (the agent shares the signer's socket) | As a sidecar, against the agent. Nothing against the Docker host's administrators | Experimental |
| Central signer over HTTPS | Whoever administers the signer's host and storage | `remote` | Nothing on the agent's machine holds the evidence. Against the operator, only with an independent witness and a monitor | Experimental |
| Mediated: LLM gateway, tool executor, MCP gateway, egress observer | As for a central signer | `remote` | Model calls, credentialed actions and MCP calls are recorded by services outside the agent, which holds no credentials to act around them. That they are the only route is the operator's assertion, recorded as not attested | Experimental |

Assurance is a separate question: who vouches for the checkpoints. `dev` means nothing outside the operator does, or a
run holds a self-approval; `local`, only witnesses the operator runs; `witnessed`, enough independent witnesses or
anchors. Without an independent witness, whoever holds the signer's key can rewrite history unseen. No public witness
runs yet, so `witnessed` needs a witness you or a partner run ([witnesses](../witnesses.md#the-public-witness)). For an
audit, ask for `isolation: separate-user` or `remote` and `Assurance: witnessed`.

## What Tracekit doesn't do

- **Compliance or certification.** It doesn't assess conformity, register a system, write its technical
  documentation or certify anything.
- **Your management system.** Policies, roles, risk and impact assessments, internal audit, management review and
  training stay yours. Tracekit gives those processes records to use.
- **Data governance.** Training, validation and test data, their quality and their provenance are out of scope.
- **Model evaluation.** It doesn't measure accuracy or robustness, red-team a model, or assess bias and fairness.
- **Transparency to end users.** It doesn't tell people they are dealing with an AI, or mark generated content.
- **What no capture path sees.** A subprocess's own actions (unless a kernel sensor import covers the run), code that
  skips the adapter and a call around a gateway that isn't mandatory leave no record. Processes and files are captured
  only by the experimental kernel sensor import (Linux, Tetragon or Falco) ([limits](../limits.md)).
- **Prevention of everything it records.** A record doesn't stop an action. Only calls routed through Tracekit can be
  denied or held, and policy rules are tripwires a determined agent can reword around.
- **Intent and truth.** A verified bundle doesn't prove why a call was made, or that a tool result the agent
  reported was true ([FAQ](../faq.md#what-cant-tracekit-prove)).
- **Retention.** The signer never deletes records, but keeping the store and the bundles for the period the law sets,
  backing them up and disposing of them are yours. So is the personal data in them: approvers' and principals'
  identities, and when people and agents acted.

## Stable and experimental

Tracekit has a small stable core and larger experimental surfaces ([what's stable](../support.md)). The stable core
includes the dev and Linux system mode signers, the Python SDK and the stable framework integrations, the Claude Code
hooks, policy v2 with command-line approvals, v2 bundles, both verifiers and the laptop viewer. Experimental features
work and are tested, but may change between releases and get less hardening. The pages mark each experimental
mechanism they rely on. Where an auditor will test a control, build it on the stable core if you can.
