# Viewer

## Laptop viewer

![tracekit view: three runs with their verdicts, the support agent's run selected, its blocked calls with rule reasons, the held refund approved by an ops approver, and the run review](demo/viewer.png)

`tracekit view [--dev | --config signer.yaml | --data-dir DIR]` reads one signer's store, read-only, and verifies each
run with the code `tracekit verify` runs. The page is the observer's terminal, for runs:

- **Runs** (panel 1): each run with its agent's registered name, the verifier's verdict (`VERIFIED`, `FAILED`, or
  `PENDING` until a checkpoint covers the run's last record; every verdict is operator-side, see below), start time,
  duration, and its calls, blocked, held and gaps. Clicking a run scopes the tape, timeline, tool mix and header to it;
  **All runs** restores the full view. A run that fails shows only its verifier report.
- **Tape** filters: All, Decisions, Approvals, Gaps & alerts. Holds and approvals are their own rows (`HOLD`,
  `APPROVE`, `REJECT`) in words: who asked, which rules, who answered (attested, or vouched for by a bridge), the
  reason, self-approval and break-glass. The signer's own records (`signer.epoch`, `refusal.summary`, key records) are
  the `signer`'s rows, not an agent's.
- **Detail**: a call's decision, its rules with their reasons, its arguments commitment and approval binding, and the
  verdict of its run. v2 records keep a call's arguments only as a salted commitment, so the viewer shows the rules'
  reasons instead (from the policy whose hash the decision records: a shipped pack or the config's `policy`; other
  policies show rule ids only); `tracekit signer reveal --record <seq>` gives an auditor the salt.
- **Run review** (detail, with a run selected and no row): Integrity and Assurance, allowed / flagged / denied / held
  and who approved, gaps by kind, coverage. Each line opens its first record.
- **Replay** (with a run selected): `SPACE` plays or pauses, `←` `→` step one record, `D` `H` `G` jump to the next deny,
  hold or gap, `L` or `ESC` returns to live. The header and tape show the run as of the playhead; the timeline marks
  it.

The timeline is scaled to the calls shown, not the clock. The page and server are the observer's, with its
checklist ([security-checklist.md](security-checklist.md)).

### Laptop viewer API

Every request needs the token in the URL `tracekit view` prints (`$TRACEKIT_VIEW_TOKEN`, else a random one). Open
`/?token=…` once: the page exchanges it for an `HttpOnly` session cookie and reloads without it. A script sends
`Authorization: Bearer <token>` instead; `?token=` on an `/api/` path is refused (401), so the token never sits in an
API URL. Every request is a `GET`:

| Path | Answers |
|---|---|
| `/api/snapshot` | `{next, dropped, records}`: the tape rows the page renders (each run's verifier report, then its records once it verifies), `next` the index to stream from |
| `/api/verify` | `{records, ok, problems, head}`: the records shown from runs that verified, and each run that failed with its failure (the header's chain badge) |
| `/api/stream?from=N` | `text/event-stream`: one `data:` line per record from index `N` on, as they are recorded |
| `/api/why/workspace`, `/api/why/runs/<id>` | the why logs, with `--why` ([below](#why)) |

The run pages and their API (`/runs`, `/api/runs`, `/api/run`, `/api/bundle`) are the central viewer's, served only
with `view.logs` ([below](#pages-and-api)).

## Why

The viewer is also the UI of [`tracekit why`](why.md): with why logs it investigates them on the same page, so one run
is both signed evidence and a causal log.

```bash
tracekit view --why runs --allow-program myapp.agents:SYSTEM
tracekit why serve runs --allow-program myapp.agents:SYSTEM     # the same page on why logs alone, no signer store
```

`--why DIR` names the why logs (default: `why/` in the signer's data dir, where the signer-backed why runtime writes
them, when it exists). A tool call's why event cites the signed record it produced (`tracekit: {run_id, run_seq}`);
that citation joins the two.

- **Detail · where the arguments came from**: from the signed `provenance` of the call's decision (labelled
  `signed · observed`): each argument whose value only untrusted content brought into the run, its kind and the record
  that brought it (click to select it), never the value; `unavailable (signer restarted)` or `truncated` when the
  signer's index could not say. With a why log of the run, also the why analysis of each value: the task, a trusted
  input or result, an untrusted input or result, or written by the model.
- **Detail · WHY** (the detail's second view, for the selected call): the verdict sentence, **how it got here** (the
  observed path through agents, model calls and messages, from every untrusted input), **candidate causes** with their
  status (primary cause, contributing, confirmed, joint, inconclusive, no effect seen, ruled out, not tested), effect,
  95% interval and with → without rates, and **FIND THE CAUSE** / **RUN TEST**.
- **Views** (header buttons; the run list and tape stay): **GRAPH**, the run's data flow (observed edges; tested causes
  in red; inferred links and ruled-out tests hidden until ticked; click a node for what it came from and led to),
  **AGENTS** (the channels used, the influence matrix, the critical path), **INFLUENCE** (across runs: sources ×
  tools, with tested effects). **DESK** returns to the panels.
- **Alerts**: the why alerts (a sensitive call using a value only untrusted content supplied, a call downstream of
  untrusted input, evidence alerts) join the alert panel labelled `WHY`; signed records' alerts are labelled `SIGNED`.

FIND THE CAUSE and RUN TEST replay the run, so they run only for the programs passed with `--allow-program` (the run
names its program; replay imports it). Otherwise the panel shows the `tracekit why` command to run instead. New runs
and new alerts arrive over the page's event stream as they are recorded.

The why API is served by the viewer, on its session and checklist: `GET /api/why/workspace`, `GET /api/why/runs/<id>`,
`POST /api/why/runs/<id>/tests` and `/attribute` (the token, a same-origin JSON body) and `POST /v1/ingest` (a
Bearer token only: an `--ingest-token`, which reads nothing, else the token; [why.md](why.md#server-and-api)). Why logs belong to no tenant, so only the printed token
sees them, never an OIDC session.

## Central viewer

`tracekit view` with a `view.logs` section reads every log of a central deployment
([deploy-kubernetes.md](deploy-kubernetes.md)) and serves its runs to auditors, approvers and operators, read-only.

```yaml
data_dir: /tmp                        # the viewer's own; never a signer's
view:
  logs: [log-0.dsn, log-1.dsn]        # one DSN file per log (its schema), for a role holding READ_GRANTS only
  oidc: {issuer: corp, client_id: tracekit-viewer, redirect_uri: https://view.corp.example/callback,
         roles: {auditor: ["group:corp/auditors"], approver: ["group:corp/approvers"],
                 operator-admin: ["group:corp/sre"]}}
```

```bash
tracekit view --config viewer.yaml --host 0.0.0.0 --tls-cert tls.crt --tls-key tls.key
```

Each DSN's role holds `tracekit.storage.postgres.READ_GRANTS` (SELECT only), so the viewer can't write a log even by
mistake. Each log's verdicts pin the log vkey that log's store holds (or `--log-vkey`, for every log).

### Who sees what

| Session | Runs | Approvals |
|---|---|---|
| auditor (OIDC, the issuer's tenant claim) | its tenant's, read-only | none |
| approver (OIDC, the tenant claim) | its tenant's, read-only | its tenant's, with `view.signer` ([approvals.md](approvals.md#web-approvals-and-passkeys)) |
| operator-admin (OIDC) | every tenant's, read-only | none |
| the printed token | every tenant's, read-only | none |

The tenant is enforced in every query the viewer makes (a `tenant = …` condition taken from an auditor's or approver's
session, never from the request), not only on the page: a session of tenant A gets no run of tenant B from a list, a
search, a run's page or a bundle download, even with B's run id. Its only write path is the approval pages.

### Pages and API

`/runs` lists the runs, log by log, newest first, and searches them. Every request is a `GET`:

| Path | Answers |
|---|---|
| `/api/runs?run&agent&tenant&since&until&verdict&gaps&denies&approvals&limit&after` | `{runs, next}`: at most `limit` (50) runs, each with its log, tenant, agent, first and last event time, record count, gaps, denies, approvals and verdict; `next` is the `after` of the next page. `since`/`until` are RFC 3339 UTC times; `verdict` is `verified`, `failed` or `pending`; `gaps=1`, `denies=1` and `approvals=1` keep runs that have one; `tenant` narrows an operator-admin's list. One search query per log per page, plus a reader of each log with matching runs (it reads that log's index). |
| `/api/run?log&tenant&run&from` | the run's verdict with verify.v2's full report and, only when it verified, 500 of its records from the `from`th, with `next` |
| `/api/bundle?log&tenant&run` | the run's `.tkb` bundle |

A run's verdict is what `tracekit verify` gives the bundle the viewer exports from the store; a run whose last record no
checkpoint covers yet is `pending`, and a run that fails shows its failure report and none of its records. Every verdict
carries the label **"operator-side view — re-verify with the signed release for evidence"**: the viewer runs on the
operator's side, so its verdict is not evidence. An auditor downloads the bundle and checks it with `tracekit verify`
from the signed release, against keys and witnesses they pinned themselves ([auditor-guide.md](auditor-guide.md)).

The page and API pass the browser surface's checklist ([security-checklist.md](security-checklist.md)): strict CSP
with a fresh nonce, every value shown as text, `HttpOnly; SameSite=Strict` session cookies, and HTTPS off loopback.
