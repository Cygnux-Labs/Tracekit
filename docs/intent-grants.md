# Intent grants for costly actions (design proposal)

Status: a proposal, 2026-11-06. Nothing here is built. The owner approved the idea on 2026-11-06; this is the design
to review. Related: #606 (principled policy, for stops in coding work) and [PCM](pcm.md), whose grants this reuses.

## The problem

Tracekit holds each costly call for a person, one at a time. An agent paying ten invoices to the same two vendors
makes ten stops, and after a few the person approves without reading. The record holds ten single approvals and an
open total: fifty approvals of $20 add up to $1,000 that no one decided to spend.

## The idea

A person states the bounds once. The signer signs them into the run as a **grant**. A call inside the bounds runs and
is recorded as within the grant; a call outside is held with the exact reason. The offline verifier re-checks every
in-grant call against the grant from the bundle alone.

| The person says | The grant |
|---|---|
| "Send up to 500 USDC today, only to these two addresses" | `payment.send`: `currency == USDC`, `payee in [0xa1…, 0xb2…]`; `amount` totals at most 500 USDC; until 23:59Z |
| "Apply to staging only, destroy nothing" | `change.apply`: `env == staging`, `destroys == 0`, `replaces == 0`; for 4 h |
| "Email at most 20 people at @acme.com" | `message.send`: `channel == email`, `domain in [acme.com]`, `attachments == 0`; at most 20 distinct recipients; for 8 h |

Grants cover costly, narrow actions whose intent fits in a few typed fields. Everyday coding stays with #606.

## What it reuses

- **PCM grants, as they are** ([grants](pcm.md#grants), `tracekit/pcm/__init__.py`): signed by the log key, a root
  only from a person's approval, typed caveats (`check_caveats`, `satisfies`), children only by narrowing (`narrows`),
  tenant, expiry within 24 h. A grant made in Tracekit can ride in a PCM message as is.
- **Agent approvers' bounds and budgets** ([approvals](approvals.md#agent-approvers)): the closed-world reading of
  arguments (exact JSON types, no alias pairs, a size cap) and sum and count totals rebuilt from signed records. A
  grant's bounds come from a person, and the signer decides each call against them.
- **Approvals** (`tracekit/signer/service.py`) for who may issue; the **class readers**
  (`tracekit/policy2/classes.py`) for fields; **live constraints**, whose holds stay with a person.

### The grant record

The signer writes one record when a person issues a grant: a grant in PCM's own format, and beside it what the run
needs.

```json
{"name": "intent.grant",
 "grant": {"pcm_grant": 0, "ts": "2026-11-06T09:12:03.120000Z",
           "issuer": {"kind": "person", "id": "oidc:alice", "person": "alice", "run": "4205…", "tenant": "acme",
                      "approval_id": "apr-7c1e…"},
           "subject": "mtls:spiffe://acme/payout-agent", "intent": "payment.send@sha256:…",
           "caveats": [{"field": "currency", "op": "==", "value": "USDC"},
                       {"field": "payee", "op": "in", "value": ["0xa1…", "0xb2…"]},
                       {"field": "amount", "op": "<=", "value": 200000000}],
           "expires_at": "2026-11-06T23:59:00.000000Z", "delegable": false, "parent": null,
           "sig": {"key": "…", "sig": "…"}},
 "limits": [{"op": "sum", "field": "amount", "max": 500000000}, {"op": "count", "max": 10}],
 "description": "This week's two contractors, up to 500 USDC in all"}
```

- The grant's caveats bound each call. Its `issuer.run` is the one run that may use it, so the totals are complete in
  that run's records, and its `expires_at` ends it.
- `limits` bound all the calls together (`sum` of a field, `count` of calls, `distinct` values of a field). The signer
  keeps the totals, and the verifier recounts them from the run.
- `description` is the person's own words, shown on every hold.
- The person's approval covers the whole record, and the record is signed with the run.

Each intent is a PCM schema document in its existing field types: `payment.send` (`amount` int, `currency` enum,
`payee` id), `change.apply` (`env` enum; `creates`, `updates`, `destroys`, `replaces` int; `plan` id) and
`message.send` (`channel` enum, `recipient` string, `domain` id, `attachments` int).

**AP2.** Google's Agent Payments Protocol states the same thing for payments, and the names line up: Intent Mandate
`natural_language_description` → `description`; `intent_expiry` → `expires_at`; `merchants` and
`payment.allowed_payees` → `payee in […]`; `payment.amount_range {currency, min, max}` in integer minor units → the
same caveats in the same units; `payment.budget` → a `sum` limit; `payment.agent_recurrence.max_occurrences` → a
`count` limit. AP2's rule that an unknown constraint fails is ours too. Source: AP2 at
[`e1ea56db`](https://github.com/google-agentic-commerce/AP2/tree/e1ea56db72a6385bce3e5c1112b3a56ce60acb43)
(2026-04-29): `code/sdk/python/ap2/models/mandate.py` (`IntentMandate`),
`code/sdk/schemas/ap2/open_payment_mandate.json`, `docs/ap2/payment_mandate.md`, `docs/ap2/agent_authorization.md`.

## How a call is decided

1. The policy decides as today. Only an `ask` can be released; a deny stays a deny.
2. Every rule that asked must opt into the grant's intent: `approval: {grant: payment.send}` on `TK-M001` and
   `TK-M002`, as `approval: {agent: …}` opts a rule into agent approvers. Any other ask keeps the hold: `TK-M005` (no
   amount), the synthetic rules, `TK-HOLD`, `TK-CONSTRAINT`, a secrets rule. `TK-P001` and `TK-P002` (a recipient or
   payee only untrusted content brought) are released only when the grant pins that field with `==` or `in`.
3. The intent's reader turns the call into fields. A field it can't read keeps the hold (`no currency in the call`).
4. Every caveat passes (`pcm.satisfies`) and every limit has room, checked again on the writer so two calls can't
   spend the same room. A call counts toward the limits as soon as it is decided.
5. Inside: `flag`, `rule_ids: [TK-M001, TK-GRANT]`, `within grant g-3f9a by alice: 120 USDC to 0xa1…; 380 of 500 USDC
   left`. Outside: `ask`, with `grant g-3f9a: amount 700 USDC > 200 USDC`.

## The first three cases

They are the short list's costly actions whose meaning is in their arguments. They can't be undone or they reach
other people, and they come in runs of similar calls, where one-at-a-time approval breaks down.

**Payments** (`amount` in integer minor units, `currency`, `payee`). Read by `classes.extract` from the tools the
policy places in class `payment`, MCP ones included. Every payee key counts (`payee`, `to`, `destination`, `iban`, …);
two different values hold. Held: an amount that isn't integer minor units (`"12.50"`, `12.5`), no currency, a payee
off the list, a total reached.

**Production changes** (`env`, counts of `creates`, `updates`, `destroys`, `replaces`, and `plan`, a digest). The
[T2 executor](executor.md), which holds the credentials, makes the plan and runs exactly that plan: Terraform's
`plan -out` read with `show -json` (`resource_changes[].change.actions`; delete-then-create is a replace) and an apply
of that file by digest; a server-side dry run for `kubectl` and Helm; a deploy API's own environment, with a delete
counted as a destroy (PocketOS's `volumeDelete`); a migration's SQL through the SQL class's parser. `env` comes from
a `targets` table in the policy (state key, cluster URL, database host). Held: a T1 shell `terraform apply` or
`kubectl apply` (its plan is the agent's word), an unknown target, a destroy the grant forbids.

**Outbound messages** (`channel`, `recipient`, `domain`, `attachments`). Read from class `email` tools over `to`,
`cc`, `bcc` and `recipients` (today's `domains` field reads only `to`), Slack channel ids, SMS numbers. A call to
several people is checked once per recipient, and each must pass. Recipients are recorded as keyed hashes, so the
verifier counts distinct people without seeing addresses. Held: an address that isn't one mailbox
(`"a@acme.com"@x.io`), a domain not listed exactly after IDNA and lower case (`acme.com.evil.io`), too many recipients.
A grant bounds who and how many; the secrets rules still read every message body.

## How a person issues a grant

From a held call, the main path: the hold message and `tracekit approvals show` offer "approve this and others like
it", with bounds proposed from the call for the person to edit. The approval and the grant are one signed step, and
the held call is the grant's first use. The viewer's approval page gets the same form. The commands (all proposed):

- From a held call: `tracekit approvals approve apr-7c1e… --grant --payee 0xa1… --payee 0xb2… --max '200 USDC'
  --total '500 USDC' --until 23:59Z`.
- Directly, before the run asks: `tracekit grant add --run 4205… --intent payment.send --where 'payee in [0xa1…,
  0xb2…]' --total 'amount 500 USDC' --until 23:59Z --note "this week's contractors"`.
- `tracekit grant list --run 4205…` shows a run's grants and what each has left; `tracekit grant revoke g-3f9a…` ends
  one.

## Security invariants

1. **Only a person issues a root grant.** `grant_issue` makes `pcm_grant`'s checks: signer.yaml has `approvals`; the
   issuer is a person `approvals.persons` names who may answer this run; never the run's agent, an agent approver or
   the subject; never self-approved. A dev signer has no grants, so costly calls are held as today.
2. **The agent can't widen or extend one.** No RPC changes a grant; a child only narrows (`pcm_delegate`) and never
   outlives its parent; 24 h at most; a person can revoke.
3. **Signed records:** the grant, its revocation, and each in-grant `policy.decision` with the fields and totals used.
4. **Anything missing falls back to today's hold:** no grant, an expired, revoked or used-up one, another run's,
   tenant's or agent's, a field the reader can't read.
5. **The verifier re-checks every in-grant call offline** (below).
6. **Only opted-in asks are released.** Never a deny, a synthetic rule, `TK-HOLD` or `TK-CONSTRAINT`; no grant is
   issued or used in a held or quarantined run.
7. **What runs is what was checked.** At T2 the call runs with the arguments the signer decided. At T1 the agent's
   process reports its own, so the first build releases only T2 calls (the executor, the MCP gateway).

## Records and verification

The closed v2 schema and its TypeScript copy stay as they are. Everything new rides in `ext`, format 1.4's non-critical
slot ([format v2](format-v2.md#9-bundle-layout)), and meets its rule: an older verifier's lines stay true, since an
in-grant call is a `flag` and was allowed.

| Where | Change |
|---|---|
| `intent.grant` ext record | new: the PCM grant as is, its `limits` and `description` ([above](#the-grant-record)) |
| `intent.revoked` ext record | new: the grant's hash, who revoked it, why |
| `policy.decision` `ext.grant` | new: `{grant, fields, used}`: the grant's hash, the fields it bounds, the totals after this call |
| Policy file | an ask rule's `approval: {grant: <intent>}`; the `targets` table |
| Signer RPC | `grant_issue`, `grant_list`, `grant_revoke`: contract version 22. The `pcm_*` calls stay as they are |
| Bundle | the policy snapshot of in-grant decisions, as export bundles one for agent approvals |

The Python and TypeScript verifiers add an `intent grants` check:

- **Each grant:** signed by the log key; its `approval_id` names a person's `approval` in the run, not self-approved
  or an agent's; the subject is the run's agent and not the issuer; the run's tenant; at most 24 h; caveats valid for
  the intent's schema document, which the verifier ships.
- **Each in-grant call:** its grant is earlier in the run and not revoked; decided before expiry; its fields pass every
  caveat; its `used` is the previous call's plus its own, within every limit; its rules opt into the intent in the
  bundled policy.
- **The fields** are the signer's reading of the arguments, which the bundle holds as commitments. With the arguments
  opened (`tracekit signer reveal`, `tracekit audit`), the named reader version reads them again and must agree; with
  them closed, the line says "fields as the signer read them".

```text
intent grants   2 grant(s) by alice; 14 call(s) within them, each re-checked; fields as the signer read them
```

## The smallest first build

Payments only, T2 only, a grant scoped to one run: `grant_issue` from a held call and `tracekit grant`; `TK-M001` and
`TK-M002` opted in in `server-comms.yaml`; the `intent grants` check in both verifiers. Production changes (Terraform
through the executor first), then messages, follow as their own PRs. Later, for on-chain payments: Proof-Gated Signing
(arXiv 2610.00354), on the after-investment list.

| Measure | How | Passes when |
|---|---|---|
| Harmless stops removed | E18's payment workload and the dogfood customer-service agent, with and without one grant | stops fall to the first call plus the out-of-bounds ones |
| Attacks still held | new E23, E18- and E8-style: out-of-bounds arguments (`"50"`, 50.5, an alias pair, a currency switch), calls summing past the total, two racing for the last room, expiry, revocation, a foreign grant, the agent issuing, widening or extending one, an untrusted payee | every call held; every forged bundle (edited fields or totals, a missing grant, a grant after its call) fails in both verifiers |
| Nothing else moves | E17's policy corpus and #605's scoreboard under a broad payment grant | no verdict changes outside class `payment`; PocketOS's `volumeDelete` still held |
| Speed | E21's p99 gate | within it |

The gain shows on payment work, so the dogfood agent and E18's workload are the measure.

## Open questions

1. Dev mode: no grants (proposed, as `pcm_grant`), or allowed and labelled self-approved, as #606 does for learning?
2. Scope: one run (proposed), or an agent's runs for a day? Recounting across runs needs a run-set bundle.
3. T1: keep holding (proposed), or release labelled "the agent's process reported these arguments"?
4. Should the policy cap what a person may grant (no grant over 5,000 USD a day)?
5. Accept an AP2 open Payment Mandate the user's wallet signed as the grant? It carries the user's own signature.
6. Schema documents: `payment.send`, `change.apply` and `message.send` are new documents. Publish them as new entries
   in the PCM repository's registry, so other receivers share them, or keep them in Tracekit for now?
