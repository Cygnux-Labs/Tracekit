# Intent grants: approve costly payments once, with limits

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

An agent pays this week's invoices to the same two contractors. Each payment waits for a person, so the person
approves ten payments one at a time. With an intent grant, the person approves the first payment and states the
bounds for the rest once: who may be paid, the most for one payment, the total, and for how long. The signer then lets
each payment inside those bounds run, records it as within the grant, and holds anything outside them with the exact
reason. `tracekit verify` re-checks every released payment against the grant and its running total, from the bundle
alone.

Payments are the first kind of call a grant covers (the intent `payment.send`). A grant covers one run.

## A worked example

A Claude Code agent on a laptop pays through an MCP tool, `mcp__payments__send_money`. The dev signer holds money-moving
MCP tools for a person (rule `TK-A044` of the coding pack).

**1. The first payment is held.** The agent pays the first contractor 120 USDC:

```text
[tracekit] HELD, nothing ran: apr-99c7fe5d7ff4ef1014c764c787b56c4f (TK-A044, TK-F006), expires 07:19 UTC.
Why: moving money through an MCP tool (sending, transferring or converting money, or a refund)
Instead: Check the amount, currency and recipient in the call's arguments before approving it; a refund with no amount refunds in full.
Person: look with `! tracekit approvals show apr-99c7fe5d7ff4ef1014c764c787b56c4f`; allow once with `! tracekit approvals approve apr-99c7fe5d7ff4ef1014c764c787b56c4f`; refuse with `! tracekit approvals reject apr-99c7fe5d7ff4ef1014c764c787b56c4f`.
```

**2. The person looks.** `tracekit approvals show` says how a payment grant reads the call, and gives a command with
limits taken from it, to edit:

```text
$ tracekit approvals show apr-99c7fe5d7ff4ef1014c764c787b56c4f
approval    apr-99c7fe5d7ff4ef1014c764c787b56c4f (requested)
tool        "mcp__payments__send_money"
why         moving money through an MCP tool (sending, transferring or converting money, or a refund) (TK-A044)
...
grant       a payment grant reads it as 120 USDC to "0x1111111111111111111111111111111111111111"; to approve it and let more payments like it run, set your own limits:
            tracekit approvals approve apr-99c7fe5d7ff4ef1014c764c787b56c4f --grant --payee 0x1111111111111111111111111111111111111111 --max '120 USDC' --total '600 USDC' --for 1h
...
arguments (the signer's copy, in full):
{
  "amount": 120000000,
  "currency": "USDC",
  "to": "0x1111111111111111111111111111111111111111"
}
```

**3. The person approves it and grants payments like it.** Both contractors, at most 200 USDC each, 500 USDC in all,
for an hour:

```text
$ tracekit approvals approve apr-99c7fe5d7ff4ef1014c764c787b56c4f --grant \
    --payee 0x1111111111111111111111111111111111111111 --payee 0x2222222222222222222222222222222222222222 \
    --max '200 USDC' --total '500 USDC' --for 1h --note "this week's two contractors"
grant g-2f9deebdfc669a5b issued for run 1c2fd065d4cddefa68a4aca823c9631a: payments through "mcp__payments__send_money" to 0x1111111111111111111111111111111111111111, 0x2222222222222222222222222222222222222222, up to 200 USDC each, 380 of 500 USDC left, until 2026-11-06T07:20:58.856118Z. Recorded as self-approved: the dev signer runs as your own user and can't tell you from your agent
approved: apr-99c7fe5d7ff4ef1014c764c787b56c4f, by you. ...
```

The grant covers the held call's tool, `mcp__payments__send_money`, and no other. The held payment is the grant's
first: its 120 USDC count toward the total. The agent's retry of it runs on the approval, and the grant doesn't count
it again.

**4. Payments within the grant run.** 200 USDC to the second contractor, then 150 USDC to the first: no stop. Each
decision is signed as `flag` with `TK-GRANT`, and says what it released and what is left
(`within grant g-2f9deebdfc669a5b: 150 USDC to 0x1111…; 30 of 500 USDC left`).

**5. A payment outside it is held, with the reason.** 20 USDC to an address the person never named:

```text
[tracekit] HELD, nothing ran: apr-… (TK-A044, TK-F006), expires …
Why: grant g-2f9deebdfc669a5b: payee "0x3333333333333333333333333333333333333333" is not one of "0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222"; moving money through an MCP tool (sending, transferring or converting money, or a refund)
```

**6. The grant, as it stands.**

```text
$ tracekit grant list
g-2f9deebdfc669a5b  live  run=1c2fd065d4cddefa68a4aca823c9631a  payment.send  tools="mcp__payments__send_money"  self-approved (the run's own user, which the agent can be)  to 0x1111111111111111111111111111111111111111, 0x2222222222222222222222222222222222222222, up to 200 USDC each, 30 of 500 USDC left  until 2026-11-06T07:20:58.856118Z  "this week's two contractors"
```

**7. Verify.** `tracekit last` exports the run and verifies it; with `--detail` the report has the grant's line:

```text
intent grants   1 grant(s) (1 self-approved: issued by the run's own user, which the agent can be); 2 call(s) released
                within them (0 at T2, decided and run by an executor or gateway; 2 at T1, on the arguments the harness
                reported), each re-checked against its grant and its running totals
```

In `tracekit view`, the run's PERMISSIONS page lists the grant (who issued it, its limits, what is left, until when),
and each payment it released reads `WITHIN GRANT`, with the payment and what the grant had left after it. The tab
`WITHIN A GRANT` shows only those.

## Commands

| Command | What it does |
|---|---|
| `tracekit approvals show ID` | For a held payment, how a grant reads it (amount, currency, payee) and a command to approve it with a grant, limits taken from the call for you to edit; or why a grant can't read it |
| `tracekit approvals approve ID --grant LIMITS` | Issues a grant from the held call, then approves the call: the call is the grant's first payment, and its tool one the grant covers |
| `tracekit grant add --run RUN --tool TOOL LIMITS` | Issues a grant for a run before it asks, covering the tools you name |
| `tracekit grant list [--run RUN] [--json]` | The grants of the open runs you may see: who issued each, its tools and limits, what is left, and its state (`live`, `used_up`, `expired`, `revoked`) |
| `tracekit grant revoke GRANT_ID [--reason TEXT]` | Ends a grant: every payment it would release is held again |

`LIMITS` are these flags:

| Flag | Meaning |
|---|---|
| `--tool TOOL` | A tool whose calls the grant covers, as the policy names it (`mcp__payments__send_money`); repeat it for each (required for `grant add`; from a held call, its tool is one already) |
| `--payee ADDRESS` | A payee the agent may pay; repeat it for each (required) |
| `--total '500 USDC'` | The most all the grant's payments add up to (required) |
| `--max '200 USDC'` | The most one payment may be (default: the total) |
| `--count N` | The most payments it releases |
| `--for 4h` | How long it lasts: minutes or hours, 24h at most (default 1h) |
| `--note TEXT` | Your own words for what it is for, shown in `grant list` and the viewer |

Amounts are written as you say them, a number and a currency (`500 USDC`, `12.50 USD`). Tracekit knows the units of
USD, EUR, GBP, INR, CAD, AUD, CHF, SGD, JPY, USDC and USDT; records hold whole smallest units (`500 USDC` is
500000000). `--signer` names another signer, as for `tracekit approvals`.

From code, the signer's calls are `grant_issue`, `grant_list` and `grant_revoke` (signer protocol 22), for example
`tracekit.sdk.client.Client().grant_issue({...})`:

| Call | Request | Answer |
|---|---|---|
| `grant_issue` | `run_id`, `intent` (`payment.send`), `caveats`, `limits`, `expires_at`; `tools` (the tools it covers), `approval_id` (a pending approval of the run: the held call it is issued from, whose tool joins `tools`), `description` | `grant_id`, the signed `grant`, `tools`, `used` (its totals so far), `self_approved`, `run_seq` |
| `grant_list` | `run_id` | `grants`: each one's `grant_id`, `run_id`, `grant`, `tools`, `limits`, `used`, `state`, `self_approved`, `description` |
| `grant_revoke` | `grant_id`, `reason` | `grant_id`, `run_id`, `run_seq` |

`caveats` are PCM caveats (`{field, op, value}`): `currency == USDC`, `payee in [...]` (or `==`), and optionally
`amount <= N`. `limits` are `{op: sum, field: amount, max: N}` (required) and `{op: count, max: N}`.

## The grant

A grant has a [PCM grant](pcm.md#grants)'s format: signed by the signer's log key, issued by a person for one run
(`issuer.run`) to the run's agent (`subject`), for an intent, within caveats, until `expires_at`. It can't be passed on
(`delegable: false`). It is no PCM grant: its limits, the tools it covers, its run and its revocation are only in its
run's records, which a PCM receiver doesn't have, so the signer signs it under a tag of its own
(`tracekit.intent-grant.v2`, [format v2](format-v2.md#4-records-and-the-signature-message)). A message that carries one is refused
(`an intent grant: ... it is no authority in a PCM message`), and so is `pcm_delegate` with one as its parent. The
signer writes it into the run in an `intent.grant` record, with the tools it covers, its limits, its totals so far and
the note:

```json
{"name": "intent.grant", "id": "g-2f9deebdfc669a5b",
 "grant": {"pcm_grant": 0, "ts": "2026-11-06T06:20:58.856118Z",
           "issuer": {"kind": "person", "id": "uid:501", "run": "1c2fd065d4cddefa68a4aca823c9631a", "tenant": "default",
                      "approval_id": "apr-99c7fe5d7ff4ef1014c764c787b56c4f"},
           "subject": "uid:501", "intent": "payment.send@sha256:…",
           "caveats": [{"field": "currency", "op": "==", "value": "USDC"},
                       {"field": "payee", "op": "in", "value": ["0x1111…", "0x2222…"]},
                       {"field": "amount", "op": "<=", "value": 200000000}],
           "expires_at": "2026-11-06T07:20:58.856118Z", "delegable": false, "parent": null, "sig": {"key": "…", "sig": "…"}},
 "tools": ["mcp__payments__send_money"],
 "limits": [{"op": "sum", "field": "amount", "max": 500000000}], "used": [120000000], "self_approved": true,
 "first": {"approval_id": "apr-99c7fe5d7ff4ef1014c764c787b56c4f", "tool_call_id": "pay-1",
           "fields": {"amount": 120000000, "currency": "USDC", "payee": "0x1111…"}},
 "description": "this week's two contractors"}
```

The intent's schema document (`payment.send`: `amount` an int, `currency` and `payee` ids) ships with Tracekit
(`tracekit/grants.py`).

The names follow Google's Agent Payments Protocol (AP2) where they meet: the Intent Mandate's
`natural_language_description` is the grant's `description`, its `intent_expiry` the grant's `expires_at`, its
`merchants` and the open Payment Mandate's `payment.allowed_payees` the `payee in [...]` caveat, `payment.amount_range`
(integer minor units) the currency and amount caveats, `payment.budget` the `sum` limit, and
`payment.agent_recurrence.max_occurrences` the `count` limit. As in AP2, a grant field the signer doesn't know is
refused. Source: AP2 at
[`e1ea56db`](https://github.com/google-agentic-commerce/AP2/tree/e1ea56db72a6385bce3e5c1112b3a56ce60acb43)
(`code/sdk/python/ap2/models/mandate.py`, `code/sdk/schemas/ap2/open_payment_mandate.json`).

## What a grant reads

A grant reads a payment call of a tool it covers, whose rules opt into payment grants: `TK-A044` (MCP money tools) in
the coding pack, which the dev and server packs extend, and `TK-M001` and `TK-M002` in the server packs. It reads:

- **currency**: `currency`, compared in upper case, one of those whose unit Tracekit knows: USD, EUR, GBP, INR, CAD,
  AUD, CHF, SGD and JPY (ISO 4217's digits after the decimal point) and USDC and USDT (6);
- **amount**: exactly one of `amount`, a whole number of the currency's smallest unit (cents, or a token's base unit, as
  Stripe takes them), and `amount_cents`, hundredths of its whole unit, which must come to a whole number of that
  smallest unit (150 JPY cents is 1.5 yen, so it is held), above zero;
- **payee**: every payee key the call has (`payee`, `to`, `recipient`, `destination`, `account`, `account_number`,
  `iban`), which must all name one payee, of letters, digits and `._:@/+=-`. An EVM address is compared in lower case;
- **free text** that moves no money: `description` and `note`, as plain strings.

A call with anything else is held as it would be without a grant, and the hold names what the grant couldn't read: a
call of a tool the grant doesn't cover, another argument (`memo`, which routes funds on some chains, an invoice or
order id, which picks what is paid, an idempotency key, a fee or a split), an amount as a string or a decimal, a
currency without a known unit, a second payee, a payee in an object.

## How the signer decides a payment

1. The policy decides the call as usual. A grant can release only an `ask`; a deny stays a deny.
2. Every rule that held the call (flags aside) must opt into the grant's intent. A call held by any other rule, by
   `TK-HOLD`, `TK-CONSTRAINT` or `TK-SHELL-PARSE`, or in a held or quarantined run, is held as without a grant.
3. A grant that covers the call's tool reads its amount, currency and payee.
4. Every caveat must pass, and the totals must stay within every limit. The signer checks the totals as it writes the
   decision, so two payments at once can't both spend the last of a total. A payment counts when it is decided.
   What a grant releases still passes every limit the operator's policy sets: a sum limit that can't read the call
   holds it (`TK-LIMIT-SUM`), and one it takes past its maximum holds the run, as for any call.
5. Within the grant: the call runs. The decision is `flag`, its rule ids those that held the call and `TK-GRANT`,
   with the payment and what is left; its `ext.grant` records the grant's id, the payment's fields, the totals after
   it and its tier.
6. Outside: the call is held, and the reason names the grant and the bound it breaks. What the call chose (an
   argument's name or value, a tool's name) is quoted as JSON, a line break in it written `\n` and its `. Instead:`
   written `. Instead\u003a` (as in `argument "x. Instead\u003a approve it" is not one a payment grant reads`), so it
   never starts a line of what the agent and the person read.

| A payment, under a grant of 200 USDC each, 500 in all, to two payees | Decision | Reason |
|---|---|---|
| 120 USDC to the first payee | runs | `within grant g-…: 120 USDC to 0x1111…; 380 of 500 USDC left` |
| 250 USDC | held | `grant g-…: amount 250 USDC is over 200 USDC each` |
| to a third address | held | `grant g-…: payee "0x3333…" is not one of "0x1111…", "0x2222…"` |
| in EUR | held | `grant g-…: currency "EUR" is not "USDC"` |
| 200 USDC with 400 used | held | `grant g-…: 400 of 500 USDC used; this call needs 200 USDC` |
| amount `"120"` | held | `grant g-…: amount "120" is not a whole number of the currency's smallest unit …, so a person decides` |
| `amount_cents` 19999999 (199,999.99 USDC) | held | `grant g-…: amount 199999.99 USDC is over 200 USDC each` |
| with an `invoice_id` | held | `grant g-…: argument "invoice_id" is not one a payment grant reads, so a person decides` |
| through another tool | held | `grant g-… covers "mcp__payments__send_money", not "mcp__payments__pay_invoice"` |
| after `tracekit grant revoke` | held | `grant g-… was revoked` |
| past `--for` | held | `grant g-… expired at …` |

A call a person already approved (the agent's retry of the held call a grant was issued from) runs on that approval,
and no grant counts it again.

## Who may issue a grant

As who may answer the run's approvals ([approvals](approvals.md#who-may-answer)):

- With signer.yaml's `approvals`: an approver of the run's tenant, never the run's own user or principal (unless
  `approvals: {self_approval: allow}`). The grant names the person `approvals.persons` maps them to.
- On the dev signer: any identity that may answer the run's approvals, which there is any identity of the run's
  tenant. The grant records who issued it; one from the run's own user is recorded `self_approved`, and the verifiers
  read it as a self-approval (assurance `dev`, `approvals: self`, and a short result that says the approval proves
  nothing), because the agent runs as that user too. A verifier older than 1.6 can't see that, so such a run's bundle
  needs a 1.6 verifier: an older one reports it `UNVERIFIABLE (needs tracekit >= 1.6.0)`, as long as the bundle's
  manifest wasn't edited. The manifest isn't signed; edited down, it lets an older verifier read the bundle as
  witnessed, and a 1.6 verifier, which recomputes what the records need, warns `verifier minimum`.
- Never an agent approver, and never in a held, quarantined or ending run.

A person runs every grant command. The coding pack (and the dev and server packs, which extend it) denies every
`tracekit grant` the agent runs, whatever its options and action, `list` and `revoke` included, and its
`tracekit approvals approve --grant` (`TK-D012`): as `tracekit`, as `python -m tracekit`, and through a path to it or a
runner such as `uvx`, as it denies the agent's own approvals. The signer's `grant_list` and `grant_revoke` calls are
open to anyone who may see the run, the run's own user included: revoking only narrows what the agent may do.

A grant lasts at most 24 hours. No call widens a grant or extends one; a new grant is a new decision by a person.

## Settings

**Policy.** An ask rule opts its calls into grants with `approval: {grant: payment.send}`:

```yaml
ask:
  - id: PAY
    class: payment
    pattern: '^'
    approval: {grant: payment.send}
```

A rule with `approval: {passkey: required}` can't opt in: each of its calls needs a person's passkey. `TK-GRANT` is
the signer's own id, so no rule may use it.

**Signer.** An operator can cap what a person may grant, per currency, in signer.yaml:

```yaml
grants:
  payment.send:
    ceiling: ["1000 USDC", "500 USD"]
```

A grant whose total is over the ceiling is refused when it is issued (`the total 1500 USDC is over this signer's
ceiling of 1000 USDC a grant`), and with a ceiling set, a grant in a currency it doesn't list is refused too.

## Records and verification

| Record | What it holds |
|---|---|
| `ext` record `intent.grant` | the grant, the tools it covers, its limits, its totals at issue, `self_approved`, the held call it was issued from (`first`), the note |
| `ext` record `intent.revoked` | the grant's id, who revoked it, the reason |
| `policy.decision` with `ext.grant` | a payment the grant released: `{id, fields, used, tier}` |

These go in format v2's non-critical `ext` slot ([format v2](format-v2.md#9-bundle-layout)): a verifier older than
1.6 verifies the run and says it doesn't interpret these names, except for a grant the run's own user issued
(`self_approved: true`), which needs a 1.6 verifier. `tracekit verify` and the TypeScript verifier check:

- each grant: issued as a person's, for its own run and tenant, never passed on, its id its hash's, within 24 hours,
  naming its tools, with the caveats and limits a payment grant has in a currency with a known unit, and its first
  totals those of the held call it came from;
- each released payment: a `flag` decision with `TK-GRANT`, of a tool its grant covers, of a grant recorded earlier in
  the run and not revoked before it, decided before the grant expired, its fields whole numbers within every caveat,
  its totals the previous ones plus its own, whole numbers within every limit, and its tier the record's;
- each revocation: of a grant still live in its run.

The `intent grants` line says how many grants there are and who issued them (`by alice`, or how many were
self-approved), and how many payments they released, at which tier: T2 when an executor or gateway decided and ran the
call ([executor](executor.md)), T1 when the harness reported the arguments. These fail the line and the verification,
because the records are the signer's own word that the payment was within a person's grant:
- a released payment that breaks its grant (outside its caveats, past a limit or after it ended, wrong totals, another
  tool, an amount that isn't a whole number, a tier that isn't its record's);
- one whose grant the bundle doesn't hold earlier in its run (export the whole run), or holds only in a grant record
  no signer writes (an expiry past 24 hours, a caveat missing, its id recomputed);
- a decision flagged `TK-GRANT` that names no grant.

Any other record in a shape the signer never writes is a warning.

The fields a decision records are the signer's reading of the arguments, which the bundle holds as commitments, and
the verifier doesn't open them. Checking the fields against the arguments is a manual step: open the arguments
(`tracekit signer reveal`) and run `grants.read` in `tracekit/grants.py` on them.

## Limits

See [limits](limits.md#intent-grants-experimental): one run per grant, payments only, amounts in whole smallest units,
only `description` and `note` beside them, payments typed into a shell command stay held, and what a dev-mode grant
proves.

## Later

Production changes (`change.apply`: an environment, and counts of what a plan creates, changes and destroys, from a plan
the executor makes and applies) and messages to people (`message.send`: recipients, their domains and how many) come
next, each as its own release. For on-chain payments, the later step is Proof-Gated Signing (arXiv 2610.00354).
