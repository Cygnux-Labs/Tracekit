# Spending limits and receipts for any agent

> **Experimental:** intent grants work and are tested, but may change and get less hardening than the [stable
> core](../support.md).

When an agent pays bills for you, you want three things. It pays only the payees you named. It stays under a limit
you set. And afterwards you hold a record of what it paid that you can check yourself. Tracekit's [intent
grants](../intent-grants.md) do this for an agent you run yourself, on a server or in your app:

- the first payment is held for you;
- you approve it with a grant: who may be paid, the most for one payment, the total, and for how long;
- later payments inside those bounds run on their own, each recorded as within the grant;
- a payment outside them is held, with the exact reason;
- the run exports to one file that `tracekit verify` checks offline, the grant included. You keep that file as your
  receipt.

This page runs it with the OpenAI Agents SDK, a scripted model and the dev signer, so it needs no API key.

## Run it

```sh
git clone --depth 1 https://github.com/Cygnux-Labs/Tracekit && cd Tracekit
python3 -m venv .venv && . .venv/bin/activate
pip install . 'openai-agents>=0.23.1,<0.24'
python examples/v2/openai_agents/spending.py --scripted
```

The first call starts a dev signer in the background (`tracekit down` stops it). With `--scripted`, the example runs
the person's commands itself and prints each one with its output. Without it, the example prints the commands and
waits for you to run them from another terminal. The output below is from one run of the example; long lines and ids
are as it printed them, and `...` marks lines left out.

## The agent

A `send_payment` tool, gated by Tracekit ([the OpenAI Agents quickstart](openai-agents.md) shows the wiring):

```python
from agents import Agent, Runner, function_tool
from tracekit.integrations.openai_agents import TracekitAgents
from tracekit.sdk.client import Client

@function_tool
def send_payment(payee: str, amount: int, currency: str) -> str:
    """Pay `amount` (in cents) of `currency` to `payee`."""
    ...

client = Client()
tk = TracekitAgents(client, client.register_run({"agent": {"name": "bills"}}))
agent = Agent(name="bills", model="gpt-5", tools=[tk.tool(send_payment)])   # the example: a scripted model
result = await Runner.run(agent, "pay this month's print and hosting bills", context={}, hooks=tk)
```

The dev signer's policy holds a payment tool's calls for a person: `TK-M001` (a payment called with an amount) and
`TK-M002` (a tool named for moving money). Both let a person's payment grant release the calls it covers. A grant
reads `amount` as the currency's smallest unit (cents for USD), `currency`, and one payee.

The scripted model asks for four payments, one at a time: 30 USD to `acct-print-shop`, 45 USD to `acct-hosting`,
25 USD to `acct-print-shop`, then 40 USD to `acct-hosting`.

## 1. The first payment is held

The run stops with an interruption. `tracekit approvals show` says how a payment grant reads the call, and gives a
command with limits taken from it, for you to edit:

```text
call-1 send_payment {"payee": "acct-print-shop", "amount": 3000, "currency": "USD"}: held, apr-37abaca9651b7e8ab87cb0e31016b5d7
$ tracekit approvals show apr-37abaca9651b7e8ab87cb0e31016b5d7
approval    apr-37abaca9651b7e8ab87cb0e31016b5d7 (requested)
tool        "send_payment"
why         sending money (TK-M001); moving money (TK-M002)
...
grant       a payment grant reads it as 30 USD to "acct-print-shop"; to approve it and let more payments like it run, set your own limits:
            tracekit approvals approve apr-37abaca9651b7e8ab87cb0e31016b5d7 --grant --payee acct-print-shop --max '30 USD' --total '150 USD' --for 1h
...
arguments (the signer's copy, in full):
{
  "amount": 3000,
  "currency": "USD",
  "payee": "acct-print-shop"
}
```

## 2. Approve it with a grant

Two payees, at most 50 USD each, 120 USD in all, for an hour:

```text
$ tracekit approvals approve apr-37abaca9651b7e8ab87cb0e31016b5d7 --grant --payee acct-print-shop --payee acct-hosting --max '50 USD' --total '120 USD' --for 1h --note 'the print and hosting bills'
grant g-be6e67519621e4e9 issued for run f4c2f422a5d8119a172a840478b433ae: payments through "send_payment" to acct-print-shop, acct-hosting, up to 50 USD each, 90 of 120 USD left, until 2026-11-14T01:53:09.769413Z. Recorded as self-approved: the dev signer runs as your own user and can't tell you from your agent
approved: apr-37abaca9651b7e8ab87cb0e31016b5d7, by you. It counts: the dev signer runs as your own user and can't tell you from your agent, so it records this as self-approved, and the run's assurance stays dev. A signer started from signer.yaml refuses an approval from the call's own requester unless that file sets approvals: {self_approval: allow}.
```

The grant covers the held call's tool, `send_payment`. The held payment is the grant's first: its 30 USD count toward
the total. The app applies the decision (`await tk.apply_decisions(state)`) and resumes the run.

## 3. Payments inside the grant run on their own

The held payment runs on its approval. The next two run with no stop:

```text
call-1: (pretend) paid 30.00 USD to acct-print-shop
call-2: (pretend) paid 45.00 USD to acct-hosting
call-3: (pretend) paid 25.00 USD to acct-print-shop
```

The signer records each as within the grant, with what is left (the signed decisions, as the example prints them
from the bundle in step 5):

```text
  #9 policy.decision {"decision": "flag", "reasons": ["within grant g-be6e67519621e4e9: 45 USD to acct-hosting; 45 of 120 USD left"], "rule_ids": ["TK-M001", "TK-M002", "TK-F021", "TK-GRANT"], "tool": "send_payment", "tool_use_id": "call-2"}
  #12 policy.decision {"decision": "flag", "reasons": ["within grant g-be6e67519621e4e9: 25 USD to acct-print-shop; 20 of 120 USD left"], "rule_ids": ["TK-M001", "TK-M002", "TK-F021", "TK-GRANT"], "tool": "send_payment", "tool_use_id": "call-3"}
```

## 4. A payment past the limit is held, with the reason

The fourth payment, 40 USD, would take the total to 140 USD. The signer holds it, and signs the reason with the
decision:

```text
call-4 send_payment {"payee": "acct-hosting", "amount": 4000, "currency": "USD"}: held, apr-aa10b626fabff3dac9561cf943e5512a
...
  #15 policy.decision {"decision": "ask", "reasons": ["grant g-be6e67519621e4e9: 100 of 120 USD used; this call needs 40 USD"], "rule_ids": ["TK-M001", "TK-M002", "TK-F021"], "tool": "send_payment", "tool_use_id": "call-4"}
```

The person rejects it, and the model gets the refusal as the tool's output:

```text
$ tracekit approvals reject apr-aa10b626fabff3dac9561cf943e5512a
rejected: apr-aa10b626fabff3dac9561cf943e5512a, by you, recorded as self-approved (an answer from the call's own requester): the run's assurance stays dev
...
call-4: Tool call rejected in Tracekit
Paid 100 USD of the bills; the last 40 USD needs your approval.
```

`tracekit grant list` shows the grant as it stands:

```text
$ tracekit grant list --run f4c2f422a5d8119a172a840478b433ae
g-be6e67519621e4e9  live  run=f4c2f422a5d8119a172a840478b433ae  payment.send  tools="send_payment"  self-approved (the run's own user, which the agent can be)  to acct-print-shop, acct-hosting, up to 50 USD each, 20 of 120 USD left  until 2026-11-14T01:53:09.769413Z  "the print and hosting bills"
```

## 5. Export, verify, and keep the receipt

When the run closes, the example exports it to `<run id>.tkb`, writes the dev signer's public key to `trust.json`
and verifies the bundle offline. The `intent grants` line re-checks each released payment against the grant and its
running totals, from the bundle alone:

```text
$ tracekit verify f4c2f422a5d8119a172a840478b433ae.tkb --trust trust.json --detail
...
[PASS] intent grants — 1 grant(s) (1 self-approved: issued by the run's own user, which the agent can be); 2 call(s) released within them (0 at T2, decided and run by an executor or gateway; 2 at T1, on the arguments the harness reported), each re-checked against its grant and its running totals

Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint Ed25519 only (tracekit.local/75ed00f44376df026f900962eb38fc42); no witness cosignature; approvals: self; key retirements not proven complete.
```

Keep the `.tkb` file and `trust.json`: they are your receipt. Anyone with both can check it later, with no network
and no access to the signer:

```text
$ tracekit verify f4c2f422a5d8119a172a840478b433ae.tkb --trust trust.json
VERIFIED: 4 tool calls in 21 signed records, none changed, removed or added after signing.
NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could have rewritten the record.
To make it proof, keep the key away from the agent: https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy
NOT ANCHORED: no independent witness or anchor cosigned the log (https://github.com/Cygnux-Labs/Tracekit/wiki/Witnesses).
Pinned log key SHA-256 fingerprint: 4ceec39846a5db2d50d32ad74698ccf258ac8d5e4096baccf1f06a15f5029824.
```

A copy with one payment edited (45 USD made 4 USD in the file, its manifest hashes recomputed) fails:

```text
$ tracekit verify edited.tkb --trust trust.json
TAMPERED at event 10: its content was changed after it was signed.
Add --detail to see each check.
```

## What the receipt shows, and its limits

The receipt holds what the signer decided and signed: the grant, who issued it, each payment it released with the
totals after it, the payment it held with the reason, and each approval and rejection. What it proves depends on where
the signer ran.

- **On the dev signer it isn't proof against the agent.** The signer runs as your user, so the agent could reach its
  key, and the grant and approvals are recorded self-approved (`approvals: self`, assurance `dev`). For an agent on a
  server, [deploy the signer](../deploy.md) where the agent can't reach it, with an `approvals` section in
  signer.yaml, so only an approver it names issues grants. The `intent grants` line then names that person
  ([who may issue a grant](../intent-grants.md#who-may-issue-a-grant)).
- **These payments are T1.** The tool runs in the agent's process, on the arguments the agent reported. Run payments
  through the [tool executor](../executor.md) (T2) so they run with the arguments the signer decided.
- **The verifier checks each payment against its grant, not against the call's arguments.** The bundle holds the
  arguments as commitments; opening them is a manual step ([records and
  verification](../intent-grants.md#records-and-verification)).
- **A grant covers one run, and payments only.** A payment counts toward the total when it is decided, also when the
  payment then fails.

Every limit of intent grants is in [limits](../limits.md#intent-grants-experimental).
