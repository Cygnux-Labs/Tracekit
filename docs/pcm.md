# PCM 0.1: proof-carrying messages

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

Agent A asks agent B to refund $120 on order 81. It says alice approved refunds up to $200 for that order. B has only
A's word for it. If A was prompt-injected, or another process sends the message in A's name, B pays out anyway.

A proof-carrying message (PCM 0.1, an open protocol Tracekit implements) lets B check the request before it acts. The message carries:

- who sent it, signed by the v2 signer, which signs only as the calling run's own agent;
- what it asks for, as a typed intent (`refund.request`, `amount`, `order`) checked against a schema both sides agreed on;
- what it claims (`approved_by alice`), each claim with records from the sender's signed log as evidence;
- a grant: alice's approval, signed by the signer, saying who may ask for what, within which limits, until when.

B checks all of it offline with the trust.json it already has. A claim with no proof comes back `unproven`, so B
sees what rests on A's word alone. A prompt-injected A can still ask for anything its grant allows: the grant, not A,
sets the limit.

```text
$ tracekit pcm demo
tracekit pcm demo: two agents negotiate a refund (an in-process signer in /var/folders/s9/g815rzd5779dlvsx6pzq9pl00000gn/T/tk-pcm-lo5rs176)
  alice approves agent A's grant: refund.request, amount <= $200.00, order == 81, until 18:00Z, can be passed on: no
  A -> B  refund.request {amount $120.00, order 81} + approved_by(alice)
      B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · approved_by proven
  A -> B  same request + tests_passed(pytest tests/test_refund.py), no evidence
      B: ACCEPT-UNPROVEN  tests_passed: unproven (no evidence)
  A -> B  approved_by with one record hash changed
      B: REJECT           approved_by: failed (record 1: hash does not match the event)
  A -> B  refund.request {amount $500.00, order 81} + approved_by(alice)
      B: REJECT           grant: grant 0: amount 50000 breaks amount <= 20000
  A asks the signer to sign as B
      signer: forbidden: the signer signs only as the calling run's own agent (uid:990101, run 4205598ec8ab06b650a402d019b1592a, tenant default)
```

The demo runs a real signer in a temp dir (removed at exit), with A, B and alice as three local identities. It exits 0
when every verdict is the one shown.

## The message

The agent sends the body: `from`, `to`, `intent`, and optionally `claims`, `grants` and a `payload`. The signer adds
`pcm`, `id`, `ts` and `nonce` from its own clock and randomness, so the agent can't choose them, and signs it. A message
from the demo (its claims and grants left out here):

```json
{
 "from": {"agent": "uid:990101", "run": "4205598ec8ab06b650a402d019b1592a", "tenant": "default"},
 "to": {"agent": "uid:990102"},
 "intent": {"type": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
            "args": {"amount": 12000, "order": 81}},
 "pcm": 0,
 "id": "5ff5392983a0b7d8f4dd8bd88d6fecb3",
 "ts": "2026-10-27T13:37:07.594540Z",
 "nonce": "ebf9449e4b30726f5f9621f5c22b4fbe",
 "sig": {"key": "tracekit.local/39efd223d635ba423b1faced04a8e7d7+52ebcdec",
         "sig": "89bs02iZt3un/Myxp2qmq7pvqk9Y4zLNsTz2HT86Itf6dSpqG99Wr/THuZoIm4Y2fz9NqOqFs48ozJUm5eapBA=="}
}
```

- `from` is the run's own identity (`scheme:subject`, as the transport proved it), run and tenant. The signer refuses
  any other `from` with `forbidden`.
- `intent.type` names a schema by content hash; `args` must match it.
- `payload` is free text (`{"kind": "text", "text"}`) or JSON (`{"kind": "data", "data"}`). Nothing checks it.
- The signature is Ed25519 by the signer's **log key**, the key trust.json already pins under `logs`. It covers every
  field except `sig`: `JCS({...message without sig, "t": "pcm.message.v0"})`. Grants sign with
  `"t": "pcm.grant.v0"`, so one can't pass as the other, and neither can pass as a checkpoint note. The tags are
  PCM's own, not `tracekit.*`, because PCM is an open protocol that other implementations sign too
  ([format](format-v2.md)).
- The media type is `application/vnd.pcm+json`.

Each signed message is one record in the sender's run: `ext` with `name: pcm.sent`, the message's hash, its id, the
receiver and the intent. It holds no args:

```json
{"name": "pcm.sent", "message": "sha256:651f71bd8b686a10a99249483fc8dd257ea519f5552c5dfaf25b039a36f8e364",
 "id": "5ff5392983a0b7d8f4dd8bd88d6fecb3", "to": "uid:990102",
 "intent": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c"}
```

So an auditor of A's run sees every message A had signed, in order among its tool calls.

## Schemas

A schema is a small JSON document. Both sides keep a copy. Its content hash is its name on the wire, so an edited
schema is a different schema:

```json
{"pcm_schema": 0, "name": "refund.request",
 "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
            "order":  {"type": "int", "min": 1, "max": 999999999}},
 "claims": ["approved_by"], "grant": true}
```

`refund.request@sha256:d8636b6f…` is `name` + `@` + the SHA-256 of the document's JCS. `claims` lists the claim types
the intent needs; `grant: true` says a message without a grant is rejected.

| Type | Parameters | A value passes when |
|---|---|---|
| `string` | `max` (1..65536) | it is a string of at most `max` characters |
| `int` | `min`, `max` | it is an integer in range: `true`, `120.0` and `"120"` fail |
| `money` | `currency` (3 capitals), `max` | it is an integer number of minor units (cents), 0..`max` |
| `id` | `pattern` | it is a string of at most 128 characters that the whole pattern matches |
| `enum` | `values` | it is one of the strings listed |
| `bool` | none | it is `true` or `false` |
| `time` | none | it is `YYYY-MM-DDTHH:MM:SS.ffffffZ` |

Any field may add `"optional": true`. Args may have no field the schema doesn't list. Nothing is converted: $120.00 is
`12000`, never `120.0`.

## Claims and evidence

A claim says something happened in the sender's run. There are four types:

| Claim | Proven when the evidence holds |
|---|---|
| `tests_passed {suite}` | a call of a tool the shipped policy packs class as shell (`Bash`, `shell`, `terminal`…), whose opened args have `command` equal to `suite`, not denied by policy, with a result `ok` written by a gateway or executor (T2). `suite` must be one test command (`pytest -q tests/x.py`, not `pytest -q; true` or `echo hi`) |
| `approved_by {person, call}` | an `approval` record that approves call `call`, by the person `person` (the name signer.yaml's `persons` gives the approver; an identity no person maps to proves nothing), not an agent approver and not self-approved |
| `reached_host {host}` | an `effect.observed` the signer wrote from an [egress observer](egress.md) or kernel sensor, to `host`, not denied; or a call of a tool the shipped packs class as http (`WebFetch`, `http_request`…) whose opened args have a `url` on `host`, with a T2 result `ok` |
| `file_written {path, digest}` | a `Write` call of `path` whose opened `content` has SHA-256 `digest` (as `sha256sum` prints it, with `sha256:` in front), with a T2 result `ok` |

Each claim gets one result:

- **proven**: the evidence verifies and says what the claim says.
- **unproven**: there is no evidence, or the only matching result is the agent's own report (T1:
  `the result is the agent's own report (T1)`). The agent's process said the call succeeded; nothing else saw it.
  A matching call of another tool is unproven too (`a tool the verifier can't place as a shell tool`).
- **failed**: the evidence does not verify, or no record in it says what the claim says.

The evidence for a claim is self-contained. It needs only trust.json:

```json
{"checkpoint": "tracekit.local/39efd223d635ba423b1faced04a8e7d7\n8\nMOdodHINu4iy4en2EA2+YPnEKH/Nt5/aXOJHRgr4qaY=\n\n— tracekit.local/39efd223d635ba423b1faced04a8e7d7 UuvN7Jot…\n",
 "records": [{"event": {"type": "approval", "seq": 4, "run_id": "4205598ec8ab06b650a402d019b1592a", "tenant": "default",
                        "data": {"tool_use_id": "grant-1", "decision": "approve", "approver": "uid:990001",
                                 "person": "alice", "self_approved": false, "…": "…"}, "…": "…"},
              "hash": "sha256:5bf218dc39a3c41efdfaccd33e99bc7f7a6e8f365c7aaaa01b708b2332b47cfa",
              "proof": ["zq3sGmbBpb1ungBDmMhpS6xl1UszRL8GQa4msQbSm9w=", "8xx0dD16…", "s5+blM63…"]}]}
```

The receiver checks, in order:

1. The checkpoint note is signed by a log key trust.json pins, has the cosignatures `witnesses_required` asks for,
   and is of the same log as the key that signed the message.
2. Each record's hash is the hash of its event, and its inclusion proof leads to the note's root.
3. Each record is from the sender's own run and tenant (`from.run`, `from.tenant`).
4. Where a claim reads a call's args (`command`, `url`, `content`), the record is a `policy.decision` and carries
   `salt` and `args` that open its `args_commitment`. The signer never stores args in clear; the salt is what proves
   these are the args it decided.

Change one byte and the claim fails. The demo's third message changes one hex digit of a record hash:

```text
B: REJECT           approved_by: failed (record 1: hash does not match the event)
```

Opening a decision shows its args to the receiver. The SDK opens only the decisions you name.

## Grants

A grant says: this agent may ask for this intent, within these caveats, until this time. The signer signs it with
the log key. A root grant needs a person's approval. A grant from the demo signer:

```json
{"pcm_grant": 0, "ts": "2026-10-27T13:37:07.576604Z",
 "issuer": {"kind": "person", "id": "uid:990001", "run": "4205598ec8ab06b650a402d019b1592a", "tenant": "default",
            "approval_id": "apr-982067cfc47a41b2d652f9a51860d02d", "person": "alice"},
 "subject": "uid:990101",
 "intent": "refund.request@sha256:d8636b6fbbd07430d057ea9ead9c27f0df1b918b10d34ab9257a4971d487846c",
 "caveats": [{"field": "amount", "op": "<=", "value": 20000}, {"field": "order", "op": "==", "value": 81}],
 "expires_at": "2026-10-27T18:00:00.000000Z", "delegable": false, "parent": null,
 "sig": {"key": "tracekit.local/39efd223d635ba423b1faced04a8e7d7+52ebcdec", "sig": "gmNkRPWL…"}}
```

**Root grants come from a person.** The agent makes a tool call `pcm.grant` with the grant's args (`subject`,
`intent`, `caveats`, `expires_at`, `delegable`). Your policy must `ask` for it:

```yaml
tools:
  pcm.grant: app          # known, so unknown_tools leaves it alone
ask:
  - {id: PCM-GRANT, tool: pcm.grant, pattern: "^"}
```

A person answers it as any other approval ([approvals](approvals.md)), and sees the args, `delegable` included. The
agent consumes the approval, then calls `pcm_grant`. The signer refuses when:

- signer.yaml has no `approvals` section (without it no answer comes from a named person);
- the call was not approved and consumed with exactly these args;
- the approver was an agent approver, the run's own agent (self-approved) or the grant's subject;
- `expires_at` is not within the next 24 hours;
- the `pcm.grant` call already has its result (one grant per approval);
- the run is held or quarantined.

Without the ask rule there is nothing to consume, so no root grant can be made.

**`delegable`** is the person's choice: may the subject pass this grant on? A child is made with `pcm_delegate`, by
the grant's subject only, with no approval. It can only narrow: the same intent, an expiry no later than the
parent's and caveats that imply the parent's. The child sets its own `delegable`. A grant with `delegable: false`
can't be passed on, by the signer or in a chain the receiver checks:

```text
forbidden: this grant can't be passed on
```

**Caveats** use these operators, by field type:

| Field type | Operators |
|---|---|
| `int`, `money` | `==` `<=` `>=` `<` `>` |
| `time` | `==` `<=` `>=` |
| `string`, `id`, `enum` | `==`, `in` (1 to 64 distinct values) |
| `bool` | `==` |

`< b` counts as `<= b-1`, and `> b` as `>= b+1`.

**Narrowing** is checked per caveat. Each parent caveat needs a child caveat on the same field that implies it. A
missing caveat counts as widening. The child may add caveats on any field.

| Parent | Child may be |
|---|---|
| `== x` | `== x` (same type), or `in [x]` for a string |
| `in S` | `== v` with v in S, or `in T` with T a subset of S |
| `<= b` | `== v` or `<= b'` with v, b' ≤ b |
| `>= b` | `== v` or `>= b'` with v, b' ≥ b |

A bound never implies an equality: `>= 81` and `<= 81` together don't narrow `== 81`.

A worked delegation: A holds alice's grant (`amount <= 20000`, `order == 81`, delegable) and passes B a smaller one.

```text
pcm_delegate  subject uid:990102, caveats amount <= 15000, order == 81, delegable false
-> issuer {kind: agent, id: uid:990101}, parent sha256:e24112e9…, delegable false
```

B sends `refund.request {amount 18000, order 81}` with both grants, root first. The receiver rejects it at the child:

```text
grant: grant 1: amount 18000 breaks amount <= 15000
```

A child that widens one caveat and tightens another fails. Raising the cap to $300 while adding a $1 floor:

```text
pcm_delegate  caveats amount <= 30000, amount >= 100, order == 81
-> invalid_request: amount <= 20000: dropped or widened
```

The receiver checks the whole chain again (`verify_grants`), so a chain the signer never made fails the same way:

| Rule | Check |
|---|---|
| signature | every grant is signed by the log key that signed the message |
| root | no parent, issued by a person, issuer is not the subject |
| link | each child's `parent` is the hash of the grant before it, which is delegable |
| who delegates | each child's issuer is the agent its parent was granted to |
| intent | every grant is for the message's intent |
| tenant | every grant was issued in the sender's tenant |
| caveats | well formed for the schema, and each child narrows its parent |
| expiry | no child outlives its parent; the message was signed before every grant expired |
| subject | the last grant is for the sender |
| args | the message's args pass every caveat of every grant |

## Verifying

`pcm.verify(msg, trust, schemas, replay=None, me=None, strict=False)` returns one result. The demo's first message:

```json
{"signature": {"ok": true, "key": "tracekit.local/39efd223d635ba423b1faced04a8e7d7+52ebcdec"},
 "replay": {"ok": true, "detail": "fresh"},
 "schema": {"ok": true, "ref": "refund.request@sha256:d8636b6f…", "errors": []},
 "grants": {"result": "ok", "steps": 1, "root": {"kind": "person", "id": "uid:990001", "person": "alice"},
            "problems": []},
 "claims": [{"type": "approved_by", "result": "proven", "detail": "approval seq 4 by alice of grant-1"}],
 "verdict": "accept", "reasons": []}
```

| Verdict | When |
|---|---|
| `reject` | the envelope or signature fails, replay or recipient fails, the args break the schema, the grant chain fails, any claim fails, or (with `strict`) a claim type the schema lists is not proven |
| `accept-unproven` | otherwise, when a claim is unproven or a claim type the schema lists has no proven claim |
| `accept` | everything checked passed and every claim is proven |

A forged message stops at the signature; no claim work is done for it.

**Replay.** A receiver keeps one `pcm.Replay()` for its whole life and passes it to every call. A message passes once:
within 300 s of the receiver's clock, not signed before the receiver started, and with a nonce not seen before from
that sender. A message signed before the receiver started is refused:

```text
replay: sent before this receiver started: ask for it again
```

So a restart needs no saved state; the sender asks again. `me` is the receiver's own identity: a message addressed to
another is rejected (`replay: addressed to uid:990102, not uid:990103`).

**From the command line,** for one saved message:

```text
$ tracekit pcm verify msg.json --trust trust.json --schema refund.request.json --me uid:990102
ACCEPT  signature ok · schema ok · grant ok (alice, 1 step) · approved_by proven
```

It exits 0 for accept, 3 for accept-unproven, 1 for reject and 2 when it can't read its inputs. `--strict` rejects
when a claim type the schema lists is not proven; `--json` prints the whole result. It does not check replay: it
reads one message, and a new process remembers no nonces.

## Signer calls

Four RPCs, in the RPC contract from version 20. Each is for the run's own agent only: the identity that registered
the run. A tailer or observer holding a delegated run token is refused, and so are agent approvers.

| Call | Does |
|---|---|
| `pcm_sign` | signs a message body; `from` must be the run's own agent, run and tenant. Writes `ext pcm.sent` |
| `pcm_grant` | signs a root grant from the consumed approval of the run's `pcm.grant` call. Writes `ext pcm.grant` |
| `pcm_delegate` | signs a narrower child of a grant this signer issued to the run's agent. Writes `ext pcm.grant` |
| `pcm_evidence` | returns records of the run with inclusion proofs under the latest checkpoint, and each `policy.decision`'s salt; records the next checkpoint will cover come back in `pending` |

`pcm_sign`, `pcm_grant` and `pcm_delegate` are refused in a held or quarantined run, so no new authority leaves a run
while a person looks at it; `pcm_evidence` still reads. All four count against the caller's event quota.

## Python SDK

```python
import datetime

import tracekit.pcm as pcm
from tracekit.sdk.client import Client

DOC = {"pcm_schema": 0, "name": "refund.request",
       "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
                  "order": {"type": "int", "min": 1, "max": 999999999}},
       "claims": ["approved_by"], "grant": True}
REF = pcm.schema_ref(DOC)
in_an_hour = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

with Client().run("agent-a") as run:
    # blocks until a person answers the pcm.grant approval (the policy must ask for it)
    grant = run.pcm_grant("uid:990101", REF, in_an_hour.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                          caveats=[{"field": "amount", "op": "<=", "value": 20000},
                                   {"field": "order", "op": "==", "value": 81}])
    [a] = [e for e in run.call("read", limit=1000)["events"] if e["type"] == "approval"]
    ev = run.pcm_evidence([a["run_seq"]])   # waits for a checkpoint that covers it
    msg = run.pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, grants=[grant], claims=[
        {"type": "approved_by", "args": {"person": "alice", "call": a["data"]["tool_use_id"]}, "evidence": ev}])

# on B's side: one Replay for the receiver's life
replay = pcm.Replay()
out = pcm.verify(msg, trust, [DOC], replay=replay, me="uid:990102")
```

- `pcm_grant(subject, intent, expires_at, caveats=(), delegable=False, parent=None, timeout_s=300.0)`: with `parent`,
  a child grant (`pcm_delegate`); else the `pcm.grant` call, its approval, the root grant and the call's result.
  Raises `Refused` when the policy doesn't ask, the person rejects, or nobody answers in time.
- `pcm_evidence(run_seqs, args=None, wait_s=15.0)`: `args` maps a decision's run_seq to the args it decided; only
  those decisions are opened.
- `pcm_send(to, intent, args, claims=(), grants=(), payload=None)`: the signed message.

TypeScript has the RPC schemas (`sdk/typescript/src/v2/rpc_schema.ts`), so its client can call the four RPCs, but no
verifier.

## Trust and keys

A receiver needs nothing new. The log key that signs checkpoints signs messages and grants too, and trust.json
already pins it under `logs`. Witnesses in trust.json apply to evidence: `witnesses_required` counts cosignatures on
each evidence checkpoint.

Because the log key signs all three, a fault in PCM signing is a fault of the log key: the fix is rotating it.

## Agent-to-agent transport (later)

The A2A gateway (#434) will check PCM parts before it forwards them, drop rejected ones, and let policy require
proven claims per receiver or intent. A `transfer` payload waits for it too. Until then the receiver calls
`pcm.verify` itself.

## Limits

All of them, with what to do: [limits](limits.md#pcm-01-proof-carrying-messages-experimental).
