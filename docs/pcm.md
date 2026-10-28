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
      B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · approved_by proven (approval seq 4 by alice of "pcm.grant" call grant-1, which issued this message's root grant)
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
- `sig.sig`, like every base64 value in PCM (evidence proof entries too), is canonical: the standard alphabet,
  padded, no whitespace, unused bits of the last character zero. Any other text fails, so a signature has one
  text form.
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
the intent needs; `grant: true` says a message without a grant is rejected. An optional `tool` (1 to 256 characters)
names the tool the intent stands for, such as `"tool": "pay"`: an `approved_by` claim with `covers` is checked against
it ([What `approved_by` says](#what-approved_by-says)).

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
| `tests_passed {suite}` | a call of a tool the [placement table](#tool-placement) classes as shell (`Bash`, `shell`, `terminal`…), whose opened args have `command` equal to `suite`, not denied by policy, with a result `ok` written by a gateway or executor (T2). `suite` must be one [test command](#test-commands) (`pytest -q tests/x.py`, not `pytest -q; true`, `pytest &`, `pytest --co` or `echo hi`) |
| `approved_by {person, call, covers?}` | an `approval` record that approves call `call`, by the person `person` (the name signer.yaml's `persons` gives the approver; an identity no person maps to proves nothing), not an agent approver and not self-approved; with the `approval.request` it answers (the same `approval_id`) and the `policy.decision` that request names (its `decision_id`), of call `call` and with its `tool`. The result's `approved` says which tool call was approved. With `"covers": true`, that approval must also cover the message's request: [what `approved_by` says](#what-approved_by-says) |
| `reached_host {host}` | an `effect.observed` the signer wrote from an [egress observer](egress.md), to `host`, in which a connection opened (`connections` above 0); or a call of a tool the placement table classes as http (`WebFetch`, `http_request`…) whose opened args have a `url` on `host`, with a T2 result `ok` (an answer with an HTTP error status, such as a 404, is not `ok`). Hosts are compared in [canonical form](#hosts) |
| `file_written {path, digest}` | a `Write` call of `path` whose opened `content` has SHA-256 `digest` (as `sha256sum` prints it, with `sha256:` in front), with a T2 result `ok`. `path` must be absolute (`/repo/refund.py`, `C:\repo\refund.py`) and have no `..`; it is compared as [Paths](#paths) says |

Each claim gets one result:

- **proven**: the evidence verifies and says what the claim says.
- **unproven**: there is no evidence, or the only matching result is the agent's own report (T1:
  `the result is the agent's own report (T1)`). The agent's process said the call succeeded; nothing else saw it.
  A matching call of a tool the placement table doesn't class so is unproven too (`a tool the verifier can't place
  as a shell tool`), and so is a record that says less than the claim: a connect a kernel sensor or OpenShell saw
  (`the run try to connect to api.example.com, an attempt`), an egress minute in which no connection opened
  (`saw no connection to api.example.com open`), a host the verifier can't tell (a URL outside printable ASCII, a host
  with `%`, an IPv4 address not written as a dotted quad: [Hosts](#hosts)), or a `Write` whose path the verifier
  can't tell from the claimed one ([Paths](#paths)). A connect the sensor marked `denied` counts for nothing, so a
  `reached_host` claim that rests on one alone fails.
- **failed**: the evidence does not verify, no record in it says what the claim says, or the claim is malformed (a
  relative `file_written` path, a `tests_passed` suite that is no test command). An `approval` without the
  `approval.request` and `policy.decision` that say what was approved fails too: the sender chooses its evidence and
  can always add them. So do records that disagree on what the person approved, in any order: two `approval.request`
  records of one approval that name different decisions, or approvals of the call that name decisions of different
  tools or args, compared in JCS, so `{"x": true}` and `{"x": 1}` differ (`the evidence holds 2 different decisions
  approved as call c1 by alice: send the records of one approval`). A malformed claim fails with or without evidence.

### What `approved_by` says

`call` is the agent's own name for its call: an agent can name a `read_file` call `refund-81-approved`. Only the
decision the approval answers says what the person approved, so a proven claim's result carries it as `approved`:
the decision's `tool`, and its `args` when the evidence opens that decision (else `null`). The detail says the same,
the tool as a JSON string, so a tool the agent named `pay call x with args {…} and read_file` can't pass for opened
args, and the args whole and in JCS:

```json
{"type": "approved_by", "result": "proven", "detail": "approval seq 4 by alice of \"pcm.grant\" call grant-1",
 "approved": {"tool": "pcm.grant", "args": null}}
{"type": "approved_by", "result": "proven",
 "detail": "approval seq 4 by alice of \"read_file\" call refund-81-approved with args {\"path\":\"/etc/motd\"}",
 "approved": {"tool": "read_file", "args": {"path": "/etc/motd"}}}
```

Both are `proven`: alice approved that call. Without `covers`, that is all the claim says: nothing ties the call to
the request. `tracekit pcm verify` prints the detail of a proven `approved_by` on its line.

With `"covers": true` the sender says the approval covers this message's request, and the verifier checks it. The
claim is proven only when either:

- the approval issued the message's root grant: a `pcm.grant` approval whose `approval_id`, run and tenant are the
  root grant's issuer's (`approval seq 4 by alice of "pcm.grant" call grant-1, which issued this message's root
  grant`); or
- the schema names the `tool`, the approval is of that tool, the evidence opens the decision, and its args equal the
  intent's args in JCS (`…: this request's tool and args`).

The second way covers every message that asks for that tool with those args, as often as the run sends one: for
one-time authority, put a field unique to the request (such as `request_id`) in the schema and act once per value, or
require a grant ([limits](limits.md#pcm-01-proof-carrying-messages-experimental)).

Else the claim fails when it can tell the approval doesn't cover the request: a `pcm.grant` approval that issued
another grant or none, a decision of another tool than the schema names (opened or not), or opened args that differ
(`approval seq 7 by alice of "pay" call pay-6 with args {"amount":500,"order":81}: not this request's args
{"amount":12000,"order":81}, so it does not cover this request`). It is unproven when it can't tell, with what to do:
the schema names no tool (`… name the tool in the schema document, or cite the approval that issued the message's
root grant`), or the decision isn't opened (`… open the decision`).

A schema that lists `approved_by` in `claims` needs a proven `approved_by` with `covers`. One without it doesn't
count, so a sender that cites alice's approval of a $5 refund for a $50 refund and leaves `covers` out gets
`accept-unproven`, or `reject` with `--strict`: `approved_by: required, not proven to cover this request: claim it
with covers true`.

### Tool placement

`tests_passed` and `reached_host` count a call only when PCM 0.1 places its tool as shell or http. The placement
table is part of the protocol: 54 tool names and their class, frozen from the policy packs of Tracekit 1.4 and
shipped as `tracekit/pcm/tools.json`. The verifier reads no deployment's policy, and a pack Tracekit adds or edits
later changes no verdict.

A T2 record's tool name stands for its class: the verifier takes a `Bash` call an executor ran as a shell call,
whatever the action runs. Name executor actions and gateway tools after what they do, never after a placed tool of
another class; an HTTP action called `Bash` would prove `tests_passed`.

### Test commands

`suite` is one line of plain words. It may not hold any of `` ; & | ( ) < > $ ` \ # { } * ? [ ] `` or a control
character other than tab, so it has no operator, redirection, background `&`, expansion, escape, comment or glob, and
its quotes must balance. Its words (split at spaces and tabs, `'…'` and `"…"` grouping) must begin with one of these,
compared exactly, so the program is a bare name looked up on `PATH` (`./pytest` and `.venv/bin/pytest` are not
`pytest`):

```text
pytest  py.test  python -m pytest  python3 -m pytest  python -m unittest  python3 -m unittest  tox  nox  nose2
trial  behave  jest  vitest  mocha  ava  karma  cucumber  playwright test  phpunit  rspec  ctest
npm test  npm run test  yarn test  yarn run test  pnpm test  pnpm run test  bun test
go test  cargo test  cargo nextest run  dotnet test  deno test  swift test  mix test  bazel test
make test  make check  mvn test  mvn verify  gradle test  gradle check
```

and no word may be `-h` or `-V`, or 3 or more characters that begin `--help`, `--version` or `--collect-only`
(`--he`, `--co`), with which a runner runs no tests. A wrapper or an assignment in front (`uv run pytest`,
`CI=1 pytest`, `sudo pytest`) is no test command: claim the command the way the list writes it. The list is a
deliberately strict subset of the test commands `tracekit analyze` knows (no `./gradlew`, `npm t` or
`npm run test:unit`).

`proven` means only that this exact command line exited 0 through an executor. Runners take other flags that run no
tests and exit 0 (`pytest -qh`, `pytest --fixtures`, `go test -run NONE`, `go test -exec true`,
`make test SHELL=/bin/true`, `npm test --script-shell=true`, `cargo test --no-run`, `mvn test -DskipTests`), and the
program is whatever `PATH` names `pytest` on the executor. A receiver must compare `suite` with the suites it accepts,
not rely on the runner list.

### Hosts

PCM 0.1 compares hosts in ASCII only. The claim's `host`, the call's URL host and the effect's `host` are each put in
one form before they are compared, and a port is ignored:

1. The URL, or the effect's host, must be printable ASCII: every character from `!` to `~` (U+0021 to U+007E). A
   space, tab, newline or other control character, DEL or any non-ASCII character anywhere in it, the path too, makes
   it one the verifier can't tell. An international name is compared in its `xn--` form, as DNS names it: claim and
   fetch `xn--bcher-kva.example`, not `bücher.example`. A call's detail then ends with `its URL is not printable
   ASCII: send it without spaces or control characters, with the host in xn-- form and anything else
   percent-encoded`. A claim's `host` may hold only `a`-`z`, `0`-`9`, `.`, `_`, `:` and `-`: any other character, a
   capital letter or `%` among them, fails the claim as malformed.
2. Before anything else reads the URL, a `[` or `]` in its authority (between `//` and the first `/`, `?` or `#`) is
   taken only as one pair around an IPv6 or IPvFuture address that opens the host after the last `@`, followed by
   nothing or `:` and a port: `http://[::1]:8080/` and `http://u@[::1]/x` have a host; `http://[x]@good.com/`,
   `http://[zz]@[::1]/`, `http://[::1]x/` and an authority of `[::1]@` alone can't be told. Brackets in the path or
   query (`http://good.com/a[1]`) don't count.
3. A claim's or effect's host is read as the host of `http://<host>/` (a bare IPv6 address as `http://[<host>]/`); a
   port after it must be 1 to 5 digits. A URL's host is read as a browser (WHATWG URL) reads it, and must also be the
   host Python's `urllib` reads (`http://a.example\@b.example/` is read apart). The host is read by these rules alone,
   so a URL a browser refuses (a port above 65535, an `xn--` label that is no valid punycode) can still have one.
   Only `http`, `https`, `ws`, `wss`, `ftp` and `//` URLs have a host: `file://a.example/x` reaches no host.
   A URL that starts with `view-source:` or `blob:` can't be told: a browser's address bar reads the URL inside it,
   WHATWG URL no host. Nor can a URL with no scheme that doesn't start with `//` (`/api.example.com/x`,
   `api.example.com/x`): a client given a base URL reads it as a path on the base's host. A call's detail then ends
   with `its URL has no scheme, so a client may read it against a base URL: send the whole URL, scheme and host`.
4. A host is never percent-decoded: one with a `%`, as either reads it, can't be told (`http://%61.example/` is not
   `a.example`, `http://[::1%25eth0]/` not `::1`). A call's detail then ends with `its host has a %: send the URL with
   the host as plain ASCII, not percent-encoded`.
5. The host is then written for comparison:
   - a name: lowercased, without one trailing dot, of labels of 1 to 63 of `a`-`z`, `0`-`9`, `_` and `-` joined by
     dots. An `xn--` label is compared as written, without a punycode check.
   - an IPv4 address (a host whose last label is a number: digits, or `0x` and hex digits): only as a dotted quad,
     four decimal numbers 0 to 255 without leading zeros (`127.0.0.1`, `10.0.0.1`). Any other form can't be told
     (`0127.0.0.1`, which macOS reaches as `127.0.0.1` and `inet_aton` reads as `87.0.0.1`; `127.1`, `0x7f.0.0.1`,
     `2130706433`), and a call's or a claim's detail then ends with `its host is an IPv4 address not written as a
     dotted quad: send it as four decimal numbers 0-255 without leading zeros`.
   - an IPv6 address in brackets: RFC 5952 section 4 text (`[2001:DB8:0:0::1]` is `2001:db8::1`), an IPv4-mapped or
     NAT64 one the IPv4 address it reaches. One whose dotted quad has a leading zero (`[::ffff:01.2.3.4]`) can't be
     told: Python before 3.9.5 reads `01` as `1`, later releases refuse it.

A record whose host the verifier can't tell (any of the above, an empty label, something that looks like an address
and is none, a URL Python can't split) is unproven, never proven or failed; a claimed host it can't tell
(`a..example`, `0127.0.0.1`, `:80`) makes the claim unproven. The verifier checks each rule itself, so its verdict is
the same on every Python: `urlsplit`'s own bracket check, and what it strips from a URL (leading controls and spaces,
tabs and newlines), differ between releases.

### Paths

`file_written` reads the claimed path by one of two sets of rules, and the call's path by the same set:

- A path that begins with `/` is a POSIX path: only `/` separates and `\` is part of a name, so `/repo\refund.py` is
  one file in `/`, not `/repo/refund.py`. Both are compared after POSIX normalisation (`/repo//./refund.py` is
  `/repo/refund.py`). A call's `C:/repo/refund.py` is a relative path under these rules.
- A drive path (`C:\repo\refund.py`, `C:/repo/refund.py`) is a Windows path: `\` and `/` both separate. Only a call of
  the very same string proves it. The same path spelled otherwise (`C:/repo/refund.py`, `C:\repo\.\refund.py`) is
  unproven: the record doesn't say which system ran the call, and on POSIX that is a relative path. So a proven drive
  path assumes the call ran on Windows: an executor on Linux that wrote `C:\deploy\a.py` made a file of that name in
  its working directory, and the claim is still proven, since the claim and the call carry the same string.

Case counts under both: a call of `c:\repo\refund.py` doesn't prove `C:\repo\refund.py`. A claimed path that is relative
on either system is malformed: `repo/refund.py`, `\repo\refund.py` (the current drive's), `C:refund.py` (the drive's
working directory) and a UNC path (`\\server\share\refund.py`); so is one with a `..`. A call's path that is relative,
or holds a `..` (only what follows the last one is certain), is unproven when it ends with the claimed path, and fails
otherwise.

### Evidence

The evidence for a claim is self-contained. It needs only trust.json:

```json
{"checkpoint": "tracekit.local/39efd223d635ba423b1faced04a8e7d7\n8\nMOdodHINu4iy4en2EA2+YPnEKH/Nt5/aXOJHRgr4qaY=\n\n— tracekit.local/39efd223d635ba423b1faced04a8e7d7 UuvN7Jot…\n",
 "records": [
  {"event": {"type": "policy.decision", "seq": 2, "run_id": "4205598ec8ab06b650a402d019b1592a", "tenant": "default",
             "data": {"tool_use_id": "grant-1", "tool": "pcm.grant", "decision": "ask",
                      "decision_id": "dec-85e37303efb88bac7da4e610d711ab3f", "…": "…"}, "…": "…"},
   "hash": "sha256:…", "proof": ["…"]},
  {"event": {"type": "approval.request", "seq": 3,
             "data": {"approval_id": "apr-982067cfc47a41b2d652f9a51860d02d",
                      "decision_id": "dec-85e37303efb88bac7da4e610d711ab3f", "…": "…"}, "…": "…"},
   "hash": "sha256:…", "proof": ["…"]},
  {"event": {"type": "approval", "seq": 4,
             "data": {"tool_use_id": "grant-1", "approval_id": "apr-982067cfc47a41b2d652f9a51860d02d",
                      "decision": "approve", "approver": "uid:990001", "person": "alice", "self_approved": false,
                      "…": "…"}, "…": "…"},
   "hash": "sha256:5bf218dc39a3c41efdfaccd33e99bc7f7a6e8f365c7aaaa01b708b2332b47cfa",
   "proof": ["zq3sGmbBpb1ungBDmMhpS6xl1UszRL8GQa4msQbSm9w=", "8xx0dD16…", "s5+blM63…"]}]}
```

That is the demo's `approved_by` evidence: the decision, the approval.request that names it and alice's approval.

The receiver checks, in order:

1. The checkpoint note is signed by a log key trust.json pins, has the cosignatures `witnesses_required` asks for,
   and is of the same log as the key that signed the message.
2. Each record's hash is the hash of its event, its inclusion proof leads to the note's root, and no record is listed
   twice (`record 4: the same record as record 3`).
3. Each record is from the sender's own run and tenant (`from.run`, `from.tenant`).
4. Where a claim reads a call's args (`command`, `url`, `content`), the record is a `policy.decision` and carries
   `salt` and `args` that open its `args_commitment`. The signer never stores args in clear; the salt is what proves
   these are the args it decided.

Change one byte and the claim fails. The demo's third message changes one hex digit of a record hash:

```text
B: REJECT           approved_by: failed (record 1: hash does not match the event)
```

Opening a decision shows its args to the receiver. The SDK opens only the decisions you name.

### Freshness

A claim says a call happened, not that nothing happened after it. The sender picks the records it sends, so none of
the run's later ones need be there. A suite passed, the code changed and the suite failed: the record of the pass
still proves `tests_passed`. A file was written, then overwritten: the first write still proves `file_written`. Both
are `proven`: PCM 0.1 can't show what came later (its specification, section 14.13). If you act on the current
state, check:

- **Age.** Take the oldest `ts` among a claim's evidence records (the sender can add records, but not to make the
  evidence look newer; for `tests_passed` it's no later than the decision, made before the runner ran) and refuse
  the message when its own `ts` is more than your maximum age after that. The signer sets both times from its clock,
  so yours doesn't matter. Use seconds or a minute, not hours: `pcm_evidence` has a checkpoint about a second after
  the call, and a suite can pass, change and fail within a minute. `tracekit pcm verify` prints that age after a
  proven `tests_passed` or `file_written` (`evidence 2 s before the message: …`).
- **After the last change you know of.** If you know when what you act on last changed (the commit you'll merge was
  pushed, you sent the request that asked for the check), refuse evidence older than that, allowing for clock skew.
- **`tests_passed`.** Name the suite you need, compare `suite` with it, and ask the sender to run it after your
  request. The claim still doesn't say which code the suite ran on: the agent can change the code after the run, run
  the suite again in another run, or run it until it passes. If that matters, run the suite yourself on the code you
  act on.
- **`file_written`.** Hash the file you receive, once, and use those same bytes: `"sha256:" + sha256(bytes)` must
  equal the claim's `digest`. If it differs, the file was written again since, or it's another file. This is the one
  check that rules a later write out.
- **`approved_by`, `reached_host`.** Only the age check applies. For authority that must lapse, require a grant: the
  verifier checks its expiry.

```python
import datetime
import hashlib

def evidence_age_s(msg, i):
    """Seconds from the oldest record of claim i's evidence to the message."""
    t = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    oldest = min(t(r["event"]["ts"]) for r in msg["claims"][i]["evidence"]["records"])
    return (t(msg["ts"]) - oldest).total_seconds()

def same_file(claim, data):
    """Whether `data`, the bytes you received, are what a file_written claim proves was written."""
    return "sha256:" + hashlib.sha256(data).hexdigest() == claim["args"]["digest"]
```

As a sender, send the claim right after the call. A later PCM version could carry every record of the run since the
call, and bind `tests_passed` to the git tree it ran on and `file_written` to the bytes the executor wrote (the PCM
0.1 specification, Appendix B question 5).

## Grants

A grant says: this agent may ask for this intent, within these caveats, until this time. The signer signs it with
the log key. A root grant needs the approval of a person signer.yaml's `approvals.persons` names, and carries that
name in `issuer.person`. A grant from the demo signer:

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
- `approvals.persons` maps the approver's identity to no person (an OIDC approver too: map its identity there), so
  the grant would name no one: `a root grant needs the approval of a person signer.yaml's approvals.persons names:
  uid:990009 maps to none`;
- `expires_at` is not within the next 24 hours;
- the `pcm.grant` call already has its result (one grant per approval);
- the run is held or quarantined.

Without the ask rule there is nothing to consume, so no root grant can be made.

**`delegable`** is the person's choice: may the subject pass this grant on? A child is made with `pcm_delegate`, by
the grant's subject only, with no approval. It can only narrow: the same intent, an expiry after now and no later than
the parent's, and caveats that imply the parent's. The child sets its own `delegable`. A grant with `delegable: false`
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
| root | no parent, issued by a person it names (`issuer.person`), issuer is not the subject |
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
 "claims": [{"type": "approved_by", "result": "proven",
             "detail": "approval seq 4 by alice of \"pcm.grant\" call grant-1, which issued this message's root grant",
             "approved": {"tool": "pcm.grant", "args": null}}],
 "verdict": "accept", "reasons": [], "skipped": []}
```

`skipped` names the checks the caller didn't ask for: `replay` when it passes no `Replay`, `recipient` when it passes
no `me`. An `accept` with something skipped says less than it reads: the message may be a replay, or for another
receiver.

| Verdict | When |
|---|---|
| `reject` | the envelope or signature fails, replay or recipient fails, the args break the schema, the grant chain fails, any claim fails, or (with `strict`) a claim type the schema lists is not proven (`approved_by`: not proven with `covers`) |
| `accept-unproven` | otherwise, when a claim is unproven or a claim type the schema lists has no proven claim (`approved_by`: none proven with `covers`) |
| `accept` | everything checked passed and every claim is proven |

A forged message stops at the signature; no claim work is done for it.

**Replay.** A receiver keeps one `pcm.Replay()` for its whole life and passes it to every call. A message passes once:
within 300 s of the receiver's clock, not signed before the receiver started, and with a nonce not seen before from
that sender. A sender is the log key that signed the message and its `from.agent`: the same agent name under two
pinned logs is two senders. A message signed before the receiver started is refused:

```text
replay: sent before this receiver started: ask for it again
```

So a restart needs no saved state; the sender asks again. `me` is the receiver's own identity: a message addressed to
another is rejected (`replay: addressed to uid:990102, not uid:990103`). A message rejected because it is for another
receiver, or of a schema this receiver doesn't have or whose args break it, spends no nonce: the same message still
passes once it reaches its receiver, or once the receiver has its schema.

**From the command line,** for one saved message:

```text
$ tracekit pcm verify msg.json --trust trust.json --schema refund.request.json --me uid:990102
ACCEPT  signature ok · schema ok · grant ok (alice, 1 step) · approved_by proven (approval seq 4 by alice of "pcm.grant" call grant-1, which issued this message's root grant) · not checked: replay
```

It exits 0 for accept, 3 for accept-unproven, 1 for reject and 2 when it can't read its inputs (trust.json with two
keys of one log too: [Trust and keys](#trust-and-keys)). `--strict` rejects when a claim type the schema lists is not
proven; `--json` prints the whole result. It does not check replay: it reads one message, and a new process remembers
no nonces. So its line ends `not checked: replay`, and `not checked: replay, recipient` without `--me`. The sender
chose parts of the line, so it prints a character a terminal would act on, and `\`, as JSON escapes it (`\u001b`,
`\\`): a `\u001b` the sender wrote shows as `\\u001b`.

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
    # the approval, the approval.request it answers and the decision that request names
    recs = run.call("read", limit=1000)["events"]
    [a] = [e for e in recs if e["type"] == "approval"]
    [r] = [e for e in recs if e["type"] == "approval.request"
           and e["data"]["approval_id"] == a["data"]["approval_id"]]
    [d] = [e for e in recs if e["type"] == "policy.decision"
           and e["data"].get("decision_id") == r["data"]["decision_id"]]
    ev = run.pcm_evidence([d["run_seq"], r["run_seq"], a["run_seq"]])   # waits for a checkpoint that covers them
    # covers: alice's approval issued the grant this request is under
    msg = run.pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, grants=[grant], claims=[
        {"type": "approved_by", "args": {"person": "alice", "call": a["data"]["tool_use_id"], "covers": True},
         "evidence": ev}])

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
each evidence checkpoint. A malformed or non-canonical vkey anywhere in `logs` or `witnesses` is the receiver's own
error: `pcm.verify` raises on it before it checks a message.

Because the log key signs all three, a fault in PCM signing is a fault of the log key: the fix is rotating it.

PCM 0.1 takes one Ed25519 key per log. A trust.json that pins two under one log name is the receiver's own error:
`pcm.verify` raises and `tracekit pcm verify` exits 2 (`trust.json pins 2 Ed25519 keys for log …; PCM verifies with
one: pass a trust file with only the current key`, and `tracekit signer trust --config <signer.yaml> -o pcm-trust.json`
writes one). PCM declares no rotation, so it can't tell which of the two may sign a message now, and an old key that
leaked would sign grants for as long as it stays pinned. For bundles, [signing](signing.md) says to keep old public
keys pinned after a rotation, so old bundles still verify; that trust.json is not one for PCM. Give PCM its own
trust.json that pins only each log's current key. To rotate, replace the key in it: messages, grants and evidence the
old key signed then don't verify, so senders ask for new grants and send again.

There is no revocation and no key validity period. A leaked log key signs any message, grant or evidence checkpoint,
with any time and expiry, until every receiver removes it from trust.json: the 24-hour grant cap binds only an honest
signer, and witness cosignatures (`witnesses_required`) limit forged evidence, not forged messages or grants. Keep the
log key where only the signer reads it ([signing](signing.md)). If it leaks, remove it from every receiver's
trust.json, rotate it, and treat what you accepted under it since the leak as unverified.

## Agent-to-agent transport

The [A2A gateway](a2a.md) is merged, but it doesn't check PCM parts yet: it forwards them like any other part.
Enforcing PCM in it (checking PCM parts before it forwards them, dropping rejected ones, and letting policy require
proven claims per receiver or intent) is a follow-up. `run.transfer` ([latent transfers](c2c.md)) already records a
transfer; only the `transfer` payload that would carry its evidence is a follow-up. Until then the receiver calls
`pcm.verify` itself.

## Limits

All of them, with what to do: [limits](limits.md#pcm-01-proof-carrying-messages-experimental).
