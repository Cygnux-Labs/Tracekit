# Auditor guide (v2 bundles)

You are checking an operator's evidence about its agents. The operator gives you bundles; everything you trust has to
come from somewhere else. That is the point of the format: a bundle carries no code and no trust configuration, and
the verifier pins its own ([format v2](format-v2.md), invariant I9 in the [threat model](threat-model-server.md)).

## 1. Get a verifier you trust

Install Tracekit yourself, from PyPI or a source checkout you have reviewed, at a version you pin:

```sh
pip install 'tracekit-ai==<version>'
tracekit --version
```

Never run a verifier, script or trust file the operator ships with the evidence. Verifying a v2 bundle needs no network
access.

## 2. Build the trust config from independent sources

`trust.json` pins the log key, the witnesses and the algorithms ([format v2](format-v2.md#10-the-trust-config)):

```json
{"logs": ["tracekit.example.org/log/1+1a2b3c4d+AZ..."],
 "witnesses": [{"vkey": "witness.example.org/w1+257cc7f1+BG...", "class": "public"}],
 "algs": ["ed25519"],
 "witnesses_required": 1}
```

| Entry | Where to get it |
|---|---|
| `logs` | The operator's log vkey (`tracekit signer vkey` on their side). Get it once, through a channel you can hold them to (a signed letter, a contract annex, a published page you archive), and keep your copy. Cross-check it against the copy each witness registered for that log (the witness network's logs list). |
| `witnesses` | Each witness's cosignature vkey, **from the witness's operator**, not from the signer's config. |
| `class` | Your judgement of who runs each witness: `public` (a witness network), `customer` (you or another customer), `tracekit`, or `operator` (the party being audited). Only non-`operator` witnesses count toward `witnessed`. |
| `witnesses_required` | How many pinned cosignatures a checkpoint must carry. Set it to at least 1 for an audit. |
| `rekor` (optional) | Sigstore's `trusted_root` from Sigstore's TUF repository, the signer's Rekor publishing key (`rekor.pub`) from the operator, and its class. See [witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps). |

`tracekit signer trust -o trust.json` writes a trust config from a signer's own config. It is a convenience for the
operator; as an auditor, check every key in it against your own sources before using it.

## 3. Get the bundles

Ask for the runs you sample, and for the tenant's run-set, which shows that no run was left out:

```sh
tracekit export --v2 --run <run id> -o run.tkb                  # one run
tracekit export --v2 --run-set --tenant <tenant> -o run-set.tkb  # the registry from size 0 to its latest checkpoint,
                                                                 # with every run finalised in it
```

The operator runs these after the next checkpoint covers the records. A run-set bundle holds the tenant's registry
salt, so it lets you test guessed run ids against that tenant's leaves (only that tenant's).

## 4. Verify

```sh
tracekit verify run.tkb --trust trust.json --strict
tracekit verify run-set.tkb --trust trust.json --strict --json > run-set.report.json
```

Exit 0 is clean, 1 failed, 2 unusable, 3 warnings under `--strict`. For a bundle whose log continues a v1 ledger, add
`--v1-ledger ledger.jsonl --v1-key signer.pub` to check the format bridge.

**A second verifier.** The TypeScript verifier was written from the [format spec](format-v2.md), not from the Python
code, and is tested to reach the same verdicts ([implementations](format-v2.md#13-implementations)). Running both, from
two sources you obtained yourself, means a bug in one doesn't decide your audit:

```sh
npx @cygnux/tracekit@<version> verify run.tkb --trust trust.json --strict
```

It needs only Node ≥ 20.12. Where it can't check something the bundle relies on (an SLH-DSA checkpoint line, a Rekor
anchor, a certified record key) it says `UNVERIFIABLE` and names it; use the Python verifier for those.

## 5. Read the report

[Verdicts](verdicts.md) explains every line. For an audit, look at least at:

- `Integrity:` `VERIFIED`, not `VERIFIED TO HEAD n (open)`, for runs that should be finished.
- `Assurance:` `witnessed`, with cosignatures from witnesses you classed as independent, at times inside the window.
  `dev` or `local` means nothing outside the operator vouches for the checkpoint.
- `run-set: COMPLETE`, and no `keys` warning `retirements not proven complete`.
- `isolation`: `separate-user` (or a remote signer) for production runs; `same-user` is a dev signer.
- `coverage`, `tiers` and `fail-open classes`: how much of what the agent did the evidence can speak for.
- `policy`, `break-glass approvals` and `approvals: self`: calls that ran against policy and who approved what.

## 6. Check content against a commitment

Records never hold a plain hash of what the agent sent, only an HMAC commitment under a per-record salt
([format v2](format-v2.md#2-hashes-over-agent-content)). To check that some arguments you were given (from the
application's own logs, say) are the ones a decision was made on:

1. Note the record's `seq` (for example a `policy.decision`), and ask the operator to reveal its salt:

   ```sh
   tracekit signer reveal --record 1234 --config signer.yaml
   {"seq": 1234, "type": "policy.decision", "salt": "9f…"}
   ```

   Only the owner of the signer's keys can run this. One salt opens one record's commitments, nothing else.

2. Recompute the commitment and compare it with the record's `data.args_commitment`:

   ```python
   import hashlib, hmac
   from tracekit.format.canon import canonical

   digest = "sha256:" + hashlib.sha256(canonical({"tool": tool, "args": args})).hexdigest()
   commitment = "hmac-sha256:" + hmac.new(bytes.fromhex(salt), digest.encode(), "sha256").hexdigest()
   assert commitment == record["event"]["data"]["args_commitment"]
   ```

   `args` are the arguments as JSON values; for `args_source: raw` parse the raw text first (strict JSON). A
   `tool.result`'s `output.hash` commits the same way to `"sha256:" + hex(SHA-256(JCS(value)))`, where value
   holds the call's `result` and `error` fields as the signer redacted them, so it matches the original only when
   nothing was redacted (`output.redacted: false`).

A match shows those were the arguments; a mismatch shows they were not. Without the salt, a commitment says nothing
about the content, and guessing it is not feasible.
