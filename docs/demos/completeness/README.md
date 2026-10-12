# Completeness and tamper evidence

An agent's two calls are allowed; only the first reports a result. The second never does, as when a tool hangs, the
process dies or a post-call hook doesn't fire. When the run ends the signer, which saw the decision, writes a signed
`capture.gap{decided_not_completed}` for it. Then a copy of the bundle with one byte changed (the gap's `tool_use_id`,
`call-2` to `call-1`) is verified as well.

```sh
python examples/v2/demos/completeness.py   # on the dev signer
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** Two `policy.decision` records (allow), one `tool.result` (call-1) and the gap naming
call-2. [verify.txt](verify.txt): `Integrity: VERIFIED` with a `[WARN] gaps` line. In the
[transcript](transcript.txt) the one-byte copy fails: `[FAIL] manifest`, `[FAIL] signatures` (hash does not match the
event), `Integrity: FAILED`.

**Why it matters.** A trace that holds only what arrived can't tell "never ran" from "lost". The signer names the
call that is unaccounted for, and nobody can move that gap to another call, or remove it, and still verify.

[the example](../../../examples/v2/demos/completeness.py) · [reading a verify report](../../verdicts.md)
