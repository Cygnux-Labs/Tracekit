# A production volume

After a public incident report: in May 2026 a coding agent that hit a credential mismatch deleted PocketOS's
production database with one call to Railway's GraphQL API (`volumeDelete`). Here a scripted coding agent makes that
call as a `Bash` tool call under the dev pack, the signer's default for coding agents on a laptop. The `curl` waits for
a person (TK-A001, destroying a deployment, database or volume). The person rejects it with a reason; the agent's
`railway` and `git` calls run.

```sh
python examples/v2/demos/pocketos.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** The `curl`'s `policy.decision` (`ask` and the rule ids) before anything ran, the person's
`approval` (reject, with the reason they gave), then the signer's `approval.refused` (`TK-APPROVAL-REJECTED`) when the
agent tries to run it anyway; no `tool.result` for it. A call the person approves would show the approval, then its
result.

**Why it matters.** The rule reads the command's arguments, not what the model says it is doing: a mutation named
`volumeDelete` with its call parenthesis is held however the request is worded. A URL or file named
`serviceDelete.json` is not.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/pocketos.py) ·
[packs](../../policy-v2.md#packs-shipped) · [limits](../../limits.md)
