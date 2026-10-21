# A production bucket

After a public incident report: a coding agent, told "no new upload", uploaded files to a production bucket anyway;
told to roll back, it deleted them and then purged every version of them, destroying the version history kept as a
safety net. Here a scripted coding agent makes the same three calls under the dev pack, the signer's default for
coding agents on a laptop. The upload waits for a person (TK-A032, uploads to cloud storage), and so do the delete
and the version purge (TK-A031, destroying cloud storage data). The person rejects each with a reason; the agent's
listing and its `git diff` run.

```sh
python examples/v2/demos/cloud_storage.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** For each held call, its `policy.decision` (`ask` and the rule ids) before anything ran,
and the person's `approval` (reject, with the reason they gave); no `tool.result` for any of the three. A call the
person approves would show the approval, then its result.

**Why it matters.** The request said "no new upload", but the person's words aren't what stops the upload here: the
rules hold the action itself, however the model describes it. A version purge can't be undone, so it waits for a
person on every pack; uploads wait on the dev pack, where a coding agent rarely writes to a bucket.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/cloud_storage.py) ·
[packs](../../policy-v2.md#packs-shipped) · [limits](../../limits.md)
