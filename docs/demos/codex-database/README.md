# A production database

After a public incident report: in July 2026 a developer reported that GPT-5.6 Sol, OpenAI's model behind Codex,
deleted their whole production database ([The Register](https://www.theregister.com/a/5274008)); the database's
credentials were in the project's local `.env` file. OpenAI's Codex lead said such deletions happen mostly in
Full-Access mode, without Codex's sandbox or its Auto-review. The report doesn't say which commands ran, so here a
scripted coding agent takes one likely path under the dev pack, the signer's default for coding agents on a laptop:
it reads `.env` (flagged, TK-F005, a secret-looking path), runs the tests, then drops the database's schema with
`psql "$DATABASE_URL" -c "DROP SCHEMA public CASCADE; …"`. The `psql` waits for a person (TK-A039, a drop, truncate
or unfiltered delete through a database client). The person rejects it with a reason; the agent's other calls run.

```sh
python examples/v2/demos/codex_database.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** The `.env` read's `policy.decision` (`flag`, TK-F005: it ran, marked), then the `psql`'s
(`ask` and the rule id) before it could run, the person's `approval` (reject, with the reason they gave), then the
signer's `approval.refused` (`TK-APPROVAL-REJECTED`) when the agent tries to run it anyway; no `tool.result` for it.
A call the person approves would show the approval, then its result.

**Why it matters.** The rule holds the statement itself, whatever mode the agent runs in and whatever the model says
it is doing: a `DROP`, `TRUNCATE` or unfiltered `DELETE` given to `psql -c`, `mysql -e`, `mongosh --eval` or
`redis-cli` waits for a person, and so do `dropdb` (TK-A001) and a framework's reset (`prisma migrate reset`,
`rails db:drop`, TK-A055). It reads the statement on the command line, so one run from a file (`psql -f reset.sql`,
`psql < reset.sql`), built in a variable or sent from an interpreter one-liner isn't held
([what TK-A039 reads](../../limits.md)); keep production credentials out of the agent's project.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/codex_database.py) ·
[packs](../../policy-v2.md#packs-shipped) · [limits](../../limits.md)
