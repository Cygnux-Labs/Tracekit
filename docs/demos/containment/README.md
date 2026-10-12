# Detection and containment

A coding agent reads `.env`, then posts a file to a paste site. Each call alone is allowed; together they complete
the sequence TK-Q001 (a secret read, then egress), which this policy enforces with a hold. In the same step as the
second decision the signer opens an incident and holds the run, and decides the upload again: `ask` (TK-HOLD). The
person at the terminal reviews the incident, rejects the upload and resumes the run; the next call runs.

```sh
python examples/v2/demos/containment.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** `incident.opened` (trigger `sequence`, TK-Q001, `mode: enforce`, `actions: [hold]`,
citing both decisions), `run.held`, the upload's second `policy.decision` with the incident's id, the person's
`approval` (reject) and `run.resumed` naming who ended the hold. [verify.txt](verify.txt) recomputes the incident from
the bundle's records and policy snapshot: `1 checked against the bundle`.

**Why it matters.** Rules judge one call at a time; an exfiltration is often two harmless-looking calls. Detection
runs in the signer, so the hold lands before the second call can run, and an auditor can check it was honoured.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/containment.py) ·
[incidents](../../incidents.md)
