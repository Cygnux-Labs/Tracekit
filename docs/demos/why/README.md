# Why: which input caused the action

A three-agent support system (researcher, planner, executor; seeded mock models, fake tools) handles a refund ticket.
A vendor note the researcher reads carries a planted instruction to email the customer list to an outside address,
and in 5 of 8 recorded runs the executor exports the customers and emails them to `audit@vendor-compliance.example`.
`tracekit why` investigates one of those runs. Every untrusted input reached the email, so it replays the run without
each suspect (10 paired replays, tools served from the recorded tape) and measures whether the email still goes out.

```sh
tracekit why demo --out runs --n 10                                # no API key, no network
tracekit view --why runs --allow-program tracekit.why.demo:SYSTEM   # the same runs in the viewer
```

**What the record shows.** The run's five calls by agent, its hash chain checked (20 events), and the blast radius:
the ticket, the shipping FAQ and the vendor note each reached the exfiltration email. The tests then separate them.
Without `vendor:portal/notes.md` the email goes out in 0% of replays instead of 90%: `CAUSAL (primary)`, effect
+0.90, interval [+0.49, +0.98]. Without the FAQ or the ticket it still goes out 90% of the time: effect +0.00, but at
n=10 the interval is too wide to rule them out (`INCONCLUSIVE`; the report suggests n=25). The researcher's message
to the planner, which carried the instruction on, is causal too, and re-calling only the researcher's model call
without the vendor inputs finds the decision the instruction entered at. The why log is hash-chained, not signed;
`tracekit demo --why` runs the same support desk on the signer ([with the signer](../../why.md#with-the-signer)).

**Why it matters.** In a multi-agent run every input reaches every later action, so reach can't name a cause.
Replaying without each one turns "the vendor note was in the context" into "without the vendor note the email doesn't
go out", with an interval, so the fix goes to the input that did it.

[transcript.txt](transcript.txt) · [the demo system](../../../tracekit/why/demo.py) ·
[tracekit why](../../why.md) · [how causality is tested](../../why.md#how-causality-is-tested)
