# Provenance and `tracekit why`

Prompt injection works by getting text the agent read (a web page, an email, a support ticket) to steer what it does
next. Tracekit has two tools for this. **Provenance** notices, at decision time, when a value in a call came only from
untrusted content, so a policy can hold that call for a person. **`tracekit why`** answers, after the fact, which input
actually caused an action, by replaying the run without it. Both are experimental in 1.2.

## Argument provenance

### What counts as untrusted

The policy's `untrusted` list names the tool classes and tool names whose results are untrusted content, for example
`untrusted: [http, mcp, WebFetch]`. The agent has no say. For those tools, the signer asks the client for the full
result instead of a digest. Other content the agent reads (an email body, a ticket) can be recorded with
`observe(..., trust="untrusted")`; the task itself is observed as trusted.

### The index

For each run, the signer indexes values from untrusted content: email addresses, URLs and their hosts, IP addresses,
absolute paths, long digit runs (account numbers) and other strings of 6 to 256 characters. Text is normalised first
(invisible characters removed, Unicode normalised). The index keeps, for each value, the first record that brought it
in. A value that has also been seen in trusted content stays trusted. Results of tools that echo the agent's own input,
such as SQL and shell, are never indexed.

### Rules that use it

A rule with `from: untrusted` matches only if its pattern matches **and** some value in the field came only from
untrusted content. The server packs use it in three ask rules:

| Rule | Holds a call when |
|---|---|
| `TK-P001` | An email recipient came only from untrusted content |
| `TK-P002` | A payee or account came only from untrusted content |
| `TK-P003` | Data is sent to a host that came only from untrusted content |

The decision records where each matching value came from (the field, the kind of value, and the record that introduced
it, never the value itself). If the index is incomplete for any reason (a result sent only as a digest, a counter gap,
a restart), the rule fails closed: it matches whenever its pattern does.

### Where it stops

Matching is verbatim. A value the agent paraphrases, encodes or shortens isn't recognised, and an agent program that
labels untrusted content as trusted defeats it. It's a tripwire against injected values, not information-flow control.

## `tracekit why`

### The question it answers

"Would this action still have happened without this input?" Rather than guessing from text overlap, `tracekit why`
runs the experiment: it replays the agent's decision with the suspect input removed, many times, and measures whether
the action still happens.

### How it works

1. **Record.** A run is recorded as a hash-chained event log: inputs, model calls, decisions, actions and messages.
2. **Taint.** Starting from the action in question, it finds every upstream input that could have reached it, through
   observed edges (the input was in the model's context, or its content reappears) and inferred ones (strong text
   overlap).
3. **Test.** It replays decisions with paired random seeds, with and without an input. Tools are served from the
   recording, so replays never repeat real side effects; a call that was never recorded gets a stub.
4. **Attribute.** It first removes every upstream untrusted input together. If that changes the outcome, it narrows down
   to individual inputs (one at a time for four or fewer, by halving for more).

Each test reports the effect (how much more often the action happens with the input than without) with a confidence
interval, corrected for testing several inputs, and a verdict: **causal**, **suppressive**, **ruled out** (any effect is
smaller than 20 points), or **inconclusive** (with a suggested number of runs to decide).

### Signed findings

On a run recorded by the signer, with the content vault and the LLM gateway, every replay is itself a signed run, and
each result is written as a signed `why.finding` record. `tracekit export --v2 --run R --with-findings` bundles them,
and the verifier recomputes each finding's interval and verdict from the replay runs it cites.

### Results and cost

On a small local model (Qwen 2.5 7B), in scenarios where the planted document really caused the harm, `tracekit why`
named exactly that cause in 6 of 6 harmful runs, with no false blames. The sample is small. Attributing one run took
320 to 540 model calls. Tracing provenance alone (no replay) blames every untrusted input upstream; replay is what
narrows it to the cause.

`tracekit why` began as a separate project, Causeway, and joined Tracekit in 1.1. Commands and the viewer's why views:
[tracekit why](../why.md); design: [its architecture](../why-architecture.md).

## Reference

[Provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted) · [tracekit why](../why.md) ·
[why architecture](../why-architecture.md) · code: [`tracekit/provenance.py`](../../tracekit/provenance.py),
[`tracekit/why/`](../../tracekit/why)

---

Previous: [Custody](custody.md) · [All concepts](README.md) · Next: [Deployment and isolation](deployment.md)
