# Provenance and `tracekit why`

Prompt injection works by getting text the agent read (a web page, an email, a support ticket) to steer what it does
next. Tracekit has two tools for this. **Provenance** notices, at decision time, when a value in a call came only from
untrusted content, so a policy can hold that call for a person. **`tracekit why`** answers, after the fact, which input
actually caused an action, by replaying the run without it. A third, `tracekit analyze --v2`, checks after a run
whether what the person asked, what the model said and what the agent did agree. All three are experimental.

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

## What was asked, said and done

`tracekit analyze --v2` reads a finished run's signed records and, from the content vault, the text they commit to
(each piece must open its record's commitment, or the analysis stops). It then runs fixed checks that compare the
person's request, what the model said before each call, and what the calls did:

| Rule | Finds |
|---|---|
| TK-X201, TK-X202, TK-X203 | An action with no reasoning before it, an edit of a file nobody named, a write outside the project |
| TK-X204 | A call that broke something the person (or the model itself) said not to do |
| TK-X205, and v1's text checks | Success claimed after a failed check, a test run, commit or push claimed that never ran, a denied action that ran |
| TK-X206, TK-X207 | With a kernel sensor's records: an effect no call explains, or a call that reported success with no effect |
| TK-X208 | A "request" in the agent's transcript that the person never typed |
| TK-X210 (`--review`) | A second model's opinion of the run, preferably from another model family. Warn only: it never changes the exit code and holds nothing |

Each finding names the text it relied on and who could have written it: the LLM gateway's record ranks above the hook's
copy of a prompt, and both above the agent's own transcript. A check that can't run says why and what would make it
checkable; it never counts as a pass. Reasoning is the model's own account of itself, and providers often return it
sealed: [reasoning](../reasoning.md) says what each agent, framework and provider hands over, and how to turn it on.

**Signed findings.** The analyzer sends each finding through the signer (`review_finding`, RPC 19) into a findings run
of its own about the run. Each is a `review` record that cites the analysed records by `run_seq` and hash and holds no
text of the run. `tracekit export --v2 --run R --with-findings` bundles them with the run, and `tracekit verify` fails
a citation that doesn't match. The findings get their own `Findings:` line, after integrity and assurance, saying whose
opinion they are: on a laptop the analyzer is the agent's own user, so they read `self-asserted`; run it as an operator
identity the verifier pins to get findings it reads as independent.

**Live constraints.** TK-X204 reads the same small grammar the signer uses during the run: what a prompt says not to do
is held live by the signer ([live constraints](policy.md#live-constraints)) and checked again afterwards, together
with the model's own promises.

**Where it stops.** The checks read names and order, not meaning. A file named innocently in the model's text clears
TK-X202, and the constraint grammar reads 4 of the 12 ways of saying "don't touch X" in E20's held-out pool v2
([evaluation](../evaluation.md#e20-intent-reasoning-and-action-checks),
[limits](../limits.md#intent-reasoning-and-action-checks)). Commands, every rule and the `--json` shape:
[findings](../findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2).

## Reference

[Provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted) · [tracekit why](../why.md) ·
[why architecture](../why-architecture.md) · [findings](../findings.md) · code:
[`tracekit/provenance.py`](../../tracekit/provenance.py), [`tracekit/why/`](../../tracekit/why),
[`tracekit/findings_v2.py`](../../tracekit/findings_v2.py)

---

Previous: [Custody](custody.md) · [All concepts](README.md) · Next: [Deployment and isolation](deployment.md)
