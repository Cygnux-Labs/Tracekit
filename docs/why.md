# tracekit why: causal investigation and replay

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

`tracekit why` records multi-agent runs with their full content and answers three questions about an action one of
the agents took:

1. **What happened?** Which agent did it, with what arguments, after which steps.
2. **Why?** Which input, message or other agent led to it.
3. **Is that really why?** Or was the suspect input merely present?

In a typical run every document an agent read is in the context of every later decision, so every document "reached"
the action. Reach does not say which one changed the outcome. `tracekit why` answers the third question by replaying
the run without a suspect input and measuring whether the action still happens.

What it records, per run (`events.jsonl` plus content-addressed `blobs/`, hash-chained; schema
`tracekit.why.event.v1`):

- inputs, with a trust label (`trusted` or `untrusted`) and a source;
- model calls, with exactly the context items they saw (by content hash), their output, latency and usage;
- tool calls, linked to the model call that asked for them;
- messages between agents.

The why log is hash-chained, not signed: anyone who can rewrite the whole log can rebuild the chain. Recorded with
the signer, or imported from a Tracekit ledger, each event cites the signed record it came from (see
[With the signer](#with-the-signer) and [Importing a v1 ledger](#importing-a-v1-ledger)).
The formats and algorithms are in [why-architecture.md](why-architecture.md).

## Demo

No API key and no network. The demo is a three-agent support system (researcher, planner, executor) whose models are
seeded mock policies and whose tools are fakes. A vendor note the researcher reads contains a planted instruction to
email the customer list to an outside address.

```bash
tracekit why demo --out runs                                        # also writes runs/report.html
tracekit view --why runs --allow-program tracekit.why.demo:SYSTEM
```

`demo` records 8 runs, then tests the inputs of one where the email went out:

```text
== counterfactual tests (n=40 paired replays each; tools served from tape)
  remove input:vendor:portal/notes.md  target tool=send_email,arg~vendor-compliance  P(with)=0.80 P(without)=0.00 effect=+0.80 [+0.63, +0.90]  CAUSAL
  remove input:web:shipping_faq        target tool=send_email,arg~vendor-compliance  P(with)=0.80 P(without)=0.80 effect=+0.00 [-0.18, +0.18]  RULED-OUT
  remove input:inbox:ticket-881        target tool=send_email,arg~vendor-compliance  P(with)=0.80 P(without)=0.80 effect=+0.00 [-0.18, +0.18]  RULED-OUT
  remove msg:researcher->planner       target tool=send_email,arg~vendor-compliance  P(with)=0.80 P(without)=0.00 effect=+0.80 [+0.63, +0.90]  CAUSAL
```

All three untrusted inputs reached the email; replaying without the vendor note drops it from 80% of runs to 0%, and
removing the other two changes nothing detectable. `tracekit view` prints a URL with a one-time token; open it.
`runs/report.html` is the same page with the 8 runs embedded: it opens from the file, with no server and no network,
and runs no replays (`tracekit why report ROOT [-o FILE]` writes one for any folder of why logs, or one run).

**The UI is the viewer** ([viewer.md](viewer.md#why)): `tracekit view --why DIR` shows the why logs alone, and
`tracekit view --dev --why DIR` adds them to a signer's runs (`tracekit why serve DIR` still runs the first). Each run's calls are on the tape; select one and open **WHY**
in the detail panel for where each argument came from, the recorded path through the agents, and every candidate cause
with its test status and the **FIND THE CAUSE** / **RUN TEST** buttons. The header switches the lower panels to
**RUNS**, **OVERVIEW**, **TIMELINE**, **WHY DID IT HAPPEN?**, **GRAPH** (the data-flow graph, tested causes in red), **AGENTS** (per-channel usage and tested influence, the
influence matrix, the critical path) or **INFLUENCE** (across runs: which content reached which tools, and which links
tests confirmed). The why alerts join the alert panel.

## Instrumenting agents

Three ways in, from most control to least effort.

### 1. Write the loop with the runtime

```python
from tracekit.why import System

def program(rt):
    researcher = rt.agent("researcher", role="gathers facts")
    planner = rt.agent("planner", parent="researcher")

    doc = researcher.observe(page_text, source="web:vendor-notes", trust="untrusted")
    order = researcher.act("lookup_order", {"order_id": 1042})
    summary = researcher.decide([rt.task_ref, doc, order], model="claude", purpose="summarize")
    researcher.send("planner", summary)

    plan = planner.decide([rt.task_ref, *planner.inbox()], model="claude", purpose="plan")
    for step in plan.value["steps"]:
        planner.act(step["tool"], step["args"], decision=plan)

SYSTEM = System(program,
                models={"claude": my_model_fn},       # fn(context_values, *, purpose, seed, params, agent)
                tools={"lookup_order": lookup_order, "send_email": send_email},
                task="Resolve ticket #881",
                name="myapp.agents:SYSTEM",           # importable, so replay can re-run it
                sensitive_tools=("send_email", "issue_refund"))

SYSTEM.run(seed=0, out_dir="runs")
```

| Call | Records |
|---|---|
| `agent.observe(value, source=, trust=)` | an input (file, page, email, user message) |
| `agent.decide(context, model=, purpose=)` | a model call: exactly this context, its output, latency, usage |
| `agent.act(tool, args, decision=)` | a tool call linked to the decision that asked for it |
| `agent.send(to, content)` / `agent.inbox()` | agent-to-agent messages |
| `agent.record_decision(...)`, `agent.record_action(...)` | calls your own code already made |

A model function may return `tracekit.why.core.ModelOutput(value, usage={...})` to record tokens.
[examples/why/quickstart.py](../examples/why/quickstart.py) is a complete example with a test at the end.

### 2. Wrap the Anthropic SDK

`pip install 'tracekit-ai[why-anthropic]'`, then:

```python
from anthropic import Anthropic
from tracekit.why import Runtime
from tracekit.why.adapters.anthropic import TracedMessages

rt = Runtime({}, out_dir="runs", task="Answer the customer", sensitive_tools=("send_email",))
msgs = TracedMessages(Anthropic().messages, rt.agent("support"), untrusted_tools={"fetch_page"})

resp = msgs.create(model=MODEL, max_tokens=800, system=..., tools=..., messages=history)
for block in resp.content:
    if block.type == "tool_use":
        result = run_tool(block.name, block.input)
        msgs.tool_result(block.id, result)       # links the tool call to this model call
rt.finish()
```

Every system prompt, message block and tool result in each request becomes a context item. Results of tools in
`untrusted_tools` are marked untrusted. See [examples/why/anthropic_agent.py](../examples/why/anthropic_agent.py)
(`TRACEKIT_WHY_MODEL` names the model). The adapter's tests run against a fake client that mimics the SDK's response
objects.

### 3. Ship events from another process

```python
from tracekit.why.core import HttpSink
SYSTEM.run(seed=0, sink=HttpSink("http://collector:7778", token))   # tracekit view's port; why serve: 7788
```

`HttpSink` posts to a `tracekit view --why` collector's `/v1/ingest` after every tool call, so the collector sees the
run live. See [examples/why/remote_agent.py](../examples/why/remote_agent.py).

## How causality is tested

**Run replay** (`tracekit why test RUN --system module:ATTR --remove SPEC --target SPEC`):

1. Load the program: `--system`, or the one the run names (`System.name`) when `--allow-program` lists it. A run file
   is data, so the CLI never imports the module it names on its own say-so.
2. For each of N trials, run it twice with the same seed: once as is, once with the intervention. The intervention
   removes matching items from every model call's context and records what it removed.
3. Tool calls identical to recorded ones get the recorded result. Calls the original never made are **stubbed**, so a
   replay does not send a real email or move real money. That holds for tools run through `act()` or the Anthropic
   adapter's `run_tool`; a tool your own code runs and records with `record_action` (or the adapter's `tool_result`)
   runs for real in a replay too, with a warning, and counts in `off_tape_actions`.
4. Report how often the target happened in each arm, the difference, and a 95% interval (Newcombe's interval for two
   proportions, which a verifier recomputes for signed findings; it ignores the pairing, so it is conservative; a
   decision replay uses Tango's paired interval). `off_tape_actions` counts the calls of both arms the tape
   did not serve; `p_value` (exact McNemar) is corrected for the looks and for `family`, as the interval is.

| Verdict | Meaning |
|---|---|
| `causal` | the interval is above zero: removing it makes the target less likely |
| `suppressive` | the interval is below zero: removing it makes the target more likely |
| `ruled-out` | the interval shows any effect is smaller than 20 points (`min_effect`) |
| `inconclusive` | the interval is too wide to say either way; the result gives how often the target reproduced and a suggested `n` |
| `not-applied` | the spec matched nothing |

A test never says `ruled-out` only because its interval includes zero: [−0.19, +0.40] includes zero and also a
40-point effect, so it is `inconclusive`.

**Sequential testing** (`--n-max`). A real model repeats a harmful action in only some replays, and a fixed small `n`
then cannot decide. With `--n 10 --n-max 160` the test runs 10 pairs, checks, and doubles until the verdict is
decisive or it reaches 160. The interval is widened for the number of checks (Bonferroni), so stopping early does not
add false positives. On an agent that follows an injection in 25% of runs, 10 fixed trials find the cause 13% of the
time; sequential testing finds it every time, using 38 trials on average. Across 200 tests of an input with no effect
it called 5.5% causal. The viewer's **RUN TEST** button uses `--n 20 --n-max 160`.

**Find the cause** (`tracekit why attribute RUN --system module:ATTR --target SPEC`, or FIND THE CAUSE in the viewer) runs the investigation for one
action:

1. Remove every untrusted input upstream of the action at once. If the action still happens about as often, none of
   them is the reason: the agent does this on its own, or for a reason that was not recorded. One test answers that.
2. Otherwise narrow down: test the suspects one by one (with more than four, halve the group).
3. Classify each cause from its interval. A **primary cause** explains at least half of the occurrences; a
   **contributing factor** explains less than half; a **confirmed cause** is causal with its share not yet clear. When
   the group matters but no single input does, each is enough on its own: they are reported as **joint (redundant)
   causes**.

All tests share one "nothing removed" arm, and every interval is corrected for all the tests the attribution may run.
On the simulated benchmark this needs 6–20% fewer model calls than testing each input separately, and one test instead
of one per input when no input is the cause. `--no-roles` skips sizing each cause's share; `--workers N` runs replays
in parallel.

**Decision replay** (`tracekit why test RUN --decision SEQ --remove SPEC [--contains TEXT]`) re-calls one recorded model
call with and without one context item, from the log alone. Use it when the whole system cannot be re-run, or to find
the model call an effect enters at. `--anthropic` re-sends a call recorded by the Anthropic adapter (needs
`ANTHROPIC_API_KEY`). Real models ignore seeds, so decision tests compare against a no-removal control call.

**LangGraph fork replay (rung 3)** (`tracekit why attribute --langgraph module:graph_factory --thread T --target
SPEC`, or `tracekit.why.langgraph.fork_replay` / `attribute_thread` in Python) tests a LangGraph agent without a
`System`. The factory takes no arguments and returns the compiled graph over the app's own checkpointer, so the
thread's checkpoints are there; `--langgraph` imports and calls it, so name only code you trust (as with `--system`
and `--allow-program`). For each trial:

1. Fork the checkpoint at which the suspect entered the state (found by its tool_call_id or message id), with
   `update_state(..., as_node=<the node that added it>)`: once as recorded, once with the suspect removed. A removed
   tool result is replaced by a placeholder, since model APIs reject a tool call left without its result; any other
   message is removed with `RemoveMessage`. `--checkpoint ID` starts from an earlier checkpoint than the latest.
2. Run only what comes after (`invoke(None, fork)`). The prefix is the recorded run itself, not a re-execution: this
   is a counterfactual on the run that happened.
3. Every call of a ToolNode that is a node of the graph (also inside `.with_fallbacks()`), or of a subgraph added as a
   node, is served from the thread's own recorded `ToolMessage` (same tool, same canonical arguments, in order;
   content, status and artifact) or a stub (`off_tape_actions`); a removed tool result is blanked only at its own
   occurrence. Those ToolNodes run no tool and the signer sees nothing. A tool called any other way would run: a
   branch with a tool result that was not served stops with an error. A call a node of the app answers itself (a
   routing schema such as `ToFlightBookingAssistant` or `CompleteOrEscalate`) stops it too unless you name it:
   `--routing CompleteOrEscalate` (repeatable), `routing=[...]` in Python. Such a result is the app's own message, and
   is not a suspect by default. A model node that wants paired seeds reads `config["configurable"]["tracekit_seed"]`.
4. Score the target on the branch's tool calls, with the same verdicts, intervals and attribution as above. Results
   carry `rung: 3` and the fork point, and each test is appended to the why log at
   `runs/langgraph-<thread>/tests.jsonl` (`--out DIR`; `log=` in Python, where nothing is written without it).

Each branch runs on its own copy of the graph and its ToolNodes, so the app's graph object, and other threads invoked
on it meanwhile, are untouched. Branch nodes see a fresh in-memory checkpointer holding only the fork point under a new
`thread_id`, an empty scratch store if the graph has one, and no node cache; nothing is written to the thread, the
store or the cache. Default suspects: every tool result before the first matching tool call. `--suspect` takes a
tool_call_id or message id. `examples/v2/langchain/injection.py` records a thread whose fetched page carries a planted
instruction and finds it as the primary cause while ruling out the benign weather lookup.

Intervention specs: `input:<glob>`, `msg:<from>-><to>`, `result:<tool>`, `ref:<hash>`, `untrusted`.
Target specs: comma-separated `tool=`, `agent=`, `arg~` (substring of the arguments), `result~`.

## Evidence grades

Every edge in the graph says how it was established.

| Grade | Meaning | Example |
|---|---|---|
| **observed** | recorded at the time | X was in D's context; D asked for A; identical content reappeared (a file side channel, caught by hashing) |
| **inferred** | a heuristic | text from X shows up in Y with no recorded path between them (word 5-gram overlap) |
| **tested** | measured by intervention | removing X in N paired replays changed P(target) |

Tracing (`tracekit why taint`, "blast radius") follows observed edges and answers what an input could have influenced.
Only tested edges answer what it did influence.

## Alerts

| Severity | When |
|---|---|
| **high** | a sensitive tool used an argument value that appears only in untrusted content, or the log fails verification |
| **review** | a sensitive tool is downstream of untrusted input (reach only), or a tool or model call failed |
| **info** | a tool call was stubbed during replay |

Sensitive tools are the ones a run declares. If it declares none, tool names such as send, pay, delete or export are
treated as sensitive and labelled "by name". A tool result is untrusted when it was recorded so
(`untrusted_tools=[...]`, `act(..., untrusted=True)`, or an adapter), or when the action itself is marked untrusted,
such as a subagent's answer after it read untrusted content. A whole string argument of 6+ characters that appears
verbatim in untrusted content counts as coming from it, so short, generic argument strings can produce false positives.

## Live mode and the guard

Recording is live: each event is appended as it happens.

**The guard** checks sensitive tool calls before they run, with the high-alert rule above. It is a **tripwire, not a
defense**: it catches injected values that reach a tool verbatim, and misses a model that paraphrases or re-encodes the
value. For prevention use an information-flow-control system and use `tracekit why` to investigate what got through.

```python
from tracekit.why import Guard, Runtime
from tracekit.why.guard import webhook

guard = Guard("block", on_alert=webhook("https://hooks.example/alerts"))   # or "alert" (the default)
rt = Runtime(models, tools, sensitive_tools=["send_email"], untrusted_tools=["web_fetch"], guard=guard)
```

In `block` mode a sensitive call that would use a value only untrusted content supplied does not run; the agent gets
`{"error": "blocked by tracekit why guard: ..."}` back and the action is recorded with `status: "blocked"` and the
verdict. In `alert` mode the call runs and the verdict is recorded. `on_alert` receives high alerts. Rules are
functions of a `CheckContext`:

```python
def no_large_wires(ctx):
    if ctx.tool == "wire" and ctx.args.get("amount", 0) > 1000:
        return {"title": "wire over 1000"}
Guard("block", rules=[no_large_wires])
```

With the Anthropic adapter, `msgs.run_tool(block, fn)` checks, runs, records and returns the `tool_result` block.
`tracekit why record module:SYSTEM --guard block` runs a System under the guard. Replays never use the guard. The guard
sees only what the log has recorded so far.

**The page updates as runs are recorded.** `tracekit view --why` watches the runs folder
(and anything ingested), recomputes alerts for each run that changes and pushes them over the viewer's `/api/stream`. `--webhook URL` also POSTs each new
high alert (Slack-compatible JSON): its rule, title and run, never the call's arguments, with `<`, `>` and `&`
escaped so it cannot mention anyone; at most 100 wait to be sent. `tracekit why watch ROOT` prints new alerts in the terminal. To try it:

```bash
tracekit view --why runs-live                        # terminal 1: open the URL it prints
python examples/why/live_demo.py runs-live block      # terminal 2
```

## Importing a v1 ledger

```bash
tracekit why import --v1 ~/.tracekit --list
tracekit why import --v1 ~/.tracekit --run <session> --out runs --sensitive send_email
```

| v1 record | why event |
|---|---|
| `user.prompt` | task input (trusted) |
| `model.exchange` request + response | model call; context rebuilt block by block from the recorded request (`exact`), or from what the agent had seen so far when the request was hashed (`reconstructed`) |
| `tool.call` + `tool.result` | tool call, linked to the model call that asked for it |
| results of untrusted tools (default: all but subagents; `--untrusted-tool` / `--trusted-tool`) | untrusted input `tool:<name>` |
| subagent spawn and answer | messages parent → child and child → parent |
| policy deny, or ask not approved | tool call with status `blocked` and the rule ids |
| policy flag / ask | sensitive tool call |
| `capture.gap`, `trace.tamper`, failed signatures | high alerts: the evidence is incomplete |

The import checks the ledger's chain and signatures (`signer.pub` next to the ledger) and records the result in the
run; `tracekit-map.json` maps each why event to the signed records (seq, hash) it came from, and the run's data carries
them per event. Values can be traced only with `content_capture: full` (at least for untrusted tools); with
hashed content provenance says the content was hashed instead of guessing. Model calls appear only when they were
recorded (autotrace, the SDK or the model proxy).

## With the signer

One run is then both signed evidence and a causal log with content, and every causal claim cites signed records.

```bash
tracekit demo --why     # the support desk on the signer: a held email, its cause, a verified bundle; exit 0
```

**The runtime.** Give `Runtime` (or `System.run`) a Tracekit client, `signer=Client()`, or set `TRACEKIT_SIGNER`
(the SDK's own resolution, system mode included; `signer=False` turns it off). Each agent gets its own Tracekit run,
with the task observed in it as trusted, and every event also goes to the signer:

| why event | signer |
|---|---|
| `observe()` | `observe` with its source and trust |
| message to an agent | `observe` in the recipient's run, source `msg:<from>-><to> run:<sender's run id>`, with the message's trust: the only link between the agents' runs the signer records (`agent(parent=)` is in the why log only) |
| model call | `model_event`: the request with the `content_digest` of the exact context, the response (at `finish()`) with the tool calls it led to and their args digests; `record_models=False` when a gateway records them |
| `act()` | `decide`; on `ask` an approval request and a wait of up to `approval_wait_s` (300 s); `approval_consume`; the tool runs; `complete` (a stub, no tool registered, as the error "not run: no tool registered"; a result the signer refuses, not JSON or over its quota, as the error "result not recordable: ...") |
| `act(untrusted=True)` | also `observe` of the result as untrusted, so the signer's provenance has it whatever its policy says of the tool; when the policy treats the tool's results as untrusted too, the value is indexed twice and a provenance entry may cite either record |

A deny comes back to the agent as `{"error": "blocked by policy: <rule ids>"}` with status `blocked`; an `ask` nobody
answers in time is blocked the same way and names its approval. The call stays held: when the agent retries it in the
same run with the same tool and arguments, the retry reuses its tool call id and approval, so an approval given
meanwhile lets it run (and a rejection blocks it). `finish()` abandons the approvals still held. A signer that cannot be reached blocks the call (fail
closed). With a signer the guard is not asked: the signer is the gate. Each event stores the record it produced as
`tracekit: {run_id, run_seq, type}`, shown in the app's event details. Replays (`test`, `attribute`, `replay`) never
talk to the signer: they must not write evidence.

**Import.** `tracekit why import --store DIR` reads a signer data dir (read-only, like `tracekit view --data-dir`);
`--bundle FILE.tkb --trust trust.json` verifies the bundle first and refuses one that does not verify. Each v2 run
becomes a why run `tk-<run id>-<hash>` (the hash covers the tenant and the whole run id, so two runs never share a
folder; the readable run id and tenant are in its `run.start` meta):

| v2 record | why event |
|---|---|
| `input.observed` | input with its source and trust; content "content committed, not in the log" |
| `model.exchange` | model call over what the run had observed so far (`reconstructed`) |
| `policy.decision` + `tool.result` | tool call with the decision, rule ids and reasons; results committed, not in the log |
| `policy.decision` without a result | tool call `blocked` (a deny, or an ask nobody approved), with the approval and who answered it; a call allowed or approved that has no result is an `error` "the signer recorded no outcome: the call may have run" (the signer was unreachable when it ended) |
| decision `provenance` | an observed edge from the record that brought the value to the call ("argument to (email), untrusted") |
| `capture.gap`, `trace.tamper` | high evidence alerts |

Every event cites its record (`tracekit`: log_id, seq, run_id, run_seq, the record hash and its commitment). When a why
log under `--out` cites the imported runs (the runtime wrote it), the two are merged into `tk-<why run id>`: content
from the why log, citations, verdicts and provenance from the signed records. An executed call cites its result and,
under `decision`, the decision it ran under (its arguments' commitment). These are high evidence alerts, and the event
is marked `tracekit_mismatch`: a citation that does not match its record (another type, tool, trust, source, outcome,
hash or decision), one of another agent's run, a record cited twice (a held call retried cites its decision each time),
an agent start, input, model call, tool call or message that cites nothing; so are a record of a cited run (decision,
result, observed input, model call) that no event cites and a why log whose own chain is broken. An earlier import
under `--out` that cites the same runs is checked the same way, not taken on its word; the import refuses (exit 2,
nothing written) when a run it would write exists.

**Content against commitments.** The signer commits to content without keeping it. With the salts of the records a
case cites (`tracekit signer reveal --record SEQ`, one JSON line per record),

```bash
tracekit why verify runs/tk-desk --salts salts.jsonl
```

recomputes each cited blob's digest (an executed call's arguments too, against its decision) and checks it against
the record's commitment: `matched`, `mismatched` (the content or the salt does not match), `not revealed`, or `bad salt
row` (a row for another type of record). A mismatch exits 1 and is a high evidence alert in the app; a bad salt row, or
a salts file that is not `tracekit signer reveal` lines, exits 2. Limits:
[limits.md](limits.md#investigation-tracekit-why).

## Attribution on signed runs

A run the signer and the [gateway](gateway.md) recorded, with the signer's [content vault](privacy.md#the-content-vault)
on, can be tested without its code: the vault holds each model call's request and response and each tool call's
arguments and result.

```bash
export TRACEKIT_SIGNER=https://signer.internal:8443        # the investigator's identity, as for any client
tracekit why test --run R --store /var/lib/tracekit-signer --gateway https://gateway.internal:8080 \
    --gateway-token-file investigator.token --remove input:web:* --target "tool=send_email,arg~evil.example"
tracekit why attribute --run R --bundle r.tkb --trust trust.json --gateway https://gateway.internal:8080 \
    --target "tool=send_email" --max-calls 400
```

The ladder: what each rung can say, and what it needs.

| Rung | What it does | Evidence | Needs |
|---|---|---|---|
| 0 | observed: signed provenance (a value only untrusted content brought); predicted: the surrogate's ranking | never "tested" | the records; the ranking also the vault and the gateway |
| 1 | decision replay: one recorded model call re-sent with the item removed, against the same call re-sent unchanged | tested, for that call | the call's request in the vault, the gateway |
| 2 | agentless run replay: from the first call holding the item, the loop re-simulated: each tool use answered from the run's tape when tool and canonical arguments match exactly, else the stub `{"error": "not in the recorded run"}` (counted in `off_tape_actions`); the model called again until it stops or the recorded number of turns + 2 | tested, for the run | rung 1's, and the tools' results in the vault |
| 3 | program replay (`tracekit why test RUN` with a System) | tested, for the program | a re-executable program |

`--decision SEQ` (the run_seq of the call's request record) picks rung 1; without it `test` uses rung 2; `--rung`
overrides. Only executed replays are tested evidence: step-level credit signals don't match what an executed replay
shows, so the surrogate only orders what to test.

- **Loading.** The run's records come from `--store` or a verified `--bundle`; their content from the signer
  (`content_get`, purpose: the investigation id, `--investigation` or a new one; each read is a signed
  `content.accessed`). Each record's content is checked against its commitment with the salt the signer returns; a
  mismatch stops the investigation with a high evidence alert (exit 1). Content changed by redaction comes back without
  a salt and is used unchecked.
- **Interventions** name blocks of the recorded request body (Anthropic messages, OpenAI chat completions and
  responses): `input:<source glob>` blocks holding a value the run observed from that source (an address, a URL or a
  whole string of 6+ characters, verbatim), `result:<tool glob>` tool results, `msg:<index>` one message,
  `ref:<hash prefix>` one block by content hash. A removed block keeps its place, its content replaced by
  `[removed by tracekit why]`, so the request stays valid.
- **Targets**: `tool=NAME` and `arg~TEXT` (one tool use matching every such clause), `text~TEXT` (the response text).
  Rung 2 scores the whole continuation.
- **Through the gateway, as evidence.** Each arm is a replay run registered with `replay_of: R` and the investigation
  id, by an investigator listed in signer.yaml `analyzers` (with the `content_read` grant); its model calls go through
  the gateway (`--gateway`, authenticated as the same identity: `--gateway-token-file`, or `--gateway-cert`/`--gateway-key`),
  so they are signed records. After each call the investigator reads the replay run back: a call the gateway did not
  record (a fail-open gateway that could not reach the signer) stops the investigation. Requests are sent with
  `stream: false`, and to OpenAI with `store: false`. A replay run is not reconciled (no `reconcile.*` records, no
  coverage in its `run.final`): it has model exchanges and, by design, no decisions.
- **When tools run.** Tools the client runs (function and custom tools, and in rung 2 every tool use the model makes)
  never run: their results come from the tape or the stub. A tool the provider runs itself would run again on every
  arm, so a call whose request enables one is refused before anything is sent, naming it: OpenAI Responses tools other
  than function and custom (hosted MCP, web search, file search, code interpreter, computer use, ...), Anthropic typed
  server tools (web search, web fetch, code execution, ...), `mcp_servers` and `container`, chat completions'
  `web_search_options`, or a recorded response in which the provider ran a tool. So is a Responses call that continues
  context the provider holds (`previous_response_id`, `conversation`), which a removal can't reach. Test such a run on a
  call without them (`--decision`), or record runs without provider-executed tools.
- **Tests** are paired and sequential with the same intervals, corrections and verdicts as above (`--n`, `--n-max` up
  to 1024, `--workers N` arms in parallel, 1 to 16). Every result reports `off_tape_actions` and its assumptions: no
  code between the model calls rewrote the history, and tools are deterministic. A removed tool output keeps its
  shape: a screenshot becomes a blank image, content parts one text part.
- **Budgets** per investigation, counted in the `tracekit why` process (two processes with the same `--investigation`
  each have their own): `--max-calls` model calls, `--max-cost` estimated cost (with `--prices`, the
  [price table](../tracekit/usage.py) `tracekit cost` reads). Before each call the costliest call so far (recorded or
  replayed) is reserved, and the call is sent only while spent + reserved stays within `--max-cost`; a call overshoots
  only by what it costs past that estimate. A test that reaches a budget stops `inconclusive` with `stopped: budget`,
  reporting the looks it finished. One reached while ranking, before any test finished, ends `attribute` with
  `inconclusive (budget)` (exit 2).
- **Find the cause** (`attribute`) without `--suspect`: a ContextCite-style surrogate re-sends the target's call with
  32 random halves of its blocks removed, scores each response (the target's log-probability when every response
  carries it, which only OpenAI chat calls can: they are sent with `logprobs: true`; else whether it hit), fits a
  sparse linear model and ranks the blocks, labelled `predicted`. The four top-ranked blocks with a positive weight
  become the suspects of the group-then-narrow search.
- **Signed findings.** Each finished test is written by the investigator through the signer as a `why.finding` record
  (target, intervention, n, the rates, effect, interval, verdict and what it was decided on: `looks`, `family`,
  `min_effect`, `applied`, `stopped`; every replay run with its arm and outcome; models, rung, off-tape actions,
  investigation; and `uncounted`: the replay runs of the investigation it doesn't count, the ranking's calls and the
  arms a budget stop abandoned) in a findings run (`analyzes: R`) of the run's tenant.
  `tracekit export --v2 --run R --with-findings` bundles the run with its findings and replay runs. The verifier checks
  that each finding's replay runs are in the bundle, are replay runs of R in that investigation, each holds its model
  calls as gateway records (exactly one for rung 1 and the ranking), and count to its rates; recomputes the interval
  and verdict from those outcomes; for a `tool=` target, checks each outcome against the tool uses the gateway recorded
  (a hit needs one; a miss must have none when the target is `tool` clauses alone); and fails a replay run of an
  investigation with findings that no finding counts or lists. Replay runs of an investigation with no finding are a
  warning. What stays the investigator's claim: outcomes scored on `text~` and `arg~` clauses, `applied`, and why a
  run is `uncounted`.

For the viewer and other tools: `tracekit.why.signed.Investigation(records, client, gateway)`, then
`counterfactual_signed`, `attribute_signed` and `rank`. Limits:
[limits.md](limits.md#investigation-tracekit-why).

## Server and API

```bash
tracekit view --why runs --allow-program myapp.agents:SYSTEM
```

| Method | Path | Purpose |
|---|---|---|
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | the viewer's page |
| GET | `/api/why/workspace` | run summaries, the influence graph, every run's alerts and the signed calls each why event cites |
| GET | `/api/why/runs/<id>` | one run's investigation data, and whether this server may replay it |
| GET | `/api/stream` | the viewer's server-sent events: each run's events as tape rows, and `why` records (a run changed, with its new alerts; a test finished) |
| POST | `/api/why/runs/<id>/tests` | `{"intervention", "target", "n", "n_max"}`: a replay test |
| POST | `/api/why/runs/<id>/attribute` | `{"target", "n", "n_max"}`: Find the cause |
| POST | `/v1/ingest` | `{"events": [...], "blobs": {ref: value}}`: receive events |

The server is the viewer's ([viewer.md](viewer.md#why)), with its security checklist. Every request needs the token:
`--token`, else `$TRACEKIT_WHY_TOKEN`, else a random one printed in the URL. The page exchanges the URL's `?token=`
once for an HttpOnly, SameSite=Strict cookie; the API also takes the token as `Authorization: Bearer`, and
`/v1/ingest` takes only that, unless `--ingest-token` (repeatable) is given: then `/v1/ingest` takes only those
tokens, and they read nothing. A run belongs to the token whose batch created it: only that token may append to it,
and nothing may follow its `run.end`; a run written to the folder by a local Runtime is never appended to. Requests addressed to a Host other than loopback or the bound address need the token (DNS
rebinding); POSTs need the bearer token or an expected Host. The replay POSTs need a JSON body and a same-origin
`Origin`, if any, and run only the programs passed with `--allow-program`.
The server binds to 127.0.0.1; beyond loopback it needs `--tls-cert` and `--tls-key`, or `--insecure-http` when TLS is
terminated in front. Connections are bounded overall and per client address, with read timeouts and deadlines.

Before writing anything, ingest checks the token, every blob's hash, that each event's `seq` and `prev_hash` continue
the stored chain, each event's hash, its common fields (`id`, `agent`, `ts`, `type`, `seq`), the fields each event
type needs and their types (refs are `sha256:` hashes, token counts integers >= 0), that its id is new in the run, and
that every referenced blob exists and every blob sent is referenced. Edits, gaps, forks, forged blobs, duplicate ids
and replayed batches are refused (401, 403, 409, 422); a body nested deeper than 64 levels is a 400. A 409 names the
run's head (`{"head": {"seq", "hash"}}`): `HttpSink` drops the events up to it as delivered when it holds that event,
so a batch the server committed before the client's timeout is not resent forever. Ingest answers once the batch is
appended; the watcher analyses the run (once per change, however many batches made it). A run on disk that cannot be
analysed is listed as broken rather than dropped or breaking the workspace. Replay imports the Python program a run names, so it is allowed only for programs listed
with `--allow-program`. The server is in the [HTTP security checklist](security-checklist.md).

## Command reference

| Command | What it does |
|---|---|
| `tracekit why demo [--out DIR] [--n N]` | record the demo, run tests, write `DIR/report.html` |
| `tracekit why report ROOT [-o FILE]` | the viewer's page with every run under ROOT (or the run ROOT) embedded: a static file, no server (default `ROOT/report.html`) |
| `tracekit why record module:SYSTEM [--out DIR] [--seed S] [--guard off\|alert\|block] [--webhook URL]` | record one run of a System |
| `tracekit view --why ROOT [--host] [--port] [--ingest-token T] [--allow-program SPEC] [--webhook URL] [--tls-cert --tls-key \| --insecure-http]` | the viewer on ROOT's why logs: page, API, ingest and live updates (token: `$TRACEKIT_VIEW_TOKEN`, else printed) |
| `tracekit why serve ROOT [--token] [...]` | the same, under its old name (port 7788, token `--token` or `$TRACEKIT_WHY_TOKEN`) |
| `tracekit why watch ROOT [--webhook URL]` | print new alerts as runs are recorded |
| `tracekit why import --v1 SRC [--run R] [--out DIR] [--sensitive TOOL] [--list]` | import runs from a v1 ledger |
| `tracekit why import --store DIR \| --bundle FILE --trust FILE [--run R] [--out DIR] [--list]` | import runs from the v2 signer, merged with the why log that cites them |
| `tracekit why verify RUN [--salts FILE]` | check the chain, seq, unique event ids, event hashes, blob hashes, the closing `run.end` and the chain of `tests.jsonl`, and with `--salts` content against commitments; exit 1 when either fails |
| `tracekit why taint RUN [--source SPEC] [--inferred] [--json]` | blast radius with paths |
| `tracekit why test RUN --system S --remove SPEC --target SPEC [--n N] [--n-max N] [--live-tools]` | run replay test |
| `tracekit why test RUN --decision SEQ --remove SPEC [--system S] [--contains TEXT] [--anthropic]` | decision replay test |
| `tracekit why attribute RUN --system S --target SPEC [--suspect SPEC] [--n N] [--n-max N] [--workers N] [--no-roles]` | Find the cause |
| `tracekit why test --run R (--store DIR \| --bundle FILE --trust FILE) --gateway URL --remove SPEC --target SPEC [--decision SEQ] [--rung 1\|2] [--max-calls N] [--max-cost X --prices FILE]` | test a signed run (rung 1 or 2), signed as a finding |
| `tracekit why attribute --run R (--store DIR \| --bundle FILE --trust FILE) --gateway URL --target SPEC [--suspect SPEC] [--decision SEQ]` | Find the cause on a signed run, the surrogate's ranking first |
| `tracekit why attribute --langgraph MODULE:FACTORY --thread T --target SPEC [--checkpoint ID] [--suspect ID] [--out DIR]` | Find the cause in a LangGraph thread by forking its checkpoints |
| `tracekit why matrix RUN --system S --target SPEC [--n N]` | test every channel and input against targets |
| `tracekit why replay RUN --system S [--remove SPEC]` | re-run from tape and diff against the original |

`--system S` (`module:ATTR`) is the program a replay runs; `--allow-program S` instead runs the program the run names
when it is `S`. Without either, a replaying command exits and imports nothing.
| `tracekit why graph RUN [--json] [--no-infer]` | edges with evidence grades |
| `tracekit why index ROOT [--target SPEC]` | cross-run influence index |

## Limits

All of Tracekit's limits: [limits.md](limits.md).

- An effect is a total effect for this program on this task. It does not explain the model's internal reasons and may
  not transfer to other tasks.
- `ruled-out` means smaller than 20 points, not zero. At n = 40 the demo's intervals are about ±18 points.
- Each test reports an exact paired p-value; `family=k` corrects the interval when k inputs of one action are tested
  together (attribution and the benchmark do). The viewer's **RUN TEST** button tests one input at a time without that
  correction, so testing many inputs one by one there can produce a chance `causal` (about 1 in 20 per input with no
  effect).
- The graph is only as complete as the recorded context: content sent to a model without being recorded is missing.
- Replay costs model calls: about 2·n per test per downstream model call. Program replay has no budgets; replays of
  signed runs take `--max-calls` and `--max-cost`.
- Run replay needs a re-executable program; decision replay does not.
- Tape matching is exact on tool arguments. New calls are stubbed, which can change behaviour after the stub; results
  report `off_tape_actions`.
- LangGraph fork replay serves tools only through a `ToolNode` that is a node of the graph or of a subgraph added as a
  node (also inside `.with_fallbacks()`): a graph without one is refused, and a tool called any other way (inside a
  function or model node, say) runs for real; the branch then stops with an error, after the fact, unless `routing`
  names the call (keep it to routing schemas). It removes messages only: a suspect whose step also
  wrote another state key, or a thread whose tools return `Command` updates, is refused. Async-only nodes and async
  checkpointers are refused. Branches see an empty scratch store. All tests of one attribution fork where the
  earliest suspect entered; a later suspect that is not a tool result cannot be removed in that branch and is refused.
- Inferred edges are heuristic and miss paraphrase.
- The guard is a string-matching tripwire; it inherits the provenance alert's false positives and misses re-encoded
  values.
- The why log is hash-chained but not signed, and the server's runs are plain files. `verify` reports a log with no
  `run.end` (cut short, or still running) and each test result `tests.jsonl`'s chain does not cover (the viewer marks
  them UNCHAINED or FAILED CHECK); whoever can rewrite the files can still rebuild both chains.
- The demo models are seeded mock policies: the demo shows the method works, not how a real model behaves.

## Benchmark

[eval/why_bench](../eval/why_bench/README.md) measures whether attribution names the input that actually caused a
harmful action, against three things possible without replay: **reach** (blame every untrusted input upstream),
**provenance** (blame inputs that are the only untrusted source of an argument value) and **reuse** (blame the input
whose wording was reused most). Five scenarios have one planted cause each, plus a clean control.

```bash
python -m eval.why_bench                                                   # simulated model, seconds
python -m eval.why_bench --model openai --openai-model qwen2.5:7b --runs 4 --n 10 --yes   # local model through Ollama
```

Results on Qwen 2.5 7B through Ollama on a laptop (2026-10-09; [details](../eval/why_bench/README.md#results-a-real-model-qwen-25-7b-local)):

| | Harmful runs attributed | Named exactly the true cause | False blames |
|---|---|---|---|
| Scenarios where a ground-truth check confirms the planted document drives the harm | 6 | 6 | 0 |
| `refund-override` (the model refunds 92% of the time with or without it) | 3 | 1, plus 2 inconclusive | 0 |
| reach | 9 | 0 (always blames every untrusted input) | – |
| provenance | 9 | 6, abstains on the other 3 | 0 |

Each attribution cost 320–540 model calls. One 7B model and nine harmful runs are a small sample. On the simulated
model the pipeline names the true cause in all 61 harmful runs with no false blames
([results](../eval/why_bench/results/sim-2026-10-05.md)); that checks the machinery, not a model.
