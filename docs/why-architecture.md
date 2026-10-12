# tracekit why: architecture

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

The formats and algorithms of [`tracekit why`](why.md), in enough detail to reimplement them or to audit what a result
means. [why.md](why.md) covers how to use them. The code is `tracekit/why/`.

- [Run layout on disk](#run-layout-on-disk)
- [Hashing](#hashing)
- [Event schema](#event-schema-tracekitwhyeventv1)
- [The graph and its evidence grades](#the-graph-and-its-evidence-grades)
- [Argument provenance and alerts](#argument-provenance-and-alerts)
- [Run replay](#run-replay)
- [Decision replay](#decision-replay)
- [Statistics](#statistics)
- [Server and ingestion](#server-and-ingestion)
- [Cross-run influence graph](#cross-run-influence-graph)
- [Live guard](#live-guard)
- [Live server](#live-server)
- [v1 ledger import](#v1-ledger-import)

## Run layout on disk

```
runs/
  demo-seed0/
    events.jsonl          one event per line, hash-chained, append-only
    blobs/<sha256>.json   every value, stored once: {"v": <value>}
    tests.jsonl           results of counterfactual tests run against this run (optional), chained
    ingest-owner          for a run created by ingest: the digest of the ingest token that may append to it
```

Storage is plain files. Every reader goes through `tracekit.why.core.load_run`, so swapping in a database means replacing that function and `Runtime._emit` / `Runtime._blob`.

## Hashing

| What | How |
|---|---|
| Canonical JSON | `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` |
| Blob ref | `"sha256:" + sha256(canonical({"v": value}))` |
| Event hash | `sha256(canonical(event without the "hash" key))`, hex |
| Chain | `event.prev_hash` = previous event's `hash`; 64 zeros for seq 0 |

Wrapping the value in `{"v": ...}` gives strings, numbers and objects one hashing rule. Because the event hash covers `prev_hash`, editing, deleting, inserting or reordering any event breaks every later link. `tracekit why verify` checks contiguous `seq`, every link, unique event ids, every event hash, every blob hash, that every ref an event mentions exists, and that the log ends with `run.end` (a log cut short loses its end: verify reports it, as it does for a run still recording). Each line of `tests.jsonl` carries `prev` (the previous line's `hash`, 64 zeros for the first), `head` (the hash of the run's last event when it was tested) and `hash` (`sha256(canonical(line without "hash"))`); verify reports a line that does not link, and the viewer marks a line without them UNCHAINED.

The chains are unsigned. Anyone who can rewrite the files can rebuild consistent chains, a closing `run.end` included.
Tracekit's signer solves that for the records it signs; the why log's own head is not recorded there yet.

## Event schema (`tracekit.why.event.v1`)

Every event has these fields:

| Field | Meaning |
|---|---|
| `schema` | `"tracekit.why.event.v1"` |
| `seq` | 0, 1, 2, … within the run |
| `id` | random 128-bit hex id |
| `prev_hash`, `hash` | the chain |
| `ts` | UTC, microseconds, host clock (order comes from `seq`, not `ts`) |
| `run_id` | the run |
| `agent` | agent name, or `"run"` for run-level events |
| `type` | one of the types below |

Type-specific fields:

| Type | Fields |
|---|---|
| `run.start` | `program` (`module:ATTR` used for replay), `seed`, `interventions` (non-empty only in replays), `models`, `tools`, `sensitive_tools`, `untrusted_tools`, `guard` (mode, or null), `meta` (for imports: `source`, `content_capture`, `signatures`, `evidence_alerts`) |
| `agent.start` | `parent`, `role` |
| `input` | `ref`, `source` (free label such as `web:vendor-notes`), `trust` (`trusted` / `untrusted`), `kind` (`task` or `input`) |
| `decision` | `model`, `purpose`, `params` (adapter calls add `request`: the request layout by content hash), `seed`, `context` (list of `{ref, kind, source, trust, from_event}`), `ablated` (refs removed by an intervention), `output` (ref), `usage`, `status`, `duration_ms`; imports add `context_mode` (`exact` / `reconstructed`) |
| `action` | `tool`, `args_ref`, `result_ref`, `decision` (event id that asked for it, or null), `status` (`ok` / `error` / `blocked`), `mode` (`live` / `tape` / `stub` / `blocked`), `sensitive`, `duration_ms`; optional `guard` (`{verdict, reason, alerts}`), `policy` (Tracekit's `{decision, rule_ids, policy_hash}`), `trust` (`untrusted` when the result carries untrusted content, e.g. a subagent's answer) |
| `message` | `to`, `ref`, `decision`, `trust` |
| `run.end` | `outcome` |

`context[].from_event` is the event that brought that value into the run. It is what turns "this value was in the context" into a precise edge, even when two events produced identical content.

Trust propagates at record time: a decision whose context holds any untrusted item produces an output marked untrusted, and messages and actions inherit it. This is a conservative label for display. The graph and the tests do the actual analysis.

## The graph and its evidence grades

Nodes are `input`, `decision`, `action` and `message` events. Edges:

| Edge kind | Grade | Rule |
|---|---|---|
| `context:<kind>` | observed | item X was in decision D's context (`from_event` → D) |
| `invoked` | observed | decision D asked for action A |
| `sent` | observed | decision D produced the message M |
| `same-content` | observed | an input has the exact hash of something produced earlier in the run, such as a file one agent wrote and another read |
| `content-overlap` | inferred | at least 3 shared word 5-grams and overlap ≥ 0.3 (`|A∩B| / min(|A|,|B|)`), with no observed path already linking the two |
| `causal` | tested | a saved test removed X and the target changed (or did not) |

Observed context edges also carry `reuse`: the share of the input's 5-grams that reappear in the decision's output. It hints at which inputs the model drew on. It is not evidence of cause.

Tested edges carry `effect`, `ci`, `n` and `verdict`. Edges with a CI that includes zero are kept as "ruled out" and are not followed when tracing.

**Taint / blast radius** is forward reachability over observed edges (optionally inferred) from chosen input nodes. It answers "what could this have influenced?", which is a superset of what it did influence.

## Argument provenance and alerts

For each tool call, `analysis.atoms` extracts values worth tracing: email addresses, URLs, and string arguments of 6+ characters. For each value, it searches earlier inputs and tool results for a case-insensitive verbatim match:

| Status | Meaning |
|---|---|
| `untrusted-only` | only untrusted content contained it |
| `trusted` | at least one trusted input or tool result contained it |
| `generated` | nothing earlier contained it; the model wrote it |

A tool result counts as untrusted when its content was also recorded as untrusted input (the Anthropic adapter does this for tools listed in `untrusted_tools`).

Alerts:

| Severity | Condition |
|---|---|
| high | sensitive action with at least one `untrusted-only` argument value; or the log fails verification |
| review | sensitive action downstream of an untrusted input (reach only); failed tool call; failed model call |
| info | tool call stubbed during a replay |

A tool is sensitive when the run declared it (`sensitive_tools`, or `act(..., sensitive=True)`). If a run declares none, names matching send, email, post, publish, transfer, pay, refund, delete, remove, export, upload, exec, shell, bash, write, deploy, sign or approve are treated as sensitive and labelled "by name".

## Run replay

`replay.counterfactual(run, intervention, target, n)`:

1. Load the `System` named in `run.start.program` (or use the one passed in; the CLI and the server never load the named one unless `--allow-program` lists it).
2. Build a **tape** from the original run: a map from `(agent, tool, args hash, occurrence)` to the recorded result.
3. For i in 0..n-1, with seed `s_i` derived from the run id and i:
   - run the program with seed `s_i`, tape on, no intervention → did the target happen?
   - run it again with seed `s_i`, tape on, intervention on → did the target happen?
4. Report `p_with`, `p_without`, `effect = p_with - p_without`, the paired 95% CI, pair flips, how many trials the intervention actually removed something in, and how many tool calls of both arms left the tape.

**Interventions** remove matching items from every decision's context at call time and record what was removed in `ablated`:

| Spec | Matches |
|---|---|
| `input:<glob>` | inputs whose source matches |
| `msg:<from>-><to>` | messages on that channel (globs allowed) |
| `result:<tool glob>` | tool results |
| `ref:<hash prefix>` | a specific content |
| `untrusted` | anything marked untrusted |

**Tape and stubs.** A tool call identical to a recorded one replays the recorded result. A call the original run never made is stubbed (`{"_unrecorded": true}`) unless `live_tools=True`. A replay therefore never repeats a real side effect of a tool run through `Agent.act` or `TracedMessages.run_tool` (which, in a replay, goes through the same tape and stub path and never calls your function). A tool your own code runs and records with `record_action` (or `TracedMessages.tool_result`) has already run when the runtime hears of it: in a replay it runs for real, is recorded as `live`, warns, and counts in `off_tape_actions`. The cost is that behaviour after a stubbed call can differ from what the real tool would have caused, which is why `off_tape_actions` is reported.

**Paired seeds** (common random numbers) mean the only difference within a pair is the intervention, which cuts the variance of the estimated difference considerably.

**Verdicts:** `causal` if the CI lower bound > 0; `suppressive` if the upper bound < 0; `ruled-out` if the whole interval lies within ±`min_effect` (default 0.2); `inconclusive` otherwise, with `n_needed` (the n at which the interval's half-width would reach `min_effect`); `not-applied` if the spec matched nothing in any trial.

What a `causal` verdict means: in this program, on this task, removing X changes how often the target happens. It is a total effect through every path. It says nothing about the model's internal reasons.

## Decision replay

`replay.decision_test(run, decision_seq, intervention, n, contains=None)` uses only the recorded log and the model function:

- rebuild the decision's context from blobs;
- call the model n times with the full context and n times without the matching items, paired seeds;
- with `contains`, measure P(output contains the text) in each arm and report the difference with a paired CI;
- without it, measure how often the output differs from the paired full-context output, minus how often a second full-context call differs (`noise`), with a paired CI on the difference. Real model APIs ignore seeds, so without the control any sampling noise would read as an effect.

This measures the direct effect on one model call. It does not need the program to be re-runnable, which matters for production systems that can't be re-executed end to end. Decisions recorded through the Anthropic adapter store the request layout (which context item sat in which message block), and `adapters.anthropic.replay_model(client.messages)` rebuilds the request without the removed items. A removed tool result becomes `"[removed]"` so tool_use / tool_result pairing still holds.

## Attribution (Find the cause)

`replay.attribute(run, target, suspects=None, n=10, n_max=40)`:

1. Group test: one counterfactual removing every suspect (default: untrusted inputs upstream of the target). Not causal: stop, and report the rate with all suspects removed (`unprompted_rate`).
2. Causal: with 4 or fewer suspects, test each alone; with more, test halves and recurse into causal halves.
3. A causal group with no causal member is a joint cause. For groups of 4 or fewer, a leave-one-in test per member (remove all the others) keeps the members that are enough on their own.

All tests share `base_cache`, the "nothing removed" arm keyed by trial index; with paired seeds, trial i of that arm is the same computation for every intervention. The family for the Bonferroni correction is 1 + (m if m ≤ 4 else 2m − 2) + m, an upper bound on the number of tests. Roles use the interval of the effect divided by `p_with`: lower bound ≥ 0.5 is primary, upper bound < 0.5 is contributing, otherwise unclear. With `size_roles`, a test that has proven causality keeps sampling (up to `n_max`) until its role is clear.

## Statistics

**Sequential tests.** With `n_max > n`, a test checks its interval at n, 2n, 4n, … and n_max (k looks), and stops at the first decisive verdict (causal, suppressive, ruled-out). Each look uses z for α = 0.05 / k (Bonferroni), and the reported McNemar p-value is multiplied by k (and by `family`). The union bound keeps the overall false-positive rate at or below 5% however early the test stops. It is conservative, and simpler than group-sequential boundaries (O'Brien-Fleming) that would spend α more efficiently.

- **Wilson score interval** for a single proportion.
- **Newcombe's hybrid score interval** (method 10) for the difference of the two arms' rates in run tests and signed findings (the verifier recomputes it); conservative for paired arms.
- **Tango's score interval** (1998) for the difference of two paired proportions (`replay.paired_diff`), used by decision replay: every difference whose score test, with the variance at the restricted maximum-likelihood estimate, is not rejected. Only pairs whose arms differ move it, so the pairing reaches the verdict, and with no discordant pair it is as wide as the trials allow (±0.28 at n = 10) instead of falsely certain. It behaves well at 0% and 100%, which plain Wald intervals do not. Checked against Fagerland, Lydersen & Laake (2014), Table I. `replay.newcombe_diff` (Newcombe's hybrid score interval for two independent samples) is kept for unpaired data.

- **Exact McNemar test** on the discordant pairs (target happened only with the item, or only without it). Its p-value is reported as `p_value`. With b discordant pairs all in one direction the smallest possible p is 2 × 0.5^b, so fewer than 6 discordant pairs can never reach p < 0.05.
- **Testing several inputs of one action** (`family=k`): the interval is corrected by Bonferroni across the k inputs (and the looks of a sequential test), so the verdicts for all of an action's suspects together keep a 5% false-positive rate. The benchmark scores this verdict. `replay.benjamini_hochberg` is still available for false-discovery-rate control over p-values.
- **Futility stopping** (sequential tests): after at least 2n pairs, a test whose estimated effect is within 5 points of zero stops. It can only lose power, never add false positives.

Intervals are computed at 95% (z = 1.96). The viewer's verdicts use each test's own interval and are not corrected across tests.

## Server and ingestion

`tracekit why serve ROOT` is the viewer (`tracekit.view.server`, on `tracekit.netserver.Server`) on the why logs under
ROOT: the same page, session, headers and limits ([viewer.md](viewer.md#why)). The event stream and the replay POSTs
lift the connection deadline once their request is read.

| Method | Path | Notes |
|---|---|---|
| GET | `/` | the viewer's page |
| GET | `/api/why/workspace` | run summaries, the cross-run influence graph, every run's alerts, and the signed calls each why event cites (joined only when the signed record is of the same tool) |
| GET | `/api/why/runs/<id>` | everything the page shows for one run |
| POST | `/api/why/runs/<id>/tests` | `{"intervention", "target", "n", "n_max"}` → run replay; only for programs passed with `--allow-program` |
| POST | `/api/why/runs/<id>/attribute` | `{"target", "n", "n_max", "suspects"}` → Find the cause; same allow-list |
| POST | `/v1/ingest` | `Authorization: Bearer <token>`; body `{"events": [...], "blobs": {ref: value}}` |
| GET | `/api/stream` | the viewer's event stream: each run's records and `why` records for new runs, alerts and test results |

Ingest validation, all before anything is written:

1. Bearer token compared in constant time.
2. Every blob's content matches its ref.
3. All events in a batch share a run id, and the run id is a safe name.
4. Each event's `seq` is exactly one past the stored head, `prev_hash` equals the stored head hash, and the event hash recomputes.
5. Every ref an event mentions exists in the batch or on disk.

Rejections: 401 bad token, 409 gap / fork / replayed batch, 422 bad hash or missing blob, 413 body over 20 MB.

`HttpSink` batches events (default 50) and also sends after every tool call, at the end of the run and when a second
has passed since the last send, so a collector sees a run live. It raises on HTTP errors, so a lost batch is visible to
the caller.

**Security.** Every request needs the token (`--token`, `$TRACEKIT_WHY_TOKEN`, else a random one printed in the URL).
The page exchanges the URL's `?token=` once for an HttpOnly, SameSite=Strict cookie derived from it; the API also takes
`Authorization: Bearer <token>`, and ingest takes only that. A request addressed to a Host other than loopback or the
bound address is refused unless it carries the token; a POST needs an expected Host. The replay POSTs need a JSON body
and, when an `Origin` is sent, a same-origin one. The page has a strict CSP with a script nonce per response. Beyond
loopback the server needs TLS (`--tls-cert`, `--tls-key`) or `--insecure-http`. Replay imports Python code named in
the run, which is why it is restricted to an explicit allow-list: an ingested run can name any module.

## Cross-run influence graph

`analysis.influence_graph(paths)`:

- **Sources** are input contents, keyed by blob hash, so the same document is one node across runs even under different labels.
- **Outcomes** are tool names.
- An edge (source, tool) counts the runs in which the source reached that tool (`reach_runs`) and collects every test in those runs whose intervention was `input:<that source>`.
- `cited_by` counts observed context edges from the source, meaning how many decisions used it.

A citation index counts who cited whom. This one also records which citations were shown to matter. Tests are attached to outcomes by the tool named in the target, so a test targeting `send_email,arg~vendor-compliance` shows on the `send_email` outcome. The tooltip keeps the full target.

## Live guard

`Guard.check(rt, agent, tool, args, decision, sensitive)` runs inside `Agent.act` (or `Agent.check` for adapters) before the tool executes, on a snapshot of the log so far. The built-in rule is the alert rule above: a `high` alert when some argument value appears only in untrusted content (`untrusted-value`), else a `review` alert when the deciding call's output is untrusted (`untrusted-upstream`). Custom rules return an alert dict. In `block` mode an alert whose severity is in `block_on` stops the call. The verdict is stored on the action event, so it is hash-chained with it.

## Live server

A watcher thread polls the runs folder every 0.5 s. When a run's `events.jsonl` changes (written locally or by ingest), the server recomputes that run's alerts. Alerts it has not announced before go out on `/api/stream`, and high ones to `--webhook`. Runs already present at start-up are indexed silently, so only new alerts are announced.

## v1 ledger import

`tracekit.why.import_v1` reads a v1 Tracekit ledger (`ledger/ledger.jsonl`), checks its chain and signatures with
`tracekit.observe.verify_ledger` (the result goes into `run.start.meta.signatures`), and writes a why run
`tk-<run id>` plus `tracekit-map.json` (`{"events": {why event id: [{seq, hash, type}, ...]}}`). The mapping is in
[why.md](why.md#importing-a-v1-ledger). Hashes are not shared: Tracekit hashes raw content with its own canonical form
and the why log hashes `{"v": value}`, so the map, not content hashes, is the join between the two.
