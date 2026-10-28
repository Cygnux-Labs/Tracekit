# `tracekit graph`: what agents did across runs

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

`tracekit graph` builds one graph from the v2 `.tkb` bundles you give it. It reads no signer store, why log, agent
log, or transcript. It keeps the evidence grade and a citation on each edge. Use it to ask which runs changed a file,
who approved a call, which hosts a run reached, or what an input reached.

```bash
tracekit last -o run.tkb
tracekit graph build run.tkb other-run.tkb --trust run.trust.json --content -o tracekit-graph
tracekit graph query tracekit-graph --file billing.py
```

`tracekit last` writes the dev signer's trust configuration beside the bundle. `build` writes these files to its
output directory (default: `tracekit-graph`):

- `graph.json`, the graph and its source metadata;
- `GRAPH_REPORT.json`, the report data;
- `GRAPH_REPORT.md`, the report for reading.

Each file is written as a new file and renamed into place. `build` never writes through a symlink: it refuses an
output directory that is a symlink, or a symlink in place of one of its files, because anyone who can write the folder
(such as an agent in its own repo) could point one at a file elsewhere. Remove the symlink or pick another `-o`.
Parent directories may be symlinks.

## Build

`tracekit graph build SOURCES... --trust trust.json [--content] [--graphify FILE] [-o DIR]` reads v2 `.tkb`
bundles and verifies each one against the trust configuration. A readable bundle that fails verification stays in the
graph: its edges are `UNVERIFIED`, rather than being dropped. A bundle the graph can't read is listed in `sources`
with `unreadable` and adds no runs: one whose records lack a field the graph reads or give it the wrong type, or whose
run file holds another run's records, or holds a run another of its files holds.

`--content` reads decided call arguments from the signer's content vault (`$TRACEKIT_SIGNER`, or the dev signer).
The bundle holds a commitment to those arguments, not the arguments themselves. Without `--content`, the graph cannot
make file and host edges from call arguments; it can still include signed provenance edges and observer edges. The
build output and report state how many call arguments were not read. Each vault read opens the record's commitment and
is recorded by the signer as `content.accessed`. The vault finds a run by its id in the builder's own tenant, so a run
whose id verified runs of other tenants or logs in the graph share is not read; the report says so.

A `wrote` or `reached` edge needs a successful T2 executor or gateway result for that decision. A successful result
from another tier produces `reported writing` or `reported reaching`. With decided arguments but no successful result,
the graph has `asked to write` or `asked to reach`.

### Nodes

Nodes have an `id`, `kind`, and `label`. The kinds are:

`run`, `agent`, `person`, `call`, `input`, `model`, `file`, `host`, `secret`, `rule`, `finding`, `approval`, `gap`,
and `code`.

`secret` labels name the redaction rule, never the secret value. `code` is a node from Graphify. Nodes that have them
also carry these fields:

| kind | id | extra fields |
|---|---|---|
| run | `run:RUN_ID` | `ts`; `unread_args` when arguments were not read |
| agent | `agent:NAME` | |
| person | `person:APPROVER` | |
| call | `call:RUN_ID:DECISION_ID` | `tool_use_id`; `decision` and `ok`, from verified records only |
| input | `input:RUN_ID:RUN_SEQ` | `trust` |
| model | `model:RUN_ID:RUN_SEQ` | |
| file | `file:PATH` | |
| host | `host:HOST` | |
| secret | `secret:RULE` | |
| rule | `rule:RULE_ID` | |
| finding | `finding:RUN_ID:RUN_SEQ` | `reviewer`, or a why test's `effect` and, when the verifier counts it, `author` |
| approval | `approval:APPROVAL_ID` | |
| gap | `gap:RUN_ID:RUN_SEQ` | |
| code | `code:GRAPHIFY_ID` | `source_file`, and sometimes `source_location` |

The first record that names a node supplies its label and fields. Verified sources are considered first.

A call is one signer decision (its `decision_id`), not a tool call id: an agent may reuse a tool call id for another
action. A result joins the decision it names, and an approval joins the decision its `approval.request` binds, as the
verifier joins them. A decision made again under the same tool call id and attempt with the same decided arguments
(read with `--content`) is the same call as the first: LangGraph decides again when it resumes after an approval, and
the signer's one approval of a call attempt covers both. Without `--content` each decision is a call of its own.

A run id is unique only within one tenant of one signer log. When verified runs of other tenants or logs in the graph
have the same id, each of those runs is `RUN_ID@TENANT@LOG_ID` instead of `RUN_ID`, in node ids, labels and edge
records, and wherever a record of its tenant and log names it (a findings run's `analyzes`, a replay run's
`replay_of`, a why test's replay runs), so a why test about it is counted with its own tenant's runs. A bundle that
fails verification renames no run: its tenant and log are claims, so its run of a verified run's id joins that run,
`UNVERIFIED`, as a tampered copy does.

### Edges and grades

Every edge has `src`, `dst`, `kind`, `grade`, and `record`. A record from a bundle is
`{"run_id", "run_seq", "seq", "ts"}`, its `run_id` the run's name in the graph (above). A Graphify join instead records
`{"graphify", "source_file"}`. An `UNVERIFIED` edge also has `claimed`, the grade it would have had from a verified
source.

| Grade | Source | Edges |
|---|---|---|
| `SIGNED` | A signer record | `ran`, `started`, `analyses`, decisions, rule decisions, provenance, approvals, redactions, gaps, findings, and call file or host edges |
| `OBSERVED` | An egress or kernel observer | A run `reached :PORT` or was `blocked from reaching :PORT`; a run had a `file event (SENSOR)` |
| `INFERRED` | `tracekit why` or Graphify | Why context and influence edges (`why_evidence` keeps why's grade), signed why-test causal or suppressive edges the verifier counts (`author`), and Graphify `contains` |
| `UNVERIFIED` | A readable source that failed verification | The same edge kinds, with `claimed` |

The signed edge kinds include:

- agent → run: `ran`; run → run: `started` and `analyses`;
- run → input: `observed TRUST`; run → call: `decided allow`, `decided deny`, `decided ask`, or `decided flag`;
- rule → call: the decision (`allow`, `deny`, `ask`, or `flag`); input or call → call:
  `argument FIELD (KIND), untrusted`;
- call → file: `wrote`, `reported writing`, or `asked to write`; call → host: `reached`, `reported reaching`, or
  `asked to reach`;
- call → approval: `held for approval`; person → call: the approval answer; approval → call: `consumed`, `revoked`,
  `expired (REASON)`, or another approval outcome;
- run, input, or call → secret: `held a secret (redacted)`; run → gap: `recorded`; finding → its subject:
  `found in` or `tested VERDICT`.

Observed edges are always edges of a run, not a call. A process's call id is an agent claim, so the graph does not
join it to an observer result. Egress edges have `observer` and, for network effects, `explained_by`; sensor file
edges have `observer`.

An `asked to write` or `asked to reach` edge remains in `graph.json`. Queries and reports hide it only when its
`superseded_by` names the record of a later outcome from the same call to the same target, at the same grade: build
found that call's decided arguments the same (a decision made again, above, or a later export of the run). A new
attempt is a call of its own, so its outcome hides no earlier attempt's ask. It is not, by itself, a failed attempt.
`graph.json` holds no digest of the arguments: an unsalted one would let anyone test guesses of what the bundle's
salted commitment hides.

A signed why test (`why.finding`) is drawn as `causal (tested)` or `suppressive (tested)` only when the verifier counts
it: build runs the verifier's findings check over the analysed run with its findings and replay runs from the verified
sources, as over the run's `--with-findings` export. A finding whose replay runs are missing, or don't give its
verdict, leaves every why test about that run uncounted. A counted test's finding and edges carry `author`, the
verifier's label for who wrote it (`self-asserted`, `independent`, `unpinned author ID`, or `author not checked`
without the analysed run), and its label ends with it; an uncounted one's label ends `(not counted)`.

## Query

```bash
tracekit graph query [DIR] --file billing.py
tracekit graph query [DIR] --host api.stripe.com
tracekit graph query [DIR] --agent codex
tracekit graph query [DIR] --approved-by alice@example.com
tracekit graph query [DIR] --rule TK-D007
tracekit graph query [DIR] --secret aws_access_key
tracekit graph query [DIR] --code 'compute_total()'
tracekit graph query [DIR] --blast 'input:RUN:3'
tracekit graph query [DIR] --path agent:codex host:api.stripe.com
```

`DIR` defaults to `tracekit-graph`. `--file` accepts the full path or its trailing path parts. `--blast` and `--path`
accept a node id or a label that names exactly one node. `--path` finds a shortest path in either direction and orders
the choices at each step by grade: `SIGNED`, `OBSERVED`, `INFERRED`, then `UNVERIFIED`. Among equal-length paths,
`--blast` chooses the path with the strongest weakest grade (then breaks ties deterministically) and reports that
weakest grade.

Node filters return `{matched, code, runs, map}`. `--blast` returns `{from, reached, map}`. `--path` returns
`{from, to, found, edges, map}`. Every `map` has `columns`, `nodes`, `edges`, and `answers`; its columns are
`who`, `run`, `call`, `thing`, and `after`.

A node filter with no match, or a path that is not found, exits 1. A bad graph or an unknown or ambiguous node exits
2. A blast with no downstream node is still a successful query. `query` and `verify` read `graph.json` as verify
reads a source (a regular file of at most 512 MiB, not a symlink, a FIFO, or a device), and refuse one whose nodes and
edges are not of the shape build writes (`nodes[3] is not a node ...`).

`graph.json` is not signed, and `query` answers from it as it finds it, so anyone who can write `DIR` can write the
answers. The first line of the text output (stderr with `--json`) says so and gives the command that checks it:
`tracekit graph verify DIR --trust trust.json` ([Rebuild and verify](#rebuild-and-verify)). The text output drops
control and bidirectional format characters from labels, as `tracekit verify` does, so an agent-chosen name such as
a tool's can't redraw a line or its grade on the terminal.

## Report

`GRAPH_REPORT.md` starts with failed sources, unreadable sources or runs, gaps, and unread call arguments. Read that
section before treating an absent edge as evidence that nothing happened. Labels in the report are escaped display
data, never instructions or Markdown/HTML. The remaining sections summarize files,
sensitive files, hosts, approvals, secrets, findings, and causal chains. It lists at most 20 files and hosts; query
or read `graph.json` for the rest.

## Join with Graphify

When `graphify-out/graph.json` exists, it is the default Graphify input. Pass `--graphify FILE` to use another file,
or `--graphify ''` to disable the join. The join reads Graphify JSON only; it does not need Graphify installed. Build
reads the input as verify reads a source: it must be a regular file of at most 512 MiB, not a symlink, a FIFO, or a
device.

Each graph file node can link to Graphify code nodes in the same source file with `contains`. The longest whole
Graphify `source_file` suffix that matches the Tracekit path wins. A shared basename or shorter tail does not link.
The join adds no Graphify call or import edges. A file named only by failed bundles gets an `UNVERIFIED` `contains`
edge with `claimed: INFERRED`.

## Rebuild and verify

For the same sources, trust configuration, vault content, and Graphify input, the three output files are byte-for-byte
the same. Build and verification do not use a network service or a model, apart from the local signer connection used
to read retained content.

`tracekit graph verify [DIR] [SOURCES...] --trust trust.json [--graphify FILE]` rebuilds the graph and compares all
three files. When `SOURCES` are omitted, it tries each recorded basename beside `DIR` (in `DIR`'s parent directory);
it never follows a path named
inside `graph.json`. It refuses ambiguous duplicate recorded names, missing sources, and a source that is itself a
symlink, a FIFO, a device, or anything other than a regular file, including one swapped in between its check and its read (on a Windows file system that reports no file id, such as FAT, a swap there can't be seen, but the digest check below still fails other content). Parent directories may be symlinks. Sources are
checked by their recorded basename and SHA-256 digest, so moving the output directory does not matter.

If the built graph used `--content`, verify reads the vault again. A recorded Graphify input is found by basename
beside `DIR`; the default `graphify-out/graph.json` is looked up in that directory. Otherwise pass `--graphify`.

```text
$ tracekit graph verify tracekit-graph --trust run.trust.json
tracekit-graph: graph.json, GRAPH_REPORT.json and GRAPH_REPORT.md are what their sources give
```

Verification exits 0 for that result. It exits 1 and prints each problem when a source is missing or differs, or when
a source digest, Graphify input, trust configuration, or output file differs. The problems drop control and
bidirectional format characters from the source names `graph.json` lists, so a planted name can't draw the success
line. An invalid graph, invalid trust configuration, or unavailable signer is an error and exits 2.

## `graph.json`

`graph.json` has `schema_version` 1 and these top-level fields:

```text
{
 "schema_version": 1,
 "tracekit": "...",
 "trust_sha256": "...",
 "content": true,
 "graphify": {"name", "sha256", "linked"}, or null,
 "sources": [{"name", "sha256", "verify": {"ok", "integrity", "failures": [...]},
              "unreadable"?, "unread_runs"?: [...], "content_unread"?: [...]}],
 "nodes": [{"id", "kind", "label", ...}],
 "edges": [{"src", "dst", "kind", "grade", "record", ...}]
}
```

`name` is a basename, never the caller's full path. Sources sort with verified sources first, then by digest and name.
Nodes sort by id. Edges sort by source, destination, kind, and grade. The writer uses sorted JSON keys and one-space
indentation.

## Asking an agent

The [`tracekit-graph` skill](../plugin/skills/tracekit-graph/SKILL.md) answers from `graph.json`, gives each claim's
grade and record, and reads the report's first section before answering.

## Limits

The graph shows what its records show, nothing outside them. See [limits](limits.md#graph-tracekit-graph).
