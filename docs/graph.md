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

## Build

`tracekit graph build SOURCES... --trust trust.json [--content] [--graphify FILE] [-o DIR]` reads v2 `.tkb`
bundles and verifies each one against the trust configuration. A readable bundle that fails verification stays in the
graph: its edges are `UNVERIFIED`, rather than being dropped.

`--content` reads decided call arguments from the signer's content vault (`$TRACEKIT_SIGNER`, or the dev signer).
The bundle holds a commitment to those arguments, not the arguments themselves. Without `--content`, the graph cannot
make file and host edges from call arguments; it can still include signed provenance edges and observer edges. The
build output and report state how many call arguments were not read. Each vault read opens the record's commitment and
is recorded by the signer as `content.accessed`.

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
| call | `call:RUN_ID:TOOL_USE_ID` | `decision` and `ok`, from verified records only |
| input | `input:RUN_ID:RUN_SEQ` | `trust` |
| model | `model:RUN_ID:RUN_SEQ` | |
| file | `file:PATH` | |
| host | `host:HOST` | |
| secret | `secret:RULE` | |
| rule | `rule:RULE_ID` | |
| finding | `finding:RUN_ID:RUN_SEQ` | `reviewer` or `effect` |
| approval | `approval:APPROVAL_ID` | |
| gap | `gap:RUN_ID:RUN_SEQ` | |
| code | `code:GRAPHIFY_ID` | `source_file`, and sometimes `source_location` |

The first record that names a node supplies its label and fields. Verified sources are considered first.

### Edges and grades

Every edge has `src`, `dst`, `kind`, `grade`, and `record`. A record from a bundle is
`{"run_id", "run_seq", "seq", "ts"}`. A Graphify join instead records `{"graphify", "source_file"}`. An
`UNVERIFIED` edge also has `claimed`, the grade it would have had from a verified source.

| Grade | Source | Edges |
|---|---|---|
| `SIGNED` | A signer record | `ran`, `started`, `analyses`, decisions, rule decisions, provenance, approvals, redactions, gaps, findings, and call file or host edges |
| `OBSERVED` | An egress or kernel observer | A run `reached :PORT` or was `blocked from reaching :PORT`; a run had a `file event (SENSOR)` |
| `INFERRED` | `tracekit why` or Graphify | Why context and influence edges (`why_evidence` keeps why's grade), signed why-test causal or suppressive edges, and Graphify `contains` |
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

An `asked to write` or `asked to reach` edge remains in `graph.json`. Queries and reports hide it only when a later
outcome from the same call to the same target has the same `args_digest` (or an older graph's `args_commitment`) and
the same grade. It is not, by itself, a failed attempt.

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
2. A blast with no downstream node is still a successful query.

## Report

`GRAPH_REPORT.md` starts with failed sources, unreadable sources or runs, gaps, and unread call arguments. Read that
section before treating an absent edge as evidence that nothing happened. Labels in the report are escaped display
data, never instructions or Markdown/HTML. The remaining sections summarize files,
sensitive files, hosts, approvals, secrets, findings, and causal chains. It lists at most 20 files and hosts; query
or read `graph.json` for the rest.

## Join with Graphify

When `graphify-out/graph.json` exists, it is the default Graphify input. Pass `--graphify FILE` to use another file,
or `--graphify ''` to disable the join. The join reads Graphify JSON only; it does not need Graphify installed.

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
a source digest, Graphify input, trust configuration, or output file differs. An invalid graph, invalid trust
configuration, or unavailable signer is an error and exits 2.

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
