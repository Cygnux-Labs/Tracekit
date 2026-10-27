"""`tracekit graph`: what agents did across runs, as one queryable graph built only from Tracekit's records.

    tracekit graph build RUN.tkb... --trust trust.json [-o tracekit-graph]    # graph.json and GRAPH_REPORT.md
    tracekit graph query [DIR] --file billing.py | --host H | --agent A | --approved-by P | --rule TK-... [--json]
    tracekit graph query [DIR] --blast NODE | --path NODE NODE [--json]
    tracekit graph verify [DIR] --trust trust.json                            # rebuilt from its sources and compared

Every edge has a grade (`evidence`) and cites the record it came from (`record`: run_id, run_seq, seq):

    SIGNED      the signer's record says so: agent ran run, run decided call, rule held or denied call, person approved
                or rejected call, an untrusted input or result supplied a call's argument, run recorded a gap
    OBSERVED    an observer outside the agent saw it: egress hosts, kernel sensor connections and files; a run's, never a
                call's (the call id a process carries is the agent's claim)
    INFERRED    tracekit why's causal graph of the run, why's own grade kept (`why_evidence`)
    UNVERIFIED  any of these from a bundle that fails verification against the trust config (`claimed`: the grade it
                would have): kept, never dropped

The same sources and trust config give the same files byte for byte; no network, no model.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import statistics
import sys
import tempfile
from collections import deque
from typing import Any, Dict, List, Optional

from . import __version__
from .why.graph import Graph

GRADES = ("SIGNED", "OBSERVED", "INFERRED", "UNVERIFIED")
SCHEMA_VERSION = 1
GRAPH, REPORT = "graph.json", "GRAPH_REPORT.md"
FILTERS = {"file": "file", "host": "host", "agent": "agent", "approved_by": "person", "rule": "rule"}
FACTS = ("agent", "person", "rule", "host", "file", "gap")   # what a query shows of each run it finds


# --------------------------------------------------------------------------- sources

def _read(path: str, trust: str):
    """(source entry, run_id -> records) of v2 bundle `path`, read once: its records are read even when it fails
    verification, so that its edges are marked UNVERIFIED rather than dropped."""
    from .bundle_v2 import run_files
    from .verify import v2
    with open(path, "rb") as f:
        data = f.read()
    rep, code = v2.verify(io.BytesIO(data), trust)
    src: Dict[str, Any] = {"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                           "verify": {"ok": code == 0, "integrity": rep.integrity, "failures": rep.failures}}
    runs: Dict[str, List[Dict[str, Any]]] = {}
    try:
        files = v2.read_zip(io.BytesIO(data))
        for parts in run_files(files).values():
            recs = [r for n in parts for r in v2._jsonl(files[n])]
            runs[recs[0]["event"]["run_id"]] = recs
    except Exception as e:   # not readable as a bundle at all: listed in sources, with no runs
        src["unreadable"] = f"{type(e).__name__}: {e}"
    return src, runs


# --------------------------------------------------------------------------- build

def _node(g: Graph, nid: str, kind: str, label: str, **attrs: Any) -> str:
    g.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, **attrs})
    return nid


def _cite(e: Dict[str, Any]) -> Dict[str, Any]:
    return {"run_id": e["run_id"], "run_seq": e["run_seq"], "seq": e["seq"]}


def _edge(g: Graph, ok: bool, src: str, dst: str, kind: str, grade: str, cite: Dict[str, Any], **extra: Any) -> None:
    g.add_edge(src, dst, kind, grade if ok else "UNVERIFIED", record=cite, **extra,
               **({} if ok else {"claimed": grade}))


def _add_run(g: Graph, recs: List[Dict[str, Any]], ok: bool) -> None:
    """The nodes and SIGNED and OBSERVED edges of one run's records."""
    first = recs[0]["event"]
    rid = first["run_id"]
    run = _node(g, "run:" + rid, "run", rid, ts=first["ts"])
    by_seq: Dict[int, str] = {}   # run_seq -> the node of the record that brought a value into the run
    for r in recs:
        e = r["event"]
        t, d, at = e["type"], e.get("data") or {}, _cite(e)
        if t == "run.registered":
            name = (d.get("agent") or {}).get("name") or "main"
            who = d.get("identity") or {}
            _edge(g, ok, _node(g, "agent:" + name, "agent", name), run, "ran", "SIGNED", at,
                  **({"identity": f"{who.get('scheme')}:{who.get('subject')}"} if who else {}))
        elif t == "input.observed":
            by_seq[e["run_seq"]] = _node(g, f"input:{rid}:{e['run_seq']}", "input", str(d.get("source")),
                                         trust=d.get("trust"))
            _edge(g, ok, run, by_seq[e["run_seq"]], "observed " + str(d.get("trust")), "SIGNED", at)
        elif t == "policy.decision":
            call = _node(g, f"call:{rid}:{d.get('tool_use_id')}", "call", str(d.get("tool")))
            _edge(g, ok, run, call, "decided " + str(d.get("decision")), "SIGNED", at)
            for rule in d.get("rule_ids") or []:
                _edge(g, ok, _node(g, "rule:" + rule, "rule", rule), call, str(d.get("decision")), "SIGNED", at)
            for p in d.get("provenance") or []:
                src = by_seq.get((p.get("source") or {}).get("run_seq"))
                if src:
                    _edge(g, ok, src, call, f"argument {p.get('field')} ({p.get('kind')}), untrusted", "SIGNED", at)
        elif t == "tool.result":
            by_seq[e["run_seq"]] = _node(g, f"call:{rid}:{d.get('tool_use_id')}", "call", "?")
        elif t == "approval":
            who = str(d.get("approver"))
            _edge(g, ok, _node(g, "person:" + who, "person", who), _node(g, f"call:{rid}:{d.get('tool_use_id')}",
                                                                          "call", "?"),
                  str(d.get("decision")), "SIGNED", at, self_approved=bool(d.get("self_approved")),
                  **({"wait_ms": d["wait_ms"]} if isinstance(d.get("wait_ms"), int) else {}))
        elif t in ("capture.gap", "trace.tamper"):
            gap = _node(g, f"gap:{rid}:{e['run_seq']}", "gap", f"{t} {d.get('kind') or ''}: {d.get('reason') or ''}")
            _edge(g, ok, run, gap, "recorded", "SIGNED", at)
        elif t == "effect.observed" and d.get("kind") in ("net", "connect") and d.get("host"):
            _edge(g, ok, run, _node(g, "host:" + d["host"], "host", d["host"]), f"reached :{d.get('port')}",
                  "OBSERVED", at, observer=d.get("observer"))
        elif t == "effect.observed" and d.get("kind") == "file" and d.get("path"):
            _edge(g, ok, run, _node(g, "file:" + d["path"], "file", d["path"]), f"file event ({d.get('sensor')})",
                  "OBSERVED", at, observer=d.get("observer"))


def _add_why(g: Graph, recs: List[Dict[str, Any]], ok: bool) -> None:
    """INFERRED edges: tracekit why's causal graph of the run, mapped onto this graph's nodes."""
    from .why.core import load_run
    from .why.graph import build_graph
    from .why.import_v2 import convert
    with tempfile.TemporaryDirectory() as d:
        wg = build_graph(load_run(convert(recs, d, {})))

    def ours(nid: str) -> Optional[str]:
        ev = wg.nodes[nid]["event"]
        c = ev.get("tracekit") or {}
        if ev["type"] == "action":
            return f"call:{c['run_id']}:{c['tool_call_id']}"
        if ev["type"] == "input":
            return f"input:{c['run_id']}:{c['run_seq']}"
        if ev["type"] == "decision":
            return _node(g, f"model:{c['run_id']}:{c['run_seq']}", "model call", str(ev.get("model")))
        return None

    for e in wg.edges:
        if e["kind"].startswith("argument"):   # the signer's provenance: already a SIGNED edge
            continue
        src, dst = ours(e["src"]), ours(e["dst"])
        if src and dst:
            _edge(g, ok, src, dst, e["kind"], "INFERRED", _cite(wg.nodes[e["dst"]]["event"]["tracekit"]),
                  why_evidence=e["evidence"])


def build(paths: List[str], trust: str) -> Dict[str, Any]:
    """graph.json's document from v2 bundles `paths`, each verified against trust config `trust`. Verified sources go
    first, so that a node's label comes from a verified record wherever one has it."""
    read = sorted((_read(p, trust) for p in paths), key=lambda s: (not s[0]["verify"]["ok"], s[0]["path"]))
    g = Graph(None)  # type: ignore[arg-type]
    for src, runs in read:
        ok = src["verify"]["ok"]
        for rid in sorted(runs):
            try:
                _add_run(g, runs[rid], ok)
                _add_why(g, runs[rid], ok)
            except Exception as e:   # a record an unverified bundle mangled: what was read is kept, the rest named
                src.setdefault("unread_runs", []).append(f"{rid}: {type(e).__name__}: {e}")
    with open(trust, "rb") as f:
        trust_sha256 = hashlib.sha256(f.read()).hexdigest()
    return {"schema_version": SCHEMA_VERSION, "tracekit": __version__, "trust_sha256": trust_sha256,
            "sources": [s for s, _ in read],
            "nodes": sorted(g.nodes.values(), key=lambda n: n["id"]),
            "edges": sorted(g.edges, key=lambda e: (e["src"], e["dst"], e["kind"], e["evidence"]))}


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def _graph(doc: Dict[str, Any]) -> Graph:
    g = Graph(None)  # type: ignore[arg-type]
    g.nodes = {n["id"]: n for n in doc["nodes"]}
    for e in doc["edges"]:
        g.add_edge(e["src"], e["dst"], e["kind"], e["evidence"],
                   **{k: v for k, v in e.items() if k not in ("src", "dst", "kind", "evidence")})
    return g


# --------------------------------------------------------------------------- report

def report(doc: Dict[str, Any]) -> str:
    g = _graph(doc)

    def lab(n: str) -> str:
        return g.nodes[n]["label"]

    def of(kind: str) -> List[str]:
        return sorted(n for n, v in g.nodes.items() if v["kind"] == kind)

    def runs(n: str) -> str:
        return ", ".join(sorted({f"run {e['record']['run_id']} ({e['evidence']})" for e in g.in_edges(n, GRADES)}))

    def approvals(n: str) -> str:
        es = g.out_edges(n, GRADES)
        waits = [e["wait_ms"] for e in es if "wait_ms" in e]
        return (", ".join(f"{sum(e['kind'] == k for e in es)} {k}" for k in ("approve", "reject"))
                + (f", median wait {statistics.median(waits):g} ms" if waits else "")
                + (f", {sum(e['self_approved'] for e in es)} self-approved" if any(e.get("self_approved") for e in es)
                   else ""))

    sections = {
        "Unverified sources and gaps":
            [f"{s['path']}: {s['verify']['integrity']} ({', '.join(s['verify']['failures'])}): every edge from it is "
             "UNVERIFIED" for s in doc["sources"] if not s["verify"]["ok"]]
            + [f"{s['path']}: {p}" for s in doc["sources"] for p in [s.get("unreadable")] + s.get("unread_runs", []) if p]
            + [f"{lab(e['dst'])} (run {e['record']['run_id']}, record {e['record']['run_seq']}, {e['evidence']})"
               for e in doc["edges"] if g.nodes[e["dst"]]["kind"] == "gap"],
        "Files": [f"{lab(n)}: {runs(n)}" for n in of("file")],
        "Hosts": [f"{lab(n)}: {runs(n)}" for n in of("host")],
        "Approvals": [f"{lab(n)}: {approvals(n)}" for n in of("person")],
    }
    out = [f"# Tracekit graph report\n\n{len(doc['sources'])} sources, {len(of('run'))} runs, {len(doc['nodes'])} "
           f"nodes, {len(doc['edges'])} edges (tracekit {doc['tracekit']})."]
    for title, lines in sections.items():
        out.append(f"\n## {title}\n\n" + "\n".join(f"- {x}" for x in lines or ["none"]))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- query

def _run_of(e: Dict[str, Any]) -> str:
    return e["record"]["run_id"]


def matching(doc: Dict[str, Any], kind: str, needle: str) -> Dict[str, Any]:
    """The runs that touched a node of `kind` labelled `needle` (a file also by its last path parts), newest first:
    each run's agents, approvals, rules, hosts, files and gaps, and the edges to the matched nodes."""
    g = _graph(doc)
    hits = sorted(n for n, v in g.nodes.items() if v["kind"] == kind
                  and (v["label"] == needle or kind == "file" and v["label"].endswith("/" + needle.lstrip("/"))))
    touching = [e for h in hits for e in g.in_edges(h, GRADES) + g.out_edges(h, GRADES)]
    runs = sorted({_run_of(e) for e in touching}, key=lambda r: (g.nodes.get("run:" + r, {}).get("ts", ""), r),
                  reverse=True)
    out = []
    for rid in runs:
        # lean: scans every edge per run; index edges by run if graphs grow past a few thousand runs
        es = [e for e in g.edges if _run_of(e) == rid]
        facts = {k: [e for e in es if g.nodes[e["src"]]["kind"] == k or g.nodes[e["dst"]]["kind"] == k] for k in FACTS}
        out.append({"run": rid, "ts": g.nodes.get("run:" + rid, {}).get("ts"), **facts,
                    "matched": [e for e in touching if _run_of(e) == rid]})
    return {"matched": hits, "runs": out}


def _find(g: Graph, spec: str) -> str:
    if spec in g.nodes:
        return spec
    hits = sorted(n for n, v in g.nodes.items() if v["label"] == spec)
    if len(hits) != 1:
        raise ValueError(f"{spec!r} names {'no node' if not hits else 'several nodes: ' + ', '.join(hits[:5])}; "
                         "give a node id")
    return hits[0]


def blast(doc: Dict[str, Any], spec: str) -> Dict[str, Any]:
    """Everything downstream of a node, each with the shortest path to it (why's forward reachability)."""
    g = _graph(doc)
    start = _find(g, spec)
    parent = g.descendants([start], GRADES)
    return {"from": start, "reached": [{"node": n, "kind": g.nodes[n]["kind"], "label": g.nodes[n]["label"],
                                        "path": Graph.path(parent, n)}
                                       for n in sorted(parent) if n != start]}


def path(doc: Dict[str, Any], a: str, b: str) -> Dict[str, Any]:
    """The shortest chain of edges between two nodes, either way along each edge, the stronger grade first at each
    step."""
    g = _graph(doc)
    a, b = _find(g, a), _find(g, b)
    via: Dict[str, Optional[Dict[str, Any]]] = {a: None}
    q = deque([a])
    while q and b not in via:
        n = q.popleft()
        for e in sorted(g.out_edges(n, GRADES) + g.in_edges(n, GRADES), key=lambda e: GRADES.index(e["evidence"])):
            m = e["dst"] if e["src"] == n else e["src"]
            if m not in via:
                via[m] = e
                q.append(m)
    edges, n = [], b
    while b in via and via[n] is not None:
        e = via[n]
        edges.append(e)
        n = e["src"] if e["dst"] == n else e["dst"]
    return {"from": a, "to": b, "found": b in via, "edges": edges[::-1]}


# --------------------------------------------------------------------------- CLI

def _line(g: Dict[str, Dict[str, Any]], e: Dict[str, Any]) -> str:
    r = e["record"]
    return (f"  {e['evidence']:<10} {g[e['src']]['label']} -{e['kind']}-> {g[e['dst']]['label']}"
            f"  (run {r['run_id']} record {r['run_seq']})")


def write(doc: Dict[str, Any], out: str) -> None:
    os.makedirs(out, exist_ok=True)
    for name, text in ((GRAPH, dumps(doc)), (REPORT, report(doc))):
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def verify(out: str, trust: str) -> List[str]:
    """What differs between DIR's files and the ones its sources give now ([] when nothing does)."""
    with open(os.path.join(out, GRAPH), encoding="utf-8") as f:
        have = json.load(f)
    doc = build([s["path"] for s in have["sources"]], trust)
    listed = {s["path"]: s["sha256"] for s in have["sources"]}
    problems = [f"{s['path']}: its digest is not the one graph.json lists" for s in doc["sources"]
                if s["sha256"] != listed[s["path"]]]
    if doc["trust_sha256"] != have.get("trust_sha256"):
        problems.append("the trust config is not the one graph.json was built with")
    for name, text in ((GRAPH, dumps(doc)), (REPORT, report(doc))):
        with open(os.path.join(out, name), encoding="utf-8", newline="") as f:
            if f.read() != text:
                problems.append(f"{name} is not what its sources give")
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tracekit graph", description="What agents did across runs, from verified "
                                 "bundles; every edge graded SIGNED, OBSERVED, INFERRED or UNVERIFIED.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build", help="write graph.json and GRAPH_REPORT.md from v2 bundles")
    p.add_argument("sources", nargs="+", help="v2 bundles (.tkb)")
    p.add_argument("--trust", required=True, help="the verifier's pinned trust config")
    p.add_argument("-o", "--out", default="tracekit-graph")
    p = sub.add_parser("query", help="runs that touched a file, host, agent, approver or rule; --blast; --path")
    p.add_argument("dir", nargs="?", default="tracekit-graph")
    m = p.add_mutually_exclusive_group(required=True)
    for k in FILTERS:
        m.add_argument("--" + k.replace("_", "-"), dest=k)
    m.add_argument("--blast", metavar="NODE", help="everything downstream of a node (id or unique label)")
    m.add_argument("--path", nargs=2, metavar="NODE", help="the shortest evidence path between two nodes")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("verify", help="rebuild DIR from the sources it lists and compare, byte for byte")
    p.add_argument("dir", nargs="?", default="tracekit-graph")
    p.add_argument("--trust", required=True)
    a = ap.parse_args(argv)
    from .verify import v2
    try:
        if a.cmd in ("build", "verify"):
            v2.load_trust(a.trust)   # a bad trust config would mark every source UNVERIFIED: refuse it instead
        if a.cmd == "build":
            doc = build(a.sources, a.trust)
            write(doc, a.out)
            bad = [s["path"] for s in doc["sources"] if not s["verify"]["ok"]]
            print(f"wrote {os.path.join(a.out, GRAPH)} and {REPORT}: {len(doc['nodes'])} nodes, {len(doc['edges'])} "
                  "edges" + (f"; UNVERIFIED (failed verification): {', '.join(bad)}" if bad else ""))
            return 0
        if a.cmd == "verify":
            problems = verify(a.dir, a.trust)
            print("\n".join(problems) or f"{a.dir}: graph.json and {REPORT} are what their sources give")
            return 1 if problems else 0
        with open(os.path.join(a.dir, GRAPH), encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print(f"tracekit graph: {e}", file=sys.stderr)
        return 2
    nodes = {n["id"]: n for n in doc["nodes"]}
    try:
        if a.blast:
            res = blast(doc, a.blast)
            text = [f"downstream of {res['from']}:"] + [f"  {r['kind']} {r['label']}  via {' -> '.join(r['path'])}"
                                                        for r in res["reached"]]
        elif a.path:
            res = path(doc, *a.path)
            text = [_line(nodes, e) for e in res["edges"]] if res["found"] else [f"no path from {res['from']} to "
                                                                               f"{res['to']}"]
        else:
            k = next(k for k in FILTERS if getattr(a, k))
            res = matching(doc, FILTERS[k], getattr(a, k))
            text = [] if res["matched"] else [f"no {FILTERS[k]} node is {getattr(a, k)!r}"]
            for r in res["runs"]:
                text.append(f"run {r['run']} ({r['ts']})")
                text += [_line(nodes, e) for e in r["matched"]] + [
                    _line(nodes, e) for k2 in FACTS for e in r[k2] if e not in r["matched"]]
    except ValueError as e:
        print(f"tracekit graph: {e}", file=sys.stderr)
        return 2
    print(json.dumps(res, sort_keys=True, indent=1, ensure_ascii=False) if a.json else "\n".join(text))
    return 0 if res.get("matched", res.get("found", True)) else 1


if __name__ == "__main__":
    sys.exit(main())
