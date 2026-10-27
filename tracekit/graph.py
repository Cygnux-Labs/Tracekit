"""`tracekit graph`: what agents did across runs, as one queryable graph built only from Tracekit's records.

    tracekit graph build RUN.tkb... --trust trust.json [--content] [--graphify FILE] [-o tracekit-graph]
    tracekit graph query [DIR] --file billing.py | --host H | --agent A | --approved-by P | --rule TK-... |
                               --secret NAME | --code NAME [--json]
    tracekit graph query [DIR] --blast NODE | --path NODE NODE [--json]
    tracekit graph verify [DIR] --trust trust.json         # rebuilt from its sources and compared, byte for byte

Nodes: run, agent, person (an approver), call, input, model (a model call), file, host, secret (the name of the
redaction rule that caught it, never the value), rule, finding, approval, gap, and code (a Graphify node). Every edge
has a grade (`evidence`) and cites the record it came from (`record`: run_id, run_seq, seq):

    SIGNED      the signer's record says so: agent ran run, run decided call, rule held or denied call, the call's
                decided arguments wrote a file or reached a host (--content: the arguments the signer's content vault
                holds, each opening its record's commitment), call held for approval and what became of the approval,
                person approved or rejected call, run, input or call held a secret the signer redacted, an untrusted
                input supplied a call's argument, run recorded a gap, run started or analyses run, a signed finding
                about a record
    OBSERVED    an observer outside the agent saw it: egress hosts, kernel sensor connections and files; a run's, never
                a call's (the call id a process carries is the agent's claim)
    INFERRED    tracekit why's causal graph of the run and the signed why tests about it (why.finding), why's own grade
                kept (`why_evidence`); and the Graphify join: a code node in a file the graph has (`record` names the
                Graphify file)
    UNVERIFIED  any of these from a bundle that fails verification against the trust config (`claimed`: the grade it
                would have): kept, never dropped

The same sources, trust config, vault content and Graphify graph give the same files byte for byte; no network, no
model.
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
from collections import Counter, deque
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .why.graph import Graph

GRADES = ("SIGNED", "OBSERVED", "INFERRED", "UNVERIFIED")
SCHEMA_VERSION = 1
GRAPH, REPORT = "graph.json", "GRAPH_REPORT.md"
GRAPHIFY = os.path.join("graphify-out", "graph.json")
FILTERS = {"file": "file", "host": "host", "agent": "agent", "approved_by": "person", "rule": "rule",
           "secret": "secret", "code": "code"}
# what a query shows of each run it finds
FACTS = ("agent", "person", "approval", "rule", "host", "file", "secret", "finding", "gap")
TOP = 20   # lean: the files and hosts GRAPH_REPORT.md lists; graph.json has them all
Content = Callable[[str, List[Dict[str, Any]]], Dict[int, Any]]


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


def vault() -> Content:
    """build's `content`: the decided arguments of a run's calls from the signer's content vault ($TRACEKIT_SIGNER,
    else the dev signer), each opening its record's commitment (why.signed.vault_content: EvidenceAlert when one does
    not); each read is a signed content.accessed. The client connects on the first run read."""
    from .sdk.client import Client
    from .why.signed import vault_content
    client = None

    def read(run_id: str, recs: List[Dict[str, Any]]) -> Dict[int, Any]:
        nonlocal client
        client = client or Client()
        decisions = [r for r in recs if r["event"]["type"] == "policy.decision"]
        # content redaction changed opens no commitment: not what the record holds
        return {seq: c for seq, c, opened in vault_content(client, decisions, "tracekit graph") if opened}
    return read


# --------------------------------------------------------------------------- build

def _node(g: Graph, nid: str, kind: str, label: str, **attrs: Any) -> str:
    n = g.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label})
    for k, v in attrs.items():   # a node first named by another run (a child run, an analysed one) gets its own later
        n.setdefault(k, v)
    return nid


def _cite(e: Dict[str, Any]) -> Dict[str, Any]:
    return {"run_id": e["run_id"], "run_seq": e["run_seq"], "seq": e["seq"]}


def _edge(g: Graph, ok: bool, src: str, dst: str, kind: str, grade: str, cite: Dict[str, Any], **extra: Any) -> None:
    g.add_edge(src, dst, kind, grade if ok else "UNVERIFIED", record=cite, **extra,
               **({} if ok else {"claimed": grade}))


def _of(g: Graph, e: Dict[str, Any]) -> str:
    """The node of record `e`: its call's for a decision, result or approval, its input's, else its run's."""
    d = e.get("data") or {}
    nid = (f"call:{e['run_id']}:{d.get('tool_use_id')}" if e["type"] in ("policy.decision", "tool.result", "approval")
           else f"input:{e['run_id']}:{e['run_seq']}" if e["type"] == "input.observed" else "")
    return nid if nid in g.nodes else "run:" + e["run_id"]


def _about(recs: List[Dict[str, Any]]) -> Optional[str]:
    """The run a findings run analyses, or None."""
    first = recs[0]["event"]
    return (first.get("data") or {}).get("analyzes") if first["type"] == "run.registered" else None


def _written(tool: Any, args: Any) -> List[str]:
    """The paths call (`tool`, `args`) writes as its decided arguments say: a write tool's path and `paths`, a shell
    command's targets as far as the policy engine's parser reads them (constraints.shell), each as path rules match it.
    lean: write tools by name (findings.WRITE_TOOLS), not by the policy's fs class; a relative path stays relative"""
    from .constraints import shell
    from .findings import WRITE_TOOLS
    from .policy2.classes import PATH_KEYS, SHELL_KEYS, first, fs_path
    if not isinstance(args, dict):
        return []
    if tool in WRITE_TOOLS:
        paths = [first(args, *PATH_KEYS), *(args["paths"] if isinstance(args.get("paths"), list) else ())]
    elif any(args.get(k) is not None for k in SHELL_KEYS):
        paths = shell(args)["paths"]
    else:
        return []
    return sorted({fs_path(p) for p in paths if isinstance(p, str) and p})


def _host(args: Any) -> Optional[str]:
    """The host of a call's `url` argument, as the policy engine reads it. lean: not a shell command's hosts"""
    from .policy2.classes import url_info
    url = args.get("url") if isinstance(args, dict) else None
    return url_info(url).get("host") if isinstance(url, str) else None


def _add_run(g: Graph, recs: List[Dict[str, Any]], ok: bool, args: Optional[Dict[int, Any]] = None,
             index: Optional[Dict[tuple, Dict[str, Any]]] = None) -> None:
    """The nodes and SIGNED and OBSERVED edges of one run's records. `args`: run_seq -> the decided arguments of a
    call, opened against its record's commitment (None: none were read); `index`: (run_id, run_seq) -> record of every
    run read, for the records a finding cites."""
    first = recs[0]["event"]
    rid = first["run_id"]
    run = _node(g, "run:" + rid, "run", rid, ts=first["ts"])
    ran = {r["event"]["data"].get("tool_use_id") for r in recs
           if r["event"]["type"] == "tool.result" and r["event"]["data"].get("ok")}
    by_seq: Dict[int, str] = {}   # run_seq -> the node of the record that brought a value into the run
    asked: Dict[str, str] = {}    # approval id -> the call it is for (a later approval record may not name it)
    unread = 0
    for r in recs:
        e = r["event"]
        t, d, at = e["type"], e.get("data") or {}, _cite(e)
        if t == "run.registered":
            name = (d.get("agent") or {}).get("name") or "main"
            who = d.get("identity") or {}
            _edge(g, ok, _node(g, "agent:" + name, "agent", name), run, "ran", "SIGNED", at,
                  **({"identity": f"{who.get('scheme')}:{who.get('subject')}"} if who else {}))
            if d.get("analyzes"):
                _edge(g, ok, run, _node(g, "run:" + d["analyzes"], "run", d["analyzes"]), "analyses", "SIGNED", at)
        elif t == "run.child" and d.get("run_id"):
            _edge(g, ok, run, _node(g, "run:" + d["run_id"], "run", d["run_id"]), "started", "SIGNED", at)
        elif t == "input.observed":
            by_seq[e["run_seq"]] = _node(g, f"input:{rid}:{e['run_seq']}", "input", str(d.get("source")),
                                         trust=d.get("trust"))
            _edge(g, ok, run, by_seq[e["run_seq"]], "observed " + str(d.get("trust")), "SIGNED", at)
        elif t == "policy.decision":
            # what a call's decision and result were: from verified records only (a node's label is any record's)
            call = _node(g, f"call:{rid}:{d.get('tool_use_id')}", "call", str(d.get("tool")),
                         **({"decision": d.get("decision")} if ok else {}))
            _edge(g, ok, run, call, "decided " + str(d.get("decision")), "SIGNED", at)
            for rule in d.get("rule_ids") or []:
                _edge(g, ok, _node(g, "rule:" + rule, "rule", rule), call, str(d.get("decision")), "SIGNED", at)
            for p in d.get("provenance") or []:
                src = by_seq.get((p.get("source") or {}).get("run_seq"))
                if src:
                    _edge(g, ok, src, call, f"argument {p.get('field')} ({p.get('kind')}), untrusted", "SIGNED", at)
            body = (args or {}).get(e["run_seq"])
            if body is None and d.get("args_commitment"):
                unread += 1
            done = d.get("tool_use_id") in ran   # the call ran and its result says it succeeded
            for p in _written(d.get("tool"), body):
                _edge(g, ok, call, _node(g, "file:" + p, "file", p), "wrote" if done else "asked to write", "SIGNED", at)
            host = _host(body)
            if host:
                _edge(g, ok, call, _node(g, "host:" + host, "host", host), "reached" if done else "asked to reach",
                      "SIGNED", at)
        elif t == "tool.result":
            by_seq[e["run_seq"]] = _node(g, f"call:{rid}:{d.get('tool_use_id')}", "call", "?",
                                         **({"ok": bool(d.get("ok"))} if ok else {}))
        elif t == "approval.request":
            b, aid = d.get("binding") or {}, str(d.get("approval_id"))
            asked[aid] = _node(g, f"call:{rid}:{b.get('tool_call_id')}", "call", str(b.get("tool")))
            _edge(g, ok, asked[aid], _node(g, "approval:" + aid, "approval", f"approval of {b.get('tool')}"),
                  "held for approval", "SIGNED", at, rule_ids=d.get("rule_ids") or [])
        elif t == "approval":
            who = str(d.get("approver"))
            _edge(g, ok, _node(g, "person:" + who, "person", who), _node(g, f"call:{rid}:{d.get('tool_use_id')}",
                                                                          "call", "?"),
                  str(d.get("decision")), "SIGNED", at, self_approved=bool(d.get("self_approved")),
                  **({"wait_ms": d["wait_ms"]} if isinstance(d.get("wait_ms"), int) else {}),
                  **({"approval_id": d["approval_id"]} if d.get("approval_id") else {}))
        elif t.startswith("approval.") and str(d.get("approval_id")) in asked:
            reason = f" ({d['reason']})" if isinstance(d.get("reason"), str) else ""
            _edge(g, ok, "approval:" + str(d["approval_id"]), asked[str(d["approval_id"])],
                  t.split(".", 1)[1] + reason, "SIGNED", at)
        elif t in ("capture.gap", "trace.tamper") or t.startswith("reconcile."):
            what = " ".join(filter(None, [t, d.get("kind")]))
            gap = _node(g, f"gap:{rid}:{e['run_seq']}", "gap", f"{what}: {d.get('reason') or d.get('detail') or ''}"[:300])
            _edge(g, ok, run, gap, "recorded", "SIGNED", at)
        elif t == "effect.observed" and d.get("kind") in ("net", "connect") and d.get("host"):
            _edge(g, ok, run, _node(g, "host:" + d["host"], "host", d["host"]), f"reached :{d.get('port')}",
                  "OBSERVED", at, observer=d.get("observer"),
                  **({"explained_by": d.get("explained_by") or "nothing"} if d["kind"] == "net" else {}))
        elif t == "effect.observed" and d.get("kind") == "file" and d.get("path"):
            _edge(g, ok, run, _node(g, "file:" + d["path"], "file", d["path"]), f"file event ({d.get('sensor')})",
                  "OBSERVED", at, observer=d.get("observer"))
        elif t == "review" and (d.get("verdict") or {}).get("kind") == "finding":
            v, about = d["verdict"], _about(recs)
            f = _node(g, f"finding:{rid}:{e['run_seq']}", "finding",
                      f"{v.get('rule')} ({v.get('severity')}): {v.get('title')}", reviewer=d.get("reviewer"))
            cited = [(c, (index or {}).get((about, c.get("run_seq")))) for c in d.get("cites") or []]
            # a cite whose hash is not its record's names no node: the finding is then about its run
            for n in sorted({_of(g, x["event"]) for c, x in cited if x and x.get("hash") == c.get("hash")}) or [
                    _node(g, "run:" + str(about), "run", str(about))]:
                _edge(g, ok, f, n, "found in", "SIGNED", at)
        elif t == "why.finding":
            about = str(_about(recs))
            f = _node(g, f"finding:{rid}:{e['run_seq']}", "finding",
                      f"why test: without {d.get('intervention')}, {d.get('target')}: {d.get('verdict')}",
                      effect=d.get("effect"))
            _edge(g, ok, f, _node(g, "run:" + about, "run", about), "tested " + str(d.get("verdict")), "SIGNED", at)
        for rule in (d.get("redaction") or {}).get("rules") or []:
            _edge(g, ok, _of(g, e), _node(g, "secret:" + rule, "secret", rule), "held a secret (redacted)", "SIGNED",
                  at)
    if ok and unread:
        g.nodes[run]["unread_args"] = unread


def _add_why(g: Graph, recs: List[Dict[str, Any]], ok: bool, tests=()) -> None:
    """INFERRED edges: tracekit why's causal graph of the run, mapped onto this graph's nodes, and the signed why tests
    about the run (`tests`: (why.finding record, whether its source verified)) whose verdict is causal or
    suppressive, from what the test removed to the calls of its target."""
    from .why.core import load_run
    from .why.graph import build_graph, nodes_matching, target_hits
    from .why.import_v2 import convert
    with tempfile.TemporaryDirectory() as d:
        wrun = load_run(convert(recs, d, {}))
        wg = build_graph(wrun)

        def ours(nid: str) -> Optional[str]:
            ev = wg.nodes[nid]["event"]
            c = ev.get("tracekit") or {}
            if ev["type"] == "action":
                return f"call:{c['run_id']}:{c['tool_call_id']}"
            if ev["type"] == "input":
                return f"input:{c['run_id']}:{c['run_seq']}"
            if ev["type"] == "decision":
                return _node(g, f"model:{c['run_id']}:{c['run_seq']}", "model", str(ev.get("model")))
            return None

        for e in wg.edges:
            if e["kind"].startswith("argument"):   # the signer's provenance: already a SIGNED edge
                continue
            src, dst = ours(e["src"]), ours(e["dst"])
            if src and dst:
                _edge(g, ok, src, dst, e["kind"], "INFERRED", _cite(wg.nodes[e["dst"]]["event"]["tracekit"]),
                      why_evidence=e["evidence"])
        for rec, verified in tests:
            t = rec["event"]["data"]
            if t.get("verdict") not in ("causal", "suppressive"):
                continue
            try:
                srcs = nodes_matching(wg, t["intervention"])
                dsts = ["ev:" + x["id"] for x in target_hits(wrun, t["target"])]
            except (KeyError, ValueError):   # a spec why's graph does not read (text~): the finding stays on its run
                continue
            for s in srcs:
                for x in dsts:
                    a, b = ours(s), ours(x)
                    if a and b:
                        _edge(g, ok and verified, a, b, f"{t['verdict']} (tested)", "INFERRED", _cite(rec["event"]),
                              why_evidence="tested", effect=t.get("effect"))


def _graphify(g: Graph, path: str) -> Dict[str, Any]:
    """The Graphify join: each code node of the Graphify graph at `path` whose `source_file` is a file node's path, or
    its end, linked from that file (INFERRED): what the agents changed, by function and concept. Read-only.
    lean: Graphify's own edges (calls, imports) are left out; add them when a query must reach past the file"""
    with open(path, "rb") as f:
        data = f.read()
    top = json.loads(data)
    if not (isinstance(top, dict) and isinstance(top.get("nodes"), list)):
        raise ValueError(f"{path} is not a Graphify graph.json (it has no list of nodes); pass --graphify '' to build "
                         "without it")
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for n in top["nodes"]:
        sf = n.get("source_file") if isinstance(n, dict) else None
        if isinstance(sf, str) and sf.strip("./") and n.get("id") is not None:
            by_file.setdefault(sf.replace("\\", "/").removeprefix("./"), []).append(n)
    linked = 0
    for f in sorted((n for n in g.nodes.values() if n["kind"] == "file"), key=lambda n: n["id"]):
        sf = max((s for s in by_file if f["label"] == s or f["label"].endswith("/" + s)), key=len, default=None)
        for n in sorted(by_file.get(sf or "", ()), key=lambda n: str(n["id"])):
            loc = n.get("source_location")
            code = _node(g, f"code:{n['id']}", "code", str(n.get("label") or n["id"]), source_file=sf,
                         **({"source_location": loc} if isinstance(loc, str) else {}))
            g.add_edge(f["id"], code, "contains", "INFERRED", record={"graphify": path, "source_file": sf})
            linked += 1
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "linked": linked}


def build(paths: List[str], trust: str, content: Optional[Content] = None,
          graphify: Optional[str] = None) -> Dict[str, Any]:
    """graph.json's document from v2 bundles `paths`, each verified against trust config `trust`. `content`: a run's
    decided arguments (vault()), read for verified runs only; `graphify`: a Graphify graph.json to join. Verified
    sources go first, so that a node's label comes from a verified record wherever one has it, and findings runs after
    the runs they are about."""
    read = sorted((_read(p, trust) for p in paths), key=lambda s: (not s[0]["verify"]["ok"], s[0]["path"]))
    runs = sorted(((src, rs[rid]) for src, rs in read for rid in sorted(rs)), key=lambda x: bool(_about(x[1])))
    index: Dict[tuple, Dict[str, Any]] = {}
    tests: Dict[str, List[tuple]] = {}   # run_id -> the why.finding records about it
    for src, recs in runs:
        for r in recs:
            index.setdefault((r["event"]["run_id"], r["event"]["run_seq"]), r)
            if r["event"]["type"] == "why.finding" and _about(recs):
                tests.setdefault(str(_about(recs)), []).append((r, src["verify"]["ok"]))
    g = Graph(None)  # type: ignore[arg-type]
    for src, recs in runs:
        ok, rid = src["verify"]["ok"], recs[0]["event"]["run_id"]
        args = None
        if content and ok:
            try:
                args = content(rid, recs)
            except Exception as e:   # the vault's content does not open its record, or the signer gives none
                src.setdefault("content_unread", []).append(f"run {rid}: {type(e).__name__}: {e}")
        try:
            _add_run(g, recs, ok, args, index)
            _add_why(g, recs, ok, tests.get(rid, ()))
        except Exception as e:   # a record an unverified bundle mangled: what was read is kept, the rest named
            src.setdefault("unread_runs", []).append(f"{rid}: {type(e).__name__}: {e}")
    joined = _graphify(g, graphify) if graphify else None
    with open(trust, "rb") as f:
        trust_sha256 = hashlib.sha256(f.read()).hexdigest()
    return {"schema_version": SCHEMA_VERSION, "tracekit": __version__, "trust_sha256": trust_sha256,
            "content": bool(content), "graphify": joined, "sources": [s for s, _ in read],
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


def _run_of(e: Dict[str, Any]) -> Optional[str]:
    return (e.get("record") or {}).get("run_id")   # None: a Graphify edge


def _n(k: int, word: str) -> str:
    return f"{k} {word}{'' if k == 1 else 's'}"


# --------------------------------------------------------------------------- report

def report(doc: Dict[str, Any]) -> str:
    """GRAPH_REPORT.md: what can't be trusted first (unverified sources, gaps, arguments not read), then the files
    changed most, sensitive files, hosts, approvals, secrets, findings and causal chains, every number from the graph."""
    g = _graph(doc)
    nodes = g.nodes

    def lab(n: str) -> str:
        return nodes[n]["label"]

    def of(kind: str) -> List[str]:
        return sorted(n for n, v in nodes.items() if v["kind"] == kind)

    def grades(es: List[Dict[str, Any]]) -> str:
        c = Counter(e["evidence"] for e in es)
        return ", ".join(f"{c[k]} {k}" for k in GRADES if c[k])

    def runs(es: List[Dict[str, Any]]) -> List[str]:
        return sorted({r for e in es if (r := _run_of(e))})

    def agents(rid: str) -> str:
        return ", ".join(sorted({lab(e["src"]) for e in g.in_edges("run:" + rid, GRADES)
                                 if nodes[e["src"]]["kind"] == "agent"})) or "?"

    def approvers(call: str) -> List[Dict[str, Any]]:
        return [e for e in g.in_edges(call, GRADES) if nodes[e["src"]]["kind"] == "person"]

    def by_person(call: str) -> bool:   # a person other than the run's own identity approved it, on a verified record
        return any(e["kind"] == "approve" and not e.get("self_approved") and e["evidence"] == "SIGNED"
                   for e in approvers(call))

    def called(n: str) -> str:   # a call with its decision
        return lab(n) + (f" ({nodes[n]['decision']})" if nodes[n].get("decision") else "")

    def where(n: str) -> str:   # a node as a reader finds it: a run by its id, anything else with its run
        return "run " + lab(n) if nodes[n]["kind"] == "run" else called(n) + (
            f" in run {n.split(':')[1]}" if nodes[n]["kind"] in ("call", "input", "model", "finding", "gap") else "")

    def capped(lines: List[str], what: str) -> List[str]:
        return lines[:TOP] + ([f"and {len(lines) - TOP} more {what} (graph.json has them all)"] if len(lines) > TOP
                              else [])

    bad = [s for s in doc["sources"] if not s["verify"]["ok"]]
    unread = [n for n in of("run") if nodes[n].get("unread_args")]
    first = (
        [f"{s['path']}: {s['verify']['integrity']} ({', '.join(s['verify']['failures'])}): every edge from it is "
         "UNVERIFIED" for s in bad]
        + [f"{s['path']}: {p}" for s in doc["sources"]
           for p in [s.get("unreadable")] + s.get("unread_runs", []) + s.get("content_unread", []) if p]
        + [f"run {e['record']['run_id']}: {lab(e['dst'])} (record {e['record']['run_seq']}, {e['evidence']})"
           for e in doc["edges"] if nodes[e["dst"]]["kind"] == "gap"]
        + ([f"{_n(sum(nodes[n]['unread_args'] for n in unread), 'call')} in {_n(len(unread), 'run')}: their "
            "arguments were not read, so the files they wrote and the hosts they named are not in the graph"
            + ("" if doc.get("content") else " (build with --content, against the signer that recorded them)")]
           if unread else []))

    # lean: a kernel sensor's file event and the call that made it are two writes; join them when sensors are common
    writes = {f: [e for e in g.in_edges(f, GRADES) if e["kind"] == "wrote" or e["kind"].startswith("file event")]
              for f in of("file")}
    tried = {f: [e for e in g.in_edges(f, GRADES) if e["kind"] == "asked to write"] for f in of("file")}
    files = []
    for f in sorted(writes, key=lambda f: (-len(writes[f]), -len(tried[f]), f)):
        es, calls = writes[f], sorted({e["src"] for e in writes[f] if e["kind"] == "wrote"})
        files.append(f"{lab(f)}: " + (f"written {_n(len(es), 'time')} in {_n(len(runs(es)), 'run')} ({grades(es)})"
                                      if es else "not written")
                     + (f"; calls that wrote it: {len(calls)}, without a person's approval: "
                        f"{sum(not by_person(c) for c in calls)}" if calls else "")
                     + (f"; calls that asked to write it and did not run: {len(tried[f])} ({grades(tried[f])})"
                        if tried[f] else ""))

    sensitive = []
    for f in of("file"):
        for w in sorted(writes[f] + tried[f], key=lambda e: (e["src"], e["evidence"])):
            rules = [e for e in g.in_edges(w["src"], GRADES) if nodes[e["src"]]["kind"] == "rule"]
            if rules:
                who = [f"{lab(a['src'])} {a['kind']}d it ({a['evidence']}"
                       + (", self-approved)" if a.get("self_approved") else ")") for a in approvers(w["src"])]
                sensitive.append(f"{lab(f)}: {where(w['src'])} {w['kind']} it ({w['evidence']}) under "
                                 + ", ".join(f"{lab(e['src'])} {e['kind']} ({e['evidence']})" for e in rules) + "; "
                                 + ("; ".join(who) if who else "it ran with no person's approval"
                                    if nodes[w["src"]].get("ok") else "it did not run"))

    hosts = []
    for h in sorted(of("host"), key=lambda h: (-len(runs(g.in_edges(h, GRADES))), h)):
        es = g.in_edges(h, GRADES)
        hosts.append(f"{lab(h)}: " + "; ".join(
            f"run {r} (agent {agents(r)}): " + ", ".join(
                f"{'the run' if nodes[e['src']]['kind'] == 'run' else lab(e['src'])} {e['kind']} ({e['evidence']}"
                + (f", explained by {e['explained_by']}" if "explained_by" in e else "") + ")"
                for e in es if _run_of(e) == r) for r in runs(es)))

    def approvals(p: str) -> str:
        es = g.out_edges(p, GRADES)
        waits = [e["wait_ms"] for e in es if "wait_ms" in e]
        return (", ".join(f"{n} {k}" for k, n in sorted(Counter(e["kind"] for e in es).items()))
                + (f", median wait {statistics.median(waits):g} ms" if waits else ", no wait recorded")
                + (f", {sum(bool(e.get('self_approved')) for e in es)} self-approved (the approver is the run's own "
                   "identity)" if any(e.get("self_approved") for e in es) else "")
                + (f" ({grades(es)})" if any(e["evidence"] != "SIGNED" for e in es) else ""))

    fates = [f"{lab(a)} in run {_run_of(e)}: {e['kind']} ({e['evidence']})" for a in of("approval")
             for e in g.out_edges(a, GRADES) if not e["kind"].startswith("consumed")]

    chains = []
    for i in (n for n in of("input") if nodes[n].get("trust") == "untrusted"):
        parent = g.descendants([i], ("SIGNED", "INFERRED"))
        reached = [n for n in sorted(parent) if nodes[n]["kind"] in ("call", "file", "host") and n != i]
        if reached:
            chains.append(f"untrusted {lab(i)} in run {i.split(':')[1]} reached {_n(len(reached), 'node')}: " + "; ".join(
                " -> ".join(called(x) for x in Graph.path(parent, n)) for n in reached))
    chains += [f"run {lab(e['src'])} {e['kind']} run {lab(e['dst'])} ({e['evidence']})" for e in doc["edges"]
               if nodes[e["src"]]["kind"] == "run" and nodes[e["dst"]]["kind"] == "run"]
    chains += [f"{lab(f)} was written by {_n(len(runs(es)), 'run')}: {', '.join(runs(es))}" for f, es in writes.items()
               if len(runs(es)) > 1]

    sections = {
        "Read first: unverified sources, gaps and what was not read": first,
        "Files agents changed most": capped(files, "files"),
        "Sensitive files: written by calls a rule flagged, held or denied": sensitive,
        "Hosts reached, by run and agent": capped(hosts, "hosts"),
        "Approvals by person": [f"{lab(p)}: {approvals(p)}" for p in of("person")] + fates,
        "Secrets (by the name of the rule that redacted them)": [
            f"{lab(s)}: in {_n(len(runs(es)), 'run')}, held by " + ", ".join(sorted({where(e['src']) for e in es}))
            + f" ({grades(es)})" for s in of("secret") for es in [g.in_edges(s, GRADES)]],
        "Findings": [f"{lab(f)}: about " + ", ".join(sorted({where(e['dst']) for e in es})) + f" ({grades(es)})"
                     for f in of("finding") for es in [g.out_edges(f, GRADES)]],
        "Causal chains (why) and runs linked to other runs": chains,
    }
    c = Counter(e["evidence"] for e in doc["edges"])
    gf = doc.get("graphify")
    out = [f"# Tracekit graph report\n\n{_n(len(doc['sources']), 'source')} ({len(bad)} failed verification), "
           f"{_n(len(of('run')), 'run')}, {len(doc['nodes'])} nodes, {len(doc['edges'])} edges: "
           + (", ".join(f"{c[k]} {k}" for k in GRADES if c[k]) or "none") + ". "
           + ("Call arguments were read from the signer's content vault. " if doc.get("content") else
              "Call arguments were not read (no --content). ")
           + (f"Graphify: {gf['path']}, {gf['linked']} code nodes linked. " if gf else "")
           + f"Built by tracekit {doc['tracekit']}; every line cites its grade, and graph.json cites each record."]
    for title, lines in sections.items():
        out.append(f"\n## {title}\n\n" + "\n".join(f"- {x}" for x in lines or ["none"]))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- query

def matching(doc: Dict[str, Any], kind: str, needle: str) -> Dict[str, Any]:
    """The runs that touched a node of `kind` labelled `needle` (a file also by its last path parts; code: the files
    Graphify places it in), newest first: each run's agents, approvers, approvals, rules, hosts, files, secrets,
    findings and gaps, and the edges to the matched nodes; `code`: the Graphify code nodes in the matched files."""
    g = _graph(doc)
    hits = sorted(n for n, v in g.nodes.items() if v["kind"] == kind
                  and (v["label"] == needle or kind == "file" and v["label"].endswith("/" + needle.lstrip("/"))))
    files = sorted({e["src"] for h in hits for e in g.in_edges(h, GRADES)}) if kind == "code" else hits
    touching = [e for h in files for e in g.in_edges(h, GRADES) + g.out_edges(h, GRADES) if _run_of(e)]
    by_run: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for e in g.edges:
        by_run.setdefault(_run_of(e), []).append(e)
    runs = sorted({_run_of(e) for e in touching}, key=lambda r: (g.nodes.get(f"run:{r}", {}).get("ts", ""), r),
                  reverse=True)
    out = []
    for rid in runs:
        es = by_run[rid]
        facts = {k: [e for e in es if g.nodes[e["src"]]["kind"] == k or g.nodes[e["dst"]]["kind"] == k] for k in FACTS}
        out.append({"run": rid, "ts": g.nodes.get(f"run:{rid}", {}).get("ts"), **facts,
                    "matched": [e for e in touching if _run_of(e) == rid]})
    code = sorted({e["dst"] for f in files for e in g.out_edges(f, GRADES) if g.nodes[e["dst"]]["kind"] == "code"})
    return {"matched": hits, "code": [g.nodes[n] for n in code], "runs": out}


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
    where = f"run {r['run_id']} record {r['run_seq']}" if "run_id" in r else f"Graphify {r.get('source_file')}"
    return f"  {e['evidence']:<10} {g[e['src']]['label']} -{e['kind']}-> {g[e['dst']]['label']}  ({where})"


def write(doc: Dict[str, Any], out: str) -> None:
    os.makedirs(out, exist_ok=True)
    for name, text in ((GRAPH, dumps(doc)), (REPORT, report(doc))):
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def verify(out: str, trust: str, content: Optional[Content] = None) -> List[str]:
    """What differs between DIR's files and the ones its sources give now ([] when nothing does). `content`: the vault
    reader, used when graph.json was built with call arguments from it."""
    with open(os.path.join(out, GRAPH), encoding="utf-8") as f:
        have = json.load(f)
    gf = have.get("graphify")
    doc = build([s["path"] for s in have["sources"]], trust, content if have.get("content") else None,
                gf and gf["path"])
    listed = {s["path"]: s["sha256"] for s in have["sources"]}
    problems = [f"{s['path']}: its digest is not the one graph.json lists" for s in doc["sources"]
                if s["sha256"] != listed[s["path"]]]
    if gf and doc["graphify"]["sha256"] != gf["sha256"]:
        problems.append(f"{gf['path']}: the Graphify graph changed since the build")
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
    p.add_argument("--content", action="store_true",
                   help="read each call's decided arguments from the signer's content vault ($TRACEKIT_SIGNER, else "
                        "the dev signer; each read is recorded), for the files calls wrote and the hosts they reached")
    p.add_argument("--graphify", default=GRAPHIFY if os.path.exists(GRAPHIFY) else "",
                   help=f"a Graphify graph.json whose code nodes to link to the files (default: {GRAPHIFY} when it "
                        "exists; '' for none)")
    p.add_argument("-o", "--out", default="tracekit-graph")
    p = sub.add_parser("query", help="runs that touched a file, host, agent, approver, rule, secret or code node; "
                                     "--blast; --path")
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
    from .sdk.client import SignerUnavailable
    from .signer.rpc_schema import RPCError
    from .verify import v2
    try:
        if a.cmd in ("build", "verify"):
            v2.load_trust(a.trust)   # a bad trust config would mark every source UNVERIFIED: refuse it instead
        if a.cmd == "build":
            doc = build(a.sources, a.trust, vault() if a.content else None, a.graphify or None)
            write(doc, a.out)
            bad = [s["path"] for s in doc["sources"] if not s["verify"]["ok"]]
            unread = sum(n.get("unread_args", 0) for n in doc["nodes"])
            print(f"wrote {os.path.join(a.out, GRAPH)} and {REPORT}: {len(doc['nodes'])} nodes, {len(doc['edges'])} "
                  "edges" + (f"; UNVERIFIED (failed verification): {', '.join(bad)}" if bad else "")
                  + (f"; {unread} calls' arguments not read" + ("" if a.content else " (pass --content)")
                     if unread else ""))
            return 0
        if a.cmd == "verify":
            problems = verify(a.dir, a.trust, vault())
            print("\n".join(problems) or f"{a.dir}: graph.json and {REPORT} are what their sources give")
            return 1 if problems else 0
        with open(os.path.join(a.dir, GRAPH), encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError, SignerUnavailable, RPCError) as e:
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
            text += [f"code in these files (Graphify): {n['label']} ("
                     + " ".join(filter(None, (n["source_file"], n.get("source_location")))) + ")" for n in res["code"]]
    except ValueError as e:
        print(f"tracekit graph: {e}", file=sys.stderr)
        return 2
    print(json.dumps(res, sort_keys=True, indent=1, ensure_ascii=False) if a.json else "\n".join(text))
    return 0 if res.get("matched", res.get("found", True)) else 1


if __name__ == "__main__":
    sys.exit(main())
