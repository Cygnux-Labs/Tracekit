"""`tracekit graph`: what agents did across runs, as one queryable graph built only from Tracekit's records.

    tracekit graph build RUN.tkb... --trust trust.json [--content] [--graphify FILE] [-o tracekit-graph]
    tracekit graph query [DIR] --file billing.py | --host H | --agent A | --approved-by P | --rule TK-... |
                               --secret NAME | --code NAME [--json]
    tracekit graph query [DIR] --blast NODE | --path NODE NODE [--json]
    tracekit graph verify [DIR] SOURCES... --trust trust.json  # rebuilt from its sources and compared, byte for byte

Nodes: run, agent, person (an approver), call, input, model (a model call), file, host, secret (the name of the
redaction rule that caught it, never the value), rule, finding, approval, gap, and code (a Graphify node). Every edge
has a grade (`grade`) and cites the record it came from (`record`: run_id, run_seq, seq, ts):

    SIGNED      the signer's record says so: agent ran run, run decided call, rule held or denied call; a T2 executor
                or gateway result says a call wrote a file or reached a host; an agent completion report says it
                reported writing or reaching (--content: the arguments the signer's content vault holds, each opening
                its record's commitment); call held for approval and what became of the approval,
                person approved or rejected call, run, input or call held a secret the signer redacted, an untrusted
                input supplied a call's argument, run recorded a gap, run started or analyses run, a signed finding
                about a record
    OBSERVED    an observer outside the agent saw it: egress hosts, kernel sensor connections and files; a run's, never
                a call's (the call id a process carries is the agent's claim)
    INFERRED    tracekit why's causal graph of the run and the signed why tests about it the verifier counts
                (why.finding; `author`, its author's label), why's own grade kept (`why_evidence`); and the Graphify
                join (`join`: "graphify"): a code node in a file the graph has (`record` names the Graphify file)
    UNVERIFIED  any of these from a bundle that fails verification against the trust config, or a Graphify join for a
                file named only by failed bundles (`claimed`: the grade it would have): kept, never dropped

build writes FILES: graph.json and its highlights as data (GRAPH_REPORT.json) and as Markdown (GRAPH_REPORT.md).
Sources and Graphify input are recorded by digest and file name, so `verify DIR SOURCES...` can find moved bundles. A
query's --json answer also carries `map`, the answer as the viewer draws it (_drawn). The same sources, trust config, vault
content and Graphify graph give the same files byte for byte; no network, no model.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import statistics
import sys
import tempfile
import unicodedata
from collections import Counter, deque
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .why.graph import Graph

GRADES = ("SIGNED", "OBSERVED", "INFERRED", "UNVERIFIED")
SCHEMA_VERSION = 1
GRAPH, REPORT_JSON, REPORT = "graph.json", "GRAPH_REPORT.json", "GRAPH_REPORT.md"
FILES = (GRAPH, REPORT_JSON, REPORT)
GRAPHIFY = os.path.join("graphify-out", "graph.json")
FILTERS = {"file": "file", "host": "host", "agent": "agent", "approved_by": "person", "rule": "rule",
           "secret": "secret", "code": "code"}
# what a query shows of each run it finds
FACTS = ("agent", "person", "approval", "rule", "host", "file", "secret", "finding", "gap")
TOP = 20   # lean: the files and hosts GRAPH_REPORT.md lists; graph.json has them all
Content = Callable[[str, List[Dict[str, Any]]], Dict[int, Any]]
MAX_SOURCE_BYTES = 512 * 1024 * 1024


# --------------------------------------------------------------------------- sources

def _graph_data(e: Dict[str, Any]) -> None:
    """Reject nested event shapes that graph building reads as objects, lists, or string node ids."""
    d, t = e.get("data") or {}, e["type"]

    def obj(value: Any, name: str) -> None:
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"{t} data.{name} must be an object")

    def strings(value: Any, name: str) -> None:
        if value is not None and (not isinstance(value, list) or not all(isinstance(x, str) for x in value)):
            raise ValueError(f"{t} data.{name} must be a list of strings")

    def string(value: Any, name: str) -> None:
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{t} data.{name} must be a string")

    def integer(value: Any, name: str) -> None:
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError(f"{t} data.{name} must be an integer")

    if t == "run.registered":
        obj(d.get("agent"), "agent")
        obj(d.get("identity"), "identity")
        if isinstance(d.get("agent"), dict):
            string(d["agent"].get("name"), "agent.name")
        string(d.get("analyzes"), "analyzes")
        string(d.get("replay_of"), "replay_of")
    elif t == "run.child":
        string(d.get("run_id"), "run_id")
    elif t == "why.finding":
        for k in ("replay_runs", "uncounted"):   # the replay runs it names (_named_runs)
            arms = d.get(k)
            if arms is not None and (not isinstance(arms, list) or not all(
                    isinstance(x, dict) and isinstance(x.get("run_id"), str) for x in arms)):
                raise ValueError(f"why.finding data.{k} must be a list of objects with a string run_id")
    elif t == "policy.decision":
        strings(d.get("rule_ids"), "rule_ids")
        if not isinstance(d.get("decision_id"), str):   # its call's identity (_calls): the signer writes one always
            raise ValueError("policy.decision data.decision_id must be a string")
        provenance = d.get("provenance")
        if provenance is not None:
            if not isinstance(provenance, list) or not all(isinstance(p, dict) for p in provenance):
                raise ValueError("policy.decision data.provenance must be a list of objects")
            for p in provenance:
                obj(p.get("source"), "provenance.source")
                if isinstance(p.get("source"), dict):
                    integer(p["source"].get("run_seq"), "provenance.source.run_seq")
    elif t == "approval.request":
        obj(d.get("binding"), "binding")
        strings(d.get("rule_ids"), "rule_ids")
        string(d.get("decision_id"), "decision_id")
    elif t == "tool.result":
        string(d.get("decision_id"), "decision_id")
    elif t == "effect.observed":
        string(d.get("host"), "host")
        string(d.get("path"), "path")
    elif t == "review":
        obj(d.get("verdict"), "verdict")
        cites = d.get("cites")
        if cites is not None and (not isinstance(cites, list) or not all(isinstance(c, dict) for c in cites)):
            raise ValueError("review data.cites must be a list of objects")
        for cite in cites or []:
            integer(cite.get("run_seq"), "cites.run_seq")
    redaction = d.get("redaction")
    obj(redaction, "redaction")
    if isinstance(redaction, dict):
        strings(redaction.get("rules"), "redaction.rules")


def _secure_source(path: str) -> bytes:
    """Read a verify source through one descriptor, refusing an unsafe final component: the file opened must be the
    regular file lstat saw (same device and inode), so a swap to a symlink between the two is refused also where
    O_NOFOLLOW doesn't exist (Windows).
    lean: a Windows file system that reports no file id (st_ino 0: FAT, some network shares) can't tell two files
    apart, so a swap there between the check and the open goes unseen; the digest check still fails a swapped-in file
    with other content. Read through a handle opened with FILE_FLAG_OPEN_REPARSE_POINT if that matters there"""
    seen = os.lstat(path)
    if not stat.S_ISREG(seen.st_mode):
        raise OSError(f"{path}: source is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (seen.st_dev, seen.st_ino):
            raise OSError(f"{path}: source is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError(f"{path}: source is more than {MAX_SOURCE_BYTES // (1024 * 1024)} MiB")
        return data
    finally:
        os.close(fd)

def _runs(data: bytes) -> Dict[str, List[Dict[str, Any]]]:
    """run_id -> records of the v2 bundle `data`, unverified."""
    from .bundle_v2 import run_files
    from .verify import v2
    files = v2.read_zip(io.BytesIO(data))
    runs = {}
    for parts in run_files(files).values():
        recs = [r for n in parts for r in v2._jsonl(files[n])]
        if not recs:
            raise ValueError("a run has no records")
        for r in recs:
            e = r.get("event") if isinstance(r, dict) else None
            if not (isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("run_id", "type", "ts", "tenant",
                                                                                     "log_id"))
                    and all(isinstance(e.get(k), int) and not isinstance(e[k], bool) for k in ("run_seq", "seq"))
                    and ("data" not in e or isinstance(e["data"], dict))):
                raise ValueError("a record must have string run_id, type, ts, tenant and log_id, integer run_seq and "
                                 "seq, and object data")
            _graph_data(e)
        # as the verifier's run chain: one run per file, every record naming it (else a citation names no run node)
        run = [(e["log_id"], e["tenant"], e["run_id"]) for e in (r["event"] for r in recs)]
        if run.count(run[0]) != len(run) or run[0][2] in runs:
            raise ValueError(f"run {run[0][2]!r}: a run file holds another run's records, or two files hold the run")
        runs[run[0][2]] = recs
    return runs


def _read(path: str, trust: str, data: Optional[bytes] = None):
    """(source entry, run_id -> records) of v2 bundle `path`, read once: its records are read even when it fails
    verification, so that its edges are marked UNVERIFIED rather than dropped."""
    from .verify import v2
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    rep, code = v2.verify(io.BytesIO(data), trust)
    src: Dict[str, Any] = {"name": os.path.basename(path), "sha256": hashlib.sha256(data).hexdigest(),
                           "verify": {"ok": code == 0, "integrity": rep.integrity, "failures": rep.failures}}
    runs: Dict[str, List[Dict[str, Any]]] = {}
    try:
        runs = _runs(data)
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
    if n["label"] == "?" and label != "?":
        n["label"] = label
    for k, v in attrs.items():   # a node first named by another run (a child run, an analysed one) gets its own later
        n.setdefault(k, v)
    return nid


def _cite(e: Dict[str, Any]) -> Dict[str, Any]:
    return {"run_id": e["run_id"], "run_seq": e["run_seq"], "seq": e["seq"], "ts": e["ts"]}


def _edge(g: Graph, ok: bool, src: str, dst: str, kind: str, grade: str, cite: Dict[str, Any], **extra: Any) -> None:
    g.add_edge(src, dst, kind, grade if ok else "UNVERIFIED", record=cite, **extra,
               **({} if ok else {"claimed": grade}))


def _calls(recs: List[Dict[str, Any]], args: Optional[Dict[int, Any]] = None) -> Dict[str, str]:
    """decision id -> its call node, call:RUN:DECISION_ID, of one run's records: a node per decision, since an agent may
    reuse a tool call id for another action. A decision made again under the same tool call id and attempt with the
    same decided arguments (`args`, opened from the vault) is the same action, its first decision's node: LangGraph
    decides again on resume, and the signer's one approval of a call attempt covers both."""
    calls: Dict[str, str] = {}
    first: Dict[tuple, str] = {}
    for r in recs:
        e = r["event"]
        if e["type"] == "policy.decision":
            did, body = e["data"]["decision_id"], (args or {}).get(e["run_seq"])
            calls[did] = f"call:{e['run_id']}:{did}" if body is None else first.setdefault(
                (e["data"].get("tool_use_id"), e.get("attempt"), _args_digest(body)), f"call:{e['run_id']}:{did}")
    return calls


def _of(g: Graph, e: Dict[str, Any], calls: Optional[Dict[str, str]] = None) -> str:
    """The node of record `e`: its decision's call for a decision or result (`calls`: _calls of its run), its
    approval's for an approval, its input's, else its run's."""
    d = e.get("data") or {}
    did = d.get("decision_id") if e["type"] in ("policy.decision", "tool.result") else None
    nid = ((calls or {}).get(did) or f"call:{e['run_id']}:{did}" if did
           else "approval:" + str(d.get("approval_id")) if e["type"] == "approval"
           else f"input:{e['run_id']}:{e['run_seq']}" if e["type"] == "input.observed" else "")
    committed = getattr(g, "_committed_nodes", {})
    for n in (nid, "run:" + e["run_id"]):
        if n and n not in g.nodes and n in committed:   # another source's node: into this source's overlay, so an
            g.nodes[n] = dict(committed[n])               # edge to it isn't dropped
        if n and n in g.nodes:
            return n
    return "run:" + e["run_id"]


def _about(recs: List[Dict[str, Any]]) -> Optional[str]:
    """The run a findings run analyses, or None."""
    first = recs[0]["event"]
    return (first.get("data") or {}).get("analyzes") if first["type"] == "run.registered" else None


def _named_runs(recs: List[Dict[str, Any]]) -> List[str]:
    """The run ids one run's records name: its own, the run it analyses or replays, its child runs and its why tests'
    replay runs, all of its tenant."""
    first = recs[0]["event"]
    replays = (first.get("data") or {}).get("replay_of") if first["type"] == "run.registered" else None
    children = [(r["event"].get("data") or {}).get("run_id") for r in recs if r["event"]["type"] == "run.child"]
    arms = [x["run_id"] for r in recs if r["event"]["type"] == "why.finding"
            for k in ("replay_runs", "uncounted") for x in (r["event"].get("data") or {}).get(k) or ()]
    return [x for x in [first["run_id"], _about(recs), replays, *children, *arms] if x]


def _qualified(recs: List[Dict[str, Any]], shared: set) -> List[Dict[str, Any]]:
    """`recs` as the graph names runs: each run id they name (_named_runs) that runs of other tenants or logs have too
    (`shared`) as RUN_ID@TENANT@LOG_ID; `recs` itself when they name none."""
    first = recs[0]["event"]
    if not shared.intersection(_named_runs(recs)):
        return recs

    def name(rid: str) -> str:
        return f"{rid}@{first.get('tenant')}@{first.get('log_id')}" if rid in shared else rid
    out = []
    for r in recs:
        e = dict(r["event"], run_id=name(r["event"]["run_id"]))
        d = e.get("data") or {}
        if e["type"] == "run.registered" and (d.get("analyzes") or d.get("replay_of")):
            e["data"] = dict(d, **{k: name(d[k]) for k in ("analyzes", "replay_of") if d.get(k)})
        elif e["type"] == "run.child" and d.get("run_id"):
            e["data"] = dict(d, run_id=name(d["run_id"]))
        elif e["type"] == "why.finding":   # _counted finds its replay runs by these ids
            e["data"] = dict(d, **{k: [dict(x, run_id=name(x["run_id"])) for x in d[k]]
                                   for k in ("replay_runs", "uncounted") if d.get(k)})
        out.append(dict(r, event=e))
    return out


def _written(tool: Any, args: Any) -> List[str]:
    """The paths call (`tool`, `args`) writes as its decided arguments say: a write tool's path and `paths`, a shell
    command's targets as far as the policy engine's parser reads them (constraints.shell), each as path rules match it.
    lean: write tools by name (findings.WRITE_TOOLS), not by the policy's fs class; a relative path stays relative;
    gateway MCP tools are recognized by their final tool name, but other tool namespaces are not"""
    from .constraints import shell
    from .findings import WRITE_TOOLS
    from .policy2.classes import PATH_KEYS, SHELL_KEYS, first, fs_path
    if not isinstance(args, dict):
        return []
    if tool in WRITE_TOOLS or isinstance(tool, str) and tool.startswith("mcp:") and tool.rsplit("/", 1)[-1] in WRITE_TOOLS:
        paths = [first(args, *PATH_KEYS), *(args["paths"] if isinstance(args.get("paths"), list) else ())]
    elif any(args.get(k) is not None for k in SHELL_KEYS):
        paths = shell(args)["paths"]
    else:
        return []
    return sorted({fs_path(p) for p in paths if isinstance(p, str) and p})


def _host(args: Any) -> Optional[str]:
    """The host of a call's `url` argument, as the policy engine reads it. lean: not a shell command's hosts or an
    executor action's contacted url_template host"""
    from .policy2.classes import url_info
    url = args.get("url") if isinstance(args, dict) else None
    return url_info(url).get("host") if isinstance(url, str) else None


def _args_digest(args: Any) -> str:
    """The opened arguments of a call, as build compares them (_calls, _supersede); never written out: unsalted, it
    would test guesses of what the bundle's salted commitment hides."""
    return hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _add_run(g: Graph, recs: List[Dict[str, Any]], ok: bool, args: Optional[Dict[int, Any]] = None,
             index: Optional[Dict[tuple, Dict[str, Any]]] = None, counted: Optional[Dict[tuple, str]] = None) -> None:
    """The nodes and SIGNED and OBSERVED edges of one run's records. `args`: run_seq -> the decided arguments of a
    call, opened against its record's commitment (None: none were read); `index`: (run_id, run_seq) -> record of every
    run read, for the records a finding cites; `counted`: the why tests the verifier counts (_counted)."""
    first = recs[0]["event"]
    rid = first["run_id"]
    run = _node(g, "run:" + rid, "run", rid, ts=first["ts"])
    results = {r["event"]["data"]["decision_id"]: r["event"] for r in recs
               if r["event"]["type"] == "tool.result" and r["event"]["data"].get("ok")
               and r["event"]["data"].get("decision_id")}
    calls = _calls(recs, args)
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
            call = _node(g, calls[d["decision_id"]], "call", str(d.get("tool")), tool_use_id=d.get("tool_use_id"),
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
            result = results.get(d["decision_id"]) if d.get("decision_id") else None
            done = result is not None
            attested = bool(result and result.get("tier") == "T2")
            result_at = _cite(result) if result else at
            for p in _written(d.get("tool"), body):
                _edge(g, ok, call, _node(g, "file:" + p, "file", p),
                      "wrote" if attested else "reported writing" if done else "asked to write", "SIGNED",
                      result_at, _args=_args_digest(body),
                      **({"args_commitment": d["args_commitment"]} if d.get("args_commitment") else {}))
            host = _host(body)
            if host:
                _edge(g, ok, call, _node(g, "host:" + host, "host", host),
                      "reached" if attested else "reported reaching" if done else "asked to reach", "SIGNED", result_at,
                      _args=_args_digest(body),
                      **({"args_commitment": d["args_commitment"]} if d.get("args_commitment") else {}))
        elif t == "tool.result" and d.get("decision_id") in calls:   # its decision's, as the verifier joins them
            by_seq[e["run_seq"]] = _node(g, calls[d["decision_id"]], "call", "?",
                                         **({"ok": bool(d.get("ok"))} if ok else {}))
        elif t == "approval.request":   # for the decision it binds; an approval record names only a tool call id
            b, aid = d.get("binding") or {}, str(d.get("approval_id"))
            asked[aid] = calls.get(d.get("decision_id"), run)
            _edge(g, ok, asked[aid], _node(g, "approval:" + aid, "approval", f"approval of {b.get('tool')}"),
                  "held for approval", "SIGNED", at, rule_ids=d.get("rule_ids") or [])
        elif t == "approval":
            who = str(d.get("approver"))
            _edge(g, ok, _node(g, "person:" + who, "person", who), asked.get(str(d.get("approval_id")), run),
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
            _edge(g, ok, run, _node(g, "host:" + d["host"], "host", d["host"]),
                  f"blocked from reaching :{d.get('port')}" if d.get("denied") else f"reached :{d.get('port')}",
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
            cited_nodes = set()
            for c, x in cited:
                if not x or x.get("hash") != c.get("hash"):
                    continue
                # lean: without the cited run's vault arguments, a decision made again (_calls: its first decision's
                # call) names no node, so the finding is about the run; pass that run's _calls if findings cite those
                cited_nodes.add(_of(g, x["event"]))
            for n in sorted(cited_nodes) or [
                    _node(g, "run:" + str(about), "run", str(about))]:
                _edge(g, ok, f, n, "found in", "SIGNED", at)
        elif t == "why.finding":
            about, author = str(_about(recs)), (counted or {}).get((rid, e["run_seq"]))
            f = _node(g, f"finding:{rid}:{e['run_seq']}", "finding",
                      f"why test: without {d.get('intervention')}, {d.get('target')}: {d.get('verdict')} "
                      f"({author or 'not counted'})", effect=d.get("effect"), **({"author": author} if author else {}))
            _edge(g, ok, f, _node(g, "run:" + about, "run", about), "tested " + str(d.get("verdict")), "SIGNED", at)
        for rule in (d.get("redaction") or {}).get("rules") or []:
            _edge(g, ok, _of(g, e, calls), _node(g, "secret:" + rule, "secret", rule), "held a secret (redacted)",
                  "SIGNED", at)
    if ok and unread:
        g.nodes[run]["unread_args"] = unread


def _add_why(g: Graph, recs: List[Dict[str, Any]], ok: bool, tests=(), args: Optional[Dict[int, Any]] = None) -> None:
    """INFERRED edges: tracekit why's causal graph of the run, mapped onto this graph's nodes, and the signed why tests
    about the run the verifier counts (`tests`: (why.finding record, its author's label), _counted) whose verdict is
    causal or suppressive, from what the test removed to the calls of its target. `args`: as _add_run's, for the call
    nodes."""
    from .why.core import load_run
    from .why.graph import build_graph, nodes_matching, target_hits
    from .why.import_v2 import convert
    calls = _calls(recs, args)
    decided = {r["event"]["run_seq"]: (r["event"].get("data") or {}).get("decision_id") for r in recs}
    with tempfile.TemporaryDirectory() as d:
        wrun = load_run(convert(recs, d, {}))
        wg = build_graph(wrun)

        def ours(nid: str) -> Optional[str]:
            ev = wg.nodes[nid]["event"]
            c = ev.get("tracekit") or {}
            if ev["type"] == "action":   # it cites its result, or its decision when it did not run
                return calls.get(decided.get(c["run_seq"]))
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
                ev = wg.nodes[e["dst"]]["event"]
                _edge(g, ok, src, dst, e["kind"], "INFERRED", _cite({**ev["tracekit"], "ts": ev["ts"]}),
                      why_evidence=e["evidence"])
        for rec, author in tests:
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
                        _edge(g, ok, a, b, f"{t['verdict']} (tested)", "INFERRED", _cite(rec["event"]),
                              why_evidence="tested", effect=t.get("effect"), author=author)


def _counted(runs: List[List[Dict[str, Any]]], trust: str) -> Dict[tuple, str]:
    """(run_id, run_seq) of each why.finding of verified runs `runs` the verifier counts -> its author's label
    (verify.v2._label; `author not checked` without the analysed run). The verifier's findings check (v2._findings)
    runs over each analysed run with its findings and replay runs, as over the run's `--with-findings` export: a finding
    whose replay runs are not there, or do not give its verdict, fails that export, so none about the run counts."""
    from .verify import v2
    by_id = {recs[0]["event"]["run_id"]: recs for recs in runs}
    about = sorted({_about(recs) for recs in runs if any(r["event"]["type"] == "why.finding" for r in recs)} - {None})
    pinned = v2.load_trust(trust)["analyzers"] if about else []
    out: Dict[tuple, str] = {}
    for a in about:
        group = {rid: recs for rid, recs in by_id.items() if a in (rid, *v2._about(recs)[:2])}
        rep = v2.Report()
        v2._findings(rep, group)
        if {"findings", "findings counted"} & {*rep.failures, *rep.warnings}:
            continue
        for rid, recs in group.items():
            if _about(recs) == a:
                label = v2._label(recs, by_id[a], pinned)[0] if a in by_id else "author not checked"
                out.update({(rid, r["event"]["run_seq"]): label for r in recs if r["event"]["type"] == "why.finding"})
    return out


def _merge(g: Graph, staged: Graph) -> None:
    """Commit a source-local graph only after all of its records built successfully."""
    for nid, node in sorted(staged.nodes.items()):   # as _node: a "?" label gives way to a named one
        attrs = {k: v for k, v in sorted(node.items()) if k not in ("id", "kind", "label")}
        _node(g, nid, node["kind"], node["label"], **attrs)
    for edge in staged.edges:
        g.add_edge(edge["src"], edge["dst"], edge["kind"], edge["grade"],
                   **{k: v for k, v in edge.items() if k not in ("src", "dst", "kind", "grade")})


def _staged(g: Graph) -> Graph:
    """An empty source-local overlay, committed only when this source built successfully."""
    staged = Graph(None, "grade")  # type: ignore[arg-type]
    staged._committed_nodes = g.nodes  # type: ignore[attr-defined]
    return staged


def _graphify(g: Graph, path: str, data: Optional[bytes] = None) -> Dict[str, Any]:
    """The Graphify join: each code node of the Graphify graph at `path` whose `source_file` is a file node's path, or
    its end, linked from that file (INFERRED, or UNVERIFIED if only an unverified source names the file): what the
    agents changed, by function and concept. Read-only.
    lean: Graphify's own edges (calls, imports) are left out; add them when a query must reach past the file"""
    if data is None:   # a FIFO, device or symlink planted at the default path is refused, as verify refuses it
        try:
            data = _secure_source(path)
        except (OSError, ValueError) as e:
            raise ValueError(f"{e}; pass --graphify '' to build without it") from e
    top = json.loads(data)
    if not (isinstance(top, dict) and isinstance(top.get("nodes"), list)):
        raise ValueError(f"{path} is not a Graphify graph.json (it has no list of nodes); pass --graphify '' to build "
                         "without it")
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for n in top["nodes"]:
        sf = n.get("source_file") if isinstance(n, dict) else None
        if isinstance(sf, str) and sf.strip("./") and n.get("id") is not None:
            normalized = sf.replace("\\", "/").removeprefix("./")
            by_file.setdefault(normalized, []).append(n)
    tails: Dict[Any, Any] = {}   # by_file's paths by their parts, last part first: the join is linear in path parts
    for sf in by_file:
        t = tails
        for part in reversed(sf.split("/")):
            t = t.setdefault(part, {})
        t[None] = sf
    linked = 0
    for f in sorted((n for n in g.nodes.values() if n["kind"] == "file"), key=lambda n: n["id"]):
        normalized = f["label"].replace("\\", "/").removeprefix("./")
        t, sf = tails, None
        for part in reversed(normalized.split("/")):   # the longest whole suffix in by_file
            t = t.get(part)
            if t is None:
                break
            sf = t.get(None, sf)
        provenance = g.in_edges(f["id"], GRADES)
        unverified = provenance and all(e["grade"] == "UNVERIFIED" for e in provenance)
        for n in sorted(by_file.get(sf or "", ()), key=lambda n: str(n["id"])):
            loc = n.get("source_location")
            code = _node(g, f"code:{n['id']}", "code", str(n.get("label") or n["id"]), source_file=sf,
                         **({"source_location": loc} if isinstance(loc, str) else {}))
            g.add_edge(f["id"], code, "contains", "UNVERIFIED" if unverified else "INFERRED",
                       record={"graphify": os.path.basename(path), "source_file": sf}, join="graphify",
                       **({"claimed": "INFERRED"} if unverified else {}))
            linked += 1
    return {"name": os.path.basename(path), "sha256": hashlib.sha256(data).hexdigest(), "linked": linked}


def build(paths: List[str], trust: str, content: Optional[Content] = None,
          graphify: Optional[str] = None, _source_data: Optional[Dict[str, bytes]] = None,
          _graphify_data: Optional[bytes] = None) -> Dict[str, Any]:
    """graph.json's document from v2 bundles `paths`, each verified against trust config `trust`. `content`: a run's
    decided arguments (vault()), read for verified runs only; `graphify`: a Graphify graph.json to join. Verified
    sources go first, so that a node's label comes from a verified record wherever one has it, and findings runs after
    the runs they are about."""
    source_data = _source_data or {}
    read = sorted((_read(p, trust, source_data[p]) if p in source_data else _read(p, trust) for p in paths),
                  key=lambda s: (not s[0]["verify"]["ok"], s[0]["sha256"], s[0]["name"]))
    # run id -> the (tenant, log id)s verified runs name it in, as it is unique only within one: a failed bundle's
    # claimed tenant renames no verified run (and stops no vault read); its runs of that id join it, UNVERIFIED
    owners: Dict[str, set] = {}
    for src, rs in read:
        for recs in rs.values() if src["verify"]["ok"] else ():
            for rid in _named_runs(recs):
                owners.setdefault(rid, set()).add((recs[0]["event"].get("tenant"), recs[0]["event"].get("log_id")))
    shared = {rid for rid, o in owners.items() if len(o) > 1}
    read = [(src, {rid: _qualified(recs, shared) for rid, recs in rs.items()}) for src, rs in read]
    runs = sorted(((src, rs[rid]) for src, rs in read for rid in sorted(rs)), key=lambda x: bool(_about(x[1])))
    index: Dict[tuple, Dict[str, Any]] = {}
    counted = _counted([recs for src, recs in runs if src["verify"]["ok"]], trust)
    tests: Dict[str, List[tuple]] = {}   # run_id -> the counted why.finding records about it, with their author's label
    for src, recs in runs:
        if not src["verify"]["ok"]:
            continue
        for r in recs:
            key = (r["event"]["run_id"], r["event"]["run_seq"])
            index.setdefault(key, r)
            if key in counted:
                tests.setdefault(str(_about(recs)), []).append((r, counted[key]))
    g = Graph(None, "grade")  # type: ignore[arg-type]
    for src, rs in sorted(read, key=lambda item: all(_about(recs) for recs in item[1].values())):
        staged = _staged(g)
        try:
            for rid in sorted(rs, key=lambda rid: bool(_about(rs[rid]))):
                recs, ok, args = rs[rid], src["verify"]["ok"], None
                if content and ok and rid in shared:   # the vault finds a run by its id, in the builder's own tenant
                    src.setdefault("content_unread", []).append(
                        f"run {recs[0]['event']['run_id']}: not read from the vault: runs of other tenants or logs "
                        "in this graph have its id; build each tenant's graph as an identity of that tenant")
                elif content and ok:
                    try:
                        args = content(rid, recs)
                    except Exception as e:   # the vault's content does not open its record, or the signer gives none
                        src.setdefault("content_unread", []).append(f"run {rid}: {type(e).__name__}: {e}")
                _add_run(staged, recs, ok, args, index, counted)
                _add_why(staged, recs, ok, tests.get(recs[0]["event"]["run_id"], ()), args)
        except Exception as e:
            src["unreadable"] = f"{type(e).__name__}: {e}"
        else:
            _merge(g, staged)
    _supersede(g)
    joined = _graphify(g, graphify, _graphify_data) if graphify else None
    with open(trust, "rb") as f:
        trust_sha256 = hashlib.sha256(f.read()).hexdigest()
    return {"schema_version": SCHEMA_VERSION, "tracekit": __version__, "trust_sha256": trust_sha256,
            "content": bool(content), "graphify": joined, "sources": [s for s, _ in read],
            "nodes": sorted(g.nodes.values(), key=lambda n: n["id"]),
            "edges": sorted(g.edges, key=lambda e: (e["src"], e["dst"], e["kind"], e["grade"]))}


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def _graph(doc: Dict[str, Any]) -> Graph:
    g = Graph(None, "grade")  # type: ignore[arg-type]
    g.nodes = {n["id"]: n for n in doc["nodes"]}
    for e in doc["edges"]:
        g.add_edge(e["src"], e["dst"], e["kind"], e["grade"],
                   **{k: v for k, v in e.items() if k not in ("src", "dst", "kind", "grade")})
    return g


def _is_tracekit_graph(doc: Any) -> bool:
    return (isinstance(doc, dict) and doc.get("schema_version") == SCHEMA_VERSION
            and all(isinstance(doc.get(k), list) for k in ("sources", "nodes", "edges"))
            and all(_named(source) for source in doc["sources"])
            and (doc.get("graphify") is None or _named(doc["graphify"])))


def _named(entry: Any) -> bool:
    """Whether a sources or graphify entry of graph.json has the name and digest verify reads."""
    return isinstance(entry, dict) and isinstance(entry.get("name"), str) and isinstance(entry.get("sha256"), str)


def _malformed(doc: Dict[str, Any]) -> Optional[str]:
    """The first node or edge of graph.json `doc` not of the shape query reads (build writes no other), or None."""
    ids = set()
    for i, n in enumerate(doc["nodes"]):
        if not (isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("id", "kind", "label"))
                and n["id"].startswith(n["kind"] + ":") and isinstance(n.get("ts", ""), str)
                and (n["kind"] != "code" or isinstance(n.get("source_file"), str)
                     and isinstance(n.get("source_location") or "", str))):
            return f"nodes[{i}] is not a node (string id KIND:..., kind and label)"
        ids.add(n["id"])
    for i, e in enumerate(doc["edges"]):
        r = e.get("record") if isinstance(e, dict) else None
        if not (isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("src", "dst", "kind"))
                and e.get("grade") in GRADES and (e["grade"] != "UNVERIFIED" or e.get("claimed") in GRADES)
                and isinstance(r, dict) and ("run_id" not in r or isinstance(r["run_id"], str)
                                             and "run:" + r["run_id"] in ids and isinstance(r.get("ts"), str)
                                             and all(isinstance(r.get(k), int) for k in ("run_seq", "seq")))
                and (not isinstance(e.get("effect"), (int, float)) or -1 <= e["effect"] <= 1)   # p_with - p_without
                and not {"evidence", "self"} & e.keys()):   # _graph passes its other fields to Graph.add_edge
            return f"edges[{i}] is not an edge (string src, dst and kind, a grade, a record of a run in the graph)"
    return None


def _load(out: str) -> Dict[str, Any]:
    """DIR `out`'s graph.json, read as verify reads a source (a FIFO planted there blocks nothing), refused unless it
    is a Tracekit graph of the shape query reads: it is unsigned, so a hand-written one can hold anything."""
    path = os.path.join(out, GRAPH)
    try:
        data = _secure_source(path)
    except ValueError as e:   # more than MAX_SOURCE_BYTES
        raise ValueError(f"{e}; build graphs of fewer bundles each") from e
    doc = json.loads(data)
    if not _is_tracekit_graph(doc):
        raise ValueError("not a Tracekit graph (Graphify's graph.json is joined with --graphify, not queried)")
    bad = _malformed(doc)
    if bad:
        raise ValueError(f"{path}: {bad}; build it again with tracekit graph build")
    return doc


def _run_of(e: Dict[str, Any]) -> Optional[str]:
    return (e.get("record") or {}).get("run_id")   # None: a Graphify edge


def _n(k: int, word: str) -> str:
    return f"{k} {word}{'' if k == 1 else 's'}"


ASKED = ("asked to write", "asked to reach")
OUTCOMES = ("wrote", "reported writing", "reached", "reported reaching")
OutcomeIndex = Dict[tuple, List[Dict[str, Any]]]


def _outcomes(g: Graph) -> OutcomeIndex:
    """Later call outcomes by (call, target), indexed in one pass over the graph's edges."""
    out: OutcomeIndex = {}
    for e in g.edges:
        if e["kind"] in OUTCOMES:
            out.setdefault((e["src"], e["dst"]), []).append(e)
    return out


def _not_run(e: Dict[str, Any], outcomes: OutcomeIndex) -> bool:
    """Whether an asked edge has no later same-argument outcome at its own evidence grade (`superseded_by`:
    _supersede)."""
    return e["kind"] in ASKED and not any(
        other["grade"] == e["grade"] and other["record"] == e.get("superseded_by")
        for other in outcomes.get((e["src"], e["dst"]), ()))


def _supersede(g: Graph) -> None:
    """Point each asked edge at a later outcome of the same call to the same target, at its grade, from the same opened
    arguments (`superseded_by`: that outcome's record), then drop the arguments' digests (_args_digest)."""
    outcomes = _outcomes(g)
    for e in g.edges:
        if e["kind"] in ASKED:
            later = [o["record"] for o in outcomes.get((e["src"], e["dst"]), ()) if o["grade"] == e["grade"]
                     and o.get("_args") == e["_args"] and o["record"]["run_seq"] > e["record"]["run_seq"]]
            if later:
                e["superseded_by"] = later[0]
    for e in g.edges:
        e.pop("_args", None)


def _shown(e: Dict[str, Any], outcomes: OutcomeIndex) -> bool:
    """Whether a query should show this edge as the call's outcome."""
    return e["kind"] not in ASKED or _not_run(e, outcomes)


# --------------------------------------------------------------------------- report

def highlights(doc: Dict[str, Any]) -> Dict[str, Any]:
    """GRAPH_REPORT.json, which GRAPH_REPORT.md renders: what can't be trusted first (unverified sources, gaps,
    arguments not read), then the files changed most, sensitive files, hosts, approvals, secrets, findings and causal
    chains, every number from the graph. Each section's items carry their line (`text`) and the node ids, runs and
    grades behind it."""
    g = _graph(doc)
    nodes = g.nodes
    outcomes = _outcomes(g)

    def lab(n: str) -> str:
        return nodes[n]["label"]

    def of(kind: str) -> List[str]:
        return sorted(n for n, v in nodes.items() if v["kind"] == kind)

    def count(es: List[Dict[str, Any]]) -> Dict[str, int]:
        c = Counter(e["grade"] for e in es)
        return {k: c[k] for k in GRADES if c[k]}

    def grades(es: List[Dict[str, Any]]) -> str:
        return ", ".join(f"{n} {k}" for k, n in count(es).items())

    def runs(es: List[Dict[str, Any]]) -> List[str]:
        return sorted({r for e in es if (r := _run_of(e))})

    def agents(rid: str) -> List[str]:
        return sorted({lab(e["src"]) for e in g.in_edges("run:" + rid, ("SIGNED",))
                       if nodes[e["src"]]["kind"] == "agent"})

    def approvers(call: str) -> List[Dict[str, Any]]:
        return [e for e in g.in_edges(call, ("SIGNED",)) if nodes[e["src"]]["kind"] == "person"]

    def by_person(call: str) -> bool:   # a person other than the run's own identity approved it, on a verified record
        return any(e["kind"] == "approve" and not e.get("self_approved") and e["grade"] == "SIGNED"
                   for e in approvers(call))

    def called(n: str) -> str:   # a call with its decision
        return lab(n) + (f" ({nodes[n]['decision']})" if nodes[n].get("decision") else "")

    def where(n: str) -> str:   # a node as a reader finds it: a run by its id, anything else with its run
        return "run " + lab(n) if nodes[n]["kind"] == "run" else called(n) + (
            f" in run {n.split(':')[1]}" if nodes[n]["kind"] in ("call", "input", "model", "finding", "gap") else "")

    def cite(e: Dict[str, Any]) -> Dict[str, Any]:   # an edge as an item names it
        return {"src": e["src"], "dst": e["dst"], "kind": e["kind"], "grade": e["grade"], "record": e["record"]}

    bad = [s for s in doc["sources"] if not s["verify"]["ok"]]
    unread = [n for n in of("run") if nodes[n].get("unread_args")]
    first = (
        [{"text": f"{s['name']}: {s['verify']['integrity']} ({', '.join(s['verify']['failures'])}): every edge from it "
                  "is UNVERIFIED", "what": "source failed verification", "source": s["name"],
          "integrity": s["verify"]["integrity"], "failures": s["verify"]["failures"]} for s in bad]
        + [{"text": f"{s['name']}: {p}", "what": "not read", "source": s["name"], "detail": p} for s in doc["sources"]
           for p in [s.get("unreadable")] + s.get("unread_runs", []) + s.get("content_unread", []) if p]
        + [{"text": f"run {e['record']['run_id']}: {lab(e['dst'])} (record {e['record']['run_seq']}, {e['grade']})",
            "what": "gap", "node": e["dst"], "edge": cite(e)} for e in doc["edges"] if nodes[e["dst"]]["kind"] == "gap"]
        + ([{"text": f"{_n(sum(nodes[n]['unread_args'] for n in unread), 'call')} in {_n(len(unread), 'run')}: their "
                     "arguments were not read, so the files and hosts they named are not in the graph"
                     + ("" if doc.get("content") else " (build with --content, against the signer that recorded them)"),
             "what": "arguments not read", "calls": sum(nodes[n]["unread_args"] for n in unread),
             "runs": [lab(n) for n in unread]}] if unread else []))

    # lean: a kernel sensor's file event and the call that made it are two writes; join them when sensors are common
    writes = {f: [e for e in g.in_edges(f, GRADES) if e["kind"] == "wrote" or e["kind"].startswith("file event")]
              for f in of("file")}
    reported = {f: [e for e in g.in_edges(f, GRADES) if e["kind"] == "reported writing"] for f in of("file")}
    tried = {f: [e for e in g.in_edges(f, GRADES) if _not_run(e, outcomes)] for f in of("file")}
    files = []
    for f in sorted(writes, key=lambda f: (-len(writes[f]), -len(reported[f]), -len(tried[f]), f)):
        es, calls = writes[f], sorted({e["src"] for e in writes[f] + reported[f]
                                       if e["kind"] in ("wrote", "reported writing")})
        alone = sum(not by_person(c) for c in calls)
        files.append({"text": f"{lab(f)}: " + (f"written {_n(len(es), 'time')} in {_n(len(runs(es)), 'run')} "
                                               f"({grades(es)})" if es else "no attested write")
                      + (f"; calls that wrote or reported writing it: {len(calls)}, without a person's approval: {alone}"
                         if calls else "")
                      + (f"; reported written: {len(reported[f])} ({grades(reported[f])})" if reported[f] else "")
                      + (f"; calls that asked to write it and did not run: {len(tried[f])} ({grades(tried[f])})"
                         if tried[f] else ""),
                      "node": f, "writes": len(es), "runs": runs(es), "grades": count(es), "calls": calls,
                      "without_person": alone, "reported": len(reported[f]),
                      "reported_grades": count(reported[f]), "asked": len(tried[f]), "asked_grades": count(tried[f])})

    sensitive = []
    for f in of("file"):
        for w in sorted(writes[f] + reported[f] + tried[f], key=lambda e: (e["src"], e["grade"])):
            rules = [e for e in g.in_edges(w["src"], GRADES) if nodes[e["src"]]["kind"] == "rule"]
            if rules:
                who = [f"{lab(a['src'])} {a['kind']}d it ({a['grade']}"
                       + (", self-approved)" if a.get("self_approved") else ")") for a in approvers(w["src"])]
                attested = w["kind"] == "wrote"
                reported_run = w["kind"] == "reported writing"
                sensitive.append({"text": f"{lab(f)}: {where(w['src'])} {w['kind']} it ({w['grade']}) under "
                                          + ", ".join(f"{lab(e['src'])} {e['kind']} ({e['grade']})" for e in rules)
                                          + "; " + ("; ".join(who) if who else "it ran with no person's approval"
                                                    if attested else "it reported running with no person's approval"
                                                    if reported_run else "it did not run"),
                                  "node": f, "call": w["src"], "edge": cite(w), "rules": [cite(e) for e in rules],
                                  "approvals": [{**cite(a), "self_approved": bool(a.get("self_approved"))}
                                                for a in approvers(w["src"])], "ran": attested,
                                  "reported_ran": reported_run})

    hosts = []
    for h in sorted(of("host"), key=lambda h: (-len(runs(g.in_edges(h, GRADES))), h)):
        es = [e for e in g.in_edges(h, GRADES) if _shown(e, outcomes)]
        by_run: Dict[str, List[Dict[str, Any]]] = {}
        for e in es:
            if (rid := _run_of(e)):
                by_run.setdefault(rid, []).append(e)

        def said(e: Dict[str, Any]) -> str:
            if nodes[e["src"]]["kind"] == "run" and e["kind"].startswith("blocked from"):
                return "the run was " + e["kind"]
            return ("the run" if nodes[e["src"]]["kind"] == "run" else lab(e["src"])) + " " + e["kind"]

        hosts.append({"text": f"{lab(h)}: " + "; ".join(
            f"run {r} (agent {', '.join(agents(r)) or '?'}): " + ", ".join(
                f"{said(e)} ({e['grade']}"
                + (f", explained by {e['explained_by']}" if "explained_by" in e else "") + ")"
                for e in by_run[r]) for r in sorted(by_run)),
            "node": h, "runs": [{"run_id": r, "agents": agents(r),
                                 "edges": [{**cite(e), **({"explained_by": e["explained_by"]} if "explained_by" in e
                                                          else {})} for e in by_run[r]]}
                                for r in sorted(by_run)]})

    people = []
    for p in of("person"):
        es = g.out_edges(p, GRADES)
        waits = [e["wait_ms"] for e in es if e["grade"] == "SIGNED" and "wait_ms" in e]
        kinds, selfs = dict(sorted(Counter(e["kind"] for e in es).items())), sum(bool(e.get("self_approved")) for e in es)
        people.append({"text": f"{lab(p)}: " + ", ".join(f"{n} {k}" for k, n in kinds.items())
                       + (f", median wait {statistics.median(waits):g} ms" if waits else ", no wait recorded")
                       + (f", {selfs} self-approved (the approver is the run's own identity)" if selfs else "")
                       + (f" ({grades(es)})" if any(e["grade"] != "SIGNED" for e in es) else ""),
                       "node": p, "answers": kinds, "median_wait_ms": statistics.median(waits) if waits else None,
                       "self_approved": selfs, "grades": count(es)})
    fates = [{"text": f"{lab(a)} in run {_run_of(e)}: {e['kind']} ({e['grade']})", "node": a, "edge": cite(e)}
             for a in of("approval") for e in g.out_edges(a, GRADES) if not e["kind"].startswith("consumed")]

    chains = []
    for i in (n for n in of("input") if nodes[n].get("trust") == "untrusted"):
        parent: Dict[str, Optional[Dict[str, Any]]] = {i: None}
        previous: Dict[str, Optional[str]] = {i: None}
        q = deque([i])
        while q:
            n = q.popleft()
            for e in g.out_edges(n, ("SIGNED", "INFERRED")):
                if e["kind"] in ("asked to write", "asked to reach") or e["dst"] in parent:
                    continue
                parent[e["dst"]] = e
                previous[e["dst"]] = n
                q.append(e["dst"])
        reached = [n for n in sorted(parent) if nodes[n]["kind"] in ("call", "file", "host") and n != i]
        if reached:
            def chain(n: str) -> str:
                target = n
                steps = []
                while parent[n] is not None:
                    e = parent[n]
                    steps.append(e)
                    n = e["src"]
                return " ".join(f"{called(e['src'])} -{e['kind']} ({e['grade']})->" for e in steps[::-1]) + \
                    " " + called(target)
            chains.append({"text": f"untrusted {lab(i)} in run {i.split(':')[1]} reached {_n(len(reached), 'node')}: "
                                   + "; ".join(chain(n) for n in reached),
                           "what": "untrusted input", "node": i,
                           "reached": [{"node": n, "path": Graph.path(previous, n)} for n in reached]})
    chains += [{"text": f"run {lab(e['src'])} {e['kind']} run {lab(e['dst'])} ({e['grade']})", "what": "runs",
                "edge": cite(e)} for e in doc["edges"]
               if nodes[e["src"]]["kind"] == "run" and nodes[e["dst"]]["kind"] == "run"]
    chains += [{"text": f"{lab(f)} was written by {_n(len(runs(es)), 'run')}: {', '.join(runs(es))} ({grades(es)})",
                "what": "file written by several runs", "node": f, "runs": runs(es)}
               for f, es in writes.items() if len(runs(es)) > 1]

    secrets = [{"text": f"{lab(s)}: in {_n(len(runs(es)), 'run')}, held by "
                        + ", ".join(sorted({where(e['src']) for e in es})) + f" ({grades(es)})",
                "node": s, "runs": runs(es), "held_by": sorted({e["src"] for e in es}), "grades": count(es)}
               for s in of("secret") for es in [g.in_edges(s, GRADES)]]
    findings = [{"text": f"{lab(f)}: about " + ", ".join(sorted({where(e['dst']) for e in es})) + f" ({grades(es)})",
                 "node": f, "about": sorted({e["dst"] for e in es}), "grades": count(es)}
                for f in of("finding") for es in [g.out_edges(f, GRADES)]]
    c, gf = count(doc["edges"]), doc.get("graphify")
    summary = {"sources": len(doc["sources"]), "failed": len(bad), "runs": len(of("run")), "nodes": len(doc["nodes"]),
               "edges": len(doc["edges"]), "grades": c, "content": bool(doc.get("content")),
               "graphify": gf, "tracekit": doc["tracekit"]}
    summary["text"] = (f"{_n(len(doc['sources']), 'source')} ({len(bad)} failed verification), "
                       f"{_n(len(of('run')), 'run')}, {len(doc['nodes'])} nodes, {len(doc['edges'])} edges: "
                       + (", ".join(f"{n} {k}" for k, n in c.items()) or "none") + ". "
                       + ("Call arguments were read from the signer's content vault. " if doc.get("content") else
                          "Call arguments were not read (no --content). ")
                       + (f"Graphify: {gf['name']}, {gf['linked']} code nodes linked. " if gf else "")
                       + f"Built by tracekit {doc['tracekit']}; graph.json cites each record.")
    return {"schema_version": SCHEMA_VERSION, "summary": summary, "sections": [
        {"id": i, "title": t, "items": items} for i, t, items in (
            ("read_first", "Read first: unverified sources, gaps and what was not read", first),
            ("files", "Files agents changed most", files),
            ("sensitive", "Sensitive files: written by calls a rule flagged, held or denied", sensitive),
            ("hosts", "Hosts named or observed, by run and agent", hosts),
            ("approvals", "Approvals by person", people + fates),
            ("secrets", "Secrets (by the name of the rule that redacted them)", secrets),
            ("findings", "Findings", findings),
            ("chains", "Causal chains (why) and runs linked to other runs", chains))]}


def report(doc: Dict[str, Any], data: Optional[Dict[str, Any]] = None) -> str:
    """GRAPH_REPORT.md: highlights(doc) as Markdown, the files and hosts sections cut to the TOP most."""
    data = data or highlights(doc)
    def text(value: str, markdown: bool = True) -> str:   # markdown=False: a title of ours, its Markdown kept
        value = " ".join(value.splitlines())
        return "".join((f"\\u{ord(c):04X}" if unicodedata.category(c) in ("Cc", "Cf")
                         else "\\" + c if markdown and c in "\\`*_[]()<>#!|~" else c) for c in value)

    out = [f"# Tracekit graph report\n\n{text(data['summary']['text'])}"]
    for s in data["sections"]:
        lines = [text(i["text"]) for i in s["items"]]
        if s["id"] in ("files", "hosts") and len(lines) > TOP:
            lines = lines[:TOP] + [f"and {len(lines) - TOP} more {s['id']} (graph.json has them all)"]
        out.append(f"\n## {text(s['title'], markdown=False)}\n\n" + "\n".join(f"- {x}" for x in lines or ["none"]))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- query

COLUMNS = ("who", "run", "call", "thing", "after")


def _drawn(g: Graph, outcomes: OutcomeIndex, hits: List[str], things: List[str], touching: List[Dict[str, Any]],
           runs: List[str]) -> Dict[str, Any]:
    """A query's answer as the viewer draws it: each node in a column, who (agents, people) -> run -> call (calls,
    inputs) -> the thing (the matched nodes, the files a code node is in, the code in a matched file) -> after (where
    tracekit why's edges lead from the calls, and what an observer saw the runs reach); the edges between them; and
    one answer per edge that touches the thing or leads after it, newest record first."""
    col: Dict[str, str] = {}
    rank = {r: i for i, r in enumerate(runs)}

    def put(n: str, c: str) -> None:
        col.setdefault(n, c)

    def column(n: str) -> str:
        k = g.nodes[n]["kind"]
        return "who" if k in ("agent", "person") else "run" if k == "run" else "call" if k in ("call", "input") else "thing"

    for h in hits:
        put(h, column(h))
    for n in things:
        put(n, column(n))
        for e in g.out_edges(n, GRADES):
            if e.get("join"):
                put(e["dst"], "thing")
    for e in touching:
        for n in (e["src"], e["dst"]):
            put(n, column(n))
    for r in runs:
        put("run:" + r, "run")
    for n in [n for n, c in col.items() if c in ("run", "call")]:
        for e in g.in_edges(n, GRADES):
            if g.nodes[e["src"]]["kind"] in ("agent", "person"):
                put(e["src"], "who")
    after = [e for n, c in list(col.items()) for e in g.out_edges(n, GRADES) if _shown(e, outcomes)
             if _run_of(e) and e["dst"] not in col and (c == "call" and "INFERRED" in (e["grade"], e.get("claimed"))
                                                         or c == "run" and "OBSERVED" in (e["grade"], e.get("claimed")))]
    for e in after:
        put(e["dst"], "after")

    def order(n: str) -> tuple:
        v = g.nodes[n]
        run = v["label"] if v["kind"] == "run" else n.split(":")[1] if v["kind"] in ("call", "input", "model") else ""
        return (COLUMNS.index(col[n]), rank.get(run, len(rank)), v["kind"], v["label"], n)

    shown = sorted(col, key=order)
    edges = sorted((e for e in g.edges if _shown(e, outcomes) and e["src"] in col and e["dst"] in col),
                   key=lambda e: (e["src"], e["dst"], e["kind"], e["grade"]))
    index = {id(e): i for i, e in enumerate(edges)}

    def note(e: Dict[str, Any]) -> str:
        if e["grade"] == "UNVERIFIED":
            return f"from a bundle that failed verification; it would be {e['claimed']}"
        if e["grade"] == "OBSERVED":
            return f"seen by {e.get('observer')}" + (f", explained by {e['explained_by']}" if "explained_by" in e else "")
        if e["grade"] == "INFERRED":
            return f"tracekit why: {e.get('why_evidence')}" + (f", effect {e['effect']:+g}"
                                                              if isinstance(e.get("effect"), (int, float)) else "")
        call = e["src"] if g.nodes[e["src"]]["kind"] == "call" else e["dst"] if g.nodes[e["dst"]]["kind"] == "call" else ""
        if not call:
            return ""
        ok = [a for a in g.in_edges(call, ("SIGNED",)) if g.nodes[a["src"]]["kind"] == "person"]
        rules = [a for a in g.in_edges(call, ("SIGNED",)) if g.nodes[a["src"]]["kind"] == "rule"]
        return "; ".join(filter(None, [
            ", ".join(f"{g.nodes[a['src']]['label']} {a['kind']}" for a in rules),
            ", ".join(f"{g.nodes[a['src']]['label']} {a['kind']}d it" + (" (the run's own identity)"
                                                                         if a.get("self_approved") else "")
                      for a in ok)
            or ("no person approved it" if e["kind"] in ("wrote", "reached") else "")]))

    answers = []
    for e in sorted({id(e): e for e in touching + after}.values(),
                    key=lambda e: (e["record"].get("ts", ""), e["record"]["seq"]), reverse=True):
        rid = _run_of(e)
        who = sorted({g.nodes[a["src"]]["label"] for a in g.in_edges("run:" + rid, ("SIGNED",))
                      if g.nodes[a["src"]]["kind"] == "agent"})
        answers.append({"edge": index[id(e)], "grade": e["grade"], **({"claimed": e["claimed"]} if "claimed" in e
                                                                        else {}),
                        **e["record"], "agents": who, "note": note(e),
                        "text": f"{', '.join(who) or 'run ' + rid}: "
                                + ("the run" if g.nodes[e["src"]]["kind"] == "run" else g.nodes[e["src"]]["label"])
                                + f" {e['kind']} {g.nodes[e['dst']]['label']}"})
    return {"columns": list(COLUMNS), "nodes": [{**g.nodes[n], "column": col[n]} for n in shown], "edges": edges,
            "answers": answers}


def matching(doc: Dict[str, Any], kind: str, needle: str) -> Dict[str, Any]:
    """The runs that touched a node of `kind` labelled `needle` (a file also by its last path parts; code: the files
    Graphify places it in), newest first: each run's agents, approvers, approvals, rules, hosts, files, secrets,
    findings and gaps, and the edges to the matched nodes; `code`: the Graphify code nodes in the matched files;
    `map`: the answer drawn (_drawn)."""
    g = _graph(doc)
    outcomes = _outcomes(g)
    hits = sorted(n for n, v in g.nodes.items() if v["kind"] == kind
                  and (v["label"] == needle or kind == "file" and v["label"].endswith("/" + needle.lstrip("/"))))
    files = sorted({e["src"] for h in hits for e in g.in_edges(h, GRADES)}) if kind == "code" else hits
    touching = [e for h in files for e in g.in_edges(h, GRADES) + g.out_edges(h, GRADES)
                if _run_of(e) and _shown(e, outcomes)]
    touching_by_run: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for e in touching:
        touching_by_run.setdefault(_run_of(e), []).append(e)
    by_run: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for e in g.edges:
        if _shown(e, outcomes):
            by_run.setdefault(_run_of(e), []).append(e)
    runs = sorted(touching_by_run, key=lambda r: (g.nodes.get(f"run:{r}", {}).get("ts", ""), r),
                  reverse=True)
    out = []
    for rid in runs:
        es = by_run[rid]
        facts = {k: [e for e in es if g.nodes[e["src"]]["kind"] == k or g.nodes[e["dst"]]["kind"] == k] for k in FACTS}
        out.append({"run": rid, "ts": g.nodes.get(f"run:{rid}", {}).get("ts"), **facts,
                    "matched": touching_by_run[rid]})
    code = sorted({e["dst"] for f in files for e in g.out_edges(f, GRADES) if g.nodes[e["dst"]]["kind"] == "code"})
    return {"matched": hits, "code": [g.nodes[n] for n in code], "runs": out,
            "map": _drawn(g, outcomes, hits, sorted(set(hits) | set(files)), touching, runs)}


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
    outcomes = _outcomes(g)
    start = _find(g, spec)
    parent: Dict[str, Optional[str]] = {start: None}
    via: Dict[str, Dict[str, Any]] = {}
    depth = {start: 0}
    # (weakest grade, path's edge tuples): among equally short paths, lower is stronger and then deterministic.
    rank = {start: (0, ())}
    q = deque([start])
    while q:
        n = q.popleft()
        for e in sorted((e for e in g.out_edges(n, GRADES) if _shown(e, outcomes)),
                        key=lambda e: GRADES.index(e["grade"])):
            dst = e["dst"]
            candidate_depth = depth[n] + 1
            candidate_rank = (max(rank[n][0], GRADES.index(e["grade"])),
                              rank[n][1] + ((e["src"], e["dst"], e["kind"], e["grade"]),))
            if dst not in depth or candidate_depth < depth[dst] or \
                    (candidate_depth == depth[dst] and candidate_rank < rank[dst]):
                parent[dst], via[dst] = n, e
                depth[dst], rank[dst] = candidate_depth, candidate_rank
                q.append(dst)
    reached = sorted(parent)
    touching = [e for e in g.edges if _shown(e, outcomes) and e["src"] in parent and e["dst"] in parent and _run_of(e)]
    runs = sorted({_run_of(e) for e in touching}, key=lambda r: (g.nodes.get(f"run:{r}", {}).get("ts", ""), r), reverse=True)
    things = [n for n in reached if g.nodes[n]["kind"] not in ("run", "call", "input")]
    def grade(n: str) -> str:
        edges = []
        while n != start:
            edges.append(via[n])
            n = parent[n]  # type: ignore[assignment]
        return max(edges, key=lambda e: GRADES.index(e["grade"]))["grade"]

    return {"from": start, "reached": [{"node": n, "kind": g.nodes[n]["kind"], "label": g.nodes[n]["label"],
                                        "path": Graph.path(parent, n), "grade": grade(n)}
                                       for n in reached if n != start],
            "map": _drawn(g, outcomes, [start], things, touching, runs)}


def path(doc: Dict[str, Any], a: str, b: str) -> Dict[str, Any]:
    """The shortest chain of edges between two nodes, either way along each edge, the stronger grade first at each
    step."""
    g = _graph(doc)
    outcomes = _outcomes(g)
    a, b = _find(g, a), _find(g, b)
    via: Dict[str, Optional[Dict[str, Any]]] = {a: None}
    q = deque([a])
    while q and b not in via:
        n = q.popleft()
        for e in sorted((e for e in g.out_edges(n, GRADES) + g.in_edges(n, GRADES) if _shown(e, outcomes)),
                        key=lambda e: GRADES.index(e["grade"])):
            m = e["dst"] if e["src"] == n else e["src"]
            if m not in via:
                via[m] = e
                q.append(m)
    edges, n = [], b
    while b in via and via[n] is not None:
        e = via[n]
        edges.append(e)
        n = e["src"] if e["dst"] == n else e["dst"]
    edges = edges[::-1]
    runs = sorted({_run_of(e) for e in edges if _run_of(e)}, key=lambda r: (g.nodes.get(f"run:{r}", {}).get("ts", ""), r), reverse=True)
    return {"from": a, "to": b, "found": b in via, "edges": edges,
            "map": _drawn(g, outcomes, [a, b], [b], [e for e in edges if _run_of(e)], runs)}


# --------------------------------------------------------------------------- CLI

def _line(g: Dict[str, Dict[str, Any]], e: Dict[str, Any]) -> str:
    r = e["record"]
    where = f"run {r['run_id']} record {r['run_seq']}" if "run_id" in r else f"Graphify {r.get('source_file')}"
    return f"  {e['grade']:<10} {g[e['src']]['label']} -{e['kind']}-> {g[e['dst']]['label']}  ({where})"


def _files(doc: Dict[str, Any]) -> Dict[str, str]:
    data = highlights(doc)
    return {GRAPH: dumps(doc), REPORT_JSON: dumps(data), REPORT: report(doc, data)}


def _and(names) -> str:
    return ", ".join(names[:-1]) + " and " + names[-1]


def write(doc: Dict[str, Any], out: str) -> None:
    """FILES into `out`, never through a symlink: a symlinked `out`, or a symlink in a file's place (anyone who can
    write `out`, such as an agent in its repo, can plant one), is refused, and each file is a new one renamed into
    place. Parent directories may be symlinks."""
    from .deploy import files
    os.makedirs(out, exist_ok=True)
    d = files.open_dir(out)
    try:
        for name, text in _files(doc).items():
            files.write(d, name, text.encode("utf-8"), None)
    finally:
        files.close(d)


def verify(out: str, trust: str, content: Optional[Content] = None, paths: Optional[List[str]] = None,
           graphify: Optional[str] = None) -> List[str]:
    """What differs between DIR's files and the ones its sources give now ([] when nothing does). `content`: the vault
    reader, used when graph.json was built with call arguments from it."""
    have = _load(out)
    listed = have["sources"]
    default_paths = paths is None
    source_dir = os.path.dirname(os.path.abspath(out))
    paths = paths if paths is not None else [os.path.join(source_dir, os.path.basename(s["name"])) for s in listed]
    names = Counter(s["name"] for s in listed)
    duplicates = sorted(name for name, count in names.items() if count > 1)
    if default_paths and duplicates:
        return [f"multiple sources are named {name}; pass SOURCES explicitly" for name in duplicates]
    def regular(path: str) -> bool:
        try:
            return stat.S_ISREG(os.lstat(path).st_mode)
        except OSError:
            return False

    by_basename = {os.path.basename(path): path for path in paths}
    missing = [s["name"] for s in listed
               if not regular(by_basename.get(os.path.basename(s["name"]), ""))]
    if missing and not default_paths:
        supplied = by_basename.get(os.path.basename(missing[0]))
        if supplied and os.path.lexists(supplied):
            return [f"{supplied}: source is not a regular file"]
    problems = [f"{name}: source is missing; pass it to tracekit graph verify" for name in missing]
    if missing:
        return problems
    source_data = {}
    try:
        for path in paths:
            source_data[path] = _secure_source(path)
    except (OSError, ValueError) as e:
        return [f"{e}: source is missing; pass SOURCES to tracekit graph verify"]
    gf = have.get("graphify")
    if gf is not None and (not isinstance(gf, dict) or not isinstance(gf.get("name"), str)):
        raise ValueError("not a Tracekit graph (its Graphify entry is malformed)")
    if graphify is None:
        graphify = (gf and os.path.join(source_dir, GRAPHIFY if gf["name"] == os.path.basename(GRAPHIFY)
                                        else os.path.basename(gf["name"])))
    if gf and (not graphify or not regular(graphify)):
        return [f"the Graphify graph {gf['name']} is missing; pass --graphify PATH"]
    try:
        graphify_data = _secure_source(graphify) if graphify else None
        doc = build(paths, trust, content if have.get("content") else None, graphify, source_data, graphify_data)
    except (OSError, ValueError) as e:
        return [f"{getattr(e, 'filename', None) or e}: source is missing; pass SOURCES to tracekit graph verify"]
    expected = sorted((s["name"], s["sha256"]) for s in listed)
    actual = sorted((s["name"], s["sha256"]) for s in doc["sources"])
    if actual != expected:
        problems.append("source digests are not the ones graph.json lists")
    if gf and doc["graphify"] and doc["graphify"]["sha256"] != gf["sha256"]:
        problems.append(f"{gf['name']}: the Graphify graph changed since the build")
    if doc["trust_sha256"] != have.get("trust_sha256"):
        problems.append("the trust config is not the one graph.json was built with")
    for name, text in _files(doc).items():
        try:
            same = _secure_source(os.path.join(out, name)) == text.encode("utf-8")
        except (OSError, ValueError):
            same = False
        if not same:
            problems.append(f"{name} is not what its sources give")
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tracekit graph", description="What agents did across runs, from verified "
                                 "bundles; every edge graded SIGNED, OBSERVED, INFERRED or UNVERIFIED.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build", help=f"write {_and(FILES)} from v2 bundles")
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
    p = sub.add_parser("verify", help="rebuild DIR from SOURCES and compare, byte for byte")
    p.add_argument("dir", nargs="?", default="tracekit-graph")
    p.add_argument("sources", nargs="*", help="the v2 bundles passed to build (defaults to their recorded names)")
    p.add_argument("--trust", required=True)
    p.add_argument("--graphify", help="the Graphify graph passed to build (defaults to its recorded name)")
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
            bad = [s["name"] for s in doc["sources"] if not s["verify"]["ok"]]
            unread = sum(n.get("unread_args", 0) for n in doc["nodes"])
            print(f"wrote {_and([os.path.join(a.out, n) for n in FILES])}: {len(doc['nodes'])} nodes, "
                  f"{len(doc['edges'])} edges"
                  + (f"; UNVERIFIED (failed verification): {', '.join(bad)}" if bad else "")
                  + (f"; {unread} calls' arguments not read" + ("" if a.content else " (pass --content)")
                     if unread else ""))
            return 0
        if a.cmd == "verify":
            problems = verify(a.dir, a.trust, vault(), a.sources or None, a.graphify)
            # they name graph.json's sources, as anyone who can write DIR wrote them: none may redraw the success line
            print("\n".join(v2._CONTROL.sub("", line) for line in problems)
                  or f"{a.dir}: {_and(FILES)} are what their sources give")
            return 1 if problems else 0
        doc = _load(a.dir)
    except (OSError, ValueError, RecursionError, SignerUnavailable, RPCError) as e:   # RecursionError: nested too deep
        print(f"tracekit graph: {e}", file=sys.stderr)
        return 2
    nodes = {n["id"]: n for n in doc["nodes"]}
    try:
        if a.blast:
            res = blast(doc, a.blast)
            text = [f"downstream of {res['from']}:"] + [f"  {r['grade']:<10} {r['kind']} {r['label']}  via {' -> '.join(r['path'])}"
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
        print(f"tracekit graph: {v2._CONTROL.sub('', str(e))}", file=sys.stderr)
        return 2
    # graph.json is unsigned: whoever can write DIR can write the answers
    unverified = (f"{os.path.join(a.dir, GRAPH)} is not verified here: check it against its bundles with "
                  f"`tracekit graph verify {a.dir} --trust trust.json` before relying on these answers")
    if a.json:
        print(v2._CONTROL.sub("", unverified), file=sys.stderr)
    # labels are agent-chosen (a tool name is stored as given): no control character may redraw a line or its grade
    print(json.dumps(res, sort_keys=True, indent=1, ensure_ascii=False) if a.json
          else "\n".join(v2._CONTROL.sub("", line) for line in [unverified] + text))
    return 0 if res.get("matched", res.get("found", True)) else 1


if __name__ == "__main__":
    sys.exit(main())
