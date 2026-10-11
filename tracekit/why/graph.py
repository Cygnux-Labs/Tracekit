"""Causal graph over a run, with edges graded by evidence.

observed  structural: X was in D's context, D invoked A, D sent M, identical content reappeared
inferred  heuristic: text from X shows up in Y with no observed path between them
tested    interventional: removing X in replay changed whether target Y happened (effect size + CI)
"""
from __future__ import annotations

import json
import re
from collections import deque
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from .core import Ref, Run, ablation_matches, canonical

EVIDENCE = ("observed", "inferred", "tested")


# --------------------------------------------------------------------------- target predicates

def parse_target(spec: str) -> Callable[[Dict[str, Any], Run], bool]:
    """'tool=send_email,arg~external.example,agent=executor,result~sent' -> predicate on action events."""
    conds = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        if "~" in part and ("=" not in part or part.index("~") < part.index("=")):
            k, v = part.split("~", 1)
            conds.append((k.strip(), "~", v))
        elif "=" in part:
            k, v = part.split("=", 1)
            conds.append((k.strip(), "=", v))
        else:
            raise ValueError(f"bad target clause {part!r}")
    for k, _, _ in conds:
        if k not in ("tool", "agent", "arg", "result"):
            raise ValueError(f"unknown target field {k!r} (tool, agent, arg, result)")

    def pred(ev: Dict[str, Any], run: Run) -> bool:
        if ev.get("type") != "action":
            return False
        for k, op, v in conds:
            if k in ("tool", "agent"):
                hay = ev.get(k, "")
            elif k == "arg":
                hay = canonical(run.value(ev["args_ref"])).decode()
            else:
                hay = canonical(run.value(ev["result_ref"])).decode()
            if op == "=" and hay != v:
                return False
            if op == "~" and v not in hay:
                return False
        return True

    pred.spec = spec  # type: ignore[attr-defined]
    return pred


def target_hits(run: Run, spec: str) -> List[Dict[str, Any]]:
    p = parse_target(spec)
    return [e for e in run.events if p(e, run)]


# --------------------------------------------------------------------------- text helpers

_WORD = re.compile(r"[a-z0-9@._-]+")


def _text(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False, default=str)


def shingles(text: str, n: int = 5) -> Set[str]:
    w = _WORD.findall(text.lower())
    return {" ".join(w[i:i + n]) for i in range(max(0, len(w) - n + 1))}


def overlap(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


# --------------------------------------------------------------------------- graph

class Graph:
    def __init__(self, run: Run):
        self.run = run
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._out: Dict[str, List[Dict[str, Any]]] = {}
        self._in: Dict[str, List[Dict[str, Any]]] = {}

    # -- construction
    def add_edge(self, src: str, dst: str, kind: str, evidence: str, **extra: Any) -> None:
        if src not in self.nodes or dst not in self.nodes or src == dst:
            return
        for e in self._out.get(src, []):
            if e["dst"] == dst and e["kind"] == kind and e["evidence"] == evidence:
                return
        e = {"src": src, "dst": dst, "kind": kind, "evidence": evidence, **extra}
        self.edges.append(e)
        self._out.setdefault(src, []).append(e)
        self._in.setdefault(dst, []).append(e)

    def out_edges(self, n: str, evidence: Iterable[str] = EVIDENCE) -> List[Dict[str, Any]]:
        ev = set(evidence)
        return [e for e in self._out.get(n, []) if e["evidence"] in ev]

    def in_edges(self, n: str, evidence: Iterable[str] = EVIDENCE) -> List[Dict[str, Any]]:
        ev = set(evidence)
        return [e for e in self._in.get(n, []) if e["evidence"] in ev]

    # -- traversal
    def descendants(self, starts: Iterable[str], evidence: Iterable[str] = ("observed",)) -> Dict[str, Optional[str]]:
        """BFS forward. Returns {node: parent} (parent None for starts) for shortest-path recovery."""
        evidence = tuple(evidence)
        parent: Dict[str, Optional[str]] = {}
        q = deque()
        for s in starts:
            if s in self.nodes and s not in parent:
                parent[s] = None
                q.append(s)
        while q:
            n = q.popleft()
            for e in self.out_edges(n, evidence):
                if e["dst"] not in parent:
                    parent[e["dst"]] = n
                    q.append(e["dst"])
        return parent

    def ancestors(self, n: str, evidence: Iterable[str] = ("observed",)) -> Set[str]:
        seen: Set[str] = set()
        q = deque([n])
        while q:
            x = q.popleft()
            for e in self.in_edges(x, evidence):
                if e["src"] not in seen:
                    seen.add(e["src"])
                    q.append(e["src"])
        return seen

    @staticmethod
    def path(parent: Dict[str, Optional[str]], n: str) -> List[str]:
        out = []
        while n is not None:
            out.append(n)
            n = parent[n]
        return out[::-1]

    def node_for_event(self, ev_id: str) -> str:
        return "ev:" + ev_id

    def to_dict(self) -> Dict[str, Any]:
        return {"run_id": self.run.run_id, "nodes": list(self.nodes.values()), "edges": self.edges}


def _label(ev: Dict[str, Any], run: Run) -> str:
    t = ev["type"]
    if t == "input":
        return ev.get("source", "input")
    if t == "decision":
        return ev.get("purpose") or ev.get("model", "decision")
    if t == "action":
        return ev["tool"]
    if t == "message":
        return f"{ev['agent']} → {ev['to']}"
    return t


def _node_text(ev: Dict[str, Any], run: Run) -> str:
    t = ev["type"]
    if t in ("input", "message"):
        return _text(run.value(ev["ref"]))
    if t == "decision":
        return _text(run.value(ev["output"]))
    if t == "action":
        return _text(run.value(ev["args_ref"])) + " " + _text(run.value(ev["result_ref"]))
    return ""


def build_graph(run: Run, *, infer: bool = True, infer_threshold: float = 0.3, min_shared: int = 3) -> Graph:
    g = Graph(run)
    # nodes
    producer: Dict[str, str] = {}  # first event that brought each ref into the run
    for ev in run.events:
        if ev["type"] not in ("input", "decision", "action", "message"):
            continue
        nid = "ev:" + ev["id"]
        g.nodes[nid] = {
            "id": nid, "type": ev["type"], "agent": ev["agent"], "seq": ev["seq"], "label": _label(ev, run),
            "trust": ev.get("trust", "trusted"), "kind": ev.get("kind"), "to": ev.get("to"),
            "event": ev,
        }
        for k in ("ref", "output", "result_ref"):
            if ev.get(k):
                producer.setdefault(ev[k], nid)

    # observed edges
    for ev in run.events:
        nid = "ev:" + ev["id"]
        t = ev["type"]
        if t == "decision":
            for c in ev.get("context", []):
                src = ("ev:" + c["from_event"]) if c.get("from_event") else producer.get(c["ref"])
                if src:
                    g.add_edge(src, nid, "context:" + c.get("kind", "?"), "observed", ref=c["ref"])
        elif t in ("action", "message"):
            if ev.get("decision"):
                g.add_edge("ev:" + ev["decision"], nid, "invoked" if t == "action" else "sent", "observed")
        elif t == "input":
            # identical content that already existed in this run: a side channel made visible by hashing
            p = producer.get(ev["ref"])
            if p and p != nid:
                g.add_edge(p, nid, "same-content", "observed", ref=ev["ref"])

    if infer:
        _infer_edges(g, run, infer_threshold, min_shared)
        _weight_context_edges(g, run)

    _attach_tests(g, run)
    return g


def _infer_edges(g: Graph, run: Run, threshold: float, min_shared: int) -> None:
    order = sorted(g.nodes.values(), key=lambda n: n["seq"])
    sh = {n["id"]: shingles(_node_text(n["event"], run)) for n in order}
    for j, dst in enumerate(order):
        if dst["type"] not in ("input", "decision", "action"):
            continue
        anc = None
        for src in order[:j]:
            a, b = sh[src["id"]], sh[dst["id"]]
            shared = len(a & b)
            if shared < min_shared:
                continue
            score = overlap(a, b)
            if score < threshold:
                continue
            if anc is None:
                anc = g.ancestors(dst["id"], ("observed",))
            if src["id"] in anc:
                continue
            # skip if any observed ancestor of dst already carries the same text (avoid duplicate inferred hops)
            g.add_edge(src["id"], dst["id"], "content-overlap", "inferred", score=round(score, 3), shared=shared)


def _weight_context_edges(g: Graph, run: Run) -> None:
    """Annotate observed context edges with how much of the input's text the decision output reuses.
    This is a hint about *which* inputs the model drew on, never proof."""
    for e in g.edges:
        if e["evidence"] != "observed" or not e["kind"].startswith("context"):
            continue
        dst_ev = g.nodes[e["dst"]]["event"]
        a = shingles(_text(run.value(e.get("ref"))))
        b = shingles(_text(run.value(dst_ev.get("output"))))
        e["reuse"] = round(overlap(a, b), 3) if a and b else 0.0


def nodes_matching(g: Graph, spec: str) -> List[str]:
    """Map an intervention spec to the nodes it would remove in the original run. A group test
    removes several specs at once; it is written "spec | spec | ...".
    """
    if " | " in spec:
        return sorted({n for part in spec.split(" | ") for n in nodes_matching(g, part)})
    out = []
    for nid, n in g.nodes.items():
        ev = n["event"]
        if n["type"] == "input":
            r = Ref(ev["ref"], None, ev.get("kind", "input"), ev["agent"], ev.get("source", ""), ev.get("trust", "trusted"))
        elif n["type"] == "message":
            r = Ref(ev["ref"], None, "message", ev["to"], f"{ev['agent']}->{ev['to']}", ev.get("trust", "trusted"))
        elif n["type"] == "action":
            r = Ref(ev["result_ref"], None, "result", ev["agent"], ev["tool"])
        else:
            continue
        if ablation_matches(spec, r):
            out.append(nid)
    return out


def _attach_tests(g: Graph, run: Run) -> None:
    for t in run.tests:
        if t.get("group"):
            continue  # removing several items at once says nothing about any one of them
        if t.get("scope") == "decision":
            dec = "ev:" + t["decision"]
            ctx = {c["ref"] for c in g.nodes[dec]["event"]["context"]} if dec in g.nodes else set()
            srcs = [s for s in nodes_matching(g, t["intervention"])
                    if g.nodes[s]["event"].get("ref") in ctx]
            dsts = [dec]
        else:
            srcs = nodes_matching(g, t["intervention"])
            try:
                dsts = ["ev:" + e["id"] for e in target_hits(run, t["target"])]
            except ValueError:
                dsts = []
        for s in srcs:
            for d in dsts:
                g.add_edge(s, d, "causal", "tested", effect=t["effect"], ci=t["ci"], n=t["n"],
                           verdict=t["verdict"], target=t["target"])


# --------------------------------------------------------------------------- taint / blast radius

def taint(run: Run, sources: Iterable[str] = ("untrusted",), *, include_inferred: bool = False,
          graph: Optional[Graph] = None) -> Dict[str, Any]:
    """Forward reachability from source inputs. Answers: what did this content *reach*?
    Reach is not causation; use replay to test whether it changed anything."""
    g = graph or build_graph(run)
    starts: List[str] = []
    for s in sources:
        starts.extend(n for n in nodes_matching(g, s) if g.nodes[n]["type"] == "input")
    evidence = ("observed", "inferred") if include_inferred else ("observed",)
    parent = g.descendants(starts, evidence)
    reached = [n for n in parent if n not in starts]
    actions = []
    for n in sorted(reached, key=lambda x: g.nodes[x]["seq"]):
        node = g.nodes[n]
        if node["type"] != "action":
            continue
        ev = node["event"]
        actions.append({
            "node": n, "seq": ev["seq"], "agent": ev["agent"], "tool": ev["tool"],
            "args": run.value(ev["args_ref"]),
            "path": [g.nodes[p]["label"] + f" [{g.nodes[p]['agent']}]" for p in Graph.path(parent, n)],
        })
    return {
        "sources": [{"node": s, "label": g.nodes[s]["label"], "agent": g.nodes[s]["agent"]} for s in starts],
        "reached_nodes": reached,
        "agents_reached": sorted({g.nodes[n]["agent"] for n in reached}),
        "actions": actions,
        "evidence": list(evidence),
    }
