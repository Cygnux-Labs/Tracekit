"""Attribution on signed runs: replay a run the signer and the gateway recorded, from the signer's content vault.

    tracekit why test --run R --store DIR --gateway URL --remove SPEC --target SPEC [--decision SEQ]
    tracekit why attribute --run R --store DIR --gateway URL --target SPEC

The ladder (docs/why.md "Attribution on signed runs"):

    rung 0  observed (signed provenance) or predicted (rank(): a sparse linear surrogate): never "tested"
    rung 1  decision replay: one recorded model exchange re-sent with the item removed, against it re-sent unchanged
    rung 2  agentless run replay: from that exchange on, the agent loop re-simulated without the agent's code: each
            tool use answered from the run's tape when tool and canonical args match exactly, else a stub (off tape),
            the model called again until it stops or the recorded number of turns + MARGIN
    rung 3  program replay: tracekit.why.replay with the run's System

Every executed replay is evidence: each arm is a replay run registered with `replay_of` and the investigation id,
whose model calls go through the Tracekit gateway as the investigator, so they are signed records (each call is read
back from the replay run: one the gateway did not record stops the investigation). No tool the client runs is
executed: its results come from the tape or a stub. A request that lets the provider run a tool itself (hosted MCP, web
search, code execution, ...) or continues context the provider holds is refused before anything is sent. A finished
test is written through the signer as a `why.finding` in a findings run (`analyzes`) of the run's tenant.

Content comes from `content_get` (purpose: the investigation id), each record checked against its commitment with the
returned salt; a mismatch stops the investigation (EvidenceAlert).

Interventions name blocks of a recorded request body (Anthropic messages, OpenAI chat completions and responses):
`input:<source glob>` blocks holding a value the run observed from that source, `result:<tool glob>` tool results,
`msg:<index>` one message, `ref:<hash prefix>` one block by content hash (the surrogate's ranking names blocks so). A
removed block keeps its place, its content replaced by REMOVED, so the request stays valid for the provider. Targets:
`tool=NAME`, `arg~TEXT` (one tool use matching every tool/arg clause), `text~TEXT` (the response's text).
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import hmac
import json
import math
import random
import threading
import urllib.error
import urllib.request
import uuid
from collections import namedtuple
from typing import Any, Dict, List, Optional, Sequence, Union

from .. import parsers
from ..format.canon import canonical, event_hash, loads_strict
from ..gateway import KINDS, OPEN, UPSTREAM_TIMEOUT_S, _NoRedirect
from .analysis import atoms
from .core import content_hash
from .import_v2 import _calls, cite
from .replay import MIN_EFFECT, Stop, clauses, find_cause, holds, looks, paired, summary

PATHS = {kind: path for path, kind in KINDS.items()}
VAULTED = ("input.observed", "policy.decision", "tool.result", "model.exchange")
CHUNK = 100   # records per content_get
REMOVED = "[removed by tracekit why]"
STUB = {"error": "not in the recorded run"}
MARGIN = 2   # model calls a rung 2 replay may make past the recorded number of turns
MAX_WORKERS = 16
MAX_N = 1024   # pairs per test: a finding names two replay runs per pair
MAX_K = 1024   # the surrogate's samples
# a 1x1 PNG: what a removed screenshot becomes, so a computer_call_output keeps its shape
BLANK_PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
SERVER_HELD = ("previous_response_id", "conversation")   # OpenAI Responses: context the provider holds
ASSUMPTIONS = ["no code between model calls rewrote the history the model was sent",
               "tools are deterministic: a recorded result is what the tool would return again"]

Block = namedtuple("Block", "path repl text tool role msg")


class EvidenceAlert(Exception):
    """The vault's content does not open its record's commitment: the investigation stops."""


class Budget(Stop):
    pass


# --------------------------------------------------------------------------- loading

def _digest(e: Dict[str, Any], content: Any) -> str:
    """The digest a record's commitment is over, from its vaulted content."""
    if e["type"] == "policy.decision":
        return event_hash({"tool": e["data"]["tool"], "args": content})
    return "sha256:" + hashlib.sha256(canonical(content)).hexdigest()


def _kind(data: Dict[str, Any], request: Any) -> str:
    if data["upstream"] == "anthropic":
        return "anthropic:messages"
    return "openai:responses" if isinstance(request, dict) and "input" in request else "openai:chat"


def _txt(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False)


class Investigation:
    """One investigation of a signed run: its vaulted content, its replays through the gateway and their budget.

    `records`: the run's v2 records (import_v2.store_records or bundle_records). `client`: the investigator's signer
    client (tracekit.sdk.client.Client): content_get needs the `content_read` grant, replay and findings runs the
    investigator in signer.yaml `analyzers`. `gateway`: the gateway's base URL; `headers` authenticate the investigator
    to it (the same identity as `client`), `context` an ssl.SSLContext. Budgets, for this object's lifetime (one
    process): `max_calls` model calls, `max_cost` (with `prices`, a tracekit.usage.Prices) cost estimate; a test that
    reaches one stops `inconclusive` (budget). Each call reserves its estimate before it is sent: the costliest call so
    far (recorded or replayed), so it is sent only while spent + reserved stays within max_cost, and a call overshoots
    only by what it costs past that estimate."""

    def __init__(self, records: List[Dict[str, Any]], client: Any, gateway: str, *, headers: Optional[Dict[str, str]] = None,
                 context: Any = None, investigation: Optional[str] = None, max_calls: Optional[int] = None,
                 max_cost: Optional[float] = None, prices: Any = None):
        self.client, self.url, self.headers = client, gateway.rstrip("/"), dict(headers or {})
        self.open = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context)).open \
            if context else OPEN
        self.id = investigation or "inv-" + uuid.uuid4().hex[:16]
        self.max_calls, self.max_cost, self.prices = max_calls, max_cost, prices
        self.calls, self.cost, self.held, self.models, self.lock = 0, 0.0, 0.0, set(), threading.Lock()
        self.findings_run, self.runs, self.counted = None, {}, set()   # replay run id -> "test" | "ranking"
        first = records[0]["event"]
        self.run_id = first["run_id"]
        content = self._content(records)
        self.tape = {}
        for call in _calls(records).values():
            d, res = call["decision"]["event"], call.get("result")
            if res and d["run_seq"] in content and res["event"]["run_seq"] in content:
                self.tape[(d["data"]["tool"], canonical(content[d["run_seq"]]))] = content[res["event"]["run_seq"]]
        self.observed = [(r["event"]["data"]["source"], atoms(content[r["event"]["run_seq"]])) for r in records
                         if r["event"]["type"] == "input.observed" and r["event"]["run_seq"] in content]
        ex: Dict[str, Dict[str, Any]] = {}
        for r in records:
            e = r["event"]
            if e["type"] == "model.exchange":
                x = ex.setdefault(e["data"]["exchange_id"], {"seq": e["run_seq"], "model": e["data"]["model"]})
                x[e["data"]["phase"]] = content.get(e["run_seq"])
                x["kind"] = _kind(e["data"], x.get("request"))
        # lean: subagent runs are not linked in v2 records, so a subagent tool is served from the tape, never replayed;
        # replay it once v2 records link a subagent run to its parent
        self.exchanges = [x for x in ex.values() if isinstance(x.get("request"), dict)]
        if max_cost is not None:
            unpriced = sorted({x["model"] for x in self.exchanges if prices is None or prices.rate(x["model"]) is None})
            if unpriced:
                raise ValueError(f"--max-cost needs a price for every model the run called (--prices): none for "
                                 f"{', '.join(unpriced)}")
        self.estimate = max((prices.cost(x["model"], parsers.parse(x["kind"], x["response"], x["request"])["usage"]) or 0
                             for x in self.exchanges if isinstance(x.get("response"), dict)), default=0.0) \
            if max_cost is not None else 0.0

    def _content(self, records: List[Dict[str, Any]]) -> Dict[int, Any]:
        """run_seq -> vaulted content of every record with a commitment; EvidenceAlert when one does not open it."""
        want = {r["event"]["run_seq"]: r for r in records if r["event"]["type"] in VAULTED and cite(r).get("commitment")}
        seqs, out, self.unchecked = sorted(want), {}, 0
        # lean: fixed chunks; an answer over the signer's frame refuses with quota_exceeded: lower CHUNK if records are big
        for i in range(0, len(seqs), CHUNK):
            got = self.client.content_get({"run_id": self.run_id, "seqs": seqs[i:i + CHUNK], "purpose": self.id})
            for item in got["items"]:
                if "content" not in item:
                    continue
                r = want[item["seq"]]
                e = r["event"]
                if "salt" not in item:   # changed by redaction: it opens no commitment
                    self.unchecked += 1
                elif not hmac.compare_digest(cite(r)["commitment"], "hmac-sha256:" + hmac.new(
                        bytes.fromhex(item["salt"]), _digest(e, item["content"]).encode(), "sha256").hexdigest()):
                    raise EvidenceAlert(
                        f"run {self.run_id} record {e['run_seq']} ({e['type']}, log seq {e['seq']}): the content the "
                        "vault returned does not open the record's commitment; the investigation stopped. The vault "
                        "or the record was altered: keep both and compare them with `tracekit signer reveal`")
                out[item["seq"]] = item["content"]
        return out

    # ----------------------------------------------------------------------- the recorded run

    def exchange(self, seq: int) -> int:
        """Index of the exchange whose request is record `seq`."""
        for i, x in enumerate(self.exchanges):
            if x["seq"] == seq:
                return i
        raise ValueError(f"no model exchange with its request vaulted at record {seq} of run {self.run_id}")

    def target_exchange(self, target: str) -> int:
        """The first exchange whose recorded response hits `target`."""
        pred = parse_target(target)
        for i, x in enumerate(self.exchanges):
            if isinstance(x.get("response"), dict) and pred(*outputs(x["kind"], x["response"])):
                return i
        raise ValueError(f"target {target!r} did not happen in a vaulted model response of run {self.run_id}; "
                         "pass --decision SEQ")

    def first_with(self, specs: Sequence[str]) -> int:
        """The first exchange whose request holds a block one of `specs` removes."""
        for i, x in enumerate(self.exchanges):
            if ablate(self, x["kind"], x["request"], specs)[1]:
                return i
        raise ValueError(f"no vaulted model request of run {self.run_id} holds {' | '.join(specs)}")

    def serve(self, name: str, args: Any) -> Optional[Any]:
        """The recorded result of tool `name` on `args`, or None off the tape."""
        try:
            value = loads_strict(args) if isinstance(args, str) else args
            out = self.tape.get((name, canonical(value)))
        except ValueError:   # StrictJSONError, CanonicalizationError
            return None
        return None if out is None else out.get("result", out)

    # ----------------------------------------------------------------------- replays

    def reserve(self) -> float:
        """Take one model call and its cost estimate from the budgets, before it is sent; Budget once one is spent."""
        with self.lock:
            est = self.estimate if self.max_cost is not None else 0.0
            if self.max_calls is not None and self.calls >= self.max_calls or self.max_cost is not None and (
                    self.cost >= self.max_cost or self.cost + self.held + est > self.max_cost):
                raise Budget("budget")
            self.calls += 1
            self.held += est
        return est

    def arm(self, purpose: str = "test") -> list:
        """A new replay run, its first call reserved: [run_id, run_token, the run_seq read next, the reservation]."""
        est = self.reserve()
        try:
            out = self.client.register_run({"agent": {"name": "tracekit-why"}, "replay_of": self.run_id,
                                            "investigation": self.id})
        except BaseException:
            self._release(est, 0.0)
            raise
        with self.lock:
            self.runs[out["run_id"]] = purpose
        return [out["run_id"], out["run_token"], 1, est]

    def close(self, run) -> None:
        self.client.close_run({"run_id": run[0], "run_token": run[1]})

    def _release(self, est: float, cost: float) -> None:
        with self.lock:
            self.held -= est
            self.cost += cost
            self.estimate = max(self.estimate, cost)

    def call(self, run: list, kind: str, model: str, req: Dict[str, Any]) -> Dict[str, Any]:
        """The response body to `req`, sent through the gateway in replay run `run` and read back from it; Budget once
        one is spent, ValueError for a request that can't be replayed, RuntimeError when the gateway did not record it."""
        why = unreplayable(kind, req)
        if why:
            raise ValueError(f"a replay of run {self.run_id}: {why}; it was not sent")
        est, run[3] = (self.reserve() if run[3] is None else run[3]), None
        body = {k: v for k, v in req.items() if k != "stream_options"}
        body["stream"] = False
        if kind.startswith("openai:"):
            body["store"] = False   # the provider keeps no copy of a replay
        r = urllib.request.Request(self.url + PATHS[kind], data=json.dumps(body).encode(), method="POST", headers={
            **self.headers, "Content-Type": "application/json", "X-Tracekit-Run": f"{run[0]}.{run[1]}"})
        cost = 0.0
        try:
            try:
                with self.open(r, timeout=UPSTREAM_TIMEOUT_S) as resp:
                    out = json.loads(resp.read())
            except urllib.error.HTTPError as e:
                raise RuntimeError(f"the gateway answered {e.code} for a replay of run {self.run_id}: "
                                   f"{e.read()[:500].decode('utf-8', 'replace')}") from None
            cost = (self.prices.cost(model, parsers.parse(kind, out, body)["usage"]) if self.prices else None) or 0.0
        finally:
            self._release(est, cost)
        got = self.client.read({"run_id": run[0], "run_token": run[1], "from_seq": run[2]})["events"]
        if sorted(e["data"].get("phase") for e in got if e["type"] == "model.exchange") != ["request", "response"]:
            raise RuntimeError(f"the gateway did not record the model call of replay run {run[0]} (its model.exchange "
                               "request and response): the investigation stopped. Check that the gateway reaches the "
                               "signer: a gateway whose fail mode is open forwards calls it could not record")
        run[2] = got[-1]["run_seq"] + 1
        with self.lock:
            self.models.add(str(out.get("model") or model)[:128])
        return out

    def record(self, result: Dict[str, Any]) -> int:
        """Write a finished test as a why.finding in this investigation's findings run; its run_seq."""
        with self.lock:
            if self.findings_run is None:
                out = self.client.register_run({"agent": {"name": "tracekit-why"}, "analyzes": self.run_id})
                self.findings_run = out["run_id"], out["run_token"]
            cited = {x["run_id"] for x in result["replay_runs"]}
            # what the investigation ran and no finding counts: the ranking's calls, and with a budget stop the arms it
            # abandoned; any other uncited replay run is left for the verifier to report
            uncounted = [{"run_id": r, "reason": p if p == "ranking" else "budget"} for r, p in self.runs.items()
                         if r not in cited | self.counted and (p == "ranking" or result["stopped"] == "budget")]
            self.counted |= cited | {u["run_id"] for u in uncounted}
        finding = {"target": result["target"], "intervention": result["intervention"], "n": result["n"],
                   "p_with": result["p_with"], "p_without": result["p_without"], "effect": result["effect"],
                   "interval": result["ci"], "verdict": result["verdict"], "replay_runs": result["replay_runs"],
                   "models": result["models"], "rung": result["rung"], "off_tape": result["off_tape_actions"],
                   "investigation": self.id, "looks": result["looks"], "family": result["family"],
                   "min_effect": result["min_effect"], "applied": result["applied"], "stopped": result["stopped"],
                   **({"uncounted": uncounted} if uncounted else {})}
        return self.client.why_finding({"run_id": self.findings_run[0], "run_token": self.findings_run[1],
                                        "finding": finding})["run_seq"]

    def finish(self) -> None:
        """Close the findings run, once every finding is recorded."""
        if self.findings_run is not None:
            self.close(self.findings_run)
            self.findings_run = None


# --------------------------------------------------------------------------- request bodies

def unreplayable(kind: str, req: Dict[str, Any], resp: Any = None) -> Optional[str]:
    """Why request `req` (with its recorded response `resp`) can't be replayed, or None: it lets the provider run a tool
    itself (a replay would run it again), or continues context the provider holds (a removal can't reach it)."""
    names = parsers.provider_tools(kind, req)
    if isinstance(resp, dict):
        names += [u["name"] for u in parsers.parse(kind, resp, req)["tool_uses"] if u["executed_by"] == "provider"]
    if names:
        return f"its request lets the provider run {', '.join(sorted(set(names)))[:300]} itself, which a replay would run again"
    held = [k for k in SERVER_HELD if req.get(k)]
    if held:
        return f"its request continues context the provider holds ({', '.join(held)}), which a removal cannot reach"
    return None


def _replayable(inv: "Investigation", xs: Sequence[Dict[str, Any]]) -> None:
    """ValueError, before anything is sent, when the first of recorded exchanges `xs` (the one a replay starts from)
    can't be replayed, or a later one's response shows the provider ran a tool."""
    for i, x in enumerate(xs):
        why = unreplayable(x["kind"], {} if i else x["request"], x.get("response"))
        if why:
            raise ValueError(f"record {x['seq']} of run {inv.run_id}: {why}; nothing was sent. Test a model call whose "
                             "request declares only tools the client runs (function or custom) and holds its whole "
                             "context, or record the run without provider-executed tools")


def _cleared(v: Any) -> Any:
    """A tool call's output with its content removed and its shape kept."""
    if isinstance(v, list):
        if all(isinstance(p, dict) and "stdout" in p for p in v):   # shell_call_output
            return [dict(p, stdout=REMOVED, stderr="") for p in v]
        return [{"type": "input_text", "text": REMOVED}]   # content parts
    if isinstance(v, dict) and v.get("type") == "computer_screenshot":
        return {"type": "computer_screenshot", "image_url": BLANK_PNG}
    return REMOVED


def _blocks(kind: str, req: Dict[str, Any]) -> List[Block]:
    """Every removable block of request body `req`: its path, what replaces it, its content, the tool whose result it
    is, its role and its message index."""
    out, names = [], {}
    if kind == "openai:responses":
        items = req.get("input") if isinstance(req.get("input"), list) else []   # a plain string: nothing to remove
        for i, it in enumerate(items):
            t = it.get("type", "message")
            if t in parsers.CLIENT_ITEMS:
                names[it.get("call_id")] = parsers.CLIENT_ITEMS[t][0] or it.get("name")
            elif t.endswith("_output"):
                out.append(Block(("input", i), dict(it, output=_cleared(it.get("output"))), it.get("output"),
                                 names.get(it.get("call_id")), "tool", i))
            elif t == "message":
                out.append(Block(("input", i), dict(it, content=REMOVED), it.get("content"), None, it.get("role"), i))
        return out
    for i, m in enumerate(req.get("messages") or []):
        role, content = m.get("role"), m.get("content")
        if kind == "openai:chat":
            for tc in m.get("tool_calls") or []:
                names[tc.get("id")] = (tc.get("function") or {}).get("name")
            if role == "tool":
                out.append(Block(("messages", i), dict(m, content=REMOVED), content, names.get(m.get("tool_call_id")),
                                 "tool", i))
            elif content:
                out.append(Block(("messages", i), dict(m, content=REMOVED), content, None, role, i))
        elif not isinstance(content, list):
            out.append(Block(("messages", i), dict(m, content=REMOVED), content, None, role, i))
        else:
            for j, b in enumerate(content):
                if b.get("type") == "tool_use":
                    names[b.get("id")] = b.get("name")
                elif b.get("type") == "tool_result":
                    out.append(Block(("messages", i, "content", j), dict(b, content=REMOVED), b.get("content"),
                                     names.get(b.get("tool_use_id")), "tool", i))
                elif b.get("type") in ("text", "image", "document"):
                    out.append(Block(("messages", i, "content", j), {"type": "text", "text": REMOVED}, b, None, role, i))
    return out


def _matches(spec: str, b: Block, observed: List[tuple]) -> bool:
    kind, _, pat = spec.partition(":")
    if kind == "result":
        return b.tool is not None and fnmatch.fnmatch(b.tool, pat)
    if kind == "msg":
        return pat == str(b.msg)
    if kind == "ref":
        return content_hash(b.text).startswith(pat if pat.startswith("sha256:") else "sha256:" + pat)
    if kind == "input":
        hay = _txt(b.text)
        return any(fnmatch.fnmatch(src, pat) and any(a in hay for a in found) for src, found in observed)
    raise ValueError(f"unknown intervention {spec!r}: input:<source glob>, result:<tool glob>, msg:<message index> "
                     "or ref:<hash prefix>")


def ablate(inv: Investigation, kind: str, req: Dict[str, Any], specs: Sequence[str]):
    """(request `req` with every block a spec matches replaced, whether any matched)."""
    out, hit = copy.deepcopy(req), False
    for b in _blocks(kind, req):
        if any(_matches(s, b, inv.observed) for s in specs):
            _set(out, b.path, b.repl)
            hit = True
    return out, hit


def _set(obj: Any, path: tuple, value: Any) -> None:
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


def outputs(kind: str, resp: Dict[str, Any]):
    """(tool uses the client runs [(id, name, args)], text) of a response body."""
    uses, text = [], []
    if kind == "anthropic:messages":
        for b in resp.get("content") or []:
            if b.get("type") == "tool_use":
                uses.append((b.get("id"), b.get("name"), b.get("input")))
            elif b.get("type") == "text":
                text.append(b.get("text"))
    elif kind == "openai:chat":
        m = ((resp.get("choices") or [{}])[0]).get("message") or {}
        text.append(m.get("content"))
        for tc in m.get("tool_calls") or []:
            f = tc.get("custom") or tc.get("function") or {}
            uses.append((tc.get("id"), f.get("name"), f.get("input", f.get("arguments"))))
    else:
        for it in resp.get("output") or []:
            t = it.get("type")
            if t in parsers.CLIENT_ITEMS:
                name, field, _ = parsers.CLIENT_ITEMS[t]
                uses.append((it.get("call_id"), name or it.get("name"), it.get(field)))
            elif t == "message":
                text += [p.get("text") for p in it.get("content") or [] if isinstance(p, dict)]
    return uses, "\n".join(t for t in text if isinstance(t, str))


def _append(kind: str, req: Dict[str, Any], resp: Dict[str, Any], results: List[tuple]) -> Dict[str, Any]:
    """The next request of the loop: `req`, the model's response and the tool results, in the provider's format."""
    if kind == "anthropic:messages":
        return dict(req, messages=list(req["messages"]) + [
            {"role": "assistant", "content": resp.get("content") or []},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": i, "content": _txt(r)}
                                         for i, r in results]}])
    if kind == "openai:chat":
        msg = ((resp.get("choices") or [{}])[0]).get("message") or {}
        return dict(req, messages=list(req["messages"]) + [msg] + [
            {"role": "tool", "tool_call_id": i, "content": _txt(r)} for i, r in results])
    prior = req.get("input") if isinstance(req.get("input"), list) else [{"role": "user", "content": req.get("input")}]
    calls = {it.get("call_id"): it.get("type") for it in resp.get("output") or []}
    return dict(req, input=prior + list(resp.get("output") or []) + [
        {"type": f"{calls.get(i) or 'function_call'}_output", "call_id": i, "output": _txt(r)} for i, r in results])


# --------------------------------------------------------------------------- targets

def parse_target(spec: str):
    """'tool=send_email,arg~evil.example' or 'text~wire the money' -> predicate on (tool uses, text)."""
    conds = clauses(spec)

    def pred(uses: List[tuple], text: str) -> bool:
        if not all(holds(op, text, v) for k, op, v in conds if k == "text"):
            return False
        per_use = [c for c in conds if c[0] != "text"]
        return not per_use or any(all(holds(op, (name or "") if k == "tool" else _txt(args), v)
                                      for k, op, v in per_use) for _, name, args in uses)
    pred.needle = next((v for k, _, v in conds if k != "tool"), next((v for _, _, v in conds), ""))
    return pred


def _logprob(resp: Dict[str, Any], needle: str) -> Optional[float]:
    """Log-probability of the response tokens that spell `needle`, when the provider returned logprobs (OpenAI chat)
    and the text holds it; else None."""
    toks = ((((resp.get("choices") or [{}])[0]).get("logprobs") or {}).get("content")) or []
    at = "".join(t.get("token", "") for t in toks).find(needle) if needle else -1
    if at < 0:
        return None
    lp, pos = 0.0, 0
    for t in toks:
        end = pos + len(t.get("token", ""))
        if end > at and pos < at + len(needle):
            lp += t.get("logprob", 0.0)
        pos = end
    return lp


# --------------------------------------------------------------------------- tests

def _sized(label: str, target: str, n: int, n_max: Optional[int], workers: int) -> None:
    """ValueError, before any replay, for a test whose finding the signer would refuse or whose workers are too many."""
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"--workers takes 1 to {MAX_WORKERS}")
    if max(len(label), len(target)) > 1024 or not 1 <= n <= looks(n, n_max)[-1] <= MAX_N:
        raise ValueError(f"a finding takes an intervention and a target of up to 1024 characters and 1 to {MAX_N} "
                         "pairs (--n, --n-max)")


def _one_call(inv: Investigation, i: int, req: Dict[str, Any], pred, purpose: str = "test") -> tuple:
    """Rung 1: (replay run id, target hit, off-tape actions, response) of one re-sent exchange."""
    x, run = inv.exchanges[i], inv.arm(purpose)
    try:
        resp = inv.call(run, x["kind"], x["model"], req)
    finally:
        inv.close(run)
    return run[0], pred(*outputs(x["kind"], resp)), 0, resp


def _loop(inv: Investigation, start: int, specs: Sequence[str], pred) -> tuple:
    """Rung 2: (replay run id, target hit anywhere in the continuation, off-tape actions) of the loop from exchange
    `start` with `specs` removed from every request."""
    x, run, off = inv.exchanges[start], inv.arm(), 0
    req = x["request"]
    try:
        for _ in range(len(inv.exchanges) - start + MARGIN):
            req = ablate(inv, x["kind"], req, specs)[0]
            resp = inv.call(run, x["kind"], x["model"], req)
            uses, text = outputs(x["kind"], resp)
            if pred(uses, text):
                return run[0], True, off
            if not uses:   # the model stopped
                break
            results = []
            for id_, name, args in uses:
                got = inv.serve(name, args)
                off += got is None
                results.append((id_, STUB if got is None else got))
            req = _append(x["kind"], req, resp, results)
        return run[0], False, off
    finally:
        inv.close(run)


def counterfactual_signed(inv: Investigation, intervention: Union[str, Sequence[str]], target: str, *,
                          decision: Optional[int] = None, rung: Optional[int] = None, start: Optional[int] = None,
                          n: int = 30, n_max: Optional[int] = None, family: int = 1,
                          base_cache: Optional[Dict[int, tuple]] = None, workers: int = 1,
                          min_effect: float = MIN_EFFECT, size_role: bool = False, record: bool = True) -> Dict[str, Any]:
    """Does removing `intervention` change how often `target` happens? Paired and sequential as
    replay.counterfactual, each arm a replay run: the exchange re-sent unchanged (control) or ablated.

    rung 1 (the default with `decision`, the run_seq of an exchange's request record; else the first exchange whose
    response hits the target): score that one response. rung 2 (the default without `decision`): continue the loop
    from `start` (default: `decision`, else the first exchange holding the item) and score the whole continuation.
    base_cache shares the control arm between tests of the same exchange (or start) and target. `record`: write the
    result as a why.finding."""
    specs = [intervention] if isinstance(intervention, str) else list(intervention)
    pred = parse_target(target)
    label = " | ".join(specs)
    _sized(label, target, n, n_max, workers)
    rung = rung or (1 if decision is not None else 2)
    if rung == 1:
        at = inv.exchange(decision) if decision is not None else inv.target_exchange(target)
    else:
        at = start if start is not None else inv.exchange(decision) if decision is not None else inv.first_with(specs)
    x = inv.exchanges[at]
    _replayable(inv, [x] if rung == 1 else inv.exchanges[at:])
    ablated, applied = ablate(inv, x["kind"], x["request"], specs)
    if rung == 2 and not applied:
        applied = any(ablate(inv, y["kind"], y["request"], specs)[1] for y in inv.exchanges[at:])
    cache = base_cache if base_cache is not None else {}
    lock, treated = threading.Lock(), {}

    def arm(removed: bool) -> tuple:
        if rung == 1:
            return _one_call(inv, at, ablated if removed else x["request"], pred)[:3]
        return _loop(inv, at, specs if removed else (), pred)

    def trial(i: int) -> tuple:
        with lock:
            c = cache.get(i)
        if c is None:
            c = arm(False)
            with lock:
                cache[i] = c
        t = arm(True)
        with lock:
            treated[i] = t
        return c[1], t[1], applied, t[2]

    s = paired(trial, n, n_max, family, min_effect, workers, size_role)
    runs = [{"run_id": cache[i][0], "arm": "control", "hit": cache[i][1]} for i in range(s["n"])] + \
        [{"run_id": treated[i][0], "arm": "ablated", "hit": treated[i][1]} for i in range(s["n"])]
    result = {**summary(s, label, target, family, min_effect), "applied": applied,
              "scope": "decision" if rung == 1 else "run", "rung": rung, "decision": x["seq"], "run_id": inv.run_id,
              "replay_runs": runs, "models": sorted(inv.models)[:32], "investigation": inv.id,
              "model_calls": inv.calls, "content_unchecked": inv.unchecked, "assumptions": ASSUMPTIONS,
              "method": ("re-send one recorded model call through the gateway" if rung == 1 else
                         "re-simulate the agent loop from the vault through the gateway, tool results from tape")
                        + ", paired, Newcombe 95% CI"}
    if len(specs) > 1:
        result["group"] = specs
    if record:
        result["finding"] = inv.record(result)
    return result


def _lasso(X: List[List[float]], y: List[float], alpha: float = 0.01, iters: int = 200) -> List[float]:
    """Weights of a sparse linear fit of y on X (L1, coordinate descent on centred data)."""
    n, m = len(X), len(X[0]) if X else 0
    xm, ym = [sum(r[j] for r in X) / n for j in range(m)], sum(y) / n
    xc = [[r[j] - xm[j] for j in range(m)] for r in X]
    resid, w = [v - ym for v in y], [0.0] * m
    norms = [sum(r[j] ** 2 for r in xc) for j in range(m)]
    for _ in range(iters):
        for j in range(m):
            if not norms[j]:
                continue
            rho = sum(xc[i][j] * (resid[i] + xc[i][j] * w[j]) for i in range(n))
            new = math.copysign(max(abs(rho) - alpha * n, 0.0), rho) / norms[j]
            if new != w[j]:
                resid = [resid[i] - xc[i][j] * (new - w[j]) for i in range(n)]
                w[j] = new
    return w


def rank(inv: Investigation, target: str, *, decision: Optional[int] = None, k: int = 32, seed: int = 0,
         workers: int = 1) -> Dict[str, Any]:
    """Rung 0, predicted: a ContextCite-style surrogate. Re-send the target's exchange (`decision`, else the first
    whose response hits the target) with k random halves of its blocks removed, score each response (the target's
    log-probability when the provider returns logprobs for every one, else whether it hit), fit a sparse linear
    model of the score on which blocks were kept, and rank the blocks by weight. A ranking says what to test first,
    never what caused the target. OpenAI chat requests ask for logprobs; other providers' are scored by hit."""
    pred = parse_target(target)
    if not 1 <= k <= MAX_K or not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"the ranking takes 1 to {MAX_K} samples and 1 to {MAX_WORKERS} workers")
    at = inv.exchange(decision) if decision is not None else inv.target_exchange(target)
    x = inv.exchanges[at]
    _replayable(inv, [x])
    blocks = _blocks(x["kind"], x["request"])
    if not blocks:
        raise ValueError(f"the request of record {x['seq']} has no blocks to rank")
    rng = random.Random(seed)
    masks = [[rng.random() < 0.5 for _ in blocks] for _ in range(k)]

    def one(mask: List[bool]) -> tuple:
        req = copy.deepcopy(x["request"])
        for keep, b in zip(mask, blocks):
            if not keep:
                _set(req, b.path, b.repl)
        if x["kind"] == "openai:chat":
            req["logprobs"] = True
        _, hit, _, resp = _one_call(inv, at, req, pred, "ranking")
        return hit, _logprob(resp, pred.needle)

    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(workers) as pool:
            scored = list(pool.map(one, masks))
    else:
        scored = [one(mk) for mk in masks]
    lps = [lp for _, lp in scored]
    y = lps if all(lp is not None for lp in lps) else [float(h) for h, _ in scored]
    w = _lasso([[float(v) for v in mk] for mk in masks], y)
    items = sorted(({"spec": "ref:" + content_hash(b.text)[7:23], "weight": round(wj, 4), "role": b.role,
                     "tool": b.tool, "message": b.msg, "preview": _txt(b.text)[:120]} for b, wj in zip(blocks, w)),
                   key=lambda r: -r["weight"])
    return {"label": "predicted", "target": target, "decision": x["seq"], "k": k,
            "score": "logprob" if y is lps else "hit", "items": items, "model_calls": inv.calls}


def attribute_signed(inv: Investigation, target: str, suspects: Optional[Sequence[str]] = None, *,
                     decision: Optional[int] = None, rung: Optional[int] = None, n: int = 10, n_max: int = 40,
                     workers: int = 1, k: int = 32, top: int = 4, size_roles: bool = True,
                     min_effect: float = MIN_EFFECT, record: bool = True) -> Dict[str, Any]:
    """Find the cause on a signed run: replay.find_cause over counterfactual_signed. Without suspects, rank() the target's
    exchange and test its `top` blocks with a positive weight (the ranking is returned, labelled predicted). Every
    test is written as a why.finding unless record=False."""
    _sized(" | ".join(suspects or ()), target, n, n_max, workers)
    ranking = None
    if suspects is None:
        ranking = rank(inv, target, decision=decision, k=k, workers=workers)
        suspects = [r["spec"] for r in ranking["items"][:top] if r["weight"] > 0]
        if not suspects:
            raise ValueError("the surrogate found no block that raises the target: pass --suspect SPEC")
    rung = rung or (1 if decision is not None else 2)
    start = None if rung == 1 or decision is not None else min(inv.first_with([sp]) for sp in suspects)

    def test(specs: Sequence[str], family: int, cache: Dict[int, Any], single: bool) -> Dict[str, Any]:
        return counterfactual_signed(inv, list(specs), target, decision=decision, rung=rung, start=start, n=n, n_max=n_max,
                           family=family, base_cache=cache, workers=workers, min_effect=min_effect,
                           size_role=size_roles and single, record=record)
    out = find_cause(test, target, suspects)
    out.update(ranking=ranking, model_calls=inv.calls, investigation=inv.id, run_id=inv.run_id)
    return out
