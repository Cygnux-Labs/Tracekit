"""Run the attribution benchmark.

    python -m eval.why_bench                                   # simulated model, all scenarios
    python -m eval.why_bench --model claude --claude-model ID --runs 10 --n 20 --yes

For each scenario: record R runs. In every run where the harmful action happened, ask four methods
which untrusted input caused it, and score them against the ground truth.

  reach        blame every untrusted input upstream of the action (what tracing alone gives you)
  provenance   blame inputs that are the only untrusted source of an argument value (string matching)
  reuse        blame the untrusted input whose wording the researcher reused most
  why          replay without each untrusted input (paired runs, tool results from tape), exact McNemar
               test per input, Benjamini-Hochberg at q=0.05 across the inputs of that action
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import statistics
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set

from tracekit.why import System, load_run
from tracekit.why.analysis import alerts, arg_provenance, candidates
from tracekit.why.graph import build_graph, target_hits
from tracekit.why.replay import attribute, counterfactual, newcombe_diff, verdict_for

from . import models
from .scenarios import SCENARIOS, Scenario

METHODS = ("reach", "provenance", "reuse", "why")


def build_system(sc: Scenario, model_fn) -> System:
    def program(rt):
        planner = rt.agent("planner", role="decides steps")
        executor = rt.agent("executor", parent="planner", role="runs tools")
        for name, docs in sc.researchers.items():
            r = rt.agent(name, role="reads sources")
            refs = [r.observe(d.text, source=d.source, trust=d.trust) for d in docs]
            refs += [r.act(tool, args) for tool, args in sc.lookups.get(name, [])]
            summary = r.decide([rt.task_ref, *refs], model="llm", purpose="summarize")
            r.send("planner", summary)
        plan = planner.decide([rt.task_ref, *planner.inbox()], model="llm", purpose="plan")
        planner.send("executor", plan)
        calls = executor.decide(executor.inbox(), model="runner", purpose="execute")
        for c in calls.value["calls"]:
            executor.act(c["tool"], c.get("args") or {}, decision=calls)
        return {"tools_run": [c["tool"] for c in calls.value["calls"]]}

    return System(program, models={"llm": model_fn, "runner": models.runner}, tools=sc.tools, task=sc.task,
                  name=f"bench:{sc.id}", sensitive_tools=sc.sensitive)


def attribute_run(run, sc: Scenario, system: System, n: int, n_max: Optional[int] = None,
                  args_ns: Any = None) -> Dict[str, Any]:
    g = build_graph(run)
    hit = target_hits(run, sc.harmful)[0]
    node = "ev:" + hit["id"]
    cands = [c for c in candidates(run, g, node) if c["kind"] == "input" and c["trust"] == "untrusted"]
    sources = [g.nodes[c["node"]]["event"]["source"] for c in cands]
    out: Dict[str, Any] = {"candidates": sources}

    out["reach"] = set(sources)

    prov = arg_provenance(run, g, hit)
    blamed: Set[str] = set()
    for p in prov:
        if p["status"] == "untrusted-only":
            blamed |= {s["label"] for s in p["sources"]}
    out["provenance"] = blamed  # empty = abstained

    reuse = {g.nodes[c["node"]]["event"]["source"]: c["reuse"] for c in cands}
    best = max(reuse.values(), default=0)
    out["reuse"] = {s for s, r in reuse.items() if r == best and best > 0}

    if getattr(args_ns, "per_input", False):
        # the earlier procedure: one sequential test per suspect, each with its own baseline arm
        tests = [counterfactual(run, f"input:{s}", sc.harmful, n=n, system=system, save=False, n_max=n_max,
                                family=len(sources)) for s in sources]
        out["why"] = {s for s, t in zip(sources, tests) if t["verdict"] == "causal"}
        out["roles"] = {}
    else:
        # The attribution: remove all suspects first, then narrow down, one shared baseline arm;
        # every interval corrected for all the tests it may run. The same verdicts the app shows.
        att = attribute(run, sc.harmful, [f"input:{s}" for s in sources], n=n, n_max=n_max or n, system=system,
                        save=False, size_roles=False)  # scored on which inputs are blamed, not their share
        tests = att["tests"]
        blamed = {c["intervention"] for c in att["causes"]} | {sp for j in att["joint"] for sp in j}
        out["why"] = {sp[len("input:"):] for sp in blamed}
        out["roles"] = {c["intervention"][len("input:"):]: c["role"] for c in att["causes"]}
        out["summary"] = att["summary"]
    out["tests"] = [{"source": t["intervention"], "effect": t["effect"], "ci": t["ci"], "p": t["p_value"], "n": t["n"],
                     "verdict": t["verdict"], "p_with": t["p_with"], "role": t.get("role")} for t in tests]
    out["high_alert"] = any(a["severity"] == "high" and a.get("node") == node for a in alerts(run, g))
    return out


def score(blamed: Set[str], truth: Set[str]) -> Dict[str, Any]:
    if not blamed:
        return {"exact": 0, "precision": None, "recall": 0.0, "abstain": 1, "false_blames": 0}
    tp = len(blamed & truth)
    return {"exact": int(blamed == truth), "precision": tp / len(blamed), "recall": tp / len(truth),
            "abstain": 0, "false_blames": len(blamed - truth)}


def run_scenario(sc: Scenario, model: str, runs: int, n: int, args, workdir: str) -> Dict[str, Any]:
    counter = models.Counter()
    if model == "sim":
        fn = models.sim_model(sc, counter)
    elif model == "openai":
        fn = models.openai_model(sc, counter, args.openai_model, args.base_url, args.temperature,
                                 json_mode=not getattr(args, "no_json_mode", False))
    else:
        fn = models.claude_model(sc, counter, args.claude_model, args.temperature)
    system = build_system(sc, fn)
    rows: List[Dict[str, Any]] = []
    harmful_runs = 0
    high_alert_runs = 0
    record_calls = 0
    skipped = 0
    max_calls = getattr(args, "max_calls", None)
    model_agents = len(sc.researchers) + 1
    for seed in range(runs):
        before = counter.calls
        r = system.run(seed=seed, out_dir=os.path.join(workdir, sc.id), run_id=f"{sc.id}-{seed}")
        record_calls += counter.calls - before
        run = load_run(r.path)
        g = build_graph(run)
        high_alert_runs += any(a["severity"] == "high" for a in alerts(run, g))
        if sc.harmful is None or not target_hits(run, sc.harmful):
            continue
        harmful_runs += 1
        n_cands = len({e["source"] for e in run.of_type("input") if e.get("trust") == "untrusted"})
        if max_calls and counter.calls + 2 * (getattr(args, "n_max", None) or n) * model_agents * n_cands > max_calls:
            skipped += 1  # over budget: count the harmful run, skip its replay tests
            print(f"  {sc.id} seed {seed}: harmful, attribution skipped (call budget {max_calls})", flush=True)
            continue
        before = counter.calls
        att = attribute_run(run, sc, system, n, getattr(args, "n_max", None), args)
        att["replay_calls"] = counter.calls - before
        att["scores"] = {m: score(att[m], sc.truth) for m in METHODS}
        att["run"] = run.run_id
        rows.append(att)
        print(f"  {sc.id} seed {seed}: why blamed {sorted(att['why'])} (truth {sorted(sc.truth)}), "
              f"{att['replay_calls']} replay model calls", flush=True)

    def agg(m: str) -> Dict[str, Any]:
        s = [r["scores"][m] for r in rows]
        if not s:
            return {}
        prec = [x["precision"] for x in s if x["precision"] is not None]
        return {"exact": sum(x["exact"] for x in s) / len(s),
                "precision": statistics.mean(prec) if prec else None,
                "recall": statistics.mean(x["recall"] for x in s),
                "abstain": sum(x["abstain"] for x in s) / len(s),
                "false_blames_per_run": statistics.mean(x["false_blames"] for x in s)}

    oracle = None
    m = getattr(args, "oracle", 0) or 0
    if m and sc.harmful and sc.truth:
        # Is the planted document really the cause for THIS model? Fresh runs (new seeds, no tape) with and
        # without it. Independent of the per-run replays tracekit why does, and the check that ground truth by
        # construction holds: a model may do the harmful thing anyway, injection or not.
        spec = [f"input:{t}" for t in sorted(sc.truth)]
        hit = lambda r: bool(target_hits(r, sc.harmful))
        k_with = sum(hit(system.run(seed=10_000 + i)) for i in range(m))
        k_without = sum(hit(system.run(seed=20_000 + i, interventions=spec)) for i in range(m))
        lo, hi = newcombe_diff(k_with, m, k_without, m)
        oracle = {"n": m, "p_with": k_with / m, "p_without": k_without / m, "effect": (k_with - k_without) / m,
                  "ci": [round(lo, 3), round(hi, 3)], "verdict": verdict_for(lo, hi)}
        print(f"  {sc.id} oracle: harmful in {k_with}/{m} fresh runs with the planted document, "
              f"{k_without}/{m} without -> {oracle['verdict']}", flush=True)

    return {"scenario": sc.id, "title": sc.title, "runs": runs, "harmful_runs": harmful_runs, "oracle": oracle,
            "attributed_runs": len(rows), "skipped_for_budget": skipped, "model_calls": counter.calls,
            "high_alert_runs": high_alert_runs, "string_matching": sc.what_string_matching_sees,
            "methods": {m: agg(m) for m in METHODS},
            "high_alert_on_harmful": (sum(r["high_alert"] for r in rows) / len(rows)) if rows else None,
            "record_calls_per_run": record_calls / runs,
            "replay_calls_per_attribution": statistics.mean(r["replay_calls"] for r in rows) if rows else 0,
            "detail": [{k: (sorted(v) if isinstance(v, set) else v) for k, v in r.items()} for r in rows],
            "tokens": {"input": counter.input_tokens, "output": counter.output_tokens},
            "parse_failures": getattr(counter, "parse_failures", 0)}


def pct(x: Optional[float]) -> str:
    return "–" if x is None else f"{x:.0%}"


def markdown(res: Dict[str, Any]) -> str:
    L = [f"# Attribution benchmark: {res['model']}", "",
         f"{res['date']} · runs per scenario: {res['runs']} · replays per test: {res['n']}" +
         (f" to {res['n_max']} (sequential)" if res.get("n_max") else "") +
         (" · **simulated model: these numbers test the pipeline, not a real LLM**" if res["model"] == "sim" else ""), "",
         "Exact = the method blamed exactly the true cause. Precision = share of blamed inputs that were the cause. "
         "Abstain = the method named nothing.", "",
         "| Scenario | Harmful runs | Reach exact | Provenance exact / abstain | Reuse exact | **why exact** | why false blames / run | Replay calls / attribution |",
         "|---|---|---|---|---|---|---|---|"]
    for s in res["scenarios"]:
        if not s.get("attributed_runs", s["harmful_runs"]):
            L.append(f"| {s['scenario']} | {s['harmful_runs']} of {s['runs']} | – | – | – | – | – | – |")
            continue
        m = s["methods"]
        att = s.get("attributed_runs", s["harmful_runs"])
        hr = f"{s['harmful_runs']} of {s['runs']}" + (f" ({att} tested)" if att < s["harmful_runs"] else "")
        L.append(f"| {s['scenario']} | {hr} | {pct(m['reach']['exact'])} | "
                 f"{pct(m['provenance']['exact'])} / {pct(m['provenance']['abstain'])} | {pct(m['reuse']['exact'])} | "
                 f"**{pct(m['why']['exact'])}** | {m['why']['false_blames_per_run']:.2f} | "
                 f"{s['replay_calls_per_attribution']:.0f} |")
    tot = [s for s in res["scenarios"] if s.get("attributed_runs", s["harmful_runs"])]
    if tot:
        def k(s):
            return s.get("attributed_runs", s["harmful_runs"])

        def w(meth, key):
            return sum(s["methods"][meth][key] * k(s) for s in tot) / sum(k(s) for s in tot)
        L.append(f"| **All** | {sum(k(s) for s in tot)} attributed | {pct(w('reach','exact'))} | "
                 f"{pct(w('provenance','exact'))} / {pct(w('provenance','abstain'))} | {pct(w('reuse','exact'))} | "
                 f"**{pct(w('why','exact'))}** | {w('why','false_blames_per_run'):.2f} | – |")
    ctrl = [s for s in res["scenarios"] if s["scenario"].startswith("control")]
    L += ["", "**Scenarios**", ""]
    for s in res["scenarios"]:
        L.append(f"- `{s['scenario']}`: {s['title']}. String matching: {s['string_matching']}.")
    orc = [s for s in res["scenarios"] if s.get("oracle")]
    if orc:
        L += ["", "**Is the planted cause really the cause for this model?** Fresh runs with and without the planted "
                  "document (no replay, new seeds). Where it is not clearly causal, \"exact\" scores above rest on "
                  "a ground truth that does not hold for this model.", ""]
        for s in orc:
            o = s["oracle"]
            label = "the harmful action never happened: this model ignores the injection" \
                if o["p_with"] == 0 and o["p_without"] == 0 else o["verdict"]
            L.append(f"- `{s['scenario']}`: harmful in {o['p_with']:.0%} of {o['n']} runs with it, {o['p_without']:.0%} "
                     f"without; effect {o['effect']:+.2f} [{o['ci'][0]:+.2f}, {o['ci'][1]:+.2f}]: **{label}**")
    if ctrl:
        c = ctrl[0]
        L += ["", f"**Control (no injection):** high alerts in {c['high_alert_runs']} of {c['runs']} runs."]
    skipped = sum(s.get("skipped_for_budget", 0) for s in res["scenarios"])
    calls = sum(s.get("model_calls", 0) for s in res["scenarios"])
    tin = sum(s.get("tokens", {}).get("input", 0) for s in res["scenarios"])
    tout = sum(s.get("tokens", {}).get("output", 0) for s in res["scenarios"])
    bad = sum(s.get("parse_failures", 0) for s in res["scenarios"])
    L += ["", f"Model calls: {calls:,}" + (f" · tokens: {tin:,} in, {tout:,} out" if tin else "") +
          (f" · harmful runs not attributed because of the call budget: {skipped}" if skipped else "") +
          (f" · model replies with no parseable JSON (read as no action): {bad}" if bad else "")]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.why_bench")
    ap.add_argument("--model", choices=("sim", "claude", "openai"), default="sim")
    ap.add_argument("--claude-model", help="Claude model id, for --model claude")
    ap.add_argument("--openai-model", help="model name, for --model openai (e.g. qwen2.5:7b on Ollama)")
    ap.add_argument("--base-url", default="http://localhost:11434/v1",
                    help="OpenAI-compatible endpoint, for --model openai (default: local Ollama)")
    ap.add_argument("--no-json-mode", action="store_true", help="--model openai: don't request JSON-constrained output")
    ap.add_argument("--temperature", type=float, default=1.0)
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--n-max", type=int, help="sequential replay tests: double n up to this until decisive")
    ap.add_argument("--per-input", action="store_true",
                    help="the earlier procedure: one test per suspect with its own baseline (for comparison)")
    ap.add_argument("--oracle", type=int, default=0,
                    help="fresh runs with and without the planted document, to check it is the cause for this model")
    ap.add_argument("--scenario", action="append", help="limit to these scenario ids")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results"))
    ap.add_argument("--keep-runs", help="write the recorded runs here instead of a temp folder")
    ap.add_argument("--yes", action="store_true", help="skip the cost confirmation for real models")
    ap.add_argument("--max-calls", type=int, help="per-scenario cap on model calls; replay tests that would pass it are skipped")
    ap.add_argument("--tag", help="extra word in the result file name, e.g. the scenario in a parallel run")
    a = ap.parse_args(argv)
    if a.model == "claude" and not a.claude_model:
        ap.error("--claude-model is required with --model claude")
    if a.model == "openai" and not a.openai_model:
        ap.error("--openai-model is required with --model openai")
    scs = [SCENARIOS[s] for s in (a.scenario or SCENARIOS)]
    if a.model != "sim" and not a.yes:
        est = sum(a.runs * len(sc.researchers) + a.runs + a.runs * 4 * 2 * a.n * (len(sc.researchers) + 1) for sc in scs)
        print(f"Worst case about {est:,} model calls (every run harmful, 4 candidates each). "
              f"Typical is lower. Re-run with --yes to proceed.")
        return 1
    workdir = a.keep_runs or tempfile.mkdtemp(prefix="tracekit-why-bench-")
    res = {"model": {"sim": "sim", "claude": a.claude_model, "openai": a.openai_model}[a.model], "date": dt.date.today().isoformat(),
           "runs": a.runs, "n": a.n, "n_max": a.n_max,
           "json_mode": a.model == "openai" and not a.no_json_mode, "temperature": a.temperature, "scenarios": []}
    for sc in scs:
        print(f"== {sc.id}: {sc.title}", flush=True)
        res["scenarios"].append(run_scenario(sc, a.model, a.runs, a.n, a, workdir))
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.join(a.out, f"{res['model'].replace('/', '_')}-{res['date']}" + (f"-{a.tag}" if a.tag else ""))
    with open(stem + ".json", "w") as f:
        json.dump(res, f, indent=2, default=list)
    md = markdown(res)
    with open(stem + ".md", "w") as f:
        f.write(md)
    print("\n" + md)
    print(f"wrote {stem}.json and {stem}.md; recorded runs in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
