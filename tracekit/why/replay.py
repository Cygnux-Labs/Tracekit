"""Replay and counterfactual tests.

A recorded run names the program that produced it. Replay re-executes that program with
tool results served from the run's tape (so nothing real is re-sent) and model calls made
again with fresh seeds. A counterfactual test runs N paired trials with and without an
intervention (e.g. remove one document) and reports how often a target action happens in each.
"""
from __future__ import annotations

import importlib
import math
import threading
from concurrent.futures import ThreadPoolExecutor
from statistics import NormalDist
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .core import ModelOutput, Ref, Run, Runtime, Tape, ablation_matches, canonical, derive_seed
from .graph import parse_target

Z95 = 1.959963984540054
# Smallest effect worth acting on. A cause is "ruled out" only when the interval shows any effect is
# smaller than this; a wide interval that merely includes zero is "inconclusive", never "ruled out".
MIN_EFFECT = 0.2


def verdict_for(lo: float, hi: float, applied: bool = True, min_effect: float = MIN_EFFECT) -> str:
    if not applied:
        return "not-applied"
    if lo > 0:
        return "causal"
    if hi < 0:
        return "suppressive"
    if hi < min_effect and lo > -min_effect:
        return "ruled-out"
    return "inconclusive"


DECISIVE = ("causal", "suppressive", "ruled-out")


def looks(n: int, n_max: Optional[int]) -> List[int]:
    """Trial counts at which a sequential test checks its interval: n, 2n, 4n, ... and finally n_max."""
    if not n_max or n_max <= n:
        return [n]
    out = [n]
    while out[-1] * 2 < n_max:
        out.append(out[-1] * 2)
    return out + [n_max]


def z_for(k: int) -> float:
    """Critical value for k simultaneous comparisons at an overall 95% level (Bonferroni): k looks of a
    sequential test, times the number of inputs tested together for one action. Checking an interval
    several times, or testing several suspects, must not raise the false-positive rate."""
    return Z95 if k <= 1 else NormalDist().inv_cdf(1 - 0.05 / (2 * k))


def _futile(i: int, n: int, effect: float) -> bool:
    """Stop early when, after at least 2n pairs, the estimated effect is still within 5 points of zero.
    Stopping for futility can only lose power; it never adds false positives."""
    return i >= 2 * n and abs(effect) <= 0.05


def n_hint(n: int, lo: float, hi: float, min_effect: float = MIN_EFFECT) -> int:
    """Roughly how many paired trials would shrink the interval's half-width to min_effect
    (intervals narrow with the square root of n)."""
    half = (hi - lo) / 2
    return int(math.ceil(n * (half / min_effect) ** 2)) if half > min_effect else n


@dataclass
class System:
    """A replayable multi-agent program: program(rt) plus the models and tools it uses."""

    program: Callable[[Runtime], Any]
    models: Dict[str, Callable[..., Any]]
    tools: Dict[str, Callable[..., Any]] = field(default_factory=dict)
    task: Any = None
    name: str = ""
    sensitive_tools: Sequence[str] = ()
    untrusted_tools: Sequence[str] = ()

    def run(self, *, seed: int = 0, interventions: Sequence[str] = (), tape: Optional[Tape] = None,
            out_dir: Optional[str] = None, live_tools: bool = True, run_id: Optional[str] = None,
            task: Any = None, sink: Any = None, guard: Any = None) -> Run:
        """Replays (counterfactual, replay) never pass a guard: they measure what the agents would
        do, and the tape already keeps them from repeating side effects."""
        rt = Runtime(self.models, self.tools, out_dir=out_dir, run_id=run_id,
                     task=self.task if task is None else task, program=self.name, seed=seed,
                     interventions=interventions, tape=tape, live_tools=live_tools,
                     sensitive_tools=self.sensitive_tools, untrusted_tools=self.untrusted_tools,
                     sink=sink, guard=guard)
        outcome = self.program(rt)
        return rt.finish(outcome)


def load_system(spec: str) -> System:
    mod, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(mod), attr or "SYSTEM")
    if not isinstance(obj, System):
        raise TypeError(f"{spec} is not a tracekit why System")
    if not obj.name:
        obj.name = spec
    return obj


def system_for(run: Run) -> System:
    prog = run.start.get("program")
    if not prog:
        raise ValueError("run has no program recorded; pass a System explicitly")
    return load_system(prog)


def recorded_task(run: Run) -> Any:
    for e in run.of_type("input"):
        if e.get("kind") == "task":
            return run.value(e["ref"])
    return None


# --------------------------------------------------------------------------- stats

def wilson(k: int, n: int, z: float = Z95):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar test on discordant pairs: b pairs where the target happened only with
    the item, c pairs where it happened only without it. Returns the p-value."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def benjamini_hochberg(pvalues: List[float], q: float = 0.05) -> List[bool]:
    """Which hypotheses to reject while controlling the false discovery rate at q."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    cutoff = 0
    for rank, i in enumerate(order, 1):
        if pvalues[i] <= q * rank / m:
            cutoff = rank
    keep = set(order[:cutoff])
    return [i in keep for i in range(m)]


def newcombe_diff(k0: int, n0: int, k1: int, n1: int, z: float = Z95):
    """95% CI for p0 - p1 (Newcombe hybrid score method)."""
    p0, p1 = k0 / n0, k1 / n1
    l0, u0 = wilson(k0, n0, z)
    l1, u1 = wilson(k1, n1, z)
    d = p0 - p1
    lo = d - math.sqrt((p0 - l0) ** 2 + (u1 - p1) ** 2)
    hi = d + math.sqrt((u0 - p0) ** 2 + (p1 - l1) ** 2)
    return (max(-1.0, lo), min(1.0, hi))


# --------------------------------------------------------------------------- counterfactual

def counterfactual(run: Run, intervention: Union[str, Sequence[str]], target: str, *, n: int = 30,
                   system: Optional[System] = None, use_tape: bool = True, save: bool = True,
                   seed_base: str = "cf", live_tools: bool = False, min_effect: float = MIN_EFFECT,
                   n_max: Optional[int] = None, family: int = 1, base_cache: Optional[Dict[int, bool]] = None,
                   workers: int = 1, size_role: bool = False) -> Dict[str, Any]:
    """Does removing `intervention` change how often `target` happens?

    Paired design: trial i uses the same seed with and without the intervention, so the only
    difference between a pair is the intervention (common random numbers).

    Sequential when n_max > n: run n pairs, check the interval, and keep doubling up to n_max until
    the verdict is decisive (causal, suppressive or ruled out). The interval is widened for the number
    of checks, so stopping early does not inflate false positives. Real models often repeat a harmful
    action in only some replays; a fixed small n then leaves the answer inconclusive.

    family: how many inputs are being tested together for this action. The interval is corrected for
    it, so testing every suspect of an action keeps the overall false-positive rate at 5%.

    intervention may be a list of specs, removed together (a group test).
    base_cache: share the "nothing removed" arm between tests of the same run, target and seed_base.
    Trial i of that arm is the same computation whatever is being removed, so it is run once.
    workers: run trials in parallel threads (hosted model APIs, or Ollama with OLLAMA_NUM_PARALLEL).
    size_role: once causal, keep going (up to n_max) until the interval also says whether the item is a
    primary cause or a contributing factor.

    Tool calls that match the recorded tape replay its results. Calls the original run never made
    are stubbed unless live_tools=True, so a replay cannot send a real email or move real money."""
    system = system or system_for(run)
    pred = parse_target(target)
    task = recorded_task(run)
    specs = [intervention] if isinstance(intervention, str) else list(intervention)
    label = " | ".join(specs)
    cache = base_cache if base_cache is not None else {}
    lock = threading.Lock()
    base_runs = [0]

    def hit(r: Run) -> bool:
        return any(pred(e, r) for e in r.events)

    def trial(i: int):
        s = derive_seed(seed_base, run.run_id, i)
        with lock:
            h0 = cache.get(i)
        if h0 is None:
            h0 = hit(system.run(seed=s, tape=Tape(run) if use_tape else None, task=task,
                                run_id=f"{run.run_id}-b{i}", live_tools=live_tools))
            with lock:
                cache[i] = h0
                base_runs[0] += 1
        treat = system.run(seed=s, interventions=specs, tape=Tape(run) if use_tape else None,
                           task=task, run_id=f"{run.run_id}-t{i}", live_tools=live_tools)
        return (h0, hit(treat), any(e.get("ablated") for e in treat.of_type("decision")),
                sum(1 for e in treat.of_type("action") if e.get("mode") != "tape"))

    k0 = k1 = 0
    matched = 0
    off_tape = 0
    flips = {"removed": 0, "added": 0}
    plan = looks(n, n_max)
    z = z_for(len(plan) * family)
    i = 0
    stopped = "n_max"
    pool = ThreadPoolExecutor(workers) if workers > 1 else None
    try:
        for size in plan:
            batch = range(i, size)
            outs = list(pool.map(trial, batch)) if pool else [trial(j) for j in batch]
            i = size
            for h0, h1, applied, off in outs:
                k0 += h0
                k1 += h1
                if h0 and not h1:
                    flips["removed"] += 1
                if h1 and not h0:
                    flips["added"] += 1
                matched += applied
                off_tape += off
            lo, hi = newcombe_diff(k0, i, k1, i, z)
            verdict = verdict_for(lo, hi, matched > 0, min_effect)
            if verdict == "causal" and size_role and role_for(k0 / i, [lo, hi]) == "cause":
                continue  # proven; keep going until its share is clear too
            if verdict in DECISIVE or verdict == "not-applied":
                stopped = "decisive"
                break
            if len(plan) > 1 and _futile(i, n, (k0 - k1) / i):
                stopped = "futility"  # no effect seen; stopped to save replays, not proof of none
                break
    finally:
        if pool:
            pool.shutdown()
    n = i
    p0, p1 = k0 / n, k1 / n
    result = {
        "intervention": label, "target": target, "n": n, "looks": len(plan), "n_max": plan[-1],
        "family": family, "stopped": stopped,
        "p_with": round(p0, 4), "p_without": round(p1, 4),
        "effect": round(p0 - p1, 4), "ci": [round(lo, 4), round(hi, 4)],
        "verdict": verdict, "pair_flips": flips,
        "p_value": round(min(1.0, len(plan) * mcnemar_exact(flips["removed"], flips["added"])), 6),  # x looks
        "intervention_applied_in": matched, "off_tape_actions": off_tape, "min_effect": min_effect,
        "n_needed": n_hint(n, lo, hi, min_effect) if verdict == "inconclusive" else None,
        "program_runs": n + base_runs[0],  # what the test cost: base runs not served from the cache, plus treatments
        "method": "paired re-execution, tool results from tape, Newcombe 95% CI"
                  + (f", sequential over {len(plan)} looks (Bonferroni)" if len(plan) > 1 else ""), "scope": "run",
    }
    if len(specs) > 1:
        result["group"] = specs
    if verdict == "causal":
        result["role"] = role_for(p0, result["ci"])
    if save:
        run.add_test(result)
    return result


def role_for(p_with: float, ci: Sequence[float]) -> str:
    """How much of the action a causal item explains, judged on the interval, not the point estimate:
    primary       removing it confidently prevents at least half of the occurrences
    contributing  it confidently explains less than half: the action mostly happens without it too
    cause         causal, but the data cannot yet say which (more trials would)"""
    if p_with <= 0:
        return "cause"
    lo, hi = ci[0] / p_with, ci[1] / p_with
    return "primary" if lo >= 0.5 else "contributing" if hi < 0.5 else "cause"


def attribute(run: Run, target: str, suspects: Optional[Sequence[str]] = None, *, n: int = 10, n_max: int = 40,
              system: Optional[System] = None, min_effect: float = MIN_EFFECT, workers: int = 1,
              save: bool = True, seed_base: str = "cf", size_roles: bool = True) -> Dict[str, Any]:
    """Which of the suspects caused `target`, and how much of it do they explain?

    1. Remove every suspect at once. If the action still happens about as often, none of them is the
       reason: the agent does it on its own (or for a reason that was not tested). Stop there.
    2. Otherwise test the suspects one by one (or, with more than four, by halving the group) and
       classify each causal one as a primary cause or a contributing factor.
    3. A group that matters when no single member does is reported as a joint cause: each member is
       enough on its own, so removing one changes nothing (redundant causes).

    Every test shares one "nothing removed" arm, and all intervals are corrected for every test this
    function may run, so the whole attribution keeps a 5% false-positive rate.
    size_roles: keep testing a proven cause until its share is clear (primary or contributing). It costs
    more replays; turn it off when only "which inputs" matters.
    Default suspects: every untrusted input upstream of the first matching action."""
    system = system or system_for(run)
    if suspects is None:
        suspects = _default_suspects(run, target)
    suspects = list(dict.fromkeys(suspects))
    m = len(suspects)
    if m == 0:
        raise ValueError("no suspects: the action has no untrusted input upstream; pass suspects explicitly")
    # every test this may run: the group, the halvings or singles, and a leave-one-in test per member
    # of a joint group
    family = 1 if m == 1 else 1 + (m if m <= 4 else 2 * m - 2) + m
    cache: Dict[int, bool] = {}
    tests: List[Dict[str, Any]] = []

    def test(specs: Sequence[str]) -> Dict[str, Any]:
        r = counterfactual(run, list(specs) if len(specs) > 1 else specs[0], target, n=n, n_max=n_max,
                           system=system, family=family, base_cache=cache, min_effect=min_effect,
                           workers=workers, save=save, seed_base=seed_base, size_role=size_roles and len(specs) == 1)
        tests.append(r)
        return r

    group = test(suspects)
    causes: List[Dict[str, Any]] = []
    joint: List[List[str]] = []
    if m > 1 and group["verdict"] == "causal":
        def narrow_joint(specs: List[str]) -> List[str]:
            """Members that are enough on their own: removing every other member leaves the action as
            likely as with nothing removed (the leave-one-in test is not causal)."""
            if len(specs) > 4:
                return specs
            keep = [sp for sp in specs if test([o for o in specs if o != sp])["verdict"] != "causal"]
            return keep or specs

        def split(specs: List[str]) -> None:
            if len(specs) <= 4:
                singles = [(sp, test([sp])) for sp in specs]
                hits = [(sp, r) for sp, r in singles if r["verdict"] == "causal"]
                causes.extend(_cause(sp, r) for sp, r in hits)
                if not hits:
                    joint.append(narrow_joint(specs))
                return
            half = len(specs) // 2
            parts = [specs[:half], specs[half:]]
            results = [test(p) for p in parts]
            causal = [p for p, r in zip(parts, results) if r["verdict"] == "causal"]
            if not causal:
                joint.append(specs)
            for p in causal:
                split(p)
        split(suspects)
    elif group["verdict"] == "causal":
        causes.append(_cause(suspects[0], group))
    if group["verdict"] == "causal" and m > 1 and not causes and not joint:
        joint.append(suspects)

    explained = group["effect"] if group["verdict"] == "causal" else 0.0
    unprompted = group["p_without"]
    if group["verdict"] == "causal":
        summary = "; ".join(f"{c['role']} cause {c['intervention']} ({c['effect']:+.2f})" for c in causes) or \
            "the suspects matter only together"
        if joint:
            summary += "; joint (each enough alone): " + ", ".join(" + ".join(j) for j in joint)
        if unprompted >= 0.2:
            summary += f"; the action still happens in {unprompted:.0%} of replays without any of them"
    elif group["verdict"] in ("ruled-out",) or (group["p_with"] > 0 and group["p_without"] >= group["p_with"] - 0.05):
        summary = (f"none of the {m} suspects explains it: the action happens in {group['p_with']:.0%} of replays "
                   f"with them and {group['p_without']:.0%} without any of them")
    else:
        summary = f"inconclusive: removing all {m} suspects gave {group['effect']:+.2f} {group['ci']}"
    return {"target": target, "suspects": suspects, "group": group, "tests": tests, "causes": causes,
            "joint": joint, "explained": round(explained, 4), "unprompted_rate": unprompted,
            "program_runs": sum(t["program_runs"] for t in tests), "family": family, "summary": summary}


def _cause(spec: str, r: Dict[str, Any]) -> Dict[str, Any]:
    return {"intervention": spec, "role": r.get("role") or role_for(r["p_with"], r["ci"]),
            "effect": r["effect"], "ci": r["ci"], "p_with": r["p_with"], "p_without": r["p_without"], "n": r["n"]}


def _default_suspects(run: Run, target: str) -> List[str]:
    from .graph import build_graph, target_hits
    hits = target_hits(run, target)
    if not hits:
        raise ValueError(f"target {target!r} did not happen in this run")
    g = build_graph(run, infer=False)
    anc = g.ancestors("ev:" + hits[0]["id"], ("observed",))
    out = []
    for nid in sorted(anc, key=lambda x: g.nodes[x]["seq"]):
        ev = g.nodes[nid]["event"]
        if g.nodes[nid]["type"] == "input" and ev.get("kind") != "task" and ev.get("trust") == "untrusted":
            out.append(f"input:{ev['source']}")
    return list(dict.fromkeys(out))


def decision_test(run: Run, decision: Any, intervention: str, *, n: int = 30,
                  models: Optional[Dict[str, Callable[..., Any]]] = None, system: Optional[System] = None,
                  contains: Optional[str] = None, save: bool = True, min_effect: float = MIN_EFFECT,
                  n_max: Optional[int] = None, family: int = 1) -> Dict[str, Any]:
    """Direct effect on ONE recorded model call, using only the log: re-call the model on the recorded
    context with and without the matching items. No need to re-run the program, so this works for
    systems that cannot be replayed end to end. `decision` is a seq number or event id.

    With `contains`, measures P(output contains text). Without it, measures how often removing the
    item changes the output, minus how often a second full-context call changes it (`noise`). Real
    model APIs ignore seeds, so without that control any sampling noise would read as an effect."""
    ev = next((e for e in run.of_type("decision") if e["seq"] == decision or e["id"] == decision), None)
    if ev is None:
        raise ValueError(f"no decision {decision!r} in run")
    if models is None:
        models = (system or system_for(run)).models
    fn = models.get(ev["model"])
    if fn is None:
        raise KeyError(f"model {ev['model']!r} is not available for replay")
    ctx = [(Ref(c["ref"], run.value(c["ref"]), c.get("kind", "input"), ev["agent"], c.get("source", ""),
                c.get("trust", "trusted")), run.value(c["ref"])) for c in ev["context"]]
    full = [v for _, v in ctx]
    kept = [v for r, v in ctx if not ablation_matches(intervention, r)]
    applied = len(kept) < len(full)

    def call(values, seed):
        out = fn(values, purpose=ev.get("purpose", ""), seed=seed, params=ev.get("params") or {}, agent=ev["agent"])
        return out.value if isinstance(out, ModelOutput) else out

    k0 = k1 = 0
    plan = looks(n, n_max)
    z = z_for(len(plan) * family)
    i = 0
    for size in plan:
        while i < size:
            s = derive_seed("dt", run.run_id, ev["seq"], i)
            i += 1  # seeds are derived from the 0-based trial index, as before
            a, b = call(full, s), call(kept, s)
            if contains is not None:
                k0 += contains in canonical(a).decode()
                k1 += contains in canonical(b).decode()
            else:
                k1 += canonical(a) != canonical(b)            # changed when the item is removed
                k0 += canonical(a) != canonical(call(full, s))  # changed anyway: sampling noise
        if contains is not None:
            lo, hi = newcombe_diff(k0, i, k1, i, z)
        else:
            lo, hi = newcombe_diff(k1, i, k0, i, z)
        verdict = verdict_for(lo, hi, applied, min_effect)
        eff_now = (k0 - k1) / i if contains is not None else (k1 - k0) / i
        if verdict in DECISIVE or verdict == "not-applied" or (len(plan) > 1 and _futile(i, n, eff_now)):
            break
    n = i
    noise = None
    if contains is not None:
        p0, p1, eff = k0 / n, k1 / n, (k0 - k1) / n
        target = f"decision#{ev['seq']} output~{contains}"
    else:
        p0, p1, eff, noise = None, None, (k1 - k0) / n, round(k0 / n, 4)
        target = f"decision#{ev['seq']} output changed"
    result = {"intervention": intervention, "target": target, "n": n, "looks": len(plan), "n_max": plan[-1],
              "p_with": p0, "p_without": p1,
              "effect": round(eff, 4), "ci": [round(lo, 4), round(hi, 4)], "verdict": verdict,
              "noise": noise, "min_effect": min_effect,
              "n_needed": n_hint(n, lo, hi, min_effect) if verdict == "inconclusive" else None, "scope": "decision", "decision": ev["id"], "decision_seq": ev["seq"],
              "method": "re-call one recorded model call with and without the item, paired seeds"}
    if save:
        run.add_test(result)
    return result


def replay(run: Run, *, system: Optional[System] = None, seed: Optional[int] = None,
           interventions: Sequence[str] = ()) -> Run:
    """Re-run once. With the original seed and no intervention, a deterministic program reproduces
    the original decisions; `diff_runs` shows where it did not."""
    system = system or system_for(run)
    task = recorded_task(run)
    return system.run(seed=run.start.get("seed", 0) if seed is None else seed, interventions=interventions,
                      tape=Tape(run), task=task, run_id=run.run_id + "-replay", live_tools=False)


def diff_runs(a: Run, b: Run) -> List[Dict[str, Any]]:
    """Align decisions and actions by (agent, type, ordinal) and report the first divergences."""
    def key_events(r: Run):
        counts: Dict[tuple, int] = {}
        out = {}
        for e in r.events:
            if e["type"] not in ("decision", "action", "message"):
                continue
            k = (e["agent"], e["type"])
            i = counts.get(k, 0)
            counts[k] = i + 1
            sig = e.get("output") or (e.get("tool"), e.get("args_ref")) or e.get("ref")
            if e["type"] == "message":
                sig = (e["to"], e["ref"])
            out[k + (i,)] = (e, sig)
        return out

    ka, kb = key_events(a), key_events(b)
    diffs = []
    for k in sorted(set(ka) | set(kb), key=lambda k: (ka.get(k, kb.get(k))[0]["seq"])):
        ea, eb = ka.get(k), kb.get(k)
        if ea is None or eb is None:
            diffs.append({"at": list(k), "change": "only-in-" + ("replay" if ea is None else "original")})
        elif ea[1] != eb[1]:
            diffs.append({"at": list(k), "change": "different"})
    return diffs
