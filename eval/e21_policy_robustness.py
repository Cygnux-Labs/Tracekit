#!/usr/bin/env python3
"""E21: how do the v2 packs decide calls they were not written against, and how fast?

Two profiles: `default` (server.yaml, what E17 measures) and `strict` (strict.yaml).
(a) The held-out pool, eval/e21_heldout/corpus.jsonl: {tool, args, label (harmful|benign), severity, technique, owasp,
    category, evasion, note}, written blind to the rules and only scored, never tuned against. A harmful call is caught
    when it is denied or held (ask); deny-only is reported beside it, and so are catches by TK-UNKNOWN-TOOL alone (a
    tool no pack maps, held by the server pack's `unknown_tools: ask`). A benign call is a false positive when it is
    denied or held. Broken down by category, severity and evasion.
(c) eval/e21_benign_sessions.jsonl: calls of ordinary developer sessions, written by the pack's builder (so tuned),
    for false positives only; E17's benign calls are scored the same way on both profiles.
(d) Latency per decision (the fastest of three per call), p50/p99/max, on both engines, for dev.yaml and both
    profiles, over E17's corpus and both E21 sets.
(e) No-regression gates against the first run, recorded in eval/results/e21_policy_robustness.json and kept by later
    runs: per profile, held-out recall doesn't drop and the false-positive rate of each benign set (held-out, sessions,
    E17) doesn't rise; p99 stays within 25% of the first run's on the same machine (re-measured once before failing;
    another machine is not compared). False positives over 2% (default) or 5% (strict) are reported as over target.
Exit 0 only when every gate holds and both engines decide every call the same. `--record` writes the gates anew."""
import collections
import glob
import json
import os
import platform
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402

PACKS = os.path.join(ROOT, "tracekit", "policy2", "packs")
PROFILES = {"default": "server.yaml", "strict": "strict.yaml"}
TARGET_FP = {"default": 0.02, "strict": 0.05}   # reported, not gated
HELDOUT = os.path.join(ROOT, "eval", "e21_heldout", "corpus.jsonl")
SESSIONS = os.path.join(ROOT, "eval", "e21_benign_sessions.jsonl")
E17 = os.path.join(ROOT, "tests", "data", "policy")
RESULTS = os.path.join(ROOT, "eval", "results", "e21_policy_robustness.json")
HELD = ("deny", "ask")
SETS = ("heldout", "sessions", "e17")   # the sets whose benign calls are scored for false positives


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def tags(value):
    """A breakdown key's values: a list counts under each element, nothing under `none`."""
    values = value if isinstance(value, list) else [value]
    return [str(v) for v in values if v not in (None, "", False)] or ["none"]


def score(engines, cases):
    """Both engines decide each case; (rows by breakdown, totals, engine mismatches)."""
    rows = {k: collections.defaultdict(collections.Counter) for k in ("category", "severity", "evasion")}
    total, mismatches, missed, fps = collections.Counter(), [], [], []
    for c in cases:
        a, b = (e.decide(c["tool"], c["args"]) for e in engines)
        if {**a, "engine": None} != {**b, "engine": None}:
            mismatches.append({"tool": c["tool"], "re2": a["verdict"], "regex": b["verdict"]})
        harmful = c.get("label", "benign") == "harmful"
        got = {"label": "harmful" if harmful else "benign",
               "caught": harmful and a["verdict"] in HELD, "deny": harmful and a["verdict"] == "deny",
               "unknown_only": harmful and a["rule_ids"] == ["TK-UNKNOWN-TOOL"],
               "fp": not harmful and a["verdict"] in HELD}
        for key in [got["label"]] + [k for k in ("caught", "deny", "unknown_only", "fp") if got[k]]:
            total[key] += 1
            for dim, by in rows.items():
                for t in tags(c.get(dim)):
                    by[t][key] += 1
        if harmful and not got["caught"]:
            missed.append({k: c.get(k) for k in ("tool", "category", "severity", "evasion", "technique")})
        if got["fp"]:
            fps.append({"tool": c["tool"], "args": json.dumps(c["args"])[:160], "verdict": a["verdict"],
                        "rule_ids": a["rule_ids"]})
    return ({dim: {t: dict(n) for t, n in sorted(by.items())} for dim, by in rows.items()}, dict(total), mismatches,
            missed, fps)


def rates(total):
    h, b = total.get("harmful", 0), total.get("benign", 0)
    return {"recall": total.get("caught", 0) / h if h else None, "deny_recall": total.get("deny", 0) / h if h else None,
            "fp_rate": total.get("fp", 0) / b if b else None}


def latency(engine, calls):
    took = []
    for tool, args in calls:
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            engine.decide(tool, args)
            best = min(best, time.perf_counter() - start)
        took.append(best * 1e6)
    took.sort()
    return {"p50_us": round(took[len(took) // 2]), "p99_us": round(took[len(took) * 99 // 100]),
            "max_us": round(took[-1]), "calls": len(took)}


def machine():
    return f"{platform.system()} {platform.machine()} {platform.processor()} python {platform.python_version()}"


def run(record=False):
    heldout = load(HELDOUT) if os.path.exists(HELDOUT) else None
    sessions = load(SESSIONS)
    e17 = [(c["tool"], c["args"]) for p in sorted(glob.glob(os.path.join(E17, "*", "*.jsonl"))) for c in load(p)]
    calls = e17 + [(c["tool"], c["args"]) for c in (heldout or []) + sessions]
    e17_benign = [c for p in sorted(glob.glob(os.path.join(E17, "benign", "*.jsonl"))) for c in load(p)]
    out = {"machine": machine(), "heldout_cases": len(heldout) if heldout is not None else None,
           "session_calls": len(sessions), "profiles": {}, "latency": {}, "engine_mismatches": []}
    for name, pack in PROFILES.items():
        pol, errors = pc.build(os.path.join(PACKS, pack))
        if errors:
            raise SystemExit("\n".join(errors))
        engines = [Engine(pol, "re2"), Engine(pol, "regex")]
        prof = out["profiles"][name] = {"pack": pack, "policy_hash": engines[0].policy_hash}
        for key, cases in (("heldout", heldout), ("sessions", sessions), ("e17", e17_benign)):
            if cases is None:
                continue
            by, total, mismatches, missed, fps = score(engines, cases)
            prof[key] = {**rates(total), "totals": total, "by": by, "missed": missed, "false_positives": fps}
            out["engine_mismatches"] += [{"profile": name, "set": key, **m} for m in mismatches]
        for e in engines:
            out["latency"][f"{name}/{e.engine.split('@')[0]}"] = latency(e, calls)
    for e in (Engine(pc.build(os.path.join(PACKS, "dev.yaml"))[0], x) for x in ("re2", "regex")):
        out["latency"][f"dev/{e.engine.split('@')[0]}"] = latency(e, calls)
    old = None if record or not os.path.exists(RESULTS) else json.load(open(RESULTS, encoding="utf-8")).get("gates")
    out["gates"] = keep(old, {
        "machine": out["machine"],
        "min_heldout_recall": {n: p["heldout"]["recall"] for n, p in out["profiles"].items() if "heldout" in p},
        "max_fp_rate": {n: {k: p[k]["fp_rate"] for k in SETS if k in p} for n, p in out["profiles"].items()},
        "max_p99_us": {k: round(v["p99_us"] * 1.25) for k, v in out["latency"].items()}})
    out["over_target"] = [f"{n} {k} false positives {p[k]['fp_rate']:.2%} over the {TARGET_FP[n]:.0%} target"
                          for n, p in out["profiles"].items() for k in SETS
                          if k in p and p[k]["fp_rate"] > TARGET_FP[n]]
    out["failed"] = gate(out, calls)
    out["ok"] = not out["failed"] and not out["engine_mismatches"]
    return out


def keep(old, first):
    """The recorded gates `old`, with what they lack (a new set, profile or engine) taken from this run's `first`."""
    if isinstance(first, dict):
        return {k: keep(old.get(k) if isinstance(old, dict) else None, v) for k, v in first.items()}
    return first if old is None else old


def gate(out, calls):
    g, failed = out["gates"], []
    for name, p in out["profiles"].items():
        for key in SETS:
            cap = g["max_fp_rate"].get(name, {}).get(key)
            if key in p and cap is not None and p[key]["fp_rate"] > cap:
                failed.append(f"{name} {key} false positives {p[key]['fp_rate']:.2%} > the first run's {cap:.2%}")
        want = g["min_heldout_recall"].get(name)
        if want is not None and "heldout" in p and p["heldout"]["recall"] < want:
            failed.append(f"{name} held-out recall {p['heldout']['recall']:.2%} < {want:.2%}")
    if g["machine"] == out["machine"]:
        for key, cap in g["max_p99_us"].items():
            if out["latency"].get(key, {}).get("p99_us", 0) > cap:
                prof, engine = key.split("/")
                pol = pc.build(os.path.join(PACKS, PROFILES.get(prof, prof + ".yaml")))[0]
                again = latency(Engine(pol, engine), calls)   # best of two before it fails
                out["latency"][key] = min(out["latency"][key], again, key=lambda x: x["p99_us"])
                if out["latency"][key]["p99_us"] > cap:
                    failed.append(f"{key} p99 {out['latency'][key]['p99_us']} us > {cap} us")
    return failed


def main():
    out = run(record="--record" in sys.argv)
    os.makedirs(os.path.dirname(RESULTS), exist_ok=True)
    with open(RESULTS, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    if out["heldout_cases"] is None:
        print(f"no held-out pool at {os.path.relpath(HELDOUT, ROOT)}: held-out scores skipped")
    for name, p in out["profiles"].items():
        for key in SETS:
            if key not in p:
                continue
            r = p[key]
            print(f"{name:8s} {key:9s} recall {_pct(r['recall'])} (deny only {_pct(r['deny_recall'])}, by an "
                  f"unmapped tool alone {r['totals'].get('unknown_only', 0)}), benign FP {_pct(r['fp_rate'])}")
            if key == "heldout":
                for dim in ("category", "severity", "evasion"):
                    for t, n in r["by"][dim].items():
                        print(f"    {dim:9s} {t:24s} caught {n.get('caught', 0)}/{n.get('harmful', 0)} "
                              f"deny {n.get('deny', 0)}  FP {n.get('fp', 0)}/{n.get('benign', 0)}")
    for key, v in out["latency"].items():
        print(f"latency {key:14s} p50 {v['p50_us']} us  p99 {v['p99_us']} us  max {v['max_us']} us ({v['calls']} calls)")
    for f in out["over_target"]:
        print("over target:", f)
    for f in out["failed"]:
        print("FAILED", f)
    if out["engine_mismatches"]:
        print("engine mismatches", len(out["engine_mismatches"]))
    return 0 if out["ok"] else 1


def _pct(x):
    return "n/a" if x is None else f"{x:.1%}"


if __name__ == "__main__":
    sys.exit(main())
