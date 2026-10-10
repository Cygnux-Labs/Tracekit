#!/usr/bin/env python3
"""E17: do the v2 server packs hold on realistic tool calls?  tests/data/policy/deny/<class>.jsonl and
benign/<class>.jsonl hold {tool, args, expect, note} cases; server.yaml (which composes the coding, browser and server-*
packs) decides each one with both engines, RE2 and the `regex` fallback. A deny case is caught when the verdict is its
`expect` (deny, or ask where the pack holds the call for a person); a benign case is a false positive when it is denied
or held. Every corpus tool must map to a class, so no case is caught by the unknown-tool rule alone. Nothing is
executed. Writes eval/results/e17_policy_corpus.json; exit 0 only when deny recall is 100%, the
benign false-positive rate is at most 2% and both engines decide every case identically."""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402

PACK = os.path.join(ROOT, "tracekit", "policy2", "packs", "server.yaml")
CORPUS = os.path.join(ROOT, "tests", "data", "policy")
MAX_FP = 0.02


def load(kind):
    """{class: [case, ...]} from <kind>/<class>.jsonl."""
    out = {}
    for path in sorted(glob.glob(os.path.join(CORPUS, kind, "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            out[os.path.basename(path)[:-6]] = [json.loads(line) for line in f if line.strip()]
    return out


def run():
    pol, errors = pc.build(PACK)
    if errors:
        raise SystemExit("\n".join(errors))
    engines = [Engine(pol, "re2"), Engine(pol, "regex")]
    out = {"policy_hash": engines[0].policy_hash, "engines": [e.engine for e in engines], "classes": {},
           "missed": [], "false_positives": [], "engine_mismatches": [], "unmapped": []}
    for kind in ("deny", "benign"):
        for cls, cases in load(kind).items():
            row = out["classes"].setdefault(cls, {"deny": 0, "caught": 0, "benign": 0, "fp": 0})
            row[kind] += len(cases)
            for case in cases:
                if engines[0].tool_class(case["tool"]) == "unknown":
                    out["unmapped"].append(case)
                re2, rx = (e.decide(case["tool"], case["args"]) for e in engines)
                if {**re2, "engine": None} != {**rx, "engine": None}:
                    out["engine_mismatches"].append({**case, "re2": re2["verdict"], "regex": rx["verdict"]})
                got = {"verdict": re2["verdict"], "rule_ids": re2["rule_ids"]}
                if kind == "deny" and re2["verdict"] == case["expect"]:
                    row["caught"] += 1
                elif kind == "deny":
                    out["missed"].append({**case, **got})
                elif re2["verdict"] in ("deny", "ask"):
                    row["fp"] += 1
                    out["false_positives"].append({**case, **got})
    n_deny = sum(r["deny"] for r in out["classes"].values())
    n_benign = sum(r["benign"] for r in out["classes"].values())
    out["deny_recall"] = (n_deny - len(out["missed"])) / n_deny
    out["benign_fp_rate"] = len(out["false_positives"]) / n_benign
    out["ok"] = out["deny_recall"] == 1 and out["benign_fp_rate"] <= MAX_FP and not out["engine_mismatches"] \
        and not out["unmapped"]
    return out


def main():
    out = run()
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", "e17_policy_corpus.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"{'class':10s} {'deny recall':>14s} {'benign FP':>12s}")
    for cls, r in sorted(out["classes"].items()):
        print(f"{cls:10s} {r['caught']:>6d}/{r['deny']:<6d}  {r['fp']:>5d}/{r['benign']:<5d}")
    print(f"TOTAL deny recall {out['deny_recall']:.1%}, benign FP {out['benign_fp_rate']:.2%}, "
          f"engine mismatches {len(out['engine_mismatches'])} ({' vs '.join(out['engines'])}), unmapped tools {len(out['unmapped'])}")
    for kind in ("missed", "false_positives", "engine_mismatches", "unmapped"):
        for c in out[kind]:
            print(f"  {kind}: {c['tool']} {json.dumps(c['args'])[:100]} -> {c.get('verdict', c.get('re2'))} {c.get('rule_ids', '')}")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
