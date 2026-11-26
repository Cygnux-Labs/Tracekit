#!/usr/bin/env python3
"""E17: do the v2 server packs hold on realistic tool calls?  tests/data/policy/deny/<class>.jsonl and
benign/<class>.jsonl hold {tool, args, expect, note} cases; server.yaml (which composes the coding, browser and server-*
packs) decides each one with both engines, RE2 and the `regex` fallback. A case that names `"packs"`, such as
`"packs": ["dev"]` for a rule only dev.yaml defines, is decided on each pack it names instead (its server decision
is then skipped); without the field the case is decided on server.yaml alone, exactly as before. A deny case is
caught when the verdict is its `expect` (deny, or ask where the pack holds the call for a person); a benign case is a
false positive when it is denied
or held. Every corpus tool must map to a class, so no case is caught by the unknown-tool rule alone. Nothing is
executed. Writes eval/results/e17_policy_corpus.json, with every case's verdict and rule ids (`decisions`, which
tests/test_signer_policy.py holds the engine to); exit 0 only when deny recall is 100%, the benign false-positive rate
is at most 2% and both engines decide every case identically."""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402

PACKS_DIR = os.path.join(ROOT, "tracekit", "policy2", "packs")
CORPUS = os.path.join(ROOT, "tests", "data", "policy")
MAX_FP = 0.02


def load(kind):
    """{class: [case, ...]} from <kind>/<class>.jsonl."""
    out = {}
    for path in sorted(glob.glob(os.path.join(CORPUS, kind, "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            out[os.path.basename(path)[:-6]] = [json.loads(line) for line in f if line.strip()]
    return out


def build_engines(pack):
    pol, errors = pc.build(os.path.join(PACKS_DIR, pack + ".yaml"))
    if errors:
        raise SystemExit("\n".join(errors))
    return [Engine(pol, "re2"), Engine(pol, "regex")]


def run(cases_by_kind=None):
    if cases_by_kind is None:
        cases_by_kind = {kind: load(kind) for kind in ("deny", "benign")}
    pack_names = {"server"}
    for kind in ("deny", "benign"):
        for cases in cases_by_kind[kind].values():
            for case in cases:
                pack_names.update(case.get("packs", ["server"]))
    engines = {pack: build_engines(pack) for pack in sorted(pack_names)}
    server = engines["server"]
    out = {"policy_hash": server[0].policy_hash, "engines": [e.engine for e in server], "classes": {}, "packs": {},
           "missed": [], "false_positives": [], "engine_mismatches": [], "unmapped": [], "decisions": {}}
    for kind in ("deny", "benign"):
        for cls, cases in cases_by_kind[kind].items():
            row = out["classes"].setdefault(cls, {"deny": 0, "caught": 0, "benign": 0, "fp": 0})
            row[kind] += len(cases)
            for i, case in enumerate(cases):
                packs = case.get("packs", ["server"])
                missed, fps = [], []
                for pack in packs:
                    re2e, rxe = engines[pack]
                    if re2e.tool_class(case["tool"]) == "unknown":
                        out["unmapped"].append({**case, "pack": pack} if pack != "server" else case)
                    re2, rx = (e.decide(case["tool"], case["args"]) for e in (re2e, rxe))
                    if {**re2, "engine": None} != {**rx, "engine": None}:
                        out["engine_mismatches"].append({**case, "pack": pack, "re2": re2["verdict"], "regex": rx["verdict"]})
                    got = {"verdict": re2["verdict"], "rule_ids": re2["rule_ids"]}
                    key = f"{kind}/{cls}:{i + 1}" if pack == "server" else f"{kind}/{cls}@{pack}:{i + 1}"
                    out["decisions"][key] = " ".join([re2["verdict"]] + re2["rule_ids"])
                    prow = out["packs"].setdefault(pack, {"deny": 0, "caught": 0, "benign": 0, "fp": 0})
                    prow[kind] += 1
                    extra = {"pack": pack} if pack != "server" else {}
                    if kind == "deny" and re2["verdict"] == case["expect"]:
                        prow["caught"] += 1
                    elif kind == "deny":
                        missed.append({**case, **got, **extra})
                    elif re2["verdict"] in ("deny", "ask"):
                        prow["fp"] += 1
                        fps.append({**case, **got, **extra})
                # a deny case is caught when every pack it names decides its expect; a benign case is one false
                # positive however many of its packs hold it (its class row counts the case once), with the packs
                # holding it named in the entry; a pack's own row counts it against that pack, as the row counts
                # each of the pack's decisions
                if kind == "deny" and not missed:
                    row["caught"] += 1
                out["missed"].extend(missed)
                if fps:
                    row["fp"] += 1
                    entry = fps[0]
                    if len(fps) > 1 or len(packs) > 1:
                        entry = {**entry, "packs": [f.get("pack", "server") for f in fps]}
                    out["false_positives"].append(entry)
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
    for pack, r in sorted(out["packs"].items()):
        print(f"  {pack}: deny recall {r['caught']}/{r['deny']}, benign FP {r['fp']}/{r['benign']}")
    for kind in ("missed", "false_positives", "engine_mismatches", "unmapped"):
        for c in out[kind]:
            print(f"  {kind}: {c['tool']} {json.dumps(c['args'])[:100]} -> {c.get('verdict', c.get('re2'))} {c.get('rule_ids', '')}")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
