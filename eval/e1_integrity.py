#!/usr/bin/env python3
"""E1: tamper detection. Builds ledgers from real agent records, applies random
mutations of seven classes, and measures detection by (a) the hash chain alone and
(b) the chain plus an external anchor of the head taken before the mutation.
Also measures, for the strongest attacker (full re-chain), detection probability as a
function of the anchoring interval."""
import json
import os
import random
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)
import common  # noqa: E402
import verify  # noqa: E402

random.seed(7)
SRC = [os.path.join(KIT, "demo/sample-output/multi-agent-ledger.jsonl"),
       os.path.join(KIT, "demo/sample-output/ledger.jsonl")]
BODIES = []
for p in SRC:
    for r in common.read_ledger(p):
        BODIES.append({k: v for k, v in r.items() if k not in ("seq", "ts", "prev", "hash")})
N, TRIALS = 300, 200


def build(path):
    if os.path.exists(path):
        os.remove(path)
    common.append([random.choice(BODIES) for _ in range(N)], path=path)
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def write(path, recs, raw_tail=None):
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        if raw_tail:
            f.write(raw_tail)


def rechain(recs):
    prev = common.GENESIS
    for i, r in enumerate(recs):
        r["seq"], r["prev"] = i, prev
        r["hash"] = common.record_hash(r)
        prev = r["hash"]
    return recs


def mutate(kind, recs):
    i = random.randrange(1, len(recs) - 1)
    if kind == "edit_field":
        recs[i]["event"] = recs[i]["event"] + "_x"
    elif kind == "delete_record":
        del recs[i]
    elif kind == "swap_adjacent":
        recs[i], recs[i + 1] = recs[i + 1], recs[i]
    elif kind == "insert_forged":
        f = dict(recs[i]); f["event"] = "PreToolUse"; f["tool_name"] = "Bash"; f["tool_input"] = {"command": "echo forged"}
        f["hash"] = common.record_hash(f); recs.insert(i + 1, f)
    elif kind == "truncate_tail":
        del recs[-random.randint(1, 20):]
    elif kind == "rechain_after_edit":
        recs[i]["tool_input"] = {"command": "rm -rf build"}
        rechain(recs)
    elif kind == "rechain_after_delete":
        del recs[i]
        rechain(recs)
    return recs


def detect(path, anchor_line):
    n, problems, head = verify.verify(path)
    chain_ok = not problems
    anchors = os.path.join(os.path.dirname(path), "anchors.log")
    with open(anchors, "w") as f:
        f.write(anchor_line + "\n")
    anchor_fail = bool(verify.check_anchors(anchors, path))
    return (not chain_ok), (not chain_ok) or anchor_fail


def main():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "ledger.jsonl")
    kinds = ["edit_field", "delete_record", "swap_adjacent", "insert_forged", "truncate_tail",
             "rechain_after_edit", "rechain_after_delete", "torn_write"]
    results = {}
    for kind in kinds:
        chain_hits = anchor_hits = 0
        for _ in range(TRIALS):
            recs = build(path)
            anchor = f"t {recs[-1]['seq']} {recs[-1]['hash']}"
            if kind == "torn_write":
                write(path, recs, raw_tail='{"seq": %d, "ev' % len(recs))
            else:
                write(path, mutate(kind, recs))
            c, a = detect(path, anchor)
            chain_hits += c; anchor_hits += a
        results[kind] = {"chain_only": chain_hits / TRIALS, "chain_plus_anchor": anchor_hits / TRIALS, "trials": TRIALS}
        print(kind, results[kind], flush=True)

    # anchoring interval vs detection of a full re-chain attack at a uniformly random position
    interval = {}
    for k in [1, 5, 10, 25, 50, 100, 300]:
        hits = 0
        for _ in range(TRIALS):
            recs = build(path)
            # anchors every k records; the attack lands a uniform number of records after the last one
            last_anchor = N - 1 - random.randrange(k)
            anchor = f"t {last_anchor} {recs[last_anchor]['hash']}"
            i = random.randrange(0, N)
            recs[i]["tool_input"] = {"command": "tampered"}
            rechain(recs)
            write(path, recs)
            hits += detect(path, anchor)[1]
        interval[k] = hits / TRIALS
        print("interval", k, interval[k], flush=True)
    out = {"records_per_ledger": N, "mutations": results, "anchor_interval_vs_detection": interval,
           "source_records": len(BODIES)}
    json.dump(out, open(os.path.join(KIT, "eval/results/e1_integrity.json"), "w"), indent=2)


if __name__ == "__main__":
    os.makedirs(os.path.join(KIT, "eval/results"), exist_ok=True)
    main()
