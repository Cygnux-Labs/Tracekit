#!/usr/bin/env python3
"""E1: tamper detection on the v0.2 signed ledger.

Builds ledgers of signed, hash-chained records, applies random mutations, and measures detection by
  (a) the ledger alone: hash chain + Ed25519 signatures (what `tracekit observe` and `verify` check), and
  (b) the ledger plus independent witness checkpoints taken before the attack.
It also measures, for the strongest attacker (holds the signing key and re-chains and re-signs
everything), detection as a function of the witness interval. Writes eval/results/e1_integrity.json."""
import json
import os
import random
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import crypto  # noqa: E402
from tracekit.core import GENESIS, event_hash, now_ts  # noqa: E402
from tracekit.ledger import Keys, make_record  # noqa: E402
from tracekit.observe import verify_ledger  # noqa: E402
from tracekit.witness import make_checkpoint  # noqa: E402

random.seed(7)
N, TRIALS = 120, 60
TOOLS = [("Bash", {"command": "ls -la"}), ("Read", {"file_path": "src/app.py"}), ("Edit", {"file_path": "src/app.py"}),
         ("Bash", {"command": "python3 -m pytest -q"}), ("Write", {"file_path": "notes.md"})]
SECRET, PUBLIC = crypto.generate()
KEYS = Keys(SECRET, PUBLIC)


def make_event(i, prev):
    tool, ti = random.choice(TOOLS)
    return {"v": 1, "run_id": "run1", "agent_id": "main", "parent_id": None, "source": "hook", "type": "tool.call",
            "ts": now_ts(), "seq": i, "prev_hash": prev, "data": {"tool": tool, "input": ti, "n": i}}


def build_records(events=None):
    recs, prev = [], GENESIS
    for i in range(N):
        e = make_event(i, prev)
        recs.append(make_record(e, KEYS))
        prev = recs[-1]["hash"]
    return recs


def rechain(recs, key=True):
    """Rebuild the chain after an edit. With the key the attacker re-signs; without it, signatures go stale."""
    prev = GENESIS
    for i, r in enumerate(recs):
        e = r["event"]; e["seq"], e["prev_hash"] = i, prev
        if key:
            recs[i] = make_record(e, KEYS)
        else:
            r["hash"] = event_hash(e)
        prev = recs[i]["hash"]
    return recs


def checkpoints(recs, every):
    return [make_checkpoint(r["event"]["seq"], r["hash"], KEYS) for r in recs if (r["event"]["seq"] + 1) % every == 0]


def write(path, recs, tail=None):
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
        if tail:
            f.write(tail)


def mutate(kind, recs):
    i = random.randrange(1, len(recs) - 1)
    if kind == "edit_field":
        recs[i]["event"]["data"]["tool"] = "Bash"; recs[i]["event"]["data"]["input"] = {"command": "echo forged"}
    elif kind == "delete_record":
        del recs[i]
    elif kind == "swap_adjacent":
        recs[i], recs[i + 1] = recs[i + 1], recs[i]
    elif kind == "insert_forged":
        f = json.loads(json.dumps(recs[i])); f["event"]["data"]["input"] = {"command": "echo forged"}
        f["hash"] = event_hash(f["event"]); recs.insert(i + 1, f)
    elif kind == "truncate_tail":
        del recs[-random.randint(1, 20):]
    elif kind == "rechain_no_key":
        recs[i]["event"]["data"]["input"] = {"command": "rm -rf build"}
        rechain(recs, key=False)
    elif kind == "rechain_with_key":
        recs[i]["event"]["data"]["input"] = {"command": "rm -rf build"}
        rechain(recs, key=True)
    return recs


def witness_detects(path_recs, cps):
    by_seq = {}
    for r in path_recs:
        if isinstance(r, dict) and not r.get("elided"):
            by_seq[(r.get("event") or {}).get("seq")] = r.get("hash")
    return any(by_seq.get(cp["head_seq"]) != cp["head_hash"] for cp in cps)


def detect(d, recs, cps, tail=None):
    path = os.path.join(d, "ledger.jsonl")
    write(path, recs, tail)
    _n, problems, _head = verify_ledger(path)
    ledger_only = bool(problems)
    return ledger_only, ledger_only or witness_detects(recs, cps)


def main():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "signer.pub"), "wb") as f:
        f.write(PUBLIC)
    kinds = ["edit_field", "delete_record", "swap_adjacent", "insert_forged", "truncate_tail",
             "rechain_no_key", "rechain_with_key", "torn_write"]
    results = {}
    for kind in kinds:
        a = b = 0
        for _ in range(TRIALS):
            recs = build_records()
            cps = checkpoints(recs, 10)
            if kind == "torn_write":
                x, y = detect(d, recs, cps, tail='{"v": 1, "event": {"seq": %d, ' % len(recs))
            else:
                x, y = detect(d, mutate(kind, json.loads(json.dumps(recs))), cps)
            a += x; b += y
        results[kind] = {"ledger_only": a / TRIALS, "ledger_plus_witness": b / TRIALS, "trials": TRIALS}
        print(f"{kind:18s} ledger-only {a / TRIALS:.2f}   +witness {b / TRIALS:.2f}", flush=True)

    interval = {}
    for k in [1, 5, 10, 25, 50, 100, N]:
        hits = 0
        for _ in range(TRIALS):
            recs = build_records()
            cps = checkpoints(recs, k)
            r2 = json.loads(json.dumps(recs))
            i = random.randrange(0, N)
            r2[i]["event"]["data"]["input"] = {"command": "tampered"}
            rechain(r2, key=True)
            hits += detect(d, r2, cps)[1]
        interval[k] = hits / TRIALS
        print(f"witness every {k:3d} records -> key-holder rewrite detected {interval[k]:.2f}", flush=True)
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", "e1_integrity.json"), "w") as f:
        json.dump({"records_per_ledger": N, "mutations": results, "witness_interval_vs_detection": interval}, f, indent=2)


if __name__ == "__main__":
    main()
