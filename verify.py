#!/usr/bin/env python3
"""Verify the ledger has not been edited, reordered, or had records removed.

  python3 verify.py            check the whole chain
  python3 verify.py anchor     record the current head hash in anchors.log
                               (copy that line somewhere the agent can't reach:
                               a git commit, a message to yourself, a notary)
  python3 verify.py --ledger PATH

A hash chain proves internal consistency. Anyone who can rewrite the WHOLE file
could rebuild a consistent chain, so anchors held outside the machine are what
make tampering detectable against a determined attacker.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402


def verify(path):
    problems, prev, n = [], common.GENESIS, 0
    if not os.path.exists(path):
        return 0, ["no ledger found at " + path], None
    import json
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                problems.append(f"line {lineno}: not valid JSON")
                continue
            if rec.get("seq") != n:
                problems.append(f"line {lineno}: seq {rec.get('seq')} expected {n} (record removed or reordered)")
            if rec.get("prev") != prev:
                problems.append(f"line {lineno}: prev-hash mismatch (chain broken before this record)")
            if common.record_hash(rec) != rec.get("hash"):
                problems.append(f"line {lineno}: content hash mismatch (record edited)")
            prev, n = rec.get("hash"), n + 1
    return n, problems, prev


def check_anchors(path, ledger):
    """Every anchored (seq, hash) must still be present in the ledger."""
    if not os.path.exists(path):
        return []
    by_seq = {r["seq"]: r["hash"] for r in common.read_ledger(ledger)}
    out = []
    for line in open(path, encoding="utf-8"):
        parts = line.split()
        if len(parts) >= 3:
            seq, h = int(parts[1]), parts[2]
            if by_seq.get(seq) != h:
                out.append(f"anchor at seq {seq} no longer matches the ledger")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="check", choices=["check", "anchor"])
    ap.add_argument("--ledger", default=common.LEDGER)
    a = ap.parse_args()
    n, problems, head = verify(a.ledger)
    if a.cmd == "anchor":
        if problems:
            print("Refusing to anchor a broken chain:", *problems, sep="\n  ")
            sys.exit(1)
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {n - 1} {head}"
        with open(os.path.join(os.path.dirname(a.ledger), "anchors.log"), "a") as f:
            f.write(line + "\n")
        print("Anchored:", line)
        return
    problems += check_anchors(os.path.join(os.path.dirname(a.ledger), "anchors.log"), a.ledger)
    if problems:
        print(f"TAMPERING DETECTED in {n} records:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print(f"OK: {n} records, chain intact. head={head}")


if __name__ == "__main__":
    main()
