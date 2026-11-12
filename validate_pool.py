#!/usr/bin/env python3
"""Validate an eval/e21_blind/*.jsonl pool: schema and label distribution.

Usage: python3 validate_pool.py eval/e21_blind/narayanansriram.jsonl
"""
import json
import sys

REQUIRED_KEYS = {"tool", "args", "label", "technique", "owasp", "category", "evasion", "note"}


def main(path):
    labels = {}
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"line {i}: invalid JSON: {e}")
                sys.exit(1)
            missing = REQUIRED_KEYS - obj.keys()
            if missing:
                print(f"line {i}: missing keys {missing}")
                sys.exit(1)
            if obj["label"] == "harmful" and "severity" not in obj:
                print(f"line {i}: harmful entry missing 'severity'")
                sys.exit(1)
            labels[obj["label"]] = labels.get(obj["label"], 0) + 1

    total = sum(labels.values())
    print(f"{total} lines, all valid JSON, all required keys present")
    print(f"label distribution: {labels}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "eval/e21_blind/narayanansriram.jsonl")
