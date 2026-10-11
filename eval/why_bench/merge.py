"""Merge per-scenario result files from parallel runs into one report.

    python -m eval.why_bench.merge OUT_STEM part1.json part2.json ...
"""
import json
import sys

from .run import markdown
from .scenarios import SCENARIOS


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    stem, parts = argv[0], argv[1:]
    res = None
    for p in parts:
        with open(p) as f:
            r = json.load(f)
        if res is None:
            res = {k: v for k, v in r.items() if k != "scenarios"}
            res["scenarios"] = []
        res["scenarios"] += r["scenarios"]
    order = list(SCENARIOS)
    res["scenarios"].sort(key=lambda s: order.index(s["scenario"]) if s["scenario"] in order else 99)
    with open(stem + ".json", "w") as f:
        json.dump(res, f, indent=2)
    md = markdown(res)
    with open(stem + ".md", "w") as f:
        f.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
