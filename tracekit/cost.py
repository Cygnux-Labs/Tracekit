"""Token usage and cost per run or per model, from the ledger.

    tracekit cost                          # tokens per run (no prices needed)
    tracekit cost --prices prices.json     # adds cost; models without a price show "-" instead of a guess
    tracekit cost --by model --run R --format json

See tracekit/usage.py for the price-table format. Tracekit ships no prices."""
import argparse
import csv
import io
import json
import os
import sys

from .usage import Prices


def render(cols, rows, fmt="table", truncated=False):
    if fmt == "json":
        return json.dumps([dict(zip(cols, r)) for r in rows], indent=2, ensure_ascii=False, default=str)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        w.writerows(rows)
        return buf.getvalue()
    cells = [[("" if v is None else str(v)).replace("\n", " ")[:80] for v in r] for r in rows]
    widths = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
    line = "  ".join(c.ljust(w) for c, w in zip(cols, widths))
    out = [line, "  ".join("-" * w for w in widths)] + ["  ".join(v.ljust(w) for v, w in zip(r, widths)) for r in cells]
    out.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''}{', truncated' if truncated else ''})")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit cost")
    ap.add_argument("--home")
    ap.add_argument("--run")
    ap.add_argument("--by", choices=("run", "model"), default="run")
    ap.add_argument("--prices", help="JSON price table (see tracekit/usage.py)")
    ap.add_argument("--format", choices=("table", "json", "csv"), default="table")
    a = ap.parse_args(argv)
    from . import client
    home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
    try:
        prices = Prices.load(a.prices) if a.prices else None
    except (OSError, ValueError) as e:
        print(f"tracekit cost: {e}", file=sys.stderr)
        return 2
    from .ledger import read_records
    rows = []
    for _, r, _ in read_records(os.path.join(home, "ledger", "ledger.jsonl")):
        ev = (r or {}).get("event") or {}
        d = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        u = d.get("usage") if isinstance(d.get("usage"), dict) else {}
        if ev.get("type") != "model.exchange" or d.get("phase") != "response" or u.get("input_tokens") is None:
            continue
        if a.run and ev.get("run_id") != a.run:
            continue
        rows.append((ev.get("run_id"), "?" if d.get("model") is None else str(d["model"]), u["input_tokens"], u.get("output_tokens"),
                     u.get("cache_read_tokens") or 0, u.get("cache_write_tokens") or 0, u.get("reasoning_tokens") or 0))
    groups = {}
    for run, model, i, o, cr, cw, rt in rows:
        key = run if a.by == "run" else model
        g = groups.setdefault(key, {"calls": 0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "reasoning": 0,
                                    "cost": 0.0, "unpriced": 0})
        g["calls"] += 1
        g["input"] += i or 0
        g["output"] += o or 0
        g["cache_read"] += cr
        g["cache_write"] += cw
        g["reasoning"] += rt
        if prices:
            c = prices.cost(model, {"input_tokens": i, "output_tokens": o, "cache_read_tokens": cr, "cache_write_tokens": cw})
            if c is None:
                g["unpriced"] += 1
            else:
                g["cost"] += c
    cols = [a.by, "calls", "input", "output", "cache_read", "cache_write", "reasoning"] + (["cost_" + prices.currency.lower()] if prices else [])
    out = []
    for k, g in sorted(groups.items(), key=lambda x: -(x[1]["input"] + x[1]["output"])):
        row = [k, g["calls"], g["input"], g["output"], g["cache_read"], g["cache_write"], g["reasoning"]]
        if prices:
            row.append("-" if g["unpriced"] == g["calls"] else round(g["cost"], 6) if not g["unpriced"] else f"{g['cost']:.6f} (+{g['unpriced']} unpriced)")
        out.append(row)
    if not out:
        print("tracekit cost: no model exchanges with token usage recorded", file=sys.stderr)
    print(render(cols, out, a.format) if a.format != "json" else json.dumps([dict(zip(cols, r)) for r in out], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
