"""Token usage and cost per run or per model, from the ledger.

    tracekit cost                          # tokens per run (no prices needed)
    tracekit cost --prices prices.json     # adds cost; models without a price show "-" instead of a guess
    tracekit cost --by model --run R --format json

See tracekit/usage.py for the price-table format. Tracekit ships no prices."""
import argparse
import json
import sys

from .query import Index, render
from .usage import Prices


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit cost")
    ap.add_argument("--home")
    ap.add_argument("--index")
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
    idx = Index(home, a.index)
    idx.refresh()
    where = "WHERE input_tokens IS NOT NULL" + (" AND run_id = ?" if a.run else "")
    _, rows, _ = idx.query("SELECT run_id, coalesce(model, '?'), input_tokens, output_tokens, coalesce(cache_read_tokens,0), "
                           "coalesce(cache_write_tokens,0), coalesce(reasoning_tokens,0) FROM model_exchanges " + where,
                           (a.run,) if a.run else ())
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
