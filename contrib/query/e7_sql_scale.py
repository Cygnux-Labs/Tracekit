#!/usr/bin/env python3
"""E7: the SQL index at scale (#8). Synthesises a hash-chained ledger of N events (default 1,000,000) in a temp folder,
builds the index, times a no-op refresh and a set of typical queries, then rebuilds a second index from the same ledger
and checks every query returns identical rows.

Records are hash-chained like the signer's but carry a placeholder signature: the index never checks signatures (it is
not evidence; `tracekit verify` is), so signing a million records would only measure Ed25519.

    python3 contrib/query/e7_sql_scale.py [--events 1000000] [--out contrib/query/e7_sql_scale.json]"""
import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(os.path.dirname(HERE)), HERE]
import tracekit_query as query  # noqa: E402
from tracekit import __version__  # noqa: E402
from tracekit.core import GENESIS, SCHEMA_VERSION, event_hash  # noqa: E402

TOOLS = [("Bash", "command", ["pytest -q", "git status", "ls -la", "npm test", "curl -s https://api.example/x", "sudo rm -rf /tmp/x"]),
         ("Read", "file_path", ["src/app.py", "README.md", ".env", "tests/test_app.py"]),
         ("Edit", "file_path", ["src/app.py", "src/util.py"]),
         ("WebFetch", "url", ["https://docs.example/a", "https://paste.example/upload"])]
MODELS = ["gpt-4o-2026", "claude-x-1", "gemini-x-001"]


def synth(path, n):
    """~n events across runs of ~100 events each: run.start, then (model request, response, tool.call, decision, result)*."""
    seq, prev, run_no, t0 = 0, GENESIS, 0, 1_790_000_000
    with open(path, "w", encoding="utf-8") as f:
        def put(run, etype, data, agent="main", source="hook"):
            nonlocal seq, prev
            ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t0 + seq // 10)) + f".{seq % 1000000:06d}Z"
            ev = {"schema_version": SCHEMA_VERSION, "id": f"{seq:032x}", "seq": seq, "prev_hash": prev, "ts": ts, "run_id": run,
                  "agent_id": agent, "parent_id": None, "source": source, "type": etype, "data": data, "ts_signed": ts}
            h = event_hash(ev)
            f.write(json.dumps({"event": ev, "hash": h, "sig": "synthetic"}, separators=(",", ":")) + "\n")
            prev, seq = h, seq + 1
        while seq < n:
            run = f"run-{run_no:06d}"
            run_no += 1
            put(run, "run.start", {"agent": {"name": ["claude-code", "codex", "research-bot"][run_no % 3]}, "model": MODELS[run_no % 3],
                                   "content_capture": "hashed"})
            for i in range(19):
                if seq >= n:
                    break
                k = (run_no * 31 + i) % 97
                name, field, values = TOOLS[k % len(TOOLS)]
                value = values[k % len(values)]
                tid = f"toolu_{run_no:06d}_{i:02d}"
                model = MODELS[(run_no + i) % 3]
                put(run, "model.exchange", {"exchange_id": f"x{seq}", "phase": "request", "model": model}, source="sdk")
                put(run, "model.exchange", {"exchange_id": f"x{seq}", "phase": "response", "model": model, "status": 200,
                                            "stop_reason": "tool_use", "duration_ms": 300 + k, "tool_uses": [{"id": tid, "name": name}],
                                            "usage": {"input_tokens": 100 + k, "output_tokens": 20 + k % 7, "cache_read_tokens": 50}},
                    source="sdk")
                put(run, "tool.call", {"tool_use_id": tid, "name": name, "input": {field: {"value": value}}})
                deny = "sudo" in value or "paste.example" in value
                put(run, "policy.decision", {"tool_use_id": tid, "decision": "deny" if deny else "allow",
                                             "rule_ids": ["TK-D001"] if deny else [], "reasons": [], "policy_hash": "sha256:" + "0" * 64,
                                             "policy_version": "default"})
                if not deny:
                    put(run, "tool.result", {"tool_use_id": tid, "ok": k % 11 != 0, "output": {"hash": "sha256:" + "1" * 64, "size": k},
                                             "duration_ms": 40 + k})
            put(run, "run.end", {"reason": "done"})
    return seq


QUERIES = {
    "events by type": "SELECT type, count(*) FROM events GROUP BY type ORDER BY 1",
    "tool calls by name, with denies (joins every call to its decision and result)":
        "SELECT name, count(*), sum(decision='deny'), sum(ok=0) FROM tool_calls GROUP BY name ORDER BY 1",
    "one run's tool calls": "SELECT seq, name, command, file_path, decision, ok FROM tool_calls WHERE run_id='run-004242' ORDER BY seq",
    "denied commands, most recent 20": "SELECT run_id, seq, command FROM tool_calls WHERE decision='deny' ORDER BY seq DESC LIMIT 20",
    "tokens by model": "SELECT model, count(*), sum(input_tokens), sum(output_tokens) FROM model_exchanges GROUP BY model ORDER BY 1",
    "runs rollup, top 10 by tokens": "SELECT run_id, agent, events, tool_calls, tokens_in, denied FROM runs ORDER BY tokens_in DESC, run_id LIMIT 10",
    "one run's rollup": "SELECT * FROM runs WHERE run_id='run-004242'",
    "substring search over all event data (full scan)": "SELECT count(*) FROM events WHERE data LIKE '%paste.example%'",
}


def timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=1_000_000)
    ap.add_argument("--out", default=os.path.join(HERE, "e7_sql_scale.json"))
    a = ap.parse_args(argv)
    d = tempfile.mkdtemp(prefix="tk-e7-")
    try:
        home = os.path.join(d, "home")
        os.makedirs(os.path.join(home, "ledger"))
        ledger = os.path.join(home, "ledger", "ledger.jsonl")
        n, t_synth = timed(lambda: synth(ledger, a.events))
        size_mb = os.path.getsize(ledger) / 1e6
        print(f"ledger: {n:,} events, {size_mb:.0f} MB (synthesised in {t_synth:.0f} s)")
        idx = query.Index(home, os.path.join(d, "a.sqlite"))
        added, t_build = timed(idx.refresh)
        assert added == n, (added, n)
        _, t_noop = timed(idx.refresh)
        print(f"index build {t_build:.1f} s; refresh with nothing new {t_noop:.2f} s")
        results, rows_a = {}, {}
        for name, sql in QUERIES.items():
            idx.query(sql)  # warm the page cache once, like a second query on a laptop
            (cols, rows, _trunc), t = timed(lambda: idx.query(sql))
            results[name] = {"seconds": round(t, 3), "rows": len(rows)}
            rows_a[name] = rows
            print(f"  {t * 1000:8.0f} ms  {name}  ({len(rows)} rows)")
        rebuilt = query.Index(home, os.path.join(d, "b.sqlite"))
        rebuilt.refresh()
        identical = all(rebuilt.query(sql)[1] == rows_a[name] for name, sql in QUERIES.items())
        print("rebuilt-from-ledger index returns identical rows:", identical)
        out = {"experiment": "E7 SQL index at scale", "tracekit_version": __version__, "events": n, "ledger_mb": round(size_mb),
               "python": platform.python_version(), "sqlite": __import__("sqlite3").sqlite_version, "cpus": os.cpu_count(),
               "machine": platform.machine(), "index_build_s": round(t_build, 1), "noop_refresh_s": round(t_noop, 2),
               "queries": results, "rebuild_identical": identical,
               "under_1s": sorted(k for k, v in results.items() if v["seconds"] < 1.0),
               "over_1s": sorted(k for k, v in results.items() if v["seconds"] >= 1.0)}
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        with open(a.out, "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
        return 0 if identical else 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
