#!/usr/bin/env python3
"""E2: overhead. (a) end-to-end latency of one hook invocation per event type, at several
ledger sizes, against a bare interpreter start; (b) in-process append and verify throughput;
(c) concurrent writers: throughput and chain correctness."""
import json
import os
import shutil
import statistics as st
import subprocess
import sys
import tempfile
import time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)
import common  # noqa: E402
import verify  # noqa: E402

REAL = [{k: v for k, v in r.items() if k not in ("seq", "ts", "prev", "hash")}
        for r in common.read_ledger(os.path.join(KIT, "demo/sample-output/multi-agent-ledger.jsonl"))]
REPS = 60


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def timed(cmd, inp, env):
    t = time.perf_counter()
    subprocess.run(cmd, input=inp, capture_output=True, text=True, env=env)
    return (time.perf_counter() - t) * 1000


def hook_latency():
    out = {}
    base_env = dict(os.environ)
    out["python_startup_ms"] = [timed([sys.executable, "-c", "pass"], "", base_env) for _ in range(REPS)]
    payloads = {
        "PreToolUse": {"hook_event_name": "PreToolUse", "session_id": "b", "cwd": "/p", "tool_name": "Bash",
                       "tool_input": {"command": "python3 -m pytest -q"}, "tool_use_id": "t"},
        "PostToolUse": {"hook_event_name": "PostToolUse", "session_id": "b", "cwd": "/p", "tool_name": "Bash",
                        "tool_input": {"command": "python3 -m pytest -q"}, "tool_use_id": "t",
                        "tool_response": {"stdout": "..\n2 passed in 0.01s" * 20}},
    }
    for size in [0, 1000, 10000, 100000]:
        home = tempfile.mkdtemp()
        shutil.copy(os.path.join(KIT, "policy.json"), home)
        env = dict(os.environ, TRACEKIT_HOME=home, TRACEKIT_POLICY=os.path.join(home, "policy.json"))
        if size:
            os.environ["TRACEKIT_HOME"] = home
            batch = [REAL[i % len(REAL)] for i in range(size)]
            common.append(batch, path=os.path.join(home, "ledger.jsonl"))
        for name, p in payloads.items():
            out[f"{name}@{size}"] = [timed([sys.executable, os.path.join(KIT, "hook.py")], json.dumps(p), env) for _ in range(REPS)]
        print("latency size", size, {k: round(st.median(v), 1) for k, v in out.items() if k.endswith(f"@{size}")}, flush=True)
        shutil.rmtree(home)
    return out


def throughput():
    home = tempfile.mkdtemp(); path = os.path.join(home, "l.jsonl")
    n = 2000
    t = time.perf_counter()
    for i in range(n):
        common.append([REAL[i % len(REAL)]], path=path)  # one fsync per record: worst case
    append_rps = n / (time.perf_counter() - t)
    size = os.path.getsize(path)
    t = time.perf_counter(); cnt, problems, _ = verify.verify(path); verify_rps = cnt / (time.perf_counter() - t)
    shutil.rmtree(home)
    return {"append_records_per_s_fsync_each": append_rps, "verify_records_per_s": verify_rps,
            "mean_record_bytes": size / n, "records": n}


def concurrency():
    res = {}
    code = ("import sys,os,json;sys.path.insert(0,%r);import common\n"
            "recs=[json.loads(l) for l in open(%r)]\n"
            "for i in range(200): common.append([{k:v for k,v in recs[i%%len(recs)].items() if k not in ('seq','ts','prev','hash')}])")
    code = code % (KIT, os.path.join(KIT, "demo/sample-output/multi-agent-ledger.jsonl"))
    for w in [1, 2, 4, 8, 16]:
        home = tempfile.mkdtemp()
        env = dict(os.environ, TRACEKIT_HOME=home)
        t = time.perf_counter()
        ps = [subprocess.Popen([sys.executable, "-c", code], env=env) for _ in range(w)]
        [p.wait() for p in ps]
        el = time.perf_counter() - t
        n, problems, _ = verify.verify(os.path.join(home, "ledger.jsonl"))
        res[w] = {"records": n, "expected": 200 * w, "chain_ok": not problems, "records_per_s": n / el}
        print("writers", w, res[w], flush=True)
        shutil.rmtree(home)
    return res


if __name__ == "__main__":
    lat = hook_latency()
    summary = {k: {"p50": st.median(v), "p95": pct(v, 95), "n": len(v)} for k, v in lat.items()}
    out = {"hook_latency_ms": summary, "raw_latency_ms": lat, "throughput": throughput(), "concurrency": concurrency(),
           "python": sys.version.split()[0]}
    print(json.dumps(out["throughput"], indent=1))
    json.dump(out, open(os.path.join(KIT, "eval/results/e2_perf.json"), "w"), indent=2)
