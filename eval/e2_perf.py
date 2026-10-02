#!/usr/bin/env python3
"""E2: overhead of the v0.2 capture path (dev-mode signer, same machine).

  (a) latency of one `python -m tracekit.hook` invocation per event type at several ledger sizes,
      against a bare interpreter start (the floor any hook pays);
  (b) signer append throughput and latency in-process, single writer;
  (c) concurrent writers: throughput and whether the chain is still intact;
  (d) offline `verify` time against bundle size.
Writes eval/results/e2_perf.json. Numbers depend on the machine; the file records platform and Python."""
import os
import platform
import statistics as st
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import Stack, summarize, write_results  # noqa: E402
from tracekit import bundle  # noqa: E402
from tracekit.observe import verify_ledger  # noqa: E402

REPS = int(os.environ.get("E2_REPS", 40))
SIZES = [0, 1000, 5000]


def payloads(cwd):
    base = {"session_id": "e2", "cwd": cwd}
    return {
        "PreToolUse": {**base, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t1",
                       "tool_input": {"command": "python3 -m pytest -q"}},
        "PostToolUse": {**base, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1",
                        "tool_input": {"command": "python3 -m pytest -q"},
                        "tool_response": {"stdout": "..\n2 passed in 0.01s\n" * 20, "exit_code": 0}},
    }


def hook_latency():
    out = {"python_startup_ms": []}
    for _ in range(REPS):
        t = time.perf_counter()
        subprocess.run([sys.executable, "-c", "pass"], capture_output=True)
        out["python_startup_ms"].append((time.perf_counter() - t) * 1000)
    out["python_startup_ms"] = summarize(out["python_startup_ms"])
    out["hook_ms"] = {}
    with Stack(checkpoint_every=50) as s:
        grown = 0
        cwd = tempfile.mkdtemp()
        for size in SIZES:
            if size > grown:
                s.fill(size - grown, run_id=f"fill{size}")
                grown = size
            for name, p in payloads(cwd).items():
                p = {**p, "session_id": f"e2-{size}"}
                times = []
                for i in range(REPS):
                    code, ms = s.hook({**p, "tool_use_id": f"t{i}"})
                    assert code == 0, (name, code)
                    times.append(ms)
                out["hook_ms"][f"{name}@{size}"] = summarize(times)
                print(f"  hook {name:11s} ledger~{size:5d}: p50 {st.median(times):6.1f} ms", flush=True)
    return out


def append_throughput(n=1500):
    from tracekit.agent_sdk import Tracer
    lat = []
    with Stack(checkpoint_every=50) as s:
        with Tracer(agent="e2-append", session_id="tp") as t:
            t0 = time.perf_counter()
            for i in range(n // 2):
                a = time.perf_counter()
                with t.tool("Read", {"file_path": f"f{i % 40}.py"}) as c:
                    c.result({"bytes": i})
                lat.append((time.perf_counter() - a) * 1000 / 2)
            dt = time.perf_counter() - t0
        s.stop()
        ok, problems = verify_ledger_file(s.ledger)
    return {"events": n, "events_per_s": round(n / dt, 1), "per_event_ms": summarize(lat), "chain_ok": ok, "problems": problems[:3]}


def verify_ledger_file(path):
    n, problems, _head = verify_ledger(path)
    return (not problems and n > 0), problems


def concurrent(writers=8, per_writer=200):
    from tracekit.agent_sdk import Tracer
    errors = []
    with Stack(checkpoint_every=50) as s:
        def work(w):
            try:
                with Tracer(agent="e2-conc", session_id=f"conc{w}") as t:
                    for i in range(per_writer // 2):
                        with t.tool("Read", {"file_path": f"w{w}/f{i}.py"}) as c:
                            c.result({"bytes": i})
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
        th = [threading.Thread(target=work, args=(w,)) for w in range(writers)]
        t0 = time.perf_counter()
        [x.start() for x in th]
        [x.join() for x in th]
        dt = time.perf_counter() - t0
        s.stop()
        ok, problems = verify_ledger_file(s.ledger)
        from tracekit.ledger import read_records
        evs = [r["event"] for _, r, _ in read_records(s.ledger) if r and not r.get("elided")]
        recorded = len([e for e in evs if e["run_id"].startswith("conc") and e["type"] in ("tool.call", "tool.result")])
        gaps = len([e for e in evs if e["type"] == "capture.gap"])
    total = writers * per_writer
    return {"writers": writers, "events": total, "events_per_s": round(total / dt, 1), "errors": errors[:3],
            "recorded_tool_events": recorded, "capture_gaps": gaps,
            "chain_ok": ok and recorded == total and gaps == 0, "problems": problems[:3]}


def verify_time():
    out = {}
    for size in (500, 2000, 8000):
        with Stack(checkpoint_every=50) as s:
            s.fill(size)
            s.stop()
            tkb = os.path.join(s.dir, "run.tkb")
            bundle.export(s.home, tkb, last=False, since="1970-01-01T00:00:00Z")
            t = time.perf_counter()
            rep, code = bundle.verify(tkb, [s.witness_spec])
            ms = (time.perf_counter() - t) * 1000
            out[str(size)] = {"verify_ms": round(ms, 1), "exit_code": code, "bundle_bytes": os.path.getsize(tkb)}
            print(f"  verify {size:5d} events: {ms:7.1f} ms (exit {code})", flush=True)
    return out


def main():
    print("E2 hook latency", flush=True)
    res = {"platform": platform.platform(), "python": sys.version.split()[0], "reps": REPS}
    res["latency"] = hook_latency()
    print("E2 append throughput", flush=True)
    res["append"] = append_throughput()
    print("  ", res["append"], flush=True)
    print("E2 concurrent writers", flush=True)
    res["concurrent"] = concurrent()
    print("  ", res["concurrent"], flush=True)
    print("E2 verify time", flush=True)
    res["verify"] = verify_time()
    print("wrote", write_results("e2_perf", res))
    bad = [k for k in ("append", "concurrent") if not res[k]["chain_ok"]]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
