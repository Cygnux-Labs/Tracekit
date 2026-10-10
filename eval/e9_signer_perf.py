#!/usr/bin/env python3
"""E9: v2 signer latency and throughput through the real Unix-socket transport (04-design §11).

Runs `tracekit signer serve` as its own process and drives it with the Python client (tracekit.sdk.client), so every
number includes the client, the socket and the signer's writer:

  latency      one client, decide + complete per tool call, one after the other, over CALLS calls at ack-on-write:
               the time a tool call waits for the signer (gate: p99 <= 5 ms)
  throughput   WORKERS client processes calling decide + complete as fast as they can for SECONDS at ack-on-write:
               events (records) per second (gate: >= 1,000)
  fsync        the latency measurement at ack-on-fsync over FSYNC_CALLS calls (reported, no gate)

The gates hold on Linux only; elsewhere, and with --quick (a short local run), the numbers are informational.
Writes eval/results/e9_signer_perf.json; exit 1 when a gate fails.
"""
import argparse
import concurrent.futures
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import pct, v2_signer, write_results  # noqa: E402
from tracekit.sdk.client import Client  # noqa: E402

ARGS = '{"path": "src/a.py"}'
WARMUP = 200


def tool_calls(sock, n):
    """Milliseconds per decide + complete, for n calls after a warm-up."""
    client, lat = Client(sock), []
    run = client.run("e9")
    for i in range(WARMUP + n):
        t = time.perf_counter()
        run.decide(f"t{i}", "read_file", ARGS)
        run.complete(f"t{i}")
        lat.append((time.perf_counter() - t) * 1000)
    run.close()
    client.close()
    return lat[WARMUP:]


def worker(sock, start, seconds):
    """Events written by one client process calling decide + complete in a loop from `start` (time.time()) on."""
    client = Client(sock)
    run, i = client.run("e9-load"), 0
    time.sleep(max(0, start - time.time()))
    while time.time() < start + seconds:
        run.decide(f"t{i}", "read_file", ARGS)
        run.complete(f"t{i}")
        i += 1
    run.close()
    client.close()
    return 2 * i


def summary(lat):
    return {"calls": len(lat), "p50_ms": round(pct(lat, 50), 3), "p99_ms": round(pct(lat, 99), 3),
            "max_ms": round(max(lat), 3)}


def measure(d, durability, fn):
    p, sock = v2_signer(os.path.join(d, durability), durability)
    try:
        return fn(sock)
    finally:
        p.terminate()
        p.wait(30)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="1,000 calls, 5 s of load, 200 ack-on-fsync calls; no gates")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    calls, seconds, fsync_calls = (1000, 5, 200) if a.quick else (10_000, 60, 2000)
    gated = sys.platform.startswith("linux") and not a.quick
    d = tempfile.mkdtemp(prefix="e9-", dir="/tmp" if os.path.isdir("/tmp") else None)   # short socket paths
    try:
        latency = summary(measure(d, "ack-on-write", lambda s: tool_calls(s, calls)))
        print(f"ack-on-write: decide + complete p50 {latency['p50_ms']} ms, p99 {latency['p99_ms']} ms "
              f"over {calls} calls", flush=True)

        def load(sock):
            start = time.time() + 2   # every worker has connected and registered its run by then
            with concurrent.futures.ProcessPoolExecutor(a.workers) as pool:
                return sum(pool.map(worker, [sock] * a.workers, [start] * a.workers, [seconds] * a.workers))
        events = measure(d, "ack-on-write", load)
        rate = round(events / seconds)
        print(f"ack-on-write: {rate} events/s over {seconds} s ({a.workers} client processes)", flush=True)
        fsync = summary(measure(d, "ack-on-fsync", lambda s: tool_calls(s, fsync_calls)))
        print(f"ack-on-fsync: decide + complete p50 {fsync['p50_ms']} ms, p99 {fsync['p99_ms']} ms "
              f"over {fsync_calls} calls", flush=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    gates = {"p99_ms_at_ack_on_write_le_5": latency["p99_ms"] <= 5.0, "events_per_s_ge_1000": rate >= 1000}
    out = {"platform": sys.platform, "python": sys.version.split()[0], "cpus": os.cpu_count(), "quick": a.quick,
           "gated": gated, "ack_on_write": latency, "throughput": {"events_per_s": rate, "seconds": seconds,
                                                                    "workers": a.workers, "events": events},
           "ack_on_fsync": fsync, "gates": gates}
    print("wrote", write_results("e9_signer_perf", out))
    if not gated:
        print("informational: the gates apply to a full run on Linux")
    return 1 if gated and not all(gates.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
