#!/usr/bin/env python3
"""E15: no silent drops when the v2 signer is killed (04-design §2.4, §11). POSIX only.

Runs `tracekit signer serve` as its own process, drives it with WORKERS concurrent clients (one run and stream each,
explicit client_seq), and kill -9's the signer at a random point ROUNDS times, restarting it each time. Clients keep
going: a call that fails is not retried by the eval, its client_seq is simply used up. After the last round each
client makes one more call, so a call lost at the end is followed by one that reaches the signer. Then the store is
read back and checked:

  every acknowledged call is in the store, with the run_seq it was acknowledged with
  every call that got no acknowledgement is in the store or inside a signed client_counter_gap of its stream
  (the signer writes one when a stream's client_seq skips); anything else is a silent drop
  `tracekit signer fsck` finds nothing

Both durability modes run. ack-on-fsync: zero acknowledged records lost is a gate. ack-on-write: acknowledged records
lost are reported (kill -9 keeps the page cache, so this is expected to be 0; the power-loss window of one background
sync interval is not exercised here). Zero silent drops is a gate in both.
Writes eval/results/e15_durability.json; exit 1 when a gate fails.
"""
import argparse
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import v2_signer, write_results  # noqa: E402
from tracekit.sdk.client import Client, SignerUnavailable  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import RPCError  # noqa: E402

rng = random.Random(15)


class Worker(threading.Thread):
    def __init__(self, sock, n):
        super().__init__(daemon=True)
        self.client, self.stream, self.seq = Client(sock, timeout=10), f"w{n}", 0
        out = self.client.register_run({"agent": {"name": "e15"}})
        self.run_ = {"run_id": out["run_id"], "run_token": out["run_token"]}
        self.acked, self.unacked, self.errors, self.stop = {}, [], {}, threading.Event()

    def call(self):
        """One decide; True when acknowledged."""
        seq, self.seq = self.seq, self.seq + 1
        try:
            out = self.client.decide({"request_id": uuid.uuid4().hex, **self.run_, "stream": self.stream,
                                      "client_seq": seq, "tool_call_id": f"t{seq}", "tool": "read_file",
                                      "args_source": "raw", "args": '{"path": "src/a.py"}'})
        except (SignerUnavailable, RPCError) as e:
            code = getattr(e, "code", "signer_unavailable")
            self.errors[code] = self.errors.get(code, 0) + 1
            self.unacked.append(seq)
            return False
        self.acked[seq] = out["run_seq"]
        return True

    def run(self):
        while not self.stop.is_set():
            if not self.call():
                time.sleep(0.01)

    def last_call(self, deadline):
        while not self.call():
            if time.monotonic() > deadline:
                raise SystemExit(f"{self.stream}: the signer did not come back")
            time.sleep(0.05)


def check(records, workers):
    """(acknowledged records lost, silent drops, calls found in the store, calls inside a gap) over all workers."""
    by_run = {}
    for r in records:
        by_run.setdefault(r["event"]["run_id"], []).append(r["event"])
    lost = silent = present = gapped = 0
    for w in workers:
        found, covered, missed = {}, set(), None
        for e in sorted(by_run.get(w.run_["run_id"], []), key=lambda e: e["run_seq"]):
            if e.get("stream") != w.stream:
                continue
            if e["type"] == "capture.gap" and e["data"]["kind"] == "client_counter_gap":
                missed = e["data"]["missed_events"]   # the client_seq values just before the next event's
            elif "client_seq" in e:
                found[e["client_seq"]] = e["run_seq"]
                if missed:
                    covered.update(range(e["client_seq"] - missed, e["client_seq"]))
                missed = None
        lost += sum(found.get(seq) != run_seq for seq, run_seq in w.acked.items())
        present += sum(seq in found for seq in w.unacked)
        gapped += sum(seq not in found and seq in covered for seq in w.unacked)
        silent += sum(seq not in found and seq not in covered for seq in w.unacked)
    return lost, silent, present, gapped


def mode(d, durability, rounds, n_workers):
    data = os.path.join(d, durability)
    p, sock = v2_signer(data, durability)
    workers = [Worker(sock, n) for n in range(n_workers)]
    for w in workers:
        w.start()
    try:
        for _ in range(rounds):
            time.sleep(rng.uniform(0.05, 0.5))
            p.kill()
            p.wait()
            p, _ = v2_signer(data, durability)
        time.sleep(0.2)
        for w in workers:
            w.stop.set()
        for w in workers:
            w.join()
            w.last_call(time.monotonic() + 30)
            w.client.close()
    finally:
        p.terminate()
        p.wait(30)
    with open(os.path.join(data, "data", "store", "records.jsonl"), "rb") as f:
        records = [json.loads(line) for line in f.read().splitlines()]
    lost, silent, present, gapped = check(records, workers)
    errors = {}
    for w in workers:
        for k, v in w.errors.items():
            errors[k] = errors.get(k, 0) + v
    return {"rounds": rounds, "clients": n_workers, "records": len(records),
            "acknowledged": sum(len(w.acked) for w in workers), "not_acknowledged": sum(len(w.unacked) for w in workers),
            "not_acknowledged_but_in_store": present, "not_acknowledged_in_a_signed_gap": gapped,
            "acknowledged_lost": lost, "silent_drops": silent, "client_errors": errors,
            "torn_tails_set_aside": sum(r["event"]["type"] == "capture.gap"
                                        and r["event"]["data"]["kind"] == "signer_unavailable" for r in records),
            "fsck_problems": svc.fsck(os.path.join(data, "data"))[:20]}


def main(argv=None):
    if os.name != "posix":
        raise SystemExit("E15 needs POSIX (kill -9)")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rounds", type=int, default=30, help="kill -9 and restarts per durability mode")
    ap.add_argument("--clients", type=int, default=8)
    a = ap.parse_args(argv)
    d = tempfile.mkdtemp(prefix="e15-", dir="/tmp")   # short socket paths
    try:
        out = {"platform": sys.platform, "python": sys.version.split()[0]}
        for durability in ("ack-on-fsync", "ack-on-write"):
            r = out[durability.replace("-", "_")] = mode(d, durability, a.rounds, a.clients)
            print(f"{durability}: {r['acknowledged']} acknowledged, {r['acknowledged_lost']} lost; "
                  f"{r['not_acknowledged']} not acknowledged: {r['not_acknowledged_but_in_store']} in the store, "
                  f"{r['not_acknowledged_in_a_signed_gap']} in a signed gap, {r['silent_drops']} silent drops; "
                  f"fsck {r['fsck_problems'] or 'ok'}", flush=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    fsync, write = out["ack_on_fsync"], out["ack_on_write"]
    out["gates"] = gates = {"ack_on_fsync_zero_acknowledged_lost": fsync["acknowledged_lost"] == 0,
                            "zero_silent_drops": fsync["silent_drops"] == write["silent_drops"] == 0,
                            "fsck_clean": not fsync["fsck_problems"] and not write["fsck_problems"]}
    print("wrote", write_results("e15_durability", out))
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
