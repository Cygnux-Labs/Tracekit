"""The v2 signer service (tracekit/signer/service.py, pipeline.py): the RPC conformance suite in process and over a real
Unix socket, refusals that leave no state, disk errors, restart with a torn tail, rollback detection, quotas, the CLI,
and (with -m perf, Linux) the S1 performance gates."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

import pytest

from test_rpc_contract import SignerContract
from tracekit import locking, schema
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.pipeline import SIGNER_RUN
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import StorageCorrupt, StorageUnavailable
from tracekit.storage.file import FileStorage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
OTHER = CallerIdentity("uid", "999999", True)
# what the signer measures for a uid caller (ME, OTHER): Windows has no uid of its own to compare with
SAME_USER, SEPARATE_USER = ("same-user", "separate-user") if hasattr(os, "getuid") else ("unknown", "unknown")
PAY_ASKS = Engine({"ask": [{"id": "TEST-PAY", "tool": "pay", "pattern": "^"}]})


def tmpdir(case):
    d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: macOS caps socket paths at 104 bytes
    case.addCleanup(shutil.rmtree, d, True)
    return d


def records(data_dir):
    with open(os.path.join(data_dir, "store", "records.jsonl"), "rb") as f:
        return [json.loads(line) for line in f.read().splitlines()]


class TestServiceContract(SignerContract, unittest.TestCase):
    def make_signer(self):
        self.dir = tmpdir(self)
        s = svc.SignerService(self.dir, policy=PAY_ASKS, multi_tenant_apps=[f"uid:{ME.subject}"])
        self.addCleanup(s.close)
        return s

    def test_records_are_signed_schema_valid_and_fsck_clean(self):
        self.register(tenant="acme")
        self.complete(*self.decide(), result={"n": 1})
        self.call("state_write", self.ev(key="k", value_digest="sha256:" + "0" * 64))
        self.call("model_event", self.ev(provider="openai", model="gpt", phase="request",
                                         content_digest="sha256:" + "1" * 64, usage={"input_tokens": 1, "output_tokens": 2}))
        self.call("model_event", self.ev(provider="openai", model="gpt", phase="response", exchange_id="ex-1",
                                         tool_uses=self.TOOL_USES, tool_results_sent=["call_prev"], error="x" * 1024,
                                         usage={"input_tokens": 1, "output_tokens": 2, "cache_read_tokens": 3}))
        self.seq += 3
        self.decide(tcid="tc-2")
        self.call("close_run", self.run_req())
        self.signer.close()
        rs = records(self.dir)
        self.assertEqual([r["event"]["seq"] for r in rs], list(range(len(rs))))
        self.assertEqual(rs[0]["event"]["type"], "signer.epoch")
        for r in rs:
            self.assertEqual(schema.validate(r["event"]), [], r["event"])
        self.assertEqual(svc.fsck(self.dir), [])
        reg = [r["event"] for r in rs if r["event"]["type"] == "run.registered"][0]
        self.assertEqual(reg["data"]["signer_isolation"], SAME_USER)
        self.assertFalse(reg["tenant_attested"])
        resp = [r["event"]["data"] for r in rs if r["event"]["type"] == "model.exchange"][-1]
        self.assertEqual(resp["usage"]["cache_read_tokens"], 3)
        self.assertNotIn("a" * 64, json.dumps(resp), "args digests are published only as commitments")
        self.assertEqual([("args_commitment" in t, t.get("args_unparseable")) for t in resp["tool_uses"]],
                         [(True, None), (False, True), (True, None), (False, None)])

    def test_isolation_is_measured_from_the_caller(self):
        self.signer.call(OTHER, "register_run", {"request_id": "r", "agent": {"name": "a"}})
        self.signer.close()
        reg = [r["event"] for r in records(self.dir) if r["event"]["type"] == "run.registered"][0]
        self.assertEqual(reg["data"]["signer_isolation"], SEPARATE_USER)

    def test_request_id_and_tokens_are_scoped_to_the_identity(self):
        reg = {"request_id": "reg-1", "agent": {"name": "a"}}
        mine = self.call("register_run", dict(reg))
        theirs = self.signer.call(OTHER, "register_run", dict(reg))
        self.assertNotEqual(mine["run_id"], theirs["run_id"])
        with self.assertRaises(RPCError) as cm:
            self.signer.call(OTHER, "read", {"run_id": mine["run_id"], "run_token": mine["run_token"]})
        self.assertEqual(cm.exception.code, "run_token_invalid")

    def test_demo_deny_rule_by_default(self):
        s = svc.SignerService(tmpdir(self))
        self.addCleanup(s.close)
        self.signer = s
        self.register()
        self.assertIn("TK-DEMO-DENY", self.decide(tool="tracekit_demo_denied")[1]["rule_ids"])
        self.assertEqual(self.decide(tool="pay", tcid="tc-2")[1]["decision"], "allow")


class Disk(FileStorage):
    """File storage whose next appends fail the way a full disk does."""
    fail = 0

    def append_batch(self, records):
        if Disk.fail:
            Disk.fail -= 1
            raise StorageUnavailable("No space left on device")
        super().append_batch(records)


class TestService(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        Disk.fail = 0

    def open(self, **kw):
        s = svc.SignerService(self.dir, policy=PAY_ASKS, open_storage=lambda: Disk(os.path.join(self.dir, "store")), **kw)
        self.addCleanup(s.close)
        return s

    def state(self, s):
        return s.log.storage.tail_state(), json.dumps(sorted(s.log.runs.items()), sort_keys=True)

    def register(self, s, identity=ME, **kw):
        return s.call(identity, "register_run", {"request_id": f"reg-{time.monotonic_ns()}", "agent": {"name": "a"}, **kw})

    def ev(self, run, seq, rid=None, **kw):
        return {"request_id": rid or uuid.uuid4().hex, "run_id": run["run_id"], "run_token": run["run_token"],
                "stream": "s1", "client_seq": seq, **kw}

    def refused(self, code, s, method, req, identity=ME):
        with self.assertRaises(RPCError) as cm:
            s.call(identity, method, req)
        self.assertEqual(cm.exception.code, code, cm.exception)

    def test_refusals_leave_no_state(self):
        s = self.open()
        run = self.register(s)
        s.decide(self.ev(run, 0, rid="d0", tool_call_id="tc", tool="t", args_source="parsed", args={}))
        before = self.state(s)
        self.refused("client_seq_reused", s, "decide", self.ev(run, 0, tool_call_id="x", tool="t", args_source="parsed", args={}))
        self.refused("conflict", s, "decide", self.ev(run, 5, rid="d0", tool_call_id="tc", tool="t", args_source="parsed", args={}))
        self.refused("unknown_decision", s, "complete", self.ev(run, 7, tool_call_id="never", decision_id="dec-x",
                                                                args_digest="sha256:" + "0" * 64, status="ok"))
        self.refused("unknown_tool_call", s, "approval_request", {"request_id": "a", "run_id": run["run_id"],
                                                                  "run_token": run["run_token"], "tool_call_id": "tc"})
        self.assertEqual(self.state(s), before)
        out = s.decide(self.ev(run, 1, tool_call_id="tc2", tool="t", args_source="parsed", args={}))
        self.assertEqual(out["run_seq"], 2)   # no gap from the refused client_seq values 5, 7

    def test_a_refused_item_inside_a_batch_leaves_the_rest(self):
        s = self.open()
        run = self.register(s)
        errors, n = [], 40

        def go(i):
            try:   # every other call reuses client_seq 0 of its own stream
                s.decide(self.ev(run, 0, tool_call_id=f"t{i}", tool="t", args_source="parsed", args={}, stream=f"s{i // 2}"))
            except RPCError as e:
                errors.append(e.code)
        threads = [threading.Thread(target=go, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, ["client_seq_reused"] * (n // 2))
        events = s.read({"run_id": run["run_id"], "run_token": run["run_token"], "limit": 1000})["events"]
        self.assertEqual([e["run_seq"] for e in events], list(range(1 + n // 2)))

    def test_disk_error_is_unavailable_then_a_signed_gap(self):
        s = self.open()
        run = self.register(s)
        before = self.state(s)
        Disk.fail = 1
        self.refused("unavailable", s, "decide", self.ev(run, 0, tool_call_id="t", tool="t", args_source="parsed", args={}))
        self.assertEqual(self.state(s)[1], before[1])
        time.sleep(1.05)   # pipeline.RECOVER_S
        out = s.decide(self.ev(run, 0, tool_call_id="t", tool="t", args_source="parsed", args={}))
        self.assertEqual(out["run_seq"], 1)
        s.close()
        gaps = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([g["kind"] for g in gaps], ["signer_unavailable"])
        self.assertIn("No space left", gaps[0]["reason"])

    def test_restart_keeps_counters_and_sets_a_torn_tail_aside(self):
        s = self.open()
        run = self.register(s)
        d = s.decide(self.ev(run, 0, tool_call_id="t", tool="t", args_source="parsed", args={}))
        s.close()
        with open(os.path.join(self.dir, "store", "records.jsonl"), "ab") as f:
            f.write(b'{"v":2,"event":{"seq":')
        s = self.open()
        self.refused("client_seq_reused", s, "decide", self.ev(run, 0, tool_call_id="t2", tool="t", args_source="parsed", args={}))
        self.assertEqual(s.complete(self.ev(run, 1, tool_call_id="t", decision_id=d["decision_id"], status="ok",
                                            args_digest=event_hash({"tool": "t", "args": {}})))["run_seq"], 2)
        s.close()
        gaps = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("torn last line", gaps[0]["reason"])
        self.assertEqual(svc.fsck(self.dir), [])

    def test_a_damaged_tail_signature_stops_startup(self):
        s = self.open()
        self.register(s)
        s.close()
        path = os.path.join(self.dir, "store", "records.jsonl")
        lines = open(path, "rb").read().splitlines()
        r = json.loads(lines[-1])
        r["sig"] = r["sig"][:-4] + ("AAA=" if not r["sig"].endswith("AAA=") else "BBB=")
        lines[-1] = json.dumps(r, separators=(",", ":")).encode()
        open(path, "wb").write(b"\n".join(lines) + b"\n")
        with self.assertRaises(StorageCorrupt):
            self.open()
        self.assertTrue(any("bad signature" in p for p in svc.fsck(self.dir)))

    def test_second_signer_is_refused_by_the_lock(self):
        self.open()
        with self.assertRaises(BlockingIOError):
            svc.SignerService(self.dir)

    def test_a_windows_lock_conflict_is_the_same_refusal(self):
        msvcrt = mock.Mock(LK_NBLCK=2)
        msvcrt.locking.side_effect = PermissionError(13, "Permission denied")
        with mock.patch.object(locking, "fcntl", None), mock.patch.object(locking, "msvcrt", msvcrt), \
                open(os.path.join(self.dir, "lock"), "a") as f:
            with self.assertRaises(BlockingIOError):
                locking.lock_file(f, blocking=False)

    def test_rollback_against_a_witness(self):
        s = self.open()
        run = self.register(s)
        size, root = s.log.storage.tail_state()["tree_size"] + 5, b"\x01" * 32
        s.close()

        class Witness:
            def latest(self):
                return size, root
        s = self.open(witnesses=[Witness()])
        self.refused("unavailable", s, "close_run", {"request_id": "c", "run_id": run["run_id"], "run_token": run["run_token"]})
        s.close()
        tampers = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "trace.tamper"]
        self.assertEqual([(t["kind"], t["before"]["length"]) for t in tampers], [("rollback", size)])
        s = self.open(witnesses=[Witness()], acknowledge_rollback=True)
        s.close_run({"request_id": "c", "run_id": run["run_id"], "run_token": run["run_token"]})

    def test_unreachable_witness_starts_degraded(self):
        class Down:
            def latest(self):
                raise OSError("connection refused")
        s = self.open(witnesses=[Down()])
        self.register(s)
        s.close()
        gaps = [r["event"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([g["data"]["kind"] for g in gaps], ["degraded_unanchored"])
        self.assertEqual((gaps[0]["tenant"], gaps[0]["run_id"]), SIGNER_RUN)

    def test_quotas_and_refusal_summaries(self):
        s = self.open(limits=Limits(open_runs=1, events_per_s=0.001, burst=1, streams_per_run=1))
        run = self.register(s)
        self.refused("quota_exceeded", s, "register_run", {"request_id": "r2", "agent": {"name": "a"}})
        s.decide(self.ev(run, 0, tool_call_id="t", tool="t", args_source="parsed", args={}))
        self.refused("quota_exceeded", s, "decide", self.ev(run, 1, tool_call_id="t2", tool="t", args_source="parsed", args={}))
        s.quotas.limits = Limits(open_runs=1, streams_per_run=1)
        self.refused("quota_exceeded", s, "decide", self.ev(run, 0, tool_call_id="t3", tool="t", args_source="parsed",
                                                            args={}, stream="s2"))
        self.refused("invalid_request", s, "model_event", self.ev(run, 1, provider="p", model="m", phase="request",
                                                                  type="capture.gap"))
        s.close()
        sums = {r["event"]["data"]["code"]: r["event"]["data"] for r in records(self.dir)
                if r["event"]["type"] == "refusal.summary"}
        self.assertEqual(sums["quota_exceeded"]["count"], 3)
        self.assertEqual(sums["invalid_request"]["count"], 1)
        self.assertEqual(sums["quota_exceeded"]["identity"], f"uid:{ME.subject}")


class SocketSigner:
    """SignerAPI over a Unix socket connection to `signer serve`."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(path)
        self.rfile = self.sock.makefile("rb")

    def __getattr__(self, method):
        def call(req):
            frame = {"method": method, **req} if isinstance(req, dict) else {"method": method, "params": req}
            self.sock.sendall(json.dumps(frame).encode() + b"\n")
            out = json.loads(self.rfile.readline())
            if "error" in out:
                e = out["error"]
                raise RPCError(e["code"], e["message"], e.get("retry_after_ms"))
            return out
        return call

    def close(self):
        self.rfile.close()
        self.sock.close()


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestServeContract(SignerContract, unittest.TestCase):
    def make_signer(self):
        d = tmpdir(self)
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "multi_tenant_apps": [f"uid:{ME.subject}"],
               "approvals": {"self_approval": "allow"}}   # one uid runs and approves
        service = svc.open_service(cfg, policy=PAY_ASKS)
        servers = svc.serve(cfg, service)
        for srv in servers:
            self.addCleanup(service.close)
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = SocketSigner(cfg["socket"])
        self.addCleanup(client.close)
        return client


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCli(unittest.TestCase):
    def test_serve_takes_the_lock_before_the_socket_and_fsck(self):
        d = tmpdir(self)
        cfg = os.path.join(d, "signer.yaml")
        with open(cfg, "w") as f:
            f.write("data_dir: data\nsocket: s.sock\n")
        cmd = [sys.executable, "-m", "tracekit", "signer"]
        p = subprocess.Popen(cmd + ["serve", "--config", cfg], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(p.kill)
        self.assertIn(b"serving", p.stdout.readline())
        second = subprocess.run(cmd + ["serve", "--config", cfg], cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(second.returncode, 1)
        self.assertIn(b"another signer holds", second.stderr)
        c = SocketSigner(os.path.join(d, "s.sock"))   # the first signer's socket survived the second start
        self.assertEqual(c.status({})["identity"]["scheme"], "uid")
        c.register_run({"request_id": "r", "agent": {"name": "a"}})
        c.close()
        p.terminate()
        self.assertEqual(p.wait(30), 0)
        out = subprocess.run(cmd + ["fsck", "--config", cfg], cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, b"ok"))


@pytest.mark.perf
@unittest.skipUnless(sys.platform.startswith("linux"), "the S1 gates are Linux-only")
class TestPerf(unittest.TestCase):
    """S1 gates, ack-on-write over a Unix socket: >= 1,000 events/s for 60 s with p99 <= 5 ms at that rate."""
    RATE, SECONDS, CLIENTS = 1050, 60, 8

    def test_s1_gates(self):
        d = tmpdir(self)
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "limits": {"events_per_s": 1e6, "burst": 10 ** 6}}
        service = svc.open_service(cfg)
        servers = svc.serve(cfg, service)
        self.addCleanup(service.close)
        for srv in servers:
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        lat, lock = [], threading.Lock()
        start = time.monotonic() + 0.5

        def client(n):
            c = SocketSigner(cfg["socket"])
            run = c.register_run({"request_id": f"r{n}", "agent": {"name": "perf"}})
            per, i, mine = self.RATE / self.CLIENTS, 0, []
            while True:
                due = start + i / per
                if due - start >= self.SECONDS:
                    break
                time.sleep(max(0, due - time.monotonic()))
                t = time.perf_counter()
                c.decide({"request_id": f"d{n}-{i}", "run_id": run["run_id"], "run_token": run["run_token"],
                          "stream": "s", "client_seq": i, "tool_call_id": f"t{i}", "tool": "read_file",
                          "args_source": "raw", "args": '{"path": "a.txt"}'})
                mine.append(time.perf_counter() - t)
                i += 1
            c.close()
            with lock:
                lat.extend(mine)
        threads = [threading.Thread(target=client, args=(n,)) for n in range(self.CLIENTS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - start
        lat.sort()
        p99 = lat[int(len(lat) * 0.99)] * 1000
        rate = len(lat) / elapsed
        print(f"S1: {rate:.0f} events/s over {elapsed:.0f} s, p99 {p99:.2f} ms")
        self.assertGreaterEqual(rate, 1000)
        self.assertLessEqual(p99, 5.0)


if __name__ == "__main__":
    unittest.main()
