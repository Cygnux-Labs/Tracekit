"""The v2 signer service (tracekit/signer/service.py, pipeline.py): the RPC conformance suite in process and over a real
Unix socket, refusals that leave no state, disk errors, restart with a torn tail, rollback detection, quotas, the CLI,
and (with -m perf, Linux) the S1 performance gates."""
import json
import logging
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
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import pipeline, service as svc
from tracekit.signer.pipeline import SIGNER_RUN
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.storage import file as file_storage
from tracekit.storage.base import StorageCorrupt, StorageUnavailable
from tracekit.storage.file import FileStorage
from tracekit.tlog_witness import TlogWitness

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
OTHER = CallerIdentity("uid", "999999", True)
# what the signer measures for a uid caller (ME, OTHER): Windows has no uid of its own to compare with
SAME_USER, SEPARATE_USER = ("same-user", "separate-user") if hasattr(os, "getuid") else ("unknown", "unknown")
PAY_ASKS = Engine({"ask": [{"id": "TEST-PAY", "tool": "pay", "pattern": "^"}]})
# a child's prelude: each Event.wait that serve_dev or `signer serve` (service.main) makes raises SIGTERM while it holds
# the Event's lock, as a signal that lands there does
SIGTERM_IN_WAIT = ("import signal, sys, threading\n"
                   "from tracekit.signer import service\n"
                   "real = threading.Event.wait\n"
                   "def wait(self, timeout=None):\n"
                   "    if sys._getframe(1).f_code in (service.serve_dev.__code__, service.main.__code__):\n"
                   "        with self._cond:\n"
                   "            signal.raise_signal(signal.SIGTERM)\n"
                   "    return real(self, timeout)\n"
                   "threading.Event.wait = wait\n")


class Unreachable(TlogWitness):
    def __init__(self):
        super().__init__("http://127.0.0.1:9", checkpoint.vkey("w.example/w", checkpoint.COSIGNATURE, bytes(32)))


def tmpdir(case):
    d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: macOS caps socket paths at 104 bytes
    case.addCleanup(shutil.rmtree, d, True)
    return d


def records(data_dir):
    with open(os.path.join(data_dir, "store", "records.jsonl"), "rb") as f:
        return [json.loads(line) for line in f.read().splitlines()]


def drop_call_keys(data_dir, *keys):
    """Rewrite the latest snapshot of the closed signer at `data_dir` as one written before its calls kept `keys`."""
    snaps = os.path.join(data_dir, "store", "snapshots")
    path = os.path.join(snaps, max(os.listdir(snaps), key=lambda n: int(n.split(".")[0])))
    with open(path, "rb") as f:
        snap = json.loads(f.read().partition(b"\n")[2])
    for r in snap["state"]["runs"]:
        for c in [*r.get("calls", {}).values(), *filter(None, r.get("decisions", {}).values())]:
            for k in keys:
                c.pop(k, None)
    body = json.dumps(snap, separators=(",", ":")).encode()
    with open(os.path.join(data_dir, "keys", "snapshot.key"), "rb") as f:
        mac = file_storage._mac(f.read(), body)
    with open(path, "wb") as f:
        f.write(mac + b"\n" + body)


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


class FlakyRegistry(Disk):
    """Disk whose next registry reads fail, as a replay's last steps make them."""
    fail = 0

    def registry_iter(self, tenant, start=0):
        if FlakyRegistry.fail:
            FlakyRegistry.fail -= 1
            raise OSError("registry read failed")
        return super().registry_iter(tenant, start)


class TestService(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        Disk.fail = FlakyRegistry.fail = 0

    def open(self, **kw):
        s = svc.SignerService(self.dir, policy=PAY_ASKS, open_storage=lambda: Disk(os.path.join(self.dir, "store")), **kw)
        self.addCleanup(s.close)
        return s

    def state(self, s):
        return s.log.storage.tail_state(), json.dumps(sorted(s.log.runs.items()), sort_keys=True)

    def register(self, s, identity=ME, **kw):
        return s.call(identity, "register_run", {"request_id": f"reg-{uuid.uuid4().hex}", "agent": {"name": "a"}, **kw})

    def ev(self, run, seq, rid=None, **kw):
        return {"request_id": rid or uuid.uuid4().hex, "run_id": run["run_id"], "run_token": run["run_token"],
                "stream": "s1", "client_seq": seq, **kw}

    def refused(self, code, s, method, req, identity=ME):
        with self.assertRaises(RPCError) as cm:
            s.call(identity, method, req)
        self.assertEqual(cm.exception.code, code, cm.exception)

    def test_privileged_methods_are_never_granted_by_default(self):
        """Every method is a default grant or never one, so a new method can't reach an unconfigured uid peer or the
        dev token by accident."""
        self.assertEqual(svc.DEFAULT_GRANTS | svc.NEVER_DEFAULT, set(REQUESTS))
        self.assertFalse(svc.DEFAULT_GRANTS & svc.NEVER_DEFAULT)
        s, other = self.open(), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        configured = svc.SignerService(other, policy=PAY_ASKS, approvals={"approvers": ["uid:1"]})
        self.addCleanup(configured.close)
        for who in (OTHER, CallerIdentity("token", "dev", True)):
            for method in sorted(svc.NEVER_DEFAULT - {"run_label_clear"}):
                self.refused("forbidden", s, method, {}, who)
            # but a signer with no approvals config (a dev signer) lets its own user clear their run's label, as it
            # lets them answer their run's approvals (self_cleared: tests/test_run_conditions.py)
            self.refused("invalid_request", s, "run_label_clear", {}, who)
            self.refused("forbidden", configured, "run_label_clear", {}, who)

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

    def test_state_write_from_another_state_than_the_last_written_is_a_signed_state_tamper(self):
        d1, d2, d3, other = ("sha256:" + c * 64 for c in "1234")
        s = self.open()
        run = self.register(s)
        s.state_write(self.ev(run, 0, key="k", value_digest=d1, prev_digest=None))
        s.state_write(self.ev(run, 1, key="k", value_digest=d2, prev_digest=d1))
        s.state_write(self.ev(run, 2, key="j", value_digest=d1, prev_digest=other))   # no earlier write to compare
        s.state_write(self.ev(run, 3, key="k", value_digest=d3, prev_digest=other))
        s.close()
        s = self.open()   # the last digest per key survives a restart
        s.state_write(self.ev(run, 4, key="k", value_digest=d1, prev_digest=d2))
        s.close()
        events = [r["event"] for r in records(self.dir) if r["event"].get("run_id") == run["run_id"]]
        for e in events:
            self.assertEqual(schema.validate(e), [], e)
        gaps = [e["data"] for e in events if e["type"] == "capture.gap"]
        self.assertEqual([g["kind"] for g in gaps], ["state_tamper", "state_tamper"])
        for g in gaps:   # the reason names the key; the state digests stay commitments, never in clear
            self.assertIn("state k ", g["reason"])
            self.assertFalse(any(d in g["reason"] for d in (d1, d2, d3, other)), g["reason"])

    def snapshotting(self):
        """The signer on the file storage it opens by default, which snapshots its state (Disk keeps no snapshot)."""
        s = svc.SignerService(self.dir, policy=PAY_ASKS)
        self.addCleanup(s.close)
        return s

    def call_states(self):
        """(the call_state of each of a run's calls, as a function of a signer, as it is now) of a closed signer whose
        run holds a refused pay, a call that failed, and a pay refused, then approved, consumed and run"""
        s = self.snapshotting()
        run = self.register(s)
        call = {"run_id": run["run_id"], "run_token": run["run_token"], "tool_call_id": "tc", "tool": "pay",
                "args_source": "parsed", "args": {"to": "a"}}
        s.decide({**self.ev(run, 0), **call})
        s.approval_request({"request_id": "r", **{k: call[k] for k in ("run_id", "run_token", "tool_call_id")}})
        s.approval_consume({"request_id": "c", **call})
        d = s.decide(self.ev(run, 1, tool_call_id="ok", tool="t", args_source="parsed", args={}))
        s.complete(self.ev(run, 2, tool_call_id="ok", decision_id=d["decision_id"], status="error",
                           args_digest=event_hash({"tool": "t", "args": {}})))
        later = dict(call, tool_call_id="later")
        d = s.decide({**self.ev(run, 3), **later})
        aid = s.approval_request({"request_id": "r2", **{k: later[k] for k in ("run_id", "run_token",
                                                                               "tool_call_id")}})["approval_id"]
        s.approval_consume({"request_id": "c2", **later})
        s.call(OTHER, "approval_decide", {"request_id": "ok", "approval_id": aid, "decision": "approve"})
        self.assertTrue(s.approval_consume({"request_id": "c3", **later})["ok"])
        s.complete(self.ev(run, 4, tool_call_id="later", decision_id=d["decision_id"], status="ok",
                           args_digest=event_hash({"tool": "pay", "args": {"to": "a"}})))

        def states(s):
            return [s.call(ME, "call_state", {"run_id": run["run_id"], "run_token": run["run_token"], "tool_call_id": t})
                    for t in ("tc", "ok", "later")]
        before = states(s)
        self.assertEqual((before[0]["refused"], before[1]["result"]["ok"], before[2]["consumed"],
                          before[2]["result"]["ok"], "refused" in before[2]),
                         (["TK-APPROVAL-REQUESTED"], False, True, True, False))
        s.close()
        return states, before

    def test_call_state_is_the_same_after_a_restart(self):
        """call_state reads what the records hold: a refused consume and a result survive a restart, from the
        snapshot and from a replay of the records alone."""
        states, before = self.call_states()
        s = self.snapshotting()
        self.assertIsNotNone(s.log.storage.snapshot)
        self.assertEqual(states(s), before)   # from the snapshot a clean close wrote
        s.close()
        shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
        s = self.snapshotting()
        self.assertIsNone(s.log.storage.snapshot)
        self.assertEqual(states(s), before)   # from the records alone

    def test_call_state_from_a_snapshot_written_before_it(self):
        """A snapshot written before call_state (RPC 24) keeps no call's refusal or result: the start reads them from
        the records, so a pay that ran isn't taken for one consumed and never ended."""
        states, before = self.call_states()
        drop_call_keys(self.dir, "ended", "refused")   # as a snapshot written before 1.7.0's call_state holds them
        s = self.snapshotting()
        self.assertIsNotNone(s.log.storage.snapshot)   # it started from the edited snapshot
        self.assertEqual(states(s), before)

    def consumed(self, s, run, tcid, seq):
        """A pay `tcid` of `run`, decided ask, approved by another identity and consumed."""
        tok = {"run_id": run["run_id"], "run_token": run["run_token"]}
        call = {**tok, "tool_call_id": tcid, "tool": "pay", "args_source": "parsed", "args": {"to": tcid}}
        s.decide({**self.ev(run, seq), **call})
        aid = s.approval_request({"request_id": f"r-{tcid}", **tok, "tool_call_id": tcid})["approval_id"]
        s.call(OTHER, "approval_decide", {"request_id": f"ok-{tcid}", "approval_id": aid, "decision": "approve"})
        self.assertTrue(s.approval_consume({"request_id": f"c-{tcid}", **call})["ok"])

    @staticmethod
    def claim(s, run, tcid, answers=2):
        return s.call(ME, "call_claim", {"request_id": uuid.uuid4().hex, "run_id": run["run_id"],
                                         "run_token": run["run_token"], "tool_call_id": tcid, "attempt": 0,
                                         "answers": answers})

    def test_call_claim_refuses_a_consume_from_before_the_signer_started(self):
        """Claims are memory: a call whose approval was consumed before this signer process started may have gone on
        under a claim a crash took with it, so it is refused (a person approves it again), from the snapshot and from
        the records alone; one consumed since is claimed as before."""
        s = self.snapshotting()
        run = self.register(s)
        self.consumed(s, run, "before", 0)
        self.assertTrue(self.claim(s, run, "before")["ok"])
        s.close()
        for snapshot in (True, False):
            if not snapshot:
                shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
            s = self.snapshotting()
            self.assertEqual(self.claim(s, run, "before", 3), {
                "ok": False, "reason": "the signer restarted since this call's approval was used; ask again"})
            s.close()
        s = self.snapshotting()
        self.consumed(s, run, "since", 1)
        self.assertEqual((self.claim(s, run, "since")["ok"], self.claim(s, run, "since")["ok"]), (True, False))

    def test_call_claim_survives_a_storage_recovery(self):   # probe test_probe851_recover.py
        """The signer recovers from a storage error without restarting, rebuilding its run state from the records.
        At 93a34eebb0 the rebuild dropped the claims, so a pause claimed before the outage was claimed again (a pay ran
        twice). They are carried over now; and a call consumed in this process, claimed first after the outage, is
        claimed as usual (its consume's place in the log, rebuilt from the records, is after the start)."""
        s = self.open()
        run = self.register(s)
        self.consumed(s, run, "claimed", 0)
        self.consumed(s, run, "waiting", 1)
        self.assertTrue(self.claim(s, run, "claimed")["ok"])
        Disk.fail = 1
        self.refused("unavailable", s, "decide", self.ev(run, 2, tool_call_id="t", tool="t", args_source="parsed",
                                                         args={}))
        with mock.patch.object(pipeline, "RECOVER_S", 0):
            s.decide(self.ev(run, 2, tool_call_id="t", tool="t", args_source="parsed", args={}))
        self.assertEqual((self.claim(s, run, "claimed")["ok"], self.claim(s, run, "waiting")["ok"]), (False, True))

    def test_call_claim_survives_a_recovery_that_fails_partway(self):   # probe test_probe851_recover2.py
        """A recovery whose replay rebuilt the runs and then failed (a registry read): at 1de86d23a8 the runs it left
        had no claims, and the next recovery carried over none, so a pause claimed before the outage was claimed again.
        The claims go back onto the runs whether the replay ends or not."""
        s = svc.SignerService(self.dir, policy=PAY_ASKS,
                              open_storage=lambda: FlakyRegistry(os.path.join(self.dir, "store")))
        self.addCleanup(s.close)
        run = self.register(s)
        self.consumed(s, run, "claimed", 0)
        self.assertTrue(self.claim(s, run, "claimed")["ok"])
        Disk.fail, decide = 1, self.ev(run, 1, tool_call_id="t", tool="t", args_source="parsed", args={})
        self.refused("unavailable", s, "decide", decide)
        FlakyRegistry.fail = 1
        with mock.patch.object(pipeline, "RECOVER_S", 0):
            self.refused("unavailable", s, "decide", decide)   # the first recovery fails after its replay
            s.decide(decide)
        self.assertFalse(self.claim(s, run, "claimed")["ok"])

    def test_disk_error_is_unavailable_then_a_signed_gap(self):
        s = self.open()
        run = self.register(s)
        before = self.state(s)
        Disk.fail = 1
        self.refused("unavailable", s, "decide", self.ev(run, 0, tool_call_id="t", tool="t", args_source="parsed", args={}))
        self.assertEqual(self.state(s)[1], before[1])
        with mock.patch.object(pipeline, "RECOVER_S", 0):
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

    def test_restart_sets_aside_a_registry_leaf_whose_record_was_lost(self):
        s = self.open()
        self.register(s)
        s.close()
        path = os.path.join(self.dir, "store", "registry.jsonl")
        line = json.loads(open(path, "rb").read().splitlines()[-1])
        leaf = bytes.fromhex(line["leaf"])
        size = len(records(self.dir))
        with open(path, "ab") as f:   # ack-on-write power loss: the leaf's line survived, its record's did not
            f.write(json.dumps({**line, "leaf": (leaf[:49] + size.to_bytes(8, "big") + leaf[57:]).hex()}).encode() + b"\n")
        s = self.open()
        self.register(s)
        s.close()
        gaps = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("registry.jsonl set aside", gaps[0]["reason"])
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

        class Witness(Unreachable):
            def latest(self, empty_note, log_vkey):
                return size, root
        s = self.open(witnesses=[Witness()])
        self.refused("unavailable", s, "close_run", {"request_id": "c", "run_id": run["run_id"], "run_token": run["run_token"]})
        s.close()
        tampers = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "trace.tamper"]
        self.assertEqual([(t["kind"], t["before"]["length"]) for t in tampers], [("rollback", size)])
        s = self.open(witnesses=[Witness()], acknowledge_rollback=True)
        s.close_run({"request_id": "c", "run_id": run["run_id"], "run_token": run["run_token"]})

    def test_a_stuck_witness_does_not_hold_up_the_start(self):
        s = self.open()
        size = s.log.storage.tail_state()["tree_size"] + 5
        s.close()
        release = threading.Event()
        self.addCleanup(release.set)

        class Stuck(Unreachable):
            def latest(self, empty_note, log_vkey):
                release.wait(30)
                raise OSError("too late")

        class Ahead(Unreachable):
            def latest(self, empty_note, log_vkey):
                return size, None
        start = time.monotonic()
        with mock.patch.object(svc, "WITNESS_START_S", 0.3):
            s = self.open(witnesses=[Stuck(), Ahead()])   # asked at once: the stuck one first holds up neither
        self.assertLess(time.monotonic() - start, 5)
        s.close()
        tampers = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "trace.tamper"]
        self.assertEqual([(t["kind"], t["before"]["length"]) for t in tampers], [("rollback", size)])

    def test_unreachable_witness_starts_degraded(self):
        class Down(Unreachable):
            def latest(self, empty_note, log_vkey):
                raise OSError("connection refused")
        s = self.open(witnesses=[Down()])
        self.register(s)
        s.close()
        gaps = [r["event"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([g["data"]["kind"] for g in gaps], ["degraded_unanchored"])
        self.assertEqual((gaps[0]["tenant"], gaps[0]["run_id"]), SIGNER_RUN)

    def test_silent_startup_witness_keeps_writes_and_verifies_the_signed_gap(self):
        from tracekit.bundle_v2 import export
        from tracekit.verify import v2

        release = threading.Event()
        witness_key = checkpoint.vkey("witness.example.org/silent", checkpoint.COSIGNATURE, b"\x01" * 32)

        class Silent(Unreachable):
            name = "witness.example.org/silent"
            vkey = witness_key

            def latest(self, empty_note, log_vkey):
                release.wait(10)
                raise OSError("silent")

            def add_checkpoint(self, note, log_vkey, start_size=0):
                raise OSError("silent")

        start = time.monotonic()
        with mock.patch.object(svc, "CLOSE_WAIT_S", 0.05):
            s = self.open(witnesses=[Silent()], witness_start_s=0.05, grace_s=0)
        self.assertLess(time.monotonic() - start, 1)
        with open(os.path.join(self.dir, svc.WITNESSED), encoding="ascii") as f:
            self.assertEqual(json.load(f), {s.witnesses[0].name: None})   # configured, no answer
        run = self.register(s)
        s.call(ME, "close_run", {"request_id": uuid.uuid4().hex, "run_id": run["run_id"],
                                  "run_token": run["run_token"]})
        self.assertGreater(s.log.storage.tree.size, 0)
        release.set()
        s.close()
        bundle_path, trust_path = os.path.join(self.dir, "signer.tkb"), os.path.join(self.dir, "trust.json")
        note = s.log.storage.checkpoint_latest("records")[1]
        export(s.log.storage, SIGNER_RUN[0], SIGNER_RUN[1], note, bundle_path)
        with open(trust_path, "w", encoding="utf-8") as f:
            json.dump({"logs": [s.vkey], "witnesses": [{"vkey": witness_key, "class": "public"}],
                       "algs": ["ed25519"], "witnesses_required": 0}, f)
        rep, code = v2.verify(bundle_path, trust_path)
        self.assertEqual(code, 0, rep.checks)
        signed_gaps = [r["event"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([g["data"]["kind"] for g in signed_gaps], ["degraded_unanchored"])
        self.assertTrue(rep.assurance.startswith("dev;"))

    def test_every_start_records_its_witnesses_none_with_none(self):
        """init and up --wait read it: a start with no witness wrote nothing, so they read an older start's."""
        self.open()
        with open(os.path.join(self.dir, svc.WITNESSED), encoding="ascii") as f:
            self.assertEqual(json.load(f), {})

    def test_a_key_made_while_the_signer_starts_is_the_one_it_uses(self):
        """`tracekit init --dev --v2` makes keys/log.key outside the signer's lock, to print its fingerprint."""
        path = os.path.join(self.dir, "log.key")

        def make():
            svc._write_new(path, b"\1" * 32)   # init, between the signer's read and its write
            return b"\2" * 32
        self.assertEqual(svc._secret(path, make), b"\1" * 32)

    def test_quotas_and_refusal_summaries(self):
        s = self.open(limits=Limits(open_runs=1, events_per_s=0.001, burst=3, streams_per_run=1))
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


class TestLogging(unittest.TestCase):
    def setUp(self):
        root, tk = logging.getLogger(), logging.getLogger("tracekit")
        saved = root.handlers[:], root.level, tk.level

        def restore():
            root.handlers[:], level, tk_level = saved
            root.setLevel(level)
            tk.setLevel(tk_level)
        self.addCleanup(restore)
        root.handlers[:] = []   # pytest's capture handler would make basicConfig a no-op
        root.setLevel(logging.WARNING)
        tk.setLevel(logging.NOTSET)

    @mock.patch("logging.basicConfig")
    def test_serve_default_does_not_configure_logging(self, basic_config):
        with mock.patch.object(svc, "_serve_dev"):
            svc.main(["serve", "--dev"])
        basic_config.assert_not_called()

    def test_serve_log_level_reaches_tracekit_loggers_only(self):
        for name, level in (("warning", logging.WARNING), ("info", logging.INFO), ("debug", logging.DEBUG)):
            with self.subTest(name=name), mock.patch.object(svc, "_serve_dev"):
                svc.main(["serve", "--dev", "--log-level", name])
                self.assertEqual(logging.getLogger("tracekit.transport.http").getEffectiveLevel(), level)
                # botocore's debug log prints AWS credentials when the log key is in KMS
                self.assertFalse(logging.getLogger("botocore").isEnabledFor(logging.INFO))


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCli(unittest.TestCase):
    def test_serve_takes_the_lock_before_the_socket_and_fsck(self):
        d = tmpdir(self)
        cfg = os.path.join(d, "signer.yaml")
        with open(cfg, "w") as f:
            f.write("data_dir: data\nsocket: s.sock\nlock_timeout_s: 0.5\n")   # the second start gives up quickly
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

    def test_a_sigterm_landing_while_the_serving_loop_waits_stops_the_signer(self):
        """Review of 1.5.3: the loop waited on the Event its SIGTERM handler set, and a signal landing while wait() held
        the Event's lock left the handler waiting for that lock for good."""
        d = tmpdir(self)
        cfg = os.path.join(d, "signer.yaml")
        with open(cfg, "w") as f:
            f.write("data_dir: data\nsocket: s.sock\n")
        p = subprocess.Popen([sys.executable, "-c", SIGTERM_IN_WAIT + "sys.exit(service.main(sys.argv[1:]))", "serve",
                              "--config", cfg], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(p.kill)
        self.assertIn(b"serving", p.stdout.readline())
        p.terminate()
        self.assertEqual(p.wait(10), 0)

    def test_serve_names_the_http_port_it_bound(self):
        """http.listen with port 0 takes a free port, and the serving line names it: a script that picked a free port
        itself raced every other process for it (the demos' signer failed with Address already in use)."""
        d = tmpdir(self)
        cfg = os.path.join(d, "signer.yaml")
        with open(cfg, "w") as f:   # JSON is YAML
            json.dump({"data_dir": "data", "socket": "s.sock", "http": {
                "listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"], "tokens": "tokens.json"}}, f)
        p = subprocess.Popen([sys.executable, "-m", "tracekit", "signer", "serve", "--config", cfg], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(p.kill)
        line = p.stdout.readline()
        if " serving on 127.0.0.1:" not in line:
            self.fail(line + p.communicate(timeout=30)[1])
        port = int(line.rsplit(":", 1)[1])
        self.assertNotEqual(port, 0)
        socket.create_connection(("127.0.0.1", port), timeout=10).close()   # the signer listens there
        p.terminate()
        self.assertEqual(p.wait(30), 0)


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
