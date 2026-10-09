"""Signer core robustness: key files, the rollback check against stored notes, memory of final runs, rate limits on
every write, clocks across a restart, registry replay, background loops, owner identity, shutdown and committed reads."""
import base64
import errno
import json
import os
import threading
import time
import unittest
import uuid
from unittest import mock

from factories import wait_for
from test_signer_service import ME, PAY_ASKS, records, tmpdir
from tracekit.identity.base import CallerIdentity
from tracekit.signer import pipeline
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import StorageCorrupt, StorageUnavailable
from tracekit.storage.file import FileStorage

PAY = {"to": "acct-42", "cents": 1500}


class Gate(FileStorage):
    """File storage whose appends, while `hold` is set, wait for `release` and then fail."""
    hold, entered, release = False, threading.Event(), threading.Event()

    def append_batch(self, records):
        if Gate.hold:
            Gate.entered.set()
            Gate.release.wait(5)
            Gate.hold = False
            raise StorageUnavailable("No space left on device")
        super().append_batch(records)


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)

    def open(self, **kw):
        kw.setdefault("open_storage", lambda: Gate(os.path.join(self.dir, "store")))
        s = svc.SignerService(self.dir, policy=PAY_ASKS, **kw)
        self.addCleanup(s.close)
        return s

    def call(self, s, method, req, who=ME):
        return s.call(who, method, {"request_id": uuid.uuid4().hex, **req})

    def register(self, s, who=ME):
        out = self.call(s, "register_run", {"agent": {"name": "a"}}, who)
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def ask(self, s, run, seq=0, tcid="tc-1"):
        self.call(s, "decide", {**run, "stream": "s", "client_seq": seq, "tool_call_id": tcid, "tool": "pay",
                                "args_source": "parsed", "args": PAY})
        return self.call(s, "approval_request", {**run, "tool_call_id": tcid})["approval_id"]

    def refused(self, code, fn, *a):
        with self.assertRaises(RPCError) as cm:
            fn(*a)
        self.assertEqual(cm.exception.code, code, cm.exception)

    def types(self, typ):
        return [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == typ]


class TestKeyFiles(Case):
    def test_a_failed_key_write_leaves_no_key_and_a_short_key_stops_the_start(self):
        def short(fd, data):
            os.write(fd, data[:5])
            raise OSError(errno.ENOSPC, "No space left on device")
        with mock.patch.object(svc, "_write_all", short), self.assertRaises(OSError):
            svc.SignerService(self.dir)
        self.assertEqual(os.listdir(os.path.join(self.dir, "keys")), [])
        svc.SignerService(self.dir).close()
        path = os.path.join(self.dir, "keys", "run_token.key")
        with open(path, "r+b") as f:
            f.truncate(5)
        with self.assertRaises(ValueError) as cm:
            svc.SignerService(self.dir)
        self.assertIn("run_token.key holds 5 bytes", str(cm.exception))


class TestRollbackAgainstStoredNotes(Case):
    def written(self):
        s = self.open()
        run = self.register(s)
        self.call(s, "decide", {**run, "stream": "s", "client_seq": 0, "tool_call_id": "t", "tool": "t",
                                "args_source": "parsed", "args": {}})
        s.close()   # writes the notes of the record tree and the registry tree
        return run

    def assert_rolled_back(self, run, path):
        s = self.open()
        self.refused("unavailable", self.call, s, "close_run", run)
        s.close()
        self.assertEqual([(t["kind"], t["path"]) for t in self.types("trace.tamper")], [("rollback", path)])
        self.call(self.open(acknowledge_rollback=True), "close_run", run)

    def test_records_cut_short_after_a_note(self):
        run = self.written()
        p = os.path.join(self.dir, "store", "records.jsonl")
        lines = open(p, "rb").read().splitlines(True)
        self.assertEqual(json.loads(lines[-1])["event"]["type"], "policy.decision")
        with open(p, "wb") as f:
            f.writelines(lines[:-1])
        self.assert_rolled_back(run, "records")

    def test_records_forked_at_the_notes_size(self):
        run = self.written()
        p = os.path.join(self.dir, "store", "checkpoint.note")
        note = open(p).read().split("\n")
        note[2] = base64.b64encode(b"\x01" * 32).decode()
        with open(p, "w") as f:
            f.write("\n".join(note))
        self.assert_rolled_back(run, "records")

    def test_registry_forked_at_the_notes_size(self):
        run = self.written()
        p = os.path.join(self.dir, "store", "registry-notes.jsonl")
        lines = open(p).read().splitlines()
        last = json.loads(lines[-1])
        note = last["note"].split("\n")
        note[2] = base64.b64encode(b"\x01" * 32).decode()
        last["note"] = "\n".join(note)
        with open(p, "w") as f:
            f.write("\n".join(lines[:-1] + [json.dumps(last)]) + "\n")
        self.assert_rolled_back(run, note[0])


class TestMemory(Case):
    def test_final_runs_keep_only_what_refuses_late_writes(self):
        s = self.open(grace_s=0)
        run = self.register(s)
        key = ("default", run["run_id"])
        aids = [self.ask(s, run, i, f"tc-{i}") for i in range(3)]
        self.assertEqual([c["pending"] for c in s.log.runs[key]["calls"].values()], [None] * 3)
        self.call(s, "approval_decide", {"approval_id": aids[0], "decision": "approve"},
                  CallerIdentity("uid", "999999", True))
        self.call(s, "close_run", run)
        s.sweep()
        for restart in (False, True):   # live, then the same after a restart
            if restart:
                s = self.open(grace_s=0)
            self.assertEqual(set(s.log.runs[key]), set(pipeline.FINAL_KEYS))
            self.assertEqual((s.log.approvals, s.log.approval_index), ({}, {}))
            self.refused("run_closed", self.call, s, "decide", {**run, "stream": "s", "client_seq": 9,
                                                                "tool_call_id": "x", "tool": "t", "args_source": "parsed",
                                                                "args": {}})
            s.close()


class TestRateLimits(Case):
    def test_register_close_and_approvals_take_events_and_open_runs_are_counted(self):
        s = self.open(limits=Limits(events_per_s=0.001, burst=2))
        run = self.register(s)
        self.assertEqual(s.log.open_runs, {f"uid:{ME.subject}": 1})
        self.call(s, "close_run", run)
        self.assertEqual(s.log.open_runs, {})
        self.refused("quota_exceeded", self.register, s)
        self.refused("quota_exceeded", self.call, s, "close_run", run)


class TestClocksAcrossRestart(Case):
    def test_idle_and_grace_clocks_keep_running_while_the_signer_is_down(self):
        s = self.open(idle_s=60, grace_s=60)
        idle, closing = self.register(s), self.register(s)
        self.call(s, "close_run", closing)
        s.close()
        real = time.time
        with mock.patch("time.time", lambda: real() + 61):   # restarted a minute later
            s = self.open(idle_s=60, grace_s=60)
        s.sweep()
        s.close()
        es = [r["event"] for r in records(self.dir)]
        self.assertEqual([e["data"]["reason"] for e in es if e["type"] == "run.closing" and e["run_id"] == idle["run_id"]],
                         ["idle_timeout"])
        self.assertEqual([e["run_id"] for e in es if e["type"] == "run.final"], [closing["run_id"]])

    def test_a_record_from_the_future_is_not_idle_time(self):
        self.assertAlmostEqual(pipeline.since("2999-01-01T00:00:00Z"), time.monotonic(), delta=1)


class TestRegistryReplay(Case):
    def test_a_registry_leaf_its_records_do_not_give_stops_the_start(self):
        s = self.open()
        self.register(s)
        s.close()
        p = os.path.join(self.dir, "store", "registry.jsonl")
        lines = open(p, "rb").read().splitlines(True)
        with open(p, "ab") as f:
            f.write(lines[-1])   # a leaf whose record was lost
        with self.assertRaises(StorageCorrupt):
            self.open()


class TestLoops(Case):
    def test_an_unexpected_error_is_counted_and_the_loop_carries_on(self):
        with mock.patch.object(svc, "TICK_S", 0.02), mock.patch.object(svc, "CHECKPOINT_MIN_S", 0.02):
            s = self.open()
            sweep, checkpoint = s.sweep, s.checkpoint
            s.sweep = mock.Mock(side_effect=[KeyError("x")] + [None] * 1000)
            s.checkpoint = mock.Mock(side_effect=[ValueError("x")] + [None] * 1000)
            s._nudged.set()
            self.assertTrue(wait_for(lambda: s.sweep.call_count > 1 and s.checkpoint.call_count, 5))
            time.sleep(0.1)
            self.assertTrue(s._ticker.is_alive() and s._checkpointer.is_alive())
            s.sweep, s.checkpoint = sweep, checkpoint
        out = s.metrics.render()
        for loop in ("ticker", "checkpointer"):
            self.assertIn(f'tracekit_signer_loop_errors_total{{loop="{loop}"}} 1', out)

    def test_dropping_approval_args_never_fails(self):
        s = self.open()
        with mock.patch.object(svc.os, "unlink", side_effect=PermissionError(errno.EACCES, "denied")):
            s._drop_args("a-1")


class TestOwner(Case):
    def test_a_long_subject_owns_its_runs_across_a_restart(self):
        long = CallerIdentity("token", "s" * 300, True)
        s = self.open(limits=Limits(open_runs=1), authorize={"token:" + "s" * 300: ["register_run"]})
        run = self.register(s, long)
        before = s.log.runs[("default", run["run_id"])]["owner"]
        s.close()
        s = self.open(limits=Limits(open_runs=1), authorize={"token:" + "s" * 300: ["register_run"]})
        self.assertEqual(s.log.runs[("default", run["run_id"])]["owner"], before)
        self.refused("quota_exceeded", self.register, s, long)


class TestShutdown(Case):
    def test_a_write_after_close_is_refused(self):
        s = self.open()
        s.close()
        self.refused("unavailable", s.log.write, lambda tx: None)


class TestCommittedReads(Case):
    def test_an_answer_not_yet_written_is_not_read(self):
        s = self.open()
        run = self.register(s)
        aid = self.ask(s, run)
        Gate.hold = True
        Gate.entered.clear()
        Gate.release.clear()
        decided = threading.Thread(target=lambda: self.assertRaises(RPCError, self.call, s, "approval_decide", {
            "approval_id": aid, "decision": "approve"}, CallerIdentity("uid", "999999", True)))
        decided.start()
        self.assertTrue(Gate.entered.wait(5))
        got = []
        reader = threading.Thread(target=lambda: got.append(self._get(s, aid)))
        reader.start()
        time.sleep(0.2)
        Gate.release.set()
        decided.join(5)
        reader.join(5)
        self.assertNotEqual(got, ["approved"])
        time.sleep(1.05)   # pipeline.RECOVER_S
        self.assertEqual(self._get(s, aid), "requested")

    def _get(self, s, aid):
        try:
            return s.call(ME, "approval_get", {"approval_id": aid})["state"]
        except RPCError as e:
            return e.code


if __name__ == "__main__":
    unittest.main()
