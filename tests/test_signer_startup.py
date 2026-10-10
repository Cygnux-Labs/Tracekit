"""Signer startup and store health (04-design §2.5, §2.6): store snapshots, the background fsck and the storage lock's
timeout."""
import contextlib
import io
import hashlib
import hmac
import json
import os
import shutil
import time
import unittest
from unittest import mock

from factories import wait_for
from test_signer_service import ME, records, tmpdir
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage


class Case(unittest.TestCase):
    def setUp(self):
        self.dir, self.n = tmpdir(self), 0

    def open(self, **kw):
        s = svc.SignerService(self.dir, grace_s=0, **kw)
        self.addCleanup(s.close)
        return s

    def call(self, s, method, req):
        self.n += 1
        return s.call(ME, method, {"request_id": f"req-{self.n}", **req})

    def register(self, s):
        out = self.call(s, "register_run", {"agent": {"name": "a"}})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def crash(self, s):
        """Close without the snapshot a clean close writes."""
        with mock.patch.object(FileStorage, "snapshot_put"):
            s.close()

    def read_on_open(self, **kw):
        """(the signer, seqs indexed by the store, seqs replayed by the signer) of one open."""
        indexed, replayed = [], []
        index, iter_range = FileStorage._index, FileStorage.iter_range

        def counted_index(st, record):
            indexed.append(record["event"]["seq"])
            return index(st, record)

        def counted_range(st, lo, hi):
            for r in iter_range(st, lo, hi):
                replayed.append(r["event"]["seq"])
                yield r
        with mock.patch.object(FileStorage, "_index", counted_index), \
                mock.patch.object(FileStorage, "iter_range", counted_range):
            s = self.open(**kw)
        return s, indexed, replayed


def comparable(state):
    for r in state["runs"]:
        r.pop("active", None)
        r.pop("closing_at", None)
    return json.loads(json.dumps(state))


class TestSnapshots(Case):
    def test_open_reads_only_the_records_after_the_snapshot(self):
        s = self.open()
        runs = [self.register(s) for _ in range(30)]
        for run in runs[:10]:
            self.call(s, "close_run", run)
        s.close()   # a clean close snapshots
        snap = s.log.storage.tree.size
        s = self.open()
        self.call(s, "close_run", runs[10])
        self.crash(s)
        total = s.log.storage.tree.size
        s, indexed, replayed = self.read_on_open()
        self.assertEqual(indexed, list(range(snap, total)))
        self.assertEqual(replayed, [snap - 1] + list(range(snap, total)))   # its last record, then the tail
        state = comparable(s.log._state())
        self.crash(s)
        shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
        s, indexed, _ = self.read_on_open()
        self.assertEqual(indexed, list(range(total)))
        self.assertEqual(comparable(s.log._state()), state)   # the same state as a full replay
        self.call(s, "close_run", runs[11])   # a run from before the snapshot, and its token, still known

    def edit_snapshot(self, edit, remac):
        s = self.open()
        self.register(s)
        s.close()
        snaps = os.path.join(self.dir, "store", "snapshots")
        name = os.listdir(snaps)[0]
        with open(os.path.join(snaps, name), "rb") as f:
            mac, _, body = f.read().partition(b"\n")
        snap = json.loads(body)
        edit(snap)
        body = json.dumps(snap).encode()
        if remac:
            with open(os.path.join(self.dir, "keys", "snapshot.key"), "rb") as f:
                mac = hmac.new(f.read(), body, hashlib.sha256).hexdigest().encode()
        with open(os.path.join(snaps, name), "wb") as f:
            f.write(mac + b"\n" + body)
        self.assertEqual(svc.fsck(self.dir), [f"snapshots/{name}: does not match the logs or its MAC, so open "
                                              "ignores it and replays them in full"])
        s, indexed, _ = self.read_on_open()
        self.assertEqual(indexed, list(range(s.log.storage.tree.size)))
        return s

    def test_a_snapshot_that_no_longer_matches_is_ignored_and_reported(self):
        self.edit_snapshot(lambda snap: snap.update(hash="sha256:" + "1" * 64), remac=True)

    def test_an_edited_snapshot_fails_its_mac_and_is_ignored(self):
        def edit(snap):
            for r in snap["state"]["runs"]:
                r["owner"] = "uid:4242"
        s = self.edit_snapshot(edit, remac=False)
        self.assertNotIn("uid:4242", [r.get("owner") for r in s.log.runs.values()])

    def test_old_snapshots_are_pruned(self):
        for _ in range(4):
            s = self.open()
            self.register(s)
            s.close()
        self.assertEqual(len(os.listdir(os.path.join(self.dir, "store", "snapshots"))), 2)


class TestBackgroundFsck(Case):
    def test_a_flipped_byte_is_a_tamper_record_and_refuses_writes(self):
        s = self.open(fsck_every_s=0.1)
        run = self.register(s)
        self.assertEqual(s.check_store(), [])
        p = os.path.join(self.dir, "store", "records.jsonl")
        with open(p, "r+b") as f:
            data = f.read()
            at = data.index(b'"id":"') + 6
            f.seek(at)
            f.write(b"0" if data[at:at + 1] != b"0" else b"1")
        self.assertTrue(wait_for(lambda: s.log.refuse_writes, 10))
        with self.assertRaises(RPCError) as e:
            self.call(s, "close_run", run)
        self.assertEqual(e.exception.code, "unavailable")
        s.close()
        tampers = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "trace.tamper"]
        self.assertEqual(tampers[0]["kind"], "edited")
        self.assertEqual(tampers[0]["path"], "records.jsonl line 1")


    def test_acknowledge_rollback_does_not_cover_it_and_a_finding_is_recorded_once(self):
        s = self.open(fsck_every_s=3600, acknowledge_rollback=True)
        run = self.register(s)
        p = os.path.join(self.dir, "store", "records.jsonl")
        with open(p, "r+b") as f:
            data = f.read()
            at = data.index(b'"id":"') + 6
            f.seek(at)
            f.write(b"0" if data[at:at + 1] != b"0" else b"1")
        self.assertTrue(s.check_store())
        self.assertTrue(s.log.refuse_writes)
        s.check_store()
        with self.assertRaises(RPCError):
            self.call(s, "close_run", run)
        s.close()
        self.assertEqual(sum(r["event"]["type"] == "trace.tamper" for r in records(self.dir)), 1)


class TestStorageLock(Case):
    def test_a_second_signer_waits_its_timeout_then_names_the_holder(self):
        self.open()
        start = time.monotonic()
        with self.assertRaises(BlockingIOError) as e:
            svc.SignerService(self.dir, lock_timeout_s=0.3)
        self.assertGreaterEqual(time.monotonic() - start, 0.3)
        if os.name != "nt":   # Windows keeps the holder's locked byte, and so its pid, unreadable
            self.assertIn(f"(pid {os.getpid()})", e.exception.strerror)
        cfg = os.path.join(self.dir, "signer.yaml")
        with open(cfg, "w") as f:
            f.write(f"data_dir: {self.dir}\nsocket: {self.dir}/s.sock\nlock_timeout_s: 0.1\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(svc.logkey, "harden"):   # keeps pytest dumpable
            self.assertEqual(svc.main(["serve", "--config", cfg]), 1)
        self.assertIn(f"another signer holds {os.path.join(self.dir, 'store')}", err.getvalue())


if __name__ == "__main__":
    unittest.main()
