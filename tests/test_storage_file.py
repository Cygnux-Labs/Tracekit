"""The file storage backend: the storage contract, plus what only a local disk has (modes, locking, disk errors,
unreadable lines, and acknowledged records surviving kill -9)."""
import errno
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from factories import wait_for
from storage_contract import Chain, StorageContract, leaves
from tracekit.format import checkpoint
from tracekit.merkle import leaf_hash, root
from tracekit.storage import file as file_storage
from tracekit.storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, StorageCorrupt, StorageUnavailable, registry_tree
from tracekit.storage.file import FileStorage, fsck

TESTS = os.path.dirname(os.path.abspath(__file__))
RUNS = ("a", "b", "c")


class FileCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.root = os.path.join(self.d, "store")
        self.log = os.path.join(self.root, "records.jsonl")

    def open(self, mode=ACK_ON_WRITE):
        return FileStorage(self.root, mode)


class TestContract(StorageContract, FileCase):
    def tear(self):
        with open(self.log, "r+b") as f:
            f.truncate(os.path.getsize(self.log) - 40)

    def damage(self, seq):
        with open(self.log, "rb") as f:
            lines = f.readlines()
        lines[seq] = lines[seq].replace(f'"t{seq}"'.encode(), f'"x{seq}"'.encode())
        with open(self.log, "wb") as f:
            f.writelines(lines)


class TestFileStorage(FileCase):
    def test_unreadable_middle_line_stops_open_and_fsck_reports_it(self):
        s = self.open()
        s.append_batch(Chain().batch(4))
        s.close()
        with open(self.log, "rb") as f:
            lines = f.readlines()
        lines[1] = lines[1][:30] + b"\n"
        with open(self.log, "wb") as f:
            f.writelines(lines)
        with self.assertRaisesRegex(StorageCorrupt, "line 2"):
            self.open()
        problems = fsck(self.root)
        self.assertTrue(problems[0].startswith("records.jsonl line 2: unreadable"), problems)

    def test_unreadable_witness_queue_is_corrupt(self):
        s = self.open()
        s.witness_queue_put({})
        s.close()
        with open(os.path.join(self.root, "witness-queue.json"), "wb") as f:
            f.write(b"{")
        s = self.open()
        self.addCleanup(s.close)
        with self.assertRaisesRegex(StorageCorrupt, "witness-queue.json"):
            s.witness_queue()

    def test_registry_leaves_set_aside_are_the_last_lines(self):
        s = self.open()
        a, b = [bytes([1, i]) * 44 + b"a" for i in range(3)], [bytes([2, i]) * 44 + b"b" for i in range(2)]
        for tenant, leaf in (("acme", a[0]), ("beta", b[0]), ("acme", a[1]), ("acme", a[2]), ("beta", b[1])):
            s.registry_append(tenant, leaf)
        with self.assertRaises(StorageCorrupt):
            s.registry_set_aside({"acme": 1})   # beta's leaves follow acme's second
        s.registry_set_aside({"acme": 2, "beta": 1})
        self.assertEqual((list(s.registry_iter("acme")), list(s.registry_iter("beta"))), (a[:2], b[:1]))
        self.assertEqual(s.tail_state()["registry"]["acme"], (2, root([leaf_hash(x) for x in a[:2]])))
        self.assertEqual(s.torn[0]["log"], "registry.jsonl")
        s.close()
        s = self.open()
        self.addCleanup(s.close)
        self.assertEqual((list(s.registry_iter("acme")), s.registry_merkle("beta").size), (a[:2], 1))

    def test_registry_notes_are_indexed_not_kept(self):
        key, tree = b"k" * 32, registry_tree("acme")
        notes = [checkpoint.body("example.org/log/registry/x", n, bytes(32)) + "\n— example.org/log c2ln\n"
                 for n in (1, 2, 3)]
        s = FileStorage(self.root, snapshot_key=key)
        s.append_batch(Chain().batch(1))
        for n, note in enumerate(notes, 1):
            s.checkpoint_put(n, note, tree)
        self.assertEqual(s.notes[tree], [(1, 0), (2, 1), (3, 2)])   # line numbers in registry-notes.jsonl
        s.snapshot_put({})
        s.close()
        with open(file_storage._snapshots(self.root)[0][1], "rb") as f:
            self.assertNotIn(b"c2ln", f.read())
        s = FileStorage(self.root, snapshot_key=key)
        self.addCleanup(s.close)
        self.assertIsNotNone(s.snapshot)
        self.assertEqual((s.checkpoint_at(tree, 1), s.checkpoint_at(tree, 4), s.checkpoint_latest(tree)),
                         (notes[0], None, (3, notes[2])))

    def test_tile_outliving_lost_log_lines_is_rewritten(self):
        s = self.open()
        s.append_batch(Chain().batch(300))
        s.close()
        with open(self.log, "rb") as f:
            kept = f.readlines()[:250]
        with open(self.log, "wb") as f:
            f.writelines(kept)
        c = Chain()
        records = c.batch(250) + c.batch(50, ("other",))
        s = self.open()
        s.append_batch(records[250:])
        s.close()
        s = self.open()
        self.addCleanup(s.close)
        self.assertEqual(s.tail_state()["tree_root"], root(leaves(records)))
        self.assertEqual(s.tree.root_at(255), root(leaves(records[:255])))

    @unittest.skipIf(not os.path.isdir("/dev/fd"), "needs /dev/fd")
    def test_failed_open_releases_files(self):
        s = self.open()
        s.append_batch(Chain().batch(2))
        s.close()
        with open(self.log, "ab") as f:
            f.write(b"{}\n")
        before = len(os.listdir("/dev/fd"))
        with self.assertRaises(StorageCorrupt):
            self.open()
        self.assertEqual(len(os.listdir("/dev/fd")), before)

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_modes(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        s = self.open()
        self.addCleanup(s.close)
        s.append_batch(Chain().batch(256))
        for d, _, files in os.walk(self.root):
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o750, d)
            for f in files:
                self.assertEqual(os.stat(os.path.join(d, f)).st_mode & 0o777, 0o640, f)

    def test_one_writer(self):
        s = self.open()
        self.addCleanup(s.close)
        with self.assertRaises(OSError):
            self.open()

    def test_disk_errors_make_the_store_unavailable(self):
        s = self.open()
        self.addCleanup(s.close)
        c = Chain()
        with mock.patch("os.write", side_effect=OSError(errno.ENOSPC, "full")):
            with self.assertRaises(StorageUnavailable):
                s.append_batch(c.batch(1))
        with self.assertRaises(StorageUnavailable):
            s.append_batch(c.batch(1))

    def test_a_failed_batch_leaves_no_line_on_disk(self):
        s = self.open(ACK_ON_FSYNC)
        self.addCleanup(s.close)
        c = Chain()
        s.append_batch(c.batch(1))
        size = os.path.getsize(self.log)
        with mock.patch.object(file_storage, "_sync", side_effect=OSError(errno.EIO, "EIO")):
            with self.assertRaises(StorageUnavailable):
                s.append_batch(c.batch(2))   # every line written, then the sync fails
        self.assertEqual((os.path.getsize(self.log), len(s.log.offsets)), (size, 2))
        s.close()
        self.assertEqual(self.open(ACK_ON_FSYNC).tree.size, 1)

    def test_a_failed_background_sync_names_the_records_not_known_durable(self):
        s = self.open()
        self.addCleanup(s.close)
        c = Chain()
        s.append_batch(c.batch(2))
        self.assertTrue(wait_for(lambda: s.log.dirty_since is None and s.log.syncing_since is None, timeout=2))
        with mock.patch.object(file_storage, "_sync", side_effect=OSError(errno.EIO, "Input/output error")):
            s.append_batch(c.batch(1))
            self.assertTrue(wait_for(lambda: s._error, timeout=2))
        with self.assertRaises(StorageUnavailable) as cm:
            s.append_batch(c.batch(1))
        self.assertIn("records from seq 2 on are not known durable", str(cm.exception))

    def test_durability_modes(self):
        with mock.patch.object(file_storage, "_sync", wraps=file_storage._sync) as sync:
            s = self.open(ACK_ON_FSYNC)
            s.append_batch(Chain().batch(1))
            # only this store's log: another test's ack-on-write store may sync its own fd in the background meanwhile
            self.assertEqual([c for c in sync.call_args_list if c.args[0] == s.log.fd], [mock.call(s.log.fd, True)])
            s.close()
            sync.reset_mock()
            s = self.open(ACK_ON_WRITE)
            self.addCleanup(s.close)
            s.append_batch(Chain().batch(2)[1:])
            self.assertTrue(wait_for(lambda: mock.call(s.log.fd, False) in sync.call_args_list, timeout=2))
            self.assertNotIn(mock.call(s.log.fd, True), sync.call_args_list)

    @unittest.skipIf(os.name == "nt", "SIGKILL is POSIX")
    def test_kill_9_keeps_every_acknowledged_record(self):
        rng, expected, chain = random.Random(), [], Chain()
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([os.path.dirname(TESTS), TESTS])}
        for i in range(20):
            mode = (ACK_ON_WRITE, ACK_ON_FSYNC)[i % 2]
            p = subprocess.Popen([sys.executable, __file__, self.root, mode], stdout=subprocess.PIPE, env=env)
            first = p.stdout.readline()
            self.assertTrue(first, "the writer exited before its first ack")
            time.sleep(rng.uniform(0, 0.05))
            p.kill()
            acked = int((first + p.stdout.read()).split()[-1])
            p.wait()
            p.stdout.close()
            while len(expected) <= acked:
                expected += chain.batch(1, RUNS)
            s = self.open()
            try:
                self.assertEqual(list(s.iter_range(0, acked + 1)), expected[:acked + 1], f"round {i}")
            finally:
                s.close()
        self.assertEqual(fsck(self.root), [])


def _writer(root, mode):
    """Append random-sized batches forever, printing the last seq of each batch once append_batch returns."""
    s, c = FileStorage(root, mode), Chain()
    st = s.tail_state()
    c.seq, c.prev = st["tree_size"], st["prev_hash"]
    c.runs = {k: (r["run_seq"] + 1, r["head"]) for k, r in st["runs"].items()}
    while True:
        s.append_batch(c.batch(random.randint(1, 20), RUNS))
        sys.stdout.write(f"{c.seq - 1}\n")
        sys.stdout.flush()


if __name__ == "__main__":
    _writer(*sys.argv[1:])
