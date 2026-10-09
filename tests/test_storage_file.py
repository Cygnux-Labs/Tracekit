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
from tracekit.merkle import root
from tracekit.storage import file as file_storage
from tracekit.storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, StorageCorrupt, StorageUnavailable
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

    def test_durability_modes(self):
        with mock.patch.object(file_storage, "_sync", wraps=file_storage._sync) as sync:
            s = self.open(ACK_ON_FSYNC)
            s.append_batch(Chain().batch(1))
            sync.assert_called_once_with(s.log.fd, True)
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
