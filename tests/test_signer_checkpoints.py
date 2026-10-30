"""Checkpoints of the v2 signer: the log key, signed notes (run.final, nudge, shutdown), the read-only store reader and
`tracekit export --v2` (the dev end to end is in test_signer_dev)."""
import contextlib
import io
import json
import os
import threading
import unittest
import zipfile
from unittest import mock

import pytest

from factories import wait_for
from storage_contract import Chain
from test_signer_service import ME, tmpdir
from tracekit import cli, crypto
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.signer import service as svc
from tracekit.storage import file as file_storage
from tracekit.storage.file import FileReader, FileStorage
from tracekit.verify import v2


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Notes(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = self.open()

    def open(self):
        s = svc.SignerService(self.dir, grace_s=0)
        self.addCleanup(s.close)
        return s

    def call(self, method, req):
        return self.s.call(ME, method, {"request_id": os.urandom(8).hex(), **req})

    def latest(self):
        return self.s.log.storage.checkpoint_latest()

    def size(self):
        return self.s.log.storage.tail_state()["tree_size"]

    def test_note_after_run_final_and_on_nudge_never_smaller(self):
        out = self.call("register_run", {"agent": {"name": "a"}})
        run = {"run_id": out["run_id"], "run_token": out["run_token"]}
        self.assertEqual(self.s.call(ME, "checkpoint_nudge", {}), {"scheduled": True})
        self.assertTrue(wait_for(lambda: self.latest() and self.latest()[0] == self.size(), 5))
        first = self.latest()
        self.call("close_run", run)
        self.s.sweep()
        final = self.size()   # run.final is the last record
        self.assertTrue(wait_for(lambda: self.latest()[0] == final, 5))
        origin, size, root, _ = checkpoint.open_note(self.latest()[1], [self.s.vkey])
        self.assertEqual((origin, size, root), (self.s.origin, final, self.s.log.storage.tree.root_at(final)))
        self.assertGreater(final, first[0])

    def test_shutdown_note_survives_restart_and_log_key_is_stable(self):
        vkey, origin = self.s.vkey, self.s.origin
        self.s.close()
        self.s = self.open()
        self.assertEqual(self.latest()[0], self.size())   # written on close, read back on start
        self.assertEqual((self.s.vkey, self.s.origin), (vkey, origin))
        self.assertTrue(origin.startswith("tracekit.local/"))
        keys = os.path.join(self.dir, "keys")
        with open(os.path.join(keys, "log.key"), "rb") as f, open(os.path.join(keys, "record.key"), "rb") as g:
            self.assertNotEqual(f.read(), g.read())
        if os.name == "posix":   # Windows has no permission bits
            self.assertEqual(os.stat(os.path.join(keys, "log.key")).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.join(self.dir, "log.vkey")).st_mode & 0o777, 0o644)
        self.assertEqual(svc.read_vkeys(self.dir), [vkey])

    def test_note_signed_by_another_key_fails(self):
        self.s.checkpoint()
        size, note = self.latest()
        text = note[:note.index("\n\n") + 1]
        forged = text + "\n" + checkpoint.sign(text, self.s.origin, crypto.generate()[0])
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"], "witnesses_required": 0}, f)
        signer_run = self.s.log.storage.iter_range(0, 1).__next__()["event"]["run_id"]
        out = os.path.join(self.dir, "forged.tkb")
        export(self.s.log.storage, "tracekit", signer_run, forged, out)
        rep, code = v2.verify(out, trust)
        self.assertEqual(rep.integrity, "FAILED")
        self.assertIn("checkpoint", [c["check"] for c in rep.checks if c["status"] == "fail"])


class Reader(unittest.TestCase):
    def setUp(self):
        self.root = os.path.join(tmpdir(self), "store")
        self.store = FileStorage(self.root)
        self.addCleanup(self.store.close)
        self.records = Chain().batch(5)
        self.store.append_batch(self.records)

    def snapshot(self):
        out = {}
        for d, _, names in os.walk(self.root):
            for n in names:
                p = os.path.join(d, n)
                with open(p, "rb") as f:   # Windows refuses reads of the writer's locked lock file
                    out[p] = (b"" if n == "lock" else f.read(), os.stat(p).st_mtime_ns)
        return out

    def test_partial_last_line_is_left_alone_and_nothing_is_modified(self):
        with open(os.path.join(self.root, "records.jsonl"), "ab") as f:
            f.write(b'{"v": 2, "event": {"seq": 5')   # the writer, mid-append
        before = self.snapshot()
        r = FileReader(self.root)   # while the writer holds the store lock
        self.assertEqual(list(r.iter_range(0, 100)), self.records)
        self.assertEqual(list(r.iter_run("acme", "run-1")), self.records)
        self.assertEqual((r.tree.size, r.tree.root()), (5, self.store.tree.root()))
        self.assertIsNone(r.checkpoint_latest())
        self.assertEqual(self.snapshot(), before)

    def test_sees_newer_notes(self):
        r = FileReader(self.root)
        note = checkpoint.body("example.org/log", 5, self.store.tree.root()) + "\n— example.org/log c2ln\n"
        self.store.checkpoint_put(5, note)
        self.assertEqual(r.checkpoint_latest(), (5, note))

    def test_note_replaced_while_a_reader_reads_it(self):
        r, stop, seen, errors = FileReader(self.root), threading.Event(), [], []

        def read():
            while not stop.is_set():
                try:
                    seen.append(r.checkpoint_latest())
                except Exception as e:
                    errors.append(e)
                    return
        reader = threading.Thread(target=read)
        reader.start()
        try:
            for i in range(5, 105):
                self.store.checkpoint_put(i, checkpoint.body("example.org/log", i, self.store.tree.root()) + "\n")
        finally:
            stop.set()
            reader.join()
        self.assertEqual(errors, [])
        self.assertEqual(r.checkpoint_latest()[0], 104)
        self.assertTrue(all(n is None or 5 <= n[0] <= 104 for n in seen))

    def test_note_replace_retries_while_windows_denies_it(self):
        real, denied = os.replace, []

        def replace(src, dst):   # Windows: access denied while a reader still has dst open
            if not denied:
                denied.append(dst)
                raise PermissionError(13, "Access is denied", dst)
            return real(src, dst)
        note = checkpoint.body("example.org/log", 5, self.store.tree.root()) + "\n"
        with mock.patch.object(os, "name", "nt"), mock.patch.object(os, "replace", replace):
            self.store.checkpoint_put(5, note)
        self.assertEqual(len(denied), 1)
        self.assertEqual(FileReader(self.root).checkpoint_latest(), (5, note))

    def test_note_is_written_after_its_records_are_synced(self):
        calls = []   # full syncs only: the ack-on-write background syncer may run meanwhile
        sync, write = file_storage._sync, file_storage._write_new
        with mock.patch.object(file_storage, "_sync", lambda fd, full: full and calls.append(("sync", fd)) or sync(fd, full)), \
                mock.patch.object(file_storage, "_write_new", lambda p, d: calls.append(("note", p)) or write(p, d)):
            self.store.checkpoint_put(5, checkpoint.body("example.org/log", 5, self.store.tree.root()))
        self.assertEqual(calls, [("sync", self.store.log.fd), ("note", os.path.join(self.root, file_storage.NOTE))])

    def test_update_reads_only_what_was_appended_and_holds_what_a_new_reader_would(self):
        """tracekit view opened a new reader at every store change: 2.5 s and 1.2 GB for 400k records, every second
        while an agent wrote. update() reads the bytes appended since, and the reader then holds what a new one does,
        the key records (key_records, so an export reads no other record for them) and registry leaves included."""
        chain = Chain()
        chain.batch(5)   # the records setUp appended
        r = FileReader(self.root)
        self.store.append_batch([chain.next(type_="signer.epoch")] + chain.batch(3, runs=("run-2",)))
        self.store.registry_append("acme", b"leaf")
        with mock.patch.object(FileReader, "_index", autospec=True, side_effect=FileReader._index) as parsed:
            self.assertFalse(r.update())   # appended to: not written in place
        self.assertEqual([c.args[1]["event"]["seq"] for c in parsed.call_args_list], [5, 6, 7, 8])
        fresh = FileReader(self.root)
        self.assertEqual((r.tree.size, r.tree.root(), r.runs, r.key_seqs), (9, fresh.tree.root(), fresh.runs, [5]))
        self.assertEqual(r.key_records(9), [next(fresh.iter_range(5, 6))])
        self.assertEqual(r.key_records(5), [])
        self.assertEqual(r.registry_merkle("acme").root(), fresh.registry_merkle("acme").root())
        self.assertEqual(r.changed(), [])

    def test_an_edit_or_a_replaced_file_is_told_never_read_as_new_records(self):
        """A reader kept across store changes must not hold records the file no longer has: a file replaced, cut back
        or with its last line rewritten is StorageCorrupt (open a new reader), and an edit in place that keeps every
        line where it was is in changed(), the pieces of the file read again that differ (written to without growing:
        update() True when nothing was appended)."""
        path = os.path.join(self.root, "records.jsonl")
        with open(path, "rb") as f:
            orig = f.read()
        for label, data in (("cut back", orig[:orig.rindex(b"\n", 0, -1) + 1]),
                            ("its last line rewritten", orig[:-30] + b"x" * 29 + b"\n")):
            with self.subTest(label):
                r = FileReader(self.root)
                with open(path, "wb") as f:
                    f.write(data)
                with self.assertRaises(file_storage.StorageCorrupt):
                    r.update()
                with open(path, "wb") as f:
                    f.write(orig)
        if os.name == "posix":   # Windows refuses to rename over a file a reader holds open
            r = FileReader(self.root)
            os.replace(path, path + ".old")
            with open(path, "wb") as f:   # the same bytes in another file
                f.write(orig)
            with self.assertRaises(file_storage.StorageCorrupt):
                r.update()
        r = FileReader(self.root)
        st = os.stat(path)
        with open(path, "r+b") as f:   # a record's tool name, same length, in a line before the last
            f.write(orig.replace(b'"name":"Bash"', b'"name":"Bosh"', 1))
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1000))
        self.assertTrue(r.update())
        self.assertEqual(r.changed(), [(0, len(orig))])
        with mock.patch.object(file_storage, "PIECE", 64):   # pieces of 64 bytes: only the edited one differs
            r = FileReader(self.root)
            with open(path, "r+b") as f:
                data = f.read()
                pos = data.index(b'"name":"Bosh"') + len(b'"name":"B')
                f.seek(pos)
                f.write(b"u")
            self.assertEqual(r.changed(), [(pos // 64 * 64, pos // 64 * 64 + 64)])
            self.assertEqual(r.changed(pos + 64), [])   # from the piece after it on, as read

    def test_a_reader_read_anew_says_which_pieces_the_reader_before_read_otherwise(self):
        """A reader read anew took the file as it found it: bytes changed before it read them were what later readings
        were compared with. Read against the reader before, it says which of that reader's pieces differ, a whole one
        or the part of its last one that reader read, as it reads them; a file cut back differs from where it ends."""
        path = os.path.join(self.root, "records.jsonl")
        with mock.patch.object(file_storage, "PIECE", 256):
            old = FileReader(self.root)
            end = old.log.offsets[-1]
            self.assertEqual(FileReader(self.root, against=old).differs, [])   # the same bytes

            def poke(at):   # a letter of a signature
                with open(path, "r+b") as f:
                    f.seek(at)
                    b = f.read(1)
                    f.seek(at)
                    f.write(b"x" if b != b"x" else b"y")
            with open(path, "rb") as f:
                first = f.read().index(b'"sig":"') + 10
            poke(first)   # the first record's: a whole piece
            poke(end - 5)   # the last record's: in the last piece the reader before read, before where it ended
            self.assertEqual(FileReader(self.root, against=old).differs,
                             [(first // 256 * 256, first // 256 * 256 + 256), ((end - 5) // 256 * 256, end)])
            with open(path, "r+b") as f:
                f.truncate(end - 300)
            cut = FileReader(self.root, against=old)   # its last whole line is before end - 300
            self.assertEqual(cut.differs[-1], (cut.log.offsets[-1] // 256 * 256, end))

    @unittest.skipUnless(os.name == "posix", "modes and owners are POSIX")
    def test_refuses_a_file_others_may_write(self):
        os.chmod(os.path.join(self.root, "records.jsonl"), 0o666)
        with self.assertRaises(PermissionError):
            FileReader(self.root)


class ExportWithoutSigner(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.cfg = os.path.join(self.dir, "signer.yaml")
        with open(self.cfg, "w") as f:
            json.dump({"data_dir": ".", "socket": "nobody.sock", "tenant": "acme"}, f)

    @pytest.mark.unverified_bundles
    def test_note_newer_than_the_first_reader_still_exports(self):
        store, chain, key = FileStorage(os.path.join(self.dir, "store")), Chain(), crypto.generate()[0]
        self.addCleanup(store.close)

        def note():
            text = checkpoint.body("example.org/log", store.tree.size, store.tree.root())
            store.checkpoint_put(store.tree.size, text + "\n" + checkpoint.sign(text, "example.org/log", key))
        store.append_batch(chain.batch(3))
        note()
        opened = []

        def reader(root, against=None):
            r = FileReader(root, against)
            if not opened:   # the signer appends and writes a newer note after the first reader opened
                opened.append(r)
                store.append_batch(chain.batch(2, runs=("run-2",)))
                note()
            return r
        out = os.path.join(self.dir, "x.tkb")
        with mock.patch.object(file_storage, "FileReader", reader):
            code, stdout, err = run_cli("export", "--v2", "--run", "run-1", "--config", self.cfg, "-o", out, "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(stdout)["tree_size"], 5)
        # the summary says what verifier the bundle needs, which records made it need that one, and what verifier
        # checks all of it: a minimum, not the version that exported it (the manifest calls it verifier_version)
        self.assertEqual([json.loads(stdout)[k] for k in ("verifier_min_version", "raised_by",
                                                         "verifier_min_version_full")],
                         ["1.0.0", [], "1.0.0"])
        # a policy goes in only when cited_policies names it: an agent approval's decision or a run's incident (none)
        with zipfile.ZipFile(out) as z:
            self.assertFalse([n for n in z.namelist() if n.startswith("policies/")])

    def test_no_covering_note_and_no_signer_is_a_clear_error(self):
        store = FileStorage(os.path.join(self.dir, "store"))
        store.append_batch(Chain().batch(3))
        store.close()
        out = os.path.join(self.dir, "x.tkb")
        code, _, err = run_cli("export", "--v2", "--run", "run-1", "--config", self.cfg, "-o", out)
        self.assertEqual(code, 1)
        self.assertIn("no checkpoint covers run 'run-1' yet and no signer answered", err)
        self.assertFalse(os.path.exists(out))
        # a data dir names no socket: it says so, and never asks the dev signer, another signer, for a checkpoint
        with mock.patch("tracekit.sdk.client.Client", side_effect=AssertionError("asked a signer")):
            code, _, err = run_cli("export", "--v2", "--run", "run-1", "--tenant", "acme", "--data-dir", self.dir, "-o",
                                   out)
        self.assertEqual((code, err), (1, "tracekit export: no checkpoint covers run 'run-1' yet, and a data dir names no "
                                          "signer to ask for one: export again after its signer's next checkpoint, or "
                                          "with --config or --dev\n"))
        self.assertEqual(run_cli("export", "--v2", "--run", "run-1", "--data-dir", self.dir, "--dev", "-o", out)[0], 2)

    def test_export_says_where_a_v2_run_is(self):
        """`export --data-dir DIR --run R` without --v2 read a v1 ledger instead and said only "ledger is empty", as a
        plain `export` did on a v2-only setup; a data dir that doesn't exist got a raw [Errno 2]."""
        store = FileStorage(os.path.join(self.dir, "store"))
        store.append_batch(Chain().batch(3))
        store.close()
        out = os.path.join(self.dir, "x.tkb")
        with mock.patch("tracekit.sdk.client.Client", side_effect=AssertionError("asked a signer")):   # the v2 export
            code, _, err = run_cli("export", "--run", "run-1", "--tenant", "acme", "--data-dir", self.dir, "-o", out)
        self.assertEqual((code, err), (1, "tracekit export: no checkpoint covers run 'run-1' yet, and a data dir names no "
                                          "signer to ask for one: export again after its signer's next checkpoint, or "
                                          "with --config or --dev\n"))
        v1 = os.path.join(self.dir, "v1")
        with self.assertRaises(SystemExit) as got:
            run_cli("export", "--home", v1, "-o", out)
        self.assertEqual(str(got.exception), f"no v1 records in {os.path.join(v1, 'ledger', 'ledger.jsonl')}: a v2 "
                         "signer's runs export with tracekit export --v2 --run RUN_ID (tracekit last exports and verifies "
                         "the newest)")
        with mock.patch("tracekit.cli._export_v2", return_value=0) as v2:   # --dev names the dev signer's v2 store too
            self.assertEqual(run_cli("export", "--dev", "--run", "run-1", "-o", out)[0], 0)
        v2.assert_called_once()
        nope = os.path.join(self.dir, "nope")
        self.assertEqual(run_cli("export", "--v2", "--run", "run-1", "--data-dir", nope, "-o", out)[::2],
                         (1, f"tracekit export: no signer data dir at {nope}\n"))
        self.assertEqual(run_cli("signer", "trust", "--data-dir", nope, "-o", out)[::2],
                         (2, f"tracekit signer: no signer data dir at {nope}\n"))


if __name__ == "__main__":
    unittest.main()
