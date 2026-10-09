"""Local-disk storage: append-only JSONL logs plus tile files under one directory (local disk only).

    lock                 held while open, so one process writes
    records.jsonl        one v2 record per line, seq order
    registry.jsonl       {"tenant", "leaf": hex} per line, every tenant's registry log
    checkpoint.note      the latest signed checkpoint note of the record tree, replaced whole
    registry-notes.jsonl {"tree", "size", "note"} per line, every signed note of every registry tree (a later line of
                         the same size is that note cosigned, and replaces it)
    witness-queue.json   the witness publisher's state, replaced whole
    anchors.jsonl        {"size", "note", "rekor", "tsa"} per line: each record tree note anchored in Rekor
    tiles/<tree>/<level>/<index>.<width>

Files are 0640 and directories 0750; creating or renaming a file syncs it and its directory. The run index and the
trees are rebuilt from the logs on open, rewriting any tile that no longer matches them (an ack-on-write tile can
outlive the log lines it covers after a power loss). `FileReader` reads a store while its writer runs."""
import contextlib
import errno
import json
import os
import re
import stat
import sys
import threading
import time

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

from tracekit.deploy.files import replace_retrying
from tracekit.format.canon import event_hash, loads_strict
from tracekit.locking import lock_file
from tracekit.merkle import leaf_hash
from tracekit.merkle.tiles import MemoryTileStore, Tree

from .base import (ACK_ON_FSYNC, ACK_ON_WRITE, RECORDS, ZERO_HASH, Storage, StorageCorrupt, StorageUnavailable,
                   registry_tree)

SYNC_INTERVAL = 0.005  # ack-on-write: the longest a written record waits for the background sync
_UNAVAILABLE = {errno.EIO, errno.ENOSPC}
_BINARY = getattr(os, "O_BINARY", 0)
NOTE = "checkpoint.note"
QUEUE = "witness-queue.json"
ANCHORS = "anchors.jsonl"


def _sync(fd, full):
    """full: to stable storage (F_FULLFSYNC on macOS); otherwise the background sync (F_BARRIERFSYNC on macOS)."""
    op = getattr(fcntl, "F_FULLFSYNC" if full else "F_BARRIERFSYNC", None) if sys.platform == "darwin" else None
    if op is not None:
        fcntl.fcntl(fd, op)
    else:
        getattr(os, "fdatasync", os.fsync)(fd)


def _sync_dir(path):
    if os.name == "nt":  # Windows can't open a directory to sync it
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir(path):
    if os.path.isdir(path):
        return
    parent = os.path.dirname(os.path.abspath(path))
    _mkdir(parent)
    os.mkdir(path, 0o750)
    os.chmod(path, 0o750)
    _sync_dir(parent)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _write_new(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o640)
    try:
        os.chmod(tmp, 0o640)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    replace_retrying(tmp, path)   # a FileReader may be reading the old file
    _sync_dir(os.path.dirname(path))


def _raw(h):
    return bytes.fromhex(h[len("sha256:"):])


class _Lines:
    """The complete lines of a file; offsets[i] is where line i starts and offsets[-1] where the last one ends."""

    def __init__(self, path, data):
        self.path = path
        self.lines = data[:data.rfind(b"\n") + 1].split(b"\n")[:-1]  # for the caller to index once, then dropped
        self.offsets = [0]
        for line in self.lines:
            self.offsets.append(self.offsets[-1] + len(line) + 1)

    def read(self, indices):
        with open(self.path, "rb") as f:
            for i in indices:
                f.seek(self.offsets[i])
                yield f.read(self.offsets[i + 1] - self.offsets[i])


class _Log(_Lines):
    """An append-only file of lines, open for writing."""

    def __init__(self, path, torn, on_sync):
        new = not os.path.exists(path)
        self.on_sync = on_sync
        self.synced = 0   # lines known durable; set on open and after each sync
        self.dirty_since = self.syncing_since = None   # monotonic time of the oldest line not yet synced
        self.fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | _BINARY, 0o640)
        try:
            if new:
                os.chmod(path, 0o640)
                _sync_dir(os.path.dirname(path))
            # lean: reads the whole log on open; replay a snapshot plus the tail once logs outgrow memory
            with open(path, "rb") as f:
                data = f.read()
            end = data.rfind(b"\n") + 1
            if end < len(data):
                aside = f"{path}.torn-{end}-{time.time_ns()}"
                _write_new(aside, data[end:])
                os.ftruncate(self.fd, end)
                os.fsync(self.fd)
                torn.append({"log": os.path.basename(path), "offset": end, "length": len(data) - end, "path": aside})
        except BaseException:
            os.close(self.fd)
            raise
        super().__init__(path, data)
        self.synced = len(self.lines)

    def append(self, lines, full):
        """All of `lines` or, when the write or sync fails, none: the file is cut back to where it ended."""
        end, n = self.offsets[-1], len(self.offsets)
        try:
            _write_all(self.fd, b"".join(lines))
            for line in lines:
                self.offsets.append(self.offsets[-1] + len(line))
            if full:
                self.sync(True)
        except BaseException:
            del self.offsets[n:]
            os.ftruncate(self.fd, end)
            raise
        if not full and self.dirty_since is None:
            self.dirty_since = time.monotonic()

    def sync(self, full):
        start = time.monotonic()
        _sync(self.fd, full)
        if self.on_sync:
            self.on_sync(time.monotonic() - start)


def _parse_note(data):
    note = data.decode("utf-8")
    return int(note.split("\n", 2)[1]), note


class _Records:
    """The run index and record tree over records.jsonl, and the registry trees and notes, shared by the writer and
    the reader."""

    def _index_log(self):
        for n, line in enumerate(self.log.lines, 1):
            try:
                self._index(json.loads(line))
            except (ValueError, KeyError, TypeError) as e:
                raise StorageCorrupt(f"records.jsonl line {n}: {e}; run fsck") from None
        del self.log.lines

    def _index_registry(self):
        self.registry, self.notes = {}, {}   # tenant -> ([line numbers], Tree); registry tree -> [(size, note)]
        for name, log in (("registry.jsonl", self.reg_log), ("registry-notes.jsonl", self.note_log)):
            for n, line in enumerate(log.lines):
                try:
                    r = json.loads(line)
                    if log is self.reg_log:
                        self._index_leaf(r["tenant"], bytes.fromhex(r["leaf"]), n)
                    else:
                        self._index_note(r["tree"], r["size"], r["note"])
                except (ValueError, KeyError, TypeError) as e:
                    raise StorageCorrupt(f"{name} line {n + 1}: {e}; run fsck") from None
            del log.lines
        del self.anchor_log.lines   # read on demand, by anchors()

    def _index_leaf(self, tenant, leaf, n):
        if tenant not in self.registry:
            self.registry[tenant] = ([], Tree(self._tiles(registry_tree(tenant))))
        lines, tree = self.registry[tenant]
        lines.append(n)
        tree.append(leaf_hash(leaf))

    def _index_note(self, tree, size, note):
        notes = self.notes.setdefault(tree, [])
        if notes and notes[-1][0] == size:
            notes[-1] = (size, note)
        else:
            notes.append((size, note))

    def registry_iter(self, tenant):
        lines, _ = self.registry.get(tenant, ([], None))
        for line in self.reg_log.read(list(lines)):
            yield bytes.fromhex(json.loads(line)["leaf"])

    def registry_merkle(self, tenant):
        return self.registry.get(tenant, (None, None))[1]

    def checkpoint_at(self, tree, size):
        return next((note for s, note in self.notes.get(tree, ()) if s == size), None)

    def anchors(self):
        # lean: reads every anchor per call (at most 24 a day); index anchors by size if exports become frequent
        return [json.loads(line) for line in self.anchor_log.read(range(len(self.anchor_log.offsets) - 1))]

    def _index(self, record):
        e = record["event"]
        if e["seq"] != self.tree.size:
            raise StorageCorrupt(f"seq {e['seq']} where {self.tree.size} was expected")
        run = self.runs.setdefault((e["tenant"], e["run_id"]), {"seqs": [], "run_seq": None, "head": None})
        run["seqs"].append(e["seq"])
        run["run_seq"], run["head"] = e["run_seq"], record["hash"]
        self.tree.append(leaf_hash(_raw(record["hash"])))
        self.prev = record["hash"]

    def iter_range(self, lo, hi):
        for line in self.log.read(range(max(lo, 0), min(hi, self.tree.size))):
            yield json.loads(line)

    def iter_run(self, tenant, run_id):
        run = self.runs.get((tenant, run_id))
        for line in self.log.read(list(run["seqs"]) if run else []):
            yield json.loads(line)

    def get_run(self, tenant, run_id):
        run = self.runs.get((tenant, run_id))
        return run and {"run_seq": run["run_seq"], "head": run["head"], "count": len(run["seqs"])}


class FileStorage(_Records, Storage):
    def __init__(self, root, mode=ACK_ON_WRITE, on_sync=None):
        """`on_sync(seconds)` is called after each sync of a log."""
        if mode not in (ACK_ON_WRITE, ACK_ON_FSYNC):
            raise ValueError(f"unknown durability mode {mode!r}")
        _mkdir(root)
        self.root, self.full, self._error = root, mode == ACK_ON_FSYNC, None
        self._lock = open(os.path.join(root, "lock"), "a+b")
        os.chmod(self._lock.name, 0o640)
        try:
            lock_file(self._lock, blocking=False)
        except OSError:
            self._lock.close()
            raise
        self.torn = []
        self.runs = {}  # (tenant, run_id) -> {"seqs": [...], "run_seq", "head"}
        # lean: run and registry indexes live in memory, O(records); snapshot them when logs reach millions of records
        self.tree = Tree(self.tile_store(RECORDS))
        self.prev = ZERO_HASH
        self.log = self.reg_log = self.note_log = self.anchor_log = None
        try:
            self.log = _Log(os.path.join(root, "records.jsonl"), self.torn, on_sync)
            self.reg_log = _Log(os.path.join(root, "registry.jsonl"), self.torn, on_sync)
            self.note_log = _Log(os.path.join(root, "registry-notes.jsonl"), self.torn, on_sync)
            self.anchor_log = _Log(os.path.join(root, ANCHORS), self.torn, on_sync)
            with self._disk():
                self._index_log()
                self._index_registry()
                try:
                    with open(os.path.join(root, NOTE), "rb") as f:
                        self._note = _parse_note(f.read())
                except FileNotFoundError:
                    self._note = None
        except BaseException:
            for log in (self.log, self.reg_log, self.note_log, self.anchor_log):
                if log:
                    os.close(log.fd)
            self._lock.close()
            raise
        self._stop = threading.Event()
        self._syncer = None
        if not self.full:
            self._syncer = threading.Thread(target=self._sync_loop, name="tracekit-storage-sync", daemon=True)
            self._syncer.start()

    @contextlib.contextmanager
    def _disk(self):
        if self._error:
            raise StorageUnavailable(*self._error.args)
        try:
            yield
        except OSError as e:
            if e.errno not in _UNAVAILABLE:
                raise
            self._error = StorageUnavailable(os.strerror(e.errno))
            raise StorageUnavailable(*self._error.args) from e

    def _sync_loop(self):
        while not self._stop.wait(SYNC_INTERVAL):
            # registry leaves first: a leaf is appended after its record, so every leaf synced has its record synced
            for log in (self.reg_log, self.log):
                if log.dirty_since is not None:
                    log.syncing_since, log.dirty_since = log.dirty_since, None
                    n = len(log.offsets) - 1
                    try:
                        log.sync(False)
                        log.synced = n
                    except OSError as e:
                        what = "records from seq" if log is self.log else "registry leaves from line"
                        self._error = StorageUnavailable(f"background sync failed ({e.strerror or e}): {what} "
                                                         f"{log.synced} on are not known durable")
                    log.syncing_since = None

    def unsynced_s(self):
        since = [t for log in (self.log, self.reg_log) for t in (log.syncing_since, log.dirty_since) if t is not None]
        return time.monotonic() - min(since) if since else 0.0

    def _tiles(self, tree):
        return self.tile_store(tree)

    def append_batch(self, records):
        with self._disk():
            for i, r in enumerate(records):
                if r["event"]["seq"] != self.tree.size + i:
                    raise ValueError(f"seq {r['event']['seq']} does not continue the log at {self.tree.size + i}")
            lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n" for r in records]
            self.log.append(lines, self.full)
            for r in records:
                self._index(r)

    def tail_state(self):
        return {"seq": self.tree.size - 1 if self.tree.size else None, "prev_hash": self.prev,
                "tree_size": self.tree.size, "tree_root": self.tree.root(),
                "runs": {k: self.get_run(*k) for k in self.runs},
                "registry": {t: (tree.size, tree.root()) for t, (_, tree) in self.registry.items()}}

    def registry_append(self, tenant, leaf):
        line = json.dumps({"tenant": tenant, "leaf": leaf.hex()}, ensure_ascii=False).encode("utf-8") + b"\n"
        with self._disk():
            self.reg_log.append([line], self.full)
            self._index_leaf(tenant, leaf, len(self.reg_log.offsets) - 2)

    def checkpoint_put(self, size, note, tree=RECORDS):
        latest = self.checkpoint_latest(tree)
        if latest and size < latest[0]:
            raise ValueError(f"a checkpoint of size {size} is older than the stored one of size {latest[0]}")
        with self._disk():
            if tree == RECORDS:
                _sync(self.log.fd, True)   # the records a note covers are durable before the note
                _write_new(os.path.join(self.root, NOTE), note.encode("utf-8"))
                self._note = (size, note)
            else:
                _sync(self.reg_log.fd, True)
                line = json.dumps({"tree": tree, "size": size, "note": note}, ensure_ascii=False).encode("utf-8")
                self.note_log.append([line + b"\n"], True)
                self._index_note(tree, size, note)

    def checkpoint_latest(self, tree=RECORDS):
        return self._note if tree == RECORDS else (self.notes.get(tree) or [None])[-1]

    def witness_queue(self):
        try:
            with open(os.path.join(self.root, QUEUE), "rb") as f:
                return json.loads(f.read())
        except FileNotFoundError:
            return {}
        except ValueError as e:
            raise StorageCorrupt(f"{QUEUE}: {e}; run fsck") from None

    def witness_queue_put(self, state):
        with self._disk():
            _write_new(os.path.join(self.root, QUEUE), json.dumps(state, sort_keys=True).encode("utf-8"))

    def anchor_put(self, size, anchor):
        line = json.dumps({"size": size, **anchor}, sort_keys=True).encode("utf-8") + b"\n"
        with self._disk():
            self.anchor_log.append([line], True)

    def _tile_path(self, tree, level, index, width):
        if not re.fullmatch(r"[a-z0-9-]{1,64}", tree):
            raise ValueError(f"bad tree name {tree!r}")
        return os.path.join(self.root, "tiles", tree, str(level), f"{index}.{width}")

    def tiles_get(self, tree, level, index, width):
        try:
            with open(self._tile_path(tree, level, index, width), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def tiles_put(self, tree, level, index, width, data):
        if self.tiles_get(tree, level, index, width) == data:
            return
        p = self._tile_path(tree, level, index, width)
        with self._disk():
            _mkdir(os.path.dirname(p))
            _write_new(p, data)

    def fsck(self):
        return fsck(self.root)

    def close(self):
        if self._lock.closed:
            return
        self._stop.set()
        if self._syncer:
            self._syncer.join()
        for log in (self.log, self.reg_log, self.note_log, self.anchor_log):
            with contextlib.suppress(OSError):
                _sync(log.fd, True)
            os.close(log.fd)
        self._lock.close()


class FileReader(_Records):
    """A read-only view of a file store, safe while its writer appends: takes no lock, opens files read-only and never
    writes. It holds the records that were complete when it was opened (a partial last line is the writer mid-append,
    so it stops before it) and sees every checkpoint note written since. On POSIX it refuses a store whose directory or
    files are symlinks, writable by group or others, or owned by another user than the directory.

    Offers what `bundle_v2.export` reads: iter_run, iter_range, get_run, `runs`, `tree` (size, root_at, inclusion
    proofs), checkpoint_latest(), anchors(), and the registry: registry_iter, registry_merkle and checkpoint_at.
    Registry leaves, notes and anchors are those written when it was opened; open it after reading the record note an
    export uses."""

    def __init__(self, root):
        self.root, self.runs, self.prev = root, {}, ZERO_HASH
        st = os.lstat(root)
        self._owner = st.st_uid
        self._check(root, st, stat.S_ISDIR)
        # lean: rebuilds the trees in memory from every leaf, O(records) per open; read the tiles once views stay open
        self.tree = Tree(MemoryTileStore())
        self.log, self.reg_log, self.note_log, self.anchor_log = (self._lines(n) for n in (
            "records.jsonl", "registry.jsonl", "registry-notes.jsonl", ANCHORS))
        self._index_log()
        self._index_registry()

    def _lines(self, name):
        path = os.path.join(self.root, name)
        try:
            return _Lines(path, self._read(path))
        except FileNotFoundError:
            if name == "records.jsonl":
                raise
            return _Lines(path, b"")   # not created yet: the writer creates it on open

    def _tiles(self, tree):
        return MemoryTileStore()

    def _check(self, path, st, kind):
        if not kind(st.st_mode) or os.name == "posix" and (st.st_mode & 0o022 or st.st_uid != self._owner):
            raise PermissionError(f"{path}: not a file of the store's owner, or writable by group or others")

    def _read(self, path):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY)
        with os.fdopen(fd, "rb") as f:
            self._check(path, os.fstat(fd), stat.S_ISREG)
            return f.read()

    def checkpoint_latest(self, tree=RECORDS):
        """The record tree's note is read again on every call: the writer replaces it whole, so each call sees the
        newest one. It may be of a larger tree than the records this reader holds; open a new reader to cover it."""
        if tree != RECORDS:
            return (self.notes.get(tree) or [None])[-1]
        for i in range(20):
            try:
                return _parse_note(self._read(os.path.join(self.root, NOTE)))
            except FileNotFoundError:
                return None
            except PermissionError:   # Windows: the writer is replacing the note this instant
                if os.name != "nt" or i == 19:
                    raise
                time.sleep(0.05)


def fsck(root):
    """Check every line of a file store: strict JSON, record hash, the seq/prev_hash chain and each run's chain.
    Returns the problems found, empty when the store is intact."""
    problems = []

    def lines(name):
        try:
            with open(os.path.join(root, name), "rb") as f:
                parts = f.read().split(b"\n")
        except FileNotFoundError:
            return []
        if parts[-1]:
            problems.append(f"{name}: torn last line ({len(parts[-1])} bytes)")
        return parts[:-1]

    prev, runs = ZERO_HASH, {}
    for n, line in enumerate(lines("records.jsonl"), 1):
        where = f"records.jsonl line {n}"
        try:
            r = loads_strict(line)
            e = r["event"]
            intact = r["hash"] == event_hash(e)
            key = (e.get("tenant"), e.get("run_id"))
        except (ValueError, KeyError, TypeError, AttributeError) as x:
            problems.append(f"{where}: unreadable ({x})")
            continue
        if not intact:
            problems.append(f"{where}: hash does not match the event")
        if e.get("seq") != n - 1 or e.get("prev_hash") != prev:
            problems.append(f"{where}: breaks the log chain")
        count, head = runs.get(key, (0, ZERO_HASH))
        if e.get("run_seq") != count or e.get("run_prev_hash") != head:
            problems.append(f"{where}: breaks the chain of run {key[1]!r}")
        prev, runs[key] = r["hash"], (count + 1, r["hash"])
    for n, line in enumerate(lines("registry.jsonl"), 1):
        try:
            r = loads_strict(line)
            bytes.fromhex(r["leaf"])
            if not isinstance(r["tenant"], str):
                raise TypeError("tenant is not a string")
        except (ValueError, KeyError, TypeError) as x:
            problems.append(f"registry.jsonl line {n}: unreadable ({x})")
    return problems
