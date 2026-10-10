"""PostgreSQL (>= 14) storage, through psycopg 3 (`pip install 'tracekit-ai[postgres]'`). One log per schema: the DSN
picks the database, and its search_path the schema (`options=-csearch_path=tracekit`).

    tracekit_schema         the schema version row, written by migrate()
    tracekit_records        seq (primary key), tenant, run_id, run_seq (UNIQUE(tenant, run_id, run_seq)), hash, record
    tracekit_registry       tenant, idx, leaf: every tenant's registry log
    tracekit_notes          tree, size, note: every signed note of every tree (the latest row of a tree is its latest
                            note; a later row of the same size is that note cosigned, and replaces it)
    tracekit_anchors        size, anchor: each record tree note anchored in Rekor (the latest row of a size wins)
    tracekit_witness_queue  the witness publisher's state, one row
    tracekit_tiles          tree, level, idx, width, data
    tracekit_snapshots      size, mac, body: the indexes at a record tree size and the signer's state; the newest two
                            are kept
    tracekit_meta           key, value: what readers need without the signer's data dir ("log_vkey", the log key's vkey)

migrate() creates them (idempotent); run it as a migration role, `tracekit signer migrate --config signer.yaml`. The
signer's role needs no UPDATE or DELETE on the logs: records, registry, notes and anchors are insert-only, and fsck
finds a row edited behind the signer's back (hash, chains, signatures). GRANTS is the signer role's set.

Export, view and reveal read through PostgresReader, with the DSN of their own config's dsn_file: give it a role
holding READ_GRANTS only (SELECT), so a reader can't write even by mistake.

One writer per log: open takes a session-level advisory lock keyed by the schema, waiting up to `lock_timeout_s`, and
holds it on the connection every write goes through, so a lost connection loses the lock and the writes with it; a
second signer is refused naming the holder. Durability: ack-on-fsync commits with synchronous_commit on (the commit
returns once its WAL is flushed, and replicated when the server requires it); ack-on-write with synchronous_commit off
(the commit returns before its WAL is flushed; the server flushes it within 3 x wal_writer_delay, 200 ms by default, so a
server crash or power loss, never a signer crash, can lose the last records acknowledged in that window, leaving a
consistent prefix of the log). Notes, anchors, snapshots and the witness queue always commit with synchronous_commit
on, which also makes every record before them durable. A batch is one transaction: a failure leaves none of it. A
connection lost while a commit is in flight leaves its outcome unknown: the store answers StorageUnavailable and the
signer's reopen reads back what was committed.

There is no torn last line: a crash mid-transaction leaves nothing. Run and registry indexes and the trees' right edges
live in memory, as in the file store, rebuilt on open from the newest snapshot that still matches the log (else from
nothing) and the rows after it."""
import contextlib
import errno
import hashlib
import hmac
import json
import os
import threading
import time

import psycopg
from psycopg import errors

from tracekit.format.canon import event_hash
from tracekit.merkle import leaf_hash
from tracekit.merkle.tiles import W, Tree, _reduce

from .base import (ACK_ON_FSYNC, ACK_ON_WRITE, RECORDS, ZERO_HASH, Storage, StorageCorrupt, StorageUnavailable,
                   check_records, registry_tree)
from .file import _edge, _mac, _raw, _unedge
from .pg_schema import GRANTS, READ_GRANTS, SCHEMA, VERSION  # noqa: F401

PAGE = 1000
LOCK_CLASS = 0x746b   # the advisory lock's first key: "tk"


def read_dsn(section):
    """The DSN of a `postgres: {dsn_file}` config section: the file's content, or "" (the libpq PG* environment
    variables) without one."""
    path = section.get("dsn_file")
    if not path:
        return ""
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def _connect(dsn):
    try:
        return psycopg.connect(dsn, autocommit=True, application_name=f"tracekit-signer pid {os.getpid()}")
    except psycopg.OperationalError as e:
        raise StorageUnavailable(f"cannot connect to Postgres: {e}") from None


def migrate(dsn):
    """Create the tables, or check those of an earlier migrate(); returns the schema version."""
    with _connect(dsn) as conn, conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s, 0)", (LOCK_CLASS,))   # one migrate at a time
        conn.execute(SCHEMA)
        row = conn.execute("SELECT max(version) FROM tracekit_schema").fetchone()
        if row[0] is None:
            conn.execute("INSERT INTO tracekit_schema VALUES (%s)", (VERSION,))
        elif row[0] > VERSION:
            raise ValueError(f"the store's schema is version {row[0]}, newer than this tracekit's {VERSION}")
    return VERSION


def _check_version(conn):
    try:
        version = conn.execute("SELECT max(version) FROM tracekit_schema").fetchone()[0]
    except errors.UndefinedTable:
        version = None
    if version != VERSION:
        raise ValueError(f"the Postgres store's schema is version {version}, not {VERSION}: run "
                         "`tracekit signer migrate --config signer.yaml`")


def _where(conn):
    schema, db = conn.execute("SELECT current_schema(), current_database()").fetchone()
    return schema, f"schema {schema} of database {db}"


def _take(conn, timeout_s):
    """Take the log's advisory lock, waiting up to `timeout_s`; BlockingIOError names the holder."""
    schema, where = _where(conn)
    key = int.from_bytes(hashlib.sha256(schema.encode("utf-8")).digest()[:4], "big") & 0x7fffffff
    deadline = time.monotonic() + timeout_s
    while not conn.execute("SELECT pg_try_advisory_lock(%s, %s)", (LOCK_CLASS, key)).fetchone()[0]:
        if time.monotonic() >= deadline:
            holder = conn.execute(
                "SELECT a.application_name, a.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE "
                "l.locktype = 'advisory' AND l.granted AND l.database = (SELECT oid FROM pg_database WHERE datname = "
                "current_database()) AND l.classid = %s AND l.objid = %s AND l.objsubid = 2",
                (LOCK_CLASS, key)).fetchone()
            raise BlockingIOError(errno.EAGAIN, f"another signer holds {where}"
                                  + (f" ({holder[0]}, backend pid {holder[1]})" if holder else ""))
        time.sleep(0.05)


def _snapshot(conn, mac, body, key, counts):
    """The snapshot when its MAC under `key` holds (unchecked when `key` is None: fsck without the keys) and the store
    still holds what it covers (its last record, with that hash, and the registry leaves it counts), else None."""
    try:
        if key is not None and not hmac.compare_digest(mac.encode("ascii"), _mac(key, body.encode("utf-8"))):
            return None
        snap = json.loads(body)
        n = snap["size"]
        row = conn.execute("SELECT record FROM tracekit_records WHERE seq = %s", (n - 1,)).fetchone()
        if n < 1 or row is None or any(size > counts.get(t, 0) for t, size, _ in snap["registry"]):
            return None
        r = row[0]
        return snap if r["hash"] == snap["hash"] == event_hash(r["event"]) and r["event"]["seq"] == n - 1 else None
    except (ValueError, KeyError, TypeError, UnicodeEncodeError):
        return None


def _registry_counts(conn):
    return dict(conn.execute("SELECT tenant, count(*) FROM tracekit_registry GROUP BY tenant").fetchall())


class _Reads:
    """The reads PostgresStorage and PostgresReader share, through self.conn under self._lock."""
    _error = None

    @contextlib.contextmanager
    def _db(self):
        """The connection, under the store's lock; a lost connection or a server refusing writes is
        StorageUnavailable."""
        with self._lock:
            try:
                yield self.conn
            except psycopg.OperationalError as e:
                self._error = self._error or StorageUnavailable(str(e).strip() or type(e).__name__)
                raise StorageUnavailable(*self._error.args) from e

    def _pages(self, sql, params, after, hi=None):
        """The rows of `sql`, which takes the first column >= %(after)s and orders by it, read PAGE at a time (the lock
        is not held between pages); with `hi`, only those < hi."""
        while hi is None or after < hi:
            with self._db() as conn:
                rows = conn.execute(sql + " LIMIT %(page)s", {**params, "after": after, "page": PAGE}).fetchall()
            for row in rows:
                if hi is not None and row[0] >= hi:
                    return
                yield row
            if len(rows) < PAGE:
                return
            after = rows[-1][0] + 1

    def iter_run(self, tenant, run_id):
        run = self.runs.get((tenant, run_id))
        for _, r in self._pages("SELECT run_seq, record FROM tracekit_records WHERE tenant = %(t)s AND run_id = %(r)s "
                                "AND run_seq >= %(after)s ORDER BY run_seq", {"t": tenant, "r": run_id}, 0,
                                run["run_seq"] + 1 if run else 0):
            yield r

    def registry_iter(self, tenant, start=0):
        tree = self.registry.get(tenant)
        for _, leaf in self._pages("SELECT idx, leaf FROM tracekit_registry WHERE tenant = %(t)s AND idx >= %(after)s "
                                   "ORDER BY idx", {"t": tenant}, start, tree.size if tree else 0):
            yield bytes(leaf)

    def registry_merkle(self, tenant):
        return self.registry.get(tenant)

    def checkpoint_latest(self, tree=RECORDS):
        with self._db() as conn:
            row = conn.execute("SELECT size, note FROM tracekit_notes WHERE tree = %s ORDER BY id DESC LIMIT 1",
                               (tree,)).fetchone()
        return row and tuple(row)

    def checkpoint_at(self, tree, size):
        with self._db() as conn:
            row = conn.execute("SELECT note FROM tracekit_notes WHERE tree = %s AND size = %s ORDER BY id DESC LIMIT 1",
                               (tree, size)).fetchone()
        return row and row[0]

    def anchors(self):
        with self._db() as conn:
            anchors = [json.loads(a) for (a,) in conn.execute("SELECT anchor FROM tracekit_anchors ORDER BY id")]
        return list({a["size"]: a for a in anchors}.values())

    def tiles_get(self, tree, level, index, width):
        with self._db() as conn:
            row = conn.execute("SELECT data FROM tracekit_tiles WHERE tree = %s AND level = %s AND idx = %s AND "
                               "width = %s", (tree, level, index, width)).fetchone()
        return row and bytes(row[0])


class PostgresStorage(_Reads, Storage):
    def __init__(self, dsn, mode=ACK_ON_WRITE, lock_timeout_s=0, snapshot_key=None):
        """Another process holding the log's lock for `lock_timeout_s` raises BlockingIOError naming it. `snapshot_key`
        authenticates snapshots: without it none is read or written (set the attribute once the key exists)."""
        if mode not in (ACK_ON_WRITE, ACK_ON_FSYNC):
            raise ValueError(f"unknown durability mode {mode!r}")
        self.dsn, self.full, self.snapshot_key, self._error = dsn, mode == ACK_ON_FSYNC, snapshot_key, None
        self.torn = []   # a crash mid-transaction leaves nothing to set aside
        # lean: one connection, every read and write under one lock; a read pool if exports contend with the writer
        self._lock = threading.RLock()
        self.conn = _connect(dsn)
        try:
            with self._db():
                _check_version(self.conn)
                self.conn.execute("SET synchronous_commit = " + ("on" if self.full else "off"))
                _take(self.conn, lock_timeout_s)
                self._open()
        except BaseException:
            self.conn.close()
            raise

    def _open(self):
        # lean: run and registry indexes live in memory, O(runs + tenants); query them past millions of runs
        self.tree, self.prev, self.runs, self.registry, self.snapshot = Tree(self.tile_store(RECORDS)), ZERO_HASH, {}, {}, None
        counts = _registry_counts(self.conn)
        if self.snapshot_key:
            for mac, body in self.conn.execute("SELECT mac, body FROM tracekit_snapshots ORDER BY size DESC"):
                snap = _snapshot(self.conn, mac, body, self.snapshot_key, counts)
                if snap:
                    self._restore(snap)
                    break
        for seq, tenant, run_id, run_seq, h in self._pages(
                "SELECT seq, tenant, run_id, run_seq, hash FROM tracekit_records WHERE seq >= %(after)s ORDER BY seq",
                {}, self.tree.size):
            if seq != self.tree.size:
                raise StorageCorrupt(f"seq {seq} where {self.tree.size} was expected; run fsck")
            self._index(self.runs, tenant, run_id, run_seq, h)
        for tenant, count in counts.items():
            tree = self.registry.setdefault(tenant, Tree(self.tile_store(registry_tree(tenant))))
            for idx, leaf in self._pages("SELECT idx, leaf FROM tracekit_registry WHERE tenant = %(t)s AND idx >= "
                                         "%(after)s ORDER BY idx", {"t": tenant}, tree.size):
                if idx != tree.size:
                    raise StorageCorrupt(f"registry leaf {idx} of a tenant where {tree.size} was expected; run fsck")
                tree.append(leaf_hash(leaf))

    def _restore(self, snap):
        self.tree, self.prev = Tree(self.tile_store(RECORDS), snap["size"], _unedge(snap["edge"])), snap["hash"]
        self.runs = {(t, r): {"run_seq": n, "head": h, "count": c} for t, r, n, h, c in snap["runs"]}
        self.registry = {t: Tree(self.tile_store(registry_tree(t)), size, _unedge(edge))
                         for t, size, edge in snap["registry"]}
        self.snapshot = {k: snap[k] for k in ("size", "hash", "state")}

    def _index(self, runs, tenant, run_id, run_seq, h):
        run = runs.get((tenant, run_id)) or dict(self.runs.get((tenant, run_id)) or {"count": 0})
        runs[(tenant, run_id)] = {"run_seq": run_seq, "head": h, "count": run["count"] + 1}
        self.tree.append(leaf_hash(_raw(h)))
        self.prev = h

    @contextlib.contextmanager
    def _write(self, durable=False, *trees):
        """One transaction; `durable` commits with synchronous_commit on in either mode. The right edges of `trees` and
        the record log's head are put back when it fails."""
        if self._error:
            raise StorageUnavailable(*self._error.args)
        with self._db() as conn:
            saved = [(t, t.size, [list(e) for e in t.edge]) for t in trees], self.prev
            try:
                with conn.transaction():
                    if durable and not self.full:
                        conn.execute("SET LOCAL synchronous_commit = on")
                    yield conn
            except BaseException:
                for t, size, edge in saved[0]:
                    t.size, t.edge = size, edge
                self.prev = saved[1]
                raise

    def snapshot_put(self, state):
        if not (self.tree.size and self.snapshot_key):
            return
        body = json.dumps({
            "size": self.tree.size, "hash": self.prev, "edge": _edge(self.tree.edge),
            "runs": [[*k, r["run_seq"], r["head"], r["count"]] for k, r in self.runs.items()],
            "registry": [[t, tree.size, _edge(tree.edge)] for t, tree in self.registry.items()],
            "state": state}, separators=(",", ":"), ensure_ascii=False)
        mac = _mac(self.snapshot_key, body.encode("utf-8")).decode("ascii")
        with self._write(True) as conn:
            conn.execute("INSERT INTO tracekit_snapshots VALUES (%s, %s, %s) ON CONFLICT (size) DO UPDATE SET "
                         "mac = excluded.mac, body = excluded.body", (self.tree.size, mac, body))
            conn.execute("DELETE FROM tracekit_snapshots WHERE size NOT IN (SELECT size FROM tracekit_snapshots "
                         "ORDER BY size DESC LIMIT 2)")

    def append_batch(self, records):
        runs = {}
        with self._write(False, self.tree) as conn:
            for i, r in enumerate(records):
                if r["event"]["seq"] != self.tree.size + i:
                    raise ValueError(f"seq {r['event']['seq']} does not continue the log at {self.tree.size + i}")
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO tracekit_records VALUES (%s, %s, %s, %s, %s, %s)", [
                    (e["seq"], e["tenant"], e["run_id"], e["run_seq"], r["hash"],
                     json.dumps(r, separators=(",", ":"), ensure_ascii=False)) for r in records for e in [r["event"]]])
            for r in records:   # the full tiles they complete commit with them
                e = r["event"]
                self._index(runs, e["tenant"], e["run_id"], e["run_seq"], r["hash"])
        self.runs.update(runs)

    def tail_state(self):
        return {"seq": self.tree.size - 1 if self.tree.size else None, "prev_hash": self.prev,
                "tree_size": self.tree.size, "tree_root": self.tree.root(),
                "runs": {k: self.get_run(*k) for k in self.runs},
                "registry": {t: (tree.size, tree.root()) for t, tree in self.registry.items()}}

    def iter_range(self, lo, hi):
        for _, r in self._pages("SELECT seq, record FROM tracekit_records WHERE seq >= %(after)s ORDER BY seq", {},
                                max(lo, 0), min(hi, self.tree.size)):
            yield r

    def get_run(self, tenant, run_id):
        run = self.runs.get((tenant, run_id))
        return run and dict(run)

    def registry_append(self, tenant, leaf):
        tree = self.registry.get(tenant) or Tree(self.tile_store(registry_tree(tenant)))
        with self._write(False, tree) as conn:
            conn.execute("INSERT INTO tracekit_registry VALUES (%s, %s, %s)", (tenant, tree.size, leaf))
            tree.append(leaf_hash(leaf))
        self.registry[tenant] = tree

    def checkpoint_put(self, size, note, tree=RECORDS):
        latest = self.checkpoint_latest(tree)
        if latest and size < latest[0]:
            raise ValueError(f"a checkpoint of size {size} is older than the stored one of size {latest[0]}")
        with self._write(True) as conn:
            conn.execute("INSERT INTO tracekit_notes (tree, size, note) VALUES (%s, %s, %s)", (tree, size, note))

    def witness_queue(self):
        with self._db() as conn:
            row = conn.execute("SELECT state FROM tracekit_witness_queue").fetchone()
        try:
            return json.loads(row[0]) if row else {}
        except ValueError as e:
            raise StorageCorrupt(f"tracekit_witness_queue: {e}; run fsck") from None

    def witness_queue_put(self, state):
        with self._write(True) as conn:
            conn.execute("INSERT INTO tracekit_witness_queue VALUES (1, %s) ON CONFLICT (id) DO UPDATE SET "
                         "state = excluded.state", (json.dumps(state, sort_keys=True),))

    def anchor_put(self, size, anchor):
        with self._write(True) as conn:
            conn.execute("INSERT INTO tracekit_anchors (size, anchor) VALUES (%s, %s)",
                         (size, json.dumps({"size": size, **anchor}, sort_keys=True)))

    def tiles_put(self, tree, level, index, width, data):
        """Within the caller's transaction when there is one (an append's full tiles commit with it)."""
        with self._db() as conn:
            conn.execute("INSERT INTO tracekit_tiles VALUES (%s, %s, %s, %s, %s) ON CONFLICT (tree, level, idx, width) "
                         "DO UPDATE SET data = excluded.data WHERE tracekit_tiles.data <> excluded.data",
                         (tree, level, index, width, data))

    def meta_put(self, key, value):
        with self._write(True) as conn:
            conn.execute("INSERT INTO tracekit_meta VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = "
                         "excluded.value", (key, value))

    def fsck(self):
        return fsck(self.dsn, self.snapshot_key)

    def close(self):
        with self._lock:
            self.conn.close()   # ends the session, and its advisory lock


class _EdgeTiles:
    """The stored tiles of tree `name`, read only. The signer stores full tiles only (a tree's right edge lives in its
    memory), so a partial tile is rebuilt from `leaves(lo, hi)` at level 0 and from the full tiles below it above;
    a leaf or tile missing makes it short, which Tree refuses."""

    def __init__(self, reader, name, leaves):
        self.reader, self.name, self.leaves = reader, name, leaves

    def get(self, level, index, width):
        if width == W:
            return self.reader.tiles_get(self.name, level, index, W)
        lo = index * W
        if level == 0:
            return b"".join(self.leaves(lo, lo + width))
        with self.reader._db() as conn:
            tiles = [bytes(d) for (d,) in conn.execute(
                "SELECT data FROM tracekit_tiles WHERE tree = %s AND level = %s AND width = %s AND idx >= %s AND idx < %s "
                "ORDER BY idx", (self.name, level - 1, W, lo, lo + width))]
        return b"".join(_reduce([t[i:i + 32] for i in range(0, len(t), 32)]) for t in tiles if len(t) == 32 * W)

    def put(self, level, index, width, data):
        raise PermissionError("a reader never writes tiles")


class PostgresReader(_Reads):
    """A read-only view of a Postgres store, safe while its signer writes: takes no lock and reads in one REPEATABLE
    READ, READ ONLY transaction, so it holds the store as it was when opened. Open one per export or view request,
    after reading the record note it uses, and close it. Its DSN's role needs SELECT only: READ_GRANTS.

    Offers what FileReader offers: iter_run, iter_range, get_run, `runs` (with `seqs`), `tree` (the record tree at its
    latest note's size), checkpoint_latest(), anchors(), registry_iter, registry_merkle (each tenant's registry tree at
    its latest note's size) and checkpoint_at; and meta(key), what the signer stored for readers ("log_vkey")."""

    @contextlib.contextmanager
    def _db(self):
        """The connection; any database error (a lost connection, a role missing a grant) is StorageUnavailable, which
        the readers' callers (export, view, reveal) report instead of failing with a traceback."""
        with self._lock:
            try:
                yield self.conn
            except psycopg.Error as e:
                raise StorageUnavailable(f"Postgres: {str(e).strip() or type(e).__name__}") from e

    def __init__(self, dsn):
        self._lock, self.conn, self.runs, self.registry, self.size = threading.RLock(), _connect(dsn), {}, {}, 0
        try:
            with self._db() as conn:
                conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                _check_version(conn)
                tenants = [t for (t,) in conn.execute("SELECT DISTINCT tenant FROM tracekit_registry")]
            # lean: the run index lives in memory, O(records) per open as FileReader's; query it past millions of runs
            for seq, tenant, run_id, run_seq, h in self._pages("SELECT seq, tenant, run_id, run_seq, hash FROM "
                                                               "tracekit_records WHERE seq >= %(after)s ORDER BY seq",
                                                               {}, 0):
                run = self.runs.setdefault((tenant, run_id), {"seqs": []})
                run["seqs"].append(seq)
                run["run_seq"], run["head"], self.size = run_seq, h, seq + 1
            self.tree = self._tree(RECORDS, "SELECT hash FROM tracekit_records WHERE seq >= %s AND seq < %s ORDER BY "
                                   "seq", (), lambda h: leaf_hash(_raw(h)))
            for t in tenants:
                self.registry[t] = self._tree(registry_tree(t), "SELECT leaf FROM tracekit_registry WHERE tenant = %s "
                                              "AND idx >= %s AND idx < %s ORDER BY idx", (t,), lambda b: leaf_hash(bytes(b)))
        except BaseException:
            self.conn.close()
            raise

    def _tree(self, name, sql, params, leaf):
        """Tree `name` at the size of its latest note, from its stored tiles."""
        def leaves(lo, hi):
            with self._db() as conn:
                return [leaf(x) for (x,) in conn.execute(sql, (*params, lo, hi))]
        return Tree(_EdgeTiles(self, name, leaves), (self.checkpoint_latest(name) or (0,))[0])

    def iter_range(self, lo, hi):
        for _, r in self._pages("SELECT seq, record FROM tracekit_records WHERE seq >= %(after)s ORDER BY seq", {},
                                max(lo, 0), min(hi, self.size)):
            yield r

    def get_run(self, tenant, run_id):
        run = self.runs.get((tenant, run_id))
        return run and {"run_seq": run["run_seq"], "head": run["head"], "count": len(run["seqs"])}

    def meta(self, key):
        with self._db() as conn:
            row = conn.execute("SELECT value FROM tracekit_meta WHERE key = %s", (key,)).fetchone()
        return row and row[0]

    def close(self):
        self.conn.close()


def fsck(dsn, snapshot_key=None, verify=None):
    """Check every row of a Postgres store, in one consistent snapshot of it, as the file store's fsck checks its lines:
    each record (base.check_records, `verify`) and that its columns match it, each tenant's registry leaves numbered
    0, 1, 2, ..., and every snapshot (one that no longer matches the log, or whose MAC under `snapshot_key` fails, is
    ignored on open). Takes no lock: safe while the signer runs."""
    with _connect(dsn) as conn, conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        _check_version(conn)
        cur = conn.cursor(name="tracekit_fsck")   # server-side: streams the log
        cur.execute("SELECT record::text FROM tracekit_records ORDER BY seq")
        problems = check_records((line for (line,) in cur), "records", verify)
        cur.close()
        rows = conn.execute(
            "SELECT n FROM (SELECT seq, tenant, run_id, run_seq, hash, record, row_number() OVER (ORDER BY seq) AS n "
            "FROM tracekit_records) r WHERE json_typeof(record) IS DISTINCT FROM 'object' OR json_typeof(record->'event') IS DISTINCT FROM 'object' "
            "OR hash IS DISTINCT FROM record->>'hash' OR seq::text IS DISTINCT FROM record->'event'->>'seq' "
            "OR tenant IS DISTINCT FROM record->'event'->>'tenant' OR run_id IS DISTINCT FROM record->'event'->>'run_id' "
            "OR run_seq::text IS DISTINCT FROM record->'event'->>'run_seq' ORDER BY n").fetchall()
        problems.extend(f"records line {n}: its columns do not match the record" for (n,) in rows)
        counts = _registry_counts(conn)
        for tenant, top in conn.execute("SELECT tenant, max(idx) FROM tracekit_registry GROUP BY tenant"):
            if top + 1 != counts[tenant]:
                problems.append(f"registry: the leaves of tenant {tenant[:64]!r} are not numbered 0 to {counts[tenant] - 1}")
        for size, mac, body in conn.execute("SELECT size, mac, body FROM tracekit_snapshots ORDER BY size"):
            if _snapshot(conn, mac, body, snapshot_key, counts) is None:
                problems.append(f"snapshots/{size}: does not match the log or its MAC, so open ignores it and replays "
                                "the log in full")
    return problems
