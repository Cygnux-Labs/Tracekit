"""The storage interface the signer writes through (04-design §2.5). Backends: `file` (here), Postgres (M3).

A record log holds format v2 records in `seq` order (0, 1, 2, ...). Its Merkle tree has one leaf per record,
`0x00 ‖ record_hash` (RFC 6962), and its hashes live in tiles (`tracekit.merkle.tiles`) under the tree name
`RECORDS`. Each tenant also has a registry log of fixed-width binary leaves (§1.5), with a tree named
`registry_tree(tenant)`."""
import base64
import functools
import hashlib
import types

ACK_ON_WRITE, ACK_ON_FSYNC = "ack-on-write", "ack-on-fsync"
ZERO_HASH = "sha256:" + "0" * 64  # prev_hash of seq 0, run_prev_hash of run_seq 0
RECORDS = "records"


def registry_tree(tenant):
    return "registry-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:32]


def check_records(lines, name, verify=None):
    """The problems of a record log given as its records' JSON texts in seq order (line n holds seq n - 1): strict JSON,
    record hash, the seq/prev_hash chain, each run's chain and, with `verify(record)` (raises ValueError), the
    signatures."""
    from tracekit.format.canon import event_hash, loads_strict   # not at import: v1 verification needs the stdlib only
    problems, prev, runs = [], ZERO_HASH, {}
    for n, line in enumerate(lines, 1):
        where = f"{name} line {n}"
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
        if verify:
            try:
                verify(r)
            except ValueError as x:
                problems.append(f"{where}: {x}")
        prev, runs[key] = r["hash"], (count + 1, r["hash"])
    return problems


def check_trees(records, registry, notes, tiles_get, partial=False):
    """The problems of the trees a store keeps, rebuilt from its logs: `records` [(seq, type, hash, log_id)] in seq
    order, `registry` {tenant: [leaf bytes]} in index order, `notes` [(tree, note)] the stored checkpoint notes and
    `tiles_get(tree, level, index, width)` the stored tiles. Each registry leaf points to a record with its seq, type,
    hash and log_id; each note is of its tree's root at its size; each stored full tile is its tree's. `partial`: the
    logs are what a running writer had written, so a note of a larger tree is not a problem."""
    from tracekit.format import registry as reg   # not at import: v1 verification needs the stdlib only
    from tracekit.merkle import leaf_hash
    from tracekit.merkle.tiles import MemoryTileStore, Tree
    # lean: the rebuilt trees and the record index are in memory, O(records); stream them per tile past ~100M records
    problems, trees = [], {RECORDS: Tree(MemoryTileStore())}
    for _, _, h, _ in records:
        trees[RECORDS].append(leaf_hash(bytes.fromhex(h[len("sha256:"):])))
    for tenant, leaves in registry.items():
        trees[registry_tree(tenant)] = tree = Tree(MemoryTileStore())
        for i, leaf in enumerate(leaves):
            tree.append(leaf_hash(leaf))
            try:
                typ, _, log_id, seq, h = reg.parse(leaf)
            except ValueError:
                typ = seq = None
            if not (type(seq) is int and seq < len(records) and records[seq][1:] == (typ, h, log_id)):
                problems.append(f"registry: leaf {i} of tenant {tenant[:64]!r} points to no record of the log with its "
                                "type and hash")
    for name, note in notes:
        tree = trees.get(name)
        try:
            size, root = note.split("\n")[1:3]
            size, root = int(size), base64.b64decode(root, validate=True)
        except ValueError:
            problems.append(f"notes: a note of {name} is unreadable")
            continue
        if tree is None or size > tree.size:
            if not partial:
                problems.append(f"notes: a note of {name} at size {size}, the log holds {tree.size if tree else 0}")
        elif tree.root_at(size) != root:
            problems.append(f"notes: the note of {name} at size {size} is not of the log's tree")
    for name, tree in trees.items():
        bad = [f"{level}/{i}" for (level, i, width), data in tree.store.tiles.items()
               if tiles_get(name, level, i, width) not in (None, data)]
        problems.extend(f"tiles: {name} tile {i} does not match the log" for i in bad)
    return problems


class StorageUnavailable(Exception):
    """The disk refused a write (EIO, ENOSPC); the signer answers `unavailable` until it is reopened."""


class StorageCorrupt(Exception):
    """A log can't be read as written: a damaged line before the tail, or a seq out of order."""


class Storage:
    torn = ()  # torn last lines (a write cut short by a crash) set aside on open: [{"log", "offset", "length", "path"}]
    snapshot = None  # the snapshot the store opened from: {"size", "hash" of record size-1, "state"}, or None
    snapshot_key = None  # the key authenticating snapshots; none are read or written without it

    def snapshot_put(self, state):
        """Store a snapshot of the indexes at the current tree size with `state` (JSON), the caller's state at that
        size, so the next open replays only the records after it. Call it with no append in flight."""

    def meta_put(self, key, value):
        """Store `value` (str) for the store's readers that can't read the signer's data dir (the log key's vkey under
        "log_vkey"); a store read through that dir (file) keeps none."""

    def append_batch(self, records):
        """Append v2 records whose seqs continue the log, with one write. Returns once written; with
        `ack-on-fsync` also once durable, with `ack-on-write` a background sync follows within 5 ms."""
        raise NotImplementedError

    def tail_state(self):
        """{"seq": last seq or None, "prev_hash": hash of the last record (ZERO_HASH if none), "tree_size",
        "tree_root" (bytes), "runs": {(tenant, run_id): get_run(...)}, "registry": {tenant: (size, root)}}."""
        raise NotImplementedError

    def iter_range(self, lo, hi):
        """Records with lo <= seq < hi, in order."""
        raise NotImplementedError

    def iter_run(self, tenant, run_id):
        """The run's records in run_seq order."""
        raise NotImplementedError

    def get_run(self, tenant, run_id):
        """{"run_seq": last run_seq, "head": its record hash, "count"}, or None for an unknown run."""
        raise NotImplementedError

    def registry_append(self, tenant, leaf):
        """Append one registry leaf (bytes) to the tenant's registry log."""
        raise NotImplementedError

    def registry_set_aside(self, keep):
        """Set aside, as a torn last line is, each tenant's registry leaves after its first keep[tenant]: leaves a
        power loss kept while it lost their records (the file store's ack-on-write). StorageCorrupt when they are not
        the last leaves written."""
        raise StorageCorrupt("registry leaves without their records")

    def registry_iter(self, tenant, start=0):
        """The tenant's registry leaves from index `start`, in order."""
        raise NotImplementedError

    def registry_merkle(self, tenant):
        """The tenant's registry Merkle tree (`merkle.tiles.Tree`: size, root_at, proofs), or None."""
        raise NotImplementedError

    def checkpoint_put(self, size, note, tree=RECORDS):
        """Store the signed checkpoint note (str) of `tree` (RECORDS or a registry_tree) at `size` as the latest;
        ValueError when an older stored note is of a larger tree. A note of the latest size replaces it (the same
        note with witness cosignatures added). The record tree keeps only its latest note, a registry tree every note
        (a run-set export proves consistency between two of them)."""
        raise NotImplementedError

    def checkpoint_latest(self, tree=RECORDS):
        """(size, note) of the latest stored checkpoint note of `tree`, or None."""
        raise NotImplementedError

    def checkpoint_at(self, tree, size):
        """The stored note of registry tree `tree` at `size`, or None."""
        raise NotImplementedError

    def witness_queue(self):
        """The witness publisher's persisted state (a JSON object), {} before the first witness_queue_put."""
        raise NotImplementedError

    def witness_queue_put(self, state):
        raise NotImplementedError

    def anchor_put(self, size, anchor):
        """Store the Rekor anchor (a JSON object with the anchored "note") of the record tree note at `size`."""
        raise NotImplementedError

    def anchors(self):
        """Every stored anchor, {"size", **anchor}, oldest first; the last one stored for each size."""
        raise NotImplementedError

    def tiles_get(self, tree, level, index, width):
        raise NotImplementedError

    def tiles_put(self, tree, level, index, width, data):
        raise NotImplementedError

    def unsynced_s(self):
        """Seconds the oldest written but not yet synced record has waited; 0 when everything written is durable."""
        return 0.0

    def fsck(self):
        """Full check of every log: a list of problems, empty when the store is intact."""
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def tile_store(self, tree):
        """A `merkle.tiles` tile store over this storage's tiles of `tree`."""
        return types.SimpleNamespace(get=functools.partial(self.tiles_get, tree),
                                     put=functools.partial(self.tiles_put, tree))
