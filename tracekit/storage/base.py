"""The storage interface the signer writes through (04-design §2.5). Backends: `file` (here), Postgres (M3).

A record log holds format v2 records in `seq` order (0, 1, 2, ...). Its Merkle tree has one leaf per record,
`0x00 ‖ record_hash` (RFC 6962), and its hashes live in tiles (`tracekit.merkle.tiles`) under the tree name
`RECORDS`. Each tenant also has a registry log of fixed-width binary leaves (§1.5), with a tree named
`registry_tree(tenant)`."""
import functools
import hashlib
import types

ACK_ON_WRITE, ACK_ON_FSYNC = "ack-on-write", "ack-on-fsync"
ZERO_HASH = "sha256:" + "0" * 64  # prev_hash of seq 0, run_prev_hash of run_seq 0
RECORDS = "records"


def registry_tree(tenant):
    return "registry-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:32]


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
