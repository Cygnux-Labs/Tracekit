"""Append-only RFC 6962 Merkle tree whose hashes are stored as tiles (tlog-tiles layout), so proofs for old leaves read a
few tiles instead of needing the whole tree in memory.

Tile (level L, index N, width w) holds w <= 256 consecutive hashes at tree height 8*L, starting at hash 256*N, as raw
concatenated 32-byte hashes. Full tiles (width 256) never change. The right edge of the tree (fewer than 256 hashes per
tile level) lives in memory; flush() writes it as partial tiles so Tree(store, size) can reopen the tree.

A tile store is any object with get(level, index, width) -> bytes or None and put(level, index, width, data)."""
import hashlib
import os

from . import _k, node_hash

H = 8  # tree levels per tile
W = 1 << H  # hashes in a full tile


class MemoryTileStore:
    def __init__(self):
        self.tiles = {}

    def get(self, level, index, width):
        return self.tiles.get((level, index, width))

    def put(self, level, index, width, data):
        self.tiles[(level, index, width)] = data


def write_durable(path, data):
    """Replace the file at `path` with `data`, on stable storage before it returns (the file, then its directory)."""
    with open(path + ".tmp", "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path + ".tmp", path)
    if os.name != "nt":   # Windows can't open a directory to sync it
        fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class DirTileStore:
    def __init__(self, root):
        self.root = root

    def _path(self, level, index, width):
        return os.path.join(self.root, str(level), f"{index}.{width}")

    def get(self, level, index, width):
        try:
            with open(self._path(level, index, width), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def put(self, level, index, width, data):
        p = self._path(level, index, width)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        write_durable(p, data)


def _reduce(hashes):
    """Root of a power-of-two run of sibling hashes."""
    while len(hashes) > 1:
        hashes = [node_hash(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


class Tree:
    def __init__(self, store, size=0, edge=None):
        """Open the tree of `size` leaves in `store`, whose right edge is `edge` or was written by the last flush()."""
        self.store, self.size = store, size
        self.edge = [] if edge is None else edge  # edge[L]: the hashes of the unfinished tile at level L
        while edge is None and size >> (H * len(self.edge)):
            c = size >> (H * len(self.edge))
            self.edge.append(self._read(len(self.edge), c // W, c % W) if c % W else [])

    def _read(self, level, index, width):
        data = self.store.get(level, index, width)
        if data is None or len(data) != 32 * width:
            raise ValueError(f"tile {level}/{index}.{width} missing or damaged")
        return [data[i:i + 32] for i in range(0, len(data), 32)]

    def append(self, leaf_hash):
        self.size += 1
        h, level = leaf_hash, 0
        while True:
            if level == len(self.edge):
                self.edge.append([])
            e = self.edge[level]
            e.append(h)
            if len(e) < W:
                return
            self.store.put(level, (self.size >> (H * level)) // W - 1, W, b"".join(e))
            h, self.edge[level] = _reduce(e), []
            level += 1

    def flush(self):
        for level, e in enumerate(self.edge):
            if e:
                self.store.put(level, (self.size >> (H * level)) // W, len(e), b"".join(e))

    def _node(self, height, index):
        """Hash of the complete subtree of the given height covering leaves index*2^height .. (index+1)*2^height - 1."""
        level, r = divmod(height, H)
        start = index << r
        n = start // W
        tile = self.edge[level] if n == (self.size >> (H * level)) // W else self._read(level, n, W)
        return _reduce(tile[start % W:start % W + (1 << r)])

    def _hash(self, lo, hi):
        """MTH(D[lo:hi]); lo is a multiple of the largest power of two below hi - lo, as in every RFC 6962 split."""
        n = hi - lo
        if n & (n - 1) == 0:
            h = n.bit_length() - 1
            return self._node(h, lo >> h)
        k = _k(n)
        return node_hash(self._hash(lo, lo + k), self._hash(lo + k, hi))

    def root_at(self, n):
        if not 0 <= n <= self.size:
            raise ValueError("tree size out of range")
        return self._hash(0, n) if n else hashlib.sha256(b"").digest()

    def root(self):
        return self.root_at(self.size)

    def inclusion_proof(self, index, tree_size):
        """PATH(index, D[tree_size]), RFC 6962 section 2.1.1."""
        if not 0 <= index < tree_size <= self.size:
            raise ValueError("leaf index or tree size out of range")
        path, lo, hi = [], 0, tree_size
        while hi - lo > 1:
            k = _k(hi - lo)
            if index < lo + k:
                path.append(self._hash(lo + k, hi))
                hi = lo + k
            else:
                path.append(self._hash(lo, lo + k))
                lo += k
        return path[::-1]

    def consistency_proof(self, old_size, new_size):
        """PROOF(old_size, D[new_size]), RFC 6962 section 2.1.2."""
        if not 0 < old_size <= new_size <= self.size:
            raise ValueError("bad sizes for a consistency proof")
        path, lo, hi, complete = [], 0, new_size, True
        while old_size != hi:
            k = _k(hi - lo)
            if old_size <= lo + k:
                path.append(self._hash(lo + k, hi))
                hi = lo + k
            else:
                path.append(self._hash(lo, lo + k))
                lo += k
                complete = False
        if not complete:
            path.append(self._hash(lo, hi))
        return path[::-1]
