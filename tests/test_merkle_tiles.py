import hashlib
import random
import tempfile
import unittest

from tracekit.merkle import verify_consistency, verify_inclusion
from tracekit.merkle.tiles import DirTileStore, MemoryTileStore, Tree


# Reference: RFC 6962 section 2.1 written out literally over a list of leaf hashes.
def H(b):
    return hashlib.sha256(b).digest()


def leaf(i):
    return H(b"\x00" + i.to_bytes(8, "big"))


def split(n):
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def mth(d):
    if not d:
        return H(b"")
    if len(d) == 1:
        return d[0]
    k = split(len(d))
    return H(b"\x01" + mth(d[:k]) + mth(d[k:]))


def path(m, d):
    if len(d) == 1:
        return []
    k = split(len(d))
    if m < k:
        return path(m, d[:k]) + [mth(d[k:])]
    return path(m - k, d[k:]) + [mth(d[:k])]


def subproof(m, d, b):
    if m == len(d):
        return [] if b else [mth(d)]
    k = split(len(d))
    if m <= k:
        return subproof(m, d[:k], b) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def build(store, n):
    t = Tree(store)
    for i in range(n):
        t.append(leaf(i))
    return t


class TileTreeTest(unittest.TestCase):
    def check(self, t, leaves, rng, samples):
        for _ in range(samples):
            n = rng.randint(1, len(leaves))
            d = leaves[:n]
            r = mth(d)
            self.assertEqual(t.root_at(n), r)
            i = rng.randrange(n)
            p = t.inclusion_proof(i, n)
            self.assertEqual(p, path(i, d))
            self.assertTrue(verify_inclusion(i, n, leaves[i], p, r))
            m = rng.randint(1, n)
            c = t.consistency_proof(m, n)
            self.assertEqual(c, subproof(m, d, True))
            self.assertTrue(verify_consistency(m, n, mth(leaves[:m]), r, c))

    def test_random_sizes(self):
        rng = random.Random(6962)
        leaves = [leaf(i) for i in range(1300)]  # past five full level-0 tiles, so level-1 nodes come from the edge
        t = build(MemoryTileStore(), len(leaves))
        self.assertEqual(t.root_at(0), H(b""))
        self.assertEqual(t.root(), mth(leaves))
        self.check(t, leaves, rng, 400)

    def test_every_small_size(self):
        leaves = [leaf(i) for i in range(70)]
        t = build(MemoryTileStore(), len(leaves))
        for n in range(1, len(leaves) + 1):
            for i in range(n):
                self.assertEqual(t.inclusion_proof(i, n), path(i, leaves[:n]))
                self.assertEqual(t.consistency_proof(i + 1, n), subproof(i + 1, leaves[:n], True))

    def test_reopen_from_directory(self):
        rng = random.Random(9162)
        leaves = [leaf(i) for i in range(900)]
        with tempfile.TemporaryDirectory() as d:
            t = build(DirTileStore(d), 600)
            t.flush()
            t = Tree(DirTileStore(d), 600)
            for h in leaves[600:]:
                t.append(h)
            self.check(t, leaves, rng, 100)

    def test_out_of_range(self):
        t = build(MemoryTileStore(), 5)
        for bad in (lambda: t.root_at(6), lambda: t.inclusion_proof(5, 5), lambda: t.inclusion_proof(0, 6),
                    lambda: t.consistency_proof(0, 5), lambda: t.consistency_proof(4, 6), lambda: t.consistency_proof(5, 4)):
            self.assertRaises(ValueError, bad)

    def test_verifiers_reject_bad_proofs(self):
        leaves = [leaf(i) for i in range(13)]
        t, x, r13 = build(MemoryTileStore(), 13), H(b"x"), mth(leaves)
        for m in (4, 5):   # a power of two and not: the consistency verifier treats them differently
            p, c, rm = t.inclusion_proof(m, 13), t.consistency_proof(m, 13), mth(leaves[:m])
            self.assertTrue(verify_inclusion(m, 13, leaves[m], p, r13) and verify_consistency(m, 13, rm, r13, c))
            cases = {
                "index = size": verify_inclusion(13, 13, leaves[m], p, r13),
                "index > size": verify_inclusion(14, 13, leaves[m], p, r13),
                "size 0": verify_inclusion(0, 0, leaves[0], [], H(b"")),
                "inclusion proof one node too long": verify_inclusion(m, 13, leaves[m], p + [x], r13),
                "inclusion proof one node too short": verify_inclusion(m, 13, leaves[m], p[:-1], r13),
                "inclusion against a wrong root": verify_inclusion(m, 13, leaves[m], p, rm),
                "consistency from size 0": verify_consistency(0, 13, H(b""), r13, c),
                "consistency proof one node too long": verify_consistency(m, 13, rm, r13, c + [x]),
                "consistency proof one node too short": verify_consistency(m, 13, rm, r13, c[:-1]),
                "first == second with a proof": verify_consistency(13, 13, r13, r13, [x]),
                "first > second": verify_consistency(13, m, r13, rm, c),
                "wrong first root": verify_consistency(m, 13, x, r13, c),
                "wrong second root": verify_consistency(m, 13, rm, x, c),
            }
            for why, ok in cases.items():
                with self.subTest(m=m, case=why):
                    self.assertFalse(ok)

    def test_million_leaves(self):
        n = 10 ** 6
        rng = random.Random(n)
        leaves = [leaf(i) for i in range(n)]
        t = build(MemoryTileStore(), n)
        sizes = [n, n - 1, 1 << 16, 65537, rng.randint(1, n)]
        roots = {s: mth(leaves[:s]) for s in sizes}
        for s, r in roots.items():
            self.assertEqual(t.root_at(s), r)
        for _ in range(20):
            s = rng.choice(sizes)
            i = rng.randrange(s)
            self.assertTrue(verify_inclusion(i, s, leaves[i], t.inclusion_proof(i, s), roots[s]))
            m = rng.choice([x for x in sizes if x <= s])
            self.assertTrue(verify_consistency(m, s, roots[m], roots[s], t.consistency_proof(m, s)))


if __name__ == "__main__":
    unittest.main()
