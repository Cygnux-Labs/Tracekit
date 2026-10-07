"""RFC 6962 / RFC 9162 Merkle tree: root, inclusion proofs, consistency proofs (generation and verification).

Leaves are hashed as SHA-256(0x00 || data), interior nodes as SHA-256(0x01 || left || right). All hashes are raw bytes.
Generation is the textbook recursive definition (RFC 6962 section 2.1); fine for logs of up to a few million entries."""
import hashlib


def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _k(n):
    """Largest power of two strictly less than n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves):
    """leaves: list of leaf hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _k(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(m, leaves):
    """PATH(m, D[n])."""
    n = len(leaves)
    if not 0 <= m < n:
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_proof(m, leaves[:k]) + [root(leaves[k:])]
    return inclusion_proof(m - k, leaves[k:]) + [root(leaves[:k])]


def consistency_proof(m, leaves):
    """PROOF(m, D[n]) for 0 < m <= n."""
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError("bad sizes for a consistency proof")

    def sub(m, d, complete):
        n = len(d)
        if m == n:
            return [] if complete else [root(d)]
        k = _k(n)
        if m <= k:
            return sub(m, d[:k], complete) + [root(d[k:])]
        return sub(m - k, d[k:], False) + [root(d[:k])]
    return sub(m, leaves, True)


def verify_inclusion(index, size, leaf, proof, expected_root):
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def verify_consistency(first, second, first_root, second_root, proof):
    """RFC 9162 section 2.1.4.2."""
    if first == 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    path = list(proof)
    if first & (first - 1) == 0:  # first is a power of two: its root is the first proof node implicitly
        path = [first_root] + path
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
