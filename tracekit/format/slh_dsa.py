"""SLH-DSA-SHA2-128s (FIPS 205), pure mode with an empty context, in pure Python: the checkpoints' hybrid signature.

A public key is PK.seed ‖ PK.root (32 bytes), a secret key SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root (64 bytes), a signature
7856 bytes. Signing is hedged (fresh randomness per signature) and takes about a second; verifying, about a
millisecond. Names follow FIPS 205 §§5-10. tests/vectors/slh_dsa_note.json holds a signature by another implementation.
No stateful hash signatures (XMSS, LMS): a restored snapshot of a key would reuse one-time state."""
import hashlib
import hmac
import os
import struct

N, H, D, HP, A, K, LG_W = 16, 63, 7, 9, 12, 14, 4
W, LEN1, LEN2 = 1 << LG_W, 32, 3
LEN, PK_SIZE = LEN1 + LEN2, 2 * N
SIG_SIZE = N + K * (1 + A) * N + (H + D * LEN) * N
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)


def _adrs(layer, tree, type_, keypair=0, chain=0, hash_=0):
    """ADRS^c, the 22-byte compressed address SHA2 hashes."""
    return struct.pack(">BQBIII", layer, tree, type_, keypair, chain, hash_)


class _Ctx:
    """PK.seed's hashes: F, H, T_l and PRF are SHA-256(PK.seed ‖ 0^48 ‖ ADRS^c ‖ input) truncated to N bytes."""

    def __init__(self, pk_seed):
        self.pk_seed, self._seeded = pk_seed, hashlib.sha256(pk_seed + bytes(64 - N))

    def hash(self, adrs, data):
        h = self._seeded.copy()
        h.update(adrs + data)
        return h.digest()[:N]

    def chain(self, x, start, steps, layer, tree, keypair, i):
        for j in range(start, start + steps):
            x = self.hash(_adrs(layer, tree, WOTS_HASH, keypair, i, j), x)
        return x


def _base_2b(x, b, out_len):
    bits = int.from_bytes(x, "big") >> (len(x) * 8 - b * out_len)
    return [(bits >> (b * (out_len - 1 - i))) & ((1 << b) - 1) for i in range(out_len)]


def _wots_digits(msg):
    d = _base_2b(msg, LG_W, LEN1)
    csum = sum(W - 1 - x for x in d) << 4   # (8 - LEN2 * LG_W % 8) % 8
    return d + _base_2b(csum.to_bytes(2, "big"), LG_W, LEN2)


def _wots_pk(c, chains, layer, tree, keypair):
    return c.hash(_adrs(layer, tree, WOTS_PK, keypair), b"".join(chains))


def _xmss_tree(c, sk_seed, layer, tree):
    """Every level of an XMSS tree, leaves first."""
    leaves = []
    for kp in range(1 << HP):
        chains = [c.chain(c.hash(_adrs(layer, tree, WOTS_PRF, kp, i), sk_seed), 0, W - 1, layer, tree, kp, i)
                  for i in range(LEN)]
        leaves.append(_wots_pk(c, chains, layer, tree, kp))
    return _levels(c, leaves, lambda z, i: _adrs(layer, tree, TREE, 0, z, i))


def _levels(c, nodes, adrs):
    levels = [nodes]
    for z in range(1, len(nodes).bit_length()):
        prev = levels[-1]
        levels.append([c.hash(adrs(z, i), prev[2 * i] + prev[2 * i + 1]) for i in range(len(prev) // 2)])
    return levels


def _auth(levels, idx, offset=0):
    return b"".join(levels[j][((idx >> j) ^ 1) + (offset >> j)] for j in range(len(levels) - 1))


def _root_from_path(c, node, idx, auth, adrs):
    """The root over `node` at leaf `idx` with authentication path `auth`; adrs(z, i) names node i at height z."""
    for k in range(len(auth) // N):
        sib = auth[k * N:(k + 1) * N]
        node = c.hash(adrs(k + 1, idx >> 1), sib + node if idx & 1 else node + sib)
        idx >>= 1
    return node


def _xmss_pk_from_sig(c, idx, sig, msg, layer, tree):
    digits = _wots_digits(msg)
    chains = [c.chain(sig[i * N:(i + 1) * N], digits[i], W - 1 - digits[i], layer, tree, idx, i) for i in range(LEN)]
    node = _wots_pk(c, chains, layer, tree, idx)
    return _root_from_path(c, node, idx, sig[LEN * N:], lambda z, i: _adrs(layer, tree, TREE, 0, z, i))


def _split(digest):
    md, t, leaf = digest[:21], digest[21:28], digest[28:30]
    return md, int.from_bytes(t, "big") & ((1 << (H - HP)) - 1), int.from_bytes(leaf, "big") & ((1 << HP) - 1)


def _h_msg(r, pk_seed, pk_root, msg):
    """MGF1-SHA-256 to 30 bytes: one block."""
    return hashlib.sha256(r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + msg).digest() + bytes(4)).digest()[:30]


def _fors_pk_from_sig(c, sig, md, tree, keypair):
    roots = []
    for i, x in enumerate(_base_2b(md, A, K)):
        part = sig[i * (A + 1) * N:(i + 1) * (A + 1) * N]
        node = c.hash(_adrs(0, tree, FORS_TREE, keypair, 0, (i << A) + x), part[:N])
        roots.append(_root_from_path(c, node, (i << A) + x, part[N:],
                                     lambda z, j: _adrs(0, tree, FORS_TREE, keypair, z, j)))
    return c.hash(_adrs(0, tree, FORS_ROOTS, keypair), b"".join(roots))


def keygen(seed=None):
    """(secret key, public key); `seed`: SK.seed ‖ SK.prf ‖ PK.seed (48 bytes), random by default."""
    seed = seed or os.urandom(3 * N)
    sk_seed, sk_prf, pk_seed = seed[:N], seed[N:2 * N], seed[2 * N:]
    root = _xmss_tree(_Ctx(pk_seed), sk_seed, D - 1, 0)[-1][0]
    return sk_seed + sk_prf + pk_seed + root, pk_seed + root


def public(sk):
    return sk[2 * N:]


def sign(sk, msg):
    """The signature of `msg` by secret key `sk`."""
    sk_seed, sk_prf, pk_seed, pk_root = (sk[i * N:(i + 1) * N] for i in range(4))
    msg = b"\0\0" + msg   # pure mode, empty context
    c = _Ctx(pk_seed)
    r = hmac.new(sk_prf, os.urandom(N) + msg, "sha256").digest()[:N]
    md, tree, leaf = _split(_h_msg(r, pk_seed, pk_root, msg))
    out = [r]
    for i, x in enumerate(_base_2b(md, A, K)):
        leaves = [c.hash(_adrs(0, tree, FORS_TREE, leaf, 0, (i << A) + j),
                         c.hash(_adrs(0, tree, FORS_PRF, leaf, 0, (i << A) + j), sk_seed)) for j in range(1 << A)]
        levels = _levels(c, leaves, lambda z, j, i=i: _adrs(0, tree, FORS_TREE, leaf, z, (i << (A - z)) + j))
        out += [c.hash(_adrs(0, tree, FORS_PRF, leaf, 0, (i << A) + x), sk_seed), _auth(levels, x)]
    node = _fors_pk_from_sig(c, b"".join(out[1:]), md, tree, leaf)
    for layer in range(D):
        levels = _xmss_tree(c, sk_seed, layer, tree)
        digits = _wots_digits(node)
        out += [c.chain(c.hash(_adrs(layer, tree, WOTS_PRF, leaf, i), sk_seed), 0, digits[i], layer, tree, leaf, i)
                for i in range(LEN)]
        out.append(_auth(levels, leaf))
        node = levels[-1][0]
        leaf, tree = tree & ((1 << HP) - 1), tree >> HP
    return b"".join(out)


def verify(pk, msg, sig):
    """Whether `sig` is a valid signature of `msg` under public key `pk`."""
    if len(pk) != 2 * N or len(sig) != SIG_SIZE:
        return False
    pk_seed, pk_root = pk[:N], pk[N:]
    msg = b"\0\0" + msg
    c, r = _Ctx(pk_seed), sig[:N]
    md, tree, leaf = _split(_h_msg(r, pk_seed, pk_root, msg))
    fors_len = K * (A + 1) * N
    node = _fors_pk_from_sig(c, sig[N:N + fors_len], md, tree, leaf)
    xmss_len = (LEN + HP) * N
    for layer in range(D):
        part = sig[N + fors_len + layer * xmss_len:N + fors_len + (layer + 1) * xmss_len]
        node = _xmss_pk_from_sig(c, leaf, part, node, layer, tree)
        leaf, tree = tree & ((1 << HP) - 1), tree >> HP
    return hmac.compare_digest(node, pk_root)
