"""Property (04-design §11): one random mutation of a valid v2 bundle (tests/golden/v2/closed.tkb) never verifies as
`VERIFIED` with exit 0, and the verifier never raises. Mutations: a flipped bit anywhere in the file, an entry dropped or
duplicated, a line of a JSON lines entry deleted or two swapped. Entry and line mutations also refresh the manifest's
hashes, as anyone rewriting a bundle would. Derandomized and bounded, so the suite stays fast and repeatable."""
import hashlib
import io
import json
import os
import tempfile
import unittest
import warnings
import zipfile

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from tracekit.verify import v2

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "v2")
BUNDLE, TRUST = os.path.join(GOLDEN, "closed.tkb"), os.path.join(GOLDEN, "trust.json")
with open(BUNDLE, "rb") as f:
    GOOD = f.read()
with zipfile.ZipFile(BUNDLE) as z:
    ENTRIES = [(n, z.read(n)) for n in z.namelist()]
# entries the bundle may omit and still verify: the Rekor anchor is optional evidence
REQUIRED = [i for i, (n, _) in enumerate(ENTRIES) if not n.startswith(("rekor/", "tsa/"))]
JSONL = [i for i, (n, b) in enumerate(ENTRIES) if n.endswith(".jsonl") and b.count(b"\n") >= 2]
FAST = settings(max_examples=100, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow])


def zipped(entries):
    """Bundle bytes of (name, data) entries, each manifest.json among them refreshed with the others' hashes."""
    files = {n: b for n, b in entries if n != "manifest.json"}
    manifest = json.loads(dict(ENTRIES)["manifest.json"])
    manifest["files"] = {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
    with tempfile.SpooledTemporaryFile() as f:
        with warnings.catch_warnings(), zipfile.ZipFile(f, "w") as z:
            warnings.simplefilter("ignore")   # the duplicate entry
            for n, b in entries:
                z.writestr(n, json.dumps(manifest) if n == "manifest.json" else b)
        f.seek(0)
        return f.read()


class SingleMutations(unittest.TestCase):
    def assert_not_verified(self, data):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.tkb")
            with open(path, "wb") as f:
                f.write(data)
            rep, code = v2.verify(path, TRUST)   # raising fails the test
        self.assertIn(code, (1, 2), rep.checks)
        self.assertNotEqual(rep.integrity, "VERIFIED")

    def test_the_bundle_verifies(self):
        rep, code = v2.verify(BUNDLE, TRUST)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)

    @FAST
    @given(st.integers(0, len(GOOD) * 8 - 1))
    def test_bit_flip(self, bit):
        data = bytearray(GOOD)
        data[bit // 8] ^= 1 << (bit % 8)
        try:
            same = v2.read_zip(io.BytesIO(data)) == dict(ENTRIES)
        except Exception:
            same = False
        assume(not same)   # a flip in zip metadata the reader ignores leaves the same bundle
        self.assert_not_verified(bytes(data))

    @FAST
    @given(st.sampled_from(REQUIRED), st.booleans())
    def test_entry_dropped_or_duplicated(self, i, duplicate):
        entries = ENTRIES + [ENTRIES[i]] if duplicate else ENTRIES[:i] + ENTRIES[i + 1:]
        self.assert_not_verified(zipped(entries))

    @FAST
    @given(st.sampled_from(JSONL), st.integers(0, 1 << 16), st.integers(0, 1 << 16), st.booleans())
    def test_line_deleted_or_swapped(self, i, a, b, swap):
        name, data = ENTRIES[i]
        lines = data.split(b"\n")[:-1]
        a, b = a % len(lines), b % len(lines)
        if swap:
            assume(lines[a] != lines[b])
            lines[a], lines[b] = lines[b], lines[a]
        else:
            del lines[a]
        self.assert_not_verified(zipped(ENTRIES[:i] + [(name, b"".join(x + b"\n" for x in lines))] + ENTRIES[i + 1:]))


if __name__ == "__main__":
    unittest.main()
