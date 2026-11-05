"""The independent Go verifier (contrib/independent-go-verifier's tkverify) on the mutated bundles the TypeScript one is
held to: every structural mutation of the golden closed bundle, run-set and run in parts (test_bounded.py), and the
mutated copies of the real signer's bundles (test_ts_verifier.py). Each must get the reference's verdict: its exit code
and integrity, so neither verifier accepts what the other refuses. The golden corpus goes through
contrib/independent-go-verifier/scripts/differential_golden.py. Skipped without Go; CI's go-verifier job runs it."""
import atexit
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import test_bounded as tb
import test_ts_verifier as tv

from tracekit.verify import v2

MODULE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "contrib", "independent-go-verifier")
GO = shutil.which("go")
SKIP = None if GO else "needs Go on PATH to build contrib/independent-go-verifier's tkverify"
_BUILT = []


def tkverify():
    """tkverify, built once per session into a temp dir."""
    if not _BUILT:
        d = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, d, True)
        _BUILT.append(os.path.join(d, "tkverify.exe" if os.name == "nt" else "tkverify"))
        subprocess.run([GO, "build", "-o", _BUILT[0], "./cmd/tkverify"], cwd=MODULE, check=True)
    return _BUILT[0]


def go_verdict(bundle, trust):
    """(exit code, integrity) of tkverify on `bundle`."""
    p = subprocess.run([tkverify(), "-bundle", bundle, "-trust", trust, "-json"], capture_output=True, text=True)
    out = json.loads(p.stdout)
    assert out["exit_code"] == p.returncode, p
    return out["exit_code"], out["integrity"]


class InGo:
    def assert_none(self, wrong):
        """No mutation verified, and tkverify gives each the reference's exit code and integrity."""
        self.assertEqual(wrong, [])
        self.assertEqual([(path, want[:2], got) for path, want in self.made
                          if (got := go_verdict(path, self.TRUST)) != want[:2]], [])


@unittest.skipIf(SKIP, SKIP)
class EveryStructuralMutation(InGo, tb.EveryStructuralMutation):
    pass


@unittest.skipIf(SKIP, SKIP)
class EveryStructuralMutationOfARunSet(InGo, tb.EveryStructuralMutationOfARunSet):
    pass


@unittest.skipIf(SKIP, SKIP)
class EveryStructuralMutationOfARunInParts(InGo, tb.EveryStructuralMutationOfARunInParts):
    pass


@unittest.skipIf(SKIP, SKIP)
class SignerBundleMutations(tv.SignerBundles):
    def test_mutations(self):
        for name, (bundle, trust, code) in self.mutations().items():
            with self.subTest(name):
                rep, got = v2.verify(bundle, trust)
                self.assertEqual(got, code)
                self.assertEqual(go_verdict(bundle, trust), (code, rep.integrity))
