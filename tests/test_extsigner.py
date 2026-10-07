"""External signers (#16): the signing key never enters tracekitd; bad helpers stop the signer, never corrupt the ledger.
python3 -m pytest tests/test_extsigner.py -q"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, crypto, install  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from tracekit.extsigner import ExternalKeys, SignerError  # noqa: E402

HELPER = os.path.join(ROOT, "examples", "ext_signer.py")


class Unit(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.key = os.path.join(self.d, "hsm.key")
        subprocess.run([sys.executable, HELPER, "--key", self.key, "--init"], check=True, capture_output=True)
        self.pub = open(self.key + ".pub", "rb").read()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_signs_and_signatures_verify(self):
        k = ExternalKeys([sys.executable, HELPER, "--key", self.key], self.pub, "hsm")
        try:
            sig = k.sign(b"hello")
            self.assertTrue(crypto.verify(self.pub, b"hello", sig))
            self.assertIsNone(k.secret)
            for i in range(50):  # one long-lived helper, not a process per signature
                k.sign(str(i).encode())
        finally:
            k.close()

    def test_wrong_key_is_caught(self):
        other_secret, other_pub = crypto.generate()
        k = ExternalKeys([sys.executable, HELPER, "--key", self.key], other_pub)
        with self.assertRaises(SignerError) as cm:
            k.sign(b"x")
        self.assertIn("does not verify", str(cm.exception))
        k.close()

    def test_dead_or_silent_helper(self):
        dead = ExternalKeys([sys.executable, "-c", "pass"], self.pub)
        with self.assertRaises(SignerError):
            dead.sign(b"x")
        silent = ExternalKeys([sys.executable, "-c", "import time; time.sleep(60)"], self.pub, timeout=0.5)
        with self.assertRaises(SignerError):
            silent.sign(b"x")
        with self.assertRaises(SignerError):
            ExternalKeys(["x"], b"short")


class Signed(unittest.TestCase):
    def test_signer_with_external_key_end_to_end(self):
        d = tempfile.mkdtemp()
        old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(d, "client")
        home = os.path.join(d, "signer")
        key = os.path.join(d, "hsm.key")
        subprocess.run([sys.executable, HELPER, "--key", key, "--init"], check=True, capture_output=True)
        try:
            signer = {"type": "external", "argv": [sys.executable, HELPER, "--key", key], "public_key": key + ".pub", "assurance": "hsm"}
            install.init_dev(home, [], start=True, signer=signer)
            install.stop_dev_daemon(home)
            install.init_dev(home, [], start=True)  # re-running init must keep the external signer
            self.assertEqual(json.load(open(os.path.join(home, "config.json")))["signer"], signer)
            with Tracer(agent="hw", session_id="hw-1", cwd=d) as t:
                with t.tool("Bash", {"command": "ls"}) as c:
                    c.result("x")
            self.assertEqual(open(os.path.join(home, "ledger", "signer.pub"), "rb").read(), open(key + ".pub", "rb").read())
            self.assertFalse(any("hsm" in f for f in os.listdir(os.path.join(home, "keys")) if f.endswith(".key")))
            out = os.path.join(d, "b.tkb")
            bundle.export(home, out, run="hw-1")
            rep, code = bundle.verify(out, trusted_key=key + ".pub")
            self.assertEqual(code, 0, rep.failures)
            chk = next(c for c in rep.checks if c["check"] == "signing key")
            self.assertIn("hsm", chk["detail"])
        finally:
            install.stop_dev_daemon(home)
            if old is None:
                os.environ.pop("TRACEKIT_CLIENT_HOME", None)
            else:
                os.environ["TRACEKIT_CLIENT_HOME"] = old
            shutil.rmtree(d, ignore_errors=True)

    def test_attestation_document_travels_with_the_bundle(self):
        import hashlib
        import zipfile
        d = tempfile.mkdtemp()
        old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(d, "client")
        home = os.path.join(d, "signer")
        key = os.path.join(d, "tee.key")
        att = os.path.join(d, "attestation.cbor")
        with open(att, "wb") as f:
            f.write(b"\xa1fdigestfSHA384 (stand-in for a vendor attestation document)")
        subprocess.run([sys.executable, HELPER, "--key", key, "--init"], check=True, capture_output=True)
        try:
            install.init_dev(home, [], start=True, signer={"type": "external", "argv": [sys.executable, HELPER, "--key", key],
                                                           "public_key": key + ".pub", "assurance": "tee", "attestation": att})
            with Tracer(agent="hw", session_id="hw-2", cwd=d) as t:
                with t.tool("Bash", {"command": "ls"}) as c:
                    c.result("x")
            install.stop_dev_daemon(home)
            out = os.path.join(d, "b.tkb")
            bundle.export(home, out, run="hw-2")
            sha = hashlib.sha256(open(att, "rb").read()).hexdigest()
            self.assertIn(f"attestation/{sha}.bin", zipfile.ZipFile(out).namelist())
            rep, code = bundle.verify(out, trusted_key=key + ".pub")
            self.assertEqual(code, 0, rep.failures)
            chk = next(c for c in rep.checks if c["check"] == "signing key")
            self.assertEqual(chk["status"], "pass")
            self.assertIn("attestation document in the bundle", chk["detail"])
            # a bundle without the document the checkpoints name is reported
            files = {n: zipfile.ZipFile(out).read(n) for n in zipfile.ZipFile(out).namelist()}
            del files[f"attestation/{sha}.bin"]
            man = json.loads(files["manifest.json"])
            del man["files"][f"attestation/{sha}.bin"]
            files["manifest.json"] = json.dumps(man).encode()
            bad = os.path.join(d, "bad.tkb")
            with zipfile.ZipFile(bad, "w") as z:
                for n, v in files.items():
                    z.writestr(n, v)
            rep2, _ = bundle.verify(bad, trusted_key=key + ".pub")
            chk2 = next(c for c in rep2.checks if c["check"] == "signing key")
            self.assertNotEqual(chk2["status"], "pass")
            self.assertTrue(any("does not carry it" in p for p in chk2["problems"]), chk2)
        finally:
            install.stop_dev_daemon(home)
            if old is None:
                os.environ.pop("TRACEKIT_CLIENT_HOME", None)
            else:
                os.environ["TRACEKIT_CLIENT_HOME"] = old
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
