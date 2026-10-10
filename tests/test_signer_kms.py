"""The signer's log key in AWS KMS (tracekit.signer.logkey) and the signer process's key hygiene. FakeKms answers with
the GetPublicKey and Sign shapes of the AWS KMS API reference; the same cases run against moto's KMS when it is
installed and has Ed25519 keys."""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from test_signer_service import ME, records, tmpdir
from tracekit import crypto, doctor
from tracekit.format import checkpoint
from tracekit.signer import logkey
from tracekit.signer import service as svc

ARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"


class KmsDown(Exception):   # stands in for botocore's ClientError (KMSInternalException, DisabledException, ...)
    pass


class FakeKms:
    """A KMS client holding one Ed25519 key; `down` fails every Sign, `foreign` signs with another key."""

    def __init__(self, spec="ECC_NIST_EDWARDS25519", usage="SIGN_VERIFY"):
        self.secret, self.spec, self.usage = crypto.generate()[0], spec, usage
        self.down = self.foreign = False

    def get_public_key(self, KeyId):
        return {"CustomerMasterKeySpec": self.spec, "EncryptionAlgorithms": [], "KeyAgreementAlgorithms": [],
                "KeyId": ARN, "KeySpec": self.spec, "KeyUsage": self.usage,
                "PublicKey": crypto.spki(crypto.public_from_secret(self.secret)),
                "SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"], "ResponseMetadata": {}}

    def sign(self, **req):
        assert set(req) == {"KeyId", "Message", "MessageType", "SigningAlgorithm"}, req
        assert (req["MessageType"], req["SigningAlgorithm"]) == ("RAW", "ED25519_SHA_512"), req
        assert isinstance(req["Message"], bytes) and len(req["Message"]) <= 4096
        if self.down:
            raise KmsDown("An error occurred (KMSInternalException) when calling the Sign operation")
        secret = crypto.generate()[0] if self.foreign else self.secret
        return {"KeyId": ARN, "Signature": crypto.sign(secret, req["Message"]), "SigningAlgorithm": "ED25519_SHA_512",
                "ResponseMetadata": {}}


class Cases:
    def key(self, spec="ECC_NIST_EDWARDS25519", usage="SIGN_VERIFY"):
        """(key id, client) of a new KMS key."""
        raise NotImplementedError

    def outage(self, down):
        raise NotImplementedError

    def setUp(self):
        self.dir = tmpdir(self)

    def open(self, key):
        s = svc.SignerService(self.dir, grace_s=0, log_key=key)
        self.addCleanup(s.close)
        return s

    def kms_key(self):
        key_id, client = self.key()
        return logkey.AwsKmsKey(key_id, "eu-west-1", client)

    def test_notes_signed_by_the_kms_key_verify_with_its_vkey(self):
        key = self.kms_key()
        s = self.open(key)
        s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.assertTrue(s.checkpoint())
        vkey = checkpoint.vkey(s.origin, checkpoint.ED25519, key.public)
        self.assertEqual(s.vkey, vkey)
        size, note = s.log.storage.checkpoint_latest()
        self.assertEqual(checkpoint.open_note(note, [vkey])[:2], (s.origin, size))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys", "log.key")))
        cfg = os.path.join(self.dir, "signer.yaml")
        with open(cfg, "w") as f:
            f.write(f"data_dir: {self.dir}\nlog_key: {{aws_kms: {{key_id: k, region: eu-west-1}}}}\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(svc.main(["vkey", "--config", cfg]), 0)
        self.assertEqual(out.getvalue().strip(), vkey)

    def test_a_key_of_another_spec_or_usage_is_refused(self):
        for spec, usage in (("ECC_NIST_P256", "SIGN_VERIFY"), ("ECC_NIST_EDWARDS25519", "KEY_AGREEMENT")):
            try:
                key_id, client = self.key(spec, usage)
            except Exception as e:   # moto may not create that combination
                self.skipTest(f"no {spec}/{usage} key: {e}")
            with self.assertRaisesRegex(ValueError, "must be a ECC_NIST_EDWARDS25519 SIGN_VERIFY key"):
                logkey.AwsKmsKey(key_id, "eu-west-1", client)

    def test_an_outage_leaves_the_note_unsigned_then_recovers(self):
        s = self.open(self.kms_key())
        s.checkpoint()
        before = s.log.storage.checkpoint_latest()
        s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.outage(True)
        with mock.patch.object(svc, "LOG_KEY_GAP_S", 0):
            self.assertFalse(s.checkpoint())
            self.assertFalse(s.checkpoint())
        self.assertEqual(s.log.storage.checkpoint_latest(), before)
        self.assertEqual(s.metrics.log_key_failures._values[None], 2)
        gaps = [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([g["kind"] for g in gaps], ["degraded_unanchored"])   # one per outage
        self.assertIn("the log key has signed no note since", gaps[0]["reason"])
        self.outage(False)
        self.assertTrue(s.checkpoint())
        size, note = s.log.storage.checkpoint_latest()
        self.assertEqual(size, s.log.storage.tree.size)
        checkpoint.open_note(note, [s.vkey])

    def test_switching_to_another_public_key_is_refused(self):
        s = svc.SignerService(self.dir, grace_s=0)   # the file key
        file_vkey = s.vkey
        s.close()
        with self.assertRaisesRegex(ValueError, "did not sign this log's notes"):
            svc.SignerService(self.dir, grace_s=0, log_key=self.kms_key())
        self.assertEqual(svc.read_vkey(self.dir), file_vkey)
        with open(os.path.join(self.dir, "keys", "log.key"), "rb") as f:
            same = logkey.FileKey(f.read())   # a backend holding the same key is allowed
        self.assertEqual(self.open(same).vkey, file_vkey)


class FakeKmsTests(Cases, unittest.TestCase):
    def key(self, spec="ECC_NIST_EDWARDS25519", usage="SIGN_VERIFY"):
        self.fake = FakeKms(spec, usage)
        return ARN, self.fake

    def outage(self, down):
        self.fake.down = down

    def test_a_signature_by_another_key_is_never_stored(self):
        s = self.open(self.kms_key())
        self.fake.foreign = True
        self.assertFalse(s.checkpoint())
        self.assertIsNone(s.log.storage.checkpoint_latest())


class MotoTests(Cases, unittest.TestCase):
    def setUp(self):
        try:
            import boto3
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto is not installed (the dev extra)")
        for m in (mock.patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing"}),
                  mock_aws()):
            m.start()
            self.addCleanup(m.stop)
        self.client = boto3.client("kms", region_name="eu-west-1")
        try:
            key_id, _ = self.key()
            self.client.sign(KeyId=key_id, Message=b"probe", MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        except Exception as e:
            self.skipTest(f"moto's KMS has no Ed25519 signing: {type(e).__name__}: {e}")
        super().setUp()

    def key(self, spec="ECC_NIST_EDWARDS25519", usage="SIGN_VERIFY"):
        self.key_id = self.client.create_key(KeySpec=spec, KeyUsage=usage)["KeyMetadata"]["KeyId"]
        return self.key_id, self.client

    def outage(self, down):
        (self.client.disable_key if down else self.client.enable_key)(KeyId=self.key_id)


class Config(unittest.TestCase):
    def load(self, text):
        d = tmpdir(self)
        path = os.path.join(d, "signer.yaml")
        with open(path, "w") as f:
            f.write(f"data_dir: {d}\n{text}\n")
        return svc.load_config(path)

    def test_log_key_section(self):
        cfg = self.load("log_key: {aws_kms: {key_id: alias/log, region: eu-west-1}}")
        self.assertEqual(cfg["log_key"], {"aws_kms": {"key_id": "alias/log", "region": "eu-west-1"}})
        for bad in ("log_key: {gcp_kms: {key: k}}", "log_key: {aws_kms: {key_id: k}}", "log_key: file"):
            with self.assertRaisesRegex(ValueError, "log_key is"):
                self.load(bad)


@unittest.skipIf(os.name == "nt", "POSIX process limits")
class Hygiene(unittest.TestCase):
    def test_harden_and_mlock(self):
        code = ("import ctypes, json, resource, sys\n"
                "from tracekit.signer import logkey\n"
                "logkey.harden(); logkey.mlock(bytes(32))\n"
                "dumpable = ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) if sys.platform.startswith('linux') else None\n"
                "print(json.dumps([logkey.HYGIENE, resource.getrlimit(resource.RLIMIT_CORE), dumpable]))")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        hygiene, core, dumpable = json.loads(subprocess.run([sys.executable, "-c", code], cwd=root, check=True,
                                                            capture_output=True, text=True).stdout)
        self.assertEqual(core, [0, 0])
        self.assertEqual(hygiene["core_limit"], 0)
        if sys.platform.startswith("linux"):
            self.assertEqual((hygiene["dumpable"], dumpable), (False, 0))
        self.assertIn(hygiene["mlock"], (True, False))   # False where RLIMIT_MEMLOCK is 0

    def test_signer_writes_its_hygiene_and_doctor_reports_it(self):
        d = tmpdir(self)
        os.chmod(d, 0o700)
        with mock.patch.dict(logkey.HYGIENE, {"core_limit": 0, "dumpable": False, "mlock": True}), \
                mock.patch.object(logkey, "mlock"):
            svc.SignerService(d).close()

        def got():
            return {r["id"]: r for r in doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none"))}
        self.assertEqual(got()["D-KEY-HYGIENE"]["status"], "ok")
        with open(os.path.join(d, "hygiene.json"), "w") as f:
            json.dump({"core_limit": None, "dumpable": True, "mlock": False}, f)
        r = got()["D-KEY-HYGIENE"]
        self.assertEqual(r["status"], "warn")
        self.assertIn("core dumps allowed", r["detail"])


if __name__ == "__main__":
    unittest.main()
