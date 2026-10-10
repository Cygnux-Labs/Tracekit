"""Rekor v2 anchors with RFC 3161 timestamps (tracekit/anchor/): offline, against an in-test Rekor v2 log and TSA (a
self-generated Rekor log key and test CA), and the real staging entry of spike S2 (tests/golden/rekor_staging/)."""
import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from factories import wait_for
from test_signer_service import ME, records, tmpdir
from test_witness_publish import NAME, VKEY, FakeWitness, signed_note
from tracekit import cli, crypto, merkle
from tracekit.anchor import rekor2, tsa
from tracekit.anchor.rekor2 import RekorAnchor
from tracekit.anchor.tsa import AnchorError, der, der_int
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint, registry
from tracekit.signer import service as svc
from tracekit.storage.base import RECORDS
from tracekit.tlog_witness import TlogWitness, log_signed
from tracekit.verify import v2

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "rekor_staging")
SINCE = {"start": "2020-01-01T00:00:00Z"}
ORIGIN = "tracekit.example.org/log/anchor"


def b64(b):
    return base64.b64encode(b).decode("ascii")


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def cert(subject, key, issuer=None, issuer_key=None, tsa_leaf=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=1)))
    if tsa_leaf:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return b.sign(issuer_key or key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def make_ca(label):
    """(leaf key, [leaf DER, root DER]) of a TSA chain."""
    root_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root = cert(f"{label} root", root_key)
    issuer = x509.load_der_x509_certificate(root).subject
    return leaf_key, [cert(f"{label} tsa", leaf_key, issuer, root_key, tsa_leaf=True), root]


def tsa_response(req, leaf_key, chain):
    """An RFC 3161 TimeStampResp (granted) for a TimeStampReq, signed by `leaf_key` with ECDSA P-256 SHA-256."""
    fields = tsa.items(tsa.items(req)[0][1])
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%SZ").encode()
    tst = der(0x30, der_int(1), der(0x06, bytes.fromhex("2b0601040183bf3002")), fields[1][2], der_int(7),
              der(0x18, now), fields[2][2])
    attrs = (der(0x30, der(0x06, tsa.ID_CONTENT_TYPE), der(0x31, der(0x06, tsa.ID_TST_INFO)))
             + der(0x30, der(0x06, tsa.ID_MESSAGE_DIGEST), der(0x31, der(0x04, hashlib.sha256(tst).digest()))))
    sig = leaf_key.sign(der(0x31, attrs), ec.ECDSA(hashes.SHA256()))
    sha256 = der(0x30, der(0x06, tsa.SHA256))
    si = der(0x30, der_int(1), der(0x30, der_int(7)), sha256, der(0xA0, attrs),
             der(0x30, der(0x06, bytes.fromhex("2a8648ce3d040302"))), der(0x04, sig))
    sd = der(0x30, der_int(3), der(0x31, sha256), der(0x30, der(0x06, tsa.ID_TST_INFO), der(0xA0, der(0x04, tst))),
             der(0xA0, chain[0]), der(0x31, si))
    return der(0x30, der(0x30, der_int(0)), der(0x30, der(0x06, tsa.ID_SIGNED_DATA), der(0xA0, sd)))


class FakeSigstore:
    """A Rekor v2 log (POST /api/v2/log/entries; GET /api/v2/checkpoint and /api/v2/tile/entries/<N>[.p/<W>]) and a TSA
    (POST /api/v1/timestamp) on one port; `status` forces an answer (e.g. 503)."""

    def __init__(self, port=0):
        self.log_key = ed25519.Ed25519PrivateKey.generate()
        self.log_id = hashlib.sha256(spki(self.log_key)).digest()
        self.tsa_key, self.chain = make_ca("fake")
        self.leaves, self.entries, self.bodies, self.status = [], [], [], None
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                code, out = (fake.status, b"down") if fake.status else (
                    (200, fake.add(json.loads(body))) if self.path == "/api/v2/log/entries"
                    else (200, tsa_response(body, fake.tsa_key, fake.chain)))
                self.send_response(code)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_GET(self):
                if self.path == "/api/v2/checkpoint":
                    out = fake.envelope(len(fake.leaves)).encode()
                else:
                    n, _, w = self.path[len("/api/v2/tile/entries/"):].replace("x", "").replace("/", "").partition(".p")
                    out = b"".join(len(b).to_bytes(2, "big") + b
                                   for b in fake.bodies[int(n) * 256:int(n) * 256 + int(w or 256)])
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.origin = f"127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def add(self, req):
        r = req["hashedRekordRequestV002"]
        body = json.dumps({"apiVersion": "0.0.2", "kind": "hashedrekord", "spec": {"hashedRekordV002": {
            "data": {"algorithm": "SHA2_256", "digest": r["digest"]}, "signature": r["signature"]}}},
            separators=(",", ":")).encode()
        self.leaves.append(merkle.leaf_hash(body))
        self.entries.append(req)
        self.bodies.append(body)
        i, size, root = len(self.leaves) - 1, len(self.leaves), merkle.root(self.leaves)
        envelope = self.envelope(size)
        return json.dumps({
            "logIndex": str(i), "logId": {"keyId": b64(self.log_id)},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"}, "integratedTime": "0",
            "inclusionProof": {"logIndex": str(i), "rootHash": b64(root), "treeSize": str(size),
                               "hashes": [b64(h) for h in merkle.inclusion_proof(i, self.leaves)],
                               "checkpoint": {"envelope": envelope}},
            "canonicalizedBody": b64(body)}).encode()

    def envelope(self, size):
        text = f"{self.origin}\n{size}\n{b64(merkle.root(self.leaves[:size]))}\n"
        return f"{text}\n— {self.origin} {b64(self.log_id[:4] + self.log_key.sign(text.encode()))}\n"

    def trusted_root(self, chain=None):
        return {"tlogs": [{"baseUrl": self.url, "logId": {"keyId": b64(self.log_id)},
                           "publicKey": {"rawBytes": b64(spki(self.log_key)), "keyDetails": "PKIX_ED25519",
                                         "validFor": SINCE}}],
                "timestampAuthorities": [{"certChain": {"certificates": [{"rawBytes": b64(c)} for c in chain or self.chain]},
                                          "validFor": SINCE}]}

    def files(self, d):
        """(signing_config path, trusted_root path) in `d`."""
        paths = os.path.join(d, "signing_config.json"), os.path.join(d, "trusted_root.json")
        for path, doc in zip(paths, (
                {"rekorTlogUrls": [{"url": "https://rekor.example.org", "majorApiVersion": 1, "validFor": SINCE},
                                   {"url": self.url, "majorApiVersion": 2, "validFor": SINCE}],
                 "tsaUrls": [{"url": self.url + "/api/v1/timestamp", "majorApiVersion": 1, "validFor": SINCE}]},
                self.trusted_root())):
            with open(path, "w") as f:
                json.dump(doc, f)
        return paths


class Anchors(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.fake = FakeSigstore()
        self.addCleanup(self.fake.stop)
        self.secret = rekor2.new_key()
        self.anchor = RekorAnchor(*self.fake.files(self.dir), self.secret)
        self.log_secret = hashlib.sha256(b"log").digest()
        self.log_vkey = checkpoint.vkey(ORIGIN, checkpoint.ED25519, crypto.public_from_secret(self.log_secret))
        self.leaves = [merkle.leaf_hash(b"%d" % i) for i in range(5)]

    def submit(self, n=3):
        note = signed_note(ORIGIN, self.leaves[:n], self.log_secret)
        return self.anchor.add_checkpoint(note, self.log_vkey, 0, None), log_signed(note, self.log_vkey).encode()

    def check(self, anchor, data, spki_der=None, root=None):
        return rekor2.verify(anchor, data, spki_der or self.anchor.spki, root or self.fake.trusted_root())

    def test_submit_and_verify(self):
        anchor, data = self.submit()
        at, log = self.check(anchor, data)
        self.assertEqual(log, self.fake.origin)
        self.assertLess(abs((datetime.datetime.now(datetime.timezone.utc) - at).total_seconds()), 5)
        sent = self.fake.entries[0]["hashedRekordRequestV002"]
        self.assertEqual(sent["digest"], b64(hashlib.sha256(data).digest()))   # over the log-signed note bytes
        self.assertEqual(sent["signature"]["verifier"]["keyDetails"], "PKIX_ECDSA_P256_SHA_256")

    def test_tampered_body_fails(self):
        anchor, data = self.submit()
        body = json.loads(base64.b64decode(anchor["rekor"]["canonicalizedBody"]))
        body["spec"]["hashedRekordV002"]["data"]["digest"] = b64(hashlib.sha256(b"other").digest())
        anchor["rekor"]["canonicalizedBody"] = b64(json.dumps(body).encode())
        with self.assertRaisesRegex(AnchorError, "not a hashedrekord v0.0.2 of these note bytes"):
            self.check(anchor, data)
        with self.assertRaisesRegex(AnchorError, "timestamp is not over these note bytes"):
            self.check(self.submit()[0], data + b"x")

    def test_wrong_publishing_key_fails(self):
        anchor, data = self.submit()
        with self.assertRaisesRegex(AnchorError, "not signed by the pinned publishing key"):
            self.check(anchor, data, base64.b64decode(rekor2.publishing_key(rekor2.new_key())))

    def test_bad_inclusion_proof_fails(self):
        self.submit(2)
        anchor, data = self.submit(4)
        hashes_ = anchor["rekor"]["inclusionProof"]["hashes"]
        hashes_[0] = b64(bytes(32))
        with self.assertRaisesRegex(AnchorError, "inclusion proof does not verify"):
            self.check(anchor, data)

    def test_rekor_checkpoint_must_be_signed_by_the_shard_key(self):
        anchor, data = self.submit()
        root = self.fake.trusted_root()
        root["tlogs"][0]["publicKey"]["rawBytes"] = b64(spki(ed25519.Ed25519PrivateKey.generate()))
        with self.assertRaisesRegex(AnchorError, "not signed by the pinned key"):
            self.check(anchor, data, root=root)
        root = self.fake.trusted_root()   # a shard retired before the anchor's time
        root["tlogs"][0]["publicKey"]["validFor"] = {"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
        with self.assertRaisesRegex(AnchorError, "no shard of the trusted root valid at its time"):
            self.check(anchor, data, root=root)

    def test_wrong_tsa_chain_fails(self):
        anchor, data = self.submit()
        with self.assertRaisesRegex(AnchorError, "not signed by a pinned TSA"):
            self.check(anchor, data, root=self.fake.trusted_root(make_ca("other")[1]))

    def test_a_bad_answer_is_refused_before_it_is_stored(self):
        self.fake.tsa_key, self.fake.chain = make_ca("other")   # a TSA key the trusted root does not pin
        with self.assertRaises(AnchorError) as cm:
            self.submit()
        self.assertFalse(cm.exception.retryable)
        self.fake.status = 503
        with self.assertRaises(AnchorError) as cm:
            self.submit()
        self.assertTrue(cm.exception.retryable)

    def test_cadence_and_signing_config_limits(self):
        sc, tr = self.fake.files(self.dir)
        with self.assertRaisesRegex(ValueError, "at least 3600"):
            RekorAnchor(sc, tr, self.secret, every_s=60)
        with open(sc, "w") as f:   # production today: Rekor v1 writes only
            json.dump({"rekorTlogUrls": [{"url": "https://rekor.example.org", "majorApiVersion": 1, "validFor": SINCE}],
                       "tsaUrls": [{"url": self.fake.url, "majorApiVersion": 1, "validFor": SINCE}]}, f)
        with self.assertRaisesRegex(ValueError, "no Rekor v2 log"):
            RekorAnchor(sc, tr, self.secret)

    def test_golden_staging_entry(self):
        with open(os.path.join(GOLDEN, "tle.json"), "rb") as f:
            tle = json.load(f)
        with open(os.path.join(GOLDEN, "note.txt"), "rb") as f:
            note = f.read()
        with open(os.path.join(GOLDEN, "token.tsr"), "rb") as f:
            token = f.read()
        with open(os.path.join(GOLDEN, "trusted_root.json"), "rb") as f:
            root = json.load(f)
        body = json.loads(base64.b64decode(tle["canonicalizedBody"]))
        pinned = base64.b64decode(body["spec"]["hashedRekordV002"]["signature"]["verifier"]["publicKey"]["rawBytes"])
        at, log = rekor2.verify({"rekor": tle, "tsa": b64(token)}, note, pinned, root)
        self.assertEqual((log, at.isoformat()), ("log2025-alpha3.rekor.sigstage.dev", "2026-10-09T07:03:57+00:00"))
        with self.assertRaises(AnchorError):
            rekor2.verify({"rekor": tle, "tsa": b64(token)}, note + b"\n", pinned, root)


class SignerAnchors(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.fake = FakeSigstore()
        self.addCleanup(lambda: self.fake.stop())
        for k, v in {"BACKOFF_S": (0.05, 0.2), "TICK_S": 0.05}.items():
            p = mock.patch.object(svc, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.sc, self.tr = self.fake.files(self.dir)
        self.s = self.open()

    def open(self):
        s = svc.SignerService(self.dir, grace_s=0, origin=ORIGIN,
                              rekor={"signing_config": self.sc, "trusted_root": self.tr, "every_s": 3600})
        self.addCleanup(s.close)
        return s

    def finished_run(self):
        call = lambda m, r: self.s.call(ME, m, {"request_id": os.urandom(8).hex(), **r})   # noqa: E731
        out = call("register_run", {"agent": {"name": "a"}})
        call("close_run", {"run_id": out["run_id"], "run_token": out["run_token"]})
        self.s.sweep()
        self.s.checkpoint()
        return out["run_id"]

    def trust(self, rekor):
        path = os.path.join(self.dir, "trust.json")
        with open(path, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"], **({"rekor": rekor} if rekor else {})}, f)
        return path

    def test_anchor_is_stored_exported_and_verified(self):
        run = self.finished_run()
        anchors = wait_for(lambda: self.s.log.storage.anchors(), 10)
        size, note = anchors[0]["size"], anchors[0]["note"]
        self.assertEqual(size, self.s.log.storage.checkpoint_latest()[0])
        out = os.path.join(self.dir, "run.tkb")
        export(self.s.log.storage, "default", run, note, out)
        cfg = os.path.join(self.dir, "signer.yaml")   # `tracekit signer trust` pins the trusted root and publishing key
        with open(cfg, "w") as f:
            json.dump({"data_dir": self.dir, "anchors": {"rekor": {"signing_config": self.sc, "trusted_root": self.tr}}}, f)
        trust = os.path.join(self.dir, "trust.json")
        self.assertEqual(svc.main(["trust", "--config", cfg, "-o", trust]), 0)
        with open(trust) as f:
            pinned = json.load(f)["rekor"]
        self.assertEqual(pinned["class"], "public")
        rep, code = v2.verify(out, trust)
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertTrue(rep.assurance.startswith("witnessed;"), rep.assurance)
        self.assertIn(f"anchored in Rekor {self.fake.origin} (public)", rep.assurance)
        rep, code = v2.verify(out, self.trust(dict(pinned, **{"class": "operator"})))
        self.assertTrue(rep.assurance.startswith("local;"), rep.assurance)
        rep, code = v2.verify(out, self.trust(None))   # not pinned: ignored
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertTrue(rep.assurance.startswith("dev;"), rep.assurance)
        rep, code = v2.verify(out, self.trust(dict(pinned, publishing_key=rekor2.publishing_key(rekor2.new_key()))))
        self.assertEqual((rep.integrity, code), ("FAILED", 1), rep.checks)   # a bad entry for a pinned anchor fails
        self.assertIn("rekor anchor", [c["check"] for c in rep.checks if c["status"] == "fail"])

    def test_retry_queue_survives_restart(self):
        self.fake.status = 503
        self.finished_run()
        attempts = lambda: self.s.log.storage.witness_queue().get("rekor", {}).get(RECORDS, {}).get("attempts", 0)  # noqa: E731
        self.assertTrue(wait_for(lambda: attempts() >= 1, 10))
        self.s.close()
        self.assertEqual(self.s.log.storage.witness_queue()["rekor"][RECORDS]["size"], 0)
        self.fake.status = None
        self.s = self.open()
        self.assertTrue(wait_for(lambda: self.s.log.storage.anchors(), 10))
        self.assertTrue(wait_for(lambda: attempts() == 0, 10))

    def test_rekor_down_gets_one_gap(self):
        self.fake.status = 503
        with mock.patch.object(svc, "WITNESS_GAP_S", 0.3):
            self.finished_run()
            gaps = lambda: [r["event"]["data"] for r in records(self.dir) if r["event"]["type"] == "capture.gap"]  # noqa: E731
            self.assertTrue(wait_for(gaps, 10))
            time.sleep(0.5)
        self.assertEqual(len(gaps()), 1)
        self.assertEqual(gaps()[0]["kind"], "witness_failed")
        self.assertTrue(gaps()[0]["reason"].startswith(f"witness rekor has not cosigned {ORIGIN} "), gaps())

    def test_at_most_one_anchor_per_every_s(self):
        run = self.finished_run()
        self.assertTrue(wait_for(lambda: self.s.log.storage.anchors(), 10))
        self.finished_run()
        time.sleep(0.5)   # ten publisher rounds
        self.assertEqual(len(self.fake.entries), 1)
        cfg, out = os.path.join(self.dir, "signer.yaml"), os.path.join(self.dir, "run.tkb")
        with open(cfg, "w") as f:
            json.dump({"data_dir": self.dir}, f)
        with contextlib.redirect_stdout(io.StringIO()):   # export prefers the anchored note that covers the run
            self.assertEqual(cli.main(["export", "--v2", "--config", cfg, "--run", run, "-o", out]), 0)
        size = self.s.log.storage.anchors()[0]["size"]
        self.assertLess(size, self.s.log.storage.checkpoint_latest()[0])
        with zipfile.ZipFile(out) as z:
            self.assertIn(f"rekor/{size}.json", z.namelist())
        self.assertGreater(self.s.log.storage.witness_queue()["rekor"][RECORDS]["next"], time.time() + 3000)
        self.assertRegex(self.s.metrics.render(), r'tracekit_signer_anchor_lag_records{anchor="rekor"} [1-9]')
        self.s.close()
        self.s = self.open()   # the cadence holds across a restart
        time.sleep(0.3)
        self.assertEqual(len(self.fake.entries), 1)

    def test_an_entry_that_does_not_verify_waits_every_s(self):
        self.fake.log_key = ed25519.Ed25519PrivateKey.generate()   # a shard the pinned trusted root does not list
        self.fake.log_id = hashlib.sha256(spki(self.fake.log_key)).digest()
        self.finished_run()
        self.assertTrue(wait_for(lambda: self.fake.entries, 10))
        time.sleep(0.5)   # ten backoff rounds
        self.assertEqual(len(self.fake.entries), 1)
        st = self.s.log.storage.witness_queue()["rekor"][RECORDS]
        self.assertEqual(st["attempts"], 1)
        self.assertGreater(st["next"], time.time() + 3000)

    def test_anchored_export_keeps_witness_cosignatures(self):
        w = FakeWitness()
        self.addCleanup(w.stop)
        answer = w.answer
        w.answer = lambda body: (time.sleep(0.5), answer(body))[1]   # cosigns after the anchor is stored
        public = checkpoint.parse_vkey(self.s.vkey)[3]
        for origin in (ORIGIN, registry.origin(ORIGIN, self.s.log.tenant_salt("default"))):
            w.logs[origin] = checkpoint.vkey(origin, checkpoint.ED25519, public)
        self.s.close()
        self.s = svc.SignerService(self.dir, grace_s=0, origin=ORIGIN, witnesses=[TlogWitness(w.url, VKEY, timeout=5)],
                                   rekor={"signing_config": self.sc, "trusted_root": self.tr})
        self.addCleanup(self.s.close)
        cosigned = lambda: f"— {NAME} " in self.s.log.storage.checkpoint_latest()[1]   # noqa: E731
        run = self.finished_run()
        anchored = lambda: f"— {NAME} " in (self.s.log.storage.anchors() or [{"note": ""}])[-1]["note"]   # noqa: E731
        self.assertTrue(wait_for(lambda: anchored() and cosigned(), 10))
        self.finished_run()
        self.assertTrue(wait_for(cosigned, 10))
        size = self.s.log.storage.anchors()[-1]["size"]
        self.assertLess(size, self.s.log.storage.checkpoint_latest()[0])
        cfg, out = os.path.join(self.dir, "signer.yaml"), os.path.join(self.dir, "run.tkb")
        with open(cfg, "w") as f:
            json.dump({"data_dir": self.dir}, f)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["export", "--v2", "--config", cfg, "--run", run, "-o", out]), 0)
        with zipfile.ZipFile(out) as z:
            self.assertIn(f"rekor/{size}.json", z.namelist())
        path = os.path.join(self.dir, "trust.json")
        with open(path, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": [{"vkey": VKEY, "class": "customer"}], "algs": ["ed25519"],
                       "witnesses_required": 1}, f)
        rep, code = v2.verify(out, path)
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)

    def test_export_from_a_store_without_anchors(self):   # a store from before anchors
        run = self.finished_run()
        self.s.close()
        os.remove(os.path.join(self.dir, "store", "anchors.jsonl"))
        cfg, out = os.path.join(self.dir, "signer.yaml"), os.path.join(self.dir, "run.tkb")
        with open(cfg, "w") as f:
            json.dump({"data_dir": self.dir}, f)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["export", "--v2", "--config", cfg, "--run", run, "-o", out]), 0)

    def test_config(self):
        cfg = os.path.join(self.dir, "signer.yaml")
        for anchors, ok in (({"rekor": {"signing_config": "sc.json", "trusted_root": "tr.json"}}, True),
                            ({"rekor": {"signing_config": "sc.json", "trusted_root": "tr.json", "every_s": 7200}}, True),
                            ({"rekor": {"signing_config": "sc.json", "trusted_root": "tr.json", "every_s": 60}}, False),
                            ({"rekor": {"signing_config": "sc.json"}}, False),
                            ({"tsa": {}}, False)):
            with open(cfg, "w") as f:
                json.dump({"data_dir": "d", "anchors": anchors}, f)
            if ok:
                got = svc.load_config(cfg)["anchors"]["rekor"]
                self.assertEqual(got["trusted_root"], os.path.join(self.dir, "tr.json"))
            else:
                with self.assertRaises(ValueError, msg=anchors):
                    svc.load_config(cfg)


if __name__ == "__main__":
    unittest.main()
