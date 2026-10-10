"""Record-key issuer (tracekit/issuer.py): scoped, proven, witnessed issuance and revocation; the signer's certified,
rotating record keys; and the verifier's checks of certified keys (tracekit/verify/v2.py, tracekit/format/cert.py)."""
import base64
import json
import os
import threading
import unittest
from unittest import mock

from test_bundle_v2 import KEY1, KEY2, LOG_SECRET, ORIGIN, WIT_SECRET, WITNESS, Log, cosign, pub, spki
from test_otlp import agent_trace
from test_signer_service import ME, tmpdir
from test_signer_service import records as ts_records
from test_witness_publish import VKEY, FakeWitness
from tracekit import crypto, issuer
from tracekit.bundle_v2 import export
from tracekit.format import cert, checkpoint
from tracekit.identity.base import CallerIdentity
from tracekit.signer import pipeline
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.tlog_witness import TlogWitness, WitnessError
from tracekit.transport import http
from tracekit.verify import v2

NAME, ISSUANCE = "issuer.example.org", "issuer.example.org/issuance"
SVC = CallerIdentity("token", "http", True)
T0 = 1791547200   # the ts of every record test_bundle_v2.Log writes, 2026-10-09T12:00:00Z
TOKEN = "t" * 40


def request(secret, log_id="0" * 32, tenants=("acme",), ttl_s=600, **over):
    der = base64.b64encode(spki(secret)).decode()
    req = {"method": "issue", "spki": der, "log_id": log_id, "tenants": list(tenants), "ttl_s": ttl_s}
    req["pop"] = base64.b64encode(crypto.sign(secret, cert.pop_message(der, log_id, list(tenants), ttl_s))).decode()
    return {**req, **over}


class StubWitness:
    """Cosigns every note as test_bundle_v2's WITNESS; `down` refuses."""
    name, down = WITNESS, False
    vkey = checkpoint.vkey(WITNESS, checkpoint.COSIGNATURE, pub(WIT_SECRET))

    def add_checkpoint(self, note, log_vkey, old, proof):
        if self.down:
            raise WitnessError(f"{self.name}: HTTP 503: down", True)
        return cosign(note[:note.index("\n\n") + 1], WITNESS, WIT_SECRET, T0)


def scopes(log_ids=("0" * 32,), tenants=("acme",), max_ttl_s=3600):
    return {"token:http": {"log_ids": list(log_ids), "tenants": list(tenants), "max_ttl_s": max_ttl_s}}


class Issuance(unittest.TestCase):
    def setUp(self):
        self.dir, self.w = tmpdir(self), StubWitness()
        self.iss = issuer.Issuer(self.dir, NAME, ISSUANCE, scopes(), [self.w])
        self.pin = {"vkey": self.iss.vkey, "issuance_log_vkey": self.iss.log_vkey}

    def refused(self, code, req, identity=SVC):
        with self.assertRaises(RPCError) as e:
            self.iss.issue(identity, req)
        self.assertEqual(e.exception.code, code, e.exception)
        return e.exception

    def test_issues_a_witnessed_certificate(self):
        first, second = self.iss.issue(SVC, request(KEY1)), self.iss.issue(SVC, request(KEY2))
        for i, entry in enumerate((first, second)):
            c, pin = cert.check(entry, [self.pin], [self.w.vkey], 1)
            self.assertEqual((entry["index"], pin, c["kid"]), (i, self.pin, crypto.spki_kid(spki((KEY1, KEY2)[i]))))
            self.assertEqual(c["not_after"] - c["not_before"], 600 + issuer.BACKDATE_S)
        self.assertNotEqual(first["certificate"]["cert"]["serial"], second["certificate"]["cert"]["serial"])
        self.assertEqual([d["cert"] for d in self.iss.documents()], [first["certificate"]["cert"],
                                                                     second["certificate"]["cert"]])
        with self.assertRaisesRegex(ValueError, "pinned cosignature"):   # a cosignature from an unpinned witness
            cert.check(first, [self.pin], [], 1)

    def test_scope_refusals(self):
        self.assertIn("log_id", self.refused("forbidden", request(KEY1, log_id="1" * 32)).message)
        self.assertIn("tenants", self.refused("forbidden", request(KEY1, tenants=("acme", "other"))).message)
        self.assertIn("ttl_s", self.refused("forbidden", request(KEY1, ttl_s=3601)).message)
        self.assertIn("ttl_s", self.refused("forbidden", request(KEY1, ttl_s=0)).message)
        self.refused("forbidden", request(KEY1), CallerIdentity("mtls", "spiffe://acme/agent", True))
        self.assertEqual(self.iss.documents(), [])

    def test_proof_of_possession_required(self):
        self.refused("invalid_request", {k: v for k, v in request(KEY1).items() if k != "pop"})
        self.refused("forbidden", request(KEY1, pop=request(KEY2)["pop"]))   # another key's proof
        self.refused("forbidden", request(KEY1, ttl_s=60, pop=request(KEY1, ttl_s=600)["pop"]))   # for other terms
        self.assertEqual(self.iss.documents(), [])

    def test_not_returned_when_no_witness_cosigns(self):
        self.w.down = True
        self.assertIn("no witness cosigned", self.refused("unavailable", request(KEY1)).message)
        self.w.down = False
        entry = self.iss.issue(SVC, request(KEY2))   # the next checkpoint covers the unanswered one too
        self.assertEqual(entry["index"], 1)
        cert.check(entry, [self.pin], [self.w.vkey], 1)

    def test_revocation_is_ca_signed_and_witnessed(self):
        serial = self.iss.issue(SVC, request(KEY1))["certificate"]["cert"]["serial"]
        doc = self.iss.revoke(serial, 7)
        self.assertEqual(cert.revocation(doc, [self.pin]), (self.iss.vkey, serial, 7))
        self.assertEqual(self.iss.documents()[-1], doc)
        with self.assertRaisesRegex(ValueError, "not signed by a pinned issuer"):
            cert.revocation(doc, [{**self.pin, "vkey": checkpoint.vkey(NAME, checkpoint.ED25519, pub(KEY2))}])
        with self.assertRaisesRegex(ValueError, "no certificate"):
            self.iss.revoke("ab" * 16)


class HttpIssuer(unittest.TestCase):
    """The issuer over HTTP and a v2 signer whose record keys it certifies."""

    def setUp(self):
        self.dir = tmpdir(self)
        self.fw = FakeWitness()
        self.addCleanup(self.fw.stop)
        token = os.path.join(self.dir, "token")
        with open(token, "w") as f:
            f.write(TOKEN)
        self.iss = issuer.Issuer(os.path.join(self.dir, "issuer"), NAME, ISSUANCE,
                                 scopes(log_ids=("*",), tenants=("default",)), [TlogWitness(self.fw.url, VKEY, timeout=2)])
        self.fw.logs[ISSUANCE] = self.iss.log_vkey
        srv = http.HttpServer(*http.configure({"listen": "127.0.0.1:0", "authenticators": ["token"],
                                               "token_file": token, "insecure_loopback": True}), self.iss.handle_frame)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.cfg = {"url": f"http://127.0.0.1:{srv.server_address[1]}", "vkey": self.iss.vkey,
                    "issuance_log_vkey": self.iss.log_vkey, "tenants": ["default"], "ttl_s": 600, "token_file": token}
        self.data = os.path.join(self.dir, "signer")

    def open(self):
        s = svc.SignerService(self.data, grace_s=0, record_key={"issuer": self.cfg})
        self.addCleanup(s.close)
        return s

    def trust(self, issuers):
        path = os.path.join(self.dir, "trust.json")
        with open(path, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": [{"vkey": VKEY, "class": "customer"}], "algs": ["ed25519"],
                       "issuers": issuers}, f)
        return path

    def test_an_expired_key_never_signs_writes_wait_for_renewal(self):
        self.s = self.open()
        c = self.s.log.cert["certificate"]["cert"]
        with mock.patch.object(self.s.log, "certify", side_effect=OSError("issuer down")), \
                mock.patch.object(svc.time, "time", return_value=c["not_after"] + 1):
            self.s._renew()
        with self.assertRaises(RPCError) as e:
            self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.assertEqual(e.exception.code, "unavailable")
        self.s._renew()   # the issuer is back
        self.s.call(ME, "register_run", {"request_id": "r2", "agent": {"name": "a"}})

    def test_an_expired_key_signs_no_record_of_the_signer_either_until_renewed(self):
        self.s = self.open()
        run = self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.s.call(ME, "close_run", {"request_id": "r2", "run_id": run["run_id"], "run_token": run["run_token"]})
        c = self.s.log.cert["certificate"]["cert"]
        with mock.patch.object(svc.time, "time", return_value=c["not_after"] + 1):
            with self.assertRaises(RPCError) as e:
                self.s.sweep()   # the ticker's next round retries
            self.assertEqual(e.exception.code, "unavailable")
        self.s.close()
        self.assertNotIn("run.final", [r["event"]["type"] for r in ts_records(self.data)])
        self.s = self.open()   # a fresh certified key
        self.s.sweep()
        self.assertIn("run.final", [r["event"]["type"] for r in self.s.log.storage.iter_run("default", run["run_id"])])

    def test_runs_only_of_the_tenants_the_key_is_certified_for(self):
        app = CallerIdentity("token", "app", True, {"tenant": "acme"})
        self.s = svc.SignerService(self.data, record_key={"issuer": self.cfg}, tenants={f"uid:{ME.subject}": "acme"},
                                   authorize={"token:app": ["otlp_import"]})
        self.addCleanup(self.s.close)
        with self.assertRaises(RPCError) as e:
            self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.assertEqual(e.exception.code, "forbidden")
        status, _, out = self.s.otlp(app, json.dumps(agent_trace()).encode(), "application/json", None)
        self.assertEqual((status, json.loads(out)["partialSuccess"]["rejectedSpans"]), (200, "2"))   # tool and llm spans
        self.assertEqual(self.s.log.runs.keys() - {pipeline.SIGNER_RUN}, set())

    def test_scope_refusal_over_http(self):
        with self.assertRaisesRegex(RPCError, "forbidden: tenants"):
            issuer.certify({**self.cfg, "tenants": ["other"]}, "0" * 32)

    def test_signer_rotates_certified_keys_and_the_bundle_verifies(self):
        self.s = self.open()
        self.s.rotate_key()
        run = self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.s.call(ME, "close_run", {"request_id": "r2", "run_id": run["run_id"], "run_token": run["run_token"]})
        self.s.sweep()
        self.s.close()
        self.s = self.open()   # every start: a fresh key, the last one retired
        self.assertFalse(os.path.exists(os.path.join(self.data, "keys", "record.key")))
        self.assertTrue(self.s.checkpoint())
        st = self.s.log.storage
        keyed = [r["event"] for r in st.iter_range(0, st.tree.size) if r["event"]["type"] in ("signer.epoch", "key.retire")]
        self.assertEqual([e["type"] for e in keyed], ["signer.epoch", "signer.epoch", "key.retire", "signer.epoch",
                                                       "key.retire"])
        kids = [e["data"]["keys"][0]["kid"] for e in keyed if e["type"] == "signer.epoch"]
        self.assertEqual(len(set(kids)), 3)
        self.assertEqual([(e["data"]["kid"], e["data"]["last_seq"]) for e in keyed if e["type"] == "key.retire"],
                         [(kids[0], keyed[1]["seq"] - 1), (kids[1], keyed[3]["seq"] - 1)])
        self.assertEqual(svc.fsck(self.data, record_key={"issuer": self.cfg}), [])
        out = os.path.join(self.dir, "run.tkb")
        export(st, "default", run["run_id"], st.checkpoint_latest()[1], out)
        pin = {"vkey": self.iss.vkey, "issuance_log_vkey": self.iss.log_vkey}
        rep, code = v2.verify(out, self.trust([pin]))
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertIn("certified: 3 of 3 record key(s) by pinned issuer(s) issuer.example.org",
                      [c["detail"] for c in rep.checks if c["check"] == "key assurance"])
        rep, code = v2.verify(out, self.trust([]))   # an unpinned issuer vouches for nothing
        self.assertEqual(code, 1)
        self.assertIn("keys", rep.failures)
        self.assertTrue(any("not signed by a pinned issuer" in p for c in rep.checks for p in c["problems"]), rep.checks)

        # the run was signed under the second key: revoking it makes the bundle unverifiable, from its last_seq on
        serial = keyed[1]["data"]["keys"][0]["cert"]["certificate"]["cert"]["serial"]
        self.iss.revoke(serial, keyed[3]["seq"])
        rep, code = v2.verify(out, self.trust([pin]), revocations=[self.iss.path])
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.iss.revoke(serial)
        rep, code = v2.verify(out, self.trust([pin]), revocations=[self.iss.path])
        self.assertEqual((rep.integrity, code), ("UNVERIFIABLE (key revoked)", 2), rep.checks)
        self.assertEqual(rep.failures, [])
        self.assertIn("revocations", rep.warnings)


class CertifiedKeys(unittest.TestCase):
    """Bundles of test_bundle_v2.Log logs whose key is certified."""

    def setUp(self):
        self.dir = tmpdir(self)
        self.iss = issuer.Issuer(os.path.join(self.dir, "issuer"), NAME, ISSUANCE, scopes(), [StubWitness()],
                                 clock=lambda: T0)
        self.pin = {"vkey": self.iss.vkey, "issuance_log_vkey": self.iss.log_vkey}

    def bundle(self, entry):
        log = Log(os.path.join(self.dir, "store"))
        self.addCleanup(log.store.close)
        der = spki(KEY1)
        log.add("signer.epoch", {"keys": [{"kid": crypto.spki_kid(der), "alg": "ed25519",
                                           "spki": base64.b64encode(der).decode(), "cert": entry}]}, run="signer")
        log.register()
        log.call()
        log.final()
        out = os.path.join(self.dir, "a.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        return out

    def verify(self, path):
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, checkpoint.ED25519, pub(LOG_SECRET))],
                       "witnesses": [{"vkey": StubWitness.vkey, "class": "customer"}], "algs": ["ed25519"],
                       "witnesses_required": 1, "issuers": [self.pin]}, f)
        return v2.verify(path, trust)

    def problems(self, rep):
        return [p for c in rep.checks for p in c["problems"]]

    def test_accepts_a_certified_key(self):
        rep, code = self.verify(self.bundle(self.iss.issue(SVC, request(KEY1))))
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)

    def test_rejects_an_uncertified_key_when_issuers_are_pinned(self):
        log = Log(os.path.join(self.dir, "store"))
        self.addCleanup(log.store.close)
        log.epoch(KEY1)
        log.register()
        log.final()
        out = os.path.join(self.dir, "u.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, code = self.verify(out)
        self.assertEqual(code, 1)
        self.assertTrue(any("has no certificate" in p for p in self.problems(rep)), rep.checks)

    def test_rejects_a_certificate_missing_from_the_issuance_log(self):
        entry = self.iss.issue(SVC, request(KEY1))
        other = self.iss.issue(SVC, request(KEY2))   # a real checkpoint and proof, of another leaf
        rep, code = self.verify(self.bundle({**other, "certificate": entry["certificate"]}))
        self.assertEqual(code, 1)
        self.assertIn("keys", rep.failures)
        self.assertTrue(any("not in the issuer's issuance log" in p for p in self.problems(rep)), rep.checks)

    def test_rejects_records_after_the_certificate_expired(self):
        self.iss.clock = lambda: T0 - 3600
        rep, code = self.verify(self.bundle(self.iss.issue(SVC, request(KEY1))))
        self.assertEqual(code, 1)
        self.assertIn("signatures", rep.failures)
        self.assertTrue(any("outside the validity" in p for p in self.problems(rep)), rep.checks)

    def test_rejects_a_tenant_outside_the_certificate(self):
        self.iss.identities = scopes(tenants=("acme", "other"))
        rep, code = self.verify(self.bundle(self.iss.issue(SVC, request(KEY1, tenants=("other",)))))
        self.assertEqual(code, 1)
        self.assertTrue(any("outside key" in p for p in self.problems(rep)), rep.checks)


if __name__ == "__main__":
    unittest.main()
