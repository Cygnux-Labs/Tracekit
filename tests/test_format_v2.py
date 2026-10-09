"""Format v2 records, signatures and the v2 event schema: the shared vectors (tests/vectors/sig_v2.jsonl) in both
directions on both Ed25519 backends, the v2 Ed25519 rules, alg confusion, domain tags and schema validation.
Record vectors are signed with the published RFC 8032 section 7.1 test 1 key."""
import copy
import json
import os
import unittest
from unittest import mock

from tracekit import core, crypto, schema
from tracekit.format import sigmsg
from tracekit.format.records import RecordError, make_record, verify_record

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "sig_v2.jsonl")
SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
KEY = crypto.spki(crypto.public_from_secret(SECRET))
ALGS = {"ed25519"}
H = "sha256:" + "ab" * 32


def vectors():
    with open(VECTORS, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def backends():
    for pure in (False, True):
        with mock.patch.object(crypto, "FORCE_PURE", pure):
            yield pure


def ev(type_="tool.call", data=None, **kw):
    e = {"schema_version": "tracekit.event.v2", "id": "0" * 31 + "1", "seq": 1, "prev_hash": H,
         "ts": "2026-10-09T12:00:00.000000Z", "run_id": "run-1", "agent_id": "main", "parent_id": None,
         "source": "signer", "type": type_,
         "data": {"tool_use_id": "t1", "name": "Bash", "input": {}} if data is None else data}
    e.update(kw)
    return e


class TestVectors(unittest.TestCase):
    def test_records_both_directions(self):
        records = [v for v in vectors() if v["id"].startswith("record-")]
        self.assertEqual(len(records), 3)
        for v in records:
            with self.subTest(v["id"]):
                self.assertEqual(schema.validate(v["event"]), [])
                self.assertEqual(crypto.spki(bytes.fromhex(v["public"])), KEY)
                self.assertEqual(make_record(v["event"], SECRET), v["record"])
                r = v["record"]
                fields = {**{k: v["event"].get(k) for k in sigmsg.RECORD_FIELDS}, "alg": r["alg"], "kid": r["kid"],
                          "hash": r["hash"]}
                self.assertEqual(sigmsg.sig_message_v2(fields), v["message"].encode("utf-8"))
                for pure in backends():
                    verify_record(r, [KEY], ALGS)

    def test_ed25519_rules(self):
        rules = [v for v in vectors() if not v["id"].startswith("record-")]
        self.assertEqual(len(rules), 12)
        for v in rules:
            pub, msg, sig = (bytes.fromhex(v[k]) for k in ("public", "msg", "sig"))
            if v["id"].startswith("ed25519-small-order-key"):
                self.assertTrue(crypto._pure_verify(pub, msg, sig), v["id"])  # only the small-order rule rejects it
            for pure in backends():
                with self.subTest(v["id"], pure=pure):
                    self.assertIs(crypto.verify_v2("ed25519", crypto.spki(pub), msg, sig), v["valid"])

    def test_cofactored_only_vector_holds_under_the_cofactored_equation(self):
        v = next(v for v in vectors() if v["id"] == "ed25519-cofactored-only")
        pub, msg, sig = (bytes.fromhex(v[k]) for k in ("public", "msg", "sig"))
        A, R = crypto._decompress(pub), crypto._decompress(sig[:32])
        s, k = int.from_bytes(sig[32:], "little"), crypto._hq(sig[:32] + pub + msg)
        lhs = crypto._mul(8 * s, crypto._G)
        self.assertTrue(crypto._equal(lhs, crypto._mul(8, crypto._add(R, crypto._mul(k, A)))))


class TestRecords(unittest.TestCase):
    def setUp(self):
        self.r = make_record(ev(tenant="acme", run_seq=0, run_prev_hash=H, log_id="0" * 32), SECRET)

    def rejects(self, record, why, keys=(KEY,), algs=ALGS):
        with self.assertRaisesRegex(RecordError, why):
            verify_record(record, list(keys), algs)

    def test_kid_hashes_the_spki(self):
        self.assertEqual(self.r["kid"], "sha256:" + core.sha256_hex(KEY))
        self.assertEqual(crypto.key_alg(KEY), "ed25519")
        self.assertIsNone(crypto.key_alg(KEY[1:]))

    def test_alg_not_pinned(self):
        self.rejects(self.r, "not allowed", algs={"ecdsa-p256"})

    def test_alg_confusion(self):
        self.rejects(dict(self.r, alg="ecdsa-p256"), "not the key's algorithm", algs={"ed25519", "ecdsa-p256"})
        self.assertFalse(crypto.verify_v2("ecdsa-p256", KEY, b"", b"\0" * 64))

    def test_tampering(self):
        e = copy.deepcopy(self.r["event"])
        e["run_seq"] = 5
        self.rejects(dict(self.r, event=e), "hash does not match")
        self.rejects(dict(self.r, event=e, hash=make_record(e, SECRET)["hash"]), "bad signature")
        self.rejects(dict(self.r, kid="sha256:" + "0" * 64), "unknown kid")
        self.rejects(dict(self.r, sig="!!"), "not base64")
        self.rejects(dict(self.r, v=1), "not a v2 record")
        self.rejects(dict(self.r, kid=["x"]), "not a v2 record")
        self.rejects(self.r, "unknown kid", keys=[crypto.spki(crypto.generate()[1])])

    def test_domain_tags(self):
        body = {"hash": H}
        sig = crypto.sign(SECRET, sigmsg.message("approval", body))
        for p in sigmsg.PURPOSES:
            self.assertIs(crypto.verify_v2("ed25519", KEY, sigmsg.message(p, body), sig), p == "approval", p)
        with self.assertRaises(ValueError):
            sigmsg.message("bogus", body)
        with self.assertRaises(ValueError):
            sigmsg.message("record", {"t": "tracekit.approval.v2"})

    def test_v1_message_is_the_frozen_one(self):
        self.assertIs(sigmsg.sig_message_v1, core.sig_message)


NEW_TYPES = {
    "run.registered": {"agent": {"name": "a"}, "identity": {"scheme": "uid", "subject": "1000", "attested": True}},
    "run.closing": {"reason": "idle_timeout"},
    "run.final": {"head_run_seq": 3, "head_hash": H},
    "approval.request": {"approval_id": "ap-1", "policy_hash": H, "rule_ids": ["TK-1"],
                         "expires_at": "2026-10-09T12:05:00.000000Z", "requester": "svc-a", "decision_id": "dec-1",
                         "binding": {"v": 1, "approval_id": "ap-1", "tenant": "acme", "run_id": "run-1",
                                     "tool_call_id": "call_1", "attempt": 0, "tool": "pay",
                                     "args_commitment": "hmac-sha256:" + "0" * 64, "args_source": "parsed",
                                     "policy_hash": H, "nonce": "0" * 32, "expires_at": "2026-10-09T12:05:00.000000Z"},
                         "binding_digest": H},
    "approval.consumed": {"approval_id": "ap-1"},
    "approval.expired": {"approval_id": "ap-1"},
    "approval.refused": {"tool_use_id": "call_1", "rule_ids": ["TK-APPROVAL-REQUIRED"], "reason": "none requested"},
    "approval.binding_mismatch": {"approval_id": "ap-1", "tool_use_id": "call_1",
                                  "approved_commitment": "hmac-sha256:" + "0" * 64,
                                  "args_commitment": "hmac-sha256:" + "1" * 64},
    "approval.abandoned": {"approval_id": "ap-1", "reason": "the run state could not be resumed"},
    "state.write": {"store": "langgraph", "key": "thread-1", "prev_digest": None, "digest": "hmac-sha256:" + "ab" * 32},
    "signer.epoch": {"keys": [{"kid": H, "alg": "ed25519", "spki": "MCowBQYDK2VwAyEA"}]},
    "key.retire": {"kid": H, "last_seq": 9},
    "log.closed": {"final_seq": 9},
    "reconcile.hook_missing": {"layers": ["L2", "L3"], "detail": "no L2 record for an L3 tool use"},
    "reconcile.fabricated": {"layers": ["L2"]},
    "reconcile.args_mismatch": {"layers": ["L2", "L3"]},
    "reconcile.result_without_call": {"layers": ["L2"]},
    "reconcile.unexplained_effect": {"layers": ["L6"]},
    "reconcile.args_unparseable": {"layers": ["L3"]},
    "refusal.summary": {"code": "quota_exceeded", "count": 12, "from_ts": "2026-10-09T12:00:00.000000Z",
                        "to_ts": "2026-10-09T12:01:00.000000Z"},
}


class TestSchemaV2(unittest.TestCase):
    def test_every_new_type(self):
        self.assertLessEqual(set(NEW_TYPES), set(schema.schema(schema.V2)["properties"]["type"]["enum"]))
        for t, data in NEW_TYPES.items():
            with self.subTest(t):
                self.assertEqual(schema.validate(ev(t, data)), [])
                self.assertTrue(schema.validate(ev(t, {**data, "extra": 1})))
                missing = dict(data)
                missing.pop(next(iter(data)))
                self.assertTrue(schema.validate(ev(t, missing)))

    def test_new_fields(self):
        good = ev(tenant="acme", tenant_attested=False, principal="u@x", principal_attested=False, request_id="r-1",
                  stream="s-1", client_seq=4, tool_call_id="call_1", attempt=0, step=2, run_seq=1, run_prev_hash=H,
                  capture_layer="L2", tier="T1", args_commitment="hmac-sha256:" + "0" * 64, args_source="parsed",
                  log_id="f" * 32, engine="tracekit-policy@2.0.0")
        self.assertEqual(schema.validate(good), [])
        for k, bad in (("tier", "T4"), ("capture_layer", "L7"), ("tenant", "a b"), ("client_seq", 2 ** 53),
                       ("engine", "noversion"), ("prev_hash", "0" * 64)):
            self.assertTrue(schema.validate(dict(good, **{k: bad})), k)

    def test_gap_kind_is_an_enum(self):
        self.assertEqual(schema.validate(ev("capture.gap", {"reason": "x", "kind": "reconcile.fabricated"})), [])
        self.assertTrue(schema.validate(ev("capture.gap", {"reason": "x", "kind": "counter_jump"})))
        self.assertEqual(schema.validate(dict(ev("capture.gap", {"reason": "x", "kind": "counter_jump"}),
                                              schema_version="tracekit.event.v1", prev_hash="0" * 64)), [])

    def test_full_match_ascii(self):
        for k, bad in (("id", "0" * 31 + "1\n"), ("ts", "2026-10-09T12:00:00.00000١Z")):
            self.assertTrue(schema.validate(ev(**{k: bad})), k)
            v1 = dict(ev(**{k: bad}), schema_version="tracekit.event.v1", prev_hash="0" * 64)
            warns = []
            self.assertEqual(schema.validate(v1, warns), [], k)
            self.assertEqual(len(warns), 1, k)
        warns = []
        self.assertEqual(schema.validate(dict(ev(), schema_version="tracekit.event.v1", prev_hash="0" * 64), warns), [])
        self.assertEqual(warns, [])

    def test_every_string_and_array_is_bounded(self):
        def walk(n, path):
            if isinstance(n, dict):
                ts = n.get("type") if isinstance(n.get("type"), list) else [n.get("type")]
                if "string" in ts:
                    self.assertIn("maxLength", n, path)
                if "array" in ts:
                    self.assertIn("maxItems", n, path)
                for k, v in n.items():
                    walk(v, f"{path}/{k}")
            elif isinstance(n, list):
                for i, v in enumerate(n):
                    walk(v, f"{path}/{i}")
        walk(schema.schema(schema.V2), "#")

    def test_unknown_keyword_raises(self):
        s = {"type": "string", "maxLenght": 3}
        with self.assertRaisesRegex(ValueError, "maxLenght"):
            schema._check("abcd", s, s, "v", [])


if __name__ == "__main__":
    unittest.main()
