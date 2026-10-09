"""Signer-side redaction and salted commitments (tracekit/signer/service.py): what reaches the store, the redaction
manifest, client pre-redaction, dictionary attacks on commitments and `reveal`, and the v2 schema's digest fields."""
import hmac
import json
import os
import shutil
import tempfile
import unittest

from test_rpc_contract import Harness
from tracekit import schema
from tracekit.format.canon import event_hash, loads_strict
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc

SECRET = "sk-ant-" + "Zq8" * 10   # a redaction fixture
# deny `pay` when its arguments hold an Anthropic key, ask for `wire`, allow everything else
POLICY = Engine({"deny": [{"id": "T-KEY", "tool": "pay", "pattern": "sk-ant-"}],
                 "ask": [{"id": "T-WIRE", "tool": "wire", "pattern": "^"}]})
# hashes of the log and the policy, never of agent content
NOT_CONTENT = {"/properties/prev_hash", "/properties/run_prev_hash", "/$defs/run_start/properties/policy/properties/hash",
               "/$defs/policy_decision/properties/policy_hash", "/$defs/trace_tamper/properties/before/properties/hash",
               "/$defs/run_final/properties/head_hash", "/$defs/approval_request/properties/policy_hash",
               "/$defs/approval_request/properties/binding/properties/policy_hash",
               "/$defs/approval_request/properties/binding_digest", "/$defs/signer_epoch/properties/keys/items/properties/kid",
               "/$defs/key_retire/properties/kid"}


class SignerPrivacy(Harness, unittest.TestCase):
    def make_signer(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        s = svc.SignerService(self.dir, policy=POLICY)
        self.addCleanup(s.close)
        return s

    def records(self):
        with open(os.path.join(self.dir, "store", "records.jsonl"), "rb") as f:
            return [json.loads(line)["event"] for line in f]

    def result(self, tcid):
        [e] = [e for e in self.records() if e["type"] == "tool.result" and e["tool_call_id"] == tcid]
        return e

    def stored(self):
        out = b""
        for root, _, names in os.walk(self.dir):
            for n in names:
                with open(os.path.join(root, n), "rb") as f:
                    out += f.read()
        return out

    def test_a_secret_in_a_result_never_reaches_the_store(self):
        self.register()
        self.complete(*self.decide(), result={"stdout": f"key {SECRET}"}, error=f"failed with {SECRET}")
        self.signer.close()
        self.assertNotIn(SECRET.encode(), self.stored())
        data = self.result("tc-1")["data"]
        self.assertEqual(data["redaction"], {"rules": ["anthropic_key"], "count": 2, "client_claimed": False})
        self.assertTrue(data["output"]["redacted"])
        for e in self.records():
            self.assertEqual(schema.validate(e), [], e)

    def test_dotenv_values_are_redacted_when_the_call_touched_a_env_file(self):
        self.register()
        for tcid, command in (("tc-1", "cat .env"), ("tc-2", "cat notes.txt")):
            self.complete(*self.decide("Bash", {"command": command}, tcid), result={"stdout": "COLOR=blue"})
        self.assertEqual(self.result("tc-1")["data"]["redaction"]["rules"], ["dotenv"])
        self.assertEqual(self.result("tc-2")["data"]["redaction"]["count"], 0)

    def test_a_client_redaction_claim_is_checked_and_never_trusted(self):
        self.register()
        claim = {"rules": ["openai_key"], "count": 1}
        self.complete(*self.decide(), result={"a": "[REDACTED:openai_key]", "b": SECRET}, redacted=True, redaction=claim)
        self.complete(*self.decide(tcid="tc-2"), result={"a": "[REDACTED:openai_key]"}, redacted=True, redaction=claim)
        self.assertNotIn(SECRET.encode(), self.stored())
        self.assertEqual(self.result("tc-1")["data"]["redaction"],
                         {"rules": ["anthropic_key"], "count": 1, "client_claimed": True, "client": claim,
                          "client_redaction_incomplete": True})
        self.assertEqual(self.result("tc-2")["data"]["redaction"],
                         {"rules": [], "count": 0, "client_claimed": True, "client": claim})

    def test_the_approver_sees_the_signers_copy_redacted(self):
        self.register()
        self.decide("wire", {"to": "acct-1", "memo": SECRET})
        aid = self.call("approval_request", self.run_req(tool_call_id="tc-1", reason=f"use {SECRET}"))["approval_id"]
        got = self.call("approval_get", {"approval_id": aid})
        self.assertEqual((got["args"], got["reason"]), ({"to": "acct-1", "memo": "[REDACTED:anthropic_key]"},
                                                        "use [REDACTED:anthropic_key]"))

    def test_a_raw_approver_copy_stays_valid_json(self):
        self.register()
        self.decide("wire", '{"url":"postgres://u:p@db/x","to":"acct-1"}', args_source="raw")
        aid = self.call("approval_request", self.run_req(tool_call_id="tc-1"))["approval_id"]
        got = self.call("approval_get", {"approval_id": aid})
        self.assertEqual(loads_strict(got["args"]), {"url": "[REDACTED:connection_string]", "to": "acct-1"})

    def test_a_model_error_is_redacted(self):
        self.register()
        self.call("model_event", self.ev(provider="p", model="m", phase="response", error=f"bad key {SECRET}"))
        self.signer.close()
        self.assertNotIn(SECRET.encode(), self.stored())

    def test_policy_decides_on_the_unredacted_arguments(self):
        self.register()
        _, d = self.decide("pay", {"key": SECRET})
        self.assertEqual((d["decision"], d["rule_ids"]), ("deny", ["T-KEY"]))

    def test_a_dictionary_attack_needs_the_revealed_salt_of_that_record(self):
        self.register()
        pins = {"tc-1": "7310", "tc-2": "2964"}
        for tcid, pin in pins.items():
            self.complete(*self.decide("unlock", {"pin": pin}, tcid), result={"pin": pin})
        self.signer.close()
        candidates = {f"{i:04d}": event_hash({"result": {"pin": f"{i:04d}"}}) for i in range(10000)}

        def crack(commitment, salt=None):
            return [pin for pin, digest in candidates.items() if commitment in (
                digest, salt and "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest())]
        a, b = (self.result(t) for t in pins)
        self.assertEqual(crack(a["data"]["output"]["hash"]), [])
        salt = bytes.fromhex(svc.reveal(self.dir, a["seq"])["salt"])
        self.assertEqual(crack(a["data"]["output"]["hash"], salt), ["7310"])
        self.assertEqual(crack(b["data"]["output"]["hash"], salt), [])
        [decision] = [e for e in self.records() if e["type"] == "policy.decision" and e["tool_call_id"] == "tc-1"]
        self.assertEqual(crack(decision["data"]["args_commitment"], salt), [])   # its own salt, not the result's
        args = {f"{i:04d}": event_hash({"tool": "unlock", "args": {"pin": f"{i:04d}"}}) for i in range(10000)}
        salt = bytes.fromhex(svc.reveal(self.dir, decision["seq"])["salt"])
        self.assertEqual([p for p, d in args.items() if decision["data"]["args_commitment"] ==
                          "hmac-sha256:" + hmac.new(salt, d.encode(), "sha256").hexdigest()], ["7310"])

    def test_client_digests_are_published_as_commitments(self):
        self.register()
        digest = "sha256:" + "0" * 64
        self.call("state_write", self.ev(key="k", value_digest=digest))
        self.call("model_event", self.ev(provider="p", model="m", phase="response", content_digest=digest))
        self.signer.close()
        for e in self.records():
            if e["type"] in ("state.write", "model.exchange"):
                commitment = e["data"].get("digest") or e["data"]["content_digest"]
                salt = bytes.fromhex(svc.reveal(self.dir, e["seq"])["salt"])
                self.assertEqual(commitment, "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest())

    def test_reveal_refuses_records_without_commitments(self):
        self.register()
        self.signer.close()
        with self.assertRaisesRegex(ValueError, "no commitments"):
            svc.reveal(self.dir, 0)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            svc.reveal(self.dir, 999)


class SchemaSweep(unittest.TestCase):
    def test_every_digest_field_is_a_commitment(self):
        def walk(x, path):
            if isinstance(x, dict):
                if x.get("$ref") == "#/$defs/hash":
                    yield path
                for k, v in x.items():
                    yield from walk(v, f"{path}/{k}")
            elif isinstance(x, list):
                for v in x:
                    yield from walk(v, path)
        digests = {p.replace("/oneOf", "") for p in walk(schema.schema(schema.V2), "")}
        self.assertEqual(digests - NOT_CONTENT, set())


if __name__ == "__main__":
    unittest.main()
