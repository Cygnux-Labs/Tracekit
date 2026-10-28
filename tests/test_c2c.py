"""Latent transfers through C2C (tracekit/integrations/c2c.py): a sharer's KV cache fused into a receiver's, recorded
and gated as an a2a:transfer before the fuser runs; the kept copy in the content vault; and `tracekit why transfer`
(tracekit/why/transfer.py), the receiver re-run with and without it. A tiny fake RosettaModel and fuser stand in for
C2C (no torch, no downloads): their tensors are float arrays."""
import contextlib
import hashlib
import io
import json
import os
import threading
import time
import unittest
from array import array
from unittest import mock

from adapter_contract import _serve, tmpdir
from test_gateway import AGENT
from test_signer_service import records
from test_why_signed_replay import As
from tracekit.bundle_v2 import export
from tracekit.format.canon import canonical, event_hash
from tracekit.integrations import c2c
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client, Refused, RunHandle, SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS
from tracekit.verify import v2
from tracekit.why import cli as why_cli
from tracekit.why.signed import EvidenceAlert
from tracekit.why.transfer import effect


class Projector:
    """A fake C2C fuser: the receiver's key and value plus its weight times the sharer's."""

    def __init__(self, w):
        self.w, self.calls = array("f", [w]), 0

    def state_dict(self):
        return {"w": self.w}

    def forward(self, source_kv, target_kv):
        self.calls += 1
        return tuple(array("f", [t + self.w[0] * s for s, t in zip(sk, tk)]) for sk, tk in zip(source_kv, target_kv))


class Rosetta:
    """A fake RosettaModel: the receiver is model 0, the sharer model 1; layer i of each through projector i."""

    def __init__(self, w=(0.5, 2.0)):
        self.base_model_idx = 0
        self.projector_list = [Projector(x) for x in w]
        self.projector_dict = {0: {1: {0: [(0, 0)], 1: [(1, 1)]}}}


def cache(*layers):
    return [(array("f", k), array("f", v)) for k, v in layers]


SHARER = cache(([1, 2], [3, 4]), ([5, 6], [7, 8]))
EMPTY = cache(([0, 0], [0, 0]), ([0, 0], [0, 0]))
RAW = b"".join(t.tobytes() for kv in SHARER for t in kv)
IDS = {"sender": "qwen-0.5b@1", "receiver": "qwen3-0.6b@1"}
# the weights hash as docs/c2c.md defines it: {projector index: {parameter: [dtype, shape, sha256 of its bytes]}}
TREE = {str(i): {"w": ["f", [1], hashlib.sha256(array("f", [w]).tobytes()).hexdigest()]} for i, w in enumerate((0.5, 2.0))}
WEIGHTS = "sha256:" + hashlib.sha256(canonical(TREE)).hexdigest()
ROUTE = "qwen-0\\.5b@1->qwen3-0\\.6b@1 via c2c-fuser@"
POLICY = {"tools": {"a2a:*": "a2a"},
          "deny": [{"id": "R-TRIPLE", "class": "a2a", "field": "route", "pattern": ".",
                    "unless": f"^({ROUTE}1|{ROUTE}ask)$"},   # only the listed (sender, receiver, fuser) triples
                   {"id": "R-WEIGHTS", "class": "a2a", "field": "weights", "pattern": ".", "unless": f"^{WEIGHTS}$"},
                   {"id": "R-SIZE", "class": "a2a", "field": "size", "pattern": "^[0-9]{3,}$"}],   # 100 bytes or more
          "ask": [{"id": "R-NEW-FUSER", "class": "a2a", "field": "projector", "pattern": "@ask$"}]}


def receiver(sent, model=Rosetta()):
    """A tiny fake receiver model: it reads a code from its cache, which only the sharer's cache gives it."""
    total = sum(sum(t) for kv in (EMPTY if sent is None else c2c.fused(model, sent, EMPTY, c2c.layer_map(model)))
                for t in kv)
    return f"the code is {total:g}" if total else "I don't know the code"


class Fuse(unittest.TestCase):
    content = None

    def setUp(self):
        p = mock.patch.object(c2c, "RosettaModel", Rosetta)   # C2C is "installed": the fake is its RosettaModel
        p.start()
        self.addCleanup(p.stop)
        self.dir = tmpdir(self)
        grants = sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR) + [svc.CONTENT_READ]
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), grace_s=0, content=self.content,
                                   authorize={"token:http": grants,
                                              svc._dev_identity(): sorted(svc.DEFAULT_GRANTS | {svc.CONTENT_READ})})
        self.closed = False
        self.addCleanup(self.close)
        self.path = _serve(self, self.s.handle_frame)
        self.run = Client(self.path).run("fuser")
        self.model = Rosetta()

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def fuse(self, source=SHARER, projector="c2c-fuser@1", **kw):
        return c2c.fuse(self.run, self.model, source, EMPTY, projector=projector, **IDS, **kw)

    def records(self):
        return list(self.s.log.storage.iter_run("default", self.run.run_id))

    def verified(self):
        """The run closed, exported and verified; its events."""
        self.run.close()
        self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", self.run.run_id, self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, [c for c in rep.checks if c["status"] != "ok"])
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run.run_id]

    def assertNotStored(self, *needles):
        for root, _, files in os.walk(self.dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    data = f.read()
                for n in needles:
                    self.assertNotIn(n, data, name)


class Gate(Fuse):
    def test_an_allowed_triple_is_fused_and_its_record_commits_to_what_was_measured(self):
        out = self.fuse()
        self.assertEqual([[list(t) for t in kv] for kv in out], [[[0.5, 1], [1.5, 2]], [[10, 12], [14, 16]]])
        evs = self.verified()
        [d] = [e["data"] for e in evs if e["type"] == "policy.decision"]
        self.assertEqual((d["tool"], d["decision"]), ("a2a:transfer", "allow"))
        self.assertTrue([e for e in evs if e["type"] == "tool.result" and e["data"]["ok"]])
        # who claimed what to whom through which fuser, and what Tracekit measured of what was sent
        args = {**IDS, "modality": "kv-cache", "projector": "c2c-fuser@1",
                "claimed": ["modality", "projector", "receiver", "sender"],
                "size": 32, "digest": "sha256:" + hashlib.sha256(RAW).hexdigest(), "weights": WEIGHTS,
                "layers": [[0, 0, 0], [1, 1, 1]], "layout": [["f", [2], 8]] * 4,
                "measured": ["digest", "layers", "layout", "size", "weights"]}
        self.assertTrue(self.s._opens(d["args_commitment"], d["decision_id"],
                                      event_hash({"tool": "a2a:transfer", "args": args})))
        self.assertNotStored(RAW, RAW.hex().encode())   # never the payload

    def test_a_triple_the_policy_does_not_list_is_refused_and_nothing_is_fused(self):
        with self.assertRaisesRegex(Refused, "R-TRIPLE"):
            self.fuse(projector="c2c-fuser@2")
        self.assertEqual([p.calls for p in self.model.projector_list], [0, 0])

    def test_a_fuser_with_other_weights_is_refused_under_the_same_claimed_id(self):
        self.model = Rosetta(w=(0.5, 3.0))
        with self.assertRaisesRegex(Refused, "R-WEIGHTS"):
            self.fuse()
        self.assertEqual([p.calls for p in self.model.projector_list], [0, 0])

    def test_a_cache_over_the_size_rule_is_refused(self):
        with self.assertRaisesRegex(Refused, "R-SIZE"):
            self.fuse(cache(([1] * 8, [2] * 8), ([3] * 8, [4] * 8)))   # 128 bytes

    def test_an_asked_triple_waits_for_a_person(self):
        for answer, held, after in (("approve", 0, 1), ("reject", 1, 1)):   # fuser calls while held and after
            got = {}

            def fuse():
                try:
                    got["out"] = self.fuse(projector="c2c-fuser@ask")
                except Refused as e:
                    got["out"] = e
            t = threading.Thread(target=fuse)
            t.start()
            for _ in range(500):
                aids = [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {"run_id": self.run.run_id})[
                    "approvals"] if a["state"] == "requested"]
                if aids:
                    break
                time.sleep(0.01)
            self.assertEqual([p.calls for p in self.model.projector_list], [held] * 2)
            self.s.call(AGENT, "approval_decide", {"request_id": answer, "approval_id": aids[0], "decision": answer})
            t.join(20)
            self.assertEqual([p.calls for p in self.model.projector_list], [after] * 2)
            if answer == "approve":
                self.assertEqual(list(got["out"][1][0]), [10, 12])
            else:
                self.assertIsInstance(got["out"], Refused)
                self.assertIn("approval rejected", str(got["out"]))

    def test_the_signer_unreachable_fails_closed_whatever_the_fail_mode(self):
        class Down:
            def call(self, method, req):
                raise SignerUnavailable("down")
        run = RunHandle(Down(), {"run_id": "r", "run_token": "t", "fail_modes": {"default": "open"}})
        with self.assertWarns(UserWarning), self.assertRaisesRegex(Refused, "signer unavailable"):
            c2c.fuse(run, self.model, SHARER, EMPTY, projector="c2c-fuser@1", **IDS)
        self.assertEqual([p.calls for p in self.model.projector_list], [0, 0])

    def test_without_c2c_fuse_says_what_to_install(self):
        with mock.patch.object(c2c, "RosettaModel", None), self.assertRaisesRegex(ImportError, "thu-nics/C2C"):
            self.fuse()
        with self.assertRaisesRegex(TypeError, "RosettaModel"):
            c2c.fuse(self.run, object(), SHARER, EMPTY, projector="c2c-fuser@1", **IDS)


class Vault(Fuse):
    content = {"retain": True}

    def effect(self, recv=receiver, **kw):
        return effect(As(self.s, AGENT), self.records(), recv, "check", **kw)

    def test_a_kept_cache_is_encrypted_in_the_vault_and_opens_its_commitment(self):
        self.fuse(keep=True)
        [res] = [r for r in self.records() if r["event"]["type"] == "tool.result"]
        [item] = As(self.s, AGENT).content_get({"run_id": self.run.run_id, "seqs": [res["event"]["run_seq"]],
                                                "purpose": "check"})["items"]
        self.assertEqual(bytes.fromhex(item["content"]["result"]["payload"]), RAW)
        self.assertIn("salt", item)   # it opens the result's commitment
        self.verified()
        self.assertNotStored(RAW, RAW.hex().encode())   # in the store only as ciphertext

    def test_the_effect_check_says_how_much_the_transfer_changed_the_answer(self):
        self.fuse(keep=True)
        r = self.effect()
        self.assertEqual((r["with"], r["without"]), ("the code is 57", "I don't know the code"))
        self.assertGreater(r["change"], 0.3)
        self.assertIn(f"changed the receiver's answer by {r['change']:.0%}", r["sentence"])
        self.assertEqual((r["sender"], r["receiver"]), (IDS["sender"], IDS["receiver"]))
        same = self.effect(lambda sent: "I don't know the code")
        self.assertEqual((same["change"], same["sentence"]), (0, "The transfer did not change the receiver's answer."))
        accessed = [x["event"]["data"] for x in self.s.log.storage.iter_run("default", "tracekit/signer")
                    if x["event"]["type"] == "content.accessed"]
        self.assertEqual([a["purpose"] for a in accessed], ["check", "check"])   # each read is a signed record

    def test_the_check_runs_from_the_command_line(self):
        self.fuse(keep=True)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": self.path}), contextlib.redirect_stdout(out):
            self.assertEqual(why_cli.main(["transfer", "--run", self.run.run_id, "--store", self.dir,
                                           "--receiver", "test_c2c:receiver"]), 0)
        self.assertRegex(out.getvalue(), r"transfer \d+ qwen-0.5b@1 -> qwen3-0.6b@1 \(names claimed by the caller\): "
                                         r"change 0\.\d+\n  The transfer changed the receiver's answer by \d+%")

    def test_a_transfer_not_kept_has_nothing_to_measure(self):
        self.fuse()
        with self.assertRaisesRegex(ValueError, "holds no copy of what was sent"):
            self.effect()

    def test_a_copy_that_is_not_what_the_transfer_recorded_is_an_evidence_alert(self):
        args = {**IDS, "modality": "bytes", "projector": "c2c-fuser@1", "size": 3,
                "digest": "sha256:" + hashlib.sha256(b"abc").hexdigest()}
        self.run.decide("tx-1", "a2a:transfer", args)
        self.assertTrue(self.run.approval_consume("tx-1", "a2a:transfer", args)["ok"])
        self.run.complete("tx-1", result={"payload": b"abd".hex()})   # one payload recorded, another kept
        with self.assertRaisesRegex(EvidenceAlert, "not the size and digest the transfer recorded"):
            self.effect()
