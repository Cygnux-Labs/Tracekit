"""Proof-carrying messages through a real in-process signer (#436): who may call the PCM RPCs, pcm_sign, root grants
from a person's consumed approval of a `pcm.grant` call, delegation, evidence with inclusion proofs, and the bundle of a
run that sent messages."""
import base64
import hashlib
import hmac
import itertools
import json
import os
import time
import unittest
from unittest import mock

import test_signer_service as ts
from tracekit import merkle, pcm
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import logkey, service as svc
from tracekit.signer.rpc_schema import REQUESTS, RESPONSES, RPCError, validate
from tracekit.verify import v2

A, B, ALICE = (CallerIdentity("uid", u, True) for u in ("990101", "990102", "990001"))
TAILER = CallerIdentity("uid", "990105", True)   # a run token is delegated to it
REVIEWER, OPS = CallerIdentity("token", "reviewer", True), CallerIdentity("token", "ops", True)
DOC = {"pcm_schema": 0, "name": "refund.request",
       "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
                  "order": {"type": "int", "min": 1, "max": 999999999}}}
REF = pcm.schema_ref(DOC)
CAVEATS = [{"field": "amount", "op": "<=", "value": 20000}, {"field": "order", "op": "==", "value": 81}]
NARROWER = [{"field": "amount", "op": "<=", "value": 15000}, {"field": "order", "op": "==", "value": 81}]
ASK = {"ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^"}, {"id": "PAY", "tool": "pay", "pattern": "^"}]}
APPROVALS = {"approvers": ["uid:990001", "uid:990102"], "persons": {"uid:990001": "alice", "uid:990102": "bob"},
             "agents": ["token:reviewer"]}
AUTHORIZE = {"token:reviewer": sorted(svc.AGENT_METHODS), "token:ops": ["run_quarantine", "run_hold"],
             "uid:990105": ["read", "pcm_sign", "pcm_evidence"]}
_ids = itertools.count()


def rid():
    return f"p{next(_ids)}"


class Case(unittest.TestCase):
    policy, approvals = ASK, APPROVALS

    def setUp(self):
        self.dir = ts.tmpdir(self)
        p = mock.patch.object(svc, "CHECKPOINT_S", 3600.0)   # checkpoints only when a test asks for one
        p.start()
        self.addCleanup(p.stop)
        self.s = self.open()
        self.seqs = itertools.count()
        self.run = self.register(A)
        self.trust = {"logs": [self.s.vkey], "algs": ["ed25519"]}

    def open(self):
        s = svc.SignerService(self.dir, policy=Engine(self.policy), approvals=self.approvals, authorize=AUTHORIZE)
        self.addCleanup(s.close)
        return s

    def register(self, who):
        r = self.s.call(who, "register_run", {"request_id": rid(), "agent": {"name": "a"}})
        return {"run_id": r["run_id"], "run_token": r["run_token"]}

    def call(self, method, who=A, run=None, **req):
        """`method` as `who`, on `run` (default A's run; {} for none), with a fresh request_id where it takes one."""
        full = {**({"request_id": rid()} if "request_id" in REQUESTS[method]["properties"] else {}),
                **(self.run if run is None else run), **req}
        out = self.s.call(who, method, full)
        self.assertEqual(validate(RESPONSES[method], out), [], out)
        return out

    def refused(self, code, method, who=A, run=None, **req):
        with self.assertRaises(RPCError) as cm:
            self.call(method, who, run, **req)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception.message

    def body(self, frm=None, **kw):
        return {"from": frm or {"agent": "uid:990101", "run": self.run["run_id"], "tenant": "default"},
                "to": {"agent": "uid:990102"}, "intent": {"type": REF, "args": {"amount": 12000, "order": 81}}, **kw}

    @staticmethod
    def args(**kw):
        return {"subject": "uid:990101", "intent": REF, "caveats": CAVEATS, "expires_at": svc._iso(time.time() + 3600),
                "delegable": True, **kw}

    def decide(self, args, tcid="g1"):
        return self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool="pcm.grant",
                         args_source="parsed", args=args)

    def approve(self, args, who=ALICE, tcid="g1", decision="approve", consume=True):
        """Decide `pcm.grant` with `args`, ask, answer and consume; (approval id, decision id)."""
        d = self.decide(args, tcid)
        self.assertEqual(d["decision"], "ask")
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.call("approval_decide", who, {}, approval_id=aid, decision=decision)
        if consume:
            self.assertTrue(self.call("approval_consume", tool_call_id=tcid, tool="pcm.grant", args_source="parsed",
                                      args=args)["ok"])
        return aid, d["decision_id"]

    def root(self, **kw):
        args = self.args(**kw)
        self.approve(args)
        return self.call("pcm_grant", tool_call_id="g1", args=args)["grant"]

    def records(self, run=None):
        return self.call("read", run=run, limit=1000)["events"]


class TestSign(Case):
    def test_signed_as_the_run_and_recorded_without_args(self):
        out = self.call("pcm_sign", message=self.body())
        msg = out["message"]
        self.assertEqual(pcm.verify(msg, self.trust, [DOC])["verdict"], "accept")
        self.assertEqual(msg["from"], {"agent": "uid:990101", "run": self.run["run_id"], "tenant": "default"})
        self.assertLessEqual(abs(pcm._epoch(msg["ts"]) - time.time()), 60)
        [rec] = [e for e in self.records() if e["type"] == "ext"]
        self.assertEqual((rec["run_seq"], rec["data"]), (out["run_seq"], {
            "name": "pcm.sent", "message": event_hash(msg), "id": msg["id"], "to": "uid:990102", "intent": REF}))
        self.assertNotIn("12000", json.dumps(rec))

    def test_a_retry_returns_the_same_message(self):
        req = {"request_id": rid(), **self.run, "message": self.body()}
        out = self.s.call(A, "pcm_sign", req)
        self.assertEqual(out, self.s.call(A, "pcm_sign", dict(req)))
        self.assertEqual(len([e for e in self.records() if e["type"] == "ext"]), 1)
        again = self.call("pcm_sign", message=self.body())["message"]   # a new request: a new id and nonce
        self.assertTrue(again["id"] != out["message"]["id"] and again["nonce"] != out["message"]["nonce"])

    def test_never_as_another(self):
        other = self.register(A)   # another run of the same agent
        for frm in ({"agent": "uid:990102", "run": self.run["run_id"], "tenant": "default"},
                    {"agent": "uid:990101", "run": other["run_id"], "tenant": "default"},
                    {"agent": "uid:990101", "run": self.run["run_id"], "tenant": "acme"}):
            with self.subTest(frm=frm):
                self.assertIn("own agent (uid:990101", self.refused("forbidden", "pcm_sign", message=self.body(frm)))
        token = self.call("delegate_run", identity="uid:990105")["run_token"]
        tailer = {"run_id": self.run["run_id"], "run_token": token}
        self.assertTrue(self.call("read", TAILER, tailer)["events"])   # the token works for what it was granted
        self.refused("forbidden", "pcm_sign", TAILER, tailer, message=self.body())
        self.refused("forbidden", "pcm_sign", REVIEWER, message=self.body())   # an agent approver
        self.assertEqual([e for e in self.records() if e["type"] == "ext"], [])

    def test_the_agent_sets_none_of_the_signer_fields(self):
        for extra in ({"ts": svc._iso(time.time())}, {"nonce": "0" * 32}, {"id": "0" * 32}, {"pcm": 0},
                      {"sig": {"key": "k", "sig": "s"}}, {"t": "tracekit.checkpoint.v2"}, {"colour": "red"}):
            with self.subTest(extra=extra):
                self.refused("invalid_request", "pcm_sign", message=self.body(**extra))

    def test_quarantined_and_closed_runs(self):
        self.s.call(OPS, "run_quarantine", {"request_id": rid(), "run_id": self.run["run_id"]})
        self.assertIn("quarantined", self.refused("forbidden", "pcm_sign", message=self.body()))
        self.call("close_run")
        self.refused("run_closed", "pcm_sign", message=self.body())


class TestHeld(Case):
    """A held run passes no new authority on (sign, grant, delegate) while a person looks; it may still read."""

    def setUp(self):
        super().setUp()
        self.grant_args, self.parent = self.args(), self.root()
        self.approve(self.grant_args, tcid="g2")   # consumed before the hold: only the hold refuses its grant
        self.s.call(OPS, "run_hold", {"request_id": rid(), "run_id": self.run["run_id"]})

    def held(self, method, **req):
        self.assertIn("is held by incident", self.refused("forbidden", method, **req))

    def test_sign(self):
        self.held("pcm_sign", message=self.body())

    def test_grant(self):
        self.held("pcm_grant", tool_call_id="g2", args=self.grant_args)

    def test_delegate(self):
        self.held("pcm_delegate", parent=self.parent, subject="uid:990102", caveats=NARROWER, delegable=True,
                  expires_at=self.parent["expires_at"])

    def test_evidence_still_reads(self):
        self.assertEqual(self.call("pcm_evidence", run_seqs=[0])["pending"], [0])


class TestGrant(Case):
    def test_from_a_person_approval(self):
        args = self.args()
        aid, _ = self.approve(args)
        out = self.call("pcm_grant", tool_call_id="g1", args=args)
        g = out["grant"]
        self.assertIsNone(pcm.check_sig(g, "pcm-grant", self.trust))
        self.assertEqual(g["issuer"], {"kind": "person", "id": "uid:990001", "person": "alice",
                                       "run": self.run["run_id"], "tenant": "default", "approval_id": aid})
        self.assertEqual({k: g[k] for k in args}, args)
        self.assertIsNone(g["parent"])
        [rec] = [e for e in self.records() if e["type"] == "ext"]
        self.assertEqual((rec["run_seq"], rec["data"]), (out["run_seq"], {
            "name": "pcm.grant", "grant": event_hash(g), "subject": "uid:990101", "intent": REF,
            "approval_id": aid}))
        msg = self.call("pcm_sign", message=self.body(grants=[g]))["message"]
        out = pcm.verify(msg, self.trust, [DOC])
        self.assertEqual((out["verdict"], out["grants"]["root"]), (
            "accept", {"kind": "person", "id": "uid:990001", "person": "alice"}))

    def test_delegable_comes_from_the_approved_args(self):
        self.assertFalse(self.root(delegable=False)["delegable"])

    def test_refused_without_a_consumed_approval_of_these_args(self):
        args = self.args()
        self.approve(args, decision="reject", consume=False)
        self.assertIn("approved and consumed", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))
        self.approve(args, tcid="g2", consume=False)
        self.refused("forbidden", "pcm_grant", tool_call_id="g2", args=args)   # approved, not consumed
        self.refused("forbidden", "pcm_grant", tool_call_id="nope", args=args)
        self.approve(args, tcid="g3")
        self.refused("args_mismatch", "pcm_grant", tool_call_id="g3", args=dict(args, delegable=False))
        self.refused("forbidden", "pcm_grant", tool_call_id="g3", attempt=1, args=args)
        self.call("pcm_grant", tool_call_id="g3", args=args)

    def test_only_another_tool_call_is_no_grant(self):
        args = self.args()
        self.assertEqual(self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id="g1", tool="pay",
                                   args_source="parsed", args=args)["decision"], "ask")
        aid = self.call("approval_request", tool_call_id="g1")["approval_id"]
        self.call("approval_decide", ALICE, {}, approval_id=aid, decision="approve")
        self.call("approval_consume", tool_call_id="g1", tool="pay", args_source="parsed", args=args)
        self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args)

    def test_the_approver_is_not_the_subject(self):
        args = self.args(subject="uid:990102")
        self.approve(args, who=B)
        self.assertIn("other than", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))

    def test_expiry_within_a_day(self):
        for t in (time.time() + svc.MAX_GRANT_S + 600, time.time() - 1):
            args = self.args(expires_at=svc._iso(t))
            tcid = f"g{t:.0f}"
            self.approve(args, tcid=tcid)
            with self.subTest(expires_at=args["expires_at"]):
                self.assertIn("within 24 h", self.refused("forbidden", "pcm_grant", tool_call_id=tcid, args=args))

    def test_one_approval_one_grant(self):
        args = self.args()
        _, did = self.approve(args)
        first = {"request_id": rid(), **self.run, "tool_call_id": "g1", "args": args}
        g = self.s.call(A, "pcm_grant", first)["grant"]
        self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id="g1", decision_id=did,
                  args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok",
                  result={"grant": event_hash(g)})
        self.assertEqual(self.s.call(A, "pcm_grant", dict(first))["grant"], g)   # a retry: its grant
        self.assertIn("already issued", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))
        self.s.close()
        self.s = self.open()   # replayed: the call still has its result
        self.assertIn("already issued", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))

    def test_rechecked_on_the_writer_after_signing(self):
        args = self.args()
        _, did = self.approve(args)
        sign = self.s._pcm_signed

        def completed_meanwhile(purpose, body):
            self.call("complete", stream="s", client_seq=next(self.seqs), tool_call_id="g1", decision_id=did,
                      args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok", result={})
            return sign(purpose, body)
        with mock.patch.object(self.s, "_pcm_signed", completed_meanwhile):
            self.assertIn("already issued", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))
        self.assertEqual([e for e in self.records() if e["type"] == "ext"], [])

    def test_an_approval_without_its_kept_answer_counts_as_self_approved(self):
        args = self.args()
        aid, _ = self.approve(args)
        del self.s.log.approvals[aid]["answer"]   # as a snapshot written before it has it
        self.assertIn("other than", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))


class TestGrantPolicyAllows(Case):
    policy = {}

    def test_no_approval_no_grant(self):
        args = self.args()
        self.assertEqual(self.decide(args)["decision"], "allow")
        self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args)


class TestGrantWithoutApprovals(Case):
    approvals = None

    def test_refused_as_any_identity_of_the_tenant_may_answer(self):
        args = self.args()
        self.approve(args, who=CallerIdentity("uid", "990103", True))   # another agent of the tenant
        self.assertIn("signer.yaml's approvals", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))


class TestGrantWithoutPersons(Case):
    approvals = {"approvers": ["uid:990001"]}

    def test_refused_as_the_approver_maps_to_no_person(self):
        args = self.args()
        self.approve(args)
        self.assertIn("uid:990001 maps to none", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))
        self.assertEqual([e for e in self.records() if e["type"] == "ext"], [])


class TestGrantSelfApproved(Case):
    approvals = dict(APPROVALS, persons=dict(APPROVALS["persons"], **{"uid:990101": "alice"}), self_approval="allow")

    def test_refused(self):
        args = self.args()
        self.approve(args)   # alice approves her own agent's call
        self.assertIn("other than", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))


class TestGrantAgentApprover(Case):
    BOUNDS = {k: {"type": "string"} for k in ("subject", "intent", "expires_at")}
    policy = {"tools": {"pcm.grant": "app"}, "ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^",
                                                      "approval": {"agent": {"mode": "enforce", "allow": {
                                                          "fields": dict(BOUNDS, delegable={"type": "boolean"})}}}}]}

    def test_a_root_grant_needs_a_person(self):
        args = self.args()
        del args["caveats"]   # within the agent's bounds: the widest grant
        self.approve(args, who=REVIEWER)
        self.assertIn("a person's approval", self.refused("forbidden", "pcm_grant", tool_call_id="g1", args=args))


class TestDelegate(Case):
    def delegate(self, parent, who=A, run=None, caveats=NARROWER, subject="uid:990102", expires=1800, **kw):
        return self.call("pcm_delegate", who, run, parent=parent, subject=subject, caveats=caveats,
                         expires_at=svc._iso(time.time() + expires), **{"delegable": True, **kw})

    def test_a_narrower_child_verifies(self):
        root = self.root()
        out = self.delegate(root, delegable=False)
        kid = out["grant"]
        self.assertEqual((kid["issuer"], kid["parent"], kid["intent"], kid["delegable"]), (
            {"kind": "agent", "id": "uid:990101", "run": self.run["run_id"], "tenant": "default"}, event_hash(root),
            REF, False))
        [rec] = [e for e in self.records() if e["type"] == "ext" and e["run_seq"] == out["run_seq"]]
        self.assertEqual(rec["data"], {"name": "pcm.grant", "grant": event_hash(kid), "subject": "uid:990102",
                                       "intent": REF, "parent": event_hash(root)})
        b = self.register(B)
        msg = self.call("pcm_sign", B, b, message=self.body({"agent": "uid:990102", "run": b["run_id"],
                                                              "tenant": "default"}, grants=[root, kid]))["message"]
        out = pcm.verify(msg, self.trust, [DOC])
        self.assertEqual((out["verdict"], out["grants"]["steps"]), ("accept", 2), out)
        self.assertIn("can't be passed on", self.refused("forbidden", "pcm_delegate", B, b, parent=kid,
                                                         subject="uid:990101", caveats=NARROWER,
                                                         expires_at=kid["expires_at"], delegable=False))

    def test_refused(self):
        root = self.root()
        self.assertIn("amount <= 20000: dropped or widened", self.refused(
            "invalid_request", "pcm_delegate", parent=root, subject="uid:990102", expires_at=root["expires_at"],
            delegable=True, caveats=[{"field": "amount", "op": "<=", "value": 30000}, CAVEATS[1]]))
        self.assertIn("after the parent's", self.refused(
            "invalid_request", "pcm_delegate", parent=root, subject="uid:990102", caveats=NARROWER, delegable=True,
            expires_at=svc._iso(time.time() + 7200)))
        b = self.register(B)
        self.assertIn("subject, uid:990101", self.refused(
            "forbidden", "pcm_delegate", B, b, parent=root, subject="uid:990102", caveats=NARROWER, delegable=True,
            expires_at=root["expires_at"]))
        forged = dict(root, caveats=[])
        self.assertIn("bad signature", self.refused(
            "invalid_request", "pcm_delegate", parent=forged, subject="uid:990102", delegable=True,
            expires_at=root["expires_at"]))
        key = logkey.FileKey(os.urandom(32))
        elsewhere = pcm.sign(key, checkpoint.vkey("elsewhere/log", checkpoint.ED25519, key.public), "pcm-grant",
                             {k: v for k, v in root.items() if k != "sig"})
        self.assertIn("does not pin", self.refused(
            "invalid_request", "pcm_delegate", parent=elsewhere, subject="uid:990102", caveats=NARROWER,
            delegable=True, expires_at=root["expires_at"]))
        acme = self.s._pcm_signed("pcm-grant", {k: v for k, v in root.items() if k != "sig"} | {
            "issuer": dict(root["issuer"], tenant="acme")})   # this signer's grant, of another tenant
        self.assertIn("issued in tenant acme, not default", self.refused(
            "forbidden", "pcm_delegate", parent=acme, subject="uid:990102", caveats=NARROWER, delegable=True,
            expires_at=root["expires_at"]))
        self.assertIn("is not in the future", self.refused(
            "invalid_request", "pcm_delegate", parent=root, subject="uid:990102", caveats=NARROWER, delegable=True,
            expires_at=svc._iso(time.time() - 60)))
        gone = self.s._pcm_signed("pcm-grant", {k: v for k, v in root.items() if k != "sig"} | {
            "expires_at": svc._iso(time.time() - 60)})   # A's own grant, already expired
        self.assertIn("expired at", self.refused(
            "invalid_request", "pcm_delegate", parent=gone, subject="uid:990102", caveats=NARROWER, delegable=True,
            expires_at=gone["expires_at"]))

    def test_a_grant_that_cannot_be_passed_on(self):
        root = self.root(delegable=False)
        self.assertIn("can't be passed on", self.refused(
            "forbidden", "pcm_delegate", parent=root, subject="uid:990102", caveats=NARROWER, delegable=False,
            expires_at=root["expires_at"]))


class TestEvidence(Case):
    def test_pending_then_proven_under_the_checkpoint(self):
        args = self.args()
        self.s.checkpoint()
        seq = self.decide(args)["run_seq"]
        out = self.call("pcm_evidence", run_seqs=[seq, 0])
        self.assertEqual((out["records"][0]["run_seq"], out["pending"]), (0, [seq]))
        self.assertNotIn("salt", out["records"][0])   # run.registered has no commitment
        self.s.checkpoint()
        out = self.call("pcm_evidence", run_seqs=[seq])
        _, size, root, _ = checkpoint.open_note(out["checkpoint"], self.trust["logs"])
        [r] = out["records"]
        e = r["event"]
        self.assertEqual((out["pending"], e["type"], event_hash(e)), ([], "policy.decision", r["hash"]))
        self.assertTrue(merkle.verify_inclusion(e["seq"], size, merkle.leaf_hash(bytes.fromhex(r["hash"][7:])),
                                                [base64.b64decode(p) for p in r["proof"]], root))
        opened = hmac.new(bytes.fromhex(r["salt"]), event_hash({"tool": "pcm.grant", "args": args}).encode(),
                          hashlib.sha256).hexdigest()
        self.assertEqual("hmac-sha256:" + opened, e["data"]["args_commitment"])

    def test_only_the_runs_own_records_for_its_agent(self):
        self.assertIn("no run_seq 99", self.refused("invalid_request", "pcm_evidence", run_seqs=[0, 99]))
        token = self.call("delegate_run", identity="uid:990105")["run_token"]
        self.refused("forbidden", "pcm_evidence", TAILER, {"run_id": self.run["run_id"], "run_token": token},
                     run_seqs=[0])

    def test_charged_to_the_quota(self):
        with mock.patch.object(self.s.quotas, "take_event", side_effect=RPCError("quota_exceeded", "over")):
            self.refused("quota_exceeded", "pcm_evidence", run_seqs=[0])


class TestBundle(Case):
    def test_the_senders_run_verifies(self):
        self.call("pcm_sign", message=self.body(grants=[self.root()]))
        self.s.checkpoint()
        path, trust = os.path.join(self.dir, "a.tkb"), os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump(self.trust, f)
        export(self.s.log.storage, "default", self.run["run_id"], self.s.log.storage.checkpoint_latest()[1], path)
        rep, code = v2.verify(path, trust)
        self.assertEqual(code, 0)
        warned = [c["detail"] for c in rep.checks if c["check"] == "not interpreted"]
        self.assertTrue(any("ext.pcm.sent" in d for d in warned) and any("ext.pcm.grant" in d for d in warned), warned)


if __name__ == "__main__":
    unittest.main()
