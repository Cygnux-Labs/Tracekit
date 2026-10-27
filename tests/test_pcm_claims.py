"""Claims of proof-carrying messages checked end to end through a real in-process signer (#436): each checker proven by
a signer-side or T2 record, unproven on the agent's own report (T1), failed on a mismatch or on evidence that does not
verify; the verdicts; and the Python SDK's pcm_send, pcm_evidence and pcm_grant."""
import concurrent.futures
import hashlib
import itertools
import os
import time
import unittest
from unittest import mock

import test_pcm_signer
import test_signer_service as ts
from test_pcm_signer import A, ALICE, APPROVALS, ASK, AUTHORIZE, CAVEATS, DOC, NARROWER, REF, REVIEWER, Case, rid
from tracekit import crypto, pcm
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.sdk import client
from tracekit.sdk.client import Refused, RunHandle, SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError

B = CallerIdentity("uid", "990102", True)
M = CallerIdentity("uid", "990107", True)   # in tenant acme
GW, OBS, SENSOR = (CallerIdentity("mtls", f"spiffe://acme/{n}", True) for n in ("executor", "egress", "sensor"))
SUITE = "pytest -q tests/test_refund.py"
WRITE = {"file_path": "/repo/refund.py", "content": "def refund():\n    return 1\n"}
DIGEST = "sha256:" + hashlib.sha256(WRITE["content"].encode()).hexdigest()
URL = {"url": "https://api.example.com/v1/refunds"}
T1 = "the result is the agent's own report (T1)"


class InProcess(client.Client):
    """The SDK client, speaking to an in-process signer as `who`."""

    def __init__(self, s, who):
        super().__init__(signer="in-process")
        self.s, self.who = s, who

    def _send(self, method, req):
        with self._lock:
            self._prepare(method, req)
        fut = concurrent.futures.Future()
        try:
            fut.set_result(self.s.call(self.who, method, req))
        except RPCError as e:
            fut.set_result({"error": {"code": e.code, "message": e.message}})
        return fut

    def _poll(self, method, req, timeout):
        return self._send(method, req).result()


class Claims(Case):
    def open(self):
        s = svc.SignerService(self.dir, policy=Engine(self.policy), approvals=self.approvals,
                              gateways=["mtls:spiffe://acme/executor"], tenants={"uid:990107": "acme"},
                              authorize={**AUTHORIZE, "mtls:spiffe://acme/executor": ["decide", "complete"],
                                         **{f"mtls:{w.subject}": ["observe_effect"] for w in (OBS, SENSOR)}})
        self.addCleanup(s.close)
        return s

    def setUp(self):
        super().setUp()
        self.gw = itertools.count()
        self.h = self.handle(A, self.run)

    def handle(self, who, run):
        return RunHandle(InProcess(self.s, who), {**run, "tenant": "default"})

    def ran(self, tool, args, ok=True, t2=False, decision="allow"):
        """(decision run_seq, result run_seq) of `tool` with `args` decided and completed in A's run: by the executor
        for A (T2), else by A's own process (T1)."""
        tcid, who = rid(), GW if t2 else A
        via = {"stream": "gw", "caller": "uid:990101"} if t2 else {"stream": "s"}
        seqs = self.gw if t2 else self.seqs
        d = self.call("decide", who, client_seq=next(seqs), tool_call_id=tcid, tool=tool, args_source="parsed",
                      args=args, **via)
        self.assertEqual(d["decision"], decision)
        r = self.call("complete", who, client_seq=next(seqs), tool_call_id=tcid, decision_id=d["decision_id"],
                      args_digest=event_hash({"tool": tool, "args": args}), status="ok" if ok else "error", **via)
        return d["run_seq"], r["run_seq"]

    def evidence(self, seqs, opened=None):
        self.s.checkpoint()
        return self.h.pcm_evidence(seqs, args=opened)

    def claim(self, type_, args, ev=None, trust=None, h=None):
        """(result, detail) of the claim as B verifies it in a message A's run sends."""
        c = {"type": type_, "args": args, **({"evidence": ev} if ev else {})}
        msg = (h or self.h).pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, claims=[c])
        out = pcm.verify(msg, trust or self.trust, [DOC])["claims"][0]
        return out["result"], out["detail"]

    def assertClaim(self, want, got, detail=""):
        self.assertEqual(got[0], want, got[1])
        self.assertIn(detail, got[1])


class TestTestsPassed(Claims):
    policy = {**ASK, "deny": [{"id": "NO", "tool": "Bash", "pattern": "denied"}]}

    def run_suite(self, command=SUITE, **kw):
        d, r = self.ran("Bash", {"command": command}, **kw)
        return d, r, self.evidence([d, r], {d: {"command": command}})

    def test_proven_by_a_result_the_executor_wrote(self):
        _, _, ev = self.run_suite(t2=True)
        self.assertClaim("proven", self.claim("tests_passed", {"suite": SUITE}, ev),
                         "run by mtls:spiffe://acme/executor (T2)")

    def test_the_agents_own_result_is_unproven(self):
        _, _, ev = self.run_suite()
        self.assertEqual(self.claim("tests_passed", {"suite": SUITE}, ev), ("unproven", T1))
        self.assertEqual(self.claim("tests_passed", {"suite": SUITE}), ("unproven", "no evidence"))

    def test_failed(self):
        _, _, ev = self.run_suite(t2=True)
        self.assertClaim("failed", self.claim("tests_passed", {"suite": "pytest -q"}, ev),
                         "no call in the evidence ran")
        _, _, ev = self.run_suite(ok=False, t2=True)
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE}, ev), "and failed")
        for cmd in ("echo hi", SUITE + " || true"):   # || true: the call succeeds whatever the tests do
            _, _, ev = self.run_suite(cmd, t2=True)
            self.assertClaim("failed", self.claim("tests_passed", {"suite": cmd}, ev), "not a single test command")
        d, r = self.ran("Bash", {"command": "pytest -q tests/other.py"}, t2=True)
        ev = self.evidence([d, r], {d: {"command": SUITE}})   # the args it claims, not the ones decided
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE}, ev), "do not open")
        _, _, ev = self.run_suite("pytest -q tests/denied.py", t2=True, decision="deny")   # ran against policy
        self.assertClaim("failed", self.claim("tests_passed", {"suite": "pytest -q tests/denied.py"}, ev))

    def test_a_result_of_another_decision(self):
        """Attempt 0 runs the suite and fails; attempt 1 of the same call runs `true`: its result is not the suite's."""
        tcid, via = rid(), {"stream": "gw", "caller": "uid:990101"}
        d = {}
        for attempt, cmd, status in ((0, SUITE, "error"), (1, "true", "ok")):
            args = {"command": cmd}
            d[attempt] = self.call("decide", GW, client_seq=next(self.gw), tool_call_id=tcid, attempt=attempt,
                                   tool="Bash", args_source="parsed", args=args, **via)
            r = self.call("complete", GW, client_seq=next(self.gw), tool_call_id=tcid, attempt=attempt,
                          decision_id=d[attempt]["decision_id"], args_digest=event_hash({"tool": "Bash", "args": args}),
                          status=status, **via)
        ev = self.evidence([d[0]["run_seq"], r["run_seq"]], {d[0]["run_seq"]: {"command": SUITE}})
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE}, ev), "no call in the evidence ran")

    def test_other_and_unopened_calls(self):
        """Evidence may hold calls of another kind and decisions it does not open: they match nothing."""
        dw, rw = self.ran("Write", WRITE, t2=True)
        d, r = self.ran("Bash", {"command": SUITE}, t2=True)
        ev = self.evidence([dw, rw, d, r], {dw: WRITE, d: {"command": SUITE}})
        self.assertClaim("proven", self.claim("tests_passed", {"suite": SUITE}, ev))
        self.assertClaim("failed", self.claim("reached_host", {"host": "api.example.com"}, ev))
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE}, self.evidence([d, r])),
                         "no call in the evidence ran")

    def test_an_agent_cannot_make_its_own_result_look_t2(self):
        tcid, args = rid(), {"command": SUITE}
        d = self.call("decide", client_seq=next(self.seqs), stream="s", tool_call_id=tcid, tool="Bash",
                      args_source="parsed", args=args)
        req = {"stream": "s", "client_seq": next(self.seqs), "tool_call_id": tcid, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": "Bash", "args": args}), "status": "ok"}
        self.refused("invalid_request", "complete", **req, source="gateway", tier="T2")
        self.assertIn("not a configured gateway", self.refused("forbidden", "complete", **req, caller="uid:990101"))
        r = self.call("complete", **req, result={"source": "gateway", "tier": "T2", "via": "spiffe://acme/executor"})
        ev = self.evidence([d["run_seq"], r["run_seq"]], {d["run_seq"]: args})
        self.assertEqual(self.claim("tests_passed", {"suite": SUITE}, ev), ("unproven", T1))


class TestFileWritten(Claims):
    def write(self, t2=True, args=WRITE, tool="Write"):
        d, r = self.ran(tool, args, t2=t2)
        return self.evidence([d, r], {d: args})

    def test_proven_and_unproven(self):
        self.assertClaim("proven", self.claim("file_written", {"path": WRITE["file_path"], "digest": DIGEST},
                                              self.write()), "(T2)")
        self.assertEqual(self.claim("file_written", {"path": WRITE["file_path"], "digest": DIGEST},
                                    self.write(t2=False)), ("unproven", T1))

    def test_failed(self):
        ev = self.write()
        for args in ({"path": WRITE["file_path"], "digest": "sha256:" + "0" * 64},
                     {"path": "/repo/other.py", "digest": DIGEST}):
            with self.subTest(args=args):
                self.assertClaim("failed", self.claim("file_written", args, ev), "no call in the evidence wrote")
        ev = self.write(args={"file_path": WRITE["file_path"], "old_string": "1", "new_string": "2"})   # no content
        self.assertClaim("failed", self.claim("file_written", {"path": WRITE["file_path"], "digest": DIGEST}, ev))

    def test_only_a_write_tool_writes(self):
        """The op comes from the tool's name, not from an `op` the agent put in its args."""
        claim = {"path": WRITE["file_path"], "digest": DIGEST}
        for tool, args in (("mcp:search/find", {"path": WRITE["file_path"], "op": "write", "content": WRITE["content"]}),
                           ("Read", WRITE), ("Edit", WRITE)):
            with self.subTest(tool=tool):
                self.assertClaim("failed", self.claim("file_written", claim, self.write(args=args, tool=tool)),
                                 "no call in the evidence wrote")

    def test_a_path_with_dots(self):
        ev = self.write(args=dict(WRITE, file_path="/etc/y/../refund.py"))   # matched as `refund.py` only
        self.assertClaim("failed", self.claim("file_written", {"path": "/repo/x/../refund.py", "digest": DIGEST}, ev),
                         "has a `..`")


class TestReachedHost(Claims):
    def effect(self, seen, **kw):
        """run_seq of the effect.observed of what `seen` (an egress observer or a kernel sensor) saw A's run do."""
        if seen is OBS:
            e = {"kind": "net", "host": "api.example.com", "port": 443, "bytes_out": 10, "bytes_in": 20,
                 "connections": 1, "first_ts": svc._iso(time.time()), "last_ts": svc._iso(time.time()), **self.run, **kw}
            self.call("observe_effect", OBS, {}, instance="obs-1", effects=[e])
        else:
            e = {"kind": "connect", "ts": svc._iso(time.time()), "pid": 7, "binary": "/usr/bin/curl",
                 "host": "api.example.com", "port": 443, **self.run, **kw}
            self.call("observe_effect", SENSOR, {}, instance="sen-1", sensor="tetragon", callers=["uid:990101"],
                      effects=[e])
        return [x for x in self.records() if x["type"] == "effect.observed"][-1]["run_seq"]

    def test_proven_by_an_observer(self):
        ev = self.evidence([self.effect(OBS)])
        self.assertClaim("proven", self.claim("reached_host", {"host": "api.example.com"}, ev),
                         "spiffe://acme/egress saw the run reach api.example.com")
        self.assertClaim("failed", self.claim("reached_host", {"host": "other.example.com"}, ev))
        ev = self.evidence([self.effect(SENSOR, denied=True)])
        self.assertClaim("failed", self.claim("reached_host", {"host": "api.example.com"}, ev))

    def test_by_an_http_call(self):
        d, r = self.ran("fetch", URL, t2=True)
        self.assertClaim("proven", self.claim("reached_host", {"host": "api.example.com"},
                                              self.evidence([d, r], {d: URL})), "(T2)")
        d, r = self.ran("fetch", URL)
        ev = self.evidence([d, r], {d: URL})
        self.assertEqual(self.claim("reached_host", {"host": "api.example.com"}, ev), ("unproven", T1))
        self.assertClaim("failed", self.claim("reached_host", {"host": "other.example.com"}, ev))


class TestApprovedBy(Claims):
    def approval(self):
        self.approve(self.args())
        return self.evidence([[x for x in self.records() if x["type"] == "approval"][-1]["run_seq"]])

    def test_proven_by_the_persons_approval_of_that_call(self):
        ev = self.approval()
        self.assertClaim("proven", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev), "by alice of g1")
        self.assertClaim("proven", self.claim("approved_by", {"person": "uid:990001", "call": "g1"}, ev))
        for args in ({"person": "bob", "call": "g1"}, {"person": "alice", "call": "g2"}):
            with self.subTest(args=args):
                self.assertClaim("failed", self.claim("approved_by", args, ev), "no approval of")

    def test_a_rejection(self):
        self.approve(self.args(), decision="reject", consume=False)
        ev = self.evidence([[x for x in self.records() if x["type"] == "approval"][-1]["run_seq"]])
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev), "no approval of")

    def test_not_from_another_run(self):
        ev = self.approval()
        other = self.register(A)   # A's other run sends it
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev,
                                              h=self.handle(A, other)), "not the sender's")

    def mallory(self, s):
        """A handle of M's run on signer `s` under the run id of A's run (a client picks its run id)."""
        r = s.call(M, "register_run", {"request_id": rid(), "agent": {"name": "m"}, "run_id": self.run["run_id"]})
        self.assertEqual(r["run_id"], self.run["run_id"])
        return RunHandle(InProcess(s, M), {"run_id": r["run_id"], "run_token": r["run_token"], "tenant": r["tenant"]})

    def test_not_from_a_run_of_the_same_id_in_another_tenant(self):
        ev = self.approval()
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev,
                                              h=self.mallory(self.s)), "not the sender's")

    def test_not_from_another_log(self):
        """Both logs are pinned, and M's run on the other has the run id and tenant of A's: the evidence is still
        not of the log that signed M's message."""
        ev = self.approval()
        s2 = svc.SignerService(ts.tmpdir(self), policy=Engine(ASK), approvals=APPROVALS, authorize=AUTHORIZE)
        self.addCleanup(s2.close)
        h = self.mallory(s2)
        self.assertEqual(h.registered["tenant"], "default")
        trust = {"logs": [self.s.vkey, s2.vkey], "algs": ["ed25519"]}
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev, trust=trust, h=h),
                         "not the one that signed the message")


class TestApprovedByAnAgent(Claims):
    policy = test_pcm_signer.TestGrantAgentApprover.policy

    def test_an_agent_approvers_approval_is_no_persons(self):
        args = self.args()
        del args["caveats"]   # within the agent's bounds
        self.approve(args, who=REVIEWER, consume=False)
        [a] = [x for x in self.records() if x["type"] == "approval"]
        self.assertEqual(a["data"]["approver_kind"], "agent")
        ev = self.evidence([a["run_seq"]])
        self.assertClaim("failed", self.claim("approved_by", {"person": "token:reviewer", "call": "g1"}, ev))


class TestApprovedBySelf(Claims):
    approvals = test_pcm_signer.TestGrantSelfApproved.approvals

    def test_a_self_approval_is_no_proof(self):
        self.approve(self.args())   # alice approves her own agent's call
        [a] = [x for x in self.records() if x["type"] == "approval"]
        self.assertTrue(a["data"]["self_approved"])
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"},
                                              self.evidence([a["run_seq"]])))


class TestEvidence(Claims):
    """Evidence that does not verify fails the claim: a changed record, a cut proof, a note the pinned key did not
    sign, too few witnesses."""

    def setUp(self):
        super().setUp()
        self.approve(self.args())
        seq = [x for x in self.records() if x["type"] == "approval"][-1]["run_seq"]
        self.ev = self.evidence([seq])
        self.args_ = {"person": "alice", "call": "g1"}
        self.assertClaim("proven", self.claim("approved_by", self.args_, self.ev))

    def with_record(self, **kw):
        return dict(self.ev, records=[dict(self.ev["records"][0], **kw)])

    def test_a_changed_record(self):
        r = self.ev["records"][0]
        for ev in (self.with_record(hash="sha256:" + "0" * 64),
                   self.with_record(event=dict(r["event"], source="gateway", tier="T2"))):
            self.assertClaim("failed", self.claim("approved_by", self.args_, ev), "record 1: hash does not match")

    def test_a_cut_proof(self):
        proof = self.ev["records"][0]["proof"]
        self.assertTrue(proof)
        for cut in (proof[:-1], proof[1:], []):
            self.assertClaim("failed", self.claim("approved_by", self.args_, self.with_record(proof=cut)),
                             "record 1: not in the checkpoint")

    def test_a_note_from_an_unpinned_signer(self):
        text = self.ev["checkpoint"].partition("\n\n")[0] + "\n"
        origin = text.split("\n")[0]
        forged = text + "\n" + checkpoint.sign(text, origin, os.urandom(32))
        self.assertClaim("failed", self.claim("approved_by", self.args_, dict(self.ev, checkpoint=forged)),
                         "checkpoint:")

    def test_a_bad_proof_or_seq(self):
        fake = {"seq": "x"}
        for ev in (self.with_record(proof=["é" * 4]), self.with_record(event=fake, hash=event_hash(fake))):
            self.assertClaim("failed", self.claim("approved_by", self.args_, ev), "record 1: not in the checkpoint")

    def test_witnesses_required(self):
        secret = os.urandom(32)
        w = checkpoint.vkey("witness.example/w", checkpoint.COSIGNATURE, crypto.public_from_secret(secret))
        trust = dict(self.trust, witnesses=[{"vkey": w, "class": "public"}], witnesses_required=1)
        self.assertClaim("failed", self.claim("approved_by", self.args_, self.ev, trust),
                         "checkpoint: 0 pinned cosignature(s), 1 required")
        text = self.ev["checkpoint"].partition("\n\n")[0] + "\n"
        cosigned = self.ev["checkpoint"] + checkpoint.cosign(text, "witness.example/w", secret, int(time.time()))
        self.assertClaim("proven", self.claim("approved_by", self.args_, dict(self.ev, checkpoint=cosigned), trust))


class TestVerdicts(Claims):
    NEED = {**DOC, "claims": ["tests_passed"]}

    def send(self, *claims):
        return self.h.pcm_send("uid:990102", pcm.schema_ref(self.NEED), {"amount": 12000, "order": 81},
                               claims=list(claims))

    def suite(self, t2):
        d, r = self.ran("Bash", {"command": SUITE}, t2=t2)
        return {"type": "tests_passed", "args": {"suite": SUITE},
                "evidence": self.evidence([d, r], {d: {"command": SUITE}})}

    def verdict(self, msg, strict=False):
        out = pcm.verify(msg, self.trust, [self.NEED], strict=strict)
        return out["verdict"], out["reasons"]

    def test_paths(self):
        proven, own = self.suite(True), self.suite(False)
        self.assertEqual(self.verdict(self.send(proven), strict=True), ("accept", []))
        self.assertEqual(self.verdict(self.send(own)), ("accept-unproven", [f"tests_passed: unproven ({T1})",
                                                                            "tests_passed: required, not proven"]))
        self.assertEqual(self.verdict(self.send(own), strict=True)[0], "reject")
        forged = dict(own, evidence=dict(own["evidence"], records=[dict(r, hash="sha256:" + "0" * 64)
                                                                   for r in own["evidence"]["records"]]))
        verdict, reasons = self.verdict(self.send(proven, forged))
        self.assertEqual(verdict, "reject")
        self.assertIn("tests_passed: failed (record 1: hash does not match the event)", reasons)


class TestSDK(Claims):
    def answer(self, decision):
        """As alice, answer the pcm.grant approval A's run is waiting on."""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            ids = [i for i, a in list(self.s.log.approvals.items()) if a["tool"] == "pcm.grant"
                   and a["state"] == "requested"]
            if ids:
                return self.s.call(ALICE, "approval_decide", {"request_id": rid(), "approval_id": ids[0],
                                                              "decision": decision})
            time.sleep(0.05)
        self.fail("no pcm.grant approval was requested")

    def grant(self, decision="approve", **kw):
        exp = svc._iso(time.time() + 3600)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            fut = pool.submit(self.h.pcm_grant, "uid:990101", REF, exp, CAVEATS, delegable=True, **kw)
            self.answer(decision)
            return fut.result(30)

    def test_end_to_end(self):
        root = self.grant()
        self.assertEqual((root["issuer"]["person"], root["delegable"], root["caveats"]), ("alice", True, CAVEATS))
        recs = self.records()
        [a] = [x for x in recs if x["type"] == "approval"]
        [res] = [x for x in recs if x["type"] == "tool.result"]
        self.assertEqual(res["data"]["tool_use_id"], a["data"]["tool_use_id"])   # the pcm.grant call completed
        ev = self.h.pcm_evidence([a["run_seq"]], wait_s=20)   # nudges until a checkpoint covers it
        msg = self.h.pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, grants=[root], claims=[
            {"type": "approved_by", "args": {"person": "alice", "call": a["data"]["tool_use_id"]}, "evidence": ev}])
        out = pcm.verify(msg, self.trust, [DOC], me="uid:990102")
        self.assertEqual((out["verdict"], out["grants"]["root"]["person"]), ("accept", "alice"), out)
        kid = self.h.pcm_grant("uid:990102", REF, root["expires_at"], NARROWER, parent=root)
        self.assertEqual((kid["parent"], kid["delegable"]), (event_hash(root), False))
        b = self.handle(B, self.register(B))
        msg = b.pcm_send("uid:990101", REF, {"amount": 12000, "order": 81}, grants=[root, kid])
        self.assertEqual(pcm.verify(msg, self.trust, [DOC])["verdict"], "accept")
        with self.assertRaises(ValueError):
            self.h.pcm_grant("uid:990102", "other.intent@sha256:" + "0" * 64, root["expires_at"], parent=root)

    def test_refused(self):
        with self.assertRaises(Refused) as cm:
            self.grant("reject")
        self.assertIn("rejected", str(cm.exception))
        veto = {"ok": False, "rule_ids": [], "reason": "veto"}
        with mock.patch.object(self.h, "approval_consume", return_value=veto), self.assertRaises(Refused) as cm:
            self.grant()
        self.assertIn("veto", str(cm.exception))
        with self.assertRaises(Refused) as cm:
            self.h.pcm_grant("uid:990101", REF, svc._iso(time.time() + 60), timeout_s=0.2)   # nobody answers
        self.assertIn("is requested", str(cm.exception))
        with mock.patch.object(self.h.client, "checkpoint_nudge"), self.assertRaises(SignerUnavailable):
            self.h.pcm_evidence([0], wait_s=0.3)   # no checkpoint covers it
        self.s.checkpoint()
        for args in ({0: {}}, {1: {}}):   # run.registered: no decision to open; 1: not asked for
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.h.pcm_evidence([0], args=args)


class TestSDKPolicyAllows(Claims):
    policy = {}

    def test_a_grant_the_policy_does_not_ask_for(self):
        with self.assertRaises(Refused) as cm:
            self.h.pcm_grant("uid:990101", REF, svc._iso(time.time() + 60))
        self.assertIn("not asked", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
