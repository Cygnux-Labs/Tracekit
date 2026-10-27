"""Claims of proof-carrying messages checked end to end through a real in-process signer (#436): each checker proven by
a signer-side or T2 record, unproven on the agent's own report (T1), failed on a mismatch or on evidence that does not
verify; the verdicts; and the Python SDK's pcm_send, pcm_evidence and pcm_grant."""
import base64
import concurrent.futures
import hashlib
import hmac
import itertools
import json
import math
import os
import time
import types
import unittest
from unittest import mock

import test_pcm_signer
import test_signer_service as ts
from test_pcm_signer import A, ALICE, APPROVALS, ASK, AUTHORIZE, CAVEATS, DOC, NARROWER, REF, REVIEWER, Case, rid
from tracekit import core, crypto, egress, merkle, pcm
from tracekit.format import checkpoint
from tracekit.format.canon import canonical, event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.pcm import claims
from tracekit.policy2 import classes
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


def approval_seqs(recs, tcid):
    """run_seqs of the decision, approval.request and approval of call `tcid`'s latest approval, among records as
    `read` returns them."""
    a = [x for x in recs if x["type"] == "approval" and x["data"]["tool_use_id"] == tcid][-1]
    r = next(x for x in recs if x["type"] == "approval.request" and x["data"]["approval_id"] == a["data"]["approval_id"])
    d = next(x for x in recs if x["type"] == "policy.decision" and x["data"]["decision_id"] == r["data"]["decision_id"])
    return [d["run_seq"], r["run_seq"], a["run_seq"]]


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

    def approved(self, tcid="g1", args=None):
        """Evidence of call `tcid`'s approval, the approval.request it answers and the decision that request names
        (opened with `args`)."""
        d, r, a = approval_seqs(self.records(), tcid)
        return self.evidence([d, r, a], args and {d: args})

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

    def test_a_malformed_claim_fails_without_evidence(self):
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE + " || true"}),
                         "not a single test command")
        self.assertClaim("failed", self.claim("file_written", {"path": "repo/refund.py", "digest": DIGEST}),
                         "is relative")

    def test_a_tool_the_verifier_cannot_place_as_a_shell(self):
        d, r = self.ran("mcp:ci/run", {"command": SUITE}, t2=True)
        self.assertEqual(self.claim("tests_passed", {"suite": SUITE}, self.evidence([d, r], {d: {"command": SUITE}})),
                         ("unproven", "a tool the verifier can't place as a shell tool"))

    def test_failed(self):
        _, _, ev = self.run_suite(t2=True)
        self.assertClaim("failed", self.claim("tests_passed", {"suite": "pytest -q"}, ev),
                         "no call in the evidence ran")
        _, _, ev = self.run_suite(ok=False, t2=True)
        self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE}, ev), "and failed")
        # || true, &, or a quote shlex and sh read apart ($'\''): the call succeeds whatever the tests do
        for cmd in ("echo hi", SUITE + " || true", SUITE + "#|| true", SUITE + " &", "pytest $'\\'';true #'"):
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

    def test_an_attempt_is_unproven(self):
        """A connect the egress proxy could not open (egress._forward counts its minute with no connection) and a
        kernel sensor's connect, which is the attempt, say the run tried the host, not that it reached it."""
        obs = egress.Observer(types.SimpleNamespace(observe_effect=lambda req: self.s.call(OBS, "observe_effect", req)))
        obs.add(("token", self.run["run_id"], self.run["run_token"], None), "api.example.com", 443)
        obs.flush(math.inf)
        [e] = [x for x in self.records() if x["type"] == "effect.observed"]
        self.assertEqual((e["data"]["connections"], e["data"]["bytes_out"], e["data"]["bytes_in"]), (0, 0, 0))
        self.assertClaim("unproven", self.claim("reached_host", {"host": "api.example.com"},
                                                self.evidence([e["run_seq"]])), "saw no connection to")
        self.assertClaim("unproven", self.claim("reached_host", {"host": "api.example.com"},
                                                self.evidence([self.effect(SENSOR)])), "an attempt")

    def test_by_an_http_call(self):
        d, r = self.ran("fetch", URL, t2=True)
        self.assertClaim("proven", self.claim("reached_host", {"host": "api.example.com"},
                                              self.evidence([d, r], {d: URL})), "(T2)")
        d, r = self.ran("fetch", URL)
        ev = self.evidence([d, r], {d: URL})
        self.assertEqual(self.claim("reached_host", {"host": "api.example.com"}, ev), ("unproven", T1))
        self.assertClaim("failed", self.claim("reached_host", {"host": "other.example.com"}, ev))
        d, r = self.ran("mcp:web/get", URL, t2=True)
        self.assertEqual(self.claim("reached_host", {"host": "api.example.com"}, self.evidence([d, r], {d: URL})),
                         ("unproven", "a tool the verifier can't place as a http tool"))


class TestApprovedBy(Claims):
    policy = {"ask": ASK["ask"] + [{"id": "READ", "tool": "read_file", "pattern": "^"}]}

    def approval(self):
        self.approve(self.args())
        return self.approved()

    def test_proven_by_the_persons_approval_of_that_call(self):
        ev = self.approval()
        self.assertClaim("proven", self.claim("approved_by", {"person": "alice", "call": "g1"}, ev),
                         "by alice of pcm.grant call g1")
        for args in ({"person": "bob", "call": "g1"}, {"person": "alice", "call": "g2"},
                     {"person": "uid:990001", "call": "g1"}):   # the person's name, not the identity that answered
            with self.subTest(args=args):
                self.assertClaim("failed", self.claim("approved_by", args, ev), "no approval of")

    def test_the_approval_alone_says_nothing_of_what_was_approved(self):
        """The call id is the agent's: without the decision the approval answers, the claim fails."""
        self.approve(self.args())
        seqs = {x["type"]: x["run_seq"] for x in self.records()}
        for kept in (["approval"], ["approval.request", "approval"], ["policy.decision", "approval"]):
            with self.subTest(kept=kept):
                self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"},
                                                      self.evidence([seqs[k] for k in kept])),
                                 "holds no decision of the call it approved")

    def test_names_the_tool_and_args_that_were_approved(self):
        """alice approved a read_file call the agent named refund-81-approved: the claim says so, not that she
        approved a refund."""
        args, tcid = {"path": "/etc/motd"}, "refund-81-approved"
        d = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool="read_file",
                      args_source="parsed", args=args)
        self.assertEqual(d["decision"], "ask")
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.call("approval_decide", ALICE, {}, approval_id=aid, decision="approve")
        claim = {"person": "alice", "call": tcid}
        for opened, end in ((None, ""), (args, f" with args {canonical(args).decode()}")):
            result, detail = self.claim("approved_by", claim, self.approved(tcid, opened))
            self.assertEqual(result, "proven", detail)
            self.assertTrue(detail.endswith(f"by alice of read_file call {tcid}{end}"), detail)

    def test_the_decision_its_request_names(self):
        """Two decisions of one call id: the approval is of the one its approval.request names, not the other."""
        first = self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id="x", tool="pay",
                          args_source="parsed", args={"amount": 50000})
        self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id="x", tool="read_file",
                  args_source="parsed", args={"path": "/etc/motd"})
        aid = self.call("approval_request", tool_call_id="x")["approval_id"]
        self.call("approval_decide", ALICE, {}, approval_id=aid, decision="approve")
        seqs = {x["type"]: x["run_seq"] for x in self.records()}
        claim = {"person": "alice", "call": "x"}
        self.assertClaim("failed", self.claim("approved_by", claim, self.evidence(
            [first["run_seq"], seqs["approval.request"], seqs["approval"]])), "holds no decision of the call")
        self.assertClaim("proven", self.claim("approved_by", claim, self.approved("x")), "of read_file call x")

    def test_a_rejection(self):
        self.approve(self.args(), decision="reject", consume=False)
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, self.approved()),
                         "no approval of")

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


class TestApprovedWithoutApprovals(Claims):
    approvals = None

    def test_an_identity_no_person_maps_is_no_person(self):
        self.approve(self.args(), who=CallerIdentity("uid", "990103", True))   # any identity of the tenant may answer
        [a] = [x for x in self.records() if x["type"] == "approval"]
        self.assertNotIn("person", a["data"])
        self.assertClaim("failed", self.claim("approved_by", {"person": "uid:990103", "call": "g1"},
                                              self.evidence([a["run_seq"]])), "no approval of")


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
        self.ev = self.approved()
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

    def test_a_proof_entry_in_non_canonical_base64(self):
        proof, alpha = self.ev["records"][0]["proof"], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        bent = proof[0][:42] + alpha[alpha.index(proof[0][42]) ^ 1] + proof[0][43:]   # an unused bit of char 42 set
        self.assertEqual(base64.b64decode(bent), base64.b64decode(proof[0]))
        self.assertClaim("failed", self.claim("approved_by", self.args_, self.with_record(proof=[bent, *proof[1:]])),
                         "record 1: not in the checkpoint")

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


class TestMalformedRecords(Claims):
    """Records the pinned log key signed that are no valid event, or that lack a field a checker reads, fail the
    claim: a hostile pinned log can't make the verifier raise."""

    def relog(self, events, opened=None):
        """Evidence of `events` alone, numbered from 0, under a checkpoint the signer's log key signs; `opened`:
        {index: (args, the tool its commitment names)} of decisions to open with a fresh salt."""
        events, opened, salt = [dict(e, seq=i) for i, e in enumerate(events)], opened or {}, os.urandom(32)
        for i, (args, tool) in opened.items():
            mac = hmac.new(salt, event_hash({"tool": tool, "args": args}).encode(), "sha256").hexdigest()
            events[i]["data"] = dict(events[i]["data"], args_commitment="hmac-sha256:" + mac)
        leaves = [merkle.leaf_hash(bytes.fromhex(event_hash(e)[7:])) for e in events]
        text = checkpoint.body(self.s.origin, len(leaves), merkle.root(leaves))
        note = text + "\n" + checkpoint.log_line(self.s.origin, self.s._log_key.public,
                                                 self.s._log_key.sign(text.encode()))
        return {"checkpoint": note, "records": [
            {"event": e, "hash": event_hash(e), "proof": [base64.b64encode(p).decode()
                                                         for p in merkle.inclusion_proof(i, leaves)],
             **({"salt": salt.hex(), "args": opened[i][0]} if i in opened else {})} for i, e in enumerate(events)]}

    def test_no_valid_event(self):
        self.approve(self.args())
        *rest, a = (r["event"] for r in self.approved()["records"])
        self.assertClaim("proven", self.claim("approved_by", {"person": "alice", "call": "g1"},
                                              self.relog([a, *rest])))
        for bad in ({k: v for k, v in a.items() if k != "data"}, dict(a, data=[]),
                    dict(a, data={k: v for k, v in a["data"].items() if k != "decision"})):
            with self.subTest(bad=bad):
                self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"},
                                                      self.relog([bad, *rest])), "record 1: not a valid event")
        dec = dict(rest[0], data={k: v for k, v in rest[0]["data"].items() if k != "tool"})   # a decision says no tool
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"},
                                              self.relog([a, dec, rest[1]])), "holds no decision of the call")

    def test_a_decision_without_its_tool_or_id(self):
        dec, res = (r["event"] for r in self.evidence(self.ran("Bash", {"command": SUITE}, t2=True))["records"])
        opened = {0: ({"command": SUITE}, "Bash")}
        self.assertClaim("proven", self.claim("tests_passed", {"suite": SUITE}, self.relog([dec, res], opened)))
        for drop, tool in (("tool", None), ("decision_id", "Bash")):
            with self.subTest(drop=drop):
                bad = dict(dec, data={k: v for k, v in dec["data"].items() if k != drop})
                self.assertClaim("failed", self.claim("tests_passed", {"suite": SUITE},
                                                      self.relog([bad, res], {0: ({"command": SUITE}, tool)})),
                                 "no call in the evidence ran")


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
        # nudges until a checkpoint covers them
        ev = self.h.pcm_evidence(approval_seqs(recs, a["data"]["tool_use_id"]), wait_s=20)
        msg = self.h.pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, grants=[root], claims=[
            {"type": "approved_by", "args": {"person": "alice", "call": a["data"]["tool_use_id"]}, "evidence": ev}])
        out = pcm.verify(msg, self.trust, [DOC], me="uid:990102")
        self.assertEqual((out["verdict"], out["grants"]["root"]["person"]), ("accept", "alice"), out)
        self.assertIn(f"by alice of pcm.grant call {a['data']['tool_use_id']}", out["claims"][0]["detail"])
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


def call(tool, args, t2=True):
    """A call decided and completed (T2 by a gateway, else T1), as evidence() returns its records."""
    d = {"type": "policy.decision", "seq": 1,
         "data": {"tool": tool, "decision": "allow", "decision_id": "d1", "tool_use_id": "c1"}}
    r = {"type": "tool.result", "seq": 2, "source": "gateway" if t2 else "client", "tier": "T2" if t2 else "T1",
         "data": {"decision_id": "d1", "tool_use_id": "c1", "ok": True, "via": "gw"}}
    return [(d, args), (r, None)]


def effect(host):
    """An egress observer's minute in which a connection to `host` opened."""
    return [({"type": "effect.observed", "seq": 3, "data": {"kind": "net", "host": host, "observer": "obs",
                                                           "connections": 1}}, None)]


class PCM01(unittest.TestCase):
    """PCM 0.1's decisions on what a claim names, on records as evidence() returns them."""

    def test_reached_host_compares_canonical_hosts(self):
        for host, recs in (("xn--bcher-kva.example", call("fetch", {"url": "https://BÜCHER.example:8443/x"})),
                           ("api.example.com", call("fetch", {"url": "https://api.example.com./"})),
                           ("api.example.com.", call("fetch", {"url": "https://api.example.com/"})),
                           ("api.example.com:443", call("fetch", {"url": "https://api.example.com/"})),
                           ("::1", call("fetch", {"url": "http://[::1]:8080/"})),
                           ("api.example.com", effect("api.example.com.")),
                           ("10.0.0.1", effect("::ffff:10.0.0.1"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "proven")
        self.assertEqual(claims.reached_host({"host": "b.example"}, call("fetch", {"url": "http://a.example/"}))[0],
                         "failed")

    def test_a_host_that_wont_parse_is_unproven(self):
        for host, recs in (("999.1.1.1", []), ("a..example", call("fetch", {"url": "http://a..example/"})),
                           ("a.example", call("fetch", {"url": "http://a..example/"})),
                           ("a.example", effect("a..example")),
                           # a browser reads a.example, Python's urllib b.example
                           ("a.example", call("fetch", {"url": "http://a.example\\@b.example/"})),
                           # sharp s: a browser reads xn--fa-hia.example, IDNA 2003 fass.example; U+03F2 is a final
                           # sigma after NFKC; ZWJ
                           ("fass.example", call("fetch", {"url": "http://fa%C3%9F.example/"})),
                           ("xn--4xa.example", call("fetch", {"url": "http://\u03f2.example/"})),
                           ("ab.example", effect("a\u200db.example")), ("fass.example", effect("FA\u00df.example")),
                           # no IPv6 address in brackets, a NUL, a port that is no number
                           ("h.com", call("fetch", {"url": "http://%5b::1%5d/"})),
                           ("h.com.evil", call("fetch", {"url": "http://h.com%00.evil/"})),
                           ("example.com:abc", []), ("example.com:", []), ("1.2.3.4:123456", []),
                           ("a.example", effect("a.example:x"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "unproven")

    def test_a_url_whose_scheme_has_no_host_reaches_none(self):
        for url in ("file://a.example/x", "gopher://a.example/", "FILE://a.example/x"):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": "a.example"}, call("fetch", {"url": url}))[0], "failed")
        self.assertEqual(claims.reached_host({"host": "a.example"}, call("fetch", {"url": "//a.example/x"}))[0],
                         "proven")

    def test_below_python_3_11_4_a_bracket_but_an_ipv6_hosts_is_unproven(self):
        """urlsplit refuses http://[x]@good.com/ from Python 3.11.4 on, and reads good.com before it: there, a URL
        with a bracket anywhere but around an IPv6 host can't be told apart."""
        fetch = lambda url: call("fetch", {"url": url})   # noqa: E731
        self.assertEqual(claims.reached_host({"host": "good.com"}, fetch("http://[x]@good.com/"))[0], "unproven")
        for old in (True, False):
            with self.subTest(old=old), mock.patch.object(claims, "URLSPLIT_CHECKS_BRACKETS", not old):
                if old:
                    # agent-flow:allow-secret (a bracketed IPv6 address before the @, not a password)
                    for url in ("http://[x]@good.com/", "http://[::1]@good.com/"):
                        self.assertEqual(claims.reached_host({"host": "good.com"}, fetch(url))[0], "unproven")
                for url in ("http://[::1]:8080/", "http://u@[::1]/x"):
                    self.assertEqual(claims.reached_host({"host": "::1"}, fetch(url))[0], "proven")
                for url in ("http://good.com/a[1]", "http://good.com/?q=]"):
                    self.assertEqual(claims.reached_host({"host": "good.com"}, fetch(url))[0],
                                     "unproven" if old else "proven")

    def test_placement_is_pcm_01s_frozen_table(self):
        """The tool placement table is data shipped with tracekit, the same as the PCM repo's registry/tools.json."""
        with open(os.path.join(os.path.dirname(claims.__file__), "tools.json"), "rb") as f:
            raw = f.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "15f8410f513344e4c60327d4fc3dd14949ebeaf7722f641d985d3ca721c8fe07")
        self.assertEqual(claims.placed(), json.loads(raw))

    def test_a_tool_a_live_pack_adds_is_not_placed(self):
        """A pack tracekit ships later, or a pack edited, changes no PCM 0.1 verdict."""
        packs = os.path.join(os.path.dirname(os.path.abspath(classes.__file__)), "packs")
        extra, listdir, read = os.path.join(packs, "zz-extra.yaml"), os.listdir, core.read_text
        claims.placed.cache_clear()
        self.addCleanup(claims.placed.cache_clear)
        with mock.patch("os.listdir", lambda p: listdir(p) + ["zz-extra.yaml"] * (os.path.abspath(p) == packs)), \
                mock.patch.object(core, "read_text", lambda p, *a, **k: "tools:\n  deploy_sh: shell\n"
                                  if os.path.abspath(p) == extra else read(p, *a, **k)):
            self.assertIn("zz-extra.yaml", os.listdir(packs))
            self.assertEqual(claims.tests_passed({"suite": "pytest"}, call("deploy_sh", {"command": "pytest"})),
                             ("unproven", "a tool the verifier can't place as a shell tool"))
            self.assertNotIn("deploy_sh", claims.placed())

    def test_idna_2003_takes_unassigned_code_points(self):
        """CPython's codec doesn't check Nameprep's table A.1, so PCM 0.1 has AllowUnassigned on."""
        self.assertEqual(claims.reached_host({"host": "xn--x-qib.example"},
                                             call("fetch", {"url": "http://x\u0378.example/"}))[0], "proven")

    def test_file_written_names_an_absolute_path(self):
        content = "x = 1\n"
        digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        wrote = lambda path, t2=True: call("Write", {"file_path": path, "content": content}, t2)   # noqa: E731
        for claim, path in (("/repo/a.py", "/repo/a.py"), ("C:\\repo\\a.py", "C:\\repo\\a.py")):
            self.assertEqual(claims.file_written({"path": claim, "digest": digest}, wrote(path))[0], "proven")
        for rel in ("a.py", "repo/a.py", "./a.py"):   # a relative claim is malformed
            self.assertEqual(claims.malformed("file_written", {"path": rel, "digest": digest}),
                             f"{rel} is relative: name the file's absolute path")
        for rel in ("a.py", "repo/a.py", "../repo/a.py"):   # the call's cwd is unknown
            with self.subTest(rel=rel):
                self.assertEqual(claims.file_written({"path": "/repo/a.py", "digest": digest}, wrote(rel))[0],
                                 "unproven")
        self.assertEqual(claims.file_written({"path": "/repo/a.py", "digest": digest}, wrote("b.py"))[0], "failed")

    def test_a_backslash_separates_only_in_a_drive_path(self):
        """A path that begins with / is read by POSIX rules, where `\\` is part of a name (/repo\\a.py is one file in
        /); a drive path by Windows rules, and proven only by a call of its very string, because the record doesn't
        say which system ran the call: C:/repo/a.py is C:\\repo\\a.py on Windows and a relative path on POSIX."""
        content = "x = 1\n"
        digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        for claim, path, want in (("/repo\\a.py", "/repo\\a.py", "proven"), ("/repo//./a\\b", "/repo/a\\b", "proven"),
                                  ("/repo\\a.py", "/repo/a.py", "failed"), ("/repo/a.py", "/repo\\a.py", "failed"),
                                  ("/repo/a.py", "\\repo\\a.py", "failed"), ("/repo/x/a.py", "x\\a.py", "failed"),
                                  ("/repo/a.py", "C:/repo/a.py", "failed"),
                                  ("/home/u/C:/repo/a.py", "C:/repo/a.py", "unproven"),   # relative on POSIX
                                  ("C:/repo/a.py", "C:/repo/a.py", "proven"),
                                  ("C:\\repo\\a.py", "C:/repo/a.py", "unproven"),
                                  ("C:/repo/a.py", "C:\\repo\\.\\a.py", "unproven"),
                                  ("C:\\repo\\a.py", "repo\\a.py", "unproven"),   # from C:\ on Windows
                                  ("C:\\repo\\a.py", "\\repo\\a.py", "unproven"),   # the current drive's
                                  ("C:\\repo\\a.py", "D:\\repo\\a.py", "failed"),
                                  ("C:\\repo\\a.py", "c:\\repo\\a.py", "failed")):
            with self.subTest(claim=claim, path=path):
                self.assertIsNone(claims.malformed("file_written", {"path": claim, "digest": digest}))
                self.assertEqual(claims.file_written({"path": claim, "digest": digest},
                                                     call("Write", {"file_path": path, "content": content}))[0], want)
        self.assertIsNone(claims.malformed("file_written", {"path": "/repo\\..\\a.py", "digest": digest}))   # a name
        for path, why in (("C:\\repo\\..\\a.py", "has a `..`"), ("\\\\server\\share\\a.py", "is relative"),
                          ("C:a.py", "is relative"), ("\\repo\\a.py", "is relative")):
            with self.subTest(path=path):
                self.assertIn(why, claims.malformed("file_written", {"path": path, "digest": digest}))

    def test_tests_passed_knows_a_fixed_list_of_runners(self):
        for suite in ("pytest -q tests/x.py", "python -m pytest -x", "python3 -m unittest", "npm test",
                      "go test ./...", "go test -short ./...", "cargo test", "cargo nextest run", "make test", "jest",
                      "pytest -k 'not slow' --verbose", 'pytest -k "a or b"', "pytest\t-q", "pytest --color=yes"):
            with self.subTest(suite=suite):
                self.assertIsNone(claims.malformed("tests_passed", {"suite": suite}))
        for suite in ("pytest --co", "pytest --collect-only -q", "pytest --help", "go test -h", "cargo test --version",
                      "npm test -- -h", "echo pytest", "python -m http.server", "npm run build", "go build", "make",
                      "CI=1 pytest", "uv run pytest", "pytest; true", "pytest\ntrue", "pytest | tee out",
                      # in the background, in a subshell, after a separator, redirected: sh's status is not pytest's
                      "pytest &", "(pytest &)", "(pytest) &", "pytest ;", "pytest &&", "pytest 2>&1",
                      # quotes and escapes shlex and sh read apart, expansions, comments, globs, other lines
                      "pytest $'\\'';true #'", "pytest $'\\'';true''", "pytest 'a", "pytest $X", "pytest `x`",
                      "pytest \\-h", "pytest # x", "pytest -{h,q}", "pytest -[h]", "pytest -?", "pytest\r-q",
                      "pytest\n", "pytest\x00",
                      # flags that run no tests, short and abbreviated
                      "pytest -V", "pytest '-h'", "pytest -'-'help", "python -m unittest --he",
                      "python -m pytest --vers", "pytest --c", "pytest --coll",
                      # a program that is the runner by its base name only
                      ".venv/bin/pytest", "./pytest", "/tmp/evil/pytest -q"):
            with self.subTest(suite=suite):
                self.assertEqual(claims.malformed("tests_passed", {"suite": suite}),
                                 f"{suite!r} is not a single test command")


if __name__ == "__main__":
    unittest.main()
