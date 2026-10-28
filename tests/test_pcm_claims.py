"""Claims of proof-carrying messages checked end to end through a real in-process signer (#436): each checker proven by
a signer-side or T2 record, unproven on the agent's own report (T1), failed on a mismatch or on evidence that does not
verify; the verdicts; and the Python SDK's pcm_send, pcm_evidence and pcm_grant."""
import base64
import concurrent.futures
import contextlib
import hashlib
import hmac
import ipaddress
import itertools
import json
import math
import os
import re
import time
import types
import unittest
import urllib.parse
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

    def result(self, type_, args, ev=None, trust=None, h=None):
        """The claim's result as B verifies it in a message A's run sends."""
        c = {"type": type_, "args": args, **({"evidence": ev} if ev else {})}
        msg = (h or self.h).pcm_send("uid:990102", REF, {"amount": 12000, "order": 81}, claims=[c])
        return pcm.verify(msg, trust or self.trust, [DOC])["claims"][0]

    def claim(self, *a, **kw):
        """(result, detail) of the claim as B verifies it in a message A's run sends."""
        out = self.result(*a, **kw)
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
                         'by alice of "pcm.grant" call g1')
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
            out = self.result("approved_by", claim, self.approved(tcid, opened))
            self.assertEqual(out["result"], "proven", out["detail"])
            self.assertTrue(out["detail"].endswith(f'by alice of "read_file" call {tcid}{end}'), out["detail"])
            self.assertEqual(out["approved"], {"tool": "read_file", "args": opened})

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
        self.assertClaim("proven", self.claim("approved_by", claim, self.approved("x")), 'of "read_file" call x')

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
        self.assertClaim("failed", self.claim("approved_by", {"person": "uid:990103", "call": "g1"}, self.approved()),
                         "no approval of")


class TestApprovedByAnAgent(Claims):
    policy = test_pcm_signer.TestGrantAgentApprover.policy

    def test_an_agent_approvers_approval_is_no_persons(self):
        args = self.args()
        del args["caveats"]   # within the agent's bounds
        self.approve(args, who=REVIEWER, consume=False)
        [a] = [x for x in self.records() if x["type"] == "approval"]
        self.assertEqual(a["data"]["approver_kind"], "agent")
        self.assertClaim("failed", self.claim("approved_by", {"person": "token:reviewer", "call": "g1"},
                                              self.approved()), "no approval of")


class TestApprovedBySelf(Claims):
    approvals = test_pcm_signer.TestGrantSelfApproved.approvals

    def test_a_self_approval_is_no_proof(self):
        self.approve(self.args())   # alice approves her own agent's call
        [a] = [x for x in self.records() if x["type"] == "approval"]
        self.assertTrue(a["data"]["self_approved"])
        self.assertClaim("failed", self.claim("approved_by", {"person": "alice", "call": "g1"}, self.approved()),
                         "no approval of")


class TestCovers(Claims):
    """approved_by with covers through a real signer (PCM 0.1 6.6): the PCM-Lies L3.A lies, which cite alice's
    approval of a smaller pay or of a read_file to ask for a pay of 5000, and the two ways an approval covers a request.
    The schemas list approved_by, which only a proven approved_by with covers meets."""
    policy = TestApprovedBy.policy
    NEED = {**DOC, "name": "refund.paid", "claims": ["approved_by"]}
    PAY = {**NEED, "tool": "pay"}
    ASK = {"amount": 5000, "order": 81}

    def approve_call(self, tool, args):
        """The call id of a `tool` call with `args` that alice approved."""
        tcid = rid()
        self.call("decide", stream="s", client_seq=next(self.seqs), tool_call_id=tcid, tool=tool, args_source="parsed",
                  args=args)
        aid = self.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.call("approval_decide", ALICE, {}, approval_id=aid, decision="approve")
        return tcid

    def verify(self, doc, tcid, opened=None, covers=True, grants=(), strict=False):
        """B's result for A's message asking for ASK under `doc`, citing alice's approval of `tcid`."""
        claim = {"type": "approved_by", "args": {"person": "alice", "call": tcid, **({"covers": True} if covers else {})},
                 "evidence": self.approved(tcid, opened)}
        msg = self.h.pcm_send("uid:990102", pcm.schema_ref(doc), self.ASK, claims=[claim], grants=list(grants))
        return pcm.verify(msg, self.trust, [doc], strict=strict)

    def test_the_lies_of_pcm_lies_l3a(self):
        small, read = {"amount": 500, "order": 81}, {"path": "/etc/motd"}
        less, motd = self.approve_call("pay", small), self.approve_call("read_file", read)
        for tcid, opened, result in ((less, small, "failed"), (less, None, "unproven"), (motd, read, "failed"),
                                     (motd, None, "failed")):
            with self.subTest(tcid=tcid, opened=opened):
                out = self.verify(self.PAY, tcid, opened)
                self.assertEqual((out["verdict"], out["claims"][0]["result"]),
                                 ("reject" if result == "failed" else "accept-unproven", result), out["reasons"])
                self.assertNotIn("approved", out["claims"][0])
                # without covers the claim says only what alice approved, which meets no need
                out = self.verify(self.PAY, tcid, opened, covers=False)
                self.assertEqual((out["verdict"], out["claims"][0]["result"], out["reasons"]),
                                 ("accept-unproven", "proven", ["approved_by: required, not proven to cover this "
                                                                "request: claim it with covers true"]))
                self.assertEqual(self.verify(self.PAY, tcid, opened, covers=False, strict=True)["verdict"], "reject")

    def test_the_two_ways_an_approval_covers_a_request(self):
        exact = self.approve_call("pay", self.ASK)
        out = self.verify(self.PAY, exact, self.ASK)
        self.assertEqual((out["verdict"], out["claims"][0]["approved"]), ("accept", {"tool": "pay", "args": self.ASK}))
        self.assertTrue(out["claims"][0]["detail"].endswith(": this request's tool and args"))
        out = self.verify(self.NEED, exact, self.ASK)   # its schema names no tool
        self.assertEqual((out["verdict"], out["claims"][0]["result"]), ("accept-unproven", "unproven"))
        self.assertIn("name the tool in the schema document", out["claims"][0]["detail"])
        ref = pcm.schema_ref(self.NEED)
        root = self.root(intent=ref)
        out = self.verify(self.NEED, "g1", grants=[root])
        self.assertEqual((out["verdict"], out["claims"][0]["approved"]), ("accept", {"tool": "pcm.grant", "args": None}))
        self.assertTrue(out["claims"][0]["detail"].endswith(", which issued this message's root grant"))
        args = self.args(intent=ref)
        self.approve(args, tcid="g2")
        other = self.call("pcm_grant", tool_call_id="g2", args=args)["grant"]
        for grants in ([other], []):   # under a grant g1's approval did not issue, or none
            with self.subTest(grants=grants):
                out = self.verify(self.NEED, "g1", grants=grants)
                self.assertEqual((out["verdict"], out["claims"][0]["result"]), ("reject", "failed"))
                self.assertIn("did not issue this message's root grant", out["claims"][0]["detail"])


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

    def test_a_record_listed_twice(self):
        """The decision listed once unopened and once opened would give `approved` by their order: any record listed
        twice fails the claim."""
        args, claim = self.args(), {"person": "alice", "call": "g2"}
        self.approve(args, tcid="g2")
        d, r, a = approval_seqs(self.records(), "g2")
        ev = self.evidence([d, r, a], {d: args})
        self.assertEqual(self.result("approved_by", claim, ev)["approved"], {"tool": "pcm.grant", "args": args})
        unopened = {k: v for k, v in ev["records"][0].items() if k not in ("salt", "args")}
        for records, detail in (([unopened, *ev["records"]], "record 2: the same record as record 1"),
                                ([*ev["records"], ev["records"][-1]], "record 4: the same record as record 3")):
            self.assertClaim("failed", self.claim("approved_by", claim, dict(ev, records=records)), detail)

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
        self.assertIn(f'by alice of "pcm.grant" call {a["data"]["tool_use_id"]}', out["claims"][0]["detail"])
        self.assertEqual(out["claims"][0]["approved"], {"tool": "pcm.grant", "args": None})
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


def approval(tool="pay", **edit):
    """alice's approval of call c1, the approval.request it answers and the decision of `tool` that request names, as
    evidence() returns them; `edit`: {record type: fields to change in its data}."""
    recs = [{"type": "policy.decision", "seq": 1, "data": {"tool": tool, "decision": "ask", "decision_id": "d1",
                                                           "tool_use_id": "c1"}},
            {"type": "approval.request", "seq": 2, "data": {"approval_id": "a1", "decision_id": "d1"}},
            {"type": "approval", "seq": 3, "data": {"decision": "approve", "tool_use_id": "c1", "approval_id": "a1",
                                                    "person": "alice"}}]
    return [(dict(r, data={**r["data"], **edit.get(r["type"].replace(".", "_"), {})}), None) for r in recs]


def asking(args, *grants):
    """A message of run r1 in tenant default asking for `args` under `grants`: what approved_by's covers reads."""
    return {"from": {"agent": "uid:990101", "run": "r1", "tenant": "default"}, "intent": {"args": args},
            "grants": list(grants)}


ASKED = asking({"amount": 12000, "order": 81})


class PCM01(unittest.TestCase):
    """PCM 0.1's decisions on what a claim names, on records as evidence() returns them."""

    def test_approved_by_is_a_persons_own_approval_of_the_decision_its_request_names(self):
        """Records a hostile pinned log could write: an agent approver's answer naming a person, a self-approval, a
        rejection, a request of another approval, a decision of another call or of no tool prove nothing."""
        claim = {"person": "alice", "call": "c1"}
        for edit in ({}, {"approval": {"approver_kind": "person", "self_approved": False}}):
            self.assertEqual(claims.approved_by(claim, approval(**edit), ASKED, None),
                             ("proven", 'approval seq 3 by alice of "pay" call c1', {"tool": "pay", "args": None}))
        for edit in ({"approval": {"approver_kind": "agent"}}, {"approval": {"self_approved": True}},
                     {"approval": {"decision": "reject"}}, {"approval_request": {"approval_id": "a2"}},
                     {"policy_decision": {"tool_use_id": "c2"}}, {"policy_decision": {"tool": ""}}):
            with self.subTest(edit=edit):
                self.assertEqual(claims.approved_by(claim, approval(**edit), ASKED, None)[0], "failed")

    def test_approved_by_does_not_depend_on_record_order(self):
        """Records that disagree on what the person approved fail the claim in either order: a decision listed
        unopened and opened, two requests of one approval naming two decisions (the other one in the evidence or
        not), two approvals of the call naming different decisions, args {"x": true} and {"x": 1} among them (equal in
        Python, apart in JCS). Records that agree prove it, by the first approval; an opened decision gives its args."""
        claim, motd = {"person": "alice", "call": "c1"}, {"path": "/etc/motd"}
        dec, req, app = approval("read_file")
        pay = ({"type": "policy.decision", "seq": 4, "data": {"tool": "pay", "decision": "ask", "decision_id": "d2",
                                                              "tool_use_id": "c1"}}, None)
        one = ({"type": "policy.decision", "seq": 4, "data": dict(dec[0]["data"], decision_id="d2")}, {"x": 1})
        again = ({"type": "approval", "seq": 6, "data": dict(app[0]["data"], approval_id="a2")}, None)

        def request(aid, did):
            return {"type": "approval.request", "seq": 5, "data": {"approval_id": aid, "decision_id": did}}, None
        two = "approval seq 3: its approval.request records name 2 decisions"
        for recs, why in (([dec, (dec[0], motd), req, app], "2 different decisions approved as call c1 by alice"),
                          ([dec, req, pay, request("a1", "d2"), app], two),
                          ([dec, req, app, request("a1", "d2")], two),
                          ([dec, req, app, pay, request("a2", "d2"), again], "2 different decisions approved as"),
                          ([(dec[0], {"x": True}), req, app, one, request("a2", "d2"), again],
                           "2 different decisions approved as")):
            for order in (recs, recs[::-1]):
                with self.subTest(order=order):
                    got = claims.approved_by(claim, order, ASKED, None)
                    self.assertEqual(got[0], "failed", got)
                    self.assertIn(why, got[1])
        for recs, want in (([dec, req, app, request("a2", "d1"), again], {"tool": "read_file", "args": None}),
                           ([(dec[0], motd), req, app], {"tool": "read_file", "args": motd})):
            end = "" if want["args"] is None else ' with args {"path":"/etc/motd"}'
            for order in (recs, recs[::-1]):
                with self.subTest(order=order):
                    self.assertEqual(claims.approved_by(claim, order, ASKED, None),
                                     ("proven", f'approval seq 3 by alice of "read_file" call c1{end}', want))

    def test_approved_by_writes_the_tool_as_json(self):
        """data.tool is the agent's own string: as JSON in the detail it can't spell opened args, and `approved`
        carries it apart."""
        tool = 'pay call c1 with args {"amount":20000,"to":"acct-9"} and read_file'
        self.assertEqual(claims.approved_by({"person": "alice", "call": "c1"}, approval(tool), ASKED, None)[1:],
                         (f"approval seq 3 by alice of {canonical(tool).decode()} call c1", {"tool": tool, "args": None}))

    def test_approved_by_covers_only_this_request(self):
        """With covers the sender says the approval covers the message's request (PCM 0.1 6.6). The PCM-Lies L3.A
        lies cite alice's approval of a refund of 500 to ask for 5000, or of a read_file to ask for a refund: opened,
        a refund of 500 fails; unopened, the verifier can't tell; a read_file fails either way. An approval covers by
        its tool and args under a schema that names the tool, or as the approval that issued the message's root grant;
        under a schema that names no tool, or as a pcm.grant approval of another grant, it can't or does not. Without
        covers the claim only says what alice approved."""
        claim, ask, pay = {"person": "alice", "call": "c1", "covers": True}, {"amount": 5000, "order": 81}, {
            "tool": "refund"}
        dec, req, app = approval("refund")
        small, (read, *answered) = {"amount": 500, "order": 81}, approval("read_file")
        said = 'approval seq 3 by alice of "refund" call c1'
        not_of = 'approval seq 3 by alice of "read_file" call c1{}: not of "refund", the tool the intent\'s schema ' \
            "names, so it does not cover this request"
        root = {"issuer": {"kind": "person", "id": "uid:990001", "approval_id": "a1", "run": "r1", "tenant": "default"}}
        g = approval("pcm.grant")
        granted = 'approval seq 3 by alice of "pcm.grant" call c1'
        other = f"{granted}: a pcm.grant approval covers only the requests under the grant it issued, and it did not " \
            "issue this message's root grant"
        rows = [([(dec[0], ask), req, app], asking(ask), pay, "proven",
                 f"{said} with args {canonical(ask).decode()}: this request's tool and args"),
                ([(dec[0], small), req, app], asking(ask), pay, "failed",   # L3.A.07, L3.A.09
                 f"{said} with args {canonical(small).decode()}: not this request's args {canonical(ask).decode()}, "
                 "so it does not cover this request"),
                ([dec, req, app], asking(ask), pay, "unproven",   # L3.A.08, L3.A.10
                 f"{said}: its args are not opened, so the verifier can't tell whether they are this request's: open "
                 "the decision"),
                ([(read[0], {"path": "/etc/motd"}), *answered], asking(ask), pay, "failed",   # L3.A.11
                 not_of.format(' with args {"path":"/etc/motd"}')),
                ([read, *answered], asking(ask), pay, "failed", not_of.format("")),   # L3.A.12
                ([(dec[0], ask), req, app], asking(ask), None, "unproven",
                 f"{said} with args {canonical(ask).decode()}: the intent's schema names no tool, so the verifier "
                 "can't tell whether it covers this request: name the tool in the schema document, or cite the "
                 "approval that issued the message's root grant"),
                (g, asking(ask, root), None, "proven", f"{granted}, which issued this message's root grant"),
                (g, asking(ask, root), pay, "proven", f"{granted}, which issued this message's root grant"),
                (g, asking(ask), pay, "failed", other)]
        # true and 1 are equal in Python, apart in JCS
        flag, one = {"amount": 5000, "order": True}, {"amount": 5000, "order": 1}
        rows.append(([(dec[0], flag), req, app], asking(one), pay, "failed",
                     f"{said} with args {canonical(flag).decode()}: not this request's args {canonical(one).decode()}, "
                     "so it does not cover this request"))
        # a second attempt of the grant call, approved too, issued the root grant: the detail names its approval
        again = [({"type": "policy.decision", "seq": 4, "data": dict(g[0][0]["data"], decision_id="d2")}, None),
                 ({"type": "approval.request", "seq": 5, "data": {"approval_id": "a2", "decision_id": "d2"}}, None),
                 ({"type": "approval", "seq": 6, "data": dict(g[2][0]["data"], approval_id="a2")}, None)]
        rows.append((g + again, asking(ask, {"issuer": {**root["issuer"], "approval_id": "a2"}}), None, "proven",
                     'approval seq 6 by alice of "pcm.grant" call c1, which issued this message\'s root grant'))
        for k, v in (("approval_id", "a2"), ("run", "r2"), ("tenant", "acme")):
            rows.append((g, asking(ask, {"issuer": {**root["issuer"], k: v}}), None, "failed", other))
        for recs, msg, doc, result, detail in rows:
            with self.subTest(recs=recs, msg=msg, doc=doc):
                got = claims.approved_by(claim, recs, msg, doc)
                self.assertEqual(got[:2], (result, detail))
                self.assertEqual(len(got), 3 if result == "proven" else 2)   # `approved` only when proven
                self.assertEqual(claims.approved_by({"person": "alice", "call": "c1"}, recs, msg, doc)[0], "proven")

    def test_reached_host_compares_canonical_hosts(self):
        for host, recs in (("xn--bcher-kva.example", call("fetch", {"url": "https://XN--BCHER-KVA.Example:8443/x"})),
                           ("xn--zz.example", call("fetch", {"url": "http://XN--zz.example/"})),   # no valid punycode
                           ("api.example.com", call("fetch", {"url": "https://api.example.com./"})),
                           ("api.example.com.", call("fetch", {"url": "https://api.example.com/"})),
                           ("api.example.com:443", call("fetch", {"url": "https://api.example.com/"})),
                           ("::1", call("fetch", {"url": "http://[::1]:8080/"})),
                           ("2001:db8::1", call("fetch", {"url": "http://[2001:DB8:0:0::1]/"})),
                           ("10.0.0.1", call("fetch", {"url": "http://10.0.0.1:8080/"})),
                           ("127.0.0.1", call("fetch", {"url": "http://127.0.0.1./"})),
                           ("1.2.3.4", call("fetch", {"url": "http://[64:ff9b::102:304]/"})),   # NAT64
                           ("api.example.com", effect("api.example.com.")),
                           ("10.0.0.1", effect("::ffff:10.0.0.1"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "proven")
        self.assertEqual(claims.reached_host({"host": "b.example"}, call("fetch", {"url": "http://a.example/"}))[0],
                         "failed")

    def test_a_failed_call_says_how_to_prove_the_host(self):
        """A call the host answered with an HTTP error is recorded as not ok, as one that reached nothing is: the claim
        fails, and its detail says how to prove the host instead."""
        recs = call("fetch", {"url": "http://a.example/"})
        recs[1][0]["data"]["ok"] = False
        self.assertEqual(claims.reached_host({"host": "a.example"}, recs), (
            "failed", "call c1 reached a.example, and failed: its result is not ok, which an HTTP error answer gives "
                      "too: claim the host from a call that succeeded, or from an egress observer's record"))

    def test_a_host_that_wont_parse_is_unproven(self):
        long = "a" * 64 + ".example"   # a label over 63 characters
        for host, recs in (("999.1.1.1", []), ("a..example", call("fetch", {"url": "http://a..example/"})),
                           ("a.example", call("fetch", {"url": "http://a..example/"})),
                           ("a.example", effect("a..example")), (long, call("fetch", {"url": f"http://{long}/"})),
                           # a label character outside a-z, 0-9, _ and -; two trailing dots
                           ("api.example.com", call("fetch", {"url": "http://a*b.example/"})),
                           ("a.example", call("fetch", {"url": "http://a.example../"})),
                           # a browser reads a.example, Python's urllib b.example
                           ("a.example", call("fetch", {"url": "http://a.example\\@b.example/"})),
                           # no IPv6 address in brackets, read by the browser alone; a port that is no number
                           ("h.com", call("fetch", {"url": "http:\\\\[h.com]/"})),
                           ("api.example.com", call("fetch", {"url": "http:\\\\[::g]/"})),
                           ("example.com:abc", []), ("example.com:", []), ("1.2.3.4:123456", []),
                           ("a.example", effect("a.example:x"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "unproven")

    def test_only_printable_ascii_is_read(self):
        """A URL or host with any character outside U+0021 to U+007E is one the verifier can't tell: IDNA 2003, UTS 46
        and Python's codec name some hosts apart (sharp s, U+1806, U+3164, U+0378), and urlsplit releases drop leading
        controls and spaces, tabs and newlines differently, even inside a percent-escape. A call's detail says what the
        sender can do."""
        why = ("its URL is not printable ASCII: send it without spaces or control characters, with the host in xn-- "
               "form and anything else percent-encoded")
        for host, url in (("fass.example", "http://fa%C3\t%9F.example/"), ("fass.example", "http://fa\u00df.example/"),
                          ("ab.example", "http://a\u1806b.example/"), ("ab.example", "http://a\u3164b.example/"),
                          ("xn--x-qib.example", "http://x\u0378.example/"),
                          ("xn--bcher-kva.example", "http://b\u00fccher.example/"),
                          *(("a.example", url) for url in (
                              "http://a.example/caf\u00e9", " http://a.example/", "\x01http://a.example/",
                              "http://a.ex\tample/", "http://a.example/ x", "http://a.example/\x7f"))):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url})),
                                 ("unproven", f"the verifier can't tell whether call c1 reached {host}: {why}"))
        for host, recs in (("xn--bcher-kva.example", effect("b\u00fccher.example")),
                           ("b\u00fccher.example", effect("xn--bcher-kva.example"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "unproven")

    def test_a_host_with_a_percent_is_unproven(self):
        """Hosts are never percent-decoded: a `%` in the host the browser or urllib reads makes it one the verifier
        can't tell. A call's detail says what the sender can do; it gives no advice for a cause the sender can't fix
        that way."""
        why = "its host has a %: send the URL with the host as plain ASCII, not percent-encoded"
        for host, url in (("a.example", "http://%61.example/"),
                          ("a.example", "http:\\\\%61.example/"),   # the browser's host
                          ("a.example", "http://a.example\\@%61.example/"),   # urllib's
                          ("b.example", "http://a.example\\@%62.example/"),   # the two read apart too
                          ("h.com", "http://%5bh.com%5d/"), ("h.com.evil", "http://h.com%00.evil/"),
                          ("::1", "http://[::1%25eth0]/"),
                          # a zone id is no address, so its .01 is no leading zero: the URL passes the bracket rule
                          ("::1", "http://[::1%25a.01]/"), ("fe80::1", "http://[fe80::1%25en.05]/")):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url})),
                                 ("unproven", f"the verifier can't tell whether call c1 reached {host}: {why}"))
        self.assertEqual(claims.reached_host({"host": "b.example"},
                                             call("fetch", {"url": "http://a.example\\@b.example/"})),
                         ("unproven", "the verifier can't tell whether call c1 reached b.example"))
        for host, recs in (("a.example", effect("%61.example")), ("%61.example", effect("a.example"))):
            with self.subTest(host=host, recs=recs):
                self.assertEqual(claims.reached_host({"host": host}, recs)[0], "unproven")

    def test_a_url_without_a_scheme_is_unproven(self):
        """A client with a base URL reads `/api.example.com/x` or `api.example.com/x` as a path on the base's host, so
        the verifier can't tell what a call of one reached, and the detail says what to send; a URL that starts with
        `//` names its host whatever the base."""
        why = "its URL has no scheme, so a client may read it against a base URL: send the whole URL, scheme and host"
        for host, url in (("api.example.com", "/api.example.com/v1/x"), ("api.example.com", "\\api.example.com/x"),
                          ("api.example.com", "api.example.com/x"), ("api.example.com", "api.example.com"),
                          ("api.example.com", "api.example.com:8080/x"), ("127.0.0.1", "/127.0.0.1/x")):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url})),
                                 ("unproven", f"the verifier can't tell whether call c1 reached {host}: {why}"))
        for url in ("//api.example.com/x", "\\\\api.example.com/x"):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": "api.example.com"}, call("fetch", {"url": url}))[0],
                                 "proven")

    def test_an_ipv4_host_not_written_as_a_dotted_quad_is_unproven(self):
        """A host whose last label is a number (ASCII digits, or 0x and hex digits or none) is an IPv4 address, read
        only as four decimal numbers 0-255 without leading zeros: resolvers read the other forms apart (macOS reaches
        127.0.0.1 from 0127.0.0.1, inet_aton reads 87.0.0.1). The detail of a call or a claim says what the sender can
        do; an effect's host gets none."""
        why = ("its host is an IPv4 address not written as a dotted quad: send it as four decimal numbers 0-255 without "
               "leading zeros")
        for host, url in (("87.0.0.1", "http://0127.0.0.1/"), ("127.0.0.1", "http://0127.0.0.1:8080/x"),
                          ("10.0.0.1", "http://010.0.0.1/"), ("192.168.0.10", "http://192.168.0.010/"),
                          ("127.0.0.1", "http://0127.0.0.1./"), ("127.0.0.1", "http://127.1/"),
                          ("127.0.0.1", "http://0x7f.0.0.1/"), ("127.0.0.1", "http://0X7F.0.0.1/"),
                          ("127.0.0.1", "http://2130706433/"), ("0.0.0.0", "http://0x/"),
                          ("1.2.3.4", "http://1.2.3.4.5/"), ("1.2.3.4", "http://a.1.2.3.4/"),
                          ("1.2.3.4", "http://1.2.3.256/"), ("8.8.8.8", "http://0128.0.0.1/"),
                          ("127.0.0.1", "http:\\\\0127.0.0.1/")):   # the browser's reading alone
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url})),
                                 ("unproven", f"the verifier can't tell whether call c1 reached {host}: {why}"))
        for host in ("0127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "127.0.0.01:443"):
            with self.subTest(host=host):
                self.assertEqual(claims.reached_host({"host": host}, effect("127.0.0.1")),
                                 ("unproven", f"{host} is no host the verifier can read: {why}"))
        for host in ("1::2:3:4:5:6:7:8", "10:20:30:40:50:60:70:80:90"):   # read in brackets, as _host does: no advice
            with self.subTest(host=host):
                self.assertEqual(claims.reached_host({"host": host}, effect("127.0.0.1")),
                                 ("unproven", f"{host} is no host the verifier can read"))
        for host in ("0127.0.0.1", "127.1", "2130706433"):
            with self.subTest(host=host):
                self.assertEqual(claims.reached_host({"host": "127.0.0.1"}, effect(host)),
                                 ("unproven", "effect.observed seq 3: a host the verifier can't read"))
        for host, url in (("1a.example", "http://1a.example/"), ("example.0x1g", "http://example.0x1g/")):
            with self.subTest(url=url):   # a last label that is no number: a name
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url}))[0], "proven")

    def test_a_claimed_host_that_reads_as_none_is_unproven(self):
        """`:80` passes the claim pattern and reads as no host, which must not match the no host of a file: URL or of an
        effect's `:443`."""
        for recs in (call("fetch", {"url": "file:///x"}), effect(":443")):
            with self.subTest(recs=recs):
                self.assertEqual(claims.reached_host({"host": ":80"}, recs),
                                 ("unproven", ":80 is no host the verifier can read"))

    def test_no_advice_for_a_url_the_bracket_rule_refuses(self):
        """The `%` and dotted-quad sentences are for a URL that passes the bracket rule (PCM 0.1 6.6): a reading of one
        it refuses moves with the URL and the urlsplit release."""
        # agent-flow:allow-secret (no password: an IPv6 address in the user info)
        for host, url in (("::1", "http://[::1]@[::1%25x]/"), ("127.0.0.1", "http://[x]@0127.0.0.1/")):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": host}, call("fetch", {"url": url})),
                                 ("unproven", f"the verifier can't tell whether call c1 reached {host}"))

    def test_a_view_source_or_blob_url_is_unproven(self):
        """A browser's address bar reads the URL inside view-source: and blob:, WHATWG URL reads no host from either:
        the verifier can't tell, and says nothing the sender could fix in the host."""
        for url in ("blob:http://a.com/x", "view-source:http://a.com/", "BLOB:view-source:https://a.com/",
                    "blob:http://[x]@a.com/", "blob:http://%61.com/", "view-source:http://0127.0.0.1/"):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": "a.com"}, call("fetch", {"url": url})),
                                 ("unproven", "the verifier can't tell whether call c1 reached a.com"))

    def test_an_ipv6_dotted_quad_with_a_leading_zero_is_unproven(self):
        """Python before 3.9.5 reads ::ffff:01.2.3.4 as ::ffff:1.2.3.4, later releases refuse it: PCM 0.1 refuses it
        on every release, emulated here."""
        octet = ipaddress._BaseV4._parse_octet.__func__
        lenient = classmethod(lambda cls, s: octet(cls, s.lstrip("0") or "0"))
        for old in (False, True):
            with self.subTest(old=old), mock.patch.object(ipaddress._BaseV4, "_parse_octet", lenient) if old \
                    else contextlib.nullcontext():
                for host, recs in (("1.2.3.4", call("fetch", {"url": "http://[::ffff:01.2.3.4]/"})),
                                   ("1.2.3.4", call("fetch", {"url": "http://[::ffff:1.2.03.4]/"})),
                                   ("1.2.3.4", call("fetch", {"url": "file://[::ffff:01.2.3.4]/"})),   # bracket rule
                                   # no authority, so no bracket rule: the readings' own check
                                   ("1.2.3.4", call("fetch", {"url": "http:\\\\[::ffff:01.2.3.4]/"})),
                                   ("1.2.3.4", call("fetch", {"url": "http:\\\\[::ffff:1.2.3.04]/"})),
                                   ("1.2.3.4", effect("::ffff:1.2.03.4")),
                                   ("::ffff:01.2.3.4", call("fetch", {"url": "http://1.2.3.4/"}))):
                    self.assertEqual(claims.reached_host({"host": host}, recs)[0], "unproven", (host, recs))

    def test_a_url_whose_scheme_has_no_host_reaches_none(self):
        for url in ("file://a.example/x", "gopher://a.example/", "FILE://a.example/x"):
            with self.subTest(url=url):
                self.assertEqual(claims.reached_host({"host": "a.example"}, call("fetch", {"url": url}))[0], "failed")
        self.assertEqual(claims.reached_host({"host": "a.example"}, call("fetch", {"url": "//a.example/x"}))[0],
                         "proven")

    def test_no_verdict_depends_on_the_urlsplit_release(self):
        """A `[` or `]` in a URL's authority reaches a host only as one pair around an IPv6 or IPvFuture address that
        opens the host after the last `@`, checked before anything else reads the URL. urlsplit's own check differs
        between Python releases (none, the first bracketed part of the authority, the part after the last `@`), and so
        does what it strips (leading controls and spaces from 3.11.4, tabs and newlines from 3.9.5), so each is
        emulated: the verdicts and details must not move."""
        def first_part(netloc):   # earlier CPython releases' check, from 3.11.4 on
            inside = netloc.partition("[")[2].partition("]")[0]
            if not (re.fullmatch(r"v[0-9A-Fa-f]+\..+", inside) if inside.startswith("v")
                    else ipaddress.ip_address(inside).version == 6):
                raise ValueError("Invalid IPv6 URL")
        cases = (("good.com", "http://[x]@good.com/", "unproven"), ("good.com", "http://[v1.x]@good.com/", "unproven"),
                 ("good.com", "[v1.x]@good.com/", "unproven"), ("evil.example", "http://[v1.x]@evil.example/",
                                                                  "unproven"),
                 ("::1", "http://[zz]@[::1]/", "unproven"), ("::1", "http://[::1]x/", "unproven"),
                 ("x", "http://[@x::1]/", "unproven"), ("a.com", "http://[x]@%61.com/", "unproven"),
                 # agent-flow:allow-secret (no password: an IPv6 address before an empty host)
                 ("api.example.com", "http://[::1]@/", "unproven"), ("::1", "http://[::1]@/", "unproven"),
                 ("a.example", " http://a.example\\@b.example/", "unproven"),
                 ("a.example", "\x01http://a.example/", "unproven"),
                 ("a.example", "ht\ttp://a.example\\@b.example/", "unproven"),
                 ("::1", "http://[::1]:8080/", "proven"), ("::1", "http://u@[::1]/x", "proven"),
                 ("1.2.3.4", "http://[::ffff:1.2.3.4]/", "proven"), ("good.com", "http://good.com/a[1]", "proven"),
                 ("good.com", "http://good.com/?q=]", "proven"), ("other.com", "http://good.com/?q=]", "failed"))
        self.addCleanup(urllib.parse.clear_cache)
        details = {}   # this release's, the first run's
        for emu in ({}, {"_check_bracketed_netloc": lambda netloc: None}, {"_check_bracketed_netloc": first_part},
                    {"_WHATWG_C0_CONTROL_OR_SPACE": ""},
                    {"_WHATWG_C0_CONTROL_OR_SPACE": "", "_UNSAFE_URL_BYTES_TO_REMOVE": []}):
            urllib.parse.clear_cache()   # urlsplit caches what it read
            with self.subTest(emu=emu), mock.patch.multiple(urllib.parse, create=True, **emu) if emu \
                    else contextlib.nullcontext():
                for host, url, want in cases:
                    got = claims.reached_host({"host": host}, call("fetch", {"url": url}))
                    self.assertEqual(got, (want, details.setdefault((host, url), got[1])), url)

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
