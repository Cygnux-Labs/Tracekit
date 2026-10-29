"""Approvals on the v2 signer (04-design §5, decision S6). Scenarios A–G of the binding rule run against FakeSigner,
the signer in process and the signer over its socket; then the real signer alone: restart, expiry, the binding record,
self-approval and the verifier's cap, and the `tracekit approvals` CLI against the signer and the dev signer."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

import test_bundle_v2 as tb
import test_rpc_contract as rc
import test_signer_service as ts
from tracekit import cli, schema
from tracekit.bundle_v2 import export
from tracekit.format.canon import canonical, event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from test_signer_privacy import SECRET

PAY = {"to": "acct-42", "cents": 1500}


class Scenarios(rc.Harness):
    def consume(self, args=PAY, tcid="tc-1", hint=None, **kw):
        req = self.run_req(tool_call_id=tcid, tool="pay", args_source="parsed", args=args, **kw)
        if hint:
            req["approval_id_hint"] = hint
        return self.call("approval_consume", req)

    def refused_with(self, code, out):
        self.assertEqual((out["ok"], out["rule_ids"]), (False, [code]), out)

    def test_a_happy_path(self):
        aid = self.ask(PAY)
        self.approve(aid)
        out = self.consume(hint=aid)
        self.assertEqual((out["ok"], out["rule_ids"], out["approval_id"]), (True, ["TK-APPROVED"], aid))
        self.assertEqual(self.wait(aid), "consumed")
        self.assertEqual(self.types().count("approval.consumed"), 1)

    def test_b_replay_is_refused(self):
        aid = self.ask(PAY)
        self.approve(aid)
        self.consume(hint=aid)
        self.refused_with("TK-APPROVAL-CONSUMED", self.consume(hint=aid))
        self.assertEqual(self.types()[-1], "approval.refused")

    def test_c_edited_args_are_a_signed_mismatch(self):
        aid = self.ask(PAY)
        self.approve(aid)
        self.refused_with("TK-APPROVAL-MISMATCH", self.consume(dict(PAY, cents=1500000), hint=aid))
        self.assertEqual(self.types()[-1], "approval.binding_mismatch")
        self.assertTrue(self.consume(hint=aid)["ok"])   # the approved args still run, once

    def test_d_another_runs_approval_is_not_bound(self):
        other = self.ask(PAY)
        self.approve(other)
        self.ask(PAY)
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(hint=other))
        self.assertEqual(self.wait(self.call("approval_request", self.run_req(tool_call_id="tc-1"))["approval_id"]),
                         "requested")

    def test_e_resume_without_a_human_approval(self):
        aid = self.ask(PAY)
        self.refused_with("TK-APPROVAL-REQUESTED", self.consume(hint=aid))
        self.approve(aid, "reject")
        self.refused_with("TK-APPROVAL-REJECTED", self.consume(hint=aid))

    def test_f_missing_hint_is_resolved_from_the_index(self):
        aid = self.ask(PAY)
        self.refused_with("TK-APPROVAL-REQUESTED", self.consume())
        self.approve(aid)
        self.assertEqual(self.consume()["approval_id"], aid)

    def test_g_rewritten_call_id_needs_its_own_approval(self):
        aid = self.ask(PAY)
        self.approve(aid)
        edited = dict(PAY, cents=9)
        self.decide(tool="pay", args=edited, tcid="tc-2")
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(edited, tcid="tc-2", hint=aid))
        self.refused_with("TK-APPROVAL-REQUIRED", self.consume(edited, tcid="tc-2"))

    def test_retry_needs_a_fresh_approval(self):
        aid = self.ask(PAY)
        self.approve(aid)
        self.consume(hint=aid)
        self.decide(tool="pay", args=PAY, attempt=1)
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(hint=aid, attempt=1))
        self.refused_with("TK-APPROVAL-REQUIRED", self.consume(attempt=1))
        fresh = self.call("approval_request", self.run_req(tool_call_id="tc-1", attempt=1))["approval_id"]
        self.assertNotEqual(fresh, aid)

    def test_abandoned_approval_is_never_consumed(self):
        aid = self.ask(PAY)
        self.approve(aid)
        out = self.call("approval_abandon", self.run_req(approval_id=aid))
        self.assertEqual(out["state"], "expired")
        self.refused_with("TK-APPROVAL-EXPIRED", self.consume(hint=aid))
        self.refused("approval_not_pending", "approval_abandon", self.run_req(approval_id=aid))
        self.assertIn("approval.abandoned", self.types())

    def test_one_approval_per_call_attempt(self):
        aid = self.ask(PAY)
        self.approve(aid, "reject")
        again = self.call("approval_request", self.run_req(tool_call_id="tc-1"))
        self.assertEqual((again["approval_id"], again["state"]), (aid, "rejected"))

    def test_allowed_call_needs_no_approval(self):
        self.register()
        req, _ = self.decide()
        out = self.call("approval_consume", self.run_req(tool_call_id="tc-1", tool=req["tool"], args_source="parsed",
                                                         args=req["args"]))
        self.assertEqual((out["ok"], out["rule_ids"]), (True, []))

    def test_approver_sees_the_signers_copy(self):
        self.register()
        self.decide(tool="pay", args=PAY)
        aid = self.call("approval_request", self.run_req(tool_call_id="tc-1", reason="reads a file"))["approval_id"]
        got = self.call("approval_get", {"approval_id": aid})
        self.assertEqual((got["tool"], got["args"], got["reason"], got["state"]), ("pay", PAY, "reads a file", "requested"))
        listed = self.call("approval_list", {"run_id": self.run_id})["approvals"]
        self.assertEqual([a["approval_id"] for a in listed], [aid])
        self.assertEqual(self.call("approval_list", {"run_id": "no-such-run"})["approvals"], [])


    def test_approver_copy_is_redacted_and_an_unknown_cursor_is_an_empty_page(self):
        self.register()
        self.decide(tool="pay", args={"key": SECRET})
        aid = self.call("approval_request", self.run_req(tool_call_id="tc-1", reason=f"uses {SECRET}"))["approval_id"]
        self.assertNotIn(SECRET, json.dumps(self.call("approval_get", {"approval_id": aid})))
        self.assertEqual(self.call("approval_list", {"cursor": "apr-unknown"}), {"approvals": [], "next_cursor": None})

    def test_a_call_run_without_a_consumed_approval_is_a_signed_gap(self):
        self.register()
        for tcid in ("tc-1", "tc-2"):
            req, d = self.decide(tool="pay", args=PAY, tcid=tcid)
            if tcid == "tc-2":
                aid = self.call("approval_request", self.run_req(tool_call_id=tcid))["approval_id"]
                self.approve(aid)
                self.assertTrue(self.consume(tcid=tcid, hint=aid)["ok"])
            self.complete(req, d)
        self.assertEqual([(e["data"]["kind"], e["data"]["tool_use_id"]) for e in self.read() if e["type"] == "capture.gap"],
                         [("executed_against_policy", "tc-1")])

    # approve, then retry: the first attempt was blocked before anyone answered (the Claude Code hook doesn't wait); a
    # person approves it, and the agent sends the same call again under a new tool_call_id

    def retry(self, args=PAY, tcid="tc-2"):
        """The agent's call `tcid` of pay(`args`), decided and asked for: (decide request, decision, approval)."""
        req, d = self.decide(tool="pay", args=args, tcid=tcid)
        self.assertEqual(d["decision"], "ask")
        return req, d, self.call("approval_request", self.run_req(tool_call_id=tcid))

    def test_approve_then_retry_runs_the_same_call_once(self):
        aid = self.ask(PAY)
        _, _, early = self.retry(tcid="tc-2")   # sent again before anyone answered: asks on its own
        self.assertNotEqual(early["approval_id"], aid)
        self.assertEqual(early["state"], "requested")
        self.approve(aid)
        req, d, again = self.retry(tcid="tc-3")
        self.assertEqual((again["approval_id"], again["state"]), (aid, "approved"))
        out = self.consume(tcid="tc-3", hint=aid)
        self.assertEqual((out["ok"], out["rule_ids"], out["approval_id"]), (True, ["TK-APPROVED"], aid))
        self.complete(req, d)
        self.assertEqual(self.wait(aid), "consumed")
        _, _, third = self.retry(tcid="tc-4")   # used up: the next one asks a person again
        self.assertNotIn(third["approval_id"], (aid, early["approval_id"]))
        self.assertEqual(third["state"], "requested")
        self.refused_with("TK-APPROVAL-REQUESTED", self.consume(tcid="tc-4"))
        self.refused_with("TK-APPROVAL-CONSUMED", self.consume(hint=aid))   # nor does the first attempt run now
        self.refused_with("TK-APPROVAL-CONSUMED", self.consume(tcid="tc-3", hint=aid))   # nor the retry twice
        types = self.types()
        self.assertEqual((types.count("approval.consumed"), types.count("approval.request")), (1, 3))
        self.assertNotIn("capture.gap", types)   # tc-3 ran under a consumed approval

    def test_the_first_attempt_run_anyway_after_its_retry_used_the_approval_ran_against_the_policy(self):
        """A retry consumed the approval and ran; the blocked first attempt's own result (an agent that ran it in spite
        of the ask) is a signed gap on every signer, the test double included: only the consuming call ran under it."""
        aid = self.ask(PAY)
        self.approve(aid)
        req, d, _ = self.retry(tcid="tc-3")
        self.assertTrue(self.consume(tcid="tc-3", hint=aid)["ok"])
        self.complete(req, d)
        first = next(e["data"] for e in self.read() if e["type"] == "policy.decision"   # the fake names it tool_call_id
                     and "tc-1" in (e["data"].get("tool_use_id"), e["data"].get("tool_call_id")))
        self.complete({"tool_call_id": "tc-1", "tool": "pay", "args": PAY}, {"decision_id": first["decision_id"]})
        self.assertEqual([(e["data"]["kind"], e["data"]["tool_use_id"]) for e in self.read() if e["type"] == "capture.gap"],
                         [("executed_against_policy", "tc-1")])

    def test_a_retry_with_other_args_needs_its_own_approval(self):
        """An approval covers its tool and arguments: the agent can't carry it over to a changed call."""
        aid = self.ask(PAY)
        self.approve(aid)
        edited = dict(PAY, cents=1500000)
        _, _, own = self.retry(edited)
        self.assertNotEqual(own["approval_id"], aid)
        self.assertEqual(own["state"], "requested")
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(edited, tcid="tc-2", hint=aid))
        self.refused_with("TK-APPROVAL-REQUESTED", self.consume(edited, tcid="tc-2"))
        self.decide(tool="pay", args=edited, tcid="tc-3")   # without asking: still no approval for these args
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(edited, tcid="tc-3", hint=aid))
        self.refused_with("TK-APPROVAL-REQUIRED", self.consume(edited, tcid="tc-3"))
        self.decide(tool="read_file", args=PAY, tcid="tc-4")   # another tool: allowed, and aid not used for it
        self.assertEqual(self.wait(aid), "approved")
        self.assertTrue(self.consume(hint=aid)["ok"])   # the approved call itself still runs, once

    def test_one_approval_runs_one_call(self):
        """Two retries of the same call both see the approval; only the first consume runs."""
        aid = self.ask(PAY)
        self.approve(aid)
        for tcid in ("tc-2", "tc-3"):
            self.assertEqual(self.retry(tcid=tcid)[2]["approval_id"], aid)
        self.assertTrue(self.consume(tcid="tc-2", hint=aid)["ok"])
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(tcid="tc-3", hint=aid))
        self.refused_with("TK-APPROVAL-REQUIRED", self.consume(tcid="tc-3"))
        self.assertEqual(self.types().count("approval.consumed"), 1)

    def test_a_rejected_or_abandoned_approval_is_never_used_by_a_retry(self):
        for end in ("reject", "abandon"):
            with self.subTest(end):
                aid = self.ask(PAY)
                if end == "reject":
                    self.approve(aid, "reject")
                else:
                    self.call("approval_abandon", self.run_req(approval_id=aid))
                _, _, own = self.retry()
                self.assertNotEqual(own["approval_id"], aid)
                self.assertEqual(own["state"], "requested")
                self.refused_with("TK-APPROVAL-UNBOUND", self.consume(tcid="tc-2", hint=aid))

    def test_another_runs_approval_is_never_used(self):
        aid = self.ask(PAY)
        self.approve(aid)
        self.ask(PAY)   # a new run's call of the same arguments: its own approval
        self.assertNotEqual(self.call("approval_request", self.run_req(tool_call_id="tc-1"))["approval_id"], aid)
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(hint=aid))

    def test_a_call_that_ran_has_its_own_approval_or_needs_none_uses_no_other(self):
        """A call that ran under the approval never runs under it again; one with an approval of its own keeps it; an
        allowed call asks for none; and the approval stays for the call it was asked for."""
        aid = self.ask(PAY)
        _, _, own = self.retry(tcid="tc-5")   # asked before the approval: its own, still waiting
        self.approve(aid)
        self.refused_with("TK-APPROVAL-REQUESTED", self.consume(tcid="tc-5"))
        self.refused_with("TK-APPROVAL-UNBOUND", self.consume(tcid="tc-5", hint=aid))
        self.assertEqual(self.call("approval_request", self.run_req(tool_call_id="tc-5"))["approval_id"],
                         own["approval_id"])
        self.retry(tcid="tc-2")
        self.assertTrue(self.consume(tcid="tc-2", hint=aid)["ok"])
        self.refused_with("TK-APPROVAL-CONSUMED", self.consume(tcid="tc-2", hint=aid))
        self.refused_with("TK-APPROVAL-CONSUMED", self.consume(tcid="tc-2"))
        other = self.ask(PAY)   # a new run: tc-1 asks, a person approves it
        self.approve(other)
        req, d = self.decide(tool="read_file", args={"path": "a.txt"}, tcid="tc-3")
        self.assertEqual(d["decision"], "allow")
        self.refused("unknown_tool_call", "approval_request", self.run_req(tool_call_id="tc-3"))
        out = self.call("approval_consume", self.run_req(tool_call_id="tc-3", tool="read_file", args_source="parsed",
                                                         args={"path": "a.txt"}))
        self.assertEqual((out["ok"], out["rule_ids"]), (True, []))
        self.assertEqual(self.wait(other), "approved")


class TestFakeApprovals(Scenarios, unittest.TestCase):
    make_signer = rc.TestFakeSigner.make_signer

    def test_approvals_follow_the_dev_signers_visibility_and_self_approval_rules(self):
        aid = self.ask(PAY)
        self.signer.identity, self.signer.tenant = "someone-else", "acme"
        self.assertEqual(self.call("approval_list", {})["approvals"], [])
        self.refused("unknown_approval", "approval_get", {"approval_id": aid})
        self.refused("unknown_approval", "approval_decide", {"request_id": self.rid(), "approval_id": aid,
                                                             "decision": "approve"})
        self.signer.tenant = "default"   # another identity of the run's tenant may answer: not a self-approval
        self.assertFalse(self.approve(aid)["self_approved"])


class TestServiceApprovals(Scenarios, unittest.TestCase):
    make_signer = ts.TestServiceContract.make_signer


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestServeApprovals(Scenarios, unittest.TestCase):
    make_signer = ts.TestServeContract.make_signer


class TestRealSigner(unittest.TestCase):
    def setUp(self):
        self.dir = ts.tmpdir(self)
        self.s = self.open()

    def open(self):
        s = svc.SignerService(self.dir, policy=ts.PAY_ASKS)
        self.addCleanup(s.close)
        return s

    def restart(self):
        self.s.close()
        self.s = self.open()

    def pending(self, reason=None):
        """A run whose call tc-1 waits for approval; (run, approval_id)."""
        run = self.s.register_run({"request_id": "reg", "agent": {"name": "a"}})
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.s.decide({"request_id": "d", **self.run, "stream": "s", "client_seq": 0, "tool_call_id": "tc-1",
                       "tool": "pay", "args_source": "raw", "args": '{"to": "acct-42", "cents": 1500}'})
        req = {"request_id": "a", **self.run, "tool_call_id": "tc-1", **({"reason": reason} if reason else {})}
        return self.s.approval_request(req)["approval_id"]

    def consume(self, **kw):
        return self.s.approval_consume({"request_id": f"c{uuid.uuid4().hex}", **self.run, "tool_call_id": "tc-1",
                                        "tool": "pay", "args_source": "parsed", "args": PAY, **kw})

    def events(self):
        self.s.close()
        es = [r["event"] for r in ts.records(self.dir)]
        for e in es:
            self.assertEqual(schema.validate(e), [], e)
        return [e for e in es if e["run_id"] == self.run["run_id"]]

    def test_restart_between_request_and_approve(self):
        aid = self.pending()
        self.restart()
        self.assertEqual(self.s.approval_get({"approval_id": aid})["args"], '{"to": "acct-42", "cents": 1500}')
        self.assertEqual(self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})["state"],
                         "approved")
        self.restart()
        self.assertTrue(self.consume()["ok"])
        self.assertIsNone(self.s.approval_get({"approval_id": aid})["args"])   # purged once consumed
        self.assertEqual(os.listdir(os.path.join(self.dir, "approvals")), [])

    def test_args_are_encrypted_at_rest(self):
        aid = self.pending()
        with open(os.path.join(self.dir, "approvals", aid), "rb") as f:
            self.assertNotIn(b"acct-42", f.read())

    def test_expiry(self):
        aid = self.pending()
        for _ in range(2):
            self.s.sweep(wall=time.time() + svc.APPROVAL_TTL_S + 1)
        with self.assertRaises(RPCError) as cm:
            self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.assertEqual(cm.exception.code, "approval_not_pending")
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-EXPIRED"])
        self.assertEqual(os.listdir(os.path.join(self.dir, "approvals")), [])
        self.assertEqual([e["type"] for e in self.events()].count("approval.expired"), 1)

    def test_approval_past_its_expiry_is_refused_before_the_sweep(self):
        aid = self.pending()
        self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.s.log.approvals[aid]["expires_at"] = svc._iso(time.time() - 1)
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-EXPIRED"])

    def test_binding_and_self_approval_are_recorded(self):
        aid = self.pending()
        out = self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.assertTrue(out["self_approved"])
        self.consume(args=dict(PAY, cents=1))
        es = {e["type"]: e for e in self.events()}
        req = es["approval.request"]["data"]
        self.assertEqual(req["binding_digest"], "sha256:" + hashlib.sha256(canonical(req["binding"])).hexdigest())
        self.assertEqual((req["binding"]["approval_id"], req["binding"]["attempt"]), (aid, 0))
        self.assertNotIn("args_digest", req["binding"])
        self.assertTrue(es["approval"]["data"]["self_approved"])
        self.assertEqual(es["approval.binding_mismatch"]["data"]["approved_commitment"], req["binding"]["args_commitment"])

    def retry(self, tcid, seq):
        """The agent's call `tcid` of the same pay as tc-1, decided (client_seq `seq`) and asked for: its approval."""
        self.s.decide({"request_id": f"d{tcid}", **self.run, "stream": "s", "client_seq": seq, "tool_call_id": tcid,
                       "tool": "pay", "args_source": "parsed", "args": PAY})
        return self.s.approval_request({"request_id": f"a{tcid}", **self.run, "tool_call_id": tcid})

    def test_the_retry_that_lost_the_race_for_an_approval_is_told_so(self):
        """Two retries of one approved call: the one whose consume came second read "approval_id not bound to this
        call", as if it had named another call's approval. It says the approval was used by another attempt."""
        aid = self.pending()
        self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        for tcid, seq in (("tc-2", 1), ("tc-3", 2)):
            self.assertEqual(self.retry(tcid, seq)["approval_id"], aid)
        self.assertTrue(self.consume(tool_call_id="tc-2", approval_id_hint=aid)["ok"])
        lost = self.consume(tool_call_id="tc-3", approval_id_hint=aid)
        self.assertEqual((lost["ok"], lost["rule_ids"], lost["reason"]), (
            False, ["TK-APPROVAL-UNBOUND"], f"approval {aid} was already used by another attempt of the same call"))
        other = self.retry("tc-4", 3)["approval_id"]   # another approval of the same call, never answered: not that
        self.assertNotEqual(other, aid)
        self.assertEqual(self.consume(tool_call_id="tc-4", approval_id_hint=other)["rule_ids"],
                         ["TK-APPROVAL-REQUESTED"])
        self.s.decide({"request_id": "d5", **self.run, "stream": "s", "client_seq": 4, "tool_call_id": "tc-5",
                       "tool": "pay", "args_source": "parsed", "args": dict(PAY, cents=1)})
        self.assertEqual(self.consume(tool_call_id="tc-5", args=dict(PAY, cents=1), approval_id_hint=aid)["reason"],
                         "approval_id not bound to this call")   # used, but by a call of other arguments

    def test_a_retry_after_a_restart_runs_under_the_approval_and_completes(self):
        aid = self.pending()
        self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.restart()
        self.assertEqual(self.retry("tc-2", 1)["approval_id"], aid)
        self.assertTrue(self.consume(tool_call_id="tc-2", approval_id_hint=aid)["ok"])
        self.restart()   # the snapshot keeps which call ran under it
        self.s.complete({"request_id": "c2", **self.run, "stream": "s", "client_seq": 2, "tool_call_id": "tc-2",
                         "decision_id": self.s.log.runs[("default", self.run["run_id"])]["calls"]["tc-2"]["decision_id"],
                         "args_digest": event_hash({"tool": "pay", "args": PAY}), "status": "ok"})
        es = self.events()
        self.assertNotIn("capture.gap", [e["type"] for e in es])
        used = next(e for e in es if e["type"] == "approval.consumed")
        self.assertEqual((used["tool_call_id"], used["data"]), ("tc-2", {"approval_id": aid}))

    def test_an_expired_approval_is_never_used_by_a_retry(self):
        aid = self.pending()
        self.s.approval_decide({"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.s.log.approvals[aid]["expires_at"] = svc._iso(time.time() - 1)
        again = self.retry("tc-2", 1)
        self.assertNotEqual(again["approval_id"], aid)
        self.assertEqual(again["state"], "requested")
        self.assertEqual(self.consume(tool_call_id="tc-2")["rule_ids"], ["TK-APPROVAL-REQUESTED"])

    def test_only_a_person_approves_so_the_agents_retry_stays_held(self):
        """System mode: signer.yaml names the approvers, so the agent's own uid (the requester and the run's owner)
        and any other non-approver are refused; nothing is approved, and the retry asks again. A person's approval
        lets the next retry run, once."""
        self.s.close()
        self.s = svc.SignerService(self.dir, policy=ts.PAY_ASKS, approvals={"approvers": ["uid:990001"]})
        self.addCleanup(self.s.close)
        aid = self.pending()
        for who, code in ((ts.ME, "forbidden"), (ts.OTHER, "unknown_approval")):   # not an approver: not shown it
            with self.subTest(who=who.subject), self.assertRaises(RPCError) as cm:
                self.s.call(who, "approval_decide", {"request_id": f"h{who.subject}", "approval_id": aid,
                                                     "decision": "approve"})
            self.assertEqual(cm.exception.code, code)
        held = self.retry("tc-2", 1)
        self.assertNotEqual(held["approval_id"], aid)
        self.assertEqual(self.consume(tool_call_id="tc-2", approval_id_hint=aid)["rule_ids"], ["TK-APPROVAL-UNBOUND"])
        person = CallerIdentity("uid", "990001", True)
        self.assertFalse(self.s.call(person, "approval_decide", {"request_id": "p", "approval_id": aid,
                                                                 "decision": "approve"})["self_approved"])
        self.assertEqual(self.retry("tc-3", 2)["approval_id"], aid)
        self.assertTrue(self.consume(tool_call_id="tc-3", approval_id_hint=aid)["ok"])
        self.assertNotEqual(self.retry("tc-4", 3)["approval_id"], aid)

    def test_another_tenant_does_not_see_the_approval(self):
        aid = self.pending()
        self.s.tenants[f"uid:{ts.OTHER.subject}"] = "acme"
        self.assertEqual(self.s.call(ts.OTHER, "approval_list", {})["approvals"], [])
        with self.assertRaises(RPCError) as cm:
            self.s.call(ts.OTHER, "approval_decide", {"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.assertEqual(cm.exception.code, "unknown_approval")


class TestExecutedAgainstPolicy(tb.Case):
    def test_a_call_run_against_the_policy_is_a_counted_warning(self):
        log = self.log()
        log.epoch(tb.KEY1)
        log.register()
        for tcid in ("t1", "t2"):
            log.add("capture.gap", {"kind": "executed_against_policy", "tool_use_id": tcid,
                                    "reason": f"{tcid} ran after a deny decision"})
        log.final()
        out = os.path.join(self.d, "a.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        [check] = [c for c in rep.checks if c["check"] == "policy"]
        self.assertEqual((check["status"], len(check["problems"])), ("warn", 2))
        self.assertIn("2 tool call(s)", check["detail"])


class TestSelfApprovalCapsAssurance(tb.Case):
    def test_witnessed_run_with_a_self_approval_is_dev(self):
        log = self.log()
        log.epoch(tb.KEY1)
        log.register()
        log.add("approval", {"tool_use_id": "t1", "approval_id": "apr-1", "decision": "approve", "approver": "uid:1",
                             "channel": "rpc", "self_approved": True})
        log.final()
        out = os.path.join(self.d, "a.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        self.assertTrue(rep.assurance.startswith("dev;"), rep.assurance)
        self.assertIn("; approvals: self", rep.assurance)


def tracekit(*args, env=None):
    return subprocess.run([sys.executable, "-m", "tracekit", *args], capture_output=True, text=True, timeout=60,
                          env=env, cwd=ts.ROOT)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCli(unittest.TestCase):
    def test_json_lists_all_pages_and_shows_redacted_decoded_arguments_without_a_pager(self):
        d = ts.tmpdir(self)
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "approvals": {"self_approval": "allow"}}
        service = svc.open_service(cfg, policy=ts.PAY_ASKS)
        self.addCleanup(service.close)
        for srv in svc.serve(cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = Client(cfg["socket"])
        self.addCleanup(client.close)
        run = client.run(agent="a")
        memo = "payment\n\x1b[31m"
        args = {"to": "acct-42", "memo": memo, "key": SECRET}
        aids = []
        for tcid, source in (("tc-1", "parsed"), ("tc-2", "raw")):
            run.decide(tcid, "pay", args if source == "parsed" else json.dumps(args), args_source=source)
            aids.append(run.call("approval_request", tool_call_id=tcid, reason=memo)["approval_id"])
        with mock.patch.object(svc, "LIST_PAGE", 1):
            listed = tracekit("approvals", "--signer", cfg["socket"], "list", "--json")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        rows = json.loads(listed.stdout)
        self.assertEqual([x["approval_id"] for x in rows], aids)
        self.assertEqual(rows, client.approval_list({})["approvals"])
        for row in rows:
            self.assertEqual((row["state"], row["tool"], row["rule_ids"]), ("requested", "pay", ["TEST-PAY"]))
        for aid in aids:
            buf = io.StringIO()
            with mock.patch("pydoc.pager") as pager, contextlib.redirect_stdout(buf):
                self.assertEqual(cli.main(["approvals", "--signer", cfg["socket"], "show", aid, "--json"]), 0)
            pager.assert_not_called()
            shown = buf.getvalue()
            approval = json.loads(shown)
            self.assertEqual(approval["approval_id"], aid)
            self.assertEqual(approval["args"]["memo"], memo)
            self.assertEqual(approval["reason"], memo)
            self.assertNotIn(SECRET, shown)
            self.assertNotEqual(approval["args"]["key"], SECRET)
            self.assertNotIn(memo, shown)
            self.assertIn(r"payment\n\u001b[31m", shown)
            text = tracekit("approvals", "--signer", cfg["socket"], "show", aid)
            self.assertIn(json.dumps(approval["args"], indent=2), text.stdout)

    def test_show_prints_the_real_args_and_approve_reject_round_trip(self):
        d = ts.tmpdir(self)
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "approvals": {"self_approval": "allow"}}
        service = svc.open_service(cfg, policy=ts.PAY_ASKS)
        self.addCleanup(service.close)
        for srv in svc.serve(cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = Client(cfg["socket"])
        self.addCleanup(client.close)
        run = client.run(agent="a")
        big = "x" * 5000
        aids = []
        for tcid in ("tc-1", "tc-2"):
            run.decide(tcid, "pay", {"to": "acct-666", "memo": big})
            aids.append(run.call("approval_request", tool_call_id=tcid, reason="harmless read of a.txt")["approval_id"])
        shown = tracekit("approvals", "--signer", cfg["socket"], "show", aids[0])
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn('"to": "acct-666"', shown.stdout)
        self.assertIn(big, shown.stdout)   # in full, never cut to a summary
        self.assertIn('unverified): "harmless read of a.txt"', shown.stdout)
        listed = tracekit("approvals", "--signer", cfg["socket"], "list").stdout
        self.assertEqual([line.split()[:2] for line in listed.splitlines()], [[a, "requested"] for a in aids])
        out = tracekit("approvals", "--signer", cfg["socket"], "approve", aids[0], "--reason", "checked")
        self.assertEqual((out.returncode, out.stdout.strip()), (0, f"approved: {aids[0]} (self-approved: dev mode only)"))
        self.assertEqual(tracekit("approvals", "--signer", cfg["socket"], "reject", aids[1]).returncode, 0)
        args = {"to": "acct-666", "memo": big}
        self.assertTrue(run.approval_consume("tc-1", "pay", args, approval_id_hint=aids[0])["ok"])
        self.assertEqual(run.approval_consume("tc-2", "pay", args)["rule_ids"], ["TK-APPROVAL-REJECTED"])
        again = tracekit("approvals", "--signer", cfg["socket"], "approve", aids[1])
        self.assertEqual(again.returncode, 1)
        self.assertIn("approval_not_pending", again.stderr)


    def test_a_refusal_and_an_empty_list_say_how_to_get_further(self):
        d = ts.tmpdir(self)
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock")}   # a configured signer without an approvals section
        service = svc.open_service(cfg, policy=ts.PAY_ASKS)
        self.addCleanup(service.close)
        for srv in svc.serve(cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        listed = tracekit("approvals", "--signer", cfg["socket"], "list")
        first, note = listed.stdout.splitlines()   # that it lists none, then who may see one
        self.assertEqual(first, "no approvals to show")   # it said "nothing is waiting": nothing waits on a held call
        self.assertIn(f"you are uid:{os.getuid()}", note)
        self.assertIn("approvals.approvers", note)
        listed = tracekit("approvals", "--signer", cfg["socket"], "list", "--json")
        self.assertEqual((listed.returncode, listed.stdout.strip()), (0, "[]"))
        client = Client(cfg["socket"])
        self.addCleanup(client.close)
        run = client.run(agent="a")
        run.decide("tc-1", "pay", PAY)
        aid = run.call("approval_request", tool_call_id="tc-1")["approval_id"]
        out = tracekit("approvals", "--signer", cfg["socket"], "approve", aid)
        self.assertEqual(out.returncode, 1)
        self.assertIn("may not answer its own run's approval", out.stderr)
        self.assertIn("approvals.approvers lists, or set approvals: {self_approval: allow}", out.stderr)

    def test_the_v1_approve_and_reject_answer_a_v2_id_as_approvals_does(self):
        """`tracekit approve|reject apr-...` said "signer unavailable": they are tracekitd's commands (#420). An id of
        the v2 signer's shape, `[<route>.]apr-` and 32 hex digits, is answered as `tracekit approvals` does; any other
        id, one that only contains "apr-" too, stays tracekitd's."""
        for route in (None, "tk-0"):
            d = ts.tmpdir(self)
            cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "approvals": {"self_approval": "allow"},
                   "route": route}
            service = svc.open_service(cfg, policy=ts.PAY_ASKS)
            self.addCleanup(service.close)
            for srv in svc.serve(cfg, service):
                self.addCleanup(srv.server_close)
                self.addCleanup(srv.shutdown)
            client = Client(cfg["socket"])
            self.addCleanup(client.close)
            run = client.run(agent="a")
            aids = []
            for tcid in ("tc-1", "tc-2"):
                run.decide(tcid, "pay", PAY)
                aids.append(run.call("approval_request", tool_call_id=tcid)["approval_id"])
            env = dict(os.environ, TRACEKIT_SIGNER=cfg["socket"])
            for cmd, aid, state in (("approve", aids[0], "approved"), ("reject", aids[1], "rejected")):
                out = tracekit(cmd, aid, env=env)
                self.assertEqual((out.returncode, out.stdout.strip()),
                                 (0, f"{state}: {aid} (self-approved: dev mode only)"), out.stderr)
            self.assertTrue(run.approval_consume("tc-1", "pay", PAY)["ok"])
            self.assertEqual(run.approval_consume("tc-2", "pay", PAY)["rule_ids"], ["TK-APPROVAL-REJECTED"])
        self.assertTrue(aids[0].startswith("tk-0.apr-"), aids[0])
        v1 = dict(env, TRACEKIT_CLIENT_HOME=os.path.join(d, "client"),
                  TRACEKIT_SOCKET=os.path.join(d, "tracekitd.sock"))   # no tracekitd runs there
        # a v1 id, a prefix of one, and ids with "apr-" in them that no v2 signer makes
        for aid in ("0" * 32, "0a1b", "apr-0004", aids[0] + "0"):
            out = tracekit("approve", aid, env=v1)
            self.assertEqual(out.returncode, 2, (aid, out.stderr))
            self.assertIn("signer unavailable", out.stderr)


@unittest.skipUnless(os.name == "posix", "POSIX paths, signals and shells; DevSignerOverTcp (test_signer_dev.py) runs everywhere")
class TestCliDevSigner(unittest.TestCase):
    def test_approve_round_trip_with_the_dev_signer(self):
        d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        env = {"TRACEKIT_RUNTIME_DIR": os.path.join(d, "run"), "TRACEKIT_DEV_IDLE": "60", "PYTHONPATH": ts.ROOT}
        fake = mock.patch.object(autospawn, "SIGNER_ARGV", [sys.executable, "-m", "tracekit.testing", "--ask", "pay"])
        fake.start()
        self.addCleanup(fake.stop)
        os.environ.pop("TRACEKIT_SIGNER", None)
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.addCleanup(lambda: [os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
                                 for k, v in saved.items()])
        self.addCleanup(autospawn.down)
        run = Client().run(agent="a")
        run.decide("tc-1", "pay", PAY)
        aid = run.call("approval_request", tool_call_id="tc-1")["approval_id"]
        out = tracekit("approvals", "approve", aid, env=dict(os.environ))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(run.approval_consume("tc-1", "pay", PAY)["ok"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["approvals", "list"]), 0)
        self.assertIn(f"{aid}  consumed", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
