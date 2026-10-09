"""E13: approvals on a signer with an approver config (04-design §5, decision S6). The approver is another identity, the
CLI answers as this process's uid, and each test fails without the part of the approvals it names."""
import os
import socket
import threading
import time
import unittest

import test_bundle_v2 as tb
import test_signer_service as ts
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from test_signer_approvals import tracekit

PAY = {"to": "acct-42", "cents": 1500}
APPROVER = CallerIdentity("uid", "999999", True)
STRANGER = CallerIdentity("uid", "777777", True)
GLASS = CallerIdentity("uid", "424242", True)
CONFIG = {"approvers": [f"uid:{APPROVER.subject}"], "break_glass": [f"uid:{GLASS.subject}"]}
T2 = Engine({"ask": [{"id": "PAY", "tool": "^pay$", "pattern": "^", "approval": {"executor": "t2"}},
                     {"id": "MAIL", "tool": "^mail$", "pattern": "^"}]})


class Signer(unittest.TestCase):
    approvals = CONFIG

    def setUp(self):
        self.dir = ts.tmpdir(self)
        self.cfg = {"data_dir": self.dir, "socket": os.path.join(self.dir, "s.sock"), "approvals": self.approvals}
        self.s = self.open()

    def open(self):
        s = svc.open_service(self.cfg, policy=T2)
        self.addCleanup(s.close)
        return s

    def restart(self):
        self.s.close()
        self.s = self.open()

    def pending(self, tool="pay"):
        """A run of this process whose call tc-1 waits for approval; its approval_id."""
        run = self.s.register_run({"request_id": "reg", "agent": {"name": "a"}})
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.s.decide({"request_id": "d", **self.run, "stream": "s", "client_seq": 0, "tool_call_id": "tc-1",
                       "tool": tool, "args_source": "raw", "args": '{"to": "acct-42", "cents": 1500}'})
        return self.s.approval_request({"request_id": "a", **self.run, "tool_call_id": "tc-1"})["approval_id"]

    def decide(self, aid, who=APPROVER, decision="approve", **kw):
        return self.s.call(who, "approval_decide", {"request_id": f"h{time.monotonic_ns()}", "approval_id": aid,
                                                    "decision": decision, **kw})

    def refused(self, code, fn, *args, **kw):
        with self.assertRaises(RPCError) as cm:
            fn(*args, **kw)
        self.assertEqual(cm.exception.code, code, cm.exception)
        return cm.exception

    def consume(self, args=PAY, tool="pay"):
        return self.s.approval_consume({"request_id": f"c{time.monotonic_ns()}", **self.run, "tool_call_id": "tc-1",
                                        "tool": tool, "args_source": "parsed", "args": args})

    def records(self, typ):
        self.s.close()
        return [r["event"]["data"] for r in ts.records(self.dir) if r["event"]["type"] == typ]


class TestBinding(Signer):
    def test_bait_and_switch(self):
        self.decide(self.pending())
        self.assertEqual(self.consume(dict(PAY, cents=1500000))["rule_ids"], ["TK-APPROVAL-MISMATCH"])
        self.assertTrue(self.consume()["ok"])

    def test_replay_of_a_consumed_approval(self):
        self.decide(self.pending())
        self.assertTrue(self.consume()["ok"])
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-CONSUMED"])

    def test_expiry(self):
        aid = self.pending()
        self.s.sweep(wall=time.time() + svc.APPROVAL_TTL_S + 1)
        self.refused("approval_not_pending", self.decide, aid)
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-EXPIRED"])

    def test_restart_keeps_pending_approvals(self):
        aid = self.pending()
        self.restart()
        self.assertEqual(self.decide(aid)["state"], "approved")
        self.assertTrue(self.consume()["ok"])


class TestWhoAnswers(Signer):
    def test_approver_is_recorded_as_the_transport_established_it(self):
        out = self.decide(self.pending())
        self.assertEqual((out["state"], out["self_approved"]), ("approved", False))
        [rec] = self.records("approval")
        self.assertEqual(rec["approver_identity"], {"scheme": "uid", "subject": APPROVER.subject, "attested": True})
        self.assertNotIn("break_glass", rec)

    def test_approver_not_in_the_list_is_refused(self):
        aid = self.pending()
        self.refused("unknown_approval", self.decide, aid, STRANGER)
        self.assertEqual(self.s.call(STRANGER, "approval_list", {})["approvals"], [])
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-REQUESTED"])

    def test_requester_cannot_approve_in_process(self):
        self.refused("forbidden", self.decide, self.pending(), self.s.identity)

    def test_approver_of_another_tenant_does_not_see_it(self):
        aid = self.pending()
        self.s.tenants[f"uid:{APPROVER.subject}"] = "acme"
        self.refused("unknown_approval", self.decide, aid)

    def test_break_glass_is_recorded_with_its_reason(self):
        aid = self.pending()
        self.s.tenants[f"uid:{GLASS.subject}"] = "acme"   # any tenant
        self.refused("forbidden", self.decide, aid, GLASS)
        self.assertEqual(self.decide(aid, GLASS, reason="incident 7")["state"], "approved")
        [rec] = self.records("approval")
        self.assertEqual((rec["break_glass"], rec["reason"], rec["approver"]), (True, "incident 7", f"uid:{GLASS.subject}"))

    def test_bad_config_is_refused(self):
        for bad in ({"self_approval": "maybe"}, {"approvers": "uid:1"}, {"approver": []}):
            with self.assertRaises(ValueError):
                svc.SignerService(ts.tmpdir(self), approvals=bad)


class TestExecutorAndListing(Signer):
    def test_t2_executor_gets_only_the_approved_args(self):
        self.decide(self.pending())
        self.assertEqual(self.consume(dict(PAY, cents=1))["rule_ids"], ["TK-APPROVAL-MISMATCH"])
        out = self.consume()
        self.assertEqual((out["ok"], out["args"]), (True, PAY))   # parsed from the signer's raw copy

    def test_t1_consume_returns_no_args(self):
        self.decide(self.pending("mail"))
        out = self.consume(tool="mail")
        self.assertTrue(out["ok"])
        self.assertNotIn("args", out)

    def test_t2_is_a_lint_checked_ask_rule_field(self):
        errs = policy_compile._lint({"deny": [{"id": "D", "pattern": "^", "approval": {"executor": "t2"}}],
                                     "ask": [{"id": "A", "pattern": "^", "approval": {"executor": "t3"}},
                                             {"id": "B", "pattern": "^", "approval": {"executor": "t2"}}]}, "p")
        self.assertEqual(len(errs), 2, errs)
        self.assertTrue(all("approval must be" in e for e in errs), errs)

    def test_abandoned_approval_refuses_consume(self):
        aid = self.pending()
        self.decide(aid)
        out = self.s.approval_abandon({"request_id": "ab", **self.run, "approval_id": aid, "reason": "state lost"})
        self.assertEqual(out["state"], "expired")
        self.assertEqual(self.consume()["rule_ids"], ["TK-APPROVAL-EXPIRED"])
        self.assertEqual(os.listdir(os.path.join(self.dir, "approvals")), [])
        self.assertEqual(self.records("approval.abandoned"), [{"approval_id": aid, "reason": "state lost"}])
        self.s = self.open()   # replayed: still ended
        self.assertEqual(self.s.log.approvals[aid]["state"], "expired")

    def test_list_is_paginated(self):
        aids = []
        for i in range(5):
            run = self.s.register_run({"request_id": f"reg{i}", "agent": {"name": "a"}})
            r = {"run_id": run["run_id"], "run_token": run["run_token"]}
            self.s.decide({"request_id": f"d{i}", **r, "stream": "s", "client_seq": 0, "tool_call_id": "tc-1",
                           "tool": "pay", "args_source": "parsed", "args": PAY})
            aids.append(self.s.approval_request({"request_id": f"a{i}", **r, "tool_call_id": "tc-1"})["approval_id"])
        pages, req = [], {"limit": 2}
        while True:
            page = self.s.call(APPROVER, "approval_list", req)
            pages.append([a["approval_id"] for a in page["approvals"]])
            if page["next_cursor"] is None:
                break
            req = {"limit": 2, "cursor": page["next_cursor"]}
        self.assertEqual(pages, [aids[:2], aids[2:4], aids[4:]])

    def test_concurrent_waits_are_capped_per_identity(self):
        self.cfg["limits"] = {"concurrent_waits": 1}
        self.restart()
        aid = self.pending()
        wait = {"approval_id": aid, **self.run, "timeout_ms": 5000}
        t = threading.Thread(target=self.s.approval_wait, args=(wait,))
        t.start()
        time.sleep(0.2)
        self.refused("quota_exceeded", self.s.approval_wait, dict(wait, timeout_ms=0))
        self.decide(aid)
        t.join()
        self.assertEqual(self.s.approval_wait(dict(wait, timeout_ms=0))["state"], "approved")


class TestVerifierListsBreakGlass(tb.Case):
    def test_break_glass_approval_is_listed(self):
        log = self.log()
        log.epoch(tb.KEY1)
        log.register()
        log.add("approval", {"tool_use_id": "t1", "approval_id": "apr-1", "decision": "approve", "approver": "uid:0",
                             "channel": "rpc", "self_approved": False, "break_glass": True, "reason": "incident 7"})
        log.final()
        out = os.path.join(self.d, "a.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, code = self.verify(out)
        [c] = [c for c in rep.checks if c["check"] == "break-glass approvals"]
        self.assertEqual(c["status"], "warn")
        self.assertIn("incident 7", str(c))


def cli_approve(case):
    """`tracekit approvals approve` (as this process's uid, the requester) on a pending approval; (output, its id)."""
    aid = case.pending()
    for srv in svc.serve(case.cfg, case.s):
        case.addCleanup(srv.server_close)
        case.addCleanup(srv.shutdown)
    return tracekit("approvals", "--signer", case.cfg["socket"], "approve", aid), aid


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCli(Signer):
    def test_self_approval_is_refused_under_a_config(self):
        out, _ = cli_approve(self)
        self.assertEqual(out.returncode, 1)
        self.assertIn("forbidden", out.stderr)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCliDev(Signer):
    def open(self):
        s = svc.SignerService(self.dir, policy=T2)   # no approver config: the dev signer's rules
        self.addCleanup(s.close)
        return s

    def test_self_approval_is_labelled_under_dev(self):
        out, aid = cli_approve(self)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, f"approved: {aid} (self-approved: dev mode only)"))


if __name__ == "__main__":
    unittest.main()
