"""Approvals on the v2 signer (04-design §5, decision S6). Scenarios A–G of the binding rule run against FakeSigner,
the signer in process and the signer over its socket; then the real signer alone: restart, expiry, the binding record,
self-approval and the verifier's cap, and the `tracekit approvals` CLI against the signer and the dev signer."""
import contextlib
import hashlib
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_bundle_v2 as tb
import test_rpc_contract as rc
import test_signer_service as ts
from tracekit import cli, schema
from tracekit.bundle_v2 import export
from tracekit.format.canon import canonical, event_hash
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError

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


class TestFakeApprovals(Scenarios, unittest.TestCase):
    make_signer = rc.TestFakeSigner.make_signer


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
        return self.s.approval_consume({"request_id": f"c{time.monotonic_ns()}", **self.run, "tool_call_id": "tc-1",
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
        binding = {k: v for k, v in req["binding"].items() if k != "args_commitment"}
        binding["args_digest"] = event_hash({"tool": "pay", "args": PAY})
        self.assertEqual(req["binding_digest"], "sha256:" + hashlib.sha256(canonical(binding)).hexdigest())
        self.assertEqual((req["binding"]["approval_id"], req["binding"]["attempt"]), (aid, 0))
        self.assertNotIn("args_digest", req["binding"])
        self.assertTrue(es["approval"]["data"]["self_approved"])
        self.assertEqual(es["approval.binding_mismatch"]["data"]["approved_commitment"], req["binding"]["args_commitment"])

    def test_another_tenant_does_not_see_the_approval(self):
        aid = self.pending()
        self.s.tenants[f"uid:{ts.OTHER.subject}"] = "acme"
        self.assertEqual(self.s.call(ts.OTHER, "approval_list", {})["approvals"], [])
        with self.assertRaises(RPCError) as cm:
            self.s.call(ts.OTHER, "approval_decide", {"request_id": "h", "approval_id": aid, "decision": "approve"})
        self.assertEqual(cm.exception.code, "unknown_approval")


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
        self.assertTrue(rep.assurance.endswith("; approvals: self"), rep.assurance)


def tracekit(*args, env=None):
    return subprocess.run([sys.executable, "-m", "tracekit", *args], capture_output=True, text=True, timeout=60,
                          env=env, cwd=ts.ROOT)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestCli(unittest.TestCase):
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
