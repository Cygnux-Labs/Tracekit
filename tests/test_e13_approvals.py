"""E13: approvals on a signer with an approver config (04-design §5, decision S6). The approver is another identity, the
CLI answers as this process's uid, the web path answers through the viewer's approval pages for an OIDC person, and
each test fails without the part of the approvals it names."""
import http.client
import json
import os
import socket
import threading
import time
import types
import unittest
import uuid
from unittest import mock

import test_bundle_v2 as tb
import test_signer_service as ts
from test_webauthn import ORIGIN, RP_ID, Authenticator
from tracekit import observe, view
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.identity.webauthn import b64url, unb64url
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import StorageUnavailable
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

    def pending(self, tool="pay", raw='{"to": "acct-42", "cents": 1500}'):
        """A run of this process whose call tc-1 waits for approval; its approval_id."""
        n = uuid.uuid4().hex
        run = self.s.register_run({"request_id": f"reg{n}", "agent": {"name": "a"}})
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.s.decide({"request_id": f"d{n}", **self.run, "stream": "s", "client_seq": 0, "tool_call_id": "tc-1",
                       "tool": tool, "args_source": "raw", "args": raw})
        return self.s.approval_request({"request_id": f"a{n}", **self.run, "tool_call_id": "tc-1"})["approval_id"]

    def decide(self, aid, who=APPROVER, decision="approve", **kw):
        return self.s.call(who, "approval_decide", {"request_id": f"h{uuid.uuid4().hex}", "approval_id": aid,
                                                    "decision": decision, **kw})

    def refused(self, code, fn, *args, **kw):
        with self.assertRaises(RPCError) as cm:
            fn(*args, **kw)
        self.assertEqual(cm.exception.code, code, cm.exception)
        return cm.exception

    def consume(self, args=PAY, tool="pay"):
        return self.s.approval_consume({"request_id": f"c{uuid.uuid4().hex}", **self.run, "tool_call_id": "tc-1",
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

    def test_a_consumed_approval_covers_only_the_approved_arguments(self):
        self.decide(self.pending("mail"))
        self.assertTrue(self.consume(tool="mail")["ok"])
        for seq, args in ((1, PAY), (3, dict(PAY, to="acct-other"))):   # the same call, run again
            d = self.s.decide({"request_id": f"d{seq}", **self.run, "stream": "s", "client_seq": seq,
                               "tool_call_id": "tc-1", "tool": "mail", "args_source": "parsed", "args": args})
            self.s.complete({"request_id": f"c{seq}", **self.run, "stream": "s", "client_seq": seq + 1,
                             "tool_call_id": "tc-1", "decision_id": d["decision_id"], "status": "ok", "result": "sent",
                             "args_digest": event_hash({"tool": "mail", "args": args})})
        gaps = [g for g in self.records("capture.gap") if g["kind"] == "executed_against_policy"]
        self.assertEqual(len(gaps), 1, gaps)   # the approved arguments ran under the approval; the others did not

    def test_an_answer_racing_the_end_of_its_run_is_refused_cleanly(self):
        aid = self.pending()
        visible = self.s._visible

        def then_final(identity, approval_id):   # the run goes final right after the approval was looked up
            a = visible(identity, approval_id)
            self.s.close_run({"request_id": "close", **self.run})
            self.s.sweep(now=time.monotonic() + svc.GRACE_S + 1)
            return a
        self.s._visible = then_final
        self.refused("run_closed", self.decide, aid)


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

    def test_t2_executor_gets_the_real_args_and_the_approver_only_the_redacted_copy(self):
        secret = {"to": "acct-42", "cents": 1500, "key": "sk-ant-" + "x" * 24}   # a redaction fixture
        aid = self.pending(raw=json.dumps(secret))
        shown = self.s.call(APPROVER, "approval_get", {"approval_id": aid})
        self.assertNotIn(secret["key"], json.dumps(shown))
        self.assertNotIn("exec_args", shown)
        self.decide(aid)
        out = self.consume(secret)
        self.assertEqual((out["ok"], out["args"]), (True, secret))

    def test_t2_args_stay_out_of_the_retry_cache_and_a_retry_still_gets_them(self):
        self.decide(self.pending())
        req = {"request_id": "c-1", **self.run, "tool_call_id": "tc-1", "tool": "pay", "args_source": "parsed",
               "args": PAY}
        first = self.s.approval_consume(req)
        self.assertEqual((first["ok"], first["args"]), (True, PAY))
        self.assertEqual([v[1].get("args") for v in self.s.log.done.values() if "ok" in v[1]], [None])
        self.assertEqual(self.s.approval_consume(dict(req)), first)

    def test_a_rolled_back_request_leaves_no_copy_of_the_arguments(self):
        append = self.s.log.storage.append_batch

        def full(records):   # the disk fills up as the request is written
            if any(r["event"]["type"] == "approval.request" for r in records):
                raise StorageUnavailable("No space left on device")
            append(records)
        with mock.patch.object(self.s.log.storage, "append_batch", full):
            self.refused("unavailable", self.pending)
        self.assertEqual(os.listdir(os.path.join(self.dir, "approvals")), [])

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

    def test_abandon_reason_is_redacted_before_signing(self):
        aid = self.pending()
        secret = "sk-ant-" + "x" * 24   # a redaction fixture
        self.s.approval_abandon({"request_id": "ab", **self.run, "approval_id": aid, "reason": f"lost {secret}"})
        [rec] = self.records("approval.abandoned")
        self.assertNotIn(secret, rec["reason"])

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


BRIDGE = CallerIdentity("mtls", "spiffe://acme/viewer", True)
ALICE = {"subject": "corp/u-alice", "person": "corp/alice", "groups": ["corp/approvers"], "tenant": "default"}
BOB = {"subject": "corp/u-bob", "person": "corp/bob", "groups": ["corp/approvers"], "tenant": "default"}
CAROL = {"subject": "corp/u-carol", "person": "corp/carol", "groups": ["corp/approvers"], "tenant": "acme"}
OLIVE = {"subject": "corp/u-olive", "person": "corp/olive", "groups": ["corp/oncall"], "tenant": "acme"}
WEB = {"approvers": ["group:corp/approvers", f"uid:{APPROVER.subject}", "slack:T01/U02"],
       "break_glass": ["group:corp/oncall"],
       "webauthn": {"rp_id": RP_ID, "origin": ORIGIN}}
WIRE = Engine({"ask": [{"id": "WIRE", "tool": "^wire$", "pattern": "^", "approval": {"passkey": "required"}},
                       {"id": "MAIL", "tool": "^mail$", "pattern": "^"}]})


class Sessions:
    """Stands in for view.OidcLogin: sessions as its login leaves them (tests/test_identity_oidc.py logs in for real)."""
    redirect_uri = "https://127.0.0.1/callback"

    def __init__(self):
        self.by_id = {}

    def add(self, person, role):
        sid = uuid.uuid4().hex
        self.by_id[sid] = {"tenant": person["tenant"], "role": role, "person": person, "csrf": uuid.uuid4().hex,
                           "at": time.time()}
        return sid

    def session(self, sid):
        return self.by_id.get(sid)

    def tenant(self, sid):
        return self.by_id.get(sid, {}).get("tenant")


class TestWeb(Signer):
    """The viewer's approval pages, answering for OIDC people over the signer RPC as an authorized bridge."""
    approvals = WEB

    def setUp(self):
        super().setUp()
        self.sessions = Sessions()
        desk = view.ApprovalDesk(types.SimpleNamespace(call=lambda m, req: self.s.call(BRIDGE, m, req)), WEB["webauthn"])
        feed = types.SimpleNamespace(records=[], base=0, lock=threading.Condition(), verify=lambda t=None: (0, [], None))
        srv = view.server(feed, "127.0.0.1", 0, "tok", login=self.sessions, desk=desk)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.port = srv.server_address[1]

    def open(self):
        self.cfg["authorize"] = {
            "person:corp/bob": ["register_run", "decide", "approval_request"],
            f"mtls:{BRIDGE.subject}": ["approval_list", "approval_get", "approval_decide", "passkey_register",
                                       svc.ON_BEHALF]}
        self.cfg["multi_tenant_apps"] = [f"mtls:{BRIDGE.subject}"]   # it serves the approvers of every tenant
        s = svc.open_service(self.cfg, policy=WIRE)
        self.addCleanup(s.close)
        return s

    def web(self, method, path, person=ALICE, body=None, role="approver", csrf=True, ctype="application/json"):
        """(status, answer) of a request from a fresh session of `person`; the answer parsed when it is JSON."""
        sid = self.sessions.add(person, role)
        headers = {"Cookie": f"{observe.COOKIE}={sid}"}
        if body is not None:
            headers["Content-Type"] = ctype
            if csrf:
                headers["X-CSRF-Token"] = self.sessions.by_id[sid]["csrf"]
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=headers)
            r = c.getresponse()
            out = r.read()
            return r.status, json.loads(out) if r.getheader("Content-Type").startswith("application/json") else out
        finally:
            c.close()

    def register(self, person=ALICE):
        auth = Authenticator()
        code, _ = self.web("POST", "/api/passkey", person, {"credential_id": b64url(auth.id),
                                                            "public_key": b64url(auth.spki)})
        self.assertEqual(code, 200)
        return auth

    def assertion(self, aid, auth, person=ALICE):
        code, shown = self.web("GET", f"/api/approvals/{aid}", person)
        self.assertEqual((code, shown["passkey"]), (200, True))
        return auth.sign(unb64url(shown["challenge"]))

    def approve(self, aid, person=ALICE, **body):
        return self.web("POST", f"/api/approvals/{aid}", person, {"decision": "approve", **body})

    def test_answer_records_the_person_and_the_bridge(self):
        aid = self.pending("mail")
        code, page = self.web("GET", "/approvals")
        self.assertEqual(code, 200)
        self.assertIn(b"<script nonce=", page)
        code, listed = self.web("GET", "/api/approvals")
        self.assertEqual([a["approval_id"] for a in listed["approvals"]], [aid])
        code, out = self.approve(aid, reason="checked")
        self.assertEqual((code, out["state"]), (200, "approved"))
        [rec] = self.records("approval")
        self.assertEqual((rec["approver"], rec["channel"], rec["reason"]), ("oidc:corp/u-alice", "web", "checked"))
        self.assertEqual(rec["approver_identity"], {"scheme": "oidc", "subject": "corp/u-alice", "attested": False,
                                                    "person": "corp/alice"})
        self.assertEqual(rec["via"], {"scheme": "mtls", "subject": BRIDGE.subject, "attested": True})
        self.assertNotIn("passkey", rec)

    def test_bait_and_switch_after_a_passkey_approval(self):
        auth = self.register()
        aid = self.pending("wire")
        code, out = self.approve(aid, passkey=self.assertion(aid, auth))
        self.assertEqual((code, out["state"]), (200, "approved"))
        self.assertEqual(self.consume(dict(PAY, cents=1500000), tool="wire")["rule_ids"], ["TK-APPROVAL-MISMATCH"])
        self.assertTrue(self.consume(tool="wire")["ok"])
        [rec] = self.records("approval")
        self.assertEqual(rec["passkey"], {"credential_id": b64url(auth.id), "user_verified": True})

    def test_replayed_assertion_is_refused(self):
        auth = self.register()
        first = self.pending("wire")
        signed = self.assertion(first, auth)
        second = self.pending("wire")   # the same arguments, another run
        self.assertEqual(self.approve(second, passkey=signed)[0], 403)
        self.assertEqual(self.approve(first, passkey=signed)[0], 200)
        self.assertEqual(self.approve(first, passkey=signed)[0], 403)
        self.assertEqual(self.s.log.approvals[second]["state"], "requested")

    def test_expired_approval_is_refused(self):
        auth = self.register()
        aid = self.pending("wire")
        signed = self.assertion(aid, auth)
        self.s.sweep(wall=time.time() + svc.APPROVAL_TTL_S + 1)
        self.assertEqual(self.approve(aid, passkey=signed)[0], 409)

    def test_self_approval_by_person_id_is_refused(self):
        bob = CallerIdentity("oidc", "corp/u-bob-laptop", True, {"person": "corp/bob", "groups": []})
        run = self.s.call(bob, "register_run", {"request_id": "reg", "agent": {"name": "a"}})
        r = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.s.call(bob, "decide", {"request_id": "d", **r, "stream": "s", "client_seq": 0, "tool_call_id": "tc-1",
                                    "tool": "mail", "args_source": "parsed", "args": PAY})
        aid = self.s.call(bob, "approval_request", {"request_id": "a", **r, "tool_call_id": "tc-1"})["approval_id"]
        code, out = self.approve(aid, BOB)   # another subject, the same person
        self.assertEqual(code, 403, out)
        self.assertEqual(self.approve(aid)[0], 200)

    def test_cross_tenant_approval_is_refused(self):
        aid = self.pending("mail")
        self.assertEqual(self.web("GET", "/api/approvals", CAROL), (200, {"approvals": [], "next_cursor": None}))
        self.assertEqual(self.web("GET", f"/api/approvals/{aid}", CAROL)[0], 404)
        self.assertEqual(self.approve(aid, CAROL)[0], 404)

    def test_passkey_rule_is_not_approved_without_an_assertion(self):
        self.register()
        aid = self.pending("wire")
        self.assertEqual(self.approve(aid)[0], 403)
        self.refused("forbidden", self.decide, aid)   # nor over the CLI's RPC
        self.refused("forbidden", self.s.call, BRIDGE, svc.ON_BEHALF, {   # nor through a chat bridge
            "request_id": "slack-1", "approval_id": aid, "decision": "approve", "approver": "slack:T01/U02"})
        self.assertEqual(self.web("POST", f"/api/approvals/{aid}", body={"decision": "reject"})[0], 200)

    def test_break_glass_without_a_reason_is_refused(self):
        aid = self.pending("mail")
        self.assertEqual(self.approve(aid, OLIVE)[0], 403)
        code, out = self.approve(aid, OLIVE, reason="incident 7")
        self.assertEqual((code, out["state"]), (200, "approved"))
        [rec] = self.records("approval")
        self.assertEqual((rec["break_glass"], rec["approver_identity"]["person"]), (True, "corp/olive"))

    def test_csrf_role_and_bridge_grant(self):
        aid = self.pending("mail")
        self.assertEqual(self.web("POST", f"/api/approvals/{aid}", body={"decision": "approve"}, csrf=False)[0], 403)
        self.assertEqual(self.web("POST", f"/api/approvals/{aid}", body={"decision": "approve"},
                                  ctype="text/plain")[0], 403)
        self.assertEqual(self.web("POST", f"/api/approvals/{aid}", body={"decision": "approve"}, role="auditor")[0], 403)
        self.assertEqual(self.web("GET", "/api/approvals", role="auditor")[0], 403)
        self.refused("forbidden", self.s.call, APPROVER, "approval_list", {"on_behalf": ALICE})   # not a bridge
        self.assertEqual(self.s.log.approvals[aid]["state"], "requested")

    def test_a_person_registers_one_passkey(self):
        first, auth = self.register(), Authenticator()
        code, _ = self.web("POST", "/api/passkey", ALICE, {"credential_id": b64url(auth.id),
                                                           "public_key": b64url(auth.spki)})
        self.assertEqual(code, 403)
        self.restart()   # kept in data_dir
        aid = self.pending("wire")
        self.assertEqual(self.approve(aid, passkey=self.assertion(aid, auth))[0], 403)
        self.assertEqual(self.approve(aid, passkey=self.assertion(aid, first))[0], 200)

    def test_a_passkey_is_registered_only_soon_after_a_sign_in(self):
        now, auth = time.time(), Authenticator()
        desk = view.ApprovalDesk(types.SimpleNamespace(call=lambda m, req: self.s.call(BRIDGE, m, req)),
                                 WEB["webauthn"], clock=lambda: now)
        body = {"credential_id": b64url(auth.id), "public_key": b64url(auth.spki)}
        stale = {"person": ALICE, "at": now - view.PASSKEY_LOGIN_S - 1}
        self.assertEqual(desk.post(stale, "/api/passkey", body)[0], 403)
        self.assertEqual(self.s._passkeys, {})
        self.assertEqual(desk.post(dict(stale, at=now - 60), "/api/passkey", body)[0], 200)

    def test_self_approval_by_a_person_the_run_owner_maps_to(self):
        aid = self.pending("mail")   # registered by this process's uid
        self.s._persons[f"uid:{self.s.identity.subject}"] = "corp/alice"
        self.assertEqual(self.approve(aid)[0], 403)
        self.assertEqual(self.approve(aid, BOB)[0], 200)

    def test_a_retried_passkey_answer_gets_its_first_answer(self):
        auth = self.register()
        aid = self.pending("wire")
        req = {"request_id": "web-1", "approval_id": aid, "on_behalf": ALICE, "decision": "approve",
               "passkey": self.assertion(aid, auth)}
        first = self.s.call(BRIDGE, "approval_decide", req)
        self.assertEqual(self.s.call(BRIDGE, "approval_decide", dict(req)), first)

    def test_a_retry_evicted_from_the_cache_still_needs_its_passkey(self):
        self.register()
        aid = self.pending("wire")
        req = {"request_id": "web-1", "approval_id": aid, "on_behalf": ALICE, "decision": "approve"}
        done = self.s.log.done

        class Evicted(type(done)):   # the entry is there when the answer is checked, gone when the writer runs
            seen = False

            def __contains__(self, k):
                if k == ("oidc", ALICE["subject"], "web-1") and not self.seen:
                    self.seen = True
                    return True
                return super().__contains__(k)
        self.s.log.done = Evicted(done)
        self.refused("forbidden", self.s.call, BRIDGE, "approval_decide", req)
        self.assertEqual(self.s.log.approvals[aid]["state"], "requested")

    def test_a_blank_break_glass_reason_is_refused(self):
        aid = self.pending("mail")
        self.assertEqual(self.approve(aid, OLIVE, reason=" \n")[0], 403)
        self.assertEqual(self.s.log.approvals[aid]["state"], "requested")

    def test_a_bridge_acts_for_its_own_tenant_unless_multi_tenant(self):
        aid = self.pending("mail")   # tenant default
        self.s.multi_tenant_apps.clear()
        self.s.tenants[f"mtls:{BRIDGE.subject}"] = "acme"
        self.assertEqual(self.web("GET", "/api/approvals", ALICE)[0], 403)   # a person of another tenant than its own
        self.assertEqual(self.web("GET", f"/api/approvals/{aid}", ALICE)[0], 403)
        self.assertEqual(self.approve(aid, ALICE)[0], 403)
        self.assertEqual(self.web("GET", "/api/approvals", CAROL), (200, {"approvals": [], "next_cursor": None}))
        del self.s.tenants[f"mtls:{BRIDGE.subject}"]   # a bridge of the run's tenant
        alice = {k: v for k, v in ALICE.items() if k != "tenant"}   # no tenant named: the bridge's
        self.assertEqual(self.s.call(BRIDGE, "approval_decide", {"request_id": "web-1", "approval_id": aid,
                                                                 "on_behalf": alice, "decision": "approve"})["state"],
                         "approved")

    def test_a_bridge_granted_through_a_group_sees_its_tenants_approvals(self):
        aid = self.pending("mail")
        bot = CallerIdentity("oidc", "corp/svc-bridge", True, {"person": "corp/bridge", "groups": ["corp/bridges"]})
        self.s.authorize["group:corp/bridges"] = ["approval_list", svc.ON_BEHALF]
        self.assertEqual([a["approval_id"] for a in self.s.call(bot, "approval_list", {})["approvals"]], [aid])


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
