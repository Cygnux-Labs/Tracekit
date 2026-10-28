"""Containment (docs/incidents.md): holds, quarantines and suspensions enforced by the signer, the operator calls, the
`incidents` check of both verifiers, the viewer's marks and `tracekit signer incidents`; and eval E17 part 2."""
import contextlib
import importlib.util
import io
import json
import os
import sys
import threading
import time
import types
import unittest
from unittest import mock

import pytest

from tracekit import view
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.schema import validate
from tracekit.signer import detect
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.verify import v2

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, TESTS)
_spec = importlib.util.spec_from_file_location("e17_containment", os.path.join(ROOT, "eval", "e17_containment.py"))
e17c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e17c)
e17, HOLD, ME, OP, PAY = e17c.e17, e17c.HOLD, e17c.ME, e17c.OP, e17c.PAY
OTHER = CallerIdentity("uid", "777777", True)   # an approver, not mapped to a person
GLASS = CallerIdentity("uid", "888888", True)   # break-glass, a person


class Signer(e17c.Signer):
    """E17's containment signer with self_approval allow, a non-person approver, a break-glass person and the rest of
    `approvals` given."""

    def __init__(self, pol=HOLD, **approvals):
        self.extra = approvals
        super().__init__(pol)

    def open(self):
        person = f"uid:{OP.subject}"
        grants = sorted(svc.OPERATOR | {"approval_decide"})
        self.s = svc.SignerService(
            self.dir, policy=self.eng, grace_s=0, idle_s=60, limits=self.limits or Limits(events_per_s=1e6, burst=10 ** 6),
            approvals={"approvers": [person, f"uid:{OTHER.subject}"], "break_glass": [f"uid:{GLASS.subject}"],
                       "persons": {person: "alice", f"uid:{GLASS.subject}": "gwen"}, "self_approval": "allow",
                       **self.extra},
            authorize={k: grants for k in (person, f"uid:{OTHER.subject}", f"uid:{GLASS.subject}")},
            suspensions=getattr(self, "suspensions", None))

    def as_(self, who, method, req):
        self.n += 1
        rid = {"request_id": f"as-{self.n}"} if "request_id" in REQUESTS[method]["properties"] else {}
        return self.s.call(who, method, {**rid, **req})

    def held_approval(self, run, tcid="p"):
        self.decide(run, PAY, tcid=tcid)
        return self.call("approval_request", {**run, "tool_call_id": tcid})["approval_id"]


TWO_HOLDS = {**HOLD, "respond": HOLD["respond"] + [{"trigger": "denied_calls", "max": 2, "window": 600, "mode": "enforce",
                                                     "action": "hold"}]}


def two_holds(s, run):
    """Hold `run` by Q, then by denied_calls too; their incident ids."""
    s.hold(run)
    for i in range(4):
        s.decide(run, ("read_file", {"path": f"/forbidden/{i}"}))
    return [i["incident_id"] for i in s.incidents(run)]


class Case(unittest.TestCase):
    def signer(self, pol=HOLD, **approvals):
        s = Signer(pol, **approvals)
        self.addCleanup(s.close)
        return s

    def refused(self, f, code="forbidden", why=""):
        with self.assertRaises(RPCError) as c:
            f()
        self.assertEqual(c.exception.code, code, c.exception.message)
        self.assertIn(why, c.exception.message)


class TestE17(unittest.TestCase):
    @pytest.mark.unverified_bundles
    def test_every_scenario_holds(self):
        for name, f in e17c.SCENARIOS.items():
            with self.subTest(name):
                ok, detail = f()
                self.assertTrue(ok, detail)


class TestHold(Case):
    def test_the_call_that_fires_it_is_held_and_earlier_calls_are_in_flight(self):
        s = self.signer()
        run = s.register()
        first = s.decide(run, e17.SECRET)
        out = s.decide(run, e17.EGRESS)
        self.assertEqual((out["decision"], out["rule_ids"]), ("ask", ["T-EGRESS", "TK-HOLD"]))
        self.assertIn("a person ends the hold", out["reason"])
        inc = s.incidents(run)[0]
        self.assertEqual((inc["mode"], inc["actions"], inc["incident_id"]), ("enforce", ["hold"], out["incident_id"]))
        self.assertEqual([x["decision_id"] for x in inc["in_flight"]], [first["decision_id"]])
        types_ = [e["type"] for e in s.events(run)]
        self.assertEqual(types_[-4:], ["policy.decision", "incident.opened", "run.held", "policy.decision"])
        for e in s.events():
            self.assertEqual(validate(e), [], e["type"])
        # the first decision of the held call is gone: completing it is refused
        self.refused(lambda: s.call("complete", {**run, "stream": "s", "client_seq": 9, "tool_call_id": "tc-1",
                                                 "decision_id": s.events(run)[2]["data"]["decision_id"],
                                                 "args_digest": "sha256:" + "0" * 64, "status": "ok"}),
                     "unknown_decision")

    def test_only_a_person_answers_a_held_call(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        aid = s.held_approval(run)
        self.refused(lambda: s.call("approval_decide", {"approval_id": aid, "decision": "approve"}), why="a person")
        self.refused(lambda: s.as_(OTHER, "approval_decide", {"approval_id": aid, "decision": "approve"}),
                     why="a person answers it")
        s.as_(OP, "approval_decide", {"approval_id": aid, "decision": "approve"})
        ok = s.call("approval_consume", {**run, "tool_call_id": "p", "tool": "pay", "args_source": "parsed",
                                         "args": PAY[1]})
        self.assertTrue(ok["ok"])
        answer = [e["data"] for e in s.events(run) if e["type"] == "approval"][0]
        self.assertEqual((answer["incident_id"], answer["person"]), (s.incidents(run)[0]["incident_id"], "alice"))

    def test_the_owner_is_refused_even_as_a_person_with_self_approval_allowed(self):
        s = self.signer(persons={f"uid:{ME.subject}": "me", f"uid:{OP.subject}": "alice"})
        run = s.register()
        s.hold(run)
        aid = s.held_approval(run)
        self.refused(lambda: s.call("approval_decide", {"approval_id": aid, "decision": "approve"}),
                     why="whatever self_approval says")

    def test_a_hold_wakes_waiters_on_the_approvals_it_expires(self):
        s = self.signer()
        run = s.register()
        s.decide(run, PAY, tcid="p")
        aid = s.call("approval_request", {**run, "tool_call_id": "p"})["approval_id"]
        got = []
        t = threading.Thread(target=lambda: got.append((s.s.call(ME, "approval_wait", {
            **run, "approval_id": aid, "timeout_ms": 10000}), time.monotonic())))
        t.start()
        time.sleep(0.2)
        start = time.monotonic()
        s.hold(run)
        t.join(10)
        self.assertEqual(got[0][0]["state"], "expired")
        self.assertLess(got[0][1] - start, 0.9)   # woken, not the once-a-second recheck
        self.assertFalse(os.path.exists(os.path.join(s.dir, "approvals", aid)))

    def test_paused_the_engine_records_and_does_not_act(self):
        s = self.signer()
        s.as_(OP, "response_pause", {"reason": "maintenance"})
        run = s.register()
        self.assertEqual(s.hold(run)["decision"], "allow")
        inc = s.incidents(run)[0]
        self.assertEqual((inc["actions"], inc["would"]), ([], ["hold"]))
        self.assertIn("paused", inc["reason"])
        s.as_(OP, "response_resume", {})
        other = s.register()
        self.assertEqual(s.hold(other)["decision"], "ask")
        self.assertEqual([e["data"]["enabled"] for e in s.events() if e["type"] == "incident.response"], [False, True])

    def test_a_decision_the_detector_cant_vouch_for_holds_its_run(self):
        s = self.signer()
        run = s.register()
        s.s.log.write(lambda tx: tx.set(s.s.log.det, "until", time.time() + 60))
        out = s.decide(run, e17.SECRET)
        self.assertEqual(out["decision"], "ask")
        self.assertEqual(s.incidents(run)[0]["trigger"], "detector_unavailable")
        self.assertIn('tracekit_signer_detector_unavailable 1', s.s.metrics.render())

    def test_a_child_of_a_held_run_starts_held(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        child = s.register(parent=run)
        self.assertEqual(s.state(child), "held")
        self.assertTrue([e for e in s.events(child) if e["type"] == "run.held"][0]["data"]["inherited"])

    def test_a_run_held_by_two_incidents_stays_held_until_both_end(self):
        s = self.signer(TWO_HOLDS)
        run = s.register()
        first, second = two_holds(s, run)
        self.assertEqual([e["data"]["incident_id"] for e in s.events(run) if e["type"] == "run.held"], [first, second])
        s.as_(OP, "incident_resolve", {"incident_id": first})
        self.assertEqual(s.events(run)[-1]["data"]["held_by"], [second])
        out = s.decide(run, e17.EGRESS)
        self.assertEqual((out["decision"], out["incident_id"]), ("ask", second))
        self.assertEqual(s.as_(OP, "incident_show", {"incident_id": second})["runs"],
                         [{"run_id": run["run_id"], "state": "held"}])
        s.as_(OP, "incident_resolve", {"incident_id": second})
        self.assertEqual(s.decide(run, e17.EGRESS)["decision"], "allow")

    def test_resume_ends_every_hold(self):
        s = self.signer(TWO_HOLDS)
        run = s.register()
        both = two_holds(s, run)
        s.as_(OP, "run_resume", {"run_id": run["run_id"]})
        self.assertEqual([(e["data"]["incident_id"], e["data"]["held_by"]) for e in s.events(run)
                          if e["type"] == "run.resumed"], [(both[0], [both[1]]), (both[1], [])])
        self.assertEqual(s.decide(run, e17.EGRESS)["decision"], "allow")

    def test_metrics(self):
        s = self.signer()
        s.hold(s.register())
        text = s.s.metrics.render()
        self.assertIn('tracekit_signer_incidents_total{trigger="sequence",action="hold",mode="enforce"} 1', text)
        self.assertIn("tracekit_signer_held_runs 1", text)
        self.assertIn("tracekit_signer_quarantined_runs 0", text)


class TestQuarantine(Case):
    def test_denies_are_capped_then_refused_and_consumes_refused(self):
        s = self.signer()
        run = s.register()
        s.as_(OP, "run_quarantine", {"run_id": run["run_id"], "reason": "case 1"})
        with mock.patch.object(svc, "QUARANTINE_DENIES", 2):
            self.assertEqual([s.decide(run, e17.SECRET)["rule_ids"] for _ in range(2)], [["TK-QUARANTINE"]] * 2)
            self.refused(lambda: s.decide(run, e17.SECRET), why="refused unrecorded")
        out = s.call("approval_consume", {**run, "tool_call_id": "x", "tool": "pay", "args_source": "parsed",
                                          "args": PAY[1]})
        self.assertEqual(out["rule_ids"], ["TK-QUARANTINE"])

    def test_resolve_is_not_undo(self):
        s = self.signer()
        run = s.register()
        iid = s.as_(OP, "run_quarantine", {"run_id": run["run_id"]})["incident_id"]
        self.assertEqual(s.as_(OP, "incident_resolve", {"incident_id": iid})["resumed"], [])
        self.assertEqual(s.state(run), "quarantined")
        self.refused(lambda: s.as_(OP, "run_resume", {"run_id": run["run_id"]}), "invalid_request",
                     "a quarantine is final")
        self.assertEqual(s.as_(OP, "incident_show", {"incident_id": iid})["state"], "resolved")


class TestOperators(Case):
    def test_resolve_needs_a_person_not_of_the_run_and_break_glass_a_reason(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        iid = s.incidents(run)[0]["incident_id"]
        self.refused(lambda: s.as_(OTHER, "incident_resolve", {"incident_id": iid}), why="is not a person")
        self.refused(lambda: s.as_(GLASS, "incident_resolve", {"incident_id": iid}), why="needs a reason")
        out = s.as_(GLASS, "incident_resolve", {"incident_id": iid, "reason": "on call, case 7"})
        self.assertEqual(out["resumed"], [run["run_id"]])
        done = [e for e in s.events() if e["type"] == "incident.resolved"][0]
        self.assertEqual((done["run_id"], done["data"]["person"], done["data"]["break_glass"]),
                         ("tracekit/signer", "gwen", True))
        self.assertEqual(s.decide(run, e17.SECRET)["decision"], "allow")
        self.refused(lambda: s.as_(OP, "incident_resolve", {"incident_id": iid}), "invalid_request", "resolved already")

    def test_the_runs_owner_can_not_resolve(self):
        s = self.signer(persons={f"uid:{OP.subject}": "alice", f"uid:{OTHER.subject}": "alice"})
        run = s.register()
        s.hold(run)
        iid = s.incidents(run)[0]["incident_id"]
        with mock.patch.dict(s.s.log.runs[("default", run["run_id"])], owner=f"uid:{OP.subject}"):
            self.refused(lambda: s.as_(OTHER, "incident_resolve", {"incident_id": iid}), why="owner, principal")

    def test_hold_without_person_approvers_is_refused(self):
        s = e17c.Signer(approvers=False)
        self.addCleanup(s.close)
        run = s.register()
        self.refused(lambda: s.op("run_hold", {"run_id": run["run_id"]}), "invalid_request", "quarantine the run")

    def test_hold_resume_list_show(self):
        s = self.signer()
        run = s.register()
        iid = s.as_(OP, "run_hold", {"run_id": run["run_id"], "reason": "looks odd"})["incident_id"]
        self.assertEqual(s.decide(run, e17.SECRET)["incident_id"], iid)
        listed = s.s.call(OP, "incident_list", {"state": "open"})["incidents"]
        self.assertEqual([(x["incident_id"], x["trigger"], x["runs"]) for x in listed],
                         [(iid, "operator", [{"run_id": run["run_id"], "state": "held"}])])
        s.as_(OP, "run_resume", {"run_id": run["run_id"]})
        self.assertEqual(s.s.call(OP, "incident_show", {"incident_id": iid})["runs"][0]["state"], "resumed")
        self.assertEqual(s.decide(run, e17.SECRET)["decision"], "allow")
        other = CallerIdentity("uid", "999999", True)
        s.s.tenants["uid:999999"] = "acme"
        s.s.authorize["uid:999999"] = sorted(svc.OPERATOR)
        self.refused(lambda: s.s.call(other, "incident_show", {"incident_id": iid}), "unknown_incident")
        for e in s.events():
            self.assertEqual(validate(e), [], e["type"])

    def test_an_operator_response_passes_to_the_owners_next_run(self):
        for method, state in (("run_hold", "held"), ("run_quarantine", "quarantined")):
            with self.subTest(method):
                s = self.signer()
                run = s.register()
                iid = s.as_(OP, method, {"run_id": run["run_id"]})["incident_id"]
                s.call("close_run", run)
                new = s.s.log.runs[("default", s.register()["run_id"])]
                self.assertEqual(new.get(state), [iid] if state == "held" else iid)

    def test_a_run_without_an_attested_principal_inherits_every_hold_of_its_owner(self):
        s = self.signer()
        run = s.register()
        iid = s.as_(OP, "run_hold", {"run_id": run["run_id"]})["incident_id"]
        s.call("close_run", run)
        cool = s.s.log.contain["cooldown"]
        [key] = list(cool)
        cool[key + "alice"] = cool.pop(key)   # the held run was alice's (an attested principal)
        new = s.s.log.runs[("default", s.register()["run_id"])]   # the next run sends no principal_token
        self.assertEqual(new.get("held"), [iid])

    def test_an_identity_granted_register_run_and_operator_calls_refuses_to_start(self):
        with self.assertRaisesRegex(ValueError, "uid:1 both register_run and containment's operator calls"):
            svc.SignerService(os.path.join(self.signer().dir, "other"), policy=e17.engine(HOLD),
                              authorize={"uid:1": ["register_run", "decide", "run_resume"]})

    def test_an_identity_whose_keys_together_grant_register_run_can_not_operate(self):
        s = self.signer()
        s.s.authorize.update({"oidc:corp/*": ["register_run"], "group:sre": sorted(svc.OPERATOR)})
        bob = CallerIdentity("oidc", "corp/u-bob", True, {"person": "corp/bob", "groups": ["sre"]})
        self.refused(lambda: s.as_(bob, "response_pause", {}), why="is also granted register_run")
        s.s.authorize["oidc:corp/*"] = ["approval_decide"]
        s.as_(bob, "incident_list", {})

    def test_resolved_holds_leave_no_cooldown_behind(self):
        s = self.signer()
        for _ in range(20):
            run = s.register()
            iid = s.as_(OP, "run_hold", {"run_id": run["run_id"]})["incident_id"]
            s.as_(GLASS, "incident_resolve", {"incident_id": iid, "reason": "on call, case 7"})
            s.call("close_run", run)
        self.assertEqual(s.s.log.contain["cooldown"], {})

    def test_operator_calls_are_never_defaults(self):
        self.assertLessEqual(svc.OPERATOR, svc.NEVER_DEFAULT)


class TestSuspension(Case):
    def test_suspend_refuses_every_call_and_each_replica_records_it(self):
        a = self.signer()
        a.suspensions = os.path.join(a.dir, "shared.json")
        a.s.close()
        a.open()
        run = a.register()
        b = self.signer()
        b.suspensions = a.suspensions
        b.s.close()
        b.open()
        a.as_(OP, "suspend", {"identity": f"uid:{ME.subject}", "reason": "case 3"})
        self.refused(lambda: a.decide(run, e17.SECRET), why="is suspended")
        self.refused(lambda: b.register(), why="tracekit signer incidents unsuspend")
        states = [(e["data"]["state"], e["data"]["by"]) for e in b.events() if e["type"] == "identity.suspension"]
        self.assertEqual(states, [("enforced", "signer")])
        a.as_(OP, "unsuspend", {"identity": f"uid:{ME.subject}"})
        b.register()
        self.assertEqual([e["data"]["state"] for e in b.events() if e["type"] == "identity.suspension"],
                         ["enforced", "lifted"])
        self.assertEqual([e["data"]["state"] for e in a.events() if e["type"] == "identity.suspension"],
                         ["suspended", "lifted"])

    def test_a_suspended_operator_is_refused_and_only_break_glass_lifts_it(self):
        s = self.signer()
        s.as_(GLASS, "suspend", {"identity": f"uid:{OP.subject}"})
        self.refused(lambda: s.as_(OP, "response_pause", {}), why="is suspended")
        self.refused(lambda: s.as_(OP, "unsuspend", {"identity": f"uid:{OP.subject}"}), why="is suspended")
        s.as_(GLASS, "suspend", {"identity": f"uid:{GLASS.subject}"})
        s.as_(GLASS, "unsuspend", {"identity": f"uid:{GLASS.subject}"})   # break-glass is never locked out
        s.as_(GLASS, "unsuspend", {"identity": f"uid:{OP.subject}"})
        s.as_(OP, "incident_list", {})

    def test_an_entry_reaches_only_its_tenant(self):
        s = self.signer()
        s.s.tenants["uid:999999"] = "acme"
        s.s.authorize["uid:999999"] = sorted(svc.OPERATOR)
        acme_op = CallerIdentity("uid", "999999", True)
        s.as_(OP, "suspend", {"identity": "token:*"})
        s.s._check_suspended(CallerIdentity("token", "bob", True, {"tenant": "acme"}))
        self.refused(lambda: s.s._check_suspended(CallerIdentity("token", "carl", True)), why="is suspended")
        s.as_(acme_op, "suspend", {"identity": "oidc:dana"})
        self.refused(lambda: s.s._check_suspended(CallerIdentity("oidc", "dana", True, {"tenant": "acme"})),
                     why="is suspended")
        s.s._check_suspended(CallerIdentity("oidc", "dana", True))
        self.refused(lambda: s.as_(OP, "suspend", {"identity": "uid:999999"}),
                     why="is not an identity of tenant")

    def test_an_operator_changes_only_their_own_tenants_entries(self):
        s = self.signer()
        s.s.tenants["uid:999999"] = "acme"
        s.s.authorize["uid:999999"] = sorted(svc.OPERATOR)
        acme_op = CallerIdentity("uid", "999999", True)
        s.as_(OP, "suspend", {"identity": "token:*"})
        self.refused(lambda: s.as_(acme_op, "unsuspend", {"identity": "token:*"}), "invalid_request", "not suspended")
        s.as_(acme_op, "suspend", {"identity": "token:*"})   # acme's own entry, next to the default tenant's
        s.as_(acme_op, "unsuspend", {"identity": "token:*"})
        self.refused(lambda: s.s._check_suspended(CallerIdentity("token", "carl", True)), why="is suspended")
        s.s._check_suspended(CallerIdentity("token", "bob", True, {"tenant": "acme"}))

    def test_a_suspended_approver_can_not_answer(self):
        s = self.signer()
        run = s.register()
        s.decide(run, PAY, tcid="p")
        aid = s.call("approval_request", {**run, "tool_call_id": "p"})["approval_id"]
        s.as_(OP, "suspend", {"identity": f"uid:{OTHER.subject}"})
        self.refused(lambda: s.as_(OTHER, "approval_decide", {"approval_id": aid, "decision": "approve"}),
                     why="is suspended")

    def test_an_empty_entry_suspends(self):
        s = self.signer()
        with open(os.path.join(s.dir, "suspensions.json"), "w") as f:
            json.dump({"default": {f"uid:{ME.subject}": {}}}, f)
        self.refused(lambda: s.register(), why="is suspended")

    def test_an_unreadable_list_refuses(self):
        s = self.signer()
        with open(os.path.join(s.dir, "suspensions.json"), "w") as f:
            f.write("{not json")
        self.refused(lambda: s.register(), "unavailable", "unreadable")

    def test_notify_needs_a_webhook(self):
        pol = {**HOLD, "respond": [{"trigger": "Q", "mode": "enforce", "action": "notify"}]}
        with self.assertRaisesRegex(ValueError, "no webhook subscribes to incident events"):
            Signer(pol)


def bundle(s, run):
    s.call("close_run", run)
    s.s.sweep()
    s.s.checkpoint()
    path, trust = os.path.join(s.dir, "b.tkb"), os.path.join(s.dir, "trust.json")
    export(s.s.log.storage, "default", run["run_id"], s.s.log.storage.checkpoint_latest()[1], path,
           policy_dir=os.path.join(s.dir, "policies"))
    with open(trust, "w") as f:
        json.dump({"logs": [s.s.vkey], "algs": ["ed25519"]}, f)
    return path, trust


class TestVerifier(Case):
    def check(self, path, trust):
        rep, code = v2.verify(path, trust)
        line = next(c for c in rep.checks if c["check"] == "incidents")
        import test_ts_verifier as tv
        if not tv.SKIP:
            ts = tv.ts_verify(path, trust)
            self.assertEqual([(c["check"], c["status"]) for c in ts["checks"]], [(c["check"], c["status"])
                                                                                 for c in rep.checks])
            self.assertEqual([c for c in ts["checks"] if c["check"] == "incidents"], [line])
        return code, line

    def test_an_honest_hold_verifies_and_is_recomputed(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        aid = s.held_approval(run)
        s.as_(OP, "approval_decide", {"approval_id": aid, "decision": "approve"})
        s.call("approval_consume", {**run, "tool_call_id": "p", "tool": "pay", "args_source": "parsed", "args": PAY[1]})
        code, line = self.check(*bundle(s, run))
        self.assertEqual((code, line["status"]), (0, "pass"), line)
        self.assertTrue(line["detail"].startswith("1 incident(s): 1 checked against the bundle"))

    @pytest.mark.unverified_bundles
    def test_an_incident_the_records_dont_give_fails(self):
        s = self.signer()
        run = s.register()
        real = detect.Detector.observe

        def forged(self, tx, det, e):
            view_, out = real(self, tx, det, e)
            if e["type"] == "policy.decision" and e["data"]["tool"] == "read_file" and not out:
                out = [("incident.opened", {"incident_id": "inc-forged", "trigger": "sequence", "rule_ids": ["Q"],
                                            "scope": {"kind": "run", "id": e["run_id"]}, "mode": "shadow",
                                            "cites": [{"run_id": e["run_id"], "run_seq": e["run_seq"]}], "actions": [],
                                            "would": ["hold"]})]
            return view_, out
        with mock.patch.object(detect.Detector, "observe", forged):
            s.decide(run, e17.SECRET)
        code, line = self.check(*bundle(s, run))
        self.assertEqual((code, line["status"]), (1, "fail"))
        self.assertIn("does not follow from the run's records", line["problems"][0])

    @pytest.mark.unverified_bundles
    def test_a_missing_policy_is_signer_asserted_and_a_wrong_one_fails(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        path, trust = bundle(s, run)
        note = s.s.log.storage.checkpoint_latest()[1]
        export(s.s.log.storage, "default", run["run_id"], note, path)
        code, line = self.check(path, trust)
        self.assertEqual(line["status"], "pass", line)
        self.assertIn("0 checked against the bundle, 1 signer-asserted", line["detail"])
        rep, _ = v2.verify(path, trust)
        self.assertEqual([c["status"] for c in rep.checks if c["check"] == "incident policies"], ["warn"])
        pol = os.path.join(s.dir, "policies")
        for name in os.listdir(pol):
            with open(os.path.join(pol, name), "ab") as f:
                f.write(b" ")
        export(s.s.log.storage, "default", run["run_id"], note, path, policy_dir=pol)
        code, line = self.check(path, trust)   # bytes that don't hash to the name: no snapshot either check reads
        rep, _ = v2.verify(path, trust)
        self.assertEqual((code, [c["status"] for c in rep.checks if c["check"] == "policy snapshot"]), (1, ["fail"]))
        self.assertIn("0 checked against the bundle, 1 signer-asserted", line["detail"])

    def test_a_consume_under_a_later_hold_fails(self):
        ev = [("run.held", {"incident_id": "inc-1"}), ("approval.request", {"approval_id": "a", "incident_id": "inc-1"}),
              ("run.resumed", {"incident_id": "inc-1", "held_by": []}), ("run.held", {"incident_id": "inc-2"}),
              ("approval.consumed", {"approval_id": "a"})]
        problems = v2._honoured([{"type": t, "data": d, "seq": i} for i, (t, d) in enumerate(ev)], set())
        self.assertIn("an approval consumed while the run is held by incident inc-2", problems[0])

    def test_a_run_held_by_two_incidents_verifies(self):
        s = self.signer(TWO_HOLDS)
        run = s.register()
        first, _ = two_holds(s, run)
        s.as_(OP, "incident_resolve", {"incident_id": first})
        s.decide(run, e17.EGRESS)
        code, line = self.check(*bundle(s, run))
        self.assertEqual((code, line["status"]), (0, "pass"), line)

    @pytest.mark.unverified_bundles
    def test_an_enforced_hold_no_run_held_follows_fails(self):
        s = self.signer()
        run = s.register()
        with mock.patch.object(svc.SignerService, "_contain"):
            s.hold(run)
        s.decide(run, e17.EGRESS)
        code, line = self.check(*bundle(s, run))
        self.assertEqual((code, line["status"]), (1, "fail"))
        self.assertIn("enforces hold on this run, which no run.held or run.quarantined follows", line["problems"][0])

    @pytest.mark.unverified_bundles
    def test_an_enforced_incident_recorded_without_its_response_fails(self):
        for change, why in (({"action": None}, "records no response (hold) and no reason"),   # actions: []
                            ({"mode": "shadow"}, "does not follow from the run's records")):
            with self.subTest(change):
                s = self.signer()
                run = s.register()
                for r in s.s.log.detector.respond.values():   # a signer that answers otherwise than its policy says
                    r.update(change)
                s.hold(run)
                code, line = self.check(*bundle(s, run))
                self.assertEqual((code, line["status"]), (1, "fail"), line)
                self.assertIn(why, line["problems"][0])

    def test_a_held_call_asked_under_a_later_hold_verifies(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        s.decide(run, PAY, tcid="p")   # held under the first incident
        s.as_(OP, "run_resume", {"run_id": run["run_id"]})
        second = s.as_(OP, "run_hold", {"run_id": run["run_id"]})["incident_id"]
        aid = s.call("approval_request", {**run, "tool_call_id": "p"})["approval_id"]
        self.assertEqual([e["data"]["incident_id"] for e in s.events(run) if e["type"] == "approval.request"], [second])
        s.as_(OP, "approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertTrue(s.call("approval_consume", {**run, "tool_call_id": "p", "tool": "pay", "args_source": "parsed",
                                                    "args": PAY[1]})["ok"])
        code, line = self.check(*bundle(s, run))
        self.assertEqual((code, line["status"]), (0, "pass"), line)

    def test_a_cross_run_pointer_is_signer_asserted(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        s.call("close_run", run)
        again = s.register()
        code, line = self.check(*bundle(s, again))
        self.assertEqual((code, line["status"]), (0, "pass"))
        self.assertTrue(line["detail"].startswith("1 incident(s): 0 checked against the bundle, 1 signer-asserted"))


class TestView(Case):
    def test_check_passes_an_honest_run_with_an_incident(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        _, trust = bundle(s, run)
        rep, code, _, _ = view.check(s.s.log.storage, "default", run["run_id"], s.s.log.storage.checkpoint_latest()[1],
                                  trust, os.path.join(s.dir, "v.tkb"))
        self.assertEqual([c["status"] for c in rep.checks if c["check"] == "incidents"], ["pass"])
        self.assertEqual(rep.integrity, "VERIFIED")

    def test_review_lists_incidents_and_the_timeline_marks_them(self):
        s = self.signer()
        run = s.register()
        s.hold(run)
        recs = list(s.s.log.storage.iter_run("default", run["run_id"]))
        rv = view.review(recs, types.SimpleNamespace(integrity="VERIFIED", assurance="dev"), "verified")
        self.assertEqual([(i["trigger"], i["actions"], i["state"]) for i in rv["incidents"]],
                         [("sequence", ["hold"], "held")])
        tr = view.Translator({})
        marks = [x["title"] for r in recs for x in tr.feed(r) if r["event"]["type"] in ("incident.opened", "run.held")]
        self.assertTrue(marks[0].startswith("INCIDENT · sequence Q") and marks[1].startswith("RUN HELD"), marks)


class TestCli(unittest.TestCase):
    def run_cli(self, argv, answers):
        calls = []

        class Client:
            def __init__(self, url):
                self.url = url

            def call(self, method, req):
                calls.append((self.url, method, req))
                out = answers[self.url]
                if isinstance(out, Exception):
                    raise out
                return out

            def close(self):
                pass
        out = io.StringIO()
        with mock.patch("tracekit.sdk.client.Client", Client), contextlib.redirect_stdout(out):
            code = svc.main(["incidents", *argv])
        return code, calls, out.getvalue()

    def test_list_fans_out_and_resolve_stops_at_the_replica_that_knows(self):
        inc = {"incident_id": "inc-1", "state": "open", "trigger": "sequence", "rule_ids": ["Q"], "run_id": "tk-1.r",
               "mode": "enforce", "actions": ["hold"], "runs": [{"run_id": "tk-1.r", "state": "held"}]}
        code, calls, out = self.run_cli(["list", "--signer", "a", "--signer", "b"],
                                        {"a": {"incidents": []}, "b": {"incidents": [inc]}})
        self.assertEqual((code, [c[0] for c in calls]), (0, ["a", "b"]))
        self.assertIn("inc-1  open  sequence Q  run=tk-1.r  enforce hold  tk-1.r:held", out)
        code, calls, _ = self.run_cli(["resolve", "inc-1", "--reason", "ok", "--signer", "a", "--signer", "b"],
                                      {"a": RPCError("unknown_incident", "inc-1"), "b": {"incident_id": "inc-1",
                                                                                         "resumed": []}})
        self.assertEqual((code, calls[-1]), (0, ("b", "incident_resolve", {"incident_id": "inc-1", "reason": "ok"})))


if __name__ == "__main__":
    unittest.main()
