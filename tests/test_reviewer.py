"""The reference reviewer (tracekit/reviewer.py) against an in-process signer with agent approvers, with fake models
(always approve, garbage, refusal, timeout), a fake LLM gateway and `reviewer eval`; and what people see of agent
approvals: the signer's approval summaries, the Slack bridge, the viewer's approval desk and timeline."""
import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_agent_approvers as aa
import test_signer_service as ts
from tracekit import reviewer, slack_approvals, view
from tracekit.sdk.client import RunHandle, SignerUnavailable
from tracekit.signer.rpc_schema import REQUESTS, RESPONSES, RPCError, validate


class As:
    """An sdk Client stand-in: the in-process signer of `case`, called as `who`."""

    def __init__(self, case, who):
        self.case, self.who, self.seq = case, who, itertools.count()

    def call(self, method, req):
        props = REQUESTS[method]["properties"]
        req = {**({"request_id": aa.rid()} if "request_id" in props else {}),
               **({"stream": "s", "client_seq": next(self.seq)} if "client_seq" in props else {}), **req}
        return self.case.s.call(self.who, method, req)

    def run(self, agent):
        return RunHandle(self, self.call("register_run", {"agent": agent}))

    def __getattr__(self, method):
        return lambda req: self.call(method, req)


def message(decision="approve", reason="routine", **kw):
    """An Anthropic Messages response whose text is the reviewer's answer."""
    text = decision if reason is None else json.dumps({"decision": decision, "reason": reason})
    return {"type": "message", "role": "assistant", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}], **kw}


class Model:
    def __init__(self, *answers):
        self.answers, self.views = list(answers), []

    def __call__(self, tenant, view):
        self.views.append((tenant, view))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


class Case(aa.Case):
    def reviewer(self, model, agent=None):
        return reviewer.Reviewer([("acme", agent or As(self, aa.AGENT))], model, "m-test")

    def state(self, aid):
        return self.s.log.approvals[aid]


class TestReviewer(Case):
    def test_an_always_approve_model_approves_within_the_bounds_one_call_each(self):
        a1, _ = self.ask(tcid="tc-1")
        a2, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-2")
        model = Model(message())
        self.reviewer(model).poll()
        self.assertEqual([self.state(a)["state"] for a in (a1, a2)], ["approved", "approved"])
        self.assertEqual([v["approval_id"] for _, v in model.views], [a1, a2])   # one isolated call per approval
        self.assertTrue(all(self.run["run_id"] not in json.dumps(v) for _, v in model.views))
        [rec, _] = [e["data"] for e in self.events() if e["type"] == "approval"]
        self.assertEqual(rec["asserted"], {"model": "m-test", "version": reviewer.__version__,
                                           "prompt_hash": reviewer.PROMPT_HASH, "attested": False})

    def test_every_unusable_answer_escalates(self):
        for i, answer in enumerate((message("not json", None), message("maybe"), message(reason="x" * 501),
                                    message(stop_reason="refusal"), {"content": []}, TimeoutError("timed out"),
                                    OSError("gateway unreachable"))):
            with self.subTest(answer=str(answer)[:60]):
                aid, _ = self.ask(aa.OK | {"amount": 1 + i}, tcid=f"tc-{i}")
                with self.assertLogs("tracekit.reviewer", "WARNING") as logs:
                    self.reviewer(Model(answer)).poll()
                self.assertEqual((self.state(aid)["state"], self.state(aid)["escalated"]), ("requested", True))
                self.assertIn(aid, logs.output[0])
                self.assertIn("check the gateway URL, run token and model", logs.output[0])

    def test_a_transient_signer_error_is_tried_again_next_poll(self):
        class Busy(As):   # the signer answers `method` once with `code`
            def call(self, method, req):
                if self.fail and method == self.fail[0]:
                    code, self.fail = self.fail[1], None
                    raise RPCError(code, "try again")
                return super().call(method, req)
        for i, fail in enumerate((("approval_review", "unavailable"), ("approval_decide", "quota_exceeded"))):
            with self.subTest(fail=fail):
                aid, _ = self.ask(aa.OK | {"amount": 1 + i}, tcid=f"tc-{i}")
                agent = Busy(self, aa.AGENT)
                agent.fail = fail
                rv = self.reviewer(Model(message()), agent)
                rv.poll()
                self.assertEqual(self.state(aid)["state"], "requested")
                rv.poll()
                self.assertEqual(self.state(aid)["state"], "approved")

    def test_an_unreachable_replica_does_not_stop_the_others(self):
        class Down:
            def approval_list(self, req):
                raise SignerUnavailable("replica 0 is down")
        aid, _ = self.ask(aa.OK | {"amount": 3}, tcid="tc-down")
        rv = reviewer.Reviewer([("acme", Down()), ("acme", As(self, aa.AGENT))], Model(message()), "m-test")
        rv.seen.add("apr-answered-earlier")
        rv.poll()
        self.assertEqual(self.state(aid)["state"], "approved")
        self.assertIn("apr-answered-earlier", rv.seen)   # a partial listing forgets nothing

    def test_what_approval_review_calls_ineligible_is_never_approved(self):
        model = Model(message())
        aid, agent = self.ask(aa.OK | {"amount": 5000})   # outside the bounds: not listed for agents
        self.assertFalse(agent["eligible"])
        self.reviewer(model).poll()
        self.assertEqual((self.state(aid)["state"], model.views), ("requested", []))

        class Failing(As):   # a view with a condition that did not pass: escalated without asking the model
            def approval_review(self, req):
                v = self.call("approval_review", req)
                v["conditions"][0]["passed"] = False
                return v
        aid, _ = self.ask(tcid="tc-2")
        self.reviewer(model, Failing(self, aa.AGENT)).poll()
        self.assertEqual((self.state(aid)["escalated"], model.views), (True, []))

    def test_config(self):
        d = ts.tmpdir(self)
        path = os.path.join(d, "reviewer.yaml")

        def load(text):
            with open(path, "w") as f:
                f.write(text)
            return reviewer.load(path)
        cfg = load("signer: https://signer:8443\ngateway: https://gw:8080\n"
                   "tenants: {acme: {token_file: a.token, run_token_file: r.token}}\n")
        self.assertEqual((cfg["signer"], cfg["tenants"]["acme"]["token_file"]),
                         (["https://signer:8443"], os.path.join(d, "a.token")))
        for signer in ("/run/tracekit/signer.sock", "tcp://127.0.0.1:7000"):   # the uid and dev transports
            with self.subTest(signer), self.assertRaisesRegex(ValueError, "never a uid"):
                load(f"signer: {signer}\ngateway: https://gw\ntenants: {{acme: {{token_file: a, run_token_file: r}}}}\n")
        with self.assertRaisesRegex(ValueError, "tenants"):
            load("signer: https://s\ngateway: https://gw\n")
        tenants = "tenants: {acme: {token_file: a, run_token_file: r}}\n"
        for gateway in ("http://gw.internal:8080", "https://user@gw"):   # run tokens never go in the clear
            with self.subTest(gateway), self.assertRaisesRegex(ValueError, "gateway: URL must"):
                load(f"signer: https://s\ngateway: {gateway}\n{tenants}")
        self.assertEqual(load(f"signer: https://s\ngateway: http://127.0.0.1:8080\n{tenants}")["gateway"],
                         "http://127.0.0.1:8080")


class TestShadow(Case):
    agent = {"mode": "shadow"}

    def test_people_answer_it_and_the_reviewer_still_suggests(self):
        aid, _ = self.ask()
        [x] = self.s.call(aa.ALICE, "approval_list", {"for": "person"})["approvals"]
        self.assertEqual((x["approval_id"], "agent" in x), (aid, False))
        self.assertEqual([a["approval_id"] for a in self.s.call(aa.AGENT, "approval_list", {"for": "agent"})
                          ["approvals"]], [aid])

    def test_a_shadow_suggestion_is_sent_once(self):
        self.ask()
        rv = self.reviewer(Model(message()))
        rv.poll()
        rv.poll()
        self.assertEqual([e["type"] for e in self.events()].count("approval.suggested"), 1)


class Gateway(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, dict(self.headers), body))
        out = json.dumps(message("approve", "a routine fee")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class TestGateway(Case):
    def test_a_model_call_is_a_run_of_its_own_linked_to_the_approval(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        srv.seen = []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        token = os.path.join(ts.tmpdir(self), "runs.token")
        with open(token, "w") as f:
            f.write("run-identity-token\n")
        aid, _ = self.ask()
        ask = reviewer.Gateway(f"http://127.0.0.1:{srv.server_address[1]}", {"acme": (As(self, ts.ME), token)})
        self.reviewer(ask).poll()
        self.assertEqual(self.state(aid)["state"], "approved")
        [(path, headers, body)] = srv.seen
        self.assertEqual((path, headers["Authorization"], body["model"], body["system"]),
                         ("/v1/messages", "Bearer run-identity-token", reviewer.DEFAULT_MODEL, reviewer.PROMPT))
        self.assertEqual(body["output_config"]["format"]["schema"], reviewer.ANSWER)
        self.assertEqual(json.loads(body["messages"][0]["content"])["approval_id"], aid)
        run_id = headers["X-Tracekit-Run"].split(".")[0]
        mine = [e for e in self.events() if e["run_id"] == run_id]
        self.assertEqual(mine[0]["data"]["agent"]["name"], "tracekit-reviewer")
        [linked] = [e for e in mine if e["type"] == "input.observed"]
        self.assertEqual(linked["data"]["source"], "tracekit-reviewer:approval")
        self.assertIn("run.closing", [e["type"] for e in mine])


class TestEval(Case):
    def test_replays_what_people_decided_and_sends_nothing(self):
        a1, _ = self.ask(tcid="tc-1")
        a2, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-2")
        self.answer(aa.ALICE, a1, "approve")
        self.answer(aa.ALICE, a2, "reject")
        self.s.close()
        events = reviewer.records(store=self.dir)
        model = Model(message())
        self.assertEqual(reviewer.evaluate(events, model, {self.s.tenant}),
                         {"approvals": 2, "agree": 1, "false_approve": 1, "false_reject": 0, "escalate": 0})
        self.assertIsNone(model.views[0][1]["args"])   # the records hold no arguments
        self.assertEqual(reviewer.evaluate(events, model, {"another-tenant"})["approvals"], 0)   # opt-in
        self.assertEqual(reviewer.evaluate(events, Model(message("not json", None)), {self.s.tenant})["escalate"], 2)
        self.assertEqual([e["type"] for e in reviewer.records(store=self.dir)].count("approval"), 2)


class TestSummaries(Case):
    def test_people_see_who_answered_and_why_it_was_escalated(self):
        esc, _ = self.ask(tcid="tc-1")
        self.answer(aa.AGENT, esc, "escalate", reason="unusual payee")
        agent_view = self.s.call(aa.AGENT, "approval_list", {})["approvals"]
        self.assertFalse({"answered", "escalation"} & {k for a in agent_view for k in a})
        self.restart()   # rebuilt from the records
        [x] = self.s.call(aa.ALICE, "approval_list", {"escalated": True})["approvals"]
        self.assertEqual(x["escalation"], {"by": "agent", "reason": "unusual payee"})
        self.answer(aa.ALICE, esc)
        self.run = self.register()   # a run from before the restart has incomplete provenance: people answer it
        ok, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-2")
        self.answer(aa.AGENT, ok)
        page = self.s.call(aa.ALICE, "approval_list", {})
        self.assertEqual(validate(RESPONSES["approval_list"], page), [])
        self.assertEqual({a["approval_id"]: a["answered"] for a in page["approvals"]},
                         {esc: {"by": "uid:990001", "kind": "person"}, ok: {"by": "token:reviewer", "kind": "agent"}})


    def test_agent_marks_only_what_an_agent_answer_can_still_decide(self):
        a1, _ = self.ask(tcid="tc-1")
        a2, _ = self.ask(tcid="tc-2")   # the same arguments: people answer it once an agent rejects a1
        a3, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-3")

        def flags():
            return {a["approval_id"]: "agent" in a for a in self.s.call(aa.ALICE, "approval_list", {
                "state": "requested"})["approvals"]}

        def people():
            return [a["approval_id"] for a in self.s.call(aa.ALICE, "approval_list", {
                "state": "requested", "for": "person"})["approvals"]]
        self.assertEqual((flags(), people()), ({a1: True, a2: True, a3: True}, []))
        self.answer(aa.AGENT, a1, "reject")
        self.assertEqual((flags(), people()), ({a2: False, a3: True}, [a2]))
        self.agent = {"veto_s": 1}   # a policy change
        self.restart()
        self.assertEqual((flags(), people()), ({a2: False, a3: False}, [a2, a3]))
        self.assertEqual(self.s.call(aa.AGENT, "approval_list", {"for": "agent"})["approvals"], [])

    def test_switching_agents_off_escalates_what_they_could_answer(self):
        aid, _ = self.ask()
        self.s.call(aa.OPS, "approval_agents", {"request_id": aa.rid(), "enabled": False})
        self.s.call(aa.OPS, "approval_agents", {"request_id": aa.rid(), "enabled": True})   # it stays with people
        [x] = self.s.call(aa.ALICE, "approval_list", {"for": "person"})["approvals"]
        self.assertEqual((x["approval_id"], "agent" in x, x["escalation"]),
                         (aid, False, {"by": "signer", "reason": "agent approvals switched off"}))
        [esc] = [e["data"] for e in self.events() if e["type"] == "approval.escalated"]
        self.assertEqual(esc, {"approval_id": aid, "by": "signer", "reason": "agent approvals switched off"})


class FakeSigner:
    def __init__(self, approvals):
        self.approvals, self.calls = approvals, []

    def approval_list(self, req):
        return {"approvals": list(self.approvals.values()), "next_cursor": None}

    def approval_get(self, req):
        return {**self.approvals[req["approval_id"]], "args_source": "parsed", "args": {"amount": 5}}

    def call(self, method, req):
        self.calls.append((method, req))
        return {"approval_id": req["approval_id"], "state": "rejected"}


def summary(aid, **kw):
    return {"approval_id": aid, "state": "requested", "run_id": "r", "tool_call_id": "t", "attempt": 0, "tool": "pay",
            "rule_ids": ["PAY"], "policy_hash": "sha256:" + "0" * 64, "requester": "token:a",
            "expires_at": "2026-10-12T00:00:00Z", **kw}


class TestSlack(unittest.TestCase):
    def test_posts_what_people_answer_and_labels_model_output(self):
        signer = FakeSigner({a["approval_id"]: a for a in (
            summary("with-agent", agent=True), summary("person-only"),
            summary("escalated", escalated=True, escalation={"by": "agent", "reason": "odd payee"}))})
        bridge = slack_approvals.Bridge({"channel": "C0", "bot_token": "x", "signing_secret": b"s"}, signer)
        sent = []
        bridge.slack = lambda method, **f: sent.append((method, f)) or {"ok": True, "ts": str(len(sent))}
        bridge.poll()
        posted = {f["blocks"][1]["elements"][0]["text"]: f["blocks"][0]["text"]["text"] for m, f in sent
                  if m == "chat.postMessage"}
        self.assertEqual(set(posted), {"person-only", "escalated"})   # the agent-eligible one stays with the agent
        self.assertIn("\"odd payee\" (model output, over arguments the requesting agent supplied)", posted["escalated"])   # quoted: model text
        signer.approvals["person-only"].update(state="approved", answered={"by": "oidc:alice", "kind": "person"})
        bridge.poll()
        updates = [f["blocks"][-1]["elements"][0]["text"] for m, f in sent if m == "chat.update"]
        self.assertEqual(updates, ["approved by oidc:alice"])


class TestViewer(unittest.TestCase):
    def test_a_person_revokes_an_agent_approval_from_the_desk(self):
        signer = FakeSigner({})
        desk = view.ApprovalDesk(signer)
        person = {"subject": "corp/alice", "person": "alice"}
        code, out = desk.post({"person": person}, "/api/approvals/apr-1/revoke", {"reason": "not today"})
        self.assertEqual((code, out["state"]), (200, "rejected"))
        [(method, req)] = signer.calls
        self.assertEqual((method, req["approval_id"], req["on_behalf"], req["reason"]),
                         ("approval_revoke", "apr-1", person, "not today"))
        self.assertEqual(validate(REQUESTS["approval_revoke"], req), [])
        page = open(view.observe.APPROVALS_UI, encoding="utf-8").read()
        for needle in ('id="filter"', 'id="revoke"', "/revoke", "(model output)"):
            self.assertIn(needle, page)


class TestTimeline(Case):
    agent = {"mode": "shadow"}

    def test_agent_records_have_their_own_labels_and_shadow_agreement_per_rule(self):
        aid, _ = self.ask()
        self.answer(aa.AGENT, aid)   # shadow: a suggestion
        self.answer(aa.ALICE, aid)
        a2, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-2")
        self.answer(aa.AGENT, a2)
        self.answer(aa.ALICE, a2, "reject")
        tr = view.Translator()
        shown = [x for r in ts.records(self.dir) for x in tr.feed(r)]
        self.assertIn("AGENT SUGGESTED APPROVE · pay", [x.get("title") for x in shown])
        texts = [x.get("text", "") for x in shown if x.get("title", "").startswith(("APPROVED", "REJECTED"))]
        self.assertIn("shadow agent agreed · agreement PAY 1/1", texts[0])
        self.assertIn("shadow agent disagreed · agreement PAY 1/2", texts[1])


class TestAgentLabels(Case):
    def test_an_agent_approval_and_its_revocation(self):
        aid, _ = self.ask()
        self.answer(aa.AGENT, aid, asserted={"model": "m-1"})
        self.s.call(aa.ALICE, "approval_revoke", {"request_id": aa.rid(), "approval_id": aid})
        esc, _ = self.ask(aa.OK | {"amount": 41}, tcid="tc-2")
        self.answer(aa.AGENT, esc, "escalate", reason="odd payee")
        tr = view.Translator()
        shown = {x.get("title"): x.get("text") for r in ts.records(self.dir) for x in tr.feed(r)}
        self.assertIn("by agent token:reviewer (attested) (model output, m-1)", shown["AGENT APPROVED · pay"])
        self.assertIn("AGENT APPROVAL REVOKED · pay", shown)
        self.assertIn("(model output, over arguments the requesting agent supplied) · “odd payee”",
                      shown["ESCALATED TO PEOPLE · pay"])

    @unittest.skipUnless(shutil.which("node"), "needs node to run the viewer's lastAnswer()")
    def test_the_viewer_shows_a_revoked_agent_approval_as_revoked(self):
        aid, _ = self.ask()
        self.answer(aa.AGENT, aid)
        self.s.call(aa.ALICE, "approval_revoke", {"request_id": aa.rid(), "approval_id": aid})
        tr = view.Translator()
        call = {"approvals": [x for r in ts.records(self.dir) for x in tr.feed(r)
                              if (x.get("v2") or {}).get("approval") and x["v2"]["tool_use_id"] == "tc-1"]}
        with open(view.observe.UI, encoding="utf-8") as f:
            page = f.read()
        # lastAnswer reads the ANSWER map of answer kinds, defined just before it
        helper = (re.search(r"^\s*(const ANSWER = \{.*?\};)$", page, re.M | re.S).group(1) + "\n"
                  + re.search(r"^\s*(const lastAnswer = .*;)$", page, re.M).group(1))
        out = subprocess.run(["node", "-e", f"{helper} process.stdout.write(String(lastAnswer({json.dumps(call)})))"],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out, "revoked")


if __name__ == "__main__":
    unittest.main()
