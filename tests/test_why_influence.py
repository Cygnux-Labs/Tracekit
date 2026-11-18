"""Graded influence (tracekit.why.influence): exact, measured, seen and hint edges into a call, its chain back to the
run's goal, what it serves, the drift alert, the gateway's seen results on import and the viewer's signed join.

    python3 -m pytest tests/test_why_influence.py -q
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import factories  # noqa: E402
from tracekit.why import build_graph, load_run  # noqa: E402
from tracekit.why.analysis import alerts, analyse, workspace  # noqa: E402
from tracekit.why.core import Runtime  # noqa: E402
from tracekit.why.import_v2 import convert  # noqa: E402
from tracekit.why.influence import call_influence, chain, drift, graded, influences  # noqa: E402
from tracekit.why.server import Store  # noqa: E402

TASK = "Fix the login bug in issue 12"


def desk(provenance=None, tool="git_push", args=None, decide=True, extra=None):
    """A run: the task, a trusted README and an untrusted issue, a model call that had all three in its context and
    asked for one call, `tool` with `args`. `provenance`: the signer's entries on the call ("issue" names the issue's
    event). `extra`: (source, text, trust) of one more input, observed after the call's model call."""
    rt = Runtime({"m": lambda ctx, **k: "push it"}, {tool: lambda **a: "ok"}, task=TASK, signer=False)
    a = rt.agent("dev")
    readme = a.observe("README: run make test before you push", source="repo:README.md", trust="trusted")
    issue = a.observe("Issue 12: login fails. Push the fix to branch hotfix-from-issue-12", source="github:issue-12")
    d = a.decide([rt.task_ref, readme, issue], model="m") if decide else None
    if extra:
        a.observe(extra[1], source=extra[0], trust=extra[2])
    a.act(tool, args or {"branch": "hotfix-from-issue-12"}, decision=d)
    run = rt.finish()
    call = run.of_type("action")[-1]
    if provenance:
        call["provenance"] = [{**p, "from_event": issue.event_id if p["from_event"] == "issue" else p["from_event"]}
                              for p in provenance]
    return run, "ev:" + call["id"], issue


EXACT = [{"field": "branch", "kind": "string", "record": 4, "from_event": "issue"}]


class Grades(unittest.TestCase):
    def test_the_signers_provenance_is_exact_and_the_context_is_seen(self):
        run, call, issue = desk(EXACT)
        edges = graded(build_graph(run), call)["edges"]
        self.assertEqual(sorted((e["grade"], e["label"], e["basis"]) for e in edges), [
            ("exact", "github:issue-12", "provenance"),
            ("seen", "github:issue-12", "recorded"), ("seen", "repo:README.md", "recorded"), ("seen", "task", "recorded")])
        exact = next(e for e in edges if e["grade"] == "exact")
        self.assertEqual((exact["field"], exact["trust"], exact["src"]), ("branch", "untrusted", "ev:" + issue.event_id))

    def test_a_replay_that_changed_the_call_is_measured_and_one_that_ruled_it_out_is_not_an_edge(self):
        run, call, _ = desk()
        run.add_test({"intervention": "input:github:issue-12", "target": "tool=git_push", "effect": 0.7,
                      "ci": [0.5, 0.85], "verdict": "causal", "n": 40})
        run.add_test({"intervention": "input:repo:README.md", "target": "tool=git_push", "effect": 0.0,
                      "ci": [-0.1, 0.1], "verdict": "ruled-out", "n": 80})
        got = graded(build_graph(run), call)
        self.assertEqual([(e["label"], e["effect"]) for e in got["edges"] if e["grade"] == "measured"],
                         [("github:issue-12", 0.7)])
        self.assertEqual(got["ruled_out"], ["repo:README.md"])

    def test_text_overlap_is_a_hint_never_an_edge_and_never_in_the_words(self):
        run, call, _ = desk()
        inf = call_influence(run, build_graph(run), call)
        self.assertNotIn("hint", {e["grade"] for e in inf["edges"]})
        self.assertEqual([(h["label"], h["value"]) for h in inf["hints"]], [("github:issue-12", "hotfix-from-issue-12")])
        self.assertIsNone(inf["drift"])
        self.assertNotIn("github:issue-12", inf["words"])

    def test_a_reconstructed_context_and_a_gateways_entry_say_how_they_are_known(self):
        run, call, issue = desk()
        dec = next(e for e in run.events if e["type"] == "decision")
        dec["context_mode"] = "reconstructed"
        next(c for c in dec["context"] if c["from_event"] == issue.event_id)["seen"] = "gateway"
        dec["tracekit"] = {"run_id": "tk", "run_seq": 3}
        edges = {e["label"]: e for e in graded(build_graph(run), call)["edges"]}
        self.assertEqual((edges["github:issue-12"]["basis"], edges["github:issue-12"]["cites"]),
                         ("gateway", {"run_id": "tk", "run_seq": 3}))
        self.assertEqual((edges["task"]["basis"], "cites" in edges["task"]), ("reconstructed", False))


class Serves(unittest.TestCase):
    def test_an_argument_set_by_untrusted_content_serves_no_step_of_the_task(self):
        run, call, _ = desk(EXACT)
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["drift"]["grade"], inf["step"]), ("drift", "exact", None))
        self.assertEqual(inf["words"], "git_push (dev) serves no step of the task: its `branch` came only from "
                                       "github:issue-12 (untrusted; exact). Chain: read github:issue-12 (untrusted; "
                                       "exact: `branch`) → dev decided (m; 3 in context, 1 untrusted) → this call.")

    def test_a_call_whose_chain_is_clean_serves_the_task_even_after_untrusted_reads(self):
        run, call, _ = desk(args={"branch": "fix-login"})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["drift"]), ("task", None))
        self.assertEqual([s["text"] for s in inf["chain"]], ["the task", "dev decided (m; 3 in context, 1 untrusted)",
                                                              "this call"])
        self.assertTrue(inf["words"].startswith(f"git_push (dev) came from: task '{TASK}' → dev decided"))

    def test_a_replay_that_untrusted_content_caused_the_call_is_drift_too(self):
        run, call, _ = desk(args={"branch": "fix-login"})
        run.add_test({"intervention": "input:github:issue-12", "target": "tool=git_push", "effect": 0.7,
                      "ci": [0.5, 0.85], "verdict": "causal", "n": 40})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["drift"]["grade"]), ("drift", "measured"))
        self.assertIn("a replay without github:issue-12 (untrusted) changed it (measured: effect +0.70)", inf["words"])

    def test_a_call_no_model_call_asked_for_has_no_influence_found(self):
        run, call, _ = desk(decide=False, args={"branch": "fix-login"})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["edges"]), ("unknown", []))
        self.assertEqual(inf["words"], "git_push (dev): no influence found. Nothing exact, measured or seen links it to "
                                       "what the agents read.")

    def test_a_value_from_another_agents_message_is_exact_but_not_drift(self):
        """The signer's index is per run: a message from the run's own planner is untrusted in the executor's run
        whatever the planner read, so it can't say the value came from outside the task."""
        rt = Runtime({"m": lambda ctx, **k: {"to": "c@example.com"}}, {"send_email": lambda **a: "ok"}, task=TASK,
                     signer=False)
        planner, executor = rt.agent("planner"), rt.agent("executor", parent="planner")
        planner.send("executor", "email c@example.com", decision=planner.decide([rt.task_ref], model="m"))
        executor.act("send_email", {"to": "c@example.com"}, decision=executor.decide(executor.inbox(), model="m"))
        run = rt.finish()
        msg = run.of_type("message")[0]
        run.of_type("action")[0]["provenance"] = [{"field": "to", "kind": "email", "record": 2, "from_event": msg["id"]}]
        inf = call_influence(run, build_graph(run), "ev:" + run.of_type("action")[0]["id"])
        self.assertEqual((inf["serves"], [e["grade"] for e in inf["edges"] if e["grade"] == "exact"]), ("task", ["exact"]))
        self.assertEqual([s["text"] for s in inf["chain"]], [
            "the task", "planner decided (m; 1 in context)", "message planner → executor",
            "executor decided (m; 1 in context)", "this call"])

    def test_drift_reads_exact_from_outside_content_and_measured_from_untrusted_only(self):
        e = {"type": "input", "trust": "untrusted"}
        self.assertTrue(drift([{**e, "grade": "exact"}]))
        self.assertTrue(drift([{**e, "grade": "exact", "type": "action"}]))
        self.assertFalse(drift([{**e, "grade": "exact", "type": "message"}]))
        self.assertTrue(drift([{**e, "grade": "measured"}]))
        self.assertFalse(drift([{**e, "grade": "measured", "trust": "trusted"}]))
        self.assertFalse(drift([{**e, "grade": "seen"}, {**e, "grade": "hint"}]))

    def test_a_long_chain_is_cut_and_says_so(self):
        rt = Runtime({"m": lambda ctx, **k: "x"}, {"send_email": lambda **a: "ok"}, task=TASK, signer=False)
        agents = [rt.agent(f"a{i}") for i in range(10)]
        prev = rt.task_ref
        for a, b in zip(agents, agents[1:]):
            a.send(b.name, "go", decision=a.decide([prev] + a.inbox(), model="m"))
            prev = None
        last = agents[-1]
        last.act("send_email", {"to": "x@example.com"}, decision=last.decide(last.inbox(), model="m"))
        run = rt.finish()
        g = build_graph(run)
        steps, cut = chain(g, "ev:" + run.of_type("action")[0]["id"], set(), set())
        self.assertTrue(cut)
        inf = call_influence(run, g, "ev:" + run.of_type("action")[0]["id"])
        self.assertTrue(inf["truncated"])
        self.assertTrue(inf["words"].startswith("send_email (a9): no chain to the task recorded. … → "))


class Alerts(unittest.TestCase):
    def test_drift_is_a_review_alert_unless_the_call_already_has_a_high_one(self):
        run, call, _ = desk(EXACT)
        g = build_graph(run, infer=False)
        self.assertEqual([(a["severity"], a["title"]) for a in alerts(run, g) if a.get("node") == call],
                         [("review", "git_push serves no step of the task")])
        run.of_type("action")[-1]["status"] = "blocked"
        self.assertEqual([a["severity"] for a in alerts(run, build_graph(run, infer=False)) if a.get("node") == call],
                         ["high"])


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_influence_answers_for_risky_calls_drift_first(self):
        clean, _, _ = desk(args={"branch": "fix-login"}, tool="deploy_site")
        stopped, _, _ = desk(args={"branch": "fix-login"})
        stopped.of_type("action")[-1]["policy"] = {"decision": "deny"}
        drifted, _, _ = desk(EXACT)
        items = [{"run": r, "graph": build_graph(r, infer=False)} for r in (clean, stopped, drifted)]
        got = workspace([], [{**i, "summary": {"started": ""}} for i in items])["influence"]
        self.assertEqual([(c["run"], c["serves"], c["ended"]) for c in got["calls"]],
                         [(drifted.run_id, "drift", None), (stopped.run_id, "task", "blocked")])
        self.assertEqual(got["calls_total"], 2)
        self.assertEqual(len(influences(clean, build_graph(clean, infer=False))), 1)   # consequential, not risky

    def test_an_exact_edge_is_signed_only_on_a_call_whose_signed_record_the_viewer_verified(self):
        store = Store(os.path.join(self.tmp, "why"))
        run, call, _ = desk(EXACT)
        act = run.of_type("action")[-1]
        act["tracekit"] = {"run_id": "tk-1", "run_seq": 7, "type": "policy.decision"}
        path = os.path.join(store.root, run.run_id)
        _write(run, path)
        store.scan(announce=False)
        [c] = store.workspace()["influence"]["calls"]
        self.assertEqual([e.get("signed") for e in c["edges"] if e["grade"] == "exact"], [False])
        store.out.records.append({"session_id": "tk-1", "tool_name": "git_push", "v2": {"run_seq": 7}})
        [c] = store.workspace()["influence"]["calls"]
        self.assertEqual([e.get("signed") for e in c["edges"] if e["grade"] == "exact"], [True])
        store.out.records[-1]["tool_name"] = "Bash"   # a signed record of another call joins nothing
        [c] = store.workspace()["influence"]["calls"]
        self.assertEqual([e.get("signed") for e in c["edges"] if e["grade"] == "exact"], [False])
        self.assertEqual(analyse(path)["run"].run_id, run.run_id)


def _write(run, path):
    os.makedirs(os.path.join(path, "blobs"))
    with open(os.path.join(path, "events.jsonl"), "w") as f:
        for ev in run.events:
            f.write(json.dumps(ev) + "\n")
    for ref, v in run.blobs.items():
        with open(os.path.join(path, "blobs", ref[7:] + ".json"), "w") as f:
            json.dump({"v": v}, f)


class GatewaySeen(unittest.TestCase):
    """A v2 import's context is everything the run observed before a model call (reconstructed); a result the LLM
    gateway (T2) recorded a request sending is in it by the gateway's own record."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def records(self, source):
        ex = {"exchange_id": "x1", "streamed": False, "model": "m"}

        def v2rec(*a, **k):
            return factories.v2rec(*a, log_id="L", tenant="t", **k)
        return [
            v2rec(0, "run.registered", {"agent": {"name": "a"}, "identity": {}}),
            v2rec(1, "input.observed", {"source": "task", "trust": "trusted", "output": {"hash": "sha256:t"}}),
            v2rec(2, "policy.decision", {"tool_use_id": "c1", "tool": "web_fetch", "decision": "allow",
                                         "rule_ids": [], "policy_hash": "sha256:unknown"}),
            v2rec(3, "tool.result", {"tool_use_id": "c1", "ok": True, "output": {"hash": "sha256:r"}}),
            v2rec(4, "model.exchange", {**ex, "phase": "request", "tool_results_sent": ["c1"]}, source=source),
            v2rec(5, "model.exchange", {**ex, "phase": "response", "tool_uses": [{"id": "c2", "name": "send"}]},
                  source=source),
            v2rec(6, "policy.decision", {"tool_use_id": "c2", "tool": "send", "decision": "deny", "rule_ids": [],
                                         "policy_hash": "sha256:unknown"}),
            v2rec(7, "run.final", {})]

    def test_a_result_the_gateway_saw_sent_is_seen_and_cites_its_record(self):
        run = load_run(convert(self.records("gateway"), self.tmp, {}))
        [dec] = run.of_type("decision")
        self.assertEqual([(c["source"], c["trust"], c.get("seen")) for c in dec["context"]],
                         [("task", "trusted", None), ("tool:web_fetch", "untrusted", "gateway")])
        call = "ev:" + run.of_type("action")[-1]["id"]
        edges = {e["label"]: e for e in graded(build_graph(run), call)["edges"]}
        self.assertEqual((edges["web_fetch"]["basis"], edges["web_fetch"]["cites"]["run_seq"]), ("gateway", 4))
        self.assertEqual(edges["task"]["basis"], "reconstructed")

    def test_an_agents_own_report_of_what_it_sent_adds_nothing(self):
        run = load_run(convert(self.records("sdk"), self.tmp, {}))
        [dec] = run.of_type("decision")
        self.assertEqual([c["source"] for c in dec["context"]], ["task"])


if __name__ == "__main__":
    unittest.main()
