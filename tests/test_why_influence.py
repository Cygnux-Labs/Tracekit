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
from tracekit.policy2 import compile as compile_policy  # noqa: E402
from tracekit.why import build_graph, load_run  # noqa: E402
from tracekit.why.analysis import alerts, analyse, workspace  # noqa: E402
from tracekit.why.core import Runtime  # noqa: E402
from tracekit.why.import_v2 import convert  # noqa: E402
from tracekit.why.influence import call_influence, chain, graded, influences, untrusted  # noqa: E402
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
        g = build_graph(run)
        got = graded(g, call)
        self.assertEqual([(e["label"], e["effect"]) for e in got["edges"] if e["grade"] == "measured"],
                         [("github:issue-12", 0.7)])
        self.assertEqual([g.nodes[x]["label"] for x in got["ruled"]], ["repo:README.md"])

    def test_text_overlap_is_a_hint_never_an_edge_and_never_in_the_words(self):
        run, call, _ = desk()
        inf = call_influence(run, build_graph(run), call)
        self.assertNotIn("hint", {e["grade"] for e in inf["edges"]})
        self.assertEqual([(h["label"], h["value"]) for h in inf["hints"]], [("github:issue-12", "hotfix-from-issue-12")])
        self.assertEqual((inf["untrusted"], inf["serves"]), (None, "task"))
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


def without_task(run, verdict, effect, target="tool=git_push"):
    """A replay test of the run without its task (the `ref:` of the task's content)."""
    task = next(e for e in run.events if e.get("kind") == "task")
    run.add_test({"intervention": "ref:" + task["ref"][7:19], "target": target, "effect": effect,
                  "ci": [effect - 0.1, effect + 0.1], "verdict": verdict, "n": 40})


class Serves(unittest.TestCase):
    def test_an_argument_set_by_untrusted_content_is_named_never_called_drift_on_its_own(self):
        """E28: 31 of 97 clean AgentDojo runs had a call whose argument came only from what the agent read, because
        their tasks asked for it ("pay the bill in bill.txt"); that alone says nothing about the task."""
        run, call, _ = desk(EXACT)
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["untrusted"]["grade"], inf["step"]),
                         ("task", "exact", "dev decided (m; 3 in context, 1 untrusted)"))
        self.assertEqual(inf["words"], "git_push (dev) came from: read github:issue-12 (untrusted; exact: `branch`) → dev "
                                       "decided (m; 3 in context, 1 untrusted) → this call. Its `branch` came only from "
                                       "github:issue-12 (untrusted; exact): test it without the task to see whether it "
                                       "serves the task.")

    def test_a_call_a_replay_without_the_task_kept_serves_no_step_of_the_task(self):
        run, call, _ = desk(EXACT)
        without_task(run, "ruled-out", 0.0)
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["step"]), ("drift", None))
        self.assertEqual(inf["words"], "git_push (dev) serves no step of the task: a replay without the task kept it. "
                                       "Chain: read github:issue-12 (untrusted; exact: `branch`) → dev decided (m; 3 in "
                                       "context, 1 untrusted) → this call.")

    def test_a_call_a_replay_without_the_task_changed_serves_it(self):
        run, call, _ = desk(decide=False)   # no chain recorded: the replay alone says it needs the task
        without_task(run, "causal", 0.9)
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual(inf["serves"], "task")
        self.assertEqual([(e["grade"], e["label"]) for e in inf["edges"]], [("measured", "task")])

    def test_a_test_without_one_of_several_prompts_proves_nothing(self):
        """With no task input the goal is every prompt the person typed: one removed, the others may still ask for it."""
        rt = Runtime({"m": lambda ctx, **k: "x"}, {"git_push": lambda **a: "ok"}, signer=False)
        a = rt.agent("dev")
        asks = [a.observe(t, source="dev:UserPromptSubmit", trust="trusted") for t in ("fix the bug", "then push it")]
        a.act("git_push", {"branch": "fix"}, decision=a.decide(asks, model="m"))
        run = rt.finish()
        run.add_test({"intervention": "ref:" + asks[0].ref[7:19], "target": "tool=git_push", "effect": 0.0,
                      "ci": [-0.1, 0.1], "verdict": "ruled-out", "n": 40})
        call = "ev:" + run.of_type("action")[0]["id"]
        self.assertEqual(call_influence(run, build_graph(run), call)["serves"], "task")
        run.add_test({"intervention": "ref:" + asks[1].ref[7:19], "target": "tool=git_push", "effect": 0.0,
                      "ci": [-0.1, 0.1], "verdict": "ruled-out", "n": 40})
        self.assertEqual(call_influence(run, build_graph(run), call)["serves"], "drift")

    def test_a_call_whose_chain_is_clean_serves_the_task_even_after_untrusted_reads(self):
        run, call, _ = desk(args={"branch": "fix-login"})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["untrusted"]), ("task", None))
        self.assertEqual([s["text"] for s in inf["chain"]], ["the task", "dev decided (m; 3 in context, 1 untrusted)",
                                                              "this call"])
        self.assertTrue(inf["words"].startswith(f"git_push (dev) came from: task '{TASK}' → dev decided"))

    def test_a_replay_that_untrusted_content_caused_the_call_is_named(self):
        run, call, _ = desk(args={"branch": "fix-login"})
        run.add_test({"intervention": "input:github:issue-12", "target": "tool=git_push", "effect": 0.7,
                      "ci": [0.5, 0.85], "verdict": "causal", "n": 40})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["untrusted"]["grade"]), ("task", "measured"))
        self.assertIn("A replay without github:issue-12 (untrusted) changed it (measured: effect +0.70): test it without "
                      "the task", inf["words"])

    def test_a_call_no_model_call_asked_for_has_no_influence_found(self):
        run, call, _ = desk(decide=False, args={"branch": "fix-login"})
        inf = call_influence(run, build_graph(run), call)
        self.assertEqual((inf["serves"], inf["edges"]), ("unknown", []))
        self.assertEqual(inf["words"], "git_push (dev): no influence found. Nothing exact, measured or seen links it to "
                                       "what the agents read.")

    def test_a_value_from_another_agents_message_is_exact_but_not_named_untrusted(self):
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
        self.assertEqual((inf["serves"], inf["untrusted"], [e["grade"] for e in inf["edges"] if e["grade"] == "exact"]),
                         ("task", None, ["exact"]))
        self.assertEqual([s["text"] for s in inf["chain"]], [
            "the task", "planner decided (m; 1 in context)", "message planner → executor",
            "executor decided (m; 1 in context)", "this call"])

    def test_untrusted_reads_exact_from_outside_content_and_measured_from_untrusted_only(self):
        e = {"type": "input", "trust": "untrusted"}
        self.assertTrue(untrusted([{**e, "grade": "exact"}]))
        self.assertTrue(untrusted([{**e, "grade": "exact", "type": "action"}]))
        self.assertFalse(untrusted([{**e, "grade": "exact", "type": "message"}]))
        self.assertTrue(untrusted([{**e, "grade": "measured"}]))
        self.assertFalse(untrusted([{**e, "grade": "measured", "trust": "trusted"}]))
        self.assertFalse(untrusted([{**e, "grade": "seen"}, {**e, "grade": "hint"}]))

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
    def test_an_untrusted_argument_and_drift_are_review_alerts_unless_the_call_already_has_a_high_one(self):
        run, call, _ = desk(EXACT)
        mine = lambda: [(a["severity"], a["title"]) for a in alerts(run, build_graph(run, infer=False))  # noqa: E731
                        if a.get("node") == call]
        self.assertEqual(mine(), [("review", "git_push's `branch` came only from untrusted content")])
        without_task(run, "ruled-out", 0.0)
        self.assertEqual(mine(), [("review", "git_push serves no step of the task")])
        run.of_type("action")[-1]["status"] = "blocked"
        self.assertEqual([s for s, _ in mine()], ["high"])


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_influence_answers_for_risky_calls_drift_first(self):
        clean, _, _ = desk(args={"branch": "fix-login"}, tool="deploy_site")
        stopped, _, _ = desk(args={"branch": "fix-login"})
        stopped.of_type("action")[-1]["policy"] = {"decision": "deny"}
        named, _, _ = desk(EXACT)
        drifted, _, _ = desk(args={"branch": "fix-login"})
        without_task(drifted, "ruled-out", 0.0)
        items = [{"run": r, "graph": build_graph(r, infer=False)} for r in (clean, stopped, named, drifted)]
        got = workspace([], [{**i, "summary": {"started": ""}} for i in items])["influence"]
        self.assertEqual([(c["run"], c["serves"], c["ended"], bool(c["untrusted"])) for c in got["calls"]], [
            (drifted.run_id, "drift", None, False), (named.run_id, "task", None, True),
            (stopped.run_id, "task", "blocked", False)])
        self.assertEqual(got["calls_total"], 3)
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

    def records(self, source, policy_hash="sha256:unknown"):
        ex = {"exchange_id": "x1", "streamed": False, "model": "m"}

        def v2rec(*a, **k):
            return factories.v2rec(*a, log_id="L", tenant="t", **k)
        return [
            v2rec(0, "run.registered", {"agent": {"name": "a"}, "identity": {}}),
            v2rec(1, "input.observed", {"source": "task", "trust": "trusted", "output": {"hash": "sha256:t"}}),
            v2rec(2, "policy.decision", {"tool_use_id": "c1", "tool": "web_fetch", "decision": "allow",
                                         "rule_ids": [], "policy_hash": policy_hash}),
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

    def test_a_results_trust_is_the_policys_the_call_was_decided_under(self):
        """A result the policy doesn't list as untrusted is trusted context; one of a policy the importer doesn't have is
        untrusted, so nothing unknown reads as trusted."""
        trust = {}
        for name, listed in (("listed", "untrusted: [web_fetch]\n"), ("unlisted", "")):
            path = os.path.join(self.tmp, name + ".yaml")
            with open(path, "w") as f:
                f.write(f"version: t-{name}\ndescription: test\n{listed}")
            pol, errors = compile_policy.build(path)
            self.assertEqual(errors, [])

            class Reasons(dict):
                policies = {"sha256:" + name: pol}
            run = load_run(convert(self.records("gateway", "sha256:" + name), os.path.join(self.tmp, name), Reasons()))
            trust[name] = run.of_type("decision")[0]["context"][-1]["trust"]
        self.assertEqual(trust, {"listed": "untrusted", "unlisted": "trusted"})

    def test_an_agents_own_report_of_what_it_sent_adds_nothing(self):
        run = load_run(convert(self.records("sdk"), self.tmp, {}))
        [dec] = run.of_type("decision")
        self.assertEqual([c["source"] for c in dec["context"]], ["task"])


if __name__ == "__main__":
    unittest.main()
