"""Stated constraints (#309): the grammar that reads them (tracekit/constraints.py) and live constraints, which the
signer applies to the rest of a run after its policy (constraint_add, TK-CONSTRAINT): a call that breaks one is held for
a person's approval and no decision is ever lowered; both verifiers check where each such hold sits
(docs/policy-v2.md#live-constraints). tests/test_ts_verifier.py runs a run with live constraints through both."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_bundle_v2 as b
from factories import unverified_bundles
from test_reviews import ME, Signed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.e20_alignment import TUNED, fill  # noqa: E402
from tracekit import agent_hooks, constraints  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.integrations import claude_code  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import RPCError  # noqa: E402
from tracekit.verify import v2  # noqa: E402

TARGET, TASK, ASKED = "config/settings.yaml", "src/pager.py", "Fix the off-by-one error in src/pager.py. "


class Grammar(unittest.TestCase):
    def test_what_each_kind_reads(self):
        for text, want in (
                ("Fix src/pager.py. Leave billing.py untouched.", [("keep_away", "billing.py")]),
                ("Don't modify config/Settings.YAML.", [("keep_away", "settings.yaml")]),
                ("Do not touch src/auth/session.ts, it is frozen.", [("keep_away", "session.ts")]),
                ("Fix pager.py but leave billing.py alone.", [("keep_away", "billing.py")]),
                ("billing.py must stay unchanged.", [("keep_away", "billing.py")]),
                ("Make sure .env is read-only.", [("keep_away", ".env")]),
                ("Don't touch a.py or b.py.", [("keep_away", "a.py"), ("keep_away", "b.py")]),
                ("Only change src/pager.py.", [("only_change", "pager.py")]),
                ("Read only: just tell me what you'd change.", [("read_only", None)]),
                ("Please don't change anything.", [("read_only", None)]),
                ("Don't push.", [("no_push", None)]),
                ("No network access, please.", [("no_network", None)]),
                ("Work offline.", [("no_network", None)]),
                ("Don't change anything except foo.py", [("only_change", "foo.py")]),
                ("Don't touch anything other than src/foo.py.", [("only_change", "foo.py")]),
                ("Do not modify anything, except foo.py and bar.py.", [("only_change", "foo.py"),
                                                                      ("only_change", "bar.py")]),
                ("Don't change anything but foo.py.", [("only_change", "foo.py")]),
                ("Read-only except docs/notes.md.", [("only_change", "notes.md")]),
                ("Fix foo.py. Don't change anything else.", [("only_change", "foo.py")]),
                ("Don't touch billing.py. Fix foo.py and don't change anything else.",
                 [("keep_away", "billing.py"), ("only_change", "foo.py")]),
                ("I don't want anything changed.", [("read_only", None)]),
                ("Don't change anything, but do run the tests.", [("read_only", None)]),
                ("Don't commit or push.", [("no_push", None)]),
                ("Don't go online.", [("no_network", None)]),
                ("Don't use the internet.", [("no_network", None)]),
                ("Don't search the web.", [("no_network", None)]),
                ("No internet during this task.", [("no_network", None)]),
                ("Please stay offline while you work.", [("no_network", None)])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)

    def test_no_constraint_where_none_is_stated(self):
        for text in ("Updating billing.py to match the fix.", "A small consistency change in billing.py.",
                     "I'll leave the tests unchanged and fix billing.py.", "Please also update billing.py.",
                     "Push the branch when you are done.", "Fix the network timeout in net.py.", "", None, 7,
                     # everyday phrasings that state no constraint (#309 review): each would hold a wanted call
                     "Make the CLI work offline.", "Add an offline mode to the app.",
                     "We need the app to work offline.", "Don't forget to update README.md.",
                     "Don't forget to push when you're done.", "Don't hesitate to change config.py.",
                     "You don't need to touch test_a.py.", "Don't break the network code in net.py.",
                     "Don't modify the web UI.", "Don't change the network timeout.", "No web UI changes.",
                     "Don't change anything except the docs.", "Run the tests; don't change anything else.",
                     "Don't forget to change anything that references it."):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), [])
        self.assertEqual(constraints.extract("Fix the online checkout, don't push."), [("no_push", None)])

    def test_how_people_say_keep_it_away(self):
        """E20's tuned phrasings (written from how people put it, never from a pool): each keeps the file away, after
        a request that names the task file; each scope keeps the task file to itself."""
        for said in TUNED["constraints"]:
            with self.subTest(said):
                self.assertIn(("keep_away", "settings.yaml"), constraints.extract(ASKED + fill(said, target=TARGET)))
        missed = {s for s in TUNED["scope_constraints"]
                  if ("only_change", "pager.py") not in constraints.extract(ASKED + fill(s, task_file=TASK))}
        self.assertEqual(missed, {"Please keep the diff to {task_file}."})   # "keep the changes to X small" says go

    def test_requests_that_state_no_constraint_hold_nothing(self):
        """Permission, reminders, questions, quoted text and code, a condition, "don't" in another clause: no
        constraint, so nothing the hook would hold live."""
        for said in TUNED["constraint_negatives"]:
            with self.subTest(said):
                text = ASKED + fill(said, target=TARGET)
                self.assertEqual((constraints.extract(text), claude_code._live(text)), ([], []))

    def test_conditions_questions_quotes_and_what_it_refers_to(self):
        for text, want in (
                ("Don't edit billing.py without checking the tests first.", []),   # allowed once checked
                ("Don't touch billing.py until the release.", []),
                ("Could you leave billing.py alone?", [("keep_away", "billing.py")]),
                ("Don't touch billing.py, ok?", [("keep_away", "billing.py")]),
                ("Should I leave billing.py alone?", []),
                ('The old note says "never edit billing.py".', []),
                ("Don't touch `billing.py`.", [("keep_away", "billing.py")]),
                ("billing.py is generated; make no changes there.", [("keep_away", "billing.py")]),
                ("Here is billing.py. Don't change it.", [("keep_away", "billing.py")]),
                ("Fix billing.py; don't rewrite it from scratch.", []),
                ("If billing.py is generated, don't touch it.", []),
                ("Don't change how billing.py is imported.", []),
                ("Don't change the tests to make billing.py pass.", []),
                ("I didn't change billing.py yet.", []),   # a report, not an instruction
                ("Everything outside src/pager.py is off-limits.", [("only_change", "pager.py")]),
                ("Fix src/pager.py; everything else is out of scope.", [("only_change", "pager.py")])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)

    def test_a_scope_is_checked_after_the_run_and_never_held_live(self):
        """"Only change X" holds no call (every test or lockfile write would ask the person): TK-X204 reads it after."""
        text = "Only change src/pager.py and don't touch billing.py."
        self.assertEqual(constraints.extract(text), [("only_change", "pager.py"), ("keep_away", "billing.py")])
        self.assertEqual(claude_code._live(text), [("keep_away", "billing.py")])
        sent = []
        claude_code.prompted(mock.Mock(call=lambda m, **kw: sent.append(kw["constraint"])), text)
        self.assertEqual(sent, [{"kind": "keep_away", "object": "billing.py"}])

    def test_a_64_kib_prompt_is_read_in_bounded_time(self):
        n = 1 << 16
        for unit in ("don't ", "leave ", "hands off ", "only ", "it ", '"', "`", "```", "nothing else ", "? ",
                     "a.py is not to be ", "x.py ", "no changes to ", "everything else ", "as is ", "make no changes "
                     "there. ", "don't touch a.py until ", "stay away from ", "is the only "):
            text = (unit * (n // len(unit) + 1))[:n]
            t0 = time.perf_counter()
            constraints.extract(text)
            constraints.mentions(text)
            self.assertLess(time.perf_counter() - t0, 2, unit)

    def test_a_later_request_lifts_what_it_names(self):
        keep = "billing.py".__eq__
        self.assertTrue(constraints.lifts("keep_away", constraints.mentions("Now update billing.py too."), keep))
        self.assertFalse(constraints.lifts("keep_away", constraints.mentions("Still don't touch billing.py."), keep))
        self.assertTrue(constraints.lifts("no_push", constraints.mentions("OK, push it."), keep))
        self.assertFalse(constraints.lifts("no_push", constraints.mentions("Never push."), keep))
        self.assertTrue(constraints.lifts("read_only", constraints.mentions("Go ahead and fix it."), keep))

    def test_what_a_call_does(self):
        bash = lambda c: constraints.facts("Bash", {"command": c})   # noqa: E731
        self.assertEqual(bash("sed -i 's/a/b/' src/Billing.py && cat pager.py")["names"], ["billing.py"])
        self.assertEqual(bash("echo x > billing.py")["names"], ["billing.py"])
        self.assertEqual(bash("cp billing.py /tmp/b")["names"], ["b"])   # read, not written
        self.assertEqual(bash("cat billing.py")["write"], False)
        self.assertTrue(bash("git push origin main")["push"] and bash("git push origin main")["network"])
        self.assertTrue(bash("sudo pip install leftpad")["network"])
        self.assertEqual(constraints.facts("Edit", {"file_path": "/w/billing.py"})["names"], ["billing.py"])
        self.assertEqual(constraints.facts("Read", {"file_path": "/w/billing.py"}, "fs")["write"], False)
        self.assertTrue(constraints.facts("WebFetch", {"url": "https://example.org"})["network"])
        self.assertTrue(constraints.facts("fetch_page", {"url": "https://example.org"}, "http")["network"])

    def test_a_call_is_read_as_the_policy_engine_reads_it(self):
        """A shell call through the policy engine's parser: an argv list, OpenAI's `commands`, a nested shell, eval and
        wrappers; a write tool's path and `paths` (every file of a Codex patch, whose text is in `command`) before any
        command."""
        sh = lambda **a: constraints.facts("Bash", a, "shell")   # noqa: E731
        for args in ({"command": "bash -c 'git push origin main'"}, {"command": ["git", "push", "origin", "main"]},
                     {"commands": ["ls", "git push origin main"]}, {"command": "eval git push origin main"},
                     {"cmd": "env A=1 sudo git push origin main"},
                     {"command": ["bash", "-lc", "sh -c 'git push origin main'"]},
                     {"command": "echo $(git push origin main)"}):
            with self.subTest(args):
                self.assertTrue(sh(**args)["push"] and sh(**args)["network"])
        self.assertEqual(sh(command="sh -c 'echo x > Billing.py'")["names"], ["billing.py"])
        self.assertEqual(sh(command="bash -c 'tee -a billing.py < in.txt'")["names"], ["billing.py"])
        self.assertTrue(sh(command=["bash", "-lc", "curl https://example.org"])["network"])
        self.assertEqual(sh(command="wc -l < billing.py 2>/dev/null >&2"), {"names": [], "write": False, "push": False,
                                                                            "network": False})
        self.assertTrue(sh(command="rm *.pyc")["write"])   # no name to compare, but a write
        patch = ("*** Begin Patch\n*** Update File: src/config.py\n@@\n-a\n+b\n*** Add File: docs/new.md\n+x\n"
                 "*** End Patch")
        tool, ti = agent_hooks.tool("codex", "apply_patch", {"command": patch})
        self.assertEqual(constraints.facts(tool, ti, "fs")["names"], ["config.py", "new.md"])
        self.assertEqual(constraints.facts(tool, ti)["names"], ["config.py", "new.md"])   # as the analysis reads it

    def test_breaks(self):
        f = constraints.facts("Edit", {"file_path": "/w/billing.py"})
        self.assertEqual(constraints.breaks("keep_away", f, "billing.py".__eq__), "billing.py")
        self.assertIsNone(constraints.breaks("keep_away", f, "pager.py".__eq__))
        self.assertEqual(constraints.breaks("only_change", f, {"pager.py"}.__contains__), "billing.py")
        self.assertEqual(constraints.breaks("read_only", f, None), "billing.py")
        self.assertIsNone(constraints.breaks("no_push", f, None))

    def test_hostile_text_is_read_in_linear_time(self):
        for text in ("don't " * 100_000 + "touch billing.py", "a/" * 300_000, "x.py " * 100_000, "." * 600_000):
            t0 = time.perf_counter()
            constraints.extract(text)
            constraints.mentions(text)
            constraints.facts("Bash", {"command": text})
            self.assertLess(time.perf_counter() - t0, 5, text[:20])
        for many in ("Don't touch " + " or ".join(f"a{k}.py" for k in range(9000)),   # one clause naming 9,000 files
                     "Don't change anything except " + " ".join(f"a{k}.py" for k in range(9000)),
                     "Don't change anything" + "".join(f", except a{k}.py" for k in range(4000))):
            t0 = time.perf_counter()
            self.assertGreater(len(constraints.extract(many)), 3000)
            constraints.mentions(many)
            self.assertLess(time.perf_counter() - t0, 0.2)   # each file looked only at the next, not at every other


class Live(Signed):
    """Live constraints in an in-process signer whose default policy allows reads and edits, asks for a push and
    denies touching Tracekit's own files."""

    def run_(self):
        r = self.register(ME)
        self.seq = 0
        return r

    def add(self, run, kind, obj=None, who=ME):
        return self.call(who, "constraint_add", **run, constraint={"kind": kind, **({"object": obj} if obj else {})})

    def decide(self, run, tool, args, tcid=None):
        self.seq += 1
        return self.call(ME, "decide", **run, stream="s", client_seq=self.seq - 1,
                         tool_call_id=tcid or f"t{self.seq}", tool=tool, args_source="parsed", args=args)

    def records(self, run):
        return [r["event"] for r in self.s.log.storage.iter_run("default", run["run_id"])]

    def test_holds_the_next_matching_call_and_nothing_else(self):
        run = self.run_()
        self.add(run, "keep_away", "src/Billing.py")
        held = self.decide(run, "Edit", {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"})
        self.assertEqual((held["decision"], held["rule_ids"]), ("ask", ["TK-CONSTRAINT"]))
        self.assertEqual(held["reason"], "the person's request in this run said not to modify billing.py; ask the "
                                         "person")
        for tool, args in (("Edit", {"file_path": "/w/pager.py", "old_string": "a", "new_string": "b"}),
                           ("Read", {"file_path": "/w/billing.py"}), ("Bash", {"command": "cat billing.py"})):
            with self.subTest(tool=tool, args=args):
                self.assertEqual(self.decide(run, tool, args)["decision"], "allow")
        self.assertEqual(self.decide(run, "Bash", {"command": "sed -i s/a/b/ billing.py"})["decision"], "ask")

    def test_a_codex_patch_and_a_nested_push_are_held(self):
        run = self.run_()
        self.add(run, "keep_away", "config.py")
        self.add(run, "no_push")
        tool, ti = agent_hooks.tool("codex", "apply_patch", {
            "command": "*** Begin Patch\n*** Update File: src/config.py\n@@\n-a\n+b\n*** End Patch"})
        for tool, args in ((tool, ti), ("Bash", {"command": "bash -c 'git push origin main'"}),
                           ("shell", {"command": ["git", "push", "origin", "main"]}),
                           ("shell", {"commands": ["git push origin main"]})):
            with self.subTest(args):
                self.assertIn("TK-CONSTRAINT", self.decide(run, tool, args)["rule_ids"])

    def test_the_writer_checks_at_most_max_names_files_per_constraint(self):
        """The salted commitments of a call's files are computed off the writer, once per distinct name and file
        constraint, and at most MAX_NAMES names: a call writing more is held whenever the run has a file constraint."""
        run = self.run_()
        for i in range(svc.MAX_CONSTRAINTS):
            self.add(run, "keep_away", f"never{i}.py")
        with mock.patch.object(svc, "_commitment", wraps=svc._commitment) as commit:
            out = self.decide(run, "Bash", {"command": "tee " + " ".join(f"f{i}" for i in range(9000))})
            self.assertEqual((out["decision"], out["rule_ids"]), ("ask", ["TK-CONSTRAINT"]))
            self.assertIn(f"more than {svc.MAX_NAMES} files", out["reason"])
            self.assertLessEqual(commit.call_count, 2)   # the decision's own args commitment
            commit.reset_mock()
            out = self.decide(run, "Bash", {"command": "tee " + " ".join(f"f{i % 200}" for i in range(10000))})
            self.assertEqual(out["decision"], "allow")
            self.assertLessEqual(commit.call_count, svc.MAX_CONSTRAINTS * 200 + 2)
        bare = self.run_()
        self.add(bare, "no_push")
        self.assertEqual(self.decide(bare, "Bash", {"command": "tee " + " ".join(f"f{i}" for i in range(9000))})[
            "decision"], "allow")

    def test_a_constraint_added_after_the_request_thread_looked_still_holds(self):
        run = self.run_()
        self.add(run, "no_push")
        key = ("default", run["run_id"])
        early = self.s._facts(key, "Edit", {"file_path": "/w/billing.py"}, "fs")   # before keep_away billing.py
        self.add(run, "keep_away", "billing.py")
        self.assertIn("not to modify billing.py", self.s._constrained(self.s.log.runs[key], early))

    def test_the_record_holds_a_commitment_never_the_name(self):
        run = self.run_()
        self.add(run, "keep_away", "billing.py")
        self.add(run, "no_push")
        added = [e for e in self.records(run) if e["type"] == "constraint.added"]
        self.assertEqual([e["data"]["kind"] for e in added], ["keep_away", "no_push"])
        self.assertTrue(added[0]["data"]["object_commitment"].startswith("hmac-sha256:"))
        self.assertNotIn("billing", repr(added))
        self.assertEqual(set(added[1]["data"]), {"kind"})

    def test_a_decision_is_never_lowered(self):
        """For every kind, each call decides at least as strictly with constraints as without: a deny stays a deny, an
        ask stays an ask and names TK-CONSTRAINT beside the policy's rules, an allow may become an ask."""
        calls = [("Bash", {"command": "pkill tracekitd"}), ("Bash", {"command": 'echo "open'}),
                 ("Bash", {"command": "git push origin main"}),
                 ("Edit", {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"}),
                 ("Bash", {"command": "curl https://example.org"}), ("Read", {"file_path": "/w/x.py"}),
                 ("Bash", {"command": "ls"})]
        bare = self.run_()
        base = [self.decide(bare, *c) for c in calls]
        run = self.run_()
        for kind, obj in (("keep_away", "billing.py"), ("only_change", "pager.py"), ("read_only", None),
                          ("no_push", None), ("no_network", None)):
            self.add(run, kind, obj)
        order = ("allow", "ask", "deny")
        for c, was in zip(calls, base):
            with self.subTest(c):
                now = self.decide(run, *c)
                self.assertGreaterEqual(order.index(now["decision"]), order.index(was["decision"]))
                if was["decision"] == "deny":
                    self.assertEqual(now["rule_ids"], was["rule_ids"])
                else:
                    self.assertEqual(now["rule_ids"][:len(was["rule_ids"])], was["rule_ids"])
        self.assertEqual([d["decision"] for d in base], ["deny", "ask", "allow", "allow", "allow", "allow", "allow"])
        self.assertEqual([d["decision"] for d in (self.decide(run, *c) for c in calls)],
                         ["deny", "ask", "ask", "ask", "ask", "allow", "allow"])

    def test_a_made_up_constraint_only_adds_holds(self):
        """The agent's own identity may add one (the hook runs as it): all it can do is hold its own calls."""
        run = self.run_()
        self.add(run, "no_network")
        out = self.decide(run, "Bash", {"command": "curl https://example.org"})
        self.assertEqual((out["decision"], out["rule_ids"][-1]), ("ask", "TK-CONSTRAINT"))   # after the policy's flags
        self.assertIn("said not to use the network", out["reason"])
        self.assertEqual(self.decide(run, "Bash", {"command": "pkill tracekitd"})["decision"], "deny")

    def test_a_held_call_is_approved_like_any_ask(self):
        run = self.run_()
        self.add(run, "keep_away", "billing.py")
        args = {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"}
        d = self.decide(run, "Edit", args, "t-held")
        aid = self.call(ME, "approval_request", **run, tool_call_id="t-held")["approval_id"]
        self.call(ME, "approval_decide", approval_id=aid, decision="approve")
        self.assertTrue(self.call(ME, "approval_consume", **run, tool_call_id="t-held", tool="Edit",
                                  args_source="parsed", args=args, approval_id_hint=aid)["ok"])
        self.call(ME, "complete", **run, stream="s", client_seq=self.seq, tool_call_id="t-held",
                  decision_id=d["decision_id"], args_digest=svc.event_hash({"tool": "Edit", "args": args}),
                  status="ok")
        types = [e["type"] for e in self.records(run)]
        self.assertEqual(types[-4:], ["approval.request", "approval", "approval.consumed", "tool.result"])
        self.assertNotIn("capture.gap", types)

    def test_constraints_outlive_a_signer_restart(self):
        run = self.run_()
        self.add(run, "keep_away", "billing.py")
        self.s.close()
        self.s = svc.SignerService(os.path.join(self.dir, "data"), grace_s=0, fsck_every_s=0)
        self.addCleanup(self.s.close)
        out = self.decide(run, "Write", {"file_path": "/w/billing.py", "content": "x"})
        self.assertEqual((out["decision"], out["rule_ids"]), ("ask", ["TK-CONSTRAINT"]))

    def test_refusals(self):
        run = self.run_()
        for bad in ({"kind": "keep_away"}, {"kind": "no_push", "object": "x.py"}, {"kind": "keep_away", "object": "/"},
                    {"kind": "anything"}):
            with self.subTest(bad), self.assertRaises(RPCError) as e:
                self.call(ME, "constraint_add", **run, constraint=bad)
            self.assertEqual(e.exception.code, "invalid_request")

    def test_an_equal_constraint_is_the_one_the_run_has(self):
        """The hook sends what each prompt states: the same constraint again is the one the run has (for a file, by
        its commitment), so repeats never fill the run and the person's next constraint still holds."""
        run = self.run_()
        first = [self.add(run, kind, obj)["run_seq"] for kind, obj in (("no_push", None), ("keep_away", "a.py"))]
        for _ in range(svc.MAX_CONSTRAINTS + 1):
            self.assertEqual(self.add(run, "no_push")["run_seq"], first[0])
            self.assertEqual(self.add(run, "keep_away", "src/A.py")["run_seq"], first[1])
        self.add(run, "keep_away", "billing.py")
        held = self.decide(run, "Edit", {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"})
        self.assertEqual((held["decision"], held["rule_ids"]), ("ask", ["TK-CONSTRAINT"]))
        self.assertEqual([e["type"] for e in self.records(run)].count("constraint.added"), 3)

    def test_past_the_cap_a_constraint_is_a_signed_gap(self):
        run = self.run_()
        for i in range(svc.MAX_CONSTRAINTS):
            self.add(run, "keep_away", f"f{i}.py")
        seq = self.add(run, "no_push")["run_seq"]
        gap = next(e for e in self.records(run) if e["run_seq"] == seq)
        self.assertEqual((gap["type"], gap["source"], gap["data"]["kind"]), ("capture.gap", "signer",
                                                                              "constraint_refused"))
        self.assertIn("a further no_push constraint was not added", gap["data"]["reason"])
        self.assertEqual(self.add(run, "keep_away", "f3.py")["run_seq"], 4)   # an equal one is still the one it has
        self.call(ME, "close_run", **run)
        rep, code = v2.verify(*self.export(run))
        self.assertEqual(code, 0, rep.checks)
        self.assertIn("constraint_refused 1", next(c for c in rep.checks if c["check"] == "gaps")["detail"])

    def test_a_run_with_live_constraints_verifies(self):
        run = self.run_()
        self.add(run, "keep_away", "billing.py")
        self.decide(run, "Edit", {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"})
        self.call(ME, "close_run", **run)
        bundle, trust = self.export(run)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, rep.checks)
        line = next(c for c in rep.checks if c["check"] == "constraints")
        self.assertEqual((line["status"], line["detail"]), ("pass", "1 live constraint(s) added; 1 call(s) held by them"))


def misplaced_bundle(log, out, decision="ask", before=True):
    """Export to `out` a run whose TK-CONSTRAINT decision comes before any constraint.added (`before`), or is a
    `decision` other than ask: what no signer writes."""
    log.epoch(b.KEY1)
    log.register()
    held = {"tool_use_id": "t1", "decision": decision, "rule_ids": ["TK-CONSTRAINT"]}
    if not before:
        log.add("constraint.added", {"kind": "no_push"})
    log.add("policy.decision", held, tool_call_id="t1")
    if before:
        log.add("constraint.added", {"kind": "no_push"})
    log.final()
    export(log.store, "acme", "run-a", log.note(), out)
    return out


class Verify(unittest.TestCase):
    @unverified_bundles   # a hold no signer writes, on purpose
    def test_a_hold_before_its_constraint_or_no_ask_fails(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        trust = os.path.join(d, "trust.json")
        with open(trust, "w") as f:
            f.write(b.json.dumps(b.trust_config()))
        for name, kw, why in (("before", {}, "before any constraint.added in its run"),
                              ("allow", {"decision": "allow", "before": False}, "is no ask")):
            with self.subTest(name):
                log = b.Log(os.path.join(d, name))
                self.addCleanup(log.store.close)
                rep, code = v2.verify(misplaced_bundle(log, os.path.join(d, f"{name}.tkb"), **kw), trust)
                self.assertEqual((code, rep.failures), (1, ["constraints"]))
                self.assertIn(why, next(c for c in rep.checks if c["check"] == "constraints")["problems"][0])


if __name__ == "__main__":
    unittest.main()
