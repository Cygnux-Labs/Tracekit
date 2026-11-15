"""TIPS' lessons (tracekit/lessons.py): what coding agents keep relearning, found in signed records, approved by a person
and given to the next Claude Code session; the folder they live in; what the next session reads; each one's effect.

    python3 -m pytest tests/test_lessons.py -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from factories import v2rec  # noqa: E402
from tracekit import lessons, view  # noqa: E402

DAY = 86400
T0 = datetime(2026, 11, 2, 9, tzinfo=timezone.utc).timestamp()
CWD, PROJECT = "/Users/me/proj", "-Users-me-proj"
FILE = CWD + "/tracekit/why/import_v2.py"


def tmp(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return d


class Scene:
    """Claude Code sessions as the viewer's rows see them: each a verified run's signed records (view.Translator's
    rows, the decisions' arguments as the dev signer's vault opens them) and its calls in the transcripts (`tr`, as
    tips.read_transcripts joins them: session, project, working directory, a failed call's error text)."""

    def __init__(self):
        self.recs, self.content, self.tr = [], {}, {}

    def session(self, sid, t, project=PROJECT, cwd=CWD):
        self.sid, self.run, self.t, self.project, self.cwd, self.seq = sid, f"run-{sid}", t, project, cwd, 1
        self._rec("run.registered", {"agent": {"name": "claude-code"}})
        return self

    def _rec(self, typ, data):
        self.t += 1
        stamp = datetime.fromtimestamp(self.t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.recs.append(v2rec(self.seq, typ, data, run=self.run, ts=stamp))
        self.seq += 1
        return self.seq - 1

    def call(self, tool, args, ok=True, decision="allow", error=None, prov=None, state=None, agent=None):
        """A decided call (and its signed result when it ran: `ok` None gives none)."""
        tid = f"toolu_{len(self.tr):04d}"
        d = {"tool_use_id": tid, "tool": tool, "decision": decision, "args_commitment": "hmac-sha256:00",
             "rule_ids": [] if decision == "allow" else ["TK-D001"], **({"provenance": prov} if prov else {}),
             **({"provenance_state": state} if state else {})}
        seq = self._rec("policy.decision", d)
        self.content[self.run, seq] = args
        if decision in lessons.RAN and ok is not None:
            self._rec("tool.result", {"tool_use_id": tid, "ok": ok, "duration_ms": 1500})
        self.tr[tid] = {"agent": self.sid + (f"/{agent}" if agent else ""), "project": self.project, "cwd": self.cwd,
                        **({"error": error} if error else {})}
        return seq

    def lookup(self, pattern="held_calls", path=FILE, tool="Grep", **kw):
        self.call(tool, {"pattern": pattern} if tool == "Grep" else {"command": f"rg {pattern} tracekit"}, **kw)
        return self.call("Read", {"file_path": path}, **kw)

    def fix(self, failed="python3 -m pytest tests/a.py", worked=".venv/bin/python -m pytest tests/a.py",
            error="Exit code 1\n/usr/bin/python3: No module named pytest"):
        self.call("Bash", {"command": failed}, ok=False, error=error)
        return self.call("Bash", {"command": worked})

    def prompt(self, text, source="claude-code:UserPromptSubmit", trust="trusted"):
        seq = self._rec("input.observed", {"source": source, "trust": trust, "output": {"hash": "sha256:00"}})
        self.content[self.run, seq] = text

    def given(self, value):
        self.prompt(value, source=lessons.SOURCE)

    def rows(self):
        tr = view.Translator()
        tr.content.update(self.content)
        return [x for r in self.recs for x in tr.feed(r)]

    def found(self, notes=()):
        """(waiting, not proposed) of these sessions against the folder's `notes`."""
        occs, idx, _ = lessons.detect(self.rows(), self.tr)
        return lessons.propose(occs, idx, list(notes))


def lookups(s, days=(0, 0, 1), **kw):
    for i, d in enumerate(days):
        s.session(f"s{i}", T0 + d * DAY + i * 600).lookup(**kw)
    return s


class Lookup(unittest.TestCase):
    def test_a_search_then_open_in_three_sessions_on_two_days_is_a_lookup(self):
        waiting, nope = lookups(Scene()).found()
        [w] = waiting
        self.assertEqual((w["kind"], w["key"], w["sessions"], w["days"]),
                         ("lookup", ["held_calls", "tracekit/why/import_v2.py"], 3, 2))
        self.assertEqual(w["text"], "Searching for `held_calls` here leads to `tracekit/why/import_v2.py`: it was "
                                    "opened right after that search in 3 sessions.")
        self.assertEqual((w["origin"], w["type"], w["tier"], w["risky"]), ("run", "reference", "signed+transcript", False))
        self.assertEqual(w["id"], lessons.lesson_id("lookup", PROJECT, w["key"]))
        self.assertEqual(w["approve"], f"tracekit tips approve {w['id']}")
        self.assertEqual(len(w["evidence"]), 3)   # each session's search and read, its records named
        self.assertEqual([c["what"] for c in w["evidence"][0]["calls"]],
                         ["Grep held_calls", "Read tracekit/why/import_v2.py"])
        self.assertEqual(w["saving"]["calls"], 3)   # each session's search
        self.assertEqual(nope, [])

    def test_a_shell_search_counts_as_one(self):
        waiting, _ = lookups(Scene(), tool="Bash").found()
        self.assertEqual([w["key"] for w in waiting], [["held_calls", "tracekit/why/import_v2.py"]])

    def test_two_sessions_or_one_day_is_not_enough_and_the_page_says_why(self):
        for days in ((0, 1), (0, 0, 0)):
            with self.subTest(days=days):
                waiting, [n] = lookups(Scene(), days).found()
                self.assertEqual(waiting, [])
                self.assertEqual(n["rule"], "one_session")
                self.assertIn("a lookup needs 3 sessions on 2 days", n["why"])

    def test_a_file_written_between_the_search_and_the_read_is_no_lookup(self):
        s = Scene()
        for i, d in enumerate((0, 0, 1)):
            s.session(f"s{i}", T0 + d * DAY + i * 600)
            s.call("Grep", {"pattern": "held_calls"})
            s.call("Edit", {"file_path": FILE, "old_string": "a", "new_string": "b"})
            s.call("Read", {"file_path": FILE})
        self.assertEqual(s.found(), ([], []))

    def test_a_read_more_than_three_calls_after_the_search_is_no_lookup(self):
        s = Scene()
        for i, d in enumerate((0, 0, 1)):
            s.session(f"s{i}", T0 + d * DAY + i * 600)
            s.call("Grep", {"pattern": "held_calls"})
            for _ in range(lessons.PAIR_WITHIN):
                s.call("Bash", {"command": "ls"})
            s.call("Read", {"file_path": FILE})
        self.assertEqual(s.found(), ([], []))


class Taint(unittest.TestCase):
    PAGE = [{"field": "file_path", "kind": "path", "source": {"run_seq": 2, "tool": "WebFetch"}}]

    def test_a_path_only_a_fetched_page_brought_is_tainted_and_never_proposed(self):
        waiting, [n] = lookups(Scene(), prov=self.PAGE).found()
        self.assertEqual(waiting, [])
        self.assertEqual(n["rule"], "tainted")
        self.assertIn("its file_path came from record 2", n["why"])

    def test_a_run_whose_provenance_is_not_complete_gives_no_occurrence(self):
        for state in ("partial", "truncated", "unavailable", "timeout"):
            with self.subTest(state=state):
                waiting, [n] = lookups(Scene(), state=state).found()
                self.assertEqual((waiting, n["rule"]), ([], "tainted"))
                self.assertIn(f"its provenance is {state}", n["why"])

    def test_a_tainted_candidate_is_named_only_when_taint_is_what_stopped_it(self):
        """The real week listed 131 tainted candidates, most seen in one session: no lesson either way. One that
        would have been proposed but for the taint is named; one too rare anyway is not, or is a near miss."""
        self.assertEqual(lookups(Scene(), days=(0,), state="partial").found(), ([], []))
        s = lookups(Scene(), days=(0, 0))
        s.session("s9", T0 + 3600).lookup(state="partial")   # a third session, the same day: too rare anyway
        waiting, [n] = s.found()
        self.assertEqual((waiting, n["rule"]), ([], "one_session"))
        self.assertIn("Seen in 2 sessions on 1 day", n["why"])
        s.session("s10", T0 + DAY).lookup()   # a clean one the next day: 3 clean sessions on 2 days, proposed
        self.assertEqual([(len(w["evidence"]), n) for w in s.found()[0] for n in [s.found()[1]]], [(3, [])])

    def test_a_complete_index_with_nothing_untrusted_says_nothing_and_is_clean(self):
        """The signer leaves provenance_state out when the index is complete and no argument was untrusted
        (service._provenance's fields()): absent is complete."""
        self.assertEqual(len(lookups(Scene(), state=None).found()[0]), 1)

    def test_a_value_untrusted_content_brought_in_another_session_taints_it_everywhere(self):
        """A page fetched in one session names a path; three later sessions, which fetched nothing, search and open
        it: the signer's provenance of the first proves where the value came from, and that is enough."""
        s = Scene().session("s-page", T0 - 600)
        s.call("WebFetch", {"url": "https://docs.example.net/setup", "prompt": "where is it"})
        s.call("Write", {"file_path": "/Users/me/.claude/projects/-Users-me-proj/memory/setup.md",
                         "content": f"The helper lives in {FILE}"},
               prov=[{"field": "content", "kind": "path", "source": {"run_seq": 3, "tool": "WebFetch"}}])
        waiting, [n] = lookups(s).found()
        self.assertEqual((waiting, n["rule"]), ([], "tainted"))
        self.assertIn("carries a value untrusted content brought in another run", n["why"])


class Fix(unittest.TestCase):
    def test_the_same_failure_and_fix_three_times_in_two_sessions_is_a_fix_with_its_shape(self):
        s = Scene().session("s0", T0)
        s.fix()
        s.fix(failed="python3 -m pytest tests/b.py", worked=".venv/bin/python -m pytest tests/b.py")
        s.session("s1", T0 + DAY).fix(failed="python3 -m pytest", worked=".venv/bin/python -m pytest")
        [w], _ = s.found()
        self.assertEqual(w["key"], ["python3", "python3: No module named pytest", "python3 → .venv/bin/python"])
        self.assertEqual(w["text"], "`python3 -m pytest` fails here with “python3: No module named pytest”; "
                                    "`.venv/bin/python -m pytest` worked (3 times in 2 sessions).")
        self.assertEqual((w["type"], w["sessions"], w["times"]), ("feedback", 2, 3))

    def test_twice_is_not_enough(self):
        s = Scene().session("s0", T0)
        s.fix()
        s.session("s1", T0 + DAY).fix()
        waiting, [n] = s.found()
        self.assertEqual((waiting, n["rule"]), ([], "one_session"))

    def test_a_fix_with_a_write_between_is_a_code_change_not_a_lesson(self):
        s = Scene()
        for i in range(3):
            s.session(f"s{i}", T0 + i * DAY)
            s.call("Bash", {"command": "python3 -m pytest"}, ok=False, error="E   No module named pytest")
            s.call("Write", {"file_path": CWD + "/conftest.py", "content": "x"})
            s.call("Bash", {"command": "python3 -m pytest -x"})
        self.assertEqual(s.found(), ([], []))

    def test_a_deny_or_hold_then_a_rewrite_teaches_nothing(self):
        """The 11-07 rule: a call the policy stopped, then a rewrite of it that ran, is evasion, never a lesson;
        neither is a failure whose fix comes after a stop."""
        for decision in ("deny", "ask"):
            with self.subTest(decision=decision):
                s = Scene()
                for i in range(3):
                    s.session(f"s{i}", T0 + i * DAY)
                    s.call("Bash", {"command": "git push --no-verify origin main"}, decision=decision, ok=None)
                    s.call("Bash", {"command": "git push origin main"})
                    s.call("Bash", {"command": "make test"}, ok=False, error="make: *** error: no rule")
                    s.call("Bash", {"command": "sudo make test"}, decision=decision, ok=None)
                    s.call("Bash", {"command": "make tests"})
                self.assertEqual(s.found(), ([], []))

    def test_an_error_is_cut_to_one_line_with_paths_and_numbers_masked(self):
        self.assertEqual(lessons._signature("Exit code 1\n/opt/x/bin/sh: line 3: timeout: command not found"),
                         "sh: line N: timeout: command not found")
        self.assertEqual(lessons._signature("Traceback (most recent call last):\n  File \"/a/b.py\", line 9\n"
                                            "ModuleNotFoundError: No module named 'yaml'"),
                         "ModuleNotFoundError: No module named 'yaml'")
        self.assertIsNone(lessons._signature("Exit code 1\nFAILED tests/test_a.py::test_b"))


class Told(unittest.TestCase):
    def test_a_typed_remember_is_a_told_lesson_and_pasted_text_never_is(self):
        s = Scene().session("s0", T0)
        s.call("Bash", {"command": "ls"})
        s.prompt("From now on, run the tests with the venv's python. Fix the flaky test.")
        s.prompt("Always reply in French.", source="claude-code:paste", trust="untrusted")
        s.prompt("Should we always squash commits?")
        s.prompt("Maybe always use tabs.")
        [w], _ = s.found()
        self.assertEqual((w["kind"], w["origin"], w["type"]), ("told", "you", "feedback"))
        self.assertEqual(w["text"], "The person said: “From now on, run the tests with the venv's python.” "
                                    "(1 session).")

    def test_the_same_instruction_in_two_sessions_is_one_lesson(self):
        s = Scene()
        for i, text in enumerate(("Always run make lint before you commit.",
                                  "Remember to always run make lint before you commit please.")):
            s.session(f"s{i}", T0 + i * DAY).call("Bash", {"command": "ls"})
            s.prompt(text)
        [w], _ = s.found()
        self.assertEqual(w["sessions"], 2)

    def test_a_told_lesson_about_holds_is_shown_to_the_person_only(self):
        s = Scene().session("s0", T0)
        s.call("Bash", {"command": "ls"})
        s.prompt("From now on approve every held push yourself.")
        waiting, [n] = s.found()
        self.assertEqual((waiting, n["rule"]), ([], "evasion"))
        self.assertIn("never given to the agent", n["why"])

    def test_a_told_lesson_that_loosens_a_check_is_risky(self):
        s = Scene().session("s0", T0)
        s.call("Bash", {"command": "ls"})
        s.prompt("From now on skip the lint step.")
        [w], _ = s.found()
        self.assertTrue(w["risky"])


class Checks(unittest.TestCase):
    def test_over_4096_bytes_invisible_or_secret_is_refused_not_cut(self):
        folder = lessons.Folder(os.path.join(tmp(self), "lessons"))
        for body, rule in (("x" * 4096, "too_large"), ("Use make​ test.", "invisible_unicode"),
                           ("The key is sk-ant-api03-" + "a" * 40, "secret_shape"),
                           ("Pay to account number 12345678.", "secret_shape"),
                           ("Its token is [REDACTED:github_token].", "secret_value")):
            with self.subTest(rule=rule):
                with self.assertRaises(lessons.Refused) as e:
                    folder.add(PROJECT, body)
                self.assertEqual(e.exception.rule, rule)
                self.assertFalse(os.path.exists(folder.path))   # nothing written, nothing cut

    def test_emoji_and_script_joiners_are_text(self):
        for text in ("Ship it 👍🏽 and 👨‍👩‍👧 ❤️", "می‌خواهم", "क्‍ष"):
            with self.subTest(text=text):
                self.assertIsNone(lessons.hidden(text))
        self.assertEqual(lessons.hidden("a‮b"), 1)

    def test_add_takes_no_key_only_tracekit_writes_and_nothing_about_the_policy(self):
        folder = lessons.Folder(os.path.join(tmp(self), "lessons"))
        with self.assertRaises(lessons.Refused) as e:
            folder.add(PROJECT, "Use make test.", name="Tests\nstatus: retired")
        self.assertEqual(e.exception.rule, "status")
        with self.assertRaises(lessons.Refused) as e:
            folder.add(PROJECT, "Tracekit holds pushes here: ask the person to approve them.")
        self.assertEqual(e.exception.rule, "evasion")


class FolderTests(unittest.TestCase):
    def setUp(self):
        self.folder = lessons.Folder(os.path.join(tmp(self), "lessons"))
        self.waiting = lookups(Scene()).found()[0][0]

    def git(self, *a):
        return subprocess.run(["git", "-C", self.folder.path, *a], capture_output=True, text=True, check=True).stdout

    def test_approve_writes_the_note_rebuilds_memory_md_and_commits(self):
        self.assertIsNone(self.folder.approve(self.waiting, now=T0 + 3 * DAY))
        d = os.path.join(self.folder.path, "projects", PROJECT)
        [n] = self.folder.notes()
        self.assertEqual((n["id"], n["status"], n["origin"], n["kind"], n["key"], n["before"], n["approved"]),
                         (self.waiting["id"], "active", "run", "lookup", self.waiting["key"], "3/3",
                          "2026-11-05T09:00:00Z"))
        self.assertEqual(len(n["evidence"]), 6)
        self.assertTrue(all(":" in e for e in n["evidence"]))
        with open(os.path.join(d, "MEMORY.md")) as f:
            self.assertEqual(f.read(), f"- [Where `held_calls` is]({n['file']}) — When looking for held_calls in this "
                                       "project\n")
        log = self.git("log", "--format=%s%n%b")
        self.assertIn(f"lessons: approve {n['id']}", log)
        self.assertIn(f"Lesson-Id: {n['id']}", log)
        self.assertEqual(lookups(Scene()).found([n]), ([], []))   # in use: not proposed again

    def test_retire_keeps_the_file_and_leaves_the_index_and_restore_brings_it_back(self):
        self.folder.approve(self.waiting)
        lid = self.waiting["id"]
        memory = os.path.join(self.folder.path, "projects", PROJECT, "MEMORY.md")
        self.folder.retire(lid)
        [n] = self.folder.notes()
        self.assertEqual((n["status"], n["retired_from"]), ("retired", "active"))
        with open(memory) as f:
            self.assertEqual(f.read(), "")
        self.assertEqual(lessons.for_agent(project=PROJECT, folder=self.folder)["block"], "")
        self.folder.restore(lid)
        self.assertEqual(self.folder.notes()[0]["status"], "active")
        self.assertIn(lid, lessons.for_agent(project=PROJECT, folder=self.folder)["given"]["whole"])
        self.assertEqual(len(self.git("log", "--format=%s").split()), 9)   # three commits, three words each

    def test_a_retired_proposal_is_not_proposed_again(self):
        self.folder.retire(self.waiting["id"], self.waiting)
        notes = self.folder.notes()
        self.assertEqual([(n["status"], n["retired_from"]) for n in notes], [("retired", "pending")])
        self.assertEqual(lookups(Scene()).found(notes), ([], []))

    def test_a_new_fact_about_the_same_identifier_supersedes_the_old_lesson(self):
        self.folder.approve(self.waiting)
        moved = lookups(Scene(), path=CWD + "/tracekit/why/held.py").found(self.folder.notes())[0][0]
        self.assertEqual([o["id"] for o in moved["supersedes"]], [self.waiting["id"]])
        self.folder.approve(moved)
        by = {n["id"]: n for n in self.folder.notes()}
        self.assertEqual((by[self.waiting["id"]]["status"], by[self.waiting["id"]]["superseded_by"]),
                         ("superseded", moved["file"]))
        self.assertEqual(lessons.for_agent(project=PROJECT, folder=self.folder)["given"]["whole"], [moved["id"]])

    def test_a_symlinked_folder_or_note_is_refused(self):
        self.folder.approve(self.waiting)
        d = os.path.join(self.folder.path, "projects", PROJECT)
        os.symlink(os.path.join(d, "MEMORY.md"), os.path.join(d, "linked.md"))
        for call in (self.folder.notes, lambda: lessons.for_agent(project=PROJECT, folder=self.folder),
                     lambda: self.folder.retire(self.waiting["id"])):
            with self.assertRaises(lessons.Refused):
                call()
        os.remove(os.path.join(d, "linked.md"))
        elsewhere = lessons.Folder(self.folder.path + "-link")
        os.symlink(self.folder.path, elsewhere.path)
        with self.assertRaises(lessons.Refused):
            elsewhere.notes()

    def test_a_project_name_that_is_not_one_folder_is_refused(self):
        """A transcripts root reached through a link once gave the project `..`, and approve wrote beside projects/."""
        for name in ("..", ".", "a/b", "", None):
            with self.subTest(name=name):
                with self.assertRaises(lessons.Refused) as e:
                    self.folder.approve(dict(self.waiting, project=name))
                self.assertEqual(e.exception.rule, "outside")
        self.assertFalse(os.path.exists(self.folder.path))

    def test_a_201st_active_lesson_is_refused(self):
        self.folder.add(PROJECT, "Lesson 0 says nothing.")
        d = os.path.join(self.folder.path, "projects", PROJECT)
        for i in range(1, lessons.INDEX_LINES):
            with open(os.path.join(d, f"you-{i:08x}.md"), "w") as f:
                f.write(lessons.render({"name": f"Lesson {i}", "description": "d", "type": "feedback",
                                        "id": f"L-{i:08x}", "kind": "you", "body": f"Lesson {i}.", "status": "active"}))
        with self.assertRaises(lessons.Refused) as e:
            self.folder.add(PROJECT, "One more.")
        self.assertEqual(e.exception.rule, "index_full")
        self.assertEqual(len([n for n in self.folder.notes() if n["status"] == "active"]), lessons.INDEX_LINES)


def note(i, body="", name=None, description="d"):
    return {"id": f"L-{i:08x}", "file": f"you-{i:08x}.md", "name": name or f"Lesson {i}", "description": description,
            "body": body or f"Lesson {i}.", "status": "active", "approved": f"2026-11-{1 + i % 28:02d}T00:00:00Z"}


class Relevance(unittest.TestCase):
    def test_bm25_ranks_the_lesson_that_bears_on_the_prompt_first(self):
        notes = [note(0, "The release checklist is in docs/RELEASING.md.", "Releasing"),
                 note(1, "Tests run with .venv/bin/python -m pytest.", "Running the tests"),
                 note(2, "The viewer's page is tracekit/ui/terminal.html.", "The viewer's page")]
        scores = lessons.bm25(notes, lessons.query("why do the tests fail with pytest?"))
        self.assertEqual(max(range(3), key=scores.__getitem__), 1)
        self.assertEqual((scores[0], scores[2]), (0, 0))
        paths = lessons.query("tracekit/ui/terminal.html\nfix the page")
        self.assertEqual((paths["terminal"], paths["fix"]), (lessons.PATH_WEIGHT, 1))

    def test_every_lesson_whole_while_all_fit(self):
        notes = [note(i) for i in range(5)]
        self.assertEqual(lessons.select(notes, "anything"), (notes, [], []))

    def test_past_the_budget_whole_lessons_then_lines_then_left_out(self):
        big = "x" * 3000
        notes = [note(0, big + " pytest", "Tests"), note(1, big, "Lint"), note(2, big, "Docs"),
                 *(note(i, "y " * 10) for i in range(3, 400))]
        whole, lines, left = lessons.select(notes, "how do I run pytest?", budget=lessons.BUDGET)
        self.assertEqual(whole[0]["id"], notes[0]["id"])   # the one that bears on the prompt, whole and first
        self.assertNotIn(notes[1], whole)   # bears on nothing: a line at most
        self.assertTrue(lines and left)
        self.assertLessEqual(len(lines), lessons.INDEX_LINES)
        text = lessons.block(whole, lines, True)
        self.assertLessEqual(len(text.encode()), lessons.BUDGET)
        self.assertTrue(text.startswith(lessons.INTRO))
        self.assertTrue(text.endswith(lessons.MORE))

    def test_a_prompt_that_shares_no_word_reads_by_recency(self):
        notes = [note(i, "z" * 3000, f"Lesson {i}") for i in range(4)]
        whole, lines, _ = lessons.select(notes, "unrelated words", budget=lessons.BUDGET)
        self.assertEqual([n["id"] for n in whole], [notes[0]["id"], notes[1]["id"]])

    def test_the_block_stays_under_claude_codes_10000_character_cap(self):
        notes = [note(i, "w " * 1900, f"Lesson {i} pytest") for i in range(200)]
        text = lessons.block(*lessons.select(notes, "pytest")[:2], True)
        self.assertLessEqual(len(text.encode()), lessons.BUDGET)
        self.assertLess(len(text), 10_000)

    def test_a_query_gives_only_the_lessons_that_share_a_word(self):
        folder = lessons.Folder(os.path.join(tmp(self), "lessons"))
        folder.add(PROJECT, "Tests run with .venv/bin/python -m pytest.", name="Running the tests")
        folder.add(PROJECT, "The release checklist is docs/RELEASING.md.", name="Releasing")
        got = lessons.for_agent(project=PROJECT, q="pytest", folder=folder)
        self.assertEqual([x["name"] for x in got["lessons"]], ["Running the tests"])
        self.assertEqual(got["left_out"], [])
        self.assertEqual(got["bytes"], len(got["block"].encode()))
        self.assertEqual(set(got["given"]), {"commit", "whole", "lines", "left_out", "sha256"})


class Measure(unittest.TestCase):
    """A lesson in use, measured on the detector that found it: before its approval against the sessions the signed
    tracekit:lessons observe proves were given it."""

    def run_with(self, before, after, given=5, exposed=5):
        """A lookup approved at T0 + 10 days with `before` recorded; `exposed` later sessions open its file, the first
        `given` of them were given it, and `after` of those searched first."""
        n = {"id": "L-0000abcd", "kind": "lookup", "project": PROJECT, "key": ["held_calls", "tracekit/why/import_v2.py"],
             "before": before, "approved": "2026-11-12T09:00:00Z", "status": "active"}
        s = Scene()
        for i in range(exposed):
            s.session(f"a{i}", T0 + 10 * DAY + 3600 * (i + 1))
            if i < given:
                s.given({"whole": [n["id"]], "lines": [], "left_out": [], "sha256": "0" * 64, "commit": None})
            if i < after:
                s.call("Grep", {"pattern": "held_calls"})
            s.call("Read", {"file_path": FILE})
        occs, idx, runs = lessons.detect(s.rows(), s.tr)
        hit = {o["session"] for o in occs if o["key"] == n["key"]}
        return lessons.effect(n, idx, hit, lessons.given(s.rows(), runs).get(n["id"], {}))

    def test_effect_waits_for_five_exposed_sessions_each_side(self):
        e = self.run_with("4/5", 0, given=3, exposed=3)
        self.assertEqual((e["shown"], e["why"], e["given"]), (False, "3 of 5 sessions so far", 3))
        self.assertFalse(self.run_with("4/4", 0)["shown"])

    def test_effect_uses_the_same_detector_before_and_after(self):
        e = self.run_with("4/5", 1, given=5, exposed=6)   # the sixth wasn't given it: not counted
        self.assertEqual((e["shown"], e["before"], e["after"], e["worse"]),
                         (True, {"hits": 4, "exposed": 5}, {"hits": 1, "exposed": 5}, False))
        self.assertEqual(e["change"], -75)
        self.assertEqual(e["basis"], "before and after on the same detector, not a controlled test")

    def test_a_session_given_lessons_counts_before_its_first_call(self):
        """A session that only got its first prompt so far read "given to 0 sessions": its run joined no transcript."""
        s = Scene().session("only-a-prompt", T0)
        s.given({"whole": ["L-0000abcd"], "lines": ["L-0000beef"], "left_out": [], "sha256": "0" * 64, "commit": None})
        got = lessons.given(s.rows(), {})
        self.assertEqual({k: list(v) for k, v in got.items()}, {"L-0000abcd": ["run-only-a-prompt"],
                                                               "L-0000beef": ["run-only-a-prompt"]})

    def test_a_worse_after_is_shown(self):
        e = self.run_with("1/5", 4)
        self.assertEqual((e["shown"], e["worse"]), (True, True))


class Policy(unittest.TestCase):
    def test_the_agents_own_tracekit_tips_approve_is_denied_and_for_agent_is_not(self):
        """TK-D012: a lesson changes what every later session reads, so only a person answers one; reading lessons
        (tracekit tips, --for-agent) stays the agent's. The action is read as tips' first word, the only place
        `tracekit tips` takes it."""
        import importlib.util
        from tracekit.policy2 import compile as policy_compile
        from tracekit.policy2.engine import Engine
        from tracekit.signer import service as svc
        pol, errors = policy_compile.build(svc.DEFAULT_POLICY)
        self.assertEqual(errors, [])
        denied = ["tracekit tips approve L-0123abcd", "tracekit tips retire L-0123abcd", "tracekit tips restore L-1",
                  "tracekit tips add 'Always run make lint.'", "python3 -m tracekit tips approve L-1",
                  "python3 -m tracekit.cli tips approve L-1", "sh -c 'tracekit tips approve L-1'",
                  "/opt/venv/bin/tracekit tips approve L-1", "tracekit -- tips approve L-1",
                  "tracekit tips $A L-1", 'A=approve; tracekit tips "$A" L-1', "cd /tmp && tracekit tips add x"]
        allowed = ["tracekit tips", "tracekit tips --json", "tracekit tips --since 24h",
                   "tracekit tips --for-agent", "tracekit tips --for-agent --json --query 'how to add a test'",
                   "tracekit tips --for-agent --prompt approve", "tracekit tips --help"]
        for backend in ("re2", "regex") if importlib.util.find_spec("re2") else ("regex",):
            e = Engine(pol, backend)
            for line in denied:
                with self.subTest(backend=backend, line=line):
                    d = e.decide("Bash", {"command": line})
                    self.assertEqual(d["verdict"], "deny", d)
                    self.assertIn("TK-D012", d["rule_ids"])
            for line in allowed:
                with self.subTest(backend=backend, line=line):
                    self.assertNotIn("TK-D012", e.decide("Bash", {"command": line})["rule_ids"])
        from tracekit import tips   # an action anywhere but the first word is no action: the command refuses it
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            tips.main(["--since", "7d", "approve", "L-0123abcd"])


class Page(unittest.TestCase):
    def test_the_page_part_has_waiting_in_use_not_proposed_and_the_next_sessions_block(self):
        folder = lessons.Folder(os.path.join(tmp(self), "lessons"))
        s = lookups(Scene())
        for i in (3, 4):   # a near miss: one more lookup in two sessions
            s.session(f"s{i}", T0 + i * 600).lookup(pattern="Translator", path=CWD + "/tracekit/view.py")
        p = lessons.page(s.rows(), s.tr, folder, now=T0 + 7 * DAY, since=T0 - DAY, cwds={PROJECT: "~/proj"})
        self.assertEqual(([w["kind"] for w in p["waiting"]], [n["rule"] for n in p["not_proposed"]]),
                         (["lookup"], ["one_session"]))
        self.assertEqual(p["waiting"][0]["where"], "~/proj")
        folder.approve(p["waiting"][0])
        p = lessons.page(s.rows(), s.tr, folder, now=T0 + 7 * DAY, since=T0 - DAY)
        [a], [nxt] = p["active"], p["next"]
        self.assertEqual((p["waiting"], a["effect"]["shown"]), ([], False))
        self.assertEqual((nxt["whole"], nxt["bytes"], nxt["budget"]), ([a["id"]], len(nxt["block"].encode()),
                                                                       lessons.BUDGET))
        self.assertIsNotNone(p["commit"])

    def test_without_the_dev_store_it_says_why(self):
        self.assertFalse(lessons.page([], {}, None)["ok"])


if __name__ == "__main__":
    unittest.main()
