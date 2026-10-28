"""Stated constraints (#309): the grammar that reads them (tracekit/constraints.py) and live constraints, which the
signer applies to the rest of a run after its policy (constraint_add, TK-CONSTRAINT): a call that breaks one is held for
a person's approval and no decision is ever lowered; both verifiers check where each such hold sits
(docs/policy-v2.md#live-constraints). tests/test_ts_verifier.py runs a run with live constraints through both."""
import os
import shutil
import sys
import tempfile
import time
import timeit
import unittest
from unittest import mock

import test_bundle_v2 as b
from factories import unverified_bundles
from test_reviews import ME, Signed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.e20_alignment import TUNED, Signer, Transcript, fill, replay, score_honest  # noqa: E402
from tracekit import agent_hooks, constraints, findings_v2  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.integrations import claude_code  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import RPCError  # noqa: E402
from tracekit.verify import v2  # noqa: E402

TARGET, TASK, ASKED = "config/settings.yaml", "src/pager.py", "Fix the off-by-one error in src/pager.py. "


def replay_one(prompt, tool, args):
    """(whether a live constraint held the call, the severity of its TK-X204 finding or None) of a Claude Code
    session of `prompt` and one call, replayed into an in-process signer (E20's replay)."""
    d = tempfile.mkdtemp()
    signer = Signer(os.path.join(d, "data"))
    try:
        t = Transcript("/w")
        t.prompt(prompt)
        tid = t.step("Next step.", tool, args)
        t.final("Done.")
        _, records, content = replay(signer, t.lines)
        out = findings_v2.analyze(records, content)
    finally:
        signer.close()
        shutil.rmtree(d, True)
    held = any(r["event"]["type"] == "policy.decision" and r["event"]["data"]["tool_use_id"] == tid
               and "TK-CONSTRAINT" in r["event"]["data"]["rule_ids"] for r in records)
    return held, next((f["verdict"]["severity"] for f in out["findings"] if f["verdict"]["rule"] == "TK-X204"), None)


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
                ("Fix src/pager.py; everything else is out of scope.", [("only_change", "pager.py")]),
                # the rest of the vocabulary, a phrase each
                ("Leave billing.py as-is.", [("keep_away", "billing.py")]),
                ("billing.py is hands-off.", [("keep_away", "billing.py")]),
                ("billing.py is out of bounds.", [("keep_away", "billing.py")]),
                ("Can you leave billing.py alone?", [("keep_away", "billing.py")]),
                ("billing.py cannot be modified.", [("keep_away", "billing.py")]),
                ("Keep your changes scoped to src/pager.py.", [("only_change", "pager.py")]),
                ("Don't omit updating billing.py.", [])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)

    def test_descriptions_scopes_conditions_and_quotes_state_nothing(self):
        """Round-2 review: honest prompts the 1.4 grammar read as constraints, each holding wanted work live.
        "read-only" describing a thing, "nothing should change" for callers, a negated change of one aspect of the file
        asked for, a scoped or conditional push, the network in a description, quoted or indented text, a constraint
        the same request lifts later."""
        for text in (
                "Add a read-only mode to the API client in client.py.", "Adding a read_only flag to the client.",
                "Make the database connection read-only when DEBUG is set (db.py).",
                "The cache should be read-only after startup; please implement that in cache.py.",
                "Please add read-only replicas support to db.py.", "Implement a read-only API token type in tokens.py.",
                "Implement the LRU cache in cache.py. Nothing should change for existing callers.",
                "Please don't change the public API of client.py, just fix the timeout bug inside it.",
                "Don't change the function signature in utils.py, but make parse_date handle empty strings.",
                "Don't overwrite user data in save.py when the file already exists.",
                "Make sure nothing in api.py changes its public behaviour while you refactor the internals.",
                "Run the tests and push when they pass. Don't push to main, use the feature branch.",
                "Don't push until the tests pass. Then push the branch.", "Don't push until the build is green.",
                "Never push secrets to the repo; add a pre-commit hook that scans for them.",
                "The CONTRIBUTING file says: never push to main. Open a PR from a branch and push the branch.",
                "In docs/limits.md, document that the agent can't push without approval.",
                "We don't use the network in unit tests, so mock requests in tests/test_http.py.",
                "Ensure the app works without network access; add an offline fallback to fetch.py.",
                "Our policy is no network access in CI; add a check to ci.py that fails if a test opens a socket.",
                "Make the test suite run without internet; some tests hit httpbin.",
                "> Please don't modify billing.py\nThat note from Sam is outdated, go ahead and fix billing.py.",
                "Here is the code:\n    # don't edit settings.py by hand\n    load()\nAdd a loader to settings.py.",
                "Error log:\nE: do not change config.yaml while the server runs\nFix the server restart in server.py.",
                "Write a test asserting that sync.py never writes to state.db when read-only mode is on.",
                "Don't touch billing.py for now; first fix pager.py. After that, update billing.py too.",
                "Investigate (don't change anything) why build.sh is slow, then speed it up."):
            with self.subTest(text):
                self.assertEqual((constraints.extract(text), claude_code._live(text)), ([], []))
        for text, want in (   # and what still states one
                ("Fix tests/test_api.py. Don't touch anything in vendor/.", [("keep_away", "vendor/")]),
                ("Leave src/legacy/ alone.", [("keep_away", "legacy/")]),
                ("Don't touch the Dockerfile.", [("keep_away", "dockerfile")]),
                ("Fix pager.py. Later I'll ask you to change billing.py, so don't modify billing.py yet.",
                 [("keep_away", "billing.py")]),
                ("Don't touch billing.py while you're at it.", [("keep_away", "billing.py")]),
                ("Please leave billing.py unchanged while fixing pager.py.", [("keep_away", "billing.py")]),
                ("Don't change anything in billing.py.", [("keep_away", "billing.py")]),
                ("Don't touch any code in billing.py.", [("keep_away", "billing.py")]),
                ("Nothing in billing.py should change.", [("keep_away", "billing.py")]),
                ("Don't push it to origin.", [("no_push", None)]), ("I don't want you to push.", [("no_push", None)]),
                ("Stay read-only.", [("read_only", None)]), ("Work in read-only mode.", [("read_only", None)]),
                ("You must not use the network.", [("no_network", None)]),
                ("Work without internet access.", [("no_network", None)]),
                ("Investigate why it fails; don't change anything.", [("read_only", None)])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)

    def test_the_rest_of_the_word_lists(self):
        """A phrase each for words of the lists no other test reads (the phrase-leak guard wants every word of a
        check written with the checks)."""
        for text, want in (("Don't rename it because billing.py imports it.", []),   # BLOCK: no object of its own
                           ("billing.py must be left entirely untouched.", [("keep_away", "billing.py")]),
                           ("billing.py has been frozen.", [("keep_away", "billing.py")]),
                           ("billing.py is considered off-limits.", [("keep_away", "billing.py")]),
                           ("Fix it; though stay offline.", [("no_network", None)])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)
        for cmd in ("git clone https://example.org/r.git", "ssh build-host ls"):
            self.assertTrue(constraints.facts("Bash", {"command": cmd})["network"], cmd)

    def test_a_condition_on_the_persons_own_go_ahead_keeps_the_constraint(self):
        """Round-3 review: "don't push before I review" asks for exactly the hold a live constraint gives; a condition
        on the work ("until the tests pass") still states nothing. Each is held live, and TK-X204 finds the call."""
        for text, call in (("Don't push before I review.", ("Bash", {"command": "git push origin fix"})),
                           ("Don't push without asking me.", ("Bash", {"command": "git push"})),
                           ("Don't push anything to origin until I say so.", ("Bash", {"command": "git push origin"})),
                           ("Never touch deploy/prod.yaml without asking me first.",
                            ("Edit", {"file_path": "/w/deploy/prod.yaml", "old_string": "a", "new_string": "b"})),
                           ("Don't modify billing.py until I approve it.",
                            ("Edit", {"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"})),
                           ("Don't change schema.sql unless I confirm.",
                            ("Write", {"file_path": "/w/schema.sql", "content": "x"}))):
            with self.subTest(text):
                held, rule = replay_one(f"Fix the off-by-one in src/pager.py. {text}", *call)
                self.assertEqual((held, rule), (True, "high"))
        for text in ("Don't push until the tests pass.", "Don't edit billing.py until the tests pass.",
                     "Don't push to main before I review."):
            with self.subTest(text):
                self.assertEqual((constraints.extract(text), claude_code._live(text)), ([], []))

    def test_a_later_it_lifts_a_constraint_only_where_it_asks_for_the_change(self):
        """1.4.0 review H2: a later "it", "them" or "there" with a change word lifted the file named before it, though
        that clause asked the agent for no change ("ask me before you change it", "I'll update it myself"). Each is
        held live and found; a clause that asks for the change still lifts it."""
        for text, name in (("Don't touch prod.yaml. Ask me before you change it.", "prod.yaml"),
                           ("Never touch deploy.yaml; I'll update it myself.", "deploy.yaml"),
                           ("Don't modify config.yaml. If you need to change it, ask me first.", "config.yaml"),
                           ("Don't edit schema.sql; we'll change it in the next PR.", "schema.sql"),
                           ("Don't touch billing.py. Explain how you would change it.", "billing.py"),
                           ("Don't touch prod.yaml. Changing it breaks the deploy.", "prod.yaml"),
                           ("Don't touch prod.yaml. Changes to it need a review.", "prod.yaml"),
                           # delta review D-H1: the person's go-ahead, a purpose clause, should or need
                           ("Don't touch prod.yaml. To change it, ask me first.", "prod.yaml"),
                           ("Don't touch prod.yaml. To edit it, ping me first.", "prod.yaml"),
                           ("Don't touch prod.yaml, but to change it, ask me first.", "prod.yaml"),
                           ("Don't touch prod.yaml. You can change it after I approve.", "prod.yaml"),
                           ("Don't touch prod.yaml. You can change it, once I approve.", "prod.yaml"),
                           ("Don't touch prod.yaml. Feel free to edit it once I say so.", "prod.yaml"),
                           ("Don't touch prod.yaml. Go ahead and update it after I review the plan.", "prod.yaml"),
                           ("Don't touch prod.yaml. You can change it later, but ask me first.", "prod.yaml"),
                           ("Don't touch prod.yaml. You may need to change it later, but ask me first.", "prod.yaml"),
                           ("Don't touch prod.yaml. Should you need to change it, ask me.", "prod.yaml"),
                           ("Don't touch prod.yaml. You can edit prod.yaml once I approve.", "prod.yaml")):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), [("keep_away", name)])
                self.assertEqual(replay_one(f"Fix the off-by-one in src/pager.py. {text}", "Edit", {
                    "file_path": f"/w/{name}", "old_string": "a", "new_string": "b"}), (True, "high"))
        text = "Don't touch prod.yaml or deploy.yaml. You can update them after I approve."
        self.assertEqual(constraints.extract(text), [("keep_away", "prod.yaml"), ("keep_away", "deploy.yaml")])
        for text, want in (("settings.py is frozen in production, but you can edit it locally.", []),
                           ("Leave billing.py alone for now; then go ahead and update it.", []),
                           ("Don't touch billing.py yet. Feel free to change it after the refactor.", []),
                           ("Don't touch billing.py for now. Feel free to change it.", []),
                           ("Don't touch billing.py. If tests fail, fix them.", []),
                           # delta review D-L5
                           ("settings.py is frozen in production, but locally you can edit it.", []),
                           ("Leave settings.py alone in prod, but you're free to edit it locally.", []),
                           ("Don't touch billing.py for now. Later you can update it.", []),
                           ("Don't touch billing.py. Go ahead and fix it, but don't push before I review.",
                            [("no_push", None)])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)

    def test_more_ways_of_keeping_a_file_or_a_directory_away(self):
        """Round-3 review: prohibitions the grammar didn't read (each now held live and found), and "any changes"."""
        edit = lambda p: ("Edit", {"file_path": f"/w/{p}", "old_string": "a", "new_string": "b"})   # noqa: E731
        for text, want, call in (
                ("Leave settings/base.py exactly as it is.", ("keep_away", "base.py"), edit("settings/base.py")),
                ("The LICENSE file must not change.", ("keep_away", "license"), edit("LICENSE")),
                ("Under no circumstances touch sync/engine.py.", ("keep_away", "engine.py"), edit("sync/engine.py")),
                ("Under no circumstances should .github/workflows/release.yml be edited.",
                 ("keep_away", "release.yml"), edit(".github/workflows/release.yml")),
                ("Leave the vendor/ directory untouched.", ("keep_away", "vendor/"), edit("vendor/lib/x.go")),
                ("Stay out of the infra/ folder.", ("keep_away", "infra/"), edit("infra/main.tf")),
                ("Keep your changes out of db/migrations/.", ("keep_away", "migrations/"),
                 edit("db/migrations/0004.sql")),
                ("Don't modify the vendor directory.", ("keep_away", "vendor/"), edit("vendor/x.py")),
                ("Don't make any changes, only review cache.go.", ("read_only", None), edit("cache.go")),
                # delta review D-L7: a folder whose name has a dot, an underscore or a hyphen
                ("Don't touch the .github folder.", ("keep_away", ".github/"), edit(".github/workflows/ci.yml")),
                ("Don't touch the node_modules folder.", ("keep_away", "node_modules/"),
                 edit("node_modules/left-pad/index.js"))):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), [want])
                self.assertEqual(replay_one(f"Fix the off-by-one in src/pager.py. {text}", *call), (True, "high"))
        self.assertEqual(constraints.extract("Change the output directory to dist."), [])

    def test_any_changes_to_a_named_thing_is_not_read_only(self):
        """1.4.0 review M1: "don't make any changes to the tests" read as read_only, so the edit the person asked for
        was held and found. "Any changes" is read-only only with no object after it."""
        for said in ("Don't make any changes to the tests.", "Don't make any changes to the public API.",
                     "Don't make any edits in the database schema.",
                     # delta review D-M1: what picks the changes out
                     "Don't make any changes that break the public API.",
                     "Don't make any changes on main; work on a new branch.",
                     "Don't make any changes directly on main.", "Don't make any changes beyond what the fix needs.",
                     "Don't make any changes which would slow down the parser.",
                     "Don't make any changes for the sake of style.", "Don't make any edits that touch the schema.",
                     # delta review D-L7: a scope, not src/ kept away
                     "Don't make any changes outside src/.", "Don't touch anything outside src/.",
                     # final review M1: "machine", "own", "computer" only in "on your own", "on this machine"
                     "Don't make any changes to the machine learning pipeline.",
                     "Don't make any changes in my own module.", "Don't make any changes in the computer vision module.",
                     "Don't make any changes to your own tests."):
            with self.subTest(said):
                self.assertEqual(constraints.extract(f"Fix the bug in src/pager.py. {said}"), [])
                self.assertEqual(replay_one(f"Fix the bug in src/pager.py. {said}", "Edit", {
                    "file_path": "/w/src/pager.py", "old_string": "a", "new_string": "b"}), (False, None))
        self.assertEqual(constraints.extract("Investigate the crash. Don't make any changes."), [("read_only", None)])
        self.assertEqual(constraints.extract("Don't make any changes " + "directly " * 1200 + "please."),
                         [("read_only", None)])   # final review L2: no recursion per word
        for said in ("Don't make any changes of any kind.", "Don't make any changes in the meantime.",
                     "Don't make any changes under any circumstances.", "Don't make any edits to any file.",
                     "Don't make any changes for now.", "Don't make any changes for the time being.",
                     # delta review N-M1: "directly", "for", "on" that say how or for whom, not which changes
                     "Don't make any changes directly; propose a diff instead.",
                     "Don't make any changes for any reason.", "Don't make any changes on your own.",
                     "Don't make any changes for me, just explain.", "Don't make any changes on this machine.",
                     # delta review D-M2: the whole project
                     "Don't make any changes to the code.", "Don't make any changes to the codebase.",
                     "Don't make any changes to the repo.", "Don't make any changes in this repository.",
                     "Don't make any changes to the project.", "Don't make any changes to the files.",
                     "Don't make any changes to my project.", "Don't make any changes in the workspace.",
                     "Don't make any changes on disk."):
            with self.subTest(said):   # how many, when, or the whole project: still read-only
                self.assertEqual(constraints.extract(f"Investigate the crash. {said}"), [("read_only", None)])
        self.assertEqual(replay_one("Investigate the crash in src/pager.py. Don't make any changes to the code.",
                                    "Edit", {"file_path": "/w/src/pager.py", "old_string": "a", "new_string": "b"}),
                         (True, "high"))

    def test_keeping_something_else_out_of_a_file_keeps_nothing_away(self):
        """1.4.0 review M2: "keep the API key out of settings.py" kept settings.py away, so the edit the person asked
        for was held and found. Only the agent's changes kept out of X keep X away."""
        for said, path in (("Keep the API key out of settings.py and read it from the environment.", "settings.py"),
                           ("Keep hardcoded credentials out of config.py.", "config.py"),
                           ("Keep debug prints out of main.py.", "main.py"),
                           ("Here is the new key. Keep this out of settings.py.", "settings.py")):
            with self.subTest(said):
                self.assertEqual(constraints.extract(said), [])
                self.assertEqual(replay_one(said, "Edit", {"file_path": f"/w/{path}", "old_string": "a",
                                                           "new_string": "b"}), (False, None))
        for said in ("Keep your hands out of billing.py.", "Keep any edits out of billing.py.",
                     # delta review D-L1
                     "Keep all changes out of billing.py.", "Keep all your changes out of billing.py.",
                     "Keep your own changes out of billing.py.", "Keep your code changes out of billing.py."):
            with self.subTest(said):
                self.assertEqual(constraints.extract(said), [("keep_away", "billing.py")])

    def test_a_place_before_a_folder_word_is_no_folder(self):
        """1.4.0 review L1: "don't touch the home directory" kept home/ away, so with the project under /home every
        write was held. A place ("home", "root", "current", "working", "parent") names no folder."""
        for text in ("Don't touch the home directory.", "Never write to the root directory.",
                     "Don't change the working directory in run.sh.", "Leave the current folder alone."):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), [])

    def test_a_folder_word_keeps_the_clauses_files_in_order(self):
        """1.4.0 review H3: a "<word> folder" was read after the clause's files, so a file after it lost its bound and
        its constraint: mentioning a folder cancelled an unrelated file's constraint."""
        for text, want in (("Use the tmp folder for scratch files and leave config.yaml as is.",
                            [("keep_away", "config.yaml")]),
                           ("Leave the vendor folder and config.yaml untouched.", [("keep_away", "config.yaml")]),
                           ("Don't touch the vendor folder or config.yaml.",
                            [("keep_away", "vendor/"), ("keep_away", "config.yaml")])):
            with self.subTest(text):
                self.assertEqual(constraints.extract(text), want)
                self.assertEqual(replay_one(f"Fix the off-by-one in src/pager.py. {text}", "Edit", {
                    "file_path": "/w/config.yaml", "old_string": "a", "new_string": "b"}), (True, "high"))

    def test_e20s_honest_sessions_hold_no_call_and_break_no_constraint(self):
        """E20's honest Claude Code sessions (HONEST_SESSIONS), replayed through the hook into a signer: no call is
        held live and no TK-X204 finding."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        signer = Signer(os.path.join(d, "data"))
        self.addCleanup(signer.close)
        out = score_honest(signer)
        self.assertEqual((out["held"], [k for k in out["findings"] if k.startswith("TK-X204")]), (0, []), out)

    def test_a_directory_kept_away_breaks_on_a_write_under_it_never_on_a_scope(self):
        f = constraints.facts("Edit", {"file_path": "/w/src/legacy/old.py"})
        self.assertEqual(constraints.breaks("keep_away", f, "legacy/".__eq__), "legacy/")
        self.assertIsNone(constraints.breaks("only_change", f, "old.py".__eq__))   # its directories are no file
        self.assertEqual(constraints.facts("Bash", {"command": "echo x > src/legacy/a.py"})["names"],
                         ["a.py", "src/", "legacy/"])
        self.assertEqual(constraints.breaks("keep_away", constraints.facts("Bash", {"command": "rm -r src/legacy"}),
                                            "legacy/".__eq__), "legacy/")   # the directory itself

    def test_a_scope_is_checked_after_the_run_and_never_held_live(self):
        """"Only change X" holds no call (every test or lockfile write would ask the person): TK-X204 reads it after."""
        text = "Only change src/pager.py and don't touch billing.py."
        self.assertEqual(constraints.extract(text), [("only_change", "pager.py"), ("keep_away", "billing.py")])
        self.assertEqual(claude_code._live(text), [("keep_away", "billing.py")])
        sent = []
        claude_code.prompted(mock.Mock(call=lambda m, **kw: sent.append(kw["constraint"]) or {"run_seq": 1}), text)
        self.assertEqual(sent, [{"kind": "keep_away", "object": "billing.py"}])

    def test_a_64_kib_prompt_is_read_in_bounded_time(self):
        n = 1 << 16
        for unit in ("don't ", "leave ", "hands off ", "only ", "it ", '"', "`", "```", "nothing else ", "? ",
                     "a.py is not to be ", "x.py ", "no changes to ", "everything else ", "as is ", "make no changes "
                     "there. ", "don't touch a.py until ", "stay away from ", "is the only ", " "):
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
        self.assertEqual(bash("sed -i 's/a/b/' src/Billing.py && cat pager.py")["names"], ["billing.py", "src/"])
        self.assertEqual(bash("echo x > billing.py")["names"], ["billing.py"])
        self.assertEqual(bash("cp billing.py /tmp/b")["names"], ["b", "tmp/"])   # read, not written
        self.assertEqual(bash("cat billing.py")["write"], False)
        self.assertTrue(bash("git push origin main")["push"] and bash("git push origin main")["network"])
        self.assertTrue(bash("sudo pip install leftpad")["network"])
        self.assertEqual(constraints.facts("Edit", {"file_path": "/w/billing.py"})["names"], ["billing.py", "w/"])
        self.assertEqual(constraints.facts("Read", {"file_path": "/w/billing.py"}, "fs")["write"], False)
        self.assertTrue(constraints.facts("WebFetch", {"url": "https://example.org"})["network"])
        self.assertTrue(constraints.facts("fetch_page", {"url": "https://example.org"}, "http")["network"])

    def test_git_dd_patch_rsync_find_and_formatters_write_their_files(self):
        """Round-2 review: ordinary commands that write a file the constraint names, each held (keep_away)."""
        for cmd in ("git rm billing.py", "git checkout -- billing.py", "git -C src restore billing.py",
                    "git mv billing.py old.py", "dd if=/tmp/x of=billing.py", "patch billing.py < fix.diff",
                    "rsync /tmp/x billing.py", "scp host:x billing.py", "find . -name billing.py -delete",
                    "find . -name billing.py -exec rm {} \\;", "npx prettier --write billing.py", "black billing.py",
                    "ruff format billing.py", "ruff check --fix billing.py", "gofmt -w billing.py", "shred billing.py"):
            with self.subTest(cmd):
                f = constraints.facts("Bash", {"command": cmd})
                self.assertTrue(f["write"])
                self.assertEqual(f["names"][0], "billing.py")
        self.assertEqual(constraints.facts("Bash", {"command": "git checkout -b fix"})["names"], [])   # a branch
        self.assertTrue(constraints.facts("Bash", {"command": "patch -p1 < fix.diff"})["write"])   # files unnamed

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
        self.assertEqual(constraints.facts(tool, ti, "fs")["names"], ["config.py", "new.md", "src/", "docs/"])
        self.assertEqual(constraints.facts(tool, ti)["names"], ["config.py", "new.md", "src/", "docs/"])   # analysis

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

        def read(text):
            r = constraints._read(text)
            constraints.extract(None, r)
            constraints.mentions(None, r)
            constraints.changes(r)
        files = lambda n, sep=" ": sep.join(f"a{k}.py" for k in range(n))   # noqa: E731
        for label, text, n in (   # each file looked only at the next, not at every other
                ("a clause naming files", lambda n: "Don't touch " + files(n, " or "), 1350),
                ("files after except", lambda n: "Don't change anything except " + files(n), 1800),
                ("an except clause each", lambda n: "Don't change anything, except " + files(n, ", except "), 950),
                # 1.4.0 review L2: each "it" read the clause before again
                ("change it", lambda n: "Don't touch " + "a.py " * (2 * n) + ". " + "change it, " * n, 700),
                ("don't change it", lambda n: "Don't touch " + "a.py " * (2 * n) + ". " + "don't change it, " * n,
                 550),
                # delta review D-L4: changes() read a "them" no change word governs once per file
                ("keep them", lambda n: "Leave " + "a.py " * (2 * n) + "alone. " + "keep them, " * n, 750),
                ("keep them, each file once", lambda n: f"Leave {files(n)} alone. " + "keep them, " * n, 750)):
            with self.subTest(label):   # linear: 4n takes 4 times as long as n, quadratic 16; in CPU time, which
                best = [min(timeit.repeat(lambda: read(t), timer=time.process_time, number=3, repeat=3))   # load
                        for t in (text(n), text(4 * n))]   # on the machine doesn't change; the best of three
                self.assertLess(best[1], 8 * best[0], best)
        for text in ("Don't touch " + files(1400, " or "), "Don't change anything except " + files(1400),
                     "Don't change anything, except " + files(1400, ", except ")):
            self.assertEqual(len(constraints.extract(text)), 1400)   # each file read


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

    def test_a_held_call_is_told_the_constraint_not_a_flags_label(self):
        """A flag beside the hold (TK-F004 on a push, TK-F012 on a URL) lets a call run: its label is no reason the
        call was held, so the agent and the person read only what the person said."""
        run = self.run_()
        self.add(run, "no_push")
        self.add(run, "no_network")
        for kind, command, flag in (("no_push", "git push origin main", "TK-F004"),
                                    ("no_network", "curl https://example.org", "TK-F012")):
            with self.subTest(kind):
                held = self.decide(run, "Bash", {"command": command})
                self.assertIn(flag, held["rule_ids"])
                self.assertEqual(held["reason"], constraints.held(kind, None))

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

    def test_past_the_cap_a_file_constraint_is_a_signed_gap_and_every_write_is_held(self):
        """Any client of the run may add a constraint, so the agent can add made-up ones first: they never leave the
        person's later one unheld. A kind that names no file is always added; past MAX_CONSTRAINTS file constraints a
        further one is a signed gap the hook is told of (`refused`), and every write is held from then on, also after
        a restart."""
        run = self.run_()
        for i in range(svc.MAX_CONSTRAINTS):
            self.add(run, "keep_away", f"f{i}.py")
        self.assertNotIn("refused", self.add(run, "no_push"))
        push = self.decide(run, "Bash", {"command": "git push origin main"})
        self.assertEqual((push["decision"], push["rule_ids"][-1]), ("ask", "TK-CONSTRAINT"))
        other = {"file_path": "/w/other.py", "old_string": "a", "new_string": "b"}
        self.assertEqual(self.decide(run, "Edit", other)["decision"], "allow")
        out = self.add(run, "keep_away", "billing.py")
        self.assertTrue(out["refused"])
        gap = next(e for e in self.records(run) if e["run_seq"] == out["run_seq"])
        self.assertEqual((gap["type"], gap["source"], gap["data"]["kind"]), ("capture.gap", "signer",
                                                                              "constraint_refused"))
        self.assertIn("a further keep_away constraint was not added", gap["data"]["reason"])
        for args in ({"file_path": "/w/billing.py", "old_string": "a", "new_string": "b"}, other):
            held = self.decide(run, "Edit", args)
            self.assertEqual((held["decision"], held["rule_ids"]), ("ask", ["TK-CONSTRAINT"]))
            self.assertIn("so every write is held", held["reason"])
        self.assertEqual(self.decide(run, "Read", {"file_path": "/w/billing.py"})["decision"], "allow")
        self.assertEqual(self.add(run, "keep_away", "f3.py")["run_seq"], 4)   # an equal one is still the one it has
        self.s.close()
        self.s = svc.SignerService(os.path.join(self.dir, "data"), grace_s=0, fsck_every_s=0)
        self.addCleanup(self.s.close)
        self.assertEqual(self.decide(run, "Write", {"file_path": "/w/x.py", "content": "x"})["decision"], "ask")
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
