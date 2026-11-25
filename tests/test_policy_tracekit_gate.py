"""The gate in front of the `tracekit` field (engine.TracekitGate): a call that can't touch Tracekit's files, signer or
approvals isn't read for TK-D007 at all, and what the field gives is read once each, not again in the other case."""
import glob
import json
import os
import re
import unittest
from unittest import mock

from tracekit.policy2 import classes, compile as pc, engine as engine_module, shell
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc

PACKS = os.path.dirname(svc.DEFAULT_POLICY)
DATA = os.path.join(os.path.dirname(__file__), "data", "policy")


def parse(engine, command):
    return engine._parse(classes.with_workdir({"command": command}), command, [0])[0]


class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine(pc.build(os.path.join(PACKS, "dev.yaml"))[0])
        cls.gate = cls.engine._tracekit_gate
        rule = next(r for sec in engine_module.SECTIONS for r in cls.engine.policy.get(sec, []) if r["id"] == "TK-D007")
        cls.pattern = re.compile(rule["pattern"], re.I)

    def touches(self, command):
        return self.gate.touches(parse(self.engine, command), [0])

    def test_ordinary_commands_touch_nothing(self):
        for command in ("ls -la", "npm test", "kubectl get pods -n prod", "git log --oneline -5 -- src/a.py",
                        "curl -s https://example.com/api -o out.json", "rm -rf build dist", "python3 -m pytest -x tests",
                        "psql -h db -c 'SELECT * FROM users'", "find src -name '*.py' -delete"):
            with self.subTest(command):
                self.assertFalse(self.touches(command))

    def test_what_names_tracekits_places_touches(self):
        for command in ("rm ~/.local/share/tracekit/ledger", "cat /etc/tracekit/client.json", "ls /tmp/tk-501/sock",
                        "pkill -f signer", "python -m tracekit.signer", "systemctl stop tracekit",
                        "rm -rf ~/Library/Application Support/tracekit", "cd ~/.local/share && rm -r tracekit",
                        "ln -sf x ~/.local/bin/tracekit", "python3 -c 'import autospawn'", "rm -rf ~/.TraceKit-Signer",
                        "chmod -R 777 /var/lib/tracekit", "echo x > $XDG_RUNTIME_DIR/tracekit/sock"):
            with self.subTest(command):
                self.assertTrue(self.touches(command))

    def test_a_name_a_pattern_or_an_effect_makes_touches(self):
        # a pattern under ~ (or after a bare cd) may stand for Tracekit's folder; HOME moves what ~ is; a delete of a home takes
        # the roots below it, which the line doesn't name
        for command in ("rm -rf ~/.local/share/trace?it", "cd; rm -rf Library/Application\\ Support/tr*", "HOME=/x; rm -rf ~/y",
                        "find ~ -delete"):
            with self.subTest(command):
                self.assertTrue(self.touches(command))

    def test_a_casefolded_or_wide_spelling_touches(self):
        for command in ("rm ~/.LOCAL/SHARE/TRACEKIT/x", "rm ~/.local/share/ｔracekit/x"):
            with self.subTest(command):
                self.assertTrue(self.touches(command))

    def test_a_call_the_gate_rules_out_is_not_read(self):
        with mock.patch.object(engine_module, "_tracekit", wraps=engine_module._tracekit) as read:
            self.engine.decide("Bash", {"command": "npm test"})
            read.assert_not_called()
            self.engine.decide("Bash", {"command": "rm ~/.local/share/tracekit/x"})
            read.assert_called_once()

    def test_the_decision_is_the_same_without_the_gate(self):
        plain = Engine(self.engine.policy)
        plain._tracekit_gate = None
        for command in ("ls", "rm ~/.local/share/tracekit/x", "find ~ -delete", "rm -rf ~/.Local/Share/TraceKit",
                        "cd ~/.local/share; rm -rf tracekit", "python3 -c 'import autospawn; autospawn.stop()'",
                        "pkill -f 'python -m tracekit.signer'", "cat /etc/tracekit/policy.yaml"):
            with self.subTest(command):
                self.assertEqual(self.engine.decide("Bash", {"command": command}),
                                 plain.decide("Bash", {"command": command}))

    def test_a_call_it_rules_out_gives_no_subject_a_rule_matches(self):
        """On every shell call of the policy corpus: where the gate says nothing is touched, the reader's subjects match no
        pattern of the rule."""
        seen = ruled_out = 0
        for path in sorted(glob.glob(os.path.join(DATA, "*", "*.jsonl"))):
            for line in open(path, encoding="utf-8"):
                call = json.loads(line)
                command = call["args"].get("command") if isinstance(call["args"], dict) else None
                if call["tool"] != "Bash" or not isinstance(command, str):
                    continue
                try:
                    parsed = parse(self.engine, command)
                except Exception:   # noqa: BLE001 (a line the parser refuses: the engine holds it before any rule)
                    continue
                seen += 1
                if not self.gate.touches(parsed, [0]):
                    ruled_out += 1
                    subjects = engine_module._tracekit(parsed, lambda *a: True, [0])
                    self.assertFalse([s for s in subjects if self.pattern.search(s)], command)
        self.assertGreater(seen, 500)
        self.assertGreater(ruled_out, seen // 2)

    def test_a_rule_that_is_not_a_set_of_strings_reads_every_call(self):
        rule = {"id": "X", "pattern": r"^ACT:[\w\W]*", "field": "tracekit"}
        self.assertIsNone(engine_module.TracekitGate.of([("deny", rule)]))

    def test_every_string_a_sdk_match_holds_is_a_prefilter_string(self):
        for text in ("import autospawn", "x = dev_data_dir()", "from t import data_dir_at", "runpy.run_module('t')",
                     "python -m t.__main__", "run_label_clear", "record_hooks_settings(1)", "record_hook_python",
                     "import tracekit.cli", "import cli", "import install", "tracekit.install", "walk_packages(p)",
                     "iter_modules(p)", "run_path(p)", "mod = '.install'", 'mod = ".cli"', "tracekit.x + '+' 'y'",
                     "tracekit.x'+'y'", "run_label_x"):
            if engine_module._SDK.search(text):
                with self.subTest(text):
                    self.assertTrue(any(lit in text for lit in engine_module._SDK_LITS), text)


class Subjects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine(pc.build(os.path.join(PACKS, "dev.yaml"))[0])

    def subjects(self, command):
        return engine_module._tracekit(parse(self.engine, command), lambda *a: True, [0])

    def test_an_ascii_subject_is_given_once_whatever_its_case(self):
        out = self.subjects("rm -rf ~")
        for tag in ("ACT:", "TARGET:"):
            mine = [s.lower() for s in out if s.startswith(tag)]
            self.assertEqual(len(mine), len(set(mine)), out)
        self.assertLess(len(out), 22)

    def test_a_subject_that_is_not_ascii_is_also_casefolded(self):
        out = self.subjects("rm ~/Ü/Tracekit")
        self.assertIn("ACT:rm ~/ü/tracekit", out)

    def test_a_name_without_a_pattern_is_not_read_as_one(self):
        with mock.patch.object(engine_module, "_pattern_forms", wraps=engine_module._pattern_forms) as forms:
            self.subjects("cd ~/work; rm -f a.txt b.txt")
            forms.assert_not_called()
            self.subjects("cd ~/work; rm -f a*.txt")
            forms.assert_called()

    def test_the_rule_still_denies_a_spelling_in_another_case(self):
        for command in ("rm -rf ~/.LOCAL/Share/TraceKit", "rm ~/.local/bin/TRACEKIT"):
            with self.subTest(command):
                self.assertIn("TK-D007", self.engine.decide("Bash", {"command": command})["rule_ids"])


class Once(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine(pc.build(os.path.join(PACKS, "dev.yaml"))[0])

    def test_pushes_are_read_once_for_a_line_both_fields_read_alike(self):
        with mock.patch.object(engine_module, "_pushes", wraps=engine_module._pushes) as read:
            self.engine.decide("Bash", {"command": "gh api -X DELETE repos/o/r/secrets/X"})
            self.assertEqual(read.call_count, 1)

    def test_the_push_settings_are_read_once_a_line(self):
        with mock.patch.object(engine_module, "_push_config_env", wraps=engine_module._push_config_env) as read:
            self.engine.decide("Bash", {"command": "git push origin feature"})
            self.assertEqual(read.call_count, 1)

    def test_the_two_fields_still_read_a_line_that_only_some_commands_of_it_are_push_programs(self):
        d = self.engine.decide("Bash", {"command": "cd x && git push --force origin main"})
        self.assertNotEqual(d["verdict"], "allow")

    def test_a_listed_read_only_program_is_skipped_and_none_writes(self):
        for name in ("get-content", "get-childitem", "get-item", "get-itemproperty", "select-string", "test-path",
                     "resolve-path", "get-location", "get-process", "get-date", "get-command", "measure-object"):
            with self.subTest(name):
                self.assertIn(name, engine_module._INERT_PROGRAMS)
                parsed = shell.analyse(f"{name} data.txt", work=[0])
                self.assertTrue(engine_module._writes_nothing(parsed))
                full = engine_module._write_effects(parsed, [0])
                self.assertEqual([t for t in full if not t.startswith("NAMED_TARGET:")], [])

    def test_no_listed_program_is_a_writer_the_reader_knows(self):
        for name in engine_module._INERT_PROGRAMS:
            with self.subTest(name):
                self.assertNotIn(name, engine_module._WRITER_WORDS)


if __name__ == "__main__":
    unittest.main()
