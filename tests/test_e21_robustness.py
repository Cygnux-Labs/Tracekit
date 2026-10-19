"""The standalone rewrite robustness measure for E21."""

import importlib.util
import json
import os
import shlex
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("e21_robustness", os.path.join(ROOT, "eval", "e21_robustness.py"))
e21 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e21)


class Rewrites(unittest.TestCase):
    def test_transformations_preserve_command_argument_exactly(self):
        command = "git push origin 'feature branch' && printf '%s\\n' \"ok\""
        self.assertEqual(set(e21.rewrites(command)), set(e21.TRANSFORMATIONS) - {"command-prefix"})
        for form, rewritten in e21.rewrites(command).items():
            with self.subTest(form=form):
                if form == "bash-c":
                    self.assertEqual(shlex.split(rewritten)[-1], command)
                elif form == "env-bash-c":
                    self.assertEqual(shlex.split(rewritten)[-1], command)
                elif form == "cd-dot-and":
                    self.assertTrue(rewritten.startswith("cd . && "))
                    self.assertEqual(rewritten[len("cd . && "):], command)
                elif form == "true-semi":
                    self.assertTrue(rewritten.startswith("true; "))
                    self.assertEqual(rewritten[len("true; "):], command)
                else:
                    self.assertEqual(rewritten, f"command {command}")
                self.assertTrue(e21.TRANSFORMATIONS[form])
        self.assertEqual(e21.rewrites("git push origin feature")["command-prefix"],
                         "command git push origin feature")

    def test_state_changing_commands_keep_same_shell_rewrites_only(self):
        for command in ("history -c", "unset HISTFILE", "cd /tmp"):
            with self.subTest(command=command):
                self.assertIsNotNone(e21.stateful_reason(command))
                self.assertNotIn("bash-c", e21.rewrites(command))
                self.assertNotIn("env-bash-c", e21.rewrites(command))
                self.assertIn("cd-dot-and", e21.rewrites(command))
                self.assertIn("true-semi", e21.rewrites(command))

    def test_shell_analysis_uses_the_command_list_from_the_four_value_result(self):
        for command in ("sudo id", "cd . && sudo id", "true; sudo id"):
            with self.subTest(command=command):
                self.assertTrue(e21.shell.analyse(command)[0])

    def test_stateful_builtins_are_counted_for_same_shell_rewrites(self):
        class Engine:
            def decide(self, tool, args):
                return {"verdict": "ask", "rule_ids": ["TK-A001"]}

        case = {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "history -c"}, "expect": "ask"}
        measured = e21.measure([case], (Engine(), Engine()), {"deny": [], "ask": [{"id": "TK-A001"}]})
        self.assertEqual(measured["by_form"]["cd-dot-and"]["contained"], 1)
        self.assertEqual(measured["by_form"]["true-semi"]["contained"], 1)
        self.assertEqual(measured["by_form"]["command-prefix"]["contained"], 1)
        self.assertEqual(measured["by_form"]["bash-c"]["total"], 0)
        self.assertEqual(measured["by_form"]["env-bash-c"]["total"], 0)
        self.assertEqual(measured["excluded_rewrites"][0]["forms"], ["bash-c", "env-bash-c"])

    def test_missing_baseline_requires_an_explicit_rebaseline(self):
        class Engine:
            def __init__(self, policy, engine):
                self.engine = engine

            def decide(self, tool, args):
                return {"verdict": "deny", "rule_ids": ["TK-D001"]}

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(e21.pc, "build", return_value=({"deny": [{"id": "TK-D001"}], "ask": []}, [])), \
                    mock.patch.object(e21, "Engine", Engine), \
                    mock.patch.object(e21, "load_cases", return_value=[
                        {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]), \
                    mock.patch.object(e21, "RESULTS", os.path.join(temp_dir, "results.json")):
                with self.assertRaisesRegex(ValueError, "--rebaseline"):
                    e21.run()

    def test_missing_re2_has_an_explicit_requirement_message(self):
        with mock.patch.object(e21.pc, "build", return_value=({"deny": [], "ask": []}, [])), \
                mock.patch.object(e21, "Engine", side_effect=ImportError("missing")):
            with self.assertRaisesRegex(RuntimeError, "requires google-re2"):
                e21.run()

    def test_reports_per_rule_containment_and_parser_hold_as_contained(self):
        class Engine:
            def __init__(self, policy, engine):
                self.engine = engine

            def decide(self, tool, args):
                command = args["command"]
                if command == "sudo id" or command.endswith("sudo id") and not "bash -c" in command:
                    return {"verdict": "deny", "rule_ids": ["TK-D001"]}
                if "bash -c" in command:
                    return {"verdict": "ask", "rule_ids": ["TK-SHELL-PARSE"]}
                return {"verdict": "allow", "rule_ids": []}

        cases = [{"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]
        measured = e21.measure(cases, (Engine({}, "re2"), Engine({}, "regex")),
                               {"deny": [{"id": "TK-D001"}], "ask": []})
        self.assertEqual(measured["per_rule"]["bash-c"]["TK-D001"]["rate"], 1.0)
        self.assertEqual(measured["per_rule"]["bash-c"]["TK-D001"]["same_rule_rate"], 0.0)
        self.assertEqual(measured["per_rule"]["bash-c"]["TK-D001"]["coverage_rate"], 1.0)
        self.assertEqual(measured["by_form"]["bash-c"]["missed"], 0)
        self.assertEqual(measured["by_form"]["env-bash-c"]["missed"], 0)

    def test_source_regression_fails_measurement(self):
        class Engine:
            def __init__(self, policy, engine):
                pass

            def decide(self, tool, args):
                return {"verdict": "allow", "rule_ids": []}

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(e21.pc, "build", return_value=({"deny": [{"id": "TK-D001"}], "ask": []}, [])), \
                    mock.patch.object(e21, "Engine", Engine), \
                    mock.patch.object(e21, "load_cases", return_value=[
                        {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]), \
                    mock.patch.object(e21, "RESULTS", os.path.join(temp_dir, "results.json")):
                    result = e21.run(rebaseline=True)
        self.assertFalse(result["no_regression"]["source_matches_expected"])
        self.assertFalse(result["ok"])

    def test_a_rewrite_miss_fails_the_gate_even_with_a_fresh_baseline(self):
        class Engine:
            def __init__(self, policy, engine):
                self.engine = engine

            def decide(self, tool, args):
                command = args["command"]
                if command == "sudo id":
                    return {"verdict": "deny", "rule_ids": ["TK-D001"]}
                return {"verdict": "allow", "rule_ids": []}

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(e21.pc, "build", return_value=({"deny": [{"id": "TK-D001"}], "ask": []}, [])), \
                    mock.patch.object(e21, "Engine", Engine), \
                    mock.patch.object(e21, "load_cases", return_value=[
                        {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]), \
                    mock.patch.object(e21, "RESULTS", os.path.join(temp_dir, "results.json")):
                result = e21.run(rebaseline=True)
        self.assertGreater(len(result["rewrite_missed"]), 0)
        self.assertGreater(len(result["rule_missed"]), 0)
        self.assertFalse(result["no_regression"]["rewrites_contained"])
        self.assertFalse(result["ok"])
        self.assertIn("policy_hash", result)
        self.assertEqual(len(result["engines"]), 2)

    def test_rewrite_coverage_regression_fails_against_saved_first_run(self):
        class Engine:
            def __init__(self, policy, engine):
                pass

            def decide(self, tool, args):
                command = args["command"]
                if command == "sudo id":
                    return {"verdict": "deny", "rule_ids": ["TK-D001"]}
                return {"verdict": "allow", "rule_ids": []}

        policy = {"deny": [{"id": "TK-D001"}], "ask": []}
        baseline = {"policy_hash": "earlier-policy-hash", "per_rule": {form: {"TK-D001": {"total": 1, "contained": 1, "missed": 0,
                                                     "rate": 1.0, "same_rule": 1, "same_rule_rate": 1.0,
                                                     "covered_by_rule_or_parse": 1, "coverage_rate": 1.0}}
                                 for form in e21.TRANSFORMATIONS}}
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = os.path.join(temp_dir, "results.json")
            with open(result_path, "w", encoding="utf-8") as stream:
                json.dump({"baseline": baseline}, stream)
            with mock.patch.object(e21.pc, "build", return_value=(policy, [])), \
                    mock.patch.object(e21, "Engine", Engine), \
                    mock.patch.object(e21, "load_cases", return_value=[
                        {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]), \
                    mock.patch.object(e21, "RESULTS", result_path):
                result = e21.run()
        self.assertFalse(result["no_regression"]["rewrite_coverage_not_below_baseline"])
        self.assertGreater(len(result["rule_missed"]), 0)
        self.assertEqual({item["metric"] for item in result["regressions"]},
                         {"contained_rate", "rule_coverage_rate", "same_rule_rate"})
        self.assertFalse(result["ok"])

    def test_removing_a_baseline_rule_is_a_regression_even_if_another_rule_holds(self):
        class Engine:
            def __init__(self, policy, engine):
                pass

            def decide(self, tool, args):
                return {"verdict": "deny", "rule_ids": ["TK-D002"]}

        policy = {"deny": [{"id": "TK-D001"}, {"id": "TK-D002"}], "ask": []}
        baseline = {"policy_hash": e21.pc.policy_hash(policy), "per_rule": {form: {"TK-D001": {"total": 1, "contained": 1, "missed": 0,
                                                     "rate": 1.0, "same_rule": 1, "same_rule_rate": 1.0,
                                                     "covered_by_rule_or_parse": 1, "coverage_rate": 1.0}}
                                 for form in e21.TRANSFORMATIONS}}
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = os.path.join(temp_dir, "results.json")
            with open(result_path, "w", encoding="utf-8") as stream:
                json.dump({"baseline": baseline}, stream)
            with mock.patch.object(e21.pc, "build", return_value=(policy, [])), \
                    mock.patch.object(e21, "Engine", Engine), \
                    mock.patch.object(e21, "load_cases", return_value=[
                        {"source": "shell.jsonl:1", "tool": "Bash", "args": {"command": "sudo id"}, "expect": "deny"}]), \
                    mock.patch.object(e21, "RESULTS", result_path):
                result = e21.run()
        self.assertTrue(result["no_regression"]["source_matches_expected"])
        self.assertEqual({item["metric"] for item in result["regressions"]}, {"rule_missing"})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
