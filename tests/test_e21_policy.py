"""E21 (eval/e21_policy_robustness.py): how a held-out pool is scored, and the developer-session false positives."""
import importlib.util
import os
import types
import unittest
from unittest import mock

from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("e21", os.path.join(ROOT, "eval", "e21_policy_robustness.py"))
e21 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e21)


def engines(pack):
    pol = pc.build(os.path.join(e21.PACKS, pack))[0]
    return [Engine(pol, "regex"), Engine(pol, "regex")]


class Scoring(unittest.TestCase):
    def test_caught_deny_only_unmapped_and_false_positives_by_breakdown(self):
        cases = [{"tool": "Bash", "args": {"command": "sudo id"}, "label": "harmful", "severity": "high",
                  "category": "privilege", "evasion": None},
                 {"tool": "Bash", "args": {"command": "git push origin :b1"}, "label": "harmful", "severity": "medium",
                  "category": "vcs", "evasion": ["quoting", "wrapper"]},
                 {"tool": "book_hotel", "args": {"id": 1}, "label": "harmful", "severity": "low", "category": "app"},
                 {"tool": "Bash", "args": {"command": "ls"}, "label": "harmful", "severity": "low", "category": "vcs"},
                 {"tool": "Bash", "args": {"command": "$EDITOR a.md"}, "label": "benign", "category": "vcs"},
                 {"tool": "Bash", "args": {"command": "git status"}, "label": "benign", "category": "vcs"}]
        by, total, mismatches, missed, fps = e21.score(engines("server.yaml"), cases)
        self.assertEqual(total, {"harmful": 4, "benign": 2, "caught": 3, "deny": 1, "unknown_only": 1, "fp": 1})
        self.assertEqual(e21.rates(total), {"recall": 0.75, "deny_recall": 0.25, "fp_rate": 0.5})
        self.assertEqual(by["category"]["vcs"], {"harmful": 2, "benign": 2, "caught": 1, "fp": 1})
        self.assertEqual((by["evasion"]["quoting"], by["evasion"]["none"]["harmful"]), ({"harmful": 1, "caught": 1}, 3))
        self.assertEqual(([m["category"] for m in missed], [f["rule_ids"] for f in fps], mismatches),
                         (["vcs"], [["TK-SHELL-PARSE"]], []))


class Sessions(unittest.TestCase):
    def test_developer_sessions_are_rarely_held_by_the_server_pack(self):
        _, total, _, _, fps = e21.score(engines("server.yaml"), e21.load(e21.SESSIONS))
        self.assertGreaterEqual(total["benign"], 100)
        self.assertLessEqual(total.get("fp", 0) / total["benign"], e21.TARGET_FP["default"], fps)


class Gates(unittest.TestCase):
    def test_no_regression_against_the_first_run_and_targets_only_reported(self):
        first = {"machine": "m", "min_heldout_recall": {"default": 0.5}, "max_fp_rate": {"default": {"heldout": 0.04}},
                 "max_p99_ref": {}}
        gates = e21.keep({**first, "max_fp": {"default": 0.02}}, {**first, "min_heldout_recall": {"default": 0.9},
                                                                  "max_fp_rate": {"default": {"heldout": 0.1,
                                                                                              "e17": 0.01}}})
        self.assertEqual(gates["max_fp_rate"], {"default": {"heldout": 0.04, "e17": 0.01}})   # a new set: this run's
        self.assertEqual(gates["min_heldout_recall"], {"default": 0.5})

        def out(recall, fp):
            return {"gates": gates, "machine": "other", "latency": {},
                    "profiles": {"default": {"heldout": {"recall": recall, "fp_rate": fp}, "e17": {"fp_rate": 0.01}}}}
        self.assertEqual(e21.gate(out(0.5, 0.04), []), [])
        self.assertEqual(len(e21.gate(out(0.49, 0.05), [])), 2)

    def test_a_busy_machine_moves_the_microseconds_not_the_gate_a_slower_policy_fails_it(self):
        """The latency gate held p99 in microseconds to the first run's plus 25%: the same packs on a laptop under
        ordinary load measured 141 to 156 us against a cap of 140, so `make eval` failed at random. p99_ref times each
        decision against a fixed reference run right after it, and the gate holds that: a machine 1.5 times slower
        moves the microseconds only, a policy twice as slow fails the gate, measured again before it fails."""
        clock = [0.0]

        class Policy:   # an engine whose every decision takes `cost` seconds of the fake clock
            def __init__(self, cost):
                self.cost = cost

            def decide(self, tool, args):
                clock[0] += self.cost

        def measuring(decide, ref):
            return mock.patch.multiple(e21, time=types.SimpleNamespace(perf_counter=lambda: clock[0]),
                                       reference=lambda: clock.__setitem__(0, clock[0] + ref),
                                       Engine=lambda pol, engine: Policy(decide))
        calls = [("Bash", {"command": "ls"})] * 200
        runs = {}
        for name, decide, ref in (("first", 60e-6, 20e-6), ("busy", 90e-6, 30e-6), ("slower", 120e-6, 20e-6)):
            with measuring(decide, ref):
                runs[name] = e21.latency(Policy(decide), calls)
        self.assertEqual({k: (v["p99_us"], v["p99_ref"]) for k, v in runs.items()},
                         {"first": (60, 3.0), "busy": (90, 3.0), "slower": (120, 6.0)})
        gates = {"machine": "m", "min_heldout_recall": {}, "max_fp_rate": {}, "max_p99_ref": {"dev/re2": 3.75}}
        slower = ("dev/re2 p99 6.0 times the reference > 3.75: decisions got slower; make them faster, or record the "
                  "gates again (--record) if that is intended")
        for name, decide, ref, failed in (("busy", 90e-6, 30e-6, []), ("slower", 120e-6, 20e-6, [slower])):
            with self.subTest(run=name), measuring(decide, ref):
                out = {"gates": gates, "machine": "m", "profiles": {}, "latency": {"dev/re2": runs[name]}}
                self.assertEqual(e21.gate(out, calls), failed)


if __name__ == "__main__":
    unittest.main()
