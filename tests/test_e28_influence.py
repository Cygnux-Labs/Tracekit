"""E28 (eval/e28_influence.py): its gate fails each promise docs/evaluation.md makes, and the AgentDojo runs it keeps in
eval/e28_agentdojo/ are the ones its committed results were made from.

    python3 -m pytest tests/test_e28_influence.py -q
"""
import copy
import importlib.util
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("e28_influence", os.path.join(ROOT, "eval", "e28_influence.py"))
e28 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e28)


def result():
    with open(os.path.join(ROOT, "eval", "results", "e28_influence.json"), encoding="utf-8") as f:
        return json.load(f)


class Gate(unittest.TestCase):
    def test_the_committed_result_keeps_every_promise(self):
        self.assertEqual(e28.broken(result()), [])

    def test_each_broken_promise_fails_the_eval(self):
        cases = [(("agentdojo", "exact_claims", "digits", "value_in_source"), -1,
                  "agentdojo: an exact claim names a record without its value"),
                 (("agentdojo", "grades", "exact", "fp"), 1, "agentdojo: exact edges from a source labelled no cause"),
                 (("desk", "grades", "measured", "fp"), 1, "desk: measured edges from a source labelled no cause"),
                 (("without_task", "asked_drift"), 1, "without_task: an asked call serves no step of the task")]
        for path, delta, said in cases:
            with self.subTest(said=said):
                r = copy.deepcopy(result())
                at = r
                for k in path[:-1]:
                    at = at[k]
                at[path[-1]] += delta
                self.assertEqual(e28.broken(r), [said])


class Data(unittest.TestCase):
    def test_the_kept_runs_are_the_ones_the_results_count(self):
        with open(os.path.join(e28.DATA, "ground_truth.json"), encoding="utf-8") as f:
            gt = json.load(f)
        with open(os.path.join(e28.DATA, "traces.jsonl"), encoding="utf-8") as f:
            traces = [json.loads(line) for line in f]
        r = result()["agentdojo"]
        attacks = [t for t in traces if t["attack_type"] not in (None, "none")]
        self.assertEqual((len(attacks), len(traces) - len(attacks), gt["source"]["attacked"]),
                         (r["runs"]["succeeded"], r["runs"]["clean"], r["runs"]["attacked"]))
        self.assertTrue(all(t["security"] for t in attacks))
        self.assertEqual(gt["source"]["commit"], r["agentdojo_commit"])
        self.assertEqual({t["suite_name"] + "/" + t["injection_task_id"] for t in attacks}, set(gt["tasks"]))
        self.assertTrue(os.path.exists(os.path.join(e28.DATA, "AGENTDOJO-LICENSE")))


if __name__ == "__main__":
    unittest.main()
