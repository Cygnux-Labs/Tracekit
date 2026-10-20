"""E20's phrase pools (eval/e20_alignment.py load_pool): schema 1 read as it is, schema 2 mapped by meaning into the
Claude Code sessions E20 replays. Loading and building sessions only: nothing is replayed or scored."""
import json
import os
import random
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import e20_alignment as e20  # noqa: E402


def blocks(lines):
    return [b for _, e in lines if isinstance((e.get("message") or {}).get("content"), list)
            for b in e["message"]["content"]]


class Pools(unittest.TestCase):
    def test_schema_1_is_read_as_it_is(self):
        with open(e20.DEV_POOL, encoding="utf-8") as f:
            self.assertEqual(e20.load_pool(e20.DEV_POOL), (json.load(f), []))

    def test_another_schema_version_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "pool.json")
        with open(path, "w") as f:
            json.dump({"schema_version": 3}, f)
        with self.assertRaisesRegex(SystemExit, "schema version 3"):
            e20.load_pool(path)

    def test_every_pool_v2_item_builds_without_scoring(self):
        pool, unmapped = e20.load_pool(e20.DEV_POOL_V2)
        self.assertEqual({u["key"]: u["n"] for u in unmapped}, {
            "covers.F6": 18, "covers.F7": 18, "covers.{F1-F5}.fault": 5, "failure_outputs[].runner": 10,
            "honest_controls.hard_negatives[].note": 10, "targets[].lang": 12})
        values = {"target": "billing.py", "task_file": "src/pager.py"}
        texts = [*pool["prompts"], *pool["constraints"], *pool["claims"], *pool["reviewer_injections"],
                 *pool["failure_outputs"], *(x for c in pool["covers"].values() for v in c.values() for x in v)]
        for text in texts:
            self.assertIsInstance(text, str)
            self.assertNotRegex(e20.fill(text, **values), r"\{(target|task_file)\}")
        for c in pool["covers"].values():
            self.assertTrue(all(x.startswith("thinking: ") and " | final: " in x for x in c["c2"]))
        rng = random.Random(0)
        for kind, steps in pool["honest_controls"].items():
            for i, step in enumerate(steps):
                with self.subTest(kind=kind, i=i):
                    lines, _, honest = e20.session(pool, rng, i, control=(kind, step))
                    if step["tool"] in ("message", "final"):   # text, no call: the session's own read, edit, tests
                        self.assertEqual(len(honest), 3)
                        said = [b["text"] for b in blocks(lines) if b["type"] == "text"]
                        start = step["args"]["text"].split("{")[0]
                        self.assertTrue(any(s.startswith(start) for s in said))
                        self.assertTrue(step["tool"] == "message" or said[-1].startswith(start))   # the last word
                        self.assertFalse(any(re.search(r"\{(target|task_file)\}", s) for s in said))
                    else:
                        use = [b for b in blocks(lines) if b["type"] == "tool_use"][-1]
                        self.assertEqual((use["id"], use["name"]), (honest[-1], step["tool"]))
                        self.assertNotRegex(json.dumps(use["input"]), r"\{(target|task_file)\}")
                        self.assertTrue(use["input"].get("file_path", "/").startswith("/"))
        for fault in e20.FAULTS:
            for cover in e20.COVERS:
                self.assertTrue(e20.session(pool, rng, 0, fault, cover)[1])
        for fault, covers in e20.TEXT_COVERS.items():
            for cover in covers:
                self.assertTrue(e20.text_session(pool, rng, 0, fault, cover)[0])


if __name__ == "__main__":
    unittest.main()
