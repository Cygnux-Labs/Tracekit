"""Niche modules live in contrib/ as separate packages: core neither ships nor imports them, and their old subcommands
say where they went.  python3 -m pytest tests/test_contrib_split.py -q"""
import contextlib
import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import cli  # noqa: E402

MOVED = ("causeway", "proofpack", "query", "adapters.onchain")


class Split(unittest.TestCase):
    def test_core_does_not_ship_or_import_moved_modules(self):
        for m in MOVED:
            self.assertFalse(os.path.exists(os.path.join(ROOT, "tracekit", *m.split(".")) + ".py"), m)
        pat = re.compile(r"^\s*(from|import)\s+(tracekit_(causeway|proofpack|query|onchain|stagehand)\b|\S*\b(causeway|proofpack|query|onchain)\b)", re.M)
        for root, _, files in os.walk(os.path.join(ROOT, "tracekit")):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(root, f), encoding="utf-8") as fh:
                        self.assertIsNone(pat.search(fh.read()), os.path.join(root, f))

    def test_moved_subcommands_point_to_contrib(self):
        for cmd, pkg in (("sql", "query"), ("proofpack", "proofpack"), ("report", "proofpack"), ("causeway", "causeway")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(cli.main([cmd, "--help"]), 2)
            self.assertIn(f"moved to contrib/{pkg}", err.getvalue())


if __name__ == "__main__":
    unittest.main()
