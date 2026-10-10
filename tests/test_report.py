"""The technical report's tables are generated from eval/results/*.json and must not drift from them."""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from report import tables  # noqa: E402


class Report(unittest.TestCase):
    def setUp(self):
        with open(tables.REPORT) as f:
            self.text = f.read()

    def test_tables_match_the_eval_results(self):
        self.assertEqual(tables.render(self.text), self.text, "run python3 report/tables.py")

    def test_a_hand_edited_number_is_caught(self):
        edited = self.text.replace("| 30/30 |", "| 29/30 |", 1)
        self.assertNotEqual(edited, self.text)
        self.assertNotEqual(tables.render(edited), edited)

    def test_every_table_is_in_the_report(self):
        self.assertEqual(sorted(re.findall(r"<!-- table (\S+) -->", self.text)), sorted(tables.TABLES))

    def test_relative_links_resolve(self):
        for link in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", self.text):
            if not link.startswith(("http://", "https://")):
                self.assertTrue(os.path.exists(os.path.join(ROOT, "report", link)), link)


if __name__ == "__main__":
    unittest.main()
