"""tests/INVARIANTS.md: every invariant I0-I10 names at least one test, and every test it names exists."""
import importlib
import os
import re
import unittest

MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "INVARIANTS.md")
NODE = re.compile(r"`tests/(test_\w+)\.py::(\w+)::(test_\w+)`")


def rows():
    """{invariant: [(module, class, test), ...]} from the map's table."""
    with open(MAP, encoding="utf-8") as f:
        return {m.group(1): NODE.findall(line) for line in f if (m := re.match(r"\| (I\d+) \|", line))}


class InvariantsMap(unittest.TestCase):
    def test_every_invariant_names_a_test(self):
        table = rows()
        self.assertEqual(sorted(table, key=lambda i: int(i[1:])), [f"I{n}" for n in range(11)])
        for inv, nodes in table.items():
            self.assertTrue(nodes, f"{inv} names no test")

    def test_every_named_test_exists(self):
        for inv, nodes in rows().items():
            for module, cls, test in nodes:
                with self.subTest(f"{inv}: tests/{module}.py::{cls}::{test}"):
                    case = getattr(importlib.import_module(module), cls, None)
                    self.assertTrue(isinstance(case, type) and issubclass(case, unittest.TestCase), "no such class")
                    self.assertTrue(callable(getattr(case, test, None)), "no such test")


if __name__ == "__main__":
    unittest.main()
