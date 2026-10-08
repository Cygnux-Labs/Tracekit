"""Experimental servers (ingest gateway, model proxy, OTLP receiver) are off unless --experimental is given.
python3 -m pytest tests/test_experimental.py -q"""
import contextlib
import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import cli  # noqa: E402


class Experimental(unittest.TestCase):
    def run_cli(self, argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, err.getvalue()

    def test_refused_without_the_flag(self):
        for argv in (["ingest", "serve", "--home", "/nonexistent"], ["otel", "serve"], ["proxy", "--home", "/nonexistent"],
                     ["init", "--dev", "--home", "/nonexistent", "--proxy"]):
            code, err = self.run_cli(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("pass --experimental", err, argv)

    def test_flag_lets_it_through_with_a_warning(self):
        # with the flag, ingest serve gets past the gate and stops at its next check (no client tokens)
        code, err = self.run_cli(["ingest", "serve", "--experimental", "--home", "/nonexistent"])
        self.assertEqual(code, 2)
        self.assertIn("experimental and being rebuilt", err)
        self.assertIn("no client tokens", err)


if __name__ == "__main__":
    unittest.main()
