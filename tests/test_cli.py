"""`tracekit help` and a bare `tracekit`: every command in one group, and `help NAME` as NAME's own --help.
python3 -m pytest tests/test_cli.py -q"""
import contextlib
import io
import unittest

from tracekit import cli


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


COMMANDS = sorted(cli._parser()[1].choices)


class Help(unittest.TestCase):
    def test_every_command_is_in_exactly_one_group(self):
        grouped = sorted(c for _, names in cli._GROUPS for c in names.split())
        self.assertEqual(grouped, sorted(set(COMMANDS) - {"help"}))

    def test_the_overview_names_every_group_and_command_within_80_columns(self):
        code, out, err = run(["help"])
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertLessEqual(max(map(len, lines)), 80)
        for title, names in cli._GROUPS:
            self.assertIn(title, lines)
            for name in names.split():
                self.assertTrue(any(line.split()[:1] == [name] for line in lines), name)
        self.assertIn("  verify          verify a .tkb offline", lines)
        self.assertIn("  report          what the agents did this week, on one page, from the v2", lines)
        self.assertIn("  why             causal investigation and replay of multi-agent runs", lines)
        self.assertIn("                  (experimental)", lines)
        self.assertEqual(lines[-1], "`tracekit help <command>` shows a command's options.")

    def test_bare_tracekit_prints_the_overview(self):
        self.assertEqual(run([]), run(["help"]))

    def test_help_command_is_the_commands_own_help(self):
        for name in COMMANDS:
            with self.subTest(name=name):
                code, out, err = run(["help", name])
                self.assertEqual(code, 0)
                self.assertIn(f"usage: tracekit {name}", out)
                self.assertEqual((code, out, err), run([name, "--help"]))

    def test_an_unknown_command_lists_the_names_and_exits_2(self):
        code, out, err = run(["help", "nosuch"])
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("tracekit help: no command named 'nosuch'; the commands are:\n"), err)
        self.assertEqual(err.replace("\n", " ").split(":", 2)[2].replace(",", " ").split(), COMMANDS)


if __name__ == "__main__":
    unittest.main()
