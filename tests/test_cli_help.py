import argparse
import unittest
from unittest import mock

from tracekit import cli


def _top_parser():
    """The parser `cli.main` builds: it parses argv, so capture it there and stop before any command runs."""
    seen = []

    def capture(self, *args, **kwargs):
        seen.append(self)
        raise SystemExit(0)

    with mock.patch.object(argparse.ArgumentParser, "parse_args", capture):
        try:
            cli.main(["status"])
        except SystemExit:
            pass
    return seen[0]


def _options(parser, path=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from _options(sub, path + (name,))
        elif isinstance(action, (argparse._HelpAction, argparse._VersionAction)) or action.nargs == argparse.REMAINDER:
            continue
        else:
            yield " ".join(path), action


# `init --no-hooks` has no help yet; it is written with the upkeep change for #464.
EXEMPT = {("init", "--no-hooks")}


class CliHelpTest(unittest.TestCase):
    def test_every_option_and_argument_has_help(self):
        missing = [f"{path} {action.option_strings or action.dest}" for path, action in _options(_top_parser())
                   if not action.help and (path, action.option_strings[0] if action.option_strings else action.dest)
                   not in EXEMPT]
        self.assertEqual(missing, [], f"no help= for: {missing}")


if __name__ == "__main__":
    unittest.main()
