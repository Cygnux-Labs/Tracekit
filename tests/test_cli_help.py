import argparse
import unittest

from tracekit import cli


def _options(parser, path=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from _options(sub, path + (name,))
        elif isinstance(action, (argparse._HelpAction, argparse._VersionAction)) or action.nargs == argparse.REMAINDER:
            continue
        else:
            yield " ".join(path), action


class CliHelpTest(unittest.TestCase):
    def test_every_option_and_argument_has_help(self):
        parser, _ = cli._parser()
        missing = [f"{path} {action.option_strings or action.dest}" for path, action in _options(parser)
                   if not action.help]
        self.assertEqual(missing, [], f"no help= for: {missing}")


if __name__ == "__main__":
    unittest.main()
