"""tracekit --version, the Claude Code plugin, the npm package and the README carry one version."""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _semver(v):
    """PEP 440 pre-release (0.2.0rc1, 1.1.0.dev0) to semver (0.2.0-rc.1, 1.1.0-dev.0); finals pass through."""
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc|\.dev)(\d+))?", v)
    if not m:
        raise ValueError(f"unsupported version {v!r}")
    base, pre, n = m.groups()
    if not pre:
        return base
    pre = {"a": "alpha", "b": "beta", ".dev": "dev"}.get(pre, pre)
    return f"{base}-{pre}.{n}"


class VersionSourceTest(unittest.TestCase):
    def test_cli_plugin_and_npm_agree(self):
        out = subprocess.run([sys.executable, "-m", "tracekit", "--version"], capture_output=True, text=True, cwd=ROOT,
                             check=True).stdout.split()
        self.assertEqual(out[0], "tracekit")
        expected = _semver(out[1])
        for rel in ("plugin/.claude-plugin/plugin.json", "sdk/typescript/package.json"):
            with open(os.path.join(ROOT, rel)) as f:
                self.assertEqual(json.load(f)["version"], expected, rel)

    def test_readme_names_this_version(self):
        """The README's licence line and its CI example name the version: a release moves them by hand
        (docs/RELEASING.md)."""
        from tracekit import __version__
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertEqual(re.findall(r"\bVersion (\S+?);", readme), [__version__])
        self.assertEqual(re.findall(r"uses: Cygnux-Labs/Tracekit@v([^\s`]+)", readme), [__version__])

    def test_hermes_plugin_takes_this_version(self):
        """The Hermes plugin's tracekit-ai bound admits this version: a release raises it by hand (docs/RELEASING.md),
        else the plugin refuses to install beside the release."""
        from tracekit import __version__
        with open(os.path.join(ROOT, "integrations", "hermes", "plugin.yaml"), encoding="utf-8") as f:
            (low, high), = re.findall(r'"tracekit-ai>=([\d.]+),<([\d.]+)"', f.read())

        def release(v):   # 1.7.0rc1 -> (1, 7, 0)
            return tuple(int(n) for n in re.match(r"\d+(\.\d+)*", v).group().split("."))
        self.assertTrue(release(low) <= release(__version__) < release(high), (__version__, low, high))

    def test_semver_mapping(self):
        self.assertEqual(_semver("0.2.0rc1"), "0.2.0-rc.1")
        self.assertEqual(_semver("1.0.0a2"), "1.0.0-alpha.2")
        self.assertEqual(_semver("1.0.0"), "1.0.0")
        self.assertEqual(_semver("1.1.0.dev0"), "1.1.0-dev.0")


if __name__ == "__main__":
    unittest.main()
