"""tracekit --version, the Claude Code plugin and the npm package carry one version; server.json names its release."""
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

    def test_mcp_registry_server_json_names_this_release(self):
        import tracekit
        with open(os.path.join(ROOT, "server.json")) as f:
            server = json.load(f)
        release = re.match(r"\d+\.\d+\.\d+", tracekit.__version__).group()
        self.assertEqual(server["version"], release)

    def test_mcp_registry_lists_the_gateway_as_one_you_deploy(self):
        """A `packages` entry had MCP clients start the gateway as the agent's own user, at a fixed localhost URL: the
        agent could read its upstream credentials, which undid the gateway's T2 claim."""
        with open(os.path.join(ROOT, "server.json")) as f:
            server = json.load(f)
        self.assertNotIn("packages", server)
        (remote,) = server["remotes"]
        self.assertEqual(remote["url"], "https://{tracekit_gateway}/mcp")
        self.assertTrue(remote["variables"]["tracekit_gateway"]["isRequired"])
        self.assertLessEqual(len(server["description"]), 100)

    def test_semver_mapping(self):
        self.assertEqual(_semver("0.2.0rc1"), "0.2.0-rc.1")
        self.assertEqual(_semver("1.0.0a2"), "1.0.0-alpha.2")
        self.assertEqual(_semver("1.0.0"), "1.0.0")
        self.assertEqual(_semver("1.1.0.dev0"), "1.1.0-dev.0")


if __name__ == "__main__":
    unittest.main()
