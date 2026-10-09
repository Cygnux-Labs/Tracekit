"""Hook commands run Python isolated and follow the configured fail mode.  python3 -m pytest tests/test_hook_invocation.py -q"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import agent_hooks, client, install  # noqa: E402

MARKER = "SHADOWED-TRACEKIT-RAN"
SITE = mock.Mock(origin="/usr/lib/python3/site-packages/tracekit/__init__.py")


class IsolatedCommand(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_commands_run_python_isolated_on_posix_and_windows(self):
        for name in ("posix", "nt"):
            for spec in (None, SITE):
                with mock.patch.object(install.os, "name", name), mock.patch("importlib.util.find_spec", return_value=spec):
                    for cmd in (install._hook_command(), agent_hooks._command("codex")):
                        self.assertIn(" -I ", cmd, (name, spec, cmd))
                        self.assertNotIn("PYTHONPATH", cmd)

    def test_project_directory_cannot_shadow_the_hook(self):
        proj = os.path.join(self.d, "project")
        os.makedirs(os.path.join(proj, "tracekit"))
        shadow = f"import sys\nprint({MARKER!r}); sys.stderr.write({MARKER!r}); sys.exit(0)\n"
        for f in ("__init__.py", "hook.py", "agent_hooks.py"):
            with open(os.path.join(proj, "tracekit", f), "w") as fh:
                fh.write(shadow)
        env = dict(os.environ, TRACEKIT_CLIENT_HOME=os.path.join(self.d, "client"), PYTHONPATH=proj)
        event = json.dumps({"hook_event_name": "SessionStart", "session_id": "shadow-test", "cwd": proj})
        for cmd in (install._hook_command(), agent_hooks._command("codex")):
            r = subprocess.run(cmd, shell=True, cwd=proj, input=event, capture_output=True, text=True, env=env, timeout=60)
            self.assertNotIn(MARKER, r.stdout + r.stderr, cmd)
            self.assertNotIn("Traceback", r.stderr, cmd)


class FailMode(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("TRACEKIT_FAIL_CLOSED", None)
        os.environ.pop("TRACEKIT_POLICY", None)

    def cursor_fail_closed(self):
        with open(agent_hooks.install("cursor", project=self.d), encoding="utf-8") as f:
            return {h["failClosed"] for lst in json.load(f)["hooks"].values() for h in lst}

    def test_cursor_fail_closed_follows_system_config(self):
        with mock.patch.object(client, "system_fail_closed", return_value=True):
            self.assertEqual(self.cursor_fail_closed(), {True})
        with mock.patch.object(client, "system_fail_closed", return_value=False):
            self.assertEqual(self.cursor_fail_closed(), {False})

    def test_wiring_error_blocks_when_fail_closed(self):
        with mock.patch.object(client, "system_fail_closed", return_value=True), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(agent_hooks.entry("not-a-harness"), 2)
        with mock.patch.object(client, "system_fail_closed", return_value=False), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(agent_hooks.entry("not-a-harness"), 0)


@unittest.skipIf(sys.platform == "win32", "the plugin wrapper is POSIX shell")
class PluginShim(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.config = os.path.join(self.d, "client.json")
        with open(os.path.join(ROOT, "plugin", "bin", "tracekit-hook"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("SYSTEM_CONFIG=/etc/tracekit/client.json", text)
        self.assertIn("SYSTEM_PYTHON=/opt/tracekit/bin/python", text)
        self.system_python = os.path.join(self.d, "opt-python")
        self.script = os.path.join(self.d, "tracekit-hook")
        with open(self.script, "w", encoding="utf-8") as f:
            f.write(text.replace("SYSTEM_CONFIG=/etc/tracekit/client.json", f"SYSTEM_CONFIG={self.config}")
                    .replace("SYSTEM_PYTHON=/opt/tracekit/bin/python", f"SYSTEM_PYTHON={self.system_python}"))
        self.bin = os.path.join(self.d, "bin")  # grep only: no python on PATH, so the package is missing
        os.makedirs(self.bin)
        os.symlink(shutil.which("grep"), os.path.join(self.bin, "grep"))

    def run_missing_package(self, fail_mode):
        if fail_mode is not None:
            with open(self.config, "w", encoding="utf-8") as f:
                json.dump({"fail_mode": fail_mode} if fail_mode else {}, f)
        return subprocess.run(["/bin/sh", self.script], input="{}", capture_output=True, text=True,
                              env={"PATH": self.bin, "TRACEKIT_PYTHON": ""}).returncode

    def test_missing_package_blocks_when_system_config_is_fail_closed(self):
        self.assertEqual(self.run_missing_package("closed"), 2)
        self.assertEqual(self.run_missing_package(""), 2)  # system mode defaults to closed

    def test_missing_package_allows_when_fail_open_or_no_system_config(self):
        self.assertEqual(self.run_missing_package(None), 0)
        self.assertEqual(self.run_missing_package("open"), 0)

    def fake_python(self, path):
        """A python that has tracekit: it logs how it was called."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\necho "$0 $*" >> {self.d}/calls\nexit 0\n')
        os.chmod(path, 0o755)
        return path

    def calls(self):
        try:
            with open(os.path.join(self.d, "calls"), encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def run_system_mode(self):
        with open(self.config, "w", encoding="utf-8") as f:
            json.dump({}, f)
        user_python = self.fake_python(os.path.join(self.bin, "python3"))
        return subprocess.run(["/bin/sh", self.script], input="{}", capture_output=True, text=True,
                              env={"PATH": self.bin, "TRACEKIT_PYTHON": user_python}).returncode

    def test_system_mode_runs_only_the_root_owned_runtime(self):
        self.fake_python(self.system_python)
        self.assertEqual(self.run_system_mode(), 0)
        self.assertIn(f"{self.system_python} -I -m tracekit.hook", self.calls())
        self.assertNotIn("python3", self.calls())

    def test_system_mode_blocks_without_the_runtime_and_ignores_other_pythons(self):
        self.assertEqual(self.run_system_mode(), 2)
        self.assertEqual(self.calls(), "")


if __name__ == "__main__":
    unittest.main()
