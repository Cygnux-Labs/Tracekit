"""Hook commands run Python isolated and follow the configured fail mode.  python3 -m pytest tests/test_hook_invocation.py -q"""
import io
import json
import os
import re
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
                    for cmd in (install._hook_command(), install._hook_command("tracekit.agent_hooks", "entry", ("codex",))):
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
        for cmd in (install._hook_command(), install._hook_command("tracekit.agent_hooks", "entry", ("codex",))):
            r = subprocess.run(cmd, shell=True, cwd=proj, input=event, capture_output=True, text=True, env=env, timeout=60)
            self.assertNotIn(MARKER, r.stdout + r.stderr, cmd)
            self.assertNotIn("Traceback", r.stderr, cmd)


@unittest.skipIf(os.name == "nt", "the fail-closed wrapper is POSIX shell")
class WorkingTree(unittest.TestCase):
    """A dev hook imports Tracekit from the working tree init ran in (#427): a branch switch or rebase there that
    leaves code which won't import says which tree, what it is on now and what to run, and still blocks the call."""

    def git(self, *args):
        """git in the test's tree only: no GIT_DIR or other GIT_* (set when a git hook runs the tests) points it at
        the repository under test."""
        subprocess.run(["git", "-C", self.tree, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                       env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")})

    def write_hook(self, source):
        with open(os.path.join(self.tree, "tracekit", "integrations", "claude_code.py"), "w", encoding="utf-8") as f:
            f.write(source)

    def test_a_tree_that_no_longer_imports_names_the_tree_its_branch_and_the_fix(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.tree = os.path.join(d, "the checkout")   # a space: the fix command quotes the path
        os.makedirs(os.path.join(self.tree, "tracekit", "integrations"))
        for name in ("__init__.py", os.path.join("integrations", "__init__.py")):
            open(os.path.join(self.tree, "tracekit", name), "w").close()
        self.write_hook("def _entry(event):\n    return 0\n")
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.git("add", ".")
        self.git("commit", "-qm", "hook")
        elsewhere = {"GIT_DIR": os.path.join(d, "another repository")}   # as a git hook sets it: git ignores it here
        with mock.patch.object(install, "ROOT", self.tree), mock.patch("importlib.util.find_spec", return_value=None), \
                mock.patch.dict(os.environ, elsewhere):
            pre, stop = (install._hook_command(install.V2_HOOK, args=(ev,), pre=ev == "PreToolUse")
                         for ev in ("PreToolUse", "Stop"))
            for module, args, flags in ((install.V2_HOOKS[1], ("codex", "PreToolUse"), "--dev --v2 --agent codex"),
                                        ("tracekit.agent_hooks", ("codex",), "--dev --agent codex")):
                self.assertIn(f"or run tracekit init {flags} again from", install._dev_hook_argv(module, "entry", args)[3])

        def run(cmd, **env):
            return subprocess.run(cmd, shell=True, input="{}", capture_output=True, text=True, timeout=60,
                                  env=dict(os.environ, **elsewhere, **env))
        self.assertEqual([(r.returncode, r.stderr) for r in (run(pre), run(stop))], [(0, ""), (0, "")])
        self.git("checkout", "-qb", "feature")
        self.write_hook("from tracekit import a_name_this_branch_removed\n")
        for now in ("feature", "a detached HEAD"):
            p, s = run(pre), run(stop)
            self.assertEqual((p.returncode, s.returncode), (2, 1), p.stderr)   # blocked as before; only the line is new
            line = p.stderr.splitlines()[0]
            self.assertEqual(s.stderr.splitlines()[0], line)
            for part in (f"the working tree {self.tree},",
                         "(ImportError: cannot import name 'a_name_this_branch_removed'",
                         f"it is on {now} there, and was on main when the hooks were installed",
                         f"git -C '{self.tree}' checkout main",
                         "or run tracekit init --dev --v2 again from"):
                self.assertIn(part, line)
            self.assertNotIn("Traceback", p.stderr)
            self.git("checkout", "-q", "--detach")   # as a rebase leaves it
        p = run(pre, PATH=d)   # no git on PATH: the plain traceback, and the call is still blocked
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("ImportError: cannot import name 'a_name_this_branch_removed'", p.stderr)
        self.assertNotIn("Error in sys.excepthook", p.stderr)


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
            return {ev for ev, lst in json.load(f)["hooks"].items() for h in lst if h["failClosed"]}

    def test_cursor_fail_closed_follows_system_config(self):   # for a tool call only: no other event is blocked
        with mock.patch.object(client, "system_fail_closed", return_value=True):
            self.assertEqual(self.cursor_fail_closed(), {"preToolUse"})
        with mock.patch.object(client, "system_fail_closed", return_value=False):
            self.assertEqual(self.cursor_fail_closed(), set())

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
        with open(os.path.join(ROOT, "plugin", "scripts", "tracekit-hook"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("SYSTEM_CONFIG=/etc/tracekit/client.json", text)
        self.assertIn("SYSTEM_PYTHON=/opt/tracekit/bin/python", text)
        self.system_python = os.path.join(self.d, "opt-python")
        self.script = os.path.join(self.d, "tracekit-hook")
        with open(self.script, "w", encoding="utf-8") as f:
            f.write(text.replace("SYSTEM_CONFIG=/etc/tracekit/client.json", f"SYSTEM_CONFIG={self.config}")
                    .replace("SYSTEM_PYTHON=/opt/tracekit/bin/python", f"SYSTEM_PYTHON={self.system_python}"))
        self.bin = os.path.join(self.d, "bin")  # grep and uname only: no python on PATH, so the package is missing
        os.makedirs(self.bin)
        for tool in ("grep", "uname"):
            os.symlink(shutil.which(tool), os.path.join(self.bin, tool))
        self.home, self.data = os.path.join(self.d, "home"), os.path.join(self.d, "data")

    def test_every_install_command_names_the_plugins_version(self):
        # that package decides which calls run, so the plugin names the version it was built for
        with open(os.path.join(ROOT, "plugin", ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
            version = json.load(f)["version"]
        for name in ("scripts/tracekit-hook", "README.md"):
            with open(os.path.join(ROOT, "plugin", name), encoding="utf-8") as f:
                pins = re.findall(r"tracekit-ai([^\s)'\"]*)", f.read())
            with self.subTest(file=name):
                self.assertTrue(pins)
                self.assertEqual(set(pins), {"==" + version})

    def hook(self, event="PreToolUse", **env):
        """(exit code, stderr) of the plugin's hook for `event`, with this test's PATH, HOME and XDG_DATA_HOME."""
        r = subprocess.run(["/bin/sh", self.script, event], input="{}", capture_output=True, text=True,
                           env={"PATH": self.bin, "HOME": self.home, "XDG_DATA_HOME": self.data, "TRACEKIT_PYTHON": "",
                                **env})
        return r.returncode, r.stderr

    def run_missing_package(self, fail_mode):
        if fail_mode is not None:
            with open(self.config, "w", encoding="utf-8") as f:
                json.dump({"fail_mode": fail_mode} if fail_mode else {}, f)
        return self.hook()[0]

    def test_missing_package_blocks_when_system_config_is_fail_closed(self):
        self.assertEqual(self.run_missing_package("closed"), 2)
        self.assertEqual(self.run_missing_package(""), 2)  # system mode defaults to closed

    def test_missing_package_runs_the_call_with_a_visible_error_when_fail_open_or_not_set_up(self):
        """Both exited 0, and Claude Code shows no stderr of a hook that exits 0: nobody saw "NOT recorded"."""
        self.assertEqual(self.run_missing_package(None), 1)
        self.assertEqual(self.run_missing_package("open"), 1)

    def test_without_tracekit_or_its_setup_every_event_proceeds_with_a_notice(self):
        for event in ("PreToolUse", "UserPromptSubmit", "Stop"):
            code, err = self.hook(event)
            self.assertEqual(code, 1, event)
            self.assertIn("NOT recorded", err.splitlines()[0])   # the line Claude Code shows
            self.assertIn("Ask the person to set it up: pip install tracekit-ai==1.4.2 && tracekit init --dev --v2 --no-hooks", err)

    def set_up_tracekit(self):
        """What `tracekit init --dev --v2` and the dev signer leave behind: the dev signer's data dir."""
        from tracekit.signer import service
        with mock.patch.dict(os.environ, {"HOME": self.home, "XDG_DATA_HOME": self.data}):
            service.dev_data_dir()

    def test_once_tracekit_is_set_up_a_missing_package_blocks_tool_calls_only(self):
        self.set_up_tracekit()
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2)
        self.assertIn("call was blocked", err)
        self.assertIn("/plugin disable tracekit@tracekit", err)
        for event in ("UserPromptSubmit", "Stop", "SubagentStop", "SessionStart"):   # 2 would erase or loop these
            code, err = self.hook(event)
            self.assertEqual(code, 1, event)
            self.assertIn(f"this {event} event was NOT recorded", err.splitlines()[0])

    def test_a_tracekit_python_that_is_gone_counts_as_set_up(self):
        self.assertEqual(self.hook(TRACEKIT_PYTHON=os.path.join(self.d, "gone", "python"))[0], 2)

    def install_tracekit(self, hook_source):
        """A python3 on PATH whose only tracekit is a stub in the user site-packages (`pip install --user`)."""
        py = os.path.join(self.bin, "python3")
        with open(py, "w", encoding="utf-8") as f:   # -S: none of this interpreter's own site-packages
            f.write(f'#!/bin/sh\nexec "{sys.executable}" -S "$@"\n')
        os.chmod(py, 0o755)
        site = subprocess.run([py, "-I", "-c", "import site; print(site.getusersitepackages())"], env={"HOME": self.home},
                              capture_output=True, text=True, check=True).stdout.strip()
        os.makedirs(os.path.join(site, "tracekit", "integrations"))
        for path, text in (("__init__.py", '__version__ = "1.0.0"\n'), ("integrations/__init__.py", ""),
                           ("integrations/claude_code.py", hook_source)):
            with open(os.path.join(site, "tracekit", path), "w", encoding="utf-8") as f:
                f.write(text)

    def test_a_tracekit_before_1_2_blocks_tool_calls_and_says_to_upgrade(self):
        """0.4 and 1.0 define _entry() without the event: the plugin's call raised TypeError, and the wrapper blocked
        every event, prompts and Stop included."""
        self.install_tracekit("def _entry():\n    return 0\n")
        for event, want in (("PreToolUse", 2), ("UserPromptSubmit", 1), ("Stop", 1)):
            code, err = self.hook(event)
            self.assertEqual(code, want, (event, err))
            self.assertIn("tracekit 1.0.0", err.splitlines()[0])
            self.assertIn("is older than 1.2", err)
            self.assertIn("Ask the person to run: pip install tracekit-ai==1.4.2 && tracekit init --dev --v2 --no-hooks", err)
            self.assertNotIn("Traceback", err)

    def test_a_tracekit_whose_hook_does_not_import_blocks_tool_calls(self):
        self.install_tracekit("import a_dependency_that_is_missing\n")
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2)
        self.assertIn("cannot import its hook (ModuleNotFoundError", err)
        self.assertEqual(self.hook("Stop")[0], 1)

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
        return subprocess.run(["/bin/sh", self.script, "PreToolUse"], input="{}", capture_output=True, text=True,
                              env={"PATH": self.bin, "TRACEKIT_PYTHON": user_python}).returncode

    def test_system_mode_runs_only_the_root_owned_runtime(self):
        self.fake_python(self.system_python)
        self.assertEqual(self.run_system_mode(), 0)
        self.assertIn(f"{self.system_python} -I -m tracekit.integrations.claude_code PreToolUse", self.calls())
        self.assertNotIn("python3", self.calls())

    def test_system_mode_blocks_without_the_runtime_and_ignores_other_pythons(self):
        self.assertEqual(self.run_system_mode(), 2)
        self.assertEqual(self.calls(), "")
        code, err = self.hook("Stop")   # never sends Claude back to work
        self.assertEqual(code, 1)
        self.assertIn("tracekit init --v2 --user <agent-user> --no-hooks", err)

    def test_dev_mode_blocks_when_the_hook_starts_but_cannot_finish(self):
        for status in (1, 2):   # imports tracekit, but the hook exits 1 (a crash) or 2 (a 1.2 hook's error)
            py = os.path.join(self.bin, "python3")
            with open(py, "w", encoding="utf-8") as f:
                f.write(f'#!/bin/sh\ncase "$*" in *_entry*) exit {status} ;; esac\n')
            os.chmod(py, 0o755)
            code, err = self.hook("PreToolUse")
            self.assertEqual(code, 2)
            if status == 1:
                self.assertIn("call was blocked", err)
            for event in ("UserPromptSubmit", "Stop"):
                self.assertEqual(self.hook(event)[0], 1, (status, event))


if __name__ == "__main__":
    unittest.main()
