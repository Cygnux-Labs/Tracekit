"""Hook commands run Python isolated and follow the configured fail mode.  python3 -m pytest tests/test_hook_invocation.py -q"""
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import __version__, agent_hooks, client, install  # noqa: E402

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
class ClearText(unittest.TestCase):
    """The hook command init wrote from a working tree (or a --user install) carried the tree's path and branch in
    base64, which reads as malware to a security reviewer: they are plain, quoted arguments now, and the hook runs as
    before from a path with spaces and quotes."""

    def tree(self, name, entry="import sys\ndef _entry(event):\n    print('ran', event, sys.path[0], sys.argv[1:])\n"
                                    "    return 0\n"):
        """A directory `name` holding a tracekit package whose v2 hook's _entry is `entry`."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        tree = os.path.join(d, name)
        os.makedirs(os.path.join(tree, "tracekit", "integrations"))
        for f in ("__init__.py", os.path.join("integrations", "__init__.py")):
            open(os.path.join(tree, "tracekit", f), "w").close()
        with open(os.path.join(tree, "tracekit", "integrations", "claude_code.py"), "w") as f:
            f.write(entry)
        return tree

    def test_the_command_names_its_tree_in_clear_text_and_runs_from_any_path(self):
        """Review of #628: doctor took a `"` off the end of every word of a POSIX command, so a tree whose name ends
        in one was misread."""
        from tracekit import doctor
        for name in ("it's a \"tree\" $HOME", 'ends in a quote "'):
            tree = self.tree(name)
            with self.subTest(tree=tree), mock.patch.object(install, "ROOT", tree), \
                    mock.patch("importlib.util.find_spec", return_value=None):
                cmd = install._hook_command(install.V2_HOOK, args=("PreToolUse",))
                self.assertNotIn("base64", cmd)
                self.assertIn("from tracekit.integrations.claude_code import _entry", cmd)
                p = subprocess.run(cmd, shell=True, input="{}", capture_output=True, text=True, timeout=60)
                self.assertEqual((p.returncode, p.stdout.strip()),
                                 (0, f"ran PreToolUse {tree} {[tree, 'PreToolUse']}"), p.stderr)
                self.assertEqual(doctor._probe_target(doctor._hook_argv(cmd)), (sys.executable, tree))   # D-VERSIONS

    HOSTILE = "C:\\Users\\O'Brien $(id) `id` %PATH% !x &calc \"q\"\\Tracekit"

    def windows(self, tree, branch):
        """The hook command init writes on Windows for `tree` on `branch`, and doctor's reading of its tree."""
        from tracekit import doctor
        with mock.patch.object(install.os, "name", "nt"), mock.patch.object(install, "ROOT", tree), \
                mock.patch.object(install, "_branch", return_value=branch), \
                mock.patch("importlib.util.find_spec", return_value=None):
            cmd = install._hook_command(install.V2_HOOK, args=("PreToolUse",))
            return cmd, doctor._probe_target(doctor._hook_argv(cmd))[1]

    def test_on_windows_no_shell_expands_the_tree_or_branch_in_the_command(self):
        """Review of #628: the Windows command passed the tree, branch and event as arguments quoted for the C runtime,
        which Claude Code's Git Bash (Codex's PowerShell, Droid's cmd.exe) read as shell text: C:\\Users\\me lost its
        backslashes, O'Brien broke the line, and a branch fix&calc or f$(id) ran a command. They are literals inside
        the code now, every character a shell reads in double quotes escaped; here under bash, as Git Bash runs it."""
        branch = "fix&calc$(id)`id`%PATH%'q\"!x"
        tree = self.tree(self.HOSTILE)
        cmd, read = self.windows(tree, branch)
        self.assertEqual(read, tree)   # doctor reads the tree back from the code
        self.assertNotIn("base64", cmd)
        p = subprocess.run(["bash", "-c", cmd], input="{}", capture_output=True, text=True, timeout=60)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, f"ran PreToolUse {tree} []"), p.stderr)
        self.assertNotIn("uid=", p.stdout + p.stderr)
        broken = self.tree(self.HOSTILE, "from tracekit import a_name_this_branch_removed\n")
        p = subprocess.run(["bash", "-c", self.windows(broken, branch)[0]], input="{}", capture_output=True,
                           text=True, timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertIn(f"the working tree {broken}, which cannot import it now", p.stderr)
        self.assertIn(f"was on {branch} when the hooks were installed", p.stderr)
        self.assertNotIn("uid=", p.stdout + p.stderr)


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

    @unittest.skipIf(os.name == "nt", "the fail-closed wrapper is POSIX shell")
    def test_a_v1_dev_hook_that_cannot_run_follows_tracekit_fail_closed(self):
        """A v1 dev pre-tool hook that can't start (tracekit gone: exit 1; its Python gone: 127) can't read the fail
        mode, so its command does: TRACEKIT_FAIL_CLOSED=1 blocks the call, else it runs with an error shown."""
        gone = shlex.quote(os.path.join(self.d, "gone", "python"))
        for module, args in (("tracekit.hook", ()), ("tracekit.agent_hooks", ("codex",))):
            for run, open_, closed in (("false", 1, 2), (gone, 1, 2), ("sh -c 'exit 2'", 2, 2), ("true", 0, 0)):
                with mock.patch.object(install, "_dev_hook_command", return_value=run):
                    cmd = install._hook_command(module, "entry", args)
                    self.assertEqual(install._hook_command(module, "entry", args, pre=False), run)   # never blocks
                for env, want in (({}, open_), ({"TRACEKIT_FAIL_CLOSED": "0"}, open_), ({"TRACEKIT_FAIL_CLOSED": "1"}, closed)):
                    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30,
                                       env=dict(os.environ, **env))
                    self.assertEqual(p.returncode, want, (module, run, env, p.stderr))
                    if run in ("false", gone):
                        self.assertIn("call blocked (fail-closed)" if want == 2 else "set TRACEKIT_FAIL_CLOSED=1",
                                      p.stderr)
                        self.assertNotIn("fail-open", p.stderr)   # goose and Cursor may still block it

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
        self.bin = os.path.join(self.d, "bin")  # grep, uname, readlink: no python on PATH, so the package is missing
        os.makedirs(self.bin)
        for tool in ("grep", "uname", "readlink"):
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

    def hook(self, event="PreToolUse", agent=None, **env):
        """(exit code, stderr) of the plugin's hook for `event` (and `agent`, as hooks/<agent>.json names it), with this
        test's PATH, HOME and XDG_DATA_HOME."""
        r = subprocess.run(["/bin/sh", self.script, event, *([agent] if agent else [])], input="{}",
                           capture_output=True, text=True,
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
            self.assertIn(f"Ask the person to set it up: pip install tracekit-ai=={__version__} && tracekit init --dev --v2 "
                          "--no-hooks", err)

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
        self.assertIn("turn the plugin off in /plugin", err)   # no CLAUDE_PLUGIN_ROOT: the key isn't known
        for event in ("UserPromptSubmit", "Stop", "SubagentStop", "SessionStart"):   # 2 would erase or loop these
            code, err = self.hook(event)
            self.assertEqual(code, 1, event)
            self.assertIn(f"this {event} event was NOT recorded", err.splitlines()[0])

    def test_the_disable_command_names_the_marketplace_the_plugin_came_from(self):
        """Claude Code installs a marketplace plugin at <plugins root>/cache/<marketplace>/<plugin>/<version>."""
        self.set_up_tracekit()
        for root, key in (("/home/u/.claude/plugins/cache/buildwithclaude/tracekit/1.5.3",
                           "tracekit@buildwithclaude"),
                          ("/home/u/.claude/plugins/cache/buildwithclaude/tracekit/1.5.3/",
                           "tracekit@buildwithclaude"),
                          ("/home/u/.claude/plugins/cache/tracekit/tracekit/1.5.3", "tracekit@tracekit"),
                          ("/home/u/My Plugins/cache/buildwithclaude/tracekit/1.5.3", "tracekit@buildwithclaude")):
            with self.subTest(root=root):
                code, err = self.hook("PreToolUse", CLAUDE_PLUGIN_ROOT=root)
                self.assertEqual(code, 2, err)
                self.assertEqual(err.count("/plugin disable "), 1, err)
                self.assertIn(f"/plugin disable {key}\n", err)
                self.assertNotIn("turn the plugin off in /plugin", err)

    def test_copilot_and_cursor_run_calls_before_tracekit_is_set_up(self):
        """Copilot CLI denies a preToolUse call at any exit but 0, and so does Cursor with failClosed: the notice's exit
        1 would block every call, the agent's own install of Tracekit included."""
        for agent, pre, want in (("copilot", "preToolUse", 0), ("cursor", "preToolUse", 0), ("codex", "PreToolUse", 1),
                                 (None, "PreToolUse", 1), ("cursor", "postToolUse", 0)):
            with self.subTest(agent=agent, event=pre):
                code, err = self.hook(pre, agent)
                self.assertEqual(code, want, err)
                self.assertIn(f"this {pre} event was NOT recorded", err)
        self.set_up_tracekit()   # then a call no hook can decide is blocked, under every harness
        for agent, pre in (("copilot", "preToolUse"), ("cursor", "preToolUse"), ("codex", "PreToolUse")):
            with self.subTest(agent=agent, set_up=True):
                code, err = self.hook(pre, agent)
                self.assertEqual(code, 2, err)
                self.assertIn("turn the Tracekit plugin off", err)
                self.assertNotIn("/plugin", err)   # Claude Code's command

    def test_a_tracekit_command_installed_on_its_own_runs_the_hook(self):
        """`uv tool install tracekit-ai` and pipx give tracekit a venv of its own, which python3 doesn't import: the
        hook found none, and once Tracekit was set up blocked every call. The command on PATH links (here through a
        relative link and an absolute one) to the venv's bin/tracekit, beside its python. Its #! line doesn't always
        name that python: uv and pip write a /bin/sh trampoline for a long path, or one with spaces."""
        venv_bin = os.path.join(self.d, "tools", "tracekit ai", "bin")
        os.makedirs(venv_bin)
        tool_python = self.fake_python(os.path.join(venv_bin, "python"))
        with open(os.path.join(venv_bin, "tracekit"), "w", encoding="utf-8") as f:
            f.write(f"#!/bin/sh\n'''exec' '{tool_python}' \"$0\" \"$@\"\n' '''\nimport sys\n")
        os.chmod(os.path.join(venv_bin, "tracekit"), 0o755)
        os.symlink(os.path.join(venv_bin, "tracekit"), os.path.join(self.d, "tools", "link"))
        os.symlink(os.path.join("..", "tools", "link"), os.path.join(self.bin, "tracekit"))
        self.set_up_tracekit()
        for agent in (None, "codex"):
            with self.subTest(agent=agent):
                self.assertEqual(self.hook("PreToolUse", agent)[0], 0)
        self.assertIn(f"{tool_python} -I -c", self.calls())
        self.assertIn("tracekit.integrations.claude_code import _entry", self.calls())
        self.assertIn("harness_hooks import entry", self.calls())
        self.assertIn(" codex PreToolUse", self.calls())   # harness_hooks takes the harness, then the event

    def test_no_disable_command_when_the_plugins_key_is_not_known(self):
        """No CLAUDE_PLUGIN_ROOT, a --plugin-dir or local-marketplace plugin (which loads in place), a claude.ai-synced
        one, or a cache path with no version: none of them names a key here."""
        self.set_up_tracekit()
        for env in ({}, {"CLAUDE_PLUGIN_ROOT": "/home/u/.claude/plugins/marketplaces/tracekit/plugin"},
                    {"CLAUDE_PLUGIN_ROOT": "/home/u/.claude/plugins/cache/buildwithclaude/tracekit"}):
            with self.subTest(**env):
                code, err = self.hook("PreToolUse", **env)
                self.assertEqual(code, 2, err)
                self.assertIn("turn the plugin off in /plugin", err)
                self.assertNotIn("/plugin disable", err)

    def test_a_tracekit_python_that_is_gone_counts_as_set_up(self):
        self.assertEqual(self.hook(TRACEKIT_PYTHON=os.path.join(self.d, "gone", "python"))[0], 2)

    def install_tracekit(self, hook_source):
        """A python3 on PATH whose only tracekit is a stub in the user site-packages (`pip install --user`). -> the
        stub package's directory."""
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
        return os.path.join(site, "tracekit")

    def test_a_tracekit_before_1_2_blocks_tool_calls_and_says_to_upgrade(self):
        """0.4 and 1.0 define _entry() without the event: the plugin's call raised TypeError, and the wrapper blocked
        every event, prompts and Stop included."""
        self.install_tracekit("def _entry():\n    return 0\n")
        for event, want in (("PreToolUse", 2), ("UserPromptSubmit", 1), ("Stop", 1)):
            code, err = self.hook(event)
            self.assertEqual(code, want, (event, err))
            self.assertIn("tracekit 1.0.0", err.splitlines()[0])
            self.assertIn("is older than 1.2", err)
            self.assertIn(f"Ask the person to run: pip install tracekit-ai=={__version__} && tracekit init --dev --v2 "
                          "--no-hooks", err)
            self.assertNotIn("Traceback", err)

    def test_the_venv_of_the_tracekit_command_comes_before_python3(self):
        """The plugin review: with the real tracekit a uv tool on PATH, a tracekit planted in python3's user
        site-packages ran the hook in its place and let every call through. The python of the venv the `tracekit`
        command is in now comes first; a `tracekit` in no venv keeps the old order (python3 first)."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n")   # python3's: the planted one
        for in_venv in (True, False):
            with self.subTest(in_venv=in_venv):
                venv = os.path.join(self.d, f"venv-{in_venv}")
                os.makedirs(os.path.join(venv, "bin"))
                if in_venv:
                    open(os.path.join(venv, "pyvenv.cfg"), "w").close()
                tool_python = self.fake_python(os.path.join(venv, "bin", "python"))
                with open(os.path.join(venv, "bin", "tracekit"), "w", encoding="utf-8") as f:
                    f.write("#!/bin/sh\n")
                os.chmod(os.path.join(venv, "bin", "tracekit"), 0o755)
                link = os.path.join(self.bin, "tracekit")
                if os.path.lexists(link):
                    os.unlink(link)
                os.symlink(os.path.join(venv, "bin", "tracekit"), link)
                self.assertEqual(self.hook("PreToolUse")[0], 0)
                self.assertEqual(f"{tool_python} -I -c" in self.calls(), in_venv)

    def test_a_tracekit_without_the_harness_hook_blocks_tool_calls_and_says_to_upgrade(self):
        """1.6.0 has no Copilot CLI hook: its harness_hooks printed a usage line, and the call was blocked unexplained."""
        package = self.install_tracekit("def _entry(event=None):\n    return 0\n")
        for path, text in (("agent_hooks.py", 'HARNESSES = ("codex",)\n'),
                           ("integrations/harness_hooks.py", "def entry(harness, event):\n    return 0\n")):
            with open(os.path.join(package, path), "w", encoding="utf-8") as f:
                f.write(text)
        self.assertEqual(self.hook("PreToolUse", "codex")[0], 0)
        code, err = self.hook("preToolUse", "copilot")
        self.assertEqual(code, 2, err)
        self.assertIn("has no copilot hook (it is older than this plugin)", err)
        self.assertIn(f"pip install tracekit-ai=={__version__}", err)

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
