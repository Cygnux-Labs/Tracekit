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
from tracekit import __version__, agent_hooks, client, hook, install  # noqa: E402
from tracekit.locking import lock_file, unlock_file  # noqa: E402

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
        for name in ("scripts/tracekit-hook", "scripts/tracekit-hook.ps1", "README.md"):
            with open(os.path.join(ROOT, "plugin", name), encoding="utf-8") as f:
                pins = re.findall(r"tracekit-ai(?![/\\])([^\s)'\"]*)", f.read())   # (not a venv's folder: uv/tools/…)
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
            self.assertIn(f"Ask the person to set it up: uv tool install tracekit-ai=={__version__} && tracekit init --dev --v2 "
                          "--no-hooks", err)

    def record_python(self, python, allowed=True, ascii=True):
        """What `tracekit init` leaves in the client config: the Python the hook runs in (`allowed`: a person gave init
        --allow-hook-python, for a Python that isn't a tool install's)."""
        client = os.path.join(self.home, ".tracekit-client")
        os.makedirs(client, exist_ok=True)
        with open(os.path.join(client, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"hook_python": python, "hooks_settings": "/x", **({"hook_python_allowed": True} if allowed else {})},
                      f, indent=2, ensure_ascii=ascii)

    def test_the_python_init_recorded_is_the_only_one_that_runs_the_hook(self):
        """The fifth review: with the uv install's folder unreadable or removed the hook fell back to python3, where a
        planted tracekit ran. Once init has recorded a Python, that one runs it: not TRACEKIT_PYTHON (a project's settings
        can set it), not what PATH or a default folder holds, and a record that can't run it stops the call."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)   # python3's: a planted one
        self.set_up_tracekit()
        os.makedirs(os.path.join(self.d, "rec"))
        recorded = self.fake_python(os.path.join(self.d, "rec", "python"))
        agents = self.fake_python(os.path.join(self.d, "agents-python"))
        self.record_python(recorded)
        self.assertEqual(self.hook("PreToolUse", TRACEKIT_PYTHON=agents)[0], 0)
        self.assertIn(f"{recorded} -I -c", self.calls())
        self.assertNotIn(agents, self.calls())
        self.assertNotIn("python3", self.calls())
        os.remove(recorded)   # gone: blocked, with what to run, and no other Python tried
        code, err = self.hook("PreToolUse", TRACEKIT_PYTHON=agents)
        self.assertEqual(code, 2, err)
        self.assertIn("tracekit init --dev --v2 --no-hooks", err)
        self.assertNotIn(agents, self.calls())

    def test_a_tracekit_that_is_set_up_with_no_python_recorded_blocks_the_call(self):
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        self.set_up_tracekit()
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2, err)
        self.assertIn("recorded no Python", err)
        self.assertIn("turn the plugin off in /plugin", err)

    def test_a_recorded_python_outside_a_tool_install_is_refused_unless_a_person_allowed_it(self):
        """The record is the one Python the hook runs, so a record anywhere an agent can write (a project's .venv) would
        let it choose that Python: only a uv tool or pipx install of tracekit-ai's folder is run, or one init recorded with
        a person's --allow-hook-python."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        self.set_up_tracekit()
        os.makedirs(os.path.join(self.d, "rec"))
        outside = self.fake_python(os.path.join(self.d, "rec", "python"))
        self.record_python(outside, allowed=False)
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2, err)
        self.assertIn("is not one of a uv tool or pipx install of Tracekit", err)
        self.assertNotIn(outside, self.calls())
        self.record_python(outside, allowed=True)
        self.assertEqual(self.hook("PreToolUse")[0], 0)
        inside = os.path.join(self.data, "uv", "tools", "tracekit-ai", "bin")
        os.makedirs(inside)
        tool = self.fake_python(os.path.join(inside, "python"))
        self.record_python(tool, allowed=False)
        self.assertEqual(self.hook("PreToolUse")[0], 0)
        self.assertIn(f"{tool} -I -c", self.calls())
        self.assertEqual(self.hook("PreToolUse", UV_TOOL_DIR=os.path.join(self.d, "other"))[0], 2)   # (as this process sees it)

    def test_a_python_init_recorded_on_windows_is_one_of_a_tool_install_in_uvs_and_pipxs_folders_there(self):
        """Git Bash runs this script on Windows, where init records a Python in uv's or pipx's Windows folders
        (install.tool_venvs) as Windows writes it: one there runs (here it can't, so the call stops as it can't import
        tracekit), a folder named like one is refused, as before init recorded these."""
        windows = {"APPDATA": r"C:\Users\u\AppData\Roaming", "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
                   "USERPROFILE": r"C:\Users\u"}
        for python, env, inside in (
                (r"C:\Users\u\AppData\Roaming\uv\tools\tracekit-ai\Scripts\python.exe", {}, True),
                (r"C:\Users\u\AppData\Roaming\uv\data\tools\tracekit-ai\Scripts\python.exe", {}, True),
                (r"C:\Users\u\AppData\Local\pipx\pipx\venvs\tracekit-ai\Scripts\python.exe", {}, True),
                (r"C:\Users\u\pipx\venvs\tracekit-ai\Scripts\python.exe", {}, True),
                (r"C:\Users\u\.local\pipx\venvs\tracekit-ai\Scripts\python.exe", {}, True),
                (r"D:\tools\tracekit-ai\Scripts\python.exe", {"UV_TOOL_DIR": r"D:\tools"}, True),
                (r"C:\Users\u\AppData\Roaming\uv\tools\tracekit-ai\Scripts\python.exe", {"UV_TOOL_DIR": r"D:\tools"}, False),
                (r"D:\px\venvs\tracekit-ai\Scripts\python.exe", {"PIPX_HOME": r"D:\px"}, True),
                (r"C:\Users\u\AppData\Roaming\uv\tools\tracekit-ai-x\Scripts\python.exe", {}, False),   # a look-alike
                (r"C:\Users\u\AppData\Roaming\uv\data\python\cpython-3.12\python.exe", {}, False),
                (r"C:\Users\u\proj\.venv\Scripts\python.exe", {}, False)):
            with self.subTest(python=python, env=env):
                self.record_python(python, allowed=False)
                code, err = self.hook("PreToolUse", **windows, **env)
                self.assertEqual(code, 2, err)
                self.assertEqual("cannot import tracekit" in err, inside, err)
                self.assertEqual("is not one of a uv tool or pipx install of Tracekit" in err, not inside, err)

    def test_the_record_is_read_as_json_so_quotes_backslashes_and_non_ascii_paths_work(self):
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        self.set_up_tracekit()
        folder = os.path.join(self.d, 'r\u00e9c "q" a\\b')
        os.makedirs(folder)
        python = self.fake_python(os.path.join(folder, "python"))
        self.record_python(python, ascii=False)
        self.assertEqual(self.hook("PreToolUse")[0], 0)
        self.assertIn('r\u00e9c "q" a', self.calls())
        self.record_python(python, ascii=True)   # (\u00e9: a text the hook can't unescape is refused, never guessed)
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2, err)
        self.assertIn("is not one of a uv tool or pipx install of Tracekit", err)

    def test_the_hook_runs_no_program_found_through_path_before_it_reads_its_record(self):
        """The hook ran the first `uname` on PATH on every call, which an agent can put there and which then ran in the
        hook: the record is read first with the shell's builtins, and uname is /usr/bin/uname."""
        os.makedirs(os.path.join(self.d, "plant"))
        planted = os.path.join(self.d, "plant", "uname")
        log = os.path.join(self.d, "planted")
        path = os.path.join(self.d, "plant") + os.pathsep + self.bin
        with open(planted, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\necho ran >> {log}\necho Darwin\n')
        os.chmod(planted, 0o755)
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        self.set_up_tracekit()
        os.makedirs(os.path.join(self.d, "rec"))
        self.record_python(self.fake_python(os.path.join(self.d, "rec", "python")))
        self.hook("PreToolUse", PATH=path)
        self.assertFalse(os.path.exists(log))   # (a record: nothing found through PATH runs)
        os.remove(os.path.join(self.home, ".tracekit-client", "config.json"))
        self.hook("PreToolUse", PATH=path)
        self.assertFalse(os.path.exists(log))   # (none: the system's own uname finds the data dir)

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
        self.record_python(tool_python)   # (set up, the Python init recorded runs it, whatever PATH holds)
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

    def install_tracekit(self, hook_source, version="1.0.0"):
        """A python3 on PATH whose only tracekit is a stub in the user site-packages (`pip install --user`). -> the
        stub package's directory."""
        py = os.path.join(self.bin, "python3")
        with open(py, "w", encoding="utf-8") as f:   # -S: none of this interpreter's own site-packages
            f.write(f'#!/bin/sh\nexec "{sys.executable}" -S "$@"\n')
        os.chmod(py, 0o755)
        site = subprocess.run([py, "-I", "-c", "import site; print(site.getusersitepackages())"], env={"HOME": self.home},
                              capture_output=True, text=True, check=True).stdout.strip()
        os.makedirs(os.path.join(site, "tracekit", "integrations"))
        for path, text in (("__init__.py", f'__version__ = "{version}"\n'), ("integrations/__init__.py", ""),
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
            self.assertIn(f"Ask the person to run: uv tool install tracekit-ai=={__version__} && tracekit init --dev --v2 "
                          "--no-hooks", err)
            self.assertNotIn("Traceback", err)

    def link_tracekit(self, venv, cfg=False):
        """A `tracekit` command on PATH linking into `venv`/bin, beside a python that logs its calls (pyvenv.cfg above
        it with `cfg`). -> that python."""
        os.makedirs(os.path.join(venv, "bin"))
        if cfg:
            open(os.path.join(venv, "pyvenv.cfg"), "w").close()
        tool_python = self.fake_python(os.path.join(venv, "bin", "python"))
        with open(os.path.join(venv, "bin", "tracekit"), "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n")
        os.chmod(os.path.join(venv, "bin", "tracekit"), 0o755)
        link = os.path.join(self.bin, "tracekit")
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(os.path.join(venv, "bin", "tracekit"), link)
        return tool_python

    def test_a_uv_tool_or_pipx_install_comes_before_python3(self):
        """The plugin review: with the real tracekit a uv tool on PATH, a tracekit planted in python3's user
        site-packages ran the hook in its place and let every call through. The python of the uv tool or pipx install
        the `tracekit` command is now comes first."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)   # python3's: the planted one
        for venv in ("uv/tools/tracekit-ai", "pipx/venvs/tracekit-ai"):
            with self.subTest(venv=venv):
                tool_python = self.link_tracekit(os.path.join(self.data, venv), cfg=True)
                self.assertEqual(self.hook("PreToolUse")[0], 0)
                self.assertIn(f"{tool_python} -I -c", self.calls())
                shutil.rmtree(os.path.join(self.data, venv.split("/")[0]))

    def test_a_venv_shaped_folder_the_agent_made_on_path_is_not_a_uv_install(self):
        """The fourth review: any */uv/tools/tracekit-ai/bin/tracekit the PATH's `tracekit` linked to was the install, so an
        agent's folder of that shape with its link first on PATH ran the hook. Only where uv or pipx put it counts."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        agents = self.link_tracekit(os.path.join(self.d, "work", "x", "uv", "tools", "tracekit-ai"), cfg=True)
        self.assertEqual(self.hook("PreToolUse")[0], 0)
        self.assertNotIn(f"{agents} -I -c", self.calls())

    def test_a_broken_uv_install_blocks_the_call_and_runs_no_python3(self):
        """The fourth review: with the uv tool's interpreter removed the hook fell back to python3's user site-packages,
        where a planted tracekit ran. The install's folder alone stops it."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        os.makedirs(os.path.join(self.data, "uv", "tools", "tracekit-ai", "bin"))
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2, err)
        self.assertIn("cannot import tracekit", err)
        self.assertNotIn("python3", self.calls())

    def test_uv_tool_dir_and_pipx_home_name_where_the_install_is(self):
        os.makedirs(os.path.join(self.d, "tools", "tracekit-ai", "bin"))
        installed = self.fake_python(os.path.join(self.d, "tools", "tracekit-ai", "bin", "python"))
        self.assertEqual(self.hook("PreToolUse", UV_TOOL_DIR=os.path.join(self.d, "tools"))[0], 0)
        self.assertIn(f"{installed} -I -c", self.calls())

    def test_a_tracekit_older_than_the_plugin_blocks_tool_calls(self):
        """Its packs hold what the plugin's rules need: an older one (here 1.7.1, the plugin's own version moves with
        each release) is refused with what to run, as one before 1.2 is."""
        with open(os.path.join(ROOT, "plugin", ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
            version = json.load(f)["version"]
        with open(os.path.join(ROOT, "plugin", "scripts", "tracekit-hook"), encoding="utf-8") as f:
            self.assertIn(f"MIN_TRACEKIT={version} ", f.read())
        older = ".".join(str(max(int(p) - (i == 2), 0)) for i, p in enumerate(version.split(".")[:3]))
        self.install_tracekit("def _entry(event=None):\n    return 0\n", older)
        code, err = self.hook("PreToolUse")
        self.assertEqual(code, 2, err)
        self.assertIn(f"tracekit {older}", err.splitlines()[0])
        self.assertIn(f"is older than this plugin, which needs {version}", err)
        self.assertIn(f"uv tool install tracekit-ai=={version}", err)

    def test_a_tracekit_link_the_agent_made_elsewhere_loses_to_python3(self):
        """The second review: any `tracekit` link whose folder had a pyvenv.cfg came before python3, so an agent could
        link one into ~/bin to a folder of its own whose python allows everything. Only a uv tool or pipx install's
        does; any other comes after python3 and python, as before."""
        self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)   # python3's: here, the real one
        tool_python = self.link_tracekit(os.path.join(self.d, "e"), cfg=True)
        self.assertEqual(self.hook("PreToolUse")[0], 0)
        self.assertNotIn(f"{tool_python} -I -c", self.calls())

    def test_an_agents_tracekit_early_on_path_does_not_hide_a_uv_or_pipx_install(self):
        """The third review: for a uv tool user python3 has no tracekit, so an agent's `tracekit` put earlier on PATH
        than ~/.local/bin made the hook run that tracekit's python, which let every call through. A uv tool or pipx
        install where they put it by default is found whatever PATH says, and with one nothing else runs the hook."""
        agents = self.link_tracekit(os.path.join(self.d, "e"), cfg=True)
        for venv in ("uv/tools/tracekit-ai", "pipx/venvs/tracekit-ai"):
            with self.subTest(venv=venv):
                os.makedirs(os.path.join(self.data, venv, "bin"))
                installed = self.fake_python(os.path.join(self.data, venv, "bin", "python"))
                self.assertEqual(self.hook("PreToolUse")[0], 0)
                self.assertIn(f"{installed} -I -c", self.calls())
                self.assertNotIn(f"{agents} -I -c", self.calls())
                shutil.rmtree(os.path.join(self.data, venv.split("/")[0]))

    def test_a_pth_file_in_the_user_site_packages_does_not_run(self):
        """The third review: the user site-packages was added with site.addsitedir, which runs each .pth file's import
        lines, so a .pth the agent planted ran before tracekit and could end the hook with 0."""
        package = self.install_tracekit("def _entry(event=None):\n    return 2\n", __version__)   # the real one blocks this call
        with open(os.path.join(os.path.dirname(package), "zz.pth"), "w", encoding="utf-8") as f:
            f.write("import os; os._exit(0)\n")
        self.assertEqual(self.hook("PreToolUse")[0], 2)

    def test_a_tracekit_without_the_harness_hook_blocks_tool_calls_and_says_to_upgrade(self):
        """1.6.0 has no Copilot CLI hook: its harness_hooks printed a usage line, and the call was blocked unexplained."""
        package = self.install_tracekit("def _entry(event=None):\n    return 0\n", __version__)
        for path, text in (("agent_hooks.py", 'HARNESSES = ("codex",)\n'),
                           ("integrations/harness_hooks.py", "def entry(harness, event):\n    return 0\n")):
            with open(os.path.join(package, path), "w", encoding="utf-8") as f:
                f.write(text)
        self.assertEqual(self.hook("PreToolUse", "codex")[0], 0)
        code, err = self.hook("preToolUse", "copilot")
        self.assertEqual(code, 2, err)
        self.assertIn("has no copilot hook (it is older than this plugin)", err)
        self.assertIn(f"uv tool install tracekit-ai=={__version__}", err)

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


@unittest.skipUnless(os.name == "nt", "Claude Code runs the plugin's hooks in PowerShell on Windows without Git Bash")
class PluginInPowerShell(unittest.TestCase):
    """#1097: the PreToolUse command as hooks/claude.json names it, run as Claude Code runs it on Windows without Git
    Bash (in PowerShell, ${CLAUDE_PLUGIN_ROOT} rewritten to ${env:CLAUDE_PLUGIN_ROOT}), with no sh on PATH, against the
    dev signer."""

    def setUp(self):
        from tracekit.sdk import autospawn
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.powershell = shutil.which("powershell")
        system32 = os.path.join(os.environ["SystemRoot"], "System32")
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": os.path.join(self.d, "run"), "TRACEKIT_DEV_IDLE": "60",
                                           "LOCALAPPDATA": os.path.join(self.d, "data"),
                                           "TRACEKIT_CLIENT_HOME": os.path.join(self.d, "client"),
                                           "USERPROFILE": os.path.join(self.d, "home"),   # PowerShell's $HOME
                                           "TRACEKIT_PYTHON": sys.executable,
                                           "CLAUDE_PLUGIN_ROOT": os.path.join(ROOT, "plugin"),
                                           "PATH": os.pathsep.join((os.path.dirname(self.powershell), system32))})
        env.start()
        self.addCleanup(env.stop)
        for k in ("TRACEKIT_SIGNER", "TRACEKIT_FAIL_CLOSED", "TRACEKIT_POLICY"):
            os.environ.pop(k, None)
        self.addCleanup(autospawn.down)
        self.assertIsNone(shutil.which("sh"))
        with open(os.path.join(ROOT, "plugin", "hooks", "claude.json"), encoding="utf-8") as f:
            self.command = json.load(f)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def record(self, python):
        """What `tracekit init --allow-hook-python` leaves in the client config under $HOME: the one Python the hook
        runs in once Tracekit is set up."""
        client = os.path.join(self.d, "home", ".tracekit-client")
        os.makedirs(client)
        with open(os.path.join(client, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"hook_python": python, "hook_python_allowed": True}, f)

    def pre(self, command, tid):
        payload = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                   "tool_input": {"command": command}, "tool_use_id": tid, "cwd": self.d}
        r = subprocess.run([self.powershell, "-NoProfile", "-Command",
                            self.command.replace("${CLAUDE_PLUGIN_ROOT}", "${env:CLAUDE_PLUGIN_ROOT}")],
                           input=json.dumps(payload), capture_output=True, text=True, cwd=self.d, timeout=120)
        return r.returncode, r.stderr

    def test_a_denied_call_is_blocked_and_an_allowed_one_runs_and_is_recorded(self):
        from tracekit.integrations import claude_code
        from tracekit.sdk.client import Client, RunHandle
        self.record(sys.executable)
        code, err = self.pre("pkill tracekitd", "t1")
        self.assertEqual(code, 2, err)
        self.assertIn("BLOCKED", err)
        self.assertEqual(self.pre("ls", "t2"), (0, ""))
        with open(claude_code._state("s1"), encoding="utf-8") as f:
            run = RunHandle(Client(), json.load(f))
        decisions = [(e["data"]["tool_use_id"], e["data"]["decision"]) for e in run.call("read")["events"]
                     if e["type"] == "policy.decision"]
        self.assertEqual(decisions, [("t1", "deny"), ("t2", "allow")])

    def test_once_init_recorded_a_python_no_other_runs_the_hook(self):
        """As tracekit-hook: TRACEKIT_PYTHON (a project's settings can set it) never stands in for the Python init
        recorded, and a record that can't run the hook blocks the call."""
        self.record(os.path.join(self.d, "gone", "python.exe"))
        code, err = self.pre("ls", "t1")
        self.assertEqual(code, 2, err)
        self.assertIn("the Python tracekit init recorded for this hook, cannot import tracekit", err)

    def test_without_tracekit_a_tool_call_is_blocked_once_it_is_set_up(self):
        os.environ["TRACEKIT_PYTHON"] = os.path.join(self.d, "gone", "python.exe")
        code, err = self.pre("ls", "t1")
        self.assertEqual(code, 2, err)
        self.assertIn("so this call was blocked (fail-closed)", err)

    def test_a_script_that_never_starts_blocks_the_call(self):
        root = os.path.join(self.d, "a[1] b")   # PowerShell's cd would read [1] as a wildcard
        shutil.copytree(os.path.join(ROOT, "plugin", "scripts"), os.path.join(root, "scripts"))
        os.environ["CLAUDE_PLUGIN_ROOT"] = root
        self.assertEqual(self.pre("pkill tracekitd", "t1")[0], 2)   # the script runs from there
        with open(os.path.join(root, "scripts", "tracekit-hook.ps1"), "w", encoding="utf-8") as f:
            f.write("if ( {\n")   # a parse error: the script never starts, as under a Group Policy execution policy
        self.assertEqual(self.pre("ls", "t2")[0], 2)
        os.environ["CLAUDE_PLUGIN_ROOT"] = os.path.join(self.d, "gone")
        self.assertEqual(self.pre("ls", "t3")[0], 2)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell 7 (pwsh)")
class PluginPreToolUseInPwsh(unittest.TestCase):
    """#1097: the PreToolUse command as hooks/claude.json names it, run in pwsh as Claude Code runs it on Windows without
    Git Bash, against a plugin root whose script is broken or fake: a hook that never runs still blocks the call."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        with open(os.path.join(ROOT, "plugin", "hooks", "claude.json"), encoding="utf-8") as f:
            command = json.load(f)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.command = command.replace("${CLAUDE_PLUGIN_ROOT}", "${env:CLAUDE_PLUGIN_ROOT}")

    def run_with(self, script, prefix=""):
        root = os.path.join(self.d, "root")
        if script is not None:
            os.makedirs(os.path.join(root, "scripts"), exist_ok=True)
            with open(os.path.join(root, "scripts", "tracekit-hook.ps1"), "w", encoding="utf-8") as f:
                f.write(script)
        env = dict(os.environ, CLAUDE_PLUGIN_ROOT=root)
        return subprocess.run(["pwsh", "-NoProfile", "-Command", prefix + self.command], input="{}", env=env,
                              capture_output=True, text=True, timeout=120).returncode

    def test_a_script_that_cannot_run_blocks_the_call(self):
        for name, script in (("parse error", "if ( {\n"), ("throw", 'throw "x"\n'), ("missing root", None)):
            for prefix in ("", '$ErrorActionPreference="Stop"; '):
                with self.subTest(name, stop=bool(prefix)):
                    self.assertEqual(self.run_with(script, prefix), 2)

    def test_the_scripts_own_exit_code_is_kept(self):
        for code in (0, 2):
            with self.subTest(code):
                self.assertEqual(self.run_with(f"exit {code}\n"), code)


@unittest.skipUnless(shutil.which("pwsh") and os.name != "nt", "needs PowerShell 7 (pwsh), and sh for the stand-in")
class PluginWindowsToolFoldersInPwsh(unittest.TestCase):
    """tracekit-hook.ps1, run as hooks/claude.json's PreToolUse command in pwsh as Claude Code runs it on Windows without
    Git Bash: a Python init recorded in uv's or pipx's Windows folders (install.tool_venvs: %APPDATA%\\uv\\tools,
    %APPDATA%\\uv\\data\\tools, %LOCALAPPDATA%\\pipx\\pipx\\venvs, ~\\pipx\\venvs) runs the hook with no person's allowance,
    whatever its case, and a folder named like one is refused. Before, only ~/.local/share's were, so on Windows init
    recorded none and the hook blocked every call. The Python is a stand-in that logs each run and exits 0."""
    STAND_IN = '#!/bin/sh\necho "$0" >> "$FAKE_LOG"\n'

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = os.path.join(self.d, "home")
        self.roaming, self.local = (os.path.join(self.home, "AppData", n) for n in ("Roaming", "Local"))
        with open(os.path.join(ROOT, "plugin", "hooks", "claude.json"), encoding="utf-8") as f:
            command = json.load(f)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.command = command.replace("${CLAUDE_PLUGIN_ROOT}", "${env:CLAUDE_PLUGIN_ROOT}")

    def pre(self, python, record=None, **env):
        """(exit code, the stand-in's runs, stderr) of the PreToolUse command, the stand-in at `python` and `record`
        (else `python`) what `tracekit init` recorded, with no allowance."""
        os.makedirs(os.path.dirname(python), exist_ok=True)
        with open(python, "w", encoding="utf-8") as f:
            f.write(self.STAND_IN)
        os.chmod(python, 0o755)
        os.makedirs(os.path.join(self.home, ".tracekit-client"), exist_ok=True)
        with open(os.path.join(self.home, ".tracekit-client", "config.json"), "w", encoding="utf-8") as f:
            json.dump({"hook_python": record or python}, f)
        log, pwsh = os.path.join(self.d, "log"), os.path.realpath(shutil.which("pwsh"))
        open(log, "w").close()
        env = {"HOME": self.home, "APPDATA": self.roaming, "LOCALAPPDATA": self.local, "FAKE_LOG": log,
               "CLAUDE_PLUGIN_ROOT": os.path.join(ROOT, "plugin"), "PATH": os.path.dirname(pwsh), **env}
        r = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", self.command], input="{}", env=env,
                           cwd=self.d, capture_output=True, text=True, timeout=120)
        with open(log, encoding="utf-8") as f:
            return r.returncode, len(f.read().split()), r.stderr

    def test_a_python_in_uvs_or_pipxs_windows_folders_runs_the_hook(self):
        for folder in (os.path.join(self.roaming, "uv", "tools"), os.path.join(self.roaming, "uv", "data", "tools"),
                       os.path.join(self.local, "pipx", "pipx", "venvs"), os.path.join(self.home, "pipx", "venvs")):
            with self.subTest(folder=folder):
                code, runs, err = self.pre(os.path.join(folder, "tracekit-ai", "Scripts", "python.exe"))
                self.assertEqual((code, runs), (0, 2), err)   # (its import of tracekit, then the hook)

    def test_one_in_any_case_is_one_of_them_and_a_look_alike_is_refused(self):
        python = os.path.join(self.roaming, "uv", "data", "tools", "tracekit-ai", "Scripts", "python.exe")
        record = python.replace(os.path.join("data", "tools", "tracekit-ai"), os.path.join("DATA", "Tools", "TraceKit-AI"))
        code, runs, err = self.pre(python, record=record)
        # (accepted, as Windows matches any case: it runs where this file system finds it so, else can't import tracekit)
        self.assertEqual((code, runs), (0, 2) if os.path.exists(record) else (2, 0), err)
        self.assertNotIn("is not one of a uv tool or pipx install of Tracekit", err)
        for python, env in ((os.path.join(self.roaming, "uv", "data", "tools", "tracekit-ai-x", "Scripts", "python.exe"), {}),
                            (os.path.join(self.roaming, "uv", "data", "python", "cpython-3.12", "python.exe"), {}),
                            (python, {"UV_TOOL_DIR": os.path.join(self.d, "tools")})):   # (as this process sees it)
            with self.subTest(python=python, env=env):
                code, runs, err = self.pre(python, **env)
                self.assertEqual((code, runs), (2, 0), err)
                self.assertIn("is not one of a uv tool or pipx install of Tracekit", err)


class PruneRunState(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        env = mock.patch.dict(os.environ, {"TRACEKIT_CLIENT_HOME": os.path.join(self.d, "client")})
        env.start()
        self.addCleanup(env.stop)
        self.runs = os.path.join(client.client_dir(), "runs")
        self.pol = hook.policy_mod.load()[0]

    def state(self, name, days):
        path = os.path.join(self.runs, name)
        with open(path, "w") as f:
            f.write("{}")
        t = os.path.getmtime(path) - days * 86400
        os.utime(path, (t, t))
        return path

    def start(self, sid="now"):
        return hook.build_events({"hook_event_name": "SessionStart", "session_id": sid, "cwd": self.d}, self.pol)

    def test_a_session_start_removes_state_no_hook_wrote_for_a_month(self):
        gone, today, now = (client.state_name(r) for r in ("gone", "today", "now"))
        old = [self.state(gone + s, 31) for s in (".started", ".started.txoff", ".json", ".json.lock")]
        old += [self.state(n, 31) for n in ("gemini-0123456789abcdef.json", "gemini-0123456789abcdef.json.lock",
                                            "typed-0123456789abcdef.json")]
        kept = [self.state(today + ".started", 0), self.state(now + ".json", 31)]
        self.start()
        self.assertEqual([p for p in old if os.path.exists(p)], [])
        self.assertTrue(all(os.path.exists(p) for p in kept))

    def test_a_run_with_one_fresh_file_keeps_them_all(self):
        live = client.state_name("live")   # .started and the lock are written once; its counter is written on each call
        kept = [self.state(live + ".started", 40), self.state(live + ".json.lock", 40), self.state(live + ".json", 0)]
        self.start()
        self.assertEqual([p for p in kept if not os.path.exists(p)], [])

    def test_the_counters_tracekitd_keeps_for_good_stay(self):
        unattributed, proxy, findings = (client.state_name(r) for r in ("_unattributed", "_proxy", "findings:r1"))
        kept = [self.state(unattributed + s, 40) for s in (".json", ".json.lock", ".json.tmp")]
        kept += [self.state(proxy + s, 40) for s in (".proxy.json", ".proxy.json.lock")]
        kept += [self.state(findings + s, 40) for s in (".analyzer.json", ".analyzer.json.lock", ".analyzer.json.tmp")]
        self.start()
        self.assertEqual([p for p in kept if not os.path.exists(p)], [])

    def test_files_tracekit_did_not_write_stay(self):
        kept = [self.state(n, 40) for n in ("notes.txt", "my-run.json", "session_1.started", "gemini-queue.json",
                                            "A" * 64 + ".json", client.state_name("x")[:63] + ".json")]
        self.start()
        self.assertEqual([p for p in kept if not os.path.exists(p)], [])

    def test_state_whose_lock_is_held_stays(self):
        queue = self.state("gemini-0123456789abcdef.json", 31)
        lock = self.state("gemini-0123456789abcdef.json.lock", 31)
        with open(lock, "a") as f:
            lock_file(f)
            try:
                self.start()
            finally:
                unlock_file(f)
        self.assertTrue(os.path.exists(queue) and os.path.exists(lock))

    def test_acks_of_transcripts_that_are_gone_are_dropped(self):
        here = os.path.join(self.d, "here.jsonl")
        open(here, "w").close()
        acks = os.path.join(self.runs, "transcript-acks.json")
        with open(acks, "w") as f:
            json.dump({here: 5, os.path.join(self.d, "deleted.jsonl"): 9}, f)
        self.start()
        with open(acks) as f:
            self.assertEqual(json.load(f), {here: 5})

    def test_a_prune_that_cannot_list_or_remove_changes_no_decision(self):
        listdir = os.listdir

        def unlistable(path="."):
            if os.path.abspath(path) == os.path.abspath(self.runs):
                raise PermissionError(13, "denied", path)
            return listdir(path)

        fails = {"listdir": mock.patch("os.listdir", unlistable),
                 "remove": mock.patch("os.remove", side_effect=PermissionError(13, "denied"))}
        for how, failing in fails.items():
            codes = []
            for i, call in enumerate(({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
                                      {"tool_name": "Read", "tool_input": {"file_path": "a"}})):
                sid = f"{how}{i}"
                raw = json.dumps({"hook_event_name": "PreToolUse", "session_id": sid, "tool_use_id": "t",
                                  "cwd": self.d, **call})
                with mock.patch.object(client, "send", return_value={"ok": True}):
                    code = hook.main(raw=raw)
                    os.remove(os.path.join(self.runs, client.state_name(sid) + ".started"))
                    gone = self.state(client.state_name("gone") + ".started", 31)
                    with failing:
                        self.assertEqual(hook.main(raw=raw), code, (how, call))
                codes.append(code)
                self.assertTrue(os.path.exists(gone), how)
            self.assertEqual(codes, [2, 0], how)


if __name__ == "__main__":
    unittest.main()
