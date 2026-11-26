"""Where a person starts or checks a dev-mode signer, one plain line says it decides and records every call, and that
the agent still runs as you."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tracekit import cli, doctor, install
from tracekit.sdk import autospawn

LINE = ("Dev mode decides and records every call: a denied call is blocked, a held one waits for you. But the agent "
        "runs as you, so it could stop the signer, change its policy or reach its key. To close that, run the signer "
        "as another user (system mode: https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy) or the agent in Tracekit "
        "Box, a micro-VM (https://github.com/Cygnux-Labs/Tracekit-box).")


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class DevModeLine(unittest.TestCase):
    def test_the_line_is_the_one_in_the_task(self):
        self.assertEqual(install.DEV_MODE_LINE, LINE)

    def test_up_says_it(self):
        hello = {"version": "9", "pid": 1}
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(autospawn, "ensure", return_value=(mock.Mock(), None, hello)):
            code, out = run(["up"])
            self.assertEqual(code, 0)
            self.assertEqual(out.splitlines()[1:], [LINE])
            self.assertEqual(json.loads(run(["up", "--json"])[1].split("\n")[0]), hello)   # --json: still one document

    def test_init_dev_says_it_once(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(install, "init_dev", return_value={"socket": "s.sock"}), \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d}):
            code, out = run(["init", "--dev", "--home", d, "--no-hooks"])
        self.assertEqual(code, 0)
        self.assertEqual(out.count(LINE), 1)

    def test_init_dev_v2_says_it_once(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for argv in (["init", "--dev", "--v2", "--no-hooks"], ["init", "--dev", "--v2", "--agent", "codex", "--no-hooks"]):
            with self.subTest(argv), mock.patch.object(cli, "_signer_extra", return_value=True), \
                    mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d,
                                                 "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}):
                code, out = run(argv)
                self.assertEqual(code, 0)
                self.assertEqual(out.count(LINE), 1)

    def test_init_dev_v2_with_the_plugin_and_no_python_the_hook_finds_exits_non_zero(self):
        """With Tracekit in a venv the plugin's hook finds no Python and blocks every call, while init said nothing
        and exited 0."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        err = io.StringIO()
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(install, "plugin_enabled", return_value=("settings.json", "tracekit@x")), \
                mock.patch.object(install, "plugin_hook_python", return_value=None), \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d,
                                             "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}), \
                contextlib.redirect_stderr(err):
            code, _ = run(["init", "--dev", "--v2", "--no-thinking-summaries"])
        self.assertEqual(code, 1)
        self.assertIn("TRACEKIT_PYTHON=", err.getvalue())

    def test_doctor_fails_when_the_plugin_is_on_and_its_hook_finds_no_python(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for python, want in ((None, "fail"), ("/usr/bin/python3", None)):
            with self.subTest(python=python), mock.patch.object(install, "plugin_enabled",
                                                              return_value=("settings.json", "tracekit@x")), \
                    mock.patch.object(install, "plugin_hook_python", return_value=python), \
                    mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d,
                                                 "LOCALAPPDATA": d, "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}):
                got = {r["id"]: r for r in doctor.collect()}
                self.assertEqual(got.get("D-HOOKS-PYTHON", {}).get("status"), want)
                if want:
                    self.assertIn("TRACEKIT_PYTHON=", got["D-HOOKS-PYTHON"]["fix"])

    def test_init_with_the_plugin_and_no_hooks_runs_the_same_check(self):
        """The README tells plugin users to run init with --no-hooks, which skipped the check."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        err = io.StringIO()
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(install, "plugin_enabled", return_value=("settings.json", "tracekit@x")), \
                mock.patch.object(install, "plugin_hook_python", return_value=None), \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d,
                                             "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}), \
                contextlib.redirect_stderr(err):
            code, _ = run(["init", "--dev", "--v2", "--no-hooks"])
        self.assertEqual(code, 1)
        self.assertIn("TRACEKIT_PYTHON=", err.getvalue())

    def test_a_python_named_in_claude_codes_settings_env_counts(self):
        """The fix text offered "env" in ~/.claude/settings.json, but the check read the process environment only, so a
        setup that works still failed init and doctor."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, ".claude"))
        with open(os.path.join(d, ".claude", "settings.json"), "w") as f:
            json.dump({"env": {"TRACEKIT_PYTHON": sys.executable}}, f)
        with mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "PATH": d, "CLAUDE_CONFIG_DIR": ""}):
            os.environ.pop("TRACEKIT_PYTHON", None)
            self.assertEqual(install.plugin_hook_python(), shutil.which(sys.executable))
            os.remove(os.path.join(d, ".claude", "settings.json"))
            self.assertIsNone(install.plugin_hook_python())

    def test_the_hook_python_probe_cannot_hang_or_read_stdin(self):
        with mock.patch.dict(os.environ, {"TRACEKIT_PYTHON": sys.executable}), \
                mock.patch.object(install.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)) as probe:
            self.assertIsNone(install.plugin_hook_python())
        kwargs = probe.call_args.kwargs
        self.assertEqual((kwargs["stdin"], isinstance(kwargs["timeout"], (int, float))), (subprocess.DEVNULL, True))

    def test_doctor_after_a_plugin_init_and_disabling_the_plugin_still_warns_about_hooks(self):
        """Init's plugin branch wrote no client config, so doctor read the machine as SDK-only (info, "dev setup OK")
        once the plugin was off, though Claude Code is not recorded."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, ".claude", "settings.json")
        os.makedirs(os.path.dirname(settings))
        with open(settings, "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        env = {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d, "CLAUDE_CONFIG_DIR": "",
               "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(install, "plugin_hook_python", return_value="/usr/bin/python3"), \
                mock.patch.dict(os.environ, env), mock.patch.object(doctor.shutil, "which", return_value="/bin/claude"), \
                mock.patch.object(doctor.client, "system_config", return_value=None), \
                mock.patch.object(install.client, "system_config", return_value=None):
            self.assertEqual(run(["init", "--dev", "--v2", "--no-thinking-summaries"])[0], 0)
            with open(settings, "w") as f:
                json.dump({"enabledPlugins": {install.PLUGIN: False}}, f)
            got = {r["id"]: r for r in doctor.collect()}
        self.assertEqual(got["D-HOOKS-PRESENT"]["status"], "warn")

    def test_the_hook_python_is_the_first_that_imports_tracekit(self):
        with mock.patch.dict(os.environ, {"TRACEKIT_PYTHON": sys.executable}):
            self.assertEqual(install.plugin_hook_python(), shutil.which(sys.executable))
        with mock.patch.dict(os.environ, {"TRACEKIT_PYTHON": "", "PATH": tempfile.gettempdir()}):
            self.assertIsNone(install.plugin_hook_python())

    def test_init_dev_v2_with_the_plugin_enabled_says_it_too(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(install, "plugin_enabled", return_value=("settings.json", "tracekit@x")), \
                mock.patch.object(install, "plugin_hook_python", return_value="/usr/bin/python3"), \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d,
                                             "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}):
            code, out = run(["init", "--dev", "--v2", "--no-thinking-summaries"])
        self.assertEqual(code, 0)
        self.assertIn("v2 hooks: not installed: the Tracekit Claude Code plugin", out)
        self.assertEqual(out.count(LINE), 1)

    def test_doctor_says_it_once_as_the_process_boundary_check(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        got = doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none"))
        self.assertEqual([r["status"] for r in got if r["id"] == "D-PROCESS-BOUNDARY"], ["warn"])
        self.assertEqual([r["id"] for r in got if r["detail"] == LINE], ["D-PROCESS-BOUNDARY"])

    def status(self, dev, system):
        with mock.patch.object(install, "status", return_value={"client_config": None}), \
                mock.patch.object(autospawn, "status", return_value={"socket": "s", "dev": dev}), \
                mock.patch("tracekit.client.system_config", return_value=system):
            return json.loads(run(["status", "--json"])[1]).get("dev_mode")

    def test_status_prints_a_summary_and_json_only_with_json(self):
        """A new user's `tracekit status` printed a page of JSON; it prints what it found in lines, --json the JSON."""
        hello = {"socket": "s.sock", "dev": True, "running": True, "version": "9", "pid": 7, "data_dir": "/d"}
        with mock.patch.object(install, "status", return_value={"client_config": None, "hooks": [], "signer": None}), \
                mock.patch.object(autospawn, "status", return_value=hello), \
                mock.patch("tracekit.client.system_config", return_value=None):
            self.assertEqual(run(["status"]), (0, "\n".join([
                "signer      dev signer 9, running (pid 7), socket s.sock", "data        /d (its keys and signed runs)",
                "hooks       none in Claude Code's settings: tracekit init --dev --v2 adds them", LINE,
                "(tracekit status --json prints all of it)", ""])))

    def test_status_reads_any_settings_file_and_says_how_to_add_hooks(self):
        """Review of #628: a settings file that isn't JSON (or isn't a settings object) crashed `tracekit status` with
        KeyError: 'versions', and one with no Tracekit hooks printed "(0 events)" instead of how to add them. Review of
        #654: one it may not read crashed it too, and "none" after an unreadable file contradicted "unknown"."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        project = os.path.join(d, ".claude")
        os.makedirs(project)
        with open(os.path.join(project, "settings.json"), "w") as f:
            f.write("[]")   # JSON, not a settings object
        with mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "CLAUDE_CONFIG_DIR": ""}), \
                mock.patch("os.getcwd", return_value=d), \
                mock.patch.object(install, "MANAGED_SETTINGS", {"linux": os.path.join(d, "none")}):
            hooks = install._installed_hooks()
            with mock.patch.object(install, "read_json", side_effect=PermissionError(13, "Permission denied")):
                self.assertEqual(install._installed_hooks(), hooks)
            managed = os.path.join(project, "settings.json")   # JSON, not a settings object, as a managed file
            with mock.patch.object(install, "MANAGED_SETTINGS", {"linux": managed}):
                self.assertEqual(install._installed_hooks()[-1], {"settings": managed, "managed": True,
                                                                  "error": "unreadable"})
        self.assertEqual(hooks, [{"settings": os.path.join(project, "settings.json"), "error": "unreadable"}])
        none = {"settings": "b.json", "events": [], "versions": []}
        self.assertEqual(cli._status_lines({"hooks": hooks + [none]}, {"dev": True, "error": "not started"})[1:], [
            f"hooks       {hooks[0]['settings']} isn't a settings file Tracekit can read, so its hooks are unknown"])
        self.assertEqual(cli._status_lines({"hooks": [none]}, {"dev": True, "error": "not started"})[1:], [
            "hooks       none in Claude Code's settings: tracekit init --dev --v2 adds them"])

    def test_status_says_a_v1_signer_no_hook_uses_is_not_running_and_one_v1_hooks_use_is_unreachable(self):
        """A v1 signer a config names that doesn't answer read as an error (`unreachable at …: [Errno 2] …`) to a user
        with v2 hooks alone, who doesn't need it. With v1 hooks installed, which use it, it is one."""
        down = {"ok": False, "error": "unreachable at /v1.sock: [Errno 2] No such file or directory"}

        def line(signer, *versions):
            hooks = [{"settings": "s.json", "events": ["PreToolUse"], "versions": list(versions)}]
            return [x for x in cli._status_lines({"hooks": hooks, "signer": signer}, {"dev": True, "error": "x"})
                    if x.startswith("v1 signer")]
        self.assertEqual(line(down, "v2"), ["v1 signer   not running (only v1 hooks use it)"])
        self.assertEqual(line(down), ["v1 signer   not running (only v1 hooks use it)"])
        unread = [{"settings": "s.json", "error": "unreadable"}]   # its hooks may be v1
        self.assertIn("v1 signer   " + down["error"], cli._status_lines({"hooks": unread, "signer": down},
                                                                       {"dev": True, "error": "x"}))
        self.assertEqual(line(down, "v1", "v2"), ["v1 signer   " + down["error"]])
        self.assertEqual(line({"ok": True}, "v2"), ["v1 signer   answering"])

    def test_status_names_the_plugins_hooks_and_a_no_hooks_choice(self):
        """Review of #628: status told a plugin user, and one whose init chose --no-hooks, that `tracekit init --dev
        --v2` adds hooks, though init adds none while the plugin is on."""
        def hooks(client_config, plugin, system=None):
            with mock.patch.object(install, "status", return_value={"client_config": client_config, "hooks": [],
                                                                     "signer": None}), \
                    mock.patch.object(autospawn, "status", return_value={"socket": "s.sock", "dev": True}), \
                    mock.patch("tracekit.client.system_config", return_value=system), \
                    mock.patch.object(install, "plugin_enabled", return_value=plugin):
                return [x for x in run(["status"])[1].splitlines() if x.startswith("hooks")]
        self.assertEqual(hooks(None, ("/h/.claude/settings.json", "tracekit@tracekit")),
                         ["hooks       the Claude Code plugin tracekit@tracekit's, enabled in /h/.claude/settings.json"])
        chosen = ["hooks       none, as init --no-hooks chose: SDK runs (tracekit.instrument()) are still recorded; "
                  "init without --no-hooks adds Claude Code's"]
        self.assertEqual(hooks({"mode": "dev", "no_hooks": True}, None), chosen)
        sc = {"signer": "/run/s.sock", "hooks": {"user": "agent", "no_hooks": True}}   # system mode's choice
        self.assertEqual(hooks(sc, None, sc), chosen)
        self.assertEqual(hooks(None, None), ["hooks       none in Claude Code's settings: tracekit init --dev --v2 adds "
                                             "them"])

    def test_status_names_another_coding_agents_hooks(self):
        """QA of 1.6.0: after init --dev --v2 --agent gemini (or codex) status said `none in Claude Code's settings:
        tracekit init --dev --v2 adds them`, advice that adds Claude Code's hooks, and --json said "hooks": []."""
        for agent, path in (("codex", (".codex", "hooks.json")), ("gemini", (".gemini", "settings.json"))):
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            settings = os.path.join(d, *path)
            with self.subTest(agent), mock.patch.object(cli, "_signer_extra", return_value=True), \
                    mock.patch("tracekit.client.system_config", return_value=None), \
                    mock.patch("os.getcwd", return_value=d), \
                    mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "LOCALAPPDATA": d,
                                                 "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}):
                self.assertEqual(run(["init", "--dev", "--v2", "--agent", agent, "--no-thinking-summaries"])[0], 0)
                self.assertEqual([x for x in run(["status"])[1].splitlines() if x.startswith("hooks")],
                                 [f"hooks       v2 hooks for {agent} in {settings}"])
                self.assertEqual(json.loads(run(["status", "--json"])[1])["hooks"],
                                 [{"settings": settings, "agent": agent, "versions": ["v2"]}])

    def test_status_says_it_for_a_dev_signer_and_not_for_a_system_one(self):
        self.assertEqual(self.status(True, None), LINE)
        self.assertIsNone(self.status(False, None))

    def test_status_does_not_say_it_on_a_v1_system_mode_host(self):
        self.assertIsNone(self.status(True, {"socket": "system.sock"}))
