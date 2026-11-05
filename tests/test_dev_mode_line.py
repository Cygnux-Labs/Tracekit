"""Where a person starts or checks a dev-mode signer, one plain line says it records and does not guard."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tracekit import cli, doctor, install
from tracekit.sdk import autospawn

LINE = ("Dev mode records; it does not guard. The agent runs as you and can reach the key. To guard, run the signer "
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

    def test_init_dev_v2_with_the_plugin_enabled_says_it_too(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(cli, "_signer_extra", return_value=True), \
                mock.patch.object(install, "plugin_enabled", return_value=("settings.json", "tracekit@x")), \
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
        KeyError: 'versions', and one with no Tracekit hooks printed "(0 events)" instead of how to add them."""
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
        self.assertEqual(hooks, [{"settings": os.path.join(project, "settings.json"), "error": "unreadable"}])
        none = {"settings": "b.json", "events": [], "versions": []}
        self.assertEqual(cli._status_lines({"hooks": hooks + [none]}, {"dev": True, "error": "not started"})[1:], [
            f"hooks       {hooks[0]['settings']} isn't a settings file Tracekit can read, so its hooks are unknown",
            "hooks       none in Claude Code's settings: tracekit init --dev --v2 adds them"])

    def test_status_says_it_for_a_dev_signer_and_not_for_a_system_one(self):
        self.assertEqual(self.status(True, None), LINE)
        self.assertIsNone(self.status(False, None))

    def test_status_does_not_say_it_on_a_v1_system_mode_host(self):
        self.assertIsNone(self.status(True, {"socket": "system.sock"}))
