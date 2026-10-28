"""Installer writes never follow a planted symlink, create files 0600 from the start, and dev TCP has no port race."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pytest

from tracekit import install
from tracekit.deploy import files

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
CAN_SYMLINK = hasattr(os, "symlink") and os.name != "nt"


class _Sentinel:
    """A file outside the target directory that a planted symlink points at; it must come out untouched."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.outside, True)
        self.sentinel = os.path.join(self.outside, "sentinel")
        with open(self.sentinel, "w") as f:
            f.write("do not touch")
        os.chmod(self.sentinel, 0o640)
        self.before = self.state()

    def state(self):
        st = os.stat(self.sentinel)
        return open(self.sentinel).read(), st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)

    def plant(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(self.sentinel, path)

    def assertSentinelUntouched(self):
        self.assertEqual(self.state(), self.before)


@unittest.skipUnless(CAN_SYMLINK, "needs symlinks")
class ClientConfig(_Sentinel, unittest.TestCase):
    def test_symlinked_config_is_refused(self):
        self.plant(os.path.join(self.d, ".tracekit-client", "config.json"))
        with self.assertRaises(files.UnsafePath):
            install._write_client_config(self.d, {"socket": "x"})
        self.assertSentinelUntouched()

    def test_symlinked_client_dir_and_runs_are_refused(self):
        os.symlink(self.outside, os.path.join(self.d, ".tracekit-client"))
        with self.assertRaises(files.UnsafePath):
            install._write_client_config(self.d, {"socket": "x"})
        os.remove(os.path.join(self.d, ".tracekit-client"))
        os.makedirs(os.path.join(self.d, ".tracekit-client"))
        os.symlink(self.outside, os.path.join(self.d, ".tracekit-client", "runs"))
        with self.assertRaises(files.UnsafePath):
            install._write_client_config(self.d, {"socket": "x"})
        self.assertSentinelUntouched()
        self.assertEqual(os.listdir(self.outside), ["sentinel"])

    def test_client_home_with_trailing_slash(self):
        p = install._write_client_dir(os.path.join(self.d, "client") + os.sep, {"socket": "x"})
        self.assertEqual(p, os.path.join(self.d, "client", "config.json"))
        self.assertEqual(json.load(open(p)), {"socket": "x"})

    def test_writes_0600_config(self):
        p = install._write_client_config(self.d, {"socket": "x"})
        self.assertEqual(json.load(open(p)), {"socket": "x"})
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertTrue(os.path.isdir(os.path.join(self.d, ".tracekit-client", "runs")))


@unittest.skipUnless(CAN_SYMLINK, "needs symlinks")
class Settings(_Sentinel, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.p = os.path.join(self.d, ".claude", "settings.json")

    def test_symlinked_settings_is_refused(self):
        self.plant(self.p)
        with self.assertRaises(install.SettingsError):
            install.install_hooks(self.p)
        self.assertSentinelUntouched()

    def test_symlinked_settings_dir_is_refused(self):
        os.symlink(self.outside, os.path.join(self.d, ".claude"))
        with self.assertRaises(install.SettingsError):
            install.install_hooks(self.p)
        self.assertEqual(os.listdir(self.outside), ["sentinel"])

    def test_old_predictable_temp_and_backup_names_are_not_followed(self):
        os.makedirs(os.path.dirname(self.p))
        with open(self.p, "w") as f:
            json.dump({"theme": "dark"}, f)
        import time
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for name in (f"settings.json.tmp-{os.getpid()}", f"settings.json.bak-{stamp}"):
            self.plant(os.path.join(self.d, ".claude", name))
        install.install_hooks(self.p)
        self.assertSentinelUntouched()
        self.assertIn("PreToolUse", json.load(open(self.p))["hooks"])
        baks = [n for n in os.listdir(os.path.dirname(self.p)) if ".bak-" in n
                and not os.path.islink(os.path.join(self.d, ".claude", n))]
        self.assertEqual(len(baks), 1)
        bak = os.path.join(self.d, ".claude", baks[0])
        self.assertEqual(json.load(open(bak)), {"theme": "dark"})
        self.assertEqual(stat.S_IMODE(os.stat(bak).st_mode), 0o600)


class HookOwnership(unittest.TestCase):
    def test_a_users_own_hook_py_is_not_tracekits(self):
        """Any command naming "tracekit" and "hook.py" counted as Tracekit's: uninstall removed a user's own hook."""
        group = lambda c: {"hooks": [{"type": "command", "command": c}]}  # noqa: E731
        self.assertIsNone(install._hook_version(group("python3 ~/src/tracekit-dogfood/scripts/hook.py")))
        self.assertEqual(install._hook_version(group("python3 /src/tracekit/hook.py")), "v1")
        self.assertEqual(install._hook_version(group("python3 -m tracekit.hook")), "v1")
        for mine in ("python3 -m acme.tracekit.hooklog --stop", "python3 -m tracekit.hooks", "/x/acme-tracekit/hook.py",
                     "python3 -m acme.tracekit.integrations.claude_code"):
            self.assertIsNone(install._hook_version(group(mine)), mine)
        for module in ("tracekit.hook", install.V2_HOOK):
            for python in (None, install.OPT_PYTHON):
                cmd = install._hook_command(module, args=("PreToolUse",) * (module == install.V2_HOOK), python=python)
                self.assertEqual(install._hook_version(group(cmd)), "v2" if module == install.V2_HOOK else "v1", cmd)

    def test_a_persons_hook_in_tracekits_group_stays(self):
        """Uninstall and a v1<->v2 re-init dropped a whole group with a Tracekit hook in it, a person's own hook filed
        into it too."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "settings.json")
        mine = {"type": "command", "command": "~/bin/my-audit.sh"}
        stop = {"hooks": [{"type": "command", "command": "python3 -m acme.tracekit.hooklog --stop"}]}
        with open(p, "w") as f:
            json.dump({"hooks": {"Stop": [stop]}}, f)
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(p)
            s = install.read_json(p)
            s["hooks"]["PreToolUse"][0]["hooks"].append(mine)
            with open(p, "w") as f:
                json.dump(s, f)
            install.install_hooks(p, module=install.V2_HOOK)
            pre = install.read_json(p)["hooks"]["PreToolUse"]
            self.assertEqual(pre[0], {"matcher": "*", "hooks": [mine]})
            self.assertEqual([install._hook_version(g) for g in pre], [None, "v2"])
            self.assertEqual(len(pre[1]["hooks"]), 1)   # Tracekit's own group holds only its hook
            install.install_hooks(p, uninstall=True)
        self.assertEqual(install.read_json(p), {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [mine]}],
                                                          "Stop": [stop]}})


class HarnessFileWrites(unittest.TestCase):
    def test_non_ascii_stays_utf8_and_an_init_that_changes_nothing_writes_nothing(self):
        """Init wrote a person's non-ASCII text as \\u escapes, and each coding agent's file but Claude Code's was
        backed up by every init, even one that changed nothing."""
        from tracekit import agent_hooks
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        theme = "Café 日本"
        for harness in ("claude", *agent_hooks.HARNESSES):
            with self.subTest(harness):
                home = os.path.join(d, harness)
                path = os.path.join(home, ".claude", "settings.json") if harness == "claude" else \
                    agent_hooks.config_path(harness, home=home)
                os.makedirs(os.path.dirname(path))
                theirs = harness not in ("goose", "opencode")   # those two files are Tracekit's own plugin
                if theirs:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump({"theme": theme}, f, ensure_ascii=False)
                init = (lambda: install.install_hooks(path, module=install.V2_HOOK)) if harness == "claude" else \
                    (lambda: agent_hooks.install(harness, v2=True, path=path))
                with contextlib.redirect_stdout(io.StringIO()):
                    init()
                    files_then = sorted(os.listdir(os.path.dirname(path)))
                    init()
                self.assertEqual(sorted(os.listdir(os.path.dirname(path))), files_then)   # no new backup
                if theirs:
                    with open(path, "rb") as f:
                        self.assertIn(theme.encode("utf-8"), f.read())

    def test_a_lone_surrogate_in_the_file_still_lets_init_and_uninstall_finish(self):
        """With UTF-8 kept, a lone surrogate (valid JSON as \\ud83d, which UTF-8 can't encode) made init and uninstall
        raise, so uninstall left the fail-closed hooks in place."""
        from tracekit import agent_hooks
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for harness in ("claude", *(h for h in agent_hooks.HARNESSES if h not in ("goose", "opencode"))):
            with self.subTest(harness):
                home = os.path.join(d, harness)
                path = os.path.join(home, ".claude", "settings.json") if harness == "claude" else \
                    agent_hooks.config_path(harness, home=home)
                os.makedirs(os.path.dirname(path))
                with open(path, "w", encoding="utf-8") as f:
                    f.write('{"note": "\\ud83d"}\n')
                for uninstall in (False, True):
                    with contextlib.redirect_stdout(io.StringIO()):
                        if harness == "claude":
                            install.install_hooks(path, uninstall=uninstall, module=install.V2_HOOK)
                        else:
                            agent_hooks.install(harness, uninstall=uninstall, v2=True, path=path)
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                    self.assertEqual(json.loads(text)["note"], "\ud83d")
                    self.assertEqual("tracekit" in text, not uninstall)


@unittest.skipUnless(CAN_SYMLINK, "needs symlinks")
class SignerConfig(_Sentinel, unittest.TestCase):
    def test_symlinked_signer_config_is_refused(self):
        self.plant(os.path.join(self.d, "config.json"))
        with self.assertRaises(files.UnsafePath):
            install._write_signer_config(self.d, [], 50, "s")
        with self.assertRaises(files.UnsafePath):
            install._update_signer_config(self.d, {"x": 1})
        self.assertSentinelUntouched()

    def test_old_predictable_temp_name_is_not_followed(self):
        install._write_signer_config(self.d, [], 50, "s")
        self.plant(os.path.join(self.d, "config.json.tmp"))
        install._update_signer_config(self.d, {"x": 1})
        self.assertSentinelUntouched()
        self.assertEqual(json.load(open(os.path.join(self.d, "config.json")))["x"], 1)

    def test_rerun_keeps_the_policy_pin_and_harnesses_until_replaced(self):
        kept = {"pinned_policy_hash": "sha256:" + "1" * 64, "harnesses": [{"name": "claude", "exe": "/usr/bin/claude"}],
                "harness_binding": "enforce"}
        install._write_signer_config(self.d, [], 50, "s", extra=kept)
        cfg = install._write_signer_config(self.d, [], 50, "s")
        self.assertEqual({k: cfg[k] for k in kept}, kept)
        self.assertEqual(json.load(open(os.path.join(self.d, "config.json"))), cfg)
        new = [{"name": "codex", "exe": "/usr/bin/codex"}]
        self.assertEqual(install._write_signer_config(self.d, [], 50, "s", extra={"harnesses": new})["harnesses"], new)

    def test_rerun_keeps_the_witnesses_and_checkpoint_interval_unless_given(self):
        """A re-run without --witness replaced a remote witness with the local one and reset the interval to 50."""
        cfg = install._write_signer_config(self.d, [], None, "s")
        self.assertEqual((cfg["witnesses"], cfg["checkpoint_every"]), ([f"git:{os.path.join(self.d, 'witness')}"], 50))
        install._write_signer_config(self.d, ["git:/srv/witness@origin"], 10, "s")
        cfg = install._write_signer_config(self.d, [], None, "s")
        self.assertEqual((cfg["witnesses"], cfg["checkpoint_every"]), (["git:/srv/witness@origin"], 10))
        cfg = install._write_signer_config(self.d, ["file:/w.jsonl"], 7, "s")
        self.assertEqual((cfg["witnesses"], cfg["checkpoint_every"]), (["file:/w.jsonl"], 7))

    def test_signer_home_owned_by_someone_else_is_refused(self):
        other = type("pw", (), {"pw_uid": os.getuid() + 1, "pw_gid": os.getgid()})
        with self.assertRaises(files.UnsafePath):
            install._write_signer_config(self.d, [], 50, "s", tk_user=other)
        self.assertFalse(os.path.exists(os.path.join(self.d, "config.json")))


@unittest.skipIf(os.name == "nt", "POSIX modes")
class ModeFromCreation(unittest.TestCase):
    def test_temp_file_is_0600_before_rename_even_with_umask_0(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        seen = []
        real = os.replace

        def spy(src, dst, **kw):
            seen.append(stat.S_IMODE(os.stat(src, dir_fd=kw.get("src_dir_fd"), follow_symlinks=False).st_mode))
            return real(src, dst, **kw)
        old = os.umask(0)
        try:
            with mock.patch.object(files.os, "replace", spy):
                install._write_signer_config(d, [], 50, "s")
                install._write_client_config(d, {"socket": "x"})
                install.install_hooks(os.path.join(d, "settings.json"))
        finally:
            os.umask(old)
        self.assertEqual(seen, [0o600, 0o600, 0o600])


@unittest.skipIf(os.name == "nt", "POSIX fifos and fork")
class ReadAndDropPrivileges(unittest.TestCase):
    def test_read_refuses_a_fifo_without_blocking_or_stat_by_path(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.mkfifo(os.path.join(d, "config.json"))
        with mock.patch.object(files.os, "stat", side_effect=AssertionError("stat by path, then open")):
            with self.assertRaises(files.UnsafePath):
                files.read(d, "config.json")
            self.assertIsNone(files.read(d, "missing.json"))

    def test_as_user_uses_initgroups(self):
        pw = type("pw", (), {"pw_name": "bob", "pw_uid": 1001, "pw_gid": 1001})
        with mock.patch.object(files.os, "geteuid", return_value=0), mock.patch.object(files.os, "fork", return_value=0), \
                mock.patch.object(files.os, "initgroups", create=True) as initgroups, \
                mock.patch.object(files.os, "setgroups", create=True) as setgroups, \
                mock.patch.object(files.os, "setgid"), mock.patch.object(files.os, "setuid"), \
                mock.patch.object(files.os, "_exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):  # the forked child's exit, run in this process
                files.as_user(pw, lambda: 1)
        initgroups.assert_called_once_with("bob", 1001)
        setgroups.assert_not_called()


class DevTcpEndpoint(unittest.TestCase):
    def test_dev_socket_opens_no_socket(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch("tracekit.peercred.has_peer_credentials", return_value=False), \
                mock.patch.object(install.socket, "socket", side_effect=AssertionError("bound a probe socket")):
            sock, token = install._dev_socket(d)
        self.assertEqual(sock, "tcp://127.0.0.1:0")
        self.assertGreaterEqual(len(token), 32)

    def test_signer_binds_its_own_port_and_init_reads_it_back(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home = os.path.join(d, "signer")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(d, "client")
        try:
            with mock.patch("tracekit.peercred.has_peer_credentials", return_value=False):
                cfg = install.init_dev(home, [], start=True)
            try:
                signer_cfg = json.load(open(os.path.join(home, "config.json")))
                client_cfg = json.load(open(os.path.join(d, "client", "config.json")))
                self.assertRegex(signer_cfg["socket"], r"^tcp://127\.0\.0\.1:[1-9][0-9]*$")
                self.assertEqual(client_cfg["socket"], signer_cfg["socket"])
                self.assertEqual(client_cfg["socket_token"], signer_cfg["socket_token"])
                self.assertEqual(cfg["socket"], signer_cfg["socket"])
                self.assertTrue(install._signer_healthy(home))
            finally:
                install.stop_dev_daemon(home)
        finally:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)


@pytest.mark.root
@unittest.skipUnless(IS_ROOT and CAN_SYMLINK, "needs root to drop to another user")
class RootWritesAsUser(_Sentinel, unittest.TestCase):
    def setUp(self):
        super().setUp()
        import pwd
        self.user = pwd.getpwnam("nobody")
        os.chmod(self.d, 0o755)
        self.home = os.path.join(self.d, "home")
        os.mkdir(self.home, 0o755)
        os.chown(self.home, self.user.pw_uid, self.user.pw_gid)
        # the sentinel is root's 0640 file: only a write that kept root's privileges could touch it

    def test_client_config_is_written_as_the_user_and_symlink_refused(self):
        p = install._write_client_config(self.home, {"socket": "x"}, self.user)
        self.assertEqual(os.stat(p).st_uid, self.user.pw_uid)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        os.remove(p)
        os.symlink(self.sentinel, p)
        with self.assertRaises(files.UnsafePath):
            install._write_client_config(self.home, {"socket": "x"}, self.user)
        self.assertSentinelUntouched()

    def test_settings_are_written_as_the_user_and_symlink_refused(self):
        p = os.path.join(self.home, ".claude", "settings.json")
        install.install_hooks(p, owner=self.user)
        self.assertEqual(os.stat(p).st_uid, self.user.pw_uid)
        os.remove(p)
        os.symlink(self.sentinel, p)
        with self.assertRaises(install.SettingsError):
            install.install_hooks(p, owner=self.user)
        self.assertSentinelUntouched()

    def test_signer_config_is_fchowned_and_symlink_refused(self):
        os.chown(self.d, self.user.pw_uid, self.user.pw_gid)
        install._write_signer_config(self.d, [], 50, "s", tk_user=self.user)
        st = os.stat(os.path.join(self.d, "config.json"))
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (self.user.pw_uid, 0o600))
        os.remove(os.path.join(self.d, "config.json"))
        os.symlink(self.sentinel, os.path.join(self.d, "config.json"))
        with self.assertRaises(files.UnsafePath):
            install._write_signer_config(self.d, [], 50, "s", tk_user=self.user)
        self.assertSentinelUntouched()


@pytest.mark.root
@unittest.skipUnless(IS_ROOT and sys.platform.startswith("linux"), "needs root on Linux to create the signer's user")
class SystemV2Install(unittest.TestCase):
    """`tracekit init --v2` for real (users, ownership, modes), then `uninstall --v2 --purge`, under a temp root. The
    venv build and the service are left out: E8 v2 runs those."""

    def test_install_then_purge(self):
        import pwd
        from tracekit import client
        from tracekit.signer import service
        base = tempfile.mkdtemp(dir="/var/lib")   # root-owned all the way up, as a trusted --policy must be
        self.addCleanup(shutil.rmtree, base, True)
        os.chmod(base, 0o755)
        agent = pwd.getpwnam("nobody")
        project = os.path.join(base, "project")
        os.mkdir(project, 0o755)
        os.chown(project, agent.pw_uid, agent.pw_gid)
        policy = os.path.join(base, "policy.yaml")
        with open(policy, "w") as f:
            f.write("version: test\n")
        etc = os.path.join(base, "etc")
        patches = [mock.patch.object(install, k, v) for k, v in {
            "V2_DATA": os.path.join(base, "data"), "V2_CONFIG": os.path.join(etc, "signer.yaml"), "SYSTEMD_DIR": base,
            "OPT": os.path.join(base, "opt"), "V2_USER": "tk-test-signer", "V2_UNIT": "tk-test-signer",
            "V2_TAILER": "tk-test-tailer", "TAILER_SUDOERS": os.path.join(base, "sudoers"),
            "_install_source": mock.Mock(return_value=None), "_install_venv": mock.Mock()}.items()]
        patches.append(mock.patch.object(client, "SYSTEM_CONFIG", os.path.join(etc, "client.json")))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(subprocess.run, ["userdel", "tk-test-signer"], capture_output=True)
        self.addCleanup(subprocess.run, ["userdel", "tk-test-tailer"], capture_output=True)
        sock, settings = install.init_system_v2("nobody", approver="root", policy=policy, project=project,
                                                no_service=True)
        sig = pwd.getpwnam("tk-test-signer")
        st = os.stat(install.V2_DATA)
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (sig.pw_uid, 0o700))
        for p in (install.V2_CONFIG, client.SYSTEM_CONFIG):
            st = os.stat(p)
            self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o644))
        cfg = service.load_config(install.V2_CONFIG)
        self.assertEqual(cfg["approvals"], {"self_approval": "deny", "approvers": ["uid:0"]})
        self.assertEqual(cfg["tenants"], {f"uid:{agent.pw_uid}": "nobody", "uid:0": "nobody"})
        self.assertEqual(client.system_config()["signer"], sock)
        self.assertEqual(os.stat(settings).st_uid, agent.pw_uid)
        with open(settings) as f:
            s = json.load(f)
        self.assertEqual(s["env"], {"TRACEKIT_SIGNER": sock})
        self.assertIn(f"{install.OPT_PYTHON} -I -m {install.V2_HOOK}", s["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
        self.assertEqual(install.uninstall_system_v2(purge=True), [])
        for p in (install.V2_DATA, install.V2_CONFIG, client.SYSTEM_CONFIG):
            self.assertFalse(os.path.exists(p), p)
        with open(settings) as f:
            self.assertEqual(json.load(f), {})
        for user in ("tk-test-signer", "tk-test-tailer"):
            with self.assertRaises(KeyError):
                pwd.getpwnam(user)


class ClaudeConfigDir(unittest.TestCase):
    def test_hooks_go_to_and_are_found_in_claude_config_dir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": d}):
            path = install.user_settings()
            self.assertEqual(path, os.path.join(d, "settings.json"))
            install.install_hooks(path)
            self.assertIn(path, [h["settings"] for h in install._installed_hooks()])
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(install.user_settings(), os.path.join(os.path.expanduser("~"), ".claude", "settings.json"))

    def test_init_dev_records_where_it_put_the_hooks(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, "cfg", "settings.json")
        os.makedirs(os.path.dirname(settings))
        with mock.patch.dict(os.environ, {"TRACEKIT_CLIENT_HOME": os.path.join(d, "client")}):
            install.init_dev(os.path.join(d, "sig"), [], start=False, hooks_path=settings)
        self.assertEqual(install.read_json(os.path.join(d, "client", "config.json"))["hooks_settings"], settings)

    def test_v2_init_records_where_it_put_the_hooks(self):
        """init --dev --v2 or --remote --v2 with CLAUDE_CONFIG_DIR set: doctor finds the hooks and uninstall removes
        every one from a shell without it (they stayed, and blocked every call once tracekit was gone)."""
        from tracekit import cli, doctor
        token = tempfile.NamedTemporaryFile(delete=False)
        token.close()
        self.addCleanup(os.remove, token.name)
        for argv in (["init", "--dev", "--v2"],
                     ["init", "--remote", "https://signer.example", "--v2", "--token-file", token.name]):
            with self.subTest(argv[1]):
                d = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, d, True)
                settings, client_home = os.path.join(d, "conf", "settings.json"), os.path.join(d, "client")
                install._write_client_dir(client_home, {"socket": "s"})   # an earlier init's client config
                env = {"HOME": d, "USERPROFILE": d, "XDG_DATA_HOME": d, "TRACEKIT_CLIENT_HOME": client_home}
                with mock.patch.dict(os.environ, dict(env, CLAUDE_CONFIG_DIR=os.path.dirname(settings))), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(argv), 0)
                self.assertEqual(install._hook_summary(install.read_json(settings))["versions"], ["v2"])
                self.assertEqual(install.read_json(os.path.join(client_home, "config.json")),
                                 {"socket": "s", "hooks_settings": settings})
                with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(doctor._dev_settings(), settings)
                    self.assertEqual(install.uninstall(), settings)
                self.assertEqual(install.read_json(settings).get("hooks"), None)

    def test_hooks_are_found_and_removed_with_or_without_claude_config_dir(self):
        for installed_with, removed_with in ((True, False), (False, True)):
            with self.subTest(installed_with_env=installed_with):
                home, cfg = tempfile.mkdtemp(), tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, home, True)
                self.addCleanup(shutil.rmtree, cfg, True)
                os.makedirs(os.path.join(home, ".claude"))
                env = lambda on: mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home,   # Windows' ~
                                                              **({"CLAUDE_CONFIG_DIR": cfg} if on else {})})
                with env(installed_with):
                    if not installed_with:
                        os.environ.pop("CLAUDE_CONFIG_DIR", None)
                    path = install.user_settings()
                    install.install_hooks(path)
                recorded = {"hooks_settings": path}   # what `tracekit init` writes to the client config
                with env(removed_with), mock.patch.object(install.client, "client_config", return_value=recorded):
                    if not removed_with:
                        os.environ.pop("CLAUDE_CONFIG_DIR", None)
                    self.assertIn(path, [h["settings"] for h in install._installed_hooks()])
                    self.assertEqual(install.uninstall(), path)   # it named files it never found
                    self.assertEqual(install._hook_summary(install.read_json(path)), install._hook_summary({}))


if __name__ == "__main__":
    unittest.main()
