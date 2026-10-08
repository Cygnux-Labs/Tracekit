"""Installer writes never follow a planted symlink, create files 0600 from the start, and dev TCP has no port race."""
import json
import os
import stat
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
        self.outside = tempfile.mkdtemp()
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

    def test_signer_home_owned_by_someone_else_is_refused(self):
        other = type("pw", (), {"pw_uid": os.getuid() + 1, "pw_gid": os.getgid()})
        with self.assertRaises(files.UnsafePath):
            install._write_signer_config(self.d, [], 50, "s", tk_user=other)
        self.assertFalse(os.path.exists(os.path.join(self.d, "config.json")))


@unittest.skipIf(os.name == "nt", "POSIX modes")
class ModeFromCreation(unittest.TestCase):
    def test_temp_file_is_0600_before_rename_even_with_umask_0(self):
        d = tempfile.mkdtemp()
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


class DevTcpEndpoint(unittest.TestCase):
    def test_dev_socket_opens_no_socket(self):
        with mock.patch("tracekit.peercred.has_peer_credentials", return_value=False), \
                mock.patch.object(install.socket, "socket", side_effect=AssertionError("bound a probe socket")):
            sock, token = install._dev_socket(tempfile.mkdtemp())
        self.assertEqual(sock, "tcp://127.0.0.1:0")
        self.assertGreaterEqual(len(token), 32)

    def test_signer_binds_its_own_port_and_init_reads_it_back(self):
        d = tempfile.mkdtemp()
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


if __name__ == "__main__":
    unittest.main()
