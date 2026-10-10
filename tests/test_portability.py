"""macOS and Windows paths, exercised with mocks: this suite runs on Linux CI, so it proves the parsing,
the generated files and the refusal logic, not behaviour on real hardware (see docs/portability.md)."""
import os
import plistlib
import struct
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install, peercred  # noqa: E402


class FakeConn:
    def __init__(self, table):
        self.table = table

    def getsockopt(self, level, opt, size):
        try:
            return self.table[(level, opt)]
        except KeyError:
            raise OSError("no such option")


def xucred(uid, version=0, groups=(20,)):
    gs = list(groups) + [0] * (16 - len(groups))
    return struct.pack(peercred._XUCRED_FMT, version, uid, len(groups), *gs)


class MacPeerCred(unittest.TestCase):
    def test_xucred_parse(self):
        self.assertEqual(peercred.parse_xucred(xucred(501)), 501)
        self.assertIsNone(peercred.parse_xucred(xucred(501, version=9)))   # unknown struct version: not attested
        self.assertIsNone(peercred.parse_xucred(b"\x00" * 4))

    def test_peer_on_darwin_uses_local_peercred(self):
        conn = FakeConn({(0, peercred.LOCAL_PEERCRED): xucred(501), (0, peercred.LOCAL_PEERPID): struct.pack("i", 4242)})
        saved = getattr(peercred.socket, "SO_PEERCRED", None)  # present on Linux, absent on macOS
        if saved is not None:
            del peercred.socket.SO_PEERCRED
        try:
            with mock.patch.object(peercred.sys, "platform", "darwin"):
                self.assertEqual(peercred.peer(conn), (4242, 501))
        finally:
            if saved is not None:
                peercred.socket.SO_PEERCRED = saved

    def test_pid_failure_still_attests_uid(self):
        conn = FakeConn({(0, peercred.LOCAL_PEERCRED): xucred(502)})
        with mock.patch.object(peercred.sys, "platform", "darwin"):
            if hasattr(peercred.socket, "SO_PEERCRED"):
                with mock.patch.object(peercred.socket, "SO_PEERCRED", create=True):
                    delattr(peercred.socket, "SO_PEERCRED")
                    self.assertEqual(peercred.peer(conn), (None, 502))
            else:
                self.assertEqual(peercred.peer(conn), (None, 502))

    def test_unattestable_platform_returns_none(self):
        with mock.patch.object(peercred.sys, "platform", "win32"):
            if not hasattr(peercred.socket, "SO_PEERCRED"):
                self.assertEqual(peercred.peer(FakeConn({})), (None, None))
                self.assertFalse(peercred.has_peer_credentials())

    def test_ps_line_parsing(self):
        self.assertEqual(peercred.parse_ps_line("  812 ttys003 /usr/bin/zsh\n")[:2], ("zsh", 812))
        self.assertGreater(peercred.parse_ps_line("812 ttys003 zsh")[2], 0)
        self.assertEqual(peercred.parse_ps_line("1 ?? launchd")[2], 0)
        self.assertIsNone(peercred.parse_ps_line(""))
        self.assertIsNone(peercred.parse_ps_line("x y z"))


class MacSystemMode(unittest.TestCase):
    def test_plist_is_valid_and_runs_as_the_signer_account(self):
        data = install.launchd_plist("dev.tracekit.tracekitd", "_tracekit", "/usr/bin/python3", "tracekit.daemon",
                                     "/var/lib/tracekit")
        p = plistlib.loads(data)
        self.assertEqual(p["UserName"], "_tracekit")
        self.assertEqual(p["ProgramArguments"], ["/usr/bin/python3", "-I", "-m", "tracekit.daemon", "--home", "/var/lib/tracekit"])
        self.assertTrue(p["KeepAlive"] and p["RunAtLoad"])
        self.assertNotIn("EnvironmentVariables", p)

    def test_refused_without_experimental_flag(self):
        with mock.patch.object(install.sys, "platform", "darwin"):
            with self.assertRaises(SystemExit) as cm:
                install.init_system("bob", [], experimental_macos=False)
        self.assertIn("--experimental-macos", str(cm.exception))

    def test_unsupported_platform_refused(self):
        with mock.patch.object(install.sys, "platform", "win32"):
            with self.assertRaises(SystemExit):
                install.init_system("bob", [])

    def test_user_creation_steps_and_free_id(self):
        calls = []

        def fake_dscl(*args):
            calls.append(args)
            if args[0] == "-list":
                out = "root 0\n_tracekit_other 399\nnobody -2\n" if args[1] == "/Users" else "wheel 0\n_x 398\n"
                return mock.Mock(returncode=0, stdout=out, stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(install, "_dscl", fake_dscl):
            install._create_system_user_darwin("_tracekit")
        created = [c for c in calls if c[0] == "-create"]
        ids = {c[3] for c in created if len(c) > 3 and c[2] in ("UniqueID", "PrimaryGroupID")}
        self.assertEqual(ids, {"397"})  # 399 and 398 are taken
        self.assertIn(("-create", "/Users/_tracekit", "UserShell", "/usr/bin/false"), created)
        self.assertIn(("-create", "/Users/_tracekit", "IsHidden", "1"), created)

    def test_user_creation_failure_is_reported(self):
        def fake_dscl(*args):
            return mock.Mock(returncode=0 if args[0] == "-list" else 1, stdout="", stderr="eDSPermissionError")
        with mock.patch.object(install, "_dscl", fake_dscl):
            with self.assertRaises(SystemExit) as cm:
                install._create_system_user_darwin("_tracekit")
        self.assertIn("eDSPermissionError", str(cm.exception))


class WindowsPaths(unittest.TestCase):
    def test_dev_socket_falls_back_to_tokened_tcp_without_peer_credentials(self):
        with mock.patch("tracekit.peercred.has_peer_credentials", return_value=False):
            sock, token = install._dev_socket("/tmp/x")
        self.assertTrue(sock.startswith("tcp://127.0.0.1:"))
        self.assertGreaterEqual(len(token), 32)

    def test_hook_command_on_windows_has_no_shell_env_prefix(self):
        with mock.patch.object(install.os, "name", "nt"):
            cmd = install._hook_command()
        self.assertNotIn("env PYTHONPATH", cmd)


class PluginPackage(unittest.TestCase):
    def test_plugin_hooks_match_the_installer_exactly(self):
        import json
        with open(os.path.join(ROOT, "plugin", "hooks", "hooks.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertEqual(set(hooks), set(install.TOOL_EVENTS + install.OTHER_EVENTS))
        for ev, groups in hooks.items():
            h = groups[0]["hooks"][0]
            self.assertEqual(h["command"], "${CLAUDE_PLUGIN_ROOT}/bin/tracekit-hook")
            self.assertEqual(h["timeout"], install.HOOK_TIMEOUT.get(ev, 30), ev)
            self.assertEqual(groups[0].get("matcher") == "*", ev in install.TOOL_EVENTS, ev)

    def test_manifests_parse_and_versions_agree(self):
        import json
        import tracekit
        with open(os.path.join(ROOT, "plugin", ".claude-plugin", "plugin.json")) as f:
            plugin = json.load(f)
        with open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")) as f:
            market = json.load(f)
        self.assertEqual(plugin["version"], tracekit.__version__.replace("rc", "-rc.").replace(".dev", "-dev."))
        self.assertEqual(market["plugins"][0]["source"], "./plugin")
        self.assertEqual(market["plugins"][0]["name"], plugin["name"])

    @unittest.skipIf(sys.platform == "win32", "the plugin wrapper is POSIX shell")
    def test_wrapper_is_executable_and_fails_open_with_a_notice(self):
        import subprocess
        script = os.path.join(ROOT, "plugin", "bin", "tracekit-hook")
        self.assertTrue(os.access(script, os.X_OK))
        r = subprocess.run(["/bin/sh", script], input="{}", capture_output=True, text=True,
                           env={"PATH": "/nonexistent", "TRACEKIT_PYTHON": ""})
        self.assertEqual(r.returncode, 0)
        self.assertIn("NOT recorded", r.stderr)


if __name__ == "__main__":
    unittest.main()
