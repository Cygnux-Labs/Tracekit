"""System mode runs from a root-owned virtualenv, refuses privileged agent users, keeps the ledger 0640;
`tracekit doctor` flags agent-modifiable code; action.yml passes inputs to shell only through env."""
import contextlib
import io
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

from tracekit import install
from tracekit.ledger import Keys, Ledger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
POLICY = os.path.join(install.OPT, "lib", "python3", "site-packages", "tracekit", "policy", "default.yaml")


@contextlib.contextmanager
def as_root_on_linux():
    with mock.patch.object(install.sys, "platform", "linux"), mock.patch.object(install.os, "geteuid", return_value=0):
        yield


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class SystemModeUsesOpt(unittest.TestCase):
    def test_units_hooks_key_and_policy_point_at_opt(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home, units = os.path.join(d, "home"), os.path.join(d, "units")
        os.makedirs(units)
        me = install.pwd.getpwuid(os.getuid())
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        with as_root_on_linux(), \
                mock.patch.object(install, "SYS_HOME", home), mock.patch.object(install, "SYSTEMD_DIR", units), \
                mock.patch.object(install.pwd, "getpwnam", return_value=me), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "harness_config", return_value={"harness_binding": "off"}), \
                mock.patch.object(install, "_install_venv", return_value=POLICY), \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install, "_write_client_config"), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "_pin_policy"), \
                mock.patch.object(install, "install_hooks") as hooks, \
                contextlib.redirect_stdout(io.StringIO()):
            install.init_system("agent", [], proxy=True)
        for name, module in (("tracekitd.service", "tracekit.daemon"), ("tracekit-proxy.service", "tracekit.proxy")):
            with open(os.path.join(units, name)) as f:
                unit = f.read()
            self.assertIn(f"ExecStart={install.OPT_PYTHON} -I -m {module} ", unit)
            self.assertNotIn("PYTHONPATH", unit)
            self.assertIn("UMask=0027", unit)
        keygen = next(c.args[0] for c in run.call_args_list if "Keys.load_or_create" in " ".join(c.args[0]))
        self.assertIn(install.OPT_PYTHON, keygen)
        self.assertEqual(hooks.call_args.kwargs["python"], install.OPT_PYTHON)
        self.assertEqual(sys_cfg.call_args.args[0]["policy"], POLICY)
        for sub in ("ledger", "blobs"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(home, sub)).st_mode), 0o750)

    def test_migrate_keeps_a_policy_path(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "config.json"), "w") as f:
            f.write("{}")
        me = install.pwd.getpwuid(os.getuid())
        for existing, expected in (({"policy": "/etc/tracekit/p.yaml"}, "/etc/tracekit/p.yaml"), (None, POLICY)):
            with as_root_on_linux(), mock.patch.object(install, "SYS_HOME", d), \
                    mock.patch.object(install, "SYSTEMD_DIR", d), \
                    mock.patch.object(install.client, "system_config", return_value=existing), \
                    mock.patch.object(install.os.path, "exists", return_value=True), \
                    mock.patch.object(install, "_opt_default_policy", return_value=POLICY), \
                    mock.patch.object(install.pwd, "getpwnam", return_value=me), \
                    mock.patch.object(install, "harness_config", return_value={}), \
                    mock.patch.object(install, "_update_signer_config"), \
                    mock.patch.object(install, "_pin_policy", return_value="sha256:" + "0" * 64), \
                    mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                    contextlib.redirect_stdout(io.StringIO()):
                install.migrate_system()
            self.assertEqual(sys_cfg.call_args.args[0]["policy"], expected)

    def test_hook_command_runs_the_opt_interpreter(self):
        self.assertTrue(install._hook_command(python=install.OPT_PYTHON).startswith(f"{install.OPT_PYTHON} -I -m tracekit.hook"))


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class PrivilegedAgentRefused(unittest.TestCase):
    def init(self, pw, groups, **kw):
        names = {27: "docker", 1001: "bob"}

        def getgrgid(gid):
            if gid not in names:
                raise KeyError(gid)
            return types.SimpleNamespace(gr_name=names[gid])
        with as_root_on_linux(), mock.patch.object(install.pwd, "getpwnam", return_value=pw), \
                mock.patch.object(install.os, "getgrouplist", return_value=groups, create=True), \
                mock.patch.object(install.grp, "getgrgid", getgrgid):
            return install.init_system("bob", [], **kw)

    def test_docker_member_refused(self):
        with self.assertRaises(SystemExit) as cm:
            self.init(types.SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name="bob"), [1001, 27])
        self.assertIn("docker", str(cm.exception))
        self.assertIn("--i-understand-agent-is-privileged", str(cm.exception))

    def test_root_refused(self):
        with self.assertRaises(SystemExit) as cm:
            self.init(types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_name="root"), [0])
        self.assertIn("root", str(cm.exception))

    def test_unprivileged_user_passes_the_check(self):
        with mock.patch.object(install.os, "getgrouplist", return_value=[1001, 4242], create=True), \
                mock.patch.object(install.grp, "getgrgid", side_effect=KeyError):
            self.assertEqual(install._privileges(types.SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name="bob")), [])


class LedgerMode(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_ledger_created_0640(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        led = Ledger(os.path.join(d, "ledger", "ledger.jsonl"), Keys.load_or_create(os.path.join(d, "keys")))
        self.addCleanup(led.close)
        self.assertEqual(stat.S_IMODE(os.stat(led.path).st_mode), 0o640)


@unittest.skipIf(os.name == "nt", "POSIX ownership")
class Doctor(unittest.TestCase):
    def run_doctor(self, checks):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            return install.doctor(checks), out.getvalue()

    def test_fails_when_package_dir_is_agent_writable(self):
        pkg = tempfile.mkdtemp()  # owned by this (non-root) user, or under world-writable /tmp
        self.addCleanup(shutil.rmtree, pkg, True)
        code, out = self.run_doctor([("tracekit package", pkg, "reinstall")])
        self.assertEqual(code, 1)
        self.assertIn("FAIL  tracekit package", out)
        self.assertIn("fix: reinstall", out)

    def test_fails_without_a_system_install(self):
        with mock.patch.object(install.client, "system_config", return_value=None):
            self.assertEqual(self.run_doctor(None)[0], 1)

    @unittest.skipUnless(IS_ROOT and os.path.isdir("/var/lib"), "needs root to make a root-owned package dir")
    def test_passes_when_root_owned_and_fails_once_writable(self):
        pkg = tempfile.mkdtemp(dir="/var/lib")
        self.addCleanup(shutil.rmtree, pkg, True)
        os.chmod(pkg, 0o755)
        f = os.path.join(pkg, "daemon.py")
        open(f, "w").close()
        os.chmod(f, 0o644)
        self.assertEqual(self.run_doctor([("tracekit package", pkg, "reinstall")])[0], 0)
        os.chmod(f, 0o666)
        self.assertEqual(self.run_doctor([("tracekit package", pkg, "reinstall")])[0], 1)


class ActionInputs(unittest.TestCase):
    def test_no_input_expression_inside_run_blocks(self):
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as f:
            lines = f.read().splitlines()
        in_run, indent, bad = False, 0, []
        for n, line in enumerate(lines, 1):
            body = line.lstrip(" -")
            ind = len(line) - len(line.lstrip(" "))
            if in_run and line.strip() and ind <= indent:
                in_run = False
            if body.startswith("run:"):
                in_run, indent = True, ind
            if in_run and "${{" in line:
                bad.append(f"{n}: {line.strip()}")
        self.assertEqual(bad, [])

    def test_require_anchor_defaults_true(self):
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as f:
            text = f.read()
        block = text.split("  require-anchor:", 1)[1].split("\n  version:", 1)[0]
        self.assertIn('default: "true"', block)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
