"""System mode runs from a root-owned virtualenv, refuses privileged agent users, keeps the ledger 0640;
`tracekit doctor` flags agent-modifiable code; action.yml passes inputs to shell only through env."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import pytest

from tracekit import __version__, client, install
from tracekit.ledger import Keys, Ledger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
POLICY = os.path.join(install.OPT, "lib", "python3", "site-packages", "tracekit", "policy", "default.yaml")
V2_KEYS = {"signer": "/run/tracekit-signer/signer.sock", "hooks": {"user": "agent", "settings": None}}


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
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_install_venv", return_value=POLICY), \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install, "_write_client_config"), \
                mock.patch.object(install.client, "system_config", return_value=dict(V2_KEYS, mode="system")), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "_pin_policy"), \
                mock.patch.object(install, "install_hooks") as hooks, \
                contextlib.redirect_stdout(io.StringIO()) as out:
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
        self.assertLessEqual(V2_KEYS.items(), sys_cfg.call_args.args[0].items())  # a v2 install keeps its signer pin
        for sub in ("ledger", "blobs"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(home, sub)).st_mode), 0o750)
        cmds = [c.args[0] for c in run.call_args_list]
        self.assertIn(["systemctl", "restart", "tracekitd", "tracekit-proxy"], cmds)
        self.assertFalse([c for c in cmds if "--now" in c])
        self.assertIn("restarted tracekitd and tracekit-proxy", out.getvalue())

    def test_rerun_without_harness_keeps_the_registered_binding(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home, units = os.path.join(d, "home"), os.path.join(d, "units")
        os.makedirs(home)
        os.makedirs(units)
        harnesses = [{"exe": "/usr/local/bin/claude", "sha256": "ab" * 32}]
        with open(os.path.join(home, "config.json"), "w") as f:
            json.dump({"harnesses": harnesses, "harness_binding": "enforce"}, f)
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        with as_root_on_linux(), \
                mock.patch.object(install, "SYS_HOME", home), mock.patch.object(install, "SYSTEMD_DIR", units), \
                mock.patch.object(install.pwd, "getpwnam", return_value=install.pwd.getpwuid(os.getuid())), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "harness_config", return_value={"harness_binding": "off"}) as hc, \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_install_venv", return_value=POLICY), \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install, "_write_client_config"), \
                mock.patch.object(install, "_write_system_client_config"), \
                mock.patch.object(install, "_pin_policy"), \
                mock.patch.object(install, "install_hooks"), \
                contextlib.redirect_stdout(io.StringIO()):
            install.init_system("agent", [])
        hc.assert_not_called()
        with open(os.path.join(home, "config.json")) as f:
            cfg = json.load(f)
        self.assertEqual((cfg["harness_binding"], cfg["harnesses"]), ("enforce", harnesses))
        with open(os.path.join(units, "tracekitd.service")) as f:
            self.assertIn(install.UNIT_CAPS, f.read())

    def test_source_is_checked_before_any_system_change(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home = os.path.join(d, "home")
        run = mock.Mock()
        with as_root_on_linux(), mock.patch.object(install, "SYS_HOME", home), \
                mock.patch.object(install.pwd, "getpwnam", return_value=install.pwd.getpwuid(os.getuid())), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", side_effect=SystemExit("untrusted source")), \
                mock.patch.object(install.subprocess, "run", run):
            with self.assertRaises(SystemExit):
                install.init_system("agent", [])
        run.assert_not_called()
        self.assertFalse(os.path.exists(home))

    def migrate_dir(self, signer_cfg="{}", exec_python=install.OPT_PYTHON):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "config.json"), "w") as f:
            f.write(signer_cfg)
        with open(os.path.join(d, "tracekitd.service"), "w") as f:
            f.write(install.UNIT.format(user="tracekit", python=exec_python, home=d, caps=""))
        return d

    def test_migrate_refuses_an_install_without_the_root_owned_runtime(self):
        d = self.migrate_dir(exec_python="/usr/bin/python3")
        with as_root_on_linux(), mock.patch.object(install, "SYS_HOME", d), mock.patch.object(install, "SYSTEMD_DIR", d), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg:
            with self.assertRaises(SystemExit) as cm:
                install.migrate_system()
        self.assertIn("predates the root-owned runtime", str(cm.exception))
        sys_cfg.assert_not_called()

    def test_migrate_keeps_the_harness_binding_unless_given(self):
        d = self.migrate_dir('{"harnesses": [{"name": "claude", "exe": "/usr/bin/claude"}], "harness_binding": "enforce"}')
        me = install.pwd.getpwuid(os.getuid())
        for given, called in (([], False), (["/usr/bin/claude"], True)):
            with as_root_on_linux(), mock.patch.object(install, "SYS_HOME", d), \
                    mock.patch.object(install, "SYSTEMD_DIR", d), \
                    mock.patch.object(install.client, "system_config", return_value={"policy": POLICY}), \
                    mock.patch.object(install.pwd, "getpwnam", return_value=me), \
                    mock.patch.object(install, "harness_config", return_value={}) as hcfg, \
                    mock.patch.object(install, "_update_signer_config") as update, \
                    mock.patch.object(install, "_pin_policy", return_value="sha256:" + "0" * 64), \
                    mock.patch.object(install, "_write_system_client_config"), \
                    contextlib.redirect_stdout(io.StringIO()):
                install.migrate_system(harnesses=given)
            self.assertEqual(hcfg.called, called)
            if not called:
                self.assertEqual(update.call_args.args[1], {})

    def test_migrate_keeps_a_policy_path(self):
        d = self.migrate_dir()
        me = install.pwd.getpwuid(os.getuid())
        for existing, expected in (({"policy": "/etc/tracekit/p.yaml", **V2_KEYS}, "/etc/tracekit/p.yaml"), (None, POLICY)):
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
            self.assertEqual(sys_cfg.call_args.args[0].get("signer"), existing and V2_KEYS["signer"])

    def test_release_install_pins_the_pypi_name_and_version(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(install, "ROOT", d), \
                mock.patch("tracekit.daemon.trusted_file", return_value=None):
            req = install._install_source()
        self.assertEqual(req[-1], f"tracekit-ai=={__version__}")
        self.assertEqual("--pre" in req, any(c.isalpha() for c in __version__))

    def test_agent_writable_checkout_is_refused(self):
        src = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, src, True)
        open(os.path.join(src, "pyproject.toml"), "w").close()
        vcs = os.path.join(src, ".git")
        os.makedirs(vcs)
        open(os.path.join(vcs, "config"), "w").close()

        def trusted_file(p):
            return None if p in (sys.executable, os.path.dirname(os.__file__), src) or p.startswith(vcs) else f"{p} is mine"
        with mock.patch.object(install, "ROOT", src), mock.patch("tracekit.daemon.trusted_file", trusted_file):
            with self.assertRaises(SystemExit) as cm:
                install._install_source()
        self.assertIn("pyproject.toml is mine", str(cm.exception))
        self.assertIn("sudo git clone https://github.com/Cygnux-Labs/Tracekit /usr/local/src/Tracekit", str(cm.exception))
        with mock.patch.object(install, "ROOT", src), \
                mock.patch("tracekit.daemon.trusted_file", lambda p: f"{p} is mine" if p.startswith(vcs) else None):
            self.assertIsNone(install._install_source())  # the repository metadata is not installed

    def opt(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        opt = os.path.join(d, "tracekit")
        os.makedirs(os.path.join(opt, "bin"))
        with open(os.path.join(opt, "bin", "old"), "w") as f:
            f.write("old")
        return opt

    def test_failed_reinstall_leaves_opt_untouched(self):
        opt = self.opt()

        def run(cmd, **kw):
            if "venv" in cmd:
                os.makedirs(os.path.join(cmd[-1], "bin"))
            if "pip" in cmd:
                raise subprocess.CalledProcessError(1, cmd)
        with mock.patch.object(install, "OPT", opt), mock.patch.object(install.subprocess, "run", side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                install._install_venv(["tracekit-ai==0"])
        self.assertEqual(os.listdir(opt), ["bin"])
        self.assertEqual(os.listdir(os.path.join(opt, "bin")), ["old"])

    def test_reinstall_swaps_in_a_venv_built_from_a_copy(self):
        opt = self.opt()
        seen = {}

        def run(cmd, **kw):
            if "venv" in cmd:
                os.makedirs(os.path.join(cmd[-1], "bin"))
                open(os.path.join(cmd[-1], "bin", "new"), "w").close()
            if "pip" in cmd:
                seen["src"] = cmd[-1]
                seen["copied"] = os.path.isfile(os.path.join(cmd[-1], "pyproject.toml"))
        with mock.patch.object(install, "OPT", opt), mock.patch.object(install.subprocess, "run", side_effect=run), \
                mock.patch.object(install.os, "lchown"), \
                mock.patch.object(install, "_opt_default_policy", return_value=POLICY):
            self.assertEqual(install._install_venv(None), POLICY)
        self.assertEqual(os.listdir(os.path.join(opt, "bin")), ["new"])
        self.assertEqual(sorted(os.listdir(os.path.dirname(opt))), ["tracekit"])
        self.assertTrue(seen["copied"])
        self.assertNotEqual(seen["src"], install.ROOT)
        self.assertFalse(os.path.exists(seen["src"]))

    def test_hook_command_runs_the_opt_interpreter(self):
        self.assertIn(f"{install.OPT_PYTHON} -I -m tracekit.hook;", install._hook_command(python=install.OPT_PYTHON))

    def test_hook_command_fails_closed_without_the_package(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = os.path.join(d, "client.json")

        def run(status, fail_mode=None):
            py = os.path.join(d, "python")
            with open(py, "w") as f:
                f.write(f"#!/bin/sh\necho 'No module named tracekit' >&2\nexit {status or 0}\n")
            os.chmod(py, 0o755)
            if fail_mode:
                with open(cfg, "wb") as f:
                    f.write(install.files.json_bytes({"fail_mode": fail_mode}))
            with mock.patch.object(client, "SYSTEM_CONFIG", cfg):
                cmd = install._hook_command(python=py if status is not None else os.path.join(d, "missing"))
            return subprocess.run(cmd, shell=True, input="{}", capture_output=True, text=True).returncode
        self.assertEqual(run(1), 2)
        self.assertEqual(run(None), 2)  # no interpreter at all
        self.assertEqual(run(0), 0)
        self.assertEqual(run(1, "closed"), 2)
        self.assertEqual(run(1, "open"), 0)
        self.assertEqual(run(2, "open"), 2)


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

    def test_container_and_disk_groups_refused(self):
        for name in ("lxd", "libvirt", "disk"):
            with mock.patch.object(install.os, "getgrouplist", return_value=[1001, 4242], create=True), \
                    mock.patch.object(install.grp, "getgrgid", return_value=types.SimpleNamespace(gr_name=name)):
                self.assertEqual(install._privileges(types.SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name="bob")),
                                 [f"it is in the {name} group"])

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

    def test_untrusted_system_config_is_a_fail_line(self):
        with mock.patch.object(install.client, "system_config", side_effect=client.SystemConfigError("not root-owned")):
            code, out = self.run_doctor(None)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  system mode: not root-owned", out)

    def test_checks_the_venv_config(self):
        opt = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, opt, True)
        with mock.patch.object(install.client, "system_config", return_value={}), mock.patch.object(install, "OPT", opt):
            code, out = self.run_doctor(None)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  venv config", out)

    def test_symlink_is_judged_by_its_own_owner(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.symlink("/", os.path.join(d, "link"))  # the target is root-owned; the link is ours
        with mock.patch("tracekit.daemon.trusted_file", return_value=None):
            code, out = self.run_doctor([("runtime", d, "reinstall")])
        self.assertEqual(code, 1)
        self.assertIn("link is not owned by root", out)

    @pytest.mark.root
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
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            self.assertIn("`require-anchor` defaults to `true`, so an unanchored bundle fails the step", f.read())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
