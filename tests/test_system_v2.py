"""v2 system mode (`tracekit init --v2 --user AGENT`): the generated signer.yaml, unit and plist, the refusals before
any change, the root-owned config that pins the hook's signer, and uninstall. The real install runs as root in
tests/test_install_files.py (-m root) and against attacks in eval/e8_insider_v2.py."""
import contextlib
import io
import json
import os
import plistlib
import shutil
import stat
import tempfile
import types
import unittest
from unittest import mock

from test_system_install import as_root_on_linux
from tracekit import install
from tracekit.sdk import client as sdk_client
from tracekit.signer import service

AGENT = types.SimpleNamespace(pw_uid=64101, pw_gid=64101, pw_name="agent", pw_dir="/home/agent")
POLICY = "/opt/tracekit/lib/python3/site-packages/tracekit/policy2/packs/coding.yaml"


class SignerConfig(unittest.TestCase):
    def test_signer_yaml_loads_with_tenants_approvals_and_policy(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "signer.yaml")
        with open(path, "w") as f:
            f.write(install.v2_signer_yaml(AGENT, 501, POLICY, "/run/tracekit-signer/signer.sock"))
        cfg = service.load_config(path)
        self.assertEqual(cfg["data_dir"], install.V2_DATA)
        self.assertEqual((cfg["socket"], cfg["socket_mode"]), ("/run/tracekit-signer/signer.sock", "0666"))
        self.assertEqual(cfg["tenants"], {"uid:64101": "agent", "uid:501": "agent"})
        self.assertEqual(cfg["tenant"], "local")
        self.assertEqual(cfg["approvals"], {"self_approval": "deny", "approvers": ["uid:501"]})
        self.assertEqual(cfg["policy"], POLICY)

    def test_unit_is_hardened_with_no_capabilities(self):
        unit = install.V2_UNIT_TEXT.format(user="tracekit-signer", python=install.OPT_PYTHON,
                                           config=install.V2_CONFIG, unit=install.V2_UNIT, data=install.V2_DATA)
        self.assertIn(f"ExecStart={install.OPT_PYTHON} -I -m tracekit signer serve --config {install.V2_CONFIG}\n",
                      unit)
        for line in ("User=tracekit-signer", "CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges=true",
                     "ProtectSystem=strict", "PrivateDevices=true", "ProtectKernelTunables=true",
                     "ProtectKernelModules=true", "ProtectKernelLogs=true", "RestrictNamespaces=true",
                     "SystemCallFilter=@system-service", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                     "UMask=0027", "RuntimeDirectory=tracekit-signer", f"ReadWritePaths={install.V2_DATA}"):
            self.assertIn(line + "\n", unit.split("[Install]")[0])
        self.assertNotIn("CAP_", unit)

    def test_plist_runs_the_signer_as_its_user(self):
        p = plistlib.loads(install.v2_plist("_tracekit_signer"))
        self.assertEqual((p["UserName"], p["GroupName"], p["InitGroups"], p["Umask"]),
                         ("_tracekit_signer", "_tracekit_signer", False, 0o027))
        self.assertEqual(p["ProgramArguments"],
                         [install.OPT_PYTHON, "-I", "-m", "tracekit", "signer", "serve", "--config", install.V2_CONFIG])

    def test_socket_mode_is_applied_and_checked(self):
        d = tempfile.mkdtemp(dir="/tmp" if os.name == "posix" else None)   # short: macOS caps socket paths
        self.addCleanup(shutil.rmtree, d, True)
        if not hasattr(__import__("socket"), "AF_UNIX"):
            self.skipTest("no Unix sockets")
        svc = service.SignerService(os.path.join(d, "data"))
        self.addCleanup(svc.close)
        sock = os.path.join(d, "s.sock")
        for srv in service.serve({"socket": sock, "socket_mode": "0666"}, svc):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.assertEqual(stat.S_IMODE(os.stat(sock).st_mode), 0o666)
        path = os.path.join(d, "bad.yaml")
        with open(path, "w") as f:
            f.write(f'data_dir: "{d}"\nsocket_mode: "0999"\n')
        with self.assertRaises(ValueError):
            service.load_config(path)


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class InitRefusals(unittest.TestCase):
    """Each refusal comes before anything is installed."""

    def init(self, agent=AGENT, env=None, **kw):
        names = {AGENT.pw_name: AGENT, "admin": types.SimpleNamespace(pw_uid=501, pw_name="admin")}
        with as_root_on_linux(), mock.patch.dict(os.environ, env or {}, clear=False), \
                mock.patch.object(install.pwd, "getpwnam", lambda n: names[n]), \
                mock.patch.object(install.pwd, "getpwuid", lambda u: next(p for p in names.values() if p.pw_uid == u)), \
                mock.patch.object(install, "_privileges", return_value=[] if agent.pw_uid else ["it is root"]), \
                mock.patch.object(install, "_install_source") as src:
            with self.assertRaises(SystemExit) as cm:
                install.init_system_v2(agent.pw_name, **kw)
        src.assert_not_called()
        return str(cm.exception)

    def test_privileged_agent(self):
        root = types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_name="agent")
        self.assertIn("refusing to trace agent: it is root", self.init(root, approver="admin"))

    def test_approver_must_be_another_user(self):
        self.assertIn("approver must be another user", self.init(approver="agent"))
        self.assertIn("approver must be another user", self.init(env={"SUDO_UID": "64101"}))

    def test_no_approver(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SUDO_UID", None)
            self.assertIn("--approver USER", self.init())

    def test_agent_writable_policy(self):
        with mock.patch("tracekit.daemon.trusted_file", return_value="/home/agent/p.yaml is not owned by root"):
            self.assertIn("--policy: /home/agent/p.yaml is not owned by root",
                          self.init(approver="admin", policy="/home/agent/p.yaml"))

    def test_needs_root(self):
        with mock.patch.object(install.sys, "platform", "linux"), mock.patch.object(install.os, "geteuid",
                                                                                    return_value=1001):
            with self.assertRaises(SystemExit) as cm:
                install.init_system_v2("agent", approver="admin")
        self.assertIn("needs root", str(cm.exception))


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class InstallAndUninstall(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.me = install.pwd.getpwuid(os.getuid())
        self.opt = os.path.join(self.d, "opt")
        os.makedirs(self.opt)
        self.written = {}
        for k, v in {"V2_DATA": os.path.join(self.d, "data"), "V2_CONFIG": os.path.join(self.d, "signer.yaml"),
                     "SYSTEMD_DIR": self.d, "OPT": self.opt}.items():
            p = mock.patch.object(install, k, v)
            p.start()
            self.addCleanup(p.stop)
        for p in (as_root_on_linux(), mock.patch.object(install.client, "SYSTEM_CONFIG", os.path.join(self.d, "c.json")),
                  mock.patch.object(install, "_write_root_file", lambda path, data: self.written.update({path: data}))):
            p.__enter__()
            self.addCleanup(p.__exit__, None, None, None)

    def test_init_wires_signer_service_and_hook(self):
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
        v1 = {"socket": "/var/lib/tracekit/tracekitd.sock", "mode": "system", "fail_mode": "closed"}
        with mock.patch.object(install.pwd, "getpwnam", return_value=AGENT), \
                mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_system_user", return_value=self.me), \
                mock.patch.object(install, "_install_venv") as venv, \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install.client, "system_config", return_value=v1), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "install_hooks") as hooks:
            sock, settings = install.init_system_v2("agent")
        self.assertEqual(sock, "/run/tracekit-signer/signer.sock")
        self.assertEqual(settings, "/home/agent/.claude/settings.json")
        venv.assert_called_once_with(None, "[signer]")
        self.assertEqual(stat.S_IMODE(os.stat(install.V2_DATA).st_mode), 0o700)
        yaml = self.written[install.V2_CONFIG].decode()
        self.assertIn(f'approvers:\n    - "uid:{self.me.pw_uid}"', yaml)
        self.assertIn(f'policy: "{POLICY}"', yaml)
        self.assertIn("ExecStart=", self.written[os.path.join(self.d, "tracekit-signer.service")].decode())
        self.assertEqual(sys_cfg.call_args.args[0], dict(v1, signer=sock, hooks={"user": "agent", "settings": settings}))
        self.assertEqual(hooks.call_args.kwargs, {"owner": AGENT, "python": install.OPT_PYTHON,
                                                  "module": install.V2_HOOK, "signer": sock})
        self.assertIn(["systemctl", "restart", "tracekit-signer"], [c.args[0] for c in run.call_args_list])

    def uninstall(self, sc, purge=False):
        run = mock.Mock(return_value=mock.Mock(returncode=0))
        for p in (install.V2_CONFIG, os.path.join(self.d, "tracekit-signer.service")):
            open(p, "w").close()
        os.makedirs(install.V2_DATA)
        with mock.patch.object(install.client, "system_config", return_value=sc), \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "install_hooks") as hooks:
            kept = install.uninstall_system_v2(purge)
        return kept, sys_cfg, hooks, [c.args[0] for c in run.call_args_list]

    def test_uninstall_removes_everything_but_the_data(self):
        settings = os.path.join(self.d, "settings.json")
        open(settings, "w").close()
        sc = {"mode": "system", "fail_mode": "closed", "signer": "/run/tracekit-signer/signer.sock",
              "hooks": {"user": self.me.pw_name, "settings": settings}}
        kept, sys_cfg, hooks, cmds = self.uninstall(sc)
        self.assertEqual(kept, [install.V2_DATA, install.V2_USER])
        hooks.assert_called_once_with(settings, uninstall=True, owner=self.me, signer=sc["signer"])
        sys_cfg.assert_not_called()
        for gone in (install.V2_CONFIG, os.path.join(self.d, "tracekit-signer.service"), self.opt):
            self.assertFalse(os.path.exists(gone), gone)
        self.assertTrue(os.path.isdir(install.V2_DATA))
        self.assertIn(["systemctl", "disable", "--now", "tracekit-signer"], cmds)
        self.assertNotIn(["userdel", install.V2_USER], cmds)

    def test_uninstall_keeps_v1_system_mode_and_purges(self):
        v1 = {"socket": "/var/lib/tracekit/tracekitd.sock", "mode": "system", "fail_mode": "closed"}
        kept, sys_cfg, hooks, cmds = self.uninstall(dict(v1, signer="/run/x.sock", hooks={"user": "a", "settings": None}),
                                                    purge=True)
        self.assertEqual(kept, [])
        sys_cfg.assert_called_once_with(v1)
        hooks.assert_not_called()
        self.assertTrue(os.path.isdir(self.opt))
        self.assertFalse(os.path.exists(install.V2_DATA))
        self.assertIn(["userdel", install.V2_USER], cmds)


class HookEnv(unittest.TestCase):
    def test_signer_env_is_set_and_removed_only_while_unchanged(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "settings.json")
        install.install_hooks(path, module=install.V2_HOOK, signer="/run/s.sock")
        with open(path) as f:
            self.assertEqual(json.load(f)["env"], {"TRACEKIT_SIGNER": "/run/s.sock"})
        install.install_hooks(path, uninstall=True, signer="/run/s.sock")
        with open(path) as f:
            self.assertNotIn("env", json.load(f))
        with open(path, "w") as f:
            json.dump({"env": {"TRACEKIT_SIGNER": "/mine.sock"}}, f)
        install.install_hooks(path, uninstall=True, signer="/run/s.sock")
        with open(path) as f:
            self.assertEqual(json.load(f)["env"], {"TRACEKIT_SIGNER": "/mine.sock"})


class SystemSigner(unittest.TestCase):
    """In system mode the client takes the signer from the root-owned config; TRACEKIT_SIGNER cannot redirect it."""

    def client(self, env, system):
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": env} if env else {}), \
                mock.patch("tracekit.client.system_config", return_value=system):
            if not env:
                os.environ.pop("TRACEKIT_SIGNER", None)
            return sdk_client.Client()

    def test_system_signer_wins_and_a_decoy_is_refused(self):
        system = {"signer": "/run/tracekit-signer/signer.sock"}
        self.assertEqual(self.client(None, system).signer, system["signer"])
        self.assertEqual(self.client(system["signer"], system).signer, system["signer"])
        with self.assertRaises(sdk_client.SignerUnavailable) as cm:
            self.client("/tmp/decoy.sock", system)
        self.assertIn("not the system signer", str(cm.exception))

    def test_env_without_system_mode(self):
        self.assertEqual(self.client("/tmp/dev.sock", None).signer, "/tmp/dev.sock")
        self.assertEqual(self.client("/tmp/dev.sock", {"socket": "/var/lib/tracekit/tracekitd.sock"}).signer,
                         "/tmp/dev.sock")

    def hook(self, env, sid="s1"):
        from tracekit.integrations import claude_code
        system = {"signer": os.path.join(self.tmp, "absent.sock")}
        payload = {"hook_event_name": "PreToolUse", "session_id": sid, "tool_use_id": "t1", "tool_name": "Bash",
                   "tool_input": {"command": "ls"}}
        with mock.patch.dict(os.environ, dict(env, TRACEKIT_RUNTIME_DIR=self.tmp)), \
                mock.patch("tracekit.client.system_config", return_value=system), \
                mock.patch.object(claude_code, "system_config", return_value=system), \
                mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stderr(io.StringIO()):
            if "TRACEKIT_SIGNER" not in env:
                os.environ.pop("TRACEKIT_SIGNER", None)
            return claude_code._entry()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_hook_blocks_a_decoy_signer(self):
        self.assertEqual(self.hook({"TRACEKIT_SIGNER": "/tmp/decoy.sock"}), 2)

    def test_hook_is_fail_closed_whatever_the_state_says(self):
        from tracekit.integrations import claude_code
        with mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.tmp}):
            path = claude_code._state("s1")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:   # the agent's uid can write its own state
                json.dump({"run_id": "r", "run_token": "x.y", "fail_modes": {"default": "open"}, "stream": "a",
                           "seq": 0}, f)
        self.assertEqual(self.hook({}), 2)


class CliUninstall(unittest.TestCase):
    def test_purge_needs_v2(self):
        from tracekit import cli
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["uninstall", "--purge"]), 2)
        self.assertIn("--purge goes with --v2", err.getvalue())


if __name__ == "__main__":
    unittest.main()
