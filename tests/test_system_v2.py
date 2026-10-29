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
from tracekit import agent_hooks, install
from tracekit.sdk import client as sdk_client
from tracekit.signer import service

AGENT = types.SimpleNamespace(pw_uid=64101, pw_gid=64101, pw_name="agent", pw_dir="/home/agent")
POLICY = "/opt/tracekit/lib/python3/site-packages/tracekit/policy2/packs/coding.yaml"


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class SignerConfig(unittest.TestCase):
    def test_signer_yaml_loads_with_tenants_approvals_and_policy(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "signer.yaml")
        with open(path, "w") as f:
            f.write(install.v2_signer_yaml(AGENT, 501, POLICY, "/run/tracekit-signer/signer.sock", 64102))
        cfg = service.load_config(path)
        self.assertEqual(cfg["data_dir"], install.V2_DATA)
        self.assertEqual((cfg["socket"], cfg["socket_mode"]), ("/run/tracekit-signer/signer.sock", "0666"))
        self.assertEqual(cfg["tenants"], {"uid:64101": "agent", "uid:501": "agent"})
        self.assertEqual(cfg["tenant"], "local")
        self.assertEqual(cfg["approvals"], {"self_approval": "deny", "approvers": ["uid:501"]})
        self.assertEqual(cfg["policy"], POLICY)
        self.assertEqual(cfg["authorize"], {"uid:64102": ["model_event", "state_write", "tailer_lost", "tailer_heartbeat", "status"]})

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
        with mock.patch("tracekit.harness_helper.trusted_file", return_value="/home/agent/p.yaml is not owned by root"):
            self.assertIn("--policy: /home/agent/p.yaml is not owned by root",
                          self.init(approver="admin", policy="/home/agent/p.yaml"))

    def test_egress_needs_linux(self):
        with mock.patch.object(install, "_require_system", return_value=True):
            self.assertIn("--egress needs Linux", self.init(approver="admin", egress=True))

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
                     "SYSTEMD_DIR": self.d, "OPT": self.opt,
                     "TAILER_SUDOERS": os.path.join(self.d, "sudoers")}.items():
            p = mock.patch.object(install, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.managed = os.path.join(self.d, "claude-code", "managed-settings.json")   # init reads it: never the host's
        for p in (as_root_on_linux(), mock.patch.object(install.client, "SYSTEM_CONFIG", os.path.join(self.d, "c.json")),
                  mock.patch.object(install, "_write_root_file", lambda path, data: self.written.update({path: data})),
                  mock.patch.dict(install.MANAGED_SETTINGS, linux=self.managed, darwin=self.managed)):
            p.__enter__()
            self.addCleanup(p.__exit__, None, None, None)

    def test_without_tailer_access_init_writes_no_tailer_key(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sys_cfg = self.init_v2(sudo_why="no sudo rule: visudo refused it")
        self.assertNotIn("tailer", sys_cfg.call_args.args[0])
        self.assertIn("each run of agent's sessions records a tailer_lost gap", out.getvalue())

    def test_init_wires_signer_service_and_hook(self):
        self.init_v2()

    def test_init_with_a_harness_requires_it_and_starts_the_helper(self):
        h = {"name": "claude", "exe": "/usr/local/bin/claude"}
        with mock.patch.object(install, "resolve_harness", return_value=h) as res:
            self.init_v2(harnesses=["claude=/usr/local/bin/claude"])
        res.assert_called_once_with("claude=/usr/local/bin/claude", "claude")
        path = os.path.join(self.d, "check.yaml")
        with open(path, "wb") as f:
            f.write(self.written[install.V2_CONFIG])
        cfg = service.load_config(path)["harness_binding"]
        self.assertEqual(cfg, {"helper": install.V2_HELPER_SOCKET, "required": [f"uid:{AGENT.pw_uid}"],
                               "harnesses": {"claude": "/usr/local/bin/claude"}})
        unit = self.written[os.path.join(self.d, install.V2_HELPER + ".service")].decode()
        self.assertIn("CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n", unit)
        self.assertNotIn("CAP_", self.written[os.path.join(self.d, "tracekit-signer.service")].decode())
        cmds = [c.args[0] for c in self.run.call_args_list]
        self.assertLess(cmds.index(["systemctl", "enable", "--now", install.V2_HELPER + ".socket"]),
                        cmds.index(["systemctl", "restart", "tracekit-signer"]))

    def init_v2(self, sudo_why=None, harnesses=()):
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
        v1 = {"socket": "/var/lib/tracekit/tracekitd.sock", "mode": "system", "fail_mode": "closed",
              "tailer": {"user": "stale"}}
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
                mock.patch.object(install, "_tailer_acl", return_value=None) as acl, \
                mock.patch.object(install, "_tailer_sudo", return_value=sudo_why) as sudo, \
                mock.patch.object(install, "install_hooks") as hooks:
            sock, settings = install.init_system_v2("agent", harnesses=harnesses)
        self.run = run
        self.assertEqual(sock, "/run/tracekit-signer/signer.sock")
        self.assertEqual(settings, "/home/agent/.claude/settings.json")
        venv.assert_called_once_with(None, "[signer]")
        self.assertEqual(stat.S_IMODE(os.stat(install.V2_DATA).st_mode), 0o700)
        yaml = self.written[install.V2_CONFIG].decode()
        self.assertIn(f'approvers:\n    - "uid:{self.me.pw_uid}"', yaml)
        self.assertIn(f'policy: "{POLICY}"', yaml)
        self.assertIn("ExecStart=", self.written[os.path.join(self.d, "tracekit-signer.service")].decode())
        acl.assert_called_once_with(AGENT, self.me.pw_name, False)
        sudo.assert_called_once_with(AGENT, self.me)
        if sudo_why:
            return sys_cfg
        del v1["tailer"]
        self.assertEqual(sys_cfg.call_args.args[0], dict(v1, signer=sock, hooks={"user": "agent", "settings": settings,
                                                                                      "agent": "claude"},
                                                         tailer={"user": self.me.pw_name, "uid": self.me.pw_uid,
                                                                 "python": install.OPT_PYTHON}))
        self.assertIn(f'authorize:\n  "uid:{self.me.pw_uid}": [model_event, state_write, tailer_lost, tailer_heartbeat, status]', yaml)
        self.assertEqual(hooks.call_args.kwargs, {"owner": AGENT, "python": install.OPT_PYTHON,
                                                  "module": install.V2_HOOK, "signer": sock, "thinking": True})
        self.assertIn(["systemctl", "restart", "tracekit-signer"], [c.args[0] for c in run.call_args_list])

    def test_a_signer_that_does_not_start_fails_init_after_the_hooks(self):
        run = mock.Mock(side_effect=lambda cmd, **kw: mock.Mock(returncode=int(cmd[:2] == ["systemctl", "restart"]),
                                                                 stdout=POLICY + "\n", stderr=""))
        with mock.patch.object(install.pwd, "getpwnam", return_value=AGENT), \
                mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_system_user", return_value=self.me), \
                mock.patch.object(install, "_install_venv"), mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install.client, "system_config", return_value={}), \
                mock.patch.object(install, "_write_system_client_config"), \
                mock.patch.object(install, "_tailer_acl", return_value=None), \
                mock.patch.object(install, "_tailer_sudo", return_value=None), \
                mock.patch.object(install, "install_hooks") as hooks, \
                self.assertRaisesRegex(install.ServiceError, "could not start tracekit-signer: see systemctl status "
                                                             "tracekit-signer"):
            install.init_system_v2("agent")
        hooks.assert_called_once()

    def test_no_hooks_is_recorded_as_the_choice_it_is(self):
        """`init --v2 --no-hooks` in system mode left doctor saying "no hooks recorded in client.json" with the reinit
        that installs them: client.json records the choice, as dev mode's client config does."""
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
        with mock.patch.object(install.pwd, "getpwnam", return_value=AGENT), \
                mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_system_user", return_value=self.me), \
                mock.patch.object(install, "_install_venv"), mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install.client, "system_config", return_value={}), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "_tailer_acl", return_value=None), \
                mock.patch.object(install, "_tailer_sudo", return_value=None), \
                mock.patch.object(install, "install_hooks") as hooks:
            self.assertEqual(install.init_system_v2("agent", hooks=False)[1], None)
        hooks.assert_not_called()
        self.assertEqual(sys_cfg.call_args.args[0]["hooks"], {"user": "agent", "settings": None, "agent": "claude",
                                                               "no_hooks": True})

    def test_egress_routes_the_agents_traffic_through_the_observer_until_uninstall(self):
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
        with mock.patch.object(install.pwd, "getpwnam", return_value=AGENT), \
                mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_system_user", return_value=self.me), \
                mock.patch.object(install, "_install_venv"), mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install.client, "system_config", return_value={}), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "_tailer_acl", return_value=None), \
                mock.patch.object(install, "_tailer_sudo", return_value=None), \
                mock.patch.object(install, "install_hooks") as hooks:
            sock, _ = install.init_system_v2("agent", egress=True)
        path = os.path.join(self.d, "check.yaml")
        with open(path, "wb") as f:
            f.write(self.written[install.V2_CONFIG])
        cfg = service.load_config(path)
        me = f"uid:{self.me.pw_uid}"
        self.assertEqual((cfg["tenants"][me], cfg["authorize"][me][-1]), ("agent", "observe_effect"))
        self.assertIn(f'listen: "{install.EGRESS_LISTEN}"', self.written[install.EGRESS_CONFIG].decode())
        unit = self.written[os.path.join(self.d, install.V2_EGRESS + ".service")].decode()
        self.assertIn(f"-m tracekit egress serve --config {install.EGRESS_CONFIG}", unit)
        wall = self.written[os.path.join(self.d, install.EGRESS_FIREWALL + ".service")].decode()
        self.assertIn(f"$$t -I OUTPUT -m owner --uid-owner {AGENT.pw_uid} -j TRACEKIT-EGRESS", wall)
        self.assertIn("$$t -A TRACEKIT-EGRESS -o lo -j RETURN && $$t -A TRACEKIT-EGRESS -j REJECT", wall)
        self.assertIn(["systemctl", "enable", "--now", install.V2_EGRESS, install.EGRESS_FIREWALL],
                      [c.args[0] for c in run.call_args_list])
        proxy = {"HTTPS_PROXY": "http://127.0.0.1:3128", "HTTP_PROXY": "http://127.0.0.1:3128"}
        self.assertEqual(hooks.call_args.kwargs["signer"], {"TRACEKIT_SIGNER": sock, **proxy})
        sc = sys_cfg.call_args.args[0]
        self.assertEqual(sc["hooks"]["env"], proxy)
        open(os.path.join(self.d, install.V2_EGRESS + ".service"), "w").close()
        sc["hooks"]["settings"] = os.path.join(self.d, "settings.json")
        open(sc["hooks"]["settings"], "w").close()
        kept, _, hooks, cmds = self.uninstall(sc)
        self.assertIn(["systemctl", "disable", "--now", install.V2_EGRESS, install.EGRESS_FIREWALL], cmds)
        self.assertEqual(hooks.call_args.kwargs["signer"], {"TRACEKIT_SIGNER": sock, **proxy})
        self.assertEqual(kept[-1], install.V2_EGRESS)
        self.assertFalse(os.path.exists(os.path.join(self.d, install.V2_EGRESS + ".service")))

    def test_init_and_uninstall_wire_a_harness_hook(self):
        for harness in ("codex", "opencode"):
            with self.subTest(agent=harness):
                home = os.path.join(self.d, harness)
                agent = types.SimpleNamespace(**dict(vars(AGENT), pw_dir=home))
                run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
                with mock.patch.object(install.pwd, "getpwnam", return_value=agent), \
                        mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                        mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                        mock.patch.object(install, "_privileges", return_value=[]), \
                        mock.patch.object(install, "_install_source", return_value=None), \
                        mock.patch.object(install, "_system_user", return_value=self.me), \
                        mock.patch.object(install, "_install_venv"), \
                        mock.patch.object(install.subprocess, "run", run), \
                        mock.patch.object(install.client, "system_config", return_value={}), \
                        mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                        mock.patch.object(install.files, "as_user", lambda pw, fn, *a, errors=(): fn(*a)):
                    sock, settings = install.init_system_v2("agent", agent=harness)
                    self.assertEqual(settings, agent_hooks.config_path(harness, home=home))
                    with open(settings) as f:
                        hook = f.read()
                    if harness == "codex":
                        with open(os.path.join(home, ".codex", "config.toml")) as f:   # its reasoning summaries, on
                            self.assertEqual(f.read(), agent_hooks.CODEX_LINE)
                        self.assertIn(f"{install.OPT_PYTHON} -I -m tracekit.integrations.harness_hooks codex PreToolUse; s=$?", hook)
                    else:
                        self.assertEqual(settings, os.path.join(home, ".config", "opencode", "plugin", "tracekit.js"))
                        for event in ("tool.execute.before", "tool.execute.after"):
                            self.assertIn(json.dumps([install.OPT_PYTHON, "-I", "-m",
                                                      "tracekit.integrations.harness_hooks", harness, event]), hook)
                    sc = sys_cfg.call_args.args[0]
                    self.assertEqual(sc["hooks"], {"user": "agent", "settings": settings, "agent": harness})
                    self.uninstall(sc)
                    if harness == "opencode":
                        self.assertFalse(os.path.exists(settings))
                    else:
                        with open(settings) as f:
                            self.assertNotIn("tracekit", f.read())

    def uninstall(self, sc, purge=False):
        run = mock.Mock(return_value=mock.Mock(returncode=0))
        for p in (install.V2_CONFIG, os.path.join(self.d, "tracekit-signer.service")):
            open(p, "w").close()
        os.makedirs(install.V2_DATA, exist_ok=True)
        with mock.patch.object(install.client, "system_config", return_value=sc), \
                mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "install_hooks") as hooks:
            kept = install.uninstall_system_v2(purge)
        return kept, sys_cfg, hooks, [c.args[0] for c in run.call_args_list]

    def init_real(self, sc, **kw):
        """init_system_v2 writing the hooks for real: the agent's home and the managed settings are under self.d."""
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=POLICY + "\n", stderr=""))
        with mock.patch.object(install.pwd, "getpwnam", return_value=self.agent), \
                mock.patch.object(install.pwd, "getpwuid", return_value=self.me), \
                mock.patch.dict(os.environ, {"SUDO_UID": str(self.me.pw_uid)}), \
                mock.patch.object(install, "_privileges", return_value=[]), \
                mock.patch.object(install, "_install_source", return_value=None), \
                mock.patch.object(install, "_system_user", return_value=self.me), \
                mock.patch.object(install, "_install_venv"), mock.patch.object(install.subprocess, "run", run), \
                mock.patch.object(install.client, "system_config", return_value=sc), \
                mock.patch.object(install, "_write_system_client_config") as sys_cfg, \
                mock.patch.object(install, "_tailer_acl", return_value=None), \
                mock.patch.object(install, "_tailer_sudo", return_value=None), \
                mock.patch.object(install.files, "as_user", lambda pw, fn, *a, errors=(): fn(*a)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                sock, settings = install.init_system_v2("agent", **kw)
            finally:   # the system config after this init, written or not
                self.sc = sys_cfg.call_args.args[0] if sys_cfg.called else sc
        return sock, settings, self.sc, out.getvalue()

    def managed_setup(self, admin=None):
        """The agent's home and a managed settings file (holding an admin's `admin` settings) under self.d."""
        self.agent = types.SimpleNamespace(**dict(vars(AGENT), pw_dir=os.path.join(self.d, "home")))
        self.user = os.path.join(self.agent.pw_dir, ".claude", "settings.json")
        os.makedirs(os.path.dirname(self.managed))
        if admin is not None:
            with open(self.managed, "w") as f:
                json.dump(admin, f)

    def read(self, path):
        with open(path) as f:
            return json.load(f)

    def test_managed_hooks_go_in_the_admin_settings_and_uninstall_takes_only_tracekits_out(self):
        """init --v2 --managed wrote the hooks into the agent's own settings, which the agent can edit."""
        admin = {"permissions": {"deny": ["Read(./.env)"]}, "env": {"CORP": "1"},
                 "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/bin/audit"}]}]}}
        self.managed_setup(admin)
        sock, settings, sc, out = self.init_real({}, managed=True, managed_only=True)
        self.assertEqual(settings, self.managed)
        self.assertEqual(sc["hooks"], {"user": "agent", "settings": self.managed, "agent": "claude"})
        self.assertFalse(os.path.exists(self.user))
        s = self.read(self.managed)
        self.assertEqual((s["permissions"], s["env"]), (admin["permissions"], {"CORP": "1", "TRACEKIT_SIGNER": sock}))
        self.assertEqual(s["hooks"]["PreToolUse"][0], admin["hooks"]["PreToolUse"][0])
        self.assertEqual(s["hooks"]["PreToolUse"][1]["hooks"][0]["command"],
                         install._hook_command(install.V2_HOOK, args=("PreToolUse",), python=install.OPT_PYTHON))
        for ev in install.TOOL_EVENTS + install.OTHER_EVENTS:
            self.assertEqual(install._hook_version(s["hooks"][ev][-1]), "v2", ev)
        self.assertEqual((s["allowManagedHooksOnly"], s[install.THINKING]), (True, True))
        self.assertEqual(stat.S_IMODE(os.stat(self.managed).st_mode), 0o644)   # Claude Code skips a file it can't read
        self.assertIn("admin-managed hooks: agent can't edit or turn them off, and they run in every user's Claude Code",
                      out)
        self.assertIn("allowManagedHooksOnly is on: every user's own hooks (user, project, local, plugin) stop", out)
        self.assertIn("Thinking summaries are on in every user's Claude Code too", out)   # the notice said hooks only
        self.uninstall_real(sc)
        self.assertEqual(self.read(self.managed), admin)
        self.assertEqual(stat.S_IMODE(os.stat(self.managed).st_mode), 0o644)

    def test_init_moves_the_hooks_into_and_out_of_the_admin_settings(self):
        """Re-running init with --managed (or without it) left the hooks in the other file too: Claude Code ran both,
        so every call was decided twice."""
        self.managed_setup()
        _, settings, sc, _ = self.init_real({})
        self.assertEqual(settings, self.user)
        self.assertEqual(install._hook_summary(self.read(self.user))["versions"], ["v2"])
        _, _, sc, _ = self.init_real(sc, managed=True)
        self.assertEqual(self.read(self.user), {})   # the thinking setting init turned on went with the hooks
        self.assertEqual(install._hook_summary(self.read(self.managed))["versions"], ["v2"])
        self.init_real(sc)
        self.assertEqual(self.read(self.managed), {})
        self.assertEqual(install._hook_summary(self.read(self.user))["versions"], ["v2"])

    def test_a_managed_init_that_fails_records_nothing_and_its_rerun_moves_the_hooks(self):
        """An init --managed that failed on a malformed managed file had already recorded it, so once the file was
        fixed, its re-run left the hooks in the agent's own settings too: every call was decided twice."""
        self.managed_setup()
        _, _, sc, _ = self.init_real({})
        with open(self.managed, "w") as f:
            f.write("{")
        with self.assertRaisesRegex(install.SettingsError, "is not valid JSON"):
            self.init_real(sc, managed=True)
        self.assertEqual(self.sc, sc)
        with open(self.managed) as f:
            self.assertEqual(f.read(), "{")
        with open(self.managed, "w") as f:
            f.write("{}")
        self.init_real(self.sc, managed=True)
        self.assertEqual(self.read(self.user), {})
        self.assertEqual(install._hook_summary(self.read(self.managed))["versions"], ["v2"])

    def test_init_with_another_agent_takes_the_managed_hooks_out(self):
        """init --managed, then init --agent codex for the same user, left the managed hooks in place and the config
        forgot them: after uninstall --v2 they blocked every user's Claude Code calls."""
        self.managed_setup()
        _, _, sc, _ = self.init_real({}, managed=True)
        _, settings, sc, _ = self.init_real(sc, agent="codex")
        self.assertEqual(self.read(self.managed), {})
        self.assertEqual(sc["hooks"], {"user": "agent", "settings": settings, "agent": "codex"})

    def test_init_for_another_user_takes_the_managed_hooks_out(self):
        """init --managed for one user, then init without it for another, left the managed hooks running in the other
        user's Claude Code beside the ones in its own settings."""
        self.managed_setup()
        _, _, sc, _ = self.init_real({}, managed=True)
        sc["hooks"]["user"] = "alice"   # the managed init was another user's
        self.init_real(sc)
        self.assertEqual(self.read(self.managed), {})
        self.assertEqual(install._hook_summary(self.read(self.user))["versions"], ["v2"])

    def test_managed_init_takes_the_hooks_out_of_the_agents_own_settings_the_config_forgot(self):
        """Hooks in the agent's own settings that the config doesn't record stayed beside the managed ones."""
        self.managed_setup()
        _, _, sc, _ = self.init_real({})
        self.init_real(dict(sc, hooks=dict(sc["hooks"], settings=None)), managed=True)
        self.assertEqual(self.read(self.user), {})

    def test_init_that_names_the_recorded_file_by_another_path_keeps_its_hooks(self):
        """With the agent's home in the user database a symlink, init --project run from that home (the working
        directory's real path) took the hooks it had just written out again, as the file the last init recorded:
        init exited 0 with the hooks in no file."""
        self.managed_setup()
        os.mkdir(os.path.join(self.d, "real-home"))
        os.symlink(os.path.join(self.d, "real-home"), self.agent.pw_dir)
        _, _, sc, _ = self.init_real({})
        _, settings, sc, _ = self.init_real(sc, project=os.path.realpath(self.agent.pw_dir))
        self.assertNotEqual(settings, self.user)
        self.assertEqual(sc["hooks"]["settings"], settings)
        self.assertEqual(install._hook_summary(self.read(settings))["versions"], ["v2"])

    def test_a_recorded_managed_file_init_cant_edit_stops_init_and_uninstall_before_any_change(self):
        """With client.json recording a managed file that isn't valid JSON, init without --managed wrote its hooks into
        the agent's own settings, then stopped without recording them: uninstall --v2 left them there, where they
        blocked every call once the signer was gone."""
        self.managed_setup()
        _, _, sc, _ = self.init_real({}, managed=True)
        with open(self.managed, "w") as f:
            f.write("{")
        for kw in ({}, {"hooks": False}, {"managed": True}):
            with self.subTest(**kw):
                self.written.clear()
                with self.assertRaisesRegex(install.SettingsError, "is not valid JSON"):
                    self.init_real(sc, **kw)
                self.assertFalse(os.path.exists(self.user))
                self.assertEqual((self.written, self.sc), ({}, sc))   # no signer config, nothing recorded
        with self.assertRaisesRegex(install.SettingsError, "is not valid JSON"):
            self.uninstall_real(sc)
        self.assertTrue(os.path.exists(install.V2_CONFIG))
        with open(self.managed) as f:
            self.assertEqual(f.read(), "{")

    def test_init_names_the_claude_code_file_it_takes_the_hooks_out_of(self):
        """--no-hooks, or an init for another coding agent or user, takes init's v2 hooks out of the agent's Claude Code
        settings: init says so in one line, as it does for Codex's."""
        self.managed_setup()
        for kw in ({"hooks": False}, {"agent": "codex"}, {"project": os.path.join(self.d, "project")}):
            with self.subTest(**kw):
                _, _, sc, _ = self.init_real({})
                sc["hooks"]["user"] = "alice" if "project" in kw else "agent"
                out = self.init_real(sc, **kw)[3]
                self.assertIn(f"Tracekit v2 hooks removed from {self.user}\n", out)
                self.assertEqual(install._hook_summary(self.read(self.user))["versions"], [])

    def test_uninstall_takes_tracekits_hooks_out_of_the_managed_settings_the_config_forgot(self):
        """Managed hooks the config no longer recorded outlived uninstall --v2, and with the signer gone they failed
        closed: every user's Claude Code calls were blocked."""
        admin = {"env": {"CORP": "1"},
                 "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/bin/audit"}]}]}}
        self.managed_setup(admin)
        _, _, sc, _ = self.init_real({}, managed=True, managed_only=True)
        self.uninstall_real(dict(sc, hooks={"user": "agent", "settings": None, "agent": "claude"}))
        self.assertEqual(self.read(self.managed), admin)
        self.assertEqual(stat.S_IMODE(os.stat(self.managed).st_mode), 0o644)

    def test_init_without_managed_only_turns_allow_managed_hooks_only_off_only_when_init_turned_it_on(self):
        """Re-running init --managed without --managed-only left allowManagedHooksOnly on: every user's own Claude Code
        hooks stayed off."""
        self.managed_setup()
        for admin in ({}, {"allowManagedHooksOnly": True}):
            with self.subTest(admin=admin):
                with open(self.managed, "w") as f:
                    json.dump(admin, f)
                _, _, sc, _ = self.init_real({}, managed=True, managed_only=True)
                self.assertIs(self.read(self.managed)["allowManagedHooksOnly"], True)
                self.init_real(sc, managed=True)
                s = self.read(self.managed)
                self.assertEqual(s.get("allowManagedHooksOnly"), admin.get("allowManagedHooksOnly"))
                self.assertNotIn("_tracekit_allowManagedHooksOnly", s)

    def uninstall_real(self, sc):
        for p in (install.V2_CONFIG, os.path.join(self.d, "tracekit-signer.service")):
            open(p, "w").close()
        with mock.patch.object(install.client, "system_config", return_value=sc), \
                mock.patch.object(install.pwd, "getpwnam", return_value=self.agent), \
                mock.patch.object(install.subprocess, "run", mock.Mock(return_value=mock.Mock(returncode=0))), \
                mock.patch.object(install, "_write_system_client_config"), \
                contextlib.redirect_stdout(io.StringIO()):
            install.uninstall_system_v2()

    def test_uninstall_removes_everything_but_the_data(self):
        settings = os.path.join(self.d, "settings.json")
        open(settings, "w").close()
        sc = {"mode": "system", "fail_mode": "closed", "signer": "/run/tracekit-signer/signer.sock",
              "hooks": {"user": self.me.pw_name, "settings": settings}}
        kept, sys_cfg, hooks, cmds = self.uninstall(sc)
        self.assertEqual(kept, [install.V2_DATA, install.V2_USER, install.V2_TAILER])
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
        self.assertIn(["userdel", install.V2_TAILER], cmds)

    def test_uninstall_revokes_the_tailers_acl_and_sudo_rule_and_purges_its_user(self):
        open(install.TAILER_SUDOERS, "w").close()   # no `tailer` key: an ACL set before the sudo rule failed goes too
        sc = {"mode": "system", "signer": "/run/x.sock", "hooks": {"user": self.me.pw_name, "settings": None}}
        kept, _, _, cmds = self.uninstall(sc, purge=True)
        self.assertEqual(kept, [])
        projects = os.path.join(self.me.pw_dir, ".claude", "projects")
        self.assertIn(["setfacl", "-R", "-x", "u:tracekit-tailer,d:u:tracekit-tailer", projects], cmds)
        self.assertFalse(os.path.exists(install.TAILER_SUDOERS))
        self.assertIn(["userdel", install.V2_TAILER], cmds)


@unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
class TailerAccess(unittest.TestCase):
    """The tailer's read access to the agent's transcripts, as commands (mocked): setfacl on Linux, chmod +a on macOS."""

    def acl(self, darwin, returncode=0):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        owner = types.SimpleNamespace(pw_uid=os.getuid(), pw_dir=d)
        run = mock.Mock(return_value=mock.Mock(returncode=returncode, stderr="Operation not supported"))
        with mock.patch.object(install.subprocess, "run", run):
            why = install._tailer_acl(owner, "tk-tailer", darwin)
        self.assertTrue(os.path.isdir(os.path.join(d, ".claude", "projects")))
        return why, [c.args[0] for c in run.call_args_list], d

    def test_linux_grants_read_on_the_transcripts_and_search_above_them(self):
        why, cmds, home = self.acl(False)
        self.assertIsNone(why)
        self.assertEqual(cmds, [["setfacl", "-m", "u:tk-tailer:x", home],
                                ["setfacl", "-m", "u:tk-tailer:x", os.path.join(home, ".claude")],
                                ["setfacl", "-R", "-m", "u:tk-tailer:rX,d:u:tk-tailer:rX",
                                 os.path.join(home, ".claude", "projects")]])

    def test_macos_uses_inherited_acl_entries(self):
        why, cmds, home = self.acl(True)
        self.assertIsNone(why)
        self.assertEqual(cmds[-1], ["chmod", "-R", "+a", "user:tk-tailer allow list,search,read,readattr,readextattr,"
                                    "file_inherit,directory_inherit", os.path.join(home, ".claude", "projects")])

    def test_no_acl_support_is_reported(self):
        why, cmds, _ = self.acl(False, returncode=1)
        self.assertIn("Operation not supported", why)
        self.assertEqual(len(cmds), 1)


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

    def test_uninstall_turns_allow_managed_hooks_only_off_only_when_init_turned_it_on(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "managed-settings.json")
        for admin in ({}, {"allowManagedHooksOnly": True}):
            with open(path, "w") as f:
                json.dump(admin, f)
            with contextlib.redirect_stdout(io.StringIO()):
                for _ in range(2):   # init run twice
                    install.install_managed(None, True, path, module=install.V2_HOOK)
                with open(path) as f:
                    self.assertIs(json.load(f)["allowManagedHooksOnly"], True)
                install.install_managed(None, True, path, uninstall=True)
            with open(path) as f:
                self.assertEqual(json.load(f), admin)

    def test_a_managed_settings_folder_it_makes_is_readable_by_every_user_whatever_the_umask(self):
        # under a hardened root umask (027) the folder was 0750: the agent's Claude Code could not read the hooks
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "claude-code", "managed-settings.json")
        old = os.umask(0o027)
        try:
            install.install_managed(None, False, path, module=install.V2_HOOK)
        finally:
            os.umask(old)
        self.assertEqual((os.stat(os.path.dirname(path)).st_mode & 0o777, os.stat(path).st_mode & 0o777), (0o755, 0o644))


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

    def test_uninstall_v2_without_root_says_how_to_remove_a_dev_setup(self):
        """Not as root, `uninstall --v2` said to "use tracekit init --dev": advice to install, to someone removing one."""
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform), mock.patch.object(install.sys, "platform", platform), \
                    mock.patch.object(install.os, "geteuid", return_value=1001, create=True), \
                    self.assertRaises(SystemExit) as cm:
                install.uninstall_system_v2()
            self.assertTrue(str(cm.exception).endswith(
                ". Removing a dev setup (init --dev) needs no root: tracekit uninstall takes its hooks out and tracekit "
                "down stops its signer"), str(cm.exception))
            self.assertNotIn("init --dev for", str(cm.exception))


class CliManaged(unittest.TestCase):
    def test_v2_system_mode_takes_managed(self):
        """--managed was refused with --v2 as a v1 signer option."""
        from tracekit import cli
        with mock.patch.object(install, "init_system_v2", return_value=("/run/s.sock", "/m.json")) as init, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["init", "--v2", "--user", "agent", "--managed", "--managed-only"]), 0)
        self.assertEqual(init.call_args.args[-2:], (True, True))
        self.assertIn("hooks: /m.json", out.getvalue())

    def test_managed_is_refused_with_dev_project_or_another_agent(self):
        from tracekit import cli
        for argv, why in ((["--v2", "--dev"], "--managed is for system mode: a --dev setup belongs to its user"),
                          (["--dev"], "--managed is for system mode"),
                          (["--v2", "--user", "agent", "--project"], "--managed and --project name different settings"),
                          (["--v2", "--user", "agent", "--agent", "codex"], "--managed is for Claude Code only: "
                           "Tracekit wires no admin-managed settings for codex, so its hooks go in the agent user's")):
            with self.subTest(argv=argv), mock.patch.object(install, "init_system_v2") as v2, \
                    mock.patch.object(install, "init_system") as v1, mock.patch.object(install, "init_dev") as dev, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main(["init", "--managed", *argv]), 2)
                for init in (v2, v1, dev):
                    init.assert_not_called()
                self.assertIn(why, err.getvalue())


if __name__ == "__main__":
    unittest.main()
