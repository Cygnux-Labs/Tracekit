"""`tracekit doctor` for the v2 signer: every check's ok path (the clean E16 layout) and fail path (its E16 case),
setup detection, --json and the exit codes. The v1 doctor's own tests are in tests/test_system_install.py."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

from tracekit import cli, client, doctor, install

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("e16_doctor", os.path.join(HERE, "..", "eval", "e16_doctor.py"))
e16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e16)


@unittest.skipIf(os.name == "nt", "POSIX ownership and modes")
class E16(unittest.TestCase):
    def test_clean_layout_passes_every_check(self):
        results = e16.run_case(None)
        self.assertEqual([r for r in results if r["status"] != "ok"], [])
        self.assertEqual({r["id"] for r in results}, {want for _, want, _ in e16.CASES})

    def test_every_misconfiguration_is_flagged(self):
        self.assertGreaterEqual(len(e16.CASES), 20)
        for name, want, mutate in e16.CASES:
            if name in e16.ROOT_ONLY and not e16.IS_ROOT:
                continue
            with self.subTest(name), contextlib.redirect_stdout(io.StringIO()):
                got = {r["id"]: r["status"] for r in e16.run_case(mutate)}
                self.assertIn(got.get(want), ("warn", "fail"), name)

    def test_malformed_agent_settings_are_results_not_crashes(self):
        def bad(shape):
            def mutate(L):
                with open(L.settings) as f:
                    s = json.load(f)
                shape(s)
                with open(L.settings, "w") as f:
                    json.dump(s, f)
            return mutate
        for name, shape, want in (
                ("timeout", lambda s: s["hooks"]["PreToolUse"][0]["hooks"][0].update(timeout="600"), "D-HOOKS-TIMEOUT"),
                ("env", lambda s: s.update(env=["x"]), "D-SIGNER-ENV"),
                ("hooks", lambda s: s["hooks"]["PreToolUse"][0].update(hooks=5), "D-HOOKS-PRESENT"),
                ("entry", lambda s: s["hooks"]["PreToolUse"][0]["hooks"].append("x"), "D-HOOKS-PRESENT")):
            with self.subTest(name), contextlib.redirect_stdout(io.StringIO()):
                got = {r["id"]: r["status"] for r in e16.run_case(bad(shape))}
                self.assertIn(want, got)

    def test_hooks_installed_before_1_2_only_need_init_again(self):
        got = {r["id"]: r["status"] for r in e16.run_case(e16._unnamed)}
        self.assertEqual((got["D-HOOKS-EVENT"], got["D-HOOKS-VENV"]), ("warn", "ok"))

    def test_data_dir_of_the_agents_user_fails_the_boundary(self):
        def agent_is_me(L):
            L.kw["agent"] = types.SimpleNamespace(**dict(vars(e16.AGENT), pw_uid=os.getuid()))
        got = {r["id"]: r for r in e16.run_case(agent_is_me)}
        self.assertEqual(got["D-PROCESS-BOUNDARY"]["status"], "fail")


class DevFresh(unittest.TestCase):
    def test_a_dev_signer_that_never_started_gets_dev_advice(self):
        """On a fresh home doctor said "run doctor as root" for the missing keys and "add a witness in signer.yaml" at
        assurance "local", none of which fits a dev signer: it has no keys until `tracekit up` and takes no witnesses."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        got = {r["id"]: r for r in doctor.v2_checks({"data_dir": d}, "dev")}
        self.assertEqual(got["D-KEYS-MODE"]["fix"], "start the dev signer: tracekit up")
        self.assertIn("assurance stays dev", got["D-WITNESS-CONFIGURED"]["detail"])
        self.assertIn("the dev signer takes no witnesses", got["D-WITNESS-CONFIGURED"]["fix"])


class K8s(unittest.TestCase):
    def test_clean_deployment_passes_every_check(self):
        results = e16.run_k8s_case(None)
        self.assertEqual([r for r in results if r["status"] != "ok"], [])
        self.assertEqual({r["id"] for r in results}, {want for _, want, _ in e16.K8S_CASES})

    def test_every_misconfiguration_is_flagged(self):
        self.assertGreaterEqual(len(e16.K8S_CASES), 10)
        for name, want, mutate in e16.K8S_CASES:
            with self.subTest(name):
                got = {r["id"]: r["status"] for r in e16.run_k8s_case(mutate)}
                self.assertIn(got.get(want), ("warn", "fail"), name)

    def test_a_token_with_cloud_identity_fails_without_it_warns(self):
        token = e16._set(e16._pod, automountServiceAccountToken=True)
        gke = e16._sa_note("iam.gke.io/gcp-service-account", "s@p.iam.gserviceaccount.com")
        for mutate, want in ((token, "warn"), (lambda d: (token(d), gke(d)), "fail")):
            got = {r["id"]: r["status"] for r in e16.run_k8s_case(mutate)}
            self.assertEqual(got["D-K8S-SA-TOKEN"], want)

    def test_central_signer_with_cloud_identity_and_a_sidecar_passes(self):
        def central(docs):
            e16._sa_note("eks.amazonaws.com/role-arn", "arn:aws:iam::111122223333:role/tracekit-kms")(docs)
            e16._pod(docs)["containers"] = [{"name": "istio-proxy", "image": "istio/proxyv2:1.22",
                                             "securityContext": dict(e16.HARDENED, runAsUser=1337)}]
        self.assertEqual([r for r in e16.run_k8s_case(central) if r["status"] != "ok"], [])

    def test_block_yaml_lists_cronjobs_and_json_files(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "a.yaml"), "w") as f:
            f.write("# rendered\n---\napiVersion: v1\nkind: List\nitems:\n  - kind: Pod\n    metadata:\n      name: p\n"
                    "    spec:\n      hostNetwork: true\n      containers:\n        - name: s\n"
                    "          args: [signer, serve]\n---\n")
        with open(os.path.join(d, "b.json"), "w") as f:
            json.dump({"kind": "CronJob", "metadata": {"name": "c"}, "spec": {"jobTemplate": {"spec": {"template": {
                "spec": {"hostPID": True, "containers": [{"name": "a", "env": [{"name": "TRACEKIT_SIGNER"}]}]}}}}}}, f)
        docs, bad = doctor.load_manifests(d)
        self.assertEqual(bad, [])
        got = {r["id"]: r for r in doctor.k8s_checks(docs)}
        self.assertEqual(got["D-K8S-HOST-ACCESS"]["detail"], "Pod/p: hostNetwork; CronJob/c: hostPID")

    def test_in_pod_reads_its_pod_and_service_account(self):
        docs = e16.k8s_clean()
        pod = {"kind": "Pod", "metadata": {"name": "agent-1", "namespace": "acme"}, "spec": e16._pod(docs)}
        sa = dict(docs[0], metadata=dict(docs[0]["metadata"], annotations={"eks.amazonaws.com/role-arn": "arn"}))
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for n, text in (("namespace", "acme"), ("token", "t0k"), ("ca.crt", "")):
            with open(os.path.join(d, n), "w") as f:
                f.write(text)
        urls = []

        def urlopen(req, **kw):
            urls.append((req.full_url, req.headers["Authorization"]))
            return io.BytesIO(json.dumps(pod if "/pods/" in req.full_url else sa).encode())
        with mock.patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1", "HOSTNAME": "agent-1"}), \
                mock.patch.object(doctor, "SA_DIR", d), mock.patch("ssl.create_default_context"), \
                mock.patch("urllib.request.urlopen", urlopen):
            got = {r["id"]: r["status"] for r in doctor.in_pod()}
        self.assertEqual(urls, [("https://10.0.0.1:443/api/v1/namespaces/acme/pods/agent-1", "Bearer t0k"),
                                ("https://10.0.0.1:443/api/v1/namespaces/acme/serviceaccounts/agent", "Bearer t0k")])
        self.assertEqual(got["D-K8S-WORKLOAD-IDENTITY"], "fail")

    def test_outside_a_pod_it_warns(self):
        with mock.patch.dict(os.environ, clear=True):
            self.assertEqual([(r["id"], r["status"]) for r in doctor.in_pod()], [("D-K8S-WORKLOADS", "warn")])


class Postgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin, cls.cluster = e16.pg_admin()
        if not cls.admin:
            raise unittest.SkipTest(cls.cluster)

    @classmethod
    def tearDownClass(cls):
        e16.pg_stop(cls.cluster)

    def test_signer_with_postgres_grants_passes(self):
        self.assertEqual([r["status"] for r in e16.run_pg_case(self.admin, None)], ["ok", "ok"])

    def test_extra_grants_are_flagged(self):
        for name, want, sql in e16.PG_CASES:
            with self.subTest(name):
                got = {r["id"]: r["status"] for r in e16.run_pg_case(self.admin, sql)}
                self.assertEqual(got[want], "fail", name)


class Kms(unittest.TestCase):
    def setUp(self):
        from test_signer_kms import FakeKms
        self.kms = FakeKms()
        self.issuer = None   # the error code Sign with DryRun raises on the issuer key

        def sign(**req):
            if req.get("DryRun"):
                e = Exception(self.issuer)
                e.response = {"Error": {"Code": self.issuer}}
                raise e
            return FakeKms.sign(self.kms, **req)
        self.kms.sign = sign
        boto3 = types.SimpleNamespace(client=lambda name, region_name: self.kms)
        patcher = mock.patch.dict("sys.modules", boto3=boto3)
        patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, issuer_key=None):
        return {r["id"]: r for r in doctor.kms_checks({"key_id": "alias/log", "region": "eu-west-1"}, issuer_key)}

    def test_log_key_spec_and_usage(self):
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "ok")
        self.kms.spec = "ECC_NIST_P256"
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "fail")

    def test_issuer_key_must_not_be_signable(self):
        for code, want in (("DryRunOperationException", "fail"), ("AccessDeniedException", "ok"),
                           ("NotFoundException", "warn")):
            self.issuer = code
            with self.subTest(code):
                self.assertEqual(self.check("alias/issuer-ca")["D-KMS-ISSUER-SIGN"]["status"], want)
        self.assertNotIn("D-KMS-ISSUER-SIGN", self.check())

    def test_skipped_with_the_reason_without_boto3_or_credentials(self):
        with mock.patch.dict("sys.modules", boto3=None):
            self.assertEqual(self.check()["D-KMS-LOG-KEY"]["detail"], "not checked: no boto3")
        self.kms.get_public_key = mock.Mock(side_effect=type("NoCredentialsError", (Exception,), {})("no creds"))
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "warn")

    @unittest.skipIf(os.name == "nt", "the E16 layout is a POSIX system mode install")
    def test_signer_yaml_with_kms_and_postgres_runs_both(self):
        def mutate(L):
            L.signer_yaml(log_key={"aws_kms": {"key_id": "alias/log", "region": "eu-west-1"}},
                          storage={"postgres": {"dsn_file": "pg.dsn"}})
        with mock.patch.object(doctor, "pg_checks", return_value=[doctor.result("D-PG-SIGNER-ROLE", "ok", "")]) as pg:
            got = {r["id"] for r in e16.run_case(mutate)}
        self.assertTrue({"D-KMS-LOG-KEY", "D-PG-SIGNER-ROLE"} <= got)
        self.assertTrue(pg.call_args.args[0]["dsn_file"].endswith("pg.dsn"))


class Probe(unittest.TestCase):
    agent = types.SimpleNamespace(pw_name="agent", pw_uid=64101, pw_gid=64101)

    @unittest.skipIf(os.name == "nt", "POSIX uids")
    def test_not_probed_unless_root_or_the_agent(self):
        with mock.patch.object(doctor.os, "geteuid", return_value=1000):
            self.assertIsNone(doctor.agent_access(self.agent, [["/", "read"]]))

    @unittest.skipIf(os.name == "nt", "POSIX uids")
    def test_root_probes_in_a_child_dropped_to_the_agent(self):
        with mock.patch.object(doctor.os, "geteuid", return_value=0), \
                mock.patch.object(doctor.files, "as_user", return_value=[["/k", "read"]]) as as_user:
            self.assertEqual(doctor.agent_access(self.agent, [["/k", "read"]]), [["/k", "read"]])
        as_user.assert_called_once_with(self.agent, doctor._access, [["/k", "read"]])

    def test_access_reports_only_what_succeeds(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        missing = os.path.join(d, "missing")
        self.assertEqual(doctor._access([[d, "read"], [missing, "write"]]), [[d, "read"]])


@unittest.skipIf(os.name == "nt", "mount table parsing is POSIX-only")
class FileSystem(unittest.TestCase):
    def test_longest_mount_wins(self):
        with mock.patch.object(doctor, "_mounts", return_value=[("/", "ext4"), ("/srv", "nfs4"), ("/srv/a", "xfs")]):
            self.assertEqual(doctor.fs_type("/srv/data"), "nfs4")
            self.assertEqual(doctor.fs_type("/srv/a/b"), "xfs")
            self.assertEqual(doctor.fs_type("/srvx"), "ext4")


class Report(unittest.TestCase):
    def run_report(self, statuses, as_json=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = doctor.report([doctor.result(f"D-{i}", s, "detail", "fix it") for i, s in enumerate(statuses)],
                                 as_json)
        return code, out.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_report(["ok", "ok"])[0], 0)
        self.assertEqual(self.run_report(["ok", "warn"])[0], 2)
        self.assertEqual(self.run_report(["warn", "fail"])[0], 1)

    def test_json_lists_id_status_detail_fix(self):
        code, out = self.run_report(["ok", "fail"], as_json=True)
        self.assertEqual(json.loads(out), [{"id": "D-0", "status": "ok", "detail": "detail", "fix": ""},
                                           {"id": "D-1", "status": "fail", "detail": "detail", "fix": "fix it"}])

    def test_cli_passes_config_and_json(self):
        with mock.patch.object(doctor, "main", return_value=2) as main:
            self.assertEqual(cli.main(["doctor", "--json", "--config", "/etc/x.yaml"]), 2)
            cli.main(["doctor", "--k8s", "--manifests", "/m", "--issuer-key", "alias/ca"])
        self.assertEqual(main.call_args_list, [mock.call("/etc/x.yaml", True, False, None, None),
                                               mock.call(None, False, True, "/m", "alias/ca")])


class Detect(unittest.TestCase):
    def collect(self, sc, config=None):
        with mock.patch.object(doctor.client, "system_config", return_value=sc), \
                mock.patch.object(install, "v1_results", return_value=[doctor.result("D-V1-X", "ok", "v1")]), \
                mock.patch.object(doctor, "v2_checks", return_value=[doctor.result("D-V2", "ok", "v2")]) as v2:
            return [r["id"] for r in doctor.collect(config)], v2

    def test_v1_system_mode(self):
        self.assertEqual(self.collect({"socket": "/var/lib/tracekit/tracekitd.sock"})[0], ["D-V1-X"])

    def test_v2_system_mode(self):
        ids, v2 = self.collect({"signer": "/run/tracekit-signer/signer.sock", "hooks": {"user": "nobody-e16"}})
        self.assertEqual(ids, ["D-V2"])
        self.assertEqual(v2.call_args.args[0], install.V2_CONFIG)
        self.assertEqual(v2.call_args.kwargs["signer"], "/run/tracekit-signer/signer.sock")

    def test_both_system_modes(self):
        self.assertEqual(self.collect({"socket": "/s", "signer": "/t"})[0], ["D-V1-X", "D-V2"])

    def test_config_flag(self):
        ids, v2 = self.collect(None, "/etc/other.yaml")
        self.assertEqual((ids, v2.call_args.args[0]), (["D-V2"], "/etc/other.yaml"))

    def test_dev_signer(self):
        ids, v2 = self.collect(None)
        self.assertEqual(v2.call_args.args[1], "dev")
        # the dev signer keeps content (1.2.2): doctor checks the vault it runs, not one that is off
        self.assertTrue(v2.call_args.args[0]["content"]["retain"])
        with mock.patch.dict(os.environ, {"TRACEKIT_DEV_CONTENT": "0"}):
            self.assertIsNone(self.collect(None)[1].call_args.args[0]["content"])

    def test_dev_signer_finds_the_hooks_in_any_settings_file_init_writes(self):
        """Dev doctor read only $CLAUDE_CONFIG_DIR's (or ~/.claude's) settings: hooks in the other one, or in the
        project's, were reported missing."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home, config, project = (os.path.join(d, n) for n in ("home", "config", "project"))
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        for settings, env in ((os.path.join(home, ".claude", "settings.json"), {"CLAUDE_CONFIG_DIR": config}),
                              (os.path.join(project, ".claude", "settings.json"), {})):
            os.makedirs(project, exist_ok=True)
            os.chdir(project)
            with contextlib.redirect_stdout(io.StringIO()):
                install.install_hooks(settings, module=install.V2_HOOK)
            with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home, **env}), \
                    mock.patch.object(install.client, "client_config", return_value={}):
                _, v2 = self.collect(None)
            self.assertEqual(os.path.realpath(v2.call_args.kwargs["settings"]), os.path.realpath(settings))
            install.install_hooks(settings, uninstall=True)

    def test_untrusted_system_config_fails(self):
        with mock.patch.object(doctor.client, "system_config", side_effect=client.SystemConfigError("not root-owned")):
            self.assertEqual([(r["id"], r["status"]) for r in doctor.collect()], [("D-SYSTEM-CONFIG", "fail")])


class PluginHooks(unittest.TestCase):
    """The Claude Code plugin's hooks are init's: doctor told plugin users `fix: tracekit init --dev --v2`, after which
    every call was decided twice and every approved call blocked."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.settings, self.plugin = os.path.join(self.d, "settings.json"), os.path.join(self.d, "user.json")

    def hooks_present(self, settings, plugin):
        return {r["id"]: r for r in doctor.v2_checks({"data_dir": self.d}, "dev", settings=settings,
                                                     plugin=plugin)}["D-HOOKS-PRESENT"]

    def test_the_plugins_hooks_count_and_init_is_not_suggested(self):
        for settings in (self.settings, None):   # dev mode; system mode with no hooks recorded in client.json
            got = self.hooks_present(settings, self.plugin)
            self.assertEqual((got["status"], got["fix"]), ("ok", ""), settings)
            self.assertIn("Claude Code plugin", got["detail"])
        self.assertIn("tracekit init --dev --v2", self.hooks_present(self.settings, None)["fix"])

    def test_the_plugin_with_inits_hooks_is_flagged(self):
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(self.settings, module=install.V2_HOOK)
        got = self.hooks_present(self.settings, self.plugin)
        self.assertEqual(got["status"], "warn")
        self.assertIn("every approved call is blocked", got["detail"])
        self.assertIn(f"/plugin disable {install.PLUGIN}", got["fix"])
        self.assertEqual(self.hooks_present(self.settings, None)["status"], "ok")

    def test_collect_reads_enabled_plugins(self):
        home = os.path.join(self.d, "home")
        os.makedirs(os.path.join(home, ".claude"))
        with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.d)
        with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}), \
                mock.patch.object(install.client, "client_config", return_value={}), \
                mock.patch.object(doctor.client, "system_config", return_value=None), \
                mock.patch.object(doctor, "v2_checks", return_value=[]) as v2:
            doctor.collect()
        self.assertEqual(v2.call_args.kwargs["plugin"], os.path.join(home, ".claude", "settings.json"))


class ThinkingSummaries(unittest.TestCase):
    """D-THINKING-SUMMARIES: with Claude Code's hooks and the content vault on, thinking summaries off leave every
    transcript's reasoning sealed, so `tracekit analyze --v2` can't check it."""

    def check(self, settings_extra, vault=True):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, "settings.json")
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, module=install.V2_HOOK)
        with open(settings) as f:
            s = json.load(f)
        with open(settings, "w") as f:
            json.dump(dict(s, **settings_extra), f)
        cfg = {"data_dir": d, "content": {"retain": True} if vault else None}
        with mock.patch.object(install, "user_settings", return_value=os.path.join(d, "none.json")):
            return {r["id"]: r for r in doctor.v2_checks(cfg, "dev", settings=settings)}["D-THINKING-SUMMARIES"]

    def test_off_with_the_vault_warns_and_names_the_setting_and_the_headless_flag(self):
        got = self.check({})
        self.assertEqual(got["status"], "warn")
        self.assertIn('"showThinkingSummaries": true', got["fix"])
        self.assertIn("claude -p --thinking-display summarized", got["fix"])
        self.assertEqual(self.check({"showThinkingSummaries": False})["status"], "warn")

    def test_on_or_without_the_vault_is_ok(self):
        self.assertEqual(self.check({"showThinkingSummaries": True})["status"], "ok")
        self.assertEqual(self.check({}, vault=False)["status"], "ok")


@unittest.skipIf(os.name == "nt", "POSIX modes")
class DevProfile(unittest.TestCase):
    def test_dev_signer_warns_instead_of_failing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        got = {r["id"]: r["status"] for r in doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none"))}
        self.assertEqual(got["D-PROCESS-BOUNDARY"], "warn")
        self.assertEqual(got["D-WITNESS-CONFIGURED"], "warn")
        self.assertEqual(got["D-HOOKS-PRESENT"], "warn")
        self.assertEqual(got["D-DURABILITY"], "ok")
        self.assertNotIn("D-AGENT-PRIV", got)


if __name__ == "__main__":
    unittest.main()
