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

    def test_data_dir_of_the_agents_user_fails_the_boundary(self):
        def agent_is_me(L):
            L.kw["agent"] = types.SimpleNamespace(**dict(vars(e16.AGENT), pw_uid=os.getuid()))
        got = {r["id"]: r for r in e16.run_case(agent_is_me)}
        self.assertEqual(got["D-PROCESS-BOUNDARY"]["status"], "fail")


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

    def test_untrusted_system_config_fails(self):
        with mock.patch.object(doctor.client, "system_config", side_effect=client.SystemConfigError("not root-owned")):
            self.assertEqual([(r["id"], r["status"]) for r in doctor.collect()], [("D-SYSTEM-CONFIG", "fail")])


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
