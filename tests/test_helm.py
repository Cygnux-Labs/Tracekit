"""The Helm charts: what `helm template` renders. The sidecar (deploy/helm/tracekit-signer) keeps the agent away from the
signer's data, keys and config; deploy/helm/e2e.sh runs it on a kind cluster. The central signer
(deploy/helm/tracekit-central): one writer per log, a run's calls routed to its replica, identities, credentials."""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tracekit import yamlmini
from tracekit.sdk.client import _Https
from tracekit.signer import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART = os.path.join(ROOT, "deploy", "helm", "tracekit-signer")
HARDENED = {"runAsNonRoot": True, "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


def render(*sets):
    args = ["helm", "template", "t", CHART, "--set", "agent.image=agent:1"]
    for s in sets:
        args += ["--set", s]
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


@unittest.skipIf(not shutil.which("helm"), "helm is not installed")
class Chart(unittest.TestCase):
    def manifests(self, *sets):
        import yaml
        p = render(*sets)
        self.assertEqual(p.returncode, 0, p.stderr)
        return {d["kind"]: d for d in yaml.safe_load_all(p.stdout) if d}

    def test_sidecar_is_isolated_from_the_agent(self):
        m = self.manifests("recordKey.secretName=rk")
        pod = m["Deployment"]["spec"]["template"]["spec"]
        self.assertIs(pod["automountServiceAccountToken"], False)
        [signer], [agent] = pod["initContainers"], pod["containers"]
        self.assertEqual(signer["restartPolicy"], "Always")
        for c, uid in ((signer, 10001), (agent, 1000)):
            self.assertEqual(c["securityContext"], {**HARDENED, "runAsUser": uid, "runAsGroup": uid})
        volumes = {v["name"]: v for v in pod["volumes"]}
        self.assertEqual([v["name"] for v in agent["volumeMounts"]], ["signer-socket"])
        self.assertIn("emptyDir", volumes["signer-socket"])
        self.assertEqual({v["name"] for v in signer["volumeMounts"]},
                         {"signer-data", "signer-socket", "signer-config", "record-key"})
        self.assertEqual(volumes["signer-data"]["persistentVolumeClaim"]["claimName"], "t-signer-data")
        self.assertEqual(volumes["record-key"]["secret"]["secretName"], "rk")
        self.assertIn({"name": "TRACEKIT_SIGNER", "value": "/run/tracekit-signer/signer.sock"}, agent["env"])

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "signer.yaml")
            with open(path, "w") as f:
                f.write(m["ConfigMap"]["data"]["signer.yaml"])
            cfg = service.load_config(path)
        self.assertEqual(cfg["tenants"], {"uid:1000": "default"})
        self.assertEqual(cfg["socket"], "/run/tracekit-signer/signer.sock")
        self.assertEqual(cfg["metrics"], {"listen": "127.0.0.1:9464"})

    def test_config_keeps_the_chart_keys(self):
        p = render("signer.config.socket=/tmp/s", "signer.config.grace_s=9")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('socket: "/run/tracekit-signer/signer.sock"', p.stdout)
        self.assertIn("grace_s: 9", p.stdout)

    def test_dev_volume_and_network_policy(self):
        m = self.manifests("persistence.enabled=false", "metrics.remote=true", "networkPolicy.enabled=true")
        self.assertNotIn("PersistentVolumeClaim", m)
        volumes = {v["name"]: v for v in m["Deployment"]["spec"]["template"]["spec"]["volumes"]}
        self.assertEqual(volumes["signer-data"], {"name": "signer-data", "emptyDir": {}})
        [rule] = m["NetworkPolicy"]["spec"]["ingress"]
        self.assertEqual(rule["ports"], [{"port": 9464, "protocol": "TCP"}])
        self.assertEqual(rule["from"][0]["namespaceSelector"]["matchLabels"],
                         {"kubernetes.io/metadata.name": "monitoring"})

    def test_refuses_an_agent_uid_the_signer_cannot_tell_apart(self):
        for uid in (0, 10001):
            p = render(f"agent.uid={uid}")
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("agent.uid must be neither 0 nor signer.uid", p.stderr)


CENTRAL = os.path.join(ROOT, "deploy", "helm", "tracekit-central")
FULL = ["tls.secretName=tls", "autoscaling.enabled=true", "autoscaling.maxReplicas=3", "awsKms.region=eu-west-1",
        "awsKms.keyIds={k0,k1,k2}", "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:signer",
        "issuer.enabled=true", "issuer.tlsSecretName=itls", "viewer.enabled=true", "viewer.tokenSecretName=vt",
        "viewer.tlsSecretName=vtls", "monitor.enabled=true", "monitor.logKeys={a+1+b,c+2+d,e+3+f}"]


def render_central(*sets):
    args = ["helm", "template", "t", CENTRAL, "--namespace", "ns"]
    for s in sets:
        args += ["--set", s]
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


@unittest.skipIf(not shutil.which("helm"), "helm is not installed")
class Central(unittest.TestCase):
    def objects(self, *sets):
        import yaml
        p = render_central(*sets)
        self.assertEqual(p.returncode, 0, p.stderr)
        return {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(p.stdout) if d}

    def configs(self, m):
        out = {}
        with tempfile.TemporaryDirectory() as d, mock.patch("tracekit.transport.http.configure"):   # no TLS files here
            for name, text in m["ConfigMap", "t-signer"]["data"].items():
                with open(os.path.join(d, name), "w") as f:
                    f.write(text)
                out[name] = service.load_config(os.path.join(d, name))
        return out

    def test_lint(self):
        p = subprocess.run(["helm", "lint", CENTRAL, "--set", "tls.secretName=tls"], capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_one_writer_per_log(self):
        m = self.objects(*FULL)
        cfgs = self.configs(m)
        self.assertEqual(sorted(cfgs), ["signer-0.yaml", "signer-1.yaml", "signer-2.yaml"])   # one per reachable replica
        for n in range(3):
            c = cfgs[f"signer-{n}.yaml"]
            self.assertEqual((c["route"], c["origin"], c["storage"]["postgres"]["dsn_file"], c["log_key"]),
                             (f"t-{n}", f"t.ns/log/{n}", f"/etc/tracekit/dsn/dsn-{n}",
                              {"aws_kms": {"key_id": f"k{n}", "region": "eu-west-1"}}))
        sts = m["StatefulSet", "t"]
        self.assertNotIn("replicas", sts["spec"])   # the HPA's
        pod = sts["spec"]["template"]["spec"]
        [signer] = pod["containers"]
        self.assertIn('--config "/etc/tracekit/central/signer-${HOSTNAME##*-}.yaml"', signer["command"][2])
        [dsn] = [v for v in pod["volumes"] if v["name"] == "dsn"]
        self.assertEqual([s["secret"] for s in dsn["projected"]["sources"]],
                         [{"name": f"tracekit-log-{n}", "items": [{"key": "dsn", "path": f"dsn-{n}"}]} for n in range(3)])
        self.assertEqual(sts["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"], ["ReadWriteOnce"])
        hpa = m["HorizontalPodAutoscaler", "t"]["spec"]
        self.assertEqual((hpa["minReplicas"], hpa["maxReplicas"], hpa["metrics"][0]["pods"]["metric"]["name"]),
                         (2, 3, "tracekit_signer_queue_depth"))
        self.assertEqual(hpa["behavior"], {"scaleDown": {"selectPolicy": "Disabled"}})

    def test_a_run_is_routed_to_its_replica(self):
        m = self.objects(*FULL)
        sel = {"app.kubernetes.io/name": "tracekit-central", "app.kubernetes.io/instance": "t",
               "app.kubernetes.io/component": "signer"}
        self.assertEqual(m["Service", "t"]["spec"]["selector"], sel)   # register_run: any ready replica
        for n in range(3):   # a run's later calls: t-<n>.ns.svc, the replica whose route its id carries
            self.assertEqual(m["Service", f"t-{n}"]["spec"]["selector"],
                             {**sel, "statefulset.kubernetes.io/pod-name": f"t-{n}"})
            self.assertEqual(_Https("https://t.ns.svc:8443")._host({"run_id": f"t-{n}.ab"}), f"t-{n}.ns.svc")

    def test_identities(self):
        m = self.objects(*FULL)
        for c in self.configs(m).values():
            self.assertEqual(c["http"]["authenticators"], ["k8s_sa"])
            self.assertEqual(c["http"]["k8s_sa"]["tokenreview"], "https://kubernetes.default.svc")
        crb = m["ClusterRoleBinding", "ns-t-tokenreview"]
        self.assertEqual(crb["roleRef"]["name"], "system:auth-delegator")
        self.assertEqual({s["name"] for s in crb["subjects"]}, {"t-signer", "t-issuer"})
        [rule] = m["Role", "t-signer"]["rules"]
        self.assertEqual((rule["resourceNames"], rule["verbs"]), (["t"], ["get"]))

    def test_cloud_credentials_only_on_the_signers_account(self):
        m = self.objects(*FULL)
        annotated = {k for k, d in m.items() if k[0] == "ServiceAccount" and d["metadata"].get("annotations")}
        self.assertEqual(annotated, {("ServiceAccount", "t-signer")})
        for kind, name in (("Deployment", "t-viewer"), ("Deployment", "t-monitor")):
            pod = m[kind, name]["spec"]["template"]["spec"]
            self.assertIs(pod["automountServiceAccountToken"], False, name)
            self.assertNotIn("serviceAccountName", pod)
        self.assertEqual(m["StatefulSet", "t"]["spec"]["template"]["spec"]["serviceAccountName"], "t-signer")
        for k, d in m.items():   # no Secret, credential or env reaches anything an agent talks to
            if k[0] == "Service":
                self.assertEqual(set(d["spec"]), {"selector", "ports"}, k)

    def test_security_contexts(self):
        m = self.objects(*FULL)
        pods = [d["spec"]["template"]["spec"] for (kind, _), d in m.items() if kind in ("StatefulSet", "Deployment")]
        self.assertEqual(len(pods), 4)
        for pod in pods:
            for c in pod["containers"]:
                sc = c["securityContext"]
                self.assertEqual(sc, {**HARDENED, "runAsUser": 10001, "runAsGroup": 10001}, c["name"])
        net = m["NetworkPolicy", "t-signer"]["spec"]["ingress"]
        self.assertEqual(net[0], {"ports": [{"port": 8443, "protocol": "TCP"}]})
        self.assertEqual(net[1]["ports"], [{"port": 9464, "protocol": "TCP"}])

    def test_viewer_reads_every_log_with_its_own_dsn(self):
        m = self.objects(*FULL, "viewer.config.view.oidc.issuer=corp", "viewer.config.data_dir=/nope")
        cfg = yamlmini.load_any(m["ConfigMap", "t-viewer"]["data"]["viewer.yaml"])
        self.assertEqual(cfg, {"data_dir": "/tmp", "view": {"oidc": {"issuer": "corp"}, "logs": [
            "/etc/tracekit/dsn/dsn-0", "/etc/tracekit/dsn/dsn-1", "/etc/tracekit/dsn/dsn-2"]}})
        [dsn] = [v for v in m["Deployment", "t-viewer"]["spec"]["template"]["spec"]["volumes"] if v["name"] == "dsn"]
        self.assertEqual([s["secret"]["name"] for s in dsn["projected"]["sources"]],
                         ["tracekit-log-read-0", "tracekit-log-read-1", "tracekit-log-read-2"])

    def test_refusals(self):
        for sets, err in ((["tls.secretName=tls", "awsKms.region=r", "awsKms.keyIds={k0}"], "awsKms.keyIds needs a key"),
                          ([], "tls.secretName is required"),
                          (["tls.secretName=tls", "replicas=0"], "replicas must be at least 1")):
            p = render_central(*sets)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(err, p.stderr)
