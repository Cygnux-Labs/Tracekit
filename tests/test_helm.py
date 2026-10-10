"""The Helm chart (deploy/helm/tracekit-signer): what `helm template` renders keeps the agent away from the signer's
data, keys and config. deploy/helm/e2e.sh runs it on a kind cluster."""
import os
import shutil
import subprocess
import tempfile
import unittest

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
