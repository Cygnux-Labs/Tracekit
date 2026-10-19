"""examples/v2/agent_sandbox without a cluster (e2e.sh runs it on kind): the signer config in its ConfigMap loads, and
the Sandbox reaches that signer with a token it accepts, as an identity it maps to a tenant and grants the calls
agent.py makes."""
import os
import re
import ssl
import tempfile
import unittest
from unittest import mock

import yaml

from tracekit.signer import service

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "v2", "agent_sandbox")
# agents.x-k8s.io/v1beta1 SandboxSpec: SandboxBlueprint, Lifecycle and operatingMode (api/v1beta1/sandbox_types.go)
SANDBOX_SPEC = {"podTemplate", "volumeClaimTemplates", "service", "shutdownTime", "shutdownPolicy", "operatingMode"}


def objects(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return {o["kind"]: o for o in yaml.safe_load_all(f)}


@unittest.skipUnless(os.path.exists(os.path.join(DIR, "signer.yaml")), "an sdist ships only the examples' .py files")
class AgentSandboxExample(unittest.TestCase):
    def test_the_sandbox_reaches_the_signer_as_an_identity_it_accepts(self):
        signer, agent = objects("signer.yaml"), objects("sandbox.yaml")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(signer["ConfigMap"]["data"]["signer.yaml"])
        self.addCleanup(os.remove, f.name)
        with mock.patch.object(ssl.SSLContext, "load_cert_chain"), mock.patch("ssl.create_default_context"):
            cfg = service.load_config(f.name)
        sandbox = agent["Sandbox"]
        self.assertEqual(sandbox["apiVersion"], "agents.x-k8s.io/v1beta1")
        self.assertLessEqual(set(sandbox["spec"]), SANDBOX_SPEC)
        self.assertLessEqual(set(sandbox["spec"]["podTemplate"]), {"spec", "metadata"})
        pod = sandbox["spec"]["podTemplate"]["spec"]
        self.assertIs(pod["automountServiceAccountToken"], False)
        sa = agent["ServiceAccount"]["metadata"]
        self.assertEqual((pod["serviceAccountName"], sa["namespace"]), (sa["name"], sandbox["metadata"]["namespace"]))
        token = next(v for v in pod["volumes"] if "projected" in v)["projected"]["sources"][0]["serviceAccountToken"]
        self.assertEqual(token["audience"], cfg["http"]["k8s_sa"]["audience"])
        env = {e["name"]: e["value"] for e in pod["containers"][0]["env"]}
        svc = signer["Service"]
        self.assertEqual(env["TRACEKIT_SIGNER"], f"https://{svc['metadata']['name']}.{svc['metadata']['namespace']}.svc:"
                                                 f"{svc['spec']['ports'][0]['port']}")
        identity = f"k8s_sa:system:serviceaccount:{sa['namespace']}:{sa['name']}"
        self.assertEqual(service.lookup(cfg["tenants"], identity), "agents")   # e2e.sh exports with --tenant agents
        with open(os.path.join(DIR, "agent.py"), encoding="utf-8") as f:
            calls = {"register_run", *re.findall(r"\brun\.(\w+)\(", f.read())}   # decide, complete
        self.assertLessEqual(calls, set(service.lookup(cfg["authorize"], identity)))
