"""Bundles of today's signer, checked by the released verifiers: the Python verifier of each tag in RELEASED, from the
tag itself (`git archive`), in a child process. A bundle that declares a verifier_min_version up to the release's must
verify there with the same check lines (names and statuses) as here; one that needs more (a run in parts among them) is
`UNVERIFIABLE (needs tracekit >= x)`, exit 2, never FAILED. Skipped when the clone has no release tags; under CI, a
clone with some tags but not this one fails (CI's test job fetches them)."""
import http.client
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

from adapter_contract import _serve
from test_a2a import A2aServer, TEXT
from test_bundle_v2 import Log, ext_bundle, trust_config
from test_executor import InProcess
from test_gateway import AGENT as TOKEN_AGENT, SECRET, serve   # TOKEN_AGENT: the agent the A2A gateway's token names
from test_reviews import ANALYZER, ME, Signed
from tracekit import a2a_gateway
from tracekit.deploy import files as tkfiles
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASED = ["v1.2.0", "v1.2.3", "v1.3.0", "v1.4.0", "v1.4.1", "v1.4.2"]   # add each release's tag
SENSOR = CallerIdentity("mtls", "spiffe://acme/tetragon", True)
OPENSHELL = CallerIdentity("mtls", "spiffe://acme/openshell", True)   # a configured gateway
VERIFY = ("import json, sys, tracekit\nfrom tracekit.verify import v2\nrep, code = v2.verify(sys.argv[1], sys.argv[2])\n"
          "print(json.dumps({'version': tracekit.__version__, 'code': code, 'integrity': rep.integrity, "
          "'checks': rep.checks}))")


class Released(Signed):
    @classmethod
    def setUpClass(cls):
        cls.roots = {}   # tag -> a directory holding that release's tracekit package
        for tag in RELEASED:
            p = subprocess.run(["git", "-C", ROOT, "archive", "--format=zip", tag, "tracekit"], capture_output=True)
            if p.returncode == 0:
                cls.roots[tag] = tempfile.mkdtemp()
                cls.addClassCleanup(shutil.rmtree, cls.roots[tag], True)
                with zipfile.ZipFile(io.BytesIO(p.stdout)) as z:
                    z.extractall(cls.roots[tag])

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.s = svc.SignerService(os.path.join(self.dir, "data"), grace_s=0, fsck_every_s=0, observe_grace_s=0,
                                   analyzers=[f"uid:{ANALYZER.subject}"], gateways=[f"mtls:{OPENSHELL.subject}"],
                                   authorize={f"{SENSOR.scheme}:{SENSOR.subject}": ["observe_effect"],
                                              f"mtls:{OPENSHELL.subject}": sorted(svc.DEFAULT_GRANTS
                                                                                  | {"observe_effect"}),
                                              f"{TOKEN_AGENT.scheme}:{TOKEN_AGENT.subject}":
                                                  sorted(svc.DEFAULT_GRANTS)})
        self.addCleanup(self.s.close)

    def released_verify(self, tag, bundle, trust):
        if tag not in self.roots:
            # under CI, a clone that fetched the release tags (it has some) must have every one; a plain checkout skips
            missing = self.fail if os.environ.get("CI") and self.roots else self.skipTest
            missing(f"{tag} is not in this clone: git fetch origin tag {tag}")
        p = subprocess.run([sys.executable, "-c", VERIFY, bundle, trust], cwd=self.roots[tag], capture_output=True,
                           text=True, env={**os.environ, "PYTHONPATH": self.roots[tag]})
        out = json.loads(p.stdout or "null") or self.fail(p.stderr)
        self.assertEqual(out["version"], tag[1:])   # that release's verifier, not this checkout's
        return out

    def sensor_run(self, effect):
        """A run a kernel sensor's import covered: with `effect` an exec it saw, else none and then a loss."""
        def observe(**req):
            self.call(SENSOR, "observe_effect", instance="i", sensor="tetragon", callers=[f"uid:{ME.subject}"], **req)
        observe(effects=[])
        run = self.register(ME)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() + 1))   # after the run registered
        proc = {"caller": f"uid:{ME.subject}", "ts": ts, "pid": 7, "binary": "/usr/bin/curl"}
        if effect:
            observe(effects=[dict(proc, kind="exec")])
        else:
            observe(effects=[], lost="ring buffer overflow")
        self.call(ME, "close_run", **run)
        return run

    def openshell_run(self):
        """A sandbox's run the OpenShell middleware registered and its OCSF import covered: a connection OpenShell
        blocked, then a loss of the run's events OpenShell reported."""
        def observe(*effects):
            self.call(OPENSHELL, "observe_effect", instance="i", sensor="openshell",
                      callers=[f"mtls:{OPENSHELL.subject}"], effects=list(effects))
        observe()
        run = self.register(OPENSHELL)
        at = {**run, "ts": "2026-10-12T10:00:00.000000Z"}
        observe(dict(at, kind="connect", pid=7, binary="/usr/bin/curl", host="blocked.example.com", port=443,
                     denied=True))
        observe(dict(run, kind="lost", reason="OpenShell dropped 3 records"))
        self.call(OPENSHELL, "close_run", **run)
        return run

    def a2a_run(self):
        """A run whose agent messaged another agent through the A2A gateway: decided and completed by the gateway (as
        OPENSHELL, a configured one), tier T2."""
        up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), A2aServer)
        up.seen, up.cards, up.big = [], [], False
        tkfiles.write(self.dir, "bearer", SECRET.encode())
        cfg, url = os.path.join(self.dir, "a2a.yaml"), f"http://127.0.0.1:{serve(self, up)}/researcher"
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused",
                       "upstreams": [{"name": "researcher", "url": url}]}, f)
        port = serve(self, a2a_gateway.serve(a2a_gateway.load_config(cfg), InProcess(self.s, OPENSHELL)))
        run = self.register(TOKEN_AGENT)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        self.addCleanup(c.close)
        c.request("POST", "/a2a/researcher", json.dumps({"jsonrpc": "2.0", "id": 7, "method": "message/send",
                                                          "params": {"message": TEXT}}),
                  {"authorization": "Bearer " + SECRET, "content-type": "application/json",
                   "x-tracekit-run": f"{run['run_id']}.{run['run_token']}"})
        self.assertIn("result", json.loads(c.getresponse().read()))
        self.call(TOKEN_AGENT, "close_run", **run)
        return run

    def transfer_run(self):
        """A run that transferred a model's state to another model (run.transfer, tool a2a:transfer), as C2C does."""
        run = Client(_serve(self, self.s.handle_frame)).run("sender")
        out = run.transfer("qwen-7b@1", "llama-1b@2", b"KV-STATE", "kv-cache", projector="c2c@0.1")
        self.assertTrue(out["ok"], out)
        run.close()
        return {"run_id": run.run_id}

    def test_released_verifiers_read_todays_bundles(self):
        run = self.agent_run()
        cases = {"an agent run": (self.export(run), "1.2.0")}
        # a run past the per-file limit, here lowered so it fills two parts: no released verifier reads parts
        files = v2.read_zip(cases["an agent run"][0][0])
        with mock.patch.object(v2, "MAX_ENTRY", max(len(b) for n, b in files.items() if n.startswith("runs/")) - 1):
            cases["a run in parts"] = (self.export(run), "1.4.0")
        self.findings(ANALYZER, run)
        cases["the run, with a findings run not exported"] = (self.export(run), "1.2.0")
        # a sensor's loss names its sensor: an older verifier says it can't verify it rather than print a line about
        # an egress observer
        cases["a sensor covered it, then lost events"] = (self.export(self.sensor_run(effect=False)), "1.4.0")
        cases["a sensor's effect"] = (self.export(self.sensor_run(effect=True)), "1.4.0")
        cases["OpenShell blocked a connection, then lost events"] = (self.export(self.openshell_run()), "1.4.0")
        cases["an A2A gateway call"] = (self.export(self.a2a_run()), "1.2.0")
        cases["a C2C transfer"] = (self.export(self.transfer_run()), "1.2.0")
        log = Log(os.path.join(self.dir, "ext"))
        self.addCleanup(log.store.close)
        cases["an ext field and record"] = ((ext_bundle(log, os.path.join(self.dir, "ext.tkb")),
                                             os.path.join(self.dir, "ext.trust.json")), "1.4.0")
        with open(cases["an ext field and record"][0][1], "w") as f:
            json.dump(trust_config(), f)
        for tag in RELEASED:
            for name, ((bundle, trust), need) in cases.items():
                with self.subTest(tag=tag, bundle=name):
                    self.assertEqual(json.loads(v2.read_zip(bundle)["manifest.json"])["verifier_min_version"], need)
                    old, (rep, code) = self.released_verify(tag, bundle, trust), v2.verify(bundle, trust)
                    self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
                    self.assertEqual("observers" in rep.warnings, "lost" in name)   # the loss is a signed gap
                    if v2._version(need) <= v2._version(tag[1:]):
                        self.assertEqual((old["code"], old["integrity"]), (0, "VERIFIED"), old["checks"])
                        self.assertEqual([(c["check"], c["status"]) for c in old["checks"]],
                                         [(c["check"], c["status"]) for c in rep.checks])
                    else:
                        self.assertEqual((old["code"], old["integrity"]), (2, f"UNVERIFIABLE (needs tracekit >= {need})"))


if __name__ == "__main__":
    unittest.main()
