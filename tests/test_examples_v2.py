"""The v2 examples (examples/v2/<framework>/agent.py) run to completion in scripted mode on a dev signer they start on
demand, each with its deny, its approval and a verified bundle; and `tracekit demo --server` verifies its bundle and
fails the tampered copy. A temp HOME and runtime dir keep them off the user's own dev signer."""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from e22_import import import_e22  # noqa: E402
NEEDS = {"custom": (), "langchain": ("langchain", "langgraph"), "openai_agents": ("agents",),
         "claude_agent_sdk": ("claude_agent_sdk",), "mcp": ("mcp",),
         "pydantic_ai": ("pydantic_ai",), "agent_framework": ("agent_framework",), "google_adk": ("google.adk",),
         "haystack": ("haystack",), "strands": ("strands",), "llama_index": ("llama_index",), "crewai": ("crewai",)}


def python(*argv, env, cwd):
    return subprocess.run([sys.executable, *argv], capture_output=True, text=True, env=env, cwd=cwd, timeout=180)


class Examples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
        cls.addClassCleanup(shutil.rmtree, cls.dir, True)
        home = os.path.join(cls.dir, "home")
        # importing crewai on Windows asks for these folders (#391)
        for sub in (("AppData", "Local"), ("AppData", "Roaming"), ("local",), ("data",)):
            os.makedirs(os.path.join(home, *sub), exist_ok=True)
        # TRACEKIT_DEV_GRACE: the dev signer makes a closed run final 0.2 s after, not 5 s; each example exports its
        # run once it is
        cls.env = dict(os.environ, HOME=home, USERPROFILE=home, LOCALAPPDATA=os.path.join(home, "local"),
                       XDG_DATA_HOME=os.path.join(home, "data"), TRACEKIT_RUNTIME_DIR=os.path.join(cls.dir, "run"),
                       TRACEKIT_DEV_GRACE="0.2", PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        for k in ("TRACEKIT_SIGNER", "TRACEKIT_SIGNER_TOKEN"):
            cls.env.pop(k, None)
        cls.addClassCleanup(python, "-m", "tracekit", "down", env=cls.env, cwd=cls.dir)

    def run_example(self, name):
        missing = [m for m in NEEDS[name] if importlib.util.find_spec(m) is None]
        if missing:
            self.skipTest(f"{', '.join(missing)} not installed")
        p = python(os.path.join(ROOT, "examples", "v2", name, "agent.py"), "--scripted", env=self.env, cwd=self.dir)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev", p.stdout)
        self.assertIn("approved: apr-", p.stdout)
        self.assertIn("blocked by policy: TK-DEMO-DENY" if name == "mcp" else "TK-D001", p.stdout)
        return p.stdout

    def test_custom(self):
        out = self.run_example("custom")
        self.assertLess(out.index("approved: apr-"), out.index(": ask -> (pretend) ran"), out)   # as it happened

    def test_langchain(self):
        self.run_example("langchain")

    def test_langchain_injection_fork_replay(self):
        if any(importlib.util.find_spec(m) is None for m in NEEDS["langchain"]):
            self.skipTest("langchain / langgraph not installed")
        p = python(os.path.join(ROOT, "examples", "v2", "langchain", "injection.py"), env=self.env, cwd=self.dir)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("recorded: fetch_page, get_weather, send_email", p.stdout)
        self.assertIn("primary cause", p.stdout)
        self.assertIn("Integrity: VERIFIED.", p.stdout)

    def test_openai_agents(self):
        self.run_example("openai_agents")

    def test_claude_agent_sdk(self):
        self.run_example("claude_agent_sdk")

    def test_mcp(self):
        self.run_example("mcp")

    def test_pydantic_ai(self):
        self.run_example("pydantic_ai")

    def test_agent_framework(self):
        self.run_example("agent_framework")

    def test_google_adk(self):
        self.run_example("google_adk")

    def test_haystack(self):
        self.run_example("haystack")

    def test_strands(self):
        self.run_example("strands")

    def test_llama_index(self):
        self.run_example("llama_index")

    def test_crewai(self):
        self.run_example("crewai")


class DemoServer(unittest.TestCase):
    def test_bundle_verifies_and_the_tampered_copy_fails(self):
        p = subprocess.run([sys.executable, "-m", "tracekit", "demo", "--server"], capture_output=True, text=True,
                           timeout=120, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        verified, tampered = p.stdout.split("tamper test")
        # each scripted call's verdict and first rule under the server pack as shipped
        self.assertIn("\n  policy: server pack\n", verified)
        self.assertEqual(re.findall(r"': (\w+) ?(\S*)", verified),
                         [("allow", ""), ("ask", "TK-SHELL-PARSE"), ("deny", "TK-D002"), ("deny", "TK-S004"),
                          ("ask", "TK-P003"), ("deny", "TK-D003")])
        self.assertEqual(len(re.findall(r"^    rejected apr-[0-9a-f]{32}: it never runs$", verified, re.M)), 2)
        self.assertIn("\nVERIFIED: 6 tool calls in 17 signed records, none changed, removed or added after signing.\n"
                      "NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could "
                      "have rewritten the record.\n", verified)   # what dev mode means
        self.assertNotIn("PASS", verified)
        self.assertIn("\nTAMPERED at event 8: its content was changed after it was signed.\n", tampered)
        self.assertRegex(tampered, r"\ndeleted .+ \(--keep keeps it\)\n$")

    def test_detail_prints_every_check_and_keep_says_where_the_files_are(self):
        p = subprocess.run([sys.executable, "-m", "tracekit", "demo", "--server", "--detail", "--keep"],
                           capture_output=True, text=True, timeout=120, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        verified, tampered = p.stdout.split("tamper test")
        self.assertIn("Integrity: VERIFIED.", verified)
        self.assertIn("cosigned ed25519 by witness.demo.tracekit.local", verified)
        self.assertIn("Integrity: FAILED.", tampered)
        kept = tampered.split("\nkept ", 1)[1].split("\n")[0]
        self.addCleanup(shutil.rmtree, kept, True)
        kept_files = {f for f in os.listdir(kept) if f.endswith((".tkb", ".json"))}   # Windows: the signer's endpoint
        self.assertEqual(kept_files - {"endpoint.json"}, {"run.tkb", "tampered.tkb", "trust.json"})
        from tracekit.cli import _quote
        self.assertIn(f"\n  verify the bundle again: tracekit verify {_quote(os.path.join(kept, 'run.tkb'))} --trust "
                      f"{_quote(os.path.join(kept, 'trust.json'))}\n", tampered)
        # the kept store is no dev signer's: `tracekit view --dev` does not show it, so the command that does is printed
        self.assertIn(f"\n  see the run: tracekit view --data-dir {_quote(os.path.join(kept, 'data'))}\n", tampered)

    def test_e22_reads_the_kept_dir_from_its_line_alone(self):
        """Since the demo prints how to verify and view the kept files after "kept DIR" (#600), E22 read those lines as
        part of the dir, and the nightly run failed."""
        e22 = import_e22()
        with tempfile.TemporaryDirectory() as d:
            corpus = e22.Corpus(d)
            corpus.demo()
            self.assertEqual([(c["name"], os.path.isfile(c["bundle"])) for c in corpus.cases],
                             [("demo run", True), ("demo tampered", True)])


class E22Import(unittest.TestCase):
    def test_importing_e22_leaves_sys_path_alone(self):
        """Importing the E22 script put examples/v2 at the front of sys.path, so ``find_spec("crewai")`` found the
        example folder and the Examples tests ran without their dependencies (#721)."""
        before = list(sys.path)
        import_e22()
        self.assertEqual(sys.path, before)
        spec = importlib.util.find_spec("crewai")
        self.assertFalse(spec is not None and spec.origin is None
                         and any(os.path.join("examples", "v2") in p for p in spec.submodule_search_locations),
                         "find_spec('crewai') points into examples/v2")


if __name__ == "__main__":
    unittest.main()
