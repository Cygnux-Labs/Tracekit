"""Clean-machine quickstart (README, docs/quickstart-v2.md): build the wheel, then with only a fresh venv (a temp HOME
and runtime dir, nothing of this checkout on the path) take the three steps a user takes: `pip install` the wheel
(no extras), run an agent that has `import tracekit; tracekit.instrument()` (tests/quickstart_agents.py, one per
framework whose package installs here), `tracekit last`. Then Claude Code's v2 hook. Each run must verify, and the three
steps must fit in STEPS_BUDGET_S. Builds and installs from the package index, so it runs only with TRACEKIT_QUICKSTART=1
(`make quickstart`)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import pytest

from quickstart_agents import AGENTS, REFUSED

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUDGET_S = 300
STEPS_BUDGET_S = 120   # install, run the agent, `tracekit last`: the framework itself is the agent the user has
HELD = {"command": 'echo "unterminated'}   # the signer can't parse it, so it asks (TK-SHELL-PARSE)


def sh(*argv, env, code=0, **kw):
    p = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=BUDGET_S, **kw)
    assert code is None or p.returncode == code, f"{argv} exited {p.returncode}\n{p.stdout}\n{p.stderr}"
    return p


@pytest.mark.quickstart
@unittest.skipUnless(os.environ.get("TRACEKIT_QUICKSTART") == "1", "builds and installs a wheel: TRACEKIT_QUICKSTART=1")
class Quickstart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.start = time.monotonic()
        cls.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
        cls.addClassCleanup(shutil.rmtree, cls.dir, True)
        venv = os.path.join(cls.dir, "venv")
        bin_dir = os.path.join(venv, "Scripts" if os.name == "nt" else "bin")
        cls.py, cls.tracekit = os.path.join(bin_dir, "python"), os.path.join(bin_dir, "tracekit")
        home = os.path.join(cls.dir, "home")
        cls.env = {k: v for k, v in os.environ.items()
                   if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG") or k.startswith("PIP_")
                   or k.upper().endswith("_PROXY")}
        cls.env.update(PATH=bin_dir + os.pathsep + os.environ.get("PATH", ""), HOME=home, USERPROFILE=home,
                       LOCALAPPDATA=os.path.join(home, "local"), XDG_DATA_HOME=os.path.join(home, "data"),
                       TRACEKIT_RUNTIME_DIR=os.path.join(cls.dir, "run"), TRACEKIT_DEV_IDLE="120")
        dist = os.path.join(cls.dir, "dist")
        sh(sys.executable, "-m", "pip", "wheel", "-q", "--no-deps", "-w", dist, ROOT, env=dict(os.environ))
        sh(sys.executable, "-m", "venv", venv, env=cls.env)
        [wheel] = os.listdir(dist)
        t = time.monotonic()
        sh(cls.py, "-m", "pip", "install", "-q", os.path.join(dist, wheel), env=cls.env, cwd=cls.dir)   # step 1
        cls.install_s = time.monotonic() - t
        cls.addClassCleanup(sh, cls.tracekit, "down", env=cls.env, cwd=cls.dir)

    def sh(self, *argv, code=0):
        return sh(*argv, env=self.env, cwd=self.dir, code=code)

    def approve_when_asked(self, aid):
        self.assertIn("approved: ", self.sh(self.tracekit, "approvals", "approve", aid).stdout)

    def last(self):
        """Step 3; its time."""
        t = time.monotonic()
        out = self.sh(self.tracekit, "last").stdout
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev", out)
        self.assertIn("next: tracekit view --dev", out)
        return time.monotonic() - t

    def test_three_steps(self):
        for name, (reqs, script) in AGENTS.items():
            with self.subTest(name):
                if self.sh(self.py, "-m", "pip", "install", "-q", *reqs, code=None).returncode:
                    self.skipTest(f"{' '.join(reqs)} does not install here")
                path = os.path.join(self.dir, f"{name}.py")
                with open(path, "w") as f:
                    f.write(script)
                t = time.monotonic()
                out = json.loads(self.sh(self.py, path).stdout.splitlines()[-1])   # step 2
                run_s = time.monotonic() - t
                self.assertTrue(out[0].startswith("ran "), out)
                if name != "openai":
                    self.assertIn(REFUSED, out[1])
                took = self.install_s + run_s + self.last()
                print(f"\nquickstart ({name}): install {self.install_s:.1f} s + agent {run_s:.1f} s + tracekit last = "
                      f"{took:.1f} s", file=sys.stderr)
                self.assertLessEqual(took, STEPS_BUDGET_S)
        self.assertLessEqual(time.monotonic() - self.start, BUDGET_S * len(AGENTS))

    def hook(self, event, tid=None, wait=True, **fields):
        p = {"hook_event_name": event, "session_id": "quickstart", **({"tool_use_id": tid} if tid else {}), **fields}
        proc = subprocess.Popen([self.py, "-I", "-m", "tracekit.integrations.claude_code"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.dir, env=self.env)
        self.addCleanup(proc.kill)
        proc.stdin.write(json.dumps(p))
        proc.stdin.close()
        return proc.wait(120) if wait else proc

    def test_claude_code_hook(self):
        self.assertEqual(self.hook("SessionStart"), 0)
        ls = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        self.assertEqual(self.hook("PreToolUse", "c1", **ls), 0)
        self.assertEqual(self.hook("PostToolUse", "c1", tool_response={"stdout": "agent.py"}, **ls), 0)
        blocked = self.hook("PreToolUse", "c2", wait=False, tool_name="Bash", tool_input={"command": "pkill tracekitd"})
        self.assertEqual(blocked.wait(120), 2)
        self.assertIn("TK-D007", blocked.stderr.read())
        held = self.hook("PreToolUse", "c3", wait=False, tool_name="Bash", tool_input=HELD)
        deadline, pending = time.monotonic() + 60, []
        while not pending and time.monotonic() < deadline:
            pending = [line.split() for line in self.sh(self.tracekit, "approvals", "list").stdout.splitlines()
                       if " requested " in line]
            time.sleep(0.2)
        self.assertTrue(pending, "the hook asked for no approval")
        self.approve_when_asked(pending[0][0])
        self.assertEqual(held.wait(120), 0, held.stderr.read())
        self.assertEqual(self.hook("PostToolUse", "c3", tool_name="Bash", tool_input=HELD, tool_response={}), 0)
        self.assertEqual(self.hook("SessionEnd", reason="exit"), 0)
        self.last()


if __name__ == "__main__":
    unittest.main()
