"""Clean-machine quickstart (docs/quickstart-v2.md; the M1a exit gate): build the wheel, install it into a fresh venv,
then with only that venv (a temp HOME and runtime dir, nothing of this checkout on the path) drive the dev signer the
way a user does: a scripted agent through tracekit.sdk.client, then Claude Code's v2 hook. Each run must export and
verify. Builds and installs from the package index, so it runs only with TRACEKIT_QUICKSTART=1 (`make quickstart`)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUDGET_S = 300
HELD = {"command": 'echo "unterminated'}   # the signer can't parse it, so it asks (TK-SHELL-PARSE)

AGENT = r"""
import json, sys
import tracekit
from tracekit.sdk.client import Client

held = json.loads(sys.argv[1])
with Client().run(agent="quickstart") as run:
    out = {"run_id": run.run_id, "imported": tracekit.__file__}
    out["allowed"] = run.decide("c1", "Bash", {"command": "ls"})["decision"]
    run.complete("c1")
    blocked = run.decide("c2", "Bash", {"command": "pkill tracekitd"})
    out["blocked"] = [blocked["decision"], blocked["rule_ids"]]
    out["held"] = run.decide("c3", "Bash", held)["decision"]
    aid = run.call("approval_request", tool_call_id="c3")["approval_id"]
    print(aid, flush=True)
    out["approval"] = run.call("approval_wait", approval_id=aid, timeout_ms=60000)["state"]
    out["consumed"] = run.approval_consume("c3", "Bash", held, approval_id_hint=aid)["ok"]
    run.complete("c3")
print(json.dumps(out))
"""


def sh(*argv, env, code=0, **kw):
    p = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=BUDGET_S, **kw)
    assert p.returncode == code, f"{argv} exited {p.returncode}\n{p.stdout}\n{p.stderr}"
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
        sh(cls.py, "-m", "pip", "install", "-q", os.path.join(dist, wheel) + "[signer]", env=cls.env, cwd=cls.dir)
        cls.addClassCleanup(sh, cls.tracekit, "down", env=cls.env, cwd=cls.dir)

    def sh(self, *argv):
        return sh(*argv, env=self.env, cwd=self.dir)

    def approve_when_asked(self, aid):
        self.assertIn("approved: ", self.sh(self.tracekit, "approvals", "approve", aid).stdout)

    def verified(self, run_id):
        """`tracekit verify` of the run's bundle, once the signer has finalised the run (its grace window)."""
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, f"{run_id}.tkb")
        self.sh(self.tracekit, "signer", "trust", "-o", trust)
        deadline = time.monotonic() + 30
        while True:
            if os.path.exists(out):
                os.remove(out)
            self.sh(self.tracekit, "export", "--v2", "--run", run_id, "-o", out)
            report = self.sh(self.tracekit, "verify", out, "--trust", trust).stdout
            if "Integrity: VERIFIED." in report or time.monotonic() > deadline:
                return report

    def assert_verified(self, run_id):
        report = self.verified(run_id)
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev", report)
        took = time.monotonic() - self.start
        print(f"\nquickstart ({self._testMethodName}): {took:.1f} s since the wheel build started", file=sys.stderr)
        self.assertLessEqual(took, BUDGET_S)

    def test_scripted_agent(self):
        script = os.path.join(self.dir, "agent.py")
        with open(script, "w") as f:
            f.write(AGENT)
        agent = subprocess.Popen([self.py, script, json.dumps(HELD)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, cwd=self.dir, env=self.env)
        self.addCleanup(agent.kill)
        aid = agent.stdout.readline().strip()
        if not aid:
            self.fail(agent.communicate(timeout=120))
        self.approve_when_asked(aid)   # from a second process, as a human would
        out, err = agent.communicate(timeout=120)
        self.assertEqual(agent.returncode, 0, err)
        out = json.loads(out)
        self.assertTrue(os.path.realpath(out.pop("imported")).startswith(os.path.realpath(self.dir)))   # not the checkout
        self.assertEqual({k: out[k] for k in ("allowed", "blocked", "held", "approval", "consumed")},
                         {"allowed": "allow", "blocked": ["deny", ["TK-D007"]], "held": "ask", "approval": "approved",
                          "consumed": True})
        self.assert_verified(out["run_id"])

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
        self.assert_verified(pending[0][2][len("run="):])


if __name__ == "__main__":
    unittest.main()
