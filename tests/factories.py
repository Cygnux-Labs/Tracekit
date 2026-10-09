"""Shared test builders: events, in-process signers, a dev signer daemon, bundle rewriting and ledger reading.

Import with `from factories import ...` (tests/ is on sys.path under pytest; see conftest.py).
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install, policy  # noqa: E402
from tracekit.core import now_ts  # noqa: E402
from tracekit.daemon import Signer, load_config  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402


def ev(typ, data, run="r1", agent="main", source="hook"):
    return {"run_id": run, "agent_id": agent, "parent_id": None if agent == "main" else "main", "source": source,
            "type": typ, "ts": now_ts(), "data": data}


def run_start(run="r1", pol=None, fail_mode="open", isolation="same-user"):
    pol = pol or policy.load()[0]
    return ev("run.start", {"agent": {"name": "test", "version": None}, "host": "h", "os_user": "u", "fail_mode": fail_mode,
                            "policy": {"version": pol["version"], "hash": policy.policy_hash(pol)}, "capture_sources": ["hook"],
                            "sandbox": "unknown", "content_capture": "hashed", "signer_isolation": isolation}, run)


def tool_call(tid, cmd="ls", run="r1"):
    return ev("tool.call", {"tool_use_id": tid, "name": "Bash", "input": {"command": {"value": cmd, "redacted": False}}}, run)


def make_signer(home, **cfg):
    """An in-process Signer over `home`; `cfg` overrides the config.json defaults."""
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.json"), "w") as f:
        json.dump({"checkpoint_every": 50, "witnesses": [f"file:{home}/witness.jsonl"], **cfg}, f)
    return Signer(home, load_config(home))


def ledger_records(home):
    """Every readable record in the signer's ledger, in order."""
    return [r for _, r, _ in read_records(os.path.join(home, "ledger", "ledger.jsonl")) if r]


def rewrite_bundle(src, dst, edit):
    """Copy a bundle, letting `edit(files: dict, manifest: dict)` change it; manifest hashes are refreshed."""
    with zipfile.ZipFile(src) as z:
        files = {n: z.read(n) for n in z.namelist() if n != "manifest.json"}
        manifest = json.loads(z.read("manifest.json"))
    edit(files, manifest)
    manifest["files"] = {k: hashlib.sha256(v).hexdigest() for k, v in files.items() if k in manifest["files"]}
    with zipfile.ZipFile(dst, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for k, v in files.items():
            z.writestr(k, v)


def patch_env(case, **env):
    """Set env vars for one test (or, given the class, for the whole TestCase class); the whole environment is restored
    on cleanup. A None value unsets the var."""
    p = mock.patch.dict(os.environ)
    p.start()
    (case.addClassCleanup if isinstance(case, type) else case.addCleanup)(p.stop)
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class DaemonCase(unittest.TestCase):
    """A real dev-mode signer daemon per test, with its own client home. Set `policy_yaml` to run under a custom policy."""

    policy_yaml = None

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.home = os.path.join(self.d, "signer")
        env = {"TRACEKIT_CLIENT_HOME": os.path.join(self.d, "client")}
        if self.policy_yaml is not None:
            env["TRACEKIT_POLICY"] = os.path.join(self.d, "p.yaml")
            with open(env["TRACEKIT_POLICY"], "w") as f:
                f.write(self.policy_yaml)
        patch_env(self, **env)
        install.init_dev(self.home, [], start=True)
        self.addCleanup(install.stop_dev_daemon, self.home)

    def records(self):
        return ledger_records(self.home)


def wait_for(cond, timeout=10, interval=0.05):
    """Poll cond() until it returns something truthy or the deadline passes; return its last value."""
    deadline = time.monotonic() + timeout
    while True:
        v = cond()
        if v or time.monotonic() >= deadline:
            return v
        time.sleep(interval)
