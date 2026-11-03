"""Shared test builders: events, in-process signers, a dev signer daemon, bundle rewriting and ledger reading.

Import with `from factories import ...` (tests/ is on sys.path under pytest; see conftest.py).
"""
import hashlib
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
import zlib
from concurrent.futures import ProcessPoolExecutor
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# time limits in tests are for an untraced run; a coverage run traces every line, about 3x slower
SLOWER = 3 if "coverage" in sys.modules else 1
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


def unverified_bundles(test):
    """@pytest.mark.unverified_bundles for files the TypeScript suite runs without pytest: the test exports v2 bundles
    the verifier rejects on purpose, so conftest's every-export-verifies check skips it."""
    test.unverified_bundles = True
    return test


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


def damage_crc(src, dst):
    """Copy a bundle with the CRC-32 of its first runs/ entry changed in both its headers: the layout holds, the entry's
    bytes no longer match it (a damaged copy)."""
    with open(src, "rb") as f:
        data = bytearray(f.read())
    with zipfile.ZipFile(src) as z:
        entry = next(i for i in z.infolist() if i.filename.startswith("runs/"))
    directory = int.from_bytes(data[data.rindex(b"PK\x05\x06") + 16:][:4], "little")   # the end record's offset field
    central = data.index(entry.filename.encode(), directory) - 46   # its name follows its 46-byte central header
    for at in (entry.header_offset + 14, central + 16):
        data[at] ^= 1
    with open(dst, "wb") as f:
        f.write(data)


def overinflate(src, dst):
    """Copy a bundle with its first runs/ entry's deflate stream holding bytes past the entry's stated size, which, with
    its CRC-32, stays that of the run's records: the layout holds, the stream inflates to more than the entry says."""
    with zipfile.ZipFile(src) as z:
        entries = [(n, z.read(n)) for n in z.namelist()]
    name = next(n for n, _ in entries if n.startswith("runs/"))
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in entries:
            z.writestr(n, b + b"x" * 1000 if n == name else b)
    with zipfile.ZipFile(dst) as z:
        entry = z.getinfo(name)
    with open(dst, "rb") as f:
        data = bytearray(f.read())
    central = data.index(name.encode(), int.from_bytes(data[-6:-2], "little")) - 46
    real = dict(entries)[name]
    for at in (entry.header_offset + 14, central + 16):   # CRC-32, then the uncompressed size 8 bytes on
        data[at:at + 4], data[at + 8:at + 12] = zlib.crc32(real).to_bytes(4, "little"), len(real).to_bytes(4, "little")
    with open(dst, "wb") as f:
        f.write(data)


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


def persisted_queue(signer):
    """The witness queue as the signer's store holds it, read under the lock its publisher writes it with: Windows
    can't open the file while it's being replaced."""
    with signer._queue_lock:
        return signer.log.storage.witness_queue()


def process_pool():
    """Worker processes, one per CPU this process may use (at most 61: Windows takes no more), spawned: a test process
    has threads, which a fork would copy mid-lock."""
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1
    return ProcessPoolExecutor(min(cpus, 61), mp_context=multiprocessing.get_context("spawn"))


def wait_for(cond, timeout=10, interval=0.05):
    """Poll cond() until it returns something truthy or the deadline passes; return its last value."""
    deadline = time.monotonic() + timeout
    while True:
        v = cond()
        if v or time.monotonic() >= deadline:
            return v
        time.sleep(interval)


class VersionCheckCases:
    """The version check a hand-wired integration shares with the others (tracekit.integrations.version_check): a
    framework outside the versions Tracekit is tested with warns once when the integration is built, one inside the
    range does not. A test class sets `module` (under tracekit.integrations), `inside` and `message`."""

    def warnings_for(self, version):
        import importlib
        import warnings
        from tracekit.integrations import version_check
        integration = importlib.import_module("tracekit.integrations." + self.module)
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value=version), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            integration.Tracekit(mock.Mock())
        return [str(x.message) for x in w if "is wired but untested" in str(x.message)]

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        msgs = self.warnings_for("0.0.1")
        self.assertEqual(1, len(msgs))
        self.assertIn(self.message, msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        self.assertEqual([], self.warnings_for(self.inside))
