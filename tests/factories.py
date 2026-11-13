"""Shared test builders: events, in-process signers, a dev signer daemon, bundle rewriting and ledger reading.

Import with `from factories import ...` (tests/ is on sys.path under pytest; see conftest.py).
"""
import contextlib
import datetime
import hashlib
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid
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
from tracekit.storage import file as storage_file  # noqa: E402


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


def v2rec(seq, typ, data, run="r1", **top):
    """A v2 signed record as the viewer reads it from a store (its signature left out), `seq` its run_seq and second."""
    return {"event": {"seq": seq, "run_seq": seq, "run_id": run, "agent_id": "main", "type": typ, "data": data,
                      "ts": f"2026-10-10T17:00:{seq:02d}.000000Z", "prev_hash": "sha256:p", **top},
            "hash": f"sha256:{seq}"}


def iso(t):
    """Epoch seconds as a transcript writes its times (UTC, Z)."""
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def cc_assistant(mid, t, read=0, write=0, life="5m", new=0, out=200, tools=(), model="claude-opus-5-5"):
    """A Claude Code transcript's assistant line: message `mid` at `t` (epoch seconds) whose context is `read` tokens
    read from the prompt cache, `write` written to it (lasting `life`: "5m" or "1h") and `new` sent uncached; it calls
    each of `tools`, (tool_use id, tool name, input)."""
    return {"type": "assistant", "timestamp": iso(t), "message": {
        "id": mid, "model": model, "role": "assistant",
        "content": [{"type": "tool_use", "id": i, "name": n, "input": inp} for i, n, inp in tools] or
        [{"type": "text", "text": "done"}],
        "usage": {"input_tokens": new, "output_tokens": out, "cache_read_input_tokens": read,
                  "cache_creation_input_tokens": write,
                  "cache_creation": {"ephemeral_5m_input_tokens": write * (life == "5m"),
                                     "ephemeral_1h_input_tokens": write * (life == "1h")}}}}


def cc_result(tool_use_id, t):
    """A Claude Code transcript's user line that returns tool `tool_use_id`'s result at `t`."""
    return {"type": "user", "timestamp": iso(t), "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": tool_use_id, "content": "ok"}]}}


def write_jsonl(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.writelines(json.dumps(x) + "\n" for x in lines)
    return path


def make_signer(home, **cfg):
    """An in-process Signer over `home`; `cfg` overrides the config.json defaults."""
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.json"), "w") as f:
        json.dump({"checkpoint_every": 50, "witnesses": [f"file:{home}/witness.jsonl"], **cfg}, f)
    return Signer(home, load_config(home))


def ledger_records(home):
    """Every readable record in the signer's ledger, in order."""
    return [r for _, r, _ in read_records(os.path.join(home, "ledger", "ledger.jsonl")) if r]


# a Tracekit Box box, as its daemon describes it (register_run `box`)
BOX = {"id": "b-1", "image_digest": "sha256:" + "a" * 64, "allow": ["claude-code", "anthropic"], "channel": "agent"}


def box_runset_bundle(d):
    """(a run-set bundle of a plain run whose registry range also points to an open box run's run.registered, the
    plain run's bundle alone, their trust file): the box's label is on a record of a run the bundle doesn't hold (#603's
    review)."""
    from tracekit.bundle_v2 import export
    from tracekit.identity.base import CallerIdentity
    from tracekit.signer import service as svc
    from tracekit.storage.base import registry_tree
    me = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
    os.makedirs(d, exist_ok=True)
    s = svc.SignerService(os.path.join(d, "data"), grace_s=0, fsck_every_s=0,
                          box_daemons={f"uid:{me.subject}": "firecracker"})
    try:
        n = iter(range(10))
        call = lambda m, req: s.call(me, m, {"request_id": f"r{next(n)}", **req})   # noqa: E731
        call("register_run", {"agent": {"name": "tkbox"}, "box": BOX})   # stays open
        plain = call("register_run", {"agent": {"name": "plain-agent"}})
        call("close_run", {"run_id": plain["run_id"], "run_token": plain["run_token"]})
        s.sweep(time.monotonic() + 1)
        s.checkpoint()
        st, out, trust = s.log.storage, os.path.join(d, "plain-runset.tkb"), os.path.join(d, "plain-runset-trust.json")
        export(st, "default", plain["run_id"], st.checkpoint_latest()[1], out,
               run_set=(0, st.checkpoint_latest(registry_tree("default"))[0]), tenant_salt=s.log.tenant_salt("default"))
        alone = os.path.join(d, "plain.tkb")
        export(st, "default", plain["run_id"], st.checkpoint_latest()[1], alone)
        with open(trust, "w") as f:
            json.dump({"logs": [s.vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}, f)
    finally:
        s.close()
    with zipfile.ZipFile(out) as z:
        assert b'"box":{"id":"b-1"' in z.read("registry/records.jsonl"), "the range holds no box label"
    return out, alone, trust


class BoxScene:
    """A Tracekit Box box run and its agent channel's runs in an in-process signer that keeps content, on a synthetic
    signer clock (seconds from the box's start), with the records Box's daemon writes (internal/daemon): a WebFetch
    decision per connection out of the box, {url: <scheme>://<host>:<port>}, completed ok when it went through; a Write
    decision per file written back at apply; a Bash decision per command Box started; tkbox.* observes. The steps run
    in time order at bundle(), which exports the run-set (the box run and its agent runs) and its trust file."""

    DAEMON = "1001"

    def __init__(self, d, workspace="/home/dev/proj"):
        from tracekit.identity.base import CallerIdentity
        from tracekit.signer import service as svc
        self.d, self.steps, self.agents = d, [], []
        self.me = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
        self.daemon = CallerIdentity("uid", self.DAEMON, True)
        self.s = svc.SignerService(os.path.join(d, "data"), fsck_every_s=0, grace_s=0,
                                   box_daemons={f"uid:{self.DAEMON}": "firecracker"}, content={"retain": True},
                                   analyzers=[f"uid:{self.me.subject}"], authorize={
                                       f"uid:{self.me.subject}": sorted(svc.DEFAULT_GRANTS | {svc.CONTENT_READ})})
        self.box = self._register(self.daemon, box=BOX)
        self.observe(0, "tkbox.box", {"event": "created", "box_id": BOX["id"], "workspace": workspace}, "trusted")
        self.channel = self.s.call(self.daemon, "channel_open", dict(self.box["handle"])).identity

    def _register(self, who, **kw):
        out = self.s.call(who, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "claude-code"}, **kw})
        return {"handle": {"run_id": out["run_id"], "run_token": out["run_token"]}, "who": who, "seq": 0}

    def _send(self, run, method, **fields):
        req = {**run["handle"], "request_id": uuid.uuid4().hex, "stream": "s", "client_seq": run["seq"], **fields}
        run["seq"] += 1
        return self.s.call(run["who"], method, req)

    def agent(self, t):
        """A run the box's agent registers over the channel at `t`: its index, for call(run=)."""
        self.agents.append(None)
        self.steps.append((t, len(self.steps), "register", len(self.agents) - 1))
        return len(self.agents) - 1

    def stop(self, t, run=0):
        """The agent closes run `run` at `t` (the rest close at bundle()'s end)."""
        self.steps.append((t, len(self.steps), "close", run))

    def call(self, t0, t1, tool, args, ok=True, run=0):
        """A call of the agent's run `run`: decided at t0, its result at t1 (None: none). -> its tool call id."""
        tid = f"toolu_{len(self.steps)}"
        self.steps += [(t0, len(self.steps), "decide", (run, tid, tool, args)),
                       *([(t1, len(self.steps) + 1, "complete", (run, tid, tool, args, ok))] if t1 is not None else [])]
        return tid

    def door(self, t, url, allowed=True):
        """A connection out of the box at `t`: let through, or refused after the signer allowed it (an approval no one
        gave); allowed None: no outcome recorded."""
        tid = f"egress-{len(self.steps)}"
        self.steps.append((t, len(self.steps), "decide", ("box", tid, "WebFetch", {"url": url})))
        if allowed is not None:
            self.steps.append((t + 0.01, len(self.steps), "complete", ("box", tid, "WebFetch", {"url": url}, allowed)))

    def write(self, t, path, deleted=False):
        """A file of the box's patch written back at apply, at `t`."""
        args = {"file_path": path, "sha256": "0" * 64, "mode": 420, "symlink": False, "deleted": deleted,
                "patch_sha256": "1" * 64}
        self.steps += [(t, len(self.steps), "decide", ("box", f"write-{len(self.steps)}", "Write", args)),
                       (t + 0.01, len(self.steps) + 1, "complete", ("box", f"write-{len(self.steps)}", "Write", args,
                                                                    True))]

    def command(self, t0, t1, cmd):
        """A command Box started from the host, running from t0 to t1."""
        args = {"command": cmd}
        self.steps += [(t0, len(self.steps), "decide", ("box", f"exec-{len(self.steps)}", "Bash", args)),
                       (t1, len(self.steps) + 1, "complete", ("box", f"exec-{len(self.steps)}", "Bash", args, True))]

    def observe(self, t, source, value, trust="untrusted"):
        self.steps.append((t, len(self.steps), "observe", (source, trust, value)))

    def bundle(self, end):
        """Run the steps, close the runs still open at `end` (the agent's, then the box run), and export the run-set.
        -> (bundle path, trust path, box run id, [agent run ids])."""
        from tracekit.bundle_v2 import export
        from tracekit.format.canon import event_hash
        from tracekit.signer import pipeline
        from tracekit.storage.base import registry_tree
        base = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        clock, decided = [0.0], {}

        def run_of(who):
            return self.box if who == "box" else self.agents[who]
        with mock.patch.object(pipeline, "now_ts", lambda: (base + datetime.timedelta(seconds=clock[0])).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ")):
            for t, _, kind, x in sorted(self.steps, key=lambda s: s[:2]):
                clock[0] = t
                if kind == "register":
                    self.agents[x] = self._register(self.channel)
                elif kind == "close":
                    self.s.call(self.channel, "close_run", {**self.agents[x]["handle"], "request_id": uuid.uuid4().hex})
                    self.agents[x]["closed"] = True
                elif kind == "observe":
                    self._send(self.box, "observe", source=x[0], trust=x[1], value=x[2])
                elif kind == "decide":
                    decided[x[1]] = self._send(run_of(x[0]), "decide", tool_call_id=x[1], tool=x[2],
                                               args_source="parsed", args=x[3])
                else:
                    self._send(run_of(x[0]), "complete", tool_call_id=x[1], decision_id=decided[x[1]]["decision_id"],
                               status="ok" if x[4] else "error", result={"allowed": x[4]} if x[0] == "box" else "done",
                               args_digest=event_hash({"tool": x[2], "args": x[3]}))
            clock[0] = end
            for run in [*(a for a in self.agents if not a.get("closed")), self.box]:
                self.s.call(run["who"], "close_run", {**run["handle"], "request_id": uuid.uuid4().hex})
            self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()
        st = self.s.log.storage
        out, trust = os.path.join(self.d, "box-runset.tkb"), os.path.join(self.d, "box-runset-trust.json")
        export(st, "default", None, st.checkpoint_latest()[1], out,
               run_set=(0, st.checkpoint_latest(registry_tree("default"))[0]), tenant_salt=self.s.log.tenant_salt(
                   "default"))
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}, f)
        return out, trust, self.box["handle"]["run_id"], [a["handle"]["run_id"] for a in self.agents]

    def call_as_me(self, method, req):
        """A call as the analysing user (an analyzer with content_read, as the dev signer's user is)."""
        return self.s.call(self.me, method, req)

    def content_get(self, req):   # what tracekit.why.signed.vault_content reads through
        return self.call_as_me("content_get", req)

    def close(self):
        self.s.close()


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


# the modules whose syncs a signer on the file store makes: its logs, its new files, and its state and key files
SIGNER_SYNCS = {"tracekit.storage.file", "tracekit.signer.service", "tracekit.deploy.files"}


@contextlib.contextmanager
def signer_without_fsync():
    """The signer's syncs (SIGNER_SYNCS) skipped in this process while it's open, for a test of what a signer decides
    and records, not of its durability, which has tests of its own (test_storage_file's test_durability_modes and
    test_a_failed_background_sync_names_the_records_not_known_durable, storage_contract's
    test_torn_tail_is_set_aside_and_reported): fsync is most of such a test's time on windows-latest (#722). Yields the
    modules of the syncs made anywhere else, which still run: a sync the signer moves to another module fails the test
    instead of silently making it slow again."""
    elsewhere, real = [], {name: getattr(os, name) for name in ("fsync", "fdatasync") if hasattr(os, name)}

    def stub(name):
        def sync(fd):
            caller = sys._getframe(1).f_globals.get("__name__")
            if caller not in SIGNER_SYNCS:
                elsewhere.append(caller)
                real[name](fd)
        return sync
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(storage_file, "_sync", lambda fd, full: None))   # macOS's is an fcntl
        for name in real:
            stack.enter_context(mock.patch.object(os, name, stub(name)))
        yield elsewhere


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
