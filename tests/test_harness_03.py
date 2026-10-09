"""0.3 harness binding tests: the signer attributes each hook run to the registered harness process it came from,
using the kernel's process tree, and refuses runs and events that did not come from that harness instance.

Real processes are used throughout: a copy of /bin/sh plays the harness, and `sleep` children play its hooks.

    python3 -m unittest tests.test_harness_03 -v
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import daemon, policy  # noqa: E402
from tracekit.daemon import Signer, find_harness, load_config, trusted_file  # noqa: E402
from factories import ledger_records, make_signer, run_start, tool_call  # noqa: E402

LINUX_PROC = sys.platform.startswith("linux") and os.path.isdir("/proc/self")
# must differ from the uid running the tests (1001 on GitHub runners), or the signer treats the agent as itself
AGENT_UID = 1001 if not hasattr(os, "getuid") or os.getuid() != 1001 else 1002
SH = shutil.which("dash") or shutil.which("sh")


def _spawn(argv, cwd=None):
    """Start argv in its own process group; it prints the pid of a `sleep` child it keeps running.
    Returns (process, child pid)."""
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, cwd=cwd, start_new_session=True)
    line = p.stdout.readline().strip()
    return p, int(line)


@unittest.skipUnless(LINUX_PROC and SH, "harness binding reads the Linux /proc process tree")
class _Harness(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.harness = os.path.join(self.d, "fakeharness")
        shutil.copy(os.path.realpath(SH), self.harness)
        os.chmod(self.harness, 0o755)
        self.procs = []
        # a temp dir is world-writable, so the trust check on the harness binary is tested on its own below
        self._trusted = daemon.trusted_file
        daemon.trusted_file = lambda p: None

    def tearDown(self):
        daemon.trusted_file = self._trusted
        for p in self.procs:  # the whole group, so no `sleep` child outlives the test
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
            p.stdout.close()
        shutil.rmtree(self.d, ignore_errors=True)

    def hook_under_harness(self, exe=None):
        """A process tree like a real hook: harness -> sh -> hook (sleep). Returns the hook's pid."""
        p, pid = _spawn([exe or self.harness, "-c", "sh -c 'sleep 60' & echo $!; wait"])
        self.procs.append(p)
        return pid

    def hook_outside_harness(self):
        p, pid = _spawn([SH, "-c", "sleep 60 & echo $!; wait"])
        self.procs.append(p)
        return pid

    def harnesses(self):
        return [{"name": "fake", "exe": os.path.realpath(self.harness), "script": None}]


class FindHarness(_Harness):
    def test_hook_spawned_by_the_harness_is_attributed(self):
        pid = self.hook_under_harness()
        inst, why = find_harness(pid, self.harnesses())
        self.assertIsNotNone(inst, why)
        self.assertEqual(inst["exe"], os.path.realpath(self.harness))
        self.assertEqual(inst["name"], "fake")
        self.assertIsInstance(inst["start_time"], int)

    def test_process_outside_the_harness_is_not(self):
        inst, why = find_harness(self.hook_outside_harness(), self.harnesses())
        self.assertIsNone(inst)
        self.assertIn("no registered harness", why)

    def test_a_process_named_like_the_harness_is_not(self):
        # same name, different binary: a process can choose its name but not its executable
        other = os.path.join(self.d, "elsewhere")
        os.makedirs(other)
        impostor = os.path.join(other, "fakeharness")
        shutil.copy(os.path.realpath(SH), impostor)
        inst, _ = find_harness(self.hook_under_harness(impostor), self.harnesses())
        self.assertIsNone(inst)

    def test_detached_process_is_not(self):
        # a double fork reparents the process to init, out from under the harness
        p, pid = _spawn([self.harness, "-c", "(setsid sleep 60 >/dev/null 2>&1 & echo $!)"])
        self.procs.append(p)
        p.wait()  # the harness and the subshell are gone: the kernel reparented the sleep when they exited
        try:
            inst, _ = find_harness(pid, self.harnesses())
            self.assertIsNone(inst)
        finally:
            try:
                os.kill(pid, 9)
            except OSError:
                pass

    def test_script_harness_matches_its_script_only(self):
        py = os.path.realpath(sys.executable)
        agent = os.path.join(self.d, "agent.py")
        other = os.path.join(self.d, "other.py")
        body = "import subprocess,sys\np=subprocess.Popen(['sleep','60'])\nprint(p.pid,flush=True)\np.wait()\n"
        for f in (agent, other):
            with open(f, "w") as fh:
                fh.write(body)
        reg = [{"name": "agent", "exe": py, "script": os.path.realpath(agent)}]
        p, pid = _spawn([py, "-I", agent])
        self.procs.append(p)
        inst, why = find_harness(pid, reg)
        self.assertIsNotNone(inst, why)
        p, pid = _spawn([py, "-I", "other.py"], cwd=self.d)  # same interpreter, different script
        self.procs.append(p)
        self.assertIsNone(find_harness(pid, reg)[0])
        p, pid = _spawn([py, "-I", "agent.py"], cwd=self.d)  # relative path, resolved against the process's cwd
        self.procs.append(p)
        self.assertIsNotNone(find_harness(pid, reg)[0])


class TrustedFile(unittest.TestCase):
    def test_world_writable_dir_is_not_trusted(self):
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, "x")
            open(f, "w").close()
            os.chmod(d, 0o777)
            self.assertIsNotNone(trusted_file(f))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @pytest.mark.root
    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and os.path.exists("/bin/sh"), "needs root-owned /bin/sh")
    def test_root_owned_system_binary_is_trusted(self):
        self.assertIsNone(trusted_file("/bin/sh"))

    def test_relative_path_is_not_trusted(self):
        self.assertIsNotNone(trusted_file("bin/sh"))


class SignerBinding(_Harness):
    def setUp(self):
        super().setUp()
        self.pol, self.pol_raw = policy.load()
        self.home = os.path.join(self.d, "home")
        self.s = self.signer("enforce")
        self.cseq = {}

    def tearDown(self):
        self.s.ledger.close()
        super().tearDown()

    def signer(self, binding):
        return make_signer(self.home, harnesses=self.harnesses(), harness_binding=binding, mode="system")

    def append(self, e, pid, uid=AGENT_UID):
        n = self.cseq[e["run_id"]] = self.cseq.get(e["run_id"], -1) + 1
        req = {"op": "append", "cseq": n, "event": e}
        if e["type"] == "run.start":
            req["attach"] = {"policy": self.pol_raw}
        return self.s.handle(req, peer_uid=uid, peer_pid=pid)

    def events(self):
        return [r["event"] for r in ledger_records(self.s.home)]

    def gaps(self, kind):
        return [e for e in self.events() if e["type"] == "capture.gap" and e["data"].get("kind") == kind]

    def test_run_from_the_harness_is_bound_and_attested(self):
        hook = self.hook_under_harness()
        self.assertTrue(self.append(run_start(), hook)["ok"])
        self.assertTrue(self.append(tool_call("t1"), hook)["ok"])
        start = [e for e in self.events() if e["type"] == "run.start"][0]
        self.assertEqual(start["data"]["harness"]["name"], "fake")
        self.assertTrue(start["data"]["harness"]["attested"])

    def test_fabricated_run_outside_the_harness_is_refused(self):
        r = self.append(run_start("fake"), self.hook_outside_harness())
        self.assertFalse(r["ok"])
        self.assertIn("registered harness", r["error"])
        self.assertFalse(any(e["type"] == "run.start" for e in self.events()))
        errs = [e for e in self.events() if e["type"] == "error"]
        self.assertEqual(errs[-1]["data"]["client_run_id"], "fake")

    def test_events_from_outside_the_harness_are_refused(self):
        hook = self.hook_under_harness()
        self.append(run_start(), hook)
        r = self.append(tool_call("injected", "rm -rf important/"), self.hook_outside_harness())
        self.assertFalse(r["ok"])
        self.assertFalse(any(e["type"] == "tool.call" and e["data"]["tool_use_id"] == "injected" for e in self.events()))

    def test_events_from_another_harness_instance_are_refused(self):
        self.append(run_start(), self.hook_under_harness())
        r = self.append(tool_call("t2"), self.hook_under_harness())  # same binary, different process
        self.assertFalse(r["ok"])
        self.assertIn("bound to harness pid", r["error"])

    def test_second_run_inside_the_same_harness_is_a_gap(self):
        hook = self.hook_under_harness()
        self.append(run_start("real"), hook)
        self.assertTrue(self.append(run_start("inside"), hook)["ok"])
        g = self.gaps("concurrent_run")
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]["run_id"], "inside")

    def test_sequential_runs_in_one_harness_are_not_a_gap(self):
        hook = self.hook_under_harness()
        self.append(run_start("one"), hook)
        self.append({**tool_call("x", run="one"), "type": "run.end", "data": {"reason": "done"}}, hook)
        self.append(run_start("two"), hook)
        self.assertEqual(self.gaps("concurrent_run"), [])

    def test_client_cannot_claim_a_harness(self):
        e = run_start("claims")
        e["data"]["harness"] = {"name": "fake", "exe": "/x", "pid": 1, "start_time": 1, "attested": True}
        self.assertFalse(self.append(e, self.hook_outside_harness())["ok"])

    def test_binding_survives_restart(self):
        hook = self.hook_under_harness()
        self.append(run_start(), hook)
        self.s.ledger.close()
        self.s = Signer(self.home, load_config(self.home))
        self.assertTrue(self.append(tool_call("t3"), hook)["ok"])
        self.assertFalse(self.append(tool_call("t4"), self.hook_under_harness())["ok"])

    def test_verifier_reports_the_attested_harness(self):
        from tracekit import bundle
        hook = self.hook_under_harness()
        s = run_start("v")
        s["data"]["os_user_attested"] = True
        self.append(s, hook)
        self.append({**tool_call("x", run="v"), "type": "run.end", "data": {"reason": "done"}}, hook)
        self.s.ledger.close()
        out = os.path.join(self.d, "v.tkb")
        bundle.export(self.home, out, run="v")
        rep, code = bundle.verify(out)
        chk = [c for c in rep.checks if c["check"] == "harness attribution"]
        self.assertEqual(chk[0]["status"], "pass", chk)
        self.assertIn("fake", chk[0]["detail"])
        self.s = Signer(self.home, load_config(self.home))

    def test_verifier_warns_on_an_unbound_system_run(self):
        from tracekit import bundle
        self.s.ledger.close()
        self.s = self.signer("off")
        hook = self.hook_outside_harness()
        self.append(run_start("u"), hook)
        self.append({**tool_call("x", run="u"), "type": "run.end", "data": {"reason": "done"}}, hook)
        self.s.ledger.close()
        out = os.path.join(self.d, "u.tkb")
        bundle.export(self.home, out, run="u")
        rep, code = bundle.verify(out)
        chk = [c for c in rep.checks if c["check"] == "harness attribution"]
        self.assertEqual(chk[0]["status"], "warn", chk)
        self.s = Signer(self.home, load_config(self.home))

    def test_record_mode_writes_gaps_instead_of_refusing(self):
        self.s.ledger.close()
        self.s = self.signer("record")
        self.assertTrue(self.append(run_start("rec"), self.hook_outside_harness())["ok"])
        self.assertEqual(len(self.gaps("unattributed_run")), 1)

    def test_off_mode_checks_nothing(self):
        self.s.ledger.close()
        self.s = self.signer("off")
        self.assertTrue(self.append(run_start("off"), self.hook_outside_harness())["ok"])
        self.assertNotIn("harness", [e for e in self.events() if e["type"] == "run.start"][0]["data"])

    def test_proxy_and_sdk_sources_are_not_bound(self):
        hook = self.hook_under_harness()
        self.append(run_start(), hook)
        sdk = {**tool_call("s1"), "source": "sdk"}
        self.assertTrue(self.append(sdk, self.hook_outside_harness())["ok"])


@unittest.skipUnless(LINUX_PROC, "Linux only")
class DefaultsAndConfig(unittest.TestCase):
    def test_no_harnesses_means_off(self):
        d = tempfile.mkdtemp()
        try:
            s = make_signer(d)
            self.assertEqual(s.binding, "off")
            s.ledger.close()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_registered_harness_defaults_to_enforce_in_system_mode(self):
        d = tempfile.mkdtemp()
        try:
            s = make_signer(d, harnesses=[{"exe": "/bin/sh"}])
            self.assertEqual(s.binding, "enforce")
            s.ledger.close()
            s = make_signer(os.path.join(d, "dev"), harnesses=[{"exe": "/bin/sh"}], mode="dev")
            self.assertEqual(s.binding, "off")
            s.ledger.close()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unknown_binding_mode_fails_closed(self):
        d = tempfile.mkdtemp()
        try:
            s = make_signer(d, harnesses=[{"exe": "/bin/sh"}], harness_binding="maybe")
            self.assertEqual(s.binding, "enforce")
            s.ledger.close()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_resolve_harness_for_a_script(self):
        from tracekit import install
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, "cli.js")
            with open(f, "w") as fh:
                fh.write(f"#!/usr/bin/env {os.path.basename(sys.executable)}\nprint(1)\n")
            saved = daemon.trusted_file
            daemon.trusted_file = lambda p: None
            try:
                h = install.resolve_harness(f"claude={f}")
            finally:
                daemon.trusted_file = saved
            self.assertEqual(h["name"], "claude")
            self.assertEqual(h["script"], os.path.realpath(f))
            self.assertTrue(os.path.isabs(h["exe"]))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_resolve_harness_refuses_a_user_writable_binary(self):
        from tracekit import install
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, "claude")
            shutil.copy(os.path.realpath(SH or "/bin/sh"), f)
            os.chmod(d, 0o777)
            with self.assertRaises(SystemExit):
                install.resolve_harness(f)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
