"""0.3 harness binding tests: the signer attributes each hook run to the registered harness process it came from,
using the kernel's process tree, and refuses runs and events that did not come from that harness instance.

Real processes are used throughout: a copy of /bin/sh plays the harness, and `sleep` children play its hooks.

    python3 -m unittest tests.test_harness_03 -v
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import socket
import tempfile
import threading
import unittest
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import harness_helper, policy  # noqa: E402
from tracekit.daemon import Signer, load_config  # noqa: E402
from tracekit.harness_helper import find as find_harness, trusted_file  # noqa: E402
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
        self._trusted = harness_helper.trusted_file
        harness_helper.trusted_file = lambda p: None

    def tearDown(self):
        harness_helper.trusted_file = self._trusted
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

    def test_signer_asks_the_helper_when_one_is_configured(self):
        sock = os.path.join(tempfile.mkdtemp(dir="/tmp"), "h.sock")
        self.addCleanup(shutil.rmtree, os.path.dirname(sock), True)
        self.s.ledger.close()
        self.s = make_signer(self.home, harnesses=self.harnesses(), mode="system", harness_helper=sock)
        r = self.append(run_start("down"), self.hook_under_harness())
        self.assertFalse(r["ok"])
        self.assertIn("harness helper unavailable", r["error"])
        start_helper(self, sock)
        self.assertTrue(self.append(run_start("up"), self.hook_under_harness())["ok"])


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
            saved = harness_helper.trusted_file
            harness_helper.trusted_file = lambda p: None
            try:
                h = install.resolve_harness(f"claude={f}")
            finally:
                harness_helper.trusted_file = saved
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


def start_helper(case, sock, allow_uid=None, server=None):
    srv = (server or harness_helper.serve)(sock, os.getuid() if allow_uid is None else allow_uid)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv


def raw_request(sock, line):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(sock)
        s.sendall(line)
        return s.makefile("rb").readline()


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and hasattr(os, "getuid"), "Unix sockets")
class Helper(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(dir="/tmp")   # short: macOS caps socket paths
        self.addCleanup(shutil.rmtree, d, True)
        self.sock = os.path.join(d, "h.sock")

    def test_answers_the_chain_of_a_pid(self):
        start_helper(self, self.sock)
        procs = harness_helper.ask(self.sock, os.getpid())
        self.assertEqual(procs[0]["pid"], os.getpid())
        self.assertEqual(procs[1]["pid"], os.getppid())
        self.assertEqual(procs[0]["start_time"], harness_helper.start_time(os.getpid()))
        self.assertEqual(os.stat(self.sock).st_mode & 0o777, 0o600)

    def test_answers_only_a_pid(self):
        start_helper(self, self.sock)
        for line in (b'{"pid": 1, "path": "/etc/shadow"}\n', b'{"cmd": "id"}\n', b'{"pid": "1"}\n', b'{"pid": 0}\n',
                     b'[1]\n', b'{"pid": true}\n', b"x" * 4096 + b"\n"):
            self.assertIn(b"error", raw_request(self.sock, line), line)

    def test_answers_only_the_signers_uid(self):
        start_helper(self, self.sock, os.getuid() + 1, harness_helper.Server)   # bound as is: no chown to another uid
        try:   # closed unanswered: an empty read, or a reset / broken pipe when the request was not read
            self.assertEqual(raw_request(self.sock, b'{"pid": 1}\n'), b"")
        except (ConnectionResetError, BrokenPipeError):
            pass
        with self.assertRaises((OSError, ValueError)):
            harness_helper.ask(self.sock, os.getpid())

    @pytest.mark.root
    @unittest.skipUnless(LINUX_PROC and hasattr(os, "geteuid") and os.geteuid() == 0, "needs root on Linux")
    def test_real_helper_reads_another_users_exe_for_the_signer_only(self):
        import pwd
        nobody = pwd.getpwnam("nobody").pw_uid
        os.chmod(os.path.dirname(self.sock), 0o755)
        start_helper(self, self.sock, allow_uid=nobody)
        code = ("import json, sys; from tracekit import harness_helper as h; "
                "print(json.dumps(h.ask(sys.argv[1], int(sys.argv[2]))[0]))")
        r = subprocess.run([sys.executable, "-c", code, self.sock, str(os.getpid())], user=nobody, capture_output=True,
                           text=True, cwd="/", env={"PYTHONPATH": ROOT})
        self.assertEqual(r.returncode, 0, r.stderr)
        me = json.loads(r.stdout)
        self.assertEqual(me["exe"], os.path.realpath(sys.executable))   # root's process, which nobody can't read
        with self.assertRaises((OSError, ValueError)):   # root is not the signer: no answer (or a reset)
            harness_helper.ask(self.sock, os.getpid())


class Units(unittest.TestCase):
    def test_signer_units_have_no_capabilities(self):
        from tracekit import install
        for text in (install.UNIT, install.PROXY_UNIT, install.V2_UNIT_TEXT):
            self.assertNotIn("CAP_", text)
            for line in ("CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges=true", "UMask=0027",
                         "ProtectSystem=strict", "SystemCallFilter=@system-service"):
                self.assertIn(line + "\n", text)

    @unittest.skipIf(os.name == "nt", "POSIX users (pwd)")
    def test_helper_unit_has_exactly_the_helpers_capabilities(self):
        import pwd
        from tracekit import install
        me = pwd.getpwuid(os.getuid())
        sock_unit, service = install.helper_units(install.V2_HELPER, install.V2_UNIT, me, install.V2_HELPER_SOCKET)
        caps = [line for line in service.splitlines() if line.startswith("CapabilityBoundingSet=")]
        self.assertEqual(caps, ["CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH"])
        for line in ("RestrictAddressFamilies=AF_UNIX", "PrivateNetwork=true", "NoNewPrivileges=true",
                     f"ExecStart={install.OPT_PYTHON} -I -m tracekit.harness_helper --allow-uid {me.pw_uid}"):
            self.assertIn(line + "\n", service)
        for line in (f"ListenStream={install.V2_HELPER_SOCKET}", f"SocketUser={me.pw_name}", "SocketMode=0600"):
            self.assertIn(line + "\n", sock_unit)

    def test_doctor_reports_the_helper_and_its_capability_set(self):
        from tracekit import doctor, install
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        unit = os.path.join(d, "h.service")
        cases = (("CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n", "ok"),
                 ("CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
                  "fail"), ("ExecStart=x\n", "fail"))
        for text, status in cases:
            with open(unit, "w") as f:
                f.write(text)
            r = doctor.helper_result(unit, "fix")
            self.assertEqual((r["id"], r["status"]), ("D-HARNESS-HELPER", status), r)
            self.assertIn("CapabilityBoundingSet=" + ("CAP_SYS_PTRACE" if "CAP_" in text else "(unset"), r["detail"])
        self.assertEqual(doctor.helper_result(os.path.join(d, "none.service"), "fix")["status"], "fail")
        signer = os.path.join(d, "s.service")
        with open(signer, "w") as f:
            f.write(install.V2_UNIT_TEXT.format(user="s", python="p", config="c", unit="u", data="d")
                    .replace("AmbientCapabilities=\n", "AmbientCapabilities=CAP_SYS_PTRACE\n"))
        self.assertIn("an empty capability set", doctor._hardening(signer)[1])


HARNESS = "/usr/bin/fake-harness"


def ident(pid, uid="4242"):
    from tracekit.identity.base import CallerIdentity
    return CallerIdentity("uid", uid, True, {"pid": pid})


def proc(pid, exe, start):
    return {"pid": pid, "exe": exe, "start_time": start, "script": None}


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and hasattr(os, "getuid"), "Unix sockets")
class V2Binding(unittest.TestCase):
    """The v2 signer binds a run to the harness process the helper finds above register_run's caller. The helper is
    real; its view of the process tree is simulated."""

    def setUp(self):
        from tracekit.signer import service
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.sock = os.path.join(self.d, "h.sock")
        self.chains, self.asked = {}, []

        def chain(pid, limit=64):
            self.asked.append(pid)
            return self.chains.get(pid, [])
        for name, fn in (("chain", chain), ("trusted_file", lambda p: None),
                         ("start_time", lambda pid: (self.chains.get(pid) or [{}])[0].get("start_time"))):
            p = mock.patch.object(harness_helper, name, fn)
            p.start()
            self.addCleanup(p.stop)
        start_helper(self, self.sock)
        self.chains[100] = [proc(100, "/usr/bin/python3", 7), proc(90, "/bin/sh", 6), proc(80, HARNESS, 5)]
        self.chains[200] = [proc(200, "/usr/bin/python3", 9), proc(1, "/sbin/init", 1)]
        self.chains[300] = [proc(300, "/usr/bin/python3", 9), proc(80, HARNESS, 6)]   # pid 80 reused by another harness
        self.cfg = {"data_dir": os.path.join(self.d, "data"),
                    "harness_binding": {"helper": self.sock, "required": ["uid:4242"], "harnesses": {"fake": HARNESS}}}
        self.service = service
        self.s = self.open()

    def open(self):
        s = self.service.open_service(self.cfg)
        self.addCleanup(s.close)
        return s

    def register(self, pid, uid="4242"):
        run = self.s.call(ident(pid, uid), "register_run", {"request_id": f"r{pid}{uid}", "agent": {"name": "a"}})
        return {"run_id": run["run_id"], "run_token": run["run_token"]}

    def decide(self, run, pid, n=0):
        self.seq = getattr(self, "seq", -1) + 1
        return self.s.call(ident(pid), "decide", {"request_id": f"d{pid}-{n}", **run, "tool_call_id": f"t{pid}-{n}",
                                                  "stream": "s", "client_seq": self.seq, "tool": "ls",
                                                  "args_source": "parsed", "args": {}})

    def refused(self, fn, *a):
        from tracekit.signer.rpc_schema import RPCError
        with self.assertRaises(RPCError) as cm:
            fn(*a)
        self.assertEqual(cm.exception.code, "forbidden")
        return str(cm.exception)

    def registered(self):
        from test_signer_service import records
        return [r["event"]["data"] for r in records(self.cfg["data_dir"]) if r["event"]["type"] == "run.registered"]

    def test_run_from_the_harness_is_registered_with_it(self):
        self.decide(self.register(100), 100)
        self.assertEqual(self.registered()[0]["harness"],
                         {"name": "fake", "exe": HARNESS, "pid": 80, "start_time": 5, "attested": True})

    def test_run_from_outside_the_harness_is_refused(self):
        self.assertIn("not from a registered harness", self.refused(self.register, 200))
        self.assertEqual(self.registered(), [])

    def test_identity_without_required_binding_registers_unbound(self):
        self.register(200, uid="5151")
        self.assertNotIn("harness", self.registered()[0])

    def test_calls_must_come_from_below_the_runs_harness_process(self):
        run = self.register(100)
        self.refused(self.decide, run, 200)
        self.refused(self.decide, run, 300)   # same harness pid, another start time: another process
        self.decide(run, 100)

    def test_chains_are_cached_per_process_instance(self):
        run = self.register(100)
        self.decide(run, 100, 1)
        self.decide(run, 100, 2)
        self.assertEqual(self.asked.count(100), 1)
        self.chains[100] = [proc(100, "/usr/bin/python3", 8), proc(1, "/sbin/init", 1)]   # pid 100 reused
        self.refused(self.decide, run, 100, 3)
        self.assertEqual(self.asked.count(100), 2)

    def test_binding_survives_a_restart(self):
        run = self.register(100)
        self.s.close()
        self.s = self.open()
        self.decide(run, 100)
        self.refused(self.decide, run, 200)

    def test_helper_down_refuses_a_required_identity(self):
        os.unlink(self.sock)
        self.assertIn("harness helper did not answer", self.refused(self.register, 100))

    def test_bad_config_is_refused(self):
        for bad in ({"harnesses": {"x": "relative/exe"}}, {"harnesses": ["/bin/sh"]}, {"helper": 1, "harnesses": {}},
                    {"harnesses": {}, "extra": 1}):
            with self.assertRaises(ValueError):
                self.service.SignerService(os.path.join(self.d, "bad"), harness_binding=bad)


if __name__ == "__main__":
    unittest.main()
