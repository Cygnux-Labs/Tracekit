"""`tracekit signer serve --dev` auto-spawned by the v2 client, end to end with no fakes."""
import contextlib
import io
import json
import os
import shlex
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

from factories import wait_for
from tracekit import __version__, cli
from tracekit.format.canon import event_hash
from tracekit.locking import lock_file
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import service
from tracekit.signer.rpc_schema import RPC_MIN, RPC_VERSION, RPCError
from tracekit.storage.file import FileReader
from tracekit.transport import tcp_dev, read_frame, write_frame
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(os.name == "posix", "POSIX paths, signals and shells; DevSignerOverTcp (test_signer_dev.py) runs everywhere")
class DevSignerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_IDLE": "60",
                                           "PYTHONPATH": ROOT, "HOME": os.path.join(self.dir, "home"),
                                           "XDG_DATA_HOME": os.path.join(self.dir, "data")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("TRACEKIT_SIGNER", None)
        self.addCleanup(autospawn.down)

    def path(self, name):
        return os.path.join(self.run_dir, name)

    def held(self):
        return autospawn._held(self.path(autospawn.LOCK))

    def wait_released(self, timeout=20):
        deadline = time.monotonic() + timeout
        while self.held():
            self.assertLess(time.monotonic(), deadline, "the signer did not exit")
            time.sleep(0.05)

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(list(argv)), 0)
        return out.getvalue()

    def one_run(self, client):
        with client.run("e2e") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            events = run.call("read")["events"]
        self.assertEqual(events[0]["data"]["signer_isolation"], "same-user")
        return client.hello["pid"]

    def test_autospawn_reuse_down_sigkill_and_verify(self):
        first = Client()
        pid = self.one_run(first)
        first.close()
        self.assertEqual(autospawn._pid(self.run_dir), pid)
        data_dir = service.dev_data_dir()
        self.assertEqual(os.stat(data_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(data_dir, "keys", "record.key")).st_mode & 0o777, 0o600)
        second = Client()
        self.assertEqual(self.one_run(second), pid)   # reuses the running signer
        second.close()

        self.assertIn(f"dev signer stopped (pid {pid})", self.cli("down"))
        self.assertFalse(os.path.exists(self.path(autospawn.SOCK)))
        self.assertFalse(os.path.exists(self.path(autospawn.ENDPOINT)))

        third = Client()
        killed = self.one_run(third)
        self.assertNotEqual(killed, pid)
        os.kill(killed, signal.SIGKILL)
        self.wait_released()
        fourth = Client()
        self.assertNotIn(self.one_run(fourth), (pid, killed))   # stale socket and endpoint replaced
        fourth.close()
        third.close()
        self.cli("down")
        self.assertEqual(service.fsck(data_dir), [])   # one chain across all three signers, every signature valid

    def test_two_homes_sharing_a_runtime_dir_never_share_a_signer(self):
        """macOS falls back to /tmp/tk-<uid> for a long HOME, Linux keeps $XDG_RUNTIME_DIR per user: two HOMEs of one
        user share the runtime dir, while each has its own data dir."""
        a = Client()
        self.addCleanup(a.close)
        pid_a = self.one_run(a)
        home_b = {"HOME": os.path.join(self.dir, "home-b"), "XDG_DATA_HOME": os.path.join(self.dir, "data-b")}
        with mock.patch.dict(os.environ, home_b):
            self.addCleanup(lambda: mock.patch.dict(os.environ, home_b)(autospawn.down)())
            b = Client()
            self.addCleanup(b.close)
            pid_b = self.one_run(b)
            self.assertNotEqual(pid_b, pid_a)   # its own signer, of its own data dir, in a sibling runtime dir
            self.assertEqual(os.path.realpath(b.hello["data_dir"]), os.path.realpath(service.dev_data_dir()))
            self.assertTrue(autospawn.signer_dir().startswith(self.run_dir + "-"))
            self.assertLess(len(os.path.join(autospawn.signer_dir(), autospawn.SOCK).encode()), 104)
        self.assertEqual(os.path.realpath(a.hello["data_dir"]), os.path.realpath(service.dev_data_dir()))
        again = Client()
        self.addCleanup(again.close)
        self.assertEqual(self.one_run(again), pid_a)   # HOME A still finds its own, in the runtime dir itself
        self.assertEqual(autospawn.signer_dir(), self.run_dir)
        with mock.patch.dict(os.environ, home_b):
            self.assertEqual(autospawn.down(), pid_b)   # `tracekit down` in HOME B stops B's alone
        self.assertTrue(self.held())

    def test_a_runtime_dir_too_long_for_a_socket_path_gets_a_short_one_of_its_own(self):
        """macOS caps socket paths at 104 bytes: a TRACEKIT_RUNTIME_DIR too long for one serves its signer from
        /tmp/tk-<uid>.<hex of its path>, which every client given that dir finds and `tracekit status` names."""
        long = {"TRACEKIT_RUNTIME_DIR": os.path.join(self.dir, "r" * 100)}
        with mock.patch.dict(os.environ, long):
            short = autospawn.runtime_dir()
            self.addCleanup(shutil.rmtree, short, True)
            self.addCleanup(lambda: mock.patch.dict(os.environ, long)(autospawn.down)())
            self.assertTrue(short.startswith(f"/tmp/tk-{os.getuid()}."), short)
            self.assertEqual(os.stat(short).st_mode & 0o777, 0o700)
            first = Client()
            self.addCleanup(first.close)
            pid = self.one_run(first)
            again = Client()
            self.addCleanup(again.close)
            self.assertEqual(self.one_run(again), pid)
            self.assertEqual(json.loads(self.cli("status"))["signer_v2"]["socket"], os.path.join(short, autospawn.SOCK))
        self.assertNotEqual(autospawn.runtime_dir(), short)   # another dir's is never this one
        near = "/tmp/" + "s" * (103 - len("/tmp/") - len("/" + autospawn.SOCK))   # its socket path fits, a side dir's not
        self.assertEqual(autospawn._short(near), near)
        self.assertLessEqual(len(os.path.join(autospawn._side(near), autospawn.SOCK).encode()), 103)

    def test_a_signer_from_before_1_4_is_this_homes_when_this_data_dirs_store_is_held(self):
        os.makedirs(self.run_dir, 0o700)
        with open(self.path(autospawn.ENDPOINT), "w") as f:   # as a 1.3 dev signer published it: no data_dir
            json.dump({"proto": [15, 17], "version": "1.3.0", "pid": 1}, f)
        locks = []
        for path in (self.path(autospawn.LOCK), os.path.join(service.dev_data_dir(), "store", "lock")):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            locks.append(open(path, "a"))
            self.addCleanup(locks[-1].close)
        lock_file(locks[0], blocking=False)   # it is alive
        self.assertTrue(autospawn._theirs(self.run_dir))   # and doesn't hold this HOME's store: another HOME's
        lock_file(locks[1], blocking=False)
        self.assertFalse(autospawn._theirs(self.run_dir))   # this HOME's: replaced as before

    def test_the_dev_signer_keeps_each_calls_arguments_for_its_user(self):
        """`tracekit view --dev` showed "no rule matched" for every allowed call: the dev signer kept no content. It
        keeps each call's redacted arguments and lets its own user read them; TRACEKIT_DEV_CONTENT=0 keeps none."""
        c = Client()
        self.addCleanup(c.close)
        with c.run("e2e") as run:
            seq = run.decide("c1", "Bash", {"command": "ls -la"})["run_seq"]
            run.complete("c1")
        got = c.call("content_get", run_id=run.run_id, seqs=[seq], purpose="test")["items"]
        self.assertEqual(got[0]["content"], {"command": "ls -la"})
        c.close()
        autospawn.down()
        with mock.patch.dict(os.environ, {"TRACEKIT_DEV_CONTENT": "0"}):
            off = Client()
            self.addCleanup(off.close)
            with off.run("e2e") as run:
                seq = run.decide("c1", "Bash", {"command": "ls"})["run_seq"]
            with self.assertRaises(RPCError) as e:
                off.call("content_get", run_id=run.run_id, seqs=[seq], purpose="test")
            self.assertEqual(e.exception.code, "forbidden")

    def test_down_right_after_up_stops_the_starting_signer(self):
        """`tracekit up` returns while the signer starts; a `down` before it published endpoint.json exited 1 (Hung)."""
        self.assertIn("dev signer starting", self.cli("up"))
        self.assertIn("dev signer stopped (pid ", self.cli("down"))
        self.assertFalse(self.held())

    def test_a_previous_version_client_is_served(self):
        """RPC 16 adds only optional fields: the signer serves 15..16, and a 15 client keeps working unchanged."""
        with mock.patch("tracekit.sdk.client.RPC_VERSION", RPC_MIN):
            c = Client()
            self.addCleanup(c.close)
            self.one_run(c)
        self.assertEqual(c.hello["proto"], [RPC_MIN, RPC_VERSION])

    def test_dev_run_exports_and_verifies_while_the_signer_runs(self):
        c = Client()
        self.addCleanup(c.close)
        with c.run("e2e") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            self.assertEqual(run.decide("c2", "tracekit_demo_denied", "{}")["decision"], "deny")
        store = os.path.join(service.dev_data_dir(), "store")
        self.assertTrue(wait_for(lambda: list(FileReader(store).iter_run("default", run.run_id))[-1]["event"]["type"]
                                 == "run.final", 20), "no run.final after the grace window")
        vkey = self.cli("signer", "vkey", "--dev").strip()
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, "run.tkb")
        self.cli("signer", "trust", "--dev", "-o", trust)
        with open(trust) as f:
            self.assertEqual(json.load(f), {"logs": [vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0})
        self.cli("export", "--v2", "--run", run.run_id, "--dev", "-o", out)
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev;", self.cli("verify", out, "--trust", trust))
        self.assertTrue(self.held())   # the signer kept running throughout

    def test_export_says_what_it_wrote_and_the_commands_it_gives_verify_it(self):
        """`tracekit export --v2` printed bundle_v2.export's summary as raw JSON: it says what it wrote and where, then
        the commands that verify the bundle, which run as printed. --json keeps the JSON for scripts."""
        c = Client()
        self.addCleanup(c.close)
        with c.run("e2e") as run:
            run.decide("c1", "Bash", '{"command": "ls"}')
            run.complete("c1")
        store = os.path.join(service.dev_data_dir(), "store")
        self.assertTrue(wait_for(lambda: list(FileReader(store).iter_run("default", run.run_id))[-1]["event"]["type"]
                                 == "run.final", 20), "no run.final after the grace window")
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.dir)
        said = self.cli("export", "--v2", "--run", run.run_id, "-o", "run.tkb")
        self.assertRegex(said, rf"^wrote run\.tkb: run {run.run_id}, \d+ records; a verifier needs tracekit "
                               r"\d+\.\d+\.\d+ or newer\nnext, pin the signer's log key and verify the bundle against "
                               r"it:\n  tracekit signer trust -o trust\.json\n  tracekit verify run\.tkb --trust "
                               r"trust\.json\n$")
        trust, verify = [shlex.split(x)[1:] for x in said.splitlines() if x.startswith("  tracekit ")]
        self.cli(*trust)
        self.assertIn("Integrity: VERIFIED.", self.cli(*verify))
        info = json.loads(self.cli("export", "--v2", "--run", run.run_id, "-o", "again.tkb", "--json"))
        self.assertEqual((info["bundle"], info["verifier_min_version"] in said), ("again.tkb", True))

    def test_the_dev_user_signs_findings_about_its_runs_and_they_read_self_asserted(self):
        """The dev signer lists its user in analyzers (#309): a findings run about the user's own run signs a finding,
        which the verifier labels self-asserted, the dev user being the agent too."""
        c = Client()
        self.addCleanup(c.close)
        with c.run("e2e") as run:
            run.decide("c1", "Bash", {"command": "ls"})
        store = os.path.join(service.dev_data_dir(), "store")
        cites = [{"run_seq": r["event"]["run_seq"], "hash": r["hash"]} for r in FileReader(store).iter_run(
            "default", run.run_id)]
        with c.run("tracekit-analyze", analyzes=run.run_id) as findings:
            findings.review_finding("tracekit-analyze/1.4.0", {"kind": "finding", "rule": "TK-X201", "severity": "low"},
                                    cites)
        for rid in (run.run_id, findings.run_id):
            self.assertTrue(wait_for(lambda: list(FileReader(store).iter_run("default", rid))[-1]["event"]["type"]
                                     == "run.final", 20), "no run.final after the grace window")
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, "run.tkb")
        self.cli("signer", "trust", "--dev", "-o", trust)
        self.cli("export", "--v2", "--run", run.run_id, "--dev", "--with-findings", "-o", out)
        rep, code = v2.verify(out, trust)
        self.assertEqual(code, 0, rep.checks)
        self.assertEqual(next((x["status"], x["detail"]) for x in rep.checks if x["check"] == "reviews"),
                         ("warn", "1 review(s): 1 self-asserted"))

    def test_tracekit_analyze_signs_a_dev_runs_findings_and_verify_shows_them_apart(self):
        """End to end (#309): a Claude Code-shaped run (the hook's prompt, the tailer's lines, an edit nobody asked
        for), `tracekit analyze --v2` signs its finding and coverage in a findings run, `tracekit export --with-findings`
        bundles both, and `tracekit verify` checks the citations: integrity on its own, a reviews line (self-asserted:
        the dev user is agent and analyzer) and a Findings line after Integrity and Assurance."""
        c = Client()
        self.addCleanup(c.close)
        args = {"file_path": "/work/proj/billing.py", "old_string": "a", "new_string": "b"}
        asked = {"transcript": "main", "entry": {"type": "user", "cwd": "/work/proj", "message": {
            "role": "user", "content": "Fix src/pager.py."}}}
        said = {"transcript": "main", "entry": {"type": "assistant", "message": {"id": "msg_1", "content": [
            {"type": "thinking", "thinking": "One more small fix.", "signature": "c2ln"},
            {"type": "tool_use", "id": "toolu_1", "name": "Edit", "input": args}]}}}
        with c.run("claude-code") as run:
            run.observe("Fix src/pager.py.", "claude-code:UserPromptSubmit", "trusted")
            run.call("model_event", provider="anthropic", model="m", phase="request", exchange_id="u1",
                     content_digest=event_hash(asked), body=asked)
            run.call("model_event", provider="anthropic", model="m", phase="response", exchange_id="msg_1",
                     content_digest=event_hash(said), body=said, tool_uses=[{
                         "id": "toolu_1", "name": "Edit", "executed_by": "client", "args_source": "parsed",
                         "args_digest": event_hash({"tool": "Edit", "args": args})}])
            self.assertEqual(run.decide("toolu_1", "Edit", args)["decision"], "allow")
            run.complete("toolu_1")
        store = os.path.join(service.dev_data_dir(), "store")
        final = lambda rid: list(FileReader(store).iter_run("default", rid))[-1]["event"]["type"] == "run.final"  # noqa
        self.assertTrue(wait_for(lambda: final(run.run_id), 20), "no run.final after the grace window")
        out = self.cli("analyze", "--v2", "--run", run.run_id)
        self.assertIn("1 problem (1 medium)", out.splitlines()[0])
        findings_run = out.rsplit("in findings run ", 1)[1].split(";")[0]
        self.assertTrue(wait_for(lambda: final(findings_run), 20), "no run.final for the findings run")
        trust, bundle = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, "run.tkb")
        self.cli("signer", "trust", "--dev", "-o", trust)
        self.cli("export", "--v2", "--run", run.run_id, "--dev", "--with-findings", "-o", bundle)
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            self.assertEqual(cli.main(["verify", bundle, "--trust", trust]), 0)
        text = report.getvalue()
        self.assertIn("[WARN] reviews — 2 review(s): 2 self-asserted", text)
        self.assertIn("\nIntegrity: VERIFIED.\nAssurance: dev;", text)
        self.assertTrue(text.endswith("Findings: 1 finding(s) (1 medium) and 1 coverage review(s); 2 self-asserted "
                                      "(an opinion of the run, not its integrity).\n"), text[-300:])

    def test_idle_exit(self):
        os.environ["TRACEKIT_DEV_IDLE"] = "1"
        c = Client()
        c.status()
        time.sleep(1.5)
        self.assertTrue(self.held())   # an open connection keeps it alive
        c.close()
        self.wait_released()
        self.assertFalse(os.path.exists(self.path(autospawn.SOCK)))
        self.assertFalse(os.path.exists(self.path(autospawn.ENDPOINT)))

    def test_up_wait_json(self):
        hello = json.loads(self.cli("up", "--wait", "--json"))
        self.assertEqual(hello["proto"], [RPC_MIN, RPC_VERSION])
        self.assertEqual(hello["version"], __version__)
        with open(self.path(autospawn.ENDPOINT)) as f:
            self.assertEqual(json.load(f), hello)

    def test_hello_over_tcp(self):
        os.makedirs(self.run_dir, 0o700)
        ep = self.path("tcp.json")
        svc = service.SignerService(os.path.join(self.dir, "tcp-data"))
        self.addCleanup(svc.close)
        (server,) = service.serve({"tcp_endpoint": ep}, svc)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        sock, rfile = tcp_dev.connect(ep)
        with sock:
            write_frame(sock, {"method": "hello"})
            self.assertEqual(read_frame(rfile)["proto"], [RPC_MIN, RPC_VERSION])


class SpawnAndStatus(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.run_dir})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("TRACEKIT_SIGNER", None)

    def test_signer_starts_in_the_private_runtime_dir_with_cwd_off_sys_path(self):
        os.makedirs(self.run_dir, 0o700)
        with mock.patch.object(autospawn.subprocess, "Popen") as popen:
            popen.return_value.wait.return_value = 0
            autospawn.spawn(self.run_dir)
        (argv,), kw = popen.call_args
        self.assertEqual(kw["cwd"], self.run_dir)
        self.assertEqual(argv[argv.index("-m") - 1] == "-P", sys.version_info >= (3, 11))

    def test_status_creates_nothing(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["status"]), 0)
        self.assertFalse(json.loads(out.getvalue())["signer_v2"]["running"])
        self.assertFalse(os.path.exists(self.run_dir))

    def test_status_says_how_a_dev_signer_not_started_starts(self):
        # right after `init --dev --v2` status said "[Errno 2] No such file or directory: '/tmp/tk-501.…'"
        self.assertIn("not started", autospawn.status()["error"])
        os.makedirs(self.run_dir, 0o700)
        self.assertIn("tracekit up", autospawn.status()["error"])
        os.chmod(self.run_dir, 0o755)   # a dir someone else could have made: refused, and status says why
        self.assertIn("mode 0700", autospawn.status()["error"])
        os.chmod(self.run_dir, 0o700)   # a signer of another protocol over TCP (no Unix sockets): not "not started"
        with mock.patch.object(autospawn, "address", return_value=("tcp://127.0.0.1:1", "t")), \
                mock.patch.object(autospawn, "connect", side_effect=autospawn.Incompatible("protocol 15")):
            self.assertEqual(autospawn.status()["error"], "protocol 15")

    def test_status_shows_no_v1_signer_or_policy_on_a_v2_only_setup(self):
        """`signer` and `policy` are the v1 signer's and the v1 hooks' (whose fail mode v2 hooks don't follow): null
        when no config or TRACEKIT_SOCKET names a v1 signer and none answers at the default socket."""
        from tracekit import client, install
        os.environ.pop("TRACEKIT_SOCKET", None)   # setUp's patch.dict puts it back
        down = client.SignerUnavailable("[Errno 2] No such file or directory")
        cases = (({"hooks_settings": "/h/.claude/settings.json"}, down, None),   # init --dev --v2 writes only this
                 ({"socket": "/srv/v1.sock"}, down, {"ok": False, "error": f"unreachable at /srv/v1.sock: {down}"}),
                 ({}, None, {"ok": True}))   # a v1 signer from before 0.2.1's config, at the default socket
        for cfg, err, signer in cases:
            with self.subTest(cfg=cfg, reachable=err is None), \
                    mock.patch.object(client, "system_config", return_value=None), \
                    mock.patch.object(client, "client_config", return_value=cfg), \
                    mock.patch.object(client, "status", side_effect=err, return_value={"ok": True}), \
                    mock.patch.object(install, "_installed_hooks", return_value=[]):
                out = install.status()
                self.assertEqual(out["signer"], signer)
                self.assertEqual(out["policy"] and out["policy"]["fail_mode"], signer and "open")

    def test_status_names_the_system_signer_in_system_mode(self):
        from tracekit import client
        sock = os.path.join(self.dir, "system.sock")
        with mock.patch.object(client, "system_config", return_value={"signer": sock}):
            got = autospawn.status()
        self.assertEqual((got["socket"], got["running"]), (sock, False))
        self.assertFalse(os.path.exists(self.run_dir))


class DevSignerOverTcp(unittest.TestCase):
    """The loopback TCP transport (Windows, decision S3), forced on every OS by hiding AF_UNIX from both sides."""
    NO_UNIX = "import socket, sys; socket.__dict__.pop('AF_UNIX', None); from tracekit.cli import main; sys.exit(main())"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.run_dir = os.path.join(self.dir, "run")
        for p in (mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.run_dir, "TRACEKIT_DEV_IDLE": "60",
                                               "PYTHONPATH": ROOT, "HOME": os.path.join(self.dir, "home"),
                                               "XDG_DATA_HOME": os.path.join(self.dir, "data"),
                                               "LOCALAPPDATA": os.path.join(self.dir, "data")}),
                  mock.patch.dict(socket.__dict__),
                  mock.patch.object(autospawn, "SIGNER_ARGV", [sys.executable, "-c", self.NO_UNIX, "signer", "serve", "--dev"])):
            p.start()
            self.addCleanup(p.stop)
        socket.__dict__.pop("AF_UNIX", None)
        os.environ.pop("TRACEKIT_SIGNER", None)
        self.addCleanup(autospawn.down)

    def test_autospawned_dev_signer(self):
        c = Client()
        with c.run("tcp") as run:
            self.assertEqual(run.decide("c1", "Bash", '{"command": "ls"}')["decision"], "allow")
            run.complete("c1")
            self.assertEqual(run.call("read")["events"][0]["data"]["signer_isolation"], "same-user")
        c.close()
        out, trust = os.path.join(self.dir, "run.tkb"), os.path.join(self.dir, "trust.json")
        DevSignerEndToEnd.cli(self, "export", "--v2", "--run", run.run_id, "-o", out)   # nudges the signer over TCP
        DevSignerEndToEnd.cli(self, "signer", "trust", "-o", trust)
        self.assertIn("Integrity: VERIFIED", DevSignerEndToEnd.cli(self, "verify", out, "--trust", trust))
        endpoint = os.path.join(self.run_dir, autospawn.ENDPOINT)
        with open(endpoint) as f:
            self.assertEqual(json.load(f)["pid"], c.hello["pid"])
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, autospawn.SOCK)))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(endpoint).st_mode), 0o600)
            os.chmod(endpoint, 0o644)
            with self.assertRaisesRegex(SignerUnavailable, "readable by no one else"):
                Client().status()

    def test_named_signer_with_a_token(self):
        ep = os.path.join(self.dir, "tcp.json")
        svc = service.SignerService(os.path.join(self.dir, "tcp-data"))
        self.addCleanup(svc.close)
        (server,) = service.serve({"tcp_endpoint": ep}, svc)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with open(ep) as f:
            published = json.load(f)
        os.environ["TRACEKIT_SIGNER"] = f"tcp://127.0.0.1:{published['port']}"
        with self.assertRaisesRegex(SignerUnavailable, "need TRACEKIT_SIGNER_TOKEN"):
            Client().status()
        os.environ["TRACEKIT_SIGNER_TOKEN"] = "0" * 64
        with self.assertRaisesRegex(SignerUnavailable, "proof mismatch"):
            Client().status()
        os.environ["TRACEKIT_SIGNER_TOKEN"] = published["token"]
        c = Client()
        self.addCleanup(c.close)
        self.assertEqual(c.status()["identity"]["scheme"], "token")


if __name__ == "__main__":
    unittest.main()
