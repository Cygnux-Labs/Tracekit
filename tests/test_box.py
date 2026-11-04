"""`tracekit up --isolated` (tracekit/box.py, docs/design/isolated-up.md): the box gets the project, its token and the
signer's CA certificate only, with what the host runs from the project read-only (placeholders for a missing .git and
.claude; a symlink there stops `up`); it is on an internal network whose only way out is its relay to the signer; the
box signer records its runs `unknown` with a signed ext.box, which both verifiers read as proof against the boxed agent
only; the token is revoked when `up` ends, is stopped, or (killed) at the next `up`; doctor flags a box container with
the Docker socket, your home or its secrets, root or confinement off. BoxInDocker runs the stand-in agent and
tests/box_probe.py in a real box (Docker only: skipped without a reachable daemon; on a Mac with colima set
DOCKER_CONTEXT=colima). Each review finding of #601 has its test, named for it in its docstring."""
import contextlib
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from factories import patch_env
from test_container import NO_DOCKER
from tracekit import box, cli, doctor
from tracekit.identity.token import TokenStore
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tmpdir(case, under_home=False):
    """A temp dir; `under_home`: in your home, the only part of a Mac colima mounts into its VM."""
    d = tempfile.mkdtemp(prefix=".tk-box-test-" if under_home else "tk-box-",
                         dir=os.path.expanduser("~") if under_home else "/tmp" if os.name == "posix" else None)
    case.addCleanup(shutil.rmtree, d, True)
    return d


def mounts(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]


def pairs(argv):
    return [argv[i:i + 2] for i in range(len(argv))]


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Argv(unittest.TestCase):
    def setUp(self):
        self.project = tmpdir(self)
        self.h = os.path.join(tmpdir(self), "box")
        patch_env(self, TRACEKIT_BOX_HOME=self.h)

    def argv(self, **kw):
        return box.argv("box-1", self.project, "img", "10.0.9.2", "/h/empty", **kw)

    def test_the_box_gets_the_project_its_token_and_the_ca_only_on_an_internal_network(self):
        """Review 6: the box reached the host's 127.0.0.1 services and colima's sshd over Docker's bridge."""
        a = self.argv(cmd=["stand-in-agent", "ls"])
        self.assertEqual(mounts(a), [f"{self.project}:/work", "/h/empty:/work/.claude:ro", "/h/empty:/work/.git:ro",
                                     f"{self.h}/boxes/box-1/token:/run/tracekit/token:ro",
                                     f"{self.h}/tls/ca.pem:/run/tracekit/ca.pem:ro"])
        for flag in (["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--pull", "never"],
                     ["--user", f"{os.getuid()}:{os.getgid()}"], ["--network", box.NETWORK],
                     ["--add-host", "host.docker.internal:10.0.9.2"], ["--pids-limit", "1024"], ["--memory", "2g"],
                     ["-e", f"TRACEKIT_SIGNER=https://host.docker.internal:{box.RELAY_PORT}"],
                     ["--label", "tracekit.box=box-1"]):
            self.assertIn(flag, pairs(a))
        self.assertNotIn(["--network", "bridge"], pairs(a))
        self.assertIn(["--network", "bridge"], pairs(self.argv(network=True)))
        self.assertFalse([x for x in a if "docker.sock" in x or "--privileged" in x])
        self.assertEqual(a[-3:], ["img", "stand-in-agent", "ls"])

    def test_what_the_host_runs_is_read_only(self):
        """Review 2 and 3: .git and .claude were read-only only when present; husky, pre-commit, lefthook, other
        agents' project configs, .mcp.json and editor tasks stayed writable."""
        for d in (".git", ".husky", ".gemini", ".cursor", ".codex", ".qwen", ".vscode", ".claude"):
            os.mkdir(os.path.join(self.project, d))
        for f in (".pre-commit-config.yaml", "lefthook.yml", ".mcp.json", "crush.json"):
            open(os.path.join(self.project, f), "w").close()
        ro = {m.split(":")[1] for m in mounts(self.argv()) if m.endswith(":ro")}
        for n in (".git", ".husky", ".gemini", ".cursor", ".codex", ".qwen", ".vscode", ".claude",
                  ".pre-commit-config.yaml", "lefthook.yml", ".mcp.json", "crush.json"):
            self.assertIn(f"/work/{n}", ro)
        self.assertNotIn("/h/empty:/work/.git:ro", mounts(self.argv()))   # there now: no placeholder
        self.assertLessEqual({".codex", ".cursor", ".gemini", ".qwen", ".factory", ".agents", ".opencode", ".kilo",
                              ".devin", "crush.json"}, set(box.host_run(self.project)))   # agent_hooks' harness list


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Project(unittest.TestCase):
    def test_a_project_holding_your_home_or_a_signers_files_or_inside_them_is_refused(self):
        """Review 7: a project inside a signer's dir was mounted."""
        h = os.path.join(tmpdir(self), "a", "box")
        for project in ("/", os.path.expanduser("~"), os.path.dirname(os.path.expanduser("~")), os.path.dirname(h),
                        os.path.dirname(autospawn.data_dir()), h, os.path.join(h, "data"),
                        os.path.join(autospawn.data_dir(), "x")):
            with self.subTest(project), self.assertRaises(box.BoxError):
                box.check_project(project, h)
        inside = os.path.join(os.path.dirname(h), "project")
        os.makedirs(inside)
        self.assertEqual(box.check_project(inside, h), os.path.realpath(inside))

    def test_a_symlink_where_the_host_runs_a_file_stops_up(self):
        """Review E1: box 1 made .claude a symlink into the project; box 2 skipped it and wrote the host's settings."""
        h, p = os.path.join(tmpdir(self), "box"), tmpdir(self)
        os.mkdir(os.path.join(p, ".claude-real"))
        for name in (".claude", ".husky", ".mcp.json"):
            os.symlink(".claude-real", os.path.join(p, name))
            with self.subTest(name), self.assertRaises(box.BoxError) as cm:
                box.check_project(p, h)
            self.assertIn(name, str(cm.exception))
            os.remove(os.path.join(p, name))


class Problems(unittest.TestCase):
    H = "/h/box"

    def container(self, **over):
        c = {"Name": "/tracekit-box-1", "Config": {"User": "501:20"},
             "HostConfig": {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]},
             "Mounts": [{"Source": "/src/project", "Destination": "/work", "RW": True},
                        {"Source": f"{self.H}/empty", "Destination": "/work/.git", "RW": False},
                        {"Source": f"{self.H}/boxes/box-1/token", "Destination": "/run/tracekit/token", "RW": False},
                        {"Source": f"{self.H}/tls/ca.pem", "Destination": "/run/tracekit/ca.pem", "RW": False}]}
        for k, v in over.items():
            c[k] = {**c[k], **v} if isinstance(v, dict) else v
        return c

    def problems(self, **over):
        with mock.patch.object(os.path, "realpath", lambda p: p):
            return box.problems(self.container(**over), self.H)

    def test_what_up_runs_has_none(self):
        self.assertEqual(self.problems(), [])

    def test_each_way_out_is_named(self):
        """Review 7: ~/.ssh, ~/.aws, ~/.claude, socket dirs and unconfined seccomp or AppArmor went unflagged."""
        home = os.path.expanduser("~")
        for over, want in (
                ({"Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]}, "Docker socket"),
                ({"Mounts": [{"Source": "/var/run", "Destination": "/x"}]}, "Docker socket"),
                ({"Mounts": [{"Source": home, "Destination": "/work"}]}, "your home"),
                *(({"Mounts": [{"Source": os.path.join(home, s), "Destination": "/x"}]}, "credential")
                  for s in (".ssh", ".aws", ".claude", ".colima/default", ".docker")),
                ({"Mounts": [{"Source": f"{self.H}/data", "Destination": "/d"}]}, "a signer's file"),
                ({"Mounts": [{"Source": f"{self.H}/boxes/box-1/token", "Destination": "/run/tracekit/token",
                              "RW": True}]}, "a signer's file"),
                ({"Mounts": [{"Source": f"{self.H}/tokens.json", "Destination": "/run/tracekit/ca.pem"}]},
                 "a signer's file"),
                ({"Config": {"User": ""}}, "runs as root"), ({"HostConfig": {"Privileged": True}}, "privileged"),
                ({"HostConfig": {"CapDrop": []}}, "capabilities not dropped"),
                ({"HostConfig": {"SecurityOpt": []}}, "new privileges allowed"),
                ({"HostConfig": {"SecurityOpt": ["no-new-privileges", "seccomp=unconfined"]}}, "unconfined"),
                ({"HostConfig": {"SecurityOpt": ["no-new-privileges", "apparmor=unconfined"]}}, "unconfined"),
                ({"HostConfig": {"PidMode": "host"}}, "the host's pid namespace")):
            with self.subTest(want=want, over=over):
                self.assertTrue([p for p in self.problems(**over) if want in p], self.problems(**over))


class Tokens(unittest.TestCase):
    def setUp(self):
        self.store = TokenStore(os.path.join(tmpdir(self), "tokens.json"))

    def conn(self, secret, addr):
        return types.SimpleNamespace(headers={"Authorization": f"Bearer {secret}"}, client_address=(addr, 1))

    def test_a_box_token_says_so_and_is_taken_only_from_its_address(self):
        """Review 1 (Linux): a box's token worked from any address; now only from its relay's."""
        minted = self.store.add("box-b", 60, box=True, addr="172.17.0.9")
        self.assertEqual(self.store.authenticate(self.conn(minted, "172.17.0.9"), {}).claims["box"], True)
        with self.assertRaises(RPCError) as cm:
            self.store.authenticate(self.conn(minted, "127.0.0.1"), {})
        self.assertEqual(cm.exception.code, "unauthenticated")
        plain = self.store.add("agent", 60)
        self.assertNotIn("box", self.store.authenticate(self.conn(plain, "10.1.1.1"), {}).claims)

    def test_orphans_are_box_tokens_outliving_their_box(self):
        """Review E3: `up` killed left its box's token valid for 12 h."""
        for name, kw in (("box-old", {"box": True}), ("box-live", {"box": True}), ("agent", {})):
            self.store.add(name, 3600, **kw)
        later = self.store.load()["box-old"]["created"] + box.ORPHAN_S + 1
        self.assertEqual(box.orphans(self.store, {"box-live"}, now=later), ["box-old"])
        self.assertEqual(box.orphans(self.store, set(), now=later - box.ORPHAN_S), [])   # its `up` may be starting it
        self.store.revoke("box-old")
        self.assertEqual(box.orphans(self.store, {"box-live"}, now=later), [])


@unittest.skipUnless(hasattr(os, "getuid"), "the box signer has a Unix socket: macOS and Linux")
class BoxSigner(unittest.TestCase):
    """The signer.yaml setup() writes, served in this process: what the box's hooks can do over its TLS listener."""

    def setUp(self):
        self.h = os.path.join(tmpdir(self), "box")
        with mock.patch.object(box, "_listen_host", return_value="127.0.0.1"):
            self.path = box.setup(self.h)
        self.assertEqual(box.setup(self.h), self.path)   # a second up reuses it
        self.cfg = svc.load_config(self.path)
        self.service = svc.open_service(self.cfg)
        self.addCleanup(self.service.close)
        for s in svc.serve(self.cfg, self.service):
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        self.store = TokenStore(self.cfg["http"]["tokens"])
        self.bearer_file = os.path.join(self.h, "bearer")
        with open(self.bearer_file, "w") as f:
            f.write(self.store.add("box-test", box.TTL_S, box=True))
        patch_env(self, TRACEKIT_SIGNER_CA=os.path.join(self.h, "tls", "ca.pem"),
                  TRACEKIT_SIGNER_TOKEN_FILE=self.bearer_file)
        self.box = Client(f"https://127.0.0.1:{self.cfg['http']['listen'].rpartition(':')[2]}", timeout=10)
        self.addCleanup(self.box.close)

    def test_a_box_run_records_unknown_and_ext_box_never_remote(self):
        """Review 1: box runs read `remote`, which a host process holding the box's token got as well (E2)."""
        self.assertEqual(oct(os.stat(self.h).st_mode & 0o777), "0o700")
        self.assertNotIn("PRIVATE KEY", open(os.path.join(self.h, "tls", "ca.pem")).read())   # no CA key kept
        run = self.box.run("claude-code")
        self.assertEqual(run.decide("t1", "Bash", {"command": "ls"})["decision"], "allow")
        run.call("constraint_add", constraint={"kind": "no_push"})
        run.complete("t1")
        run.close()
        r = svc.reader({"data_dir": self.cfg["data_dir"]})
        self.addCleanup(r.close)
        reg = next(x["event"] for x in r.iter_range(0, len(r.log.offsets) - 1) if x["event"]["type"] == "run.registered")
        self.assertEqual((reg["data"]["signer_isolation"], reg["ext"]), ("unknown", {"box": {"token": "box-test"}}))
        self.assertEqual(box.runs(self.cfg["data_dir"]), [(run.run_id, "box")])
        self.assertEqual(box.runs(self.cfg["data_dir"], "box-other"), [])

    def test_the_box_sends_no_isolation(self):
        with self.assertRaises(RPCError) as cm:
            self.service.handle_frame(self.store.authenticate(types.SimpleNamespace(
                headers={"Authorization": "Bearer " + open(self.bearer_file).read()}, client_address=("x", 1)), {}),
                {"method": "register_run", "request_id": "r", "agent": {"name": "x"}, "signer_isolation": "separate-user"})
        self.assertEqual(cm.exception.code, "invalid_request")

    def test_you_answer_its_held_calls_on_the_socket_and_it_cannot(self):
        run = self.box.run("claude-code")
        self.assertEqual(run.decide("t1", "tracekit_demo_ask", {})["decision"], "ask")
        aid = run.call("approval_request", tool_call_id="t1")["approval_id"]
        with self.assertRaises(RPCError) as cm:
            self.box.call("approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertEqual(cm.exception.code, "forbidden")
        you = Client(self.cfg["socket"], timeout=10)
        self.addCleanup(you.close)
        self.assertFalse(you.call("approval_decide", {"approval_id": aid, "decision": "approve"})["self_approved"])
        self.assertTrue(run.approval_consume("t1", "tracekit_demo_ask", {})["ok"])
        run.complete("t1")
        run.close()


class Verify(unittest.TestCase):
    def test_the_boxed_line_says_what_it_proves_and_no_more(self):
        """Review 1: verify must say exactly what a box run proves, against the boxed agent only."""
        rep = types.SimpleNamespace(checks=[])
        rep.check = lambda name, ok, detail, problems=(), warn=False: rep.checks.append((name, ok, detail, problems))
        good = {"type": "run.registered", "ext": {"box": {"token": "box-a"}}, "seq": 1,
                "data": {"signer_isolation": "unknown", "identity": {"scheme": "token", "subject": "box-a"}}}
        v2.EXT_CHECKS["box"](rep, [good])
        [(name, ok, detail, problems)] = rep.checks
        self.assertEqual((name, ok, problems), ("boxed agent", True, []))
        self.assertTrue(detail.startswith("PROOF AGAINST THE BOXED AGENT: the signing key was outside its box (1 run"))
        self.assertIn("not proof against a process of the signer's own user", detail)
        for bad in ({**good, "data": {**good["data"], "signer_isolation": "remote"}},   # never with a wider claim
                    {**good, "ext": {"box": {"token": "box-b"}}}, {**good, "type": "tool.call"}):
            rep.checks.clear()
            v2.EXT_CHECKS["box"](rep, [bad])
            self.assertFalse(rep.checks[0][1], bad)


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Up(unittest.TestCase):
    def setUp(self):
        self.h = os.path.join(tmpdir(self), "box")
        self.project = tmpdir(self)
        patch_env(self, TRACEKIT_BOX_HOME=self.h)
        with mock.patch.object(box, "_listen_host", return_value="127.0.0.1"):
            box.setup(self.h)
        self.docker = []

    def up(self, call):
        out = []
        with mock.patch.object(box, "start"), mock.patch.object(box, "runs", return_value=[("r1", "box")]), \
                mock.patch.object(box, "image", return_value="img"), mock.patch.object(box, "build"), \
                mock.patch.object(box, "_relay", return_value=("10.0.9.2", "172.17.0.9")), \
                mock.patch.object(box, "running", return_value=set()), \
                mock.patch.object(box, "_docker", side_effect=lambda *a, **k: self.docker.append(a) or ""), \
                mock.patch.object(box.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(box.subprocess, "call", call), contextlib.redirect_stderr(io.StringIO()):
            try:
                got = box.up(self.project, None, ["stand-in-agent", "ls"], out=out.append)
            except SystemExit as e:
                got = e.code
        return got, out

    def name(self):
        return next(a[2] for a in self.docker if a[:2] == ("rm", "-f")).removeprefix("tracekit-")

    def test_the_token_is_revoked_and_the_box_stopped_when_it_exits(self):
        seen = {}

        def call(argv):
            seen.update(argv=argv, token=open(mounts(argv)[-2].split(":")[0]).read())
            return 0
        self.assertEqual(self.up(call)[0], 0)
        name = self.name()
        self.assertEqual(seen["argv"][-2:], ["stand-in-agent", "ls"])
        self.assertTrue(seen["token"].startswith(f"tk2_{name}."))
        rec = TokenStore(os.path.join(self.h, "tokens.json")).load()[name]
        self.assertIsNotNone(rec["revoked"])
        self.assertTrue(rec["box"])
        self.assertEqual(rec.get("addr"), None if sys.platform == "darwin" else "172.17.0.9")
        self.assertEqual(os.listdir(os.path.join(self.h, "boxes")), [])
        self.assertIn(("rm", "-f", f"tracekit-{name}-relay"), self.docker)
        self.assertEqual(os.listdir(self.project), [])   # the placeholders' mountpoints are gone

    @unittest.skipUnless(hasattr(signal, "SIGHUP"), "POSIX signals")
    def test_a_stopped_up_revokes_the_token_and_stops_the_box(self):
        """Review E3: `kill -TERM` (or a closed terminal) skipped the cleanup: the token stayed valid, the box ran on."""
        for sig in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(sig):
                self.docker.clear()
                before = signal.getsignal(sig)
                code, _ = self.up(lambda argv: os.kill(os.getpid(), sig) or 0)
                self.assertEqual(code, 128 + sig)
                name = self.name()
                self.assertIsNotNone(TokenStore(os.path.join(self.h, "tokens.json")).load()[name]["revoked"])
                self.assertIn(("rm", "-f", f"tracekit-{name}"), self.docker)
                self.assertEqual(signal.getsignal(sig), before)   # its handler put back

    def test_files_the_host_runs_and_a_copied_token_are_listed_at_exit(self):
        """Review 1 and 3: a token copied into the project (E2), and files the host runs, went unmentioned."""
        def call(argv):   # the box copies the file it was given at /run/tracekit/token into notes.txt
            given = mounts(argv)[-2].split(":")[0]
            os.makedirs(os.path.join(self.project, "src"))
            shutil.copyfile(given, os.path.join(self.project, "notes.txt"))
            for rel, text in (("Makefile", "all:\n"), ("src/app.py", "x = 1\n"),
                              (".pre-commit-config.yaml", "repos: []\n")):   # missing before: the box made it
                os.makedirs(os.path.dirname(os.path.join(self.project, rel)), exist_ok=True)
                with open(os.path.join(self.project, rel), "w") as f:
                    f.write(text)
            return 0
        _, out = self.up(call)
        self.assertIn("files the host may run on its own; read them before you build, test or open the project here: "
                      ".pre-commit-config.yaml, Makefile", out[0])
        self.assertNotIn("app.py", out[0])
        self.assertIn("copied its token into notes.txt; it is revoked now", out[1])

    def test_an_orphaned_token_is_revoked_at_the_next_up(self):
        store = TokenStore(os.path.join(self.h, "tokens.json"))
        store.add("box-killed", 3600, box=True)
        with mock.patch.object(box, "ORPHAN_S", -1):
            _, out = self.up(lambda argv: 0)
        self.assertIsNotNone(store.load()["box-killed"]["revoked"])
        self.assertIn("revoked box-killed's token", out[0])

    def test_options_without_isolated_are_refused(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["up", "--network"]), 2)
        self.assertIn("go with --isolated", err.getvalue())

    def test_doctor_reports_the_box_signer(self):
        with mock.patch.object(doctor.subprocess, "run", side_effect=OSError("no docker")):
            rows = {r["id"]: r for r in doctor._box()}
        self.assertEqual((rows["D-BOX-SIGNER"]["status"], rows["D-BOX-MOUNTS"]["status"]), ("warn", "warn"))
        self.assertIn("is not running", rows["D-BOX-SIGNER"]["detail"])


class Image(unittest.TestCase):
    def test_the_tag_follows_the_package_files(self):
        pkg = tmpdir(self)
        with open(os.path.join(pkg, "a.py"), "w") as f:
            f.write("x = 1\n")
        with mock.patch.object(box, "_package", return_value=pkg):
            first = box.image()
            with open(os.path.join(pkg, "b.pyc"), "w"):   # bytecode doesn't count
                pass
            self.assertEqual(box.image(), first)
            with open(os.path.join(pkg, "a.py"), "a") as f:
                f.write("y = 2\n")
            self.assertNotEqual(box.image(), first)
        self.assertRegex(first, r"^tracekit-box:[0-9.]+-[0-9a-f]{12}$")

    def test_a_missing_image_is_built_from_this_tracekit_and_an_existing_one_reused(self):
        built = {}

        def run(argv, **kw):
            if argv[:3] == ["docker", "image", "inspect"]:
                return subprocess.CompletedProcess(argv, 1 if not built else 0)
            ctx = argv[-1]
            built.update(files=sorted(os.listdir(ctx)), dockerfile=open(os.path.join(ctx, "Dockerfile")).read(),
                         reqs=open(os.path.join(ctx, "requirements.txt")).read().split("\n"),
                         box=os.path.exists(os.path.join(ctx, "tracekit", "box.py")))
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(box.subprocess, "run", run):
            box.build("tracekit-box:x", out=lambda *_: None)
            box.build("tracekit-box:x", out=self.fail)   # there now: not built again
        self.assertEqual(built["files"], ["Dockerfile", "requirements.txt", "tracekit"])
        self.assertTrue(built["box"])
        self.assertIn(f"@anthropic-ai/claude-code@{box.CLAUDE_CODE}", built["dockerfile"])
        self.assertTrue([r for r in built["reqs"] if r.startswith("rfc8785")], built["reqs"])
        self.assertFalse([r for r in built["reqs"] if "extra" in r])   # the signer's extras stay out of the box
        with mock.patch.object(box.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 1),
                                                                   subprocess.CompletedProcess([], 1, "", "no net")]), \
                self.assertRaises(box.BoxError) as cm:
            box.build("tracekit-box:y", out=lambda *_: None)
        self.assertIn("no net", str(cm.exception))

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX modes")
    def test_the_image_pins_the_signer_where_the_project_cant_move_it(self):
        """Review 4: no root-owned client config and no pinned env: a project `env` could point the hooks elsewhere."""
        root = tmpdir(self)
        box.image_setup(root)
        with open(os.path.join(root, "etc/claude-code/managed-settings.json")) as f:
            settings = json.load(f)
        self.assertEqual({k: settings["env"][k] for k in box.SIGNER_ENV}, box.SIGNER_ENV)
        with open(os.path.join(root, "etc/tracekit/client.json")) as f:
            self.assertEqual(json.load(f), {"signer": box.SIGNER_ENV["TRACEKIT_SIGNER"], "box": True,
                                            "fail_mode": "closed"})
        self.assertEqual(oct(os.stat(os.path.join(root, "etc/tracekit/client.json")).st_mode & 0o777), "0o644")
        from tracekit.sdk import client   # in the box, a TRACEKIT_SIGNER that names another signer is refused
        with mock.patch("tracekit.client.system_config", return_value={"signer": box.SIGNER_ENV["TRACEKIT_SIGNER"]}), \
                mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": "https://127.0.0.1:9"}), \
                self.assertRaises(client.SignerUnavailable):
            client._default_signer()


class Relay(unittest.TestCase):
    def test_it_forwards_bytes_both_ways(self):
        """Review 6: the box's only way out is this relay to the signer's port."""
        upstream = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(upstream.close)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        threading.Thread(target=box.relay, args=(port, "127.0.0.1", upstream.getsockname()[1], "127.0.0.1"),
                         daemon=True).start()
        for _ in range(100):
            with contextlib.suppress(OSError):
                c = socket.create_connection(("127.0.0.1", port), 1)
                break
            threading.Event().wait(0.05)
        self.addCleanup(c.close)
        u, _ = upstream.accept()
        self.addCleanup(u.close)
        c.sendall(b"hello")
        self.assertEqual(u.recv(5), b"hello")
        u.sendall(b"back")
        self.assertEqual(c.recv(4), b"back")


@unittest.skipUnless(os.name == "posix", "the stand-in's hooks are shell commands")
class StandIn(unittest.TestCase):
    def test_each_call_goes_through_the_hooks_with_their_env_and_a_blocked_one_does_not_run(self):
        d = tmpdir(self)
        log = os.path.join(d, "log")
        hook = (f"{sys.executable} -c \"import json, os, sys; p = json.load(sys.stdin); open({log!r}, 'a').write("
                f"p['hook_event_name'] + ' ' + p.get('tool_input', {{}}).get('command', '') + ' ' + "
                f"os.environ.get('PINNED', '') + '\\\\n'); "
                f"sys.exit(2 if 'blocked' in p.get('tool_input', {{}}).get('command', '') else 0)\"")
        settings = os.path.join(d, "managed-settings.json")
        with open(settings, "w") as f:
            json.dump({"env": {"PINNED": "yes"}, "hooks": {e: [{"matcher": "*", "hooks": [{"type": "command",
                                                                                          "command": hook}]}]
                       for e in ("SessionStart", "PreToolUse", "PostToolUse", "SessionEnd")}}, f)
        with mock.patch.object(box, "SETTINGS", settings), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = box.stand_in([f"echo ran > {d}/ran", "echo blocked > /dev/null"])
        self.assertEqual(code, 2)
        with open(log) as f:
            self.assertEqual(f.read().splitlines(), [
                "SessionStart  yes", f"PreToolUse echo ran > {d}/ran yes", f"PostToolUse echo ran > {d}/ran yes",
                "PreToolUse echo blocked > /dev/null yes", "SessionEnd  yes"])
        self.assertTrue(os.path.exists(os.path.join(d, "ran")))


@unittest.skipIf(NO_DOCKER, NO_DOCKER)
@unittest.skipUnless(sys.platform in ("darwin", "linux"), "the box: macOS and Linux")
class BoxInDocker(unittest.TestCase):
    """Builds the box image on its first `up` (a few minutes once), as a person's first `up --isolated` does."""

    def setUp(self):
        self.h, self.project = (os.path.join(tmpdir(self, under_home=True), n) for n in ("box", "project"))
        os.makedirs(os.path.join(self.project, ".git", "hooks"))
        shutil.copy(os.path.join(ROOT, "tests", "box_probe.py"), self.project)
        patch_env(self, TRACEKIT_BOX_HOME=self.h, PYTHONPATH=ROOT)   # the box signer runs this checkout
        self.addCleanup(self.stop)

    def stop(self):
        with contextlib.suppress(OSError, ValueError, TypeError):
            hello = box._hello(svc.load_config(os.path.join(self.h, "signer.yaml"))["socket"])
            os.kill(hello["pid"], signal.SIGTERM)

    def up(self, *cmd, network=()):
        return subprocess.run([sys.executable, "-m", "tracekit", "up", "--isolated", *network, "--project",
                               self.project, "--", *cmd], capture_output=True, text=True, timeout=900,
                              stdin=subprocess.DEVNULL)

    def started(self, *cmd):
        """`up` running `cmd`, once its box runs; (the process, the box's name)."""
        proc = subprocess.Popen([sys.executable, "-m", "tracekit", "up", "--isolated", "--project", self.project, "--",
                                 *cmd], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        self.addCleanup(proc.kill)
        for _ in range(9000):   # the first `up` builds the image
            if names := box.running():
                return proc, names.pop()
            if proc.poll() is not None:
                self.fail(proc.communicate())
            threading.Event().wait(0.1)
        self.fail("no box started")

    def test_a_stopped_up_revokes_the_token_and_stops_the_box(self):
        """Review E3, live: `kill -TERM <up>` left the token valid for 12 h and the box running."""
        proc, name = self.started("sleep", "600")
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM)
        self.assertNotIn(name, box.running())
        tokens = TokenStore(svc.load_config(os.path.join(self.h, "signer.yaml"))["http"]["tokens"]).load()
        self.assertIsNotNone(tokens[name]["revoked"])

    def test_a_token_the_box_copies_out_proves_nothing_more_and_is_reported(self):
        """Review E2, live: the box copied its token into the project; a host process used it and got `remote`."""
        proc, name = self.started("sh", "-c", "cp /run/tracekit/token /work/.tok && sleep 20")
        cfg = svc.load_config(os.path.join(self.h, "signer.yaml"))
        for _ in range(100):
            if os.path.exists(os.path.join(self.project, ".tok")):
                break
            threading.Event().wait(0.1)
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_CA": os.path.join(self.h, "tls", "ca.pem")}):
            host = Client(f"https://{cfg['http']['listen']}", timeout=10, token_file=os.path.join(self.project, ".tok"))
            try:
                host.run("from-the-host").close()
            except RPCError as e:   # Linux: the token is taken only from its relay's address
                self.assertEqual((sys.platform, e.code), ("linux", "unauthenticated"))
            finally:
                host.close()
        out, _ = proc.communicate(timeout=120)
        self.assertNotIn("remote", [iso for _, iso in box.runs(cfg["data_dir"])])
        self.assertIn("the box copied its token into .tok; it is revoked now", out)

    def test_the_hooks_reach_the_signer_and_nothing_else_does(self):
        p = self.up("stand-in-agent", "echo from-the-box > made.txt", "touch .git/hooks/pre-commit",
                    "mkdir .claude/x")
        print(p.stdout + p.stderr)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)   # the touch and mkdir: .git, .claude are read-only
        self.assertEqual(p.stderr.count("Read-only file system"), 2, p.stderr)
        self.assertEqual(os.listdir(os.path.join(self.project, ".git", "hooks")), [])
        self.assertFalse(os.path.exists(os.path.join(self.project, ".claude")))   # its placeholder's mountpoint went
        with open(os.path.join(self.project, "made.txt")) as f:
            self.assertEqual(f.read(), "from-the-box\n")
        path = os.path.join(self.h, "signer.yaml")
        cfg = svc.load_config(path)
        [(run_id, isolation)] = box.runs(cfg["data_dir"])
        self.assertEqual(isolation, "box")
        self.assertIn(f"{run_id} (isolation box)", p.stdout)

        hello = box._hello(cfg["socket"])
        p = self.up("/opt/tracekit/bin/python", "/work/box_probe.py", cfg["data_dir"],
                    os.path.expanduser("~/.colima/default/docker.sock"))
        print(p.stdout + p.stderr)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(p.stdout.count(": refused ("), 10, p.stdout)
        self.assertEqual(box._hello(cfg["socket"])["pid"], hello["pid"])   # still running

        d = tmpdir(self)
        tkb, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["export", "--v2", "--config", path, "--run", run_id, "-o", tkb]), 0)
            self.assertEqual(svc.main(["trust", "--config", path, "-o", trust]), 0)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["verify", tkb, "--trust", trust]), 0, out.getvalue())
        print(out.getvalue())
        self.assertIn(v2.BOXED, out.getvalue())
        self.assertNotRegex(out.getvalue(), r"isolation.*remote")
        rows = {r["id"]: r for r in doctor._box()}
        self.assertIn(f"{run_id}, recorded isolation box", rows["D-BOX-SIGNER"]["detail"])
        self.assertEqual((rows["D-BOX-MOUNTS"]["status"], rows["D-BOX-TOKENS"]["status"]), ("ok", "ok"))
