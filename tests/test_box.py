"""`tracekit up --isolated` (tracekit/box.py, docs/design/isolated-up.md): the box gets the project, its token and the
signer's CA certificate only; a project dir that holds your home or a signer's files is refused; the box signer's own
config serves the hooks over TLS, records their runs `remote` and lets them answer no approval; the token is revoked
when the box exits; doctor flags a box container with the Docker socket, your home or root. BoxInDocker runs the
stand-in agent and tests/box_probe.py in a real box (Docker only: skipped without a reachable daemon; on a Mac with
colima set DOCKER_CONTEXT=colima)."""
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tmpdir(case, under_home=False):
    """A temp dir; `under_home`: in your home, the only part of a Mac colima mounts into its VM."""
    d = tempfile.mkdtemp(prefix=".tk-box-test-" if under_home else "tk-box-",
                         dir=os.path.expanduser("~") if under_home else "/tmp" if os.name == "posix" else None)
    case.addCleanup(shutil.rmtree, d, True)
    return d


def mounts(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Argv(unittest.TestCase):
    def setUp(self):
        self.project = tmpdir(self)

    def test_the_box_gets_the_project_its_token_and_the_ca_only(self):
        a = box.argv("box-1", self.project, "/h/boxes/box-1/token", "/h/tls/ca.pem", "8443", "img", linux=False)
        self.assertEqual(mounts(a), [f"{self.project}:/work", "/h/boxes/box-1/token:/run/tracekit/token:ro",
                                     "/h/tls/ca.pem:/run/tracekit/ca.pem:ro"])
        for flag in (["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--pull", "never"],
                     ["--user", f"{os.getuid()}:{os.getgid()}"], ["-e", "TRACEKIT_SIGNER=https://host.docker.internal:8443"],
                     ["--label", "tracekit.box=box-1"]):
            self.assertIn(flag, [a[i:i + 2] for i in range(len(a))])
        self.assertNotIn("--add-host", a)   # colima and Docker Desktop name the host themselves
        self.assertNotIn("--privileged", a)
        self.assertFalse([x for x in a if "docker.sock" in x])
        self.assertEqual(a[-1], "img")
        linux = box.argv("box-1", self.project, "t", "c", "8443", "img", ["stand-in-agent", "ls"], linux=True)
        self.assertIn("host.docker.internal:host-gateway", linux)
        self.assertEqual(linux[-3:], ["img", "stand-in-agent", "ls"])

    def test_git_and_claude_dirs_are_read_only_and_a_symlinked_one_is_not_followed(self):
        os.mkdir(os.path.join(self.project, ".git"))
        with open(os.path.join(self.project, ".claude"), "w"):   # a file is protected as well as a dir
            pass
        ro = mounts(box.argv("box-1", self.project, "t", "c", "1", "i", linux=False))[1:3]
        self.assertEqual(ro, [f"{self.project}/.git:/work/.git:ro", f"{self.project}/.claude:/work/.claude:ro"])
        os.remove(os.path.join(self.project, ".claude"))
        os.symlink(os.path.expanduser("~"), os.path.join(self.project, ".claude"))   # docker would mount its target
        self.assertNotIn(f"{self.project}/.claude:/work/.claude:ro", mounts(box.argv("b", self.project, "t", "c", "1", "i")))


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Project(unittest.TestCase):
    def test_a_project_holding_your_home_or_a_signers_files_is_refused(self):
        h = os.path.join(tmpdir(self), "a", "box")
        for project in ("/", os.path.expanduser("~"), os.path.dirname(os.path.expanduser("~")), os.path.dirname(h),
                        os.path.dirname(autospawn.data_dir()), h):
            with self.subTest(project), self.assertRaises(box.BoxError):
                box.check_project(project, h)
        inside = os.path.join(os.path.dirname(h), "project")
        self.assertEqual(box.check_project(inside, h), os.path.realpath(inside))


class Problems(unittest.TestCase):
    H = "/h/box"

    def container(self, **over):
        c = {"Name": "/tracekit-box-1", "Config": {"User": "501:20"},
             "HostConfig": {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]},
             "Mounts": [{"Source": "/src/project", "Destination": "/work", "RW": True},
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
        home = os.path.expanduser("~")
        for over, want in (
                ({"Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]}, "Docker socket"),
                ({"Mounts": [{"Source": "/var/run", "Destination": "/x"}]}, "Docker socket"),
                ({"Mounts": [{"Source": home, "Destination": "/work"}]}, "your home"),
                ({"Mounts": [{"Source": f"{self.H}/data", "Destination": "/d"}]}, "a signer's file"),
                ({"Mounts": [{"Source": f"{self.H}/boxes/box-1/token", "Destination": "/run/tracekit/token",
                              "RW": True}]}, "a signer's file"),
                ({"Mounts": [{"Source": f"{self.H}/tokens.json", "Destination": "/run/tracekit/ca.pem"}]},
                 "a signer's file"),
                ({"Config": {"User": ""}}, "runs as root"), ({"HostConfig": {"Privileged": True}}, "privileged"),
                ({"HostConfig": {"CapDrop": []}}, "capabilities not dropped"),
                ({"HostConfig": {"SecurityOpt": []}}, "new privileges allowed"),
                ({"HostConfig": {"PidMode": "host"}}, "the host's pid namespace")):
            with self.subTest(want=want, over=over):
                self.assertTrue([p for p in self.problems(**over) if want in p], self.problems(**over))


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
        token = TokenStore(self.cfg["http"]["tokens"]).add("box-test", box.TTL_S)
        self.token_file = os.path.join(self.h, "token")
        with open(self.token_file, "w") as f:
            f.write(token)
        patch_env(self, TRACEKIT_SIGNER_CA=os.path.join(self.h, "tls", "ca.pem"),
                  TRACEKIT_SIGNER_TOKEN_FILE=self.token_file)
        self.box = Client(f"https://127.0.0.1:{self.cfg['http']['listen'].rpartition(':')[2]}", timeout=10)
        self.addCleanup(self.box.close)

    def test_the_hooks_run_over_tls_and_their_runs_record_remote(self):
        self.assertEqual(oct(os.stat(self.h).st_mode & 0o777), "0o700")
        self.assertNotIn("PRIVATE KEY", open(os.path.join(self.h, "tls", "ca.pem")).read())   # no CA key kept
        self.assertEqual(sorted(os.listdir(os.path.join(self.h, "tls"))), ["ca.pem", "server.key", "server.pem"])
        run = self.box.run("claude-code")
        d = run.decide("t1", "Bash", {"command": "ls"})
        self.assertEqual(d["decision"], "allow")
        run.call("constraint_add", constraint={"kind": "no_push"})
        run.complete("t1")
        run.close()
        self.assertEqual(box.runs(self.cfg["data_dir"]), [(run.run_id, "remote")])
        self.assertEqual(box.runs(self.cfg["data_dir"], "box-other"), [])

    def test_the_box_sends_no_isolation(self):
        with self.assertRaises(RPCError) as cm:
            self.service.handle_frame(TokenStore(self.cfg["http"]["tokens"]).authenticate(
                type("C", (), {"headers": {"Authorization": "Bearer " + open(self.token_file).read()}})(), {}),
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


@unittest.skipUnless(hasattr(os, "getuid"), "the box runs as your uid: macOS and Linux")
class Up(unittest.TestCase):
    def setUp(self):
        self.h = os.path.join(tmpdir(self), "box")
        self.project = tmpdir(self)
        patch_env(self, TRACEKIT_BOX_HOME=self.h)
        with mock.patch.object(box, "_listen_host", return_value="127.0.0.1"):
            box.setup(self.h)

    def up(self, code=0):
        seen = {}

        def call(argv):
            seen["argv"] = argv
            seen["token"] = open(mounts(argv)[1].split(":")[0]).read()
            return code
        out = io.StringIO()
        with mock.patch.object(box, "start"), mock.patch.object(box, "runs", return_value=[("r1", "remote")]), \
                mock.patch.object(box, "image", return_value="img"), mock.patch.object(box, "build") as build, \
                mock.patch.object(box.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(box.subprocess, "call", call), contextlib.redirect_stderr(out):
            got = cli.main(["up", "--isolated", "--project", self.project, "--", "stand-in-agent", "ls"])
        build.assert_called_once_with("img", print)
        return got, seen, out.getvalue()

    def test_the_token_is_revoked_and_removed_when_the_box_exits(self):
        code, seen, _ = self.up()
        self.assertEqual(code, 0)
        self.assertEqual(seen["argv"][-2:], ["stand-in-agent", "ls"])
        name = seen["argv"][seen["argv"].index("--name") + 1].removeprefix("tracekit-")
        rec = TokenStore(os.path.join(self.h, "tokens.json")).load()[name]
        self.assertIsNotNone(rec["revoked"])
        self.assertTrue(seen["token"].startswith(f"tk2_{name}."))
        self.assertEqual(os.listdir(os.path.join(self.h, "boxes")), [])


    def test_options_without_isolated_are_refused(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["up", "--project", self.project]), 2)
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


@unittest.skipUnless(os.name == "posix", "the stand-in's hooks are shell commands")
class StandIn(unittest.TestCase):
    def test_each_call_goes_through_the_hooks_and_a_blocked_one_does_not_run(self):
        d = tmpdir(self)
        log = os.path.join(d, "log")
        hook = (f"{sys.executable} -c \"import json, sys; p = json.load(sys.stdin); open({log!r}, 'a').write("
                f"p['hook_event_name'] + ' ' + p.get('tool_input', {{}}).get('command', '') + '\\\\n'); "
                f"sys.exit(2 if 'blocked' in p.get('tool_input', {{}}).get('command', '') else 0)\"")
        settings = os.path.join(d, "managed-settings.json")
        with open(settings, "w") as f:
            json.dump({"hooks": {e: [{"matcher": "*", "hooks": [{"type": "command", "command": hook}]}]
                                 for e in ("SessionStart", "PreToolUse", "PostToolUse", "SessionEnd")}}, f)
        with mock.patch.object(box, "SETTINGS", settings), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = box.stand_in([f"echo ran > {d}/ran", "echo blocked > /dev/null"])
        self.assertEqual(code, 2)
        with open(log) as f:
            self.assertEqual(f.read().splitlines(), [
                "SessionStart ", f"PreToolUse echo ran > {d}/ran", f"PostToolUse echo ran > {d}/ran",
                "PreToolUse echo blocked > /dev/null", "SessionEnd "])
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
        with contextlib.suppress(OSError, ValueError):
            hello = box._hello(svc.load_config(os.path.join(self.h, "signer.yaml"))["socket"])
            os.kill(hello["pid"], signal.SIGTERM)

    def up(self, *cmd):
        return subprocess.run([sys.executable, "-m", "tracekit", "up", "--isolated", "--project", self.project, "--",
                               *cmd], capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)

    def test_the_hooks_reach_the_signer_and_nothing_else_does(self):
        p = self.up("stand-in-agent", "echo from-the-box > made.txt", "touch .git/hooks/pre-commit")
        print(p.stdout + p.stderr)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)   # the touch: .git is read-only
        self.assertIn("Read-only file system", p.stderr)
        self.assertEqual(os.listdir(os.path.join(self.project, ".git", "hooks")), [])
        with open(os.path.join(self.project, "made.txt")) as f:
            self.assertEqual(f.read(), "from-the-box\n")
        path = os.path.join(self.h, "signer.yaml")
        cfg = svc.load_config(path)
        [(run_id, isolation)] = box.runs(cfg["data_dir"])
        self.assertEqual(isolation, "remote")
        self.assertIn(f"{run_id} (isolation remote)", p.stdout)

        hello = box._hello(cfg["socket"])
        p = self.up("/opt/tracekit/bin/python", "/work/box_probe.py", cfg["data_dir"],
                    os.path.expanduser("~/.colima/default/docker.sock"))
        print(p.stdout + p.stderr)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(p.stdout.count(": refused ("), 8, p.stdout)
        self.assertEqual(box._hello(cfg["socket"])["pid"], hello["pid"])   # still running

        d = tmpdir(self)
        tkb, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["export", "--v2", "--config", path, "--run", run_id, "-o", tkb]), 0)
            self.assertEqual(svc.main(["trust", "--config", path, "-o", trust]), 0)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["verify", tkb, "--trust", trust]), 0, out.getvalue())
        print(out.getvalue())
        self.assertRegex(out.getvalue(), r"isolation.*signer-reported: remote 1 run")
        rows = {r["id"]: r for r in doctor._box()}
        self.assertIn(f"{run_id}, recorded isolation remote", rows["D-BOX-SIGNER"]["detail"])
        self.assertEqual(rows["D-BOX-MOUNTS"]["status"], "ok")
