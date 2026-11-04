"""`tracekit up --isolated [--network] [--image IMAGE] [--project DIR] [-- COMMAND ...]` (experimental): the coding
agent in a container, the signer outside it (docs/design/isolated-up.md).

The box image (image()) is built on first use from DOCKERFILE: Claude Code (CLAUDE_CODE) and this Tracekit, the
hooks' client. image_setup() puts Tracekit's v2 hooks in Claude Code's managed settings, with the signer's variables
pinned in their `env`, and a root-owned /etc/tracekit/client.json naming the signer (`box`: the hook keeps its own
tailer), so neither a project setting nor the agent can point the hooks elsewhere. Its tag names this Tracekit's
version and a hash of its files. Its default command is `claude`; `stand-in-agent CMD ...` (stand_in) runs Bash calls
through the same hooks as Claude Code would, for a box without a Claude Code login.

The box signer is a v2 signer of its own, run as you from home() (`<dev data dir>-box`, or $TRACEKIT_BOX_HOME):
signer.yaml, its keys and store under data/, its TLS key under tls/, tokens.json. The dev signer is not touched. Each
box gets a token of its own (`box`, identity token:box-<id>, TTL_S), revoked when `up` exits, is stopped (SIGTERM,
SIGHUP) or, killed outright, by the next `up` (orphans). The container gets the project at /work, that token and the
signer's CA certificate, read-only, and nothing else of the host: no signer data, keys or socket, no Docker socket, no
home. It runs as your uid with every capability dropped, no new privileges and pids and memory limits. What the host
runs from the project on its own (host_run: git's and the hook frameworks' configs, every coding agent's project config
Tracekit knows, editor tasks) is read-only; `.git` and `.claude` always, an empty placeholder where one is missing; a
symlink among them stops `up`. When the box exits, `up` lists the files it changed that the host may run.

The box is on an internal Docker network (NETWORK): no internet, none of the host's services, only its relay, a
container of the same image that forwards RELAY_PORT to the signer's HTTPS listener (colima and Docker Desktop forward
host.docker.internal to the host's loopback; on Linux the signer listens on the default bridge, and the box's token is
taken only from its relay's address). `--network` also puts the box on Docker's default bridge: the internet, and on a
Mac every service on the host's 127.0.0.1.

The signer records a box run's isolation as `unknown` (any process of its user can hold the token too) with a signed
ext.box naming the token: verifiers say what it proves, BOXED (tracekit.verify.v2), never more.
"""
import contextlib
import datetime
import hashlib
import importlib.metadata
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings

from tracekit import __version__
from tracekit.deploy import files
from tracekit.identity.token import TokenStore
from tracekit.sdk import autospawn

CLAUDE_CODE = "2.1.305"   # pinned: published 2026-10-20
# node:22.20.0-bookworm-slim (multi-arch index), pinned by digest; Debian's python3 runs the hooks
DOCKERFILE = f"""FROM node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/home/agent
COPY requirements.txt /tmp/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates \\
 && rm -rf /var/lib/apt/lists/* \\
 && python3 -m venv /opt/tracekit && /opt/tracekit/bin/pip install --no-cache-dir -r /tmp/requirements.txt \\
 && npm install -g --no-audit --no-fund @anthropic-ai/claude-code@{CLAUDE_CODE} && npm cache clean --force \\
 && install -d -m 1777 /home/agent
COPY tracekit /opt/tracekit/src/tracekit
RUN /opt/tracekit/bin/python -c "import site; open(site.getsitepackages()[0] + '/tracekit.pth', 'w').write('/opt/tracekit/src')" \\
 && /opt/tracekit/bin/python -I -c "from tracekit import box; box.image_setup()"
WORKDIR /work
USER 1000:1000
CMD ["claude"]
"""
PYTHON = "/opt/tracekit/bin/python"   # the image's
SETTINGS = "/etc/claude-code/managed-settings.json"
HOST = "host.docker.internal"
RELAY_PORT = 8443   # the signer's port inside the box: its relay's
SIGNER_ENV = {"TRACEKIT_SIGNER": f"https://{HOST}:{RELAY_PORT}", "TRACEKIT_SIGNER_TOKEN_FILE": "/run/tracekit/token",
              "TRACEKIT_SIGNER_CA": "/run/tracekit/ca.pem"}
NETWORK = "tracekit-box"
LABEL = "tracekit.box"
LIMITS = ["--pids-limit", "1024", "--memory", "2g"]
# lean: a box past 12 h loses its token, and its hooks then block every call; renew it while the box runs once
# sessions last longer
TTL_S = 12 * 3600
START_S = 20
ORPHAN_S = 60   # a box token this old with no box running is revoked: younger, its `up` may be starting the box
# what a coding-agent hook calls (docs/deploy.md#compose); not approval_decide: the box can't answer its own holds
GRANTS = ("register_run", "decide", "approval_consume", "complete", "close_run", "model_event", "approval_request",
          "approval_wait", "state_write", "status", "observe", "constraint_add", "approval_get")
# project paths the host runs on its own, beside every coding agent's project config (host_run): git's hooks and
# config, Claude Code's settings, the hook frameworks' configs (husky, pre-commit, lefthook), MCP servers, editor tasks
HOST_RUN = (".git", ".claude", ".husky", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml",
            ".lefthook.yaml", "lefthook-local.yml", ".mcp.json", ".vscode", ".idea", ".kilocode")
PLACEHOLDER = (".git", ".claude")   # mounted read-only even when missing, so the box can't create one
# files the host may run without being asked to (a build, a test run, a shell entering the dir): listed when changed
RUNS = {"Makefile", "makefile", "GNUmakefile", "package.json", "setup.py", "setup.cfg", "pyproject.toml", "conftest.py",
        "noxfile.py", "tox.ini", "Justfile", "justfile", "Taskfile.yml", ".envrc", ".gitattributes", ".gitmodules",
        "Dockerfile", "compose.yaml", "docker-compose.yml", ".npmrc", ".yarnrc.yml", "build.gradle", "pom.xml"}
SENSITIVE = (".ssh", ".aws", ".claude", ".claude.json", ".colima", ".docker", ".kube", ".gnupg", ".config/gcloud",
             ".netrc")   # in your home: never in a box
SNAPSHOT_MAX = 500_000   # lean: files compared for the exit list; past it, the rest aren't listed


class BoxError(Exception):
    pass


def home():
    return os.environ.get("TRACEKIT_BOX_HOME") or autospawn.data_dir() + "-box"


def _package():
    return os.path.dirname(os.path.abspath(__file__))


def image():
    """The box image's tag: this Tracekit's version and a hash of its files (DOCKERFILE is one of them)."""
    h = hashlib.sha256()
    for d, dirs, names in sorted(os.walk(_package())):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for n in sorted(names):
            if not n.endswith(".pyc"):
                with open(os.path.join(d, n), "rb") as f:
                    h.update(os.path.relpath(os.path.join(d, n), _package()).encode() + b"\0" + f.read())
    return f"tracekit-box:{__version__}-{h.hexdigest()[:12]}"


def build(tag, out=print):
    """Build image `tag` from DOCKERFILE unless Docker has it; BoxError when the build fails."""
    if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode == 0:
        return
    out(f"tracekit: building the box image {tag}: Claude Code {CLAUDE_CODE} and this Tracekit (once; a minute or two)")
    sys.stdout.flush()
    # the installed distribution's dependencies; extras are the signer's, not the hooks'
    reqs = [r for r in importlib.metadata.requires("tracekit-ai") or () if "extra ==" not in r]
    with tempfile.TemporaryDirectory() as ctx:
        shutil.copytree(_package(), os.path.join(ctx, "tracekit"), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name, text in (("Dockerfile", DOCKERFILE), ("requirements.txt", "\n".join(reqs) + "\n")):
            with open(os.path.join(ctx, name), "w", encoding="utf-8") as f:
                f.write(text)
        p = subprocess.run(["docker", "build", "-q", "-t", tag, ctx], capture_output=True, text=True)
    if p.returncode:
        raise BoxError(f"the box image did not build:\n{(p.stdout + p.stderr)[-2000:]}")


def image_setup(root="/"):
    """As root, in the image (DOCKERFILE): the managed settings' hooks with the signer's variables pinned, the
    root-owned client config naming the signer, and the stand-in-agent command. `root`: a test's stand-in for /."""
    from tracekit import install
    at = lambda p: os.path.join(root, p.lstrip("/"))   # noqa: E731
    install.install_hooks(at(SETTINGS), module=install.V2_HOOK, python=PYTHON, mode=0o644, signer=SIGNER_ENV)
    for d in ("/etc/tracekit", "/usr/local/bin"):
        os.makedirs(at(d), 0o755, exist_ok=True)
    for path, text, mode in ((at("/etc/tracekit/client.json"), json.dumps(
            {"signer": SIGNER_ENV["TRACEKIT_SIGNER"], "box": True, "fail_mode": "closed"}), 0o644),
            (at("/usr/local/bin/stand-in-agent"), f'#!/bin/sh\nexec {PYTHON} -I -m tracekit.box "$@"\n', 0o755)):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, mode)


def stand_in(commands):
    """A stand-in for Claude Code in the box: runs each of `commands` as a Bash tool call through the hooks in Claude
    Code's managed settings, with their `env`, as Claude Code runs them (SessionStart; per call PreToolUse, the command
    if the hooks let it through, PostToolUse; SessionEnd). The worst exit code: 2 when a hook blocked a call."""
    with open(SETTINGS, encoding="utf-8") as f:
        settings = json.load(f)
    hooks, env, session = settings["hooks"], {**os.environ, **settings.get("env", {})}, str(uuid.uuid4())

    def hook(event, **fields):
        payload = json.dumps({"hook_event_name": event, "session_id": session, "cwd": os.getcwd(), **fields})
        for h in (h for g in hooks.get(event, ()) for h in g["hooks"]):
            if code := subprocess.run(h["command"], shell=True, input=payload, text=True, env=env).returncode:
                return code
        return 0
    hook("SessionStart", source="startup")
    worst = 0
    for i, command in enumerate(commands):
        call = {"tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": f"toolu_standin_{i}"}
        if hook("PreToolUse", **call):
            print(f"stand-in-agent: blocked: {command}", file=sys.stderr)
            worst = 2
            continue
        p = subprocess.run(command, shell=True, capture_output=True, text=True)
        sys.stdout.write(p.stdout)
        sys.stderr.write(p.stderr)
        hook("PostToolUse", **call, tool_response={"stdout": p.stdout[-4000:], "stderr": p.stderr[-4000:],
                                                   "exit_code": p.returncode})
        worst = worst or p.returncode
    hook("SessionEnd", reason="exit")
    return worst


def relay(port, host, to_port, bind="0.0.0.0"):
    """The box's relay (a container of the box image): each connection to `port` here is forwarded to `host`:`to_port`,
    the signer's TLS listener; the bytes go through unread."""
    def pipe(a, b):
        with contextlib.suppress(OSError):
            while data := a.recv(65536):
                b.sendall(data)
        for s in (a, b):
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)
    srv = socket.create_server((bind, port))
    while True:
        c, _ = srv.accept()
        try:
            u = socket.create_connection((host, to_port), 10)
        except OSError:
            c.close()
            continue
        for a, b in ((c, u), (u, c)):
            threading.Thread(target=pipe, args=(a, b), daemon=True).start()


def _docker(*args, check=True):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if check and p.returncode:
        raise BoxError(f"docker {args[0]}: {(p.stderr or p.stdout).strip()[-500:]}")
    return p.stdout.strip()


def _listen_host():
    """Where the relay reaches the host: its loopback on a Mac (colima and Docker Desktop forward host.docker.internal
    to it), the default bridge's gateway on Linux."""
    if sys.platform == "darwin":
        return "127.0.0.1"
    out = _docker("network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}", check=False)
    try:
        return str(ipaddress.ip_address(out))
    except ValueError:
        raise BoxError(f"no Docker bridge gateway to listen on: {out}") from None


def _tls(d, host):
    """A CA certificate (ca.pem, for the box) and the server key and certificate it signed (server.key, server.pem),
    naming host.docker.internal and `host`. The CA key is not kept: nothing else is ever signed with it.
    lean: ten years, never rotated; delete tls/ and signer.yaml to make new ones"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())

    def cert(name, public, ca):
        usage = dict.fromkeys(("content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
                               "encipher_only", "decipher_only"), False)
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tracekit box CA")]))
             .public_key(public).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=3650))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=not ca, key_cert_sign=ca, crl_sign=ca, **usage), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
        if not ca:
            b = (b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                 .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST), x509.IPAddress(ipaddress.ip_address(host))]),
                                critical=False))
        return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    files.write(d, "ca.pem", cert("tracekit box CA", ca_key.public_key(), True), 0o644)
    files.write(d, "server.pem", cert(HOST, key.public_key(), False), 0o644)
    files.write(d, "server.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))


def setup(h):
    """signer.yaml of the box signer in `h`, written with its TLS files and an empty dir (placeholders' source) the
    first time; its path."""
    path = os.path.join(h, "signer.yaml")
    if os.path.exists(path):
        return path
    host = _listen_host()
    with socket.socket(socket.AF_INET) as s:   # lean: a free port now, fixed from then on; a taken one stops the start
        s.bind((host, 0))
        port = s.getsockname()[1]
    os.makedirs(h, 0o700, exist_ok=True)
    d = files.open_dir(h)
    try:
        for sub in ("tls", "empty"):
            t = files.subdir(d, sub, 0o700 if sub == "tls" else 0o755)
            try:
                if sub == "tls":
                    _tls(t, host)
            finally:
                files.close(t)
        sock = os.path.join(autospawn._private(autospawn._short(h), True), autospawn.SOCK)   # macOS caps socket paths
        files.write(d, "signer.yaml", f"""# Written by `tracekit up --isolated` (docs/design/isolated-up.md). Keys: tracekit/signer/service.py.
data_dir: data
socket: {json.dumps(sock)}   # you, as your uid: approvals, status
http:
  listen: {host}:{port}
  cert: tls/server.pem
  key: tls/server.key
  authenticators: [token]
  tokens: tokens.json         # one token per box, revoked when it exits
authorize: {{"token:*": [{", ".join(GRANTS)}]}}
approvals: {{approvers: ["uid:{os.getuid()}"]}}   # you answer the box's held calls
""".encode())
    finally:
        files.close(d)
    return path


def _hello(sock):
    """The hello of the signer at `sock`, None when none answers; its version is the box hooks' to tell you about."""
    from tracekit.sdk.client import Incompatible, SignerUnavailable, connect
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s, _, hello = connect(sock)
    except (SignerUnavailable, Incompatible, OSError):
        return None
    s.close()
    return hello


def start(path, cfg):
    """Start the box signer of config `path` (loaded: `cfg`) unless it answers; its hello.
    lean: it runs until stopped (kill the pid its hello names) and isn't replaced after an upgrade; a `down` for it
    when people keep one running across upgrades"""
    hello = _hello(cfg["socket"])
    if hello:
        return hello
    h = os.path.dirname(path)
    with open(os.path.join(h, "signer.log"), "ab") as log:
        p = subprocess.Popen([*autospawn.PYTHON, "-m", "tracekit", "signer", "serve", "--config", path],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=h, start_new_session=True,
                             env={k: v for k, v in os.environ.items() if k in autospawn._ENV}, umask=0o077)
    deadline = time.monotonic() + START_S
    while time.monotonic() < deadline and p.poll() is None:
        if hello := _hello(cfg["socket"]):
            return hello
        time.sleep(0.1)
    raise BoxError(f"the box signer did not start; see {os.path.join(h, 'signer.log')}")


def host_run(project):
    """The paths under `project` the host runs on its own: HOST_RUN and each coding agent's project config
    (agent_hooks.config_path, the one list of them)."""
    from tracekit import agent_hooks
    return sorted(set(HOST_RUN) | {os.path.relpath(agent_hooks.config_path(a, project), project).split(os.sep)[0]
                                   for a in agent_hooks.HARNESSES})


def _under(path, d):
    return path == d or path.startswith(d.rstrip(os.sep) + os.sep)


def check_project(project, h):
    """The project's real path; BoxError for one that holds your home or a signer's files, or is inside a signer's
    dir (mounted, the box would reach them), or one with a symlink where the host runs a file (host_run): it would
    take the box out of the project, or a placeholder couldn't cover it."""
    p = os.path.realpath(project)
    for what, path in (("your home", os.path.expanduser("~")), ("the box signer's files", h),
                       ("the dev signer's data", autospawn.data_dir())):
        r = os.path.realpath(path)
        if _under(r, p):
            raise BoxError(f"{project} holds {what} ({path}): the box would reach it; run it on a project dir below")
        if what != "your home" and _under(p, r):
            raise BoxError(f"{project} is inside {what} ({path}): the box would reach them; run it on another dir")
    if ":" in p:   # lean: -v splits on it; --mount when a project path needs one
        raise BoxError(f"{project}: a project path with ':' can't be mounted")
    links = [n for n in host_run(p) if os.path.islink(os.path.join(p, n))]
    if links:
        raise BoxError(f"{', '.join(links)} in {project} {'is a symlink' if len(links) == 1 else 'are symlinks'}: the "
                       "host runs what they point at, which the box can't be kept from; replace them with the files")
    return p


def argv(name, project, image, relay_ip, empty, cmd=(), tty=False, network=False):
    """The `docker run` of box `name`: the project with what the host runs read-only (an `empty` placeholder for a
    missing .git or .claude), its token and the CA certificate; on the internal network, its relay as the signer."""
    box = os.path.join(home(), "boxes", name)
    ro = []
    for n in host_run(project):
        if os.path.exists(os.path.join(project, n)):
            ro += ["-v", f"{os.path.join(project, n)}:/work/{n}:ro"]
        elif n in PLACEHOLDER:
            ro += ["-v", f"{empty}:/work/{n}:ro"]
    return ["docker", "run", "--rm", "-i", *(["-t"] if tty else []), "--pull", "never", "--name", f"tracekit-{name}",
            "--label", f"{LABEL}={name}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *LIMITS,
            "--user", f"{os.getuid()}:{os.getgid()}", "--network", NETWORK, *(["--network", "bridge"] if network else []),
            "--add-host", f"{HOST}:{relay_ip}", "-v", f"{project}:/work", *ro, "-w", "/work",
            "-v", f"{os.path.join(box, 'token')}:/run/tracekit/token:ro",
            "-v", f"{os.path.join(home(), 'tls', 'ca.pem')}:/run/tracekit/ca.pem:ro",
            *[x for k, v in SIGNER_ENV.items() for x in ("-e", f"{k}={v}")], image, *cmd]


def _relay(name, image, port):
    """Start box `name`'s relay; (its address on NETWORK, its address on the default bridge)."""
    if not _docker("network", "ls", "-q", "--filter", f"name=^{NETWORK}$"):
        _docker("network", "create", "--internal", NETWORK)
    relay_name = f"tracekit-{name}-relay"
    _docker("run", "-d", "--rm", "--pull", "never", "--name", relay_name, "--label", f"{LABEL}.relay={name}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--user", "65534:65534",
            "--pids-limit", "64", "--memory", "128m",
            *(["--add-host", f"{HOST}:host-gateway"] if sys.platform != "darwin" else []), image, PYTHON, "-I", "-c",
            f"from tracekit.box import relay; relay({RELAY_PORT}, {HOST!r}, {int(port)})")
    _docker("network", "connect", NETWORK, relay_name)
    nets = json.loads(_docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", relay_name))
    return nets[NETWORK]["IPAddress"], nets["bridge"]["IPAddress"]


def running():
    """The names of the boxes Docker runs."""
    return set(_docker("ps", "--filter", f"label={LABEL}", "--format", f'{{{{.Label "{LABEL}"}}}}').split())


def orphans(store, live, now=None):
    """The names of the box tokens in TokenStore `store` still valid with no box running (`live`: running()), past
    ORPHAN_S: their `up` was killed outright."""
    now = time.time() if now is None else now
    return sorted(n for n, r in store.load().items() if r.get("box") and r["revoked"] is None
                  and r["expires"] > now and r["created"] < now - ORPHAN_S and n not in live)


def _files(project):
    """{relative path: (mtime_ns, size)} of the project's files, .git's left out."""
    out = {}
    for d, dirs, names in os.walk(project):
        dirs[:] = [x for x in dirs if not (d == project and x == ".git")]
        for n in names:
            if len(out) >= SNAPSHOT_MAX:
                return out
            with contextlib.suppress(OSError):
                st = os.lstat(os.path.join(d, n))
                out[os.path.relpath(os.path.join(d, n), project)] = (st.st_mtime_ns, st.st_size, st.st_mode)
    return out


def changed(project, before, token):
    """(the changed or new files the host may run: RUNS, executable, a workflow, a host_run path the box created;
    those that hold `token`)."""
    after, runs_, leaked, hosts = _files(project), [], [], set(host_run(project))
    for rel, (mtime, size, mode) in after.items():
        if before.get(rel, (None,))[:2] == (mtime, size):
            continue
        if os.path.basename(rel) in RUNS or mode & 0o111 or rel.startswith(os.path.join(".github", "workflows")) \
                or rel.split(os.sep)[0] in hosts:
            runs_.append(rel)
        if size <= 1 << 20 and stat.S_ISREG(mode):
            with contextlib.suppress(OSError), open(os.path.join(project, rel), "rb") as f:
                if token.encode() in f.read():
                    leaked.append(rel)
    return sorted(runs_), sorted(leaked)


def runs(data_dir, name="box-"):
    """(run id, `box` for a run its box's token registered (ext.box), else the isolation the signer recorded) of each
    run a box token named `name...` registered (default: any box's), oldest first."""
    from tracekit.signer.service import reader
    r = reader({"data_dir": data_dir})
    try:
        return [(e["run_id"], "box" if (e.get("ext") or {}).get("box") else e["data"]["signer_isolation"])
                for x in r.iter_range(0, len(r.log.offsets) - 1)
                if (e := x["event"])["type"] == "run.registered" and e["data"]["identity"]["scheme"] == "token"
                and e["data"]["identity"]["subject"].startswith(name)]
    finally:
        r.close()


def problems(c, h):
    """What gives box container `c` (an object of `docker inspect`) a way to the signer or the host, as text: the
    Docker socket or a socket's dir, your home, a sensitive dir in it or a signer's files mounted, root, capabilities,
    seccomp or AppArmor off, host namespaces."""
    hc, user = c.get("HostConfig") or {}, ((c.get("Config") or {}).get("User") or "0").split(":")[0]
    opts = hc.get("SecurityOpt") or ()
    out = [w for w, bad in (
        ("privileged", hc.get("Privileged")), (f"capabilities added: {hc.get('CapAdd')}", hc.get("CapAdd")),
        ("capabilities not dropped", "ALL" not in (hc.get("CapDrop") or ())), ("runs as root", user in ("0", "root")),
        ("new privileges allowed", not any(o.startswith("no-new-privileges") for o in opts)),
        ("seccomp or AppArmor unconfined", any(o in ("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined",
                                                     "apparmor:unconfined") for o in opts)),
        *((f"the host's {ns.lower()} namespace", hc.get(f"{ns}Mode") == "host") for ns in ("Pid", "Network", "Ipc")))
        if bad]
    home_, box, dev = (os.path.realpath(p) for p in (os.path.expanduser("~"), h, autospawn.data_dir()))
    secret = [os.path.join(home_, s) for s in SENSITIVE]
    ours = {"/run/tracekit/ca.pem": os.path.join(box, "tls", "ca.pem") + os.sep,   # the files up mounts, read-only
            "/run/tracekit/token": os.path.join(box, "boxes") + os.sep}
    for m in c.get("Mounts") or ():
        raw = m.get("Source") or "/"
        src = os.path.realpath(raw)
        if raw.endswith(".sock") or raw in ("/run", "/var/run", "/var"):   # where the Docker socket lives
            out.append(f"{raw} mounted: the Docker socket, or a socket's dir")
        elif any(_under(r, src) for r in (home_, box, dev)):
            out.append(f"{raw} mounted: it holds your home or a signer's files")
        elif any(_under(src, s) for s in secret):
            out.append(f"{raw} mounted: a credential, agent login or socket dir of your home")
        elif _under(src, os.path.join(box, "empty")) and not m.get("RW"):   # a placeholder for a missing .git, .claude
            continue
        elif (_under(src, box) or _under(src, dev)) and not (
                m.get("Destination") in ours and (src + os.sep).startswith(ours[m["Destination"]]) and not m.get("RW")):
            out.append(f"{raw} mounted: a signer's file")
    return out


def up(project=".", tag=None, cmd=(), out=print, network=False):
    """Run `cmd` (default: the image's, Claude Code) in a box on `project`, in image `tag` (default: image(), built
    on first use); the container's exit code. `network`: the box gets Docker's default bridge too."""
    from tracekit.signer.service import load_config
    if os.name == "nt" or not hasattr(os, "getuid"):
        raise BoxError("up --isolated runs on macOS and Linux")
    if os.getuid() == 0:
        raise BoxError("run up --isolated as yourself, not root: the box runs as your uid")
    if not shutil.which("docker"):
        raise BoxError("needs Docker: colima or Docker Desktop on a Mac, Docker Engine on Linux")
    h = home()
    project = check_project(project, h)
    if tag is None:
        build(tag := image(), out)
    path = setup(h)
    cfg = load_config(path)
    start(path, cfg)
    store = TokenStore(cfg["http"]["tokens"])
    for n in orphans(store, running()):
        store.revoke(n)
        shutil.rmtree(os.path.join(h, "boxes", n), ignore_errors=True)
        out(f"tracekit: revoked {n}'s token: its box isn't running (its `up` was killed)")
    name, made = f"box-{secrets.token_hex(6)}", []
    box = os.path.join(h, "boxes", name)

    def stopped(signum, frame):
        raise SystemExit(128 + signum)
    handlers = {s: signal.signal(s, stopped) for s in (signal.SIGTERM, signal.SIGHUP)}
    secret = ""
    try:
        made = [n for n in PLACEHOLDER if not os.path.lexists(os.path.join(project, n))]
        relay_ip, bridge_ip = _relay(name, tag, cfg["http"]["listen"].rpartition(":")[2])
        secret = store.add(name, TTL_S, box=True, addr=None if sys.platform == "darwin" else bridge_ip)
        os.makedirs(box, 0o700)
        d = files.open_dir(box)
        try:
            files.write(d, "token", secret.encode())
        finally:
            files.close(d)
        before = _files(project)
        sys.stdout.flush()
        code = subprocess.call(argv(name, project, tag, relay_ip, os.path.join(h, "empty"), cmd, sys.stdin.isatty(),
                                    network))
    finally:
        for s, old in handlers.items():
            signal.signal(s, old)
        for c in (f"tracekit-{name}", f"tracekit-{name}-relay"):
            _docker("rm", "-f", c, check=False)
        if name in store.load():
            store.revoke(name)
        shutil.rmtree(box, ignore_errors=True)
        for n in made:   # the placeholders' mountpoints Docker made; empty, as the box couldn't write them
            with contextlib.suppress(OSError):
                os.rmdir(os.path.join(project, n))
    runs_, leaked = changed(project, before, secret)
    if runs_:
        out(f"tracekit: the box changed files the host may run on its own; read them before you build, test or open "
            f"the project here: {', '.join(runs_[:20])}" + (f" and {len(runs_) - 20} more" if len(runs_) > 20 else ""))
    if leaked:
        out(f"tracekit: the box copied its token into {', '.join(leaked)}; it is revoked now")
    ids = runs(cfg["data_dir"], name)
    out(f"{name}: {len(ids) or 'no'} run(s)" + "".join(
        f"\n  {r} (isolation {iso}): tracekit export --v2 --config {json.dumps(path)} --run {r}" for r, iso in ids))
    return code


if __name__ == "__main__":   # stand-in-agent in the box image
    sys.exit(stand_in(sys.argv[1:]))
