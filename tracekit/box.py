"""`tracekit up --isolated [--image IMAGE] [--project DIR] [-- COMMAND ...]` (experimental): the coding agent in a
container, the signer outside it (docs/design/isolated-up.md).

The box image (image()) is built on first use from DOCKERFILE: Claude Code (CLAUDE_CODE) and this Tracekit, the
hooks' client, with Claude Code's managed settings holding Tracekit's v2 hooks, which nothing in the project can turn
off. Its tag names this Tracekit's version and a hash of its files, so a changed Tracekit builds a new one. Its default
command is `claude`; `stand-in-agent CMD ...` (stand_in, `python -m tracekit.box`) runs Bash calls through the same
hooks as Claude Code would, for a box without a Claude Code login.

The box signer is a v2 signer of its own, run as you from home() (`<dev data dir>-box`, or $TRACEKIT_BOX_HOME):
signer.yaml, its keys and store under data/, its TLS key under tls/, tokens.json. The dev signer is not touched. Each
box gets a token of its own (identity token:box-<id>, TTL_S), revoked when the container exits. The container gets the
project at /work and that token and the signer's CA certificate, read-only, and nothing else of the host: no signer
data, keys or socket, no Docker socket, no home. It runs as your uid with every capability dropped and no new
privileges; the project's .git and .claude, when present, are read-only, so the box can't leave a git or Claude Code
hook that runs on the host later. Its hooks reach the signer's HTTPS listener at https://host.docker.internal:PORT
(colima and Docker Desktop forward it to the host's loopback; on Linux the signer listens on the Docker bridge). The
signer records each run's isolation from the caller it authenticates (a token it issued, over HTTPS: `remote`),
never from anything the container sends.
"""
import datetime
import hashlib
import importlib.metadata
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
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
 && /opt/tracekit/bin/python -c "from tracekit import install; install.install_hooks('/etc/claude-code/managed-settings.json', \\
    module=install.V2_HOOK, python='/opt/tracekit/bin/python', mode=0o644)" \\
 && printf '#!/bin/sh\\nexec /opt/tracekit/bin/python -I -m tracekit.box "$@"\\n' > /usr/local/bin/stand-in-agent \\
 && chmod 755 /usr/local/bin/stand-in-agent
WORKDIR /work
USER 1000:1000
CMD ["claude"]
"""
SETTINGS = "/etc/claude-code/managed-settings.json"
HOST = "host.docker.internal"
LABEL = "tracekit.box"
# lean: a box past 12 h loses its token, and its hooks then block every call; renew it while the box runs once
# sessions last longer
TTL_S = 12 * 3600
START_S = 20
# what a coding-agent hook calls (docs/deploy.md#compose); not approval_decide: the box can't answer its own holds
GRANTS = ("register_run", "decide", "approval_consume", "complete", "close_run", "model_event", "approval_request",
          "approval_wait", "state_write", "status", "observe", "constraint_add", "approval_get")
READ_ONLY = (".git", ".claude")   # what the host runs from the project on its own: git's hooks, Claude Code's


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


def stand_in(commands):
    """A stand-in for Claude Code in the box: runs each of `commands` as a Bash tool call through the hooks in Claude
    Code's managed settings, as Claude Code runs them (SessionStart; per call PreToolUse, the command if the hooks let
    it through, PostToolUse; SessionEnd). The worst exit code: 2 when a hook blocked a call."""
    with open(SETTINGS, encoding="utf-8") as f:
        hooks = json.load(f)["hooks"]
    session = str(uuid.uuid4())

    def hook(event, **fields):
        payload = json.dumps({"hook_event_name": event, "session_id": session, "cwd": os.getcwd(), **fields})
        for h in (h for g in hooks.get(event, ()) for h in g["hooks"]):
            if code := subprocess.run(h["command"], shell=True, input=payload, text=True).returncode:
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


def _listen_host():
    """Where the containers reach the host: its loopback on a Mac (colima and Docker Desktop forward
    host.docker.internal to it), the default bridge's gateway on Linux."""
    if sys.platform == "darwin":
        return "127.0.0.1"
    p = subprocess.run(["docker", "network", "inspect", "bridge", "--format",
                        "{{range .IPAM.Config}}{{.Gateway}}{{end}}"], capture_output=True, text=True, timeout=30)
    try:
        return str(ipaddress.ip_address(p.stdout.strip()))
    except ValueError:
        raise BoxError(f"no Docker bridge gateway to listen on: {p.stderr.strip() or p.stdout.strip()}") from None


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
    """signer.yaml of the box signer in `h`, written with its TLS files the first time; its path."""
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
        t = files.subdir(d, "tls")
        try:
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


def check_project(project, h):
    """BoxError for a project dir that holds your home or a signer's files: mounted, the box would reach them."""
    p = os.path.realpath(project)
    for what, path in (("your home", os.path.expanduser("~")), ("the box signer's files", h),
                       ("the dev signer's data", autospawn.data_dir())):
        r = os.path.realpath(path)
        if r == p or r.startswith(p.rstrip(os.sep) + os.sep):
            raise BoxError(f"{project} holds {what} ({path}): the box would reach it; run it on a project dir below")
    if ":" in p:   # lean: -v splits on it; --mount when a project path needs one
        raise BoxError(f"{project}: a project path with ':' can't be mounted")
    return p


def argv(name, project, token, ca, port, image, cmd=(), tty=False, linux=sys.platform != "darwin"):
    """The `docker run` of box `name`: the project, the token file and CA certificate, nothing else of the host."""
    ro = [x for d in READ_ONLY for x in ("-v", f"{os.path.join(project, d)}:/work/{d}:ro")
          if not os.path.islink(os.path.join(project, d)) and os.path.exists(os.path.join(project, d))]
    return ["docker", "run", "--rm", "-i", *(["-t"] if tty else []), "--pull", "never", "--name", f"tracekit-{name}",
            "--label", f"{LABEL}={name}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", *(["--add-host", f"{HOST}:host-gateway"] if linux else []),
            "-v", f"{project}:/work", *ro, "-w", "/work",
            "-v", f"{token}:/run/tracekit/token:ro", "-v", f"{ca}:/run/tracekit/ca.pem:ro",
            "-e", f"TRACEKIT_SIGNER=https://{HOST}:{port}", "-e", "TRACEKIT_SIGNER_TOKEN_FILE=/run/tracekit/token",
            "-e", "TRACEKIT_SIGNER_CA=/run/tracekit/ca.pem", image, *cmd]


def runs(data_dir, name="box-"):
    """(run id, the isolation the signer recorded) of each run box `name`'s token registered (default: any box's),
    oldest first."""
    from tracekit.signer.service import reader
    r = reader({"data_dir": data_dir})
    try:
        return [(e["run_id"], e["data"]["signer_isolation"]) for x in r.iter_range(0, len(r.log.offsets) - 1)
                if (e := x["event"])["type"] == "run.registered" and e["data"]["identity"]["scheme"] == "token"
                and e["data"]["identity"]["subject"].startswith(name)]
    finally:
        r.close()


def problems(c, h):
    """What gives box container `c` (an object of `docker inspect`) a way to the signer or the host, as text: the
    Docker socket or another socket, your home or a signer's files mounted, root, capabilities, host namespaces."""
    hc, user = c.get("HostConfig") or {}, ((c.get("Config") or {}).get("User") or "0").split(":")[0]
    out = [w for w, bad in (
        ("privileged", hc.get("Privileged")), (f"capabilities added: {hc.get('CapAdd')}", hc.get("CapAdd")),
        ("capabilities not dropped", "ALL" not in (hc.get("CapDrop") or ())), ("runs as root", user in ("0", "root")),
        ("new privileges allowed", not any(o.startswith("no-new-privileges") for o in hc.get("SecurityOpt") or ())),
        *((f"the host's {ns.lower()} namespace", hc.get(f"{ns}Mode") == "host") for ns in ("Pid", "Network", "Ipc")))
        if bad]
    home_, box, dev = (os.path.realpath(p) for p in (os.path.expanduser("~"), h, autospawn.data_dir()))
    ours = {"/run/tracekit/ca.pem": os.path.join(box, "tls", "ca.pem") + os.sep,   # the files up mounts, read-only
            "/run/tracekit/token": os.path.join(box, "boxes") + os.sep}

    def under(path, d):
        return path == d or path.startswith(d.rstrip(os.sep) + os.sep)
    for m in c.get("Mounts") or ():
        raw = m.get("Source") or "/"
        src = os.path.realpath(raw)
        if raw.endswith(".sock") or raw in ("/run", "/var/run", "/var"):   # where the Docker socket lives
            out.append(f"{raw} mounted: the Docker socket, or a socket's dir")
        elif any(under(r, src) for r in (home_, box, dev)):
            out.append(f"{raw} mounted: it holds your home or a signer's files")
        elif (under(src, box) or under(src, dev)) and not (
                m.get("Destination") in ours and (src + os.sep).startswith(ours[m["Destination"]]) and not m.get("RW")):
            out.append(f"{raw} mounted: a signer's file")
    return out


def up(project=".", tag=None, cmd=(), out=print):
    """Run `cmd` (default: the image's, Claude Code) in a box on `project`, in image `tag` (default: image(), built
    on first use); the container's exit code."""
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
    name = f"box-{secrets.token_hex(6)}"
    token = TokenStore(cfg["http"]["tokens"]).add(name, TTL_S)
    box = os.path.join(h, "boxes", name)
    try:
        os.makedirs(box, 0o700)
        d = files.open_dir(box)
        try:
            files.write(d, "token", token.encode())
        finally:
            files.close(d)
        sys.stdout.flush()
        code = subprocess.call(argv(name, project, os.path.join(box, "token"), os.path.join(h, "tls", "ca.pem"),
                                    cfg["http"]["listen"].rpartition(":")[2], tag, cmd, sys.stdin.isatty()))
    finally:
        TokenStore(cfg["http"]["tokens"]).revoke(name)
        shutil.rmtree(box, ignore_errors=True)
    ids = runs(cfg["data_dir"], name)
    out(f"{name}: {len(ids) or 'no'} run(s)" + "".join(
        f"\n  {r} (isolation {iso}): tracekit export --v2 --config {json.dumps(path)} --run {r}" for r, iso in ids))
    return code


if __name__ == "__main__":   # stand-in-agent in the box image
    sys.exit(stand_in(sys.argv[1:]))
