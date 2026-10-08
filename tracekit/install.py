"""`tracekit init` / `status` / `uninstall` (P1, I1, I2).

System mode (default, needs root; Linux, experimental on macOS): a `tracekit` OS user owns the key and the
ledger; tracekitd runs as that user under systemd (launchd on macOS).
Dev mode (--dev): the signer runs as *your* user. Convenient, but the agent could rewrite the
ledger, so every run is labelled signer_isolation=same-user and verify says so.
"""
import base64
import json
import os
import secrets
import shlex
import socket
import shutil
import signal
import subprocess
import sys
import time

try:
    import grp
    import pwd
except ImportError:
    grp = pwd = None

from .core import read_json, read_text
from . import client
from .deploy import files

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SYS_HOME = "/var/lib/tracekit"
SYS_USER = "tracekit"
OPT = "/opt/tracekit"   # system mode: root-owned virtualenv the signer and hooks run from
OPT_PYTHON = os.path.join(OPT, "bin", "python")
SYSTEMD_DIR = "/etc/systemd/system"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
OTHER_EVENTS = ["UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop", "SessionStart", "SessionEnd"]
UNIT = """[Unit]
Description=Tracekit signer daemon
After=network.target

[Service]
User={user}
Group={user}
ExecStart={python} -I -m tracekit.daemon --home {home}
Restart=on-failure
UMask=0027
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={home}
PrivateTmp=true
{caps}
[Install]
WantedBy=multi-user.target
"""
PROXY_UNIT = """[Unit]
Description=Tracekit model proxy
After=tracekitd.service
Requires=tracekitd.service

[Service]
User={user}
Group={user}
ExecStart={python} -I -m tracekit.proxy --home {home}
Restart=on-failure
UMask=0027
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={home}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
LAUNCHD_DIR = "/Library/LaunchDaemons"
SYS_USER_DARWIN = "_tracekit"  # macOS system accounts are underscore-prefixed


def launchd_plist(label, user, python, module, home, extra_args=()):
    """A LaunchDaemon that runs `python -I -m <module> --home <home>` as the signer's own account."""
    import plistlib
    return plistlib.dumps({
        "Label": label, "UserName": user, "GroupName": user,
        "ProgramArguments": [python, "-I", "-m", module, "--home", home, *extra_args],
        "RunAtLoad": True, "KeepAlive": True,
        "Umask": 0o027, "WorkingDirectory": home,
        "StandardErrorPath": os.path.join(home, module.split(".")[-1] + ".log"),
    })


def _dscl(*args):
    return subprocess.run(["dscl", ".", *args], capture_output=True, text=True)


def _create_system_user_darwin(name):
    """Create a hidden, non-login system user and group with a free id in the 200-399 service range."""
    used = set()
    for kind, key in (("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")):
        for line in _dscl("-list", kind, key).stdout.splitlines():
            parts = line.split()
            if parts and parts[-1].isdigit():
                used.add(int(parts[-1]))
    ident = next((i for i in range(399, 199, -1) if i not in used), None)
    if ident is None:
        raise SystemExit("no free system id in 200-399 for the tracekit account")
    steps = [("-create", f"/Groups/{name}"), ("-create", f"/Groups/{name}", "PrimaryGroupID", str(ident)),
             ("-create", f"/Users/{name}"), ("-create", f"/Users/{name}", "UniqueID", str(ident)),
             ("-create", f"/Users/{name}", "PrimaryGroupID", str(ident)),
             ("-create", f"/Users/{name}", "UserShell", "/usr/bin/false"),
             ("-create", f"/Users/{name}", "NFSHomeDirectory", SYS_HOME),
             ("-create", f"/Users/{name}", "RealName", "Tracekit signer"),
             ("-create", f"/Users/{name}", "IsHidden", "1")]
    for step in steps:
        r = _dscl(*step)
        if r.returncode != 0:
            raise SystemExit(f"dscl {' '.join(step)} failed: {r.stderr.strip()}")


MANAGED_SETTINGS = {"linux": "/etc/claude-code/managed-settings.json",
                    "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json"}
HOOK_TIMEOUT = {"PreToolUse": 600, "SessionEnd": 15}   # PreToolUse may hold a call for approval (C8)
def _hook_command(module="tracekit.hook", func="_entry", args=(), python=None):
    """Shell command that runs `module.func(*args)`. Python runs isolated (-I): the working directory, user
    site-packages and PYTHON* variables are not on the import path, so the harness's cwd cannot shadow tracekit.
    python: an interpreter that has tracekit installed (system mode: OPT_PYTHON)."""
    if python:
        return " ".join([shlex.quote(python), "-I", "-m", module, *args])
    try:
        import importlib.util
        import site
        spec = importlib.util.find_spec("tracekit")
        user_site = site.getusersitepackages()
        installed = bool(spec and spec.origin and "site-packages" in spec.origin
                         and not spec.origin.startswith(user_site))
    except Exception:
        installed = False
    py = f'"{sys.executable}"' if os.name == "nt" else shlex.quote(sys.executable)
    if installed:
        return " ".join([py, "-I", "-m", module, *args])
    encoded_root = base64.b64encode(ROOT.encode("utf-8")).decode("ascii")
    code = (f"import base64,sys; sys.path.insert(0, base64.b64decode('{encoded_root}').decode('utf-8')); "
            f"from {module} import {func}; raise SystemExit({func}({', '.join(repr(a) for a in args)}))")
    return f'{py} -I -c "{code}"' if os.name == "nt" else f"{py} -I -c {shlex.quote(code)}"


def _is_ours(group):
    return any("tracekit.hook" in (h.get("command") or "") or ("tracekit" in (h.get("command") or "") and "hook.py" in (h.get("command") or ""))
               for h in group.get("hooks", []))


class SettingsError(Exception):
    """A Claude Code settings file Tracekit cannot safely edit."""


def _atomic_write_json(path, obj, mode=0o600):
    files.write_json(path, obj, mode)


def _backup(path, data):
    d = files.open_dir(os.path.dirname(os.path.abspath(path)))
    try:
        return files.backup(d, os.path.basename(path), data)
    finally:
        files.close(d)


def install_hooks(settings_path, uninstall=False, owner=None, proxy_url=None, extra=None, mode=0o600, python=None):
    """Add (or remove) Tracekit's hooks in a Claude Code settings file. Idempotent; backs up the
    file before changing it; leaves other hooks and settings alone. proxy_url sets
    env.ANTHROPIC_BASE_URL (C3). Raises SettingsError instead of overwriting a file it cannot parse,
    or one that is a symlink. With owner (as root) the whole edit runs as that user. python: see _hook_command."""
    if owner is not None:
        return files.as_user(owner, install_hooks, settings_path, uninstall, None, proxy_url, extra, mode, python,
                             errors=(SettingsError,))
    settings_path = os.path.abspath(settings_path)
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    try:
        d = files.open_dir(os.path.dirname(settings_path))
        try:
            _install_hooks_at(d, settings_path, uninstall, proxy_url, extra, mode, python)
        finally:
            files.close(d)
    except files.UnsafePath as e:
        raise SettingsError(f"{settings_path}: {e}") from e


def _install_hooks_at(d, settings_path, uninstall, proxy_url, extra, mode, python=None):
    name = os.path.basename(settings_path)
    s, raw = {}, files.read(d, name)
    original = None
    if raw is not None:
        try:
            original = raw.decode("utf-8")
            s = json.loads(original) if original.strip() else {}
        except ValueError as e:
            raise SettingsError(f"{settings_path} is not valid JSON ({e}); fix or remove it, then retry. "
                                "Tracekit did not change it.") from e
        if not isinstance(s, dict):
            raise SettingsError(f"{settings_path} must contain a JSON object; Tracekit did not change it.")
    hooks = s.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {settings_path} must be an object; Tracekit did not change it.")
    for ev in TOOL_EVENTS + OTHER_EVENTS:
        existing = hooks.get(ev, [])
        if not isinstance(existing, list):
            raise SettingsError(f"hooks.{ev} in {settings_path} must be a list; Tracekit did not change it.")
        groups = [g for g in existing if not (isinstance(g, dict) and _is_ours(g))]
        if not uninstall:
            e = {"hooks": [{"type": "command", "command": _hook_command(python=python), "timeout": HOOK_TIMEOUT.get(ev, 30)}]}
            groups.append({"matcher": "*", **e} if ev in TOOL_EVENTS else e)
        if groups:
            hooks[ev] = groups
        else:
            hooks.pop(ev, None)
    if not hooks:
        s.pop("hooks", None)
    env = s.get("env", {})
    if not isinstance(env, dict):
        raise SettingsError(f"'env' in {settings_path} must be an object; Tracekit did not change it.")
    marker = "_tracekit_proxy"
    if uninstall or not proxy_url:
        if s.get(marker) and env.get("ANTHROPIC_BASE_URL") == s[marker]:
            env.pop("ANTHROPIC_BASE_URL", None)
        s.pop(marker, None)
    if proxy_url and not uninstall:
        env["ANTHROPIC_BASE_URL"] = proxy_url
        s[marker] = proxy_url
    if env:
        s["env"] = env
    else:
        s.pop("env", None)
    for k, v in (extra or {}).items():
        if uninstall:
            s.pop(k, None)
        else:
            s[k] = v
    if original is not None:
        try:
            unchanged = json.loads(original) == s
        except ValueError:
            unchanged = False
        if unchanged:
            return
        files.backup(d, name, raw)
    files.write(d, name, files.json_bytes(s), mode)


def _my_uid():
    return {os.geteuid()} if hasattr(os, "geteuid") else None


def _write_client_config(user_home, cfg, owner=None):
    """Write ~/.tracekit-client/config.json; with owner (as root) the write runs as that user."""
    return files.as_user(owner, _write_client_dir, os.path.join(user_home, ".tracekit-client"), cfg)


def _write_client_dir(path, cfg):
    """Create path/ and path/runs (owned by the current user) and write path/config.json (0600), following no symlink."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    parent = files.open_dir(os.path.dirname(os.path.abspath(path)))
    try:
        d = files.subdir(parent, os.path.basename(path), 0o755, _my_uid())
    finally:
        files.close(parent)
    try:
        files.close(files.subdir(d, "runs", 0o755, _my_uid()))
        files.write(d, "config.json", files.json_bytes(cfg))
    finally:
        files.close(d)
    return os.path.join(path, "config.json")


def _signer_dir(home, tk_user=None):
    return files.open_dir(home, {tk_user.pw_uid} if tk_user else _my_uid())


def _read_config(d):
    raw = files.read(d, "config.json")
    try:
        cfg = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return cfg if isinstance(cfg, dict) else {}


def _save_config(d, cfg, tk_user=None):
    files.write(d, "config.json", files.json_bytes(cfg), 0o600, tk_user and tk_user.pw_uid, tk_user and tk_user.pw_gid)


def _write_signer_config(home, witnesses, checkpoint_every, socket_path, proxy=None, extra=None, tk_user=None):
    cfg = {"checkpoint_every": checkpoint_every, "witnesses": witnesses, "socket": socket_path, "socket_mode": "0666"}
    if proxy:
        cfg["proxy"] = proxy
    cfg.update(extra or {})
    d = _signer_dir(home, tk_user)
    try:
        # re-running init must never drop a configured external signer: the daemon would fall back to a new file key
        if "signer" not in cfg and _read_config(d).get("signer"):
            cfg["signer"] = _read_config(d)["signer"]
        _save_config(d, cfg, tk_user)
    finally:
        files.close(d)


HARNESS_COMMANDS = {"claude": "claude", "codex": "codex", "cursor": "cursor-agent", "gemini": "gemini"}
# 0.3: lets tracekitd read /proc/<pid>/exe of the agent's processes to find the harness that sent an event. It is only
# set when harnesses are registered. The signer already holds the signing key, so this does not widen what a
# compromised signer could do to the record; it does let it inspect the agent's processes (docs/threat-model.md).
UNIT_CAPS = "AmbientCapabilities=CAP_SYS_PTRACE\nCapabilityBoundingSet=CAP_SYS_PTRACE\n"


def resolve_harness(spec, agent="claude"):
    """`--harness` value -> registered harness. spec is PATH or NAME=PATH; a script (#!) registers its interpreter as
    the executable and the script itself, because that is what the kernel shows for the running harness."""
    name, path = spec.split("=", 1) if "=" in spec else (agent, spec)
    found = path if os.path.isabs(path) else shutil.which(path)
    if not found or not os.path.exists(found):
        raise SystemExit(f"--harness: {path} not found")
    real = os.path.realpath(found)
    with open(real, "rb") as f:
        head = f.read(256)
    entry = {"name": name or agent, "exe": real}
    if head.startswith(b"#!"):
        interp = head[2:].split(b"\n", 1)[0].decode(errors="replace").strip().split()
        if interp and os.path.basename(interp[0]) == "env":
            prog = [a for a in interp[1:] if not a.startswith("-")]
            interp = [shutil.which(prog[0]) or prog[0]] if prog else []
        if not interp or not os.path.isabs(interp[0]):
            raise SystemExit(f"--harness: cannot resolve the interpreter of {real}")
        entry = {"name": entry["name"], "exe": os.path.realpath(interp[0]), "script": real}
    from .daemon import trusted_file
    for f in (entry["exe"], entry.get("script")):
        bad = f and trusted_file(f)
        if bad:
            raise SystemExit(f"--harness: {f} could be replaced by a non-root user ({bad}). Install the agent "
                             "system-wide (root-owned) so Tracekit can trust which program sent each event.")
    return entry


def harness_config(specs, agent="claude"):
    """Signer-config fields for 0.3 harness binding. With no --harness, the agent's CLI on root's PATH is used if it
    is installed root-owned; otherwise binding stays off and init says so."""
    if specs:
        return {"harnesses": [resolve_harness(s, agent) for s in specs], "harness_binding": "enforce"}
    cmd = shutil.which(HARNESS_COMMANDS.get(agent, agent))
    if cmd:
        try:
            return {"harnesses": [resolve_harness(cmd, agent)], "harness_binding": "enforce"}
        except SystemExit as e:
            print(f"note: harness binding off: {e}")
            return {"harness_binding": "off"}
    print(f"note: harness binding off: no root-owned `{HARNESS_COMMANDS.get(agent, agent)}` on PATH. Without it, any "
          "process running as the agent's user can start a run (docs/threat-model.md). Re-run with --harness PATH.")
    return {"harness_binding": "off"}


def _upstream():
    """Where the proxy forwards: whatever the user already pointed Claude Code at, else Anthropic."""
    cur = os.environ.get("ANTHROPIC_BASE_URL", "")
    return cur if cur and "127.0.0.1" not in cur and "localhost" not in cur else "https://api.anthropic.com"


def _validate_init_options(checkpoint_every, proxy, proxy_port):
    try:
        checkpoint_every = int(checkpoint_every)
        proxy_port = int(proxy_port)
    except (TypeError, ValueError) as e:
        raise ValueError("checkpoint interval and proxy port must be integers") from e
    if checkpoint_every < 1:
        raise ValueError("checkpoint interval must be positive")
    if proxy and not 1 <= proxy_port <= 65535:
        raise ValueError("proxy port must be between 1 and 65535")
    return checkpoint_every, proxy_port


def start_dev_proxy(home):
    env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    with open(os.path.join(home, "proxy.log"), "a") as log:  # the child keeps its own copy of the fd
        p = subprocess.Popen([sys.executable, "-m", "tracekit.proxy", "--home", home], stdout=log, stderr=log, env=env,
                             start_new_session=True)
    _CHILDREN[p.pid] = p
    with open(os.path.join(home, "proxy.pid"), "w") as f:
        f.write(str(p.pid))
    import urllib.request
    health = f"http://127.0.0.1:{load_proxy_port(home)}/__tracekit_health"
    for _ in range(100):
        if p.poll() is not None:
            break
        try:
            with urllib.request.urlopen(health, timeout=0.2) as response:
                if response.status == 200:
                    return p.pid
        except Exception:
            pass
        time.sleep(0.05)
    try:
        with open(os.path.join(home, "proxy.log"), encoding="utf-8") as f:
            detail = f.read()[-4000:].strip()
    except OSError:
        detail = ""
    raise RuntimeError(f"tracekit proxy did not become ready; see {home}/proxy.log" + (f":\n{detail}" if detail else ""))


def load_proxy_port(home):
    with open(os.path.join(home, "config.json"), encoding="utf-8") as f:
        return int(json.load(f).get("proxy", {}).get("port", 8787))


def _dev_socket(home):
    """Unix socket where the kernel names the caller, else token-authenticated TCP on port 0: tracekitd binds a free
    port itself and writes it to its config (daemon.serve). A signer that is already running keeps its endpoint."""
    from .peercred import has_peer_credentials
    if hasattr(socket, "AF_UNIX") and has_peer_credentials():
        return os.path.join(home, "tracekitd.sock"), None
    if _signer_healthy(home):
        old = read_json(os.path.join(home, "config.json"))
        if str(old.get("socket", "")).startswith("tcp://") and old.get("socket_token"):
            return old["socket"], old["socket_token"]
    return "tcp://127.0.0.1:0", secrets.token_urlsafe(32)


def init_dev(home, witnesses, checkpoint_every=50, hooks_path=None, start=True, proxy=False, proxy_port=8787, fail_mode=None,
             signer=None):
    checkpoint_every, proxy_port = _validate_init_options(checkpoint_every, proxy, proxy_port)
    home = os.path.abspath(home)
    for sub in ("", "keys", "ledger", "blobs"):
        os.makedirs(os.path.join(home, sub), exist_ok=True)
    sock, socket_token = _dev_socket(home)
    if not witnesses:
        witnesses = [f"git:{os.path.join(home, 'witness')}"]
    pcfg = {"port": proxy_port, "upstream": _upstream(), "fail_mode": fail_mode or "open"} if proxy else None
    # dev mode: the agent and the approver are the same OS user, so approvals are allowed but labelled untrustworthy
    signer_extra = {"mode": "dev", "allow_same_user_approval": True}
    if signer:
        signer_extra["signer"] = signer
    if socket_token:
        signer_extra["socket_token"] = socket_token
    _write_signer_config(home, witnesses, checkpoint_every, sock, pcfg, signer_extra)
    cfg = {"socket": sock, "signer_home": home, "signer_isolation": "same-user", "mode": "dev"}
    if socket_token:
        cfg["socket_token"] = socket_token
    if proxy:
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{proxy_port}")
    try:
        if start:
            if not _signer_healthy(home):
                start_dev_daemon(home)
            if proxy and not _proxy_healthy(home):
                start_dev_proxy(home)
        # lean: with start=False a TCP client config keeps port 0 until init runs with start; resolve it from the
        # signer config in the client if dev TCP without start becomes a supported setup
        cfg["socket"] = read_json(os.path.join(home, "config.json")).get("socket", sock)
        client_home = os.environ.get("TRACEKIT_CLIENT_HOME")
        if client_home:
            _write_client_dir(client_home, cfg)
        else:
            _write_client_config(os.path.expanduser("~"), cfg)
        if hooks_path:
            install_hooks(hooks_path, proxy_url=cfg.get("proxy_url"))
    except Exception:
        if start and _CHILDREN:
            stop_dev_daemon(home)
        raise
    return cfg


def _signer_healthy(home):
    try:
        return bool(client._rpc({"op": "status"}, timeout=1.0, config=read_json(os.path.join(home, "config.json"))).get("ok"))
    except Exception:
        return False


def _proxy_healthy(home):
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{load_proxy_port(home)}/__tracekit_health", timeout=0.5) as r:
            return r.status == 200
    except Exception:
        return False


def start_dev_daemon(home):
    env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    with open(os.path.join(home, "tracekitd.log"), "a") as log:
        p = subprocess.Popen([sys.executable, "-m", "tracekit.daemon", "--home", home], stdout=log, stderr=log,
                             env=env, start_new_session=True)
    _CHILDREN[p.pid] = p
    with open(os.path.join(home, "tracekitd.pid"), "w") as f:
        f.write(str(p.pid))
    for _ in range(100):
        if p.poll() is not None:
            break
        try:
            # re-read each time: on TCP port 0 the signer writes the port it bound into its config
            if client._rpc({"op": "status"}, config=read_json(os.path.join(home, "config.json"))).get("ok"):
                return p.pid
        except client.SignerUnavailable:
            pass
        time.sleep(0.05)
    try:
        with open(os.path.join(home, "tracekitd.log"), encoding="utf-8") as f:
            detail = f.read()[-4000:].strip()
    except OSError:
        detail = ""
    raise RuntimeError(f"tracekitd did not become ready; see {home}/tracekitd.log" + (f":\n{detail}" if detail else ""))


_CHILDREN = {}  # pid -> Popen for daemons started by this process (reaped on stop)


def _pid_is_tracekit(pid):
    """Guard against a stale pidfile whose pid was reused by an unrelated process.
    Where /proc is unavailable (macOS, Windows) the pidfile is trusted."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"tracekit" in f.read()
    except FileNotFoundError:
        return not os.path.isdir("/proc")  # on Linux a missing entry means the process is gone
    except OSError:
        return True


def _pid_alive(pid):
    """Is the process still running? os.kill(pid, 0) is a probe on POSIX but on Windows signal 0 is CTRL_C_EVENT, which
    would be sent to a console process group (it can interrupt the caller), so Windows asks the kernel directly."""
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # exists but is not ours to signal
    return True


def _checkpoint_before_stop(home):
    try:
        client._rpc({"op": "checkpoint"}, timeout=5, config=read_json(os.path.join(home, "config.json")))
    except Exception:  # noqa: BLE001  best effort: the signer may already be gone
        pass


def _stop_pidfile(path):
    try:
        pid = int(read_text(path))
    except (OSError, ValueError):
        return
    child = _CHILDREN.get(pid)
    if child is None and not _pid_is_tracekit(pid):
        try:
            os.remove(path)  # stale: the pid now belongs to something else
        except OSError:
            pass
        return
    if sys.platform == "win32":
        # there is no catchable SIGTERM on Windows (os.kill terminates the process outright), so ask the signer for its
        # final checkpoint over the socket first
        _checkpoint_before_stop(os.path.dirname(path))
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    child = _CHILDREN.pop(pid, None)
    if child is not None:
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait(5)
    else:
        for _ in range(100):
            if not _pid_alive(pid):
                break
            time.sleep(0.05)
    try:
        os.remove(path)
    except OSError:
        pass


def stop_dev_daemon(home):
    _stop_pidfile(os.path.join(home, "proxy.pid"))
    _stop_pidfile(os.path.join(home, "tracekitd.pid"))


def install_managed(proxy_url=None, managed_only=False, path=None, python=None):
    """C5: put the hooks in Claude Code's admin-managed settings, which users and projects cannot
    override. managed_only additionally sets allowManagedHooksOnly (user/project hooks stop running)."""
    path = path or MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]
    install_hooks(path, proxy_url=proxy_url, extra={"allowManagedHooksOnly": True} if managed_only else None, mode=0o644,
                  python=python)
    return path


def _write_system_client_config(cfg):
    """0.2.1: root-owned client config. In system mode it overrides the agent-writable copy in the agent's home
    and the TRACEKIT_SOCKET / TRACEKIT_POLICY environment, so the agent cannot redirect or reconfigure its hooks."""
    path = client.SYSTEM_CONFIG
    os.makedirs(os.path.dirname(path), exist_ok=True)
    d = files.open_dir(os.path.dirname(path), {0})
    try:
        os.fchown(d, 0, 0)
        os.fchmod(d, 0o755)
        files.write(d, os.path.basename(path), files.json_bytes(cfg), 0o644, 0, 0)
    finally:
        files.close(d)


def _update_signer_config(home, fields, tk_user=None):
    d = _signer_dir(home, tk_user)
    try:
        raw = files.read(d, "config.json")
        if raw is None:
            raise FileNotFoundError(os.path.join(home, "config.json"))
        cfg = json.loads(raw)
        cfg.update(fields)
        _save_config(d, cfg, tk_user)
    finally:
        files.close(d)
    return cfg


def _pin_policy(home, tk_user=None):
    """0.2.1: record the hash of the effective system-mode policy in the signer config. The signer then turns any
    run or decision made under a different policy into a policy_mismatch capture gap. Re-run after a policy change."""
    from . import policy as policy_mod
    pol, _ = policy_mod.load()
    return _update_signer_config(home, {"pinned_policy_hash": policy_mod.policy_hash(pol)}, tk_user)["pinned_policy_hash"]


def migrate_system(fail_mode=None, harnesses=None):
    """`tracekit migrate --system`: upgrade a 0.2.x system-mode install in place. Writes the root-owned client config,
    pins the policy and (0.3) registers the harness; the ledger, key and witness are untouched. Restart tracekitd."""
    if not sys.platform.startswith("linux"):
        raise SystemExit("migrate --system: system mode is Linux-only in 0.2.1")
    if os.geteuid() != 0:
        raise SystemExit("migrate --system needs root: sudo tracekit migrate --system")
    signer_cfg = os.path.join(SYS_HOME, "config.json")
    if not os.path.exists(signer_cfg):
        raise SystemExit(f"no system-mode signer at {SYS_HOME}; run `sudo tracekit init --user <agent-user>` instead")
    with open(signer_cfg, encoding="utf-8") as f:
        scfg = json.load(f)
    cfg = {"socket": scfg.get("socket") or os.path.join(SYS_HOME, "tracekitd.sock"), "signer_home": SYS_HOME,
           "signer_isolation": "separate-user", "mode": "system", "fail_mode": fail_mode or "closed"}
    if scfg.get("proxy"):
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{scfg['proxy'].get('port', 8787)}")
    policy = (client.system_config() or {}).get("policy")
    if not policy and os.path.exists(OPT_PYTHON):  # 0.2.x configs have no policy key; use the root-owned default
        policy = _opt_default_policy()
    if policy:
        cfg["policy"] = policy
    _write_system_client_config(cfg)
    tk = pwd.getpwnam(SYS_USER)
    hcfg = harness_config(harnesses)
    _update_signer_config(SYS_HOME, hcfg, tk)
    unit = os.path.join(SYSTEMD_DIR, "tracekitd.service")
    if hcfg.get("harnesses") and os.path.exists(unit):
        with open(unit) as f:
            text = f.read()
        if "CAP_SYS_PTRACE" not in text:
            with open(unit, "w") as f:
                f.write(text.replace("PrivateTmp=true\n", "PrivateTmp=true\n" + UNIT_CAPS, 1))
            subprocess.run(["systemctl", "daemon-reload"], check=False)
    pinned = _pin_policy(SYS_HOME, tk)
    print(f"wrote {client.SYSTEM_CONFIG} (root-owned; agent config and TRACEKIT_SOCKET/TRACEKIT_POLICY now ignored)")
    for h in hcfg.get("harnesses", []):
        print(f"harness binding: {h['name']} = {h['exe']}" + (f" running {h['script']}" if h.get("script") else ""))
    print(f"pinned policy {pinned[:19]}; fail_mode={cfg['fail_mode']}")
    print("restart the signer to load the pin: sudo systemctl restart tracekitd")
    return 0


PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "docker", SYS_USER, SYS_USER_DARWIN}


def _privileges(pw):
    """Why the agent's user could take over the signer (root, or a member of an admin, docker or tracekit group)."""
    if pw.pw_uid == 0:
        return ["it is root"]
    names = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return [f"it is in the {g} group" for g in sorted(names & PRIVILEGED_GROUPS)]


def _install_venv():
    """Install this Tracekit into a root-owned virtualenv at OPT, so the signer and hooks never run code the agent's
    user can modify. Returns the default policy path inside it."""
    from .daemon import trusted_file
    for f in (sys.executable, os.path.dirname(os.__file__)):
        bad = trusted_file(f)
        if bad:
            raise SystemExit(f"the Python running init could be modified by a non-root user ({bad}). Run init with a "
                             "root-owned Python, e.g. sudo /usr/bin/python3 -m tracekit init")
    if not os.path.isfile(os.path.join(ROOT, "pyproject.toml")):
        # lean: source checkout only; install from a pinned wheel once the distribution name is settled
        raise SystemExit("system mode installs from a Tracekit source checkout: run it from the repository, e.g. "
                         "cd tracekit && sudo /usr/bin/python3 -m tracekit init --user <agent-user>")
    src = ROOT
    old = os.umask(0o022)
    try:
        subprocess.run([sys.executable, "-m", "venv", "--clear", OPT], check=True)
        subprocess.run([OPT_PYTHON, "-m", "pip", "install", "--quiet", "--no-cache-dir", src], check=True)
    finally:
        os.umask(old)
    for dirpath, dirnames, filenames in os.walk(OPT):
        for p in [dirpath] + [os.path.join(dirpath, n) for n in dirnames + filenames]:
            os.lchown(p, 0, 0)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode & ~0o022)
    return _opt_default_policy()


def _opt_default_policy():
    return subprocess.run([OPT_PYTHON, "-I", "-c", "from tracekit.policy import DEFAULT_POLICY; print(DEFAULT_POLICY)"],
                          check=True, capture_output=True, text=True).stdout.strip()


def _unit_path():
    return (os.path.join(LAUNCHD_DIR, "dev.tracekit.tracekitd.plist") if sys.platform == "darwin"
            else os.path.join(SYSTEMD_DIR, "tracekitd.service"))


def doctor(checks=None):
    """`tracekit doctor`: check that system mode runs only code and policy the agent's user cannot modify. Prints one
    line per check with a fix; returns 1 if any check fails."""
    from .daemon import trusted_file
    if checks is None:
        import glob
        sc = client.system_config()
        if sc is None:
            print(f"FAIL  system mode: {client.SYSTEM_CONFIG} is missing or not root-owned\n"
                  "      fix: sudo tracekit init --user <agent-user>")
            return 1
        from .policy import DEFAULT_POLICY
        reinstall = "re-run sudo tracekit init --user <agent-user> to reinstall into " + OPT
        checks = [("signer python", OPT_PYTHON, reinstall)]
        checks += [("tracekit package", p, reinstall) for p in glob.glob(os.path.join(OPT, "lib", "python*", "site-packages", "tracekit"))
                   ] or [("tracekit package", os.path.join(OPT, "lib", "site-packages", "tracekit"), reinstall)]
        checks += [("unit file", _unit_path(), reinstall),
                   ("policy file", sc.get("policy") or DEFAULT_POLICY,
                    "make it and every directory above it root-owned and not group/world-writable (sudo chown root:root, "
                    "sudo chmod go-w), then sudo tracekit migrate --system")]
    failed = 0
    for label, path, fix in checks:
        bad = trusted_file(path)
        if bad is None and os.path.isdir(path):
            # lean: one stat per file and ancestor; fine for a package of a few hundred files
            bad = next((b for dp, dns, fns in os.walk(path) for n in dns + fns
                        for b in [trusted_file(os.path.join(dp, n))] if b), None)
        if bad:
            failed += 1
            print(f"FAIL  {label}: {bad}\n      fix: {fix}")
        else:
            print(f"ok    {label}: {path}")
    return 1 if failed else 0


def init_system(target_user, witnesses, checkpoint_every=50, project=None, no_service=False, proxy=False, proxy_port=8787,
                managed=False, managed_only=False, fail_mode=None, experimental_macos=False, hooks=True, signer=None,
                harnesses=None, agent="claude", allow_privileged=False):
    darwin = sys.platform == "darwin"
    if not (sys.platform.startswith("linux") or darwin):
        raise SystemExit("v0.2 system mode runs on Linux and (experimentally) macOS: tracekitd must identify callers "
                         "from the kernel to attest users, refuse forged proxy events and check approvers. Use "
                         "`tracekit init --dev` to try Tracekit here (same-user, clearly labelled).")
    if darwin and not experimental_macos:
        raise SystemExit("macOS system mode is experimental: it has been written to the platform documentation but not "
                         "yet validated on hardware (docs/portability.md). Re-run with --experimental-macos to use it, "
                         "or use `tracekit init --dev`.")
    if os.geteuid() != 0:
        raise SystemExit("system mode needs root: sudo tracekit init   (or tracekit init --dev for a same-user signer)")
    checkpoint_every, proxy_port = _validate_init_options(checkpoint_every, proxy, proxy_port)
    owner = pwd.getpwnam(target_user)
    why = _privileges(owner)
    if why and not allow_privileged:
        raise SystemExit(f"refusing to trace {target_user}: {'; '.join(why)}, so its agents could stop or replace the "
                         "signer. Trace an unprivileged user, or re-run with --i-understand-agent-is-privileged.")
    user = SYS_USER_DARWIN if darwin else SYS_USER
    try:
        pwd.getpwnam(user)
    except KeyError:
        if darwin:
            os.makedirs(SYS_HOME, exist_ok=True)
            _create_system_user_darwin(user)
        else:
            subprocess.run(["useradd", "--system", "--home-dir", SYS_HOME, "--shell", "/usr/sbin/nologin", "--user-group", user], check=True)
    tk = pwd.getpwnam(user)
    os.makedirs(SYS_HOME, exist_ok=True)
    home_fd = files.open_dir(SYS_HOME, {0, tk.pw_uid})
    try:
        for sub, mode in (("keys", 0o700), ("ledger", 0o750), ("blobs", 0o750), ("", 0o755)):
            fd = files.subdir(home_fd, sub, mode, {0, tk.pw_uid}) if sub else home_fd
            try:
                os.fchown(fd, tk.pw_uid, tk.pw_gid)
                os.fchmod(fd, mode)
            finally:
                if sub:
                    files.close(fd)
    finally:
        files.close(home_fd)
    sock = os.path.join(SYS_HOME, "tracekitd.sock")
    if not witnesses:
        witnesses = [f"git:{os.path.join(SYS_HOME, 'witness')}"]
        print("note: using a local git witness only. It protects against the agent's user, not against root on this "
              "machine. Point --witness at a remote repository the security team owns (docs/witnesses.md).")
    pcfg = {"port": proxy_port, "upstream": _upstream(), "fail_mode": fail_mode or "open"} if proxy else None
    extra = dict({"signer": signer} if signer else {}, **({} if darwin else harness_config(harnesses, agent)))
    _write_signer_config(SYS_HOME, witnesses, checkpoint_every, sock, pcfg, extra or None, tk)
    policy = _install_venv()
    # generate the key as the tracekit user so root-only reads are the only other path to it
    subprocess.run(["runuser" if shutil.which("runuser") else "sudo", "-u", tk.pw_name, "--", OPT_PYTHON, "-I", "-c",
                    f"from tracekit.ledger import Keys; Keys.load_or_create({os.path.join(SYS_HOME, 'keys')!r})"],
                   check=True)
    if not no_service:
        if darwin:
            for label, module, enabled in (("dev.tracekit.tracekitd", "tracekit.daemon", True),
                                            ("dev.tracekit.proxy", "tracekit.proxy", proxy)):
                if not enabled:
                    continue
                plist = os.path.join(LAUNCHD_DIR, label + ".plist")
                with open(plist, "wb") as f:
                    f.write(launchd_plist(label, tk.pw_name, OPT_PYTHON, module, SYS_HOME))
                os.chmod(plist, 0o644)
                subprocess.run(["launchctl", "bootstrap", "system", plist], check=False)
        else:  # systemd
            with open(os.path.join(SYSTEMD_DIR, "tracekitd.service"), "w") as f:
                f.write(UNIT.format(user=tk.pw_name, python=OPT_PYTHON, home=SYS_HOME,
                                    caps=UNIT_CAPS if extra.get("harnesses") else ""))
            if proxy:
                with open(os.path.join(SYSTEMD_DIR, "tracekit-proxy.service"), "w") as f:
                    f.write(PROXY_UNIT.format(user=tk.pw_name, python=OPT_PYTHON, home=SYS_HOME))
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", "--now", "tracekitd"], check=False)
            if proxy:
                subprocess.run(["systemctl", "enable", "--now", "tracekit-proxy"], check=False)
    cfg = {"socket": sock, "signer_home": SYS_HOME, "signer_isolation": "separate-user", "mode": "system"}
    if proxy:
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{proxy_port}")
    _write_client_config(owner.pw_dir, cfg, owner)
    _write_system_client_config(dict(cfg, fail_mode=fail_mode or "closed", policy=policy))
    _pin_policy(SYS_HOME, tk)
    if not hooks:
        settings = None  # hooks come from elsewhere (the Claude Code plugin)
    elif managed:
        settings = install_managed(cfg.get("proxy_url"), managed_only, python=OPT_PYTHON)
    else:
        settings = os.path.join(project, ".claude", "settings.json") if project else os.path.join(owner.pw_dir, ".claude", "settings.json")
        install_hooks(settings, owner=owner, proxy_url=cfg.get("proxy_url"), python=OPT_PYTHON)
    return cfg, settings


def status():
    cfg = client.client_config()
    visible_cfg = {k: v for k, v in cfg.items() if k != "socket_token"}
    out = {"client_config": visible_cfg or None}
    try:
        from . import policy as P
        pol, _ = P.load()
        out["policy"] = {"version": pol.get("version"), "hash": P.policy_hash(pol), "fail_mode": pol.get("fail_mode", "open"),
                         "content_capture": pol.get("content_capture", "hashed"), "reasoning_capture": pol.get("reasoning_capture", False)}
    except Exception as e:
        out["policy"] = {"error": str(e)}
    try:
        out["signer"] = client.status()
    except client.SignerUnavailable as e:
        out["signer"] = {"ok": False, "error": f"unreachable at {client.socket_path()}: {e}"}
    hooks = []
    seen = set()
    for p in (os.path.expanduser("~/.claude/settings.json"), os.path.join(os.getcwd(), ".claude", "settings.json")):
        if os.path.realpath(p) in seen:  # cwd is the home directory: one file, listed once
            continue
        seen.add(os.path.realpath(p))
        if os.path.exists(p):
            try:
                s = read_json(p)
                evs = [ev for ev, gs in s.get("hooks", {}).items() if any(_is_ours(g) for g in gs)]
                hooks.append({"settings": p, "events": evs})
            except ValueError:
                hooks.append({"settings": p, "error": "unreadable"})
    for p in MANAGED_SETTINGS.values():
        if os.path.exists(p):
            try:
                s = read_json(p)
                evs = [ev for ev, gs in s.get("hooks", {}).items() if any(_is_ours(g) for g in gs)]
                hooks.append({"settings": p, "managed": True, "events": evs, "allowManagedHooksOnly": bool(s.get("allowManagedHooksOnly"))})
            except (ValueError, OSError):
                hooks.append({"settings": p, "managed": True, "error": "unreadable"})
    out["hooks"] = hooks
    out["capture_sources"] = ["hook"] + (["proxy"] if cfg.get("proxy") else []) + \
        (["transcript"] if out["policy"].get("reasoning_capture") else [])
    if cfg.get("proxy_url"):
        import urllib.request
        try:
            urllib.request.urlopen(cfg["proxy_url"] + "/__tracekit_health", timeout=2)
            out["proxy"] = {"url": cfg["proxy_url"], "reachable": True}
        except Exception as e:
            reachable = "HTTP Error" in str(e)
            out["proxy"] = {"url": cfg["proxy_url"], "reachable": reachable, **({} if reachable else {"error": str(e)[:200]})}
    return out


def uninstall(project=None):
    settings = os.path.join(project, ".claude", "settings.json") if project else os.path.expanduser("~/.claude/settings.json")
    if os.path.exists(settings):
        install_hooks(settings, uninstall=True)
    cfg = client.client_config()
    if not project and cfg.get("mode") == "dev" and cfg.get("signer_home"):
        stop_dev_daemon(cfg["signer_home"])
    return settings
