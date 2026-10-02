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
    import pwd
except ImportError:
    pwd = None

from .core import read_json, read_text
from . import client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SYS_HOME = "/var/lib/tracekit"
SYS_USER = "tracekit"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
OTHER_EVENTS = ["UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop", "SessionStart", "SessionEnd"]
UNIT = """[Unit]
Description=Tracekit signer daemon
After=network.target

[Service]
User={user}
Group={user}
ExecStart={python} -m tracekit.daemon --home {home}
Environment=PYTHONPATH={pythonpath}
Restart=on-failure
UMask=0022
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={home}
PrivateTmp=true

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
ExecStart={python} -m tracekit.proxy --home {home}
Environment=PYTHONPATH={pythonpath}
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={home}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
LAUNCHD_DIR = "/Library/LaunchDaemons"
SYS_USER_DARWIN = "_tracekit"  # macOS system accounts are underscore-prefixed


def launchd_plist(label, user, python, module, home, pythonpath, extra_args=()):
    """A LaunchDaemon that runs `python -m <module> --home <home>` as the signer's own account."""
    import plistlib
    return plistlib.dumps({
        "Label": label, "UserName": user, "GroupName": user,
        "ProgramArguments": [python, "-m", module, "--home", home, *extra_args],
        "EnvironmentVariables": {"PYTHONPATH": pythonpath}, "RunAtLoad": True, "KeepAlive": True,
        "Umask": 0o022, "WorkingDirectory": home,
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
def _hook_command():
    try:
        import importlib.util
        spec = importlib.util.find_spec("tracekit")
        installed = bool(spec and spec.origin and "site-packages" in spec.origin)
    except Exception:
        installed = False
    if os.name == "nt":
        cmd = f'"{sys.executable}" -m tracekit.hook'
    else:
        cmd = f"{shlex.quote(sys.executable)} -m tracekit.hook"
    if installed:
        return cmd
    if os.name == "nt":
        encoded_root = base64.b64encode(ROOT.encode("utf-8")).decode("ascii")
        code = (f"import base64,sys; sys.path.insert(0, base64.b64decode('{encoded_root}').decode('utf-8')); "
                "from tracekit.hook import _entry; raise SystemExit(_entry())")
        return f'"{sys.executable}" -c "{code}"'
    return f"env PYTHONPATH={shlex.quote(ROOT)} {cmd}"


def _is_ours(group):
    return any("tracekit.hook" in (h.get("command") or "") or ("tracekit" in (h.get("command") or "") and "hook.py" in (h.get("command") or ""))
               for h in group.get("hooks", []))


class SettingsError(Exception):
    """A Claude Code settings file Tracekit cannot safely edit."""


def _atomic_write_json(path, obj, mode=None):
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def install_hooks(settings_path, uninstall=False, owner=None, proxy_url=None, extra=None):
    """Add (or remove) Tracekit's hooks in a Claude Code settings file. Idempotent; backs up the
    file before changing it; leaves other hooks and settings alone. proxy_url sets
    env.ANTHROPIC_BASE_URL (C3). Raises SettingsError instead of overwriting a file it cannot parse."""
    os.makedirs(os.path.dirname(settings_path) or ".", exist_ok=True)
    s, original = {}, None
    if os.path.exists(settings_path):
        try:
            with open(settings_path, encoding="utf-8") as f:
                original = f.read()
            s = json.loads(original) if original.strip() else {}
        except (OSError, ValueError) as e:
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
            e = {"hooks": [{"type": "command", "command": _hook_command(), "timeout": HOOK_TIMEOUT.get(ev, 30)}]}
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
        shutil.copy2(settings_path, f"{settings_path}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    _atomic_write_json(settings_path, s)
    if owner:
        os.chown(settings_path, owner.pw_uid, owner.pw_gid)


def _write_client_config(user_home, cfg, owner=None):
    d = os.path.join(user_home, ".tracekit-client")
    os.makedirs(os.path.join(d, "runs"), exist_ok=True)
    p = os.path.join(d, "config.json")
    with open(p, "w") as f:
        json.dump(cfg, f, indent=2)
    if owner:
        for root, dirs, files in os.walk(d):
            for x in [root] + [os.path.join(root, n) for n in dirs + files]:
                os.chown(x, owner.pw_uid, owner.pw_gid)
    os.chmod(p, 0o600)
    return p


def _write_signer_config(home, witnesses, checkpoint_every, socket_path, proxy=None, extra=None):
    cfg = {"checkpoint_every": checkpoint_every, "witnesses": witnesses, "socket": socket_path, "socket_mode": "0666"}
    if proxy:
        cfg["proxy"] = proxy
    cfg.update(extra or {})
    path = os.path.join(home, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(path, 0o600)


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
    from .peercred import has_peer_credentials
    if hasattr(socket, "AF_UNIX") and has_peer_credentials():
        return os.path.join(home, "tracekitd.sock"), None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"tcp://127.0.0.1:{port}", secrets.token_urlsafe(32)


def init_dev(home, witnesses, checkpoint_every=50, hooks_path=None, start=True, proxy=False, proxy_port=8787, fail_mode=None):
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
    if socket_token:
        signer_extra["socket_token"] = socket_token
    _write_signer_config(home, witnesses, checkpoint_every, sock, pcfg, signer_extra)
    cfg = {"socket": sock, "signer_home": home, "signer_isolation": "same-user", "mode": "dev"}
    if socket_token:
        cfg["socket_token"] = socket_token
    if proxy:
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{proxy_port}")
    client_home = os.environ.get("TRACEKIT_CLIENT_HOME")
    if client_home:
        os.makedirs(os.path.join(client_home, "runs"), exist_ok=True)
        client_config_path = os.path.join(client_home, "config.json")
        with open(client_config_path, "w") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(client_config_path, 0o600)
    else:
        _write_client_config(os.path.expanduser("~"), cfg)
    try:
        if start:
            if not _signer_healthy(home):
                start_dev_daemon(home)
            if proxy and not _proxy_healthy(home):
                start_dev_proxy(home)
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
    signer_config = read_json(os.path.join(home, "config.json"))
    for _ in range(100):
        if p.poll() is not None:
            break
        try:
            if client._rpc({"op": "status"}, config=signer_config).get("ok"):
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


def install_managed(proxy_url=None, managed_only=False, path=None):
    """C5: put the hooks in Claude Code's admin-managed settings, which users and projects cannot
    override. managed_only additionally sets allowManagedHooksOnly (user/project hooks stop running)."""
    path = path or MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]
    install_hooks(path, proxy_url=proxy_url, extra={"allowManagedHooksOnly": True} if managed_only else None)
    os.chmod(path, 0o644)
    return path


def init_system(target_user, witnesses, checkpoint_every=50, project=None, no_service=False, proxy=False, proxy_port=8787,
                managed=False, managed_only=False, fail_mode=None, experimental_macos=False, hooks=True):
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
    for sub, mode in (("", 0o755), ("keys", 0o700), ("ledger", 0o755), ("blobs", 0o755)):
        p = os.path.join(SYS_HOME, sub)
        os.makedirs(p, exist_ok=True)
        os.chown(p, tk.pw_uid, tk.pw_gid)
        os.chmod(p, mode)
    sock = os.path.join(SYS_HOME, "tracekitd.sock")
    if not witnesses:
        witnesses = [f"git:{os.path.join(SYS_HOME, 'witness')}"]
        print("note: using a local git witness only. It protects against the agent's user, not against root on this "
              "machine. Point --witness at a remote repository the security team owns (docs/witnesses.md).")
    pcfg = {"port": proxy_port, "upstream": _upstream(), "fail_mode": fail_mode or "open"} if proxy else None
    _write_signer_config(SYS_HOME, witnesses, checkpoint_every, sock, pcfg)
    os.chown(os.path.join(SYS_HOME, "config.json"), tk.pw_uid, tk.pw_gid)
    # generate the key as the tracekit user so root-only reads are the only other path to it
    env = dict(os.environ, PYTHONPATH=ROOT)
    subprocess.run(["runuser" if shutil.which("runuser") else "sudo", "-u", tk.pw_name, "--", sys.executable, "-c",
                    f"import sys; sys.path.insert(0,{ROOT!r}); from tracekit.ledger import Keys; Keys.load_or_create({os.path.join(SYS_HOME, 'keys')!r})"],
                   check=True, env=env)
    if not no_service:
        if darwin:
            for label, module, enabled in (("dev.tracekit.tracekitd", "tracekit.daemon", True),
                                            ("dev.tracekit.proxy", "tracekit.proxy", proxy)):
                if not enabled:
                    continue
                plist = os.path.join(LAUNCHD_DIR, label + ".plist")
                with open(plist, "wb") as f:
                    f.write(launchd_plist(label, tk.pw_name, sys.executable, module, SYS_HOME, ROOT))
                os.chmod(plist, 0o644)
                subprocess.run(["launchctl", "bootstrap", "system", plist], check=False)
        else:  # systemd
            with open("/etc/systemd/system/tracekitd.service", "w") as f:
                f.write(UNIT.format(user=tk.pw_name, python=sys.executable, home=SYS_HOME, pythonpath=ROOT))
            if proxy:
                with open("/etc/systemd/system/tracekit-proxy.service", "w") as f:
                    f.write(PROXY_UNIT.format(user=tk.pw_name, python=sys.executable, home=SYS_HOME, pythonpath=ROOT))
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", "--now", "tracekitd"], check=False)
            if proxy:
                subprocess.run(["systemctl", "enable", "--now", "tracekit-proxy"], check=False)
    cfg = {"socket": sock, "signer_home": SYS_HOME, "signer_isolation": "separate-user", "mode": "system"}
    if proxy:
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{proxy_port}")
    _write_client_config(owner.pw_dir, cfg, owner)
    if not hooks:
        settings = None  # hooks come from elsewhere (the Claude Code plugin)
    elif managed:
        settings = install_managed(cfg.get("proxy_url"), managed_only)
    else:
        settings = os.path.join(project, ".claude", "settings.json") if project else os.path.join(owner.pw_dir, ".claude", "settings.json")
        install_hooks(settings, owner=owner, proxy_url=cfg.get("proxy_url"))
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
