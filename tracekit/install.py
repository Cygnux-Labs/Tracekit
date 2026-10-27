"""`tracekit init` / `status` / `uninstall` (P1, I1, I2).

System mode (default, needs root; Linux, experimental on macOS): a `tracekit` OS user owns the key and the
ledger; tracekitd runs as that user under systemd (launchd on macOS).
Dev mode (--dev): the signer runs as *your* user. Convenient, but the agent could rewrite the
ledger, so every run is labelled signer_isolation=same-user and verify says so.
"""
import errno
import json
import os
import re
import secrets
import shlex
import socket
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

try:
    import grp
    import pwd
except ImportError:
    grp = pwd = None

from .core import b64e, read_json, read_text
from . import client, harness_helper
from .deploy import files
from .wiki import wiki_url

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SYS_HOME = "/var/lib/tracekit"
SYS_USER = "tracekit"
OPT = "/opt/tracekit"   # system mode: root-owned virtualenv the signer and hooks run from
OPT_PYTHON = os.path.join(OPT, "bin", "python")
SYSTEMD_DIR = "/etc/systemd/system"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
OTHER_EVENTS = ["UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop", "SessionStart", "SessionEnd"]
# systemd hardening of every Tracekit service (04-design §9): no capabilities, a read-only system, no devices, kernel
# knobs or namespaces. Services that need an exception (a device for an external signer, the harness helper's
# capabilities) drop or replace a line.
HARDENING = """NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
"""
UNIT = """[Unit]
Description=Tracekit signer daemon
After=network.target

[Service]
User={user}
Group={user}
ExecStart={python} -I -m tracekit.daemon --home {home}
Restart=on-failure
UMask=0027
ReadWritePaths={home}
""" + HARDENING.replace("PrivateDevices=true\n", "") + """RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""   # an external signer (config.json `signer`) may talk to a TPM or HSM device, so tracekitd keeps /dev
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
ReadWritePaths={home}
""" + HARDENING + """RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""
LAUNCHD_DIR = "/Library/LaunchDaemons"
SYS_USER_DARWIN = "_tracekit"  # macOS system accounts are underscore-prefixed
# v2 system mode (`tracekit init --v2`): the v2 signer service, as its own user, configured by a root-owned signer.yaml
V2_USER, V2_USER_DARWIN = "tracekit-signer", "_tracekit_signer"
V2_DATA = "/var/lib/tracekit-signer"   # keys and log: 0700, owned by the signer's user
V2_CONFIG = "/etc/tracekit/signer.yaml"
V2_UNIT, V2_LABEL = "tracekit-signer", "dev.tracekit.signer"
# the transcript tailer (tracekit.tailer): its own user, which reads the agent's transcripts through an ACL; the agent
# starts it through sudo, and the signer lets its uid make only the calls of TAILER_METHODS
V2_TAILER, V2_TAILER_DARWIN = "tracekit-tailer", "_tracekit_tailer"
TAILER_SUDOERS = "/etc/sudoers.d/tracekit-tailer"
TAILER_METHODS = ["model_event", "state_write", "tailer_lost", "tailer_heartbeat", "status"]
V2_RUN = {"linux": "/run/tracekit-signer", "darwin": "/Library/Application Support/tracekit-signer"}   # the socket's dir
V2_UNIT_TEXT = """[Unit]
Description=Tracekit v2 signer
After=network.target

[Service]
User={user}
Group={user}
ExecStart={python} -I -m tracekit signer serve --config {config}
Restart=on-failure
UMask=0027
RuntimeDirectory={unit}
RuntimeDirectoryMode=0755
ReadWritePaths={data}
""" + HARDENING + """RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""
# the egress observer (`init --v2 --egress`, Linux): tracekit.egress as its own user on loopback, and a firewall unit
# whose owner-match rule lets the agent's uid reach only loopback, so its outside traffic goes through the observer
V2_EGRESS, EGRESS_FIREWALL = "tracekit-egress", "tracekit-egress-firewall"
EGRESS_CONFIG, EGRESS_LISTEN = "/etc/tracekit/egress.yaml", "127.0.0.1:3128"
EGRESS_UNIT_TEXT = """[Unit]
Description=Tracekit egress observer
After=network.target {signer}.service

[Service]
User={user}
Group={user}
ExecStart={python} -I -m tracekit egress serve --config {config}
Restart=on-failure
""" + HARDENING + """RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""
# its own unit, so a stopped or crashed observer leaves the agent's traffic blocked, never unobserved ($$: systemd's $)
FIREWALL_UNIT_TEXT = """[Unit]
Description=Tracekit: {agent}'s outside traffic only through the egress observer
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for t in iptables ip6tables; do $$t -N TRACEKIT-EGRESS 2>/dev/null; $$t -F TRACEKIT-EGRESS && \
$$t -A TRACEKIT-EGRESS -o lo -j RETURN && $$t -A TRACEKIT-EGRESS -j REJECT && \
{{ $$t -C OUTPUT -m owner --uid-owner {uid} -j TRACEKIT-EGRESS 2>/dev/null || \
$$t -I OUTPUT -m owner --uid-owner {uid} -j TRACEKIT-EGRESS; }} || exit 1; done'
ExecStop=/bin/sh -c 'for t in iptables ip6tables; do $$t -D OUTPUT -m owner --uid-owner {uid} -j TRACEKIT-EGRESS; \
$$t -F TRACEKIT-EGRESS; $$t -X TRACEKIT-EGRESS; done; true'

[Install]
WantedBy=multi-user.target
"""
# the harness helper (tracekit.harness_helper): one per signer, socket-activated, the only process that reads the agent's
# /proc/<pid>/exe; its socket is in a directory only the signer's user can reach (V2_DATA; HELPER_DIR for v1)
V2_HELPER, V1_HELPER = "tracekit-harness-helper", "tracekitd-harness-helper"
V2_HELPER_SOCKET = os.path.join(V2_DATA, "harness-helper.sock")
HELPER_DIR = os.path.join(SYS_HOME, "helper")
V1_HELPER_SOCKET = os.path.join(HELPER_DIR, "harness-helper.sock")
HELPER_LABEL = "dev.tracekit.harness-helper"


def helper_units(name, signer, sig, sock):
    """(.socket, .service) unit texts of the harness helper that answers the signer unit `signer`, running as `sig`."""
    socket_unit = (f"[Unit]\nDescription=Tracekit harness helper socket ({signer})\n\n[Socket]\nListenStream={sock}\n"
                   f"SocketUser={sig.pw_name}\nSocketGroup={sig.pw_name}\nSocketMode=0600\nRemoveOnStop=true\n\n"
                   "[Install]\nWantedBy=sockets.target\n")
    service = (f"[Unit]\nDescription=Tracekit harness helper ({signer})\nRequires={name}.socket\n\n[Service]\n"
               f"ExecStart={OPT_PYTHON} -I -m tracekit.harness_helper --allow-uid {sig.pw_uid}\nUMask=0077\n"
               + HARDENING.replace("CapabilityBoundingSet=\n", f"CapabilityBoundingSet={harness_helper.HELPER_CAPS}\n")
               + "RestrictAddressFamilies=AF_UNIX\nPrivateNetwork=true\n")
    return socket_unit, service


def _install_helper(name, signer, sig, sock, darwin):
    """Write and start the harness helper for the signer `signer` running as `sig` (systemd; launchd on macOS)."""
    if darwin:
        import plistlib
        plist = os.path.join(LAUNCHD_DIR, HELPER_LABEL + ".plist")
        _write_root_file(plist, plistlib.dumps({
            "Label": HELPER_LABEL, "RunAtLoad": True, "KeepAlive": True, "Umask": 0o077,
            "ProgramArguments": [OPT_PYTHON, "-I", "-m", "tracekit.harness_helper", "--allow-uid", str(sig.pw_uid),
                                 "--socket", sock]}))
        subprocess.run(["launchctl", "bootout", "system", plist], check=False)
        subprocess.run(["launchctl", "bootstrap", "system", plist], check=False)
        return
    for suffix, text in zip((".socket", ".service"), helper_units(name, signer, sig, sock)):
        _write_root_file(os.path.join(SYSTEMD_DIR, name + suffix), text.encode())
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", name + ".socket"], check=False)


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


def _create_system_user_darwin(name, home=SYS_HOME):
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
             ("-create", f"/Users/{name}", "NFSHomeDirectory", home),
             ("-create", f"/Users/{name}", "RealName", "Tracekit signer"),
             ("-create", f"/Users/{name}", "IsHidden", "1")]
    for step in steps:
        r = _dscl(*step)
        if r.returncode != 0:
            raise SystemExit(f"dscl {' '.join(step)} failed: {r.stderr.strip()}")


MANAGED_SETTINGS = {"linux": "/etc/claude-code/managed-settings.json",
                    "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json"}
HOOK_TIMEOUT = {"PreToolUse": 600, "SessionEnd": 15}   # PreToolUse may hold a call for approval (C8)
V2_HOOK = "tracekit.integrations.claude_code"
SIGNER_ENV = ("TRACEKIT_SIGNER", "TRACEKIT_SIGNER_TOKEN_FILE", "TRACEKIT_SIGNER_CA")   # what init --remote --v2 sets
V2_HOOKS = (V2_HOOK, "tracekit.integrations.harness_hooks")   # Claude Code's, the other harnesses' (agent_hooks.V2_MODULE)
PLUGIN = "tracekit@tracekit"   # the Claude Code plugin, as enabledPlugins names it
PLUGIN_NAME = "tracekit"


def _blocking(run, unless="", pre=True, json_deny=False):
    """`run` in a shell that turns any exit status but 0 and 2 (the hook could not run) into 2, a blocked call, unless
    the shell command `unless` exits first. Not `pre` (any event but a pre-tool call): every status but 0 becomes 1, a
    non-blocking error the harness shows, as 2 there would block a prompt or send the agent back to work at Stop.
    json_deny: the call is blocked by a JSON deny on stdout at exit 0 instead (Antigravity CLI reads only that), on any
    status but 0 (its hook answers every call at exit 0)."""
    if not pre:
        script = (f"{run}; s=$?; [ $s = 0 ] && exit 0; [ $s = 1 ] || [ $s = 2 ] || "
                  "echo 'tracekit: the hook could not run; event not recorded' >&2; exit 1")
    else:
        why = "tracekit: the hook could not run; call blocked (fail-closed)"
        block = (f"echo '{json.dumps({'decision': 'deny', 'reason': why})}'; exit 0" if json_deny else
                 f"echo '{why}' >&2; exit 2")
        passed = "[ $s = 0 ] && exit 0" if json_deny else "[ $s = 0 ] || [ $s = 2 ] && exit $s"
        script = f"{run}; s=$?; {passed}; {unless}{block}"
    return f"/bin/sh -c {shlex.quote(script)}"


def _hook_command(module="tracekit.hook", func="_entry", args=(), python=None, pre=True, json_deny=False):
    """Shell command that runs `module.func(*args)`. Python runs isolated (-I): the working directory, user
    site-packages and PYTHON* variables are not on the import path, so the harness's cwd cannot shadow tracekit.
    python: an interpreter that has tracekit installed (system mode: OPT_PYTHON). If it cannot run the hook (the
    package or interpreter is missing), a pre-tool call (`pre`) is blocked unless the system config sets fail_mode
    open (then it runs, with an error the harness shows); a v2 hook, or one that answers in JSON (json_deny), that
    cannot run blocks the call in dev mode too. Any other event is never blocked (_blocking, which json_deny goes to)."""
    if python:
        return _blocking(" ".join([shlex.quote(python), "-I", "-m", module, *args]),
                         f"grep -Eq '\"fail_mode\"[[:space:]]*:[[:space:]]*\"open\"' {client.SYSTEM_CONFIG} 2>/dev/null "
                         "&& { echo 'tracekit: the hook could not run; call NOT recorded (fail_mode open)' >&2; "
                         "exit 1; }; ", pre, json_deny)
    cmd = _dev_hook_command(module, func, args)
    # lean: on Windows a dev v2 or agy hook that cannot start fails open (no POSIX shell to wrap it in); wrap it in
    # PowerShell when Windows dev mode must fail closed
    return _blocking(cmd, pre=pre, json_deny=json_deny) if (module in V2_HOOKS or json_deny) and os.name != "nt" else cmd


def _dev_hook_argv(module, func, args):
    """argv that runs `module.func(*args)` with this interpreter under -I: -m where tracekit is installed in a
    site-packages -I keeps, else with the directory tracekit is in (a checkout, a --user install) put on sys.path.
    From a git working tree, a hook that can't import tracekit there (a branch switch, a rebase) prints one line in
    place of the traceback: the tree, the branch it is on now and the one it was on here, and how to fix it."""
    try:
        import importlib.util
        import site
        spec = importlib.util.find_spec("tracekit")
        user_site = site.getusersitepackages()
        installed = bool(spec and spec.origin and "site-packages" in spec.origin
                         and not spec.origin.startswith(user_site))
    except Exception:
        installed = False
    if installed:
        return [sys.executable, "-I", "-m", module, *args]
    # base64: a path or branch name can hold any quote or shell character
    code = (f"import base64,sys; r=base64.b64decode('{b64e(ROOT.encode('utf-8'))}').decode('utf-8'); "
            "sys.path.insert(0, r); ")
    call = f"raise SystemExit({func}({', '.join(map(repr, args))}))"
    branch = _branch(ROOT)
    if branch:
        # lean: the hooks still run the working tree, so a branch switch there still breaks them and this only says
        # what happened; run them from a copy init makes if switching branches under them keeps happening
        # lean: the hook's command doesn't carry --remote or --project, so a hook init wired with them is told this
        # command without them; carry them here if those installs from a working tree hit this
        init = "tracekit init --dev" + (" --v2" if module in V2_HOOKS else "") + (
            "" if module in ("tracekit.hook", V2_HOOK) else f" --agent {args[0]}")
        # exec: a try statement can't follow `;` on one line, and the command must stay one line (Windows); git that
        # can't run (not on the hook's PATH) gives the plain traceback
        code += (f"import os,shlex,subprocess; w=base64.b64decode('{b64e(branch.encode('utf-8'))}').decode('utf-8'); "
                 "exec('''def h(t,e,b):\\n try: n=subprocess.run(['git','-C',r,'symbolic-ref','-q','--short','HEAD'],"
                 "capture_output=True,text=True,env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')})"
                 ".stdout.strip() or 'a detached HEAD'\\n except OSError: return sys.__excepthook__(t,e,b)\\n "
                 "print(f'tracekit: the hook runs Tracekit from the working tree {r}, which cannot import it now "
                 "({t.__name__}: {e}): it is on {n} there, and was on {w} when the hooks were installed. Check out {w} "
                 "there again (git -C {shlex.quote(r)} checkout {shlex.quote(w)}) if a branch switch broke it, or run "
                 f"{init} again from a Tracekit installed outside a working tree (pip install, not pip install -e)', "
                 "file=sys.stderr)'''); sys.excepthook=h; ")
        call = "sys.excepthook=sys.__excepthook__; " + call
    return [sys.executable, "-I", "-c", f"{code}from {module} import {func}; {call}"]


def _branch(root):
    """The branch (else the commit) of the git working tree `root`, or None when it isn't one."""
    if not os.path.exists(os.path.join(root, ".git")):
        return None
    for args in (("symbolic-ref", "-q", "--short", "HEAD"), ("rev-parse", "--short", "HEAD")):
        try:
            out = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                                 env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")}).stdout.strip()
        except OSError:   # no git
            return None
        if out:
            return out
    return None


def _dev_hook_command(module, func, args):
    argv = _dev_hook_argv(module, func, args)
    py = f'"{argv[0]}"' if os.name == "nt" else shlex.quote(argv[0])
    if argv[2] == "-m":
        return " ".join([py, *argv[1:]])
    return f'{py} -I -c "{argv[3]}"' if os.name == "nt" else f"{py} -I -c {shlex.quote(argv[3])}"


def _hook_version(group):
    """"v2" for a group running the v2 hook, "v1" for the v1 hook, else None."""
    hooks = group.get("hooks") if isinstance(group, dict) else None
    cmds = [h["command"] for h in hooks if isinstance(h, dict) and isinstance(h.get("command"), str)] \
        if isinstance(hooks, list) else []
    if any(V2_HOOK in c for c in cmds):
        return "v2"
    if any("tracekit.hook" in c or re.search(r"tracekit[/\\]hook\.py", c) for c in cmds):
        return "v1"
    return None


def _is_ours(group):
    return _hook_version(group) is not None


class SettingsError(Exception):
    """A Claude Code settings file Tracekit cannot safely edit."""


class ServiceError(Exception):
    """A service system init installed did not start; init did everything else, then raised this."""


def _atomic_write_json(path, obj, mode=0o600):
    files.write_json(path, obj, mode)


def _backup(path, data):
    d = files.open_dir(os.path.dirname(os.path.abspath(path)))
    try:
        return files.backup(d, os.path.basename(path), data)
    finally:
        files.close(d)


def user_settings():
    """Claude Code's user settings file: in $CLAUDE_CONFIG_DIR when set (Claude Code's own setting for another config
    dir), else ~/.claude."""
    return os.path.join(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude"),
                        "settings.json")


def user_settings_all():
    """Every user settings file hooks may have gone to: $CLAUDE_CONFIG_DIR's when set, ~/.claude's, and the one
    `tracekit init` recorded (hooks_settings), each once (by realpath). Hooks installed from a shell with
    CLAUDE_CONFIG_DIR are found from one without it, and back."""
    out, seen = [], set()
    try:
        recorded = client.client_config().get("hooks_settings")
    except client.SystemConfigError:   # doctor reports an untrusted system config; it records no hooks file
        recorded = None
    for p in (user_settings(), os.path.join(os.path.expanduser("~"), ".claude", "settings.json"),
              *([recorded] if isinstance(recorded, str) else [])):
        if os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            out.append(p)
    return out


AGENT_FILE_MAX = 4 << 20   # bytes of an agent's settings file doctor and init read at most


def agent_file(path):
    """The bytes of a settings file the agent's user controls: a regular file (a symlink to one is read, as the agent
    reads it) of at most AGENT_FILE_MAX bytes, opened without blocking, so a FIFO or a device can't hang or flood the
    reader. OSError otherwise (FileNotFoundError when missing)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        data = f.read(AGENT_FILE_MAX + 1)
    if len(data) > AGENT_FILE_MAX:
        raise OSError(errno.EFBIG, f"larger than {AGENT_FILE_MAX} bytes", path)
    return data


def plugin_enabled(user=None):
    """The Claude Code settings file that enables the Tracekit plugin (plugin/, whose hooks are the ones init writes),
    or None. Reads `user` (default user_settings_all()), the working directory's project and local settings, then the
    managed settings: a later file's enabledPlugins entry wins, as in Claude Code. -> (settings path, plugin key)."""
    # lean: enabledPlugins plus Claude Code's install state; a plugin on through --plugin-dir, --settings or its
    # defaultEnabled with no entry, or from a claude.ai-synced marketplace (no known_marketplaces.json entry), goes
    # unseen; read those too if users hit that
    active, order, managed = {}, 0, MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]
    project = [os.path.join(os.getcwd(), ".claude", f) for f in ("settings.json", "settings.local.json")]
    for p in (*(user or user_settings_all()), *project, managed):
        try:
            enabled = json.loads(agent_file(p)).get("enabledPlugins", {})
        except (OSError, ValueError, AttributeError):   # missing, or not a settings file
            continue
        if not isinstance(enabled, dict):
            continue
        for key, value in enabled.items():
            if (key == PLUGIN or key.rpartition("@")[0] == PLUGIN_NAME and
                    _installed_tracekit_plugin(key, p)) and isinstance(value, bool):
                order += 1
                if value:
                    active[key] = (p, key, order)
                else:
                    active.pop(key, None)
    return max(active.values(), key=lambda found: found[2])[:2] if active else None


def _plugin_config_dirs(settings_path):
    """The Claude config root whose plugins/ holds the install state for a plugin enabled in settings_path: a user
    settings file's own directory (another user's too: system-mode doctor reads the agent's), else this user's.
    Claude Code never writes plugin state into a project's .claude."""
    parent = os.path.dirname(os.path.abspath(settings_path))
    config = os.environ.get("CLAUDE_CONFIG_DIR")
    project = os.path.join(os.path.abspath(os.getcwd()), ".claude")
    if (os.path.basename(parent) == ".claude" and parent != project) or (config and parent == os.path.abspath(config)):
        return [os.path.realpath(parent)]
    return [os.path.realpath(config or os.path.join(os.path.expanduser("~"), ".claude"))]


def _installed_tracekit_plugin(plugin_id, settings_path):
    """True only when Claude's install record and marketplace catalog point at Tracekit's plugin directory."""
    def tracekit_repo(value):
        if not isinstance(value, str):
            return False
        value = value.removeprefix("https://github.com/").removeprefix("http://github.com/")
        value = value.removeprefix("git@github.com:").rstrip("/").removesuffix(".git")
        return value == "Cygnux-Labs/Tracekit"

    marketplace = plugin_id.rpartition("@")[2]
    for config_dir in _plugin_config_dirs(settings_path):
        try:
            installed = json.loads(agent_file(os.path.join(config_dir, "plugins", "installed_plugins.json")))
            records = installed.get("plugins", {}).get(plugin_id)
            records = records if isinstance(records, list) else [records]
            if not any(isinstance(record, dict) and isinstance(record.get("installPath"), str)
                       and record.get("installPath")
                       for record in records):
                continue
            known = json.loads(agent_file(os.path.join(config_dir, "plugins", "known_marketplaces.json")))
            market = known.get(marketplace)
            location = market.get("installLocation") if isinstance(market, dict) else None
            location = location if isinstance(location, str) and os.path.isabs(location) else None
            source = market.get("source") if isinstance(market, dict) else None
            manifest_path = os.path.join(location, ".claude-plugin", "marketplace.json") if location else None
            manifest = json.loads(agent_file(manifest_path)) if manifest_path else {}
        except (OSError, ValueError, AttributeError, TypeError):
            continue
        plugins = manifest.get("plugins", ()) if isinstance(manifest, dict) else ()
        entry = next((p for p in plugins if isinstance(p, dict) and p.get("name") == PLUGIN_NAME), None) \
            if isinstance(plugins, list) else None
        plugin_source = entry.get("source") if entry else None
        if isinstance(plugin_source, str):
            repo = source.get("repo") if isinstance(source, dict) and source.get("source") == "github" else None
            path = plugin_source.replace("\\", "/").removeprefix("./").strip("/")
            if tracekit_repo(repo) and path == "plugin":
                return True
        elif isinstance(plugin_source, dict):
            repo = plugin_source.get("repo") or plugin_source.get("url")
            path = plugin_source.get("path")
            path = path.replace("\\", "/").strip("/") if isinstance(path, str) else ""
            if plugin_source.get("source") == "git-subdir" and tracekit_repo(repo) and path == "plugin":
                return True
    return False


def install_hooks(settings_path, uninstall=False, owner=None, proxy_url=None, extra=None, mode=0o600, python=None,
                  module="tracekit.hook", signer=None, thinking=False):
    """Add (or remove) Tracekit's hooks in a Claude Code settings file. Idempotent; backs up the
    file before changing it; leaves other hooks and settings alone. proxy_url sets
    env.ANTHROPIC_BASE_URL (C3), signer env.TRACEKIT_SIGNER or a dict of env variables (each removed on uninstall
    while it still has that value); the SIGNER_ENV variables it doesn't name are removed. thinking: also turn
    Claude Code's thinking summaries on (THINKING: true) unless the file already sets them; uninstall turns them off
    again only when init turned them on and they are still on (_thinking). Returns the file's THINKING setting then.
    Raises SettingsError instead of overwriting a file it cannot parse,
    or one that is a symlink. With owner (as root) the whole edit runs as that user. python, module: see _hook_command."""
    if owner is not None:
        return files.as_user(owner, install_hooks, settings_path, uninstall, None, proxy_url, extra, mode, python,
                             module, signer, thinking, errors=(SettingsError,))
    settings_path = os.path.abspath(settings_path)
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    try:
        d = files.open_dir(os.path.dirname(settings_path))
        try:
            return _install_hooks_at(d, settings_path, uninstall, proxy_url, extra, mode, python, module, signer,
                                     thinking)
        finally:
            files.close(d)
    except files.UnsafePath as e:
        raise SettingsError(f"{settings_path}: {e}") from e


def _parse_settings(raw, settings_path):
    """The settings object in a file's bytes `raw` ({} for no file or an empty one); SettingsError if it isn't one."""
    try:
        s = json.loads(raw.decode("utf-8")) if raw and raw.strip() else {}
    except ValueError as e:
        raise SettingsError(f"{settings_path} is not valid JSON ({e}); fix or remove it, then retry. "
                            "Tracekit did not change it.") from e
    if not isinstance(s, dict):
        raise SettingsError(f"{settings_path} must contain a JSON object; Tracekit did not change it.")
    return s


def _install_hooks_at(d, settings_path, uninstall, proxy_url, extra, mode, python=None, module="tracekit.hook",
                      signer=None, thinking=False):
    name = os.path.basename(settings_path)
    raw = files.read(d, name)
    s = _parse_settings(raw, settings_path)
    hooks = s.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError(f"'hooks' in {settings_path} must be an object; Tracekit did not change it.")
    new, replaced = "v2" if module == V2_HOOK else "v1", set()
    for ev in TOOL_EVENTS + OTHER_EVENTS:
        existing = hooks.get(ev, [])
        if not isinstance(existing, list):
            raise SettingsError(f"hooks.{ev} in {settings_path} must be a list; Tracekit did not change it.")
        groups = []
        for g in existing:
            v = _hook_version(g) if isinstance(g, dict) else None
            if v is None:
                groups.append(g)
            elif uninstall or v != new:
                replaced.add(v)
        if not uninstall:
            cmd = _hook_command(module, args=(ev,) if module == V2_HOOK else (), python=python,   # v2: names its event
                                pre=ev == "PreToolUse")
            e = {"hooks": [{"type": "command", "command": cmd, "timeout": HOOK_TIMEOUT.get(ev, 30)}]}
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
    signer = {"TRACEKIT_SIGNER": signer} if isinstance(signer, str) else signer or {}
    for k in SIGNER_ENV:   # an earlier init's signer that this one doesn't name
        if k not in signer:
            env.pop(k, None)
    for k, v in signer.items():
        if not uninstall:
            env[k] = v
        elif env.get(k) == v:
            env.pop(k)
    if env:
        s["env"] = env
    else:
        s.pop("env", None)
    for k, v in (extra or {}).items():
        if uninstall:
            s.pop(k, None)
        else:
            s[k] = v
    _thinking(s, thinking, uninstall)
    if raw is not None:
        if _parse_settings(raw, settings_path) == s:
            return s.get(THINKING)
        files.backup(d, name, raw)
    files.write(d, name, files.json_bytes(s), mode)
    if replaced:
        old = " and ".join(sorted(replaced))
        print(f"Tracekit {old} hooks removed from {settings_path}" if uninstall else
              f"Tracekit {old} hooks replaced by {new} hooks in {settings_path}")
    return s.get(THINKING)


THINKING = "showThinkingSummaries"   # Claude Code keeps the model's thinking summaries in its transcript
THINKING_MARKER = "_tracekit_thinking"   # init turned THINKING on, so uninstall turns it off again


def _thinking(s, on, uninstall):
    """Turn THINKING on in settings `s` unless it sets it (a person's own setting stays), marking that init did; on
    uninstall, remove it again only when init set it and it is still true."""
    if uninstall:
        if s.pop(THINKING_MARKER, None) and s.get(THINKING) is True:
            s.pop(THINKING)
    elif on and THINKING not in s:
        s[THINKING], s[THINKING_MARKER] = True, True


def thinking_on(settings_path):
    """Claude Code's thinking summaries on in `settings_path` (_thinking), its hooks untouched: for the plugin's users,
    whose hooks come from the plugin. -> the file's THINKING setting. Raises SettingsError as install_hooks does."""
    settings_path = os.path.abspath(settings_path)
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    try:
        d = files.open_dir(os.path.dirname(settings_path))
        try:
            name = os.path.basename(settings_path)
            raw = files.read(d, name)
            s = _parse_settings(raw, settings_path)
            if THINKING not in s:
                _thinking(s, True, False)
                if raw is not None:
                    files.backup(d, name, raw)
                files.write(d, name, files.json_bytes(s), 0o600)
            return s.get(THINKING)
        finally:
            files.close(d)
    except files.UnsafePath as e:
        raise SettingsError(f"{settings_path}: {e}") from e


def thinking_line(settings, on):
    """What init says about Claude Code's thinking summaries (`on`: the THINKING setting of `settings`)."""
    if on is True:
        return (f"thinking summaries: on ({THINKING} in {settings}), so `tracekit analyze --v2` can read the model's "
                "reasoning; for headless runs pass `claude -p --thinking-display summarized`; init "
                "--no-thinking-summaries leaves the setting alone")
    return (f"thinking summaries: off ({settings} sets {THINKING} to {str(on).lower()}): `tracekit analyze --v2` can't "
            f"read the model's reasoning; set {THINKING} to true to check it")


def _my_uid():
    return {os.geteuid()} if hasattr(os, "geteuid") else None


def _write_client_config(user_home, cfg, owner=None):
    """Write ~/.tracekit-client/config.json; with owner (as root) the write runs as that user."""
    return files.as_user(owner, _write_client_dir, os.path.join(user_home, ".tracekit-client"), cfg)


def _write_client_dir(path, cfg):
    """Create path/ and path/runs (owned by the current user) and write path/config.json (0600), following no symlink."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    parent = files.open_dir(os.path.dirname(path))
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
    """No `witnesses` or `checkpoint_every`: an earlier init's, else a local git witness and 50."""
    cfg = {"socket": socket_path, "socket_mode": "0666"}
    if proxy:
        cfg["proxy"] = proxy
    cfg.update(extra or {})
    d = _signer_dir(home, tk_user)
    try:
        # re-running init keeps what it does not replace: dropping the external signer would make the daemon fall back
        # to a new file key, dropping the pin or the harnesses would loosen the policy and harness checks, dropping a
        # remote witness the tamper evidence
        old = _read_config(d)
        cfg["witnesses"] = witnesses or old.get("witnesses") or [f"git:{os.path.join(home, 'witness')}"]
        cfg["checkpoint_every"] = checkpoint_every or old.get("checkpoint_every") or 50
        for k in ("signer", "pinned_policy_hash", "harnesses", "harness_binding"):
            if k not in cfg and k in old:
                cfg[k] = old[k]
        _save_config(d, cfg, tk_user)
    finally:
        files.close(d)
    return cfg


HARNESS_COMMANDS = {"claude": "claude", "codex": "codex", "cursor": "cursor-agent", "gemini": "gemini",
                    "opencode": "opencode", "qwen": "qwen"}


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
    from .harness_helper import trusted_file
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
          f"process running as the agent's user can start a run ({wiki_url('docs/threat-model-laptop.md')}). Re-run with "
          "--harness PATH.")
    return {"harness_binding": "off"}


def _upstream():
    """Where the proxy forwards: whatever the user already pointed Claude Code at, else Anthropic."""
    cur = os.environ.get("ANTHROPIC_BASE_URL", "")
    return cur if cur and "127.0.0.1" not in cur and "localhost" not in cur else "https://api.anthropic.com"


def _validate_init_options(checkpoint_every, proxy, proxy_port):
    try:
        checkpoint_every = None if checkpoint_every is None else int(checkpoint_every)
        proxy_port = int(proxy_port)
    except (TypeError, ValueError) as e:
        raise ValueError("checkpoint interval and proxy port must be integers") from e
    if checkpoint_every is not None and checkpoint_every < 1:
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


MAX_UNIX_SOCKET_PATH = 103  # sun_path holds 104 bytes on macOS/BSD (108 on Linux), including the final NUL


def _dev_socket(home):
    """Unix socket where the kernel names the caller, else token-authenticated TCP on port 0: tracekitd binds a free
    port itself and writes it to its config (daemon.serve). A signer that is already running keeps its endpoint."""
    from .peercred import has_peer_credentials
    if hasattr(socket, "AF_UNIX") and has_peer_credentials():
        path = os.path.join(os.path.abspath(home), "tracekitd.sock")
        if len(path.encode()) > MAX_UNIX_SOCKET_PATH:
            raise SystemExit(f"the signer home path is too long for a Unix socket ({len(path.encode())} bytes, the "
                             f"limit is {MAX_UNIX_SOCKET_PATH}): use a shorter --home (or TMPDIR for `tracekit demo`)")
        return path, None
    if _signer_healthy(home):
        old = read_json(os.path.join(home, "config.json"))
        if str(old.get("socket", "")).startswith("tcp://") and old.get("socket_token"):
            return old["socket"], old["socket_token"]
    return "tcp://127.0.0.1:0", secrets.token_urlsafe(32)


def init_dev(home, witnesses, checkpoint_every=None, hooks_path=None, start=True, proxy=False, proxy_port=8787, fail_mode=None,
             signer=None):
    checkpoint_every, proxy_port = _validate_init_options(checkpoint_every, proxy, proxy_port)
    home = os.path.abspath(home)
    for sub in ("", "keys", "ledger", "blobs"):
        os.makedirs(os.path.join(home, sub), exist_ok=True)
    sock, socket_token = _dev_socket(home)
    pcfg = {"port": proxy_port, "upstream": _upstream(), "fail_mode": fail_mode or "open"} if proxy else None
    # dev mode: the agent and the approver are the same OS user, so approvals are allowed but labelled untrustworthy
    signer_extra = {"mode": "dev", "allow_same_user_approval": True}
    if signer:
        signer_extra["signer"] = signer
    if socket_token:
        signer_extra["socket_token"] = socket_token
    _write_signer_config(home, witnesses, checkpoint_every, sock, pcfg, signer_extra)
    cfg = {"socket": sock, "signer_home": home, "signer_isolation": "same-user", "mode": "dev"}
    if hooks_path:   # where the hooks went, so uninstall finds them from a shell without the same CLAUDE_CONFIG_DIR
        cfg["hooks_settings"] = os.path.abspath(hooks_path)
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
        except (client.SignerUnavailable, PermissionError, ValueError):   # its config mid-write (Windows: locked)
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
    _write_root_file(client.SYSTEM_CONFIG, files.json_bytes(cfg))


def _v2_client_keys():
    """The v2 system mode keys of the existing system config, which a v1 (re)install must keep."""
    try:
        sc = client.system_config() or {}
    except client.SystemConfigError:
        sc = {}
    return {k: sc[k] for k in ("signer", "hooks", "tailer") if k in sc}


def _write_root_file(path, data):
    """Write `path` root-owned and 0644, in a root-owned 0755 directory (created if missing), following no symlink."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    d = files.open_dir(os.path.dirname(path), {0})
    try:
        os.fchown(d, 0, 0)
        os.fchmod(d, 0o755)
        files.write(d, os.path.basename(path), data, 0o644, 0, 0)
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
        raise SystemExit(f"no system-mode signer at {SYS_HOME}; run `sudo /usr/bin/python3 -m tracekit init --user <agent-user>` instead")
    unit = os.path.join(SYSTEMD_DIR, "tracekitd.service")
    try:
        runs_opt = f"ExecStart={OPT_PYTHON} " in read_text(unit)
    except OSError:
        runs_opt = False
    if not runs_opt:
        raise SystemExit("this install predates the root-owned runtime: re-run `sudo /usr/bin/python3 -m tracekit init "
                         "--user <agent-user>` from a root-owned clone")
    with open(signer_cfg, encoding="utf-8") as f:
        scfg = json.load(f)
    cfg = {"socket": scfg.get("socket") or os.path.join(SYS_HOME, "tracekitd.sock"), "signer_home": SYS_HOME,
           "signer_isolation": "separate-user", "mode": "system", "fail_mode": fail_mode or "closed"}
    if scfg.get("proxy"):
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{scfg['proxy'].get('port', 8787)}")
    policy = (client.system_config() or {}).get("policy")
    cfg["policy"] = policy or _opt_default_policy()  # 0.2.x configs have no policy key; use the root-owned default
    _write_system_client_config(dict(cfg, **_v2_client_keys()))
    tk = pwd.getpwnam(SYS_USER)
    hcfg = harness_config(harnesses) if harnesses or not scfg.get("harnesses") else {}
    _update_signer_config(SYS_HOME, dict(hcfg, harness_helper=V1_HELPER_SOCKET), tk)
    if hcfg.get("harnesses") or scfg.get("harnesses"):
        d = files.open_dir(SYS_HOME, {0, tk.pw_uid})
        try:
            fd = files.subdir(d, "helper", 0o700, {0, tk.pw_uid})
            os.fchown(fd, tk.pw_uid, tk.pw_gid)
            files.close(fd)
        finally:
            files.close(d)
        _install_helper(V1_HELPER, "tracekitd", tk, V1_HELPER_SOCKET, False)
    with open(unit, "w") as f:   # the hardened unit, without the CAP_SYS_PTRACE of 0.3
        f.write(UNIT.format(user=tk.pw_name, python=OPT_PYTHON, home=SYS_HOME))
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    pinned = _pin_policy(SYS_HOME, tk)
    print(f"wrote {client.SYSTEM_CONFIG} (root-owned; agent config and TRACEKIT_SOCKET/TRACEKIT_POLICY now ignored)")
    for h in hcfg.get("harnesses", []):
        print(f"harness binding: {h['name']} = {h['exe']}" + (f" running {h['script']}" if h.get("script") else ""))
    print(f"pinned policy {pinned[:19]}; fail_mode={cfg['fail_mode']}")
    print("restart the signer to load the pin: sudo systemctl restart tracekitd")
    return 0


PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "docker", "lxd", "libvirt", "disk", SYS_USER, SYS_USER_DARWIN, V2_USER,
                     V2_USER_DARWIN}


def _privileges(pw):
    """Why the agent's user could take over the signer (root, or a member of an admin, docker or tracekit group)."""
    if pw.pw_uid == 0:
        return ["it is root"]
    names = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except (KeyError, OverflowError):   # macOS may list an out-of-range gid for a user with no groups entry
            pass
    return [f"it is in the {g} group" for g in sorted(names & PRIVILEGED_GROUPS)]


def _first_problem(top, check, skip=()):
    """The first problem check() reports for a file or directory below top (directories named in skip are not entered)."""
    for dirpath, dirnames, filenames in os.walk(top):
        dirnames[:] = [n for n in dirnames if n not in skip]
        for n in dirnames + filenames:
            bad = check(os.path.join(dirpath, n))
            if bad:
                return bad
    return None


def _root_only(path):
    """Problem with `path` itself (a symlink is not followed): it must be root-owned and not group/world-writable."""
    st = os.lstat(path)
    if st.st_uid != 0:
        return f"{path} is not owned by root"
    if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
        return f"{path} is group- or world-writable"
    return None


def _install_source():
    """Check, before init changes anything, that it runs a root-owned Python and installs Tracekit from a source the
    agent's user cannot modify. Returns the pip requirement for an installed release, or None for this source checkout."""
    from .harness_helper import trusted_file
    for f in (sys.executable, os.path.dirname(os.__file__)):
        bad = trusted_file(f)
        if bad:
            raise SystemExit(f"the Python running init could be modified by a non-root user ({bad}). Run init with a "
                             "root-owned Python, e.g. sudo /usr/bin/python3 -m tracekit init")
    if not os.path.isfile(os.path.join(ROOT, "pyproject.toml")):
        from . import __version__
        # lean: trusts PyPI over TLS for the exact version; hash pinning comes with signed release artifacts (M3-15)
        return (["--pre"] if any(c.isalpha() for c in __version__) else []) + [f"tracekit-ai=={__version__}"]
    # lean: one stat per file and ancestor; fine for a checkout of a few thousand files
    bad = trusted_file(ROOT) or _first_problem(ROOT, trusted_file, skip=(".git",))
    if bad:
        raise SystemExit(f"the source checkout could be modified by a non-root user ({bad}). Clone into a root-owned "
                         "directory, e.g. sudo git clone https://github.com/Cygnux-Labs/Tracekit /usr/local/src/Tracekit, "
                         "then cd /usr/local/src/Tracekit && sudo /usr/bin/python3 -m tracekit init --user <agent-user>")
    return None


def _install_venv(requirement, extra=""):
    """Install Tracekit (requirement from _install_source) into a root-owned virtualenv at OPT, so the signer and hooks
    never run code the agent's user can modify. The new venv is built beside OPT and swapped in only once it imports
    tracekit; if any step fails the existing OPT is untouched. extra: pip extras of Tracekit, such as "[signer]".
    Returns the default policy path inside it."""
    new, old_opt = OPT + ".new", OPT + ".old"
    new_python = os.path.join(new, "bin", "python")
    shutil.rmtree(new, ignore_errors=True)
    tmp = None
    old = os.umask(0o022)
    try:
        if requirement is None:  # build from a root-owned copy so the checkout gets no build/ or *.egg-info
            tmp = tempfile.mkdtemp()
            requirement = [os.path.join(tmp, "Tracekit")]
            shutil.copytree(ROOT, requirement[0], ignore=shutil.ignore_patterns(".git"))
        subprocess.run([sys.executable, "-m", "venv", "--clear", new], check=True)
        name, eq, version = requirement[-1].partition("==")
        subprocess.run([new_python, "-m", "pip", "install", "--quiet", "--no-cache-dir", *requirement[:-1],
                        name + extra + eq + version], check=True)
        subprocess.run([new_python, "-I", "-c", "import tracekit"], check=True)
    finally:
        os.umask(old)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    for dirpath, dirnames, filenames in os.walk(new):
        for p in [dirpath] + [os.path.join(dirpath, n) for n in dirnames + filenames]:
            os.lchown(p, 0, 0)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode & ~0o022)
    shutil.rmtree(old_opt, ignore_errors=True)
    if os.path.lexists(OPT):
        os.rename(OPT, old_opt)
    os.rename(new, OPT)
    shutil.rmtree(old_opt, ignore_errors=True)
    return _opt_default_policy()


def _opt_default_policy():
    return subprocess.run([OPT_PYTHON, "-I", "-c", "from tracekit.policy import DEFAULT_POLICY; print(DEFAULT_POLICY)"],
                          check=True, capture_output=True, text=True).stdout.strip()


def _unit_path():
    return (os.path.join(LAUNCHD_DIR, "dev.tracekit.tracekitd.plist") if sys.platform == "darwin"
            else os.path.join(SYSTEMD_DIR, "tracekitd.service"))


def doctor(checks=None):
    """The v1 system mode doctor: prints one line per check with a fix; returns 1 if any check fails."""
    from .doctor import report
    return report(v1_results(checks))


def v1_results(checks=None):
    """v1 system mode checks (tracekit.doctor results): the signer and policy run only from code and policy the agent's
    user cannot modify. checks: [(label, path, fix)] instead of the installed files."""
    from .harness_helper import trusted_file
    from .doctor import FAIL, OK, result
    out, helper = [], []
    if checks is None:
        try:
            if sys.platform.startswith("linux") and read_json(os.path.join(SYS_HOME, "config.json")).get("harnesses"):
                from .doctor import helper_result
                helper = [helper_result(os.path.join(SYSTEMD_DIR, V1_HELPER + ".service"), "sudo tracekit migrate --system")]
        except (OSError, ValueError, AttributeError):   # no or unreadable signer config: the other checks say so
            pass
        for h in _installed_hooks():
            out.append(result("D-V1-HOOKS", OK, "hooks: " + (' and '.join(h.get('versions', ())) or h.get('error')
                                                             or 'none') + f" in {h['settings']}"))
        try:
            sc = client.system_config()
        except client.SystemConfigError as e:
            return out + [result("D-SYSTEM-CONFIG", FAIL, f"system mode: {e}", "sudo tracekit init --user <agent-user>")]
        if sc is None:
            return out + [result("D-SYSTEM-CONFIG", FAIL, f"system mode: {client.SYSTEM_CONFIG} is missing or not "
                                 "root-owned", "sudo /usr/bin/python3 -m tracekit init --user <agent-user>")]
        from .policy import DEFAULT_POLICY
        reinstall = "re-run sudo /usr/bin/python3 -m tracekit init --user <agent-user> to reinstall into " + OPT
        checks = [("signer python", OPT_PYTHON, reinstall), ("venv config", os.path.join(OPT, "pyvenv.cfg"), reinstall),
                  ("runtime", OPT, reinstall), ("unit file", _unit_path(), reinstall),
                   ("policy file", sc.get("policy") or DEFAULT_POLICY,
                    "make it and every directory above it root-owned and not group/world-writable (sudo chown root:root, "
                    "sudo chmod go-w), then sudo tracekit migrate --system")]
    for label, path, fix in checks:
        bad = trusted_file(path)
        if bad is None and os.path.isdir(path):
            bad = _first_problem(path, _root_only)
        out.append(result("D-V1-" + label.upper().replace(" ", "-"), FAIL if bad else OK, f"{label}: {bad or path}", fix))
    return out + helper


def _require_system(experimental_macos):
    """Refuse a platform or user system mode cannot run on; True on macOS."""
    darwin = sys.platform == "darwin"
    if not (sys.platform.startswith("linux") or darwin):
        raise SystemExit("v0.2 system mode runs on Linux and (experimentally) macOS: tracekitd must identify callers "
                         "from the kernel to attest users, refuse forged proxy events and check approvers. Use "
                         "`tracekit init --dev` to try Tracekit here (same-user, clearly labelled).")
    if darwin and not experimental_macos:
        raise SystemExit("macOS system mode is experimental: it has been written to the platform documentation but not "
                         f"yet validated on hardware ({wiki_url('docs/portability.md')}). Re-run with --experimental-macos to use it, "
                         "or use `tracekit init --dev`.")
    if os.geteuid() != 0:
        raise SystemExit("system mode needs root: sudo tracekit init   (or tracekit init --dev for a same-user signer)")
    return darwin


def _agent_user(name, allow_privileged):
    owner = pwd.getpwnam(name)
    why = _privileges(owner)
    if why and not allow_privileged:
        raise SystemExit(f"refusing to trace {name}: {'; '.join(why)}, so its agents could stop or replace the "
                         "signer. Trace an unprivileged user, or re-run with --i-understand-agent-is-privileged.")
    return owner


def _system_user(name, home, darwin):
    """The signer's own OS user, created (no login, no home made) when missing."""
    try:
        return pwd.getpwnam(name)
    except KeyError:
        pass
    if darwin:
        _create_system_user_darwin(name, home)
    else:
        subprocess.run(["useradd", "--system", "--home-dir", home, "--shell", "/usr/sbin/nologin", "--user-group", name],
                       check=True)
    return pwd.getpwnam(name)


def v2_signer_yaml(agent, approver_uid, policy, sock, tailer_uid, harnesses=(), public_witness=False, egress_uid=None):
    """signer.yaml of v2 system mode. The agent's uid gets its own tenant (named after it), and so does the approver's,
    who alone may answer its approvals; every other local user lands in tenant `local`. The tailer's uid may make only
    the TAILER_METHODS calls. With harnesses (resolve_harness entries), the agent's runs must come from one of them.
    public_witness: the public witness cosigns the logs (`witnesses: [public]`). egress_uid: the egress observer's,
    in the agent's tenant, granted observe_effect only.
    Scalars are JSON-quoted, which the built-in YAML subset reads back exactly."""
    q = json.dumps
    tenant, me, approver = q(agent.pw_name), q(f"uid:{agent.pw_uid}"), q(f"uid:{approver_uid}")
    binding = ["harness_binding:", f"  helper: {q(V2_HELPER_SOCKET)}", f"  required: [{me}]", "  harnesses:"] + [
        line for h in harnesses for line in ([f"    {q(h['name'])}:", f"      exe: {q(h['exe'])}",
                                                f"      script: {q(h['script'])}"] if h.get("script")
                                               else [f"    {q(h['name'])}: {q(h['exe'])}"])] if harnesses else []
    return "\n".join([
        "# written by `tracekit init --v2`; re-run it to change this file", f"data_dir: {q(V2_DATA)}",
        f"socket: {q(sock)}", 'socket_mode: "0666"', 'tenant: "local"', "tenants:", f"  {me}: {tenant}",
        f"  {approver}: {tenant}", *([f"  {q(f'uid:{egress_uid}')}: {tenant}"] if egress_uid is not None else []),
        "approvals:", '  self_approval: "deny"', "  approvers:", f"    - {approver}",
        "authorize:", f"  {q(f'uid:{tailer_uid}')}: [{', '.join(TAILER_METHODS)}]",
        *([f"  {q(f'uid:{egress_uid}')}: [observe_effect]"] if egress_uid is not None else []), f"policy: {q(policy)}",
        *binding, *(['witnesses: ["public"]'] if public_witness else []), ""])


def _tailer_acl(owner, u, darwin, grant=True):
    """Grant (or revoke) the tailer's user `u` read access to `owner`'s Claude Code transcripts: an ACL on ~/.claude/projects that
    what is created under it inherits, and search on the directories above (setfacl; macOS chmod +a). Returns None, or
    why it could not."""
    dot = os.path.join(owner.pw_dir, ".claude")
    projects = os.path.join(dot, "projects")
    if grant:
        try:
            files.as_user(owner, os.makedirs, projects, 0o700, True)
        except (OSError, RuntimeError, files.UnsafePath) as e:
            return f"cannot create {projects}: {e}"
    if darwin:
        # lean: -a removes the entries +a wrote; entries the files below inherited may stay after a revoke
        op = "+a" if grant else "-a"
        read = f"user:{u} allow list,search,read,readattr,readextattr,file_inherit,directory_inherit"
        cmds = [["chmod", op, f"user:{u} allow search", owner.pw_dir], ["chmod", op, f"user:{u} allow search", dot],
                ["chmod", "-R", op, read, projects]]
    elif grant:
        cmds = [["setfacl", "-m", f"u:{u}:x", owner.pw_dir], ["setfacl", "-m", f"u:{u}:x", dot],
                ["setfacl", "-R", "-m", f"u:{u}:rX,d:u:{u}:rX", projects]]
    else:
        cmds = [["setfacl", "-x", f"u:{u}", owner.pw_dir], ["setfacl", "-x", f"u:{u}", dot],
                ["setfacl", "-R", "-x", f"u:{u},d:u:{u}", projects]]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as e:   # no setfacl: a file system or system without ACL tools
            return f"{cmd[0]}: {e.strerror}"
        if r.returncode:
            return f"{' '.join(cmd)}: {(r.stderr or '').strip()}"
    return None


def _tailer_sudo(owner, tailer):
    """The sudoers rule that lets `owner` start the tailer as `tailer`, that exact command only; None, or why not."""
    rule = f"{owner.pw_name} ALL=({tailer.pw_name}) NOPASSWD: {OPT_PYTHON} -I -m tracekit.tailer\n"
    try:
        d = files.open_dir(os.path.dirname(TAILER_SUDOERS), {0})
        try:
            files.write(d, os.path.basename(TAILER_SUDOERS), rule.encode(), 0o440, 0, 0)
        finally:
            files.close(d)
    except (OSError, files.UnsafePath) as e:
        return f"no sudo rule: {e}"
    try:
        if subprocess.run(["visudo", "-cf", TAILER_SUDOERS], capture_output=True).returncode == 0:
            return None
    except OSError:   # no visudo, so no sudo to start the tailer with
        pass
    os.remove(TAILER_SUDOERS)   # a rule sudo cannot parse would stop sudo for everyone
    return "no sudo rule: visudo refused it, or there is no sudo"


def v2_plist(user):
    """The LaunchDaemon of v2 system mode: the signer as its own user, without supplementary groups."""
    import plistlib
    return plistlib.dumps({
        "Label": V2_LABEL, "UserName": user, "GroupName": user, "InitGroups": False,
        "ProgramArguments": [OPT_PYTHON, "-I", "-m", "tracekit", "signer", "serve", "--config", V2_CONFIG],
        "RunAtLoad": True, "KeepAlive": True, "Umask": 0o027, "WorkingDirectory": V2_DATA,
        "StandardErrorPath": os.path.join(V2_DATA, "signer.log")})


def init_system_v2(target_user, approver=None, policy=None, project=None, no_service=False, hooks=True,
                   experimental_macos=False, allow_privileged=False, agent="claude", harnesses=(), public_witness=False,
                   egress=False, thinking=True):
    """`sudo tracekit init --v2 --user AGENT`: the v2 signer service as its own user, from the root-owned venv, with
    the v2 hook of `agent` (Claude Code, or a harness of tracekit.agent_hooks) for AGENT. Approvals are answered only by `approver` (default: the admin who ran sudo), a
    different uid from the agent's. harnesses (`--harness [NAME=]PATH`): the agent's runs must come from one of them,
    which the harness helper attests. public_witness (`--public-witness`): the public witness cosigns the signer's logs.
    egress (`--egress`, Linux): the agent's outside traffic only through a local egress observer (docs/egress.md).
    thinking: turn Claude Code's thinking summaries (install_hooks), or Codex's reasoning summaries
    (agent_hooks.codex_reasoning), on for AGENT unless its settings set them.
    Returns (socket, settings path or None)."""
    if public_witness:
        from . import public_witness as pw
        try:
            pw.entry()
        except ValueError as e:
            raise SystemExit(f"--public-witness: {e}") from None
    darwin = _require_system(experimental_macos)
    if egress and darwin:
        raise SystemExit("--egress needs Linux (an owner-match firewall rule); on macOS the agent's network is reported "
                         "only")
    owner = _agent_user(target_user, allow_privileged)
    if approver:
        approver = pwd.getpwnam(approver)
    elif os.environ.get("SUDO_UID"):
        approver = pwd.getpwuid(int(os.environ["SUDO_UID"]))
    else:
        raise SystemExit("name the user who answers the agent's approvals: --approver USER")
    if approver.pw_uid == owner.pw_uid:
        raise SystemExit(f"the approver must be another user than {target_user}: an agent may not approve its own calls")
    if policy:
        from .harness_helper import trusted_file
        policy = os.path.abspath(policy)
        bad = trusted_file(policy)
        if bad:
            raise SystemExit(f"--policy: {bad}. The policy must be a root-owned file in root-owned directories, so "
                             f"{target_user} cannot change it")
    harnesses = [resolve_harness(h, agent) for h in harnesses]
    requirement = _install_source()
    sig = _system_user(V2_USER_DARWIN if darwin else V2_USER, V2_DATA, darwin)
    run_dir = V2_RUN["darwin" if darwin else "linux"]   # on Linux systemd creates it (RuntimeDirectory=)
    for path, mode in ((V2_DATA, 0o700),) + (((run_dir, 0o755),) if darwin else ()):
        os.makedirs(path, mode, exist_ok=True)
        d = files.open_dir(path, {0, sig.pw_uid})
        try:
            os.fchown(d, sig.pw_uid, sig.pw_gid)
            os.fchmod(d, mode)
        finally:
            files.close(d)
    _install_venv(requirement, "[signer]")
    policy = policy or subprocess.run(
        [OPT_PYTHON, "-I", "-c", "from tracekit.signer.service import DEFAULT_POLICY; print(DEFAULT_POLICY)"],
        check=True, capture_output=True, text=True).stdout.strip()
    tailer = _system_user(V2_TAILER_DARWIN if darwin else V2_TAILER, "/var/empty", darwin)
    # the tailer reads Claude Code transcripts only
    why = (_tailer_acl(owner, tailer.pw_name, darwin) or _tailer_sudo(owner, tailer)) if agent == "claude" else None
    if why:
        print(f"transcript tailer: {why}. No tailer is set up, so each run of {target_user}'s sessions records a "
              "tailer_lost gap instead of their tool uses and prompts")
    sock = os.path.join(run_dir, "signer.sock")
    observer = _system_user(V2_EGRESS, "/var/empty", darwin) if egress else None
    _write_root_file(V2_CONFIG, v2_signer_yaml(owner, approver.pw_uid, policy, sock, tailer.pw_uid, harnesses,
                                                public_witness, observer and observer.pw_uid).encode())
    proxy = {"HTTPS_PROXY": f"http://{EGRESS_LISTEN}", "HTTP_PROXY": f"http://{EGRESS_LISTEN}"} if egress else {}
    if egress:   # attribution by the agent's uid, read from /proc: no token in the proxy URL
        _write_root_file(EGRESS_CONFIG, (f"# written by `tracekit init --v2 --egress`\nlisten: {json.dumps(EGRESS_LISTEN)}"
                                         f"\nsigner: {json.dumps(sock)}\n").encode())
    from . import agent_hooks
    settings = None if not hooks else (os.path.join(project or owner.pw_dir, ".claude", "settings.json")
                                       if agent == "claude" else agent_hooks.config_path(agent, project, owner.pw_dir))
    sc = {k: v for k, v in (client.system_config() or {}).items() if k != "tailer"}   # v1 system mode keeps its keys
    # no `tailer` key: the hook has the signer record a tailer_lost gap for each run instead of starting one
    _write_system_client_config(dict(sc, mode="system", signer=sock, fail_mode=sc.get("fail_mode", "closed"),
                                     hooks={"user": target_user, "settings": settings, "agent": agent,
                                            **({"env": proxy} if proxy else {})},
                                     **({"tailer": {"user": tailer.pw_name, "uid": tailer.pw_uid, "python": OPT_PYTHON}}
                                        if agent == "claude" and not why else {})))
    failed = []   # what to check for each service that did not start
    if not no_service:
        if harnesses:   # before the signer, which asks it from its first register_run
            _install_helper(V2_HELPER, V2_UNIT, sig, V2_HELPER_SOCKET, darwin)
        if darwin:
            plist = os.path.join(LAUNCHD_DIR, V2_LABEL + ".plist")
            _write_root_file(plist, v2_plist(sig.pw_name))
            subprocess.run(["launchctl", "bootout", "system", plist], check=False)
            if subprocess.run(["launchctl", "bootstrap", "system", plist], check=False).returncode:
                failed.append(f"could not start {V2_LABEL}: see launchctl print system/{V2_LABEL}")
        else:
            _write_root_file(os.path.join(SYSTEMD_DIR, V2_UNIT + ".service"), V2_UNIT_TEXT.format(
                user=sig.pw_name, python=OPT_PYTHON, config=V2_CONFIG, unit=V2_UNIT, data=V2_DATA).encode())
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", V2_UNIT], check=False)
            r = subprocess.run(["systemctl", "restart", V2_UNIT], check=False)
            if r.returncode:
                failed.append(f"could not start {V2_UNIT}: see systemctl status {V2_UNIT}")
            if egress:
                for unit, text in ((V2_EGRESS, EGRESS_UNIT_TEXT.format(signer=V2_UNIT, user=V2_EGRESS, python=OPT_PYTHON,
                                                                        config=EGRESS_CONFIG)),
                                   (EGRESS_FIREWALL, FIREWALL_UNIT_TEXT.format(agent=target_user, uid=owner.pw_uid))):
                    _write_root_file(os.path.join(SYSTEMD_DIR, unit + ".service"), text.encode())
                subprocess.run(["systemctl", "daemon-reload"], check=False)
                if subprocess.run(["systemctl", "enable", "--now", V2_EGRESS, EGRESS_FIREWALL], check=False).returncode:
                    failed.append(f"could not start {V2_EGRESS} or {EGRESS_FIREWALL} (iptables with the owner match is "
                                  f"needed): see systemctl status {V2_EGRESS} {EGRESS_FIREWALL}; until then "
                                  f"{target_user}'s network is reported only")
    if settings and agent == "claude":
        on = install_hooks(settings, owner=owner, python=OPT_PYTHON, module=V2_HOOK,
                           signer={"TRACEKIT_SIGNER": sock, **proxy} if proxy else sock, thinking=thinking)
        if thinking:
            print(thinking_line(settings, on))
    elif settings:
        files.as_user(owner, agent_hooks.install, agent, None, False, True, OPT_PYTHON, settings, errors=(SettingsError,))
        if agent == "codex" and thinking:
            print(agent_hooks.reasoning_line(*files.as_user(owner, agent_hooks.codex_reasoning, settings,
                                                            errors=(SettingsError,))))
    if proxy and agent != "claude":
        print(f"egress: start {target_user}'s agent with HTTPS_PROXY=http://{EGRESS_LISTEN}: anything else it sends "
              "outside is refused by the firewall")
    if failed:
        raise ServiceError("; ".join(failed))
    return sock, settings


def uninstall_system_v2(purge=False):
    """`sudo tracekit uninstall --v2`: remove the service, signer.yaml, the system config's v2 keys (the file, and the
    venv, unless v1 system mode still uses them) and the agent's hooks. purge: also the signer's data dir (its keys and
    log) and its user, and the tailer's user. Returns what was kept."""
    darwin = _require_system(True)
    sc = client.system_config() or {}
    h = sc.get("hooks") or {}
    try:
        owner = pwd.getpwnam(h["user"])
    except KeyError:
        owner = None
    if h.get("settings") and os.path.exists(h["settings"]):
        if h.get("agent", "claude") == "claude":
            install_hooks(h["settings"], uninstall=True, owner=owner, signer={
                **({"TRACEKIT_SIGNER": sc["signer"]} if sc.get("signer") else {}), **h["env"]} if h.get("env") else
                sc.get("signer"))
        else:
            from . import agent_hooks
            files.as_user(owner, agent_hooks.install, h["agent"], None, True, True, None, h["settings"],
                          errors=(SettingsError,))
    users = [V2_USER_DARWIN, V2_TAILER_DARWIN] if darwin else [V2_USER, V2_TAILER] + ([V2_EGRESS] if h.get("env") else [])
    if owner and h.get("agent", "claude") == "claude":   # also when init kept no `tailer` key: the ACL may be set
        why = _tailer_acl(owner, users[1], darwin, grant=False)
        if why:
            print(f"transcript tailer: could not remove its ACL ({why})")
    if darwin:
        plist, helper = (os.path.join(LAUNCHD_DIR, label + ".plist") for label in (V2_LABEL, HELPER_LABEL))
        for p in (plist, helper):
            subprocess.run(["launchctl", "bootout", "system", p], check=False)
        removed = [plist, V2_RUN["darwin"], helper]
    else:
        removed = [os.path.join(SYSTEMD_DIR, n) for n in (V2_UNIT + ".service", V2_HELPER + ".socket",
                                                          V2_HELPER + ".service", V2_EGRESS + ".service",
                                                          EGRESS_FIREWALL + ".service")]
        if os.path.exists(removed[3]):   # the firewall unit's stop removes the owner-match rule
            subprocess.run(["systemctl", "disable", "--now", V2_EGRESS, EGRESS_FIREWALL], check=False)
    unit = not darwin and os.path.exists(removed[0])   # none after --no-service: nothing to stop
    if unit:
        subprocess.run(["systemctl", "disable", "--now", V2_UNIT], check=False)
    if not darwin and os.path.exists(removed[1]):
        subprocess.run(["systemctl", "disable", "--now", V2_HELPER + ".socket", V2_HELPER], check=False)
    rest = {k: v for k, v in sc.items() if k not in ("signer", "hooks", "tailer")}
    if "socket" in rest:   # v1 system mode
        _write_system_client_config(rest)
    else:
        removed += [client.SYSTEM_CONFIG, OPT]
    removed += [V2_CONFIG, TAILER_SUDOERS, EGRESS_CONFIG]
    if purge:
        removed.append(V2_DATA)
    for p in removed:
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        elif os.path.lexists(p):
            os.remove(p)
    if unit:
        subprocess.run(["systemctl", "daemon-reload"], check=False)
    try:
        os.rmdir(os.path.dirname(V2_CONFIG))
    except OSError:
        pass   # not empty: v1 system mode or a policy lives there
    if purge:
        for user in users:
            cmds = ([["dscl", ".", "-delete", f"/Users/{user}"], ["dscl", ".", "-delete", f"/Groups/{user}"]] if darwin
                    else [["userdel", user]])
            for cmd in cmds:
                subprocess.run(cmd, check=False)
        return []
    return [V2_DATA, *users]


def init_system(target_user, witnesses, checkpoint_every=None, project=None, no_service=False, proxy=False, proxy_port=8787,
                managed=False, managed_only=False, fail_mode=None, experimental_macos=False, hooks=True, signer=None,
                harnesses=None, agent="claude", allow_privileged=False):
    darwin = _require_system(experimental_macos)
    checkpoint_every, proxy_port = _validate_init_options(checkpoint_every, proxy, proxy_port)
    owner = _agent_user(target_user, allow_privileged)
    requirement = _install_source()
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
        for sub, mode in (("keys", 0o700), ("ledger", 0o750), ("blobs", 0o750), ("helper", 0o700), ("", 0o755)):
            fd = files.subdir(home_fd, sub, mode, {0, tk.pw_uid}) if sub else home_fd
            try:
                os.fchown(fd, tk.pw_uid, tk.pw_gid)
                os.fchmod(fd, mode)
            finally:
                if sub:
                    files.close(fd)
        kept_harnesses = _read_config(home_fd).get("harnesses")
    finally:
        files.close(home_fd)
    sock = os.path.join(SYS_HOME, "tracekitd.sock")
    pcfg = {"port": proxy_port, "upstream": _upstream(), "fail_mode": fail_mode or "open"} if proxy else None
    extra = {"signer": signer} if signer else {}
    if not darwin and (harnesses or not kept_harnesses):  # a registered harness stays until --harness replaces it
        extra.update(harness_config(harnesses, agent))
    if not darwin:
        extra["harness_helper"] = V1_HELPER_SOCKET
    scfg = _write_signer_config(SYS_HOME, witnesses, checkpoint_every, sock, pcfg, extra or None, tk)
    if scfg["witnesses"] == [f"git:{os.path.join(SYS_HOME, 'witness')}"]:
        print("note: using a local git witness only. It protects against the agent's user, not against root on this "
              f"machine. Point --witness at a remote repository the security team owns ({wiki_url('docs/witnesses.md')}).")
    policy = _install_venv(requirement)
    # generate the key as the tracekit user so root-only reads are the only other path to it
    subprocess.run(["runuser" if shutil.which("runuser") else "sudo", "-u", tk.pw_name, "--", OPT_PYTHON, "-I", "-c",
                    f"from tracekit.ledger import Keys; Keys.load_or_create({os.path.join(SYS_HOME, 'keys')!r})"],
                   check=True)
    plists = []
    if not no_service:
        if darwin:
            for label, module, enabled in (("dev.tracekit.tracekitd", "tracekit.daemon", True),
                                            ("dev.tracekit.proxy", "tracekit.proxy", proxy)):
                if not enabled:
                    continue
                plists.append(os.path.join(LAUNCHD_DIR, label + ".plist"))
                with open(plists[-1], "wb") as f:
                    f.write(launchd_plist(label, tk.pw_name, OPT_PYTHON, module, SYS_HOME))
                os.chmod(plists[-1], 0o644)
        else:  # systemd
            with open(os.path.join(SYSTEMD_DIR, "tracekitd.service"), "w") as f:
                f.write(UNIT.format(user=tk.pw_name, python=OPT_PYTHON, home=SYS_HOME))
            if scfg.get("harnesses"):
                _install_helper(V1_HELPER, "tracekitd", tk, V1_HELPER_SOCKET, False)
            if proxy:
                with open(os.path.join(SYSTEMD_DIR, "tracekit-proxy.service"), "w") as f:
                    f.write(PROXY_UNIT.format(user=tk.pw_name, python=OPT_PYTHON, home=SYS_HOME))
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", "tracekitd", *(["tracekit-proxy"] if proxy else [])], check=False)
    cfg = {"socket": sock, "signer_home": SYS_HOME, "signer_isolation": "separate-user", "mode": "system"}
    if proxy:
        cfg.update(proxy=True, proxy_url=f"http://127.0.0.1:{proxy_port}")
    _write_client_config(owner.pw_dir, cfg, owner)
    _write_system_client_config(dict(cfg, fail_mode=fail_mode or "closed", policy=policy, **_v2_client_keys()))
    _pin_policy(SYS_HOME, tk)
    failed = []   # what to check for each service that did not start
    for plist in plists:   # after the pin, and booted out first: a running signer must reload its config
        subprocess.run(["launchctl", "bootout", "system", plist], check=False)
        if subprocess.run(["launchctl", "bootstrap", "system", plist], check=False).returncode:
            label = os.path.basename(plist)[:-len(".plist")]
            failed.append(f"could not start {label}: see launchctl print system/{label}")
    if not no_service and not darwin:  # restart, not enable --now: a running signer must reload its config
        units = ["tracekitd", *(["tracekit-proxy"] if proxy else [])]
        if subprocess.run(["systemctl", "restart", *units], check=False).returncode:
            failed.append(f"could not restart {' and '.join(units)}: see systemctl status {' '.join(units)}")
        else:
            print(f"restarted {' and '.join(units)}")
    if not hooks:
        settings = None  # hooks come from elsewhere (the Claude Code plugin)
    elif managed:
        settings = install_managed(cfg.get("proxy_url"), managed_only, python=OPT_PYTHON)
    else:
        settings = os.path.join(project, ".claude", "settings.json") if project else os.path.join(owner.pw_dir, ".claude", "settings.json")
        install_hooks(settings, owner=owner, proxy_url=cfg.get("proxy_url"), python=OPT_PYTHON)
    if failed:
        raise ServiceError("; ".join(failed))
    return cfg, settings


def _hook_summary(settings):
    """{"events": events with a Tracekit hook, "versions": which hooks (v1, v2)} of a settings object."""
    found = {(ev, _hook_version(g)) for ev, gs in settings.get("hooks", {}).items() for g in gs if _is_ours(g)}
    return {"events": sorted({ev for ev, _ in found}), "versions": sorted({v for _, v in found})}


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
    out["hooks"] = _installed_hooks()
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


def _installed_hooks():
    """Tracekit's hooks (events, v1/v2) in the user, project and managed Claude Code settings files that exist."""
    hooks = []
    seen = set()
    for p in (*user_settings_all(), os.path.join(os.getcwd(), ".claude", "settings.json")):
        if os.path.realpath(p) in seen:  # cwd is the home directory: one file, listed once
            continue
        seen.add(os.path.realpath(p))
        if os.path.exists(p):
            try:
                s = read_json(p)
                hooks.append({"settings": p, **_hook_summary(s)})
            except ValueError:
                hooks.append({"settings": p, "error": "unreadable"})
    for p in MANAGED_SETTINGS.values():
        if os.path.exists(p):
            try:
                s = read_json(p)
                hooks.append({"settings": p, "managed": True, **_hook_summary(s),
                              "allowManagedHooksOnly": bool(s.get("allowManagedHooksOnly"))})
            except (ValueError, OSError):
                hooks.append({"settings": p, "managed": True, "error": "unreadable"})
    return hooks


def uninstall(project=None):
    """Removes Tracekit's hooks from the project's settings, or from every user settings file (user_settings_all);
    returns the files it found, joined."""
    found = [s for s in ([os.path.join(project, ".claude", "settings.json")] if project else user_settings_all())
             if os.path.exists(s)]
    for settings in found:
        install_hooks(settings, uninstall=True)
    cfg = client.client_config()
    if not project and cfg.get("mode") == "dev" and cfg.get("signer_home"):
        stop_dev_daemon(cfg["signer_home"])
    return ", ".join(found) or "no settings file"
