"""`tracekit doctor [--json] [--config signer.yaml]`: checks a Tracekit setup and says how to fix what it finds.

It detects the setup: v1 system mode (/etc/tracekit/client.json names a socket), v2 system mode (it names a signer),
the v2 dev signer (no system config), or the signer.yaml given with --config. Every check has a stable id and gives
ok, warn or fail; docs/doctor.md lists them. Exit 1 when any fails, else 0: a warning is advice, not a failure.
Run it as root for system mode: it then probes the files as the agent's user, in a forked child that dropped to it.
`--k8s` checks the pod it runs in, or the manifests under `--manifests DIR`, instead.

Doctor output is advice, not evidence: it reads the host as it is now, and nothing it prints is signed or verified.
"""
import ast
import base64
import contextlib
import errno
import hashlib
import itertools
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time

try:
    import pwd
except ImportError:
    pwd = None

from . import client, install, yamlmini
from .core import read_json, read_text
from .harness_helper import HELPER_CAPS, trusted_file
from .deploy import files
from .wiki import wiki_url

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"   # info: what this setup doesn't have, said once, not a fault
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb", "smb3", "smbfs", "afpfs", "webdav", "fuse", "fuseblk", "9p", "macfuse",
              "osxfuse"}
MAX_SKEW_S = 300
# system mode's init from a root-owned clone of the release, as the plugin and CI run it: it works on every Python,
# whether or not /opt/tracekit exists or can be trusted (docs/deploy.md also gives the routes through /opt's venv).
# The Python is doctor's own when only root can change it (init refuses any other) and it isn't /opt's venv; else the
# system one
_PY = sys.executable if sys.executable and not sys.executable.startswith(install.OPT + os.sep) \
    and trusted_file(sys.executable) is None else "/usr/bin/python3"
REINIT = (f"from a root-owned clone of the release ({wiki_url('docs/deploy.md', 'laptop-system-mode')}), sudo "
          f"{shlex.quote(_PY)} -m tracekit init --v2 --user <agent-user>"
          + (" --experimental-macos" if sys.platform == "darwin" else ""))
V2_FLAGS = "--approver, --policy, --harness, --egress, --project DIR, --managed-only"   # some of what init --v2 records
DEV_INFO = {"D-WITNESS-CONFIGURED"}   # info in the dev profile, not a warning: the dev signer uses the public
# witness by default, and has none only until a release names it or after --no-witness
ROOT_DOCTOR = "run doctor as root (system mode: sudo /opt/tracekit/bin/python -I -m tracekit doctor)"
FAIL_CLOSED = "call blocked (fail-closed)"   # the pre-tool wrapper's words (install._blocking); before 1.3 every event's
# wrapper had them, so a hook that couldn't run blocked a prompt or a tool result too (D-HOOKS-EVENT warns)



class _Windows(Exception):
    """POSIX file modes mean nothing on Windows (ACLs): a check that reads them reports so instead."""


def result(id, status, detail, fix=""):
    return {"id": id, "status": status, "detail": detail, "fix": fix if status != OK else ""}


def report(results, as_json=False):
    """Print the results; returns the exit code (1 any fail, else 0)."""
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['status'] if r['status'] in (OK, INFO) else r['status'].upper():<6}{r['detail']}  ({r['id']})"
                  + (f"\n      fix: {r['fix']}" if r["fix"] else ""))
    return 1 if any(r["status"] == FAIL for r in results) else 0


def _google_re2_supported(python_version=None, implementation=None, sys_platform=None, machine=None):
    """Whether google-re2 is declared for this Python and platform.

    Keep these conditions in sync with the google-re2 markers in pyproject.toml.
    """
    python_version = python_version or f"{sys.version_info.major}.{sys.version_info.minor}"
    implementation = implementation or platform.python_implementation()
    sys_platform = sys_platform or sys.platform
    machine = machine or platform.machine()

    version = tuple(int(part) for part in python_version.split("."))

    if implementation != "CPython" or not ((3, 10) <= version < (3, 15)):
        return False

    return (
        (sys_platform == "win32" and (
            machine in ("x86", "AMD64") or
            (version >= (3, 11) and machine == "ARM64")
        ))
        or (sys_platform == "linux" and machine in ("x86_64", "aarch64"))
        or (sys_platform == "darwin" and machine in ("x86_64", "arm64"))
    )


def _google_re2_wheel_expected():
    """The marker, and what it cannot see: libc and OS version constraints."""
    if not _google_re2_supported():
        return False

    if sys.platform == "linux":
        if sys.maxsize <= 2**32 - 1:
            return False
        libc, version = platform.libc_ver()
        return (
            libc == "glibc"
            and tuple(int(p) for p in version.split(".")[:2] if p.isdigit()) >= (2, 28)
        )

    if sys.platform == "darwin":
        return int((platform.mac_ver()[0] or "0").split(".")[0]) >= 13

    return True


def main(config=None, as_json=False, k8s=False, manifests=None, issuer_key=None):
    if not (k8s or manifests):
        rows = collect(config, issuer_key)
        code = report(rows, as_json)
        # the dev profile's own warning (D-PROCESS-BOUNDARY: it runs as you) and nothing else: say it is healthy
        if not as_json and any(r["detail"] == install.DEV_MODE_LINE for r in rows) and \
                all(r["status"] in (OK, INFO) or r["id"] == "D-PROCESS-BOUNDARY" for r in rows):
            print("dev setup OK: every call is decided and recorded, but the agent runs as you and could switch "
                  "Tracekit off; system mode or Tracekit Box close that (D-PROCESS-BOUNDARY)")
        return code
    out = k8s_checks(*load_manifests(manifests)) if manifests else in_pod()
    return report(out + (v2_checks(config, issuer_key=issuer_key) if config else []), as_json)


def collect(config=None, issuer_key=None):
    """The checks that apply to the setup on this host (or to signer.yaml `config`)."""
    try:
        sc = client.system_config()
    except client.SystemConfigError as e:   # of init's flags, only init --managed's hooks can be seen then
        flags, tail = install.reinit_flags(None, _managed() if install._v2_hooks_in(_managed()) else None, V2_FLAGS,
                                           f"{client.SYSTEM_CONFIG} records them, and it can't be read")
        return [result("D-SYSTEM-CONFIG", FAIL, str(e), REINIT + flags + tail)]
    out = install.v1_results() if sc and "socket" in sc and not config else []
    if config or (sc and sc.get("signer")):
        h = (sc or {}).get("hooks") or {}
        unit = (os.path.join(install.LAUNCHD_DIR, install.V2_LABEL + ".plist") if sys.platform == "darwin"
                else os.path.join(install.SYSTEMD_DIR, install.V2_UNIT + ".service"))
        agent_name = h.get("agent", "claude")
        settings = h.get("settings") if agent_name == "claude" else None
        agent = _user(h.get("user"))
        home = agent and os.path.join(agent.pw_dir, ".claude", "settings.json")
        project = (os.path.dirname(os.path.dirname(settings))
                   if settings and settings not in (home, *install.MANAGED_SETTINGS.values())
                   and os.path.basename(os.path.dirname(settings)) == ".claude" else None)
        users = [home] if home else []
        plugin = install.plugin_enabled(users, project) if project else install.plugin_enabled(users)
        layers = [p for p in (home, settings, _managed()) if p]
        # lean: another coding agent's hook config gets D-HOOKS-EVENT, D-HOOKS-TIMEOUT (CodeBuddy Code's D-HOOKS-ORDER
        # too) and the reasoning checks only;
        # D-HOOKS-PRESENT names it without reading its events, and D-HOOKS-VENV and D-SIGNER-ENV are Claude Code's;
        # until doctor reads them per format
        rows = v2_checks(config or install.V2_CONFIG, agent=agent, settings=settings,
                         signer=(sc or {}).get("signer"), opt=install.OPT, unit=unit,
                         client_json=client.SYSTEM_CONFIG if sc else None, issuer_key=issuer_key, plugin=plugin,
                         sandbox_settings=layers,
                         gemini_settings=_gemini(agent and os.path.join(agent.pw_dir, ".gemini", "settings.json"),
                                                 h.get("settings") if h.get("agent") == "gemini" else None),
                         gemini_project=h.get("settings") if h.get("agent") == "gemini" else None,
                         harnesses={agent_name: h["settings"]} if agent_name != "claude" and h.get("settings")
                         else None, no_hooks=h.get("no_hooks") is True)
        # the re-init a fix names keeps init's agent, and --no-hooks where init was told it or Claude Code's
        # root-trusted managed settings enable the Tracekit plugin (else init writes its hooks beside the plugin's,
        # deciding each call twice); not over init --managed's hooks, nor from the agent's own or project settings,
        # which the agent's user can write to make a re-init drop init's hooks. It keeps --managed, else init moves the
        # hooks from the root-owned file into the agent's own settings, and --managed-only, else init turns
        # allowManagedHooksOnly off. And the rest of init's flags, which only root-owned client.json gives
        # (install.reinit_flags): without them init puts its defaults (its own policy, no harness binding) in place of
        # the host's
        managed = settings in install.MANAGED_SETTINGS.values()
        flags, tail = install.reinit_flags(h.get("init_flags"), settings if managed else None, V2_FLAGS,
                                           f"{client.SYSTEM_CONFIG} doesn't record them" if sc else
                                           f"there's no {client.SYSTEM_CONFIG} here to record them")
        agent_flag = f" --agent {shlex.quote(agent_name)}" if agent_name != "claude" else ""
        active_plugin = plugin if plugin and not _plugin_idle(plugin, True, settings) else None
        no_hooks = (" --no-hooks"
                    if h.get("no_hooks") is True or active_plugin and agent_name == "claude" and not managed else "")

        def again(text, extra):
            if " --managed-only" in extra:   # a fix's own (D-HOOKS-PRESENT's) is init's already
                text = text.replace(REINIT + " --managed-only", REINIT)
            return text.replace(REINIT, REINIT + extra) + tail if REINIT in text else text
        # a detail's re-init (D-HOOKS-PRESENT after init --no-hooks) is the one that adds the hooks
        return out + [dict(r, fix=again(r["fix"], agent_flag + no_hooks + flags),
                           detail=again(r["detail"], agent_flag + flags)) for r in rows]
    if sc:
        return out
    from . import agent_hooks
    from .sdk import autospawn
    from .signer.service import dev_content, dev_witnesses
    dev_data = autospawn.data_dir()
    project = os.path.join(os.getcwd(), ".claude")
    mine, harnesses = client.client_config(), _dev_harnesses()
    rows = v2_checks({"data_dir": dev_data, "content": dev_content().get("content"),
                      "witnesses": dev_witnesses(dev_data)}, "dev",
                     settings=_dev_settings(), plugin=install.plugin_enabled(), harnesses=harnesses,
                     no_hooks=isinstance(mine, dict) and mine.get("no_hooks") is True,
                     sandbox_settings=[install.user_settings(), os.path.join(project, "settings.json"),
                                       os.path.join(project, "settings.local.json"), _managed()],
                     gemini_settings=_gemini(agent_hooks.config_path("gemini"),
                                             os.path.join(os.getcwd(), ".gemini", "settings.json")),
                     gemini_project=os.path.join(os.getcwd(), ".gemini", "settings.json"))
    for trusting in agent_hooks.TRUSTING:   # their v1 hooks (init --dev --agent codex) run only once trusted, as v2 do
        if trusting in harnesses:
            continue
        paths = {}   # one file once: from $HOME the user's and the project's are the same
        for p in (agent_hooks.config_path(trusting), agent_hooks.config_path(trusting, os.getcwd())):
            paths.setdefault(os.path.realpath(p), p)
        for path in paths.values():
            try:
                hooks = _harness_hooks(trusting, _json(path) or {})
            except (OSError, ValueError, AttributeError, TypeError):   # missing, or not a hook config: not this one
                continue
            _codex_trust(lambda id, ok, detail, fix, bad=FAIL: rows.append(result(id, OK if ok else bad, detail, fix)),
                         path, hooks if isinstance(hooks, dict) else {}, None, WARN, trusting)
    if "gptme" not in harnesses:
        path = agent_hooks.config_path("gptme")
        bridge = agent_hooks._gptme_hook_path(path)
        if os.path.isfile(bridge) or os.path.isfile(os.path.join(os.path.dirname(bridge), "__init__.py")):
            ok, detail = _gptme_load_check(path)
            rows.append(result("D-GPTME-LOAD", OK if ok else WARN, detail, "tracekit init --dev --agent gptme"))
    return rows


def _managed():
    return install.MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]

def _dropin_folder(settings):
    """Claude Code's `managed-settings.d/`: the drop-ins it merges with the admin-managed settings file beside them."""
    return os.path.join(os.path.dirname(settings), "managed-settings.d")


def _managed_dropins(settings):
    """The drop-ins Claude Code merges with the admin-managed settings `settings`, in its order: the `*.json` files of
    the `managed-settings.d/` folder beside it, by name. Claude Code's docs (code.claude.com/docs/en/managed-settings,
    "Split a file-based policy across teams", read 2026-11-23): it "merges `managed-settings.json` first, then every
    `*.json` file in the directory in alphabetical order", and "ignores hidden files and files that don't end in
    `.json`"."""
    folder = _dropin_folder(settings)
    try:
        names = sorted(os.listdir(folder))
    except OSError:   # no folder
        return []
    return [os.path.join(folder, n) for n in names
            if n.endswith(".json") and not n.startswith(".") and os.path.isfile(os.path.join(folder, n))]


def _admin_files(settings):
    """The file-based managed sources in the order Claude Code merges them: `managed-settings.json`, then each drop-in
    by name."""
    return [settings, *_managed_dropins(settings)]


def _setting_in_order(paths, key):
    """(the file whose value Claude Code uses for `key`, that value) over file-based managed sources in merge order.
    Its docs: for a single value, "the later file's value replaces the earlier one", so the last file that sets the key
    decides — and a drop-in setting it false lifts an earlier true."""
    at, value = None, None
    for p in paths:
        v = _setting(p, key)
        if v is not None:
            at, value = p, v
    return at, value


def _dropins(settings, unreadable=()):
    """(problem with the drop-ins beside the admin-managed `settings`, what the detail then says was checked). A drop-in
    the agent's user can write is a way to set `disableAllHooks` and turn every hook off, so the folder and each file in
    it must be trusted the way the managed file is: `trusted_file` resolves a symlink and checks every directory above
    it, which is what Claude Code reads (its docs: "You can deploy any of these files as a symbolic link, and Claude
    Code reads the file the link leads to"). A source the agent's user can't read is a fault too: its docs say that when
    the OS denies the read, "every session starts without that source's policies", and `unreadable` names those. The
    folder is checked even when it holds no drop-ins: an empty one the agent's user can write is where a
    `99-off.json` can be added."""
    folder, found = _dropin_folder(settings), _managed_dropins(settings)
    if not found and not os.path.isdir(folder):
        return None, ""
    bad = [why for why in map(trusted_file, (folder, *found)) if why]
    bad += [f"{p} isn't readable by the agent's user, so its Claude Code starts without that source's policies"
            for p in (folder, *found) if p in unreadable]
    return "; ".join(bad) or None, (f", and the {len(found)} drop-in(s) in {folder} are root-owned too" if found
                                    else f", and {folder} is root-owned too")


def _layers(paths, key):
    """The `key` object of each settings file in `paths` that has one, in order."""
    for p in paths:
        try:
            s = _json(p).get(key)
        except (OSError, ValueError, AttributeError, TypeError):   # missing, unreadable, not a settings object, or
            continue                                                  # client.json's settings not a path
        if isinstance(s, dict):
            yield s


def _sandbox(paths):
    """Claude Code's `sandbox` settings from the files `paths`, a later file winning each key (the order Claude Code
    ranks them: user, project, local, managed).
    lean: key by key, not Claude Code's whole precedence (--settings, a user `allowUnsandboxedCommands: false` that a
    project can't undo); doctor reports these files, so a setup that relies on the rest can read differently"""
    out = {"network": {}}
    for s in _layers(paths, "sandbox"):
        out.update(s, network={**out["network"], **(s["network"] if isinstance(s.get("network"), dict) else {})})
    return out


def _gemini(user, project, cli="gemini"):
    """Gemini CLI's settings files (cli "qwen": Qwen Code's, a fork), lowest rank first: system defaults, the user's,
    the project's, system settings (the system ones where the CLI looks for them, its two environment variables
    included; qwen-code 0.28.0 storage-paths-lite)."""
    env, mac, folder = ("QWEN_CODE", "QwenCode", "qwen-code") if cli == "qwen" else ("GEMINI_CLI", "GeminiCli",
                                                                                       "gemini-cli")
    d = {"darwin": f"/Library/Application Support/{mac}", "win32": rf"C:\ProgramData\{folder}"}.get(
        sys.platform, f"/etc/{folder}")
    system = os.environ.get(f"{env}_SYSTEM_SETTINGS_PATH") or os.path.join(d, "settings.json")
    defaults = os.environ.get(f"{env}_SYSTEM_DEFAULTS_PATH") or os.path.join(os.path.dirname(system),
                                                                              "system-defaults.json")
    return [p for p in (defaults, user, project, system) if p]


def _folder_trust(cli, home, project):
    """Whether Gemini CLI (cli "gemini") or Qwen Code ("qwen") loads the project settings file `project` by its folder
    trust, as gemini-cli 0.68.0 (checkPathTrust) and qwen-code 0.28.0 (isWorkspaceTrusted) decide from their files
    (home: the agent user's home, else this user's): True when it is the user's own file, or
    security.folderTrust.enabled is off in the system and user settings (Gemini CLI's default is on, Qwen Code's off);
    else by the rule in trustedFolders.json for the project's folder (Gemini CLI: the longest rule path; Qwen Code:
    the deepest folder, DO_NOT_TRUST on a tie), no rule being untrusted; None when that file can't be read (the CLI
    stops then). Before folder trust, Gemini CLI's environment decides: GEMINI_RESTRICTED_MODE=true or
    GEMINI_CLI_TRUST_WORKSPACE=false untrusted, GEMINI_CLI_TRUST_WORKSPACE=true trusted (Qwen Code 0.28.0 has no
    such variable).
    -> (that, the trust file, the variable setting that made it untrusted or None).
    lean: IDE trust decides before the file and doctor can't see it; the environment read is doctor's own (this user's
    only), which a Gemini CLI started elsewhere may not share; a trust file with comments (JSONC) reads as unreadable"""
    from . import agent_hooks
    user = agent_hooks.config_path(cli, home=home)
    trust = (None if home else os.environ.get(f"{'QWEN_CODE' if cli == 'qwen' else 'GEMINI_CLI'}_TRUSTED_FOLDERS_PATH")
             ) or os.path.join(os.path.dirname(user), "trustedFolders.json")
    on = cli == "gemini"
    for s in _layers(_gemini(user, None, cli), "security"):   # a project's can't turn it on or off
        if isinstance(s.get("folderTrust"), dict) and s["folderTrust"].get("enabled") is not None:
            on = s["folderTrust"]["enabled"]
    if os.path.realpath(project) == os.path.realpath(user):
        return True, trust, None
    if cli == "gemini" and not home:
        for env in ("GEMINI_RESTRICTED_MODE=true", "GEMINI_CLI_TRUST_WORKSPACE=false"):
            if os.environ.get(env.split("=")[0]) == env.split("=")[1]:
                return False, trust, env
        if os.environ.get("GEMINI_CLI_TRUST_WORKSPACE") == "true":
            return True, trust, None
    if not on:
        return True, trust, None
    try:
        rules = _json(trust)
    except FileNotFoundError:
        rules = {}
    except (OSError, ValueError):
        return None, trust, None
    if not isinstance(rules, dict):
        return None, trust, None

    def real(p):
        p = os.path.realpath(p)
        return p.lower() if sys.platform in ("darwin", "win32") else p
    here, best = real(os.path.dirname(os.path.dirname(project))), None
    for rule, level in rules.items():
        if level not in ("TRUST_FOLDER", "TRUST_PARENT", "DO_NOT_TRUST"):
            continue
        at = real(os.path.dirname(rule) if level == "TRUST_PARENT" else rule)
        if here == at or here.startswith(at.rstrip(os.sep) + os.sep):
            rank = (len(rule),) if cli == "gemini" else (len(at.rstrip(os.sep).split(os.sep)), level == "DO_NOT_TRUST")
            if best is None or rank > best[0]:
                best = rank, level
    return best is not None and best[1] != "DO_NOT_TRUST", trust, None


def _dev_settings():
    """The first settings file with a v2 hook: a user one (install.user_settings_all) or the project's in the working
    directory; else the user one Claude Code reads."""
    for p in (*install.user_settings_all(), os.path.join(os.getcwd(), ".claude", "settings.json")):
        try:
            if any(_hooks(p).values()):
                return p
        except (OSError, ValueError, AttributeError, TypeError):   # missing, or not a settings file: not this one
            pass
    return install.user_settings()


def _harness_hooks(harness, config):
    """{event: [hook groups]} of a coding agent's hook config: Droid's file is the event map (a Devin project's
    hooks.v1.json too), agy's names each hook's (Tracekit's is agent_hooks.AGY_HOOK), Kiro's is a list of hooks, each
    naming its event (`trigger`) and its command (`action`), less those Kiro skips (`"enabled": false`), the others'
    is under `hooks`."""
    from . import agent_hooks
    if harness == "kiro":
        out = {}
        for h in config.get("hooks") or ():
            if isinstance(h, dict) and isinstance(h.get("action"), dict) and h.get("enabled") is not False:
                out.setdefault(h.get("trigger"), []).append({**h, "command": h["action"].get("command")})
        return out
    if harness == "droid":
        return {ev: config[ev] for ev in agent_hooks.DROID_EVENTS if ev in config}
    if harness == "devin" and "hooks" not in config:
        return {ev: config[ev] for ev in agent_hooks.DEVIN_EVENTS if ev in config}
    if harness == "openhands" and "hooks" not in config:   # its direct form, in either key style
        return {ev: config.get(ev) or config.get(f) for ev, f in agent_hooks.OPENHANDS_FIELDS.items()
                if config.get(ev) or config.get(f)}
    if harness == "antigravity":   # its "enabled" is D-AGY-HOOKS-RUN's
        named = config.get(agent_hooks.AGY_HOOK) or {}
        return {ev: named[ev] for ev in agent_hooks.AGY_EVENTS if ev in named}
    if harness == "jcode":   # its [hooks] table: each key a command or a list of them; one gate timeout, in ms (5 s
        # when unset), for every pre_tool command
        table = config.get("hooks") or {}
        timeout = table.get("pre_tool_timeout_ms", 5000)
        timeout = timeout / 1000 if type(timeout) in (int, float) else 0
        return {ev: [{"command": c, **({"timeout": timeout} if ev in agent_hooks.PRE else {})}
                     for c in (table[k] if isinstance(table[k], list) else [table[k]])]
                for k, ev in agent_hooks.JCODE_EVENTS.items() if k in table}
    return config.get("hooks") or {}


def _hook_entries(hooks):
    """[(event, hook)] of a coding agent's {event: [hook groups]}: each group's hooks, or the group itself."""
    return [(ev, h) for ev, groups in hooks.items() for g in groups
            for h in (g.get("hooks") or () if "hooks" in g else [g]) if isinstance(h, dict)]


def _config(harness, path):
    """A coding agent's hook config at `path`, parsed: jcode's TOML, the others' JSON."""
    from . import agent_hooks
    return agent_hooks.jcode_config(path) if harness == "jcode" else _json(path) or {}


def _dev_harnesses():
    """{harness: its hook config} for each coding agent (agent_hooks) with a v2 hook in its user or project config."""
    from . import agent_hooks
    out = {}
    for harness in agent_hooks.HARNESSES:
        if harness == "gptme":
            path = agent_hooks.config_path(harness)
            try:
                if agent_hooks._version(" ".join(_gptme_argv(path))) == "v2":
                    out[harness] = path
            except (OSError, ValueError, TypeError):
                pass
            continue
        for path in (agent_hooks.config_path(harness), agent_hooks.config_path(harness, os.getcwd())):
            if harness in agent_hooks.PLUGIN_TOOLS or harness == "cline":   # a JavaScript plugin or Cline's hook
                # files, not a JSON hook config
                try:
                    if agent_hooks._version(install.agent_file(path).decode("utf-8", "replace")) == "v2":
                        out.setdefault(harness, path)
                except OSError:
                    pass
                continue
            try:
                if _hook_commands(harness, path):
                    out.setdefault(harness, path)
            except (OSError, ValueError, AttributeError, TypeError):   # missing, or not a hook config: not this one
                continue
    return out


def _hook_commands(harness, path):
    """The command of each of Tracekit's v2 hooks in a coding agent's hook config at `path`; OpenCode's plugin: each
    event's argv; Cline's: the argv of each of Tracekit's hook files beside `path`."""
    from . import agent_hooks
    if harness == "cline":
        folder, suffix = os.path.split(path)[0], os.path.splitext(path)[1]
        texts = [install.agent_file(os.path.join(folder, ev + suffix)).decode("utf-8", "replace")
                 for ev in agent_hooks.CLINE_EVENTS if os.path.exists(os.path.join(folder, ev + suffix))]
        return [agent_hooks.cline_argv(t) for t in texts if agent_hooks._version(t) == "v2"]

    if harness == "gptme":
        argv = _gptme_argv(path)
        return [shlex.join(argv)] if argv else []
    if harness in agent_hooks.PLUGIN_TOOLS:
        m = re.search(r"^const commands = (.*);$", install.agent_file(path).decode("utf-8", "replace"), re.M)
        return list(_loads(m.group(1)).values()) if m else []
    hooks = _harness_hooks(harness, _config(harness, path))
    return [h["command"] for lst in hooks.values() for g in lst
            for h in (g.get("hooks") or () if "hooks" in g else [g])
            if isinstance(h, dict) and agent_hooks._version(h.get("command")) == "v2"]


def _gptme_argv(path):
    from . import agent_hooks
    source = install.agent_file(agent_hooks._gptme_hook_path(path)).decode("utf-8")
    if not source.startswith(agent_hooks.GPTME_MARKER + "\n"):
        return []
    match = re.search(r"^COMMAND = (.*)$", source, re.M)
    return _loads(match[1]) if match else []


def _outside_cwd(path):
    if not path or not os.path.isabs(path):
        return False
    cwd = os.path.normcase(os.path.realpath(os.getcwd()))
    for candidate in (os.path.abspath(path), os.path.realpath(path)):
        try:
            if os.path.commonpath((cwd, os.path.normcase(candidate))) == cwd:
                return False
        except ValueError:   # Windows paths on different drives
            pass
    return True


def _gptme_python():
    launcher = shutil.which("gptme")
    if not _outside_cwd(launcher):
        return None
    executable = "python.exe" if os.name == "nt" else "python"
    adjacent = os.path.join(os.path.dirname(os.path.realpath(launcher)), executable)
    if _outside_cwd(adjacent) and os.path.isfile(adjacent):
        return adjacent
    uv = shutil.which("uv") if os.name == "nt" else None
    if _outside_cwd(uv):
        try:
            tool_dir = subprocess.check_output([uv, "tool", "dir"], text=True, timeout=5).strip()
            candidate = os.path.join(tool_dir, "gptme", "Scripts", executable)
            if _outside_cwd(candidate) and os.path.isfile(candidate):
                return candidate
        except (OSError, subprocess.SubprocessError):
            pass
    return None


_GPTME_PROBE = """
import sys
from pathlib import Path
from gptme.config import get_config, set_config_from_workspace
from gptme.hooks import HookType, get_hooks
from gptme.plugins import register_plugin_hooks

bridge = Path(sys.argv[1]).resolve()
package = bridge.parents[1]
set_config_from_workspace(Path.cwd())
paths, enabled = get_config().get_plugin_config()
if not any(path.resolve() in (package.parent, package) for path in paths):
    raise SystemExit("the installed plugin is outside gptme's configured plugin paths")
if enabled and "tracekit" not in enabled:
    raise SystemExit("the effective plugin allowlist excludes tracekit")
register_plugin_hooks([package], enabled)
for hook in get_hooks(HookType.TOOL_CONFIRM):
    if hook.name == "tracekit.confirm" and Path(hook.func.__code__.co_filename).resolve() == bridge:
        break
else:
    raise SystemExit("gptme did not register tracekit.confirm")
"""


def _gptme_load_check(path):
    from . import agent_hooks
    bridge = agent_hooks._gptme_hook_path(path)
    try:
        argv = _gptme_argv(path)
        if not argv or not all(isinstance(part, str) for part in argv):
            return False, f"cannot read the gptme bridge command at {bridge}"
        # Check the generated files before loading the Tracekit package on its own.
        source = install.agent_file(bridge).decode("utf-8")
        v2 = agent_hooks._version(" ".join(argv)) == "v2"
        expected = agent_hooks._gptme_plugin(None, v2)
        command = "COMMAND = " + json.dumps(argv)
        expected = re.sub(r"^COMMAND = .*$", lambda _: command, expected, count=1, flags=re.M)
        init = (agent_hooks.GPTME_MARKER + "\n").encode()
        hooks = os.path.dirname(bridge)
        if (source != expected or install.agent_file(os.path.join(hooks, "__init__.py")) !=
                init + b"from .bridge import register\n" or
                install.agent_file(os.path.join(os.path.dirname(hooks), "__init__.py")) != init):
            return False, f"gptme plugin at {bridge} differs from this Tracekit's generated files"
        python = _gptme_python()
        if not python:
            return False, "doctor couldn't find gptme's Python outside the working directory"
        run = subprocess.run([python, "-I", "-B", "-c", _GPTME_PROBE, bridge], capture_output=True,
                             encoding="utf-8", errors="replace", timeout=10)
        if run.returncode:
            return False, (run.stderr.strip().splitlines() or ["gptme failed to load the plugin"])[-1]
        return True, f"gptme registered Tracekit's confirmation hook from {bridge}"
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return False, f"cannot verify the gptme plugin: {e}"


# what a hook's Python imports as tracekit: its version, its tracekit/__init__.py and that Python's user site-packages
# (claude_code.upgrade); a -c hook's directory (install._dev_hook_argv's `r`) goes first on sys.path, as the hook puts it
PROBE = ("import site, sys; sys.path[:0] = sys.argv[1:]; import tracekit; "
         "print(tracekit.__version__, tracekit.__file__, site.getusersitepackages(), sep='\\n')")


def _hook_argv(cmd):
    """The argv of the Python a v2 hook command runs, as install._hook_command writes it (bare, or in _blocking's
    /bin/sh -c wrapper; on Windows quoted, or after PowerShell's &), or OpenCode's argv; None for any other command."""
    if not isinstance(cmd, list):
        try:
            cmd = shlex.split(cmd, posix=os.name != "nt")
            if len(cmd) == 3 and os.path.basename(cmd[0]) == "sh" and cmd[1] == "-c":
                lex = shlex.shlex(cmd[2], posix=True, punctuation_chars=True)
                lex.whitespace_split = True
                cmd = list(itertools.takewhile(lambda w: w != ";", lex))
        except (ValueError, AttributeError):
            return None
        cmd = [w.strip('"') if os.name == "nt" else w for w in cmd if w != "&"]   # POSIX's split took its quotes off
    ok = len(cmd) > 3 and all(isinstance(w, str) for w in cmd) and cmd[1:3] in (["-I", "-m"], ["-I", "-c"])
    return cmd if ok else None


def _probe_target(argv):
    """(interpreter, the directory a -c hook puts first on sys.path (install._dev_hook_argv's `r`: a working tree) or
    None) of the hook `argv`; ValueError for a path that isn't absolute, which would resolve against doctor's working
    directory, or one the hook's code can't decode."""
    # the tree: on POSIX the code's first argument, on Windows a literal in the code (install._literal), and in a hook
    # an earlier init wrote, base64 in the code
    m = argv[2] == "-c" and re.search(r"b64decode\('([A-Za-z0-9+/=]*)'\)", argv[3])
    lit = argv[2] == "-c" and re.match(r"import sys; r = ('[^']*');", argv[3])
    try:
        tree = base64.b64decode(m.group(1)).decode("utf-8") if m else ast.literal_eval(lit.group(1)) if lit else \
            argv[4] if argv[2] == "-c" and argv[3].startswith("import sys; r = sys.argv[1];") and len(argv) > 4 else None
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"a path the hook's code can't decode ({e})") from None
    for what, p in (("an interpreter", argv[0]), ("a path", tree)):
        if p is not None and not (p.isprintable() and os.path.isabs(p)):
            raise ValueError(f"{what} that isn't an absolute path ({p[:128]!r})")
    return argv[0], tree


PROBE_S, PROBE_BYTES = 10, 4096   # what doctor gives a hook's Python: time, and output read


def _hook_tracekit(python, tree):
    """[version, module file, user site-packages] of the Tracekit that `python` imports (with `tree` first on its path),
    asked in a subprocess given PROBE_S and read up to PROBE_BYTES; ValueError or OSError when it can't tell. Its
    output goes into doctor's report: only printable lines and a version claude_code.VERSION matches are taken."""
    from .integrations.claude_code import VERSION
    end = time.monotonic() + PROBE_S
    p = subprocess.Popen([python, "-I", "-c", PROBE, *([tree] if tree else [])], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    got = []
    reader = threading.Thread(target=lambda: got.append(p.stdout.read(PROBE_BYTES + 1)), daemon=True)
    reader.start()
    reader.join(PROBE_S)
    out, hung = got[0] if got else b"", reader.is_alive()
    if hung or len(out) > PROBE_BYTES:
        p.kill()
    try:
        code = p.wait(max(end - time.monotonic(), 0.1))
    except subprocess.TimeoutExpired:   # closed its output, then hung
        p.kill()
        code, hung = p.wait(), True
    reader.join(1)
    if not reader.is_alive():   # else a child it left holds the pipe: the reader ends with doctor
        p.stdout.close()
    lines = out.decode("utf-8", "replace").splitlines()[-3:]   # stderr comes first, unbuffered
    if len(out) > PROBE_BYTES or hung or code or len(lines) != 3 or not VERSION.fullmatch(lines[0]) \
            or not all(x.isprintable() for x in lines):
        why = (f"it wrote more than {PROBE_BYTES} bytes" if len(out) > PROBE_BYTES else
               f"no answer within {PROBE_S} s" if hung else (lines or [f"it exited {code}"])[-1] if code else
               "its answer is unreadable")
        raise ValueError(re.sub(r"[^ -~]", "?", why)[:256])
    return lines


def _dev_signer():
    """The hello that this HOME's running dev signer publishes as endpoint.json (its version and pid; {} while it hasn't
    yet), or None when none runs. Starts, creates and connects to nothing."""
    from .sdk import autospawn
    try:
        d = autospawn.signer_dir(create=False)
        if not autospawn._held(os.path.join(d, autospawn.LOCK)):
            return None
    except (OSError, autospawn.SignerUnavailable):   # no runtime dir yet, or one no client uses (not private)
        return None
    try:
        hello = read_json(os.path.join(d, autospawn.ENDPOINT))
    except (OSError, ValueError):   # still starting, or not readable
        return {}
    return hello if isinstance(hello, dict) else {}


# the environment variables that place a user's hook files (install.user_settings_all, agent_hooks.config_path); `~`
# is USERPROFILE on Windows
USER_ENV = ("USERPROFILE" if os.name == "nt" else "HOME", "CLAUDE_CONFIG_DIR", "TRACEKIT_CLIENT_HOME", "CODEX_HOME",
            "XDG_CONFIG_HOME", "CRUSH_GLOBAL_CONFIG", "COPILOT_HOME", "CODEBUDDY_CONFIG_DIR", "QWEN_HOME",
            "INTERPRETER_HOME")


def _user_hook_files():
    """(the realpaths of the user's own hook files, the USER_ENV variables set to a relative path). A file such a
    variable places resolves against doctor's working directory, so it isn't counted as the user's (the XDG spec says
    to ignore a relative XDG_CONFIG_HOME, and Codex, Qwen Code and Open Interpreter resolve a relative CODEX_HOME,
    QWEN_HOME or INTERPRETER_HOME against their own directory)."""
    from . import agent_hooks
    relative = [k for k in USER_ENV if os.environ.get(k) and not os.path.isabs(
        os.path.expanduser(os.environ[k]) if k == "QWEN_HOME" else os.environ[k])]   # Qwen Code expands ~
    record = os.environ.get("TRACEKIT_CLIENT_HOME") or os.path.expanduser("~")   # init's record is under it
    paths = [install.user_settings(), os.path.join(os.path.expanduser("~"), ".claude", "settings.json"),
             *(install.user_settings_all() if os.path.isabs(record) else ()),   # + the absolute paths it records
             *(agent_hooks.config_path(h) for h in agent_hooks.HARNESSES   # it resolves CODEX_HOME itself
               if {"codex": "CODEX_HOME", "qwen": "QWEN_HOME", "interpreter": "INTERPRETER_HOME"}.get(h)
               not in relative)]
    return {os.path.realpath(p) for p in paths if os.path.isabs(p)}, relative


def _pid(hello):
    return hello.get("pid") if type(hello.get("pid")) is int else "?"


def _versions(add, settings, harnesses):
    """D-VERSIONS (dev profile): the Tracekit that each hook's Python imports (Claude Code's in `settings`, the other
    coding agents' in `harnesses`), and the running dev signer's, against this doctor's. An older one is a warning that
    says what to run on this machine; doctor upgrades and stops nothing. It runs only what the user's own hook files
    name (install.user_settings_all, agent_hooks.config_path), with absolute paths: doctor never runs a project's
    commands, so running it in a cloned repository runs none of its code.
    lean: the Claude Code plugin's hook isn't asked: it picks its Python as it runs (plugin/scripts/tracekit-hook), in
    Claude Code's environment, and says itself when it and the signer differ; repeat its search here if that's short"""
    from . import __version__ as mine
    from .integrations.claude_code import VERSION, quote, release, upgrade

    def vs(v):
        r, m = release(v), release(mine)
        return f"older than this doctor's {mine}" if r < m else "as this doctor does" if r == m else \
            f"newer than this doctor's {mine}"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        add("D-VERSIONS", False, "not checked as root: doctor won't run the Python your hooks name as root",
            "run tracekit doctor as the user whose hooks these are", bad=WARN)
        return
    signer = _dev_signer()
    if signer and not VERSION.fullmatch(str(signer.get("version"))):
        signer = {"pid": signer.get("pid")}   # an endpoint.json that names no version doctor prints
    # a signer whose version isn't known yet (still starting) is not called old
    old_signer = bool(signer and signer.get("version")) and release(signer["version"]) < release(mine)
    pythons, old_hooks = {}, False   # (python, the -c hook's tree) -> the hook files that run it
    mine_files, relative = _user_hook_files()
    set_to = ", ".join(f"{k}={os.environ[k][:128]!r}" for k in relative)
    sources = [("Claude Code", settings, lambda: [h.get("command") for hs in _hooks(settings).values() for h in hs])]
    for name, path, cmds in sources + [(h, p, lambda h=h, p=p: _hook_commands(h, p))
                                       for h, p in sorted((harnesses or {}).items())]:
        fix = f"tracekit init --dev --v2{'' if name == 'Claude Code' else f' --agent {name}'}"
        try:
            argvs = [_hook_argv(c) for c in cmds()] if path else []
        except (OSError, ValueError, AttributeError, TypeError):   # D-HOOKS-PRESENT and D-HOOKS-EVENT say why
            continue
        if argvs and os.path.realpath(path) not in mine_files:
            add("D-VERSIONS", False, f"the {name} hooks in {path} not probed: a project hook file"
                + (f", or one that {set_to}, a relative path, places" if relative else "")
                + ". Doctor never runs a project's commands: running it in a cloned repository runs none of its code",
                (f"set {', '.join(relative)} to an absolute path, or unset it; " if relative else "")
                + "check the Tracekit version the Python they name imports once you trust them, or install the hooks "
                "for your user: " + fix, bad=WARN)
            continue
        if None in argvs:
            add("D-VERSIONS", False, f"can't tell which Python runs the {name} hooks in {path}: a command init doesn't "
                "write", f"{fix} writes one", bad=WARN)
        for a in filter(None, argvs):
            try:
                pythons.setdefault(_probe_target(a), {})[f"{name} ({path})"] = None
            except ValueError as e:
                add("D-VERSIONS", False, f"a {name} hook in {path} not probed: it names {e}, which would resolve against "
                    "doctor's working directory", f"{fix} writes absolute paths", bad=WARN)
    for (python, tree), who in pythons.items():
        who = "the hooks of " + ", ".join(who)
        try:
            version, module, user_site = _hook_tracekit(python, tree)
            if not release(version):
                raise ValueError(f"its tracekit says version {version!r}")
        except (OSError, ValueError) as e:
            add("D-VERSIONS", False, f"can't read the Tracekit version {who} run: {python} -I -c 'import tracekit' "
                f"fails ({str(e) or type(e).__name__})", f"install it there ({quote(python)} -m pip install tracekit-ai), or "
                "re-run tracekit init --dev --v2 [--agent NAME] from the Tracekit you use", bad=WARN)
            continue
        old = release(version) < release(mine)
        old_hooks |= old
        add("D-VERSIONS", not old, f"{who} run Tracekit {version} ({python}), {vs(version)}"
            + (": they lack the fixes since" if old else ""), f"`{upgrade(python, module, user_site)}`"
            + (", then `tracekit down`, so the next call starts a signer of the new version (open sessions go on in it: "
               "it keeps their runs and run tokens)" if old_signer else ""), bad=WARN)
    if signer is None:
        add("D-VERSIONS", True, "no dev signer is running (the first call starts one)", "")
    elif not release(signer.get("version")):
        add("D-VERSIONS", False, f"the running dev signer (pid {_pid(signer)}) doesn't say its version",
            "`tracekit down`: the next call starts a new one", bad=WARN)
    else:
        add("D-VERSIONS", not old_signer, f"the running dev signer (pid {_pid(signer)}) runs Tracekit "
            f"{signer['version']}, {vs(signer['version'])}" + (
                ": it keeps that version until it stops, after 15 minutes with no client connected" if old_signer
                else ""), "`tracekit down`" + (" once the hooks above are upgraded" if old_hooks else "")
            + ": the next call starts a signer of the calling hook's version, and open sessions go on in it (it keeps "
            "their runs and run tokens)", bad=WARN)


def _includes_thoughts_off(v):
    """Whether a Gemini CLI settings value sets `includeThoughts: false` anywhere in it."""
    if isinstance(v, dict):
        return v.get("includeThoughts") is False or any(_includes_thoughts_off(x) for x in v.values())
    return isinstance(v, list) and any(_includes_thoughts_off(x) for x in v)


def _reasoning_checks(add, harnesses, vault, fix):
    """Per coding agent with v2 hooks (`harnesses`: {harness: its hook config}): whether the content vault can keep
    readable reasoning from it (D-CODEX-REASONING, D-GEMINI-THOUGHTS; Cursor's thinking text needs no setting)."""
    from . import agent_hooks
    for harness, path in sorted((harnesses or {}).items()):
        if harness == "codex":
            toml = os.path.join(os.path.dirname(path), "config.toml")
            try:
                value = agent_hooks.codex_summary(install.agent_file(toml).decode("utf-8"))
            except (OSError, ValueError):
                value = None
            on, key = value not in (None, "none"), agent_hooks.CODEX_SUMMARY
            add("D-CODEX-REASONING", on or not vault, f'Codex\'s reasoning summaries are on ({key} = "{value}" in {toml})'
                if on else "the content vault is off: no reasoning is kept to check" if not vault else
                f"the content vault keeps each Codex response, but its reasoning summaries are off ({key} is "
                f"{'unset' if value is None else 'none'} in {toml}; Codex's current models default to none): the "
                "model's reasoning is kept sealed or not at all, so `tracekit analyze --v2` can't read it",
                f'add the line {key} = "auto" at the top of {toml} ({fix} --agent codex does)', bad=WARN)
        elif harness == "gemini":
            try:
                off = _includes_thoughts_off((_json(path) or {}).get("modelConfigs"))
            except (OSError, ValueError, AttributeError):
                off = False
            add("D-GEMINI-THOUGHTS", not off or not vault, f"Gemini CLI records its thought summaries ({path} leaves "
                "includeThoughts on)" if not off else "the content vault is off: no reasoning is kept to check"
                if not vault else f"{path} sets includeThoughts: false in modelConfigs: Gemini CLI records no thoughts, "
                "so `tracekit analyze --v2` has no reasoning to read", f"remove includeThoughts: false from "
                f"modelConfigs in {path} (Gemini CLI's default includes thoughts)", bad=WARN)


def _codex_sandbox(add, harnesses):
    """D-CODEX-SANDBOX: whether Codex's settings leave a person to answer its escalations. Codex's PreToolUse hook
    sends a shell call's command alone, so a request to run outside the sandbox, and Codex's answer to it, never reach
    Tracekit (docs/integrations/codex-sandbox.md).
    Keys and values as codex-rs/core/config.schema.json names them in openai/codex rust-v0.172.0; a value this doesn't
    know (such as a `granular` approval policy) gives no WARN.
    lean: reads the config.toml beside Tracekit's hooks and its selected [profiles.<name>]; not a project's
    .codex/config.toml, /etc/codex/config.toml, managed_config.toml or -c flags at launch, which Codex layers on top
    (codex-rs/config/src/loader/README.md, "Layering model")"""
    path = (harnesses or {}).get("codex")
    if not path:
        return
    toml, why = os.path.join(os.path.dirname(path), "config.toml"), None
    try:
        from . import tomlsafe as tomllib   # Python 3.11 and newer
        cfg = tomllib.loads(install.agent_file(toml).decode("utf-8"))
    except FileNotFoundError:   # Codex's defaults: on-request, a person reviews, the feature off
        cfg = {}
    except ImportError:
        why = "Python 3.11 or newer reads Codex's config.toml, this is " + sys.version.split()[0]
    except (OSError, ValueError) as e:   # unreadable, or not TOML
        why = f"{toml}: {e}"
    if why:
        add("D-CODEX-SANDBOX", False, f"can't check Codex's approval settings ({why})",
            f"keep approvals_reviewer = \"user\" and features.exec_permission_approvals off in {toml}", bad=INFO)
        return
    profiles = cfg.get("profiles")
    chosen = profiles.get(cfg.get("profile")) if isinstance(profiles, dict) and isinstance(cfg.get("profile"), str) \
        else None
    layers = [cfg] + ([chosen] if isinstance(chosen, dict) else [])

    def setting(key, table=None):   # the selected profile wins each key
        value, where = None, None
        for layer, name in zip(layers, ("", f"[profiles.{cfg.get('profile')}] ")):
            src = layer.get(table) if table else layer
            if isinstance(src, dict) and key in src:
                value, where = src[key], name
        return value, where or ""

    feature, feature_at = setting("exec_permission_approvals", "features")
    policy, _ = setting("approval_policy")
    reviewer, reviewer_at = setting("approvals_reviewer")
    feature_on = feature is True
    # AskForApproval in codex-rs/protocol/src/protocol.rs: on-request is its #[default] and on-failure an alias of it;
    # under untrusted every command a rule doesn't allow asks for approval. The reviewer answers all of them.
    asks = policy in ("on-request", "on-failure", "untrusted", None)
    model_reviews = asks and reviewer in ("auto_review", "guardian_subagent")
    why, fix = [], []
    if feature_on:
        why.append(f"{feature_at}features.exec_permission_approvals is true in {toml}: Codex can then run some calls "
                   "with no hook, so Tracekit neither decides nor records them")
        fix.append("turn features.exec_permission_approvals off")
    if model_reviews:
        why.append(f'{reviewer_at}approvals_reviewer = "{reviewer}" with approval_policy "{policy or "on-request"}" in '
                   f"{toml}: a model, not a person, answers Codex's approval requests, and Tracekit sees neither the "
                   "request nor the answer")
        fix.append('set approvals_reviewer = "user"')
    add("D-CODEX-SANDBOX", not why, "; ".join(why) or (
        f'Codex asks a person for approval (approval_policy = "{policy or "on-request"}", {toml})'
        if asks and reviewer in ("user", None) else
        f'Codex never asks to run a call outside its sandbox (approval_policy = "never", {toml})' if policy == "never"
        else f"doctor doesn't know Codex's approval settings in {toml} (approval_policy = {policy!r}, "
        f"approvals_reviewer = {reviewer!r})"),
        f"{'; '.join(fix)} in {toml} ({wiki_url('docs/integrations/codex-sandbox.md')})" if fix else "", bad=WARN)


def _agy_runs(add, path, home, fix):
    """D-AGY-HOOKS-RUN: whether agy runs the hooks in `path` at all. It loads and never runs them when Tracekit's
    named hook is disabled (in `path`, the user's hooks.json or this workspace's), or when it signs in with a Gemini
    API key (google-antigravity/antigravity-cli#893) or Application Default Credentials (#1310), set as its install
    docs say.
    lean: reads this process's environment and working directory, which are agy's only when doctor runs in agy's shell
    (dev mode)"""
    from . import agent_hooks

    def get(obj, key):
        return obj.get(key) if isinstance(obj, dict) else None
    settings = os.path.join(home, ".gemini", "antigravity-cli", "settings.json")
    app = os.path.join(home, ".gemini", "config", "config.json")
    off = [p for p in dict.fromkeys((path, agent_hooks.config_path("antigravity", home=home),
                                     agent_hooks.config_path("antigravity", os.getcwd())))
           if get(_setting(p, agent_hooks.AGY_HOOK), "enabled") is False]
    why = [w for w, hit in (
        *((f'Tracekit\'s hook is "enabled": false in {p}', True) for p in off),
        (f"a Gemini API key sign-in (modelProvider gemini in {settings}; antigravity-cli#893)",
         _setting(settings, "modelProvider") == "gemini"),
        (f"Application Default Credentials (enableAdc in {app}; antigravity-cli#1310)",
         get(_setting(app, "userSettings"), "enableAdc") is True),
        ("Application Default Credentials (AGY_ADC_AUTH=true in this environment; antigravity-cli#1310)",
         os.environ.get("AGY_ADC_AUTH", "").lower() == "true")) if hit]
    add("D-AGY-HOOKS-RUN", not why, f"agy loads its hooks and never runs them: {'; '.join(why)}. No agy call is "
        "decided or recorded, and agy doesn't say so" if why else f"nothing stops agy running the hooks in {path}",
        "sign agy in with a Google account (remove modelProvider gemini, enableAdc and AGY_ADC_AUTH), "
        + "".join(f'remove "{agent_hooks.AGY_HOOK}" from {p}, ' for p in off if p != path) + "then " + fix,
        bad=WARN)


def _codex_hash(ev, group, hook):
    """The trusted_hash Codex records for `hook`, in matcher group `group` of event `ev`, once a person trusts it as it
    is now (codex-rs hooks engine/discovery.rs hook_hash: sha256 of the sorted-key JSON of the hook's normal form, its
    event, its matcher where the event takes one, and its handler with Codex's default and clamped timeout); None for a
    handler with a setting Tracekit doesn't write.
    lean: rebuilds only the handler settings init writes (type, command, timeout), so a hook given async,
    statusMessage, commandWindows or additionalContextLimit by hand reads as unconfirmed; rebuild those if people do"""
    t = hook.get("timeout")
    if set(hook) - {"type", "command", "timeout"} or hook.get("type") != "command" or \
            not isinstance(hook.get("command"), str) or t is not None and (type(t) is not int or t < 0):
        return None
    end = ev in ("SessionEnd", "Interrupt")   # 1 s by default, 3 s at most
    ident = {"event_name": re.sub(r"(?<!^)(?=[A-Z])", "_", ev).lower(), "hooks": [
        {"type": "command", "command": hook["command"], "async": False,
         "timeout": min(max(1 if t is None else t, 1), 3) if end else max(600 if t is None else t, 1)}]}
    if group.get("matcher") is not None and ev not in ("UserPromptSubmit", "Stop", "Interrupt", "PreModelRequest",
                                                       "PostModelRequest"):   # events whose matcher Codex drops
        ident["matcher"] = group["matcher"]
    return "sha256:" + hashlib.sha256(json.dumps(ident, sort_keys=True, separators=(",", ":"),
                                                 ensure_ascii=False).encode()).hexdigest()


def _codex_trust(add, path, hooks, home, bad, harness="codex"):
    """D-CODEX-HOOK-TRUST: whether Codex runs Tracekit's hooks, v2 or v1, in `path` (a Codex hooks.json, read as
    `hooks`). Codex runs a hook that isn't managed only once a person trusted it as it is now, and records that in the
    user's config.toml ($CODEX_HOME's, else ~/.codex's; `home`: the agent user's, whose ~/.codex it is) as
    [hooks.state."<hooks.json path>:<event>:<group>:<handler>"] trusted_hash (_codex_hash; enabled = false for a hook
    turned off). Interactive codex asks at startup for a hook that is new or changed; `codex exec` skips it without a
    word (learn.chatgpt.com/docs/hooks; codex-rs/hooks hook_key and engine/discovery.rs). harness "interpreter":
    D-INTERPRETER-HOOK-TRUST, Open Interpreter's, which keeps the same trust in its own home's config.toml (0.0.61,
    recorded: a trusted_hash written from _codex_hash runs the hook)."""
    from . import agent_hooks
    name, cmd, _ = agent_hooks.TRUSTING[harness]
    check = "D-CODEX-HOOK-TRUST" if harness == "codex" else "D-INTERPRETER-HOOK-TRUST"
    keys = {f"{os.path.abspath(path)}:{re.sub(r'(?<!^)(?=[A-Z])', '_', ev).lower()}:{g}:{h}":
            (ev, _codex_hash(ev, group, hook))
            for ev, groups in hooks.items() for g, group in enumerate(groups if isinstance(groups, list) else ())
            if isinstance(group, dict) for h, hook in enumerate(group.get("hooks") if isinstance(group.get("hooks"), list)
                                                                 else ())
            if isinstance(hook, dict) and agent_hooks._version(hook.get("command"))}
    if not keys:   # D-HOOKS-EVENT says there are none
        return
    store, state, why = agent_hooks.codex_trust_store(home, harness), {}, None
    try:
        from . import tomlsafe as tomllib   # Python 3.11 and newer
        state = tomllib.loads(install.agent_file(store).decode("utf-8")).get("hooks", {}).get("state", {})
        if not isinstance(state, dict):
            raise ValueError("hooks.state is not a table")
    except FileNotFoundError:   # no config.toml: Codex recorded no trust
        pass
    except ImportError:
        why = f"Python 3.11 or newer reads {name}'s config.toml, this is " + sys.version.split()[0]
    except (OSError, ValueError, AttributeError) as e:   # unreadable, not TOML, or not of tables
        why = f"{store}: {e}"
    entry = {k: state.get(k) if isinstance(state.get(k), dict) else {} for k in keys}
    untrusted = sorted({keys[k][0] for k, s in entry.items() if not s.get("trusted_hash")})
    changed = sorted({keys[k][0] for k, s in entry.items() if s.get("trusted_hash") and keys[k][1]
                      and s["trusted_hash"] != keys[k][1]})
    unsure = sorted({keys[k][0] for k, s in entry.items() if s.get("trusted_hash") and not keys[k][1]})
    off = sorted({keys[k][0] for k, s in entry.items() if s.get("enabled") is False})
    step = (f"run {cmd} in a terminal, type /hooks and trust Tracekit's hooks (from {path}); {name} asks again "
            "whenever they change, as after tracekit init")
    silent = f"so no {name} call is decided or recorded (interactive {cmd} asks at startup; `{cmd} exec` doesn't)"
    if why:
        add(check, False, f"can't confirm that {name} trusts Tracekit's hooks in {path} ({why}): {name} runs a hook "
            f"only once a person trusted it, and `{cmd} exec` skips one without a word", step, bad=WARN)
        return
    if unsure and not (untrusted or changed or off):
        add(check, False, f"{name}'s trust is recorded for Tracekit's hooks in {path} ({store}); doctor can't confirm "
            f"it's for these exact hooks: the {', '.join(unsure)} hook(s) have settings Tracekit doesn't write, whose "
            "hash doctor doesn't rebuild", step, bad=WARN)
        return
    add(check, not (untrusted or changed or off),
        f"{name} skips Tracekit's {', '.join(untrusted)} hook(s) in {path}: nobody trusted them in {name} ({store} "
        f"records no trust), {silent}" if untrusted else
        f"{name} skips Tracekit's {', '.join(changed)} hook(s) in {path}: they changed since a person trusted them "
        f"(the trust {store} records is for an earlier version of them, as after tracekit init), {silent}" if changed
        else f"Tracekit's {', '.join(off)} hook(s) in {path} are turned off in {name}'s /hooks ({store}): {name} runs "
        "none of them" if off else f"{name} trusts each of Tracekit's hooks in {path} as they are now ({store})",
        step if untrusted or changed else f"run {cmd} in a terminal, type /hooks and turn Tracekit's hooks back on",
        bad=bad)


def _hook_run(scale=1, unit="s"):
    """What D-HOOKS-TIMEOUT holds a pre-tool hook's timeout to (claude_code._pre): the hook answers within
    APPROVAL_WAIT_S, and a held call's hook waits for its answer only with TRACEKIT_APPROVAL_WAIT set, keeping two
    signer calls' time (30 s each, the hook client's timeout) of it for the answer and the consume."""
    from .integrations.claude_code import APPROVAL_WAIT_S, WAIT_ENV
    return (f"the hook answers within {APPROVAL_WAIT_S * scale} {unit} (a held call waits up to about "
            f"{(APPROVAL_WAIT_S - 2 * 30) * scale} {unit}, only with {WAIT_ENV} set)")


def _openhands_checks(add, path, home, fix):
    """OpenHands (#563): the CLI reads the hooks of its working directory ($OPENHANDS_WORK_DIR, else the current one),
    .openhands/hooks.json, in place of the user's ~/.openhands/hooks.json when it exists (HookConfig.load reads the first
    that exists; $OPENHANDS_PERSISTENCE_DIR moves the CLI's settings, not this file). Only a Tracekit v2 hook on
    PreToolUse there decides its calls."""
    from . import agent_hooks
    project = agent_hooks.config_path("openhands", os.environ.get("OPENHANDS_WORK_DIR") or os.getcwd())
    if os.path.realpath(path) == os.path.realpath(project) or not os.path.exists(project):
        return
    try:
        ours = any(agent_hooks._version(h.get("command")) == "v2"
                   for g in _harness_hooks("openhands", _json(project) or {}).get("PreToolUse") or ()
                   if isinstance(g, dict) for h in g.get("hooks") or () if isinstance(h, dict))
    except (OSError, ValueError, AttributeError, TypeError):
        ours = False
    add("D-OPENHANDS-PROJECT", ours,
        f"{project} replaces {path} here: the OpenHands CLI reads only the first of them that exists, and it has no "
        "Tracekit v2 PreToolUse hook, so in this directory OpenHands runs its calls undecided" if not ours else
        f"{project} has Tracekit's v2 PreToolUse hook",
        f"{fix} --project (in this directory), or don't run OpenHands on this repo", bad=WARN)


def _ps_policy():
    """PowerShell's effective execution policy (Restricted, RemoteSigned, ...), else None when it can't be read."""
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
                              capture_output=True, text=True, timeout=15).stdout.strip() or None
    return None


def _harness_hook_checks(add, harnesses, prod, home=None):
    """Event arguments and approval timeouts of the other coding agents' v2 command hooks (home: the agent user's home
    directory, where agy's sign-in settings are)."""
    from . import agent_hooks
    from .integrations.claude_code import APPROVAL_WAIT_S
    for harness, path in sorted((harnesses or {}).items()):
        if harness == "cline":   # its hooks are files, one per event: a second copy of them runs each hook again
            fix = "keep Tracekit's Cline hooks in one place: tracekit uninstall --agent cline [--project] for the other"
            copies = [d for d in agent_hooks.cline_dirs(home)
                      if agent_hooks._version(_text(os.path.join(d, agent_hooks.CLINE_FILE))) is not None]
            add("D-HOOKS-EVENT", len(copies) < 2,
                f"Tracekit's Cline hooks are in {' and '.join(copies)}: Cline runs both, so each call is decided and "
                "recorded twice" if len(copies) > 1 else f"Tracekit's Cline hooks are in one place ({path})", fix, bad=WARN)
            if os.name == "nt":   # Cline's CLI runs a .ps1 hook with `powershell -File`, under the execution policy
                policy = _ps_policy()
                add("D-HOOKS-EVENT", policy not in ("Restricted", "AllSigned"),
                    f"PowerShell's execution policy is {policy}: Cline's CLI can't start Tracekit's .ps1 hooks, so "
                    "every call runs undecided (its VS Code extension passes -ExecutionPolicy Bypass)"
                    if policy in ("Restricted", "AllSigned") else
                    f"PowerShell's execution policy ({policy or 'unread'}) lets Cline's CLI start Tracekit's hooks",
                    "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned", bad=WARN)
            continue
        fix = REINIT if prod else f"tracekit init --dev --v2 --agent {harness}"   # collect() adds system init's agent
        if harness == "opencode":
            _opencode_loads(add, path, fix, FAIL if prod else WARN)
        if harness not in agent_hooks.HARNESSES or harness in agent_hooks.PLUGIN_TOOLS:   # a JavaScript plugin
            continue
        if harness == "gptme":
            if not prod:
                ok, detail = _gptme_load_check(path)
                add("D-GPTME-LOAD", ok, detail, fix, bad=WARN)
            continue
        if harness == "antigravity":
            _agy_runs(add, path, home or os.path.expanduser("~"), fix)
        if harness == "qwen":
            _qwen_runs(add, path, home)
        if harness == "kiro":
            version = agent_hooks.kiro_version()
            old = version is not None and version < (3,)
            add("D-HOOKS-EVENT", not old,
                agent_hooks.KIRO_OLD.format(".".join(map(str, version))) if old else
                f"Kiro CLI {'.'.join(map(str, version)) if version else '(version unread)'} runs the hook files in "
                f"{os.path.dirname(path)}", "upgrade Kiro CLI to 3.0 or later", bad=WARN)
            with contextlib.suppress(OSError, ValueError, AttributeError, TypeError):
                off = sorted({h.get("trigger") for h in (_json(path) or {}).get("hooks") or ()
                              if isinstance(h, dict) and h.get("enabled") is False and isinstance(h.get("action"), dict)
                              and agent_hooks._version(h["action"].get("command")) is not None})
                add("D-HOOKS-EVENT", not off,
                    f'Tracekit\'s Kiro {", ".join(map(str, off))} hook(s) are "enabled": false in {path}, so Kiro '
                    "skips them" if off else f"Tracekit's Kiro hooks in {path} are enabled", fix, bad=WARN)
        try:
            hooks = _harness_hooks(harness, _config(harness, path))
            every = _hook_entries(hooks)
            cmds = [(ev, h) for ev, h in every if agent_hooks._version(h.get("command")) == "v2"]
        except (OSError, ValueError, AttributeError, TypeError) as e:
            add("D-HOOKS-EVENT", False, f"cannot check {harness} hooks in {path}: {e}", fix, bad=WARN)
            continue
        if harness == "interpreter":   # /import copies Claude Code's hooks into the user's file (#940)
            held = {path: every}
            user = agent_hooks.config_path(harness, home=home)
            if os.path.realpath(user) != os.path.realpath(path):
                with contextlib.suppress(OSError, ValueError, AttributeError, TypeError):   # none, or not hooks
                    held[user] = _hook_entries(_harness_hooks(harness, _config(harness, user)))
            copied = {f: sorted({ev for ev, h in entries if install._cmd_version(h.get("command")) is not None})
                      for f, entries in held.items()}
            copied = {f: evs for f, evs in copied.items() if evs}
            add("D-HOOKS-EVENT", not copied,
                " and ".join(f"{f} holds Tracekit's Claude Code hook ({', '.join(evs)})" for f, evs in copied.items())
                + ": Open Interpreter runs it as well as its own, so each call is decided a second time, recorded as "
                "claude-code" if copied else f"no Tracekit Claude Code hook in {' or '.join(held)}",
                f"remove Tracekit's Claude Code hook from {' and '.join(copied or held)}", bad=WARN)
        if harness in agent_hooks.TRUSTING:
            _codex_trust(add, path, hooks, home, FAIL if prod else WARN, harness)
        if harness == "openhands":
            _openhands_checks(add, path, home, fix)
        unnamed =sorted({ev for ev, h in cmds if not re.search(rf"\b{re.escape(ev)}\b", h["command"])})
        blocking = sorted({ev for ev, h in cmds if ev not in agent_hooks.PRE
                           and (FAIL_CLOSED in h["command"] or h.get("failClosed") is True)})   # Cursor's failClosed
        pre = [h for ev, h in cmds if ev in agent_hooks.PRE]
        # Cursor and goose let a call through when its pre-tool hook can't run, unless the hook says to block it
        key, block = {"cursor": ("failClosed", True), "goose": ("on_failure", "block")}.get(harness, (None, None))
        lets_past = key and any(h.get(key) != block for h in pre)
        add("D-HOOKS-EVENT", bool(pre) and not unnamed and not blocking and not lets_past,
            f"no v2 {harness} hook commands found in {path}" if not cmds else
            f"{harness} hooks in {path}: no Tracekit v2 hook on the pre-tool event, so {harness} runs every tool call "
            "undecided and unrecorded" if not pre else
            f"{harness} hooks in {path}: {', '.join(unnamed)} command(s) do not name their configured event; "
            "a pre-tool payload the hook cannot read can pass unrecorded" if unnamed else
            f"{harness} hooks in {path}: the {', '.join(blocking)} hook(s) block their event when the hook can't run, "
            "not only tool calls (an older init wrote them)" if blocking else
            f"{harness} hooks in {path}: the pre-tool hook has no {key}: {json.dumps(block)}, so {harness} runs a call "
            "whose hook can't run, undecided and unrecorded" if lets_past else
            f"each {harness} hook command in {path} names its event", fix, bad=WARN)
        if harness == "codebuddy":
            off = _codebuddy_off(home)
            add("D-HOOKS-EVENT", not off,
                f"disableAllHooks is set in {off}: CodeBuddy Code runs none of its hooks, so every call runs "
                "undecided and unrecorded" if off else "no CodeBuddy Code settings file turns its hooks off",
                f'remove "disableAllHooks" from {off}' if off else fix, bad=FAIL if prod else WARN)
            moved = (os.environ.get("CODEBUDDY_CONFIG_DIR") or "").strip()
            here = os.path.dirname(path)
            if moved and os.path.realpath(os.path.expanduser(moved)) != os.path.realpath(here):
                add("D-HOOKS-EVENT", False,
                    f"CODEBUDDY_CONFIG_DIR names {moved}, but Tracekit's hooks are in {path}: a CodeBuddy Code started "
                    "with that variable reads another settings file, so these hooks don't run",
                    f"unset CODEBUDDY_CONFIG_DIR, or re-run init where it names {here}", bad=WARN)
            later = _codebuddy_later(home)
            add("D-HOOKS-ORDER", not later,
                f"a CodeBuddy Code PreToolUse hook in {' and '.join(later)} runs after Tracekit's, and CodeBuddy takes "
                "the last hook's permissionDecision: its allow runs a call Tracekit denied" if later else
                "no other CodeBuddy Code PreToolUse hook runs after Tracekit's",
                "have no hook that runs after Tracekit's answer permissionDecision allow, or remove it", bad=WARN)
        if harness == "jcode":   # jcode runs its gates in order, and one's updatedInput replaces the input the next
            # gates get and the tool runs with. Find the first Tracekit module even under another interpreter;
            # any later gate but an exact command init writes may rewrite the call, as for CodeBuddy Code
            gates = [h["command"] for h in hooks.get("PreToolUse", ())]
            mine = {agent_hooks._command("jcode", "PreToolUse", v2, python)
                    for v2 in (True, False) for python in (None, install.OPT_PYTHON)}
            start = next((i + 1 for i, c in enumerate(gates) if agent_hooks._version(c) is not None), len(gates))
            after = [c for c in gates[start:] if c not in mine]
            add("D-HOOKS-ORDER", not after,
                f"{len(after)} jcode pre_tool command(s) in {path} run after Tracekit's: a gate's updatedInput replaces "
                "the input of the call Tracekit decided" if after else "Tracekit's is the last jcode pre_tool command",
                f"put Tracekit's command last in pre_tool in {path}", bad=WARN)
        scale, unit = (1000, "ms") if harness in ("gemini", "qwen") else (1, "s")
        # a timeout the hook doesn't set: agy's and Crush's own default is 30 s
        default = 30 if harness in ("antigravity", "crush", "copilot") else 60
        pre = [h.get("timeout", default * scale) for h in pre]
        pre = [t if type(t) in (int, float) and 0 <= t < float("inf") else 0 for t in pre]
        if pre:
            add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S * scale,
                f"{harness} pre-tool timeout {min(pre)} {unit} in {path}; " + _hook_run(scale, unit), fix, bad=WARN)


def _qwen_runs(add, path, home):
    """Whether Qwen Code (0.28.0) runs Tracekit's hooks in `path` (home: the agent user's home, else this user's): none
    while a settings file sets disableAllHooks (a true value), and a project's none when folder trust is on and the
    project's folder isn't trusted (_folder_trust), as Qwen Code then loads none of the project's settings.
    lean: with folder trust off a project's hooks run only once a person approves them (hookApprovals.json, bound to
    the hooks' exact configuration), which doctor doesn't read"""
    from . import agent_hooks
    project = agent_hooks.config_path("qwen", os.getcwd())
    files = [p for p in dict.fromkeys([*_gemini(agent_hooks.config_path("qwen", home=home), project, "qwen"), path])
             if p not in (project, path) or _folder_trust("qwen", home, p)[0] is not False]   # Qwen Code loads it
    off = [p for p in files if _setting(p, "disableAllHooks") not in (None, False, 0, "")]
    if off:
        add("D-HOOKS-EVENT", False, f"disableAllHooks is set in {', '.join(off)}: Qwen Code runs none of its hooks, so "
            "every call runs undecided and unrecorded", f'remove "disableAllHooks" from {", ".join(off)}', bad=WARN)
    loads, trust, _ = _folder_trust("qwen", home, path)   # no variable decides Qwen Code's
    folder = os.path.dirname(os.path.dirname(path))
    if not loads:
        add("D-HOOKS-EVENT", False, (f"folder trust is on and {trust} doesn't trust {folder}: Qwen Code loads none of "
            f"its settings there, so the hooks in {path} don't run" if loads is False else f"{trust} can't be read, "
            f"so doctor can't tell whether Qwen Code trusts {folder} and runs the hooks in {path}")
            + " (IDE trust, which doctor can't see, decides first)", f"trust {folder} in Qwen Code (/permissions)",
            bad=WARN)


def _opencode_loads(add, path, fix, bad):
    """D-OPENCODE-PLUGIN: whether the OpenCode on PATH loads Tracekit's plugin at `path`. OpenCode 2.x (@opencode/cli)
    loads a plugin only from its default export, {id, setup}; one without it (as an earlier Tracekit wrote) it logs as
    failed to load and runs every call undecided, and says nothing else.
    lean: reads `opencode --version` from doctor's PATH, which is OpenCode's only when doctor runs where OpenCode does"""
    try:
        default = re.search(r"^export default \{", install.agent_file(path).decode("utf-8", "replace"), re.M)
    except OSError as e:
        add("D-OPENCODE-PLUGIN", False, f"cannot read Tracekit's OpenCode plugin {path}: {e}", fix, bad=bad)
        return
    exe, out = shutil.which("opencode"), ""
    with contextlib.suppress(OSError, subprocess.SubprocessError):   # never a program the working directory placed
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15).stdout \
            if _outside_cwd(exe) else ""
    major = re.search(r"(\d+)\.\d+\.\d+", out)
    two = major is not None and int(major[1]) >= 2
    add("D-OPENCODE-PLUGIN", bool(default),
        f"Tracekit's plugin {path} has the default export OpenCode 2.x loads, and the plugin 1.x loads"
        if default else f"Tracekit's plugin {path} has no default export: OpenCode {major[0]} can't load it, so every "
        "call runs undecided and unrecorded (its log says \"failed to load plugin\")" if two else
        f"Tracekit's plugin {path} has no default export: OpenCode 2.x can't load it, so after an upgrade every call "
        "would run undecided and unrecorded", fix, bad=bad if two else WARN)


def _codebuddy_off(home=None):
    """The CodeBuddy Code settings file whose `disableAllHooks` is in force, or None. The layers are CodeBuddy's own
    settings order — its settings page, "Settings Priority": the user's `settings.json`, the project's
    `.codebuddy/settings.json`, then `settings.local.json` beside it — and the last file that sets the key decides.
    `@tencent-ai/codebuddy-code` 2.183.0 (`dist/codebuddy.js`) reads exactly those three files for the key in
    `settingsDisableAllHooks`, which is `codebuddy plugin test`'s refusal helper (module 902551, beside
    `pluginTestFormOf` and `pluginTestRefusal`, called only from `runPluginTestFastPath`) — not the code that decides
    whether a session runs its hooks, which the bundle doesn't expose. It keeps the last value
    (`eA?.disableAllHooks !== void 0 && (el = eA.disableAllHooks)`) and returns `true === el`, so this reads a literal
    `true`: a later file's `false` lifts an earlier file's `true`, and a later `null` does not, which matches it rather
    than JavaScript truthiness.
    lean: `allowManagedHooksOnly` turns the hooks off too ("hooks modules are turned off here (disableAllHooks,
    allowManagedHooksOnly or a policy)"), but CodeBuddy reads it only from its managed settings documents
    (`parseManagedModSettings`), which doctor can't see"""
    from . import agent_hooks
    user = agent_hooks.config_path("codebuddy", home=home) if home else agent_hooks.config_path("codebuddy")
    project = agent_hooks.config_path("codebuddy", os.getcwd())
    at, value = None, None
    for f in dict.fromkeys([user, project, os.path.join(os.path.dirname(project), "settings.local.json")]):
        v = _setting(f, "disableAllHooks")
        if v is not None:
            at, value = f, v
    return at if value is True else None


def _codebuddy_later(home=None):
    """The settings files with a CodeBuddy Code PreToolUse hook that runs after Tracekit's. CodeBuddy runs the user's
    settings' hooks (`home`: the agent user's home), then the project's .codebuddy/settings.json and
    settings.local.json (doctor's working directory's), each in its order, and the last permissionDecision stands.
    Tracekit's hook is the first that runs its module; after it, any hook but the exact PreToolUse command init writes
    (v1 or v2, dev or system mode) is named: one that only names the module, in a comment, may answer anything.
    lean: a plugin's, a skill's or an SDK host's hooks, which run later too, aren't read (docs/limits.md). The bundle
    names the file a plugin's hooks live in — `hooks/hooks.json` inside the plugin ("no hooks module to load;
    hooks/hooks.json names none in …", "hooks.json declares PreToolUse/PermissionRequest at its top") — but not the root
    a plugin or a skill is installed under, which is what a check would have to walk"""
    from . import agent_hooks
    mine = {agent_hooks._command("codebuddy", "PreToolUse", v2, python)
            for v2 in (True, False) for python in (None, install.OPT_PYTHON)}
    project = agent_hooks.config_path("codebuddy", os.getcwd())
    files = [agent_hooks.config_path("codebuddy", home=home) if home else agent_hooks.config_path("codebuddy"),
             project, os.path.join(os.path.dirname(project), "settings.local.json")]
    ours, later = False, []
    for f in dict.fromkeys(files):
        try:
            hooks = [h for g in _json(f)["hooks"]["PreToolUse"] for h in g["hooks"]]
        except (OSError, ValueError, LookupError, TypeError):   # no file, no hooks, or not CodeBuddy's shape
            continue
        for h in hooks:
            cmd = h.get("command") if isinstance(h, dict) else None
            if ours and not (isinstance(cmd, str) and cmd in mine) and f not in later:
                later.append(f)
            ours = ours or agent_hooks._version(cmd) is not None
    return later


def _text(path):
    """A file the agent's user controls as text (install.agent_file), or "" when it can't be read."""
    try:
        return install.agent_file(path).decode("utf-8", "replace")
    except OSError:
        return ""


_loads = install.agent_loads


def _json(path):
    """A settings file the agent's user controls, parsed (install.agent_file: a FIFO or a device can't hang or flood
    doctor)."""
    return install.agent_json(path)


_setting = install.setting   # a Claude Code settings file's key, or None


def _user(name):
    try:
        return pwd.getpwnam(name) if name and pwd else None
    except KeyError:
        return None


def _access(targets):
    """The targets the agent's user can reach, as [[path, mode]]. "read" asks for R_OK and "write" for W_OK; "open"
    is for a folder, which has to be *entered*: a folder at 0744 is readable by others and cannot be listed or walked
    into, so the files in it are unreadable to Claude Code too, and R_OK alone would call it fine."""
    return [[p, m] for p, m in targets
            if os.access(p, os.R_OK | os.X_OK if m == "open" else os.W_OK if m == "write" else os.R_OK)]


def agent_access(pw, targets):
    """The (path, "read"|"write"|"open") targets the agent's user can access, probed as that user without changing
    anything; None when this process can't act as it (not root, not the agent)."""
    if not hasattr(os, "geteuid") or os.geteuid() not in (0, pw.pw_uid):
        return None
    return files.as_user(pw, _access, targets)


def _mounts():
    """(mount point, file system type) of every mount."""
    if sys.platform.startswith("linux"):
        with open("/proc/self/mounts", encoding="utf-8") as f:
            return [(p[1].replace("\\040", " "), p[2]) for p in (line.split() for line in f) if len(p) > 2]
    try:
        out = subprocess.run(["mount"], capture_output=True, text=True).stdout
    except OSError:   # no mount command (Windows)
        return []
    return re.findall(r" on (.+) \(([^,)]+)", out)


def fs_type(path):
    path = os.path.realpath(path)
    mounts = [m for m in _mounts() if path == m[0] or path.startswith(m[0].rstrip("/") + "/")]
    return max(mounts, key=lambda m: len(m[0]))[1] if mounts else "unknown"


def _hardening(unit):
    """(score, missing) of the service file against the hardening init writes."""
    if unit.endswith(".plist"):
        import plistlib
        with open(unit, "rb") as f:
            got = plistlib.load(f)
        want = {"InitGroups": False, "Umask": 0o027}
        missing = [f"{k}={v}" for k, v in want.items() if got.get(k) != v]
        missing += [] if got.get("UserName") not in (None, "root") else ["UserName=<signer user>"]
        return f"{len(want) + 1 - len(missing)}/{len(want) + 1}", missing
    service = install.V2_UNIT_TEXT.split("[Service]")[1].split("[Install]")[0]
    want = [line for line in service.splitlines() if "=" in line and "{" not in line]
    lines = {line.strip() for line in read_text(unit).splitlines()}
    missing = [d for d in want if d not in lines]
    if not any(line.startswith("User=") and line != "User=root" for line in lines):
        missing.append("User=<signer user>")
    if any(line.startswith(("CapabilityBoundingSet=", "AmbientCapabilities=")) and "CAP_" in line for line in lines):
        missing.append("an empty capability set")
    return f"{len(want) + 1 - len(missing)}/{len(want) + 1}", missing


def helper_result(unit, fix):
    """D-HARNESS-HELPER: the harness helper's service file, whose capability bounding set must be exactly HELPER_CAPS
    (it alone reads other users' /proc/<pid>/exe). macOS has no capability sets: there the plist must exist."""
    if unit.endswith(".plist"):
        ok = os.path.exists(unit)
        return result("D-HARNESS-HELPER", OK if ok else FAIL, f"harness helper: {unit}" + ("" if ok else " is missing"),
                      fix)
    try:
        caps = [line.split("=", 1)[1].strip() for line in read_text(unit).splitlines()
                if line.startswith("CapabilityBoundingSet=")]
    except OSError as e:
        return result("D-HARNESS-HELPER", FAIL, f"harness binding is on but {unit}: {e.strerror}", fix)
    return result("D-HARNESS-HELPER", OK if caps == [HELPER_CAPS] else FAIL,
                  f"harness helper {os.path.basename(unit)}: CapabilityBoundingSet="
                  + (" + ".join(caps) or "(unset: every capability)"), fix)


def _hooks(settings):
    """{tool event: [v2 hook entries, each with its group's "matcher"]} of a Claude Code settings file."""
    hooks = (_json(settings) or {}).get("hooks") or {}
    return {ev: [{**h, "matcher": g.get("matcher")} for g in hooks.get(ev) or ()
                 if isinstance(g, dict) and install._hook_version(g) == "v2"
                 for h in g.get("hooks") or () if isinstance(h, dict)] for ev in install.TOOL_EVENTS}


def _plugin_idle(plugin, prod, settings=None):
    """Why `plugin` (`(settings_path, key)`) doesn't count as active Claude Code hooks, or None when it does.
    In system mode (`prod`), only a root-trusted managed settings file counts: collect()'s --no-hooks and
    D-HOOKS-PRESENT's decided-twice check both call this so the two never disagree."""
    if not plugin:
        return None
    plugin_settings, _ = plugin
    admin = settings if settings in install.MANAGED_SETTINGS.values() else _managed()
    in_managed = plugin_settings in install.MANAGED_SETTINGS.values()
    if not in_managed and _setting(admin, "allowManagedHooksOnly") is True:
        return "allowManagedHooksOnly"
    if not prod:
        return None
    if not in_managed:
        return "not_managed"
    bad = trusted_file(plugin_settings)
    if bad:
        return f"untrusted: {bad}"
    if _setting(plugin_settings, "disableAllHooks") not in (None, False, 0, ""):
        return f"disableAllHooks in {plugin_settings}"
    return None


def _plugin_note(plugin_settings, why, kept=False):
    if not why:
        return ""
    if why == "allowManagedHooksOnly":
        return f"; the Tracekit plugin's, enabled in {plugin_settings}, don't run (allowManagedHooksOnly)"
    prefix = "; init's hooks kept: " if kept else "; "
    if why == "not_managed":
        return f"{prefix}the Tracekit plugin is enabled in {plugin_settings}, not managed settings"
    if why.startswith("disableAllHooks "):
        return f"{prefix}the Tracekit plugin, enabled in {plugin_settings}, doesn't run ({why})"
    reason = why[len("untrusted: "):]
    return f"{prefix}the Tracekit plugin is enabled in {plugin_settings}, which isn't root-only ({reason})"


def _vault_off(cfg, keys):
    """(ok, detail, fix) of D-CONTENT-VAULT with the vault off: what it kept while it was on stays until erased."""
    from .storage import file as file_store
    off = "off: the signer keeps commitments only, no content"
    if not os.path.exists(os.path.join(keys, "content.key")):
        return True, off, ""
    fix = "erase them (tracekit signer content erase --run R), or keep them: retention still erases them"
    if cfg.get("storage"):   # a reader's role has no grant on the vault's tables
        return False, "off, but keys/content.key exists: runs kept while it was on may still be retained", fix
    try:
        n = len(file_store.content_runs(os.path.join(cfg["data_dir"], "store")))
    except (OSError, ValueError, KeyError) as e:
        return False, f"off; cannot count the runs still retained: {e}", "run doctor as root"
    return (False, f"off, {n} runs still retained (erase or keep)", fix) if n else (True, off, "")


def _acl_perms(out, uid):
    """The permissions `getfacl -n` output `out` gives uid: its named entry (as the mask leaves it), else other's."""
    # lean: the groups' entries aren't read; init grants the tailer's user a named entry
    named = other = None
    for line in out.splitlines():
        entry, _, effective = line.partition("#effective:")
        parts = entry.strip().split(":")
        if len(parts) == 3 and parts[:2] == ["user", str(uid)]:
            named = effective.strip() or parts[2]
        elif len(parts) == 3 and parts[0] == "other":
            other = parts[2]
    return named if named is not None else other or ""


def _tailer_checks(add, client_json, agent):
    """D-TAILER-*: what system init sets up for a Claude Code agent's transcript tailer (install._tailer_acl,
    install._tailer_sudo, client.json's `tailer` key). Without it each session records a tailer_lost gap, whose signed
    reason sends the reader here."""
    try:
        sc = read_json(client_json)
    except (OSError, ValueError):   # D-SYSTEM-CONFIG's
        return
    hooks = sc.get("hooks") if isinstance(sc, dict) else None
    if not isinstance(hooks, dict) or hooks.get("agent", "claude") != "claude":   # the tailer reads Claude Code's only
        return
    t = sc.get("tailer")
    if not (isinstance(t, dict) and isinstance(t.get("user"), str) and type(t.get("uid")) is int
            and isinstance(t.get("python"), str)):
        add("D-TAILER-CONFIG", False, f"{client_json} " + ("names no tailer" if t is None else
            "has a tailer that isn't {user, uid, python}") + ": each Claude Code session records a tailer_lost gap "
            "instead of its transcript", REINIT, bad=WARN)
        return
    user, uid, python = t["user"], t["uid"], t["python"]
    add("D-TAILER-CONFIG", True, f"{client_json} names the tailer: {user} (uid {uid}), {python}", "")
    pw = _user(user)
    add("D-TAILER-USER", pw is not None and pw.pw_uid == uid, f"no user {user}" if pw is None else
        f"{user} has uid {pw.pw_uid}, not {uid}: the signer lets only uid {uid} make the tailer's calls"
        if pw.pw_uid != uid else f"the tailer's user {user} has uid {uid}", REINIT, bad=WARN)

    sudoers, cmd = install.TAILER_SUDOERS, f"{python} -I -m tracekit.tailer"
    try:
        st = os.lstat(sudoers)
        bad = [why for why, hit in ((f"{sudoers} isn't a file", not stat.S_ISREG(st.st_mode)),
                                    (f"{sudoers} belongs to uid {st.st_uid}, not root", st.st_uid != 0),
                                    (f"{sudoers} is {stat.S_IMODE(st.st_mode):04o}, not 0440",
                                     stat.S_IMODE(st.st_mode) != 0o440)) if hit]
        if bad:
            add("D-TAILER-SUDO", False, "; ".join(bad), f"sudo chown 0:0 {sudoers}; sudo chmod 440 {sudoers}; or "
                + REINIT)
        else:
            # the exact line install._tailer_sudo writes, so a commented-out line or another user's rule doesn't count
            rule = f"{agent.pw_name} ALL=({user}) NOPASSWD: {cmd}" if agent else None
            text = read_text(sudoers)
            named = rule in (ln.strip() for ln in text.splitlines()) if rule else cmd in text
            add("D-TAILER-SUDO", named, f"{sudoers} lets the agent's user start {cmd}" if named else
                f"{sudoers} has no rule for {cmd}: the agent's user can't start the tailer", REINIT, bad=WARN)
    except FileNotFoundError:
        add("D-TAILER-SUDO", False, f"{sudoers} is missing: the agent's user can't start the tailer", REINIT, bad=WARN)
    except OSError as e:
        add("D-TAILER-SUDO", False, f"cannot read {sudoers}: {e.strerror}", ROOT_DOCTOR, bad=WARN)
    except ValueError as e:   # not UTF-8
        add("D-TAILER-SUDO", False, f"cannot read {sudoers}: {e}", REINIT, bad=WARN)

    getfacl = shutil.which("getfacl")
    if not agent or not sys.platform.startswith("linux") or not getfacl:
        add("D-TAILER-ACL", False, "not checked: " + ("no agent user is known (client.json names none)" if not agent
            else f"doctor reads ACLs on Linux only, this is {sys.platform}" if not sys.platform.startswith("linux")
            else "no getfacl (install the acl package)"),
            f"check that {user} can search {agent.pw_dir} and ~/.claude and read ~/.claude/projects"
            if agent else REINIT, bad=WARN)
        return
    dot = os.path.join(agent.pw_dir, ".claude")
    missing = []
    for path, need in ((agent.pw_dir, "x"), (dot, "x"), (os.path.join(dot, "projects"), "rx")):
        try:
            r = subprocess.run([getfacl, "-n", "-p", path], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as e:
            missing.append(f"{path}: {e}")
            continue
        got = _acl_perms(r.stdout, uid) if r.returncode == 0 else None
        if got is None:
            missing.append(f"{path}: {(r.stderr or '').strip()[:256] or f'getfacl exited {r.returncode}'}")
        elif not all(c in got for c in need):
            missing.append(f"{path} ({got or 'no entry'}, needs {'read and search' if need == 'rx' else 'search'})")
    add("D-TAILER-ACL", not missing, f"{user} can't reach the transcripts: " + "; ".join(missing) if missing else
        f"{user} can search {agent.pw_dir} and {dot} and read {os.path.join(dot, 'projects')}", REINIT, bad=WARN)


def v2_checks(config, profile="production", agent=None, settings=None, signer=None, opt=None, unit=None,
              client_json=None, now=None, issuer_key=None, plugin=None, sandbox_settings=(), gemini_settings=(),
              harnesses=None, no_hooks=False, gemini_project=None):
    """Checks of a v2 signer. config: a signer.yaml path, or the dev signer's config dict. profile "dev" turns what
    a dev setup can't have into warnings. agent: the agent's pwd entry; settings: its Claude Code settings; signer: the
    socket client.json names; opt: the root-owned venv; unit: the service file; client_json: the system client config;
    issuer_key: the KMS key of the record key issuer, which this host's AWS principal must not sign with; plugin: the
    (settings file, plugin key) returned by install.plugin_enabled, whose hooks are init's;
    sandbox_settings: the Claude Code settings files that set its sandbox, lowest rank first (_sandbox);
    gemini_settings: Gemini CLI's settings files, lowest rank first (_gemini), of which gemini_project is the project's
    (left out of D-GEMINI-SANDBOX when Gemini doesn't trust its folder: _folder_trust); harnesses: {coding agent: its hook
    config} of the other agents with v2 hooks (agent_hooks), whose hooks and reasoning settings are checked; no_hooks:
    init was told --no-hooks (install.record_hooks_settings; system mode: client.json's hooks.no_hooks), so no Claude
    Code hook is the person's choice."""
    from . import agent_hooks
    from .format import checkpoint
    from .integrations.claude_code import APPROVAL_WAIT_S
    from .signer import service
    from .storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, RECORDS
    from .tlog_witness import TlogWitness
    prod, out, now = profile != "dev", [], time.time() if now is None else now
    sev = FAIL if prod else WARN

    def add(id, ok, detail, fix, bad=FAIL):
        out.append(result(id, OK if ok else INFO if not prod and id in DEV_INFO else bad, detail, fix))

    if isinstance(config, dict):
        cfg = config
    else:
        try:
            cfg = service.load_config(config)
        except (OSError, ValueError) as e:
            return [result("D-CONFIG", FAIL, f"signer.yaml does not load: {e}", "fix signer.yaml, or " + REINIT)]
        bad = trusted_file(os.path.abspath(config))
        add("D-CONFIG", not bad, bad or f"{config} is root-owned and loads",
            "make it and its directories root-owned and not group/world-writable (sudo chown 0:0; chmod go-w)")
    data = cfg["data_dir"]
    keys = os.path.join(data, "keys")
    # dev, before the dev signer's first start (no store yet, as right after init): what that start makes is info,
    # not a fault
    first = not prod and not os.path.isdir(os.path.join(data, "store"))
    later = "checked after the dev signer's first start (an agent's first call, or tracekit up)"
    policy = cfg.get("policy") or service.DEFAULT_POLICY

    if prod:
        why = install._privileges(agent) if agent else ["no agent user is known (client.json names none)"]
        add("D-AGENT-PRIV", not why, f"{agent.pw_name} is unprivileged" if not why else "; ".join(why),
            "trace an unprivileged user: remove it from admin, docker and tracekit groups", bad=FAIL if agent else WARN)
    if agent:   # a findings run of the agent's own identity: its findings about its runs read self-asserted
        listed = f"uid:{agent.pw_uid}" in (cfg.get("analyzers") or ())
        add("D-ANALYZER-AGENT", not listed, f"{agent.pw_name} is in analyzers: it can sign findings about its own "
            "runs" if listed else f"{agent.pw_name} is not in analyzers",
            "remove the agent's uid from analyzers in signer.yaml; run tracekit analyze --v2 as an operator identity",
            bad=WARN)
    try:
        owner = os.stat(data).st_uid
    except OSError as e:
        owner, why = None, f"{data}: {e.strerror}"
    else:
        why = (f"{data} belongs to the agent's user, which can rewrite the log and read the keys"
               if agent and owner == agent.pw_uid else None)
    if prod:
        add("D-PROCESS-BOUNDARY", owner is not None and not why, why or f"{data} belongs to uid {owner}, not the agent",
            "run the signer as its own user: " + REINIT)
    else:
        add("D-PROCESS-BOUNDARY", False, install.DEV_MODE_LINE,
            "use system mode where the agent must not reach the signer: " + REINIT, bad=WARN)

    acl = "Windows controls access with ACLs, which doctor doesn't read: check that only the signer's user can read it"
    try:
        names = sorted(n for n in os.listdir(keys) if n.endswith(".key"))
        if os.name == "nt":
            raise _Windows
        bad = [f"{p} is not 0700" for p in (data, keys) if stat.S_IMODE(os.stat(p).st_mode) != 0o700]
        kowner = os.stat(keys).st_uid
        for n in names:
            st = os.lstat(os.path.join(keys, n))
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != kowner:
                bad.append(f"{n} is not a 0600 file of the signer's user")
        add("D-KEYS-MODE", not bad, "; ".join(bad) or f"{len(names)} keys, 0600 in a 0700 dir",
            f"chmod 700 {data} {keys}; chmod 600 {keys}/*.key; chown them to the signer's user")
    except _Windows:
        add("D-KEYS-MODE", False, f"{len(names)} keys in {keys}; modes not checked", acl, bad=WARN)
    except OSError as e:
        names = None
        missing = not prod and e.errno == errno.ENOENT   # a dev signer makes its keys as it starts
        fresh = missing and first   # one that never started: nothing to check yet, not a fault
        add("D-KEYS-MODE", False, f"{keys}: not made yet, {later}" if fresh else f"cannot inspect {keys}: {e.strerror}",
            "" if fresh else "start the dev signer: tracekit up" if missing else ROOT_DOCTOR,
            bad=INFO if fresh else WARN)

    try:
        content = service.content_config(cfg.get("content"))   # as the signer validates it
    except ValueError as e:
        add("D-CONTENT-VAULT", False, f"signer.yaml: {e}", "fix the content section of signer.yaml")
    else:
        if not content["retain"]:
            add("D-CONTENT-VAULT", *_vault_off(cfg, keys), bad=WARN)
        else:
            on = (f"on: keeps redacted content {content['retention_days']} days, up to {content['max_record_bytes']} "
                  "bytes a record")
            try:
                st = os.lstat(os.path.join(keys, "content.key"))
                if os.name == "nt":
                    raise _Windows
                bad = not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.stat(keys).st_uid
                add("D-CONTENT-VAULT", not bad, f"{on}; keys/content.key " + (
                    "is readable by others than the signer" if bad else "is a 0600 file of the signer's user"),
                    f"chmod 600 {keys}/content.key; chown it to the signer's user")
            except _Windows:
                add("D-CONTENT-VAULT", False, f"{on}; keys/content.key present, its mode not checked", acl, bad=WARN)
            except OSError as e:
                add("D-CONTENT-VAULT", False, f"{on}; keys/content.key: " + (f"not made yet, {later}" if first else
                    e.strerror), "" if first else "start the signer once (it makes the key), or run doctor as root",
                    bad=INFO if first else WARN)

    if names is not None and cfg.get("log_key"):
        add("D-KEYS-DISTINCT", True, "the log key is held in AWS KMS", "")
    elif names is not None:
        try:
            with open(os.path.join(keys, "log.key"), "rb") as f, open(os.path.join(keys, "record.key"), "rb") as g:
                same = f.read() == g.read()
            add("D-KEYS-DISTINCT", not same, "the log key and the record key are the same key" if same else
                "the log key and the record key differ", "a log keeps its log key, so start a new signer on a new "
                "data_dir (its keys are made distinct); export what you need from this one first")
        except OSError as e:
            add("D-KEYS-DISTINCT", False, f"the record key: not made yet, {later}" if first else
                f"no keys yet ({e.strerror})", "" if first else "start the signer once", bad=INFO if first else WARN)
    if (cfg.get("log_key") or {}).get("aws_kms"):
        out += kms_checks(cfg["log_key"]["aws_kms"], issuer_key)
    if (cfg.get("storage") or {}).get("postgres") is not None:
        out += pg_checks(cfg["storage"]["postgres"],
                         isinstance(cfg.get("content"), dict) and cfg["content"].get("retain") is True)

    try:
        with open(os.path.join(data, "hygiene.json"), encoding="utf-8") as f:
            h = json.load(f)
        bad = [why for why, ok in ((f"core dumps allowed (RLIMIT_CORE {h.get('core_limit')})", h.get("core_limit") == 0),
                                   ("the process is dumpable (Linux PR_SET_DUMPABLE)", h.get("dumpable") is not True),
                                   ("key buffers not mlocked (raise RLIMIT_MEMLOCK)", h.get("mlock") is not False))
               if not ok]
        add("D-KEY-HYGIENE", not bad, "; ".join(bad) or "no core dumps, not dumpable, keys mlocked where the OS allows",
            "start the signer with `tracekit signer serve` and a LimitMEMLOCK of at least 64K", bad=WARN)
    except (OSError, ValueError, AttributeError) as e:
        add("D-KEY-HYGIENE", False, f"the key hygiene report: not written yet, {later}" if first else
            f"no key hygiene report: {e}", "" if first else "start the signer once", bad=INFO if first else WARN)

    if prod and agent:
        targets = [[data, "read"], [data, "write"], [keys, "read"], [keys, "write"]]
        targets += [[os.path.join(keys, n), m] for n in names or () for m in ("read", "write")]
        targets += [[p, "write"] for p in (None if isinstance(config, dict) else config, policy, client_json) if p]
        hits = agent_access(agent, targets)
        if hits is None:
            add("D-AGENT-PROBE", False, f"not probed: doctor runs as neither root nor {agent.pw_name}",
                ROOT_DOCTOR, bad=WARN)
        else:
            add("D-AGENT-PROBE", not hits, f"{agent.pw_name} can " + ", ".join(f"{m} {p}" for p, m in hits) if hits
                else f"{agent.pw_name} can neither read the keys and store nor write the signer's files",
                "make these owned by root or the signer's user and not accessible to others (chmod o-rwx, go-w)")

    if prod and opt:
        python = os.path.join(opt, "bin", "python")
        bad = ((trusted_file(opt) or trusted_file(python) or install._first_problem(opt, install._root_only))
               if os.path.isdir(opt)
               else f"{opt} is missing")
        add("D-CODE-TRUST", not bad, bad or f"{opt} and every directory above it are root-owned and not writable by "
            "others", "re-run init to reinstall the venv: " + REINIT)

    if prod and unit:
        try:
            score, missing = _hardening(unit)
            add("D-UNIT-HARDENING", not missing, f"hardening {score}" + (f"; missing {', '.join(missing)}"
                if missing else f" ({unit})"), "re-run init to rewrite the service file: " + REINIT, bad=WARN)
        except OSError as e:
            add("D-UNIT-HARDENING", False, f"no service file: {unit}: {e.strerror}", REINIT, bad=WARN)
        if cfg.get("harness_binding"):
            out.append(helper_result(
                os.path.join(os.path.dirname(unit), (install.HELPER_LABEL + ".plist") if unit.endswith(".plist")
                             else install.V2_HELPER + ".service"), REINIT))   # collect() adds init's --harness

    managed = settings in install.MANAGED_SETTINGS.values()   # init --managed: Claude Code's admin-managed settings
    hook_fix = REINIT if prod else "tracekit init --dev --v2"   # collect() adds --managed, as to every re-init
    # Claude Code merges the drop-ins beside the managed file with it, in both modes: they are a settings layer
    dropins = _managed_dropins(settings if managed else _managed())
    if managed:   # the hooks are for the agent: whether other users' Claude Code reads the file doesn't count
        folder = _dropin_folder(settings)
        sources = list(dict.fromkeys([settings, folder, *dropins]))   # the folder whenever it exists, empty or not
        # the files are read; the folder has to be enterable too, or Claude Code can't open the drop-ins in it either
        probes = [(p, "open" if p == folder else "read") for p in sources]
        read = agent and agent_access(agent, probes)   # None: not probed (doctor isn't root)
        can = {p for p, how in (read or [])}
        unreadable = [p for p in sources if read is not None and p not in can]
        problem, note = _dropins(settings, unreadable)
        bad = trusted_file(settings) or (f"{agent.pw_name} can't read {settings}, so its Claude Code starts without "
                                         "it" if settings in unreadable else None) or problem
        add("D-HOOKS-MANAGED", not bad, bad or f"{settings} is root-owned and writable by root only"
            + (f", and {agent.pw_name} can read it" if read else "") + note, f"sudo chown 0:0 and sudo chmod 644 "
            f"{settings}, and sudo chmod go-w the directories above it; or {hook_fix}")
    layers = list(dict.fromkeys([*(sandbox_settings or [p for p in (
        os.path.join(agent.pw_dir, ".claude", "settings.json") if agent else install.user_settings(),
        settings, _managed()) if p]), *dropins]))
    plugin_settings, plugin_key = plugin or (None, install.PLUGIN)
    # Claude Code runs managed hooks only, and a drop-in can set that too: the later file's value wins
    only = managed and _setting_in_order(_admin_files(settings), "allowManagedHooksOnly")[1] is True
    why = _plugin_idle(plugin, prod, settings)   # and in system mode only managed settings count for the plugin
    active_plugin = plugin if plugin and not why else None
    note = _plugin_note(plugin_settings, why)
    from_plugin = f"hooks from the Tracekit Claude Code plugin, enabled in {plugin_settings}"
    others = "v2 hooks for " + ", ".join(f"{h} in {p}" for h, p in sorted((harnesses or {}).items()))
    chosen = ("no Claude Code hooks, as init --no-hooks chose: runs that SDK clients send (tracekit.instrument()) are "
              f"still recorded; to record Claude Code's calls too, run {hook_fix}")
    if not settings:
        add("D-HOOKS-PRESENT", bool(active_plugin or harnesses or no_hooks),
            from_plugin if active_plugin else (others if harnesses else chosen if no_hooks
                                               else "no hooks recorded in client.json") + note, REINIT, bad=WARN)
    else:
        try:
            hooks = _hooks(settings)
        except FileNotFoundError:   # no settings file, so no hooks in it
            hooks = {ev: [] for ev in install.TOOL_EVENTS}
        except (OSError, ValueError, AttributeError, TypeError) as e:   # the agent's own file: any shape or mode,
            hooks = None   # which init leaves as it is
            add("D-HOOKS-PRESENT", False, f"{settings}: {e}", f"make {settings} "
                f"{'readable' if isinstance(e, OSError) else 'a JSON object'} (move it aside, or fix it), then {hook_fix}",
                bad=sev)
        if hooks is not None and active_plugin:   # init's hooks too would decide every call twice
            both = any(hooks.values())
            add("D-HOOKS-PRESENT", not both, f"{from_plugin}, and init's v2 hooks in {settings}: every call is decided "
                "twice, and every approved call is blocked" if both else from_plugin, (
                    f"keep one: take {plugin_key} out of enabledPlugins in {plugin_settings}"
                    + ("" if managed else f", or {hook_fix}") if prod else
                    f"keep one: tracekit uninstall (init's hooks), or /plugin disable {plugin_key}"), bad=sev)
        elif hooks is not None and harnesses and not any(hooks.values()):   # another coding agent's, not Claude's
            add("D-HOOKS-PRESENT", True, others + note, "")
        elif hooks is not None and no_hooks and not any(hooks.values()):
            add("D-HOOKS-PRESENT", True, chosen + note, "")
        elif hooks is not None and not prod and not any(hooks.values()) and not shutil.which("claude") \
                and not os.path.isdir(os.path.dirname(install.user_settings())):   # no Claude Code here to hook
            add("D-HOOKS-PRESENT", False, "no Claude Code here (no claude on PATH, no "
                f"{os.path.dirname(install.user_settings())}), so no hooks: runs that SDK clients send "
                "(tracekit.instrument()) are still recorded", f"once Claude Code is installed: {hook_fix}", bad=INFO)
        elif hooks is not None:
            missing = [ev for ev, hs in hooks.items() if not hs]
            own = managed and agent and os.path.join(agent.pw_dir, ".claude", "settings.json")
            twice = not missing and own and install._v2_hooks_in(own)   # Claude Code runs both files' hooks
            unused = twice and only   # unless it runs managed ones only
            add("D-HOOKS-PRESENT", not (missing or twice) or unused,
                (f"no v2 hook for {', '.join(missing)} in {settings}" if missing
                 else f"v2 hooks in {settings}; those in {own} don't run (allowManagedHooksOnly)" if unused
                 else f"v2 hooks in {settings}, and in {own} too: Claude Code runs both, so every call is decided twice"
                 if twice else f"v2 hooks in {settings}")
                + _plugin_note(plugin_settings, why, kept=not missing), hook_fix, bad=WARN if twice else sev)
        if hooks is not None:
            cmds = [(ev, h.get("command") or "") for ev, hs in hooks.items() for h in hs]
            unnamed = sorted({ev for ev, c in cmds if not re.search(rf"\b{ev}\b", c)})
            blocking = sorted({ev for ev, c in cmds if ev != "PreToolUse" and FAIL_CLOSED in c})
            # what Claude Code skips: every hook (disableAllHooks, a true value in JavaScript; only managed settings can
            # turn managed hooks off), the tools a matcher other than "*", "" or none leaves out, and on POSIX a
            # PreToolUse hook that can't start and isn't wrapped to block the call
            # a drop-in is a managed source too, merged after managed-settings.json by name: for a single value the
            # later file wins, so the last file that sets disableAllHooks decides, and a later false lifts an earlier true
            managed_hooks = managed or (not any(hooks.values()) and plugin_settings in install.MANAGED_SETTINGS.values())
            order = [*(([plugin_settings] if not managed else [settings]) if managed_hooks
                       else [*layers, settings]),   # the hooks' own file too
                     *dropins]
            at, value = _setting_in_order(order, "disableAllHooks")
            off = [at] if at and value not in (False, 0, "") and (
                any(hooks.values()) or active_plugin or (why or "").startswith("disableAllHooks ")) else []
            narrowed = {ev: hs[0]["matcher"] for ev, hs in hooks.items()
                        if hs and all(h["matcher"] not in (None, "", "*") for h in hs)}
            unwrapped = os.name != "nt" and hooks["PreToolUse"] and not any(
                FAIL_CLOSED in (h.get("command") or "") for h in hooks["PreToolUse"])
            add("D-HOOKS-EVENT", not (off or narrowed or unnamed or blocking or unwrapped),
                f"disableAllHooks is set in {', '.join(off)}: Claude Code runs none of its hooks, so every call runs "
                "undecided and unrecorded" if off else f"the matcher of the "
                f"{', '.join(f'{ev} hook ({json.dumps(m)[:64]})' for ev, m in narrowed.items())} leaves tools out: "
                "Claude Code runs their calls undecided or unrecorded (\"*\" matches every tool)" if narrowed else
                f"the {', '.join(unnamed)} hook command(s) do not name "
                "their event (installed before 1.2): a PreToolUse payload the hook cannot read lets the call through "
                "unrecorded" if unnamed else f"the {', '.join(blocking)} hook command(s) block the event when the hook "
                "can't run (installed before 1.3, which did so for each prompt and Stop too)" if blocking else
                "the PreToolUse hook command isn't wrapped to block the call when the hook can't run: one that can't "
                "start exits 1, and Claude Code runs the call undecided and unrecorded" if unwrapped else
                "each hook command names its event", f'remove "disableAllHooks" from {", ".join(off)}' if off
                else hook_fix, bad=sev if off else WARN)
            if prod and opt and cmds:
                python = os.path.join(opt, "bin", "python")
                stray = [c for ev, c in cmds if c not in (install._hook_command(install.V2_HOOK, args=a, python=python,
                                                                                pre=ev == "PreToolUse")
                                                          for a in ((ev,), ()))]   # a pre-1.2 one is D-HOOKS-EVENT's
                add("D-HOOKS-VENV", not stray, f"{len(stray)} hooks are not the command init writes for {python} "
                    "(another Python, or init from before 1.3)" if stray else f"hooks run {python}", hook_fix)
            pre = [t if type(t) in (int, float) else 0 for t in (h.get("timeout", 60) for h in hooks["PreToolUse"])]
            if pre:
                add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S, f"PreToolUse timeout {min(pre)} s; " + _hook_run(),
                    f"set the PreToolUse hook timeout to {install.HOOK_TIMEOUT['PreToolUse']}")
            if any(hooks.values()) or active_plugin:   # without Claude Code's hooks none of its reasoning is recorded
                vault = isinstance(cfg.get("content"), dict) and cfg["content"].get("retain") is True
                value, where = None, None   # Claude Code's precedence: the last file that sets it wins
                for p in layers:
                    v = _setting(p, install.THINKING)
                    if v is not None:
                        value, where = v, p
                off = f"{where} sets {install.THINKING} to {json.dumps(value)[:64]}" if where else \
                    f"{install.THINKING} is set in none of its settings files"
                add("D-THINKING-SUMMARIES", value is True or not vault, f"Claude Code's thinking summaries are on "
                    f"({where})" if value is True else "the content vault is off: no reasoning is kept to check"
                    if not vault else f"the content vault keeps each transcript line, but Claude Code's thinking "
                    f"summaries are off ({off}): its thinking is kept sealed, so `tracekit analyze --v2` can't read "
                    f"the model's reasoning", (f'set "{install.THINKING}": true in {where}' if where else
                                               f'set "{install.THINKING}": true in {settings} ({hook_fix} does)')
                    + ", and for headless runs pass `claude -p --thinking-display summarized`", bad=WARN)
            if signer:
                env = _setting(settings, "env")   # none when uninstall deleted the file init made
                env = env.get("TRACEKIT_SIGNER") if isinstance(env, dict) else None
                add("D-SIGNER-ENV", env in (None, signer), f"TRACEKIT_SIGNER is {str(env)[:256]!r}, not {signer}" if env not in
                    (None, signer) else "TRACEKIT_SIGNER names the system socket or is unset",
                    f"remove env.TRACEKIT_SIGNER from {settings} (the hook refuses it and blocks every call)")

    sandbox = _sandbox(sandbox_settings)
    if sandbox.get("enabled") is True:
        why, fix = [], []
        if sandbox.get("failIfUnavailable") is not True:
            why.append("when the sandbox can't start, Claude Code runs commands unsandboxed (failIfUnavailable is "
                       "not true), and no hook sees that it didn't start")
            fix.append('set "failIfUnavailable": true under "sandbox"')
        ports = [k for k in ("httpProxyPort", "socksProxyPort") if sandbox["network"].get(k) is not None]
        if ports:
            why.append(f"{' and '.join(ports)} set: Claude Code's network allowlist stops applying to what its "
                       "commands send to that proxy")
            fix.append("remove the proxy ports unless your proxy enforces an allowlist")
        retry = ("off (allowUnsandboxedCommands is false)" if sandbox.get("allowUnsandboxedCommands") is False else
                 "on: the shipped coding pack's TK-A003 holds each one for a person")
        add("D-CLAUDE-SANDBOX", not why, "; ".join(why) or f"Claude Code's sandbox is on and fails closed; "
            f"unsandboxed retries {retry}",
            "; ".join(fix) + f" ({wiki_url('docs/integrations/claude-code-sandbox.md')})" if fix else "", bad=WARN)

    # lean: the settings files only, a later one winning each key of `tools` and `security`; doctor doesn't see
    # GEMINI_SANDBOX or -s at launch (they override tools.sandbox), IDE trust or Gemini's deeper merge of objects such
    # as tools.sandbox; upgrade if a setup relies on them
    if any(agent_hooks._version(json.dumps(h)) for h in _layers(gemini_settings, "hooks")):
        loads, trust, env = _folder_trust("gemini", agent and agent.pw_dir, gemini_project) if gemini_project else (
            True, None, None)
        skip, cure = (f"{env} in the environment makes Gemini skip the project's settings",
                      f"unset {env.split('=')[0]}") if env else (
            f"folder trust is on and {trust} doesn't trust its folder (IDE trust, which doctor can't see, decides first)",
            "trust the folder (/permissions)")
        def sandboxes(paths):   # (the whole CLI's sandbox, the tool sandbox) the files turn on
            tools, security = ({k: v for s in _layers(paths, key) for k, v in s.items()}
                               for key in ("tools", "security"))
            box = tools.get("sandbox")
            return (bool(box.get("enabled")) if isinstance(box, dict) else (
                isinstance(box, (int, float, str)) and box not in (False, "", "0", "false")),
                security.get("toolSandboxing") is True)
        whole, tool = sandboxes([p for p in gemini_settings if loads is not False or p != gemini_project])
        if not (whole or tool) and loads is False and any(sandboxes(gemini_settings)):
            add("D-GEMINI-SANDBOX", False, f"{gemini_project} turns Gemini's sandbox on, but Gemini doesn't load it: "
                + skip, f"to sandbox Gemini there, {cure} or set the sandbox in your user settings", bad=INFO)
        if whole or tool:
            add("D-GEMINI-SANDBOX", not whole, ("Gemini's tools.sandbox runs the whole CLI, Tracekit's hooks with it, in a "
                "sandbox: in a container the hooks don't run and nothing is recorded; under Seatbelt they can't keep "
                "their state and block every call" if whole else "Gemini's tool sandbox is on (security.toolSandboxing): "
                "the shipped coding pack's TK-A004 holds each command that asks it for more; GEMINI_SANDBOX or -s at "
                "launch, which doctor can't see, would run the whole CLI in a sandbox instead") + (
                "" if loads else f" ({gemini_project} left out: {skip})" if loads is False else
                f" ({trust} can't be read, so doctor can't tell whether Gemini trusts the folder of {gemini_project}, "
                "and reads it)"),
                'remove tools.sandbox and set "toolSandboxing": true under "security" '
                f"({wiki_url('docs/integrations/gemini-sandbox.md')})", bad=WARN)

    _harness_hook_checks(add, harnesses, prod, agent and agent.pw_dir)
    _reasoning_checks(add, harnesses, isinstance(cfg.get("content"), dict) and cfg["content"].get("retain") is True,
                      REINIT if prod else "tracekit init --dev --v2")
    _codex_sandbox(add, harnesses)
    # lean: dev only; system mode's hooks run the root-owned venv doctor runs from (D-HOOKS-VENV), but its running
    # signer isn't compared with it; read its hello too if /opt/tracekit gets upgraded in place under a running signer
    if not prod:
        _versions(add, settings, harnesses)

    if prod:
        bad = trusted_file(policy)
        add("D-POLICY-TRUST", not bad, bad or f"{policy} is root-owned", "make the policy and its directories "
            "root-owned and not group/world-writable, or set policy: in signer.yaml to such a file")
    try:
        # lean: loads the policy with this process's Python; check the signer venv's engine if they ever differ
        loaded = service.load_policy(policy)
        using_re2 = loaded.engine.startswith("re2@")
        wheel_expected = _google_re2_wheel_expected()
        detail = f"{policy} loads on {loaded.engine}"
        if not using_re2:
            detail += (
                " (regex fallback: large inputs can exhaust the 1 s budget "
                "and the call will be denied)"
                if wheel_expected else
                " (no google-re2 wheel is expected for this Python or platform)"
            )
        fix = (
            f"{sys.executable} -m pip install google-re2, then restart the signer "
            "(tracekit down in dev)"
            if wheel_expected and not using_re2 else ""
        )
        add("D-POLICY-ENGINE", using_re2, detail, fix,
            bad=WARN if wheel_expected else INFO)
    except ImportError as e:
        add("D-POLICY-ENGINE", False, f"no regex engine: {e}", "pip install tracekit-ai (a --no-deps install leaves the engine out)")
    except (OSError, ValueError) as e:
        add("D-POLICY-ENGINE", False, f"{policy} does not load: {e}", f"fix the policy: tracekit policy lint {policy}")

    mode = cfg.get("durability", ACK_ON_WRITE)
    add("D-DURABILITY", not prod or mode == ACK_ON_FSYNC, f"durability {mode}" + (
        ": a power loss can drop acknowledged records" if prod and mode != ACK_ON_FSYNC else ""),
        f"set durability: {ACK_ON_FSYNC} in signer.yaml", bad=WARN)
    open_ = sorted(k for k, v in (cfg.get("fail_modes") or {}).items() if v == "open")
    try:
        if client_json and read_json(client_json).get("fail_mode") == "open":
            open_.append(f"{client_json} fail_mode")
    except (OSError, ValueError):
        pass
    add("D-FAIL-MODES", not open_, f"fail-open: {', '.join(open_)}" if open_ else "every class fails closed",
        "set fail_modes to closed in signer.yaml (and fail_mode in client.json) unless an outage must not stop the agent",
        bad=WARN)
    if prod and client_json:
        _tailer_checks(add, client_json, agent)

    ws = cfg.get("witnesses") or []
    add("D-WITNESS-CONFIGURED", bool(ws), f"{len(ws)} witnesses" if ws else "no witnesses: checkpoints are not cosigned, "
        f"so assurance stays {'local' if cfg.get('anchors') else 'dev'}", f"add a witness under witnesses: in signer.yaml ({wiki_url('docs/witnesses.md')})"
        if prod else ("--no-witness turned the dev signer's witness off: tracekit init --dev --v2 --public-witness turns "
                      "it back on" if os.path.exists(os.path.join(data, service.NO_WITNESS)) else
                      "the dev signer uses the public witness, which isn't deployed yet: nothing to do until a release "
                      "names it; to anchor now, run a signer from a signer.yaml that lists your own witness "
                      f"({wiki_url('docs/witnesses.md')})"),
        bad=sev)
    if ws:
        operator = all(w["class"] == "operator" for w in ws)
        add("D-WITNESS-OWNERSHIP", not operator, "only operator witnesses: whoever runs the signer can also rewrite "
            "what they cosign" if operator else "a non-operator witness cosigns", "add a public, customer or tracekit "
            "witness", bad=sev)
    store = os.path.join(data, "store")
    try:
        note = read_text(os.path.join(store, "checkpoint.note"))
        noted = os.path.getmtime(os.path.join(store, "checkpoint.note"))
    except FileNotFoundError:
        note = None
    except OSError as e:
        note = None
        if ws:
            add("D-WITNESS-FRESH", False, f"cannot read {store}: {e.strerror}", "run doctor as root", bad=WARN)
    if ws and note:
        try:
            queue = read_json(os.path.join(store, "witness-queue.json"))
        except FileNotFoundError:
            queue = {}
        size, stale, behind = int(note.split("\n", 2)[1]), [], []
        for w in ws:
            name = TlogWitness(w["url"], w["vkey"]).name
            st = queue.get(name, {}).get(RECORDS)
            lag = size - (st or {}).get("size", 0)
            # failing since (`since`), or not asked yet (just started or added: since the latest note), for a while
            since = st.get("since") if st else noted
            said = f"{name} is {lag} record{'s' if lag != 1 else ''} behind"
            if lag > 0 and since and now - since >= service.WITNESS_GAP_S:
                stale.append(said)
            elif lag > 0:   # the signer sends each new checkpoint at once: a start or a busy log is a moment behind
                behind.append(f"{said}, as for a moment after each checkpoint (a problem only after "
                              f"{int(service.WITNESS_GAP_S)} s)")
        add("D-WITNESS-FRESH", not stale, "; ".join(stale or behind) or "every witness has cosigned the latest checkpoint",
            f"check the witness is reachable and accepts this log ({wiki_url('docs/witnesses.md')})", bad=WARN)
        try:
            cosigs = checkpoint.open_note(note, service.read_vkeys(data), [w["vkey"] for w in ws])[3]
        except (OSError, ValueError) as e:
            add("D-CLOCK-SKEW", False, f"cannot read the latest cosignatures: {e}", "start the signer once", bad=WARN)
        else:
            skew = max((ts for _, ts in cosigs), default=now) - now
            add("D-CLOCK-SKEW", skew <= MAX_SKEW_S, f"this clock is {int(skew)} s behind the latest cosignature" if
                skew > MAX_SKEW_S else "this clock is not behind the latest cosignature", "sync the clock (NTP)", bad=WARN)

    where = data   # a data dir the signer hasn't made yet will be on its nearest existing parent's file system
    while not os.path.exists(where) and os.path.dirname(where) != where:
        where = os.path.dirname(where)
    kind = fs_type(where) if os.path.exists(where) else "unknown"
    network = kind.split(".")[0] in NETWORK_FS
    if os.path.exists(data):
        detail = f"{data} is on {kind}"
    else:
        detail = f"{data} (not made yet) will be on {kind}"
    if network:
        detail += ": file locking and fsync can't be trusted there"
    add("D-DATA-FS", not network, detail, "put data_dir on a local disk")
    return out


def kms_checks(kms, issuer_key=None):
    """The KMS log key's spec and usage, and whether this host's AWS principal can also sign with `issuer_key`."""
    from .signer import logkey
    try:
        import boto3
        kms_client = boto3.client("kms", region_name=kms["region"])
        logkey.AwsKmsKey(kms["key_id"], kms["region"], kms_client)
    except ImportError:
        return [result("D-KMS-LOG-KEY", WARN, "not checked: no boto3", "pip install 'tracekit-ai[aws]'")]
    except ValueError as e:
        return [result("D-KMS-LOG-KEY", FAIL, str(e), f"create the log key as {logkey.KEY_SPEC} {logkey.KEY_USAGE}")]
    except Exception as e:   # botocore's errors: no credentials, access denied, network
        return [result("D-KMS-LOG-KEY", WARN, f"not checked: {type(e).__name__}: {str(e)[:256]}",
                       "run doctor with the signer's AWS credentials")]
    out = [result("D-KMS-LOG-KEY", OK, f"{kms['key_id']} is a {logkey.KEY_SPEC} {logkey.KEY_USAGE} key")]
    if issuer_key:
        try:
            alg = kms_client.get_public_key(KeyId=issuer_key)["SigningAlgorithms"][0]
        except Exception:   # no kms:GetPublicKey on it: try the log key's algorithm
            alg = logkey.ALGORITHM
        try:
            kms_client.sign(KeyId=issuer_key, Message=b"tracekit doctor", MessageType="RAW", SigningAlgorithm=alg,
                            DryRun=True)
            code = "DryRunOperationException"
        except Exception as e:
            code = (getattr(e, "response", None) or {}).get("Error", {}).get("Code") or type(e).__name__
        status = {"DryRunOperationException": FAIL, "AccessDeniedException": OK}.get(code, WARN)
        out.append(result("D-KMS-ISSUER-SIGN", status, {
            FAIL: f"this principal may call kms:Sign on the issuer key {issuer_key}",
            OK: f"this principal may not call kms:Sign on the issuer key {issuer_key}"}.get(status, f"not checked: {code}"),
            "remove kms:Sign on the issuer's key from the signer's IAM role: only the issuer signs with it"))
    return out


LOG_TABLES = ["tracekit_records", "tracekit_registry", "tracekit_notes", "tracekit_anchors"]
VAULT_TABLES = ["tracekit_content_keys", "tracekit_content"]
PG_WRITERS = """SELECT r.rolname, t FROM pg_roles r, unnest(%s::text[]) t
WHERE r.rolname <> current_user AND r.rolname !~ '^pg_' AND NOT r.rolsuper
  AND NOT pg_has_role(r.oid, (SELECT relowner FROM pg_class WHERE oid = t::regclass), 'USAGE')
  AND has_table_privilege(r.oid, t, 'INSERT, UPDATE, DELETE, TRUNCATE') ORDER BY 1, 2"""


def pg_checks(section, vault=False):
    """The signer's Postgres role, connected to as the signer, against the grants of postgres.GRANTS: no UPDATE, DELETE
    or TRUNCATE on the logs and not superuser; and no other role but the tables' owner may write the logs. With the
    content vault on (`vault`), it also holds every grant of GRANTS on the vault's tables."""
    try:
        import psycopg
        from .storage import postgres
    except ImportError:
        return [result("D-PG-SIGNER-ROLE", WARN, "not checked: no psycopg", "pip install 'tracekit-ai[postgres]'")]
    try:
        with psycopg.connect(postgres.read_dsn(section), autocommit=True, connect_timeout=10,
                             client_encoding="utf8") as c:   # names as str, even on a SQL_ASCII database
            role, superuser = c.execute("SELECT rolname, rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()
            bad = c.execute("SELECT t || ': ' || p FROM unnest(%s::text[]) t, unnest(array['UPDATE', 'DELETE', "
                            "'TRUNCATE']) p WHERE has_table_privilege(t, p) ORDER BY 1", (LOG_TABLES,)).fetchall()
            writers = c.execute(PG_WRITERS, (LOG_TABLES,)).fetchall()
            lacks = c.execute("SELECT t || ': ' || p, to_regclass(t) IS NULL FROM unnest(%s::text[]) t, unnest(array["
                              "'SELECT', 'INSERT', 'UPDATE', 'DELETE']) p WHERE CASE WHEN to_regclass(t) IS NULL THEN "
                              "true ELSE NOT has_table_privilege(t, p) END ORDER BY (t || ': ' || p) COLLATE \"C\"",
                              (VAULT_TABLES,)).fetchall() if vault else []
    except (OSError, psycopg.Error) as e:
        return [result("D-PG-SIGNER-ROLE", WARN, f"not checked: {str(e)[:256]}",
                       "run doctor where the signer's DSN reaches Postgres, after `tracekit signer migrate`")]
    bad = (["superuser"] if superuser else []) + [b for b, in bad]
    return [result("D-PG-SIGNER-ROLE", FAIL if bad else OK, f"{role} has " + ", ".join(bad) if bad else
                   f"{role} may only insert into and read the logs", f"grant {role} only postgres.GRANTS: REVOKE UPDATE, "
                   f"DELETE, TRUNCATE ON {', '.join(LOG_TABLES)} FROM {role}; ALTER ROLE {role} NOSUPERUSER"),
            result("D-PG-READER-ROLES", FAIL if writers else OK, "; ".join(f"{r} can write {t}" for r, t in writers)
                   or f"no role but {role} and the tables' owner can write the logs",
                   "readers get SELECT only: REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON the log tables FROM them")] + ([
            result("D-PG-VAULT-GRANTS", FAIL if lacks else OK,
                   "the content vault's tables are missing (schema version 1)" if any(m for _, m in lacks)
                   else f"{role} lacks " + ", ".join(t for t, _ in lacks) if lacks
                   else f"{role} may keep and erase the content vault's items",
                   ("run `tracekit signer migrate`, then " if any(m for _, m in lacks) else "")   # a v1 store
                   + postgres.VAULT_GRANTS.format(role=role))] if vault else [])


# Kubernetes: the signer image's user and paths (deploy/docker), and what hands a pod cloud credentials
# lean: the image's default socket dir and data_dir, not the signer.yaml the pod mounts; read it from the manifests'
# ConfigMap if deployments move them
SIGNER_UID, SOCKET_DIR, SIGNER_DATA = 10001, "/run/tracekit-signer", "/var/lib/tracekit-signer"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
WORKLOAD_IDENTITY = ("iam.gke.io/gcp-service-account", "eks.amazonaws.com/role-arn")
CLOUD_ENV = ("AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
             "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")   # what IRSA and EKS Pod Identity inject
TEMPLATES = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}
K8S_FIX = {
    "D-K8S-WORKLOADS": "point --manifests at the rendered manifests (helm template, kustomize build)",
    "D-K8S-HOST-ACCESS": "remove hostPath volumes and hostPID, hostIPC and hostNetwork from the pod",
    "D-K8S-SECURITY-CONTEXT": "set runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, "
                              "capabilities: {drop: [ALL]} and no privileged on each container",
    "D-K8S-RUN-AS-USER": f"run the agent container with its own runAsUser (not the signer's, {SIGNER_UID})",
    "D-K8S-SHARED-VOLUME": f"share only the socket directory ({SOCKET_DIR}) between the agent and the signer",
    "D-K8S-SIGNER-DATA": f"mount the signer's data volume ({SIGNER_DATA}) in the signer's container only",
    "D-K8S-SA-TOKEN": "set automountServiceAccountToken: false on the agent's pod",
    "D-K8S-WORKLOAD-IDENTITY": "give the agent's pod a service account without cloud identity; keep KMS credentials "
                               "with a central signer, outside the agent's pod",
}


def load_manifests(top):
    """(objects, problems) of the .yaml, .yml and .json files under `top`; a file that doesn't parse is a problem."""
    try:
        from yaml import YAMLError
    except ImportError:
        YAMLError = ValueError
    docs, bad = [], []
    for d, _, names in sorted(os.walk(top)):
        for n in sorted(names):
            if n.endswith((".yaml", ".yml", ".json")):
                try:
                    text = read_text(os.path.join(d, n))
                    for part in [text] if n.endswith(".json") else re.split(r"(?m)^---[ \t]*$", text):
                        docs.append(json.loads(part) if part.lstrip().startswith("{") else yamlmini.load_any(part))
                except (OSError, ValueError, YAMLError) as e:
                    bad.append(f"{os.path.join(d, n)}: {str(e)[:256]}")
    return docs, bad


def in_pod():
    """The k8s checks of the pod doctor runs in, read from the API server with the pod's service account token."""
    import socket
    import ssl
    import urllib.request
    try:
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        ns, token = (read_text(os.path.join(SA_DIR, n)).strip() for n in ("namespace", "token"))
        ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))

        def get(path):
            req = urllib.request.Request(f"https://{host}:{port}/api/v1/namespaces/{ns}/{path}",
                                         headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                return json.load(r)
        docs = [get(f"pods/{os.environ.get('HOSTNAME') or socket.gethostname()}")]
        docs.append(get(f"serviceaccounts/{docs[0]['spec'].get('serviceAccountName') or 'default'}"))
    except (KeyError, OSError, ValueError) as e:
        return [result("D-K8S-WORKLOADS", WARN, f"cannot read this pod from the API server: {type(e).__name__}: "
                       f"{str(e)[:256]}", "grant get on pods and serviceaccounts, or run doctor --k8s --manifests DIR")]
    return k8s_checks(docs)


def _pods(docs):
    """(name, namespace, pod spec) of every pod and pod template in `docs`."""
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind, spec, meta = d.get("kind"), d.get("spec") or {}, d.get("metadata") or {}
        if kind == "List":
            yield from _pods(d.get("items") or [])
            continue
        pod = (d if kind == "Pod" else spec.get("template") if kind in TEMPLATES else
               ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") if kind == "CronJob" else None)
        if pod:
            yield f"{kind}/{meta.get('name')}", meta.get("namespace") or "default", pod.get("spec") or {}


def _is_signer(c):
    cmd = [str(a) for a in (c.get("command") or []) + (c.get("args") or [])]
    return "tracekit-signer" in str(c.get("image")) or "signer" in cmd and "serve" in cmd


def _source(pod, v):
    """What a volume is, so two pods mounting the same claim, secret or host path compare equal."""
    for kind, key in (("persistentVolumeClaim", "claimName"), ("secret", "secretName"), ("configMap", "name"),
                      ("hostPath", "path")):
        if v.get(kind):
            return kind, v[kind].get(key)
    return pod, v.get("name")


def _ns(d):
    return (d.get("metadata") or {}).get("namespace") or "default"


def _uid(c, spec):
    return (c.get("securityContext") or {}).get("runAsUser", (spec.get("securityContext") or {}).get("runAsUser"))


def _volume_mounts(cs):
    return {m.get("name"): str(m.get("mountPath")) for c in cs for m in c.get("volumeMounts") or []}


def k8s_checks(docs, problems=()):
    """Checks of the pods in `docs` (manifests or API objects) that run a Tracekit signer or agent: an agent container
    is one with a TRACEKIT_* env var, or one that mounts the volume the signer mounts at its socket dir."""
    docs = [d for d in docs if isinstance(d, dict)]
    found = {k: [] for k in K8S_FIX}
    sas = {(_ns(d), (d.get("metadata") or {}).get("name")): d for d in docs if d.get("kind") == "ServiceAccount"}
    pia = {((d.get("spec") or {}).get("namespace") or "default", (d.get("spec") or {}).get("serviceAccount"))
           for d in docs if d.get("kind") == "PodIdentityAssociation"}
    pods, data, agent_mounts, token_cloud = [], set(), [], False
    for name, ns, spec in _pods(docs):
        # lean: regular init containers are skipped (they exit before the agent starts); native sidecars count
        cs = (spec.get("containers") or []) + [c for c in spec.get("initContainers") or []
                                               if c.get("restartPolicy") == "Always"]
        signers = [c for c in cs if _is_signer(c)]
        sig = _volume_mounts(signers)
        sock = {v for v, p in sig.items() if p.rstrip("/") == SOCKET_DIR}
        agents = [c for c in cs if not _is_signer(c) and (sock & set(_volume_mounts([c])) or any(
            str(e.get("name", "")).startswith("TRACEKIT_") for e in c.get("env") or []))]
        if not (signers or agents):
            continue
        pods.append(name)
        vols = {v.get("name"): _source(name, v) for v in spec.get("volumes") or []}
        uid = {id(c): _uid(c, spec) for c in cs}
        uid.update({id(c): SIGNER_UID for c in signers if uid[id(c)] is None})   # the image's USER
        host = [k for k in ("hostPID", "hostIPC", "hostNetwork") if spec.get(k)]
        host += [f"hostPath {s[1]}" for s in vols.values() if s[0] == "hostPath"]
        if host:
            found["D-K8S-HOST-ACCESS"].append(f"{name}: {', '.join(host)}")
        for c in signers + agents:
            sc = c.get("securityContext") or {}
            non_root = sc.get("runAsNonRoot", (spec.get("securityContext") or {}).get("runAsNonRoot"))
            weak = [why for why, ok in (
                ("may run as root", uid[id(c)] not in (None, 0) or non_root is True),
                ("privileged", sc.get("privileged") is not True),
                ("root fs writable", sc.get("readOnlyRootFilesystem") is True),
                ("privilege escalation allowed", sc.get("allowPrivilegeEscalation") is False),
                ("capabilities not dropped", "ALL" in ((sc.get("capabilities") or {}).get("drop") or []))) if not ok]
            if weak:
                found["D-K8S-SECURITY-CONTEXT"].append(f"{name} {c.get('name')}: {', '.join(weak)}")
        data |= {vols.get(v) for v, p in sig.items() if p.rstrip("/") == SIGNER_DATA or p.startswith(SIGNER_DATA + "/")}
        agent_mounts += [(name, c.get("name"), vols.get(v)) for c in agents for v in _volume_mounts([c])]
        if signers and agents:
            shared = sorted(set(sig) & set(_volume_mounts(agents)) - sock)
            if shared:
                found["D-K8S-SHARED-VOLUME"].append(f"{name}: {', '.join(shared)}")
            theirs = {uid[id(c)] for c in signers}
            found["D-K8S-RUN-AS-USER"] += [f"{name} {c.get('name')}: runAsUser " + (
                "not set" if uid[id(c)] is None else f"{uid[id(c)]}, the signer's") for c in agents
                if uid[id(c)] is None or uid[id(c)] in theirs]
        if agents:
            sa_name = spec.get("serviceAccountName") or "default"
            sa = sas.get((ns, sa_name)) or {}
            notes = (sa.get("metadata") or {}).get("annotations") or {}
            cloud = [f"{k} on {sa_name}" for k in WORKLOAD_IDENTITY if notes.get(k)]
            cloud += [f"an EKS Pod Identity association for {sa_name}"] if (ns, sa_name) in pia else []
            cloud += sorted({e.get("name") for c in cs for e in c.get("env") or [] if e.get("name") in CLOUD_ENV})
            if cloud:
                found["D-K8S-WORKLOAD-IDENTITY"].append(f"{name}: {', '.join(cloud)}")
            projected = {v.get("name") for v in spec.get("volumes") or []
                         if any("serviceAccountToken" in s for s in (v.get("projected") or {}).get("sources") or [])}
            if (spec.get("automountServiceAccountToken", sa.get("automountServiceAccountToken")) is not False
                    or projected & set(_volume_mounts(agents))):
                token_cloud |= bool(cloud)
                found["D-K8S-SA-TOKEN"].append(f"{name}: the agent gets {sa_name}'s token"
                                               + (", which has cloud identity" if cloud else ""))
    found["D-K8S-SIGNER-DATA"] = [f"{p} {c} mounts {s[1]}" for p, c, s in agent_mounts if s in data]
    found["D-K8S-WORKLOADS"] = list(problems) + ([] if pods else ["no pod runs a Tracekit signer or agent"])
    # a token without cloud identity reaches only what its RBAC grants: a warning
    soft = {"D-K8S-WORKLOADS"} | (set() if token_cloud else {"D-K8S-SA-TOKEN"})
    return [result(id, (WARN if id in soft else FAIL) if bad else OK, "; ".join(bad) or (
        f"{len(pods)} pods checked" if id == "D-K8S-WORKLOADS" else "none found"), K8S_FIX[id])
        for id, bad in found.items()]
