"""`tracekit doctor [--json] [--config signer.yaml]`: checks a Tracekit setup and says how to fix what it finds.

It detects the setup: v1 system mode (/etc/tracekit/client.json names a socket), v2 system mode (it names a signer),
the v2 dev signer (no system config), or the signer.yaml given with --config. Every check has a stable id and gives
ok, warn or fail; docs/doctor.md lists them. Exit 0 when all are ok, 1 when any fails, 2 when there are only warnings.
Run it as root for system mode: it then probes the files as the agent's user, in a forked child that dropped to it.
`--k8s` checks the pod it runs in, or the manifests under `--manifests DIR`, instead.

Doctor output is advice, not evidence: it reads the host as it is now, and nothing it prints is signed or verified.
"""
import errno
import json
import os
import re
import stat
import subprocess
import sys
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

OK, WARN, FAIL = "ok", "warn", "fail"
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb", "smb3", "smbfs", "afpfs", "webdav", "fuse", "fuseblk", "9p", "macfuse",
              "osxfuse"}
MAX_SKEW_S = 300
# system mode's init from a root-owned clone of the release, as the plugin and CI run it: it works on every Python,
# whether or not /opt/tracekit exists or can be trusted (docs/deploy.md also gives the routes through /opt's venv)
REINIT = ("from a root-owned clone of the release (docs/deploy.md#laptop-system-mode), sudo /usr/bin/python3 -m tracekit "
          "init --v2 --user <agent-user>" + (" --experimental-macos" if sys.platform == "darwin" else ""))
ROOT_DOCTOR = "run doctor as root (system mode: sudo /opt/tracekit/bin/python -I -m tracekit doctor)"
FAIL_CLOSED = "call blocked (fail-closed)"   # the pre-tool wrapper's words (install._blocking); before 1.3 every event's
# wrapper had them, so a hook that couldn't run blocked a prompt or a tool result too (D-HOOKS-EVENT warns)



class _Windows(Exception):
    """POSIX file modes mean nothing on Windows (ACLs): a check that reads them reports so instead."""


def result(id, status, detail, fix=""):
    return {"id": id, "status": status, "detail": detail, "fix": fix if status != OK else ""}


def report(results, as_json=False):
    """Print the results; returns the exit code (0 all ok, 1 any fail, 2 only warnings)."""
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{'ok' if r['status'] == OK else r['status'].upper():<6}{r['detail']}  ({r['id']})"
                  + (f"\n      fix: {r['fix']}" if r["fix"] else ""))
    statuses = {r["status"] for r in results}
    return 1 if FAIL in statuses else 2 if WARN in statuses else 0


def main(config=None, as_json=False, k8s=False, manifests=None, issuer_key=None):
    if not (k8s or manifests):
        return report(collect(config, issuer_key), as_json)
    out = k8s_checks(*load_manifests(manifests)) if manifests else in_pod()
    return report(out + (v2_checks(config, issuer_key=issuer_key) if config else []), as_json)


def collect(config=None, issuer_key=None):
    """The checks that apply to the setup on this host (or to signer.yaml `config`)."""
    try:
        sc = client.system_config()
    except client.SystemConfigError as e:
        return [result("D-SYSTEM-CONFIG", FAIL, str(e), REINIT)]
    out = install.v1_results() if sc and "socket" in sc and not config else []
    if config or (sc and sc.get("signer")):
        h = (sc or {}).get("hooks") or {}
        unit = (os.path.join(install.LAUNCHD_DIR, install.V2_LABEL + ".plist") if sys.platform == "darwin"
                else os.path.join(install.SYSTEMD_DIR, install.V2_UNIT + ".service"))
        agent_name = h.get("agent", "claude")
        settings = h.get("settings") if agent_name == "claude" else None
        agent = _user(h.get("user"))
        home = agent and os.path.join(agent.pw_dir, ".claude", "settings.json")
        plugin = agent and install.plugin_enabled([home])
        # lean: another coding agent's hook config gets D-HOOKS-EVENT, D-HOOKS-TIMEOUT and the reasoning checks only;
        # D-HOOKS-PRESENT names it without reading its events, and D-HOOKS-VENV and D-SIGNER-ENV are Claude Code's;
        # until doctor reads them per format
        return out + v2_checks(config or install.V2_CONFIG, agent=agent, settings=settings,
                               signer=(sc or {}).get("signer"), opt=install.OPT, unit=unit,
                               client_json=client.SYSTEM_CONFIG if sc else None, issuer_key=issuer_key, plugin=plugin,
                               sandbox_settings=[p for p in (home, settings, _managed()) if p],
                               gemini_settings=_gemini(agent and agent.pw_dir,
                                                        h.get("settings") if h.get("agent") == "gemini" else None),
                               harnesses={agent_name: h["settings"]} if agent_name != "claude" and h.get("settings")
                               else None)
    if sc:
        return out
    from .signer.service import dev_content, dev_data_dir
    project = os.path.join(os.getcwd(), ".claude")
    return v2_checks({"data_dir": dev_data_dir(), "content": dev_content().get("content")}, "dev",
                     settings=_dev_settings(), plugin=install.plugin_enabled(), harnesses=_dev_harnesses(),
                     sandbox_settings=[install.user_settings(), os.path.join(project, "settings.json"),
                                       os.path.join(project, "settings.local.json"), _managed()],
                     gemini_settings=_gemini(os.path.expanduser("~"),
                                             os.path.join(os.getcwd(), ".gemini", "settings.json")))


def _managed():
    return install.MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]


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


def _gemini(home, project):
    """Gemini CLI's settings files, lowest rank first: system defaults, the user's, the project's, system settings
    (the system ones where Gemini CLI looks for them, its two environment variables included)."""
    d = {"darwin": "/Library/Application Support/GeminiCli", "win32": r"C:\ProgramData\gemini-cli"}.get(
        sys.platform, "/etc/gemini-cli")
    system = os.environ.get("GEMINI_CLI_SYSTEM_SETTINGS_PATH") or os.path.join(d, "settings.json")
    defaults = os.environ.get("GEMINI_CLI_SYSTEM_DEFAULTS_PATH") or os.path.join(os.path.dirname(system),
                                                                                  "system-defaults.json")
    return [p for p in (defaults, home and os.path.join(home, ".gemini", "settings.json"), project, system) if p]


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
    """{event: [hook groups]} of a coding agent's hook config: Droid's file is the event map, agy's names each hook's
    (Tracekit's is agent_hooks.AGY_HOOK), the others' is under `hooks`."""
    from . import agent_hooks
    if harness == "droid":
        return {ev: config[ev] for ev in agent_hooks.DROID_EVENTS if ev in config}
    if harness == "antigravity":   # its "enabled" is D-AGY-HOOKS-RUN's
        named = config.get(agent_hooks.AGY_HOOK) or {}
        return {ev: named[ev] for ev in agent_hooks.AGY_EVENTS if ev in named}
    return config.get("hooks") or {}


def _dev_harnesses():
    """{harness: its hook config} for each coding agent (agent_hooks) with a v2 hook in its user or project config."""
    from . import agent_hooks
    out = {}
    for harness in agent_hooks.HARNESSES:
        for path in (agent_hooks.config_path(harness), agent_hooks.config_path(harness, os.getcwd())):
            if harness == "opencode":   # a JavaScript plugin, not a JSON hook config
                try:
                    if agent_hooks._version(install.agent_file(path).decode("utf-8", "replace")) == "v2":
                        out.setdefault(harness, path)
                except OSError:
                    pass
                continue
            try:
                hooks = _harness_hooks(harness, _json(path) or {})
                cmds = [h.get("command") for lst in hooks.values() for g in lst
                        for h in (g.get("hooks") or () if "hooks" in g else [g]) if isinstance(h, dict)]
            except (OSError, ValueError, AttributeError, TypeError):   # missing, or not a hook config: not this one
                continue
            if any(agent_hooks._version(c) == "v2" for c in cmds):
                out.setdefault(harness, path)
    return out


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


def _harness_hook_checks(add, harnesses, prod, home=None):
    """Event arguments and approval timeouts of the other coding agents' v2 command hooks (home: the agent user's home
    directory, where agy's sign-in settings are)."""
    from . import agent_hooks
    from .integrations.claude_code import APPROVAL_WAIT_S
    for harness, path in sorted((harnesses or {}).items()):
        if harness not in ("codex", "cursor", "gemini", "goose", "qwen", "droid", "antigravity"):
            continue
        fix = REINIT + f" --agent {harness}" if prod else f"tracekit init --dev --v2 --agent {harness}"
        if harness == "antigravity":
            _agy_runs(add, path, home or os.path.expanduser("~"), fix)
        try:
            hooks = _harness_hooks(harness, _json(path) or {})
            cmds = [(ev, h) for ev, groups in hooks.items() for g in groups
                    for h in (g.get("hooks") or () if "hooks" in g else [g])
                    if isinstance(h, dict) and agent_hooks._version(h.get("command")) == "v2"]
        except (OSError, ValueError, AttributeError, TypeError) as e:
            add("D-HOOKS-EVENT", False, f"cannot check {harness} hooks in {path}: {e}", fix, bad=WARN)
            continue
        unnamed = sorted({ev for ev, h in cmds if not re.search(rf"\b{re.escape(ev)}\b", h["command"])})
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
        scale, unit = (1000, "ms") if harness in ("gemini", "qwen") else (1, "s")
        default = 30 if harness == "antigravity" else 60   # a timeout the hook doesn't set: agy's own default is 30 s
        pre = [h.get("timeout", default * scale) for h in pre]
        pre = [t if type(t) in (int, float) and 0 <= t < float("inf") else 0 for t in pre]
        if pre:
            add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S * scale,
                f"{harness} pre-tool timeout {min(pre)} {unit} in {path}, approval wait {APPROVAL_WAIT_S * scale} {unit}",
                fix, bad=WARN)


def _json(path):
    """A settings file the agent's user controls, parsed (install.agent_file: a FIFO or a device can't hang or flood
    doctor)."""
    return json.loads(install.agent_file(path))


def _setting(path, key):
    """A Claude Code settings file's `key`, or None when the file or the key is missing or unreadable."""
    try:
        s = _json(path)
    except (OSError, ValueError):
        return None
    return s.get(key) if isinstance(s, dict) else None


def _user(name):
    try:
        return pwd.getpwnam(name) if name and pwd else None
    except KeyError:
        return None


def _access(targets):
    return [[p, m] for p, m in targets if os.access(p, os.R_OK if m == "read" else os.W_OK)]


def agent_access(pw, targets):
    """The (path, "read"|"write") targets the agent's user can access, probed as that user without changing anything;
    None when this process can't act as it (not root, not the agent)."""
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


def v2_checks(config, profile="production", agent=None, settings=None, signer=None, opt=None, unit=None,
              client_json=None, now=None, issuer_key=None, plugin=None, sandbox_settings=(), gemini_settings=(),
              harnesses=None):
    """Checks of a v2 signer. config: a signer.yaml path, or the dev signer's config dict. profile "dev" turns what
    a dev setup can't have into warnings. agent: the agent's pwd entry; settings: its Claude Code settings; signer: the
    socket client.json names; opt: the root-owned venv; unit: the service file; client_json: the system client config;
    issuer_key: the KMS key of the record key issuer, which this host's AWS principal must not sign with; plugin: the
    (settings file, plugin key) returned by install.plugin_enabled, whose hooks are init's;
    sandbox_settings: the Claude Code settings files that set its sandbox, lowest rank first (_sandbox);
    gemini_settings: Gemini CLI's settings files, lowest rank first (_gemini); harnesses: {coding agent: its hook
    config} of the other agents with v2 hooks (agent_hooks), whose hooks and reasoning settings are checked."""
    from . import agent_hooks
    from .format import checkpoint
    from .integrations.claude_code import APPROVAL_WAIT_S
    from .signer import service
    from .storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, RECORDS
    from .tlog_witness import TlogWitness
    prod, out, now = profile != "dev", [], time.time() if now is None else now
    sev = FAIL if prod else WARN

    def add(id, ok, detail, fix, bad=FAIL):
        out.append(result(id, OK if ok else bad, detail, fix))

    if isinstance(config, dict):
        cfg = config
    else:
        try:
            cfg = service.load_config(config)
        except (OSError, ValueError) as e:
            return [result("D-CONFIG", FAIL, f"signer.yaml does not load: {e}", "fix signer.yaml, or " + REINIT)]
        bad = trusted_file(os.path.abspath(config))
        add("D-CONFIG", not bad, bad or f"{config} is root-owned and loads",
            "make it and its directories root-owned and not group/world-writable (sudo chown root:root; chmod go-w)")
    data = cfg["data_dir"]
    keys = os.path.join(data, "keys")
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
        add("D-PROCESS-BOUNDARY", False, "dev signer: it runs as your user, so the agent could rewrite its log "
            "(dev assurance)", "use system mode where the agent must not reach the signer: " + REINIT, bad=WARN)

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
        fresh = not prod and e.errno == errno.ENOENT   # a dev signer that never started has no keys yet
        add("D-KEYS-MODE", False, f"cannot inspect {keys}: {e.strerror}",
            "start the dev signer: tracekit up" if fresh else ROOT_DOCTOR, bad=WARN)

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
                add("D-CONTENT-VAULT", False, f"{on}; keys/content.key: {e.strerror}", "start the signer once (it makes "
                    "the key), or run doctor as root", bad=WARN)

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
            add("D-KEYS-DISTINCT", False, f"no keys yet ({e.strerror})", "start the signer once", bad=WARN)
    if (cfg.get("log_key") or {}).get("aws_kms"):
        out += kms_checks(cfg["log_key"]["aws_kms"], issuer_key)
    if (cfg.get("storage") or {}).get("postgres") is not None:
        out += pg_checks(cfg["storage"]["postgres"])

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
        add("D-KEY-HYGIENE", False, f"no key hygiene report: {e}", "start the signer once", bad=WARN)

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
                             else install.V2_HELPER + ".service"), REINIT + " --harness [NAME=]PATH"))

    hook_fix = REINIT if prod else "tracekit init --dev --v2"
    plugin_settings, plugin_key = plugin or (None, install.PLUGIN)
    from_plugin = f"hooks from the Tracekit Claude Code plugin, enabled in {plugin_settings}"
    others = "v2 hooks for " + ", ".join(f"{h} in {p}" for h, p in sorted((harnesses or {}).items()))
    if not settings:
        add("D-HOOKS-PRESENT", bool(plugin or harnesses), from_plugin if plugin else others if harnesses else
            "no hooks recorded in client.json", REINIT, bad=WARN)
    else:
        try:
            hooks = _hooks(settings)
        except FileNotFoundError:   # no settings file, so no hooks in it
            hooks = {ev: [] for ev in install.TOOL_EVENTS}
        except (OSError, ValueError, AttributeError, TypeError) as e:   # the agent's own file: any shape
            hooks = None
            add("D-HOOKS-PRESENT", False, f"{settings}: {e}", hook_fix, bad=sev)
        if hooks is not None and plugin:   # init's hooks too would decide every call twice
            both = any(hooks.values())
            add("D-HOOKS-PRESENT", not both, f"{from_plugin}, and init's v2 hooks in {settings}: every call is decided "
                "twice, and every approved call is blocked" if both else from_plugin,
                f"keep one: tracekit uninstall (init's hooks), or /plugin disable {plugin_key}", bad=sev)
        elif hooks is not None and harnesses and not any(hooks.values()):   # another coding agent's, not Claude's
            add("D-HOOKS-PRESENT", True, others, "")
        elif hooks is not None:
            missing = [ev for ev, hs in hooks.items() if not hs]
            add("D-HOOKS-PRESENT", not missing, f"no v2 hook for {', '.join(missing)} in {settings}" if missing else
                f"v2 hooks in {settings}", hook_fix, bad=sev)
        if hooks is not None:
            layers = sandbox_settings or dict.fromkeys((os.path.join(agent.pw_dir, ".claude", "settings.json") if agent
                                                        else install.user_settings(), settings))
            cmds = [(ev, h.get("command") or "") for ev, hs in hooks.items() for h in hs]
            unnamed = sorted({ev for ev, c in cmds if not re.search(rf"\b{ev}\b", c)})
            blocking = sorted({ev for ev, c in cmds if ev != "PreToolUse" and FAIL_CLOSED in c})
            # what Claude Code skips: every hook (disableAllHooks, a true value in JavaScript), the tools a matcher
            # other than "*", "" or none leaves out, and on POSIX a PreToolUse hook that can't start and isn't wrapped
            # to block the call
            off = [p for p in dict.fromkeys([*layers, settings])   # the hooks' own file too (init's record of it)
                   if _setting(p, "disableAllHooks") not in (None, False, 0, "")] \
                if any(hooks.values()) or plugin else []
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
                    "(another Python, or init from before 1.3)" if stray else f"hooks run {python}", REINIT)
            pre = [t if type(t) in (int, float) else 0 for t in (h.get("timeout", 60) for h in hooks["PreToolUse"])]
            if pre:
                add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S, f"PreToolUse timeout {min(pre)} s, approval wait "
                    f"{APPROVAL_WAIT_S} s", f"set the PreToolUse hook timeout to {install.HOOK_TIMEOUT['PreToolUse']}")
            if any(hooks.values()) or plugin:   # without Claude Code's hooks none of its reasoning is recorded
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
                env = (_json(settings) or {}).get("env")
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
    # GEMINI_SANDBOX or -s at launch (they override tools.sandbox), folder trust (Gemini skips an untrusted project's
    # settings) or Gemini's deeper merge of objects such as tools.sandbox; upgrade if a setup relies on them
    if any(agent_hooks._version(json.dumps(h)) for h in _layers(gemini_settings, "hooks")):
        tools, security = ({k: v for s in _layers(gemini_settings, key) for k, v in s.items()}
                           for key in ("tools", "security"))
        box = tools.get("sandbox")
        whole = bool(box.get("enabled")) if isinstance(box, dict) else (
            isinstance(box, (int, float, str)) and box not in (False, "", "0", "false"))
        if whole or security.get("toolSandboxing") is True:
            add("D-GEMINI-SANDBOX", not whole, "Gemini's tools.sandbox runs the whole CLI, Tracekit's hooks with it, in a "
                "sandbox: in a container the hooks don't run and nothing is recorded; under Seatbelt they can't keep "
                "their state and block every call" if whole else "Gemini's tool sandbox is on (security.toolSandboxing): "
                "the shipped coding pack's TK-A004 holds each command that asks it for more; GEMINI_SANDBOX or -s at "
                "launch, which doctor can't see, would run the whole CLI in a sandbox instead",
                'remove tools.sandbox and set "toolSandboxing": true under "security" '
                f"({wiki_url('docs/integrations/gemini-sandbox.md')})", bad=WARN)

    _harness_hook_checks(add, harnesses, prod, agent and agent.pw_dir)
    _reasoning_checks(add, harnesses, isinstance(cfg.get("content"), dict) and cfg["content"].get("retain") is True,
                      REINIT if prod else "tracekit init --dev --v2")

    if prod:
        bad = trusted_file(policy)
        add("D-POLICY-TRUST", not bad, bad or f"{policy} is root-owned", "make the policy and its directories "
            "root-owned and not group/world-writable, or set policy: in signer.yaml to such a file")
    try:
        # lean: loads the policy with this process's Python; check the signer venv's engine if they ever differ
        add("D-POLICY-ENGINE", True, f"{policy} loads on {service.load_policy(policy).engine}", "")
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

    ws = cfg.get("witnesses") or []
    add("D-WITNESS-CONFIGURED", bool(ws), f"{len(ws)} witnesses" if ws else "no witnesses: checkpoints are not cosigned, "
        f"so assurance stays {'local' if cfg.get('anchors') else 'dev'}", f"add a witness under witnesses: in signer.yaml ({wiki_url('docs/witnesses.md')})"
        if prod else f"the dev signer takes no witnesses: serve one from a signer.yaml with witnesses: ({wiki_url('docs/witnesses.md')})",
        bad=sev)
    if ws:
        operator = all(w["class"] == "operator" for w in ws)
        add("D-WITNESS-OWNERSHIP", not operator, "only operator witnesses: whoever runs the signer can also rewrite "
            "what they cosign" if operator else "a non-operator witness cosigns", "add a public, customer or tracekit "
            "witness", bad=sev)
    store = os.path.join(data, "store")
    try:
        note = read_text(os.path.join(store, "checkpoint.note"))
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
        size, stale = int(note.split("\n", 2)[1]), []
        for w in ws:
            name = TlogWitness(w["url"], w["vkey"]).name
            st = queue.get(name, {}).get(RECORDS)
            lag = size - (st or {}).get("size", 0)
            if lag > 0 and (st is None or (st.get("since") and now - st["since"] >= service.WITNESS_GAP_S)):
                stale.append(f"{name} is {lag} records behind")
        add("D-WITNESS-FRESH", not stale, "; ".join(stale) or "every witness has cosigned the latest checkpoint",
            f"check the witness is reachable and accepts this log ({wiki_url('docs/witnesses.md')})", bad=WARN)
        try:
            cosigs = checkpoint.open_note(note, service.read_vkeys(data), [w["vkey"] for w in ws])[3]
        except (OSError, ValueError) as e:
            add("D-CLOCK-SKEW", False, f"cannot read the latest cosignatures: {e}", "start the signer once", bad=WARN)
        else:
            skew = max((ts for _, ts in cosigs), default=now) - now
            add("D-CLOCK-SKEW", skew <= MAX_SKEW_S, f"this clock is {int(skew)} s behind the latest cosignature" if
                skew > MAX_SKEW_S else "this clock is not behind the latest cosignature", "sync the clock (NTP)", bad=WARN)

    kind = fs_type(data) if os.path.exists(data) else "unknown"
    add("D-DATA-FS", kind.split(".")[0] not in NETWORK_FS, f"{data} is on {kind}" + (
        ": file locking and fsync can't be trusted there" if kind.split(".")[0] in NETWORK_FS else ""),
        "put data_dir on a local disk")
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
PG_WRITERS = """SELECT r.rolname, t FROM pg_roles r, unnest(%s::text[]) t
WHERE r.rolname <> current_user AND r.rolname !~ '^pg_' AND NOT r.rolsuper
  AND NOT pg_has_role(r.oid, (SELECT relowner FROM pg_class WHERE oid = t::regclass), 'USAGE')
  AND has_table_privilege(r.oid, t, 'INSERT, UPDATE, DELETE, TRUNCATE') ORDER BY 1, 2"""


def pg_checks(section):
    """The signer's Postgres role, connected to as the signer, against the grants of postgres.GRANTS: no UPDATE, DELETE
    or TRUNCATE on the logs and not superuser; and no other role but the tables' owner may write the logs."""
    try:
        import psycopg
        from .storage import postgres
    except ImportError:
        return [result("D-PG-SIGNER-ROLE", WARN, "not checked: no psycopg", "pip install 'tracekit-ai[postgres]'")]
    try:
        with psycopg.connect(postgres.read_dsn(section), autocommit=True, connect_timeout=10) as c:
            role, superuser = c.execute("SELECT rolname, rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()
            bad = c.execute("SELECT t || ': ' || p FROM unnest(%s::text[]) t, unnest(array['UPDATE', 'DELETE', "
                            "'TRUNCATE']) p WHERE has_table_privilege(t, p) ORDER BY 1", (LOG_TABLES,)).fetchall()
            writers = c.execute(PG_WRITERS, (LOG_TABLES,)).fetchall()
    except (OSError, psycopg.Error) as e:
        return [result("D-PG-SIGNER-ROLE", WARN, f"not checked: {str(e)[:256]}",
                       "run doctor where the signer's DSN reaches Postgres, after `tracekit signer migrate`")]
    bad = (["superuser"] if superuser else []) + [b for b, in bad]
    return [result("D-PG-SIGNER-ROLE", FAIL if bad else OK, f"{role} has " + ", ".join(bad) if bad else
                   f"{role} may only insert into and read the logs", f"grant {role} only postgres.GRANTS: REVOKE UPDATE, "
                   f"DELETE, TRUNCATE ON {', '.join(LOG_TABLES)} FROM {role}; ALTER ROLE {role} NOSUPERUSER"),
            result("D-PG-READER-ROLES", FAIL if writers else OK, "; ".join(f"{r} can write {t}" for r, t in writers)
                   or f"no role but {role} and the tables' owner can write the logs",
                   "readers get SELECT only: REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON the log tables FROM them")]


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
