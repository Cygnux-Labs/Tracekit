"""`tracekit doctor [--json] [--config signer.yaml]`: checks a Tracekit setup and says how to fix what it finds.

It detects the setup: v1 system mode (/etc/tracekit/client.json names a socket), v2 system mode (it names a signer),
the v2 dev signer (no system config), or the signer.yaml given with --config. Every check has a stable id and gives
ok, warn or fail; docs/doctor.md lists them. Exit 0 when all are ok, 1 when any fails, 2 when there are only warnings.
Run it as root for system mode: it then probes the files as the agent's user, in a forked child that dropped to it.

Doctor output is advice, not evidence: it reads the host as it is now, and nothing it prints is signed or verified.
"""
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

from . import client, install
from .core import read_json, read_text
from .daemon import trusted_file
from .deploy import files

OK, WARN, FAIL = "ok", "warn", "fail"
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb", "smb3", "smbfs", "afpfs", "webdav", "fuse", "fuseblk", "9p"}
MAX_SKEW_S = 300
REINIT = "sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user>"


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


def main(config=None, as_json=False):
    return report(collect(config), as_json)


def collect(config=None):
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
        return out + v2_checks(config or install.V2_CONFIG, agent=_user(h.get("user")), settings=h.get("settings"),
                               signer=(sc or {}).get("signer"), opt=install.OPT, unit=unit,
                               client_json=client.SYSTEM_CONFIG if sc else None)
    if sc:
        return out
    from .signer.service import dev_data_dir
    return v2_checks({"data_dir": dev_data_dir()}, "dev", settings=os.path.expanduser(os.path.join("~", ".claude", "settings.json")))


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
    return f"{len(want) + 1 - len(missing)}/{len(want) + 1}", missing


def _hooks(settings):
    """{tool event: [v2 hook entries]} of a Claude Code settings file."""
    hooks = (read_json(settings) or {}).get("hooks") or {}
    return {ev: [h for g in hooks.get(ev) or () if isinstance(g, dict) and install._hook_version(g) == "v2"
                 for h in g.get("hooks", ())] for ev in install.TOOL_EVENTS}


def v2_checks(config, profile="production", agent=None, settings=None, signer=None, opt=None, unit=None,
              client_json=None, now=None):
    """Checks of a v2 signer. config: a signer.yaml path, or the dev signer's config dict. profile "dev" turns what
    a dev setup can't have into warnings. agent: the agent's pwd entry; settings: its Claude Code settings; signer: the
    socket client.json names; opt: the root-owned venv; unit: the service file; client_json: the system client config."""
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

    try:
        names = sorted(n for n in os.listdir(keys) if n.endswith(".key"))
        bad = [f"{p} is not 0700" for p in (data, keys) if stat.S_IMODE(os.stat(p).st_mode) != 0o700]
        kowner = os.stat(keys).st_uid
        for n in names:
            st = os.lstat(os.path.join(keys, n))
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != kowner:
                bad.append(f"{n} is not a 0600 file of the signer's user")
        add("D-KEYS-MODE", not bad, "; ".join(bad) or f"{len(names)} keys, 0600 in a 0700 dir",
            f"chmod 700 {data} {keys}; chmod 600 {keys}/*.key; chown them to the signer's user")
    except OSError as e:
        names = None
        add("D-KEYS-MODE", False, f"cannot inspect {keys}: {e.strerror}", "run doctor as root (sudo tracekit doctor)",
            bad=WARN)

    if names is not None:
        try:
            with open(os.path.join(keys, "log.key"), "rb") as f, open(os.path.join(keys, "record.key"), "rb") as g:
                same = f.read() == g.read()
            add("D-KEYS-DISTINCT", not same, "the log key and the record key are the same key" if same else
                "the log key and the record key differ", "move both keys away and restart the signer to make new ones "
                "(new keys start a new log: export what you need first)")
        except OSError as e:
            add("D-KEYS-DISTINCT", False, f"no keys yet ({e.strerror})", "start the signer once", bad=WARN)

    if prod and agent:
        targets = [[data, "read"], [data, "write"], [keys, "read"], [keys, "write"]]
        targets += [[os.path.join(keys, n), m] for n in names or () for m in ("read", "write")]
        targets += [[p, "write"] for p in (None if isinstance(config, dict) else config, policy, client_json) if p]
        hits = agent_access(agent, targets)
        if hits is None:
            add("D-AGENT-PROBE", False, f"not probed: doctor runs as neither root nor {agent.pw_name}",
                "run doctor as root (sudo tracekit doctor)", bad=WARN)
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

    hook_fix = REINIT if prod else "tracekit init --dev --v2"
    if not settings:
        add("D-HOOKS-PRESENT", False, "no hooks recorded in client.json", REINIT, bad=WARN)
    else:
        try:
            hooks = _hooks(settings)
        except (OSError, ValueError, AttributeError) as e:
            hooks = None
            add("D-HOOKS-PRESENT", False, f"{settings}: {e}", hook_fix, bad=sev)
        if hooks is not None:
            missing = [ev for ev, hs in hooks.items() if not hs]
            add("D-HOOKS-PRESENT", not missing, f"no v2 hook for {', '.join(missing)} in {settings}" if missing else
                f"v2 hooks in {settings}", hook_fix, bad=sev)
            cmds = [h.get("command") or "" for hs in hooks.values() for h in hs]
            if prod and opt and cmds:
                python = os.path.join(opt, "bin", "python")
                stray = [c for c in cmds if c != install._hook_command(install.V2_HOOK, python=python)]
                add("D-HOOKS-VENV", not stray, f"{len(stray)} hooks run another Python than {python}" if stray else
                    f"hooks run {python}", REINIT)
            pre = [h.get("timeout", 60) for h in hooks["PreToolUse"]]
            if pre:
                add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S, f"PreToolUse timeout {min(pre)} s, approval wait "
                    f"{APPROVAL_WAIT_S} s", f"set the PreToolUse hook timeout to {install.HOOK_TIMEOUT['PreToolUse']}")
            if signer:
                env = (read_json(settings).get("env") or {}).get("TRACEKIT_SIGNER")
                add("D-SIGNER-ENV", env in (None, signer), f"TRACEKIT_SIGNER is {env}, not {signer}" if env not in
                    (None, signer) else "TRACEKIT_SIGNER names the system socket or is unset",
                    f"remove env.TRACEKIT_SIGNER from {settings} (the hook refuses it and blocks every call)")

    if prod:
        bad = trusted_file(policy)
        add("D-POLICY-TRUST", not bad, bad or f"{policy} is root-owned", "make the policy and its directories "
            "root-owned and not group/world-writable, or set policy: in signer.yaml to such a file")
    try:
        # lean: loads the policy with this process's Python; check the signer venv's engine if they ever differ
        add("D-POLICY-ENGINE", True, f"{policy} loads on {service.load_policy(policy).engine}", "")
    except ImportError as e:
        add("D-POLICY-ENGINE", False, f"no regex engine: {e}", "install the signer extra: pip install 'tracekit-ai[signer]'")
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
        "so assurance stays local", "add a witness under witnesses: in signer.yaml (docs/witnesses.md)", bad=sev)
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
            "check the witness is reachable and accepts this log (docs/witnesses.md)", bad=WARN)
        try:
            cosigs = checkpoint.open_note(note, [service.read_vkey(data)], [w["vkey"] for w in ws])[3]
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

