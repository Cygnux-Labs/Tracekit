"""`tracekit doctor [--json] [--config signer.yaml]`: checks a Tracekit setup and says how to fix what it finds.

It detects the setup: v1 system mode (/etc/tracekit/client.json names a socket), v2 system mode (it names a signer),
the v2 dev signer (no system config), or the signer.yaml given with --config. Every check has a stable id and gives
ok, warn or fail; docs/doctor.md lists them. Exit 0 when all are ok, 1 when any fails, 2 when there are only warnings.
Run it as root for system mode: it then probes the files as the agent's user, in a forked child that dropped to it.
`--k8s` checks the pod it runs in, or the manifests under `--manifests DIR`, instead.

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

from . import client, install, yamlmini
from .core import read_json, read_text
from .harness_helper import HELPER_CAPS, trusted_file
from .deploy import files

OK, WARN, FAIL = "ok", "warn", "fail"
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb", "smb3", "smbfs", "afpfs", "webdav", "fuse", "fuseblk", "9p", "macfuse",
              "osxfuse"}
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
        # lean: the hook checks read Claude Code's settings only; a Codex, Cursor or Gemini config goes unchecked
        # (reported as no hooks recorded) until doctor learns their formats
        settings = h.get("settings") if h.get("agent", "claude") == "claude" else None
        return out + v2_checks(config or install.V2_CONFIG, agent=_user(h.get("user")), settings=settings,
                               signer=(sc or {}).get("signer"), opt=install.OPT, unit=unit,
                               client_json=client.SYSTEM_CONFIG if sc else None, issuer_key=issuer_key)
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
    """{tool event: [v2 hook entries]} of a Claude Code settings file."""
    hooks = (read_json(settings) or {}).get("hooks") or {}
    return {ev: [h for g in hooks.get(ev) or () if isinstance(g, dict) and install._hook_version(g) == "v2"
                 for h in g.get("hooks") or () if isinstance(h, dict)] for ev in install.TOOL_EVENTS}


def v2_checks(config, profile="production", agent=None, settings=None, signer=None, opt=None, unit=None,
              client_json=None, now=None, issuer_key=None):
    """Checks of a v2 signer. config: a signer.yaml path, or the dev signer's config dict. profile "dev" turns what
    a dev setup can't have into warnings. agent: the agent's pwd entry; settings: its Claude Code settings; signer: the
    socket client.json names; opt: the root-owned venv; unit: the service file; client_json: the system client config;
    issuer_key: the KMS key of the record key issuer, which this host's AWS principal must not sign with."""
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
        if cfg.get("harness_binding"):
            out.append(helper_result(
                os.path.join(os.path.dirname(unit), (install.HELPER_LABEL + ".plist") if unit.endswith(".plist")
                             else install.V2_HELPER + ".service"), REINIT + " --harness [NAME=]PATH"))

    hook_fix = REINIT if prod else "tracekit init --dev --v2"
    if not settings:
        add("D-HOOKS-PRESENT", False, "no hooks recorded in client.json", REINIT, bad=WARN)
    else:
        try:
            hooks = _hooks(settings)
        except (OSError, ValueError, AttributeError, TypeError) as e:   # the agent's own file: any shape
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
            pre = [t if type(t) in (int, float) else 0 for t in (h.get("timeout", 60) for h in hooks["PreToolUse"])]
            if pre:
                add("D-HOOKS-TIMEOUT", min(pre) >= APPROVAL_WAIT_S, f"PreToolUse timeout {min(pre)} s, approval wait "
                    f"{APPROVAL_WAIT_S} s", f"set the PreToolUse hook timeout to {install.HOOK_TIMEOUT['PreToolUse']}")
            if signer:
                env = (read_json(settings) or {}).get("env")
                env = env.get("TRACEKIT_SIGNER") if isinstance(env, dict) else None
                add("D-SIGNER-ENV", env in (None, signer), f"TRACEKIT_SIGNER is {str(env)[:256]!r}, not {signer}" if env not in
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
