#!/usr/bin/env python3
"""E16: does `tracekit doctor` flag misconfigured v2 signers?  Each case builds a clean v2 system mode layout (venv,
signer.yaml, policy, client.json, data dir with keys and a cosigned checkpoint, systemd unit, the agent's hooks) in a
temp root, breaks one thing, and expects the named check to fail or warn; the clean layout must pass every check.
Nothing outside the temp root changes. Without root, "root-owned" means owned by this user inside the temp root, the
agent's access is modelled by the other-permission bits, and root-only cases are skipped.
K8S_CASES do the same for `doctor --k8s --manifests`: a clean sidecar deployment written to a temp dir, one thing broken
per case. PG_CASES check the signer's Postgres role on a throwaway cluster (TRACEKIT_TEST_PG_DSN, a superuser DSN, or
initdb and pg_ctl on PATH; skipped with the reason otherwise).
Writes eval/results/e16_doctor.json; exit 0 only when every case is flagged and the clean cases pass."""
import json
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import types
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import crypto, doctor, install  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402

AGENT = types.SimpleNamespace(pw_name="e16-agent", pw_uid=54321, pw_gid=54321, pw_dir="/nonexistent")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
SIZE = 7


class Layout:
    def __init__(self, top):
        self.top = top
        p = self.path = lambda *a: os.path.join(top, *a)
        for d in ("opt/bin", "etc", "unit", "home/.claude"):
            os.makedirs(p(d), 0o755, exist_ok=True)
        for f, mode in (("opt/bin/python", 0o755), ("opt/pyvenv.cfg", 0o644)):
            self.write(f, b"", mode)
        self.python, self.sock = p("opt/bin/python"), p("run/signer.sock")
        self.write("etc/policy.json", b'{"description": "e16"}')
        self.client({"mode": "system", "signer": self.sock, "fail_mode": "closed"})
        os.mkdir(p("data"), 0o700)
        os.mkdir(p("data/keys"), 0o700)
        os.makedirs(p("data/store"), 0o750)
        self.log_key, self.witness_key = crypto.generate()[0], crypto.generate()[0]
        self.write("data/keys/record.key", crypto.generate()[0], 0o600)
        self.write("data/keys/log.key", self.log_key, 0o600)
        self.log_vkey = checkpoint.vkey("e16.example/log", checkpoint.ED25519, crypto.public_from_secret(self.log_key))
        self.write("data/log.vkey", self.log_vkey.encode())
        self.write("data/hygiene.json", b'{"core_limit": 0, "dumpable": false, "mlock": true}')
        self.wname = "e16.example/witness"
        self.wvkey = checkpoint.vkey(self.wname, checkpoint.COSIGNATURE, crypto.public_from_secret(self.witness_key))
        self.note(int(time.time()))
        self.queue({self.wname: {"records": {"size": SIZE, "since": None}}})
        self.yaml = {"data_dir": p("data"), "socket": self.sock, "durability": "ack-on-fsync",
                     "policy": p("etc/policy.json"), "witnesses": [{"url": "https://w.example", "vkey": self.wvkey,
                                                                     "class": "customer"}]}
        self.signer_yaml()
        self.write("unit/tracekit-signer.service", install.V2_UNIT_TEXT.format(
            user="tracekit-signer", python=self.python, config=p("etc/signer.yaml"), unit="tracekit-signer",
            data=p("data")).encode())
        self.settings = p("home/.claude/settings.json")
        self.hooks()
        self.kw = dict(agent=AGENT, settings=self.settings, signer=self.sock, opt=p("opt"),
                       unit=p("unit/tracekit-signer.service"), client_json=p("etc/client.json"))

    def write(self, rel, data, mode=0o644):
        path = self.path(rel)
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(path, mode)

    def client(self, cfg):
        self.write("etc/client.json", json.dumps(cfg).encode())

    def signer_yaml(self, **changes):
        self.yaml.update(changes)
        self.write("etc/signer.yaml", json.dumps(self.yaml).encode())

    def note(self, ts):
        text = checkpoint.body("e16.example/log", SIZE, b"\x01" * 32)
        sig = struct.pack(">Q", ts) + crypto.sign(self.witness_key, f"cosignature/v1\ntime {ts}\n{text}".encode())
        cosig = checkpoint._b64(checkpoint.key_id(self.wname, checkpoint.COSIGNATURE,
                                                  crypto.public_from_secret(self.witness_key)) + sig)
        note = text + "\n" + checkpoint.sign(text, "e16.example/log", self.log_key) + f"— {self.wname} {cosig}\n"
        self.write("data/store/checkpoint.note", note.encode(), 0o640)

    def queue(self, q):
        self.write("data/store/witness-queue.json", json.dumps(q).encode(), 0o640)

    def hooks(self, python=None, **extra):
        if os.path.exists(self.settings):
            os.remove(self.settings)
        install.install_hooks(self.settings, python=python or self.python, module=install.V2_HOOK, signer=self.sock)
        s = json.load(open(self.settings))
        s.update(extra)
        with open(self.settings, "w") as f:
            json.dump(s, f)

    def run(self):
        return doctor.v2_checks(self.path("etc/signer.yaml"), **self.kw)


def trusted_under(top, me):
    """harness_helper.trusted_file with `me` as root and `top` as /."""
    def check(path):
        p = os.path.realpath(path)
        while True:
            try:
                st = os.stat(p)
            except OSError as e:
                return f"{p}: {e.strerror}"
            if st.st_uid != me:
                return f"{p} is not owned by root"
            if st.st_mode & 0o022:
                return f"{p} is group- or world-writable"
            if p == top or not p.startswith(top):
                return None
            p = os.path.dirname(p)
    return check


def root_only_under(me):
    def check(path):
        st = os.lstat(path)
        if st.st_uid != me:
            return f"{path} is not owned by root"
        return f"{path} is group- or world-writable" if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022 else None
    return check


def other_access(top):
    """lean: the agent as a user that neither owns the files nor is in their group (other bits; no ACLs)"""
    def probe(pw, targets):
        def can(p, bit):
            q = os.path.dirname(p)
            while q.startswith(top):
                if not os.stat(q).st_mode & 0o001:
                    return False
                q = os.path.dirname(q)
            return bool(os.stat(p).st_mode & bit)
        return [[p, m] for p, m in targets if can(p, 0o004 if m == "read" else 0o002)]
    return probe


def _chmod(rel, mode):
    return lambda L: os.chmod(L.path(rel), mode)


def _probe_keys(L):
    for rel, mode in (("data", 0o711), ("data/keys", 0o755), ("data/keys/record.key", 0o644)):
        os.chmod(L.path(rel), mode)


def _unit_without(*directives):
    def mutate(L):
        unit = L.kw["unit"]
        lines = [line for line in open(unit).read().splitlines() if line not in directives]
        L.write(os.path.relpath(unit, L.top), "\n".join(lines).encode())
    return mutate


def _timeout(L):
    s = json.load(open(L.settings))
    s["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 60
    json.dump(s, open(L.settings, "w"))


def _mounts(kind):
    return lambda L: L.patches.append(mock.patch.object(doctor, "_mounts", return_value=[(L.top, kind)]))


CASES = [
    ("signer.yaml does not load", "D-CONFIG", lambda L: L.signer_yaml(bogus=1)),
    ("signer.yaml world-writable", "D-CONFIG", _chmod("etc/signer.yaml", 0o666)),
    ("agent is root", "D-AGENT-PRIV", lambda L: L.kw.update(agent=types.SimpleNamespace(**dict(vars(AGENT), pw_uid=0)))),
    ("keys readable by the agent", "D-AGENT-PROBE", _probe_keys),
    ("client.json writable by the agent", "D-AGENT-PROBE", _chmod("etc/client.json", 0o666)),
    ("policy writable by others", "D-POLICY-TRUST", _chmod("etc/policy.json", 0o666)),
    ("venv file group-writable", "D-CODE-TRUST", _chmod("opt/pyvenv.cfg", 0o664)),
    ("venv missing", "D-CODE-TRUST", lambda L: shutil.rmtree(L.path("opt"))),
    ("key file 0640", "D-KEYS-MODE", _chmod("data/keys/record.key", 0o640)),
    ("data dir 0750", "D-KEYS-MODE", _chmod("data", 0o750)),
    ("log key is the record key", "D-KEYS-DISTINCT",
     lambda L: L.write("data/keys/log.key", open(L.path("data/keys/record.key"), "rb").read(), 0o600)),
    ("signer may dump core", "D-KEY-HYGIENE",
     lambda L: L.write("data/hygiene.json", b'{"core_limit": null, "dumpable": true, "mlock": false}')),
    ("unit without NoNewPrivileges and the syscall filter", "D-UNIT-HARDENING",
     _unit_without("NoNewPrivileges=true", "SystemCallFilter=@system-service")),
    ("no service unit", "D-UNIT-HARDENING", lambda L: os.remove(L.kw["unit"])),
    ("hooks missing", "D-HOOKS-PRESENT",
     lambda L: install.install_hooks(L.settings, uninstall=True, signer=L.sock)),
    ("hooks run another Python", "D-HOOKS-VENV", lambda L: L.hooks(python="/usr/bin/python3")),
    ("PreToolUse timeout below the approval wait", "D-HOOKS-TIMEOUT", _timeout),
    ("TRACEKIT_SIGNER elsewhere", "D-SIGNER-ENV", lambda L: L.hooks(env={"TRACEKIT_SIGNER": L.path("decoy.sock")})),
    ("policy does not compile", "D-POLICY-ENGINE", lambda L: L.write("etc/policy.json", b'{"bogus": 1}')),
    ("ack-on-write", "D-DURABILITY", lambda L: L.signer_yaml(durability="ack-on-write")),
    ("a fail-open class", "D-FAIL-MODES", lambda L: L.signer_yaml(fail_modes={"default": "closed", "read": "open"})),
    ("client.json fail_mode open", "D-FAIL-MODES",
     lambda L: L.client({"mode": "system", "signer": L.sock, "fail_mode": "open"})),
    ("no witnesses", "D-WITNESS-CONFIGURED", lambda L: L.signer_yaml(witnesses=[])),
    ("only operator witnesses", "D-WITNESS-OWNERSHIP",
     lambda L: L.signer_yaml(witnesses=[dict(L.yaml["witnesses"][0], **{"class": "operator"})])),
    ("witness never cosigned", "D-WITNESS-FRESH", lambda L: L.queue({})),
    ("witness failing for an hour", "D-WITNESS-FRESH",
     lambda L: L.queue({L.wname: {"records": {"size": 2, "since": time.time() - 3600}}})),
    ("clock an hour behind the witness", "D-CLOCK-SKEW", lambda L: L.note(int(time.time()) + 3600)),
    ("data dir on NFS", "D-DATA-FS", _mounts("nfs4")),
    ("data dir on FUSE", "D-DATA-FS", _mounts("fuse.sshfs")),
    ("data dir owned by the agent", "D-PROCESS-BOUNDARY",
     lambda L: os.chown(L.path("data"), AGENT.pw_uid, AGENT.pw_gid)),
]
ROOT_ONLY = {"data dir owned by the agent"}


def run_case(mutate):
    tmp = tempfile.mkdtemp(prefix="e16-")
    top = os.path.realpath(tmp)
    os.chmod(top, 0o755)
    try:
        L = Layout(top)
        L.patches = []
        me = os.geteuid()
        L.patches += [mock.patch.object(doctor, "trusted_file", trusted_under(top, me)),
                      mock.patch.object(install, "_root_only", root_only_under(me))]
        if not IS_ROOT:
            L.patches.append(mock.patch.object(doctor, "agent_access", other_access(top)))
        if mutate:
            mutate(L)
        for p in L.patches:
            p.start()
        try:
            return L.run()
        finally:
            for p in L.patches:
                p.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


HARDENED = {"runAsNonRoot": True, "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]}}


def k8s_clean():
    """A sidecar deployment: the agent shares only the socket dir with a native-sidecar signer, as another uid."""
    agent = {"name": "agent", "image": "example.org/agent:1", "securityContext": dict(HARDENED, runAsUser=1000),
             "env": [{"name": "TRACEKIT_SIGNER", "value": "/run/tracekit-signer/signer.sock"}],
             "volumeMounts": [{"name": "socket", "mountPath": "/run/tracekit-signer"},
                              {"name": "work", "mountPath": "/work"}]}
    signer = {"name": "signer", "image": "ghcr.io/cygnux-labs/tracekit-signer:0.4", "restartPolicy": "Always",
              "securityContext": dict(HARDENED, runAsUser=10001),
              "volumeMounts": [{"name": "socket", "mountPath": "/run/tracekit-signer"},
                               {"name": "data", "mountPath": "/var/lib/tracekit-signer"},
                               {"name": "scratch", "mountPath": "/tmp"}]}
    pod = {"serviceAccountName": "agent", "automountServiceAccountToken": False, "initContainers": [signer],
           "containers": [agent], "volumes": [{"name": "socket", "emptyDir": {}}, {"name": "work", "emptyDir": {}},
                                              {"name": "scratch", "emptyDir": {}},
                                              {"name": "data", "persistentVolumeClaim": {"claimName": "signer-data"}}]}
    return [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "agent", "namespace": "acme"}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "agent", "namespace": "acme"},
             "spec": {"template": {"spec": pod}}}]


def _pod(docs):
    return docs[1]["spec"]["template"]["spec"]


def _agent(docs):
    return _pod(docs)["containers"][0]


def _signer(docs):
    return _pod(docs)["initContainers"][0]


def _sa_note(key, value):
    return lambda docs: docs[0]["metadata"].setdefault("annotations", {}).update({key: value})


def _set(part, **kv):
    return lambda docs: part(docs).update(kv)


def _ctx(part, **kv):
    return lambda docs: part(docs)["securityContext"].update(kv)


def _mount(part, name, path):
    return lambda docs: part(docs)["volumeMounts"].append({"name": name, "mountPath": path})


def _other_pod(docs):
    """A central-mode agent in its own pod that mounts the signer's claim."""
    pod = {"containers": [{"name": "agent", "image": "example.org/agent:1", "securityContext":
                           dict(HARDENED, runAsUser=1000), "env": [{"name": "TRACEKIT_SIGNER_URL", "value":
                                                                    "https://signer.acme.svc:8443"}],
                           "volumeMounts": [{"name": "d", "mountPath": "/mnt"}]}],
           "automountServiceAccountToken": False,
           "volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": "signer-data"}}]}
    docs.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "debug", "namespace": "acme"}, "spec": pod})


K8S_CASES = [
    ("agent mounts the signer's data volume", "D-K8S-SIGNER-DATA", _mount(_agent, "data", "/data")),
    ("another pod mounts the signer's claim", "D-K8S-SIGNER-DATA", _other_pod),
    ("agent shares a scratch volume with the signer", "D-K8S-SHARED-VOLUME", _mount(_agent, "scratch", "/scratch")),
    ("agent runs as the signer's uid", "D-K8S-RUN-AS-USER", _ctx(_agent, runAsUser=10001)),
    ("agent's runAsUser not set", "D-K8S-RUN-AS-USER", lambda docs: _agent(docs)["securityContext"].pop("runAsUser")),
    ("service account token automounted", "D-K8S-SA-TOKEN", _set(_pod, automountServiceAccountToken=True)),
    ("GKE Workload Identity on the agent's service account", "D-K8S-WORKLOAD-IDENTITY",
     _sa_note("iam.gke.io/gcp-service-account", "signer@acme.iam.gserviceaccount.com")),
    ("IRSA role on the agent's service account", "D-K8S-WORKLOAD-IDENTITY",
     _sa_note("eks.amazonaws.com/role-arn", "arn:aws:iam::111122223333:role/tracekit-kms")),
    ("EKS Pod Identity association for the agent's service account", "D-K8S-WORKLOAD-IDENTITY", lambda docs: docs.append(
        {"apiVersion": "eks.services.k8s.aws/v1alpha1", "kind": "PodIdentityAssociation", "metadata": {"name": "a"},
         "spec": {"clusterName": "c", "namespace": "acme", "serviceAccount": "agent",
                  "roleARN": "arn:aws:iam::111122223333:role/tracekit-kms"}})),
    ("EKS credentials injected into the pod", "D-K8S-WORKLOAD-IDENTITY", _set(_signer, env=[
        {"name": "AWS_CONTAINER_CREDENTIALS_FULL_URI", "value": "http://169.254.170.23/v1/credentials"}])),
    ("agent privileged", "D-K8S-SECURITY-CONTEXT", _ctx(_agent, privileged=True)),
    ("agent may escalate privileges", "D-K8S-SECURITY-CONTEXT", _ctx(_agent, allowPrivilegeEscalation=True)),
    ("agent root fs writable", "D-K8S-SECURITY-CONTEXT", _ctx(_agent, readOnlyRootFilesystem=False)),
    ("signer keeps its capabilities", "D-K8S-SECURITY-CONTEXT", _ctx(_signer, capabilities={})),
    ("agent runs as root", "D-K8S-SECURITY-CONTEXT", _ctx(_agent, runAsUser=0, runAsNonRoot=False)),
    ("hostPath volume", "D-K8S-HOST-ACCESS", lambda docs: _pod(docs)["volumes"].append(
        {"name": "host", "hostPath": {"path": "/var/run"}})),
    ("hostPID", "D-K8S-HOST-ACCESS", _set(_pod, hostPID=True)),
    ("hostNetwork", "D-K8S-HOST-ACCESS", _set(_pod, hostNetwork=True)),
    ("a manifest that does not parse", "D-K8S-WORKLOADS", lambda docs: docs.append("[unclosed")),
]


def run_k8s_case(mutate):
    docs = k8s_clean()
    if mutate:
        mutate(docs)
    top = tempfile.mkdtemp(prefix="e16-k8s-")
    try:
        with open(os.path.join(top, "agent.yaml"), "w") as f:   # multi-document, like helm template's output
            f.write("".join(f"---\n{d if isinstance(d, str) else json.dumps(d)}\n" for d in docs))
        return doctor.k8s_checks(*doctor.load_manifests(top))
    finally:
        shutil.rmtree(top, ignore_errors=True)


PG_CASES = [
    ("signer role may UPDATE records", "D-PG-SIGNER-ROLE", "GRANT UPDATE ON tracekit_records TO {signer}"),
    ("signer role may DELETE notes", "D-PG-SIGNER-ROLE", "GRANT DELETE ON tracekit_notes TO {signer}"),
    ("signer role may TRUNCATE the registry", "D-PG-SIGNER-ROLE", "GRANT TRUNCATE ON tracekit_registry TO {signer}"),
    ("signer role is superuser", "D-PG-SIGNER-ROLE", "ALTER ROLE {signer} SUPERUSER"),
    ("reader role may INSERT records", "D-PG-READER-ROLES", "GRANT INSERT ON tracekit_records TO {reader}"),
]


def pg_admin():
    """(superuser DSN, cluster dir to stop or None), or (None, why) when there is no Postgres to run on."""
    try:
        from psycopg.conninfo import make_conninfo
    except ImportError:
        return None, "needs psycopg: pip install 'tracekit-ai[postgres]'"
    if os.environ.get("TRACEKIT_TEST_PG_DSN"):
        return os.environ["TRACEKIT_TEST_PG_DSN"], None
    if not (shutil.which("initdb") and shutil.which("pg_ctl")):
        return None, "needs TRACEKIT_TEST_PG_DSN, or initdb and pg_ctl on PATH"
    cluster = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: the socket path
    data = os.path.join(cluster, "data")
    try:
        subprocess.run(["initdb", "-D", data, "-A", "trust", "-U", "postgres", "--no-sync"], check=True,
                       capture_output=True)
        subprocess.run(["pg_ctl", "-D", data, "-l", os.path.join(cluster, "log"), "-w", "-o",
                        f"-k {cluster} -c listen_addresses='' -c fsync=off", "start"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        shutil.rmtree(cluster, ignore_errors=True)
        return None, f"{e.cmd[0]} failed: {e.stderr.decode(errors='replace').strip()[-256:]}"
    return make_conninfo(host=cluster, dbname="postgres", user="postgres"), cluster


def pg_stop(cluster):
    if cluster:
        subprocess.run(["pg_ctl", "-D", os.path.join(cluster, "data"), "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(cluster, ignore_errors=True)


def run_pg_case(admin, sql):
    """Doctor's Postgres checks as a signer role holding postgres.GRANTS, beside a SELECT-only reader role, after `sql`,
    in a schema and roles of their own (dropped after)."""
    import psycopg
    from psycopg.conninfo import make_conninfo
    from tracekit.storage import postgres
    tag = secrets.token_hex(4)
    schema, signer, reader, pw = f"e16_{tag}", f"e16_signer_{tag}", f"e16_reader_{tag}", secrets.token_hex(16)
    tables = ", ".join(doctor.LOG_TABLES)
    top = tempfile.mkdtemp(prefix="e16-pg-")
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
        try:
            postgres.migrate(make_conninfo(admin, options=f"-csearch_path={schema}"))
            c.execute(f"SET search_path = {schema}")
            c.execute(f"CREATE ROLE {signer} LOGIN PASSWORD '{pw}'; CREATE ROLE {reader};"
                      f"GRANT USAGE ON SCHEMA {schema} TO {reader}; GRANT SELECT ON {tables} TO {reader};"
                      + postgres.GRANTS.format(schema=schema, role=signer) + (sql or "").format(signer=signer, reader=reader))
            with open(os.path.join(top, "pg.dsn"), "w") as f:
                f.write(make_conninfo(admin, user=signer, password=pw, options=f"-csearch_path={schema}"))
            return doctor.pg_checks({"dsn_file": os.path.join(top, "pg.dsn")})
        finally:
            c.execute(f"DROP SCHEMA {schema} CASCADE")
            for role in (signer, reader):
                c.execute(f"DROP OWNED BY {role}; DROP ROLE {role}")
            shutil.rmtree(top, ignore_errors=True)


def _score(clean, cases, run):
    """{"clean", "cases"} of one corpus: the clean run's not-ok results, and each case's flag."""
    res = {"clean": {"passed": all(r["status"] == "ok" for r in clean),
                     "not_ok": [r for r in clean if r["status"] != "ok"]}, "cases": {}}
    for name, want, mutate in cases:
        got = {r["id"]: r for r in run(mutate)}
        res["cases"][name] = {"expect": want, "flagged": want in got and got[want]["status"] != "ok",
                              "result": got.get(want)}
    return res


def main():
    out = os.path.join(ROOT, "eval", "results", "e16_doctor.json")
    res = _score(run_case(None), [c for c in CASES if c[0] not in ROOT_ONLY or IS_ROOT], run_case)
    res["cases"].update({n: {"expect": w, "skipped": "needs root"} for n, w, _ in CASES if n in ROOT_ONLY and not IS_ROOT})
    res["k8s"] = _score(run_k8s_case(None), K8S_CASES, run_k8s_case)
    admin, cluster = pg_admin()
    if admin:
        try:
            res["postgres"] = _score(run_pg_case(admin, None), PG_CASES, lambda sql: run_pg_case(admin, sql))
        finally:
            pg_stop(cluster)
    else:
        res["postgres"] = {"skipped": cluster}
    corpora = [res, res["k8s"]] + ([res["postgres"]] if admin else [])
    ran = [c for r in corpora for c in r["cases"].values() if "skipped" not in c]
    res["passed"] = all(r["clean"]["passed"] for r in corpora) and all(c["flagged"] for c in ran)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    for label, r in zip(("signer", "k8s", "postgres"), corpora):
        print(f"{'PASS' if r['clean']['passed'] else 'FAIL'}  clean {label} configuration"
              + "".join(f"\n      {x['id']}: {x['detail']}" for x in r["clean"]["not_ok"]))
        for name, c in r["cases"].items():
            print(f"{'SKIP' if 'skipped' in c else 'FLAG' if c['flagged'] else 'MISS'}  {c['expect']}: {name}")
    if not admin:
        print(f"SKIP  postgres cases: {cluster}")
    skipped = len(CASES) + len(K8S_CASES) + len(PG_CASES) - len(ran)
    print(f"E16: {sum(c['flagged'] for c in ran)}/{len(ran)} flagged ({skipped} skipped without root or Postgres); "
          f"gate {'PASS' if res['passed'] else 'FAIL'}")
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
