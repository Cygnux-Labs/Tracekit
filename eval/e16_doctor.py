#!/usr/bin/env python3
"""E16: does `tracekit doctor` flag misconfigured v2 signers?  Each case builds a clean v2 system mode layout (venv,
signer.yaml, policy, client.json, data dir with keys and a cosigned checkpoint, systemd unit, the agent's hooks) in a
temp root, breaks one thing, and expects the named check to fail or warn; the clean layout must pass every check.
Nothing outside the temp root changes. Without root, "root-owned" means owned by this user inside the temp root, the
agent's access is modelled by the other-permission bits, and root-only cases are skipped.
Writes eval/results/e16_doctor.json; exit 0 only when every case is flagged and the clean case passes."""
import json
import os
import shutil
import stat
import struct
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
    """daemon.trusted_file with `me` as root and `top` as /."""
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


def main():
    out = os.path.join(ROOT, "eval", "results", "e16_doctor.json")
    clean = run_case(None)
    res = {"clean": {"passed": all(r["status"] == "ok" for r in clean),
                     "not_ok": [r for r in clean if r["status"] != "ok"]}, "cases": {}}
    for name, want, mutate in CASES:
        if name in ROOT_ONLY and not IS_ROOT:
            res["cases"][name] = {"expect": want, "skipped": "needs root"}
            continue
        got = {r["id"]: r for r in run_case(mutate)}
        flagged = want in got and got[want]["status"] != "ok"
        res["cases"][name] = {"expect": want, "flagged": flagged, "result": got.get(want)}
    ran = [c for c in res["cases"].values() if "skipped" not in c]
    res["passed"] = res["clean"]["passed"] and all(c["flagged"] for c in ran)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"{'PASS' if res['clean']['passed'] else 'FAIL'}  clean configuration"
          + "".join(f"\n      {r['id']}: {r['detail']}" for r in res["clean"]["not_ok"]))
    for name, c in res["cases"].items():
        print(f"{'SKIP' if 'skipped' in c else 'FLAG' if c['flagged'] else 'MISS'}  {c['expect']}: {name}")
    print(f"E16: {sum(c.get('flagged', False) for c in ran)}/{len(ran)} flagged ({len(CASES) - len(ran)} skipped "
          f"without root); gate {'PASS' if res['passed'] else 'FAIL'}")
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
