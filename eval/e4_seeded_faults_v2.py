#!/usr/bin/env python3
"""E4 on evidence format v2: seeded faults against a real v2 bundle.

Builds a v2 bundle from an in-process v2 signer (two runs of the default tenant, one with decide, complete and an
approval; the tenant's run-set from registry size 0; the record checkpoint cosigned by a fake witness that the trust
config pins and requires), then, for each fault class, makes many corrupted copies at random positions and runs
`tracekit.verify.v2`. A fault is "detected" when the verifier exits non-zero. The attacker edits the zip directly and
repairs the manifest hashes (except in the manifest class), the strongest attacker without the signing keys.
Writes eval/results/e4_seeded_faults_v2.json; exit 0 only when every class is detected in every trial.
"""
import base64
import copy
import hashlib
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import write_results  # noqa: E402
from tracekit import crypto  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.format import checkpoint, registry  # noqa: E402
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.format.records import make_record  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.storage.base import registry_tree  # noqa: E402
from tracekit.verify import v2  # noqa: E402

TRIALS = int(os.environ.get("E4_TRIALS", 30))
WITNESS = "witness.example.org/e4"
WIT_SECRET, FOREIGN = hashlib.sha256(b"e4-witness").digest(), hashlib.sha256(b"e4-foreign").digest()
rng = random.Random(14)


def cosign(note, name, secret, ts):
    """`note` with one more C2SP cosignature line, by the witness `name`."""
    text = note[:note.index("\n\n") + 1]
    sig = struct.pack(">Q", ts) + crypto.sign(secret, f"cosignature/v1\ntime {ts}\n{text}".encode())
    kid = checkpoint.key_id(name, checkpoint.COSIGNATURE, crypto.public_from_secret(secret))
    return note + f"— {name} {base64.b64encode(kid + sig).decode()}\n"


def build(d):
    """(bundle path, trust config path) of an honest v2 bundle."""
    s = svc.SignerService(os.path.join(d, "signer"), grace_s=0,
                          policy=Engine({"ask": [{"id": "E4-PAY", "tool": "pay", "pattern": "^"}]}))
    try:
        runs = []
        for n in range(2):
            out = s.register_run({"request_id": f"reg-{n}", "agent": {"name": "e4"}})
            run = {"run_id": out["run_id"], "run_token": out["run_token"]}
            runs.append(run)
            for i in range(4):
                ev = {**run, "stream": "s", "client_seq": 2 * i, "tool_call_id": f"tc-{i}", "tool": "read_file",
                      "args_source": "parsed", "args": {"path": f"src/f{i}.py"}}
                dec = s.decide({"request_id": f"d-{n}-{i}", **ev})
                s.complete({"request_id": f"c-{n}-{i}", **run, "stream": "s", "client_seq": 2 * i + 1,
                            "tool_call_id": f"tc-{i}", "decision_id": dec["decision_id"], "status": "ok",
                            "args_digest": event_hash({"tool": "read_file", "args": ev["args"]})})
        run, pay = runs[0], {"to": "acct-42", "cents": 1500}
        dec = s.decide({"request_id": "d-pay", **run, "stream": "s", "client_seq": 8, "tool_call_id": "tc-pay",
                        "tool": "pay", "args_source": "parsed", "args": pay})
        assert dec["decision"] == "ask", dec
        aid = s.approval_request({"request_id": "a-pay", **run, "tool_call_id": "tc-pay"})["approval_id"]
        s.approval_decide({"request_id": "ad-pay", "approval_id": aid, "decision": "approve"})
        assert s.approval_consume({"request_id": "ac-pay", **run, "tool_call_id": "tc-pay", "tool": "pay",
                                   "args_source": "parsed", "args": pay, "approval_id_hint": aid})["ok"]
        s.complete({"request_id": "c-pay", **run, "stream": "s", "client_seq": 9, "tool_call_id": "tc-pay",
                    "decision_id": dec["decision_id"], "status": "ok",
                    "args_digest": event_hash({"tool": "pay", "args": pay})})
        for n, r in enumerate(runs):
            s.close_run({"request_id": f"close-{n}", **r})
        s.sweep(time.monotonic() + 1)
        s.checkpoint()
        st, tenant = s.log.storage, s.tenant
        note = cosign(st.checkpoint_latest()[1], WITNESS, WIT_SECRET, int(time.time()))
        out = os.path.join(d, "base.tkb")
        export(st, tenant, run["run_id"], note, out, run_set=(0, st.checkpoint_latest(registry_tree(tenant))[0]),
               tenant_salt=s.log.tenant_salt(tenant))
        trust = os.path.join(d, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [s.vkey], "algs": ["ed25519"], "witnesses_required": 1, "witnesses": [
                {"vkey": checkpoint.vkey(WITNESS, checkpoint.COSIGNATURE, crypto.public_from_secret(WIT_SECRET)),
                 "class": "customer"}]}, f)
        return out, trust
    finally:
        s.close()


# --- helpers over the bundle's files ({name: bytes}) ---

def lines(data):
    return [json.loads(x) for x in data.splitlines()]


def dump(records):
    return b"".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode() + b"\n" for r in records)


def flip(blob):
    """`blob` with one random bit flipped."""
    b = bytearray(blob)
    b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    return bytes(b)


def flip_b64(s):
    return base64.b64encode(flip(base64.b64decode(s))).decode("ascii")


def record_files(files, runs_only=False):
    return sorted(n for n in files if n.endswith(".jsonl") and files[n].strip()
                  and (n.startswith("runs/") or not runs_only))


def main_run(files):
    """The name of the bundled run that holds the approval."""
    return next(n for n in record_files(files, True) if b'"approval"' in files[n])


def edit_records(files, name, fn):
    rs = lines(files[name])
    fn(rs)
    files[name] = dump(rs)


def rehash(r):
    r["hash"] = event_hash(r["event"])


# --- fault classes: fn(files) mutates the bundle's files in place ---

def record_bytes(files):
    name = rng.choice(record_files(files))
    ls = files[name].split(b"\n")
    i = rng.randrange(len(ls) - 1)
    line = ls[i].decode()
    lo, hi = line.index('"event":') + 9, line.index(',"hash":')
    j = rng.randrange(lo, hi)
    ls[i] = (line[:j] + rng.choice([c for c in "abcdefXYZ0123456789" if c != line[j]]) + line[j + 1:]).encode()
    files[name] = b"\n".join(ls)


def signatures(files):
    def fn(rs):
        r = rng.choice(rs)
        r["sig"] = flip_b64(r["sig"])
    edit_records(files, rng.choice(record_files(files)), fn)


def chain_links(files):
    def fn(rs):
        r = rng.choice(rs)
        e, field = r["event"], rng.choice(["prev_hash", "run_prev_hash", "run_seq"])
        e[field] = (e[field] + rng.choice([-1, 1])) if field == "run_seq" else "sha256:" + os.urandom(32).hex()
        rehash(r)   # the attacker can recompute the hash, not the signature
    edit_records(files, rng.choice(record_files(files, True)), fn)


def inclusion_proofs(files):
    name = rng.choice(["proofs/records.json", "registry/run-set.json"])
    p = json.loads(files[name])
    paths = p["inclusion"].values() if name.startswith("proofs/") else [x["inclusion"] for x in p["leaves"]]
    path = rng.choice([x for x in paths if x])
    i = rng.randrange(len(path))
    path[i] = flip_b64(path[i])
    files[name] = json.dumps(p).encode()


def checkpoint_note(files):
    name = rng.choice(sorted(n for n in files if n.endswith(".note")))
    note = files[name].decode()
    i = note.index("\n\n")
    if rng.random() < 0.5:   # the body: origin, size or root
        j = rng.randrange(i)
        if note[j] == "\n":
            j -= 1
        note = note[:j] + rng.choice([c for c in "abcXYZ0123" if c != note[j]]) + note[j + 1:]
    else:   # a signature line: the log's, or the witness's cosignature
        sigs = note[i + 2:-1].split("\n")
        k = rng.randrange(len(sigs))
        head, blob = sigs[k].rsplit(" ", 1)
        sigs[k] = f"{head} {flip_b64(blob)}"
        note = note[:i + 2] + "\n".join(sigs) + "\n"
    files[name] = note.encode()


def registry_leaves(files):
    p = json.loads(files["registry/run-set.json"])
    x = rng.choice(p["leaves"])
    x["leaf"] = flip_b64(x["leaf"])
    files["registry/run-set.json"] = json.dumps(p).encode()


def run_set(files):
    p = json.loads(files["registry/run-set.json"])
    how = rng.choice(["to", "salt", "drop", "swap"])
    if how == "to":
        p["to"] += rng.choice([-1, 1])
    elif how == "salt":
        p["tenant_salt"] = flip_b64(p["tenant_salt"])
    elif how == "drop":
        del p["leaves"][rng.randrange(len(p["leaves"]))]
    else:
        i, j = rng.sample(range(len(p["leaves"])), 2)
        p["leaves"][i], p["leaves"][j] = p["leaves"][j], p["leaves"][i]
    files["registry/run-set.json"] = json.dumps(p).encode()


def manifest(files):
    m = json.loads(files["manifest.json"])
    how = rng.choice(["hash", "drop", "phantom", "unlisted"])
    if how == "hash":
        k = rng.choice(sorted(m["files"]))
        m["files"][k] = hashlib.sha256(m["files"][k].encode()).hexdigest()
    elif how == "drop":
        del m["files"][rng.choice(sorted(m["files"]))]
    elif how == "phantom":
        m["files"]["policies/" + "0" * 64 + ".json"] = "0" * 64
    else:
        files["policies/extra.json"] = b"{}"
    files["manifest.json"] = json.dumps(m).encode()


def dropped(files):
    edit_records(files, main_run(files), lambda rs: rs.pop(rng.randrange(len(rs))))


def reordered(files):
    def fn(rs):
        i, j = rng.sample(range(len(rs)), 2)
        rs[i], rs[j] = rs[j], rs[i]
    edit_records(files, main_run(files), fn)


def duplicated(files):
    edit_records(files, main_run(files), lambda rs: rs.insert(rng.randrange(len(rs) + 1), copy.deepcopy(rng.choice(rs))))


def foreign_key(files):
    """A record edited and re-signed with a key the log never declared; half the time with a forged signer.epoch
    declaring that key added to the key records."""
    name = main_run(files)
    rs = lines(files[name])
    i = rng.randrange(len(rs))
    e = rs[i]["event"]
    e["ts"] = e["ts"][:-2] + str((int(e["ts"][-2]) + 1) % 10) + "Z"
    rs[i] = make_record(e, FOREIGN)
    files[name] = dump(rs)
    if rng.random() < 0.5:
        keys = lines(files["keys/records.jsonl"])
        epoch = copy.deepcopy(keys[0])
        der = crypto.spki(crypto.public_from_secret(FOREIGN))
        epoch["event"]["data"]["keys"] = [{"kid": crypto.spki_kid(der), "alg": "ed25519",
                                           "spki": base64.b64encode(der).decode("ascii")}]
        keys.insert(0, make_record(epoch["event"], FOREIGN))
        files["keys/records.jsonl"] = dump(keys)


def removed_final(files):
    """run.final dropped from the run; half the time from the registry range too (its record and its leaf)."""
    name = main_run(files)
    rs = lines(files[name])
    final = rs.pop()
    files[name] = dump(rs)
    if rng.random() < 0.5:
        pointed = [r for r in lines(files["registry/records.jsonl"]) if r["hash"] != final["hash"]]
        files["registry/records.jsonl"] = dump(pointed)
        p = json.loads(files["registry/run-set.json"])
        p["leaves"] = [x for x in p["leaves"] if registry.parse(base64.b64decode(x["leaf"]))[4] != final["hash"]]
        files["registry/run-set.json"] = json.dumps(p).encode()


FAULTS = [
    ("edit record bytes (any record file)", record_bytes),
    ("flip a bit of a record signature", signatures),
    ("break a chain link (prev_hash, run_prev_hash, run_seq; hash recomputed)", chain_links),
    ("flip a bit of an inclusion proof (record tree or registry tree)", inclusion_proofs),
    ("edit a checkpoint note's body or signature lines (record or registry note)", checkpoint_note),
    ("flip a bit of a registry leaf", registry_leaves),
    ("edit the run-set (range end, tenant salt, drop or swap leaves)", run_set),
    ("edit the manifest without the files (hash, drop, phantom, unlisted file)", manifest),
    ("drop a record of the run", dropped),
    ("reorder two records of the run", reordered),
    ("duplicate a record of the run", duplicated),
    ("re-sign an edited record with a foreign key", foreign_key),
    ("remove the run's run.final", removed_final),
]


def load(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def write(files, path, fix_manifest=True):
    if fix_manifest:
        m = json.loads(files["manifest.json"])
        m["files"] = {n: hashlib.sha256(b).hexdigest() for n, b in files.items() if n != "manifest.json"}
        files["manifest.json"] = json.dumps(m).encode()
    with zipfile.ZipFile(path, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)


def verify(path, trust):
    """(exit code, first failing check); exit code None when the verifier raised."""
    try:
        rep, code = v2.verify(path, trust)
    except BaseException as e:  # noqa: BLE001  the verifier must never raise
        return None, f"CRASH {type(e).__name__}: {e}"
    return code, next((c["check"] for c in rep.checks if c["status"] == "fail"), "")


def main():
    d = tempfile.mkdtemp(prefix="tracekit-e4v2-")
    try:
        base, trust = build(d)
        rep, control = v2.verify(base, trust)
        print(f"control (unmodified): exit {control}, {rep.integrity}; {rep.assurance}")
        base_files, tmp, results, crashes = load(base), os.path.join(d, "t.tkb"), [], 0
        for name, fn in FAULTS:
            detected, by_check = 0, {}
            for _ in range(TRIALS):
                files = copy.deepcopy(base_files)
                fn(files)
                write(files, tmp, fn is not manifest)
                code, why = verify(tmp, trust)
                crashes += code is None
                detected += code not in (0, None)
                by_check[why or "-"] = by_check.get(why or "-", 0) + 1
            results.append({"fault": name, "trials": TRIALS, "detected": detected, "first_failing_check": by_check})
            print(f"  {name:80s} {detected:3d}/{TRIALS}", flush=True)
        trunc, raw = 0, open(base, "rb").read()
        for _ in range(TRIALS):   # a damaged zip is refused cleanly, never a crash
            with open(tmp, "wb") as f:
                f.write(raw[:rng.randrange(1, len(raw) - 1)])
            code, _ = verify(tmp, trust)
            crashes += code is None
            trunc += code not in (0, None)
        results.append({"fault": "truncate the zip file at a random byte", "trials": TRIALS, "detected": trunc})
        print(f"  {'truncate the zip file at a random byte':80s} {trunc:3d}/{TRIALS}", flush=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    out = {"control_exit": control, "control_integrity": rep.integrity, "verifier_crashes": crashes,
           "results": results, "platform": sys.platform, "python": sys.version.split()[0]}
    print("wrote", write_results("e4_seeded_faults_v2", out))
    return 0 if control == 0 and crashes == 0 and all(r["detected"] == r["trials"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
