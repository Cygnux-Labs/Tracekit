#!/usr/bin/env python3
"""E4: seeded faults against the v0.2 evidence bundle.

Builds a real signed bundle from a dev signer with a git witness, then, for each fault class, makes many
corrupted copies (random positions) and runs the offline verifier. A fault is "detected" when `verify` exits
non-zero. The attacker edits the zip directly and always repairs the manifest hashes, which is the strongest
attacker who does not hold the signing key. Three classes give the attacker the real signing key.
Each class is reported twice: the bundle alone (no witness) and the bundle against the independent git witness.
Writes eval/results/e4_seeded_faults.json."""
import copy
import hashlib
import json
import os
import random
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import Stack, write_results  # noqa: E402
from tracekit import bundle, crypto  # noqa: E402
from tracekit.core import GENESIS, b64e, event_hash  # noqa: E402
from tracekit.ledger import Keys, make_record  # noqa: E402

TRIALS = int(os.environ.get("E4_TRIALS", 30))
random.seed(11)


def build_base(stack):
    from tracekit.agent_sdk import Tracer
    with Tracer(agent="e4", session_id="e4-run") as t:
        t.prompt("fix the failing test")
        for i in range(14):
            with t.tool(["Read", "Edit", "Bash"][i % 3], {"file_path": f"src/f{i}.py"} if i % 3 < 2 else {"command": f"pytest -q t{i}"}) as c:
                c.result({"ok": True, "n": i})
        try:
            with t.tool("Bash", {"command": "sudo cp x /etc/x"}):
                pass
        except PermissionError:
            pass
        t.say("done")
    stack.stop()
    out = os.path.join(stack.dir, "base.tkb")
    bundle.export(stack.home, out)
    return out


def bump(event):
    """Change the timestamp by one microsecond-digit, keeping the exact format the schema requires."""
    ts = event["ts"]
    event["ts"] = ts[:-2] + str((int(ts[-2]) + 1) % 10) + "Z"


def load(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def dump(files, path):
    with zipfile.ZipFile(path, "w") as z:
        for n, v in files.items():
            z.writestr(n, v)


def fix_manifest(files):
    man = json.loads(files["manifest.json"])
    for n in list(man.get("files", {})):
        if n in files:
            man["files"][n] = hashlib.sha256(files[n]).hexdigest()
    files["manifest.json"] = json.dumps(man).encode()


def records(files):
    return [json.loads(l) for l in files["records.jsonl"].decode().splitlines() if l.strip()]


def put_records(files, recs):
    files["records.jsonl"] = ("\n".join(json.dumps(r) for r in recs) + "\n").encode()


def rechain(recs, keys=None):
    """Renumber, re-link and re-hash; re-sign with `keys` when given, otherwise leave the old signatures."""
    prev = GENESIS
    for i, r in enumerate(recs):
        e = r["event"]
        e["seq"], e["prev_hash"] = i, prev
        if keys:
            r.update(make_record(e, keys))
        else:
            r["hash"] = event_hash(e)
        prev = r["hash"]
    return recs


def resign_checkpoints(files, recs, keys):
    cps = []
    for l in files["checkpoints.jsonl"].decode().splitlines():
        cp = json.loads(l)
        if cp["head_seq"] < len(recs):
            from tracekit.witness import make_checkpoint
            cps.append(make_checkpoint(cp["head_seq"], recs[cp["head_seq"]]["hash"], keys, ts=cp["ts"]))
    files["checkpoints.jsonl"] = ("\n".join(json.dumps(c) for c in cps) + "\n").encode()


# ---- fault classes: each takes (files, ctx) and edits in place --------------------------------------------

def f_edit(files, ctx):
    recs = records(files)
    i = random.randrange(1, len(recs) - 1)
    bump(recs[i]["event"])
    put_records(files, recs)


def f_delete(files, ctx):
    recs = records(files)
    del recs[random.randrange(1, len(recs) - 1)]
    put_records(files, recs)


def f_swap(files, ctx):
    recs = records(files)
    i = random.randrange(1, len(recs) - 2)
    recs[i], recs[i + 1] = recs[i + 1], recs[i]
    put_records(files, recs)


def f_forge_tail(files, ctx):
    recs = records(files)
    e = copy.deepcopy(recs[-1]["event"])
    e["seq"], e["prev_hash"] = e["seq"] + 1, recs[-1]["hash"]
    bump(e)
    forged = {"v": 1, "event": e, "hash": event_hash(e), "kid": recs[-1]["kid"], "sig": b64e(os.urandom(64))}
    put_records(files, recs + [forged])


def f_rechain_nokey(files, ctx):
    recs = records(files)
    i = random.randrange(1, len(recs) - 1)
    bump(recs[i]["event"])
    put_records(files, rechain(recs))


def f_other_key(files, ctx):
    keys = Keys(*crypto.generate())
    recs = records(files)
    i = random.randrange(1, len(recs) - 1)
    bump(recs[i]["event"])
    put_records(files, rechain(recs, keys))
    resign_checkpoints(files, recs, keys)
    files["signer.pub"] = keys.public
    man = json.loads(files["manifest.json"])
    man["public_key_b64"], man["kid"] = b64e(keys.public), keys.kid
    files["manifest.json"] = json.dumps(man).encode()


def f_realkey_edit(files, ctx):
    keys = ctx["keys"]
    recs = records(files)
    i = random.randrange(1, len(recs) - 1)
    bump(recs[i]["event"])
    put_records(files, rechain(recs, keys))
    resign_checkpoints(files, recs, keys)


def f_realkey_truncate(files, ctx):
    keys = ctx["keys"]
    recs = records(files)
    recs = recs[:len(recs) - random.randint(1, 4)]
    put_records(files, recs)
    resign_checkpoints(files, recs, keys)
    man = json.loads(files["manifest.json"])
    man["seq_range"] = [man["seq_range"][0], len(recs) - 1]
    files["manifest.json"] = json.dumps(man).encode()


def f_truncate_nokey(files, ctx):
    recs = records(files)
    recs = recs[:len(recs) - random.randint(1, 4)]
    put_records(files, recs)
    man = json.loads(files["manifest.json"])
    man["seq_range"] = [man["seq_range"][0], len(recs) - 1]
    files["manifest.json"] = json.dumps(man).encode()


def f_policy_swap(files, ctx):
    name = [n for n in files if n.startswith("policies/")][0]
    pol = json.loads(files[name])
    for sec in ("deny", "ask"):
        if pol.get(sec):
            pol[sec] = pol[sec][1:]
    files[name] = json.dumps(pol).encode()


def f_range(files, ctx):
    man = json.loads(files["manifest.json"])
    man["seq_range"] = [man["seq_range"][0], man["seq_range"][1] - random.randint(1, 3)]
    files["manifest.json"] = json.dumps(man).encode()


def f_extra_file(files, ctx):
    files[f"notes{random.randint(0, 99)}.txt"] = b"nothing to see"


def f_swap_pub(files, ctx):
    k = Keys(*crypto.generate())
    files["signer.pub"] = k.public


def f_zero_checkpoints(files, ctx):
    files["checkpoints.jsonl"] = b""


FAULTS = [
    ("edit a record", f_edit, True), ("delete a record", f_delete, True), ("swap two records", f_swap, True),
    ("append a forged record (valid hash, random signature)", f_forge_tail, True),
    ("edit then re-chain, without the key", f_rechain_nokey, True),
    ("truncate the tail, without the key", f_truncate_nokey, True),
    ("replace the signer: re-sign everything with an attacker key", f_other_key, True),
    ("replace signer.pub only", f_swap_pub, True),
    ("remove a deny rule from the policy snapshot", f_policy_swap, True),
    ("narrow the manifest's seq range", f_range, True),
    ("add a file the manifest does not list", f_extra_file, True),
    ("delete the bundle's own checkpoints", f_zero_checkpoints, False),
    ("edit then re-chain and re-sign, WITH the real key", f_realkey_edit, "witness"),
    ("truncate the tail and re-sign, WITH the real key", f_realkey_truncate, "strict"),
]


def verify(path, witness, strict=False):
    try:
        rep, code = bundle.verify(path, [witness] if witness else [], strict)
    except BaseException as e:  # noqa: BLE001  the verifier must never raise
        return None, f"CRASH {type(e).__name__}: {e}"
    failed = [c["check"] for c in rep.checks if c["status"] == "fail"]
    return code, (failed[0] if failed else "")


def main():
    results = []
    with Stack(checkpoint_every=4) as s:
        base = build_base(s)
        keys = Keys.load_or_create(os.path.join(s.home, "keys"))
        ctx = {"keys": keys}
        w = s.witness_spec
        c_alone, _ = verify(base, None)
        c_wit, _ = verify(base, w)
        print(f"control (unmodified): bundle alone exit {c_alone}, with witness exit {c_wit}")
        crashes = 0
        tmp = os.path.join(s.dir, "t.tkb")
        for name, fn, must in FAULTS:
            alone = wit = strict = 0
            by_check = {}
            for _ in range(TRIALS):
                files = load(base)
                fn(files, ctx)
                fix_manifest(files)  # refreshes file hashes only; manifest edits made by a fault are kept
                dump(files, tmp)
                a, ca = verify(tmp, None)
                b, cb = verify(tmp, w)
                st, _ = verify(tmp, w, strict=True)
                strict += 1 if (st not in (0, None)) else 0
                for code, why in ((a, ca), (b, cb)):
                    if code is None:
                        crashes += 1
                alone += 1 if (a not in (0, None)) else 0
                wit += 1 if (b not in (0, None)) else 0
                by_check[cb or "-"] = by_check.get(cb or "-", 0) + 1
            results.append({"fault": name, "trials": TRIALS, "detected_bundle_alone": alone, "detected_with_witness": wit,
                            "detected_with_witness_strict": strict,
                            "first_failing_check_with_witness": by_check})
            print(f"  {name:62s} alone {alone:2d}/{TRIALS}  witness {wit:2d}/{TRIALS}  strict {strict:2d}/{TRIALS}", flush=True)
        # robustness: a damaged zip must be refused cleanly, never crash
        trunc = 0
        raw = open(base, "rb").read()
        for _ in range(TRIALS):
            cut = random.randrange(1, len(raw) - 1)
            with open(tmp, "wb") as f:
                f.write(raw[:cut])
            code, why = verify(tmp, w)
            if code is None:
                crashes += 1
            trunc += 1 if code not in (0, None) else 0
        results.append({"fault": "truncate the zip file at a random byte", "trials": TRIALS, "detected_bundle_alone": trunc,
                        "detected_with_witness": trunc})
        print(f"  {'truncate the zip file at a random byte':62s} refused {trunc}/{TRIALS}", flush=True)
    out = {"control_exit_bundle_alone": c_alone, "control_exit_with_witness": c_wit, "verifier_crashes": crashes,
           "results": results}
    print("wrote", write_results("e4_seeded_faults", out))
    expect = {name: must for name, _fn, must in FAULTS}
    must_ok = True
    for r in results:
        must = expect.get(r["fault"], True)
        key = "detected_with_witness_strict" if must == "strict" else "detected_with_witness"
        if must is not False and r.get(key, r["detected_with_witness"]) != r["trials"]:
            must_ok = False
    return 0 if (must_ok and c_wit == 0 and crashes == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
