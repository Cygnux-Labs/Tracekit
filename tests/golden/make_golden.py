"""Regenerate the golden corpus (tests/golden/v1, tests/golden/v01, tests/golden/expected.json). Run by hand only:

    python3 tests/golden/make_golden.py

It copies the shipped samples, builds three extra v1 bundles with fixed keys, and records what the current verifier
says about every case. The output is frozen evidence: only rerun it when a task says the corpus may change."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

GOLDEN = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(GOLDEN))
sys.path.insert(0, ROOT)
from tests.test_hotfix_021 import ev, make_signer, run_start, tool_call  # noqa: E402
from tracekit import bundle, crypto, policy  # noqa: E402

HELPER = os.path.join(ROOT, "examples", "ext_signer.py")
FILE_SECRET = hashlib.sha256(b"tracekit golden corpus: file key").digest()
EXT_SECRET = hashlib.sha256(b"tracekit golden corpus: external key").digest()


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def signer_home(d, extra=None):
    home = os.path.join(d, "signer")
    os.makedirs(os.path.join(home, "keys"), mode=0o700)
    write(os.path.join(home, "keys", "signer.key"), FILE_SECRET)
    return home, make_signer(home, {"mode": "dev", **(extra or {})})


def record_run(s, run, pol_raw, tools=("ls",)):
    s.handle({"op": "append", "cseq": 0, "event": run_start(run), "attach": {"policy": pol_raw}})
    for i, cmd in enumerate(tools, 1):
        s.handle({"op": "append", "cseq": i, "event": tool_call(f"{run}-t{i}", cmd, run)})
    s.handle({"op": "append", "cseq": len(tools) + 1, "event": ev("run.end", {"reason": "done"}, run)})


def close(s):
    s.ledger.close()
    getattr(s.keys, "close", lambda: None)()


def multi_run(out):
    """Two interleaved runs; exporting one elides the other's records. Also keeps the file witness copy."""
    with tempfile.TemporaryDirectory() as d:
        home, s = signer_home(d)
        pol_raw = policy.load()[1]
        s.handle({"op": "append", "cseq": 0, "event": run_start("other"), "attach": {"policy": pol_raw}})
        record_run(s, "golden-multi", pol_raw, ("ls", "git status"))
        s.handle({"op": "append", "cseq": 1, "event": tool_call("other-t1", "pwd", "other")})
        s.handle({"op": "append", "cseq": 2, "event": ev("run.end", {"reason": "done"}, "other")})
        s.checkpoint()
        close(s)
        bundle.export(home, os.path.join(out, "multi-run.tkb"), run="golden-multi")
        shutil.copy(os.path.join(home, "witness.jsonl"), os.path.join(out, "multi-run.witness.jsonl"))


def external_signer(out):
    """Checkpoints (and records) signed by an external signer command holding its own key."""
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "ext.key")
        write(key, EXT_SECRET)
        write(key + ".pub", crypto.public_from_secret(EXT_SECRET))
        home, s = signer_home(d, {"signer": {"type": "external", "argv": [sys.executable, HELPER, "--key", key],
                                             "public_key": key + ".pub", "assurance": "hsm"}})
        record_run(s, "golden-ext", policy.load()[1])
        s.checkpoint()
        close(s)
        bundle.export(home, os.path.join(out, "external-signer.tkb"), run="golden-ext")
        shutil.copy(key + ".pub", os.path.join(out, "external-signer.pub"))


def torn_ledger(out):
    """A ledger whose last line was cut short (no newline), as after a crash mid-write, exported as is."""
    with tempfile.TemporaryDirectory() as d:
        home, s = signer_home(d)
        record_run(s, "golden-torn", policy.load()[1])
        s.checkpoint()
        close(s)
        path = os.path.join(home, "ledger", "ledger.jsonl")
        with open(path, "rb") as f:
            last = f.read().splitlines()[-1]
        with open(path, "ab") as f:
            f.write(last[:len(last) // 2])
        bundle.export(home, os.path.join(out, "torn-ledger.tkb"), run="golden-torn")


def run_case(case):
    """What the verifier (or, for v0.1, the migrate entry point) says, via the CLI as a user would run it."""
    cwd = os.path.join(GOLDEN, case["dir"])
    env = {**os.environ, "PYTHONPATH": ROOT}
    cli = [sys.executable, "-m", "tracekit", case["command"], *case["args"]]
    text = subprocess.run(cli, cwd=cwd, env=env, capture_output=True, text=True)
    out = {"exit_code": text.returncode}
    if case["command"] == "migrate":
        out["output"] = text.stdout.splitlines()
        return out
    js = json.loads(subprocess.run(cli + ["--json"], cwd=cwd, env=env, capture_output=True, text=True).stdout)
    lines = text.stdout.splitlines()
    out["integrity"] = next(l for l in lines if l.startswith("Integrity: "))
    out["assurance"] = next(l for l in lines if l.startswith("Assurance: "))
    out["checks"] = [[c["check"], c["status"]] for c in js["checks"]]
    return out


CASES = [
    {"name": "v1 sample", "dir": "v1", "command": "verify", "args": ["demo-run.tkb", "--key", "signer.pub"],
     "files": ["demo-run.tkb", "signer.pub"]},
    {"name": "v1 sample, unpinned", "dir": "v1", "command": "verify", "args": ["demo-run.tkb"], "files": ["demo-run.tkb"]},
    {"name": "v1 sample, tampered", "dir": "v1", "command": "verify", "args": ["demo-run-tampered.tkb", "--key", "signer.pub"],
     "files": ["demo-run-tampered.tkb", "signer.pub"]},
    {"name": "v1 multi-run export, other run elided", "dir": "v1", "command": "verify",
     "args": ["multi-run.tkb", "--key", "golden.pub", "--witness", "file:multi-run.witness.jsonl"],
     "files": ["multi-run.tkb", "golden.pub", "multi-run.witness.jsonl"]},
    {"name": "v1 external signer checkpoints", "dir": "v1", "command": "verify",
     "args": ["external-signer.tkb", "--key", "external-signer.pub"], "files": ["external-signer.tkb", "external-signer.pub"]},
    {"name": "v1 export of a ledger with a torn last line", "dir": "v1", "command": "verify",
     "args": ["torn-ledger.tkb", "--key", "golden.pub"], "files": ["torn-ledger.tkb", "golden.pub"]},
    {"name": "v0.1 ledger", "dir": "v01", "command": "migrate", "args": ["v01-ledger.jsonl"], "files": ["v01-ledger.jsonl"]},
]


def main():
    v1, v01 = os.path.join(GOLDEN, "v1"), os.path.join(GOLDEN, "v01")
    for d in (v1, v01):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for name in ("demo-run.tkb", "demo-run-tampered.tkb", "signer.pub", "demo-run-replay.html"):
        shutil.copy(os.path.join(ROOT, "docs", "sample", name), v1)
    shutil.copy(os.path.join(ROOT, "tests", "fixtures", "v01-ledger.jsonl"), v01)
    write(os.path.join(v1, "golden.pub"), crypto.public_from_secret(FILE_SECRET))
    multi_run(v1)
    external_signer(v1)
    torn_ledger(v1)
    files = {f"{d}/{n}": sha(os.path.join(GOLDEN, d, n)) for d in ("v1", "v01") for n in sorted(os.listdir(os.path.join(GOLDEN, d)))}
    cases = [{**c, "files": {n: files[f"{c['dir']}/{n}"] for n in c["files"]}, "expected": run_case(c)} for c in CASES]
    with open(os.path.join(GOLDEN, "expected.json"), "w", encoding="utf-8") as f:
        json.dump({"files": files, "cases": cases}, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
