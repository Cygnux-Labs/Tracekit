"""Regenerate the golden corpus. Run by hand only:

    python3 tests/golden/make_golden.py            v1/, v01/ and expected.json
    python3 tests/golden/make_golden.py v2         v2/ and negative/, each with its own expected.json

The v1 section copies the shipped samples, builds three extra v1 bundles with fixed keys, and records what the current
verifier says about every case. The v2 section records bundles of an in-process dev signer and a negative corpus of
bundles with one defect each. The output is frozen evidence: only rerun a section when a task says it may change."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import warnings
import zipfile

GOLDEN = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(GOLDEN))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from factories import ev, make_signer, run_start, tool_call  # noqa: E402
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
    return home, make_signer(home, mode="dev", **(extra or {}))


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


V2_ORIGIN = "tracekit.example.org/log/golden"


def v2_signer(out):
    """A dev signer (same-user, self-approval allowed) records a closed run, a self-approved run and an open run; then,
    restarted with a test witness and a test Sigstore (Rekor v2 + TSA), checkpoints them once: the note is cosigned and
    anchored. Exports each run and the tenant's run-set, and the trust configs with and without the Rekor pin."""
    from factories import wait_for
    from test_rekor_anchor import FakeSigstore
    from test_signer_service import ME, PAY_ASKS
    from test_witness_publish import NAME, VKEY, FakeWitness
    from tracekit.bundle_v2 import export
    from tracekit.format import checkpoint, registry
    from tracekit.format.canon import event_hash
    from tracekit.signer import service as svc
    from tracekit.storage.base import registry_tree
    from tracekit.tlog_witness import TlogWitness
    d = tempfile.mkdtemp(dir="/tmp")   # short: macOS caps socket paths at 104 bytes
    fake, w = FakeSigstore(), FakeWitness()
    try:
        opts = {"policy": PAY_ASKS, "grace_s": 0, "origin": V2_ORIGIN, "fail_modes": {"default": "closed", "read": "open"}}
        s = svc.SignerService(d, **opts)

        def call(method, req):
            return s.call(ME, method, {"request_id": uuid.uuid4().hex, **req})

        def run(tool, args, args_source="parsed", approve=False, close=True):
            r = call("register_run", {"agent": {"name": "golden"}})
            ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
            call_ = {"tool_call_id": "tc-1", "tool": tool, "args_source": args_source, "args": args}
            dec = call("decide", {**ids, "stream": "s1", "client_seq": 0, **call_})
            if approve:
                aid = call("approval_request", {**ids, "tool_call_id": "tc-1"})["approval_id"]
                call("approval_decide", {"approval_id": aid, "decision": "approve"})
                call("approval_consume", {**ids, **call_, "approval_id_hint": aid})
            ran = json.loads(args) if args_source == "raw" else args
            call("complete", {**ids, "stream": "s1", "client_seq": 1, "tool_call_id": "tc-1",
                              "decision_id": dec["decision_id"], "args_digest": event_hash({"tool": tool, "args": ran}),
                              "status": "ok"})
            if close:
                call("close_run", ids)
            return r["run_id"]
        runs = {"closed": run("read_file", {"path": "a.txt"}), "approval": run("pay", {"amount": 5}, approve=True),
                "open": run("read_file", '{"path": "b.txt"}', "raw", close=False)}
        s.sweep()
        s.close()
        sc, tr = fake.files(d)
        s = svc.SignerService(d, **opts, witnesses=[TlogWitness(w.url, VKEY, timeout=5)],
                              rekor={"signing_config": sc, "trusted_root": tr, "every_s": 3600})
        public = checkpoint.parse_vkey(s.vkey)[3]
        for origin in (V2_ORIGIN, registry.origin(V2_ORIGIN, s.log.tenant_salt("default"))):
            w.logs[origin] = checkpoint.vkey(origin, checkpoint.ED25519, public)
        st = s.log.storage
        s.checkpoint()

        def done():
            note, anchors = st.checkpoint_latest(), st.anchors()
            return anchors and anchors[-1]["size"] == note[0] and f"— {NAME} " in note[1] and note
        note = wait_for(done, 20)
        if not note:
            raise RuntimeError("the checkpoint was not cosigned and anchored")
        s.close()
        for name, rid in runs.items():
            export(st, "default", rid, note[1], os.path.join(out, f"{name}.tkb"))
        reg = st.checkpoint_latest(registry_tree("default"))
        export(st, "default", None, note[1], os.path.join(out, "run-set.tkb"), run_set=(0, reg[0]),
               tenant_salt=s.log.tenant_salt("default"))
        trust = {"logs": [s.vkey], "witnesses": [{"vkey": VKEY, "class": "customer"}], "algs": ["ed25519"],
                 "witnesses_required": 1}
        with open(tr, encoding="utf-8") as f:
            rekor = {"trusted_root": json.load(f), "publishing_key": svc.read_rekor_pub(d), "class": "public"}
        for name, t in (("trust.json", trust), ("trust-rekor.json", dict(trust, rekor=rekor))):
            write(os.path.join(out, name), json.dumps(t, indent=1).encode())
    finally:
        fake.stop()
        w.stop()
        shutil.rmtree(d, ignore_errors=True)


V2_CASES = [
    {"name": "v2 closed run, witnessed", "dir": "v2", "command": "verify",
     "args": ["closed.tkb", "--trust", "trust.json"], "files": ["closed.tkb", "trust.json"]},
    {"name": "v2 closed run, Rekor anchor pinned", "dir": "v2", "command": "verify",
     "args": ["closed.tkb", "--trust", "trust-rekor.json"], "files": ["closed.tkb", "trust-rekor.json"]},
    {"name": "v2 open run", "dir": "v2", "command": "verify",
     "args": ["open.tkb", "--trust", "trust.json"], "files": ["open.tkb", "trust.json"]},
    {"name": "v2 self-approved run", "dir": "v2", "command": "verify",
     "args": ["approval.tkb", "--trust", "trust.json"], "files": ["approval.tkb", "trust.json"]},
    {"name": "v2 run-set", "dir": "v2", "command": "verify",
     "args": ["run-set.tkb", "--trust", "trust.json"], "files": ["run-set.tkb", "trust.json"]},
]


def negative(out):
    """Bundles with one defect each, from a fixed-key log (tests/test_bundle_v2.Log); [(case name, bundle file)].
    Every case verifies against negative/trust.json (the log key and one pinned witness, one cosignature required)."""
    import test_bundle_v2 as tb
    from factories import rewrite_bundle
    from tracekit.bundle_v2 import export
    from tracekit.format import checkpoint
    d = tempfile.mkdtemp()
    cases, n = [], [0]

    def log(close=True):
        n[0] += 1
        lg = tb.Log(os.path.join(d, f"store{n[0]}"))
        lg.epoch(tb.KEY1)
        lg.register()
        lg.register("run-b")
        for _ in range(2):
            lg.call()
            lg.call("run-b")
        if close:
            lg.final()
        return lg

    def signed(name, file, lg, **note):
        export(lg.store, "acme", "run-a", lg.note(**note), os.path.join(out, file))
        lg.store.close()
        cases.append((name, file))

    def mutated(name, file, run=None, edit=None):
        def apply(files, manifest):
            if run:
                k = next(k for k in files if k.startswith("runs/"))
                recs = [json.loads(line) for line in files[k].splitlines()]
                run(recs)
                files[k] = b"".join(json.dumps(r).encode() + b"\n" for r in recs)
            if edit:
                edit(files, manifest)
        rewrite_bundle(good, os.path.join(out, file), apply)
        cases.append((name, file))

    def raw(name, file, entries):
        with warnings.catch_warnings(), zipfile.ZipFile(os.path.join(out, file), "w", zipfile.ZIP_DEFLATED) as z:
            warnings.simplefilter("ignore")   # zipfile warns about the duplicate entry
            for info, data in entries:
                z.writestr(info, data)
        cases.append((name, file))

    try:
        base = log()
        other = next(r for r in base.store.iter_range(0, 100) if r["event"]["run_id"] == "run-b")
        good = os.path.join(d, "good.tkb")
        export(base.store, "acme", "run-a", base.note(), good, policies=[b'{"version":"1"}'])
        base.store.close()
        with zipfile.ZipFile(good) as z:
            entries = [(i.filename, z.read(i)) for i in z.infolist()]
        manifest = dict(entries)["manifest.json"]

        # archive and JSON safety: unusable before anything is checked
        raw("zip traversal", "zip-traversal.tkb", entries + [("../evil", b"x")])
        raw("absolute entry name", "zip-absolute.tkb", entries + [("/etc/evil", b"x")])
        raw("duplicate entry", "zip-duplicate.tkb", entries + [entries[-1]])
        link = zipfile.ZipInfo("policies/link.json")
        link.external_attr = 0o120777 << 16
        raw("symlink entry", "zip-symlink.tkb", entries + [(link, b"/etc/passwd")])
        raw("oversized entry", "zip-oversized.tkb", entries + [("policies/big.json", bytes((64 << 20) + 1))])
        raw("no manifest", "zip-no-manifest.tkb", [e for e in entries if e[0] != "manifest.json"])
        raw("non-strict JSON manifest (duplicate key)", "json-manifest-duplicate-key.tkb",
            [("manifest.json", manifest[:-1] + b', "format": "tracekit.bundle.v2"}')] + entries[1:])
        mutated("non-strict JSON record (duplicate key)", "json-record-duplicate-key.tkb",
                edit=lambda f, m: f.update({k: v.replace(b'{"v":', b'{"v":2,"v":', 1)
                                            for k, v in f.items() if k.startswith("runs/")}))
        mutated("run file without its final newline", "json-no-final-newline.tkb",
                edit=lambda f, m: f.update({k: v[:-1] for k, v in f.items() if k.startswith("runs/")}))
        mutated("empty run file", "run-empty.tkb", edit=lambda f, m: f.update({k: b"" for k in f if k.startswith("runs/")}))
        mutated("format is not v2", "manifest-format-v1.tkb", edit=lambda f, m: m.update(format="tracekit.bundle.v1"))
        mutated("needs a newer verifier", "manifest-newer-verifier.tkb",
                edit=lambda f, m: m.update(verifier_min_version="99.0"))

        # the manifest is only an index
        mutated("file not in the manifest", "manifest-unlisted-file.tkb", edit=lambda f, m: f.update({"extra.txt": b"x"}))
        wrong = json.loads(manifest)
        wrong["files"][next(iter(wrong["files"]))] = "0" * 64
        raw("manifest hash wrong", "manifest-wrong-hash.tkb", [("manifest.json", json.dumps(wrong))] + entries[1:])

        # records (E1 classes, ported to v2)
        def edit(rs):
            rs[2]["event"]["data"]["name"] = "Write"

        def swap(rs):
            rs[1], rs[2] = rs[2], rs[1]

        def splice(rs):
            rs[2] = other

        def alg(rs):
            rs[1]["alg"] = "ed25519ph"

        def bad_sig(rs):
            rs[1]["sig"] = rs[2]["sig"]
        mutated("edited record", "record-edited.tkb", run=edit)
        mutated("deleted record", "record-deleted.tkb", run=lambda rs: rs.pop(2))
        mutated("swapped records", "record-swapped.tkb", run=swap)
        mutated("record from another run spliced in", "record-spliced.tkb", run=splice)
        mutated("run.final cut off", "record-truncated.tkb", run=lambda rs: rs.pop())
        mutated("signature algorithm swapped", "record-alg-confusion.tkb", run=alg)
        mutated("another record's signature", "record-bad-signature.tkb", run=bad_sig)
        mutated("signer.epoch dropped", "keys-dropped.tkb", edit=lambda f, m: f.update({"keys/records.jsonl": b""}))
        mutated("two runs without a run-set", "run-second-run.tkb",
                edit=lambda f, m: (f.update({"runs/" + "0" * 32 + ".jsonl": next(v for k, v in f.items()
                                                                                 if k.startswith("runs/"))}),
                                   m["files"].update({"runs/" + "0" * 32 + ".jsonl": ""})))
        mutated("policy snapshot under another name", "policy-misnamed.tkb",
                edit=lambda f, m: [(f.update({"policies/x.json": f.pop(k)}), m["files"].update({"policies/x.json": ""}))
                                   for k in list(f) if k.startswith("policies/")])

        # checkpoint and proofs
        def proofs(fn):
            def go(f, m):
                p = json.loads(f["proofs/records.json"])
                fn(p)
                f["proofs/records.json"] = json.dumps(p).encode()
            return go

        def zero_last(p):
            last = max(p["inclusion"], key=int)
            p["inclusion"][last][0] = "A" * 43 + "="
        def bump_size(f, m):
            k = next(k for k in f if k.startswith("checkpoints/"))
            lines = f[k].split(b"\n")
            lines[1] = b"%d" % (int(lines[1]) + 1)
            f[k] = b"\n".join(lines)
        mutated("checkpoint body edited", "checkpoint-body-edited.tkb", edit=bump_size)
        mutated("proofs name another tree size", "proofs-tree-size.tkb", edit=proofs(lambda p: p.update(tree_size=1)))
        mutated("inclusion proof altered", "proofs-inclusion-altered.tkb", edit=proofs(zero_last))
        forged = log()   # same record key, a different history, swapped in under the real checkpoint
        forged.add("tool.call", {"tool_use_id": "x", "name": "Read", "input": {}})
        forged.final()
        tmp = os.path.join(d, "forged.tkb")
        export(forged.store, "acme", "run-a", forged.note(), tmp)
        forged.store.close()
        with zipfile.ZipFile(tmp) as z:
            forged_runs = {k: z.read(k) for k in z.namelist() if k.startswith("runs/")}
        mutated("run rebuilt with the real key under the real checkpoint", "run-rebuilt.tkb",
                edit=lambda f, m: f.update(forged_runs))

        # signed by the real keys, wrong by the rules
        lg = log(close=False)
        lg.final()
        lg.call()
        signed("record after run.final", "run-record-after-final.tkb", lg)
        lg = log(close=False)
        lg.add("run.closing", {"reason": "close_run"})
        signed("run.closing without run.final (claimed closed)", "run-closing-without-final.tkb", lg)
        lg = log(close=False)
        lg.add("key.retire", {"kid": crypto.spki_kid(tb.spki(tb.KEY1)), "last_seq": lg.store.tree.size}, run="signer")
        lg.epoch(tb.KEY2)
        lg.call(key=tb.KEY2)
        lg.final()   # with the retired KEY1
        signed("key used after its key.retire", "key-used-after-retire.tkb", lg)
        lg = log()
        lg.add("tool.call", {"tool_use_id": "x"})
        lg.final()
        signed("schema-invalid event", "record-schema-invalid.tkb", lg)
        signed("checkpoint of another origin", "checkpoint-wrong-origin.tkb", log(), origin="other.example.org/log")
        signed("cosigned only by an unpinned witness", "witness-unpinned-only.tkb", log(),
               witnesses=(("rogue.example.org/w", hashlib.sha256(b"rogue").digest()),))
        signed("no cosignature", "witness-none.tkb", log(), witnesses=())
        trust = {"logs": [checkpoint.vkey(tb.ORIGIN, checkpoint.ED25519, tb.pub(tb.LOG_SECRET))],
                 "witnesses": [{"vkey": checkpoint.vkey(tb.WITNESS, checkpoint.COSIGNATURE, tb.pub(tb.WIT_SECRET)),
                                "class": "customer"}], "algs": ["ed25519"], "witnesses_required": 1}
        write(os.path.join(out, "trust.json"), json.dumps(trust, indent=1).encode())
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return cases


def negative_verdict(path, trust):
    """Exit code, integrity and the first failing check (None when none fails) of the v2 verifier, in process."""
    from tracekit.verify import v2
    rep, code = v2.verify(path, trust)
    return {"exit_code": code, "integrity": rep.integrity,
            "first_failure": next((c["check"] for c in rep.checks if c["status"] == "fail"), None)}


def write_expected(d, cases):
    names = sorted(os.listdir(os.path.join(GOLDEN, d)))
    files = {f"{d}/{n}": sha(os.path.join(GOLDEN, d, n)) for n in names}
    with open(os.path.join(GOLDEN, d, "expected.json"), "w", encoding="utf-8") as f:
        json.dump({"files": files, "cases": cases}, f, indent=2)
        f.write("\n")


def main_v2():
    v2, neg = os.path.join(GOLDEN, "v2"), os.path.join(GOLDEN, "negative")
    for d in (v2, neg):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    v2_signer(v2)
    write_expected("v2", [{**c, "files": {n: sha(os.path.join(v2, n)) for n in c["files"]}, "expected": run_case(c)}
                          for c in V2_CASES])
    trust = os.path.join(neg, "trust.json")
    write_expected("negative", [{"name": name, "bundle": file,
                                 "expected": negative_verdict(os.path.join(neg, file), trust)}
                                for name, file in negative(neg)])


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
    main_v2() if sys.argv[1:] == ["v2"] else main()
