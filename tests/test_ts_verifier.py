"""Agreement of the two v2 verifiers: the reference (tracekit/verify/v2.py) and the independent TypeScript one
(sdk/typescript/src/verify, written from docs/format-v2.md). Bundles from the real signer (honest runs: dev, witnessed,
with a gap, with an approval, a run-set; and mutated copies) and the golden corpus go through both, which must agree on
integrity, assurance, exit code and every check's name and status. Skipped without Node >= 20 or a TypeScript build
(`make test-ts` builds it; the TypeScript suite runs this file too)."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, TESTS)
from factories import rewrite_bundle  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.demo_server import Witness  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.format.records import make_record  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.storage.base import registry_tree  # noqa: E402
from tracekit.tlog_witness import signed_by  # noqa: E402
from tracekit.verify import v2  # noqa: E402

TS = os.path.join(ROOT, "sdk", "typescript")
CLI = os.path.join(TS, "bin", "tracekit.mjs")
TSC = os.path.join(TS, "node_modules", "typescript", "bin", "tsc")
ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


def _node():
    """Why the TypeScript verifier can't run here, or None; builds it when the compiler is installed."""
    node = shutil.which("node")
    if not node:
        return "needs node"
    v = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v").split(".")[:2]
    if not all(x.isdigit() for x in v) or tuple(map(int, v)) < (20, 12):   # JSON imports and deflate-raw
        return "needs node >= 20.12"
    return None if os.path.exists(TSC) or os.path.exists(os.path.join(TS, "dist", "verify", "cli.js")) else \
        "needs the TypeScript build (make test-ts)"


def _build():
    """Compile the TypeScript (a compile error fails the tests that need it, not the whole suite's collection)."""
    if os.path.exists(TSC):
        subprocess.run(["node", TSC, "-p", TS], check=True)


SKIP = _node()


def ts_verify(bundle, trust):
    p = subprocess.run(["node", CLI, "verify", bundle, "--trust", trust, "--json"], capture_output=True, text=True)
    out = json.loads(p.stdout)
    assert out["exit_code"] == p.returncode, p
    return out


@unittest.skipIf(SKIP, SKIP)
class Agreement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _build()
        cls.d = d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)
        cls.addClassCleanup(shutil.rmtree, d, True)
        witness = Witness()
        s = svc.SignerService(os.path.join(d, "data"), policy=Engine({"ask": [{"id": "PAY", "tool": "pay", "pattern": "^"}]}),
                              witnesses=[witness], isolation="same-user", grace_s=0, fsck_every_s=0,
                              fail_modes={"default": "closed", "read": "open"})
        try:
            runs = {"closed": cls.record_run(s, "read_file"), "approval": cls.record_run(s, "pay", approve=True),
                    "gap": cls.record_run(s, "read_file", skip=True), "open": cls.record_run(s, "read_file", close=False)}
            s.sweep()
            store = s.log.storage

            def cosigned():
                s.checkpoint()
                size, note = store.checkpoint_latest()
                return size == store.tree.size and signed_by(note.split("\n\n", 1)[1], witness.vkey) and note
            deadline = time.monotonic() + 20
            while not (note := cosigned()):
                if time.monotonic() > deadline:
                    raise TimeoutError("no cosigned checkpoint")
                time.sleep(0.1)
            cls.bundles = {}
            for name, rid in runs.items():
                cls.bundles[name] = os.path.join(d, f"{name}.tkb")
                export(store, "default", rid, note, cls.bundles[name])
            cls.bundles["run-set"] = os.path.join(d, "run-set.tkb")
            reg = store.checkpoint_latest(registry_tree("default"))
            export(store, "default", None, note, cls.bundles["run-set"], run_set=(0, reg[0]),
                   tenant_salt=s.log.tenant_salt("default"))
            with open(os.path.join(d, "data", "keys", "record.key"), "rb") as f:
                cls.record_key = f.read()
            log_vkey = s.vkey
        finally:
            s.close()
        cls.trusts = {}
        for name, witnesses, required in (("witnessed", [(witness.vkey, "customer")], 1), ("dev", [], 0),
                                          ("below-quorum", [(witness.vkey, "customer")], 2),
                                          ("operator", [(witness.vkey, "operator")], 1)):
            cls.trusts[name] = os.path.join(d, f"trust-{name}.json")
            with open(cls.trusts[name], "w") as f:
                json.dump({"logs": [log_vkey], "witnesses": [{"vkey": k, "class": c} for k, c in witnesses],
                           "algs": ["ed25519"], "witnesses_required": required}, f)

    @staticmethod
    def record_run(s, tool, approve=False, skip=False, close=True):
        def call(method, req):
            return s.call(ME, method, {"request_id": uuid.uuid4().hex, **req})
        r = call("register_run", {"agent": {"name": "agreement"}})
        ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
        args = {"path": "a.txt"} if tool == "read_file" else {"amount": 5}
        dec = call("decide", {**ids, "stream": "s1", "client_seq": 0, "tool_call_id": "tc-1", "tool": tool,
                              "args_source": "parsed", "args": args})
        if approve:
            aid = call("approval_request", {**ids, "tool_call_id": "tc-1"})["approval_id"]
            call("approval_decide", {"approval_id": aid, "decision": "approve"})
            call("approval_consume", {**ids, "tool_call_id": "tc-1", "tool": tool, "args_source": "parsed", "args": args,
                                      "approval_id_hint": aid})
        call("complete", {**ids, "stream": "s1", "client_seq": 2 if skip else 1, "tool_call_id": "tc-1",
                          "decision_id": dec["decision_id"], "args_digest": event_hash({"tool": tool, "args": args}),
                          "status": "ok"})
        if close:
            call("close_run", ids)
        return r["run_id"]

    def agree(self, bundle, trust):
        rep, code = v2.verify(bundle, trust)
        ts = ts_verify(bundle, trust)
        self.assertEqual((ts["exit_code"], ts["integrity"], ts["assurance"]), (code, rep.integrity, rep.assurance))
        self.assertEqual([(c["check"], c["status"]) for c in ts["checks"]], [(c["check"], c["status"]) for c in rep.checks])
        return code, rep

    def mutate(self, edit_run=None, edit=None, src="closed"):
        out = os.path.join(self.d, f"m-{uuid.uuid4().hex}.tkb")

        def apply(files, manifest):
            if edit_run:
                name = next(n for n in files if n.startswith("runs/"))
                records = [json.loads(line) for line in files[name].splitlines()]
                edit_run(records)
                files[name] = b"".join(json.dumps(r).encode() + b"\n" for r in records)
            if edit:
                edit(files, manifest)
        rewrite_bundle(self.bundles[src], out, apply)
        return out

    def test_honest_bundles(self):
        for name, bundle in self.bundles.items():
            for trust in ("witnessed", "dev", "operator"):
                with self.subTest(bundle=name, trust=trust):
                    self.assertEqual(self.agree(bundle, self.trusts[trust])[0], 0)
        with zipfile.ZipFile(self.bundles["gap"]) as z:
            self.assertIn(b'"type":"capture.gap"', z.read(next(n for n in z.namelist() if n.startswith("runs/"))))

    def test_mutations(self):
        def resign(i, change):
            def go(rs):
                change(rs[i]["event"])
                rs[i] = make_record(rs[i]["event"], self.record_key)
            return go

        def manifest(change):
            return lambda files, m: change(m)

        def drop_cosignatures(files, m):
            k = next(k for k in files if k.startswith("checkpoints/"))
            text, sigs = files[k].split(b"\n\n")
            files[k] = text + b"\n\n" + sigs.split(b"\n")[0] + b"\n"

        def forge_proof(files, m):
            p = json.loads(files["proofs/records.json"])
            p["inclusion"][max(p["inclusion"], key=int)][0] = base64.b64encode(bytes(32)).decode()
            files["proofs/records.json"] = json.dumps(p).encode()
        other = os.urandom(32)
        cases = {
            "edited record": (1, dict(edit_run=lambda rs: rs[1]["event"].update(tool="write_file"))),
            "dropped record": (1, dict(edit_run=lambda rs: rs.pop(1))),
            "reordered records": (1, dict(edit_run=lambda rs: rs.insert(1, rs.pop(2)))),
            "swapped signature": (1, dict(edit_run=lambda rs: rs[1].update(sig=rs[2]["sig"]))),
            "wrong key": (1, dict(edit_run=lambda rs: rs.__setitem__(1, make_record(rs[1]["event"], other)))),
            "schema-invalid field, re-signed": (1, dict(edit_run=resign(-1, lambda e: e.update(extra=1)))),
            "integer written as a float": (1, dict(edit_run=lambda rs: rs[1]["event"].update(run_seq=1.0))),
            "missing witness cosignature": (1, dict(edit=drop_cosignatures)),
            "forged inclusion proof": (1, dict(edit=forge_proof)),
            "newer verifier_min_version": (2, dict(edit=manifest(lambda m: m.update(verifier_min_version="9.0")))),
            "older verifier_min_version": (0, dict(edit=manifest(lambda m: m.update(verifier_min_version="0.4")))),
        }
        for name, (code, how) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.agree(self.mutate(**how), self.trusts["witnessed"])[0], code)
        with self.subTest("below quorum"):
            self.assertEqual(self.agree(self.bundles["closed"], self.trusts["below-quorum"])[0], 1)
        with self.subTest("bad manifest hash"):
            bad = os.path.join(self.d, "bad-manifest.tkb")
            with zipfile.ZipFile(self.bundles["closed"]) as z, zipfile.ZipFile(bad, "w") as out:
                for i in z.infolist():
                    data = z.read(i)
                    if i.filename == "manifest.json":
                        m = json.loads(data)
                        m["files"]["keys/records.jsonl"] = "0" * 64
                        data = json.dumps(m).encode()
                    out.writestr(i.filename, data)
            self.assertEqual(self.agree(bad, self.trusts["witnessed"])[0], 1)

    def test_golden_corpus(self):
        golden = os.path.join(TESTS, "golden")
        for d in ("v2", "negative"):
            trust = os.path.join(golden, d, "trust.json")
            for name in sorted(os.listdir(os.path.join(golden, d))):
                if name.endswith(".tkb"):
                    with self.subTest(f"{d}/{name}"):
                        self.agree(os.path.join(golden, d, name), trust)

    def test_unimplemented_checks_are_unverifiable(self):
        golden = os.path.join(TESTS, "golden", "v2")
        ts = ts_verify(os.path.join(golden, "closed.tkb"), os.path.join(golden, "trust-rekor.json"))
        self.assertEqual((ts["exit_code"], ts["integrity"]), (2, "UNVERIFIABLE (not checked by this verifier: rekor anchor)"))
        # a pinned hybrid SLH-DSA key of the origin: a note without its line fails in both
        with open(os.path.join(TESTS, "vectors", "slh_dsa_note.json"), encoding="utf-8") as f:
            slh = checkpoint.parse_vkey(json.load(f)["slh_vkey"])
        with open(os.path.join(golden, "trust.json"), encoding="utf-8") as f:
            t = json.load(f)
        trust = os.path.join(self.d, "trust-hybrid.json")
        with open(trust, "w") as f:
            json.dump({**t, "logs": t["logs"] + [checkpoint.vkey(checkpoint.parse_vkey(t["logs"][0])[0], *slh[2:])]}, f)
        self.assertEqual(self.agree(os.path.join(golden, "closed.tkb"), trust)[0], 1)

if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(SKIP, SKIP)
class Primitives(unittest.TestCase):
    def test_consistency_proofs_agree_with_the_reference(self):
        """RFC 9162 consistency proofs for every first < second <= 33 (run-sets past registry size 0 use them), plus a
        tampered proof and a wrong first root for each, through the TypeScript verifyConsistency."""
        from tracekit import merkle
        _build()
        b64 = lambda b: base64.b64encode(b).decode()   # noqa: E731
        cases = []
        for n in range(2, 34):
            leaves = [merkle.leaf_hash(bytes([i])) for i in range(n)]
            for m in range(1, n):
                proof, r1, r2 = merkle.consistency_proof(m, leaves), merkle.root(leaves[:m]), merkle.root(leaves)
                bad = [bytes([proof[0][0] ^ 1]) + proof[0][1:]] + proof[1:] if proof else proof
                for p_, first, want in ((proof, r1, True), (bad, r1, not proof), (proof, r2 if m != n else r1, False)):
                    cases.append({"m": m, "n": n, "r1": b64(first), "r2": b64(r2), "proof": [b64(x) for x in p_],
                                  "want": want and merkle.verify_consistency(m, n, first, r2, p_)})
        script = ("import { verifyConsistency } from %s;\n"
                  "const d = (s) => Uint8Array.from(Buffer.from(s, 'base64'));\n"
                  "const cases = JSON.parse(require_stdin());\n" % json.dumps(
                      "file://" + os.path.join(TS, "dist", "verify", "primitives.js").replace(os.sep, "/")))
        script = script.replace("require_stdin()", "(await new Response(process.stdin).text())")
        script += ("const out = [];\nfor (const c of cases) out.push(await verifyConsistency(c.m, c.n, d(c.r1), d(c.r2), "
                   "c.proof.map(d)));\nconsole.log(JSON.stringify(out));\n")
        p = subprocess.run(["node", "--input-type=module", "-e", script], input=json.dumps(cases), capture_output=True,
                           text=True, check=True)
        self.assertEqual(json.loads(p.stdout), [c["want"] for c in cases])

    def test_the_schema_copy_is_the_schema(self):
        """The TypeScript verifier carries a copy of the v2 event schema (browsers can't read the Python package)."""
        with open(os.path.join(ROOT, "tracekit", "schema", "tracekit.event.v2.json"), "rb") as a, \
                open(os.path.join(TS, "src", "verify", "tracekit.event.v2.json"), "rb") as b:
            self.assertEqual(json.loads(a.read()), json.loads(b.read()))
