"""Format v2: C2SP checkpoint notes, per-run bundle export and the v2 verifier (E1 mutation classes ported to v2)."""
import base64
import contextlib
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

from factories import rewrite_bundle
from tracekit import cli, crypto
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.checkpoint import COSIGNATURE, ED25519, NoteError
from tracekit.format.records import make_record
from tracekit.storage.base import ZERO_HASH
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

TESTS = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(TESTS, "vectors", "c2sp_checkpoint.json"), encoding="utf-8") as f:
    VEC = json.load(f)

ORIGIN = "tracekit.example.org/log/test"
WITNESS = "witness.example.org/w1"
OPERATOR = "ops.example.org/w"
LOG_SECRET, WIT_SECRET, OP_SECRET, KEY1, KEY2 = (hashlib.sha256(s).digest() for s in
                                                 (b"log", b"witness", b"operator", b"record-1", b"record-2"))


def pub(secret):
    return crypto.public_from_secret(secret)


def spki(secret):
    return crypto.spki(pub(secret))


def cosign(text, name, secret, ts):
    sig = struct.pack(">Q", ts) + crypto.sign(secret, f"cosignature/v1\ntime {ts}\n{text}".encode())
    blob = base64.b64encode(checkpoint.key_id(name, COSIGNATURE, pub(secret)) + sig).decode()
    return f"— {name} {blob}\n"


class Log:
    """A file store plus the chain state to append signed v2 records to it."""

    def __init__(self, root, key=KEY1):
        self.store, self.key, self.prev, self.runs = FileStorage(root), key, ZERO_HASH, {}

    def add(self, type_, data, run="run-a", key=None):
        seq = self.store.tree.size
        run_seq, run_prev = self.runs.get(run, (0, ZERO_HASH))
        e = {"schema_version": "tracekit.event.v2", "id": f"{seq:032x}", "seq": seq, "prev_hash": self.prev,
             "ts": "2026-10-09T12:00:00.000000Z", "run_id": run, "agent_id": "main", "parent_id": None,
             "source": "signer", "type": type_, "data": data, "tenant": "acme", "log_id": "0" * 32,
             "run_seq": run_seq, "run_prev_hash": run_prev}
        r = make_record(e, key or self.key)
        self.store.append_batch([r])
        self.prev, self.runs[run] = r["hash"], (run_seq + 1, r["hash"])
        return r

    def epoch(self, secret):
        der = crypto.spki(pub(secret))
        return self.add("signer.epoch", {"keys": [{"kid": crypto.spki_kid(der), "alg": "ed25519",
                                                   "spki": base64.b64encode(der).decode()}]}, run="signer", key=secret)

    def call(self, run="run-a", key=None):
        return self.add("tool.call", {"tool_use_id": f"t{self.store.tree.size}", "name": "Bash", "input": {}}, run, key)

    def register(self, run="run-a"):
        return self.add("run.registered", {"agent": {"name": "agent"},
                                           "identity": {"scheme": "token", "subject": "svc", "attested": True}}, run)

    def final(self, run="run-a"):
        n, head = self.runs[run]
        return self.add("run.final", {"head_run_seq": n - 1, "head_hash": head}, run)

    def note(self, origin=ORIGIN, log_secret=LOG_SECRET, witnesses=((WITNESS, WIT_SECRET),)):
        size = self.store.tree.size
        text = checkpoint.body(origin, size, self.store.tree.root_at(size))
        return (text + "\n" + checkpoint.sign(text, origin, log_secret)
                + "".join(cosign(text, n, s, 1760000000 + i) for i, (n, s) in enumerate(witnesses)))


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.trust = self.write_trust()

    def write_trust(self, witnesses_required=1, algs=("ed25519",), name="trust.json"):
        t = {"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))],
             "witnesses": [{"vkey": checkpoint.vkey(WITNESS, COSIGNATURE, pub(WIT_SECRET)), "class": "customer"},
                           {"vkey": checkpoint.vkey(OPERATOR, COSIGNATURE, pub(OP_SECRET)), "class": "operator"}],
             "algs": list(algs), "witnesses_required": witnesses_required}
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            json.dump(t, f)
        return p

    def log(self, name="store", key=KEY1):
        log = Log(os.path.join(self.d, name), key)
        self.addCleanup(log.store.close)
        return log

    def honest(self, close=True):
        """Run run-a interleaved with run-b; returns (log, bundle path)."""
        log = self.log()
        log.epoch(KEY1)
        log.register()
        log.register("run-b")
        for _ in range(3):
            log.call()
            log.call("run-b")
        if close:
            log.final()
        out = os.path.join(self.d, "a.tkb")
        export(log.store, "acme", "run-a", log.note(), out, policies=[b'{"version":"1"}'])
        return log, out

    def verify(self, path, trust=None):
        rep, code = v2.verify(path, trust or self.trust)
        return rep, code

    def assert_fails(self, path, check, trust=None):
        rep, code = self.verify(path, trust)
        self.assertEqual(code, 1, rep.checks)
        self.assertEqual(rep.integrity, "FAILED")
        self.assertIn(check, rep.failures)

    def mutate(self, src, edit_run=None, edit=None):
        """Rewrite a bundle; `edit_run(records)` edits the run's record list in place."""
        out = os.path.join(self.d, f"m{random.random()}.tkb")

        def apply(files, manifest):
            if edit_run:
                name = next(n for n in files if n.startswith("runs/"))
                records = [json.loads(line) for line in files[name].splitlines()]
                edit_run(records)
                files[name] = b"".join(json.dumps(r).encode() + b"\n" for r in records)
            if edit:
                edit(files, manifest)
        rewrite_bundle(src, out, apply)
        return out


class TestCheckpointNotes(unittest.TestCase):
    def test_vector_signed_here_byte_for_byte(self):
        seed = base64.b64decode(VEC["log_skey"].split("+", 4)[4])[1:]
        origin = VEC["text"].split("\n")[0]
        self.assertEqual(checkpoint.vkey(origin, ED25519, pub(seed)), VEC["log_vkey"])
        self.assertEqual(VEC["text"] + "\n" + checkpoint.sign(VEC["text"], origin, seed),
                         VEC["note"][:VEC["note"].index(f"— {WITNESS}")])

    def test_vectors_verify_and_unknown_lines_are_ignored(self):
        for note in (VEC["note"], VEC["hybrid"]):
            origin, size, root, cosigs = checkpoint.open_note(note, [VEC["log_vkey"]], [VEC["wit_vkey"]])
            self.assertEqual((size, len(root), cosigs), (13, 32, [(VEC["wit_vkey"], 1760000000)]))
            self.assertEqual(checkpoint.body(origin, size, root), VEC["text"])
        # the witness is unpinned: its line is ignored, the log signature still holds
        self.assertEqual(checkpoint.open_note(VEC["hybrid"], [VEC["log_vkey"]])[3], [])

    def test_vkey_base64_with_plus(self):
        self.assertIn("+", VEC["wit_vkey"].split("+", 2)[2])
        self.assertEqual(checkpoint.parse_vkey(VEC["wit_vkey"])[0], WITNESS)

    def test_rejections(self):
        note, log, wit = VEC["note"], [VEC["log_vkey"]], [VEC["wit_vkey"]]
        sig = note.split("\n")[4].split(" ")[2]
        bad_sig = base64.b64encode(base64.b64decode(sig)[:-1] + b"\0").decode()
        wsig = note.split("\n")[5].split(" ")[2]
        bad_wsig = base64.b64encode(base64.b64decode(wsig)[:-1] + b"\0").decode()
        cases = {
            "pinned log key's bad signature": (note.replace(sig, bad_sig), log, wit),
            "pinned witness's bad cosignature": (note.replace(wsig, bad_wsig), log, wit),
            "no pinned log key": (note, [], wit),
            "changed body": (note.replace("\n13\n", "\n14\n"), log, wit),
            "non-canonical base64": (note.replace(sig, sig[:-2] + "V="), log, wit),
            "duplicate signature": (note + note.split("\n\n")[1].split("\n")[0] + "\n", log, wit),
            "extension line": (note.replace("=\n\n", "=\next\n\n"), log, wit),
            "witness pinned as a log key": (note, log + wit, []),
        }
        for why, (n, lk, wk) in cases.items():
            with self.subTest(why), self.assertRaises(NoteError):
                checkpoint.open_note(n, lk, wk)

    def test_wrong_origin(self):
        other = "other.example.org/log"
        text = checkpoint.body(other, 1, b"\0" * 32)
        note = text + "\n" + checkpoint.sign(text, other, LOG_SECRET)
        with self.assertRaisesRegex(NoteError, "pinned log key"):
            checkpoint.open_note(note, [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))])


class TestVerifyV2(Case):
    def test_honest_bundle_verifies(self):
        _, out = self.honest()
        rep, code = self.verify(out)
        self.assertEqual((code, rep.failures, rep.integrity), (0, [], "VERIFIED"), rep.checks)
        self.assertEqual(rep.assurance, f"witnessed; records ed25519; checkpoint ed25519 ({ORIGIN}); cosigned ed25519 "
                                        f"by {WITNESS} (customer) at 2025-10-09T08:53:20Z; key retirements not proven "
                                        "complete")
        self.assertEqual(rep.warnings, ["keys"])   # one run, no run-set: a withheld key.retire would not show
        with zipfile.ZipFile(out) as z:
            names = set(z.namelist())
        self.assertFalse({n for n in names if n.endswith((".html", ".py", ".js"))})

    def test_open_run_verifies_to_head(self):
        _, out = self.honest(close=False)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED TO HEAD 3 (open)"), rep.checks)

    def test_assurance_levels(self):
        log = self.log()
        log.epoch(KEY1)
        log.register()
        log.final()
        for witnesses, level in (((), "dev"), (((OPERATOR, OP_SECRET),), "local")):
            out = os.path.join(self.d, f"{level}.tkb")
            export(log.store, "acme", "run-a", log.note(witnesses=witnesses), out)
            rep, code = self.verify(out, self.write_trust(witnesses_required=0, name="t0.json"))
            self.assertEqual(code, 0, rep.checks)
            self.assertTrue(rep.assurance.startswith(level + ";"), rep.assurance)
        # the default trust config requires one pinned cosignature
        self.assert_fails(os.path.join(self.d, "dev.tkb"), "witness quorum")

    def test_e1_mutations_fail(self):
        log, out = self.honest()
        other = next(r for r in log.store.iter_range(0, 100) if r["event"]["run_id"] == "run-b"
                     and r["event"]["run_seq"] == 2)

        def edit(rs):
            rs[2]["event"]["data"]["name"] = "Write"

        def delete(rs):
            del rs[2]

        def reorder(rs):
            rs[1], rs[2] = rs[2], rs[1]

        def splice(rs):
            rs[2] = other

        def truncate(rs):
            del rs[-1]

        def alg(rs):
            rs[1]["alg"] = "ed25519ph"
        cases = {"edit": (edit, "signatures"), "delete": (delete, "run chain"), "reorder": (reorder, "run chain"),
                 "splice from another run": (splice, "run chain"), "truncation": (truncate, "inclusion"),
                 "alg confusion": (alg, "signatures")}
        for why, (fn, check) in cases.items():
            with self.subTest(why):
                self.assert_fails(self.mutate(out, fn), check)
        with self.subTest("record alg not pinned by the verifier"):
            self.assert_fails(out, "signatures", self.write_trust(algs=("ed448",), name="t2.json"))

    def test_rebuilt_chain_with_the_real_key_fails(self):
        _, out = self.honest()
        forged = self.log("forged")  # same record key, a different history
        forged.epoch(KEY1)
        forged.register()
        forged.register("run-b")
        for _ in range(3):
            forged.add("tool.call", {"tool_use_id": "x", "name": "Read", "input": {}})
            forged.call("run-b")
        forged.final()
        tmp = os.path.join(self.d, "forged.tkb")
        export(forged.store, "acme", "run-a", forged.note(witnesses=()), tmp)
        with zipfile.ZipFile(tmp) as z:
            forged_runs = {n: z.read(n) for n in z.namelist() if n.startswith("runs/")}
        with self.subTest("against the real witnessed checkpoint"):
            self.assert_fails(self.mutate(out, edit=lambda files, m: files.update(forged_runs)), "inclusion")
        with self.subTest("with its own log-signed checkpoint that no witness cosigned"):
            self.assert_fails(tmp, "witness quorum")

    def test_wrong_origin_fails(self):
        log = self.log()
        log.epoch(KEY1)
        log.register()
        log.final()
        out = os.path.join(self.d, "o.tkb")
        export(log.store, "acme", "run-a", log.note(origin="other.example.org/log"), out)
        self.assert_fails(out, "checkpoint")

    def test_keys_valid_by_position(self):
        log = self.log()
        log.epoch(KEY1)
        log.register()
        log.call()
        log.add("key.retire", {"kid": crypto.spki_kid(spki(KEY1)), "last_seq": log.store.tree.size},
                run="signer", key=KEY1)
        log.epoch(KEY2)
        log.call(key=KEY2)
        log.final()  # signed with the retired KEY1
        out = os.path.join(self.d, "k.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, _ = self.verify(out)
        self.assertEqual(rep.failures, ["signatures"], rep.checks)
        self.assertIn("unknown kid", str(rep.checks))

        log.key = KEY2
        log.register("run-d")
        log.call("run-d")
        log.final("run-d")
        export(log.store, "acme", "run-d", log.note(), out)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)

    def test_manifest_is_only_an_index(self):
        _, out = self.honest()
        self.assert_fails(self.mutate(out, edit=lambda files, m: files.update({"policies/x.json": b"{}"})), "manifest")

    def test_newer_bundle_is_unverifiable(self):
        _, out = self.honest()
        rep, code = self.verify(self.mutate(out, edit=lambda f, m: m.update(verifier_min_version="99.0")))
        self.assertEqual((code, rep.integrity), (2, "UNVERIFIABLE (needs tracekit >= 99.0)"))
        for bad in ("99.0\x1b[2J", "1.2.3.4", "v1", "", 4):
            with self.subTest(bad):
                rep, code = self.verify(self.mutate(out, edit=lambda f, m: m.update(verifier_min_version=bad)))
                self.assertEqual((code, rep.integrity), (2, "UNUSABLE BUNDLE"))
                self.assertNotIn("99.0", str(rep.checks))

    def test_report_drops_control_characters(self):
        rep, esc = v2.Report(), "a\x1b]0;x\x07\x1b[2J\x9bb\nc"
        rep.check("break-glass approvals", False, esc, [esc], warn=True)
        rep.integrity, rep.assurance = "FAILED", esc
        buf = io.StringIO()
        v2.print_report(rep, 1, buf)
        self.assertEqual(buf.getvalue().count("a]0;x[2Jbc"), 3)
        self.assertNotRegex(buf.getvalue(), r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return cli.main(["verify", *args]), out.getvalue(), err.getvalue()

    def test_cli_dispatches_on_format(self):
        _, out = self.honest()
        code, stdout, _ = self.cli(out, "--trust", self.trust)
        self.assertEqual(code, 0)
        self.assertIn("Integrity: VERIFIED.\nAssurance: witnessed;", stdout)
        self.assertEqual(self.cli(out)[0], 2)
        self.assertEqual(self.cli(out, "--trust", self.trust, "--strict")[0], 3)   # the keys warning

    def test_cli_refuses_flags_of_the_other_format(self):
        _, out = self.honest()
        v1 = os.path.join(os.path.dirname(TESTS), "docs", "sample", "demo-run.tkb")
        pubf = os.path.join(os.path.dirname(TESTS), "docs", "sample", "signer.pub")
        cases = {
            "--trust with a v1 bundle": (v1, "--trust", self.trust),
            "--v1-ledger with a v1 bundle": (v1, "--v1-ledger", pubf, "--v1-key", pubf),
            "--key with a v2 bundle": (out, "--trust", self.trust, "--key", pubf),
            "--witness with a v2 bundle": (out, "--trust", self.trust, "--witness", "file:/nonexistent"),
        }
        for why, args in cases.items():
            with self.subTest(why):
                code, stdout, err = self.cli(*args)
                self.assertEqual((code, stdout), (2, ""), err)
        with self.subTest("a manifest that is not v2 is refused under --trust"):
            code, stdout, _ = self.cli(self.mutate(out, edit=lambda f, m: m.update(format="tracekit.bundle.v1")),
                                       "--trust", self.trust)
            self.assertEqual((code, stdout), (2, ""))

    def test_v1_verify_needs_only_the_standard_library(self):
        v1 = os.path.join(os.path.dirname(TESTS), "docs", "sample", "demo-run.tkb")
        code = ("import sys; sys.modules['rfc8785'] = None\n"
                "from tracekit import cli\n"
                f"sys.exit(cli.main(['verify', {v1!r}]))")
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           cwd=os.path.dirname(TESTS))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("VERIFIED", p.stdout)


class TestMalformedInput(Case):
    def zip(self, entries, name="z.tkb"):
        p = os.path.join(self.d, name)
        with zipfile.ZipFile(p, "w") as z:
            for info, data in entries:
                z.writestr(info, data)
        return p

    def assert_unusable(self, path):
        rep, code = self.verify(path)
        self.assertEqual(code, 2, rep.checks)

    def test_unsafe_archives_are_refused(self):
        link = zipfile.ZipInfo("keys/records.jsonl")
        link.external_attr = 0o120777 << 16
        m = json.dumps({"format": "tracekit.bundle.v2", "verifier_min_version": "0.3.0", "files": {}})
        cases = {
            "traversal": [("manifest.json", m), ("../evil", "x")],
            "absolute": [("manifest.json", m), ("/etc/x", "x")],
            "backslash": [("manifest.json", m), ("runs\\..\\x", "x")],
            "symlink": [("manifest.json", m), (link, "/etc/passwd")],
            "duplicate": [("manifest.json", m), ("manifest.json", m)],
            "duplicate keys": [("manifest.json", '{"format": "tracekit.bundle.v2", "format": 1}')],
            "no manifest": [("runs/x.jsonl", "")],
        }
        for why, entries in cases.items():
            with self.subTest(why), mock.patch("warnings.warn"):
                self.assert_unusable(self.zip(entries, why.replace(" ", "_") + ".tkb"))
        with self.subTest("too large"), mock.patch.object(v2, "MAX_ENTRY", 10):
            self.assert_unusable(self.zip([("manifest.json", m)]))

    def test_corrupted_bytes_never_crash(self):
        _, out = self.honest()
        with open(out, "rb") as f:
            good = f.read()
        rnd = random.Random(7)
        bad = os.path.join(self.d, "bad.tkb")
        for i in range(150):
            data = bytearray(good)
            if i % 3 == 0:
                data = data[:rnd.randrange(len(data))]
            else:
                for _ in range(rnd.randint(1, 4)):
                    data[rnd.randrange(len(data))] ^= 1 << rnd.randrange(8)
            with open(bad, "wb") as f:
                f.write(data)
            rep, code = self.verify(bad)
            self.assertIn(code, (0, 1, 2))
            if code == 0:
                self.assertEqual(rep.failures, [])

    def test_malformed_content_never_crashes(self):
        _, out = self.honest()
        junk = [b"", b"\n", b"null\n", b"[]\n", b'{"v":2}\n', b"\xff\n", b'{"a":1,"a":2}\n', b"1e400\n"]
        for name in ("keys/records.jsonl", "proofs/records.json", "runs/", "checkpoints/"):
            for j in junk:
                def edit(files, manifest, name=name, j=j):
                    files[next(n for n in files if n.startswith(name))] = j
                with self.subTest(name=name, junk=j):
                    rep, code = self.verify(self.mutate(out, edit=edit))
                    self.assertEqual(code, 1, rep.checks)


if __name__ == "__main__":
    unittest.main()
