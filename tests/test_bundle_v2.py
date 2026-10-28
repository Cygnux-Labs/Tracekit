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
import time
import unittest
import zipfile
from unittest import mock


from factories import rewrite_bundle, unverified_bundles
from tracekit import cli, crypto
from tracekit.bundle_v2 import VERIFIER_MIN_VERSION, VERSIONS, export, needs, run_name
from tracekit.format import checkpoint
from tracekit.format.canon import canonical
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

    def add(self, type_, data, run="run-a", key=None, **fields):
        seq = self.store.tree.size
        run_seq, run_prev = self.runs.get(run, (0, ZERO_HASH))
        e = {"schema_version": "tracekit.event.v2", "id": f"{seq:032x}", "seq": seq, "prev_hash": self.prev,
             "ts": "2026-10-09T12:00:00.000000Z", "run_id": run, "agent_id": "main", "parent_id": None,
             "source": "signer", "type": type_, "data": data, "tenant": "acme", "log_id": "0" * 32,
             "run_seq": run_seq, "run_prev_hash": run_prev, **fields}
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


def trust_config(witnesses_required=1, algs=("ed25519",)):
    return {"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))],
            "witnesses": [{"vkey": checkpoint.vkey(WITNESS, COSIGNATURE, pub(WIT_SECRET)), "class": "customer"},
                          {"vkey": checkpoint.vkey(OPERATOR, COSIGNATURE, pub(OP_SECRET)), "class": "operator"}],
            "algs": list(algs), "witnesses_required": witnesses_required}


def tiers_bundle(log, out):
    """Export to `out` a run of four calls: decided and completed by a gateway (T2); decided by it and completed by
    the run's client, which the signer refuses; decided by it, its result imported (T3); decided in process, with
    another system's view of it imported (T3); and a signer gap for a call a gateway held that got no result."""
    log.epoch(KEY1)
    log.register()
    gw = {"source": "gateway", "tier": "T2"}
    for tcid, result in (("t2", gw), ("hijacked", {"source": "sdk"}), ("imported", {"source": "import", "tier": "T3"})):
        log.add("policy.decision", {"tool_use_id": tcid, "decision": "allow", "rule_ids": [], "via": "uid:10012"},
                tool_call_id=tcid, **gw)
        log.add("tool.result", {"tool_use_id": tcid, "ok": True, "output": OUTPUT}, tool_call_id=tcid, **result)
    log.add("policy.decision", {"tool_use_id": "t1", "decision": "allow", "rule_ids": []}, tool_call_id="t1", source="sdk")
    log.add("policy.external", {"system": "opa", "decision": "allow", "tool_use_id": "t1", "tool": "pay", "rule_ids": [],
                                "signature": "unverified", "salt_id": "a" * 32,
                                "record": {"hash": "hmac-sha256:" + "0" * 64, "size": 2},
                                "identity": {"scheme": "token", "subject": "opa", "attested": True}},
            tool_call_id="t1", source="import", tier="T3")
    log.add("capture.gap", {"kind": "held_call_unresolved", "tool_use_id": "t9",
                            "reason": "uid:10012 decided t9 for token:agent and recorded no result before the run ended"},
            tool_call_id="t9")
    log.final()
    export(log.store, "acme", "run-a", log.note(), out)
    return out


def gaps_bundle(log, out):
    """Export to `out` a run that declares a fail-open class and holds signer records a person must read: a checkpoint
    edited between pause and resume (state_tamper) and the refused consume it caused (approval.binding_mismatch), calls
    the client numbered that never arrived (client_counter_gap: a fail-open class ran while the signer was down), and
    an informational gap (approval_expired)."""
    log.epoch(KEY1)
    log.add("run.registered", {"agent": {"name": "agent"}, "identity": {"scheme": "uid", "subject": "1", "attested": True},
                               "fail_modes": {"default": "closed", "browser": "open"}})
    log.add("capture.gap", {"kind": "client_counter_gap", "missed_events": 2, "reason": "stream s skipped client_seq 1..2"},
            stream="s")
    log.add("capture.gap", {"kind": "state_tamper", "reason": "state langgraph:t changed between writes"})
    log.add("approval.binding_mismatch", {"approval_id": "apr-1", "tool_use_id": "tc-1", "salt_id": "a" * 32,
                                          "approved_commitment": "hmac-sha256:" + "1" * 64,
                                          "args_commitment": "hmac-sha256:" + "2" * 64}, tool_call_id="tc-1")
    log.add("capture.gap", {"kind": "approval_expired", "reason": "approval apr-2 expired"})
    log.final()
    export(log.store, "acme", "run-a", log.note(), out)
    return out


NOTE = {"acme.note": {"seen": [1, "x"], "by": None}}


def ext_bundle(log, out, field=NOTE, record=("acme.note", {"detail": {"k": "v"}})):
    """Export to `out` a run whose tool call carries the ext field `field` and that holds an `ext` record (name, other
    data): format 1.4's non-critical slot."""
    log.epoch(KEY1)
    log.register()
    log.add("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}, ext=field)
    log.add("ext", {"name": record[0], **record[1]})
    log.final()
    export(log.store, "acme", "run-a", log.note(), out)
    return out


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.trust = self.write_trust()

    def write_trust(self, witnesses_required=1, algs=("ed25519",), name="trust.json"):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            json.dump(trust_config(witnesses_required, algs), f)
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
        export(log.store, "acme", "run-a", log.note(), out)
        return log, out

    def verify(self, path, trust=None):
        rep, code = v2.verify(path, trust or self.trust)
        return rep, code

    def assert_fails(self, path, check, trust=None):
        rep, code = self.verify(path, trust)
        self.assertEqual(code, 1, rep.checks)
        self.assertEqual(rep.integrity, "FAILED")
        self.assertIn(check, rep.failures)

    def assert_gated(self, version, *added):
        """Records `added` ((type, data, run), each run's first its run.registered; the first run is exported, with the
        others) need verifier `version`: the bundle declares it, a verifier of that version says VERIFIED and one of the
        version before says UNVERIFIABLE, never FAILED."""
        log = self.log(f"gated-{random.random()}")
        log.epoch(KEY1)
        for type_, data, run in added:
            if type_ == "run.final":   # ends its run at its head
                n, head = log.runs[run]
                data = {"head_run_seq": n - 1, "head_hash": head, **data}
            log.add(type_, data, run)
        runs = list(dict.fromkeys(run for *_, run in added))
        for run in runs:
            if ("run.final", run) not in {(t, r) for t, _, r in added}:
                log.final(run)
        out = os.path.join(self.d, f"g{random.random()}.tkb")
        export(log.store, "acme", runs[0], log.note(), out, with_runs=runs[1:])
        self.assertEqual(json.loads(v2.read_zip(out)["manifest.json"])["verifier_min_version"], version)
        versions = [VERIFIER_MIN_VERSION, *VERSIONS]
        for have, want in ((version, (0, "VERIFIED")), (versions[versions.index(version) - 1],
                                                       (2, f"UNVERIFIABLE (needs tracekit >= {version})"))):
            with mock.patch.object(v2, "__version__", have):
                rep, code = self.verify(out)
            self.assertEqual((code, rep.integrity), want, rep.checks)

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
        self.assertEqual(rep.assurance, f"witnessed; records ed25519; checkpoint Ed25519 only ({ORIGIN}); cosigned "
                                        f"ed25519 by {WITNESS} (customer) at 2025-10-09T08:53:20Z; earliest independent "
                                        "anchor 2025-10-09T08:53:20Z; key retirements not proven complete")
        self.assertEqual(rep.warnings, [])   # one key never retired: the assurance line notes it, no warning
        with zipfile.ZipFile(out) as z:
            names = set(z.namelist())
        self.assertFalse({n for n in names if n.endswith((".html", ".py", ".js"))})

    def test_open_run_verifies_to_head(self):
        _, out = self.honest(close=False)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED TO HEAD 3 (open)"), rep.checks)

    def test_a_failed_export_leaves_no_file(self):
        log, _ = self.honest()
        out = os.path.join(self.d, "failed.tkb")
        with mock.patch.object(zipfile.ZipFile, "writestr", side_effect=OSError(28, "No space left on device")), \
                self.assertRaises(OSError):
            export(log.store, "acme", "run-a", log.note(), out)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith("failed")], [])

    def test_a_bundle_over_the_format_limits_is_refused_and_not_written(self):
        """docs/format-v2.md §9: a bundle over its limits is UNUSABLE to every verifier (a run of 40,000 tool calls
        exported one), so export refuses it and says why. A run over the per-file limit goes in parts (TestRunParts);
        any other file over it is refused."""
        log, out = self.honest()
        files, big = v2.read_zip(out), os.path.join(self.d, "big.tkb")
        for limit, value in (("MAX_ENTRY", len(files["keys/records.jsonl"]) - 1), ("MAX_ENTRIES", len(files) - 1),
                             ("MAX_TOTAL", sum(map(len, files.values())) - 1)):
            with self.subTest(limit), mock.patch.object(v2, limit, value), \
                    self.assertRaisesRegex(ValueError, "over the format's limits .* so no verifier could read it"):
                export(log.store, "acme", "run-a", log.note(), big)
            self.assertFalse(os.path.exists(big))

    def test_run_written_after_the_checkpoint_exports_to_it(self):
        log, _ = self.honest(close=False)
        note = log.note()
        log.call()   # the run goes on after the checkpoint the export uses
        out = os.path.join(self.d, "active.tkb")
        export(log.store, "acme", "run-a", note, out)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED TO HEAD 3 (open)"), rep.checks)

    def test_report_lines(self):
        log = self.log()
        log.epoch(KEY1)
        log.add("run.registered", {"agent": {"name": "agent"}, "identity": {"scheme": "uid", "subject": "1", "attested": True},
                                   "signer_isolation": "separate-user", "fail_modes": {"default": "closed", "read": "open"},
                                   "harness": {"name": "claude", "exe": "/usr/bin/claude", "pid": 9, "start_time": 1,
                                               "attested": True}})
        for i, (tier, source) in enumerate((("T1", "parsed"), ("T2", "raw"), (None, "coerced"))):
            log.add("tool.call", {"tool_use_id": f"tc-{i}", "name": "Bash", "input": {}}, tool_call_id=f"tc-{i}",
                    args_source=source, **({"tier": tier} if tier else {}))
        log.add("tool.call", {"tool_use_id": "tc-0", "name": "Bash", "input": {}}, tool_call_id="tc-0")   # same call
        log.final()
        out = os.path.join(self.d, "lines.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        want = {"tiers": "3 tool call(s): T1 1, T2 1, T3 0, untiered 1",
                "args source": "3 record(s): raw 1, parsed 1, coerced 1",
                "isolation": "signer-reported: separate-user 1 run(s)",
                "harness": "signer-attested: run-a claude",
                "fail-open classes": "read",
                "key assurance": "asserted: the log declares its record keys; none is attested"}
        details = {c["check"]: c["detail"] for c in rep.checks if c["status"] == "pass" or c["check"] == "fail-open classes"}
        self.assertEqual({k: details.get(k) for k in want}, want)
        self.assertEqual(rep.warnings, ["fail-open classes"])   # read calls may have run unrecorded in an outage

    def test_signed_gaps_tampering_and_fail_open_classes_warn(self):
        out = gaps_bundle(self.log(), os.path.join(self.d, "gaps.tkb"))
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity, rep.warnings), (0, "VERIFIED", ["gaps", "fail-open classes"]), rep.checks)
        lines = {c["check"]: c for c in rep.checks}
        self.assertEqual(lines["gaps"]["detail"], "3 signed gap, tamper or mismatch record(s): "
                                                  "approval.binding_mismatch 1, client_counter_gap 1, state_tamper 1")
        self.assertEqual(lines["gaps"]["problems"][2], "seq 4: approval.binding_mismatch: approval apr-1 of call tc-1: "
                                                       "the arguments differ from the approved ones")
        self.assertEqual((lines["fail-open classes"]["detail"], lines["fail-open classes"]["problems"]),
                         ("browser", ["calls the agent classed as one of these may have run unrecorded while the signer "
                                      "was down"]))
        self.assertEqual(self.cli(out, "--trust", self.trust, "--strict")[0], 3)

    def test_a_call_counts_at_its_weakest_tier_and_a_split_capture_path_warns(self):
        rep, code = self.verify(tiers_bundle(self.log(), os.path.join(self.d, "tiers.tkb")))
        [line] = [c for c in rep.checks if c["check"] == "tiers"]
        self.assertEqual((code, line["status"], line["detail"]), (0, "warn", "5 tool call(s): T1 0, T2 1, T3 1, untiered 3"
                                                                  "; 2 decided and completed by different capture paths"))
        self.assertEqual(line["problems"], ["run-a hijacked: gateway T2, sdk untiered", "run-a imported: gateway T2, import T3"])
        [held] = [c for c in rep.checks if c["check"] == "held calls"]
        self.assertEqual((held["status"], held["detail"]), ("warn", "1 tool call(s) a gateway or executor decided have no result"))

    def test_principals_are_reported_attested_or_app_asserted(self):
        for attested, word in ((True, "attested"), (False, "app-asserted")):
            log = self.log(f"store-{word}")
            log.epoch(KEY1)
            log.add("run.registered", {"agent": {"name": "agent"}, "identity": {
                "scheme": "oidc", "subject": "corp/u-1", "attested": True, "person": "corp/bob"}},
                principal="corp/bob", principal_attested=attested)
            log.final()
            out = os.path.join(self.d, f"{word}.tkb")
            export(log.store, "acme", "run-a", log.note(), out)
            rep, code = self.verify(out)
            self.assertEqual(code, 0, rep.checks)
            self.assertIn({"check": "principals", "status": "pass", "detail": f"corp/bob ({word})", "problems": []},
                          rep.checks)

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

    def test_a_memo_skips_only_the_checks_the_same_record_passed(self):
        """tracekit view checked a growing run in full at each checkpoint (0.5 ms a record each time): with verify's
        memo a record that passed is not checked again for its signature and schema, the report is the same, and an
        edited record, a changed algorithm or another record's signature still fail against a memo of every honest
        record."""
        _, out = self.honest()
        memo = set()
        rep, code = v2.verify(out, self.trust, memo=memo)
        self.assertEqual(code, 0, rep.checks)
        with mock.patch.object(crypto, "verify_v2", wraps=crypto.verify_v2) as signatures, \
                mock.patch.object(v2, "validate", side_effect=AssertionError("schema checked again")):
            again, code = v2.verify(out, self.trust, memo=memo)
        self.assertEqual((again.checks, again.integrity, code), (rep.checks, rep.integrity, 0))
        self.assertEqual(signatures.call_count, 2)   # the checkpoint and its cosignature, every time; no record

        def edit(rs):
            rs[2]["event"]["data"]["name"] = "Write"

        def alg(rs):
            rs[1]["alg"] = "ed25519ph"

        def swap(rs):
            rs[1]["sig"] = rs[2]["sig"]
        for fn in (edit, alg, swap):
            with self.subTest(fn.__name__):
                rep, code = v2.verify(self.mutate(out, fn), self.trust, memo=memo)
                self.assertEqual((code, rep.integrity), (1, "FAILED"))
                self.assertIn("signatures", rep.failures)

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

    @unverified_bundles
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
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity, rep.failures), (1, "FAILED", ["signatures"]), rep.checks)
        self.assertIn(f"seq {log.store.tree.size - 1}: signed by key", str(rep.checks))

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

    def test_a_run_of_tiny_lines_is_refused_before_it_is_parsed(self):
        _, out = self.honest()

        def tiny(files, manifest):
            name = next(n for n in files if n.startswith("runs/"))
            files[name] = b"1\n" * (v2.MAX_LINES + 1)   # 0.5 MB of lines no signed record could be
        bad = self.mutate(out, edit=tiny)
        started = time.monotonic()
        rep, code = self.verify(bad)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("more lines than the bundle limits", str(rep.checks))
        import test_ts_verifier as tv
        if not tv.SKIP:
            ts = tv.ts_verify(bad, self.trust)
            self.assertEqual((ts["exit_code"], ts["integrity"]), (code, rep.integrity))
            self.assertIn("more lines than the bundle limits", json.dumps(ts["checks"]))

    def test_lines_shorter_than_a_record_are_refused_before_they_are_parsed(self):
        """No signed record is shorter than 256 bytes, so neither verifier parses a shorter line: a bundle that unzips to
        millions of tiny lines (which crashed the browser page without a trust file) is refused at its first one."""
        _, out = self.honest()

        def tiny(files, manifest):
            name = next(n for n in files if n.startswith("runs/"))
            files[name] = b'{"event":{"seq":1}}\n' * 1000
        bad = self.mutate(out, edit=tiny)
        rep, code = self.verify(bad)
        self.assertEqual(code, 1)
        self.assertIn("line shorter than a signed record", str(rep.checks))
        import test_ts_verifier as tv
        if not tv.SKIP:
            ts = tv.ts_verify(bad, self.trust)
            self.assertEqual((ts["exit_code"], ts["checks"]), (code, rep.checks))

    def test_a_seq_written_as_a_float_fails_the_same_checks_in_both_verifiers(self):
        _, out = self.honest()
        bad = self.mutate(out, edit_run=lambda rs: rs[0]["event"].update(seq=float(rs[0]["event"]["seq"])))
        rep, code = self.verify(bad)
        self.assertEqual((code, rep.failures), (1, ["signatures"]))
        import test_ts_verifier as tv
        if not tv.SKIP:
            ts = tv.ts_verify(bad, self.trust)
            self.assertEqual([c["check"] for c in ts["checks"] if c["status"] == "fail"], rep.failures)

    def test_newer_bundle_is_unverifiable(self):
        _, out = self.honest()
        rep, code = self.verify(self.mutate(out, edit=lambda f, m: m.update(verifier_min_version="99.0")))
        self.assertEqual((code, rep.integrity), (2, "UNVERIFIABLE (needs tracekit >= 99.0)"))
        for bad in ("99.0\x1b[2J", "1.2.3.4", "v1", "", 4, "\u0661.\u0660.\u0660", "\uff11.0"):   # ASCII digits only
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
        self.assertEqual(self.cli(out, "--trust", self.trust, "--strict")[0], 0)   # no warning

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

    @unittest.skipIf(sys.version_info < (3, 10), "sys.stdlib_module_names is 3.10+")
    def test_verifiers_need_only_the_standard_library(self):
        """`pip install --no-deps tracekit-ai`: both verifiers import and run with every module outside the standard
        library blocked, cryptography and rfc8785 included."""
        sample = os.path.join(os.path.dirname(TESTS), "docs", "sample")
        _, v2_bundle = self.honest()
        blocker = ("import importlib.abc, sys\n"
                   "class Block(importlib.abc.MetaPathFinder):\n"
                   "    def find_spec(self, name, path=None, target=None):\n"
                   "        if name.partition('.')[0] not in sys.stdlib_module_names | {'tracekit'}:\n"
                   "            raise ImportError(f'blocked: {name}')\n"
                   "sys.meta_path.insert(0, Block())\n"
                   "import tracekit.verify.v1, tracekit.verify.v2\n"
                   "from tracekit import cli, crypto\n"
                   "assert crypto.BACKEND == 'pure-python'\n"
                   "sys.exit(cli.main(sys.argv[1:]))\n")
        key = ["--key", os.path.join(sample, "signer.pub")]
        cases = {"v1 sample": (["verify", os.path.join(sample, "demo-run.tkb"), *key], 0, "Integrity: VERIFIED."),
                 "v1 tampered sample": (["verify", os.path.join(sample, "demo-run-tampered.tkb"), *key], 1,
                                        "Integrity: VERIFICATION FAILED."),
                 "v2 bundle": (["verify", v2_bundle, "--trust", self.trust], 0, "Integrity: VERIFIED.")}
        for why, (argv, want, verdict) in cases.items():
            with self.subTest(why):
                p = subprocess.run([sys.executable, "-c", blocker, *argv], capture_output=True, text=True,
                                   cwd=os.path.dirname(TESTS))
                self.assertEqual(p.returncode, want, p.stdout + p.stderr)
                self.assertIn(verdict, p.stdout)


class TestRunParts(Case):
    """Format 1.4: a run whose records don't fit one file of a bundle is written in parts, split at records, which a
    verifier reads in order as that one file; anything else about the parts fails `run parts` (format-v2.md §9)."""

    def parted(self, cap=4096):
        """(log, bundle) of a closed run of 20 calls, exported with the per-file limit lowered to `cap` bytes."""
        log = self.log()
        log.epoch(KEY1)
        log.register()
        for _ in range(20):
            log.call()
        log.final()
        out = os.path.join(self.d, "parts.tkb")
        with mock.patch.object(v2, "MAX_ENTRY", cap):
            self.info = export(log.store, "acme", "run-a", log.note(), out)
        return log, out

    def test_a_run_past_the_file_limit_is_in_parts_that_verify_as_its_one_file(self):
        log, out = self.parted()
        whole = os.path.join(self.d, "whole.tkb")
        one = export(log.store, "acme", "run-a", log.note(), whole)
        files, name = v2.read_zip(out), run_name("acme", "run-a")
        parts = [n for n in files if n.startswith("runs/")]
        self.assertEqual(parts, [f"{name[:-len('.jsonl')]}.part-{i:04d}.jsonl" for i in range(1, len(parts) + 1)])
        self.assertGreater(len(parts), 2)
        self.assertTrue(all(len(files[n]) <= 4096 for n in parts))
        self.assertEqual(b"".join(files[n] for n in parts), v2.read_zip(whole)[name])   # split only between records
        self.assertEqual(sorted(json.loads(files.pop("manifest.json"))["files"]), sorted(files))
        self.assertEqual([(i["verifier_min_version"], i["raised_by"]) for i in (self.info, one)],
                         [("1.4.0", ["run parts"]), ("1.0.0", [])])
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        self.assertEqual([c for c in rep.checks if c["check"] != "run parts"], self.verify(whole)[0].checks)
        self.assertIn({"check": "run parts", "status": "pass", "problems": [],
                       "detail": f"1 run(s) in {len(parts)} parts, each part continuing the one before it"}, rep.checks)
        with mock.patch.object(v2, "__version__", "1.3.0"):   # a verifier before parts: says it can't, never FAILED
            rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (2, "UNVERIFIABLE (needs tracekit >= 1.4.0)"))
        self.assertEqual(needs([], ["run parts"]), ("1.4.0", "1.4.0"))

    def test_a_run_that_fits_is_one_file_as_before(self):
        log, out = self.parted(cap=64 << 20)
        self.assertEqual([n for n in v2.read_zip(out) if n.startswith("runs/")], [run_name("acme", "run-a")])
        self.assertEqual(self.info["verifier_min_version"], "1.0.0")
        with mock.patch.object(v2, "MAX_ENTRY", len(v2.read_zip(out)[run_name("acme", "run-a")])):   # at the limit
            export(log.store, "acme", "run-a", log.note(), out)
        self.assertEqual([n for n in v2.read_zip(out) if n.startswith("runs/")], [run_name("acme", "run-a")])

    @unverified_bundles
    def test_a_part_missing_out_of_order_extra_misnamed_or_doubled_fails_naming_it(self):
        _, out = self.parted()
        p = [n for n in v2.read_zip(out) if n.startswith("runs/")]
        one = run_name("acme", "run-a")
        last, misnamed, zero = (f"{one[:-len('.jsonl')]}.part-{n}.jsonl" for n in (f"{len(p) + 1:04d}", "002", "0000"))

        def copy(name, to):
            return lambda f, m: (f.update({to: f[name]}), m["files"].update({to: ""}))
        later = "is not in the checkpointed tree, so a later part may be missing"
        for case, edit, check, first in [
                ("a part missing", lambda f, m: f.pop(p[1]), "run parts", f"{p[1]} is missing"),
                ("the first part missing", lambda f, m: f.pop(p[0]), "run parts", f"{p[0]} is missing"),
                ("the last part missing", lambda f, m: f.pop(p[-1]), "inclusion",
                 f"run 'run-a': the last record of {p[-2]} {later}"),
                ("parts out of order", lambda f, m: f.update({p[0]: f[p[1]], p[1]: f[p[0]]}), "run parts",
                 f"{p[1]} does not continue {p[0]}"),
                ("an extra part", copy(p[0], last), "run parts", f"{last} does not continue {p[-1]}"),
                ("a part under two names", copy(p[1], misnamed), "run parts",
                 f"{misnamed}: not a part's name (part-0001, part-0002, ...)"),
                ("a part numbered 0", copy(p[0], zero), "run parts", f"{zero}: not a part's name (part-0001, part-0002, "
                                                                     "...)"),
                ("an empty part", lambda f, m: f.update({p[1]: b""}), "run parts", f"{p[1]} holds no records"),
                ("the run in one file and in parts", lambda f, m: (
                    f.update({one: b"".join(f[n] for n in p)}), m["files"].update({one: ""})), "run parts",
                 f"{one} and {p[0]}: one run in one file and in parts")]:
            with self.subTest(case):
                bad = os.path.join(self.d, "bad.tkb")
                rewrite_bundle(out, bad, edit)
                rep, code = self.verify(bad)
                failed = [c for c in rep.checks if c["status"] == "fail"]
                self.assertEqual((code, rep.integrity, failed[0]["check"], failed[0]["problems"][0]),
                                 (1, "FAILED", check, first), rep.checks)
        with zipfile.ZipFile(out) as z, zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as w:
            for i in z.infolist():
                w.writestr(i.filename, bytes((64 << 20) + 1) if i.filename == p[1] else z.read(i))
        self.assertEqual(self.verify(bad)[0].checks[0]["detail"], f"cannot read bundle: Unusable: {p[1]} is larger "
                                                                   "than the bundle limits")   # as any file over it


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

    def test_one_zip_layout(self):
        """docs/format-v2.md §9: any other layout is unusable, so every reader sees the same entries."""
        def built(*entries, comment=b""):
            f = io.BytesIO()
            with zipfile.ZipFile(f, "w") as z:
                z.comment = comment
                for e in entries:
                    z.writestr(*e)
            return bytearray(f.getvalue())

        def info(name, **attrs):
            i = zipfile.ZipInfo(name)
            for k, v in attrs.items():
                setattr(i, k, v)
            return i

        def patched(at, fmt, value, data=None):
            data = bytearray(good if data is None else data)
            for a in at:
                struct.pack_into(fmt, data, a, value)
            return data
        good = built(("a", b"x"), ("b", b"y"))
        cd = struct.unpack("<I", good[-6:-2])[0]
        second = struct.unpack("<I", good[cd + 42:cd + 46])[0]
        self.assertEqual(v2.read_zip(io.BytesIO(good)), {"a": b"x", "b": b"y"})
        with open(os.path.join(self.d, "good.zip"), "wb") as f:
            f.write(good)
        self.assertEqual(v2.read_zip(os.path.join(self.d, "good.zip")), {"a": b"x", "b": b"y"})
        cases = {
            "end record": [b"MZ" + good, built(("a", b"x"), comment=b"c"), patched((len(good) - 14,), "<H", 1)],
            "not a zip file": [good + b"\0", patched((len(good) - 22,), "<I", 0x07064b50), b"PK"],
            "entry count": [patched((len(good) - 14, len(good) - 12), "<H", 3)],
            "bad central directory entry": [built((info("a", extra=b"\xfe\xca\0\0"), b"x")),
                                            built((info("a", comment=b"c"), b"x"))],
            "general-purpose flags 0x800": [patched((6, cd + 8), "<H", 0x800)],
            "is encrypted": [patched((6, cd + 8), "<H", 1)],
            "bad local header": [patched((6,), "<H", 8), patched((second + 30,), "<B", ord("c"))],
            "compression method 12": [built(("a", b"x", zipfile.ZIP_BZIP2))],
            "compression method 14": [built(("a", b"x", zipfile.ZIP_LZMA))],
            "compression method 0": [patched((22, cd + 24), "<I", 2)],
            "does not follow the entry before it": [patched((cd + 46 + 1 + 42,), "<I", 0)],
            "bytes before the central directory": [good[:cd] + b"z" + patched((len(good) - 6,), "<I", cd + 1)[cd:]],
        }
        short = built(("a", b"x" * 10, zipfile.ZIP_DEFLATED))
        short_cd = struct.unpack("<I", short[-6:-2])[0]
        cases["10 bytes, not the 100"] = [patched((22, short_cd + 24), "<I", 100, short)]
        for why, datas in cases.items():
            for data in datas:
                with self.subTest(why, data=bytes(data[:8])), self.assertRaisesRegex(v2.Unusable, why):
                    v2.read_zip(io.BytesIO(bytes(data)))

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


def registered(run="run-a", **data):
    return ("run.registered", {"agent": {"name": "agent"},
                               "identity": {"scheme": "token", "subject": "svc", "attested": True}, **data}, run)


def decision(**data):
    return ("policy.decision", {"tool_use_id": "t1", "decision": "allow", "rule_ids": [], **data}, "run-a")


def gap(kind, **data):
    return ("capture.gap", {"kind": kind, "reason": "r", **data}, "run-a")


AGENT = {"scheme": "token", "subject": "reviewer", "attested": True}
TS_ = "2026-10-11T00:00:00.000000Z"


def answered(**data):
    return ("approval", {"tool_use_id": "t1", "approval_id": "apr-1", "decision": "approve", "approver": "token:reviewer",
                         "approver_identity": AGENT, "channel": "rpc", **data}, "run-a")


def asked(**data):
    binding = {"v": 1, "approval_id": "apr-1", "tenant": "acme", "run_id": "run-a", "tool_call_id": "t1", "attempt": 0,
               "tool": "pay", "args_commitment": "hmac-sha256:" + "0" * 64, "args_source": "parsed",
               "policy_hash": "sha256:" + "0" * 64, "nonce": "0" * 32, "expires_at": TS_}
    return ("approval.request", {"approval_id": "apr-1", "policy_hash": "sha256:" + "0" * 64, "rule_ids": ["R1"],
                                 "expires_at": TS_, "requester": "uid:1", "decision_id": "dec-1", "binding": binding,
                                 "binding_digest": "sha256:" + "0" * 64, **data}, "run-a")


AGENT_POLICY = {"ask": [{"id": "R1", "pattern": "^", "approval": {"agent": {
    "mode": "enforce", "allow": {"fields": {"amount": {"type": "integer"}}}}}}], "flag": [{"id": "F1", "pattern": "^"}]}


ELIGIBLE = {"eligible": True, "reason": "within the bounds of R1", "rules": ["R1"],
            "conditions_hash": "sha256:" + "0" * 64, "args_key": "hmac-sha256:" + "0" * 64}


def agent_bundle(log, out, policy=AGENT_POLICY, snapshot=True, decided=None, request=None, answer=None, before=()):
    """Export to `out` a run whose ask an agent approved, the signer's policy_dir holding the snapshot of `policy` (or
    none); `decided`, `request` and `answer` override fields of the policy.decision, approval.request and approval
    records, and `before` ((type, data) pairs) are recorded between the request and the approval; a `request` or
    `answer` field None leaves it out."""
    snap = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    h = "sha256:" + hashlib.sha256(snap).hexdigest()
    log.epoch(KEY1)
    log.register()
    log.add("policy.decision", {"tool_use_id": "t1", "decision": "ask", "rule_ids": ["R1", "F1"], "decision_id": "dec-1",
                                "policy_hash": h, "provenance_state": "complete", **(decided or {})}, tool_call_id="t1")
    req = {"agent": ELIGIBLE, **(request or {})}
    log.add(*asked(policy_hash=h, **{k: v for k, v in req.items() if v is not None})[:2], tool_call_id="t1")
    for type_, data in before:
        log.add(type_, data, tool_call_id="t1")
    ans = {"approver_kind": "agent", **(answer or {})}
    log.add(*answered(**{k: v for k, v in ans.items() if v is not None})[:2], tool_call_id="t1")
    log.final()
    pol = out + ".policies"   # the signer's policy_dir
    os.makedirs(pol)
    if snapshot:
        with open(os.path.join(pol, h[7:] + ".json"), "wb") as f:
            f.write(snap)
    export(log.store, "acme", "run-a", log.note(), out, policy_dir=pol)
    return out


# an agent approval of a call the signer did not leave to agents (person-only, escalated or revoked first)
AGENT_ROUTING = (("not agent-eligible", {"request": {"agent": dict(ELIGIBLE, eligible=False)}}),
                 ("no agent field", {"request": {"agent": None}}),
                 ("escalated first", {"before": [("approval.escalated", {"approval_id": "apr-1", "by": "signer",
                                                                         "reason": "no agent answered"})]}),
                 ("revoked first", {"before": [("approval.revoked", {"approval_id": "apr-1", "by": "oidc:alice"})]}))


class TestAgentApprovals(Case):
    def lines(self, **kw):
        name = f"agent-{len(os.listdir(self.d))}"
        rep, code = self.verify(agent_bundle(self.log(name), os.path.join(self.d, f"{name}.tkb"), **kw))
        return code, {c["check"]: c for c in rep.checks}

    def test_people_and_agents_on_separate_lines(self):
        code, lines = self.lines()
        self.assertEqual((code, lines["approvals by agents"]["status"]), (0, "pass"))
        self.assertIn("tracekit signer reveal", lines["approvals by agents"]["detail"])
        self.assertEqual(lines["approvals by people"]["detail"], "0 approval(s) answered by people")
        code, lines = self.lines(answer={"approver_kind": None})   # without agent approvals, the report as before
        self.assertFalse({"approvals by people", "approvals by agents"} & set(lines))

    def test_a_bundle_holds_only_the_snapshots_its_agent_approvals_cite(self):
        for kw, want in (({}, True), ({"answer": {"approver_kind": None}}, False),
                         ({"answer": {"decision": "reject"}}, False)):
            with self.subTest(kw):
                name = f"cited-{len(os.listdir(self.d))}"
                out = agent_bundle(self.log(name), os.path.join(self.d, f"{name}.tkb"), **kw)
                self.assertEqual(any(n.startswith("policies/") for n in v2.read_zip(out)), want)

    def test_without_the_snapshot_the_bounds_are_unchecked(self):
        code, lines = self.lines(snapshot=False)
        self.assertEqual((code, lines["approvals by agents"]["status"]), (0, "warn"))
        self.assertIn("agent approval bounds unchecked", lines["approvals by agents"]["detail"])

    @unverified_bundles
    def test_what_an_agent_may_not_approve_fails(self):
        person_rule = {"ask": [{"id": "R1", "pattern": "^"}], "flag": [{"id": "F1", "pattern": "^"}]}
        for why, kw in (("provenance", {"decided": {"provenance": [{"field": "amount", "kind": "x",
                                                                    "source": {"run_seq": 1}}]}}),
                        ("incomplete provenance", {"decided": {"provenance_state": "partial"}}),
                        ("passkey", {"request": {"passkey": True}}),
                        ("requester", {"answer": {"approver": "uid:1"}}),
                        ("run owner", {"answer": {"approver_identity": dict(AGENT, subject="svc")}}),
                        ("a rule without approval.agent", {"policy": person_rule}),
                        ("a synthetic rule", {"decided": {"rule_ids": ["R1", "TK-UNKNOWN-TOOL"]}}),
                        *AGENT_ROUTING):
            with self.subTest(why):
                code, lines = self.lines(**kw)
                self.assertEqual((code, lines["approvals by agents"]["status"]), (1, "fail"), lines)


OUTPUT = {"hash": "hmac-sha256:" + "0" * 64, "size": 2, "redacted": False}
OBSERVED = {"source": "inbox:1", "trust": "untrusted", "salt_id": "a" * 32, "output": OUTPUT,
            "redaction": {"rules": [], "count": 0, "client_claimed": False}}
H = "sha256:" + "0" * 64
EXPIRES = "2026-10-09T12:05:00.000000Z"
APPROVAL = {"approval_id": "ap-1", "policy_hash": H, "rule_ids": ["R-PAY"], "expires_at": EXPIRES, "requester": "token:svc",
            "decision_id": "dec-1", "binding_digest": H, "binding": {
                "v": 1, "approval_id": "ap-1", "tenant": "acme", "run_id": "run-a", "tool_call_id": "t1", "attempt": 0,
                "tool": "pay", "args_commitment": "hmac-sha256:" + "0" * 64, "args_source": "parsed", "policy_hash": H,
                "nonce": "0" * 32, "expires_at": EXPIRES}}
VIA = "mtls:spiffe://acme/executor"
FINDING = {"target": "tool=pay", "intervention": "i", "n": 0, "p_with": 0, "p_without": 0, "effect": 0,
           "interval": [-1, 1], "verdict": "inconclusive", "replay_runs": [], "models": [], "rung": 1, "off_tape": 0,
           "investigation": "i", "looks": 1, "family": 1, "min_effect": 0.2, "applied": True, "stopped": "budget"}
INCIDENT = {"incident_id": "inc-1", "trigger": "sequence", "rule_ids": ["Q"], "scope": {"kind": "run", "id": "run-a"},
            "cites": [{"run_id": "run-a", "run_seq": 1}], "mode": "shadow", "actions": [], "would": ["notify"]}
FIRED = decision(detect={"sequences": [{"id": "Q", "step": 1}], "limits": [], "state": "complete"})   # run_seq 1
HELD = ("run.held", {"incident_id": "inc-1", "scope": {"kind": "run", "id": "run-a"}, "by": "signer", "reason": "r"},
        "run-a")
EFFECT = {"observer": "uid:7", "kind": "net", "host": "pypi.org", "port": 443, "bytes_out": 1, "bytes_in": 2,
          "connections": 1, "first_ts": "2026-10-11T00:00:00.000000Z", "last_ts": "2026-10-11T00:00:00.000000Z",
          "attribution": "token"}
UNEXPLAINED = {"layers": ["L6"], "observer": "uid:7", "kind": "net", "host": "pypi.org", "port": 443}
MATRIX = {k: {"status": "none", "layers": []} for k in ("model_calls", "tool_calls", "network", "processes", "services")}
# per VERSIONS entry ("type" or "type.field"), records that use it
ENTRIES = {
    "input.observed": [registered(), ("input.observed", OBSERVED, "run-a")],
    "content.accessed": [registered(), ("content.accessed", {"principal": "token:svc", "run_id": "run-x", "seqs": [1],
                                                             "purpose": "case 1"}, "run-a")],
    "content.erased": [registered(), ("content.erased", {"run_id": "run-x", "reason": "retention", "by": "signer"},
                                      "run-a")],
    "why.finding": [registered(), registered("run-f", analyzes="run-a"), ("why.finding", FINDING, "run-f")],
    "policy.decision.provenance": [registered(), decision(provenance_state="complete", provenance=[
        {"field": "to", "kind": "email", "source": {"run_seq": 1}}])],
    "policy.decision.provenance_state": [registered(), decision(provenance_state="complete")],
    "run.registered.replay_of": [registered(replay_of="run-x", investigation="i")],
    "run.registered.parent_run": [registered(parent_run="run-p", session="run-p")],
    "run.registered.session": [registered(parent_run="run-p", session="run-root")],
    "capture.gap.run_id": [registered(), gap("concurrent_run", run_id="run-x")],
    "run.final.provider_executed": [registered(), ("run.final", {"provider_executed": 2}, "run-a")],
    "run.final.paired_by_args": [registered(), ("run.final", {"paired_by_args": 1}, "run-a")],
    "capture.gap.kind=decided_not_completed": [registered(), gap("decided_not_completed", tool_use_id="t1")],
    "capture.gap.kind=late_activity": [registered(), gap("late_activity", run_id="run-x", missed_events=3)],
    "capture.gap.kind=concurrent_run": [registered(), gap("concurrent_run")],
    "capture.gap.kind=tailer_redelegated": [registered(), gap("tailer_redelegated")],
    "run.child": [registered(), ("run.child", {"run_id": "run-x"}, "run-a")],
    "policy.decision.detect": [registered(), decision(detect={"sequences": [{"id": "Q", "step": 1}], "limits": [],
                                                              "state": "complete"})],
    "incident.opened": [registered(), FIRED, ("incident.opened", INCIDENT, "run-a")],
    "incident.updated": [registered(), FIRED, ("incident.updated", {"incident_id": "inc-1", "cites": [
        {"run_id": "run-a", "run_seq": 1}]}, "run-a")],
    "run.held": [registered(), HELD],
    "run.quarantined": [registered(), ("run.quarantined", dict(HELD[1]), "run-a")],
    "run.resumed": [registered(), HELD, ("run.resumed", {"incident_id": "inc-1", "by": "uid:1", "person": "ana",
                                                         "held_by": []}, "run-a")],
    "incident.resolved": [registered(), ("incident.resolved", {"incident_id": "inc-1", "by": "uid:1", "person": "ana"},
                                         "run-a")],
    "incident.response": [registered(), ("incident.response", {"enabled": False, "by": "uid:1"}, "run-a")],
    "identity.suspension": [registered(), ("identity.suspension", {"identity": "token:svc", "state": "enforced",
                                                                    "by": "signer"}, "run-a")],
    "policy.decision.incident_id": [registered(), decision(incident_id="inc-1")],
    "approval.request.incident_id": [registered(), ("approval.request", dict(APPROVAL, incident_id="inc-1"), "run-a")],
    "approval.incident_id": [registered(), answered(incident_id="inc-1")],
    "run.closing.reason=quarantine": [registered(), ("run.closing", {"reason": "quarantine"}, "run-a")],
    "incident.capped": [registered(), ("incident.capped", {"cap": "run", "max": 100, "trigger": "sequence",
                                                           "reason": "cap"}, "run-a")],
    "approval.escalated": [registered(), ("approval.escalated", {"approval_id": "apr-1", "by": "signer",
                                                                 "reason": "no agent answered"}, "run-a")],
    "approval.revoked": [registered(), ("approval.revoked", {"approval_id": "apr-1", "by": "uid:1"}, "run-a")],
    "approval.suggested": [registered(), ("approval.suggested", {
        "tool_use_id": "t1", "approval_id": "apr-1", "decision": "approve", "approver": "token:reviewer",
        "approver_identity": AGENT, "channel": "rpc", "approver_kind": "agent"}, "run-a")],
    "approval.agents": [registered(), ("approval.agents", {"enabled": False, "by": "uid:0"}, "run-a")],
    "approval.request.agent": [registered(), asked(agent=ELIGIBLE)],
    "approval.approver_kind": [registered(), decision(decision="ask", decision_id="dec-1",
                                                      provenance_state="complete"), asked(agent=ELIGIBLE), answered(
        approver_kind="agent")],
    "approval.asserted": [registered(), answered(asserted={"model": "m", "attested": False})],
    "approval.spent": [registered(), answered(spent={"R1": 100})],
    "approval.not_before": [registered(), answered(not_before=TS_)],
    "approval.consume_by": [registered(), answered(consume_by=TS_)],
    "approval.expired.reason": [registered(), ("approval.expired", {"approval_id": "apr-1", "reason": "ttl"}, "run-a")],
    "capture.gap.kind=reask_after_reject": [registered(), ("capture.gap", {
        "kind": "reask_after_reject", "reason": "asked again", "tool_use_id": "t1"}, "run-a")],
    "policy.decision.via": [registered(), decision(via=VIA)],
    "policy.decision.caller": [registered(), decision(via=VIA, caller="token:agent")],
    "capture.gap.kind=held_call_unresolved": [registered(), ("capture.gap", {
        "kind": "held_call_unresolved", "tool_use_id": "t1", "reason": "no result"}, "run-a")],
    "approval.request.via": [registered(), ("approval.request", dict(APPROVAL, via=VIA), "run-a")],
    "approval.request.passkey": [registered(), ("approval.request", dict(APPROVAL, passkey=True), "run-a")],
    "tool.result.via": [registered(), ("tool.result", {"tool_use_id": "t1", "ok": True, "output": OUTPUT, "via": VIA},
                                       "run-a")],
    "input.observed.via": [registered(), ("input.observed", dict(OBSERVED, via=VIA), "run-a")],
    "effect.observed": [registered(), ("effect.observed", EFFECT, "run-a")],
    "run.registered.posture": [registered(posture={"network": "enforced", "tool_calls": "open",
                                                   "gateway_mandatory": True, "attested": False})],
    "run.final.matrix": [registered(), ("run.final", {"matrix": MATRIX}, "run-a")],
    **{f"reconcile.unexplained_effect.{f}": [registered(), ("reconcile.unexplained_effect", UNEXPLAINED, "run-a")]
       for f in ("observer", "kind", "host", "port")},
    **{f"capture.gap.kind={k}": [registered(), ("capture.gap", {"kind": k, "reason": "r"}, "run-a")]
       for k in ("observer_lost", "effect_outside_run")},
    "reconcile.result_mismatch": [registered(), ("reconcile.result_mismatch", {"layers": ["L2", "L3"], "detail": "d"},
                                                 "run-a")],
    "capture.gap.kind=result_unchecked": [registered(), ("capture.gap", {
        "kind": "result_unchecked", "tool_use_id": "t1", "reason": "no digests"}, "run-a")],
    "capture.gap.kind=constraint_refused": [registered(), ("capture.gap", {
        "kind": "constraint_refused", "reason": "the run has 32 live constraints"}, "run-a")],
    "effect.observed.sensor": [registered(), ("effect.observed", {
        "observer": "uid:7", "sensor": "tetragon", "kind": "exec", "ts": TS_, "pid": 7, "binary": "/usr/bin/curl",
        "attribution": "identity"}, "run-a")],
    "capture.gap.sensor": [registered(), ("capture.gap", {"kind": "observer_lost", "sensor": "falco", "reason": "r"},
                                          "run-a")],
    "effect.observed.denied": [registered(), ("effect.observed", {
        "observer": "uid:7", "sensor": "openshell", "kind": "connect", "ts": TS_, "pid": 7, "binary": "/usr/bin/curl",
        "host": "blocked.example.com", "port": 443, "denied": True, "attribution": "token"}, "run-a")],
    "constraint.added": [registered(), ("constraint.added", {"kind": "no_push"}, "run-a")],
    "model.exchange.said_only": [registered(), ("model.exchange", {
        "exchange_id": "x1", "phase": "response", "streamed": False, "model": "m", "said_only": True}, "run-a")],
    "review.cites": [registered(), registered("run-f", analyzes="run-a"), ("review", {
        "reviewer": "tracekit-analyze/1.4.0", "verdict": {"kind": "coverage", "rule": "TK-X200", "severity": "info",
                                                          "checks": {}}, "cites": []}, "run-f")],
}


class TestVersionTable(Case):
    def test_every_entry_gates_its_version(self):
        for version, added in VERSIONS.items():
            names = added["types"] + [f"{t}.{f}" for t, fs in added["fields"].items() for f in fs] + [
                f"{t}.{f}={v}" for t, fs in added["values"].items() for f, vs in fs.items() for v in vs]
            for name in names:
                with self.subTest(name):
                    self.assertIn(name, ENTRIES, "add records that use it to ENTRIES")
                    self.assert_gated(version, *ENTRIES[name])

    def test_shipped_rows_are_frozen(self):
        # a row is frozen once its version's first release candidate ships: later additions go in a new row, so a
        # verifier of that version never meets a field its own version claims to know
        shipped = {"1.1.0": "2e5a668bf93c0e4b3fca960f9824e2c5858d5539109511d636bd7635e648061e",
                   "1.2.0": "c0c704e79fe3641a7784cd2c05cf943c2ea9cab4c39181f6ab3bea5f736b1eb9",
                   "1.3.0": "1ced79b94a5a8e0cb977946b39109020beeaaea8a5c2ac5ac856dbd1c0f794d2",
                   "1.4.0": "7ba74fe8501c26765ef5cd3d0a762e6fbb9c9226e71cdcbc124d8f430c404d2b"}
        for version, digest in shipped.items():
            self.assertEqual(hashlib.sha256(canonical(VERSIONS[version])).hexdigest(), digest, version)



class TestExt(Case):
    """Format 1.4's non-critical slot: ext fields and records are signed, chained and included like any record; a name
    the verifier doesn't interpret is a warning, never a failure; any use of the slot needs 1.4.0."""

    def test_an_ext_on_a_key_record_needs_1_4_0_too(self):
        log = self.log()
        der = crypto.spki(pub(KEY1))   # keys/records.jsonl, which the verifier reads like any run's records
        log.add("signer.epoch", {"keys": [{"kid": crypto.spki_kid(der), "alg": "ed25519",
                                           "spki": base64.b64encode(der).decode()}]}, run="signer", key=KEY1, ext=NOTE)
        log.register()
        log.final()
        out = os.path.join(self.d, "key-ext.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        manifest = json.loads(v2.read_zip(out)["manifest.json"])
        self.assertEqual((manifest["verifier_min_version"], manifest["verifier_version"]), ("1.4.0", "1.4.0"))
        rep, code = self.verify(out)
        self.assertEqual((code, rep.warnings), (0, ["not interpreted"]), rep.checks)

    def test_an_ext_name_not_interpreted_verifies_with_a_warning(self):
        out = ext_bundle(self.log(), os.path.join(self.d, "ext.tkb"))
        manifest = json.loads(v2.read_zip(out)["manifest.json"])
        self.assertEqual((manifest["verifier_min_version"], manifest["verifier_version"]), ("1.4.0", "1.4.0"))
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity, rep.warnings), (0, "VERIFIED", ["not interpreted"]), rep.checks)
        self.assertEqual(rep.checks[-1]["detail"], "2 record(s) carry ext.acme.note: their signatures, chain and "
                                                   "inclusion are checked above; what ext.acme.note means is not checked")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["verify", out, "--trust", self.trust, "--strict"]), 3)

    def test_an_older_verifier_is_unverifiable_and_told_how_to_verify(self):
        out = ext_bundle(self.log(), os.path.join(self.d, "ext.tkb"))
        with mock.patch.object(v2, "__version__", "1.3.0"):
            rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (2, "UNVERIFIABLE (needs tracekit >= 1.4.0)"))
        self.assertEqual(rep.checks, [{"check": "bundle readable", "status": "fail", "detail": rep.integrity, "problems": [
            f'uvx --from "tracekit-ai>=1.4.0" tracekit verify {out} --trust {self.trust}',
            f"npx -y @cygnuxlabs/tracekit@latest verify {out} --trust {self.trust}",
            f"or open {v2.PAGE} and choose both files: the page verifies them in your browser and sends nothing"]}])
        if os.name != "nt":   # a path the shell would split is quoted
            self.assertIn("verify '/tmp/my run.tkb' --trust t.json", v2.upgrade("1.4.0", "/tmp/my run.tkb", "t.json")[0])

    def test_a_name_a_later_version_interprets_names_that_version(self):
        with mock.patch.dict(VERSIONS, {"9.0.0": {"types": [], "fields": {}, "values": {}, "ext": ["acme.note"]}}):
            out = ext_bundle(self.log(), os.path.join(self.d, "ext.tkb"))
        manifest = json.loads(v2.read_zip(out)["manifest.json"])
        self.assertEqual((manifest["verifier_min_version"], manifest["verifier_version"]), ("1.4.0", "9.0.0"))
        rep, code = self.verify(out)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"))
        self.assertTrue(rep.checks[-1]["detail"].endswith("is not checked; tracekit >= 9.0.0 checks it"))

    def test_the_slot_needs_1_4_and_the_export_says_which_records(self):
        log = self.log()
        log.epoch(KEY1)
        log.register()
        log.add("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}, ext={})
        log.final()
        info = export(log.store, "acme", "run-a", log.note(), os.path.join(self.d, "e.tkb"))
        self.assertEqual((info["verifier_min_version"], info["raised_by"], info["verifier_min_version_full"]),
                         ("1.4.0", ["ext: seq 2"], "1.4.0"))
        self.assertEqual(needs([{"type": "ext", "data": {"name": "n"}}]), ("1.4.0", "1.4.0"))

    def test_an_ext_is_tamper_evident(self):
        out = ext_bundle(self.log(), os.path.join(self.d, "ext.tkb"))
        for name, (edit, check) in {
                "an ext value edited": (lambda rs: rs[1]["event"]["ext"]["acme.note"].update(seen=[2]), "signatures"),
                "an ext field removed": (lambda rs: rs[1]["event"].pop("ext"), "signatures"),
                "an ext record edited": (lambda rs: rs[2]["event"]["data"].update(detail={}), "signatures"),
                "an ext record dropped": (lambda rs: rs.pop(2), "run chain")}.items():
            with self.subTest(name):
                self.assert_fails(self.mutate(out, edit), check)

    @unverified_bundles   # each is schema-invalid on purpose
    def test_ext_names_are_schema_checked(self):
        for name, field, record in (("upper case", {"Acme": 1}, ("acme", {})), ("too long", {"a" * 65: 1}, ("a", {})),
                                    ("a record's name not a string", NOTE, ("x", {"name": None}))):
            with self.subTest(name):
                out = ext_bundle(self.log(f"s-{random.random()}"), os.path.join(self.d, f"{random.random()}.tkb"),
                                 field, record)
                self.assert_fails(out, "signatures")

    def test_an_ext_interpretation_adds_only_its_own_lines(self):
        """What may go in ext: every line a verifier that doesn't interpret a name prints stays true without it, so the
        report with the name's interpretation off is the full report minus that name's own lines, with its `not
        interpreted` line instead. Every name a VERSIONS row lists has its check in EXT_CHECKS; a stand-in shows the
        rule with one."""
        listed = [n for row in VERSIONS.values() for n in row.get("ext", ())]
        self.assertEqual(sorted(v2.EXT_CHECKS), sorted(listed))
        checks = {**v2.EXT_CHECKS, "acme.note": lambda rep, es: rep.check("acme notes", True, f"{len(es)} note(s)")}
        for name, check in checks.items():
            with self.subTest(name):
                out = ext_bundle(self.log(f"s-{name}"), os.path.join(self.d, f"{name}.tkb"), {name: {}}, (name, {}))
                own = []

                def tracked(rep, events, check=check, own=own):
                    n = len(rep.checks)
                    check(rep, events)
                    own.extend(rep.checks[n:])
                with mock.patch.dict(v2.EXT_CHECKS, {name: tracked}):
                    on = self.verify(out)
                with mock.patch.dict(v2.EXT_CHECKS):
                    v2.EXT_CHECKS.pop(name, None)
                    off = self.verify(out)
                self.assertTrue(own)
                self.assertEqual([c for c in on[0].checks if not any(c is o for o in own)],
                                 [c for c in off[0].checks if c["detail"].split(":")[0] != f"2 record(s) carry ext.{name}"])
                self.assertEqual((on[1], on[0].integrity, on[0].assurance), (off[1], off[0].integrity, off[0].assurance))


if __name__ == "__main__":
    unittest.main()
