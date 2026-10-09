"""Registry log checkpoints, run-set bundles and log.closed (04-design §1.5-§1.8): the signer's registry notes, the
run-set export and its verifier line, a withheld key.retire, and closing a log for good."""
import base64
import json
import os
import random
import time
import unittest
import zipfile

from factories import rewrite_bundle
from test_signer_checkpoints import run_cli
from test_signer_service import ME, tmpdir
from tracekit.bundle_v2 import export, run_name
from tracekit.format import checkpoint, registry
from tracekit.merkle import verify_consistency
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import registry_tree
from tracekit.verify import v2


class RunSet(unittest.TestCase):
    def setUp(self):
        self.dir, self.n = tmpdir(self), 0
        self.s = self.open()
        self.trust = os.path.join(self.dir, "trust.json")
        with open(self.trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"], "witnesses_required": 0}, f)

    def open(self):
        s = svc.SignerService(self.dir, grace_s=0, multi_tenant_apps=[f"uid:{ME.subject}"])
        self.addCleanup(s.close)
        return s

    def call(self, method, req):
        self.n += 1
        return self.s.call(ME, method, {"request_id": f"req-{self.n}", **req})

    def register(self, tenant="acme"):
        out = self.call("register_run", {"agent": {"name": "a"}, "tenant": tenant})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def finish(self, *runs):
        for run in runs:
            self.call("close_run", run)
        self.s.sweep(time.monotonic() + 1)

    def registry_note(self, tenant="acme"):
        return self.s.log.storage.checkpoint_latest(registry_tree(tenant))

    def export(self, run_set=None, tenant="acme", run_id=None, name="rs.tkb"):
        self.s.checkpoint()
        st, out = self.s.log.storage, os.path.join(self.dir, name)
        export(st, tenant, run_id, st.checkpoint_latest()[1], out,
               run_set=run_set or (0, self.registry_note(tenant)[0]), tenant_salt=self.s.log.tenant_salt(tenant))
        return out

    def honest(self):
        """acme: a and b final, c open; beta: one final run. Returns (bundle of acme's run-set, runs)."""
        a, b, c = self.register(), self.register(), self.register()
        beta = self.register("beta")
        self.finish(a, b, beta)
        return self.export(), {"a": a, "b": b, "c": c, "beta": beta}

    def check(self, path, name):
        rep, code = v2.verify(path, self.trust)
        return code, rep, next((c for c in rep.checks if c["check"] == name), None)

    def assert_incomplete(self, path, why):
        code, rep, line = self.check(path, "run-set")
        self.assertEqual((code, rep.integrity, line["detail"].split(",")[0]), (1, "FAILED", "INCOMPLETE"), rep.checks)
        self.assertIn(why, str(line["problems"]))

    def mutate(self, src, edit):
        out = os.path.join(self.dir, f"m{random.random()}.tkb")
        rewrite_bundle(src, out, edit)
        return out


def _lines(data):
    return [json.loads(x) for x in data.splitlines()]


def _dump(records):
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


class TestRunSet(RunSet):
    def test_honest_run_set_is_complete_and_holds_one_tenant(self):
        out, runs = self.honest()
        code, rep, line = self.check(out, "run-set")
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        self.assertEqual(line["detail"], "COMPLETE, registry 0..5 (3 runs registered, 2 final, 1 open)")
        self.assertEqual(rep.warnings, ["log tail"])   # the log is still open: its tail is unproven
        with zipfile.ZipFile(out) as z:
            blob = b"".join(z.read(n) for n in z.namelist())
            self.assertEqual(sorted(n for n in z.namelist() if n.startswith("runs/")),
                             sorted(run_name("acme", runs[k]["run_id"]) for k in "ab"))
            leaves = json.loads(z.read("registry/run-set.json"))["leaves"]
        self.assertEqual(len(leaves), len(list(self.s.log.storage.registry_iter("acme"))))
        self.assertNotIn(runs["beta"]["run_id"].encode(), blob)
        self.assertNotIn(b"\"beta\"", blob)
        beta_leaves = {base64.b64encode(x).decode() for x in self.s.log.storage.registry_iter("beta")}
        self.assertFalse(beta_leaves & {x["leaf"] for x in leaves})
        self.assertNotIn("acme", self.registry_note()[1])   # the registry origin never names the tenant

    def test_whole_run_deletion_is_detected(self):
        out, runs = self.honest()
        gone = run_name("acme", runs["a"]["run_id"])

        def drop_run(files, manifest):
            del files[gone]
        self.assert_incomplete(self.mutate(out, drop_run), "its records are not in the bundle")

        def drop_leaves(files, manifest):   # and the run's leaves with it
            rs = json.loads(files["registry/run-set.json"])
            rs["leaves"] = rs["leaves"][2:]
            files["registry/run-set.json"] = json.dumps(rs).encode()
            del files[gone]
        self.assert_incomplete(self.mutate(out, drop_leaves), "a leaf is missing")

        def drop_record(files, manifest):
            files["registry/records.jsonl"] = _dump(_lines(files["registry/records.jsonl"])[1:])
        self.assert_incomplete(self.mutate(out, drop_record), "points to a missing or different record")

    def test_cross_run_splice_is_detected(self):
        out, runs = self.honest()
        a, b = (run_name("acme", runs[k]["run_id"]) for k in "ab")

        def swap_runs(files, manifest):
            files[a], files[b] = files[b], files[a]
        self.assert_incomplete(self.mutate(out, swap_runs), "its records are not in the bundle")

        def swap_pointed(files, manifest):   # leaf 0 (a registered) now points at b's run.registered
            rs = _lines(files["registry/records.jsonl"])
            seq0 = rs[0]["event"]["seq"]
            rs[0] = dict(rs[1])
            rs[0]["event"] = dict(rs[1]["event"], seq=seq0)
            files["registry/records.jsonl"] = _dump(rs)
        self.assert_incomplete(self.mutate(out, swap_pointed), "points to a missing or different record")

    def test_second_run_final_is_detected(self):
        a = self.register()
        self.finish(a)
        run = self.s.log.runs[("acme", a["run_id"])]
        self.s.log.write(lambda tx: tx.emit(run, "run.final", {"head_run_seq": run["run_seq"] - 1,
                                                                "head_hash": run["head"]}, source="signer"))
        self.assert_incomplete(self.export(), "a second run.final")

    def test_withheld_key_retire_is_detected(self):
        a = self.register()
        signer = self.s.log.runs[svc.SIGNER_RUN]
        self.s.log.write(lambda tx: tx.emit(signer, "key.retire", {"kid": self.s.log.sign.kid, "last_seq": 10 ** 6},
                                            source="signer"))
        self.finish(a)
        out = self.export()
        self.assertEqual(self.check(out, "keys")[0], 0)

        def withhold(files, manifest):
            files["keys/records.jsonl"] = _dump(r for r in _lines(files["keys/records.jsonl"])
                                                if r["event"]["type"] != "key.retire")
        code, rep, line = self.check(self.mutate(out, withhold), "keys")
        self.assertEqual((code, line["status"]), (1, "fail"), rep.checks)
        self.assertIn("key.retire withheld", str(line["problems"]))

        # a per-run bundle without a run-set cannot tell, and says so
        st, single = self.s.log.storage, os.path.join(self.dir, "one.tkb")
        export(st, "acme", a["run_id"], st.checkpoint_latest()[1], single)
        for path in (single, self.mutate(single, withhold)):
            code, rep, _ = self.check(path, "keys")
            self.assertEqual((code, rep.warnings), (0, ["keys"]), rep.checks)
            self.assertIn({"check": "keys", "status": "warn", "detail": "retirements not proven complete"},
                          [{k: c[k] for k in ("check", "status", "detail")} for c in rep.checks])
            self.assertTrue(rep.assurance.endswith("; key retirements not proven complete"), rep.assurance)

    def test_empty_range_is_incomplete(self):
        out, _ = self.honest()

        def empty(files, manifest):
            rs = json.loads(files["registry/run-set.json"])
            rs.update({"to": 0, "leaves": []})
            files["registry/run-set.json"] = json.dumps(rs).encode()
        self.assert_incomplete(self.mutate(out, empty), "bad registry range 0..0")
        self.assertEqual(self.check(self.mutate(out, empty), "run-set")[2]["detail"], "INCOMPLETE, registry 0..0")

    def test_only_the_selected_run_may_be_outside_the_range(self):
        x, y = self.register(), self.register()
        self.finish(x, y)
        self.s.checkpoint()
        n1 = self.registry_note()[0]
        self.finish(self.register())
        self.s.checkpoint()
        n2 = self.registry_note()[0]
        out = self.export(run_set=(n1, n2), run_id=x["run_id"])
        code, rep, line = self.check(out, "run-set")
        self.assertEqual((code, line["status"]), (0, "pass"), rep.checks)
        other = self.export(run_set=(n1, n2), run_id=y["run_id"], name="y.tkb")
        with zipfile.ZipFile(other) as z:
            y_run = run_name("acme", y["run_id"])
            y_files = {y_run: z.read(y_run)}
            y_proofs = json.loads(z.read("proofs/records.json"))

        def add_y(files, manifest):
            proofs = json.loads(files["proofs/records.json"])
            self.assertEqual(proofs["tree_size"], y_proofs["tree_size"])
            proofs["inclusion"].update(y_proofs["inclusion"])
            files["proofs/records.json"] = json.dumps(proofs).encode()
            files.update(y_files)
            manifest["files"].update(dict.fromkeys(y_files, ""))
        self.assert_incomplete(self.mutate(out, add_y), "only the selected run may be in no leaf")

    def test_registry_notes_grow_survive_restart_and_are_consistent(self):
        self.finish(self.register())
        self.s.checkpoint()
        first = self.registry_note()
        self.finish(self.register(), self.register())
        self.s.checkpoint()
        second = self.registry_note()
        self.assertGreater(second[0], first[0])
        tree = registry_tree("acme")
        with self.assertRaises(ValueError):
            self.s.log.storage.checkpoint_put(first[0], first[1], tree)
        self.s.close()
        self.s = self.open()
        st = self.s.log.storage
        self.assertEqual((st.checkpoint_latest(tree), st.checkpoint_at(tree, first[0])), (second, first[1]))
        origin = registry.origin(self.s.origin, self.s.log.tenant_salt("acme"))
        vkey = checkpoint.vkey(origin, checkpoint.ED25519, checkpoint.parse_vkey(self.s.vkey)[3])
        (n1, r1), (n2, r2) = (checkpoint.open_note(n, [vkey])[1:3] for _, n in (first, second))
        self.assertTrue(verify_consistency(n1, n2, r1, r2, st.registry_merkle("acme").consistency_proof(n1, n2)))

        out = self.export(run_set=(n1, n2))
        code, rep, line = self.check(out, "run-set")
        self.assertEqual((code, line["detail"]), (0, "COMPLETE, registry 2..6 (2 runs registered, 2 final, 0 open)"), rep.checks)
        self.assertIn("keys", rep.warnings)   # the range starts after registry size 0: retirements before it unseen

        def bad_proof(files, manifest):
            rs = json.loads(files["registry/run-set.json"])
            rs["consistency"][0] = base64.b64encode(bytes(32)).decode()
            files["registry/run-set.json"] = json.dumps(rs).encode()
        self.assert_incomplete(self.mutate(out, bad_proof), "is not a prefix of")


class TestLogClosed(RunSet):
    def test_closed_log_refuses_writes_and_covers_the_tail(self):
        a = self.register()
        self.finish(a)
        open_run = self.register()
        self.register("beta")
        self.s.close()
        cfg = os.path.join(self.dir, "signer.yaml")
        with open(cfg, "w") as f:
            json.dump({"data_dir": ".", "tenant": "acme"}, f)
        self.assertEqual(run_cli("signer", "close-log", "--config", cfg)[0], 0)
        self.s = self.open()
        last = self.s.log.storage.iter_range(self.s.log.head["seq"] - 1, self.s.log.head["seq"]).__next__()["event"]
        self.assertEqual((last["type"], last["data"]["final_seq"]), ("log.closed", last["seq"]))
        self.assertEqual(self.s.log.storage.checkpoint_latest()[0], last["seq"] + 1)   # the final note covers it
        for tenant in ("acme", "beta"):
            self.assertEqual(registry.parse(list(self.s.log.storage.registry_iter(tenant))[-1])[0], "log.closed")
        with self.assertRaises(RPCError) as cm:
            self.register()
        self.assertEqual(cm.exception.code, "unavailable")
        with self.assertRaises(RPCError):
            self.call("close_run", open_run)

        out = os.path.join(self.dir, "closed.tkb")
        code, stdout, err = run_cli("export", "--v2", "--run-set", "--config", cfg, "-o", out)
        self.assertEqual((code, err), (0, ""))
        code, rep, line = self.check(out, "log tail")
        self.assertEqual((code, rep.warnings, line["status"]), (0, [], "pass"), rep.checks)


if __name__ == "__main__":
    unittest.main()
