"""Reconciliation across capture layers in the v2 signer (tracekit/signer/reconcile.py), its coverage line in the v2
verifier, and eval E10."""
import importlib.util
import io
import json
import os
import shutil
import time
import unittest

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from test_signer_lifecycle import Lifecycle
from test_signer_service import ME, records
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def use(tcid, tool="read_file", args=None, **kw):
    return {"id": tcid, "name": tool, "executed_by": "client", "args_source": "parsed",
            "args_digest": event_hash({"tool": tool, "args": {} if args is None else args}), **kw}


class Reconcile(Lifecycle):
    def setUp(self):
        super().setUp()
        self.seq = {}

    def next(self, run):
        n = self.seq[run["run_id"]] = self.seq.get(run["run_id"], -1) + 1
        return n

    def model(self, run, uses=(), sent=()):
        self.call("model_event", self.ev(run, self.next(run), provider="p", model="m", phase="response",
                                         tool_uses=list(uses), tool_results_sent=list(sent)))

    def run_call(self, run, tcid, tool="read_file", args=None, source="parsed"):
        args = {} if args is None else args
        self.call("decide", self.ev(run, self.next(run), tool_call_id=tcid, tool=tool, args_source=source, args=args))

    def final(self, *runs):
        """Close `runs` and end their grace window; the reconcile records (type, tool_call_id) and run.final of each."""
        for run in runs:
            if not self.s.log.runs[("default", run["run_id"])]["closed"]:
                self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        self.close()
        out = []
        for run in runs:
            es = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]]
            out.append(([(e["type"], e["tool_call_id"]) for e in es if e["type"].startswith("reconcile.")], es[-1]))
        return out


class TestReconcile(Reconcile):
    def test_each_kind(self):
        runs = [self.register() for _ in range(5)]
        missing, fabricated, mismatch, unparseable, result = runs
        self.model(missing, [use("tc-1"), use("tc-2")])
        self.run_call(missing, "tc-1")
        self.model(fabricated, [use("tc-1")])
        self.run_call(fabricated, "tc-1")
        self.run_call(fabricated, "tc-2")
        self.model(mismatch, [use("tc-1"), use("tc-2")])
        self.run_call(mismatch, "tc-1", "write_file")
        self.run_call(mismatch, "tc-2", args={"path": "b"})
        self.model(unparseable, [{"id": "tc-1", "name": "read_file", "executed_by": "client", "args_source": "raw",
                                  "args_unparseable": True}])
        self.run_call(unparseable, "tc-1")
        self.model(result, [use("tc-1")], sent=["tc-0"])
        self.run_call(result, "tc-1")
        got = [found for found, _ in self.final(*runs)]
        self.assertEqual(got, [[("reconcile.hook_missing", "tc-2")], [("reconcile.fabricated", "tc-2")],
                               [("reconcile.args_mismatch", "tc-1"), ("reconcile.args_mismatch", "tc-2")],
                               [("reconcile.args_unparseable", "tc-1")], [("reconcile.result_without_call", "tc-0")]])

    def test_coerced_and_provider_executed_are_not_flagged_and_final_states_coverage(self):
        run = self.register()
        self.model(run, [use("tc-1", args={"n": "1"}), {"id": "ws-1", "name": "web_search", "executed_by": "provider"}])
        self.run_call(run, "tc-1", args={"n": 1}, source="coerced")
        [(found, final)] = self.final(run)
        self.assertEqual(found, [])
        self.assertEqual(final["data"]["coverage"], {"layers": ["L2", "L3"], "reconciled": 1, "unreconciled": {}})

    def test_late_l3_inside_grace_is_matched(self):
        run = self.register()
        self.run_call(run, "tc-1")
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 30)
        self.model(run, [use("tc-1")])
        [(found, final)] = self.final(run)
        self.assertEqual((found, final["data"]["coverage"]["reconciled"]), ([], 1))

    def test_run_without_l3_is_not_flagged(self):
        run = self.register()
        self.run_call(run, "tc-1")
        self.call("state_write", self.ev(run, self.next(run), key="k", value_digest="sha256:" + "0" * 64))
        [(found, final)] = self.final(run)
        self.assertEqual(found, [])
        self.assertEqual(final["data"]["coverage"], {"layers": ["L1", "L2"], "reconciled": 0, "unreconciled": {}})

    def test_index_is_released_at_final(self):
        run = self.register()
        self.model(run, [use("tc-1")])
        self.run_call(run, "tc-1")
        state = self.s.log.runs[("default", run["run_id"])]
        self.assertEqual((list(state["rec"]["l2"]), list(state["rec"]["l3"])), (["tc-1"], ["tc-1"]))
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        state = self.s.log.runs[("default", run["run_id"])]
        self.assertTrue(state["final"])
        self.assertNotIn("rec", state)
        self.assertNotIn("digests", state)

    def test_index_survives_a_restart(self):
        for replay in (False, True):   # from the snapshot close() writes, or (no snapshot) from the log
            with self.subTest(replay=replay):
                self.setUp()
                run = self.register()
                self.run_call(run, "tc-1")
                self.close()
                if replay:
                    shutil.rmtree(os.path.join(self.dir, "store", "snapshots"))
                self.s = svc.SignerService(self.dir, grace_s=60, idle_s=60)
                self.closed = False
                self.model(run, [use("tc-1", args={"other": 1})])   # the decide's digest is gone: name only
                [(found, _)] = self.final(run)
                self.assertEqual(found, [])

    def test_client_cannot_send_reconcile_records(self):
        run = self.register()
        self.refused("invalid_request", "model_event", self.ev(run, 0, provider="p", model="m", phase="response",
                                                               type="reconcile.fabricated"))
        with self.assertRaises(RPCError) as cm:
            self.s.handle_frame(ME, {"method": "reconcile.hook_missing", "request_id": "x"})
        self.assertEqual(cm.exception.code, "invalid_request")
        [(found, _)] = self.final(run)
        self.assertEqual(found, [])


class TestCoverageLine(Reconcile):
    def verify(self, run):
        trust, out = os.path.join(self.dir, "trust.json"), os.path.join(self.dir, f"{run['run_id']}.tkb")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, checkpoint.ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        store = FileStorage(os.path.join(self.dir, "store"))
        try:
            size = store.tree.size
            text = checkpoint.body(ORIGIN, size, store.tree.root_at(size))
            export(store, "default", run["run_id"], text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET), out)
        finally:
            store.close()
        rep, code = v2.verify(out, trust)
        s = io.StringIO()
        v2.print_report(rep, code, s)
        return rep, code, s.getvalue()

    def test_unreconciled_calls_are_a_coverage_warning(self):
        clean, flagged = self.register(), self.register()
        for run in (clean, flagged):
            self.model(run, [use("tc-1")])
            self.run_call(run, "tc-1")
        self.run_call(flagged, "tc-2")
        self.final(clean, flagged)
        rep, code, text = self.verify(clean)
        self.assertEqual((code, "coverage" in rep.warnings), (0, False))
        self.assertIn("[PASS] coverage — layers L2+L3; 1 call(s) reconciled; unreconciled: none", text)
        rep, code, text = self.verify(flagged)
        self.assertEqual((code, "coverage" in rep.warnings), (0, True))   # --strict exits 3 on it
        self.assertIn("[WARN] coverage — layers L2+L3; 1 call(s) reconciled; unreconciled: fabricated 1", text)
        self.assertIn("reconcile.fabricated tc-2", text)

    def test_run_without_l3_says_so(self):
        run = self.register()
        self.run_call(run, "tc-1")
        self.final(run)
        self.assertIn("[PASS] coverage — layers L2 (L3 absent); 0 call(s) reconciled", self.verify(run)[2])


class TestE10(unittest.TestCase):
    def test_e10_flags_every_seeded_discrepancy_and_no_clean_run(self):
        spec = importlib.util.spec_from_file_location("e10", os.path.join(ROOT, "eval", "e10_reconcile.py"))
        e10 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(e10)
        out = e10.run()
        self.assertTrue(out["ok"], [x for x in out["rows"] if not x["ok"]])
        self.assertEqual((out["seeded"], out["seeded_flagged"], out["false_positives"]), (12, 12, 0))
