"""Reconciliation across capture layers in the v2 signer (tracekit/signer/reconcile.py), its coverage line in the v2
verifier, and eval E10."""
import importlib.util
import io
import json
import os
import shutil
import time
import unittest
import unittest.mock

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from test_signer_lifecycle import Lifecycle
from test_signer_service import ME, records
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.policy2.engine import Engine
from tracekit.signer import reconcile, service as svc
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


class Wording(unittest.TestCase):
    def test_under_gateway_mandatory_a_decide_the_agent_reported_is_called_a_call_around_the_gateway(self):
        run = {"rec": reconcile.new(), "digests": {}}
        put = lambda d, k, v: d.__setitem__(k, v)
        reconcile.observe(put, run, {"type": "policy.decision", "tool_call_id": "tc-1", "args_source": "parsed",
                                     "source": "sdk", "data": {"tool": "cancel_ticket", "decision": "allow",
                                                               "rule_ids": []}})
        reconcile.observe(put, run, {"type": "model.exchange", "source": "sdk", "data": {"tool_uses": [use(
            "tc-1", "cancel_ticket")]}})
        self.assertEqual(reconcile._found(run, mandatory=False), [])
        [(kind, tcid, _, detail)] = reconcile._found(run, mandatory=True)
        self.assertEqual((kind, tcid), ("fabricated", "tc-1"))
        self.assertIn("no gateway exchange asked for: the agent reported the model asking for it", detail)
        self.assertNotIn("never asked", detail)


    def test_a_coerced_decide_does_not_hide_other_arguments_than_the_gateway_saw(self):
        put = lambda d, k, v: d.__setitem__(k, v)
        for source, gateway, mandatory in (("gateway", True, True), ("gateway", True, False), ("sdk", False, False)):
            with self.subTest(l3=source, mandatory=mandatory):
                run = {"rec": reconcile.new(), "digests": {}}
                reconcile.observe(put, run, {"type": "model.exchange", "source": source, "data": {"tool_uses": [
                    use("tc-1", "Bash")]}}, digests={"tc-1": event_hash({"tool": "Bash", "args": {"command": "x"}})})
                reconcile.observe(put, run, {"type": "policy.decision", "tool_call_id": "tc-1", "args_source": "coerced",
                                             "source": "sdk", "data": {"tool": "Bash", "decision": "allow",
                                                                       "rule_ids": []}},
                                  digests={"tc-1": event_hash({"tool": "Bash", "args": {"command": "ls"}})})
                found = [(k, detail) for k, _, _, detail in reconcile._found(run, mandatory)]
                self.assertEqual(found, [("args_mismatch", "decided other arguments than the model asked for (the "
                                          "decide says a framework coerced them)")] if gateway else [])


class TestReconcile(Reconcile):
    def handoff_run(self):
        run = self.register()
        self.model(run, [use("tc-1", "transfer_to_refunds_agent"), use("tc-2", "issue_refund")])
        self.model(run, [], sent=["tc-1"])   # the SDK sends the handoff's output back: asked for, not fabricated
        return run

    def test_a_handoff_is_a_missing_decide_unless_the_policy_names_it(self):
        run = self.handoff_run()
        [(found, _)] = self.final(run)
        self.assertEqual(found, [("reconcile.hook_missing", "tc-1"), ("reconcile.hook_missing", "tc-2")])
        details = [r["event"]["data"]["detail"] for r in records(self.dir) if r["event"]["type"] == "reconcile.hook_missing"]
        self.assertIn("name it in the policy's handoffs:", details[0])   # what to do, for the handoff only
        self.assertNotIn("handoffs", details[1])
        self.assertIn("or the framework turned it down before any hook (arguments that failed its validation)",
                      details[1])   # not only "ran ungated": PydanticAI re-asks after failed validation, undecided

    def test_a_handoff_the_policy_names_is_not_a_missing_decide(self):
        self.s.policy = Engine({**self.s.policy.policy, "handoffs": ["transfer_to_refunds_agent"]})   # the operator
        [(found, _)] = self.final(self.handoff_run())
        self.assertEqual(found, [("reconcile.hook_missing", "tc-2")])

    def test_calls_in_the_models_structured_output_are_not_compared_with_its_tool_uses(self):
        """Browser Use asks for its actions as structured output (here through the forced AgentOutput tool call):
        neither the decides nor the output tool reconcile against L3 once the policy names them (unnamed, the same run
        is a hook_missing and a fabricated: test_each_kind)."""
        self.s.policy = Engine({**self.s.policy.policy, "structured_output": ["browser_use:*", "AgentOutput"]})
        run = self.register()
        self.model(run, [use("tc-out", "AgentOutput")])
        self.run_call(run, "tc-1", "browser_use:click", {"index": 3})
        self.run_call(run, "tc-2", "read_file")   # any other tool still is
        [(found, final)] = self.final(run)
        self.assertEqual(found, [("reconcile.fabricated", "tc-2")])
        self.assertEqual(final["data"]["coverage"]["layers"], ["L2", "L3"])

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

    def test_an_mcp_call_matches_only_the_names_a_framework_shows_the_model(self):
        cases = [("mcp:filesystem/read_text_file", "read_text_file", {}),
                 ("mcp:filesystem/read_text_file", "mcp__filesystem__read_text_file", {}),
                 ("mcp:filesystem/read_text_file", "mcp_filesystem__read_text_file", {}),
                 ("mcp:filesystem/read_text_file", "filesystem_read_text_file", {}),   # no server_tool suffix match
                 ("mcp:filesystem/read_text_file", "fs.read_text_file", {}),
                 ("mcp:filesystem/read_text_file", "read_text_file_x", {}),
                 ("mcp:x/account", "delete_account", {}),   # a renamed call can't hide behind a suffix
                 ("mcp:filesystem/read_text_file", "read_text_file", {"path": "/etc/passwd"}),   # other arguments
                 # another server's call can't be decided under a server or tool name that spells its prefixed form
                 ("mcp:_prod/drop_table", "mcp__prod__drop_table", {}),
                 ("mcp:prod_/drop_table", "mcp_prod___drop_table", {}),
                 ("mcp:z/mcp__prod__drop_table", "mcp__prod__drop_table", {}),
                 ("mcp:z/mcp_prod__drop_table", "mcp_prod__drop_table", {})]
        run = self.register()
        self.model(run, [use(f"tc-{i}", asked) for i, (_, asked, _) in enumerate(cases)])
        for i, (decided, _, args) in enumerate(cases):
            self.run_call(run, f"tc-{i}", decided, args)
        [(found, _)] = self.final(run)
        self.assertEqual(found, [("reconcile.args_mismatch", f"tc-{i}") for i in range(3, 12)])

    def test_coerced_and_provider_executed_are_not_flagged_and_final_states_coverage(self):
        run = self.register()
        self.model(run, [use("tc-1", args={"n": "1"}), {"id": "ws-1", "name": "web_search", "executed_by": "provider"}])
        self.run_call(run, "tc-1", args={"n": 1}, source="coerced")
        [(found, final)] = self.final(run)
        self.assertEqual(found, [])
        self.assertEqual(final["data"]["coverage"], {"layers": ["L2", "L3"], "reconciled": 1, "unreconciled": {}})

    def test_a_call_decided_under_an_id_of_its_own_pairs_by_arguments_in_its_turn_only(self):
        paired, ambiguous, later, other = runs = [self.register() for _ in range(4)]
        self.model(paired, [use("call_1", args={"path": "a"}), use("call_2", args={"path": "b"})])
        self.run_call(paired, "crewai-1", args={"path": "a"})
        self.run_call(paired, "crewai-2", args={"path": "b"})
        self.model(ambiguous, [use("call_1"), use("call_2")])   # two of the same call: which is which is unknown
        self.run_call(ambiguous, "crewai-1")
        self.run_call(ambiguous, "crewai-2")
        self.model(later, [use("call_1")])
        self.model(later, [use("call_2", "write_file")])   # the next turn
        self.run_call(later, "crewai-1")
        self.model(other, [use("call_1", args={"path": "a"})])
        self.run_call(other, "crewai-1", args={"path": "b"})
        (found, final), *rest = self.final(*runs)
        self.assertEqual((found, final["data"]["coverage"]["reconciled"], final["data"]["paired_by_args"]), ([], 2, 2))
        self.assertEqual([sorted(f) for f, _ in rest], [
            [("reconcile.fabricated", "crewai-1"), ("reconcile.fabricated", "crewai-2"),
             ("reconcile.hook_missing", "call_1"), ("reconcile.hook_missing", "call_2")],
            [("reconcile.fabricated", "crewai-1"), ("reconcile.hook_missing", "call_1"),
             ("reconcile.hook_missing", "call_2")],
            [("reconcile.fabricated", "crewai-1"), ("reconcile.hook_missing", "call_1")]])
        self.assertNotIn("paired_by_args", rest[0][1]["data"])

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


class Observe(unittest.TestCase):
    """reconcile.observe on its own: a run index fed the records the writer writes."""

    def run_(self):
        return {"rec": reconcile.new(), "digests": {}}

    def exchange(self, run, source, uses=(), sent=()):
        e = {"type": "model.exchange", "source": source, "tool_call_id": None,
             "data": {"tool_uses": [{"id": u, "name": "read_file", "executed_by": "client"} for u in uses],
                      "tool_results_sent": list(sent)}}
        return reconcile.observe(dict.__setitem__, run, e, {u: "sha256:" + u[-1] * 64 for u in uses})

    def decide(self, run, tcid, digest_of):
        e = {"type": "policy.decision", "source": "sdk", "tool_call_id": tcid,
             "data": {"tool": "read_file", "decision": "allow", "rule_ids": []}}
        return reconcile.observe(dict.__setitem__, run, e, {tcid: "sha256:" + digest_of[-1] * 64})

    def test_a_second_copy_of_a_response_stays_in_its_turn(self):
        for order in (("gateway", "sdk"), ("sdk", "gateway")):
            with self.subTest(order=order):
                run = self.run_()
                for source in order:   # the gateway and the agent's autotrace both record the one response
                    self.exchange(run, source, ["call_1"])
                self.decide(run, "crewai-1", "call_1")
                self.assertEqual(reconcile.paired(run, False), {"call_1": "crewai-1"})
                self.assertEqual(self.exchange(run, "gateway", sent=["call_1"]), [])   # no live hook_missing

    def test_the_live_check_reads_one_turn_not_the_run(self):
        run = self.run_()
        for i in range(300):   # one id-less call per turn under the gateway
            tcid = f"call_{i}"
            self.exchange(run, "gateway", [tcid], sent=[f"call_{i - 1}"] if i else [])
            self.decide(run, f"crewai-{i}", tcid)
        self.assertEqual(self.exchange(run, "gateway", sent=["call_299"]), [])
        with unittest.mock.patch.object(reconcile, "paired", side_effect=AssertionError("whole-run pairing")):
            self.exchange(run, "gateway", ["call_x"], sent=["call_299"])

    def test_the_live_check_agrees_with_the_run_end_pairing(self):
        run = self.run_()
        self.exchange(run, "gateway", ["call_1", "call_2"])
        self.decide(run, "crewai-1", "call_1")
        self.decide(run, "crewai-2", "call_1")   # two decides with call_1's arguments: ambiguous, no pair
        found = self.exchange(run, "gateway", ["call_3"], sent=["call_1", "call_2"])
        self.assertEqual(sorted(t for _, t, *_ in found), ["call_1", "call_2"])
        self.assertEqual(reconcile.paired(run, False), {})


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

    def test_calls_paired_by_arguments_are_named(self):
        run = self.register()
        self.model(run, [use("call_1")])
        self.run_call(run, "crewai-1")
        self.final(run)
        line = "[PASS] coverage — layers L2+L3; 1 call(s) reconciled (1 paired by arguments: no tool-call id)"
        self.assertIn(line, self.verify(run)[2])
        import test_ts_verifier as tv
        if not tv.SKIP:
            out = tv.ts_verify(os.path.join(self.dir, f"{run['run_id']}.tkb"), os.path.join(self.dir, "trust.json"))
            self.assertIn("1 call(s) reconciled (1 paired by arguments: no tool-call id)",
                          next(c["detail"] for c in out["checks"] if c["check"] == "coverage"))

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
