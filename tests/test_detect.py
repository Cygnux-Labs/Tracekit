"""Signer-side detection (tracekit/signer/detect.py): the policy's sequences, limits and respond sections, the decision's
`detect` field, incidents, `tracekit policy backtest`, and eval E17 part 1."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

from tracekit import bundle_v2, cli, schema
from tracekit.policy2 import compile as pc
from tracekit.signer import detect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("e17_detection", os.path.join(ROOT, "eval", "e17_detection.py"))
e17 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e17)
EGRESS, SECRET, POLICY, Signer, engine = e17.EGRESS, e17.SECRET, e17.POLICY, e17.Signer, e17.engine


def lint(**changes):
    """The lint errors of POLICY with `changes` (a None value drops the key)."""
    pol = {k: v for k, v in {**POLICY, **changes}.items() if v is not None}
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "p.json")
        with open(path, "w") as f:
            json.dump(pol, f)
        return pc.build(path)[1]
    finally:
        shutil.rmtree(d, True)


class TestE17(unittest.TestCase):
    def test_every_scenario_holds(self):
        for name, f in e17.SCENARIOS.items():
            with self.subTest(name):
                ok, detail = f()
                self.assertTrue(ok, detail)


class TestLint(unittest.TestCase):
    def test_the_shipped_policy_lints_clean(self):
        self.assertEqual(lint(), [])

    def test_errors(self):
        seq = POLICY["sequences"][0]
        cases = {
            "unknown rule id or label 'nope'": {"sequences": [{**seq, "steps": ["secret", "nope"]}]},
            "can never count: only deny rules carry it": {"sequences": [{**seq, "steps": ["T-DENY", "egress"]}]},
            "window must be whole seconds": {"sequences": [{**seq, "window": 0}]},
            "need unknown_tools flag, ask or deny": {"unknown_tools": None},
            "is a raw tool name": {"limits": [{"id": "L", "match": "shell", "count": True, "max": 3, "window": 60}]},
            "needs `count: true` or `sum": {"limits": [{"id": "L", "match": "destructive", "max": 3, "window": 60}]},
            "is notify-only": {"respond": [{"trigger": "tamper", "mode": "enforce", "action": "hold"}]},
            "trigger must be a sequence or limit id": {"respond": [{"trigger": "nope", "mode": "shadow",
                                                                   "action": "notify"}]},
            "scope must be one of": {"sequences": [{**seq, "scope": "tenant"}]},
        }
        for want, change in cases.items():
            with self.subTest(want):
                errors = lint(**change)
                self.assertTrue(any(want in e for e in errors), errors)


class Case(unittest.TestCase):
    def signer(self, pol=None):
        s = Signer(engine(pol) if pol else None)
        self.addCleanup(s.close)
        return s


class TestDecisions(Case):
    def test_decisions_say_what_detection_saw_and_records_are_schema_valid(self):
        s = self.signer()
        run = s.register()
        s.decide(run, SECRET)
        s.decide(run, EGRESS)
        decisions = [e["data"]["detect"] for e in s.events(run) if e["type"] == "policy.decision"]
        self.assertEqual(decisions, [{"sequences": [{"id": "Q", "step": 1}], "limits": [], "state": "complete"},
                                     {"sequences": [{"id": "Q", "step": 2}], "limits": [], "state": "complete"}])
        [opened] = s.incidents(run)
        self.assertEqual({k: opened[k] for k in ("trigger", "rule_ids", "mode", "actions", "would")},
                         {"trigger": "sequence", "rule_ids": ["Q"], "mode": "shadow", "actions": [], "would": []})
        self.assertEqual([c["run_seq"] for c in opened["cites"]],
                         [e["run_seq"] for e in s.events(run) if e["type"] == "policy.decision"])
        for e in s.events():
            self.assertEqual(schema.validate(e), [], e["type"])
        self.assertEqual(bundle_v2.needs(s.events(run)), "1.2.0")

    def test_a_policy_without_detection_writes_no_detect_field(self):
        s = self.signer({k: v for k, v in POLICY.items() if k not in pc.DETECT})
        run = s.register()
        s.decide(run, SECRET)
        self.assertIsNone(s.s.log.detector)
        self.assertNotIn("detect", s.events(run)[-1]["data"])

    def test_a_limit_opens_one_incident_and_updates_it(self):
        s = self.signer()
        run = s.register()
        for _ in range(5):   # max 3: the 4th opens, the 5th is in the same window but already past max: nothing
            s.decide(run, ("shell", {"command": "rm a"}))
        counts = [e["data"]["detect"]["limits"][0]["count"] for e in s.events(run) if e["type"] == "policy.decision"]
        self.assertEqual(counts, [1, 2, 3, 4, 5])
        self.assertEqual([i["rule_ids"] for i in s.incidents(run)], [["L"]])

    def test_later_matches_update_the_open_incident(self):
        s = self.signer()
        run = s.register()
        s.decide(run, SECRET)
        s.decide(run, EGRESS)
        s.decide(run, EGRESS)
        [opened], [updated] = s.incidents(run), s.incidents(run, "incident.updated")
        self.assertEqual(updated["incident_id"], opened["incident_id"])

    def test_a_class_hint_cant_hide_a_step(self):
        s = self.signer()
        run = s.register()
        # the policy reads http (egress only); the hint's fs reading also sees the secret path
        s.decide(run, ("http_get", {"url": "https://example.org/", "path": "/srv/app/.env"}), hint="fs")
        s.decide(run, EGRESS)
        first = next(e for e in s.events(run) if e["type"] == "policy.decision")
        self.assertEqual(sorted(first["data"]["detect"]["rule_ids"]), ["T-EGRESS", "T-SECRET"])
        self.assertEqual([i["rule_ids"] for i in s.incidents(run)], [["Q"]])

    def test_an_asked_step_counts_once_its_approval_is_consumed(self):
        pol = {**POLICY, "tools": {**POLICY["tools"], "vault": "fs"},
               "ask": [{"id": "T-VAULT", "tool": "vault", "pattern": "^", "label": "secret"}]}
        s = self.signer(pol)
        run = s.register()
        call = ("vault", {"path": "k"})
        s.decide(run, call, tcid="tc-v")
        s.decide(run, EGRESS)
        self.assertEqual(s.incidents(run), [])   # asked, not consumed: no step
        aid = s.call("approval_request", {**run, "tool_call_id": "tc-v"})["approval_id"]
        s.call("approval_decide", {"approval_id": aid, "decision": "approve"})
        out = s.call("approval_consume", {**run, "tool_call_id": "tc-v", "tool": "vault", "args_source": "parsed",
                                          "args": call[1]})
        self.assertTrue(out["ok"], out)
        s.decide(run, EGRESS)
        self.assertEqual([i["rule_ids"] for i in s.incidents(run)], [["Q"]])

    def test_a_sum_limit_needs_an_amount_and_currency(self):
        pol = {**POLICY, "tools": {**POLICY["tools"], "pay": "payment"},
               "flag": POLICY["flag"] + [{"id": "T-PAY", "tool": "pay", "pattern": "^", "label": "payment"}],
               "limits": [{"id": "S", "match": "payment", "sum": {"field": "cents", "currency_field": "currency"},
                           "max": 1000, "window": 60}]}
        s = self.signer(pol)
        run = s.register()
        bad = s.decide(run, ("pay", {"cents": "600"}))
        self.assertEqual((bad["decision"], bad["rule_ids"][-1]), ("ask", detect.SUM_UNREADABLE))
        s.decide(run, ("pay", {"cents": 600, "currency": "USD"}))
        s.decide(run, ("pay", {"cents": 600, "currency": "EUR"}))   # another currency: its own total
        self.assertEqual(s.incidents(run), [])
        s.decide(run, ("pay", {"cents": 600, "currency": "USD"}))
        last = s.events(run)[-2]
        self.assertEqual(last["data"]["detect"]["sums"], {"S": [600, "USD"]})
        self.assertEqual(last["data"]["detect"]["limits"][0]["count"], 1200)
        self.assertEqual([i["rule_ids"] for i in s.incidents(run)], [["S"]])

    def test_respond_off_writes_no_incident_and_built_in_triggers_need_an_entry(self):
        s = self.signer({**POLICY, "respond": [{"trigger": "Q", "mode": "off", "action": "notify"}]})
        run = s.register()
        s.decide(run, SECRET)
        s.decide(run, EGRESS)
        for i in range(4):
            s.decide(run, ("read_file", {"path": f"/forbidden/{i}"}))
        self.assertEqual(s.incidents(run), [])

    def test_incidents_are_capped_with_a_summary(self):
        s = self.signer()
        run = s.register()
        with mock.patch.object(detect, "RUN_CAP", 2):
            s.decide(run, SECRET)
            for _ in range(4):
                s.decide(run, EGRESS)
        types = [e["type"] for e in s.events(run) if e["type"].startswith("incident.")]
        self.assertEqual(types, ["incident.opened", "incident.updated", "incident.capped"])

    def test_executed_against_policy_opens_an_incident(self):
        s = self.signer({**POLICY, "respond": [{"trigger": "executed_against_policy", "mode": "enforce",
                                                "action": "quarantine"}]})
        run = s.register()
        d = s.decide(run, ("read_file", {"path": "/forbidden"}))
        s.call("complete", {**run, "stream": "s", "client_seq": 1, "tool_call_id": "tc-0", "decision_id": d["decision_id"],
                            "status": "ok", "result": "x", "args_digest": e17_digest("read_file", {"path": "/forbidden"})})
        [i] = s.incidents(run)
        self.assertEqual((i["trigger"], i["mode"], i["would"]), ("executed_against_policy", "shadow", ["quarantine"]))

    def test_state_lost_in_a_restart_is_unavailable(self):
        s = self.signer({k: v for k, v in POLICY.items() if k not in pc.DETECT})
        run = s.register()
        s.s.close()   # its snapshot holds no detection state
        s.eng = engine()
        s.open()
        s.decide(run, SECRET)
        self.assertEqual(s.events(run)[-1]["data"]["detect"]["state"], "unavailable")

    def test_a_snapshot_under_another_policy_is_not_reused(self):
        s = self.signer()
        run = s.register()
        s.decide(run, SECRET)
        s.decide(run, ("shell", {"command": "rm a"}))
        s.s.close()   # its snapshot holds Q's and L's state
        s.eng = engine({**POLICY, "sequences": [{**POLICY["sequences"][0], "steps": ["secret", "egress", "egress"]}],
                        "limits": [{"id": "L", "match": "destructive", "sum": {"field": "n", "currency_field": "c"},
                                    "max": 3, "window": 60}]})
        s.open()
        s.decide(run, EGRESS)
        s.decide(run, ("shell", {"command": "rm b", "n": 1, "c": "USD"}))
        self.assertEqual([e["data"]["detect"]["state"] for e in s.events(run)[-2:]], ["unavailable"] * 2)

    def test_an_idle_scope_starts_over_by_the_records_clock(self):
        s = self.signer()
        run = s.register()
        for _ in range(4):
            s.decide(run, ("shell", {"command": "rm a"}))
        events = [e for e in s.events(run) if not e["type"].startswith("incident.")]
        later = [{**e, "ts": e["ts"][:2] + str(int(e["ts"][2:4]) + 1) + e["ts"][4:], "tool_call_id": "x" + e["tool_call_id"]}
                 for e in events if e["type"] == "policy.decision"]   # a year later: past every window
        det, state, out = detect.Detector(s.eng), detect.new(), []
        for e in events + later:
            for typ, data in det.observe(detect.Plain, state, e)[1]:
                out.append(typ)
                det.observe(detect.Plain, state, {**e, "type": typ, "data": data})
        self.assertEqual(out, ["incident.opened", "incident.opened"])


def e17_digest(tool, args):
    from tracekit.format.canon import event_hash
    return event_hash({"tool": tool, "args": args})


class TestCost(Case):
    def test_ack_seconds_does_not_grow_with_the_run(self):
        s = self.signer()
        run = s.register()
        h = s.s.metrics.ack_seconds

        def mean_of(n):
            before = (h._sum, sum(h._counts))
            for i in range(n):
                s.decide(run, ("shell", {"command": "rm a"}) if i % 2 else SECRET)
            return (h._sum - before[0]) / (sum(h._counts) - before[1])
        first = mean_of(100)
        mean_of(800)
        last = mean_of(100)
        self.assertLess(last, 3 * first + 0.005, (first, last))


class TestBacktest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.policy = os.path.join(self.d, "p.json")
        with open(self.policy, "w") as f:
            json.dump(POLICY, f)

    def backtest(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["policy", "backtest", "--policy", self.policy, *args])
        return code, out.getvalue()

    def test_store_and_bundle(self):
        s = Signer(engine({k: v for k, v in POLICY.items() if k not in pc.DETECT}))   # recorded without detection
        run = s.register()
        s.decide(run, SECRET)
        s.decide(run, EGRESS)
        records = [json.loads(line) for line in open(os.path.join(s.dir, "store", "records.jsonl"), "rb")]
        s.s.close()
        code, out = self.backtest("--store", os.path.join(s.dir, "store"))
        shutil.rmtree(s.dir, True)
        self.assertEqual(code, 0)
        self.assertIn("incident.opened", out)
        self.assertIn("sequence Q scope session", out)
        self.assertTrue(out.rstrip().endswith("1 incident(s) would open"), out)
        bundle = os.path.join(self.d, "b.tkb")
        with zipfile.ZipFile(bundle, "w") as z:
            z.writestr("runs/a.jsonl", "".join(json.dumps(r) + "\n" for r in records))
        self.assertEqual(self.backtest("--bundle", bundle), (code, out))

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["policy", "backtest", "--policy", self.policy]), 2)
            self.assertEqual(cli.main(["policy", "lint", self.policy, "--store", self.d]), 2)
