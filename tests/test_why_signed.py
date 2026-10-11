"""`tracekit why` on the v2 signer: the signer-backed runtime, `why import --store/--bundle` with the merge, `why verify
--salts`, and `tracekit demo --why`. A real dev signer serves each class, in a temp dir.

    python3 -m pytest tests/test_why_signed.py -q
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tracekit import demo_why
from tracekit.demo_server import Witness, _serve, export_final, tamper
from tracekit.deploy import files
from tracekit.sdk.client import Client
from tracekit.signer.service import SignerService, reveal
from tracekit.why import import_v2
from tracekit.why.analysis import alerts
from tracekit.why.cli import main
from tracekit.why.core import Runtime, load_run
from tracekit.why.graph import build_graph
from tracekit.why.replay import System, replay

RAN = []


def bash(command):
    RAN.append(command)
    return {"stdout": "ok"}


def program(rt):
    a = rt.agent("a")
    note = a.observe("a page", source="web:page", trust="untrusted")
    d = a.decide([rt.task_ref, note], model="m", purpose="p")
    for command in ("ls", "sudo rm -rf /", 'echo "unterminated'):   # the dev pack: allow, deny, ask
        a.act("Bash", {"command": command}, decision=d)


SYSTEM = System(program=program, models={"m": lambda ctx, **kw: {"calls": 3}}, tools={"Bash": bash}, task="list files",
                name="tests.test_why_signed:SYSTEM")


def record(**kw):
    rt = Runtime(SYSTEM.models, SYSTEM.tools, task=SYSTEM.task, program=SYSTEM.name, **kw)
    program(rt)
    return rt.finish()


class SignedRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="tk-why-", dir="/tmp" if os.path.isdir("/tmp") else None)
        cls.witness = Witness()
        cls.service = SignerService(os.path.join(cls.dir, "data"), witnesses=[cls.witness], isolation="same-user",
                                    grace_s=0.2, fsck_every_s=0)
        cls.path, cls.srv = _serve(cls.dir, cls.service)
        cls.client = Client(cls.path)
        cls.runs = os.path.join(cls.dir, "runs")
        del RAN[:]
        cls.why = record(out_dir=cls.runs, run_id="r", signer=cls.client, approval_wait_s=0.2)
        cls.tk_run = cls.why.of_type("agent.start")[0]["tracekit"]["run_id"]

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.service.close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def records(self):
        return import_v2.store_records(os.path.join(self.dir, "data"))

    def actions(self, run=None):
        run = run or self.why
        return {run.value(e["args_ref"])["command"]: e for e in run.of_type("action")}

    def test_every_event_cites_the_record_it_produced(self):
        recs = {r["event"]["run_seq"]: r["event"] for r in self.records()[self.tk_run]}
        want = {"agent.start": "run.registered", "input": "input.observed", "decision": "model.exchange"}
        for e in self.why.events:
            if e["type"] in want and e["agent"] != "run":   # the task: observed in each agent's run as it registers
                self.assertEqual(recs[e["tracekit"]["run_seq"]]["type"], want[e["type"]], e)
        acts = self.actions()
        self.assertEqual(recs[acts["ls"]["tracekit"]["run_seq"]]["type"], "tool.result")
        self.assertEqual(recs[acts["sudo rm -rf /"]["tracekit"]["run_seq"]]["type"], "policy.decision")

    def test_the_model_call_names_the_tool_calls_it_led_to(self):
        uses = [u for r in self.records()[self.tk_run] if r["event"]["type"] == "model.exchange"
                for u in r["event"]["data"].get("tool_uses", [])]
        self.assertEqual(sorted(u["id"] for u in uses), sorted(e["tracekit"]["tool_call_id"]
                                                               for e in self.why.of_type("action")))

    def test_a_deny_comes_back_as_the_blocked_result_and_the_tool_does_not_run(self):
        e = self.actions()["sudo rm -rf /"]
        self.assertEqual((e["status"], e["mode"], e["policy"]["decision"]), ("blocked", "blocked", "deny"))
        self.assertEqual(self.why.value(e["result_ref"]), {"error": "blocked by policy: " + ", ".join(e["policy"]["rule_ids"])})
        self.assertNotIn("sudo rm -rf /", RAN)
        self.assertIn("ls", RAN)

    def test_an_ask_nobody_approves_is_blocked(self):
        e = self.actions()['echo "unterminated']
        self.assertEqual((e["status"], e["policy"]["decision"], e["policy"]["approval"]["state"]),
                         ("blocked", "ask", "requested"))
        self.assertIn("tracekit approvals", self.why.value(e["result_ref"])["error"])
        self.assertNotIn('echo "unterminated', RAN)

    def test_replays_write_no_evidence(self):
        before = self.records()
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": self.path}):   # a recording would find the signer
            replay(load_run(self.why.path), system=SYSTEM)
        self.assertEqual(self.records(), before)

    def test_the_guard_is_not_asked_when_the_signer_gates(self):
        class Refuse:
            def describe(self):
                return {}

            def check(self, *a):
                raise AssertionError("asked the guard")
        record(signer=self.client, guard=Refuse(), approval_wait_s=0)

    def test_import_merges_the_why_log_with_its_records(self):
        out = tempfile.mkdtemp(dir=self.dir)
        shutil.copytree(self.why.path, os.path.join(out, "r"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["import", "--store", os.path.join(self.dir, "data"), "--out", out]), 0)
        self.assertIn("merged with", buf.getvalue())
        merged = load_run(os.path.join(out, "tk-r"))
        acts = self.actions(merged)
        self.assertEqual(acts["ls"]["tracekit"]["log_id"], self.service.log.log_id)
        self.assertIn("commitment", acts["ls"]["tracekit"])
        self.assertEqual(acts["sudo rm -rf /"]["policy"]["decision"], "deny")
        self.assertEqual(acts["ls"]["args_ref"], self.actions()["ls"]["args_ref"])   # content from the why log
        self.assertFalse([e for e in merged.events if e.get("tracekit_mismatch")])

    def test_a_citation_that_does_not_match_its_record_is_flagged(self):
        run = load_run(self.why.path)
        inp = next(e for e in run.events if e["type"] == "input" and e.get("tracekit"))
        inp["tracekit"]["run_seq"] = self.actions(run)["ls"]["tracekit"]["run_seq"]
        merged = load_run(import_v2.merge(run, self.records(), tempfile.mkdtemp(dir=self.dir), {}))
        bad = next(e for e in merged.events if e["id"] == inp["id"])
        self.assertIn("not a input.observed", bad["tracekit_mismatch"])
        titles = [a["title"] for a in alerts(merged, build_graph(merged))]
        self.assertTrue(any("does not match the signed record" in t for t in titles), titles)
        self.assertTrue(any("failed its integrity check" in t for t in titles), titles)   # the edit broke its chain

    def test_content_is_checked_against_the_commitments(self):
        out = tempfile.mkdtemp(dir=self.dir)
        shutil.copytree(self.why.path, os.path.join(out, "r"))
        merged = load_run(import_v2.import_records(self.records(), out)[0])
        cited = [e for e in merged.events if "commitment" in e.get("tracekit", {})]
        salts = os.path.join(out, "salts.jsonl")
        with open(salts, "w") as f:
            for e in cited[:-1]:
                f.write(json.dumps(reveal(os.path.join(self.dir, "data"), e["tracekit"]["seq"])) + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify", merged.path, "--salts", salts]), 0)
        verdicts = [r["verdict"] for r in import_v2.check_content(merged, [json.loads(x) for x in open(salts)])]
        self.assertEqual(verdicts, ["matched"] * (len(cited) - 1) + ["not revealed"])
        inp = next(e for e in cited if e["type"] == "input")
        merged.blobs[inp["ref"]] = "another page"
        rows = import_v2.check_content(merged, [json.loads(x) for x in open(salts)])
        self.assertEqual(next(r for r in rows if r["event"] == inp["id"])["verdict"], "mismatched")
        again = load_run(merged.path)
        self.assertIn("Content does not match what the signer committed to",
                      [a["title"] for a in alerts(again, build_graph(again))])

    def test_a_bundle_imports_only_if_it_verifies(self):
        out, bad = os.path.join(self.dir, "r.tkb"), os.path.join(self.dir, "bad.tkb")
        export_final(os.path.join(self.dir, "data", "store"), self.tk_run, self.witness, out)
        trust = os.path.join(self.dir, "trust.json")
        files.write_json(trust, {"logs": [self.service.vkey], "algs": ["ed25519"],
                                 "witnesses": [{"vkey": self.witness.vkey, "class": "customer"}]}, 0o644)
        self.assertEqual(list(import_v2.bundle_records(out, trust)[0]), [self.tk_run])
        tamper(out, bad)
        self.assertEqual(import_v2.bundle_records(bad, trust)[0], {})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertNotEqual(main(["import", "--bundle", bad, "--trust", trust, "--out", self.dir]), 0)
        self.assertIn("nothing imported", err.getvalue())


class DemoWhy(unittest.TestCase):
    def test_demo_why_holds(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = demo_why.main()
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("TK-P001: `to` 'audit@vendor-compliance.example' came only from untrusted content", out.getvalue())


if __name__ == "__main__":
    unittest.main()
