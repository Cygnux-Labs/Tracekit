"""Causeway integration (#14): anchors make Causeway runs tamper-evident, test verdicts become signed findings, and
Tracekit runs export into Causeway's format (checked with Causeway's own verifier when installed).
python3 -m pytest tests/test_causeway.py -q"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, causeway, install  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402

try:
    from causeway.core import load_run as cw_load, verify as cw_verify
    HAVE_CW = True
except ImportError:
    HAVE_CW = False


def make_cw_run(path, n=4, tests=()):
    """A small Causeway run written to the documented format (no package needed)."""
    os.makedirs(os.path.join(path, "blobs"), exist_ok=True)
    events, prev = [], causeway.GENESIS
    for i in range(n):
        val = {"step": i}
        ref = causeway.cw_content_hash(val)
        json.dump({"v": val}, open(os.path.join(path, "blobs", ref[7:] + ".json"), "w"))
        ev = {"schema": "causeway.event.v1", "seq": i, "id": f"{i:032x}", "prev_hash": prev, "ts": "2026-10-07T00:00:00.000000Z",
              "run_id": os.path.basename(path), "agent": "a", "type": "run.start" if i == 0 else "input", "ref": ref, "source": "x",
              "trust": "trusted", "kind": "input"}
        ev["hash"] = causeway.cw_event_hash(ev)
        prev = ev["hash"]
        events.append(ev)
    with open(os.path.join(path, "events.jsonl"), "w") as f:
        f.writelines(json.dumps(e, sort_keys=True) + "\n" for e in events)
    if tests:
        with open(os.path.join(path, "tests.jsonl"), "w") as f:
            f.writelines(json.dumps(t, sort_keys=True) + "\n" for t in tests)
    return path


TESTS = [{"intervention": "input:vendor:*", "target": "tool=send_email", "n": 40, "p_with": 0.8, "p_without": 0.0, "effect": 0.8,
          "ci": [0.63, 0.9], "verdict": "causal", "method": "paired re-execution"},
         {"intervention": "input:web:faq", "target": "tool=send_email", "n": 40, "p_with": 0.8, "p_without": 0.8, "effect": 0.0,
          "ci": [-0.18, 0.18], "verdict": "no-detectable-effect", "method": "paired re-execution"}]


class Integration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def records(self):
        return causeway._records(self.home)

    def test_anchor_detects_every_kind_of_change(self):
        run = make_cw_run(os.path.join(self.d, "cw-1"), tests=TESTS)
        status, v, seq = causeway.anchor(self.home, run)
        self.assertEqual(status, "anchored")
        self.assertEqual(causeway.anchor(self.home, run)[0], "unchanged")  # idempotent
        self.assertTrue(causeway.check(self.records(), run)[0])
        lines = open(os.path.join(run, "events.jsonl")).read().splitlines()

        def rewrite(i, **kw):  # an attacker who rebuilds a consistent Causeway chain
            evs = [json.loads(x) for x in lines]
            evs[i].update(kw)
            prev = causeway.GENESIS
            for e in evs:
                e["prev_hash"] = prev
                e["hash"] = causeway.cw_event_hash(e)
                prev = e["hash"]
            open(os.path.join(run, "events.jsonl"), "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in evs))
        rewrite(2, source="edited")
        ok, why = causeway.check(self.records(), run)
        self.assertFalse(ok)
        self.assertIn("rewritten", why[0])
        open(os.path.join(run, "events.jsonl"), "w").write("\n".join(lines[:2]) + "\n")
        self.assertIn("removed", causeway.check(self.records(), run)[1][0])
        open(os.path.join(run, "events.jsonl"), "w").write("\n".join(lines) + "\n")
        open(os.path.join(run, "tests.jsonl"), "a").write(json.dumps({"verdict": "causal"}) + "\n")
        ok, why = causeway.check(self.records(), run)
        self.assertFalse(ok)
        self.assertTrue(any("tests.jsonl changed" in x for x in why))

    def test_broken_chain_is_not_anchored(self):
        run = make_cw_run(os.path.join(self.d, "cw-bad"))
        p = os.path.join(run, "events.jsonl")
        lines = open(p).read().splitlines()
        e = json.loads(lines[1])
        e["source"] = "edited-without-rehash"
        lines[1] = json.dumps(e)
        open(p, "w").write("\n".join(lines) + "\n")
        self.assertEqual(causeway.anchor(self.home, run)[0], "refused")

    def test_tests_become_signed_findings_and_bundle_verifies(self):
        run = make_cw_run(os.path.join(self.d, "cw-2"), tests=TESTS)
        with self.assertRaises(RuntimeError):
            causeway.import_tests(self.home, run)  # not anchored yet
        causeway.anchor(self.home, run)
        wrote = causeway.import_tests(self.home, run)
        self.assertEqual([w["rule"] for w in wrote], ["TK-C001", "TK-C003"])
        self.assertEqual(causeway.import_tests(self.home, run), [])  # idempotent
        out = os.path.join(self.d, "a.tkb")
        bundle.export(self.home, out, run="anchors:causeway:cw-2")
        rep, code = bundle.verify(out)
        self.assertEqual(code, 0, rep.failures)
        chk = next(c for c in rep.checks if c["check"] == "findings cite intact evidence")
        self.assertIn("2 signed finding", chk["detail"])
        self.assertFalse([r for r in self.records() if r["event"]["type"] == "capture.gap"])

    def test_export_tracekit_run_as_causeway(self):
        with Tracer(agent="bot", session_id="tk-1", cwd=self.d) as t:
            t.prompt("fix the bug")
            with t.tool("Bash", {"command": "pytest"}) as c:
                c.result("1 failed")
            try:
                with t.tool("Bash", {"command": "sudo rm -rf /"}):
                    pass
            except PermissionError:
                pass
        path, n = causeway.export(self.home, "tk-1", os.path.join(self.d, "runs"))
        events, blobs, _, _ = causeway.load(path)
        self.assertEqual(causeway.chain_problems(events, blobs), [])
        self.assertEqual([e["type"] for e in events], ["run.start", "agent.start", "input", "action", "run.end"])
        self.assertEqual(events[0]["meta"]["source"], "tracekit")
        m = json.load(open(os.path.join(path, "tracekit-map.json")))
        recs = {r["event"]["seq"]: r["hash"] for r in self.records()}
        self.assertTrue(all(recs[x["seq"]] == x["hash"] for x in m["events"].values()), "every exported event maps to a signed record")
        if HAVE_CW:
            self.assertEqual(cw_verify(cw_load(path)), [], "Causeway's own verifier accepts the export")

    @unittest.skipUnless(HAVE_CW and shutil.which("causeway"), "causeway not installed")
    def test_real_causeway_demo_run(self):
        out = os.path.join(self.d, "demo")
        subprocess.run(["causeway", "demo", "--out", out], check=True, capture_output=True, timeout=600)
        run = os.path.join(out, "demo-seed0")
        self.assertEqual(causeway.anchor(self.home, run)[0], "anchored")
        wrote = causeway.import_tests(self.home, run)
        self.assertTrue(any(w["rule"] == "TK-C001" and "vendor" in w["title"] for w in wrote))
        p = subprocess.run([sys.executable, "-m", "tracekit", "causeway", "verify", "--home", self.home, run], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
