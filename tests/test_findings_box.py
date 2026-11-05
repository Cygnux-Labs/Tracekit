"""TK-X212 (tracekit/findings_box.py): a Tracekit Box box run's door records against its agent channel's runs, on
run-set bundles that verify (factories.BoxScene: an in-process signer on a synthetic clock, the records Box's daemon
writes and the agent's hook calls), read back from the bundle with the vault's content: each finding kind, each way it
can't tell, and a clean box."""
import contextlib
import io
import os
import shutil
import tempfile
import time
import types
import unittest
from unittest import mock

from factories import BoxScene
from test_findings_v2 import Via
from tracekit import findings, findings_box, findings_effects, findings_v2
from tracekit.bundle_v2 import export
from tracekit.verify import v2
from tracekit.why.import_v2 import bundle_records
from tracekit.why.signed import vault_content

PROJ = "/home/dev/proj"


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.box = BoxScene(self.d, workspace=PROJ)
        self.addCleanup(self.box.close)

    def content(self, recs):
        return vault_content(self.box, recs, "test")

    def analyze(self, end=40.0, of="box", others=True, content=True, **kw):
        """The run-set's bundle, verified and read back; TK-X212 of the box run (or of agent run `of`)."""
        bundle, trust, box_id, agents = self.box.bundle(end)
        runs, rep, code = bundle_records(bundle, trust)
        self.assertEqual(code, 0, rep.checks)
        self.ids = box_id, agents
        run_id = box_id if of == "box" else agents[of]
        get = self.content if content else None
        return findings_v2.analyze(runs[run_id], get, others=(runs, get) if others else None,
                                   effects=findings_effects.options(), **kw)

    @staticmethod
    def found(out):
        return [(f, d) for f, d in zip(out["findings"], out["shown"]["details"])
                if f["verdict"]["rule"] == "TK-X212"]

    @staticmethod
    def cov(out):
        c = out["coverage"]["verdict"]["checks"]["TK-X212"]
        return c["checked"], c["found"], {g["reason"]: g["n"] for g in c["not_checkable"]}


class Clean(Base):
    def test_a_box_whose_doors_match_its_agents_account_has_no_finding(self):
        b = self.box
        b.agent(1.0)
        b.door(0.5, "https://api.anthropic.com:443")                 # the harness's model API, before its hooks start
        b.call(2.0, 3.0, "WebFetch", {"url": "https://docs.example.com/guide", "prompt": "summarise"})
        b.door(2.4, "https://docs.example.com:443")                  # the fetch's connection
        b.call(4.0, 4.5, "Write", {"file_path": "/workspace/app.py", "content": "x"})
        b.call(5.0, 6.0, "Bash", {"command": "pip install -r requirements.txt"})
        b.door(5.5, "https://pypi.org:443")                          # in the shell's window
        b.write(30.0, f"{PROJ}/app.py")                              # apply, after the box stopped
        out = self.analyze()
        self.assertEqual(self.found(out), [])
        self.assertEqual(self.cov(out), (4, 0, {"model_host": 1}))   # 2 connections, the file and the fetch
        self.assertNotIn("TK-X212", [f["verdict"]["rule"] for f in out["findings"]])
        text = findings_v2.render(out)
        self.assertIn("TK-X212 for 1 door event: a connection to a model API host", text)
        self.assertIn("TK-X212 80% (4 checked, 0 found)", text)


class DoorEventNoCallExplains(Base):   # (a)
    def test_a_connection_outside_every_call_is_found_naming_both_sides_and_holding_no_plaintext(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.2, "Read", {"file_path": "/workspace/README.md"})
        b.door(10.0, "https://exfil.example.net:443")
        b.door(12.0, "https://exfil.example.net:443", allowed=False)
        out = self.analyze()
        [(f, d)] = self.found(out)
        box_id, [agent] = self.ids
        self.assertEqual(f["verdict"], {"kind": "finding", "rule": "TK-X212", "severity": "high",
                                        "window": {"grace_s": 2.0, "skew_s": 0.0}})
        doors = [r for r in bundle_runs(self)[box_id] if r["event"]["type"] in ("policy.decision", "tool.result")
                 and "egress" in r["event"]["data"]["tool_use_id"]]
        self.assertEqual(f["cites"], [{"run_seq": r["event"]["run_seq"], "hash": r["hash"]} for r in doors])
        self.assertEqual(d["labels"], ["door_unexplained"])
        self.assertIn("connect to exfil.example.net 2 times (1 let through, 1 refused; the first at box run record",
                      d["what"])
        self.assertIn(f"while the agent's run {agent} was open", d["what"])
        self.assertIn(f"the agent's last call before it: Read (run {agent}, record", d["what"])
        self.assertIn("8.0 s earlier", d["what"])
        self.assertNotIn("exfil", str(out["findings"]))   # the signed part: rule, severity, window, cites
        self.assertEqual(self.cov(out), (2, 1, {}))
        self.assertIn("HIGH · Agent's account and the box's doors disagree  (TK-X212) [door_unexplained]",
                      findings_v2.render(out))

    def test_a_connection_a_fetch_of_another_host_was_in_progress_for_is_found(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 4.0, "WebFetch", {"url": "https://docs.example.com/a"})
        b.door(2.5, "https://docs.example.com:443")
        b.door(3.0, "https://other.example.org:443")
        out = self.analyze()
        [(f, d)] = self.found(out)
        self.assertIn("other.example.org", d["what"])

    def test_a_file_of_the_patch_no_write_call_named_is_found(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Edit", {"file_path": "/workspace/src/app.py", "old_string": "a", "new_string": "b"})
        b.call(3.0, 3.5, "Write", {"file_path": "/workspace/src/fail.py", "content": "x"}, ok=False)
        b.write(30.0, f"{PROJ}/src/app.py")
        b.write(30.1, f"{PROJ}/.github/workflows/ci.yml")
        b.write(30.2, f"{PROJ}/src/fail.py")   # its write call said it failed
        out = self.analyze()
        whats = sorted(d["what"] for _, d in self.found(out))
        self.assertEqual(len(whats), 2)
        self.assertIn("the box's patch changes .github/workflows/ci.yml (written back at apply", whats[0])
        self.assertIn("named /workspace/.github/workflows/ci.yml", whats[0])
        self.assertIn("changes src/fail.py", whats[1])
        self.assertEqual([f["verdict"].get("window") for f, _ in self.found(out)], [None, None])
        self.assertEqual(self.cov(out), (3, 2, {}))


class AgentCallNoDoorEvent(Base):   # (b)
    def test_a_fetch_that_returned_ok_with_no_connection_is_found(self):
        b = self.box
        b.agent(1.0)
        tid = b.call(5.0, 6.0, "WebFetch", {"url": "https://example.org/report", "prompt": "read"})
        b.observe(20.0, "tkbox.box", {"event": "stopped", "box_id": "b-1"}, "trusted")
        out = self.analyze()
        [(f, d)] = self.found(out)
        box_id, [agent] = self.ids
        after = [r for r in bundle_runs(self)[box_id] if r["event"]["type"] == "input.observed"][-1]   # at 20 s
        self.assertEqual((f["verdict"]["severity"], d["labels"]), ("medium", ["no_door_event"]))
        self.assertEqual(f["cites"], [{"run_seq": after["event"]["run_seq"], "hash": after["hash"]}])
        self.assertIn(f"the agent's WebFetch of example.org (run {agent}, call {tid}, records", d["what"])
        self.assertIn("returned ok, but no connection to example.org crossed the box's door from the box's start to "
                      f"2 s after that result (the box run's records up to {after['event']['run_seq']})", d["what"])

    def test_a_fetch_that_failed_claims_nothing(self):
        self.box.agent(1.0)
        self.box.call(5.0, 6.0, "WebFetch", {"url": "https://example.org/report"}, ok=False)
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (0, 0, {})))


class OutcomeMismatch(Base):   # (c)
    def test_a_fetch_that_returned_ok_while_the_door_refused_it_is_found(self):
        b = self.box
        b.agent(1.0)
        b.call(5.0, 6.0, "WebFetch", {"url": "http://blocked.example.com/x"})
        b.door(5.2, "http://blocked.example.com:80", allowed=False)
        b.door(5.4, "https://blocked.example.com:443", allowed=False)
        out = self.analyze()
        [(f, d)] = self.found(out)
        self.assertEqual((f["verdict"]["severity"], d["labels"]), ("high", ["door_refused"]))
        self.assertEqual(len(f["cites"]), 4)   # both refusals: their decisions and results
        self.assertIn("returned ok, but Box's door refused every connection to blocked.example.com in that call's "
                      "window (box run records", d["what"])
        self.assertEqual(self.cov(out), (3, 1, {}))   # the two connections (the fetch explains them) and the fetch

    def test_one_connection_let_through_is_enough(self):
        b = self.box
        b.agent(1.0)
        b.call(5.0, 6.0, "WebFetch", {"url": "https://flaky.example.com/x"})
        b.door(5.2, "https://flaky.example.com:443", allowed=False)
        b.door(5.4, "https://flaky.example.com:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (3, 0, {})))


class CantTell(Base):
    """Each way TK-X212 can't tell, counted not checkable with its reason, never a finding."""

    def assert_only(self, out, reasons):
        self.assertEqual(self.found(out), [])
        self.assertEqual(self.cov(out)[2], reasons)
        text = findings_v2.render(out)
        for r in reasons:
            self.assertIn(findings_v2.REASONS[r][0], text)

    def test_a_connection_before_the_agents_hooks_started_or_after_it_closed_its_run(self):
        b = self.box
        b.door(0.5, "https://deb.debian.org:443")
        b.agent(1.0)
        b.stop(5.0)
        b.door(10.0, "https://late.example.com:443")   # the box still runs
        self.assert_only(self.analyze(), {"no_agent_run": 2})

    def test_a_command_box_started_during_the_agents_run(self):
        b = self.box
        b.agent(1.0)
        b.command(5.0, 8.0, "git fetch")                 # an operator's tkbox exec, not the agent's
        b.door(6.0, "https://github.com:443")
        b.write(30.0, f"{PROJ}/out.bin")                 # it may have written this too
        self.assert_only(self.analyze(), {"host_command": 2})

    def test_the_command_the_agent_ran_in_explains_nothing(self):
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")   # the agent's own, started before its hooks registered
        b.agent(1.0)
        b.door(6.0, "https://github.com:443")
        out = self.analyze()
        self.assertEqual(len(self.found(out)), 1)

    def test_a_shell_call_that_left_a_process_running(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Bash", {"command": "npm run dev > dev.log 2>&1 &"})
        b.door(10.0, "https://registry.npmjs.org:443")
        b.agent(11.0)
        b.call(12.0, 12.5, "Bash", {"command": "sleep 100", "run_in_background": True}, run=1)
        b.door(20.0, "https://telemetry.example.com:443")
        self.assert_only(self.analyze(), {"background": 2})

    def test_a_shell_call_that_backgrounds_nothing_explains_nothing_later(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Bash", {"command": "make && echo 'a & b'"})
        b.door(10.0, "https://registry.npmjs.org:443")
        self.assertEqual(len(self.found(self.analyze())), 1)

    def test_a_call_with_no_result(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, None, "Bash", {"command": "./build.sh"})
        b.door(10.0, "https://cdn.example.com:443")
        self.assert_only(self.analyze(), {"call_unfinished": 1})

    def test_a_shell_call_ran_so_any_file_of_the_patch_may_be_its(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "Bash", {"command": "make generate"})
        b.write(30.0, f"{PROJ}/gen/schema.go")
        self.assert_only(self.analyze(), {"shell_ran": 1})

    def test_a_file_applied_to_another_directory(self):
        b = self.box
        b.agent(1.0)
        b.write(30.0, "/srv/other-checkout/app.py")
        self.assert_only(self.analyze(), {"apply_dir": 1})

    def test_a_fetch_an_earlier_connection_may_have_served(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://docs.example.com/a"})
        b.door(2.5, "https://docs.example.com:443")
        b.call(10.0, 11.0, "WebFetch", {"url": "https://docs.example.com/b"})
        out = self.analyze()
        self.assertEqual(self.found(out), [])
        self.assertEqual(self.cov(out), (2, 0, {"reused": 1}))

    def test_a_fetch_box_refused_itself_records_later(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://10.0.0.5/admin"})
        b.observe(3.5, "tkbox.egress", {"host": "10.0.0.5", "port": 443, "decision": "deny",
                                        "reason": "a private address"})
        b.call(10.0, 11.0, "WebFetch", {"url": "https://flood.example.com/"})
        b.observe(12.0, "tkbox.egress", {"decision": "deny", "summary": True, "suppressed": 40})
        self.assert_only(self.analyze(), {"box_refusal": 2})

    def test_a_connection_with_no_recorded_outcome(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://slow.example.com/"})
        b.door(2.5, "https://slow.example.com:443", allowed=None)
        out = self.analyze()
        self.assertEqual(self.found(out), [])
        self.assertEqual(self.cov(out), (1, 0, {"no_outcome": 1}))

    def test_a_fetch_whose_url_box_would_not_see(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://bücher.example/"})
        b.call(4.0, 5.0, "WebFetch", {"url": "not a url"})
        self.assert_only(self.analyze(), {"no_url": 2})

    def test_no_vault_content(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://example.org/"})
        b.door(10.0, "https://exfil.example.net:443")
        self.assert_only(self.analyze(content=False), {"no_content": 1, "no_url": 1})

    def test_past_the_budget_the_rest_is_incomplete(self):
        b = self.box
        b.agent(1.0)
        b.door(10.0, "https://exfil.example.net:443")
        out = self.analyze(budget_s=-1)
        self.assertEqual(self.cov(out)[2], {"budget": 1})
        self.assertIn("INCOMPLETE", out["summary"])
        self.assertIn("TK-X212 for 1 record: the analysis ran out of time", findings_v2.render(out))

    def test_a_box_run_analysed_without_its_agent_runs(self):
        b = self.box
        b.agent(1.0)
        b.door(10.0, "https://exfil.example.net:443")
        b.write(30.0, f"{PROJ}/app.py")
        self.assert_only(self.analyze(others=False), {"no_agent_runs": 2})

    def test_an_agent_run_points_to_its_box_run(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://example.org/"})
        out = self.analyze(of=0)
        self.assert_only(out, {"agent_run": 1})
        self.assertIn("TK-X212 for 1 call: this is a box's agent run", findings_v2.render(out))


class Signed(Base):
    def test_its_findings_are_signed_about_the_box_run_and_verify_with_it(self):
        b = self.box
        b.agent(1.0)
        b.call(5.0, 6.0, "WebFetch", {"url": "https://example.org/report"})
        b.door(10.0, "https://exfil.example.net:443")
        out = self.analyze()
        self.assertEqual(len(self.found(out)), 2)
        box_id, _ = self.ids
        me = types.SimpleNamespace(call=self.box.call_as_me, content_get=self.box.content_get)
        findings_run = findings_v2.sign(Via(me), box_id, out)
        self.assertEqual(out["signed"]["records"], out["signed"]["of"])
        s = self.box.s
        s.sweep(time.monotonic() + 1)
        s.checkpoint()
        st = s.log.storage
        path = os.path.join(self.d, "box-findings.tkb")
        export(st, "default", box_id, st.checkpoint_latest()[1], path, with_runs=[findings_run])
        rep, code = v2.verify(path, os.path.join(self.d, "box-runset-trust.json"))
        self.assertEqual(code, 0, rep.checks)
        self.assertIn("2 finding(s) (1 high, 1 medium)", rep.findings)

    def test_the_store_holds_the_box_runs_agent_runs(self):
        b = self.box
        b.agent(1.0)
        b.agent(2.0)
        self.box.bundle(40.0)
        box_id = self.box.box["handle"]["run_id"]
        runs = findings_box.store_runs(os.path.join(self.d, "data"), box_id)
        self.assertEqual(sorted(runs), sorted(a["handle"]["run_id"] for a in self.box.agents))
        self.assertEqual(findings_box.store_runs(os.path.join(self.d, "data"), sorted(runs)[0]), {})


class Cli(Base):
    """`tracekit analyze --v2 --run BOX` from a run-set bundle and from the store: the box's agent runs come along."""

    def cli(self, *args):
        me = types.SimpleNamespace(call=self.box.call_as_me, content_get=self.box.content_get)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("tracekit.sdk.client.Client", return_value=Via(me)), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = findings.main(["--v2", "--dry-run", *args])
        return code, out.getvalue(), err.getvalue()

    def test_a_box_run_from_a_run_set_bundle_or_the_store(self):
        b = self.box
        b.command(0.2, 35.0, "claude -p 'make the failing test pass'")   # the agent's own command
        b.door(0.5, "https://api.anthropic.com:443")
        b.agent(1.0)
        b.call(2.0, 2.4, "WebFetch", {"url": "https://docs.python.org/3/library/json.html"})
        b.door(2.2, "https://docs.python.org:443")
        b.call(3.0, 3.2, "Edit", {"file_path": "/workspace/src/app.py", "old_string": "a", "new_string": "b"})
        b.door(8.0, "https://collector.example.io:443")
        b.call(12.0, 12.4, "WebFetch", {"url": "https://pastebin.example.net/raw/x1"})
        b.door(12.2, "https://pastebin.example.net:443", allowed=False)
        b.call(16.0, 16.4, "WebFetch", {"url": "https://example.org/changelog"})
        b.write(36.0, f"{PROJ}/src/app.py")
        b.write(36.1, f"{PROJ}/.github/workflows/release.yml")
        bundle, trust, box_id, [agent] = b.bundle(40.0)
        for source in (["--bundle", bundle, "--trust", trust], ["--store", os.path.join(self.d, "data")]):
            with self.subTest(source[0]):
                code, out, err = self.cli("--run", box_id, *source)
                self.assertEqual((code, err), (4, ""))   # a high finding
                self.assertEqual(out.count("(TK-X212)"), 4)
                self.assertIn("Box's door saw the box connect to collector.example.io 1 time", out)
                self.assertIn("the box's patch changes .github/workflows/release.yml", out)
                self.assertIn(f"the agent's WebFetch of pastebin.example.net (run {agent}", out)
                self.assertIn(f"the agent's WebFetch of example.org (run {agent}", out)
                self.assertIn("TK-X212 for 1 door event: a connection to a model API host", out)
                self.assertIn("TK-X212 89% (8 checked, 4 found)", out)
        code, out, _ = self.cli("--run", agent, "--bundle", bundle, "--trust", trust)
        self.assertEqual(code, 0)
        self.assertIn("TK-X212 for 4 calls: this is a box's agent run", out)


def bundle_runs(case):
    """The runs of the run-set bundle case.analyze() exported."""
    runs, _, code = bundle_records(os.path.join(case.d, "box-runset.tkb"),
                                   os.path.join(case.d, "box-runset-trust.json"))
    assert code == 0
    return runs


if __name__ == "__main__":
    unittest.main()
