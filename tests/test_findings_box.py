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
import uuid
from unittest import mock

from factories import BoxScene
from test_findings_v2 import Via
from tracekit import bundle_v2, findings, findings_box, findings_effects, findings_v2
from tracekit.bundle_v2 import export
from tracekit.signer import rpc_schema
from tracekit.storage.base import registry_tree
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
        return findings_v2.analyze(runs[run_id], get, others=(runs, get, True) if others else None,
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

    def test_a_fetch_an_earlier_connection_may_have_served_is_not_refused(self):   # P3
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://docs.example.com/a"})
        b.door(2.5, "https://docs.example.com:443")
        b.call(10.0, 11.0, "WebFetch", {"url": "https://docs.example.com/a"})            # the tool's cache: ok
        b.call(10.0, 11.5, "WebFetch", {"url": "https://docs.example.com/b"}, ok=False)  # its connection refused
        b.door(10.3, "https://docs.example.com:443", allowed=False)
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (3, 0, {"reused": 1})))

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
        # and on the door side: the refusal, and the 40 the summary stands for
        self.assert_only(self.analyze(), {"box_refusal": 2, "untimed_refusal": 41})

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
        b.call(4.0, 5.0, "WebFetch", {"url": "not a url"})
        b.call(6.0, 7.0, "WebFetch", {"url": "https://example.com:99999/"})   # no port there is
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


class Matching(Base):
    """#608's review: a fetch matches a connection to its host with a leading www. aside, on its URL's port (and 443
    for plain http), its host as Node sends it (punycode, a dotted number form); an unusable URL matches nothing."""

    def test_a_redirect_that_only_adds_www_is_the_fetchs_own(self):   # Claude Code's WebFetch follows it (P1)
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://python.org/downloads/", "prompt": "latest"})
        b.door(2.2, "https://python.org:443")
        b.door(2.5, "https://www.python.org:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (3, 0, {})))

    def test_a_fetch_explains_no_other_port(self):   # H5
        b = self.box
        b.agent(1.0)
        b.call(2.0, 30.0, "WebFetch", {"url": "https://example.com/"})
        b.door(2.5, "https://example.com:443")
        b.door(10.0, "tcp://example.com:22")   # a tunnel while a long fetch runs
        out = self.analyze()
        [(_, d)] = self.found(out)
        self.assertIn("connect to example.com 1 time", d["what"])
        self.assertEqual(self.cov(out), (3, 1, {}))   # :443 the fetch's, :22 found, the fetch matched

    def test_a_fetch_whose_url_box_never_sees_explains_nothing(self):   # H4
        b = self.box
        b.agent(1.0)
        b.call(2.0, 30.0, "WebFetch", {"url": "not a url"})
        b.door(10.0, "https://exfil.example.net:443")
        out = self.analyze()
        self.assertEqual([d["labels"] for _, d in self.found(out)], [["door_unexplained"]])
        self.assertEqual(self.cov(out)[2], {"no_url": 1})

    def test_a_number_form_or_internationalised_host_as_node_sends_it(self):   # P6
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "https://0x5db8d822/"})
        b.door(2.5, "https://93.184.216.34:443")
        b.call(4.0, 5.0, "WebFetch", {"url": "https://bücher.example/"})
        b.door(4.5, "https://xn--bcher-kva.example:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (4, 0, {})))
        self.assertEqual([findings_box._bare(h) for h in ("1572395042", "0135.0xb8.216.34", "0x5db8d822.",
                                                          "08.1.2.3", "example.123")],
                         ["93.184.216.34"] * 3 + [None, None])   # a name ending in a number: an address, or no host

    def test_urls_as_node_reads_them(self):   # #608's second review
        for url, host, dests in (
                ("https://example.com:8080/x", "example.com", {("example.com", 8080)}),
                ("http://example.com:8080/x", "example.com", {("example.com", 8080)}),
                ("https://example.com:443/x", "example.com", {("example.com", 443)}),
                ("http://example.com:80/x", "example.com", {("example.com", 80), ("example.com", 443)}),
                ("https://[2001:DB8:0::1]/x", "2001:db8::1", {("2001:db8::1", 443)}),
                ("https://[::ffff:93.184.216.34]/x", "93.184.216.34", {("93.184.216.34", 443)}),
                ("https://www.example.com/x", "www.example.com", {("example.com", 443)}),
                ("https://exfil.example.net\\@docs.python.org/", "exfil.example.net", {("exfil.example.net", 443)}),
                ("https:///x.example/a", "x.example", {("x.example", 443)}),
                ("HTTPS:\\\\x.example\\a", "x.example", {("x.example", 443)}),
                ("https://exfil.example.net:0/", "exfil.example.net", {("exfil.example.net", 0)}),
                ("https://www.93.184.216.34/", None, set()), ("https://", None, set()),
                ("https://exfil.example.net:99999/", None, set()), ("//exfil.example.net/x", None, set()),
                ("exfil.example.net", None, set()), ("ftp://exfil.example.net/x", None, set()), (None, None, set())):
            with self.subTest(url):
                self.assertEqual(findings_box._dests(url), (host, dests))
        self.assertEqual(findings_box._door("https://www.python.org:443"), ("www.python.org", ("python.org", 443)))
        self.assertEqual(findings_box._door("tcp://example.com:22"), ("example.com", ("example.com", 22)))

    def test_http_to_port_80_upgraded_and_a_www_fetch_of_a_www_host(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 3.0, "WebFetch", {"url": "http://example.com:80/x"})
        b.door(2.5, "https://example.com:443")
        b.call(4.0, 5.0, "WebFetch", {"url": "https://www.example.com/x"})
        b.door(4.2, "https://www.example.com:443")
        b.door(4.4, "https://example.com:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)), ([], (5, 0, {})))

    def test_a_fetch_of_no_url_node_takes_explains_nothing(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 30.0, "WebFetch", {"url": "https://www.93.184.216.34/"})
        b.door(3.0, "https://93.184.216.34:443")
        out = self.analyze()
        self.assertEqual([d["labels"] for _, d in self.found(out)], [["door_unexplained"]])
        self.assertEqual(self.cov(out)[2], {"no_url": 1})

    def test_a_connection_only_a_fetch_of_unknown_arguments_could_explain_is_not_checked(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 30.0, "WebFetch", {"url": "https://example.org/"})
        b.door(10.0, "https://exfil.example.net:443")
        bundle, trust, box_id, _ = b.bundle(40.0)
        runs, _, _ = bundle_records(bundle, trust)

        def content(recs):   # the vault kept the box's records, none of the agent's
            return self.content([r for r in recs if r["event"]["run_id"] == box_id])
        out = findings_v2.analyze(runs[box_id], content, others=(runs, content, True))
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"no_content": 1, "no_url": 1}))


class Background(Base):
    """#608's review: what may leave a process running past its call, and what doesn't."""

    def test_what_a_command_may_leave_running(self):
        for cmd in ("npm run dev &", "(npm run dev > /tmp/dev.log 2>&1 &)", "sleep 1&", "a & b",
                    "bash -c 'npm start &'", 'sh -lc "(x &)"', "tmux new -d -s dev 'npm start'",
                    "screen -dmS dev npm start", "coproc cat", "setsid x", "x; disown", "echo 'unclosed",
                    # #608's second review: options before -c, nested and wrapped shells, commands on their own line
                    "bash -o pipefail -c 'npm run dev &'", "sh -e -c 'npm run dev &'", "bash --norc -c 'npm run dev &'",
                    "bash -c \"sh -c 'npm run dev &'\"", "env -i bash -c 'npm run dev &'",
                    "sudo -u dev bash -c 'npm run dev &'", "cd app && bash -c '(npm start &)'",
                    "timeout 10 bash -c 'x &'", "make\nsetsid x", "if true; then setsid x; fi", "FOO=1 setsid x",
                    "$(cmd &)",
                    # the final check: as bash reads them (policy2.shell): heredocs, comments, continuations, coproc
                    "cat > start.sh <<'EOF'\nnpm run dev\nEOF\nbash -c './start.sh &'",
                    "cat > a.txt <<EOF\nhi\nEOF\ntmux new -d -s dev 'npm start'", 'grep -q x <<< "$v"\ncoproc cat',
                    "cd app # into the app\nbash -c 'npm start &'", "make # build it\ntmux new -d -s dev 'npm run dev'",
                    "npm run dev \\\n&", "echo a\\\\&", "\\coproc cat", "time coproc cat", "builtin coproc cat",
                    # #608's review: a block or an and-or list sent to the background; what runs after the line
                    "{ npm run dev; } &", "while true; do curl -s https://example.com/health; sleep 30; done &",
                    "if true; then npm run dev; fi &", "a && b &", "curl -s https://example.com && x=1 &",
                    "systemd-run --user npm start", "echo 'npm start' | at now + 1 minute", "batch < jobs.txt",
                    "{ npm run dev; } | (x=1) &", "{ npm run dev; } | case q in y) x=1;; esac &"):
            with self.subTest(cmd):
                self.assertTrue(findings_box._detaches(cmd))
        for cmd in ("make && make test", "cmd 2>&1", "cmd &> log", "cmd |& tee log", "cat <&3", "echo 'a & b'",
                    "bash -c 'make && echo ok'", "tmux ls",
                    # #608's second review: a quoted or escaped `&`, the background words as text
                    'echo "&"', "echo '&'", "echo '&)'", 'echo "a &"', "echo a\\&", "grep -c '&' f",
                    "printf '%s\\n' '&'", "echo coproc", "echo 'coproc'", 'echo "coproc cat"', "echo nohup",
                    "grep -rn setsid .", "echo tmux -d", "echo screen -d", "echo bash -c 'x &'",
                    "git log --grep=disown", "cat <<EOF\ncoproc\nEOF",
                    # nohup alone runs in the foreground; quotes that start mid-word (the final check)
                    "nohup x", "\\nohup npm run dev", "git commit -m'fix a & b'", "git commit -qm'fix a & b'",
                    "FOO='a & b' make", "git log --grep='a & b'", "echo x'&'", "echo $'a & b'",
                    'URL="https://x.example/?a=1&b=2" npm test'):
            with self.subTest(cmd):
                self.assertFalse(findings_box._detaches(cmd))

    def test_a_line_nested_too_deep_to_read_is_unreadable_not_a_crash(self):
        # the 1.6.0 review: the parser's RecursionError on deep nesting reached analyze --v2
        self.assertTrue(findings_box._detaches("f() { " * 2000))

    def test_a_dev_server_left_running_as_bash_reads_the_command(self):   # the final check, end to end
        for cmd, found in (("cat > notes.txt <<EOF\nstarting the dev server\nEOF\ntmux new -d -s dev 'npm run dev'", 0),
                           ("cat > start.sh <<'EOF'\nnpm run dev\nEOF\nchmod +x start.sh\nbash -c './start.sh &'", 0),
                           ("cd app # the web app\nbash -c 'npm run dev > dev.log 2>&1 &'", 0),
                           ("{ npm run dev; } &", 0), ("if true; then npm run dev; fi &", 0),   # #608's review
                           ("while true; do curl -s https://telemetry.nextjs.org/health; sleep 30; done &", 0),
                           ("npm ci && npm run dev &", 0),
                           ("git commit -qm'fix a & b'", 1)):   # nothing left running: the later connection is found
            with self.subTest(cmd):
                d = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, d, True)
                self.box = BoxScene(d, workspace=PROJ)
                self.addCleanup(self.box.close)
                self.box.agent(1.0)
                self.box.call(2.0, 2.5, "Bash", {"command": cmd})
                self.box.door(10.0, "https://telemetry.nextjs.org:443")
                out = self.analyze()
                self.assertEqual((len(self.found(out)), self.cov(out)[2]), (found, {} if found else {"background": 1}))

    def test_a_subshell_sent_to_the_background(self):   # P2
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Bash", {"command": "(npm run dev > /tmp/dev.log 2>&1 &)"})
        b.door(10.0, "https://telemetry.nextjs.org:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"background": 1}))

    def test_one_call_marked_background_covers_the_rest_of_its_run_and_says_so(self):   # H3: a documented limit
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.1, "Bash", {"command": "true", "run_in_background": True})
        for t in (100.0, 200.0, 300.0):
            b.door(t, "https://exfil.example.net:443")
        out = self.analyze(end=400.0)
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"background": 3}))


class HostCommandsAndRuns(Base):
    """#608's review: host commands, an agent that keeps no account, and what stays visible as not checkable."""

    def test_two_host_commands_span_the_agents_start(self):   # P4: either may be the agent's
        b = self.box
        b.command(0.1, 35.0, "npm run dev")
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.agent(1.0)
        b.door(10.0, "https://telemetry.nextjs.org:443")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"host_command": 1}))

    def test_a_daemon_a_host_command_left_running_is_found(self):   # P5: a documented limit
        b = self.box
        b.command(0.1, 0.4, "sh -c 'redis-server --daemonize yes'")
        b.command(0.5, 35.0, "claude -p 'fix the bug'")
        b.agent(1.0)
        b.door(10.0, "https://updates.example.com:443")
        self.assertEqual(len(self.found(self.analyze())), 1)

    def test_an_agent_that_never_registers_a_run_is_named_on_the_first_line(self):   # H1
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.door(10.0, "https://exfil.example.net:443")
        b.write(36.0, f"{PROJ}/.github/workflows/ci.yml")
        out = self.analyze()
        self.assertEqual(self.cov(out)[2], {"no_agent_account": 2})
        self.assertIn("NO AGENT ACCOUNT: the box's agent channel was on, and its agent registered no run",
                      out["summary"])
        runs = bundle_runs(self)   # the same box from a source that may not hold every run: no claim either way
        out = findings_v2.analyze(runs[self.ids[0]], self.content, others=(runs, self.content, False))
        self.assertEqual(self.cov(out)[2], {"no_agent_runs": 2})
        self.assertNotIn("NO AGENT ACCOUNT", out["summary"])

    def test_an_agent_that_closes_its_run_early_leaves_the_rest_not_checkable(self):   # H2
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.agent(1.0)
        b.stop(3.0)
        b.door(10.0, "https://exfil.example.net:443")
        self.assertEqual(self.cov(self.analyze())[2], {"no_agent_run": 1})

    def test_a_call_with_no_result_covers_the_rest_of_its_run_and_says_so(self):   # H6: a documented limit
        b = self.box
        b.agent(1.0)
        b.call(2.0, None, "Bash", {"command": "sleep 1"})
        b.door(300.0, "https://exfil.example.net:443")
        self.assertEqual(self.cov(self.analyze(end=400.0))[2], {"call_unfinished": 1})

    def test_box_s_own_refusals_have_no_time_to_place_a_call_against(self):
        b = self.box
        b.agent(1.0)
        b.observe(10.0, "tkbox.egress", {"host": "169.254.169.254", "port": 80, "decision": "deny",
                                         "reason": "a metadata address"})
        b.observe(39.0, "tkbox.gap", {"kind": "tkbox.egress", "dropped": 3, "reason": "the signer did not answer"},
                  "trusted")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"untimed_refusal": 4}))

    def test_a_patch_applied_to_a_directory_under_the_workspace(self):   # P7
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Edit", {"file_path": "/workspace/src/app.py", "old_string": "a", "new_string": "b"})
        b.write(30.0, f"{PROJ}/sub/src/app.py")   # tkbox apply --dir PROJ/sub
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"apply_dir": 1}))

    def test_a_write_call_that_names_no_path(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Write", {"content": "x"})
        b.write(30.0, f"{PROJ}/app.py")
        out = self.analyze()
        self.assertEqual((self.found(out), self.cov(out)[2]), ([], {"no_path": 1}))

    def test_a_connection_with_no_outcome_is_not_counted_refused(self):
        b = self.box
        b.agent(1.0)
        b.door(10.0, "https://exfil.example.net:443", allowed=None)
        [(_, d)] = self.found(self.analyze())
        self.assertIn("(0 let through, 0 refused, 1 with no outcome recorded;", d["what"])


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

    def bundle_leaving_open(self, which, end=40.0):
        """bundle(end), leaving the runs `which(run_id)` picks open: a box stopped mid-session, or still running."""
        real = self.box.s.call

        def call(who, method, req):
            return {} if method == "close_run" and which(req.get("run_id")) else real(who, method, req)
        with mock.patch.object(self.box.s, "call", call):
            return self.box.bundle(end)

    def test_no_agent_account_only_from_a_source_that_holds_every_run(self):   # #608's second review, F1
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.door(10.0, "https://exfil.example.net:443")
        bundle, trust, box_id, _ = b.bundle(40.0)   # a run-set from registry 0, nothing open: the agent registered none
        _, out, _ = self.cli("--run", box_id, "--bundle", bundle, "--trust", trust)
        self.assertIn("NO AGENT ACCOUNT", out.splitlines()[0])
        self.assertIn("TK-X212 for 1 door event: the box ran with its agent channel on, yet its agent registered no "
                      "run", out)

    def test_a_box_stopped_mid_session_is_no_proof_the_agent_registered_nothing(self):
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.agent(1.0)
        b.door(10.0, "https://exfil.example.net:443")
        bundle, trust, box_id, [agent] = self.bundle_leaving_open(lambda r: r != b.box["handle"]["run_id"])
        _, out, _ = self.cli("--run", box_id, "--bundle", bundle, "--trust", trust)   # the agent's open run isn't in it
        self.assertNotIn("NO AGENT ACCOUNT", out)
        self.assertIn("TK-X212 for 1 door event: no run of the box's agent channel is in what was analysed", out)

    def test_a_live_box_whose_agent_has_not_registered_yet(self):
        b = self.box
        b.door(10.0, "https://exfil.example.net:443")
        _, _, box_id, _ = self.bundle_leaving_open(lambda r: r == b.box["handle"]["run_id"])
        _, out, _ = self.cli("--run", box_id, "--store", os.path.join(self.d, "data"), "--open")
        self.assertNotIn("NO AGENT ACCOUNT", out)
        self.assertIn("TK-X212 for 1 door event: no run of the box's agent channel is in what was analysed", out)

    def test_box_refused_the_agents_registration(self):
        b = self.box
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.observe(1.0, "tkbox.channel", {"refusal": "limit", "method": "register_run", "reason": "too many runs"})
        b.door(10.0, "https://exfil.example.net:443")
        bundle, trust, box_id, _ = b.bundle(40.0)
        _, out, _ = self.cli("--run", box_id, "--bundle", bundle, "--trust", trust)
        self.assertNotIn("NO AGENT ACCOUNT", out)
        self.assertIn("TK-X212 for 1 door event: no run of the box's agent channel is in what was analysed", out)

    def test_every_run_needs_a_range_from_0_with_none_open_that_holds_the_box_run(self):
        def rep(**kw):
            return types.SimpleNamespace(run_set={"from": 0, "registered": {"box", "agent"}, "open": set(), **kw})
        self.assertTrue(findings_box.whole(rep(), "box"))
        for r in (rep(**{"from": 3}), rep(open={"agent"}), rep(registered={"agent"}), types.SimpleNamespace(),
                  types.SimpleNamespace(run_set=None)):   # no run-set, or one that didn't verify
            with self.subTest(getattr(r, "run_set", "none")):
                self.assertFalse(findings_box.whole(r, "box"))

    def test_refusals_folded_into_a_count_may_hold_a_registration(self):   # the final check, F1
        b = self.box   # Box events one refusal of a kind a second; the next one's `folded` counts the rest
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        why = "field caller is not passed"
        b.observe(1.0, "tkbox.channel", {"refusal": "field", "method": "decide", "reason": why})
        b.observe(3.0, "tkbox.channel", {"refusal": "field", "method": "observe", "reason": why, "folded": 1})
        b.door(10.0, "https://exfil.example.net:443")
        bundle, trust, box_id, _ = b.bundle(40.0)
        _, out, _ = self.cli("--run", box_id, "--bundle", bundle, "--trust", trust)
        self.assertNotIn("NO AGENT ACCOUNT", out)
        self.assertIn("TK-X212 for 1 door event: no run of the box's agent channel is in what was analysed", out)

    def test_a_run_set_from_0_that_does_not_hold_the_box_run(self):   # the final check, F1
        early, real = {}, BoxScene._register

        def register(scene, who, **kw):   # an earlier run, closed and checkpointed, before the box registers
            if kw.get("box"):
                other = real(scene, scene.me)
                scene.s.call(scene.me, "close_run", {**other["handle"], "request_id": uuid.uuid4().hex})
                scene.s.sweep(time.monotonic() + 1)
                scene.s.checkpoint()
                early["n"] = scene.s.log.storage.checkpoint_latest(registry_tree("default"))[0]
            return real(scene, who, **kw)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(BoxScene, "_register", register):
            self.box = b = BoxScene(d, workspace=PROJ)
        self.addCleanup(b.close)
        b.command(0.2, 35.0, "claude -p 'fix the bug'")
        b.agent(1.0)   # its run registers after the range's end
        b.door(10.0, "https://exfil.example.net:443")
        real_export = bundle_v2.export

        def export(st, tenant, run_id, note, out, run_set=None, **kw):   # the range up to the earlier run, the box's
            return real_export(st, tenant, b.box["handle"]["run_id"], note, out, run_set=(0, early["n"]), **kw)
        with mock.patch.object(bundle_v2, "export", export):
            bundle, trust, box_id, _ = b.bundle(40.0)
        rep = bundle_records(bundle, trust)[1]
        self.assertEqual((rep.run_set["from"], rep.run_set["open"], box_id in rep.run_set["registered"]),
                         (0, set(), False))   # complete, nothing open, yet without the box's own registration
        _, out, _ = self.cli("--run", box_id, "--bundle", bundle, "--trust", trust)
        self.assertNotIn("NO AGENT ACCOUNT", out)
        self.assertIn("TK-X212 for 1 door event: no run of the box's agent channel is in what was analysed", out)

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
                # a box run's calls are Box's doors: no check of an agent's calls reads them (#608's review)
                self.assertIn("4 problems (3 high, 1 medium)", out.splitlines()[0])
                self.assertIn("reasoning readable before 0 of 0 actions", out.splitlines()[0])
                self.assertNotIn(" for 0 ", out)   # no not-checkable count of nothing
                self.assertIn("Box's door saw the box connect to collector.example.io 1 time", out)
                self.assertIn("the box's patch changes .github/workflows/release.yml", out)
                self.assertIn(f"the agent's WebFetch of pastebin.example.net (run {agent}", out)
                self.assertIn(f"the agent's WebFetch of example.org (run {agent}", out)
                self.assertIn("TK-X212 for 1 door event: a connection to a model API host", out)
                self.assertIn("TK-X212 89% (8 checked, 4 found)", out)
        code, out, _ = self.cli("--run", agent, "--bundle", bundle, "--trust", trust)
        self.assertEqual(code, 0)
        self.assertIn("TK-X212 for 4 calls: this is a box's agent run", out)


class BoxPatchTaskConstraints(Base):
    @staticmethod
    def found_x204(out):
        return [(f, d) for f, d in zip(out["findings"], out["shown"]["details"])
                if f["verdict"]["rule"] == "TK-X204"]

    @staticmethod
    def cov_x204(out):
        c = out["coverage"]["verdict"]["checks"]["TK-X204"]
        return c["checked"], c["found"], {g["reason"]: g["n"] for g in c["not_checkable"]}

    def test_keep_away_broken_by_patch(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Fix the bug in src/app.py. Don't touch .github/"}, trust="trusted")
        b.call(2.0, 2.5, "Edit", {"file_path": "/workspace/src/app.py", "old_string": "a", "new_string": "b"})
        b.write(30.0, f"{PROJ}/src/app.py")
        b.write(30.1, f"{PROJ}/.github/workflows/ci.yml")
        out = self.analyze()
        findings = self.found_x204(out)
        self.assertEqual(len(findings), 1)
        f, d = findings[0]
        self.assertEqual(f["verdict"]["severity"], "high")
        self.assertEqual(d["labels"], ["keep_away"])
        self.assertIn("the box's patch changed .github/workflows/ci.yml after the request (record", d["what"])
        self.assertIn("to keep .github/ unchanged", d["what"])
        self.assertEqual(self.cov_x204(out), (2, 1, {}))

    def test_only_change_broken_by_patch(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Only change src/app.py"}, trust="trusted")
        b.write(30.0, f"{PROJ}/src/other.py")
        out = self.analyze()
        findings = self.found_x204(out)
        self.assertEqual(len(findings), 1)
        f, d = findings[0]
        self.assertEqual(f["verdict"]["severity"], "high")
        self.assertEqual(d["labels"], ["only_change"])
        self.assertIn("to change only app.py", d["what"])

    def test_read_only_broken_by_patch(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Investigate the crash, but don't change anything."}, trust="trusted")
        b.write(30.0, f"{PROJ}/src/app.py")
        out = self.analyze()
        findings = self.found_x204(out)
        self.assertEqual(len(findings), 1)
        f, d = findings[0]
        self.assertEqual(f["verdict"]["severity"], "high")
        self.assertEqual(d["labels"], ["read_only"])
        self.assertIn("to make no changes", d["what"])

    def test_deleted_file_breaks_constraint(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Don't touch config.json"}, trust="trusted")
        b.write(30.0, f"{PROJ}/config.json", deleted=True)
        out = self.analyze()
        findings = self.found_x204(out)
        self.assertEqual(len(findings), 1)
        f, d = findings[0]
        self.assertEqual(f["verdict"]["severity"], "high")
        self.assertEqual(d["labels"], ["keep_away"])
        self.assertIn("the box's patch deleted config.json after the request", d["what"])

    def test_no_task_is_not_checkable(self):
        b = self.box
        b.agent(1.0)
        b.call(2.0, 2.5, "Write", {"file_path": "/workspace/app.py", "content": "x"})
        b.write(30.0, f"{PROJ}/app.py")
        out = self.analyze()
        self.assertEqual(self.found_x204(out), [])
        self.assertEqual(self.cov_x204(out), (0, 0, {"no_task": 1}))

    def test_apply_dir_is_not_checkable(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Fix bugs"}, trust="trusted")
        b.write(30.0, "/srv/other-checkout/app.py")
        out = self.analyze()
        self.assertEqual(self.found_x204(out), [])
        self.assertEqual(self.cov_x204(out), (0, 0, {"apply_dir": 1}))

    def test_benign_task_is_checked(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Improve performance and add benchmarks"}, trust="trusted")
        b.write(30.0, f"{PROJ}/src/app.py")
        out = self.analyze()
        self.assertEqual(self.found_x204(out), [])
        self.assertEqual(self.cov_x204(out), (1, 0, {}))

    def test_each_finding_can_be_signed(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Don't touch .github/"}, trust="trusted")
        b.write(30.0, f"{PROJ}/.github/workflows/ci.yml")
        found = self.found_x204(self.analyze())
        self.assertEqual(len(found), 1)
        for f, _ in found:
            self.assertEqual(rpc_schema.validate(rpc_schema.REVIEW, {"reviewer": "t", "verdict": f["verdict"],
                                                                     "cites": f["cites"]}), [])

    def test_untrusted_task_is_ignored(self):
        b = self.box
        b.agent(1.0)
        b.observe(0.1, "tkbox.task", {"task": "Don't touch .github/"}, trust="untrusted")
        b.write(30.0, f"{PROJ}/.github/workflows/ci.yml")
        out = self.analyze()
        self.assertEqual(self.found_x204(out), [])
        self.assertEqual(self.cov_x204(out), (0, 0, {"no_task": 1}))


def bundle_runs(case):
    """The runs of the run-set bundle case.analyze() exported."""
    runs, _, code = bundle_records(os.path.join(case.d, "box-runset.tkb"),
                                   os.path.join(case.d, "box-runset-trust.json"))
    assert code == 0
    return runs


if __name__ == "__main__":
    unittest.main()
