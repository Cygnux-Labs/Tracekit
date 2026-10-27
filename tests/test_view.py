"""`tracekit view`: the v2 signer's runs, each verified by verify.v2, served with the observer's page and security."""
import collections
import contextlib
import datetime
import functools
import http.client
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import types
import unittest
import urllib.request
from unittest import mock

import pytest

import test_signer_service as ts
from factories import wait_for
from test_observe_render import XSS, script_of, unescaped
from test_sensor import SENSOR
from tracekit import cli, findings_v2, observe, view
from tracekit.format.canon import event_hash as canon_hash
from tracekit.observe import _session
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage
from tracekit.why.core import GENESIS, HttpSink, event_hash, load_run, referenced_refs
from tracekit.why.demo import EXFIL_TARGET, SYSTEM
from tracekit.why.graph import target_hits
from tracekit.why import cli as why_cli, import_v2
from tracekit.why.import_v2 import _target, store_records
from tracekit.why.server import Feed as WhyFeed, IngestError, Store, tape

POLICY = Engine({"deny": [{"id": "T-DENY", "tool": "rm", "pattern": "^"}],
                 "ask": [{"id": "T-PAY", "tool": "pay", "pattern": "^"}]})
SERVER = view.policy_reasons()   # the shipped packs' rule reasons, by policy hash
SERVER_HASH = next(h for h, rules in SERVER.items() if "TK-S001" in rules and "TK-M001" in rules)


def store_feed(test, cfg, **kw):
    """A StoreFeed whose threads stop before the test's store goes away."""
    feed = view.StoreFeed(cfg, **kw)
    test.addCleanup(feed.close)
    return feed


def page_js(names, script):
    """What `script` prints, run in Node after terminal.html's own definitions `names` (functions, one-line consts)."""
    page = observe.read_text(observe.UI)
    code = "".join(re.search(rf"^    (?:function {n}\(.*?^    }}|const {n} = .*?;)$", page, re.M | re.S).group(0) + "\n"
                   for n in names)
    # on stdin: Linux caps one argument at 128 KiB (MAX_ARG_STRLEN), which a test's records can pass
    return subprocess.run(["node", "-"], input=code + script, capture_output=True, encoding="utf-8", check=True).stdout


def v2rec(seq, typ, data, run="r1", **top):
    return {"event": {"seq": seq, "run_seq": seq, "run_id": run, "agent_id": "main", "type": typ, "data": data,
                      "ts": f"2026-10-10T17:00:{seq:02d}.000000Z", "prev_hash": "sha256:p", **top},
            "hash": f"sha256:{seq}"}


class Translate(unittest.TestCase):
    """v2 records -> the page's rows: the agent's name, rule reasons for a call whose arguments are only a commitment,
    holds and approvals as their own tape rows in words, and the signer's run as the signer, not an agent."""

    def feed(self, *recs):
        tr = view.Translator(SERVER)
        return [x for r in recs for x in tr.feed(r)]

    def test_a_denied_call_shows_its_rules_reasons_and_its_commitment(self):
        start, call = self.feed(
            v2rec(1, "run.registered", {"agent": {"name": "support-agent"}, "signer_isolation": "separate-user",
                                        "identity": {"scheme": "uid", "subject": "501", "attested": True}}),
            v2rec(2, "policy.decision", {"tool_use_id": "c3", "tool": "http_get", "decision": "deny",
                                         "rule_ids": ["TK-N001", "TK-S001", "TK-NEW"], "policy_hash": SERVER_HASH,
                                         "args_commitment": "hmac-sha256:ab", "decision_id": "dec-1"}))
        self.assertEqual((start["agent"], start["source"]),
                         ("support-agent", "separate-user signer · uid:501 (attested)"))
        self.assertEqual((call["event"], call["agent"], call["tool_name"], call["tool_input"]),
                         ("PreToolUse", "support-agent", "http_get", {}))
        self.assertEqual(call["target"],
                         "TK-N001 request to an internal address; TK-S001 cloud metadata service; TK-NEW")
        self.assertEqual(call["policy"], {"decision": "deny", "reasons": ["TK-N001", "TK-S001", "TK-NEW"], "flags": []})
        self.assertEqual(call["v2"], {"type": "policy.decision", "run_seq": 2, "tool_use_id": "c3", "decision": "deny",
                                      "args_commitment": "hmac-sha256:ab", "policy_hash": SERVER_HASH,
                                      "decision_id": "dec-1", "cls": "http", "read": {"deny": 7, "ask": 6, "flag": 3},
                                      "secs": {"TK-N001": "deny", "TK-S001": "deny"}, "rules": [
                                          {"id": "TK-N001", "reason": "request to an internal address"},
                                          {"id": "TK-S001", "reason": "cloud metadata service",
                                           "remedy": "Use the credentials the deployment gives the tool; no tool call "
                                                     "needs the cloud metadata service."},
                                          {"id": "TK-NEW", "reason": ""}]})
        [other] = self.feed(v2rec(2, "policy.decision", {"tool_use_id": "c3", "tool": "x", "decision": "ask",
                                                         "rule_ids": ["TK-S001"], "policy_hash": "sha256:unknown"}))
        # a decision of a policy the viewer does not have: its rule ids only
        self.assertEqual((other["target"], other["policy"]["flags"]), ("TK-S001", ["held_for_approval"]))
        self.assertNotIn("read", other["v2"])

    def test_a_model_message_of_any_shape_reads_as_what_it_says(self):
        """{"output": [{"type": ["x"]}]}, an agent's own words the dev vault keeps, raised TypeError in the parser and
        ended the viewer's checks of every run; an item whose type is no name is no item."""
        tr = view.Translator()
        tr.content[("r1", 1)] = {"output": [{"type": ["x"]}, {"type": {"a": 1}}]}
        self.assertEqual(tr.feed(v2rec(1, "model.exchange", {"phase": "response", "exchange_id": "x1",
                                                             "content_digest": "sha256:c"})), [])

    def test_the_analysis_reads_content_it_cannot_parse_as_unread(self):
        """findings_v2.analyze raised on the same body: an agent could make its own run unanalysable."""
        recs = [v2rec(0, "run.registered", {"agent": {"name": "a"}}, source="sdk"),
                v2rec(1, "model.exchange", {"phase": "response", "exchange_id": "x", "content_digest": "sha256:c",
                                            "tool_uses": [{"id": "c1", "name": "read_file"}]}, source="sdk"),
                v2rec(2, "policy.decision", {"tool": "read_file", "tool_use_id": "c1", "decision": "allow"},
                      source="sdk")]

        def vault(want):
            return ((r["event"]["run_seq"], {"output": [{"type": ["x"]}]}, True) for r in want
                    if r["event"]["type"] == "model.exchange")
        self.assertIn("no problems found", findings_v2.analyze(recs, vault)["summary"])
        with mock.patch.object(findings_v2._Run, "feed", side_effect=RecursionError("too deep")):   # any reader error
            self.assertIn("no problems found", findings_v2.analyze(recs, vault)["summary"])

    def test_what_the_model_said_before_a_call_leaves_out_what_it_said_after(self):
        """SAID BEFORE THIS CALL listed every block of the message that asked for the call, text written after it too,
        labelled "signed before this call": each block says how many of the message's calls came before it."""
        tr = view.Translator()
        tr.content[("r1", 1)] = {"output": [
            {"type": "message", "content": [{"type": "output_text", "text": "BEFORE"}]},
            {"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"},
            {"type": "message", "content": [{"type": "output_text", "text": "AFTER"}]},
            {"type": "function_call", "call_id": "c2", "name": "f", "arguments": "{}"}]}
        uses = [{"id": "c1", "name": "f"}, {"id": "c2", "name": "f"}]
        turn = tr.feed(v2rec(1, "model.exchange", {"phase": "response", "exchange_id": "x1",
                                                   "content_digest": "sha256:c", "tool_uses": uses}))[0]
        self.assertEqual([(b["text"], b["after"]) for b in turn["blocks"]], [("BEFORE", 0), ("AFTER", 1)])
        self.assertEqual(turn["calls"], ["c1", "c2"])
        if not shutil.which("node"):
            self.skipTest("needs node to run the page's saidBefore()")
        said = json.loads(page_js(["saidBefore"], f"""
            const rec = {{ session_id: "r1" }}, asked = {{ x: "x1", seq: 1 }};
            const entries = [{{ x: "x1", seq: 0, rec, text: "EARLIER RECORD" }},
              ...{json.dumps(turn["blocks"])}.map(b =>
              ({{ x: "x1", seq: 1, rec, calls: {json.dumps(turn["calls"])}, k: b.after, text: b.text }})),
              {{ x: "x1", seq: 1, rec, text: "COMMITTED" }}, {{ x: "x1", seq: 2, rec, text: "LATER RECORD" }}];
            process.stdout.write(JSON.stringify(["c1", "c2", "c9"].map(id => entries.filter(r =>
              saidBefore(r, asked, {{ session_id: "r1", tool_use_id: id }})).map(r => r.text))));"""))
        self.assertEqual(said, [["EARLIER RECORD", "BEFORE", "COMMITTED"],
                                ["EARLIER RECORD", "BEFORE", "AFTER", "COMMITTED"],
                                ["EARLIER RECORD", "COMMITTED"]])

    def test_said_vs_did_and_whose_words_get_the_tier_the_claims_and_the_input_source(self):
        """SAID VS DID needs who wrote a call's result (a gateway or executor, tier T2, or the agent) and which
        sentences state an outcome (TK-X205's reader); WHOSE WORDS where an input came from: none reached the page."""
        tr = view.Translator()
        tr.content[("r1", 4)] = {"output": [
            {"type": "message", "content": [{"type": "output_text", "text": "I will push it now."}]},
            {"type": "message", "content": [{"type": "output_text", "text": "All 12 tests pass. Pushed the fix."}]}]}
        rows = [x for r in (
            v2rec(1, "input.observed", {"source": "msg:planner->executor run:p1", "trust": "untrusted"}),
            v2rec(2, "tool.result", {"tool_use_id": "c1", "ok": True, "via": "mtls:executor"}, source="gateway",
                  tier="T2"),
            v2rec(3, "tool.result", {"tool_use_id": "c2", "ok": True}, source="sdk"),
            v2rec(4, "model.exchange", {"phase": "response", "exchange_id": "x1", "content_digest": "sha256:c"}))
            for x in tr.feed(r)]
        inp, ran, own, turn = rows
        self.assertEqual((inp["v2"]["source"], inp["v2"]["trust"]), ("msg:planner->executor run:p1", "untrusted"))
        self.assertEqual((ran["tk_tier"], ran["tk_source"], ran["v2"]["via"]), ("T2", "gateway", "mtls:executor"))
        self.assertEqual(("tk_tier" in own, "via" in own["v2"]), (False, False))
        self.assertEqual([b.get("claims") for b in turn["blocks"]],
                         [None, ["All 12 tests pass.", "Pushed the fix."]])   # a plan states no outcome

    def test_content_redaction_changed_is_not_shown_as_the_records(self):
        """The dev content source dropped `opened`: content that opens no commitment (redacted) showed as the call's
        arguments, as content that does."""
        recs = [v2rec(1, "policy.decision", {"tool": "Bash", "args_commitment": "hmac-sha256:a"}),
                v2rec(2, "policy.decision", {"tool": "Bash", "args_commitment": "hmac-sha256:b"})]
        with mock.patch.object(view, "Client"), mock.patch("tracekit.why.signed.vault_content", return_value=iter(
                [(1, {"command": "ls"}, True), (2, {"command": "[REDACTED]"}, False)])):
            self.assertEqual(view.dev_content_source()("r1", recs), {1: {"command": "ls"}})

    def test_openshells_blocks_and_policy_changes_are_rows_in_words(self):
        seen = {"observer": "mtls:spiffe://acme.example/tracekit-openshell", "sensor": "openshell",
                "ts": "2026-10-15T00:00:00.000000Z", "pid": 2187, "binary": "/usr/bin/curl", "attribution": "token"}
        blocked, allowed, policy = self.feed(
            v2rec(1, "effect.observed", {**seen, "kind": "connect", "host": "blocked.example.com", "port": 443,
                                         "denied": True}),
            v2rec(2, "effect.observed", {**seen, "kind": "connect", "host": "api.example.com", "port": 443}),
            v2rec(3, "ext", {"name": "openshell.policy", "observer": seen["observer"], "ts": seen["ts"],
                             "change": "approved", "policy_hash": "3f" * 32, "by": "user:dev@example.com",
                             "attribution": "token"}))
        self.assertEqual((blocked["tape"], blocked["title"]), ("BLOCK", "BLOCKED BY OPENSHELL · connect "
                                                                        "blocked.example.com:443"))
        self.assertTrue(blocked["text"].startswith("OpenShell's policy blocked /usr/bin/curl (pid 2187) from "
                                                   "connecting to blocked.example.com:443"))
        self.assertEqual((allowed["tape"], allowed["title"]), ("EFFECT", "OPENSHELL · connect api.example.com:443"))
        self.assertNotIn("effect", allowed["v2"])   # not a kernel sensor's: never joined to a call
        self.assertEqual((policy["tape"], policy["title"]), ("STATE", "OPENSHELL POLICY · approved"))
        self.assertIn("by user:dev@example.com · policy 3f3f3f3f3f3f3f3f", policy["text"])

    def test_holds_and_approvals_are_their_own_rows_in_words(self):
        rows = self.feed(
            v2rec(1, "policy.decision", {"tool_use_id": "c6", "tool": "create_refund", "decision": "ask",
                                         "rule_ids": ["TK-M001"], "policy_hash": SERVER_HASH}),
            v2rec(2, "approval.request", {"approval_id": "apr-1", "rule_ids": ["TK-M001"], "policy_hash": SERVER_HASH,
                                          "requester": "uid:501", "expires_at": "2026-10-10T18:00:34.000000Z",
                                          "binding": {"tool": "create_refund", "tool_call_id": "c6"},
                                          "binding_digest": "sha256:bd"}),
            v2rec(3, "approval", {"tool_use_id": "c6", "approval_id": "apr-1", "decision": "approve",
                                  "approver": "oidc:alice", "approver_identity": {"scheme": "oidc", "subject": "alice",
                                                                                   "attested": False},
                                  "via": {"scheme": "mtls", "subject": "spiffe://acme/viewer", "attested": True},
                                  "channel": "web", "self_approved": False, "break_glass": True, "reason": "on call"}),
            v2rec(4, "approval.consumed", {"approval_id": "apr-1"}, tool_call_id="c6"))
        req, ans, used = rows[1:]
        self.assertEqual((req["tape"], req["title"]), ("HOLD", "APPROVAL REQUESTED · create_refund"))
        self.assertEqual(req["text"], "requested by uid:501 · rules TK-M001 sending money · expires 18:00:34 UTC")
        self.assertEqual((req["v2"]["approval"], req["v2"]["tool_use_id"], req["v2"]["approval_id"]),
                         ("requested", "c6", "apr-1"))
        self.assertEqual((ans["tape"], ans["severity"], ans["title"]), ("APPROVE", "high", "APPROVED · create_refund"))
        self.assertEqual(ans["text"], "by oidc:alice (not attested) · vouched for by mtls:spiffe://acme/viewer "
                                      "(attested) via web · “on call” · not self-approved · BREAK-GLASS")
        self.assertEqual({k: ans["v2"][k] for k in ("approval", "approver", "via", "self_approved", "break_glass")},
                         {"approval": "approve", "approver": "oidc:alice (not attested)",
                          "via": "mtls:spiffe://acme/viewer (attested)", "self_approved": False, "break_glass": True})
        self.assertEqual((used["tape"], used["title"], used["v2"]["tool_use_id"]),
                         ("APPROVE", "APPROVAL CONSUMED · create_refund", "c6"))
        self.assertNotIn("{", "".join(r.get("text", "") for r in rows))   # no record JSON in place of words

    def test_live_constraints_are_rows_and_head_the_run_review(self):
        recs = [v2rec(1, "constraint.added", {"kind": "keep_away", "salt_id": "a" * 32,
                                              "object_commitment": "hmac-sha256:" + "b" * 64}),
                v2rec(2, "constraint.added", {"kind": "no_push"}),
                v2rec(3, "policy.decision", {"tool_use_id": "c1", "tool": "Edit", "decision": "ask",
                                             "rule_ids": ["TK-CONSTRAINT"], "policy_hash": SERVER_HASH})]
        added = self.feed(*recs)[:2]
        self.assertEqual([(r["tape"], r["title"]) for r in added],
                         [("HOLD", "CONSTRAINT · keep a file unchanged"), ("HOLD", "CONSTRAINT · don't push")])
        self.assertIn("the file is committed, not named", added[0]["text"])
        rv = view.review(recs, mock.Mock(integrity="VERIFIED", assurance="dev; records ed25519"), "verified")
        self.assertEqual((rv["constraints"], rv["constraint_holds"]),
                         ([{"kind": "keep a file unchanged", "seq": 1}, {"kind": "don't push", "seq": 2}], 1))
        with open(os.path.join(os.path.dirname(view.__file__), "ui", "terminal.html"), encoding="utf-8") as f:
            self.assertIn('line(r.constraints[0].seq, "CONSTRAINTS"', f.read())   # the review's first line after it

    def test_gaps_and_signer_records_in_words_and_the_signer_is_no_agent(self):
        gap, child, final = self.feed(
            v2rec(1, "capture.gap", {"kind": "client_counter_gap", "missed_events": 3, "reason": "stream s skipped"}),
            v2rec(2, "run.child", {"run_id": "run-c"}),
            v2rec(3, "run.final", {"head_run_seq": 2, "provider_executed": 2, "coverage": {
                "layers": ["L2"], "reconciled": 0, "unreconciled": {"hook_missing": 1}}}))
        self.assertEqual((child["title"], child["text"]), ("CHILD RUN", "run run-c registered from this run's harness "
                                                                        "process with this run as its parent"))
        # the kind in words; the code stays on the row (its tooltip and DETAIL)
        self.assertEqual((gap["tape"], gap["title"], gap["text"], gap["v2"]["kind"]),
                         ("GAP", "GAP · events the client sent never arrived", "stream s skipped · 3 events missed",
                          "client_counter_gap"))
        self.assertEqual(final["reason"], "final · head run_seq 2 · coverage L2 · reconciled 0 · unreconciled "
                                          "hook_missing 1 · provider-run tools 2")
        signer = view.SIGNER_RUN[1]
        epoch, refused = self.feed(
            v2rec(0, "signer.epoch", {"keys": [{"kid": "sha256:6cb1e807d62770b7", "alg": "ed25519"}]}, run=signer),
            v2rec(1, "refusal.summary", {"code": "forbidden", "count": 2, "identity": "uid:501",
                                         "from_ts": "2026-10-10T17:00:34.1Z", "to_ts": "2026-10-10T17:00:35.1Z"},
                  run=signer))
        for r in (epoch, refused):
            self.assertEqual((r["signer"], r["agent"], r["tape"]), (True, "signer", "SIGNER"))
        self.assertEqual(epoch["text"], "1 signing key(s): ed25519 6cb1e807d627")
        self.assertEqual((refused["title"], refused["text"]),
                         ("SIGNER REFUSED 2 · forbidden", "from uid:501 · 17:00:34 UTC–17:00:35 UTC"))

    def test_inputs_reads_and_signed_findings_are_rows_in_words(self):
        """An observed input, the viewer's own content reads and a findings run's signed findings were ALERT rows of
        raw record JSON."""
        signer = view.SIGNER_RUN[1]
        start, finding, coverage, seen, read = self.feed(
            v2rec(1, "run.registered", {"agent": {"name": "tracekit-analyze"}, "analyzes": "r1",
                                        "identity": {"scheme": "uid", "subject": "501", "attested": True}}, run="f1"),
            v2rec(2, "review", {"reviewer": "tracekit-analyze/1.4.0", "cites": [{"run_seq": 5, "hash": "sha256:5"}],
                                "verdict": {"kind": "finding", "rule": "TK-X208", "severity": "high"}}, run="f1"),
            v2rec(3, "review", {"reviewer": "tracekit-analyze/1.4.0", "cites": [], "verdict": {
                "kind": "coverage", "rule": "TK-X200", "severity": "info", "checks": {"TK-X201": {
                    "checked": 2, "found": 0, "not_checkable": [{"reason": "withheld", "n": 1}]}}}}, run="f1"),
            v2rec(4, "input.observed", {"source": "claude:UserPromptSubmit", "trust": "trusted",
                                        "output": {"hash": "hmac-sha256:aa"}}),
            v2rec(5, "content.accessed", {"principal": "uid:501", "run_id": "r1", "seqs": [1, 2],
                                          "purpose": "tracekit view"}, run=signer))
        self.assertIn("findings about run r1", start["source"])
        self.assertEqual((finding["tape"], finding["severity"], finding["title"], finding["v2"]["about"]),
                         ("FINDING", "high", "FINDING TK-X208 · " + findings_v2.TITLES["TK-X208"], "r1"))
        self.assertEqual(finding["v2"]["cites"], [{"run_seq": 5, "hash": "sha256:5"}])
        # the reviewer is the analyzer's own claim; who wrote the findings is the identity the signer measured
        self.assertIn("Written by uid:501 (attested), reviewer tracekit-analyze/1.4.0 (its own claim), about run r1",
                      finding["text"])
        self.assertEqual(coverage["title"], "FINDINGS COVERAGE · 2 checks ran")
        self.assertIn("TK-X201: not checkable for 1: " + findings_v2.REASONS["withheld"][0], coverage["text"])
        self.assertEqual((seen["event"], seen["tape"], seen["title"]),
                         ("tk_note", "INPUT", "INPUT · claude:UserPromptSubmit"))
        self.assertEqual((read["event"], read["tape"], read["signer"], read["text"]),
                         ("tk_note", "SIGNER", True, "uid:501 read the kept content of 2 records of run r1 · "
                                                     "“tracekit view”"))
        self.assertNotIn("{", "".join(r["text"] for r in (finding, coverage, seen, read)))

    def test_a_rejection_is_never_a_self_approval_and_signer_rules_have_reasons(self):
        who = {"scheme": "uid", "subject": "501", "attested": True}
        rejected, approved, held = self.feed(
            v2rec(1, "approval", {"decision": "reject", "self_approved": True, "approver_identity": who}),
            v2rec(2, "approval", {"decision": "approve", "self_approved": True, "approver_identity": who}),
            v2rec(3, "policy.decision", {"tool_use_id": "c1", "tool": "Edit", "decision": "ask",
                                         "rule_ids": ["TK-CONSTRAINT"], "policy_hash": SERVER_HASH}))
        self.assertEqual((rejected["severity"], rejected["text"]), ("info", "by uid:501 (attested) · by the requester"))
        self.assertEqual((approved["severity"], approved["text"]), ("med", "by uid:501 (attested) · SELF-APPROVED"))
        self.assertEqual(held["v2"]["rules"], [{"id": "TK-CONSTRAINT", "reason": view.ENGINE_RULES["TK-CONSTRAINT"]}])

    def test_a_model_line_shows_only_what_was_recorded(self):
        [line] = [r for r in self.feed(v2rec(1, "model.exchange", {
            "phase": "response", "model": "m", "exchange_id": "x", "tool_uses": [{"id": "t1", "name": "Bash"}]}))
            if r["event"] == "tk_model"]
        self.assertEqual(line["text"], "model m · Bash")   # it read "model m → None  · Bash · None ms"

    def test_review_counts_a_run_and_points_at_its_first_records(self):
        recs = [v2rec(1, "run.registered", {"agent": {"name": "a"}}),
                v2rec(2, "policy.decision", {"decision": "allow"}), v2rec(3, "policy.decision", {"decision": "deny"}),
                v2rec(4, "policy.decision", {"decision": "deny"}), v2rec(5, "policy.decision", {"decision": "ask"}),
                v2rec(6, "approval", {"decision": "approve", "tool_use_id": "c4", "self_approved": True,
                                      "approver_identity": {"scheme": "uid", "subject": "501", "attested": True}}),
                v2rec(7, "capture.gap", {"kind": "signer_unavailable"}), v2rec(8, "reconcile.hook_missing", {}),
                v2rec(9, "run.closing", {"reason": "close_run"}),
                v2rec(10, "run.final", {"coverage": {"layers": ["L2", "L3"], "reconciled": 4}})]
        rep = mock.Mock(integrity="VERIFIED", assurance="dev; same user")
        rv = view.review(recs, rep, "verified")
        self.assertEqual({k: rv[k] for k in ("verdict", "integrity", "assurance", "label", "agent", "records", "state")},
                         {"verdict": "verified", "integrity": "VERIFIED", "assurance": "dev", "label": view.OPERATOR_SIDE,
                          "agent": "a", "records": 10, "state": "final"})
        self.assertEqual(rv["decisions"], {"allow": 1, "deny": 2, "ask": 1})
        self.assertEqual(rv["approvals"], [{"decision": "approve", "tool_use_id": "c4", "approver": "uid:501 (attested)",
                                            "via": None, "self_approved": True, "break_glass": False, "seq": 6}])
        self.assertEqual(rv["gaps"], {"signer_unavailable": 1, "reconcile.hook_missing": 1})
        self.assertEqual(rv["coverage"], {"layers": ["L2", "L3"], "reconciled": 4, "unreconciled": {},
                                          "provider_executed": 0})
        self.assertEqual(rv["first"], {"allow": 2, "deny": 3, "ask": 5, "approval": 6, "gap:signer_unavailable": 7,
                                       "gap:reconcile.hook_missing": 8})
        self.assertEqual((rv["first_ts"], rv["last_ts"]), ("2026-10-10T17:00:01.000000Z", "2026-10-10T17:00:10.000000Z"))
        json.dumps(rv)   # served to the page as is

    def test_policy_reasons_of_a_configured_policy_by_its_hash(self):
        path = os.path.join(ts.tmpdir(self), "p.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("deny:\n  - id: X-1\n    pattern: 'rm'\n    reason: removing files\n    remedy: Move it aside.\n"
                    "flag:\n  - id: X-2\n    pattern: 'ls'\n    label: listing\n")
        h = policy_compile.policy_hash(policy_compile.build(path)[0])
        self.assertEqual(view.policy_reasons([path])[h], {"X-1": {"reason": "removing files", "remedy": "Move it aside."},
                                                          "X-2": {"reason": "listing"}})
        self.assertEqual(SERVER[SERVER_HASH]["TK-DB001"], {"reason": "dropping a database object"})

    def test_a_calls_signed_provenance_rides_on_its_row(self):
        src = {"run_seq": 4, "tool": "fetch_page", "tool_call_id": "c2"}
        call, restarted, plain = self.feed(
            v2rec(5, "policy.decision", {"tool_use_id": "c5", "tool": "send_email", "decision": "ask",
                                         "provenance_state": "complete",
                                         "provenance": [{"field": "to", "kind": "email", "source": src}]}),
            v2rec(6, "policy.decision", {"tool_use_id": "c6", "tool": "send_email", "decision": "allow",
                                         "provenance_state": "unavailable"}),
            v2rec(7, "policy.decision", {"tool_use_id": "c7", "tool": "ls", "decision": "allow"}))
        self.assertEqual(call["v2"]["provenance"], [{"field": "to", "kind": "email", "source": src}])
        self.assertEqual(restarted["v2"]["provenance_state"], "unavailable")
        self.assertFalse({"provenance", "provenance_state"} & set(plain["v2"]))   # a 1.0 record: nothing to show


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class View(unittest.TestCase):
    def setUp(self):
        self.d = ts.tmpdir(self)
        cfg = {"data_dir": self.d, "socket": os.path.join(self.d, "s.sock"), "grace_s": 0,
               "approvals": {"self_approval": "allow"},   # one uid runs and approves
               "authorize": {f"{SENSOR.scheme}:{SENSOR.subject}": ["observe_effect"]}, "observe_grace_s": 0}
        self.service = svc.open_service(cfg, policy=POLICY)
        self.addCleanup(self.service.close)
        for srv in svc.serve(cfg, self.service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.client = Client(cfg["socket"])
        self.addCleanup(self.client.close)

    def finished_run(self):
        """allow, deny, ask -> approve -> run, complete, close; returns the run id once a note covers run.final."""
        run = self.client.run(agent="e2e")
        self.assertEqual(run.decide("c1", "Bash", {"command": "ls"})["decision"], "allow")
        run.complete("c1")
        self.assertEqual(run.decide("c2", "rm", {"path": "x"})["decision"], "deny")
        self.assertEqual(run.decide("c3", "pay", {"cents": 5})["decision"], "ask")
        aid = run.call("approval_request", tool_call_id="c3")["approval_id"]
        self.client.call("approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertTrue(run.approval_consume("c3", "pay", {"cents": 5})["ok"])
        run.complete("c3")
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] == "run.final"
                                 and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        return run.run_id

    def rows(self, feed, run_id):
        with feed.lock:
            return [r for r in feed.records if r["session_id"] == run_id]

    def report(self, feed, run_id):
        wait_for(lambda: any(r.get("title", "").startswith(f"RUN {run_id}") for r in self.rows(feed, run_id)), 15)
        return [r for r in self.rows(feed, run_id) if r.get("title", "").startswith(f"RUN {run_id}")]

    @pytest.mark.unverified_bundles
    def test_a_run_opens_from_the_store_verified_again_and_only_for_its_tenant(self):
        """Past the live view's newest 50,000 records older runs had no rows on the page; /api/rows reads a run from the
        store, checked again for the request, for the token or a session of its tenant."""
        run_id = self.finished_run()
        feed = store_feed(self, {"data_dir": self.d})
        self.report(feed, run_id)
        with mock.patch.object(import_v2, "bundle_records", wraps=import_v2.bundle_records) as checked:
            rows = feed.rows(observe.ALL, "default", run_id)
            self.assertIs(feed.rows(observe.ALL, "default", run_id), rows)   # asked again: checked once
            other = self.finished_run()   # another run moves the log's checkpoint; this run's own records did not grow
            self.assertIs(feed.rows(observe.ALL, "default", run_id), rows)
        self.assertEqual(checked.call_count, 1)
        self.assertEqual([r["tool_use_id"] for r in rows if r["event"] == "PreToolUse"], ["c1", "c2", "c3"])
        self.assertEqual({r["tenant"] for r in rows}, {"default"})
        self.assertIsNone(feed.rows("other", "default", run_id))   # an OIDC session of another tenant
        self.assertIsNone(feed.rows(observe.ALL, "default", "nope"))
        srv = view.server(feed, "127.0.0.1", 0, "t0k")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        for path, code in ((f"/api/rows?tenant=default&run={run_id}", 200), (f"/api/rows?run={run_id}", 400),
                           ("/api/rows?tenant=default&run=nope", 404)):
            c.request("GET", path, headers={"Authorization": "Bearer t0k"})
            r = c.getresponse()
            self.assertEqual((path, r.status), (path, code))
            body = json.loads(r.read())
        c.request("GET", f"/api/rows?tenant=default&run={run_id}")
        self.assertEqual(c.getresponse().status, 401)
        # two checks at once at most: a third request is told to come back, not queued behind them
        feed.verifying = threading.BoundedSemaphore(1)
        feed.verifying.acquire()
        with self.assertRaises(observe.Busy):
            feed.rows(observe.ALL, "default", other)
        c.request("GET", f"/api/rows?tenant=default&run={other}", headers={"Authorization": "Bearer t0k"})
        r = c.getresponse()
        self.assertEqual((r.status, r.getheader("Retry-After")), (503, "5"))
        r.read()
        feed.verifying.release()
        # the rows are of the records the check verified, not a second read of the store after it
        real = view.export

        def export_then_edit(*a, **k):
            real(*a, **k)
            with open(os.path.join(self.d, "store", "records.jsonl"), encoding="utf-8") as f:
                data = f.read()
            with open(os.path.join(self.d, "store", "records.jsonl"), "w", encoding="utf-8") as f:
                f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
        self.service.close()
        feed.rowcache.clear()
        with mock.patch.object(view, "export", side_effect=export_then_edit):
            rows = feed.rows(observe.ALL, "default", run_id)
        self.assertEqual([x["tool_name"] for x in rows if x["event"] == "PreToolUse"], ["Bash", "rm", "pay"])
        # a record edited after it was shown: the viewer's re-check fails it, and it is refused
        path = os.path.join(self.d, "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            data = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
        with mock.patch.object(view.time, "time", return_value=time.time() + view.RECHECK_S + 1):
            for _ in range(2):   # one stale run a pass: the signer's own, then this one
                feed.refresh()
        self.assertIsNone(feed.rows(observe.ALL, "default", run_id))
        self.assertIsNone(store_feed(self, {"data_dir": self.d}).rows(observe.ALL, "default", run_id))
        self.assertIn("error", body)

    def test_rows_never_outlive_a_failed_check_and_a_checkpoint_written_while_reading_is_read_again(self):
        """An answer cached as the watcher failed the run (or cached before, with the same covered count after an edit
        in place) was served again; and a checkpoint written while rows() read the store made it miss the run."""
        run_id = self.finished_run()
        feed = store_feed(self, {"data_dir": self.d})
        self.report(feed, run_id)
        key = ("default", run_id)
        self.assertIsNotNone(feed.rows(observe.ALL, *key))
        with feed.lock:   # the watcher failed it; the cached answer stays (the same covered count)
            feed.runs[key] = dict(feed.runs[key], failed="FAILED")
        self.assertIsNone(feed.rows(observe.ALL, *key))
        with feed.lock:
            feed.runs[key] = dict(feed.runs[key], failed=None)
        feed.rowcache.clear()
        real = import_v2.bundle_records

        def failed_meanwhile(*a, **k):   # the watcher fails the run while this request checks it
            out = real(*a, **k)
            with feed.lock:
                feed.runs[key] = dict(feed.runs[key], failed="FAILED")
            return out
        with mock.patch.object(import_v2, "bundle_records", side_effect=failed_meanwhile):
            self.assertIsNone(feed.rows(observe.ALL, *key))
        self.assertEqual(dict(feed.rowcache), {})
        with feed.lock:
            feed.runs[key] = dict(feed.runs[key], failed=None)
        opened, real_reader = [], view.reader

        class Behind:   # a reader opened before the checkpoint its note names: its tree is shorter
            def __init__(self, r):
                self.r, self.tree = r, types.SimpleNamespace(size=0)

            def __getattr__(self, name):
                return getattr(self.r, name)

        def reader(cfg):
            opened.append(1)
            r = real_reader(cfg)
            return Behind(r) if len(opened) == 1 else r
        with mock.patch.object(view, "reader", side_effect=reader):
            self.assertIsNotNone(feed.rows(observe.ALL, *key))
        self.assertEqual(len(opened), 2)

    def test_with_a_content_source_each_decision_carries_its_arguments(self):
        """The tape named every allowed call "no rule matched": with the dev signer's retained arguments each decision
        carries them (the page names the call by them), asked for once, for exactly the run's decisions."""
        run_id = self.finished_run()
        asked = []

        def content(rid, recs):
            seqs = [r["event"]["run_seq"] for r in recs]
            asked.append((rid, seqs))
            return {s: {"command": f"at {s}"} for s in seqs}
        feed = store_feed(self, {"data_dir": self.d}, content=content)
        self.report(feed, run_id)
        rows = [r for r in self.rows(feed, run_id) if r["event"] == "PreToolUse"]
        self.assertEqual(len(rows), 3)
        self.assertEqual([(r["tool_input"], r["target"]) for r in rows],
                         [({"command": f"at {r['v2']['run_seq']}"}, None) for r in rows])
        self.assertEqual(asked, [(run_id, [r["v2"]["run_seq"] for r in rows])])

    def test_an_agents_odd_model_message_never_stops_the_viewer_checking_runs(self):
        """A model message {"output": [{"type": ["x"]}]} (the agent's own words, kept by the dev vault) raised in the
        viewer's parser and ended its watch thread: no run, earlier or later, was checked again while the page said
        LIVE. The message reads as nothing said, and the watch goes on to the next run."""
        bodies, storage = {}, self.service.log.storage

        def a_run(name, body):
            run = self.client.run(agent=name)
            seq = run.call("model_event", provider="openai", model="m", phase="response", exchange_id="x1",
                           content_digest=canon_hash(body))["run_seq"]
            bodies[(run.run_id, seq)] = body
            run.decide("c1", "Bash", {"command": "ls"})
            run.complete("c1")
            run.close()
            self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] ==
                                     "run.final" and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
            return run.run_id
        odd = a_run("odd", {"output": [{"type": ["x"]}]})
        feed = store_feed(self, {"data_dir": self.d}, content=lambda rid, recs: {
            r["event"]["run_seq"]: bodies[(rid, r["event"]["run_seq"])] for r in recs
            if (rid, r["event"]["run_seq"]) in bodies})
        self.assertEqual([r["review"]["verdict"] for r in self.report(feed, odd)], ["verified"])
        later = a_run("later", {"output": []})
        self.assertEqual([r["review"]["verdict"] for r in self.report(feed, later)], ["verified"])
        self.assertTrue(feed.threads[-1].is_alive())
        self.assertIsNone(feed.stopped)

    def test_vault_content_that_does_not_open_its_record_is_not_shown(self):
        run_id = self.finished_run()

        class Tampered:   # a vault whose content is not what the record committed to
            def content_get(self, req):
                return {"items": [{"seq": s, "content": {"command": "echo tampered"}, "salt": "00" * 32}
                                  for s in req["seqs"]]}
        with mock.patch.object(view, "Client", Tampered):
            feed = store_feed(self, {"data_dir": self.d}, content=view.dev_content_source())
            self.report(feed, run_id)
        rows = self.rows(feed, run_id)
        self.assertEqual([r["title"] for r in rows if r.get("title") == "CONTENT NOT SHOWN"], ["CONTENT NOT SHOWN"])
        self.assertNotIn("tampered", json.dumps([r.get("tool_input") for r in rows]))

    def test_asked_and_said_show_beside_the_call_and_findings_beside_the_integrity(self):
        """#309: a transcript's prompt and thinking (their retained content) show as what was asked and said, the
        thinking labelled by its form; the run's findings are FINDING alerts and review lines, never in the integrity
        line; a line whose content the viewer can't read shows as committed."""
        run, bodies, args = self.client.run(agent="claude-code"), {}, {"file_path": "/w/billing.py"}

        def line(phase, entry, **kw):
            body = {"transcript": "main", "entry": entry}
            out = run.call("model_event", provider="anthropic", model="m", phase=phase,
                           content_digest=canon_hash(body), **kw)
            bodies[out["run_seq"]] = body
        line("request", {"type": "user", "cwd": "/w", "message": {"content": "Fix pager.py."}}, exchange_id="u1")
        line("response", {"type": "assistant", "message": {"id": "msg_1", "content": [
            {"type": "thinking", "thinking": "One more small fix.", "signature": "s"}]}}, exchange_id="msg_1")
        line("response", {"type": "assistant", "message": {"id": "msg_1", "content": [
            {"type": "tool_use", "id": "t1", "name": "Edit", "input": args}]}}, exchange_id="msg_1", tool_uses=[
            {"id": "t1", "name": "Edit", "executed_by": "client", "args_source": "parsed",
             "args_digest": canon_hash({"tool": "Edit", "args": args})}])
        bodies[run.decide("t1", "Edit", args)["run_seq"]] = args
        run.complete("t1")
        unread = run.call("model_event", provider="anthropic", model="m", phase="response", exchange_id="msg_2",
                          content_digest=canon_hash({"x": 1}))["run_seq"]
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] ==
                                 "run.final" and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))

        def vault(want):
            return ((r["event"]["run_seq"], bodies[r["event"]["run_seq"]], True) for r in want
                    if r["event"]["run_seq"] in bodies)
        feed = store_feed(self, {"data_dir": self.d}, content=lambda rid, recs: {
                                  r["event"]["run_seq"]: bodies[r["event"]["run_seq"]] for r in recs
                                  if r["event"]["run_seq"] in bodies},
                              analyze=lambda records: findings_v2.analyze(records, vault))
        [rep] = self.report(feed, run.run_id)   # the verdict first, then the analysis and the review with its findings
        self.assertTrue(wait_for(lambda: (self.rows(feed, run.run_id)[-1].get("review") or {}).get("findings"), 15))
        rows = self.rows(feed, run.run_id)
        self.assertEqual([r["prompt"] for r in rows if r["event"] == "UserPromptSubmit"], ["Fix pager.py."])
        turns = [r for r in rows if r["event"] == "model_turn"]
        self.assertEqual([(t["blocks"], t["v2"]["exchange_id"]) for t in turns], [
            ([{"kind": "thinking", "text": "One more small fix.", "form": "summary", "after": 0}], "msg_1"),
            ([{"kind": "committed", "text": "said something here; it is committed, and this viewer reads no content"}],
             "msg_2")])
        self.assertEqual(turns[1]["v2"]["run_seq"], unread)
        self.assertEqual([r["v2"]["tool_ids"] for r in rows if r["event"] == "tk_model"], [["t1"]])
        found = [r for r in rows if r.get("tape") == "FINDING"]
        self.assertEqual([r["title"] for r in found], ["FINDING TK-X202 · Edit of a file not mentioned before",
                                                       "FINDINGS · 1 problem (1 medium) · reasoning readable before "
                                                       "1 of 1 actions (100%)"])
        self.assertIn("billing.py", found[0]["text"])
        self.assertEqual(found[0]["v2"]["finding"]["rule"], "TK-X202")
        self.assertEqual(rep["title"], f"RUN {run.run_id} · Integrity VERIFIED · Assurance dev")
        self.assertEqual(rows[-1]["review"]["findings"]["line"], "1 problem (1 medium) · reasoning readable before 1 "
                                                                 "of 1 actions (100%)")

    def test_what_a_sensor_saw_shows_joined_to_its_call_and_what_no_call_explains_is_a_finding(self):
        """#309 TK-X206: each kernel sensor effect is an EFFECT row; once the run is final its analysis joins each to
        the call that explains it (the page's Happened column), and one no call explains is a FINDING."""
        def observe(*effects):
            self.service.call(SENSOR, "observe_effect", {"request_id": os.urandom(8).hex(), "instance": "i",
                                                         "sensor": "tetragon", "callers": [f"uid:{os.getuid()}"],
                                                         "effects": list(effects)})

        def at(dt=0.0):
            t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=dt)
            return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        me = f"uid:{os.getuid()}"
        observe()   # the import's heartbeat: it covers the runs registered from now on
        run = self.client.run(agent="claude-code")
        stray = {"caller": me, "kind": "exec", "ts": at(30), "pid": 9, "binary": "/usr/bin/curl", "exec_id": "c"}
        run.decide("c1", "Bash", {"command": "git status"})
        observe({"caller": me, "kind": "exec", "ts": at(), "pid": 10, "binary": "/bin/bash", "exec_id": "b",
                 "parent_exec_id": "harness"},
                {"caller": me, "kind": "exec", "ts": at(), "pid": 11, "binary": "/usr/bin/git", "exec_id": "g",
                 "parent_exec_id": "b"}, stray)
        run.complete("c1")
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] ==
                                 "run.final" and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        feed = store_feed(self, {"data_dir": self.d}, analyze=lambda records: findings_v2.analyze(records, None))
        [rep] = self.report(feed, run.run_id)
        self.assertEqual(rep["title"], f"RUN {run.run_id} · Integrity VERIFIED · Assurance dev")
        rows = self.rows(feed, run.run_id)
        effects = {r["v2"]["run_seq"]: r for r in rows if r.get("tape") == "EFFECT"}
        self.assertEqual(sorted(r["title"] for r in effects.values()),
                         ["EFFECT · exec /bin/bash", "EFFECT · exec /usr/bin/curl", "EFFECT · exec /usr/bin/git"])
        joined = next(r for r in rows if r.get("title", "").startswith("FINDINGS · "))["v2"]["effects"]
        self.assertEqual({effects[s]["v2"]["effect"]["target"]: (j["call"], j["status"]) for s, j in joined.items()},
                         {"/bin/bash": ("c1", "explained"), "/usr/bin/git": ("c1", "explained"),
                          "/usr/bin/curl": (None, "found")})
        [finding] = [r for r in rows if r.get("title", "").startswith("FINDING TK-X206")]
        self.assertIn("/usr/bin/curl start", finding["text"])

    def test_dev_run_is_listed_with_its_counts_and_verified_while_the_signer_holds_the_lock(self):
        run_id = self.finished_run()
        with self.assertRaises(OSError):
            FileStorage(os.path.join(self.d, "store"))   # the signer still holds the store
        feed = store_feed(self, {"data_dir": self.d})
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity VERIFIED · Assurance dev")
        self.assertIn("tenant default · agent e2e · final · decisions allow 1, ask 1, deny 1 · approvals 1 · gaps 0",
                      rep["text"])
        self.assertIn("same user as the dev signer", rep["text"])
        self.assertIn(view.OPERATOR_SIDE, rep["text"])
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev;", rep["text"])   # verify.v2's own report
        rows = self.rows(feed, run_id)
        self.assertEqual([r["tool_name"] for r in rows if r["event"] == "PreToolUse"], ["Bash", "rm", "pay"])
        self.assertEqual((rows[0]["event"], rows[-1]["title"]), ("SessionStart", rep["title"]))
        self.assertEqual(feed.verify()[1], [])
        # the page's run list and review, the denied call's rule, the hold's rows, and the signer's records as its own
        self.assertEqual({k: rep["review"][k] for k in ("verdict", "agent", "state", "decisions")},
                         {"verdict": "verified", "agent": "e2e", "state": "final",
                          "decisions": {"allow": 1, "deny": 1, "ask": 1}})
        self.assertEqual([(a["decision"], a["self_approved"]) for a in rep["review"]["approvals"]], [("approve", True)])
        self.assertEqual({r["agent"] for r in rows}, {"e2e"})
        self.assertEqual(next(r["target"] for r in rows if r.get("tool_name") == "rm"), "T-DENY")
        self.assertEqual([(r["tape"], r["v2"]["approval"]) for r in rows if r.get("v2", {}).get("approval")],
                         [("HOLD", "requested"), ("APPROVE", "approve"), ("APPROVE", "consumed")])
        self.assertTrue(wait_for(lambda: any(r.get("signer") for r in feed.records), 15))
        with feed.lock:
            self.assertEqual({(r["agent"], r["session_id"]) for r in feed.records if r.get("signer")},
                             {("signer", view.SIGNER_RUN[1])})

    def test_a_run_no_checkpoint_covers_yet_is_listed_as_pending(self):
        fake = mock.Mock(runs={("default", "r9"): {"seqs": [0]}})
        fake.checkpoint_latest.return_value = None
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "late"}}, "r9")])
        with mock.patch.object(view, "reader", return_value=fake):
            feed = store_feed(self, {"data_dir": self.d})
            self.assertTrue(wait_for(lambda: feed.records, 5))
            r = feed.records[0]
        self.assertEqual((r["event"], r["session_id"], r["tenant"], r["review"]),
                         ("tk_run", "r9", "default",
                          {"verdict": "pending", "agent": "late", "label": view.OPERATOR_SIDE}))

    def test_the_viewers_own_rows_carry_no_record_and_a_findings_run_is_not_analysed_again(self):
        """A verifier report and a finding of the viewer's analysis showed as SIGNED with a made-up seq and the run's
        last record hash; a findings run was analysed again ("0 of 0 actions"); a run whose checks could not run said
        "no problems found"."""
        recs = {"r1": [v2rec(0, "run.registered", {"agent": {"name": "a"}}, "r1"), v2rec(1, "run.final", {}, "r1")],
                "f1": [v2rec(2, "run.registered", {"agent": {"name": "tracekit-analyze"}, "analyzes": "r1"}, "f1"),
                       v2rec(3, "run.final", {}, "f1")]}
        fake = mock.Mock(runs={("default", k): {"seqs": [r["event"]["seq"] for r in v]} for k, v in recs.items()})
        fake.checkpoint_latest.return_value = None
        fake.iter_run.side_effect = lambda tenant, rid: iter(recs[rid])
        analysed = []

        def analyze(records):
            analysed.append(records[0]["event"]["run_id"])
            return {"findings": [], "shown": {"details": []},
                    "summary": "Findings for run r1: no problems found · reasoning readable before 0 of 1 actions (0%)",
                    "coverage": {"verdict": {"reasoning": {"full": 0, "summary": 0, "withheld": 0, "none": 1},
                                             "checks": {"TK-X201": {"checked": 0, "found": 0, "not_checkable": [
                                                 {"reason": "no_response", "n": 1}]}}}}}
        verified = (mock.Mock(integrity="VERIFIED", assurance="dev"), 0, "Integrity: VERIFIED.")
        with mock.patch.object(view, "reader", return_value=fake), mock.patch.object(view, "check",
                                                                                      return_value=verified):
            feed = store_feed(self, {"data_dir": self.d}, analyze=analyze)
            for rid in recs:
                feed._verify(fake, "note", ("default", rid), 2)
        with feed.lock:
            own = [r for r in feed.records if r.get("tape") in ("VERIFY", "FINDING")]
            reviews = {r["session_id"]: r["review"] for r in feed.records if r.get("review")}   # each run's latest
        self.assertEqual(analysed, ["r1"])
        self.assertEqual(reviews["f1"]["analyzes"], "r1")
        # a final run's verdict shows before its analysis, which reads its content (80 s for a 25k-call run)
        self.assertEqual([(r["session_id"], r["tape"]) for r in own], [("r1", "VERIFY"), ("r1", "FINDING"),
                                                                       ("f1", "VERIFY")])
        self.assertEqual({(r["hash"], r["tk_seq"], r["analysis"]) for r in own}, {(None, None, True)})
        self.assertEqual(reviews["r1"]["findings"]["line"], "nothing found in what could be checked · reasoning "
                                                            "readable before 0 of 1 actions (0%)")
        self.assertEqual(reviews["r1"]["findings"]["not_checkable"], [
            {"rule": "TK-X201", "code": "no_response", "n": 1, "text": findings_v2.REASONS["no_response"][0]}])

    def test_a_run_still_being_written_shows_up_to_each_checkpoint(self):
        """A large run reached the page only once it stopped (~50 s late): a run whose records kept arriving was never
        fully covered by a checkpoint, so it was never verified. It is shown up to each checkpoint now; the verifier's
        report is a row when the run first shows and when it is final, its review updated in between."""
        recs = [v2rec(0, "run.registered", {"agent": {"name": "bulk"}}, "r1")] + [
            v2rec(i, "policy.decision", {"tool_use_id": f"c{i}", "tool": "Bash", "decision": "allow"}, "r1")
            for i in range(1, 5)] + [v2rec(5, "run.final", {}, "r1")]
        fake = mock.Mock(runs={("default", "r1"): {"seqs": list(range(6))}}, tree=mock.Mock(size=6))
        fake.iter_run.side_effect = lambda tenant, rid: iter(recs)
        verified = (mock.Mock(integrity="VERIFIED", assurance="dev"), 0, "Integrity: VERIFIED.")

        def rows():
            with feed.lock:
                return [(r["event"], r.get("tape")) for r in feed.records if r["session_id"] == "r1"]
        with mock.patch.object(view, "reader", return_value=fake), \
                mock.patch.object(view, "check", return_value=verified) as check, \
                mock.patch.object(view, "BACKOFF", 0):   # each refresh() checks the grown run (BACKOFF: its own test)
            fake.checkpoint_latest.return_value = (3, "note at 3")
            feed = store_feed(self, {"data_dir": self.d})
            self.assertTrue(wait_for(lambda: rows(), 5))
            self.assertEqual(rows(), [("SessionStart", None), ("PreToolUse", None), ("PreToolUse", None),
                                      ("tk_alert", "VERIFY")])
            fake.checkpoint_latest.return_value = (5, "note at 5")
            feed.refresh()
            self.assertEqual(rows()[4:], [("PreToolUse", None), ("PreToolUse", None), ("tk_run", None)])
            fake.checkpoint_latest.return_value = (6, "note at 6")
            feed.refresh()
            self.assertEqual(rows()[7:], [("SessionEnd", None), ("tk_alert", "VERIFY")])
        self.assertEqual([c.args[3] for c in check.call_args_list], ["note at 3", "note at 5", "note at 6"])
        with feed.lock:
            self.assertEqual([r["review"]["records"] for r in feed.records if r.get("review")], [3, 5, 6])

    def test_a_tenants_signer_run_is_the_signer_never_an_agent_run(self):
        signer = ("acme", view.SIGNER_RUN[1])   # content.accessed and content.erased go in each tenant's own
        fake = mock.Mock(runs={signer: {"seqs": [0]}, ("default", "r9"): {"seqs": [1]}})
        fake.checkpoint_latest.return_value = None
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "late"}}, key[1])])
        with mock.patch.object(view, "reader", return_value=fake):
            feed = store_feed(self, {"data_dir": self.d})
            self.assertTrue(wait_for(lambda: feed.records, 5))
        with feed.lock:
            self.assertEqual([r["session_id"] for r in feed.records], ["r9"])   # not listed as a pending agent run
        with mock.patch.object(view, "check", return_value=(mock.Mock(integrity="FAILED", assurance="none"), 1, "t")):
            feed._verify(fake, "note", signer, 1)
        with feed.lock:
            self.assertEqual((feed.records[-1]["signer"], feed.records[-1]["agent"]), (True, "signer"))

    def test_last_skips_each_tenants_signer_run(self):
        runs = {("default", "r1"): {"seqs": [1]}, ("acme", view.SIGNER_RUN[1]): {"seqs": [5]}}
        fake = mock.Mock(runs=runs)
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "a"}}, key[1]),
                                                       v2rec(1, "run.final" if key[1] == "r1" else "content.accessed",
                                                             {}, key[1])])
        exported, err = [], io.StringIO()
        with mock.patch.object(svc, "reader", return_value=fake), \
                mock.patch.object(svc, "signer_config", return_value={"data_dir": self.d}), \
                mock.patch.object(cli, "_export_v2", side_effect=lambda ns, show: exported.append(ns.run) or 1), \
                contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["last"]), 1)
        self.assertEqual((exported, err.getvalue()), (["r1"], ""))

    @pytest.mark.unverified_bundles
    def test_tampered_record_shows_only_the_failure(self):
        run_id = self.finished_run()
        self.service.close()
        path = os.path.join(self.d, "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data.count('"tool":"Bash"'), 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
        feed = store_feed(self, {"data_dir": self.d})
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity FAILED")
        self.assertIn(view.OPERATOR_SIDE, rep["text"])
        self.assertEqual(self.rows(feed, run_id), [rep])   # none of its events
        self.assertEqual(feed.verify()[1], [f"run {run_id} of tenant default: FAILED"])

    @pytest.mark.unverified_bundles
    def test_an_edit_of_a_run_already_shown_takes_its_records_back_at_its_next_check(self):
        """A run was checked only when it grew: an edit of records the page already showed stayed VERIFIED until the
        viewer restarted."""
        run_id = self.finished_run()
        feed = store_feed(self, {"data_dir": self.d})
        self.report(feed, run_id)
        self.service.close()
        path = os.path.join(self.d, "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            data = f.read()
        with mock.patch.object(view, "RECHECK_S", 0):
            with open(path, "w", encoding="utf-8") as f:
                f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
            self.assertTrue(wait_for(lambda: feed.verify()[1] == [f"run {run_id} of tenant default: FAILED"], 15))
        with feed.lock:
            self.assertEqual([r for r in feed.records if r.get("session_id") == run_id and not r.get("analysis")], [])

    def serve(self, feed, token="t0k", tls=None):
        srv = view.server(feed, "127.0.0.1", 0, token, tls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def session(self, port, timeout=5):
        """(connection, headers) of a browser that exchanged the printed token for its session cookie."""
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 401)   # no anonymous access, even on loopback
        c.request("GET", "/?token=t0k")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        return c, {"Cookie": r.getheader("Set-Cookie").split(";")[0]}

    def test_loopback_viewer_prints_a_token_url_and_needs_it(self):
        with mock.patch.object(view, "server") as server, mock.patch.dict(os.environ), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            os.environ.pop("TRACEKIT_VIEW_TOKEN", None)
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            self.assertEqual(view.main(["--data-dir", self.d]), 0)
        token = server.call_args[0][3]
        self.assertGreaterEqual(len(token), 32)
        self.assertIn(f"http://127.0.0.1:7778/?token={token} ", out.getvalue())
        with mock.patch.object(view, "server") as server, mock.patch.object(view, "Runs") as runs, \
                mock.patch.object(view, "load_config", return_value={"view": {"logs": ["a.dsn", "b.dsn"]}}), \
                mock.patch.dict(os.environ), contextlib.redirect_stdout(io.StringIO()) as out:
            os.environ.pop("TRACEKIT_VIEW_TOKEN", None)
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            runs.return_value.logs = ["a.dsn", "b.dsn"]
            self.assertEqual(view.main(["--config", "signer.yaml"]), 0)
        self.assertIn(f"http://127.0.0.1:7778/?token={server.call_args[0][3]}  (2 Postgres logs", out.getvalue())
        with self.assertRaises(ValueError):
            view.server(None, "127.0.0.1", 0, None)

    def test_why_logs_default_to_the_data_dir_when_present(self):
        def why(*args):
            with mock.patch.object(view, "server") as server, mock.patch.object(view.Store, "watch"), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                server.return_value.serve_forever.side_effect = KeyboardInterrupt
                server.return_value.server_address = ("127.0.0.1", 7778)
                self.assertEqual(view.main(["--data-dir", self.d, *args]), 0)
            return server.call_args[0][8], out.getvalue()
        store, out = why()   # no why logs: the store's own runs, imported as they verify
        self.assertNotEqual(store.root, os.path.join(self.d, view.WHY_DIR))
        self.assertIn("graphs: each verified run", out)
        os.makedirs(os.path.join(self.d, view.WHY_DIR))
        store, out = why("--allow-program", "m:SYSTEM")
        self.assertEqual((store.root, store.allow), (os.path.join(self.d, view.WHY_DIR), {"m:SYSTEM"}))
        self.assertIn("replay m:SYSTEM", out)
        other = os.path.join(self.d, "elsewhere")
        store, out = why("--why", other)
        self.assertEqual(store.root, other)
        self.assertIn("start with --allow-program", out)

    def test_a_store_with_no_why_logs_still_gets_a_graph_of_each_run_with_its_decisions(self):
        run_id = self.finished_run()
        why_dir = ts.tmpdir(self)
        feed = store_feed(self, {"data_dir": self.d}, on_run=functools.partial(view.mirror_run, why_dir))
        self.report(feed, run_id)
        why_id = os.path.basename(_target(why_dir, run_id, "default"))
        wait_for(lambda: os.listdir(why_dir) == [why_id], 15)   # renamed in, its .import-* staging folder gone
        store = Store(why_dir, out=feed)
        d = store.detail(why_id)
        calls = {n["tool"]: n for n in d["nodes"] if n["type"] == "action"}
        self.assertEqual(calls["rm"]["policy"]["decision"], "deny")   # GRAPH and NODE mark it DENIED with its rule
        self.assertEqual(calls["rm"]["policy"]["rule_ids"], ["T-DENY"])
        self.assertEqual(calls["pay"]["policy"]["decision"], "ask")
        self.assertEqual(calls["pay"]["policy"]["approval"]["decision"], "approve")
        self.assertEqual(calls["Bash"]["policy"]["decision"], "allow")
        self.assertTrue(store.workspace()["calls"])   # each signed call joins its imported why event (the WHY tab)
        ids = [n["id"] for n in d["nodes"]]
        view.mirror_run(why_dir, "default", run_id, store_records(self.d, run_id)[run_id])   # a re-import replaces it
        self.assertEqual(sorted(os.listdir(why_dir)), [why_id])
        # the same event ids: a re-import neither re-announces its alerts nor drops the page's selection
        self.assertEqual([n["id"] for n in Store(why_dir).detail(why_id)["nodes"]], ids)
        with self.assertRaises(IngestError) as e:   # the mirror is the store's: nothing ingests into it
            Store(why_dir, ingest=False).ingest({"events": [{}]}, "t")
        self.assertEqual(e.exception.status, 404)
        view.mirror_run(why_dir, "default", run_id, None)   # it failed verification: no graph says LOG INTACT
        self.assertEqual(os.listdir(why_dir), [])

    def test_a_mirror_waits_for_a_reader_windows_lets_deny_its_rename(self):
        """On Windows a reader with a file of a run's folder open (the why server's scan) denies the folder's rename:
        the graph of a run that left the live view stayed for the server's life."""
        why_dir = ts.tmpdir(self)
        os.makedirs(_target(why_dir, "r", "default"))
        rename, denied = os.rename, []

        def held(src, dst):
            if not denied:
                denied.append(src)
                e = PermissionError(13, "Access is denied")
                e.winerror = 5
                raise e
            rename(src, dst)
        with mock.patch.object(view.os, "rename", held):
            view.mirror_run(why_dir, "default", "r", None)
        self.assertEqual((os.listdir(why_dir), len(denied)), ([], 1))

    def test_mirror_folders_are_unique_per_tenant_and_run_id(self):
        names = {os.path.basename(_target("/w", rid, tenant)) for rid, tenant in (
            ("victim_run", "default"), ("victim:run", "default"), ("victim_run", "other"),
            ("x" * 100 + "a", "default"), ("x" * 100 + "b", "default"))}
        self.assertEqual(len(names), 5)
        self.assertTrue(all(n.startswith("tk-") and len(n) < 120 for n in names))

    def test_a_mirror_takes_the_feeds_reasons_and_comes_after_the_tape(self):
        run_id = self.finished_run()
        seen = []
        feed = store_feed(self, {"data_dir": self.d}, on_run=lambda *a: seen.append((len(feed.records), a)))
        self.report(feed, run_id)
        wait_for(lambda: seen, 15)
        shown, (tenant, rid, records, reasons) = seen[0]
        self.assertEqual((tenant, rid), ("default", run_id))
        self.assertIs(reasons, feed.tr.reasons)   # computed once, with the operator's policy: not per import
        self.assertTrue(shown and records)   # the tape had the run before its graph was built
        with mock.patch.object(view, "policy_reasons", side_effect=AssertionError("recompiled the packs")):
            view.mirror_run(ts.tmpdir(self), tenant, rid, records, reasons)

    def test_a_stop_cleans_up_and_a_bad_bundle_keeps_its_name_and_code(self):
        before = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, before)
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            code = view.main(["--bundle", os.path.join(self.d, "missing.tkb")])
        self.assertEqual(code, 2)   # observe's exit code for an unreadable bundle, not 1
        self.assertIn("tracekit view: cannot read bundle", err.getvalue())
        with self.assertRaises(SystemExit):   # SIGTERM exits through atexit, which removes the temp dirs
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

    def test_hostile_tool_names_are_data_and_the_page_escapes_every_sink(self):
        run = self.client.run(agent="a")
        run.decide("c1", XSS, {"q": XSS})
        self.client.call("checkpoint_nudge", {})
        feed = store_feed(self, {"data_dir": self.d})
        self.report(feed, run.run_id)
        c, cookie = self.session(self.serve(feed))
        c.request("GET", "/", headers=cookie)
        r = c.getresponse()
        page = r.read().decode()
        self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy"))
        self.assertNotIn("<img", page)
        self.assertEqual(unescaped(script_of(page)), [])
        c.request("GET", "/api/snapshot", headers=cookie)
        snap = json.loads(c.getresponse().read())
        self.assertIn(XSS, [x.get("tool_name") for x in snap["records"]])

    def test_sse_shows_a_new_record(self):
        feed = store_feed(self, {"data_dir": self.d})
        c, cookie = self.session(self.serve(feed), 15)
        c.request("GET", "/api/snapshot", headers=cookie)
        start = json.loads(c.getresponse().read())["next"]
        c.request("GET", f"/api/stream?from={start}", headers=cookie)
        stream = c.getresponse()
        run = self.client.run(agent="late")
        run.decide("c1", "Bash", {"command": "ls"})
        self.client.call("checkpoint_nudge", {})
        while True:
            line = stream.fp.readline()
            if line.startswith(b"data: ") and json.loads(line[6:]).get("tool_name") == "Bash":
                break

    def test_beyond_loopback_needs_https(self):
        self.assertEqual(view.main(["--host", "0.0.0.0", "--data-dir", self.d]), 2)

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a certificate")
    def test_https_serves_with_a_secure_cookie(self):
        cert, key = os.path.join(self.d, "c.pem"), os.path.join(self.d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days",
                        "1", "-keyout", key, "-out", cert], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        port = self.serve(store_feed(self, {"data_dir": self.d}), "s3cret", tls)
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ssl._create_unverified_context())
        c.request("GET", "/?token=s3cret")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        self.assertIn("; Secure", r.getheader("Set-Cookie"))

    def test_close_stops_the_feeds_threads(self):
        feed = view.StoreFeed({"data_dir": self.d}, on_run=lambda *a: None)
        self.assertEqual(len(feed.threads), 2)   # the watch and the mirror thread
        feed.close()
        self.assertEqual([t.is_alive() for t in feed.threads], [False, False])


TOKEN = "why-test-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}


def cite(path, run_id, seqs):
    """Rewrite the why log at `path` as the signer-backed runtime writes it: each tool call cites the signed record it
    produced (`tracekit`: run_id, run_seq from `seqs`, in order), the chain rebuilt."""
    with open(os.path.join(path, "events.jsonl"), encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    prev, seqs = GENESIS, iter(seqs)
    for ev in events:
        if ev["type"] == "action":
            ev["tracekit"] = {"run_id": run_id, "run_seq": next(seqs), "type": "tool.result"}
        ev["prev_hash"] = prev
        ev.pop("hash")
        ev["hash"] = prev = event_hash(ev)
    with open(os.path.join(path, "events.jsonl"), "w", encoding="utf-8") as f:
        f.writelines(json.dumps(ev, sort_keys=True) + "\n" for ev in events)


class WhyServer(unittest.TestCase):
    """The viewer on why logs, as `tracekit why serve` runs it: a why.server.Store publishing into its own feed."""

    def setUp(self):
        self.tmp = ts.tmpdir(self)
        self.store = Store(os.path.join(self.tmp, "srv"), ["tracekit.why.demo:SYSTEM"], tape=True)
        self.httpd = view.server(self.store.out, "127.0.0.1", 0, TOKEN, why=self.store)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.store.watch()
        self.addCleanup(self.store.stop)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def get(self, path):
        status, _, body = self.request("GET", path, AUTH)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def post(self, path, body, headers=JSON):
        status, _, out = self.request("POST", path, headers, json.dumps(body).encode())
        return status, json.loads(out)

    def stream(self, timeout=10):
        """The why messages on the viewer's event stream, until a run finishes; and the records the tape gets."""
        out, rows, ready = [], [], threading.Event()

        def read():
            req = urllib.request.Request(self.base + "/api/stream", headers=AUTH)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ready.set()
                for line in r:
                    if line.startswith(b"data: "):
                        rec = json.loads(line[6:])
                        if rec["event"] != "why":
                            rows.append(rec)
                        elif rec["why"]["type"] == "run":
                            out.append(rec["why"])
                            if out[-1]["finished"]:
                                return

        t = threading.Thread(target=read, daemon=True)
        t.start()
        ready.wait(timeout)
        return out, rows, t


class WhyData(WhyServer):
    """What the page shows of a why run: argument provenance, candidate causes, a test's result, the signed calls each
    why event cites, and the tape rows of a why log."""

    def exfil(self):
        return next(r for r in (SYSTEM.run(seed=s, out_dir=self.store.root, run_id=f"fc-{s}") for s in range(8))
                    if target_hits(r, EXFIL_TARGET))

    def test_provenance_candidates_and_a_test_result(self):
        run = self.exfil()
        d = self.get(f"/api/why/runs/{run.run_id}")
        self.assertEqual(d["replay"], {"program": "tracekit.why.demo:SYSTEM", "allowed": True})
        send = next(k for k, v in d["actions"].items() if "vendor-compliance" in v["target"])
        prov = d["actions"][send]["provenance"]
        bad = [p for p in prov if p["status"] == "untrusted-only"]
        self.assertTrue(bad and all(s["trust"] == "untrusted" for p in bad for s in p["sources"]))
        self.assertIn("vendor:portal/notes.md", [s["label"] for p in bad for s in p["sources"]])
        cands = {c["intervention"]: c for c in d["actions"][send]["candidates"]}
        self.assertEqual(cands["input:vendor:portal/notes.md"]["status"], "untested")
        self.assertTrue(d["actions"][send]["lineage"])
        code, r = self.post(f"/api/why/runs/{run.run_id}/tests", {"intervention": "input:vendor:portal/notes.md",
                                                                  "target": EXFIL_TARGET, "n": 20})
        self.assertEqual((code, r["verdict"]), (200, "causal"))
        c = next(c for c in self.get(f"/api/why/runs/{run.run_id}")["actions"][send]["candidates"]
                 if c["intervention"] == "input:vendor:portal/notes.md")
        self.assertEqual((c["status"], c["test"]["n"] >= 20), ("confirmed", True))
        self.assertGreater(c["test"]["p_with"], c["test"]["p_without"])

    def test_every_node_carries_what_its_node_detail_shows(self):
        """Clicking a GRAPH node opens NODE (Causeway's drawer): what each type saw, did or held, its links, its record."""
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="nodes")
        d = self.get(f"/api/why/runs/{run.run_id}")
        ids = {n["id"] for n in d["nodes"]}
        by_type = {n["type"]: n for n in d["nodes"]}
        self.assertEqual(set(by_type), {"input", "decision", "action", "message"})
        for n in d["nodes"]:
            self.assertTrue(n["hash"] and n["prev"] and n["ts"] and n["label"], n)
        dec, act = by_type["decision"], by_type["action"]
        self.assertTrue(dec["model"] and dec["output"] and dec["context"])
        self.assertTrue(all(c["node"] is None or c["node"] in ids for c in dec["context"]))   # WHAT IT SAW links
        self.assertIn("args", act)
        self.assertIsInstance(act["result"], str)
        self.assertTrue(by_type["input"]["content"] and by_type["message"]["to"])
        self.assertTrue(all(e["src"] in ids and e["dst"] in ids for e in d["edges"]))   # CAME FROM / LED TO links
        status, page = self.request("GET", "/", AUTH)[::2]
        self.assertEqual(status, 200)
        self.assertIn(b'data-wtab="node"', page)

    def test_workspace_has_every_alert_and_the_signed_call_each_why_event_cites(self):
        run = self.exfil()
        acts = run.of_type("action")
        cite(run.path, "signed-run", range(10, 10 + len(acts)))
        self.assertEqual(self.get("/api/why/workspace")["calls"], {})   # no signed record yet: nothing joins
        with self.store.out.lock:   # the signed records, the first of another tool than its why event says
            self.store.out.records.extend({"session_id": "signed-run", "tool_name": "other" if i == 0 else a["tool"],
                                           "v2": {"run_seq": 10 + i}} for i, a in enumerate(acts))
        ws = self.get("/api/why/workspace")
        self.assertEqual([r["run_id"] for r in ws["runs"]], [run.run_id])
        self.assertNotIn("signed-run|10", ws["calls"])
        self.assertEqual(ws["calls"]["signed-run|11"], [run.run_id, "ev:" + acts[1]["id"]])
        self.assertEqual(len(ws["calls"]), len(acts) - 1)
        with self.store.out.lock:   # a call that ran cites its result record, which names no tool: its decision's
            self.store.out.records[-len(acts)] = {"session_id": "signed-run", "tool_use_id": "c0", "v2": {"run_seq": 10}}
            self.store.out.records.append({"session_id": "signed-run", "tool_use_id": "c0", "tool_name": acts[0]["tool"],
                                           "v2": {"run_seq": 9}})
        self.assertEqual(self.get("/api/why/workspace")["calls"]["signed-run|10"], [run.run_id, "ev:" + acts[0]["id"]])
        high = [a for a in ws["alerts"] if a["severity"] == "high"]
        self.assertTrue(high and high[0]["run_id"] == run.run_id and "send_email" in high[0]["title"])
        node = next(n for n in self.get(f"/api/why/runs/{run.run_id}")["nodes"] if n["id"] == "ev:" + acts[0]["id"])
        self.assertEqual(node["tracekit"], {"run_id": "signed-run", "run_seq": 10, "type": "tool.result"})

    def test_a_why_log_on_the_tape(self):
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="t0")
        rows = tape(load_run(run.path))
        pre = [r for r in rows if r["event"] == "PreToolUse"]
        self.assertEqual([r["tool_name"] for r in pre], [a["tool"] for a in run.of_type("action")])
        self.assertEqual(pre[0]["why"], {"run": "t0", "node": "ev:" + run.of_type("action")[0]["id"]})
        self.assertEqual(rows[0]["event"], "SessionStart")
        self.assertEqual(rows[-1]["event"], "SessionEnd")
        self.assertTrue(all(r["session_id"] == "t0" for r in rows))
        sub = {r["agent_id"] for r in rows if r["event"] == "SubagentStart"}
        self.assertEqual(sub, {e["agent"] for e in run.of_type("agent.start")})

    def test_a_why_log_time_the_tape_cannot_read_shows_as_now_and_is_marked(self):
        """load_run does not check a log's ts: a row whose ts the tape cannot read shows as now (never 1970) and is
        marked ts_unread, which HORIZON sorts oldest."""
        run = load_run(SYSTEM.run(seed=0, out_dir=self.store.root, run_id="t1").path)
        run.events[1]["ts"] = "2026-10-27T10:00:00+00:00"
        rows, node = tape(run), "ev:" + run.events[1]["id"]
        self.assertEqual({r["why"]["node"] for r in rows if r.get("ts_unread")}, {node})
        self.assertTrue(all(abs(r["ts"] - time.time()) < 5 for r in rows if r["why"]["node"] == node))

    def test_replay_without_the_program_says_what_to_run(self):
        store = Store(os.path.join(self.tmp, "srv2"))
        SYSTEM.run(seed=0, out_dir=store.root, run_id="r")
        self.assertFalse(store.detail("r")["replay"]["allowed"])
        with self.assertRaises(IngestError) as e:
            store.test("r", {"intervention": "untrusted", "target": "tool=send_email"})
        self.assertEqual(e.exception.status, 403)
        self.assertIn("--allow-program tracekit.why.demo:SYSTEM", str(e.exception))


class WhyIngest(WhyServer):
    def test_remote_ingest_then_investigate_and_test(self):
        for s in range(3):
            SYSTEM.run(seed=s, run_id=f"remote-{s}", sink=HttpSink(self.base, TOKEN, batch=7))
        ws = self.get("/api/why/workspace")
        self.assertEqual({r["run_id"] for r in ws["runs"]}, {"remote-0", "remote-1", "remote-2"})
        self.assertTrue(all(r["integrity"] == "ok" for r in ws["runs"]))
        self.assertEqual(self.get("/api/why/runs/remote-0")["summary"]["alerts"]["high"], 1)
        code, r = self.post("/api/why/runs/remote-0/tests", {"intervention": "input:vendor:*", "target": EXFIL_TARGET,
                                                             "n": 20})
        self.assertEqual((code, r["verdict"]), (200, "causal"))
        d = self.get("/api/why/runs/remote-0")
        send = [k for k, v in d["actions"].items() if "vendor-compliance" in v["target"]][0]
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")

    def test_rejects_bad_token_tamper_and_gaps(self):
        run = SYSTEM.run(seed=0, run_id="t1")
        evs = run.events
        blobs = {r: run.blobs[r] for ev in evs[:3] for r in referenced_refs(ev)}   # what the first batch references
        ingest = lambda events, blobs, token=TOKEN: self.post(  # noqa: E731
            "/v1/ingest", {"events": events, "blobs": blobs},
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})[0]
        self.assertEqual(ingest(evs, blobs, "wrong"), 401)
        cookie = _session(self.httpd.RequestHandlerClass.session_key, int(time.time()) + 60)   # the token's session
        self.assertEqual(self.request("POST", "/v1/ingest", {"Cookie": f"tracekit_observe={cookie}"}, b"{}")[0], 401)
        bad = json.loads(json.dumps(evs[:3]))
        bad[2]["agent"] = "mallory"
        self.assertEqual(ingest(bad, blobs), 422)
        self.assertEqual(ingest(evs[1:4], {r: run.blobs[r] for ev in evs[1:4] for r in referenced_refs(ev)}), 409)
        fake = dict(blobs)
        fake[next(iter(fake))] = "forged"
        self.assertEqual(ingest(evs[:3], fake), 422)
        self.assertEqual(ingest(evs[:3], blobs), 200)
        self.assertEqual(ingest(evs[:3], blobs), 409)  # replayed batch

    def test_malformed_ingest_is_rejected_and_cannot_break_the_workspace(self):
        ev = {"schema": "tracekit.why.event.v1", "seq": 0, "id": "x", "prev_hash": GENESIS, "run_id": "poison",
              "agent": "run", "type": "decision", "ts": "2026-10-09T00:00:00.000000Z"}
        ev["hash"] = event_hash(ev)
        self.assertEqual(self.post("/v1/ingest", {"events": [ev], "blobs": {}})[0], 422)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "abc"}, b"{}")[0], 411)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "99999999"})[0], 413)
        self.assertEqual(self.request("POST", "/v1/ingest", JSON, b"[1]")[0], 400)
        os.makedirs(os.path.join(self.store.root, "broken"))  # a broken run written straight to disk is listed
        with open(os.path.join(self.store.root, "broken", "events.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        SYSTEM.run(seed=1, out_dir=self.store.root, run_id="fine")
        with contextlib.redirect_stderr(io.StringIO()):
            runs = {x["run_id"]: x for x in self.get("/api/why/workspace")["runs"]}
        self.assertEqual(set(runs), {"fine", "poison"})   # the log's own run id: analysed, bad values and all
        with open(os.path.join(self.store.root, "broken", "events.jsonl"), "w", encoding="utf-8") as f:
            f.write("{not json\n")
        with contextlib.redirect_stderr(io.StringIO()):
            runs = {x["run_id"]: x for x in self.get("/api/why/workspace")["runs"]}
            self.assertEqual(self.request("GET", "/api/why/runs/broken", AUTH)[0], 422)
        self.assertEqual(set(runs), {"fine", "broken"})   # listed as broken, not dropped
        self.assertTrue(runs["broken"]["broken"] and not runs["fine"].get("broken"))


class WhyLive(WhyServer):
    def test_stream_announces_runs_written_to_disk_with_their_alerts_and_tape(self):
        msgs, rows, t = self.stream()
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="disk-0")  # a local Runtime, no sink
        t.join(10)
        self.assertTrue(msgs and msgs[0]["run_id"] == "disk-0" and msgs[-1]["finished"])
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("send_email", highs[0]["title"])
        self.assertEqual([r["tool_name"] for r in rows if r["event"] == "PreToolUse"],
                         [a["tool"] for a in run.of_type("action")])   # each event on the tape once

    def test_stream_announces_ingested_runs(self):
        msgs, _, t = self.stream()
        SYSTEM.run(seed=0, run_id="remote-live", sink=HttpSink(self.base, TOKEN))
        t.join(10)
        self.assertEqual(msgs[0]["run_id"], "remote-live")
        self.assertGreaterEqual(len(msgs), 3)  # flushed per tool call, not only at the end
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertGreaterEqual(len(highs), 1)
        self.assertEqual(len(highs), len({(a["title"], a["node"]) for a in highs}))

    def test_find_the_cause_endpoint(self):
        run = next(r for r in (SYSTEM.run(seed=s, out_dir=self.store.root, run_id=f"fc-{s}") for s in range(8))
                   if target_hits(r, EXFIL_TARGET))
        code, out = self.post(f"/api/why/runs/{run.run_id}/attribute", {"target": EXFIL_TARGET, "n": 10, "n_max": 40})
        self.assertEqual(code, 200)
        self.assertEqual((out["causes"][0]["intervention"], out["causes"][0]["role"]),
                         ("input:vendor:portal/notes.md", "primary"))
        d = self.get(f"/api/why/runs/{run.run_id}")
        send = next(k for k, v in d["actions"].items() if "vendor-compliance" in v["target"])
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")


class WhyPage(WhyServer):
    def test_a_task_kept_out_of_the_log_reads_as_committed(self):
        # a signed run's imported task is a committed value, not text: the run header showed "[object Object]"
        out = page_js(["COMMITTED", "taskText"], 'for (const v of [{content: COMMITTED, hash: "h"}, "Close ACC-9", null])'
                                                 ' console.log(JSON.stringify(taskText(v)))')
        self.assertEqual([json.loads(x) for x in out.splitlines()],
                         ["task: content committed, not in the log", "Close ACC-9", ""])

    def test_the_page_is_the_viewers_and_the_why_api_needs_the_token(self):
        self.assertEqual(self.request("GET", "/api/why/workspace")[0], 401)
        status, h, _ = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(status, 303)
        self.assertNotIn(TOKEN, h["Location"] + h["Set-Cookie"])
        self.assertIn("HttpOnly; SameSite=Strict", h["Set-Cookie"])
        session = {"Cookie": h["Set-Cookie"].split(";")[0]}
        status, h, page = self.request("GET", "/", session)
        self.assertEqual(status, 200)
        for directive in ("script-src 'nonce-", "default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"):
            self.assertIn(directive, h["Content-Security-Policy"])
        self.assertIn(b'data-wtab="why"', page)
        self.assertEqual(unescaped(script_of(page.decode())), [])
        self.assertIn("DESK · RUNS · LIVE · APPROVALS · PERMISSIONS · HORIZON · INFLUENCE".encode(), page)
        self.assertIn("1–7 · OVERVIEW · CALLS · TIMELINE · GRAPH · WHY · AGENTS · EVIDENCE".encode(), page)
        self.assertIn(b'<option value="${esc(a)}"', page)   # an agent name with odd spaces still matches its filter
        self.assertEqual(self.request("GET", "/api/why/workspace", session)[0], 200)

    def test_foreign_host_is_refused_without_the_token(self):
        self.assertEqual(self.request("GET", "/api/why/workspace", {"Host": "evil.example:7788"})[0], 403)
        self.assertEqual(self.request("GET", "/api/why/workspace", {**AUTH, "Host": "evil.example:7788"})[0], 200)
        session = {"Cookie": self.request("GET", f"/?token={TOKEN}")[1]["Set-Cookie"].split(";")[0]}
        self.assertEqual(self.request("POST", "/api/why/runs/x/tests", {
            **session, "Content-Type": "application/json", "Host": "evil.example"}, b"{}")[0], 403)
        self.assertEqual(self.request("POST", "/v1/ingest", {"Host": "evil.example"}, b"{}")[0], 403)
        # remote agents reach the server by its DNS name: the bearer token is enough
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Host": "why.example.com"}, b"{}")[0], 400)

    def test_replay_posts_need_the_token_and_a_same_origin_json_body(self):
        SYSTEM.run(seed=0, out_dir=self.store.root, run_id="r")
        body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, "n": 2}).encode()
        for headers, status in (({"Content-Type": "application/json"}, 401),
                                ({**AUTH, "Content-Type": "text/plain"}, 403),
                                ({**AUTH}, 403),
                                ({**JSON, "Origin": "http://evil.example"}, 403),
                                ({**JSON, "Content-Length": "99999999"}, 413)):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/api/why/runs/r/tests", headers, body)[0], status)
        for bad in ({"n": "x"}, {"n": None}, {"n_max": [1]}):
            with self.subTest(bad=bad):
                bad_body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, **bad}).encode()
                self.assertEqual(self.request("POST", "/api/why/runs/r/tests", JSON, bad_body)[0], 400)
                self.assertEqual(self.request("POST", "/api/why/runs/r/attribute", JSON, bad_body)[0], 400)
        self.assertEqual(self.request("POST", "/api/why/runs/r/tests", JSON, body)[0], 200)
        self.assertEqual(self.request("POST", "/api/why/runs/no-such/tests", JSON, body)[0], 404)



class OneViewer(unittest.TestCase):
    """`tracekit view` is the one viewer: the v1 ledger or bundle (`tracekit observe`) and why logs alone (`tracekit
    why serve`) on its server, token and nav; the old commands keep working and say so."""
    SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "sample")

    def main(self, *args):
        """(code, the args view.server was called with, stdout) of `tracekit view ARGS`, the server not started."""
        with mock.patch.object(view, "server") as server, mock.patch.object(Store, "watch"), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            code = view.main(list(args))
        return code, server.call_args and server.call_args[0], out.getvalue()

    def get(self, port, path, headers):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        self.addCleanup(c.close)
        c.request("GET", path, headers=headers)
        r = c.getresponse()
        return r.status, r.read().decode()

    def test_v1_bundle_is_served_on_the_viewers_server_and_a_tampered_one_is_refused(self):
        code, args, out = self.main("--bundle", os.path.join(self.SAMPLE, "demo-run.tkb"))
        feed, token = args[0], args[3]
        self.assertEqual(code, 0)
        self.assertIsInstance(feed, observe.Feed)
        # the bundle it shows, not the temp ledger it was unpacked to
        self.assertIn(f"(bundle: {os.path.join(self.SAMPLE, 'demo-run.tkb')}, verified, read-only)", out)
        self.assertNotIn(feed.path, out)
        srv = view.server(feed, "127.0.0.1", 0, token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        self.assertEqual(self.get(port, "/api/verify", {})[0], 401)   # the viewer's token, unlike observe's default
        auth = {"Authorization": f"Bearer {token}"}
        wait_for(lambda: json.loads(self.get(port, "/api/verify", auth)[1])["records"] > 0)
        self.assertTrue(json.loads(self.get(port, "/api/verify", auth)[1])["ok"])
        # a bundle has no why logs (204, not a 404 in the console) and the page says BUNDLE, not LIVE
        self.assertEqual(self.get(port, "/api/why/workspace", auth)[0], 204)
        self.assertEqual(json.loads(self.get(port, "/api/snapshot", auth)[1])["source"], "bundle")
        status, page = self.get(port, "/", auth)
        self.assertEqual(status, 200)
        self.assertIn('<nav class="nav"><a href="/" class="on">LIVE</a></nav>', page)
        code, args, _ = self.main("--bundle", os.path.join(self.SAMPLE, "demo-run-tampered.tkb"))
        self.assertNotEqual(code, 0)
        self.assertIsNone(args)

    def test_v1_ledger_defaults_to_its_home_and_stays_on_loopback(self):
        home = ts.tmpdir(self)
        code, args, out = self.main("--ledger", home)
        self.assertEqual((code, args[0].path), (0, os.path.join(home, "ledger", "ledger.jsonl")))
        for host in ("0.0.0.0", "192.0.2.1"):   # the v1 ledger stays on loopback, as observe kept it, even with TLS
            self.assertEqual(self.main("--ledger", home, "--host", host, "--tls-cert", "c", "--tls-key", "k")[:2],
                             (2, None))

    def test_why_alone_is_why_serve(self):
        root = ts.tmpdir(self)
        code, args, out = self.main("--why", root, "--allow-program", "m:SYSTEM", "--webhook", "http://127.0.0.1:9/")
        store = args[8]
        self.assertEqual(code, 0)
        self.assertEqual((store.root, store.tape, store.allow, args[0]), (root, True, {"m:SYSTEM"}, store.out))
        self.assertIsNotNone(store.webhook)
        self.assertIn(f"(why logs alone: {root})", out)

    def test_one_nav_reaches_every_page_this_server_has(self):
        runs = mock.Mock()
        runs.search.return_value = {"runs": [], "next": None}
        srv = view.server(WhyFeed(), "127.0.0.1", 0, "t0k", runs=runs)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port, auth = srv.server_address[1], {"Authorization": "Bearer t0k"}
        for path, on in (("/", "LIVE"), ("/runs", "RUNS")):
            status, page = self.get(port, path, auth)
            self.assertEqual(status, 200)
            self.assertIn('<a href="/" class="%s">LIVE</a><a href="/runs" class="%s">RUNS</a>'
                          % ("on" if on == "LIVE" else "", "on" if on == "RUNS" else ""), page)
            # no way to the approval pages this server lacks: none in its nav, and the terminal page's own links to it
            # are drawn only from the nav's link (its APPROVALS page lists the holds read-only on every server)
            self.assertNotIn("APPROVALS", re.search(r'<nav class="nav">.*?</nav>', page).group(0))
            for link in re.findall(r'.{0,60}<a href="/approvals">', page):
                self.assertIn("DESK()", link)
        self.assertEqual(self.get(port, "/runs", {})[0], 401)

    def test_observe_and_why_serve_say_they_are_part_of_view_and_keep_working(self):
        with mock.patch.object(observe, "Feed"), mock.patch.object(observe, "ThreadingHTTPServer") as httpd, \
                contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            httpd.return_value.serve_forever.side_effect = KeyboardInterrupt
            httpd.return_value.server_address = ("127.0.0.1", 7777)
            self.assertEqual(observe.main(["--home", ts.tmpdir(self)]), 0)
        self.assertEqual(err.getvalue(), observe.NOTICE + "\n")
        with mock.patch.object(view, "server") as server, contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7788)
            why_cli.main(["serve", ts.tmpdir(self)])
        self.assertTrue(server.called)
        self.assertEqual(err.getvalue().splitlines(), ["tracekit why serve is now part of tracekit view: "
                                                       "`tracekit view --why ROOT`; this command keeps working"])

class Pages(unittest.TestCase):
    def test_the_runs_page_takes_the_token_and_a_page_without_it_says_so_in_words(self):
        """/runs?token= answered raw 401 JSON; a person at a page without the token got JSON too."""
        srv = view.server(None, "127.0.0.1", 0, "t0k", runs=mock.Mock())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/runs")
        r = c.getresponse()
        self.assertEqual((r.status, r.getheader("Content-Type")), (401, "text/html; charset=utf-8"))
        self.assertIn("needs its token", r.read().decode())
        c.request("GET", "/api/runs")
        r = c.getresponse()
        self.assertEqual((r.status, json.loads(r.read())), (401, {"error": "missing or wrong token"}))
        c.request("GET", "/runs?token=t0k")
        r = c.getresponse()
        r.read()
        self.assertEqual((r.status, r.getheader("Location")), (303, "/runs"))
        self.assertTrue(r.getheader("Set-Cookie").startswith("tracekit_observe="))


    def test_text_set_on_the_page_shows_bidi_and_invisible_characters_escaped(self):
        """DETAIL's heading is set as text: a tool name holding U+202E rendered reversed there, though escaped
        everywhere else."""
        page = observe.read_text(observe.UI)
        sinks = re.findall(r'\$\("detsum"\)\.textContent = ([^;]*);', page)
        self.assertEqual([x for x in sinks if not (x.startswith("vis(") or re.fullmatch(r'"[^"]*"', x))], [])
        if shutil.which("node"):
            self.assertEqual(page_js(["vis"], 'process.stdout.write(vis("rm\\u202e/hs.exe <b>"))'),
                             "rm\\u202e/hs.exe <b>")

    def test_runs_tape_rows_and_alerts_open_by_keyboard(self):
        """Runs, tape rows and alerts took no keyboard focus: a keyboard user could open none of them."""
        page = observe.read_text(observe.UI)
        for row in ('data-run="" tabindex="0"', 'data-run="${esc(r.id)}" tabindex="0"',
                    'data-i="${esc(row.i)}" tabindex="0"', 'data-al="${esc(al.i)}" tabindex="0"'):
            self.assertIn(row, page)
        self.assertIn('if (e.key === "Enter" && e.target.matches("[data-run][tabindex],[data-i][tabindex],[data-wf][tabindex],'
                      '[data-al][tabindex],[data-grp][tabindex],[data-orun][tabindex]")) e.target.click();', page)


VERIFIED = (mock.Mock(integrity="VERIFIED", assurance="dev"), 0, "Integrity: VERIFIED.")
FAILED = (mock.Mock(integrity="FAILED", assurance="none"), 1, "[FAIL] signatures — seq 1: bad signature\n\nFAILED.")


class LiveRuns(unittest.TestCase):
    """What a viewer left running shows as runs grow, fail at a later checkpoint and leave the live view, and what that
    costs; the store is a fake and each check's verdict is given."""

    def setUp(self):
        self.d = ts.tmpdir(self)
        self.recs = {"r1": [v2rec(0, "run.registered", {"agent": {"name": "a"}}, "r1"),
                            v2rec(1, "policy.decision", {"tool": "Bash", "decision": "allow"}, "r1")]}
        self.fake = mock.Mock(tree=mock.Mock(size=10 ** 6))
        self.fake.iter_run.side_effect = lambda tenant, rid: iter(list(self.recs[rid]))
        self.fake.checkpoint_latest.return_value = (10 ** 6, "note")
        self.now, self.cfg = [1000.0], {"data_dir": self.d}
        real = view.reader   # another test's feed, still watching its own store, reads that store
        clock = types.SimpleNamespace(time=lambda: self.now[0], thread_time=lambda: self.now[0], sleep=time.sleep)
        for p in (mock.patch.object(view, "reader", side_effect=lambda cfg: self.fake if cfg is self.cfg else real(cfg)),
                  mock.patch.object(view, "time", clock)):
            p.start()
            self.addCleanup(p.stop)

    def feed(self, verdicts, **kw):
        """A StoreFeed the test refreshes itself (no watch thread); `verdicts(run_id)`: each check's answer."""
        self.checks, real = [], view.check

        def check(reader, tenant, run_id, note, trust, out, memo):
            if reader is not self.fake:
                return real(reader, tenant, run_id, note, trust, out, memo)
            self.checks.append(run_id)
            self.now[0] += 2   # each check takes 2 s
            return verdicts(run_id)
        p = mock.patch.object(view, "check", side_effect=check)
        p.start()
        self.addCleanup(p.stop)
        with mock.patch.object(view, "read_vkeys", return_value=[]), \
                mock.patch.object(view.StoreFeed, "_watch", lambda feed: None):
            return view.StoreFeed(self.cfg, **kw)

    def refresh(self, feed, **grow):
        for run_id, n in grow.items():
            self.recs.setdefault(run_id, [v2rec(0, "run.registered", {"agent": {"name": run_id}}, run_id)])
            self.recs[run_id] += [v2rec(len(self.recs[run_id]), "policy.decision", {"tool": "Bash", "decision": "allow"},
                                        run_id) for _ in range(n)]
        self.fake.runs = {("default", k): {"seqs": [r["event"]["seq"] for r in v]} for k, v in self.recs.items()}
        feed.refresh()

    def served(self, feed):
        """(snapshot, the rows a stream from position 0 sends) over HTTP, as the page reads them."""
        srv = view.server(feed, "127.0.0.1", 0, "t0k")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        auth = {"Authorization": "Bearer t0k"}
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/api/snapshot", headers=auth)
        snap = json.loads(c.getresponse().read())
        c.request("GET", "/api/stream?from=0", headers=auth)
        stream, rows = c.getresponse(), []
        while len(rows) < len(snap["records"]) - len(getattr(feed, "kept", {})):
            line = stream.fp.readline()
            if line.startswith(b"data: "):
                rows.append(json.loads(line[6:]))
        c.close()
        return snap, rows

    def test_a_run_that_fails_at_a_later_checkpoint_takes_back_every_record_it_showed(self):
        """A run that verified at one checkpoint and failed at the next kept its earlier rows on the tape as SIGNED,
        next to a review saying none of its records are shown, and its VERIFIED report and FINDING alerts (counted in
        HIGH ALERTS). They are taken back from the snapshot and the stream; the page drops them on the failed review;
        if the run verifies again it is shown again from its start."""
        verdicts = [VERIFIED, FAILED, VERIFIED]
        feed = self.feed(lambda run_id: verdicts.pop(0))
        self.refresh(feed)
        self.now[0] += 60
        self.refresh(feed, r1=1)
        snap, streamed = self.served(feed)
        for rows in (snap["records"], streamed):
            self.assertEqual([(r["event"], r.get("analysis"), (r.get("review") or {}).get("verdict")) for r in rows],
                             [("tk_alert", True, "failed")])
        self.assertEqual(feed.verify()[1], ["run r1 of tenant default: FAILED"])
        self.now[0] += 60
        self.refresh(feed, r1=1)
        snap, _ = self.served(feed)
        self.assertEqual([r["v2"]["run_seq"] for r in snap["records"] if not r.get("analysis")], [0, 1, 2, 3])
        if shutil.which("node"):   # the page drops them too, its own report and findings included
            rows = [{"session_id": "r1", "tenant": "default", "analysis": True, "review": {"verdict": "verified"}},
                    {"session_id": "r1", "tenant": "default", "analysis": True, "tape": "FINDING"},
                    {"session_id": "r1", "tenant": "default", "v2": {"run_seq": 0}},
                    {"session_id": "r2", "tenant": "default", "analysis": True, "tape": "FINDING"}]
            self.assertEqual(json.loads(page_js(["accept"], f"""
                let V2 = true, R = null, scope = null, DROPPED = 0, MAXREC = 50000;
                const ALL = [], RUNS = new Map(), document = {{ body: {{ classList: {{ add() {{}} }} }} }};
                const inScope = () => true, ingest = () => {{}}, rebuild = () => {{}}, stopRun = () => {{}}, toastOf = () => {{}}, LOADED = new Map();
                for (const r of {json.dumps(rows)}) accept(r);
                accept({{ session_id: "r1", tenant: "default", analysis: true, review: {{ verdict: "failed" }} }});
                process.stdout.write(JSON.stringify(ALL.map(r => [r.session_id, r.review?.verdict ?? r.tape])));""")),
                [["r2", "FINDING"], ["r1", "failed"]])

    def test_a_flood_of_rows_never_pushes_a_failed_runs_verdict_out_of_the_run_list(self):
        """Past the live cap the oldest rows went, reviews included, and the page never said so: an agent writing
        records pushed a FAILED run out of the run list. Each run's latest review stays in the snapshot."""
        self.recs = {"a": [v2rec(0, "run.registered", {"agent": {"name": "a"}}, "a")]}
        feed = self.feed(lambda run_id: FAILED if run_id == "a" else VERIFIED)
        feed.max_records = 10
        self.refresh(feed)
        self.refresh(feed, b=20)
        snap, _ = self.served(feed)
        self.assertEqual((snap["dropped"], snap["max"]), (13, 10))
        reviews = {r["session_id"]: r["review"]["verdict"] for r in snap["records"] if r.get("review")}
        self.assertEqual(reviews, {"a": "failed", "b": "verified"})
        self.assertEqual(snap["records"][0]["session_id"], "a")   # kept rows come first: they are older
        with mock.patch.object(view, "KEPT_MAX", 1):   # past KEPT_MAX runs, a failed run's verdict goes last
            self.refresh(feed, c=20)
        self.assertEqual(list(feed.kept), [("default", "a")])

    def test_a_growing_run_is_checked_again_no_sooner_than_backoff_times_its_last_check(self):
        """One watch thread checked every run in full at each checkpoint (5.4 s for 10k records, 27 s for 50k, every
        10 s): a run being written pinned the CPU and the page fell minutes behind. A run is checked again no sooner
        than BACKOFF times its last check's time, and a run put off is checked once it is due with no store change."""
        feed = self.feed(lambda run_id: VERIFIED)
        self.refresh(feed)
        self.assertEqual((self.checks, feed.due), (["r1"], 1000 + view.RECHECK_S))
        self.refresh(feed, r1=1)
        self.assertEqual((self.checks, feed.due), (["r1"], 1002 + view.BACKOFF * 2))
        self.now[0] = feed.due
        self.refresh(feed)
        self.assertEqual(self.checks, ["r1", "r1"])
        with feed.lock:
            self.assertEqual(feed.records[-1]["review"]["records"], 3)

    def test_a_growing_runs_graph_is_imported_again_no_sooner_than_backoff_times_its_last_import(self):
        """A run's graph is imported whole each time it grows (4.7 s for 20k records, on a thread holding the CPU the
        checks need): it is imported again no sooner than BACKOFF times its last import's time, and a run that failed
        loses its graph at once."""
        imported, key = [], ("default", "r1")

        def on_run(tenant, run_id, records, reasons):
            self.now[0] += 2   # each import takes 2 s
            imported.append(records)
        feed = self.feed(lambda run_id: VERIFIED, on_run=on_run)

        def mirror(records, advance=0):
            with feed._mlock:
                self.now[0] += advance
                feed._mirror[key] = records
                feed._mlock.notify()
        mirror([1])
        self.assertTrue(wait_for(lambda: imported == [[1]], 5))
        mirror([2])
        self.assertFalse(wait_for(lambda: len(imported) > 1, 0.3))
        mirror(None)
        self.assertTrue(wait_for(lambda: imported == [[1], None], 5))
        mirror([3], advance=view.BACKOFF * 2)
        self.assertTrue(wait_for(lambda: imported == [[1], None, [3]], 5))

    def test_a_runs_graph_goes_when_its_rows_leave_the_live_view(self):
        """Each verified run's graph (its import, and the why server's analysis of it) stayed for the server's life,
        some 3.4 KiB a record: a 30k-call run peaked at 1.45 GB. A run whose rows left the live view loses its graph, as
        a run that fails does, so the why dir and the why server's cache hold the runs on the live view only."""
        why = os.path.join(self.d, "why")
        os.makedirs(why)
        store = Store(why, out=WhyFeed(), ingest=False)
        feed = self.feed(lambda run_id: VERIFIED, on_run=functools.partial(view.mirror_run, why))
        feed.max_records = 100
        for i in range(50):
            run = f"run{i}"
            at = {"log_id": "l", "tenant": "default"}   # what an import reads
            self.recs[run] = [v2rec(0, "run.registered", {"agent": {"name": run}}, run, **at)] + [
                v2rec(k, "policy.decision", {"tool": "Bash", "decision": "allow", "tool_use_id": f"c{k}",
                                             "policy_hash": "sha256:p", "rule_ids": []}, run, **at)
                for k in range(1, 6)]
            self.refresh(feed)
            store.scan(announce=False)
        live = {os.path.basename(_target(why, k[1], k[0])) for k in feed.latest if k[1] != "r1"}
        self.assertTrue(10 < len(live) < 20, live)
        self.assertTrue(wait_for(lambda: set(os.listdir(why)) == live, 10), (sorted(os.listdir(why)), sorted(live)))
        store.scan(announce=False)
        self.assertEqual(set(store._cache), {os.path.join(why, n) for n in live})

    def test_a_run_that_did_not_grow_is_checked_again_and_adds_no_rows_while_unchanged(self):
        """A run was checked only when it grew, so an edit of records already shown stayed VERIFIED until a restart."""
        verdicts = [VERIFIED, VERIFIED, FAILED]
        feed = self.feed(lambda run_id: verdicts.pop(0))
        self.refresh(feed)
        rows = len(feed.records)
        self.refresh(feed)
        self.assertEqual(self.checks, ["r1"])   # not due yet
        self.now[0] += view.RECHECK_S
        self.refresh(feed)
        self.assertEqual((self.checks, len(feed.records)), (["r1", "r1"], rows))   # unchanged: nothing new
        self.now[0] += view.RECHECK_S
        self.refresh(feed)
        with feed.lock:
            self.assertEqual(feed.records[-1]["review"]["verdict"], "failed")
            self.assertEqual([r for r in feed.records if not r.get("analysis")], [observe.RETRACTED] * 3)

    def test_a_run_whose_check_raises_says_not_checked_and_every_other_run_is_still_checked(self):
        """An error checking one run escaped the watch thread and ended it: no run was checked again. That run gets a
        "not checked" row and is tried again as a run that did not grow; the others are checked as before. A pending
        run whose unverified first record names no agent object (a store edit) raised AttributeError the same way."""
        self.recs["bad"] = [v2rec(0, "run.registered", {"agent": {"name": "bad"}}, "bad")]
        self.recs["edited"] = [v2rec(10 ** 7, "run.registered", {"agent": "x"}, "edited")]   # no note covers it yet
        feed = self.feed(lambda run_id: VERIFIED)
        real = feed.tr.feed

        def translate(rec):
            if rec["event"]["run_id"] == "bad":
                raise TypeError("unhashable type: 'list'")
            return real(rec)
        with mock.patch.object(feed.tr, "feed", side_effect=translate):
            self.refresh(feed)
        reviews = {r["session_id"]: r["review"] for r in feed.records if r.get("review")}
        self.assertEqual({k: (v["verdict"], v["agent"]) for k, v in reviews.items()},
                         {"r1": ("verified", "a"), "bad": ("error", None), "edited": ("pending", None)})
        [row] = [r for r in feed.records if r.get("session_id") == "bad"]
        self.assertEqual(row["title"], "RUN bad · NOT CHECKED: error")
        self.assertIn("TypeError: unhashable type: 'list'", row["text"])
        self.assertEqual(feed.verify()[1], ["run bad of tenant default: NOT CHECKED (error)"])
        self.refresh(feed)
        self.assertEqual(self.checks, ["r1", "bad"])   # not tried again at once
        self.now[0] += view.RECHECK_S
        self.refresh(feed)
        self.refresh(feed)
        self.assertEqual(self.checks[2:], ["r1", "bad"])   # one run a pass, the one checked longest ago first
        self.assertEqual(feed.latest[("default", "bad")]["review"]["verdict"], "verified")
        self.assertEqual(feed.verify()[1], [])

    def test_a_watch_that_ends_stops_the_page_saying_live(self):
        """Had the watch thread ended, no run would be checked again while the page went on saying LIVE: the viewer
        says verification stopped (/api/verify's `stopped`, and a problem), and the page shows STOPPED, not LIVE."""
        class Ended(BaseException):
            pass
        with mock.patch.object(view, "read_vkeys", return_value=[]), \
                mock.patch.object(view.StoreFeed, "refresh", side_effect=Ended("out of memory")), \
                mock.patch.object(threading, "excepthook", lambda args: None):
            feed = store_feed(self, self.cfg)
            self.assertTrue(wait_for(lambda: not feed.threads[-1].is_alive(), 5))
        self.assertEqual(feed.stopped, "verification stopped (Ended: out of memory): no run is checked until tracekit "
                                       "view restarts")
        self.assertEqual(feed.verify()[1], [feed.stopped])
        srv = view.server(feed, "127.0.0.1", 0, "t0k")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/api/verify", headers={"Authorization": "Bearer t0k"})
        self.assertEqual(json.loads(c.getresponse().read())["stopped"], feed.stopped)
        if not shutil.which("node"):
            self.skipTest("needs node to run the page's renderTop()")
        top = json.loads(page_js(["renderTop", "filterChips"], f"""
            const el = {{}}, $ = id => el[id] ??= {{ classList: {{ toggle() {{}} }} }};
            const document = {{ URL: "http://127.0.0.1/", body: {{ classList: {{ toggle() {{}} }} }} }};
            let mode = "live", liveOk = true, liveErr = "", SOURCE = "", STOPPED = {json.dumps(feed.stopped)};
            const BOOT = null, V2 = true, scope = null, RUNS = new Map(), F = {{}}, TZ = "UTC", nowTs = () => 0;
            const chainState = {{ ok: false, n: 0, detail: "" }}, esc = s => s, put = () => {{}};
            renderTop();
            process.stdout.write(JSON.stringify([el.mode.textContent, el.lost.hidden, el.lost.textContent,
                                                 el.chain.textContent]));"""))
        self.assertEqual(top, ["STOPPED", False, feed.stopped, "✗ VERIFICATION STOPPED"])


class BoundedState(unittest.TestCase):
    """What a long-running viewer keeps per run, approval or session stays bounded however many it sees."""

    def test_the_translators_per_run_and_per_approval_maps_are_bounded(self):
        from tracekit import observe
        cap = 100
        with mock.patch.object(observe, "MAX_RUNS_KEPT", cap):
            t1, t2 = observe.Translator(), view.Translator()
            for i in range(cap * 10):
                run = f"run-{i}"
                t1.feed({"hash": "h", "event": {"run_id": run, "type": "run.start", "ts": "2026-10-12T00:00:00Z",
                                                "agent_id": f"child-{i}", "data": {"cwd": "/w", "agent": {"name": "a"}}}})
                for typ, data in (("run.registered", {"agent": {"name": "a"}}),
                                  ("approval.request", {"approval_id": f"apr-{i}", "binding": {"tool": "pay"}}),
                                  ("approval.suggested", {"approval_id": f"apr-{i}", "decision": "approve"})):
                    t2.feed({"hash": "h", "event": {"run_id": run, "type": typ, "ts": "2026-10-12T00:00:00Z",
                                                    "seq": i, "run_seq": 0, "data": data}})
        for name in ("cwd", "agent_names", "seen_agents"):
            self.assertLessEqual(len(getattr(t1, name)), cap, name)
        for name in ("agent_names", "requests", "suggested"):
            self.assertLessEqual(len(getattr(t2, name)), cap, name)

    def test_the_store_feed_keeps_its_newest_records(self):
        feed = types.SimpleNamespace(records=[], base=0, max_records=100, latest={}, kept=collections.OrderedDict(),
                                     on_run=None)
        for i in range(1000):
            feed.records.append({"seq": i})
            view.StoreFeed._trim(feed)
        self.assertEqual((len(feed.records), feed.base, feed.records[0]["seq"]), (100, 900, 900))

    def test_expired_sessions_are_evicted_before_live_ones(self):
        login = view.OidcLogin.__new__(view.OidcLogin)
        login._lock, login._sessions, now = threading.Lock(), collections.OrderedDict(), [1000.0]
        login.clock = lambda: now[0]
        with mock.patch.object(view, "SESSIONS_MAX", 4):
            login._keep("live", {"until": 5000})
            for i in range(3):
                login._keep(f"old-{i}", {"until": 1500})
            now[0] = 2000   # the three old ones have expired
            login._keep("new", {"until": 9000})
            login._keep("newer", {"until": 9000})
        self.assertEqual(list(login._sessions), ["live", "new", "newer"])


if __name__ == "__main__":
    unittest.main()
