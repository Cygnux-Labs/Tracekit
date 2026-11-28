"""The viewer's FLEET page (tracekit/fleet.py, /api/fleet, docs/viewer.md#fleet): what a store's verified runs did over a
range, against the range before it. `summarize` and `build` over hand-made records, then a real signer's store through
StoreFeed and the HTTP API, and the page."""
import datetime
import html.parser as html_parser
import http.client
import json
import os
import socket
import sys
import threading
import time
import types
import unittest
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from factories import iso, v2rec, wait_for  # noqa: E402
from test_signer_service import tmpdir  # noqa: E402
from tracekit import fleet, observe, view  # noqa: E402
from tracekit.sdk.client import Client  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.usage import Prices  # noqa: E402

NOW = datetime.datetime(2026, 11, 28, 14, 0, tzinfo=datetime.timezone.utc).timestamp()
DAY = 86400


SECTIONS = {"T-RM": "deny", "T-NET": "deny", "T-PAY": "ask", "T-FLAG1": "flag", "T-FLAG2": "flag", "TK-Q001": "flag"}


def rules(d):
    return [{"id": i, "reason": "why " + i, "section": SECTIONS.get(i)} for i in d.get("rule_ids") or []]


class Run:
    """The records of one run, each `after` seconds on from `at`."""

    def __init__(self, run, agent, at, final=True, analyzes=None):
        self.id, self.at, self.t, self.recs = run, at, 0, []
        self.add("run.registered", {"agent": {"name": agent}, **({"analyzes": analyzes} if analyzes else {})})
        self.final = final

    def add(self, typ, data, after=1, **top):
        self.t += after
        self.recs.append(v2rec(len(self.recs), typ, data, self.id, ts=iso(self.at + self.t), **top))
        return self

    def call(self, tid, tool, decision="allow", rule_ids=(), ok=None, took=0.5, **top):
        """A decision, and a result `took` seconds later unless `ok` is None."""
        self.add("policy.decision", {"tool_use_id": tid, "tool": tool, "decision": decision, "decision_id": "d-" + tid,
                                     "rule_ids": list(rule_ids), "policy_hash": "sha256:x"}, **top)
        if ok is not None:
            self.add("tool.result", {"tool_use_id": tid, "ok": ok, "output": {}, "decision_id": "d-" + tid,
                                     "duration_ms": 99999}, after=took)
        return self

    def turn(self, xid, model, tokens=(100, 10, 0, 0), **top):
        self.add("model.exchange", {"exchange_id": xid, "phase": "response", "model": model,
                                    "usage": dict(zip(("input_tokens", "output_tokens", "cache_read_tokens",
                                                       "cache_write_tokens"), tokens))}, **top)
        return self

    def summary(self):
        if self.final:
            self.add("run.final", {})
        return fleet.summarize(self.recs, rules)


def runs_of(*rs):
    return {("default", r.id): r.summary() for r in rs}


class Summarize(unittest.TestCase):
    def test_a_call_is_counted_once_in_the_class_it_belongs_to(self):
        r = Run("r1", "claude-code", NOW - 100)
        r.call("a", "Read", ok=True)
        r.call("b", "Bash", ok=False)
        r.call("c", "rm", "deny", ["T-RM"])
        r.call("d", "pay", "ask", ["T-PAY"], ok=False)   # held, then errored: an error that was also held
        r.call("e", "pay", "ask", ["T-PAY"])   # held, never answered
        s = r.summary()
        self.assertEqual([(c[1], c[2]) for c in s["calls"]],
                         [("Read", 0), ("Bash", fleet.ERROR), ("rm", fleet.DENIED), ("pay", fleet.HELD | fleet.ERROR),
                          ("pay", fleet.HELD)])
        self.assertEqual([(m[1], m[2], m[3]) for m in s["marks"]],
                         [("denied", "T-RM", "why T-RM"), ("held", "T-PAY", "why T-PAY"), ("held", "T-PAY", "why T-PAY")])
        out = fleet.build({("default", "r1"): s}, NOW, "7d", "UTC")
        self.assertEqual(out["totals"], {"calls": 5, "held": 2, "denied": 1, "errors": 2})
        [today] = [b for b in out["buckets"] if b["calls"]]
        # the chart's classes add up to the calls: the held-then-errored call is an error there, and a held one in held
        self.assertEqual((today["ok"], today["err"], today["den"], today["hld"]), (1, 2, 1, 1))
        self.assertEqual((today["held"], today["denied"], today["errors"]), (2, 1, 2))   # the tiles' counts

    def test_latency_is_the_signers_own_time_and_never_a_held_call(self):
        r = Run("r1", "a", NOW - 100)
        r.call("a", "Bash", ok=True, took=2.5)
        r.call("b", "pay", "ask", ["T-PAY"], ok=True, took=40)   # a person's wait is no tool's latency
        r.call("c", "Read")   # no result: not in the numbers
        out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC")
        tools = {t["tool"]: t for t in out["tools"]}
        self.assertEqual((tools["Bash"]["p50"], tools["Bash"]["timed"]), (2500, 1))   # not the agent's duration_ms 99999
        self.assertEqual((tools["pay"]["p50"], tools["pay"]["timed"], tools["Read"]["p99"]), (None, 0, None))
        self.assertEqual(out["timed"], 1)

    def test_an_agents_retry_of_a_held_call_is_that_call(self):
        r = Run("r1", "a", NOW - 100)
        r.call("h", "pay", "ask", ["T-PAY"])
        r.add("approval.request", {"approval_id": "apr-1", "rule_ids": ["T-PAY"], "binding": {"tool": "pay",
                                                                                            "tool_call_id": "h"}})
        r.add("approval", {"approval_id": "apr-1", "decision": "approve", "tool_use_id": "h", "approver": "alice"})
        r.call("h2", "pay", "ask", ["T-PAY"], ok=False)   # the retry, a new call id, ran under that approval
        r.add("approval.consumed", {"approval_id": "apr-1", "tool_use_id": "h2"}, tool_call_id="h2")
        s = r.summary()
        self.assertEqual([(c[1], c[2]) for c in s["calls"]], [("pay", fleet.HELD | fleet.ERROR)])

    def test_each_model_turn_counts_once_whatever_signed_it(self):
        r = Run("r1", "a", NOW - 100)
        r.turn("x1", "m", (10, 5, 100, 0))
        r.turn("x1", "m", (10, 5, 100, 0))   # signed twice
        r.turn("x2", "m", (20, 5, 0, 0), source="gateway")
        r.turn("x3", "m", (20, 5, 0, 0), after=10)   # the same counts from the transcript tailer: the gateway's turn
        r.turn("x4", "m", (7, 1, 0, 0), after=1000)
        self.assertEqual([(t[2], t[3], t[4]) for t in r.summary()["tokens"]], [(10, 5, 100), (20, 5, 0), (7, 1, 0)])


class Build(unittest.TestCase):
    def test_days_are_the_persons_and_the_previous_range_is_as_long(self):
        r = Run("r1", "a", NOW - 100)   # 2026-11-28 13:58 UTC
        r.call("a", "Read", ok=True)
        for tz, today in (("UTC", "2026-11-28 00:00"), ("Pacific/Auckland", "2026-11-28 11:00")):   # UTC at its midnight
            out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", tz)
            days = [datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
                    for t in out["range"]["starts"]]
            self.assertEqual((len(days), days[-1], out["range"]["tz"]), (7, today, tz))
            self.assertEqual([b["calls"] for b in out["buckets"]], [0] * 6 + [1])   # today, in that zone
        self.assertEqual(fleet.build({}, NOW, "30d", "Not/AZone")["range"]["tz"], "UTC")
        h = fleet.build({("default", "r1"): r.summary()}, NOW, "24h", "UTC")
        self.assertEqual((len(h["buckets"]), h["range"]["bucket"], h["buckets"][-2]["calls"]), (25, "hour", 1))   # the last 24 hours: its first and last hours partial
        self.assertEqual(h["range"]["since"] - h["range"]["previous"], DAY)

    def test_a_trend_compares_with_the_range_before(self):
        old = Run("r0", "a", NOW - 9 * DAY)
        old.call("a", "Read", ok=True).call("b", "Read", ok=True)
        new = Run("r1", "a", NOW - 100)
        new.call("c", "Read", ok=True)
        out = fleet.build(runs_of(old, new), NOW, "7d", "UTC")
        self.assertEqual((out["totals"]["calls"], out["previous"]["calls"]), (1, 2))

    def test_issues_are_new_ongoing_or_regressed_by_where_they_were_seen(self):
        before, prev, now = Run("r0", "a", NOW - 20 * DAY), Run("r1", "b", NOW - 10 * DAY), Run("r2", "b", NOW - 100)
        for r in (before, now):
            r.call("x", "rm", "deny", ["T-RM"])   # seen before the comparison range, and now: regressed
        for r in (prev, now):
            r.call("y", "pay", "ask", ["T-PAY"])   # seen in the comparison range and now: ongoing
        now.call("z", "Bash", "deny", ["T-NET"])   # first seen now: new
        out = fleet.build(runs_of(before, prev, now), NOW, "7d", "UTC")
        self.assertEqual([(i["rule"], i["kind"], i["status"], i["severity"], i["runs"]["n"]) for i in out["issues"]],
                         [("T-NET", "denied", "new", "high", 1), ("T-RM", "denied", "regressed", "high", 1),
                          ("T-PAY", "held", "ongoing", "med", 1)])
        self.assertEqual(out["issues"][1]["title"], "Denied: why T-RM")
        self.assertEqual([out["names"][i]["id"] for i in out["issues"][1]["examples"]], ["r2"])
        out = fleet.build(runs_of(before, prev, now), NOW, "30d", "UTC")   # all first seen within the longer range
        self.assertEqual({i["rule"]: i["status"] for i in out["issues"]}, {"T-NET": "new", "T-RM": "new", "T-PAY": "new"})

    def test_a_denied_call_is_an_issue_of_the_rule_that_denied_it_not_of_the_flags_and_notes_on_it(self):
        r = Run("r1", "a", NOW - 100)
        r.call("a", "rm", "deny", ["T-FLAG1", "T-RM", "T-FLAG2", "TK-Q001"])
        r.call("b", "pay", "ask", ["T-FLAG1", "T-PAY"])
        r.call("c", "Bash", "ask", ["TK-SHELL-PARSE"])   # an engine check: no section, the only reason
        r.call("d", "Bash", "deny")   # a deny that names no rule
        out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC")
        self.assertEqual(sorted((i["kind"], i["rule"]) for i in out["issues"]),
                         [("denied", "T-RM"), ("denied", "no rule"), ("held", "T-PAY"), ("held", "TK-SHELL-PARSE")])

    def test_signed_findings_are_about_the_run_they_analyze(self):
        run = Run("r1", "coding", NOW - 100)
        run.call("a", "Bash", ok=True)
        find = Run("f1", "tracekit-analyze", NOW - 50, analyzes="r1")
        find.add("review", {"verdict": {"kind": "finding", "rule": "TK-X205", "severity": "high", "title": "T"}})
        runs = runs_of(run, find)
        out = fleet.build(runs, NOW, "7d", "UTC")
        [issue] = out["issues"]
        self.assertEqual((issue["kind"], issue["rule"], issue["agents"], issue["runs"]["n"], out["findings"]),
                         ("finding", "TK-X205", ["coding"], 1, 1))
        self.assertEqual([a["agent"] for a in out["agents"]], ["coding"])   # an analysis run is no agent
        del runs[("default", "r1")]   # the analyzed run is not counted: its findings aren't either
        self.assertEqual(fleet.build(runs, NOW, "7d", "UTC")["issues"], [])

    def test_the_approver_panel_counts_the_holds_both_an_ai_approver_and_a_person_answered(self):
        r = Run("r1", "a", NOW - 100)
        for n, (ai, person) in enumerate((("approve", "approve"), ("reject", "approve"), (None, "approve"),
                                          ("approve", None))):
            r.call(f"c{n}", "pay", "ask", ["T-PAY"])
            r.add("approval.request", {"approval_id": f"apr-{n}", "rule_ids": ["T-PAY"],
                                       "binding": {"tool": "pay", "tool_call_id": f"c{n}"}})
            if ai:
                r.add("approval.suggested", {"approval_id": f"apr-{n}", "decision": ai, "approver_kind": "agent"})
            if person:
                r.add("approval", {"approval_id": f"apr-{n}", "decision": person, "approver": "alice"})
        out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC")
        self.assertEqual((out["approver"]["both"], out["approver"]["agree"], out["approver"]["holds"]), (2, 1, 4))
        self.assertEqual(out["approver"]["rules"], [{"rule": "T-PAY", "reason": "why T-PAY", "n": 2, "agree": 1}])
        self.assertEqual(out["approver"]["disagree"]["n"], 1)
        self.assertEqual(fleet.build({}, NOW, "7d", "UTC")["approver"]["both"], 0)

    def test_cost_is_only_from_a_price_table_and_a_model_with_no_price_has_none(self):
        r = Run("r1", "a", NOW - 100)
        r.turn("x1", "priced-1", (1_000_000, 1_000_000, 0, 0)).turn("x2", "unpriced", (500, 5, 0, 0))
        runs = {("default", "r1"): r.summary()}
        none = fleet.build(runs, NOW, "7d", "UTC")
        self.assertEqual((none["tokens"]["cost"], none["tokens"]["total"], [m["cost"] for m in none["models"]]),
                         (None, 2_000_505, [None, None]))
        prices = Prices({"currency": "EUR", "models": {"priced-*": {"input": 2, "output": 10}}})
        out = fleet.build(runs, NOW, "7d", "UTC", prices)
        self.assertEqual(({m["model"]: (m["cost"], m["priced"]) for m in out["models"]}),
                         {"priced-1": (12.0, True), "unpriced": (None, False)})
        self.assertEqual((out["tokens"]["cost"], out["tokens"]["unpriced"], out["agents"][0]["cost"]), (12.0, 505, 12.0))
        self.assertEqual(out["buckets"][-1]["cost"], 12.0)
        self.assertEqual((out["agents"][0]["tokens"], out["tokens"]["link"]["n"]), (2_000_505, 1))
        r2 = Run("r2", "b", NOW - 90)   # an agent whose only model has no price has no cost, not a zero one
        r2.turn("x3", "unpriced", (50, 5, 0, 0))
        out = fleet.build({**runs, ("default", "r2"): r2.summary()}, NOW, "7d", "UTC", prices)
        self.assertEqual({a["agent"]: (a["cost"], a["unpriced"]) for a in out["agents"]}, {"a": (12.0, 505), "b": (None, 55)})

    def test_a_trend_compares_ranges_of_the_same_length_on_steady_traffic(self):
        """A call every 10 minutes, for 70 days: the 7d range is 6 days and the day so far, so the range before it is as
        long as that, not 7 whole days (a trend of -13.7% at half past midnight)."""
        for now in (NOW, NOW - 14 * 3600 - 1800):
            r = Run("r1", "a", now - 70 * DAY)
            for i in range(70 * 144):
                r.recs.append(v2rec(len(r.recs), "policy.decision", {"tool_use_id": f"c{i}", "tool": "Read", "decision": "allow",
                                                                    "decision_id": f"d{i}", "rule_ids": []}, "r1",
                                    ts=iso(now - 70 * DAY + 600 * i)))
            r.recs.append(v2rec(len(r.recs), "tool.result", {"tool_use_id": "c0", "ok": True, "decision_id": "d0"}, "r1",
                                ts=iso(now - 70 * DAY + 1)))
            summary = fleet.summarize(r.recs, rules)
            for span, width in (("24h", 1), ("7d", 7), ("30d", 30)):
                out = fleet.build({("default", "r1"): summary}, now, span, "UTC")
                r_ = out["range"]
                self.assertEqual(r_["since"] - r_["previous"], now - r_["since"], span)
                self.assertLessEqual(abs(out["totals"]["calls"] - out["previous"]["calls"]), 1, span)

    def test_replay_runs_are_listed_and_not_counted_as_agents(self):
        r = Run("r1", "tracekit-why", NOW - 100)
        r.recs[0]["event"]["data"]["replay_of"] = "r0"
        r.call("a", "Read", ok=True)
        a = Run("r2", "claude-code", NOW - 100)
        a.call("b", "Read", ok=True)
        out = fleet.build(runs_of(r, a), NOW, "7d", "UTC")
        self.assertEqual(([x["agent"] for x in out["agents"]], out["totals"]["calls"], out["replays"]["n"]),
                         (["claude-code"], 1, 1))

    def test_the_agents_footer_link_opens_the_runs_the_table_counts(self):
        quiet = Run("r1", "a", NOW - 100)   # a run with no call in the range is still a run of the agent
        busy = Run("r2", "b", NOW - 100)
        busy.call("x", "Read", ok=True)
        out = fleet.build(runs_of(quiet, busy), NOW, "7d", "UTC")
        self.assertEqual((out["links"]["runs"]["n"], sum(a["runs"]["n"] for a in out["agents"]), out["links"]["calls"]["n"]),
                         (2, 2, 1))

    def test_an_approver_pair_is_filed_under_the_ask_rules_of_the_held_call_not_its_flags(self):
        r = Run("r1", "a", NOW - 100)
        r.call("c0", "pay", "ask", ["T-FLAG1", "T-PAY"])
        r.add("approval.request", {"approval_id": "apr-0", "rule_ids": ["T-FLAG1", "T-PAY"],
                                   "binding": {"tool": "pay", "tool_call_id": "c0"}})
        r.add("approval.suggested", {"approval_id": "apr-0", "decision": "approve", "approver_kind": "agent"})
        r.add("approval", {"approval_id": "apr-0", "decision": "approve", "approver": "alice"})
        out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC")
        self.assertEqual([x["rule"] for x in out["approver"]["rules"]], ["T-PAY"])

    @pytest.mark.serial
    def test_turn_matching_is_linear_in_turns_that_share_their_counts(self):
        """16,000 turns with the same usage (an agent can sign them) took 2.8 s, at every checkpoint. The transcript's
        8,000 come first, one a second; the gateway's 8,000 follow, and each joins a transcript turn of the 300 s
        before it, so only the last 300 of the first are joined."""
        r = Run("r1", "a", NOW - 40000)
        for i in range(8000):
            r.turn(f"x{i}", "m", (10, 5, 0, 0), after=1)
        for i in range(8000):
            r.turn(f"g{i}", "m", (10, 5, 0, 0), after=1, source="gateway")
        t0 = time.perf_counter()
        turns = fleet._turns(r.recs)
        self.assertEqual(len(turns), 16000 - 300)
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_a_turn_joined_by_its_exchange_id_is_not_joined_again_by_its_old_counts(self):
        r = Run("r1", "a", NOW - 1000)
        r.turn("x1", "m", (10, 5, 0, 0))   # the transcript's turn
        r.turn("x1", "m", (12, 5, 0, 0), source="gateway")   # the gateway's counts of the same message differ: it joins by id
        r.turn("x2", "m", (10, 5, 0, 0), source="gateway")   # another message with the first one's counts: its own turn
        self.assertEqual([t[2:4] for t in fleet._turns(r.recs)], [(12, 5), (10, 5)])

    def test_a_link_names_the_runs_it_counts_and_is_bounded(self):
        rs = []
        for i in range(fleet.RUNS_MAX + 5):
            r = Run(f"r{i}", "a", NOW - 100 - i)
            r.call("a", "rm", "deny", ["T-RM"])
            rs.append(r)
        out = fleet.build(runs_of(*rs), NOW, "7d", "UTC")
        link = out["links"]["denied"]
        self.assertEqual((link["n"], len(link["runs"]), out["names"][link["runs"][0]]["id"]), (fleet.RUNS_MAX + 5, fleet.RUNS_MAX, "r0"))


POLICY = """description: fleet test
deny:
  - {id: T-RM, tool: rm, pattern: '^', reason: deleting files}
ask:
  - {id: T-PAY, tool: pay, pattern: '^', reason: paying money}
flag:
  - {id: T-PATH, tool: rm, pattern: path, reason: a path}
"""
TOKEN = "fleet-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SESSION = {"Cookie": "tracekit_observe=1.s"}   # a sign-in's cookie, not the token's


class Zones(unittest.TestCase):
    def test_only_a_zone_this_machine_has_under_that_name_is_used_and_the_cache_stays_small(self):
        for name in ("utc", "europe/london", "Europe/London ", '"><x>', "Etc/../UTC", "A" * 5000):
            self.assertEqual(fleet._tz(name)[1], "UTC", name)
        self.assertEqual(fleet._tz("Europe/London")[1], "Europe/London")
        feed = types.SimpleNamespace(fleet_state=lambda: ({}, {"chain": True, "failed": [], "pending": [], "unread": [],
                                                              "unchecked": 0}))
        page = fleet.Page(feed, ttl=0.05)
        for span in fleet.RANGES:
            for name in ("UTC", "utc", "Utc", "Europe/London", "europe/london", "x" * 100, "Asia/Calcutta"):
                page(span, name)
        self.assertLessEqual(len(page.kept), len(fleet.RANGES) * 3)
        self.assertEqual(sorted({k[1] for k in page.kept}), ["Asia/Calcutta", "Europe/London", "UTC"])
        time.sleep(0.1)
        page("7d", "UTC")
        self.assertEqual(list(page.kept), [("7d", "UTC")])   # what is older than the ttl is gone


class Findings(unittest.TestCase):
    def test_the_viewers_findings_of_a_run_survive_its_next_summary(self):
        k = ("default", "r1")
        finding = (NOW - 5, "TK-X205", "high", "said it ran tests")
        summary = lambda: {"count": 5, "findings": []}   # noqa: E731
        feed = types.SimpleNamespace(lock=threading.Lock(), fleet_runs={k: summary()}, fleet_found={k: [finding]},
                                     runs={k: {"count": 5, "failed": None}}, verify=lambda: (0, [], None),
                                     checking=lambda: 0)
        self.assertEqual(view.StoreFeed.fleet_state(feed)[0][k]["findings"], [finding])
        feed.fleet_runs[k] = summary()   # the run is summarized again at its next checkpoint
        self.assertEqual(view.StoreFeed.fleet_state(feed)[0][k]["findings"], [finding])


class Prices_(unittest.TestCase):
    def test_a_bad_price_table_fails_at_startup_and_v1_views_take_none(self):
        d = tmpdir(self)
        bad, ok = os.path.join(d, "bad.json"), os.path.join(d, "ok.json")
        for path, body in ((bad, {"models": {"m": {"input": "abc"}}}), (ok, {"models": {"m": {"input": 1}}})):
            with open(path, "w") as f:
                json.dump(body, f)
        self.assertEqual(view.main(["--data-dir", d, "--prices", bad]), 2)
        self.assertEqual(view.main(["--ledger", "--prices", ok]), 2)
        self.assertEqual(view.main(["--bundle", ok, "--prices", ok]), 2)


class NotCounted(unittest.TestCase):
    def test_a_run_counts_only_while_its_summary_is_of_its_verified_records(self):
        """A summary kept from an earlier check is never added up: the run grew past it, is waiting for a re-check
        after a store change, or failed since."""
        k = lambda i: ("default", f"r{i}")   # noqa: E731
        feed = types.SimpleNamespace(
            lock=threading.Lock(), fleet_runs={k(i): {"count": 5, "findings": []} for i in range(5)}, fleet_found={},
            runs={k(0): {"count": 5, "failed": None}, k(1): {"count": 7, "failed": None},
                  k(2): {"count": 5, "failed": None, "again": 3}, k(3): {"count": 5, "failed": "FAILED"},
                  k(4): {"count": 0, "failed": None}},
            verify=lambda: (0, [], None), checking=lambda: 0)
        ok, rest = view.StoreFeed.fleet_state(feed)
        self.assertEqual(list(ok), [k(0)])
        self.assertEqual(([x["id"] for x in rest["failed"]], [x["id"] for x in rest["pending"]],
                          [x["id"] for x in rest["unread"]]), (["r3"], ["r4"], ["r1"]))


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class Store(unittest.TestCase):
    """The page's data and API over a real signer's store: a run with a held call a person answered, a denied call, an
    errored call and model turns; another agent's run still open; and a run whose record is edited afterwards."""

    def setUp(self):
        for name in ("TICK_S", "CHECKPOINT_S", "CHECKPOINT_MIN_S"):
            p = mock.patch.object(svc, name, 0.05)
            p.start()
            self.addCleanup(p.stop)
        d = tmpdir(self)
        with open(os.path.join(d, "policy.yaml"), "w") as f:
            f.write(POLICY)
        self.cfg = {"data_dir": os.path.join(d, "data"), "socket": os.path.join(d, "s.sock"), "grace_s": 0,
                    "approvals": {"self_approval": "allow"}, "policy": os.path.join(d, "policy.yaml")}
        self.service = svc.open_service(self.cfg)
        self.addCleanup(self.service.close)
        for srv in svc.serve(self.cfg, self.service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.client = Client(self.cfg["socket"])
        self.addCleanup(self.client.close)

    def hold(self, run, tcid, answer="approve"):
        self.assertEqual(run.decide(tcid, "pay", {"cents": 5})["decision"], "ask")
        aid = run.call("approval_request", tool_call_id=tcid)["approval_id"]
        self.client.call("approval_decide", {"approval_id": aid, "decision": answer})

    def settled(self, run=None):
        storage = self.service.log.storage
        self.assertTrue(wait_for(
            lambda: (run is None or list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] == "run.final")
            and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))

    def finish(self, run):
        run.close()
        self.settled(run)

    def build_store(self):
        self.bad = self.client.run(agent="cursor")
        self.bad.decide("b1", "Read", {"file_path": "a"})
        self.bad.complete("b1")
        self.finish(self.bad)
        self.main = self.client.run(agent="claude-code")
        self.main.decide("a1", "Read", {"file_path": "a"})
        time.sleep(0.3)
        self.main.complete("a1")
        self.main.decide("a2", "Bash", {"command": "false"})
        self.main.complete("a2", status="error", error="boom")
        self.assertEqual(self.main.decide("a3", "rm", {"path": "x"})["decision"], "deny")
        self.hold(self.main, "a4")
        for n, usage in enumerate(({"input_tokens": 1000, "output_tokens": 100},
                                   {"input_tokens": 500, "output_tokens": 50})):
            self.main.call("model_event", provider="anthropic", model="priced-1", phase="response",
                           exchange_id=f"x{n}", usage=usage)
        self.finish(self.main)
        self.open = self.client.run(agent="codex")
        self.open.decide("c1", "Read", {"file_path": "a"})
        self.open.complete("c1")
        self.settled()

    def edit_run(self, run_id):
        """With the signer stopped, change the time of a decision of the run and keep its stored hash."""
        self.service.close()
        path = os.path.join(self.cfg["data_dir"], "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        for i, line in enumerate(lines):
            rec = json.loads(line)
            if rec["event"]["run_id"] == run_id and rec["event"]["type"] == "policy.decision":
                rec["event"]["ts"] = "2026-01-01T00:00:00.000000Z"
                lines[i] = json.dumps(rec, separators=(",", ":"))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def feed(self, prices=None, verified=3):
        feed = view.StoreFeed(self.cfg)
        self.addCleanup(feed.close)
        feed.fleet = fleet.Page(feed, prices, "prices.json" if prices else None, ttl=0)
        self.assertTrue(wait_for(lambda: len(feed.fleet_runs) == verified and not feed.checking(), 30))
        return feed

    def serve(self, feed, **kw):
        srv = view.server(feed, "127.0.0.1", 0, TOKEN, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)

    def get(self, c, path, headers=AUTH):
        c.request("GET", path, headers=headers)
        r = c.getresponse()
        body = r.read()
        return r.status, json.loads(body) if r.status == 200 else body

    def test_the_page_counts_verified_runs_and_lists_the_rest(self):
        self.build_store()
        self.edit_run(self.bad.run_id)
        status, out = self.get(self.serve(self.feed(verified=2)), "/api/fleet?range=7d&tz=UTC")
        self.assertEqual(status, 200)
        # the open run's Read, and the main run's Read, Bash (errored), rm (denied) and pay (held): not the edited run's
        # Read, nor the runs before the range
        self.assertEqual(out["totals"], {"calls": 5, "held": 1, "denied": 1, "errors": 1})
        self.assertEqual({a["agent"]: a["calls"] for a in out["agents"]}, {"claude-code": 4, "codex": 1})
        self.assertEqual(out["seal"]["runs"], 2)
        self.assertEqual([x["id"] for x in out["not_counted"]["failed"]], [self.bad.run_id])
        self.assertEqual((out["not_counted"]["pending"], out["open"]["n"]), ([], 1))   # the codex run: not final yet
        tools = {t["tool"]: t for t in out["tools"]}
        self.assertTrue(300 <= tools["Read"]["p99"] < 5000)   # the signer's own times: the main run's Read took 0.3 s
        self.assertEqual(tools["Bash"]["timed"], 1)
        self.assertEqual([m["model"] for m in out["models"]], ["priced-1"])
        self.assertEqual((out["models"][0]["tokens"], out["tokens"]["cost"]), ([1500, 150, 0, 0], None))
        self.assertEqual({(i["rule"], i["status"]) for i in out["issues"]}, {("T-RM", "new"), ("T-PAY", "new")})

    def test_a_flag_is_no_issue_when_the_viewer_reads_the_policy_from_the_signers_data_dir(self):
        """The rm call is denied by T-RM and flagged by T-PATH. A viewer started with --data-dir alone (no policy file)
        read the policy the signer kept, so T-PATH stays a flag; without it every rule on the call was a deny."""
        self.build_store()
        self.service.close()
        cfg = {"data_dir": self.cfg["data_dir"]}
        feed = view.StoreFeed(cfg)
        self.addCleanup(feed.close)
        feed.fleet = fleet.Page(feed, ttl=0)
        self.assertTrue(wait_for(lambda: len(feed.fleet_runs) == 3 and not feed.checking(), 30))
        _, out = self.get(self.serve(feed), "/api/fleet")
        self.assertEqual({(i["kind"], i["rule"]) for i in out["issues"]}, {("denied", "T-RM"), ("held", "T-PAY")})

    def test_cost_shows_with_a_price_table(self):
        self.build_store()
        prices = Prices({"models": {"priced-*": {"input": 2, "output": 10}}})
        _, out = self.get(self.serve(self.feed(prices)), "/api/fleet")
        self.assertAlmostEqual(out["tokens"]["cost"], 1500 * 2e-6 + 150 * 10e-6)
        self.assertEqual(out["prices"], {"source": "prices.json", "currency": "USD", "models": 1})

    def test_every_request_needs_the_viewers_token_not_a_sign_in(self):
        self.build_store()
        feed = self.feed()
        c = self.serve(feed)
        self.assertEqual([self.get(c, "/api/fleet", h)[0] for h in ({}, SESSION, AUTH)], [401, 401, 200])
        login = mock.Mock(redirect_uri="http://127.0.0.1/callback")
        login.tenant.return_value = "acme"
        c = self.serve(feed, login=login)
        self.assertEqual(self.get(c, "/api/fleet", SESSION)[0], 403)
        self.assertTrue(self.get(c, "/api/snapshot")[1]["fleet"])
        self.assertNotIn("fleet", self.get(c, "/api/snapshot", SESSION)[1])


class Page(unittest.TestCase):
    NAMES = ["esc", "plural", "fmtD", "fmtDur", "WFMODELS", "wfModelMark", "tipTicks", "fmtInt", "fmtTok", "fleetUsd", "fleetMs",
             "fleetLabel", "renderFleetPage"]

    def render(self, data, prices=True):
        from test_view import page_js
        from test_view_ui import needs_node
        needs_node(self)
        return json.loads(page_js(self.NAMES, """
            const html = {}, $ = id => html[id] ??= { textContent: "" }, put = (id, h) => { html[id] = h; };
            let PAGE = "fleet", FLEETON = true, FLEET = %s, FLEETERR = "", FLEETRANGE = "7d", FLEETASKED = "7d", fleetKey = null, FLINKS = [], RUNFILTER = null;
            const loadFleet = () => {}; renderFleetPage();
            process.stdout.write(JSON.stringify({ html: html.fleetp, links: FLINKS, sum: $("fleetsum").textContent }));""" % json.dumps(data)))

    def test_the_page_draws_the_apis_numbers_and_its_links_name_runs(self):
        r = Run("r1", "claude-code", NOW - 100)
        r.call("a", "Read", ok=True).call("b", "rm", "deny", ["T-RM"]).call("c", "pay", "ask", ["T-PAY"], ok=False)
        r.turn("x1", "claude-opus-5", (1000, 100, 0, 0))
        out = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC", Prices({"models": {"claude-*": {"input": 5, "output": 25}}}))
        out.update(not_counted={"failed": [{"id": "bad1", "tenant": "default", "why": "x"}], "pending": [], "unread": [], "unchecked": 0},
                   seal={"chain": True, "runs": out["runs"], "records": out["records"]},
                   prices={"source": "p.json", "currency": "USD", "models": 1})
        got = self.render(out)
        for text in ("Denied: why T-RM", "claude-code", "claude-opus-5", "$0.0075", "1 run failed verification", "p.json",
                     "1 run verified · 8 signed records · chain ok", "No AI approver decisions"):
            self.assertIn(text, got["html"])
        self.assertEqual(got["sum"].split(" · ")[:2], ["1 agent", "1 run"])
        # every link carries run ids the API named, and the failed runs' own
        self.assertTrue(got["links"])
        self.assertIn(["bad1"], [x["ids"] for x in got["links"]])
        self.assertTrue(all(i in {"r1", "bad1"} for x in got["links"] for i in x["ids"]))
        # without a price table the page says so and shows no dollars
        out["prices"] = None
        none = fleet.build({("default", "r1"): r.summary()}, NOW, "7d", "UTC")
        out.update({k: none[k] for k in ("tokens", "models", "agents", "buckets")})
        text = self.render(out)["html"]
        self.assertIn("no price table", text)
        self.assertNotIn("$", text)

    def test_the_page_has_a_fleet_tab_only_where_the_server_has_it(self):
        page = observe.read_text(observe.UI)
        self.assertIn('"tips", "fleet"]', page)
        self.assertIn('(p !== "fleet" || FLEETON)', page)
        self.assertIn("FLEETON = !!snap.fleet", page)
        self.assertIn('id="fleetp"', page)

    def test_nothing_a_record_or_the_price_file_holds_reaches_the_page_as_markup(self):
        """FLEET builds most of its HTML by concatenation, which the page's esc() check does not read: every field a
        record, a run's name or the price table can fill carries hostile text through the page's own code."""
        x = '"><img src=x onerror=alert(1)>\'`${x}</svg><script>alert(2)</script>'
        hostile_rules = lambda d: [{"id": x + "rule", "reason": x + " reason", "section": None}   # noqa: E731
                                   for _ in d.get("rule_ids") or [None]]
        r = Run(x + "run", x + "agent", NOW - 100)
        r.call("c1", x + "tool", "deny", ["r"], ok=None)
        r.call("c2", x + "tool", "ask", ["r"], ok=False)
        r.add("approval.request", {"approval_id": "a1", "rule_ids": [x], "binding": {"tool": "t", "tool_call_id": "c2"}})
        r.add("approval.suggested", {"approval_id": "a1", "decision": "approve", "approver_kind": "agent"})
        r.add("approval", {"approval_id": "a1", "decision": "reject"})
        r.turn("x1", x + "model", (5, 5, 0, 0))
        r.add("run.final", {})
        s = fleet.summarize(r.recs, hostile_rules)
        s["findings"] = [(NOW - 92, x + "frule", "high", x + "title")]
        prices = Prices({"currency": "USD", "models": {"*": {"input": 1, "output": 1}}})
        for span in ("24h", "7d"):
            out = fleet.build({("default", x + "run"): s}, NOW, span, "UTC", prices)
            out["range"]["tz"] = x   # as if the server had echoed a hostile zone
            out.update(not_counted={"failed": [{"id": x + "f", "tenant": x, "why": x}], "pending": [{"id": x + "p", "tenant": x}],
                                    "unread": [{"id": x + "u", "tenant": x}], "unchecked": 3},
                       seal={"chain": False, "runs": 1, "records": 9},
                       prices={"source": x + "src", "currency": "USD", "models": 1})
            html = self.render(out)["html"]
            seen = set()

            class Tags(html_parser.HTMLParser):
                def handle_starttag(self, tag, attrs):
                    seen.update([tag, *(k for k, _ in attrs)])
            Tags().feed(html)
            self.assertFalse(seen & {"img", "script", "onerror", "onload", "onclick"}, seen)
            self.assertIn("&lt;img", html)

    def test_the_seal_shows_a_bad_chain_with_no_run_in_range_and_the_footers_say_what_they_count(self):
        out = fleet.build({}, NOW, "24h", "Europe/London")
        out.update(not_counted={"failed": [], "pending": [], "unread": [], "unchecked": 0},
                   seal={"chain": False, "runs": 0, "records": 0}, prices=None)
        html = self.render(out)["html"]
        self.assertIn('class="seal bad"', html)
        self.assertIn("no verified runs in this range", html)
        self.assertIn("times in Europe/London", html)   # the 24 hour line names the zone its hours are in
        self.assertIn("when the agent reported it", html)
        out["tools"] = [{"tool": f"t{i}", "calls": 1, "held": 0, "denied": 0, "errors": 0, "p50": None, "p99": None, "timed": 0,
                         "links": {k: None for k in ("calls", "held", "denied", "errors")}} for i in range(3)]
        out["tools_total"] = 30
        self.assertIn("all 30 tools (top 3 shown)", self.render(out)["html"])
