"""The viewer's FLEET page (tracekit/fleet.py, /api/fleet, docs/viewer.md#fleet): what a store's verified runs did over a
range, against the range before it. `summarize` and `build` over hand-made records, then a real signer's store through
StoreFeed and the HTTP API, and the page."""
import datetime
import http.client
import json
import os
import socket
import sys
import threading
import time
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


def rules(d):
    return [{"id": i, "reason": "why " + i} for i in d.get("rule_ids") or []]


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
        self.assertEqual((len(h["buckets"]), h["range"]["bucket"], h["buckets"][-2]["calls"]), (24, "hour", 1))   # the hour before this one
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
"""
TOKEN = "fleet-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SESSION = {"Cookie": "tracekit_observe=1.s"}   # a sign-in's cookie, not the token's


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
