"""tracekit view's TIPS page: what each step cost and how to cut it (tracekit/tips.py, /api/tips, the page's cards).

    python3 -m pytest tests/test_tips.py -v
"""
import hashlib
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from factories import cc_assistant, cc_result, v2rec, write_jsonl  # noqa: E402
from test_view import page_js  # noqa: E402
from tracekit import tips, view  # noqa: E402

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc).timestamp()   # a day after v2rec's records
T0 = NOW - 86400
OPUS = tips.PRICES["models"]["claude-opus-5-5*"]


def tmp(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return d


def growing(n=300, start=60_000, step=3_000, at=800_000, after=70_000, life="1h", model="claude-opus-5-5"):
    """A session's lines whose context grows `step` tokens a step and compacts itself past `at`, down to `after`."""
    lines, ctx = [], 0
    for i in range(n):
        new = start if i == 0 else after if ctx + step > at else ctx + step
        read = 0 if new < ctx or i == 0 else ctx
        lines.append(cc_assistant(f"msg_{i}", T0 + 10 * i, read=read, write=new - read, life=life, model=model))
        ctx = new
    return lines


def rows(*recs):
    tr = view.Translator()
    return [x for r in recs for x in tr.feed(r)]


class Context(unittest.TestCase):
    def test_a_replay_compacts_past_the_cap_and_pays_a_summary_and_a_cache_write(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s1.jsonl"), [
            cc_assistant("m0", T0, write=100_000, life="1h"),
            cc_assistant("m1", T0 + 1, read=100_000, write=100_000, life="1h"),
            cc_assistant("m2", T0 + 2, read=200_000, write=100_000, life="1h")])
        steps = tips.read_transcripts(root, 0)[0]["s1"]["steps"]
        usd, n, ctx = tips.replay(steps, 150_000, 50_000, OPUS, OPUS["cache_write_1h"])
        # 0.80 the first write; at 200k past the cap: a summary call (200k read, 20k written) and 50k written again;
        # then 100k more: 50k read, 100k written
        self.assertAlmostEqual(usd, 0.8 + (0.04 + 0.4 + 0.4) + (0.01 + 0.8))
        self.assertEqual((n, ctx), (1, [100_000, 50_000, 150_000]))

    def test_a_long_main_session_gets_the_point_to_compact_at_and_what_it_saves(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "sess-a.jsonl"), growing())
        t = tips.build([], root, NOW)["tips"][0]
        self.assertTrue(t["ok"], t.get("why"))
        self.assertEqual((t["source"], t["agent"]), ("transcripts", "session sess-a"))
        best = max(c["usd"] for c in t["caps"])
        # the largest compaction point that keeps 80% of the best saving: compacting more often loses more detail
        self.assertEqual(t["cap"], max(c["cap"] for c in t["caps"] if c["usd"] >= tips.NEAR_BEST * best))
        self.assertEqual(t["saving"]["usd"], next(c["usd"] for c in t["caps"] if c["cap"] == t["cap"]))
        self.assertGreater(t["saving"]["usd"], 0)
        self.assertTrue(t["title"].startswith(f"Compact at about {t['cap'] // 1000}k tokens, not at 79"), t["title"])
        c = t["chart"]
        self.assertEqual((c["n"], len(c["x"]), len(c["actual"]), len(c["replay"])), (300, 300, 300, 300))
        self.assertEqual(len(c["marks"]), 1)   # where it compacted itself, at the context it had then
        self.assertGreater(c["marks"][0][1], 790_000)
        self.assertTrue(t["fix"]["copy"].startswith("/compact"))
        self.assertTrue(any("Not counted: work redone" in m for m in t["math"]))

    def test_a_chart_series_keeps_its_sum_when_it_is_cut_to_fewer_points(self):
        x, ys = tips._series(list(range(1000)), 300)
        self.assertLessEqual(len(ys), 300)
        self.assertEqual(x[:2], [0, 4])
        self.assertAlmostEqual(sum(ys) * 4, sum(range(1000)), delta=4 * 0.5 * len(ys))   # each mean a whole token

    def test_a_subagent_is_not_told_to_compact(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "sess-a", "subagents", "agent-a1.jsonl"), growing(life="5m"))
        t = tips.build([], root, NOW)["tips"][0]
        self.assertFalse(t["ok"])
        self.assertIn("main session", t["why"])

    def test_a_model_without_a_price_gets_no_dollars(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s.jsonl"), growing(model="gpt-9"))
        t = tips.build([], root, NOW)["tips"][0]
        self.assertEqual((t["ok"], t["why"].split(":")[0]), (False, "No price for gpt-9"))


class Cache(unittest.TestCase):
    def build(self, lines, sub=True):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "sess-b", "subagents", "agent-c1.jsonl") if sub else
                    os.path.join(root, "p", "sess-b.jsonl"), lines)
        return tips.build([], root, NOW)["tips"][1]

    def test_a_wait_that_outlives_the_cache_rebuilds_it_and_bounded_polls_would_cost_less(self):
        t = self.build([
            cc_assistant("m0", T0, write=200_000, tools=[("toolu_s", "Bash", {"command": "sleep 400"})]),
            cc_result("toolu_s", T0 + 400),
            cc_assistant("m1", T0 + 405, write=200_000, tools=[("toolu_l", "Bash", {"command": "ls"})]),   # rebuilt
            cc_result("toolu_l", T0 + 406),
            cc_assistant("m2", T0 + 600, read=200_000, write=1_000)])   # 194 s: the cache held
        self.assertTrue(t["ok"], t.get("why"))
        self.assertEqual(t["title"], "Keep each blocking call under 4.5 minutes in a subagent")
        [w] = t["waits"]
        # the rebuild: 200k written at $5/M; polling: one more poll (a 200k read and 200 tokens out), then the step's read
        self.assertEqual((w["s"], w["life"], w["usd"], w["alt"], w["fix"], w["cause"]),
                         (405, 300, 1.0, 0.084, True, "a polling loop or sleep"))
        self.assertEqual(t["saving"], {"usd": 0.92, "minutes": 0})
        self.assertEqual(t["bins"], [{"label": "under 4 min", "n": 1, "rebuilt": 0},
                                     {"label": "6 to 10 min", "n": 1, "rebuilt": 1}])
        self.assertIn("sleep 10", t["fix"]["copy"])
        self.assertNotIn("400", json.dumps(t["causes"]))   # a command's family, never its arguments

    def test_idle_time_is_shown_but_no_poll_is_counted_for_it(self):
        t = self.build([cc_assistant("m0", T0, write=100_000, life="1h"),
                        cc_assistant("m1", T0 + 7200, write=100_000, life="1h")], sub=False)
        self.assertTrue(t["ok"])
        self.assertEqual([(w["fix"], w["cause"]) for w in t["waits"]], [(False, "idle: waiting for a person")])
        self.assertEqual((t["saving"]["usd"], t["fix"]), (0, None))
        self.assertEqual(t["title"], "Every cache rebuild here followed idle time, not a blocking call")

    def test_a_person_answering_a_question_is_idle_time_too(self):
        t = self.build([cc_assistant("m0", T0, write=100_000, tools=[("toolu_q", "AskUserQuestion", {})]),
                        cc_result("toolu_q", T0 + 900), cc_assistant("m1", T0 + 905, write=100_000)])
        self.assertEqual([(w["fix"], w["cause"]) for w in t["waits"]], [(False, "idle: waiting for a person")])

    def test_signed_steps_without_a_cache_lifetime_say_so(self):
        recs = rows(v2rec(1, "run.registered", {"agent": {"name": "bot"}}),
                    *[v2rec(2 + i, "model.exchange", {"exchange_id": f"x{i}", "phase": "response", "model": "m",
                                                      "upstream": "u", "usage": {"input_tokens": 5, "output_tokens": 1,
                                                                                 "cache_read_tokens": 30_000,
                                                                                 "cache_write_tokens": 100}})
                      for i in range(3)])
        t = tips.build(recs, None, NOW)["tips"][1]
        self.assertFalse(t["ok"])
        self.assertIn("No step records how long its cache lasts", t["why"])


class Holds(unittest.TestCase):
    RECS = (v2rec(1, "run.registered", {"agent": {"name": "claude-code"}}),
            # a Claude Code subagent's call is decided under the session's run: only its transcript says it's a subagent's
            v2rec(2, "policy.decision", {"tool_use_id": "toolu_h1", "tool": "Bash", "decision": "ask",
                                         "rule_ids": ["TK-SHELL-PARSE"]}),
            v2rec(3, "policy.decision", {"tool_use_id": "toolu_h2", "tool": "Bash", "decision": "ask",
                                         "rule_ids": ["TK-SHELL-PARSE"]}),
            v2rec(4, "approval.request", {"approval_id": "apr-1", "binding": {"tool": "Bash", "tool_call_id": "toolu_h2"},
                                          "rule_ids": ["TK-SHELL-PARSE"]}),
            v2rec(7, "approval", {"approval_id": "apr-1", "decision": "approve", "approver": "uid:501"}))

    def test_a_hold_nobody_answered_in_a_subagent_and_how_long_it_blocked_it(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s", "subagents", "agent-a1b2c3d4.jsonl"), [
            cc_assistant("m0", T0, write=50_000, tools=[("toolu_h1", "Bash", {"command": "$PY -m pytest"})]),
            cc_result("toolu_h1", T0 + 480)])
        t = tips.build(rows(*self.RECS), root, NOW)["tips"][2]
        self.assertTrue(t["ok"], t.get("why"))
        self.assertEqual(t["source"], "signed + transcripts")
        self.assertEqual(t["title"], "1 held call nobody answered, 1 in subagents nobody watches")
        self.assertEqual(t["where"], [{"where": "main session", "answered": 1, "open": 0, "blocked_s": 0, "joined": 0},
                                      {"where": "subagents", "answered": 0, "open": 1, "blocked_s": 480, "joined": 1}])
        self.assertEqual(t["rules"], [{"id": "TK-SHELL-PARSE", "n": 1, "reason": view.ENGINE_RULES["TK-SHELL-PARSE"],
                                       "remedy": ""}])
        self.assertEqual(t["saving"], {"usd": None, "minutes": 8})
        self.assertEqual(t["fix"]["copy"], "unset TRACEKIT_APPROVAL_WAIT")   # it waited: nobody answers there
        self.assertIn("a person answered in a median 4 s", " ".join(t["math"]))
        self.assertIn("8 min on the ones nobody answered", " ".join(t["math"]))
        self.assertTrue(t["line"].endswith("blocked the agent for 8 min in all."), t["line"])

    def test_without_a_transcript_the_wait_is_not_known_and_the_rule_is_named(self):
        t = tips.build(rows(*self.RECS), None, NOW)["tips"][2]
        self.assertEqual((t["source"], t["saving"]["minutes"]), ("signed", None))
        self.assertEqual([(w["where"], w["open"]) for w in t["where"]], [("main session", 1)])   # its records alone
        self.assertEqual(t["fix"]["copy"], "tracekit approvals list")
        self.assertTrue(t["fix"]["text"].startswith("TK-SHELL-PARSE held 1 of them"))

    def test_with_no_signed_records_or_no_holds_it_says_so(self):
        self.assertIn("No signed records", tips.build([], None, NOW)["tips"][2]["why"])
        t = tips.build(rows(self.RECS[0]), None, NOW)["tips"][2]
        self.assertEqual((t["ok"], t["why"]), (False, "No call was held for a person in this window: nothing waited "
                                                      "for an answer."))


class Sources(unittest.TestCase):
    def test_a_message_a_signed_record_holds_counts_once_from_the_record(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s.jsonl"), [cc_assistant("msg_1", T0, write=10), cc_assistant("msg_2", T0 + 1)])
        recs = rows(v2rec(1, "run.registered", {"agent": {"name": "claude-code"}}),
                    v2rec(2, "model.exchange", {"exchange_id": "msg_1", "phase": "response", "model": "claude-opus-5-5",
                                                "upstream": "anthropic", "usage": {"input_tokens": 3, "output_tokens": 2}}))
        s = tips.build(recs, root, NOW)["sources"]
        self.assertEqual((s["signed"]["steps"], s["transcripts"]["steps"], s["transcripts"]["files"]), (1, 1, 1))

    def test_reading_the_transcripts_changes_nothing_and_skips_what_the_window_leaves_out(self):
        root = tmp(self)
        path = write_jsonl(os.path.join(root, "p", "s.jsonl"), growing(n=60))
        old = write_jsonl(os.path.join(root, "p", "old.jsonl"), growing(n=60))
        os.utime(old, (T0 - 30 * 86400, T0 - 30 * 86400))   # not written in the window
        before = {p: (os.stat(p).st_mtime_ns, hashlib.sha256(open(p, "rb").read()).hexdigest()) for p in (path, old)}
        out = tips.build([], root, NOW)
        self.assertEqual(before, {p: (os.stat(p).st_mtime_ns, hashlib.sha256(open(p, "rb").read()).hexdigest())
                                  for p in (path, old)})
        self.assertEqual(out["sources"]["transcripts"]["files"], 1)

    def test_a_transcript_line_with_odd_types_is_read_as_nothing_odd(self):
        """A transcript is the agent's to write: a model or tool_use_id that isn't a string raised (an unhashable key,
        fnmatch on a dict) and took the TIPS page down."""
        root = tmp(self)
        odd = cc_assistant("m1", T0 + 1, write=10)
        odd["message"]["model"] = {"name": "x"}
        write_jsonl(os.path.join(root, "p", "s.jsonl"), [
            cc_assistant("m0", T0, write=10, tools=[("toolu_1", "Bash", {"command": ["ls"]})]), odd,
            {"type": "user", "timestamp": "2026-10-10T00:00:00Z", "message": {"content": [
                {"type": "tool_result", "tool_use_id": {"x": 1}}, {"type": "tool_result", "tool_use_id": "toolu_1"}]}}])
        out = tips.build([], root, NOW)
        self.assertEqual(out["sources"]["transcripts"]["steps"], 2)

    def test_durations_read_as_plain_words(self):
        """A wait read 5m29s and a saving 8m00: words a person reads at a glance, with seconds only under 10 minutes."""
        self.assertEqual([tips._dur(s) for s in (45, 329, 480, 2520, 3600, 3900, 7200)],
                         ["45 s", "5 min 29 s", "8 min", "42 min", "1 h", "1 h 5 min", "2 h"])

    def test_the_transcripts_folder_under_home_reads_as_tilde(self):
        root = tmp(self)
        os.makedirs(os.path.join(root, ".claude", "projects"))
        with mock.patch.dict(os.environ, {"HOME": root}):
            self.assertEqual(tips.build([], os.path.join(root, ".claude", "projects"), NOW)["root"], "~/.claude/projects")
        self.assertEqual(tips._shown("/srv/transcripts"), "/srv/transcripts")
        self.assertEqual(tips._shown(root + "x/p"), root + "x/p")   # a sibling of home is not under it

    def test_with_nothing_to_read_every_tip_says_why(self):
        out = tips.build([], None, NOW)
        self.assertEqual([t["ok"] for t in out["tips"]], [False, False, False])
        self.assertTrue(all(t["why"] for t in out["tips"]))

    def test_the_page_works_out_its_answer_at_most_once_a_minute(self):
        page = tips.Page(lambda: [], None)
        with mock.patch.object(tips, "build", return_value={"tips": []}) as built:
            self.assertEqual(page(), page())
            self.assertEqual(built.call_count, 1)
            page.at -= 61
            page()
            self.assertEqual(built.call_count, 2)


class Api(unittest.TestCase):
    def test_tips_are_the_tokens_only_and_its_snapshot_says_it_has_them(self):
        """Tips read the local transcripts and every tenant's runs: a sign-in sees neither, nor the TIPS page."""
        class Feed:
            records, base, lock = [], 0, threading.Condition()
            tips = staticmethod(lambda: '{"tips": []}')
        login = mock.Mock(redirect_uri="http://127.0.0.1/callback")
        login.tenant.return_value = "acme"
        srv = view.server(Feed(), "127.0.0.1", 0, "t0k", login=login)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)

        def get(path, **headers):
            c.request("GET", path, headers=headers)
            r = c.getresponse()
            return r.status, json.loads(r.read())
        token, session = {"Authorization": "Bearer t0k"}, {"Cookie": "tracekit_observe=1.s"}
        self.assertEqual(get("/api/snapshot", **token)[1].get("tips"), True)
        self.assertEqual(get("/api/tips", **token), (200, {"tips": []}))
        self.assertNotIn("tips", get("/api/snapshot", **session)[1])
        self.assertEqual(get("/api/tips", **session)[0], 403)


class Page(unittest.TestCase):
    NAMES = ["esc", "fmtT", "fmtD", "tipDur", "TZ", "plural", "cp", "tipTicks", "tipTok", "tipUsd", "contextChart",
             "cacheChart", "tipBar", "tipBins", "tipEvidence", "TIPNAME", "TIPFROM", "TIPTIME", "tipCard"]

    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("needs node to run the page's code")

    def test_the_context_chart_is_drawn_to_scale(self):
        """y maps tokens linearly from the axis (204) to 8% over the largest value; the right axis is the same line
        in dollars a step pays to re-read it."""
        svg = page_js(self.NAMES, """process.stdout.write(contextChart({x: [0, 1], actual: [100, 200], replay: [100, 50],
            n: 2, cap: 150, marks: [[1, 200]], read: 0.2}))""")
        top = 200 * 1.08
        y = lambda v: f"{204 - 190 * v / top:.1f}"   # noqa: E731
        self.assertIn(f'<line class="tcap" x1="52" x2="658" y1="{y(150)}" y2="{y(150)}"/>', svg)
        self.assertIn(f'<polyline class="tact" points="52.0,{y(100)} 658.0,{y(200)}"/>', svg)
        self.assertIn(f'<polyline class="tsim" points="52.0,{y(100)} 658.0,{y(50)}"/>', svg)
        self.assertIn("compacted itself at 200 tokens", svg)

    def test_the_page_writes_durations_in_plain_words(self):
        out = json.loads(page_js(self.NAMES, """process.stdout.write(JSON.stringify([
            [45, 329, 480, 2520, 3600, 3900, 7200].map(tipDur),
            [8, 42, 65].map(m => tipCard({id: "holds", ok: true, source: "signed", title: "t", line: "l", rules: [],
              where: [{where: "subagents", answered: 0, open: 1, blocked_s: m * 60, joined: 1}],
              saving: {usd: null, minutes: m}, math: [], fix: null}, 2, 7))]))"""))
        self.assertEqual(out[0], ["45 s", "5 min 29 s", "8 min", "42 min", "1 h", "1 h 5 min", "2 h"])
        for card, words in zip(out[1], ("8 min", "42 min", "1 h 5 min")):
            self.assertIn(f"about {words}</b>", card)
            self.assertIn(f"blocked {words}", card)
            self.assertNotRegex(card, r"\d+m\d\d")

    def test_the_page_asks_for_tips_only_when_its_snapshot_says_it_has_them(self):
        """A link opened TIPS on a sign-in's page: its /api/tips 403 would end the page's session."""
        out = json.loads(page_js(["esc", "renderTipsPage"], """
            let PAGE = "tips", TIPSON = false, TIPS = null, TIPSERR = "", TIPSASKED = false, tipsKey = null, asked = 0, html = "";
            const loadTips = () => { asked++; }, put = (id, h) => { html = h; };
            renderTipsPage(); const off = [asked, html];
            TIPSON = true; renderTipsPage();
            process.stdout.write(JSON.stringify([off, asked]));"""))
        self.assertEqual(out[0][0], 0)
        self.assertIn("No tips here", out[0][1])
        self.assertEqual(out[1], 1)

    def test_a_tip_without_enough_data_says_why_and_a_tip_with_it_gives_its_fix_to_copy(self):
        out = json.loads(page_js(self.NAMES, """process.stdout.write(JSON.stringify([
            tipCard({id: "holds", ok: false, why: "No signed records <here>."}, 2, 7),
            tipCard({id: "holds", ok: true, source: "signed", title: "1 held call nobody answered", line: "l",
                     where: [{where: "subagents", answered: 0, open: 1, blocked_s: 0, joined: 0}], rules: [],
                     saving: {usd: null, minutes: null}, math: ["m"], fix: {text: "t", copy: "tracekit approvals list"}},
                    2, 7)]))"""))
        self.assertIn("TIP 3 · HOLDS NOBODY ANSWERED", out[0])
        self.assertIn("No signed records &lt;here&gt;.", out[0])
        self.assertIn('data-copy="tracekit approvals list"', out[1])
        self.assertIn('data-page="approvals"', out[1])
        self.assertIn("not measured", out[1])


if __name__ == "__main__":
    unittest.main()
