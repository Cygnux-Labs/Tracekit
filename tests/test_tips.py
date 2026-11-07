"""tracekit view's TIPS page: what each step cost and how to cut it (tracekit/tips.py, /api/tips, the page's cards).

    python3 -m pytest tests/test_tips.py -v
"""
import contextlib
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_signer_service as tsvc  # noqa: E402
from factories import cc_assistant, cc_result, iso, v2rec, wait_for, write_jsonl  # noqa: E402
from test_view import page_js  # noqa: E402
from tracekit import cli, observe, tips, view  # noqa: E402
from tracekit.sdk.client import Client  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402

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


def tools_on(lines):
    """`lines` with a tool call on each message (its id from the message's), so a record can be joined by it."""
    return [{**x, "message": {**x["message"], "content": [{"type": "tool_use", "id": "toolu_" + x["message"]["id"],
                                                             "name": "Read", "input": {}}]}} for x in lines]


def rows(*recs):
    tr = view.Translator()
    return [x for r in recs for x in tr.feed(r)]


def exchanges(lines, ids=None, off=0, tools=False, agent="gateway"):
    """The signed records of an LLM gateway that saw transcript `lines`: each exchange under the gateway's own id, with
    the same token counts (`off` added to the output count) and, with `tools`, the message's tool_use ids."""
    recs = [v2rec(1, "run.registered", {"agent": {"name": agent}})]
    for i, line in enumerate(lines):
        if line["type"] != "assistant":
            continue
        m, u = line["message"], line["message"]["usage"]
        recs.append(v2rec(2 + i, "model.exchange", {
            "exchange_id": f"gx-{i:032x}", "phase": "response", "model": m["model"], "upstream": "anthropic",
            "usage": {"input_tokens": u["input_tokens"], "output_tokens": u["output_tokens"] + off,
                      "cache_read_tokens": u["cache_read_input_tokens"], "cache_write_tokens": u["cache_creation_input_tokens"]},
            **({"tool_uses": [{"id": b["id"], "name": b["name"]} for b in m["content"] if b["type"] == "tool_use"]}
               if tools else {})}, ts=line["timestamp"].replace("Z", ".000000Z") if "." not in line["timestamp"] else
            line["timestamp"]))
    return rows(*recs)


def uncached(n=80, run="r9"):
    """The signed records of an SDK agent that sends its whole context uncached at every step."""
    return rows(v2rec(1, "run.registered", {"agent": {"name": "bot"}}, run=run),
                *[v2rec(2 + i, "model.exchange", {"exchange_id": f"x{i}", "phase": "response", "model": "claude-opus-5-5",
                                                  "upstream": "anthropic",
                                                  "usage": {"input_tokens": 60_000 + 5_000 * i, "output_tokens": 300}},
                        run=run, ts=f"2026-10-10T17:{i // 60:02d}:{i % 60:02d}.000000Z") for i in range(n)])


class Context(unittest.TestCase):
    def test_a_replay_compacts_past_the_cap_and_pays_a_summary_and_a_cache_write(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s1.jsonl"), [
            cc_assistant("m0", T0, write=100_000, life="1h"),
            cc_assistant("m1", T0 + 1, read=100_000, write=100_000, life="1h"),
            cc_assistant("m2", T0 + 2, read=200_000, write=100_000, life="1h")])
        steps = tips.read_transcripts(root, 0)[0]["s1"]["steps"]
        usd, n, ctx = tips.replay(steps, 150_000, 50_000, OPUS, OPUS["cache_write_1h"])
        # 0.80 the first write; at 200k past the cap: a summary call (the 100k it had cached read, the step's 100k new
        # written, 20k out) and 50k written again; then 100k more: 50k read, 100k written
        self.assertAlmostEqual(usd, 0.8 + (0.02 + 0.8 + 0.4 + 0.4) + (0.01 + 0.8))
        self.assertEqual((n, ctx), (1, [100_000, 50_000, 150_000]))

    def test_a_long_main_session_gets_the_point_to_compact_at_and_what_it_saves(self):
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "sess-a.jsonl"), growing())
        t = tips.build([], root, NOW)["tips"][0]
        self.assertTrue(t["ok"], t.get("why"))
        self.assertEqual((t["from"], t["agent"]), ("Claude Code's transcripts (read-only)", "session sess-a"))
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
        self.assertTrue(any("An estimate: not counted is work redone" in m for m in t["math"]))
        self.assertIsNone(t["saving"]["minutes"])   # how fast a step answered is a correlation, not a saving

    def test_with_a_cap_above_every_context_the_replay_is_the_real_cost(self):
        """The replay read every step's context from cache: a rebuild after idle time or a call with no cache cost
        the full price in reality and a cache read in the replay, so the gap was counted as compaction's saving."""
        for name, steps in (("idle rebuilds", self.idle()), ("no cache", self.nocache())):
            with self.subTest(name):
                r = tips.PRICES["models"]["claude-opus-5-5*"]
                actual = sum(tips._input_usd(x, r) for x in steps)
                self.assertAlmostEqual(tips.replay(steps, 10 ** 9, 80_000, r, r["cache_write_1h"])[0], actual)

    def idle(self):
        lines, ctx, t = [], 0, T0
        for i in range(300):
            t += 7200 if i in (200, 240, 280) else 10   # two idle hours before a rebuild: past the 1-hour cache
            read = 0 if i in (0, 200, 240, 280) else ctx
            lines.append(cc_assistant(f"m{i}", t, read=read, write=60_000 + 3_000 * i - read, life="1h"))
            ctx = 60_000 + 3_000 * i
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s.jsonl"), lines)
        return tips.read_transcripts(root, 0)[0]["s"]["steps"]

    def nocache(self):
        return next(iter(tips.signed_steps(uncached(), 0).values()))["steps"]

    def test_an_agent_that_trims_itself_by_under_half_gets_no_saving_from_compacting(self):
        """A context that shrank by a third (API context editing) was subtracted from the replay's own smaller context:
        an agent that already trims itself showed $15 that compacting couldn't save."""
        tr, recs, ctx = view.Translator(), [v2rec(1, "run.registered", {"agent": {"name": "bot"}})], 0
        for i in range(400):
            new, read = (40_000, 0) if i == 0 else (100_000, 20_000) if ctx + 4_000 > 150_000 else (ctx + 4_000, ctx)
            recs.append(v2rec(2 + i, "model.exchange", {"exchange_id": f"x{i}", "phase": "response", "model": "claude-opus-5-5",
                                                        "upstream": "anthropic", "usage": {
                                                            "input_tokens": 0, "output_tokens": 300, "cache_read_tokens": read,
                                                            "cache_write_tokens": new - read}},
                              ts=f"2026-10-10T{17 + i // 3600:02d}:{(i // 60) % 60:02d}:{i % 60:02d}.000000Z"))
            ctx = new
        t = tips.build([x for r in recs for x in tr.feed(r)], None, NOW)["tips"][0]
        self.assertTrue(not t["ok"] or t["saving"]["usd"] <= 0, t.get("saving"))

    def by_hand(self, *steps):
        out = []
        for i, kw in enumerate(steps):
            out.append(tips._step(T0 + i, f"m{i}", "claude-opus-5-5"))
            out[-1].update(kw)
        return out

    def test_the_summary_call_writes_the_steps_new_tokens_it_never_had_cached(self):
        """The summary call's whole context was priced as a cache read, the step's 30k new tokens too, which were never
        cached: the replay cost $1.734 and the saving was overstated."""
        steps = self.by_hand({"w1h": 40_000}, *({"cr": 40_000 + 30_000 * (i - 1), "w1h": 30_000} for i in range(1, 5)))
        usd, n, ctx = tips.replay(steps, 100_000, 30_000, OPUS, OPUS["cache_write_1h"])
        # 40k, 70k and 100k as they ran (0.32, 0.248, 0.254); at 130k past the cap a summary call reads the 100k it had
        # cached and writes the step's 30k at the 1-hour rate, writes 20k out, and 30k is written again (0.9); then
        # 60k: 30k read, 30k written (0.246)
        self.assertAlmostEqual(usd, 0.32 + 0.248 + 0.254 + (100_000 * 0.2 + 30_000 * 8 + 400_000 + 30_000 * 8) / 1e6 + 0.246)
        self.assertGreaterEqual(usd, 1.848)   # the reviewer's paper answer, its new part sent uncached: never a larger saving
        self.assertEqual((n, ctx), (1, [40_000, 70_000, 100_000, 30_000, 60_000]))

    def test_a_summary_call_after_the_cache_expired_pays_as_the_step_did(self):
        """A step that rebuilt its cache (10k read, 110k written after an idle wait) crossed the cap: its summary call
        read 120k from a cache that had expired, at $0.20/M, and the replay cost $1.036."""
        steps = self.by_hand({"w5": 60_000}, {"cr": 60_000, "w5": 30_000}, {"cr": 10_000, "w5": 110_000})
        usd = tips.replay(steps, 100_000, 30_000, OPUS, OPUS["cache_write"])[0]
        # 0.30 and 0.162 as they ran; past the cap the summary call sends its 120k as the step paid for it (0.552), writes
        # 20k out (0.40) and 30k is written again (0.15)
        self.assertAlmostEqual(usd, 0.3 + 0.162 + 0.552 + 0.4 + 0.15)
        self.assertGreaterEqual(usd, 1.492)   # the reviewer's paper answer, at the input price

    def test_a_replay_of_an_uncached_agent_pays_its_re_reads_as_input(self):
        steps = [dict(tips._step(T0 + i, f"x{i}", "claude-opus-5-5"), **{"in": c}) for i, c in
                 enumerate((100_000, 200_000, 300_000))]
        # 0.40 the first call; past the cap a summary call re-sends 200k at $4/M, writes 20k, and 50k is sent again;
        # the last call re-sends its replayed 150k, as it sent its own 300k
        self.assertAlmostEqual(tips.replay(steps, 150_000, 50_000, OPUS, OPUS["input"])[0], 0.4 + (0.8 + 0.4 + 0.2) + 0.6)

    def test_time_is_said_only_when_steps_above_the_cap_were_slower(self):
        root = tmp(self)
        lines = []
        for i, x in enumerate(growing()):   # a reply 2 s after each prompt, however large the context
            lines += [{"type": "user", "timestamp": iso(T0 + 10 * i - 2), "message": {"role": "user", "content": "go"}}, x]
        write_jsonl(os.path.join(root, "p", "s.jsonl"), lines)
        t = tips.build([], root, NOW)["tips"][0]
        self.assertIsNone(t["slower"])
        self.assertFalse(any("slower" in m for m in t["math"]))
        self.assertIn("it compacted 1 time,", t["math"][0])

    def test_an_agent_that_is_not_claude_code_gets_its_own_fix(self):
        t = tips.build(uncached(), None, NOW)["tips"][0]
        self.assertTrue(t["ok"], t.get("why"))
        self.assertTrue(t["title"].startswith("Trim the history it sends at about"), t["title"])
        self.assertIsNone(t["fix"]["copy"])   # no /compact: that is Claude Code's
        self.assertIn("prompt caching", t["fix"]["text"])
        self.assertEqual(t["from"], "signed records")

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
        self.assertEqual(t["title"], "Keep each blocking call under 4 min 30 s in a subagent")
        [w] = t["waits"]
        # from one request's start to the next's: m0 began at T0, m1 at its tool result, T0 + 400
        # the rebuild: 200k written at $5/M; polling: one more poll (a 200k read and 200 tokens out), then the step's read
        self.assertEqual((w["s"], w["life"], w["usd"], w["alt"], w["fix"], w["cause"]),
                         (400, 300, 1.0, 0.084, True, "a polling loop or sleep"))
        self.assertEqual(t["causes"], [{"cause": "a polling loop or sleep", "n": 1, "s": 400, "usd": 1.0, "alt": 0.08}])
        self.assertIn("lasted 5 min in subagents", t["fix"]["copy"])   # what the writes showed
        self.assertEqual(t["saving"], {"usd": 0.92, "minutes": 0})
        self.assertEqual(t["bins"], [{"label": "under 4 min", "n": 1, "rebuilt": 0},
                                     {"label": "6 to 10 min", "n": 1, "rebuilt": 1}])
        self.assertIn("sleep 10", t["fix"]["copy"])
        self.assertNotIn("400", " ".join(c["cause"] for c in t["causes"]))   # a command's family, never its arguments

    def test_polling_still_pays_what_the_step_adds(self):
        t = self.build([
            cc_assistant("m0", T0, write=200_000, tools=[("toolu_s", "Bash", {"command": "sleep 400"})]),
            cc_result("toolu_s", T0 + 400),
            cc_assistant("m1", T0 + 405, write=212_000)])   # the cache expired, and the step added 12k
        [w] = t["waits"]
        # one more poll, then the step reads the 200k it had and writes its 12k at the 5-minute rate
        self.assertEqual((w["usd"], w["alt"]), (1.06, round((200_000 * 0.2 + 200 * 20 + 200_000 * 0.2 + 12_000 * 5) / 1e6, 4)))

    def test_the_wait_bins_count_subagent_steps_only(self):
        """The bins said subagent steps but counted a main session's too (an API-key session writes 5-minute entries)."""
        t = self.build([cc_assistant("m0", T0, write=50_000), cc_assistant("m1", T0 + 10, read=50_000, write=1_000)],
                       sub=False)
        self.assertEqual(t["bins"], [])

    def test_the_rewrite_after_a_compaction_is_not_a_wait(self):
        t = self.build([
            cc_assistant("m0", T0, read=700_000, write=10_000, tools=[("toolu_t", "Bash", {"command": "make test"})]),
            cc_result("toolu_t", T0 + 400),
            cc_assistant("m1", T0 + 405, write=70_000)])   # compacted: a tenth of the context, written again
        self.assertEqual(t.get("waits", []), [])

    def test_a_limit_to_stay_under_is_rounded_down(self):
        t = self.build([cc_assistant("m0", T0, write=200_000, life="1h", tools=[("toolu_a", "Agent", {})]),
                        cc_result("toolu_a", T0 + 4000), cc_assistant("m1", T0 + 4005, write=200_000, life="1h")],
                       sub=False)
        self.assertEqual(t["title"], "Keep each blocking call under 59 min")   # 1 h less 30 s: never "under 1 h"
        self.assertEqual([tips._dur(s, down=True) for s in (270, 3570, 3599)], ["4 min 30 s", "59 min", "59 min"])

    def test_a_wait_counts_from_the_start_of_the_request_before_it(self):
        """The cache lives from the start of the request that read or wrote it: a step whose model took 250 s and whose
        call took 60 s outlived a 5-minute cache, though only 65 s passed between its last line and the next step."""
        t = self.build([
            {"type": "user", "timestamp": iso(T0), "message": {"role": "user", "content": "go"}},
            cc_assistant("m0", T0 + 250, write=200_000, tools=[("toolu_t", "Bash", {"command": "make test"})]),
            cc_result("toolu_t", T0 + 310),
            cc_assistant("m1", T0 + 315, write=200_000)])
        self.assertEqual([(w["s"], w["fix"]) for w in t["waits"]], [(310, False)])   # most of it was the model's own time

    def test_a_held_call_a_person_answered_is_a_wait_for_a_person_not_a_saving(self):
        """A held call approved after 6 minutes counted as a call that could have failed at once: no poll keeps a
        cache while a person decides."""
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s", "subagents", "agent-a1.jsonl"), [
            cc_assistant("m0", T0, write=200_000, tools=[("toolu_h2", "Bash", {"command": "git push"})]),
            cc_result("toolu_h2", T0 + 400),
            cc_assistant("m1", T0 + 405, write=200_000)])
        t = tips.build(rows(*Holds.RECS), root, NOW)["tips"][1]   # toolu_h2: held, then approved
        self.assertEqual([(w["fix"], w["cause"]) for w in t["waits"]], [(False, "idle: waiting for a person")])
        self.assertEqual(t["saving"]["usd"], 0)

    def test_a_rebuild_of_a_model_without_a_price_says_so(self):
        t = self.build([cc_assistant("m0", T0, write=200_000, model="gpt-9", tools=[("toolu_s", "Bash", {"command": "sleep 400"})]),
                        cc_result("toolu_s", T0 + 400), cc_assistant("m1", T0 + 405, write=200_000, model="gpt-9")])
        self.assertEqual(t["why"], "No price for gpt-9: their rebuilds are left out.")   # not "no wait outlived" too

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
        self.assertEqual(t["from"], "signed records and Claude Code's transcripts (read-only)")
        self.assertEqual(t["title"], "1 held call nobody answered, 1 of them in a subagent")
        self.assertEqual(t["where"], [{"where": "main session", "answered": 1, "open": 0, "blocked_s": 0, "joined": 0},
                                      {"where": "subagents", "answered": 0, "open": 1, "blocked_s": 480, "joined": 1}])
        self.assertEqual(t["rules"], [{"id": "TK-SHELL-PARSE", "n": 1, "reason": view.ENGINE_RULES["TK-SHELL-PARSE"],
                                       "remedy": ""}])
        self.assertEqual(t["saving"], {"usd": None, "minutes": 8})
        # it waited and nobody answered: the edit that takes the wait out of Claude Code's settings
        # written back through the path, so a symlinked settings.json stays a link and the file keeps its mode
        self.assertEqual(t["fix"]["copy"], "jq 'del(.env.TRACEKIT_APPROVAL_WAIT)' ~/.claude/settings.json > "
                                           "~/.claude/settings.json.new && cat ~/.claude/settings.json.new > "
                                           "~/.claude/settings.json && rm ~/.claude/settings.json.new")
        for where in ("$CLAUDE_CONFIG_DIR/settings.json", ".claude/settings.local.json", "restart the agent"):
            self.assertIn(where, t["fix"]["text"])
        self.assertIn("a person answered in a median 4 s", " ".join(t["math"]))
        self.assertIn("8 min on the ones nobody answered", " ".join(t["math"]))
        self.assertTrue(t["line"].endswith("blocked the agent for 8 min in all."), t["line"])

    def test_without_a_transcript_the_wait_is_not_known_and_the_rule_is_named(self):
        t = tips.build(rows(*self.RECS), None, NOW)["tips"][2]
        self.assertEqual((t["from"], t["saving"]["minutes"]), ("signed records", None))
        self.assertEqual([(w["where"], w["open"]) for w in t["where"]], [("main session", 1)])   # its records alone
        self.assertEqual(t["fix"]["copy"], "tracekit approvals list")
        self.assertTrue(t["fix"]["text"].startswith("TK-SHELL-PARSE held 1 of them"))

    def test_a_retry_counts_with_its_held_call_as_the_review_and_permissions_count_it(self):
        """Tips counted each decision `ask` a hold of its own: the agent's retry of a held call a person approved, with
        another id (signer _reusable) or its own (LangGraph), was a second hold nobody answered, where the run review and
        PERMISSIONS count one call approved and run."""
        ask = lambda seq, call: v2rec(seq, "policy.decision", {"tool_use_id": call, "tool": "pay", "decision": "ask"})  # noqa: E731
        req = lambda seq, aid, call: v2rec(seq, "approval.request", {"approval_id": aid, "binding": {"tool": "pay", "tool_call_id": call}})  # noqa: E731
        ok = lambda seq, aid, call: v2rec(seq, "approval", {"tool_use_id": call, "approval_id": aid, "decision": "approve", "approver": "uid:501"})  # noqa: E731
        recs = [v2rec(1, "run.registered", {"agent": {"name": "claude-code"}}),
                ask(2, "c1"), req(3, "apr-1", "c1"), ok(4, "apr-1", "c1"),   # its retry c2 uses c1's approval
                ask(5, "c2"), v2rec(6, "approval.consumed", {"approval_id": "apr-1"}, tool_call_id="c2"),
                ask(7, "c3"), req(8, "apr-3", "c3"), ok(9, "apr-3", "c3"),   # its retry has its id
                ask(10, "c3"), v2rec(11, "approval.consumed", {"approval_id": "apr-3"}, tool_call_id="c3"),
                ask(12, "c4"), req(13, "apr-4", "c4"),   # nobody answered
                v2rec(14, "run.final", {"head_run_seq": 14})]
        reviewed = view.review(recs, mock.Mock(integrity="VERIFIED", assurance="dev"), "verified")["holds"]
        perm = json.loads(page_js(["ANSWER", "used", "foldsOf", "callKey", "couldRun", "permOf"], f"""
            process.stdout.write(JSON.stringify(permOf({json.dumps(rows(*recs))}).map(r => [r.rec.tool_use_id, r.out[1]])));"""))
        built = tips.build(rows(*recs), None, NOW)
        self.assertEqual(reviewed, {"approved · ran": 2, "not answered": 1})
        self.assertEqual(perm, [["c4", "NOT ANSWERED"], ["c3", "APPROVED · RAN"], ["c1", "APPROVED · RETRY RAN"]])
        self.assertEqual(built["sources"]["signed"]["holds"], 3)
        self.assertTrue(built["tips"][2]["line"].startswith("Tracekit held 3 calls for a person; 1 never got an answer"),
                        built["tips"][2]["line"])
        self.assertEqual(built["tips"][2]["where"], [{"where": "main session", "answered": 2, "open": 1,
                                                      "blocked_s": 0, "joined": 0}])

    def test_with_no_signed_records_or_no_holds_it_says_so(self):
        self.assertIn("No signed records", tips.build([], None, NOW)["tips"][2]["why"])
        t = tips.build(rows(self.RECS[0]), None, NOW)["tips"][2]
        self.assertEqual((t["ok"], t["why"]), (False, "No call was held for a person in this window: nothing waited "
                                                      "for an answer."))


class Sources(unittest.TestCase):
    def test_a_session_the_gateway_signed_and_the_transcripts_hold_counts_once(self):
        """The gateway signs each exchange under its own id (gx-...), never the transcript's message id: a Claude Code
        session through it counted twice, and its saving doubled."""
        lines = growing()
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "sess-a.jsonl"), lines)
        alone = tips.build([], root, NOW)
        for how, recs in (("by token counts", exchanges(lines)),
                          ("by tool_use id", exchanges(tools_on(lines), off=1, tools=True))):
            with self.subTest(how):
                if how == "by tool_use id":
                    write_jsonl(os.path.join(root, "p", "sess-a.jsonl"), tools_on(lines))
                    alone = tips.build([], root, NOW)
                out = tips.build(recs + uncached(10), root, NOW)   # and an SDK agent no transcript holds
                s = out["sources"]["signed"]
                self.assertEqual((s["steps"], s["also"]), (10, {"runs": 1, "steps": 300}))
                self.assertEqual(out["tips"][0]["saving"], alone["tips"][0]["saving"])
                self.assertEqual(out["tips"][0]["from"], "Claude Code's transcripts (read-only)")

    def test_a_signed_step_counts_once_only_when_a_transcript_message_matches_it(self):
        """One signed step with a transcript message's counts dropped the whole signed run: an SDK agent no transcript
        holds, and a gateway run's second session the transcripts don't hold, both vanished."""
        root = tmp(self)
        write_jsonl(os.path.join(root, "p", "s.jsonl"), growing(n=60))
        t = datetime(2026, 10, 10, 17, 2, tzinfo=timezone.utc).timestamp()   # another session, the SDK step's counts
        write_jsonl(os.path.join(root, "p", "other.jsonl"), [cc_assistant("msg_x", t, new=60_000, out=300)])
        s = tips.build(uncached(), root, NOW)["sources"]["signed"]
        self.assertEqual((s["steps"], s["also"]), (79, {"runs": 1, "steps": 1}))   # the coincidence takes one step
        root = tmp(self)
        a = growing()
        b = [{**x, "timestamp": iso(T0 + 4000 + 10 * i), "message": {**x["message"], "id": "b" + x["message"]["id"],
                                                                      "usage": {**x["message"]["usage"], "output_tokens": 210}}}
             for i, x in enumerate(growing())]
        write_jsonl(os.path.join(root, "proj-a", "sess-a.jsonl"), a)
        s = tips.build(exchanges(a + b), root, NOW)["sources"]["signed"]
        self.assertEqual((s["steps"], s["also"]), (300, {"runs": 1, "steps": 300}))

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
        with open(os.path.join(root, "p", "s.jsonl"), "a") as f:   # a count past a float: 1e999 reads as inf
            f.write('{"type": "assistant", "timestamp": "%s", "message": {"id": "m2", "model": "claude-opus-5-5", '
                    '"content": [], "usage": {"input_tokens": 5, "output_tokens": 1e999}}}\n' % iso(T0 + 2))
        out = tips.build([], root, NOW)
        self.assertEqual(out["sources"]["transcripts"]["steps"], 3)

    def test_durations_read_as_plain_words(self):
        """A wait read 5m29s and a saving 8m00: words a person reads at a glance, with seconds only under 10 minutes."""
        self.assertEqual([tips._dur(s) for s in (45, 329, 480, 2520, 3600, 3900, 7200)],
                         ["45 s", "5 min 29 s", "8 min", "42 min", "1 h", "1 h 5 min", "2 h"])

    def test_the_transcripts_folder_under_home_reads_as_tilde(self):
        """On Windows the folder stayed a full path: expanduser reads USERPROFILE, not HOME, and a temp folder comes
        back as a short name (C:\\Users\\RUNNER~1\\...) that a plain prefix check doesn't match to the long one."""
        root = tmp(self)
        projects = os.path.join(root, ".claude", "projects")
        os.makedirs(projects)
        homes = {"home": root, "home through ..": os.path.join(root, ".claude", ".."),
                 "home with a trailing separator": root + os.sep}
        if os.path.isdir(root.swapcase()) and root.swapcase() != root:   # a case-insensitive filesystem (Windows, macOS)
            homes["home in another case"] = root.swapcase()
        for name, home in homes.items():
            with self.subTest(name), mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
                self.assertEqual(tips.build([], projects, NOW)["root"], "~/.claude/projects")
                self.assertEqual(tips._shown(root), "~")
        with mock.patch.dict(os.environ, {"HOME": root, "USERPROFILE": root}):
            for elsewhere in (os.path.join(tmp(self), "transcripts"), root + "x" + os.sep + "p"):   # a sibling too
                self.assertEqual(tips._shown(elsewhere), elsewhere)

    def test_with_nothing_to_read_every_tip_says_why(self):
        out = tips.build([], None, NOW)
        self.assertEqual([t["ok"] for t in out["tips"]], [False, False, False])
        self.assertTrue(all(t["why"] for t in out["tips"]))

    def test_the_page_works_out_its_answer_at_most_once_a_minute_unless_read_again(self):
        page = tips.Page(lambda: [], None)
        with mock.patch.object(tips, "build", return_value={"tips": []}) as built:
            self.assertEqual(page(), page())
            self.assertEqual(built.call_count, 1)
            page.at -= 61
            page()
            self.assertEqual(built.call_count, 2)
            page(fresh=True)   # READ AGAIN
            self.assertEqual(built.call_count, 3)

    def test_dollars_read_plainly(self):
        self.assertEqual([tips._money(v) for v in (0, 0.00004, 0.084, 0.1, 41.17, 599.8, -16.65)],
                         ["$0", "under $0.0001", "$0.084", "$0.10", "$41.17", "$600", "costs $16.65 more"])
        self.assertEqual([tips._about(v) for v in (2.5, 0.001, -3)],
                         ["about $2.50", "nothing", "nothing: it would cost $3.00 more"])

    def test_a_transcripts_folder_that_is_not_one_is_said_at_start(self):
        missing = os.path.join(tmp(self), "nope")
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.assertEqual(view.main(["--data-dir", tmp(self), "--transcripts", missing]), 2)
        self.assertIn(f"--transcripts {missing}: no such folder", err.getvalue())


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class Command(unittest.TestCase):
    """`tracekit tips`: the TIPS page's tips without the viewer, from a real signer's store (a run with a held call
    nobody answered) and Claude Code's transcripts (a long main session)."""

    def setUp(self):
        for name in ("TICK_S", "CHECKPOINT_S", "CHECKPOINT_MIN_S"):   # a checkpoint every 0.05 s, as test_report's
            p = mock.patch.object(svc, name, 0.05)
            p.start()
            self.addCleanup(p.stop)
        d = tsvc.tmpdir(self)
        self.cfg = {"data_dir": os.path.join(d, "data"), "socket": os.path.join(d, "s.sock")}
        service = svc.open_service(self.cfg, policy=tsvc.PAY_ASKS)
        self.addCleanup(service.close)
        for srv in svc.serve(self.cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = Client(self.cfg["socket"])
        self.addCleanup(client.close)
        run = client.run(agent="claude-code")
        self.assertEqual(run.decide("c1", "pay", {"cents": 5})["decision"], "ask")
        run.call("approval_request", tool_call_id="c1")
        run.close()
        st = service.log.storage
        self.assertTrue(wait_for(lambda: (st.checkpoint_latest() or (0,))[0] == st.tree.size, 20))
        self.cc = tmp(self)
        write_jsonl(os.path.join(self.cc, "projects", "p", "s.jsonl"), growing())

    def tips(self, *args):
        """(exit code, stdout, stderr) of `tracekit tips --since 2026-10-01` as the dev signer's user, its transcripts
        in the folder setUp wrote: before growing()'s session and the store's records."""
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(svc, "dev_data_dir", return_value=self.cfg["data_dir"]), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.cc}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["tips", "--since", "2026-10-01", *args])
        return code, out.getvalue(), err.getvalue()

    def test_each_tip_says_its_title_evidence_saving_and_fix_in_plain_words(self):
        code, out, err = self.tips()
        self.assertEqual(code, 0, err)
        self.assertIn("tracekit tips is experimental", err)
        got = json.loads(self.tips("--json")[1])
        head, *cards = out.split("\n\n")
        self.assertIn(f": {got['sources']['signed']['records']} signed records; Claude Code's transcripts in ",
                      " ".join(head.split()))   # the header wraps at 100 columns
        self.assertIn(", read-only, since 2026-10-01 00:00 UTC.", " ".join(head.split()))
        self.assertEqual(len(cards), 3)
        for i, (card, t) in enumerate(zip(cards, got["tips"]), 1):
            lines, flat = card.splitlines(), " ".join(card.split())
            self.assertEqual(lines[0], f"TIP {i} · {tips.NAMES[t['id']]}" + (f" · from {t['from']}" if t.get("from")
                                                                              else ""))
            if not t["ok"]:   # why it has none
                self.assertEqual(lines[1:], [f"  {t['why']}"])
                continue
            self.assertEqual(lines[1], t["title"])   # then its evidence, saving and fix
            self.assertIn(" ".join(t["line"].split()), flat)
            self.assertIn(f"Fix: {' '.join(t['fix']['text'].split())}", flat)
            self.assertEqual(lines[-1], f"    {t['fix']['copy']}")
        context, _, holds = cards
        context = " ".join(context.split())   # lines wrap at 100 columns
        self.assertIn("Would have saved: about $", context)
        self.assertIn("an estimate. Time: not measured.", context)
        self.assertEqual(holds.splitlines()[1], "1 held call nobody answered")

    def test_json_is_what_the_page_reads(self):
        code, out, err = self.tips("--json")
        self.assertEqual(code, 0, err)
        got = json.loads(out)
        self.assertEqual(list(got), ["window", "prices", "root", "sources", "tips"])
        self.assertEqual([(t["id"], t["ok"]) for t in got["tips"]], [("context", True), ("cache", False),
                                                                     ("holds", True)])
        self.assertEqual((got["sources"]["signed"]["holds"], got["sources"]["transcripts"]["files"]), (1, 1))
        self.assertEqual(got["window"][0], datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp())

    def test_with_nothing_read_it_says_what_it_read_in_one_line(self):
        empty = {"data_dir": os.path.join(tmp(self), "data")}
        svc.open_service(empty).close()   # a signer started once: its key, no run
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["tips", "--data-dir", empty["data_dir"]]), 0)
        store = tips._shown(os.path.join(empty["data_dir"], "store"))
        self.assertRegex(out.getvalue(), rf"^tracekit tips: read {re.escape(store)}: 0 signed records, since "
                                         r"\d{4}-\d\d-\d\d \d\d:\d\d UTC: nothing yet\n$")


class Api(unittest.TestCase):
    def test_tips_are_the_tokens_only_and_its_snapshot_says_it_has_them(self):
        """Tips read the local transcripts and every tenant's runs: a sign-in sees neither, nor the TIPS page."""
        class Feed:
            records, base, lock = [], 0, threading.Condition()
            tips = staticmethod(lambda fresh=False: '{"tips": []}')
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
             "cacheChart", "tipBar", "tipBins", "tipEvidence", "TIPNAME", "TIPTIME", "tipCard"]

    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("needs node to run the page's code")

    def test_the_context_chart_is_drawn_to_scale(self):
        """y maps tokens linearly from the axis (212) to 8% over the largest value, 22 from the top; the right axis is
        the same line in dollars a step pays for that much context."""
        svg = page_js(self.NAMES, """process.stdout.write(contextChart({x: [0, 1], actual: [100, 200], replay: [100, 50],
            n: 2, cap: 150, marks: [[1, 200]], read: 0.2}))""")
        top = 200 * 1.08
        y = lambda v: f"{212 - 190 * v / top:.1f}"   # noqa: E731
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

    def test_the_page_writes_dollars_plainly_and_a_loss_as_what_it_costs_more(self):
        """A card read "$0.0000" for a tiny sum and "$-16.650" for a compaction point that cost more than it saved."""
        out = json.loads(page_js(self.NAMES, """process.stdout.write(JSON.stringify([
            [0, 0.00004, 0.084, 0.1, 41.17, 599.8, -16.65].map(tipUsd),
            tipCard({id: "context", ok: true, from: "signed records", title: "t", line: "l", cap: 200, agent: "a",
                     chart: {x: [0, 1], actual: [100, 300], replay: [100, 150], n: 2, cap: 200, marks: [], read: 0.2},
                     caps: [{cap: 100, usd: -16.65, compactions: 9}, {cap: 200, usd: -2, compactions: 1}],
                     saving: {usd: -2, pct: -4, minutes: null}, math: [], fix: null}, 0, 7)]))"""))
        self.assertEqual(out[0], ["$0", "under $0.0001", "$0.084", "$0.10", "$41.17", "$600", "costs $16.65 more"])
        self.assertIn("costs $16.65 more", out[1])
        self.assertIn('WOULD HAVE SAVED<b class="tzero">nothing</b>', out[1])
        self.assertNotRegex(out[1], r"\$-|\$0\.0000")

    def test_the_read_line_says_what_counted_once_and_that_every_project_is_listed(self):
        out = page_js(self.NAMES + ["renderTipsPage"], """
            let PAGE = "tips", TIPSON = true, TIPSERR = "", TIPSASKED = true, tipsKey = null, html = "";
            const put = (id, h) => { html = h; }, $ = () => ({}), loadTips = () => {};
            let TIPS = {window: [0, 7 * 86400], prices: "2026-11-05", root: "~/.claude/projects", tips: [],
                        sources: {signed: {records: 9, steps: 2, holds: 0, also: {runs: 1, steps: 300}, span: [43200, 86400]},
                                  transcripts: {files: 3, steps: 400, unreadable: 0}}};
            renderTipsPage(); process.stdout.write(html);""")
        self.assertIn("300 more signed model steps of 1 run the transcripts also hold, counted once, from them", out)
        self.assertIn("transcripts in ~/.claude/projects, read-only", out)
        self.assertIn("the tips list sessions from every project under that folder", out)
        self.assertIn("9 signed records from 1970-01-01", out)   # the live view's span, not the window's
        self.assertIn("to 1970-01-02", out)
        self.assertIn("the viewer&#39;s live view", out)

    def test_a_phone_stacks_card_3_wraps_its_tables_and_enlarges_the_chart_text(self):
        css = observe.read_text(observe.UI)
        phone = css[css.index("/* phones: every page stacks"):]
        for rule in (".tbars {\n        grid-template-columns: minmax(0, 1fr)", ".tcard table.wt th {\n        white-space: normal\n",
                     ".tcard table.wt td {\n        white-space: normal;\n        overflow-wrap: anywhere",
                     ".tchart text {\n        font-size: 17px"):
            with self.subTest(rule=rule):
                self.assertIn(rule, phone)

    def test_the_context_card_says_steps_were_slower_only_when_they_were(self):
        card = """tipCard({id: "context", ok: true, from: "f", title: "t", line: "l", cap: 200000, agent: "a", slower: SLOWER,
                  chart: {x: [0, 1], actual: [1, 3], replay: [1, 2], n: 2, cap: 2, marks: [], read: 0.2}, caps: [],
                  saving: {usd: 5, pct: 9, minutes: null}, math: [], fix: null}, 0, 7)"""
        out = json.loads(page_js(self.NAMES, "process.stdout.write(JSON.stringify(["
                                 + card.replace("SLOWER", "null") + "," + card.replace("SLOWER", "0.6") + "]))"))
        self.assertNotIn("slower", out[0])
        self.assertIn("compaction&#39;s effect on time isn&#39;t measured", out[0])
        self.assertIn("steps above 200k answered a median 0.6 s slower here, a correlation, not a saving", out[1])

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
