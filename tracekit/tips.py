"""Tips: what each step of a coding agent cost, and how to cut it, for `tracekit view`'s TIPS page (docs/viewer.md#tips).

Three tips, each worked out from what the agents' own records show, over the last WINDOW_S:

1. context: every step re-reads the agent's whole context. Each long agent's real context growth is replayed with an
   earlier compaction point, which says what compacting there would have cost instead.
2. cache: a wait longer than the prompt cache lasts (each cache write says whether it lasts 5 minutes or 1 hour) makes
   the next step write the whole context again; bounded polls would have kept the cache.
3. holds: calls held for a person that nobody answered, where they ran (the main session or a subagent nobody watches)
   and how long they blocked the agent.

Token counts come from signed records where those carry them (a model.exchange response's `usage`: the LLM gateway's,
an SDK integration's) and otherwise from Claude Code's transcripts, read-only as `tracekit audit` reads them (the
transcript tailer's records carry no usage). A message both hold counts once, from the signed record. Holds come only
from signed records; a transcript adds how long each one blocked the agent, joined by its tool_use_id. Every number
says its source. Dollars are Anthropic's list prices (PRICES), not what a subscription bills. No network, no model.
"""
import collections
import json
import math
import os
import re
import statistics
import threading
import time

from .audit import _entry_time, _iter_transcripts, _safe_open
from .hook import transcript_entries
from .usage import Prices, _int

# Anthropic's list prices, USD per million tokens, as of 2026-11-05: https://platform.claude.com/docs/en/about-claude/pricing
# Cache writes cost 1.25x input for the 5-minute lifetime and 2x for 1 hour; reads 0.1x input, except where shown:
# https://platform.claude.com/docs/en/build-with-claude/prompt-caching. A model matches by its exact name, then by the
# longest glob (usage.Prices.rate); a model with no row gets token counts, never a guessed price.
# lean: Haiku 5.5's row is its price for prompts up to 100K tokens ($0.50 / $2.50 beyond); split the row by prompt size
# if Haiku agents with longer prompts show up
_OPUS4 = {"input": 5, "output": 25, "cache_read": 0.5, "cache_write": 6.25, "cache_write_1h": 10}
_FABLE = {"input": 10, "output": 50, "cache_read": 1, "cache_write": 12.5, "cache_write_1h": 20}
PRICES = {"currency": "USD", "per": 1_000_000, "as_of": "2026-11-05", "models": {
    "claude-fable-5-1*": {**_FABLE, "cache_read": 0.25}, "claude-mythos-5-1*": {**_FABLE, "cache_read": 0.25},
    "claude-fable-5*": _FABLE, "claude-mythos-5*": _FABLE,
    "claude-opus-5-5*": {"input": 4, "output": 20, "cache_read": 0.2, "cache_write": 5, "cache_write_1h": 8},
    "claude-opus-5*": _OPUS4, "claude-opus-4-[678]*": _OPUS4,
    "claude-sonnet-5*": {"input": 2, "output": 10, "cache_read": 0.2, "cache_write": 2.5, "cache_write_1h": 4},
    "claude-sonnet-4-6*": {"input": 3, "output": 15, "cache_read": 0.3, "cache_write": 3.75, "cache_write_1h": 6},
    "claude-haiku-5-5*": {"input": 0.1, "output": 0.5, "cache_read": 0.01, "cache_write": 0.125, "cache_write_1h": 0.2},
    "claude-haiku-4-5*": {"input": 1, "output": 5, "cache_read": 0.1, "cache_write": 1.25, "cache_write_1h": 2}}}
_RATES = Prices(PRICES)

WINDOW_S = 7 * 86400
MIN_STEPS = 50   # an agent shorter than this is too short to say when it should have compacted
CAPS = (100_000, 200_000, 300_000, 400_000, 500_000)   # the compaction points the replay tries
NEAR_BEST = 0.8   # the tip names the largest cap that saves at least this share of the best one's saving
SUMMARY = 20_000   # output tokens of one compaction's summary call
DROP = 0.5   # a step whose context is under half the last one's followed a compaction
REBUILT = 0.5   # a step that wrote at least half its context to cache rebuilt it
MIN_CTX = 20_000   # smaller contexts cost too little to be worth a tip
POLL_OUT = 200   # output tokens of one poll step
MARGIN = 30   # a bounded poll returns this many seconds before the cache would expire
POINTS = 300   # most points a chart's series sends to the page
LIFE = {"5m": 300, "1h": 3600}
POLLS = {"sleep", "until", "while", "watch"}
KEYWORDS = {"for", "if", "case", "select", "function", "do", "then"}
BUILDS = {"pytest", "make", "npm", "npx", "tox", "cargo", "go", "gradle", "mvn"}
PERSON = {"AskUserQuestion", "ExitPlanMode"}   # tools that wait for a person's answer: no poll keeps that cache


def _rate(model):
    return _RATES.rate(model)


def _ctx(s):
    return s["in"] + s["cr"] + s["w5"] + s["w1h"] + s["w"]


def _writes(s):
    return s["w5"] + s["w1h"] + s["w"]


def _write_usd(s, r):   # a write whose lifetime no record says is priced as the API's default, 5 minutes
    return ((s["w5"] + s["w"]) * r["cache_write"] + s["w1h"] * r["cache_write_1h"]) / 1e6


def _input_usd(s, r):
    return (s["in"] * r["input"] + s["cr"] * r["cache_read"]) / 1e6 + _write_usd(s, r)


def _step(t, mid, model):
    return {"t": t, "t1": t, "id": mid, "model": model, "in": 0, "out": 0, "cr": 0, "w5": 0, "w1h": 0, "w": 0,
            "lat": None, "calls": []}


def _usage(s, u):
    """Fold one transcript line's `usage` into step s (Claude Code writes a line per content block, each repeating the
    message's usage): the largest count of each kind."""
    split = u.get("cache_creation") if isinstance(u.get("cache_creation"), dict) else {}
    w5, w1h = _int(split.get("ephemeral_5m_input_tokens")) or 0, _int(split.get("ephemeral_1h_input_tokens")) or 0
    for k, v in (("in", _int(u.get("input_tokens"))), ("out", _int(u.get("output_tokens"))),
                 ("cr", _int(u.get("cache_read_input_tokens"))), ("w5", w5), ("w1h", w1h),
                 ("w", max(0, (_int(u.get("cache_creation_input_tokens")) or 0) - w5 - w1h))):
        s[k] = max(s[k], v or 0)


def _family(cmd):
    """What a shell command waits on, in a few words and never its arguments: a polling loop or sleep, tests or a
    build, else the program it starts with."""
    words = str(cmd).replace("&&", " ").replace(";", " ").replace("(", " ").split()
    if POLLS & set(words) or "checks --watch" in str(cmd) or "run watch" in str(cmd):
        return "a polling loop or sleep"
    if BUILDS & {os.path.basename(w) for w in words}:
        return "tests or a build"
    words = [w for w in words if "=" not in w]
    while words and words[0] in ("cd", "env", "time", "nohup", "timeout"):
        words = words[2:] if words[0] in ("cd", "timeout") else words[1:]
    prog = os.path.basename(words[0]) if words else ""
    return f"Bash: {prog}" if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*", prog) and prog not in KEYWORDS else \
        "a shell script"


def signed_steps(rows, since):
    """{agent key: agent} from the viewer's rows of signed model exchanges that carry usage (observe.Translator's
    tk_model rows), each step at its record's time. The usage schema has no cache lifetime: its writes are `w`."""
    agents = {}
    for r in rows:
        u = r.get("usage") if r.get("event") == "tk_model" else None
        if not u or (r.get("ts") or 0) < since:
            continue
        sub = r.get("agent_id")
        key = r.get("session_id", "") + ("/" + sub if sub else "")
        a = agents.setdefault(key, {"key": key, "kind": "subagent" if sub else "main", "source": "signed",
                                    "label": f"{r.get('agent') or 'agent'} run {str(r.get('session_id'))[:8]}"
                                             + (f" · subagent {str(sub)[:8]}" if sub else ""), "steps": []})
        s = _step(r["ts"], (r.get("v2") or {}).get("exchange_id"), r.get("model"))
        s.update({"in": _int(u.get("input_tokens")) or 0, "out": _int(u.get("output_tokens")) or 0,
                  "cr": _int(u.get("cache_read_input_tokens")) or 0, "w": _int(u.get("cache_creation_input_tokens")) or 0})
        a["steps"].append(s)
    for a in agents.values():
        a["steps"].sort(key=lambda s: s["t"])
    return agents


def read_transcripts(root, since, skip=()):
    """Claude Code's transcripts under root, read-only (audit's walk: no symlink followed, nothing written), from
    `since` on -> (agents, calls, files read, unreadable): one agent per transcript file (a session's main file, or one
    of its subagents'), each step a message (by id: a resumed session's file repeats its earlier ones, counted once;
    ids in `skip` a signed record holds); calls: tool_use id -> {id, agent, tool, family, t0, t1}."""
    agents, calls, seen, unreadable, files = {}, {}, set(), [], 0
    for path, session in _iter_transcripts(root, unreadable):
        try:
            if os.lstat(path).st_mtime < since:   # not written in the window: nothing in it can be
                continue
        except OSError:
            continue
        f, err = _safe_open(path)
        if err:
            unreadable.append({"path": path, "error": err})
            continue
        files += 1
        sub = "subagents" in os.path.relpath(path, root).split(os.sep)
        name = os.path.basename(path)[:-len(".jsonl")]
        key = session + ("/" + name if sub else "")
        mine, last_user = {}, None
        try:
            for _n, e in transcript_entries(f, final=True):
                at = e and _entry_time(e)
                if at is None or at.timestamp() < since:
                    continue
                t, m = at.timestamp(), e.get("message") if isinstance(e.get("message"), dict) else {}
                blocks = [b for b in m.get("content") or () if isinstance(b, dict)] if isinstance(m.get("content"), list) else []
                if e.get("type") == "assistant":
                    mid = m.get("id")
                    if not isinstance(mid, str) or not isinstance(m.get("usage"), dict) or mid in skip or \
                            (mid in seen and mid not in mine) or m.get("model") == "<synthetic>":   # an error's stand-in
                        continue
                    s = mine.get(mid)
                    if s is None:
                        s = mine[mid] = _step(t, mid, m.get("model"))
                        s["lat"] = t - last_user if last_user is not None else None
                        seen.add(mid)
                    _usage(s, m["usage"])
                    s["t1"] = max(s["t1"], t)
                    for b in blocks:
                        if b.get("type") == "tool_use" and isinstance(b.get("id"), str):
                            inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                            calls[b["id"]] = {"id": b["id"], "agent": key, "tool": str(b.get("name")), "t0": t,
                                              "t1": None, "family": _family(inp.get("command", ""))
                                              if b.get("name") == "Bash" else str(b.get("name"))}
                            s["calls"].append(b["id"])
                    last_user = None
                elif e.get("type") == "user":
                    for b in blocks:
                        c = calls.get(b.get("tool_use_id")) if b.get("type") == "tool_result" else None
                        if c and c["t1"] is None:
                            c["t1"] = t
                    last_user = t
        except OSError as x:
            unreadable.append({"path": path, "error": f"cannot read: {x}"})
        finally:
            f.close()
        if mine:
            a = agents.setdefault(key, {"key": key, "kind": "subagent" if sub else "main", "source": "transcripts",
                                        "label": (f"subagent {name[6:14]} of session {session[:8]}" if sub else
                                                  f"session {session[:8]}"), "steps": []})
            a["steps"] += mine.values()
    for a in agents.values():
        a["steps"].sort(key=lambda s: s["t"])
    return agents, calls, files, unreadable


def held_calls(rows, since):
    """The calls held for a person (signed decisions `ask`) in the viewer's rows, each with when a person (or an agent
    approver) answered it, from the signed approval records: [{id, t, run, agent, sub, tool, rules, answered}]."""
    answers = {}
    for r in rows:
        v = r.get("v2") or {}
        if v.get("type") == "approval" and v.get("approval") in ("approve", "reject") and v.get("tool_use_id"):
            answers[v["tool_use_id"]] = min(answers.get(v["tool_use_id"], r["ts"]), r["ts"])
    return [{"id": r.get("tool_use_id"), "t": r["ts"], "run": r.get("session_id"), "sub": bool(r.get("agent_id")),
             "agent": r.get("agent"), "tool": r.get("tool_name"), "rules": (r.get("v2") or {}).get("rules") or [],
             "answered": answers.get(r.get("tool_use_id"))}
            for r in rows if r.get("event") == "PreToolUse" and (r.get("v2") or {}).get("decision") == "ask"
            and (r.get("ts") or 0) >= since]


def _series(values, n=POINTS):
    """At most n points of a per-step series, each the mean of its stretch of steps: the area under the line stays the
    series' sum, so what the chart shades between two series is to scale. -> (first step of each point, values)."""
    k = max(1, math.ceil(len(values) / n))
    return list(range(0, len(values), k)), [round(statistics.fmean(values[i:i + k])) for i in range(0, len(values), k)]


def replay(steps, cap, post, r, w_rate):
    """The input side of `steps` (USD) had the agent compacted whenever its context passed `cap`: each step adds the
    tokens it really added (after a real compaction, its growth from `post`); a compaction drops the context to `post`
    and costs a summary call (the context re-read, SUMMARY tokens written) and a cache write of what is left. ->
    (USD, compactions, the context of each step)."""
    usd, cur = _input_usd(steps[0], r), _ctx(steps[0])
    prev, n, ctx = cur, 0, [cur]
    for s in steps[1:]:
        real = _ctx(s)
        new = max(0, real - prev if real >= DROP * prev else real - post)
        prev, cur = real, cur + new
        if cur > cap:
            usd += (cur * r["cache_read"] + SUMMARY * r["output"]) / 1e6 + post * w_rate / 1e6
            cur, n = post, n + 1
        else:
            usd += ((cur - new) * r["cache_read"] + new * w_rate) / 1e6
        ctx.append(cur)
    return usd, n, ctx


def _money(v):
    return f"${v:,.2f}" if v < 100 else f"${v:,.0f}"


def _k(n):
    return f"{n / 1000:,.0f}k"


def context_tip(agents):
    """Tip 1: what compacting earlier would have saved, replayed on each long main session's real context growth."""
    tip = {"id": "context", "ok": False}
    mains = [a for a in agents if a["kind"] == "main"]   # a subagent can't be told to compact
    long = [a for a in mains if len(a["steps"]) >= MIN_STEPS]
    if not long:
        most = max((len(a["steps"]) for a in mains), default=0)
        tip["why"] = (f"No main session made {MIN_STEPS} steps or more (the longest made {most}): too short to say "
                      "when it should have compacted." if mains else "No main session's steps with token counts were "
                      "read.")
        return tip
    rows, unpriced = [], set()
    for a in long:
        model = collections.Counter(s["model"] for s in a["steps"]).most_common(1)[0][0]
        r = _rate(model)
        if r is None:
            unpriced.add(str(model))
            continue
        steps = [s for s in a["steps"] if s["model"] == model]   # a side call to another model has its own context
        ctx = [_ctx(s) for s in steps]
        drops = [i for i in range(1, len(ctx)) if ctx[i] < DROP * ctx[i - 1] and ctx[i - 1] > CAPS[0]]
        post = statistics.median(ctx[i] for i in drops) if drops else ctx[0] + SUMMARY
        writes = sum(_writes(s) for s in steps)
        w_rate = sum(_write_usd(s, r) for s in steps) * 1e6 / writes if writes else r["cache_write"]
        actual = sum(_input_usd(s, r) for s in steps)
        rows.append({"a": a, "r": r, "model": model, "ctx": ctx, "steps": steps, "drops": drops, "post": post, "actual": actual,
                     "replays": {cap: replay(steps, cap, post, r, w_rate) for cap in CAPS if cap < max(ctx)}})
    if not rows:
        tip["why"] = f"No price for {', '.join(sorted(unpriced))}: the tips price Anthropic's models only (tracekit/tips.py)."
        return tip
    saved = {cap: sum(x["actual"] - x["replays"][cap][0] for x in rows if cap in x["replays"]) for cap in CAPS}
    best = max(saved.values())
    if best <= 0.01:
        peak = max(max(x["ctx"]) for x in rows)
        tip["why"] = (f"No main session's context grew past {_k(CAPS[0])} tokens (the largest reached {_k(peak)}): compacting "
                      "earlier would save nothing worth a change." if peak <= CAPS[0] else
                      "Compacting earlier would not have cost less here: the replay saves nothing.")
        return tip
    cap = max(c for c in CAPS if saved[c] >= NEAR_BEST * best)
    top = max(rows, key=lambda x: x["actual"] - x["replays"].get(cap, (x["actual"],))[0])
    a, r, ctx = top["a"], top["r"], top["ctx"]
    usd, n, sim = top["replays"][cap]
    med = statistics.median(ctx)
    at = statistics.median(ctx[i - 1] for i in top["drops"]) if top["drops"] else None
    total = sum(x["actual"] for x in rows)
    # time: how much longer a step took to answer above the cap than below it, on this agent's own steps
    lat = [(c, s["lat"]) for c, s in zip(ctx, top["steps"]) if s["lat"] is not None and 0 < s["lat"] < 600]
    above, below = [d for c, d in lat if c > cap], [d for c, d in lat if c <= cap]
    slower = statistics.median(above) - statistics.median(below) if len(above) >= 10 and len(below) >= 10 else None
    minutes = round(max(0.0, slower) * len(above) / 60) if slower is not None else None
    x, act = _series(ctx)
    tip.update(ok=True, source=a["source"], cap=cap, agent=a["label"],
               title=f"Compact at about {_k(cap)} tokens" + (f", not at {_k(at)}" if at else ""),
               line=(f"Every step re-reads the whole context. {a['label']}'s median step re-read {_k(med)} tokens: "
                     f"{_money(med * r['cache_read'] / 1e6)} before it did anything."),
               saving={"usd": round(saved[cap], 2), "pct": round(100 * saved[cap] / total) if total else 0,
                       "minutes": minutes},
               caps=[{"cap": c, "usd": round(saved[c], 2), "compactions": sum(x["replays"][c][1] for x in rows
                                                                                if c in x["replays"])}
                     for c in CAPS if any(c in x["replays"] for x in rows)],
               chart={"x": x, "actual": act, "replay": _series(sim)[1], "n": len(ctx), "cap": cap,
                      "marks": [[i, ctx[i - 1]] for i in top["drops"]], "read": r["cache_read"]},
               math=[f"{a['label']} ({top['model']}): {len(ctx):,} steps; its context was {_k(med)} tokens at the "
                     f"median and {_k(max(ctx))} at most; it compacted {len(top['drops'])} times"
                     + (f", at a median {_k(at)}, down to {_k(top['post'])}." if at else "."),
                     f"Re-reading the context is a cache read at ${r['cache_read']}/M tokens: {_k(med)} x "
                     f"${r['cache_read']}/M = {_money(med * r['cache_read'] / 1e6)} a step at the median.",
                     f"Its input side as it ran (re-reads, cache writes, uncached input): {_money(top['actual'])}.",
                     f"Replayed on the same growth, compacting whenever it passed {_k(cap)}: {n} compactions, each down "
                     f"to {_k(top['post'])}, one summary call ({_k(SUMMARY)} output tokens at ${r['output']}/M plus a "
                     f"re-read) and a cache write of what is left: {_money(usd)}.",
                     f"Saved: {_money(top['actual'])} - {_money(usd)} = {_money(top['actual'] - usd)}; across the "
                     f"{len(rows)} main session{'s' * (len(rows) != 1)} of {MIN_STEPS}+ steps, {_money(saved[cap])} of "
                     f"{_money(total)} ({round(100 * saved[cap] / total) if total else 0}%).",
                     f"{_k(cap)} is the largest compaction point that keeps {round(100 * NEAR_BEST)}% of the best "
                     "saving tried: compacting more often saves a little more and loses more detail.",
                     "Not counted: work redone when a summary drops a detail."
                     + (f" Time: above {_k(cap)} a step took a median {slower:.1f}s longer to answer, "
                        f"{len(above):,} steps." if slower is not None else " Time: not measured (too few timed steps).")]
               + ([f"No price for {', '.join(sorted(unpriced))}: those agents are left out."] if unpriced else []),
               fix={"text": f"Run /compact with a one-line focus at each task boundary (a PR merged, a release tagged), "
                            f"and at about {_k(cap)} tokens; start a new session for unrelated work.",
                    "copy": "/compact keep the open task, its files and the decisions made"})
    return tip


def cache_tip(agents, calls, held=()):
    """Tip 2: steps that wrote their whole context again because the wait before them outlived the prompt cache, and
    what bounded polls would have cost instead."""
    tip = {"id": "cache", "ok": False}
    waits, bins, unknown, unpriced = [], collections.Counter(), 0, set()
    edges = ((240, "under 4 min"), (300, "4 to 5 min"), (360, "5 to 6 min"), (600, "6 to 10 min"), (math.inf, "over 10 min"))
    for a in agents:
        known = sum(s["w1h"] for s in a["steps"]), sum(s["w5"] for s in a["steps"])
        default = LIFE["1h"] if known[0] > known[1] else LIFE["5m"] if known[1] else None
        for p, s in zip(a["steps"], a["steps"][1:]):
            ctx = _ctx(s)
            if ctx < MIN_CTX:
                continue
            life = LIFE["1h"] if s["w1h"] > s["w5"] else LIFE["5m"] if s["w5"] else default
            if life is None:
                unknown += 1
                continue
            gap, rebuilt = s["t"] - p["t1"], _writes(s) >= REBUILT * ctx
            if life == LIFE["5m"]:
                label = next(lbl for edge, lbl in edges if gap < edge)
                bins[label, 0] += 1
                bins[label, 1] += rebuilt
            if gap <= life or not rebuilt:
                continue
            r = _rate(s["model"])
            if r is None:
                unpriced.add(str(s["model"]))
                continue
            done = [c for c in (calls.get(i) for i in p["calls"]) if c and c["t1"] is not None]
            c = max(done, key=lambda c: c["t1"] - c["t0"], default=None)
            blocked = c is not None and c["t1"] - c["t0"] > life and c["tool"] not in PERSON
            now = _write_usd(s, r)
            if blocked and c["id"] in held:   # a hold that fails fast keeps no one waiting
                alt = ctx * r["cache_read"] / 1e6
            else:
                polls = math.ceil(gap / (life - MARGIN)) - 1
                alt = (polls * (ctx * r["cache_read"] + POLL_OUT * r["output"]) + ctx * r["cache_read"]) / 1e6
            fix = blocked and alt < now
            waits.append({"t": p["t1"], "s": round(gap), "usd": round(now, 4), "alt": round(alt, 4), "tokens": _writes(s),
                          "agent": a["label"], "kind": a["kind"], "life": life, "fix": fix,
                          "cause": ("a call held for a person" if c["id"] in held else c["family"]) if fix else
                          "idle: waiting for a person" if a["kind"] == "main" or c and c["tool"] in PERSON else
                          "idle: resumed after it handed back"})
    tip["bins"] = [{"label": lbl, "n": bins[lbl, 0], "rebuilt": bins[lbl, 1]} for _, lbl in edges if bins[lbl, 0]]
    if not waits:
        tip["why"] = ("No step records how long its cache lasts: the tip reads that from Claude Code's transcripts "
                      "(each write says 5 minutes or 1 hour)." if unknown and not tip["bins"] else
                      "No wait outlived the prompt cache: no step had to write its whole context again."
                      + (f" No price for {', '.join(sorted(unpriced))}." if unpriced else ""))
        return tip
    fix = [w for w in waits if w["fix"]]
    causes = collections.defaultdict(lambda: [0, 0, 0.0, 0.0])
    for w in fix:
        k = causes[w["cause"]]
        k[0] += 1
        k[1] += w["s"]
        k[2] += w["usd"]
        k[3] += w["alt"]
    now, alt = sum(w["usd"] for w in fix), sum(w["alt"] for w in fix)
    lives = sorted({w["life"] for w in fix}) or [LIFE["5m"]]
    sub = [w for w in fix if w["kind"] == "subagent"]
    big = max(fix, key=lambda w: w["usd"], default=None)
    idle = len(waits) - len(fix)
    tip.update(ok=True, source="transcripts",
               title=(f"Keep each blocking call under {(lives[0] - MARGIN) / 60:g} minutes"
                      + (" in a subagent" if sub and len(sub) == len(fix) else "")) if fix else
               "Every cache rebuild here followed idle time, not a blocking call",
               line=(f"{len(fix)} wait{'s' * (len(fix) != 1)} outlived the prompt cache while the agent was blocked on a "
                     f"call, and the next step wrote its whole context again: {_money(now)}." if fix else
                     f"{idle} step{'s' * (idle != 1)} wrote the whole context again after the agent sat idle past "
                     "its cache's lifetime: nothing a poll would have kept."),
               saving={"usd": round(now - alt, 2), "minutes": round(sum(w["s"] for w in fix
                                                                        if w["cause"] == "a call held for a person") / 60)},
               waits=sorted(waits, key=lambda w: -w["usd"])[:500],
               causes=[{"cause": k, "n": v[0], "hours": round(v[1] / 3600, 2), "usd": round(v[2], 2),
                        "alt": round(v[3], 2)} for k, v in sorted(causes.items(), key=lambda kv: -kv[1][2])],
               window=[min(w["t"] for w in waits), max(w["t"] + w["s"] for w in waits)],
               math=["Each cache write records how long it lasts: 5 minutes (ephemeral_5m) or 1 hour (ephemeral_1h). "
                     "Claude Code's subagents write 5-minute entries, its main session 1-hour ones.",
                     "A step that wrote at least half its context to cache after a wait longer than that rebuilt it: "
                     f"{len(waits)} did, {len(fix)} while blocked on a call that outlived the cache, {idle} after "
                     "sitting idle (a person away, a subagent resumed later), which no poll would have kept."]
               + ([f"The largest: {big['agent']} waited {big['s'] // 60}m{big['s'] % 60:02d}s, then wrote "
                   f"{_k(big['tokens'])} tokens to cache: {_money(big['usd'])}.",
                   f"Polling instead, each wait split into calls of at most {(lives[0] - MARGIN) / 60:g} minutes: every "
                   f"extra poll re-reads the context (a cache read) and writes about {POLL_OUT} output tokens; a held "
                   "call that fails at once waits not at all.",
                   f"Saved: {_money(now)} - {_money(alt)} = {_money(now - alt)}."] if fix else [])
               + (["Steps without a recorded cache lifetime (signed records hold none) are left out: "
                   f"{unknown}."] if unknown else []),
               fix={"text": "Add a line to the agent's instructions (AGENTS.md or CLAUDE.md):",
                    "copy": f"- Keep each blocking call under {(lives[0] - MARGIN) / 60:g} minutes: the prompt cache "
                            "expires after 5 idle minutes in a subagent (1 hour in the main session) and the next step "
                            "re-pays the whole context. Poll in bounded loops "
                            "(`for i in $(seq 1 25); do <check> && break; sleep 10; done`), or run a long wait in the "
                            "background and act on its notification."} if fix else None)
    return tip


def holds_tip(holds, calls, signed):
    """Tip 3: calls held for a person that nobody answered, where they ran and how long they blocked the agent."""
    tip = {"id": "holds", "ok": False}
    if not signed:
        tip["why"] = "No signed records in this viewer yet: holds come only from the signer's records."
        return tip
    if not holds:
        tip["why"] = "No call was held for a person in this window: nothing waited for an answer."
        return tip
    # a Claude Code run's records decide a subagent's calls under the session's run: where a hold ran is the
    # transcript's word when one holds its call (a subagent's file), else the record's agent
    holds = [{**h, "sub": "/" in calls[h["id"]]["agent"] if h["id"] in calls else h["sub"]} for h in holds]
    open_ = [h for h in holds if h["answered"] is None]
    waited = {h["id"]: calls[h["id"]]["t1"] - calls[h["id"]]["t0"] for h in holds
              if h["id"] in calls and calls[h["id"]]["t1"] is not None}
    where = []
    for name, sub in (("main session", False), ("subagents", True)):
        hs = [h for h in holds if h["sub"] == sub]
        if hs:
            where.append({"where": name, "answered": sum(h["answered"] is not None for h in hs),
                          "open": sum(h["answered"] is None for h in hs),
                          "blocked_s": round(sum(waited.get(h["id"], 0) for h in hs if h["answered"] is None)),
                          "joined": sum(h["id"] in waited for h in hs)})
    rules = collections.Counter(x["id"] for h in open_ for x in h["rules"])
    words = {x["id"]: x for h in open_ for x in h["rules"]}
    answered = [h["answered"] - h["t"] for h in holds if h["answered"] is not None and not h["sub"]]
    blocked = sum(waited.get(h["id"], 0) for h in open_)
    sub_open = sum(h["sub"] for h in open_)
    top = rules.most_common(1)[0][0] if rules else None
    long_wait = blocked > 60
    tip.update(ok=True, source="signed" + (" + transcripts" if waited else ""),
               title=(f"{len(open_)} held call{'s' * (len(open_) != 1)} nobody answered"
                      + (f", {sub_open} in subagents nobody watches" if sub_open else "")) if open_ else
               "Every held call was answered",
               line=(f"Tracekit held {len(holds)} call{'s' * (len(holds) != 1)} for a person; {len(open_)} never got an "
                     "answer" + (f" and blocked the agent for {round(blocked / 60)} min in all." if waited else
                                 ", and the agent went on without them.") if open_ else
                     f"Tracekit held {len(holds)} call{'s' * (len(holds) != 1)} for a person and each was answered."),
               saving={"usd": None, "minutes": round(blocked / 60) if waited else None},
               where=where,
               rules=[{"id": i, "n": n, "reason": words[i].get("reason") or "", "remedy": words[i].get("remedy") or ""}
                      for i, n in rules.most_common(6)],
               math=[f"Held calls: {len(holds)} signed decisions `ask` in the window; {len(holds) - len(open_)} answered "
                     f"(a signed approval or rejection), {len(open_)} never."]
               + ([f"In the main session a person answered in a median {statistics.median(answered):.0f}s "
                   f"({len(answered)} answered)."] if answered else [])
               + [f"Time blocked: each held call's tool_use to its tool_result in the transcript, joined by tool_use_id: "
                  f"{len(waited)} of {len(holds)} joined; {round(blocked / 60)} min on the ones nobody answered."
                  if waited else "Time blocked: no transcript holds these calls, so how long each one waited isn't known.",
                  "Where each ran: the transcript that holds its call (a subagent's file), else the record's agent; a "
                  "Claude Code run's records decide a subagent's calls under the session's run."],
               fix={"text": "A held call's hook waits for an answer only with TRACEKIT_APPROVAL_WAIT set, and nobody "
                            "answers in a subagent: unset it where agents run unwatched, and answer from APPROVALS.",
                    "copy": "unset TRACEKIT_APPROVAL_WAIT"} if long_wait else
               {"text": (f"{top} held {rules[top]} of them" + (f": {words[top]['remedy']}" if words[top].get("remedy")
                                                               else f" ({words[top].get('reason') or 'its rule'}).")
                         + " See each one waiting, with the commands that answer it:") if top else
                "See the calls waiting, with the commands that answer them:", "copy": "tracekit approvals list"})
    return tip


def build(rows, root=None, now=None):
    """The TIPS page's data: what was read (`sources`), the window, the price table's date and the three tips."""
    now = time.time() if now is None else now
    since = now - WINDOW_S
    rows = [r for r in rows if r and not r.get("signer")]
    signed = signed_steps(rows, since)
    skip = {s["id"] for a in signed.values() for s in a["steps"] if s["id"]}
    agents, calls, files, unreadable = read_transcripts(root, since, skip) if root and os.path.isdir(root) else \
        ({}, {}, 0, [])
    holds = held_calls(rows, since)
    every = list(signed.values()) + list(agents.values())
    return {"window": [since, now], "prices": PRICES["as_of"], "root": root if root and os.path.isdir(root) else None,
            "sources": {"signed": {"agents": len(signed), "steps": sum(len(a["steps"]) for a in signed.values()),
                                   "records": sum(r.get("tk_seq") is not None for r in rows),
                                   "holds": len(holds)},
                        "transcripts": {"files": files, "agents": len(agents), "unreadable": len(unreadable),
                                        "steps": sum(len(a["steps"]) for a in agents.values())}},
            "tips": [context_tip(every), cache_tip(every, calls, {h["id"] for h in holds}),
                     holds_tip(holds, calls, bool(rows))]}


class Page:
    """/api/tips' answer: build() over `rows()` (the viewer's rows) and the transcripts under `root`, worked out again
    at most once every `ttl` seconds, one request at a time (a week of transcripts takes seconds to read)."""

    def __init__(self, rows, root, ttl=60):
        self.rows, self.root, self.ttl = rows, root, ttl
        self.lock, self.at, self.body = threading.Lock(), 0.0, None

    def __call__(self):
        with self.lock:
            if self.body is None or time.monotonic() - self.at > self.ttl:
                self.body = json.dumps(build(self.rows(), self.root), ensure_ascii=False)
                self.at = time.monotonic()
            return self.body
