"""Tips: what each step of a coding agent cost, and how to cut it, for `tracekit view`'s TIPS page (docs/viewer.md#tips)
and `tracekit tips` (main).

Three tips, each worked out from what the agents' own records show, over the last WINDOW_S:

1. context: every step sends the agent's whole context again. Each long main session's real context growth is
   replayed with an earlier compaction point, each step keeping its real cache behaviour, which estimates what
   compacting there would have cost instead.
2. cache: a wait longer than the prompt cache lasts (each cache write says whether it lasts 5 minutes or 1 hour,
   counted from the start of the request that last read or wrote it) makes the next step write the whole context
   again; bounded polls would have kept the cache.
3. holds: calls held for a person that nobody answered, where they ran (the main session or a subagent) and how long
   they blocked the agent.

Token counts come from signed records where those carry them (a model.exchange response's `usage`: the LLM gateway's,
an SDK integration's) and from Claude Code's transcripts, read-only as `tracekit audit` reads them (the transcript
tailer's records carry no usage). A signed run the transcripts also hold counts once, from the transcripts: matched by
a tool_use id, or by identical token counts within MATCH_S (the gateway signs each exchange under an id of its own,
and a message without tool calls has no tool_use id). Holds come only from signed records; a transcript adds how long
each one blocked the agent and where it ran, joined by its tool_use_id. Each tip names every source it mixes. Dollars
are Anthropic's and OpenAI's list prices (PRICES), not what a subscription bills. No network, no model.
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
from .signer.service import _escaped
from .usage import Prices, _int
from .why import import_v2

# Anthropic's list prices, USD per million tokens, as of 2026-11-05: https://platform.claude.com/docs/en/about-claude/pricing
# Cache writes cost 1.25x input for the 5-minute lifetime and 2x for 1 hour; reads 0.1x input, except where shown:
# https://platform.claude.com/docs/en/build-with-claude/prompt-caching. A model matches by its exact name, then by the
# longest glob (usage.Prices.rate); a model with no row is left out with a note naming it, never given a guessed price.
# lean: Haiku 5.5's row is its price for prompts up to 100K tokens ($0.50 / $2.50 beyond); split the row by prompt size
# if Haiku agents with longer prompts show up
_OPUS4 = {"input": 5, "output": 25, "cache_read": 0.5, "cache_write": 6.25, "cache_write_1h": 10}
_FABLE = {"input": 10, "output": 50, "cache_read": 1, "cache_write": 12.5, "cache_write_1h": 20}
PRICES = {"currency": "USD", "per": 1_000_000, "as_of": "2026-11-07", "models": {
    "claude-fable-5-1*": {**_FABLE, "cache_read": 0.25}, "claude-mythos-5-1*": {**_FABLE, "cache_read": 0.25},
    "claude-fable-5*": _FABLE, "claude-mythos-5*": _FABLE,
    "claude-opus-5-5*": {"input": 4, "output": 20, "cache_read": 0.2, "cache_write": 5, "cache_write_1h": 8},
    "claude-opus-5*": _OPUS4, "claude-opus-4-[678]*": _OPUS4,
    "claude-sonnet-5*": {"input": 2, "output": 10, "cache_read": 0.2, "cache_write": 2.5, "cache_write_1h": 4},
    "claude-sonnet-4-6*": {"input": 3, "output": 15, "cache_read": 0.3, "cache_write": 3.75, "cache_write_1h": 6},
    "claude-haiku-5-5*": {"input": 0.1, "output": 0.5, "cache_read": 0.01, "cache_write": 0.125, "cache_write_1h": 0.2},
    "claude-haiku-4-5*": {"input": 1, "output": 5, "cache_read": 0.1, "cache_write": 1.25, "cache_write_1h": 2}}}
# OpenAI's list prices, USD per million tokens, as of 2026-11-07: https://developers.openai.com/api/docs/pricing (standard
# processing; Batch is half). OpenAI's cache lifetimes are 30 minutes and 12 hours: the 30-minute write is priced
# here as the API's default write (`cache_write`) and the 12-hour one as `cache_write_1h`, so the cache tip's 1-hour
# replay is a lower bound for a 12-hour write. Cached input is a read at `cache_read`. A model with no row is left
# out with a note naming it, never given a guessed price.
# lean: the page doubles input, cached and write prices above 272K input tokens (the long sessions the context tip is
# about); split the rows by prompt size if such sessions show up. GPT-5.6 Sol's row is its promotional price, which
# ends 2026-11-30; re-check it after that.
PRICES["models"].update({
    "gpt-6-astra*": {"input": 10, "output": 50, "cache_read": 1, "cache_write": 12.5, "cache_write_1h": 25},
    "gpt-6-rosalind*": {"input": 15, "output": 75, "cache_read": 1.5, "cache_write": 18.75, "cache_write_1h": 37.5},
    "gpt-6-cyber*": {"input": 20, "output": 100, "cache_read": 2, "cache_write": 25, "cache_write_1h": 50},
    "gpt-6.1-sol*": {"input": 2, "output": 10, "cache_read": 0.1, "cache_write": 2.5, "cache_write_1h": 5},
    "gpt-6-sol*": {"input": 2, "output": 10, "cache_read": 0.2, "cache_write": 2.5, "cache_write_1h": 5},
    "gpt-5.6-sol*": {"input": 4, "output": 20, "cache_read": 0.4, "cache_write": 5, "cache_write_1h": 10},
    "gpt-6.1-terra*": {"input": 1, "output": 5, "cache_read": 0.05, "cache_write": 1.25, "cache_write_1h": 2.5},
    "gpt-5.6-terra*": {"input": 2, "output": 12, "cache_read": 0.2, "cache_write": 2.5, "cache_write_1h": 5},
    "gpt-6-luna*": {"input": 0.1, "output": 0.5, "cache_read": 0.01, "cache_write": 0.125, "cache_write_1h": 0.25},
    "gpt-5.6-luna*": {"input": 0.2, "output": 1.2, "cache_read": 0.02, "cache_write": 0.25, "cache_write_1h": 0.5}})
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
MATCH_S = 300   # a signed step and a transcript step with the same token counts this close are one message
POINTS = 300   # most points a chart's series sends to the page
LIFE = {"5m": 300, "1h": 3600}
POLLS = {"sleep", "until", "while", "watch"}
KEYWORDS = {"for", "if", "case", "select", "function", "do", "then"}
BUILDS = {"pytest", "make", "npm", "npx", "tox", "cargo", "go", "gradle", "mvn"}
PERSON = {"AskUserQuestion", "ExitPlanMode"}   # tools that wait for a person's answer: no poll keeps that cache


def _ctx(s):
    return s["in"] + s["cr"] + s["w5"] + s["w1h"] + s["w"]


def _writes(s):
    return s["w5"] + s["w1h"] + s["w"]


def _write_usd(s, r):   # a write whose lifetime no record says is priced as the API's default, 5 minutes
    return ((s["w5"] + s["w"]) * r["cache_write"] + s["w1h"] * r["cache_write_1h"]) / 1e6


def _input_usd(s, r):
    return (s["in"] * r["input"] + s["cr"] * r["cache_read"]) / 1e6 + _write_usd(s, r)


def _start(s):
    """When a step's request started: its first line's time less its latency (the line before it, a tool result or a
    prompt), else its first line's time."""
    return s["t"] - s["lat"] if s["lat"] is not None else s["t"]


def _step(t, mid, model):   # a transcript is the agent's to write: a model that isn't a name is none
    return {"t": t, "t1": t, "id": mid, "model": model if isinstance(model, str) else None, "in": 0, "out": 0, "cr": 0, "w5": 0, "w1h": 0, "w": 0,
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
                  "cr": _int(u.get("cache_read_input_tokens")) or 0, "w": _int(u.get("cache_creation_input_tokens")) or 0,
                  "calls": [i for i in (r.get("v2") or {}).get("tool_ids") or () if isinstance(i, str)]})
        a["steps"].append(s)
    for a in agents.values():
        a["steps"].sort(key=lambda s: s["t"])
    return agents


def read_transcripts(root, since):
    """Claude Code's transcripts under root, read-only (audit's walk: no symlink followed, nothing written), from
    `since` on -> (agents, calls, files read, unreadable): one agent per transcript file (a session's main file, or one
    of its subagents'), each step a message (by id: a resumed session's file repeats its earlier ones, counted once);
    calls: tool_use id -> {id, agent, tool, family, t0, t1}."""
    # lean: every transcript written in the window is read again each time the page is worked out (a 983 MB folder took
    # 6.7 s and 370 MB); keep each file's offset and fold in only its new lines if a team's week outgrows that
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
                    if not isinstance(mid, str) or not isinstance(m.get("usage"), dict) or \
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
                        tid = b.get("tool_use_id")
                        c = calls.get(tid) if b.get("type") == "tool_result" and isinstance(tid, str) else None
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


def read_codex_sessions(root, since):
    """Codex CLI's session files under root (~/.codex/sessions), read-only, from `since` on -> (agents, files read,
    unreadable): one agent per rollout file, keyed by its session_meta's payload.id (the root thread's id is repeated
    in every subagent's file, so keying on that would merge them), each step a token_usage_record (confirmed from real
    sessions: payload.usage carries input_tokens, cached_input_tokens, cache_write_input_tokens and output_tokens,
    the reasoning included; input_tokens already counts the cached and written ones, so a step's own input is the
    rest). The model is the file's last turn_context. A usage record names no cache lifetime, so its writes are `w`
    (priced at the API's default write), and no call ids are read yet, nor request latencies, so a Codex agent keeps no
    call and the holds tip covers none of them."""
    agents, unreadable, files = {}, [], 0
    if not root or not os.path.isdir(root):
        return agents, files, unreadable
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
        name, mine, seen, model, sid, sub = os.path.basename(path)[:-len(".jsonl")], [], set(), None, None, False
        try:
            for _n, e in transcript_entries(f, final=True):   # a rollout file is JSON lines, but read the safe way
                if not isinstance(e, dict):
                    continue
                p = e.get("payload")
                if not isinstance(p, dict):
                    continue
                if e.get("type") == "session_meta":
                    sid = p.get("id") if isinstance(p.get("id"), str) else sid
                    src = p.get("source")   # an object ("subagent": {...}) in real rollouts, a string in old ones
                    sub = "subagent" in src if isinstance(src, dict) else "subagent" in str(src or "").lower()
                elif e.get("type") == "turn_context" and isinstance(p.get("model"), str):
                    model = p["model"]
                elif e.get("type") == "token_usage_record" and isinstance(p.get("usage"), dict):
                    at, u = _entry_time(e), p["usage"]
                    rid = p.get("response_id")
                    if at is None or at.timestamp() < since:
                        continue
                    if isinstance(rid, str):
                        if rid in seen:   # a resumed file repeats its earlier responses: each counts once
                            continue
                        seen.add(rid)
                    s = _step(at.timestamp(), rid if isinstance(rid, str) else None, model)
                    s["in"] = max(0, (_int(u.get("input_tokens")) or 0) - (_int(u.get("cached_input_tokens")) or 0)
                                   - (_int(u.get("cache_write_input_tokens")) or 0))
                    s["out"] = max(s["out"], _int(u.get("output_tokens")) or 0)
                    s["cr"] = max(s["cr"], _int(u.get("cached_input_tokens")) or 0)
                    s["w"] = max(s["w"], _int(u.get("cache_write_input_tokens")) or 0)
                    mine.append(s)
        except OSError as x:
            unreadable.append({"path": path, "error": f"cannot read: {x}"})
        finally:
            f.close()
        if mine:
            key = sid or session or name
            a = agents.setdefault(key, {"key": key, "kind": "subagent" if sub else "main", "source": "codex",
                                        "label": f"session {key[:8]}", "steps": []})
            a["steps"] += mine
    for a in agents.values():
        a["steps"].sort(key=lambda s: s["t"])
    return agents, files, unreadable


def held_calls(rows, since):
    """The calls held for a person (signed decisions `ask`) in the viewer's rows, as view.review counts them, each with
    when a person (or an agent approver) first answered its approval request, from the signed approval records:
    [{id, t, run, agent, sub, tool, rules, answered}]. The agent's retry of a held call is that call: with its id,
    why.import_v2.held_calls folds it; with another, under the held call's approval, that approval's rows name the held
    call (`held`)."""
    runs = collections.defaultdict(list)   # a call id is unique only within its run
    for r in rows:
        v = r.get("v2") or {}
        if v.get("run_seq") is not None and (r.get("event") == "PreToolUse" or v.get("type", "").startswith("approval")):
            runs[r.get("tenant"), r.get("session_id")].append(r)
    out = []
    for recs in runs.values():
        # each row as the record held_calls reads: view.Translator's rows name its call, attempt and approval
        folds, owners = import_v2.held_calls([{"event": {
            "type": r["v2"]["type"], "run_seq": r["v2"]["run_seq"], "attempt": r["v2"].get("attempt"),
            "data": {"tool_use_id": r["v2"].get("tool_use_id"), "tool": r.get("tool_name"),
                     "decision": r["v2"].get("decision"), "approval_id": r["v2"].get("approval_id")}}} for r in recs])
        latest, answered = {}, {}   # (call id, attempt) and call id -> its latest decision; a held call -> its answer
        for r in recs:
            v = r["v2"]
            if r["event"] == "PreToolUse":
                latest[v.get("tool_use_id")] = latest[v.get("tool_use_id"), v.get("attempt")] = v["run_seq"]
            elif v.get("held"):   # the retry with another id: no hold of its own
                folds[latest.get(v["tool_use_id"] if v.get("attempt") is None else (v["tool_use_id"], v["attempt"]))] = None
            if v["type"] == "approval" and v.get("approval") in ("approve", "reject") and v.get("approval_id") in owners:
                held = owners[v["approval_id"]]
                answered[held] = min(answered.get(held, r["ts"]), r["ts"])
        # the rules that held it, as report._placed places them: not one of another section (a flag) that also matched
        out += [{"id": r.get("tool_use_id"), "t": r["ts"], "run": r.get("session_id"), "sub": bool(r.get("agent_id")),
                 "agent": r.get("agent"), "tool": r.get("tool_name"),
                 "rules": [x for x in r["v2"].get("rules") or [] if (r["v2"].get("secs") or {}).get(x["id"], "ask") == "ask"],
                 "answered": answered.get(r["v2"]["run_seq"])}
                for r in recs if r["event"] == "PreToolUse" and r["v2"].get("decision") == "ask"
                and r["v2"]["run_seq"] not in folds and (r.get("ts") or 0) >= since]
    return out


def _series(values, n=POINTS):
    """At most n points of a per-step series, each the mean of its stretch of steps: the area under the line stays the
    series' sum, so what the chart shades between two series is to scale. -> (first step of each point, values)."""
    k = max(1, math.ceil(len(values) / n))
    return list(range(0, len(values), k)), [round(statistics.fmean(values[i:i + k])) for i in range(0, len(values), k)]


def replay(steps, cap, post, r, w_rate):
    """The input side of `steps` (USD) had the agent compacted whenever its context passed `cap`: each step adds the
    tokens it really added (after a real compaction, its growth from `post`); a compaction drops the context to `post`
    and costs a summary call and a cache write of what is left (`w_rate` USD per million). The summary call sends the
    context: what was cached at the step's re-read price and the step's new part at `w_rate`, or, when the step was a
    rebuild (its cache had expired), all of it at the step's own price per token; and it writes SUMMARY tokens. Each
    other step keeps its real cache behaviour: one that sent at least REBUILT of its context
    fresh (a cache rebuild, or a call with no cache; not the step after a real compaction) re-pays the whole replayed
    context as it paid its own; any other reads from cache what it did not send fresh. A context that shrinks by less
    than half (an agent trimming itself, cleared tool results) shrinks the replay's by the same share. A re-read is
    priced as the step paid for its context (a cache read, or input for a step with no cache). So a cap above every
    context replays the real cost. -> (USD, compactions, the context of each step)."""
    usd, cur = _input_usd(steps[0], r), _ctx(steps[0])
    prev, n, ctx = cur, 0, [cur]
    for s in steps[1:]:
        real, fresh = _ctx(s), s["in"] + _writes(s)
        compacted = real < DROP * prev
        nxt = cur + max(0, real - post) if compacted else cur + real - prev if real >= prev else cur * real / prev
        delta, prev, cur = nxt - cur, real, max(0, nxt)
        reread = r["cache_read"] if s["cr"] else r["input"]
        rebuild = real and not compacted and fresh >= REBUILT * real
        if cur > cap:
            sent = cur * _input_usd(s, r) * 1e6 / real if rebuild else \
                (cur - max(0, delta)) * reread + max(0, delta) * w_rate
            usd += (sent + SUMMARY * r["output"] + post * w_rate) / 1e6
            cur, n = post, n + 1
        elif compacted:   # the replay didn't compact here: it reads its context and adds what the step added
            usd += ((cur - delta) * reread + delta * w_rate) / 1e6
        elif rebuild:
            usd += _input_usd(s, r) * cur / real
        else:
            usd += (max(0, cur - fresh) * r["cache_read"] + s["in"] * r["input"]) / 1e6 + _write_usd(s, r)
        ctx.append(cur)
    return usd, n, ctx


def _dur(s, down=False):
    """A duration in plain words, as the page writes one (its tipDur): "45 s", "5 min 29 s" (under 10 minutes, where the
    seconds still matter), "42 min", "1 h 5 min"; `down`: never rounded up (a limit to stay under)."""
    s = math.floor(s) if down else round(s)
    if s < 60:
        return f"{s} s"
    if s < 600:
        return f"{s // 60} min" + (f" {s % 60} s" if s % 60 else "")
    m = s // 60 if down else round(s / 60)
    return f"{m} min" if m < 60 else f"{m // 60} h" + (f" {m % 60} min" if m % 60 else "")


def _shown(path):
    """A path as the page shows it: under the home folder (expanduser's, as audit.default_root finds it) as ~/..., with
    forward slashes on every OS. Home is looked for among the real path's folders as the same folder (samefile: device
    and inode), so a symlink (macOS's /var), a Windows short name (RUNNER~1) or another case of it still counts, on a
    filesystem that ignores case as well as on Windows."""
    home, cur, rest = os.path.expanduser("~"), os.path.realpath(path), []
    while True:
        try:
            if os.path.samefile(cur, home):
                return "~" + "".join("/" + x for x in reversed(rest))
        except OSError:   # a folder that can't be read, or no home: not under it
            pass
        up = os.path.dirname(cur)
        if up == cur:
            return path
        rest.append(os.path.basename(cur))
        cur = up


def _money(v):
    """Dollars as the page writes them (its tipUsd): whole dollars from $100, cents from $0.10, else two significant
    digits; a negative sum is what it costs more."""
    if v < 0:
        return f"costs {_money(-v)} more"
    if v == 0:
        return "$0"
    if v < 0.0001:
        return "under $0.0001"
    return f"${v:.2g}" if v < 0.1 else f"${v:,.2f}" if v < 100 else f"${v:,.0f}"


def _about(v):
    """An estimated saving in words: about $X, or nothing (and what it would cost more)."""
    return f"about {_money(v)}" if v >= 0.005 else "nothing" + (f": it would cost {_money(-v)} more" if v < 0 else "")


def _k(n):
    return f"{n / 1000:,.0f}k"


FROM = {"signed": "signed records", "transcripts": "Claude Code's transcripts (read-only)",
        "codex": "Codex's session files (read-only)"}


def _from(kinds):
    return " and ".join(FROM[k] for k in ("signed", "transcripts", "codex") if k in kinds)


def context_tip(agents):
    """Tip 1: what compacting earlier would have cost, replayed on each long main session's real context growth."""
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
        r = _RATES.rate(model)
        if r is None:
            unpriced.add(str(model))
            continue
        steps = [s for s in a["steps"] if s["model"] == model]   # a side call to another model has its own context
        ctx = [_ctx(s) for s in steps]
        drops = [i for i in range(1, len(ctx)) if ctx[i] < DROP * ctx[i - 1] and ctx[i - 1] > CAPS[0]]
        post = statistics.median(ctx[i] for i in drops) if drops else ctx[0] + SUMMARY
        writes = sum(_writes(s) for s in steps)
        w_rate = sum(_write_usd(s, r) for s in steps) * 1e6 / writes if writes else r["input"]   # no cache: re-sent
        actual = sum(_input_usd(s, r) for s in steps)
        rows.append({"a": a, "r": r, "model": model, "ctx": ctx, "steps": steps, "drops": drops, "post": post,
                     "actual": actual, "replays": {cap: replay(steps, cap, post, r, w_rate) for cap in CAPS
                                                   if cap < max(ctx)}})
    if not rows:
        tip["why"] = f"No price for {', '.join(sorted(unpriced))}: the tips price Anthropic's and OpenAI's models only (tracekit/tips.py)."
        return tip
    saved = {cap: sum(x["actual"] - x["replays"][cap][0] for x in rows if cap in x["replays"]) for cap in CAPS}
    best = max(saved.values())
    if best <= 0.01:
        peak = max(max(x["ctx"]) for x in rows)
        tip["why"] = (f"No main session's context grew past {_k(CAPS[0])} tokens (the largest reached {_k(peak)}): "
                      "compacting earlier would save nothing worth a change." if peak <= CAPS[0] else
                      "Compacting earlier would not have cost less here: the replay saves nothing.")
        return tip
    cap = max(c for c in CAPS if saved[c] >= NEAR_BEST * best)
    top = max(rows, key=lambda x: x["actual"] - x["replays"].get(cap, (x["actual"],))[0])
    a, r, ctx, steps = top["a"], top["r"], top["ctx"], top["steps"]
    usd, n, sim = top["replays"][cap]
    med = statistics.median(ctx)
    at = statistics.median(ctx[i - 1] for i in top["drops"]) if top["drops"] else None
    total = sum(x["actual"] for x in rows)
    per = top["actual"] * 1e6 / sum(ctx)   # what one token of context cost this session a step, on average
    claude = a["source"] == "transcripts"
    uncached = sum(s["in"] for s in steps) / max(1, sum(ctx))
    # a correlation, not a saving: how much slower a step answered above the cap than below it here
    lat = [(c, s["lat"]) for c, s in zip(ctx, steps) if s["lat"] is not None and 0 < s["lat"] < 600]
    above, below = [d for c, d in lat if c > cap], [d for c, d in lat if c <= cap]
    slower = statistics.median(above) - statistics.median(below) if len(above) >= 10 and len(below) >= 10 else None
    x, act = _series(ctx)
    tip.update(ok=True, cap=cap, agent=a["label"], **{"from": _from({x["a"]["source"] for x in rows})},
               slower=round(slower, 1) if slower is not None and slower > 0 else None,
               title=f"{'Compact' if claude else 'Trim the history it sends'} at about {_k(cap)} tokens"
               + (f", not at {_k(at)}" if at else ""),
               line=(f"Every step sends the whole context again. {a['label']}'s median step carried {_k(med)} tokens "
                     f"of it: {_money(statistics.median(_input_usd(s, r) for s in steps))} before it did anything."),
               saving={"usd": round(saved[cap], 2), "pct": round(100 * saved[cap] / total) if total else 0,
                       "minutes": None},
               caps=[{"cap": c, "usd": round(saved[c], 2), "compactions": sum(x["replays"][c][1] for x in rows
                                                                                if c in x["replays"])}
                     for c in CAPS if any(c in x["replays"] for x in rows)],
               chart={"x": x, "actual": act, "replay": _series(sim)[1], "n": len(ctx), "cap": cap,
                      "marks": [[i, ctx[i - 1]] for i in top["drops"]], "read": round(per, 4)},
               math=[f"{a['label']} ({top['model']}): {len(ctx):,} steps; its context was {_k(med)} tokens at the "
                     f"median and {_k(max(ctx))} at most; it compacted {len(top['drops'])} "
                     f"time{'s' * (len(top['drops']) != 1)}"
                     + (f", at a median {_k(at)}, down to {_k(top['post'])}." if at else "."),
                     f"Its input side as it ran (context read from cache, written to it, or sent uncached): "
                     f"{_money(top['actual'])}, {_money(per)} per million tokens of context a step on average (the "
                     "chart's right axis).",
                     f"Replayed on the same growth, compacting whenever it passed {_k(cap)}: {n} compactions, each down "
                     f"to {_k(top['post'])}, one summary call ({_k(SUMMARY)} output tokens at ${r['output']}/M plus a "
                     "re-read) and a cache write of what is left. Every other step keeps its real cache behaviour (a "
                     f"rebuild after idle time, or a call with no cache, re-pays its whole replayed context): "
                     f"{_money(usd)}.",
                     f"Would have saved: {_money(top['actual'])} - {_money(usd)} = {_about(top['actual'] - usd)}; "
                     f"across the {len(rows)} main session{'s' * (len(rows) != 1)} of {MIN_STEPS}+ steps, "
                     f"{_about(saved[cap])} of {_money(total)}.",
                     f"{_k(cap)} is the largest compaction point that keeps {round(100 * NEAR_BEST)}% of the best "
                     "saving tried: compacting more often saves a little more and loses more detail.",
                     "An estimate: not counted is work redone when a summary drops a detail. Time isn't counted either"
                     + (f": above {_k(cap)} a step answered a median {slower:.1f} s slower here, a correlation, not a "
                        "measured saving." if slower is not None and slower > 0 else ".")]
               + ([f"No price for {', '.join(sorted(unpriced))}: those sessions are left out."] if unpriced else []),
               fix={"text": f"Run /compact with a one-line focus at each task boundary (a PR merged, a release tagged), "
                            f"and at about {_k(cap)} tokens; start a new session for unrelated work.",
                    "copy": "/compact keep the open task, its files and the decisions made"} if claude else
               {"text": (f"Most of what this agent sends ({round(100 * uncached)}%) goes uncached: mark the stable "
                         "start of each request for prompt caching first, which cuts more than compaction. "
                         if uncached > REBUILT else "")
                + f"Trim or summarise the history it sends once it passes about {_k(cap)} tokens (its framework's "
                  "compaction or memory setting).", "copy": None})
    return tip


def cache_tip(agents, calls, held=(), asked=()):
    """Tip 2: steps that wrote their whole context again because the wait before them outlived the prompt cache, and
    what bounded polls would have cost instead. A wait runs from one request's start to the next's: a cache entry lives
    from the start of the request that last read or wrote it. `held`: the calls held for a person nobody answered (they
    could fail at once), `asked`: the ones a person answered (a wait for a person, as idle time is)."""
    tip = {"id": "cache", "ok": False}
    waits, bins, unknown, unpriced, lives, kinds = [], collections.Counter(), 0, set(), collections.defaultdict(set), set()
    edges = ((240, "under 4 min"), (300, "4 to 5 min"), (360, "5 to 6 min"), (600, "6 to 10 min"), (math.inf, "over 10 min"))
    for a in agents:
        known = sum(s["w1h"] for s in a["steps"]), sum(s["w5"] for s in a["steps"])
        default = LIFE["1h"] if known[0] > known[1] else LIFE["5m"] if known[1] else None
        if default:
            lives[a["kind"]].add(default)
            kinds.add(a["source"])
        for p, s in zip(a["steps"], a["steps"][1:]):
            ctx = _ctx(s)
            if ctx < MIN_CTX or ctx < DROP * _ctx(p):   # under half the last step's: a compaction rewrote it, no wait
                continue
            life = LIFE["1h"] if s["w1h"] > s["w5"] else LIFE["5m"] if s["w5"] else default
            if life is None:
                unknown += 1
                continue
            gap, rebuilt = _start(s) - _start(p), _writes(s) >= REBUILT * ctx
            if life == LIFE["5m"] and a["kind"] == "subagent":   # the bins are subagent steps, as they say
                label = next(lbl for edge, lbl in edges if gap < edge)
                bins[label, 0] += 1
                bins[label, 1] += rebuilt
            if gap <= life or not rebuilt:
                continue
            r = _RATES.rate(s["model"])
            if r is None:
                unpriced.add(str(s["model"]))
                continue
            done = [c for c in (calls.get(i) for i in p["calls"]) if c and c["t1"] is not None]
            c = max(done, key=lambda c: c["t1"] - c["t0"], default=None)
            person = c is not None and (c["tool"] in PERSON or c["id"] in asked)
            # blocked on the call: it took most of the wait, and the next request went as soon as it returned
            blocked = c is not None and not person and c["t1"] - c["t0"] >= gap / 2 and _start(s) - c["t1"] <= MARGIN
            now = _write_usd(s, r)
            # with the cache kept the step still writes what it added since the last one, at its own write rate
            grew = min(_writes(s), max(0, ctx - _ctx(p)))
            kept = ((ctx - grew) * r["cache_read"] + grew * now * 1e6 / max(1, _writes(s))) / 1e6
            polls = 0 if blocked and c["id"] in held else math.ceil(gap / (life - MARGIN)) - 1   # a hold could fail at once
            alt = polls * ((ctx - grew) * r["cache_read"] + POLL_OUT * r["output"]) / 1e6 + kept   # polls before it grew
            fix = blocked and alt < now
            waits.append({"t": _start(p), "s": round(gap), "usd": round(now, 4), "alt": round(alt, 4),
                          "tokens": _writes(s), "agent": a["label"], "kind": a["kind"], "life": life, "fix": fix,
                          "cause": ("a call held for a person" if c["id"] in held else c["family"]) if fix else
                          "idle: waiting for a person" if a["kind"] == "main" or person else
                          "idle: resumed after it handed back"})
    tip["bins"] = [{"label": lbl, "n": bins[lbl, 0], "rebuilt": bins[lbl, 1]} for _, lbl in edges if bins[lbl, 0]]
    noprice = [f"No price for {', '.join(sorted(unpriced))}: their rebuilds are left out."] if unpriced else []
    if not waits:
        tip["why"] = noprice[0] if noprice else \
            "No step records how long its cache lasts: the tip reads that from Claude Code's transcripts (each write " \
            "says 5 minutes or 1 hour); Codex's session files name no lifetime either (OpenAI writes last 30 minutes " \
            "or 12 hours, and a session record doesn't say which)." \
            if unknown and not tip["bins"] and any(a["source"] == "codex" for a in agents) else \
            "No step records how long its cache lasts: the tip reads that from Claude Code's transcripts (each write " \
            "says 5 minutes or 1 hour)." if unknown and not tip["bins"] else \
            "No wait outlived the prompt cache: no step had to write its whole context again."
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
    short = min({w["life"] for w in fix} or {LIFE["5m"]})
    sub = [w for w in fix if w["kind"] == "subagent"]
    big = max(fix, key=lambda w: w["usd"], default=None)
    idle = len(waits) - len(fix)
    # what the writes showed, never a guess: "5 min in subagents, 1 h in main sessions"
    seen = ", ".join(f"{' or '.join(_dur(x) for x in sorted(lives[k]))} in {w}" for k, w in
                     (("subagent", "subagents"), ("main", "main sessions")) if lives[k])
    tip.update(ok=True, **{"from": _from(kinds)},
               title=(f"Keep each blocking call under {_dur(short - MARGIN, down=True)}"
                      + (" in a subagent" if sub and len(sub) == len(fix) else "")) if fix else
               "Every cache rebuild here followed idle time, not a blocking call",
               line=(f"{len(fix)} wait{'s' * (len(fix) != 1)} outlived the prompt cache while the agent was blocked on a "
                     f"call, and the next step wrote its whole context again: {_money(now)}." if fix else
                     f"{idle} step{'s' * (idle != 1)} wrote the whole context again after the agent sat idle past "
                     "its cache's lifetime: nothing a poll would have kept."),
               saving={"usd": round(now - alt, 2), "minutes": 0},   # a held call's waiting time is tip 3's
               waits=sorted(waits, key=lambda w: -w["usd"])[:500],
               causes=[{"cause": k, "n": v[0], "s": v[1], "usd": round(v[2], 2), "alt": round(v[3], 2)}
                       for k, v in sorted(causes.items(), key=lambda kv: -kv[1][2])],
               window=[min(w["t"] for w in waits), max(w["t"] + w["s"] for w in waits)],
               math=[f"Each cache write records how long it lasts (ephemeral_5m or ephemeral_1h); here the cache lasted "
                     f"{seen}. It counts from the start of the request that last read or wrote the entry, so each wait "
                     "runs from one request's start to the next's.",
                     "A step that wrote at least half its context to cache after a wait longer than that rebuilt it: "
                     f"{len(waits)} did, {len(fix)} while blocked on a call, {idle} after sitting idle (a person "
                     "away or answering, a subagent resumed later), which no poll would have kept."]
               + ([f"The largest: {big['agent']} waited {_dur(big['s'])}, then wrote "
                   f"{_k(big['tokens'])} tokens to cache: {_money(big['usd'])}.",
                   f"Polling instead, each wait split into calls of at most {_dur(short - MARGIN, down=True)}: every extra poll "
                   f"re-reads the context (a cache read) and writes about {POLL_OUT} output tokens, and the step after "
                   "still writes what it added; a held call nobody answered could fail at once and wait not at all "
                   "(its waiting time is counted in tip 3).",
                   f"Would have saved: {_money(now)} - {_money(alt)} = {_about(now - alt)}, an estimate."] if fix else [])
               + (["Steps without a recorded cache lifetime (signed records and Codex's session files hold none) are "
                   f"left out: {unknown}."] if unknown else []) + noprice,
               fix={"text": "Add a line to the agent's instructions (AGENTS.md or CLAUDE.md):",
                    "copy": f"- Keep each blocking call under {_dur(short - MARGIN, down=True)}: the prompt cache here lasted "
                            f"{seen}, counted from the start of the request that last read or wrote it, and the step "
                            "after it expires re-pays the whole context. Poll in bounded loops "
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
    tip.update(ok=True, **{"from": _from({"signed"} | ({"transcripts"} if waited else set()))},
               title=(f"{len(open_)} held call{'s' * (len(open_) != 1)} nobody answered"
                      + (f", {sub_open} of them in {'a subagent' if sub_open == 1 else 'subagents'}" if sub_open else ""))
               if open_ else "Every held call was answered",
               line=(f"Tracekit held {len(holds)} call{'s' * (len(holds) != 1)} for a person; {len(open_)} never got an "
                     "answer" + (f" and blocked the agent for {_dur(blocked)} in all." if waited else
                                 ", and the agent went on without them.") if open_ else
                     f"Tracekit held {len(holds)} call{'s' * (len(holds) != 1)} for a person and each was answered."),
               saving={"usd": None, "minutes": round(blocked / 60) if waited else None},
               where=where,
               rules=[{"id": i, "n": n, "reason": words[i].get("reason") or "", "remedy": words[i].get("remedy") or ""}
                      for i, n in rules.most_common(6)],
               math=[f"Held calls: {len(holds)} signed decisions `ask` in the window, the agent's retry of a held call "
                     f"counted with it, as the run review counts them; {len(holds) - len(open_)} answered (a signed "
                     f"approval or rejection), {len(open_)} never."]
               + ([f"In the main session a person answered in a median {_dur(statistics.median(answered))} "
                   f"({len(answered)} answered)."] if answered else [])
               + [f"Time blocked: each held call's tool_use to its tool_result in the transcript, joined by tool_use_id: "
                  f"{len(waited)} of {len(holds)} joined; {_dur(blocked)} on the ones nobody answered."
                  if waited else "Time blocked: no transcript holds these calls, so how long each one waited isn't known.",
                  "Where each ran: the transcript that holds its call (a subagent's file), else the record's agent; a "
                  "Claude Code run's records decide a subagent's calls under the session's run."],
               fix={"text": "A held call's hook waits for an answer only while TRACEKIT_APPROVAL_WAIT is set. Where "
                            "nobody is there to answer, remove it from the env block of the Claude Code settings that "
                            "set it: ~/.claude/settings.json ($CLAUDE_CONFIG_DIR/settings.json when that is set), or the "
                            "project's .claude/settings.json or .claude/settings.local.json; the command below edits "
                            "~/.claude/settings.json (with jq). Unset it too in the shell that starts the agent, then restart the agent: "
                            "a running session keeps the value it started with. Answer the rest from APPROVALS.",
                    # written back through the path: a symlinked settings.json stays a link, and the file its mode
                    "copy": "jq 'del(.env.TRACEKIT_APPROVAL_WAIT)' ~/.claude/settings.json > ~/.claude/settings.json.new "
                            "&& cat ~/.claude/settings.json.new > ~/.claude/settings.json && rm "
                            "~/.claude/settings.json.new"} if blocked > 60 else
               {"text": (f"{top} held {rules[top]} of them" + (f": {words[top]['remedy']}" if words[top].get("remedy")
                                                               else f" ({words[top].get('reason') or 'its rule'}).")
                         + " See each one waiting, with the commands that answer it:") if top else
                "See the calls waiting, with the commands that answer them:", "copy": "tracekit approvals list"}
               if open_ else None)
    return tip


def _same(signed, agents, calls):
    """{signed run's key: the indexes of its steps Claude Code's transcripts also hold}, step by step: one that shares a
    tool_use id with a transcript's message, or that takes up one transcript message no other step matched with the
    same token counts within MATCH_S (the gateway signs each exchange under an id of its own, and a message without
    tool calls has no tool_use id to join on)."""
    ids = {i for a in signed.values() for s in a["steps"] for i in s["calls"]}
    pool = collections.defaultdict(list)   # token counts -> the times of the transcript messages not matched yet
    for a in agents.values():
        for s in a["steps"]:
            if not ids.intersection(s["calls"]):
                pool[s["in"], s["out"], s["cr"], _writes(s)].append(s["t"])
    held = collections.defaultdict(set)
    for k, a in signed.items():
        for i, s in enumerate(a["steps"]):
            times = pool.get((s["in"], s["out"], s["cr"], s["w"]), [])
            j = next((j for j, t in enumerate(times) if abs(t - s["t"]) <= MATCH_S), None)
            if any(c in calls for c in s["calls"]) or j is not None:
                held[k].add(i)
                if j is not None and not any(c in calls for c in s["calls"]):
                    times.pop(j)
    return held


def build(rows, root=None, now=None, since=None, codex=None):
    """The TIPS page's data: what was read (`sources`), the window (from `since`, by default WINDOW_S before `now`), the
    price table's date and the three tips. A signed step the transcripts also hold counts once, from the transcripts
    (`sources.signed.also`). The signed records are the viewer's live view, its newest rows, so they may span less than
    the window: `sources.signed.span`. Codex CLI's session files are read from `codex` (~/.codex/sessions) when that
    folder exists."""
    now = time.time() if now is None else now
    since = now - WINDOW_S if since is None else since
    rows = [r for r in rows if r and not r.get("signer")]
    signed = signed_steps(rows, since)
    agents, calls, files, unreadable = read_transcripts(root, since) if root and os.path.isdir(root) else \
        ({}, {}, 0, [])
    codex_agents, codex_files, codex_bad = read_codex_sessions(codex, since)
    same = _same(signed, {**agents, **codex_agents}, calls)   # a signed Codex run its sessions also hold counts once
    also = {"runs": len(same), "steps": sum(map(len, same.values()))}
    for k, idx in same.items():
        signed[k]["steps"] = [s for i, s in enumerate(signed[k]["steps"]) if i not in idx]
    signed = {k: a for k, a in signed.items() if a["steps"]}
    times = [r["ts"] for r in rows if r.get("tk_seq") is not None and (r.get("ts") or 0) >= since]
    holds = held_calls(rows, since)
    every = list(signed.values()) + list(agents.values()) + list(codex_agents.values())
    return {"window": [since, now], "prices": PRICES["as_of"],
            "root": _shown(root) if root and os.path.isdir(root) else None,
            "codex_root": _shown(codex) if codex and os.path.isdir(codex) else None,
            "sources": {"signed": {"agents": len(signed), "steps": sum(len(a["steps"]) for a in signed.values()),
                                   "also": also, "records": len(times),
                                   "span": [min(times), max(times)] if times else None,
                                   "holds": len(holds)},
                        "transcripts": {"files": files, "agents": len(agents), "unreadable": len(unreadable),
                                        "steps": sum(len(a["steps"]) for a in agents.values())},
                        "codex": {"files": codex_files, "agents": len(codex_agents), "unreadable": len(codex_bad),
                                  "steps": sum(len(a["steps"]) for a in codex_agents.values())}},
            "tips": [context_tip(every), cache_tip(every, calls, {h["id"] for h in holds if h["answered"] is None},
                                                   {h["id"] for h in holds if h["answered"] is not None}),
                     holds_tip(holds, calls, bool(rows))]}


class Page:
    """/api/tips' answer: build() over `rows()` (the viewer's rows) and the transcripts under `root`, worked out again
    at most once every `ttl` seconds unless asked `fresh` (READ AGAIN), one request at a time (a week of transcripts
    takes seconds to read)."""

    def __init__(self, rows, root, ttl=60, codex=None):
        self.rows, self.root, self.ttl, self.codex = rows, root, ttl, codex
        self.lock, self.at, self.body = threading.Lock(), 0.0, None

    def __call__(self, fresh=False):
        with self.lock:
            if fresh or self.body is None or time.monotonic() - self.at > self.ttl:
                self.body = json.dumps(build(self.rows(), self.root, codex=self.codex), ensure_ascii=False)
                self.at = time.monotonic()
            return self.body


def signed_rows(cfg, since, say=None):
    """(rows, failed): tracekit view's rows of the client runs in the store of config `cfg` with a record at or after
    `since`, each run checked with the verifier first, as the viewer checks it; `failed`: the runs that didn't verify,
    which give no rows. `say(text)`: told how many runs are checked before the checks."""
    import tempfile

    from . import view
    from .signer.pipeline import SIGNER_RUN
    from .why.core import ts_seconds

    def recent(run):
        # lean: a run is placed by its last record's time as the store says it, before the check; place it by the
        # records a checkpoint covers, as tracekit report does, if a store edited to hide a run matters here
        try:
            return ts_seconds(next(r.iter_range(run["seqs"][-1], run["seqs"][-1] + 1))["event"]["ts"]) >= since
        except (KeyError, TypeError, ValueError):   # a time it can't read: checked, and fails there if it must
            return True
    vkeys, _ = view.store_trust(cfg)
    tr = view.Translator(view.policy_reasons([], os.path.join(cfg["data_dir"], "policies")))
    rows, failed = [], 0
    with tempfile.TemporaryDirectory(prefix="tk-tips-") as tmp:
        trust = view.write_trust(os.path.join(tmp, "trust.json"), vkeys)
        r = view.reader(cfg)
        try:
            note = r.checkpoint_latest()
            keys = [k for k, run in sorted(r.runs.items()) if note and k[1] != SIGNER_RUN[1] and recent(run)]
            if say and keys:
                say(f"checking {len(keys)} run{'s' * (len(keys) != 1)} with the verifier, as tracekit view does: a "
                    "busy week takes minutes")
            for key in keys:
                _, code, _, records = view.check(r, *key, note[1], trust)
                failed += bool(code)
                rows += [x for rec in records for x in tr.feed(rec)]
        finally:
            r.close()
    return rows, failed


NAMES = {"context": "CONTEXT", "cache": "CACHE", "holds": "HOLDS NOBODY ANSWERED"}   # the page's names of the tips


def _wrap(text, indent="  "):
    import textwrap
    return textwrap.fill(text, 100, initial_indent=indent, subsequent_indent=indent, break_on_hyphens=False,
                         break_long_words=False)


def text(t, store, failed=0, root=None):
    """`tracekit tips` in plain words: what it read from `store` (its name) and the transcripts (looked for in `root`),
    then each tip's title, evidence, estimated saving and fix, or why it has none; one line when nothing was read."""
    s, tr, cx = t["sources"]["signed"], t["sources"]["transcripts"], t["sources"]["codex"]
    since = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t["window"][0]))
    read = f"{store}: {s['records']:,} signed records" + (
        f", {failed} run{'s' * (failed != 1)} left out: {'they' if failed != 1 else 'it'} didn't verify (tracekit view "
        "shows why)" if failed else "") + (
        f"; Claude Code's transcripts in {t['root']}: {tr['files']:,} file{'s' * (tr['files'] != 1)}" if t["root"] else
        f"; no Claude Code transcripts in {_shown(root)}" if root else "") + (
        f"; Codex CLI's sessions in {t['codex_root']}: {cx['files']:,} file{'s' * (cx['files'] != 1)}, "
        f"{cx['steps']:,} step{'s' * (cx['steps'] != 1)}"
        + (f", {cx['unreadable']} unreadable" if cx["unreadable"] else "") if t["codex_root"] else "")
    if not (s["records"] or tr["steps"] or cx["steps"]):
        return _escaped(f"tracekit tips: read {read}, since {since}: nothing yet")
    out = [_wrap(f"Read {read}, read-only, since {since}. Dollars are Anthropic's and OpenAI's list prices of {t['prices']}: a "
                 "subscription bills none of them, but the same tokens fill its usage limit. An estimate, "
                 "operator-side, not evidence.", "")]
    for i, x in enumerate(t["tips"], 1):
        out += ["", f"TIP {i} · {NAMES[x['id']]}" + (f" · from {x['from']}" if x.get("from") else "")]
        if not x["ok"]:
            out.append(_wrap(x["why"]))
            continue
        sv = x["saving"]
        usd = None if sv["usd"] is None else _about(sv["usd"]) + (
            f" ({sv['pct']}% of these sessions' input side)" if sv.get("pct") else "")
        minutes = "not measured" if sv["minutes"] is None else f"about {_dur(sv['minutes'] * 60)}" if sv["minutes"] \
            else "none"
        out += [x["title"], _wrap(x["line"]),
                _wrap((f"Would have saved: {usd}, an estimate. " if usd else "") + f"Time: {minutes}.")]
        if x.get("fix"):
            out.append(_wrap("Fix: " + x["fix"]["text"]))
            if x["fix"]["copy"]:
                out.append("    " + x["fix"]["copy"])
    return "\n".join(_escaped(line) for line in "\n".join(out).split("\n"))   # a run's agent name is the agent's text


def main(argv=None):
    """`tracekit tips [--dev | --data-dir DIR] [--since 7d] [--json]` (docs/viewer.md#tracekit-tips)."""
    import argparse
    import sys

    from .audit import codex_root, default_root
    from .report import when
    from .signer.service import dev_data_dir
    from .storage.base import StorageCorrupt, StorageUnavailable
    from .view import store_name
    ap = argparse.ArgumentParser(prog="tracekit tips", description="the TIPS page of tracekit view without the viewer: "
                                 "what each step of your coding agents cost and how to cut it, from the dev signer's "
                                 "store and Claude Code's transcripts, read-only. No network, no model.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's store and Claude Code's transcripts "
                                                      "(the default)")
    g.add_argument("--data-dir", help="a signer data dir (holds store/ and log.vkey): its store alone, as tracekit view "
                                      "--data-dir reads it")
    ap.add_argument("--since", type=when, default="7d", help="7d, 24h, 30m, or an ISO date or time, UTC unless it says "
                                                             "(default: 7d)")
    ap.add_argument("--json", action="store_true", help="print the tips as one JSON object, as the TIPS page reads them")
    a = ap.parse_args(argv)
    now = time.time()
    if a.since >= now:
        ap.error("--since must be in the past")
    try:
        cfg = {"data_dir": os.path.abspath(a.data_dir) if a.data_dir else dev_data_dir(create=False)}
        rows, failed = signed_rows(cfg, a.since, lambda s: print(f"tracekit tips: {s}", file=sys.stderr, flush=True))
    except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit tips: {e}", file=sys.stderr)
        return 1
    root = None if a.data_dir else default_root()
    codex = None if a.data_dir else codex_root()
    t = build(rows, root, now, a.since, codex=codex)
    if a.json and failed:   # the text says it in its first line
        print(f"tracekit tips: {failed} run{'s' * (failed != 1)} left out: they didn't verify (tracekit view shows why)",
              file=sys.stderr)
    print(json.dumps(t, indent=2) if a.json else text(t, _shown(store_name(cfg)), failed, root))
    return 0
