"""The viewer's FLEET page: what a store's agents did over 24 hours, 7 days or 30 days, against the range before it
(docs/viewer.md#fleet, experimental). `tracekit view` answers /api/fleet from here.

Every number comes from the signed records of runs the viewer verified, up to the checkpoint that covers them. A run
that fails, is not covered by a checkpoint yet or is checked again after a store change is never counted: the answer
lists it. `summarize` keeps what one verified run adds, once, as the viewer verifies it (StoreFeed._verify); `build`
adds the summaries up for a range.

How a call is counted. A call is a policy.decision record, with the agent's retry of a held call (the one that ran
under that call's approval) counted as the held call (why.import_v2._calls). It is in one of the three chart classes
by the first that holds: errored (its tool.result says ok false), denied (decided deny), held (decided ask), else ok.
The Held, Denied and Errors tiles and every table count each call in each of them it belongs to, so a call held and
then errored is in Held and in Errors, and in the per-day chart's errors alone. A call is placed in a day by its
policy.decision's time.

Latency is the signer's own: the time of a call's tool.result record less the time of its policy.decision record, both
stamped by the signer when it recorded them, never the tool.result's duration_ms, which the agent reports. A call that
was held, denied or has no result is not in the latency numbers: a hold's wait is a person's.

Tokens come from model.exchange responses' usage, each model turn once (as the live view counts it). Dollars only from
a price table the person passes (`tracekit view --prices FILE`, as `tracekit cost` takes it): Tracekit ships no prices
here, and a model the table doesn't name has none, never a guess.
"""
import collections
import datetime
import json
import math
import threading
import time

from .why.core import ts_seconds
from .why.import_v2 import _calls, _call_id

HELD, DENIED, ERROR = 1, 2, 4   # a call's flags
RUNS_MAX = 500   # run ids one link carries: a link past it names its first RUNS_MAX
ISSUES_MAX = 30
TOOLS_MAX = 25
RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
SEVERITY = {"critical": "high", "high": "high", "medium": "med"}
MATCH_S = 300   # a signed model turn and one the other source signed with the same token counts this close are one


def _turns(records):
    """A run's model turns as (t, model, input, output, cache read, cache write), each counted once: a response signed
    twice, or by the LLM gateway and the transcript tailer under ids of their own (joined by its exchange id, a tool_use
    id, or the same counts within MATCH_S), is one turn, with the gateway's counts."""
    turns, seen, pool = [], {}, collections.defaultdict(list)
    for r in records:
        e, d = r["event"], r["event"].get("data") or {}
        u = d.get("usage")
        if e["type"] != "model.exchange" or d.get("phase") != "response" or not isinstance(u, dict):
            continue
        t, gw = ts_seconds(e["ts"]), e.get("source") == "gateway"
        counts = tuple(u.get(k) or 0 for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"))
        keys = [k for k in ["x" + str(d["exchange_id"]) if d.get("exchange_id") is not None else None,
                            *("t" + str(x["id"]) for x in d.get("tool_uses") or ())] if k]
        mine = pool[counts]
        turn = next((seen[k] for k in keys if k in seen), None)
        j = (mine.index(turn) if turn in mine else -1) if turn and turn["gw"] != gw else -1 if turn else \
            next((i for i, p in enumerate(mine) if p["gw"] != gw and abs(p["t"] - t) <= MATCH_S), -1)
        if j >= 0:
            turn = mine.pop(j)
        if turn is None:
            turn = {"t": t, "model": d.get("model") or "?", "n": counts, "gw": gw}
            turns.append(turn)
            mine.append(turn)
        elif gw and not turn["gw"]:
            turn.update(t=t, model=d.get("model") or turn["model"], n=counts, gw=True)
        for k in keys:
            seen[k] = turn
    return [(x["t"], x["model"], *x["n"]) for x in turns]


def summarize(records, rules):
    """What one verified run adds to the page, from its `records` (as the viewer verified them): its agent, when it
    began and was last written, whether it is final, its calls (time, tool, flags, signer-observed milliseconds or
    None), the held and denied calls by rule (`marks`), its model turns, the holds an AI approver and a person both
    answered (`pairs`) and, for a findings run, its signed findings (about `analyzes`). `rules(decision data)`: its
    rules as [{"id", "reason"}] (view.Translator.rules)."""
    evs = [r["event"] for r in records]
    out = {"count": len(records), "agent": None, "analyzes": None, "final": False, "first": ts_seconds(evs[0]["ts"]),
           "last": ts_seconds(evs[-1]["ts"]), "calls": [], "marks": [], "tokens": _turns(records), "pairs": [],
           "findings": []}
    asked, verdicts = {}, {}   # approval id -> the rules its request names; -> {"agent": verdict, "person": verdict}
    for e in evs:
        t, d = e["type"], e.get("data") or {}
        if t == "run.registered":
            name = (d.get("agent") or {}).get("name")
            out["agent"], out["analyzes"] = name if isinstance(name, str) else None, d.get("analyzes")
        elif t == "run.final":
            out["final"] = True
        elif t == "approval.request":
            asked[d.get("approval_id")] = d.get("rule_ids") or []
        elif t in ("approval", "approval.suggested") and d.get("decision") in ("approve", "reject"):
            who = "agent" if d.get("approver_kind") == "agent" else "person"
            if t == "approval" or who == "agent":
                v = verdicts.setdefault(d.get("approval_id"), {})
                v.setdefault(who, d["decision"])
                v["t"] = ts_seconds(e["ts"])
        elif t == "review" and (d.get("verdict") or {}).get("kind") == "finding":
            v = d["verdict"]
            out["findings"].append((ts_seconds(e["ts"]), v.get("rule"), SEVERITY.get(v.get("severity"), "low"),
                                    v.get("title") or ""))
    for aid, v in verdicts.items():
        if "agent" in v and "person" in v:
            out["pairs"].append((v["t"], asked.get(aid) or ["no rule"], v["agent"] == v["person"]))
    calls = _calls(records)
    ran_by = {(c.get("approval") or {}).get("ran_by"): c for c in calls.values()}
    result = {}   # a held call's -> the result of the retry that ran under its approval
    for c in calls.values():
        if (c.get("approval") or {}).get("retry_of") and (held := ran_by.get(_call_id(c["decision"]))):
            result[held["seq"]] = c.get("result")
    for c in calls.values():
        if (c.get("approval") or {}).get("retry_of"):
            continue   # the held call's retry: that call
        e = c["decision"]["event"]
        d, res = e["data"], c.get("result") or result.get(c["seq"])
        t, flags = ts_seconds(e["ts"]), (d["decision"] == "ask") * HELD | (d["decision"] == "deny") * DENIED
        flags |= ERROR * (bool(res) and res["event"]["data"].get("ok") is False)
        ms = None
        if res and not flags & (HELD | DENIED):
            ms = max(0, round((ts_seconds(res["event"]["ts"]) - t) * 1000))
        out["calls"].append((t, d.get("tool") or "?", flags, ms))
        for kind in ("held" * bool(flags & HELD), "denied" * bool(flags & DENIED)):
            for rule in kind and (rules(d) or [{"id": "no rule", "reason": ""}]):
                out["marks"].append((t, kind, rule["id"], rule.get("reason") or "", d.get("tool") or "?"))
    return out




def findings(alerts, records):
    """A run's findings from the viewer's analysis of it (StoreFeed._findings' alerts), as summarize keeps signed ones:
    (time, rule, severity, title), placed at the first record each cites, else the run's last."""
    when = {r["event"]["run_seq"]: ts_seconds(r["event"]["ts"]) for r in records}
    out = []
    for a in alerts:
        v, cites = ((a.get("v2") or {}).get("finding")), (a.get("v2") or {}).get("cites") or ()
        if v:
            out.append((when.get(cites[0]["run_seq"] if cites else None, when[max(when)]), v["rule"],
                        SEVERITY.get(v["severity"], "low"), v.get("title") or ""))
    return out


def _tz(name):
    import zoneinfo
    try:
        return zoneinfo.ZoneInfo(name), name
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):   # lean: UTC when this machine has no tz data
        return datetime.timezone.utc, "UTC"


def window(now, span, tz):
    """(start, previous start, bucket starts) of the range `span` ending at `now`: the last N whole local days, today
    partial, for 7d and 30d; the last 24 clock hours for 24h. The previous range is as long, directly before."""
    if span == "24h":
        starts = [(int(now // 3600) - 23 + i) * 3600 for i in range(24)]
        return starts[0], starts[0] - 86400, starts
    n = RANGES[span] // 86400
    today = datetime.datetime.fromtimestamp(now, tz).date()
    day = lambda i: datetime.datetime.combine(today - datetime.timedelta(days=n - 1 - i), datetime.time(), tz).timestamp()
    return day(0), day(-n), [day(i) for i in range(n)]


def _pct(sorted_ms, p):
    return sorted_ms[math.ceil(p * len(sorted_ms)) - 1] if sorted_ms else None


def _usd(prices, model, n):
    """The cost of one turn's counts `n`, None when there is no price table or it has no price for `model`."""
    return prices and prices.cost(model, dict(zip(("input_tokens", "output_tokens", "cache_read_tokens",
                                                   "cache_write_tokens"), n)))


def _status(first, times, since, prev):
    """An issue's status: new when first seen in the range, ongoing when seen in the range before it, else (seen
    before that, absent in it, and now again) regressed."""
    if first >= since:
        return "new"
    return "ongoing" if any(prev <= t < since for t in times) else "regressed"


def _add(counts, n):
    for j in range(4):
        counts[j] += n[j]


def build(runs, now, span, tz_name, prices=None):
    """The page's data over range `span` (RANGES) ending at `now` for `runs`, {(tenant, run_id): summary} of the runs
    that verified; days in the IANA time zone `tz_name` (UTC when this machine does not know it); `prices`: a
    usage.Prices or None. A link is {"n": runs, "runs": [index into "names"]} of the runs a number counts."""
    import bisect

    from .findings_v2 import TITLES
    tz, tz_name = _tz(tz_name)
    since, prev, starts = window(now, span, tz)
    until = now
    day = lambda t: bisect.bisect_right(starts, t) - 1   # noqa: E731
    mine = {k: s for k, s in runs.items() if not s["analyzes"]}   # an analysis run is no agent's run
    sets, names, at = collections.defaultdict(set), [], {}   # (what, *scope) -> the runs it counts; the runs linked

    def link(*key):
        keys = sorted(sets.get(key, ()), key=lambda k: -runs[k]["last"])[:RUNS_MAX]
        for k in keys:
            if k not in at:
                at[k] = len(names)
                names.append({"id": k[1], "tenant": k[0]})
        return {"n": len(sets[key]), "runs": [at[k] for k in keys]} if sets.get(key) else None

    def count(c, flags):
        c["calls"] += 1
        for name, bit in (("held", HELD), ("denied", DENIED), ("errors", ERROR)):
            c[name] += bool(flags & bit)
    buckets, agents, tools = [collections.Counter() for _ in starts], collections.defaultdict(collections.Counter), \
        collections.defaultdict(collections.Counter)
    total, before, latency = collections.Counter(), collections.Counter(), collections.defaultdict(list)
    # token counts: by model, by agent and model, by bucket and model, and by model in the previous range
    by_model, by_agent, by_day, before_model = (collections.defaultdict(lambda: [0, 0, 0, 0]) for _ in range(4))
    turns = collections.Counter()
    for k, s in mine.items():
        a = s["agent"] or "?"
        if s["first"] < until and s["last"] >= since:
            agents[a]["runs"] += 1
            agents[a]["last"] = max(agents[a]["last"], min(s["last"], until))
            sets["runs",].add(k)
            sets["runs", a].add(k)
            if not s["final"]:
                sets["open",].add(k)
        for t, tool, flags, ms in s["calls"]:
            if prev <= t < since:
                count(before, flags)
            if not since <= t < until:
                continue
            i = day(t)
            for c in (total, buckets[i], agents[a], tools[tool]):
                count(c, flags)
            buckets[i]["ok" if not flags else "err" if flags & ERROR else "den" if flags & DENIED else "hld"] += 1
            for what, bit in (("calls", 0), ("held", HELD), ("denied", DENIED), ("errors", ERROR)):
                if not bit or flags & bit:
                    for scope in ((), ("agent", a), ("tool", tool), ("day", i)):
                        sets[(what, *scope)].add(k)
            if ms is not None:
                latency[tool].append(ms)
        for t, model, *n in s["tokens"]:
            if prev <= t < since:
                _add(before_model[model], n)
            elif since <= t < until:
                _add(by_model[model], n)
                _add(by_agent[a, model], n)
                _add(by_day[day(t), model], n)
                turns["all"] += 1
                turns[a] += 1
                sets["model", model].add(k)
                sets["agent", a, "tokens"].add(k)
    # issues: a finding, or a held or denied call, grouped across runs by its rule; a findings run's findings are about
    # the run it analyzes, which must be counted
    seen, reasons = collections.defaultdict(list), {}
    for k, s in runs.items():
        about = (k[0], s["analyzes"]) if s["analyzes"] else k
        if about not in mine:
            continue
        for t, kind, rule, reason, tool in s["marks"]:
            seen[kind, rule].append((t, about, mine[about]["agent"] or "?", reason, "high" if kind == "denied" else "med"))
            reasons[rule] = reasons.get(rule) or reason
        for t, rule, sev, title in s["findings"]:
            seen["finding", rule].append((t, about, mine[about]["agent"] or "?", title or TITLES.get(rule, rule), sev))
    issues, rank = [], {"high": 0, "med": 1, "low": 2}
    for (kind, rule), xs in seen.items():
        here = [x for x in xs if since <= x[0] < until]
        if not here:
            continue
        for x in here:
            sets["issue", kind, rule].add(x[1])
        title = max(here)[3] or rule
        issues.append({"kind": kind, "rule": rule, "severity": min((x[4] for x in here), key=rank.get),
                       "title": title if kind == "finding" else f"{kind.capitalize()}: {title}",
                       "status": _status(min(x[0] for x in xs), [x[0] for x in xs], since, prev),
                       "n": len(here), "agents": sorted({x[2] for x in here})[:3], "runs": link("issue", kind, rule)})
    for x in issues:
        x["examples"] = x["runs"]["runs"][:3]
    issues.sort(key=lambda x: (rank[x["severity"]], -x["runs"]["n"], x["rule"]))
    pairs, agree, both = collections.defaultdict(lambda: [0, 0]), 0, 0
    for k, s in mine.items():
        for t, rules, same in s["pairs"]:
            if since <= t < until:
                both += 1
                agree += same
                sets["pairs",].add(k)
                if not same:
                    sets["disagree",].add(k)
                for r in rules:
                    pairs[r][0] += 1
                    pairs[r][1] += same
    usd = lambda model, n: _usd(prices, model, n)   # noqa: E731

    def priced(table):
        """(dollars of `table` ({model or (key, model): counts}) by its first key part, tokens of models with no price)."""
        out, unpriced = collections.Counter(), collections.Counter()
        for key, n in table.items():
            model, group = (key[-1], key[0]) if isinstance(key, tuple) else (key, None)
            c = usd(model, n)
            if c is None:
                unpriced[group] += sum(n)
            else:
                out[group] += c
        return out, unpriced
    cost, unpriced = priced(by_model)
    by_cost, by_unpriced = priced(by_agent)
    day_cost, _ = priced(by_day)
    prev_cost, _ = priced(before_model)
    rate = lambda m: prices and prices.rate(m)   # noqa: E731
    out = {
        "range": {"span": span, "since": since, "until": until, "previous": prev, "tz": tz_name, "starts": starts,
                  "bucket": "hour" if span == "24h" else "day"},
        "totals": {k: total[k] for k in ("calls", "held", "denied", "errors")},
        "previous": {k: before[k] for k in ("calls", "held", "denied", "errors")},
        "buckets": [{**{k: b[k] for k in ("calls", "held", "denied", "errors", "ok", "err", "den", "hld")},
                     "cost": day_cost[i] if prices else None, "runs": link("calls", "day", i)}
                    for i, b in enumerate(buckets)],
        "links": {k: link(k) for k in ("calls", "held", "denied", "errors")},
        "agents": sorted(({"agent": a, "runs": link("runs", a), "last": c["last"], "turns": turns[a],
                           "cost": by_cost[a] if prices else None, "unpriced": by_unpriced[a],
                           **{k: c[k] for k in ("calls", "held", "denied", "errors", "tokens")},
                           "links": {k: link(k, "agent", a) for k in ("calls", "held", "denied", "errors")}}
                          for a, c in agents.items() if a is not None and (c["runs"] or c["calls"])),
                         key=lambda x: (-x["calls"], x["agent"])),
        "tools": [], "models": [], "issues": issues[:ISSUES_MAX], "issues_total": len(issues),
        "approver": {"both": both, "agree": agree, "holds": total["held"],
                     "rules": [{"rule": r, "reason": reasons.get(r, ""), "n": n, "agree": g}
                               for r, (n, g) in sorted(pairs.items(), key=lambda x: (-x[1][0], x[0]))[:8]],
                     "disagree": link("disagree")},
        "tokens": {"turns": turns["all"], "total": sum(sum(n) for n in by_model.values()),
                   "cost": cost[None] if prices else None, "previous_cost": prev_cost[None] if prices else None,
                   "unpriced": unpriced[None], "link": link("model", "all")},
        "names": names}   # filled as the links below are made
    for tool, c in sorted(tools.items(), key=lambda x: (-x[1]["calls"], x[0])):
        ms = sorted(latency[tool])
        out["tools"].append({"tool": tool, **{k: c[k] for k in ("calls", "held", "denied", "errors")},
                             "p50": _pct(ms, .5), "p99": _pct(ms, .99), "timed": len(ms),
                             "links": {k: link(k, "tool", tool) for k in ("calls", "held", "denied", "errors")}})
    for model, n in sorted(by_model.items(), key=lambda x: -sum(x[1])):
        out["models"].append({"model": model, "tokens": n, "cost": usd(model, n), "priced": rate(model) is not None,
                              "runs": link("model", model)})
    out["tools_total"] = len(out["tools"])
    out["tools"] = out["tools"][:TOOLS_MAX]
    out["timed"] = sum(len(v) for v in latency.values())
    out["findings"] = sum(len([x for x in v if since <= x[0] < until]) for k, v in seen.items() if k[0] == "finding")
    inrange = [s for s in mine.values() if s["first"] < until and s["last"] >= since]
    out.update(runs=len(inrange), records=sum(s["count"] for s in inrange), open=link("open"))
    return out


class Page:
    """/api/fleet's answer: build() over the runs `feed` (a view.StoreFeed) has verified, with what it left out. Worked
    out again at most every `ttl` seconds for each range and time zone asked for, one request at a time."""

    def __init__(self, feed, prices=None, source=None, ttl=5):
        self.feed, self.prices, self.source, self.ttl = feed, prices, source, ttl
        self.lock, self.kept = threading.Lock(), {}

    def __call__(self, span="7d", tz="UTC"):
        span, tz = span if span in RANGES else "7d", _tz(tz)[1]
        with self.lock:
            at, body = self.kept.get((span, tz), (0.0, None))
            if body is None or time.monotonic() - at > self.ttl:
                runs, rest = self.feed.fleet_state()
                out = build(runs, time.time(), span, tz, self.prices)
                out["not_counted"] = rest
                out["seal"] = {"chain": rest.pop("chain"), "runs": out["runs"], "records": out["records"]}
                out["prices"] = self.prices and {"source": self.source, "currency": self.prices.currency,
                                                 "models": len(self.prices.models)}
                body = json.dumps(out, ensure_ascii=False)
                self.kept[span, tz] = time.monotonic(), body
            return body
