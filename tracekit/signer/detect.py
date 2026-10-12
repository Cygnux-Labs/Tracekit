"""Signer-side detection: the policy's sequences and limits, and the triggers that open incidents.

A pure function of signed records. The single writer feeds every record to `observe` as Tx.emit writes it, replay
feeds the log after the snapshot, and `tracekit policy backtest` feeds stored runs or bundles. Work per record is a few
dict lookups (no regex); the state grows with the policy's rules and the scopes they key on, not with calls, and is JSON
so `RecordLog._state()` snapshots it.

The names of a decision are its rule ids (the union of both class readings: `detect.rule_ids` when it differs from
`rule_ids`), each rule's `label`, and `*`; a call whose class is unknown matches every step and limit (fail closed). A
call counts when it was allowed (allow, flag) or, for ask, once the approval of that decision is consumed; never when
denied. One call advances each partial sequence by one step, or through consecutive steps its own names match (each
name once; never through `*` or an unknown class). A sum limit reads the amount and currency the signer put in
`detect.sums`. Windows are fixed: one starts at the first call counted and runs `window` seconds of the records' `ts`
(the signer's clock).

Every incident is written in shadow mode (`incident.opened{mode: shadow}`, no actions, `would` the configured action).
Only opened incidents count toward the caps; an open incident is updated at most once per window.
"""
import datetime
import json
import secrets
import zipfile

from tracekit.format.canon import MAX_SAFE_INT
from tracekit.policy2.compile import DETECT, SECTIONS

RUN_CAP = 100      # incidents a run opens per trigger; the next one is an incident.capped summary instead
TENANT_CAP = 60    # incidents a tenant opens per minute
RUN_SHARE = 20     # of which one run may open
IDLE_S = 3600      # a scope with no record for this long (or the longest window, if longer) starts over
UPDATE_S = 60      # an open incident of a trigger without a window is updated at most once a minute
NOT_COUNTED = {"TK-ARGS-INVALID", "TK-OVERSIZE"}   # denies that say nothing about the agent's intent
SUM_UNREADABLE = "TK-LIMIT-SUM"   # a call a sum limit counts, without an amount and currency it can read: ask


class Plain:
    """Tx's set/pop on plain dicts, for replay and backtests."""
    set = staticmethod(dict.__setitem__)
    pop = staticmethod(dict.pop)


def new(policy_hash=None, until=None):
    """Empty state for the policy `policy_hash` (a snapshot's state is reused only under the same policy); `until`: a
    wall-clock time before which decisions say `state: unavailable` (a restart that could not rebuild the state: after
    the longest window nothing before the restart counts any more)."""
    return {"policy": policy_hash, "until": until or 0, "runs": {}, "scopes": {}, "minute": {}}


def run_entry(session, owner, principal):
    """A run's state: the ids of its scopes, the asks waiting for an approval, and its incident counts."""
    return {"session": session, "owner": owner, "principal": principal, "pending": {}, "n": {}, "capped": {},
            "minute": [0, 0, False]}


def _t(ts):
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


class Detector:
    def __init__(self, engine):
        """`engine`: the policy2 Engine whose policy holds the sequences, limits and respond entries."""
        pol, self.engine = engine.policy, engine
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.label = {r["id"]: r["label"] for r in rules if "label" in r}
        self.untrusted = {r["id"] for r in rules if "from" in r}
        self.deny = {r["id"] for r in pol.get("deny", [])} | ({"TK-UNKNOWN-TOOL"} if pol.get("unknown_tools") == "deny"
                                                               else set())
        self.sequences, self.limits = pol.get("sequences", []), pol.get("limits", [])
        self.respond = {r["trigger"]: r for r in pol.get("respond", [])}
        self.counts = bool(self.sequences or self.limits)   # decisions carry `detect`
        # an open incident is updated at most once per its trigger's window
        self.every = {x["id"]: x["window"] for x in self.sequences + self.limits}
        if "denied_calls" in self.respond:
            self.every["denied_calls"] = self.respond["denied_calls"]["window"]
        self.window = max([0, *self.every.values()])
        self.idle = max(self.window, IDLE_S)

    @classmethod
    def of(cls, engine):
        """A Detector when the policy has anything to detect, else None."""
        return cls(engine) if any(engine.policy.get(k) for k in DETECT) else None

    def names(self, ids):
        return set(ids) | {self.label[i] for i in ids if i in self.label} | {"*"}

    def prepare(self, tool, args, ids):
        """({sums} for the decision's `detect`, unreadable) of a call with `args` and rule ids `ids` (both readings),
        off the writer. Unreadable: a sum limit whose respond mode isn't off counts a call of a known class, and its
        amount is not a non-negative integer or its currency not a three-letter code (case and spaces aside)."""
        names, unknown, sums, bad = self.names(ids), self.engine.tool_class(tool) == "unknown", {}, False
        for lim in self.limits:
            if "sum" not in lim or not (unknown or lim["match"] in names):
                continue
            amount = args.get(lim["sum"]["field"]) if isinstance(args, dict) else None
            cur = args.get(lim["sum"]["currency_field"]) if isinstance(args, dict) else None
            cur = cur.strip().upper() if isinstance(cur, str) else ""
            if (isinstance(amount, int) and not isinstance(amount, bool) and amount >= 0
                    and len(cur) == 3 and cur.isascii() and cur.isalpha()):
                sums[lim["id"]] = [amount, cur]
            elif not unknown and self.respond.get(lim["id"], {}).get("mode", "shadow") != "off":
                bad = True
        return ({"sums": sums} if sums else {}), bad

    def prune(self, det, now):
        """Drop the scopes no window reaches any more: run before a snapshot. The next record of such a scope would
        reset it anyway (`_scope`), so this only frees memory."""
        # lean: idle session, owner and principal scopes stay in memory until the next snapshot (every
        # SNAPSHOT_RECORDS records); prune on a timer if a signer sees very many owners between snapshots
        for k in [k for k, st in det["scopes"].items() if now - _t(st["t"]) > self.idle]:
            del det["scopes"][k]

    def _scope(self, tx, det, e, run, kind):
        """(state key, record `scope`, state) of record `e`'s scope `kind`. A run whose principal is not attested is
        keyed by its owner; a run the state does not know by itself. A scope idle past `idle` starts over, open
        incidents included, by the records' clock."""
        if kind == "principal" and not (run and run["principal"]):
            kind = "owner"
        if run is None:
            kind = "run"
        val = (e["run_id"] if kind == "run" else run[kind])[:256]
        key = f"{kind}\0{e['tenant']}\0{val}"
        old = det["scopes"].get(key)
        if old is None or _t(e["ts"]) - _t(old["t"]) > self.idle:
            tx.set(det["scopes"], key, {"seq": {}, "lim": {}, "den": None, "open": {}, "t": e["ts"]})
        st = det["scopes"][key]
        tx.set(st, "t", e["ts"])
        return key, {"kind": kind, "id": val}, st

    def observe(self, tx, det, e):
        """Index record `e` into state `det`; returns (the decision's `detect` field or None, [(type, data)] of the
        incident records to write right after it, in its run). `tx`: set(d, k, v) and pop(d, k), undoable on the
        writer, Plain elsewhere."""
        typ, d, rk = e["type"], e["data"], f"{e['tenant']}\0{e['run_id']}"
        run, t, fired, view = det["runs"].get(rk), _t(e["ts"]), [], None
        if typ == "run.registered":
            owner = "{scheme}:{subject}".format(**d["identity"])
            tx.set(det["runs"], rk, run_entry(d.get("session", e["run_id"]), owner,
                                              e.get("principal") if e.get("principal_attested") else None))
        elif typ == "run.final":
            for k, top in ((rk, det["runs"]), ("run\0" + rk, det["scopes"])):
                if k in top:
                    tx.pop(top, k)
        elif typ in ("incident.opened", "incident.capped"):
            self._count_incident(tx, det, e, run, t)
        elif typ == "policy.decision":
            inp = d.get("detect", {})
            ids, cite = inp.get("rule_ids", d["rule_ids"]), [e["run_id"], e["run_seq"]]
            names, unknown = self.names(ids), self.engine.tool_class(d["tool"]) == "unknown"
            if d.get("policy_hash") != self.engine.policy_hash:   # its rule ids are another policy's
                tx.set(det, "until", max(det["until"], t + self.window))
            view = {**inp, "sequences": [], "limits": [],
                    "state": "unavailable" if t < det["until"] or run is None else "complete"}
            if run:   # an ask waits for its approval; a later decision of the call replaces one never asked for
                k = f"call\0{e['tool_call_id']}"
                if d["decision"] == "ask":
                    tx.set(run["pending"], k, [d.get("decision_id"), sorted(names), unknown, inp.get("sums", {}),
                                               "rule_ids" in inp])
                elif k in run["pending"]:
                    tx.pop(run["pending"], k)
            if d["decision"] in ("allow", "flag"):   # detect.rule_ids: a client's class hint read the call too
                self._count(tx, det, e, run, (names, unknown, inp.get("sums", {}), "rule_ids" in inp), cite, fired,
                            view)
            elif d["decision"] == "deny":
                self._denied(tx, det, e, run, t, cite, fired)
            if (d["decision"] != "allow" and self._on("provenance") and set(d["rule_ids"]) & self.untrusted
                    and d.get("provenance") and d.get("provenance_state") == "complete"):
                fired.append(("provenance", d["rule_ids"], *self._scope(tx, det, e, run, "run")[:2], [cite]))
            if not self.counts:
                view = None
        elif typ == "approval.request" and run:   # the approval is of the decision it names: the call's latest
            # lean: an ask never sent for approval keeps its entry until the call is decided again or the run ends
            k = f"call\0{e.get('tool_call_id')}"
            p = run["pending"].get(k)
            if p and p[0] == d["decision_id"]:
                tx.pop(run["pending"], k)
                tx.set(run["pending"], d["approval_id"], p[1:])
        elif typ in ("approval.consumed", "approval.abandoned", "approval.expired") and run:
            p = run["pending"].get(d["approval_id"])
            if p:
                tx.pop(run["pending"], d["approval_id"])
                if typ == "approval.consumed":
                    names, unknown, sums, *hinted = p   # an entry from before `hinted` has none
                    self._count(tx, det, e, run, (set(names), unknown, sums, any(hinted)), [e["run_id"], e["run_seq"]],
                                fired, None)
        else:
            trigger = {"trace.tamper": "tamper", "refusal.summary": "refusal_burst"}.get(typ)
            if typ == "capture.gap" and d.get("kind") in ("executed_against_policy", "class_mismatch"):
                trigger = d["kind"]
            if trigger and self._on(trigger) and (trigger != "refusal_burst" or d["count"] > self.respond[trigger]["max"]):
                fired.append((trigger, [], *self._scope(tx, det, e, run, "run")[:2], [[e["run_id"], e["run_seq"]]]))
        return view, self._incidents(tx, det, e, run, t, fired)

    def _on(self, trigger):
        return self.respond.get(trigger, {}).get("mode", "off") != "off"

    def _count(self, tx, det, e, run, call, cite, fired, view):
        """Count an allowed call (names, unknown, sums, hinted) for every sequence step and limit it matches. `unless`
        exempts only a call the policy's own reading names: a client's class hint (`hinted`) adds names to count, never
        to exempt."""
        names, unknown, sums, hinted = call
        own = set() if unknown else names - {"*"}   # the names that take a call through consecutive steps
        for s in self.sequences:
            if not unknown and not hinted and names & set(s.get("unless", ())):
                continue
            steps, last = s["steps"], len(s["steps"]) - 1
            if not (unknown or names & set(steps)):
                continue
            key, scope, st = self._scope(tx, det, e, run, s.get("scope", "run"))
            old = st["seq"].get(s["id"], [None] * last)   # old[k]: [start ts, cites] of k+1 steps seen
            new, reached, done = list(old), 0, None
            for j in range(last + 1):   # each partial this call extends (j = 0: a new one), from the state before it
                if not (unknown or steps[j] in names):
                    continue
                prev = old[j - 1] if j else None
                if j and (prev is None or _t(e["ts"]) - _t(prev[0]) > s["window"]):
                    continue
                start, cites = (prev[0], prev[1] + [cite]) if j else (e["ts"], [cite])
                k, used = j, set()
                while True:
                    reached = max(reached, k + 1)
                    if k == last:
                        if done is None or _t(start) >= _t(done[0]):
                            done = [start, cites]
                        break
                    if new[k] is None or _t(start) >= _t(new[k][0]):
                        new[k] = [start, cites]
                    used.add(steps[k])
                    if steps[k] not in own or steps[k + 1] not in own or steps[k + 1] in used:
                        break
                    k += 1
            if new != old:
                tx.set(st["seq"], s["id"], new)
            if done:
                fired.append(("sequence", [s["id"]], key, scope, done[1]))
            if view is not None and reached:
                view["sequences"].append({"id": s["id"], "step": reached})
        for lim in self.limits:
            if not (unknown or lim["match"] in names) or "sum" in lim and lim["id"] not in sums:
                continue
            key, scope, st = self._scope(tx, det, e, run, lim.get("scope", "run"))
            start, val = st["lim"].get(lim["id"], (None, None))
            # lean: fixed windows, so a burst straddling two can reach 2x max unseen; keep per-second buckets if
            # limits must be exact
            if start is None or _t(e["ts"]) - _t(start) > lim["window"]:
                start, val = e["ts"], {} if "sum" in lim else 0
            if "sum" in lim:
                amount, cur = sums[lim["id"]]
                # saturated: a total past what a record can carry would refuse every later decide in the scope
                before, val = val.get(cur, 0), {**val, cur: min(val.get(cur, 0) + amount, MAX_SAFE_INT)}
                after = val[cur]
            else:
                before, val = val, val + 1
                after = val
            tx.set(st["lim"], lim["id"], [start, val])
            if view is not None:
                view["limits"].append({"id": lim["id"], "count": after, "window_start": start})
            if before <= lim["max"] < after:
                fired.append(("limit", [lim["id"]], key, scope, [cite]))

    def _denied(self, tx, det, e, run, t, cite, fired):
        """denied_calls: more than `max` distinct (tool_call_id, attempt) denied in the window, leaving out
        nondeterministic denies and those only TK-ARGS-INVALID or TK-OVERSIZE caused (NOT_COUNTED: nothing of
        intent)."""
        r, d = self.respond.get("denied_calls"), e["data"]
        ids = set(d["rule_ids"])
        if not self._on("denied_calls") or d.get("nondeterministic") or ids & NOT_COUNTED and not ids & self.deny:
            return
        key, scope, st = self._scope(tx, det, e, run, r.get("scope", "run"))
        if st["den"] is None or t - _t(st["den"][0]) > r["window"]:
            tx.set(st, "den", [e["ts"], {}])
        seen, call = st["den"][1], f"{e['tool_call_id']}\0{e.get('attempt', 0)}"
        if call in seen or len(seen) > r["max"]:   # past max the incident is open: no need to remember more calls
            return
        tx.set(seen, call, 1)
        if len(seen) > r["max"]:
            fired.append(("denied_calls", d["rule_ids"], key, scope, [cite]))

    def _incidents(self, tx, det, e, run, t, fired):
        """The incident records of `fired` triggers: opened, or updated (at most once per window) when its (scope,
        trigger, rule) is open. Opened incidents count toward the caps (per run and trigger; per tenant a minute, and a
        run's share of that); past one, a single incident.capped instead."""
        if not fired:
            return []
        out, minute = [], int(t // 60)
        m = det["minute"].get(e["tenant"])
        n_ten = m[1] if m and m[0] == minute else 0
        n_run, capped = (dict(run["n"]), dict(run["capped"])) if run else ({}, {})
        n_mine, shared = run["minute"][1:] if run and run["minute"][0] == minute else (0, False)
        for trigger, rule_ids, key, scope, cites in fired:
            rule = rule_ids[0] if trigger in ("sequence", "limit") else trigger
            r = self.respond.get(rule, {"mode": "shadow"})
            if r["mode"] == "off":
                continue
            cites = [{"run_id": a, "run_seq": b} for a, b in cites]
            st, k = det["scopes"][key], f"{trigger}\0{rule}"
            if k in st["open"]:
                inc, last = st["open"][k]
                if t - _t(last) >= self.every.get(rule, UPDATE_S):
                    tx.set(st["open"], k, [inc, e["ts"]])
                    out.append(("incident.updated", {"incident_id": inc, "cites": cites}))
                continue
            if run and n_run.get(trigger, 0) >= RUN_CAP:
                if capped.get(trigger):
                    continue
                capped[trigger] = True
                cap, most, why = "run", RUN_CAP, f"this run opened {RUN_CAP} {trigger} incidents"
            elif n_ten >= TENANT_CAP or n_mine >= RUN_SHARE:
                if shared:
                    continue
                shared = True
                cap, most, why = ("tenant", TENANT_CAP, f"the tenant opened {TENANT_CAP} incidents this minute") \
                    if n_ten >= TENANT_CAP else ("tenant", RUN_SHARE, f"this run opened its share ({RUN_SHARE}) of "
                                                                      f"the tenant's {TENANT_CAP} incidents a minute")
            else:
                n_run[trigger], n_ten, n_mine = n_run.get(trigger, 0) + 1, n_ten + 1, n_mine + 1
                out.append(("incident.opened", {"incident_id": "inc-" + secrets.token_hex(16), "trigger": trigger,
                                                "rule_ids": rule_ids, "scope": scope, "cites": cites, "mode": "shadow",
                                                "actions": [], "would": [r["action"]] if "action" in r else []}))
                continue
            out.append(("incident.capped", {"cap": cap, "max": most, "trigger": trigger,
                                            "reason": f"{why}: later ones are not written; read the run's decisions "
                                                      "(their detect field) or backtest the policy (tracekit policy "
                                                      "backtest) to see them"}))
        return out

    def _count_incident(self, tx, det, e, run, t):
        d, minute = e["data"], int(t // 60)
        if e["type"] == "incident.capped":
            if run and d["cap"] == "run":
                tx.set(run["capped"], d["trigger"], True)
            elif run:
                tx.set(run, "minute", [minute, run["minute"][1] if run["minute"][0] == minute else 0, True])
            return
        m = det["minute"].get(e["tenant"])
        tx.set(det["minute"], e["tenant"], [minute, (m[1] if m and m[0] == minute else 0) + 1])
        if run:
            tx.set(run["n"], d["trigger"], run["n"].get(d["trigger"], 0) + 1)
            mine = run["minute"]
            tx.set(run, "minute", [minute, mine[1] + 1, mine[2]] if mine[0] == minute else [minute, 1, False])
        s = d["scope"]
        st = det["scopes"].get(f"{s['kind']}\0{e['tenant']}\0{s['id']}")
        rule = d["rule_ids"][0] if d["trigger"] in ("sequence", "limit") else d["trigger"]
        if st is not None:
            tx.set(st["open"], f"{d['trigger']}\0{rule}", [d["incident_id"], e["ts"]])


def _bundle_events(path):
    with zipfile.ZipFile(path) as z:
        events = [json.loads(line)["event"] for n in z.namelist() if n.startswith("runs/")
                  for line in z.read(n).splitlines() if line.strip()]
    return sorted(events, key=lambda e: e["seq"])


def backtest(engine, store=None, bundles=()):
    """([(event type, tenant, run_id, data)] of the incident records `engine`'s policy would write over the records
    of a file store (its directory) or of bundles, each bundle on its own; the number of decisions made under another
    policy, whose recorded rule ids are that policy's)."""
    det = Detector.of(engine)
    if det is None:
        return [], 0
    sources = []
    if store:
        from tracekit.storage.file import FileReader
        r = FileReader(store)
        sources.append([x["event"] for x in r.iter_range(0, r.tree.size)])
    sources += [_bundle_events(b) for b in bundles]
    out, other = [], 0
    for events in sources:
        state = new(engine.policy_hash)
        for e in events:
            if e["type"].startswith("incident."):   # the store's own incidents, under its policy
                continue
            other += e["type"] == "policy.decision" and e["data"].get("policy_hash") != engine.policy_hash
            _, incidents = det.observe(Plain, state, e)
            for typ, data in incidents:
                out.append((typ, e["tenant"], e["run_id"], data))
                det.observe(Plain, state, {**e, "type": typ, "data": data})
    return out, other
