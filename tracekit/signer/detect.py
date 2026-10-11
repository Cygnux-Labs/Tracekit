"""Signer-side detection: the policy's sequences and limits, and the triggers that open incidents.

A pure function of signed records. The single writer feeds every record to `observe` as Tx.emit writes it, replay
feeds the log after the snapshot, and `tracekit policy backtest` feeds stored runs or bundles. Work per record is a few
dict lookups (no regex); the state grows with the policy's rules and the scopes they key on, not with calls, and is JSON
so `RecordLog._state()` snapshots it.

The names of a decision are its rule ids (the union of both class readings: `detect.rule_ids` when it differs from
`rule_ids`), each rule's `label`, and `*`; a call whose class is unknown matches every step and limit (fail closed). A
call counts when it was allowed (allow, flag) or, for ask, once its approval is consumed; never when denied. A sum limit
reads the amount and currency the signer put in `detect.sums`. Windows are fixed: one starts at the first call counted
and runs `window` seconds of the records' `ts` (the signer's clock).

Every incident is written in shadow mode (`incident.opened{mode: shadow}`, no actions, `would` the configured action).
"""
import datetime
import json
import secrets
import zipfile

from tracekit.policy2.compile import DETECT, SECTIONS

RUN_CAP = 100      # incident records per run; the next one is an incident.capped summary instead
TENANT_CAP = 60    # incident records per tenant per minute
NOT_COUNTED = {"TK-ARGS-INVALID", "TK-OVERSIZE"}   # denies that say nothing about the agent's intent
SUM_UNREADABLE = "TK-LIMIT-SUM"   # a call a sum limit counts, without an integer amount and a currency: ask


class Plain:
    """Tx's set/pop on plain dicts, for replay and backtests."""
    set = staticmethod(dict.__setitem__)
    pop = staticmethod(dict.pop)


def new(until=None):
    """Empty state; `until`: a wall-clock time before which decisions say `state: unavailable` (a restart that could
    not rebuild the state: after the longest window nothing before the restart counts any more)."""
    return {"until": until or 0, "runs": {}, "scopes": {}, "minute": {}}


def _t(ts):
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


class Detector:
    def __init__(self, engine):
        """`engine`: the policy2 Engine whose policy holds the sequences, limits and respond entries."""
        pol, self.engine = engine.policy, engine
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.label = {r["id"]: r["label"] for r in rules if "label" in r}
        self.untrusted = {r["id"] for r in rules if "from" in r}
        self.sequences, self.limits = pol.get("sequences", []), pol.get("limits", [])
        self.respond = {r["trigger"]: r for r in pol.get("respond", [])}
        self.counts = bool(self.sequences or self.limits)   # decisions carry `detect`
        self.window = max([x["window"] for x in self.sequences + self.limits]
                          + [r.get("window", 0) for r in self.respond.values()])

    @classmethod
    def of(cls, engine):
        """A Detector when the policy has anything to detect, else None."""
        return cls(engine) if any(engine.policy.get(k) for k in DETECT) else None

    def names(self, ids):
        return set(ids) | {self.label[i] for i in ids if i in self.label} | {"*"}

    def prepare(self, tool, args, ids):
        """({sums} for the decision's `detect`, unreadable) of a call with `args` and rule ids `ids` (both readings),
        off the writer. Unreadable: a sum limit counts the call and its amount is not an integer or it has no currency."""
        names, unknown, sums, bad = self.names(ids), self.engine.tool_class(tool) == "unknown", {}, False
        for lim in self.limits:
            if "sum" in lim and (unknown or lim["match"] in names):
                amount = args.get(lim["sum"]["field"]) if isinstance(args, dict) else None
                cur = args.get(lim["sum"]["currency_field"]) if isinstance(args, dict) else None
                if isinstance(amount, int) and not isinstance(amount, bool) and isinstance(cur, str) and cur:
                    sums[lim["id"]] = [amount, cur[:16]]
                else:
                    bad = True
        return ({"sums": sums} if sums else {}), bad

    def prune(self, det, now):
        """Drop the scopes no window reaches any more (with their open incidents): run before a snapshot."""
        # lean: idle session, owner and principal scopes stay in memory until the next snapshot (every
        # SNAPSHOT_RECORDS records); prune on a timer if a signer sees very many owners between snapshots
        for k in [k for k, st in det["scopes"].items() if now - _t(st["t"]) > self.window]:
            del det["scopes"][k]

    def _scope(self, tx, det, e, run, kind):
        """(state key, record `scope`, state) of record `e`'s scope `kind`. A run whose principal is not attested is
        keyed by its owner; a run the state does not know (registered before a restart that lost it) by itself."""
        if kind == "principal" and not (run and run["principal"]):
            kind = "owner"
        if run is None:
            kind = "run"
        val = (e["run_id"] if kind == "run" else run[kind])[:256]
        key = f"{kind}\0{e['tenant']}\0{val}"
        if key not in det["scopes"]:
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
            tx.set(det["runs"], rk, {"session": d.get("session", e["run_id"]),
                                     "owner": "{scheme}:{subject}".format(**d["identity"]),
                                     "principal": e.get("principal") if e.get("principal_attested") else None,
                                     "n": 0, "capped": False, "pending": {}})
        elif typ == "run.final":
            for k, top in ((rk, det["runs"]), ("run\0" + rk, det["scopes"])):
                if k in top:
                    tx.pop(top, k)
        elif typ in ("incident.opened", "incident.updated", "incident.capped"):
            self._count_incident(tx, det, e, run, t)
        elif typ == "policy.decision":
            inp = d.get("detect", {})
            ids, cite = inp.get("rule_ids", d["rule_ids"]), [e["run_id"], e["run_seq"]]
            names, unknown = self.names(ids), self.engine.tool_class(d["tool"]) == "unknown"
            view = {**inp, "sequences": [], "limits": [], "state": "unavailable" if t < det["until"] else "complete"}
            if d["decision"] in ("allow", "flag"):
                self._count(tx, det, e, run, (names, unknown, inp.get("sums", {})), cite, fired, view)
            elif d["decision"] == "ask" and run:   # counts once its approval is consumed
                tx.set(run["pending"], f"{e['tool_call_id']}\0{e.get('attempt', 0)}",
                       [sorted(names), unknown, inp.get("sums", {})])
            elif d["decision"] == "deny":
                self._denied(tx, det, e, run, t, cite, fired)
            if (d["decision"] != "allow" and self._on("provenance") and set(d["rule_ids"]) & self.untrusted
                    and d.get("provenance") and d.get("provenance_state") == "complete"):
                fired.append(("provenance", d["rule_ids"], *self._scope(tx, det, e, run, "run")[:2], [cite]))
            if not self.counts:
                view = None
        elif typ in ("approval.consumed", "approval.abandoned") and run:
            # lean: an approval that expires leaves its pending entry until the run ends (approval.expired names no
            # call); key them by approval_id if runs hold many expired approvals
            k = f"{e.get('tool_call_id')}\0{e.get('attempt', 0)}"
            if k in run["pending"]:
                names, unknown, sums = run["pending"][k]
                tx.pop(run["pending"], k)
                if typ == "approval.consumed":
                    self._count(tx, det, e, run, (set(names), unknown, sums), [e["run_id"], e["run_seq"]], fired, None)
        else:
            trigger = {"trace.tamper": "tamper", "refusal.summary": "refusal_burst"}.get(typ)
            if typ == "capture.gap" and d.get("kind") in ("executed_against_policy", "class_mismatch"):
                trigger = d["kind"]
            if trigger and self._on(trigger) and (trigger != "refusal_burst" or d["count"] > self.respond[trigger]["max"]):
                fired.append((trigger, [], *self._scope(tx, det, e, run, "run")[:2], [[e["run_id"], e["run_seq"]]]))
        return view, self._incidents(det, e, run, t, fired)

    def _on(self, trigger):
        return self.respond.get(trigger, {}).get("mode", "off") != "off"

    def _count(self, tx, det, e, run, call, cite, fired, view):
        """Count an allowed call (names, unknown, sums) for every sequence step and limit it matches."""
        names, unknown, sums = call
        for s in self.sequences:
            if not unknown and names & set(s.get("unless", ())):
                continue
            steps, reached = s["steps"], 0
            if not (unknown or names & set(steps)):
                continue
            key, scope, st = self._scope(tx, det, e, run, s.get("scope", "run"))
            old = st["seq"].get(s["id"], [None] * (len(steps) - 1))   # old[k]: [start ts, cites] of k+1 steps seen
            new = list(old)
            for k in range(len(steps) - 1, -1, -1):   # from the last step, so one call advances each partial once
                if not (unknown or steps[k] in names):
                    continue
                prev = old[k - 1] if k else None
                if k and (prev is None or _t(e["ts"]) - _t(prev[0]) > s["window"]):
                    continue
                cand = [prev[0], prev[1] + [cite]] if k else [e["ts"], [cite]]
                reached = max(reached, k + 1)
                if k == len(steps) - 1:
                    fired.append(("sequence", [s["id"]], key, scope, cand[1]))
                elif new[k] is None or _t(cand[0]) >= _t(new[k][0]):
                    new[k] = cand
            if new != old:
                tx.set(st["seq"], s["id"], new)
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
                before, val = val.get(cur, 0), {**val, cur: val.get(cur, 0) + amount}
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
        nondeterministic denies and those that say nothing of intent (NOT_COUNTED)."""
        r, d = self.respond.get("denied_calls"), e["data"]
        if not self._on("denied_calls") or d.get("nondeterministic") or NOT_COUNTED & set(d["rule_ids"]):
            return
        key, scope, st = self._scope(tx, det, e, run, r.get("scope", "run"))
        start, seen = st["den"] or (None, [])
        if start is None or t - _t(start) > r["window"]:
            start, seen = e["ts"], []
        call = f"{e['tool_call_id']}\0{e.get('attempt', 0)}"
        if call in seen or len(seen) > r["max"]:   # past max the incident is open: no need to remember more calls
            return
        tx.set(st, "den", [start, seen + [call]])
        if len(seen) + 1 > r["max"]:
            fired.append(("denied_calls", d["rule_ids"], key, scope, [cite]))

    def _incidents(self, det, e, run, t, fired):
        """The incident records of `fired` triggers: opened, or updated when its (scope, trigger, rule) is open;
        past a cap one incident.capped instead."""
        out, n_run, minute = [], run["n"] if run else 0, det["minute"].get(e["tenant"], [None, 0, False])
        n_ten = minute[1] if minute[0] == int(t // 60) else 0
        capped = {"run": bool(run and run["capped"]), "tenant": minute[0] == int(t // 60) and minute[2]}
        for trigger, rule_ids, key, scope, cites in fired:
            rule = rule_ids[0] if trigger in ("sequence", "limit") else trigger
            r = self.respond.get(rule, {"mode": "shadow"})
            if r["mode"] == "off":
                continue
            over = "run" if run and n_run >= RUN_CAP else "tenant" if n_ten >= TENANT_CAP else None
            if over:
                if not capped[over]:
                    capped[over] = True
                    out.append(("incident.capped", {"cap": over, "max": RUN_CAP if over == "run" else TENANT_CAP,
                                                    "reason": f"more incidents than the {over} cap: later ones are not "
                                                              "written; read this run's decisions and backtest the "
                                                              "policy (tracekit policy backtest) to see them"}))
                continue
            n_run, n_ten = n_run + 1, n_ten + 1
            cites = [{"run_id": a[:256], "run_seq": b} for a, b in cites]
            open_id = det["scopes"][key]["open"].get(f"{trigger}\0{rule}")
            if open_id:
                out.append(("incident.updated", {"incident_id": open_id, "cites": cites}))
            else:
                out.append(("incident.opened", {"incident_id": "inc-" + secrets.token_hex(16), "trigger": trigger,
                                                "rule_ids": rule_ids, "scope": scope, "cites": cites, "mode": "shadow",
                                                "actions": [], "would": [r["action"]] if "action" in r else []}))
        return out

    def _count_incident(self, tx, det, e, run, t):
        d, minute = e["data"], int(t // 60)
        m = det["minute"].get(e["tenant"])
        if m is None or m[0] != minute:
            m = [minute, 0, False]
        if e["type"] == "incident.capped":
            if d["cap"] == "run" and run:
                tx.set(run, "capped", True)
            tx.set(det["minute"], e["tenant"], [m[0], m[1], m[2] or d["cap"] == "tenant"])
            return
        if run:
            tx.set(run, "n", run["n"] + 1)
        tx.set(det["minute"], e["tenant"], [m[0], m[1] + 1, m[2]])
        if e["type"] == "incident.opened":
            s = d["scope"]
            st = det["scopes"].get(f"{s['kind']}\0{e['tenant']}\0{s['id']}")
            rule = d["rule_ids"][0] if d["trigger"] in ("sequence", "limit") else d["trigger"]
            if st is not None:
                tx.set(st["open"], f"{d['trigger']}\0{rule}", d["incident_id"])


def _bundle_events(path):
    with zipfile.ZipFile(path) as z:
        events = [json.loads(line)["event"] for n in z.namelist() if n.startswith("runs/")
                  for line in z.read(n).splitlines() if line.strip()]
    return sorted(events, key=lambda e: e["seq"])


def backtest(engine, store=None, bundles=()):
    """[(event type, tenant, run_id, data)] of the incident records `engine`'s policy would write over the records
    of a file store (its directory) or of bundles, each bundle on its own."""
    det = Detector.of(engine)
    if det is None:
        return []
    sources = []
    if store:
        from tracekit.storage.file import FileReader
        r = FileReader(store)
        sources.append([x["event"] for x in r.iter_range(0, r.tree.size)])
    sources += [_bundle_events(b) for b in bundles]
    out = []
    for events in sources:
        state = new()
        for e in events:
            if e["type"].startswith("incident."):   # the store's own incidents, under its policy
                continue
            _, incidents = det.observe(Plain, state, e)
            for typ, data in incidents:
                out.append((typ, e["tenant"], e["run_id"], data))
                det.observe(Plain, state, {**e, "type": typ, "data": data})
    return out
