"""TK-X212: whether a boxed agent's own account of its calls and what Tracekit Box saw cross the box's doors agree
(docs/findings.md). One call from findings_v2.analyze, over a box run (its run.registered carries the signer-written
ext.box label and no parent_run: the Box daemon's own run) and the runs of its agent channel (each a child of it with
the same label: what the agent's hooks inside the box sent, which the agent can skip or forge).

Box's records (Tracekit Box's internal/daemon and internal/tracekit): each connection out of the box is a WebFetch
decision of the box run, {url: "<scheme>://<host>:<port>"}, made before it is dialled, with an ok result when it went
through (refused: the decision is deny, or its result isn't ok); each file of the box's patch written back at `tkbox
apply` is a Write decision, {file_path: <apply dir>/<path>, patch_sha256, ...}; a command Box started from the host is a
Bash decision; tkbox.box records name the workspace copied into the box's /workspace, tkbox.model.call records the
model calls on an inspected connection, tkbox.egress the refusals Box made itself (sent later, with no time of their
own) and tkbox.gap the records Box lost. All runs' records carry the signer's clock. A call's window runs from its
decision to its result + grace (findings_effects' --effect-grace; no skew: one clock).

(a) high, a door event no call of the agent's explains:
  - a connection decided in the window of a call whose tool may connect (a shell, an MCP or unknown tool, a fetch tool
    of that host) is explained. Not checkable: one to a model API host (model_host: the harness's own model calls),
    while no agent run was open (no_agent_run), when only a call with no result could explain it (call_unfinished), in
    the window of a command Box started during the agent's runs (host_command), after a shell call of an open run that
    may have left a process running (background: run_in_background, `&`, nohup, setsid, disown; no_content when its
    command isn't known).
  - a file of the box's patch is explained by a write call of the agent's on that path (/workspace/<path>) that did
    not fail. Not checkable: the apply directory isn't the box's workspace (apply_dir); a write call's path isn't known
    (no_content); a shell, MCP or other call that writes files without naming them ran (shell_ran); a command Box
    started ran, other than one the agent ran in (host_command).
(b) medium, a fetch call of the agent's that returned ok with no connection to its URL's host from the box's start to
    its result + grace. Not checkable: an earlier connection to that host (reused: a connection kept open, or the tool's
    cache, may have served it); Box refused a connection to that host itself after the call began, or lost such a
    refusal (box_refusal); the call's URL, or the host of a door record up to its window's end, isn't known (no_url).
(c) high, a fetch call of the agent's that returned ok while Box's door refused every connection to its host in its
    window. Not checkable: one of them has no recorded outcome (no_outcome).
A box run with no agent channel run in what was analysed is no_agent_runs for each door event; an agent channel's run
is agent_run for each call: its box run holds the doors.
"""
import ipaddress
import posixpath
import urllib.parse

from .findings import WRITE_TOOLS
from .findings_effects import ALL, FETCH, GRACE_S, KINDS, MAX_CITES, _kinds, _t, _under
from .findings_text import _Lexer
from .signer.reconcile import PROVIDER_HOSTS

RULE = "TK-X212"
CHECKS = (RULE,)
SEVERITIES = {RULE: "high"}
WORKSPACE = "/workspace"   # where Box mounts the workspace copy inside a box (its proto.DefaultWorkspacePath)
SHELLS = frozenset(t for t, k in KINDS.items() if k == ALL)
BACKGROUND = frozenset(("nohup", "setsid", "disown"))
WHY = {RULE: ("the agent's own records of its calls (sent from inside the box, where it can skip or forge them) and "
              "the box's door records (decided on the host, outside its reach) disagree: the agent did something it "
              "didn't record, or recorded something the door didn't see",
              "trust the door records over the agent's; read the agent's calls around the cited door record "
              "(`tracekit view`), and review what the box wrote before you apply or run it")}
REASONS = {
    "no_agent_runs": ("no run of the box's agent channel is in what was analysed: the box ran without one, or its runs "
                      "weren't given",
                      "analyse the box run from a run-set bundle (`tracekit export --v2 --run-set`) or the signer's "
                      "store, and start the box with its agent channel on (Box's docs/agent-channel.md)"),
    "agent_run": ("this is a box's agent run: its box run holds the door records TK-X212 compares it with",
                  "analyse the box run (its id is this run's parent_run) from the same run-set bundle or store"),
    "no_agent_run": ("no agent run of the box was open then (before its hooks started or after it closed), so no "
                     "account of the agent's covers it",
                     "review these door records by hand (`tracekit view`, `tkbox events <box>`)"),
    "model_host": ("a connection to a model API host: the agent's harness makes its own model calls, which no tool "
                   "call names", "nothing; Box records each model call on that host (tkbox.model.call)"),
    "host_command": ("a command Box started from the host (not the agent) was running, or ran, and may have done it",
                     "run host commands before the agent starts, or in a box of their own"),
    "background": ("a shell call earlier in the run may have left a process running (run_in_background, `&`, nohup), "
                   "which may have made it", "review that call's command; its later connections can't be told from "
                   "the agent's"),
    "apply_dir": ("the file was written back to a directory that isn't the box's workspace (`tkbox apply --dir`), or "
                  "the box run names no workspace", "apply to the workspace the box was started with"),
    "shell_ran": ("a shell, MCP or other call that writes files without naming them ran, so any file may be its",
                  "review the box's patch (`tkbox diff`) against the agent's commands"),
    "no_url": ("the call's URL, or the host of a door record it would match, isn't known: the signer kept no content "
               "for it, or it isn't a URL Box sees (an internationalised name)",
               "set `content: {retain: true}` in signer.yaml and grant the analysing identity content_read"),
    "reused": ("a connection to that host crossed the door before the call: one kept open, or the fetch tool's own "
               "cache, may have served it", "nothing: a fetch with a connection of its own is checked"),
    "box_refusal": ("Box refused a connection to that host itself (or lost such a record), and sends those records "
                    "later with no time of their own, so whether it was this call's can't be told",
                    "read the box's events for that host (`tkbox events <box>`)"),
    "no_outcome": ("a connection to that host in the call's window has no recorded outcome (its result was lost, or an "
                   "approval it waited on was never answered)", "read the box run's tkbox.gap records"),
}
CALL_SIDE = frozenset(("agent_run", "no_url", "reused", "box_refusal", "no_outcome"))


def unit(reason):
    """The thing TK-X212's not-checkable count of `reason` counts."""
    return "call" if reason in CALL_SIDE else "record" if reason == "budget" else "door event"


def label(records):
    """(the ext.box label, its box run's id or None) of a run's records: None for a run with no label; a box run's own
    has no box run above it."""
    e = records[0]["event"] if records else {}
    box = (e.get("ext") or {}).get("box") if e.get("type") == "run.registered" else None
    return box and (box, e["data"].get("parent_run"))


def store_runs(data_dir, box_run):
    """run_id -> records of the agent channel runs of box run `box_run` in a signer's store, read without its lock."""
    from .why.import_v2 import _store
    r = _store(data_dir)
    try:
        # lean: reads every run's first record; index runs by parent_run if stores hold many runs per analysis
        return {key[1]: list(r.iter_run(*key)) for key in list(r.runs)
                if (label(r.run_records(*key, [0])) or (None, None))[1] == box_run}
    finally:
        r.close()


def _bare(h):
    """Host `h` as Box's door writes one (lower case, no trailing dot, an IPv4-mapped address unmapped), or None."""
    h = h.lower().rstrip(".") if isinstance(h, str) else None
    # lean: an IDN host is not matched (Box sees its punycode); add IDNA when boxes' agents fetch such names
    if not h or not h.isascii():
        return None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return h
    return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)


def _host(url):
    """The host URL `url` names, as _bare gives it, or None."""
    try:
        return _bare(urllib.parse.urlsplit(url).hostname)
    except (TypeError, ValueError, AttributeError):
        return None


def _arg(c, *keys):
    """The first of `keys` that call c's arguments hold as a string, else None."""
    a = c["args"] if isinstance(c["args"], dict) else {}
    return next((a[k] for k in keys if isinstance(a.get(k), str)), None)


def _background(args):
    """Whether a shell call may leave a process running past its result (Claude Code's run_in_background; a command
    with `&`, nohup, setsid or disown), None when its arguments aren't known."""
    if not isinstance(args, dict):
        return None
    if args.get("run_in_background"):
        return True
    if not isinstance(args.get("command"), str):
        return None
    try:
        lex = _Lexer(args["command"][:1 << 16], posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return any(w == "&" or w in BACKGROUND for w in lex)
    except ValueError:   # a quote that never closes: it can't be read
        return True


def _bodies(records, want, content, late):
    """({run_seq: content} of the records of one run `want(record)` picks, whether all were read): reading stops once
    `late()`, so a record with no content may be one the time budget left unread."""
    recs, got = [r for r in records if want(r)], {}
    if not (content and recs):
        return got, True
    it = iter(content(recs))
    while not late():
        try:
            seq, body, _ = next(it)
        except StopIteration:
            return got, True
        got[seq] = body
    return got, False


def _calls(records, bodies):
    """The decided calls of one run: {id, tool, t0, t1 (None: no result), ok (None: no result), dseq, rseq, args,
    ran, outcome (allowed, refused or None: unknown), end (None: open)}."""
    by = {}
    for r in records:
        e = r["event"]
        if e["type"] == "policy.decision":
            by[e["data"]["tool_use_id"]] = [r, None]   # a later attempt replaces an earlier one
        elif e["type"] == "tool.result" and e["data"].get("tool_use_id") in by:
            by[e["data"]["tool_use_id"]][1] = r
    out = []
    for tcid, (d, res) in by.items():
        de, ok = d["event"], res and res["event"]["data"]["ok"]
        decision = de["data"].get("decision")
        out.append({"id": tcid, "tool": de["data"].get("tool") or "?", "t0": _t(de["ts"]),
                    "t1": res and _t(res["event"]["ts"]), "ok": ok, "dseq": de["run_seq"],
                    "rseq": res and res["event"]["run_seq"], "args": bodies.get(de["run_seq"]),
                    "ran": decision in ("allow", "flag") or res is not None, "end": None,
                    "outcome": "allowed" if ok else "refused" if res or decision == "deny" else None})
    return sorted(out, key=lambda c: c["dseq"])


def _span(records):
    """(start, end) of a run on the signer's clock: its registration to its close; end None while it is open."""
    closing = next((r for r in records if r["event"]["type"] == "run.closing"), None)
    final = records[-1]["event"]["type"] == "run.final"
    return _t(records[0]["event"]["ts"]), _t((closing or records[-1])["event"]["ts"]) if closing or final else None


def _runs(names):
    return f"run{'s' * (len(names) != 1)} {', '.join(names)}"


def check(run, out, cov, others, opts, deadline, clock):
    """TK-X212 over findings_v2's run (`run`), into its result `out` and coverage `cov`: for a box run, against the runs
    of its agent channel among `others` ((run_id -> records, their content as findings_v2.analyze takes it, read
    straight, never through a reviewer's tee), or None); an agent channel's run is not checkable (its box run holds the
    doors); any other run counts nothing. `opts`: findings_effects.options() (its grace); past `deadline` on `clock`
    what is left to read is not checkable: budget."""
    lab = label(run.records)
    if not lab:
        return
    cx, n0 = cov[RULE], len(out["findings"])

    def note(status, n=1):
        if status in ("checked", "found"):
            cx["checked"] += n
            cx["tier"].update(("observer", "decision"))
        elif n:
            cx["not_checkable"][status] = cx["not_checkable"].get(status, 0) + n
    if lab[1]:
        return note("agent_run", len(run.ran))
    grace = (opts or {}).get("grace_s", GRACE_S)
    runs, content = others or ({}, None)

    def late():
        return clock() > deadline

    # the box run: its doors and what Box observed
    door = {"tkbox.box", "tkbox.model.call", "tkbox.egress", "tkbox.gap"}
    bodies, done = _bodies(run.records, lambda r: r["event"]["type"] == "policy.decision" and r["event"]["data"].get(
        "tool") in ("WebFetch", "Write") or r["event"]["type"] == "input.observed" and r["event"]["data"].get(
        "source") in door, content, late)
    doors = _calls(run.records, bodies)
    conns = [{**d, "host": _host(_arg(d, "url"))} for d in doors if d["tool"] == "WebFetch"]
    writes = [d for d in doors if d["tool"] == "Write"]
    obs = [(r["event"]["data"]["source"], _t(r["event"]["ts"]), bodies.get(r["event"]["run_seq"]))
           for r in run.records if r["event"]["type"] == "input.observed" and r["event"]["data"].get("source") in door]
    obs = [(s, t, b) for s, t, b in obs if isinstance(b, dict)]
    workspace = next((posixpath.normpath(b["workspace"]) for s, _, b in obs if s == "tkbox.box"
                      and isinstance(b.get("workspace"), str) and b["workspace"].startswith("/")), None)
    model_hosts = {*PROVIDER_HOSTS.values(), *(_bare(b.get("host")) for s, _, b in obs if s == "tkbox.model.call")}
    refusals = [(t, _bare(b.get("host"))) for s, t, b in obs if s == "tkbox.egress"]   # None: a summary of several
    lost = any(s == "tkbox.gap" and b.get("kind") == "tkbox.egress" for s, _, b in obs)
    # the agent's runs: what it said it did
    kids = {k: v for k, v in ((k, sorted(v, key=lambda r: r["event"]["run_seq"])) for k, v in runs.items())
            if (label(v) or (None, None))[1] == run.run_id}
    if not kids:
        return note("no_agent_runs", len(conns) + len(writes))
    calls, spans = [], {}
    for rid, recs in sorted(kids.items()):
        got, ok = _bodies(recs, lambda r: r["event"]["type"] == "policy.decision", content, late)
        done, spans[rid] = done and ok, _span(recs)
        calls += [{**c, "run": rid, "end": spans[rid][1], "host": _host(_arg(c, "url")),
                   "bg": _background(c["args"]) if c["tool"] in SHELLS else False}
                  for c in _calls(recs, got) if c["ran"]]
    missing = "no_content" if done else "budget"
    starts = [s for s, _ in spans.values()]
    hosted = [m for m in doors if m["tool"] == "Bash" and m["ran"]   # commands Box started, but not one an agent ran in
              and not any(m["t0"] <= s and (m["t1"] is None or s <= m["t1"]) for s in starts)]
    window = f" [window: a call's decision to {grace:g} s after its result, on the signer's clock]"

    def holds(c, t):
        end = c["end"] if c["t1"] is None else c["t1"] + grace
        return c["t0"] <= t and (end is None or t <= end)

    def live(t):
        return sorted(rid for rid, (s, e) in spans.items() if s <= t and (e is None or t <= e))

    def connection(d):
        """(a) of one connection: checked, found, or why it is not checkable."""
        t, h = d["t0"], d["host"]
        if h is None:
            return missing
        if h in model_hosts:
            return "model_host"
        runs_then = live(t)
        if not runs_then:
            return "no_agent_run"
        # lean: scans every call per connection; index calls by time (findings_effects._Effects.window) if boxes run
        # thousands of each
        fits = [c for c in calls if "connect" in _kinds(c["tool"])
                and (c["tool"] not in FETCH or c["host"] in (None, h)) and holds(c, t)]
        if fits:
            return "checked" if any(c["t1"] is not None for c in fits) else "call_unfinished"
        if any(holds(m, t) for m in hosted):
            return "host_command"
        earlier = [c["bg"] for c in calls if c["tool"] in SHELLS and c["t0"] <= t and c["run"] in runs_then]
        return "background" if True in earlier else missing if None in earlier else "found"

    found = {}
    for d in conns:
        status = connection(d)
        note(status)
        if status == "found":
            found.setdefault(d["host"], []).append(d)
    for h, ds in found.items():
        t, through = ds[0]["t0"], sum(d["outcome"] == "allowed" for d in ds)
        last = max((c for c in calls if c["t0"] <= t), key=lambda c: c["t0"], default=None)
        _finding(run, out, [s for d in ds for s in (d["dseq"], d["rseq"])], "high", "door_unexplained", grace,
                 f"Box's door saw the box connect to {h} {len(ds)} time{'s' * (len(ds) != 1)} ({through} let through, "
                 f"{len(ds) - through} refused; the first at box run record {ds[0]['dseq']}) while the agent's "
                 f"{_runs(live(t))} {'was' if len(live(t)) == 1 else 'were'} open, and no call of the agent's that "
                 "could connect was in progress, nor had a shell call left a process running" + (
                     f"; the agent's last call before it: {last['tool']} (run {last['run']}, record {last['dseq']}), "
                     f"{t - last['t0']:.1f} s earlier" if last else "") + window)

    # (a) of each file of the box's patch
    shells = any("file" in _kinds(c["tool"]) and c["tool"] not in WRITE_TOOLS for c in calls)
    named = {p and posixpath.normpath(p) for p in (_arg(c, "file_path", "notebook_path", "path") for c in calls
                                                    if c["tool"] in WRITE_TOOLS and c["ok"] is not False)}

    def written(p):
        """(a) of a file written back at apply to path `p`: (status, its path in the workspace)."""
        if p is None:
            return missing, None
        p = posixpath.normpath(p)
        if not workspace or p == workspace or not _under(p, workspace):
            return "apply_dir", None
        rel = posixpath.relpath(p, workspace)
        return ("checked" if {posixpath.join(WORKSPACE, rel), rel} & named else missing if None in named
                else "shell_ran" if shells else "host_command" if hosted else "found"), rel

    found = {}
    for w in writes:
        status, rel = written(_arg(w, "file_path"))
        note(status)
        if status == "found":
            found.setdefault(rel, []).append(w)
    for rel, ws in found.items():
        _finding(run, out, [s for w in ws for s in (w["dseq"], w["rseq"])], "high", "door_unexplained", None,
                 f"the box's patch changes {rel} (written back at apply: Box's Write decision, box run record "
                 f"{ws[0]['dseq']}), and no write call of the agent's {_runs(sorted(kids))} named {WORKSPACE}/{rel}; "
                 "no shell or other call that writes files without naming them ran, nor a command Box started besides "
                 "the agent's")

    # (b) and (c) of each fetch call of the agent's that returned ok
    events = [r["event"] for r in run.records]
    for c in calls:
        if c["tool"] not in FETCH or c["ok"] is not True:
            continue
        h, end = c["host"], c["t1"] + grace
        said = (f"the agent's {c['tool']} of {h} (run {c['run']}, call {c['id']}, records {c['dseq']} and "
                f"{c['rseq']}) returned ok, but ")
        inw = [d for d in conns if d["host"] == h and c["t0"] <= d["t0"] <= end]
        if h is None or any(d["host"] is None and d["t0"] <= end for d in conns) and not any(
                d["outcome"] == "allowed" for d in inw):
            note("no_url" if done else "budget")
        elif any(d["outcome"] == "allowed" for d in inw):
            note("checked")
        elif any(d["outcome"] is None for d in inw):
            note("no_outcome")
        elif inw:
            note("found")
            _finding(run, out, [s for d in inw for s in (d["dseq"], d["rseq"])], "high", "door_refused", grace,
                     said + f"Box's door refused every connection to {h} in that call's window (box run record"
                     f"{'s' * (len(inw) != 1)} {', '.join(str(d['dseq']) for d in inw)})" + window)
        elif any(d["host"] == h and d["t0"] < c["t0"] for d in conns):
            note("reused")
        elif lost or any(t >= c["t0"] and rh in (None, h) for t, rh in refusals):
            note("box_refusal")
        else:
            note("found")
            k = next((e["run_seq"] for e in events if _t(e["ts"]) > end), events[-1]["run_seq"])
            _finding(run, out, [k], "medium", "no_door_event", grace,
                     said + f"no connection to {h} crossed the box's door from the box's start to {grace:g} s after "
                     f"that result (the box run's records up to {k})" + window)
    cx["found"] += len(out["findings"]) - n0


def _finding(run, out, seqs, severity, kind, grace, what):
    """A finding as review_finding takes it (findings_v2._finding's shape: no text of the run; its cites are the box
    run's records, the agent's are named in what printing shows), and what printing shows of it."""
    out["findings"].append({"verdict": {"kind": "finding", "rule": RULE, "severity": severity, **(
        {"window": {"grace_s": grace, "skew_s": 0.0}} if grace is not None else {})},
        "cites": [{"run_seq": s, "hash": run.by_seq[s]["hash"]}
                  for s in sorted({s for s in seqs if s is not None})[:MAX_CITES]]})
    out["shown"]["details"].append({"what": what, "tiers": ["observer", "decision"], "labels": [kind]})
