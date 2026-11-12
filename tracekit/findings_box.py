"""TK-X212: whether a boxed agent's own account of its calls and what Tracekit Box saw cross the box's doors agree
(docs/findings.md). One call from findings_v2.analyze, over a box run (its run.registered carries the signer-written
ext.box label and no parent_run: the Box daemon's own run) and the runs of its agent channel (each a child of it with
the same label: what the agent's hooks inside the box sent, which the agent can skip or forge).

Box's records (Tracekit Box's internal/daemon and internal/tracekit): each connection out of the box is a WebFetch
decision of the box run, {url: "<scheme>://<host>:<port>"}, made before it is dialled, with an ok result when Box let it
through (refused: the decision is deny, or its result isn't ok); each file of the box's patch written back at `tkbox
apply` is a Write decision, {file_path: <apply dir>/<path>, patch_sha256, ...}; a command Box started from the host is a
Bash decision; tkbox.box records name the workspace copied into the box's /workspace, tkbox.model.call records the
model calls on an inspected connection, tkbox.egress the refusals Box made itself (sent later, with no time of their
own) and tkbox.gap the records Box lost. All runs' records carry the signer's clock. A call's window runs from its
decision to its result + grace (findings_effects' --effect-grace; no skew: one clock). A fetch matches a connection to
its URL's host, a leading www. aside (Claude Code's WebFetch follows a redirect between the two), on its URL's port, and
on 443 too for plain http to port 80 (it upgrades http to https); the URL read as Node reads a web URL (_dests).

(a) high, a door event no call of the agent's explains:
  - a connection decided in the window of a call whose tool may connect (a shell, an MCP or unknown tool, a fetch tool
    that matches it, or one whose arguments aren't known) is explained. Not checkable: one to a model API host
    (model_host: the harness's own model calls), while no agent run was open (no_agent_run), when only a call with no
    result could explain it (call_unfinished), in the window of a command Box started that no agent run began in, or
    that shares that start with another (host_command), after a shell call of an open run that may have left a process
    running (background: run_in_background, or as _detaches reads its command; no_content when its command isn't
    known), when only a fetch whose arguments aren't known could explain it (no_content). A refusal Box made itself
    has no time of its own: untimed_refusal.
  - a file of the box's patch is explained by a write call of the agent's on that path (/workspace/<path>) that did
    not fail. Not checkable: the apply directory isn't the box's workspace, or may be a directory under it (apply_dir);
    a write call's arguments aren't known (no_content) or name no path (no_path); a shell, MCP or other call that
    writes files without naming them ran (shell_ran); a host command as above ran (host_command).
(b) medium, a fetch call of the agent's that returned ok with no connection it matches from the box's start to its
    result + grace. Not checkable: an earlier connection it matches that Box didn't refuse (reused: a connection kept
    open, or the tool's cache, may have served it); Box refused a connection to that host itself after the call began,
    or lost such a refusal (box_refusal); the call's URL, or the host of a door record up to its window's end, isn't
    known (no_url).
(c) high, a fetch call of the agent's that returned ok while Box's door refused every connection it matches in its
    window, and none earlier could have served it (reused). Not checkable: one of them has no recorded outcome
    (no_outcome).
A box run with no agent channel run in what was analysed is no_agent_runs for each door event; no_agent_account when
the box run is final, its channel was on, what was analysed holds every run of the box's tenant (the store, or a
run-set from registry 0 with no run open, the box run among its leaves: whole()) and Box refused no register_run on the
channel (tkbox.channel; a count of folded refusals may hold one): the agent registered none. An agent channel's run is
agent_run for each call: its box run holds the doors.
"""
import ipaddress
import posixpath
import re
import urllib.parse

from . import constraints
from .constraints import LATER_RUNS
from .findings import WRITE_TOOLS
from .findings_effects import ALL, FETCH, GRACE_S, KINDS, MAX_CITES, _kinds, _t, _under
from .policy2 import shell
from .signer.reconcile import PROVIDER_HOSTS

RULE = "TK-X212"
CHECKS = (RULE,)
SEVERITIES = {RULE: "high"}
WORKSPACE = "/workspace"   # where Box mounts the workspace copy inside a box (its proto.DefaultWorkspacePath)
SHELLS = frozenset(t for t, k in KINDS.items() if k == ALL)
# a command that detaches what it runs (coproc: \coproc), or runs it after the line returns (systemd-run, at, batch)
DETACHERS = frozenset(("setsid", "disown", "coproc")) | LATER_RUNS
WHATWG_PART = re.compile(r"0x[0-9a-f]*|[0-9]+")
STATED = {"keep_away": "to keep {} unchanged", "only_change": "to change only {}", "read_only": "to make no changes"}
WHY = {RULE: ("the agent's own records of its calls (sent from inside the box, where it can skip or forge them) and "
              "the box's door records (decided on the host, outside its reach) disagree: the agent did something it "
              "didn't record, or recorded something the door didn't see",
              "trust the door records over the agent's; read the agent's calls around the cited door record "
              "(`tracekit view`), and review what the box wrote before you apply or run it")}
REASONS = {
    "no_agent_runs": ("no run of the box's agent channel is in what was analysed: its runs weren't given (a bundle of "
                      "the box run alone, the viewer, a run-set short of them, a box still running), Box refused a "
                      "registration on the channel, or the box ran without it",
                      "analyse the box run from a run-set bundle (`tracekit export --v2 --run-set`) or the signer's "
                      "store, and start the box with its agent channel on (Box's docs/agent-channel.md)"),
    "no_agent_account": ("the box ran with its agent channel on, yet its agent registered no run: the agent kept no "
                         "account at all (its hooks never ran, or were skipped)",
                         "treat every door event of the box as unexplained and review them by hand (`tracekit view`, "
                         "`tkbox events <box>`): the agent's hooks are advice, the doors are the record"),
    "agent_run": ("this is a box's agent run: its box run holds the door records TK-X212 compares it with",
                  "analyse the box run (its id is this run's parent_run) from the same run-set bundle or store"),
    "no_agent_run": ("no agent run of the box was open then (before its hooks started or after it closed its run, "
                     "which it can do early), so no account of the agent's covers it",
                     "review these door records by hand (`tracekit view`, `tkbox events <box>`)"),
    "model_host": ("a connection to a model API host: the agent's harness makes its own model calls, which no tool "
                   "call names", "nothing; Box records each model call on that host (tkbox.model.call)"),
    "host_command": ("a command Box started from the host (not the agent's own) was running, or ran, and may have done "
                     "it", "run host commands before the agent starts, or in a box of their own"),
    "background": ("a shell call earlier in the run may have left a process running (run_in_background, `&`, setsid, "
                   "tmux, screen), which may have made it", "review that call's command; its later connections can't "
                   "be told from the agent's"),
    "untimed_refusal": ("Box refused a connection itself (or lost the record of one), and sends those records later "
                        "with no time of their own, so no call can be placed against it",
                        "read the box's events for it (`tkbox events <box>`)"),
    "apply_dir": ("the file was written back to a directory that isn't the box's workspace, or may be one under it "
                  "(`tkbox apply --dir`), or the box run names no workspace",
                  "apply to the workspace the box was started with"),
    "no_path": ("a write call of the agent's names no path, so any file may be its",
                "review the box's patch (`tkbox diff`) against the agent's calls"),
    "shell_ran": ("a shell, MCP or other call that writes files without naming them ran, so any file may be its",
                  "review the box's patch (`tkbox diff`) against the agent's commands"),
    "no_url": ("the call's URL, or the host of a door record it would match, isn't known: the signer kept no content "
               "for it, or it isn't a URL Box sees", "set `content: {retain: true}` in signer.yaml and grant the "
               "analysing identity content_read"),
    "reused": ("a connection to that host Box didn't refuse crossed the door before the call: one kept open, or the "
               "fetch tool's own cache, may have served it", "nothing: a fetch with a connection of its own is "
               "checked"),
    "box_refusal": ("Box refused a connection to that host itself (or lost such a record), and sends those records "
                    "later with no time of their own, so whether it was this call's can't be told",
                    "read the box's events for that host (`tkbox events <box>`)"),
    "no_outcome": ("a connection to that host in the call's window has no recorded outcome (its result was lost, or an "
                   "approval it waited on was never answered)", "read the box run's tkbox.gap records"),
    "no_task": ("no operator task was recorded for the box (tkbox.task), so the box's patch cannot be checked against it",
                "start the box with --task"),
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


def whole(rep, box_run):
    """Whether a verified bundle's report (verify.v2's) shows a run-set that holds every run of its tenant up to box run
    `box_run`'s end: its registry range starts at 0, no run registered in it is still open (a run-set bundles only final
    runs), and the box run's own registration is a leaf of it (a run-set may carry its selected run from outside)."""
    rs = getattr(rep, "run_set", None)
    return bool(rs) and rs["from"] == 0 and not rs["open"] and box_run in rs["registered"]


def _ipv4(h):
    """Host `h` as the dotted quad a WHATWG URL parser (Node's: Claude Code's) makes of a number form (0x5db8d822,
    1572395042, 0135.0xb8.216.34), or None when it is no such form."""
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or not all(WHATWG_PART.fullmatch(p) for p in parts):
        return None
    try:
        nums = [int(p[2:] or "0", 16) if p[:2] == "0x" else int(p, 8 if p[:1] == "0" else 10) for p in parts]
    except ValueError:   # 08: no octal number
        return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    return str(ipaddress.IPv4Address(sum(n << 8 * (3 - i) for i, n in enumerate(nums[:-1])) + nums[-1]))


def _bare(h):
    """Host `h` as Box's door writes one (lower case, no trailing dot, an internationalised name in punycode, a number
    form of an IPv4 address dotted, an IPv4-mapped address unmapped), or None."""
    h = h.lower().rstrip(".") if isinstance(h, str) else None
    if h and not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not h:
        return None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:   # a name that ends in a number is an IPv4 address, or no host (as WHATWG reads it)
        return _ipv4(h) if WHATWG_PART.fullmatch(h.split(".")[-1]) else h
    return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)


def _site(h):
    """Host `h` with a leading www. dropped: Claude Code's WebFetch follows a redirect that only adds or drops it (on
    the same protocol and port). An address never starts with www. once _bare has read it."""
    return h[4:] if h.startswith("www.") else h


def _door(url):
    """(host, (site, port) or None) of a connection Box's door names, "<scheme>://<host>:<port>"."""
    try:
        u = urllib.parse.urlsplit(url)
        h, port = _bare(u.hostname), u.port
    except (TypeError, ValueError, AttributeError):
        return None, None
    return h, (_site(h), port) if h and port is not None else None


def _dests(url):
    """(host, {(site, port)}) of a fetch's URL as a WHATWG parser (Node's) reads a web URL (tabs and newlines dropped,
    outer spaces and controls trimmed, a backslash a slash, any slashes after http: or https: its authority's): the host
    as _bare gives it (None when it names none), and the connections a fetch of it may make: its site on the URL's
    port, else its scheme's, and on 443 too for plain http to port 80 (Claude Code's WebFetch upgrades it to https)."""
    url = re.sub(r"[\t\n\r]", "", url).strip("".join(map(chr, range(33)))) if isinstance(url, str) else ""
    m = re.match(r"(?i)(https?):[/\\]*", url)
    if not m:
        return None, set()
    scheme = m.group(1).lower()
    try:
        u = urllib.parse.urlsplit(f"{scheme}://" + url[m.end():].replace("\\", "/"))
        h, port = _bare(u.hostname), u.port
    except ValueError:   # a port past 65535
        return None, set()
    p = port if port is not None else {"https": 443, "http": 80}[scheme]
    return h, {(_site(h), q) for q in ({p, 443} if scheme == "http" and p == 80 else {p})} if h else set()


def _arg(c, *keys):
    """The first of `keys` that call c's arguments hold as a string, else None."""
    a = c["args"] if isinstance(c["args"], dict) else {}
    return next((a[k] for k in keys if isinstance(a.get(k), str)), None)


def _background(args):
    """Whether a shell call may leave a process running past its result (Claude Code's run_in_background, or a command
    _detaches says may), None when its arguments aren't known."""
    if not isinstance(args, dict):
        return None
    if args.get("run_in_background"):
        return True
    return _detaches(args["command"]) if isinstance(args.get("command"), str) else None


def _detaches(cmd):
    """Whether shell command `cmd` may leave a process running past its end, as the policy engine's shell parser
    (policy2.shell: bash's quoting, heredocs, comments, `sh -c` strings, wrappers) reads it: a command it runs in the
    background (`&`, also after a block or an and-or list, in a subshell or an `sh -c` string), or one that detaches
    by itself (setsid, disown, coproc, systemd-run, at, batch, `tmux ... -d`, `screen -d...`); nohup alone runs in the
    foreground. True when the parser can't read the line (coproc as bash's keyword among it, or nesting too deep)."""
    try:
        cmds = shell.parse(cmd)
    except (shell.ParseError, RecursionError):
        return True
    return any(c.get("background") or c["argv"][0] in DETACHERS or c["argv"][0] in ("tmux", "screen") and any(
        a[:1] == "-" and "d" in a for a in c["argv"][1:]) for c in cmds)


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
    straight, never through a reviewer's tee, whether those runs are every run of the tenant: a store or a run-set), or
    None); an agent channel's run is not checkable (its box run holds the doors); any other run counts nothing. `opts`:
    findings_effects.options() (its grace); past `deadline` on `clock` what is left to read is not checkable: budget."""
    lab = label(run.records)
    if not lab:
        return
    cx, n0 = cov[RULE], sum(f["verdict"]["rule"] == RULE for f in out["findings"])

    def note(status, n=1):
        if status in ("checked", "found"):
            cx["checked"] += n
            cx["tier"].update(("observer", "decision"))
        elif n:
            cx["not_checkable"][status] = cx["not_checkable"].get(status, 0) + n
    if lab[1]:
        return note("agent_run", len(run.ran))
    grace = (opts or {}).get("grace_s", GRACE_S)
    runs, content, whole = others or ({}, None, False)

    def late():
        return clock() > deadline

    # the box run: its doors and what Box observed
    door = {"tkbox.box", "tkbox.model.call", "tkbox.egress", "tkbox.gap", "tkbox.channel", "tkbox.task"}
    bodies, done = _bodies(run.records, lambda r: r["event"]["type"] == "policy.decision" and r["event"]["data"].get(
        "tool") in ("WebFetch", "Write") or r["event"]["type"] == "input.observed" and r["event"]["data"].get(
        "source") in door, content, late)
    doors = _calls(run.records, bodies)
    conns = [{**d, "host": h, "dest": dest} for d in doors if d["tool"] == "WebFetch"
             for h, dest in [_door(_arg(d, "url"))]]
    writes = [d for d in doors if d["tool"] == "Write"]
    obs = [(r["event"]["data"]["source"], _t(r["event"]["ts"]), bodies.get(r["event"]["run_seq"]))
           for r in run.records if r["event"]["type"] == "input.observed" and r["event"]["data"].get("source") in door]
    obs = [(s, t, b) for s, t, b in obs if isinstance(b, dict)]
    workspace = next((posixpath.normpath(b["workspace"]) for s, _, b in obs if s == "tkbox.box"
                      and isinstance(b.get("workspace"), str) and b["workspace"].startswith("/")), None)
    model_hosts = {*PROVIDER_HOSTS.values(), *(_bare(b.get("host")) for s, _, b in obs if s == "tkbox.model.call")}
    refusals = [(t, _bare(b.get("host"))) for s, t, b in obs if s == "tkbox.egress"]   # None: a summary of several
    lost = sum(b.get("dropped") for s, _, b in obs if s == "tkbox.gap" and b.get("kind") == "tkbox.egress"
               and isinstance(b.get("dropped"), int))
    note("untimed_refusal", sum(b["suppressed"] if isinstance(b.get("suppressed"), int) else 1
                                for s, _, b in obs if s == "tkbox.egress") + lost)
    # the agent's runs: what it said it did
    kids = {k: v for k, v in ((k, sorted(v, key=lambda r: r["event"]["run_seq"])) for k, v in runs.items())
            if (label(v) or (None, None))[1] == run.run_id}
    # no agent account: the box ran to its end with the channel on, the source holds every run of the tenant, and Box
    # refused no register_run on the channel (a refusal with no method, refusals folded into a count, or one lost, may
    # have been one)
    refused = any(s == "tkbox.channel" and (b.get("method") in ("register_run", None) or b.get("folded"))
                  or s == "tkbox.gap" and b.get("kind") == "tkbox.channel" for s, _, b in obs)
    missing = "no_content" if done else "budget"
    _check_task(run, out, cov, writes, workspace, bodies, missing)
    if not kids:
        return note("no_agent_account" if whole and run.final and lab[0].get("channel") == "agent" and not refused
                    else "no_agent_runs", len(conns) + len(writes))
    calls, spans = [], {}
    for rid, recs in sorted(kids.items()):
        got, ok = _bodies(recs, lambda r: r["event"]["type"] == "policy.decision", content, late)
        done, spans[rid] = done and ok, _span(recs)
        for c in _calls(recs, got):
            if c["ran"]:
                h, dests = _dests(_arg(c, "url")) if isinstance(c["args"], dict) else (None, None)
                calls.append({**c, "run": rid, "end": spans[rid][1], "host": h, "dests": dests,
                              "bg": _background(c["args"]) if c["tool"] in SHELLS else False})
    missing = "no_content" if done else "budget"
    starts = [s for s, _ in spans.values()]
    cmds = [m for m in doors if m["tool"] == "Bash" and m["ran"]]

    def begun(m, s):
        return m["t0"] <= s and (m["t1"] is None or s <= m["t1"])
    agents = {id(ms[0]) for ms in ([m for m in cmds if begun(m, s)] for s in starts) if len(ms) == 1}
    hosted = [m for m in cmds if id(m) not in agents]   # commands Box started, but not the one an agent ran in
    window = f" [window: a call's decision to {grace:g} s after its result, on the signer's clock]"

    def holds(c, t):
        end = c["end"] if c["t1"] is None else c["t1"] + grace
        return c["t0"] <= t and (end is None or t <= end)

    def live(t):
        return sorted(rid for rid, (s, e) in spans.items() if s <= t and (e is None or t <= e))

    def connection(d):
        """(a) of one connection: checked, found, or why it is not checkable."""
        t = d["t0"]
        if d["dest"] is None:
            return missing
        if d["host"] in model_hosts:
            return "model_host"
        runs_then = live(t)
        if not runs_then:
            return "no_agent_run"
        # lean: scans every call per connection; index calls by time (findings_effects._Effects.window) if boxes run
        # thousands of each
        fits = [c for c in calls if "connect" in _kinds(c["tool"]) and holds(c, t)
                and (c["tool"] not in FETCH or c["dests"] is None or d["dest"] in c["dests"])]
        known = [c for c in fits if c["tool"] not in FETCH or c["dests"] is not None]
        if known:
            return "checked" if any(c["t1"] is not None for c in known) else "call_unfinished"
        if fits:   # only a fetch whose URL isn't known: it may be the one
            return missing
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
        t, n = ds[0]["t0"], {o: sum(d["outcome"] == o for d in ds) for o in ("allowed", "refused", None)}
        last = max((c for c in calls if c["t0"] <= t), key=lambda c: c["t0"], default=None)
        _finding(run, out, [s for d in ds for s in (d["dseq"], d["rseq"])], "high", "door_unexplained", grace,
                 f"Box's door saw the box connect to {h} {len(ds)} time{'s' * (len(ds) != 1)} ({n['allowed']} let "
                 f"through, {n['refused']} refused" + (f", {n[None]} with no outcome recorded" if n[None] else "")
                 + f"; the first at box run record {ds[0]['dseq']}) while the agent's {_runs(live(t))} "
                 f"{'was' if len(live(t)) == 1 else 'were'} open, and no call of the agent's that could connect was in "
                 "progress, nor had a shell call left a process running" + (
                     f"; the agent's last call before it: {last['tool']} (run {last['run']}, record {last['dseq']}), "
                     f"{t - last['t0']:.1f} s earlier" if last else "") + window)

    # (a) of each file of the box's patch
    shells = any("file" in _kinds(c["tool"]) and c["tool"] not in WRITE_TOOLS for c in calls)
    writers = [c for c in calls if c["tool"] in WRITE_TOOLS and c["ok"] is not False]
    named = set()   # the paths the agent's write calls name, under /workspace
    for c in writers:
        p = _arg(c, "file_path", "notebook_path", "path")
        p = p and posixpath.normpath(p)
        if p and _under(p, WORKSPACE) and p != WORKSPACE:
            named.add(posixpath.relpath(p, WORKSPACE))
        elif p and not p.startswith("/"):   # relative: to the workspace, where the agent works
            named.add(p)

    def written(p):
        """(a) of a file written back at apply to path `p`: (status, its path in the workspace)."""
        if p is None:
            return missing, None
        p = posixpath.normpath(p)
        if not workspace or p == workspace or not _under(p, workspace):
            return "apply_dir", None
        rel = posixpath.relpath(p, workspace)
        if rel in named:
            return "checked", rel
        if any(rel.endswith("/" + x) for x in named):   # applied to a directory under the workspace (--dir)
            return "apply_dir", rel
        return (missing if any(not isinstance(c["args"], dict) for c in writers)
                else "no_path" if any(_arg(c, "file_path", "notebook_path", "path") is None for c in writers)
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
        ours = [d for d in conns if c["dests"] and d["dest"] in c["dests"]]
        inw = [d for d in ours if c["t0"] <= d["t0"] <= end]
        if any(d["outcome"] == "allowed" for d in inw):
            note("checked")
        elif not c["dests"] or any(d["dest"] is None and d["t0"] <= end for d in conns):
            note("no_url" if done else "budget")
        elif any(d["t0"] < c["t0"] and d["outcome"] != "refused" for d in ours):
            note("reused")
        elif any(d["outcome"] is None for d in inw):
            note("no_outcome")
        elif inw:
            note("found")
            _finding(run, out, [s for d in inw for s in (d["dseq"], d["rseq"])], "high", "door_refused", grace,
                     said + f"Box's door refused every connection to {h} in that call's window (box run record"
                     f"{'s' * (len(inw) != 1)} {', '.join(str(d['dseq']) for d in inw)}), and none before it could "
                     "have served it" + window)
        elif lost or any(t >= c["t0"] and rh in (None, h) for t, rh in refusals):
            note("box_refusal")
        else:
            note("found")
            k = next((e["run_seq"] for e in events if _t(e["ts"]) > end), events[-1]["run_seq"])
            _finding(run, out, [k], "medium", "no_door_event", grace,
                     said + f"no connection to {h} crossed the box's door from the box's start to {grace:g} s after "
                     f"that result (the box run's records up to {k})" + window)
    cx["found"] += sum(f["verdict"]["rule"] == RULE for f in out["findings"]) - n0


def _finding(run, out, seqs, severity, kind, grace, what):
    """A finding as review_finding takes it (findings_v2._finding's shape: no text of the run; its cites are the box
    run's records, the agent's are named in what printing shows), and what printing shows of it."""
    out["findings"].append({"verdict": {"kind": "finding", "rule": RULE, "severity": severity, **(
        {"window": {"grace_s": grace, "skew_s": 0.0}} if grace is not None else {})},
        "cites": [{"run_seq": s, "hash": run.by_seq[s]["hash"]}
                  for s in sorted({s for s in seqs if s is not None})[:MAX_CITES]]})
    out["shown"]["details"].append({"what": what, "tiers": ["observer", "decision"], "labels": [kind]})


def _check_task(run, out, cov, writes, workspace, bodies, missing):
    """TK-X204: of each file of the box's patch against the operator's task (tkbox.task)."""
    if not writes or "TK-X204" not in cov:
        return
    cx = cov["TK-X204"]

    def note(status, n=1):
        if status in ("checked", "found"):
            cx["checked"] += n
            if status == "found":
                cx["found"] += n
            cx["tier"].update(("observer", "decision"))
        elif n:
            cx["not_checkable"][status] = cx["not_checkable"].get(status, 0) + n

    task_rec = next((r for r in run.records if r["event"]["type"] == "input.observed"
                     and r["event"]["data"].get("source") == "tkbox.task"
                     and r["event"]["data"].get("trust") == "trusted"), None)
    task_seq = task_rec["event"]["run_seq"] if task_rec else None
    task_body = bodies.get(task_seq) if task_seq is not None else None
    task_text = task_body.get("task") if isinstance(task_body, dict) else task_body if isinstance(task_body, str) else None
    task_text = task_text.strip() if isinstance(task_text, str) and task_text.strip() else None

    if task_rec is not None and task_body is None:
        return note(missing, len(writes))

    task_constraints = constraints.extract(task_text) if task_text else []
    file_constraints = [c for c in task_constraints if c[0] in ("keep_away", "only_change", "read_only")]
    only = {obj for kind, obj in file_constraints if kind == "only_change" and obj}

    for w in writes:
        p = _arg(w, "file_path")
        if p is None:
            note(missing)
            continue
        p = posixpath.normpath(p)
        if not workspace or p == workspace or not _under(p, workspace):
            note("apply_dir")
            continue
        rel = posixpath.relpath(p, workspace)
        if not task_text:
            note("no_task")
            continue
        if not file_constraints:
            note("checked")
            continue
        a = w["args"] if isinstance(w["args"], dict) else {}
        deleted = bool(a.get("deleted"))
        f = {"names": constraints.names([rel]), "write": True, "push": False, "network": False}
        hit = None
        for kind, obj in file_constraints:
            broken_name = constraints.breaks(kind, f, only.__contains__ if kind == "only_change" else obj.__eq__ if obj else None)
            if broken_name:
                hit = (kind, obj, broken_name)
                break
        if hit:
            kind, obj, broken_name = hit
            note("found")
            action = "deleted" if deleted else "changed"
            target_str = ", ".join(sorted(only)[:3]) if kind == "only_change" else (obj or "")
            what = f"the box's patch {action} {rel} after the request (record {task_seq}) said {STATED[kind].format(target_str)}"
            cites = [task_seq, w["dseq"], *([w["rseq"]] if w.get("rseq") is not None else [])]
            out["findings"].append({
                "verdict": {"kind": "finding", "rule": "TK-X204", "severity": "high"},
                "cites": [{"run_seq": s, "hash": run.by_seq[s]["hash"]} for s in sorted(set(cites))[:MAX_CITES]]
            })
            out["shown"]["details"].append({
                "what": what,
                "tiers": ["observer", "decision"],
                "labels": [kind]
            })
        else:
            note("checked")
