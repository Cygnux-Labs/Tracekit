"""TK-X206, TK-X207: whether what a kernel sensor saw a run's processes do and the tool calls the run decided agree
(docs/findings.md). One call from findings_v2.analyze, over the same run.

Effects are the effect.observed records a kernel sensor's import wrote (`sensor`: docs/integrations/tetragon.md), each
stamped with the sensor's clock; a call runs from its policy.decision to its tool.result, on the signer's clock. A
call's window is [decision - skew, result + grace + skew]: `grace` for what a call leaves running a moment after its
result, `skew` how far apart the two clocks may be (options(); both shown with each finding). An effect whose sensor
time is later than the signer recorded it shows the sensor's clock ahead by at least that much; every effect recorded
later than the import's flush interval, the sensor's clock perhaps behind (`skew_seen`, a label on each finding).

TK-X206 (high) an effect no call explains. A process the run started (its exec is in the run) is explained by:
  - the call its environment names (tool_call_id, the agent's claim: Codex's CODEX_TOOL_CALL_ID), re-checked: the run
    ran that call, the effect falls in its window, and the tool causes that kind of effect (KINDS: an exec named by a
    Read call is a finding);
  - the process that started it (parent_exec_id: Tetragon), which explains the processes a call left running and what
    they start later, whatever the time;
  - else the window of a call whose tool runs processes (a shell, a search tool, an MCP or unknown tool).
Its connect, file and exit effects go with it, each re-checked when it names a call of its own. Not checkable: an effect
of a process running before the run (the agent's harness: its model calls, its own files), unless it is a file a write
call named in its window; a shell or Python process started outside any call, not by a call's process, as Tracekit's
own hooks are (hook_like); one only a call with no result yet could explain (call_unfinished).
TK-X207 (medium) a call that returned ok without the effect it should have had in its window: a shell command's
programs (and curl's or wget's connection), a fetch tool's connection, a write tool's file where the sensor's policy
selects writes (options(skips)). Checkable only when run.final's coverage matrix says a sensor observed the run's
processes throughout, and only for kinds of effect the sensor recorded in the run.
"""
import argparse
import bisect
import datetime
import itertools
import math
import posixpath

from .findings import WRITE_TOOLS
from .findings_text import _Lexer
from .wiki import wiki_url

GRACE_S, SKEW_S = 2.0, 0.5
FLUSH_S = 1.0   # how often tracekit.sensor's import sends what it read
MAX_CITES = 8
MAX_SHOWN = 10_000   # lean: effects whose join `shown` lists for the viewer; past it the rest are counted, not listed
ALL = frozenset(("exec", "exit", "connect", "file"))
RUNS = frozenset(("exec", "exit"))
# the effects a tool's call may cause in processes of its own, by the names Claude Code and the harness hooks record
# (agent_hooks maps Codex's shell and apply_patch, Gemini's and Cursor's tools onto them); any other tool, an MCP tool
# among them, may cause any
KINDS = {**dict.fromkeys(("Bash", "bash", "shell", "local_shell", "exec_command", "container.exec"), ALL),
         **dict.fromkeys(("Grep", "Glob"), RUNS),   # Claude Code runs ripgrep for them
         **dict.fromkeys((*WRITE_TOOLS, "apply_patch", "Delete", "Memory"), frozenset(("file",))),
         **dict.fromkeys(("WebFetch", "web_fetch"), frozenset(("connect",))),
         **dict.fromkeys(("Read", "LS", "NotebookRead", "read_file", "read_many_files", "list_directory", "TodoWrite",
                          "WebSearch", "Task", "Agent", "ExitPlanMode"), frozenset())}
SHELLS = ("sh", "bash", "dash", "zsh", "python")   # what a hook runs as (install._hook_command): basename prefixes
NET = ("curl", "wget")   # a shell command whose program connects
FETCH = ("WebFetch", "web_fetch")
BUILTINS = frozenset(("cd", "echo", "export", "pwd", "true", "false", ":", "printf", "test", "[", "[[", "set", "unset",
                      "source", ".", "alias", "read", "exit", "return", "type", "wait", "shift", "local", "declare",
                      "let", "umask", "trap", "hash", "builtin", "eval", "pushd", "popd", "history", "jobs"))
WRAPPERS = frozenset(("sudo", "env", "time", "nohup", "exec", "command", "nice", "timeout", "stdbuf"))
CHECKS = ("TK-X206", "TK-X207")
TITLES = {"TK-X206": "Effect with no action", "TK-X207": "Action with no effect"}
SEVERITIES = {"TK-X206": "high", "TK-X207": "medium"}
WHY = {
    "TK-X206": ("a process ran, connected or wrote a file with no tool call to account for it: activity the run's "
                "calls don't show",
                "find what started it (its binary, the process before it, the time); a process that names a call is "
                "the agent's claim, so compare it with that call; review the harness's own hooks and status line"),
    "TK-X207": ("the call reported success, but the kernel sensor saw nothing it should have caused, so the result "
                "may not be what ran",
                "compare the call's result with the sensor's records around it, and check that the sensor covered "
                "that process and path"),
}
REASONS = {
    "agent_process": ("a process running before the run started did it (the agent's harness: its model calls, its own "
                      "files), and nothing names the call",
                      "Codex: keep CODEX_TOOL_CALL_ID in the sensor's environment variables "
                      f"({wiki_url('docs/integrations/tetragon.md', 'tool-calls')}); for hosts, the egress observer "
                      f"({wiki_url('docs/egress.md')})"),
    "hook_like": ("a shell or Python process started outside any call, not by a call's process: Tracekit's own hooks "
                  "look the same",
                  "nothing for Tracekit's hooks; a hook or status line of your own shows here too, so review the "
                  "harness's hook settings"),
    "call_unfinished": ("only a call with no recorded result could explain it, so when that call ended is unknown",
                        "make sure the agent's hook reports each call's result (PostToolUse)"),
    "no_sensor": ("run.final's coverage matrix doesn't say a kernel sensor observed the run's processes throughout, or "
                  "the run is still open",
                  f"run `tracekit sensor import` for this run ({wiki_url('docs/integrations/tetragon.md')})"),
    "sensor_paths": ("which files the sensor's policy selects is not in the run",
                     "pass --sensor-skip DIR for each directory the policy leaves out (the sample's /workspace/ and "
                     "/tmp/), or --sensor-skip '' when it selects every write"),
    "hook_binary": ("the only processes that could be the command's ran the same program as Tracekit's own hooks (a "
                    "shell or Python), so they may have been the hooks",
                    "Codex: keep CODEX_TOOL_CALL_ID in the sensor's environment variables "
                    f"({wiki_url('docs/integrations/tetragon.md', 'tool-calls')}): a command's processes then name "
                    "their call"),
    "kind_not_recorded": ("the sensor recorded no effect of this kind in the run: its policy may not select them",
                          f"use the sample TracingPolicy of {wiki_url('docs/integrations/tetragon.md')}, or the Falco "
                          f"rules of {wiki_url('docs/integrations/falco.md')}"),
}
WHAT = {"exec": "start a process", "exit": "end a process", "connect": "connect", "file": "write a file"}


def options(grace_s=GRACE_S, skew_s=SKEW_S, skips=None):
    """The effect checks' settings: `skips` the directories the sensor's file policy leaves out (None: unknown)."""
    return {"grace_s": grace_s, "skew_s": skew_s, "skips": None if skips is None else
            [posixpath.normpath(s) for s in skips if s]}


def seconds(v):
    """An argparse type: a finite number of seconds, 0 or more (nan never compares, so a budget of it never ends)."""
    s = float(v)
    if not math.isfinite(s) or s < 0:
        raise argparse.ArgumentTypeError(f"{v!r} is no number of seconds (finite, 0 or more)")
    return s


def arguments(ap):
    ap.add_argument("--effect-grace", type=seconds, default=GRACE_S, metavar="S",
                    help="seconds after a call's result its effects still count as its own (default %(default)g)")
    ap.add_argument("--clock-skew", type=seconds, default=SKEW_S, metavar="S",
                    help="seconds the kernel sensor's clock may be off the signer's (default %(default)g)")
    ap.add_argument("--sensor-skip", metavar="DIR", action="append",
                    help="TK-X207: a directory the kernel sensor's file policy leaves out (repeatable; '': it selects "
                    "every write)")


def from_args(a):
    return options(a.effect_grace, a.clock_skew, a.sensor_skip)


def unit(rule, reason):
    """The thing a check's not-checkable count counts."""
    return "effect" if rule == "TK-X206" and reason != "no_sensor" or reason == "agent_process" else "call"


def _t(ts):
    """A record's time in seconds, None for one no verified record holds."""
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _kinds(tool):
    return KINDS.get(tool, ALL)


def _name(path):
    return posixpath.basename(path or "")


def _under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _matches(binary, word):
    """Whether a process's binary is the program a command word names (python names python3.12)."""
    b, w = _name(binary), _name(word)
    return bool(w) and (b == w or b.startswith(w) and b[len(w):][:1] in tuple("0123456789.-"))


def _programs(cmd):
    """The programs a shell command runs, as far as a lexer can tell: the first word of each simple command that is
    no builtin, past wrappers (sudo, env, ...) and assignments."""
    try:
        lex = _Lexer(cmd[:1 << 16], posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:
        return []
    out, first, target = [], True, False
    for w in words:
        if target:   # a redirection's file
            target = False
        elif set(w) <= set("<>&|") and set(w) & set("<>"):
            target = True
        elif set(w) <= set(";&|()"):
            first = True
        elif first and not ("=" in w and not w.startswith("=")) and w not in WRAPPERS and not w.startswith("-") \
                and not w.isdigit():   # past an assignment, a wrapper and its options (timeout 10, nice -n 5)
            if w not in BUILTINS and not set(w) & set("$`*?"):
                out.append(w)
            first = False
    return out


class _Effects:
    def __init__(self, run, opts):
        self.run, self.grace, self.skew, self.skips = run, opts["grace_s"], opts["skew_s"], opts["skips"]
        self.calls = {}
        for tcid, c in run.calls.items():
            d, r = c["decision"]["event"], (c.get("result") or {}).get("event")
            t0 = _t(d.get("ts"))
            self.calls[tcid] = {"id": tcid, "tool": d["data"].get("tool") or "?", "t0": t0,
                                "t1": _t(r.get("ts")) if r else None, "ok": bool(r and r["data"].get("ok")),
                                "dseq": d["run_seq"], "rseq": r and r["run_seq"],
                                "ran": tcid in run.ran and t0 is not None}
        self.ran = sorted((c for c in self.calls.values() if c["ran"]), key=lambda c: c["t0"])
        # the finished calls by start, each with the latest window end up to it; the unfinished ones (no result: their
        # window never ends) apart, so one of them doesn't make every effect scan every call before it
        self.done = [c for c in self.ran if c["t1"] is not None]
        self.unfinished = [c for c in self.ran if c["t1"] is None]
        self.starts = [c["t0"] - self.skew for c in self.done]
        self.ends, top = [], float("-inf")
        for c in self.done:
            top = max(top, c["t1"] + self.grace + self.skew)
            self.ends.append(top)
        # sensor times; OpenShell's reports aren't a kernel sensor's: it names its entrypoint, not every process
        self.ts = {r["event"]["run_seq"]: _t(r["event"]["data"].get("ts")) for r in run.records
                   if r["event"]["type"] == "effect.observed" and r["event"]["data"].get("sensor") not in (None,
                                                                                                         "openshell")}
        self.effects = [run.by_seq[s] for s, t in self.ts.items() if t and _t(run.by_seq[s]["event"].get("ts"))]
        by_kind = {}
        for r in self.effects:
            by_kind.setdefault(r["event"]["data"]["kind"], []).append((self.ts[r["event"]["run_seq"]], r))
        self.by_kind = {k: ([t for t, _ in v], [r for _, r in v])   # kind -> (sensor times, records), by time
                        for k, v in ((k, sorted(v, key=lambda x: x[0])) for k, v in by_kind.items())}
        # how late the signer recorded each effect after its sensor time: below zero, the sensor's clock is ahead by at
        # least that; every effect later than the import's flush interval, it may be behind by about that
        # (`suggest_s`: a --clock-skew that covers it, all of the lag counted as skew)
        lag, at = min(((_t(r["event"]["ts"]) - self.ts[r["event"]["run_seq"]], r["event"]["run_seq"])
                       for r in self.effects), default=(0.0, None))
        self.skew_seen = (
            {"ahead_s": round(-lag, 3), "record": at, "suggest_s": round(-lag + 0.5, 1)} if -lag > self.skew else
            {"behind_s": round(lag - FLUSH_S, 3), "record": at, "suggest_s": round(lag + 0.5, 1)}
            if lag > self.skew + FLUSH_S else None)
        final = next((r["event"]["data"] for r in run.records if r["event"]["type"] == "run.final"), {})
        self.observed = ((final.get("matrix") or {}).get("processes") or {}).get("status") == "observed"

    def in_window(self, c, ts):
        return c["t0"] - self.skew <= ts and (c["t1"] is None or ts <= c["t1"] + self.grace + self.skew)

    def window(self, ts, fits):
        """(the latest call that ran whose window holds `ts` and `fits(call)`, whether only a call with no result yet
        could)."""
        for j in range(bisect.bisect_right(self.starts, ts) - 1, -1, -1):
            if self.ends[j] < ts:
                break
            c = self.done[j]
            if fits(c) and self.in_window(c, ts):
                return c, False
        # lean: scans the calls with no result, a few in a run (a crash leaves its last call); index them by kind and
        # path if runs leave many
        return None, any(c["t0"] - self.skew <= ts and fits(c) for c in self.unfinished)

    def between(self, kind, c):
        """The effects of `kind` in call c's window."""
        times, recs = self.by_kind.get(kind, ([], []))
        hi = float("inf") if c["t1"] is None else c["t1"] + self.grace + self.skew
        return recs[bisect.bisect_left(times, c["t0"] - self.skew):bisect.bisect_right(times, hi)]


def _judge(fx, d, ts, kind, proc):
    """(status: explained, found or a not-checkable reason; the call; how; why it is found, for a finding's first
    effect) of one effect. `proc`: the status of the process it goes with (an exec's parent, any other effect's own
    process), None when that process runs from before the run or is unknown."""
    tc = d.get("tool_call_id")
    if tc is not None:   # the agent's claim: re-checked
        c = fx.calls.get(tc)
        if c is None or not c["ran"]:
            return "found", tc, "claim", "claim_unknown" if c is None else "claim_denied"
        if kind not in _kinds(c["tool"]):
            return "found", tc, "claim", "claim_kind"
        if fx.in_window(c, ts):
            return "explained", tc, "claim", None
        if proc and proc[:2] == ("explained", tc):   # a process the call left running, or one that process started
            return "explained", tc, "ancestry", None
        return "found", tc, "claim", "claim_window"
    shellish = _name(d["binary"]).startswith(SHELLS)
    if proc is not None and not (proc[0] == "hook_like" and kind == "exec" and not shellish):
        status, call = proc[0], proc[1]
        if status != "explained":   # found: part of its process's finding; or not checkable as that process is
            return status, call, proc[2], None
        if kind in _kinds(fx.calls[call]["tool"]):
            return "explained", call, "ancestry" if kind == "exec" else "process", None
        return "found", call, "process", "process_kind"
    if kind == "exec":
        c, unfinished = fx.window(ts, lambda c: "exec" in _kinds(c["tool"]))
        if c:
            return "explained", c["id"], "window", None
        if unfinished:
            return "call_unfinished", None, None, None
        if shellish:
            # lean: told apart from Tracekit's own hooks by binary only; add the process's lifetime (its exit) or the
            # hook's pid if hooks from outside Tracekit hide behind it
            return "hook_like", None, None, None
        return "found", None, None, "no_call"
    if kind == "file":
        p = posixpath.normpath(d["path"])
        c, _ = fx.window(ts, lambda c: p in [posixpath.normpath(x) for x in
                                             (fx.run.args.get(c["dseq"]) or {}).get("paths", ())])
        if c:
            return "explained", c["id"], "path", None
    return "agent_process", None, None, None


def _x206(fx, out, cov, late):
    """-> run_seq -> {call, how, status} of each effect it judged."""
    procs, by_pid, shown, groups, roots = {}, {}, {}, {}, {}
    c206 = cov["TK-X206"]
    # in the sensor's time order, a process's start first: an import may record events out of order, a process's
    # never before its parent's or its own start
    order = sorted(fx.effects, key=lambda r: (fx.ts[r["event"]["run_seq"]], r["event"]["data"]["kind"] != "exec",
                                              r["event"]["run_seq"]))
    for i, r in enumerate(order):
        e, d = r["event"], r["event"]["data"]
        seq, kind, ts = e["run_seq"], d["kind"], fx.ts[e["run_seq"]]
        if kind == "exit":   # says nothing a process's start doesn't
            continue
        if late():   # past the budget: counted, not checked
            c206["not_checkable"]["budget"] = c206["not_checkable"].get("budget", 0) + 1
            shown[seq] = {"call": None, "how": None, "status": "budget"}
            continue
        if kind == "exec":   # its parent, when the sensor names one the run saw start
            proc = procs.get(d.get("parent_exec_id"))
        else:   # its own process: by the sensor's id, else (Falco) the last start of its pid
            proc = procs.get(d["exec_id"]) if d.get("exec_id") else by_pid.get(d["pid"])
        status, call, how, why = _judge(fx, d, ts, kind, proc)
        root = seq if why else proc[3] if status == "found" and proc else None
        if kind == "exec":
            by_pid[d["pid"]] = (status, call, how, root)
            if d.get("exec_id"):
                procs[d["exec_id"]] = by_pid[d["pid"]]
        if why:
            key = (why, d["binary"], call)
            groups.setdefault(key, []).append(seq)
            roots[seq] = key
        elif root is not None:
            groups[roots[root]].append(seq)
        if status in ("explained", "found"):
            c206["checked"] += 1
            c206["tier"].update(("observer", "decision") if call else ("observer",))
        else:
            c206["not_checkable"][status] = c206["not_checkable"].get(status, 0) + 1
        shown[seq] = {"call": call, "how": how, "status": status}
    if not fx.observed:
        c206["not_checkable"]["no_sensor"] = len(fx.run.ran)
    for (why, binary, call), seqs in groups.items():
        c = fx.calls.get(call)
        ds = [fx.run.by_seq[s]["event"]["data"] for s in seqs]
        first, n = ds[0], len({x["pid"] for x in ds})
        did = list(dict.fromkeys("start" if x["kind"] == "exec" else f"connect to {x['host']}:{x['port']}"
                                 if x["kind"] == "connect" else f"write {x['path']}" for x in ds))[:3]
        saw = (f"the {first['sensor']} sensor saw {n} process{'es' * (n != 1)} of {binary} "
               f"{' and '.join([', '.join(did[:-1]), did[-1]] if len(did) > 1 else did)} (first at {first['ts']}, "
               f"pid {first['pid']}, record {seqs[0]})")
        tool = c and c["tool"]
        because = {
            "no_call": "no call that runs processes was in progress then",
            "claim_unknown": f"it names call {call} (its environment's tool call id, the agent's claim), which the run "
                             "never decided",
            "claim_denied": f"it names call {call}, which the run denied",
            "claim_kind": f"it names call {call}, but that call's tool, {tool}, doesn't {WHAT[first['kind']]}",
            "claim_window": f"it names call {call} ({tool}), but happened outside that call's window",
            "process_kind": f"its process belongs to call {call}, but that call's tool, {tool}, doesn't "
                            f"{WHAT[first['kind']]}",
        }[why]
        _finding(fx, out, "TK-X206", seqs, c, f"{saw}: {because}")
    c206["found"] += len(groups)
    return shown


def _x207(fx, out, cov, late, shown):
    c207, kinds = cov["TK-X207"], set(fx.by_kind)
    # a run whose processes name their calls (Codex): a shell call's programs are the ones that name it
    claims = any(r["event"]["data"].get("tool_call_id") for r in fx.effects)
    # the hosts processes from before the run (the harness: its model calls) reach outside any fetch call: no fetch
    fetches = [c for c in fx.ran if c["tool"] in FETCH]
    background = {r["event"]["data"]["host"] for r in fx.by_kind.get("connect", ((), ()))[1]
                  if (shown.get(r["event"]["run_seq"]) or {}).get("status") == "agent_process"
                  and not any(fx.in_window(c, fx.ts[r["event"]["run_seq"]]) for c in fetches)}
    # the programs Tracekit's own hooks run as, seen outside any call: inside a call's window, one of them may be a hook
    hooks = {r["event"]["data"]["binary"] for r in fx.effects if (shown.get(r["event"]["run_seq"]) or {}).get(
        "status") == "hook_like"}
    for tcid, c in sorted(fx.calls.items(), key=lambda kv: kv[1]["dseq"]):
        if not c["ok"]:
            continue
        tool, facts = c["tool"], fx.run.args.get(c["dseq"]) or {}
        want = []   # (kind, what it should be, does an effect record satisfy it)
        if tool in FETCH:
            want.append(("connect", "connection", lambda r: r["event"]["data"]["host"] not in background))
        elif _kinds(tool) == ALL and tool in KINDS:   # a shell
            if "command" not in facts:
                want = "no_content"
            else:
                def by(w):
                    return (lambda r: r["event"]["data"].get("tool_call_id") == tcid) if claims else \
                        (lambda r: _matches(r["event"]["data"]["binary"], w))
                progs = list(dict.fromkeys(_programs(facts["command"])))
                want = [("exec", f"start of {w}", by(w)) for w in progs]
                want += [("connect", f"connection by {w}", by(w)) for w in progs if _name(w) in NET]
        elif tool in WRITE_TOOLS:
            paths = facts.get("paths")
            if not paths:
                want = "no_content" if c["dseq"] not in fx.run.content else []
            elif not paths[0].startswith("/"):
                want = "relative_path"
            elif fx.skips is None:
                want = "sensor_paths"
            elif not any(_under(posixpath.normpath(paths[0]), s) for s in fx.skips):
                p = posixpath.normpath(paths[0])
                want.append(("file", f"write to {p}", lambda r: posixpath.normpath(r["event"]["data"]["path"]) == p))
        if not want:
            continue
        if late():   # past the budget: counted, not checked
            c207["not_checkable"]["budget"] = c207["not_checkable"].get("budget", 0) + 1
            continue
        if not fx.observed:   # counted, not marked on each call: no sensor watched any of them
            c207["not_checkable"]["no_sensor"] = c207["not_checkable"].get("no_sensor", 0) + 1
            continue
        call = out["shown"]["calls"].get(tcid, {}).setdefault("checks", {})
        status = want if isinstance(want, str) else "kind_not_recorded" if {k for k, _, _ in want} - kinds else None
        missing, unsure = [], False
        for kind, what, ok in [] if status else want:
            got = [r["event"]["data"]["binary"] for r in fx.between(kind, c) if ok(r)]
            if not got:
                missing.append(what)
            unsure = unsure or not claims and bool(got) and set(got) <= hooks   # perhaps only a hook ran
        status = status or (None if missing or not unsure else "hook_binary")
        if status:
            c207["not_checkable"][status] = c207["not_checkable"].get(status, 0) + 1
            call["TK-X207"] = status
            continue
        c207["checked"] += 1
        c207["tier"].update(("observer", "decision"))
        call["TK-X207"] = "found" if missing else "checked"
        if missing:
            c207["found"] += 1
            sensor = (fx.effects[0]["event"]["data"]["sensor"] if fx.effects else "kernel")
            _finding(fx, out, "TK-X207", [c["dseq"], c["rseq"]], c,
                     f"{tool} (call {tcid}) returned ok, but the {sensor} sensor saw no {', '.join(missing[:3])} "
                     f"from its decision to {fx.grace:g} s after its result")


def _finding(fx, out, rule, seqs, call, what):
    """A finding as review_finding takes it (findings_v2._finding's shape: no text of the run), and what printing
    shows of it."""
    cited = sorted({*([call["dseq"]] if call and rule == "TK-X206" else []), *seqs})[:MAX_CITES]
    seen = fx.skew_seen
    labels = ["clock_skew"] if seen else []
    note = f" [window: grace {fx.grace:g} s, clock skew {fx.skew:g} s" + (
        "" if not seen else
        f"; the sensor's clock ran at least {seen['ahead_s']:.1f} s ahead of the signer's (record {seen['record']})"
        if "ahead_s" in seen else
        f"; every effect reached the signer at least {seen['behind_s'] + FLUSH_S:.1f} s after its sensor time (record "
        f"{seen['record']}), so the sensor's clock may be behind the signer's") + (
        f": pass --clock-skew {seen['suggest_s']:g}" if seen else "") + "]"
    out["findings"].append({"verdict": {"kind": "finding", "rule": rule, "severity": SEVERITIES[rule],
                                        "window": {"grace_s": fx.grace, "skew_s": fx.skew}},
                            "cites": [{"run_seq": s, "hash": fx.run.by_seq[s]["hash"]} for s in cited]})
    out["shown"]["details"].append({"what": what + note, "tiers": ["observer", "decision"] if call else ["observer"],
                                    "labels": labels})


def check(run, out, cov, opts, deadline, clock):
    """TK-X206 and TK-X207 over findings_v2's run, adding to its result `out` (findings, shown details, and
    shown.effects: run_seq -> {call, how, status} of each effect, for the viewer) and coverage `cov`; past `deadline` on
    `clock` what is left is not checkable: budget. -> run_seq -> {call, how, status} of every effect judged
    (shown.effects, uncut)."""
    def late():
        return clock() > deadline
    fx = _Effects(run, opts or options())
    shown = _x206(fx, out, cov, late)
    _x207(fx, out, cov, late, shown)
    out["shown"]["effects"] = dict(itertools.islice(shown.items(), MAX_SHOWN))
    out["shown"]["effect_window"] = {"grace_s": fx.grace, "skew_s": fx.skew, "skips": fx.skips,
                                     **({"skew_seen": fx.skew_seen} if fx.skew_seen else {})}
    return shown
