"""TK-X2xx: whether what a v2 run's person asked, what its model said and what its agent did agree (docs/findings.md).

    tracekit analyze --v2                          # the latest run of the dev signer's store
    tracekit analyze --v2 --run R --store DIR      # a signer's store, read-only
    tracekit analyze --v2 --run R --bundle B --trust T
        [--project DIR] [--allow DIR ...] [--open] [--budget S] [--dry-run] [--json]

Records come from the store, or from a bundle once it verifies; content (what the person asked, what the model said, a
call's arguments) from the signer's content vault (content_get, each read a signed content.accessed), each item opening
its record's commitment with the salt the vault returns, else the analysis stops (EvidenceAlert). Content redaction
changed opens nothing: a finding that relies on it is labelled `redacted`.

Checks, for each call the run allowed or ran:
  TK-X201 (info; low when most checkable calls had reasoning) the model said nothing before the tool use that asked
          for the call: no reasoning and no text earlier in the same model message (parsers.said)
  TK-X202 (medium) a write tool edited a file whose name neither the person's request nor the model's text before the
          call names. A sentence that names a file to keep away from it ("leave billing.py untouched") is no mention:
          it is a constraint, and a file the request kept away is a finding whatever the model said about it.
  TK-X203 (high) a write tool, a Bash write target or a kernel sensor's file effect outside the project
  TK-X205 (critical) a success claim after the last related call failed, and v1's say-vs-do checks TK-X101..X104,
          X111..X114 and X120 on the v2 view: tracekit.findings_text
  TK-X200 (info) coverage: per check what it checked, found and could not check (by reason), and the monitorability
          score: how many actions had full, summarized, withheld (sealed or absent) or no reasoning before them, from
          which the share of actions each check could check follows.

A finding is what review_finding signs (#309 phase 2), with no text of the run: {verdict: {kind, rule, severity,
tier: the weakest trust tier of the text it relied on (transcript: a Claude Code transcript line, which the agent can
write; sdk: what an in-process adapter reported; gateway: the LLM gateway's record), order: where the call's reasoning
sits against its decision, redacted: content redaction changed}, cites: [{run_seq, hash}] of the records it relied on};
the signer adds the rule's fixed title. What happened (the file, the root), the labels (kept_away, reasoning_absent)
and the tiers of everything a check relied on (also decision: the arguments the signer decided on; observer: a kernel
sensor; operator: --project) are in `shown`: printed, never signed. `--json` prints the whole result
(docs/findings.md).

Intent is only what a person typed: a prompt line of the main Claude Code transcript (not isMeta, a compaction
summary, command output, a tool result or a sub-agent's prompt), the newest user message of a recorded model request,
an input observed as trusted. The gateway's record of a model message is preferred where an agent's report of it
exists too; two reports of one message from different event streams make its reasoning not checkable
(conflicting_reports), and their text clears nothing. Ordering is computed from run_seq: a reasoning link is
`signed_before` the call's decision, in `transcript_order` (a transcript line the signer recorded after the decision,
before the tool use in the file), or `after`.
"""
import argparse
import bisect
import json
import os
import posixpath
import re
import shlex
import sys
import tempfile
import time

from . import findings_text, parsers
from .findings import SEVERITY, WRITE_TOOLS

BUDGET_S = 60.0
MAX_TEXT = 1 << 16    # lean: characters of one record's text a check reads; past it a long prompt or answer is cut
MAX_NAMES = 1 << 17   # distinct words the mention index holds; past it the analysis stops (budget)
MAX_CITES = 8
EXCERPT = 600
SHELL_TOOLS = ("Bash", "bash", "shell")

# the fixed titles the signer writes beside a signed finding (rpc_schema.FINDING_TITLES once review_finding is in)
TITLES = {"TK-X200": "Check coverage", "TK-X201": "Action with no reasoning before it",
          "TK-X202": "Edit of a file not mentioned before", "TK-X203": "Write outside the project",
          **findings_text.TITLES}
SEVERITIES = {"TK-X201": "info", "TK-X202": "medium", "TK-X203": "high", **findings_text.SEVERITIES}
WHY = {   # rule -> (why it matters, what to do)
    "TK-X201": ("nothing the model said explains this action, so there is no stated reason to check it against",
                "read the action and its result; if the model's reasoning was withheld, turn on thinking summaries"),
    "TK-X202": ("the agent changed a file nobody asked about, without saying why",
                "review the change to this file and ask the person who ran the agent whether they wanted it"),
    "TK-X203": ("an agent working on one project changed a file elsewhere on the machine",
                "check that file and what the change did; keep the agent's writes inside the project with a policy "
                "rule or a sandbox"),
    **findings_text.WHY,
}
REASONS = {   # not checkable: (why, the exact change that makes it checkable)
    "no_response": ("no model response was recorded for this call",
                    "Claude Code: run `tracekit init --dev --v2` (its transcript tailer records each model message); "
                    "other agents: send model calls through the Tracekit LLM gateway (docs/gateway.md)"),
    "unlinked": ("the call was decided under an id of the adapter's own, which no model response carries",
                 "use an integration that decides under the provider's tool call id (docs/integrations/)"),
    "no_content": ("the signer kept no content for the records this check reads",
                   "set `content: {retain: true}` in signer.yaml (the dev signer keeps it unless "
                   "TRACEKIT_DEV_CONTENT=0) and grant the analysing identity content_read"),
    "withheld": ("the model's reasoning was withheld or sealed, so it can't be read",
                 'Claude Code: `tracekit init --dev --v2` sets "showThinkingSummaries": true (or set it in its '
                 "settings); headless: `claude -p --thinking-display summarized`; API: thinking display "
                 '"summarized", Responses reasoning.summary "auto"'),
    "conflicting_reports": ("two event streams reported the model message this call came from",
                            "send model calls through the Tracekit LLM gateway (docs/gateway.md): its record is "
                            "preferred"),
    "no_text": ("neither a request nor anything the model said before the call was recorded",
                "Claude Code: `tracekit init --dev --v2` with the content vault on (the dev signer keeps it)"),
    "no_root": ("the project directory is unknown", "pass --project DIR"),
    "root_too_broad": ("the project directory is / or a home directory", "pass --project DIR"),
    "relative_path": ("a relative path with no working directory for the call",
                      "Claude Code: `tracekit init --dev --v2` (the transcript tailer records each call's cwd)"),
    "budget": ("the analysis reached its time or size budget", "pass --budget SECONDS, larger than the default 60"),
    **findings_text.REASONS,
}
CHECKS = ("TK-X201", "TK-X202", "TK-X203", *findings_text.CHECKS)
FORMS = ("full", "summary", "withheld", "none", "unknown")   # the monitorability classes, best first
TIERS = ("operator", "observer", "gateway", "decision", "sdk", "transcript")   # trust, best first
TEXT_TIERS = ("transcript", "sdk", "gateway")   # weakest first: a finding names the weakest text it relied on

WORD = re.compile(r"[\w.~/\\-]+")   # path-like runs: a word, a file name, a path
# lean: a clause ends at a sentence end, a comma or semicolon, "but", "except" or "though": "fix pager.py but leave
# billing.py alone" keeps billing.py away and asks for pager.py; "don't touch a.py, b.py" keeps only a.py away
CLAUSE = re.compile(r"(?<=[.!?])\s+|\n+|[,;:]\s*|\s+(?:but|except|though)\s+", re.I)
FILE_LIKE = re.compile(r"\w\.\w|/")
WORDS = re.compile(r"[a-z']+")
KEEP_WORDS = frozenset(("untouched", "unchanged", "intact"))
NEGATIONS = frozenset(("not", "never", "don't", "dont", "won't", "wont", "mustn't", "shouldn't", "without", "avoid"))
VERBS = frozenset(("touch", "touching", "touched", "modify", "modifying", "modified", "edit", "editing", "edited",
                   "change", "changing", "changed", "delete", "deleting", "deleted", "alter", "altering", "rewrite",
                   "overwrite", "update", "updating", "remove", "removing"))
COMMAND_OUTPUT = ("<command-", "<local-command-", "<bash-stdout", "<bash-stderr")
WRITERS = {"tee": "all", "touch": "all", "mkdir": "all", "rm": "all", "rmdir": "all", "truncate": "all",
           "cp": "last", "mv": "last", "install": "last", "ln": "last"}
SEPARATORS = (";", ";;", "&&", "||", "|", "|&", "&", "(", ")")


class Budget(Exception):
    pass


# --------------------------------------------------------------------------- reading text

def _text(v):
    return v[:MAX_TEXT] if isinstance(v, str) else ""


def _blocks_text(content):
    """The text of a message's content: a string, or its text blocks; None when it holds a tool result."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    if any(isinstance(b, dict) and str(b.get("type", "")).endswith(("tool_result", "function_response")) for b in content):
        return None
    return "\n".join(b["text"] for b in content if isinstance(b, dict) and isinstance(b.get("text"), str))


def _tailer(body):
    return isinstance(body, dict) and set(body) == {"transcript", "entry"} and isinstance(body["entry"], dict)


def _prompt(body):
    """(the text a person typed, the line's cwd) of a transcript line, or None when it is no human prompt."""
    e = body["entry"]
    msg = e.get("message") if isinstance(e.get("message"), dict) else {}
    if (body["transcript"] != "main" or e.get("type") != "user" or e.get("isMeta") or e.get("isCompactSummary")
            or e.get("isSidechain")):
        return None
    text = _blocks_text(msg.get("content"))
    if not text or text.lstrip().startswith(COMMAND_OUTPUT):
        return None
    return text, e.get("cwd") if isinstance(e.get("cwd"), str) else None


def _asked(body):
    """The newest user message of a model request body (Anthropic or OpenAI chat messages, Responses input, Gemini
    contents): what a person typed there, as far as the request shows; None without one."""
    if not isinstance(body, dict):
        return None
    for key, role in (("messages", "role"), ("input", "role"), ("contents", "role")):
        v = body.get(key)
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v:
            last = v[-1]
            if isinstance(last, dict) and last.get(role) == "user":
                return _blocks_text(last.get("content", last.get("parts")))
            return None
    return None


def _message(body, data):
    """(kind, response) parsers.said reads from a model.exchange response's content."""
    if _tailer(body):
        msg = body["entry"].get("message") if isinstance(body["entry"].get("message"), dict) else {}
        return "anthropic:messages", {"id": msg.get("id"), "content": msg.get("content")}
    for key, kind in (("candidates", "gemini:generate_content"), ("output", "openai:responses"),
                      ("choices", "openai:chat")):
        if isinstance(body, dict) and key in body:
            return kind, body
    return "anthropic:messages", body


def _keep_away(sentence):
    words = set(WORDS.findall(sentence.lower()))
    return bool(words & KEEP_WORDS or {"leave", "alone"} <= words or {"left", "alone"} <= words
                or (words & NEGATIONS and words & VERBS))


def _names(text):
    """[(name, kept away)] of the words of `text`, each a lower-cased basename. A clause that names a file to keep away
    from it ("leave billing.py untouched", "don't modify billing.py") marks that file kept away; its other words are
    no mention."""
    out = []
    for clause in CLAUSE.split(_text(text)):
        away = None
        for m in WORD.finditer(clause):
            name = re.split(r"[/\\]", m.group().strip(".-~"))[-1].strip(".").lower()
            if name:
                if away is None:
                    away = _keep_away(clause)
                if not away or FILE_LIKE.search(m.group()):
                    out.append((name, away))
    return out


def _targets(cmd):
    """(paths, cd) of a shell command: what it writes as far as a lexer can tell, and whether it changes directory.
    lean: redirections, tee/touch/mkdir/rm/rmdir/truncate arguments and cp/mv/install/ln destinations; a word with a
    variable, a glob or a command substitution is skipped. Parse the shell properly if it misses real writes."""
    try:
        lex = shlex.shlex(_text(cmd), posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:
        return [], False
    out, cd, cur, skip = [], False, [], None

    def flush():
        nonlocal cd
        if cur:
            name, args = posixpath.basename(cur[0]), [w for w in cur[1:] if not w.startswith("-")]
            cd = cd or name in ("cd", "pushd")
            out.extend(args if WRITERS.get(name) == "all" else args[-1:] if WRITERS.get(name) == "last" and
                       len(args) > 1 else [])
        cur.clear()
    for w in words:
        if skip is not None:
            if skip and not w.isdigit() and w != "-":
                out.append(w)
            skip = None
        elif w in SEPARATORS:
            flush()
        elif set(w) <= set("<>&|") and ">" in w:   # a redirection: its target is the next word
            if cur and cur[-1].isdigit():
                cur.pop()
            skip = True
        elif set(w) <= set("<&|") and "<" in w:   # input: the next word is read, not written
            skip = False
        else:
            cur.append(w)
    flush()
    return [t for t in out if not set(t) & set("$`*?[")], cd


def _under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


# --------------------------------------------------------------------------- the run

class _Run:
    """One run's records, read once without content (calls, the responses that carry each tool use, the event
    streams of each model message), then with it, one record at a time (`feed`)."""

    def __init__(self, records):
        self.records = sorted(records, key=lambda r: r["event"]["run_seq"])
        self.by_seq = {r["event"]["run_seq"]: r for r in self.records}
        first = self.records[0]["event"]
        self.run_id, self.agent = first["run_id"], ((first["data"].get("agent") or {}).get("name")
                                                      if first["type"] == "run.registered" else None)
        self.final = any(r["event"]["type"] == "run.final" for r in self.records)
        self.calls, self.carriers, self.groups, self.streams, self.effects = {}, {}, {}, {}, []
        self.synthetic = False
        for r in self.records:
            e, d = r["event"], r["event"]["data"]
            if e["type"] == "policy.decision":
                self.calls[d["tool_use_id"]] = {"decision": r}   # a later attempt replaces an earlier one
            elif e["type"] == "tool.result" and d.get("tool_use_id") in self.calls:
                self.calls[d["tool_use_id"]]["result"] = r
            elif e["type"] == "model.exchange" and d.get("phase") == "response":
                x = d.get("exchange_id")
                if x is not None:
                    self.groups.setdefault(x, []).append(e["run_seq"])
                    self.streams.setdefault(x, set()).add(e.get("stream") or e["source"])
                for t in d.get("tool_uses") or ():
                    if t.get("executed_by") != "provider":
                        self.carriers.setdefault(t["id"], []).append(e["run_seq"])
                        self.synthetic = self.synthetic or bool(t.get("id_synthetic"))
            elif e["type"] == "effect.observed" and d.get("kind") == "file" and isinstance(d.get("path"), str):
                self.effects.append(r)
            elif e["type"] == "run.final" and (d.get("coverage") or {}).get("paired_by_args"):
                self.synthetic = True
        self.ran = {c: v for c, v in self.calls.items()
                    if v["decision"]["event"]["data"].get("decision") in ("allow", "flag") or "result" in v}
        # what pass 2 learns
        self.content, self.tier, self.redacted = set(), {}, set()
        self.segs = {}    # response run_seq -> [(kind, form, readable, tool ids right after it, excerpt)]
        # name -> its first (position, run_seq, tier) in what a person asked ("asked") or the model said ("said"),
        # and in a sentence keeping away from it ("kept_asked", "kept_said")
        self.names = {"asked": {}, "said": {}, "kept_asked": {}, "kept_said": {}}
        self.intent, self.prose = [], []   # run_seqs of intent records; positions of readable model text
        self.args, self.cwd, self.root = {}, {}, None

    def conflicting(self, x):
        return len(self.streams.get(x, ())) > 1

    def needed(self):
        """The records whose content the checks read."""
        decisions = {v["decision"]["event"]["run_seq"] for v in self.ran.values()}
        return [r for r in self.records if r["event"]["type"] == "model.exchange" or r["event"]["run_seq"] in decisions
                or r["event"]["type"] == "input.observed" and r["event"]["data"].get("trust") == "trusted"]

    def _mention(self, text, pos, seq, tier, source):
        for name, away in _names(text):
            index = self.names[("kept_" if away else "") + source]
            if name not in index:
                if sum(map(len, self.names.values())) >= MAX_NAMES:
                    raise Budget()
                index[name] = (pos, seq, tier)

    def first(self, index, name, pos):
        """(position, run_seq, tier) of `name`'s first mention in `index` before position `pos`, or None."""
        m = self.names[index].get(name)
        return m if m and m[0] < pos else None

    def feed(self, r, body, opened):
        """Read record r's content (`body`; `opened` False: redaction changed it)."""
        e, d = r["event"], r["event"]["data"]
        seq = e["run_seq"]
        self.content.add(seq)
        if not opened:
            self.redacted.add(seq)
        if e["type"] == "policy.decision":
            self.tier[seq] = "decision"
            if d["tool"] in WRITE_TOOLS and isinstance(body, dict):
                path = body.get("file_path") or body.get("notebook_path") or body.get("path")
                self.args[seq] = {"paths": [path] if isinstance(path, str) else [], "cd": False, "edit": True}
            elif d["tool"] in SHELL_TOOLS and isinstance(body, dict) and isinstance(body.get("command"), str):
                paths, cd = _targets(body["command"])
                self.args[seq] = {"paths": paths, "cd": cd, "edit": False}
            return
        tier = "gateway" if e["source"] == "gateway" else "transcript" if _tailer(body) else "sdk"
        self.tier[seq] = tier
        if _tailer(body) and isinstance(body["entry"].get("cwd"), str):
            self.cwd[seq] = body["entry"]["cwd"]
        if e["type"] == "input.observed":
            text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)[:MAX_TEXT]
        elif d.get("phase") == "request":
            prompt = _prompt(body) if _tailer(body) else None
            text = prompt[0] if prompt else None if _tailer(body) else _asked(body)
            if prompt and prompt[1] and self.root is None:
                self.root = (prompt[1], seq)
        else:
            if self.conflicting(d.get("exchange_id")):   # text that may be forged clears nothing
                self.segs[seq] = [(s["kind"], s["form"], bool(s["text"].strip()), s["tools"], "")
                                  for s in parsers.said(*_message(body, d))]
                return
            segs = parsers.said(*_message(body, d))
            self.segs[seq] = [(s["kind"], s["form"], bool(s["text"].strip()), s["tools"], s["text"][-EXCERPT:])
                              for s in segs]
            for k, s in enumerate(segs):
                if s["text"].strip():
                    self.prose.append((seq, k))
                    self._mention(s["text"], (seq, k), seq, tier, "said")
            return
        if text:
            self.intent.append(seq)
            self._mention(text, (seq, -1), seq, tier, "asked")

    # ----------------------------------------------------------------------- per call

    def carrier(self, tcid):
        """The run_seq of the response that asked for call `tcid`: the gateway's when it recorded one."""
        seqs = self.carriers.get(tcid) or []
        gw = [s for s in seqs if self.by_seq[s]["event"]["source"] == "gateway"]
        return (gw or seqs or [None])[0]

    def said_before(self, tcid):
        """(segments said before the call in its model message [(run_seq, kind, form, readable, excerpt)], the call's
        position among the records' text (run_seq, index of its first segment after the call), a reason it is not
        checkable or None)."""
        decision = self.calls[tcid]["decision"]["event"]["run_seq"]
        cs = self.carrier(tcid)
        if cs is None:
            return [], (decision, 0), "unlinked" if self.synthetic else "no_response"
        e = self.by_seq[cs]["event"]
        x = e["data"].get("exchange_id")
        if x is not None and self.conflicting(x) and e["source"] != "gateway":
            return [], (cs, 0), "conflicting_reports"
        before, k = [], -1
        group = self.groups.get(x, [cs]) if x is not None and e["source"] != "gateway" else [cs]
        for s in group:   # a transcript writes a line per content block, each its own record
            if s > cs:
                break
            if s not in self.content:
                before.append((s, None, "missing", False, ""))
                continue
            for i, (kind, form, readable, tools, excerpt) in enumerate(self.segs.get(s, ())):
                if s == cs and k >= 0:
                    break
                before.append((s, kind, form, readable, excerpt))
                if tcid in tools and s == cs:
                    k = i
        if cs in self.content and k < 0:   # the tool use came before any text of its own record
            before = [b for b in before if b[0] != cs]
        return before, (cs, k + 1), None

    def reasoning(self, tcid):
        """(form: the reasoning before the call, one of FORMS; TK-X201's outcome: a reason it is not checkable, or
        "checked" when the model said something readable before the call (reasoning or text), "none" when nothing; the
        records said before it; the last readable excerpt). Text without reasoning is form `none`: it explains the
        call, but it is not the model's reasoning."""
        before, _, why = self.said_before(tcid)
        if why:
            return "unknown", why, [], ""
        thought = [b for b in before if b[1] == "reasoning"]
        readable = [b for b in before if b[3]]
        form = ("full" if any(b[2] == "full" and b[3] for b in thought) else "summary" if any(b[3] for b in thought)
                else "withheld" if thought else "none")
        seqs = sorted({b[0] for b in before if b[2] != "missing"})
        if readable:
            return form, "checked", seqs, readable[-1][4]
        if thought:
            return form, "withheld", seqs, ""
        if any(b[2] == "missing" for b in before) or self.carrier(tcid) not in self.content:
            return "unknown", "no_content", [], ""
        return form, "none", seqs, ""

    def order(self, tcid, seqs):
        decision = self.calls[tcid]["decision"]["event"]["run_seq"]
        if seqs and max(seqs) < decision:
            return "signed_before"
        return "transcript_order" if seqs and all(self.tier.get(s) == "transcript" for s in seqs) else "after"


# --------------------------------------------------------------------------- the checks

def _cite(run, seqs):
    return [{"run_seq": s, "hash": run.by_seq[s]["hash"]} for s in sorted(set(seqs))[-MAX_CITES:]]


def _tiers(run, seqs, extra=()):
    found = {run.tier.get(s) for s in seqs} | set(extra)
    return [t for t in TIERS if t in found]


def _finding(run, rule, seqs, severity=None, order=None):
    """A finding as review_finding takes it: {verdict, cites}, no text of the run (rpc_schema.REVIEW)."""
    tier = next((t for t in TEXT_TIERS if t in {run.tier.get(s) for s in seqs}), None)
    return {"verdict": {"kind": "finding", "rule": rule, "severity": severity or SEVERITIES[rule],
                        **({"tier": tier} if tier else {}), **({"order": order} if order else {}),
                        **({"redacted": True} if run.redacted & set(seqs) else {})},
            "cites": _cite(run, seqs)}


def _home_like(root):
    return root == "/" or root == os.path.expanduser("~") or posixpath.dirname(root) in ("/home", "/Users")


def _allowed(path, allow):
    return path in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty") or path.startswith("/dev/fd/") or any(
        _under(path, a) for a in allow)


def _outside(run, facts, cs, root, allow):
    """(the paths of a call's writes outside the project, whether one was relative with no directory to resolve it
    against)."""
    outside, unresolved = [], False
    for p in facts["paths"]:
        if p.startswith("~"):   # the agent's home: never inside a project (a home is no project root)
            outside.append(p)
            continue
        if not p.startswith("/"):
            base = None if facts["cd"] else run.cwd.get(cs) or (root if facts["edit"] else None)
            if base is None:
                unresolved = True
                continue
            p = posixpath.join(base, p)
        p = posixpath.normpath(p)
        if not _under(p, root) and not _allowed(p, allow):
            outside.append(p)
    return outside, unresolved


def _check(run, out, project, allow, deadline, clock):
    cov = {r: {"checked": 0, "found": 0, "not_checkable": {}, "tier": set()} for r in CHECKS}
    forms, shown = dict.fromkeys(FORMS, 0), out["shown"]

    def note(call, rule, status, tiers=(), finding=None, what=None, labels=()):
        """Count a check's outcome: a reason it is not checkable, "checked", or a finding."""
        c = cov[rule]
        if status in REASONS:
            c["not_checkable"][status] = c["not_checkable"].get(status, 0) + 1
        else:
            c["checked"] += 1
            c["tier"].update(tiers)
        if finding:
            c["found"] += 1
            out["findings"].append(finding)
            shown["details"].append({"what": what, "tiers": list(tiers), "labels": list(labels)})
        if call is not None:
            call["checks"][rule] = "found" if finding else status

    root, root_seqs, root_tier = None, [], []
    if project:
        root, root_tier = posixpath.normpath(os.path.abspath(project)), ["operator"]
    elif run.root:
        root, root_seqs = posixpath.normpath(run.root[0]), [run.root[1]]
    root_why = "no_root" if root is None else "root_too_broad" if _home_like(root) else None
    allow = [posixpath.normpath(a) for a in ("/tmp", "/private/tmp", "/var/tmp", tempfile.gettempdir(),
                                              os.path.realpath(tempfile.gettempdir()), *(allow or ()))]
    pending, explained = [], 0
    for tcid, c in sorted(run.ran.items(), key=lambda kv: kv[1]["decision"]["event"]["run_seq"]):
        if clock() > deadline:
            raise Budget()
        dec = c["decision"]["event"]
        tool, dseq, cs = dec["data"]["tool"], dec["run_seq"], run.carrier(tcid)
        form, x201, rseqs, excerpt = run.reasoning(tcid)
        forms[form] += 1
        call = shown["calls"][tcid] = {"tool": tool, "form": form, "order": run.order(tcid, rseqs) if rseqs else None,
                                       "seqs": rseqs, "excerpt": excerpt, "checks": {}}
        # TK-X201
        if x201 == "none":
            pending.append((call, tcid, [dseq, cs, *rseqs]))
        elif x201 == "checked":
            explained += 1
            note(call, "TK-X201", "checked", _tiers(run, [cs, *rseqs]))
        else:
            note(call, "TK-X201", x201)
        facts = run.args.get(dseq)
        # TK-X202
        if tool in WRITE_TOOLS:
            pos = run.said_before(tcid)[1]
            i, prose = bisect.bisect_left(run.intent, pos[0]), bisect.bisect_left(run.prose, pos) > 0
            if not facts or not facts["paths"]:
                note(call, "TK-X202", "no_content")
            elif not i and not prose:
                note(call, "TK-X202", "no_text")
            else:
                name = posixpath.basename(facts["paths"][0]).lower()
                asked, said = run.first("asked", name, pos), run.first("said", name, pos)
                kept = run.first("kept_asked", name, pos) or run.first("kept_said", name, pos)
                kept_by_request = bool(run.first("kept_asked", name, pos)) and not asked
                seqs = [dseq, *([cs] if cs is not None else []), *run.intent[max(0, i - 3):i]]
                hit = kept_by_request or not (asked or said)
                note(call, "TK-X202", "checked", _tiers(run, seqs), hit and _finding(
                    run, "TK-X202", seqs + ([kept[1]] if kept else []), order=call["order"]),
                    f"{tool} changed {facts['paths'][0]}; " + (
                        "the request named it only to keep it unchanged" if kept_by_request else
                        f"neither the request nor the model's text before the call names {name}")
                    + ("" if prose else " (no model text was readable: checked against the request only)"),
                    (["kept_away"] if kept else []) + ([] if prose else ["reasoning_absent"]))
        # TK-X203
        if dseq not in run.content:
            note(call, "TK-X203", "no_content")
        elif not facts or not facts["paths"]:
            note(call, "TK-X203", "checked", ["decision"])   # no write a lexer can see
        elif root_why:
            note(call, "TK-X203", root_why)
        else:
            outside, unresolved = _outside(run, facts, cs, root, allow)
            seqs = [dseq, *root_seqs, *([cs] if cs in run.cwd else [])]
            if unresolved and not outside:
                note(call, "TK-X203", "relative_path")
            else:
                note(call, "TK-X203", "checked", _tiers(run, seqs, root_tier), outside and _finding(
                    run, "TK-X203", seqs, order=call["order"]),
                    f"{tool} wrote {', '.join(outside[:3])}, outside the project {root} "
                    f"({'--project' if project else f'the cwd of the first prompt, record {root_seqs[0]}'})")
    checkable = explained + len(pending)
    for call, tcid, seqs in pending:   # info, or low when most checkable calls had reasoning
        note(call, "TK-X201", "checked", _tiers(run, [seqs[1]]), _finding(
            run, "TK-X201", [s for s in seqs if s is not None],
            severity="low" if checkable and explained / checkable > 0.5 else "info"),
            f"{call['tool']} (call {tcid}) came with nothing said before it in the model's message")
    for r in run.effects:
        p = posixpath.normpath(r["event"]["data"]["path"])
        run.tier[r["event"]["run_seq"]] = "observer"
        if root_why:
            note(None, "TK-X203", root_why)
            continue
        seqs = [r["event"]["run_seq"], *root_seqs]
        note(None, "TK-X203", "checked", _tiers(run, seqs, root_tier), not _under(p, root) and not _allowed(
            p, allow) and _finding(run, "TK-X203", seqs),
            f"the kernel sensor saw {r['event']['data'].get('binary', 'a process')} write {p}, outside the project "
            f"{root}")
    return cov, forms


def analyze(records, content=None, project=None, allow=(), partial=False, budget_s=BUDGET_S, clock=time.monotonic):
    """The checks over one run's v2 records. `content(records)`: (run_seq, content, opened) of those of `records` the
    vault holds content for, in run_seq order (why.signed.vault_content), or None (no vault: little is checkable).
    -> the --json shape (docs/findings.md): {"run_id", "agent", "summary": the one line, "findings": [{verdict,
    cites}], "coverage": {verdict, cites} (TK-X200), "shown": what printing shows, plaintext, never signed
    ("details" per finding, "tiers" per check, "constraints", "calls": tool_use_id -> the reasoning before it and each
    check's outcome)}; each {verdict, cites} is what review_finding signs. EvidenceAlert (from `content`) when the
    vault's content does not open its record."""
    run, deadline = _Run(records), clock() + budget_s
    out = {"run_id": run.run_id, "agent": run.agent, "findings": [],
           "shown": {"details": [], "constraints": [], "calls": {}}}
    cov, forms, budget = None, dict.fromkeys(FORMS, 0), False
    try:
        needed = run.needed()
        got = iter(content(needed) if content else ())
        nxt = next(got, None)
        for r in needed:
            if clock() > deadline:
                raise Budget()
            seq = r["event"]["run_seq"]
            while nxt is not None and nxt[0] < seq:
                nxt = next(got, None)
            if nxt is not None and nxt[0] == seq:
                run.feed(r, nxt[1], nxt[2])
        cov, forms = _check(run, out, project, allow, deadline, clock)
        findings_text.check(run, content, out, cov, deadline, clock)
    except Budget:
        budget, out["findings"], out["shown"]["details"] = True, [], []
        out["shown"]["calls"] = {}
    if budget:
        n = len(run.ran)
        cov = {r: {"checked": 0, "found": 0, "not_checkable": {"budget": n} if n else {}, "tier": set()}
               for r in CHECKS}
        forms = dict.fromkeys(FORMS, 0)
        forms["unknown"] = n
    out["coverage"] = {"verdict": {
        "kind": "coverage", "rule": "TK-X200", "severity": "info",
        "checks": {r: {"checked": c["checked"], "found": c["found"],
                       "not_checkable": [{"reason": k, "n": n} for k, n in sorted(c["not_checkable"].items())]}
                   for r, c in cov.items()},
        **({"partial": True} if partial or not run.final else {}),
        "reasoning": {k: forms[k] for k in FORMS if k != "unknown"}}, "cites": []}
    out["shown"]["tiers"] = {r: [t for t in TIERS if t in c["tier"]] for r, c in cov.items()}
    out["shown"]["constraints"] = sorted(({"name": n, "run_seq": s, "tier": t, "source": src}
                                          for index, src in (("kept_asked", "request"), ("kept_said", "model"))
                                          for n, (_, s, t) in run.names[index].items()),
                                         key=lambda c: c["run_seq"])[:50]
    order = {s: i for i, s in enumerate(reversed(SEVERITY))}
    pairs = sorted(zip(out["findings"], out["shown"]["details"]), key=lambda fd: (
        order[fd[0]["verdict"]["severity"]], fd[0]["cites"][0]["run_seq"] if fd[0]["cites"] else 0))
    out["findings"], out["shown"]["details"] = [f for f, _ in pairs], [d for _, d in pairs]
    out["summary"] = summary(out)
    return out


# --------------------------------------------------------------------------- printing

def _pct(n, d):
    return f"{round(100 * n / d)}%" if d else "n/a"


def monitorability(coverage):
    """(actions, readable: full + summary) of a coverage verdict: every call the run ran is one TK-X201 checked or
    could not check."""
    x201 = coverage["checks"]["TK-X201"]
    actions = x201["checked"] + sum(g["n"] for g in x201["not_checkable"])
    return actions, coverage["reasoning"]["full"] + coverage["reasoning"]["summary"]


def summary(out):
    """The one line a person reads first. Findings are an opinion about the run, never part of its integrity."""
    sev = [f["verdict"]["severity"] for f in out["findings"]]
    probs = [x for x in sev if x != "info"]
    worst = ", ".join(f"{probs.count(x)} {x}" for x in reversed(SEVERITY) if x in probs)
    actions, readable = monitorability(out["coverage"]["verdict"])
    return (f"Findings for run {out['run_id']}: " + (f"{len(probs)} problem{'s' * (len(probs) != 1)} ({worst})"
                                                     if probs else "no problems found")
            + (f", {len(sev) - len(probs)} note{'s' * (len(sev) - len(probs) != 1)}" if len(sev) > len(probs) else "")
            + f" · reasoning readable before {readable} of {actions} actions ({_pct(readable, actions)})"
            + (" · PARTIAL: the run is still open" if out["coverage"]["verdict"].get("partial") else ""))


def render(out):
    lines = [summary(out), ""]
    for f, d in zip(out["findings"], out["shown"]["details"]):
        v = f["verdict"]
        why, todo = WHY[v["rule"]]
        labels = d["labels"] + (["redacted"] if v.get("redacted") else [])
        lines += [f"{v['severity'].upper()} · {TITLES[v['rule']]}  ({v['rule']})"
                  + (f" [{', '.join(labels)}]" if labels else ""),
                  f"  What happened: {d['what']}",
                  f"  Why it matters: {why}",
                  f"  What to do: {todo}",
                  "  Records: " + ", ".join(f"{c['run_seq']} ({c['hash'][7:19]})" for c in f["cites"])
                  + " · relied on: " + ", ".join("transcript (the agent can write it)" if t == "transcript" else t
                                                 for t in d["tiers"]), ""]
    cov = out["coverage"]["verdict"]
    gaps = [(r, g["reason"], g["n"]) for r, c in cov["checks"].items() for g in c["not_checkable"]]
    if gaps:
        lines.append("Not checkable (never counted as a pass):")
        for r, why, n in gaps:
            plain, fix = REASONS[why]
            lines += [f"  {r} for {n} call{'s' * (n != 1)}: {plain}.", f"    To make it checkable: {fix}"]
        lines.append("")
    if out["shown"]["constraints"]:
        lines.append("Stated constraints (a sentence that names a file to keep away from it):")
        lines += [f"  {c['name']} (record {c['run_seq']}, from the {c['source']})" for c in out["shown"]["constraints"]]
        lines.append("")
    actions, readable = monitorability(cov)
    lines.append(f"Monitorability (the share of actions whose reasoning can be read): {_pct(readable, actions)} of "
                 f"{actions} actions; " + ", ".join(f"{k} {v}" for k, v in cov["reasoning"].items())
                 + ", not known " + str(actions - sum(cov["reasoning"].values()))
                 + ". Withheld: the provider returned the reasoning sealed or not at all. Reasoning is the model's own "
                   "account: self-reported, not proof.")
    lines.append("Checkable share: " + ", ".join(
        f"{r} {_pct(c['checked'], c['checked'] + sum(g['n'] for g in c['not_checkable']))}"
        f" ({c['checked']} checked, {c['found']} found)" for r, c in cov["checks"].items()))
    return "\n".join(lines)


# --------------------------------------------------------------------------- the command

def _latest(data_dir):
    """The run of the store's newest record, other than the signer's own and findings or replay runs."""
    from .signer.pipeline import SIGNER_RUN
    from .why.import_v2 import _store
    r = _store(data_dir)
    try:
        for key, run in sorted(r.runs.items(), key=lambda kv: -kv[1]["seqs"][-1]):
            if key == SIGNER_RUN:
                continue
            first = next(iter(r.iter_run(*key)), None)
            if first and not {"analyzes", "replay_of"} & set(first["event"]["data"]):
                return key[1]
    finally:
        r.close()
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit analyze --v2", description=(
        "Check whether what a v2 run's person asked, what its model said and what its agent did agree (TK-X201 "
        "nothing said before an action, TK-X202 an unmentioned file edited, TK-X203 a write outside the project, "
        "TK-X205 success claimed after a failure, TK-X101..X104 claimed actions that never ran, TK-X111..X114 denied "
        "actions that did, TK-X120 a risky action never mentioned; "
        "TK-X200 coverage and the monitorability score). Exit 0, 4 when a finding is high or worse, 2 on an error."))
    ap.add_argument("--run", help="the run id (default: the store's latest run)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--store", metavar="DIR", help="a signer data dir (default: the dev signer's), read-only")
    src.add_argument("--bundle", metavar="FILE", help="a v2 bundle, verified first with --trust")
    ap.add_argument("--trust", help="with --bundle: the v2 trust config")
    ap.add_argument("--project", metavar="DIR", help="the project directory (default: the first prompt's cwd)")
    ap.add_argument("--allow", metavar="DIR", action="append", default=[],
                    help="a directory outside the project the agent may write (with /tmp and $TMPDIR)")
    ap.add_argument("--open", action="store_true", help="analyse a run that is still open: coverage says partial")
    ap.add_argument("--budget", type=float, default=BUDGET_S, metavar="S", help="seconds the analysis may take")
    ap.add_argument("--dry-run", action="store_true", help="print the findings, sign nothing")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from .sdk.client import Client, SignerUnavailable
    from .signer.pipeline import SIGNER_RUN
    from .signer.rpc_schema import RPCError
    from .signer.service import dev_data_dir
    from .why import import_v2
    from .why.signed import EvidenceAlert, vault_content
    if a.bundle:
        if not a.trust:
            print("tracekit analyze: --bundle needs --trust, the trust config to verify it against", file=sys.stderr)
            return 2
        runs, _, code = import_v2.bundle_records(a.bundle, a.trust)
        if code:
            print(f"tracekit analyze: refused {a.bundle}: it does not verify against {a.trust} (`tracekit verify`)",
                  file=sys.stderr)
            return 2
        runs.pop(SIGNER_RUN[1], None)
        run_id = a.run or (next(iter(runs)) if len(runs) == 1 else None)
        if run_id is None:
            print(f"tracekit analyze: {a.bundle} holds {len(runs)} runs: pass --run", file=sys.stderr)
            return 2
        records = runs.get(run_id)
    else:
        store = a.store or dev_data_dir()
        try:
            run_id = a.run or _latest(store)
            records = run_id and import_v2.store_records(store, run_id).get(run_id)
        except FileNotFoundError as e:
            print(f"tracekit analyze: {e}", file=sys.stderr)
            return 2
    if not records:
        print(f"tracekit analyze: no run to analyse{f' named {run_id}' if run_id else ''}", file=sys.stderr)
        return 2
    if not a.open and not any(r["event"]["type"] == "run.final" for r in records):
        print(f"tracekit analyze: run {run_id} is still open (no run.final yet): what it does next is not in it. Wait "
              "for it to end, or pass --open for a partial analysis", file=sys.stderr)
        return 2
    client, note = Client(), None

    def content(recs):
        nonlocal note
        try:
            yield from vault_content(client, recs, f"tracekit analyze {run_id}")
        except (SignerUnavailable, OSError) as e:
            note = f"the signer can't be reached for content ({e})"
        except RPCError as e:
            if e.code in ("unknown_run", "forbidden", "invalid_request", "unauthenticated"):
                note = f"the signer gave no content: {e}"
            else:
                raise
    try:
        out = analyze(records, content, a.project, a.allow, a.open, a.budget)
    except EvidenceAlert as e:
        print(f"tracekit analyze: EVIDENCE ALERT: {e}", file=sys.stderr)
        return 4
    finally:
        client.close()
    if note:
        print(f"tracekit analyze: {note}: checks that read content are not checkable", file=sys.stderr)
    if not a.dry_run:
        # signing plugs in here (#309 phase 2): each finding and the coverage entry through review_finding, in one
        # findings run (`analyzes`) per pass; until then they are printed only
        print("tracekit analyze: findings are printed, not signed: signing them into the log comes with the "
              "review_finding RPC", file=sys.stderr)
    print(json.dumps(out, indent=2) if a.json else render(out))
    worst = max((SEVERITY.index(f["verdict"]["severity"]) for f in out["findings"]), default=-1)
    return 4 if worst >= SEVERITY.index("high") else 0


if __name__ == "__main__":
    sys.exit(main())
