"""TK-X2xx: whether what a v2 run's person asked, what its model said and what its agent did agree (docs/findings.md).

    tracekit analyze --v2                          # the latest run of the dev signer's store
    tracekit analyze --v2 --run R --store DIR      # a signer's store, read-only
    tracekit analyze --v2 --run R --bundle B --trust T
        [--project DIR] [--allow DIR ...] [--open] [--budget S] [--dry-run] [--json]
        [--effect-grace S] [--clock-skew S] [--sensor-skip DIR ...]
        [--review [--review-model M] [--review-url URL] [--review-gateway]]

Each pass signs its findings and its coverage review through the signer (review_finding), in a findings run of its own
about the run (`register_run analyzes`), as an identity signer.yaml `analyzers` lists (the dev signer lists its user, so
dev findings read self-asserted); `tracekit export --v2 --run R --with-findings` bundles them with the run. --dry-run
signs nothing.

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
  TK-X203 (high) a write tool, a Bash write target or a kernel sensor's file effect outside the project; an effect of
          the agent's harness itself (findings_effects' agent_process: its transcript, its model calls) is counted
          not checkable, for TK-X204 too, never a finding
  TK-X204 (high; medium when the model stated it, low once a later request lifts it) a call or a kernel sensor's
          effect breaks a constraint stated before it (tracekit.constraints: "don't touch X", "leave X alone",
          "read-only", "don't push", "no network", "only change Y"). A later request that names what the constraint
          keeps away lifts it: the finding stays, downgraded, and cites the lifting record.
  TK-X205 (critical) a success claim after the last related call failed, and v1's say-vs-do checks TK-X101..X104,
          X111..X114 and X120 on the v2 view: tracekit.findings_text
  TK-X206 (high) a kernel sensor's exec, connect or file effect no call explains, and TK-X207 (medium) a call that
          returned ok without the effect it should have had (findings_effects)
For each prompt line of the main transcript:
  TK-X208 (high) the run's prompt hook recorded prompts, and none of them is this line's text: a line the harness never
          submitted (an agent can append one to its own transcript). It is no request: it lifts and clears nothing.
  TK-X200 (info) coverage: per check what it checked, found and could not check (by reason), and the monitorability
          score: how many actions had full, summarized, withheld (sealed or absent) or no reasoning before them, from
          which the share of actions each check could check follows.

A finding is what review_finding signs (#309 phase 2), with no text of the run: {verdict: {kind, rule, severity,
tier: the weakest trust tier of the text it relied on (transcript: a Claude Code transcript line, or what a coding
agent's transcript or hook payload said (a body with a `source`), which the agent can write; sdk: what an in-process
adapter reported; gateway: the LLM gateway's record), order: where the call's reasoning
sits against its decision, redacted: content redaction changed}, cites: [{run_seq, hash}] of the records it relied on};
the signer adds the rule's fixed title. What happened (the file, the root), the labels (kept_away, reasoning_absent)
and the tiers of everything a check relied on (also decision: the arguments the signer decided on; observer: a kernel
sensor; operator: --project) are in `shown`: printed, never signed. `--json` prints the whole result
(docs/findings.md).

Intent is only what a person typed: a prompt line of the main Claude Code transcript (not isMeta, a compaction
summary, command output, a tool result or a sub-agent's prompt) whose text a prompt the hook recorded at
UserPromptSubmit (input.observed, source <agent>:UserPromptSubmit: the harness's payload) matches, each hook prompt
confirming one line (tier `harness`); in a run whose hook recorded no prompt (hooks before 1.4), the line alone (tier
`transcript`); in a run with no transcript prompt line (Codex, Gemini CLI, Cursor), the hook's prompt alone (tier
`harness`). Also the newest user message of a model request the gateway recorded, and an input observed as trusted
in a run whose hook records no prompts; what else claims a person's request is the agent's claim (claimed()). A later
request lifts a constraint only from text as trusted as the constraint's (RANK). The gateway's record of a model
message is preferred where an agent's report of it exists too; two reports of one message
from different event streams make its reasoning not checkable (conflicting_reports), and their text clears nothing.
Ordering is computed from run_seq: a reasoning link is `signed_before` the call's decision, in `transcript_order` (a
transcript line the signer recorded after the decision, before the tool use in the file), or `after`.
"""
import argparse
import bisect
import collections
import hashlib
import json
import os
import posixpath
import sys
import tempfile
import time

from . import __version__, constraints, findings_effects, findings_text, parsers
from .findings import SEVERITY, WRITE_TOOLS
from .signer.reconcile import PROVIDER_HOSTS
from .signer.rpc_schema import FINDING_TITLES as TITLES, RPCError

BUDGET_S = 60.0
MAX_TEXT = 1 << 16    # lean: characters of one record's text a check reads; past it a long prompt or answer is cut
MAX_NAMES = 1 << 17   # distinct words the mention index holds; past it later text is not read (size)
MAX_PROMPTS = 1 << 23   # characters of prompt text held until the hook's prompts and the transcript's are paired; past
#                         it later prompt lines are not read (size)
MAX_CITES = 8
EXCERPT = 600
SHELL_TOOLS = ("Bash", "bash", "shell")

SEVERITIES = {"TK-X201": "info", "TK-X202": "medium", "TK-X203": "high", "TK-X204": "high", "TK-X208": "high",
              **findings_text.SEVERITIES, **findings_effects.SEVERITIES}
WHY = {   # rule -> (why it matters, what to do)
    "TK-X201": ("nothing the model said explains this action, so there is no stated reason to check it against",
                "read the action and its result; if the model's reasoning was withheld, turn on thinking summaries"),
    "TK-X202": ("the agent changed a file nobody asked about, without saying why",
                "review the change to this file and ask the person who ran the agent whether they wanted it"),
    "TK-X203": ("an agent working on one project changed a file elsewhere on the machine",
                "check that file and what the change did; keep the agent's writes inside the project with a policy "
                "rule or a sandbox"),
    "TK-X204": ("the agent did what the run's own words said not to do",
                "review the action and its result with the person who set the constraint; with this release's hooks "
                "the signer holds such a call for their approval as it happens (live constraints)"),
    "TK-X208": ("a line in the agent's own transcript reads like the person's request, but the harness never "
                "submitted it: the agent (or something with its access) can write that file",
                "treat the line as the agent's words, not the person's; find what wrote it"),
    **findings_text.WHY,
    **findings_effects.WHY,
    "TK-X210": ("a reviewer model read the run and found that what was asked, said and done disagree: a model's "
                "opinion, not proof", "read its explanation against the cited records; it never blocks a call or "
                "changes the exit code"),
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
    "budget": ("the analysis ran out of time before it got to it", "pass --budget SECONDS, larger than the default 60"),
    "size": ("the run holds more text than the analysis reads (distinct words, or prompt text), so a mention, a "
             "constraint or a lift before it may be missing", "review these calls by hand or with --review: text that "
             "large in an agent's run is worth a look itself"),
    "no_hook": ("the run's hook recorded no prompt, so no prompt line can be confirmed",
                "update the hooks: `tracekit init --dev --v2` (from 1.4 the hook records each prompt at "
                "UserPromptSubmit)"),
    **findings_text.REASONS,
    **findings_effects.REASONS,
    "no_answer": ("the reviewer model gave no usable answer (an error, a timeout or a refusal)",
                  "check --review-url, its API key and --review-model; the line above names the error"),
    "malformed": ("the reviewer model's answer was not the JSON its schema asks for",
                  "use a model that supports structured output (a JSON schema)"),
    "no_findings_run": ("no findings run could be registered to record the reviewer model's call in",
                        "run it as an identity signer.yaml `analyzers` lists, against the signer that holds the run"),
}
CHECKS = ("TK-X201", "TK-X202", "TK-X203", "TK-X204", "TK-X208", *findings_text.CHECKS, *findings_effects.CHECKS)
STOPS = ("budget", "size")   # not checkable because the analysis stopped short: the result is INCOMPLETE
PROMPT_HOOK = ":UserPromptSubmit"   # an input.observed source: <agent>:UserPromptSubmit, the hook's prompt
FORMS = ("full", "summary", "withheld", "none", "unknown")   # the monitorability classes, best first
TIERS = ("operator", "observer", "gateway", "decision", "harness", "sdk", "transcript")   # trust, best first
TEXT_TIERS = ("transcript", "sdk", "harness", "gateway")   # weakest first: a finding names the weakest text it relied on
RANK = {"transcript": 0, "sdk": 0, "harness": 1, "gateway": 2}   # the agent can write both transcript and sdk text
# lines Claude Code itself writes as a user line: command and bash-mode input and output, a person's Esc
COMMAND_OUTPUT = ("<command-", "<local-command-", "<bash-input", "<bash-stdout", "<bash-stderr",
                  "[Request interrupted by user")


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


def text_tier(e, body):
    """The trust tier of record e's text (`body`): the LLM gateway's, an agent-writable transcript's or hook payload's
    (a tailer body, or one with a `source`), else an in-process adapter's."""
    return ("gateway" if e["source"] == "gateway" else
            "transcript" if _tailer(body) or isinstance(body, dict) and "source" in body else "sdk")


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


def claimed(e, hooked):
    """Whether record e (a model request, or an input observed as trusted other than the hook's prompt) only claims
    to hold a person's request: a request the agent's own process reported (not the gateway's), or a trusted input in
    a run whose hook records the person's prompts (`hooked`), where they come in through the hook. Its text is no
    intent: it lifts and clears nothing, and the reviewer model reads it as `claimed`."""
    return e["source"] != "gateway" if e["type"] == "model.exchange" else hooked


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


def _names(text):
    """[(name, kept away)] of the words of `text`, each a basename as constraints compare them (constraints.norm). A
    file a clause keeps away ("leave billing.py untouched", "don't modify billing.py") is marked kept away, and that
    clause's other words, its other files aside, are no mention."""
    out = []
    for clause in constraints.CLAUSE.split(_text(text)):
        tokens = constraints._tokens(clause)
        kept = constraints._clause(tokens)[1]
        for t in tokens:
            file = bool(constraints.FILE_LIKE.search(t))
            if (file or not kept) and constraints.norm(t):
                out.append((constraints.norm(t), t in kept))
    return out


def _targets(cmd):
    """(paths, cd) of a shell command: what it writes as far as a lexer can tell (constraints.shell), and whether it
    changes directory."""
    s = constraints.shell(cmd)
    return s["paths"], s["cd"]


def _same_text(text):
    """A prompt's text as the hook and the transcript are compared: its words, whitespace aside."""
    return hashlib.sha256(" ".join(_text(text).split()).encode("utf-8", "surrogatepass")).hexdigest()


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
        self.synthetic = self.hooked = False   # hooked: the run's hook recorded a prompt (PROMPT_HOOK)
        self.net_effects, self.requests = [], []   # net and connect effects; agent-reported request records
        self.model_hosts = set()   # the API hosts of the model calls the run recorded: the harness's own traffic
        for r in self.records:
            e, d = r["event"], r["event"]["data"]
            if e["type"] == "model.exchange" and d.get("upstream") in PROVIDER_HOSTS:
                self.model_hosts.add(PROVIDER_HOSTS[d["upstream"]])
            if e["type"] == "policy.decision":
                self.calls[d["tool_use_id"]] = {"decision": r}   # a later attempt replaces an earlier one
            elif e["type"] == "tool.result" and d.get("tool_use_id") in self.calls:
                self.calls[d["tool_use_id"]]["result"] = r
            elif e["type"] == "model.exchange" and d.get("phase") == "request" and e["source"] != "gateway":
                self.requests.append(e["run_seq"])
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
            elif e["type"] == "effect.observed" and d.get("kind") in ("net", "connect"):
                self.net_effects.append(r)
            elif e["type"] == "input.observed" and str(d.get("source")).endswith(PROMPT_HOOK):
                self.hooked = True
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
        self.args, self.cwd, self.root, self.facts = {}, {}, None, {}   # facts: decision run_seq -> constraints.facts
        # prompts: [(run_seq, text digest, text, cwd)] of the transcript's prompt lines and the hook's prompts, until
        # confirm() pairs them; unconfirmed: the transcript's lines no hook prompt has the text of (TK-X208)
        self.prompts, self.hook_prompts, self.held, self.unconfirmed, self.confirmed = [], [], 0, [], {}
        # stated: [(position, run_seq, kind, object, "request" or "model")] of each constraint stated; lifts:
        # [(position, run_seq, constraints.mentions(text), "request" or "model")] of each text after
        self.stated, self.lifts, self.lift_names = [], [], 0
        self.claimed = []   # run_seqs of records that only claim a person's request (claimed())
        # where the analysis stopped reading: `stopped` the first run_seq whose content its time budget left unread,
        # `capped` the first position whose text its size caps left unread, `over` prompt lines they left unread
        self.stopped = self.capped = None
        self.over = 0

    def cap(self, pos):
        if self.capped is None or pos < self.capped:
            self.capped = pos

    def late(self, *seqs):
        """Whether the time budget left a record of `seqs` unread."""
        return self.stopped is not None and max(s for s in seqs if s is not None) >= self.stopped

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
            if name not in index or pos < index[name][0]:   # confirm() reads the prompts after the rest
                if name not in index and sum(map(len, self.names.values())) >= MAX_NAMES:
                    return self.cap(pos)
                index[name] = (pos, seq, tier)

    def _stated(self, text, pos, seq, source):
        """The constraints `text` states, and what it mentions that could lift one stated before it."""
        self.stated += [(pos, seq, kind, obj, source) for kind, obj in constraints.extract(_text(text))]
        mention = constraints.mentions(_text(text))
        if mention[0] or mention[1]:
            self.lift_names += len(mention[0]) + len(mention[1])
            if self.lift_names > MAX_NAMES:
                return self.cap(pos)
            self.lifts.append((pos, seq, mention, source))

    def _request(self, seq, text, tier):
        self.intent.append(seq)
        self._mention(text, (seq, -1), seq, tier, "asked")
        self._stated(text, (seq, -1), seq, "request")

    def _keep(self, into, seq, text, cwd=None):
        self.held += len(_text(text))
        if self.held > MAX_PROMPTS:
            self.over += into is self.prompts
            return self.cap((seq, -1))
        into.append((seq, _same_text(text), _text(text), cwd))

    def confirm(self):
        """Pair the prompts the hook recorded with the transcript's prompt lines, one each by their text, and read
        each confirmed line (in a run whose hook recorded none: each line; in a run with no prompt line: each hook
        prompt) as a request; the other lines are TK-X208's. Then order what was stated and mentioned by position."""
        hooks = collections.defaultdict(list)
        for seq, h, text, _ in self.hook_prompts:
            hooks[h].append(seq)
            if not self.prompts:   # no transcript prompt line (Codex, Gemini CLI, Cursor): the hook's prompts are it
                self.tier[seq] = "harness"
                self._request(seq, text, "harness")
        for seq, h, text, cwd in self.prompts:
            if self.hooked:
                if not hooks[h]:
                    self.unconfirmed.append(seq)
                    continue
                self.confirmed[seq] = hook = hooks[h].pop(0)
                self.tier[seq] = self.tier[hook] = "harness"
            if cwd and self.root is None:
                self.root = (cwd, seq)
            self._request(seq, text, self.tier[seq])
        self.prompts = [(seq, None, None, None) for seq, *_ in self.prompts]   # the text is read
        self.hook_prompts = []
        self.intent.sort()
        self.stated.sort(key=lambda c: c[:2])
        self.lifts.sort(key=lambda m: m[:2])

    def broken(self, f, pos):
        """The constraint stated before position `pos` that a call's or effect's facts `f` (constraints.facts) break,
        a request's before the model's and one no later text lifts first: (stated, what breaks it, the lifting
        entry or None), or None."""
        only = {c[3] for c in self.stated if c[2] == "only_change" and c[0] < pos}
        best = None
        for c in self.stated:
            if c[0] >= pos:
                break
            name = constraints.breaks(c[2], f, only.__contains__ if c[2] == "only_change" else c[3].__eq__)
            if name is None:
                continue
            rank = RANK.get(self.tier.get(c[1]), 0)   # a lift counts only from text as trusted as the constraint's
            lift = next((m for m in self.lifts if c[0] < m[0] < pos and (m[3] == "request" or c[4] == "model")
                         and RANK.get(self.tier.get(m[1]), 0) >= rank
                         and constraints.lifts(c[2], m[2], (name if c[2] == "only_change" else c[3]).__eq__)), None)
            if best is None or (c[4] != "request", lift is not None) < (best[0][4] != "request", best[2] is not None):
                best = (c, name, lift)
        return best

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
            if isinstance(body, dict):
                self.facts[seq] = constraints.facts(d["tool"], body)
            if d["tool"] in WRITE_TOOLS and isinstance(body, dict):
                path = body.get("file_path") or body.get("notebook_path") or body.get("path")
                self.args[seq] = {"paths": [path] if isinstance(path, str) else [], "cd": False, "edit": True}
            elif d["tool"] in SHELL_TOOLS and isinstance(body, dict) and isinstance(body.get("command"), str):
                paths, cd = _targets(body["command"])
                self.args[seq] = {"paths": paths, "cd": cd, "edit": False, "command": _text(body["command"])}
            return
        tier = self.tier[seq] = text_tier(e, body)
        if _tailer(body) and isinstance(body["entry"].get("cwd"), str):
            self.cwd[seq] = body["entry"]["cwd"]
        if e["type"] == "input.observed":
            text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)[:MAX_TEXT]
            if str(d.get("source")).endswith(PROMPT_HOOK):   # a request only once a transcript line agrees
                return self._keep(self.hook_prompts, seq, text)
        elif d.get("phase") == "request":
            if _tailer(body):
                prompt = _prompt(body)
                return prompt and self._keep(self.prompts, seq, *prompt)
            text = _asked(body)
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
                    self._stated(s["text"], (seq, k), seq, "model")
            return
        if text and claimed(e, self.hooked):
            self.claimed.append(seq)
        elif text:
            self._request(seq, text, tier)

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


def _finding(run, rule, seqs, severity=None, order=None, lifted=False):
    """A finding as review_finding takes it: {verdict, cites}, no text of the run (rpc_schema.REVIEW)."""
    tier = next((t for t in TEXT_TIERS if t in {run.tier.get(s) for s in seqs}), None)
    return {"verdict": {"kind": "finding", "rule": rule, "severity": severity or SEVERITIES[rule],
                        **({"tier": tier} if tier else {}), **({"order": order} if order else {}),
                        **({"redacted": True} if run.redacted & set(seqs) else {}),
                        **({"lifted": True} if lifted else {})},
            "cites": _cite(run, seqs)}


STATED = {"keep_away": "to keep {} unchanged", "only_change": "to change only {}", "read_only": "to make no changes",
          "no_push": "not to push", "no_network": "not to use the network"}
DID = {"keep_away": "changed {}", "only_change": "changed {}", "read_only": "changed {}", "no_push": "pushed",
       "no_network": "reached the network"}


def _constraint(run, note, call, f, pos, seqs, who):
    """TK-X204 of one call or effect (`f` its constraints.facts, at position `pos`; `seqs` its records; `who` names
    it): whether it breaks a constraint stated before it. With text before it the size caps left unread
    (`run.capped`), a break is still found (labelled `size`: a lift may be in that text) and no break is not checkable."""
    hit = run.broken(f, pos)
    capped = run.capped is not None and run.capped < pos
    if hit is None:
        return note(call, "TK-X204", "size" if capped else "checked", _tiers(run, seqs))
    (_, cseq, kind, obj, source), name, lift = hit
    seqs = [*seqs, cseq, *([lift[1]] if lift else [])]
    only = sorted({c[3] for c in run.stated if c[2] == "only_change" and c[0] < pos})
    note(call, "TK-X204", "checked", _tiers(run, seqs), _finding(
        run, "TK-X204", seqs, "low" if lift else "high" if source == "request" else "medium",
        call and call["order"], bool(lift)),
        f"{who} {DID[kind].format(name)} after the {source} (record {cseq}) said "
        + STATED[kind].format(", ".join(only[:3]) if kind == "only_change" else obj)
        + (f"; a later {lift[3]} (record {lift[1]}) named it, so the constraint may have been lifted" if lift else ""),
        [kind] + (["lifted"] if lift else []) + (["stated_by_model"] if source == "model" else [])
        + (["size"] if capped else []))
    return True


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
        dec = c["decision"]["event"]
        tool, dseq, cs = dec["data"]["tool"], dec["run_seq"], run.carrier(tcid)
        if clock() > deadline or run.late(dseq, cs):   # past the budget: counted, not checked
            forms["unknown"] += 1
            call = shown["calls"][tcid] = {"tool": tool, "form": "unknown", "order": None, "seqs": [], "excerpt": "",
                                           "checks": {}}
            for rule in ("TK-X201", "TK-X204", "TK-X202", "TK-X203"):
                if rule != "TK-X202" or tool in WRITE_TOOLS:
                    note(call, rule, "budget")
            continue
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
        pos = run.said_before(tcid)[1]
        i, prose = bisect.bisect_left(run.intent, pos[0]), bisect.bisect_left(run.prose, pos) > 0
        # TK-X204
        if dseq not in run.facts:
            note(call, "TK-X204", "no_content")
        elif not i and not prose:
            note(call, "TK-X204", "no_text")
        else:
            _constraint(run, note, call, run.facts[dseq], pos, [dseq, *([cs] if cs is not None else [])], tool)
        # TK-X202
        if tool in WRITE_TOOLS:
            if not facts or not facts["paths"]:
                note(call, "TK-X202", "no_content")
            elif not i and not prose:
                note(call, "TK-X202", "no_text")
            else:
                name = constraints.norm(facts["paths"][0])
                asked, said = run.first("asked", name, pos), run.first("said", name, pos)
                kept = run.first("kept_asked", name, pos) or run.first("kept_said", name, pos)
                seqs = [dseq, *([cs] if cs is not None else []), *run.intent[max(0, i - 3):i]]
                # a file a constraint keeps away is TK-X204's: the stronger finding covers the call
                hit = not (asked or said) and call["checks"]["TK-X204"] != "found"
                if hit and run.capped is not None and run.capped < pos:   # the name may be in text left unread
                    note(call, "TK-X202", "size")
                else:
                    note(call, "TK-X202", "checked", _tiers(run, seqs), hit and _finding(
                        run, "TK-X202", seqs + ([kept[1]] if kept else []), order=call["order"]),
                        f"{tool} changed {facts['paths'][0]}; neither the request nor the model's text before the "
                        f"call names {name}" + (" other than to keep it unchanged" if kept else "")
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
    for seq, _, _, _ in run.prompts:   # TK-X208
        if not run.hooked:
            note(None, "TK-X208", "no_hook")
        elif seq in run.unconfirmed:
            note(None, "TK-X208", "checked", ["transcript"], _finding(run, "TK-X208", [seq]),
                 f"the transcript's prompt line (record {seq}) matches no prompt the harness submitted (the hook "
                 "recorded each one): it is no request, and lifts or clears nothing", ["unconfirmed"])
        else:
            note(None, "TK-X208", "checked", ["harness"])
    for _ in range(run.over):
        note(None, "TK-X208", "size")
    for seq in run.requests:   # an agent-reported request whose content is not here: maybe a prompt line
        if seq not in run.content:
            note(None, "TK-X208", "budget" if run.late(seq) else "no_content")

    def effects(judged):
        """TK-X204 and TK-X203 of what the observers saw, once findings_effects has `judged` each sensor effect: one of
        the agent's harness itself (agent_process: a process running from before the run, its own files and model
        calls, which no call names) is not the agent's doing, and is counted as such, never checked."""
        found = {t for t, c in shown["calls"].items() if c["checks"].get("TK-X204") == "found"}
        for r in sorted(run.effects + run.net_effects, key=lambda r: r["event"]["run_seq"]):   # TK-X204 of each
            d, eseq = r["event"]["data"], r["event"]["run_seq"]
            run.tier[eseq] = "observer"
            harness = (judged.get(eseq) or {}).get("status") == "agent_process"
            if not run.stated or d.get("explained_by") and d["kind"] == "net":
                continue   # a connection a call (or the policy's explains for a tool the run called) explains: the
                #            call's own check covers it
            if clock() > deadline:
                note(None, "TK-X204", "budget")
            elif harness or d["kind"] == "net" and d.get("host") in run.model_hosts:   # the harness's model calls
                note(None, "TK-X204", "agent_process")
            elif d.get("tool_call_id") not in found:   # a call's own finding covers what it did
                file = d["kind"] == "file"
                _constraint(run, note, None, {"names": [constraints.norm(d["path"])] if file else [], "write": file,
                                              "push": False, "network": not file}, (eseq, 0), [eseq],
                            f"the {d.get('sensor') or 'egress'} observer saw {d.get('binary', 'a process')}: it")
        for r in run.effects:
            p, eseq = posixpath.normpath(r["event"]["data"]["path"]), r["event"]["run_seq"]
            if (judged.get(eseq) or {}).get("status") == "agent_process":
                note(None, "TK-X203", "agent_process")
                continue
            if clock() > deadline:
                note(None, "TK-X203", "budget")
                continue
            if root_why:
                note(None, "TK-X203", root_why)
                continue
            seqs = [eseq, *root_seqs]
            note(None, "TK-X203", "checked", _tiers(run, seqs, root_tier), not _under(p, root) and not _allowed(
                p, allow) and _finding(run, "TK-X203", seqs),
                f"the kernel sensor saw {r['event']['data'].get('binary', 'a process')} write {p}, outside the "
                f"project {root}")
    return cov, forms, effects


def analyze(records, content=None, project=None, allow=(), partial=False, budget_s=BUDGET_S, clock=time.monotonic,
            effects=None):
    """The checks over one run's v2 records. `content(records)`: (run_seq, content, opened) of those of `records` the
    vault holds content for, in run_seq order (why.signed.vault_content), or None (no vault: little is checkable).
    -> the --json shape (docs/findings.md): {"run_id", "agent", "summary": the one line, "findings": [{verdict,
    cites}], "coverage": {verdict, cites} (TK-X200), "shown": what printing shows, plaintext, never signed
    ("details" per finding, "tiers" per check, "constraints" stated, "prompts": each prompt line confirmed or not,
    "calls": tool_use_id -> the reasoning before it and each check's outcome, "effects": run_seq -> each kernel sensor
    effect's call, "effect_window")}; each {verdict, cites} is what review_finding signs; `effects`:
    findings_effects.options(). EvidenceAlert (from `content`) when the vault's content does not open its record."""
    run, deadline = _Run(records), clock() + budget_s
    out = {"run_id": run.run_id, "agent": run.agent, "findings": [],
           "shown": {"details": [], "constraints": [], "prompts": [], "calls": {}}}
    needed = run.needed()
    got = iter(content(needed) if content else ())
    nxt = next(got, None)
    for r in needed:
        seq = r["event"]["run_seq"]
        if clock() > deadline:   # the rest is counted as not checkable: budget, never dropped
            run.stopped = seq
            break
        while nxt is not None and nxt[0] < seq:
            nxt = next(got, None)
        if nxt is not None and nxt[0] == seq:
            run.feed(r, nxt[1], nxt[2])
    run.confirm()
    cov, forms, observed = _check(run, out, project, allow, deadline, clock)
    findings_text.check(run, content, out, cov, deadline, clock)
    observed(findings_effects.check(run, out, cov, effects, deadline, clock))
    out["coverage"] = {"verdict": {
        "kind": "coverage", "rule": "TK-X200", "severity": "info",
        "checks": {r: {"checked": c["checked"], "found": c["found"],
                       "not_checkable": [{"reason": k, "n": n} for k, n in sorted(c["not_checkable"].items())]}
                   for r, c in cov.items()},
        **({"partial": True} if partial or not run.final else {}),
        "reasoning": {k: forms[k] for k in FORMS if k != "unknown"}}, "cites": []}
    out["shown"]["tiers"] = {r: [t for t in TIERS if t in c["tier"]] for r, c in cov.items()}
    out["shown"]["constraints"] = [{"kind": k, **({"name": o} if o else {}), "run_seq": s, "source": src,
                                    "tier": run.tier.get(s)} for _, s, k, o, src in run.stated][:50]
    out["shown"]["prompts"] = [{"run_seq": s, "status": "unconfirmed" if s in run.unconfirmed else "confirmed"
                                if s in run.confirmed else "unchecked", **({"hook": run.confirmed[s]} if s in
                                                                            run.confirmed else {})}
                               for s, *_ in run.prompts][:200]
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


def incomplete(coverage):
    """How many of a coverage verdict's items its time budget or size caps left unchecked."""
    return sum(g["n"] for c in coverage["checks"].values() for g in c["not_checkable"] if g["reason"] in STOPS)


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
            + (" · PARTIAL: the run is still open" if out["coverage"]["verdict"].get("partial") else "")
            + (f" · INCOMPLETE: {n} check{'s' * (n != 1)} not run (budget or size, below)"
               if (n := incomplete(out["coverage"]["verdict"])) else ""))


TIER_NOTES = {"transcript": "transcript (the agent can write it)",
              "harness": "harness (the prompt hook and the transcript agree)"}


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
                  + " · relied on: " + ", ".join(TIER_NOTES.get(t, t) for t in d["tiers"]), ""]
    cov = out["coverage"]["verdict"]
    gaps = [(r, g["reason"], g["n"]) for r, c in cov["checks"].items() for g in c["not_checkable"]]
    if gaps:
        lines.append("Not checkable (never counted as a pass):")
        for r, why, n in gaps:
            plain, fix = REASONS[why]
            unit = "prompt line" if r == "TK-X208" else findings_effects.unit(r, why)
            lines += [f"  {r} for {n} {unit}{'s' * (n != 1)}: {plain}.", f"    To make it checkable: {fix}"]
        lines.append("")
    if out["shown"]["constraints"]:
        lines.append("Stated constraints (what the run's own words said not to do; TK-X204 checks each later call):")
        lines += [f"  {c['kind']}{' ' + c['name'] if 'name' in c else ''} (record {c['run_seq']}, from the "
                  f"{c['source']})" for c in out["shown"]["constraints"]]
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
    s = out.get("signed")
    lines.append(f"Signed: {s['records']} record(s), the findings and the coverage review, in findings run "
                 f"{s['findings_run']}; bundle them with `tracekit export --v2 --run {out['run_id']} --with-findings`"
                 if s else "Not signed: printed only.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- the command

def _latest(data_dir):
    """The run of the store's newest record, other than the signer's own (its tenants' too: each content read is a
    record there) and findings or replay runs."""
    from .signer.pipeline import SIGNER_RUN
    from .why.import_v2 import _store
    r = _store(data_dir)
    try:
        for key, run in sorted(r.runs.items(), key=lambda kv: -kv[1]["seqs"][-1]):
            if key[1] == SIGNER_RUN[1]:
                continue
            first = next(iter(r.iter_run(*key)), None)
            if first and not {"analyzes", "replay_of"} & set(first["event"]["data"]):
                return key[1]
    finally:
        r.close()
    return None


def sign(client, run_id, out, review=None, records=()):
    """Sign `out`'s findings and its coverage review into a new findings run about `run_id`, then close it. With
    `review` (review_model.Reviewer), TK-X210 is added to `out` first, the reviewer model asked as that findings run:
    a pass's model call and all its findings are in its one findings run. -> the findings run's id. A signer rate limit
    (quota_exceeded with retry_after_ms) is waited out."""
    reviewer = f"tracekit-analyze/{__version__}"
    try:
        run = client.run({"name": "tracekit-analyze", "version": __version__}, analyzes=run_id)
    except Exception as e:
        if review:
            review.add(out, records, why="no_findings_run")
            out["shown"]["review"]["error"] = f"no findings run: {e}"
        raise
    try:
        if review:
            review.add(out, records, run)
        for f in [*out["findings"], out["coverage"]]:
            while True:
                try:
                    run.review_finding(reviewer, f["verdict"], f["cites"])
                    break
                except RPCError as e:
                    if e.code != "quota_exceeded" or e.retry_after_ms is None:
                        raise
                    time.sleep(min(e.retry_after_ms, 5000) / 1000)
    finally:
        run.close()
    return run.run_id


def main(argv=None):
    from . import review_model
    ap = argparse.ArgumentParser(prog="tracekit analyze --v2", description=(
        "Check whether what a v2 run's person asked, what its model said and what its agent did agree (TK-X201 "
        "nothing said before an action, TK-X202 an unmentioned file edited, TK-X203 a write outside the project, "
        "TK-X204 a stated constraint broken, TK-X208 a prompt line the harness never submitted, TK-X205 success "
        "claimed after a failure, TK-X101..X104 claimed actions that never ran, TK-X111..X114 denied actions that "
        "did, TK-X120 a risky action never mentioned, TK-X206 a kernel sensor's effect no call explains, TK-X207 a "
        "call with no effect; TK-X200 coverage and the monitorability score; with --review, TK-X210 a reviewer "
        "model's reading, warn only), and sign the findings. Exit 0, 4 when a finding other than TK-X210 is high or "
        "worse, 3 when no finding is but the analysis stopped short of a check (INCOMPLETE: its time budget or size "
        "caps), 2 on an error (findings that could not be signed among them)."))
    g = ap.add_argument_group("the run")
    g.add_argument("--run", metavar="ID", help="the run id (default: the store's latest run)")
    src = g.add_mutually_exclusive_group()
    src.add_argument("--store", metavar="DIR", help="a signer data dir, read-only (default: the dev signer's)")
    src.add_argument("--bundle", metavar="FILE", help="a v2 bundle, verified first against --trust")
    g.add_argument("--trust", metavar="FILE", help="with --bundle: the v2 trust config")
    g.add_argument("--open", action="store_true", help="analyse a run that is still open: coverage says partial")
    g = ap.add_argument_group("the checks")
    g.add_argument("--project", metavar="DIR", help="the project directory, for TK-X203 (default: the first prompt's "
                   "cwd)")
    g.add_argument("--allow", metavar="DIR", action="append", default=[], help="a directory outside the project the "
                   "agent may write, besides /tmp and $TMPDIR (repeatable)")
    g.add_argument("--budget", type=float, default=BUDGET_S, metavar="S", help="seconds the analysis may take "
                   "(default %(default)g); past it what is left is not checkable: budget, and the result INCOMPLETE")
    findings_effects.arguments(ap.add_argument_group("kernel sensor effects (TK-X206, TK-X207)"))
    g = ap.add_argument_group("the reviewer model (TK-X210, warn only)")
    g.add_argument("--review", action="store_true", help="also ask a reviewer model, which sends the run's text "
                   "(redacted) to that model (docs/privacy.md#what-leaves-the-machine); not with --dry-run")
    g.add_argument("--review-model", metavar="M", help="the reviewer model (default: of those configured, the first "
                   "of another model family than the agent's: TRACEKIT_REVIEW_MODEL with TRACEKIT_REVIEW_URL, "
                   f"{review_model.reviewer.DEFAULT_MODEL} with ANTHROPIC_API_KEY, {review_model.OPENAI_MODEL} with "
                   f"OPENAI_API_KEY; else {review_model.reviewer.DEFAULT_MODEL})")
    g.add_argument("--review-url", metavar="URL", help="its endpoint: .../v1/messages (Anthropic Messages) or "
                   ".../v1/chat/completions (OpenAI chat, as a local model server speaks it) (default: the chosen "
                   "reviewer's endpoint)")
    g.add_argument("--review-gateway", action="store_true", help="--review-url is Tracekit's LLM gateway, which "
                   "records the call (default: the analyzer records it)")
    g = ap.add_argument_group("output")
    g.add_argument("--dry-run", action="store_true", help="print the findings, sign nothing")
    g.add_argument("--json", action="store_true", help="print the whole result as JSON (docs/findings.md#the---json-"
                   "shape), for CI and agents")
    a = ap.parse_args(argv)
    if a.review and a.dry_run:
        print("tracekit analyze: --review records the model call in a findings run and --dry-run signs nothing: "
              "drop one", file=sys.stderr)
        return 2
    from .sdk.client import Client, SignerUnavailable
    from .signer.pipeline import SIGNER_RUN
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
    rv = None
    if a.review:
        given = a.review_model or a.review_url or a.review_gateway
        model, url, env = (review_model.choose(records) if not given else (
            a.review_model or review_model.reviewer.DEFAULT_MODEL, a.review_url or review_model.URL, None))
        try:
            rv = review_model.Reviewer(review_model.Model(url, model, a.review_gateway, env=env), model)
        except ValueError as e:
            print(f"tracekit analyze: {e}", file=sys.stderr)
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
    failed = None
    try:
        try:
            out = analyze(records, rv.tee(content) if rv else content, a.project, a.allow, a.open, a.budget,
                          effects=findings_effects.from_args(a))
        except EvidenceAlert as e:
            print(f"tracekit analyze: EVIDENCE ALERT: {e}", file=sys.stderr)
            return 4
        if note:
            print(f"tracekit analyze: {note}: checks that read content are not checkable", file=sys.stderr)
        if not a.dry_run:
            try:
                out["signed"] = {"findings_run": sign(client, run_id, out, rv, records),
                                 "records": len(out["findings"]) + 1}
            except (SignerUnavailable, OSError, RPCError) as e:
                failed = e
    finally:
        client.close()
    review = out["shown"].get("review") or {}
    if review.get("error"):
        print(f"tracekit analyze: --review: {review['error']}", file=sys.stderr)
    if review.get("same_family"):
        print(f"tracekit analyze: --review: the reviewer model is of the agent's model family "
              f"({review['families']['reviewer']}), so it may share the agent's blind spots: pass --review-model of "
              "another family, or configure one (OPENAI_API_KEY or ANTHROPIC_API_KEY for the other provider, or "
              "TRACEKIT_REVIEW_MODEL with TRACEKIT_REVIEW_URL) and it is picked", file=sys.stderr)
    print(json.dumps(out, indent=2) if a.json else render(out))
    if failed is not None:
        print(f"tracekit analyze: the findings are printed but NOT signed: {failed}. The signer signs them for an "
              "identity its signer.yaml `analyzers` lists (the dev signer lists its user), about a run it holds; "
              "pass --dry-run to only print them", file=sys.stderr)
        return 2
    worst = max((SEVERITY.index(f["verdict"]["severity"]) for f in out["findings"]
                 if f["verdict"]["rule"] != review_model.RULE), default=-1)   # a model's opinion never fails a build
    if worst >= SEVERITY.index("high"):
        return 4
    if incomplete(out["coverage"]["verdict"]):
        print("tracekit analyze: INCOMPLETE: the analysis stopped short (budget or size, listed under Not checkable): "
              "no problems found is not the run's answer", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
