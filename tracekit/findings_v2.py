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
  TK-X202 (medium) a write tool edited a file the person's request doesn't name before the call and the model's text
          never says it changes (a change word tied to it, before the call or after: "applying the same fix to
          billing.py", "billing.py needs the same fix"; constraints.changes). A mere mention ("pager.py imports
          billing.py") clears nothing. A sentence that names a file to keep away from it ("leave billing.py
          untouched") is no mention: it is a constraint, and a file the request kept away is a finding whatever the
          model said about it; the model saying it leaves the file alone, then editing it, is a contradiction
          (TK-X204 when its words state a constraint, else this finding, labelled `contradiction`).
  TK-X203 (high) a write tool, a Bash write target or a kernel sensor's file effect outside the project; an effect of
          the agent's harness itself (findings_effects' agent_process: its transcript, its model calls) is counted
          not checkable, for TK-X204 too, never a finding
  TK-X204 (high; medium when the model stated it, low once a later request lifts it) a call or a kernel sensor's
          effect breaks a constraint stated before it (tracekit.constraints: "don't touch X", "leave X alone",
          "read-only", "don't push", "no network", "only change Y"). A later request that names what the constraint
          keeps away lifts it: the finding stays, downgraded, and cites the lifting record. So does an approval of a
          call a live constraint held, by an identity other than the run's (`approved`); the run's own identity's
          (self-approved: it may be the agent's) lowers nothing (`self_approved`).
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

A finding is what review_finding signs (#309 phase 2), with no text of the run: {verdict: {kind, rule, severity, tier:
the weakest trust tier of the text it relied on (transcript: a Claude Code transcript line, or what a coding agent's
transcript or hook payload said (a body with a `source`), which the agent can write; sdk: what an in-process adapter
reported, or a model request, whose body the agent wrote; gateway: the LLM gateway's record of a model's answer), order:
where the call's reasoning sits against its decision, redacted: content redaction changed}, cites: [{run_seq, hash}] of
the records it relied on}; the signer adds the rule's fixed title. What happened (the file, the root), the labels
(kept_away, reasoning_absent) and the tiers of everything a check relied on (also decision: the arguments the signer
decided on; observer: a kernel sensor; operator: --project) are in `shown`: printed, never signed. `--json` prints the
whole result (docs/findings.md).

Intent is only what a person typed: a prompt line of the main Claude Code transcript (not isMeta, a compaction
summary, command output, a tool result or a sub-agent's prompt) whose text a prompt the hook recorded at
UserPromptSubmit (input.observed, source <agent>:UserPromptSubmit: the harness's payload) matches, each hook prompt
confirming one line (tier `harness`); in a run whose hook recorded no prompt (hooks before 1.4), the line alone (tier
`transcript`); in a run with no transcript prompt line (Codex, Gemini CLI, Cursor), the hook's prompt alone (tier
`harness`). In a run whose hook records no prompts, also the newest user message of a model request the gateway
recorded and an input observed as trusted, both tier `sdk` (the agent's process wrote them: a gateway request's body
too); what else claims a person's request is the agent's claim (claimed()). A line's text past a wrapper's name typed
mid-line is no request, but the constraints the hook made live from it (claude_code.midline_live) are stated. A later
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
import re
import sys
import tempfile
import time

from . import __version__, constraints, findings_effects, findings_text, parsers
from .findings import SEVERITY, WRITE_TOOLS
from .integrations.claude_code import midline_live, prompt_parts
from .signer.reconcile import PROVIDER_HOSTS
from .signer.rpc_schema import FINDING_TITLES as TITLES, RPCError
from .wiki import wiki_url

BUDGET_S = 60.0
MAX_TEXT = 1 << 16    # lean: characters of one record's text a check reads; past it a long prompt or answer is cut
MAX_NAMES = 1 << 17   # distinct words the mention index holds; past it later text is not read (size)
MAX_PROMPTS = 1 << 23   # characters of prompt text held until the hook's prompts and the transcript's are paired; past
#                         it later prompt lines are not read (size)
MAX_CITES = 8
MAX_GROUP = 64   # lean: lines of one model message read back from a call; past it, nothing readable is `size`
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
                    f"other agents: send model calls through the Tracekit LLM gateway ({wiki_url('docs/gateway.md')})"),
    "unlinked": ("the call was decided under an id of the adapter's own, which no model response carries",
                 f"use an integration that decides under the provider's tool call id ({wiki_url('docs/integrations.md')})"),
    "no_content": ("the signer kept no content for the records this check reads",
                   "set `content: {retain: true}` in signer.yaml (the dev signer keeps it unless "
                   "TRACEKIT_DEV_CONTENT=0) and grant the analysing identity content_read"),
    "withheld": ("the model's reasoning was withheld or sealed, so it can't be read",
                 'Claude Code: `tracekit init --dev --v2` sets "showThinkingSummaries": true (or set it in its '
                 "settings); headless: `claude -p --thinking-display summarized`; API: thinking display "
                 '"summarized", Responses reasoning.summary "auto"'),
    "conflicting_reports": ("two event streams reported the model message this call came from",
                            f"send model calls through the Tracekit LLM gateway ({wiki_url('docs/gateway.md')}): its record is "
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
PLACEHOLDER = re.compile(r"\[(?:Pasted text|Image) #\d+[^\]\n]{0,40}\]")   # what a transcript line holds for a paste
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
    """The trust tier of record e's text (`body`): the LLM gateway's record of a model's answer, an agent-writable
    transcript's or hook payload's (a tailer body, or one with a `source`), else an in-process adapter's: so is a model
    request the gateway recorded, whose body the agent's process wrote."""
    return ("gateway" if e["source"] == "gateway" and e["data"].get("phase") != "request" else
            "transcript" if _tailer(body) or isinstance(body, dict) and "source" in body else "sdk")


def _prompt(body):
    """(the text a person typed, the line's cwd, the constraints the hook also made live: midline_live) of a transcript
    line, or None when it is no human prompt."""
    e = body["entry"]
    msg = e.get("message") if isinstance(e.get("message"), dict) else {}
    if (body["transcript"] != "main" or e.get("type") != "user" or e.get("isMeta") or e.get("isCompactSummary")
            or e.get("isSidechain")):
        return None
    text = _blocks_text(msg.get("content"))
    if not text or text.lstrip().startswith(COMMAND_OUTPUT):
        return None
    # lean: a forged wrapper-only transcript line is not TK-X208 (docs/limits.md) until real transcripts establish which
    # such lines Claude Code writes with no UserPromptSubmit; then pair each with its turn's hook prompt, which is empty
    # or the raw text Claude Code wrapped after the hook (a plugin's or observer's message).
    # The hook stores only the typed segment as a request; match that same segment in the Claude Code transcript.
    typed, wrapped = prompt_parts(text, agent="claude-code")
    if not typed.strip():
        return None
    return typed, e.get("cwd") if isinstance(e.get("cwd"), str) else None, midline_live(text, wrapped)


def claimed(e, hooked):
    """Whether record e (a model request, or an input observed as trusted other than the hook's prompt) only claims
    to hold a person's request: a request the agent's own process reported, or any record in a run whose hook records
    the person's prompts (`hooked`), where they come in through the hook: a request the gateway recorded too (the
    agent holds its run token, so it can send one itself). Its text is no intent: it lifts and clears nothing, and the
    reviewer model reads it as `claimed`."""
    return hooked or e["type"] == "model.exchange" and e["source"] != "gateway"


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


def _names(read):
    """[(name, kept away)] of the words of a request (its constraints._read()), each a basename as constraints compare
    them (constraints.norm). A file a clause keeps away ("leave billing.py untouched", "don't modify billing.py") is
    marked kept away; the other words of a clause that keeps a file away are no mention, its other files aside. In a
    clause with a negation (constraints._negating) a word is no mention where the negation governs a change of it
    (constraints._prohibited: a prohibition the grammar can't read, "nobody should ever edit X"); a negation of what
    it does ("make sure uploader.py never sends the token", "update the README so it never mentions X") leaves it
    named. A file whose constraint the request lifts itself ("X is frozen in production, but you can edit it locally")
    is named."""
    out = []
    lifted = set().union(*(k for _, _, k in read)) - {o for kind, o in constraints.extract(None, read)
                                                      if kind == "keep_away"}
    for tokens, _, kept in read:
        negating = constraints._negating(tokens)
        for i, t in enumerate(tokens):
            name = constraints.norm(t)
            if name and (name in kept or (not kept or constraints._file(t)) and (
                    not negating or not constraints._prohibited(tokens, i))):
                out.append((name, name in kept and name not in lifted))
    return out


def _targets(cmd):
    """(paths, cd) of a shell command: what it writes as far as a lexer can tell (constraints.shell), and whether it
    changes directory."""
    s = constraints.shell(cmd)
    return s["paths"], s["cd"]


def _pasted(line, hook):
    """Whether transcript prompt line `line` is hook prompt `hook` with a placeholder Claude Code shows in place of a
    paste or an image ("[Pasted text #1 +40 lines]", "[Image #1]"): it has one, and its other text is the hook's, in
    order, whitespace aside."""
    parts = [" ".join(p.split()) for p in PLACEHOLDER.split(line)]
    if len(parts) < 2:
        return False
    hook, at = " ".join(hook.split()), 0
    for part in parts:
        at = hook.find(part, at)
        if at < 0:
            return False
        at += len(part)
    return True


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
        # synthetic: some calls can't be linked to the tool use that asked for them by id (an adapter's synthetic id,
        # a pairing by arguments, a message recorded said_only: a harness whose hooks name no call); hooked: the run's
        # hook recorded a prompt (PROMPT_HOOK)
        self.synthetic = self.hooked = False
        self.net_effects, self.requests = [], []   # net and connect effects; agent-reported request records
        self.approved = {}   # tool_use_id -> the approval record that approved its call
        self.model_hosts = set()   # the API hosts of the model calls the run recorded: the harness's own traffic
        for r in self.records:
            e, d = r["event"], r["event"]["data"]
            if e["type"] == "model.exchange" and d.get("upstream") in PROVIDER_HOSTS:
                self.model_hosts.add(PROVIDER_HOSTS[d["upstream"]])
            if e["type"] == "policy.decision":
                self.calls[d["tool_use_id"]] = {"decision": r}   # a later attempt replaces an earlier one
            elif e["type"] == "tool.result" and d.get("tool_use_id") in self.calls:
                self.calls[d["tool_use_id"]]["result"] = r
            elif e["type"] == "approval" and d.get("decision") == "approve":
                self.approved[d.get("tool_use_id")] = r
            elif e["type"] == "model.exchange" and d.get("phase") == "request" and e["source"] != "gateway":
                self.requests.append(e["run_seq"])
            elif e["type"] == "model.exchange" and d.get("phase") == "response":
                x = d.get("exchange_id")
                self.synthetic = self.synthetic or bool(d.get("said_only"))
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
        # name -> its first (position, run_seq, tier) in what a person asked ("asked"), where the model said it changes
        # it ("said": constraints.changes), and in a sentence keeping away from it ("kept_asked", "kept_said")
        self.names = {"asked": {}, "said": {}, "kept_asked": {}, "kept_said": {}}
        self.intent, self.prose = [], []   # run_seqs of intent records; positions of readable model text
        self.args, self.cwd, self.root, self.facts = {}, {}, None, {}   # facts: decision run_seq -> constraints.facts
        # prompts: [(run_seq, text digest, text, cwd)] of the transcript's prompt lines and the hook's prompts, until
        # confirm() pairs them; unconfirmed: the transcript's lines no hook prompt has the text of (TK-X208)
        self.prompts, self.hook_prompts, self.held, self.unconfirmed, self.confirmed = [], [], 0, [], {}
        self.live = {}   # a prompt line's run_seq -> its midline_live constraints
        # stated: [(position, run_seq, kind, object, "request" or "model")] of each constraint stated; lifts:
        # [(position, run_seq, constraints.mentions(text), "request" or "model")] of each text after
        self.stated, self.lifts, self.lift_names = [], [], 0
        self.claimed = []   # run_seqs of records that only claim a person's request (claimed())
        # [(run_seq, the words findings_text.told() reads in it, what findings_text.asks() reads)] of each request:
        # what TK-X211 counts as asked for
        self.asked = []
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

    def _read(self, text, pos, seq, tier, source):
        """What `text` (a request's, or the model's) mentions, keeps away and states (constraints._read, once)."""
        read = constraints._read(_text(text))
        self._mention(_names(read) if source == "asked" else [
            (name, said == "kept") for name, said in constraints.changes(read).items()], pos, seq, tier, source)
        self._stated(read, pos, seq, "request" if source == "asked" else "model")

    def _mention(self, names, pos, seq, tier, source):
        for name, away in names:
            index = self.names[("kept_" if away else "") + source]
            if name not in index or pos < index[name][0]:   # confirm() reads the prompts after the rest
                if name not in index and sum(map(len, self.names.values())) >= MAX_NAMES:
                    return self.cap(pos)
                index[name] = (pos, seq, tier)

    def _stated(self, read, pos, seq, source):
        """The constraints a text (its constraints._read()) states, and what it mentions that could lift one stated
        before it."""
        self.stated += [(pos, seq, kind, obj, source) for kind, obj in constraints.extract(None, read)]
        mention = constraints.mentions(None, read)
        if mention[0] or mention[1]:
            self.lift_names += len(mention[0]) + len(mention[1])
            if self.lift_names > MAX_NAMES:
                return self.cap(pos)
            self.lifts.append((pos, seq, mention, source))

    def _request(self, seq, text, tier, live=()):
        """`live`: constraints the hook made live from text past a wrapper name typed mid-line (midline_live), stated
        here too; that text is no request, so it mentions and lifts nothing."""
        self.intent.append(seq)
        self.asked.append((seq, findings_text.told(_text(text))[0], findings_text.asks(_text(text))))
        n = len(self.stated)
        self._read(text, (seq, -1), seq, tier, "asked")
        typed = {c[2:4] for c in self.stated[n:]}
        self.stated += [((seq, -1), seq, kind, obj, "request") for kind, obj in dict.fromkeys(live)
                        if (kind, obj) not in typed]

    def _keep(self, into, seq, text, cwd=None):
        self.held += len(_text(text))
        if self.held > MAX_PROMPTS:
            self.over += into is self.prompts
            return self.cap((seq, -1))
        into.append((seq, _same_text(text), _text(text), cwd))

    def confirm(self):
        """Pair the prompts the hook recorded with the transcript's prompt lines, one each by their text, and read
        each confirmed line (in a run whose hook recorded none: each line; in a run with no prompt line: each hook
        prompt) as a request; the other lines are TK-X208's. A line left with a placeholder Claude Code writes for a
        paste or an image pairs with the hook prompt left before it whose text has the line's other text (_pasted),
        which is read; a hook prompt left after that (a line the tailer missed) is a request of its own (harness).
        Then order what was stated and mentioned by position."""
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
            self._request(seq, text, self.tier[seq], self.live.get(seq, ()))
        left = sorted(s for seqs in hooks.values() for s in seqs) if self.prompts else []
        if left:
            hook_text, line_text = {s: t for s, _, t, _ in self.hook_prompts}, {s: t for s, _, t, _ in self.prompts}
            unconfirmed, self.unconfirmed = self.unconfirmed, []
            for seq in unconfirmed:
                k = bisect.bisect_left(left, seq) - 1
                if k < 0 or not _pasted(line_text[seq], hook_text[left[k]]):
                    self.unconfirmed.append(seq)
                    continue
                self.confirmed[seq] = hook = left.pop(k)
                self.tier[seq] = self.tier[hook] = "harness"
                self._request(seq, hook_text[hook], "harness", self.live.get(seq, ()))
        for hook in left:
            self.tier[hook] = "harness"
            self._request(hook, hook_text[hook], "harness")
        self.prompts = [(seq, None, None, None) for seq, *_ in self.prompts]   # the text is read
        self.hook_prompts = []
        self.intent.sort()
        self.stated.sort(key=lambda c: c[:2])
        self.lifts.sort(key=lambda m: m[:2])
        self._index()

    def _index(self):
        """Index the constraints stated and the texts that could lift one, so broken() reads only what a call can
        break: by kind (keep_away by file) and by (source, tier rank), each in position order."""
        def lists():
            return collections.defaultdict(lambda: ([], []))
        self.by_stated, self.by_lift = collections.defaultdict(lists), collections.defaultdict(lists)
        for i, c in enumerate(self.stated):
            ps, cs = self.by_stated[c[2], c[3] if c[2] == "keep_away" else None][c[4], RANK.get(self.tier.get(c[1]), 0)]
            ps.append(c[0])
            cs.append((i, c))
        self.only = [c for c in self.stated if c[2] == "only_change"]
        self.only_pos = [c[0] for c in self.only]
        for m in self.lifts:
            by = (m[3], RANK.get(self.tier.get(m[1]), 0))
            for key in [*(("name", n) for n in m[2][0]), *(("kind", k) for k in ("read_only", "no_push", "no_network")
                                                          if constraints.lifts(k, m[2], None))]:
                ps, ms = self.by_lift[key][by]
                ps.append(m[0])
                ms.append(m)

    def only_before(self, pos):
        """The files only_change constraints stated before `pos` name."""
        return {c[3] for c in self.only[:bisect.bisect_left(self.only_pos, pos)]}

    def broken(self, f, pos):
        """The constraint stated before position `pos` that a call's or effect's facts `f` (constraints.facts) break,
        a request's before the model's and one no later text lifts first, else the first stated: (stated, what breaks
        it, the lifting entry or None), or None. A lift counts only from a request (or, for the model's own
        constraint, its text) whose tier ranks at least the constraint's (RANK)."""
        only, best = self.only_before(pos), None
        for kind, obj in [*(("keep_away", n) for n in dict.fromkeys(f["names"])), ("only_change", None),
                          ("read_only", None), ("no_push", None), ("no_network", None)]:
            groups = self.by_stated.get((kind, obj))
            name = groups and constraints.breaks(kind, f, only.__contains__ if kind == "only_change" else obj.__eq__
                                                 if obj else None)
            if not name:
                continue
            lkey = ("name", name) if kind in constraints.OBJECT_KINDS else ("kind", kind)
            for (src, rank), (ps, cs) in groups.items():
                j = bisect.bisect_left(ps, pos)
                if not j:
                    continue
                lifts = [v for (s, r), v in self.by_lift.get(lkey, {}).items()
                         if (s == "request" or src == "model") and r >= rank]
                last = max((v[0][k - 1] for v in lifts if (k := bisect.bisect_left(v[0], pos))), default=None)
                i = 0 if last is None else bisect.bisect_left(ps, last, 0, j)   # the first no lift comes after
                n, c = cs[i] if i < j else cs[0]
                lift = None if i < j else min(
                    (v[1][k] for v in lifts if (k := bisect.bisect_right(v[0], c[0])) < len(v[0]) and v[0][k] < pos),
                    key=lambda m: m[:2])
                key = (src != "request", lift is not None, n)
                if best is None or key < best[0]:
                    best = (key, c, name, lift)
        return best and best[1:]

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
            if str(d.get("source")).endswith(PROMPT_HOOK):
                # A hook request only once a transcript line agrees. Other submitted segments are observations.
                return self._keep(self.hook_prompts, seq, text)
        elif d.get("phase") == "request":
            if _tailer(body):
                prompt = _prompt(body)
                if prompt:
                    self.live[seq] = prompt[2]
                return prompt and self._keep(self.prompts, seq, *prompt[:2])
            text = _asked(body)
        else:
            if self.conflicting(d.get("exchange_id")) and e["source"] != "gateway":   # may be forged: clears nothing
                self.segs[seq] = [(s["kind"], s["form"], bool(s["text"].strip()), s["tools"], "")
                                  for s in parsers.said(*_message(body, d))]
                return
            segs = parsers.said(*_message(body, d))
            self.segs[seq] = [(s["kind"], s["form"], bool(s["text"].strip()), s["tools"], s["text"][-EXCERPT:])
                              for s in segs]
            for k, s in enumerate(segs):
                if s["text"].strip():
                    self.prose.append((seq, k))
                    self._read(s["text"], (seq, k), seq, tier, "said")
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
        end = bisect.bisect_right(group, cs)
        if end > MAX_GROUP:   # the message's lines before these are not read
            before.append((group[end - MAX_GROUP - 1], None, "cut", False, ""))
        for s in group[max(0, end - MAX_GROUP):end]:   # a transcript writes a line per content block, its own record
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
        seqs = sorted({b[0] for b in before if b[2] not in ("missing", "cut")})
        if readable:
            return form, "checked", seqs, readable[-1][4]
        if thought:
            return form, "withheld", seqs, ""
        if before and before[0][2] == "cut":
            return "unknown", "size", [], ""
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


def _constraint(run, note, call, f, pos, seqs, who, approval=None):
    """TK-X204 of one call or effect (`f` its constraints.facts, at position `pos`; `seqs` its records; `who` names
    it): whether it breaks a constraint stated before it. With text before it the size caps left unread
    (`run.capped`), a break is still found (labelled `size`: a lift may be in that text) and no break is not checkable.
    `approval`: the approval record of the call a live constraint held: by another identity than the run's (not
    self_approved), the person approved it, which lifts the constraint for it (low, `approved`); self-approved, the
    run's own identity answered, which may be the agent's: labelled `self_approved`, nothing lowered."""
    hit = run.broken(f, pos)
    capped = run.capped is not None and run.capped < pos
    if hit is None:
        return note(call, "TK-X204", "size" if capped else "checked", _tiers(run, seqs))
    (_, cseq, kind, obj, source), name, lift = hit
    aseq = approval and approval["event"]["run_seq"]
    self_approved = bool(approval and approval["event"]["data"].get("self_approved"))
    seqs = [*seqs, cseq, *([lift[1]] if lift else []), *([aseq] if approval else [])]
    only = sorted(run.only_before(pos))
    note(call, "TK-X204", "checked", _tiers(run, seqs), _finding(
        run, "TK-X204", seqs, "low" if lift or approval and not self_approved else "high" if source == "request"
        else "medium", call and call["order"], bool(lift)),
        f"{who} {DID[kind].format(name)} after the {source} (record {cseq}) said "
        + STATED[kind].format(", ".join(only[:3]) if kind == "only_change" else obj)
        + (f"; a later {lift[3]} (record {lift[1]}) named it, so the constraint may have been lifted" if lift else "")
        + ("" if not approval else f"; the run's own identity approved the held call (record {aseq}), which may be the "
           "agent" if self_approved else f"; the person approved the held call (record {aseq})"),
        [kind] + (["lifted"] if lift else []) + (["self_approved" if self_approved else "approved"] if approval else [])
        + (["stated_by_model"] if source == "model" else []) + (["size"] if capped else []))
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
            _constraint(run, note, call, run.facts[dseq], pos, [dseq, *([cs] if cs is not None else [])], tool,
                        "TK-CONSTRAINT" in dec["data"].get("rule_ids", ()) and run.approved.get(tcid) or None)
        # TK-X202
        if tool in WRITE_TOOLS:
            if not facts or not facts["paths"]:
                note(call, "TK-X202", "no_content")
            elif not i and not prose:
                note(call, "TK-X202", "no_text")
            else:
                name = constraints.norm(facts["paths"][0])
                # the request names it before the call, or the model says it changes it, before the call or after
                asked, said = run.first("asked", name, pos), run.names["said"].get(name)
                kept, denied = run.first("kept_asked", name, pos), run.first("kept_said", name, pos)
                seqs = [dseq, *([cs] if cs is not None else []), *run.intent[max(0, i - 3):i]]
                # a file a constraint keeps away is TK-X204's: the stronger finding covers the call
                hit = not (asked or said) and call["checks"]["TK-X204"] != "found"
                if hit and run.capped is not None:   # the name may be in text left unread
                    note(call, "TK-X202", "size")
                else:
                    note(call, "TK-X202", "checked", _tiers(run, seqs), hit and _finding(
                        run, "TK-X202", seqs + [m[1] for m in (kept, denied) if m], order=call["order"]),
                        f"{tool} changed {facts['paths'][0]}; the request doesn't name {name}"
                        + (" other than to keep it unchanged" if kept else "") + ", and the model never says it "
                        "changes it" + (f": its text before the call (record {denied[1]}) said it would leave it "
                                        "unchanged, a contradiction" if denied else "")
                        + ("" if prose else " (no model text was readable: checked against the request only)"),
                        (["kept_away"] if kept else []) + (["contradiction"] if denied else [])
                        + ([] if prose else ["reasoning_absent"]))
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
                _constraint(run, note, None, {"names": constraints.names([d["path"]]) if file else [], "write": file,
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
            try:
                run.feed(r, nxt[1], nxt[2])
            except Exception:   # content an agent supplied that no reader here takes: as if the vault kept none
                run.content.discard(seq)
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
    """The result as the terminal shows it. Each line without control characters (verify.v2._CONTROL: ESC, newlines,
    bidirectional overrides), which agent-written text (a quoted claim, a path, the reviewer model's explanation)
    could use to rewrite what the person reads."""
    from .verify.v2 import _CONTROL
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
    lines.append("Not signed: printed only." if not s else
                 f"Signed only {s['records']} of {s['of']} records (the coverage review first) in findings run "
                 f"{s['findings_run']}: the rest failed (below)" if s["records"] < s["of"] else
                 f"Signed: {s['records']} record(s), the findings and the coverage review, in findings run "
                 f"{s['findings_run']}; bundle them with `tracekit export --v2 --run {out['run_id']} --with-findings`")
    return "\n".join(_CONTROL.sub("", line) for line in lines)


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
    (quota_exceeded with retry_after_ms) is waited out. The coverage review goes first, so a pass cut short still says
    what it checked; `out["signed"]` counts what was signed ({findings_run, records, of}) as it goes."""
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
        todo = [out["coverage"], *out["findings"]]
        out["signed"] = {"findings_run": run.run_id, "records": 0, "of": len(todo)}
        for f in todo:
            while True:
                try:
                    run.review_finding(reviewer, f["verdict"], f["cites"])
                    break
                except RPCError as e:
                    if e.code != "quota_exceeded" or e.retry_after_ms is None:
                        raise
                    time.sleep(min(e.retry_after_ms, 5000) / 1000)
            out["signed"]["records"] += 1
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
    g.add_argument("--budget", type=findings_effects.seconds, default=BUDGET_S, metavar="S", help="seconds the "
                   "analysis may take (default %(default)g); past it what is left is not checkable: budget, and the "
                   "result INCOMPLETE")
    findings_effects.arguments(ap.add_argument_group("kernel sensor effects (TK-X206, TK-X207)"))
    g = ap.add_argument_group("the reviewer model (TK-X210, warn only)")
    g.add_argument("--review", action="store_true", help="also ask a reviewer model, which sends the run's text "
                   f"(redacted) to that model ({wiki_url('docs/privacy.md', 'what-leaves-the-machine')}); not with --dry-run")
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
    g.add_argument("--json", action="store_true", help=f"print the whole result as JSON ({wiki_url('docs/findings.md', 'the---json-shape')}), "
                   "for CI and agents")
    a = ap.parse_args(argv)
    if a.review and a.dry_run:
        print("tracekit analyze: --review records the model call in a findings run and --dry-run signs nothing: "
              "drop one", file=sys.stderr)
        return 2
    from .sdk.client import Client, SignerUnavailable
    from .signer.pipeline import SIGNER_RUN
    from .signer.service import dev_data_dir
    from .why import import_v2
    from .verify.v2 import _CONTROL
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
                sign(client, run_id, out, rv, records)
            except (SignerUnavailable, OSError, RPCError) as e:
                failed = e
    finally:
        client.close()
    review = out["shown"].get("review") or {}
    if review.get("error"):
        print(f"tracekit analyze: --review: {_CONTROL.sub('', review['error'])}", file=sys.stderr)
    if review.get("same_family"):
        print(f"tracekit analyze: --review: the reviewer model is of the agent's model family "
              f"({review['families']['reviewer']}), so it may share the agent's blind spots: pass --review-model of "
              "another family, or configure one (OPENAI_API_KEY or ANTHROPIC_API_KEY for the other provider, or "
              "TRACEKIT_REVIEW_MODEL with TRACEKIT_REVIEW_URL) and it is picked", file=sys.stderr)
    print(json.dumps(out, indent=2) if a.json else render(out))
    if failed is not None:
        s = out.get("signed") or {"records": 0}
        part = f"all signed (only {s['records']} of {s['of']})" if s["records"] else "signed"
        print(f"tracekit analyze: the findings are printed but NOT {part}: {failed}. The signer signs them for an "
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
