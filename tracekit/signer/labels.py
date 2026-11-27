"""Run labels (docs/policy-v2.md#run-conditions): what a run has done that a run condition rule reads.

A pure function of signed records, as detection is: the single writer adds a label (a `run.label` record, `by:
signer`) right after the record that sets it, replay follows the run.label records, and the verifiers replay both
under the bundled policy. A record sets the labels of a call it lets run: a decision that allows or flags it, the
consume of its approval, or its executed_against_policy gap (it ran anyway). Those labels are each matched rule's
`label` of RUN_LABELS, every label the policy reads for a call it couldn't read (TK-OVERSIZE), and untrusted_content
when the policy's `untrusted` list marks the tool's results, as the provenance index reads them; an input observed as
untrusted sets untrusted_content too, and events the signer never got (a client_counter_gap) set every label it reads,
as an unread call does: what they did is unknown. A harness call (a message to the agent's own agents) sets none. A
run carries only the labels its policy reads: those its run conditions name and those the AI approver's run bound
names (approval_agent.run.clean, docs/approvals.md#the-ai-approver).

Labels belong to the run's requesters (requesters: its client, an identity it was delegated to, a gateway's caller),
not only the run: a run inherits each label a run of any of its requesters carries, in any tenant and under any
principal, while that run is open and for the policy's `label_inherit_s` after it ends (labels_for), as a `run.label`
add naming the record it inherits (`inherited`) before its next decision; so ending a run, starting another, or moving
to another tenant, principal or delegated run keeps a label. A person clears one with run_label_clear, for the run and
its client's ended runs in that tenant (an open run that carries it in its own state still passes it on, until it is
cleared there; a dev signer's self-clear is of that run alone); nothing a client sends sets or clears one. A run's
requesters are in its records (run.registered's caller, run.writer), so a restart from the records knows them.

The AI approver's run bound reads one more thing, for itself alone: a call the policy denied or held that a rule
labelled secrets_access matched (the session tried to read a secret) gives its requesters that label for the bound and
for whether a person's answer is a precedent, as a run label is carried (tried_state, tried_for), with no record of
its own: it is a function of the decision's record, read under the policy it names. Run conditions read only what ran.
"""
import math
import os
import re
import time
import types

from tracekit.policy2 import linear
from tracekit.policy2.classes import PATH_KEYS, SHELL_KEYS
from tracekit.policy2.compile import SECTIONS, PolicyError, subject_labels
from tracekit.signer.detect import epoch

UNTRUSTED = "untrusted_content"   # of compile.RUN_LABELS
SECRETS = "secrets_access"   # of compile.RUN_LABELS: the one a call that didn't run sets, for the run bound alone
UNREAD = "TK-OVERSIZE"   # a call the policy couldn't read: it may have done what any rule reads
# the gaps of calls the signer never decided (events it never got, a signer that was down, a tailer or an observer that
# went silent): they may have done what any rule reads, as reconcile.hook_missing's call did
LOST = ("client_counter_gap", "signer_unavailable", "tailer_lost", "observer_lost")
LABEL_INHERIT_S = 3600   # label_inherit_s's default: respond's cooldown_s default, for a hold a new run inherits


class Sources:
    def __init__(self, rules, kept=None):
        """`rules`: an Engine, or a detect.Rules (a verifier's, which compiles no pattern). `kept(policy_hash)`: the
        policy (an Engine) the signer kept of that hash, or None (tried reads a decision under the policy it names)."""
        pol, self.rules, self.kept, self._at = rules.policy, rules, kept, {}
        # each run condition rule's labels, by id; the labels some rule's condition or the AI approver's run bound
        # names; the rules that set one
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.when = {r["id"]: frozenset(r["when"]["run_has"]) for r in rules if "when" in r}
        bound = ((pol.get("approval_agent") or {}).get("run") or {}).get("clean") or ()
        self.bound, self.tracked = frozenset(bound), frozenset().union(*self.when.values(), bound)
        self.label = {r["id"]: r["label"] for r in rules if r.get("label") in self.tracked}
        # every rule's label (noted); for the verifiers: the labels a rule on the labels field reads
        # (compile.subject_labels), and each run condition rule on the labels field (one with no tool: its class, its
        # pattern and unless), whose match the call's rule ids and the run's labels decide (compile.labels_subject,
        # Engine.condition)
        self.all_labels = {r["id"]: r["label"] for r in rules if r.get("label")}
        self.subject_labels = subject_labels(pol)
        # compiled as the signer compiles them (_compiled); `refused`: rule id -> why its pattern can't be (a bundle's
        # policy the signer would have refused)
        self.on_labels, self.refused = [], {}
        for r in rules:
            if r.get("field") == "labels" and "when" in r and "tool" not in r:
                try:
                    self.on_labels.append((r["id"], _compiled(r.get("pattern")),
                                           _compiled(r["unless"]) if "unless" in r else None, r.get("class")))
                except PolicyError as e:
                    self.refused[r["id"]] = str(e)
        self.window = pol.get("label_inherit_s", LABEL_INHERIT_S)

    @classmethod
    def of(cls, rules, kept=None):
        """Sources when the policy reads a label (a run condition, the AI approver's run bound), else None (its runs
        carry no label)."""
        src = cls(rules, kept)
        return src if src.tracked else None

    def under(self, policy_hash):
        """The Sources of the policy `policy_hash` (a decision's): this one, else the one the signer kept, else this
        one."""
        if policy_hash == self.rules.policy_hash or not self.kept or not isinstance(policy_hash, str):
            return self
        if policy_hash not in self._at:
            rules = self.kept(policy_hash)
            self._at[policy_hash] = self if rules is None else Sources(rules)
        return self._at[policy_hash]

    def of_call(self, tool, rule_ids):
        """The labels a call of `tool` that matched `rule_ids` sets when it runs."""
        if isinstance(tool, str) and self.rules.tool_class(tool) == "harness":
            return set()
        if UNREAD in rule_ids:
            return set(self.tracked)
        out = {self.label[i] for i in rule_ids if i in self.label}
        if UNTRUSTED in self.tracked and isinstance(tool, str) and self.rules.untrusted_results(tool):
            out.add(UNTRUSTED)
        return out

    def sets(self, e, requested, decided):
        """The labels record `e` sets. `requested(approval_id)`, `decided(tool_call_id)`: {tool, rule_ids} of the call
        an approval was asked for, and of a call's latest decision in the run, or None."""
        t, d = e["type"], e["data"]
        if t == "policy.decision" and d.get("decision") in ("allow", "flag"):
            return self.of_call(d.get("tool"), d.get("rule_ids", ()))
        call = requested(d.get("approval_id")) if t == "approval.consumed" else decided(e.get("tool_call_id")) if (
            t == "capture.gap" and d.get("kind") == "executed_against_policy") else None
        if call:
            return self.of_call(call.get("tool"), call.get("rule_ids", ()))
        if t == "input.observed" and d.get("trust") == "untrusted" and UNTRUSTED in self.tracked:
            return {UNTRUSTED}
        if t == "capture.gap" and d.get("kind") in LOST or t == "reconcile.hook_missing":   # calls never decided
            return set(self.tracked)
        return set()

    def tried(self, e):
        """The labels record `e` sets for the AI approver's run bound alone: secrets_access, where the bound names it,
        when `e` is a decision that denies or holds a call (not a harness call) a rule labelled secrets_access
        matched, each read under the policy the decision names (under): a restart under another policy replays it as
        it was written. The session tried to read a secret, and whether it gets to is a person's to say: the AI answers
        none of its holds meanwhile. Nothing that didn't run sets a run label (sets)."""
        d = e["data"]
        if e["type"] != "policy.decision" or d.get("decision") not in ("deny", "ask"):
            return set()
        src = self.under(d.get("policy_hash"))
        if SECRETS not in src.bound or isinstance(d.get("tool"), str) and src.rules.tool_class(d["tool"]) == "harness":
            return set()
        return {SECRETS} if any(src.label.get(i) == SECRETS for i in d.get("rule_ids", ())) else set()


def _compiled(pattern):
    """A search of `pattern` as the signer reads it, (text, linear.Budget) -> whether it matches: linear.Pattern, RE2's
    semantics in linear time within the verification's budget, the same in the TypeScript verifier and with or without
    google-re2, so both verifiers give one verdict on any machine. PolicyError for a pattern compile.check_pattern
    refuses or one too large (a bundle's own policy may hold anything: it fails the check, never hangs it)."""
    if not isinstance(pattern, str):
        raise PolicyError("the pattern is not a string")
    return linear.Pattern(pattern).search


def state(set_, run, e):
    """Follow `run.label` record `e` in the run's labels, `run["labels"]`: {label: the run_seq of the record that set
    it (an inherited one's own)}, and `run["label_src"]`: {label: an inherited add's `inherited`}. `set_`: as
    pipeline.agent_state's."""
    if e["type"] != "run.label":
        return
    d, have, src = e["data"], dict(run.get("labels") or {}), dict(run.get("label_src") or {})
    if d["action"] == "add":
        have[d["label"]] = d.get("source", e["run_seq"])
    else:
        have.pop(d["label"], None)
    if d["action"] == "add" and "inherited" in d:
        src[d["label"]] = d["inherited"]
    else:
        src.pop(d["label"], None)
    set_(run, "labels", have)
    if src or "label_src" in run:
        set_(run, "label_src", src)


def _who(identity):
    """An identity ("scheme:subject") in pipeline.owner's form: its subject cut at 256 characters."""
    scheme, _, sub = identity.partition(":")
    return f"{scheme}:{sub[:256]}"


def requesters(run):
    """Who controls `run`'s calls, each in pipeline.owner's form: its client (its owner, or the client a gateway
    registered it for, `caller`: the gateway's own writes in it are the client's then) and each other stream's writer
    (an identity the run was delegated to, a gateway's caller). The run's labels are each of theirs, and it carries
    each of theirs."""
    own = run.get("owner") and _who(run["owner"])
    client = run.get("caller") or run.get("owner")
    writers = {_who(w.removesuffix(" through a gateway")) for w in (run.get("writers") or {}).values()}
    return ({_who(client)} if client else set()) | writers - {own}


def _live(held, window, now):
    """`held` ({label: {run: [run_seq, ended]}}) without the entries past `window` at `now`, nor labels left empty."""
    out = {x: {r: v for r, v in runs.items() if v[1] is None or epoch(v[1]) + window > now} for x, runs in held.items()}
    return {x: runs for x, runs in out.items() if runs}


def carry(set_, log, run, e, pop):
    """Follow record `e` of `run` in the labels its requesters carry, `log.carry`: {requester (requesters): {label:
    {tenant and run id joined by a NUL: [the run_seq of the run's run.label add, the ts the run ended or None while
    it is open]}}}, in any tenant and under any principal. For each of requesters(run): a run.label add enters the
    run's entry, a run.closing ends it, and a person's clear removes it and, for the run's client, the label of every
    run of theirs in the run's tenant that has ended (a person answers for their own tenant; another writer's own runs
    stay theirs; an open run that carries the label in its own state keeps passing it on), a self-clear only the run's
    own; a run.writer carries the run's labels to its writer (join). Entries past `log.labels`' window go as their
    requester's key changes, and all of them at a snapshot (prune). `set_`, `pop`: as pipeline.contain_state's."""
    typ, d = e["type"], e["data"]
    if typ == "run.writer":
        join(set_, log, run, d["identity"])
    if typ == "run.label" and d["action"] == "clear" and "run_id" in d:   # an ended run's, in the tenant's signer run
        gone = derived(log, e["tenant"], d["run_id"], d["label"])
        for who in sorted(log.carry):
            held = log.carry[who]
            if gone & (held.get(d["label"]) or {}).keys():
                new = {x: {r: v for r, v in runs.items() if x != d["label"] or r not in gone} for x, runs in held.items()}
                new = {x: runs for x, runs in new.items() if runs}
                set_(log.carry, who, new) if new else pop(log.carry, who)
        return
    if typ not in ("run.label", "run.closing") or not run.get("owner"):
        return
    me, now = f"{e['tenant']}\0{e['run_id']}", epoch(e["ts"])
    window = log.labels.window if log.labels else LABEL_INHERIT_S
    client = _who(run.get("caller") or run["owner"])
    for who in sorted(requesters(run)):
        held = log.carry.get(who) or {}
        if typ == "run.label" and d["action"] == "clear":
            tenant = f"{e['tenant']}\0"

            def kept(r, v):   # a self-clear (a dev signer's own user, who may be the agent) ends this run's entry only
                if r == me or who == client and not d.get("self_cleared") and r.startswith(tenant):
                    other = log.runs.get(tuple(r.split("\0", 1)))
                    return r != me and v[1] is None and d["label"] in ((other or {}).get("labels") or {})
                return True
            new = {x: {r: v for r, v in runs.items() if x != d["label"] or kept(r, v)} for x, runs in held.items()}
            new = {x: runs for x, runs in new.items() if runs}
        else:
            new = _live(held, window, now)
            if typ == "run.label":
                new[d["label"]] = {**new.get(d["label"], {}),
                                   me: [e["run_seq"], e["ts"] if run.get("closed") else None]}
            else:
                new = {x: {r: [v[0], e["ts"]] if r == me and v[1] is None else v for r, v in runs.items()}
                       for x, runs in new.items()}
        if new != held:
            set_(log.carry, who, new) if new else pop(log.carry, who)


def derived(log, tenant, rid, label):
    """The carry's keys (tenant NUL run id) of run `rid` and of every run that took `label` from it, along their
    inherited adds (label_src), among the runs the carry holds `label` of: what a clear of `rid`'s label ends."""
    keys = {k for held in log.carry.values() for k in (held.get(label) or {})}
    out, ids, more = {f"{tenant}\0{rid}"}, {rid}, True
    while more:
        more = False
        for k in sorted(keys - out):
            src = ((log.runs.get(tuple(k.split("\0", 1))) or {}).get("label_src") or {}).get(label)
            if src and src.get("run_id") in ids:
                out.add(k)
                ids.add(k.split("\0", 1)[1])
                more = True
    return out


def origin(log, run, label):
    """The run `run` took `label` from first, along inherited adds (label_src) through runs the carry holds: the run
    whose clear ends it."""
    keys = {k.split("\0", 1)[1]: k for held in log.carry.values() for k in (held.get(label) or {})}
    rid, seen = run["run_id"], set()
    while (src := ((run or {}).get("label_src") or {}).get(label)) and src.get("run_id") not in seen:
        rid = src["run_id"]
        seen.add(rid)
        run = log.runs.get(tuple(keys[rid].split("\0", 1))) if rid in keys else None
    return rid


def join(set_, log, run, who):
    """`who` (a run.writer's identity) writes open `run` for the first time: it carries the labels the run carries now,
    as their run.label adds would have given it had it written then."""
    who = _who(who.removesuffix(" through a gateway"))
    if not log.labels or run.get("closed") or not run.get("labels") or who in requesters(run):
        return
    me, held = f"{run['tenant']}\0{run['run_id']}", log.carry.get(who) or {}
    set_(log.carry, who, {**held, **{x: {**held.get(x, {}), me: [seq, None]} for x, seq in run["labels"].items()}})


def prune(log, now):
    """Drop the entries past the window from every requester's labels, and from those the run bound alone reads
    (tried_state) (on the writer: no answer changes)."""
    window = log.labels.window if log.labels else LABEL_INHERIT_S
    for store in (log.carry, log.agent["tried"]):
        for who in list(store):
            held = _live(store[who], window, now)
            if held:
                store[who] = held
            else:
                del store[who]


def labels_for(log, run, now=None):
    """The labels `run`'s requesters (requesters: its client, delegates and gateway callers) carry from any run of
    theirs, in any tenant and under any principal: {label: [run_id, run_seq]}, each a label such a run carries while it
    is open and for the policy's label_inherit_s after it ends, with the record that added it there (an open run's
    first, else the one that ended last). `now`: epoch seconds (now by default). {} when the policy reads no label.
    Read it on the signer's writer (a RecordLog.submit fn) for an answer no write races: SignerService._decide adds
    them to the run before its run conditions, and an approver deciding one of the run's calls may read them the same
    way. One lookup per requester: the signer's other requesters cost it nothing."""
    return _carried(log, requesters(run), now)


def labels_of(log, identity, now=None):
    """The labels `identity` (scheme:subject, pipeline.owner's or pipeline.writer's form: an approval's requester)
    carries from any run of its, as labels_for reads them for a run's requesters."""
    return _carried(log, {_who(identity.removesuffix(" through a gateway"))}, now)


def tried_state(set_, log, run, e):
    """Follow record `e` of `run` in `log.agent["tried"]`, laid out as `log.carry` is: {requester: {label: {tenant and
    run id joined by a NUL: [the run_seq of the decision that set it (Sources.tried), the ts the run ended or None while
    it is open]}}}. Each of requesters(run) takes it, a run.writer's writer takes the run's own, and a run.closing ends
    it; entries past the window go as their requester's key changes, and all of them at a snapshot (prune). No clear
    ends one: it lasts while its run is open and for label_inherit_s after. `set_`: as pipeline.agent_state's."""
    typ, d, store = e["type"], e["data"], log.agent["tried"]
    me = f"{e['tenant']}\0{e['run_id']}"
    if typ == "run.writer":
        who = _who(d["identity"].removesuffix(" through a gateway"))
        own = {x: runs[me] for held in store.values() for x, runs in held.items() if me in runs}
        held = store.get(who) or {}
        if own and any(me not in held.get(x, {}) for x in own):
            set_(store, who, {**held, **{x: {**held.get(x, {}), me: v} for x, v in own.items()}})
        return
    new = log.labels.tried(e) if typ == "policy.decision" else set()
    if not (new or typ == "run.closing") or not run.get("owner"):
        return
    now = epoch(e["ts"])
    for who in sorted(requesters(run)):
        held = store.get(who) or {}
        if typ == "run.closing":
            out = {x: {r: [v[0], e["ts"]] if r == me and v[1] is None else v for r, v in runs.items()}
                   for x, runs in held.items()}
        else:
            out = _live(held, log.labels.window, now)
            for x in new:
                out[x] = {**out.get(x, {}), me: [e["run_seq"], e["ts"] if run.get("closed") else None]}
        if out != held:
            set_(store, who, out)


def tried_for(log, run, requester, now=None):
    """The labels a call of `run` that `requester` asks about carries for the AI approver's run bound alone, from calls
    that didn't run (tried_state): those of the run's requesters and of `requester`, while the run that tried is open
    and for label_inherit_s after it ends, as labels_for reads them: {label: [run_id, run_seq]}."""
    return _carried(types.SimpleNamespace(carry=log.agent["tried"], labels=log.labels),
                    requesters(run) | {_who(requester.removesuffix(" through a gateway"))}, now)


def _carried(log, whos, now):
    if not log.labels:
        return {}
    now, best = time.time() if now is None else now, {}
    for who in whos:
        for label, runs in (log.carry.get(who) or {}).items():
            for r, (seq, ended) in runs.items() if label in log.labels.tracked else ():
                if ended is None or epoch(ended) + log.labels.window > now:
                    rank = (ended is not None, -epoch(ended) if ended else 0, r)
                    if label not in best or rank < best[label][0]:
                        best[label] = (rank, r, seq)
    return {label: [r.split("\0", 1)[1], seq] for label, (_, r, seq) in best.items()}


# what a person reads of a call rules in shadow recorded (decide's `noted`)
NOTE_TAIL = "Nothing is blocked in 1.8; it's in the record."
_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s'\"@]*@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)")
_DETACHED = re.compile(r"(?:^|[\s;&|(])(nohup|setsid|disown|daemonize|screen|tmux|launchctl submit)(?=\s|$)")
_DONE = {"secrets_access": "read a secret", UNTRUSTED: "took in untrusted content"}


def what(tool, args):
    """The call that set a label, for a person: `read .env` (a file it names), ran `cat .env` (a command, cut at 48
    characters), else `used <tool>`."""
    a = args if isinstance(args, dict) else {}
    path = next((a[k] for k in PATH_KEYS if isinstance(a.get(k), str) and a[k].strip()), None)
    if path:
        return "read " + (os.path.basename(path.rstrip("/\\")) or path)
    cmd = next((a[k] for k in SHELL_KEYS if isinstance(a.get(k), str) and a[k].strip()), None)
    if cmd:
        line = " ".join(cmd.split())
        return f"ran `{line[:48]}{'...' if len(line) > 48 else ''}`"
    return f"used {tool}"


def _dest(tool, args):
    """Where a call sends: `to <host>` (the first two its URLs name), else `with <program>` (a command's first word
    that sets no variable, an MCP server, the tool)."""
    hosts = list(dict.fromkeys(_HOST.findall(" ".join(v for v in args.values() if isinstance(v, str)))))
    if hosts:
        return "to " + " and ".join(hosts[:2])
    cmd = next((args[k] for k in SHELL_KEYS if isinstance(args.get(k), str) and args[k].split()), None)
    if cmd:
        return "with " + next((w for w in cmd.split() if "=" not in w), cmd.split()[0])
    server = re.match(r"mcp__(.+?)__", tool or "") or re.match(r"mcp:([^/]+)/", tool or "")
    return f"with the {server.group(1)} MCP server" if server else f"with {tool}"


def _left(log, run, rid, label, now):
    """(whether a requester of `run` carries `label` from run `rid`, the seconds it carries for: None while that run is
    open)."""
    found, left = False, 0
    for who in requesters(run):
        for r, (_, ended) in ((log.carry.get(who) or {}).get(label) or {}).items():
            if r.endswith("\0" + rid):
                if ended is None:
                    return True, None
                found, left = True, max(left, log.labels.window - (now - epoch(ended)))
    return found, left


def noted(log, run, shadow, rules, rule_ids, tool, args, said, clears, now=None):
    """What a person reads of a call the rules `shadow` (in shadow; `rules`: their compiled rules by id) recorded: where
    it sends and after what (this session's read, from `said`: {(run_id, label): labels.what}, or an earlier session's
    it inherits, how long that carries and, where a person's clear ends it (`clears`), how), or that it starts a send
    in the background; then NOTE_TAIL. A rule of another kind gives its reason. "" when there is nothing to say.
    `clears`: "self" on a dev signer (its user clears the run a label came from), "person" where a person clears it,
    else None."""
    now = time.time() if now is None else now
    mine = {log.labels.all_labels[i] for i in rule_ids if i in log.labels.all_labels} if log.labels else set()
    a = args if isinstance(args, dict) else {}
    parts = []
    for rid in shadow:
        r = rules.get(rid, {})
        when = (r.get("when") or {}).get("run_has") or []
        if when and "egress" in mine:
            label = when[0]
            src = (run.get("label_src") or {}).get(label)
            done = said.get(((src or {}).get("run_id", run["run_id"]), label)) or _DONE.get(label, f"set {label}")
            if src:
                found, left = _left(log, run, src["run_id"], label, now) if log.labels else (False, 0)
                carry = "" if not found else "; this carries while that session is open" if left is None else \
                    f"; this carries for {max(1, math.ceil(left / 60))} more minutes"
                if clears == "self" and carry:   # a dev signer: its user clears the run it came from
                    carry += (f", or clear it: tracekit signer incidents clear-label {origin(log, run, label)} "
                              f"--label {label}")
                elif clears and carry:
                    carry += (f", or until a person clears it: tracekit signer incidents clear-label {run['run_id']} "
                              f"--label {label}")
                parts.append(f"this sends data {_dest(tool, a)} after an earlier session (run {src['run_id']}) "
                             f"{done}{carry}")
            else:
                parts.append(f"this sends data {_dest(tool, a)} after the session {done}")
        elif {"background_spawn", "egress"} <= mine:
            cmd = next((a[k] for k in SHELL_KEYS if isinstance(a.get(k), str)), "")
            m = _DETACHED.search(cmd)
            how = "run_in_background" if a.get("run_in_background") is True else m.group(1) if m else \
                "&" if re.search(r"(?<![&|])&\s*$", cmd) else "detached"
            parts.append(f"this starts a send in the background ({how}), which may run after a secret is read")
        elif r.get("reason"):
            parts.append(r["reason"])
    return "noted: " + "; ".join(dict.fromkeys(parts)) + ". " + NOTE_TAIL if parts else ""
