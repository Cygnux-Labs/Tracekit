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
its client's runs in that tenant; nothing a client sends sets or clears one.
"""
import time

from tracekit.policy2.compile import SECTIONS
from tracekit.signer.detect import epoch

UNTRUSTED = "untrusted_content"   # of compile.RUN_LABELS
UNREAD = "TK-OVERSIZE"   # a call the policy couldn't read: it may have done what any rule reads
LABEL_INHERIT_S = 3600   # label_inherit_s's default: respond's cooldown_s default, for a hold a new run inherits


class Sources:
    def __init__(self, rules):
        """`rules`: an Engine, or a detect.Rules (a verifier's, which compiles no pattern)."""
        pol, self.rules = rules.policy, rules
        # each run condition rule's labels, by id; the labels some rule's condition or the AI approver's run bound
        # names; the rules that set one
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.when = {r["id"]: frozenset(r["when"]["run_has"]) for r in rules if "when" in r}
        bound = ((pol.get("approval_agent") or {}).get("run") or {}).get("clean") or ()
        self.tracked = frozenset().union(*self.when.values(), bound)
        self.label = {r["id"]: r["label"] for r in rules if r.get("label") in self.tracked}
        self.window = pol.get("label_inherit_s", LABEL_INHERIT_S)

    @classmethod
    def of(cls, rules):
        """Sources when the policy reads a label (a run condition, the AI approver's run bound), else None (its runs
        carry no label)."""
        src = cls(rules)
        return src if src.tracked else None

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
        if t == "capture.gap" and d.get("kind") == "client_counter_gap":   # calls the signer never got
            return set(self.tracked)
        return set()


def state(set_, run, e):
    """Follow `run.label` record `e` in the run's labels, `run["labels"]`: {label: the run_seq of the record that set
    it (an inherited one's own)}. `set_`: as pipeline.agent_state's."""
    if e["type"] != "run.label":
        return
    d, have = e["data"], dict(run.get("labels") or {})
    if d["action"] == "add":
        have[d["label"]] = d.get("source", e["run_seq"])
    else:
        have.pop(d["label"], None)
    set_(run, "labels", have)


def _who(identity):
    """An identity ("scheme:subject") in pipeline.owner's form: its subject cut at 256 characters."""
    scheme, _, sub = identity.partition(":")
    return f"{scheme}:{sub[:256]}"


def requesters(run):
    """Who controls `run`'s calls, each in pipeline.owner's form: its client (its owner, or the client a gateway
    registered it for, `caller`: the gateway's own writes in it are the client's then) and each other stream's writer
    (an identity the run was delegated to, a gateway's caller). The run's labels are each of theirs, and it carries
    each of theirs."""
    # lean: writers and a gateway's caller are run state (memory and snapshot), as quotas' are: a run replayed from the
    # log after the last snapshot has its owner alone until its writers write again on a new stream; record them in
    # the records if delegated or gateway runs must count exactly across a crash
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
    run of theirs in the run's tenant (a person answers for their own tenant; another writer's own runs stay theirs).
    Entries past `log.labels`' window go as their requester's key changes, and all of them at a snapshot (prune).
    `set_`, `pop`: as pipeline.contain_state's."""
    typ, d = e["type"], e["data"]
    if typ not in ("run.label", "run.closing") or not run.get("owner"):
        return
    me, now = f"{e['tenant']}\0{e['run_id']}", epoch(e["ts"])
    window = log.labels.window if log.labels else LABEL_INHERIT_S
    client = _who(run.get("caller") or run["owner"])
    for who in sorted(requesters(run)):
        held = log.carry.get(who) or {}
        if typ == "run.label" and d["action"] == "clear":
            tenant = f"{e['tenant']}\0"
            new = {x: {r: v for r, v in runs.items()
                       if x != d["label"] or not (r == me or who == client and r.startswith(tenant))}
                   for x, runs in held.items()}
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


def join(set_, log, run, who):
    """`who` (pipeline.writer's) writes open `run` for the first time: it carries the labels the run carries now, as
    their run.label adds would have given it had it written then."""
    who = _who(who.removesuffix(" through a gateway"))
    if not log.labels or run.get("closed") or not run.get("labels") or who in requesters(run):
        return
    me, held = f"{run['tenant']}\0{run['run_id']}", log.carry.get(who) or {}
    set_(log.carry, who, {**held, **{x: {**held.get(x, {}), me: [seq, None]} for x, seq in run["labels"].items()}})


def prune(log, now):
    """Drop the entries past the window from every requester's labels (on the writer: no answer changes)."""
    window = log.labels.window if log.labels else LABEL_INHERIT_S
    for who in list(log.carry):
        held = _live(log.carry[who], window, now)
        if held:
            log.carry[who] = held
        else:
            del log.carry[who]


def labels_for(log, run, now=None):
    """The labels `run`'s requesters (requesters: its client, delegates and gateway callers) carry from any run of
    theirs, in any tenant and under any principal: {label: [run_id, run_seq]}, each a label such a run carries while it
    is open and for the policy's label_inherit_s after it ends, with the record that added it there (an open run's
    first, else the one that ended last). `now`: epoch seconds (now by default). {} when the policy reads no label.
    Read it on the signer's writer (a RecordLog.submit fn) for an answer no write races: SignerService._decide adds
    them to the run before its run conditions, and an approver deciding one of the run's calls may read them the same
    way. One lookup per requester: the signer's other requesters cost it nothing."""
    if not log.labels:
        return {}
    now, best = time.time() if now is None else now, {}
    for who in requesters(run):
        for label, runs in (log.carry.get(who) or {}).items():
            for r, (seq, ended) in runs.items() if label in log.labels.tracked else ():
                if ended is None or epoch(ended) + log.labels.window > now:
                    rank = (ended is not None, -epoch(ended) if ended else 0, r)
                    if label not in best or rank < best[label][0]:
                        best[label] = (rank, r, seq)
    return {label: [r.split("\0", 1)[1], seq] for label, (_, r, seq) in best.items()}
