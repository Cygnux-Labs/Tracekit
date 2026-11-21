"""Run labels (docs/policy-v2.md#run-conditions): what a run has done that a run condition rule reads.

A pure function of signed records, as detection is: the single writer adds a label (a `run.label` record, `by:
signer`) right after the record that sets it, replay follows the run.label records, and the verifiers replay both
under the bundled policy. A record sets the labels of a call it lets run: a decision that allows or flags it, the
consume of its approval, or its executed_against_policy gap (it ran anyway). Those labels are each matched rule's
`label` of RUN_LABELS, every label a run condition reads for a call the policy couldn't read (TK-OVERSIZE), and
untrusted_content when the policy's `untrusted` list marks the tool's results, as the provenance index reads them; an
input observed as untrusted sets untrusted_content too. A harness call (a message to the agent's own agents) sets none.
A run carries only the labels its policy's run conditions name.

Labels belong to the requester (pipeline.cooldown_key's tenant, owner and attested principal), not only the run: a
run of theirs inherits each label another run of theirs carries while that run is open and for the policy's
`label_inherit_s` after it ends (labels_for), as a `run.label` add naming the record it inherits (`inherited`) before
its next decision; so ending a run, or starting another, keeps a label. A person clears one with run_label_clear, for
the run and its requester; nothing a client sends sets or clears one.
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
        # each run condition rule's labels, by id; the labels some rule's condition names; the rules that set one
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.when = {r["id"]: frozenset(r["when"]["run_has"]) for r in rules if "when" in r}
        self.tracked = frozenset().union(*self.when.values())
        self.label = {r["id"]: r["label"] for r in rules if r.get("label") in self.tracked}
        self.window = pol.get("label_inherit_s", LABEL_INHERIT_S)

    @classmethod
    def of(cls, rules):
        """Sources when the policy has a run condition, else None (its runs carry no label)."""
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


def _key(tenant, owner, principal):
    return f"{tenant}\0{owner}\0{principal or ''}"   # pipeline.cooldown_key's


def _keys(carry, tenant, owner, principal):
    """The requester keys a run of (tenant, owner, principal) reads: its own, and with no attested principal every
    principal's of its owner (dropping one gains nothing), as an inherited hold's."""
    if principal:
        return [_key(tenant, owner, principal)]
    return [k for k in carry if k.startswith(_key(tenant, owner, ""))]


def carry(set_, log, run, e, pop):
    """Follow record `e` of `run` in the labels its requester carries, `log.carry`: {cooldown_key: {label: {run_id:
    [the run_seq of its run.label add, the ts the run ended or None while it is open]}}}: a run.label add enters the
    run's, a person's clear leaves the requester's (every run of theirs) and a run.closing ends the run's; entries past
    `log.labels`' window go as their key changes. `set_`, `pop`: as pipeline.contain_state's."""
    # lean: a requester's expired entries go only when another run of theirs records a label or ends; prune every key
    # at snapshot time if a signer serves many requesters who never come back
    typ, d = e["type"], e["data"]
    if typ not in ("run.label", "run.closing") or "owner" not in run:
        return
    tenant, owner, principal = e["tenant"], run["owner"], run["people"][1]
    if typ == "run.label" and d["action"] == "clear":
        for k in _keys(log.carry, tenant, owner, principal):
            rest = {x: v for x, v in log.carry[k].items() if x != d["label"]}
            set_(log.carry, k, rest) if rest else pop(log.carry, k)
        return
    k, now = _key(tenant, owner, principal), epoch(e["ts"])
    window = log.labels.window if log.labels else LABEL_INHERIT_S
    held = {x: {r: v for r, v in runs.items() if v[1] is None or epoch(v[1]) + window > now}
            for x, runs in (log.carry.get(k) or {}).items()}
    if typ == "run.label":
        held[d["label"]] = {**held.get(d["label"], {}),
                            e["run_id"]: [e["run_seq"], e["ts"] if run.get("closed") else None]}
    else:
        held = {x: {r: [v[0], e["ts"]] if r == e["run_id"] and v[1] is None else v for r, v in runs.items()}
                for x, runs in held.items()}
    held = {x: runs for x, runs in held.items() if runs}
    if held != log.carry.get(k, {}):
        set_(log.carry, k, held) if held else pop(log.carry, k)


def labels_for(log, tenant, owner, principal, now=None):
    """The run labels the requester (tenant, owner, attested principal or None) carries: {label: [run_id, run_seq]},
    each a label a run of theirs carries while it is open and for the policy's label_inherit_s after it ends, with the
    run.label record that added it there (an open run's first). `owner`: as a run's (pipeline.owner); with no attested
    principal, every principal's of the owner counts. `now`: epoch seconds (now by default). {} when the policy has no
    run condition. Read it on the signer's writer (a RecordLog.submit fn) for an answer no write races: a decision
    in any run of the requester applies these labels (SignerService._decide), and so may an approver deciding a call
    of theirs."""
    if not log.labels:
        return {}
    now, out = time.time() if now is None else now, {}
    for k in _keys(log.carry, tenant, owner, principal):
        for label, runs in log.carry[k].items():
            live = sorted(((v[1] is not None, -(epoch(v[1]) if v[1] else 0), r), v) for r, v in runs.items()
                          if label in log.labels.tracked and (v[1] is None or epoch(v[1]) + log.labels.window > now))
            if live and (label not in out or not live[0][0][0]):
                out[label] = [live[0][0][2], live[0][1][0]]
    return out
