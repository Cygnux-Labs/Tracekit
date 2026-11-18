"""Run labels (docs/policy-v2.md#run-conditions): what a run has done that a run condition rule reads.

A pure function of signed records, as detection is: the single writer adds a label (a `run.label` record, `by:
signer`) right after the record that sets it, replay follows the run.label records, and the verifiers replay both
under the bundled policy. A record sets the labels of a call it lets run: a decision that allows or flags it, the
consume of its approval, or its executed_against_policy gap (it ran anyway). Those labels are each matched rule's
`label` of RUN_LABELS, and untrusted_content when the policy's `untrusted` list marks the tool's results, as the
provenance index reads them; an input observed as untrusted sets untrusted_content too. A run carries only the labels
its policy's run conditions name. A person clears one with run_label_clear; nothing a client sends sets or clears one.
"""
from tracekit.policy2.compile import SECTIONS

UNTRUSTED = "untrusted_content"   # of compile.RUN_LABELS


class Sources:
    def __init__(self, rules):
        """`rules`: an Engine, or a detect.Rules (a verifier's, which compiles no pattern)."""
        pol, self.rules = rules.policy, rules
        # each run condition rule's labels, by id; the labels some rule's condition names; the rules that set one
        rules = [r for sec in SECTIONS for r in pol.get(sec, [])]
        self.when = {r["id"]: frozenset(r["when"]["run_has"]) for r in rules if "when" in r}
        self.tracked = frozenset().union(*self.when.values())
        self.label = {r["id"]: r["label"] for r in rules if r.get("label") in self.tracked}

    @classmethod
    def of(cls, rules):
        """Sources when the policy has a run condition, else None (its runs carry no label)."""
        src = cls(rules)
        return src if src.tracked else None

    def of_call(self, tool, rule_ids):
        """The labels a call of `tool` that matched `rule_ids` sets when it runs."""
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
    it}. `set_`: as pipeline.agent_state's."""
    if e["type"] != "run.label":
        return
    d, have = e["data"], dict(run.get("labels") or {})
    if d["action"] == "add":
        have[d["label"]] = d["source"]
    else:
        have.pop(d["label"], None)
    set_(run, "labels", have)
