---
name: Policy false positive
about: A policy rule blocked, flagged or asked for approval on something it should have allowed
labels: policy, false-positive
---

**Rule id and policy version** (`rule_ids` in the `policy.decision` event; the version is in `tracekit status`)

**The tool call that was matched** (tool name and input; redact secrets and private paths)

**Why it should have been allowed**

**Output of** `tracekit --version` and your policy file, if you use a custom one

If the rule can be bypassed, that is a false negative: use that template, or SECURITY.md if it is
exploitable.
