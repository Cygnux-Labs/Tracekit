---
name: Policy false negative
about: A risky tool call that a policy rule should have caught was allowed
labels: policy, false-negative
---

**The tool call that got through** (tool name and input; redact secrets and private paths)

**Which rule should have caught it**, or which rule is missing

**Output of** `tracekit --version`, the policy version, and your policy file, if you use a custom one

If this is a way for an agent to deliberately evade a rule that would otherwise catch it, do not open a
public issue: report it privately as described in SECURITY.md.
