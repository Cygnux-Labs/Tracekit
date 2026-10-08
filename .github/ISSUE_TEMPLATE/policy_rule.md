---
name: Policy false positive / false negative
about: A policy rule blocked something safe, or let something risky through
labels: policy
---

**Which kind?** False positive (safe action flagged or blocked) / false negative (risky action allowed)

**Rule id and pack** (from the event's policy decision or `tracekit verify` output; `none` for a false negative)

**The tool call** (tool name and input, with secrets, hostnames and personal data removed)

**What you expected the policy to decide, and why**

**Output of** `tracekit --version`

For a policy bypass that an agent could use to evade the gate, do not open an issue: see SECURITY.md.
