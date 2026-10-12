# Guardrails: allow, deny, or ask a person

A coding agent (a mock model, no API key) asks for three shell commands. The dev signer decides each before it runs:
`ls` is allowed, `sudo rm -rf /` is denied (TK-D001) and the agent goes on, and `echo "unterminated` is held
(TK-SHELL-PARSE: the signer can't parse it, so a person decides) until it is approved from a second process.

```sh
python examples/v2/custom/agent.py --scripted   # from a checkout, after pip install -e .
tracekit verify run.tkb --trust trust.json       # this folder's bundle
```

**What the record shows.** A signed `policy.decision` per call, with its verdict and rule ids; for the held call an
`approval.request`, `approval` and `approval.consumed` bound to its exact arguments; a `tool.result` only for the two
calls that ran. [verify.txt](verify.txt): `Integrity: VERIFIED`, `Assurance: dev; ... approvals: self` (a dev signer
runs as you, so you approved your own agent's call, and the bundle says so).

**Why it matters.** The verdict is made and signed outside the agent, before the call runs: nobody can turn the deny
into an allow afterwards and still have the bundle verify.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/custom/agent.py) ·
[quickstart](../../quickstarts/custom.md)
