# Use cases

The problems teams bring to Tracekit, each with what goes wrong without it, what Tracekit does, and a way to see it
yourself: a video, a recorded run you can verify, or a command you can run. The demos use scripted models so they
repeat exactly; the signer, the policy, the viewer and the verifier in them are the real ones.

## "A support agent read a ticket that told it to delete orders, then hid it"

**Who has it:** teams running customer-support or operations agents that read tickets, emails or web pages.

A ticket carries a hidden instruction. The agent follows it, deletes 43 orders, then edits its own log so nothing
shows. The log is the only record, and the agent wrote it.

With Tracekit, each call is decided and signed by a signer the agent can't reach, before it runs, so the agent can't
edit what happened. A call whose recipient came only from untrusted content (a fetched page, a ticket) is held for a
person, and a secret read followed by an upload opens an incident that holds the run.

- Video: [the cover-up](demo/cover-up.mp4) (the agent's own log and Tracekit, side by side)
- Recorded runs: [prompt injection held by provenance](demos/prompt-injection/README.md),
  [detection and containment](demos/containment/README.md)

## "A coding agent found an old token and deleted production"

**Who has it:** engineering teams using Claude Code, Codex, Cursor, Gemini CLI or other coding agents with access to
real infrastructure.

Based on a public April 2026 incident: a coding agent found an old API token and deleted a production database volume
with one API call. Nothing stood between the agent and the API.

With Tracekit, destroying a deployment, database or volume is held for a person (`TK-A001`), and the approval covers
exactly the call that was asked for. The hooks can sit in admin-managed settings the agent's user can't remove
([deploy](deploy.md#admin-managed-hooks-claude-code)).

- Video: [the delete that never ran](use-cases/pocketos-hold.mp4) (50 s, a reconstruction)
- Recorded runs: [a production volume](demos/pocketos/README.md), [a production bucket](demos/cloud-storage/README.md),
  [guardrails for a coding agent](demos/guardrails/README.md)
- Set it up: [coding agents](coding-agents.md)

## "An agent refunded the wrong amount, or paid the wrong person"

**Who has it:** teams whose agents issue refunds, payouts or payments.

An agent with a payment API key can move money as fast as it can call the API, and a prompt injection can choose the
amount.

With Tracekit, calls that move money through Stripe, PayPal or Square are held for a person whatever API key the agent
holds (`TK-A043` to `TK-A045`). On the server packs every payment tool call waits for a person (`TK-M001`), which a
team can narrow, as the demo's does to refunds of $500 and up. The person sees the signer's copy of the arguments, and
the approval covers that exact amount and payee: a changed amount is refused.

- Video: [a refund agent and the evidence file](use-cases/buyer-evidence.mp4) (60 s)
- Details: [calls that move money](coding-agents.md#calls-that-move-money), [approvals](approvals.md)

## "Our customer's security team asks what our agent did, and how we know"

**Who has it:** companies selling an agent to other companies, and anyone facing a security review or an audit.

Screenshots and log exports prove nothing: whoever runs the system could have changed them.

With Tracekit, each run exports as one `.tkb` file that anyone can verify offline, without access to your systems, with
the command line or a single web page. Change one byte and verification fails and names the record. A run cut short
reads as incomplete, never as verified, and witnesses you or a partner run can cosign the log so the key holder can't
rewrite it.

- Video: [the file you hand your customer's security team](use-cases/buyer-evidence.mp4)
- Recorded runs: [completeness and tamper evidence](demos/completeness/README.md)
- Details: [for auditors](for-auditors.md), [witnesses](witnesses.md), [what a verified run proves](guarantees.md)

## "An AI assistant in a health programme changes a dose or shares a record"

**Who has it:** health programmes and clinics using AI assistants to support health workers.

The assistant reads charts, suggests doses, messages patients and shares data, and the only record is its own log.
In the demo it tells the health worker a dose was raised and a chart was shared, and neither happened.

With Tracekit and a policy the programme writes, a dose change waits for a supervising nurse and the approval covers
only that dose; patient data goes only to allowed hosts; an urgent referral runs at once and is flagged, because
delaying it is its own harm. The evidence file holds hashes, not the patient's data, so it can be checked without
exposing anyone's records.

- Video: [a community health worker's assistant](use-cases/health.mp4) (2 min, a synthetic patient)
- Details: [policy](policy-v2.md), [privacy](privacy.md)

## "Our agent runs code we didn't write"

**Who has it:** teams running agents in sandboxes, or running agent code they don't control.

A sandbox limits what the code can reach. It doesn't tell you what the agent did inside it, and the agent's own record
is still the agent's word.

With Tracekit, the sandbox's own decisions and the agent's calls go into the same signed record. Tracekit integrates
with NVIDIA OpenShell, and Tracekit Box runs each job in its own micro-VM whose only ways out are decided and signed.

- Video: [an agent in an OpenShell sandbox](use-cases/openshell.mp4) (60 s)
- Details: [OpenShell](integrations/openshell.md), [Tracekit Box](https://github.com/Cygnux-Labs/Tracekit-box) and
  its [paper](https://arxiv.org/abs/2610.38458)

## "Three agents ran, one bad email went out: which input caused it?"

**Who has it:** teams running several agents together, and whoever investigates after something goes wrong.

Agents read many inputs, and the one that mattered is rarely the obvious one.

With Tracekit, `tracekit why` replays a run without each input to show which one caused the outcome, and
`tracekit view` shows where every agent went (HORIZON), what each read before it acted (INFLUENCE) and every call and
decision, each one signed.

- Recorded run: [why](demos/why/README.md)
- Details: [the viewer](viewer.md), [the Event Horizon map](horizon.md), [why](why.md)

## "One agent tells another the work is approved"

**Who has it:** teams where agents ask other agents to act: refunds, deploys, purchases.

Agent B has only agent A's word for it. If A was prompt-injected, or someone sends a message in A's name, B acts anyway.

With Tracekit's proof-carrying messages (PCM), A's message carries signed evidence for each claim and a grant that sets
its limits, and B checks it offline before acting. A claim with no proof comes back `unproven`.

- Try it: `tracekit pcm demo`
- Details: [PCM](pcm.md)

## On real open-source agents

Tracekit on the OpenAI customer-service agents demo and on CrewAI, with a real model: what the integration took, what
the signed record caught and what it cost: [case study](case-study-oss-agents.md). Every feature's demo, as a recorded
run you can verify: [demos](demos/README.md).

Your problem isn't here? [Open an issue](https://github.com/Cygnux-Labs/Tracekit/issues) and tell us how you handle it
today.
