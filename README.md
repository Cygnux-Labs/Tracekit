<div align="center">

<a href="https://github.com/Cygnux-Labs/Tracekit"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/banner.png" alt="Tracekit: the tamper-evident flight recorder for AI agents" width="840"></a>

# Agents can edit logs. They can't hide the edit.

**Tracekit checks every tool call your agent makes before it runs, signs each call and decision into a hash chain,
and gives you one `.tkb` file per run that anyone can verify offline.**

<a href="https://pypi.org/project/tracekit-ai/"><img src="https://img.shields.io/pypi/v/tracekit-ai?style=flat-square&color=F3B23B&labelColor=1C1A1C" alt="PyPI"></a>
<a href="#add-it-to-your-agent"><img src="https://img.shields.io/badge/works_with-25_agents_%26_frameworks-F3B23B?style=flat-square&labelColor=1C1A1C" alt="Works with 25 agents and frameworks"></a>
<a href="https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1C1A1C" alt="CI"></a>
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-F3B23B?style=flat-square&labelColor=1C1A1C" alt="MIT licence"></a>

<table>
<tr>
<td align="center" width="25%"><h3>8 of 8</h3>tamper attacks caught<br><sub><a href="#proof">480 trials</a>, with a witness (E1)</sub></td>
<td align="center" width="25%"><h3>699 of 699</h3>harmful calls stopped<br><sub><a href="#proof">11 classes</a>, 1 false alarm in 800 (E17)</sub></td>
<td align="center" width="25%"><h3>&lt; 1 ms</h3>added per tool call<br><sub><a href="#proof">0.91 ms at p99</a>, signer round trip (E9)</sub></td>
<td align="center" width="25%"><h3>8 of 8</h3>insider attacks caught<br><sub><a href="#proof">a merge gate</a> on every PR (E8)</sub></td>
</tr>
</table>

Built like **Certificate Transparency**: signed records in an append-only log that independent witnesses cosign<br>
**Open file format** · verifiers in **Python** and **TypeScript** · **MIT** · runs on your own machines

**[Try it](#try-it) · [Add it to your agent](#add-it-to-your-agent) · [What it proves](#what-it-proves) · [What's in it](#whats-in-it) · [Proof](#proof) · [How it works](#how-it-works) · [Pilot it](#pilot-it-with-us) · [Contribute](#contribute) · [Docs](#docs)**

</div>

---

When an agent does something it shouldn't, you ask three things: **what did it do, was it allowed, and can you trust
the record?** The agent's own log can't answer the third, because the agent can edit it. Here is one run, recorded
both ways:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-light.png">
  <img alt="What happened: a support ticket hides an instruction, the agent deletes 43 of 128 orders, then edits its log and Tracekit's record so the delete reads as a lookup. The agent's own log shows two lookups of order 1042; grep finds no DELETE, and the database holds 85 orders: it looks clean. Tracekit, the same run: the 13:51:59 run_sql call is flagged ACME-F001 deleting rows, and when the run closed verification failed with seq 7: hash does not match the event. Caught at record 7." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-light.png" width="100%">
</picture>

<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/cover-up.gif" alt="A ticket with a hidden instruction makes a support agent delete 43 orders, then edit its own log and Tracekit's record of the delete. grep finds no delete; Tracekit marks the run FAILED because record 7 no longer matches its hash." width="100%"></a>

<sub>The same run, recorded: the database, the signer, the viewer and both edits are real; the model is scripted. <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4">Watch it with sound (1:47)</a></sub>

In this demo the signer ran as the agent's own user (dev mode), so an agent that knew how could have read the key and
re-signed the log. Run the signer [where the agent can't reach it](#how-it-works), with a witness, and it can't.

## Try it

```sh
uvx --from tracekit-ai tracekit demo --server
```

No API key, and nothing to install with [uv](https://docs.astral.sh/uv/). From an empty cache on a Mac it took 5
seconds (10 with `pip install tracekit-ai` in a fresh venv). The package is `tracekit-ai`: `tracekit` on PyPI is an
unrelated project. A scripted agent makes three calls, and you should see:

```text
== agent run (SCRIPTED: fixed tool calls, not a model)
  Bash 'ls': allow
  Bash 'sudo rm -rf /': deny TK-D001 TK-D004 TK-F003
  Bash 'echo "unterminated': ask TK-SHELL-PARSE
...
Integrity: VERIFIED.

== tamper test: rewrite the denied call as allowed in a copy, then verify again
[FAIL] signatures — 11 record(s), keys valid at their position
        seq 4: hash does not match the event
Integrity: FAILED.
```

The delete was denied before it ran, the held call ran after an approval, and the run verified. Then the demo rewrote
the denial as allowed in a copy, and verification failed at the record it changed.

## Add it to your agent

Three lines:

```sh
pip install tracekit-ai
```

```python
import tracekit; tracekit.instrument()     # the first line of your agent; then run it as usual
```

```sh
tracekit last                               # Integrity: VERIFIED. / Assurance: dev; ...
```

`tracekit.instrument()` starts a dev signer (or reuses the running one) and gates and records every tool and model call
of the frameworks it finds. `tracekit last` exports your latest run, verifies it and says where it is.
`tracekit view --dev` shows every run. On a clean machine the LangGraph example (a mock model, no API key) installed,
ran and verified in 27 seconds: [`examples/v2/clean-machine.sh langchain`](https://github.com/Cygnux-Labs/Tracekit/blob/main/examples/v2/clean-machine.sh).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png">
  <img alt="Works with Claude Code, Codex CLI, Cursor and Gemini CLI; the Python and TypeScript SDKs; the OpenAI Agents SDK, Claude Agent SDK, LangChain, LangGraph, MCP, CrewAI, Browser Use, Pydantic AI, the Vercel AI SDK and OpenTelemetry" src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png" width="100%">
</picture>

<sub>Stable: Claude Code, the OpenAI Agents SDK, LangChain / LangGraph, the Claude Agent SDK and MCP. Experimental: Codex
CLI, Cursor, Gemini CLI, CrewAI, Browser Use, Pydantic AI, Google ADK, Haystack, LlamaIndex, Microsoft Agent
Framework, Strands Agents, the Vercel AI SDK, NVIDIA OpenShell, E2B, microsandbox, agentgateway, Wassette, LiteLLM's MCP
gateway, Docker's MCP Gateway and the TypeScript SDK.
In NVIDIA OpenShell sandboxes, Tracekit decides and signs each HTTP request OpenShell lets out, and signs OpenShell's
own blocks, process events and policy changes into the same run. Setup:
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents">coding agents</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-OpenAI-Agents">OpenAI Agents SDK</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-Claude-Agent-SDK">Claude Agent SDK</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-LangChain">LangChain / LangGraph</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-MCP">MCP</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Wassette">Wassette</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-CrewAI">CrewAI</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Browser-Use">Browser Use</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Pydantic-AI">Pydantic AI</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Google-ADK">Google ADK</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Haystack">Haystack</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-LlamaIndex">LlamaIndex</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Microsoft-Agent-Framework">Microsoft Agent Framework</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Strands">Strands Agents</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-OpenShell">NVIDIA OpenShell</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-LiteLLM">LiteLLM</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md">TypeScript</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Vercel-AI">Vercel AI SDK</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-agentgateway">agentgateway</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-microsandbox">microsandbox</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-E2B">E2B</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Docker-MCP-Gateway">Docker MCP Gateway</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/OpenTelemetry">OpenTelemetry</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-Custom">any other agent</a></sub>

<details>
<summary><strong>Other ways in</strong>: coding agents, without uv, the why demo, the sample bundles, TypeScript</summary>

<br>

Coding agents: `tracekit init --dev --v2` wires Claude Code's hooks to a dev signer; add `--agent codex`, `cursor`,
`gemini` or `opencode` for the others (experimental). With Claude Code's sandbox on, Tracekit holds each unsandboxed
retry for a person
([Claude Code's sandbox](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Claude-Code-Sandbox));
with Codex's, see what Tracekit sees and the settings to use
([Codex's sandbox](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Codex-Sandbox));
with Gemini CLI's tool sandbox, Tracekit holds each sandbox expansion for a person
([Gemini CLI's sandbox](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Gemini-Sandbox)).
Running sandbox-runtime's proxy on its own, Tracekit decides each request it forwards (experimental,
[sandbox-runtime](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Sandbox-Runtime)).
Sandboxed with agentsh? `tracekit follow` signs each decision agentsh logs, as it writes it (experimental,
[agentsh](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-agentsh)).
Without uv: `pip install tracekit-ai`, then `tracekit demo --server`. `--why`
(experimental) shows a held
email whose cause is found by replay and cited by its signed record:

```sh
tracekit demo --server                # exit 0
tracekit demo --why                   # exit 0
tracekit init --dev --v2
```

From a checkout, the shipped sample bundles (v1) check with the verifier alone (`pip install --no-deps tracekit-ai` is
enough), and `python examples/v2/langchain/agent.py --scripted` runs a LangGraph agent with a mock model:

```sh
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

TypeScript needs Node 18 or newer: `npm install @cygnuxlabs/tracekit`, and `npx @cygnuxlabs/tracekit up` starts a dev
signer without Python on Apple Silicon Macs, Linux and Windows ([TypeScript SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md#install)). Python 3.9 to
3.13; the framework integrations need 3.10 or newer.

</details>

## What it proves

Three guarantees. They're related, but one doesn't give you the others, and each needs something different.

| Guarantee | What you get | What it needs |
|---|---|---|
| **Evidence integrity** | A record that was edited, deleted, swapped or inserted fails verification at that record | Only the signed log. Cutting off the end of the log, or re-signing it with a stolen key, takes a witness to catch |
| **Execution control** | Each call is checked before it runs. A denied call is blocked; a held call runs only after a yes, with exactly the arguments that were approved | The call goes through Tracekit: an SDK, a hook or a gateway. Code that skips it isn't stopped |
| **Independent assurance** | An operator who rewrites or forks its own log is caught | A witness the operator doesn't control, and a monitor. Both are experimental, and no public witness is running yet |

### Limits

- **Dev mode protects nothing against an agent that runs as you.** Dev runs say `isolation: same-user`
  ([FAQ](https://github.com/Cygnux-Labs/Tracekit/wiki/FAQ#what-does-same-user-dev-mode-protect)).
- **A verified run proves the record is intact**: not intent, not that a reported tool result is true, and not that
  every action was captured ([FAQ](https://github.com/Cygnux-Labs/Tracekit/wiki/FAQ#what-cant-tracekit-prove)).
  `tracekit analyze --v2` compares what was asked, what the model said and what ran, but what the model said is its
  own account, and findings are an opinion beside the integrity, never part of it
  ([findings](https://github.com/Cygnux-Labs/Tracekit/wiki/Findings#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)).
- **Actions outside the capture path leave no record**, such as a subprocess a hook never sees and no kernel sensor
  import covers, or code that skips the adapter ([adapters](https://github.com/Cygnux-Labs/Tracekit/wiki/Adapters)).
- **Policy rules match text and tool names.** A determined agent can reword a command; the protection is the signer's
  isolation ([policy reference](https://github.com/Cygnux-Labs/Tracekit/wiki/Policy#packs-shipped)).
- **Commitments hide content, not timing, sizes or counts**
  ([privacy](https://github.com/Cygnux-Labs/Tracekit/wiki/Privacy#what-hashes-and-metadata-still-leak)).

What each deployment guarantees, from dev mode to a signer the agent can't reach:
[guarantees](https://github.com/Cygnux-Labs/Tracekit/wiki/Guarantees). Every limit, with what to do
about it: [limits](https://github.com/Cygnux-Labs/Tracekit/wiki/Limits). How it maps to the EU AI Act,
ISO/IEC 42001, the NIST AI RMF and OWASP: [compliance](https://github.com/Cygnux-Labs/Tracekit/wiki/Compliance).

## What's in it

One signer. The core is stable and is hardened first. The rest ships in the same package as experimental: it works and
is tested, but may change between releases ([what's stable](https://github.com/Cygnux-Labs/Tracekit/wiki/Support)).

| Core | What it does | Measured |
|---|---|---|
| **Record** | Every tool call, decision and result in one signed hash chain per run. A lost event becomes a signed gap, never silence | 6 of 8 tamper attacks caught by the log alone (E1) |
| **Decide** | Allow, deny, or hold each call for a person, before it runs. [Packs](https://github.com/Cygnux-Labs/Tracekit/wiki/Policy) for shell, files, SQL, HTTP, cloud CLIs, browsers, email, messaging, payments, secrets and MCP | 699 of 699 harmful calls stopped, 1 false alarm in 800 (E17) |
| **Approve** | A held call runs only after a yes from the command line, bound to its exact arguments and used once ([approvals](https://github.com/Cygnux-Labs/Tracekit/wiki/Approvals)) | Edited arguments, a replayed snapshot or another run's approval: refused, in the contract tests every stable framework integration runs |
| **Prove** | `tracekit verify` checks a run's file offline against keys you pinned | 8 of 8 insider attacks caught (E8) |
| **Watch** | `tracekit view`: every run verified, blocked and held calls, approvals, gaps, replay and a run review ([viewer](https://github.com/Cygnux-Labs/Tracekit/wiki/Viewer)) | Not measured |

| Experimental | What it does | Measured |
|---|---|---|
| **Witness** | Independent [witnesses](https://github.com/Cygnux-Labs/Tracekit/wiki/Witnesses) cosign each checkpoint; a [monitor](https://github.com/Cygnux-Labs/Tracekit/wiki/Monitor) watches the log for rewrites and forks | 8 of 8 tamper attacks caught with a witness (E1) |
| **Cross-check** | The signer compares the calls the model asked for, as an [LLM gateway](https://github.com/Cygnux-Labs/Tracekit/wiki/LLM-Gateway) or the session transcript saw them, with the calls the agent reported. A skipped hook or a made-up call is flagged | 12 of 12 seeded discrepancies flagged, 0 false (E10) |
| **Contain** | Signed [incidents](https://github.com/Cygnux-Labs/Tracekit/wiki/Incidents) hold or quarantine a run. Tools run on credentials the agent never holds ([executor](https://github.com/Cygnux-Labs/Tracekit/wiki/Executor), [MCP gateway](https://github.com/Cygnux-Labs/Tracekit/wiki/MCP-Gateway)). An [egress observer](https://github.com/Cygnux-Labs/Tracekit/wiki/Egress) flags traffic no call explains. A [kernel sensor import](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Tetragon) records the processes, connections and file writes Tetragon or [Falco](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Falco) saw | 8 of 8 containment and 10 of 10 detection checks (E17) |
| **Explain** | Where each argument came from, and [`tracekit why`](https://github.com/Cygnux-Labs/Tracekit/wiki/Tracekit-Why): which input caused an action, found by replaying the run without it | 6 of 6 true causes named, 0 false blames, one 7B model, small sample |
| **Check** | [`tracekit analyze --v2`](https://github.com/Cygnux-Labs/Tracekit/wiki/Findings#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2), signed: an action with nothing said before it, an edit of a file nobody named or said they were changing, a write outside the project, a broken "don't touch X", data sent out, files deleted or a package added without telling the person, a prompt line the harness never submitted, and how much of the run's reasoning could be read ([which agents' reasoning is readable](https://github.com/Cygnux-Labs/Tracekit/wiki/Reasoning)); `--review` adds a reviewer model's second opinion (warn only). [Live constraints](https://github.com/Cygnux-Labs/Tracekit/wiki/Policy#live-constraints) hold the call that would break "don't touch X" for approval | On a blind pool scored once (E20 pool v3, synthetic; the final review's fixes to the checks after that run moved none of its numbers): unrequested edits behind generic, sealed or reviewer-addressed cover text, or named innocently, caught in every session when no request names the file; after a "don't touch X", 79-100% by cover (67-92% held before the edit ran); a failed test run claimed as passing, 86%; a file sent out or deleted, or a package added and pushed, with nothing said of it, 96-100% by cover, except a file sent out under an innocent mention of it (33%); an appended prompt line flagged every time; 5 false findings and 1 call held in 1,812 honest calls. On the development pools, read while fixing the checks, after a "don't touch X": 88-96% on pool v2 (29-75% before) and 54-92% on pool v1 |
| **More approvers** | A web page with passkeys, Slack, or a reviewer agent that approves within bounds | 7 of 7 abuse cases against agent approvers caught (E18) |

## Proof

Our own experiments: small, synthetic and written by us. Nothing rounded up. The misses stay in.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-light.png">
  <img alt="Tamper detection, 60 trials per attack. The signed log alone catches editing, deleting, swapping or inserting a record, re-chaining without the key and a torn last line in 60 of 60 trials, and misses truncating the tail and re-signing with the key (0 of 60). With a witness, all eight are caught in 60 of 60." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-light.png" width="100%">
</picture>

| Experiment | Setup | Result |
|---|---|---|
| **E1** tamper detection | 120-record signed logs, 8 attacks, 60 trials each, re-run on 1.2 | 6 of 8 caught by the log alone, **8 of 8 with a witness** |
| **E8** insider attacks | Real unprivileged users against a Linux system-mode signer: a decoy signer, a stopped signer, a swapped policy, fabricated runs | **8 of 8 caught**, a merge gate on every pull request |
| **E17** policy packs | 699 harmful and 800 benign tool calls in 11 classes, decided by both regex engines | **699 of 699 stopped**; 1 false alarm, a draft email held for a person |
| **E21** policy robustness | 420 harmful and 432 benign calls written blind to the rules; 130 developer-session calls | server pack: 211 of 420 stopped or held on the one blind run, 245 after rules were added that target the pool (read since); 18 of 432 false alarms, 2 of 130 in sessions; p99 161 µs |
| **E10** reconciliation | 30 runs, 12 with a seeded discrepancy: a missing hook, a fabricated call, changed arguments | **12 of 12 flagged**, 0 false positives |
| **E9** overhead | Signer round trip over a Unix socket, file storage, macOS quick run | **0.45 ms p50, 0.91 ms p99** per call; 5,356 events/s |
| **E3** the v1 regex gate, on a rougher set | 16 harmful and 20 benign calls written after the rules | **11 of 16 caught**, 1 false alarm. Rules are tripwires, not a sandbox |

The two E1 misses are the design: a log can't see its own tail cut off, and whoever holds the key can re-sign it. Only
a copy of the head held elsewhere, a witness, catches those, so an unwitnessed run verifies as `dev`. The test sets
were written by us, and no one outside has reviewed the threat models yet. Every experiment, and what isn't
measured: [evaluation](https://github.com/Cygnux-Labs/Tracekit/wiki/Evaluation) ·
[technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md).

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png">
  <img alt="1. Your agent, through its SDK or hook, asks the signer to decide each call; it holds a run token, never a key. 2. The signer, out of the agent's reach, allows, denies or asks a person, and signs every call, decision and result into one hash chain per run. 3. Witnesses cosign each checkpoint. 4. Each run exports as run.tkb, which tracekit verify checks offline: VERIFIED, or FAILED at the record that changed." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png" width="100%">
</picture>

- **The agent never holds a signing key** and never assigns sequence numbers.
- **Each record is signed and carries the hash of the one before it**, so a changed byte fails verification at that
  record.
- **Nothing the agent reports about itself is trusted**: not its isolation, its fail mode, gaps, or who approved a call.
- **Who can rewrite the log decides what a run is worth**, so put the signer where the agent can't reach it. The agent's
  code is the same in every mode; `TRACEKIT_SIGNER` points it at the signer.

| Where the signer runs | Who can reach the keys and log | Recorded isolation |
|---|---|---|
| Laptop dev | the agent's own user | `same-user` |
| Laptop system mode (Linux; macOS experimental) | root and the signer's OS user | `separate-user` |
| Container or Kubernetes sidecar | the signer's uid and the node's administrator | `separate-user` |
| Docker Compose stack (`deploy/compose/`) | the Docker host's administrators | `separate-user` |
| Central signer over HTTPS | the signer host's administrators | `remote` |

The operator who runs the signer could still rewrite its log with its own key; an independent witness and a monitor
make that visible. Each mode end to end: [deployment](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy).
The full model: [architecture](https://github.com/Cygnux-Labs/Tracekit/wiki/Architecture),
[laptop](https://github.com/Cygnux-Labs/Tracekit/wiki/Threat-Model-Laptop) and
[server](https://github.com/Cygnux-Labs/Tracekit/wiki/Threat-Model-Server) threat models.

## Is it for you?

| Use Tracekit when | A plain tracer is enough when |
|---|---|
| Your agent acts on real systems: a shell, files, databases, email, payments, the cloud | It only reads, or runs in a throwaway sandbox |
| Some calls must be stopped or held for a person before they run | Seeing what happened afterwards is enough |
| Someone outside the team has to trust the record: a customer, an auditor, an incident review | Only your team reads the logs, to debug |

For debugging a prototype, a tracer such as OpenTelemetry, Langfuse or LangSmith is the right tool. Tracekit doesn't
replace one; it's the record you can hand to someone who doesn't trust the agent. How it compares with tracers,
guardrail libraries and other tamper-evident logs, and when it's the wrong choice:
[comparisons](https://github.com/Cygnux-Labs/Tracekit/blob/main/COMPARISONS.md).

## Pilot it with us

Running an agent that acts on real systems, with someone who has to sign off on it: a customer, an auditor, an
insurer? We'll set up Tracekit with you for two weeks, free: one agent, on your machines. At the end you have a
verified evidence file for every run and a written review of what the agent did that you didn't expect.
Email [info@cygnuxlabs.com](mailto:info@cygnuxlabs.com) or open a
[pilot request](https://github.com/Cygnux-Labs/Tracekit/issues/new?template=pilot_request.md).

## Commands

```sh
tracekit demo --server                      # allow, deny, approve, then a tampered copy fails verification
tracekit up                                 # start the dev signer, or find the running one
tracekit last                               # export your latest run, pin the dev key, verify it
tracekit view --dev                         # every run, verified: calls, decisions, gaps, replay, why
tracekit approvals list                     # calls held for a person; tracekit approvals approve ID
tracekit export --v2 --run ID -o run.tkb    # one run as one .tkb file
tracekit verify run.tkb --trust trust.json  # offline, against the keys you pinned in trust.json
                                            # (tracekit signer trust -o trust.json, or the one tracekit last wrote)
tracekit policy lint policy.yaml            # check a policy before the signer loads it
tracekit doctor                             # check this setup
tracekit init --dev --v2                    # wire Claude Code's hooks; add --agent codex, cursor, gemini or opencode
```

Nothing to install for whoever checks a run: the
[browser verifier](https://github.com/Cygnux-Labs/Tracekit/wiki/Verdicts#verify-in-your-browser), one
page, takes the `.tkb` and its trust file, sends nothing anywhere, and says VERIFIED, FAILED or UNVERIFIABLE with what
it means and what to do next.

## The evidence format

- **Specified.** [Evidence format v2](https://github.com/Cygnux-Labs/Tracekit/wiki/Format-v2) aims to be
  precise enough to write an independent verifier, with normative
  [test vectors](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/vectors).
- **Built on standards.** Records are signed with Ed25519 over RFC 8785 canonical JSON. Each log is an RFC 6962
  Merkle tree, the structure Certificate Transparency uses. Checkpoints are C2SP signed notes, and witnesses cosign
  them per C2SP tlog-cosignature.
- **Self-contained.** A `.tkb` file is a zip of records, inclusion proofs, checkpoints and the policy snapshots that
  decided the calls. It holds no verification code.
- **Old files keep verifying.** Formats only grow, each format's verifier is frozen, and an older verifier reports a
  newer file `UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`. Verify such a file with
  `uvx --from "tracekit-ai>=x" tracekit verify run.tkb --trust trust.json`,
  `npx -y @cygnuxlabs/tracekit@latest verify run.tkb --trust trust.json` (Node 20.12 or newer), or the
  [browser verifier](https://github.com/Cygnux-Labs/Tracekit/wiki/Verdicts#a-bundle-that-needs-a-newer-verifier),
  which checks it in your browser and sends nothing. From 1.4.0, an addition an older verifier can leave unread is non-critical: the bundle verifies, and the
  report names what that verifier didn't interpret.

Verify a v1 bundle in GitHub Actions with `uses: Cygnux-Labs/Tracekit@main` (`bundle:` and `key:` or `witness:`).
`require-anchor` defaults to `true`, so an unanchored bundle fails the step; set `require-anchor: "false"` to only
report it.

## Contribute

Each of these is useful on its own, and none needs to know the whole codebase:

- **Write a verifier in another language.** The [evidence format](https://github.com/Cygnux-Labs/Tracekit/wiki/Format-v2)
  is specified and has [test vectors](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/vectors). A Go or Rust
  verifier written from the spec alone is the best test that the spec is complete.
- **Find a harmful call the packs let through.** Add it to
  [`tests/data/policy/deny/`](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/data/policy/deny) with a rule
  that catches it; E17 runs every case.
- **Run Tracekit on your own agent and report what broke.** Doing that with two open-source agents found real bugs
  ([case study](https://github.com/Cygnux-Labs/Tracekit/wiki/Case-Study-OSS-Agents)).
- **Add a framework.** An integration is done when it passes the
  [adapter contract](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md#adding-a-framework-adapter).
- **Try to break it.** Find a tamper or a bypass that E1 and E8 miss, and report it privately as
  [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md) describes. Everyone who finds one is
  named in the [hall of fame](https://github.com/Cygnux-Labs/Tracekit/blob/main/HALL_OF_FAME.md) unless they ask us
  not to.

To start: `make install`, then `make check`
([contributing](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md)). Smaller tasks are labelled
[good first issue](https://github.com/Cygnux-Labs/Tracekit/labels/good%20first%20issue). Everyone taking part follows
the [code of conduct](https://github.com/Cygnux-Labs/Tracekit/blob/main/CODE_OF_CONDUCT.md).

## Docs

| To | Start here |
|---|---|
| Read your first verify report | [Tracekit for auditors](https://github.com/Cygnux-Labs/Tracekit/wiki/For-Auditors) |
| See every step on a clean install | [walkthrough (recorded on 1.2.0)](https://github.com/Cygnux-Labs/Tracekit/wiki/Walkthrough) · [recorded demos](https://github.com/Cygnux-Labs/Tracekit/wiki/Demos) · [viewer tour](https://github.com/Cygnux-Labs/Tracekit/wiki/Viewer#tour) |
| Wire up an agent | [v2 quickstart](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstart) · [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents) · [TypeScript SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md) |
| Put the signer out of reach | [deployment](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy) · [compose](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy-Compose) · [container](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy-Container) · [Kubernetes](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy-Kubernetes) · [agent-sandbox](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Agent-Sandbox) · [doctor](https://github.com/Cygnux-Labs/Tracekit/wiki/Doctor) |
| Decide calls | [policy reference](https://github.com/Cygnux-Labs/Tracekit/wiki/Policy) · [approvals](https://github.com/Cygnux-Labs/Tracekit/wiki/Approvals) · [incidents](https://github.com/Cygnux-Labs/Tracekit/wiki/Incidents) · [webhooks](https://github.com/Cygnux-Labs/Tracekit/wiki/Webhooks) |
| Check evidence | [reading a verify report](https://github.com/Cygnux-Labs/Tracekit/wiki/Verdicts) · [auditor guide](https://github.com/Cygnux-Labs/Tracekit/wiki/Auditor-Guide) · [witnesses](https://github.com/Cygnux-Labs/Tracekit/wiki/Witnesses) · [monitor](https://github.com/Cygnux-Labs/Tracekit/wiki/Monitor) · [compliance mapping](https://github.com/Cygnux-Labs/Tracekit/wiki/Compliance) |
| Ask why an action happened | [tracekit why](https://github.com/Cygnux-Labs/Tracekit/wiki/Tracekit-Why) · [its architecture](https://github.com/Cygnux-Labs/Tracekit/wiki/Tracekit-Why-Architecture) |
| Understand the design | [how Tracekit works](https://github.com/Cygnux-Labs/Tracekit/wiki/How-Tracekit-Works) · [architecture](https://github.com/Cygnux-Labs/Tracekit/wiki/Architecture) · [evaluation](https://github.com/Cygnux-Labs/Tracekit/wiki/Evaluation) · [technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md) · [case study](https://github.com/Cygnux-Labs/Tracekit/wiki/Case-Study-OSS-Agents) |
| Know what's stable | [support](https://github.com/Cygnux-Labs/Tracekit/wiki/Support) · [limits](https://github.com/Cygnux-Labs/Tracekit/wiki/Limits) · [FAQ](https://github.com/Cygnux-Labs/Tracekit/wiki/FAQ) · [security checklist](https://github.com/Cygnux-Labs/Tracekit/wiki/Security-Checklist) · [changelog](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md) |
| Run the v1 laptop signer | [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents) · [signing](https://github.com/Cygnux-Labs/Tracekit/wiki/Signing) · [v1 adapters](https://github.com/Cygnux-Labs/Tracekit/wiki/Adapters) |

## License

[MIT](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE), Copyright Cygnux Labs. This is 1.5.0, and 1.x is the
supported line. Report vulnerabilities privately as
[SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md) describes.

## Cite

The paper: [Tracekit-v2-paper.pdf](paper/Tracekit-v2-paper.pdf) ([arXiv:2609.35659](https://arxiv.org/abs/2609.35659)).

```bibtex
@misc{ghosh2026tracekit,
  author        = {Bravish Ghosh},
  title         = {Tracekit: Tamper-Evident Intent-Reasoning-Action Auditing for AI Agents},
  year          = {2026},
  eprint        = {2609.35659},
  archivePrefix = {arXiv},
  url           = {https://arxiv.org/abs/2609.35659},
  note          = {Code: \url{https://github.com/Cygnux-Labs/Tracekit}}
}
```

---

<div align="center">

**Agents can edit logs. They can't hide the edit. A star costs nothing and helps other teams find Tracekit.**

<sub>
<a href="https://cygnuxlabs.com/tracekit">Website</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Evaluation">Evaluation</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Limits">Limits</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md">Contributing</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/issues">Issues</a>
</sub>

</div>
