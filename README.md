<p align="center">
  <a href="https://github.com/Cygnux-Labs/Tracekit"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/banner.png" alt="Tracekit: the tamper-evident flight recorder for AI agents" width="840"></a>
</p>

<p align="center">
  Tracekit checks every tool call your agent makes before it runs, records each call and decision in a signed hash
  chain, and exports every run as one file that anyone can verify offline.
</p>

<p align="center">
  <a href="https://pypi.org/project/tracekit-ai/"><img alt="PyPI" src="https://img.shields.io/pypi/v/tracekit-ai?style=flat-square&color=F3B23B&labelColor=1C1A1C"></a>
  <a href="https://pypi.org/project/tracekit-ai/"><img alt="Python 3.9 to 3.13" src="https://img.shields.io/pypi/pyversions/tracekit-ai?style=flat-square&color=F3B23B&labelColor=1C1A1C"></a>
  <a href="https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1C1A1C"></a>
  <a href="#add-it-to-your-agent"><img alt="Works with 13 agents and frameworks" src="https://img.shields.io/badge/works_with-13_agents_%26_frameworks-F3B23B?style=flat-square&labelColor=1C1A1C"></a>
  <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE"><img alt="MIT licence" src="https://img.shields.io/badge/license-MIT-F3B23B?style=flat-square&labelColor=1C1A1C"></a>
</p>

<p align="center">
  <b><a href="#try-it-in-one-command">Try it</a> · <a href="#how-it-works">How it works</a> · <a href="#add-it-to-your-agent">Integrations</a> · <a href="#proof">Proof</a> · <a href="#limits">Limits</a> · <a href="#docs">Docs</a> · <a href="https://cygnuxlabs.com/tracekit">Website</a></b>
</p>

<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/cover-up.gif" alt="A ticket with a hidden instruction makes a support agent delete 43 orders, then edit its own log and Tracekit's record of the delete. grep finds no delete; Tracekit marks the run FAILED because record 7 no longer matches its hash." width="100%"></a>

<p align="center"><sub>An injected ticket makes the agent delete 43 orders, then edit its log and Tracekit's record. <code>grep</code> finds nothing; Tracekit marks the run FAILED. The model is scripted; everything else is real. <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4">Watch it with sound (1:47)</a></sub></p>

## Try it in one command

No API key, and with [uv](https://docs.astral.sh/uv/) nothing to install:

```sh
uvx --from tracekit-ai tracekit demo --server
```

A scripted agent runs three shell commands: one allowed, one denied before it runs, one held for approval. Then the
demo rewrites the denied call as allowed in a copy of the run, and verifies both:

```text
  Bash 'ls': allow
  Bash 'sudo rm -rf /': deny TK-D001 TK-D004 TK-F003
  Bash 'echo "unterminated': ask TK-SHELL-PARSE
Integrity: VERIFIED.

== tamper test: rewrite the denied call as allowed in a copy, then verify again
[FAIL] signatures — 11 record(s), keys valid at their position
        seq 4: hash does not match the event
Integrity: FAILED.
```

<details>
<summary>Without uv, and more demos</summary>

<br>

`pip install tracekit-ai`, then `tracekit demo --server`. `--why` shows a held email whose cause is found by replay and
cited by its signed record. `init --dev --v2` wires Claude Code's hooks to a dev signer:

```sh
tracekit demo --server                # exit 0
tracekit demo --why                   # exit 0
tracekit init --dev --v2
```

From a checkout, `python examples/v2/langchain/agent.py --scripted` runs a LangGraph agent with a mock model, and the
shipped sample bundles (v1) check with the verifier alone (`pip install --no-deps tracekit-ai` is enough):

```sh
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

</details>

## Why: the agent's own log vs Tracekit

An agent's log is written by the agent. When a prompt injection or a bug makes it do damage, it can rewrite that log
too, and `grep` finds nothing.

| | The agent's own log | Tracekit |
|---|---|---|
| A risky call | ❌ written down after it ran | ✅ checked before it runs: allowed, denied, or held for a person |
| The agent edits a line | ❌ nothing shows | ✅ verification fails at that record |
| The agent deletes a line | ❌ nothing shows | ✅ the chain has a hole, and the run won't export |
| An event never arrives | ❌ silence | ✅ a signed gap record |
| Someone else has to check it | ❌ they trust you | ✅ they verify one `.tkb` file offline, with keys they pinned |
| The operator rewrites history | ❌ nothing shows | ✅ an independent witness and a monitor make it visible |

> [!IMPORTANT]
> In dev mode the signer runs as your own user, so an agent that runs commands as you can read its key and re-sign
> the log. The table holds when the signer runs [where the agent can't reach it](#run-it-where-the-agent-cant-reach-it):
> as a separate OS user, in a container sidecar, or on a central host, with a witness the operator doesn't control.

## Add it to your agent

```sh
pip install tracekit-ai
```

```python
import tracekit; tracekit.instrument()     # the first line of your agent; then run it as usual
```

```sh
tracekit last                               # Integrity: VERIFIED. / Assurance: dev; ...
```

`tracekit.instrument()` starts a dev signer in the background (or reuses the running one) and gates and records every
tool and model call of the frameworks it finds. `tracekit last` exports the most recent finished run, verifies it and
says where it is; `tracekit view --dev` browses every run. A call held for a person (`ask`) pauses the run or waits,
depending on the framework ([how each integration waits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md#when-a-call-needs-a-person-ask)).
For coding agents, `tracekit init --dev --v2` wires Claude Code's hooks; add `--agent codex`, `cursor` or `gemini` for
the others.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png">
  <img alt="Works with Claude Code, Codex CLI, Cursor and Gemini CLI; the Python and TypeScript SDKs; the OpenAI Agents SDK, Claude Agent SDK, LangChain, LangGraph, MCP, CrewAI, Browser Use, the Vercel AI SDK and OpenTelemetry" src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png" width="100%">
</picture>

Setup for each:
[coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md) ·
[OpenAI Agents SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/openai-agents.md) ·
[Claude Agent SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/claude-agent-sdk.md) ·
[LangChain / LangGraph](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/langchain.md) ·
[MCP](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/mcp.md) ·
[CrewAI](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/integrations/crewai.md) ·
[Browser Use](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/integrations/browser-use.md) ·
[TypeScript and the Vercel AI SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md) ·
[OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/otel.md) ·
[any other agent](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/custom.md) ·
[LLM gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/gateway.md)

### See it

`tracekit view` is the one viewer: every run verified, every call with its decision, and why an action happened.

<table>
  <tr>
    <td width="33%" align="center"><a href="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/denied.png"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/denied.png" alt="tracekit view: two shell calls blocked by policy, each a signed alert"></a><br><sub><b>Blocked before it ran</b>: each denial a signed record</sub></td>
    <td width="33%" align="center"><a href="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/why-view.png"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/why-view.png" alt="tracekit view: why did it happen? the primary cause found by replaying the run without each input"></a><br><sub><b>Why did it happen?</b> The cause, found by replay</sub></td>
    <td width="33%" align="center"><a href="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/graph-node.png"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/graph-node.png" alt="tracekit view: the planner's model call clicked in the run graph, with what it saw, produced and led to"></a><br><sub><b>The run as a graph</b>: what each step saw and led to</sub></td>
  </tr>
</table>

Every panel: [viewer tour](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md#tour). Every step on a
clean install, with real output: [walkthrough](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/walkthrough.md).

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png">
  <img alt="1. Your agent, through its SDK or hook, asks the signer to decide each call; it holds a run token, never a key. 2. The signer, out of the agent's reach, allows, denies or asks a person, and signs every call, decision and result into one hash chain per run. 3. Witnesses cosign each checkpoint. 4. Each run exports as run.tkb, which tracekit verify checks offline: VERIFIED, or FAILED at the record that changed." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png" width="100%">
</picture>

- **The agent never holds a signing key** and never assigns sequence numbers. Each record is signed and carries the
  hash of the one before it, so changing any byte of a record makes verification fail at that record.
- **Nothing the agent reports about itself is trusted**: not its isolation, its fail mode, gaps, or who approved a
  call. The signer measures or configures these itself.
- **Who can rewrite the log decides what a bundle is worth.** A dev signer runs as you; a signer under a separate OS
  user, in a sidecar or on a central host is out of the agent's reach.
- **The operator could still rewrite the log with its own key.** An independent witness and a monitor make that
  visible.

The full model: [architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/architecture.md),
[laptop](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-laptop.md) and
[server](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-server.md) threat models.

## Proof

<table>
  <tr>
    <td width="25%" align="center"><h3>8 of 8</h3>tamper attacks caught with a witness<br><sub>60 trials each (E1)</sub></td>
    <td width="25%" align="center"><h3>6 of 8</h3>caught by the signed log alone<br><sub>the 2 misses are by design</sub></td>
    <td width="25%" align="center"><h3>8 of 8</h3>insider attacks caught<br><sub>a merge gate on every PR (E8)</sub></td>
    <td width="25%" align="center"><h3>0</h3>signing keys the agent holds<br><sub>one file per run, verified offline</sub></td>
  </tr>
</table>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-light.png">
  <img alt="Tamper detection, 60 trials per attack. The signed log alone catches editing, deleting, swapping or inserting a record, re-chaining without the key and a torn last line in 60 of 60 trials, and misses truncating the tail and re-signing with the key (0 of 60). With a witness, all eight are caught in 60 of 60." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/proof-light.png" width="100%">
</picture>

The two misses are the point: a log can't see its own tail cut off, and whoever holds the key can re-sign it. Only a
copy of the head held elsewhere, a witness, catches those, which is why an unwitnessed bundle verifies as `dev`.
E8 attacks a Linux system-mode signer as real unprivileged users (a decoy signer, a stopped signer, a swapped policy,
fabricated runs) and blocks the merge on any miss. Every experiment, and what isn't measured:
[evaluation](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/evaluation.md),
[technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md).

## What it does

<table>
  <tr>
    <td width="17%"><b>Record</b></td>
    <td>Every tool call, decision and result, plus model calls and approvals, signed in one chain per run. Lost events become signed gaps.</td>
  </tr>
  <tr>
    <td width="17%"><b>Decide</b></td>
    <td>Each call allowed, denied, or held for a person, by <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md">policy packs</a> for coding, server and browser agents, SQL, HTTP, cloud CLIs, payments and messaging.</td>
  </tr>
  <tr>
    <td width="17%"><b>Approve</b></td>
    <td>A held call runs only after a yes from the CLI, a web page with OIDC and passkeys, or Slack, bound to the exact arguments and used once; a reviewer agent may answer routine ones (<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md">approvals</a>).</td>
  </tr>
  <tr>
    <td width="17%"><b>Contain</b><br><sub>experimental</sub></td>
    <td>Signed <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/incidents.md">incidents</a> that hold or quarantine a run; tools run with credentials the agent never holds (<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/executor.md">executor</a>, <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/mcp-gateway.md">MCP gateway</a>); an <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/egress.md">egress observer</a> flags network effects no call explains.</td>
  </tr>
  <tr>
    <td width="17%"><b>Prove</b></td>
    <td><code>tracekit verify</code> checks a bundle offline against keys you pinned; <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md">witnesses</a> cosign checkpoints and a <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md">monitor</a> watches the log; each report states its <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md">assurance level</a>.</td>
  </tr>
  <tr>
    <td width="17%"><b>Watch</b></td>
    <td><code>tracekit view</code>: verdicts, blocked and held calls, approvals, gaps, replay and a run review (<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md">viewer</a>).</td>
  </tr>
  <tr>
    <td width="17%"><b>Explain</b><br><sub>experimental</sub></td>
    <td>Where each argument came from (<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md#provenance-untrusted-and-from-untrusted">provenance</a>), and which input caused an action: <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why.md"><code>tracekit why</code></a> replays the run without each suspect input.</td>
  </tr>
</table>

## Run it where the agent can't reach it

The agent's code is the same in every mode; `TRACEKIT_SIGNER` points it at the signer.

| Mode | Who can reach the keys and log | Recorded isolation |
|---|---|---|
| Laptop dev | the agent's own user | `same-user` |
| Laptop system mode (Linux; macOS experimental) | root and the signer's OS user | `separate-user` |
| Container or Kubernetes sidecar | the signer's uid and the node's administrator | `separate-user` |
| Central signer over HTTPS (or Docker Compose) | the signer host's administrators | `remote` |

Each mode end to end, with its `tracekit doctor` check and the assurance its bundles reach:
[deployment guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md). From the v1 signer or a laptop
to a server: [migration](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/migration.md).

<details>
<summary>What you need</summary>

<br>

- **Python 3.9 to 3.13**, and `pip install tracekit-ai`. The framework integrations need Python 3.10 or newer. For the
  TypeScript SDK, Node 18 or newer and the package file from the GitHub release:
  `npm install https://github.com/Cygnux-Labs/Tracekit/releases/download/v1.2.0/cygnux-tracekit-1.2.0.tgz`. It isn't
  on npm yet ([TypeScript SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md#install)).
- **An OS.** Dev mode runs on macOS, Linux and Windows. A signer under its own OS user runs on Linux (macOS is
  experimental). Containers and Kubernetes run on Linux
  ([platforms](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/portability.md)).
- **For protection against the agent:** a signer the agent can't reach.
- **For protection against the operator:** a witness the operator doesn't control, and a monitor.
- **For approvals by people:** approvers listed in the signer's config, answering from the command line, an OIDC
  identity provider (web page, passkeys) or Slack ([identity](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/identity.md)).

</details>

## Limits

- **Dev mode protects nothing against an agent that runs as you.** Dev bundles say `isolation: same-user`
  ([FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md#what-does-same-user-dev-mode-protect)).
- **A verified bundle proves the record is intact**, not intent, not that a reported tool result is true, and not that
  every action was captured ([FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md#what-cant-tracekit-prove)).
- **Actions outside the capture path leave no record**, such as a subprocess a hook never sees or code that skips the
  adapter ([adapters](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/adapters.md)).
- **Policy rules match text and tool names.** A determined agent can reword a command; rules are tripwires, and the
  protection is the signer's isolation ([policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md#packs-shipped)).
- **Without an independent witness, the operator can rewrite the log unseen**, and commitments hide content, not
  timing, sizes or counts ([privacy](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/privacy.md#what-hashes-and-metadata-still-leak)).

Every limit, with what to do about it: [docs/limits.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md)

## The evidence format

- **Specified.** [Evidence format v2](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/format-v2.md) aims to be
  precise enough to write an independent verifier, with normative
  [test vectors](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/vectors).
- **Built on standards.** JCS canonical JSON (RFC 8785), Ed25519 signatures, an RFC 6962 Merkle tree per log, C2SP
  signed-note checkpoints, cosigned per C2SP tlog-cosignature.
- **Self-contained.** A bundle is a zip of records, inclusion proofs, checkpoints and the policy snapshots that decided
  the calls. It holds no verification code; the verifier checks it offline against a trust file you pinned.
- **Old bundles keep verifying.** Formats only grow, each format's verifier is frozen, and an older verifier reports a
  newer bundle `UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`.

Verify a v1 bundle in GitHub Actions with `uses: Cygnux-Labs/Tracekit@main` (`bundle:` and `key:` or `witness:`).
`require-anchor` defaults to `true`, so an unanchored bundle fails the step; set `require-anchor: "false"` to only
report it.

## Docs

| To | Start here |
|---|---|
| See every step on a clean install | [walkthrough](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/walkthrough.md), [recorded demos](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demos/README.md), [terminal tour](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demos/tracekit-tour.mp4) (3:44) |
| Wire up an agent | [v2 quickstart](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md), [coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md), [TypeScript SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md) |
| Put the signer out of the agent's reach | [deployment](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md), [compose](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-compose.md), [container](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-container.md), [Kubernetes](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-kubernetes.md), [doctor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/doctor.md) |
| Decide calls | [policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md), [approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md), [incidents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/incidents.md), [webhooks](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/webhooks.md) |
| Check evidence | [reading a verify report](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md), [auditor guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/auditor-guide.md), [witnesses](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md), [monitor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md) |
| Ask why an action happened | [tracekit why](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why.md), [its architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why-architecture.md) |
| Understand the design | [architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/architecture.md), [evaluation](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/evaluation.md), [technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md), [case study: two open-source agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/case-study-oss-agents.md) |
| Know what's stable and what isn't | [support](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/support.md), [limits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md), [FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md), [security checklist](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/security-checklist.md), [privacy](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/privacy.md) |
| Run the v1 laptop signer (`tracekitd`) | [coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md), [signing](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/signing.md), [v1 integrations](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/integrations.md) |

## Status

This is 1.2.0, and 1.x is the supported line. Stable: evidence format v2 and its verifiers, the v2 signer (dev and
Linux system mode), `tracekit.instrument()` with its OpenAI Agents, LangChain / LangGraph, Claude Agent SDK and MCP
integrations, the Claude Code hooks, policy v2, `tracekit view` and `tracekit doctor`. Everything else works and is
tested but is experimental, and says so when it starts. Not yet done: an external review of the threat models
([what's stable](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/support.md),
[changelog](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md)).

## Contributing, security and licence

[CONTRIBUTING.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md): `make install`, then `make check`.
Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md).
MIT, Copyright Cygnux Labs ([LICENSE](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE)).

---

<p align="center">
  <b>If an agent acts for you, keep a record it can't quietly edit.</b><br>
  A ⭐ helps other teams find Tracekit.
</p>

<p align="center"><sub>
  <a href="https://cygnuxlabs.com/tracekit">Website</a> ·
  <a href="https://pypi.org/project/tracekit-ai/">PyPI</a> ·
  <a href="https://github.com/Cygnux-Labs/Tracekit/issues">Issues</a> ·
  <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md">Limits</a> ·
  <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md">Security</a>
</sub></p>
