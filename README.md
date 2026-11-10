<div align="center">

<a href="https://github.com/Cygnux-Labs/Tracekit"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/banner.png" alt="Tracekit: the tamper-evident flight recorder for AI agents" width="840"></a>

# The tamper-evident flight recorder for AI agents

**Stop risky tool calls before they run. Record every action in a log no one can quietly change, not even the agent.
Hand anyone one file that proves what happened.**

<a href="https://pypi.org/project/tracekit-ai/"><img src="https://img.shields.io/pypi/v/tracekit-ai?style=flat-square&color=F3B23B&labelColor=1C1A1C" alt="PyPI"></a>
<a href="#add-it-in-three-lines"><img src="https://img.shields.io/badge/works_with-34_agents_%26_frameworks-F3B23B?style=flat-square&labelColor=1C1A1C" alt="Works with 34 agents and frameworks"></a>
<a href="https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1C1A1C" alt="CI"></a>
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-F3B23B?style=flat-square&labelColor=1C1A1C" alt="MIT licence"></a>

**Stop** · **Record** · **Prove**

Open source (MIT) · runs on your machines · nothing leaves them unless you send it · &lt; 1 ms per tool call

**[See what your agent did](#see-what-your-coding-agent-did-last-week) · [Try the demo](#try-it-in-5-seconds) · [Who it's for](#who-its-for) · [Add it](#add-it-in-three-lines) · [How it works](#how-it-works) · [Proof](#proof-misses-included) · [Pilot](#pilot-it-with-us) · [Docs](#docs)**

</div>

---

## Your agent can act. Can you prove what it did?

Agents now run shell commands, edit code, query databases, send email and move money. Sooner or later one of them does
something nobody expected, and three questions land on your desk:

1. **What exactly did it do?**
2. **Was it allowed to?**
3. **Can anyone trust the answer?**

Your agent's own logs can answer the first two, roughly. They can't answer the third: the agent, a bug, or anyone with
write access can change them, and nothing would show it.

Tracekit sits in the tool-call path, the way a flight recorder sits in a plane:

| | What Tracekit does |
|---|---|
| **Stop** | Checks every tool call *before it runs*: allow, deny, or hold it for a person. An approval covers exactly the arguments that were approved, once. |
| **Record** | Signs every call, decision and result into a hash chain held by a signer the agent can't reach. A lost event becomes a signed gap, never silence. |
| **Prove** | Exports each run as one `.tkb` file. Anyone can verify it offline, even in a browser, and see `VERIFIED`, or `FAILED` with the record that was changed. |

Here is one run, recorded both ways. A support ticket hides an instruction; the agent deletes 43 orders, then rewrites
its own log and Tracekit's record so the delete reads as a lookup:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-light.png">
  <img alt="The agent's own log shows two lookups of order 1042 and grep finds no DELETE. Tracekit's record of the same run flags the run_sql call as deleting rows, and verification fails at record 7: hash does not match the event." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/cover-up-light.png" width="100%">
</picture>

<sub>The agent's log looks clean. Tracekit's record shows the delete, and the edit fails verification at the exact
record that was changed. <a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4">Watch the 1:47 video</a>
(real database, signer and viewer; scripted model).</sub>

## See what your coding agent did last week

No install, no account, nothing wired into your agent, nothing leaves your machine. Point it at your Claude Code
sessions and see every call Tracekit would have blocked or held:

```sh
uvx --from tracekit-ai tracekit audit --since 7d
```

Most people find at least one surprise. Add `--share` to get counts only, which you can post as a
[field report](docs/field-reports.md).

## Try it in 5 seconds

```sh
uvx --from tracekit-ai tracekit demo --server
```

No API key; from an empty cache on a Mac it took 5 seconds. A scripted agent lists the files, then tries five risky
things a real agent might, and Tracekit decides each one before it runs:

| The scripted agent tries to | Tracekit |
|---|---|
| list the files | allows it |
| delete the home folder, hidden in base64 | holds it for a person, who rejects it: it never runs |
| run a downloaded script (`curl … \| sh`) | denies it |
| read `~/.aws/credentials` | denies it |
| send `.env` to a host a web page named | holds it for a person, who rejects it: it never runs |
| force-push to main | denies it |

Then it verifies the run, and verifies a copy with one record edited:

```text
VERIFIED: 6 tool calls in 17 signed records, none changed, removed or added after signing.
NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could have rewritten the record.
...
== tamper test: rewrite the downloaded script's deny as allow in a copy, then verify again
TAMPERED at event 8: its content was changed after it was signed.
```

<sub>The package is `tracekit-ai`; `tracekit` on PyPI is an unrelated project. Without uv: `pip install tracekit-ai`
then `tracekit demo --server`.</sub>

## Who it's for

Tracekit is one product, but people come to it with different problems. Find yours:

| If you are… | You're probably thinking… | What Tracekit gives you | Start here |
|---|---|---|---|
| **A developer using coding agents** (Claude Code, Codex, Cursor, Gemini CLI) | *"I let it run on autopilot. What did it actually touch? Did it ever try `rm -rf` or a force-push?"* | A record of every command and edit, with the dangerous ones blocked or held for you to approve | [`tracekit audit`](#see-what-your-coding-agent-did-last-week) · [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents) |
| **An engineer shipping an agent to production** (support, ops, data, finance) | *"It works in the demo. I can't let it near real databases, email or payments until something stops the bad calls."* | Policy packs for shell, files, SQL, HTTP, cloud CLIs, email, payments and MCP, plus human approval bound to exact arguments | [Add it in three lines](#add-it-in-three-lines) |
| **A startup selling agents to enterprises** | *"Every security review asks: how do we know what your agent did in our environment? Screenshots of our dashboard don't cut it."* | A verifiable file per run you can hand your customer. They check it themselves, without trusting you | [Pilot it with us](#pilot-it-with-us) |
| **A platform or security team** approving agent rollouts | *"Teams want agents everywhere. I need one control point, separation of duties, and evidence I'd defend in an incident review."* | A central signer the agents can't reach, one policy for every framework, signed incidents and quarantine | [Deployment](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy) · [threat model](https://github.com/Cygnux-Labs/Tracekit/wiki/Threat-Model-Server) |
| **An auditor, GRC lead, insurer or lawyer** | *"I'm asked to sign off on AI. I need records I can check myself, not a vendor's word."* | Offline verification in a browser page that sends nothing, and mappings to the EU AI Act, ISO/IEC 42001, NIST AI RMF and OWASP | [Tracekit for auditors](https://github.com/Cygnux-Labs/Tracekit/wiki/For-Auditors) · [compliance](https://github.com/Cygnux-Labs/Tracekit/wiki/Compliance) |

**The short version:** if your agent only reads, or runs in a throwaway sandbox, a tracer is enough. Once it acts on
real systems, and someone outside your team has to trust the record, you want Tracekit.

## Add it in three lines

```sh
pip install tracekit-ai
```

```python
import tracekit; tracekit.instrument()   # first line of your agent, then run it as usual
```

```sh
tracekit last    # VERIFIED: N tool calls in M signed records, none changed ...
```

`instrument()` starts a dev signer (or reuses the running one), finds the frameworks you use, then gates and records
every tool and model call. `tracekit view --dev` opens a viewer with every run, every blocked and held call, approvals
and replay. On a clean machine the LangGraph example (a mock model, no API key) installs, runs and verifies in 27
seconds: [`examples/v2/clean-machine.sh langchain`](https://github.com/Cygnux-Labs/Tracekit/blob/main/examples/v2/clean-machine.sh).

**Coding agents:** `tracekit init --dev --v2` wires Claude Code's hooks. Add `--agent` with `codex`, `cursor`,
`gemini`, `opencode`, `kilo`, `goose`, `qwen`, `droid`, `antigravity`, `crush` or `devin` for the others.
**TypeScript:** `npm install @cygnuxlabs/tracekit`.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png">
  <img alt="Works with Claude Code, Codex CLI, Cursor and Gemini CLI; the Python and TypeScript SDKs; the OpenAI Agents SDK, Claude Agent SDK, LangChain, LangGraph, MCP, CrewAI, Browser Use, Pydantic AI, the Vercel AI SDK and OpenTelemetry" src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/works-with-light.png" width="100%">
</picture>

<details>
<summary><strong>All 34 integrations</strong>, and which are stable</summary>

<br>

**Stable:** Claude Code, OpenAI Agents SDK, LangChain / LangGraph, Claude Agent SDK, MCP.

**Experimental:** coding agents Codex CLI, Cursor, Gemini CLI, OpenCode, Kilo Code, goose, Qwen Code, Factory Droid,
Antigravity CLI, Crush and Devin; frameworks CrewAI, Browser Use, Pydantic AI, Google ADK, Haystack, LlamaIndex,
Microsoft Agent Framework, Strands Agents, Hermes Agent and the Vercel AI SDK; sandboxes and gateways NVIDIA OpenShell,
E2B, microsandbox, agentgateway, Wassette, LiteLLM's MCP gateway and Docker's MCP Gateway; and the TypeScript SDK.

Setup guides: [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents) ·
[OpenAI Agents SDK](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-OpenAI-Agents) ·
[Claude Agent SDK](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-Claude-Agent-SDK) ·
[LangChain / LangGraph](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-LangChain) ·
[MCP](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-MCP) ·
[OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/wiki/OpenTelemetry) ·
[any other agent](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstarts-Custom) ·
[full list](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations)

Sandboxes: Tracekit holds Claude Code's unsandboxed retries and Gemini CLI's sandbox expansions for a person, decides
each request that sandbox-runtime's proxy or NVIDIA OpenShell lets out, and signs each decision agentsh logs, in a run
of its own.

</details>

<details>
<summary><strong>More ways in</strong>: requirements, the why demo, the sample bundles</summary>

<br>

Python 3.9 to 3.13; the framework integrations need 3.10 or newer. TypeScript needs Node 18 or newer, and
`npx @cygnuxlabs/tracekit up` starts a dev signer without Python on Apple Silicon Macs, Linux and Windows. `--why`
(experimental) shows a held email whose cause is found by replay and cited by its signed record. From a checkout, the
shipped sample bundles check with the verifier alone:

```sh
tracekit demo --server                # exit 0
tracekit demo --why                   # exit 0
tracekit init --dev --v2
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

</details>

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png">
  <img alt="1. Your agent asks the signer to decide each call; it holds a run token, never a key. 2. The signer allows, denies or asks a person, and signs every call, decision and result into one hash chain per run. 3. Witnesses cosign each checkpoint. 4. Each run exports as run.tkb, which tracekit verify checks offline." src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/readme/how-it-works-light.png" width="100%">
</picture>

1. **Your agent asks before it acts.** Through an SDK, a hook or a gateway, each tool call goes to the signer first.
2. **The signer decides and signs.** It runs out of the agent's reach, applies your policy, and signs the call, the
   decision and the result. Each record carries the hash of the one before it, so changing one byte breaks the chain at that
   record.
3. **Witnesses cosign** (experimental). An independent copy of the log's head catches what a log can't catch alone:
   a cut-off ending, or a rewrite by whoever holds the key.
4. **Anyone verifies.** One `.tkb` file, checked offline against keys you pinned.

The agent never holds a key or assigns sequence numbers, and nothing it says about itself is trusted. **Where the
signer runs decides what a run is worth,** and your agent's code is the same in every mode (`TRACEKIT_SIGNER` points it
at the signer):

| Where the signer runs | Good for | Who could still rewrite the log |
|---|---|---|
| Your laptop, as you (dev mode) | Trying it, seeing what your agent does | The agent itself, if it tried. Dev runs say so: `isolation: same-user` |
| Your laptop, as a separate OS user (Linux; macOS experimental) | Coding agents you want held to account | Root and the signer's user |
| Container or Kubernetes sidecar | Agents in production | The signer's uid and the node admin |
| Docker Compose stack | A team's shared setup on one host | The Docker host's admins |
| Central signer over HTTPS | Many teams, one control point | The signer host's admins, which a witness makes visible |

Built like **Certificate Transparency**, on existing standards: Ed25519 over RFC 8785 canonical JSON, RFC 6962 Merkle
trees, C2SP signed notes and cosignatures. The [evidence format](https://github.com/Cygnux-Labs/Tracekit/wiki/Format-v2)
is open and specified with test vectors, with verifiers in Python, TypeScript and an independent one in Go. A `.tkb`
holds no verification code. Old files keep verifying: formats only grow, and an older verifier reports a newer file
`UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`.

## Tracekit next to the tools you already use

| You want to | Use | Tracekit's part |
|---|---|---|
| Debug prompts, see traces, run evals | A tracer: OpenTelemetry, Langfuse, LangSmith, Phoenix | Keep it. Tracekit reads and writes OpenTelemetry spans |
| Filter prompt and answer text | A guardrail library: NeMo Guardrails, LlamaFirewall | Keep it. Tracekit decides tool calls, not text |
| Isolate what code can touch | A sandbox: containers, gVisor, Firecracker | Keep it. Tracekit records and decides inside it |
| **Stop a risky action before it runs, and prove it** | **Tracekit** | **This is what it's for** |

Your tracer is the dashboard. Tracekit is the black box.
[Full comparison, and when Tracekit is the wrong choice](https://github.com/Cygnux-Labs/Tracekit/blob/main/COMPARISONS.md).

## Proof, misses included

Our own experiments: small, synthetic and written by us. Nothing rounded up, and the misses stay in.

| What we tested | Result |
|---|---|
| **Tamper detection** (E1): edit, delete, swap, insert, truncate, re-sign; 60 trials each | The log alone catches 6 of 8. **With a witness, 8 of 8.** |
| **Insider attacks** (E8): real unprivileged users vs. a system-mode signer | **8 of 8 caught**, on every pull request |
| **Cross-check** (E10): a skipped hook, a made-up call, changed arguments | **12 of 12 flagged**, 0 false positives |
| **Overhead** (E9): signer round trip over a Unix socket | **0.45 ms p50, 0.91 ms p99** per call |
| **Policy packs, known cases** (E17): 840 harmful, 890 benign calls | 840 stopped, 1 false alarm |
| **Policy packs, written blind to the rules** (E21): 420 harmful, 432 benign | 211 of 420 stopped or held on the one blind run (255 now, with rules added after reading the pool); 18 benign held |

That last row is on purpose. **Policy rules are tripwires, not a wall.** They match text, and a determined agent can
reword a command. What makes the record trustworthy is the signer's isolation and the witness, and those are what the
first two rows measure.
[Every experiment](https://github.com/Cygnux-Labs/Tracekit/wiki/Evaluation) ·
[technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md) ·
[paper](https://arxiv.org/abs/2609.35659).

### What a verified run does *not* prove

- **Dev mode protects nothing against an agent that runs as you.** Move the signer to another user or host for that.
- **Verified means the record is intact**, not that the agent's intent was good or that a tool's reported result is
  true. `tracekit analyze --v2` findings are an opinion beside the record, never part of it.
- **Actions that skip the capture path leave no record**, such as a subprocess a hook never sees, or code that
  bypasses the adapter.
- **Commitments hide content, not timing, sizes or counts.**
- **Witnesses are experimental, and no public witness runs yet.**

Every limit, and what to do about it: [limits](https://github.com/Cygnux-Labs/Tracekit/wiki/Limits) ·
[guarantees by deployment](https://github.com/Cygnux-Labs/Tracekit/wiki/Guarantees).

## What's in the box

**Stable core:** Record · Decide (allow, deny, hold) · Approve (bound to exact arguments, used once) · Verify offline ·
Viewer.

<details>
<summary><strong>Experimental</strong>: works and is tested, may change between releases</summary>

<br>

| Feature | What it does |
|---|---|
| **Witness and monitor** | Independent cosigners and a watcher that catch a rewritten or forked log |
| **Cross-check** | Compares the calls the model asked for (via an LLM gateway or the transcript) with the calls the agent reported |
| **Contain** | Signed incidents that hold or quarantine a run; tools that run on credentials the agent never holds; an egress observer; Tetragon and Falco kernel-event import |
| **`tracekit why`** | Finds which input caused an action by replaying the run without it |
| **`tracekit analyze --v2`** | Flags edits nobody asked for, broken "don't touch X" instructions, data sent out or files deleted without telling you |
| **More approvers** | Approve from a web page with passkeys, from Slack, or by a reviewer agent within bounds: 7 of 7 abuse cases against agent approvers caught (E18) |

[What's stable](https://github.com/Cygnux-Labs/Tracekit/wiki/Support)

</details>

## Commands

```sh
tracekit audit --since 7d                   # what your coding agent did, and what Tracekit would have stopped
tracekit demo --server                      # allow, deny, hold, then a tampered copy fails verification
tracekit init --dev --v2                    # wire Claude Code's hooks; --agent for the other coding agents
tracekit last                               # export and verify your latest run
tracekit view --dev                         # every run: calls, decisions, approvals, replay
tracekit approvals list                     # calls waiting for a person; tracekit approvals approve ID
tracekit export --v2 --run ID -o run.tkb    # one run as one file
tracekit verify run.tkb --trust trust.json  # offline, against keys you pinned
                                            # (tracekit signer trust -o trust.json, or the one tracekit last wrote)
tracekit policy lint policy.yaml            # check a policy before the signer loads it
tracekit doctor                             # check your setup
```

Whoever checks a run needs nothing installed: the
[browser verifier](https://github.com/Cygnux-Labs/Tracekit/wiki/Verdicts#verify-in-your-browser) takes the `.tkb`,
sends nothing anywhere, and says VERIFIED, FAILED or UNVERIFIABLE. In CI:
`uses: Cygnux-Labs/Tracekit@v1.6.0` with `bundle:` and `trust:`.
`require-anchor` defaults to `true`, so an unanchored bundle fails the step; set `require-anchor: "false"` to only
report it.

## Pilot it with us

Running an agent on real systems, with a customer, auditor or insurer who has to sign off on it? We'll set up Tracekit
with you for **two weeks, free**: one agent, on your machines. You end with a verified evidence file for every run and
a written review of what your agent did that you didn't expect.

**[Request a pilot](https://github.com/Cygnux-Labs/Tracekit/issues/new?template=pilot_request.md)** · or email
[info@cygnuxlabs.com](mailto:info@cygnuxlabs.com)

## Contribute

Each of these helps on its own, and none needs the whole codebase:

- **Try to break it.** Make a changed record verify, a denied call run, or an approval fake, and report it privately
  ([SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md)). You'll be the first name in the
  [hall of fame](https://github.com/Cygnux-Labs/Tracekit/blob/main/HALL_OF_FAME.md).
- **Find a harmful call the packs let through.** Add it to
  [`tests/data/policy/deny/`](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/data/policy/deny) with a rule.
- **Write a verifier in Rust or another language** from the [spec](https://github.com/Cygnux-Labs/Tracekit/wiki/Format-v2)
  alone.
- **Add a framework** that passes the
  [adapter contract](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md#adding-a-framework-adapter).
- **Run it on your agent and tell us what broke.**

`make install`, then `make check`. Smaller tasks:
[good first issue](https://github.com/Cygnux-Labs/Tracekit/labels/good%20first%20issue). Everyone taking part follows
the [code of conduct](https://github.com/Cygnux-Labs/Tracekit/blob/main/CODE_OF_CONDUCT.md).

## Docs

| I want to | Start here |
|---|---|
| Wire up my agent | [Quickstart](https://github.com/Cygnux-Labs/Tracekit/wiki/Quickstart) · [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents) · [TypeScript](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md) |
| Write policy and approvals | [Policy](https://github.com/Cygnux-Labs/Tracekit/wiki/Policy) · [approvals](https://github.com/Cygnux-Labs/Tracekit/wiki/Approvals) · [webhooks](https://github.com/Cygnux-Labs/Tracekit/wiki/Webhooks) |
| Put the signer out of reach | [Deployment](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy) · [Compose](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy-Compose) · [Kubernetes](https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy-Kubernetes) |
| Check a run someone gave me | [For auditors](https://github.com/Cygnux-Labs/Tracekit/wiki/For-Auditors) · [reading a verify report](https://github.com/Cygnux-Labs/Tracekit/wiki/Verdicts) |
| Map it to regulation | [EU AI Act, ISO/IEC 42001, NIST AI RMF, OWASP](https://github.com/Cygnux-Labs/Tracekit/wiki/Compliance) |
| Understand the design | [How it works](https://github.com/Cygnux-Labs/Tracekit/wiki/How-Tracekit-Works) · [architecture](https://github.com/Cygnux-Labs/Tracekit/wiki/Architecture) · threat models: [server](https://github.com/Cygnux-Labs/Tracekit/wiki/Threat-Model-Server), [laptop](https://github.com/Cygnux-Labs/Tracekit/wiki/Threat-Model-Laptop) · [FAQ](https://github.com/Cygnux-Labs/Tracekit/wiki/FAQ) |
| Know what's stable | [Support](https://github.com/Cygnux-Labs/Tracekit/wiki/Support) · [limits](https://github.com/Cygnux-Labs/Tracekit/wiki/Limits) · [security checklist](https://github.com/Cygnux-Labs/Tracekit/wiki/Security-Checklist) · [changelog](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md) |

## License and citation

[MIT](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE), © Cygnux Labs. Version 1.6.0; 1.x is the supported
line. Report vulnerabilities privately as [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md)
describes.

<details>
<summary>Cite the paper</summary>

The paper: [Tracekit-v2-paper.pdf](paper/Tracekit-v2-paper.pdf) ([arXiv:2609.35659](https://arxiv.org/abs/2609.35659)).

```bibtex
@misc{cygnuxlabs2026tracekit,
  author        = {{Cygnux Labs}},
  title         = {Tracekit: Tamper-Evident Intent-Reasoning-Action Auditing for AI Agents},
  year          = {2026},
  eprint        = {2609.35659},
  archivePrefix = {arXiv},
  url           = {https://arxiv.org/abs/2609.35659},
  note          = {Code: \url{https://github.com/Cygnux-Labs/Tracekit}}
}
```

</details>

---

<div align="center">

**Your tracer shows what happened. Tracekit proves it.**

If Tracekit would help a team you know ship agents with less worry, a star helps them find it.

<sub>
<a href="https://cygnuxlabs.com/tracekit">Website</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Evaluation">Evaluation</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/wiki/Limits">Limits</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md">Contributing</a> ·
<a href="https://github.com/Cygnux-Labs/Tracekit/issues">Issues</a>
</sub>

</div>
