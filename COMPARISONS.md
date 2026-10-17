# How Tracekit compares

Tracekit is one kind of tool among several that teams use around AI agents. Most teams need more than one. This page
says what each kind is built for, where Tracekit fits, and where it is the wrong choice. What we say about other
projects comes from their own docs; check them for the current state, and tell us in an issue if we got one wrong.

## The short version

| You want to | Use | Tracekit's part |
|---|---|---|
| Debug prompts, see traces, run evals | A tracer: OpenTelemetry, [Langfuse](https://langfuse.com), [LangSmith](https://www.langchain.com/langsmith), [Arize Phoenix](https://phoenix.arize.com) | None. Keep your tracer; Tracekit reads and writes OpenTelemetry spans (experimental, [otel](docs/otel.md)) |
| Filter prompts and model output (jailbreaks, PII, topic rules) | A guardrail library: [NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/latest/introduction.html), [LlamaFirewall](https://arxiv.org/abs/2505.03574), Guardrails AI | Partial. Tracekit decides tool calls, not prompt or answer text |
| Stop or hold a risky tool call before it runs | A policy gate in the call path | Yes: allow, deny or hold for a person, with packs for shell, files, SQL, HTTP, cloud CLIs, email, payments and MCP ([policy](docs/policy-v2.md)) |
| Contain what a call can do | A sandbox or VM (containers, gVisor, Firecracker, hosted sandboxes) | Partial. The executor and MCP gateway keep credentials away from the agent ([executor](docs/executor.md)); it is not a sandbox |
| Hand someone outside the team a record they can check | A tamper-evident log the agent can't rewrite | Yes. This is what Tracekit is for |

## Tracekit and a tracer

| | Tracer (OpenTelemetry, Langfuse, LangSmith, Phoenix) | Tracekit |
|---|---|---|
| Built for | Debugging, cost and latency, evals, dashboards | Evidence: what the agent did, whether it was allowed, and whether the record is intact |
| Who can change the record | Whoever can write to the trace store, including the app being traced | Only the signer. The agent never holds a signing key; an edit, deletion, swap or insertion fails verification at that record |
| Checking a run | In the vendor's UI or API | Offline, from one `.tkb` file, with verifiers in Python and TypeScript |
| Stops calls | No | Yes, before they run |
| Dashboards, evals, prompt management | Yes | No. Tracekit's viewer shows runs, decisions and approvals only |

They work together: send traces to your tracer for debugging and keep the Tracekit bundle as the record.

## Tracekit and a guardrail library

Guardrail libraries check what goes into and comes out of the model. NeMo Guardrails, for example, has input,
retrieval, dialog, execution and output rails; its execution rails check tool inputs and outputs. Tracekit works at the
tool call: it decides each call in a signer the agent can't control, and signs the call, the decision, the policy
snapshot that made it and any approval into the run's hash chain.

If you already use a guardrail library, keep it for content checks. Tracekit adds a signed record of each decision and
a hold-for-a-person step bound to the exact arguments that were approved.

## Tracekit and other tamper-evident agent logs

Several open-source projects hash-chain or sign agent actions. If you compare one with Tracekit, these are the
questions that decide what its record is worth:

| Question | Tracekit's answer |
|---|---|
| Does the agent's process hold the signing key? | No. The signer runs apart from the agent, and in system, container or central mode as a different user or host ([deployment](docs/deploy.md)) |
| Can cutting off the end of the log, or re-signing it with a stolen key, be caught? | Only with a witness: the log alone catches 6 of 8 attacks, and 8 of 8 with a witness (E1, [evaluation](docs/evaluation.md)) |
| Are calls checked before they run, or only logged? | Checked before they run |
| Is a lost event recorded? | Yes, as a signed gap, never silence |
| Is the format specified well enough to write another verifier? | Yes: [format v2](docs/format-v2.md), with test vectors |
| Is it built on existing standards? | Ed25519 over RFC 8785 canonical JSON, RFC 6962 Merkle trees (as in Certificate Transparency), C2SP signed notes and witness cosignatures |

## When Tracekit is the wrong choice

- Your agent only reads, or runs in a throwaway sandbox. A tracer is enough.
- You only debug a prototype. Use a tracer.
- You need a hard boundary against a hostile agent on the same machine. Dev mode protects nothing against an agent that
  runs as you; run the signer as another user or host, or use a sandbox ([limits](docs/limits.md)).
- You need a public witness today. Witnesses and the monitor are experimental, and no public witness is running yet.
- You need prompt-injection or jailbreak detection on text. Use a guardrail library; Tracekit's rules match tool names
  and arguments, and a determined agent can reword a command.

Every limit, with what to do about it: [limits](docs/limits.md).
