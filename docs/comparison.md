# Tracekit and agent observability platforms

Agent observability tools such as Laminar (open source, Y Combinator S24) answer "why did my agent fail, and how do I fix
it?". Tracekit answers a different question: "what did the agent actually do, and can anyone check that the record has
not been changed?". This page compares the two honestly, using Laminar as described in its README and site in October
2026. The two work together: Tracekit can send its signed runs to Laminar, Langfuse or Jaeger over OTLP (`tracekit otel push`).

## Where Tracekit goes further

| | Tracekit | Typical observability platform |
|---|---|---|
| Who can change the record | Nobody without detection: Ed25519-signed, hash-chained, checkpointed to an external witness; in Linux system mode the signer is a separate OS user | The operator's database |
| Checking a run | Offline, by anyone: `tracekit verify run.tkb` (or the bundled GitHub Action) | Trust the platform |
| Stopping a bad action | Policy gate before execution (deny, hold for human approval); `fail_mode: closed` refuses calls that cannot be recorded, including model calls | Observe after the fact |
| Detecting disabled capture | Proxy vs hook cross-checks, counter gaps, transcript tamper detection, stale runs | Missing data looks like no data |
| Findings | Deterministic detectors whose findings are signed and must cite unaltered evidence; `verify` fails otherwise | Model-generated alerts, not bound to evidence |
| Say vs do | Claims checked against executed commands (tests, commits, pushes, deletes), requests checked against executions | - |
| OpenTelemetry | In (GenAI, OpenLLMetry, OpenInference; protobuf or JSON) and out; every exported span carries the hash of the signed record it came from | In |
| Privacy | Hashed by default, secrets redacted before writing, everything stays on your machine | Hosted by default (self-hosting available) |
| Dependencies | One (`cryptography`); receiver, SQL index and MCP server are stdlib-only | Rust services, ClickHouse, Postgres |

## Where Laminar is ahead

- **Product surface**: a hosted service with a polished UI, SQL dashboards, data labeling and dataset management.
- **AI analysis**: model-driven failure detection ("signals") and clustering across runs. Tracekit's detectors are regexes
  and structural checks: precise, but they miss paraphrases (see E6 in [evaluation](evaluation.md)).
- **Evals**: an evaluation SDK and CLI for CI. Tracekit has no eval runner.
- **Breadth**: a TypeScript SDK, more framework integrations and browser session recordings. Tracekit's auto-instrumentation
  is Python only (OpenAI, Anthropic, Google Gen AI); other languages come in over OpenTelemetry.
- **Scale and operations**: ClickHouse-backed storage built for many teams. Tracekit's SQL index is SQLite on one machine
  (300,000 records: per-run queries under 10 ms, full scans under 1 s).
- **Cost and token accounting**: not yet in Tracekit, because the v1 event schema has no token fields (#9).
- **Adoption**: thousands of GitHub stars and production customers. Tracekit is a v0.2 release candidate.

## Choosing

Use an observability platform to debug and improve agents. Use Tracekit when the record has to stand up to someone who
does not trust you: an auditor, a regulator, a customer or a security reviewer. Or when an agent can do something you
need to stop, not just see. Use both by pushing Tracekit's signed runs into your observability tool.
