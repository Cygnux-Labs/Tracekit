# Examples

The examples use mock models and stand-in tools, so they need no API key or network; the exceptions are
`why/anthropic_agent.py` (calls Claude) and `otel_jaeger_check.py` (reads a Jaeger you run). Run them from a checkout
after `pip install .` or `make install`.

## v2 signer (server-hosted agents)

Start here. Each agent folder has a README and a quickstart in [docs/quickstarts/](../docs/quickstarts/). `--scripted`
approves held calls from a second process; without it, you approve them from another terminal.

| Example | What it shows |
|---|---|
| [v2/custom/](v2/custom/) | A plain Python agent: decide, ask for approval, complete, export and verify |
| [v2/langchain/](v2/langchain/) | A LangGraph agent (`ToolNode` and a checkpointer) |
| [v2/openai_agents/](v2/openai_agents/) | An OpenAI Agents SDK agent |
| [v2/claude_agent_sdk/](v2/claude_agent_sdk/) | A Claude Agent SDK agent |
| [v2/mcp/](v2/mcp/) | An MCP client |
| [v2/pydantic_ai/](v2/pydantic_ai/) | A Pydantic AI agent (the `Tracekit` capability) |
| [v2/google_adk/](v2/google_adk/) | A Google ADK agent (the `Tracekit` plugin) |
| [v2/haystack/](v2/haystack/) | A Haystack agent (the `Tracekit` hook) |
| [v2/llama_index/](v2/llama_index/) | A LlamaIndex `AgentWorkflow` with a handoff (`Tracekit(run).gate(...)`) |
| [v2/agent_framework/](v2/agent_framework/) | A Microsoft Agent Framework agent (the `Tracekit` function middleware) |
| [v2/strands/](v2/strands/) | A Strands Agents agent (the `Tracekit` hook provider) |
| [v2/demos/](v2/demos/) | The scenarios behind [docs/demos/](../docs/demos/): containment, prompt injection, agent approvers, completeness, egress |

`v2/story.py` holds what these examples share; `v2/clean-machine.sh` (`.ps1` on Windows) runs one in a fresh venv.

## tracekit why

Causal investigation and replay of multi-agent runs ([docs/why.md](../docs/why.md)): `why/quickstart.py` is the
smallest program, `why/live_demo.py` and `why/remote_agent.py` feed `tracekit view --why`, and
`why/anthropic_agent.py` records a real Claude tool-use loop.

## v1 signer (laptop) and SDK

The first four write to the same-user v1 signer, so start it first: `tracekit init --dev --no-hooks`. Without it they
still run, but print `signer unavailable` and record nothing. Afterwards, `tracekit export --out run.tkb` and
`tracekit verify run.tkb`.

| Example | What it shows |
|---|---|
| `custom_agent.py` | A non-Claude agent traced with `tracekit_sdk` |
| `langgraph_agent.py` | A LangGraph agent traced node by node (`pip install langgraph`) |
| `mcp_client.py` | MCP tool calls gated at the client, with a rule that denies deletes |
| `model_calls.py` | `tracekit.init()` traces OpenAI, Anthropic and Google GenAI calls (each skipped if its SDK isn't installed) |
| `browser_use_agent.py` | Browser Use actions gated by the browser policy pack, decided by an in-process `FakeSigner` ([docs](../docs/integrations/browser-use.md)) |
| `otel_jaeger_check.py` | Checks that Jaeger's spans match a verified bundle ([docs/otel.md](../docs/otel.md)) |
| `ext_signer.py` | A reference external signer for keys in an HSM or TPM, started by `tracekitd`, not by hand ([docs/signing.md](../docs/signing.md)) |
