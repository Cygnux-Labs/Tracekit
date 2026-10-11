# Limits

What Tracekit doesn't do, or does with a catch you might not expect. Each row says why and what to do. When you hit
one of these at run time, the message you see names it and says what to do.

## Install

| Limit | Why it is so | What to do | Details link |
|---|---|---|---|
| `pip install tracekit-ai` also installs `cryptography`, `rfc8785`, `google-re2` (Python 3.10+) and `regex`. | The dev signer starts from that one install. It signs, canonicalises JSON and runs its policy engine. | To get the verifier alone, `pip install --no-deps tracekit-ai`. It runs on the standard library. | [quickstart](quickstart-v2.md#1-install) |
| A `--no-deps` install verifies bundles but can't run a signer. `tracekit up` and `tracekit init --dev --v2` refuse to start. | The signer needs the policy engine and `cryptography`. Neither is in the standard library. | `pip install tracekit-ai` | [doctor](doctor.md) |
| Where `google-re2` has no wheel (a new Python, an uncommon platform), pip builds it from source, and without a C++ toolchain and abseil the whole install fails. | pip has no fallback between dependencies. The signer itself uses `regex` when `google-re2` isn't importable. | `pip install --no-deps tracekit-ai cryptography "rfc8785>=0.1,<0.2" regex` | [quickstart](quickstart-v2.md#1-install) |
| A `--no-deps` verifier is slower. | It falls back to pure-Python Ed25519 and JCS. Both are checked against `cryptography` and `rfc8785` and give the same verdict. | Install `cryptography` and `rfc8785` if you verify many large bundles. | [signing](signing.md) |

## `tracekit.instrument()`

| Limit | Why it is so | What to do | Details link |
|---|---|---|---|
| It only gates agents, tools, graphs, options and sessions built after it runs. | It wires each framework where its objects are built: `Agent`, `ToolNode`, `ClaudeAgentOptions`, `ClientSession.call_tool`. | Make `import tracekit; tracekit.instrument()` the first line of your agent. | [quickstart](quickstart-v2.md#2-one-line-in-your-agent) |
| It raises `SignerUnavailable` when no signer answers. | A run's fail mode is closed until a signer says otherwise. Without a run, no call could be recorded. | Follow the message. With no `TRACEKIT_SIGNER` set, it starts a dev signer itself. With it set, start that signer or unset it. In system mode, run `sudo tracekit doctor`. | [quickstart](quickstart-v2.md#first-run-errors) |
| A process has one run, and the run closes when the process exits. A killed process leaves its run open until the signer's idle timeout. | The run belongs to the process, not to any one agent loop or session. | `tracekit last` names a run that is still open and skips it. For one run per task, wire the adapter by hand. | [quickstarts](quickstarts/custom.md) |
| An `ask` (a call waiting for a person) only completes where the framework can wait. OpenAI Agents interrupts the run, and your code must apply the decision. LangGraph pauses only with a checkpointer and denies the call without one. MCP waits up to 300 s in `call_tool`. The Claude Agent SDK waits up to 9 minutes in its hook. | Waiting for a person is part of each framework's own control flow. | For approvals, wire the adapter by hand as its quickstart shows. | [OpenAI Agents](quickstarts/openai-agents.md), [LangGraph](quickstarts/langchain.md) |
| A framework version outside the tested range gets a warning. If its adapter can't be wired at all, it is skipped. | Each adapter hooks the framework's internals at one tested minor version. | Install the versions the warning names, or wire the adapter by hand. | [adapters](adapters.md) |
| Don't wire an adapter by hand in a process that also calls `instrument()`. | The signer would decide the same call twice. | Use one or the other. | [quickstart](quickstart-v2.md#2-one-line-in-your-agent) |
| OpenAI Agents SDK hosted tools, computer use and handoffs are not gated. A Runner call with a context that isn't a dict can't wait for an approval. | They run outside the tool hooks. Approval ids are kept in the run context. | Their calls are still in the signed model responses. Pass `context={}` or a dict. | [OpenAI Agents](quickstarts/openai-agents.md) |
| Every MCP `ClientSession` in the process shares one signer stream, so their calls are recorded in one order. | A run allows 64 streams (`streams_per_run`), and a server agent may open a session per request. | For one stream per session, wrap each session with `TracekitSession` by hand. | [MCP](quickstarts/mcp.md) |
| `tracekit.instrument(tracer)` (the v1 model-call tracer) is now `tracekit.autotrace.instrument(tracer)`. `tracekit.instrument()` takes the run's name and raises `TypeError` with that fix for anything else. | `tracekit.instrument()` is the one-line v2 entry point. | Call `tracekit.autotrace.instrument(tracer)`, and `tracekit.uninstrument()` to undo it. | [autotrace](quickstarts/custom.md) |
| Model calls are recorded only when made through the OpenAI, Anthropic or Google Gen AI Python SDKs. | Those are the clients autotrace wraps. | Record other calls with the client (`run.call("model_event", ...)`). | [custom](quickstarts/custom.md) |
| In TypeScript, `instrument()` returns the adapters for you to pass to the framework. It doesn't wire them. | ES modules can't be patched from outside. | `const tk = await instrument()`, then `tk.ai` (Vercel AI SDK) or `tk.agents` (OpenAI Agents JS). |
| In TypeScript, the run closes on `beforeExit`, which Node skips on `process.exit()`. That run stays open until the idle timeout, and `tracekit last` skips it. | Node runs no async work after `process.exit()`. | `await tk.run.close()` before `process.exit()`. | [TypeScript SDK](../sdk/typescript/README.md) | [TypeScript SDK](../sdk/typescript/README.md) |

## `tracekit last`

| Limit | Why it is so | What to do | Details link |
|---|---|---|---|
| It pins the dev signer's key from the signer's own data dir, so the verdict is `dev` assurance. | The dev signer runs as your user. Anything that runs as you could also have rewritten that key and the log. | For evidence against the agent, use system mode and witnesses, and pin keys you got another way. | [what dev assurance means](quickstart-v2.md#what-dev-assurance-means) |
| It shows finished runs only. A newer run that is still open is named and skipped. A run that just closed is waited for, up to 15 s. | The signer finalises a run a few seconds after the run closes. A bundle exported before that verifies only to its head. | End the agent, then run `tracekit last` again. `tracekit export --v2 --run ID` exports an open run to its head. | [quickstart](quickstart-v2.md#3-see-it-verified) |
| It writes `<run id>.tkb` and `<run id>.trust.json` in the current directory. | They sit where you can find them. | Use `-o PATH` to write somewhere else. | [quickstart](quickstart-v2.md#3-see-it-verified) |
| It reads only the same-user dev signer. | A configured signer's store and keys belong to another user or host. | `tracekit signer trust --config signer.yaml -o trust.json`, then `tracekit export --v2 --config signer.yaml --run ID`. | [deploy](deploy.md) |
