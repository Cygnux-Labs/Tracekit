# Docker MCP Gateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

Docker's [MCP Gateway](https://github.com/docker/mcp-gateway) (`docker mcp gateway run`, what Docker Desktop's MCP
Toolkit runs) starts MCP servers in containers and serves their tools to one MCP client. Tracekit's
[MCP gateway](../mcp-gateway.md) decides each tool call before it runs, holds risky ones for a person and signs a record
of each call and its result. Put Tracekit's in front, with Docker's as a stdio upstream. Neither side needs code.

```text
agent --Streamable HTTP--> tracekit mcp-gateway --stdio--> docker mcp gateway run --> MCP servers in containers
                                   |
                                   +-- decide, approve, complete --> signer
```

| | Docker's MCP Gateway | Tracekit's MCP gateway |
|---|---|---|
| What it does | Runs each MCP server in a container with the secrets, mounts and network you grant it; refuses a call whose arguments or text result look like they carry a secret (`--block-secrets`, on by default) | Decides each call before Docker sees it, holds risky ones for a person with the approval bound to the exact arguments, and signs the decision and the result |
| Where | A process its MCP client starts, speaking stdio | A service between the agent and Docker's gateway, outside the agent, reaching a signer |
| What a third party can check later | Its log and OpenTelemetry spans name the tool and the server, not the arguments or the result | A signed, hash-chained bundle, verified offline |

## Setup

Run Tracekit's MCP gateway as [its page](../mcp-gateway.md) describes: a v2 signer that lists it under `gateways`, its
`http` and `signer` sections, and agents that send their run in `X-Tracekit-Run`. Then add one upstream per Docker
server, each starting Docker's gateway on stdio with that one server:

```yaml
upstreams:
  - name: duckduckgo                       # tools listed as duckduckgo__<tool>, decided as mcp:duckduckgo/<tool>
    command: [docker, mcp, gateway, run, --servers=duckduckgo]
  - name: fetch
    command: [docker, mcp, gateway, run, --servers=fetch]
```

```bash
tracekit mcp-gateway serve --config mcp-gateway.yaml
```

- **One server per upstream, named after it.** A call is decided as `mcp:<upstream>/<tool>`, so the upstream's name is
  the server name your rules see (`mcp:fetch/*`). Several servers behind one `docker mcp gateway run` are all decided
  under that one name.
- **`--servers` keeps Docker's dynamic tools off.** Without it, Docker's gateway adds tools such as `mcp-find`,
  `mcp-add`, `mcp-exec` and `code-mode` (its `dynamic-tools` feature, on by default), which add servers and run other
  tools from inside one call. Tracekit decides that one call, not the calls it makes. `docker mcp feature disable
  dynamic-tools` turns them off too.
- **Docker settings go in `settings`.** A stdio upstream gets only a few variables of the gateway's environment
  (`HOME`, `PATH`, `USER` and the like); put `DOCKER_HOST`, `DOCKER_CONTEXT` or `DOCKER_CONFIG` in the upstream's
  `settings` if the `docker` CLI needs them (on Windows also `ProgramFiles` and `ProgramData`, which Docker's own
  client configs pass).
- **Docker keeps its servers' secrets** (`docker mcp secret set`); the upstream needs no `env`.
- **The agent doesn't reach Docker.** Run the agent as a user that can't use the Docker daemon or Docker Desktop (not
  in the `docker` group, no Docker socket mounted), and run Tracekit's gateway as one that can. An agent with Docker
  access can start its own `docker mcp gateway run` and call the same servers around Tracekit.
- **Point the agent at Tracekit's gateway**, not at Docker's: `docker mcp client connect` writes an `MCP_DOCKER` entry
  into a client's config that starts Docker's gateway directly.

## What Tracekit sees and doesn't

- **Sees:** each tool call the agent sends through Tracekit's gateway, recorded as on the
  [MCP gateway's page](../mcp-gateway.md#what-is-recorded): the decision for `mcp:<upstream>/<tool>` and its
  arguments, any approval, and Docker's answer as the result (source `gateway`, tier T2). A call Docker refuses (its
  `--block-secrets`, its own policy, a container that fails) completes as an error. Each tool listing is recorded as
  untrusted input.
- **Doesn't see:** what happens inside Docker's gateway: the image a call ran in, its mounts, network and secrets;
  the calls Docker's dynamic tools make (keep them off); anything the agent does with Docker itself.
- **Doesn't tell agents apart on Docker's side:** Docker's gateway sees one client, Tracekit's gateway, not the agents
  behind it. The Tracekit record names the agent.
- **Doesn't import Docker's spans:** Docker's gateway exports an OpenTelemetry span per tool call (`mcp.tool.call`,
  with `mcp.tool.name`, `mcp.server.name` and `mcp.server.type`). Tracekit's
  [OTLP import](../otel.md#receiving-traces-tier-t3-import) doesn't read those attributes as a tool call; it counts and
  skips the spans. They carry no arguments or results.

## Why not Docker's interceptors

Docker's gateway takes `--interceptor=<before|after>:<exec|docker|http>:<command, image or URL>` for tool calls. A
`before` interceptor gets the call and may answer it instead: a non-empty answer is the result and the call doesn't run,
an empty one lets it run, and an interceptor that fails (a non-zero exit, an HTTP request that can't be made) fails the
call. An `after` interceptor gets only the result: not the tool, its arguments or which call it ends, and Docker's
gateway runs calls concurrently. An interceptor could decide and hold calls, but it couldn't tie a result to its
decision, and its request carries no run or caller identity for the signer to check: every allowed call would end as
a `decided_not_completed` gap. Tracekit's gateway in front records the decision, the approval and the result of each
call.

## Limits

- Docker's dynamic tools run other tools from inside one call, which Tracekit decides as that call. Start each Docker
  upstream with `--servers`.
- All servers behind one `docker mcp gateway run` share the upstream's name. Give each server its own upstream.
- Tracekit's gateway cuts only the secrets in its own config from what it answers and records, not the ones Docker
  gives its servers. Keep Docker's `--block-secrets` on.
- Custody holds only while the agent can't reach Docker. Run the agent without Docker access.
- Docker's OpenTelemetry spans aren't imported as tool calls. Record the calls through Tracekit's gateway.
- Tested against a stand-in for `docker mcp gateway run` (an MCP server on stdio), not Docker's gateway itself.

The MCP gateway's own [limits](../mcp-gateway.md#limits) apply too. [Limits](../limits.md) lists these with what to do.
