# LangSmith Tool Gateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

LangSmith's [Tool Gateway](https://docs.langchain.com/langsmith/tool-gateway) is a managed layer that sits between
agents and the MCP servers they call: it holds the credentials, knows which identity a call runs as, and applies its
deny and approval policies. Each tool kit is one MCP URL. Tracekit adds what it doesn't: a decision before the call
leaves your side, and a signed, hash-chained record that neither the agent nor LangSmith can edit and that verifies
offline.

| | LangSmith's Tool Gateway | Tracekit |
|---|---|---|
| Holds | The credentials for each MCP server, the access and identity of each caller | The signing key and the policy; for the LangSmith API key, see the two paths below |
| Decides | Its own deny and approval policies, on every call | Your Tracekit policy, before the call is sent, with approvals bound to the exact arguments |
| Records | An optional trace per call: the tool, the server and the identity. Not the data sent or returned | A signed event for the decision and for the result, committed to by the signer, verified offline |

Both policies apply: Tracekit decides first, and a call it allows can still be denied by LangSmith (that call completes
as an error in the record).

```text
path 1:  agent --> tracekit mcp-gateway --Streamable HTTP, X-Api-Key--> LangSmith Tool Gateway --> your MCP servers
                         |
                         +-- decide, approve, complete --> signer

path 2:  LangChain agent (TracekitMiddleware) --X-Api-Key--> LangSmith Tool Gateway --> your MCP servers
                         |
                         +-- decide, complete --> signer
```

## Path 1: Tracekit's MCP gateway in front (agent never holds the key)

Run Tracekit's [MCP gateway](../mcp-gateway.md) (a v2 signer that lists it under `gateways`, its `http` and `signer`
sections, agents that send their run in `X-Tracekit-Run`), and add the kit as one upstream:

```yaml
upstreams:
  - name: langsmith                        # tools listed as langsmith__<tool>, decided as mcp:langsmith/<tool>
    url: https://api.smith.langchain.com/v1/managed-tools/kits/<kit-id>/mcp
    headers: {X-Api-Key: secrets/langsmith.key}    # the file holds the LangSmith API key, one line
    settings: {X-Tenant-Id: <workspace-id>}        # only for an organization-scoped key: not a secret
```

```bash
tracekit mcp-gateway serve --config mcp-gateway.yaml
```

Point the agent at the gateway's `/mcp`, not at LangSmith. The API key stays in the gateway's secret file: the agent's
own headers are never forwarded, and the key is cut from everything the gateway answers or records.

- **A rule names the kit and the tool:** `mcp:langsmith/<tool>`. Name the upstream after the kit if you use several.
- **Custody holds only while the agent can't reach LangSmith itself.** An agent that holds a LangSmith key can call the
  kit around Tracekit. Give the key only to the gateway, and fence the agent's egress to `api.smith.langchain.com`
  ([Kubernetes](../deploy-kubernetes.md#custody)).
- **Whose credentials a call uses** is LangSmith's choice and depends on the key type (a personal access token acts as
  you; a service or agent key acts as the user, agent or profile LangSmith is told). Tracekit's record names the agent
  that called, and the upstream sees one caller, Tracekit's gateway.

## Path 2: a LangChain agent loads the kit's tools

If the agent is a LangChain `create_agent` agent that loads the kit with `langchain-mcp-adapters`, wrap it with
[`TracekitMiddleware`](langchain.md) and the call is decided and signed in the agent's process:

```python
import asyncio
import os

from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient
from tracekit.integrations.langchain import TracekitMiddleware
from tracekit.sdk.client import Client

async def main():
    kit = MultiServerMCPClient({"langsmith": {
        "transport": "streamable_http",
        "url": "https://api.smith.langchain.com/v1/managed-tools/kits/<kit-id>/mcp",
        "headers": {"X-Api-Key": os.environ["LANGSMITH_API_KEY"], "X-Tenant-Id": os.environ["LANGSMITH_WORKSPACE_ID"]},
    }})
    tools = await kit.get_tools()
    with Client().run(agent="support-agent") as run:   # the client and run, as in the LangChain page
        agent = create_agent("anthropic:claude-sonnet-5-5", tools,
                             middleware=[TracekitMiddleware(run.client, run.run_id, run.run_token)])
        out = await agent.ainvoke({"messages": [("user", "file a ticket for the printer")]})
        print(out["messages"][-1].content)

asyncio.run(main())
```

(`X-Tenant-Id` is only for an organization-scoped key.) Here the agent's process holds the API key (the middleware is
inside the agent), so this path gives the decision and the signed record but not custody of the key. With the dev
signer that `Client()` starts, the agent can also reach the signing key, so `tracekit verify` says the record is not
proof against the agent; point `Client` at a signer the agent can't reach ([deploy](../deploy-kubernetes.md)). The
tool is decided under the name LangChain gives it (`create_ticket`), not `mcp:langsmith/create_ticket`, so a rule for
it names the tool that way (`^create_ticket$`). Use path 1 when the agent mustn't hold the key.

`langchain-mcp-adapters` needs `mcp` 1.x (0.3.2 installs 1.30.0; 0.3.1 fails to import against `mcp` 2.3). The MCP
gateway of path 1 needs `mcp>=2.3,<2.4`. They don't share an environment: install the adapters where the agent runs
and the gateway where it runs.

## What each party does

- **LangSmith:** stores the MCP servers' credentials, authenticates the caller, applies its deny and approval
  policies, and may trace each call.
- **Tracekit:** decides each call before it is sent, holds risky ones for a person, signs the decision and the result.
  Path 1 also keeps the LangSmith key away from the agent and the signer.
- **The record:** a signed bundle (`tracekit export`, `tracekit verify`) that a reviewer checks without LangSmith or
  Tracekit running.

## Tested and not tested

Confirmed from LangSmith's docs (beta, Plus and Enterprise plans): the kit URL is
`<langsmith-api-url>/v1/managed-tools/kits/<kit-id>/mcp`, it speaks Streamable HTTP, and it takes the key in
`X-Api-Key` (plus `X-Tenant-Id` for an organization-scoped key).

- **Tested:** path 1 against a stand-in kit, a local Streamable HTTP MCP server that requires `X-Api-Key` and
  `X-Tenant-Id` and records what it receives (`tests/test_langsmith_tool_gateway.py`): an allowed call reaches it with
  the headers and is signed and completed (tier T2), a denied call never reaches it, the key is in no record, no
  bundle and nothing the agent sees, and the exported bundle verifies.
- **Tested, by hand:** path 2 in a scratch environment (`langchain` 1.4.10, `langgraph` 1.2.24, `langchain-core` 1.8.4,
  `langchain-mcp-adapters` 0.3.2, `mcp` 1.30.0) against the same stand-in kit, with a fake chat model that asks for
  `create_ticket` and `delete_ticket`: the stand-in received `create_ticket` with the key, a deny rule on
  `delete_ticket` kept that call from it, and the record, signed through the middleware, verified. This isn't a
  test in the suite: the adapters and the `mcp` 2.3 the suite pins can't be installed together.
- **Not tested:** LangSmith's real Tool Gateway (it needs an account and key); `?mode=search`,
  `kits/me` and `servers/<id>` URLs; LangSmith's OAuth-based and `"auth": "langsmith"` setups (Managed Deep Agents),
  which don't send an `X-Api-Key` the gateway could hold; approval policies on LangSmith's side (an approval LangSmith
  asks the client for isn't something the MCP gateway relays).

The MCP gateway's own [limits](../mcp-gateway.md#limits) apply too. [Limits](../limits.md) lists these with what to do.
