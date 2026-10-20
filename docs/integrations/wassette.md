# Wassette

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested in CI: Wassette's tools and arguments as its source names them, served to the real MCP gateway and decided by a
> real signer under this page's policy. Checked once by hand against the Wassette 0.8.0 binary (the run below), not in
> CI ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

[Wassette](https://github.com/microsoft/wassette) is an MCP server from Microsoft that runs each tool as a WebAssembly
component in Wasmtime. A component can use only the files, hosts and environment variables its permissions allow.
Wassette's built-in tools load components and grant those permissions while it runs. Put Wassette behind the
[MCP gateway](../mcp-gateway.md) and every call the agent makes to it, built-in or component, is decided, recorded and
completed by the signer, and a policy can hold each load and grant for a person.

| | Wassette | Tracekit |
|---|---|---|
| What it does | Runs each tool in a Wasm sandbox limited to that component's permissions | Decides each call before it reaches Wassette, holds loads and grants for a person, and signs a record of every call, approval and result |
| Where | An MCP server: stdio (`wassette run`) or Streamable HTTP (`wassette serve`) | The MCP gateway in front of it, and a signer outside the agent |
| What a third party can check later | Its logs | A signed, hash-chained bundle, verified offline |

## Connecting Wassette to the gateway

Wassette (0.8.0) serves MCP two ways, and the gateway reaches both:

| Wassette | Gateway upstream |
|---|---|
| `wassette run`: stdio | `command: [wassette, run]`: the gateway starts it, as its own user |
| `wassette serve --streamable-http`: Streamable HTTP at `http://127.0.0.1:9001/mcp` (`--bind-address` changes it) | `url: http://127.0.0.1:9001/mcp` |

The gateway sends plain `http` only to `localhost`, `127.0.0.1` or `::1`, so run `wassette serve` on the gateway's host
(or in its pod), on its default loopback address. Agents connect to the gateway, never to Wassette: an agent that can
reach Wassette itself calls around the gateway.

Choose how to run Wassette by whether the agent may change its tools.

### A fixed tool set (recommended)

List the components and their permissions in a Wassette provisioning manifest, and turn the built-in tools off:

```yaml
# wassette-manifest.yaml
version: 1
components:
  - uri: file:///opt/wassette/fetch_rs.wasm   # a component you reviewed; oci:// and https:// also work
    name: fetch
    permissions:
      network:
        allow:
          - host: api.github.com
```

```bash
wassette serve --streamable-http --manifest wassette-manifest.yaml --disable-builtin-tools
```

```yaml
# mcp-gateway.yaml (the rest as in the MCP gateway's docs)
upstreams:
  - name: wassette
    url: http://127.0.0.1:9001/mcp
```

- `--manifest` loads the listed components with their permissions when Wassette starts. Wassette exits if one fails to
  load (`--continue-on-provisioning-failure` serves the rest). Only `wassette serve` takes it.
- `--disable-builtin-tools` drops the built-in tools from the tool list and refuses a call to one with
  `Built-in tools are disabled`. Both `run` and `serve` take it.

The agent then sees only the components' tools, and their permissions change only when you edit the manifest and
restart Wassette. Tracekit decides and records every call to them.

### Built-in tools on: hold each load and grant

When the agent loads components and asks for permissions as it works (Wassette's default), keep the built-in tools
and have the policy hold the ones that widen what a component may do. They are, as Wassette names them:

| Built-in tool | Arguments | Effect |
|---|---|---|
| `load-component` | `path`: a `file://`, `oci://` or `https://` URI | adds a component and its tools |
| `grant-storage-permission` | `component_id`, `details: {uri: "fs://…", access: ["read"] or ["read", "write"]}` | lets it read or write a path |
| `grant-network-permission` | `component_id`, `details: {host}` | lets it reach a host |
| `grant-environment-variable-permission` | `component_id`, `details: {key}` | lets it read an environment variable |
| `unload-component`, `revoke-storage-permission`, `revoke-network-permission`, `revoke-environment-variable-permission`, `reset-permission` | | removes a component or a permission |
| `list-components`, `get-policy`, `search-components` | | reads |

The upstream is `command: [wassette, run]`, or `url:` as above with `wassette serve --streamable-http`. Add one rule
to the signer's policy (here `/etc/tracekit/policy.yaml`, which reaches the server pack as `packs/server.yaml`,
[policy](../policy-v2.md)):

```yaml
version: 'wassette-1'
description: the server pack, with Wassette's component loads and permission grants held for a person
extends: packs/server.yaml
ask:
  - id: WASSETTE-GRANT
    tool: '(mcp:[^/]+/|mcp__.+__)?(load-component|grant-[a-z-]+-permission)'
    pattern: '^'
    approval: {executor: t2}
    reason: loading a Wassette component or granting it a permission
```

- `tool` matches the name the gateway decides (`mcp:wassette/grant-network-permission`), whatever you call the
  upstream, and the names other MCP clients give the same tool (`mcp__wassette__grant-network-permission` in Claude
  Code).
- `executor: t2`: the gateway runs the signer's copy of the approved arguments ([approvals](../approvals.md#tiers-t1-and-t2-executors)).
- The other tools run and are recorded; the server pack flags every MCP call (`TK-F006`).

Each load and grant then waits for a person, answered from outside the agent:

```text
tracekit approvals show apr-…        # the component and the path, host or variable, in full
tracekit approvals approve apr-…     # or: tracekit approvals reject apr-…
```

The approval is bound to that call's exact arguments and used once. A rejected or unanswered one (`approval_wait_s`)
is an `isError` result for the agent, and Wassette never sees the call. A run against Wassette 0.8.0 with this policy:

```text
wassette__load-component {"path": "file:///…/fetch_rs.wasm"}
  held, approved -> {"status":"component loaded successfully","id":"fetch_rs","tools":["fetch"]}
wassette__grant-network-permission {"component_id": "fetch_rs", "details": {"host": "example.com"}}
  held, rejected -> Tool call blocked by policy: WASSETTE-GRANT, TK-F006: approval rejected
wassette__fetch {"url": "https://example.com/"}
  allowed (flagged TK-F006) -> {"err":"ErrorCode::HttpRequestDenied"}
```

## What Tracekit records and doesn't see

- **Records:** every call to Wassette as `mcp:<upstream>/<tool>`, with its decision, any approval and its result
  (source `gateway`, tier T2), and each tool listing as untrusted input, as for any
  [MCP gateway](../mcp-gateway.md#what-is-recorded) upstream. A bundle shows each load and grant, the rule that held
  it (`WASSETTE-GRANT`) and who approved it; its arguments (the component, the path, host or variable) are committed
  to, not stored in the bundle ([format v2](../format-v2.md#2-hashes-over-agent-content)).
- **Records as `ok`:** a component's own failure that Wassette returns as a normal result. A request to a host the
  component may not reach comes back as `{"err":"ErrorCode::HttpRequestDenied"}` with `isError` false.
- **Doesn't see:** what a component does inside Wassette (the files it reads, the requests it makes), or permissions
  set another way: the manifest, the `wassette permission` command, the component's policy file, or an MCP client
  connected to Wassette directly. The manifest isn't signed into the run.
- **A grant outlives its call.** Wassette saves it with the component, so it applies to every later call of that
  component, from every agent and run behind the gateway, after restarts too, until it is revoked.
- **New tools appear on the next listing.** After a load, Wassette sends `notifications/tools/list_changed`, which the
  gateway doesn't relay ([MCP gateway limits](../mcp-gateway.md#limits)); the agent sees the new tools the next time
  its client lists them.

[Limits](../limits.md#custody-12) lists these with what to do.
