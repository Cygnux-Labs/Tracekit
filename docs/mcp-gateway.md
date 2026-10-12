# MCP gateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

`tracekit mcp-gateway serve` is an MCP server your agents connect to in place of the MCP servers they use. It proxies
the upstream MCP servers you configure (stdio or Streamable HTTP), whose credentials stay in the gateway, and decides,
runs and completes every tool call itself, in the signer, for the agent's run. Its records are `source: gateway`, tier
T2: a tool call through it can't happen without the signer seeing it. The [MCP client adapter](integrations/mcp.md)
records calls the agent's own process makes (T1); the gateway records calls the agent can only ask for.

## Configure

`mcp-gateway.yaml` (relative paths are from the file):

```yaml
http:                                  # the same section, and identity plugins, as the signer's https listener
  listen: 0.0.0.0:8091
  cert: tls/mcp.pem
  key: tls/mcp.key
  authenticators: [mtls, k8s_sa, token]
signer: https://signer.internal:8443
approval_wait_s: 300                   # how long a call the policy asks about waits for a person
max_body: 1048576                      # bytes, for request bodies
upstreams:
  - name: notion                       # [A-Za-z0-9-]+
    command: [npx, -y, "@notionhq/notion-mcp-server@2.5.2"]   # stdio: the gateway runs it, as its own uid; pin it
    env: {NOTION_TOKEN: secrets/notion.token}                # variable -> the file holding its value
  - name: linear
    url: https://mcp.linear.app/mcp                              # Streamable HTTP
    headers: {authorization: secrets/linear.header}             # header -> the file holding its value (one line)
    settings: {x-team: platform}                                 # inline headers (url) or env (stdio): not secrets
trusted: []                            # upstreams whose resources are recorded trusted: only ones whose content
                                       # neither the agent nor outsiders can write
```

The gateway reaches the signer as itself (`TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_SIGNER_CERT`/`_KEY`). In
`signer.yaml`, list it under `gateways` and grant it the calls it makes for the agents:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-mcp-gateway"]
authorize: {"mtls:spiffe://acme.org/tracekit-mcp-gateway": [decide, complete, approval_request, approval_wait, approval_consume, observe]}
```

## Connecting

The agent's MCP client connects over Streamable HTTP to `https://<gateway>:8091/mcp` with its identity and its run, as
at the [LLM gateway](gateway.md#calling-it): `X-Tracekit-Run: <run_id>.<run_token>` on every request. The gateway
answers each request with one JSON response and keeps no session; it serves `initialize`, `ping`, `tools/list`,
`tools/call`, `resources/list`, `resources/read`, `prompts/list` and `prompts/get`.

| | listed as | decided as |
|---|---|---|
| tool `create_issue` of upstream `linear` | `linear__create_issue` | `mcp:linear/create_issue` (the MCP adapter's name, so one policy covers both) |
| prompt `triage` of upstream `linear` | `linear__triage` | `mcp:linear/prompt:triage`: its arguments go upstream with the gateway's credential |

## What is recorded

- **tools/call**: `policy.decision` for `mcp:<upstream>/<tool>` and its arguments, `caller` the agent (source
  `gateway`, tier T2). A deny, a rejected or unanswered approval, a refusal or the signer unreachable (fail closed,
  whatever the run's fail modes) is a tool result with `isError: true` and the reason, and the upstream never sees
  the call. On `ask` the call waits up to `approval_wait_s`; an approval with a T2 executor makes the consume return
  the signer's copy of the arguments, and that is what runs. The upstream's result completes the call (`tool.result`,
  tier T2; an `isError` result as an error), redacted and committed to by the signer.
- **prompts/get**: decided, approved, run and completed as a tool call named `mcp:<upstream>/prompt:<name>` (a refusal
  is an error response, and the upstream never sees the arguments), then recorded as an observed input as below,
  always `untrusted`: a template echoes the arguments the agent passed in.
- **resources/read** and the prompt got: the content is recorded as an observed input (`input.observed`, source
  `mcp:<upstream>/resource` or `mcp:<upstream>/prompt`, tier T2), a resource `untrusted` unless its upstream is in
  `trusted`, so the signer's [provenance](policy-v2.md) index sees it. Content that can't be recorded isn't answered.
- **tools/list**, **resources/list** and **prompts/list** pass through, renamed, each upstream's page recorded as an
  untrusted observed input (`mcp:<upstream>/tools`, `/resources`, `/prompts`): the model reads the descriptions the
  upstream wrote. A tool named `prompt:...` is neither listed nor called: it would be decided as a prompt.
- An upstream that fails during a tools/call or prompts/get answers an error saying the call may have run, and the
  call completes as an error.

The upstreams' credentials never reach the agent or the signer: the agent's own headers are never forwarded, and each
`env` and `headers` value is cut from the decoded string values of everything the gateway answers or records (never
the JSON-RPC envelope), as the [executor](executor.md#what-is-recorded) cuts its headers: values of at least 8
characters, in their escaped and encoded forms too. `settings` values aren't secrets and are never cut. Each of its
records names the gateway in `via`, and the signer takes a call's approval request, consume and completion from the
gateway, for the identity it decided the call for, alone; a run closed mid-call waits for the result, as for the
[executor](executor.md#what-is-recorded).

## Limits

- Custody covers only the tool calls routed through the gateway: an agent that can reach an upstream itself, or holds
  its credential, can call around it. Keep the credentials only in the gateway and fence the agents' egress
  ([Kubernetes](deploy-kubernetes.md#custody)).
- Only the first page of each upstream's tools, resources and prompts is listed.
- A resource is read through the upstream that listed it: list resources before reading one; a URI from a resource
  template isn't routed.
- No server-initiated messages: sampling, elicitation, subscriptions and progress notifications from an upstream don't
  reach the agent.
- `trusted` makes every resource of those upstreams trusted content, which provenance doesn't hold calls for: list
  only upstreams whose content neither the agent nor outsiders can write (not an issue tracker or a mailbox).
- A stdio upstream runs as the gateway's uid: it can read the other upstreams' secret files and the gateway's signer
  credential. Run one gateway, with its own identity and secrets, per stdio upstream you don't trust fully, and pin
  its command to an exact version.
- The gateway remembers up to 10,000 listed resource URIs, the least recently listed or read going first; a read of
  one it forgot answers `unknown resource: list resources first`.
- A credential an upstream encodes or transforms (base64, a hash) isn't recognised and cut; header values are one line
  of printable ASCII (the gateway refuses to start otherwise, naming the file).
- One session per upstream, opened when the gateway starts, is shared by every agent and run: run one gateway per
  tenant when an upstream keeps per-session state. A session that went away isn't reopened: a call answers
  `upstream error ... restart the MCP gateway`; restart it.
- A tools/call has no tool-use id from the model, so the gateway decides under one of its own: with an LLM gateway on
  the same run, each call reconciles as `reconcile.fabricated` (the gateway's decide) plus `reconcile.hook_missing`
  (the model's tool use). Read such a pair as one call through the gateway.

See [limits](limits.md#custody-12).
