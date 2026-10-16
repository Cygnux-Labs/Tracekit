# Tool executor

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

`tracekit executor serve` runs the actions your agents may take on HTTP APIs (payments, email, GitHub, a database
endpoint) with credentials the agents never hold. The agent asks the executor to run an action; the executor decides
it in the signer, holds it for a person when the policy asks, runs it with its own credential and records the result.
Every record is `source: gateway`, tier T2: written by a service outside the agent, about a call the agent could not
make itself. This is custody: an action whose credential lives only in the executor can't happen without the signer
seeing it.

## Configure

`executor.yaml` (relative paths are from the file):

```yaml
http:                                  # the same section, and identity plugins, as the signer's https listener
  listen: 0.0.0.0:8090
  cert: tls/executor.pem
  key: tls/executor.key
  authenticators: [mtls, k8s_sa, token]
signer: https://signer.internal:8443
approval_wait_s: 300                   # how long an action the policy asks about waits for a person
max_body: 1048576                      # bytes, for request and response bodies
actions:
  - name: create_issue                 # the tool name the signer's policy decides on
    description: Open a GitHub issue   # what the model is told
    method: POST                       # GET, POST, PUT, PATCH or DELETE
    url_template: https://api.github.com/repos/{owner}/{repo}/issues
    headers: {authorization: secrets/github.header}   # header -> the file holding its value ("Bearer ghp_...")
    settings: {x-github-api-version: "2022-06-28"}   # headers given inline: not secrets, never cut from answers
    args:                              # JSON Schema of the arguments
      type: object
      required: [owner, repo, title]
      additionalProperties: false
      properties: {owner: {type: string}, repo: {type: string}, title: {type: string}, body: {type: string}}
```

Each `{arg}` in `url_template` is that argument; it must be a required argument, and never part of the host. In the
path it must be one plain segment: letters, digits and `.`, `_`, `~`, `-`, not all dots (anything else is refused with
400, since a slash, backslash or dot segment, even percent-encoded, can leave its segment once a proxy decodes the
path). In the query (`?memo={memo}`) it is URL-quoted whole. The arguments go as the JSON body, except for GET and
DELETE. Redirects are never followed: they would carry the credential elsewhere. Each `headers` file holds one line of
printable ASCII (the executor refuses to start otherwise, naming the file) and is a secret; a header that isn't (an API
version, an accept type) goes in `settings`, inline.

The executor reaches the signer as itself (`TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_SIGNER_CERT`/`_KEY`, as for the
Python client). In `signer.yaml`, list it under `gateways` and grant it the calls it makes for the agents:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-executor"]
authorize: {"mtls:spiffe://acme.org/tracekit-executor": [decide, complete, approval_request, approval_wait, approval_consume]}
```

Only an identity in `gateways` may name a `caller`; the signer refuses it from anyone else, and checks the agent's run
token against the agent's identity, never the executor's. It authorizes the call by the agent's `scheme:subject` alone
(an `authorize` entry for an OIDC person or group doesn't match it), and doesn't apply harness binding to it: the
executor authenticated the agent itself.

## Calling it

`GET /v1/actions` lists the actions (name, description, args schema) to any identity the authenticators accept.
`POST /v1/actions/<name>` runs one, with the agent's identity and its run, exactly as at the
[LLM gateway](gateway.md#calling-it) (`X-Tracekit-Run: <run_id>.<run_token>`), and a body
`{"args": {...}, "tool_call_id": "..."}` (the model's id for the call, optional: it lets the signer reconcile the call
against the model's tool use).

| Answer | When |
|---|---|
| 200 `{"status": <the API's status>, "result": <its JSON or text>}` | the action ran (an API error status is a result too, recorded as an error) |
| 400 | arguments off the schema, or a path `{arg}` that isn't one plain segment |
| 401 | the caller isn't one the authenticators accept, or sent no run (before the action is looked up) |
| 403 | the policy denied it, the approval was rejected or not given in `approval_wait_s`, or the signer refused the call |
| 404 | no such action |
| 502 | `upstream unreachable, the request was not sent`: the action didn't run; or `the request was sent but its response could not be read` (over `max_body`, a timeout): it may have run, so check before running it again. Either is recorded as an error |
| 503 | the signer can't be reached: nothing ran, whatever the run's fail modes |

The client helpers build framework tools from the listing, so the model sees each action as a tool:

```python
from tracekit.integrations import executor_tools as ex
actions = ex.actions("https://executor.internal:8090", run, headers={"authorization": f"Bearer {token}"})
agent = Agent(name="ops", tools=[ex.openai_agents(a) for a in actions])          # OpenAI Agents
tools = [ex.langchain(a) for a in actions]                                         # LangChain
options = ClaudeAgentOptions(mcp_servers={ex.SERVER: ex.claude_agent_sdk(actions)})  # the key the hooks skip
```

```ts
import { executorActions, openaiAgentsTool, vercelTool } from "@cygnuxlabs/tracekit/v2/executor";
const actions = await executorActions("https://executor.internal:8090", run, { headers: { authorization: `Bearer ${token}` } });
new Agent({ tools: actions.map((a) => openaiAgentsTool(tool, a)) });                       // @openai/agents
generateText({ tools: Object.fromEntries(actions.map((a) => [a.name, vercelTool(a, jsonSchema)])) });   // ai
```

`run` is the agent's `register_run` response (Python) or `RunHandle` (TypeScript). A refusal reaches the model as the
tool's error. The Tracekit adapters leave these tools alone (each is marked; the Claude Agent SDK hooks skip the tools
of the server registered under the key `tracekit-executor` in `mcp_servers`, `ex.SERVER`: the SDK names its tools by
that key, not by the server's own name), so they can sit next to gated tools of your own: the
executor decides and records them. TypeScript has no Claude Agent SDK helper (its `tool()` takes only a zod shape):
write a `tool()` per action with its zod shape whose handler returns `action.call(args)`, and keep the Tracekit hooks
off it (name its server `tracekit-executor`).

## What is recorded

For each call, in the agent's run: `policy.decision` (source `gateway`, tier T2) for the action's name and arguments;
on `ask`, `approval.request` and, once answered, the approval and its consume; then `tool.result` (source `gateway`,
tier T2) with the API's response as its result, which the signer redacts and commits to. Each of the executor's
records names it in `via` (its signer identity). An approval with a T2 executor (`approval: {executor: t2}`,
[approvals](approvals.md#tiers-t1-and-t2-executors)) makes the consume return the signer's copy of the arguments, and
that is what runs. The `headers` values are cut from the response's decoded string values and from errors, before
either is recorded or answered: each value of at least 8 characters and, of a `<scheme> <credential>` value, the
credential alone, of a Basic credential its decoded user:password and password, each also JSON-escaped (with `\/`, or
every character `\u`-escaped), percent-encoded and HTML-escaped. A shorter value, a `settings` value, and a credential
the API returns otherwise encoded (base64, a hash) aren't cut.

The call is the executor's, for the identity it decided it for (its `policy.decision` names it in `caller`): the
signer takes its approval request, consume and completion from the executor, for that identity, alone, so the agent,
though it holds the run token, can't record a result for it or ask for its approval in its own words (`forbidden`,
counted in the signer's `refusal.summary` records). For the same reason the executor refuses a `tool_call_id` the
agent already decided itself, and nobody can abandon the executor's approval: unanswered, it expires. The Tracekit
adapters leave the tools the client helpers build to the executor, so mixing them with gated tools of your own is
fine. A verifier counts a call whose decision and result came by different capture paths at the weaker tier and warns
(`tiers`).

The executor's records count against its own event rate, not the agent's, and the result of a call it decided against
none, so an agent can't spend the budget the record of its call needs. A run the agent closes while the executor is
still running a call waits for the call's result, up to the signer's `gateway_wait_s` (default 600 s) past its grace
window; if none comes, the signer writes a `held_call_unresolved` gap for the call before `run.final`, and the verifier
warns (`held calls`).

## Compose

The compose stack ([deploy compose](deploy-compose.md)) has the executor, the LLM gateway and the MCP gateway in the
`custody` profile: `docker compose --profile custody up -d`. Each reads its config and secret files from
`custody/<service>/` (`executor.yaml` with `signer: /run/tracekit-signer/signer.sock`), reaches the signer's socket as
its own uid, which the generated `signer.yaml` lists under `gateways`, and serves the agent on the agent network; only
the custody services reach the internet. Give each an `http` section with `cert` and `key` (a server certificate in
`custody/<service>/`, from a CA the agent trusts: off loopback the services serve only HTTPS),
`authenticators: [token]` and a `token_file`. The agent registers its run on the socket as its uid, so it hands the services a run token for their
`token:http` identity: `delegate_run` to `token:http`, then send `X-Tracekit-Run: <run_id>.<that token>` with the
bearer token. The services' signer identities are uids on the same socket, so run every agent container as a non-root
user with `cap_drop: [ALL]` and `no-new-privileges`, as the example `agent` service does: one that can change its uid
could connect as a custody service.

## Limits

- Custody covers only the actions routed through the executor: an agent that also holds a credential, or can reach
  the API itself, can act around it. Keep the credentials only in the executor and fence the agents' egress
  ([Kubernetes](deploy-kubernetes.md#custody)).
- The arguments are what the model asked for; the executor checks them against the schema, not against intent. Keep
  `args` narrow and let the policy ask for the actions that matter.
- An action held for a person keeps its HTTP request open up to `approval_wait_s`; an agent's HTTP client must wait at
  least that long.
- A result that can't be recorded (the signer went away after the action ran) still goes to the agent. The executor
  tries twice under one request id, then says on stderr which call and run it couldn't record and what to check; the
  run ends with a `held_call_unresolved` gap for the call.
- A call made without the model's tool-use id (the LangChain and Claude Agent SDK helpers, whose handlers don't get
  one) is decided under an id of the executor's: with an LLM gateway on the same run it reconciles as
  `reconcile.fabricated` plus `reconcile.hook_missing`. Read such a pair as one call through the executor; pass
  `tool_call_id` where the framework exposes it, as the OpenAI Agents and Vercel AI helpers do.

See [limits](limits.md#custody-12).
