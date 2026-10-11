# Tool executor

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
    args:                              # JSON Schema of the arguments
      type: object
      required: [owner, repo, title]
      additionalProperties: false
      properties: {owner: {type: string}, repo: {type: string}, title: {type: string}, body: {type: string}}
```

Each `{arg}` in `url_template` is that argument, URL-quoted so it stays inside its path segment or query value (`.`
and `..` are refused); it must be a required argument, and never part of the host. The arguments go as the JSON body,
except for GET and DELETE. Redirects are never followed: they would carry the credential elsewhere.

The executor reaches the signer as itself (`TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_SIGNER_CERT`/`_KEY`, as for the
Python client). In `signer.yaml`, list it under `gateways` and grant it the calls it makes for the agents:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-executor"]
authorize: {"mtls:spiffe://acme.org/tracekit-executor": [decide, complete, approval_request, approval_wait, approval_consume]}
```

Only an identity in `gateways` may name a `caller`; the signer refuses it from anyone else, and checks the agent's run
token against the agent's identity, never the executor's.

## Calling it

`GET /v1/actions` lists the actions (name, description, args schema) to any identity the authenticators accept.
`POST /v1/actions/<name>` runs one, with the agent's identity and its run, exactly as at the
[LLM gateway](gateway.md#calling-it) (`X-Tracekit-Run: <run_id>.<run_token>`), and a body
`{"args": {...}, "tool_call_id": "..."}` (the model's id for the call, optional: it lets the signer reconcile the call
against the model's tool use).

| Answer | When |
|---|---|
| 200 `{"status": <the API's status>, "result": <its JSON or text>}` | the action ran (an API error status is a result too, recorded as an error) |
| 400 | arguments off the schema, or a `{arg}` of `.` or `..` |
| 403 | the policy denied it, the approval was rejected or not given in `approval_wait_s`, or the signer refused the call |
| 502 | the API couldn't be reached (recorded as an error) |
| 503 | the signer can't be reached: nothing ran, whatever the run's fail modes |

The client helpers build framework tools from the listing, so the model sees each action as a tool:

```python
from tracekit.integrations import executor_tools as ex
actions = ex.actions("https://executor.internal:8090", run, headers={"authorization": f"Bearer {token}"})
agent = Agent(name="ops", tools=[ex.openai_agents(a) for a in actions])          # OpenAI Agents
tools = [ex.langchain(a) for a in actions]                                         # LangChain
options = ClaudeAgentOptions(mcp_servers={"executor": ex.claude_agent_sdk(actions)})  # Claude Agent SDK
```

```ts
import { executorActions, openaiAgentsTool, vercelTool } from "@cygnux/tracekit/v2/executor";
const actions = await executorActions("https://executor.internal:8090", run, { headers: { authorization: `Bearer ${token}` } });
new Agent({ tools: actions.map((a) => openaiAgentsTool(tool, a)) });                       // @openai/agents
generateText({ tools: Object.fromEntries(actions.map((a) => [a.name, vercelTool(a, jsonSchema)])) });   // ai
```

`run` is the agent's `register_run` response (Python) or `RunHandle` (TypeScript). A refusal reaches the model as the
tool's error. Don't wrap these tools in a Tracekit adapter as well: the executor already decides and records them, and
a second decide would record the call twice. TypeScript has no Claude Agent SDK helper (its `tool()` takes only a zod
shape): write a `tool()` per action with its zod shape whose handler returns `action.call(args)`.

## What is recorded

For each call, in the agent's run: `policy.decision` (source `gateway`, tier T2) for the action's name and arguments;
on `ask`, `approval.request` and, once answered, the approval and its consume; then `tool.result` (source `gateway`,
tier T2) with the API's response as its result, which the signer redacts and commits to. An approval with a T2
executor (`approval: {executor: t2}`, [approvals](approvals.md#tiers-t1-and-t2-executors)) makes the consume return the
signer's copy of the arguments, and that is what runs. The header values are cut from the response, also from one
that echoes them back, before it is recorded or answered (each value and, of a `<scheme> <credential>` value, the
credential alone).

## Compose

The compose stack ([deploy compose](deploy-compose.md)) has the executor, the LLM gateway and the MCP gateway in the
`custody` profile: `docker compose --profile custody up -d`. Each reads its config and secret files from
`custody/<service>/` (`executor.yaml` with `signer: /run/tracekit-signer/signer.sock`), reaches the signer's socket as
its own uid, which the generated `signer.yaml` lists under `gateways`, and serves the agent on the agent network; only
the custody services reach the internet. Give each an `http` section with `cert` and `key` (a server certificate in
`custody/<service>/`, from a CA the agent trusts: off loopback the services serve only HTTPS),
`authenticators: [token]` and a `token_file`. The agent registers its run on the socket as its uid, so it hands the services a run token for their
`token:http` identity: `delegate_run` to `token:http`, then send `X-Tracekit-Run: <run_id>.<that token>` with the
bearer token.

## Limits

- Custody covers only the actions routed through the executor: an agent that also holds a credential, or can reach
  the API itself, can act around it. Keep the credentials only in the executor and fence the agents' egress
  ([Kubernetes](deploy-kubernetes.md#custody)).
- The arguments are what the model asked for; the executor checks them against the schema, not against intent. Keep
  `args` narrow and let the policy ask for the actions that matter.
- An action held for a person keeps its HTTP request open up to `approval_wait_s`; an agent's HTTP client must wait at
  least that long.
- A result that can't be recorded (the signer went away after the action ran) still goes to the agent, with a warning
  on the executor's stderr; the run's decision then has no result in the log.
- A call made without the model's tool-use id (the LangChain and Claude Agent SDK helpers, whose handlers don't get
  one) is decided under an id of the executor's: with an LLM gateway on the same run it reconciles as
  `reconcile.fabricated` plus `reconcile.hook_missing`. Read such a pair as one call through the executor; pass
  `tool_call_id` where the framework exposes it, as the OpenAI Agents and Vercel AI helpers do.

See [limits](limits.md#custody-12).
