# Browser Use (signer RPC)

`tracekit.integrations.browser_use.trace_tools` gates every action a Browser Use agent runs (navigate, click, input,
extract, upload_file, custom actions). Before each action it asks the Tracekit signer for a policy decision; after the
action it records the outcome. It works with any object that implements the signer RPC
(`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "browser-use==0.13.11"
```

Tested with browser-use 0.13.11 (Python 3.11 or newer, its own requirement). Browser Use is imported only to build
the result of a refused action.

## Setup

```python
from browser_use import Agent, Tools
from tracekit.integrations.browser_use import trace_tools

run = signer.register_run({"request_id": "run-start-1", "agent": {"name": "shopper"}})
tools = trace_tools(Tools(), signer, run)          # or a Controller: anything with .registry.execute_action
agent = Agent(task="...", llm=llm, tools=tools,
              sensitive_data={"https://*.shop.example": {"pw": "..."}})
await agent.run()
```

Wrap each `Tools` once. Actions run through any other registry are not seen.

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before the action runs | `decide` | a fresh `tool_call_id`, the tool as `browser_use:<action>`, `tool_class_hint: browser`, the args below (`parsed`) |
| right before it runs | `approval_consume` | the same call and args, and the approval id when the action waited for one |
| after it runs | `complete` | `status` `ok`, or `error` for an `ActionResult` with an error; a `sha256:` commitment to the result (not the result), or the exception type and message |

The args are the action's params plus `page_url`, the URL of the page the action ran on (empty when there is none).

### `sensitive_data`

Browser Use fills `<secret>name</secret>` placeholders (and a param that is exactly a secret's name) with the real
value when the action runs. The adapter never sends a value to the signer:

- the args keep the placeholder form; a value written out in the params or the page URL is put back to its
  placeholder before anything is sent, and so is an exception message;
- each secret the action types is added as `typed_secrets: {name: ["sha256:<sha256 of the value>"]}`. A secret
  scoped to several domains lists the digest of each domain's value.

The signer publishes only its HMAC commitment to the args, under a salt it holds for that record. An auditor who holds
a value and gets the record's salt (`tracekit signer reveal --record SEQ`) recomputes the commitment and confirms what
was typed; the record itself never contains the value. An approver's copy of the args (`approval_get`) shows each
digest as `[REDACTED:typed_secret]`.

## Decisions

- **allow**: the action runs.
- **deny**: the action is skipped. The agent gets an `ActionResult` whose error is
  `Action blocked by policy: <rule ids>`, and the run goes on.
- **ask**: the adapter opens an approval in the signer and holds the action while it waits, up to `approval_wait_s`
  seconds (default 300), for a person to decide. Approved, the action runs; rejected, expired or undecided at the
  deadline, it is refused as for a deny. `trace_tools(tools, signer, run, approval_wait_s=0)` refuses an `ask` without
  opening an approval.

A signer that cannot be reached: the action runs unrecorded if register_run's `fail_modes` say `open` for the
`browser` class (or by default), else it is refused. Any other signer failure refuses the action. A failure to record
an outcome warns and changes nothing the agent sees.

## The browser policy pack

`tracekit/policy2/packs/browser.yaml` maps `browser_use:*` to the `browser` class and holds unmapped tools for a
person (`unknown_tools: ask`):

| Rule | Decision | Matches |
|---|---|---|
| TK-B001 | deny | navigating to a `file:` URL (also behind `view-source:` or `blob:`, or with controls in the scheme) |
| TK-B002 | deny | navigating to a loopback, private, link-local (cloud metadata) or other non-global address, in any notation |
| TK-B003 | deny | navigating to localhost, a name without a dot, or `.internal`/`.local`/`.svc` hosts |
| TK-B010 | ask | `upload_file` |
| TK-B011 | ask | `input` on a page outside the allowlist (`example.com` as shipped), or with no page |

To allow a host or set your allowlist, extend the pack and redefine the rule by id:

```yaml
extends: browser.yaml   # a copy of the pack next to this file
ask:
  - id: TK-B011
    tool: '^browser_use:input$'
    field: page_url
    pattern: '^'
    unless: '^https://([A-Za-z0-9.-]*\.)?(shop\.example|intranet\.example)\.?(:[0-9]+)?([/?#]|$)'
```

The rules are tripwires on the URL text: a host that resolves to an internal address under a public name is not
caught.

## Example

`examples/browser_use_agent.py` runs offline: a stand-in registry and `FakeSigner` deciding with the browser pack.

## Not covered

- Browser Use actions carry no call id, so every action is a call of its own (attempt 0); a retry is a new decision.
- There is no saved state: an action waiting for an approval does not survive the process.
- What the page itself does (scripts, redirects after a click) is not an action and is not seen.
