# Browser Use (signer RPC)

`tracekit.integrations.browser_use.trace_tools` gates every action a Browser Use agent runs (navigate, click, input,
extract, upload_file, evaluate, custom actions). Before each action it asks the Tracekit signer for a policy decision;
after the action it records the outcome. It works with any object that implements the signer RPC
(`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "browser-use==0.13.11"
```

Tested with browser-use 0.13.11 (Python 3.11 or newer, its own requirement). Browser Use is imported only to build
the result of a refused action and to read its action timeout.

## Setup

`import tracekit; tracekit.instrument()` before the agent is built wires it all: every `Tools` built afterwards (an
`Agent` builds one when you pass none) has its actions gated, all on one signer stream, and Browser Use's model calls
through the OpenAI, Anthropic and Google Gen AI SDKs are recorded (autotrace). By hand:

```python
import tracekit.autotrace
from browser_use import Agent, Tools
from tracekit.integrations.browser_use import trace_tools
from tracekit.sdk.client import Client

run = Client().run(agent="shopper")
run.observe(task, source="task", trust="trusted")         # what the task names counts as trusted
tracekit.autotrace.instrument(run)                        # Browser Use's model calls
tools = trace_tools(Tools(), run.client, run.registered)  # or a Controller: anything with .registry.execute_action
agent = Agent(task=task, llm=llm, tools=tools,
              sensitive_data={"https://*.shop.example": {"pw": "..."}})
await agent.run()
run.close()
```

`trace_tools(tools, signer, registered)` takes any signer RPC client and its `register_run` response. Wrap each
`Tools` once, and don't also call `instrument()` in the same process: the action would be decided twice. Actions run
through any other registry are not seen. Model calls can also go through the [LLM gateway](../gateway.md).

Observe the task as `trusted` from your application: the hosts, addresses and values it names then count as trusted,
and provenance holds only what a page alone brought in ([policy](../policy-v2.md#provenance-untrusted-and-from-untrusted)).

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before an action | `observe` | each browser state Browser Use made since the session's last action, oldest first: what the model read of the page (URL, title, tab URLs and the page's text, up to 100,000 characters), as `untrusted`, source `browser_use:page` |
| before the action runs | `decide` | a fresh `tool_call_id`, the tool as `browser_use:<action>`, `tool_class_hint: browser`, the args below (`parsed`) |
| right before it runs | `approval_consume` | the same call and args, and the approval id when the action waited for one |
| after it runs | `complete` | `status` `ok`, or `error` for an `ActionResult` with an error; the result (a page's content is untrusted, so the signer indexes it for provenance), or the exception type and message |

The args are the action's params plus `page_url`, the URL of the page the action ran on: empty when there is none, or
when Browser Use doesn't say within 2 s (an allowlist rule never exempts an empty `page_url`).

The page is observed so that a host the agent reached without naming it (a link it clicked in a mail) is in the run's
provenance index: typing there, or navigating there with data in the query string, is then held by TK-P003 unless your
task named that host. At a session's first action the adapter wraps its `get_browser_state_summary`, through which
each step reads the page (and some actions, `navigate` among them, too), and queues every state it returns, so a page
that closes itself before the action is still observed. The state the first step read, made before that, comes from
Browser Use's cached copy.

### `sensitive_data`

Browser Use fills `<secret>name</secret>` placeholders (and a param that is exactly a secret's name) with the real
value when the action runs. Before anything is sent to the signer:

- each value in the params, the page URL, the page's text, a result or an exception message is put back to its
  placeholder, written out or encoded: percent-encoded (`Corr3ct-H0rse-Battery%21`, either hex case, `+` for a
  space, or encoded twice), as HTML character references (`&#33;`, `&#x21;`, `&amp;`, `&ouml;`) or JSON escapes
  (`\"`, `\u00f6`), or any mix of these. The action still runs with what the agent wrote;
- each secret the action types is added as `typed_secrets: {name: ["sha256:<sha256 of the value>"]}`. A secret
  scoped to several domains lists the digest of each domain's value.

A value transformed any other way (base64, hashed, cut in parts, changed case) is not recognised and is sent as it
is ([limits](../limits.md#privacy)).

The signer publishes only its HMAC commitment to the args, under a salt it holds for that record. An auditor who holds
a value and gets the record's salt (`tracekit signer reveal --record SEQ`) recomputes the commitment and confirms what
was typed; the record itself never contains the value. An approver's copy of the args (`approval_get`) shows each
digest as `[REDACTED:typed_secret]`.

## Decisions

- **allow**: the action runs.
- **deny**: the action is skipped. The agent gets an `ActionResult` whose error is
  `Action blocked by policy: <rule ids>`, and the run goes on.
- **ask**: the adapter opens an approval in the signer and holds the action while it waits for a person, up to
  `approval_wait_s` seconds. Browser Use cancels an action at its own action timeout (`BROWSER_USE_ACTION_TIMEOUT_S`,
  180 s by default), the wait included, so the wait is by default, and at most, five sixths of it (150 s), leaving
  the rest for the action; a longer `approval_wait_s` warns and is cut to it. Approved, the action runs; rejected,
  expired or unanswered at the deadline, it is refused as for a deny, and an unanswered approval is withdrawn
  (`approval.abandoned`) so no one can answer it later. The agent then reads "no one approved the call within 150 s
  ...". An action Browser Use cancels while it waits (its step timeout) withdraws its approval too.
  `trace_tools(tools, signer, run, approval_wait_s=0)` refuses an `ask` without opening an approval.

To give a person longer, raise `BROWSER_USE_ACTION_TIMEOUT_S` (and the Agent's `step_timeout`, 180 s by default,
which covers the model call and every action of a step).

A signer that cannot be reached: the action runs unrecorded if register_run's `fail_modes` say `open` for the
`browser` class (or by default), else it is refused; the same goes for a page that can't be observed before it. Any
other signer failure refuses the action, a page observation the signer refuses included. A page that wasn't observed
is not sent again: the signer writes a gap for the event it never got, which makes the run's provenance index `partial`,
so TK-P003 holds every send for the rest of the run. A failure to record an outcome warns and changes nothing the
agent sees.

## The browser policy pack

`tracekit/policy2/packs/browser.yaml` maps `browser_use:*` to the `browser` class, holds unmapped tools for a person
(`unknown_tools: ask`) and counts a page's content as untrusted:

| Rule | Decision | Matches |
|---|---|---|
| TK-B001 | deny | navigating to a `file:` URL (also behind `view-source:` or `blob:`, or with controls in the scheme) |
| TK-B002 | deny | navigating to a loopback, private, link-local (cloud metadata) or other non-global address, in any notation |
| TK-B003 | deny | navigating to localhost, a name without a dot, or `.internal`/`.local`/`.svc` hosts |
| TK-B010 | ask | `upload_file` |
| TK-B011 | ask | `input` on a page outside the allowlist (`example.com` as shipped), or with no page |
| TK-B012 | ask | `evaluate`: JavaScript the agent runs in the page, which can submit a form or send data anywhere, past every other rule |
| TK-P003 | ask | data sent to a host that only untrusted content named: typing (`input`, `send_keys`, `select_dropdown`), an upload, or a navigation with a query string (`navigate`, `go_to_url`) |

`extends` takes relative paths only, so your policy reaches the pack as a file next to it. Copy it there:

```bash
cp "$(python -c 'import os, tracekit.policy2 as p; print(os.path.dirname(p.__file__))')/packs/browser.yaml" .
```

or link the installed packs directory next to your policy, as the container image does (`/etc/tracekit/packs`), and
write `extends: packs/browser.yaml`. Then redefine a rule by id to change it, for example your typing allowlist:

```yaml
extends: browser.yaml   # the copy next to this file
ask:
  - id: TK-B011
    tool: '^browser_use:input$'
    field: page_url
    pattern: '^'
    unless: '^https://([A-Za-z0-9.-]*\.)?(shop\.example|intranet\.example)\.?(:[0-9]+)?([/?#]|$)'
```

To let `evaluate` run without a person, move TK-B012 to `flag` (it runs and is marked): a rule with the same id
replaces the pack's, in any section. To hold only typing and uploads to untrusted hosts, not navigations, redefine
TK-P003 (in a policy that also extends the HTTP packs, this one rule replaces theirs too):

```yaml
ask:
  - id: TK-P003
    tool: '^browser_use:(input|upload_file)$'
    field: sends_to
    pattern: '.'
    from: untrusted
```

**A rule on a click covers the click, not the request it makes.** A deny on clicking "Permanently delete" (`click`
whose `page_url` is the delete page) doesn't stop `navigate` to the URL that button submits to
(`deleted.html?confirm=yes`), nor `evaluate` submitting the form (TK-B012 holds that). Deny the state-changing URL
itself as well, on navigations:

```yaml
deny:
  - id: ACME-D002
    class: browser
    field: url
    pattern: '^https?://account\.example/account/deleted\.html\?'
```

The rules are tripwires on the URL text: a host that resolves to an internal address under a public name is not
caught.

Browser Use asks the model for its actions as structured output, not as tool calls, so a model response carries no
tool use for them. The pack names them under `structured_output:`: reconciliation doesn't expect a tool use for a
`browser_use:*` decide. That keeps [`gateway_mandatory`](../gateway.md#reconciliation) and autotrace from marking every
action `reconcile.fabricated`, and it means Browser Use's actions get no L3 cross-check: the record can't show that
the model asked for an action, only that the signer decided it.

With an Anthropic model the output comes as one forced tool call, `AgentOutput`, which the pack doesn't name: a name
under `structured_output:` needs no decide, so any agent could call a tool of its own `AgentOutput` and run it
unchecked. Under `gateway_mandatory`, where each such call is otherwise a `reconcile.hook_missing`, a Browser Use
deployment on an Anthropic model names it in its own policy, and only if no other tool of its agents has that name:

```yaml
extends: browser.yaml
structured_output: [AgentOutput]
```

## Example

`examples/browser_use_agent.py` runs offline: a stand-in registry and `FakeSigner` deciding with the browser pack.

## Not covered

- Browser Use actions carry no call id, so every action is a call of its own (attempt 0); a retry is a new decision.
- There is no saved state: an action waiting for an approval does not survive the process.
- What the page itself does (scripts, redirects after a click) is not an action and is not seen.
- A link's target the model never read (an `href` Browser Use doesn't show it) enters the provenance index only once
  the agent is on that page (its URL is in the next step's browser state).
