# Browser Use (signer RPC)

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.browser_use.trace_tools` gates every action a Browser Use agent runs (navigate, click, input,
extract, upload_file, evaluate, custom actions). Before each action it asks the Tracekit signer for a policy decision;
after the action it records the outcome. It works with any object that implements the signer RPC
(`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "browser-use>=0.13.11,<1.1"
```

Python 3.11 or newer (browser-use's own requirement). Tested with 0.13.11, 1.0.2, 1.0.3 and 1.0.9 (the names a cell finds bound are checked against 1.0.3 to 1.0.9). Every push runs the 0.13
adapter contract, and the 1.0 one, over `BrowserLoop` and `Repl.call` on the real classes, against browser-use 1.0.x
in its own job; the nightly adapter-contract job runs it against browser-use `@latest`. On 0.13 the adapter wraps
the action registry; on 1.0 it wraps `BrowserLoop.wrap_tool_execute`, which every function tool, the `python` cell
included, passes through, and `Repl.call`, which runs the `finish_from_repl` delivery (an output tool gets no tool
hook) and every cell as `exec`. Browser Use is imported only to build the result of a refused action, to read its
action timeout and, on 1.0, to find those seams.

## Setup

`import tracekit; tracekit.instrument()` before the agent is built wires it all: on 0.13 every `Tools` built afterwards
(an `Agent` builds one when you pass none) has its actions gated; on 1.0 every function tool Browser Loop runs, the
`python` cell included, is. All of them are on one signer stream, and Browser Use's model calls through the OpenAI,
Anthropic and Google Gen AI SDKs are recorded (autotrace). By hand:

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

`trace_tools(tools, signer, registered)` takes any signer RPC client and its `register_run` response. On 0.13, wrap
each `Tools` once, and don't also call `instrument()` in the same process: the action would be decided twice. On 1.0
the seam is Browser Loop itself, one per process: `trace_tools` returns the `Tools` it was given, and a second run
(or `instrument()` after `trace_tools`) is refused (raised, or under `instrument()` reported as not wired) rather than
silently replacing the first. Actions run through any other registry are not seen. Model calls can also go through
the [LLM gateway](../gateway.md).

Observe the task as `trusted` from your application: the hosts, addresses and values it names then count as trusted,
and provenance holds only what a page alone brought in ([policy](../policy-v2.md#provenance-untrusted-and-from-untrusted)).

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before an action | `observe` | each browser state Browser Use made since the session's last action, oldest first: what the model read of the page (URL, title, tab URLs and the page's text, up to 100,000 characters), as `untrusted`, source `browser_use:page` |
| before the action runs | `decide` | a fresh `tool_call_id`, the tool as `browser_use:<action>`, `tool_class_hint: browser`, the args below (`parsed`) |
| right before it runs | `approval_consume` | the same call and args, and the approval id when the action waited for one |
| after it runs | `complete` | `status` `ok`, or `error` for an `ActionResult` with an error; the result (a page's content is untrusted, so the signer indexes it for provenance), or the exception type and message |
| on 1.0, before the delivery runs | `decide` | a fresh `tool_call_id`, `browser_use:finish_from_repl`, its source (`expression`) as args |
| after the delivery ran | `complete` | `status` `ok`, or `error` when the expression raised |

On 1.0, the `python` cell is a tool like the others: its decide names it `browser_use:python` and reads the cell's
source (`code`) with `ast.parse` only, never running it; `finish_from_repl` is read the same way from its `expression`.
The reader follows a small subset of Python. Each literal browser-helper or shell call is decided as the action it
stands for, on the pack's own rules (`goto_url` as a navigation, `js` as evaluate, and so on), and the cell takes the
strictest of those decisions. A literal argv list is decided as the shell command it runs, for `subprocess.run`/`Popen`
and for `asyncio.create_subprocess_exec`, `os.exec*` and `spawn*`, `posix_spawn*` and `pty.spawn` (the program path must
be literal too). A call in a binding target, an annotation, a default or a PEP 695 bound is read too, and so is a call
in a part of an expression that may not run (the right of `and`/`or`, an arm of `x if c else y`): it is decided as if
it runs. Inside a branch or a loop's body a name holds what was last assigned to it there; after a branch, loop, `with`
or `try`, a name bound in a part that may not have run, or run more than once, holds a value the reader can't follow.

What the reader leaves to the cell, unread:

- a builtin called directly, except those listed below;
- a call into `json`, `re`, `math`, `cmath`, `time`, `datetime`, `itertools`, `collections`, `string`, `textwrap`,
  `unicodedata`, `decimal` or `os.path`: a public function or class the module defines itself, one level down
  (`json.loads`, `datetime.datetime`), a classmethod of such a class (`datetime.datetime.now`), or a path function
  under `os.path`. The list is in `tracekit/policy2/source.py`; it leaves out `time`'s clock and time zone setters,
  `decimal.setcontext` and `localcontext`, `json.dump` and `json.load`, and `re.purge`. A class a package exports from
  a submodule of its own (`json.JSONDecodeError`) may be named only in an `except` clause or `isinstance`;
- a method of plain data the cell built: a `str`, `bytes`, list, dict, set, tuple, `int`, `float`, `re` match or
  pattern, `datetime`, `date`, `time`, `timedelta`, `timezone` or `Decimal` from a literal, a comprehension, one of the
  calls above or an operation on plain data, through that type's own methods (`items.append(x)`, `data.get("k")`,
  `d.isoformat()`). A container's items are plain too when it was built from plain data only (what `json.loads`,
  `str.split` or a `re` call returns, a literal of such values) and nothing in the whole cell puts any other value into
  any container: `for item in data["items"]: item.get("n")`. A cell that stores or appends a value the reader can't
  follow anywhere is read with no container's items plain. A data attribute (`d.tzinfo`, `m.lastindex`) is plain only
  when its value holds plain data only; a match's `string` and a pattern's `pattern` are what was passed in, and wait.
  `x or y` and `x if c else y` are one of their operands: plain only when each operand holds plain data only;
- a builtin type's own function (`str.join`, `dict.fromkeys`);
- a function, lambda or plain class the cell defines, called by its name: its body is read where it is defined. A plain
  class has no base but `object`, no keyword, decorator or type parameter, and a body of `def`s without decorators; the
  dunder methods it defines (`__init__`, `__call__`, `__new__`) are read like any other method. A function keeps that
  standing under `property`, `classmethod` or `staticmethod` only: `@d` is `f = d(f)`, so after any other decorator
  the name holds what `d` returned, and calling it waits.

These wait for `on_parse_error` (`TK-SOURCE-PARSE`):

- binding, in any form, a builtin, a name the harness binds (`goto_url`, `json`, `os` and the rest), a name an import
  in the cell binds, or `__builtins__`; an import may bind a harness name only to what it already is (`import os`). A
  function's parameters and a comprehension's targets are exempt: they bind in their own scope, where the reader
  trusts no name;
- a dunder name or attribute, `builtins` and `__builtins__` (a plain class's own dunder methods are exempt);
- `:=` anywhere; `exec`, `eval`, `compile`, `breakpoint`, `help`, `input`, `exit` and `quit` wherever they are named,
  called or not;
- an import outside the list above, standard library included; and an import outside a function that binds a command
  or helper under the cell's own name (`from os import system`, `from browser_harness.helpers import goto_url as g`),
  since the name stays bound for later cells. A command a cell function returns or yields (`h = f()` where `f`
  imports and returns `system`) stays bound for later cells too, but no cell can call it unread: a call through a
  call's result, or through a name the cell didn't bind, waits;
- a decorator that is a function, lambda or class the cell defines; any other decorator but `property`, `classmethod`
  and `staticmethod` is read as the call it is (`@goto_url` reads as `goto_url(f)`, whose argument isn't literal text,
  so it waits);
- any other class: a base, a metaclass, a decorator or a body of anything but `def`s runs code the reader does not;
- a store into anything but plain data, and any attribute store;
- a helper, builtin, module or module function used as anything but a direct call (`map(goto_url, ...)`, `key=len`,
  `print(len)`, `f = os.system`); a value the reader can't follow where the callee calls what it is handed (`map`, a
  `key`, `re.sub`'s replacement, `textwrap.indent`'s predicate); a second name for a value the reader can't follow
  (`y = x`, `y = x or z`);
- a method of anything but plain data the cell built: a helper's result (`js(...).strip()`), an item of a container
  whose items aren't plain, a harness object (`bu.click(...)`), a file;
- a call or attribute through a name the cell didn't bind: the REPL keeps its names from cell to cell, so it is an
  earlier cell's value;
- in a function, lambda or generator body, which runs later: a call through any name the cell binds, or through a
  module (`def f(): return json.loads(s)`);
- `open` with any mode but a literal read mode, `print(..., file=...)`, `globals`/`locals`/`vars`,
  `setattr`/`delattr`, `__import__`, and a computed `getattr`;
- a callee or required argument that isn't literal text, an unknown bare callee (raw CDP such as `cdp(...)` and
  `_`-prefixed helpers), over 256 calls, or over 64 KiB.

What the reader does not see: it trusts names, not what a held cell a person approved left in them. Approving a held
cell that rebinds a name it trusts (`import pickle as json`, `goto_url = ...`) lets later cells call that name unread,
as if it were still the harness's or the module's own. Nor does it read what a function it leaves unread does with an
argument an earlier approved cell made: `json.loads` calls its argument's `startswith`, `datetime` calls a time zone's
`utcoffset`. Approve a cell that rebinds a trusted name only if you would approve every later cell that uses it.

A
cell that raises is completed as `error`: Browser Use hands the traceback to the model as the cell's text, so the
completion carries the text and the error status. The `finish_from_repl` delivery is an output tool, which Pydantic AI
runs without the tool hook above: it is decided and completed at `Repl.call`, which is where its expression runs.
`Repl.call` gates both ops it runs. The `python` cell's `exec` is the one the tool hook just decided: it marks that
cell's code in a context variable, and the `exec` runs without a second decision. An `exec` from anywhere else, which a
later release could add, is decided as `browser_use:python` before it runs. 1.0's `Session`, the agent's deps, holds the
REPL and the run's state but no browser session, so no page is observed and `page_url` is always `""`.

The args are the action's params plus `page_url`, the URL of the page the action ran on: empty when there is none,
when Browser Use doesn't say within 2 s, or on 1.0, whose `Session` has no browser session (an allowlist rule never
exempts an empty `page_url`).

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
  `Action blocked by policy: <rule ids>`, and the run goes on. On 1.0 a refused `finish_from_repl` is not delivered:
  the model is told `Action blocked by policy: <rule ids>` and the run goes on, so it can deliver another way. A
  refused `exec` no python tool call decided raises `tracekit.Refused` and does not run.
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
| TK-B001 | deny | navigating to a `file:` URL (also behind `view-source:` or `blob:`, or with controls in the scheme), or to a `javascript:` URL, which runs code in the page as `evaluate` does |
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

## What the model said

Not recorded by the integration: `trace_tools` wraps the Tools, which never see the model's output (its `thinking`
and `next_goal`). Record the model calls with `tracekit.instrument()` or the [LLM gateway](../gateway.md); an action
carries no model call id, so they are not linked to the actions. Which frameworks and providers return readable reasoning, and how to turn it on: [reasoning](../reasoning.md).

## Not covered

- Browser Use actions carry no call id, so every action is a call of its own (attempt 0); a retry is a new decision.
- There is no saved state: an action waiting for an approval does not survive the process.
- What the page itself does (scripts, redirects after a click) is not an action and is not seen.
- A link's target the model never read (an `href` Browser Use doesn't show it) enters the provenance index only once
  the agent is on that page (its URL is in the next step's browser state).
- On 1.0, no page is observed and `page_url` is empty. A `python` cell's browser calls run inside the cell, not as
  actions: Tracekit reads the cell's source as a small subset of Python and decides each literal helper or shell call
  as the action it stands for, with the cell at the strictest; the same goes for the `finish_from_repl` expression.
  Left unread are builtins called directly, the inert modules' own functions, plain data's own methods and the cell's
  own functions and plain classes (their bodies read where defined); anything outside the subset is held as
  `TK-SOURCE-PARSE` (the list is under [What is recorded](#what-is-recorded)), and approving a held cell that rebinds
  a name the reader trusts lets later cells use that name unread. A decision is a statement about the calls the source names: what the cell computes
  with plain data is left to it.
