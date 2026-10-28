# Quickstart: the v2 signer

The v2 signer records every tool call your agent makes as a signed event, decides each call
against a policy before it runs, and exports a run as a bundle that anyone can verify offline. This page runs it on
your own machine (macOS, Linux or Windows) as a **dev** signer, which runs as your own user. Three steps, under two
minutes; `make quickstart` runs them on a clean venv from the built wheel for each framework
(`tests/test_quickstart.py`). What this path doesn't cover is in [limits](limits.md).

## 1. Install

```sh
pip install tracekit-ai
```

That is all the dev signer needs (`tracekit-ai[signer]` still works and installs the same). Auditors who only verify
bundles can take the verifier alone, which runs on the standard library: `pip install --no-deps tracekit-ai`.

Some Pythons refuse `pip install` outside a venv (PEP 668: `error: externally-managed-environment`): Debian 12, Ubuntu
23.04 and later, and Homebrew's Python. Install it one of these ways instead:

```sh
python3 -m venv .venv && .venv/bin/pip install tracekit-ai   # a venv (Debian, Ubuntu: sudo apt install python3-venv first)
pipx install tracekit-ai                                     # the CLI only, nothing to import
uv tool install tracekit-ai                                  # the CLI only, nothing to import
```

Step 2 imports Tracekit in your agent's process, so an SDK agent needs it in its own environment: run the agent with
that venv's Python (`. .venv/bin/activate` also puts `tracekit` on your `PATH`), or `pip install tracekit-ai` in the
venv the agent already has. pipx and `uv tool` give you the `tracekit` command
(`tracekit last`, `tracekit view`, `tracekit approvals`, and `tracekit init --dev --v2` for Claude Code, whose hooks
then run from that install), but nothing your agent can import. The command and the SDK can come from two installs:
both use the same dev signer. Keep them at the same version.

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # the first line, before your agent builds its agents, tools or sessions
```

Then run your agent as usual. `instrument()` registers a run with the signer and closes it when the process exits. It
wires every framework it finds installed: OpenAI Agents SDK tools, LangGraph / LangChain `ToolNode`s (which
`create_agent` builds), Claude Agent SDK hooks, MCP `ClientSession.call_tool`, Browser Use's `Tools` (which an `Agent`
builds), CrewAI's tool hooks, Pydantic AI `Agent`s (the `Tracekit` capability), and the OpenAI, Anthropic and Google Gen AI clients' model calls. Each tool call is decided by the signer
before it runs (`allow`, `deny`, `ask`) and recorded after. A denied call reaches the model as a refusal and the agent
goes on. Each model response is committed to and, with the signer's content vault on (the dev signer keeps it), kept
in the vault, so `tracekit analyze --v2` can read what the model said before and after each call ([findings](findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)).
Calling it again returns the same run. With none of these installed it warns and does nothing. TypeScript:
`const tk = await instrument()` from `@cygnuxlabs/tracekit`, then pass `tk.ai` (Vercel AI SDK) or `tk.agents` (OpenAI Agents
JS) to the framework.

### A server: a run per conversation

A long-running server (FastAPI, a queue worker) should record each conversation in its own run, so each can be
exported, verified and investigated on its own. Keep the run open across the conversation's requests and make it
current around each one; every wired framework's tool and model calls inside go to it, and an approval a person gives
between requests resumes in the same run:

```python
run = tracekit.instrument("support-desk")             # at startup
conversations = {}                                     # conversation id -> its Tracekit run

async def respond(conversation_id, message):
    if conversation_id not in conversations:
        conversations[conversation_id] = run.client.run("support-desk", principal=conversation_id)
    with conversations[conversation_id].current():     # current for this request; still open after it
        result = Runner.run_streamed(agent, message, context=ctx)
        async for event in result.stream_events():
            ...
```

Close a conversation's run (`conversations.pop(cid).close()`) when it ends; the signer closes one left idle for its
`idle_s` (an hour by default). A stateless request can use `with run.client.run(...) as r:`, which closes it at the end
of the block. Calls made outside any such block go to the process run; if the signer closed it after it was idle, the
next call registers a new process run and logs a warning, instead of being refused.

### When a call needs a person (`ask`)

An `ask` holds the call until a person answers it (`tracekit approvals`, or the viewer's approval pages). Each
integration waits its own way. Every one checks the answer with the signer before the call runs. A signer error
refuses the call. An unanswered approval expires after an hour.

A call held in an SDK agent prints nothing while it waits: the agent just seems to stop. Run `tracekit approvals list`
in another terminal to see the held call, then answer it ([below](#approve-from-another-terminal)). Only the coding-agent
hooks print a line naming the approval and the command that answers it.

| Integration | How it waits | Timeout | Then |
|---|---|---|---|
| OpenAI Agents SDK (Python, JS) | interrupts the run | none of its own | `apply_decisions(state)` (JS `applyDecisions`), then run the state again: an approved call runs, a rejected one reaches the model as a rejection |
| LangGraph / LangChain, with a checkpointer | pauses the graph (`interrupt`) | none of its own | resume with `Command(resume=...)`: an approved call runs, any other answer reaches the model as an error tool message |
| LangGraph / LangChain, no checkpointer | does not wait | none | denied at once: "approval required, and the agent has no checkpointer to wait for it" |
| MCP client (`call_tool`) | timed wait in `call_tool` | `approval_wait_s`, 300 s (0 refuses at once) | an error `CallToolResult` when not approved, and an unanswered approval is withdrawn; the run goes on |
| Browser Use | timed wait before the action | `approval_wait_s`, by default and at most five sixths of Browser Use's action timeout: 150 s of `BROWSER_USE_ACTION_TIMEOUT_S`'s 180 s (0 refuses at once) | an error `ActionResult` when not approved, and an unanswered approval is withdrawn; the agent goes on |
| CrewAI | timed wait in its `before_tool_call` hook | 300 s | the call is blocked and the model gets the approval's state |
| Pydantic AI | timed wait in the `Tracekit` capability, before the tool or output function runs | 300 s | the call is skipped and the model gets the approval's state; an unanswered approval, or one whose agent run is cancelled, is withdrawn |
| Google ADK | timed wait in the `Tracekit` plugin, before the tool runs | 300 s | the call is skipped and the model gets the approval's state as the tool's error result; an unanswered approval, or one whose agent run is cancelled, is withdrawn |
| Haystack | timed wait in the `Tracekit` `before_tool` hook, which holds the whole step | 300 s | the call is refused and the model gets the approval's state as an error tool result; an unanswered approval, or one whose `run_async` is cancelled, is withdrawn |
| LlamaIndex | timed wait in the gated `call_tool` step | 300 s (a workflow `timeout` under 300 s cancels the wait) | the call is skipped and the model gets the approval's state; an unanswered approval, or one whose workflow is cancelled or times out, is withdrawn |
| Microsoft Agent Framework | timed wait in the `Tracekit` function middleware, before the function runs | 300 s | the call is refused and the model gets the approval's state as the call's result; an unanswered approval, or one whose agent run is cancelled, is withdrawn |
| Strands Agents | timed wait in the `Tracekit` hook provider, before the tool runs (not a Strands interrupt) | 300 s | the call is refused and the model gets the approval's state as an error tool result; an unanswered approval, or one whose agent is cancelled (`agent.cancel()` or its task), is withdrawn |
| Claude Agent SDK (Python, TS) | timed wait in its PreToolUse hook | 540 s (the hook's own timeout is 600 s) | a `deny` with the reason when not approved; the session goes on |
| Claude Code, Codex, Cursor, Gemini hooks | timed wait in the hook process | 540 s (hook timeout 600 s) | the harness's deny when not approved; the model may retry |
| Vercel AI SDK (TS, `tk.ai`) | the SDK's own tool approval | none of its own | `approvalResponses(parts)`, pushed to `messages`, resumes it; a call not approved throws |
| `tracekit.why` runtime | timed wait in `act()` | `approval_wait_s`, 300 s | an error result; retrying the same call in the same run reuses the approval |

You don't start anything yourself. The first client that needs a signer starts one in the background and later
clients reuse it (`tracekit up` / `tracekit down` do the same by hand). The signer's keys and store live in your user's
data dir, one per `HOME`. It listens on a Unix socket in a private runtime dir; where two of your `HOME`s share that
dir (macOS's `/tmp` fallback for a long `HOME`, Linux's `$XDG_RUNTIME_DIR`), each gets its own signer, the second in a
sibling dir named after its data dir. On Windows it listens on a loopback TCP port instead,
and publishes the port and a token in `%LOCALAPPDATA%\tracekit\run\endpoint.json`, which only you can read. Each side
proves it holds the token before any request is answered.

## 3. See it verified

```sh
tracekit last
```

```text
run 40c7ee89ae9eaec8f8eb8556b32fdc9d (my-agent)
Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint Ed25519 only (...); no witness cosignature; ...
bundle: /home/me/project/40c7ee89ae9eaec8f8eb8556b32fdc9d.tkb
check it again: tracekit verify 40c7....tkb --trust 40c7....trust.json
next: tracekit view --dev   (every run, replayed and reviewed)
```

`tracekit last` finds the dev signer's most recent finished run, exports it, writes a trust config that pins the dev
signer's log key next to the bundle, and verifies the bundle. `-o PATH` writes the bundle elsewhere. The report is
explained [below](#export-and-verify-by-hand). `tracekit view --dev` lists each run with its verdict, and replays and
reviews one ([viewer.md](viewer.md#laptop-viewer)).

Per framework, the same three steps with a 10-line example: [LangChain / LangGraph](quickstarts/langchain.md),
[OpenAI Agents SDK](quickstarts/openai-agents.md), [Claude Agent SDK](quickstarts/claude-agent-sdk.md),
[MCP client](quickstarts/mcp.md), [a custom agent](quickstarts/custom.md).

## First-run errors

| You see | What to do |
|---|---|
| `tracekit.instrument(): no signer answering at ...; dev auto-spawn is off while TRACEKIT_SIGNER is set` | Start the signer `TRACEKIT_SIGNER` names, or unset it for a same-user dev signer. |
| `tracekit.instrument(): ...; system mode: start the system signer` | `sudo /opt/tracekit/bin/python -I -m tracekit doctor` says what is wrong with the system signer. |
| `the Tracekit signer X (pid N, protocol [a, b]) ... cannot serve this client` | A dev signer from a newer Tracekit version is running (an older one is replaced on its own): `tracekit up --replace` stops it and starts this one. A signer you run yourself (`TRACEKIT_SIGNER`, system mode) that is older than this client: upgrade the signer first. From the TypeScript SDK, an older `tracekit` on your PATH starts an older signer: `pip install -U tracekit-ai`. |
| `tracekit last: the newer run ID (agent) is still open` | The agent is still running, or was killed before it closed its run. End it and run `tracekit last` again; meanwhile it shows the run before. |
| `tracekit last: no runs in the dev signer's store` | Add `import tracekit; tracekit.instrument()` to your agent and run it first. |
| `tracekit.instrument(): <framework> <version> not wired ... Tracekit is tested with ...` | Install the versions it names, or wire that adapter by hand as its quickstart shows. |
| `the v2 signer needs its policy engine ... pip install tracekit-ai` | A `--no-deps` install verifies but can't sign: install with its dependencies. |
| A path with spaces (Windows profiles, macOS `Application Support`) | Paste the commands `tracekit last` prints as they are: their paths are quoted for your shell. |

## Deeper: drive the signer yourself

The rest of this page does by hand what `instrument()` and `tracekit last` do, with the approval step a framework's
own control flow needs.

### A scripted agent

Before each tool call runs, the agent asks the signer. The signer answers `allow`, `deny` or `ask` and signs that
decision.

```python
from tracekit.sdk.client import Client

with Client().run(agent="quickstart") as run:
    run.observe("List the files here.", source="task", trust="trusted")   # the task: what it names counts as trusted
    d = run.decide("call-1", "Bash", {"command": "ls"})            # allow
    run.complete("call-1")                                          # the result is recorded against that decision
    d = run.decide("call-2", "Bash", {"command": "pkill tracekitd"})
    print(d["decision"], d["rule_ids"])                             # deny ['TK-D007']: the agent can't stop its signer
    held = {"command": 'echo "unterminated'}
    d = run.decide("call-3", "Bash", held)                          # ask: a command the signer can't parse waits for a human
    aid = run.call("approval_request", tool_call_id="call-3")["approval_id"]
    print("approve with: tracekit approvals approve", aid)
    if run.call("approval_wait", approval_id=aid, timeout_ms=300000)["state"] == "approved" and \
            run.approval_consume("call-3", "Bash", held, approval_id_hint=aid)["ok"]:
        run.complete("call-3")                                      # run it only now, with exactly those arguments
    print("run", run.run_id)
```

The default policy is the coding pack (`tracekit/policy2/packs/coding.yaml`). An approval is bound to the call's
arguments: if they change after the approval, `approval_consume` refuses them.

`run.observe(value, source=..., trust="untrusted")` records content that reached the agent other than as a tool result
(a mail, a ticket, a page your app fetched); the signer records a commitment to it, never the value, and every
decision then names the arguments whose values only untrusted content brought in
([provenance](policy-v2.md#provenance-untrusted-and-from-untrusted)). Send the task as `trusted` from your app, not
from the agent.

Claude Code: `tracekit init --dev --v2` wires its hooks to the same signer (`python -I -m tracekit.integrations.claude_code`).

`tracekit demo --server` runs the whole loop in a temp dir, with a test witness's cosignature and a tampered copy that
fails. A deployment for server-hosted agents: [deploy.md](deploy.md).

### Approve from another terminal

```sh
tracekit approvals list
tracekit approvals show <id>        # the signer's copy of the arguments, in full
tracekit approvals approve <id>     # or: reject <id>
```

### Export and verify by hand

```sh
tracekit signer trust -o trust.json             # pins this signer's log key
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json
```

```text
Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint Ed25519 only (...); no witness cosignature; approvals: self; key retirements not proven complete
```

The signer finalises a run a few seconds after it closes. A bundle exported before that verifies as
`VERIFIED TO HEAD n (open)`. A record signed by a key after the log retired that key fails the bundle and names the
record.

The report (and `--json`) also lists tool calls by evidence tier (`tiers`), records by `args_source` (raw, parsed,
coerced), the `signer_isolation` the signer recorded for each run (`isolation`), the tool classes that fail open
(`fail-open classes`), and `key assurance`: `asserted`, because the log declares its own keys (`certified` when a
[record-key issuer](issuer.md) certifies them). `witnessed+monitored` needs a log monitor's report ([monitor.md](monitor.md)).

To browse the runs instead, `tracekit view` (the dev signer's store, read-only) lists each run with its verifier
verdict, and replays and reviews one ([viewer.md](viewer.md#laptop-viewer)).

## What `dev` assurance means

`Integrity: VERIFIED` means three things. The bundle's records were signed by the log key you pinned. They form one
unbroken chain. They are included in a checkpoint that key signed. Nothing in the bundle was edited, dropped or
reordered after it was signed.

`Assurance` describes checkpoint cosigning only, not how the signer is isolated: `dev` when no pinned witness cosigned
the checkpoint (or the run holds a self-approval), `local` when only operator-run witnesses did, `witnessed` when enough
independent ones did. A same-user signer whose checkpoints a pinned witness cosigns verifies as `witnessed`: the witness
shows the log was not rolled back or forked after it cosigned, not that the agent could not reach the signer. How the
signer was isolated is recorded in each run's `signer_isolation` (`same-user` here).

In dev mode the signer is not protected against the agent:

- The signer runs as **your user, the same user as the agent**. An agent that runs arbitrary commands as you can read
  the signer's key and store, stop the signer, or rewrite history and sign it again. The policy (TK-D007) makes such
  attempts visible and blocks the obvious ones. It can't make them impossible.
- **No witness** has cosigned a checkpoint, so nothing outside this machine can show that the log was not rolled back or
  forked.
- **Approvals are self-approvals**: the same user who runs the agent approved them, and the bundle says so. A signer
  started with a config (`signer.yaml`) refuses self-approvals, with or without an `approvals` section: list who may
  answer under `approvals: {approvers: [...]}`, or set `approvals: {self_approval: allow}` for a single-user setup
  ([who may answer](approvals.md#who-may-answer)).

Dev mode is for trying Tracekit and for catching mistakes, not attacks. Protection against the agent needs a signer
that runs as a different user or on another host (system mode, below), plus witnesses that cosign its checkpoints.

## System mode (Linux; macOS experimental)

System mode runs the signer as its own OS user, so the agent's user can't reach its keys, its store or its policy.
Run `tracekit init --v2 --user AGENT [--approver ADMIN] [--policy FILE]` as root from a root-owned Python:
[laptop system mode](deploy.md#laptop-system-mode) gives the commands for each Python version, and a clone route that
installs nothing into the system Python.

Init installs Tracekit into the root-owned virtualenv `/opt/tracekit` and creates the `tracekit-signer` user with its
data dir `/var/lib/tracekit-signer` (0700). It writes `/etc/tracekit/signer.yaml` and runs `tracekit signer serve
--config` under a hardened systemd unit (`tracekit-signer`: no capabilities, `ProtectSystem=strict`, a system-call
filter). The socket is `/run/tracekit-signer/signer.sock`. Init also wires AGENT's v2 hook for the coding agent
`--agent` names (default: Claude Code). The root-owned `/etc/tracekit/client.json` names the socket. Dev auto-spawn is then off, and a `TRACEKIT_SIGNER` that
names another signer is refused, so the call is blocked.

It refuses an AGENT that is root or in a sudo, wheel, admin, docker or similar group. The approver defaults to the
admin running `sudo` and must be another user than AGENT: approve from that account with
`/opt/tracekit/bin/python -I -m tracekit approvals`. A `--policy` file must be root-owned.
`sudo /opt/tracekit/bin/python -I -m tracekit uninstall --v2` removes the service, the configs, the venv (unless
v1 system mode still uses it) and the hooks. It keeps the signer's data dir and user, which `--purge` also deletes.

What system mode protects, and what it doesn't:

- **Protected:** the signing keys, the store and the sequence numbers (they belong to the signer's user), the policy
  (the signer decides; `TRACEKIT_POLICY` in the agent's environment changes nothing), and approvals (the agent's uid
  can't answer its own). Another local user can't write into the agent's runs either. The hook keeps a run's token in
  the agent's own 0700 runtime dir, and the signer accepts that token only from the uid that registered the run.
- **Not protected:** any process the agent's user runs can read that user's run tokens and write into the agent's own
  runs, or start runs of its own, unless harness binding (`--harness NAME=PATH`, Linux) binds runs to the harness's
  processes ([what binding does not stop](faq.md#what-does-harness-binding-not-stop)). Root on the machine can do anything; witnesses on another host are the defence against that.
- **Not protected either:** the hook lives in AGENT's own settings (`~/.claude/settings.json` for Claude Code), which
  AGENT can edit. Removing the hook, or running tools outside the hook or the SDK, leaves no record and no gap; system
  mode secures what is recorded, not that everything is.

Check an install with `sudo /opt/tracekit/bin/python -I -m tracekit doctor` ([docs/doctor.md](doctor.md) lists every
check and its fix).

`eval/e8_insider_v2.py` checks these properties as real separate users (decoy signer, cross-user injection, signer
down, policy through the environment, self-approval).
