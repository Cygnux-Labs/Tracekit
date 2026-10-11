# Quickstart: the v2 signer

The v2 signer is still a preview. It records every tool call your agent makes as a signed event, decides each call
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

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # the first line, before your agent builds its agents, tools or sessions
```

Then run your agent as usual. `instrument()` registers a run with the signer and closes it when the process exits. It
wires every framework it finds installed: OpenAI Agents SDK tools, LangGraph / LangChain `ToolNode`s (which
`create_agent` builds), Claude Agent SDK hooks, MCP `ClientSession.call_tool`, and the OpenAI, Anthropic and Google Gen
AI clients' model calls. Each tool call is decided by the signer before it runs (`allow`, `deny`, `ask`) and recorded
after. A denied call reaches the model as a refusal and the agent goes on. Calling it again returns the same run. With
none of these installed it warns and does nothing. TypeScript: `const tk = await instrument()` from
`@cygnux/tracekit`, then pass `tk.ai` (Vercel AI SDK) or `tk.agents` (OpenAI Agents JS) to the framework.

You don't start anything yourself. The first client that needs a signer starts one in the background and later
clients reuse it (`tracekit up` / `tracekit down` do the same by hand). The signer's keys and store live in your user's
data dir. It listens on a Unix socket in a private runtime dir. On Windows it listens on a loopback TCP port instead,
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
| `tracekit.instrument(): ...; system mode: start the system signer` | `sudo tracekit doctor` says what is wrong with the system signer. |
| `the Tracekit signer X (pid N, protocol [a, b]) ... cannot serve this client` | A dev signer from another Tracekit version is running: `tracekit up --replace` stops it and starts this one. |
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
Assurance: dev; records ed25519; checkpoint Ed25519 only (...); no witness cosignature; approvals: self
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
  started with a config refuses self-approvals: list who may answer under `approvals: {approvers: [...]}` in
  `signer.yaml` (see `tracekit/signer/service.py`).

Dev mode is for trying Tracekit and for catching mistakes, not attacks. Protection against the agent needs a signer
that runs as a different user or on another host (system mode, below), plus witnesses that cosign its checkpoints.

## System mode (Linux; macOS experimental)

System mode runs the signer as its own OS user, so the agent's user can't reach its keys, its store or its policy.
As root, from a root-owned Python and checkout:

```bash
sudo /usr/bin/python3 -m tracekit init --v2 --user AGENT [--approver ADMIN] [--policy /etc/tracekit/policy.yaml]
```

This installs Tracekit into the root-owned virtualenv `/opt/tracekit` and creates the `tracekit-signer` user with its
data dir `/var/lib/tracekit-signer` (0700). It writes `/etc/tracekit/signer.yaml` and runs `tracekit signer serve
--config` under a hardened systemd unit (`tracekit-signer`: no capabilities, `ProtectSystem=strict`, a system-call
filter). The socket is `/run/tracekit-signer/signer.sock`. The command also wires the v2 Claude Code hook for AGENT.
The root-owned `/etc/tracekit/client.json` names the socket. Dev auto-spawn is then off, and a `TRACEKIT_SIGNER` that
names another signer is refused, so the call is blocked.

It refuses an AGENT that is root or in a sudo, wheel, admin, docker or similar group. The approver defaults to the
admin running `sudo` and must be another user than AGENT: approve from that account with `tracekit approvals`. A
`--policy` file must be root-owned. `sudo tracekit uninstall --v2` removes the service, the configs, the venv (unless
v1 system mode still uses it) and the hooks. It keeps the signer's data dir and user, which `--purge` also deletes.

What system mode protects, and what it doesn't:

- **Protected:** the signing keys, the store and the sequence numbers (they belong to the signer's user), the policy
  (the signer decides; `TRACEKIT_POLICY` in the agent's environment changes nothing), and approvals (the agent's uid
  can't answer its own). Another local user can't write into the agent's runs either. The hook keeps a run's token in
  the agent's own 0700 runtime dir, and the signer accepts that token only from the uid that registered the run.
- **Not protected:** any process the agent's user runs can read that user's run tokens and write into the agent's own
  runs, or start runs of its own, unless harness binding (`--harness NAME=PATH`, Linux) binds runs to the harness's
  processes ([what binding does not stop](faq.md#what-does-harness-binding-not-stop)). Root on the machine can do anything; witnesses on another host are the defence against that.
- **Not protected either:** the hook lives in AGENT's own `~/.claude/settings.json`, which AGENT can edit. Removing
  the hook, or running tools outside Claude Code, leaves no record and no gap; system mode secures what is recorded,
  not that everything is.

Check an install with `sudo tracekit doctor` ([docs/doctor.md](doctor.md) lists every check and its fix).

`eval/e8_insider_v2.py` checks these properties as real separate users (decoy signer, cross-user injection, signer
down, policy through the environment, self-approval).
