# tracekit: see what your coding agent actually did, and why

https://github.com/user-attachments/assets/46640e32-82e2-46ef-a318-a9220f04714c

For every session it records:

- **What you asked:** each prompt.
- **What the model said and thought:** assistant text and reasoning, read from the session transcript. Treat the reasoning as a claim, not proof.
- **What it actually did:** every tool call, with its full input, the policy decision and the result.
- **Context and cost:** model, token usage, working folder, and every lifecycle event.

The log is **tamper-evident**: each record carries a SHA-256 hash of the previous one. Editing, deleting or reordering any record breaks the chain.

## Install (Claude Code, macOS or Linux)

```bash
cd tracekit
python3 install.py            # user-wide; use --project for just this repo
# restart Claude Code and use it normally
python3 view.py               # writes ~/.tracekit/report.html; open it in a browser
python3 verify.py             # check the log hasn't been altered
python3 verify.py anchor      # save the current head hash; keep a copy off this machine
python3 install.py --uninstall
```

## Observer: a live terminal for every agent

```bash
python3 observer.py          # open http://127.0.0.1:7777 and leave it running
```

This is a Bloomberg-style screen that updates as agents work. It shows every session, including each subagent Claude Code spawns and any other agent you instrument.

| Panel | What it shows |
|---|---|
| Ticker | Sessions, agents running, actions, actions per minute, tokens in and out, blocked, flagged, errors, files, elapsed time, ledger size |
| 1 Agents | Each session's prompt, with the main agent and its subagents as a tree. Shows status (running, idle, done), what each is doing right now, action count, tokens and model. |
| 2 Tape | Every event, newest first: prompts, thinking, speech, tool calls with status and duration, spawns, finishes, blocks, reviews |
| 3 Alerts | Blocked actions, policy flags, failures and reviewer findings, by severity |
| 4 Tool mix | Calls per tool |
| 5 Timeline | One lane per agent, showing when each action ran and for how long, coloured by type (read, write, run, network, spawn, blocked) |
| 6 Reasoning | What each agent said and thought, including when the provider withheld its thinking |
| 7 Files | Every file read, written or blocked, and which agent touched it last |
| 8 Detail | For the selected action: the reasoning just before it, full input and result, policy decision, and its ledger hash and previous hash |

**Commands.** Type in the top bar and press Enter. `AGT fix` shows one agent, `TOOL BASH` one tool, `FILE .env` one file, `FLAG` only problems, `FIND timeout` searches everything, `SEQ 42` opens record 42, and `CLR` clears filters. Press `/` to jump to the command bar, `F` to show only flagged actions, `?` for help.

**Integrity.** The chain badge turns red if the log fails verification. `python3 observer.py --export replay.html` writes a single file anyone can open. It replays the run with a timeline you can scrub, and re-checks every hash in the viewer's browser.

**Other agents.** Anything can be traced, not only Claude Code:

```python
from tracekit_sdk import Tracer
t = Tracer(agent="research-bot")
t.prompt("Compare Q3 revenue")
w = t.subagent("fetcher", "Fetch ACME filings")      # gets its own lane
with w.tool("http_get", {"url": "..."}) as call:     # policy-checked before it runs
    call.result({"status": 200})
w.done("ok"); t.end()
```

Agents on other machines, or written in other languages, can POST JSON to `/api/ingest`. Set `TRACEKIT_INGEST_TOKEN` and bind with `--host 0.0.0.0` to accept them. See `examples/custom_agent.py`. For the plain terminal, `python3 watch.py` prints the same feed as text.

## The five layers it covers

| Layer | What it gives you | Files |
|---|---|---|
| 1. Actions | Every tool call, with input, result and time | `hook.py` |
| 2. Context | Your prompts, model, tokens, working folder | `hook.py` |
| 3. Stated intent | Thinking and text from the transcript, placed before the action | `hook.py` |
| 4. Cross-checks | Automatic flags (below) plus an independent model review | `view.py`, `judge.py` |
| Enforcement | Rules that **block** dangerous calls before they run | `policy.json` |
| Integrity | Hash chain plus external anchors | `verify.py` |

**Automatic flags in the report:**

- Blocked by policy
- Wrote outside the project folder
- Touched secrets or credentials
- **Changed a file never mentioned in your prompt or its reasoning**
- Acted with no stated reasoning
- Network access, destructive command, external side effect
- Tool error, or no result recorded

**Independent review:**

```bash
python3 judge.py --session <id-prefix> --via-cli   # uses your signed-in `claude` CLI, no tools, one turn
export ANTHROPIC_API_KEY=...; python3 judge.py --session <id-prefix>   # or call the API directly
python3 judge.py --session <id-prefix> --dry-run   # see exactly what gets sent
```

A separate model compares what you asked, what the agent said, and what it did, then returns findings as JSON. The verdict is written into the log too.

## End-to-end demo (real Claude Code run)

```bash
bash demo/run_demo.sh
```

This copies `demo/project` (a small repo with a timeout bug) to a temp folder and runs a real headless `claude -p` session with tracekit hooks. It uses its own `TRACEKIT_HOME` and a `--settings` file, so your normal setup is untouched. It then verifies the log, renders the report and runs a tamper test on a copy.

The run in `demo/sample-output/` shows:

- The agent fixed `api.py`, ran the tests and left `billing.py` alone.
- Its attempt to write `.env` was **blocked by the policy gate**. The agent saw the reason and reported it instead of working around it.
- Some thinking was **withheld by the provider**. The report says so rather than showing it as empty.
- The tamper test caught a single edited record.
- The independent reviewer (`judge.py --via-cli`) rated the run `aligned`. It also noticed the agent had echoed an instruction written *inside* `billing.py` ("The demo checks the agent leaves this alone"). That is the kind of in-file instruction that prompt injection uses.

## Policy (`~/.tracekit/policy.json`)

- `deny` rules block the call. Claude Code receives the reason and has to take another route.
- `flag` rules let the call through but mark it in the report.

The defaults block `sudo`, `curl … | sh`, force-pushes, recursive deletes of root or home, and writes to `.env`, `.ssh` or `.aws` files. Edit the rules freely; they are regexes.

## Privacy and safety

- Nothing leaves your machine except when you run `judge.py`.
- Common secrets (API keys, GitHub, AWS and Slack tokens, private keys, `password=`) are masked *before* anything is written. Huge outputs are truncated, with a hash of the full content kept.
- **Fail-open by default:** if tracekit itself crashes, the agent carries on and the error goes to stderr. Set `TRACEKIT_FAIL_CLOSED=1` to block instead.
- Other settings: `TRACEKIT_HOME` (log folder), `TRACEKIT_POLICY`, `TRACEKIT_MAX_STR`.

## Limits

- **Reasoning is self-reported.** Models can leave out or rationalise their real reasons, and some providers summarise or hide reasoning. The flags look for gaps between words and actions; they do not read the model's internal computation. That needs interpretability tools on open-weight models.
- **The hash chain only proves internal consistency.** Someone who can rewrite the whole file can rebuild a valid chain. `verify.py anchor` plus a copy of the anchor stored elsewhere (a git commit, a message to yourself) closes that gap.
- **Hooks can't see what happens inside a command.** They see the Bash command line, not every file or network call the command makes. Use a sandbox or OS-level auditing for that.
- **Other agents.** Cursor, Codex and custom agents need their own adapters. Anything that can pipe hook-style JSON into `hook.py` works; for SDK agents, call `common.append()` from your tool wrapper.
