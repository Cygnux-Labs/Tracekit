# tracekit: see what your coding agent actually did, and why

A small, dependency-free kit (Python 3.8+, stdlib only) that plugs into Claude Code's hooks. For every session it records:

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
./demo/run_demo.sh
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
