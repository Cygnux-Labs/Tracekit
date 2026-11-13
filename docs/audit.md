# `tracekit audit`

`tracekit audit` is a read-only command that replays the tool calls found in local coding-agent transcripts through the policy engine and reports what the current policy would have held or denied. Each call is decided as the signer decides it: an MCP tool (`mcp__<server>__<tool>`) also as `mcp:<server>/<tool>` and under its bare name, and a PowerShell command also as a shell line.

It does not start a signer, does not write anything, and does not make network calls. It is a replay against today's policy, not a signed record. Tracekit never recorded these calls, so nothing here is evidence.

It is experimental ([support](support.md)): it works and is tested, but may change.

## Usage

```
tracekit audit [ROOT | --calls FILE] [--agent NAME] [--policy PATH] [--since 7d] [--show] [--all] [--json | --share]
```

```
$ tracekit audit --since 7d --show
a replay against today's policy, not a signed record
policy: …/tracekit/policy2/packs/dev.yaml (sha256:…)

read: claude (~/.claude/projects): 1204 calls in 31 sessions
1204 tool calls in 31 sessions since 7d: Tracekit would have denied 2 and held 9 for a person; it would have flagged 57 and allowed 1136.
…
by rule:
  TK-F003: 41  (destructive)
  TK-A002: 3  (deleting a remote Git ref)
  TK-D004: 1  (recursive delete of root or home)
…
denied and held calls (--all for every call):
  4f1c…  2026-10-28T14:02:11+00:00  Bash  deny  rules=TK-D004,TK-F003  text='Bash rm -rf ~/'
```

(The numbers above are an example, not a measurement.)

- `ROOT` is a Claude Code transcripts' folder (Cursor's with `--agent cursor`, Cline's with `--agent cline`,
  Gemini CLI's with `--agent gemini`, and another agent's once it has a reader); a folder that doesn't exist is
  an error (exit 2). With no ROOT and no `--calls`, audit reads every known agent's default folder that exists
  (see [What it reads](#what-it-reads)), and exits 2 when there is none.
- `--calls FILE` reads the calls from a [calls file](#calls-file) instead (`-` for stdin). FILE must be a regular
  file: a pipe (as `<(...)` gives) goes to `--calls -`. A file it can't open, or `--calls -` with no standard input,
  exits 2 with the reason; for a FILE that isn't a regular file, what it is: a directory, a pipe, a symlink (audit
  follows none), or another file that isn't regular, such as `/dev/null`.
- `--agent NAME` takes an agent's name as `tracekit init --agent` does (`claude`, `codex`, `cursor`, `gemini`,
  `opencode`, ...). With `--calls`, each call is decided as that agent's Tracekit hook would decide it: a call the hook
  denies before it maps it (Kilo's `notebook_execute`, goose's Code Mode, Crush's `agent` and `agentic_fetch`, a Devin
  call missing the argument it is decided on) is a deny by `TK-HOOK-BLOCKED`; the others are mapped as the hook maps
  them, so `run_shell_command` or `Shell` is decided as `Bash`. A line the mapping can't take (nested too deep) counts
  as malformed. Without `--agent`, names are taken as Tracekit's (`Bash`, `Write`, `Edit`, `Read`, `WebFetch`,
  `mcp__<server>__<tool>`). With ROOT, it names the reader that reads ROOT, and its calls are mapped as with
  `--calls`. An agent with no reader (every agent but `claude`, `cursor`, `cline` and `gemini`) needs
  `--calls FILE`, and `--agent claude`, `cursor`, `cline` or `gemini` a ROOT or `--calls FILE`: without them it
  exits 2.
- `--policy` selects a policy file (default: the dev pack, `tracekit/policy2/packs/dev.yaml`).
- `--since` limits the replay (e.g. `7d`, `24h`, `30m`, or an ISO-8601 time, UTC unless it gives an offset); a call
  without a timestamp is kept. A `--since` that isn't in the past, or that no date can name, exits 2.
- `--show` includes each call as an approver sees it: its secrets redacted as the signer redacts them (`.env` content
  too), cut to 72 characters.
- `--all` lists every call; without it, only the calls Tracekit would have denied or held for a person.
- `--json` emits a machine-readable report, with every call.
- `--share` prints the counts alone, to post as a [field report](field-reports.md): the window's length, the number
  of sessions, the calls by decision, and each rule by the decision of the calls it matched, marked `also matched,
  not why` when the rule's section isn't that decision and `not placed` for an engine check. A rule id that isn't
  Tracekit's own is counted as `custom rule`. No session, path, time, call or rule description. With `--since`, it
  also prints the calls by decision for each day of the window, 24 hours each and numbered from the window's start
  (`Day 1`), a day with no calls too, and the calls with no time (a calls-file line without `time`) on a `No time`
  line. A day line holds no date, weekday or hour, and the window's start isn't printed, but with the date you post
  it, a reader can tell which days the agent ran. Without `--since` there are no day lines: day 1 would be the first
  call's, and say how far back the transcripts go.

The report always begins with the disclaimer: "a replay against today's policy, not a signed record".

## What it reads

One reader per agent, each with its default folder:

| Agent | Default folder |
|---|---|
| `claude` | `$CLAUDE_CONFIG_DIR/projects` when it is set, else `~/.claude/projects` |
| `cursor` | `~/.cursor/projects` |
| `cline` | `$CLINE_SESSION_DATA_DIR`, else `$CLINE_DATA_DIR/sessions`, else `~/.cline/data/sessions` (`$CLINE_DIR` moves `~/.cline`); and, for tasks from before Cline 4.0, `saoudrizwan.claude-dev/tasks` in VS Code's global storage: `~/Library/Application Support/Code/User/globalStorage` (macOS), `~/.config/Code/User/globalStorage` (Linux), `%APPDATA%\Code\User\globalStorage` (Windows) |
| `gemini` | `$GEMINI_CLI_HOME/.gemini/tmp` when it is set, else `~/.gemini/tmp` |

The line after the policy, `read:`, names each agent read, its folder (the calls file's path, or `-`, with
`--calls`), and its calls and sessions; `--json` has the same under `agents`, and gives each call its `agent`. An
agent read from more than one of its default folders is one entry: its calls and sessions add up, and `folder` is the
list of them.

Claude Code's reader reads every `.jsonl` file under its folder, at any depth: each Claude Code session's transcript, and its subagents' files
(`<session>/subagents/*.jsonl`, a workflow's agents' in `<session>/subagents/workflows/<workflow>/`), which count
under that session. Each line is a JSON object; assistant messages may contain `tool_use` blocks. A tool use whose id
was read already (a resumed or forked session's file repeats the calls it copied) counts once. The reader reuses
`tracekit.hook.transcript_entries` and the policy engine from `tracekit.policy2.engine`.

Cursor's reader reads the agent transcripts Cursor writes for each chat, of its IDE's agent and of the `cursor-agent`
CLI: `<project>/agent-transcripts/<id>/<id>.jsonl` under its folder (an older build's flat `<id>.jsonl`, and a
subagent's file in `<id>/subagents/`, which counts under `<id>`). A ROOT can also be one project's folder or its
`agent-transcripts` folder. Each line is a JSON object; a `role: assistant` line's message may contain `tool_use`
blocks, whose names are mapped as Cursor's Tracekit hook maps them (`Shell` is decided as `Bash`). A line has no time,
no id and no tool result: with `--since`, a file last written before the window is skipped and one written in it
counts whole, and a call can't be told from a copy of it, so each line counts. The IDE's chat database (`state.vscdb`)
isn't read.

Cline's reader reads each task in its folder: `<id>/<id>.messages.json`, where Cline 4.0 and later (the CLI and the
VS Code extension) keep a session, and `<id>/api_conversation_history.json`, where earlier releases of the extension
kept a task, in VS Code's global storage (`saoudrizwan.claude-dev/tasks` under `~/Library/Application
Support/Code/User/globalStorage` on macOS, `~/.config/Code/User/globalStorage` on Linux and
`%APPDATA%\Code\User\globalStorage` on Windows; Cline 4 reads those but doesn't move them, so with no ROOT audit
reads each of those that exists as well). Like Claude Code's reader, it stays inside its folder, through a Windows
directory junction too. Each `tool_use` block of an assistant message is a call, mapped as Tracekit's Cline hook maps
it, so every command of a `run_commands` and every file of a `read_files` is decided; a call the hook can't read is a
deny by `TK-HOOK-BLOCKED`. A message's `ts` is its time, else the file's modification time. The task's id is its
session. A file that isn't JSON of that shape counts as one malformed entry. A call an older task wrote as XML in the
message's text, rather than as a `tool_use` block, isn't read.

Gemini CLI's reader reads each project's `chats` folder under its folder: `<project>/chats/session-*.jsonl` (JSON
lines, since Gemini CLI 0.39), `<project>/chats/session-*.json` (one JSON object a session, before 0.39), and a
subagent's `<project>/chats/<parent session id>/<id>.jsonl`, which counts under its parent's session. The project's
other files are not read. Tool calls are in a message's `toolCalls`, and in a `$set` line's full history; Gemini CLI
writes a message again each time it updates, so a call counts once, by its id, as its last copy has it. A call stays
counted after a `$rewindTo`: the conversation dropped it, but the agent made it. Each call is decided as Gemini
CLI's Tracekit hook decides it, so `run_shell_command` is decided as `Bash`.

Two kinds of Gemini CLI session aren't in the default folder. Under Gemini CLI's macOS Seatbelt sandbox
(`SANDBOX=sandbox-exec`) its runtime state, sessions included, is in `~/.cache/.gemini/tmp` (under `$GEMINI_CLI_HOME`
when that is set): read it with `tracekit audit ~/.cache/.gemini/tmp --agent gemini`. And Gemini CLI deletes sessions
older than 30 days by default (`general.sessionRetention`), so older calls can't be audited: set a longer
`general.sessionRetention.maxAge` in its settings to keep them.

The readers follow no symlink. Files and folders they can't read are counted and skipped, and so is a line that isn't
JSON.

## Calls file

Any agent, or any log, can be audited by turning it into a calls file: one JSON object a line.

```json
{"time": "2026-11-10T14:02:11Z", "session": "s1", "tool": "Bash", "args": {"command": "rm -rf build"}}
```

`tool` (a string) and `args` (an object) are required; a line without them counts as malformed. `time` (ISO-8601, UTC
unless it gives an offset) and `session` are optional: a call without a time is kept whatever `--since`, a `time`
that isn't ISO-8601 (an epoch number, say) counts the line as malformed, and a call without a session counts under
the file's name (`stdin` for `-`). With `--share`, a calls file read without `--since` is "the whole calls file".

For example, a log of one JSON object a line with `ts`, `tool` and `input`:

```
jq -c '{time: .ts, tool: .tool, args: .input}' agent.log | tracekit audit --calls - --since 7d
```

## Output

- After the disclaimer and the policy, the `read:` line: each agent read, with its folder, calls and sessions.
- Then how many calls in how many sessions, and how many Tracekit would have denied, held, flagged and allowed.
- Counts per verdict (`deny`, `ask` / held, `flag`, `allow`). A call the policy engine fails on counts as a deny
  (`TK-ENGINE-ERROR`), as the signer would decide it. A shell command that is neither text nor an argv of strings
  (an argv with an item that isn't a string, say), with any `--agent` or none, is held (`TK-SHELL-PARSE`), as the
  signer holds it; with `--agent cline` or `--agent devin`, a call that agent's hook can't read is denied
  (`TK-HOOK-BLOCKED`), as its hook blocks it before the signer sees it. So is a goose `read_image` call whose source
  Tracekit can't read as a URL (`http://[::1/cat.png`): that is the v2 hook's answer, while the v1 hook allows such a
  call under the default fail-open mode.
- Counts per rule id, most first, each with what the rule is (its `reason` or `label`, or the viewer's words for the
  engine's own rules).
- The session and timestamp of each denied or held call (every call with `--all`), and its redacted text with
  `--show`.

## Limitations

It sees only the tool calls the transcript holds, decided by today's policy. A transcript the agent could edit is not evidence. See [limits](limits.md#audit-tracekit-audit).
