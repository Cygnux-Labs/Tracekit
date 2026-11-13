# Coding agents other than Claude Code

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

```bash
tracekit init --dev --v2 --agent codex      # ~/.codex/hooks.json ($CODEX_HOME/hooks.json when it is set)
tracekit init --dev --v2 --agent cursor     # ~/.cursor/hooks.json
tracekit init --dev --v2 --agent gemini     # ~/.gemini/settings.json
tracekit init --dev --v2 --agent qwen       # ~/.qwen/settings.json
tracekit init --dev --v2 --agent droid      # ~/.factory/hooks.json
tracekit init --dev --v2 --agent opencode   # $XDG_CONFIG_HOME (or ~/.config)/opencode/plugin/tracekit.js; system mode: the agent's ~/.config
tracekit init --dev --v2 --agent kilo       # $XDG_CONFIG_HOME (or ~/.config)/kilo/plugin/tracekit.js; --project: .kilo/plugin/tracekit.js; system mode: the agent's ~/.config
tracekit init --dev --v2 --agent goose      # ~/.agents/plugins/tracekit/hooks/hooks.json (plus plugin.json beside it)
tracekit init --dev --v2 --agent antigravity   # ~/.gemini/config/hooks.json (see Antigravity CLI below)
tracekit init --dev --v2 --agent crush      # $CRUSH_GLOBAL_CONFIG, else $XDG_CONFIG_HOME (or ~/.config)/crush: crush.json; --project: ./crush.json
tracekit init --dev --v2 --agent devin      # ~/.config/devin/config.json (Windows %APPDATA%\devin\config.json); --project: .devin/hooks.v1.json
tracekit init --dev --v2 --agent cline      # ~/Documents/Cline/Hooks/<event>; --project: .clinerules/hooks/<event>
tracekit init --dev --v2 --agent gptme      # ~/.config/gptme/plugins/tracekit/ (user config only, no --project)
tracekit init --dev --v2 --agent openhands  # ~/.openhands/hooks.json; --project: .openhands/hooks.json
tracekit init --dev --v2 --agent copilot    # ~/.copilot/hooks/tracekit.json; --project: .github/hooks/tracekit.json (Copilot CLI 1.0.107 or later)
tracekit init --dev --v2 --agent codebuddy  # ~/.codebuddy/settings.json ($CODEBUDDY_CONFIG_DIR/settings.json when it is set); --project: .codebuddy/settings.json
# --project writes the project-level file instead; tracekit uninstall --agent X removes Tracekit's hooks and keeps your other settings
sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT --agent codex   # system mode: the signer as its own user
```

These hooks record to the v2 signer ([below](#on-the-v2-signer)), and a v2 hook replaces a v1 one. System mode's init
runs as root from a root-owned Python and puts no `tracekit` command on root's `PATH`. It writes these agents' hooks
into the agent user's own config, which that user can edit: `--managed` (hooks in admin-managed settings the agent can't
edit or turn off) is for Claude Code only, and init refuses it with these agents
([limits](limits.md#dev-mode-vs-system-mode)). The system-mode line runs after
[laptop system mode](deploy.md#laptop-system-mode)'s install. The v1 hooks, for the older laptop path (the `tracekitd` signer), are the same dev commands without
`--v2` and write the same files:

```bash
tracekit init --dev --agent codex      # v1; or cursor, gemini, qwen, droid, opencode, kilo, goose, antigravity, crush, devin, cline, gptme, openhands, copilot, codebuddy
tracekit demo --agent codex            # the scripted v1 demo, sent as Codex's own hook payloads (also cursor, gemini, opencode, goose)
```

**Codex runs these hooks only once you trust them.** Codex skips a hook that isn't managed until a person has reviewed
and trusted it as it is, so until then no Codex call is recorded or decided. Interactive `codex` asks at startup when a
hook is new or changed; `codex exec`, or choosing to continue without trusting, skips it without a word. After init,
run `codex` in a terminal and trust Tracekit's hooks (at its startup prompt, or type `/hooks`); Codex asks again
whenever they change, as after another init. Codex keeps that trust in your `~/.codex/config.toml`
(`$CODEX_HOME/config.toml` when it is set; then init writes the hooks there too, and you run Codex with the same
`CODEX_HOME`) as `[hooks.state."<hooks.json path>:<event>:<group>:<handler>"]` with a `trusted_hash`
([Codex hooks](https://learn.chatgpt.com/docs/hooks)). Init ends by saying so, v1 and v2, and `tracekit doctor` checks
that each of Tracekit's Codex hooks, v1 or v2, is trusted as it is now and not turned off (`D-CODEX-HOOK-TRUST`): it
recomputes Codex's hash of each hook. For a hook with a setting Tracekit doesn't write, and with Python 3.9 or 3.10,
which can't read the file, it says it can't confirm ([limits](limits.md#signer-and-capture)).

For Codex, Cursor, Gemini CLI, Qwen Code and CodeBuddy Code the installer merges into existing settings: other hooks and settings are kept, a
backup is written first, and running it twice changes nothing. For Droid it writes a standalone `.factory/hooks.json`; if
the legacy `.factory/hooks/hooks.json` exists, init refuses to proceed until you save once in Droid's `/hooks` UI to migrate
it. For OpenCode it writes its own `tracekit.js` local
plugin and refuses to overwrite a file it did not install (in `plugin/`, which every OpenCode 1.x loads; 1.0 doesn't
read `plugins/`). Kilo Code is built on OpenCode and loads the same plugin, so for Kilo init writes that plugin to
Kilo's own `plugin/` folder (Kilo doesn't read OpenCode's). This was run with the Kilo CLI 7.8.18 on Linux; Kilo's docs
say its VS Code extension loads the same plugins, but that hasn't been tried. Kilo's built-in tools are OpenCode's, with
the same names and arguments; of its own tools, `background_process` (it runs its `command`) is decided as `Bash`,
`notebook_read` and `send_file` as `Read` and `notebook_edit` as `NotebookEdit`, each on its `path`, and
`generate_image` as `Write` on the `path` it writes, or, given an `image` it reads and sends to the image provider, as
a `Read` of that file and the `path`. The hook blocks
`notebook_execute`, which runs a notebook cell whose code no rule has read (VS Code only, with
`experimental.native_notebook_tools`). Kilo's other tools pass through under their own names
([limits](limits.md#signer-and-capture)); everything below about OpenCode's plugin holds for Kilo. For goose it writes its own plugin directory (`plugin.json` plus `hooks/hooks.json`) and refuses
to install into a plugin whose `plugin.json` is not Tracekit's. A goose rule carries no matcher (goose silently skips
a rule whose matcher is a bare `*`, which is an invalid regex); the PreToolUse action carries `timeout: 600` and
`on_failure: block`, the post-tool actions `timeout: 30`. For Antigravity CLI it adds a hook named `tracekit` to agy's `hooks.json` ([below](#antigravity-cli)). Every v1 hook calls `python -I -m tracekit.agent_hooks <agent>` (OpenCode's plugin and Antigravity CLI's commands add the event),
which translates the harness's payload into the Claude Code hook shape and runs the same pipeline as the Claude Code
hook ([v2 hooks](#on-the-v2-signer)).

Crush reads `crushrc` / `.crushrc` (a Bash file, since Crush 0.88) first and `crush.json` as its legacy format, and
merges both. Tracekit's hooks go in `crush.json` (in a project; the user's is `$CRUSH_GLOBAL_CONFIG/crush.json`, else
`$XDG_CONFIG_HOME/crush/crush.json`, or `~/.config/crush/crush.json`, on Windows `%USERPROFILE%\.config\crush`).
Crush keeps its hooks as a flat list of `{name, command, timeout}` entries per event, not Claude Code's nested
matcher groups. Its payload and event names are already Claude Code's (`hook_event_name`, `session_id`, `tool_name`,
`tool_input`, `tool_use_id`, `tool_response`, `error`), so the adapter only maps its lower-case tool names:
`bash` -> `Bash`,
`view` -> `Read`, `write` -> `Write`, `edit`, `multiedit`, `lsp_replace_symbol` and `lsp_rename` -> `Edit`, `ls` -> `LS`,
`grep` -> `Grep`, `glob` -> `Glob` (`lsp_rename`, `ls`, `grep` and `glob` are decided on the `path` they read, never a
`file_path` sent beside it), `fetch` -> `WebFetch`, `download` -> `Write` (the file it creates is what the file rules
decide; its URL meets no fetch rule), and `mcp_<server>_<tool>` -> `mcp__<server>_<tool>`, whose results are
untrusted. That joined name doesn't split the server from the tool: the signer tries each `_` (up to eight) as the
server's end, so the shipped packs' MCP rules and `mcp:<server>/<tool>` mappings read it, and holds it as an unknown
tool on the server packs, but a rule of your own written for `mcp__<server>__<tool>` doesn't match it
([limits](limits.md)). Crush runs no hooks
inside a sub-agent, so the hook denies `agent` and `agentic_fetch` itself; put `permissions deny agent agentic_fetch`
in `crushrc` (in `crush.json`: `"options": {"disabled_tools": ["agent", "agentic_fetch"]}`) so Crush doesn't offer
them. It denies
Docker MCP Gateway's `code-mode` tools too (`mcp_<server>_code-mode` and the `code-mode-<name>` tools it makes), whose
scripts call MCP tools inside the gateway, where no hook sees them. Crush reads a built-in tool's argument names ignoring case and lets a later repeat win unless
it is null, so the hook denies a built-in tool call whose input repeats a name or has one that isn't lower-case
snake_case (`{"command":"ls","Command":"..."}`), at any depth: Tracekit would decide other arguments than the tool
runs with. Crush hands an MCP tool's arguments to its server as Tracekit reads them; a server that reads them
into a Go struct may still match names ignoring case.
A `PreToolUse` hook blocks a call with exit 2 and its reason on stderr (or `{"decision":"deny"}` on stdout at exit
0); Tracekit writes the exit-2 form, so a denied or held call does not run. Crush fires `PreToolUse` before its own
permission prompt. On macOS and Linux `install._blocking` wraps the command `init` writes: a v2 hook that cannot run
exits 2 and blocks the call, and a v1 hook does too with `TRACEKIT_FAIL_CLOSED=1`. Only Windows dev mode has no
wrapper, so there a hook that cannot start lets the call through. What Crush itself lets through is a hook that
outlives its timeout: the call proceeds (Tracekit's hook answers within 540 s, under the 600 s timeout). `TurnStart`
carries no prompt, and Tracekit doesn't read `TurnEnd`'s `last_assistant_message` yet, so `init` installs
`SessionStart`, `SessionEnd`, `PreToolUse`, `PostToolUse` and `PostToolUseFailure` only; no prompt or model text is
recorded (`SessionEnd` has a two-second budget). Tested through Crush's published hook payloads and Tracekit's
installer, not yet in a live Crush session.

Cline's CLI and its VS Code extension run a hook file named after its event: `init --agent cline` writes Tracekit's
`PreToolUse`, `PostToolUse`, `TaskStart`, `TaskComplete` and `UserPromptSubmit` files, executable and
without an extension (on Windows `<event>.ps1`, the only form the extension runs), into `~/Documents/Cline/Hooks`, or
with `--project` into the workspace's `.clinerules/hooks`, the folders both read. It never writes over a file that
isn't Tracekit's, and makes no backup next to one (the CLI runs a hook file whatever its extension). Cline runs every
hook file it finds, in `~/.cline/hooks` and a workspace's `.cline/hooks` too, so keep Tracekit's in one of them:
`tracekit doctor` warns about a second copy, which would decide and record each call twice. The extension reads
`Cline/Hooks` in the Documents folder the system reports (Windows' own, which OneDrive may have moved; on Linux
`xdg-user-dir DOCUMENTS`, which is the home folder itself when no Documents folder is set up), while the CLI always
reads `~/Documents`: when they differ `init` says so, and `--project` reaches the extension. The extension runs hooks
only while Hooks is on in Cline's settings (Features), as it is by default.

The CLI's payload carries the call's id and the model's input (`tool_call`, `tool_result`) beside the extension's
shape (`preToolUse`, `postToolUse`: `toolName` and `parameters`, each non-string value JSON-encoded, and no id), so the
hook reads the first when it is there. A hook answers `{"cancel": true, "errorMessage": "..."}` to block, and Cline turns
that into a stop of the whole task: approve a held call (`tracekit approvals approve <id>`) and resume the task, and the
retried call runs. Cline lets a call run when its hook fails, prints nothing, or takes longer than its timeout (the CLI
120 s, the extension 30 s), so each hook file prints the cancel itself when Tracekit's hook printed nothing, and the v2
hook caps `TRACEKIT_APPROVAL_WAIT` at 20 s. `PreToolUse` fires before Cline checks a call's input against the tool's schema, which
takes several shapes for each tool: every command, file or URL in any of them is decided. Tested with Cline CLI 3.0.74
and the VS Code extension 4.1.26 on Linux, each driven by a scripted model: a denied call, a held call approved and
its task resumed, and allowed calls, verified with `tracekit last`.

Kiro CLI ([hooks](https://kiro.dev/docs/hooks/)) runs the hook files in a project's `.kiro/hooks`, and from CLI V3 in
`~/.kiro/hooks`: `init --agent kiro` writes Tracekit's own file there, `tracekit.json` (with `--project`, the
project's), with one hook per event (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`),
each named `tracekit-<event>`, with no matcher (every tool), a 600 s `PreToolUse` timeout and 30 s for the rest.
Uninstall deletes the file; a file there with a hook that isn't Tracekit's is left as it is. `init` and
`tracekit doctor` read `kiro-cli --version` and say so when a CLI before 3.0 won't read `~/.kiro/hooks`. Kiro sends
Claude Code's payload shape (`session_id`, `hook_event_name`, `cwd`, `tool_name`, `tool_input`, and after the call
`tool_response`, a string) with no call id, so pre and post events are paired by tool and arguments, first in first
out. A hook blocks a call at exit 2, and Kiro shows its stderr to the model as it is and sends no `PostToolUse` for
it; any other exit, a hook that can't start, and a hook that outlives its timeout let the call run. On macOS and Linux
`install._blocking` turns a v2 hook (or any hook in system mode) that can't run into exit 2; on Windows, where Kiro
runs hooks under cmd.exe, nothing wraps a dev hook ([limits](limits.md#signer-and-capture)). `delete_file` names its
file `targetFile`, not `path`: each file tool is decided on the key it reads, never a decoy beside it, and a file,
shell or fetch call without it is denied in the hook. Kiro joins an MCP server's name and its tool's with `_`
(`mcp_<server>_<tool>`), so a server named with `_` can't be split off: the call is decided as
`mcp__<server>_<tool>`, whole. Before a deferred MCP tool's first call, Kiro calls `tool_load`
(`{"tool_ids": ["<server>::<tool>"]}`), decided under that name. `kiro-cli chat --no-interactive` fires `Stop` but no
`SessionEnd`, so its run closes at the signer's idle timeout. Tested with Kiro CLI 3.3.0 on Windows 11: the payloads in
`tests/data/harness/kiro.json` are recorded ones.

Devin (the Devin CLI, and Devin Desktop, formerly Windsurf; [hooks](https://docs.devin.ai/cli/extensibility/hooks/overview))
runs hooks in Claude Code's format: nested matcher groups under `hooks` in its user config
(`~/.config/devin/config.json`, on Windows `%APPDATA%\devin\config.json`), or the bare event map in a project's
`.devin/hooks.v1.json`. `init` writes no matcher (Devin's is a regex, so `*` isn't one; none matches every tool), a
600 s `PreToolUse` timeout and 30 s for the rest. On macOS and Linux `install._blocking` wraps each command: a v2 hook,
or any hook in system mode, that can't run exits 2 and blocks the call; a v1 dev hook that can't run lets the call run,
unrecorded, unless `TRACEKIT_FAIL_CLOSED=1` is set. On Windows nothing wraps it, and Devin doesn't document the shell it
runs a hook in there: `init` writes the Python path bare when it needs no quotes, else in cmd.exe's quoted form
([limits](limits.md#signer-and-capture)). Devin gives a call no id, so its pre and post events are paired by tool and
arguments, first in first out; a `tool_response` with `success: false` is recorded as a failure. A hook blocks a call
at exit 2, which Tracekit's does, with the reason on stderr; any other exit, a timeout or output Devin can't read is an
error that doesn't block. Devin documents only `exec`'s arguments (`command`, `shell_id`), and its decoder may match a
key ignoring case, so a `read`, `write` or `edit` is decided on every path under a key whose name, case and `_`
ignored, ends in `path`, `paths` or `file` (`file_path`, `Path`, `notebook_path`, `target_file`, …: a decoy under one
key never hides the path under another), and an `apply_patch` on every file its `*** … File:` headers and a unified
diff's `---`, `+++` and `diff --git` lines name. One with none of them, and a `webfetch` with no `url` or with one
under another spelling too (`URL`), are denied in the hook, before the signer, with the names of the arguments they sent, to report
on [#566](https://github.com/Cygnux-Labs/Tracekit/issues/566). **Devin also runs Claude Code's hooks**
(`read_config_from.claude`, on by default: `.claude/settings.json`, `~/.claude/settings.json`, `~/.claude.json`), on
its own payloads, so with Tracekit's Claude Code hook installed it would decide each Devin call a second time; that
hook blocks every one, since the payload has no `tool_use_id`. So `init --agent devin` sets
`"read_config_from": {"claude": false}` in the config it writes to (a project's `.devin/config.json`), and says so:
Devin then reads none of Claude Code's hooks, rules, skills, commands or MCP servers. Uninstall leaves the setting and
says where to set it back to `true`. Desktop runs no hooks in Restricted Mode. Tested through Devin's documented
payloads and Tracekit's installer; not tested in a live Devin session.

gptme (v0.36.0) loads a Python plugin from `~/.config/gptme/plugins/tracekit/`. Install it with
`tracekit init --dev --v2 --agent gptme` or use `tracekit init --dev --agent gptme` for v1. Installation uses the
user's configuration and supports dev mode. If the user config already has a `[plugins]` table, init prints the
updates to add the plugin path and include `tracekit` in a nonempty user allowlist. If a project uses an allowlist,
make sure the effective list includes `tracekit`. Run `tracekit doctor` from the workspace to check registration.
Remove its hooks with `tracekit uninstall --agent gptme`.

The plugin decides calls that reach gptme's confirmation hook, including under `-y`. An allow skips the interactive
editor and later confirmation hooks, including gptme's guardrail with `GPTME_GUARDRAILS=enforce`. The v2 coding policy
holds IPython (`TK-A063`), keys sent to existing tmux panes (`TK-A064`) and MCP server loads (`TK-A065`) for approval.
The v2 hook records prompts and results from undecided tools as untrusted observations. See [gptme's limits](limits.md).

OpenHands (the `openhands` CLI, whose last release, 1.16.0 on SDK 1.21.0, its README marks as no longer maintained;
[hooks](https://docs.openhands.dev/openhands/usage/customization/hooks)) runs hooks in Claude Code's format under
`hooks` in `~/.openhands/hooks.json`, with `"matcher": "*"`, a 600 s `PreToolUse` timeout and 30 s for the rest, each
command wrapped by `install._blocking`. The SDK never reads `hooks.json` by itself: an SDK app runs these hooks only
when it passes them, `Conversation(..., hook_config=HookConfig.load(working_dir=...))`. Its payload is Claude Code's
under other keys (`event_type`, `working_dir`, `message`), with no call id: pre and post events are paired by tool and
arguments, first in first out. Only exit 2 (or a JSON `deny`) blocks a call: any other exit and a timeout let it run,
so a held call that nobody answers is denied before the 600 s are up, and the agent makes the identical call again
once it is approved. `tool_input` is the tool's Action (with its class name under `kind`, which is dropped); a
`file_editor` (or a gemini-preset file tool) with no path or an `apply_patch` with no file header is denied in the hook.
**`task` and `delegate` are denied in the hook**: they run a sub-agent with no hooks, so its calls would go undecided
and unrecorded. **The terminal is interactive** (bash in tmux): text typed into the command running (`is_input: true`),
a key name (`UP`, `TAB`, `ENTER`, `C-r`, which it sends as keystrokes), a command with a control character in it
(tmux types it as a key: `^U` erases the line before it, `\r` is an Enter, a tab completes the word before it) and a line left open (a trailing `\`) run
with what came before or comes after them, so the hook marks each `typed` and the policy holds it for a person
(`TK-SHELL-PARSE`), as it holds an unclosed quote or heredoc; a whole command is decided as before. The v1 hook can't
hold, so it denies them: use `--v2` with OpenHands. **In the CLI, a working
directory's `.openhands/hooks.json` replaces the user's**: `HookConfig.load` reads only the first of the two that
exists (the working directory is `$OPENHANDS_WORK_DIR` when set), so a repo with its own file runs no Tracekit hook
(`D-OPENHANDS-PROJECT` warns; `init` merges into a `hooks.json` in whichever of OpenHands' three forms it is written;
[limits](limits.md#signer-and-capture)). Agent Canvas (the former GUI) merges project and user hooks and runs on your
machine by default; hooks in a remote or Docker sandbox can't reach a local signer, which isn't covered. On Windows the
hook command isn't wrapped and the terminal is PowerShell, which the policy decides as Bash
([limits](limits.md#signer-and-capture)). Tested through the released CLI's SDK (1.21.0) `HookManager` with its real
tools and Tracekit's installer.

GitHub Copilot CLI ([hooks](https://docs.github.com/en/copilot/reference/hooks-configuration)) needs **1.0.107 or
later**: from that release its `preToolUse`, `postToolUse` and `postToolUseFailure` payloads carry a `toolCallId`, and
Tracekit blocks a call whose payload has none rather than pair it by guesswork. `init` writes its own hooks file,
`~/.copilot/hooks/tracekit.json` (`$COPILOT_HOME/hooks/tracekit.json` when that is set; `--project`:
`.github/hooks/tracekit.json`), with a 600 s `timeout` on `preToolUse`: Copilot's own is 30 s, too short for a person
to approve, and a call whose hook times out goes on through Copilot's normal permission flow, so Tracekit's answers
within 540 s. Copilot's payload names
no event, so the hook's command does, for the v1 hook too. Copilot denies a call when its hook exits with anything but
0, which Tracekit's does at exit 2, and shows the reason from the hook's JSON (`permissionDecision: deny`). `--project`
writes this machine's Python path into `.github/`, which is usually committed: init says how to keep the file out of
the commit. `bash`, `apply_patch`, `view`, `glob`, `rg`, `web_fetch` and `task` are decided as `Bash`, `Edit` (every
file the patch names), `Read`, `Glob`, `Grep`, `WebFetch` and `Task`, and `web_search` as
`mcp:github-mcp-server/web_search`, the built-in MCP server's tool it is; `create`, `edit`, `str_replace_editor`,
`grep`, `powershell`, `write_bash`, `write_powershell` and `write_agent`, the tools Copilot gives other models, as
`Write`, `Edit`, `Read`, `Write` or `Edit`, `Grep`, `PowerShell`, `Bash` and `PowerShell` (`command` = the typed
input) and `Task`. Each file tool is decided on the `path` or `paths` it reads, never on another argument beside it.
Text `write_bash` and `write_powershell` type into a running shell is read as Devin's `write_to_process` is: a
control character, a history expansion (a `!` before a word, a `^` starting a line) or a line that sets the shell's
state is denied in the hook, and so is a call with no text; no receipt is taken before what it types runs.
The payload doesn't say which other tools are MCP ones: Copilot names them `<server>-<tool>`, so a name with a `-` is
decided as an MCP tool under every split, and the strictest decision stands; a name of 64 characters or more, where
Copilot cuts names, is denied ([limits](limits.md#policy)). No prompts, session events or model text are recorded.
Copilot also runs the hooks in a repository's `.claude/settings*.json`, so a project-level Tracekit Claude Code hook
decides each Copilot call as well ([limits](limits.md#custody-12)). Tested in live Copilot CLI 1.0.107 sessions on Linux
with the model the test plan offered (Copilot's automatic choice, a GPT model): the tools Copilot gives other models
are mapped from its bundle, not from captured payloads.

CodeBuddy Code (Tencent's coding CLI, `@tencent-ai/codebuddy-code`) runs hooks in Claude Code's format: nested matcher
groups under `hooks` in `~/.codebuddy/settings.json` (`$CODEBUDDY_CONFIG_DIR/settings.json` when it is set), a
project's `.codebuddy/settings.json` (`$CODEBUDDY_PROJECT_CONFIG_DIR/settings.json` when it is set) or its
`settings.local.json`; `init` writes where those variables point. Its payloads, event names and tool names are Claude
Code's (`session_id`, a subagent's calls in its session's, `transcript_path`, `cwd`, `tool_name`, `tool_input`,
`tool_use_id`, `tool_response`; `PostToolUseFailure` with `error`), so the adapter maps only its own tools:
`NotebookRead` and `ViewImage` are decided as a `Read` of the path each reads (`notebook_path`, `image_path`), and
`DeferExecuteTool`, which runs a deferred tool (`NotebookEdit`, `Monitor`, MCP tools and others, by default) by its
`toolName` with its `params`, as that call; the deferred tool's own `PreToolUse` decides it again under the same call
id, and the decision the call completes is its decision; a deferred call the policy holds can't run, even once a
person approves it ([limits](limits.md#signer-and-capture)). `LibraryUpload` sends the local file at its `path` off
the machine. CodeBuddy parses no URL there: it takes `file://`, else `file:`, off the front and opens what is left (`~/`
in the home folder, a relative path in its working directory, `@x` as itself or else as `x`), decoding nothing, and each
form it may open is decided, a percent-decoded one too. The v2 packs decide it as the upload it is, at least as strictly
as a shell upload of the same file: a credentials file (`.env`, `.ssh`, a private key, AWS credentials,
`.netrc`, a cluster, Docker, gcloud or Git credential file) is denied (`TK-D022`) and any other file is flagged as
egress (`TK-F024`; held on the strict pack). `init` writes a `*`
matcher on the tool events, a 600 s `PreToolUse` timeout and 30 s for the rest (CodeBuddy reads seconds, 60 unless
set, and blocks a call whose hook outlives its timeout). A hook blocks a call with exit 2 or with
`hookSpecificOutput.permissionDecision: "deny"`; Tracekit's does both, with the reason on stderr and in
`permissionDecisionReason`, which the model reads. Any other exit lets the call run, so on macOS and Linux
`install._blocking` wraps each command: a v2 hook, or any hook in system mode, that can't run exits 2 and blocks the
call; a v1 dev hook that can't run lets it run, unrecorded, unless `TRACEKIT_FAIL_CLOSED=1` is set. On Windows
nothing wraps it, and CodeBuddy runs it under Git Bash, or PowerShell when it finds none. CodeBuddy lets the last
hook's `permissionDecision` stand, so a PreToolUse hook that runs after Tracekit's and answers `allow` runs a call
Tracekit denied: `tracekit doctor` names a settings file with one (`D-HOOKS-ORDER`). These formats
come from CodeBuddy Code 2.183.0's bundled code and the hooks Tencent's LoopForge writes for it; the payloads in
`tests/data/harness/codebuddy.json` are derived from that code, not recorded in a live session
([limits](limits.md#signer-and-capture)).

| | Codex CLI | Cursor | Gemini CLI | OpenCode | goose | Qwen Code | Factory Droid | Devin | Cline (CLI and VS Code extension) | gptme | OpenHands | CodeBuddy Code | Kiro CLI |
|---|---|---|---|---|---|---|---|---| --- | --- |---| --- | --- |
| Hook events used | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | preToolUse, postToolUse, postToolUseFailure, beforeSubmitPrompt, sessionStart, sessionEnd | BeforeTool, AfterTool, BeforeAgent, SessionStart, SessionEnd | tool.execute.before, tool.execute.after | PreToolUse, PostToolUse, PostToolUseFailure | PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, TaskStart, TaskComplete, UserPromptSubmit: one hook file each | `TOOL_CONFIRM`, `TOOL_EXECUTE_POST`, `TURN_PRE`, `SESSION_START`, `SESSION_END` | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, SessionStart, SessionEnd | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, SessionEnd |
| Run id | `session_id` | `conversation_id` | `session_id` | `sessionID` | `session_id` | `session_id` | `session_id` | `session_id` | one task (each prompt, from `TaskStart` to `TaskComplete`), keyed on `sessionContext.rootSessionId` (the CLI's session, which `cline --id` resumes; its subagents' calls are in it too), else `taskId` | derived from gptme's session log directory | `session_id` | `session_id` (a subagent's calls are in its session's run) | `session_id` (`sess_<uuid>`) |
| Blocking a call | exit 2 + a reason on stderr (and `permissionDecision: deny`); on Windows exit 0 + the JSON deny, since PowerShell turns 2 into 1 and Codex reads the JSON only at 0 | exit 2 + `{"permission": "deny"}` | exit 2 + `{"decision": "deny"}` | the plugin throws before the tool runs when Tracekit blocks the call (exit 2) or the hook can't decide it (any other exit, or Python can't start) | exit 2 + a reason on stderr, stdout empty (a stray stdout line reads as no decision to goose) | exit 2 + a reason on stderr (Qwen Code ignores stdout at exit 2 and sends stderr to the model); nothing on stdout; on Windows the command ends in `; exit $LASTEXITCODE`, since PowerShell turns 2 into 1 | exit 2 + a reason on stderr and `hookSpecificOutput.permissionDecision: "deny"` | exit 2 + a reason on stderr | `{"cancel": true, "errorMessage": ...}` at exit 0 (Cline reads no exit status); a cancel stops the whole task, not only the call | the plugin returns a skip with Tracekit's reason when the hook exits nonzero, cannot start, or times out after 600 s | exit 2 + a reason on stderr; any other exit or a timeout lets the call run | exit 2 + a reason on stderr and `hookSpecificOutput.permissionDecision: "deny"` | exit 2 + a reason on stderr, which the model sees as it is; any other exit, or a timeout, runs the call |
| Tool call ids | from the harness | from the harness | none: paired by tool and arguments, first in first out | `callID` | `tool_call_id`, from the harness | `tool_use_id`, from the harness | none in documented stdin: paired by tool and arguments, first in first out | none in the documented payload: paired by tool and arguments, first in first out | the CLI's `tool_call.id`; the VS Code extension sends none: paired by tool and arguments, first in first out | assigned by the plugin and paired by the `ToolUse` object | none (`metadata` is `{}`): paired by tool and arguments, first in first out | `tool_use_id`, from the harness | none: paired by tool and arguments, first in first out |
| Tool names | `Bash`; `write_stdin` → `Bash` (`command` = the typed `chars`; current Codex sends no hook for it, so what is typed into a running command isn't decided: [limits](limits.md#signer-and-capture)); `apply_patch` → `Edit` (`paths`: every file the patch adds, updates, deletes or moves to, its file headers read as Codex reads them, indented ones too); `apply_patch` run from the shell stays a `Bash` call, which the v2 coding pack holds for a person (`TK-A034`); MCP as `mcp__server__tool` | `Shell` → `Bash`; `Read`, `Write`, `Grep`; `Delete` → `Edit`, so the file rules read it; Cursor's hook sends an edit by any of its tools as a `Read` and then a `Write` of the whole file ([limits](limits.md#signer-and-capture)); the names its transcripts give its edit tools (3.29: `StrReplace`, `ApplyPatch`, `EditNotebook`; an older prompt's `search_replace`, `write`, `delete_file`, `edit_notebook`) → `Edit`, `Edit` (`paths`: every file a patch header names, in any argument), `NotebookEdit` (path: `target_notebook`), `Edit`, `Write`, `Edit`, `NotebookEdit`, each only with the file its tool reads: a patch Tracekit can't read, or a tool without its path, is decided as an unknown tool, as before; every path argument the input names is decided too, a patch's and a notebook edit's included (`file_path`, `path`, `target_file`, `filePath`, `target_notebook`, `paths`: Cursor doesn't document which its tools read); `MCP:x` → `mcp__cursor__x`; other names pass through, which the policy treats as unknown tools | `run_shell_command` → `Bash`; `read_file` and `read_many_files` → `Read`; `write_file` → `Write`; `replace` → `Edit`; `grep_search` (`search_file_content` in older releases) → `Grep`; `glob`, `list_directory`, `web_fetch`, `google_web_search`; MCP tools, which Gemini CLI names `mcp_<server>_<tool>`, → `mcp__<server>_<tool>`; every path a file tool reads is decided, under each release's name for it (`file_path`, `absolute_path`, `dir_path`, `path`, and `read_many_files`' `paths` and `include`); `web_fetch` is decided on every URL its prompt names (`urls`) and on a `url` beside it | `bash` → `Bash`; `read`, `write`, `edit` (path: `filePath`); `apply_patch` (and 1.0's `patch`) → `Edit` (`paths`: every file its headers name, and a path with a `:` also up to it, as OpenCode 1.2 reads it); `batch` (experimental; OpenCode 1.x before 1.4 only: later releases and OpenCode 2 have none) is blocked: OpenCode runs the calls in it without plugin hooks; `glob`, `grep` (path: `path`); `webfetch`, `websearch`, `task`; MCP tools under OpenCode's `<server>_<tool>` names, which the policy treats as unknown tools | `shell` → `Bash`; `write` → `Write` (path: `path`); `edit` → `Edit` (path: `path`); `tree` → `LS` (path: `path`); `read_image` → `Read` (path: `source`, not `path`); `<extension>__<tool>` → `mcp__<extension>__<tool>`; other names pass through unchanged, which the policy treats as unknown tools | `run_shell_command` and `monitor` → `Bash`; `read_file` → `Read` (path: `file_path`, `absolute_path` before 0.13); `write_file` → `Write`; `edit` (and Gemini's `replace`) → `Edit`; `notebook_edit` → `NotebookEdit` (path: `notebook_path`); `grep_search` → `Grep`; `glob`, `list_directory`, `web_fetch`, `web_search`, `todo_write`; `agent` → `Task`; any other tool, MCP tools included, under its own name; file paths as for Gemini CLI; `web_fetch` is decided on its `url` and also on every URL its prompt names (Qwen Code fetches only the `url`) | `Execute` → `Bash`; `Create` → `Write`; `ApplyPatch` → `Edit` (`input`: complete patch; `paths`: all file headers); `FetchUrl` → `WebFetch`; other names, including `mcp__server__tool`, pass through | `exec` → `Bash` (`command` in any case, `\r` read as a line end; denied in the hook with no command, input that isn't an object, or a control character but a tab or line end); `write_to_process` → `Bash` (`command` = its one argument besides `shell_id`, the text it writes, whatever its name: its fields aren't documented; `\r` read as a line end; denied in the hook with any other argument, no text, a control character or a bash history expansion (`!-1`, a `^` starting a line) in the text, or text that sets shell state a later line runs: `fc`, an `alias` definition, a function, `trap`, the `exec` builtin, `PROMPT_COMMAND`, `LD_PRELOAD` …); a name sent twice to any tool, in any case, is denied in the hook; `read` → `Read`; `write` → `Write`; `edit` → `Edit` (each decided on every path under a key ending in `path`, `paths` or `file`, case and `_` ignored, and denied in the hook with none); `apply_patch` → `Edit` (`paths`: all patch file headers and a unified diff's file names; denied in the hook with none); `grep`, `glob`; `webfetch` → `WebFetch` (denied in the hook without a `url`, or with one under another spelling too); `mcp__server__tool` and other names pass through | `run_commands` → `Bash` (`command` for one command, `commands` for several, each decided on its own as Cline runs it in its own shell, a here-doc joined to its delimiter's line; from any shape Cline takes: a list, one command, `{command, args}`, `cmd`); `read_files` → `Read` (`paths`: every file, under `files`, `paths` or `file_paths`); `editor` → `Write` when it sends neither `old_text` nor `insert_line` (it then creates a missing file), else `Edit` (its `path`); `apply_patch` → `Edit` (`paths`: every file the patch names); `fetch_web_content` → `WebFetch` (`urls`: every request's URL); an MCP tool `<server>__<tool>` → `mcp__<server>__<tool>`; a call none of these can be read from is cancelled; the other tools pass under their own names | `shell` and tmux commands as `Bash`, `save` as `Write`, `append`, `patch`, `patch_many`, `morph` and `hashline_edit` as `Edit`, `read` as `Read`, `ipython`, MCP as `mcp__server__tool`; other tools pass through under their own names | `terminal` → `Bash` (`is_input: true`: text typed into the running command); `file_editor` → `Read` (`view`), `Write` (`create`) or `Edit` (the rest), on `path`, and denied in the hook without one; `apply_patch` → `Edit` (`paths`: every file its headers name; denied in the hook with none); the gemini preset's `write_file`, `edit`, `read_file` and `list_directory` → `Write`, `Edit`, `Read` and `LS` (path: `file_path`, `dir_path`); `glob`, `grep`; `task` and `delegate` denied in the hook (a sub-agent runs no hooks); MCP tools under their own names, decided on their `data`; other tools under their own names | Claude Code's (`Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `Monitor`, `PowerShell`, `mcp__server__tool`, ...), unchanged; `NotebookRead` and `ViewImage` → `Read` (path: `notebook_path`, `image_path`); `LibraryUpload` under its own name, decided on every file its `path` may open (`file://` or `file:` taken off, `@` dropped, percent-decoded); `DeferExecuteTool` → the tool its `toolName` names, with its `params` | `execute_bash` (`execute_pwsh` on Windows) → `Bash`; `read_file` → `Read`; `fs_write`, `fs_append` → `Write` (`text` as `content`); `str_replace` → `Edit` (`oldStr`, `newStr` as `old_string`, `new_string`); `delete_file` → `Edit` (its `targetFile`); `list_directory` → `LS`; `file_search` → `Glob`; `grep_search` → `Grep`; `web_fetch` → `WebFetch`; `mcp_<server>_<tool>` → `mcp__<server>_<tool>` |

What is the same as Claude Code: the policy gate runs before the tool (deny blocks; ask blocks the call until someone
approves it from another terminal, then the agent's retry runs: [held calls](#held-calls-approve-then-retry)), events
are signed by the same signer, and the harness's transcript is hashed at every hook when the harness passes
`transcript_path`, so edits and truncation are detected.

What is different: reasoning capture reads Claude Code's transcript format and is off for these harnesses; the model
proxy fronts the Anthropic API only, so model-side cross-checks need `tracekit_sdk.init()` or OpenTelemetry instead.
Hook formats come from each harness's published documentation (October 2026); a harness that changes its payload may
need an update here. Qwen Code's are from its [hooks documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/):
it sends Claude Code's payloads and event names (with `tool_use_id`), reads exit 2 as a block, takes hook timeouts in
milliseconds (versions since September 2026 in seconds, but 1000 or more still as milliseconds; 60 s unless set; `init` writes 600000, 600 s
either way, for `PreToolUse`, so a person has time to approve a held call), and
runs a project's hooks only in a trusted folder. On Windows it runs a hook under cmd.exe or Git Bash, by how it was
started, unless the hook names its `"shell"`: `init` writes `"shell": "powershell"` and the command in PowerShell's
form, as for Codex and Gemini CLI, ending in `; exit $LASTEXITCODE` so that a block's exit 2 gets through PowerShell
(a `PreToolUse` hook whose Python didn't run or failed exits 2, so the call is blocked).

A call on several files (a patch's `paths`, the files of a Gemini CLI or Qwen Code `read_many_files`) or URLs (a
`web_fetch`'s `urls`) is decided on each: a rule that matches any of them applies.

Droid's [hooks reference](https://docs.factory.com/harness/hooks) documents Claude Code's event names and stdin fields.
Its standalone `hooks.json` is keyed directly by event name, with no `hooks` wrapper (that wrapper is for declarations
inside `settings.json`). When creating it, the installer copies the effective hooks from `settings.json`, since Droid
reads those only while `hooks.json` is absent. `tracekit uninstall --agent droid` deletes `hooks.json` again when what is
left in it is that copy. Otherwise (you changed the hooks in either file, or `settings.json` is gone or can't be read) it
takes Tracekit's hooks out, keeps `hooks.json` and names it. If the legacy
`.factory/hooks/hooks.json` exists, init refuses to proceed until you save once in Droid's `/hooks` UI to migrate it.
On Windows Droid
is assumed to run hooks under `cmd.exe`; the interpreter path stays quoted when it contains spaces.
The documented stdin carries no tool-call id. Tracekit pairs its tool events by tool and arguments, first in first out, in a queue separate
from Gemini CLI's. An allowed call with no `PostToolUse` (declined in Droid's permission prompt, blocked by another hook, or failed; Droid has no `PostToolUseFailure`) stays queued, so the next identical call's result can be paired to it and the call that ran closes as an error at session end. The pre-tool timeout is 600 seconds so a person can answer a held call. Factory CLI 0.249.0's
`droid exec --list-tools --output-format json` describes `Execute` as a shell command and `ApplyPatch` as a complete
patch in `input`; that field and format come from the tool listing, not a captured hook payload. The minimum Droid version is unknown, and it is unknown whether `Task`-started sub-droids fire hooks. Native Windows and live authenticated Droid sessions are untested; its transcript format is
not read for model text or reasoning.

With a v1 hook, an unparseable payload or an unknown harness name is reported on stderr and the call is allowed, unless
`TRACEKIT_FAIL_CLOSED=1` or the policy says `fail_mode: closed`. Four exceptions block the call whatever the fail mode:
an OpenCode call its hook can't decide (the plugin passes the model's arguments before OpenCode checks them), an
Antigravity CLI pre-tool call its hook can't decide (its command names the event), a Cline pre-tool call its hook can't
decide (its command names the event), and, in every hook, a payload nested too deep to read.

## On the v2 signer

The v2 hooks (the commands at the top of this page) run `python -I -m tracekit.integrations.harness_hooks <agent> <event>`: the same mapping as above, then the
v2 Claude Code hook's core (the signer decides; approvals; the run's fail mode, closed by default and always closed in
system mode). Unlike v1, a payload without a session or tool call id blocks the call, and so does any hook error.
On any other event (a prompt, a tool result, a session event) a hook that fails exits 1, not 2, which
would block a prompt, and the event isn't recorded.

OpenCode (1.x) sends no session or prompt events to plugins: its run closes at the signer's idle timeout, and no prompts, live constraints or model text are recorded. A call that fails, that you decline in OpenCode's own permission prompt, or that you abort runs no `tool.execute.after`, so it stays a `decided_not_completed` gap. With `TRACEKIT_APPROVAL_WAIT` set, while a call waits for a person OpenCode waits too: list the held call with `tracekit approvals list` ([limits](limits.md#signer-and-capture)).

goose support is experimental: tested through goose's hook payloads and Tracekit's installer, not yet in a live goose
session. It needs goose 1.48.0 or later (when `on_failure` arrived). goose runs hooks with `sh -c` on every platform,
so on Windows it needs `sh` on PATH (Git Bash); without it every call is blocked. Code Mode (`execute_javascript`,
and `execute_typescript` or `execute_bash` before goose 1.56) is denied: it runs tool calls no goose hook sees.

goose's installed hooks likewise carry no session or prompt events (only PreToolUse, PostToolUse and PostToolUseFailure are installed), so no prompts, live constraints or model text are recorded for goose, and goose sends no tool result or error text with its post-tool events ([limits](limits.md#signer-and-capture)).

A session is one run, open until the session ends. To watch it, `tracekit view --dev` (each call with what it ran);
to verify it as it stands, `tracekit last --open`.

### Held calls: approve, then retry

A call the policy holds (`ask`) is blocked at once, in Claude Code and every harness above, with the approval's id, why,
what to do instead, the commands that answer it and what the agent does, as the harness's block message (in Claude
Code also a `systemMessage`, which it shows you, and the deny reason, which the model reads):

```text
[tracekit] HELD, nothing ran: apr-… (TK-A032), expires 09:27 UTC.
Why: uploading to cloud storage
Instead: Have a person approve the held call, or write the files locally and let a person upload them.
Person: look with `! tracekit approvals show apr-…`; allow once with `! tracekit approvals approve apr-…`; refuse with `! tracekit approvals reject apr-…`.
Agent: ask the person: approve or skip? Don't reword around the hold, but do take an Instead step that's yours and say so; otherwise wait for their answer. Pass on the Person line and say what the call was for; a subagent puts both in its final report. Once it is approved, make the identical call again. Never hide what a call runs to get past the policy: every call is signed and kept.
```

A call the policy denies says so, in the same form, with no commands: no one can approve it.

```text
[tracekit] BLOCKED, nothing ran, and no one can approve it (TK-D005, TK-F005).
Why: writing to a credentials file
Instead: Write a template with placeholders (.env.example) instead; a person fills in the real credentials file.
Agent: tell the person what you were doing and why it was blocked. If the Instead line is a step you can take yourself, you may take it and say so. Never hide what a call runs to get past the policy: every call is signed and kept.
```

`tracekit approvals show apr-…` prints why and what to do instead, when it expires, the commands that answer it, and
the command that opens the call in the viewer, `tracekit view --approval apr-…` (the page opens at `#approval=apr-…`).
`tracekit approvals list` lists the calls waiting for an answer first, newest first, each with what it runs; the
expired ones only with `--all`.


In Claude Code, paste the `! …` line into the same session: `!` runs it as you, the session's user, not as
the agent.

In Gemini CLI, paste the `!command` line into the same session, with no space after `!`: Gemini runs it
directly as you, the session's user, not as the agent. Alternatively, press `!` to enter shell mode and
enter the command without the prefix.

In another harness, or from another terminal, run the same command without the `!` (a shell reads a
leading `!` as "not", and an approval that worked would report failure). With a named signer (system
mode, a remote one) the line has no `!`: the session's user is the agent's, whom the signer refuses as an
approver, so the approver runs it from their own account. Then tell the agent to make the same call
again, unchanged: the signer lets that call run under your approval, once
([approve, then retry](approvals.md#approve-then-retry)).

The same call a third time, or one with other arguments, is held again, with a new approval. A call you rejected is
held again if the agent tries it again, and the block says so first among its reasons (`Why: a person rejected this
exact call (apr-…, by uid:501); ask them before trying again; …`), so the agent asks you. In Claude Code a Bash
call's arguments include its free-text `description`, which the model rewords on a retry: a retry of a call you
approved that differs only there runs under your approval, recorded with the approved arguments, description included,
unless another wording of it was rejected ([approve, then retry](approvals.md#approve-then-retry)); one that differs
in any other key is held again.
The agent can't approve its own call: the policy denies the command when the agent runs it (`TK-D012`), and in system
mode the signer refuses its user.

Until 1.5.1 the hook waited 8 minutes for an answer before it blocked the call. No harness shows a hook's output
while the hook runs, so you saw the approval id only once the wait was over, and the call was blocked anyway. Where
someone answers without seeing that message (Slack approvals, the viewer's approval pages, an agent approver, or you
watching `tracekit approvals list`), set `TRACEKIT_APPROVAL_WAIT` (seconds) in the agent's environment, and the hook
waits that long for the answer before it blocks the call, up to about 480 s: it answers within 540 s and keeps two
signer calls' time (60 s) for the answer and the approval's use, so a longer setting waits no longer. Export it before
you start the agent (a hook inherits the harness's environment), or in Claude Code put it in `settings.json`:
`"env": {"TRACEKIT_APPROVAL_WAIT": "480"}`. The hook can't tell whether a bridge or an agent approver will answer, so
this is your setting. What each harness shows while a hook runs, from its documentation or source (October 2026), and
so why none waits by default:

| Harness | While the hook runs | The block's message, once it returns |
|---|---|---|
| Claude Code | a spinner; the hook's output is read when it exits | the deny reason to the model, the `systemMessage` to you |
| Codex CLI | "Running hook" (stderr is read when the hook exits) | to the model, and a "Blocked" cell to you |
| Cursor | not documented (closed source; a Hooks output channel for debugging) | `user_message` to you, `agent_message` to the model |
| Gemini CLI | "Executing Hook: <name>" (stderr is collected and read on exit) | "Tool execution blocked: …" to both |
| Qwen Code | a fixed `statusMessage`, if configured (stderr is read on exit) | to the model, and shown to you |
| OpenCode 1.x | nothing (the plugin reads stderr once the hook exits, and kills one still running at 600 s) | the error the plugin throws |
| goose | nothing (stdout and stderr are read on exit) | to the model |
| Factory Droid | not documented | to Droid (the model) |
| Devin | not documented | not documented |
| OpenHands | nothing (the hook runs before the call; stdout and stderr are read on exit) | the reason to the model |
| Copilot CLI | not documented | "Denied by preToolUse hook:" and the reason, to you and the model |
| CodeBuddy Code | not known (stdout and stderr are read once the hook exits) | to the model, as `PreToolUse:<tool> hook blocked this tool call: <reason>` |
| Antigravity CLI | not known to show anything ([#893](https://github.com/google-antigravity/antigravity-cli/issues/893)) | the `reason` of its JSON deny |

### When Tracekit stops a call

The block message tells the agent what to do, but an agent reads its own instructions first. `tracekit init --v2`
points to these lines; paste them into the agent's `CLAUDE.md` or `AGENTS.md`. The Claude Code plugin ships them as
its `tracekit-holds` skill.

```markdown
## When Tracekit stops a tool call

- `[tracekit] HELD, nothing ran`: a person must answer it. In one message, tell them what the call was for, its Why
  line and the commands on its Person line, then wait. A subagent or a background job puts the same in its final
  report.
- Once the person says it is approved, make exactly the same call again (the same tool and arguments): it runs once.
- `[tracekit] BLOCKED, nothing ran` or `NOT APPROVED`: tell the person what you were doing and why it was stopped. If
  there is an Instead line, you may do that instead; say you did.
- Never run `tracekit approvals approve` or `reject` yourself: they are the person's commands. `tracekit approvals
  list` and `show` only read.
- Never hide what a call runs to get past a hold or a block (encoding it, a variable for the program, a script file,
  another tool or agent): every call is signed and kept. A readable call that does the same thing, as an Instead line
  says, is fine; say you made it.
```

### Calls that move money

Stripe holds an agent's refunds, payouts and outbound payments for a person only when the agent uses an agent-tagged
API key ([approval rules](https://docs.stripe.com/account/approvals)); a coding agent with your own key gets no hold.
The v2 coding pack holds these calls for a person whatever the key:

- the Stripe CLI's money commands: `stripe refunds create`, `payouts create`, `transfers create`, `topups create`,
  `transfer_reversals create`, `charges create` or `capture`, `payment_intents create`, `confirm` or `capture`, `invoices pay`, `treasury
  outbound_payments create` or `outbound_transfers create`, and `stripe post` to those endpoints (`TK-A043`);
- a POST to those endpoints on `api.stripe.com`, to PayPal's payouts, captures and refunds on `api-m.paypal.com` or
  `api.paypal.com`, or to Square's payments and refunds on `connect.squareup.com`, through `curl`, `wget`, HTTPie or
  `xh` (`TK-A043`);
- Stripe's MCP money tools, `send_money`, `transfer_money`, `convert_currency` and `create_refund` (`TK-A044`), and its
  `stripe_api_write` tool when the call names a refund or one of those endpoints (`TK-A045`).

The hold says what to check:

```text
[tracekit] HELD, nothing ran: apr-… (TK-A043), expires 09:27 UTC.
Why: moving money (a Stripe, PayPal or Square charge, payout, transfer or refund)
Instead: Check the amount, currency and payee in the command or the file it sends before approving it; a refund with no amount refunds in full, and a confirm, capture or pay moves the amount set earlier.
Person: look with `! tracekit approvals show apr-…`; allow once with `! tracekit approvals approve apr-…`; refuse with `! tracekit approvals reject apr-…`.
Agent: …
```

Read the command before you approve it, and the file it sends (`-d @body.json`): the approval covers that exact
command, so its amount and payee can't change afterwards, but a file's content can. A call with no amount moves what was set earlier: a refund with no amount refunds the whole charge, and a
confirm, capture or invoice pay takes the amount the payment intent or invoice was created with, so look that up
first. A Stripe test-mode call is held too: the command doesn't show whether the key is live. Not held: `stripe
listen`, `stripe trigger`, `stripe logs tail`, `stripe login`, listing, retrieving and cancelling, `stripe refunds
create --help`, a GET (Stripe's documented `curl -G … -d limit=3` list form too), and PayPal's and Square's sandbox
hosts.

Turn on Stripe's approval rules with an agent-tagged key as well: Stripe enforces them on its side, outside anything
the agent runs, and Tracekit adds a signed record of who approved which exact call, for PayPal and Square too. What
these rules don't see (a script that calls a payment SDK, another provider): [limits](limits.md#policy).

### What was asked and said

For Claude Code, the transcript tailer records every line the model writes (thinking, text, tool use) and every prompt
as a model exchange: a commitment to the whole line, and the line itself when the signer keeps content (the dev signer
does). `tracekit init --v2` also sets `"showThinkingSummaries": true` in the Claude Code settings it writes the hooks
to, or with the plugin enabled in the user's settings (unless they set it; `--no-thinking-summaries` leaves it alone;
`tracekit uninstall` removes it again while it's still `true`): without it Claude Code keeps the model's thinking
only sealed. For headless runs pass `claude -p --thinking-display summarized`. `tracekit analyze --v2`
([findings](findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)) and `tracekit view --dev` read
them. **Codex, Gemini CLI and Cursor:** each v2 hook first records what the model said since the session's last hook:
Codex's reasoning summaries (and the sealed `encrypted_content`), messages and tool calls from its rollout file, linked
to the calls by `call_id`; Gemini CLI's thought summaries and text from its chat recording; Cursor's thinking and
response text from its `afterAgentThought` and `afterAgentResponse` hooks (init installs them). Gemini CLI and Cursor
give a call no id, so their text is not linked to a call, and Gemini CLI writes its thoughts after the calls ran.
`tracekit init --v2 --agent codex` also sets `model_reasoning_summary = "auto"` as the first line of Codex's
`config.toml` (unless it sets one; `--no-thinking-summaries` leaves it alone; `tracekit uninstall --agent codex` removes
the line while it's unchanged): Codex's current models default to `none`, which keeps the
reasoning sealed. Per agent, what is readable and how to turn it on: [reasoning](reasoning.md). A session's later run
(after the signer closed an idle one, or a resumed session) records from where the earlier run left off, not from the
transcript's start: the hook notes how far the transcript was written while that run was open
([limits](limits.md#signer-and-capture)).

At each prompt (`UserPromptSubmit`; Cursor's `beforeSubmitPrompt`, Gemini CLI's `BeforeAgent`) the hook also records
what the person typed (`input.observed`, trusted, source `<agent>:UserPromptSubmit`: `claude-code`, `codex`, `cursor`,
`gemini-cli`, `qwen-code`, `droid`, `devin`, `openhands` or `codebuddy-code`; its text in the content vault). Text the harness added to the prompt is recorded apart, as untrusted
input under its own source, so a value in it keeps its provenance: in Claude Code a paste block, a skill's body, a
message from another session, agent, teammate, plugin, observer or channel, a task or system notification, a scheduled
task, uploads and command output (`claude-code:paste`, `claude-code:task-notification`, ...); in Gemini CLI its referenced files block
(`gemini-cli:referenced-file`). A whole Claude Code turn its payload says no person typed (a `source` other than `user`
or `sdk`: a plugin's prompt, a notice, a wake-up or a poll event) is recorded that way too (`claude-code:poll_event`,
...), and none of its constraints are live. `tracekit analyze --v2` takes a prompt line of the transcript as the person's only when
the hook recorded the same typed text: a line the agent appended to its own transcript is flagged (TK-X208) and clears nothing. A
paste or an image Claude Code writes as a placeholder (`[Pasted text #1 +40 lines]`) pairs with the hook's prompt that
holds the rest of the line, whose full text is read; a hook prompt with no line (one the tailer missed) is read on its
own. Hooks before this release record no prompt, and TK-X208 says `no_hook`.

The hook also sends what the typed text says not to do ("don't touch billing.py", "read-only", "don't push", "no
network") to the signer as [live constraints](policy-v2.md#live-constraints) (one stated only in text you pasted or the
harness added is recorded but not made live, and Claude Code shows a notice naming it; one typed after a wrapper's name
in a sentence is live, though the text from that name on is recorded as untrusted): a later call that breaks one is
held for your approval ([held calls](#held-calls-approve-then-retry)), and you and the agent read why:

```text
[tracekit] HELD, nothing ran: apr-… (TK-CONSTRAINT), expires 09:27 UTC.
Why: the person's request in this run said not to modify "billing.py"; ask the person
Person: look with `! tracekit approvals show apr-…`; allow once with `! tracekit approvals approve apr-…`; refuse with `! tracekit approvals reject apr-…`.
Agent: …
```

Answer it with the command the line names: in Claude Code, its `! …` form in the session; elsewhere, from another
terminal without the `!`, which a shell would read as "not" (`tracekit approvals list` shows every held call). Then
ask the agent to make the call again; the agent's own `approve` or `reject` is denied (`TK-D012`). When the hook's signer is a named one (system mode,
`tracekit init --remote --v2` or `TRACEKIT_SIGNER`), the command includes `--signer ADDR`. In system mode, run it from
the approver's account as `/opt/tracekit/bin/python -I -m tracekit approvals …` (init puts no `tracekit` command on the
PATH). On your default signer,
`tracekit approve apr-…` and `tracekit reject apr-…` work too. `tracekit view --dev` lists
the run's constraints at the top of its review. The grammar reads instructions, not descriptions: "add a read-only mode
to client.py", "don't change the public API of client.py, just fix the timeout bug in it", "don't push to main" and
"we don't use the network in unit tests" hold nothing. If a run already has the most file constraints the signer
takes (32: an agent can add its own), a further one is refused, the hook says so at that prompt, and every write of the
run waits for your approval from then on. A scope ("only change src/pager.py") is never held: `tracekit analyze --v2`
checks it after the run (TK-X204).

### Hooks name their event

`tracekit init` writes each hook command with the event it's configured for as its last argument (the Claude Code
hook: `... -m tracekit.integrations.claude_code PreToolUse`; Codex `PreToolUse`, Cursor `preToolUse`, Gemini CLI
`BeforeTool`, goose `PreToolUse`, and so on for every event). So a payload that can't be parsed at all is still known to be a pre-tool
event: the call is blocked, with the reason on stderr. On any other event it is reported on stderr and not recorded;
an allowed call whose post-tool payload was lost is completed as an error at the session's next Stop, prompt or end
(below).

Hooks installed before 1.2 have no event argument and keep working as before: an unparseable payload passes,
unrecorded. `tracekit doctor` warns `D-HOOKS-EVENT` for Claude Code, Codex, Cursor, Gemini CLI, goose, Qwen Code,
Factory Droid and Antigravity CLI when a command doesn't name its configured event or, on any event but the pre-tool
one, blocks that event when the hook can't run (a command init wrote before 1.3, or a Cursor hook written up to 1.4.2), and
`D-HOOKS-TIMEOUT` when a pre-tool timeout is shorter than the 540 s the hook may take to answer (milliseconds for
Gemini CLI and Qwen Code; a held call waits, up to about 480 s, only with `TRACEKIT_APPROVAL_WAIT` set). Re-run init for the active mode to repair the other coding agents' hooks
(`tracekit init --dev --v2 --agent NAME` in dev, or `sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT
--agent NAME` in system mode). `tracekit doctor` also checks Droid's and Antigravity CLI's hook presence and timeout, and warns when agy would
load its hooks and run none (`D-AGY-HOOKS-RUN`, [below](#antigravity-cli)). OpenCode's JavaScript plugin isn't checked; re-run init after upgrading.

For the other coding agents (Antigravity CLI too, not OpenCode, whose plugin doctor doesn't read), `D-HOOKS-EVENT` also warns when a call can run that no hook
decided: no Tracekit v2 hook is on the pre-tool event, Cursor's `preToolUse` hook has no `failClosed: true`, or goose's
`PreToolUse` hook has no `on_failure: "block"`. Without those two, Cursor and goose let a call through when its hook
can't run. Re-run init to put them back.

### What the signer records as a gap

Without anything else installed, the signer turns what it saw and then never heard about into signed gaps
([format](format-v2.md#3-events), [limits](limits.md#signer-and-capture)):

- a call the policy allowed, or whose approval was consumed, and that never completed (`decided_not_completed`, at the
  end of the run). A call you decline in the harness's own permission prompt runs no post-call hook, nor does one you
  interrupt: the hook completes such calls as errors ("no PostToolUse came") when the session ends, so they get no
  gap (a session that never ends, such as a killed harness, leaves them as gaps);
- with harness binding (Linux system mode), a second run started from inside the same harness process while another
  session's run is open there, once both have recorded events since (`concurrent_run`; an older session left open and
  idle gets none). Two harness windows side by side are separate processes and get none. A sub-agent's run started
  with `parent` from a bound harness process is a `run.child` record in its parent;
- in system mode, a transcript tailer that stops calling the signer while the run is open, killed, crashed or never
  started, from the moment the hook took its token (`tailer_lost`), and a second tailer token for the same run
  (`tailer_redelegated`); in dev mode, a tailer the run's next hook event finds stopped without a word (`tailer_lost`):
  the hook then starts a new one where the stopped one got, so the lines written meanwhile are recorded late, not lost
  (at most 10 times a run, [limits](limits.md));
- writes after the run ended (`late_activity`, in a run-set), apart from each client's first one, from which it learns
  that the run ended (an idle close) and moves to a new run. A hook moves to a new run too when the signer was reset
  (its data dir or run token key made anew) and refuses the session's run token: the earlier run, if the store still
  holds it, is left for the signer's idle close, its tail unproven.

The LLM gateway's verified tool results (signer.yaml `verify_tool_results`) can't be used with the Claude Code hooks: they record a digest of each tool's raw output, not what the model is sent, so every result would mismatch ([gateway](gateway.md#verified-tool-results)).

### Weights files a call wrote

When a Write, Edit, MultiEdit, NotebookEdit or Bash call that succeeds (the names every harness's hook gives its
write and shell tools) writes a model weights file (`.safetensors`, `.gguf`, `.pt`, `.pth`, `.ckpt`), the hook (Claude
Code's and each harness's above) hashes it after the call and puts the receipt in the call's result, next to the
result's digest: the file's sha256 and size and, for `.safetensors`, a sha256 of each tensor (its dtype and shape, then
its bytes) and one of the header's metadata. A call writes what the policy reads it writing: a write tool's path, or a
Bash command's write targets (a redirection, a `cp` or `mv` destination, ...). A path the hook would have to guess is
refused: one starting with `~`; every path of a command line in which `cp`, `mv`, `install` or `ln` has `-t` (in a
cluster too, `-vt`), `git`, `env`, `make` or `tar` has `-C`, `sudo` has `-D`, or one of them has `--target-directory`,
`--directory` or `--chdir` or a prefix of one that GNU accepts (`env --ch=sub`); every path of a command line that runs
`ssh`, `chroot`, `nsenter`, `unshare` or `firejail`; every path of a call whose write may land after the hook reads (a
Bash call `run_in_background` or with a lone `&`, input typed into another session, Qwen Code's `monitor`,
`systemd-run`, `setsid -f`, `at`); and a relative one in a command that changes directory (`cd`, `pushd`, `popd`, `git
--work-tree`, or a shell call's own working directory: `dir_path`, `directory`, `working_directory`, `workdir`, agy's
`Cwd`, Crush's `working_dir`). The hook hashes for at most 10 seconds per call; a receipt it can't finish, or any it
can't read, is recorded with its
reason, and the call's result is recorded either way.

The hook runs as the agent's user, so each receipt (`reported_by: hook`) is the agent side's record, not something the
signer saw. The `model_receipts` key is the hook's on those five tools' results: it removes one it didn't set. Every
other tool's result is recorded as the tool returned it, and `verify-model` counts a receipt only in the result of one
of the five tools whose recorded arguments name a file the hook hashes, so a receipt in an MCP or web tool's output is
never counted.

The signer commits to the result as to any other, so a bundle holds only that commitment. `tracekit verify-model`
verifies the bundle, reads the run's results back from the signer's content vault (the dev signer keeps them for 7
days), checks each against its record's commitment, then compares two files with the receipt:

```
$ tracekit verify-model before.safetensors model.safetensors --bundle $RUN.tkb --run $RUN --trust $RUN.trust.json
bundle: verified, run tk-0f3a...
receipt: /work/model.safetensors, hashed after tool call toolu_01 (run_seq 7, ok: true), recorded by the agent-side hook
NEW model.safetensors: matches the recorded receipt (sha256:5c1e...)
OLD -> NEW: the file differs; 1 of 3 tensors differ (dtype, shape or bytes); the metadata is the same
  changed: model.layers.0.mlp.down_proj.weight
```

It exits 0 only when the bundle verifies and NEW matches the recorded receipt, and 2 when the bundle doesn't verify. A
signer it can't reach, content the signer didn't keep, or an identity without the `content_read` grant is said as such
(exit 1); content that doesn't open its record's commitment is an evidence alert (exit 4). The receipt reaches the
signer in clear: its vault holds the file's path, hashes and tensor names
([limits](limits.md#model-receipts-tracekit-verify-model)).

## Antigravity CLI

Antigravity CLI (`agy`) support is experimental: tested through agy's documented hook payloads
([hooks reference](https://antigravity.google/docs/hooks)) and Tracekit's installer, not yet in a live agy session
([limits](limits.md#signer-and-capture)). It needs agy 1.3.0 or later (1.2.1 to 1.2.3 ran no hooks on some machines,
[#1008](https://github.com/google-antigravity/antigravity-cli/issues/1008)).

```bash
tracekit init --dev --v2 --agent antigravity               # ~/.gemini/config/hooks.json; --project: .agents/hooks.json
sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT --agent antigravity   # system mode
tracekit uninstall --agent antigravity                     # removes Tracekit's hook only
```

agy's `hooks.json` maps each hook's name to its events. Init adds one named `tracekit`, with a `PreToolUse` hook
(timeout 600 s, so a person has time to approve a held call) and a `PostToolUse` hook (30 s), both with matcher `*`.
Other named hooks in the file are kept, and a backup is written first. Init rewrites Tracekit's hook whole, so an
`"enabled": false` left on it is removed. The v1 hook (`tracekit init --dev --agent antigravity`) works in dev mode
only: v1 system mode installs Claude Code's hooks only, so it refuses `--agent antigravity`. agy runs a hook in the
folder that holds its `hooks.json`; the hook reads the workspace from the payload's `workspacePaths`. The global
`hooks.json` also runs in the Antigravity IDE app
([#1329](https://github.com/google-antigravity/antigravity-cli/issues/1329)), whose calls are then decided and recorded
too, as agent `antigravity`. While a call waits for a person, agy waits too and may show nothing: list the held call
with `tracekit approvals list`.

agy's payload doesn't name its event, so each hook command names it, the v1 one too. agy reads a hook's answer only
from JSON on stdout at exit 0, so Tracekit's hook always exits 0: `{"decision": "allow"}` leaves the call to agy's own
permissions, `{"decision": "deny", "reason": ...}` blocks it, and the post-tool hook answers `{}`. A hook that can't
start (its Python or Tracekit is gone) gives the same answers through a shell wrapper: the pre-tool hook denies the
call, and the post-tool hook answers `{}` (before agy 1.4.7, a post-tool hook that failed replaced the call's result
with an error). On Windows, dev mode has no such wrapper ([limits](limits.md#signer-and-capture)).

**What is recorded.** A conversation (`conversationId`) is one run. Each tool call is decided on the argument the tool
itself reads, so a decoy key the model sends beside it never moves the decision. agy is a Go program, whose decoder may
fill an argument from a key in another case (`commandline` for `CommandLine`), and takes the last of keys that match
ignoring case: the hook denies a call that sends any argument twice (in the same case or not), one of the arguments
below in another case, or any key outside ASCII. An argument sent once as null counts as absent, for Tracekit as for a
Go decoder:

| agy tool | Decided as | On |
|---|---|---|
| `run_command` | `Bash` | `CommandLine`; `BypassSandbox` (run outside agy's terminal sandbox) as `dangerouslyDisableSandbox`, which the v2 coding pack holds for a person (`TK-A003`) |
| `manage_task` with `Action: send_input` | `Bash` | `Input`, the text typed into a background command |
| `view_file` | `Read` | `AbsolutePath` |
| `write_to_file` | `Write` | `TargetFile` |
| `replace_file_content`, `multi_replace_file_content` | `Edit` | `TargetFile` |
| `list_dir` | `LS` | `DirectoryPath` |
| `find_by_name` | `Glob` | `SearchDirectory`, `Pattern` |
| `grep_search` | `Grep` | `SearchPath`, `Query` |
| `read_url_content` | `WebFetch` | `Url` |
| `search_web`, `invoke_subagent` | `WebSearch`, `Task` | their arguments as sent |

Any other tool passes under its own name, which the policy treats as an unknown tool. agy gives a call no id: Tracekit
pairs a call's `PreToolUse` and `PostToolUse` by the step index (`stepIdx`), tool and arguments agy sends with both.
On the v2 signer, a pre-tool payload with no `conversationId` or `stepIdx` is blocked. A result that matches no call
exactly stays unpaired, and its call is left a `decided_not_completed` gap, never guessed. agy sends a failed call's
error text with `PostToolUse`, which records the call as failed, but not a call's output. Tracekit installs only agy's
tool hooks and doesn't read its transcript, so no prompts, live constraints or model text are recorded, and the run
closes at the signer's idle timeout.

**Doctor.** `tracekit doctor` finds agy's hooks in the user's and the working directory's `hooks.json` and checks them
as the other agents' (`D-HOOKS-PRESENT`, `D-HOOKS-EVENT`, `D-HOOKS-TIMEOUT` in seconds; a hook with no timeout
counts as agy's default, 30 s). It also warns
`D-AGY-HOOKS-RUN` when agy would load the hooks and never run them: Tracekit's hook is `"enabled": false` (in the file
init wrote, the user's `hooks.json` or the workspace's), or agy signs in with a Gemini API key (`"modelProvider":
"gemini"` in `~/.gemini/antigravity-cli/settings.json`) or with Application Default Credentials (`"enableAdc": true`
under `userSettings` in `~/.gemini/config/config.json`, or `AGY_ADC_AUTH=true`). agy says nothing when it skips the
hooks. Doctor reads `AGY_ADC_AUTH` and the workspace from the shell it runs in, so run it from agy's shell
([doctor](doctor.md#v2-checks)).
