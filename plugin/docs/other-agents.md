# Tracekit in other coding agents

These agents have no Tracekit plugin. Tracekit hooks them with `tracekit init --agent <name>`, and the skills come
from the skills CLI.

1. Add the skills, and pick your agent when it asks:

   ```bash
   npx skills add Cygnux-Labs/tracekit-skills
   ```

2. Ask your agent: "Set up Tracekit." It shows you the past week first, then, after your yes, installs Tracekit and
   runs `tracekit init --dev --v2 --agent <name>`. Or do it yourself:

   ```bash
   uv tool install tracekit-ai                # or: pip install tracekit-ai
   tracekit audit --since 7d                  # read-only: what Tracekit would have held or blocked last week
   tracekit init --dev --v2 --agent <name>
   tracekit doctor
   ```

3. Start a new session: the hooks apply from then on. To undo, `tracekit uninstall --agent <name>` removes them; your
   signed runs and keys stay.

| Agent | `--agent` | Where init writes the hooks |
|---|---|---|
| Gemini CLI | `gemini` | `~/.gemini/settings.json` |
| OpenCode | `opencode` | a plugin file, `~/.config/opencode/plugin/tracekit.js` |
| Kilo Code | `kilo` | a plugin file, `~/.config/kilo/plugin/tracekit.js` |
| goose (1.48 or later) | `goose` | a goose plugin, `~/.agents/plugins/tracekit/` |
| Qwen Code | `qwen` | `~/.qwen/settings.json` |
| Factory Droid | `droid` | `~/.factory/hooks.json` |
| Antigravity CLI | `antigravity` | `~/.gemini/config/hooks.json` |
| Crush | `crush` | `~/.config/crush/crush.json` |
| Cline (CLI and VS Code) | `cline` | `~/Documents/Cline/Hooks/` |

`--project` writes a project's file instead. When Tracekit holds a call, you approve it from your own terminal with the
command it prints; in Gemini CLI you can type it in the session as `!tracekit approvals approve <id>`.

Each agent's details and limits: [coding agents](https://github.com/Cygnux-Labs/Tracekit/wiki/Coding-Agents).
