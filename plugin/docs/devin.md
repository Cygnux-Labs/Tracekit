# Tracekit in Devin

Devin loads this plugin's skills. Tracekit's hooks come from `tracekit init`, which writes them into Devin's own
config.

1. Add the plugin. In the Devin CLI:

   ```bash
   devin plugins install Cygnux-Labs/tracekit-claude-plugin
   ```

   In the Devin app: Customize → Plugins → Add plugin → From repository, then `Cygnux-Labs/tracekit-claude-plugin`.
   Devin reads the plugin's Claude Code manifest (`.claude-plugin/plugin.json`) and its skills.

2. Ask Devin: "Set up Tracekit." It shows you the past week first, then, after your yes, installs Tracekit and runs
   `tracekit init --dev --v2 --agent devin`. Or do it yourself:

   ```bash
   uv tool install tracekit-ai
   tracekit init --dev --v2 --agent devin    # ~/.config/devin/config.json; --project: .devin/hooks.v1.json
   tracekit doctor
   ```

   Devin also runs Claude Code's hooks by default (`read_config_from.claude`). Init turns that off, so a Tracekit hook
   for Claude Code doesn't decide each Devin call a second time. Devin then stops reading Claude Code's rules, skills,
   commands and MCP servers too; init says so, and leaves the setting as it is on uninstall.

3. To undo: `tracekit uninstall --agent devin`.

Tracekit records where it is installed: the Devin CLI and Devin Desktop on your machine. A cloud Devin session runs
on Devin's machines, where these hooks aren't.

Untested: installing this plugin in Devin. Devin documents the `.claude-plugin` fallback and plugin skills; nobody on
the Tracekit team has run it yet. If you use Devin, a report of what you saw helps:
[issues](https://github.com/Cygnux-Labs/Tracekit/issues).
