#!/usr/bin/env bash
# Clean-machine run of one v2 example: a fresh venv and HOME, tracekit-ai[signer] from this checkout plus the example's
# framework, then the example in scripted mode, timed.
#   examples/v2/clean-machine.sh [custom|langchain|openai_agents|claude_agent_sdk|mcp]   (default: custom)
set -euo pipefail
example=${1:-custom}
case $example in
  custom) extra=() ;;
  langchain) extra=("langchain>=1.4,<1.5" "langgraph>=1.2,<1.3") ;;
  openai_agents) extra=("openai-agents>=0.23.1,<0.24") ;;
  claude_agent_sdk) extra=("claude-agent-sdk>=0.2.165,<0.3") ;;
  mcp) extra=("mcp>=2.3,<2.4") ;;
  *) echo "unknown example: $example" >&2; exit 2 ;;
esac
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/tk-clean.XXXXXX)   # short: macOS caps socket paths
trap '"$work/venv/bin/tracekit" down >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
export HOME="$work/home" XDG_DATA_HOME="$work/home/data" TRACEKIT_RUNTIME_DIR="$work/run"
unset TRACEKIT_SIGNER PYTHONPATH
start=$SECONDS
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q "$root[signer]" ${extra[@]+"${extra[@]}"}
cd "$work"
"$work/venv/bin/python" "$root/examples/v2/$example/agent.py" --scripted
echo "clean-machine $example: $((SECONDS - start)) s"
