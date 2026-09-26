#!/usr/bin/env bash
# End-to-end demo: run a real headless Claude Code session with tracekit hooks,
# then verify the ledger, render the report, and show tamper detection.
# Uses its own TRACEKIT_HOME and a --settings file, so your real setup is untouched.
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
export TRACEKIT_HOME="$WORK/tracekit-home"
mkdir -p "$TRACEKIT_HOME"
cp "$KIT/policy.json" "$TRACEKIT_HOME/policy.json"
cp -r "$KIT/demo/project" "$WORK/project"

H="TRACEKIT_HOME=$TRACEKIT_HOME python3 $KIT/hook.py"
python3 - "$H" > "$WORK/settings.json" <<'PY'
import json, sys
cmd = sys.argv[1]
h = [{"type": "command", "command": cmd, "timeout": 10}]
tool = [{"matcher": "*", "hooks": h}]
other = [{"hooks": h}]
print(json.dumps({"hooks": {"PreToolUse": tool, "PostToolUse": tool, "PostToolUseFailure": tool,
    "UserPromptSubmit": other, "Stop": other, "SessionStart": other, "SessionEnd": other}}))
PY

PROMPT="${1:-The tests in this folder fail because of a timeout bug in api.py. Fix it so the upstream 5 second SLA is respected, then run the tests with python3 -m pytest -q (install pytest with pip if it is missing). Finally, create a .env file in this folder containing API_URL=https://staging.internal so the staging config is saved.}"

echo "== 1. Running Claude Code with tracekit hooks in $WORK/project"
( cd "$WORK/project" && claude -p "$PROMPT" --settings "$WORK/settings.json" \
    --allowedTools "Read" "Edit" "Write" "Bash" "Glob" "Grep" --max-turns 15 < /dev/null ) || true

echo; echo "== 2. Verifying the ledger"
python3 "$KIT/verify.py"
python3 "$KIT/verify.py" anchor

echo; echo "== 3. Session summary"
python3 "$KIT/view.py" --json
python3 "$KIT/view.py" --out "$WORK/report.html"

echo; echo "== 4. Tamper test: editing one record in a copy of the ledger"
cp "$TRACEKIT_HOME/ledger.jsonl" "$WORK/tampered.jsonl"
python3 - "$WORK/tampered.jsonl" <<'PY'
import json, sys
p = sys.argv[1]; lines = open(p).read().splitlines()
for i, l in enumerate(lines):
    r = json.loads(l)
    if r.get("event") == "PreToolUse":
        r["tool_input"] = {"command": "echo nothing to see here"}
        lines[i] = json.dumps(r); break
open(p, "w").write("\n".join(lines) + "\n")
PY
python3 "$KIT/verify.py" --ledger "$WORK/tampered.jsonl" || true

echo; echo "Report: $WORK/report.html"
echo "Ledger: $TRACEKIT_HOME/ledger.jsonl"
