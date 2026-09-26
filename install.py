#!/usr/bin/env python3
"""Wire tracekit into Claude Code (user-level ~/.claude/settings.json).

  python3 install.py              install (backs up settings first)
  python3 install.py --project    install into ./.claude/settings.json instead
  python3 install.py --uninstall  remove tracekit hooks
Idempotent: re-running replaces tracekit's entries and leaves your other hooks alone.
"""
import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
OTHER_EVENTS = ["UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop", "SessionStart",
                "SessionEnd", "PreCompact", "Notification"]


def is_ours(group):
    return any("tracekit" in (h.get("command") or "") and "hook.py" in (h.get("command") or "")
               for h in group.get("hooks", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    a = ap.parse_args()
    path = os.path.join(os.getcwd(), ".claude", "settings.json") if a.project \
        else os.path.expanduser("~/.claude/settings.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    settings = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            settings = json.load(f)
        backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, backup)
        print("Backed up settings to", backup)
    hooks = settings.setdefault("hooks", {})
    for ev in TOOL_EVENTS + OTHER_EVENTS:
        groups = [g for g in hooks.get(ev, []) if not is_ours(g)]
        if not a.uninstall:
            entry = {"hooks": [{"type": "command",
                                "command": f'python3 "{os.path.join(HERE, "hook.py")}"',
                                "timeout": 10}]}
            if ev in TOOL_EVENTS:
                entry = {"matcher": "*", **entry}
            groups.append(entry)
        if groups:
            hooks[ev] = groups
        else:
            hooks.pop(ev, None)
    if not hooks:
        settings.pop("hooks", None)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    if a.uninstall:
        print("Removed tracekit hooks from", path, "(your ledger in ~/.tracekit is untouched)")
        return
    home = os.environ.get("TRACEKIT_HOME", os.path.expanduser("~/.tracekit"))
    os.makedirs(home, exist_ok=True)
    pol = os.path.join(home, "policy.json")
    if not os.path.exists(pol):
        shutil.copy2(os.path.join(HERE, "policy.json"), pol)
        print("Installed default policy at", pol)
    print("Installed tracekit hooks into", path)
    print("Restart Claude Code, run any task, then:  python3", os.path.join(HERE, "view.py"))


if __name__ == "__main__":
    sys.exit(main())
