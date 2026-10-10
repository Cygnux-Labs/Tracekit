"""Codex CLI, Cursor and Gemini CLI hooks on the v2 signer RPC.

    python -I -m tracekit.integrations.harness_hooks codex|cursor|gemini
    (wired by `tracekit init --dev --v2 --agent NAME`, or as root by `tracekit init --v2 --user AGENT --agent NAME`)

Each payload is mapped onto the Claude Code hook's (tracekit.agent_hooks.normalise: session id, tool call id, tool name
through the mapping tables, arguments, pre or post) and handled by the v2 Claude Code hook's core
(tracekit.integrations.claude_code.handle): the same run per session, signer decisions and approvals, fail modes, and
a missing session or tool call id blocks the call. Only the reply differs: each harness's own stdout and exit code.
"""
import contextlib
import json
import sys

from tracekit import agent_hooks
from tracekit.integrations import claude_code

PRE = ("PreToolUse", "preToolUse", "BeforeTool")


def run(harness, raw, stdout=None, stderr=None):
    """Handle one hook invocation. -> exit code. Writes the harness's expected stdout."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        p = json.loads(raw) if raw.strip() else {}
    except ValueError:
        p = {}
    p = p if isinstance(p, dict) else {}
    is_pre = p.get("hook_event_name") in PRE
    err = agent_hooks.Tee(stderr)
    try:
        q = agent_hooks.normalise(harness, p)
        if q is None:   # an event Tracekit does not record
            code = 0
        else:
            claude_code.AGENT = agent_hooks.AGENT_NAMES[harness]
            with contextlib.redirect_stderr(err):
                code = claude_code.handle(q)
    except Exception as e:   # never a reason to let the call run
        print(f"[tracekit] {harness} hook error ({type(e).__name__}: {e}); blocking", file=err)
        code = 2
    agent_hooks._reply(harness, stdout, code == 0, err.getvalue().strip(), is_pre)
    return code


def entry(harness=None):
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness not in agent_hooks.HARNESSES:
        print(f"usage: python -m tracekit.integrations.harness_hooks {{{'|'.join(agent_hooks.HARNESSES)}}}; blocking",
              file=sys.stderr)
        return 2
    return run(harness, sys.stdin.read())


if __name__ == "__main__":
    sys.exit(entry())
