"""Codex CLI, Cursor and Gemini CLI hooks on the v2 signer RPC.

    python -I -m tracekit.integrations.harness_hooks codex|cursor|gemini EVENT
    (wired by `tracekit init --dev --v2 --agent NAME`, or as root by `tracekit init --v2 --user AGENT --agent NAME`)

The command names the harness's hook event it is configured for (as its config file names it: PreToolUse, preToolUse,
BeforeTool, ...) after the harness: with it, a payload that is not a JSON object still blocks a pre-tool call. Without
it (hooks installed before 1.2) the event comes from the payload alone.

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


def run(harness, raw, stdout=None, stderr=None, event=None):
    """Handle one hook invocation (`event`: the hook event from the command line, or None). -> exit code. Writes the
    harness's expected stdout."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        p = json.loads(raw) if raw.strip() else {}
    except ValueError:
        p = None
    if not isinstance(p, dict) and event:
        pre = event in agent_hooks.PRE
        msg = f"[tracekit] the {event} hook payload is not a JSON object; " + (
            "tool call blocked" if pre else "event not recorded")
        print(msg, file=stderr)
        agent_hooks._reply(harness, stdout, not pre, msg, pre)
        return 2 if pre else 0
    p = dict(p, hook_event_name=event) if event else p if isinstance(p, dict) else {}
    is_pre = p.get("hook_event_name") in agent_hooks.PRE
    err, q = agent_hooks.Tee(stderr), None
    try:
        q = agent_hooks.normalise(harness, p)
        if q is None:   # an event Tracekit does not record
            code = 0
        else:
            claude_code.AGENT = agent_hooks.AGENT_NAMES[harness]
            with contextlib.redirect_stderr(err):
                code = claude_code.handle(q)
    except Exception as e:   # never a reason to let the call run
        print(f"[tracekit] {harness} hook error ({type(e).__name__}: {e}); "
              + ("blocking" if is_pre else "event not recorded"), file=err)
        code = 2 if is_pre else 1
    if code and harness == "gemini" and is_pre and q and q.get("tool_use_id"):   # a blocked call gets no AfterTool
        agent_hooks._gemini_ids(q["session_id"], None, None, "pre", drop=q["tool_use_id"])
    agent_hooks._reply(harness, stdout, code == 0, err.getvalue().strip(), is_pre)
    return code


def entry(harness=None, event=None):
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness not in agent_hooks.HARNESSES:
        print(f"usage: python -m tracekit.integrations.harness_hooks {{{'|'.join(agent_hooks.HARNESSES)}}} [EVENT]; "
              "blocking", file=sys.stderr)
        return 2
    return run(harness, sys.stdin.read(), event=event)


if __name__ == "__main__":
    sys.exit(entry(*sys.argv[1:3]))
