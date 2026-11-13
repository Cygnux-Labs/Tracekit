"""Source copied into gptme's Python environment by Tracekit's installer."""

import hashlib
import json
import logging
from pathlib import Path
import subprocess
from uuid import uuid4

from gptme.hooks import ConfirmationResult, HookType, register_hook
from gptme.logmanager import LogManager
from gptme.tools import get_tool
from gptme.tools.base import get_current_tool_use

COMMAND = ()
V2 = False
TIMEOUT = 600
CONFIRM_HOOK = "tracekit.confirm"
_calls = {}
_log = logging.getLogger(__name__)


def _session(logdir):
    return hashlib.sha256(str(Path(logdir).resolve()).encode("utf-8")).hexdigest()


def _send(event, payload):
    try:
        result = subprocess.run(
            COMMAND, input=json.dumps(dict(payload, hook_event_name=event)).encode("utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return 2, f"[tracekit] the hook timed out after {TIMEOUT} s"
    except (OSError, ValueError, TypeError) as error:
        return 2, f"[tracekit] could not run the hook: {error}"
    return result.returncode, result.stderr.decode("utf-8", "replace").strip()


def _record(event, payload):
    code, reason = _send(event, payload)
    if code:
        _log.warning("%s", reason or f"[tracekit] {event} failed (exit {code})")


def _payload(call, sid, tid, workspace):
    spec = get_tool(call.tool)
    return {
        "session_id": sid, "tool_use_id": tid, "cwd": str(workspace or Path.cwd()),
        "tool_name": spec.name if spec is not None else call.tool,
        "tool_input": {"args": call.args, "content": call.content, "kwargs": call.kwargs},
    }


def _prepare(payload, preview):
    name, args = payload["tool_name"], payload["tool_input"]
    if name == "patch_many":
        from gptme.tools.patch_many import _parse_confirmation_payload

        # gptme's preview is the prepared patch for every target, including resolved paths.
        if not isinstance(preview, str):
            raise ValueError("patch_many has no confirmation preview")
        args["patches"] = [[str(path), patch] for path, patch in _parse_confirmation_payload(preview)]
    if name == "tmux":
        from gptme.tools.tmux import _split_tmux_commands

        command = args["content"] if args["kwargs"] is None else args["kwargs"].get("command")
        if not isinstance(command, str):
            raise ValueError("tmux has no command text")
        args["operations"] = _split_tmux_commands(command)


def _start(logdir, workspace, initial_msgs):
    _record("SessionStart", {"session_id": _session(logdir), "cwd": str(workspace or Path.cwd())})
    return []


def _turn(manager):
    messages = manager.log.messages
    if V2 and messages and messages[-1].role == "user":
        prompt = messages[-1].content
        # gptme's loop control submits its own prompts using a user-role system wrapper.
        if isinstance(prompt, str) and prompt and not prompt.lstrip().startswith("<system>"):
            # TURN_PRE exposes only the expanded text, which can include files, pages and piped input.
            _record("PromptObserved", {"session_id": _session(manager.logdir), "prompt": prompt, "cwd": str(Path.cwd())})
    return []


def _confirm(tool_use, preview, workspace):
    manager = LogManager.get_current_log()
    if manager is None:
        return ConfirmationResult.skip("[tracekit] no active gptme session")
    # IPython can ask confirmation under a registered helper's name. The cell is what will execute.
    call = get_current_tool_use() or tool_use
    sid, tid = _session(manager.logdir), uuid4().hex
    payload = _payload(call, sid, tid, workspace)
    try:
        _prepare(payload, preview)
    except (ImportError, OSError, TypeError, ValueError) as error:
        code, reason = 2, f"[tracekit] could not read gptme's prepared call: {error}"
    else:
        code, reason = _send("PreToolUse", payload)
    # Keep the object alive until post (or session end), so another call cannot reuse its id.
    _calls[id(call)] = (call, payload, code)
    if code:
        reason = reason or f"[tracekit] the hook blocked the call (exit {code})"
        _log.warning("%s", reason)
        return ConfirmationResult.skip(reason)
    # A later gptme confirmation can edit the command after Tracekit decides it.
    return ConfirmationResult.confirm()


def _post(data):
    call = data.tool_use
    if call is None:
        return []
    decision = _calls.pop(id(call), None)
    result = [{"role": msg.role, "content": msg.content} for msg in data.result_msgs or ()]
    if decision is not None:
        _, payload, code = decision
        if code == 0:
            _record("PostToolUse", dict(payload, tool_response=result))
    elif V2:
        manager = LogManager.get_current_log()
        if manager is not None:
            payload = _payload(call, _session(manager.logdir), uuid4().hex, data.workspace)
            _record("ToolObserved", dict(payload, tool_response=result))
    return []


def _end(manager):
    sid = _session(manager.logdir)
    for key, (_, payload, _) in list(_calls.items()):
        if payload["session_id"] == sid:
            _calls.pop(key, None)
    _record("SessionEnd", {"session_id": sid})
    return []


def register():
    register_hook("tracekit.session_start", HookType.SESSION_START, _start)
    register_hook("tracekit.turn_pre", HookType.TURN_PRE, _turn)
    register_hook(CONFIRM_HOOK, HookType.TOOL_CONFIRM, _confirm, priority=10_000)
    register_hook("tracekit.tool_post", HookType.TOOL_EXECUTE_POST, _post)
    register_hook("tracekit.session_end", HookType.SESSION_END, _end)
