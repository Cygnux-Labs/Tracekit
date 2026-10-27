"""Codex CLI, Cursor, Gemini CLI, OpenCode, goose, Qwen Code, Factory Droid and Antigravity CLI hooks on the v2 signer RPC.

    python -I -m tracekit.integrations.harness_hooks codex|cursor|gemini|opencode|goose|qwen|droid|antigravity EVENT
    (wired by `tracekit init --dev --v2 --agent NAME`, or as root by `tracekit init --v2 --user AGENT --agent NAME`)

The command names the harness's hook event it is configured for (as its config file names it: PreToolUse, preToolUse,
BeforeTool, ...) after the harness: with it, a payload that is not a JSON object still blocks a pre-tool call. Without
it (hooks installed before 1.2) the event comes from the payload alone.

Each payload is mapped onto the Claude Code hook's (tracekit.agent_hooks.normalise: session id, tool call id, tool name
through the mapping tables, arguments, pre or post) and handled by the v2 Claude Code hook's core
(tracekit.integrations.claude_code.handle): the same run per session, signer decisions and approvals, fail modes, and
a missing session or tool call id blocks the call. Only the reply differs: each harness's own stdout and exit code.

What the model said (docs/reasoning.md) is recorded before each event is handled, as model_event responses on the
session's stream (tracekit.integrations.said): Codex's reasoning items, messages and tool calls from its rollout and
Gemini CLI's thoughts and text from its chat recording (the transcript the payload names; each hook reads the lines
written since the session's last one, a resumed session's first from where it ended at SessionStart), and the text of Cursor's afterAgentThought and afterAgentResponse events. Each
Codex tool call in the rollout is a tool use under its call_id, named as its PreToolUse hook is decided (agent_hooks.tool)
with its arguments `coerced` (Codex rewrites them for the hook), so the model's reasoning before it is linked to the
decision and reconciliation pairs the two; Gemini CLI and Cursor give a call no id, so theirs is not linked, and their
messages are sent `said_only`: the signer reads no call from them, so it never takes the calls their hooks decide for
calls no model asked for. Recording
never changes a hook's answer: a failure prints a line and the hook goes on.
"""
import contextlib
import json
import os
import stat
import sys

from tracekit import agent_hooks, parsers
from tracekit.format.canon import event_hash
from tracekit.deploy import files
from tracekit.integrations import claude_code, said
from tracekit.locking import lock_file

MAX_READ = 1 << 22   # lean: bytes of a transcript one hook reads; the next hook of the session reads on from there
SEEN = 4096   # Gemini CLI message ids remembered per session: it writes a message again as its tool calls complete
NO_HOOK = ("write_stdin", "wait")   # Codex tools that fire no PreToolUse (unified_exec/write_stdin.rs:131, code-mode
# wait_handler.rs:216): no decide to link them to


def run(harness, raw, stdout=None, stderr=None, event=None):
    """Handle one hook invocation (`event`: the hook event from the command line, or None). -> exit code. Writes the
    harness's expected stdout."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        p = json.loads(raw) if raw.strip() else {}
    except (ValueError, RecursionError):   # nested too deep to read
        p = None
    if not isinstance(p, dict) and event:
        pre = event in agent_hooks.PRE
        msg = f"[tracekit] the {event} hook payload is not a JSON object; " + (
            "tool call blocked" if pre else "event not recorded")
        print(msg, file=stderr)
        agent_hooks._reply(harness, stdout, not pre, msg, pre)
        return agent_hooks._exit(harness, 2 if pre else 0, pre)
    p = dict(p, hook_event_name=event) if event else p if isinstance(p, dict) else {}
    is_pre = p.get("hook_event_name") in agent_hooks.PRE or (harness == "goose" and p.get("event") in agent_hooks.PRE)
    err, q = agent_hooks.Tee(stderr), None
    try:
        q = agent_hooks.normalise(harness, p)
        if q is not None or p.get("hook_event_name") in agent_hooks.CURSOR_SAID:
            claude_code.AGENT = agent_hooks.AGENT_NAMES[harness]   # a run said() registers is the harness's
            said_since(harness, p, stderr)
        reason = (agent_hooks._blocked_goose_tool(str(p.get("tool_name") or ""))
                  if q is not None and harness == "goose" and is_pre else None)
        if q is None:   # an event Tracekit does not record
            code = 0
        elif reason is not None:   # a goose tool that runs calls the hook never sees: denied before the signer
            print(reason, file=err)
            code = 2
        else:
            claude_code.AGENT = agent_hooks.AGENT_NAMES[harness]
            with contextlib.redirect_stderr(err):
                code = claude_code.handle(q)
    except Exception as e:   # never a reason to let the call run
        print(f"[tracekit] {harness} hook error ({type(e).__name__}: {e}); "
              + ("blocking" if is_pre else "event not recorded"), file=err)
        code = 2 if is_pre else 1
    if code and harness in agent_hooks.PAIRED and is_pre and q and q.get("tool_use_id"):   # a blocked call gets no post-tool
        with contextlib.suppress(Exception):   # bookkeeping: never in the way of the answer
            agent_hooks._paired_ids(harness, q["session_id"], None, None, "pre", drop=q["tool_use_id"])
    agent_hooks._reply(harness, stdout, code == 0, err.getvalue().strip(), is_pre)
    return agent_hooks._exit(harness, code, is_pre)


def said_since(harness, p, stderr):
    """Record what the model said since the session's last hook (see the module docstring). Never raises."""
    if harness in ("qwen", "droid", "antigravity"):   # lean: their transcript formats are not read; model text goes unrecorded
        return
    sid = (p.get("conversation_id") or p.get("session_id") if harness == "cursor" else
           p.get("session_id") or (os.environ.get("GEMINI_SESSION_ID") if harness == "gemini" else None))
    ev, path, model = p.get("hook_event_name"), p.get("transcript_path"), p.get("model")
    if not isinstance(sid, str) or not sid or (
            ev not in agent_hooks.CURSOR_SAID if harness == "cursor" else not isinstance(path, str) or not path):
        return
    try:
        state = claude_code._state(sid, "said")
        with open(state[:-len(".json")] + ".lock", "a") as lk:   # parallel hooks of a session read the lines once
            lock_file(lk)
            st = claude_code._load(state) or {}
            if harness == "cursor":
                text = p.get("text") if isinstance(p.get("text"), str) else ""
                said_items = [([said.thought(text)] if ev == "afterAgentThought" else said.text(text), model, "unknown",
                               "cursor hook")]
            else:
                resumed = ev == "SessionStart" and p.get("source") in claude_code.RESUMED
                if st.get("path") != path or resumed:   # the session's first transcript, or a new one: from its
                    # start; a resumed (or forked) session's holds its earlier history, which earlier runs recorded
                    st = {"path": path, "offset": claude_code._end(path) if resumed else 0, "seen": []}
                lines = _read(path, st)
                said_items = ([(items, model) for items in _responses(lines)] if harness == "codex" else
                              [(items, m.get("model"), "google", "gemini chat") for m, items in _gemini(lines, st["seen"])])
            if said_items:
                client = claude_code.HookClient()
                try:
                    # a SessionEnd records into the run it ends, never into a new one
                    s = said.Said(lambda **f: claude_code._run(client, sid, register=ev != "SessionEnd",
                                                               send="model_event", **f), lambda: client.status({}))
                    s.vault.limit = st.get("vault")   # asked once per session, not once per hook process
                    for args in said_items:
                        if harness == "codex":
                            _send(s, *args, stderr)
                        else:   # their messages name no call the hooks decide: none to reconcile against
                            s(*args, said_only=True)
                    st["vault"] = s.vault.limit
                finally:
                    client.close()
            if harness != "cursor":
                files.write_json(state, st)
    except Exception as e:   # what the model said goes unrecorded; the hook's answer is unchanged
        # lean: lines read and not sent are not read again, and no gap says so; have the signer write a gap if this
        # happens in practice
        print(f"[tracekit] what the model said was not recorded ({type(e).__name__}: {e})", file=stderr)


def _read(path, st):
    """The JSON objects on the complete lines of the regular file `path` past st["offset"], which moves past them; none
    of anything else."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))   # a FIFO in its place must not block the hook
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return []
        size = os.fstat(fd).st_size
        if size < st["offset"]:
            # lean: a transcript rewritten in place (Gemini CLI's rewind, a resumed session) is read on from its new
            # end, as reading it again would record its lines twice; follow such rewrites line by line if they matter
            st["offset"] = size
        f.seek(st["offset"])
        data = f.read(MAX_READ)
    end = data.rfind(b"\n") + 1 or len(data) * (len(data) == MAX_READ)   # a line longer than MAX_READ is skipped
    st["offset"] += end
    out = []
    for line in data[:end].splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def _responses(lines):
    """Codex rollout lines (`{"type": "response_item", "payload": <a Responses API item>}`) -> its model's responses,
    each the list of its items in rollout order: reasoning, assistant messages, tool calls. Any other item (a tool's
    output, a user or developer message) ends a response; other kinds of line don't."""
    out, cur = [], []
    for e in lines:
        item = e.get("payload") if e.get("type") == "response_item" else None
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        if t == "reasoning" or t == "message" and item.get("role") == "assistant" or str(t).endswith("_call"):
            cur.append(item)
        elif cur:
            out.append(cur)
            cur = []
    return out + [cur] * bool(cur)


def _use(item):
    """The tool use a Codex call item is decided as: the name and arguments of the PreToolUse payload Codex builds for it
    (core/src/tools/registry.rs:150-160, 943-960; exec_command.rs:499-509; apply_patch.rs:394-398; mcp.rs:114-131,
    449-457), mapped as agent_hooks.tool maps them; None for a call that fires no PreToolUse."""
    t, name, cid = item.get("type"), str(item.get("name") or ""), item.get("call_id")
    if t == "custom_tool_call" and name == "apply_patch":
        hook, ti = "apply_patch", {"command": item.get("input")}
    elif t == "function_call" and name and name not in NO_HOOK:
        raw = item.get("arguments") if isinstance(item.get("arguments"), str) else ""
        try:
            ti = json.loads(raw) if raw.strip() else {}
        except ValueError:
            ti = raw
        ns = item.get("namespace") or ""
        if name == "exec_command":
            if not isinstance(ti, dict) or not isinstance(ti.get("cmd"), str):   # Codex fires no hook for these
                return None
            hook, ti = "Bash", {"command": ti["cmd"]}
        elif ns.startswith("mcp"):
            hook = ns.rstrip("_") + "__" + name.lstrip("_")
            hook = hook if hook.startswith("mcp__") else "mcp__" + hook
        else:
            hook = name if name == "spawn_agent" else ns + name
    else:
        return None
    if not cid:
        return None
    tool, args = agent_hooks.tool("codex", hook, ti)
    # coerced: the payload is Codex's rewrite of the model's arguments, so reconciliation compares the tool, not them
    return {"id": parsers._id(cid), "name": tool[:256] or "?", "executed_by": "client", "args_source": "coerced",
            "args_digest": event_hash({"tool": tool, "args": args})}


def _send(s, items, model, stderr):
    """One Codex response as a model_event (said.Said's send and vault): the rollout's items as they are, each call as
    a tool use under its call_id (_use), not as said.Said would read the items."""
    body = {"output": items, "source": "codex rollout"}
    try:
        uses = [u for u in map(_use, items) if u]
        s.send(provider="openai", model=str(model or "unknown")[:128], phase="response",
               content_digest=event_hash(body), **s.vault(body), **({"tool_uses": uses[:128]} if uses else {}))
    except Exception as e:
        print(f"[tracekit] a Codex response was not recorded ({type(e).__name__}: {e})", file=stderr)


def _gemini(lines, seen):
    """Gemini CLI chat recording lines -> (message, said items) of each of its model's messages not seen before: a
    thought summary per thought ({subject, description}), then its text. Gemini CLI writes a message again as its tool
    calls complete, and queues thoughts until then (chatRecordingService.ts:1097, 1168-1199)."""
    for e in lines:
        if e.get("type") != "gemini" or e.get("id") in seen:
            continue
        thoughts = [t for t in e.get("thoughts") or () if isinstance(t, dict)]
        items = [said.thought(" ".join(x for x in (f"**{t['subject']}**" if t.get("subject") else "",
                                                   str(t.get("description") or "")) if x)) for t in thoughts]
        items += said.text(_parts_text(e.get("content")))
        if items:
            seen[:] = (seen + [e.get("id")])[-SEEN:]
            yield e, items


def _parts_text(content):
    """The text of a Gemini CLI message's content (a string, a part or a list of parts)."""
    if isinstance(content, str):
        return content
    parts = content if isinstance(content, list) else [content]
    return "".join(p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str)
                   and not p.get("thought"))


def entry(harness=None, event=None):
    harness = harness or (sys.argv[1] if len(sys.argv) > 1 else "")
    if harness not in agent_hooks.HARNESSES:
        print(f"usage: python -m tracekit.integrations.harness_hooks {{{'|'.join(agent_hooks.HARNESSES)}}} [EVENT]; "
              "blocking", file=sys.stderr)
        return 2
    return run(harness, agent_hooks.stdin_text(), event=event)


if __name__ == "__main__":
    sys.exit(entry(*sys.argv[1:3]))
