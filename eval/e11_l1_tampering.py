#!/usr/bin/env python3
"""E11: tampering with L1 saved state is a signed record (04-design §6). POSIX only.

For each L1 source a short session runs against a v2 dev signer (`tracekit signer serve`), its saved state is tampered
with in one way, and the session goes on, as a resumed process would (the wrappers) or as the tailer's next wake does:

  langgraph        TracekitCheckpointer over a SqliteSaver: a ToolNode graph pauses before its tool call, then
                   resumes from the saved checkpoint in a new checkpointer
  claude_agent_sdk TracekitSessionStore over a JSONL file store, driven as the SDK mirrors a transcript (no CLI): a
                   prompt and a tool use, then a resumed session loads the transcript and appends to it
  tailer           the Claude Code transcript tailer (tracekit.tailer) following a transcript of the same entries

Tamper kinds: edit a saved entry, delete one, reorder, truncate, replace the file (new inode), swap in a symlink to
another session's file, change the pending tool call. Edits keep the file's size (the strongest attacker), and only
`replace` changes its inode. Detected = the run has the expected signer-written gap (state_tamper for the wrappers,
tailer_lost for the tailer). An untampered control run of each source must have none.
Writes eval/results/e11_l1_tampering.json; exit 0 only when every case is detected and every control is clean. A source
whose framework is not installed (`pip install -e .[dev]`) is reported as skipped.
"""
import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import v2_signer, write_results  # noqa: E402
from tracekit import tailer  # noqa: E402
from tracekit.sdk.client import Client, RunHandle  # noqa: E402

PROMPT = {"type": "user", "uuid": "u-1", "message": {"role": "user", "content": "list the files"}}
TOOL_USE = {"type": "assistant", "uuid": "u-2", "message": {"id": "msg_1", "model": "claude-x", "content": [
    {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls -la"}}]}}
RESULT = {"type": "user", "uuid": "u-3", "message": {"content": [
    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "a.txt"}]}}
NEXT = {"type": "assistant", "uuid": "u-4", "message": {"id": "msg_2", "model": "claude-x", "content": [
    {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {"file_path": "a.txt"}}]}}
KINDS = ("edit", "delete", "reorder", "truncate", "replace", "symlink", "pending_tool_call")


def gaps(client, out):
    events = client.read({"run_id": out["run_id"], "run_token": out["run_token"], "limit": 1000})["events"]
    return [e["data"]["kind"] for e in events if e["type"] == "capture.gap"]


# --- JSONL files (the session store's transcripts and the tailer's) ---

def jsonl(entries):
    return b"".join(json.dumps(e).encode() + b"\n" for e in entries)


def rewrite(path, fn):
    """Rewrite the file's lines with fn, in place: same inode."""
    with open(path, "r+b") as f:
        lines = fn(f.read().splitlines(keepends=True))
        f.seek(0)
        f.write(b"".join(lines))
        f.truncate()


def same_size_edit(line, old, new):
    assert len(old) == len(new) and old in line
    return line.replace(old, new)


def replace_file(path, data):
    tmp = path + ".new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def symlink_to(path, data):
    other = path + ".other"
    with open(other, "wb") as f:
        f.write(data)
    os.remove(path)
    os.symlink(other, path)


OTHER = jsonl([dict(PROMPT, message={"role": "user", "content": "show the files"}), TOOL_USE])

FILE_TAMPER = {
    "edit": lambda p: rewrite(p, lambda ls: [same_size_edit(ls[0], b"list", b"wipe")] + ls[1:]),
    "delete": lambda p: rewrite(p, lambda ls: ls[1:]),
    "reorder": lambda p: rewrite(p, lambda ls: [ls[1], ls[0]] + ls[2:]),
    "truncate": lambda p: rewrite(p, lambda ls: ls[:-1]),
    "replace": lambda p: replace_file(p, OTHER),
    "symlink": lambda p: symlink_to(p, OTHER),
    "pending_tool_call": lambda p: rewrite(p, lambda ls: [ls[0], same_size_edit(ls[1], b"ls -la", b"ls -lR")] + ls[2:]),
}


# --- tailer ---

def tailer_case(client, d, tamper):
    out = client.register_run({"agent": {"name": "e11-tailer"}})
    path, until = os.path.join(d, "session.jsonl"), os.path.join(d, "until")
    with open(path, "wb") as f:
        f.write(jsonl([PROMPT, TOOL_USE]))
    open(until, "w").close()
    steps = [lambda: tamper(path)] if tamper else []
    def more():   # the session goes on
        with open(os.path.realpath(path), "ab") as f:
            f.write(jsonl([RESULT, NEXT]))
    steps.append(more)

    def wait():   # one step per wake of the tailer, then its session ends
        steps.pop(0)() if steps else os.remove(until)
    tailer.tail(RunHandle(client, out), path, os.getuid(), until, wait)
    return gaps(client, out)


# --- Claude Agent SDK session store ---

class FileStore:
    """A SessionStore keeping each transcript as a JSONL file."""

    def __init__(self, d):
        self.d = d

    def path(self, key):
        return os.path.join(self.d, key["session_id"] + ".jsonl")

    async def load(self, key):
        try:
            with open(self.path(key), "rb") as f:
                return [json.loads(line) for line in f]
        except FileNotFoundError:
            return None

    async def append(self, key, entries):
        with open(self.path(key), "ab") as f:
            f.write(jsonl(entries))


def sdk_case(client, d, tamper):
    from tracekit.integrations.claude_agent_sdk import TracekitSessionStore
    out = client.register_run({"agent": {"name": "e11-sdk"}})
    run, key, store = {"run_id": out["run_id"], "run_token": out["run_token"]}, {"session_id": "s1"}, FileStore(d)

    async def session():
        # lean: the SDK's transcript mirror is driven directly, batch by batch, without a CLI; run a real
        # `claude` session once one can run offline in CI
        first = TracekitSessionStore(store, client, run)
        await first.append(key, [PROMPT])
        await first.append(key, [TOOL_USE])
        if tamper:
            tamper(store.path(key))
        resumed = TracekitSessionStore(store, client, run)   # a new process resumes the session
        await resumed.load(key)
        await resumed.append(key, [RESULT])
    asyncio.run(session())
    return gaps(client, out)


# --- LangGraph checkpointer ---

def langgraph_case(client, d, tamper):
    from langchain_core.messages import AIMessage, HumanMessage
    from langchain_core.tools import tool
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import tools_condition

    from tracekit.integrations.langchain import TracekitCheckpointer, tracekit_tool_node

    @tool
    def echo(text: str) -> str:
        """Echo the text."""
        return text

    def model(state):
        if isinstance(state["messages"][-1], HumanMessage):
            return {"messages": [AIMessage("", tool_calls=[{"name": "echo", "args": {"text": "hi"}, "id": "call-1"}])]}
        return {"messages": [AIMessage("done")]}

    def session(db, prompt, out, resume):
        run = {"run_id": out["run_id"], "run_token": out["run_token"]}
        g = StateGraph(MessagesState)
        g.add_node("model", model)
        g.add_node("tools", tracekit_tool_node([echo], client, run))
        g.add_edge(START, "model")
        g.add_conditional_edges("model", tools_condition)
        g.add_edge("tools", "model")
        with SqliteSaver.from_conn_string(db) as cp:   # a new checkpointer each time: a new process
            graph = g.compile(checkpointer=TracekitCheckpointer(cp, client, run), interrupt_before=["tools"])
            graph.invoke(None if resume else {"messages": [HumanMessage(prompt)]}, {"configurable": {"thread_id": "t"}})

    other = os.path.join(d, "other.sqlite")   # another session of the same thread
    session(other, "show the files", client.register_run({"agent": {"name": "e11-other"}}), False)
    db, out = os.path.join(d, "cp.sqlite"), client.register_run({"agent": {"name": "e11-langgraph"}})
    session(db, "list the files", out, False)   # pauses before the tool call
    if tamper:
        tamper(db, other)
    session(db, None, out, True)
    return gaps(client, out)


def edit_checkpoint(fn):
    """Edit the thread's latest checkpoint in place through the saver: fn(messages) -> messages."""
    def tamper(db, other):
        from langgraph.checkpoint.sqlite import SqliteSaver
        with SqliteSaver.from_conn_string(db) as cp:
            t = cp.get_tuple({"configurable": {"thread_id": "t"}})
            values = t.checkpoint["channel_values"]
            values["messages"] = fn(values["messages"])
            cp.put(t.parent_config, t.checkpoint, t.metadata, {})
    return tamper


def delete_checkpoint(db, other):
    with sqlite3.connect(db) as c:
        (cid,) = c.execute("SELECT checkpoint_id FROM checkpoints ORDER BY checkpoint_id DESC LIMIT 1").fetchone()
        c.execute("DELETE FROM checkpoints WHERE checkpoint_id = ?", (cid,))
        c.execute("DELETE FROM writes WHERE checkpoint_id = ?", (cid,))


def edited(msgs):
    msgs[0].content = "wipe the files"
    return msgs


def retargeted(msgs):
    msgs[-1].tool_calls[0]["args"] = {"text": "bye"}
    return msgs


def replace_db(db, other):
    tmp = db + ".new"
    shutil.copyfile(other, tmp)
    os.replace(tmp, db)


def symlink_db(db, other):
    os.remove(db)
    os.symlink(other, db)


CHECKPOINT_TAMPER = {
    "edit": edit_checkpoint(edited),
    "delete": delete_checkpoint,
    "reorder": edit_checkpoint(lambda msgs: msgs[::-1]),
    "truncate": edit_checkpoint(lambda msgs: msgs[-1:]),
    "replace": replace_db,
    "symlink": symlink_db,
    "pending_tool_call": edit_checkpoint(retargeted),
}

SOURCES = {   # name: (case, tamper kinds, the gap that detects them, the modules it needs)
    "langgraph": (langgraph_case, CHECKPOINT_TAMPER, "state_tamper", ("langgraph.checkpoint.sqlite", "langchain")),
    "claude_agent_sdk": (sdk_case, FILE_TAMPER, "state_tamper", ("claude_agent_sdk",)),
    "tailer": (tailer_case, FILE_TAMPER, "tailer_lost", ()),
}


def main():
    if os.name != "posix":
        raise SystemExit("E11 needs POSIX (the tailer, symlinks and Unix sockets)")
    d = tempfile.mkdtemp(prefix="e11-", dir="/tmp")   # short socket paths
    out, ok = {"platform": sys.platform, "python": sys.version.split()[0], "sources": {}, "skipped": {}}, True
    p, sock = v2_signer(os.path.join(d, "signer"))
    client = Client(sock)
    try:
        for name, (case, tampers, expect, needs) in SOURCES.items():
            try:
                for mod in needs:
                    __import__(mod)
            except ImportError as e:
                out["skipped"][name] = f"{e} (pip install -e .[dev])"
                print(f"{name}: skipped, {out['skipped'][name]}", flush=True)
                continue
            n = iter(range(1000))

            def fresh():
                os.mkdir(work := os.path.join(d, f"{name}-{next(n)}"))
                return work
            control = case(client, fresh(), None)
            res = out["sources"][name] = {"expected": expect, "control_gaps": control, "cases": {}}
            ok &= not control
            print(f"{name}: control {'clean' if not control else control}", flush=True)
            for kind in KINDS:
                got = case(client, fresh(), tampers[kind])
                res["cases"][kind] = {"gaps": got, "detected": expect in got}
                ok &= expect in got
                print(f"  {kind}: {'detected' if expect in got else 'NOT DETECTED'} {got}", flush=True)
    finally:
        client.close()
        p.terminate()
        p.wait(30)
        shutil.rmtree(d, ignore_errors=True)
    out["all_detected_and_controls_clean"] = ok
    print("wrote", write_results("e11_l1_tampering", out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
