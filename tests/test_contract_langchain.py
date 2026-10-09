"""The adapter contract (tests/adapter_contract.py) for the LangChain v1 middleware, with a stub chat model (no network).

A paused call resumes in a new process, from the SQLite checkpoint it paused in; this file is that process's script.
"""
import asyncio
import json
import os
import subprocess
import sys
import unittest

import adapter_contract as ac
from tracekit.sdk.client import Client

try:
    from langchain.agents import create_agent
    from langchain.agents.middleware import ToolRetryMiddleware, wrap_tool_call
    from langchain_core.language_models import BaseChatModel
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_core.tools import tool
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command

    from tracekit.integrations.langchain import TracekitMiddleware
except ImportError:   # optional: the dev extra installs them
    HAVE_LC = False
else:
    HAVE_LC = True
    TOOLS = [tool(f) for f in ac.TOOLS]

    class StubModel(BaseChatModel):
        """Makes the tool call (or list of them) in the user's JSON message, then answers "done"."""

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            if isinstance(messages[-1], HumanMessage):
                calls = json.loads(messages[-1].content)
                msg = AIMessage("", tool_calls=calls if isinstance(calls, list) else [calls])
            else:
                msg = AIMessage("done")
            return ChatResult(generations=[ChatGeneration(message=msg)])

        def bind_tools(self, tools, **kw):
            return self

        @property
        def _llm_type(self):
            return "stub"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def agent(signer, run, checkpointer, outer=(), inner=()):
    return create_agent(StubModel(), TOOLS, checkpointer=checkpointer,
                        middleware=[*outer, TracekitMiddleware(signer, run["run_id"], run["run_token"]), *inner])


def saver(d):
    return SqliteSaver.from_conn_string(os.path.join(d, "cp.sqlite"))


async def _last(chunks):
    async for out in chunks:
        pass
    return out


def invoke(a, value, config, mode="sync"):
    """Run the agent; the contract's outcome."""
    out = raised = None
    try:
        if mode == "sync":
            out = a.invoke(value, config)
        elif mode == "async":
            out = asyncio.run(a.ainvoke(value, config))
        elif mode == "stream":
            *_, out = a.stream(value, config, stream_mode="values")
        else:
            out = asyncio.run(_last(a.astream(value, config, stream_mode="values")))
    except Exception as e:
        raised = f"{type(e).__name__}: {e}"
    o = {"ran": list(ac.RAN), "seen": None, "is_error": False, "continued": False, "raised": raised, "approval_id": None}
    if out and "__interrupt__" in out:
        o["approval_id"] = out["__interrupt__"][0].value["tracekit"]["approval_id"]
    elif out:
        msg = next(m for m in out["messages"] if isinstance(m, ToolMessage))
        o.update(seen=msg.content, is_error=msg.status == "error", continued=out["messages"][-1].content == "done")
    return o


class Driver:
    SKIP = {"l1": "no checkpointer wrapper yet (04-design §6 L1)"}
    modes = ("async", "stream", "astream")

    def __init__(self, case, signer_path):
        self.case, self.path, self.dir = case, signer_path, ac.tmpdir(case)
        self.signer = Client(signer_path)
        case.addCleanup(self.signer.close)
        r = self.signer.register_run({"agent": {"name": "contract"}})
        self._run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def run(self):
        return self._run

    def call(self, tool_name, args, tcid="call-1", mode="sync", outer=(), inner=()):
        ac.RAN.clear()
        self.config = {"configurable": {"thread_id": tcid}}
        prompt = {"messages": [HumanMessage(json.dumps({"name": tool_name, "args": args, "id": tcid}))]}
        with saver(self.dir) as cp:
            # only sync calls pause for approvals: SqliteSaver has no async API
            out = invoke(agent(self.signer, self._run, cp if mode == "sync" else None, outer, inner), prompt,
                         self.config, mode)
            if out["approval_id"]:
                self.hint, self.paused = out["approval_id"], cp.get_tuple(self.config)
        return out

    def retry(self, tool_name, args):
        failed = []

        @wrap_tool_call
        def flaky(request, handler):
            if not failed:
                failed.append(1)
                raise RuntimeError("transient")
            return handler(request)
        return self.call(tool_name, args, outer=[ToolRetryMiddleware(max_retries=1, initial_delay=0, jitter=False)],
                         inner=[flaky])

    def resume(self, hint=ac.HINT, replay=False):
        """In a new process, as a deployment resumes after a person approved."""
        config = dict(self.config["configurable"])
        if replay:
            config["checkpoint_id"] = self.paused.config["configurable"]["checkpoint_id"]
        value = {"decision": "approve"} if hint is None else {"approval_id": self.hint if hint is ac.HINT else hint}
        spec = json.dumps({"run": self._run, "config": config, "resume": value})
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [ROOT, os.environ.get("PYTHONPATH")])))
        p = subprocess.run([sys.executable, __file__, self.dir, self.path, spec], capture_output=True, text=True,
                           env=env, timeout=120)
        self.case.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout.splitlines()[-1])

    def tamper(self, args=None, tool_call_id=None):
        t = self.paused
        [send] = t.checkpoint["channel_values"]["__pregel_tasks"]   # the pending call the resumed node executes
        call = send.arg[0]
        call.update({**({"args": args} if args else {}), **({"id": tool_call_id} if tool_call_id else {})})
        with saver(self.dir) as cp:
            cp.put(t.parent_config, t.checkpoint, t.metadata, {})


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class TestOnFakeSigner(ac.Contract, ac.OnFake, unittest.TestCase):
    driver = Driver


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class TestOnRealSigner(ac.Contract, ac.OnReal, unittest.TestCase):
    driver = Driver


if __name__ == "__main__":
    d, path, spec = sys.argv[1:]
    spec = json.loads(spec)
    with saver(d) as cp:
        out = invoke(agent(Client(path), spec["run"], cp), Command(resume=spec["resume"]), {"configurable": spec["config"]})
    print(json.dumps(out))
