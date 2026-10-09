"""Contract suite for tracekit.integrations.langchain against FakeSigner, with a stub chat model (no network).

The approval tests run each step in its own process, as a real deployment would: the agent starts and pauses, a
person approves in the signer, then a new process resumes from the SQLite checkpoint. FakeSigner lives in memory, so
its state is pickled between steps. This file is also the script those processes run.
"""
import asyncio
import json
import os
import pickle
import subprocess
import sys
import tempfile
import unittest

from tracekit.testing import FakeSigner

try:
    from langchain.agents import create_agent
    from langchain_core.language_models import BaseChatModel
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_core.tools import tool
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command, interrupt

    from tracekit.format.canon import event_hash
    from tracekit.integrations.langchain import TracekitMiddleware
except ImportError:   # optional: the dev extra installs them
    HAVE_LC = False
else:
    HAVE_LC = True

    class StubModel(BaseChatModel):
        """Calls the tool named in the user's JSON message, then answers "done"."""

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            if isinstance(messages[-1], HumanMessage):
                msg = AIMessage("", tool_calls=[{**json.loads(messages[-1].content), "id": "call-1"}])
            else:
                msg = AIMessage("done")
            return ChatResult(generations=[ChatGeneration(message=msg)])

        def bind_tools(self, tools, **kw):
            return self

        @property
        def _llm_type(self):
            return "stub"

    @tool
    def echo(text: str) -> str:
        """Echo the text."""
        RAN.append("echo")
        return text

    @tool
    def pay(to: str, cents: int) -> str:
        """Send money."""
        RAN.append("pay")
        return f"paid {cents}"

    @tool
    def wipe(path: str) -> str:
        """Delete a path."""
        RAN.append("wipe")
        return "wiped"

    @tool
    def fail(why: str) -> str:
        """Always raises."""
        raise ValueError(why)

    @tool
    def confirm(question: str) -> str:
        """Ask the user, pausing the run."""
        RAN.append("confirm")
        return interrupt(question)

RAN = []
THREAD = {"configurable": {"thread_id": "t"}}


def rule(tool, args):
    return {"pay": ("ask", ["R-PAY"]), "wipe": ("deny", ["R-WIPE"])}.get(tool, ("allow", []))


def prompt(name, **args):
    return {"messages": [HumanMessage(json.dumps({"name": name, "args": args}))]}


def register(signer):
    r = signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
    return {"run_id": r["run_id"], "run_token": r["run_token"]}


def agent(signer, run, checkpointer=None):
    return create_agent(StubModel(), [echo, pay, wipe, fail, confirm], checkpointer=checkpointer,
                        middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])


def events(signer, run):
    return signer.read({**run, "limit": 1000})["events"]


def tool_message(out):
    return next(m for m in out["messages"] if isinstance(m, ToolMessage))


def save(signer, d):
    with open(os.path.join(d, "signer.pkl"), "wb") as f:
        pickle.dump({k: v for k, v in vars(signer).items() if k != "rule"}, f)


def load(d):
    signer = FakeSigner(rule)
    with open(os.path.join(d, "signer.pkl"), "rb") as f:
        vars(signer).update(pickle.load(f))
    with open(os.path.join(d, "run.json")) as f:
        return signer, json.load(f)


def saver(d):
    return SqliteSaver.from_conn_string(os.path.join(d, "cp.sqlite"))


def main(step, d, resume=None, checkpoint_id=None):
    """One step of the approval flow in this process; prints a JSON summary."""
    if step == "start":
        signer = FakeSigner(rule)
        run = register(signer)
        with open(os.path.join(d, "run.json"), "w") as f:
            json.dump(run, f)
        with saver(d) as cp:
            out = agent(signer, run, cp).invoke(prompt("pay", to="acct-42", cents=1500), THREAD)
        summary = {"interrupt": out["__interrupt__"][0].value}
    else:
        signer, run = load(d)
        config = {"configurable": dict(THREAD["configurable"], **({"checkpoint_id": checkpoint_id} if checkpoint_id else {}))}
        with saver(d) as cp:
            out = agent(signer, run, cp).invoke(Command(resume=json.loads(resume)), config)
        summary = {"ran": RAN, "tool_message": tool_message(out).content, "last": out["messages"][-1].content}
    save(signer, d)
    print(json.dumps(summary))


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class Decisions(unittest.TestCase):
    def setUp(self):
        RAN.clear()
        self.signer = FakeSigner(rule)
        self.run = register(self.signer)

    def recorded(self, typ):
        return [e["data"] for e in events(self.signer, self.run) if e["type"] == typ]

    def test_allow_runs_the_tool_and_records_decision_and_result(self):
        sent = []
        complete = self.signer.complete
        self.signer.complete = lambda req: sent.append(req) or complete(req)
        out = agent(self.signer, self.run).invoke(prompt("echo", text="hi"))
        self.assertEqual([r["result"] for r in sent], [event_hash("hi")])
        self.assertEqual(RAN, ["echo"])
        self.assertEqual(tool_message(out).content, "hi")
        [d] = self.recorded("policy.decision")
        self.assertEqual((d["tool"], d["args_source"], d["decision"]), ("echo", "parsed", "allow"))
        self.assertEqual(self.recorded("tool.result"), [{"tool_call_id": "call-1", "decision_id": d["decision_id"],
                                                         "attempt": 0, "status": "ok"}])

    def test_deny_blocks_the_tool_and_the_run_continues(self):
        out = agent(self.signer, self.run).invoke(prompt("wipe", path="/"))
        self.assertEqual(RAN, [])
        msg = tool_message(out)
        self.assertEqual(msg.status, "error")
        self.assertIn("blocked by policy", msg.content)
        self.assertIn("R-WIPE", msg.content)
        self.assertEqual(out["messages"][-1].content, "done")
        self.assertEqual(self.recorded("tool.result"), [])

    def test_ask_without_a_checkpointer_is_denied(self):
        out = agent(self.signer, self.run).invoke(prompt("pay", to="a", cents=1))
        self.assertEqual(RAN, [])
        self.assertIn("no checkpointer", tool_message(out).content)
        self.assertEqual(self.recorded("approval.request"), [])

    def test_tool_exceptions_propagate_unchanged_and_are_recorded(self):
        with self.assertRaisesRegex(ValueError, "^boom$"):
            agent(self.signer, self.run).invoke(prompt("fail", why="boom"))
        [r] = self.recorded("tool.result")
        self.assertEqual((r["status"], r["error"]), ("error", "ValueError: boom"))

    def test_interrupt_inside_a_tool_is_not_recorded_as_an_outcome(self):
        a = agent(self.signer, self.run, InMemorySaver())
        a.invoke(prompt("confirm", question="sure?"), THREAD)
        self.assertEqual(self.recorded("tool.result"), [])
        out = a.invoke(Command(resume="yes"), THREAD)
        self.assertEqual(tool_message(out).content, "yes")
        self.assertEqual([r["status"] for r in self.recorded("tool.result")], ["ok"])

    def test_async_path(self):
        a = agent(self.signer, self.run)
        out = asyncio.run(a.ainvoke(prompt("echo", text="hi")))
        self.assertEqual((RAN, tool_message(out).content), (["echo"], "hi"))
        out = asyncio.run(a.ainvoke(prompt("wipe", path="/")))
        self.assertEqual(RAN, ["echo"])
        self.assertIn("R-WIPE", tool_message(out).content)
        self.assertEqual([r["status"] for r in self.recorded("tool.result")], ["ok"])


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ApprovalAcrossProcesses(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = d.name
        payload = self.step("start")["interrupt"]["tracekit"]
        self.assertEqual((payload["tool"], payload["rule_ids"]), ("pay", ["R-PAY"]))
        self.approval_id = payload["approval_id"]
        with saver(self.dir) as s:
            self.paused = s.get_tuple(THREAD)

    def step(self, *args):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [os.getcwd(), os.environ.get("PYTHONPATH")])))
        p = subprocess.run([sys.executable, __file__, *args[:1], self.dir, *args[1:]], capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout.splitlines()[-1])

    def resume(self, value, checkpoint_id=None):
        return self.step("resume", json.dumps(value), *([checkpoint_id] if checkpoint_id else []))

    def decide(self, decision="approve"):
        signer, run = load(self.dir)
        signer.approval_decide({"request_id": "human", "approval_id": self.approval_id, "decision": decision})
        save(signer, self.dir)
        return signer, run

    def test_approved_call_runs_exactly_once_in_a_new_process(self):
        self.decide()
        out = self.resume({"approval_id": self.approval_id})
        self.assertEqual((out["ran"], out["tool_message"], out["last"]), (["pay"], "paid 1500", "done"))
        signer, run = load(self.dir)
        self.assertEqual([e["data"]["approval_id"] for e in events(signer, run) if e["type"] == "approval.consumed"],
                         [self.approval_id])

    def test_rejected_call_does_not_run(self):
        self.decide("reject")
        out = self.resume({"approval_id": self.approval_id})
        self.assertEqual(out["ran"], [])
        self.assertIn("TK-APPROVAL-REJECTED", out["tool_message"])
        self.assertEqual(out["last"], "done")

    def test_replayed_snapshot_is_refused(self):
        self.decide()
        self.assertEqual(self.resume({"approval_id": self.approval_id})["ran"], ["pay"])
        out = self.resume({"approval_id": self.approval_id}, self.paused.config["configurable"]["checkpoint_id"])
        self.assertEqual(out["ran"], [])
        self.assertIn("TK-APPROVAL-CONSUMED", out["tool_message"])

    def test_args_edited_in_the_checkpoint_are_refused(self):
        self.decide()
        t = self.paused
        [send] = t.checkpoint["channel_values"]["__pregel_tasks"]
        send.arg[0]["args"]["cents"] = 1500000   # the pending tool call the resumed node executes
        with saver(self.dir) as s:
            s.put(t.parent_config, t.checkpoint, t.metadata, {})
        out = self.resume({"approval_id": self.approval_id})
        self.assertEqual(out["ran"], [])
        self.assertIn("TK-APPROVAL-MISMATCH", out["tool_message"])

    def test_resume_without_the_approval_id_is_still_refused(self):
        out = self.resume({"decision": "approve"})   # the app claims approval; the signer has none
        self.assertEqual(out["ran"], [])
        self.assertIn("TK-APPROVAL-REQUESTED", out["tool_message"])

    def test_another_approval_id_in_the_resume_value_is_refused(self):
        self.decide()
        out = self.resume({"approval_id": "apr-9999"})
        self.assertEqual(out["ran"], [])
        self.assertIn("TK-APPROVAL-UNBOUND", out["tool_message"])


if __name__ == "__main__":
    main(*sys.argv[1:])
