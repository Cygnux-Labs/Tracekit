"""The adapter contract (tests/adapter_contract.py) for the OpenAI Agents SDK adapter, with a stub model (no network).

A paused run is saved as RunState JSON (`to_string`) and resumed in a new process (`from_string`); this file is that
process's script.
"""
import asyncio
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit.sdk.client import Client, SignerUnavailable

try:
    from agents import (Agent, ApplyPatchTool, LocalShellTool, Model, ModelResponse, RunState, Runner, ShellTool,
                        WebSearchTool, function_tool, set_tracing_disabled)
    from agents._tool_invocation import tool_invocation_identity_and_scope   # private: tied to the pinned minor
    from agents.items import ToolCallOutputItem
    from agents.usage import Usage
    from openai.types.responses import (Response, ResponseApplyPatchToolCall, ResponseCompletedEvent,
                                        ResponseFunctionShellToolCall, ResponseFunctionToolCall,
                                        ResponseFunctionWebSearch, ResponseOutputMessage, ResponseOutputText)
    from openai.types.responses.response_output_item import LocalShellCall

    from tracekit.integrations.openai_agents import TracekitAgents
except ImportError:   # optional: the dev extra installs it
    HAVE_OA = False
else:
    HAVE_OA = True
    set_tracing_disabled(True)
    TOOLS = [function_tool(f, failure_error_function=None) for f in ac.TOOLS]   # tool exceptions reach the runner

    def _reply(input, first):
        if any(isinstance(i, dict) and i.get("type", "").endswith(("_call", "_output")) for i in input):
            return ResponseOutputMessage(id="msg_1", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done", annotations=[])])
        if first is not None:
            return first
        c = json.loads(next(i["content"] for i in input if i.get("role") == "user"))
        return ResponseFunctionToolCall(id="fc_1", call_id=c["id"], type="function_call", name=c["name"],
                                        arguments=json.dumps(c["args"]), status="completed")

    class StubModel(Model):
        """Makes `first`, or else the tool call in the user's JSON message, then answers "done"."""

        def __init__(self, first=None):
            self.first = first

        async def get_response(self, system_instructions, input, *a, **kw):
            return ModelResponse(output=[_reply(input, self.first)], usage=Usage(), response_id=None)

        async def stream_response(self, system_instructions, input, *a, **kw):
            r = Response(id="resp_1", created_at=0, model="stub", object="response", parallel_tool_calls=False,
                         tool_choice="auto", tools=[], output=[_reply(input, self.first)])
            yield ResponseCompletedEvent(type="response.completed", response=r, sequence_number=0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def agent(tk):
    return Agent(name="contract", model=StubModel(), tools=[tk.tool(t) for t in TOOLS])


async def _run(a, value, tk, mode, context=None):
    if mode != "stream":
        return await Runner.run(a, value, context=context, hooks=tk)
    res = Runner.run_streamed(a, value, context=context, hooks=tk)
    async for _ in res.stream_events():
        pass
    return res


def invoke(a, tk, value, mode="sync", context=None):
    """Run the agent; the contract's outcome and the paused RunState JSON, if it paused."""
    res = raised = None
    try:
        if mode == "sync":
            res = Runner.run_sync(a, value, context=context, hooks=tk)
        else:
            res = asyncio.run(_run(a, value, tk, mode, context))
    except Exception as e:
        e = e.__cause__ or e   # the SDK wraps a tool's exception
        raised = f"{type(e).__name__}: {e}"
    o = {"ran": list(ac.RAN), "seen": None, "is_error": False, "continued": False, "raised": raised, "approval_id": None}
    if res is not None and res.interruptions:
        cid = res.interruptions[0].raw_item.call_id
        o["approval_id"] = res.context_wrapper.context["tracekit"]["approvals"][cid]
        return o, res.to_state().to_string()
    if res is not None:
        seen = [i.output for i in res.new_items if isinstance(i, ToolCallOutputItem)]
        o.update(seen=seen[0], is_error=not o["ran"], continued=res.final_output == "done")
    return o, None


def _approvals(state):
    return state["context"]["context"]["tracekit"]["approvals"]


class Driver:
    SKIP = {"retry": "the SDK runs each tool call id once", "l1": "no Session/RunState wrapper yet (04-design §6 L1)"}
    modes = ("async", "stream")

    def __init__(self, case, signer_path):
        self.case, self.path, self.dir = case, signer_path, ac.tmpdir(case)
        self.signer = Client(signer_path)
        case.addCleanup(self.signer.close)
        r = self.signer.register_run({"agent": {"name": "contract"}})
        self._run = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.tk = TracekitAgents(self.signer, self._run)

    def run(self):
        return self._run

    def call(self, tool_name, args, tcid="call-1", mode="sync"):
        ac.RAN.clear()
        out, self.snapshot = invoke(agent(self.tk), self.tk, json.dumps({"name": tool_name, "args": args, "id": tcid}), mode, {})
        self.saved = self.snapshot   # what the app keeps in its database between processes
        return out

    def resume(self, hint=ac.HINT, replay=False):
        """In a new process, as a deployment resumes after a person decided."""
        state = json.loads(self.snapshot if replay else self.saved)
        if hint is None:
            _approvals(state).clear()
        elif hint is not ac.HINT:
            _approvals(state).update(dict.fromkeys(_approvals(state), hint))
        path = os.path.join(self.dir, "state.json")
        with open(path, "w") as f:
            json.dump(state, f)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [ROOT, os.environ.get("PYTHONPATH")])))
        p = subprocess.run([sys.executable, __file__, self.path, json.dumps(self._run), path], capture_output=True,
                           text=True, env=env, timeout=120)
        self.case.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout.splitlines()[-1])

    def tamper(self, args=None, tool_call_id=None):
        """Edit the paused call and recompute the SDK's own (unkeyed) fingerprint of it, so the SDK accepts it."""
        s = self.saved
        if args:
            s = s.replace(json.dumps(json.dumps(ac.PAY))[1:-1], json.dumps(json.dumps(args))[1:-1])
        if tool_call_id:
            s = s.replace('"call-1"', json.dumps(tool_call_id))   # the Tracekit hint moves with it
        state = json.loads(s)
        _, cid, _, fp = tool_invocation_identity_and_scope(state["current_step"]["data"]["interruptions"][0]["raw_item"])
        state["context"]["tool_invocations"][cid]["fingerprint"] = fp
        self.saved = json.dumps(state)


@unittest.skipUnless(HAVE_OA, "openai-agents not installed")
class TestOnFakeSigner(ac.Contract, ac.OnFake, unittest.TestCase):
    driver = Driver


@unittest.skipUnless(HAVE_OA, "openai-agents not installed")
class TestOnRealSigner(ac.Contract, ac.OnReal, unittest.TestCase):
    driver = Driver

    def test_c2_forged_fingerprint_is_refused_by_the_signer(self):
        self.approve(self.paused())
        self.d.tamper(args=dict(ac.PAY, cents=1500000))
        out = self.d.resume()
        self.refused(out, "TK-APPROVAL-MISMATCH")
        self.assertIsNone(out["raised"])   # the SDK's own check passed; the signer caught it

    def echo(self, tk):
        return invoke(agent(tk), tk, json.dumps({"name": "echo", "args": {"text": "hi"}, "id": "c1"}))[0]

    def test_signer_unreachable_follows_the_fail_mode(self):
        down = Client(os.path.join(ac.tmpdir(self), "none.sock"))
        self.addCleanup(down.close)
        with self.assertWarns(UserWarning):   # the model responses are not recorded either
            out = self.echo(TracekitAgents(down, {**self.d.run(), "fail_modes": {"default": "closed"}}))
        self.refused(out, "signer unavailable")
        with self.assertWarns(UserWarning):
            out = self.echo(TracekitAgents(down, {**self.d.run(), "fail_modes": {"default": "open"}}))
        self.assertEqual((out["ran"], out["seen"], out["continued"]), (["echo"], "hi", True))

    def test_closed_run_refuses_the_call(self):
        self.client.close_run(dict(self.d.run()))
        out = self.echo(TracekitAgents(self.d.signer, {**self.d.run(), "fail_modes": {"default": "open"}}))
        self.refused(out, "run_closed")

    def test_a_failed_complete_leaves_the_result_unchanged(self):
        signer = mock.Mock(wraps=self.d.signer)
        signer.complete.side_effect = SignerUnavailable("gone")
        tk = TracekitAgents(signer, self.d.run())
        with self.assertWarns(UserWarning):
            out = self.echo(tk)
        self.assertEqual((out["ran"], out["seen"], out["raised"]), (["echo"], "hi", None))
        with self.assertWarns(UserWarning):
            out = invoke(agent(tk), tk, json.dumps({"name": "fail", "args": {"why": "boom"}, "id": "c2"}))[0]
        self.assertEqual(out["raised"], "ValueError: boom")


@unittest.skipUnless(HAVE_OA, "openai-agents not installed")
class TestOtherTools(ac.OnReal, unittest.TestCase):
    """Shell and apply_patch tools, the model events, and tools that run outside the process."""

    def setUp(self):
        self.client = Client(self.serve_signer())
        self.addCleanup(self.client.close)
        r = self.client.register_run({"agent": {"name": "tools"}})
        self.run_ = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.tk, self.ran = TracekitAgents(self.client, self.run_), []

    def go(self, first, tool, value="go"):
        a = Agent(name="tools", model=StubModel(first), tools=[self.tk.tool(tool)])
        return a, Runner.run_sync(a, value, context={}, hooks=self.tk)

    def test_shell_pauses_for_approval_and_runs_once_approved(self):
        call = ResponseFunctionShellToolCall(id="sh_1", call_id="sh-1", type="shell_call", status="completed",
                                             action={"commands": ["make pay"]})
        a, res = self.go(call, ShellTool(name="pay", executor=lambda req: self.ran.append(req.data.action.commands)
                                         or "paid"))
        state = res.to_state()
        self.assertEqual(len(asyncio.run(self.tk.apply_decisions(state))), 1)   # nobody decided yet
        aid = res.context_wrapper.context["tracekit"]["approvals"]["sh-1"]
        self.client.approval_decide({"approval_id": aid, "decision": "approve"})
        self.assertEqual(asyncio.run(self.tk.apply_decisions(state)), [])
        res = Runner.run_sync(a, state, hooks=self.tk)
        self.assertEqual((self.ran, res.final_output), ([["make pay"]], "done"))
        types = [e["type"] for e in self.events(self.run_)]
        self.assertEqual((types.count("approval.consumed"), types.count("tool.result")), (1, 1))
        self.assertEqual(types.count("model.exchange"), 2)   # T3: the shell call, then "done"

    def test_apply_patch_runs_when_allowed_and_refuses_an_ask(self):
        class Editor:
            def create_file(_, op):
                self.ran.append(op.path)
                return "created"
        call = ResponseApplyPatchToolCall(id="ap_1", call_id="ap-1", type="apply_patch_call", status="completed",
                                          operation={"type": "create_file", "path": "a.txt", "diff": "+hi"})
        _, res = self.go(call, ApplyPatchTool(editor=Editor()))
        self.assertEqual((self.ran, res.new_items[1].output), (["a.txt"], "created"))
        _, res = self.go(call, ApplyPatchTool(name="pay", editor=Editor()))
        self.assertEqual(self.ran, ["a.txt"])
        self.assertIn("cannot wait", res.new_items[1].output)

    def test_local_shell_runs_when_allowed_and_refuses_an_ask(self):
        class PayShell(LocalShellTool):
            name = "pay"   # the policy asks for `pay`
        call = LocalShellCall(id="ls_1", call_id="ls-1", type="local_shell_call", status="completed",
                              action={"type": "exec", "command": ["ls"], "env": {}})
        _, res = self.go(call, LocalShellTool(executor=lambda req: self.ran.append(req.data.action.command) or "ok"))
        self.assertEqual((self.ran, res.final_output), ([["ls"]], "done"))
        _, res = self.go(call, PayShell(executor=lambda req: self.ran.append("pay") or "paid"))
        self.assertEqual(self.ran, [["ls"]])
        self.assertIn("cannot wait", res.new_items[1].output)

    def test_hosted_tools_are_not_gated_but_listed_in_the_model_event(self):
        with self.assertRaises(TypeError):
            self.tk.tool(WebSearchTool())
        call = ResponseFunctionWebSearch(id="ws_1", type="web_search_call", status="completed",
                                         action={"type": "search", "query": "q"})
        self.go(call, lambda: None)
        [first, *_] = [e["data"] for e in self.events(self.run_) if e["type"] == "model.exchange"]
        self.assertEqual(first["tool_uses"], [{"id": "ws_1", "name": "web_search", "executed_by": "provider"}])


if __name__ == "__main__":
    path, run, state_path = sys.argv[1:]
    tk = TracekitAgents(Client(path), json.loads(run))

    async def resume():
        a = agent(tk)
        with open(state_path) as f:
            state = await RunState.from_string(a, f.read())
        for item in await tk.apply_decisions(state):
            state.approve(item)   # an app that resumes as approved without asking the signer
        return a, state
    a, state = asyncio.run(resume())
    print(json.dumps(invoke(a, tk, state)[0]))
