"""Google ADK's plugin hooks (tracekit.integrations.google_adk) on a real Runner with a scripted model and a mock run:
only an allow or an approved ask runs the tool, on every tool path ADK has, the model reads the reason for anything
else and the run goes on, and nothing Tracekit fails at raises into the agent."""
import asyncio
import importlib.util
import json
import os
import sys
import threading
import unittest
import warnings
from typing import Any
from unittest import mock

import adapter_contract as ac
import test_said as ts

HAVE = importlib.util.find_spec("google") is not None and importlib.util.find_spec("google.adk") is not None
if HAVE:
    from google.adk.agents import LlmAgent
    from google.adk.apps import App
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.adk.plugins.base_plugin import BasePlugin
    from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin
    from google.adk.runners import InMemoryRunner
    from google.adk.tools import FunctionTool, LongRunningFunctionTool, ToolContext
    from google.adk.tools.agent_tool import AgentTool
    from google.adk.workflow import START, Workflow
    from google.genai import types
    from pydantic import BaseModel

    from tracekit.integrations.google_adk import Tracekit

    class Model(BaseLlm):
        """A model that answers each request with script(the request's contents)."""
        model: str = "scripted"
        script: Any = None

        async def generate_content_async(self, llm_request, stream=False):
            yield LlmResponse(content=self.script(llm_request.contents))

from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    """A mock run; its decisions ask for each tool's result itself (send_result), so tests read what is recorded."""
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1",
                             "send_result": True, **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def calls(*fcs):
    """The model's turn: these function calls, each (name, args, id)."""
    return types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name=n, args=a, id=i))
                                              for n, a, i in fcs])


def back(contents, name=None):
    """The function responses in the request (to `name`'s calls only, when given)."""
    return [p.function_response for c in contents for p in c.parts or ()
            if p.function_response and name in (None, p.function_response.name)]


def once(name="close_account", args=None, call_id="call-1"):
    """A script that calls `name` once (with `args`, default {"account": "ACC-9"}) and then answers with the JSON of
    every response it got."""
    def script(contents):
        got = back(contents)
        if not got:
            return calls((name, {"account": "ACC-9"} if args is None else args, call_id))
        return types.Content(role="model", parts=[types.Part(text=json.dumps([g.response for g in got]))])
    return script


def runner(plugins, tools=(), script=None, root=None, **agent):
    root = root or LlmAgent(name="agent", model=Model(script=script or once()), tools=list(tools), **agent)
    return InMemoryRunner(app=App(name="test", root_agent=root, plugins=plugins))


async def turn(r, message="close it", session="s"):
    """One user turn on session `session`; its events."""
    if not await r.session_service.get_session(app_name="test", user_id="u", session_id=session):
        await r.session_service.create_session(app_name="test", user_id="u", session_id=session)
    if isinstance(message, str):
        message = types.Content(role="user", parts=[types.Part(text=message)])
    return [e async for e in r.run_async(user_id="u", session_id=session, new_message=message)]


def answer(plugins, tools=(), script=None, **agent):
    """The model's last text: the JSON of the tool responses it read."""
    events = asyncio.run(turn(runner(plugins, tools, script, **agent)))
    return json.loads(next(e.content.parts[0].text for e in reversed(events) if e.content and e.content.parts[0].text))


@unittest.skipUnless(HAVE, "google-adk not installed")
class Hook(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        return close_account

    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                self.ran.clear()
                out = answer([Tracekit(r)], [self.tool()])
                self.assertEqual(self.ran, ["ACC-9"] if runs else [])
                if runs:
                    self.assertEqual(out, [{"result": "closed ACC-9"}])
                    r.complete.assert_called_once_with("call-1", "ok", attempt=0, result={"result": "closed ACC-9"})
                else:
                    self.assertIn("Tracekit policy", out[0]["error"])
                    if name == "consume refused":   # allowed, then refused: completed as not run
                        r.complete.assert_called_once_with("call-1", "error", attempt=0, error=mock.ANY)
                    else:
                        r.complete.assert_not_called()

    def test_the_signer_decides_the_models_arguments_under_adks_call_id(self):
        r = run()
        answer([Tracekit(r)], [self.tool()])
        r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, attempt=0)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint=None, attempt=0)
        r = run()
        answer([Tracekit(r)], [self.tool()], once(args={}, call_id=None))   # no id from the model: ADK gives one
        call_id, tool, args = r.decide.call_args.args
        self.assertEqual((call_id[:4], tool, args), ("adk-", "close_account", {}))
        r.complete.assert_called_once_with(call_id, "ok", attempt=0, result=mock.ANY)

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        answer([Tracekit(r)], [self.tool()])
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", attempt=0)

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", answer([Tracekit(r)], [self.tool()])[0]["error"])
        self.assertEqual([c.args[0] for c in r.call.call_args_list if c.args[0] != "model_event"][-1],
                         "approval_abandon")

    def test_the_refusal_is_the_tools_error_result_and_names_the_rules_but_not_the_unknown_tool_flag(self):
        out = answer([Tracekit(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]))], [self.tool()])
        self.assertEqual(out, [{"error": "Tool call blocked by Tracekit policy: TK-D001"}])

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", answer([Tracekit(r)], [self.tool()])[0]["error"])
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(answer([Tracekit(r)], [self.tool()]), [{"result": "closed ACC-9"}])

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = answer([Tracekit(run("deny", unavailable=True, reason="signer unavailable: down"))], [self.tool()])
        self.assertEqual(out, [{"error": "Tool call refused by Tracekit: signer unavailable: down"}])
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(answer([Tracekit(r)], [self.tool()]), [{"result": "closed ACC-9"}])
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_reaches_adk_unchanged(self):
        def close_account(account: str) -> str:
            """Close an account."""
            raise ValueError("account is locked")
        r = run()
        with self.assertRaisesRegex(ValueError, "account is locked"):
            answer([Tracekit(r)], [close_account])
        r.complete.assert_called_once_with("call-1", "error", attempt=0, error="ValueError: account is locked")

    def test_adks_retry_plugin_retries_under_a_new_call_id_and_a_new_decision(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            if len(self.ran) == 1:
                raise ValueError("account is locked, try again")
            return f"closed {account}"

        def script(contents):
            got = back(contents)
            if len(got) < 2:
                return calls(("close_account", {"account": "ACC-9"}, f"call-{len(got) + 1}"))
            return types.Content(role="model", parts=[types.Part(text=json.dumps([g.response for g in got]))])
        r = run()
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded, and Tracekit listed first
            out = answer([Tracekit(r), ReflectAndRetryToolPlugin()], [close_account], script)
        self.assertEqual(out[-1], {"result": "closed ACC-9"})
        self.assertEqual([c.args[0] for c in r.decide.call_args_list], ["call-1", "call-2"])
        self.assertEqual([c.args[:2] for c in r.complete.call_args_list], [("call-1", "error"), ("call-2", "ok")])

    def test_async_tools_and_parallel_calls_are_each_decided(self):
        async def lookup(account: str) -> dict:
            """Look an account up."""
            self.ran.append(account)
            return {"account": account, "open": True}
        r = run()

        def script(contents):
            if not back(contents):
                return calls(("lookup", {"account": "ACC-1"}, "call-1"), ("lookup", {"account": "ACC-2"}, "call-2"))
            return types.Content(role="model", parts=[types.Part(text="[]")])
        answer([Tracekit(r)], [lookup], script)
        self.assertEqual(sorted(self.ran), ["ACC-1", "ACC-2"])
        self.assertEqual(sorted(c.args for c in r.decide.call_args_list),
                         [("call-1", "lookup", {"account": "ACC-1"}), ("call-2", "lookup", {"account": "ACC-2"})])
        self.assertEqual(sorted(c.kwargs["result"]["account"] for c in r.complete.call_args_list), ["ACC-1", "ACC-2"])

    def test_arguments_a_later_callback_changes_are_recorded_as_changed(self):
        class Rewrite(BasePlugin):
            async def before_tool_callback(self, *, tool, tool_args, tool_context):
                tool_args["account"] = "ACC-1"

        def rewrite(tool, args, tool_context):
            args["account"] = "ACC-1"
        for name, plugins, agent in (("a later plugin", [Rewrite(name="rewrite")], {}),
                                     ("the agent's before_tool_callback", [], {"before_tool_callback": rewrite})):
            with self.subTest(name):
                self.ran.clear()
                r = run()
                answer([Tracekit(r), *plugins], [self.tool()], **agent)
                r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, attempt=0)
                self.assertEqual(self.ran, ["ACC-1"])
                r.complete.assert_called_once_with("call-1", "error", attempt=0,
                                                   error="the call's arguments changed after the decision")

    def test_a_call_another_callback_answers_after_the_decision_completes_with_that_answer(self):
        def cached(tool, args, tool_context):
            return {"result": "closed ACC-9 (cached)"}
        r = run()
        self.assertEqual(answer([Tracekit(r)], [self.tool()], before_tool_callback=cached),
                         [{"result": "closed ACC-9 (cached)"}])
        self.assertEqual(self.ran, [])
        r.complete.assert_called_once_with("call-1", "ok", attempt=0, result={"result": "closed ACC-9 (cached)"})

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", answer([Tracekit(r)], [self.tool()])[0]["error"])
        self.assertEqual(self.ran, [])

    def test_a_run_cancelled_during_an_ask_withdraws_the_approval(self):
        waiting, answered = threading.Event(), threading.Event()
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                waiting.set()
                answered.wait(5)
                return {"state": "approved"}
            return {"approval_request": {"approval_id": "apr-1"}, "approval_abandon": {}, "model_event": {}}[method]
        r.call.side_effect = call

        async def go():
            task = asyncio.ensure_future(turn(runner([Tracekit(r)], [self.tool()])))
            self.assertTrue(await asyncio.to_thread(waiting.wait, 5))   # in the ask, however slow the runner
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            answered.set()   # a person approves after the agent run was cancelled
        asyncio.run(go())   # returns once the approval_wait thread has (asyncio.run waits for its executor)
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])


@unittest.skipUnless(HAVE, "google-adk not installed")
class Said(unittest.TestCase):
    """Each model response event is recorded: thought summaries, signatures (sealed), text and function calls, under
    the ids ADK gives the calls and the plugin decides them by; the response itself only with the vault; a failure to
    record changes nothing for the agent."""

    @staticmethod
    def script(contents):
        if back(contents):
            return types.Content(role="model", parts=[types.Part(text="done")])
        return types.Content(role="model", parts=[
            types.Part(text="the user wants ACC-9 closed", thought=True),
            types.Part(text="Closing ACC-9."),
            types.Part(function_call=types.FunctionCall(name="close_account", args={"account": "ACC-9"}),
                       thought_signature=b"sig-1")])   # no id: ADK gives it one

    def answer(self, r):
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        events = asyncio.run(turn(runner([Tracekit(r)], [close_account], self.script)))
        return events[-1].content.parts[0].text

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        r = ts.vault(run())
        self.assertEqual(self.answer(r), "done")
        first, last = ts.recorded(r)
        decided = r.decide.call_args.args[0]
        self.assertTrue(decided.startswith("adk-"))
        self.assertEqual([t["id"] for t in first["tool_uses"]], [decided])
        self.assertEqual(ts.segments(first), [("reasoning", "summary", "the user wants ACC-9 closed", []),
                                              ("text", "full", "Closing ACC-9.", []),
                                              ("reasoning", "encrypted", "", [decided])])
        self.assertEqual(ts.segments(last), [("text", "full", "done", [])])

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.answer(r)
        self.assertTrue(all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.answer(r), "done")


@unittest.skipUnless(HAVE, "google-adk not installed")
class Paths(unittest.TestCase):
    """Every tool path ADK runs through its plugin callbacks: sub-agents, agents as tools, MCP tools, workflow tool
    nodes, long-running tools, made-up tools, and the calls ADK pauses for the user (tool confirmation, credentials)."""

    def setUp(self):
        self.ran = []

    def tool(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        return close_account

    def helper(self):
        """A sub-agent whose model closes ACC-9 and then says what it got back."""
        def script(contents):
            got = back(contents, "close_account")
            if not got:
                return calls(("close_account", {"account": "ACC-9"}, "sub-1"))
            return types.Content(role="model", parts=[types.Part(text=str(got[0].response))])
        return LlmAgent(name="helper", description="Closes accounts.", model=Model(script=script), tools=[self.tool()])

    def test_a_sub_agent_and_an_agent_run_as_a_tool_are_gated(self):
        for name, root_call, agent in (("sub-agent", ("transfer_to_agent", {"agent_name": "helper"}),
                                        lambda h: {"sub_agents": [h]}),
                                       ("agent as a tool", ("helper", {"request": "close ACC-9"}),
                                        lambda h: {"tools": [AgentTool(agent=h)]})):
            with self.subTest(name):
                self.ran.clear()
                r = run()
                script = once(*root_call, call_id="root-1")
                asyncio.run(turn(runner([Tracekit(r)], root=LlmAgent(name="agent", model=Model(script=script),
                                                                     **agent(self.helper())))))
                self.assertEqual(self.ran, ["ACC-9"])
                self.assertEqual([c.args for c in r.decide.call_args_list],
                                 [("root-1", *root_call), ("sub-1", "close_account", {"account": "ACC-9"})])
                self.assertEqual(sorted(c.args for c in r.complete.call_args_list), [("root-1", "ok"), ("sub-1", "ok")])

    def test_a_denied_sub_agent_tool_never_runs(self):
        r = run()
        r.decide.side_effect = lambda call_id, tool, args, **at: (
            {"decision": "deny", "rule_ids": ["D1"]} if tool == "close_account" else run().decide.return_value)
        script = once("helper", {"request": "close ACC-9"}, "root-1")
        out = asyncio.run(turn(runner([Tracekit(r)], root=LlmAgent(name="agent", model=Model(script=script),
                                                                   tools=[AgentTool(agent=self.helper())]))))
        self.assertEqual(self.ran, [])
        self.assertIn("Tool call blocked by Tracekit policy: D1", json.dumps([e.model_dump(mode="json") for e in out]))

    def test_handing_a_task_to_a_task_mode_sub_agent_is_not_decided_but_its_tools_are(self):
        """Not covered (docs/integrations/google-adk.md): ADK runs a task-mode sub-agent outside the tool callbacks."""
        r = run()
        r.decide.side_effect = lambda call_id, tool, args, **at: (
            {"decision": "deny", "rule_ids": ["D1"]} if tool in ("helper", "close_account")
            else run().decide.return_value)

        def task(contents):
            if not back(contents, "close_account"):
                return calls(("close_account", {"account": "ACC-9"}, "sub-1"))
            return calls(("finish_task", {"result": "done"}, "sub-2"))
        helper = LlmAgent(name="helper", description="Closes accounts.", mode="task", model=Model(script=task),
                          tools=[self.tool()])
        asyncio.run(turn(runner([Tracekit(r)], root=LlmAgent(name="agent", model=Model(script=once("helper", {
            "request": "close ACC-9"}, "root-1")), sub_agents=[helper]))))
        self.assertEqual([c.args[:2] for c in r.decide.call_args_list], [("sub-1", "close_account"),
                                                                         ("sub-2", "finish_task")])
        self.assertEqual(self.ran, [])

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "mcp not installed")
    def test_an_mcp_toolsets_tools_are_gated(self):
        from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
        from mcp import StdioServerParameters
        server = os.path.join(ac.tmpdir(self), "server.py")
        with open(server, "w") as f:
            f.write("from mcp.server.mcpserver import MCPServer\nS = MCPServer('files')\n\n"
                    "@S.tool()\ndef read_file(path: str) -> str:\n    return 'contents of ' + path\n\n"
                    "@S.tool()\ndef delete_file(path: str) -> str:\n    raise SystemExit('never runs')\n\nS.run()\n")
        r = run()
        r.decide.side_effect = lambda call_id, tool, args, **at: (
            {"decision": "deny", "rule_ids": ["D1"]} if tool == "delete_file" else run().decide.return_value)
        toolset = McpToolset(connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(command=sys.executable, args=[server]), timeout=30))

        def script(contents):
            if not back(contents):
                return calls(("read_file", {"path": "a.txt"}, "m-1"), ("delete_file", {"path": "a.txt"}, "m-2"))
            return types.Content(role="model", parts=[types.Part(text="done")])

        async def go():
            rn = runner([Tracekit(r)], [toolset], script)
            try:
                await turn(rn)
            finally:
                await rn.close()
        asyncio.run(go())
        self.assertEqual(sorted(c.args[:2] for c in r.decide.call_args_list),
                         [("m-1", "read_file"), ("m-2", "delete_file")])
        r.complete.assert_called_once()
        self.assertEqual(r.complete.call_args.args, ("m-1", "ok"))
        self.assertIn("contents of a.txt", json.dumps(r.complete.call_args.kwargs["result"]))

    def test_a_workflow_tool_node_is_gated(self):
        r = run("deny", ["D1"])
        wf = Workflow(name="wf", edges=[(START, FunctionTool(self.tool()))])
        asyncio.run(turn(runner([Tracekit(r)], root=wf), '{"account": "ACC-9"}'))
        self.assertEqual(self.ran, [])
        self.assertEqual(r.decide.call_args.args[1:], ("close_account", {"account": "ACC-9"}))
        r = run()
        asyncio.run(turn(runner([Tracekit(r)], root=wf), '{"account": "ACC-9"}'))
        self.assertEqual(self.ran, ["ACC-9"])
        r.complete.assert_called_once_with(r.decide.call_args.args[0], "ok", attempt=0,
                                           result={"result": "closed ACC-9"})

    def test_a_long_running_tool_is_recorded_with_what_it_returned(self):
        def open_ticket(account: str) -> dict:
            """Open a ticket to close an account."""
            return {"status": "pending", "ticket": "T-1"}
        r = run()
        answer([Tracekit(r)], [LongRunningFunctionTool(open_ticket)], once("open_ticket"))
        r.complete.assert_called_once_with("call-1", "ok", attempt=0, result={"status": "pending", "ticket": "T-1"})

    def confirm(self, r, confirmed):
        """A tool that needs ADK's tool confirmation, called once; the user answers `confirmed`. The events of both
        turns."""
        rn = runner([Tracekit(r)], [FunctionTool(self.tool(), require_confirmation=True)])

        async def go():
            first = await turn(rn)
            ask = next(c for e in first for c in e.get_function_calls() if c.name == "adk_request_confirmation")
            reply = types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
                name="adk_request_confirmation", id=ask.id, response={"confirmed": confirmed}))])
            return first, await turn(rn, reply)
        return asyncio.run(go())

    def test_adks_tool_confirmation_pauses_without_completing_and_the_resumed_call_is_its_next_attempt(self):
        r = run()
        self.confirm(r, True)
        self.assertEqual(self.ran, ["ACC-9"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1, result={"result": "closed ACC-9"})

    def test_a_call_rejected_in_adks_tool_confirmation_never_runs_and_completes_as_an_error(self):
        r = run()
        self.confirm(r, False)
        self.assertEqual(self.ran, [])
        r.complete.assert_called_once_with("call-1", "error", attempt=1, error="rejected in ADK's tool confirmation")

    def test_a_tool_that_asks_for_confirmation_itself_and_runs_on_a_rejection_completes_with_its_result(self):
        def refund(amount: int, tool_context: ToolContext) -> str:
            """Refund."""
            if tool_context.tool_confirmation is None:
                tool_context.request_confirmation(hint="a big refund?")
                return "waiting"
            if not tool_context.tool_confirmation.confirmed:
                self.ran.append("ticket")
                return "rejected: filed ticket T-9 instead"
            return "refunded"
        r = run()
        rn = runner([Tracekit(r)], [refund], once("refund", {"amount": 500}))

        async def go():
            first = await turn(rn)
            ask = next(c for e in first for c in e.get_function_calls() if c.name == "adk_request_confirmation")
            await turn(rn, types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
                name="adk_request_confirmation", id=ask.id, response={"confirmed": False}))]))
        asyncio.run(go())
        self.assertEqual(self.ran, ["ticket"])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1,
                                           result={"result": "rejected: filed ticket T-9 instead"})

    def test_a_call_waiting_for_credentials_is_not_completed_and_its_rerun_is_its_next_attempt(self):
        from fastapi.openapi.models import APIKey
        from google.adk.auth.auth_credential import AuthCredential, AuthCredentialTypes
        from google.adk.auth.auth_tool import AuthConfig
        config = AuthConfig(auth_scheme=APIKey(**{"in": "header", "name": "X-Key"}),
                            raw_auth_credential=AuthCredential(auth_type=AuthCredentialTypes.API_KEY))

        def read_mail(folder: str, tool_context: ToolContext) -> str:
            """Read mail."""
            self.ran.append(folder)
            if not tool_context.get_auth_response(config):
                tool_context.request_credential(config)
                return "Pending User Authorization."
            return f"mail in {folder}"
        r = run()
        rn = runner([Tracekit(r)], [read_mail], once("read_mail", {"folder": "inbox"}))

        async def go():
            ask = next(c for e in await turn(rn) for c in e.get_function_calls() if c.name == "adk_request_credential")
            r.complete.assert_not_called()   # waits for the user's credentials: not run to its end yet
            given = config.model_copy(update={"exchanged_auth_credential": AuthCredential(
                auth_type=AuthCredentialTypes.API_KEY, api_key="k-1")})
            reply = types.FunctionResponse(name="adk_request_credential", id=ask.id,
                                           response=given.model_dump(exclude_none=True, by_alias=True))
            await turn(rn, types.Content(role="user", parts=[types.Part(function_response=reply)]))
        asyncio.run(go())
        self.assertEqual(self.ran, ["inbox", "inbox"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1, result={"result": "mail in inbox"})

    def test_a_tool_the_model_made_up_is_decided_and_completes_as_an_error(self):
        r = run()
        out = answer([Tracekit(r)], [self.tool()], once("no_such_tool", {}))
        self.assertIn("no tool with that name", out[0]["error"])
        r.decide.assert_called_once_with("call-1", "no_such_tool", {}, attempt=0)
        self.assertEqual(r.complete.call_args.args, ("call-1", "error"))

    def test_a_call_tracekit_refuses_never_reaches_adks_tool_confirmation(self):
        r = run("deny", ["D1"])
        out = answer([Tracekit(r)], [FunctionTool(self.tool(), require_confirmation=True)])
        self.assertEqual(out, [{"error": "Tool call blocked by Tracekit policy: D1"}])


@unittest.skipUnless(HAVE, "google-adk not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).run, sync)

    def test_a_plugin_listed_before_tracekit_is_warned_about_once(self):
        def close_account(account: str) -> str:
            """Close an account."""
            return "closed"
        t = Tracekit(run())
        with self.assertWarnsRegex(UserWarning, "list Tracekit first"):
            answer([BasePlugin(name="logger"), t], [close_account])
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")
            answer([BasePlugin(name="logger2"), t], [close_account])

    def test_import_tracekit_does_not_import_adk(self):
        import subprocess
        p = subprocess.run([sys.executable, "-c", "import sys, tracekit, tracekit.sdk.client; "
                                                  "print('google.adk' in sys.modules)"], capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "False", p.stderr)


@unittest.skipUnless(HAVE, "google-adk not installed")
class RealSigner(unittest.TestCase):
    """On a real signer: values an untrusted tool's result carries reach the provenance index, and a call resumed after
    ADK's tool confirmation is decided and completed as its next attempt."""

    def client(self, policy):
        s = SignerService(ac.tmpdir(self), policy=Engine(policy))
        self.addCleanup(s.close)
        return s, Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))

    def test_a_payee_from_an_untrusted_tools_result_is_traced_to_it(self):
        s, client = self.client({"untrusted": ["WebFetch"]})

        class Page(BaseModel):
            title: str
            pay_to: str

        def WebFetch(url: str) -> Page:   # noqa: N802 - the policy's untrusted tool
            """Fetch a page."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")

        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"

        def script(contents):
            got = back(contents)
            if not got:
                return calls(("WebFetch", {"url": "https://docs.example.org/i"}, "w-1"))
            if len(got) == 1:
                return calls(("pay", {"to": "mallory-acct-7731"}, "w-2"))
            return types.Content(role="model", parts=[types.Part(text="done")])
        with client.run(agent="provenance") as r:
            asyncio.run(turn(runner([Tracekit(r)], [WebFetch, pay], script)))
            rid = r.run_id
        d = next(e["event"]["data"] for e in s.log.storage.iter_run("default", rid)
                 if e["event"]["type"] == "policy.decision" and e["event"].get("tool_call_id") == "w-2")
        self.assertEqual([p["source"]["tool"] for p in d["provenance"]], ["WebFetch"])

    def test_a_call_resumed_after_adks_tool_confirmation_completes_as_its_next_attempt(self):
        s, client = self.client({})
        ran = []

        def close_account(account: str) -> str:
            """Close an account."""
            ran.append(account)
            return f"closed {account}"
        with client.run(agent="confirmation") as r:
            rn = runner([Tracekit(r)], [FunctionTool(close_account, require_confirmation=True)])

            async def go():
                first = await turn(rn)
                ask = next(c for e in first for c in e.get_function_calls() if c.name == "adk_request_confirmation")
                await turn(rn, types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
                    name="adk_request_confirmation", id=ask.id, response={"confirmed": True}))]))
            asyncio.run(go())
            rid = r.run_id
        self.assertEqual(ran, ["ACC-9"])
        done = [(e["event"]["type"], e["event"].get("attempt", 0)) for e in s.log.storage.iter_run("default", rid)
                if e["event"].get("tool_call_id") == "call-1"
                and e["event"]["type"] in ("policy.decision", "tool.result")]
        self.assertEqual(done, [("policy.decision", 0), ("policy.decision", 1), ("tool.result", 1)])


@unittest.skipUnless(HAVE, "google-adk not installed")
class VersionCheck(unittest.TestCase):
    """The version check the integration shares with the other hand-wired ones: a framework outside the version
    Tracekit is tested with warns once when the integration is built, one inside the range does not warn."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.google_adk import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.0.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("Google ADK 0.0.1 is wired but untested; Tracekit is tested with google-adk>=2.12,<2.13", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.google_adk import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="2.12.0"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])


if __name__ == "__main__":
    unittest.main()
