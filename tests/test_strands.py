"""Strands Agents' tool-call hooks (tracekit.integrations.strands) on a real Agent with a scripted model and a mock run:
only an allow or an approved ask runs the tool, the model reads the reason for anything else and the run goes on, and
nothing Tracekit fails at raises into the agent."""
import asyncio
import importlib.util
import json
import math
import subprocess
import sys
import threading
import unittest
import warnings
from unittest import mock

import adapter_contract as ac
import test_said as ts

HAVE = importlib.util.find_spec("strands") is not None
if HAVE:
    from mcp.types import Tool as MCPTool
    from pydantic import BaseModel
    from strands import Agent, tool
    from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookOrder
    from strands.models import Model
    from strands.multiagent import GraphBuilder, Swarm
    from strands.tools.executors import SequentialToolExecutor
    from strands.tools.mcp import MCPAgentTool

    from tracekit.integrations.strands import Tracekit

    class Scripted(Model):
        """A model that asks for each turn's tool uses [(toolUseId, name, input)] in turn, and then answers with the
        text of the last results it was sent."""

        def __init__(self, *turns):
            self.turns = turns

        def update_config(self, **config):
            pass

        def get_config(self):
            return {}

        async def structured_output(self, *a, **k):
            raise NotImplementedError
            yield

        async def stream(self, messages, *a, **k):
            done = sum(any("toolResult" in c for c in m["content"]) for m in messages)
            uses = self.turns[done] if done < len(self.turns) else ()
            yield {"messageStart": {"role": "assistant"}}
            for i, name, args in uses:
                yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": i, "name": name}}}}
                yield {"contentBlockDelta": {"delta": {"toolUse": {"input": args if isinstance(args, str)
                                                                   else json.dumps(args)}}}}
                yield {"contentBlockStop": {}}
            if not uses:
                text = " | ".join(c.get("text", "") for b in messages[-1]["content"] if "toolResult" in b
                                  for c in b["toolResult"]["content"])
                yield {"contentBlockDelta": {"delta": {"text": text}}}
                yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use" if uses else "end_turn"}}

from tracekit.format.canon import event_hash
from tracekit.gateway import result_forms
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService

CLOSE = ("call-1", "close_account", {"account": "ACC-9"})


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def agent(r, *tools, uses=(CLOSE,), **kw):
    return Agent(model=Scripted(list(uses)), tools=list(tools), hooks=[Tracekit(r)], callback_handler=None, **kw)


@unittest.skipUnless(HAVE, "strands not installed")
class Hook(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self):
        @tool
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
                out = str(agent(r, self.tool())("close it")).strip()
                self.assertEqual(self.ran, ["ACC-9"] if runs else [])
                if runs:
                    self.assertEqual(out, "closed ACC-9")
                    r.complete.assert_called_once_with("call-1", "ok", attempt=0, result=mock.ANY)
                else:
                    self.assertIn("Tracekit policy", out)
                    if name == "consume refused":   # allowed, then refused: completed as not run
                        r.complete.assert_called_once_with("call-1", "error", attempt=0, error=mock.ANY)
                    else:
                        r.complete.assert_not_called()

    def test_the_signer_decides_the_models_own_call(self):
        r = run()
        agent(r, self.tool())("close it")
        r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, attempt=0)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint=None, attempt=0)

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        agent(r, self.tool())("close it")
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", attempt=0)

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", str(agent(r, self.tool())("close it")))
        self.assertEqual([c.args[0] for c in r.call.call_args_list if c.args[0] != "model_event"][-1],
                         "approval_abandon")

    def test_a_refusal_is_an_error_result_naming_the_rules_but_not_the_unknown_tool_flag(self):
        a = agent(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool())
        a("close it")
        result = next(c["toolResult"] for m in a.messages for c in m["content"] if "toolResult" in c)
        self.assertEqual((result["status"], result["content"]),
                         ("error", [{"text": "Tool call blocked by Tracekit policy: TK-D001"}]))

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", str(agent(r, self.tool())("close it")))
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(str(agent(r, self.tool())("close it")).strip(), "closed ACC-9")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = str(agent(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool())("x")).strip()
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(str(agent(r, self.tool())("x")).strip(), "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_reaches_the_model_unchanged(self):
        @tool
        def close_account(account: str) -> str:
            """Close an account."""
            raise RuntimeError("account is locked")
        r = run()
        self.assertEqual(str(agent(r, close_account)("close it")).strip(), "Error: RuntimeError - account is locked")
        r.complete.assert_called_once_with("call-1", "error", attempt=0, error="RuntimeError: account is locked")

    def test_a_hooks_retry_is_decided_as_the_calls_next_attempt(self):
        r = run()
        a = agent(r, self.tool())
        a.add_hook(lambda e: setattr(e, "retry", len(self.ran) == 1), AfterToolCallEvent)
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            a("close it")
        self.assertEqual(self.ran, ["ACC-9", "ACC-9"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        self.assertEqual([(c.args, c.kwargs["attempt"]) for c in r.complete.call_args_list],
                         [(("call-1", "ok"), 0), (("call-1", "ok"), 1)])

    def test_an_interrupted_call_resumed_is_decided_as_its_next_attempt(self):
        def confirm(event: BeforeToolCallEvent):
            if event.interrupt("confirm", reason="close it?") != "yes":
                event.cancel_tool = "not confirmed"
        r = run()
        a = agent(r, self.tool())
        a.add_hook(confirm)
        first = a("close it")
        self.assertEqual((first.stop_reason, self.ran), ("interrupt", []))
        r.complete.assert_not_called()   # not run yet: resumed, it is the next attempt
        a([{"interruptResponse": {"interruptId": first.interrupts[0].id, "response": "yes"}}])
        self.assertEqual(self.ran, ["ACC-9"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1, result=mock.ANY)

    def test_an_empty_input_is_no_arguments(self):
        @tool
        def close_account(account: str = "ACC-0") -> str:
            """Close an account."""
            return f"closed {account}"
        r = run()
        agent(r, close_account, uses=[("call-1", "close_account", "")])("close it")
        self.assertEqual(r.decide.call_args.args, ("call-1", "close_account", {}))

    def test_an_untrusted_tools_result_goes_to_the_signer_as_the_model_reads_it(self):
        class Page(BaseModel):
            title: str
            pay_to: str
        page = {"title": "Invoice 7", "pay_to": "mallory-acct-7731"}
        for returned, model_reads, recorded in (
                ("closed ACC-9", "closed ACC-9", "closed ACC-9"),
                (Page(**page), '{"title":"Invoice 7","pay_to":"mallory-acct-7731"}', page),
                ({"status": "success", "content": [{"json": page}]}, json.dumps(page), page),
                ({"status": "success", "content": [{"text": "a"}, {"text": "b"}]}, None, [{"text": "a"}, {"text": "b"}])):
            with self.subTest(recorded=recorded):
                @tool
                def close_account(account: str) -> Page:
                    """Close an account."""
                    return returned
                r = run(send_result=True)
                agent(r, close_account)("close it")
                sent = r.complete.call_args.kwargs["result"]
                self.assertEqual(sent, recorded)
                if model_reads:   # the gateway's verified tool results find it in what the model is sent
                    self.assertIn(event_hash(sent), [f["digest"] for f in result_forms(model_reads)])

    def test_the_result_is_recorded_as_other_hooks_left_it(self):
        def redact(event: AfterToolCallEvent):
            event.result = {**event.result, "content": [{"text": "closed ACC-*"}]}
        r = run(send_result=True)
        a = agent(r, self.tool())
        a.add_hook(redact, order=math.inf)   # after events run the later added first
        self.assertEqual(str(a("close it")).strip(), "closed ACC-*")
        self.assertEqual(r.complete.call_args.kwargs["result"], "closed ACC-*")

    def test_a_call_another_hook_changes_after_the_decision_does_not_run(self):
        def replace(event: BeforeToolCallEvent):
            event.tool_use = {**event.tool_use, "input": {"account": "ACC-1"}}

        def edit(event: BeforeToolCallEvent):
            event.tool_use["input"]["account"] = "ACC-1"

        def swap(event: BeforeToolCallEvent):
            event.selected_tool = self.tool()
        orders = {"added after": HookOrder.DEFAULT, "at SDK_LAST": HookOrder.SDK_LAST,
                  "before SDK_FIRST": HookOrder.SDK_FIRST - 1}
        for hook, where in ((replace, "added after"), (edit, "added after"), (edit, "listed before Tracekit"),
                            (edit, "at SDK_LAST"), (edit, "before SDK_FIRST"), (swap, "added after")):
            with self.subTest(f"{hook.__name__}, {where}"):
                self.ran.clear()
                r, sent = run(), []
                r.decide.side_effect = lambda call_id, tool, args, **f: sent.append(json.dumps(args)) or mock.DEFAULT
                hooks = [hook, Tracekit(r)] if where == "listed before Tracekit" else [Tracekit(r)]
                a = Agent(model=Scripted([CLOSE]), tools=[self.tool()], hooks=hooks, callback_handler=None)
                if where in orders:
                    a.add_hook(hook, order=orders[where])
                self.assertIn("a hook changed the call after Tracekit decided it", str(a("close it")))
                self.assertEqual((self.ran, sent), ([], ['{"account": "ACC-9"}']))
                r.complete.assert_called_once_with("call-1", "error", attempt=0, error=mock.ANY)
                self.assertIn("not run: Tool call blocked by Tracekit", r.complete.call_args.kwargs["error"])

    def test_another_hook_does_not_undo_a_refusal(self):
        def undo(event: BeforeToolCallEvent):
            event.cancel_tool = False
        r = run("deny", ["D1"])
        a = agent(r, self.tool())
        a.add_hook(undo, order=HookOrder.SDK_LAST)
        self.assertIn("Tracekit policy: D1", str(a("close it")))
        self.assertEqual(self.ran, [])
        r.complete.assert_not_called()

    def test_a_call_another_hook_refuses_after_the_decision_is_recorded_as_not_run(self):
        def refuse(event: BeforeToolCallEvent):
            event.cancel_tool = "not today"
        r = run()
        a = agent(r, self.tool())
        a.add_hook(refuse)
        self.assertEqual(str(a("close it")).strip(), "not today")
        self.assertEqual(self.ran, [])
        r.complete.assert_called_once_with("call-1", "error", attempt=0, error="not run: not today")

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", str(agent(r, self.tool())("close it")))
        self.assertEqual(self.ran, [])

    def asking(self, abandoned):
        """A run whose approval_wait answers once abandoned (as the signer does) or after 5 s: approved."""
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                abandoned.wait(5)
                return {"state": "abandoned" if abandoned.is_set() else "approved"}
            if method == "approval_abandon":
                abandoned.set()
            return {"approval_request": {"approval_id": "apr-1"}, "approval_abandon": {}, "model_event": {}}[method]
        r.call.side_effect = call
        return r

    def test_a_run_cancelled_during_an_ask_withdraws_the_approval(self):
        r = self.asking(threading.Event())

        async def go():
            with self.assertRaises(asyncio.TimeoutError):   # TimeoutError from Python 3.11
                await asyncio.wait_for(agent(r, self.tool()).invoke_async("close it"), 0.3)
        asyncio.run(go())
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])

    def test_an_agent_cancelled_during_an_ask_withdraws_the_approval(self):
        r = self.asking(threading.Event())
        a = agent(r, self.tool())
        threading.Timer(0.3, a.cancel).start()
        self.assertEqual(a("close it").stop_reason, "cancelled")
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])


if HAVE:
    class Thinking(Scripted):
        """Scripted, with signed reasoning and a sentence before the first turn's tool uses."""

        async def stream(self, messages, *a, **k):
            first = not any("toolResult" in c for m in messages for c in m["content"])
            async for e in super().stream(messages, *a, **k):
                if first and "messageStart" in e:
                    yield e
                    for delta in ({"reasoningContent": {"text": "the user wants ACC-9 closed"}},
                                  {"reasoningContent": {"signature": "sig-1"}}):
                        yield {"contentBlockDelta": {"delta": delta}}
                    yield {"contentBlockStop": {}}
                    yield {"contentBlockDelta": {"delta": {"text": "Closing ACC-9."}}}
                    yield {"contentBlockStop": {}}
                else:
                    yield e


@unittest.skipUnless(HAVE, "strands not installed")
class Said(unittest.TestCase):
    """Each model message is recorded: reasoning (with its signature), text and tool uses under their toolUseIds; the
    message itself only with the vault; a failure to record changes nothing for the agent."""

    def answer(self, r):
        @tool
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        a = Agent(model=Thinking([CLOSE]), tools=[close_account], hooks=[Tracekit(r)], callback_handler=None)
        return str(a("close it")).strip()

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        r = ts.vault(run())
        self.assertEqual(self.answer(r), "closed ACC-9")
        first, last = ts.recorded(r)
        self.assertEqual([t["id"] for t in first["tool_uses"]], ["call-1"])
        self.assertEqual(r.decide.call_args.args[0], "call-1")
        self.assertEqual(ts.segments(first), [("reasoning", "summary", "the user wants ACC-9 closed", []),
                                              ("text", "full", "Closing ACC-9.", ["call-1"])])
        self.assertEqual(first["body"]["output"][0]["encrypted_content"], "sig-1")
        self.assertEqual(ts.segments(last), [("text", "full", "closed ACC-9", [])])

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.answer(r)
        self.assertTrue(all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.answer(r), "closed ACC-9")


@unittest.skipUnless(HAVE, "strands not installed")
class Paths(unittest.TestCase):
    """Every way Strands runs a tool reaches the hooks of the agent that runs it."""

    def setUp(self):
        self.ran = []

    def tools(self):
        @tool
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"

        @tool
        async def refund(account: str) -> str:
            """Refund an account."""
            self.ran.append(f"refund {account}")
            return f"refunded {account}"
        return close_account, refund

    def test_sync_and_async_tools_under_either_executor(self):
        uses = [CLOSE, ("call-2", "refund", {"account": "ACC-9"})]
        for executor in (None, SequentialToolExecutor()):
            with self.subTest(executor=type(executor).__name__):
                self.ran.clear()
                r = run()
                agent(r, *self.tools(), uses=uses, **({"tool_executor": executor} if executor else {}))("x")
                self.assertCountEqual(self.ran, ["ACC-9", "refund ACC-9"])
                self.assertCountEqual([c.args[0] for c in r.complete.call_args_list], ["call-1", "call-2"])

    def test_concurrent_asks_wait_for_people_at_once(self):
        both = threading.Barrier(2, timeout=5)   # each wait returns only once the other one waits too
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                both.wait()
                return {"state": "approved"}
            return {"approval_id": f"apr-{f['tool_call_id']}"}
        r.call.side_effect = call
        agent(r, *self.tools(), uses=[CLOSE, ("call-2", "refund", {"account": "ACC-9"})])("x")
        self.assertCountEqual(self.ran, ["ACC-9", "refund ACC-9"])

    def test_one_provider_serves_agents_in_several_threads(self):
        r = run()
        gate = Tracekit(r)
        threads = [threading.Thread(target=lambda i=i: Agent(
            model=Scripted([(f"call-{i}", "close_account", {"account": f"ACC-{i}"})]), tools=[self.tools()[0]],
            hooks=[gate], callback_handler=None)("x")) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertCountEqual([c.args for c in r.complete.call_args_list], [(f"call-{i}", "ok") for i in range(8)])
        self.assertEqual({c.kwargs["attempt"] for c in r.decide.call_args_list}, {0})

    def test_a_direct_tool_call_is_decided(self):
        r = run("deny", ["D1"])
        a = agent(r, *self.tools(), uses=())
        out = a.tool.close_account(account="ACC-7")
        self.assertEqual((out["status"], self.ran), ("error", []))
        self.assertEqual(r.decide.call_args.args[1:], ("close_account", {"account": "ACC-7"}))

    def test_an_agent_as_a_tool_is_decided_and_so_are_its_own_calls_when_it_has_the_hook(self):
        r = run()
        sub = Agent(name="closer", description="Closes accounts.", model=Scripted([("s-1", *CLOSE[1:])]),
                    tools=[self.tools()[0]], hooks=[Tracekit(r)], callback_handler=None)
        agent(r, sub.as_tool(), uses=[("p-1", "closer", {"input": "close ACC-9"})])("x")
        self.assertEqual([c.args for c in r.decide.call_args_list],
                         [("p-1", "closer", {"input": "close ACC-9"}), ("s-1", "close_account", {"account": "ACC-9"})])
        self.assertCountEqual([c.args for c in r.complete.call_args_list], [("p-1", "ok"), ("s-1", "ok")])

    def test_swarm_and_graph_agents_with_the_hook_are_gated(self):
        r = run("deny", ["D1"])
        gate = Tracekit(r)
        triage = Agent(name="triage", model=Scripted([("h-1", "handoff_to_agent", {"agent_name": "closer",
                                                                                   "message": "close ACC-9"})]),
                       hooks=[gate], callback_handler=None)
        closer = Agent(name="closer", model=Scripted([CLOSE]), tools=[self.tools()[0]], hooks=[gate],
                       callback_handler=None)
        Swarm([triage, closer])("close ACC-9")
        self.assertEqual([c.args[1] for c in r.decide.call_args_list], ["handoff_to_agent"])   # denied: no handoff
        b = GraphBuilder().set_max_node_executions(1)
        b.add_node(Agent(model=Scripted([CLOSE]), tools=[self.tools()[0]], hooks=[Tracekit(r)], callback_handler=None))
        b.build()("close ACC-9")
        self.assertEqual(r.decide.call_args.args[1], "close_account")
        self.assertEqual(self.ran, [])

    def test_the_hook_given_to_a_swarm_or_graph_says_where_it_goes(self):
        a = Agent(name="a", model=Scripted(), callback_handler=None)
        with self.assertRaisesRegex(TypeError, "to each of its agents"):
            Swarm([a], hooks=[Tracekit(run())])
        b = GraphBuilder().set_max_node_executions(1)
        b.add_node(a)
        with self.assertRaisesRegex(TypeError, "to each of its agents"):
            b.set_hook_providers([Tracekit(run())]).build()

    def test_an_mcp_tool_is_decided_under_its_agent_name(self):
        client = mock.Mock()
        client.call_tool_async = mock.AsyncMock(return_value={"toolUseId": "m-1", "status": "success",
                                                              "content": [{"text": "contents"}]})
        mcp_tool = MCPAgentTool(MCPTool(name="read_file", inputSchema={"type": "object"}), client,
                                name_override="fs_read_file")
        r = run()
        self.assertEqual(str(agent(r, mcp_tool, uses=[("m-1", "fs_read_file", {"path": "x"})])("x")).strip(),
                         "contents")
        r.decide.assert_called_once_with("m-1", "fs_read_file", {"path": "x"}, attempt=0)
        r.complete.assert_called_once_with("m-1", "ok", attempt=0, result=mock.ANY)

    def test_a_structured_output_tool_is_decided(self):
        class Verdict(BaseModel):
            answer: str
        r = run()
        out = agent(r, uses=[("o-1", "Verdict", {"answer": "42"})])("x", structured_output_model=Verdict)
        self.assertEqual(out.structured_output, Verdict(answer="42"))
        r.decide.assert_called_once_with("o-1", "Verdict", {"answer": "42"}, attempt=0)

    def test_a_background_tool_is_decided_before_it_is_admitted_and_recorded_when_it_ran(self):
        close = self.tools()[0]
        r = run()
        agent(r, close, background_tasks={"always": [close]})("x")
        self.assertEqual(self.ran, ["ACC-9"])
        r.decide.assert_called_once_with(*CLOSE, attempt=0)
        r.complete.assert_called_once_with("call-1", "ok", attempt=0, result=mock.ANY)
        self.ran.clear()
        r = run("deny", ["D1"])
        agent(r, close, background_tasks={"always": [close]})("x")
        self.assertEqual(self.ran, [])

    def test_a_tool_the_model_sends_to_the_background_is_recorded_as_it_ran(self):
        r = run()
        chosen = ("call-1", "close_account", {"account": "ACC-9", "_background_execution": True})
        agent(r, self.tools()[0], uses=[chosen], background_tasks=True)("x")   # Strands strips the flag before the run
        self.assertEqual(self.ran, ["ACC-9"])
        r.decide.assert_called_once_with(*chosen, attempt=0)
        r.complete.assert_called_once_with("call-1", "ok", attempt=0, result=mock.ANY)


@unittest.skipUnless(HAVE, "strands not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).run, sync)

    def test_importing_tracekit_does_not_import_strands(self):
        p = subprocess.run([sys.executable, "-c", "import sys, tracekit, tracekit.integrations, tracekit.sdk.client; "
                            "sys.exit('strands' in sys.modules)"], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)


@unittest.skipUnless(HAVE, "strands not installed")
class AfterTheLastCheck(unittest.TestCase):
    """On a real signer: what a hook that runs after Tracekit's last BeforeToolCallEvent callback (at `math.inf`,
    added after it) does to a call is signed, never silent."""

    def go(self, command, hook):
        """(the commands the tools ran, the run's signed events) when the model asks for Bash `command`."""
        s = SignerService(ac.tmpdir(self))
        self.addCleanup(s.close)
        client = Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))
        self.ran = []

        @tool
        def Bash(command: str) -> str:   # noqa: N802 - the default policy reads it as a shell
            """Run a shell command."""
            self.ran.append(command)
            return "ran"
        with client.run(agent="late-hook") as r:
            a = Agent(model=Scripted([("c-1", "Bash", {"command": command})]), tools=[Bash], hooks=[Tracekit(r)],
                      callback_handler=None)
            a.add_hook(hook, BeforeToolCallEvent, order=math.inf)
            a("x")
            rid = r.run_id
        return self.ran, [e["event"] for e in s.log.storage.iter_run("default", rid)]

    def signed(self, events, typ):
        return [e["data"] for e in events if e["type"] == typ]

    def test_arguments_changed_after_it_run_and_are_signed_as_an_error(self):
        def edit(event):
            event.tool_use["input"]["command"] = "sudo rm -rf /"
        ran, events = self.go("ls", edit)
        self.assertEqual(ran, ["sudo rm -rf /"])
        self.assertEqual([d["decision"] for d in self.signed(events, "policy.decision")], ["allow"])
        self.assertEqual([d["ok"] for d in self.signed(events, "tool.result")], [False])

    def test_a_refusal_cleared_after_it_is_signed_as_executed_against_policy(self):
        def undo(event):
            event.cancel_tool = False
        ran, events = self.go("sudo rm -rf /", undo)
        self.assertEqual(ran, ["sudo rm -rf /"])
        self.assertEqual([d["decision"] for d in self.signed(events, "policy.decision")], ["deny"])
        self.assertEqual(len(self.signed(events, "tool.result")), 1)
        self.assertEqual([d["kind"] for d in self.signed(events, "capture.gap")], ["executed_against_policy"])

    def test_a_tool_swapped_after_it_runs_and_is_signed_as_an_error(self):
        @tool
        def Other(command: str) -> str:   # noqa: N802
            """Run another way."""
            self.ran.append(f"other {command}")
            return "ran"

        def swap(event):
            event.selected_tool = Other
        ran, events = self.go("ls", swap)
        self.assertEqual(ran, ["other ls"])
        self.assertEqual([d["ok"] for d in self.signed(events, "tool.result")], [False])


@unittest.skipUnless(HAVE, "strands not installed")
class Provenance(unittest.TestCase):
    """On a real signer: values an untrusted tool's result carries reach the provenance index."""

    def test_a_payee_from_an_untrusted_tools_result_is_traced_to_it(self):
        s = SignerService(ac.tmpdir(self), policy=Engine({"untrusted": ["WebFetch"]}))
        self.addCleanup(s.close)
        client = Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))

        @tool
        def WebFetch(url: str) -> dict:   # noqa: N802 - the policy names it
            """Fetch a page."""
            return {"title": "Invoice 7", "pay_to": "mallory-acct-7731"}

        @tool
        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"

        with client.run(agent="provenance") as r:
            model = Scripted([("w-1", "WebFetch", {"url": "https://docs.example.org/i"})],
                             [("w-2", "pay", {"to": "mallory-acct-7731"})])
            Agent(model=model, tools=[WebFetch, pay], hooks=[Tracekit(r)], callback_handler=None)("pay the invoice")
            rid = r.run_id
        d = next(e["event"]["data"] for e in s.log.storage.iter_run("default", rid)
                 if e["event"]["type"] == "policy.decision" and e["event"].get("tool_call_id") == "w-2")
        self.assertEqual([p["source"]["tool"] for p in d["provenance"]], ["WebFetch"])


@unittest.skipUnless(HAVE, "strands not installed")
class VersionCheck(unittest.TestCase):
    """The version check the integration shares with the other hand-wired ones: a framework outside the version
    Tracekit is tested with warns once when the integration is built, one inside the range does not warn."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.strands import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.0.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("Strands Agents 0.0.1 is wired but untested; Tracekit is tested with "
                      "strands-agents>=1.61,<1.62", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.strands import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="1.61.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])


if __name__ == "__main__":
    unittest.main()
