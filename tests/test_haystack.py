"""Haystack's Agent hooks (tracekit.integrations.haystack) on a real Agent with a MockChatGenerator and a mock run: only
an allow or an approved ask runs the tool, the model reads the reason for anything else and the run goes on, and
nothing Tracekit fails at raises into the agent."""
import asyncio
import importlib.util
import os
import subprocess
import sys
import threading
import unittest
import warnings
from unittest import mock

import adapter_contract as ac
import test_said as ts

os.environ.setdefault("HAYSTACK_TELEMETRY_ENABLED", "False")   # Haystack's usage telemetry: off, offline
HAVE = importlib.util.find_spec("haystack") is not None
if HAVE:
    from haystack.components.agents import Agent, State
    from haystack.components.agents.state import replace_values
    from haystack.components.generators.chat import MockChatGenerator
    from haystack.dataclasses import ChatMessage, ReasoningContent, TextContent, ToolCall
    from haystack.hooks import hook
    from haystack.tools import AgentTool, Tool, create_tool_from_function
    from haystack.tools.errors import ToolInvocationError

    from tracekit.integrations.haystack import Tracekit

from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client, RunHandle, current_run
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def model(*calls):
    """The mock model: each step asks for the next of `calls` (a list of ToolCalls, or one) until they run out, then
    answers with the results it read, one per line."""
    steps = iter(calls)

    def reply(messages):
        step = next(steps, None)
        if step is not None:
            return ChatMessage.from_assistant(tool_calls=step if isinstance(step, list) else [step])
        return "\n".join(str(m.tool_call_result.result) for m in messages if m.tool_call_result)
    return MockChatGenerator(response_fn=reply)


def agent(r, tool, args=None, *more, **kw):
    """An Agent gated by Tracekit(r) whose model calls close_account once as call-1 (with `args`, default
    {"account": "ACC-9"}), then each of `more`, and then answers with what it read."""
    tk = Tracekit(r)
    calls = [ToolCall("close_account", {"account": "ACC-9"} if args is None else args, "call-1"), *more]
    return Agent(chat_generator=model(*calls), tools=[tool], hooks={"before_tool": [tk], "after_tool": [tk]}, **kw)


def answer(a, text="close it"):
    return a.run([ChatMessage.from_user(text)])["last_message"].text


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class Hook(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self, fail=None):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            if fail:
                raise fail
            return f"closed {account}"
        return create_tool_from_function(close_account)

    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                self.ran.clear()
                out = answer(agent(r, self.tool()))
                self.assertEqual(self.ran, ["ACC-9"] if runs else [])
                if runs:
                    self.assertEqual(out, "closed ACC-9")
                    r.complete.assert_called_once_with("call-1", "ok", attempt=0, decision_id="dec-1",
                                                       args_digest=mock.ANY, result=mock.ANY)
                else:
                    self.assertIn("Tracekit policy", out)
                    if name == "consume refused":   # allowed, then refused: completed as not run
                        r.complete.assert_called_once_with("call-1", "error", attempt=0, error=mock.ANY)
                    else:
                        r.complete.assert_not_called()

    def test_the_signer_decides_the_models_own_arguments(self):
        r = run()
        answer(agent(r, self.tool()))
        r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, attempt=0)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint=None, attempt=0)

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        answer(agent(r, self.tool()))
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", attempt=0)
        self.assertEqual([c for c in r.call.call_args_list if c.args[0] != "model_event"][1],
                         mock.call("approval_wait", approval_id="apr-1", timeout_ms=300000))

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", answer(agent(r, self.tool())))
        self.assertEqual([c.args[0] for c in r.call.call_args_list if c.args[0] != "model_event"][-1],
                         "approval_abandon")

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        out = answer(agent(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool()))
        self.assertEqual(out, "Tool call blocked by Tracekit policy: TK-D001")

    def test_a_refused_call_reads_as_an_error_result_and_the_run_goes_on(self):
        msgs = agent(run("deny", ["D1"]), self.tool()).run([ChatMessage.from_user("close it")])["messages"]
        result = next(m.tool_call_result for m in msgs if m.tool_call_result)
        self.assertEqual((result.origin.id, result.error, result.result),
                         ("call-1", True, "Tool call blocked by Tracekit policy: D1"))
        self.assertEqual(msgs[-1].text, "Tool call blocked by Tracekit policy: D1")   # the model's next turn

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", answer(agent(r, self.tool())))
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(answer(agent(r, self.tool())), "closed ACC-9")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = answer(agent(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool()))
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(answer(agent(r, self.tool())), "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_reaches_haystack_unchanged(self):
        r = run()
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            out = answer(agent(r, self.tool(fail=ValueError("account is locked"))))
        self.assertIn("account is locked", out)   # Haystack's error result, which the model reads
        self.assertEqual(r.complete.call_args.args, ("call-1", "error"))
        self.assertIn("account is locked", r.complete.call_args.kwargs["error"])
        r = run()   # Haystack raises it instead: the step ends before after_tool, unrecorded (docs: Not covered)
        with self.assertRaisesRegex(ToolInvocationError, "account is locked"):
            answer(agent(r, self.tool(fail=ValueError("account is locked")), raise_on_tool_invocation_failure=True))
        r.complete.assert_not_called()

    def test_empty_arguments_are_no_arguments(self):
        def close_account(account: str = "ACC-0") -> str:
            """Close an account."""
            return f"closed {account}"
        r = run()
        answer(agent(r, create_tool_from_function(close_account), {}))
        self.assertEqual(r.decide.call_args.args, ("call-1", "close_account", {}))

    def test_an_untrusted_tools_result_goes_to_the_signer_as_the_model_reads_it(self):
        for out, want in (({"title": "Invoice 7", "pay_to": "mallory-acct-7731"},
                           {"title": "Invoice 7", "pay_to": "mallory-acct-7731"}),
                          ("closed ACC-9", "closed ACC-9"), ('["a", 1]', ["a", 1]), ("42", "42"),
                          ('{"a": 1, "a": 2}', '{"a": 1, "a": 2}'), ("[NaN]", "[NaN]"),   # not strict JSON: the text
                          ([TextContent("closed")], [{"text": "closed"}])):   # raw_result: content parts
            with self.subTest(out=out):
                def close_account(account: str):
                    """Close an account."""
                    return out
                r = run(send_result=True)
                raw = {"raw_result": True} if isinstance(out, list) else None
                answer(agent(r, create_tool_from_function(close_account, outputs_to_string=raw)))
                self.assertEqual(r.complete.call_args.kwargs["result"], want)

    def test_a_tool_or_arguments_a_later_hook_changes_are_recorded_as_changed(self):
        def read_account(account: str) -> str:
            """Read an account."""
            self.ran.append(f"read {account}")
            return f"read {account}"
        for name, account in (("close_account", "ACC-1"), ("read_account", "ACC-9")):
            with self.subTest(name=name, account=account):
                @hook
                def rewrite(state: State):
                    last = state.data["messages"][-1]
                    call = ToolCall(name, {"account": account}, last.tool_calls[0].id)
                    state.set("messages", [*state.data["messages"][:-1], ChatMessage.from_assistant(tool_calls=[call])],
                              handler_override=replace_values)
                self.ran.clear()
                r = run()
                tk = Tracekit(r)
                Agent(chat_generator=model(ToolCall("close_account", {"account": "ACC-9"}, "call-1")),
                      tools=[self.tool(), create_tool_from_function(read_account)],
                      hooks={"before_tool": [tk, rewrite], "after_tool": [tk]}).run([ChatMessage.from_user("x")])
                self.assertEqual(self.ran, ["ACC-1" if name == "close_account" else "read ACC-9"])
                self.assertEqual(r.complete.call_args.args, ("call-1", "error"))
                self.assertIn("changed after the decision", r.complete.call_args.kwargs["error"])

    def test_a_result_an_earlier_after_tool_hook_moved_is_recorded(self):
        @hook
        def nudge(state: State):
            state.set("messages", [ChatMessage.from_user("be brief")])
        r = run()
        tk = Tracekit(r)
        Agent(chat_generator=model(ToolCall("close_account", {"account": "ACC-9"}, "call-1")), tools=[self.tool()],
              hooks={"before_tool": [tk], "after_tool": [nudge, tk]}).run([ChatMessage.from_user("close it")])
        self.assertEqual(r.complete.call_args.args, ("call-1", "ok"))
        self.assertEqual(tk._ran, {})

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", answer(agent(r, self.tool())))
        self.assertEqual(self.ran, [])

    def test_a_call_id_seen_again_is_decided_as_its_next_attempt(self):
        r = run(send_result=True)
        answer(agent(r, self.tool(), None, ToolCall("close_account", {"account": "ACC-8"}, "call-1")))
        self.assertEqual(self.ran, ["ACC-9", "ACC-8"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        self.assertEqual([(c.args, c.kwargs["attempt"], c.kwargs["result"]) for c in r.complete.call_args_list],
                         [(("call-1", "ok"), 0, "closed ACC-9"), (("call-1", "ok"), 1, "closed ACC-8")])

    def test_a_call_without_an_id_is_decided_under_one_it_is_given(self):
        r = run()
        tk = Tracekit(r)
        msgs = Agent(chat_generator=model(ToolCall("close_account", {"account": "ACC-9"})), tools=[self.tool()],
                     hooks={"before_tool": [tk], "after_tool": [tk]}).run([ChatMessage.from_user("x")])["messages"]
        given = r.decide.call_args.args[0]
        self.assertTrue(given.startswith("haystack-"))
        self.assertEqual(next(m.tool_call_result for m in msgs if m.tool_call_result).origin.id, given)
        r.complete.assert_called_once_with(given, "ok", attempt=0, decision_id="dec-1", args_digest=mock.ANY,
                                           result=mock.ANY)

    def test_each_call_of_a_step_is_decided_on_its_own(self):
        r = run()
        r.decide.side_effect = lambda call_id, tool, args, **at: {
            "decision": "deny" if args["account"] == "ACC-2" else "allow", "rule_ids": ["D1"], "decision_id": call_id}
        calls = [ToolCall("close_account", {"account": f"ACC-{i}"}, f"call-{i}") for i in (1, 2, 3)]
        tk = Tracekit(r)
        a = Agent(chat_generator=model(calls), tools=[self.tool()], hooks={"before_tool": [tk], "after_tool": [tk]})
        out = answer(a)
        self.assertEqual(sorted(self.ran), ["ACC-1", "ACC-3"])
        self.assertEqual(sorted(out.splitlines()),
                         ["Tool call blocked by Tracekit policy: D1", "closed ACC-1", "closed ACC-3"])
        self.assertEqual(sorted(c.args for c in r.complete.call_args_list), [("call-1", "ok"), ("call-3", "ok")])

    def test_a_sync_run_decides_in_the_callers_context_where_a_loop_is_running(self):   # a notebook's cell
        r, seen = run(), []
        r.decide.side_effect = lambda *a, **at: seen.append(current_run.get()) or {"decision": "allow", "rule_ids": [],
                                                                                   "decision_id": "dec-1"}

        async def cell():
            with RunHandle(None, {"run_id": "r-1", "run_token": "t"}).current() as handle:
                return answer(agent(r, self.tool())), handle
        out, handle = asyncio.run(cell())
        self.assertEqual((out, seen), ("closed ACC-9", [handle]))   # instrument()'s handle routes by current_run

    def test_async_tools_and_runs_are_gated_too(self):
        async def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        tool = Tool(name="close_account", description="Close an account.", async_function=close_account,
                    parameters={"type": "object", "properties": {"account": {"type": "string"}}})
        for r, out in ((run(), "closed ACC-9"), (run("deny", ["D1"]), "Tool call blocked by Tracekit policy: D1")):
            with self.subTest(out=out):
                got = asyncio.run(agent(r, tool).run_async([ChatMessage.from_user("close it")]))["last_message"].text
                self.assertEqual(got, out)
                self.assertEqual(r.complete.call_count, out == "closed ACC-9")
        self.assertEqual(self.ran, ["ACC-9"])

    def test_an_agent_used_as_a_tool_is_decided_and_so_are_its_calls(self):
        r = run()
        tk = Tracekit(r)
        inner = Agent(chat_generator=model(ToolCall("close_account", {"account": "ACC-9"}, "inner-1")),
                      tools=[self.tool()], hooks={"before_tool": [tk], "after_tool": [tk]})
        task = {"messages": [{"role": "user", "content": "close ACC-9"}]}
        outer = Agent(chat_generator=model(ToolCall("closer", task, "outer-1")),
                      tools=[AgentTool(inner, name="closer", description="Closes accounts.")],
                      hooks={"before_tool": [tk], "after_tool": [tk]})
        self.assertEqual(answer(outer), "closed ACC-9")
        self.assertEqual([c.args[:2] for c in r.decide.call_args_list], [("outer-1", "closer"),
                                                                          ("inner-1", "close_account")])
        self.assertEqual([c.args for c in r.complete.call_args_list], [("inner-1", "ok"), ("outer-1", "ok")])

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
            task = asyncio.ensure_future(agent(r, self.tool()).run_async([ChatMessage.from_user("close it")]))
            self.assertTrue(await asyncio.to_thread(waiting.wait, 5))   # in the ask, however slow the runner
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            answered.set()   # a person approves after the agent run was cancelled
        asyncio.run(go())   # returns once the approval_wait thread has (asyncio.run waits for its executor)
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class Said(unittest.TestCase):
    """At before_tool the message is recorded: its reasoning (with OpenAI's encrypted_content), text and tool calls,
    under the ids they are decided by (one Tracekit gives a call without one); the message itself only with the vault;
    a failure to record changes nothing for the agent."""

    def answer(self, r):
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        msg = ChatMessage.from_assistant("Closing ACC-9.", meta={"model": "m-1"}, tool_calls=[
            ToolCall("close_account", {"account": "ACC-9"}, "call-1"), ToolCall("close_account", {"account": "ACC-7"})],
            reasoning=ReasoningContent("the user wants both closed", {"id": "rs_1", "encrypted_content": "ENC"}))
        steps = iter([msg])

        def reply(messages):
            return next(steps, None) or "done"
        tk = Tracekit(r)
        return answer(Agent(chat_generator=MockChatGenerator(response_fn=reply),
                            tools=[create_tool_from_function(close_account)],
                            hooks={"before_tool": [tk], "after_tool": [tk]}))

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        r = ts.vault(run())
        self.assertEqual(self.answer(r), "done")
        (f,) = ts.recorded(r)
        ids = [t["id"] for t in f["tool_uses"]]
        self.assertEqual(ids[0], "call-1")
        self.assertTrue(ids[1].startswith("haystack-"))   # Tracekit's id for the call that had none
        # the two calls run concurrently, so they are decided in either order
        self.assertEqual(sorted(c.args[0] for c in r.decide.call_args_list), sorted(ids))
        self.assertEqual(ts.segments(f), [("reasoning", "summary", "the user wants both closed", []),
                                          ("text", "full", "Closing ACC-9.", ids)])
        self.assertEqual((f["model"], f["body"]["output"][0]["encrypted_content"]), ("m-1", "ENC"))

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.answer(r)
        self.assertTrue(all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.answer(r), "done")


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).handle, sync)

    def test_importing_tracekit_does_not_import_haystack(self):
        p = subprocess.run([sys.executable, "-c", "import sys, tracekit, tracekit.integrations, tracekit.sdk.client; "
                            "print('haystack' in sys.modules)"], capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "False", p.stderr)


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class RealSigner(unittest.TestCase):
    """On a real signer: what the signer takes and records."""

    def setUp(self):
        s = SignerService(ac.tmpdir(self), policy=Engine({"untrusted": ["WebFetch"]}))
        self.addCleanup(s.close)
        self.signer, self.client = s, Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))

    def events(self, rid, kind):
        return [e["event"] for e in self.signer.log.storage.iter_run("default", rid) if e["event"]["type"] == kind]

    def test_two_calls_of_a_step_under_one_id_are_each_recorded(self):
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        calls = [ToolCall("close_account", {"account": a}, "dup") for a in ("A1", "A2")]
        with warnings.catch_warnings(), self.client.run(agent="dup") as r:
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            tk = Tracekit(r)
            Agent(chat_generator=model(calls), tools=[create_tool_from_function(close_account)],
                  hooks={"before_tool": [tk], "after_tool": [tk]}).run([ChatMessage.from_user("close both")])
            rid = r.run_id
        self.assertEqual(sorted((e["attempt"], e["data"]["ok"]) for e in self.events(rid, "tool.result")),
                         [(0, True), (1, True)])

    def test_a_payee_from_an_untrusted_tools_result_is_traced_to_it(self):
        def WebFetch(url: str) -> dict:   # noqa: N802 - the policy names the tool
            """Fetch a page."""
            return {"title": "Invoice 7", "pay_to": "mallory-acct-7731"}

        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"
        calls = (ToolCall("WebFetch", {"url": "https://docs.example.org/i"}, "w-1"),
                 ToolCall("pay", {"to": "mallory-acct-7731"}, "w-2"))
        with self.client.run(agent="provenance") as r:
            tk = Tracekit(r)
            Agent(chat_generator=model(*calls), tools=[create_tool_from_function(WebFetch), create_tool_from_function(pay)],
                  hooks={"before_tool": [tk], "after_tool": [tk]}).run([ChatMessage.from_user("pay the invoice")])
            rid = r.run_id
        d = next(e["data"] for e in self.events(rid, "policy.decision") if e.get("tool_call_id") == "w-2")
        self.assertEqual([p["source"]["tool"] for p in d["provenance"]], ["WebFetch"])


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class VersionCheck(unittest.TestCase):
    """The version check the integration shares with the other hand-wired ones: a framework outside the version
    Tracekit is tested with warns once when the integration is built, one inside the range does not warn."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.haystack import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.0.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("Haystack 0.0.1 is wired but untested; Tracekit is tested with haystack-ai>=3.4,<3.5", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.haystack import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="3.4.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])


if __name__ == "__main__":
    unittest.main()
