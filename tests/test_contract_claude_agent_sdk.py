"""The adapter contract (tests/adapter_contract.py) for the Claude Agent SDK adapter, with a stub CLI (no network, no
CLI process): it speaks the SDK's control protocol over a custom transport, runs the tool call the prompt names
between its PreToolUse and PostToolUse hooks, mirrors the turn to the session store and ends the turn.
"""
import asyncio
import json
import os
import threading
import time
import unittest
import uuid
from unittest import mock

import adapter_contract as ac
from tracekit.sdk.client import Client
from tracekit.signer.rpc_schema import RPCError

try:
    from claude_agent_sdk import ClaudeAgentOptions, InMemorySessionStore, query
    from claude_agent_sdk._internal.transport import Transport

    from tracekit.integrations import claude_agent_sdk as cas
except ImportError:   # optional: the dev extra installs it
    HAVE_SDK = False
else:
    HAVE_SDK = True

    class StubCLI(Transport):
        def __init__(self, config_dir, end_session=False):
            self.config_dir, self.end_session, self.out, self.n = config_dir, end_session, asyncio.Queue(), 0
            self.hooks, self.waiting, self.outcome = {}, {}, None

        async def connect(self):
            pass

        def is_ready(self):
            return True

        async def end_input(self):
            pass

        async def close(self):
            pass

        async def read_messages(self):
            while (m := await self.out.get()) is not None:
                yield m

        async def write(self, data):
            m = json.loads(data)
            if m["type"] == "control_request" and m["request"]["subtype"] == "initialize":
                self.hooks = m["request"]["hooks"] or {}
                await self.out.put({"type": "control_response",
                                    "response": {"subtype": "success", "request_id": m["request_id"], "response": {}}})
            elif m["type"] == "control_response":
                r = m["response"]
                self.waiting.pop(r["request_id"]).set_result(r.get("response") if r["subtype"] == "success" else
                                                             {"sdk_error": r.get("error")})
            elif m["type"] == "user":
                self.task = asyncio.ensure_future(self.turn(json.loads(m["message"]["content"])))

        async def hook(self, event, **fields):
            out = {}
            for matcher in self.hooks.get(event, []):
                for cid in matcher["hookCallbackIds"]:
                    self.n += 1
                    rid = f"cli-{self.n}"
                    self.waiting[rid] = asyncio.get_running_loop().create_future()
                    await self.out.put({"type": "control_request", "request_id": rid, "request": {
                        "subtype": "hook_callback", "callback_id": cid, "tool_use_id": fields.get("tool_use_id"),
                        "input": {"hook_event_name": event, "session_id": "s1", "transcript_path": "", "cwd": "/",
                                  **fields}}})
                    out.update(await self.waiting[rid])
            return out

        async def turn(self, c):
            o = {"ran": [], "seen": None, "is_error": False, "continued": True, "raised": None, "approval_id": None}
            call = {"tool_name": c["name"], "tool_input": c["args"], "tool_use_id": c["id"]}
            pre = (await self.hook("PreToolUse", **call)).get("hookSpecificOutput", {})
            if pre.get("permissionDecision") == "deny":   # the model gets the reason as the tool's error result
                o.update(seen=pre["permissionDecisionReason"], is_error=True)
            else:
                try:
                    o["seen"] = dict((f.__name__, f) for f in ac.TOOLS)[c["name"]](**c["args"])
                except Exception as e:
                    o["raised"] = f"{type(e).__name__}: {e}"
                    await self.hook("PostToolUseFailure", **call, error=str(e))
                else:
                    await self.hook("PostToolUse", **call, tool_response={"stdout": o["seen"]})
            o["ran"], self.outcome = list(ac.RAN), o
            await self.out.put({"type": "transcript_mirror", "filePath": os.path.join(self.config_dir, "projects", "p",
                                                                                         "s1.jsonl"),
                                "entries": [{"type": "user", "uuid": uuid.uuid4().hex, "message": c}]})
            if self.end_session:
                await self.hook("SessionEnd", reason="other")
            await self.out.put({"type": "result", "subtype": "success", "duration_ms": 0, "duration_api_ms": 0,
                                "is_error": False, "num_turns": 1, "session_id": "s1"})
            await self.out.put(None)


async def _prompt(text):
    yield {"type": "user", "message": {"role": "user", "content": text}, "parent_tool_use_id": None, "session_id": ""}


class Driver:
    SKIP = {"retry": "the CLI gives every tool use its own tool_use_id and never runs one twice",
            "saved_state": "the PreToolUse hook holds the call while it waits for the approval: there is no saved "
                           "state to resume in a new process, replay or edit"}
    modes = ("stream",)   # an async iterable prompt (streaming input); the SDK has no sync path

    def __init__(self, case, signer_path):
        self.case, self.dir = case, ac.tmpdir(case)
        self.signer = Client(signer_path)
        case.addCleanup(self.signer.close)
        r = self.signer.register_run({"agent": {"name": "contract"}})
        self._run, self.store = {"run_id": r["run_id"], "run_token": r["run_token"]}, InMemorySessionStore()
        self.options = ClaudeAgentOptions(hooks=cas.tracekit_hooks(self.signer, self._run),
                                          session_store=cas.TracekitSessionStore(self.store, self.signer, self._run),
                                          env={"CLAUDE_CONFIG_DIR": self.dir})

    def run(self):
        return self._run

    async def _query(self, cli, text, mode):
        async for _ in query(prompt=_prompt(text) if mode == "stream" else text, options=self.options, transport=cli):
            pass

    def call(self, tool, args, tcid="call-1", mode="sync", end_session=False):
        ac.RAN.clear()
        self.cli, self.err = StubCLI(self.dir, end_session), []
        text = json.dumps({"name": tool, "args": args, "id": tcid})
        self.thread = threading.Thread(target=lambda: self._go(text, mode))
        self.thread.start()
        while self.thread.is_alive():
            aid = next((a["approval_id"] for a in self.signer.approval_list({"run_id": self._run["run_id"]})["approvals"]
                        if a["tool_call_id"] == tcid and a["state"] == "requested"), None)
            if aid:
                return {"ran": [], "seen": None, "is_error": False, "continued": False, "raised": None,
                        "approval_id": aid}
            time.sleep(0.02)
        return self.finish()

    def _go(self, text, mode):
        try:
            asyncio.run(self._query(self.cli, text, mode))
        except Exception as e:
            self.err.append(e)

    def resume(self, hint=ac.HINT, replay=False):
        return self.finish()

    def finish(self):
        self.thread.join(60)
        self.case.assertEqual(self.err, [])
        return self.cli.outcome


@unittest.skipUnless(HAVE_SDK, "claude-agent-sdk not installed")
class TestOnFakeSigner(ac.Contract, ac.OnFake, unittest.TestCase):
    driver = Driver


@unittest.skipUnless(HAVE_SDK, "claude-agent-sdk not installed")
class TestOnRealSigner(ac.Contract, ac.OnReal, unittest.TestCase):
    driver = Driver

    def test_hook_timeout_is_explicit_and_above_the_approval_wait(self):
        self.d.call("echo", {"text": "hi"})
        [pre] = self.d.cli.hooks["PreToolUse"]
        self.assertEqual(pre["timeout"], cas.HOOK_TIMEOUT_S)
        self.assertLess(cas.APPROVAL_WAIT_S, cas.HOOK_TIMEOUT_S)

    def test_ask_not_approved_in_time_is_refused(self):
        with mock.patch.object(cas, "APPROVAL_WAIT_S", 0.3):
            out = self.d.call("pay", ac.PAY)
            out = out if out["approval_id"] is None else self.d.resume()
        self.refused(out, "R-PAY not approved: requested")

    def test_signer_unreachable_blocks_the_call(self):
        hooks = cas.tracekit_hooks(Client(os.path.join(ac.tmpdir(self), "none.sock")), self.d.run())
        self.d.options.hooks = hooks
        self.refused(self.d.call("echo", {"text": "hi"}), "signer error")

    def test_session_end_closes_the_run(self):
        self.d.call("echo", {"text": "hi"}, end_session=True)
        self.assertEqual(len(self.recorded("run.closing")), 1)

    def test_a_transcript_changed_in_the_store_is_a_state_tamper_on_resume(self):
        self.d.call("echo", {"text": "hi"})
        self.d.call("echo", {"text": "again"}, "call-2")
        self.assertEqual(self.recorded("capture.gap"), [])
        key = {"project_key": "p", "session_id": "s1"}
        entries = asyncio.run(self.d.store.load(key))
        entries[0]["message"]["args"]["text"] = "edited"
        store = InMemorySessionStore()
        asyncio.run(store.append(key, entries))
        resumed = cas.TracekitSessionStore(store, self.client, self.d.run())   # a new process resumes the session
        asyncio.run(resumed.load(key))
        asyncio.run(resumed.append(key, [{"type": "user", "uuid": "u3", "message": "next"}]))
        gaps = [e["data"] for e in self.events(self.d.run()) if e["type"] == "capture.gap"]
        self.assertEqual([g["kind"] for g in gaps], ["state_tamper"])
        writes = self.recorded("state.write")
        self.assertEqual(len(writes), 3)


    def test_a_lost_state_write_neither_raises_nor_reads_as_tampering(self):
        key = {"project_key": "p", "session_id": "s2"}
        store = InMemorySessionStore()
        wrapped = cas.TracekitSessionStore(store, self.client, self.d.run())
        asyncio.run(wrapped.append(key, [{"type": "user", "uuid": "u1", "message": "one"}]))
        real = wrapped._rpc
        lost = [False]

        async def fails_once(method, **req):
            if method == "state_write" and not lost[0]:
                lost[0] = True
                raise RPCError("unavailable", "signer restarting")
            return await real(method, **req)
        wrapped._rpc = fails_once
        with self.assertWarns(UserWarning):   # the store has the entries: the SDK must not append them again
            asyncio.run(wrapped.append(key, [{"type": "user", "uuid": "u2", "message": "two"}]))
        asyncio.run(wrapped.append(key, [{"type": "user", "uuid": "u3", "message": "three"}]))
        self.assertEqual(len(asyncio.run(store.load(key))), 3)
        self.assertEqual([e["data"]["kind"] for e in self.events(self.d.run()) if e["type"] == "capture.gap"], [])

if __name__ == "__main__":
    unittest.main()
