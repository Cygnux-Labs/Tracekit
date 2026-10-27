"""The v2 hooks of Codex CLI, Cursor, Gemini CLI, OpenCode and goose (tracekit/integrations/harness_hooks.py).

The mapping tables are checked against recorded sample payloads (tests/data/harness/<harness>.json): each case is the
harness's PreToolUse payload, the decision the signer gives, the exact `decide` request the hook must send (tool,
args, tool_call_id) and the reply the harness must get (exit code and stdout). Gemini CLI gives tool calls no id, so
its cases name none: the hook pairs calls itself (tracekit.agent_hooks._paired_ids) and the test checks the ids are
distinct and never a default.
"""
import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit import agent_hooks, cli, client, install, parsers
from tracekit.format.canon import event_hash
from tracekit.integrations import claude_code, harness_hooks
from tracekit.sdk.client import Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService, load_policy
from tracekit.testing import FakeSigner

CODEX_DENY = 0 if os.name == "nt" else 2   # agent_hooks._exit: a blocked Codex call's exit status

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "harness")


def cases(harness):
    with open(os.path.join(DATA, harness + ".json"), encoding="utf-8") as f:
        return json.load(f)


class HarnessCase(unittest.TestCase):
    def setUp(self):
        d = ac.tmpdir(self)
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": os.path.join(d, "run"), "HOME": os.path.join(d, "home"),
                                           "TRACEKIT_CLIENT_HOME": os.path.join(d, "client")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("TRACEKIT_FAIL_CLOSED", "TRACEKIT_POLICY", "GEMINI_SESSION_ID"):
            os.environ.pop(k, None)
        agent = mock.patch.object(claude_code, "AGENT", claude_code.AGENT)
        agent.start()
        self.addCleanup(agent.stop)

    def hook(self, harness, payload, event=None):
        out, err = io.StringIO(), io.StringIO()
        code = harness_hooks.run(harness, json.dumps(payload), out, err, event=event)
        return code, out.getvalue(), err.getvalue()


class Mapping(HarnessCase):
    def setUp(self):
        super().setUp()
        self.decision, self.sent, mutex = "allow", [], threading.Lock()
        self.signer = FakeSigner(lambda tool, args: (self.decision, [] if self.decision == "allow" else ["R-1"]))

        def handle(identity, frame):
            with mutex:
                if frame["method"] == "decide":
                    self.sent.append({k: frame[k] for k in ("tool", "tool_call_id", "args")})
                return getattr(self.signer, frame.pop("method"))(frame)
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, handle)

    def approve_when_asked(self):
        def approve():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                aid = next((k for k, a in list(self.signer._approvals.items()) if a["state"] == "requested"), None)
                if aid:
                    c = Client()
                    try:
                        c.approval_decide({"approval_id": aid, "decision": "approve"})
                    finally:
                        c.close()
                    return
                time.sleep(0.02)
        t = threading.Thread(target=approve)
        t.start()
        self.addCleanup(t.join, 30)

    def check(self, harness):
        for case in cases(harness):
            with self.subTest(harness=harness, case=case["name"]):
                self.decision = case["decision"]
                if self.decision == "ask":
                    self.approve_when_asked()
                code, out, err = self.hook(harness, case["payload"], case.get("event"))   # agy: the command's event
                self.assertEqual(code, CODEX_DENY if harness == "codex" and case["exit"] == 2 else case["exit"], err)
                self.assertEqual(json.loads(out) if out else "", case["stdout"])
                sent = self.sent[-1]
                if case["request"]["tool_call_id"] is None:   # Gemini, agy: paired by the hook, never defaulted
                    prefix = "gem" if harness == "gemini" else harness
                    self.assertRegex(sent["tool_call_id"], rf"^{prefix}_[0-9a-f]{{16}}_\d+$")
                    sent = dict(sent, tool_call_id=None)
                self.assertEqual(sent, case["request"])
        self.assertEqual(len({s["tool_call_id"] for s in self.sent}), len(self.sent))

    def test_codex(self):
        self.check("codex")

    def test_cursor(self):
        self.check("cursor")

    def test_gemini(self):
        self.check("gemini")

    def test_opencode(self):
        self.check("opencode")

    def test_goose(self):
        self.check("goose")

    def test_goose_execute_javascript_is_denied_before_the_signer(self):
        # goose's Code Mode runs shell calls through dispatch_tool with no PreToolUse hook, so the hook denies
        # execute_javascript itself, before any decide request is sent
        code, out, err = self.hook("goose", {"session_id": "go-9", "working_dir": "/w", "event": "PreToolUse",
                                             "tool_name": "execute_javascript", "tool_call_id": "go-9",
                                             "tool_input": {"code": "tools.call('shell', {command: 'ls'})"}})
        self.assertEqual((code, out), (2, ""))
        self.assertIn("execute_javascript", err)
        self.assertIn("no PreToolUse hook", err)
        self.assertEqual(self.sent, [])
        code, out, err = self.hook("goose", {"session_id": "go-9", "working_dir": "/w", "event": "PreToolUse",
                                             "tool_name": "code_execution__execute_typescript",
                                             "tool_call_id": "go-10", "tool_input": {"code": "x"}})
        self.assertEqual((code, out), (2, ""))   # the name before goose 1.56, prefixed
        self.assertEqual(self.sent, [])

    def test_qwen(self):
        self.check("qwen")

    def test_droid_pairs_results_and_drops_a_blocked_call_before_allowing_a_retry(self):
        pre = {"session_id": "s-droid", "hook_event_name": "PreToolUse", "tool_name": "Execute",
               "tool_input": {"command": "ls"}}
        self.decision = "deny"
        code, out, _ = self.hook("droid", pre)
        self.assertEqual((code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]), (2, "deny"))
        self.decision = "allow"
        for _ in range(2):
            self.assertEqual(self.hook("droid", pre)[:2], (0, ""))
        calls = [s["tool_call_id"] for s in self.sent]
        self.assertEqual(len(set(calls)), 3)
        for i in range(2):
            self.assertEqual(self.hook("droid", dict(pre, hook_event_name="PostToolUse", tool_response=f"ok {i}"))[0], 0)
        run = self.signer._runs[claude_code._load(claude_code._state("s-droid"))["run_id"]]
        results = [e["data"] for e in run["events"] if e["type"] == "tool.result"]
        self.assertEqual([r["tool_call_id"] for r in results], calls[1:])
        self.assertEqual([s["tool"] for s in self.sent], ["Bash"] * 3)

    def test_droid_a_held_call_waits_for_approval(self):
        self.decision = "ask"
        self.approve_when_asked()
        self.assertEqual(self.hook("droid", {"session_id": "droid-held", "hook_event_name": "PreToolUse",
                                            "tool_name": "Create", "tool_input": {"file_path": "notes.txt", "content": "hi"}})[:2],
                         (0, ""))
        self.assertEqual(self.sent[-1]["tool"], "Write")
        self.assertTrue(any(a["state"] == "consumed" for a in self.signer._approvals.values()))

    def test_droid_does_not_read_its_transcript_as_geminis(self):
        with mock.patch.object(harness_hooks, "_read", side_effect=AssertionError("Droid transcript is not Gemini JSON")):
            code, _, _ = self.hook("droid", {"session_id": "droid-transcript", "hook_event_name": "PreToolUse",
                                             "transcript_path": "/tmp/droid.jsonl", "tool_name": "Execute",
                                             "tool_input": {"command": "ls"}})
        self.assertEqual(code, 0)

    def test_droid_missing_session_or_malformed_payload_blocks_the_call(self):
        code, out, err = self.hook("droid", {"hook_event_name": "PreToolUse", "tool_name": "Execute",
                                             "tool_input": {"command": "ls"}})
        self.assertEqual((code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]), (2, "deny"))
        self.assertIn("tool call blocked", err)
        self.assertEqual(self.sent, [])
        for raw in ("not JSON", "[]", "[" * 100_000):
            out = io.StringIO()
            self.assertEqual(harness_hooks.run("droid", raw, out, io.StringIO(), event="PreToolUse"), 2)
            self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_antigravity(self):
        self.check("antigravity")

    def test_antigravity_pairs_results_by_step_tool_and_arguments_and_always_answers_in_json_at_exit_0(self):
        # agy's payload names no event and gives a call no id: the command names the event, and the stepIdx, tool and
        # arguments sent with a call's PreToolUse and PostToolUse pair them; a step can hold two calls. agy reads a
        # hook's answer only from its JSON at exit 0
        def pre(step, cmd):
            return {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "stepIdx": step,
                    "conversationId": "ag-pair", "workspacePaths": ["/w"]}
        self.decision = "deny"
        code, out, err = self.hook("antigravity", pre(3, "ls"), "PreToolUse")
        self.assertEqual((code, json.loads(out)), (0, {"decision": "deny", "reason": "Blocked by tracekit policy: R-1"}))
        self.decision = "allow"
        for step, cmd in ((4, "ls"), (4, "pwd"), (5, "ls")):
            self.assertEqual(self.hook("antigravity", pre(step, cmd), "PreToolUse")[:2], (0, '{"decision": "allow"}'))
        # step 4's two results in the other order, each with its own error text (an empty one: the call ran)
        self.assertEqual(self.hook("antigravity", dict(pre(4, "pwd"), error="exit status 1"), "PostToolUse")[:2],
                         (0, "{}"))
        self.assertEqual(self.hook("antigravity", dict(pre(4, "ls"), error=""), "PostToolUse")[:2], (0, "{}"))
        # a result that matches no call exactly (no toolCall, or another step's arguments) is never paired by guess:
        # step 5's call stays decided and not completed
        for post in ({"stepIdx": 5, "conversationId": "ag-pair", "error": ""}, dict(pre(5, "pwd"), error="")):
            self.assertEqual(self.hook("antigravity", post, "PostToolUse")[:2], (0, "{}"))
        run = self.signer._runs[claude_code._load(claude_code._state("ag-pair"))["run_id"]]
        self.assertEqual(run["events"][0]["data"]["agent"]["name"], "antigravity")
        calls = [s["tool_call_id"] for s in self.sent]
        self.assertEqual(len(set(calls)), 4)
        results = [(e["data"]["tool_call_id"], e["data"]["status"]) for e in run["events"] if e["type"] == "tool.result"]
        self.assertEqual(results, [(calls[2], "error"), (calls[1], "ok")])   # the blocked step 3 left the queue

    def test_antigravity_a_call_it_cant_pair_or_read_is_denied_in_json(self):
        for payload in ({"toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}, "stepIdx": 1},   # no session
                        {"toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}, "conversationId": "ag-x"},
                        {"toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}, "conversationId": "ag-x",
                         "stepIdx": "1"}):
            with self.subTest(payload=payload):
                code, out, err = self.hook("antigravity", payload, "PreToolUse")
                self.assertEqual((code, json.loads(out)["decision"]), (0, "deny"))
                self.assertIn("tool call blocked", json.loads(out)["reason"])
        self.assertEqual(self.sent, [])
        for raw in ("not JSON", "[]", "[" * 100_000):
            out = io.StringIO()
            self.assertEqual(harness_hooks.run("antigravity", raw, out, io.StringIO(), event="PreToolUse"), 0)
            self.assertEqual(json.loads(out.getvalue())["decision"], "deny")
            out = io.StringIO()   # a result it can't read: nothing to answer but {}, at exit 0
            self.assertEqual(harness_hooks.run("antigravity", raw, out, io.StringIO(), event="PostToolUse"), 0)
            self.assertEqual(out.getvalue(), "{}")
        with mock.patch.object(claude_code, "handle", side_effect=RuntimeError("boom")):
            code, out, _ = self.hook("antigravity", cases("antigravity")[0]["payload"], "PreToolUse")
        self.assertEqual((code, json.loads(out)["decision"]), (0, "deny"))

    def test_results_complete_the_decided_call(self):
        for harness, pre, post in (
                ("codex", {"session_id": "s-codex", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_use_id": "c1", "tool_input": {"command": "ls"}},
                 {"hook_event_name": "PostToolUse", "tool_response": "a.txt"}),
                ("cursor", {"conversation_id": "s-cursor", "hook_event_name": "preToolUse", "tool_name": "Shell",
                            "tool_use_id": "c1", "tool_input": {"command": "ls"}},
                 {"hook_event_name": "postToolUseFailure", "error_message": "exit 1"}),
                ("gemini", {"session_id": "s-gemini", "hook_event_name": "BeforeTool",
                            "tool_name": "run_shell_command", "tool_input": {"command": "ls"}},
                 {"hook_event_name": "AfterTool", "tool_response": {"llmContent": "a.txt"}}),
                ("opencode", {"session_id": "s-opencode", "hook_event_name": "tool.execute.before",
                              "tool_name": "read", "tool_use_id": "c1", "tool_input": {"filePath": "a.txt"}},
                 {"hook_event_name": "tool.execute.after", "tool_response": {"title": "a.txt", "output": "a"}})):
            with self.subTest(harness=harness):
                self.assertEqual(self.hook(harness, pre)[0], 0)
                self.assertEqual(self.hook(harness, dict(pre, **post))[:2],
                                 (0, "{}" if harness in ("cursor", "gemini") else ""))
                run = self.signer._runs[claude_code._load(claude_code._state("s-" + harness))["run_id"]]
                self.assertEqual(run["events"][0]["data"]["agent"]["name"], agent_hooks.AGENT_NAMES[harness])
                result = run["events"][-1]
                self.assertEqual((result["type"], result["data"]["status"]),
                                 ("tool.result", "error" if harness == "cursor" else "ok"))

    def test_a_blocked_gemini_call_leaves_the_pairing_queue(self):
        pre = {"session_id": "s-gemini", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
               "tool_input": {"command": "ls"}}
        self.decision = "deny"
        self.assertEqual(self.hook("gemini", pre)[0], 2)
        self.decision = "allow"
        self.assertEqual(self.hook("gemini", pre)[0], 0)
        self.assertEqual(self.hook("gemini", dict(pre, hook_event_name="AfterTool", tool_response={}))[0], 0)
        run = self.signer._runs[claude_code._load(claude_code._state("s-gemini"))["run_id"]]
        result = run["events"][-1]
        self.assertEqual((result["type"], result["data"]["tool_call_id"]), ("tool.result", self.sent[-1]["tool_call_id"]))

    def test_missing_ids_block_the_call(self):
        for harness, payload, reply in (
                ("codex", {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": "ls"}}, "permissionDecision"),
                ("cursor", {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_use_id": "c1",
                            "tool_input": {"command": "ls"}}, "permission"),
                ("gemini", {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
                            "tool_input": {"command": "ls"}}, "decision")):
            with self.subTest(harness=harness):
                code, out, err = self.hook(harness, payload)
                self.assertEqual(code, CODEX_DENY if harness == "codex" else 2)
                self.assertIn("deny", json.dumps(json.loads(out)))
                self.assertIn(reply, out)
                self.assertIn("tool call blocked", err)
        self.assertEqual(self.sent, [])
        self.assertFalse(os.path.exists(os.environ["TRACEKIT_CLIENT_HOME"]))   # no Gemini id was paired

        code, out, err = self.hook("opencode", {"session_id": "s", "hook_event_name": "tool.execute.before",
                                                 "tool_name": "bash", "tool_input": {"command": "ls"}})
        self.assertEqual((code, out), (2, ""))
        self.assertIn("tool call blocked", err)

    def test_signer_unreachable_is_fail_closed_by_default(self):
        os.environ["TRACEKIT_SIGNER"] = os.path.join(os.environ["HOME"], "nowhere.sock")
        code, out, err = self.hook("codex", cases("codex")[0]["payload"])
        self.assertEqual(code, CODEX_DENY)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("blocking (fail-closed)", err)

    def test_only_a_tool_call_is_blocked_when_the_hook_fails(self):
        """2 on a prompt event blocked the prompt itself."""
        os.environ["TRACEKIT_SIGNER"] = os.path.join(os.environ["HOME"], "nowhere.sock")
        prompt = {"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": "hi"}
        code, _, err = self.hook("codex", prompt)
        self.assertEqual(code, 1)
        self.assertIn("event not recorded", err)
        with mock.patch.object(claude_code, "handle", side_effect=RuntimeError("boom")):
            self.assertEqual(self.hook("codex", prompt)[0], 1)
            code, out, _ = self.hook("codex", cases("codex")[0]["payload"])
            self.assertEqual((code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]), (CODEX_DENY, "deny"))
        # Gemini: BeforeAgent and AfterTool failures must not write a deny; BeforeTool continues to block
        ge_prompt = {"session_id": "s-ge", "hook_event_name": "BeforeAgent", "prompt": "hi"}
        ge_post = {"session_id": "s-ge", "hook_event_name": "AfterTool", "tool_name": "run_shell_command",
                   "tool_input": {"command": "ls"}, "tool_response": {"llmContent": "ok"}}
        code, out, err = self.hook("gemini", ge_prompt)
        self.assertEqual((code, json.loads(out)), (1, {}))
        self.assertIn("event not recorded", err)
        code, out, err = self.hook("gemini", cases("gemini")[0]["payload"])
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))
        self.assertIn("blocking (fail-closed)", err)
        with mock.patch.object(claude_code, "handle", side_effect=RuntimeError("boom")):
            self.assertEqual(self.hook("gemini", ge_prompt)[:2], (1, "{}"))
            self.assertEqual(self.hook("gemini", ge_post)[:2], (1, "{}"))
            code, out, _ = self.hook("gemini", cases("gemini")[0]["payload"])
            self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))

    def test_a_refusal_blocks(self):
        with mock.patch.object(self.signer, "decide", side_effect=RPCError("quota_exceeded", "streams_per_run")):
            code, out, err = self.hook("gemini", cases("gemini")[0]["payload"])
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))
        self.assertIn("quota_exceeded", err)

    def test_a_gemini_id_file_it_cant_update_doesnt_stop_a_block(self):
        real = agent_hooks._paired_ids

        def ids(*a, **kw):
            if kw.get("drop"):
                raise OSError("read-only")
            return real(*a, **kw)
        with mock.patch.object(self.signer, "decide", side_effect=RPCError("quota_exceeded", "streams_per_run")), \
                mock.patch.object(agent_hooks, "_paired_ids", side_effect=ids) as m:
            code, out, err = self.hook("gemini", cases("gemini")[0]["payload"])
        self.assertTrue(any(c.kwargs.get("drop") for c in m.call_args_list))
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))


class OnTheDevPolicy(HarnessCase):
    """The signer's default policy sees what the mapping gives it: every file of a patch, the input typed into a shell."""

    def setUp(self):
        super().setUp()
        self.service = SignerService(ac.tmpdir(self), policy=load_policy())
        self.addCleanup(self.service.close)
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, self.service.handle_frame)

    def test_every_patch_target_and_write_stdin_are_decided(self):
        patch = ("*** Begin Patch\n*** Update File: README.md\n@@\n-a\n+b\n*** Update File: src/a.py\n*** Move to: {}\n"
                 "@@\n-x\n+y\n*** End Patch")
        for i, target in enumerate(("src/b.py", "config/.env", "home/.ssh/config")):
            code, out, err = self.hook("codex", {"session_id": "s", "hook_event_name": "PreToolUse",
                                                 "tool_name": "apply_patch", "tool_use_id": f"p{i}",
                                                 "tool_input": {"command": patch.format(target)}})
            self.assertEqual((code, bool(out)), (CODEX_DENY if target != "src/b.py" else 0, target != "src/b.py"), target)
            if out:
                self.assertIn("TK-D005", err)
        code, out, err = self.hook("codex", {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "write_stdin",
                                             "tool_use_id": "w1", "tool_input": {"session_id": 1, "chars": "sudo -i\n"}})
        self.assertEqual((code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]), (CODEX_DENY, "deny"))
        self.assertIn("TK-D001", err)

    def test_droid_patch_decides_every_file_including_a_move_destination(self):
        patch = ("*** Begin Patch\n*** Add File: notes.txt\n+hi\n*** Update File: src/a.py\n"
                 "*** Move to: {}\n@@\n-x\n+y\n*** End Patch")
        for target, expected in (("src/b.py", 0), ("config/.env", 2), ("home/.ssh/config", 2)):
            code, out, err = self.hook("droid", {"session_id": "droid-patch", "hook_event_name": "PreToolUse",
                                                 "tool_name": "ApplyPatch", "tool_input": {"input": patch.format(target),
                                                                                           "paths": ["decoy"], "file_path": "decoy"}})
            self.assertEqual(code, expected, err)
            if expected:
                self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertIn("TK-D005", err)

    def test_an_indented_patch_header_and_a_cursor_delete_are_decided_as_file_writes(self):
        code, out, err = self.hook("codex", {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                                             "tool_use_id": "p1", "tool_input": {
                                                 "command": "*** Begin Patch\n\t*** Add File: config/.env\n+A=1\n*** End Patch"}})
        self.assertEqual((code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]), (CODEX_DENY, "deny"))
        self.assertIn("TK-D005", err)
        code, out, err = self.hook("cursor", {"conversation_id": "c", "hook_event_name": "preToolUse", "tool_name": "Delete",
                                              "tool_use_id": "d1", "tool_input": {"file_path": "/w/.env"}})
        self.assertEqual((code, json.loads(out)["permission"]), (2, "deny"))
        self.assertIn("TK-D005", err)

    def test_a_gemini_sandbox_expansion_waits_for_a_person(self):
        pre = {"session_id": "s", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
               "tool_input": {"command": "npm install", "additional_permissions": {"network": True}}}
        # nobody answers: under twice the hook client's 30 s timeout the hook asks once and doesn't wait, and 10 s leaves
        # a slow runner room for its decide and request (1 s left none on Windows py3.9)
        with mock.patch.object(claude_code, "APPROVAL_WAIT_S", 10):
            code, out, err = self.hook("gemini", pre)
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))
        self.assertIn("waiting for approval", err)
        self.assertIn("TK-A004", err)
        pre["tool_input"]["additional_permissions"] = {"network": False}
        self.assertEqual(self.hook("gemini", pre)[0], 0)

    def test_antigravity_decides_what_its_tools_read_and_holds_a_command_outside_its_sandbox(self):
        def pre(step, name, args):
            return {"toolCall": {"name": name, "args": args}, "stepIdx": step, "conversationId": "ag-pol",
                    "workspacePaths": ["/w"]}
        for step, name, args in ((1, "write_to_file", {"TargetFile": "/w/.env", "CodeContent": "A=1",
                                                       "file_path": "/w/notes.txt"}),
                                 (2, "run_command", {"CommandLine": "rm -rf ~", "command": "ls"}),
                                 (5, "manage_task", {"Action": "send_input", "TaskId": "t1", "Input": "rm -rf ~\n"})):
            with self.subTest(name=name):
                code, out, err = self.hook("antigravity", pre(step, name, args), "PreToolUse")
                self.assertEqual((code, json.loads(out)["decision"]), (0, "deny"), err)
                self.assertIn("Blocked by tracekit policy", json.loads(out)["reason"])
        cmd = {"CommandLine": "mkdir -p /tmp/x", "BypassSandbox": True}
        with mock.patch.object(claude_code, "APPROVAL_WAIT_S", 10):   # nobody answers: see the Gemini test above
            code, out, err = self.hook("antigravity", pre(3, "run_command", cmd), "PreToolUse")
        self.assertEqual((code, json.loads(out)["decision"]), (0, "deny"))
        self.assertIn("waiting for approval", err)
        self.assertIn("TK-A003", err)
        self.assertEqual(self.hook("antigravity", pre(4, "run_command", dict(cmd, BypassSandbox=False)), "PreToolUse")[:2],
                         (0, '{"decision": "allow"}'))


class Installer(unittest.TestCase):
    def setUp(self):
        agent = mock.patch.object(claude_code, "AGENT", claude_code.AGENT)   # the in-process hooks below set it
        agent.start()
        self.addCleanup(agent.stop)

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(list(argv)), out.getvalue()

    def test_init_dev_v2_replaces_v1_and_uninstall_removes_it(self):
        d = ac.tmpdir(self)
        with mock.patch("os.getcwd", return_value=d):
            for harness in agent_hooks.HARNESSES:
                with self.subTest(harness=harness):
                    path = agent_hooks.config_path(harness, d)
                    with contextlib.redirect_stdout(io.StringIO()):
                        agent_hooks.install(harness, d)   # v1
                    code, out = self.cli("init", "--dev", "--v2", "--agent", harness, "--project")
                    self.assertEqual(code, 0)
                    self.assertIn(f"Tracekit v1 hooks replaced by v2 hooks in {path}", out)
                    if harness == "opencode":
                        with open(path) as f:
                            plugin = f.read()
                        self.assertEqual(agent_hooks._version(plugin), "v2")
                        commands = json.loads(plugin.split("const commands = ", 1)[1].split(";\n", 1)[0])
                        self.assertEqual(commands, {ev: install._dev_hook_argv(harness_hooks.__name__, "entry",
                                                                               (harness, ev))
                                                    for ev in ("tool.execute.before", "tool.execute.after")})
                        again = self.cli("init", "--dev", "--v2", "--agent", harness, "--project")[1].splitlines()
                        self.assertEqual(again[0], f"v2 {harness} hooks: {path}")
                        code, out = self.cli("uninstall", "--agent", harness, "--project")
                        self.assertEqual(code, 0)
                        self.assertEqual(out, f"Tracekit v2 hooks removed from {path}\n")
                        self.assertFalse(os.path.exists(path))
                        continue
                    if harness == "goose":
                        with open(path) as f:
                            blob = json.load(f)
                        hooks = [h for hs in blob["hooks"].values() for h in hs]
                        cmds = [h["hooks"][0]["command"] for h in hooks]
                        self.assertEqual({agent_hooks._version(c) for c in cmds}, {"v2"})
                        self.assertEqual(len(cmds), 3)   # goose installs 3 events, not 5
                        cmd = cmds[0]
                        self.assertIn(" -I ", cmd)
                        # goose runs hooks through `sh -c` on every platform (block/goose
                        # crates/goose/src/hooks/mod.rs, `hook_command`, v1.48.0 and main), so a quoted
                        # interpreter on Windows is fine: sh parses it, and the quote is required when
                        # the path has a space. No `& ` prefix either: that is PowerShell syntax, and
                        # goose never uses PowerShell. The Windows prerequisite is an sh on PATH (Git
                        # Bash); without one the hook fails to spawn and, with on_failure block, every
                        # call is blocked.
                        if os.name == "nt":
                            self.assertFalse(cmd.startswith("& "), cmd)
                        self.assertTrue(os.path.isabs(shlex.split(cmd.removeprefix("& "), posix=os.name != "nt")[0].strip('"')), cmd)
                        self.assertIn(harness_hooks.__name__, cmd)
                        again = self.cli("init", "--dev", "--v2", "--agent", harness, "--project")[1].splitlines()
                        self.assertEqual(again[0], f"v2 {harness} hooks: {path}")   # idempotent: nothing replaced
                        code, out = self.cli("uninstall", "--agent", harness, "--project")
                        self.assertEqual(code, 0)
                        self.assertEqual(out, f"Tracekit v2 hooks removed from {path}\n")
                        self.assertFalse(os.path.exists(path))   # uninstall removes the plugin's files
                        continue
                    with open(path) as f:
                        blob = json.load(f)
                    key = {"antigravity": agent_hooks.AGY_HOOK}.get(harness, "hooks")   # agy: Tracekit's named hook
                    hooks = [h for hs in (blob if harness == "droid" else blob[key]).values() for h in hs]
                    cmds = [h["command"] if harness == "cursor" else h["hooks"][0]["command"] for h in hooks]
                    self.assertEqual({agent_hooks._version(c) for c in cmds}, {"v2"})
                    # Cursor: and what its model said; agy: its tool events only
                    self.assertEqual(len(cmds), {"cursor": 8, "qwen": 6, "antigravity": 2}.get(harness, 5))
                    cmd = cmds[0]
                    self.assertIn(" -I ", cmd)
                    if os.name == "nt" and harness not in ("cursor", "droid", "qwen"):   # PowerShell can't start a quoted first word
                        self.assertFalse(cmd.startswith('"'), cmd)
                    self.assertTrue(os.path.isabs(shlex.split(cmd.removeprefix("& "), posix=os.name != "nt")[0].strip('"')), cmd)
                    self.assertIn(harness_hooks.__name__, cmd)
                    if harness == "cursor":   # a hook that can't run blocks a tool call, never a prompt
                        self.assertEqual({ev for ev, hs in blob["hooks"].items() for h in hs if h["failClosed"]},
                                         {"preToolUse"})
                    again = self.cli("init", "--dev", "--v2", "--agent", harness, "--project")[1].splitlines()
                    self.assertEqual(again[0], f"v2 {harness} hooks: {path}")   # idempotent: nothing replaced
                    if harness == "codex":   # init turned Codex's reasoning summaries on, once
                        self.assertNotIn("set by init", again[1])
                    code, out = self.cli("uninstall", "--agent", harness, "--project")
                    self.assertEqual(out, f"Tracekit v2 hooks removed from {path}\n")   # once: the CLI repeated it
                    if harness == "droid":
                        self.assertFalse(os.path.exists(path))
                        continue
                    with open(path) as f:
                        config = json.load(f)
                        self.assertNotIn(key, config)

    def test_the_wired_command_runs_the_hook(self):
        cmd = install._hook_command(harness_hooks.__name__, "entry", ("codex",))
        d = ac.tmpdir(self)
        p = subprocess.run(cmd, shell=True, cwd=d, input=json.dumps({"hook_event_name": "PreToolUse", "session_id": "s"}),
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, TRACEKIT_RUNTIME_DIR=os.path.join(d, "run"), HOME=d))
        self.assertEqual(p.returncode, CODEX_DENY, p.stderr)   # no tool_use_id: blocked before reaching any signer
        out = json.loads(p.stdout)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("no tool_use_id", out["permissionDecisionReason"])   # Codex ignores a deny without a reason
        self.assertIn("no tool_use_id", p.stderr)

    @unittest.skipUnless(os.name == "posix", "a POSIX shell wraps the hook")
    def test_antigravity_installed_commands_answer_in_json_at_exit_0_even_when_the_hook_cant_run(self):
        # agy runs a hook through sh -c and reads its answer only from its stdout at exit 0
        d = ac.tmpdir(self)
        path = os.path.join(d, "hooks.json")
        with contextlib.redirect_stdout(io.StringIO()):
            agent_hooks.install("antigravity", None, v2=True, path=path)
        with open(path) as f:
            hooks = json.load(f)[agent_hooks.AGY_HOOK]
        self.assertEqual(sorted(hooks), ["PostToolUse", "PreToolUse"])
        for ev, timeout in (("PreToolUse", 600), ("PostToolUse", 30)):   # seconds: a held call has time to be approved
            (group,) = hooks[ev]
            (h,) = group["hooks"]
            self.assertEqual((group["matcher"], h["type"], h["timeout"]), ("*", "command", timeout))
            self.assertRegex(h["command"], rf"\b{ev}\b")
        env = dict(os.environ, TRACEKIT_RUNTIME_DIR=os.path.join(d, "run"), HOME=d)
        payload = json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}, "conversationId": "c"})
        p = subprocess.run(hooks["PreToolUse"][0]["hooks"][0]["command"], shell=True, cwd=d, input=payload,
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)   # no stepIdx: blocked before reaching any signer
        self.assertEqual(json.loads(p.stdout)["decision"], "deny")
        self.assertIn("no tool_use_id", json.loads(p.stdout)["reason"])
        # as when tracekit is gone (1), the interpreter refuses its options (2) or is gone (127): agy's hook answers
        # every call at exit 0, so any other status is a deny, from the v1 hook too
        for v2, status in ((True, 1), (True, 2), (True, 127), (False, 127)):
            with self.subTest(v2=v2, status=status), contextlib.redirect_stdout(io.StringIO()), \
                    mock.patch.object(install, "_dev_hook_command", return_value=f"(exit {status})"):
                agent_hooks.install("antigravity", None, v2=v2, path=path)
                with open(path) as f:
                    hooks = json.load(f)[agent_hooks.AGY_HOOK]
                pre, post = (hooks[ev][0]["hooks"][0]["command"] for ev in ("PreToolUse", "PostToolUse"))
                p = subprocess.run(pre, shell=True, capture_output=True, text=True, timeout=30)
                self.assertEqual((p.returncode, json.loads(p.stdout)["decision"]), (0, "deny"))
                self.assertIn("call blocked (fail-closed)", json.loads(p.stdout)["reason"])
                # a result is never answered with a deny, nor failed: before agy 1.4.7 a failed PostToolUse hook
                # replaced the call's result with an error (#448)
                p = subprocess.run(post, shell=True, capture_output=True, text=True, timeout=30)
                self.assertEqual((p.returncode, p.stdout.strip()), (0, "{}"))
        with contextlib.redirect_stdout(io.StringIO()):   # system mode: init's interpreter is gone
            agent_hooks.install("antigravity", None, v2=True, python=os.path.join(d, "gone", "python"), path=path)
        with open(path) as f:
            post = json.load(f)[agent_hooks.AGY_HOOK]["PostToolUse"][0]["hooks"][0]["command"]
        p = subprocess.run(post, shell=True, capture_output=True, text=True, timeout=30)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "{}"))

    def test_a_utf8_payload_is_read_under_any_console_code_page(self):
        # Windows decodes a pipe with its ANSI code page: cp1252 has no byte 0x81, so "\u00c1" (C3 81) failed to decode,
        # the hook exited 1 and the harness ran the call
        payload = json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                              "tool_input": {"command": "echo \u00c1"}}, ensure_ascii=False).encode("utf-8")
        for name, call, code in (("codex", lambda: harness_hooks.entry("codex", "PreToolUse"), CODEX_DENY),
                                 ("claude", lambda: claude_code._entry("PreToolUse"), 2)):
            with self.subTest(hook=name):
                err = io.StringIO()
                with mock.patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="cp1252")), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(call(), code, err.getvalue())   # blocked: no tool_use_id
                self.assertIn("tool_use_id", err.getvalue())

    @unittest.skipUnless(os.name == "posix", "a POSIX shell wraps the hook")
    def test_a_hook_that_cannot_start_blocks_only_a_tool_call(self):
        # init before 1.3 wrapped every event's command to fail closed, so a Python that moved blocked each prompt too;
        # init again writes each event's own: only a pre-tool call is blocked, by its exit status or Cursor's failClosed
        d = ac.tmpdir(self)
        gone, old = os.path.join(d, "gone", "python"), install._blocking
        for python in (None, gone):   # dev mode (this interpreter, moved), system mode (OPT_PYTHON)
            # OpenCode: no shell; agy answers at exit 0 in JSON (test_antigravity_installed_commands_answer_in_json_…)
            for harness in ("claude", *(h for h in agent_hooks.HARNESSES if h not in ("opencode", "antigravity"))):
                path = os.path.join(d, str(bool(python)), harness, "hooks.json")

                def init():
                    with contextlib.redirect_stdout(io.StringIO()):
                        if harness == "claude":
                            install.install_hooks(path, python=python, module=install.V2_HOOK)
                        else:
                            agent_hooks.install(harness, v2=True, python=python, path=path)
                with self.subTest(python=python, harness=harness), mock.patch.object(sys, "executable", gone), \
                        mock.patch.object(client, "SYSTEM_CONFIG", os.path.join(d, "client.json")):
                    with mock.patch.object(install, "_blocking", lambda run, unless="", pre=True, json_deny=False: old(run, unless, json_deny=json_deny)):
                        init()   # as init before 1.3 wrote it
                    init()
                    with open(path) as f:
                        blob = json.load(f)
                    hooks = [(ev, h) for ev, groups in (blob if harness == "droid" else blob["hooks"]).items()
                             for g in groups for h in (g["hooks"] if "hooks" in g else [g])]
                    for ev, h in hooks:
                        p = subprocess.run(h["command"], shell=True, input="{}", capture_output=True, text=True,
                                           timeout=30)
                        blocked = p.returncode == 2 or p.returncode != 0 and bool(
                            h.get("failClosed") or h.get("on_failure") == "block")
                        self.assertEqual(blocked, ev in agent_hooks.PRE, (ev, p.returncode, h))
                        self.assertIn("call blocked (fail-closed)" if ev in agent_hooks.PRE else "event not recorded",
                                      p.stderr, ev)

    def installed_pre(self, harness, d):
        with contextlib.redirect_stdout(io.StringIO()):
            agent_hooks.install(harness, d, v2=True)
        with open(agent_hooks.config_path(harness, d)) as f:
            groups = json.load(f)["hooks"]["PreToolUse" if harness == "codex" else "BeforeTool"]
        return groups[0]["hooks"][0]["command"]

    def test_droid_and_qwen_windows_commands_keep_the_quoted_interpreter_for_cmd(self):
        # both run hooks under cmd.exe, which can't run PowerShell's `& "..."` (#448: Qwen Code's had it)
        d = ac.tmpdir(self)
        for harness in ("droid", "qwen"):
            for exe in (r"C:\Program Files\Python311\python.exe", r"C:\Python311\python.exe"):
                with self.subTest(harness=harness, exe=exe), mock.patch("os.name", "nt"), \
                        mock.patch.object(sys, "executable", exe), contextlib.redirect_stdout(io.StringIO()):
                    agent_hooks.install(harness, d, v2=True)
                    with open(agent_hooks.config_path(harness, d)) as f:
                        config = json.load(f)
                    command = (config if harness == "droid" else config["hooks"])["PreToolUse"][0]["hooks"][0]["command"]
                    # a path that needs no quotes goes bare for Qwen Code, which either shell runs
                    plain = harness == "qwen" and " " not in exe
                    self.assertTrue(command.startswith(f'{exe} -I ' if plain else f'"{exe}" -I '), command)
                    self.assertFalse(command.startswith("&"), command)

    @unittest.skipUnless(os.name == "nt", "Droid runs Windows hooks under cmd.exe")
    def test_droid_cmd_runs_a_hook_with_a_spaced_interpreter_path_and_keeps_its_denial(self):
        d = ac.tmpdir(self)
        out = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}})
        code = "print(bytes.fromhex('" + out.encode().hex() + "').decode()); raise SystemExit(2)"
        # Stand in only for the hook target: the installer still formats the command Droid's cmd.exe will run.
        venv = os.path.join(d, "Python with spaces")
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", venv], check=True, capture_output=True, timeout=60)
        exe = os.path.join(venv, "Scripts", "python.exe")
        with mock.patch.object(install, "_dev_hook_argv", return_value=[exe, "-I", "-c", code]):
            agent_hooks.install("droid", d, v2=True)
        with open(agent_hooks.config_path("droid", d)) as f:
            command = json.load(f)["PreToolUse"][0]["hooks"][0]["command"]
        process = subprocess.run('cmd.exe /d /s /c "' + command + '"',
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(json.loads(process.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_on_windows_the_codex_and_gemini_commands_run_under_powershell_and_cmd(self):
        d = ac.tmpdir(self)
        for exe, start in (("C:\\Python312\\python.exe", "C:\\Python312\\python.exe -I "),   # bare: both shells run it
                           ("C:/msys64/ucrt64/bin/python.exe", '& "C:/msys64/'),   # cmd.exe ends a program word at /
                           ("C:\\Program Files\\Python312\\python.exe", '& "C:\\Program Files\\')):   # PowerShell's form
            with mock.patch("os.name", "nt"), mock.patch.object(sys, "executable", exe):
                cmds = {h: self.installed_pre(h, d) for h in ("codex", "gemini")}
            for harness, cmd in cmds.items():
                with self.subTest(exe=exe, harness=harness):
                    self.assertTrue(cmd.startswith(start), cmd)
                    self.assertEqual(agent_hooks._version(cmd), "v2")
        with mock.patch("os.name", "posix"):
            self.assertFalse(self.installed_pre("codex", d).startswith("&"))   # POSIX shells: unchanged

    @unittest.skipUnless(os.name == "nt", "Codex and Gemini CLI run hooks through PowerShell on Windows")
    def test_under_powershell_the_installed_hook_blocks(self):
        d = ac.tmpdir(self)
        env = dict(os.environ, TRACEKIT_RUNTIME_DIR=os.path.join(d, "run"), HOME=d, USERPROFILE=d)
        # Gemini CLI appends `exit $LASTEXITCODE` and reads the JSON at any exit status; Codex reads it at exit 0
        for harness, tail in (("codex", ""), ("gemini", "; exit $LASTEXITCODE")):
            with self.subTest(harness=harness):
                p = subprocess.run(["powershell", "-NoProfile", "-Command", self.installed_pre(harness, d) + tail],
                                   cwd=d, input="not json", capture_output=True, text=True, timeout=120, env=env)
                self.assertIn("not a JSON object", p.stderr)   # PowerShell passed the payload through to the hook
                out = json.loads(p.stdout)
                if harness == "codex":
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertTrue(out["hookSpecificOutput"]["permissionDecisionReason"])
                else:
                    self.assertEqual(out["decision"], "deny")
        # Codex falls back to cmd.exe when PowerShell isn't found
        p = subprocess.run(f'cmd /c "{self.installed_pre("codex", d)}"', cwd=d, input="not json",   # as Codex runs it
                           capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual((p.returncode, json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"]), (0, "deny"),
                         p.stderr)

    def test_a_payload_nested_too_deep_to_read_is_blocked(self):
        deep = "[" * 100_000
        for name, call, code in (("codex", lambda: harness_hooks.run("codex", deep, event="PreToolUse"), CODEX_DENY),
                                 ("claude", lambda: claude_code._entry("PreToolUse"), 2)):
            with self.subTest(hook=name):
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(sys, "stdin", io.StringIO(deep)), contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(err):
                    self.assertEqual(call(), code)
                self.assertIn("not a JSON object", err.getvalue())
                if name == "codex":   # on Windows the JSON deny is what blocks
                    self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_codex_reads_a_block_from_exit_2_except_on_windows(self):
        # elsewhere a shell startup file's output before the JSON would spoil it; PowerShell hands 2 on as 1
        for name, want in (("posix", 2), ("nt", 0)):
            with mock.patch("os.name", name):
                self.assertEqual((agent_hooks._exit("codex", 2, True), agent_hooks._exit("codex", 2, False),
                                  agent_hooks._exit("gemini", 2, True)), (want, 1, 2))

    def test_the_v1_hooks_error_path_answers_each_event_as_itself(self):
        for event, code, denied in (("PreToolUse", CODEX_DENY, True), ("UserPromptSubmit", 1, False)):
            with self.subTest(harness="codex", event=event):
                out = io.StringIO()
                with mock.patch.object(agent_hooks, "run", side_effect=RuntimeError("boom")), \
                        mock.patch.object(agent_hooks.H, "fail_closed", return_value=True), \
                        mock.patch.object(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": event}))), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(agent_hooks.entry("codex"), code)
                self.assertEqual("deny" in out.getvalue(), denied, out.getvalue())
        for event, code, denied in (("BeforeTool", 2, True), ("BeforeAgent", 1, False), ("AfterTool", 1, False)):
            with self.subTest(harness="gemini", event=event):
                out = io.StringIO()
                with mock.patch.object(agent_hooks, "run", side_effect=RuntimeError("boom")), \
                        mock.patch.object(agent_hooks.H, "fail_closed", return_value=True), \
                        mock.patch.object(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": event}))), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(agent_hooks.entry("gemini"), code)
                self.assertEqual("deny" in out.getvalue(), denied, out.getvalue())



class CodexReasoningSummary(unittest.TestCase):
    """init --v2 --agent codex turns Codex's reasoning summaries on (current models default to none), one line at the
    top level of its config.toml, and leaves a file that sets them, or a --no-thinking-summaries init, alone."""

    def setUp(self):
        self.d = ac.tmpdir(self)
        self.hooks = os.path.join(self.d, ".codex", "hooks.json")
        self.toml = os.path.join(self.d, ".codex", "config.toml")
        os.makedirs(os.path.dirname(self.toml))

    def write(self, text):
        with open(self.toml, "w") as f:
            f.write(text)

    def read(self):
        with open(self.toml) as f:
            return f.read()

    def test_unset_goes_first_so_it_is_top_level(self):
        text = 'model = "gpt-5-codex"\n# servers\n[mcp_servers.docs]\ncommand = "docs"\n'
        self.write(text)
        self.assertEqual(agent_hooks.codex_reasoning(self.hooks), [self.toml, "auto", True])
        self.assertEqual(self.read(), agent_hooks.CODEX_LINE + text)
        self.assertTrue([n for n in os.listdir(os.path.dirname(self.toml)) if n.startswith("config.toml.bak-")])
        self.write('model = "m"')   # no table, no final newline
        agent_hooks.codex_reasoning(self.hooks)
        self.assertEqual(self.read(), agent_hooks.CODEX_LINE + 'model = "m"')

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib")
    def test_a_multi_line_array_stays_valid_toml(self):
        import tomllib
        text = 'notify = [\n["x"],\n["a", "b"]\n]\nmodel = "m"\n[profiles.fast]\nmodel = "f"\n'   # a line like a table
        self.write(text)
        self.assertEqual(agent_hooks.codex_reasoning(self.hooks)[1:], ["auto", True])
        self.assertEqual(tomllib.loads(self.read()), {**tomllib.loads(text), "model_reasoning_summary": "auto"})
        self.write(text.replace('model = "m"', 'model_reasoning_summary = "none"'))   # set after that line: refused
        with self.assertRaisesRegex(install.SettingsError, "--no-thinking-summaries"):
            agent_hooks.codex_reasoning(self.hooks)
        self.assertNotIn(agent_hooks.CODEX_LINE, self.read())

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_a_symlinked_config_is_refused_with_what_to_do(self):
        real = os.path.join(self.d, "dotfiles.toml")
        with open(real, "w") as f:
            f.write('model = "m"\n')
        os.symlink(real, self.toml)
        with self.assertRaisesRegex(install.SettingsError, "symlink.*--no-thinking-summaries"):
            agent_hooks.codex_reasoning(self.hooks)
        with open(real) as f:
            self.assertEqual(f.read(), 'model = "m"\n')

    def test_uninstall_removes_only_the_line_init_added(self):
        for before in ("", 'model = "m"\n'):
            self.write(before)
            agent_hooks.codex_reasoning(self.hooks)
            with contextlib.redirect_stdout(io.StringIO()):
                agent_hooks.install("codex", path=self.hooks, v2=True)
                agent_hooks.install("codex", path=self.hooks, uninstall=True)
            self.assertEqual(self.read(), before)
        self.write('model_reasoning_summary = "auto"\n')   # a person's own line stays
        with contextlib.redirect_stdout(io.StringIO()):
            agent_hooks.install("codex", path=self.hooks, uninstall=True)
        self.assertEqual(self.read(), 'model_reasoning_summary = "auto"\n')

    def test_a_set_value_is_left_and_a_profiles_is_not_the_top_level(self):
        for text, value in (('model_reasoning_summary = "none"  # mine\n', "none"),
                            ("model_reasoning_summary='detailed'\n[x]\n", "detailed")):
            self.write(text)
            self.assertEqual(agent_hooks.codex_reasoning(self.hooks), [self.toml, value, False])
            self.assertEqual(self.read(), text)
        self.write('[profiles.fast]\nmodel_reasoning_summary = "none"\n')
        self.assertEqual(agent_hooks.codex_reasoning(self.hooks)[1:], ["auto", True])
        self.assertTrue(self.read().startswith(agent_hooks.CODEX_LINE + '[profiles.fast]'))
        self.assertIn("off", agent_hooks.reasoning_line(self.toml, "none", False))

    def test_a_missing_file_is_created_and_init_opts_out(self):
        os.rmdir(os.path.dirname(self.toml))
        out = io.StringIO()
        with mock.patch("os.getcwd", return_value=self.d), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["init", "--dev", "--v2", "--agent", "codex", "--project",
                                       "--no-thinking-summaries"]), 0)
        self.assertFalse(os.path.exists(self.toml))
        with mock.patch("os.getcwd", return_value=self.d), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["init", "--dev", "--v2", "--agent", "codex", "--project"]), 0)
        self.assertEqual(self.read(), agent_hooks.CODEX_LINE)
        self.assertIn("Codex reasoning summaries: on", out.getvalue())


def line(e):
    return (json.dumps(e) + "\n").encode()


REASONING = {"type": "reasoning", "summary": [{"type": "summary_text", "text": "**Listing** list the files first"}],
             "encrypted_content": "gAAAAsealed"}
SAID = {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Listing the files."}]}
CALL = {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "ls -la", "yield_time_ms": 10}),
        "call_id": "call_1"}
ROLLOUT = [{"timestamp": "t", "type": "session_meta", "payload": {"id": "cx-s"}},
           {"timestamp": "t", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [
               {"type": "input_text", "text": "list the files"}]}},
           *({"timestamp": "t", "type": "response_item", "payload": i} for i in (REASONING, SAID, CALL))]


@unittest.skipIf(os.name == "nt", "the content vault test reads as the socket's uid")
class WhatTheModelSaid(HarnessCase):
    """Each harness hook records what the model said since the session's last hook, before deciding: Codex's rollout
    responses (its calls linked by call_id), Gemini CLI's thoughts, Cursor's afterAgentThought."""

    def setUp(self):
        super().setUp()
        self.d = ac.tmpdir(self)
        self.frames = []

    def serve(self, vault=True):
        from tracekit.signer import service as svc
        self.service = SignerService(os.path.join(self.d, "data"), policy=load_policy(), grace_s=0,
                                     content={"retain": True} if vault else None,
                                     authorize={f"uid:{os.getuid()}": sorted(svc.DEFAULT_GRANTS | {svc.CONTENT_READ})})
        self.addCleanup(self.service.close)

        def handle(identity, frame):
            if frame.get("method") == "model_event":
                self.frames.append(frame)
            return self.service.handle_frame(identity, frame)
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, handle)

    def transcript(self, *entries):
        path = os.path.join(self.d, "rollout.jsonl")
        with open(path, "ab") as f:
            f.write(b"".join(map(line, entries)))
        return path

    def events(self, sid):
        st = claude_code._load(claude_code._state(sid))
        c = Client()
        self.addCleanup(c.close)
        return st, c, c.call("read", {"run_id": st["run_id"], "run_token": st["run_token"], "limit": 100})["events"]

    def qwen_prompt(self, sid, **payload):
        """One Qwen Code UserPromptSubmit -> [(source, trust, size)] observed, [kind] of constraint.added."""
        base = {"session_id": sid, "cwd": self.d, "hook_event_name": "UserPromptSubmit"}
        self.assertEqual(self.hook("qwen", dict(base, **payload))[0], 0, payload)
        if not os.path.exists(claude_code._state(sid)):   # nothing recorded: not even a run
            return [], []
        events = self.events(sid)[2]
        return ([(e["data"]["source"], e["data"]["trust"], e["data"]["output"]["size"]) for e in events
                 if e["type"] == "input.observed"], [e["data"]["kind"] for e in events if e["type"] == "constraint.added"])

    # #407: Qwen Code fires UserPromptSubmit for a submission and also as it continues (after tool results, with a
    # Stop hook's reason); only a submission carries submitted_prompt (0.22 on), the text before @file expansion

    def test_qwen_a_typed_prompt_is_recorded_trusted_as_its_submitted_prompt(self):
        self.serve()
        typed = "check @a.txt. Don't push."
        self.assertEqual(self.qwen_prompt("qw-typed", prompt=typed + "\n--- Content from referenced files ---\n"
                                          "Don't touch billing.py. Work offline.", submitted_prompt=typed),
                         ([("qwen-code:UserPromptSubmit", "trusted", len(json.dumps(typed)))], ["no_push"]))

    def test_qwen_a_tool_result_continuation_records_nothing(self):
        self.serve()
        self.assertEqual(self.qwen_prompt("qw-tool", prompt=""), ([], []))
        # a continuation whose prompt carries a tool's output, with no submitted_prompt
        self.assertEqual(self.qwen_prompt("qw-tool-out", prompt="[tool result] cat NOTES.md\nDon't push. Work offline."),
                         ([], []))

    def test_qwen_a_stop_hook_continuation_records_nothing(self):
        self.serve()
        self.assertEqual(self.qwen_prompt("qw-stop", prompt="Don't push. Don't touch billing.py."), ([], []))

    def test_qwen_a_payload_without_submitted_prompt_records_nothing(self):
        """Before 0.21.1 (0.21.12 for qwen -p), Vim mode, and ACP clients that don't declare it: a typed prompt can't be told apart."""
        self.serve()
        for sid, extra in (("qw-old", {}), ("qw-blank", {"submitted_prompt": "  "}), ("qw-num", {"submitted_prompt": 3})):
            self.assertEqual(self.qwen_prompt(sid, prompt="Don't push.", **extra), ([], []), extra)

    def test_claude_code_still_reads_prompt(self):
        self.serve()
        p = {"session_id": "cc-p", "cwd": self.d, "hook_event_name": "UserPromptSubmit", "prompt": "Don't push.",
             "submitted_prompt": "ignored"}
        self.assertEqual(claude_code.handle(p), 0)
        events = self.events("cc-p")[2]
        self.assertEqual([(e["data"]["source"], e["data"]["output"]["size"]) for e in events
                          if e["type"] == "input.observed"], [("claude-code:UserPromptSubmit", len(json.dumps("Don't push.")))])
        self.assertEqual([e["data"]["kind"] for e in events if e["type"] == "constraint.added"], ["no_push"])
        self.assertEqual(agent_hooks.normalise("codex", dict(p, prompt="hi"))["prompt"], "hi")

    def test_codex_reasoning_is_recorded_before_the_decision_and_linked_by_call_id(self):
        self.serve()
        path = self.transcript(*ROLLOUT)
        pre = {"session_id": "cx-s", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "call_1",
               "tool_input": {"command": "ls -la"}, "transcript_path": path, "model": "gpt-5-codex"}
        self.assertEqual(self.hook("codex", pre)[0], 0)
        self.assertEqual(self.hook("codex", dict(pre, hook_event_name="PostToolUse", tool_response="a.txt"))[0], 0)
        st, c, events = self.events("cx-s")
        kinds = [e["type"] for e in events]
        said = events[kinds.index("model.exchange")]
        self.assertLess(kinds.index("model.exchange"), kinds.index("policy.decision"))
        self.assertEqual(kinds.count("model.exchange"), 1)   # the PostToolUse found nothing new
        self.assertEqual(self.frames[0]["tool_uses"], [{"id": "call_1", "name": "Bash", "executed_by": "client",
                                                        "args_source": "coerced", "args_digest": event_hash(
                                                            {"tool": "Bash", "args": {"command": "ls -la"}})}])
        self.assertEqual([u["id"] for u in said["data"]["tool_uses"]], ["call_1"])
        got = c.call("content_get", {"run_id": st["run_id"], "seqs": [said["run_seq"]], "purpose": "test"})["items"]
        body = got[0]["content"]
        self.assertEqual(body, {"output": [REASONING, SAID, CALL], "source": "codex rollout"})
        self.assertEqual([(x["kind"], x["form"], x["tools"]) for x in parsers.said("openai:responses", body)],
                         [("reasoning", "summary", []), ("text", "full", ["call_1"])])
        self.assertEqual(self.hook("codex", dict(pre, hook_event_name="SessionEnd", reason="exit"))[0], 0)
        self.service.sweep()   # grace 0: run.final, with nothing for reconciliation to report
        recs = [r["event"]["type"] for r in self.service.log.storage.iter_run("default", st["run_id"])]
        self.assertIn("run.final", recs)
        self.assertEqual([t for t in recs if t.startswith("reconcile.")], [])

    def test_a_resumed_codex_session_records_only_what_its_model_says_from_then_on(self):
        self.serve()
        path = self.transcript(*ROLLOUT)
        pre = {"session_id": "cx-s", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "call_1",
               "tool_input": {"command": "ls -la"}, "transcript_path": path, "model": "gpt-5-codex"}
        for event in ("PreToolUse", "PostToolUse", "SessionEnd"):
            self.assertEqual(self.hook("codex", dict(pre, hook_event_name=event, tool_response="a.txt"))[0], 0)
        self.transcript({"timestamp": "t", "type": "response_item", "payload": SAID})   # after the last hook
        # `codex resume`: the same session id, its rollout appended to
        self.assertEqual(self.hook("codex", dict(pre, hook_event_name="SessionStart", source="resume"))[0], 0)
        self.transcript({"timestamp": "t", "type": "response_item", "payload": dict(CALL, call_id="call_2")})
        self.assertEqual(self.hook("codex", dict(pre, tool_use_id="call_2"))[0], 0)
        _, _, events = self.events("cx-s")
        self.assertEqual([[u["id"] for u in e["data"].get("tool_uses", ())] for e in events
                          if e["type"] == "model.exchange"], [["call_2"]])

    def test_without_the_vault_the_body_is_not_sent(self):
        self.serve(vault=False)
        pre = {"session_id": "cx-n", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "call_1",
               "tool_input": {"command": "ls -la"}, "transcript_path": self.transcript(*ROLLOUT)}
        self.assertEqual(self.hook("codex", pre)[0], 0)
        self.assertEqual(len(self.frames), 1)
        self.assertNotIn("body", self.frames[0])
        self.assertIn("tool_uses", self.frames[0])

    def test_gemini_thoughts_are_recorded_and_name_no_call(self):
        self.serve()
        msg = {"id": "m1", "timestamp": "t", "type": "gemini", "content": "Listing.", "model": "gemini-3-pro",
               "thoughts": [{"subject": "Listing", "description": "list the files first", "timestamp": "t"}],
               "toolCalls": [{"id": "run_shell_command-1", "name": "run_shell_command", "args": {"command": "ls"}}]}
        path = self.transcript({"sessionId": "g-s", "projectHash": "h"}, msg, dict(msg, toolCalls=[]),
                               {"$patch": {"id": "m1"}})
        pre = {"session_id": "g-s", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
               "tool_input": {"command": "ls"}, "transcript_path": path}
        self.assertEqual(self.hook("gemini", pre)[0], 0)
        self.assertEqual(len(self.frames), 1)   # a message written again is recorded once
        self.assertNotIn("tool_uses", self.frames[0])
        self.assertEqual([(x["kind"], x["form"], x["text"]) for x in parsers.said("openai:responses",
                                                                                  self.frames[0]["body"])],
                         [("reasoning", "summary", "**Listing** list the files first"), ("text", "full", "Listing.")])
        self.assertEqual((self.frames[0]["provider"], self.frames[0]["model"]), ("google", "gemini-3-pro"))

    def test_a_harness_that_names_no_call_is_never_accused_of_fabricating_one(self):
        """Gemini CLI's and Cursor's messages are recorded without their calls (neither gives a call an id): the
        signer must not read each decided call as one no model message asked for (reconcile.fabricated)."""
        self.serve()
        msg = {"id": "m1", "timestamp": "t", "type": "gemini", "content": "Listing.", "model": "gemini-3-pro",
               "thoughts": [{"subject": "Listing", "description": "list the files first", "timestamp": "t"}]}
        path = self.transcript({"sessionId": "g-f", "projectHash": "h"}, msg)
        pre = {"session_id": "g-f", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
               "tool_input": {"command": "ls"}, "transcript_path": path}
        self.assertEqual(self.hook("gemini", pre)[0], 0)
        self.assertEqual(self.hook("gemini", dict(pre, hook_event_name="AfterTool", tool_response="a.txt"))[0], 0)
        self.hook("cursor", {"conversation_id": "cu-f", "hook_event_name": "afterAgentThought", "text": "list first"})
        cur = {"conversation_id": "cu-f", "hook_event_name": "preToolUse", "tool_name": "Shell", "tool_use_id": "tu_1",
               "tool_input": {"command": "ls"}, "cwd": self.d}
        self.assertEqual(self.hook("cursor", cur)[0], 0)
        self.hook("cursor", dict(cur, hook_event_name="postToolUse", tool_output="a.txt"))
        runs = {sid: self.events(sid)[0]["run_id"] for sid in ("g-f", "cu-f")}
        self.hook("gemini", dict(pre, hook_event_name="SessionEnd", reason="exit"))
        self.hook("cursor", {"conversation_id": "cu-f", "hook_event_name": "sessionEnd", "reason": "exit"})
        self.service.sweep()
        for sid, run_id in runs.items():
            recs = [r["event"]["type"] for r in self.service.log.storage.iter_run("default", run_id)]
            self.assertIn("run.final", recs)
            self.assertEqual((recs.count("model.exchange") > 0, recs.count("policy.decision")), (True, 1), sid)
            self.assertEqual([t for t in recs if t.startswith("reconcile.")], [], sid)

    def test_cursor_thinking_is_recorded(self):
        self.serve()
        out = self.hook("cursor", {"conversation_id": "cu-s", "generation_id": "g1", "model": "claude-x",
                                   "hook_event_name": "afterAgentThought", "text": "check the tests first",
                                   "duration_ms": 900})
        self.assertEqual(out[:2], (0, "{}"))
        self.assertEqual([(x["kind"], x["text"]) for x in parsers.said("openai:responses", self.frames[0]["body"])],
                         [("reasoning", "check the tests first")])
        self.assertEqual(self.frames[0]["body"]["source"], "cursor hook")
        self.hook("cursor", {"conversation_id": "cu-s", "hook_event_name": "afterAgentResponse", "text": "Done."})
        self.assertEqual(self.frames[1]["body"]["output"][0]["content"][0]["text"], "Done.")

    def test_a_failure_to_record_never_changes_the_decision(self):
        self.serve()
        pre = {"session_id": "cx-f", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "call_1",
               "tool_input": {"command": "ls -la"}, "transcript_path": self.d}   # a directory: unreadable
        code, out, err = self.hook("codex", pre)
        self.assertEqual((code, out), (0, ""))
        self.assertIn("what the model said was not recorded", err)
        with mock.patch.object(harness_hooks.said.Said, "__init__", side_effect=RuntimeError("boom")):
            code, _, err = self.hook("codex", dict(pre, tool_use_id="call_2",
                                                   transcript_path=self.transcript(*ROLLOUT)))
        self.assertEqual(code, 0)
        self.assertIn("boom", err)
        _, _, events = self.events("cx-f")
        self.assertEqual([e["data"]["decision"] for e in events if e["type"] == "policy.decision"], ["allow", "allow"])


class NoTailer(unittest.TestCase):
    def test_other_harnesses_start_no_transcript_tailer(self):
        """The tailer reads Claude Code transcripts only: another harness's run starts none and records no gap."""
        st = {"run_id": "r1", "run_token": "x.y", "transcript": "/tmp/t.jsonl"}
        client = mock.Mock()
        with mock.patch.object(claude_code, "AGENT", "codex"), mock.patch.object(claude_code.subprocess, "Popen") as po, \
                mock.patch.object(claude_code, "system_config", return_value={"signer": "/run/s.sock"}):
            claude_code._tail(client, "/tmp/state.json", st)
        po.assert_not_called()
        client.assert_not_called()
        self.assertNotIn("tailer", st)


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs FIFOs")
class TranscriptRead(unittest.TestCase):
    def test_a_fifo_in_the_transcripts_place_is_not_read_and_never_blocks(self):
        fifo = os.path.join(ac.tmpdir(self), "session.jsonl")
        os.mkfifo(fifo)
        got = []
        t = threading.Thread(target=lambda: got.append(harness_hooks._read(fifo, {"offset": 0})), daemon=True)
        t.start()
        t.join(5)
        if t.is_alive():   # blocked opening it: a writer releases it
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            self.fail("the hook blocked on a FIFO transcript")
        self.assertEqual(got, [[]])


if __name__ == "__main__":
    unittest.main()
