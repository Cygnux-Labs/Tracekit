"""The v2 hooks of Codex CLI, Cursor and Gemini CLI (tracekit/integrations/harness_hooks.py).

The mapping tables are checked against recorded sample payloads (tests/data/harness/<harness>.json): each case is the
harness's PreToolUse payload, the decision the signer gives, the exact `decide` request the hook must send (tool,
args, tool_call_id) and the reply the harness must get (exit code and stdout). Gemini CLI gives tool calls no id, so
its cases name none: the hook pairs calls itself (tracekit.agent_hooks._gemini_ids) and the test checks the ids are
distinct and never a default.
"""
import contextlib
import io
import json
import os
import shlex
import subprocess
import threading
import time
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit import agent_hooks, cli, install
from tracekit.integrations import claude_code, harness_hooks
from tracekit.sdk.client import Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService, load_policy
from tracekit.testing import FakeSigner

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

    def hook(self, harness, payload):
        out, err = io.StringIO(), io.StringIO()
        code = harness_hooks.run(harness, json.dumps(payload), out, err)
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
                code, out, err = self.hook(harness, case["payload"])
                self.assertEqual(code, case["exit"], err)
                self.assertEqual(json.loads(out) if out else "", case["stdout"])
                sent = self.sent[-1]
                if case["request"]["tool_call_id"] is None:   # Gemini: paired by the hook, never defaulted
                    self.assertRegex(sent["tool_call_id"], r"^gem_[0-9a-f]{16}_\d+$")
                    sent = dict(sent, tool_call_id=None)
                self.assertEqual(sent, case["request"])
        self.assertEqual(len({s["tool_call_id"] for s in self.sent}), len(self.sent))

    def test_codex(self):
        self.check("codex")

    def test_cursor(self):
        self.check("cursor")

    def test_gemini(self):
        self.check("gemini")

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
                 {"hook_event_name": "AfterTool", "tool_response": {"llmContent": "a.txt"}})):
            with self.subTest(harness=harness):
                self.assertEqual(self.hook(harness, pre)[0], 0)
                self.assertEqual(self.hook(harness, dict(pre, **post))[:2], (0, "{}" if harness != "codex" else ""))
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
                self.assertEqual(code, 2)
                self.assertIn("deny", json.dumps(json.loads(out)))
                self.assertIn(reply, out)
                self.assertIn("tool call blocked", err)
        self.assertEqual(self.sent, [])
        self.assertFalse(os.path.exists(os.environ["TRACEKIT_CLIENT_HOME"]))   # no Gemini id was paired

    def test_signer_unreachable_is_fail_closed_by_default(self):
        os.environ["TRACEKIT_SIGNER"] = os.path.join(os.environ["HOME"], "nowhere.sock")
        code, out, err = self.hook("codex", cases("codex")[0]["payload"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("blocking (fail-closed)", err)

    def test_a_refusal_blocks(self):
        with mock.patch.object(self.signer, "decide", side_effect=RPCError("quota_exceeded", "streams_per_run")):
            code, out, err = self.hook("gemini", cases("gemini")[0]["payload"])
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))
        self.assertIn("quota_exceeded", err)


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
            self.assertEqual(code, 0 if target == "src/b.py" else 2, target)
            if code:
                self.assertIn("TK-D005", err)
        code, _, err = self.hook("codex", {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "write_stdin",
                                           "tool_use_id": "w1", "tool_input": {"session_id": 1, "chars": "sudo -i\n"}})
        self.assertEqual(code, 2)
        self.assertIn("TK-D001", err)


class Installer(unittest.TestCase):
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
                    with open(path) as f:
                        blob = json.load(f)
                    hooks = [h for hs in blob["hooks"].values() for h in hs]
                    cmds = [h["command"] if harness == "cursor" else h["hooks"][0]["command"] for h in hooks]
                    self.assertEqual({agent_hooks._version(c) for c in cmds}, {"v2"})
                    self.assertEqual(len(cmds), 6 if harness == "cursor" else 5)
                    cmd = cmds[0]
                    self.assertIn(" -I ", cmd)
                    self.assertTrue(os.path.isabs(shlex.split(cmd)[0]), cmd)
                    self.assertIn(harness_hooks.__name__, cmd)
                    if harness == "cursor":
                        self.assertTrue(all(h["failClosed"] for h in hooks))
                    self.assertEqual(self.cli("init", "--dev", "--v2", "--agent", harness, "--project")[1],
                                     f"v2 {harness} hooks: {path}\n")   # idempotent: nothing replaced
                    code, out = self.cli("uninstall", "--agent", harness, "--project")
                    self.assertIn(f"Tracekit v2 hooks removed from {path}", out)
                    with open(path) as f:
                        self.assertNotIn("hooks", json.load(f))

    def test_the_wired_command_runs_the_hook(self):
        cmd = install._hook_command(harness_hooks.__name__, "entry", ("codex",))
        d = ac.tmpdir(self)
        p = subprocess.run(cmd, shell=True, cwd=d, input=json.dumps({"hook_event_name": "PreToolUse", "session_id": "s"}),
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, TRACEKIT_RUNTIME_DIR=os.path.join(d, "run"), HOME=d))
        self.assertEqual(p.returncode, 2, p.stderr)   # no tool_use_id: blocked before reaching any signer
        self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("no tool_use_id", p.stderr)



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


if __name__ == "__main__":
    unittest.main()
