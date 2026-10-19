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
import sys
import threading
import time
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit import agent_hooks, cli, install, parsers
from tracekit.format.canon import event_hash
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

    def test_only_a_tool_call_is_blocked_when_the_hook_fails(self):
        """2 on a prompt event blocked the prompt itself."""
        os.environ["TRACEKIT_SIGNER"] = os.path.join(os.environ["HOME"], "nowhere.sock")
        prompt = {"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": "hi"}
        code, _, err = self.hook("codex", prompt)
        self.assertEqual(code, 1)
        self.assertIn("event not recorded", err)
        with mock.patch.object(claude_code, "handle", side_effect=RuntimeError("boom")):
            self.assertEqual(self.hook("codex", prompt)[0], 1)
            self.assertEqual(self.hook("codex", cases("codex")[0]["payload"])[0], 2)

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

    def test_a_gemini_sandbox_expansion_waits_for_a_person(self):
        pre = {"session_id": "s", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
               "tool_input": {"command": "npm install", "additional_permissions": {"network": True}}}
        with mock.patch.object(claude_code, "APPROVAL_WAIT_S", 1):   # nobody answers
            code, out, err = self.hook("gemini", pre)
        self.assertEqual((code, json.loads(out)["decision"]), (2, "deny"))
        self.assertIn("waiting for approval", err)
        self.assertIn("TK-A004", err)
        pre["tool_input"]["additional_permissions"] = {"network": False}
        self.assertEqual(self.hook("gemini", pre)[0], 0)


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
                    self.assertEqual(len(cmds), 8 if harness == "cursor" else 5)   # Cursor: and what its model said
                    cmd = cmds[0]
                    self.assertIn(" -I ", cmd)
                    self.assertTrue(os.path.isabs(shlex.split(cmd)[0]), cmd)
                    self.assertIn(harness_hooks.__name__, cmd)
                    if harness == "cursor":
                        self.assertTrue(all(h["failClosed"] for h in hooks))
                    again = self.cli("init", "--dev", "--v2", "--agent", harness, "--project")[1].splitlines()
                    self.assertEqual(again[0], f"v2 {harness} hooks: {path}")   # idempotent: nothing replaced
                    if harness == "codex":   # init turned Codex's reasoning summaries on, once
                        self.assertNotIn("set by init", again[1])
                    code, out = self.cli("uninstall", "--agent", harness, "--project")
                    self.assertEqual(out, f"Tracekit v2 hooks removed from {path}\n")   # once: the CLI repeated it
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


if __name__ == "__main__":
    unittest.main()
