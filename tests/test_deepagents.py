"""Deep Agents' real filesystem tools through the LangChain policy gate."""
from contextlib import closing
from functools import wraps
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

from tracekit.signer import service as svc

HAVE_DEEP_AGENTS = importlib.util.find_spec("deepagents") is not None
BACKENDS = ("re2", "regex") if importlib.util.find_spec("re2") else ("regex",)
PACKS = ("coding", "dev", "server", "strict")
LINK_TEXT = "See https://github.com/Cygnux-Labs/Tracekit for the source."


@unittest.skipUnless(HAVE_DEEP_AGENTS, "install the optional Deep Agents test dependencies")
class DeepAgents(unittest.TestCase):
    def test_real_tools_match_their_policy_counterparts_on_each_pack_and_engine(self):
        from deepagents.middleware.filesystem import FilesystemMiddleware
        from langchain_core.tools import tool

        from tracekit.integrations.langchain import _policy_tool

        @tool("read_file")
        def custom_read(file_path: str) -> str:
            """The application's own read tool."""
            return file_path

        @tool("write_file")
        def custom_write(file_path: str, content: str) -> str:
            """The application's own write tool."""
            return content

        implementations = {t.name: t for t in FilesystemMiddleware().tools}
        path = "/workspace/handoff.md"
        cases = {
            "ls": ("LS", {"path": "/workspace"}),
            "read_file": ("Read", {"file_path": path, "limit": 2}),
            "write_file": ("Write", {"file_path": path, "content": LINK_TEXT}),
            "edit_file": ("Edit", {"file_path": path, "old_string": "before", "new_string": "after"}),
            "glob": ("Glob", {"path": "/workspace", "pattern": "*.md"}),
            "grep": ("Grep", {"path": "/workspace", "pattern": "handoff", "glob": "*.md"}),
            "execute": ("Bash", {"command": "pwd", "timeout": 5}),
        }
        for pack in PACKS:
            for backend in BACKENDS:
                policy = svc.load_policy(os.path.join(os.path.dirname(svc.DEFAULT_POLICY), pack + ".yaml"), backend)
                for name, (canonical, args) in cases.items():
                    with self.subTest(pack=pack, backend=backend, tool=name):
                        tagged = _policy_tool({"name": name, "args": args}, implementations[name])
                        self.assertEqual(tagged, "deepagents:" + name)
                        decision = svc.evaluate(policy, tagged, args)[0]
                        self.assertEqual(decision, svc.evaluate(policy, canonical, args)[0])
                        if name == "write_file":
                            self.assertNotIn("TK-F012", decision["rule_ids"])
                for custom in (custom_read, custom_write):
                    name = custom.name
                    with self.subTest(pack=pack, backend=backend, custom=name):
                        args = cases[name][1]
                        if name == "read_file":
                            args = {"file_path": path}
                        self.assertEqual(_policy_tool({"name": name, "args": args}, custom), name)
                        decision = svc.evaluate(policy, name, args)[0]
                        self.assertEqual(decision["verdict"], "flag" if pack in ("coding", "dev") else "ask")
                        self.assertIn("TK-UNKNOWN-TOOL", decision["rule_ids"])
        for args in ({"command": 42}, {"command": "pwd", "cmd": "pwd"}):
            self.assertEqual(_policy_tool({"name": "execute", "args": args}, implementations["execute"]), "execute")
        self.assertIsNone(_policy_tool({"name": "deepagents:write_file", "args": {}}, custom_write))
        builtin = implementations["write_file"]

        @wraps(builtin.func)
        def app_wrapper(**kwargs):
            return kwargs

        @wraps(builtin.coroutine)
        async def async_app_wrapper(**kwargs):
            return kwargs

        wrapped = builtin.model_copy(update={"func": app_wrapper, "coroutine": async_app_wrapper})
        self.assertEqual(_policy_tool({"name": "write_file", "args": cases["write_file"][1]}, wrapped), "write_file")

    def test_real_agent_writes_a_url_and_reconciles_under_the_original_name(self):
        from deepagents import create_deep_agent
        from deepagents.backends import FilesystemBackend
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage, ToolMessage

        from test_integration_langchain import Agent
        from test_signer_service import ME
        from tracekit.integrations.langchain import TracekitMiddleware

        class ScriptedModel(GenericFakeChatModel):
            def bind_tools(self, tools, **kwargs):
                return self

        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / "workspace"
            workspace.mkdir()
            (workspace / "notes.md").write_text("Example project notes.")
            with closing(svc.SignerService(os.path.join(root, "signer"), grace_s=0)) as service:
                client = Agent(service, ME)
                registered = client.register_run({"request_id": "register", "agent": {"name": "deepagents"}})
                run = {key: registered[key] for key in ("run_id", "run_token")}
                gate = TracekitMiddleware(client, **run)
                calls = [{"id": "read-1", "name": "read_file", "args": {"file_path": "/notes.md"}},
                         {"id": "write-1", "name": "write_file",
                          "args": {"file_path": "/handoff.md", "content": LINK_TEXT}}]
                model = ScriptedModel(messages=iter([AIMessage("", tool_calls=calls), AIMessage("Done")]))
                agent = create_deep_agent(model, backend=FilesystemBackend(root_dir=workspace), middleware=[gate])
                result = agent.invoke({"messages": [("user", "Read the notes and write the handoff.")]})
                messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
                self.assertEqual({(m.name, m.status) for m in messages},
                                 {("read_file", "success"), ("write_file", "success")})
                self.assertEqual((workspace / "handoff.md").read_text().strip(), LINK_TEXT)
                client.close_run({"request_id": "close", **run})
                service.sweep(time.monotonic() + 1)
                events = [r["event"] for r in service.log.storage.iter_run("default", run["run_id"])]
                decisions = {e["data"]["tool"]: e["data"] for e in events if e["type"] == "policy.decision"}
                self.assertEqual([(d["decision"], d["rule_ids"]) for d in decisions.values()],
                                 [("allow", []), ("allow", [])])
                self.assertEqual(set(decisions), {"deepagents:read_file", "deepagents:write_file"})
                self.assertEqual(sum(e["type"] == "tool.result" for e in events), 2)
                self.assertFalse([e for e in events if e["type"].startswith("reconcile.") or e["type"] == "capture.gap"])
                self.assertEqual(events[-1]["type"], "run.final")
                self.assertEqual(events[-1]["data"]["coverage"]["reconciled"], 2)

    def test_mapped_results_keep_the_canonical_tools_untrusted_policy(self):
        from tracekit.policy2.engine import Engine

        policy = Engine({"tools": {"Read": "fs"}, "untrusted": ["Read"]})
        self.assertTrue(policy.untrusted_results("deepagents:read_file"))
        self.assertFalse(policy.untrusted_results("read_file"))
