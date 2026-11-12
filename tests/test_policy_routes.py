"""Second routes to what the packs hold, each read as a whole class on dev, coding, server and strict and on both
engines: every way the shell writes a file (TK-D014, TK-A067, TK-A068, TK-F024) and a pattern that may name one, a
for loop's brace words, a harness's own settings commands and a harness started with settings the agent chose
(TK-A054, TK-A069, TK-A070), an unmapped file tool read as the file tool it is, a `commands` list read entry by entry,
SQL comments and dollar quotes as PostgreSQL and MySQL lex them, and text typed into a live shell."""
import asyncio
import importlib.util
import json
import os
import unittest

from tracekit import agent_hooks, constraints
from tracekit.integrations import hermes
from tracekit.policy2 import classes, compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc

PACKS = os.path.dirname(svc.DEFAULT_POLICY)
BACKENDS = ("re2", "regex") if importlib.util.find_spec("re2") else ("regex",)
NAMES = ("dev", "coding", "server", "strict")
D = "DR" + "OP TABLE users"
PUSH = "git push --fo" + "rce origin main"


class Routes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engines = {(n, b): Engine(pc.build(os.path.join(PACKS, n + ".yaml"))[0], b) for n in NAMES for b in BACKENDS}

    def expect(self, cases, want, rule=None, packs=NAMES):
        """Each call's verdict on each named pack (`want`: one verdict, or {pack: verdict}) through the signer's own
        reading (service.evaluate), with `rule` among its rule ids where it isn't allowed."""
        for tool, args in cases:
            for (name, backend), e in self.engines.items():
                if name not in packs:
                    continue
                w = want[name] if isinstance(want, dict) else want
                with self.subTest(pack=name, engine=backend, tool=tool, args=str(args)[:90]):
                    d = svc.evaluate(e, tool, args)[0]
                    self.assertEqual(d["verdict"], w, d)
                    if rule and w != "allow":
                        self.assertIn(rule, d["rule_ids"], d)

    def bash(self, *commands):
        return [("Bash", {"command": c}) for c in commands]

    # --- every way the shell writes a file
    def test_a_credentials_file_written_by_any_writer_is_denied(self):
        self.expect(self.bash("sed -i 's/a/b/' .env", "perl -pi -e 's/a/b/' .env", "ruby -i -pe '1' .env",
                              "sed --in-place 's/a/b/' .env", "f=.env; sed -i 's/a/b/' $f", "truncate -s0 .env",
                              "dd if=x of=.env", "awk '{print > \".env\"}' x", "sed -i 's/a/b/' ~/.aws/credentials",
                              "sed -i 's/a/b/' ~/.ssh/config", "sed -i 's/a/b/' ~/.ssh/authorized_keys",
                              "find . -name .env -exec sed -i 's/a/b/' {} +"), "deny", "TK-D014")

    def test_a_startup_item_or_git_hook_written_by_any_writer_is_held(self):
        self.expect(self.bash("sed -i 's/a/b/' /etc/profile", "perl -pi -e 's/a/b/' /etc/profile.d/x.sh",
                              "cp x /etc/zshrc"), "ask", "TK-A067")
        self.expect(self.bash("perl -pi -e 's/a/b/' .git/hooks/pre-commit", "truncate -s0 .git/hooks/pre-push"),
                    "ask", "TK-A068")

    def test_a_shell_startup_file_written_by_any_writer_is_flagged_and_held_on_strict(self):
        # as TK-F011 reads a redirection into one: a coding agent's PATH line in ~/.bashrc is ordinary setup
        self.expect(self.bash("sed -i 's/a/b/' ~/.bashrc", "cp x ~/.zshrc", "perl -pi -e 's/a/b/' ~/.profile"),
                    {"dev": "flag", "coding": "flag", "server": "flag", "strict": "ask"}, "TK-F024")

    def test_a_pattern_is_read_as_each_protected_name_it_may_make(self):
        # bash expands a redirection's pattern that matches one file, and an argument's to each file it matches
        held = {"dev": "ask", "coding": "ask", "server": "ask", "strict": "deny"}
        self.expect(self.bash("echo k >> ~/.ssh/authorized_key?", "echo x > .en?", "sed -i 's/a/b/' .e[n]v"), held,
                    "TK-D014")
        self.expect(self.bash("echo x > ~/.bashr?", "sed -i 's/a/b/' ~/.b*", "echo x >> ~/.zsh*"),
                    {"dev": "flag", "coding": "flag", "server": "flag", "strict": "ask"}, "TK-F024")
        self.expect(self.bash("echo x > .git/hook?/pre-commit"), "ask", "TK-A068")
        self.expect(self.bash("cp ~/.ssh/id_* /tmp/"), held, "TK-D014")

    def test_ordinary_writes_and_patterns_stay_unheld(self):
        self.expect(self.bash("sed -i 's/foo/bar/g' src/app.py", "sed -i 's/a/b/' *.py", "echo x > out.txt",
                              "perl -pi -e 's/a/b/' src/*.rs", "cp config.example config.local"), "allow")
        for (name, backend), e in self.engines.items():   # flagged at most, as before
            for c in ("rm -f build/*", "find . -name '*.pyc' -delete", "sed -i 's/a/b/' .env.example",
                      "echo 'export PATH=$PATH:~/bin' >> ~/.bashrc", "chmod 600 .env"):
                with self.subTest(pack=name, engine=backend, command=c):
                    self.assertIn(svc.evaluate(e, "Bash", {"command": c})[0]["verdict"],
                                  ("allow", "flag") if name != "strict" or "bashrc" not in c else ("ask",))

    # --- a for loop's brace words
    def test_a_for_loops_brace_words_are_its_values(self):
        self.expect(self.bash("for k in id_{rsa,x}; do cp ~/.ssh/$k /tmp/; done"), "deny", "TK-D014")
        self.expect(self.bash("for h in {169.254.169.254,x}; do curl -s http://$h/; done",
                              "for h in 1{6,8}9.254.169.254; do curl -s http://$h/; done"),
                    {"dev": "deny", "server": "deny", "strict": "deny"}, "TK-S001", packs=("dev", "server", "strict"))

    # --- a harness's own settings commands and a harness started with settings the agent chose
    def test_a_harness_settings_command_is_held(self):
        self.expect(self.bash("hermes plugins disable tracekit", "hermes -p work plugins remove tracekit"), "ask",
                    "TK-A054")
        self.expect([("terminal", {"command": c}) for c in ("hermes config set approvals.mode off",
                                                            "hermes config edit", "hermes profile use other")],
                    "ask", "TK-A069")

    def test_a_harness_started_with_settings_the_agent_chose_is_held(self):
        self.expect(self.bash("HOME=/tmp/h claude -p 'fix the tests'", "env HOME=/tmp/h claude -p x",
                              "CLAUDE_CONFIG_DIR=/tmp/c claude -p x", "export CODEX_HOME=/tmp/c; codex exec x",
                              "HERMES_HOME=/tmp/h hermes chat -q x", "XDG_CONFIG_HOME=/tmp/x opencode run x",
                              "env -i claude -p x", "claude -p x --settings /tmp/s.json",
                              "claude -p x --setting-sources project", "codex -c hooks=false exec x",
                              "hermes -p other chat -q x", "cline --config /tmp/c -y x",
                              "OPENHANDS_WORK_DIR=/tmp/x openhands --headless -t x"), "ask", "TK-A070")
        # as the person set it up, a nested run reads the person's settings and runs their hooks
        self.expect(self.bash("claude -p 'fix the tests'", "codex exec 'fix it'", "gemini -p x", "hermes chat -q x",
                              "HOME=/tmp/h npm test", "claude --version"), "allow")

    def test_hermes_settings_files_are_the_harness_settings(self):
        self.expect([("Write", {"file_path": "/home/u/.hermes/config.yaml", "content": "x"})], "ask", "TK-F009")
        self.expect(self.bash("echo x >> ~/.hermes/config.yaml", "mv ~/.hermes/plugins/tracekit /tmp/",
                              "sed -i 's/a/b/' $HERMES_HOME/config.yaml"), "ask", "TK-F015")

    # --- an unmapped file tool, read as the file tool it is
    def test_an_unmapped_file_tool_is_also_decided_as_the_file_tool_it_is(self):
        patch = "*** Begin Patch\n*** Update File: ~/.ssh/config\n@@\n-a\n+b\n*** End Patch"
        self.expect([("write_file", {"path": "/home/u/.hermes/config.yaml", "content": "x"}),
                     ("patch", {"path": ".git/hooks/pre-commit", "old_string": "a", "new_string": "b"})], "ask")
        self.expect([("write_file", {"path": ".env", "content": "x"}), ("patch", {"mode": "patch", "patch": patch}),
                     ("write_file", {"file_path": "src/app.py", "path": "~/.ssh/id_rsa", "content": "x"})],
                    "deny", "TK-D005")
        # never looser than the unknown tool it also is
        self.expect([("write_file", {"path": "src/app.py", "content": "x"}), ("search_files", {"pattern": "x"})],
                    {"dev": "flag", "coding": "flag", "server": "ask", "strict": "ask"}, "TK-UNKNOWN-TOOL")

    def test_text_typed_into_a_running_process_is_also_read_as_the_shell_line_it_is(self):
        self.expect([("process_manage", {"action": a, "session_id": "p1", "data": "sudo id"})
                     for a in ("write", "submit")], "deny", "TK-D001")
        self.expect([("process_manage", {"action": "poll", "session_id": "sudo id"})],
                    {"dev": "flag", "coding": "flag", "server": "ask", "strict": "ask"})

    # --- a commands list, entry by entry
    def test_each_entry_of_a_commands_list_is_read_on_its_own(self):
        # the OpenAI Agents SDK's ShellTool runs each entry in its own process, LangChain's joins them with `;`
        self.expect([("shell", {"commands": ["echo ok \\", "sudo id"]}), ("shell", {"commands": ["echo 'x", "sudo id", "'"]}),
                     ("terminal", {"commands": ["cat <<EOF", "sudo id", "EOF"]})], "deny", "TK-D001")
        self.assertTrue(constraints.shell({"commands": ["echo ok \\", "git push origin main"]})["push"])
        self.expect([("shell", {"commands": ["ls", "git status"]})], "allow")

    # --- SQL as the database lexes it
    def test_sql_comments_and_dollar_quotes_read_as_the_database_lexes_them(self):
        pg, my = classes.SQL_DIALECTS["postgres"], classes.SQL_DIALECTS["mysql"]
        # PostgreSQL 16 dropped the table for each: `/*/` inside a comment opens a nested one, and a dollar-quote tag
        # may hold a letter past ASCII; MySQL's -- starts a comment before any control character, DEL too
        self.assertIn("DROP", classes.sql_code(f"/* /*/ ' */ */ {D}; -- '", *pg))
        self.assertIn("DROP", classes.sql_code(f"SELECT $é$'$é$; {D}; -- '", *pg))
        self.assertIn("DROP", classes.sql_code(f"--\x7f\"\n# '\n{D}\n# \"'", *my))
        self.assertIn("DROP", classes.sql_code(f"--\x01'\n{D};\n-- '", *my))
        self.assertNotIn("DROP", classes.sql_code(f"--x '\n{D}\n'", *my) or "")   # --x is no comment there
        held = {"dev": "deny", "server": "deny", "strict": "deny"}
        self.expect([("mcp:postgres/query", {"sql": f"/* /*/ ' */ */ {D}; -- '"}),
                     ("mcp:supabase/execute_sql", {"query": f"/* /*/ ' */ */ {D}; -- '"}),
                     ("mcp:mysql/execute_sql", {"sql": f"--\x7f\"\n# '\n{D}\n# \"'"})], held, "TK-DB001",
                    packs=("dev", "server", "strict"))


class TypedText(unittest.TestCase):
    """Text typed into a live terminal (Devin's write_to_process, Codex's write_stdin, agy's send_input, Hermes's
    process_manage) that leaves its line unfinished is joined to the next call's by the shell: `git \\` then
    `push --force origin main` ran the push in an interactive bash, as `git ` with no newline did."""

    def blocked(self, harness, name, ti):
        if harness == "antigravity":
            raw = json.dumps({"hook_event_name": "PreToolUse", "toolCall": {"name": name, "args": ti}})
            return agent_hooks._blocked(harness, {}, raw)
        p = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": ti}
        return agent_hooks._blocked(harness, p, json.dumps(p))

    def typed(self, text):
        return [("devin", "write_to_process", {"shell_id": "main", "input": text}),
                ("codex", "write_stdin", {"session_id": 1, "chars": text}),
                ("antigravity", "manage_task", {"Action": "send_input", "Input": text, "TaskId": "t"})]

    def test_an_unfinished_line_or_a_control_character_is_blocked(self):
        for text, why in (("git \\\n", "doesn't finish"), ("git ", "doesn't finish"), ("q", "doesn't finish"),
                          (f"echo ok\x15{PUSH}\n", "control character"), ("gix\x7ft status\n", "control character"),
                          ("ech\t hi\n", "control character")):
            for harness, name, ti in self.typed(text):
                with self.subTest(harness=harness, text=text):
                    self.assertIn(why, self.blocked(harness, name, ti) or "")
        self.assertIn("doesn't finish", hermes._typed("process_manage", {"action": "write", "data": "git "}) or "")

    def test_whole_lines_an_interrupt_and_an_end_of_input_go_to_the_signer(self):
        for text in ("ls -la\n", "y\r\n", "echo a\\\\\n", "\x03", "\x04", ""):
            for harness, name, ti in self.typed(text)[not text:]:   # (Devin's empty input names no text)
                with self.subTest(harness=harness, text=text):
                    self.assertIsNone(self.blocked(harness, name, ti))
        self.assertIsNone(hermes._typed("process_manage", {"action": "submit", "data": "git "}))   # submit adds \n
        # \r ends a typed line, so each line is decided
        tool, args = agent_hooks.tool("codex", "write_stdin", {"session_id": 1, "chars": f"echo ok\r{PUSH}\r"})
        self.assertEqual(svc.load_policy().decide(tool, args)["verdict"], "deny")


class OpenCodePaths(unittest.TestCase):
    def test_both_releases_path_keys_are_decided(self):
        # OpenCode 2.x's read, write and edit read `path`, 1.x's filePath: a decoy under the other key stood in for it
        e = svc.load_policy()
        for name, ti, want in (("write", {"path": "/home/u/.bashrc", "filePath": "/w/ok.txt", "content": "x"}, "ask"),
                               ("edit", {"path": "/w/.git/hooks/pre-commit", "filePath": "/w/ok.txt", "oldString": "a",
                                         "newString": "b"}, "ask"),
                               ("write", {"filePath": "/home/u/.bashrc", "path": "/w/ok.txt", "content": "x"}, "ask"),
                               ("read", {"path": "/w/.env", "filePath": "/w/ok.txt"}, "flag")):
            for harness in ("opencode", "kilo"):
                with self.subTest(harness=harness, name=name, ti=ti):
                    self.assertEqual(svc.evaluate(e, *agent_hooks.tool(harness, name, ti))[0]["verdict"], want)
        self.assertEqual(agent_hooks.tool("opencode", "shell", {"command": "ls"})[0], "Bash")


class MCPAnswers(unittest.TestCase):
    """An input-required round's answers (mcp 2's input_responses) are decided and recorded as its arguments."""

    def test_the_answers_are_decided_recorded_and_sent(self):
        try:
            from mcp.types import CallToolResult, ElicitResult, TextContent
            from tracekit.integrations.mcp import TracekitSession
        except ImportError:
            self.skipTest("mcp not installed")
        sent, decided = [], []

        class Session:
            server_info = type("Info", (), {"name": "bank"})()

            async def call_tool(self, name, arguments=None, *, input_responses=None):
                sent.append((arguments, input_responses))
                return CallToolResult(content=[TextContent(type="text", text="done")], is_error=False)

        class Signer:
            def __getattr__(self, method):
                def call(req):
                    if method == "decide":
                        decided.append(req)
                    return {"decide": {"decision": "allow", "decision_id": "d1", "rule_ids": []},
                            "approval_consume": {"ok": True, "rule_ids": []}}.get(method, {"run_seq": 0})
                return call

        answers = {"q1": ElicitResult(action="accept", content={"to": "acct-9"})}
        s = TracekitSession(Session(), Signer(), {"run_id": "r", "run_token": "t"})
        out = asyncio.run(s.call_tool("transfer", {"amount": 5}, input_responses=answers))
        self.assertFalse(out.is_error)
        self.assertEqual(decided[0]["args"], {"amount": 5, "input_responses": {"q1": {"action": "accept",
                                                                                   "content": {"to": "acct-9"}}}})
        self.assertEqual(sent, [({"amount": 5}, answers)])
        # a tool argument by that name can't be told from the answers: the call is refused, nothing sent
        out = asyncio.run(s.call_tool("transfer", {"input_responses": 1}, input_responses=answers))
        self.assertTrue(out.is_error)
        self.assertEqual(len(sent), 1)
