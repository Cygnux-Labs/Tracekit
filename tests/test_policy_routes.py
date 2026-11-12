"""Second routes to what the packs hold, each read as a whole class on dev, coding, server and strict and on both
engines: every way the shell writes a file (TK-D014, TK-A067, TK-A068, TK-F024) and a pattern that may name one, a
for loop's brace words, a harness's own settings commands and a harness started with settings the agent chose
(TK-A054, TK-A069, TK-A070), an unmapped file tool read as the file tool it is, a `commands` list read entry by entry,
SQL comments and dollar quotes as PostgreSQL and MySQL lex them, and text typed into a live shell."""
import asyncio
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

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
        cls.engines = {(n, b): Engine(pc.build(os.path.join(PACKS, n + ".yaml"))[0], b)
                       for n in NAMES for b in BACKENDS}

    def expect(self, cases, want, rule=None, packs=NAMES):
        """Each call's verdict on each named pack (`want`: one verdict, a tuple of those allowed, or {pack:
        verdict}) through the signer's own reading (service.evaluate), with `rule` among its rule ids where it isn't
        allowed."""
        for tool, args in cases:
            for (name, backend), e in self.engines.items():
                if name not in packs:
                    continue
                w = want[name] if isinstance(want, dict) else want
                with self.subTest(pack=name, engine=backend, tool=tool, args=str(args)[:90]):
                    d = svc.evaluate(e, tool, args)[0]
                    self.assertIn(d["verdict"], w if isinstance(w, tuple) else (w,), d)
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

    def test_every_in_place_switch_find_and_output_writer_reaches_the_rules(self):
        self.expect(self.bash(
            "sed -I '' 's/a/b/' .env", "sed -bi 's/a/b/' .env", "sed --in 's/a/b/' .env", "gsed -i 's/a/b/' .env",
            "perl -spi -e 's/a/b/' .env", "perl -Wpi -e 's/a/b/' .env", "perl -lpi -e 's/a/b/' .env",
            "perl5.34 -pi -e 's/a/b/' .env", "ruby -spi -e '1' .env", "ruby -W0 -i -pe '1' .env",
            "awk -v f=.env '{print > f}' x", "awk '{print > (\".e\" \"nv\")}' x", "awk '{print > \".e\" \"nv\"}' x",
            "gawk -i inplace '{gsub(/a/,\"b\")}1' .env", "find . -name '.en?' -exec sed -i 's/a/b/' {} +",
            "find . -name .env -exec truncate -s0 {} +", "find . -name .env | xargs sed -i 's/a/b/'",
            "echo .env | xargs sed -i 's/a/b/'", "cd ~/.ssh && sed -i 's/a/b/' authorized_keys",
            "sort -o .env .env", "uniq x .env", "ex -sc '%s/a/b/|x' .env", "vim -es -c '%s/a/b/' -c wq .env",
            "xxd -r x .env", "find . -name .env -fprint .env"), "deny", "TK-D014")
        self.expect(self.bash("find .git/hooks -type f -exec sed -i 's/a/b/' {} +",
                              "find .git -name pre-commit -exec sed -i 's/a/b/' {} +"), "ask", "TK-A068")
        self.expect(self.bash("cd ~/.hermes && sed -i 's/a/b/' config.yaml"), "ask", "TK-F015")
        # a negated or pruned test finds no file: what the find edits is everything else
        self.expect(self.bash("find . -type f ! -name .env -exec sed -i 's/a/b/' {} +",
                              "find . -type f -not -name '*.env' -exec sed -i 's/a/b/' {} +",
                              "find src -name '*.py' -exec sed -i 's/foo/bar/' {} +",
                              "find . -name '*.py' -exec perl -pi -e 's/a/b/' {} +"), ("flag", "allow"))

    def test_a_pattern_is_read_part_by_part_and_with_negated_and_posix_brackets(self):
        held = {"dev": "ask", "coding": "ask", "server": "ask", "strict": "deny"}
        self.expect(self.bash("sed -i 's/a/b/' ~/.ss?/conf?g", "echo x > .e[^x]v", "echo x > .e[!x]v",
                              "echo x > .e[[:alpha:]]v"), held, "TK-D014")
        self.expect(self.bash("echo x > .git/hook[^x]/pre-commit"), "ask", "TK-A068")

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
        self.expect(self.bash("hermes plugins disable tracekit", "hermes -p work plugins remove tracekit",
                              "hermes plugins disable $(echo tracekit)", "echo tracekit | xargs hermes plugins disable",
                              "python -m hermes_cli.main plugins disable tracekit",
                              "hermes-agent plugins disable tracekit"), "ask", "TK-A054")
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

    def test_a_harness_is_read_through_launchers_assignments_and_built_words(self):
        self.expect(self.bash(
            "npx @anthropic-ai/claude-code -p x --settings s.json", "bunx @anthropic-ai/claude-code --bare -p x",
            "pnpm dlx @openai/codex -c hooks=false exec y", "node ~/.npm/node_modules/@anthropic-ai/claude-code/cli.js "
            "--settings s.json -p x", "HERMES_HOME=/tmp/h python -m hermes_cli.main chat -q x",
            "HOME=/tmp/h hermes-agent -q x", "HOME+=/x claude -p x", "read HOME <<< /tmp/h; claude -p x",
            "printf -v HOME %s /tmp/h; claude -p x", "readonly HOME=/tmp/h; claude -p x",
            "claude -p x $(echo --settings) s.json", "echo --settings s.json | xargs claude -p x", "claude --bare -p x",
            "CLAUDE_CODE_SIMPLE=1 claude -p x", "codex exec -c sandbox_workspace_write.network_access=true x",
            "codex --profile other exec x", "env -u CODEX_HOME codex exec x"), "ask", "TK-A070")

    def test_options_and_variables_that_leave_a_harness_its_hooks_are_not_held(self):
        # its model, effort or MCP servers, or another tool's settings, change no hook, plugin, approval or sandbox
        self.expect(self.bash(
            "codex exec -c model_reasoning_effort=high 'fix it'", "claude -p --strict-mcp-config 'hi'",
            "claude -p x --mcp-config mcp.json", "AWS_PROFILE=bedrock claude -p x",
            "KUBECONFIG=~/.kube/dev codex exec x",
            "JAVA_HOME=/opt/jdk claude -p x", "NVM_DIR=~/.nvm claude -p x", "HF_HOME=/data/hf codex exec x",
            "CARGO_TARGET_DIR=/tmp/t codex exec x", "env FOO=1 claude -p x", "claude -p x --plugin-dir ./plugins"),
            "allow")

    def test_hermes_settings_files_are_the_harness_settings(self):
        self.expect([("Write", {"file_path": "/home/u/.hermes/config.yaml", "content": "x"})], "ask", "TK-F009")
        self.expect(self.bash("echo x >> ~/.hermes/config.yaml", "mv ~/.hermes/plugins/tracekit /tmp/",
                              "sed -i 's/a/b/' $HERMES_HOME/config.yaml"), "ask", "TK-F015")

    # --- an unmapped file tool, read as the file tool it is
    def test_an_unmapped_file_tool_is_also_decided_as_the_file_tool_it_is(self):
        patch = "*** Begin Patch\n*** Update File: ~/.ssh/config\n@@\n-a\n+b\n*** End Patch"
        # each header Hermes's V4A parser reads: any blanks around its words, Add, Update, Delete, Move File: a -> b
        for header in ("***Add File: .env", "*** Update  File: ~/.ssh/config", "***\tDelete File: .env",
                       "*** Move File: run.sh -> ~/.ssh/authorized_keys"):
            self.expect([("patch", {"mode": "patch", "patch": f"*** Begin Patch\n{header}\n+x\n*** End Patch"})],
                        "deny", "TK-D005")
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
    def test_a_joined_commands_list_that_reads_stands_beside_its_entries(self):
        # an entry that can't be read on its own (a heredoc across entries) leaves the joined reading as it is
        self.expect([("shell", {"commands": ["cat <<EOF > .env", "X=1", "EOF"]}),
                     ("shell", {"commands": ["cat > .env <<EOF", "X=1", "EOF"]})], "deny", "TK-D010")
        self.expect([("shell", {"commands": ["cat <<EOF > notes.txt", "hello", "EOF"]}),
                     ("shell", {"commands": ["git commit -m 'multi", "line message'"]})], "allow")

    def test_each_entry_of_a_commands_list_is_read_on_its_own(self):
        # the OpenAI Agents SDK's ShellTool runs each entry in its own process, LangChain's joins them with `;`
        self.expect([("shell", {"commands": ["echo ok \\", "sudo id"]}),
                     ("shell", {"commands": ["echo 'x", "sudo id", "'"]}),
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
        # a $ after an identifier's byte past ASCII (€, a no-break space) is part of it, not a dollar quote's start
        for ident in ("€", "x€", "\xa0"):
            stmt = f"SELECT 1 AS {ident}$a$, $q$[$q$, 1 # 2; {D}; SELECT $q$]$q$ -- $a$"
            self.assertIn("DROP", classes.sql_code(stmt, *pg))
        held = {"dev": "deny", "server": "deny", "strict": "deny"}
        self.expect([("mcp:postgres/query", {"sql": f"/* /*/ ' */ */ {D}; -- '"}),
                     ("mcp:supabase/execute_sql", {"query": f"/* /*/ ' */ */ {D}; -- '"}),
                     ("mcp:mysql/execute_sql", {"sql": f"--\x7f\"\n# '\n{D}\n# \"'"})], held, "TK-DB001",
                    packs=("dev", "server", "strict"))


class TypedText(unittest.TestCase):
    """Text typed into a live terminal (Devin's write_to_process, Codex's write_stdin, agy's send_input, Hermes's
    process_manage) that the shell hasn't finished reading is joined to the next call's: `git ` with no newline, or
    `git \\`, then `push --force origin main` ran the push in an interactive bash, and a quote opened in one call
    swallowed the next. Each call is decided as the line the terminal reads it into."""

    def setUp(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        patcher = mock.patch.dict(os.environ, {"TRACEKIT_CLIENT_HOME": home})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.e = svc.load_policy()

    def call(self, harness, text, session="s"):
        """One call as the hooks run it: blocked in the hook (its reason), else the signer's verdict on the line;
        what stays unfinished is kept when it runs (an ask counts as approved)."""
        if harness == "antigravity":
            name, ti = "manage_task", {"Action": "send_input", "Input": text, "TaskId": "t"}
            p, raw = {"tool_name": name}, json.dumps({"hook_event_name": "PreToolUse",
                                                      "toolCall": {"name": name, "args": ti}})
        else:
            name, ti = ("write_to_process", {"shell_id": "main", "input": text}) if harness == "devin" else (
                "write_stdin", {"session_id": 1, "chars": text})
            p = {"session_id": session, "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": ti}
            raw = json.dumps(p)
        tool, args = agent_hooks.tool(harness, name, dict(ti))
        q = {"session_id": session, "tool_name": tool, "tool_input": args}
        typed = agent_hooks.typed_line(harness, p, q)
        q["tool_input"]["command"] = typed[1]
        why = agent_hooks._blocked(harness, p, raw, typed[1])
        if why:
            return why
        verdict = svc.evaluate(self.e, tool, q["tool_input"])[0]["verdict"]
        if verdict != "deny":
            agent_hooks.keep_typed(*typed)
        return verdict

    def test_a_line_typed_in_parts_is_decided_whole(self):
        for harness in ("codex", "devin", "antigravity"):
            for parts in (["git ", "push --fo" + "rce origin main\n"], ["git \\\n", "push --fo" + "rce origin main\n"],
                          ["echo '\n", "' ; sudo id ; echo '\n"], ["echo $(\n", "sudo id)\n"]):
                with self.subTest(harness=harness, parts=parts):
                    first = self.call(harness, parts[0], session=f"{harness}{parts}")
                    self.assertIn(first, ("allow", "ask"))
                    self.assertEqual(self.call(harness, parts[1], session=f"{harness}{parts}"), "deny")
        # a line that ended is read alone again, and a ^C drops what was typed before it
        self.assertEqual(self.call("codex", "ls\n", "t"), "allow")
        self.assertEqual(self.call("codex", "sudo", "u"), "deny")
        self.assertEqual(agent_hooks.unfinished("sudo \x03ls"), "ls")

    def test_keys_typed_without_a_newline_wait_for_their_line(self):
        for harness in ("codex", "antigravity", "devin"):
            for key in ("q", "y", "git pu"):
                with self.subTest(harness=harness, key=key):
                    self.assertEqual(self.call(harness, key, session=f"{harness}{key}"), "allow")
        for harness in ("codex", "antigravity"):
            for key in ("\x1b", "\t", "\x1b[A", "\x03", "\x04"):
                with self.subTest(harness=harness, key=key):
                    self.assertEqual(self.call(harness, key, session=f"{harness}{key!r}"), "allow")
        # the line a key ends up in is read whole: an arrow, a tab or a line kill in it is blocked
        for harness in ("codex", "antigravity"):
            self.assertEqual(self.call(harness, "\x1b[A", session=f"k{harness}"), "allow")
            self.assertIn("control character", self.call(harness, "\n", session=f"k{harness}"))
            self.assertIn("control character", self.call(harness, f"echo ok\x15{PUSH}\n", session=f"j{harness}"))
        # Devin's keys are read as they are typed, as before: a control character, ^C and ^D too
        for key in ("\x1b", "\t", "\x03", "\x04"):
            self.assertIn("control character", self.call("devin", key, session=f"d{key!r}"))

    def test_a_live_shell_whose_home_or_harness_settings_change_is_blocked(self):
        for harness in ("codex", "devin"):
            for line in ("export HOME=/tmp/h\n", "CLAUDE_CONFIG_DIR=/tmp/c\n", "read HOME <<< /tmp/h\n"):
                with self.subTest(harness=harness, line=line):
                    self.assertIn("sets or replays state", self.call(harness, line, session=f"{harness}{line}"))

    def test_hermes_text_typed_into_a_process_is_read_as_its_line(self):
        reason, line = hermes._typed("process_manage", {"action": "write", "data": "push --fo" + "rce origin main\n"},
                                     "git ")
        self.assertIsNone(reason)
        d = svc.evaluate(self.e, "process_manage", {"action": "write", "data": "push", "typed_line": line})[0]
        self.assertEqual(d["verdict"], "deny")
        self.assertEqual(hermes._typed("process_manage", {"action": "write", "data": "q"})[0], None)
        self.assertIn("control character", hermes._typed("process_manage", {"action": "submit", "data": "\x1b[A"})[0])

    def test_the_hook_decides_the_joined_line(self):
        from tracekit.integrations import claude_code, harness_hooks
        seen = []
        decide = mock.Mock(side_effect=lambda q: seen.append(q["tool_input"]["command"]) or 0)
        # (run sets the hook module's agent name, as each hook process does: put back for the tests after this one)
        with mock.patch.object(claude_code, "handle", decide), \
                mock.patch.object(claude_code, "AGENT", claude_code.AGENT):
            for chars in ("git ", "push origin main\n"):
                p = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "write_stdin",
                     "tool_use_id": "c" + chars[:1], "tool_input": {"session_id": 1, "chars": chars}}
                harness_hooks.run("codex", json.dumps(p), stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(seen, ["git ", "git push origin main\n"])


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
