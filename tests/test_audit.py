"""Tests for `tracekit audit` (issue #490)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tracekit import __version__, agent_hooks, audit, cli
from tracekit.signer.service import DEFAULT_POLICY, evaluate, load_policy


def _call(tool, args, days_ago=0):
    """An assistant line with one tool use, as Claude Code writes it."""
    at = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"type": "assistant", "timestamp": at.isoformat().replace("+00:00", "Z"),
            "message": {"content": [{"type": "tool_use", "name": tool, "input": args}]}}


def _line(tool, args, days_ago=0, **extra):
    """A line of a calls file (#714)."""
    at = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"time": at.isoformat().replace("+00:00", "Z"), "tool": tool, "args": args, **extra}


def _gemini_msg(mid, calls, days_ago=0):
    """A Gemini CLI message line with tool calls (#715): calls are (id, name, args)."""
    at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    return {"id": mid, "timestamp": at, "type": "gemini", "content": "", "toolCalls": [
        {"id": cid, "name": name, "args": args, "status": "success", "timestamp": at} for cid, name, args in calls]}


def _write_jsonl(path: Path, lines: list[dict | str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["audit", *argv])
    return code, out.getvalue(), err.getvalue()


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_held_denied_allowed_and_malformed(self):
        _write_jsonl(self.root / "proj" / "session-abc.jsonl", [
            _call("Bash", {"command": "rm -rf /"}), _call("Bash", {"command": "terraform destroy -auto-approve"}),
            _call("Bash", {"command": "ls -la"}), "this is not json", {"type": "user", "message": {"content": "hi"}}])
        report = audit.audit(str(self.root))
        self.assertEqual(report["counts"], {"deny": 1, "ask": 1, "flag": 0, "allow": 1})
        self.assertIn("TK-D004", report["by_rule"])
        self.assertIn("TK-A001", report["by_rule"])
        self.assertEqual(report["skipped_malformed"], 1)
        self.assertEqual({c["session"] for c in report["calls"]}, {"session-abc"})
        self.assertTrue(all(c["time"] for c in report["calls"]))
        self.assertNotIn("text", report["calls"][0])   # the command text only with --show
        self.assertIn("not a signed record", report["disclaimer"])

    def test_held_calls_a_day_and_where_the_answers_are(self):
        _write_jsonl(self.root / "proj" / "s.jsonl", [
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=2),
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=1),
            _call("Bash", {"command": "ls -la"})])
        report = audit.audit(str(self.root), since="4d")
        self.assertEqual(report["holds_a_day"], 1)   # two holds in the two days from the first call, not in the four asked
        _, out, _ = _run(str(self.root), "--since", "4d")
        self.assertIn("  held calls: 1 a day. Who answered them, and how fast, is in the signed approval records: "
                      "tracekit report\n", out)
        _write_jsonl(self.root / "proj" / "s.jsonl", [_call("Bash", {"command": "ls -la"})])
        self.assertNotIn("held calls:", _run(str(self.root))[1])   # none held

    def test_the_span_starts_at_the_first_call_in_the_window(self):
        _write_jsonl(self.root / "proj" / "s.jsonl", [
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=0.1),
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=0.1)])
        self.assertLess(audit.audit(str(self.root), since="30d")["span_s"], 86400)   # not 30 days

    def test_under_a_day_the_count_is_over_the_window_not_a_daily_rate(self):
        _write_jsonl(self.root / "proj" / "s.jsonl", [
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=0.1),
            _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=0.1)])
        report = audit.audit(str(self.root), since="3h")
        self.assertIsNone(report["holds_a_day"])
        _, out, _ = _run(str(self.root), "--since", "3h")
        self.assertRegex(out, r"  held calls: 2 in 2h 2\dm\. Who answered")

    def test_a_subagents_calls_count_under_its_session(self):
        _write_jsonl(self.root / "proj" / "s1.jsonl", [_call("Bash", {"command": "ls"})])
        _write_jsonl(self.root / "proj" / "s1" / "subagents" / "agent-a.jsonl", [_call("Bash", {"command": "ls"})])
        report = audit.audit(str(self.root))
        self.assertEqual((report["sessions"], {c["session"] for c in report["calls"]}), (1, {"s1"}))

    def test_a_workflow_agents_calls_count_under_its_session(self):
        """1.5.3 review: a workflow's agents (<session>/subagents/workflows/<wf>/agent-*.jsonl) were each counted as a
        session of their own, 223 of 641 on a real folder."""
        _write_jsonl(self.root / "proj" / "s1.jsonl", [_call("Bash", {"command": "ls"})])
        _write_jsonl(self.root / "proj" / "s1" / "subagents" / "workflows" / "wf_1" / "agent-b.jsonl",
                     [_call("Bash", {"command": "ls"})])
        report = audit.audit(str(self.root))
        self.assertEqual((report["sessions"], {c["session"] for c in report["calls"]}), (1, {"s1"}))

    def test_a_call_copied_into_another_file_counts_once(self):
        """1.5.3 review: a resumed or forked session's file repeats the tool uses it copied, and a subagent's file some
        of its sidechain's: 2,529 of 158,283 calls on a real folder were counted twice, a deny read as two."""
        deny = _call("Bash", {"command": "rm -rf /"})
        deny["message"]["content"][0]["id"] = "toolu_1"
        odd = _call("Bash", {"command": "rm -rf /"})
        odd["message"]["content"][0]["id"] = {"not": "a string"}   # counted, as a call with no id is
        _write_jsonl(self.root / "proj" / "s1.jsonl", [deny, odd])
        _write_jsonl(self.root / "proj" / "s2.jsonl", [deny])
        self.assertEqual(audit.audit(str(self.root))["counts"]["deny"], 2)
        other = _call("Bash", {"command": "rm -rf ~"})   # another call under a reused id (a proxy's, a backend's)
        other["message"]["content"][0]["id"] = "toolu_1"
        _write_jsonl(self.root / "proj" / "s3.jsonl", [other])
        self.assertEqual(audit.audit(str(self.root))["counts"]["deny"], 3)

    def test_a_root_inside_a_folder_named_subagents_keeps_its_sessions_apart(self):
        """Review of #541: the session came from the whole path, so a folder named subagents above the root put every
        transcript in one session."""
        root = self.root / "subagents" / "projects"
        for s in ("s1", "s2"):
            _write_jsonl(root / "proj" / f"{s}.jsonl", [_call("Bash", {"command": "ls"})])
        report = audit.audit(str(root))
        self.assertEqual((report["sessions"], {c["session"] for c in report["calls"]}), (2, {"s1", "s2"}))

    def test_a_since_out_of_range_or_not_in_the_past_exits_2(self):
        """1.5.3 review: a --since of 400 digits of days ended in an OverflowError traceback."""
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "ls"})])
        for since, said in (("9" * 400 + "d", "is out of range"), ("3000000d", "is out of range"),
                            ("2999-01-01", "is not in the past"), ("0d", "is not in the past")):
            with self.subTest(since=since[:12]):
                code, _, err = _run(str(self.root), "--since", since)
                self.assertEqual(code, 2, err)
                self.assertIn(said, err)

    def test_a_call_the_engine_fails_on_is_a_deny_as_the_signer_decides_it(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "ls"})])
        with mock.patch("tracekit.policy2.engine.Engine.decide", side_effect=RuntimeError("boom")):
            report = audit.audit(str(self.root))
        self.assertEqual(report["counts"]["deny"], 1)
        self.assertEqual(report["by_rule"], {"TK-ENGINE-ERROR": 1})
        self.assertEqual(report["skipped_malformed"], 0)

    def test_each_call_is_decided_as_the_signer_decides_it(self):
        """The 1.6.0 review: audit decided a call on its name alone, so mcp__<server>__<tool> missed the rules on
        mcp:<server>/<tool> and on the tool's bare name, and Claude Code's PowerShell tool missed the shell rules."""
        _write_jsonl(self.root / "s.jsonl", [_call("mcp__acme__tracekit_demo_ask", {"x": 1}),
                                             _call("PowerShell", {"command": "rm -rf /"})])
        report = audit.audit(str(self.root))
        self.assertEqual([c["verdict"] for c in report["calls"]], ["ask", "deny"])
        self.assertEqual(report["counts"], {"deny": 1, "ask": 1, "flag": 0, "allow": 0})

    def test_a_line_nested_past_what_json_takes_is_malformed_and_the_rest_is_read(self):
        """Review of 1.5.3: its RecursionError made the whole file unreadable, its calls uncounted."""
        _write_jsonl(self.root / "s.jsonl", ["[" * 5000 + "]" * 5000, _call("Bash", {"command": "ls"})])
        report = audit.audit(str(self.root))
        self.assertEqual((report["counts"]["allow"], report["skipped_malformed"], report["unreadable"]), (1, 1, []))

    def test_an_unreadable_file_is_counted_and_skipped(self):
        bad = self.root / "proj" / "bad.jsonl"
        _write_jsonl(bad, [_call("Bash", {"command": "rm -rf /"})])
        bad.chmod(0)
        if os.access(bad, os.R_OK):   # root, or a file system that ignores the mode (Windows)
            self.skipTest("the file stays readable here")
        report = audit.audit(str(self.root))
        self.assertEqual(len(report["unreadable"]), 1)
        self.assertEqual(report["calls"], [])

    def test_no_symlink_is_followed_but_a_root_reached_through_one_is_read(self):
        with tempfile.TemporaryDirectory() as outside:
            real = Path(outside) / "other.jsonl"
            _write_jsonl(real, [_call("Bash", {"command": "rm -rf /"})])
            try:
                (self.root / "link.jsonl").symlink_to(real)
                (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
            except OSError:   # Windows without the privilege
                self.skipTest("no symlinks here")
            self.assertEqual(audit.audit(str(self.root))["calls"], [])
            self.assertEqual(audit.audit(str(self.root / "linkdir"))["counts"]["deny"], 1)   # a root that is a symlink

    def test_since_keeps_only_newer_calls(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "echo old"}, days_ago=30),
                                             _call("Bash", {"command": "echo new"}, days_ago=1)])
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        for since in ("10d", "240h", ten_days_ago.astimezone(timezone(timedelta(hours=5))).isoformat(),
                      ten_days_ago.replace(tzinfo=None).isoformat()):   # an offset, and none (UTC)
            report = audit.audit(str(self.root), since=since, show=True)
            self.assertEqual([c["text"] for c in report["calls"]], ["Bash echo new"], since)
        self.assertEqual(audit.audit(str(self.root), since="30m")["calls"], [])
        with self.assertRaises(ValueError):
            audit.audit(str(self.root), since="last week")

    def test_a_last_line_without_a_newline_is_read(self):
        """A finished transcript's last line may lack its newline: audit dropped it, 0 calls and 0 malformed."""
        path = self.root / "s.jsonl"
        path.write_text(json.dumps(_call("Bash", {"command": "rm -rf /"})), encoding="utf-8")
        self.assertEqual(audit.audit(str(self.root))["counts"]["deny"], 1)
        path.write_text(json.dumps(_call("Bash", {"command": "ls"})) + '\n{"type": "assis', encoding="utf-8")
        report = audit.audit(str(self.root))   # a line still being written is counted, not dropped
        self.assertEqual((report["counts"]["allow"], report["skipped_malformed"]), (1, 1))

    def test_show_redacts_secrets_as_the_signer_does(self):
        key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0" * 2
        _write_jsonl(self.root / "s.jsonl", [
            _call("Bash", {"command": f"export ANTHROPIC_API_KEY={key}"}),
            _call("Bash", {"command": "cat > .env <<'EOF'\nSTRIPE_WEBHOOK=whsec_abc123\nEOF"})])
        key_text, env_text = (c["text"] for c in audit.audit(str(self.root), show=True)["calls"])
        self.assertNotIn(key, key_text)
        self.assertIn("export ANTHROPIC_API_KEY=", key_text)
        self.assertNotIn("whsec_abc123", env_text)   # a .env write: every value, as the signer redacts it
        self.assertIn("STRIPE_WEBHOOK=", env_text)

    def test_the_command_prints_the_report_and_json_matches_it(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "rm -rf /"}), _call("Bash", {"command": "ls"})])
        report = audit.audit(str(self.root))
        code, out, err = _run(str(self.root), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["counts"], report["counts"])
        self.assertIn("tracekit audit is experimental", err)
        text = audit.format_report(report)
        self.assertTrue(text.startswith("a replay against today's policy, not a signed record\n"))
        self.assertIn("2 tool calls in 1 session: Tracekit would have denied 1 and held 0 for a person; it would have "
                      "flagged 0 and allowed 1.\n", text)
        self.assertIn("  TK-D004: 1  (recursive delete of root or home)\n", text)   # what each rule is
        self.assertIn("  deny: 1\n", text)
        self.assertIn("Bash  deny", text)
        self.assertNotIn("Bash  allow", text)   # the calls it would have stopped; --all lists every call
        self.assertIn("Bash  allow", audit.format_report(report, every=True))
        self.assertIn("Bash  allow", _run(str(self.root), "--all")[1])
        self.assertEqual(_run(str(self.root), "--since", "soon")[0], 2)
        code, _, err = _run(str(self.root / "missing"))
        self.assertEqual(code, 2)
        self.assertIn("no such folder", err)

    @mock.patch("shutil.which", lambda _: "/usr/local/bin/tracekit")   # installed: init is on PATH
    def test_the_text_ends_with_the_weeks_summary(self):
        """The report's last lines say the week in one read: calls, held and blocked, the rules that stopped them most
        (a flag is no stop) and how to guard from now on."""
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "rm -rf /"}),
                                             _call("Bash", {"command": "terraform destroy -auto-approve"}),
                                             _call("Bash", {"command": "terraform destroy -auto-approve"}, days_ago=1),
                                             _call("Bash", {"command": "ls"})])
        _, out, _ = _run(str(self.root), "--since", "7d")
        self.assertTrue(out.endswith(
            "\n\nyour agent's week: 4 tool calls; Tracekit would have held 2 and blocked 1\n"
            "  top: TK-A001 destroying a deployment, database or volume (2), TK-D004 recursive delete of root or home (1)\n"
            "  to guard from now on: tracekit init --dev --v2\n"), out)
        self.assertIn("\nyour agent's 2 days: 4 tool calls;", _run(str(self.root), "--since", "2d")[1])
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "ls"})])
        self.assertTrue(_run(str(self.root))[1].endswith(
            "\nyour agent's transcripts: 1 tool call; Tracekit would have held 0 and blocked 0\n"
            "  to guard from now on: tracekit init --dev --v2\n"))
        self.assertNotIn("your agent's", _run(str(self.root), "--json")[1] + _run(str(self.root), "--share")[1])

    def test_without_tracekit_on_path_the_guard_line_says_to_install_it(self):
        """`uvx --from tracekit-ai tracekit audit` runs with no tracekit on PATH: init alone would not be found."""
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "ls"})])
        with mock.patch("shutil.which", return_value=None):
            out = _run(str(self.root))[1]
        self.assertTrue(out.endswith("\n  to guard from now on: pip install tracekit-ai, then tracekit init --dev --v2\n"))

    def test_the_default_folder_is_in_claude_config_dir_when_it_is_set(self):
        _write_jsonl(self.root / "config" / "projects" / "p" / "s.jsonl", [_call("Bash", {"command": "rm -rf /"})])
        home = self.root / "home"   # no .claude: a fallback to ~/.claude/projects finds nothing
        home.mkdir()
        with mock.patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)}):
            self.assertEqual(_run("--json")[0], 2)
            os.environ["CLAUDE_CONFIG_DIR"] = str(self.root / "config")
            code, out, _ = _run("--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["counts"]["deny"], 1)

    def test_share_is_counts_only(self):
        """#521: --share, a field report a person posts where anyone reads it, holds the counts and the window's length,
        never a session, path, time, call or what was said, though the transcripts and the report hold them. A rule that
        only also matched its call is marked so, and an engine check as not placed: a flag rule read as why a call was
        denied. A rule id a policy's author chose is counted as "custom rule": it was printed as it was."""
        mark = "LEAKMARK"
        said = _call("Bash", {"command": f"rm -rf ~/{mark}-home"})
        said["message"]["content"].insert(0, {"type": "text", "text": f"{mark}-said: I'll clear it"})
        sub = _call("Read", {"file_path": f"/home/{mark}-user/notes.txt"})
        _write_jsonl(self.root / f"{mark}-project" / f"{mark}-session.jsonl", [
            {"type": "user", "message": {"content": f"{mark}-prompt: tidy /srv/{mark}-repo"}}, said,
            _call("Bash", {"command": "rm -rf /"}),
            _call("Bash", {"command": f"terraform destroy -auto-approve -var host={mark}-host"}),
            _call("Bash", {"command": f"echo '{mark}-unterminated"}),
            _call("Bash", {"command": "ls"}, days_ago=30)])
        _write_jsonl(self.root / f"{mark}-project" / f"{mark}-session" / "subagents" / f"agent-{mark}.jsonl",
                     [{**sub, "agentId": f"{mark}-agent", "slug": f"{mark}-agent-name"}])
        report = audit.audit(str(self.root), since="7d", show=True)
        self.assertIn(mark, json.dumps(report))
        page = audit.share(report)
        self.assertEqual(page.splitlines(), [
            f"Tracekit {__version__} field report (tracekit audit --share): 7 days",
            "a replay against today's policy, not a signed record: 1 Claude Code session",
            "Tool calls: 5   allow 1, flag 1, ask 2, deny 1",
            "Calls by decision and rule (one call can match several rules):",
            "  deny TK-D004 1", "  deny TK-F003 1 (also matched, not why)", "  ask TK-A001 1",
            "  ask TK-SHELL-PARSE 1 (not placed)", "  flag TK-F003 1"])
        self.assertEqual(audit.share(audit.audit(str(self.root))).splitlines()[0],
                         f"Tracekit {__version__} field report (tracekit audit --share): every transcript")
        code, out, _ = _run(str(self.root), "--since", "7d", "--share")
        self.assertEqual((code, out), (0, page))
        policy = self.root / "policy.yaml"   # outside the transcripts: a .yaml file the audit doesn't read
        policy.write_text(f"description: our own\ndeny:\n  - {{id: {mark}-rule.acme-prod-db.internal, tool: Bash, "
                          f"pattern: {mark}-host, reason: a host of ours}}\n", encoding="utf-8")
        custom = audit.share(audit.audit(str(self.root), str(policy), since="7d"))
        self.assertIn("\n  deny custom rule 1\n", custom)
        for text in (page, custom):
            self.assertNotIn(mark, text)
            self.assertNotIn(self.tmp.name, text)
            self.assertNotRegex(text, r"\d{4}-\d\d-\d\d|\d\d:\d\d")   # no date or time

    def test_a_time_utc_cannot_hold_is_a_call_without_a_time(self):
        line = _call("Bash", {"command": "ls"})
        _write_jsonl(self.root / "s.jsonl", [{**line, "timestamp": "0001-01-01T00:00:00+05:00"}])
        self.assertEqual([c["time"] for c in audit.audit(str(self.root))["calls"]], [None])

    def test_control_characters_from_a_transcript_are_printed_as_text(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash\x1b[2K", {"command": "ls"})])
        text = audit.format_report(audit.audit(str(self.root)), every=True)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b", text)

    def test_a_calls_file_is_decided_as_transcripts_are(self):
        """#714: a calls file any agent's log can be turned into: a line without tool and args is malformed, --since
        cuts by its time, and a line without a session counts under the file's name."""
        path = self.root / "calls.jsonl"
        _write_jsonl(path, [_line("Bash", {"command": "rm -rf /"}, session="s1"),
                            _line("Bash", {"command": "terraform destroy -auto-approve"}),
                            _line("Bash", {"command": "rm -rf /"}, days_ago=10),
                            {"args": {"command": "ls"}}, {"tool": "Bash", "args": "ls"}, "not json"])
        report = audit.audit(calls=str(path), since="7d")
        self.assertEqual(report["counts"], {"deny": 1, "ask": 1, "flag": 0, "allow": 0})
        self.assertEqual(report["skipped_malformed"], 3)
        self.assertEqual([(c["agent"], c["session"]) for c in report["calls"]],
                         [("other", "s1"), ("other", "calls.jsonl")])
        code, out, _ = _run("--calls", str(path), "--since", "7d", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["counts"], report["counts"])
        self.assertEqual(_run("--calls", str(self.root / "missing.jsonl"))[0], 2)

    def test_a_calls_file_is_read_from_stdin(self):
        data = (json.dumps(_line("Bash", {"command": "rm -rf /"})) + "\n").encode()
        with mock.patch("sys.stdin", io.TextIOWrapper(io.BytesIO(data))):
            code, out, _ = _run("--calls", "-", "--json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["counts"]["deny"], 1)
        self.assertEqual(report["calls"][0]["session"], "stdin")

    def test_agent_maps_a_calls_files_names_as_its_hook_does(self):
        args = {"command": "rm -rf /"}
        _write_jsonl(self.root / "calls.jsonl", [_line("run_shell_command", args)])
        tool, mapped = agent_hooks.tool("gemini", "run_shell_command", args)
        expected = evaluate(load_policy(DEFAULT_POLICY), tool, mapped)[0]
        call = audit.audit(calls=str(self.root / "calls.jsonl"), agent="gemini")["calls"][0]
        self.assertEqual((call["agent"], call["tool"], call["verdict"], call["rule_ids"]),
                         ("gemini", "Bash", expected["verdict"], expected["rule_ids"]))
        self.assertEqual(call["verdict"], "deny")
        code, _, err = _run(str(self.root), "--agent", "opencode")   # no reader of OpenCode's own sessions yet
        self.assertEqual(code, 2)
        self.assertIn("--calls FILE --agent opencode", err)

    def test_with_no_root_every_known_agents_folder_that_exists_is_read(self):
        home = self.root / "home"
        folder = home / ".claude" / "projects"
        _write_jsonl(folder / "p" / "s.jsonl", [_call("Bash", {"command": "rm -rf /"}),
                                                _call("Bash", {"command": "ls"})])
        absent = ("nothere", (lambda: str(home / ".nothere"), "~/.nothere", audit._claude_code))
        with mock.patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)}), \
                mock.patch.dict(audit.READERS, dict([absent])):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            os.environ.pop("GEMINI_CLI_HOME", None)
            code, out, _ = _run("--json")
            text = _run()[1]
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["agents"], {"claude": {"folder": str(folder), "calls": 2, "sessions": 1}})
        self.assertEqual({c["agent"] for c in report["calls"]}, {"claude"})
        self.assertIn(f"\nread: claude ({folder}): 2 calls in 1 session\n", text)

    def test_agent_claude_is_init_s_name_and_claude_code_still_works(self):
        """The 1.7.0 review: audit --agent took claude-code where init, uninstall and the plugin skill take claude."""
        _write_jsonl(self.root / "p" / "s.jsonl", [_call("Bash", {"command": "ls"})])
        for name in ("claude", "claude-code"):
            with self.subTest(name=name):
                code, out, err = _run(str(self.root), "--agent", name, "--json")
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out)["agents"], {"claude": {"folder": str(self.root), "calls": 1,
                                                                        "sessions": 1}})
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["audit", "--help"])
        self.assertRegex(out.getvalue(), r"--agent \{[a-z,]*\bclaude\b")   # one name in the help: init's
        self.assertNotIn("claude-code", out.getvalue())
        # audit() itself takes the old name too (the PR #754 review): it read no ROOT, and a calls file's agent kept it
        self.assertEqual(audit.audit(str(self.root), agent="claude-code")["agents"],
                         {"claude": {"folder": str(self.root), "calls": 1, "sessions": 1}})
        _write_jsonl(self.root / "calls.jsonl", [_line("Bash", {"command": "ls"})])
        report = audit.audit(calls=str(self.root / "calls.jsonl"), agent="claude-code")
        self.assertEqual((list(report["agents"]), [c["agent"] for c in report["calls"]]), (["claude"], ["claude"]))

    def test_a_shell_command_no_agent_sends_is_held_as_the_signer_holds_it(self):
        """The 1.7.0 review: --agent codex crashed (TypeError) on an argv with an item that isn't a string; then such a
        line was skipped as malformed with --agent and held without it. The signer holds a shell command its parser
        can't read (TK-SHELL-PARSE), whichever agent sent it: so does audit, with any --agent or none."""
        bad = [["ls", 1], ["ls", None], ["ls", ["-la"]], [["ls"]], ["ls", 10 ** 30], ["bash", "-lc", 1], 1, {}]
        for agent, tool in ((None, "Bash"), ("claude", "Bash"), ("codex", "shell"), ("codex", "Bash"),
                            ("gemini", "run_shell_command"), ("opencode", "bash"), ("goose", "shell")):
            with self.subTest(agent=agent, tool=tool):
                _write_jsonl(self.root / "calls.jsonl", [_line(tool, {"command": c}) for c in bad]
                             + [_line(tool, {"command": "ls -la"})])
                code, out, err = _run("--calls", str(self.root / "calls.jsonl"), "--json", "--show",
                                      *(["--agent", agent] if agent else []))
                self.assertEqual(code, 0, err)
                report = json.loads(out)
                self.assertEqual(report["skipped_malformed"], 0)
                self.assertEqual([(c["tool"], c["verdict"], "TK-SHELL-PARSE" in c["rule_ids"])
                                  for c in report["calls"]],
                                 [("Bash", "ask", True)] * len(bad) + [("Bash", "allow", False)])
        _write_jsonl(self.root / "calls.jsonl", [_line("shell", {"command": ["bash", "-lc", "ls -la"]})])   # Codex's
        report = audit.audit(calls=str(self.root / "calls.jsonl"), agent="codex")
        self.assertEqual([(c["tool"], c["verdict"]) for c in report["calls"]], [("Bash", "allow")])

    def test_a_call_cline_s_hook_cant_read_is_blocked_as_the_hook_blocks_it(self):
        """The 1.7.0 review: one Cline call the mapping can't read (a run_commands argv with a number in it, an editor
        with no path) stopped the whole --agent cline replay (exit 2). Its live hook blocks such a call: audit denies
        it (TK-HOOK-BLOCKED) and replays the rest."""
        _write_jsonl(self.root / "calls.jsonl", [_line("run_commands", {"command": "ls"}),
                                                 _line("run_commands", {"command": ["ls", 1]}),
                                                 _line("editor", {"command": "view"}),
                                                 _line("run_commands", {"command": "git status"})])
        code, out, err = _run("--calls", str(self.root / "calls.jsonl"), "--agent", "cline", "--json")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertEqual(report["skipped_malformed"], 0)
        self.assertEqual([(c["verdict"], c["rule_ids"]) for c in report["calls"]],
                         [("allow", []), ("deny", ["TK-HOOK-BLOCKED"]), ("deny", ["TK-HOOK-BLOCKED"]),
                          ("allow", [])])

    def test_kilo_generate_image_without_a_path_is_decided(self):
        """The 1.7.0 review's fuzzing: --agent kilo crashed (KeyError) on a generate_image with an image and no path;
        it is decided as the Read of the image."""
        _write_jsonl(self.root / "calls.jsonl", [_line("generate_image", {"prompt": "x", "image": "in.png"})])
        code, out, err = _run("--calls", str(self.root / "calls.jsonl"), "--agent", "kilo", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual([c["tool"] for c in json.loads(out)["calls"]], ["Read"])

    def test_a_line_nested_past_what_the_mapping_takes_is_malformed(self):
        """#730 review: --agent droid or devin crashed on a line json.loads takes but agent_hooks._strings can't."""
        deep = '{"tool": "ApplyPatch", "args": {"x": ' + "[" * 1000 + '"s"' + "]" * 1000 + "}}"
        for agent, tool in (("droid", "ApplyPatch"), ("devin", "apply_patch")):
            with self.subTest(agent=agent):
                _write_jsonl(self.root / "calls.jsonl", [deep.replace("ApplyPatch", tool),
                                                         _line("Bash", {"command": "ls"})])
                code, out, err = _run("--calls", str(self.root / "calls.jsonl"), "--agent", agent, "--json")
                self.assertEqual(code, 0, err)
                report = json.loads(out)
                self.assertEqual((report["skipped_malformed"], sum(report["counts"].values())), (1, 1))

    def test_a_time_that_isnt_iso_8601_is_malformed(self):
        _write_jsonl(self.root / "calls.jsonl", [{"time": 1762783331, "tool": "Bash", "args": {"command": "ls"}},
                                                 {"time": None, "tool": "Bash", "args": {"command": "ls"}}])
        report = audit.audit(calls=str(self.root / "calls.jsonl"), since="7d")
        self.assertEqual((report["skipped_malformed"], report["counts"]["allow"]), (1, 1))   # no time: kept

    def test_agent_denies_what_its_hook_denies_before_mapping(self):
        """#730 review: Kilo's notebook_execute, Crush's sub-agents and a Devin call missing its argument are denied in
        the hook before mapping."""
        _write_jsonl(self.root / "calls.jsonl", [_line("notebook_execute", {"cell": "print(1)"})])
        report = audit.audit(calls=str(self.root / "calls.jsonl"), agent="kilo")
        self.assertEqual((report["calls"][0]["verdict"], report["calls"][0]["rule_ids"]),
                         ("deny", ["TK-HOOK-BLOCKED"]))
        self.assertEqual(report["by_rule"], {"TK-HOOK-BLOCKED": 1})   # the per-rule counts agree with the total
        self.assertIn("TK-HOOK-BLOCKED: 1  (the agent's Tracekit hook denies", audit.format_report(report))
        # Tracekit's own id, not a custom rule; like an engine check, it has no section of the policy
        self.assertIn("  deny TK-HOOK-BLOCKED 1 (not placed)", audit.share(report).splitlines())
        _write_jsonl(self.root / "calls.jsonl", [_line("agent", {"prompt": "tidy up"})])
        self.assertEqual(audit.audit(calls=str(self.root / "calls.jsonl"), agent="crush")["counts"]["deny"], 1)
        _write_jsonl(self.root / "calls.jsonl", [_line("read", {"path_name": "notes.txt"})])   # no file_path
        self.assertEqual(audit.audit(calls=str(self.root / "calls.jsonl"), agent="devin")["counts"]["deny"], 1)

    def test_what_a_calls_file_option_cant_read_exits_2_with_the_reason(self):
        code, _, err = _run("--calls", str(self.root / "missing.jsonl"))
        self.assertEqual(code, 2)
        self.assertIn("missing.jsonl", err)
        # what isn't a regular file: what it is, and to send a pipe to --calls - only for a pipe (the 1.7.0 review)
        code, _, err = _run("--calls", str(self.root))
        self.assertEqual((code, err.splitlines()[-1]),
                         (2, f"tracekit audit: cannot read the calls file: {self.root} is a directory"))
        cases = []
        if os.path.exists("/dev/null"):
            cases.append(("/dev/null", "/dev/null is not a regular file"))
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo")
            cases.append((str(self.root / "fifo"), "fifo is a pipe (as <(...) gives); send it to --calls -"))
        try:
            (self.root / "link.jsonl").symlink_to(self.root / "missing.jsonl")
            cases.append((str(self.root / "link.jsonl"), "link.jsonl is a symlink, which audit doesn't follow"))
            (self.root / "dir-link").symlink_to(self.root, target_is_directory=True)   # not "a directory" (PR #754)
            cases.append((str(self.root / "dir-link"), "dir-link is a symlink, which audit doesn't follow"))
        except OSError:   # Windows without the privilege
            pass
        for path, said in cases:
            with self.subTest(path=path):
                code, _, err = _run("--calls", path)
                self.assertEqual(code, 2)
                self.assertTrue(err.rstrip().endswith(said), err)
                self.assertEqual("--calls -" in err, "pipe" in said)
        with mock.patch("sys.stdin", None):   # started with stdin closed (<&-)
            code, _, err = _run("--calls", "-")
        self.assertEqual(code, 2)
        self.assertIn("no standard input", err)

    def test_agent_without_root_or_calls_exits_2(self):
        # an agent with no reader: only --calls FILE, which works (a ROOT is refused); claude: a ROOT or --calls FILE
        for argv in (["--agent", "codex"], [str(self.root), "--agent", "codex"]):
            with self.subTest(argv=argv):
                code, _, err = _run(*argv)
                self.assertEqual((code, err.splitlines()[-1]), (2, "tracekit audit: no reader for codex's sessions "
                                                                   "yet; turn them into a calls file and use --calls "
                                                                   "FILE --agent codex"))
        code, _, err = _run("--agent", "claude")
        self.assertEqual(code, 2)
        self.assertIn("--agent claude needs a ROOT or --calls FILE", err)
        with self.assertRaisesRegex(ValueError, "no reader for gemini's"):   # audit() itself, a ROOT given or not
            audit.audit(str(self.root), agent="gemini")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            cli.main(["audit", "--calls", "-", "--agent", "no-such-agent"])
        self.assertEqual(e.exception.code, 2)

    def _gemini_sessions(self) -> Path:
        """A Gemini CLI tmp folder (#715): a session written as JSON lines, its subagent's file, a session from before
        v0.39 (one JSON object), and a project file that isn't a session."""
        chats = self.root / ".gemini" / "tmp" / "proj" / "chats"
        rm = ("c1", "run_shell_command", {"command": "rm -rf /"})
        _write_jsonl(chats / "session-2026-11-12T10-00-s1aaaaaa.jsonl", [
            {"sessionId": "s1", "projectHash": "h", "startTime": "2026-11-12T10:00:00Z"},
            _gemini_msg("m1", [rm]),
            _gemini_msg("m1", [rm]),   # the same message, written again when the call ended
            {"$rewindTo": "m1"},   # the conversation drops it; the call was still made
            _gemini_msg("m2", [("c2", "run_shell_command", {"command": "ls"})]),
            {"$patch": {"id": "m2", "toolCalls": [{"id": "c2", "result": []}]}},
            {"$set": {"lastUpdated": "2026-11-12T10:05:00Z"}},
            "not json"])
        _write_jsonl(chats / "s1" / "sub1.jsonl", [
            {"sessionId": "sub1", "projectHash": "h", "kind": "subagent"},
            _gemini_msg("m1", [("c1", "read_file", {"file_path": "README.md"})])])
        old = chats / "session-2026-10-30T09-00-s0bbbbbb.json"
        old.write_text(json.dumps({"sessionId": "s0", "projectHash": "h", "messages": [
            {"id": "u1", "type": "user", "content": "clean up"},
            _gemini_msg("m1", [("c1", "run_shell_command", {"command": "terraform destroy -auto-approve"})])]},
            indent=2), encoding="utf-8")
        (chats.parent / "logs.json").write_text(json.dumps(_gemini_msg("m9", [rm])), encoding="utf-8")
        return self.root / ".gemini" / "tmp"

    def test_gemini_cli_sessions_are_read_as_its_hook_decides_them(self):
        tmp = self._gemini_sessions()
        code, out, err = _run(str(tmp), "--agent", "gemini", "--json")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        engine = load_policy(DEFAULT_POLICY)
        expected = []
        for session, name, args in (("s0", "run_shell_command", {"command": "terraform destroy -auto-approve"}),
                                    ("s1", "run_shell_command", {"command": "rm -rf /"}),
                                    ("s1", "run_shell_command", {"command": "ls"}),
                                    ("s1", "read_file", {"file_path": "README.md"})):
            tool, mapped = agent_hooks.tool("gemini", name, args)
            expected.append((session, tool, evaluate(engine, tool, mapped)[0]["verdict"]))
        self.assertEqual(sorted((c["session"], c["tool"], c["verdict"]) for c in report["calls"]), sorted(expected))
        self.assertEqual([c["tool"] for c in report["calls"] if c["session"] == "s1"][:2], ["Bash", "Bash"])
        self.assertEqual((report["counts"]["deny"], report["counts"]["ask"]), (1, 1))   # rm -rf /, terraform destroy
        self.assertEqual(report["skipped_malformed"], 1)
        self.assertEqual(report["agents"], {"gemini": {"folder": str(tmp), "calls": 4, "sessions": 2}})
        self.assertEqual(report["sessions"], 2)

    def test_gemini_cli_home_moves_its_folder(self):
        tmp = self._gemini_sessions()
        with mock.patch.dict(os.environ, {"GEMINI_CLI_HOME": str(self.root), "HOME": str(self.root / "empty"),
                                          "USERPROFILE": str(self.root / "empty")}):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            code, out, err = _run("--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["agents"], {"gemini": {"folder": str(tmp), "calls": 4, "sessions": 2}})

    def test_share_over_a_calls_file(self):
        _write_jsonl(self.root / "calls.jsonl", [_line("Bash", {"command": "rm -rf /"}, session="s1")])
        page = audit.share(audit.audit(calls=str(self.root / "calls.jsonl")))
        self.assertEqual(page.splitlines()[:3], [
            f"Tracekit {__version__} field report (tracekit audit --share): the whole calls file",
            "a replay against today's policy, not a signed record: 1 coding-agent session",
            "Tool calls: 1   allow 0, flag 0, ask 0, deny 1"])
        self.assertNotIn("s1", page)


if __name__ == "__main__":
    unittest.main()
