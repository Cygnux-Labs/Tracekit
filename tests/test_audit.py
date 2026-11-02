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

from tracekit import __version__, audit, cli


def _call(tool, args, days_ago=0):
    """An assistant line with one tool use, as Claude Code writes it."""
    at = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"type": "assistant", "timestamp": at.isoformat().replace("+00:00", "Z"),
            "message": {"content": [{"type": "tool_use", "name": tool, "input": args}]}}


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


if __name__ == "__main__":
    unittest.main()
