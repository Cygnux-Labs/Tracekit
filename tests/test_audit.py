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

from tracekit import audit, cli


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

    def test_a_call_the_engine_fails_on_is_a_deny_as_the_signer_decides_it(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "ls"})])
        with mock.patch("tracekit.policy2.engine.Engine.decide", side_effect=RuntimeError("boom")):
            report = audit.audit(str(self.root))
        self.assertEqual(report["counts"]["deny"], 1)
        self.assertEqual(report["by_rule"], {"TK-ENGINE-ERROR": 1})
        self.assertEqual(report["skipped_malformed"], 0)

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
