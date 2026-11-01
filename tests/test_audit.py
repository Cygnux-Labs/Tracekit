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


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()   # on macOS it is under /var, a symlink to /private/var
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_held_denied_allowed_and_malformed(self):
        _write_jsonl(self.root / "proj" / "session-abc.jsonl", [
            _call("Bash", {"command": "rm -rf /"}), _call("Bash", {"command": "terraform destroy -auto-approve"}),
            _call("Bash", {"command": "ls -la"}), "this is not json", {"type": "user", "message": {"content": "hi"}}])
        report = audit.audit(str(self.root))
        self.assertEqual(report["counts"], {"deny": 1, "ask": 1, "flag": 0, "allow": 1})
        self.assertIn("TK-D001", report["by_rule"])
        self.assertIn("TK-A001", report["by_rule"])
        self.assertEqual(report["skipped_malformed"], 1)
        self.assertEqual({c["session"] for c in report["calls"]}, {"session-abc"})
        self.assertTrue(all(c["time"] for c in report["calls"]))
        self.assertNotIn("text", report["calls"][0])   # the command text only with --show
        self.assertIn("not a signed record", report["disclaimer"])

    def test_an_unreadable_file_is_counted_and_skipped(self):
        bad = self.root / "proj" / "bad.jsonl"
        _write_jsonl(bad, [_call("Bash", {"command": "rm -rf /"})])
        bad.chmod(0)
        if os.access(bad, os.R_OK):   # root, or a file system that ignores the mode (Windows)
            self.skipTest("the file stays readable here")
        report = audit.audit(str(self.root))
        self.assertEqual(len(report["unreadable"]), 1)
        self.assertEqual(report["calls"], [])

    def test_a_symlink_out_of_the_folder_is_not_followed(self):
        with tempfile.TemporaryDirectory() as outside:
            real = Path(outside) / "other.jsonl"
            _write_jsonl(real, [_call("Bash", {"command": "rm -rf /"})])
            try:
                (self.root / "link.jsonl").symlink_to(real)
                (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
            except OSError:   # Windows without the privilege
                self.skipTest("no symlinks here")
            self.assertEqual(audit.audit(str(self.root))["calls"], [])

    def test_since_keeps_only_newer_calls(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "echo old"}, days_ago=30),
                                             _call("Bash", {"command": "echo new"}, days_ago=1)])
        report = audit.audit(str(self.root), since="10d", show=True)
        self.assertEqual([c["text"] for c in report["calls"]], ["echo new"])
        with self.assertRaises(ValueError):
            audit.audit(str(self.root), since="last week")

    def test_show_redacts_secrets(self):
        key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0" * 2
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": f"export ANTHROPIC_API_KEY={key}"})])
        text = audit.audit(str(self.root), show=True)["calls"][0]["text"]
        self.assertNotIn(key, text)
        self.assertIn("export ANTHROPIC_API_KEY=", text)

    def test_the_command_prints_the_report_and_json_matches_it(self):
        _write_jsonl(self.root / "s.jsonl", [_call("Bash", {"command": "rm -rf /"}), _call("Bash", {"command": "ls"})])
        report = audit.audit(str(self.root))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["audit", str(self.root), "--json"]), 0)
        self.assertEqual(json.loads(out.getvalue())["counts"], report["counts"])
        self.assertIn("tracekit audit is experimental", err.getvalue())
        text = audit.format_report(report)
        self.assertTrue(text.startswith("a replay against today's policy, not a signed record\n"))
        self.assertIn("  deny: 1\n", text)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["audit", str(self.root), "--since", "soon"]), 2)


if __name__ == "__main__":
    unittest.main()
