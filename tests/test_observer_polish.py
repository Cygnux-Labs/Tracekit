"""Observer content display and the dev-socket path limit."""
import os
import sys
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install, observe  # noqa: E402


class HashedContent(unittest.TestCase):
    def test_hashed_content_shows_size_not_hash(self):
        shown = observe._show({"hash": "sha256:" + "ab" * 32, "size": 82})
        self.assertEqual(shown, "[hashed · 82 bytes]")
        self.assertEqual(observe._show({"hash": "sha256:00", "size": 5, "redacted": True}), "[hashed · 5 bytes · redacted]")
        self.assertEqual(observe._show({"value": "ls"}), "ls")


class Times(unittest.TestCase):
    def test_a_row_reads_every_timestamp_a_why_log_may_hold_and_keeps_the_signers_time(self):
        """A why log's ts with no fraction or 7-9 digits read as now (the newest call on HORIZON); a v1 row had only
        the client's ts."""
        for ts, want in (("2026-10-27T10:00:00Z", 1793095200), ("2026-10-27T10:00:00.5Z", 1793095200.5),
                         ("2026-10-27T10:00:00.123456789Z", 1793095200.123456789)):
            self.assertAlmostEqual(observe._epoch(ts), want, places=6)
        self.assertAlmostEqual(observe._epoch("2026-10-27T10:00:00+00:00"), time.time(), delta=5)   # shown as now, never 1970
        row = observe.Translator()._base({"run_id": "r", "ts": "2020-01-01T00:00:00Z", "ts_signed": "2026-10-27T10:00:00Z"}, {}, "PreToolUse")
        self.assertEqual((row["ts"], row["ts_signed"]), (1577836800, 1793095200))
        self.assertNotIn("ts_signed", observe.Translator()._base({"run_id": "r", "ts": "2026-10-27T10:00:00Z"}, {}, "PreToolUse"))


class DevSocketPath(unittest.TestCase):
    @unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "Unix sockets only")
    def test_too_long_home_is_a_clear_error(self):
        with mock.patch("tracekit.peercred.has_peer_credentials", return_value=True):
            with self.assertRaises(SystemExit) as cm:
                install._dev_socket("/tmp/" + "x" * 120)
            self.assertIn("too long for a Unix socket", str(cm.exception))
            path, token = install._dev_socket("/tmp/short")
            self.assertEqual((path, token), ("/tmp/short/tracekitd.sock", None))


if __name__ == "__main__":
    unittest.main()
