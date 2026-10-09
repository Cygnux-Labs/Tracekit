"""Observer content display and the dev-socket path limit."""
import os
import sys
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
