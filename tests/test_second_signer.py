"""A second tracekitd started on the same home must not cut the running one off: it stops at the ledger lock before
touching the socket."""
import os
import socket
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import client  # noqa: E402
from factories import DaemonCase  # noqa: E402


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and sys.platform != "win32", "Unix socket signer")
class SecondSigner(DaemonCase):
    def test_second_signer_leaves_the_running_one_reachable(self):
        self.assertTrue(client.rpc({"op": "status"})["ok"])
        p = subprocess.run([sys.executable, "-m", "tracekit.daemon", "--home", self.home], capture_output=True, text=True,
                           env=dict(os.environ, PYTHONPATH=ROOT), timeout=60)
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(client.rpc({"op": "status"})["ok"])  # still reachable through its socket


if __name__ == "__main__":
    unittest.main()
