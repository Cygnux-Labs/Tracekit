"""Dev TCP signer on an ephemeral port: the client finds the recorded port; config rewrites survive Windows locks."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tracekit import client
from tracekit.deploy import files


class PortZero(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def connect_address(self, cfg):
        sock = mock.Mock()
        sock.connect.side_effect = OSError("refused")
        with mock.patch.object(client.socket, "socket", return_value=sock):
            with self.assertRaises(client.SignerUnavailable):
                client._rpc({"op": "status"}, config=cfg)
        return [c.args[0] for c in sock.connect.call_args_list]

    def test_port_zero_resolves_from_signer_config(self):
        with open(os.path.join(self.d, "config.json"), "w") as f:
            json.dump({"socket": "tcp://127.0.0.1:45123"}, f)
        cfg = {"socket": "tcp://127.0.0.1:0", "socket_token": "t", "signer_home": self.d}
        self.assertEqual(self.connect_address(cfg), [("127.0.0.1", 45123)])

    def test_port_zero_without_a_recorded_port_is_unavailable(self):
        cfg = {"socket": "tcp://127.0.0.1:0", "socket_token": "t", "signer_home": self.d}
        with self.assertRaises(client.SignerUnavailable):
            client._rpc({"op": "status"}, config=cfg)


class ReplaceRetry(unittest.TestCase):
    def test_retries_while_windows_holds_the_target_open(self):
        calls = []

        def flaky(src, dst):
            calls.append((src, dst))
            if len(calls) < 3:
                raise PermissionError(5, "Access is denied")
        with mock.patch.object(files.os, "name", "nt"), mock.patch.object(files.os, "replace", flaky), \
                mock.patch.object(files.time, "sleep"):
            files.replace_retrying("a", "b")
        self.assertEqual(len(calls), 3)

    def test_no_retry_off_windows(self):
        with mock.patch.object(files.os, "name", "posix"), \
                mock.patch.object(files.os, "replace", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(PermissionError):
                files.replace_retrying("a", "b")


if __name__ == "__main__":
    unittest.main()
