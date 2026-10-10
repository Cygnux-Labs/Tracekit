"""The central signer's replicas (deploy/helm/tracekit-central): ids that carry the replica's route, the client sending a
run's calls to its replica, and a scaled-down replica closing its log on SIGTERM."""
import json
import os
import signal
import subprocess
import sys
import unittest

import test_rpc_contract as rc
from factories import wait_for
from test_signer_service import PAY_ASKS, tmpdir
from tracekit.sdk.client import _Https
from tracekit.signer import service as svc


class Route(rc.Harness, unittest.TestCase):
    def make_signer(self):
        s = svc.SignerService(tmpdir(self), policy=PAY_ASKS, route="t-1")
        self.addCleanup(s.close)
        return s

    def test_run_and_approval_ids_start_with_the_route(self):
        self.assertTrue(self.ask().startswith("t-1.apr-"))
        self.assertTrue(self.run_id.startswith("t-1."))
        self.assertEqual(self.register(run_id="t-1.mine")["run_id"], "t-1.mine")
        self.refused("invalid_request", "register_run", {"request_id": self.rid(), "agent": {"name": "a"},
                                                         "run_id": "t-2.theirs"})

    def test_config_takes_a_dns_label(self):
        d = tmpdir(self)
        for route, ok in (("t-1", True), ("T_1", False), ("a.b", False), (7, False)):
            path = os.path.join(d, "signer.yaml")
            with open(path, "w") as f:
                json.dump({"data_dir": ".", "route": route}, f)
            if ok:
                self.assertEqual(svc.load_config(path)["route"], route)
            else:
                self.assertRaisesRegex(ValueError, "route is a DNS label", svc.load_config, path)


class ClientRoutes(unittest.TestCase):
    def test_a_replicas_ids_go_to_its_service(self):
        h = _Https("https://t.ns.svc:8443")
        for req, host in (({"run_id": "t-2.ab"}, "t-2.ns.svc"), ({"approval_id": "t-0.apr-1"}, "t-0.ns.svc"),
                          ({"analyzes": "t-3.cd", "agent": {}}, "t-3.ns.svc"), ({}, "t.ns.svc"),
                          ({"run_id": "t-2"}, "t.ns.svc"), ({"run_id": "my.run"}, "t.ns.svc"),
                          ({"run_id": "t-x.ab"}, "t.ns.svc"), ({"run_id": "tt-1.ab"}, "t.ns.svc")):
            self.assertEqual(h._host(req), host, req)
        self.assertEqual(_Https("https://t:8443")._host({"run_id": "t-1.ab"}), "t-1")


@unittest.skipIf(os.name != "posix", "SIGTERM")
class ScaleDown(unittest.TestCase):
    def test_sigterm_with_the_marker_closes_the_log_and_a_closed_log_is_not_served(self):
        d = tmpdir(self)
        cfg, marker = os.path.join(d, "signer.yaml"), os.path.join(d, "close-log")
        with open(cfg, "w") as f:
            json.dump({"data_dir": "data", "socket": "s.sock", "route": "t-0"}, f)
        argv = [sys.executable, "-m", "tracekit.cli", "signer", "serve", "--config", cfg, "--close-on-stop", marker]

        def serve_and_stop(close):
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertTrue(wait_for(lambda: os.path.exists(os.path.join(d, "s.sock")) or p.poll() is not None, 30))
            if close:
                open(marker, "w").close()
            p.send_signal(signal.SIGTERM)
            return p.wait(60), p.communicate()[1]

        self.assertEqual(serve_and_stop(False), (0, ""))   # no marker: a restart, the log stays open
        s = svc.SignerService(os.path.join(d, "data"))
        self.assertFalse(s.log.head["closed"])
        s.close()
        self.assertEqual(serve_and_stop(True), (0, ""))
        s = svc.SignerService(os.path.join(d, "data"))
        last = next(s.log.storage.iter_range(s.log.head["seq"] - 1, s.log.head["seq"]))["event"]
        self.assertEqual(last["type"], "log.closed")
        self.assertEqual(s.log.storage.checkpoint_latest()[0], last["seq"] + 1)
        s.close()
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertIn("the log is closed (log.closed)", p.stderr)


if __name__ == "__main__":
    unittest.main()
