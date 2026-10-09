"""0.2.1 hotfix tests: root-owned client config, per-run uid binding, fail-closed default in system mode,
pinned policy, refused writes kept in exports, the VERIFIED WITH GAPS verdict, and the TK-D010 fix.

    python3 -m unittest tests.test_hotfix_021 -v
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import bundle, client, policy  # noqa: E402
from tracekit.daemon import Signer, load_config  # noqa: E402
from factories import ledger_records, make_signer, patch_env, run_start, tool_call  # noqa: E402

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
AGENT_UID, OTHER_UID = 1001, 1002


class _SystemConfig(unittest.TestCase):
    """Point client.SYSTEM_CONFIG at a temp file for the duration of a test."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        p = mock.patch.object(client, "SYSTEM_CONFIG", os.path.join(self.d, "client.json"))
        p.start()
        self.addCleanup(p.stop)
        patch_env(self, TRACEKIT_SOCKET=None, TRACEKIT_POLICY=None)

    def write(self, cfg, mode=0o644):
        with open(client.SYSTEM_CONFIG, "w") as f:
            json.dump(cfg, f)
        os.chmod(client.SYSTEM_CONFIG, mode)


class SystemConfigTrust(_SystemConfig):
    def test_absent_means_none(self):
        self.assertIsNone(client.system_config())
        self.assertFalse(client.system_fail_closed())

    @pytest.mark.root
    @unittest.skipUnless(IS_ROOT, "needs root to create a root-owned file")
    def test_root_owned_is_trusted(self):
        self.write({"socket": "/var/lib/tracekit/tracekitd.sock", "mode": "system"})
        self.assertEqual(client.system_config()["mode"], "system")

    @pytest.mark.root
    @unittest.skipUnless(IS_ROOT, "needs root to chown")
    def test_not_root_owned_fails_closed(self):
        self.write({"socket": "/x"})
        os.chown(client.SYSTEM_CONFIG, 65534, 65534)
        self.assertRaises(client.SystemConfigError, client.system_config)

    @pytest.mark.root
    @unittest.skipUnless(IS_ROOT, "needs root to create a root-owned file")
    def test_group_or_world_writable_fails_closed(self):
        for mode in (0o664, 0o666, 0o646):
            self.write({"socket": "/x"}, mode)
            self.assertRaises(client.SystemConfigError, client.system_config)
            self.assertTrue(client.system_fail_closed(), oct(mode))

    @unittest.skipIf(IS_ROOT, "as root every file is root-owned")
    @unittest.skipIf(os.name == "nt", "Windows reports every file as uid 0")
    def test_user_owned_file_fails_closed_without_falling_back(self):
        self.write({"socket": "/x", "fail_mode": "open"})
        os.environ["TRACEKIT_SOCKET"] = os.path.join(self.d, "agent.sock")
        self.assertRaises(client.SystemConfigError, client.system_config)
        self.assertRaises(client.SystemConfigError, client.socket_path)
        self.assertRaises(client.SystemConfigError, client.client_config)
        self.assertTrue(client.system_fail_closed())

    @unittest.skipIf(os.name == "nt", "system config is unsupported on Windows")
    def test_bad_json_fails_closed(self):
        with open(client.SYSTEM_CONFIG, "w") as f:
            f.write("{ nope")
        os.chmod(client.SYSTEM_CONFIG, 0o644)
        self.assertRaises(client.SystemConfigError, client.system_config)
        self.assertTrue(client.system_fail_closed())


@pytest.mark.root
@unittest.skipUnless(IS_ROOT, "system config must be root-owned to be trusted")
class SystemConfigOverrides(_SystemConfig):
    def test_socket_env_and_home_config_are_ignored(self):
        self.write({"socket": "/var/lib/tracekit/tracekitd.sock", "mode": "system"})
        os.environ["TRACEKIT_SOCKET"] = "/home/agent/decoy.sock"
        self.assertEqual(client.socket_path(), "/var/lib/tracekit/tracekitd.sock")
        self.assertEqual(client.client_config()["socket"], "/var/lib/tracekit/tracekitd.sock")

    def test_policy_env_is_ignored(self):
        empty = os.path.join(self.d, "empty.json")
        with open(empty, "w") as f:
            json.dump({"version": "x", "deny": [], "ask": [], "flag": []}, f)
        self.write({"mode": "system"})
        os.environ["TRACEKIT_POLICY"] = empty
        pol, _ = policy.load()
        self.assertTrue(pol["deny"], "TRACEKIT_POLICY must not swap in an empty policy in system mode")

    def test_fail_closed_by_default(self):
        self.write({"mode": "system"})
        self.assertEqual(policy.load()[0]["fail_mode"], "closed")
        self.assertTrue(client.system_fail_closed())

    def test_fail_open_only_when_root_config_says_so(self):
        self.write({"mode": "system", "fail_mode": "open"})
        self.assertEqual(policy.load()[0]["fail_mode"], "open")
        self.assertFalse(client.system_fail_closed())

    def test_unknown_fail_mode_falls_back_to_closed(self):
        self.write({"mode": "system", "fail_mode": "sometimes"})
        self.assertEqual(policy.load()[0]["fail_mode"], "closed")

    def test_without_system_config_env_still_works(self):
        os.environ["TRACEKIT_SOCKET"] = "/tmp/dev.sock"
        self.assertEqual(client.socket_path(), "/tmp/dev.sock")  # dev mode unchanged


class RunOwnership(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.s = make_signer(os.path.join(self.d, "signer"))
        self.pol_raw = policy.load()[1]

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def append(self, e, cseq, uid, attach=None):
        req = {"op": "append", "cseq": cseq, "event": e}
        if attach:
            req["attach"] = attach
        return self.s.handle(req, peer_uid=uid, peer_pid=1)

    def events(self):
        return [r["event"] for r in ledger_records(self.s.home)]

    def test_owner_can_append(self):
        self.assertTrue(self.append(run_start(), 0, AGENT_UID, {"policy": self.pol_raw})["ok"])
        self.assertTrue(self.append(tool_call("t1"), 1, AGENT_UID)["ok"])

    def test_other_user_is_refused_and_recorded(self):
        self.append(run_start(), 0, AGENT_UID, {"policy": self.pol_raw})
        r = self.append(tool_call("injected", "rm -rf important/"), 1, OTHER_UID)
        self.assertFalse(r["ok"])
        evs = self.events()
        self.assertFalse(any(e["type"] == "tool.call" and e["data"]["tool_use_id"] == "injected" for e in evs))
        errs = [e for e in evs if e["type"] == "error"]
        self.assertTrue(errs and errs[-1]["data"]["client_run_id"] == "r1")
        self.assertIn("run belongs to uid", errs[-1]["data"]["message"])

    def test_other_user_cannot_restart_the_run(self):
        self.append(run_start(), 0, AGENT_UID, {"policy": self.pol_raw})
        self.assertFalse(self.append(run_start(), 1, OTHER_UID, {"policy": self.pol_raw})["ok"])

    def test_signer_own_uid_is_allowed(self):  # the proxy runs as the signer's user
        self.append(run_start(), 0, AGENT_UID, {"policy": self.pol_raw})
        if self.s.my_uid is not None and self.s.my_uid != AGENT_UID:
            self.assertTrue(self.append(tool_call("t2"), 1, self.s.my_uid)["ok"])

    def test_ownership_survives_restart(self):
        if not hasattr(os, "getuid"):
            self.skipTest("no uids")
        import pwd
        me = pwd.getpwuid(os.getuid())
        self.append(run_start(), 0, me.pw_uid, {"policy": self.pol_raw})
        self.s.ledger.close()  # a restart: the old process lets go of the ledger
        s2 = Signer(self.s.home, load_config(self.s.home))
        self.assertEqual(s2.runs["r1"]["agent_uid"], me.pw_uid)


class PinnedPolicy(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.pol, self.pol_raw = policy.load()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def gaps(self, s):
        return [r["event"]["data"] for r in ledger_records(s.home)
                if r["event"]["type"] == "capture.gap" and r["event"]["data"].get("kind") == "policy_mismatch"]

    def test_matching_policy_is_silent(self):
        s = make_signer(os.path.join(self.d, "a"), pinned_policy_hash=policy.policy_hash(self.pol))
        s.handle({"op": "append", "cseq": 0, "event": run_start(pol=self.pol), "attach": {"policy": self.pol_raw}})
        self.assertEqual(self.gaps(s), [])

    def test_different_policy_is_a_gap(self):
        s = make_signer(os.path.join(self.d, "b"), pinned_policy_hash="sha256:" + "0" * 64)
        s.handle({"op": "append", "cseq": 0, "event": run_start(pol=self.pol), "attach": {"policy": self.pol_raw}})
        g = self.gaps(s)
        self.assertEqual(len(g), 1)
        self.assertIn("not the pinned policy", g[0]["reason"])

    def test_no_pin_no_check(self):
        s = make_signer(os.path.join(self.d, "c"))
        s.handle({"op": "append", "cseq": 0, "event": run_start(pol=self.pol), "attach": {"policy": self.pol_raw}})
        self.assertEqual(self.gaps(s), [])


class Verdict(unittest.TestCase):
    class Rep:
        def __init__(self, checks):
            self.checks = checks

    def verdict(self, checks, code=bundle.EXIT_OK):
        out = io.StringIO()
        bundle.print_report(self.Rep(checks), code, out)
        return next(l for l in out.getvalue().splitlines() if l.startswith("Integrity: "))[len("Integrity: "):]

    def chk(self, name, status):
        return {"check": name, "status": status, "detail": "", "problems": []}

    def test_clean_run_is_verified(self):
        v = self.verdict([self.chk("capture gaps", "pass"), self.chk("trust root", "pass")])
        self.assertTrue(v.startswith("VERIFIED."))

    def test_capture_gap_is_never_clean(self):
        v = self.verdict([self.chk("capture gaps", "warn"), self.chk("trust root", "pass")])
        self.assertTrue(v.startswith("VERIFIED WITH GAPS (capture gaps)"), v)

    def test_rejected_write_is_never_clean(self):
        v = self.verdict([self.chk("rejected writes", "warn"), self.chk("trust root", "pass")])
        self.assertIn("WITH GAPS (rejected writes)", v)

    def test_other_warnings_do_not_change_verdict(self):
        v = self.verdict([self.chk("signing key", "warn"), self.chk("trust root", "pass")])
        self.assertTrue(v.startswith("VERIFIED."))

    def test_refused_writes_are_kept_for_single_run_export(self):
        self.assertIn("error", bundle.SIGNER_TYPES)


class TKD010(unittest.TestCase):
    def setUp(self):
        self.pol = policy.load(policy.DEFAULT_POLICY)[0]

    def decision(self, cmd):
        return policy.evaluate(self.pol, "Bash", {"command": cmd})["decision"]

    def test_copying_from_env_is_not_a_write_to_it(self):
        self.assertNotEqual(self.decision("cp .env /tmp/notes.txt"), "deny")
        self.assertNotEqual(self.decision("cp .env.example /tmp/a"), "deny")

    def test_writing_to_credentials_is_still_denied(self):
        for cmd in ("cp /tmp/x .env", "mv key ~/.ssh/id_rsa", "echo X > .env", "cat a | tee -a .env",
                    "cp .env.example .env", "install -m600 k ~/.aws/credentials"):
            self.assertEqual(self.decision(cmd), "deny", cmd)


if __name__ == "__main__":
    unittest.main()
