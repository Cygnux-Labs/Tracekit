"""The v1 known gaps (tests/test_known_gaps.py) on the v2 signer: one test per gap id, deciding with the signer's packs
(tracekit/policy2/packs) or its engine. kg09 (cross-check beyond tool_use_id) belongs to M1b-06 and is not here."""
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from test_signer_service import ME, OTHER, SAME_USER, SEPARATE_USER
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError

PAY = {"to": "acct-42", "cents": 1500}


class KnownGapsV2(unittest.TestCase):
    def setUp(self):
        self.open()

    def open(self, policy=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.s = svc.SignerService(d, policy=policy)
        self.addCleanup(self.s.close)
        self.run = self.s.register_run({"request_id": "reg", "agent": {"name": "a"}})
        self.seq = -1

    def req(self, **kw):
        self.seq += 1
        return {"request_id": f"rq-{self.seq}", "run_id": self.run["run_id"], "run_token": self.run["run_token"],
                "stream": "s1", "client_seq": self.seq, **kw}

    def decide(self, tool, args, tcid="tc-1"):
        return self.s.decide(self.req(tool_call_id=tcid, tool=tool, args_source="parsed", args=args))

    def denied(self, tool, args, rule):
        d = self.decide(tool, args)
        self.assertEqual(d["decision"], "deny", d)
        self.assertIn(rule, d["rule_ids"])

    def test_kg01_sudo_by_absolute_path(self):
        self.denied("Bash", {"command": "/usr/bin/sudo id"}, "TK-D001")

    def test_kg02_sudo_after_command_builtin(self):
        self.denied("Bash", {"command": "command sudo id"}, "TK-D001")

    def test_kg03_sudo_after_env_assignment(self):
        self.denied("Bash", {"command": "x=1 sudo id"}, "TK-D001")

    def test_kg04_download_piped_to_shell_by_path(self):
        self.denied("Bash", {"command": "curl x | /bin/sh"}, "TK-D002")

    def test_kg05_key_read_piped_to_upload_across_windows(self):
        self.denied("Bash", {"command": "cat ~/.ssh/id_rsa" + " " * 20000 + "| curl x"}, "TK-D011")

    def test_kg06_notebook_edit_on_credentials_file(self):
        self.denied("NotebookEdit", {"notebook_path": "/p/.env", "new_source": "x"}, "TK-D005")

    def test_kg07_ask_rule_on_other_tool_name(self):
        self.open(Engine({"tools": {"shell": "shell"}, "ask": [{"id": "T-ASK", "class": "shell", "pattern": "deploy"}]}))
        self.assertEqual(self.decide("shell", {"command": "deploy"})["decision"], "ask")

    def test_kg08_regex_budget_off_main_thread(self):
        engine = Engine({"deny": [{"id": "T-SLOW", "tool": "Bash", "pattern": r"\s+x"}]})
        self.open(engine)
        cmd = "a" * (120 * 1024) + " " * (32 * 1024)
        cmd += "a" * (240 * 1024 - len(cmd))
        out = []

        def off_main(tcid, args):
            t = threading.Thread(target=lambda: out.append(self.decide("Bash", args, tcid)))
            t.start()
            t.join()
            return out[-1]
        self.assertEqual(off_main("tc-1", {"command": cmd})["decision"], "deny")   # over the subject cap: TK-OVERSIZE
        with mock.patch.object(engine, "_match", side_effect=TimeoutError):   # a match that runs out of time
            d = off_main("tc-2", {"command": "ls"})
        self.assertEqual((d["decision"], d["rule_ids"]), ("deny", ["T-SLOW"]))

    def test_kg10_approval_bound_to_arguments(self):
        self.open(Engine({"ask": [{"id": "T-PAY", "tool": "pay", "pattern": "^"}]}))
        self.assertEqual(self.decide("pay", PAY)["decision"], "ask")
        run = {"run_id": self.run["run_id"], "run_token": self.run["run_token"], "tool_call_id": "tc-1"}
        aid = self.s.approval_request({"request_id": "aq", **run})["approval_id"]
        self.s.approval_decide({"request_id": "ap", "approval_id": aid, "decision": "approve"})
        edited = self.s.approval_consume({"request_id": "ac", **run, "tool": "pay", "args_source": "parsed",
                                          "args": dict(PAY, cents=1500000), "approval_id_hint": aid})
        self.assertEqual((edited["ok"], edited["rule_ids"]), (False, ["TK-APPROVAL-MISMATCH"]))

    def test_kg11_signer_isolation_not_taken_from_client(self):
        with self.assertRaises(RPCError) as cm:
            self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}, "signer_isolation": "separate-user"})
        self.assertEqual(cm.exception.code, "invalid_request")
        measured = [self.s.call(who, "register_run", {"request_id": "r2", "agent": {"name": "a"}})["run_id"]
                    for who in (ME, OTHER)]
        self.assertEqual([self.isolation(r) for r in measured], [SAME_USER, SEPARATE_USER])

    def isolation(self, run_id):
        [reg] = [r["event"] for r in self.s.log.storage.iter_run("default", run_id) if r["event"]["type"] == "run.registered"]
        return reg["data"]["signer_isolation"]


if __name__ == "__main__":
    unittest.main()
