"""Guarded onchain transactions (#15): the guard's verdict is signed before signing; a blocked transaction never reaches
the wallet; detectors catch unguarded or overridden transactions. The guard here implements PGS's Guard.check()
interface; PGS itself needs a chain, web3 and Z3 and is not run in this suite.  python3 -m pytest contrib/onchain/tests -q"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from tracekit import bundle, install
from tracekit_onchain import analyze, guarded_tx
from tracekit.agent_sdk import Tracer
from factories import ledger_records, patch_env

ROUTER = "0x" + "11" * 20
ATTACKER = "0x" + "66" * 20


class PGSLikeGuard:
    """Same contract as pgs.guard.Guard.check: allow, reasons, post (compiled post-conditions)."""

    def check(self, calls):
        to = calls[0][0]
        if to == ATTACKER:
            return {"allow": False, "reasons": [f"eoa-recipient-not-allowlisted:{to}"], "post": None}
        return {"allow": True, "reasons": [], "post": ([(ROUTER, 10 ** 18)], [], [], [])}


class Wallet:
    def __init__(self):
        self.signed = []

    def execute_checked(self, calls, post):
        self.signed.append((calls, post))
        return {"transactionHash": bytes.fromhex("ab" * 32), "status": 1}


class Onchain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        patch_env(self)
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        shutil.rmtree(self.d, ignore_errors=True)

    def records(self):
        return [r for r in ledger_records(self.home) if not r.get("elided")]

    def test_allowed_and_blocked(self):
        wallet = Wallet()
        with Tracer(agent="wallet-agent", session_id="tx-1", cwd=self.d) as t:
            r = guarded_tx(t, PGSLikeGuard(), [(ROUTER, 0, "0xa9059cbb" + "00" * 64)], wallet.execute_checked, chain_id=31337)
            self.assertEqual(r["status"], 1)
            with self.assertRaises(PermissionError):
                guarded_tx(t, PGSLikeGuard(), [(ATTACKER, 5 * 10 ** 18, b"")], wallet.execute_checked, chain_id=31337)
        self.assertEqual(len(wallet.signed), 1, "the blocked transaction never reached the wallet")
        evs = [r["event"] for r in self.records() if r["event"]["run_id"] == "tx-1"]
        order = [e["type"] for e in evs]
        # for each transaction: call, policy decision, guard verdict, result, in that order
        self.assertEqual(order[1:], ["tool.call", "policy.decision", "review", "tool.result"] * 2 + ["run.end"])
        verdicts = [e["data"]["verdict"] for e in evs if e["type"] == "review"]
        self.assertEqual([v["allow"] for v in verdicts], [True, False])
        self.assertTrue(verdicts[0]["postconditions_sha256"].startswith("sha256:"))
        self.assertEqual(verdicts[0]["tx"]["calls"][0]["selector"], "0xa9059cbb")
        res = [e["data"] for e in evs if e["type"] == "tool.result"]
        self.assertEqual([x["ok"] for x in res], [True, False])
        f = {x["rule"] for x in analyze(self.records(), "tx-1")}
        self.assertIn("TK-X008", f)
        self.assertFalse({"TK-X006", "TK-X007"} & f)
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out, run="tx-1")
        self.assertEqual(bundle.verify(out)[1], 0)

    def test_guard_errors_fail_closed(self):
        class Broken:
            def check(self, calls):
                raise RuntimeError("solver timeout")
        wallet = Wallet()
        with Tracer(agent="w", session_id="tx-2", cwd=self.d) as t:
            with self.assertRaises(PermissionError):
                guarded_tx(t, Broken(), [(ROUTER, 0, b"")], wallet.execute_checked)
        self.assertEqual(wallet.signed, [])

    def test_detectors_catch_unguarded_and_overridden(self):
        def rec(seq, typ, data):
            return {"event": {"seq": seq, "run_id": "r", "type": typ, "source": "sdk", "data": data}, "hash": f"{seq:064x}"}
        unguarded = [rec(1, "tool.call", {"tool_use_id": "a", "name": "OnchainTx", "input": {}}),
                     rec(2, "tool.result", {"tool_use_id": "a", "ok": True, "output": {"value": {}, "redacted": False}})]
        self.assertIn("TK-X006", {x["rule"] for x in analyze(unguarded, "r")})
        overridden = unguarded[:1] + [rec(2, "review", {"reviewer": "tx-guard", "verdict": {"kind": "tx_guard", "allow": False,
                                                                                            "reasons": ["payee-cap"], "tool_use_id": "a"}}),
                                      rec(3, "tool.result", {"tool_use_id": "a", "ok": True, "output": {"value": {}, "redacted": False}})]
        self.assertIn("TK-X007", {x["rule"] for x in analyze(overridden, "r")})

    @unittest.skipUnless(os.environ.get("TRACEKIT_PGS"), "set TRACEKIT_PGS=<pgs repo> with a Hardhat node on :8545")
    def test_pgs_demo(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "pgs_onchain_demo.py"), "--pgs", os.environ["TRACEKIT_PGS"],
                            "--out", os.path.join(self.d, "pgs.tkb")], cwd=self.d, capture_output=True, text=True, timeout=600)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(p.stdout.count("BLOCKED by the guard, never signed"), 2)
        self.assertIn("REVERTED on-chain by the post-conditions", p.stdout)
        self.assertIn("attacker gain over the session: 0.00", p.stdout)
        verdicts = [r["event"]["data"]["verdict"]["allow"] for r in self.records()
                    if r["event"]["type"] == "review" and r["event"]["data"].get("reviewer") == "tx-guard"]
        self.assertEqual(verdicts, [True, True, False, False, True])


class Summary(unittest.TestCase):
    def test_pgs_call_dicts_keep_their_target(self):
        from tracekit_onchain import _summary
        s = _summary([{"target": "0xabc", "value": 0, "data": "0xa9059cbb" + "00" * 64}], 31337)
        self.assertEqual((s["calls"][0]["to"], s["calls"][0]["selector"]), ("0xabc", "0xa9059cbb"))


if __name__ == "__main__":
    unittest.main()
