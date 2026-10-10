"""Other systems' policy decisions imported as signed inputs: decision_import in the v2 signer, the mappers of
tracekit/integrations/external_decisions.py over the fixtures in tests/data/external/ (the documented shapes that
module's docstring cites), the decision_mismatch gap and the verifier's `external decisions` line."""
import base64
import hashlib
import os

import test_reconcile
from test_reconcile import Reconcile
from test_signer_service import PAY_ASKS, records
from tracekit import crypto
from tracekit.identity.base import CallerIdentity
from tracekit.integrations import external_decisions
from tracekit.signer import service as svc

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "external")
PDP = CallerIdentity("mtls", "spiffe://acme/pdp", True)
SECRET, PUBLIC = crypto.generate()


def fixture(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return f.read()


class TestDecisionImport(Reconcile):
    verify = test_reconcile.TestCoverageLine.verify

    def setUp(self):
        super().setUp()
        self.s.close()
        self.s = svc.SignerService(self.dir, policy=PAY_ASKS, tenants={"uid:999003": "beta"}, grace_s=60, idle_s=60,
                                   authorize={"mtls:spiffe://acme/pdp": ["decision_import"]},
                                   decision_keys={"vscode-agent-hooks": base64.b64encode(PUBLIC).decode()})

    def test_every_fixture_round_trips(self):
        run = self.register()
        aws, vsc = fixture("aws-agentcore-policy.json"), fixture("vscode-agent-hooks.json")
        avp, gh = fixture("aws-verified-permissions.json"), fixture("github-copilot-hooks.json")
        reqs = [external_decisions.agentcore(aws, run["run_id"], "tc-1", "RefundTarget___process_refund", "imp-1"),
                external_decisions.vscode_hooks(vsc, run["run_id"], "imp-2",
                                                base64.b64encode(crypto.sign(SECRET, vsc.encode())).decode()),
                external_decisions.verified_permissions(avp, run["run_id"], "tc-3", "photos_view", "imp-3"),
                external_decisions.copilot_hooks(gh, run["run_id"], "tc-4", "imp-4")]
        self.assertEqual(self.call("decision_import", reqs[0], PDP)["signature"], "unverified")   # before the decide
        for tcid, req in zip(("tc-1", "call-ms-1", "tc-3", "tc-4"), reqs):
            self.run_call(run, tcid, req["tool"])
        for req in reqs[1:]:
            self.call("decision_import", req, PDP)   # after the decide
        [(_, final)] = self.final(run)
        es = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]]
        imported = [e for e in es if e["type"] == "policy.external"]
        self.assertEqual([(e["source"], e["tier"], e["data"]["system"], e["data"]["decision"], e["data"]["tool_use_id"],
                           e["data"]["tool"], e["data"]["rule_ids"], e["data"]["signature"]) for e in imported],
                         [("import", "T3", "aws-agentcore-policy", "deny", "tc-1", "RefundTarget___process_refund",
                           ["refund-limit-1000"], "unverified"),
                          ("import", "T3", "vscode-agent-hooks", "ask", "call-ms-1", "runInTerminal", [], "verified"),
                          ("import", "T3", "aws-verified-permissions", "allow", "tc-3", "photos_view",
                           ["SPEXAMPLEabcdefg111111"], "unverified"),
                          ("import", "T3", "github-copilot-hooks", "deny", "tc-4", "bash", [], "unverified")])
        for e, raw in zip(imported, (aws, vsc, avp, gh)):   # the record only as a commitment the signer's salt opens
            self.assertNotIn("refund", str(e["data"]["record"]))
            self.assertEqual(e["data"]["record"], {"hash": self.s._commit(
                f"policy.external:{e['data']['salt_id']}", "sha256:" + hashlib.sha256(raw.encode()).hexdigest()),
                "size": len(raw.encode())})
        self.assertEqual([e["data"].get("reason") for e in imported],
                         ["a forbid policy matched", "piping a download into a shell needs a person", None,
                          "deletes outside the workspace's build rules"])
        gaps = [(e["data"]["kind"], e["tool_call_id"], e["data"]["reason"]) for e in es if e["type"] == "capture.gap"]
        self.assertEqual(gaps, [("decision_mismatch", "tc-1", "aws-agentcore-policy decided deny; the signer decided allow"),
                                ("decision_mismatch", "call-ms-1", "vscode-agent-hooks decided ask; the signer decided allow"),
                                ("decision_mismatch", "tc-4", "github-copilot-hooks decided deny; the signer decided allow")])
        self.assertEqual(final["type"], "run.final")
        rep, code, text = self.verify(run)
        self.assertEqual((code, "external decisions" in rep.warnings), (0, True))   # --strict exits 3 on it
        self.assertIn("external decisions — 4 imported:", text)
        self.assertIn("signatures verified 1, unverified 3; 3 disagree with the signer", text)

    def test_agreement_is_no_gap(self):
        run = self.register()
        self.run_call(run, "tc-1", "pay")   # PAY_ASKS: ask
        self.call("decision_import", {"run_id": run["run_id"], "system": "other-pdp", "decision": "ask",
                                      "tool_call_id": "tc-1", "tool": "pay", "record": "{}"}, PDP)
        self.final(run)
        rep, code, text = self.verify(run)
        self.assertNotIn("external decisions", rep.warnings)
        self.assertIn("[PASS] external decisions — 1 imported: other-pdp 1; signatures verified 0, unverified 1; "
                      "0 disagree with the signer", text)

    def test_an_undecided_call_or_another_tool_is_a_mismatch(self):
        run = self.register()
        self.run_call(run, "tc-1", "pay")   # PAY_ASKS: ask
        for tcid, tool in (("tc-1", "refund"), ("tc-9", "pay")):
            self.call("decision_import", {"run_id": run["run_id"], "system": "other-pdp", "decision": "ask",
                                          "tool_call_id": tcid, "tool": tool, "record": "{}"}, PDP)
        self.final(run)
        es = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]]
        self.assertEqual([(e["tool_call_id"], e["data"]["reason"]) for e in es if e["type"] == "capture.gap"],
                         [("tc-1", "other-pdp decided ask on refund; the signer decided ask on pay"),
                          ("tc-9", "other-pdp decided ask on pay; the signer decided nothing on this call")])
        rep, _, text = self.verify(run)
        self.assertIn("external decisions", rep.warnings)
        self.assertIn("2 disagree with the signer", text)

    def test_only_granted_identities_of_the_runs_tenant(self):
        run, beta = self.register(), self.register(CallerIdentity("uid", "999003", True))
        req = {"run_id": run["run_id"], "system": "x", "decision": "deny", "tool_call_id": "tc-1", "tool": "t",
               "record": "{}"}
        self.refused("forbidden", "decision_import", req)   # the run's own uid: never a default grant
        self.refused("unknown_run", "decision_import", dict(req, run_id=beta["run_id"]), PDP)   # another tenant's run

    def test_a_pinned_system_must_send_a_signature_that_verifies(self):
        run = self.register()
        req = {"run_id": run["run_id"], "system": "vscode-agent-hooks", "decision": "deny", "tool_call_id": "tc-1",
               "tool": "t", "record": "{}", "signature": base64.b64encode(crypto.sign(SECRET, b"{ }")).decode()}
        self.refused("invalid_request", "decision_import", req, PDP)
        self.refused("invalid_request", "decision_import", dict(req, signature="not base64!"), PDP)
        self.refused("invalid_request", "decision_import", {k: v for k, v in req.items() if k != "signature"}, PDP)
        self.assertEqual(self.call("decision_import", dict(req, system="unpinned"), PDP)["signature"], "unverified")
