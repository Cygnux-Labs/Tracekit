"""Run lifecycle on the v2 signer (tracekit/signer/service.py): registration, closing, grace window, run.final, idle
close, registry leaves, and the v2 counterparts of the v1 known gaps (signer-only gap/tamper records, signer-measured
isolation and fail modes, restricted `migrated` and findings runs)."""
import json
import os
import time
import unittest

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from test_rpc_contract import _pay_asks
from test_signer_service import ME, OTHER, records, tmpdir
from tracekit import merkle
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.checkpoint import ED25519
from tracekit.identity.base import CallerIdentity
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

MIGRATOR = CallerIdentity("uid", "999001", True)
ANALYZER = CallerIdentity("uid", "999002", True)
ANALYZER_BETA = CallerIdentity("uid", "999003", True)
FAIL_MODES = {"default": "closed", "read": "open"}


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.dir, self.n = tmpdir(self), 0
        self.s = svc.SignerService(self.dir, rule=_pay_asks, tenants={"uid:999003": "beta"},
                                   multi_tenant_apps=[f"uid:{ME.subject}"], migrators=["uid:999001"],
                                   analyzers=["uid:999002", "uid:999003"], fail_modes=FAIL_MODES, grace_s=60, idle_s=60)
        self.closed = False
        self.addCleanup(self.close)

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def rid(self):
        self.n += 1
        return f"req-{self.n}"

    def call(self, method, req, who=ME):
        return self.s.call(who, method, {"request_id": self.rid(), **req} if method != "read" else req)

    def refused(self, code, method, req, who=ME):
        with self.assertRaises(RPCError) as cm:
            self.call(method, req, who)
        self.assertEqual(cm.exception.code, code, cm.exception)

    def register(self, who=ME, **kw):
        out = self.call("register_run", {"agent": {"name": "a"}, **kw}, who)
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def ev(self, run, seq, **kw):
        return {**run, "stream": "s", "client_seq": seq, **kw}

    def decide(self, run, seq, tcid="tc-1", tool="read_file"):
        return self.call("decide", self.ev(run, seq, tool_call_id=tcid, tool=tool, args_source="parsed", args={}))

    def events(self, run_id):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run_id]


class TestSignerOnlyRecords(Lifecycle):
    def test_client_forged_gap_or_tamper_is_refused_and_summarised(self):
        run = self.register()
        forged = [("state_write", self.ev(run, 0, key="k", value_digest="sha256:" + "0" * 64, type="capture.gap")),
                  ("model_event", self.ev(run, 0, provider="p", model="m", phase="request", source="signer")),
                  ("complete", self.ev(run, 0, tool_call_id="tc-1", status="ok",
                                       data={"kind": "rollback", "path": "records"}))]
        for method, req in forged:
            self.refused("invalid_request", method, req)
        with self.assertRaises(RPCError) as cm:
            self.s.handle_frame(ME, {"method": "capture.gap", "request_id": "x", "kind": "client_counter_gap"})
        self.assertEqual(cm.exception.code, "invalid_request")
        self.s.flush_refusals()
        self.close()
        rs = [r["event"] for r in records(self.dir)]
        sums = [e["data"] for e in rs if e["type"] == "refusal.summary"]
        self.assertEqual([(d["code"], d["count"], d["identity"]) for d in sums], [("invalid_request", 4, f"uid:{ME.subject}")])
        self.assertEqual([e for e in rs if e["run_id"] == run["run_id"]][1:], [])   # nothing past run.registered
        self.assertTrue(all(e["source"] == "signer" for e in rs if e["type"] in ("capture.gap", "trace.tamper")))

    def test_client_isolation_and_fail_mode_claims_have_no_effect(self):
        for claim in ({"signer_isolation": "separate-user"}, {"fail_mode": "open"}, {"fail_modes": {"default": "open"}}):
            self.refused("invalid_request", "register_run", {"agent": {"name": "a"}, **claim}, OTHER)
        out = self.call("register_run", {"agent": {"name": "a"}}, OTHER)
        self.assertEqual(out["fail_modes"], FAIL_MODES)
        reg = self.events(out["run_id"])[0]
        self.assertEqual((reg["data"]["signer_isolation"], reg["data"]["fail_modes"]), ("separate-user", FAIL_MODES))

    def test_tenant_is_attested_unless_a_configured_app_asserts_it(self):
        self.refused("forbidden", "register_run", {"agent": {"name": "a"}, "tenant": "acme"}, OTHER)
        asserted = self.call("register_run", {"agent": {"name": "a"}, "tenant": "acme"})
        mapped = self.call("register_run", {"agent": {"name": "a"}}, ANALYZER_BETA)
        self.assertEqual((asserted["tenant"], asserted["tenant_attested"]), ("acme", False))
        self.assertEqual((mapped["tenant"], mapped["tenant_attested"]), ("beta", True))

    def test_migrated_only_from_a_configured_identity(self):
        self.refused("forbidden", "register_run", {"agent": {"name": "a"}, "source": "migrated"}, OTHER)
        run = self.register(MIGRATOR, source="migrated")
        self.call("state_write", self.ev(run, 0, key="k", value_digest="sha256:" + "0" * 64), MIGRATOR)
        self.assertEqual([e["source"] for e in self.events(run["run_id"])], ["migrated", "migrated"])

    def test_findings_only_from_a_configured_analyzer_bound_to_a_run_of_its_tenant(self):
        mine = self.register()
        self.refused("forbidden", "register_run", {"agent": {"name": "a"}, "analyzes": mine["run_id"]}, OTHER)
        self.refused("run_token_invalid", "state_write", self.ev(mine, 0, key="k", value_digest="sha256:" + "0" * 64),
                     OTHER)
        self.refused("unknown_run", "register_run", {"agent": {"name": "a"}, "analyzes": "no-such-run"}, ANALYZER)
        self.refused("unknown_run", "register_run", {"agent": {"name": "a"}, "analyzes": mine["run_id"]}, ANALYZER_BETA)
        findings = self.register(ANALYZER, analyzes=mine["run_id"])
        reg = self.events(findings["run_id"])[0]
        self.assertEqual(reg["data"]["analyzes"], mine["run_id"])
        self.assertEqual(len(self.events(mine["run_id"])), 1)   # nothing was written into the analysed run


class TestLifecycle(Lifecycle):
    def test_close_grace_window_and_final(self):
        run = self.register()
        self.decide(run, 0)
        self.call("close_run", run)
        self.refused("run_closed", "decide", self.ev(run, 1, tool_call_id="tc-2", tool="t", args_source="parsed",
                                                     args={}))
        self.refused("run_closed", "close_run", run)
        self.call("complete", self.ev(run, 2, tool_call_id="tc-1", status="ok"))   # a late record
        self.s.sweep(time.monotonic() + 30)
        self.call("model_event", self.ev(run, 3, provider="p", model="m", phase="response"))
        self.s.sweep(time.monotonic() + 61)
        self.refused("run_closed", "complete", self.ev(run, 4, tool_call_id="tc-1", status="ok"))
        es = self.events(run["run_id"])
        self.assertEqual([e["type"] for e in es], ["run.registered", "policy.decision", "run.closing", "capture.gap",
                                                    "tool.result", "model.exchange", "run.final"])
        final = es[-1]
        self.assertEqual(final["source"], "signer")
        rs = {r["event"]["run_seq"]: r["hash"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]}
        self.assertEqual(final["data"], {"head_run_seq": 5, "head_hash": rs[5]})

    def test_idle_close_pauses_while_an_approval_is_pending(self):
        t0 = time.monotonic()
        idle, waiting = self.register(), self.register()
        self.decide(waiting, 0, tool="pay")
        aid = self.call("approval_request", {**waiting, "tool_call_id": "tc-1"})["approval_id"]
        self.s.sweep(t0 + 61)
        self.call("approval_decide", {"approval_id": aid, "decision": "approve"}, OTHER)
        self.s.sweep(t0 + 122)
        self.s.sweep(t0 + 300)
        closing = [e for e in self.events(idle["run_id"]) if e["type"] == "run.closing"]
        self.assertEqual([(e["data"]["reason"], e["source"]) for e in closing], [("idle_timeout", "signer")])
        types = [e["type"] for e in self.events(waiting["run_id"])]
        self.assertEqual(types[-3:], ["approval", "run.closing", "run.final"])   # closed only after the approval
        self.assertEqual(self.events(idle["run_id"])[-1]["type"], "run.final")

    def test_registry_log_proves_registration_and_final(self):
        run = self.register(tenant="acme")
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        leaf_of = self.s.log.leaf
        self.close()
        rs = [r for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]]
        lifecycle = [rs[0], rs[-1]]
        self.assertEqual([r["event"]["type"] for r in lifecycle], ["run.registered", "run.final"])

        def prove(store):
            leaves = list(store.registry_iter("acme"))
            size, root = store.tail_state()["registry"]["acme"]
            for typ, r in zip((1, 2), lifecycle):
                leaf = leaf_of(r)
                self.assertEqual((leaf[0], len(leaf), leaf[-32:].hex()), (typ, 89, r["hash"][7:]))
                i = leaves.index(leaf)
                proof = merkle.inclusion_proof(i, [merkle.leaf_hash(x) for x in leaves])
                self.assertTrue(merkle.verify_inclusion(i, size, merkle.leaf_hash(leaf), proof, root))
            return leaves

        store = FileStorage(os.path.join(self.dir, "store"))
        before = prove(store)
        store.close()
        # leaves the store lost (a crash between the record and its leaf) are appended again on startup
        os.remove(os.path.join(self.dir, "store", "registry.jsonl"))
        svc.SignerService(self.dir).close()
        store = FileStorage(os.path.join(self.dir, "store"))
        self.addCleanup(store.close)
        self.assertEqual(prove(store), before)


class TestBundle(Lifecycle):
    def test_closed_run_verifies_and_open_run_verifies_to_head(self):
        self.s.idle_s = 3600
        closed, open_ = self.register(tenant="acme"), self.register(tenant="acme")
        for run in (closed, open_):
            self.decide(run, 0)
        self.call("close_run", closed)
        self.s.sweep(time.monotonic() + 61)
        self.close()
        store = FileStorage(os.path.join(self.dir, "store"))
        self.addCleanup(store.close)
        size = store.tree.size
        text = checkpoint.body(ORIGIN, size, store.tree.root_at(size))
        note = text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET)
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        verdicts = []
        for run in (closed, open_):
            out = os.path.join(self.dir, f"{run['run_id']}.tkb")
            export(store, "acme", run["run_id"], note, out)
            rep, code = v2.verify(out, trust)
            self.assertEqual(code, 0, rep.checks)
            verdicts.append(rep.integrity)
        self.assertEqual(verdicts, ["VERIFIED", "VERIFIED TO HEAD 1 (open)"])


if __name__ == "__main__":
    unittest.main()
