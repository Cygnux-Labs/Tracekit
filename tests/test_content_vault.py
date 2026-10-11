"""The signer's content vault (tracekit/signer/service.py, docs/privacy.md): off stores nothing; on, each record's
redacted content round-trips, encrypted and bound to its record, opens its commitment with the record's salt, and
every read and erasure is a signed record; retention, too_large, the content_read grant, the gateway's body and
doctor's D-CONTENT-VAULT."""
import hashlib
import hmac
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from tracekit import doctor, gateway
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import canonical, event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

SECRET = "sk-ant-" + "Zq8" * 10   # a redaction fixture
ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
READER = CallerIdentity("token", "investigator", True)
DAY = 86400


class Vault(unittest.TestCase):
    content = {"retain": True}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.open()

    def open(self, **kw):
        self.s = svc.SignerService(self.dir, content=kw.pop("content", self.content), authorize={
            "token:investigator": ["content_read", "content_erase"]}, **kw)
        self.addCleanup(self.s.close)
        self.run = self.s.register_run({"request_id": f"reg-{id(self.s)}", "agent": {"name": "a"}})
        self.n = 0

    def req(self, **kw):
        self.n += 1
        return {"request_id": f"rq-{id(self.s)}-{self.n}", "run_id": self.run["run_id"],
                "run_token": self.run["run_token"], "stream": "s", "client_seq": self.n, **kw}

    def tool(self, args, result, tool="Bash", tcid="t1"):
        d = self.s.decide(self.req(tool_call_id=tcid, tool=tool, args_source="parsed", args=args))
        c = self.s.complete(self.req(tool_call_id=tcid, decision_id=d["decision_id"], status="ok", result=result,
                                     args_digest=event_hash({"tool": tool, "args": args})))
        return d["run_seq"], c["run_seq"]

    def get(self, *seqs, who=READER, purpose="case-1"):
        return self.s.call(who, "content_get", {"run_id": self.run["run_id"], "seqs": list(seqs),
                                                "purpose": purpose})["items"]

    def records(self, run_id=None, tenant=None):
        return [r["event"] for r in self.s.log.storage.iter_run(tenant or self.run["tenant"],
                                                                 run_id or self.run["run_id"])]

    def signer_records(self):
        return self.records("tracekit/signer")

    def opens(self, item, digest, e):
        commitment = svc._committed(e)
        return commitment == "hmac-sha256:" + hmac.new(bytes.fromhex(item["salt"]), digest.encode(), "sha256").hexdigest()


class Off(Vault):
    content = None

    def test_off_stores_nothing_and_answers_nothing(self):
        self.tool({"cmd": "ls"}, {"out": "hi"})
        self.s.model_event(self.req(provider="p", model="m", phase="request", body={"messages": ["hi"]}))
        self.assertNotIn("content", self.s.status({}))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys", "content.key")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "store", "content")))
        with self.assertRaises(RPCError) as cm:
            self.get(0)
        self.assertEqual(cm.exception.code, "invalid_request")
        self.assertIn("content: {retain: true}", cm.exception.message)

    def test_config_is_validated(self):
        for bad in ({"retain": "yes"}, {"retention_days": 0}, {"max_record_bytes": 1.5}, {"keep": True}, "on"):
            with self.subTest(bad), self.assertRaises(ValueError):
                svc.SignerService(self.dir, content=bad)


class On(Vault):
    def test_each_record_round_trips_and_opens_its_commitment_with_the_salt(self):
        dseq, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        oseq = self.s.observe(self.req(source="inbox:1", trust="untrusted", value={"mail": "pay now"}))["run_seq"]
        mseq = self.s.model_event(self.req(provider="p", model="m", phase="request",
                                           body={"messages": [{"role": "user", "content": "hi"}]}))["run_seq"]
        items = self.get(0, dseq, cseq, oseq, mseq)
        self.assertEqual(items[0], {"seq": 0, "state": "not_retained"})   # run.registered commits to nothing
        events = {e["run_seq"]: e for e in self.records()}
        want = {dseq: {"cmd": "ls"}, cseq: {"result": {"out": "hi"}}, oseq: {"mail": "pay now"},
                mseq: {"messages": [{"role": "user", "content": "hi"}]}}
        for item in items[1:]:
            with self.subTest(events[item["seq"]]["type"]):
                self.assertEqual(item["content"], want[item["seq"]])
                self.assertNotIn("redacted", item)
                e = events[item["seq"]]
                digest = event_hash({"tool": "Bash", "args": item["content"]}) if e["type"] == "policy.decision" \
                    else "sha256:" + hashlib.sha256(canonical(item["content"])).hexdigest()
                self.assertTrue(self.opens(item, digest, e))
                self.assertEqual(item["salt"], svc.reveal(self.dir, e["seq"])["salt"])

    def test_nothing_unredacted_is_written(self):
        dseq, cseq = self.tool({"cmd": f"echo {SECRET}"}, {"out": f"key {SECRET}"})
        mseq = self.s.model_event(self.req(provider="p", model="m", phase="response", body={"text": SECRET}))["run_seq"]
        d, c, m = self.get(dseq, cseq, mseq)
        self.assertEqual(d["redacted"], True)   # the decision was on the real arguments: these no longer open them
        self.assertNotIn(SECRET, json.dumps([d, c, m]))
        self.assertNotIn("redacted", c)
        e = next(e for e in self.records() if e["run_seq"] == mseq)
        self.assertTrue(self.opens(m, "sha256:" + hashlib.sha256(canonical(m["content"])).hexdigest(), e))
        self.s.close()
        for root, _, names in os.walk(os.path.join(self.dir, "store", "content")):
            for n in names:
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(b"Zq8Zq8", f.read())

    def test_content_survives_a_restart(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        run = self.run
        self.s.close()
        self.open()
        self.run = run
        self.assertEqual(self.get(cseq)[0]["content"], {"result": {"out": "hi"}})

    def test_a_blob_moved_to_another_record_does_not_decrypt(self):
        dseq, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        s, log, key = self.s.log.storage, self.s.log.log_id, (self.run["tenant"], self.run["run_id"])
        s.content_put(log, *key, cseq, s.content_get(log, *key, dseq))
        with self.assertRaises(RPCError) as cm:
            self.get(cseq)
        self.assertEqual(cm.exception.code, "unavailable")
        self.assertIn("does not open against its record", cm.exception.message)
        self.assertEqual([e["type"] for e in self.signer_records()], [])   # no content returned, no access recorded

    def test_reading_needs_the_content_read_grant(self):
        self.tool({"cmd": "ls"}, {"out": "hi"})
        for who in (ME, CallerIdentity("token", "agent", True)):   # the run's own agent (a uid) has every method but it
            with self.subTest(who.subject), self.assertRaises(RPCError) as cm:
                self.get(1, who=who)
            self.assertEqual(cm.exception.code, "forbidden")
            self.assertIn("content_read", cm.exception.message)
        with self.assertRaises(RPCError) as cm:
            self.s.call(ME, "content_erase", {"request_id": "e", "run_id": self.run["run_id"]})
        self.assertEqual(cm.exception.code, "forbidden")

    def test_each_access_is_a_signed_record_in_the_tenant(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        self.get(cseq, purpose="case-7")
        self.get(cseq, 99, purpose="case-8")
        accessed = [e for e in self.signer_records() if e["type"] == "content.accessed"]
        self.assertEqual([e["data"] for e in accessed], [
            {"principal": "token:investigator", "run_id": self.run["run_id"], "seqs": [cseq], "purpose": "case-7"},
            {"principal": "token:investigator", "run_id": self.run["run_id"], "seqs": [cseq, 99], "purpose": "case-8"}])
        self.assertEqual({(e["tenant"], e["source"]) for e in accessed}, {(self.run["tenant"], "signer")})
        self.assertNotIn("hi", json.dumps(accessed))
        self.assertNotIn("tracekit/signer", [k[1] for k in self.s.log.live])   # never swept, never closed

    def test_erasure(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        before = self.records()
        out = self.s.call(READER, "content_erase", {"request_id": "e1", "run_id": self.run["run_id"], "reason": "GDPR"})
        self.assertEqual(self.get(cseq), [{"seq": cseq, "state": "erased"}])
        erased = [e for e in self.signer_records() if e["type"] == "content.erased"]
        self.assertEqual([(e["run_seq"], e["data"]) for e in erased],
                         [(out["run_seq"], {"run_id": self.run["run_id"], "reason": "GDPR", "by": "token:investigator"})])
        self.assertEqual(self.records(), before)   # the run's records and commitments are untouched
        self.tool({"cmd": "pwd"}, {"out": "/"}, tcid="t2")   # nothing more is kept for an erased run
        self.assertEqual(self.get(cseq + 2)[0]["state"], "erased")
        self.assertEqual(os.listdir(os.path.dirname(self.s.log.storage._vault(self.s.log.log_id, self.run["tenant"],
                                                                              self.run["run_id"], "key"))), ["key"])

    def test_retention(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "hi"})
        self.s.expire_content(now=self.s.log.storage.content_runs()[0][3] + 29 * DAY)
        self.assertIn("content", self.get(cseq)[0])
        self.s.expire_content(now=self.s.log.storage.content_runs()[0][3] + 31 * DAY)
        self.assertEqual(self.get(cseq), [{"seq": cseq, "state": "erased"}])
        [e] = [e for e in self.signer_records() if e["type"] == "content.erased"]
        self.assertEqual(e["data"], {"run_id": self.run["run_id"], "reason": "retention: kept 30 days", "by": "signer"})

    def test_content_over_max_record_bytes_is_not_kept(self):
        self.s.close()
        self.open(content={"retain": True, "max_record_bytes": 64})
        small, big = self.tool({"cmd": "ls"}, {"out": "x" * 100})
        self.assertEqual(self.get(big), [{"seq": big, "state": "too_large"}])
        self.assertIn("content", self.get(small)[0])
        self.assertEqual(self.s.status({})["content"], {"max_record_bytes": 64})

    def test_an_answer_too_large_for_one_frame_is_refused_and_not_recorded(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "y" * 1000})
        with mock.patch.object(svc, "MAX_LINE", 4096 + 500), self.assertRaises(RPCError) as cm:
            self.get(cseq)
        self.assertEqual(cm.exception.code, "quota_exceeded")
        self.assertIn("ask for fewer seqs", cm.exception.message)
        self.assertEqual(self.signer_records(), [])

    def test_bundles_hold_no_content_and_still_verify(self):
        _, cseq = self.tool({"cmd": "ls"}, {"out": "hidden-result"})
        self.get(cseq)
        self.s.call(READER, "content_erase", {"request_id": "e1", "run_id": self.run["run_id"]})
        self.s.close()
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, checkpoint.ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        store = FileStorage(os.path.join(self.dir, "store"))
        try:
            text = checkpoint.body(ORIGIN, store.tree.size, store.tree.root())
            note = text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET)
            for run_id, need in ((self.run["run_id"], "1.0.0"), ("tracekit/signer", "1.1.0")):
                out = os.path.join(self.dir, "b.tkb")
                export(store, self.run["tenant"], run_id, note, out)
                rep, code = v2.verify(out, trust)
                with self.subTest(run_id):
                    self.assertEqual(code, 0, rep.checks)
                    self.assertEqual(json.loads(v2.read_zip(out)["manifest.json"])["verifier_min_version"], need)
                    self.assertNotIn(b"hidden-result", b"".join(v2.read_zip(out).values()))
            report = io.StringIO()
            v2.print_report(rep, code, report)
            self.assertIn("content vault — 1 access(es), 1 erasure(s)", report.getvalue())
        finally:
            store.close()


class GatewayBody(unittest.TestCase):
    def gw(self, status):
        client = mock.Mock()
        client.status.side_effect = status if isinstance(status, Exception) else lambda req: status
        return gateway.Gateway("https://up.example", "k", client=client), client

    def test_a_body_only_when_the_signer_keeps_content(self):
        for status, want in (({"rpc_version": 14}, {}), ({"content": {"max_record_bytes": 100}}, {"body": {"a": 1}}),
                             (RPCError("forbidden", "not granted status"), {})):
            with self.subTest(status):
                gw, client = self.gw(status)
                self.assertEqual(gw.body({"a": 1}, 10), want)
                self.assertEqual(gw.body({"a": 1}, 10), want)
                self.assertEqual(client.status.call_count, 1)   # asked once
        gw, _ = self.gw({"content": {"max_record_bytes": 100}})
        self.assertEqual(gw.body({"a": 1}, 101), {})   # over the vault's limit: not sent
        gw, _ = self.gw({"content": {"max_record_bytes": 1 << 30}})
        self.assertEqual(gw.body({}, gateway.MAX_LINE // 2 + 1), {})   # or over half a frame

    def test_an_unreachable_signer_is_asked_again(self):
        gw, client = self.gw(gateway.SignerUnavailable("down"))
        self.assertEqual(gw.body({}, 1), {})
        client.status.side_effect = lambda req: {"content": {"max_record_bytes": 10}}
        self.assertEqual(gw.body({}, 1), {"body": {}})


class Doctor(unittest.TestCase):
    def check(self, cfg):
        return next(r for r in doctor.v2_checks(cfg, "dev", settings="none") if r["id"] == "D-CONTENT-VAULT")

    def test_doctor_reports_the_vault(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.assertEqual((self.check({"data_dir": d})["status"], self.check({"data_dir": d})["detail"]),
                         (doctor.OK, "off: the signer keeps commitments only, no content"))
        on = {"data_dir": d, "content": {"retain": True, "retention_days": 7}}
        self.assertEqual(self.check(on)["status"], doctor.WARN)   # no key yet
        svc.SignerService(d, content=on["content"]).close()
        r = self.check(on)
        self.assertEqual(r["status"], doctor.OK, r)
        self.assertIn("on: keeps redacted content 7 days", r["detail"])
        if os.name != "nt":
            os.chmod(os.path.join(d, "keys", "content.key"), 0o644)
            self.assertEqual(self.check(on)["status"], doctor.FAIL)


if __name__ == "__main__":
    unittest.main()
