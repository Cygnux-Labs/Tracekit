"""Run capability tokens (tracekit/signer/runtoken.py) and quotas (tracekit/signer/quotas.py)."""
import unittest

from tracekit.identity.base import CallerIdentity
from tracekit.signer import rpc_schema
from tracekit.signer.quotas import Limits, Quotas, summarise
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.runtoken import RunTokens, _b64, _unb64

ALICE = CallerIdentity("uid", "1000", True)
BOB = CallerIdentity("uid", "1001", True)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class RunToken(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.tokens = RunTokens(b"k" * 32, ttl_s=60, clock=self.clock)
        self.tok = self.tokens.issue("acme", "run-1", ALICE)

    def refused(self, token, tenant="acme", run_id="run-1", identity=ALICE):
        with self.assertRaises(RPCError) as cm:
            self.tokens.verify(token, tenant, run_id, identity)
        self.assertEqual(cm.exception.code, "run_token_invalid")

    def test_valid(self):
        self.tokens.verify(self.tok, "acme", "run-1", ALICE)
        self.assertEqual(rpc_schema.validate(rpc_schema.TOKEN, self.tokens.issue("t" * 128, "r" * 128, CallerIdentity(
            "token", "s" * 256, True))), [])

    def test_another_run_tenant_or_identity(self):
        self.refused(self.tok, run_id="run-2")
        self.refused(self.tok, tenant="other")
        self.refused(self.tok, identity=BOB)
        self.refused(self.tok, identity=CallerIdentity("token", "1000", True))   # same subject, other scheme

    def test_expired(self):
        self.clock.t += 60
        self.refused(self.tok)

    def test_tampered_or_malformed(self):
        payload, mac = self.tok.split(".")
        forged = _unb64(payload).replace(b"run-1", b"run-2")
        self.refused(_b64(forged) + "." + mac, run_id="run-2")
        self.refused(payload + "." + _b64(b"\0" * 32))
        self.refused(RunTokens(b"x" * 32, clock=self.clock).issue("acme", "run-1", ALICE))
        for bad in ("", "abc", "a.b.c", "é.é", None):
            self.refused(bad)


class RateLimit(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.q = Quotas(Limits(events_per_s=10, burst=3, buckets=2), clock=self.clock)

    def test_bucket_refuses_then_refills(self):
        for _ in range(3):
            self.q.take_event(ALICE, "acme")
        with self.assertRaises(RPCError) as cm:
            self.q.take_event(ALICE, "acme")
        self.assertEqual((cm.exception.code, cm.exception.retry_after_ms), ("quota_exceeded", 100))
        self.q.take_event(ALICE, "other")   # another tenant has its own bucket
        self.q.take_event(BOB, "acme")
        self.clock.t += 0.1
        self.q.take_event(ALICE, "acme")

    def test_state_is_fixed_size_lru(self):
        for _ in range(3):
            self.q.take_event(ALICE, "acme")
        self.q.take_event(BOB, "acme")
        with self.assertRaises(RPCError):   # a refusal counts as a use
            self.q.take_event(ALICE, "acme")
        self.q.take_event(ALICE, "other")   # evicts BOB, the least recently used
        self.assertEqual(list(self.q._buckets), [("uid", "1000", "acme"), ("uid", "1000", "other")])
        with self.assertRaises(RPCError):
            self.q.take_event(ALICE, "acme")


class Counts(unittest.TestCase):
    def test_counts_and_strings(self):
        q = Quotas(Limits(open_runs=2, pending_approvals=1, streams_per_run=4, max_string=8))
        q.check_count("open_runs", 1)
        for name, n in (("open_runs", 2), ("pending_approvals", 1), ("streams_per_run", 4)):
            with self.assertRaises(RPCError) as cm:
                q.check_count(name, n)
            self.assertEqual(cm.exception.code, "quota_exceeded")
            self.assertEqual(cm.exception.retry_after_ms, 1000)
        q.check_strings({"a": ["12345678"]})
        for bad in ({"a": [{"b": "123456789"}]}, {"123456789": 1}):
            with self.assertRaises(RPCError) as cm:
                q.check_strings(bad)
            self.assertEqual(cm.exception.code, "quota_exceeded")


class Summary(unittest.TestCase):
    def test_one_record_per_window_identity_tenant_and_code(self):
        refusals = [(t, ALICE, "acme", "quota_exceeded") for t in (100.0, 101.5, 109.9)]
        refusals += [(110.0, ALICE, "acme", "quota_exceeded"), (102.0, BOB, "acme", "quota_exceeded"),
                     (103.0, ALICE, None, "quota_exceeded"), (104.0, ALICE, "acme", "unauthenticated")]
        out = summarise(refusals, window_s=10)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0], {"type": "refusal.summary", "window_start": 100, "window_s": 10,
                                  "identity": {"scheme": "uid", "subject": "1000"}, "tenant": "acme",
                                  "code": "quota_exceeded", "count": 3, "first_ts": 100.0, "last_ts": 109.9})
        self.assertEqual([s["count"] for s in out[1:]], [1, 1, 1, 1])
        self.assertEqual(summarise([], 10), [])
