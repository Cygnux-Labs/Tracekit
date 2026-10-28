"""Proof-carrying messages, the format and offline core (tracekit.pcm): schema documents and args, the exhaustive
caveat narrowing, satisfies, the grant chain, the signature and its domain separation, replay and the verdicts.
Messages and grants are signed here with a throwaway log key, as the signer will sign them."""
import base64
import datetime
import itertools
import json
import operator
import os
import secrets
import sys
import unittest

from tracekit import pcm
from tracekit.format import checkpoint, sigmsg, slh_dsa
from tracekit.format.canon import event_hash, loads_strict
from tracekit.signer import logkey, rpc_schema

KEY = logkey.FileKey(os.urandom(32))
VKEY = checkpoint.vkey("pcm-test/log", checkpoint.ED25519, KEY.public)
OTHER = logkey.FileKey(os.urandom(32))
OTHER_VKEY = checkpoint.vkey("pcm-other/log", checkpoint.ED25519, OTHER.public)
TRUST = {"logs": [VKEY]}
A, B, C, ALICE = "uid:990101", "uid:990102", "uid:990103", "uid:990001"
T0 = 1_800_000_000.0
DOC = {"pcm_schema": 0, "name": "refund.request",
       "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
                  "order": {"type": "int", "min": 1, "max": 999999999},
                  "note": {"type": "string", "max": 500, "optional": True},
                  "kind": {"type": "enum", "values": ["full", "partial", "store"], "optional": True},
                  "ref": {"type": "id", "pattern": "[A-Z]{2}-[0-9]+", "optional": True},
                  "rush": {"type": "bool", "optional": True},
                  "due": {"type": "time", "optional": True}}}
REF = pcm.schema_ref(DOC)
ARGS = {"amount": 12000, "order": 81}
OPS = {"==": operator.eq, "<=": operator.le, ">=": operator.ge, "<": operator.lt, ">": operator.gt}


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cv(field, op, value):
    return {"field": field, "op": op, "value": value}


def message(args=None, ts=T0, frm=A, to=B, ref=REF, key=KEY, vkey=VKEY, **kw):
    body = {"pcm": 0, "id": secrets.token_hex(16), "ts": iso(ts), "nonce": secrets.token_hex(16),
            "from": {"agent": frm, "run": "run-a", "tenant": "default"}, "to": {"agent": to},
            "intent": {"type": ref, "args": dict(ARGS) if args is None else args}, **kw}
    return pcm.sign(key, vkey, "pcm", body)


def grant(caveats=(), subject=A, issuer=None, parent=None, expires=T0 + 3600, intent=REF, key=KEY, vkey=VKEY,
          delegable=True):
    body = {"pcm_grant": 0, "ts": iso(T0 - 60), "subject": subject, "intent": intent, "caveats": list(caveats),
            "issuer": issuer or {"kind": "person", "id": ALICE, "person": "alice", "run": "run-r", "tenant": "default",
                                 "approval_id": "apr-1"},
            "expires_at": iso(expires), "delegable": delegable, "parent": parent}
    return pcm.sign(key, vkey, "pcm-grant", body)


def child(parent, caveats, subject=A, **kw):
    return grant(caveats, subject=subject, issuer={"kind": "agent", "id": parent["subject"], "run": "run-x", "tenant": "default"},
                 parent=event_hash(parent), **kw)


def holds(c, v):
    """The caveat's meaning, written independently of tracekit.pcm."""
    return v in c["value"] if c["op"] == "in" else OPS[c["op"]](v, c["value"])


class Schema(unittest.TestCase):
    def test_meta_check(self):
        self.assertEqual(pcm.check_schema(DOC), [])
        f = DOC["fields"]
        bad = {"unknown type": {**f, "x": {"type": "float"}},
               "missing param": {**f, "x": {"type": "string"}},
               "extra param": {**f, "x": {"type": "int", "min": 0, "max": 1, "currency": "USD"}},
               "bad field name": {**f, "Amount": {"type": "bool"}},
               "min above max": {**f, "x": {"type": "int", "min": 2, "max": 1}},
               "repeated values": {**f, "x": {"type": "enum", "values": ["a", "a"]}},
               "bad pattern": {**f, "x": {"type": "id", "pattern": "("}},
               "lower-case currency": {**f, "x": {"type": "money", "currency": "usd", "max": 1}}}
        for why, fields in bad.items():
            self.assertTrue(pcm.check_schema({**DOC, "fields": fields}), why)
        self.assertTrue(pcm.check_schema({**DOC, "name": "Refund"}))
        self.assertTrue(pcm.check_schema({**DOC, "extra": 1}))
        self.assertTrue(pcm.check_schema({**DOC, "claims": ["approved_by", "approved_by"]}))
        self.assertTrue(pcm.check_schema({**DOC, "claims": ["looked_fine"]}))

    def test_the_tool_the_intent_stands_for(self):
        """`tool` (PCM 0.1 5.1) is optional, a string of 1 to 256, and part of the content address."""
        self.assertEqual(pcm.check_schema({**DOC, "tool": "refund"}), [])
        for bad in ("", "x" * 257, 1, None, ["refund"]):
            self.assertTrue(pcm.check_schema({**DOC, "tool": bad}), bad)
        self.assertNotEqual(pcm.schema_ref({**DOC, "tool": "refund"}), REF)

    def test_version_is_integer_zero(self):
        for v in (False, 0.0, "0", 1):
            self.assertTrue(pcm.check_schema({**DOC, "pcm_schema": v}), v)

    def test_args(self):
        ok = lambda **kw: pcm.check_args(DOC, {**ARGS, **kw})   # noqa: E731
        self.assertEqual(ok(), [])
        self.assertEqual(ok(note="n", kind="full", ref="AB-12", rush=False, due="2026-10-27T18:00:00.000000Z"), [])
        self.assertIn("args.extra: not in the schema", ok(extra=1))
        self.assertIn("args.order: missing", pcm.check_args(DOC, {"amount": 1}))
        self.assertEqual(pcm.check_args(DOC, []), ["args: not an object"])
        bad = {"order": [True, 120.0, "120", loads_strict("1e2"), 0, 10 ** 9],
               "note": ["x" * 501, 5], "ref": ["XAB-1", "AB-1x", "AB-"], "kind": ["other", ["full"]],
               "amount": [-1, 1000001, 1.5, True], "rush": [0, "true"],
               "due": ["2026-10-27T18:00:00Z", "2026-10-27T18:00:00.000000Z\n", "２026-10-27T18:00:00.000000Z"]}
        for k, values in bad.items():
            for v in values:
                self.assertTrue(ok(**{k: v}), (k, v))

    def test_unknown_or_edited_schema_is_rejected(self):
        self.assertEqual(pcm.verify(message(), TRUST, [DOC])["verdict"], "accept")
        changed = REF[:-1] + ("0" if REF[-1] != "0" else "1")
        out = pcm.verify(message(ref=changed), TRUST, [DOC])
        self.assertEqual((out["verdict"], out["schema"]["errors"]), ("reject", [f"unknown schema {changed}"]))
        edited = {**DOC, "fields": {**DOC["fields"], "amount": {"type": "money", "currency": "USD", "max": 10 ** 9}}}
        self.assertEqual(pcm.verify(message(), TRUST, [edited])["verdict"], "reject")
        with self.assertRaises(ValueError):
            pcm.verify(message(), TRUST, [{**DOC, "name": "Bad"}])


class Envelope(unittest.TestCase):
    def test_version_fields_are_integer_zero(self):
        for v in (False, 0.0):
            m = message()
            m["pcm"] = v
            self.assertTrue(rpc_schema.validate(rpc_schema.PCM_MESSAGE, m), v)
            out = pcm.verify(m, TRUST, [DOC])
            self.assertEqual((out["verdict"], out["signature"]), ("reject", None))
            g = grant()
            g["pcm_grant"] = v
            self.assertTrue(rpc_schema.validate(rpc_schema.PCM_GRANT, g), v)
        self.assertEqual(rpc_schema.validate(rpc_schema.PCM_MESSAGE, message()), [])
        self.assertEqual(rpc_schema.validate(rpc_schema.PCM_GRANT, grant()), [])

    def test_patterns_match_the_whole_value(self):
        for junk in ("!" + REF, REF + "!", REF + "\n", " " + REF):
            self.assertTrue(rpc_schema.validate(rpc_schema.SCHEMA_REF, junk), junk)
        self.assertEqual(rpc_schema.validate(rpc_schema.SCHEMA_REF, REF), [])
        for junk in ("!amount", "amount!", "amount\n"):
            self.assertTrue(rpc_schema.validate(rpc_schema._CAVEAT, cv(junk, "==", 1)), junk)
        nonce = secrets.token_hex(16)
        for junk in ("x" + nonce[1:], nonce[1:] + "x", nonce[1:] + "\n"):
            self.assertTrue(rpc_schema.validate(rpc_schema.HEX16, junk), junk)

    def test_closed_and_bounded(self):
        for extra in ({"t": "tracekit.pcm.v2"}, {"x": 1}):
            m = message()
            m.update(extra)
            self.assertEqual(pcm.verify(m, TRUST, [DOC])["verdict"], "reject")
        g = grant()
        out = pcm.verify(message(grants=[g] * 9), TRUST, [DOC])
        self.assertEqual((out["verdict"], out["signature"]), ("reject", None))

    def test_a_value_deeper_than_the_recursion_limit(self):
        deep = []
        for _ in range(sys.getrecursionlimit() + 100):
            deep = [deep]
        for m in (dict(message(), claims=[{"type": deep, "args": {}}]),
                  dict(message(), grants=[dict(grant(), caveats=[cv("amount", deep, 1)])])):
            out = pcm.verify(m, TRUST, [DOC])
            self.assertEqual((out["verdict"], out["signature"]), ("reject", None))
            self.assertIn("a list not in", out["reasons"][0])


class Narrowing(unittest.TestCase):
    def test_int_pairs_exhaustive(self):
        domain = range(-5, 16)
        for (pop, pv), (cop, cvalue) in itertools.product(itertools.product(OPS, (2, 5, 8)), repeat=2):
            p, c = cv("n", pop, pv), cv("n", cop, cvalue)
            subset = all(holds(p, v) for v in domain if holds(c, v))
            self.assertEqual(pcm.narrows([p], [c]) == [], subset, (p, c))

    def test_enum_pairs_exhaustive(self):
        sets = [list(s) for n in (1, 2, 3) for s in itertools.combinations("abc", n)]
        forms = [cv("k", "in", s) for s in sets] + [cv("k", "==", x) for x in "abc"]
        for p, c in itertools.product(forms, repeat=2):
            subset = all(holds(p, v) for v in "abc" if holds(c, v))
            self.assertEqual(pcm.narrows([p], [c]) == [], subset, (p, c))

    def test_mixed_is_sound(self):
        cands = [cv("amount", "<=", 200), cv("amount", "<=", 150), cv("amount", "<", 150), cv("amount", ">=", 100),
                 cv("amount", "==", 120), cv("order", "==", 81), cv("order", "<=", 81), cv("order", ">=", 81),
                 cv("kind", "==", "a"), cv("kind", "in", ["a", "b"]), cv("kind", "in", ["a", "b", "c"])]
        lists = [list(x) for n in (0, 1, 2) for x in itertools.combinations(cands, n)]
        grid = [dict(amount=a, order=o, kind=k) for a in (99, 100, 120, 149, 150, 151, 200, 201)
                for o in (80, 81, 82) for k in "abc"]
        narrowing = 0
        for parent, kid in itertools.product(lists, repeat=2):
            if pcm.narrows(parent, kid) == []:
                narrowing += 1
                for pt in grid:
                    if all(holds(c, pt[c["field"]]) for c in kid):
                        self.assertTrue(all(holds(c, pt[c["field"]]) for c in parent), (parent, kid, pt))
        self.assertGreater(narrowing, len(lists))   # more than the identities alone

    def test_named_cases(self):
        amount, order = cv("amount", "<=", 200), cv("order", "==", 81)
        ok = [([amount, order], [cv("amount", "<=", 150), order]),
              ([amount], [amount, cv("order", "==", 81)]),     # a caveat on a new field
              ([amount], [cv("amount", "==", 120)]),
              ([cv("kind", "==", "x")], [cv("kind", "in", ["x"])]),
              ([cv("n", "<", 5)], [cv("n", "<=", 4)]),
              ([cv("n", "<=", 4)], [cv("n", "<", 5)]),
              ([cv("due", "<=", "2026-10-27T18:00:00.000000Z")], [cv("due", "<=", "2026-10-27T17:00:00.000000Z")])]
        fail = [([amount, order], [cv("amount", "<=", 300), cv("order", "==", 81), cv("order", "<=", 80)]),
                ([amount, order], [cv("amount", "<=", 300), order]),   # widen one while keeping the other
                ([amount, order], [cv("amount", "<=", 150), cv("order", "<=", 81)]),
                ([amount, order], [amount]),                          # a missing caveat widens
                ([order], [cv("order", "<=", 81)]),
                ([order], [cv("order", ">=", 81), cv("order", "<=", 81)]),   # bounds never make an equality
                ([order], [cv("order", "in", [81])]),                  # `in` is for strings
                ([cv("kind", "in", ["a", "b"])], [cv("kind", "in", ["a", "b", "c"])]),
                ([cv("rush", "==", True)], [cv("rush", "==", 1)]),
                ([cv("n", "<=", 4)], [cv("n", "<=", "4")]),
                ([amount], [cv("amount", "<", 200.5)]),
                ([cv("n", "<=", True)], [cv("n", "<=", True)]),
                ([cv("k", "in", ["a", "a"])], [cv("k", "==", "a")]),
                ([cv("k", "==", ["a"])], [cv("k", "==", ["a"])]),
                ([cv("n", "<", "5")], [cv("n", "<", "5")]),
                ([amount], [amount, cv("x", "<", "y")])]           # a meaningless child caveat
        for parent, kid in ok:
            self.assertEqual(pcm.narrows(parent, kid), [], (parent, kid))
        for parent, kid in fail:
            self.assertTrue(pcm.narrows(parent, kid), (parent, kid))
        self.assertEqual(pcm.narrows([amount, order], [cv("amount", "<=", 300), order]),
                         ["amount <= 200: dropped or widened"])


class Satisfies(unittest.TestCase):
    def test_each_op_and_type(self):
        args = {"amount": 120, "order": 81, "kind": "full", "rush": True}
        yes = [cv("amount", "<=", 120), cv("amount", "<", 121), cv("amount", ">=", 120), cv("amount", ">", 119),
               cv("order", "==", 81), cv("kind", "in", ["full", "store"]), cv("kind", "==", "full"),
               cv("rush", "==", True)]
        no = [cv("amount", "<=", 119), cv("amount", "<", 120), cv("amount", ">=", 121), cv("amount", ">", 120),
              cv("order", "==", "81"), cv("order", "==", 82), cv("kind", "in", ["store"]), cv("rush", "==", 1),
              cv("missing", "==", 1), cv("missing", "<=", 5)]
        for c in yes:
            self.assertTrue(pcm.satisfies(args, c), c)
        for c in no:
            self.assertFalse(pcm.satisfies(args, c), c)
        self.assertFalse(pcm.satisfies({"n": True}, cv("n", "<=", 5)))
        self.assertFalse(pcm.satisfies({"n": 1}, cv("n", "==", True)))
        self.assertFalse(pcm.satisfies({"n": "a"}, cv("n", "<=", 5)))


class Grants(unittest.TestCase):
    DOC = {**DOC, "grant": True}

    def run_chain(self, grants, args=None, ts=T0, frm=A, doc=None):
        return pcm.verify(message(args=args, ts=ts, frm=frm, ref=pcm.schema_ref(doc or self.DOC), grants=grants),
                          TRUST, [doc or self.DOC])

    def refused(self, grants, why, **kw):
        out = self.run_chain(grants, **kw)
        self.assertEqual(out["verdict"], "reject", out)
        self.assertTrue(any(why in p for p in out["grants"]["problems"]), out["grants"])

    def test_chain_ok(self):
        ref = pcm.schema_ref(self.DOC)
        root = grant([cv("amount", "<=", 20000), cv("order", "==", 81)], subject=C, intent=ref)
        kid = child(root, [cv("amount", "<=", 15000), cv("order", "==", 81)], intent=ref, expires=T0 + 1800)
        out = self.run_chain([root, kid])
        self.assertEqual(out["verdict"], "accept", out)
        self.assertEqual(out["grants"], {"result": "ok", "steps": 2, "problems": [],
                                         "root": {"kind": "person", "id": ALICE, "person": "alice"}})
        self.assertEqual(self.run_chain([grant([cv("amount", "<=", 20000)], intent=ref)])["verdict"], "accept")

    def test_chain_refused(self):
        ref = pcm.schema_ref(self.DOC)
        root = grant([cv("amount", "<=", 20000), cv("order", "==", 81)], subject=C, intent=ref)
        narrow = [cv("amount", "<=", 15000), cv("order", "==", 81)]
        self.refused([root, grant(narrow, issuer={"kind": "agent", "id": C, "run": "r", "tenant": "default"}, parent="sha256:" + "0" * 64,
                                  intent=ref)], "its parent is not grant 0")
        self.refused([root, grant(narrow, issuer={"kind": "agent", "id": B, "run": "r", "tenant": "default"}, parent=event_hash(root),
                                  intent=ref)], "not grant 0's subject")
        self.refused([root, grant(narrow, issuer={"kind": "person", "id": C, "run": "r", "tenant": "default"}, parent=event_hash(root),
                                  intent=ref)], "not grant 0's subject")
        self.refused([root, child(root, narrow, intent=ref, expires=T0 + 7200)], "outlives its parent")
        other = pcm.schema_ref({**self.DOC, "name": "refund.other"})
        self.refused([root, child(root, narrow, intent=other)], "not this intent")
        self.refused([root, child(root, narrow, subject=B, intent=ref)], "not the sender")
        self.refused([root, child(root, [cv("amount", "<=", 30000), cv("order", "==", 81)], intent=ref)],
                     "amount <= 20000: dropped or widened")
        self.refused([root, child(root, narrow, intent=ref)], "expired at", ts=T0 + 3601)
        self.refused([grant(subject=A, issuer={"kind": "person", "id": A, "run": "r", "tenant": "default"}, intent=ref)],
                     "issuer is its own subject")
        self.refused([grant(intent=ref, parent="sha256:" + "0" * 64)], "the root grant has a parent")
        self.refused([grant(intent=ref, key=OTHER)], "bad signature")
        self.refused([grant(intent=ref, key=OTHER, vkey=OTHER_VKEY)], "not the log that signed the message")
        self.refused([grant(intent=ref, vkey=checkpoint.vkey("elsewhere/log", checkpoint.ED25519, KEY.public))],
                     "not the log that signed the message")
        tampered = grant([cv("amount", "<=", 20000)], intent=ref)
        tampered["caveats"][0]["value"] = 90000
        self.refused([tampered], "bad signature")
        self.refused([grant([cv("colour", "==", "red")], intent=ref)], "no field colour")
        self.refused([grant([cv("kind", "<=", "full")], intent=ref)], "does not apply to a enum field")
        self.refused([grant([cv("kind", "in", ["full", "nope"])], intent=ref)], "not a valid enum value")
        self.refused([grant([cv("kind", "in", ["full", "full"])], intent=ref)], "not a valid enum value")
        self.refused([grant([cv("amount", "<=", 20000)], intent=ref)], "amount 50000 breaks amount <= 20000",
                     args={"amount": 50000, "order": 81})
        self.refused([grant([cv("kind", "==", "full")], intent=ref)], "kind missing breaks")
        self.refused([grant(intent=ref, issuer={"kind": "agent", "id": C, "run": "r", "tenant": "default"})],
                     "the root grant must come from a person's approval")
        nobody = {"kind": "person", "id": ALICE, "run": "r", "tenant": "default", "approval_id": "apr-1"}
        self.refused([grant(intent=ref, issuer=nobody)], "grant 0: the root grant's issuer names no person")
        self.refused([root, grant(narrow, issuer={"kind": "agent", "id": C, "run": "r", "tenant": "acme"},
                                  parent=event_hash(root), intent=ref)], "grant 1: issued in tenant acme, not the "
                                                                         "sender's default")

    def test_a_grant_from_another_pinned_log(self):
        """Both logs are pinned: a grant the other one signed holds nothing in a message from this one."""
        ref, trust = pcm.schema_ref(self.DOC), {"logs": [VKEY, OTHER_VKEY]}
        g = grant([cv("amount", "<=", 20000)], intent=ref, key=OTHER, vkey=OTHER_VKEY)
        self.assertIsNone(pcm.check_sig(g, "pcm-grant", trust))
        out = pcm.verify(message(ref=ref, grants=[g]), trust, [self.DOC])
        self.assertEqual(out["verdict"], "reject")
        self.assertEqual(out["grants"]["problems"], [f"grant 0: signed by {g['sig']['key']}, not the log that signed "
                                                     f"the message ({message()['sig']['key']})"])

    def test_delegable_only_narrows(self):
        ref = pcm.schema_ref(self.DOC)
        narrow = [cv("amount", "<=", 15000)]
        for parent, kid, ok in ((True, True, True), (True, False, True), (False, False, False), (False, True, False)):
            with self.subTest(parent=parent, child=kid):
                root = grant([cv("amount", "<=", 20000)], subject=C, intent=ref, delegable=parent)
                last = child(root, narrow, intent=ref, delegable=kid)
                out = self.run_chain([root, last])
                if ok:
                    self.assertEqual(out["verdict"], "accept", out)
                else:
                    self.refused([root, last], "grant 0 can't be passed on")
                # one more step: below a child that can't be passed on, nothing links
                out = self.run_chain([root, last, child(last, narrow, intent=ref)])
                self.assertEqual(out["verdict"], "accept" if ok and kid else "reject", out)
        self.assertEqual(self.run_chain([grant([cv("amount", "<=", 20000)], intent=ref, delegable=False)])["verdict"],
                         "accept")   # a root that can't be passed on still holds for its own subject

    def test_args_not_an_object(self):
        ref = pcm.schema_ref(self.DOC)
        for args in ("amount", ["amount"], 5):
            self.refused([grant([cv("amount", "<=", 20000)], intent=ref)], "amount missing breaks", args=args)

    def test_grant_required(self):
        out = self.run_chain([])
        self.assertEqual((out["verdict"], out["grants"]["result"]), ("reject", "failed"))
        out = self.run_chain([], doc=DOC)
        self.assertEqual((out["verdict"], out["grants"]["result"]), ("accept", "none"))


class Signature(unittest.TestCase):
    def test_any_change_breaks_it(self):
        m = message(claims=[{"type": "approved_by", "args": {"person": "alice", "call": "c1"}}],
                    payload={"kind": "text", "text": "please refund order 81"})
        self.assertIsNone(pcm.check_sig(m, "pcm", TRUST))
        for k in m:
            if k != "sig":
                self.assertEqual(pcm.check_sig({**m, k: "x"}, "pcm", TRUST), "bad signature", k)
        m["intent"]["args"]["amount"] += 1
        self.assertEqual(pcm.check_sig(m, "pcm", TRUST), "bad signature")
        self.assertIn("does not pin", pcm.check_sig(message(), "pcm", {"logs": [OTHER_VKEY]}))
        self.assertIn("does not pin", pcm.check_sig(message(), "pcm", {"logs": []}))
        self.assertEqual(pcm.check_sig(message(key=OTHER), "pcm", TRUST), "bad signature")
        m = message()
        m["sig"] = {**m["sig"], "sig": "not base64!"}
        self.assertEqual(pcm.check_sig(m, "pcm", TRUST), "bad signature")

    def test_only_canonical_base64(self):
        """PCM 0.1: a signature has one text form; a set unused bit, no padding or whitespace fails it."""
        m, alpha = message(), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        s = m["sig"]["sig"]
        bits = s[:85] + alpha[alpha.index(s[85]) ^ 1] + s[86:]   # char 85 holds 2 bits of the 64th byte and 4 unused
        self.assertEqual(base64.b64decode(bits), base64.b64decode(s))
        for text in (bits, s.rstrip("="), s[:40] + "\n" + s[40:87]):
            self.assertEqual(pcm.check_sig({**m, "sig": {**m["sig"], "sig": text}}, "pcm", TRUST), "bad signature",
                             text)

    def test_domain_separation(self):
        g = grant()
        self.assertIsNone(pcm.check_sig(g, "pcm-grant", TRUST))
        self.assertEqual(pcm.check_sig(g, "pcm", TRUST), "bad signature")
        self.assertEqual(pcm.check_sig(message(), "pcm-grant", TRUST), "bad signature")
        with self.assertRaises(ValueError):
            sigmsg.message("pcm", {"t": "tracekit.checkpoint.v2"})
        # PCM's own tags (an open protocol, not a tracekit format), distinct from every tracekit purpose
        self.assertEqual(sigmsg.message("pcm", {}), b'{"t":"pcm.message.v0"}')
        self.assertEqual(sigmsg.message("pcm-grant", {}), b'{"t":"pcm.grant.v0"}')
        # every purpose is a distinct "t" in the JCS object, so no two purposes sign the same bytes for any body
        tags = [json.loads(sigmsg.message(p, {}))["t"] for p in sigmsg.PURPOSES]
        self.assertEqual(len(set(tags)), len(sigmsg.PURPOSES), tags)
        body = {"pcm": 0, "x": 1}
        self.assertEqual(len({sigmsg.message(p, body) for p in sigmsg.PURPOSES}), len(sigmsg.PURPOSES))
        text = sigmsg.message("pcm", {"x": 1}).decode() + "\n"   # PCM bytes posing as a checkpoint note
        note = text + "\n" + checkpoint.log_line("pcm-test/log", KEY.public, KEY.sign(text.encode()))
        with self.assertRaises(checkpoint.NoteError):
            checkpoint.open_note(note, [VKEY])

    def test_forged_message_is_rejected_before_any_other_check(self):
        out = pcm.verify(message(key=OTHER), TRUST, [DOC], replay=pcm.Replay(now=T0), now=T0)
        self.assertEqual(out, {"signature": {"ok": False, "key": out["signature"]["key"]}, "replay": None,
                               "schema": None, "grants": None, "claims": None, "verdict": "reject",
                               "reasons": ["signature: bad signature"], "skipped": ["recipient"]})

    def test_a_bad_pin_is_the_receivers_error_wherever_it_sits(self):
        """PCM 0.1 10.1: a malformed or non-canonical vkey in trust.json is refused before any message is checked."""
        for bad in ("not a vkey", VKEY + "="):
            for trust in ({"logs": [VKEY, bad]}, {"logs": [bad, VKEY]}, {"logs": [VKEY], "witnesses": [{"vkey": bad}]}):
                with self.subTest(trust=trust), self.assertRaises(checkpoint.NoteError):
                    pcm.verify(message(), trust, [DOC])

    def test_two_keys_of_one_log_are_the_receivers_error(self):
        """PCM 0.1 declares no rotation: a second Ed25519 key under one log name is bad input, not a key to try."""
        twin = checkpoint.vkey("pcm-test/log", checkpoint.ED25519, OTHER.public)
        for trust in ({"logs": [VKEY, twin]}, {"logs": [twin, VKEY]}):
            with self.subTest(trust=trust), self.assertRaisesRegex(ValueError, "2 Ed25519 keys for log pcm-test/log; PCM verifies "
                                                                           "with one"):
                pcm.verify(message(), trust, [DOC])
        hybrid = checkpoint.vkey("pcm-test/log", checkpoint.HYBRID, checkpoint.SLH_DSA + os.urandom(slh_dsa.PK_SIZE))
        for trust in ({"logs": [VKEY, OTHER_VKEY]}, {"logs": [VKEY, hybrid]}):   # another log; the hybrid line
            self.assertEqual(pcm.verify(message(), trust, [DOC])["verdict"], "accept", trust)


class ReplayTests(unittest.TestCase):
    def check(self, r, m, now=T0, me=None):
        return pcm.verify(m, TRUST, [DOC], replay=r, me=me, now=now)

    def test_once(self):
        r, m = pcm.Replay(now=T0), message()
        self.assertEqual(self.check(r, m)["verdict"], "accept")
        out = self.check(r, m)
        self.assertEqual((out["verdict"], out["replay"]["ok"]), ("reject", False))
        self.assertIn("replayed", out["replay"]["detail"])

    def test_same_nonce_from_another_sender(self):
        r, m = pcm.Replay(now=T0), message()
        other = pcm.sign(KEY, VKEY, "pcm", {k: v for k, v in {**m, "from": {**m["from"], "agent": C}}.items()
                                            if k != "sig"})
        self.assertEqual(self.check(r, m)["verdict"], "accept")
        self.assertEqual(self.check(r, other)["verdict"], "accept")

    def test_same_agent_under_another_log(self):
        """PCM 0.1: a sender is its log key and agent, so one agent name under two logs shares no nonce."""
        r, m = pcm.Replay(now=T0), message()
        other = pcm.sign(OTHER, OTHER_VKEY, "pcm", {k: v for k, v in m.items() if k != "sig"})
        for x in (m, other):
            out = pcm.verify(x, {"logs": [VKEY, OTHER_VKEY]}, [DOC], replay=r, now=T0)
            self.assertEqual(out["verdict"], "accept", out["reasons"])
        self.assertIn("replayed", self.check(r, m)["replay"]["detail"])

    def test_window_and_start(self):
        r = pcm.Replay(now=T0 - 1000)
        for dt in (-301, 301):
            out = self.check(r, message(ts=T0 + dt))
            self.assertEqual((out["verdict"], out["replay"]["ok"]), ("reject", False), dt)
        for dt in (-299, 299):
            self.assertEqual(self.check(r, message(ts=T0 + dt))["verdict"], "accept", dt)
        out = self.check(pcm.Replay(now=T0), message(ts=T0 - 10))
        self.assertIn("before this receiver started", out["replay"]["detail"])

    def test_eviction_raises_the_floor(self):
        r = pcm.Replay(per_sender=2, now=T0)
        ms = [message(ts=T0 + i) for i in (1, 2, 3)]
        for m in ms:
            self.assertEqual(self.check(r, m, now=T0 + 3)["verdict"], "accept")
        self.assertEqual(len(r.seen[ms[0]["sig"]["key"], A]), 2)
        for m in (ms[0], message(ts=T0 + 1)):   # the evicted nonce, and a fresh one as old
            out = self.check(r, m, now=T0 + 3)
            self.assertIn("older than", out["replay"]["detail"])
        self.assertIn("replayed", self.check(r, ms[1], now=T0 + 3)["replay"]["detail"])

    def test_recipient(self):
        out = self.check(pcm.Replay(now=T0), message(), me=C)
        self.assertEqual((out["verdict"], out["replay"]["detail"]), ("reject", f"addressed to {B}, not {C}"))
        self.assertEqual(self.check(None, message(), me=B)["verdict"], "accept")
        self.assertEqual(self.check(None, message())["replay"], {"ok": None, "detail": "not checked"})

    def test_the_result_names_what_it_skipped(self):
        for r, me, skipped in ((None, None, ["replay", "recipient"]), (pcm.Replay(now=T0), None, ["recipient"]),
                               (None, B, ["replay"]), (pcm.Replay(now=T0), B, [])):
            with self.subTest(replay=r is not None, me=me):
                self.assertEqual(self.check(r, message(), me=me)["skipped"], skipped)

    def test_a_message_rejected_for_its_recipient_or_schema_spends_no_nonce(self):
        r, m = pcm.Replay(now=T0), message()
        self.assertEqual(self.check(r, m, me=C)["verdict"], "reject")
        out = pcm.verify(m, TRUST, [], replay=r, now=T0)   # a schema this receiver doesn't have yet
        self.assertEqual((out["verdict"], out["schema"]["errors"], out["replay"]), (
            "reject", [f"unknown schema {REF}"], {"ok": True, "detail": "fresh"}))
        with self.assertRaises(ValueError):   # a bad schema document: the receiver's own error
            pcm.verify(m, TRUST, [{"name": "x"}], replay=r, now=T0)
        self.assertEqual(self.check(r, m, me=B)["verdict"], "accept")
        self.assertIn("replayed", self.check(r, m, me=B)["replay"]["detail"])

    def test_a_ts_that_is_no_real_time(self):
        body = {k: v for k, v in message().items() if k != "sig"}
        for ts in ("2026-13-01T00:00:00.000000Z", "0000-01-01T00:00:00.000000Z"):
            m = pcm.sign(KEY, VKEY, "pcm", dict(body, ts=ts))
            for r in (pcm.Replay(now=T0), pcm.Replay(window_s=None)):
                out = self.check(r, m)
                self.assertEqual((out["verdict"], out["replay"]), ("reject", {"ok": False, "detail":
                                                                              f"sent at {ts}, which is no real time"}))

    def test_auditor_ignores_clocks(self):
        r, m = pcm.Replay(window_s=None, now=T0 + 10 ** 6), message()
        self.assertEqual(self.check(r, m, now=T0 + 10 ** 6)["verdict"], "accept")
        self.assertIn("replayed", self.check(r, m, now=T0 + 10 ** 6)["replay"]["detail"])


class Verdicts(unittest.TestCase):
    CLAIM = {"type": "approved_by", "args": {"person": "alice", "call": "c1"}}

    def test_paths(self):
        need = {**DOC, "claims": ["approved_by"]}
        ref = pcm.schema_ref(need)
        out = pcm.verify(message(claims=[self.CLAIM]), TRUST, [DOC])
        self.assertEqual((out["verdict"], out["reasons"]), ("accept-unproven", ["approved_by: unproven (no evidence)"]))
        out = pcm.verify(message(ref=ref), TRUST, [need])
        self.assertEqual((out["verdict"], out["reasons"]), ("accept-unproven", ["approved_by: required, not proven"]))
        out = pcm.verify(message(ref=ref), TRUST, [need], strict=True)
        self.assertEqual((out["verdict"], out["reasons"]), ("reject", ["approved_by: required, not proven"]))
        ev = {"checkpoint": "note", "records": [{"event": {}, "hash": "sha256:" + "0" * 64, "proof": []}]}
        out = pcm.verify(message(claims=[{**self.CLAIM, "evidence": ev}]), TRUST, [DOC])
        self.assertEqual((out["verdict"], out["claims"][0]["result"]), ("reject", "failed"))
        self.assertIn("checkpoint:", out["claims"][0]["detail"])
        bad = {"type": "approved_by", "args": {"person": "alice", "call": "c 1"}}
        out = pcm.verify(message(claims=[bad]), TRUST, [DOC])
        self.assertEqual(out["verdict"], "reject")
        self.assertIn("approved_by: failed", out["reasons"][0])
        out = pcm.verify(message(args={"amount": -1, "order": 81}), TRUST, [DOC])
        self.assertEqual((out["verdict"], out["reasons"][0][:7]), ("reject", "schema:"))
        out = pcm.verify({"pcm": 0}, TRUST, [DOC])
        self.assertEqual((out["verdict"], out["reasons"][0][:9]), ("reject", "envelope:"))

    def test_table_from_parts(self):
        """Every row of the verdict table, from synthetic parts (proven claims come from evidence checks). A proven
        approved_by meets the schema's need only when it says it covers the request (PCM 0.1 6.6)."""
        def parts(claims=(), replay=True, schema=(), grants=(), covers=True):
            return {"replay": {"ok": replay, "detail": "d"}, "schema": {"errors": list(schema)},
                    "grants": {"problems": list(grants)}, "claims": [{"type": t, "result": r, "detail": "d"}
                                                                     for t, r in claims]}, \
                [{"type": t, "args": {"covers": covers}} for t, _ in claims]
        need = {"claims": ["approved_by"]}
        proven, unproven = ("approved_by", "proven"), ("tests_passed", "unproven")
        rows = [(parts([proven]), need, False, "accept"),
                (parts([proven]), need, True, "accept"),
                (parts([proven], replay=None), need, False, "accept"),
                (parts([proven, unproven]), need, False, "accept-unproven"),
                (parts([proven, unproven]), need, True, "accept-unproven"),
                (parts(), need, False, "accept-unproven"),
                (parts(), need, True, "reject"),
                (parts([("approved_by", "unproven")]), need, True, "reject"),
                (parts([proven], replay=False), need, False, "reject"),
                (parts([proven], schema=["e"]), need, False, "reject"),
                (parts([proven], grants=["p"]), need, False, "reject"),
                (parts([proven, ("tests_passed", "failed")]), need, False, "reject"),
                (parts([proven], covers=False), need, False, "accept-unproven"),
                (parts([proven], covers=False), need, True, "reject"),
                (parts([proven], covers=False), {}, True, "accept")]
        for (out, sent), doc, strict, verdict in rows:
            self.assertEqual(pcm._verdict(out, doc, strict, sent)[0], verdict, (out, strict))


if __name__ == "__main__":
    unittest.main()
