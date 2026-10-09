"""Format v2 canonical JSON: the shared JCS golden vectors (tests/vectors/jcs.jsonl) and the strict parser."""
import hashlib
import json
import os
import unittest

import rfc8785

from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "jcs.jsonl")


def vectors():
    with open(VECTORS, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class TestVectors(unittest.TestCase):
    def test_every_vector(self):
        vs = vectors()
        self.assertEqual(len(vs), 248)
        for v in vs:
            with self.subTest(v["id"]):
                if "error" in v:
                    with self.assertRaises(StrictJSONError) as cm:
                        loads_strict(v["input"])
                    self.assertEqual(cm.exception.code, v["error"])
                else:
                    out = canonical(loads_strict(v["input"]))
                    self.assertEqual(out, v["canonical"].encode("utf-8"))
                    self.assertEqual(hashlib.sha256(out).hexdigest(), v["sha256"])

    def test_event_hash(self):
        self.assertEqual(event_hash({"b": 1, "a": [2.0]}), "sha256:" + hashlib.sha256(b'{"a":[2],"b":1}').hexdigest())


class TestStrictParser(unittest.TestCase):
    def rejects(self, text, code):
        with self.assertRaises(StrictJSONError) as cm:
            loads_strict(text)
        self.assertEqual(cm.exception.code, code)

    def test_duplicate_keys(self):
        self.rejects('{"a":1,"a":1}', "duplicate_key")
        self.rejects('[{"k":{"x":1,"\\u0078":2}}]', "duplicate_key")

    def test_non_finite(self):
        for t in ("NaN", "Infinity", "-Infinity", "[1e400]", "-1e400"):
            self.rejects(t, "non_finite")

    def test_lone_surrogates_in_values_and_keys(self):
        self.rejects('"\\udc00"', "lone_surrogate")
        self.rejects('{"\\ud800":1}', "lone_surrogate")
        self.assertEqual(loads_strict('"\\ud83d\\ude00"'), "\U0001F600")

    def test_integer_tokens_outside_safe_range(self):
        self.assertEqual(loads_strict("9007199254740991"), 2 ** 53 - 1)
        self.assertEqual(loads_strict("-9007199254740991"), -(2 ** 53 - 1))
        self.rejects("9007199254740992", "int_range")
        self.rejects("[-9007199254740992]", "int_range")
        self.rejects("1" * 5000, "int_range")
        # floats are not integer tokens
        self.assertEqual(canonical(loads_strict("1e21")), b"1e+21")
        self.assertEqual(loads_strict("9007199254740993.0"), 9007199254740992.0)

    def test_bytes_and_syntax(self):
        self.assertEqual(loads_strict('{"a":"é"}'.encode("utf-8")), {"a": "é"})
        self.rejects(b'"\xff"', "invalid_utf8")
        self.rejects('{"a":', "syntax")
        self.rejects("[" * 100000, "syntax")

    def test_canonical_refuses_what_the_parser_rejects(self):
        deep = []
        for _ in range(100000):
            deep = [deep]
        for bad in (float("nan"), 2 ** 53, "\ud800", {"\ud800": 1}, deep):
            with self.assertRaises(rfc8785.CanonicalizationError):
                canonical(bad)


if __name__ == "__main__":
    unittest.main()
