"""`tracekit pcm` (#436): the demo's five outcomes through a real in-process signer, and `verify`'s exit codes."""
import contextlib
import io
import json
import os
import re
import unittest
import unittest.mock

from test_pcm_signer import DOC, Case
from tracekit import cli, pcm
from tracekit.format import checkpoint
from tracekit.pcm import cli as pcm_cli
from tracekit.signer import logkey
from tracekit.wiki import wiki_url


class TestDemo(unittest.TestCase):
    def test_five_outcomes_and_the_temp_dir_goes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(pcm_cli.main(["demo"]), 0)
        text = out.getvalue()
        for line in ("B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · "
                     'approved_by proven (approval seq 4 by alice of "pcm.grant" call grant-1, which issued this '
                     "message's root grant)\n",
                     "B: ACCEPT-UNPROVEN  tests_passed: unproven (no evidence)",
                     "B: REJECT           approved_by: failed (record 1: hash does not match the event)",
                     "B: REJECT           grant: grant 0: amount 50000 breaks amount <= 20000",
                     "signer: forbidden: the signer signs only as the calling run's own agent (uid:990101, run "):
            self.assertIn(line, text)
        self.assertFalse(os.path.exists(re.search(r"in-process signer in (\S+)\)", text).group(1)))


class TestVerify(Case):
    def setUp(self):
        super().setUp()
        self.files = {}
        for name, value in (("trust", self.trust), ("schema", DOC)):
            self.files[name] = self.write(name, value)

    def write(self, name, value):
        path = os.path.join(self.dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(value, f)
        return path

    def verify(self, msg, *extra, main=pcm_cli.main):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["verify", self.write("msg", msg), "--trust", self.files["trust"], "--schema",
                         self.files["schema"], *extra])
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        msg = self.call("pcm_sign", message=self.body())["message"]
        self.assertEqual(self.verify(msg)[:2], (0, "ACCEPT  signature ok · schema ok · not checked: replay, "
                                                   "recipient\n"))
        self.assertEqual(self.verify(msg, "--me", "uid:990102")[:2], (0, "ACCEPT  signature ok · schema ok · "
                                                                         "not checked: replay\n"))
        unproven = self.call("pcm_sign", message=self.body(claims=[
            {"type": "tests_passed", "args": {"suite": "pytest -q"}}]))["message"]
        self.assertEqual(self.verify(unproven)[:2], (3, "ACCEPT-UNPROVEN  tests_passed: unproven (no evidence); "
                                                        "not checked: replay, recipient\n"))
        code, out, _ = self.verify(msg, "--me", "uid:990103")
        self.assertEqual((code, out), (1, "REJECT  replay: addressed to uid:990102, not uid:990103; not checked: "
                                          "replay\n"))
        code, out, _ = self.verify(dict(msg, intent=dict(msg["intent"], args={"amount": 50000, "order": 81})), "--json")
        self.assertEqual((code, json.loads(out)["reasons"]), (1, ["signature: bad signature"]))

    def test_through_tracekit_and_its_inputs(self):
        msg = self.call("pcm_sign", message=self.body())["message"]
        code, _, err = self.verify(msg, main=lambda argv: cli.main(["pcm", *argv]))
        self.assertEqual(code, 0)
        self.assertEqual(err.count(f"tracekit pcm is experimental: it works and is tested, but may change "
                                   f"({wiki_url('docs/support.md')})"), 1)
        self.files["schema"] = self.write("schema", {"name": "not a schema"})
        code, _, err = self.verify(msg)
        self.assertEqual(code, 2)
        self.assertIn("schema document 0: ", err)
        self.files["schema"] = self.write("schema", [1, 2])
        self.assertEqual(self.verify(msg)[::2], (2, "tracekit pcm verify: schema document 0: $: expected object, got list\n"))
        with open(self.files["schema"], "w", encoding="utf-8") as f:
            f.write("not json")
        code, _, err = self.verify(msg)
        self.assertEqual(code, 2)
        self.assertIn(f"tracekit pcm verify: {self.files['schema']}: ", err)

    def test_a_number_past_the_double_range_exits_2(self):
        """PCM 0.1 3.3: 1e400 rounds to no finite IEEE 754 double, so the message doesn't parse: bad input, as the
        standalone verifier says too, not a reject for its signature."""
        msg = self.call("pcm_sign", message=self.body())["message"]
        path = os.path.join(self.dir, "big.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(msg)[:-1] + ', "payload": {"kind": "data", "data": {"n": 1e400}}}')
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = pcm_cli.main(["verify", path, "--trust", self.files["trust"], "--schema", self.files["schema"]])
        self.assertEqual((code, err.getvalue()), (2, f"tracekit pcm verify: {path}: non_finite: 1e400\n"))

    def test_two_keys_of_one_log_exit_2(self):
        msg = self.call("pcm_sign", message=self.body())["message"]
        name = checkpoint.parse_vkey(self.s.vkey)[0]
        twin = checkpoint.vkey(name, checkpoint.ED25519, logkey.FileKey(os.urandom(32)).public)
        self.files["trust"] = self.write("trust", dict(self.trust, logs=[self.s.vkey, twin]))
        code, _, err = self.verify(msg)
        self.assertEqual(code, 2)
        self.assertEqual(err, f"tracekit pcm verify: trust.json pins 2 Ed25519 keys for log {name}; PCM verifies with "
                              "one: pass a trust file with only the current key (`tracekit signer trust --config "
                              "<signer.yaml> -o pcm-trust.json` writes one)\n")

    def test_sender_text_is_printed_escaped(self):
        """Characters a terminal acts on, and `\\`, so a literal `\\u001b` the sender wrote can't pass for an escaped
        ESC."""
        path = "/x/\x1b[2J‮\\u001b/.."
        msg = self.call("pcm_sign", message=self.body(claims=[
            {"type": "file_written", "args": {"path": path, "digest": "sha256:" + "0" * 64}}]))["message"]
        code, out, _ = self.verify(msg)
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertIn("/x/\\u001b[2J\\u202e\\\\u001b/.. has a `..`", out)

    def test_proven_evidence_is_printed_with_its_age(self):
        """A proven tests_passed or file_written claim proves a call happened, not that nothing changed since (PCM 0.1
        14.13): the text output says how long before the message the claim's oldest record is."""
        rec = lambda ts: {"event": {"ts": f"2026-10-28T{ts}.000000Z"}}   # noqa: E731
        msg = {"ts": "2026-10-28T10:05:00.000000Z", "claims": [
            {"evidence": {"records": [rec("10:00:00"), rec("10:00:01")]}}, {"evidence": {"records": [rec("09:00:00")]}}]}
        out = {"verdict": "accept", "reasons": [], "skipped": [], "replay": {"ok": None}, "grants": {"result": None},
               "claims": [{"type": "tests_passed", "result": "proven", "detail": "d"},
                          {"type": "reached_host", "result": "proven", "detail": "d"}]}
        note = ("evidence 300 s before the message: a claim proves a call happened, not that nothing changed since: "
                "check its age (docs/pcm.md#freshness)")
        with unittest.mock.patch.object(pcm_cli.pcm, "verify", return_value=out):
            self.assertEqual(self.verify(msg)[1].splitlines()[1:], [f"  {note}"])
            self.assertNotIn("evidence", self.verify(msg, "--json")[1])
        self.assertEqual(pcm_cli.freshness(msg, out), note)
        for claims in ([dict(out["claims"][0], result="unproven"), out["claims"][1]], None):
            self.assertFalse(pcm_cli.freshness(msg, dict(out, claims=claims)))
        self.assertIsNone(pcm_cli.freshness(dict(msg, ts="2026-13-28T10:05:00.000000Z"), out))   # no date

    def test_strict(self):
        doc = dict(DOC, claims=["approved_by"])
        self.files["schema"] = self.write("schema", doc)
        msg = self.call("pcm_sign", message=self.body(
            intent={"type": pcm.schema_ref(doc), "args": {"amount": 12000, "order": 81}}))["message"]
        self.assertEqual(self.verify(msg)[:2], (3, "ACCEPT-UNPROVEN  approved_by: required, not proven; not checked: "
                                                   "replay, recipient\n"))
        self.assertEqual(self.verify(msg, "--strict")[:2], (1, "REJECT  approved_by: required, not proven; not "
                                                               "checked: replay, recipient\n"))


if __name__ == "__main__":
    unittest.main()
