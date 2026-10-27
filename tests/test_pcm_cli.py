"""`tracekit pcm` (#436): the demo's five outcomes through a real in-process signer, and `verify`'s exit codes."""
import contextlib
import io
import json
import os
import re
import unittest

from test_pcm_signer import DOC, Case
from tracekit import cli, pcm
from tracekit.pcm import cli as pcm_cli
from tracekit.wiki import wiki_url


class TestDemo(unittest.TestCase):
    def test_five_outcomes_and_the_temp_dir_goes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(pcm_cli.main(["demo"]), 0)
        text = out.getvalue()
        for line in ("B: ACCEPT           signature ok · replay ok · schema ok · grant ok (alice, 1 step) · "
                     "approved_by proven",
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
        self.assertEqual(self.verify(msg)[:2], (0, "ACCEPT  signature ok · schema ok\n"))
        unproven = self.call("pcm_sign", message=self.body(claims=[
            {"type": "tests_passed", "args": {"suite": "pytest -q"}}]))["message"]
        self.assertEqual(self.verify(unproven)[:2], (3, "ACCEPT-UNPROVEN  tests_passed: unproven (no evidence)\n"))
        code, out, _ = self.verify(msg, "--me", "uid:990103")
        self.assertEqual((code, out), (1, "REJECT  replay: addressed to uid:990102, not uid:990103\n"))
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

    def test_strict(self):
        doc = dict(DOC, claims=["approved_by"])
        self.files["schema"] = self.write("schema", doc)
        msg = self.call("pcm_sign", message=self.body(
            intent={"type": pcm.schema_ref(doc), "args": {"amount": 12000, "order": 81}}))["message"]
        self.assertEqual(self.verify(msg)[:2], (3, "ACCEPT-UNPROVEN  approved_by: required, not proven\n"))
        self.assertEqual(self.verify(msg, "--strict")[:2], (1, "REJECT  approved_by: required, not proven\n"))


if __name__ == "__main__":
    unittest.main()
