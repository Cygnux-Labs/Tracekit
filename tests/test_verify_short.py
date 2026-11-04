"""The short result `tracekit verify` prints by default (#592): a verified bundle's verdict, events, key and how far the
setup protects it; a tampered bundle's first broken record; a dev bundle said to give no protection against the agent.
`--detail` prints the full report as before and `--json` is unchanged."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import test_bundle_v2 as tb
from factories import ev, make_signer, rewrite_bundle, run_start, tool_call
from tracekit import bundle, cli, crypto, policy
from tracekit.bundle_v2 import export
from tracekit.verify import v2
from tracekit.wiki import wiki_url

KID = crypto.spki_kid(tb.spki(tb.KEY1))
DEV = ("Protection: none against the agent. Dev mode: the signer ran as the agent's own user, so the agent could have "
       "re-signed this log.\nFor real protection, run the signer where the agent can't reach it: "
       f"{wiki_url('docs/deploy.md')}\n")


def verify(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["verify", *argv])
    return code, out.getvalue()


class V2(tb.Case):
    def bundle(self, isolation, witnesses=((tb.WITNESS, tb.WIT_SECRET),), tamper=False):
        name = f"s{len(os.listdir(self.d))}"
        log = self.log(name)
        log.epoch(tb.KEY1)
        log.add("run.registered", {"agent": {"name": "agent"}, "signer_isolation": isolation,
                                   "identity": {"scheme": "uid", "subject": "1", "attested": True}})
        log.call()
        log.call()
        log.final()
        out = os.path.join(self.d, f"{name}.tkb")
        export(log.store, "acme", "run-a", log.note(witnesses=witnesses), out)
        if tamper:   # the second call's input rewritten in a copy: its record no longer hashes to what was signed
            out = self.mutate(out, edit_run=lambda records: records[2]["event"]["data"].update(input={"command": "ls"}))
        return out

    def test_a_verified_bundle_says_what_it_rests_on_and_what_protects_it(self):
        self.assertEqual(verify(self.bundle("separate-user"), "--trust", self.trust), (0, (
            f"VERIFIED: 4 events, signed by {KID}, nothing edited or missing.\n"
            "Protection: the agent could not reach the signer's key (separate-user), and an independent witness "
            "cosigned the log.\n")))

    def test_a_signer_out_of_the_agents_reach_without_a_witness_says_who_could_still_rewrite_it(self):
        code, out = verify(self.bundle("remote", witnesses=()), "--trust", self.write_trust(0, name="t0.json"))
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines()[1], "Protection: the agent could not reach the signer's key (remote), but no "
                         "independent witness cosigned the log, so whoever runs the signer could rewrite it: "
                         f"{wiki_url('docs/witnesses.md')}")

    def test_a_dev_bundle_says_it_gives_no_protection_against_the_agent_however_it_was_witnessed(self):
        code, out = verify(self.bundle("same-user"), "--trust", self.trust)
        self.assertEqual((code, out), (0, f"VERIFIED: 4 events, signed by {KID}, nothing edited or missing.\n{DEV}"))
        self.assertNotIn("PASS", out)

    def test_a_tampered_bundle_says_where_it_breaks(self):
        self.assertEqual(verify(self.bundle("same-user", tamper=True), "--trust", self.trust),
                         (1, "TAMPERED at event 3: hash does not match the event.\nAdd --detail to see each check.\n"))

    def test_detail_prints_the_full_report_and_json_is_unchanged(self):
        for tamper in (False, True):
            path = self.bundle("same-user", tamper=tamper)
            rep, code = v2.verify(path, self.trust)
            full = io.StringIO()
            v2.print_report(rep, code, full)
            self.assertEqual(verify(path, "--trust", self.trust, "--detail"), (code, full.getvalue()))
            js = json.loads(verify(path, "--trust", self.trust, "--json")[1])
            self.assertEqual((js["exit_code"], js["checks"], js["integrity"]), (code, rep.checks, rep.integrity))


class V1(unittest.TestCase):
    """A v1 dev bundle, from an in-process signer of the agent's own user."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        home = os.path.join(self.d, "home")
        s, (pol, raw) = make_signer(home, checkpoint_every=1000), policy.load()
        for n, e in enumerate([run_start("r1", pol), tool_call("t1", "pytest -q"), ev("run.end", {"reason": "done"})]):
            self.assertTrue(s.handle({"op": "append", "cseq": n, "event": e,
                                      **({"attach": {"policy": raw}} if n == 0 else {})})["ok"])
        self.out, self.key = os.path.join(self.d, "run.tkb"), os.path.join(home, "ledger", "signer.pub")
        bundle.export(home, self.out)
        with open(self.key, "rb") as f:
            self.kid = crypto.kid(f.read())

    def test_a_dev_bundle_says_it_gives_no_protection_against_the_agent(self):
        code, out = verify(self.out, "--key", self.key)
        self.assertEqual(code, 0, out)
        first, warned, protection = out.split("\n", 2)
        n = bundle.verify(self.out, trusted_key=self.key)[0].events
        self.assertEqual(first, f"VERIFIED: {n} events, signed by {self.kid}, nothing edited.")
        self.assertTrue(warned.startswith("Warnings: signing key, ") and warned.endswith(". Add --detail to see why."))
        self.assertEqual(protection, DEV)

    def test_a_tampered_bundle_says_where_it_breaks(self):
        seq = []

        def edit(files, _manifest):   # the recorded command rewritten, as `tracekit demo` does
            records = [json.loads(line) for line in files["records.jsonl"].decode().splitlines()]
            call = next(r["event"] for r in records if r["event"]["type"] == "tool.call")
            call["data"]["input"]["command"]["value"] = "echo tests skipped"
            seq.append(call["seq"])
            files["records.jsonl"] = "".join(json.dumps(r) + "\n" for r in records).encode()
        bad = os.path.join(self.d, "tampered.tkb")
        rewrite_bundle(self.out, bad, edit)
        self.assertEqual(verify(bad, "--key", self.key), (1, f"TAMPERED at event {seq[0]}: hash mismatch (event content "
                                                             "was edited).\nAdd --detail to see each check.\n"))


if __name__ == "__main__":
    unittest.main()
