"""The short result `tracekit verify` prints by default (#592), in plain ASCII: a verified bundle's recorded actions and
whether it is proof against the agent, which only a key something outside the bundle vouches for can show; a tampered
or broken bundle's first broken record in plain words; signed gaps said as such. `--detail` prints the full report as
before and `--json` is unchanged."""
import contextlib
import glob
import io
import json
import os
import shutil
import tempfile
import unittest

import pytest

import test_bundle_v2 as tb
from factories import ev, make_signer, rewrite_bundle, run_start, tool_call
from tracekit import bundle, cli, policy
from tracekit.bundle_v2 import export
from tracekit.verify import protection, v2
from tracekit.wiki import wiki_url

DEV = ("NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could have rewritten the "
       f"record.\nTo make it proof, keep the key away from the agent: {wiki_url('docs/deploy.md')}\n")
UNANCHORED = "NOT SHOWN: nothing outside the bundle vouches for the signing key. Pin it with --key, or use a witness.\n"


def verify(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["verify", *argv])
    out = out.getvalue()
    assert "--detail" in argv or out.isascii(), out   # the short result is plain ASCII; the full report is unchanged
    return code, out


class V2(tb.Case):
    def bundle(self, isolation, witnesses=((tb.WITNESS, tb.WIT_SECRET),), edit_run=None, extra=()):
        name = f"s{len(os.listdir(self.d))}"
        log = self.log(name)
        log.epoch(tb.KEY1)
        log.add("run.registered", {"agent": {"name": "agent"}, "signer_isolation": isolation,
                                   "identity": {"scheme": "uid", "subject": "1", "attested": True}})
        log.call()
        log.call()
        for type_, data in extra:
            log.add(type_, data)
        log.final()
        out = os.path.join(self.d, f"{name}.tkb")
        export(log.store, "acme", "run-a", log.note(witnesses=witnesses), out)
        return self.mutate(out, edit_run=edit_run) if edit_run else out

    def test_a_signer_out_of_the_agents_reach_is_proof_against_it(self):
        self.assertEqual(verify(self.bundle("separate-user"), "--trust", self.trust), (0, (
            "VERIFIED: 4 recorded actions, none changed, removed or added after signing.\n"
            "PROOF AGAINST THE AGENT: the signing key was out of the agent's reach (separate-user).\n"
            "An independent witness cosigned the log too.\n")))

    def test_without_a_witness_it_says_who_could_still_rewrite_it(self):
        code, out = verify(self.bundle("remote", witnesses=()), "--trust", self.write_trust(0, name="t0.json"))
        self.assertEqual((code, out.splitlines()[1:]), (0, [
            "PROOF AGAINST THE AGENT: the signing key was out of the agent's reach (remote).",
            "Not proof against whoever runs the signer: no independent witness cosigned the log "
            f"({wiki_url('docs/witnesses.md')})."]))

    def test_a_dev_bundle_is_not_proof_against_the_agent_however_it_was_witnessed(self):
        self.assertEqual(verify(self.bundle("same-user"), "--trust", self.trust),
                         (0, f"VERIFIED: 4 recorded actions, none changed, removed or added after signing.\n{DEV}"))

    def test_an_isolation_the_signer_could_not_tell_shows_nothing(self):
        code, out = verify(self.bundle("unknown"), "--trust", self.trust)
        self.assertEqual(out.splitlines()[1], "NOT SHOWN: the signer did not record that the signing key was out of "
                                              "the agent's reach (isolation: unknown).")
        self.assertNotIn("PROOF AGAINST", out)

    def test_signed_gaps_are_said_plainly(self):
        out = tb.gaps_bundle(self.log("gaps"), os.path.join(self.d, "gaps.tkb"))
        code, said = verify(out, "--trust", self.trust)
        self.assertEqual((code, said.splitlines()[0]), (0, (
            "VERIFIED WITH GAPS: 6 recorded actions, none changed after signing; 2 signed gaps (things Tracekit knows "
            "it missed or could not check).")))
        self.assertIn("NOT SHOWN: the signer did not record that the signing key was out of the agent's reach "
                      "(isolation: not recorded).", said)

    def test_a_tampered_bundle_says_where_it_breaks(self):
        changed = self.bundle("same-user", edit_run=lambda rs: rs[2]["event"]["data"].update(input={"command": "ls"}))
        self.assertEqual(verify(changed, "--trust", self.trust), (1, (
            "TAMPERED at event 3: its content was changed after it was signed.\nAdd --detail to see each check.\n")))
        removed = self.bundle("same-user", edit_run=lambda rs: rs.pop(2))
        self.assertEqual(verify(removed, "--trust", self.trust)[1].splitlines()[0],
                         "TAMPERED at event 4: the record before it is missing, extra or out of order.")

    @pytest.mark.unverified_bundles
    def test_an_invalid_event_is_one_short_line(self):
        bad = self.bundle("same-user", extra=[("policy.decision", {"tool_use_id": "t", "decision": "maybe",
                                                                   "rule_ids": []})])
        code, out = verify(bad, "--trust", self.trust)
        self.assertEqual((code, out.splitlines()[0]), (1, "FAILED at event 4: it is not a valid event at "
                                                          "event.data.decision (--detail shows the rule)."))
        self.assertIn("not in [", verify(bad, "--trust", self.trust, "--detail")[1])   # the rule, under --detail

    def test_detail_prints_the_full_report_and_json_is_unchanged(self):
        for edit in (None, lambda rs: rs[2]["event"]["data"].update(name="Write")):
            path = self.bundle("same-user", edit_run=edit)
            rep, code = v2.verify(path, self.trust)
            full = io.StringIO()
            v2.print_report(rep, code, full)
            self.assertEqual(verify(path, "--trust", self.trust, "--detail"), (code, full.getvalue()))
            js = json.loads(verify(path, "--trust", self.trust, "--json")[1])
            self.assertEqual((js["exit_code"], js["checks"], js["integrity"]), (code, rep.checks, rep.integrity))


class Negative(unittest.TestCase):
    """The golden negative corpus, one defect per bundle: each says what is wrong in one plain ASCII line, never
    VERIFIED, and one a newer verifier must check gives the commands that do."""

    def test_every_defect_reads_plainly(self):
        neg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "negative")
        want = {"record-deleted.tkb": "TAMPERED at event 7: the record before it is missing, extra or out of order.",
                "record-edited.tkb": "TAMPERED at event 5: its content was changed after it was signed.",
                "proofs-tree-size.tkb": "FAILED: its checkpoint does not match a log key your trust file pins, or the "
                                        "bundle's own proofs.",
                "witness-none.tkb": "FAILED: fewer witnesses cosigned it than your trust file requires.",
                "run-empty.tkb": "FAILED: the bundle is malformed, so it could not be fully checked.",
                "zip-no-manifest.tkb": "UNUSABLE BUNDLE: cannot read bundle: the bundle file is damaged: no "
                                       "manifest.json.",
                "manifest-newer-verifier.tkb": "UNVERIFIABLE (needs tracekit >= 99.0).\n  uvx --from "
                                               "\"tracekit-ai>=99.0\" tracekit verify "}
        for path in sorted(glob.glob(os.path.join(neg, "*.tkb"))):
            name = os.path.basename(path)
            with self.subTest(name):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    code = cli.main(["verify", path, "--trust", os.path.join(neg, "trust.json")])
                said = out.getvalue()
                self.assertTrue(said.isascii(), said)
                if code:
                    self.assertNotIn("VERIFIED", said)
                if name in want:
                    self.assertTrue(said.startswith(want[name]), said)


class V1(unittest.TestCase):
    """v1 bundles from an in-process signer: the agent's own user (dev), or another user's (separate-user)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def export(self, peer_uid=None):
        home = os.path.join(self.d, f"home{len(os.listdir(self.d))}")
        s, (pol, raw) = make_signer(home, checkpoint_every=1000), policy.load()
        for n, e in enumerate([run_start("r1", pol), tool_call("t1", "pytest -q"), ev("run.end", {"reason": "done"})]):
            self.assertTrue(s.handle({"op": "append", "cseq": n, "event": e,
                                      **({"attach": {"policy": raw}} if n == 0 else {})}, peer_uid)["ok"])
        out = os.path.join(home, "run.tkb")
        bundle.export(home, out)
        return out, os.path.join(home, "ledger", "signer.pub")

    def test_a_dev_bundle_is_not_proof_against_the_agent(self):
        out, key = self.export()
        code, said = verify(out, "--key", key)
        n = bundle.verify(out, trusted_key=key)[0].events
        first, warned, rest = said.split("\n", 2)
        self.assertEqual((code, first, rest), (0, f"VERIFIED: {n} recorded actions, none changed after signing.", DEV))
        self.assertTrue(warned.startswith("Warnings: signing key, ") and warned.endswith(". Add --detail to read them."),
                        warned)

    def test_another_users_signer_is_proof_only_with_its_key_pinned(self):
        out, key = self.export(peer_uid=os.getuid() + 1)   # the signer stamps the agent's user as not its own
        code, pinned = verify(out, "--key", key)
        self.assertEqual(code, 0, pinned)
        self.assertTrue(pinned.endswith("\nPROOF AGAINST THE AGENT: the signing key was out of the agent's reach "
                                        "(separate-user).\n"), pinned)
        code, unpinned = verify(out)   # the bundle's own word about its signer: nothing outside it vouches for that
        self.assertEqual(code, 0, unpinned)
        self.assertTrue(unpinned.startswith("VERIFIED BUT UNANCHORED: ") and unpinned.endswith("\n" + UNANCHORED),
                        unpinned)
        self.assertNotIn("PROOF AGAINST", unpinned)

    def test_mixed_isolation_shows_the_weakest(self):
        anchored = type("Rep", (), {"isolation": {}, "checks": []})()
        for assurance, want in (
                ("signer_isolation=remote, separate-user (stamped by the signer since 0.3.0; earlier bundles: "
                 "client-reported)", "PROOF AGAINST THE AGENT: the signing key was out of the agent's reach "
                                     "(separate-user)."),
                ("signer_isolation=None, separate-user (stamped by the signer since 0.3.0; earlier bundles: "
                 "client-reported)", "NOT SHOWN: the signer did not record that the signing key was out of the "
                                     "agent's reach (isolation: not recorded).")):
            with self.subTest(assurance):
                self.assertEqual(protection(anchored, assurance, False)[0], want)

    def test_a_tampered_bundle_says_where_it_breaks(self):
        out, key = self.export()
        seq = []

        def edit(files, _manifest):   # the recorded command rewritten, as `tracekit demo` does
            records = [json.loads(line) for line in files["records.jsonl"].decode().splitlines()]
            call = next(r["event"] for r in records if r["event"]["type"] == "tool.call")
            call["data"]["input"]["command"]["value"] = "echo tests skipped"
            seq.append(call["seq"])
            files["records.jsonl"] = "".join(json.dumps(r) + "\n" for r in records).encode()
        bad = os.path.join(self.d, "tampered.tkb")
        rewrite_bundle(out, bad, edit)
        self.assertEqual(verify(bad, "--key", key), (1, f"TAMPERED at event {seq[0]}: its content was changed after it "
                                                        "was signed.\nAdd --detail to see each check.\n"))


if __name__ == "__main__":
    unittest.main()
