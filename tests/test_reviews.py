"""Signed findings (`tracekit analyze --v2`, #309): the review_finding RPC signs a `review` record in a findings run
only, with a closed verdict that holds no text of the run, and the verifier checks each finding's citations against the
analysed run and labels its author (docs/verdicts.md#reviews). tests/test_ts_verifier.py runs the same bundles through
the TypeScript verifier."""
import json
import os
import shutil
import tempfile
import time
import unittest
import uuid
from unittest import mock

from factories import unverified_bundles
from test_bundle_v2 import KEY1, LOG_SECRET, ORIGIN, Log, pub, trust_config
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.checkpoint import ED25519
from tracekit.identity.base import CallerIdentity
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import FINDING_TITLES, RPCError
from tracekit.verify import v2

ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)   # the signer's own user
AGENT = CallerIdentity("uid", "999999", True)
ANALYZER = CallerIdentity("uid", "999002", True)
FINDING = {"kind": "finding", "rule": "TK-X202", "severity": "medium", "tier": "gateway", "order": "signed_before",
           "redacted": False, "digests": ["sha256:" + "ab" * 32]}
COVERAGE = {"kind": "coverage", "rule": "TK-X200", "severity": "info", "partial": False,
            "checks": {"TK-X201": {"checked": 3, "found": 1, "not_checkable": [{"reason": "withheld", "n": 1}]}},
            "reasoning": {"full": 1, "summary": 1, "withheld": 1, "none": 0}}


class Signed(unittest.TestCase):
    """An in-process signer whose analyzers are ANALYZER and, to show self-assertion, the agent AGENT."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.s = svc.SignerService(os.path.join(self.dir, "data"), grace_s=0, fsck_every_s=0,
                                   analyzers=[f"uid:{ANALYZER.subject}", f"uid:{AGENT.subject}"])
        self.addCleanup(self.s.close)

    def call(self, who, method, **req):
        return self.s.call(who, method, {"request_id": uuid.uuid4().hex, **req})

    def register(self, who, **kw):
        r = self.call(who, "register_run", agent={"name": "a"}, **kw)
        return {"run_id": r["run_id"], "run_token": r["run_token"]}

    def agent_run(self, who=AGENT):
        run = self.register(who)
        self.call(who, "decide", **run, stream="s", client_seq=0, tool_call_id="tc-1", tool="read_file",
                  args_source="parsed", args={})
        self.call(who, "close_run", **run)
        return run

    def cites(self, run):
        """Citations of every record of `run` so far."""
        return [{"run_seq": r["event"]["run_seq"], "hash": r["hash"]}
                for r in self.s.log.storage.iter_run("default", run["run_id"])]

    def review(self, who, findings, verdict=FINDING, cites=(), **kw):
        return self.call(who, "review_finding", **findings, review={
            "reviewer": "tracekit-analyze/1.4.0", "verdict": verdict, "cites": list(cites), **kw})

    def findings(self, who, run, cites=None, verdict=FINDING):
        """A closed findings run of `who` about `run`, with one signed finding citing `cites` (default: all of it)."""
        f = self.register(who, analyzes=run["run_id"])
        self.review(who, f, verdict, self.cites(run) if cites is None else cites)
        self.call(who, "close_run", **f)
        return f

    def export(self, run, *with_runs, analyzers=()):
        """(bundle, trust config pinning `analyzers`) of `run` with the findings runs `with_runs`."""
        self.s.sweep(time.monotonic() + 1)
        store = self.s.log.storage
        size = store.tree.size
        text = checkpoint.body(ORIGIN, size, store.tree.root_at(size))
        name = uuid.uuid4().hex
        out, trust = os.path.join(self.dir, f"{name}.tkb"), os.path.join(self.dir, f"{name}.trust.json")
        export(store, "default", run["run_id"], text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET), out,
               with_runs=[r["run_id"] for r in with_runs])
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))], "algs": ["ed25519"],
                       **({"analyzers": list(analyzers)} if analyzers else {})}, f)   # without: 1.3's verifier reads it
        return out, trust

    def bundles(self):
        """{name: (bundle, trust)}: a signed finding of each author label, one whose analysed run is absent, an imported
        review, and one citing a record its run does not have and one with another hash."""
        run, mine = self.agent_run(), self.agent_run(ME)
        independent, self_ = self.findings(ANALYZER, run), self.findings(AGENT, run)
        same_user = self.findings(ANALYZER, mine)
        cited = self.cites(run)
        bad = self.findings(ANALYZER, run, [dict(cited[0], hash="sha256:" + "0" * 64), dict(cited[1], run_seq=99)])
        out = {"independent": self.export(run, independent, analyzers=[f"uid:{ANALYZER.subject}"]),
               "unpinned": self.export(run, independent),
               "self-asserted": self.export(run, self_, analyzers=[f"uid:{AGENT.subject}"]),
               "alone": self.export(independent, analyzers=[f"uid:{ANALYZER.subject}"]),
               "mismatch": self.export(run, bad)}
        if hasattr(os, "getuid"):   # Windows measures no same-user isolation
            out["same-user"] = self.export(mine, same_user, analyzers=[f"uid:{ANALYZER.subject}"])
        log = Log(os.path.join(self.dir, "imported"))
        self.addCleanup(log.store.close)
        log.epoch(KEY1)
        log.register()
        log.add("review", {"reviewer": "judge", "verdict": {"aligned": True}})   # a migrated v1 judge verdict
        log.final()
        out["imported"] = (os.path.join(self.dir, "imported.tkb"), os.path.join(self.dir, "imported.trust.json"))
        export(log.store, "acme", "run-a", log.note(), out["imported"][0])
        with open(out["imported"][1], "w") as f:
            json.dump(trust_config(), f)
        return out


def reviews(rep):
    return {c["check"]: c for c in rep.checks if c["check"].startswith("reviews")}


class TestReviewFinding(Signed):
    def test_refused_outside_a_findings_run_and_for_an_identity_not_in_analyzers(self):
        run = self.agent_run()
        with self.assertRaises(RPCError) as e:
            self.review(AGENT, self.register(AGENT))   # the agent's own run is no findings run
        self.assertEqual(e.exception.code, "forbidden")
        self.assertIn("a review goes in a findings run", e.exception.message)
        with self.assertRaises(RPCError) as e:
            self.register(CallerIdentity("uid", "999003", True), analyzes=run["run_id"])
        self.assertEqual(e.exception.code, "forbidden")
        with self.assertRaises(RPCError) as e:   # nor through the run token of another identity's findings run
            self.review(ME, self.register(ANALYZER, analyzes=run["run_id"]))
        self.assertEqual(e.exception.code, "run_token_invalid")

    def test_signed_in_a_findings_run_with_the_rules_fixed_title(self):
        run = self.agent_run()
        f = self.register(ANALYZER, analyzes=run["run_id"])
        req = {"request_id": "r-1", **f, "review": {"reviewer": "tracekit-analyze/1.4.0", "verdict": FINDING,
                                                    "cites": self.cites(run)}}
        seq = self.s.call(ANALYZER, "review_finding", req)["run_seq"]
        self.assertEqual(self.s.call(ANALYZER, "review_finding", req)["run_seq"], seq)   # a retry: the same record
        self.assertEqual(self.review(ANALYZER, f, COVERAGE)["run_seq"], seq + 1)
        records = [r["event"] for r in self.s.log.storage.iter_run("default", f["run_id"])]
        self.assertEqual(records[0]["data"]["identity"]["subject"], ANALYZER.subject)   # the author, as measured
        self.assertEqual([(e["type"], e["data"]) for e in records[seq:]], [
            ("review", {"reviewer": "tracekit-analyze/1.4.0", "cites": self.cites(run),
                        "verdict": {**FINDING, "title": FINDING_TITLES["TK-X202"]}}),
            ("review", {"reviewer": "tracekit-analyze/1.4.0", "cites": [],
                        "verdict": {**COVERAGE, "title": "Check coverage"}})])

    def test_the_closed_verdict_takes_no_text_of_the_run(self):
        run = self.agent_run()
        f = self.register(ANALYZER, analyzes=run["run_id"])
        text = "the agent edited billing.py after saying it would not"
        for name, verdict, cites, extra in (
                ("free text in the verdict", {**FINDING, "detail": text}, [], {}),
                ("a title of its own", {**FINDING, "title": text}, [], {}),
                ("a reason beside the verdict", FINDING, [], {"reason": text}),
                ("an excerpt in a cite", FINDING, [{"run_seq": 0, "hash": "sha256:" + "0" * 64, "excerpt": text}], {}),
                ("a rule that is no check", {**FINDING, "rule": "TK-X999"}, [], {}),
                ("a coverage rule on a finding", {**FINDING, "rule": "TK-X200"}, [], {}),
                ("a check of no rule in coverage", {**COVERAGE, "checks": {text: {"checked": 1, "found": 0}}}, [], {}),
                ("a reason that is text", {**COVERAGE, "checks": {"TK-X201": {
                    "checked": 1, "found": 0, "not_checkable": [{"reason": text, "n": 1}]}}}, [], {}),
                ("a digest that is text", {**FINDING, "digests": [text]}, [], {})):
            with self.subTest(name), self.assertRaises(RPCError) as e:
                self.review(ANALYZER, f, verdict, cites, **extra)
            self.assertEqual(e.exception.code, "invalid_request")
        with self.assertRaises(RPCError) as e:
            self.call(ANALYZER, "review_finding", **f, review={"reviewer": text, "verdict": FINDING, "cites": []})
        self.assertEqual(e.exception.code, "invalid_request")


class TestVerify(Signed):
    @unverified_bundles   # `mismatch` cites what its analysed run does not hold, on purpose
    def test_citations_and_author_labels(self):
        b = self.bundles()
        want = {"independent": ("pass", "1 review(s): 1 independent"),
                "unpinned": ("pass", f"1 review(s): 1 unpinned author uid:{ANALYZER.subject}"),
                "self-asserted": ("warn", "1 review(s): 1 self-asserted"),
                "same-user": ("warn", "1 review(s): 1 self-asserted"),
                "alone": ("pass", "1 review(s): 1 author not checked"),
                "imported": ("pass", "1 review(s): 1 imported"),
                "mismatch": ("fail", "1 review(s): 1 unpinned author uid:999002")}
        for name, (bundle, trust) in b.items():
            with self.subTest(name):
                rep, code = v2.verify(bundle, trust)
                self.assertEqual((reviews(rep)["reviews"]["status"], reviews(rep)["reviews"]["detail"]), want[name])
                self.assertEqual(code, 1 if name == "mismatch" else 0, rep.checks)
        rep, _ = v2.verify(*b["self-asserted"])
        self.assertEqual(reviews(rep)["reviews"]["problems"],
                         [f"findings run {rep_run(b['self-asserted'][0])}: its author uid:{AGENT.subject} is the "
                          "analysed run's identity"])
        if "same-user" in b:
            rep, _ = v2.verify(*b["same-user"])
            self.assertIn("signer_isolation same-user", reviews(rep)["reviews"]["problems"][0])
        rep, _ = v2.verify(*b["alone"])
        self.assertEqual(reviews(rep)["reviews counted"]["status"], "warn")
        rep, _ = v2.verify(*b["mismatch"])
        self.assertEqual(rep.failures, ["reviews"])
        self.assertEqual([p.split(": ", 1)[1] for p in reviews(rep)["reviews"]["problems"]],
                         [f"cites run_seq 0 of run {rep_run(b['independent'][0], analysed=True)}, whose hash differs",
                          f"cites run_seq 99 of run {rep_run(b['independent'][0], analysed=True)}, which it does not "
                          "have"])

    def test_a_signed_finding_needs_format_1_4_and_older_verifiers_say_unverifiable(self):
        run = self.agent_run()
        bundle, trust = self.export(run, self.findings(ANALYZER, run))
        with open(bundle, "rb") as f:
            self.assertEqual(json.loads(v2.read_zip(f)["manifest.json"])["verifier_min_version"], "1.4.0")
        with mock.patch.object(v2, "__version__", "1.3.0"):
            rep, code = v2.verify(bundle, trust)
        self.assertEqual((code, rep.integrity), (2, "UNVERIFIABLE (needs tracekit >= 1.4.0)"))
        self.assertEqual(reviews(rep), {})

    def test_the_analyzers_pin_is_identities(self):
        run = self.agent_run()
        bundle, trust = self.export(run, analyzers=["999002"])   # no scheme
        rep, code = v2.verify(bundle, trust)
        self.assertEqual((code, rep.checks[0]["check"]), (2, "trust config"))


def rep_run(bundle, analysed=False):
    """The run id of the findings run (or with `analysed`, of the analysed run) in `bundle`."""
    with open(bundle, "rb") as f:
        files = v2.read_zip(f)
    firsts = [json.loads(files[n].split(b"\n", 1)[0])["event"] for n in files if n.startswith("runs/")]
    return next(e["run_id"] for e in firsts if ("analyzes" in e["data"]) != analysed)


if __name__ == "__main__":
    unittest.main()
