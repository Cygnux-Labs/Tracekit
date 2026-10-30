"""The technical report's tables are generated from eval/results/*.json and must not drift from them; `tracekit report`
summarises a window of a signer's store on one page."""
import argparse
import collections
import contextlib
import io
import json
import os
import re
import shlex
import socket
import sys
import time
import unittest
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from factories import patch_env, wait_for  # noqa: E402
from report import tables  # noqa: E402
from test_signer_service import tmpdir  # noqa: E402
from tracekit import cli, report as weekly, view  # noqa: E402
from tracekit.format import canon  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.sdk import autospawn  # noqa: E402
from tracekit.sdk.client import Client, Incompatible  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.pipeline import SIGNER_RUN  # noqa: E402


class Report(unittest.TestCase):
    def setUp(self):
        with open(tables.REPORT) as f:
            self.text = f.read()

    def test_tables_match_the_eval_results(self):
        self.assertEqual(tables.render(self.text), self.text, "run python3 report/tables.py")

    def test_a_hand_edited_number_is_caught(self):
        edited = self.text.replace("| 30/30 |", "| 29/30 |", 1)
        self.assertNotEqual(edited, self.text)
        self.assertNotEqual(tables.render(edited), edited)

    def test_an_e8_case_the_signer_failed_to_refuse_says_so(self):
        # a case answered by the signer, not a hook: its success sentence must not stand in for a failure
        row = tables.e8({"E8v2.5": {"caught": False, "meaning": "the agent's own approve is refused"},
                         "E8v2.2": {"caught": False, "hook_exit_code": None}, "_gate": {"passed": False}})
        self.assertIn("| E8v2.5 | **no** | not refused |", row)
        self.assertIn("| E8v2.2 | **no** | not refused |", row)

    def test_every_table_is_in_the_report(self):
        self.assertEqual(sorted(re.findall(r"<!-- table (\S+) -->", self.text)), sorted(tables.TABLES))

    def test_relative_links_resolve(self):
        for link in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", self.text):
            if not link.startswith(("http://", "https://")):
                self.assertTrue(os.path.exists(os.path.join(ROOT, "report", link)), link)


POLICY = """description: report test
deny:
  - {id: T-RM, tool: rm, pattern: '^', reason: deleting files}
ask:
  - {id: T-PAY, tool: pay, pattern: '^', reason: paying money}
flag:
  - {id: T-NET, tool: Bash, pattern: curl, reason: reaching the network}
  - {id: T-PATH, tool: rm, pattern: path, reason: a path}
"""
SECRET = "ghp_" + "Zx9" * 12   # a GitHub token: redaction changes the call's arguments, so they are never shown
BETA = CallerIdentity("uid", "999003", True)


class OtherProtocol:
    """A running dev signer of another protocol version."""

    def content_get(self, req):
        raise Incompatible("protocol 99")


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class WeeklyReport(unittest.TestCase):
    """`tracekit report` over a real signer's store: a run before the window; in it a run with a flag, a deny, holds
    approved, rejected and left to expire, a call whose arguments hold a secret and a lost transcript reader; an open
    run of another tenant; and a run whose record is edited afterwards."""

    def setUp(self):
        d = tmpdir(self)
        with open(os.path.join(d, "policy.yaml"), "w") as f:
            f.write(POLICY)
        self.cfg = {"data_dir": os.path.join(d, "data"), "socket": os.path.join(d, "s.sock"), "grace_s": 0,
                    "approvals": {"self_approval": "allow"}, "policy": os.path.join(d, "policy.yaml"),
                    "tenants": {f"{BETA.scheme}:{BETA.subject}": "beta"}, **svc.dev_content()}
        self.service = svc.open_service(self.cfg)
        self.addCleanup(self.service.close)
        for srv in svc.serve(self.cfg, self.service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.client = Client(self.cfg["socket"])
        self.addCleanup(self.client.close)
        self.before = self.finished("claude-code", ("Read", {"file_path": "README.md"}))
        self.cut = time.time()
        b = self.client.run(agent="claude-code")
        for tcid, tool, args in (("c1", "Bash", {"command": "curl -s https://example.com"}), ("c2", "rm", {"path": "x"}),
                                 ("c3", "Bash", {"command": f"curl -H 'Authorization: token {SECRET}' https://api"})):
            if b.decide(tcid, tool, args)["decision"] != "deny":
                b.complete(tcid)
        # three different payments: an approved approval nothing used yet would let the same payment's next call run
        for tcid, cents, answer in (("c4", 5, "approve"), ("c5", 6, "reject"), ("c6", 7, None)):
            self.assertEqual(b.decide(tcid, "pay", {"cents": cents})["decision"], "ask")
            aid = b.call("approval_request", tool_call_id=tcid)["approval_id"]
            if answer:
                self.client.call("approval_decide", {"approval_id": aid, "decision": answer})
        # approve, then retry: the hook blocked c4 at once, and the agent's retry (a new call id) ran under its approval
        self.assertEqual(b.decide("c7", "pay", {"cents": 5})["decision"], "ask")
        hint = b.call("approval_request", tool_call_id="c7")["approval_id"]
        self.assertTrue(b.approval_consume("c7", "pay", {"cents": 5}, approval_id_hint=hint)["ok"])
        b.complete("c7")
        b.call("tailer_lost", reason="transcript rotated", offset=10)
        b.close()
        self.busy = b.run_id
        beta = self.service.call(BETA, "register_run", {"request_id": "r1", "agent": {"name": "codex"}})
        self.service.call(BETA, "decide", {"request_id": "r2", "run_id": beta["run_id"], "run_token": beta["run_token"],
                                           "stream": "s", "client_seq": 0, "tool_call_id": "b1", "tool": "Read",
                                           "args_source": "parsed", "args": {"file_path": "a.py"}})
        self.open = beta["run_id"]
        self.edited = self.finished("cursor", ("Glob", {"pattern": "*.md"}))

    def finished(self, agent, call):
        """A run of one call, closed; its id once its run.final is checkpointed."""
        run = self.client.run(agent=agent)
        run.decide("x1", *call)
        run.complete("x1")
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] ==
                                 "run.final" and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        return run.run_id

    def build(self, since=None, until=None, cfg=None, **kw):
        return weekly.build(cfg or self.cfg, self.cut if since is None else since,
                            time.time() + 60 if until is None else until, **kw)

    def command(self, *args):
        """(exit code, stdout, stderr) of `tracekit report` on the store, from just before the window."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["report", "--data-dir", self.cfg["data_dir"], "--since",
                             time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.cut - 1)), *args])
        return code, out.getvalue(), err.getvalue()

    def edit(self, pick, **fields):
        """With the signer stopped, set `fields` in the event of each record `pick(event)` chooses and keep its stored
        hash, as the agent's own user can in dev mode; the seqs of the records edited."""
        self.service.close()
        path = os.path.join(self.cfg["data_dir"], "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        seqs = []
        for i, line in enumerate(lines):
            rec = json.loads(line)
            if pick(rec["event"]):
                rec["event"].update(fields)
                lines[i] = json.dumps(rec, separators=(",", ":"))
                seqs.append(i)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return seqs

    def test_counts_holds_rules_gaps_and_integrity(self):
        rep = self.build(content=view.dev_content_source("tracekit report", lambda: Client(self.cfg["socket"])))
        self.assertEqual({(x["run_id"], x["agent"], x["verdict"], x["state"]) for x in rep["runs"]},
                         {(self.busy, "claude-code", "verified", "final"), (self.open, "codex", "verified", "open"),
                          (self.edited, "cursor", "verified", "final")})
        self.assertEqual(rep["by_agent"], {"claude-code": 1, "codex": 1, "cursor": 1})
        self.assertEqual(rep["by_identity"], {f"uid:{os.getuid()} (attested)": 2, "uid:999003 (attested)": 1})
        self.assertEqual(rep["calls"], {"total": 9, "allow": 2, "flag": 2, "ask": 4, "deny": 1})
        holds = rep["holds"]
        # a held call and the agent's retry that ran under its approval were two holds, "approved" and "approved · ran"
        self.assertEqual((holds["total"], holds["outcomes"], holds["retries"]),
                         (3, {"approved · ran": 1, "rejected": 1, "expired": 1}, 1))
        # the run's own user answered its calls (self_approval: allow); a rejection is no self-approval
        self.assertEqual(holds["answered_by"], {f"uid:{os.getuid()} (attested) · self-approved": 1,
                                                f"uid:{os.getuid()} (attested)": 1})
        self.assertEqual((holds["longest_wait"]["tool"], holds["longest_wait"]["run_id"]), ("pay", self.busy))
        # holds had no example calls, as denies and flags have: one of each outcome
        self.assertEqual({o: (x["call"], x["run_id"]) for o, x in holds["examples"].items()},
                         {o: (f'pay {{"cents":{c}}}', self.busy)
                          for o, c in (("approved · ran", 5), ("rejected", 6), ("expired", 7))})
        self.assertEqual([(g["decision"], g["rule"], g["why"], g["reason"], g["count"],
                           [x["call"] for x in g["examples"]]) for g in rep["rules"]],
                         [("flag", "T-NET", True, "reaching the network", 2,
                           ["Bash curl -s https://example.com", f"Bash · {weekly.NO_ARGS}"]),
                          ("deny", "T-PATH", False, "a path", 1, []),   # a flag rule: not why rm was denied
                          ("deny", "T-RM", True, "deleting files", 1, ['rm {"path":"x"}'])])
        self.assertEqual(rep["gaps"]["by_kind"], {"tailer_lost": 1})
        page = weekly.text(rep)
        # a run id a person copies is a whole one: tracekit export --v2 --run takes no prefix
        for line in ("Tool calls: 9   allow 2, flag 2, ask 4, deny 1",
                     "Holds (calls held for a person): 3   approved · ran 1, rejected 1, expired 1",
                     "  and 1 of the agent's retries of a held call, under its approval: counted with it",
                     f"  answered by: uid:{os.getuid()} (attested) · self-approved 1, uid:{os.getuid()} (attested) 1",
                     f'  e.g. rejected: pay {{"cents":6}}  (run {self.busy})',
                     "Denied calls (1), by rule (one call can match several rules):",
                     "  T-RM  1  deleting files", "  also matched (not why it was denied): T-PATH 1",
                     "Flagged calls (2), by rule (one call can match several rules):",
                     f"      e.g. Bash curl -s https://example.com  (run {self.busy})",
                     "  tailer_lost 1: the transcript reader stopped: model messages may be missing",
                     f"  most: run {self.busy} (claude-code) 1",
                     "Integrity: 3 of 3 runs verify (assurance: dev)",
                     f"  open     run {self.open} (codex): verified to its latest checkpoint",
                     "  tracekit export --v2 --run <run id> -o run.tkb", "  tracekit signer trust -o trust.json"):
            self.assertIn(line + "\n", page + "\n")
        self.assertNotIn(SECRET, page + json.dumps(rep))   # nor any part of it the redaction left
        self.assertNotIn(SECRET[4:20], page + json.dumps(rep))

    def test_rules_read_the_policy_the_signer_kept(self):
        """On a store decided under a policy this Tracekit doesn't ship (an older pack, the signer's own file), every
        rule had no description, and a flag rule that also matched a denied call was counted as why it was denied: the
        signer keeps each policy it ran in data_dir/policies, named by the SHA-256 of its bytes. A policy it can't read
        places no rule: every rule that matched a denied call was counted as why it was denied."""
        cfg = {k: v for k, v in self.cfg.items() if k != "policy"}
        rules = lambda rep: {(g["decision"], g["rule"], g["reason"], g["why"]) for g in rep["rules"]}   # noqa: E731
        rep = self.build(cfg=cfg)
        self.assertEqual(rules(rep), {("flag", "T-NET", "reaching the network", True),
                                      ("deny", "T-RM", "deleting files", True), ("deny", "T-PATH", "a path", False)})
        self.assertEqual(rep["notes"], [])
        kept = os.path.join(cfg["data_dir"], "policies")
        [name] = os.listdir(kept)
        with open(os.path.join(kept, name), encoding="utf-8") as f:
            pol = f.read()
        with open(os.path.join(kept, name), "w", encoding="utf-8") as f:   # no longer the policy its name says
            f.write(pol.replace("deleting files", "tidying up"))
        rep = self.build(cfg=cfg)
        self.assertEqual(rules(rep), {("flag", "T-NET", "", None), ("deny", "T-RM", "", None),
                                      ("deny", "T-PATH", "", None)})
        page = weekly.text(rep)
        self.assertIn("Denied calls (1), by rule (one call can match several rules):\n  not placed (engine checks, which "
                      "may be why, and rules of a policy this report can't read): T-PATH 1, T-RM 1\n", page)
        self.assertIn("Note: 1 denied call cites a policy this report can't read", page)
        self.assertIn("Note: 2 flagged calls cite a policy this report can't read", page)

    def test_holds_are_what_became_of_them_and_answers_are_of_holds_in_the_window(self):
        """A hold kept its first answer, so an approval whose use was refused (other arguments) read approved; and an
        answer in the window to a hold asked before it was counted under answered by, though Holds didn't count it."""
        b = self.client.run(agent="claude-code")
        for tcid, cents in (("d1", 8), ("d2", 9)):
            self.assertEqual(b.decide(tcid, "pay", {"cents": cents})["decision"], "ask")
        first = b.call("approval_request", tool_call_id="d1")["approval_id"]
        late = b.call("approval_request", tool_call_id="d2")["approval_id"]
        self.client.call("approval_decide", {"approval_id": first, "decision": "approve"})
        self.assertFalse(b.approval_consume("d1", "pay", {"cents": 80})["ok"])   # not the approved arguments
        time.sleep(0.05)
        cut = time.time()
        time.sleep(0.05)
        self.client.call("approval_decide", {"approval_id": late, "decision": "approve"})
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        mine = lambda rep: [x for x in rep["runs"] if x["run_id"] == b.run_id]   # noqa: E731
        rep = self.build()
        self.assertEqual(mine(rep)[0]["verdict"], "verified")
        self.assertEqual(rep["holds"]["outcomes"], {"approved · ran": 1, "rejected": 1, "expired": 1, "approved": 1,
                                                    "refused: arguments changed": 1})
        rep = self.build(since=cut)
        self.assertEqual([x["calls"] for x in mine(rep)], [{}])   # in the window by d2's answer, but no call in it
        self.assertEqual((rep["holds"]["total"], rep["holds"]["answered_by"]), (0, {}))
        self.assertNotIn("answered by", weekly.text(rep))

    def test_a_run_whose_record_times_were_edited_is_listed_failed_whatever_its_times(self):
        """Runs were placed in the window by record times read from the store unverified: in dev mode the agent's
        user can move a run's last record out of the window, and the report said every run verified while tracekit
        view showed that run FAILED. With its hash rewritten too, the checkpoint's tree no longer holds the record,
        and no record of the store can place a run."""
        self.service.close()
        path = os.path.join(self.cfg["data_dir"], "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        [i] = [n for n, line in enumerate(lines)
               if (json.loads(line)["event"]["run_id"], json.loads(line)["event"]["type"]) == (self.edited, "run.final")]
        rec = json.loads(lines[i])
        rec["event"]["ts"] = "2001-01-01T00:00:00.000000Z"

        def write():
            lines[i] = json.dumps(rec, separators=(",", ":"))
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        write()
        rep = self.build()
        self.assertEqual({x["run_id"]: x["verdict"] for x in rep["runs"]},
                         {self.busy: "verified", self.open: "verified", self.edited: "failed"})
        self.assertEqual(rep["by_agent"], {"claude-code": 1, "codex": 1})   # only runs that verify name an agent
        page = weekly.text(rep)
        self.assertIn("\nRuns: 3   by agent (the 2 that verify): ", page)
        for line in ("Integrity: the store FAILED; 2 of 3 runs verify (assurance: dev)",
                     f"  FAILED   run {self.edited} (cursor): record {i} {weekly.EDITED}"):
            self.assertIn(line + "\n", page)
        rec["hash"] = canon.event_hash(rec["event"])
        write()
        rep = self.build()
        self.assertEqual({x["run_id"]: x["verdict"] for x in rep["runs"]},
                         {r: "failed" for r in (self.before, self.busy, self.open, self.edited)})
        self.assertEqual({x["detail"] for x in rep["runs"]}, {weekly.STORE_FAILED})
        page = weekly.text(rep)
        for line in ("Integrity: the store FAILED; 0 of 4 runs verify",
                     "  FAILED   the store: its records' hashes don't make the root of the signer's checkpoint: a "
                     "record's hash was rewritten"):
            self.assertIn(line + "\n", page)

    def test_a_run_renamed_to_the_signer_run_is_listed_failed(self):
        """The report skipped every run named tracekit/signer, in any tenant, unchecked, and a file store files a record
        under the run_id its event holds: in dev mode the agent's user renamed a run's records to the signer's run,
        keeping their hashes, and the report left out the run and its deny, said every run verified and exited 0."""
        first = self.edit(lambda e: e["run_id"] == self.busy, run_id=SIGNER_RUN[1])
        rep = self.build()
        self.assertEqual({(x["tenant"], x["run_id"]): x["verdict"] for x in rep["runs"]},
                         {("default", SIGNER_RUN[1]): "failed", ("beta", self.open): "verified",
                          ("default", self.edited): "verified"})
        self.assertEqual(rep["calls"]["deny"], 0)   # its deny is in a run that fails: listed, not counted
        self.assertEqual(rep["store"]["verdict"], "failed")
        page = weekly.text(rep)
        for line in ("Integrity: the store FAILED; 2 of 3 runs verify (assurance: dev)",
                     f"  FAILED   the store: {len(first)} records edited (a record's hash doesn't match its event): each "
                     "run holding one is listed FAILED",
                     f"  FAILED   run {SIGNER_RUN[1]}, tenant default (claude-code): record {first[0]} {weekly.EDITED}"):
            self.assertIn(line + "\n", page)
        code, out, _ = self.command()
        self.assertEqual(code, 1)
        self.assertIn(f"  FAILED   run {SIGNER_RUN[1]}, tenant default (claude-code): ", out)

    def test_a_run_moved_to_another_tenant_is_listed_failed_with_or_without_tenant(self):
        """With --tenant the report skipped every other tenant's run unchecked: a run whose records' tenant was edited,
        keeping their hashes, left its own tenant's report, which said every run verified and exited 0."""
        first = self.edit(lambda e: e["run_id"] == self.busy, tenant="beta")[0]
        for tenant, verdicts, where in ((None, {self.busy: "failed", self.open: "verified", self.edited: "verified"}, ""),
                                        ("default", {self.busy: "failed", self.edited: "verified"}, ", tenant beta")):
            with self.subTest(tenant=tenant):
                rep = self.build(tenant=tenant)
                self.assertEqual({x["run_id"]: x["verdict"] for x in rep["runs"]}, verdicts)
                self.assertEqual(rep["calls"]["deny"], 0)
                page = weekly.text(rep)
                self.assertIn(f"Integrity: the store FAILED; {len(verdicts) - 1} of {len(verdicts)} runs verify", page)
                self.assertIn(f"  FAILED   run {self.busy}{where} (claude-code): record {first} {weekly.EDITED}\n", page)
                self.assertEqual(self.command(*(("--tenant", tenant) if tenant else ()))[0], 1)

    def test_an_edited_record_of_a_tenants_signer_run_is_listed_failed(self):
        """A tenant's signer run (its content reads, suspensions and incidents) was never checked: an edit of one of its
        records left the report saying every run verified."""
        self.build(content=view.dev_content_source("tracekit report", lambda: Client(self.cfg["socket"])))
        seq = self.edit(lambda e: e["type"] == "content.accessed", ts="2001-01-01T00:00:00.000000Z")[0]
        rep = self.build()
        self.assertEqual({(x["tenant"], x["run_id"]): x["verdict"] for x in rep["runs"]},
                         {("default", SIGNER_RUN[1]): "failed", ("default", self.busy): "verified",
                          ("beta", self.open): "verified", ("default", self.edited): "verified"})
        page = weekly.text(rep)
        self.assertIn("Integrity: the store FAILED; 3 of 4 runs verify (assurance: dev)\n", page)
        self.assertIn(f"  FAILED   run {SIGNER_RUN[1]}, tenant default (?): record {seq} {weekly.EDITED}\n", page)
        self.assertEqual(self.command()[0], 1)

    @pytest.mark.unverified_bundles
    def test_an_edited_record_of_the_signers_own_run_is_listed_failed(self):
        """The signer's own run was never checked: the report didn't name it, though its edited key record failed
        every run, and exited 0."""
        [seq] = self.edit(lambda e: e["type"] == "signer.epoch", ts="2001-01-01T00:00:00.000000Z")
        rep = self.build()
        self.assertEqual({(x["tenant"], x["run_id"]): x["verdict"] for x in rep["runs"]},
                         {(SIGNER_RUN[0], SIGNER_RUN[1]): "failed", ("default", self.busy): "failed",
                          ("beta", self.open): "failed", ("default", self.edited): "failed"})
        page = weekly.text(rep)
        self.assertIn("Integrity: the store FAILED; 0 of 4 runs verify\n", page)
        self.assertIn(f"  FAILED   run {SIGNER_RUN[1]}, tenant {SIGNER_RUN[0]} (?): record {seq} {weekly.EDITED}\n",
                      page)
        self.assertEqual(self.command()[0], 1)

    def test_records_newer_than_the_checkpoint_are_counted_across_the_store(self):
        """Records not counted yet were summed over the runs that verify in the window: a run whose records the
        checkpoint covers all fall before the window, with newer ones in it, was left out and nothing said so."""
        note = os.path.join(self.cfg["data_dir"], "store", "checkpoint.note")
        late = self.client.run(agent="aider")
        late.decide("y1", "Read", {"file_path": "a.py"})
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        with open(note, "rb") as f:
            old = f.read()
        time.sleep(0.05)
        cut = time.time()
        late.complete("y1")
        late.close()
        self.service.close()
        with open(note, "wb") as f:   # the checkpoint before the run's newer records
            f.write(old)
        with open(os.path.join(self.cfg["data_dir"], "store", "records.jsonl"), "rb") as f:
            newer = len(f.read().splitlines()) - int(old.split(b"\n")[1])
        rep = self.build(since=cut)
        self.assertIn(f"  not counted yet: {newer} records in the store newer than the latest checkpoint\n",
                      weekly.text(rep))
        self.assertEqual((rep["runs"], rep["store"]["newer"]), ([], newer))

    def test_a_note_that_is_no_checkpoint_note_says_so(self):
        """A checkpoint.note that isn't one failed with int()'s message, or with a traceback without a line break."""
        self.service.close()
        note = os.path.join(self.cfg["data_dir"], "store", "checkpoint.note")
        for data in (b"garbage", b"origin\nnot a size\nroot\n\n", b"\xff\xfe\n12\n"):
            with self.subTest(data=data):
                with open(note, "wb") as f:
                    f.write(data)
                code, out, err = self.command()
                self.assertEqual((code, out), (1, ""))
                self.assertEqual(err.splitlines()[-1], f"tracekit report: {note} is not a checkpoint note (an origin, "
                                 "a tree size and a root, then signatures): the store was edited or damaged")

    def test_a_signer_of_another_protocol_is_said_in_the_report(self):
        notes = []
        rep = self.build(content=view.dev_content_source("tracekit report", OtherProtocol, notes.append), notes=notes)
        self.assertEqual(rep["notes"], ["calls show their rules, not their arguments: protocol 99"])
        self.assertIn("\nNote: calls show their rules, not their arguments: protocol 99\n", weekly.text(rep))

    def test_the_last_lines_are_commands_that_export_and_verify_a_run(self):
        """They left out --tenant, after --data-dir named a command that exports from the dev signer's store, and said
        to verify with a trust.json that nothing wrote: tracekit export --v2 writes none. With --data-dir they named a
        signer.yaml the person had to write first: export and signer trust take --data-dir too."""
        self.assertIn("\n  tracekit export --v2 --tenant beta --run <run id> -o run.tkb\n",
                      weekly.text(self.build(tenant="beta")))
        page = weekly.text(self.build(), data_dir=self.cfg["data_dir"])
        where = f"--data-dir {shlex.quote(self.cfg['data_dir'])}"
        self.assertIn(f"\n  tracekit export --v2 {where} --run <run id> -o run.tkb\n"
                      f"  tracekit signer trust {where} -o trust.json\nThey check", page)
        self.assertNotIn("signer.yaml", page)
        cwd = tmpdir(self)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(cwd)
        # each command as printed, with a run id copied from the page
        tail = page.split("This is an operator summary")[1].replace("<run id>", self.busy).splitlines()
        commands = [x.strip() for x in tail if x.startswith("  tracekit ")] + [tail[-1].split("then: ")[1]]
        self.assertEqual([c.split()[:2] for c in commands],
                         [["tracekit", "export"], ["tracekit", "signer"], ["tracekit", "verify"]])
        for c in commands:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(shlex.split(c)[1:]), 0, c)

    def test_the_window_and_the_tenant_choose_the_runs(self):
        ids = lambda rep: {x["run_id"] for x in rep["runs"]}   # noqa: E731
        self.assertEqual(ids(self.build(0, self.cut)), {self.before})
        self.assertEqual(ids(self.build(0)), {self.before, self.busy, self.open, self.edited})
        self.assertEqual(ids(self.build(tenant="beta")), {self.open})
        self.assertEqual(ids(self.build(0, tenant="default")), {self.before, self.busy, self.edited})
        self.assertEqual(self.build(tenant="beta")["calls"], {"total": 1, "allow": 1, "flag": 0, "ask": 0, "deny": 0})

    @pytest.mark.unverified_bundles
    def test_a_run_that_fails_verification_is_listed_never_counted(self):
        """A record whose signature fails, its event and hash intact: the store matches its checkpoint, the run's
        check fails it, and the command exits 1."""
        self.service.close()
        path = os.path.join(self.cfg["data_dir"], "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        [i] = [n for n, line in enumerate(lines) if json.loads(line)["event"]["run_id"] == self.edited
               and json.loads(line)["event"]["type"] == "policy.decision"]
        rec = json.loads(lines[i])
        rec["sig"] = rec["sig"][::-1]
        lines[i] = json.dumps(rec, separators=(",", ":"))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        rep = self.build()
        self.assertEqual(rep["store"]["verdict"], "verified")
        [run] = [x for x in rep["runs"] if x["run_id"] == self.edited]
        self.assertEqual((run["verdict"], run["calls"]), ("failed", {}))
        self.assertEqual(rep["calls"]["total"], 8)
        page = weekly.text(rep)
        self.assertIn("Integrity: 2 of 3 runs verify (assurance: dev)\n", page)
        self.assertIn(f"  FAILED   run {self.edited} (cursor): ", page)
        self.assertIn("  a run that doesn't verify is listed, not counted\n", page)
        self.assertEqual(self.command()[0], 1)

    def test_the_command_prints_json_or_text_without_reading_content(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["report", "--data-dir", self.cfg["data_dir"], "--since",
                                       time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.cut - 1)), "--json"]), 0)
        rep = json.loads(out.getvalue())
        self.assertEqual(set(rep), {"window", "source", "trust", "tenant", "store", "runs", "by_agent", "by_identity",
                                    "calls", "holds", "rules", "gaps", "notes", "alerts", "label"})
        self.assertEqual(set(rep["store"]), {"verdict", "detail", "records", "covered", "newer"})
        self.assertEqual(set(rep["runs"][0]), {"tenant", "run_id", "agent", "identity", "first_ts", "last_ts", "state",
                                               "verdict", "detail", "calls", "gaps", "not_covered"})
        self.assertIn("tracekit report is experimental", err.getvalue())
        # --data-dir, as tracekit view: no content vault, so no call shows its arguments
        self.assertEqual({x["call"] for g in rep["rules"] for x in g["examples"]},
                         {f"Bash · {weekly.NO_ARGS}", f"rm · {weekly.NO_ARGS}"})
        self.assertEqual(set(rep["holds"]["examples"]), set(rep["holds"]["outcomes"]))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["report", "--data-dir", self.cfg["data_dir"]]), 0)
        self.assertTrue(out.getvalue().startswith("Tracekit report: "), out.getvalue()[:200])
        self.assertIn("This is an operator summary, not evidence.", out.getvalue())

    def test_a_data_dir_that_isnt_there_is_named(self):
        """`tracekit report --data-dir` with no directory there printed a raw [Errno 2]."""
        nope = os.path.join(self.cfg["data_dir"], "nope")
        for argv in ([], ["--log-vkey", svc.read_vkeys(self.cfg["data_dir"])[0]]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(["report", "--data-dir", nope, *argv])
                self.assertEqual((code, err.getvalue().splitlines()[-1]),
                                 (1, f"tracekit report: no signer data dir at {nope}"))


class Window(unittest.TestCase):
    def test_since_and_until_read_days_hours_and_iso_dates(self):
        self.assertEqual(weekly.when("7d", now=1_000_000), 1_000_000 - 7 * 86400)
        self.assertEqual(weekly.when("24h", now=1_000_000), 1_000_000 - 86400)
        self.assertEqual(weekly.when("2026-10-22"), weekly.when("2026-10-22T00:00:00Z"))
        self.assertEqual(weekly.when("2026-10-22T02:00:00+02:00"), weekly.when("2026-10-22"))
        with self.assertRaises(argparse.ArgumentTypeError):
            weekly.when("last week")


class Rules(unittest.TestCase):
    def test_an_engine_check_is_never_counted_as_why_a_call_was_denied(self):
        """TK-SHELL-PARSE (on_parse_error, an ask by default) has no section: it was counted as why a call that a deny
        rule denied was denied (the docs' own sample listed it under Denied)."""
        pol, errors = view.policy_compile.build(os.path.join(ROOT, "tracekit", "policy2", "packs", "coding.yaml"))
        self.assertEqual(errors, [])
        rec = {"event": {"type": "policy.decision", "run_seq": 4, "ts": "2026-10-29T00:00:00Z", "data": {
            "tool": "Bash", "decision": "deny", "rule_ids": ["TK-D002", "TK-SHELL-PARSE"],
            "policy_hash": view.policy_compile.policy_hash(pol)}}}
        rules, unread = {}, collections.Counter()
        weekly._tally(("default", "r1"), [rec], view.Translator(view.policy_reasons()), rules, unread)
        self.assertEqual({(g["rule"], g["why"], g["reason"]) for g in rules.values()},
                         {("TK-D002", True, "running a downloaded script"),
                          ("TK-SHELL-PARSE", None, "a shell command that does not parse")})
        self.assertEqual(unread["deny"], 0)

    def test_self_approved_and_break_glass_answers_are_marked(self):
        a = {"decision": "approve", "approver": "uid:501 (attested)", "self_approved": False, "break_glass": True}
        self.assertEqual(weekly._answer(a), "uid:501 (attested) · break-glass")
        self.assertEqual(weekly._answer(dict(a, self_approved=True, break_glass=False)),
                         "uid:501 (attested) · self-approved")
        # the requester rejecting their own call was counted as a self-approval
        self.assertEqual(weekly._answer(dict(a, decision="reject", self_approved=True, break_glass=False)),
                         "uid:501 (attested)")


class DevContent(unittest.TestCase):
    def test_a_report_never_starts_or_replaces_the_dev_signer(self):
        """The viewer's content source connects with Client(), which starts the dev signer when none runs and stops
        one of an older Tracekit: a report reads the content of a signer already running, else none."""
        patch_env(self, TRACEKIT_RUNTIME_DIR=os.path.join(tmpdir(self), "none"), TRACEKIT_SIGNER=None)
        recs = [{"event": {"log_id": "0" * 32, "seq": 1, "run_id": "r1", "run_seq": 1, "type": "policy.decision",
                           "data": {"tool": "Bash", "args_commitment": "hmac-sha256:a"}}, "hash": "sha256:1"}]
        with mock.patch.object(autospawn, "spawn") as spawn:
            self.assertEqual(view.dev_content_source("tracekit report", weekly._running)("r1", recs), {})
        spawn.assert_not_called()
        notes = []
        read = view.dev_content_source("tracekit report", OtherProtocol, notes.append)
        self.assertEqual((read("r1", recs), read("r1", recs)), ({}, {}))
        self.assertEqual(notes, ["calls show their rules, not their arguments: protocol 99"])   # said once
        # Windows: an endpoint.json without a port and token is no running signer, not an error of the report
        with mock.patch.object(autospawn, "address", side_effect=ValueError("endpoint.json has no port and token yet")):
            self.assertEqual(view.dev_content_source("tracekit report", weekly._running)("r1", recs), {})


if __name__ == "__main__":
    unittest.main()
