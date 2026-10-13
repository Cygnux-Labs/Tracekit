"""`tracekit view`: the v2 signer's runs, each verified by verify.v2, served with the observer's page and security."""
import collections
import contextlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import unittest
import urllib.request
from unittest import mock

import test_signer_service as ts
from factories import wait_for
from test_observe_render import XSS, script_of, unescaped
from tracekit import cli, observe, view
from tracekit.observe import _session
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage
from tracekit.why.core import GENESIS, HttpSink, event_hash, load_run, referenced_refs
from tracekit.why.demo import EXFIL_TARGET, SYSTEM
from tracekit.why.graph import target_hits
from tracekit.why import cli as why_cli
from tracekit.why.import_v2 import store_records
from tracekit.why.server import Feed as WhyFeed, IngestError, Store, tape

POLICY = Engine({"deny": [{"id": "T-DENY", "tool": "rm", "pattern": "^"}],
                 "ask": [{"id": "T-PAY", "tool": "pay", "pattern": "^"}]})
SERVER = view.policy_reasons()   # the shipped packs' rule reasons, by policy hash
SERVER_HASH = next(h for h, rules in SERVER.items() if "TK-S001" in rules and "TK-M001" in rules)


def v2rec(seq, typ, data, run="r1", **top):
    return {"event": {"seq": seq, "run_seq": seq, "run_id": run, "agent_id": "main", "type": typ, "data": data,
                      "ts": f"2026-10-10T17:00:{seq:02d}.000000Z", "prev_hash": "sha256:p", **top},
            "hash": f"sha256:{seq}"}


class Translate(unittest.TestCase):
    """v2 records -> the page's rows: the agent's name, rule reasons for a call whose arguments are only a commitment,
    holds and approvals as their own tape rows in words, and the signer's run as the signer, not an agent."""

    def feed(self, *recs):
        tr = view.Translator(SERVER)
        return [x for r in recs for x in tr.feed(r)]

    def test_a_denied_call_shows_its_rules_reasons_and_its_commitment(self):
        start, call = self.feed(
            v2rec(1, "run.registered", {"agent": {"name": "support-agent"}, "signer_isolation": "separate-user",
                                        "identity": {"scheme": "uid", "subject": "501", "attested": True}}),
            v2rec(2, "policy.decision", {"tool_use_id": "c3", "tool": "http_get", "decision": "deny",
                                         "rule_ids": ["TK-N001", "TK-S001", "TK-NEW"], "policy_hash": SERVER_HASH,
                                         "args_commitment": "hmac-sha256:ab", "decision_id": "dec-1"}))
        self.assertEqual((start["agent"], start["source"]),
                         ("support-agent", "separate-user signer · uid:501 (attested)"))
        self.assertEqual((call["event"], call["agent"], call["tool_name"], call["tool_input"]),
                         ("PreToolUse", "support-agent", "http_get", {}))
        self.assertEqual(call["target"],
                         "TK-N001 request to an internal address; TK-S001 cloud metadata service; TK-NEW")
        self.assertEqual(call["policy"], {"decision": "deny", "reasons": ["TK-N001", "TK-S001", "TK-NEW"], "flags": []})
        self.assertEqual(call["v2"], {"type": "policy.decision", "run_seq": 2, "tool_use_id": "c3", "decision": "deny",
                                      "args_commitment": "hmac-sha256:ab", "policy_hash": SERVER_HASH,
                                      "decision_id": "dec-1", "rules": [
                                          {"id": "TK-N001", "reason": "request to an internal address"},
                                          {"id": "TK-S001", "reason": "cloud metadata service"},
                                          {"id": "TK-NEW", "reason": ""}]})
        [other] = self.feed(v2rec(2, "policy.decision", {"tool_use_id": "c3", "tool": "x", "decision": "ask",
                                                         "rule_ids": ["TK-S001"], "policy_hash": "sha256:unknown"}))
        # a decision of a policy the viewer does not have: its rule ids only
        self.assertEqual((other["target"], other["policy"]["flags"]), ("TK-S001", ["held_for_approval"]))

    def test_holds_and_approvals_are_their_own_rows_in_words(self):
        rows = self.feed(
            v2rec(1, "policy.decision", {"tool_use_id": "c6", "tool": "create_refund", "decision": "ask",
                                         "rule_ids": ["TK-M001"], "policy_hash": SERVER_HASH}),
            v2rec(2, "approval.request", {"approval_id": "apr-1", "rule_ids": ["TK-M001"], "policy_hash": SERVER_HASH,
                                          "requester": "uid:501", "expires_at": "2026-10-10T18:00:34.000000Z",
                                          "binding": {"tool": "create_refund", "tool_call_id": "c6"},
                                          "binding_digest": "sha256:bd"}),
            v2rec(3, "approval", {"tool_use_id": "c6", "approval_id": "apr-1", "decision": "approve",
                                  "approver": "oidc:alice", "approver_identity": {"scheme": "oidc", "subject": "alice",
                                                                                   "attested": False},
                                  "via": {"scheme": "mtls", "subject": "spiffe://acme/viewer", "attested": True},
                                  "channel": "web", "self_approved": False, "break_glass": True, "reason": "on call"}),
            v2rec(4, "approval.consumed", {"approval_id": "apr-1"}, tool_call_id="c6"))
        req, ans, used = rows[1:]
        self.assertEqual((req["tape"], req["title"]), ("HOLD", "APPROVAL REQUESTED · create_refund"))
        self.assertEqual(req["text"], "requested by uid:501 · rules TK-M001 sending money · expires 18:00:34 UTC")
        self.assertEqual((req["v2"]["approval"], req["v2"]["tool_use_id"]), ("requested", "c6"))
        self.assertEqual((ans["tape"], ans["severity"], ans["title"]), ("APPROVE", "high", "APPROVED · create_refund"))
        self.assertEqual(ans["text"], "by oidc:alice (not attested) · vouched for by mtls:spiffe://acme/viewer "
                                      "(attested) via web · “on call” · not self-approved · BREAK-GLASS")
        self.assertEqual({k: ans["v2"][k] for k in ("approval", "approver", "via", "self_approved", "break_glass")},
                         {"approval": "approve", "approver": "oidc:alice (not attested)",
                          "via": "mtls:spiffe://acme/viewer (attested)", "self_approved": False, "break_glass": True})
        self.assertEqual((used["tape"], used["title"], used["v2"]["tool_use_id"]),
                         ("APPROVE", "APPROVAL CONSUMED · create_refund", "c6"))
        self.assertNotIn("{", "".join(r.get("text", "") for r in rows))   # no record JSON in place of words

    def test_gaps_and_signer_records_in_words_and_the_signer_is_no_agent(self):
        gap, child, final = self.feed(
            v2rec(1, "capture.gap", {"kind": "client_counter_gap", "missed_events": 3, "reason": "stream s skipped"}),
            v2rec(2, "run.child", {"run_id": "run-c"}),
            v2rec(3, "run.final", {"head_run_seq": 2, "provider_executed": 2, "coverage": {
                "layers": ["L2"], "reconciled": 0, "unreconciled": {"hook_missing": 1}}}))
        self.assertEqual((child["title"], child["text"]), ("CHILD RUN", "run run-c registered from this run's harness "
                                                                        "process with this run as its parent"))
        self.assertEqual((gap["tape"], gap["title"], gap["text"], gap["v2"]["kind"]),
                         ("GAP", "GAP · client_counter_gap", "stream s skipped · 3 events missed",
                          "client_counter_gap"))
        self.assertEqual(final["reason"], "final · head run_seq 2 · coverage L2 · reconciled 0 · unreconciled "
                                          "hook_missing 1 · provider-run tools 2")
        signer = view.SIGNER_RUN[1]
        epoch, refused = self.feed(
            v2rec(0, "signer.epoch", {"keys": [{"kid": "sha256:6cb1e807d62770b7", "alg": "ed25519"}]}, run=signer),
            v2rec(1, "refusal.summary", {"code": "forbidden", "count": 2, "identity": "uid:501",
                                         "from_ts": "2026-10-10T17:00:34.1Z", "to_ts": "2026-10-10T17:00:35.1Z"},
                  run=signer))
        for r in (epoch, refused):
            self.assertEqual((r["signer"], r["agent"], r["tape"]), (True, "signer", "SIGNER"))
        self.assertEqual(epoch["text"], "1 signing key(s): ed25519 6cb1e807d627")
        self.assertEqual((refused["title"], refused["text"]),
                         ("SIGNER REFUSED 2 · forbidden", "from uid:501 · 17:00:34 UTC–17:00:35 UTC"))

    def test_review_counts_a_run_and_points_at_its_first_records(self):
        recs = [v2rec(1, "run.registered", {"agent": {"name": "a"}}),
                v2rec(2, "policy.decision", {"decision": "allow"}), v2rec(3, "policy.decision", {"decision": "deny"}),
                v2rec(4, "policy.decision", {"decision": "deny"}), v2rec(5, "policy.decision", {"decision": "ask"}),
                v2rec(6, "approval", {"decision": "approve", "tool_use_id": "c4", "self_approved": True,
                                      "approver_identity": {"scheme": "uid", "subject": "501", "attested": True}}),
                v2rec(7, "capture.gap", {"kind": "signer_unavailable"}), v2rec(8, "reconcile.hook_missing", {}),
                v2rec(9, "run.closing", {"reason": "close_run"}),
                v2rec(10, "run.final", {"coverage": {"layers": ["L2", "L3"], "reconciled": 4}})]
        rep = mock.Mock(integrity="VERIFIED", assurance="dev; same user")
        rv = view.review(recs, rep, "verified")
        self.assertEqual({k: rv[k] for k in ("verdict", "integrity", "assurance", "label", "agent", "records", "state")},
                         {"verdict": "verified", "integrity": "VERIFIED", "assurance": "dev", "label": view.OPERATOR_SIDE,
                          "agent": "a", "records": 10, "state": "final"})
        self.assertEqual(rv["decisions"], {"allow": 1, "deny": 2, "ask": 1})
        self.assertEqual(rv["approvals"], [{"decision": "approve", "tool_use_id": "c4", "approver": "uid:501 (attested)",
                                            "via": None, "self_approved": True, "break_glass": False, "seq": 6}])
        self.assertEqual(rv["gaps"], {"signer_unavailable": 1, "reconcile.hook_missing": 1})
        self.assertEqual(rv["coverage"], {"layers": ["L2", "L3"], "reconciled": 4, "unreconciled": {},
                                          "provider_executed": 0})
        self.assertEqual(rv["first"], {"allow": 2, "deny": 3, "ask": 5, "approval": 6, "gap:signer_unavailable": 7,
                                       "gap:reconcile.hook_missing": 8})
        self.assertEqual((rv["first_ts"], rv["last_ts"]), ("2026-10-10T17:00:01.000000Z", "2026-10-10T17:00:10.000000Z"))
        json.dumps(rv)   # served to the page as is

    def test_policy_reasons_of_a_configured_policy_by_its_hash(self):
        path = os.path.join(ts.tmpdir(self), "p.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("deny:\n  - id: X-1\n    pattern: 'rm'\n    reason: removing files\n"
                    "flag:\n  - id: X-2\n    pattern: 'ls'\n    label: listing\n")
        h = policy_compile.policy_hash(policy_compile.build(path)[0])
        self.assertEqual(view.policy_reasons([path])[h], {"X-1": "removing files", "X-2": "listing"})
        self.assertEqual(SERVER[SERVER_HASH]["TK-DB001"], "dropping a database object")

    def test_a_calls_signed_provenance_rides_on_its_row(self):
        src = {"run_seq": 4, "tool": "fetch_page", "tool_call_id": "c2"}
        call, restarted, plain = self.feed(
            v2rec(5, "policy.decision", {"tool_use_id": "c5", "tool": "send_email", "decision": "ask",
                                         "provenance_state": "complete",
                                         "provenance": [{"field": "to", "kind": "email", "source": src}]}),
            v2rec(6, "policy.decision", {"tool_use_id": "c6", "tool": "send_email", "decision": "allow",
                                         "provenance_state": "unavailable"}),
            v2rec(7, "policy.decision", {"tool_use_id": "c7", "tool": "ls", "decision": "allow"}))
        self.assertEqual(call["v2"]["provenance"], [{"field": "to", "kind": "email", "source": src}])
        self.assertEqual(restarted["v2"]["provenance_state"], "unavailable")
        self.assertFalse({"provenance", "provenance_state"} & set(plain["v2"]))   # a 1.0 record: nothing to show


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class View(unittest.TestCase):
    def setUp(self):
        self.d = ts.tmpdir(self)
        cfg = {"data_dir": self.d, "socket": os.path.join(self.d, "s.sock"), "grace_s": 0,
               "approvals": {"self_approval": "allow"}}   # one uid runs and approves
        self.service = svc.open_service(cfg, policy=POLICY)
        self.addCleanup(self.service.close)
        for srv in svc.serve(cfg, self.service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.client = Client(cfg["socket"])
        self.addCleanup(self.client.close)

    def finished_run(self):
        """allow, deny, ask -> approve -> run, complete, close; returns the run id once a note covers run.final."""
        run = self.client.run(agent="e2e")
        self.assertEqual(run.decide("c1", "Bash", {"command": "ls"})["decision"], "allow")
        run.complete("c1")
        self.assertEqual(run.decide("c2", "rm", {"path": "x"})["decision"], "deny")
        self.assertEqual(run.decide("c3", "pay", {"cents": 5})["decision"], "ask")
        aid = run.call("approval_request", tool_call_id="c3")["approval_id"]
        self.client.call("approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertTrue(run.approval_consume("c3", "pay", {"cents": 5})["ok"])
        run.complete("c3")
        run.close()
        storage = self.service.log.storage
        self.assertTrue(wait_for(lambda: list(storage.iter_run("default", run.run_id))[-1]["event"]["type"] == "run.final"
                                 and (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        return run.run_id

    def rows(self, feed, run_id):
        with feed.lock:
            return [r for r in feed.records if r["session_id"] == run_id]

    def report(self, feed, run_id):
        wait_for(lambda: any(r.get("title", "").startswith(f"RUN {run_id}") for r in self.rows(feed, run_id)), 15)
        return [r for r in self.rows(feed, run_id) if r.get("title", "").startswith(f"RUN {run_id}")]

    def test_dev_run_is_listed_with_its_counts_and_verified_while_the_signer_holds_the_lock(self):
        run_id = self.finished_run()
        with self.assertRaises(OSError):
            FileStorage(os.path.join(self.d, "store"))   # the signer still holds the store
        feed = view.StoreFeed({"data_dir": self.d})
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity VERIFIED · Assurance dev")
        self.assertIn("tenant default · agent e2e · final · decisions allow 1, ask 1, deny 1 · approvals 1 · gaps 0",
                      rep["text"])
        self.assertIn("same user as the dev signer", rep["text"])
        self.assertIn(view.OPERATOR_SIDE, rep["text"])
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev;", rep["text"])   # verify.v2's own report
        rows = self.rows(feed, run_id)
        self.assertEqual([r["tool_name"] for r in rows if r["event"] == "PreToolUse"], ["Bash", "rm", "pay"])
        self.assertEqual((rows[0]["event"], rows[-1]["title"]), ("SessionStart", rep["title"]))
        self.assertEqual(feed.verify()[1], [])
        # the page's run list and review, the denied call's rule, the hold's rows, and the signer's records as its own
        self.assertEqual({k: rep["review"][k] for k in ("verdict", "agent", "state", "decisions")},
                         {"verdict": "verified", "agent": "e2e", "state": "final",
                          "decisions": {"allow": 1, "deny": 1, "ask": 1}})
        self.assertEqual([(a["decision"], a["self_approved"]) for a in rep["review"]["approvals"]], [("approve", True)])
        self.assertEqual({r["agent"] for r in rows}, {"e2e"})
        self.assertEqual(next(r["target"] for r in rows if r.get("tool_name") == "rm"), "T-DENY")
        self.assertEqual([(r["tape"], r["v2"]["approval"]) for r in rows if r.get("v2", {}).get("approval")],
                         [("HOLD", "requested"), ("APPROVE", "approve"), ("APPROVE", "consumed")])
        self.assertTrue(wait_for(lambda: any(r.get("signer") for r in feed.records), 15))
        with feed.lock:
            self.assertEqual({(r["agent"], r["session_id"]) for r in feed.records if r.get("signer")},
                             {("signer", view.SIGNER_RUN[1])})

    def test_a_run_no_checkpoint_covers_yet_is_listed_as_pending(self):
        fake = mock.Mock(runs={("default", "r9"): {"seqs": [0]}})
        fake.checkpoint_latest.return_value = None
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "late"}}, "r9")])
        with mock.patch.object(view, "reader", return_value=fake):
            feed = view.StoreFeed({"data_dir": self.d})
            self.assertTrue(wait_for(lambda: feed.records, 5))
            r = feed.records[0]
        self.assertEqual((r["event"], r["session_id"], r["tenant"], r["review"]),
                         ("tk_run", "r9", "default",
                          {"verdict": "pending", "agent": "late", "label": view.OPERATOR_SIDE}))

    def test_a_tenants_signer_run_is_the_signer_never_an_agent_run(self):
        signer = ("acme", view.SIGNER_RUN[1])   # content.accessed and content.erased go in each tenant's own
        fake = mock.Mock(runs={signer: {"seqs": [0]}, ("default", "r9"): {"seqs": [1]}})
        fake.checkpoint_latest.return_value = None
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "late"}}, key[1])])
        with mock.patch.object(view, "reader", return_value=fake):
            feed = view.StoreFeed({"data_dir": self.d})
            self.assertTrue(wait_for(lambda: feed.records, 5))
        with feed.lock:
            self.assertEqual([r["session_id"] for r in feed.records], ["r9"])   # not listed as a pending agent run
        with mock.patch.object(view, "check", return_value=(mock.Mock(integrity="FAILED", assurance="none"), 1, "t")):
            feed._verify(fake, "note", signer, 1)
        with feed.lock:
            self.assertEqual((feed.records[-1]["signer"], feed.records[-1]["agent"]), (True, "signer"))

    def test_last_skips_each_tenants_signer_run(self):
        runs = {("default", "r1"): {"seqs": [1]}, ("acme", view.SIGNER_RUN[1]): {"seqs": [5]}}
        fake = mock.Mock(runs=runs)
        fake.iter_run.side_effect = lambda *key: iter([v2rec(0, "run.registered", {"agent": {"name": "a"}}, key[1]),
                                                       v2rec(1, "run.final" if key[1] == "r1" else "content.accessed",
                                                             {}, key[1])])
        exported, err = [], io.StringIO()
        with mock.patch.object(svc, "reader", return_value=fake), \
                mock.patch.object(svc, "signer_config", return_value={"data_dir": self.d}), \
                mock.patch.object(cli, "_export_v2", side_effect=lambda ns, show: exported.append(ns.run) or 1), \
                contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["last"]), 1)
        self.assertEqual((exported, err.getvalue()), (["r1"], ""))

    def test_tampered_record_shows_only_the_failure(self):
        run_id = self.finished_run()
        self.service.close()
        path = os.path.join(self.d, "store", "records.jsonl")
        with open(path, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data.count('"tool":"Bash"'), 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data.replace('"tool":"Bash"', '"tool":"Bosh"'))
        feed = view.StoreFeed({"data_dir": self.d})
        [rep] = self.report(feed, run_id)
        self.assertEqual(rep["title"], f"RUN {run_id} · Integrity FAILED")
        self.assertIn(view.OPERATOR_SIDE, rep["text"])
        self.assertEqual(self.rows(feed, run_id), [rep])   # none of its events
        self.assertEqual(feed.verify()[1], [f"run {run_id} of tenant default: FAILED"])

    def serve(self, feed, token="t0k", tls=None):
        srv = view.server(feed, "127.0.0.1", 0, token, tls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def session(self, port, timeout=5):
        """(connection, headers) of a browser that exchanged the printed token for its session cookie."""
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 401)   # no anonymous access, even on loopback
        c.request("GET", "/?token=t0k")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        return c, {"Cookie": r.getheader("Set-Cookie").split(";")[0]}

    def test_loopback_viewer_prints_a_token_url_and_needs_it(self):
        with mock.patch.object(view, "server") as server, mock.patch.dict(os.environ), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            os.environ.pop("TRACEKIT_VIEW_TOKEN", None)
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            self.assertEqual(view.main(["--data-dir", self.d]), 0)
        token = server.call_args[0][3]
        self.assertGreaterEqual(len(token), 32)
        self.assertIn(f"http://127.0.0.1:7778/?token={token} ", out.getvalue())
        with mock.patch.object(view, "server") as server, mock.patch.object(view, "Runs") as runs, \
                mock.patch.object(view, "load_config", return_value={"view": {"logs": ["a.dsn", "b.dsn"]}}), \
                mock.patch.dict(os.environ), contextlib.redirect_stdout(io.StringIO()) as out:
            os.environ.pop("TRACEKIT_VIEW_TOKEN", None)
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            runs.return_value.logs = ["a.dsn", "b.dsn"]
            self.assertEqual(view.main(["--config", "signer.yaml"]), 0)
        self.assertIn(f"http://127.0.0.1:7778/?token={server.call_args[0][3]}  (2 Postgres logs", out.getvalue())
        with self.assertRaises(ValueError):
            view.server(None, "127.0.0.1", 0, None)

    def test_why_logs_default_to_the_data_dir_when_present(self):
        def why(*args):
            with mock.patch.object(view, "server") as server, mock.patch.object(view.Store, "watch"), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                server.return_value.serve_forever.side_effect = KeyboardInterrupt
                server.return_value.server_address = ("127.0.0.1", 7778)
                self.assertEqual(view.main(["--data-dir", self.d, *args]), 0)
            return server.call_args[0][8], out.getvalue()
        store, out = why()   # no why logs: the store's own runs, imported as they verify
        self.assertNotEqual(store.root, os.path.join(self.d, view.WHY_DIR))
        self.assertIn("graphs: each verified run", out)
        os.makedirs(os.path.join(self.d, view.WHY_DIR))
        store, out = why("--allow-program", "m:SYSTEM")
        self.assertEqual((store.root, store.allow), (os.path.join(self.d, view.WHY_DIR), {"m:SYSTEM"}))
        self.assertIn("replay m:SYSTEM", out)
        other = os.path.join(self.d, "elsewhere")
        store, out = why("--why", other)
        self.assertEqual(store.root, other)
        self.assertIn("start with --allow-program", out)

    def test_a_store_with_no_why_logs_still_gets_a_graph_of_each_run_with_its_decisions(self):
        run_id = self.finished_run()
        why_dir = ts.tmpdir(self)
        feed = view.StoreFeed({"data_dir": self.d}, on_run=lambda recs: view.mirror_run(recs, why_dir))
        self.report(feed, run_id)
        store = Store(why_dir, out=feed)
        d = store.detail("tk-" + run_id)
        calls = {n["tool"]: n for n in d["nodes"] if n["type"] == "action"}
        self.assertEqual(calls["rm"]["policy"]["decision"], "deny")   # GRAPH and NODE mark it DENIED with its rule
        self.assertEqual(calls["rm"]["policy"]["rule_ids"], ["T-DENY"])
        self.assertEqual(calls["pay"]["policy"]["decision"], "ask")
        self.assertEqual(calls["pay"]["policy"]["approval"]["decision"], "approve")
        self.assertEqual(calls["Bash"]["policy"]["decision"], "allow")
        self.assertTrue(store.workspace()["calls"])   # each signed call joins its imported why event (the WHY tab)
        view.mirror_run(store_records(self.d, run_id)[run_id], why_dir)   # a re-import replaces the run
        self.assertEqual(sorted(os.listdir(why_dir)), ["tk-" + run_id])

    def test_hostile_tool_names_are_data_and_the_page_escapes_every_sink(self):
        run = self.client.run(agent="a")
        run.decide("c1", XSS, {"q": XSS})
        self.client.call("checkpoint_nudge", {})
        feed = view.StoreFeed({"data_dir": self.d})
        self.report(feed, run.run_id)
        c, cookie = self.session(self.serve(feed))
        c.request("GET", "/", headers=cookie)
        r = c.getresponse()
        page = r.read().decode()
        self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy"))
        self.assertNotIn("<img", page)
        self.assertEqual(unescaped(script_of(page)), [])
        c.request("GET", "/api/snapshot", headers=cookie)
        snap = json.loads(c.getresponse().read())
        self.assertIn(XSS, [x.get("tool_name") for x in snap["records"]])

    def test_sse_shows_a_new_record(self):
        feed = view.StoreFeed({"data_dir": self.d})
        c, cookie = self.session(self.serve(feed), 15)
        c.request("GET", "/api/snapshot", headers=cookie)
        start = json.loads(c.getresponse().read())["next"]
        c.request("GET", f"/api/stream?from={start}", headers=cookie)
        stream = c.getresponse()
        run = self.client.run(agent="late")
        run.decide("c1", "Bash", {"command": "ls"})
        self.client.call("checkpoint_nudge", {})
        while True:
            line = stream.fp.readline()
            if line.startswith(b"data: ") and json.loads(line[6:]).get("tool_name") == "Bash":
                break

    def test_beyond_loopback_needs_https(self):
        self.assertEqual(view.main(["--host", "0.0.0.0", "--data-dir", self.d]), 2)

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a certificate")
    def test_https_serves_with_a_secure_cookie(self):
        cert, key = os.path.join(self.d, "c.pem"), os.path.join(self.d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days",
                        "1", "-keyout", key, "-out", cert], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        port = self.serve(view.StoreFeed({"data_dir": self.d}), "s3cret", tls)
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ssl._create_unverified_context())
        c.request("GET", "/?token=s3cret")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        self.assertIn("; Secure", r.getheader("Set-Cookie"))


TOKEN = "why-test-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}


def cite(path, run_id, seqs):
    """Rewrite the why log at `path` as the signer-backed runtime writes it: each tool call cites the signed record it
    produced (`tracekit`: run_id, run_seq from `seqs`, in order), the chain rebuilt."""
    with open(os.path.join(path, "events.jsonl"), encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    prev, seqs = GENESIS, iter(seqs)
    for ev in events:
        if ev["type"] == "action":
            ev["tracekit"] = {"run_id": run_id, "run_seq": next(seqs), "type": "tool.result"}
        ev["prev_hash"] = prev
        ev.pop("hash")
        ev["hash"] = prev = event_hash(ev)
    with open(os.path.join(path, "events.jsonl"), "w", encoding="utf-8") as f:
        f.writelines(json.dumps(ev, sort_keys=True) + "\n" for ev in events)


class WhyServer(unittest.TestCase):
    """The viewer on why logs, as `tracekit why serve` runs it: a why.server.Store publishing into its own feed."""

    def setUp(self):
        self.tmp = ts.tmpdir(self)
        self.store = Store(os.path.join(self.tmp, "srv"), ["tracekit.why.demo:SYSTEM"], tape=True)
        self.httpd = view.server(self.store.out, "127.0.0.1", 0, TOKEN, why=self.store)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.store.watch()
        self.addCleanup(self.store.stop)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def get(self, path):
        status, _, body = self.request("GET", path, AUTH)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def post(self, path, body, headers=JSON):
        status, _, out = self.request("POST", path, headers, json.dumps(body).encode())
        return status, json.loads(out)

    def stream(self, timeout=10):
        """The why messages on the viewer's event stream, until a run finishes; and the records the tape gets."""
        out, rows, ready = [], [], threading.Event()

        def read():
            req = urllib.request.Request(self.base + "/api/stream", headers=AUTH)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ready.set()
                for line in r:
                    if line.startswith(b"data: "):
                        rec = json.loads(line[6:])
                        if rec["event"] != "why":
                            rows.append(rec)
                        elif rec["why"]["type"] == "run":
                            out.append(rec["why"])
                            if out[-1]["finished"]:
                                return

        t = threading.Thread(target=read, daemon=True)
        t.start()
        ready.wait(timeout)
        return out, rows, t


class WhyData(WhyServer):
    """What the page shows of a why run: argument provenance, candidate causes, a test's result, the signed calls each
    why event cites, and the tape rows of a why log."""

    def exfil(self):
        return next(r for r in (SYSTEM.run(seed=s, out_dir=self.store.root, run_id=f"fc-{s}") for s in range(8))
                    if target_hits(r, EXFIL_TARGET))

    def test_provenance_candidates_and_a_test_result(self):
        run = self.exfil()
        d = self.get(f"/api/why/runs/{run.run_id}")
        self.assertEqual(d["replay"], {"program": "tracekit.why.demo:SYSTEM", "allowed": True})
        send = next(k for k, v in d["actions"].items() if "vendor-compliance" in v["target"])
        prov = d["actions"][send]["provenance"]
        bad = [p for p in prov if p["status"] == "untrusted-only"]
        self.assertTrue(bad and all(s["trust"] == "untrusted" for p in bad for s in p["sources"]))
        self.assertIn("vendor:portal/notes.md", [s["label"] for p in bad for s in p["sources"]])
        cands = {c["intervention"]: c for c in d["actions"][send]["candidates"]}
        self.assertEqual(cands["input:vendor:portal/notes.md"]["status"], "untested")
        self.assertTrue(d["actions"][send]["lineage"])
        code, r = self.post(f"/api/why/runs/{run.run_id}/tests", {"intervention": "input:vendor:portal/notes.md",
                                                                  "target": EXFIL_TARGET, "n": 20})
        self.assertEqual((code, r["verdict"]), (200, "causal"))
        c = next(c for c in self.get(f"/api/why/runs/{run.run_id}")["actions"][send]["candidates"]
                 if c["intervention"] == "input:vendor:portal/notes.md")
        self.assertEqual((c["status"], c["test"]["n"] >= 20), ("confirmed", True))
        self.assertGreater(c["test"]["p_with"], c["test"]["p_without"])

    def test_every_node_carries_what_its_node_detail_shows(self):
        """Clicking a GRAPH node opens NODE (Causeway's drawer): what each type saw, did or held, its links, its record."""
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="nodes")
        d = self.get(f"/api/why/runs/{run.run_id}")
        ids = {n["id"] for n in d["nodes"]}
        by_type = {n["type"]: n for n in d["nodes"]}
        self.assertEqual(set(by_type), {"input", "decision", "action", "message"})
        for n in d["nodes"]:
            self.assertTrue(n["hash"] and n["prev"] and n["ts"] and n["label"], n)
        dec, act = by_type["decision"], by_type["action"]
        self.assertTrue(dec["model"] and dec["output"] and dec["context"])
        self.assertTrue(all(c["node"] is None or c["node"] in ids for c in dec["context"]))   # WHAT IT SAW links
        self.assertIn("args", act)
        self.assertIsInstance(act["result"], str)
        self.assertTrue(by_type["input"]["content"] and by_type["message"]["to"])
        self.assertTrue(all(e["src"] in ids and e["dst"] in ids for e in d["edges"]))   # CAME FROM / LED TO links
        status, page = self.request("GET", "/", AUTH)[::2]
        self.assertEqual(status, 200)
        self.assertIn(b'data-wtab="node"', page)

    def test_workspace_has_every_alert_and_the_signed_call_each_why_event_cites(self):
        run = self.exfil()
        acts = run.of_type("action")
        cite(run.path, "signed-run", range(10, 10 + len(acts)))
        self.assertEqual(self.get("/api/why/workspace")["calls"], {})   # no signed record yet: nothing joins
        with self.store.out.lock:   # the signed records, the first of another tool than its why event says
            self.store.out.records.extend({"session_id": "signed-run", "tool_name": "other" if i == 0 else a["tool"],
                                           "v2": {"run_seq": 10 + i}} for i, a in enumerate(acts))
        ws = self.get("/api/why/workspace")
        self.assertEqual([r["run_id"] for r in ws["runs"]], [run.run_id])
        self.assertNotIn("signed-run|10", ws["calls"])
        self.assertEqual(ws["calls"]["signed-run|11"], [run.run_id, "ev:" + acts[1]["id"]])
        self.assertEqual(len(ws["calls"]), len(acts) - 1)
        high = [a for a in ws["alerts"] if a["severity"] == "high"]
        self.assertTrue(high and high[0]["run_id"] == run.run_id and "send_email" in high[0]["title"])
        node = next(n for n in self.get(f"/api/why/runs/{run.run_id}")["nodes"] if n["id"] == "ev:" + acts[0]["id"])
        self.assertEqual(node["tracekit"], {"run_id": "signed-run", "run_seq": 10, "type": "tool.result"})

    def test_a_why_log_on_the_tape(self):
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="t0")
        rows = tape(load_run(run.path))
        pre = [r for r in rows if r["event"] == "PreToolUse"]
        self.assertEqual([r["tool_name"] for r in pre], [a["tool"] for a in run.of_type("action")])
        self.assertEqual(pre[0]["why"], {"run": "t0", "node": "ev:" + run.of_type("action")[0]["id"]})
        self.assertEqual(rows[0]["event"], "SessionStart")
        self.assertEqual(rows[-1]["event"], "SessionEnd")
        self.assertTrue(all(r["session_id"] == "t0" for r in rows))
        sub = {r["agent_id"] for r in rows if r["event"] == "SubagentStart"}
        self.assertEqual(sub, {e["agent"] for e in run.of_type("agent.start")})

    def test_replay_without_the_program_says_what_to_run(self):
        store = Store(os.path.join(self.tmp, "srv2"))
        SYSTEM.run(seed=0, out_dir=store.root, run_id="r")
        self.assertFalse(store.detail("r")["replay"]["allowed"])
        with self.assertRaises(IngestError) as e:
            store.test("r", {"intervention": "untrusted", "target": "tool=send_email"})
        self.assertEqual(e.exception.status, 403)
        self.assertIn("--allow-program tracekit.why.demo:SYSTEM", str(e.exception))


class WhyIngest(WhyServer):
    def test_remote_ingest_then_investigate_and_test(self):
        for s in range(3):
            SYSTEM.run(seed=s, run_id=f"remote-{s}", sink=HttpSink(self.base, TOKEN, batch=7))
        ws = self.get("/api/why/workspace")
        self.assertEqual({r["run_id"] for r in ws["runs"]}, {"remote-0", "remote-1", "remote-2"})
        self.assertTrue(all(r["integrity"] == "ok" for r in ws["runs"]))
        self.assertEqual(self.get("/api/why/runs/remote-0")["summary"]["alerts"]["high"], 1)
        code, r = self.post("/api/why/runs/remote-0/tests", {"intervention": "input:vendor:*", "target": EXFIL_TARGET,
                                                             "n": 20})
        self.assertEqual((code, r["verdict"]), (200, "causal"))
        d = self.get("/api/why/runs/remote-0")
        send = [k for k, v in d["actions"].items() if "vendor-compliance" in v["target"]][0]
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")

    def test_rejects_bad_token_tamper_and_gaps(self):
        run = SYSTEM.run(seed=0, run_id="t1")
        evs = run.events
        blobs = {r: run.blobs[r] for ev in evs[:3] for r in referenced_refs(ev)}   # what the first batch references
        ingest = lambda events, blobs, token=TOKEN: self.post(  # noqa: E731
            "/v1/ingest", {"events": events, "blobs": blobs},
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})[0]
        self.assertEqual(ingest(evs, blobs, "wrong"), 401)
        self.assertEqual(self.request("POST", "/v1/ingest", {"Cookie": f"tracekit_observe={_session(TOKEN)}"},
                                      b"{}")[0], 401)
        bad = json.loads(json.dumps(evs[:3]))
        bad[2]["agent"] = "mallory"
        self.assertEqual(ingest(bad, blobs), 422)
        self.assertEqual(ingest(evs[1:4], {r: run.blobs[r] for ev in evs[1:4] for r in referenced_refs(ev)}), 409)
        fake = dict(blobs)
        fake[next(iter(fake))] = "forged"
        self.assertEqual(ingest(evs[:3], fake), 422)
        self.assertEqual(ingest(evs[:3], blobs), 200)
        self.assertEqual(ingest(evs[:3], blobs), 409)  # replayed batch

    def test_malformed_ingest_is_rejected_and_cannot_break_the_workspace(self):
        ev = {"schema": "tracekit.why.event.v1", "seq": 0, "id": "x", "prev_hash": GENESIS, "run_id": "poison",
              "agent": "run", "type": "decision", "ts": "2026-10-09T00:00:00.000000Z"}
        ev["hash"] = event_hash(ev)
        self.assertEqual(self.post("/v1/ingest", {"events": [ev], "blobs": {}})[0], 422)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "abc"}, b"{}")[0], 411)
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Content-Length": "99999999"})[0], 413)
        self.assertEqual(self.request("POST", "/v1/ingest", JSON, b"[1]")[0], 400)
        os.makedirs(os.path.join(self.store.root, "broken"))  # a broken run written straight to disk is listed
        with open(os.path.join(self.store.root, "broken", "events.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        SYSTEM.run(seed=1, out_dir=self.store.root, run_id="fine")
        with contextlib.redirect_stderr(io.StringIO()):
            runs = {x["run_id"]: x for x in self.get("/api/why/workspace")["runs"]}
        self.assertEqual(set(runs), {"fine", "poison"})   # the log's own run id: analysed, bad values and all
        with open(os.path.join(self.store.root, "broken", "events.jsonl"), "w", encoding="utf-8") as f:
            f.write("{not json\n")
        with contextlib.redirect_stderr(io.StringIO()):
            runs = {x["run_id"]: x for x in self.get("/api/why/workspace")["runs"]}
            self.assertEqual(self.request("GET", "/api/why/runs/broken", AUTH)[0], 422)
        self.assertEqual(set(runs), {"fine", "broken"})   # listed as broken, not dropped
        self.assertTrue(runs["broken"]["broken"] and not runs["fine"].get("broken"))


class WhyLive(WhyServer):
    def test_stream_announces_runs_written_to_disk_with_their_alerts_and_tape(self):
        msgs, rows, t = self.stream()
        run = SYSTEM.run(seed=0, out_dir=self.store.root, run_id="disk-0")  # a local Runtime, no sink
        t.join(10)
        self.assertTrue(msgs and msgs[0]["run_id"] == "disk-0" and msgs[-1]["finished"])
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("send_email", highs[0]["title"])
        self.assertEqual([r["tool_name"] for r in rows if r["event"] == "PreToolUse"],
                         [a["tool"] for a in run.of_type("action")])   # each event on the tape once

    def test_stream_announces_ingested_runs(self):
        msgs, _, t = self.stream()
        SYSTEM.run(seed=0, run_id="remote-live", sink=HttpSink(self.base, TOKEN))
        t.join(10)
        self.assertEqual(msgs[0]["run_id"], "remote-live")
        self.assertGreaterEqual(len(msgs), 3)  # flushed per tool call, not only at the end
        highs = [a for m in msgs for a in m["alerts"] if a["severity"] == "high"]
        self.assertGreaterEqual(len(highs), 1)
        self.assertEqual(len(highs), len({(a["title"], a["node"]) for a in highs}))

    def test_find_the_cause_endpoint(self):
        run = next(r for r in (SYSTEM.run(seed=s, out_dir=self.store.root, run_id=f"fc-{s}") for s in range(8))
                   if target_hits(r, EXFIL_TARGET))
        code, out = self.post(f"/api/why/runs/{run.run_id}/attribute", {"target": EXFIL_TARGET, "n": 10, "n_max": 40})
        self.assertEqual(code, 200)
        self.assertEqual((out["causes"][0]["intervention"], out["causes"][0]["role"]),
                         ("input:vendor:portal/notes.md", "primary"))
        d = self.get(f"/api/why/runs/{run.run_id}")
        send = next(k for k, v in d["actions"].items() if "vendor-compliance" in v["target"])
        self.assertEqual(d["actions"][send]["candidates"][0]["status"], "confirmed")


class WhyPage(WhyServer):
    def test_the_page_is_the_viewers_and_the_why_api_needs_the_token(self):
        self.assertEqual(self.request("GET", "/api/why/workspace")[0], 401)
        status, h, _ = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(status, 303)
        self.assertNotIn(TOKEN, h["Location"] + h["Set-Cookie"])
        self.assertIn("HttpOnly; SameSite=Strict", h["Set-Cookie"])
        session = {"Cookie": h["Set-Cookie"].split(";")[0]}
        status, h, page = self.request("GET", "/", session)
        self.assertEqual(status, 200)
        for directive in ("script-src 'nonce-", "default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"):
            self.assertIn(directive, h["Content-Security-Policy"])
        self.assertIn(b'data-wtab="why"', page)
        self.assertEqual(unescaped(script_of(page.decode())), [])
        self.assertEqual(self.request("GET", "/api/why/workspace", session)[0], 200)

    def test_foreign_host_is_refused_without_the_token(self):
        self.assertEqual(self.request("GET", "/api/why/workspace", {"Host": "evil.example:7788"})[0], 403)
        self.assertEqual(self.request("GET", "/api/why/workspace", {**AUTH, "Host": "evil.example:7788"})[0], 200)
        session = {"Cookie": self.request("GET", f"/?token={TOKEN}")[1]["Set-Cookie"].split(";")[0]}
        self.assertEqual(self.request("POST", "/api/why/runs/x/tests", {
            **session, "Content-Type": "application/json", "Host": "evil.example"}, b"{}")[0], 403)
        self.assertEqual(self.request("POST", "/v1/ingest", {"Host": "evil.example"}, b"{}")[0], 403)
        # remote agents reach the server by its DNS name: the bearer token is enough
        self.assertEqual(self.request("POST", "/v1/ingest", {**JSON, "Host": "why.example.com"}, b"{}")[0], 400)

    def test_replay_posts_need_the_token_and_a_same_origin_json_body(self):
        SYSTEM.run(seed=0, out_dir=self.store.root, run_id="r")
        body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, "n": 2}).encode()
        for headers, status in (({"Content-Type": "application/json"}, 401),
                                ({**AUTH, "Content-Type": "text/plain"}, 403),
                                ({**AUTH}, 403),
                                ({**JSON, "Origin": "http://evil.example"}, 403),
                                ({**JSON, "Content-Length": "99999999"}, 413)):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/api/why/runs/r/tests", headers, body)[0], status)
        for bad in ({"n": "x"}, {"n": None}, {"n_max": [1]}):
            with self.subTest(bad=bad):
                bad_body = json.dumps({"intervention": "input:vendor:*", "target": EXFIL_TARGET, **bad}).encode()
                self.assertEqual(self.request("POST", "/api/why/runs/r/tests", JSON, bad_body)[0], 400)
                self.assertEqual(self.request("POST", "/api/why/runs/r/attribute", JSON, bad_body)[0], 400)
        self.assertEqual(self.request("POST", "/api/why/runs/r/tests", JSON, body)[0], 200)
        self.assertEqual(self.request("POST", "/api/why/runs/no-such/tests", JSON, body)[0], 404)



class OneViewer(unittest.TestCase):
    """`tracekit view` is the one viewer: the v1 ledger or bundle (`tracekit observe`) and why logs alone (`tracekit
    why serve`) on its server, token and nav; the old commands keep working and say so."""
    SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "sample")

    def main(self, *args):
        """(code, the args view.server was called with, stdout) of `tracekit view ARGS`, the server not started."""
        with mock.patch.object(view, "server") as server, mock.patch.object(Store, "watch"), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7778)
            code = view.main(list(args))
        return code, server.call_args and server.call_args[0], out.getvalue()

    def get(self, port, path, headers):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        self.addCleanup(c.close)
        c.request("GET", path, headers=headers)
        r = c.getresponse()
        return r.status, r.read().decode()

    def test_v1_bundle_is_served_on_the_viewers_server_and_a_tampered_one_is_refused(self):
        code, args, out = self.main("--bundle", os.path.join(self.SAMPLE, "demo-run.tkb"))
        feed, token = args[0], args[3]
        self.assertEqual(code, 0)
        self.assertIsInstance(feed, observe.Feed)
        self.assertIn(f"(ledger: {feed.path}, read-only)", out)
        srv = view.server(feed, "127.0.0.1", 0, token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        self.assertEqual(self.get(port, "/api/verify", {})[0], 401)   # the viewer's token, unlike observe's default
        auth = {"Authorization": f"Bearer {token}"}
        wait_for(lambda: json.loads(self.get(port, "/api/verify", auth)[1])["records"] > 0)
        self.assertTrue(json.loads(self.get(port, "/api/verify", auth)[1])["ok"])
        status, page = self.get(port, "/", auth)
        self.assertEqual(status, 200)
        self.assertIn('<nav class="nav"><a href="/" class="on">LIVE</a></nav>', page)
        code, args, _ = self.main("--bundle", os.path.join(self.SAMPLE, "demo-run-tampered.tkb"))
        self.assertNotEqual(code, 0)
        self.assertIsNone(args)

    def test_v1_ledger_defaults_to_its_home_and_stays_on_loopback(self):
        home = ts.tmpdir(self)
        code, args, out = self.main("--ledger", home)
        self.assertEqual((code, args[0].path), (0, os.path.join(home, "ledger", "ledger.jsonl")))
        for host in ("0.0.0.0", "192.0.2.1"):   # the v1 ledger stays on loopback, as observe kept it, even with TLS
            self.assertEqual(self.main("--ledger", home, "--host", host, "--tls-cert", "c", "--tls-key", "k")[:2],
                             (2, None))

    def test_why_alone_is_why_serve(self):
        root = ts.tmpdir(self)
        code, args, out = self.main("--why", root, "--allow-program", "m:SYSTEM", "--webhook", "http://127.0.0.1:9/")
        store = args[8]
        self.assertEqual(code, 0)
        self.assertEqual((store.root, store.tape, store.allow, args[0]), (root, True, {"m:SYSTEM"}, store.out))
        self.assertIsNotNone(store.webhook)
        self.assertIn(f"(why logs alone: {root})", out)

    def test_one_nav_reaches_every_page_this_server_has(self):
        runs = mock.Mock()
        runs.search.return_value = {"runs": [], "next": None}
        srv = view.server(WhyFeed(), "127.0.0.1", 0, "t0k", runs=runs)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port, auth = srv.server_address[1], {"Authorization": "Bearer t0k"}
        for path, on in (("/", "LIVE"), ("/runs", "RUNS")):
            status, page = self.get(port, path, auth)
            self.assertEqual(status, 200)
            self.assertIn('<a href="/" class="%s">LIVE</a><a href="/runs" class="%s">RUNS</a>'
                          % ("on" if on == "LIVE" else "", "on" if on == "RUNS" else ""), page)
            self.assertNotIn("APPROVALS", page)
        self.assertEqual(self.get(port, "/runs", {})[0], 401)

    def test_observe_and_why_serve_say_they_are_part_of_view_and_keep_working(self):
        with mock.patch.object(observe, "Feed"), mock.patch.object(observe, "ThreadingHTTPServer") as httpd, \
                contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            httpd.return_value.serve_forever.side_effect = KeyboardInterrupt
            httpd.return_value.server_address = ("127.0.0.1", 7777)
            self.assertEqual(observe.main(["--home", ts.tmpdir(self)]), 0)
        self.assertEqual(err.getvalue(), observe.NOTICE + "\n")
        with mock.patch.object(view, "server") as server, contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            server.return_value.serve_forever.side_effect = KeyboardInterrupt
            server.return_value.server_address = ("127.0.0.1", 7788)
            why_cli.main(["serve", ts.tmpdir(self)])
        self.assertTrue(server.called)
        self.assertEqual(err.getvalue().splitlines(), ["tracekit why serve is now part of tracekit view: "
                                                       "`tracekit view --why ROOT`; this command keeps working"])

class BoundedState(unittest.TestCase):
    """What a long-running viewer keeps per run, approval or session stays bounded however many it sees."""

    def test_the_translators_per_run_and_per_approval_maps_are_bounded(self):
        from tracekit import observe
        cap = 100
        with mock.patch.object(observe, "MAX_RUNS_KEPT", cap):
            t1, t2 = observe.Translator(), view.Translator()
            for i in range(cap * 10):
                run = f"run-{i}"
                t1.feed({"hash": "h", "event": {"run_id": run, "type": "run.start", "ts": "2026-10-12T00:00:00Z",
                                                "agent_id": f"child-{i}", "data": {"cwd": "/w", "agent": {"name": "a"}}}})
                for typ, data in (("run.registered", {"agent": {"name": "a"}}),
                                  ("approval.request", {"approval_id": f"apr-{i}", "binding": {"tool": "pay"}}),
                                  ("approval.suggested", {"approval_id": f"apr-{i}", "decision": "approve"})):
                    t2.feed({"hash": "h", "event": {"run_id": run, "type": typ, "ts": "2026-10-12T00:00:00Z",
                                                    "seq": i, "run_seq": 0, "data": data}})
        for name in ("cwd", "agent_names", "seen_agents"):
            self.assertLessEqual(len(getattr(t1, name)), cap, name)
        for name in ("agent_names", "requests", "suggested"):
            self.assertLessEqual(len(getattr(t2, name)), cap, name)

    def test_the_store_feed_keeps_its_newest_records(self):
        import types
        feed = types.SimpleNamespace(records=[], base=0, max_records=100)
        for i in range(1000):
            feed.records.append({"seq": i})
            view.StoreFeed._trim(feed)
        self.assertEqual((len(feed.records), feed.base, feed.records[0]["seq"]), (100, 900, 900))

    def test_expired_sessions_are_evicted_before_live_ones(self):
        login = view.OidcLogin.__new__(view.OidcLogin)
        login._lock, login._sessions, now = threading.Lock(), collections.OrderedDict(), [1000.0]
        login.clock = lambda: now[0]
        with mock.patch.object(view, "SESSIONS_MAX", 4):
            login._keep("live", {"until": 5000})
            for i in range(3):
                login._keep(f"old-{i}", {"until": 1500})
            now[0] = 2000   # the three old ones have expired
            login._keep("new", {"until": 9000})
            login._keep("newer", {"until": 9000})
        self.assertEqual(list(login._sessions), ["live", "new", "newer"])


if __name__ == "__main__":
    unittest.main()
