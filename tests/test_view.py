"""`tracekit view`: the v2 signer's runs, each verified by verify.v2, served with the observer's page and security."""
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
from unittest import mock

import test_signer_service as ts
from factories import wait_for
from test_observe_render import XSS, script_of, unescaped
from tracekit import view
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage

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
        gap, final = self.feed(
            v2rec(1, "capture.gap", {"kind": "client_counter_gap", "missed_events": 3, "reason": "stream s skipped"}),
            v2rec(2, "run.final", {"head_run_seq": 1, "coverage": {"layers": ["L2"], "reconciled": 0,
                                                                   "unreconciled": {"hook_missing": 1}}}))
        self.assertEqual((gap["tape"], gap["title"], gap["text"], gap["v2"]["kind"]),
                         ("GAP", "GAP · client_counter_gap", "stream s skipped · 3 events missed",
                          "client_counter_gap"))
        self.assertEqual(final["reason"], "final · head run_seq 1 · coverage L2 · reconciled 0 · unreconciled "
                                          "hook_missing 1")
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
        self.assertEqual(rv["coverage"], {"layers": ["L2", "L3"], "reconciled": 4, "unreconciled": {}})
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


if __name__ == "__main__":
    unittest.main()
