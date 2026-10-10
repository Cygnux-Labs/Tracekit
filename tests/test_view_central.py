"""The central viewer (view.Runs on observe.make_handler): two Postgres logs, each read as a SELECT-only role, with runs
of two tenants. Tenant scoping on every endpoint, bounded pages, the operator-side label on every verdict, and a
downloaded bundle that verifies offline. Needs what tests/test_storage_postgres.py needs; skipped otherwise."""
import http.client
import json
import os
import socket
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import test_storage_postgres as pg
from factories import wait_for
from test_e13_approvals import Sessions
from test_signer_service import ME, tmpdir
from tracekit import observe, view
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import pipeline
from tracekit.signer import service as svc
from tracekit.verify import v2

setUpModule, tearDownModule = pg.setUpModule, pg.tearDownModule
POLICY = Engine({"deny": [{"id": "T-DENY", "tool": "rm", "pattern": "^"}]})
TOKEN = "central-viewer-token"
SIGNER_RUN = pipeline.SIGNER_RUN[1]   # each log's signer-level records: a run only an operator-admin lists


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class CentralViewer(unittest.TestCase):
    def make_log(self, runs):
        """A Postgres log whose signer ran `runs` ({agent name: (tenant, [tool, ...])}), each closed and covered by a
        checkpoint: (its reader's DSN file, its log vkey, {agent name: run id}, the superuser's DSN)."""
        d = tmpdir(self)
        admin, signer = pg.new_log(self)
        for name, dsn in (("signer.dsn", signer), ("reader.dsn", pg.reader_dsn(admin))):
            with open(os.path.join(d, name), "w") as f:
                f.write(dsn)
        cfg = {"data_dir": os.path.join(d, "data"), "socket": os.path.join(d, "s.sock"), "grace_s": 0,
               "multi_tenant_apps": [f"uid:{ME.subject}"],
               "storage": {"postgres": {"dsn_file": os.path.join(d, "signer.dsn")}}}
        service = svc.open_service(cfg, policy=POLICY)
        self.addCleanup(service.close)
        for srv in svc.serve(cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = Client(cfg["socket"])
        self.addCleanup(client.close)
        ids = {}
        for name, (tenant, tools) in runs.items():
            run = client.run(agent=name, tenant=tenant)
            for n, tool in enumerate(tools):
                if run.decide(f"c{n}", tool, {"x": n})["decision"] == "allow":
                    run.complete(f"c{n}")
            run.close()
            ids[name] = run.run_id
        storage = service.log.storage
        self.assertTrue(wait_for(lambda: all(list(storage.iter_run(runs[n][0], r))[-1]["event"]["type"] == "run.final"
                                             for n, r in ids.items()), 20))
        client.call("checkpoint_nudge", {})
        self.assertTrue(wait_for(lambda: (storage.checkpoint_latest() or (0,))[0] == storage.tree.size, 20))
        return os.path.join(d, "reader.dsn"), service.vkey, ids, admin

    def setUp(self):
        f0, self.vkey0, ids0, _ = self.make_log({"a1": ("acme", ["Bash", "rm"]), "b1": ("beta", ["Bash"]),
                                                 "a3": ("acme", ["Bash"])})
        f1, _, ids1, self.admin1 = self.make_log({"b2": ("beta", ["Bash"]), "a2": ("acme", ["Bash"])})
        self.files, self.ids = [f0, f1], {**ids0, **ids1}
        self.names = {v: k for k, v in self.ids.items()}
        self.sessions = Sessions()
        self.acme, self.beta, self.admin = (
            f"{observe.COOKIE}={self.sessions.add({'tenant': t}, role)}"
            for t, role in (("acme", "auditor"), ("beta", "approver"), (observe.ALL, "operator-admin")))
        self.port = self.serve(view.Runs(self.files))

    def serve(self, runs):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(None, TOKEN, ["127.0.0.1"],
                                                                         login=self.sessions, runs=runs))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def get(self, path, cookie="", port=None):
        c = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=30)
        try:
            c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
            r = c.getresponse()
            return r.status, r, r.read()
        finally:
            c.close()

    def listed(self, query, cookie):
        status, _, body = self.get("/api/runs" + query, cookie)
        self.assertEqual(status, 200, body)
        return [self.names.get(r["run_id"], r["run_id"]) for r in json.loads(body)["runs"]]

    def test_every_endpoint_reads_the_sessions_tenant_only(self):
        b1 = self.ids["b1"]
        self.assertEqual(sorted(self.listed("", self.acme)), ["a1", "a2", "a3"])
        self.assertEqual(sorted(self.listed("?tenant=beta", self.acme)), ["a1", "a2", "a3"])
        self.assertEqual(self.listed(f"?run={b1}", self.acme), [])
        self.assertEqual(sorted(self.listed("", self.beta)), ["b1", "b2"])
        for path in ("/api/run", "/api/bundle"):
            for tenant in ("beta", "acme"):   # B's run by its id, under either tenant
                self.assertEqual(self.get(f"{path}?log=0&tenant={tenant}&run={b1}", self.acme)[0], 404, (path, tenant))
            self.assertEqual(self.get(f"{path}?log=0&tenant=acme&run={self.ids['a1']}", self.acme)[0], 200)
            self.assertEqual(self.get(f"{path}?log=0&tenant=beta&run={b1}", self.admin)[0], 200)
            self.assertEqual(self.get(f"{path}?log=0&tenant=beta&run={b1}", self.beta)[0], 200)
        self.assertEqual(sorted(self.listed("", self.admin)), ["a1", "a2", "a3", "b1", "b2"] + [SIGNER_RUN] * 2)
        self.assertEqual(sorted(self.listed("?tenant=beta", self.admin)), ["b1", "b2"])
        for path in ("/runs", "/api/runs", f"/api/run?log=0&tenant=beta&run={b1}",
                     f"/api/bundle?log=0&tenant=beta&run={b1}"):
            for cookie in ("", f"{observe.COOKIE}=forged"):
                self.assertEqual(self.get(path, cookie)[0], 401, (path, cookie))
        status, r, page = self.get("/runs", self.acme)
        self.assertEqual(status, 200)
        self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy"))
        self.assertEqual(self.get("/", self.acme)[1].getheader("Location"), "/runs")

    def test_pages_are_bounded_and_filters_apply(self):
        seen, after, pages = [], None, 0
        with mock.patch.object(pg.postgres, "search_runs", wraps=pg.postgres.search_runs) as query:
            while True:
                query.reset_mock()
                status, _, body = self.get("/api/runs?limit=2" + (f"&after={after}" if after else ""), self.admin)
                page = json.loads(body)
                self.assertLessEqual(len(page["runs"]), 2)
                self.assertLessEqual(query.call_count, len(self.files))   # at most one query per log
                self.assertTrue(all(c.args[2] <= 2 for c in query.call_args_list))   # each LIMIT within the page
                seen += [self.names.get(r["run_id"], r["run_id"]) for r in page["runs"]]
                after, pages = page["next"], pages + 1
                if not after:
                    break
        self.assertEqual(seen, ["a3", "b1", "a1", SIGNER_RUN, "a2", "b2", SIGNER_RUN])   # log by log, newest first
        self.assertEqual(pages, 4)
        for query, names in (("?denies=1", ["a1"]), ("?agent=a2", ["a2"]), (f"?run={self.ids['a3']}", ["a3"]),
                             ("?since=9999", []), ("?until=2000", []), ("?since=2000&until=9999", ["a3", "a1", "a2"]),
                             ("?verdict=verified", ["a3", "a1", "a2"]), ("?verdict=failed", []), ("?gaps=1", []),
                             ("?approvals=1", [])):
            self.assertEqual(self.listed(query, self.acme), names, query)
        for query in ("?limit=0", f"?limit={view.RUNS_PAGE + 1}", "?limit=x", "?after=x", "?verdict=good", "?nope=1"):
            self.assertEqual(self.get("/api/runs" + query, self.acme)[0], 400, query)
        a1 = f"/api/run?log=0&tenant=acme&run={self.ids['a1']}"
        for query in ("&from=x", "&from=-1"):
            self.assertEqual(self.get(a1 + query, self.acme)[0], 400)
        for path in ("/api/run?log=2&tenant=acme&run=x", "/api/run?log=0&tenant=acme", "/api/bundle?log=x"):
            self.assertEqual(self.get(path, self.acme)[0], 400, path)
        records = json.loads(self.get(a1, self.acme)[2])["records"]
        self.assertEqual([r["event"]["type"] for r in records][0], "run.registered")
        with mock.patch.object(view, "RECORDS_PAGE", 2):
            run = json.loads(self.get(a1 + "&from=1", self.acme)[2])
        self.assertEqual((run["records"], run["next"]), (records[1:3], 3))

    def test_every_verdict_is_labelled_and_a_failed_run_shows_no_records(self):
        status, _, body = self.get("/api/runs", self.admin)
        runs = json.loads(body)["runs"]
        self.assertEqual({r["verdict"]["label"] for r in runs}, {view.OPERATOR_SIDE})
        self.assertEqual({r["verdict"]["integrity"] for r in runs if r["run_id"] in self.names}, {"VERIFIED"})
        run = json.loads(self.get(f"/api/run?log=0&tenant=acme&run={self.ids['a1']}", self.acme)[2])
        self.assertEqual(run["verdict"]["label"], view.OPERATOR_SIDE)
        self.assertIn("Integrity: VERIFIED.", run["verdict"]["report"])
        self.assertTrue(run["records"])
        pg.sql(self.admin1, "UPDATE tracekit_records SET record = regexp_replace(record::text, '\"tool\": ?\"Bash\"', "
               "'\"tool\":\"Bosh\"')::json WHERE run_id = %s", (self.ids["a2"],))
        port = self.serve(view.Runs(self.files))   # verdicts are kept per run size: a viewer that has not seen it
        run = json.loads(self.get(f"/api/run?log=1&tenant=acme&run={self.ids['a2']}", self.acme, port)[2])
        self.assertEqual((run["verdict"]["verdict"], run["verdict"]["integrity"], run["verdict"]["label"],
                          run["records"]), ("failed", "FAILED", view.OPERATOR_SIDE, []))
        status, _, body = self.get("/api/runs?verdict=failed", self.acme, port)
        self.assertEqual([(r["run_id"], r["verdict"]["label"]) for r in json.loads(body)["runs"]],
                         [(self.ids["a2"], view.OPERATOR_SIDE)])

    def test_downloaded_bundle_verifies_offline(self):
        status, r, data = self.get(f"/api/bundle?log=0&tenant=acme&run={self.ids['a1']}", self.acme)
        self.assertEqual(status, 200)
        self.assertEqual(r.getheader("Content-Disposition"), 'attachment; filename="run.tkb"')
        d = tmpdir(self)
        out, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
        with open(out, "wb") as f:
            f.write(data)
        view.write_trust(trust, [self.vkey0])
        self.assertEqual(v2.verify(out, trust)[1], 0)


if __name__ == "__main__":
    unittest.main()
