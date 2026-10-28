"""The central viewer (view.Runs on observe.make_handler): two Postgres logs, each read as a SELECT-only role, with runs
of two tenants. Tenant scoping on every endpoint, bounded pages, the operator-side label on every verdict, and a
downloaded bundle that verifies offline. Needs what tests/test_storage_postgres.py needs; skipped otherwise."""
import http.client
import json
import os
import socket
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import pytest

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
        for query in ("?limit=0", f"?limit={view.RUNS_PAGE + 1}", "?limit=x", "?after=x", "?verdict=good", "?nope=1", "?gaps=0"):
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

    @pytest.mark.unverified_bundles
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
        run = json.loads(self.get(f"/api/run?log=1&tenant=acme&run={self.ids['a2']}", self.acme)[2])
        self.assertEqual((run["verdict"]["verdict"], run["verdict"]["integrity"], run["verdict"]["label"],
                          run["records"]), ("failed", "FAILED", view.OPERATOR_SIDE, []))
        status, _, body = self.get("/api/runs?verdict=failed", self.acme)
        self.assertEqual([(r["run_id"], r["verdict"]["label"]) for r in json.loads(body)["runs"]],
                         [(self.ids["a2"], view.OPERATOR_SIDE)])

    @pytest.mark.unverified_bundles
    def test_the_run_list_checks_a_run_again_once_its_verdict_is_old(self):
        """The run list kept a run's "verified" for good after its records were edited in place (the same count): it
        changed only once someone opened that run's page."""
        self.assertIn("a2", self.listed("?verdict=verified", self.acme))
        pg.sql(self.admin1, "UPDATE tracekit_records SET record = regexp_replace(record::text, '\"tool\": ?\"Bash\"', "
               "'\"tool\":\"Bosh\"')::json WHERE run_id = %s", (self.ids["a2"],))
        self.assertIn("a2", self.listed("?verdict=verified", self.acme))   # the last check's verdict, until it is old
        with mock.patch.object(view.time, "monotonic", return_value=time.monotonic() + view.RECHECK_S + 1):
            self.assertEqual(self.listed("?verdict=failed", self.acme), ["a2"])

    def test_a_list_checks_a_run_only_with_a_check_slot_free(self):
        """A list checked every run whose verdict was old or missing, with no limit: 16 lists at once made 91 checks of
        6 runs. With the list's check slot taken it checks none: a past-due VERIFIED, and a run never checked, show as
        NOT CHECKED."""
        def listed(port):
            runs = json.loads(self.get("/api/runs", self.admin, port)[2])["runs"]
            return {self.names[r["run_id"]]: r["verdict"]["integrity"] for r in runs if r["run_id"] in self.names}
        runs, fresh = view.Runs(self.files), view.Runs(self.files)
        port, fresh_port = self.serve(runs), self.serve(fresh)
        kept = listed(port)
        self.assertEqual(set(kept.values()), {"VERIFIED"})
        for r in (runs, fresh):
            r.listing.acquire()
        with mock.patch.object(view, "check", wraps=view.check) as checked, \
                mock.patch.object(view.time, "monotonic", return_value=time.monotonic() + view.RECHECK_S + 1):
            self.assertEqual(listed(port), dict.fromkeys(kept, "NOT CHECKED"))
            self.assertEqual(listed(fresh_port), dict.fromkeys(kept, "NOT CHECKED"))
        self.assertEqual(checked.call_count, 0)

    @pytest.mark.unverified_bundles
    def test_a_list_that_cannot_check_never_shows_a_past_due_verified(self):
        """With the list's check slot taken, a VERIFIED past RECHECK_S still showed VERIFIED after the run's records
        were edited in place. It reads NOT CHECKED; a kept FAILED stays FAILED, and one within RECHECK_S shows as is."""
        runs = view.Runs(self.files)
        port, t0 = self.serve(runs), time.monotonic()

        def a2(now):
            with mock.patch.object(view.time, "monotonic", return_value=now):
                listed = json.loads(self.get("/api/runs", self.admin, port)[2])["runs"]
            return next(r["verdict"]["integrity"] for r in listed if r["run_id"] == self.ids["a2"])
        self.assertEqual(a2(t0), "VERIFIED")
        pg.sql(self.admin1, "UPDATE tracekit_records SET record = regexp_replace(record::text, '\"tool\": ?\"Bash\"', "
               "'\"tool\":\"Bosh\"')::json WHERE run_id = %s", (self.ids["a2"],))
        runs.listing.acquire()
        self.assertEqual(a2(t0), "VERIFIED")   # within RECHECK_S: the kept verdict
        self.assertEqual(a2(t0 + view.RECHECK_S + 1), "NOT CHECKED")   # past due and not checked again: not VERIFIED
        runs.listing.release()
        self.assertEqual(a2(t0 + view.RECHECK_S + 1), "FAILED")
        runs.listing.acquire()
        self.assertEqual(a2(t0 + 3 * view.RECHECK_S), "FAILED")

    def test_a_run_page_has_a_check_slot_while_lists_check(self):
        """Lists took the run pages' two check slots: during two lists that were checking, a run page got 503 on every
        try (runs.html doesn't try again)."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        real, gate, entered, hold = view.check, threading.Event(), [], [True]

        def check(r, tenant, run_id, *a, **k):   # a list's check waits at the gate, holding its slot
            entered.append((run_id, a[1]))   # a run of a log (its trust file): both logs hold the signer's own run
            if hold[0]:
                gate.wait(20)
            return real(r, tenant, run_id, *a, **k)
        with mock.patch.object(view, "check", side_effect=check):
            lists = [threading.Thread(target=self.get, args=("/api/runs", self.admin, port)) for _ in range(2)]
            for t in lists:
                t.start()
            self.assertTrue(wait_for(lambda: len(entered) == 2 or sum(t.is_alive() for t in lists) == 1, 10))
            hold[0] = False
            self.assertEqual(self.get(f"/api/run?log=0&tenant=acme&run={self.ids['a1']}", self.acme, port)[0], 200)
            gate.set()
            for t in lists:
                t.join(20)

    def test_two_lists_with_a_free_slot_each_check_each_run_once(self):
        """Two lists checked the same runs twice (14 checks for 7 runs): a run a list checked keeps its verdict for the
        next list, which checks nothing."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        real, checked = view.check, []

        def check(r, tenant, run_id, *a, **k):
            checked.append((run_id, a[1]))   # a run of a log (its trust file): both logs hold the signer's own run
            return real(r, tenant, run_id, *a, **k)
        with mock.patch.object(view, "check", side_effect=check):
            first = self.get("/api/runs", self.admin, port)
            self.assertEqual(first[0], 200)
            after = len(checked)
            self.assertEqual(self.get("/api/runs", self.admin, port)[0], 200)
        self.assertLessEqual(set(self.ids.values()), {run_id for run_id, _ in checked})
        self.assertEqual(sorted(checked), sorted(set(checked)))   # one check per run
        self.assertEqual(len(checked), after)   # the second list checked nothing

    @pytest.mark.unverified_bundles
    def test_a_clock_stepped_back_never_keeps_a_stale_verified(self):
        """Verdicts were kept by the wall clock: after it stepped back (an NTP step, a manual change), a run page's
        FAILED was older than the list's VERIFIED and wasn't kept, and lists showed VERIFIED for the step plus
        RECHECK_S."""
        runs = view.Runs(self.files)
        port = self.serve(runs)

        def listed(query, cookie):
            status, _, body = self.get("/api/runs" + query, cookie, port)
            self.assertEqual(status, 200, body)
            return [self.names.get(r["run_id"], r["run_id"]) for r in json.loads(body)["runs"]]
        self.assertIn("a2", listed("?verdict=verified", self.acme))
        pg.sql(self.admin1, "UPDATE tracekit_records SET record = regexp_replace(record::text, '\"tool\": ?\"Bash\"', "
               "'\"tool\":\"Bosh\"')::json WHERE run_id = %s", (self.ids["a2"],))
        with mock.patch.object(view.time, "time", return_value=time.time() - 3600):   # the clock steps back an hour
            status, _, body = self.get(f"/api/run?log=1&tenant=acme&run={self.ids['a2']}", self.acme, port)
            self.assertEqual((status, json.loads(body)["verdict"]["verdict"]), (200, "failed"))
            self.assertEqual(listed("?verdict=failed", self.acme), ["a2"])

    @pytest.mark.unverified_bundles
    def test_a_lists_check_of_an_older_snapshot_never_replaces_a_newer_verdict(self):
        """A list reads one snapshot from its start: a record edited during a list turned the run's page FAILED, and the
        list's check of its older snapshot then kept VERIFIED over it, for RECHECK_S."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        a2, real, page = self.ids["a2"], view.check, []

        def listed(query, cookie):
            status, _, body = self.get("/api/runs" + query, cookie, port)
            self.assertEqual(status, 200, body)
            return [self.names.get(r["run_id"], r["run_id"]) for r in json.loads(body)["runs"]]

        def check(r, tenant, run_id, *a, **k):   # a2's check in the list: the run is edited and its page opened first
            if run_id == a2 and not page:
                page.append(0)
                pg.sql(self.admin1, "UPDATE tracekit_records SET record = regexp_replace(record::text, "
                       "'\"tool\": ?\"Bash\"', '\"tool\":\"Bosh\"')::json WHERE run_id = %s", (a2,))
                page[0] = runs.run(observe.ALL, {"log": "1", "tenant": "acme", "run": a2})["verdict"]["verdict"]
            return real(r, tenant, run_id, *a, **k)
        with mock.patch.object(view, "check", side_effect=check):
            self.assertIn("a2", listed("?verdict=verified", self.admin))   # the list's own, older snapshot
        self.assertEqual(page, ["failed"])
        self.assertEqual(listed("?verdict=failed", self.acme), ["a2"])   # the page's newer verdict is kept

    def test_a_run_page_checks_two_runs_at_once_at_most(self):
        """Each /api/run request read the log and exported and verified its run with no limit: 16 at once made 16 full
        checks."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        a1 = f"/api/run?log=0&tenant=acme&run={self.ids['a1']}"
        runs.verifying = threading.BoundedSemaphore(1)
        runs.verifying.acquire()
        status, r, _ = self.get(a1, self.acme, port)
        self.assertEqual((status, r.getheader("Retry-After")), (503, "5"))
        runs.verifying.release()
        self.assertEqual(self.get(a1, self.acme, port)[0], 200)

    def test_a_run_page_serves_the_records_its_check_verified(self):
        """/api/run checked the run, then read its records from the store again: a reader that saw an edit between the
        two (any but one snapshot) served the edited records beside the VERIFIED verdict."""
        real_open, real_check = view.Runs._open, view.check

        class Edited:   # the store as read after the check: every Bash call renamed
            def __init__(self, r):
                self.r, self.checked = r, False

            def __getattr__(self, k):
                return getattr(self.r, k)

            def iter_run(self, tenant, run_id):
                for rec in self.r.iter_run(tenant, run_id):
                    yield json.loads(json.dumps(rec).replace('"Bash"', '"Bosh"')) if self.checked else rec

        def open_(runs, i):
            r, note, at = real_open(runs, i)
            return Edited(r), note, at

        def check(r, *a, **k):
            out = real_check(r, *a, **k)
            r.checked = True
            return out
        with mock.patch.object(view.Runs, "_open", open_), mock.patch.object(view, "check", check):
            port = self.serve(view.Runs(self.files))
            run = json.loads(self.get(f"/api/run?log=0&tenant=acme&run={self.ids['a1']}", self.acme, port)[2])
        self.assertEqual(run["verdict"]["verdict"], "verified")
        tools = {rec["event"]["data"].get("tool") for rec in run["records"]} - {None}
        self.assertIn("Bash", tools)
        self.assertNotIn("Bosh", tools)

    def test_a_bundle_download_takes_the_same_limit(self):
        """Each /api/bundle request read the log and exported its whole run, with no limit."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        a1 = f"/api/bundle?log=0&tenant=acme&run={self.ids['a1']}"
        runs.verifying = threading.BoundedSemaphore(1)
        runs.verifying.acquire()
        status, r, _ = self.get(a1, self.acme, port)
        self.assertEqual((status, r.getheader("Retry-After")), (503, "5"))
        runs.verifying.release()
        self.assertEqual(self.get(a1, self.acme, port)[0], 200)

    def test_a_bundle_whose_temp_file_fails_gives_its_slot_back(self):
        """The bundle's temp file was made after the check slot was taken and before the try that gives it back: two
        failures (a full disk, no file descriptors) left /api/run and /api/bundle answering 503 until a restart."""
        runs = view.Runs(self.files)
        port = self.serve(runs)
        a1 = f"log=0&tenant=acme&run={self.ids['a1']}"
        with mock.patch.object(view.tempfile, "mkstemp", side_effect=OSError(28, "No space left on device")):
            for _ in range(2):
                self.assertEqual(self.get(f"/api/bundle?{a1}", self.acme, port)[0], 502)
        self.assertEqual((self.get(f"/api/bundle?{a1}", self.acme, port)[0], self.get(f"/api/run?{a1}", self.acme, port)[0]),
                         (200, 200))

    def test_downloaded_bundle_verifies_offline(self):
        status, r, data = self.get(f"/api/bundle?log=0&tenant=acme&run={self.ids['a1']}", self.acme)
        self.assertEqual(status, 200)
        # each download is named by its run, so two saved bundles never overwrite each other
        self.assertEqual(r.getheader("Content-Disposition"), f'attachment; filename="{self.ids["a1"]}.tkb"')
        d = tmpdir(self)
        out, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
        with open(out, "wb") as f:
            f.write(data)
        view.write_trust(trust, [self.vkey0])
        self.assertEqual(v2.verify(out, trust)[1], 0)


if __name__ == "__main__":
    unittest.main()
