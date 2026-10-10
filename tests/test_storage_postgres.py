"""The Postgres storage backend: the storage contract run as a signer role holding only postgres.GRANTS, what only
Postgres has (the advisory lock, a killed transaction, migrate, edited rows), and the signer's suites that take a storage
(lifecycle, snapshots, witness queue) on Postgres, and PostgresReader as a role holding only postgres.READ_GRANTS. Needs psycopg and TRACEKIT_TEST_PG_DSN (a superuser DSN), or initdb
and pg_ctl on PATH (a throwaway cluster in a temp dir); skipped otherwise."""
import contextlib
import hmac
import io
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import test_format_bridge
import test_signer_lifecycle
import test_witness_publish
from storage_contract import Chain, StorageContract
from test_signer_checkpoints import run_cli
from test_signer_service import ME, tmpdir
from tracekit import view
from tracekit.format.canon import event_hash
from tracekit.format.records import RecordSigner
from tracekit.sdk.client import Client
from tracekit.signer import format_bridge
from tracekit.signer import service as svc
from tracekit.storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, StorageUnavailable, registry_tree
from tracekit.verify import v2

try:
    import psycopg
    from psycopg.conninfo import make_conninfo
    from tracekit.storage import postgres
    from tracekit.storage.postgres import PostgresStorage
except ImportError:
    psycopg = None

ADMIN, CLUSTER = None, None
SIGNER, READER = "tracekit_signer_test", "tracekit_reader_test"


def setUpModule():
    global ADMIN, CLUSTER
    if psycopg is None:
        raise unittest.SkipTest("needs psycopg: pip install 'tracekit-ai[postgres]'")
    ADMIN = os.environ.get("TRACEKIT_TEST_PG_DSN")
    if not ADMIN:
        if not (shutil.which("initdb") and shutil.which("pg_ctl")):
            raise unittest.SkipTest("needs TRACEKIT_TEST_PG_DSN, or initdb and pg_ctl on PATH")
        CLUSTER = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: the socket path
        data = os.path.join(CLUSTER, "data")
        subprocess.run(["initdb", "-D", data, "-A", "trust", "-U", "postgres", "--no-sync"], check=True,
                       capture_output=True)
        subprocess.run(["pg_ctl", "-D", data, "-l", os.path.join(CLUSTER, "log"), "-w", "-o",
                        f"-k {CLUSTER} -c listen_addresses='' -c fsync=off", "start"], check=True, capture_output=True)
        ADMIN = make_conninfo(host=CLUSTER, dbname="postgres", user="postgres")
    with psycopg.connect(ADMIN, autocommit=True) as c:
        for role in (SIGNER, READER):
            c.execute(f"DO $$ BEGIN CREATE ROLE {role} NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$")


def tearDownModule():
    if CLUSTER:
        subprocess.run(["pg_ctl", "-D", os.path.join(CLUSTER, "data"), "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(CLUSTER, ignore_errors=True)


def new_log(case, migrate=True):
    """A fresh schema (dropped after the test): (the superuser's DSN, the signer role's DSN) of it."""
    schema = "t" + secrets.token_hex(8)
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
    case.addCleanup(lambda: psycopg.connect(ADMIN, autocommit=True).execute(f"DROP SCHEMA {schema} CASCADE").close())
    admin = make_conninfo(ADMIN, options=f"-c search_path={schema}")
    if migrate:
        postgres.migrate(admin)
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(postgres.GRANTS.format(schema=schema, role=SIGNER))
    return admin, make_conninfo(ADMIN, options=f"-c search_path={schema} -c role={SIGNER}")


def reader_dsn(admin):
    """The DSN of the log of `admin` as the reader role, granted postgres.READ_GRANTS (SELECT only)."""
    schema = sql(admin, "SELECT current_schema()")[0][0]
    sql(admin, postgres.READ_GRANTS.format(schema=schema, role=READER))
    return make_conninfo(ADMIN, options=f"-c search_path={schema} -c role={READER}")


def sql(dsn, query, params=()):
    with psycopg.connect(dsn, autocommit=True) as c:
        cur = c.execute(query, params)
        return cur.fetchall() if cur.description else None


class PgCase(unittest.TestCase):
    def setUp(self):
        self.admin, self.dsn = new_log(self)

    def open(self, mode=ACK_ON_WRITE, **kw):
        return PostgresStorage(self.dsn, mode, **kw)


class TestContract(StorageContract, PgCase):
    def damage(self, seq):
        sql(self.admin, "UPDATE tracekit_records SET record = replace(record::text, %s, %s)::json WHERE seq = %s",
            (f'"t{seq}"', f'"x{seq}"', seq))

    test_torn_tail_is_set_aside_and_reported = unittest.skip(
        "a crash mid-transaction leaves nothing to set aside: see test_a_killed_transaction_leaves_nothing")(
        StorageContract.test_torn_tail_is_set_aside_and_reported)


class TestPostgresStorage(PgCase):
    def test_a_killed_transaction_leaves_nothing(self):
        s, c = self.open(ACK_ON_FSYNC), Chain()
        self.addCleanup(s.close)
        records = c.batch(3)
        s.append_batch(records)
        index = s._index

        def killed(*a):   # the connection dies mid-transaction, after the INSERT
            sql(self.admin, "SELECT pg_terminate_backend(%s)", (s.conn.info.backend_pid,))
            return index(*a)
        with mock.patch.object(s, "_index", killed), self.assertRaises(StorageUnavailable):
            s.append_batch(c.batch(2))
        self.assertEqual(s.tail_state()["tree_size"], 3)
        with self.assertRaises(StorageUnavailable):
            s.append_batch(c.batch(1))
        s.close()
        s = self.open()
        self.addCleanup(s.close)
        self.assertEqual((list(s.iter_range(0, 10)), s.torn, s.fsck()), (records, [], []))
        c = Chain()
        c.batch(3)
        s.append_batch(c.batch(2))
        self.assertEqual(s.tail_state()["tree_size"], 5)

    def test_one_writer_waits_then_names_the_holder(self):
        s = self.open()
        start = time.monotonic()
        with self.assertRaises(BlockingIOError) as e:
            self.open(lock_timeout_s=0.3)
        self.assertGreaterEqual(time.monotonic() - start, 0.3)
        self.assertRegex(e.exception.strerror, rf"another signer holds schema t\w+ of database \w+ "
                                               rf"\(tracekit-signer pid {os.getpid()}, backend pid \d+\)")
        s.close()
        self.open().close()

    def test_the_signer_role_cannot_edit_or_delete_records(self):
        s = self.open()
        self.addCleanup(s.close)
        s.append_batch(Chain().batch(2))
        for query in ("UPDATE tracekit_records SET hash = 'x'", "DELETE FROM tracekit_records",
                      "UPDATE tracekit_notes SET note = 'x'", "DELETE FROM tracekit_registry"):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                sql(self.dsn, query)

    def test_fsck_finds_edited_columns_and_deleted_rows(self):
        s = self.open()
        self.addCleanup(s.close)
        s.append_batch(Chain().batch(5))
        s.registry_append("acme", b"\x01" * 89)
        s.registry_append("acme", b"\x02" * 89)
        sql(self.admin, "UPDATE tracekit_records SET run_id = 'other' WHERE seq = 1")
        sql(self.admin, "DELETE FROM tracekit_records WHERE seq = 3")
        sql(self.admin, "DELETE FROM tracekit_registry WHERE idx = 0")
        self.assertEqual(s.fsck(), ["records line 4: breaks the log chain", "records line 4: breaks the chain of run "
                                    "'run-1'", "records line 2: its columns do not match the record",
                                    "registry: the leaves of tenant 'acme' are not numbered 0 to 0"])

    def test_open_needs_migrate_and_migrate_is_idempotent(self):
        admin, dsn = new_log(self, migrate=False)
        with self.assertRaisesRegex(ValueError, "tracekit signer migrate"):
            PostgresStorage(admin)
        self.assertEqual((postgres.migrate(admin), postgres.migrate(admin)), (1, 1))
        PostgresStorage(admin).close()

    def test_durability_modes(self):
        for mode, setting in ((ACK_ON_WRITE, "off"), (ACK_ON_FSYNC, "on")):
            s = self.open(mode)
            self.assertEqual(s.conn.execute("SHOW synchronous_commit").fetchone()[0], setting)
            with s._write(True) as conn:   # notes, anchors, snapshots and the witness queue
                self.assertEqual(conn.execute("SHOW synchronous_commit").fetchone()[0], "on")
            s.close()

    def test_snapshots(self):
        key, c = os.urandom(32), Chain()
        s = self.open(snapshot_key=key)
        s.append_batch(c.batch(300, ("a", "b")))
        s.registry_append("acme", b"\x01" * 89)
        s.snapshot_put({"x": 1})
        s.append_batch(c.batch(5, ("a", "c")))
        before = s.tail_state()
        s.close()
        s = self.open(snapshot_key=key)
        self.assertEqual((s.snapshot["size"], s.snapshot["state"], s.tail_state()), (300, {"x": 1}, before))
        for _ in range(3):
            s.append_batch(c.batch(1))
            s.snapshot_put({})
        s.close()
        self.assertEqual(sql(self.admin, "SELECT size FROM tracekit_snapshots ORDER BY size"), [(307,), (308,)])
        sql(self.admin, "UPDATE tracekit_snapshots SET body = replace(body, '\"state\":{}', '\"state\":{\"y\":1}')")
        self.assertEqual(postgres.fsck(self.dsn, key), [
            f"snapshots/{n}: does not match the log or its MAC, so open ignores it and replays the log in full"
            for n in (307, 308)])
        s = self.open(snapshot_key=key)
        self.addCleanup(s.close)
        self.assertIsNone(s.snapshot)
        self.assertEqual(s.tail_state()["tree_size"], 308)


class TestPostgresReader(PgCase):
    def test_reads_a_snapshot_of_the_store_with_select_only_and_no_lock(self):
        s, c = self.open(), Chain()
        self.addCleanup(s.close)
        records = c.batch(600, runs=("run-1", "run-2"))
        s.append_batch(records)
        s.checkpoint_put(600, "note 600")
        leaves = [bytes([i]) * 89 for i in range(3)]
        for leaf in leaves:
            s.registry_append("acme", leaf)
        s.checkpoint_put(3, "registry note 3", registry_tree("acme"))
        s.anchor_put(600, {"note": "note 600"})
        records += c.batch(5)
        s.append_batch(records[600:])
        r = postgres.PostgresReader(reader_dsn(self.admin))   # while the writer holds the log's lock
        self.addCleanup(r.close)
        self.assertEqual((r.tree.size, r.tree.root()), (600, s.tree.root_at(600)))   # from the tiles: 2 full, 2 edges
        for i in (0, 300, 599):
            self.assertEqual(r.tree.inclusion_proof(i, 600), s.tree.inclusion_proof(i, 600))
        self.assertEqual(r.runs[("acme", "run-2")]["seqs"], list(range(1, 600, 2)))
        self.assertEqual(r.get_run("acme", "run-1"), s.get_run("acme", "run-1"))
        self.assertEqual(list(r.iter_run("acme", "run-1"))[-1], records[604])
        self.assertEqual(list(r.iter_range(598, 10**6)), records[598:])
        self.assertEqual((r.checkpoint_latest(), r.anchors()), ((600, "note 600"), s.anchors()))
        self.assertEqual((r.registry_merkle("acme").root(), list(r.registry_iter("acme"))),
                         (s.registry_merkle("acme").root(), leaves))
        self.assertEqual(r.checkpoint_at(registry_tree("acme"), 3), "registry note 3")
        s.append_batch(c.batch(1))
        s.checkpoint_put(606, "note 606")
        self.assertEqual((len(list(r.iter_range(0, 10**6))), r.checkpoint_latest()), (605, (600, "note 600")))
        s.close()
        self.open().close()   # a writer opens alongside the reader
        with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):
            r.conn.execute("INSERT INTO tracekit_meta VALUES ('k', 'v')")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            sql(reader_dsn(self.admin), "INSERT INTO tracekit_meta VALUES ('k', 'v')")

    def test_a_missing_tile_is_an_error_not_a_write(self):
        s = self.open()
        s.append_batch(Chain().batch(600))
        s.checkpoint_put(600, "note 600")
        s.close()
        sql(self.admin, "DELETE FROM tracekit_tiles WHERE level = 0 AND idx = 1")
        with self.assertRaisesRegex(ValueError, "tile 1/0.2 missing or damaged"):
            postgres.PostgresReader(reader_dsn(self.admin))
        self.assertEqual(sql(self.admin, "SELECT count(*) FROM tracekit_tiles"), [(1,)])


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestReadersOfAPostgresSigner(unittest.TestCase):
    def test_export_view_and_reveal_as_a_select_only_role_while_the_signer_runs(self):
        d = tmpdir(self)
        admin, signer = new_log(self)
        for name, dsn in (("signer.dsn", signer), ("reader.dsn", reader_dsn(admin))):
            with open(os.path.join(d, name), "w") as f:
                f.write(dsn)
        cfg = {"data_dir": os.path.join(d, "data"), "socket": os.path.join(d, "s.sock"), "grace_s": 0,
               "storage": {"postgres": {"dsn_file": os.path.join(d, "signer.dsn")}}}
        service = svc.open_service(cfg)
        self.addCleanup(service.close)
        for srv in svc.serve(cfg, service):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        client = Client(cfg["socket"])
        self.addCleanup(client.close)
        run = client.run(agent="a")
        self.assertEqual(run.decide("c1", "Bash", {"command": "ls"})["decision"], "allow")
        run.complete("c1")
        viewer = os.path.join(d, "viewer.yaml")   # its own data dir: never the signer's
        with open(viewer, "w") as f:
            json.dump({"data_dir": "viewer", "socket": "s.sock", "storage": {"postgres": {"dsn_file": "reader.dsn"}}}, f)
        out = os.path.join(d, "run.tkb")
        code, stdout, err = run_cli("export", "--v2", "--run", run.run_id, "--config", viewer, "-o", out)   # nudges
        self.assertEqual((code, err), (0, ""))
        trust = os.path.join(d, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [service.vkey], "witnesses": [], "algs": [RecordSigner.alg], "witnesses_required": 0}, f)
        self.assertEqual(v2.verify(out, trust)[1], 0)
        with mock.patch.object(view.StoreFeed, "_watch", lambda feed: None):
            feed = view.StoreFeed(svc.load_config(viewer))   # pins the vkey the signer stored
        feed.refresh()
        [rep] = [r for r in feed.records if r.get("title", "").startswith(f"RUN {run.run_id}")]
        self.assertEqual(rep["title"], f"RUN {run.run_id} · Integrity VERIFIED TO HEAD 2 (open) · Assurance dev")
        self.assertIn(view.STORED_NOTE, rep["text"])
        r = svc.reader(svc.load_config(viewer))
        self.addCleanup(r.close)
        self.assertEqual(r.meta("log_vkey"), service.vkey)
        [decision] = [x["event"] for x in r.iter_run("default", run.run_id) if x["event"]["type"] == "policy.decision"]
        auditor = os.path.join(d, "auditor.yaml")   # the signer's data dir, for the salt key; the store as the reader
        with open(auditor, "w") as f:
            json.dump({"data_dir": "data", "storage": {"postgres": {"dsn_file": "reader.dsn"}}}, f)
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(svc.main(["reveal", "--record", str(decision["seq"]), "--config", auditor]), 0)
        salt = bytes.fromhex(json.loads(printed.getvalue())["salt"])
        digest = event_hash({"tool": "Bash", "args": {"command": "ls"}})
        self.assertEqual(decision["data"]["args_commitment"],
                         "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest())


class OnPostgres:
    """Runs a signer suite with each data dir's store on Postgres: the signer's own, and those the suite reads
    (`records`, `FileStorage`, `svc.fsck`)."""
    suite = None

    def setUp(self):
        sections, files = {}, tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, files, True)

        def section(data_dir):
            if data_dir not in sections:
                path = os.path.join(files, f"{len(sections)}.dsn")
                with open(path, "w") as f:
                    f.write(new_log(self)[1])
                sections[data_dir] = {"postgres": {"dsn_file": path}}
            return sections[data_dir]

        def dsn(data_dir):
            return postgres.read_dsn(section(data_dir)["postgres"])
        init, fsck = svc.SignerService.__init__, svc.fsck

        def pg_init(s, data_dir, *a, **kw):
            init(s, data_dir, *a, **{"storage_config": section(data_dir), **kw})
        for target, name, value in (
                (svc.SignerService, "__init__", pg_init),
                (svc, "fsck", lambda d, upto=None, storage=None: fsck(d, upto, storage or section(d))),
                (self.suite, "records", lambda d: [r for (r,) in sql(dsn(d), "SELECT record FROM tracekit_records "
                                                                     "ORDER BY seq")]),
                (self.suite, "FileStorage", lambda root, *a: PostgresStorage(dsn(os.path.dirname(root))))):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        super().setUp()


class TestLifecycleOnPostgres(OnPostgres, test_signer_lifecycle.TestLifecycle):
    suite = test_signer_lifecycle

    @unittest.skip("removes registry.jsonl: a file store's crash")
    def test_registry_log_proves_registration_and_final(self):
        pass


class TestBundleOnPostgres(OnPostgres, test_signer_lifecycle.TestBundle):
    suite = test_signer_lifecycle


class TestWitnessQueueOnPostgres(OnPostgres, test_witness_publish.Publisher):
    suite = test_witness_publish


class TestSignerOnPostgres(OnPostgres, unittest.TestCase):
    suite = test_signer_lifecycle

    def test_snapshot_reopen_and_fsck(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        s = svc.SignerService(d, grace_s=0)
        runs = [s.call(ME, "register_run", {"request_id": f"r{i}", "agent": {"name": "a"}}) for i in range(5)]
        s.close()   # a clean close snapshots
        size = s.log.storage.tree.size
        s = svc.SignerService(d, grace_s=0)
        self.addCleanup(s.close)
        self.assertEqual(s.log.storage.snapshot["size"], size)
        s.call(ME, "close_run", {"request_id": "c", "run_id": runs[0]["run_id"], "run_token": runs[0]["run_token"]})
        self.assertEqual(s.check_store(), [])
        self.assertEqual(svc.fsck(d), [])

    def test_migrate_and_fsck_commands(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        admin = new_log(self, migrate=False)[0]
        with open(os.path.join(d, "pg.dsn"), "w") as f:
            f.write(admin)
        cfg = os.path.join(d, "signer.yaml")
        with open(cfg, "w") as f:
            f.write("data_dir: data\nstorage: {postgres: {dsn_file: pg.dsn}}\n")
        self.assertEqual(svc.main(["migrate", "--config", cfg]), 0)
        svc.open_service(svc.load_config(cfg)).close()
        self.assertEqual(svc.main(["fsck", "--config", cfg]), 0)
        with open(os.path.join(d, "pg.dsn"), "w") as f:
            f.write(new_log(self, migrate=False)[0])
        self.assertEqual(svc.main(["fsck", "--config", cfg]), 2)   # not migrated: a message, not a traceback
        with open(cfg, "w") as f:
            f.write(f"data_dir: data\nstorage: {{postgres: {{dsn: {json.dumps(admin)}}}}}\n")
        with self.assertRaisesRegex(ValueError, "never inline"):
            svc.load_config(cfg)


class TestBridgeOnPostgres(unittest.TestCase):
    setUp = test_format_bridge.Bridge.setUp

    def section(self):
        path = os.path.join(self.home, "pg.dsn")
        with open(path, "w") as f:
            f.write(new_log(self)[1])
        return {"postgres": {"dsn_file": path}}

    def test_bridge_continues_into_the_configured_store(self):
        section = self.section()
        b = format_bridge.bridge(self.home, self.data, section)
        (first,), = sql(postgres.read_dsn(section["postgres"]), "SELECT record FROM tracekit_records WHERE seq = 0")
        self.assertEqual(first["event"]["data"]["bridge"], b)
        self.assertFalse(os.path.exists(os.path.join(self.data, "store")))
        self.assertFalse(os.path.exists(self.key))

    def test_a_postgres_store_with_records_is_refused(self):
        section = self.section()
        svc.SignerService(self.data, storage_config=section).close()
        with self.assertRaisesRegex(format_bridge.BridgeError, "already has records"):
            format_bridge.bridge(self.home, self.data, section)
        self.assertTrue(os.path.exists(self.key))


if __name__ == "__main__":
    unittest.main()
