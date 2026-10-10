"""The Postgres storage backend: the storage contract run as a signer role holding only postgres.GRANTS, what only
Postgres has (the advisory lock, a killed transaction, migrate, edited rows), and the signer's suites that take a storage
(lifecycle, snapshots, witness queue) on Postgres. Needs psycopg and TRACEKIT_TEST_PG_DSN (a superuser DSN), or initdb
and pg_ctl on PATH (a throwaway cluster in a temp dir); skipped otherwise."""
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import test_signer_lifecycle
import test_witness_publish
from storage_contract import Chain, StorageContract
from test_signer_service import ME
from tracekit.signer import service as svc
from tracekit.storage.base import ACK_ON_FSYNC, ACK_ON_WRITE, StorageUnavailable

try:
    import psycopg
    from psycopg.conninfo import make_conninfo
    from tracekit.storage import postgres
    from tracekit.storage.postgres import PostgresStorage
except ImportError:
    psycopg = None

ADMIN, CLUSTER = None, None
SIGNER = "tracekit_signer_test"


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
        c.execute(f"DO $$ BEGIN CREATE ROLE {SIGNER} NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$")


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
        with open(cfg, "w") as f:
            f.write(f"data_dir: data\nstorage: {{postgres: {{dsn: {json.dumps(admin)}}}}}\n")
        with self.assertRaisesRegex(ValueError, "never inline"):
            svc.load_config(cfg)


if __name__ == "__main__":
    unittest.main()
