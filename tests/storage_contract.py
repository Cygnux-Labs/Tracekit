"""Backend-independent storage contract (tracekit.storage.base). A backend's test case mixes in StorageContract with
unittest.TestCase and supplies open() (a store over the same location every call), tear() (cut the last record's
line short, as a crash mid-write does) and damage(seq) (change a stored record's event in place)."""
from tracekit.format import checkpoint
from tracekit.format.records import make_record
from tracekit.merkle import leaf_hash, root
from tracekit.merkle.tiles import MemoryTileStore, Tree
from tracekit.storage.base import RECORDS, ZERO_HASH, registry_tree

SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


class Chain:
    """Builds signed records that continue a log: seq/prev_hash and each run's run_seq/run_prev_hash."""

    def __init__(self):
        self.seq, self.prev, self.runs = 0, ZERO_HASH, {}

    def next(self, run_id="run-1", tenant="acme"):
        run_seq, run_prev = self.runs.get((tenant, run_id), (0, ZERO_HASH))
        e = {"schema_version": "tracekit.event.v2", "id": f"{self.seq:032x}", "seq": self.seq, "prev_hash": self.prev,
             "ts": "2026-10-09T12:00:00.000000Z", "run_id": run_id, "agent_id": "main", "parent_id": None,
             "source": "signer", "type": "tool.call", "data": {"tool_use_id": f"t{self.seq}", "name": "Bash", "input": {}},
             "tenant": tenant, "log_id": "0" * 32, "run_seq": run_seq, "run_prev_hash": run_prev}
        r = make_record(e, SECRET)
        self.seq, self.prev, self.runs[(tenant, run_id)] = self.seq + 1, r["hash"], (run_seq + 1, r["hash"])
        return r

    def batch(self, n, runs=("run-1",)):
        """n records, record seq going to run runs[seq % len(runs)], so a log's records follow from its length."""
        return [self.next(runs[self.seq % len(runs)]) for _ in range(n)]


def leaves(records):
    return [leaf_hash(bytes.fromhex(r["hash"][len("sha256:"):])) for r in records]


class StorageContract:
    def store(self):
        s = self.open()
        self.addCleanup(s.close)
        return s

    def reopen(self, s):
        s.close()
        return self.store()

    def test_empty(self):
        s = self.store()
        self.assertEqual(s.tail_state(), {"seq": None, "prev_hash": ZERO_HASH, "tree_size": 0, "tree_root": root([]),
                                          "runs": {}, "registry": {}})
        self.assertEqual(list(s.iter_range(0, 10)), [])
        self.assertIsNone(s.get_run("acme", "run-1"))
        self.assertEqual(s.fsck(), [])

    def test_append_and_iterate_in_order(self):
        s, c = self.store(), Chain()
        records = c.batch(5) + c.batch(1) + c.batch(7)
        for b in (records[:5], records[5:6], records[6:]):
            s.append_batch(b)
        self.assertEqual(list(s.iter_range(0, 100)), records)
        self.assertEqual(list(s.iter_range(3, 9)), records[3:9])
        self.assertEqual(list(s.iter_range(9, 3)), [])

    def test_seq_must_continue_the_log(self):
        s, c = self.store(), Chain()
        s.append_batch(c.batch(2))
        c.seq = 5
        with self.assertRaises(ValueError):
            s.append_batch(c.batch(1))
        self.assertEqual(s.tail_state()["tree_size"], 2)

    def test_runs(self):
        s, c = self.store(), Chain()
        records = c.batch(9, runs=("a", "b", "c"))
        s.append_batch(records)
        s.append_batch([c.next("other-run", tenant="beta")])
        self.assertEqual(list(s.iter_run("acme", "b")), records[1::3])
        self.assertEqual(list(s.iter_run("beta", "b")), [])
        self.assertEqual(s.get_run("acme", "b"), {"run_seq": 2, "head": records[7]["hash"], "count": 3})
        self.assertEqual(s.get_run("beta", "other-run")["count"], 1)

    def test_tail_state_after_reopen(self):
        s, c = self.store(), Chain()
        records = c.batch(10, runs=("a", "b"))
        s.append_batch(records)
        before = s.tail_state()
        s = self.reopen(s)
        self.assertEqual(s.tail_state(), before)
        self.assertEqual(before["seq"], 9)
        self.assertEqual(before["prev_hash"], records[-1]["hash"])
        self.assertEqual(before["runs"][("acme", "a")], {"run_seq": 4, "head": records[8]["hash"], "count": 5})
        s.append_batch([c.next("a")])
        self.assertEqual(list(s.iter_run("acme", "a"))[-1]["event"]["run_seq"], 5)
        self.assertEqual(s.fsck(), [])

    def test_registry(self):
        s = self.store()
        a = [bytes([1]) + bytes([i]) * 88 for i in range(3)]
        s.registry_append("acme", a[0])
        s.registry_append("beta", b"\x02" * 89)
        s.registry_append("acme", a[1])
        s.registry_append("acme", a[2])
        s = self.reopen(s)
        self.assertEqual(list(s.registry_iter("acme")), a)
        self.assertEqual(list(s.registry_iter("nobody")), [])
        reg = s.tail_state()["registry"]
        self.assertEqual(reg["acme"], (3, root([leaf_hash(x) for x in a])))
        self.assertEqual(reg["beta"], (1, leaf_hash(b"\x02" * 89)))

    def test_tiles_round_trip(self):
        s = self.store()
        self.assertIsNone(s.tiles_get("t", 0, 0, 3))
        s.tiles_put("t", 0, 0, 3, b"x" * 96)
        s = self.reopen(s)
        self.assertEqual(s.tiles_get("t", 0, 0, 3), b"x" * 96)
        self.assertIsNone(s.tiles_get(registry_tree("acme"), 0, 0, 3))

    def test_checkpoint_notes(self):
        def note(n):
            return checkpoint.body("example.org/log", n, bytes(32)) + "\n— example.org/log c2ln\n"
        s = self.store()
        self.assertIsNone(s.checkpoint_latest())
        s.checkpoint_put(3, note(3))
        s.checkpoint_put(3, note(3))
        s.checkpoint_put(7, note(7))
        with self.assertRaises(ValueError):
            s.checkpoint_put(5, note(5))   # never older than the stored one
        self.assertEqual(s.checkpoint_latest(), (7, note(7)))
        self.assertEqual(self.reopen(s).checkpoint_latest(), (7, note(7)))

    def test_merkle_roots_match_merkle_tiles(self):
        s, c = self.store(), Chain()
        records = c.batch(300)
        for i in range(0, 300, 64):
            s.append_batch(records[i:i + 64])
        mem = Tree(MemoryTileStore())
        for h in leaves(records):
            mem.append(h)
        self.assertEqual(s.tail_state()["tree_root"], mem.root())
        self.assertEqual(mem.root(), root(leaves(records)))
        self.assertEqual(s.tiles_get(RECORDS, 0, 0, 256), mem.store.get(0, 0, 256))
        s = self.reopen(s)
        self.assertEqual(s.tail_state()["tree_root"], mem.root())

    def test_torn_tail_is_set_aside_and_reported(self):
        s, c = self.store(), Chain()
        records = c.batch(4)
        s.append_batch(records)
        s.close()
        self.tear()
        s = self.store()
        self.assertEqual(len(s.torn), 1)
        self.assertEqual(list(s.iter_range(0, 10)), records[:3])
        self.assertEqual(s.fsck(), [])
        c = Chain()
        c.batch(3)
        s.append_batch(c.batch(2))
        self.assertEqual(s.tail_state()["tree_size"], 5)
        self.assertEqual(self.reopen(s).torn, [])

    def test_fsck_finds_a_damaged_middle_record(self):
        s, c = self.store(), Chain()
        s.append_batch(c.batch(6))
        s.close()
        self.damage(2)
        s = self.store()
        problems = s.fsck()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("line 3", problems[0])
        self.assertEqual(s.torn, [])
