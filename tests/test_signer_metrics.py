"""Signer metrics (tracekit/signer/metrics.py): counts after a scripted run scraped over HTTP, histogram consistency,
bounded label sets, docs/observability.md against a scrape, and the loopback-only listen."""
import os
import re
import shutil
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request

from factories import wait_for
from storage_contract import Chain
from test_rpc_contract import Harness
from test_signer_service import PAY_ASKS, tmpdir
from tracekit.identity.base import CallerIdentity
from tracekit.signer import metrics
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage

DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "observability.md")
SAMPLE = re.compile(r"^(\w+)(\{.*\})? (\S+)$")


def parse(text):
    """{"name{labels}": value} and {name: type} from an exposition."""
    samples, types = {}, {}
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, name, typ = line.split(" ")
            types[name] = typ
        elif not line.startswith("#"):
            name, labels, value = SAMPLE.match(line).groups()
            samples[name + (labels or "")] = float(value)
    return samples, types


class TestScrape(Harness, unittest.TestCase):
    def make_signer(self):
        self.dir = tmpdir(self)
        s = svc.SignerService(self.dir, policy=PAY_ASKS)
        self.addCleanup(s.close)
        return s

    def scrape(self, path="/metrics"):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            self.assertEqual(r.headers["Content-Type"], metrics.CONTENT_TYPE)
            return parse(r.read().decode())

    def serve(self):
        servers = svc.serve({"tcp_endpoint": os.path.join(self.dir, "endpoint.json"), "metrics": {"listen": "127.0.0.1:0"}},
                            self.signer)
        for s in servers:
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        self.port = servers[0].server_address[1]

    def test_scripted_run(self):
        self.serve()
        self.register()
        self.complete(*self.decide())
        self.seq += 2   # skips two client_seq values: a client_counter_gap
        self.decide(tool="pay", args={"amount": 5}, tcid="tc-2")
        self.call("approval_request", self.run_req(tool_call_id="tc-2"))
        got, _ = self.scrape()
        self.assertEqual(got["tracekit_signer_open_runs"], 1)
        self.assertEqual(got["tracekit_signer_pending_approvals"], 1)
        self.call("close_run", self.run_req())
        self.refused("run_closed", "close_run", self.run_req())
        wait_for(lambda: self.scrape()[0]["tracekit_signer_fsync_seconds_count"] > 0)
        got, _ = self.scrape()
        for name, n in {'tracekit_signer_records_total{type="run.registered"}': 1,
                        'tracekit_signer_records_total{type="policy.decision"}': 2,
                        'tracekit_signer_records_total{type="tool.result"}': 1,
                        'tracekit_signer_records_total{type="approval.request"}': 1,
                        'tracekit_signer_records_total{type="run.closing"}': 1,
                        'tracekit_signer_gaps_total{kind="client_counter_gap"}': 1,
                        'tracekit_signer_policy_decisions_total{verdict="allow"}': 1,
                        'tracekit_signer_policy_decisions_total{verdict="ask"}': 1,
                        'tracekit_signer_policy_nondeterministic_total': 0,
                        'tracekit_signer_refusals_total{code="run_closed"}': 1,
                        'tracekit_signer_ack_seconds_count': 6,
                        'tracekit_signer_open_runs': 0}.items():
            self.assertEqual(got.get(name), n, name)
        self.assertGreaterEqual(got["tracekit_signer_queue_depth"], 0)
        self.assertGreaterEqual(got["tracekit_signer_batch_size_count"], 6)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.scrape("/")
        self.assertEqual(cm.exception.code, 404)

    def test_checkpoint_notes_are_counted_and_aged(self):
        self.serve()
        samples, _ = self.scrape()
        self.assertEqual(samples["tracekit_signer_checkpoints_total"], 0)
        time.sleep(0.05)
        self.signer.checkpoint()   # the signer.epoch record is in the tree: one note
        after, _ = self.scrape()
        self.assertEqual(after["tracekit_signer_checkpoints_total"], 1)
        self.assertLess(after["tracekit_signer_checkpoint_age_seconds"], samples["tracekit_signer_checkpoint_age_seconds"] + 0.05)

    def test_histograms_are_consistent(self):
        self.register()
        for i in range(5):
            self.decide(tcid=f"tc-{i}")
        got, types = parse(self.signer.metrics.render())
        for name in (n for n, t in types.items() if t == "histogram"):
            buckets = [(k, v) for k, v in got.items() if k.startswith(name + "_bucket{")]
            self.assertTrue(buckets, name)
            counts = [v for _, v in buckets]
            self.assertEqual(counts, sorted(counts), name)
            self.assertEqual(buckets[-1][0], name + '_bucket{le="+Inf"}')
            self.assertEqual(counts[-1], got[name + "_count"], name)
            self.assertGreaterEqual(got[name + "_sum"], 0, name)
        self.assertEqual(got["tracekit_signer_ack_seconds_count"], 6)

    def test_histogram_buckets(self):
        h = metrics.Histogram("h", "test", (0.001, 0.01))
        for v in (0.0005, 0.001, 0.005, 3):
            h.observe(v)
        got, _ = parse("\n".join(f"{n}{lab} {v}" for n, lab, v in h.samples()))
        self.assertEqual(got, {'h_bucket{le="0.001"}': 2, 'h_bucket{le="0.01"}': 3, 'h_bucket{le="+Inf"}': 4,
                               "h_sum": 3.0065, "h_count": 4})

    def test_many_runs_and_identities_add_no_series(self):
        def run(i):
            who = CallerIdentity("uid", str(100000 + i), True)
            out = self.signer.call(who, "register_run", {"request_id": f"r-{i}", "agent": {"name": "a"}})
            self.signer.call(who, "decide", {"request_id": f"d-{i}", "run_id": out["run_id"],
                                             "run_token": out["run_token"], "stream": "s1", "client_seq": 0,
                                             "tool_call_id": "tc", "tool": "read_file", "args_source": "parsed",
                                             "args": {"path": "a"}})
            with self.assertRaises(svc.RPCError):
                self.signer.call(who, "close_run", {"request_id": f"c-{i}", "run_id": "nope", "run_token": "x"})
        run(0)
        before = set(parse(self.signer.metrics.render())[0])
        for i in range(1, 40):
            run(i)
        self.assertEqual(set(parse(self.signer.metrics.render())[0]), before)
        c = metrics.Counter("c", "test", "code")
        for i in range(500):
            c.inc(f"v{i}")
        self.assertLessEqual(len(list(c.samples())), metrics.MAX_VALUES + 1)

    def test_doc_lists_every_metric(self):
        with open(DOC, encoding="utf-8") as f:
            doc = dict(re.findall(r"^\| `(tracekit_\w+)` \| (\w+) \|", f.read(), re.M))
        self.assertEqual(doc, parse(self.signer.metrics.render())[1])


class TestListen(unittest.TestCase):
    def test_non_loopback_needs_allow_remote(self):
        reg = metrics.SignerMetrics()
        for listen in ("0.0.0.0:0", ":9464", "example.com:9464", "10.1.2.3:9464"):
            with self.assertRaises(ValueError, msg=listen):
                metrics.server({"listen": listen}, reg)
        with self.assertRaises(ValueError):
            metrics.server({"listen": "0.0.0.0:0", "allow_remote": "yes"}, reg)
        for cfg in ({"listen": "0.0.0.0:0", "allow_remote": True}, {"listen": "localhost:0"}, {"listen": "127.0.0.1:0"}):
            metrics.server(cfg, reg).server_close()

    def test_config_key(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "signer.yaml")
        with open(path, "w") as f:
            f.write("data_dir: data\nmetrics: {listen: 127.0.0.1:9464}\n")
        self.assertEqual(svc.load_config(path)["metrics"], {"listen": "127.0.0.1:9464"})
        with self.assertRaises(ValueError):
            svc.serve({"socket": os.path.join(d, "s.sock"), "metrics": {"listen": "0.0.0.0:0"}},
                      types.SimpleNamespace(metrics=metrics.SignerMetrics(), logs_list=str, tlog=bytes))


class TestFsyncLag(unittest.TestCase):
    def test_unsynced_records_age_until_synced(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        synced = []
        s = FileStorage(os.path.join(d, "store"), on_sync=synced.append)
        self.addCleanup(s.close)
        self.assertEqual(s.unsynced_s(), 0.0)
        s._stop.set()
        s._syncer.join()
        s.append_batch(Chain().batch(3, ("a",)))
        self.assertTrue(wait_for(lambda: s.unsynced_s() > 0.0, 1, 0.001))   # once the monotonic clock ticks (Windows: ~16 ms)
        s._stop.clear()
        s._syncer = threading.Thread(target=s._sync_loop, daemon=True)
        s._syncer.start()
        wait_for(lambda: s.unsynced_s() == 0.0)
        self.assertEqual(len(synced), 1)
