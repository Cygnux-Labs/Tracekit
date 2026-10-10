"""`tracekit monitor` (tracekit/monitor.py): the rules over a crafted log served as tlog-tiles, a real signer's log
through its metrics port, the Rekor scan against the in-test Rekor, and the verifier's witnessed+monitored."""
import base64
import datetime
import hashlib
import json
import os
import re
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from factories import wait_for
from test_rekor_anchor import FakeSigstore
from test_signer_service import ME, tmpdir
from tracekit import crypto, merkle, monitor
from tracekit.anchor.rekor2 import RekorAnchor
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import canonical
from tracekit.format.records import make_record
from tracekit.signer import metrics
from tracekit.signer import service as svc
from tracekit.storage.base import ZERO_HASH
from tracekit.verify import v2

ORIGIN = "tracekit.example.org/log/monitor"
SECRET = hashlib.sha256(b"monitor test log").digest()
VKEY = checkpoint.vkey(ORIGIN, checkpoint.ED25519, crypto.public_from_secret(SECRET))
MONITOR = hashlib.sha256(b"monitor test key").digest()
MONITOR_VKEY = checkpoint.vkey(monitor.NAME, checkpoint.ED25519, crypto.public_from_secret(MONITOR))
KID = "ed25519:" + "ab" * 16


def chain(specs):
    """Records of (run, type[, data]) in order; a run.final without data names its run's head."""
    out, runs = [], {}
    for seq, (run, typ, *data) in enumerate(specs):
        run_seq, head = runs.get(run, (-1, ZERO_HASH))
        e = {"log_id": "00" * 16, "seq": seq, "prev_hash": out[-1]["hash"] if out else ZERO_HASH, "tenant": "t",
             "run_id": run, "run_seq": run_seq + 1, "run_prev_hash": head, "type": typ,
             "data": data[0] if data else {"head_run_seq": run_seq, "head_hash": head} if typ == "run.final" else {}}
        out.append(make_record(e, SECRET))
        runs[run] = run_seq + 1, out[-1]["hash"]
    return out


START = [("signer", "signer.epoch", {"keys": [{"kid": KID}]}), ("r1", "run.registered"), ("r1", "tool.call")]


class FakeLog:
    """A record log served as the signer serves it: /checkpoint, /logs/v0 and /tile/entries/<N>[.p/<W>]."""

    def __init__(self, records):
        self.records, self.bundles = records, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                m = re.fullmatch(r"/tile/entries/((?:x\d{3}/)*\d{3})(?:\.p/(\d+))?", self.path)
                if self.path == "/checkpoint":
                    out = fake.note().encode()
                elif self.path == "/logs/v0":
                    out = f"logs/v0\n\nvkey {VKEY}\n\n".encode()
                elif m:
                    n, w = int(m[1].replace("x", "").replace("/", "")), int(m[2] or 256)
                    fake.bundles.append(n)
                    out = b"".join(json.dumps(r).encode() + b"\n" for r in fake.records[n * 256:n * 256 + w])
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def note(self):
        text = checkpoint.body(ORIGIN, len(self.records), merkle.root(
            [merkle.leaf_hash(bytes.fromhex(r["hash"][7:])) for r in self.records]))
        return text + "\n" + checkpoint.sign(text, ORIGIN, SECRET)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Rules(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)

    def poll(self, specs, allowed=()):
        self.log = FakeLog(chain(specs))
        self.addCleanup(self.log.stop)
        return self.rules(monitor.poll(self.dir, self.log.url, VKEY, MONITOR, allowed)["report"])

    def rules(self, report):
        return [(c["rule"], c["detail"]) for c in self.conflicts(report)]

    def conflicts(self, report):   # a crafted log has no registry logs
        return [c for c in report["conflicts"] if c["rule"] != "registry leaves"]

    def test_clean_crafted_log(self):
        self.assertEqual(self.poll(START + [("r1", "run.final")]), [])

    def test_duplicate_run_final(self):
        self.assertIn(("one run.final per run, nothing after it", "seq 4: a second run.final of run 'r1' of tenant 't'"),
                      self.poll(START + [("r1", "run.final"), ("r1", "run.final")]))

    def test_record_after_final(self):
        self.assertIn(("one run.final per run, nothing after it",
                       "seq 4: a record after the run.final of run 'r1' of tenant 't'"),
                      self.poll(START + [("r1", "run.final"), ("r1", "tool.call")]))

    def test_second_registration(self):
        self.assertIn(("one run.registered per run", "seq 3: a second run.registered of run 'r1' of tenant 't'"),
                      self.poll(START + [("r1", "run.registered")]))

    def test_unexpected_key_retire(self):
        specs = START + [("signer", "key.retire", {"kid": KID, "last_seq": 3})]
        self.assertEqual(self.poll(specs), [("key announcements", f"seq 3: key.retire of key {KID}, not announced")])
        self.dir = tmpdir(self)   # a monitor that was told of the retirement
        self.assertEqual(self.poll(specs, [KID]), [])

    def test_fork_and_rollback_keep_both_notes(self):
        self.poll(START)
        first = self.log.note()
        self.log.records = chain(START[:2] + [("r1", "tool.result")])   # another tree of the same size
        report = monitor.poll(self.dir, self.log.url, VKEY, MONITOR)["report"]
        self.assertEqual(self.conflicts(report), [{"rule": "checkpoint consistency", "detail": f"{ORIGIN}: two checkpoints "
                                                "of size 3 with different roots (fork)", "notes": [first, self.log.note()]}])
        self.log.records = self.log.records[:2]
        report = monitor.poll(self.dir, self.log.url, VKEY, MONITOR)["report"]
        self.assertEqual(self.conflicts(report)[1], {"rule": "checkpoint consistency", "detail": f"{ORIGIN}: a checkpoint of "
                                                  "size 2 after one of size 3 (rollback)", "notes": [first, self.log.note()]})
        self.assertEqual(report["checked_size"], 3)

    def test_restart_resumes(self):
        records = chain(START + [("r1", "tool.call")] * 300)
        self.log = FakeLog(records[:290])
        self.addCleanup(self.log.stop)
        self.assertEqual(self.conflicts(monitor.poll(self.dir, self.log.url, VKEY, MONITOR)["report"]), [])
        self.log.records, self.log.bundles = records, []
        report = monitor.poll(self.dir, self.log.url, VKEY, MONITOR)["report"]   # a new poll reads the state dir
        self.assertEqual((report["checked_size"], self.conflicts(report), self.log.bundles), (len(records), [], [1]))

    def test_entries_must_be_the_checkpoint_tree(self):
        self.poll(START)
        self.log.records = chain(START + [("r1", "tool.call")])
        good = self.log.note()
        self.log.records = chain(START + [("r1", "tool.result")])
        with mock.patch.object(FakeLog, "note", lambda _: good), self.assertRaises(monitor.MonitorError):
            monitor.poll(self.dir, self.log.url, VKEY, MONITOR)

    def test_report_signature(self):
        self.poll(START)
        with open(os.path.join(self.dir, "report.json"), "rb") as f:
            data = f.read()
        self.assertEqual(monitor.open_report(data, MONITOR_VKEY)["checked_size"], 3)
        other = checkpoint.vkey(monitor.NAME, checkpoint.ED25519, crypto.generate()[1])
        with self.assertRaises(ValueError):
            monitor.open_report(data, other)


class Signer(unittest.TestCase):
    """A real signer's logs, through its metrics port; anchored in the in-test Rekor."""

    def setUp(self):
        self.dir = tmpdir(self)
        self.state = os.path.join(self.dir, "monitor")
        os.makedirs(self.state)
        self.fake = FakeSigstore()
        self.addCleanup(self.fake.stop)
        for k, v in {"BACKOFF_S": (0.05, 0.2), "TICK_S": 0.05}.items():
            p = mock.patch.object(svc, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.sc, self.tr = self.fake.files(self.dir)
        self.s = svc.SignerService(os.path.join(self.dir, "signer"), grace_s=0, origin=ORIGIN,
                                   rekor={"signing_config": self.sc, "trusted_root": self.tr, "every_s": 3600})
        self.addCleanup(self.s.close)
        server = metrics.server({"listen": "127.0.0.1:0"}, self.s.metrics, self.s.logs_list, self.s.tlog)
        threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        self.rekor = self.fake.trusted_root(), self.s.anchors[0].spki

    def finished_run(self):
        call = lambda m, r: self.s.call(ME, m, {"request_id": os.urandom(8).hex(), **r})   # noqa: E731
        out = call("register_run", {"agent": {"name": "a"}})
        call("close_run", {"run_id": out["run_id"], "run_token": out["run_token"]})
        self.s.sweep()
        self.s.checkpoint()
        return out["run_id"]

    def poll(self, rekor=None):
        return monitor.poll(self.state, self.url, self.s.vkey, MONITOR, rekor=rekor)["report"]

    def test_clean_log_and_served_tiles(self):
        self.finished_run()
        self.assertEqual(self.poll()["conflicts"], [])
        self.finished_run()
        report = self.poll()   # the second poll also checks the first poll's records have their registry leaves
        self.assertEqual((report["conflicts"], report["checked_size"]), ([], self.s.log.storage.tree.size))
        with open(os.path.join(self.state, "state.json")) as f:
            logs = sorted(json.load(f)["logs"])
        self.assertEqual((len(logs), logs[0]), (2, ORIGIN))   # the record log and the tenant's registry log
        size = self.s.log.storage.tree.size
        with urllib.request.urlopen(f"{self.url}/tile/0/000.p/{size}", timeout=5) as r:
            tile = r.read()
        self.assertEqual(tile, b"".join(merkle.leaf_hash(bytes.fromhex(r["hash"][7:]))
                                        for r in self.s.log.storage.iter_range(0, size)))

    def test_rekor_scan(self):
        self.finished_run()
        wait_for(lambda: self.s.log.storage.anchors(), 10)
        self.assertEqual(self.poll(self.rekor)["conflicts"], [])
        size, root = 99, hashlib.sha256(b"not the log").digest()   # a checkpoint the log never had, under its keys
        text = checkpoint.body(ORIGIN, size, root)
        with open(os.path.join(self.dir, "signer", "keys", "rekor.key"), "rb") as f:
            publisher = RekorAnchor(self.sc, self.tr, f.read())
        publisher.add_checkpoint(text + "\n" + checkpoint.sign(text, ORIGIN, self.s._log_key), self.s.vkey, 0, None)
        self.assertEqual(self.poll(self.rekor)["conflicts"], [])   # an anchor the signer may be storing right now
        self.assertEqual([c["rule"] for c in self.poll(self.rekor)["conflicts"]], ["rekor anchors"])

    def test_verifier_witnessed_and_monitored(self):
        run = self.finished_run()
        anchor = wait_for(lambda: self.s.log.storage.anchors(), 10)[0]
        bundle = os.path.join(self.dir, "run.tkb")
        export(self.s.log.storage, "default", run, anchor["note"], bundle)
        self.poll()
        report = os.path.join(self.state, "report.json")
        pinned = {"logs": [self.s.vkey], "algs": ["ed25519"], "rekor": {
            "trusted_root": self.fake.trusted_root(), "publishing_key": base64.b64encode(self.rekor[1]).decode(),
            "class": "public"}}

        def assurance(monitors, path=report):
            trust = os.path.join(self.dir, "trust.json")
            with open(trust, "w") as f:
                json.dump({**pinned, "monitors": monitors}, f)
            rep, code = v2.verify(bundle, trust, monitor_reports=[path])
            return rep.assurance.split(";")[0], code
        pin = [{"vkey": MONITOR_VKEY, "class": "customer", "max_age_s": 3600}]
        self.assertEqual(assurance(pin), ("witnessed+monitored", 0))
        self.assertEqual(assurance([]), ("witnessed", 0))   # an unpinned monitor
        with open(report) as f:
            doc = json.load(f)
        stale = os.path.join(self.dir, "stale.json")
        self.resign(stale, dict(doc["report"], time=(datetime.datetime.now(datetime.timezone.utc)
                                                     - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        self.assertEqual(assurance(pin, stale), ("witnessed", 0))
        conflicted = os.path.join(self.dir, "conflicts.json")
        self.resign(conflicted, dict(doc["report"], conflicts=[{"rule": "run chain", "detail": "seq 9: ..."}]))
        self.assertEqual(assurance(pin, conflicted)[1], 1)

    def resign(self, path, report):
        with open(path, "w") as f:
            json.dump({"report": report, "sig": base64.b64encode(
                crypto.sign(MONITOR, monitor.CONTEXT + canonical(report))).decode()}, f)

