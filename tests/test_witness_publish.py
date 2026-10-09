"""Checkpoint publishing to C2SP tlog-witnesses: the client (tracekit/tlog_witness.py) and the signer's publisher, against
an in-test witness implementing the protocol, and against omniwitness when its binary is on PATH."""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from factories import wait_for
from test_bundle_v2 import cosign, pub
from test_signer_service import ME, records, tmpdir
from tracekit import merkle
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint, registry
from tracekit.signer import service as svc
from tracekit.storage.base import RECORDS, registry_tree
from tracekit.tlog_witness import MAX_BODY, TlogWitness, WitnessError
from tracekit.verify import v2

NAME = "witness.example.org/fake"
SECRET = hashlib.sha256(b"fake witness").digest()
VKEY = checkpoint.vkey(NAME, checkpoint.COSIGNATURE, pub(SECRET))
ORIGIN = "tracekit.example.org/log/publish"


class FakeWitness:
    """tlog-witness v1.1.0 add-checkpoint: 404 unknown origin, 403 no valid log signature, 409 + size on a stale old
    size, 422 on a bad proof, 413 past MAX_BODY; `status` forces an answer (e.g. 503), `stop()` makes it unreachable."""

    def __init__(self, port=0):
        self.logs, self.sizes, self.bodies, self.status = {}, {}, [], None
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fake.bodies.append(body)
                code, out = fake.answer(body)
                self.send_response(code)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def answer(self, body):
        if self.status:
            return self.status, b"down"
        if len(body) > MAX_BODY:
            return 413, b"too large"
        head, note = body.decode().split("\n\n", 1)
        lines = head.split("\n")
        old, proof = int(lines[0].split(" ")[1]), [base64.b64decode(h) for h in lines[1:]]
        origin = note.split("\n", 1)[0]
        if origin not in self.logs:
            return 404, b"unknown log"
        try:
            _, size, root, _ = checkpoint.open_note(note, [self.logs[origin]])
        except checkpoint.NoteError:
            return 403, b"bad signature"
        have, have_root = self.sizes.get(origin, (0, merkle.root([])))
        if old != have:
            return 409, f"{have}\n".encode()
        if (old == 0 and (proof or size == 0 and root != merkle.root([]))) or (
                0 < old < size and not merkle.verify_consistency(old, size, have_root, root, proof)) or (
                old == size and root != have_root) or old > size:
            return 422, b"inconsistent"
        self.sizes[origin] = (size, root)
        text = note[:note.index("\n\n") + 1]
        return 200, cosign(text, NAME, SECRET, int(time.time())).encode()


def signed_note(origin, leaves, secret):
    text = checkpoint.body(origin, len(leaves), merkle.root(leaves))
    return text + "\n" + checkpoint.sign(text, origin, secret)


class Client(unittest.TestCase):
    def setUp(self):
        self.w = FakeWitness()
        self.addCleanup(self.w.stop)
        self.origin, self.secret = "log.example.org/a", hashlib.sha256(b"log").digest()
        self.log_vkey = checkpoint.vkey(self.origin, checkpoint.ED25519, pub(self.secret))
        self.w.logs[self.origin] = self.log_vkey
        self.client = TlogWitness(self.w.url, VKEY, timeout=2)
        self.leaves = [merkle.leaf_hash(b"%d" % i) for i in range(40)]

    def add(self, n, old, note=None):
        return self.client.add_checkpoint(note or signed_note(self.origin, self.leaves[:n], self.secret), self.log_vkey,
                                          old, lambda m: merkle.consistency_proof(m, self.leaves[:n]))

    def test_cosigns_and_the_cosignature_verifies(self):
        lines = self.add(5, 0)
        note = signed_note(self.origin, self.leaves[:5], self.secret) + lines
        self.assertEqual(len(checkpoint.open_note(note, [self.log_vkey], [VKEY])[3]), 1)
        self.assertTrue(self.add(9, 5))   # with a consistency proof from 5
        self.assertEqual(self.w.sizes[self.origin][0], 9)

    def test_409_resyncs_from_the_witness_size(self):
        self.add(7, 0)
        self.assertTrue(self.add(12, 0))   # the client thought the witness was new
        self.assertEqual(self.w.sizes[self.origin][0], 12)
        self.assertEqual([b.split(b"\n")[0] for b in self.w.bodies[-2:]], [b"old 0", b"old 7"])

    def test_only_the_log_signature_is_sent(self):
        other = hashlib.sha256(b"other").digest()
        text = checkpoint.body(self.origin, 3, merkle.root(self.leaves[:3]))
        note = text + "\n" + checkpoint.sign(text, self.origin, other) + checkpoint.sign(text, self.origin, self.secret)
        self.add(3, 0, note)
        sent = self.w.bodies[-1].decode().split("\n\n", 2)[2]
        self.assertEqual(sent, checkpoint.sign(text, self.origin, self.secret))

    def test_errors_are_classified(self):
        big = signed_note(self.origin, self.leaves[:3], self.secret) + "— x " + "A" * MAX_BODY + "\n"
        self.assertTrue(self.client.add_checkpoint(big, self.log_vkey, 0, list))   # the big line is stripped
        for status, retryable in ((503, True), (429, True), (404, False), (403, False)):
            self.w.status = status
            with self.assertRaises(WitnessError) as cm:
                self.add(4, 3)
            self.assertEqual(cm.exception.retryable, retryable, status)
        self.w.status = None
        with self.assertRaises(WitnessError) as cm:   # a forked tree: the proof does not verify
            self.client.add_checkpoint(signed_note(self.origin, [b"x" * 32] * 6, self.secret), self.log_vkey, 3,
                                       lambda m: merkle.consistency_proof(m, [b"x" * 32] * 6))
        self.assertFalse(cm.exception.retryable)
        self.w.stop()
        with self.assertRaises(WitnessError) as cm:
            self.add(5, 3)
        self.assertTrue(cm.exception.retryable)

    def test_body_over_10_kib_is_not_sent(self):
        with self.assertRaises(WitnessError) as cm:
            self.client.add_checkpoint(signed_note(self.origin, self.leaves[:3], self.secret), self.log_vkey, 1,
                                       lambda m: [b"x" * 32] * 400)
        self.assertFalse(cm.exception.retryable)
        self.assertEqual(self.w.bodies, [b for b in self.w.bodies if len(b) <= MAX_BODY])

    def test_a_bad_cosignature_is_refused(self):
        self.w.answer = lambda body: (200, cosign("x\n", NAME, SECRET, 1).encode())
        with self.assertRaises(WitnessError) as cm:
            self.add(3, 0)
        self.assertFalse(cm.exception.retryable)

    def test_malformed_answers_are_witness_errors(self):
        for answer in ((409, "\u0661\u0662\n"), (200, f"\u2014 {NAME} \u00e9\n")):   # non-ASCII digits; a non-ASCII line
            self.w.answer = lambda body, a=answer: (a[0], a[1].encode())
            with self.assertRaises(WitnessError) as cm:
                self.add(3, 0)
            self.assertFalse(cm.exception.retryable)

    def test_latest_is_the_witness_size(self):
        empty = signed_note(self.origin, [], self.secret)
        self.assertEqual(self.client.latest(empty, self.log_vkey), (0, None))
        self.add(6, 0)
        self.assertEqual(self.client.latest(empty, self.log_vkey), (6, None))


class Publisher(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.w = FakeWitness()
        self.addCleanup(lambda: self.w.stop())
        for k, v in {"BACKOFF_S": (0.05, 0.2), "TICK_S": 0.05}.items():
            p = mock.patch.object(svc, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.s = self.open()

    def open(self):
        if not self.w.logs:   # the witness knows the logs before the signer's startup check asks it for its size
            s = svc.SignerService(self.dir, origin=ORIGIN)
            s.close()
            public = checkpoint.parse_vkey(s.vkey)[3]
            for origin in (ORIGIN, registry.origin(ORIGIN, s.log.tenant_salt("default"))):
                self.w.logs[origin] = checkpoint.vkey(origin, checkpoint.ED25519, public)
        s = svc.SignerService(self.dir, grace_s=0, witnesses=[TlogWitness(self.w.url, VKEY, timeout=2)], origin=ORIGIN)
        self.addCleanup(s.close)
        return s

    def call(self, method, req):
        return self.s.call(ME, method, {"request_id": os.urandom(8).hex(), **req})

    def finished_run(self):
        out = self.call("register_run", {"agent": {"name": "a"}})
        self.call("close_run", {"run_id": out["run_id"], "run_token": out["run_token"]})
        self.s.sweep()
        return out["run_id"]

    def cosigned(self, tree=RECORDS):
        latest = self.s.log.storage.checkpoint_latest(tree)
        return latest and f"— {NAME} " in latest[1] and latest

    def trust(self, witnesses):
        path = os.path.join(self.dir, "trust.json")
        with open(path, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": witnesses, "algs": ["ed25519"], "witnesses_required": 0}, f)
        return path

    def test_cosigned_notes_export_as_witnessed(self):
        run = self.finished_run()
        self.s.checkpoint()
        size, note = wait_for(self.cosigned, 5)
        self.assertEqual(size, self.s.log.storage.tree.size)
        self.assertTrue(wait_for(lambda: self.cosigned(registry_tree("default")), 5))
        reg_note = self.s.log.storage.checkpoint_latest(registry_tree("default"))[1]
        self.assertTrue(reg_note.startswith(checkpoint.body(
            registry.origin(self.s.origin, self.s.log.tenant_salt("default")), 2,
            self.s.log.storage.registry_merkle("default").root())))
        self.s.close()   # the body never changed: the stored note is the signer's note plus the cosignature
        self.s = self.open()
        self.assertEqual(self.cosigned(), (size, note))
        out = os.path.join(self.dir, "run.tkb")
        export(self.s.log.storage, "default", run, note, out)
        rep, code = v2.verify(out, self.trust([{"vkey": VKEY, "class": "customer"}]))
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertTrue(rep.assurance.startswith("witnessed;"), rep.assurance)
        rep, code = v2.verify(out, self.trust([]))   # the witness's line from an unpinned key is ignored
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertTrue(rep.assurance.startswith("dev;"), rep.assurance)

    def test_retry_queue_survives_restart(self):
        self.finished_run()
        self.s.checkpoint()
        cosigned, _ = wait_for(self.cosigned, 5)
        self.w.status = 503
        sent = len(self.w.bodies)
        self.finished_run()
        self.s.checkpoint()
        self.assertTrue(wait_for(lambda: len(self.w.bodies) > sent, 5))
        attempts = lambda: self.s.log.storage.witness_queue().get(NAME, {}).get(RECORDS, {}).get("attempts", 0)  # noqa: E731
        self.assertTrue(wait_for(lambda: attempts() >= 1, 10))   # the failure recorded, not only the request sent
        self.s.close()
        state = self.s.log.storage.witness_queue()[NAME][RECORDS]
        self.assertGreaterEqual(state["attempts"], 1)
        self.assertEqual(state["size"], cosigned)
        self.w.status = None
        sent = len(self.w.bodies)
        self.s = self.open()   # resumes from the persisted size: no 409 round trip from 0
        self.assertTrue(wait_for(lambda: self.cosigned() and self.cosigned()[0] > cosigned, 5))
        heads = [b.decode().split("\n") for b in self.w.bodies[sent:]]   # old, ..., "", origin, size: past the startup check
        self.assertEqual([h[0] for h in heads if h[h.index("") + 1:h.index("") + 3] != [ORIGIN, "0"]
                          and h[h.index("") + 1] == ORIGIN][0], f"old {cosigned}")
        # the cosignature is merged before the queue records the success: wait for it
        self.assertTrue(wait_for(lambda: self.s.log.storage.witness_queue()[NAME][RECORDS]["attempts"] == 0, 10))

    def test_witness_down_gets_one_gap_then_catches_up(self):
        port = self.w.server.server_address[1]
        self.w.stop()
        with mock.patch.object(svc, "WITNESS_GAP_S", 0.3):
            self.finished_run()
            self.s.checkpoint()
            gaps = lambda: [r for r in records(self.dir) if r["event"]["type"] == "capture.gap"]   # noqa: E731
            self.assertTrue(wait_for(lambda: len(gaps()) == 2, 15))   # one per log (slow runners need the time)
            time.sleep(0.5)   # more failed retries, still one gap per log
            self.assertEqual([g["event"]["data"]["kind"] for g in gaps()], ["witness_failed"] * 2)
            self.assertEqual(sorted(g["event"]["data"]["reason"].split(" ")[5] for g in gaps()), sorted(self.w.logs))
            logs = self.w.logs
            self.w = FakeWitness(port)
            self.w.logs = logs
            self.s.checkpoint()   # the gap record grew the tree: a new note
            self.assertTrue(wait_for(lambda: self.cosigned() and self.cosigned()[0] == self.s.log.storage.tree.size, 5))
            self.assertEqual(len(gaps()), 2)
        lag = self.s.metrics.render()
        self.assertIn(f'tracekit_signer_witness_lag_records{{witness="{NAME}"}} 0', lag)
        self.assertRegex(lag, rf'tracekit_signer_witness_publish_failures_total{{witness="{NAME}"}} [1-9]')

    def test_an_unexpected_witness_failure_is_a_gap(self):
        with mock.patch.object(svc, "WITNESS_GAP_S", 0), \
                mock.patch.object(TlogWitness, "add_checkpoint", side_effect=KeyError("x")):
            self.finished_run()
            self.s.checkpoint()
            gaps = lambda: [r for r in records(self.dir) if r["event"]["type"] == "capture.gap"]   # noqa: E731
            self.assertTrue(wait_for(gaps, 5))
        self.assertEqual(gaps()[0]["event"]["data"]["kind"], "witness_failed")
        self.assertIn("KeyError", gaps()[0]["event"]["data"]["reason"])

    def test_checkpoint_spam_is_coalesced(self):
        with mock.patch.object(svc, "CHECKPOINT_MIN_S", 0.2):
            out = self.call("register_run", {"agent": {"name": "a"}})
            start = time.monotonic()
            for i in range(60):
                self.call("state_write", {"run_id": out["run_id"], "run_token": out["run_token"], "stream": "s",
                                          "client_seq": i, "key": "k", "value_digest": "sha256:" + "0" * 64})
                self.s.call(ME, "checkpoint_nudge", {})
                time.sleep(0.01)
            elapsed = time.monotonic() - start
        time.sleep(0.3)
        notes = self.s.metrics.checkpoints._values[None]
        self.assertGreaterEqual(notes, 1)
        self.assertLessEqual(notes, elapsed / 0.2 + 2)

    def test_logs_list(self):
        self.finished_run()
        transport = ({"socket": os.path.join(self.dir, "s.sock")} if hasattr(socket, "AF_UNIX")
                     else {"tcp_endpoint": os.path.join(self.dir, "endpoint.json")})   # Windows: no Unix sockets
        servers = svc.serve({**transport, "metrics": {"listen": "127.0.0.1:0"}}, self.s)
        for x in servers:
            self.addCleanup(x.server_close)
            self.addCleanup(x.shutdown)
        with urllib.request.urlopen(f"http://127.0.0.1:{servers[0].server_address[1]}/logs/v0", timeout=5) as r:
            text = r.read().decode()
        self.assertEqual(text, "logs/v0\n\n" + "".join(f"vkey {k}\nqpd 86400\ncontact {ORIGIN}\n\n"
                                                       for k in self.w.logs.values()))

    def test_config(self):
        cfg = os.path.join(self.dir, "signer.yaml")
        for witnesses, ok in (([{"url": self.w.url, "vkey": VKEY, "class": "customer"}], True),
                              ([{"url": self.w.url, "vkey": VKEY}], False),
                              ([{"url": self.w.url, "vkey": VKEY, "class": "friend"}], False),
                              ([{"url": self.w.url, "vkey": self.s.vkey, "class": "customer"}], False),
                              ([{"url": self.w.url, "vkey": VKEY, "class": "customer"}] * 2, False)):
            with open(cfg, "w") as f:
                json.dump({"data_dir": "d", "witnesses": witnesses}, f)
            if ok:
                self.assertEqual(svc.load_config(cfg)["witnesses"], witnesses)
            else:
                with self.assertRaises(ValueError):
                    svc.load_config(cfg)
        with open(cfg, "w") as f:
            json.dump({"data_dir": ".", "witnesses": [{"url": self.w.url, "vkey": VKEY, "class": "customer"}]}, f)
        out = os.path.join(self.dir, "trust.json")
        with mock.patch("sys.stdout"):
            self.assertEqual(svc.main(["trust", "--config", cfg, "-o", out]), 0)
        with open(out) as f:
            self.assertEqual(json.load(f)["witnesses"], [{"vkey": VKEY, "class": "customer"}])


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("omniwitness"), "omniwitness is not on PATH (go install "
                     "github.com/transparency-dev/witness/cmd/omniwitness@<commit>)")
class Omniwitness(unittest.TestCase):
    def test_registers_from_the_logs_list_and_cosigns(self):
        d = tmpdir(self)
        seed, name = hashlib.sha256(b"omniwitness").digest(), "witness.example.org/omni"
        kid = checkpoint.key_id(name, checkpoint.ED25519, pub(seed)).hex()
        with open(os.path.join(d, "w.key"), "w") as f:
            f.write(f"PRIVATE+KEY+{name}+{kid}+{base64.b64encode(bytes([1]) + seed).decode()}")
        port = _free_port()
        with mock.patch.object(svc, "TICK_S", 0.05):
            s = svc.SignerService(os.path.join(d, "signer"), grace_s=0, witnesses=[TlogWitness(
                f"http://127.0.0.1:{port}", checkpoint.vkey(name, checkpoint.COSIGNATURE, pub(seed)))])
            self.addCleanup(s.close)
            out = s.call(ME, "register_run", {"request_id": "r", "agent": {"name": "a"}})
            s.call(ME, "close_run", {"request_id": "c", "run_id": out["run_id"], "run_token": out["run_token"]})
            s.sweep()
            servers = svc.serve({"socket": os.path.join(d, "s.sock"), "metrics": {"listen": "127.0.0.1:0"}}, s)
            for x in servers:
                self.addCleanup(x.server_close)
                self.addCleanup(x.shutdown)
            p = subprocess.Popen(["omniwitness", f"--listen=127.0.0.1:{port}",
                                  f"--metrics_listen=127.0.0.1:{_free_port()}", f"--private_key_path={d}/w.key",
                                  f"--public_witness_config_url=http://127.0.0.1:{servers[0].server_address[1]}/logs/v0",
                                  "--public_witness_config_poll_interval=1s", f"--db_file={d}/w.db"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(p.wait)
            self.addCleanup(p.terminate)
            for tree in (RECORDS, registry_tree("default")):
                self.assertTrue(wait_for(lambda: s.checkpoint() or f"— {name} " in s.log.storage.checkpoint_latest(
                    tree)[1], 20, 0.2), tree)

if __name__ == "__main__":
    unittest.main()
