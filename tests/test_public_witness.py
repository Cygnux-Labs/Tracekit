"""The public witness (tracekit.public_witness_server) with the existing client, and the opt-in (tracekit.public_witness)."""
import contextlib
import hashlib
import http.client
import inspect
import io
import json
import os
import socket
import threading
import time
import unittest
from unittest import mock

from factories import wait_for
from test_signer_service import ME, tmpdir
from test_witness_publish import signed_note
from tracekit import crypto, install, merkle, public_witness
from tracekit import public_witness_server as pws
from tracekit.format import checkpoint, registry
from tracekit.signer import service as svc
from tracekit.storage.base import RECORDS, registry_tree
from tracekit.tlog_witness import MAX_BODY, TlogWitness, WitnessError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGIN = "tracekit.example.org/log/public"
NAME = "witness.example.org/public"


class Server(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.vkey = pws.init(self.home, NAME)
        self.start()
        self.secret = hashlib.sha256(b"log").digest()
        self.log_vkey = self.vkey_of(self.secret)
        self.leaves = [merkle.leaf_hash(b"%d" % i) for i in range(40)]

    def start(self, proxied=False):
        self.srv = pws.serve(self.home, proxied=proxied)
        threading.Thread(target=self.srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(self.stop)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.client = TlogWitness(self.url, self.vkey)

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()

    def vkey_of(self, secret, origin=ORIGIN):
        return checkpoint.vkey(origin, checkpoint.ED25519, crypto.public_from_secret(secret))

    def add(self, n, old, leaves=None, secret=None, origin=ORIGIN):
        leaves, secret = leaves or self.leaves, secret or self.secret
        return self.client.add_checkpoint(signed_note(origin, leaves[:n], secret), self.vkey_of(secret, origin), old,
                                          lambda m: merkle.consistency_proof(m, leaves[:n]))

    def post(self, path, body, method="POST", xff=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        try:
            c.request(method, path, body=body and body.encode("utf-8"), headers={"X-Forwarded-For": xff} if xff else {})
            r = c.getresponse()
            return r.status, r.getheader("Content-Type"), r.read().decode()
        finally:
            c.close()

    def register(self, origin=ORIGIN, secret=None, vkey=None, note=None):
        secret = secret or self.secret
        return self.post("/register", json.dumps({"origin": origin, "vkey": vkey or self.vkey_of(secret, origin),
                                                  "checkpoint": note or signed_note(origin, [], secret)}))[:3:2]

    def restart_proxied(self):
        self.stop()
        self.start(proxied=True)

    def origins(self):
        with self.srv.witness.lock:
            return [r[0] for r in self.srv.witness.db.execute("SELECT origin FROM origins ORDER BY origin")]

    def test_round_trip_with_the_client_registers_on_first_use(self):
        lines = self.add(5, 0)   # 404, then /register, then the resend
        note = signed_note(ORIGIN, self.leaves[:5], self.secret) + lines
        self.assertEqual(len(checkpoint.open_note(note, [self.log_vkey], [self.vkey])[3]), 1)
        self.assertTrue(self.add(9, 5))   # with a consistency proof from 5
        self.assertTrue(self.add(12, 0))   # 409, then from 9
        self.assertEqual(self.client.latest(signed_note(ORIGIN, [], self.secret), self.log_vkey), (12, None))

    def test_registration_needs_proof_of_possession(self):
        other = hashlib.sha256(b"other").digest()
        self.assertEqual(self.register(note=signed_note(ORIGIN, [], other))[0], 403)
        self.assertEqual(self.register(vkey=self.vkey_of(self.secret, "tracekit.example.org/log/x"))[0], 400)
        self.assertEqual(self.register(note=signed_note("tracekit.example.org/log/x", [], self.secret))[0], 403)
        for origin in ("Example.org/log", "example.org", "example.org/a b", "x" * 250 + ".org/a"):
            self.assertEqual(self.register(origin=origin, vkey=self.log_vkey, note=signed_note(ORIGIN, [], self.secret))[0],
                             400, origin)
        self.assertEqual(self.post("/register", "[1]")[0], 400)
        self.assertEqual(self.register(), (200, "registered\n"))
        self.assertEqual(self.register(), (200, "registered\n"))   # the same key again: idempotent

    def test_a_second_key_for_a_taken_origin_is_refused(self):
        self.add(3, 0)
        other = hashlib.sha256(b"other").digest()
        self.assertEqual(self.register(secret=other)[0], 409)
        with self.assertRaises(WitnessError) as cm:   # a signer with another key under that origin is told why
            self.add(3, 0, secret=other)
        self.assertIn("a new log key needs a new `origin`", str(cm.exception))
        self.assertFalse(cm.exception.retryable)

    def test_the_witness_never_cosigns_a_fork(self):
        self.add(5, 0)
        fork = [merkle.leaf_hash(b"fork %d" % i) for i in range(8)]
        with self.assertRaises(WitnessError) as cm:
            self.add(8, 5, leaves=fork)
        self.assertIn("HTTP 422", str(cm.exception))
        with self.assertRaises(WitnessError):   # the same size, another root
            self.add(5, 5, leaves=fork)
        self.assertEqual(self.client.latest(signed_note(ORIGIN, [], self.secret), self.log_vkey), (5, None))

    def test_409_carries_the_stored_size(self):
        self.add(7, 0)
        status, ctype, body = self.post("/add-checkpoint", "old 0\n\n" + signed_note(ORIGIN, self.leaves[:9], self.secret))
        self.assertEqual((status, ctype, body), (409, "text/x.tlog.size", "7\n"))
        self.assertEqual(self.post("/add-checkpoint", "old 9\n\n" + signed_note(ORIGIN, self.leaves[:7],
                                                                                 self.secret))[0], 400)

    def test_limits(self):
        now = time.time()   # the limits count per calendar minute and day: one that turns mid-test restarts a count
        clock = mock.patch.object(pws, "time", mock.Mock(time=lambda: now))
        clock.start()
        self.addCleanup(clock.stop)
        with mock.patch.object(pws, "CHECKPOINTS_PER_MIN", 2):
            self.add(1, 0)
            self.add(2, 1)
            with self.assertRaises(WitnessError) as cm:
                self.add(3, 2)
            self.assertIn("HTTP 429", str(cm.exception))
            self.assertTrue(cm.exception.retryable)
        with mock.patch.object(pws, "REGISTRATIONS_PER_DAY", 1):
            self.srv.witness._hits.pop("register", None)
            self.assertEqual(self.register(origin="a.example.org/1")[0], 200)
            self.assertEqual(self.register(origin="a.example.org/2")[0], 429)
        with mock.patch.object(pws, "MAX_ORIGINS", 2):
            self.srv.witness._hits.pop("register", None)
            status, text = self.register(origin="a.example.org/3")
            self.assertEqual(status, 403)
            self.assertIn("run your own witness", text)
        self.assertEqual(self.post("/add-checkpoint", "x" * (MAX_BODY + 1))[0], 413)
        with mock.patch.object(pws, "REGISTRATIONS_PER_DAY", 1):   # behind the proxy, the forwarded address counts
            self.restart_proxied()
            for ip, status in (("192.0.2.1", 403), ("192.0.2.200", 429), ("198.51.100.1", 403),   # 403: a bad vkey
                               ("::ffff:198.51.100.2", 429),   # IPv4-mapped: its IPv4 /24
                               ("2001:db8::1", 403), ("2001:db8:0:1::1", 429), ("2001:db8:1::1", 403)):   # IPv6: /48
                body = json.dumps({"origin": "c.example.org/" + ip.replace(":", "-"), "vkey": "x", "checkpoint": "x"})
                self.assertEqual(self.post("/register", body, xff=f"203.0.113.9, {ip}")[0], status, ip)
        self.assertEqual(self.post("/add-checkpoint", "old x\n\nnote")[0], 400)
        self.assertEqual(self.post("/add-checkpoint", "old 0\n\n" + signed_note("unknown.example.org/1", [],
                                                                                self.secret))[0], 404)

    def test_a_tree_size_past_sqlite_is_refused(self):
        self.add(1, 0)
        text = checkpoint.body(ORIGIN, 1 << 63, merkle.root([]))
        status, _, body = self.post("/add-checkpoint", "old 1\n\n" + text + "\n" + checkpoint.sign(text, ORIGIN, self.secret))
        self.assertEqual((status, body), (400, "the tree size is over 2^63 - 1\n"))

    def test_deeply_nested_json_is_a_400_not_a_crash(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:   # parsed or past the parser's depth: 400 either way
            status = self.post("/register", "[" * 5000 + "]" * 5000)[0]
        self.assertEqual((status, err.getvalue()), (400, ""))   # nothing logged

    def test_replayed_old_notes_never_hold_up_the_log(self):
        self.add(3, 0)
        old = signed_note(ORIGIN, self.leaves[:2], self.secret)
        held = signed_note(ORIGIN, self.leaves[:3], self.secret)
        with mock.patch.object(pws, "CHECKPOINTS_PER_MIN", 3), mock.patch("time.time", return_value=time.time()):
            for _ in range(5):   # anyone holding the log's public notes
                self.assertEqual(self.post("/add-checkpoint", "old 2\n\n" + old)[:3:2], (409, "3\n"))
                status, _, lines = self.post("/add-checkpoint", "old 3\n\n" + held)
                self.assertEqual(status, 200)   # the tree it holds: cosigned again, not counted
                self.assertEqual(len(checkpoint.open_note(held + lines, [self.log_vkey], [self.vkey])[3]), 1)
            self.assertTrue(self.add(5, 3))
            self.assertTrue(self.add(6, 5))   # the third that grows the log this minute
            with self.assertRaises(WitnessError):
                self.add(7, 6)
        self.assertEqual(self.client.latest(signed_note(ORIGIN, [], self.secret), self.log_vkey), (6, None))

    def test_the_checkpoint_limit_is_per_client_network(self):
        self.restart_proxied()

        def push(n, ip):
            proof = n > 1 and merkle.consistency_proof(n - 1, self.leaves[:n]) or []
            return self.post("/add-checkpoint", f"old {n - 1}\n" + "".join(checkpoint._b64(h) + "\n" for h in proof) + "\n"
                             + signed_note(ORIGIN, self.leaves[:n], self.secret), xff=ip)[0]
        self.assertEqual(self.register()[0], 200)
        with mock.patch.object(pws, "CHECKPOINTS_PER_MIN", 1), mock.patch("time.time", return_value=time.time()):
            self.assertEqual([push(1, "192.0.2.1"), push(2, "192.0.2.1"), push(2, "::ffff:192.0.2.2"),
                              push(3, "2001:db8::1"), push(4, "2001:db8::2")], [200, 429, 200, 200, 429])

    def test_registrations_are_capped_in_all_and_the_counts_are_bounded(self):
        with mock.patch.object(pws, "REGISTRATIONS_PER_MIN", 1), mock.patch("time.time", return_value=time.time()):
            self.assertEqual(self.register(origin="a.example.org/1")[0], 200)
            self.assertEqual(self.register(origin="a.example.org/1")[0], 200)   # already there: not counted
            self.assertEqual(self.register(origin="a.example.org/2")[0], 429)
        self.restart_proxied()
        with mock.patch.object(pws, "MAX_HITS", 2):
            bad = json.dumps({"origin": "b.example.org/1", "vkey": "x", "checkpoint": "x"})
            self.assertEqual([self.post("/register", bad, xff=ip)[0] for ip in ("192.0.2.1", "198.51.100.1",
                                                                                "203.0.113.1", "192.0.2.1")],
                             [403, 403, 429, 403])   # a full table refuses new networks; it never grows past it
            self.assertEqual(len(self.srv.witness._hits["register"][1]), 2)

    def test_unused_and_idle_origins_expire(self):
        now = time.time()
        self.register(origin="a.example.org/unused")
        self.add(1, 0, origin="a.example.org/idle")
        self.add(1, 0, origin="a.example.org/used")
        with mock.patch("time.time", return_value=now + 89 * 86400):
            self.add(2, 1, origin="a.example.org/used")
        with mock.patch("time.time", return_value=now + 90 * 86400 + 60):
            self.register(origin="a.example.org/new")
            self.assertEqual(self.origins(), ["a.example.org/new", "a.example.org/used"])
            self.assertTrue(self.add(3, 0, origin="a.example.org/idle"))   # a returning log registers again
        with mock.patch("time.time", return_value=now + 3600):
            self.register(origin="a.example.org/young")
        self.assertIn("a.example.org/young", self.origins())   # within its 24 hours

    def test_requests_in_flight_are_capped_per_forwarded_client(self):
        self.restart_proxied()
        port, held, stop = self.srv.server_address[1], [], threading.Event()
        self.addCleanup(lambda: [s.close() for s in held])
        self.addCleanup(stop.set)

        def trickle():   # each body a byte at a time, so no read times out while the check runs
            while not stop.wait(0.5):
                for s in held:
                    try:
                        s.sendall(b" ")
                    except OSError:
                        pass
        with mock.patch.object(pws, "MAX_PER_IP", 2):
            for _ in range(2):   # bodies that don't complete during the check, all from one client behind the proxy
                s = socket.create_connection(("127.0.0.1", port))
                s.sendall(b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 192.0.2.1\r\n"
                          b"Content-Length: 1000\r\n\r\nold 0\n")
                held.append(s)
            threading.Thread(target=trickle, daemon=True).start()
            # both counted before the check: a request in flight counts too, so one let in first turns a held one away
            active = inspect.getclosurevars(self.srv.RequestHandlerClass.do_POST).nonlocals["active"]
            self.assertTrue(wait_for(lambda: active.get("192.0.2.1/32") == 2, 20))
            self.assertIn("at a time", self.post("/register", "{}", xff="192.0.2.1")[2])
            # a neighbour in the same /24 is served: the cap is per address, not per network (its own /24 limit may 429)
            self.assertNotIn("at a time", self.post("/register", "{}", xff="192.0.2.2")[2])

    def test_deploy_buffers_bodies_and_only_compose_trusts_the_proxy(self):
        def read(name):
            with open(os.path.join(ROOT, "deploy", "public-witness", name), encoding="utf-8") as f:
                return f.read()
        caddy, compose, dockerfile = read("Caddyfile"), read("docker-compose.yml"), read("Dockerfile")
        for line in ("max_size 10KiB", "request_buffers 10KiB", "header_up X-Forwarded-For {remote_host}"):
            self.assertIn(line, caddy)
        self.assertEqual(MAX_BODY, 10 * 1024)
        self.assertIn("./Caddyfile:/etc/caddy/Caddyfile:ro", compose)
        self.assertIn("--proxied", compose)
        self.assertNotIn("--proxied", next(line for line in dockerfile.splitlines() if line.startswith("CMD")))

    def test_a_trickling_witness_answer_is_cut_at_the_deadline(self):
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen()
        self.addCleanup(ls.close)
        stop = threading.Event()
        self.addCleanup(stop.set)

        def serve():
            c, _ = ls.accept()
            with c:
                c.recv(65536)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10240\r\n\r\n")
                while not stop.wait(0.3):   # one byte at a time, each well within the per-read timeout
                    c.sendall(b"x")
        threading.Thread(target=serve, daemon=True).start()
        client = TlogWitness(f"http://127.0.0.1:{ls.getsockname()[1]}", self.vkey, timeout=1)
        start = time.monotonic()
        with self.assertRaises(WitnessError) as cm:
            client.latest(signed_note(ORIGIN, [], self.secret), self.log_vkey)
        self.assertLess(time.monotonic() - start, 3)
        self.assertTrue(cm.exception.retryable)

    def test_a_witness_without_registration_keeps_its_404(self):
        with mock.patch.object(TlogWitness, "_send", side_effect=[(404, "unknown log\n"), (404, "not found\n")]):
            with self.assertRaises(WitnessError) as cm:
                self.add(1, 0)
        self.assertEqual(str(cm.exception), f"{NAME}: HTTP 404: unknown log")
        self.assertTrue(cm.exception.retryable)

    def test_state_survives_a_restart(self):
        self.add(5, 0)
        self.stop()
        self.start()
        self.assertEqual(self.client.latest(signed_note(ORIGIN, [], self.secret), self.log_vkey), (5, None))
        with self.assertRaises(WitnessError):
            self.add(6, 5, leaves=[merkle.leaf_hash(b"fork %d" % i) for i in range(6)])
        self.assertEqual(self.register(secret=hashlib.sha256(b"other").digest())[0], 409)
        self.assertEqual(pws.init(self.home, "another/name"), self.vkey)   # init keeps the key

    def test_stats_count_distinct_origins_per_week_and_name_none(self):
        w, now = self.srv.witness, time.time()
        week_ = pws.week(now)
        for origin in ("a.example.org/1", "b.example.org/1"):
            self.add(1, 0, origin=origin)
            self.add(2, 1, origin=origin)   # twice in a week: counted once
        with mock.patch("time.time", return_value=now + 8 * 86400):
            w.add_checkpoint("192.0.2.1", "old 2\n" + "".join(
                checkpoint._b64(h) + "\n" for h in merkle.consistency_proof(2, self.leaves[:3])) + "\n"
                + signed_note("a.example.org/1", self.leaves[:3], self.secret))
            stats = w.stats()
        self.assertEqual(stats, {"origins_7d": 1, "weeks": {week_: 2, pws.week(now + 8 * 86400): 1}})
        status, ctype, body = self.post("/stats", None, "GET")
        self.assertEqual((status, ctype), (200, "application/json"))
        self.assertEqual(json.loads(body)["origins_7d"], 2)
        self.assertNotIn("example.org", body)


class OptIn(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.home = os.path.join(self.dir, "pw")
        vkey = pws.init(self.home, NAME)
        self.srv = pws.serve(self.home)
        threading.Thread(target=self.srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        for target, k, v in ((public_witness, "URL", f"http://127.0.0.1:{self.srv.server_address[1]}"),
                             (public_witness, "VKEY", vkey), (svc, "BACKOFF_S", (0.05, 0.2)), (svc, "TICK_S", 0.05)):
            p = mock.patch.object(target, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.cfg = os.path.join(self.dir, "signer.yaml")
        with open(self.cfg, "w") as f:
            f.write(f'data_dir: {json.dumps(os.path.join(self.dir, "data"))}\norigin: "{ORIGIN}"\ngrace_s: 0\n'
                    'witnesses: [public]\n')   # a JSON string is a YAML string: Windows backslashes stay literal

    def test_the_shortcut_registers_cosigns_and_is_pinned_by_trust(self):
        cfg = svc.load_config(self.cfg)
        self.assertEqual(cfg["witnesses"], [{"url": public_witness.URL, "vkey": public_witness.VKEY, "class": "public"}])
        s = svc.open_service(cfg)
        self.addCleanup(s.close)
        out = s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        s.call(ME, "close_run", {"request_id": "r2", "run_id": out["run_id"], "run_token": out["run_token"]})
        s.sweep()
        s.checkpoint()
        for tree in (RECORDS, registry_tree("default")):   # each log registered itself on first use
            self.assertTrue(wait_for(lambda t=tree: f"— {NAME} " in (s.log.storage.checkpoint_latest(t) or (0, ""))[1],
                                     5), tree)
        self.assertEqual(self.srv.witness.stats()["origins_7d"], 2)
        self.assertTrue(registry.origin(ORIGIN, s.log.tenant_salt("default")).startswith(ORIGIN + "/registry/"))
        s.close()
        trust = os.path.join(self.dir, "trust.json")
        with mock.patch("sys.stdout"):
            self.assertEqual(svc.main(["trust", "--config", self.cfg, "-o", trust]), 0)
        with open(trust) as f:
            self.assertEqual(json.load(f)["witnesses"], [{"vkey": public_witness.VKEY, "class": "public"}])

    def test_the_shortcut_and_init_error_clearly_until_deployed(self):
        with mock.patch.object(public_witness, "URL", ""):
            with self.assertRaisesRegex(ValueError, "witnesses: public: the public witness is not deployed yet"):
                svc.load_config(self.cfg)
            with self.assertRaisesRegex(SystemExit, "--public-witness: the public witness is not deployed yet"):
                install.init_system_v2("agent", public_witness=True)

    def test_the_shortcut_refuses_an_origin_the_witness_does_not_take(self):
        with open(self.cfg, "w") as f:
            f.write(f'data_dir: {json.dumps(os.path.join(self.dir, "data"))}\norigin: "Example.org"\nwitnesses: [public]\n')
        with self.assertRaisesRegex(ValueError, "origin: the public witness takes origins shaped host/path"):
            svc.load_config(self.cfg)

    @unittest.skipIf(os.name == "nt", "system mode is POSIX-only")
    def test_init_v2_writes_the_shortcut(self):
        import types
        agent = types.SimpleNamespace(pw_uid=64101, pw_gid=64101, pw_name="agent", pw_dir="/home/agent")
        with open(self.cfg, "w") as f:
            f.write(install.v2_signer_yaml(agent, 501, "p.yaml", "/run/s.sock", 64102, public_witness=True))
        self.assertEqual(svc.load_config(self.cfg)["witnesses"][0]["class"], "public")
        self.assertNotIn("witnesses", install.v2_signer_yaml(agent, 501, "p.yaml", "/run/s.sock", 64102))


if __name__ == "__main__":
    unittest.main()
