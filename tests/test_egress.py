"""Egress observation (tracekit/egress.py and the signer's observe_effect): effects attributed to runs, reconciled
against the run's calls, the gateways and the policy's explains; observer heartbeats on the tailer machinery; late and
unattributed effects; the coverage matrix in run.final and the verifier; the proxy's SNI, IP and DoH refusals."""
import base64
import json
import math
import os
import socket
import ssl
import threading
import time
import types
import unittest
from unittest import mock

from test_signer_lifecycle import Lifecycle
from test_signer_service import ME, OTHER
from tracekit import egress
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.verify import v2

OBSERVER = CallerIdentity("mtls", "spiffe://acme/egress", True)
GATEWAY = CallerIdentity("mtls", "spiffe://acme/gateway", True)
TS = "2026-10-12T10:00:00.000000Z"
POLICY = {"tools": {"fetch": "http", "Bash": "shell"},
          "flag": [{"id": "PIP", "tool": "Bash", "pattern": "pip install", "label": "package-install"}],
          "deny": [{"id": "NO", "tool": "fetch", "pattern": "denied"}],
          "explains": [{"label": "package-install", "hosts": ["*.pythonhosted.org", "pypi.org"]},
                       {"tool": "fetch", "hosts": ["cdn.example.net"]}],
          "respond": [{"trigger": "unexplained_effect", "mode": "shadow", "action": "notify"}]}


def effect(host, port=443, **kw):
    return {"kind": "net", "host": host, "port": port, "bytes_out": 10, "bytes_in": 20, "connections": 1,
            "first_ts": TS, "last_ts": TS, **kw}


class Observed(Lifecycle):
    posture = None

    def open(self):
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), grace_s=0, idle_s=3600, observe_grace_s=60,
                                   gateways=["mtls:spiffe://acme/gateway"], posture=self.posture,
                                   authorize={"mtls:spiffe://acme/egress": ["observe_effect"],
                                              "mtls:spiffe://acme/gateway": ["model_event", "decide", "complete"],
                                              f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS)})
        self.closed = False

    def observe(self, *effects, who=OBSERVER):
        return self.call("observe_effect", {"effects": list(effects)}, who)

    def covered(self):
        """A run registered while the observer is alive, so it covers it."""
        self.observe()
        return self.register()

    def final(self, run, after=61):
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + after)
        return self.events(run["run_id"])

    def typed(self, events, typ):
        return [e for e in events if e["type"] == typ]

    def gaps(self, events, kind):
        return [e["data"] for e in self.typed(events, "capture.gap") if e["data"]["kind"] == kind]


class TestReconciliation(Observed):
    def test_a_host_nothing_explains_is_one_unexplained_effect(self):
        run = self.covered()
        self.decide(run, 0, "t1", "fetch")   # an http call names api.example.com
        self.call("decide", self.ev(run, 1, tool_call_id="t2", tool="Bash", args_source="parsed",
                                    args={"command": "curl https://unlisted.example/x && pip install requests"}))
        self.call("decide", self.ev(run, 2, tool_call_id="t3", tool="fetch", args_source="parsed",
                                    args={"url": "https://api.example.com/v1"}))
        self.call("model_event", self.ev(run, 3, provider="anthropic", model="m", phase="request"))   # its API host
        self.observe(*(effect(h, **run) for h in ("api.example.com", "unlisted.example", "unlisted.example",
                                                  "files.pythonhosted.org", "cdn.example.net", "api.anthropic.com")),
                     effect("upstream.example", **run, client="mtls:spiffe://acme/gateway"))
        es = self.final(run)
        by = {e["data"]["host"]: e["data"].get("explained_by") for e in self.typed(es, "effect.observed")}
        self.assertEqual(by, {"api.example.com": "call", "unlisted.example": None, "files.pythonhosted.org": "explains",
                              "cdn.example.net": "explains", "upstream.example": "gateway",
                              "api.anthropic.com": "call"})
        (u,) = self.typed(es, "reconcile.unexplained_effect")   # once per host, though seen twice
        self.assertEqual({k: u["data"][k] for k in ("layers", "observer", "kind", "host", "port")},
                         {"layers": ["L6"], "observer": "mtls:spiffe://acme/egress", "kind": "net",
                          "host": "unlisted.example", "port": 443})
        self.assertIn("add it to the policy's explains", u["data"]["detail"])
        self.assertTrue(all(e["source"] == "signer" for e in self.typed(es, "effect.observed")))
        final = self.typed(es, "run.final")[0]["data"]
        self.assertEqual(final["coverage"]["unreconciled"]["unexplained_effect"], 1)
        [opened] = self.typed(es, "incident.opened")   # a detection trigger, notify-only in the shipped packs
        self.assertEqual((opened["data"]["trigger"], opened["data"]["would"]), ("unexplained_effect", ["notify"]))

    def test_a_denied_call_explains_nothing(self):
        run = self.covered()
        self.call("decide", self.ev(run, 0, tool_call_id="t1", tool="fetch", args_source="parsed",
                                    args={"url": "https://denied.example/"}))
        self.observe(effect("denied.example", **run))
        self.assertEqual(len(self.typed(self.final(run), "reconcile.unexplained_effect")), 1)

    def test_attribution_by_identity_and_effects_no_open_run_holds(self):
        older, newer = self.covered(), self.register()
        self.observe(effect("a.example", caller=f"uid:{ME.subject}"),   # the owner's latest open run
                     effect("b.example", caller=f"uid:{OTHER.subject}"),   # no open run
                     effect("c.example", run_id=newer["run_id"], run_token="bad.token"),
                     effect("d.example", run_id=older["run_id"], run_token=newer["run_token"]))
        es = self.events(newer["run_id"])
        (e,) = self.typed(es, "effect.observed")
        self.assertEqual((e["data"]["host"], e["data"]["attribution"]), ("a.example", "identity"))
        outside = [e["data"] for e in self.typed(self.events("tracekit/signer"), "capture.gap")
                   if e["data"]["kind"] == "effect_outside_run"]
        self.assertEqual(len(outside), 3)
        reasons = " | ".join(d["reason"] for d in outside)
        for why in (f"uid:{OTHER.subject} has no open run", "not one this signer issued", "for another run or tenant",
                    "b.example:443 (10 bytes out, 20 in, 1 connection(s)"):
            self.assertIn(why, reasons)

    def test_after_run_final_an_effect_goes_in_the_tenants_signer_run(self):
        run = self.covered()
        self.call("close_run", run)
        self.observe(effect("late.example", **run))   # closing, within observe_grace_s: the run takes it
        self.s.sweep(time.monotonic() + 30)
        self.assertFalse(self.s.log.runs[("default", run["run_id"])]["final"])   # waits for the observer's reports
        self.s.sweep(time.monotonic() + 61)
        self.observe(effect("later.example", **run))
        self.assertEqual([e["data"]["host"] for e in self.typed(self.events(run["run_id"]), "effect.observed")],
                         ["late.example"])
        (gap,) = self.gaps(self.events("tracekit/signer"), "effect_outside_run")
        self.assertEqual(gap["run_id"], run["run_id"])
        self.assertIn("was final by then (raise observe_grace_s", gap["reason"])

    def test_only_an_observer_granted_observe_effect_and_never_the_runs_owner(self):
        run = self.register()
        self.refused("forbidden", "observe_effect", {"effects": [effect("x.example", **run)]}, OTHER)   # never default
        self.close()
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), authorize={f"uid:{ME.subject}": [
            "register_run", "observe_effect"]})
        self.closed = False
        mine = self.register()
        self.refused("forbidden", "observe_effect", {"effects": [effect("x.example", **mine)]})
        self.assertIn("observe_effect", svc.NEVER_DEFAULT)


class TestHeartbeats(Observed):
    def test_a_silent_observer_is_a_gap_and_the_run_is_not_observed(self):
        run = self.covered()
        t = time.monotonic()
        self.s.sweep(t + svc.TAILER_LOST_S + 1)
        self.s.sweep(t + 2 * svc.TAILER_LOST_S)   # once
        es = self.final(run, after=3 * svc.TAILER_LOST_S)
        (lost,) = self.gaps(es, "observer_lost")
        self.assertIn("no observe_effect from egress observer mtls:spiffe://acme/egress", lost["reason"])
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["network"], {"status": "none", "layers": []})

    def test_heartbeats_keep_it_covered_and_a_run_registered_before_it_is_not(self):
        before = self.register()
        run = self.covered()
        for i in range(1, 4):   # heartbeats every 30 s
            with mock.patch.object(svc.time, "monotonic", return_value=time.monotonic() + 30 * i):
                self.observe()
        with mock.patch.object(svc.time, "monotonic", return_value=time.monotonic() + 100):
            self.call("close_run", run)
            self.call("close_run", before)
        self.s.sweep(time.monotonic() + 161)
        es = self.events(run["run_id"])
        self.assertEqual(self.gaps(es, "observer_lost"), [])
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["network"],
                         {"status": "observed", "layers": ["egress"]})
        self.assertEqual(self.typed(self.events(before["run_id"]), "run.final")[0]["data"]["matrix"]["network"]["status"],
                         "none")


class TestVerifier(Observed):
    def test_the_matrix_line_and_warnings_strict_exits_on(self):
        run = self.covered()
        self.decide(run, 0, "t1", "fetch")
        self.observe(effect("unlisted.example", **run))
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)   # the observer went silent
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 200)
        self.s.checkpoint()
        note = self.s.log.storage.checkpoint_latest()[1]
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", run["run_id"], note, bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        checks = {c["check"]: c for c in rep.checks}
        self.assertEqual(code, 0)
        self.assertEqual(checks["coverage matrix"]["detail"], "model calls not covered, tool calls reported (adapter), "
                         "network not covered, processes not covered, services not covered")
        self.assertNotIn("complete", checks["coverage matrix"]["detail"])
        self.assertEqual((checks["coverage"]["status"], checks["observers"]["status"]), ("warn", "warn"))
        self.assertIn("unexplained_effect 1", checks["coverage"]["detail"])
        self.assertTrue(rep.warnings)   # what --strict exits 3 on


class TestMatrix(Observed):
    posture = {"network": "enforced", "gateway_mandatory": True}

    def test_a_gateway_mandatory_egress_run_and_a_plain_run(self):
        run = self.covered()
        self.call("model_event", self.ev(run, 0, stream="gw", provider="openai", model="m", phase="request",
                                         caller=f"uid:{ME.subject}"), GATEWAY)
        args = {"url": "https://api.example.com/"}
        d = self.call("decide", self.ev(run, 1, stream="gw", tool_call_id="t1", tool="fetch", args_source="parsed",
                                        args=args, caller=f"uid:{ME.subject}"), GATEWAY)
        self.call("complete", self.ev(run, 2, stream="gw", tool_call_id="t1", decision_id=d["decision_id"], status="ok",
                                      args_digest=event_hash({"tool": "fetch", "args": args}),
                                      caller=f"uid:{ME.subject}"), GATEWAY)
        reg = self.typed(self.final(run), "run.registered")[0]["data"]
        self.assertEqual(reg["posture"], {"network": "enforced", "gateway_mandatory": True, "attested": False})
        matrix = self.typed(self.events(run["run_id"]), "run.final")[0]["data"]["matrix"]
        self.assertEqual(matrix, {"model_calls": {"status": "enforced", "layers": ["gateway"], "asserted": True},
                                  "tool_calls": {"status": "enforced", "layers": ["gateway"]},
                                  "network": {"status": "enforced", "layers": ["egress"], "asserted": True},
                                  "processes": {"status": "none", "layers": []},
                                  "services": {"status": "none", "layers": []}})
        self.open()
        plain = self.register()   # a new signer process has seen no observer: a T1 run, reported by its own process
        self.decide(plain, 0, "t1", "fetch")
        matrix = self.typed(self.final(plain), "run.final")[0]["data"]["matrix"]
        self.assertEqual({k: (v["status"], v["layers"]) for k, v in matrix.items()},
                         {"model_calls": ("none", []), "tool_calls": ("reported", ["adapter"]),
                          "network": ("none", []), "processes": ("none", []), "services": ("none", [])})

    def test_posture_is_validated(self):
        for bad in ({"network": "closed"}, {"gateway_mandatory": "yes"}, {"egress": True}):
            with self.subTest(bad), self.assertRaises(ValueError):
                svc.SignerService(self.dir + "-bad", posture=bad)


class TestExplainsLint(unittest.TestCase):
    def lint(self, explains):
        path = os.path.join(self.d, "p.json")
        with open(path, "w") as f:
            json.dump({"flag": [{"id": "F", "pattern": "x", "label": "deps"}], "explains": explains}, f)
        return policy_compile.build(path)[1]

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()

    def test_explains(self):
        self.assertEqual(self.lint([{"label": "deps", "hosts": ["*.pypi.org"]}, {"tool": "fetch", "hosts": ["a.io"]}]),
                         [])
        for bad, want in (([{"hosts": ["a.io"]}], "explains must list"), ([{"tool": "x", "label": "deps",
                                                                             "hosts": ["a.io"]}], "explains must list"),
                          ([{"tool": "x", "hosts": []}], "explains must list"),
                          ([{"label": "nope", "hosts": ["a.io"]}], "no rule has this label"),
                          ([{"tool": "x", "hosts": ["*.*"]}], "too loose")):
            with self.subTest(bad):
                self.assertIn(want, " ".join(self.lint(bad)))


def client_hello(name):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    out = ssl.MemoryBIO()
    tls = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


class Upstream:
    """A TCP server that keeps what it is sent and answers `pong`."""

    def __init__(self):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port, self.got = self.sock.getsockname()[1], []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                c.settimeout(5)
                data = b""
                try:
                    while b"\r\n\r\n" not in data and len(data) < 517 and (chunk := c.recv(65536)):
                        data += chunk
                        if data[:1] == b"\x16" and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
                            break
                    c.sendall(b"pong")
                except OSError:
                    pass
                self.got.append(data)


class TestProxy(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.client = types.SimpleNamespace(observe_effect=self.sent.append)
        self.srv = egress.serve({"listen": "127.0.0.1:0", "signer": "unused", "allow": ["127.0.0.2"]}, self.client)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.up = Upstream()
        self.addCleanup(self.up.sock.close)
        self.auth = "Basic " + base64.b64encode(b"run-1:tok.mac").decode()

    def connect(self, authority, auth=None):
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode()
                  + (f"Proxy-Authorization: {auth or self.auth}\r\n" if auth != "" else "").encode() + b"\r\n")
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1)
            if not chunk:
                break
            head += chunk
        return s, head.split(b"\r\n", 1)[0].decode()

    def read(self, s):
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except OSError:
            pass
        return out

    def test_a_tunnel_whose_sni_is_its_host_is_observed_per_minute(self):
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertEqual(status, "HTTP/1.1 200 Connection established")
        hello = client_hello("localhost")
        s.sendall(hello)
        self.assertEqual(self.read(s), b"pong")
        s.close()
        deadline = time.monotonic() + 5
        while not self.up.got and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.up.got, [hello])
        time.sleep(0.1)
        self.assertTrue(self.srv.observer.flush(time.time()))   # the minute has not ended: a heartbeat alone
        self.assertEqual(self.sent[-1]["effects"], [])
        self.srv.observer.flush(math.inf)
        (e,) = self.sent[-1]["effects"]
        self.assertEqual({k: e[k] for k in ("run_id", "run_token", "kind", "host", "port", "bytes_out", "bytes_in",
                                            "connections")},
                         {"run_id": "run-1", "run_token": "tok.mac", "kind": "net", "host": "localhost",
                          "port": self.up.port, "bytes_out": len(hello), "bytes_in": 4, "connections": 1})

    def test_sni_mismatch_raw_ips_and_doh_are_refused(self):
        s, status = self.connect(f"localhost:{self.up.port}")
        s.sendall(client_hello("evil.example"))
        self.assertEqual(self.read(s), b"")   # closed before anything reached the host
        self.assertEqual(self.up.got, [])
        for authority, why in ((f"127.0.0.1:{self.up.port}", "is an IP address"),
                               ("dns.google:443", "DNS-over-HTTPS endpoint")):
            s, status = self.connect(authority)
            self.assertTrue(status.startswith("HTTP/1.1 403"), status)
            self.assertIn(why, self.read(s).decode())
        self.srv.observer.flush(math.inf)
        self.assertEqual([e for r in self.sent for e in r["effects"]], [])

    def test_an_allowed_host_needs_no_tls(self):
        self.srv.observer.allow.add("127.0.0.1")
        s, status = self.connect(f"127.0.0.1:{self.up.port}")
        s.sendall(b"ping\r\n\r\n")
        self.assertEqual(self.read(s), b"pong")

    def test_no_run_and_no_identity_is_407(self):
        with mock.patch.object(egress, "_peer_uid", return_value=None):
            s, status = self.connect(f"localhost:{self.up.port}", auth="")
        self.assertTrue(status.startswith("HTTP/1.1 407"), status)
        self.assertIn("Proxy-Authorization: Basic", self.read(s).decode())
        with mock.patch.object(egress, "_peer_uid", return_value=1234):   # system mode: the agent's uid
            s, status = self.connect(f"localhost:{self.up.port}", auth="")
        self.assertEqual(status, "HTTP/1.1 200 Connection established")
        s.sendall(client_hello("localhost"))
        self.read(s)
        self.srv.observer.flush(math.inf)
        self.assertEqual(self.sent[-1]["effects"][0]["caller"], "uid:1234")

    def test_plain_http_is_forwarded(self):
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"GET http://localhost:{self.up.port}/x?y=1 HTTP/1.1\r\nHost: localhost\r\n"
                  f"Proxy-Authorization: {self.auth}\r\n\r\n".encode())
        self.assertEqual(self.read(s), b"pong")
        self.assertTrue(self.up.got[0].startswith(b"GET /x?y=1 HTTP/1.1\r\n"))
        self.assertNotIn(b"Proxy-Authorization", self.up.got[0])

    def test_totals_the_signer_did_not_take_are_sent_again(self):
        self.srv.observer.add(("token", "run-1", "tok.mac", None), "a.example", 443, 5, 6, True)
        self.client.observe_effect = mock.Mock(side_effect=SignerUnavailable("down"))
        self.assertFalse(self.srv.observer.flush(math.inf))
        rid = self.client.observe_effect.call_args[0][0]["request_id"]
        self.client.observe_effect = mock.Mock(side_effect=[RPCError("forbidden", "no grant"), None])
        self.assertTrue(self.srv.observer.flush(math.inf))
        first = self.client.observe_effect.call_args_list[0][0][0]
        self.assertEqual((first["request_id"], first["effects"][0]["host"]), (rid, "a.example"))   # the same request


class TestEndToEnd(Observed):
    def test_the_proxy_reports_to_the_signer(self):
        up = Upstream()
        self.addCleanup(up.sock.close)
        client = types.SimpleNamespace(observe_effect=lambda req: self.s.call(OBSERVER, "observe_effect", req))
        srv = egress.serve({"listen": "127.0.0.1:0", "signer": "unused"}, client)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        srv.observer.flush()
        run = self.register()
        s = socket.create_connection(srv.server_address[:2], 5)
        auth = base64.b64encode(f"{run['run_id']}:{run['run_token']}".encode()).decode()
        s.sendall(f"CONNECT localhost:{up.port} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        while not s.recv(65536).endswith(b"\r\n\r\n"):
            pass
        s.sendall(client_hello("localhost"))
        while s.recv(65536):
            pass
        s.close()
        time.sleep(0.1)
        srv.observer.flush(math.inf)
        es = self.final(run)
        self.assertEqual([e["data"]["host"] for e in self.typed(es, "reconcile.unexplained_effect")], ["localhost"])
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["network"]["status"], "observed")


if __name__ == "__main__":
    unittest.main()
