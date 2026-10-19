"""Egress observation (tracekit/egress.py and the signer's observe_effect): effects attributed to runs, reconciled
against the run's calls, the gateways and the policy's explains; observer heartbeats on the tailer machinery; late and
unattributed effects; the coverage matrix in run.final and the verifier; the proxy's SNI, IP and DoH refusals."""
import base64
import concurrent.futures
import io
import ipaddress
import json
import math
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from test_signer_lifecycle import Lifecycle
from test_netserver import self_signed
from test_signer_service import ME, OTHER
from tracekit import egress
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.sdk import client as sdk_client
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import reconcile, service as svc
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


def public(test, yes=True):
    """Treat every address as public (or none) for `test`: the test hosts are on loopback."""
    for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        p = mock.patch.object(cls, "is_global", new_callable=mock.PropertyMock, return_value=yes)
        p.start()
        test.addCleanup(p.stop)


def effect(host, port=443, **kw):
    return {"kind": "net", "host": host, "port": port, "bytes_out": 10, "bytes_in": 20, "connections": 1,
            "first_ts": TS, "last_ts": TS, **kw}


class Observed(Lifecycle):
    posture, mandatory = None, False

    def open(self):
        self.s = svc.SignerService(self.dir, policy=Engine(POLICY), grace_s=0, idle_s=3600, observe_grace_s=60,
                                   gateways=["mtls:spiffe://acme/gateway"], posture=self.posture,
                                   gateway_mandatory=self.mandatory,
                                   authorize={"mtls:spiffe://acme/egress": ["observe_effect"],
                                              "mtls:spiffe://acme/gateway": ["model_event", "decide", "complete"],
                                              f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS)})
        self.closed = False

    def observe(self, *effects, who=OBSERVER, instance="obs-1", **kw):
        return self.call("observe_effect", {"instance": instance, "effects": list(effects), **kw}, who)

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
                                                  "files.pythonhosted.org", "cdn.example.net", "api.anthropic.com")))
        es = self.final(run)
        by = {e["data"]["host"]: e["data"].get("explained_by") for e in self.typed(es, "effect.observed")}
        self.assertEqual(by, {"api.example.com": "call", "unlisted.example": None, "files.pythonhosted.org": "explains",
                              "cdn.example.net": "explains", "api.anthropic.com": "call"})
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
        for why in (f"uid:{OTHER.subject} has no open run", "not one this signer issued for that run",
                    "b.example:443 (10 bytes out, 20 in, 1 connection(s)"):
            self.assertIn(why, reasons)
        # a token that fails names its run all the same: a run-set shows the gap against it
        self.assertEqual(sorted(d.get("run_id", "") for d in outside), sorted(["", newer["run_id"], older["run_id"]]))

    def test_a_token_that_fails_or_is_anothers_falls_back_to_the_connections_identity(self):
        mine, theirs = self.covered(), self.register(OTHER)
        me, other = f"uid:{ME.subject}", f"uid:{OTHER.subject}"
        self.observe(effect("made-up.example", run_id=mine["run_id"], run_token="x", caller=me),
                     effect("borrowed.example", **mine, caller=other),   # ME's token on OTHER's connection
                     effect("own.example", **mine, caller=me))
        by = {e["data"]["host"]: (e["data"]["attribution"], e["run_id"]) for e in
              self.typed(self.events(mine["run_id"]) + self.events(theirs["run_id"]), "effect.observed")}
        self.assertEqual(by, {"made-up.example": ("identity", mine["run_id"]), "own.example": ("token", mine["run_id"]),
                              "borrowed.example": ("identity", theirs["run_id"])})

    def test_check_refuses_a_token_the_signer_did_not_issue_for_that_run(self):
        run, other = self.covered(), self.register()
        self.assertEqual(self.observe(check=run), {"recorded": 0})
        for bad in ({"run_id": run["run_id"], "run_token": "x"}, {**other, "run_id": run["run_id"]}):
            with self.subTest(bad), self.assertRaises(RPCError) as cm:
                self.observe(check=bad)
            self.assertEqual(cm.exception.code, "run_token_invalid")
            self.assertIn("not one this signer issued for that run", cm.exception.message)

    def test_a_token_check_spends_no_event_and_a_made_up_one_is_refused_first(self):
        run = self.covered()
        empty = RPCError("quota_exceeded", "event rate limit", retry_after_ms=1000)
        with mock.patch.object(self.s.quotas, "take_event", side_effect=empty) as take:
            self.assertEqual(self.observe(check=run), {"recorded": 0})   # with the observer's bucket empty
            for _ in range(50):   # made-up tokens: refused, and nothing spent
                with self.assertRaises(RPCError) as cm:
                    self.observe(check={"run_id": run["run_id"], "run_token": "made.up"})
                self.assertEqual(cm.exception.code, "run_token_invalid")
            take.assert_not_called()
            with self.assertRaises(RPCError):   # a heartbeat or effects still spend it
                self.observe()

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
        self.refused("forbidden", "observe_effect", {"instance": "i", "effects": [effect("x.example", **mine)]})
        self.assertIn("observe_effect", svc.NEVER_DEFAULT)


class AskedOnly(Observed):
    """A call only asked for (an approval never granted) explains no traffic to its host."""

    def open(self):
        super().open()
        self.s.close()
        policy = {**POLICY, "ask": [{"id": "ASK", "tool": "fetch", "pattern": "asked"}]}
        self.s = svc.SignerService(self.dir, policy=Engine(policy), grace_s=0, idle_s=3600, observe_grace_s=60,
                                   authorize={"mtls:spiffe://acme/egress": ["observe_effect"],
                                              f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS)})

    def test_a_host_only_asked_for_is_unexplained(self):
        run = self.covered()
        d = self.call("decide", self.ev(run, 0, tool_call_id="t1", tool="fetch", args_source="parsed",
                                        args={"url": "https://asked.example/"}))
        self.assertEqual(d["decision"], "ask")
        self.observe(effect("asked.example", **run))
        self.assertEqual(len(self.typed(self.final(run), "reconcile.unexplained_effect")), 1)

    def test_an_ask_explains_through_explains_only_once_approved(self):
        rec = {"l2": {"t1": {"name": "fetch", "decision": "ask", "rules": ["ASK"]}}}
        explains = [{"tool": "fetch", "hosts": ["cdn.example.net"]}]
        self.assertIsNone(reconcile.explained(rec, "cdn.example.net", explains, {}))
        rec["l2"]["t1"]["approved"] = True
        self.assertEqual(reconcile.explained(rec, "cdn.example.net", explains, {}), "explains")


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

    def test_a_restarted_observer_is_a_gap_in_each_run_it_covered(self):
        run = self.covered()
        self.observe(effect("a.example", **run))
        self.observe(instance="obs-2")   # a new process: what the old one had not reported is gone
        later = self.register()   # the new process covers it from its start
        self.call("close_run", later)
        es = self.final(run)
        (lost,) = self.gaps(es, "observer_lost")
        self.assertIn("egress observer mtls:spiffe://acme/egress restarted while the run was open", lost["reason"])
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["network"]["status"], "none")
        later = self.events(later["run_id"])
        self.assertEqual((self.gaps(later, "observer_lost"),
                          self.typed(later, "run.final")[0]["data"]["matrix"]["network"]["status"]), ([], "observed"))

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
        self.assertNotIn("observer_lost", checks.get("gaps", {}).get("detail", ""))   # on its own line only
        self.assertIn("unexplained_effect 1", checks["coverage"]["detail"])
        self.assertRegex(checks["coverage"]["problems"][0],   # a host's record names no call: no "None" in its place
                         r"^seq \d+: reconcile\.unexplained_effect: the run reached unlisted\.example:443 ")
        self.assertTrue(rep.warnings)   # what --strict exits 3 on


class TestMatrix(Observed):
    posture, mandatory = {"network": "enforced", "tool_calls": "enforced"}, True

    def gateway_run(self):
        run = self.covered()
        self.call("model_event", self.ev(run, 0, stream="gw", provider="openai", model="m", phase="request",
                                         caller=f"uid:{ME.subject}"), GATEWAY)
        args = {"url": "https://api.example.com/"}
        d = self.call("decide", self.ev(run, 1, stream="gw", tool_call_id="t1", tool="fetch", args_source="parsed",
                                        args=args, caller=f"uid:{ME.subject}"), GATEWAY)
        self.call("complete", self.ev(run, 2, stream="gw", tool_call_id="t1", decision_id=d["decision_id"], status="ok",
                                      args_digest=event_hash({"tool": "fetch", "args": args}),
                                      caller=f"uid:{ME.subject}"), GATEWAY)
        return run

    def test_a_gateway_mandatory_egress_run_and_a_plain_run(self):
        run = self.gateway_run()
        reg = self.typed(self.final(run), "run.registered")[0]["data"]
        self.assertEqual(reg["posture"], {"network": "enforced", "tool_calls": "enforced", "gateway_mandatory": True,
                                          "attested": False})
        matrix = self.typed(self.events(run["run_id"]), "run.final")[0]["data"]["matrix"]
        self.assertEqual(matrix, {"model_calls": {"status": "enforced", "layers": ["gateway"], "asserted": True},
                                  "tool_calls": {"status": "enforced", "layers": ["gateway"], "asserted": True},
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

    def test_tool_calls_through_a_gateway_are_reported_unless_posture_asserts_more(self):
        self.close()
        self.posture = {"network": "enforced"}
        self.open()
        run = self.gateway_run()
        es = self.final(run)
        self.assertEqual(self.typed(es, "run.registered")[0]["data"]["posture"]["tool_calls"], "open")
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["tool_calls"],
                         {"status": "reported", "layers": ["gateway"]})

    def test_posture_is_validated(self):
        for bad in ({"network": "closed"}, {"tool_calls": True}, {"gateway_mandatory": True}, {"egress": True}):
            with self.subTest(bad), self.assertRaises(ValueError):
                svc.SignerService(self.dir + "-bad", posture=bad)


class PublicAddress(unittest.TestCase):
    def test_a_mapped_or_nat64_address_is_judged_by_the_ipv4_it_carries(self):
        for ip, public in (("64:ff9b::a00:7", False), ("::ffff:10.0.0.7", False), ("64:ff9b::808:808", True),
                           ("2606:4700::1111", True), ("10.0.0.7", False), ("fe80::1%en0", False)):
            with self.subTest(ip):
                self.assertEqual(egress._public(ip), public)


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

    def test_a_host_glob_needs_a_domain_one_owner_holds_after_its_last_wildcard(self):
        for h in ("*.com", "*pypi.org", "*", "pypi.*", "*.", "*..org"):
            with self.subTest(h):
                self.assertIn("is too loose", " ".join(self.lint([{"tool": "x", "hosts": [h]}])))
        self.assertEqual(self.lint([{"tool": "x", "hosts": ["*.pythonhosted.org", "pypi.org", "files?.example.com",
                                                            "*.ibm.de", "*.bbc.co.uk"]}]), [])


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


def socks5(proxy, host, port, creds=("run-1", "tok.mac"), cmd=1, tls=None):
    """A SOCKS5 request to host:port as microsandbox's outbound proxy sends it (crates/network/lib/proxy/socks.rs), or
    E2B's (a host name for a domain-matched flow; inside TLS with `tls`, an SSLContext): the socket and each reply."""
    s = socket.create_connection(proxy, 5)
    s = tls.wrap_socket(s) if tls else s
    s.sendall(b"\x05\x02\x00\x02" if creds else b"\x05\x01\x00")
    replies = [s.recv(2)]
    if replies[0] == b"\x05\x02":
        user, password = (x.encode() for x in creds)
        s.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        replies.append(s.recv(2))
    if replies[-1] in (b"\x05\x00", b"\x01\x00"):
        try:
            a = ipaddress.ip_address(host)
            target = bytes([1 if a.version == 4 else 4]) + a.packed
        except ValueError:
            target = bytes([3, len(host)]) + host.encode()
        s.sendall(bytes([5, cmd, 0]) + target + port.to_bytes(2, "big"))
        replies.append(s.recv(10))
    return s, replies


OPENED = b"\x05\x00\x00\x01" + bytes(6)


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
        public(self)
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
        before = time.time()   # the connection's minute ends after this, even when the clock turns a minute mid-test
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
        self.assertTrue(self.srv.observer.flush(before))   # the minute has not ended: a heartbeat alone
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

    def test_a_client_hello_trickled_past_the_deadline_closes_the_tunnel(self):
        self.srv.deadline = 1   # the connection's deadline (netserver.DEADLINE_S), from its CONNECT
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertEqual(status, "HTTP/1.1 200 Connection established")
        hello = client_hello("localhost")
        try:
            for i in range(4):   # each byte within the read timeout, the whole after the deadline
                s.sendall(hello[i:i + 1])
                time.sleep(0.5)
            s.sendall(hello[4:])
        except OSError:   # already cut
            pass
        self.assertEqual(self.read(s), b"")
        self.assertEqual(self.up.got, [])

    def test_one_attribution_holds_at_most_max_tunnels(self):
        with mock.patch.object(egress, "MAX_TUNNELS", 2):
            held = [self.connect(f"localhost:{self.up.port}")[0] for _ in range(2)]   # ClientHellos still to come
            s, status = self.connect(f"localhost:{self.up.port}")
            self.assertEqual(status, "HTTP/1.1 200 Connection established")
            self.assertEqual(self.read(s), b"")   # a third of run-1's: closed at once
            other = "Basic " + base64.b64encode(b"run-2:tok.mac").decode()
            s, _ = self.connect(f"localhost:{self.up.port}", other)
            s.sendall(client_hello("localhost"))
            self.assertEqual(self.read(s), b"pong")   # another run's tunnel opens
            held[0].sendall(client_hello("localhost"))
            self.assertEqual(self.read(held[0]), b"pong")
            s, _ = self.connect(f"localhost:{self.up.port}")   # one of run-1's closed: room for another
            s.sendall(client_hello("localhost"))
            self.assertEqual(self.read(s), b"pong")

    def test_a_uid_holds_at_most_max_tunnels_connections_each_attributed_in_time(self):
        """In system mode every agent connects from loopback, which the transport limits to 256 connections: one
        agent's half-open handshakes must not take them all."""
        held, ports = [], set()
        uid = lambda client, server: 1000 if client[1] in ports else 2000   # noqa: E731
        with mock.patch.object(egress, "MAX_TUNNELS", 3), mock.patch.object(egress, "PRE_AUTH_S", 4), \
                mock.patch.object(egress, "_peer_uid", uid):
            t = time.monotonic()
            for _ in range(4):   # SOCKS5's version byte, then nothing
                s = socket.create_connection(self.srv.server_address[:2], 10)
                ports.add(s.getsockname()[1])
                s.sendall(b"\x05")
                held.append(s)
            self.assertEqual(self.read(held[3]), b"")   # uid 1000's fourth: closed at once
            self.assertLess(time.monotonic() - t, 3)
            other = socket.create_connection(self.srv.server_address[:2], 5)   # another agent's
            other.sendall(b"\x05\x01\x00")
            self.assertEqual(other.recv(2), b"\x05\x00")   # attributed by its uid
            for s in held[:3]:   # none sent its greeting in time: cut, not left to the 30 s deadline
                self.assertEqual(self.read(s), b"")
            self.assertLess(time.monotonic() - t, 9)   # cut at PRE_AUTH_S: each read returns before its timeout

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

    def test_a_host_observe_effect_would_not_take_is_400_and_queues_nothing(self):
        self.srv.observer.add(("token", "run-1", "tok.mac", None), "a.example", 443, 5, 6, True)
        for url in ("http://a!b.example/", f"http://{'a' * 254}/"):
            s = socket.create_connection(self.srv.server_address[:2], 5)
            s.sendall(f"GET {url} HTTP/1.1\r\nProxy-Authorization: {self.auth}\r\n\r\n".encode())
            self.assertTrue(self.read(s).startswith(b"HTTP/1.1 400"))
        s, status = self.connect(f"{'a' * 254}:443")
        self.assertTrue(status.startswith("HTTP/1.1 400"), status)
        self.srv.observer.flush(math.inf)
        self.assertEqual([e["host"] for r in self.sent for e in r["effects"]], ["a.example"])

    def test_a_name_resolving_to_a_non_public_address_is_refused_unless_allowed(self):
        public(self, False)
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertTrue(status.startswith("HTTP/1.1 403"), status)
        self.assertIn("loopback, private or link-local address: add it to allow", self.read(s).decode())
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"GET http://localhost:{self.up.port}/ HTTP/1.1\r\nProxy-Authorization: {self.auth}\r\n\r\n"
                  .encode())
        self.assertTrue(self.read(s).startswith(b"HTTP/1.1 403"))
        self.assertEqual(self.up.got, [])
        self.srv.observer.allow.add("localhost")
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertEqual(status, "HTTP/1.1 200 Connection established")

    def test_an_sdk_run_gives_its_token_to_the_commands_it_starts_and_leaves_this_process_alone(self):
        proxy = f"http://{self.srv.server_address[0]}:{self.srv.server_address[1]}"
        reply = concurrent.futures.Future()
        reply.set_result({"run_id": "run-2", "run_token": "t/k+n=.m"})
        with mock.patch.dict(os.environ, {"TRACEKIT_EGRESS_PROXY": proxy}), \
                mock.patch.object(sdk_client.Client, "_send", return_value=reply):
            before = dict(os.environ)
            run = sdk_client.Client("unused.sock").run("a")
            self.assertEqual(dict(os.environ), before)   # the app's own connections and Tracekit's stay direct
            self.assertEqual(run.proxy_env["HTTPS_PROXY"], run.proxy_env["http_proxy"])
            env = {k: v for k, v in {**os.environ, **run.proxy_env}.items() if k.lower() != "no_proxy"}
        get = f"import urllib.request; urllib.request.urlopen('http://localhost:{self.up.port}/', timeout=5)"
        r = subprocess.run([sys.executable, "-c", get], env=env, capture_output=True, text=True, timeout=60)
        self.assertIn("BadStatusLine", r.stderr)   # through the proxy from its env; `pong` isn't HTTP
        self.assertTrue(self.up.got[0].startswith(b"GET / HTTP/1.1\r\n"))
        self.srv.observer.flush(math.inf)
        (e,) = self.sent[-1]["effects"]
        self.assertEqual((e["run_id"], e["run_token"], e["host"]), ("run-2", "t/k+n=.m", "localhost"))
        with mock.patch.dict(os.environ, clear=True):
            self.assertEqual(run.proxy_env, {})

    def test_totals_the_signer_did_not_take_are_sent_again(self):
        self.srv.observer.add(("token", "run-1", "tok.mac", None), "a.example", 443, 5, 6, True)
        self.client.observe_effect = mock.Mock(side_effect=SignerUnavailable("down"))
        self.assertFalse(self.srv.observer.flush(math.inf))
        rid = self.client.observe_effect.call_args[0][0]["request_id"]
        self.client.observe_effect = mock.Mock(side_effect=[RPCError("forbidden", "no grant"), None])
        self.assertTrue(self.srv.observer.flush(math.inf))
        self.assertTrue(self.srv.observer.flush(math.inf))   # refused: sent again with the next heartbeat
        calls = [c[0][0] for c in self.client.observe_effect.call_args_list]
        self.assertEqual([(c["request_id"], c["effects"][0]["host"]) for c in calls], [(rid, "a.example")] * 2)

    def test_a_run_token_client_is_not_charged_a_failed_authentication(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "bearer"), "w") as f:
            f.write("b" * 40)
        srv = egress.serve({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                     "token_file": os.path.join(d, "bearer")}, "signer": "unused"}, self.client)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.srv = srv   # connect() goes to this proxy
        for _ in range(30):   # more than the failed-authentication burst, all with a run token the signer accepts
            s, status = self.connect(f"localhost:{self.up.port}")
            s.close()
            self.assertNotIn(" 429 ", status + " ", status)

    def test_a_rate_limited_heartbeat_is_a_failure_and_its_totals_are_kept(self):
        self.srv.observer.add(("token", "run-1", "tok.mac", None), "a.example", 443, 5, 6, True)
        limited = RPCError("quota_exceeded", "event rate limit", retry_after_ms=500)
        self.client.observe_effect = mock.Mock(side_effect=[limited, None])
        self.assertFalse(self.srv.observer.flush(math.inf))
        self.assertTrue(self.srv.observer.flush(math.inf))
        calls = [c[0][0] for c in self.client.observe_effect.call_args_list]
        self.assertEqual(calls[0], calls[1])   # the same totals, the same request id

    def test_failed_token_checks_are_limited_per_address_before_the_signer_is_asked(self):
        asked = []

        def observe_effect(req):
            asked.append(req)
            raise RPCError("run_token_invalid", "not one this signer issued for that run")
        self.client.observe_effect = observe_effect
        made_up = "Basic " + base64.b64encode(b"run-1:made.up").decode()
        statuses = []
        for _ in range(30):
            s, status = self.connect(f"localhost:{self.up.port}", made_up)
            statuses.append(status.split()[1])
            s.close()
        self.assertIn("429", statuses)
        self.assertLess(len(asked), 30)   # past the limit the signer isn't asked
        self.assertEqual(set(statuses[len(asked):]), {"429"})

    def test_totals_refused_for_good_are_kept_only_up_to_a_bound(self):
        def forbidden(req):
            raise RPCError("forbidden", "no observe_effect grant")
        self.client.observe_effect = forbidden
        with mock.patch.object(egress, "MAX_REFUSED", 50), mock.patch("sys.stderr"):
            for minute in range(5):   # 40 hosts a minute, refused every time
                for h in range(40):
                    self.srv.observer.add(("token", "run-1", "tok.mac", None), f"h{minute}-{h}.example", 443, 1, 1, True)
                self.srv.observer.flush(math.inf)
                self.assertLessEqual(len(self.srv.observer.queue), 50)

    def test_a_refused_total_is_split_out_and_never_dropped(self):
        for h in ("a.example", "refused.example", "c.example"):
            self.srv.observer.add(("token", "run-1", "tok.mac", None), h, 443, 1, 1, True)

        def observe_effect(req):
            if any(e["host"] == "refused.example" for e in req["effects"]):
                raise RPCError("quota_exceeded", "too large")
            self.sent.append(req)
        self.client.observe_effect = observe_effect
        self.assertTrue(self.srv.observer.flush(math.inf))
        self.assertEqual(sorted(e["host"] for r in self.sent for e in r["effects"]), ["a.example", "c.example"])
        self.client.observe_effect = self.sent.append
        self.srv.observer.flush(math.inf)
        self.assertEqual([e["host"] for e in self.sent[-1]["effects"]], ["refused.example"])
        self.assertEqual({r["instance"] for r in self.sent}, {self.srv.observer.instance})

    def test_a_run_token_the_signer_did_not_issue_is_refused_before_anything_opens(self):
        def observe_effect(req):
            if req.get("check", {}).get("run_token") == "made.up":
                raise RPCError("run_token_invalid", "not one this signer issued for that run")
            self.sent.append(req)
        self.client.observe_effect = observe_effect
        made_up = "Basic " + base64.b64encode(b"run-1:made.up").decode()
        s, status = self.connect(f"localhost:{self.up.port}", made_up)
        self.assertTrue(status.startswith("HTTP/1.1 407"), status)
        self.assertIn("not one this signer issued for that run: send the run token", self.read(s).decode())
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"GET http://localhost:{self.up.port}/ HTTP/1.1\r\nProxy-Authorization: {made_up}\r\n\r\n".encode())
        self.assertTrue(self.read(s).startswith(b"HTTP/1.1 407"))
        for token in ("tok mac", "t\u00f6k", "t" * 1025):   # no token a run could have: the signer isn't asked
            s, status = self.connect(f"localhost:{self.up.port}",
                                     "Basic " + base64.b64encode(f"run-1:{token}".encode()).decode())
            self.assertTrue(status.startswith("HTTP/1.1 407"), status)
            self.assertIn("names no run id and token a run could have", self.read(s).decode())
        self.assertEqual((self.up.got, self.sent), ([], []))
        self.client.observe_effect = mock.Mock(side_effect=SignerUnavailable("down"))
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertTrue(status.startswith("HTTP/1.1 503"), status)
        self.assertIn("could not be reached to check the run token", self.read(s).decode())
        self.client.observe_effect = self.sent.append
        s, status = self.connect(f"localhost:{self.up.port}")
        self.assertEqual(status, "HTTP/1.1 200 Connection established")
        self.assertEqual((self.sent[-1]["check"], self.sent[-1]["effects"]),
                         ({"run_id": "run-1", "run_token": "tok.mac"}, []))
        s.close()

    def test_every_form_of_an_ip_address_is_refused(self):
        for host in ("134744072", "0x08080808", "8.8.2056", "010.010.010.010", "::ffff:8.8.8.8"):
            with self.subTest(host):
                self.assertIn("is an IP address", self.srv.observer.refused(host) or "")
        self.assertIsNone(self.srv.observer.refused("a.example"))
        s, status = self.connect("134744072:443")
        self.assertTrue(status.startswith("HTTP/1.1 403"), status)

    def test_a_plain_http_body_is_forwarded_whole(self):
        got, up = [], socket.create_server(("127.0.0.1", 0))
        self.addCleanup(up.close)

        def serve():
            c, _ = up.accept()
            with c, c.makefile("rb") as f:
                head = b""
                while not head.endswith(b"\r\n\r\n"):
                    head += f.readline()
                got.append(f.read(int(head.lower().split(b"content-length: ")[1].split(b"\r\n")[0])))
                c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        threading.Thread(target=serve, daemon=True).start()
        body = os.urandom(300_000)
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"POST http://localhost:{up.getsockname()[1]}/u HTTP/1.1\r\nContent-Length: {len(body)}\r\n"
                  f"Proxy-Authorization: {self.auth}\r\n\r\n".encode())
        for i in range(0, len(body), 16384):   # as a client sends a large body: in pieces, over time
            s.sendall(body[i:i + 16384])
            time.sleep(0.001)
        self.assertTrue(self.read(s).startswith(b"HTTP/1.1 204"))
        self.assertEqual(got, [body])

    def test_a_plain_http_body_is_streamed_not_held_whole(self):
        up, early, got = socket.create_server(("127.0.0.1", 0)), threading.Event(), []
        self.addCleanup(up.close)

        def serve():
            c, _ = up.accept()
            with c, c.makefile("rb") as f:
                head = b""
                while not head.endswith(b"\r\n\r\n"):
                    head += f.readline()
                got.append(f.read(1000))
                early.set()   # the head and the first bytes, before the client sent the rest
                got.append(f.read(1000))
                c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        threading.Thread(target=serve, daemon=True).start()
        s = socket.create_connection(self.srv.server_address[:2], 5)
        s.sendall(f"POST http://localhost:{up.getsockname()[1]}/u HTTP/1.1\r\nContent-Length: 2000\r\n"
                  f"Proxy-Authorization: {self.auth}\r\n\r\n".encode() + b"a" * 1000)
        self.assertTrue(early.wait(5), "the proxy held the body back until all of it had arrived")
        s.sendall(b"b" * 1000)
        self.assertTrue(self.read(s).startswith(b"HTTP/1.1 204"))
        self.assertEqual(got, [b"a" * 1000, b"b" * 1000])

    @unittest.skipUnless(sys.byteorder == "little", "the rows below are a little-endian machine's")
    def socks(self, host, **kw):
        return socks5(self.srv.server_address[:2], host, self.up.port, **kw)

    def test_a_socks5_address_is_reached_by_its_sni_and_its_credentials_are_the_run(self):
        s, replies = self.socks("127.0.0.1")
        self.assertEqual(replies, [b"\x05\x02", b"\x01\x00", OPENED])
        self.assertEqual(self.sent[0]["check"], {"run_id": "run-1", "run_token": "tok.mac"})
        hello = client_hello("localhost")
        s.sendall(hello)
        self.assertEqual(self.read(s), b"pong")
        self.assertEqual(self.up.got, [hello])
        time.sleep(0.1)
        self.srv.observer.flush(math.inf)
        (e,) = self.sent[-1]["effects"]
        self.assertEqual({k: e[k] for k in ("run_id", "run_token", "host", "port", "bytes_out", "bytes_in")},
                         {"run_id": "run-1", "run_token": "tok.mac", "host": "localhost", "port": self.up.port,
                          "bytes_out": len(hello), "bytes_in": 4})

    def test_a_socks5_address_whose_sni_does_not_resolve_to_it_is_closed_before_it_is_reached(self):
        for ip, hello, why in (("127.0.0.3", client_hello("localhost"), "'localhost' does not resolve to it here"),
                               ("127.0.0.1", client_hello(None), "it sends no TLS server name"),
                               ("127.0.0.1", b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "no TLS server name"),
                               ("127.0.0.1", client_hello("dns.google"), "DNS-over-HTTPS endpoint")):
            with self.subTest(why), mock.patch.object(sys, "stderr", io.StringIO()) as err:
                s, replies = self.socks(ip)
                self.assertEqual(replies[-1], OPENED)
                s.sendall(hello)
                self.assertEqual(self.read(s), b"")
                self.assertIn(why, err.getvalue())
        self.assertEqual(self.up.got, [])
        self.srv.observer.flush(math.inf)
        self.assertEqual([e for r in self.sent for e in r["effects"]], [])
        self.srv.observer.allow.add("127.0.0.1")   # an allowed address passes as itself, any protocol
        s, _ = self.socks("127.0.0.1")
        s.sendall(b"ping\r\n\r\n")
        self.assertEqual(self.read(s), b"pong")

    def test_socks5_without_a_run_udp_and_a_made_up_token_are_refused(self):
        with mock.patch.object(egress, "_peer_uid", return_value=None), mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(self.socks("127.0.0.1", creds=None)[1], [b"\x05\xff"])
            self.assertEqual(self.socks("127.0.0.1", cmd=3)[1][-1][:2], b"\x05\x07")   # UDP ASSOCIATE
            self.client.observe_effect = mock.Mock(side_effect=RPCError("run_token_invalid", "not issued"))
            self.assertEqual(self.socks("127.0.0.1", creds=("run-1", "made.up"))[1], [b"\x05\x02", b"\x01\x01"])
            self.assertEqual(self.socks("127.0.0.1", creds=("run-1", "tok mac"))[1], [b"\x05\x02", b"\x01\x01"])
        self.assertEqual(self.client.observe_effect.call_count, 1)   # a token no run could have isn't checked
        self.client.observe_effect = self.sent.append
        with mock.patch.object(egress, "_peer_uid", return_value=1234):   # no credentials: the client's identity
            s, replies = self.socks("127.0.0.1", creds=None)
        self.assertEqual(replies, [b"\x05\x00", OPENED])
        s.sendall(client_hello("localhost"))
        self.assertEqual(self.read(s), b"pong")
        self.srv.observer.flush(math.inf)
        self.assertEqual(self.sent[-1]["effects"][0]["caller"], "uid:1234")

    def test_a_socks5_host_name_is_resolved_and_checked_as_connects(self):
        s, replies = self.socks("localhost")
        self.assertEqual(replies[-1], OPENED)
        s.sendall(client_hello("localhost"))
        self.assertEqual(self.read(s), b"pong")
        with mock.patch.object(sys, "stderr", io.StringIO()) as err:
            s, replies = self.socks("localhost")
            s.sendall(client_hello("evil.example"))
            self.assertEqual(self.read(s), b"")
            self.assertEqual(self.socks("dns.google")[1][-1][:2], b"\x05\x02")   # refused: not allowed
            self.assertEqual(self.socks("a!b.example")[1][-1][:2], b"\x05\x01")
        self.assertIn("its TLS server name is 'evil.example', not 'localhost'", err.getvalue())
        self.assertIn("DNS-over-HTTPS endpoint", err.getvalue())
        self.assertEqual(len(self.up.got), 1)
        self.srv.observer.flush(math.inf)
        self.assertEqual([e["host"] for r in self.sent for e in r["effects"]], ["localhost"])

    def test_socks5_and_http_inside_tls_on_the_http_listener(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self_signed(d)
        with open(os.path.join(d, "bearer"), "w") as f:
            f.write("b" * 40)
        self.srv = egress.serve({"http": {"listen": "127.0.0.1:0", "cert": os.path.join(d, "c.pem"),
                                          "key": os.path.join(d, "k.pem"), "authenticators": ["token"],
                                          "token_file": os.path.join(d, "bearer")}, "signer": "unused"}, self.client)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        tls = ssl.create_default_context()
        tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
        s, replies = self.socks("localhost", tls=tls)   # E2B's egressProxy with tls.enabled
        self.assertEqual(replies, [b"\x05\x02", b"\x01\x00", OPENED])
        s.sendall(client_hello("localhost"))
        self.assertEqual(self.read(s), b"pong")
        s = tls.wrap_socket(socket.create_connection(self.srv.server_address[:2], 5))
        s.sendall(f"CONNECT localhost:{self.up.port} HTTP/1.1\r\nProxy-Authorization: {self.auth}\r\n\r\n".encode())
        self.assertTrue(s.recv(65536).startswith(b"HTTP/1.1 200 Connection established"))
        s.close()

    def test_the_peer_uid_is_the_established_socket_with_both_addresses(self):
        rows = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                # the same ports from another address; the right addresses not established; the agent's socket
                "   0: 0200007F:D431 0100007F:0C38 01 00000000:00000000 00:00000000 00000000     0        0 1",
                "   1: 0100007F:D431 0100007F:0C38 06 00000000:00000000 00:00000000 00000000     0        0 2",
                "   2: 0100007F:D431 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1234        0 3"]
        with mock.patch("tracekit.egress.open", mock.mock_open(read_data="\n".join(rows)), create=True):
            self.assertEqual(egress._peer_uid(("127.0.0.1", 54321), ("127.0.0.1", 3128)), 1234)
            self.assertIsNone(egress._peer_uid(("127.0.0.1", 54321), ("127.0.0.1", 3129)))


class TestEndToEnd(Observed):
    def test_the_proxy_reports_to_the_signer(self):
        public(self)
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
        made_up = base64.b64encode(f"{run['run_id']}:made.up".encode()).decode()
        s.sendall(f"CONNECT localhost:{up.port} HTTP/1.1\r\nProxy-Authorization: Basic {made_up}\r\n\r\n".encode())
        self.assertTrue(s.recv(65536).startswith(b"HTTP/1.1 407"))
        self.assertEqual(up.got, [])
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

    def test_a_microsandbox_socks5_connection_is_its_runs_signed_effect(self):
        public(self)
        up = Upstream()
        self.addCleanup(up.sock.close)
        client = types.SimpleNamespace(observe_effect=lambda req: self.s.call(OBSERVER, "observe_effect", req))
        srv = egress.serve({"listen": "127.0.0.1:0", "signer": "unused"}, client)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        srv.observer.flush()
        run, other = self.register(), self.register()
        with mock.patch.object(sys, "stderr", io.StringIO()):
            s, replies = socks5(srv.server_address[:2], "127.0.0.1", up.port, creds=(run["run_id"], other["run_token"]))
        self.assertEqual(replies, [b"\x05\x02", b"\x01\x01"])   # another run's token
        s, replies = socks5(srv.server_address[:2], "127.0.0.1", up.port, creds=(run["run_id"], run["run_token"]))
        self.assertEqual(replies[-1], OPENED)
        s.sendall(client_hello("localhost"))
        while s.recv(65536):
            pass
        s.close()
        time.sleep(0.1)
        srv.observer.flush(math.inf)
        (e,) = self.typed(self.final(run), "effect.observed")
        self.assertEqual({k: e["data"][k] for k in ("host", "port", "bytes_in", "attribution")},
                         {"host": "localhost", "port": up.port, "bytes_in": 4, "attribution": "token"})
        self.assertEqual(e["data"]["observer"], f"{OBSERVER.scheme}:{OBSERVER.subject}")


if __name__ == "__main__":
    unittest.main()
