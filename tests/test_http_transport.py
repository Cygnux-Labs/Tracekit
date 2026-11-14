"""The signer over HTTPS (tracekit/transport/http.py, sdk/client.py https://): config checks, body size and read
timeouts, per-op authorization, errors as HTTP statuses and request ids, the client's retries, and the cross-tenant
matrix (E12 core) for k8s_sa and mtls identities."""
import http.client
import http.server
import json
import os
import re
import socket
import ssl
import time
import unittest
import uuid
from unittest import mock

import test_gateway as tg
import test_signer_service as ts
from cryptography import x509
from test_identity_k8s import AUD, Jwks, claims, jwt
from test_identity_mtls import Pki, echo, post, serve, tmpdir
from tracekit import gateway
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import Client, SignerUnavailable, _Https
from tracekit.signer import pipeline, service as svc
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import ERROR_CODES, REQUESTS, RPCError
from tracekit.storage.base import StorageUnavailable
from tracekit.storage.file import FileStorage
from tracekit.transport import answering_hello, hello
from tracekit.transport import http as tk_http


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.pki = Pki(self.d)
        self.cert, self.key = self.pki.issue("server")

    def test_tls_required_except_explicit_insecure_loopback(self):
        tk_http.configure({"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                           "token_file": self.secret()})
        for cfg in ({"listen": "0.0.0.0:8443", "insecure_loopback": True},
                    {"listen": "127.0.0.1:8443"},
                    {"listen": "127.0.0.1:8443", "insecure_loopback": True, "cert": self.cert},
                    {"listen": "127.0.0.1:8443", "insecure_loopback": True, "authenticators": ["mtls"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["mtls"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["oidc"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["k8s_sa"],
                     "k8s_sa": {"audience": AUD, "jwks_uri": "https://x", "issuer": "i", "extra": 1}},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["token"],
                     "colour": "blue"}):
            with self.subTest(cfg), self.assertRaises(ValueError):
                tk_http.configure({"authenticators": ["token"], "token_file": self.secret(), **cfg})

    def secret(self):
        path = os.path.join(self.d, "bearer")
        with open(path, "w") as f:
            f.write("s" * 40)
        return path

    def test_load_config_resolves_paths_and_refuses_unknown_keys(self):
        path = os.path.join(self.d, "signer.yaml")
        with open(path, "w") as f:
            f.write(f"data_dir: data\nhttp:\n  listen: 127.0.0.1:8443\n  cert: {os.path.basename(self.cert)}\n"
                    f"  key: {os.path.basename(self.key)}\n  authenticators: [token]\n  token_file: bearer\n")
        self.secret()
        self.assertEqual(svc.load_config(path)["http"]["cert"], self.cert)
        with open(path, "a") as f:
            f.write("  port: 1\n")
        with self.assertRaises(ValueError):
            svc.load_config(path)


class TestLimits(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.pki = Pki(d)
        cert, key = self.pki.issue("server")
        token = os.path.join(d, "bearer")
        with open(token, "w") as f:
            f.write("t" * 40)
        self.port = serve(self, {"cert": cert, "key": key, "authenticators": ["token"], "token_file": token}, echo,
                          read_timeout=0.3)
        self.ctx = ssl.create_default_context(cafile=self.pki.path)

    def tls(self):
        s = self.ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.port), 5), server_hostname="127.0.0.1")
        self.addCleanup(s.close)
        return s

    @staticmethod
    def response(sock):
        r = http.client.HTTPResponse(sock)
        r.begin()
        return r

    def test_bearer_token_and_keep_alive(self):
        s = self.tls()
        for _ in range(2):   # two requests on one connection
            s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + b"t" * 40 +
                      b"\r\nContent-Length: 17\r\n\r\n{\"method\":\"ping\"}")
            self.assertEqual(self.response(s).read(), b'{"scheme":"token","subject":"http"}')
        self.assertEqual(post(self.port, {"method": "x"}, self.ctx, {"Authorization": "Bearer wrong"})[1]["error"]["code"],
                         "unauthenticated")

    def test_oversize_body_is_refused(self):
        s = self.tls()
        s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (MAX_LINE + 1))
        r = self.response(s)
        self.assertEqual(r.status, 413)
        self.assertIn(b"quota_exceeded", r.read())

    def test_malformed_content_length_is_refused(self):
        for n in (b"\xb2", b"1" * 9, b"9" * 5000):
            s = self.tls()
            s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nContent-Length: " + n + b"\r\n\r\n")
            r = self.response(s)
            self.assertEqual(r.status, 400, n[:9])
            self.assertIn(b"invalid_request", r.read())

    def test_slow_client_is_cut_off(self):
        for partial in (b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\n", b"POST /v2/rpc HTTP/1.1\r\nContent-Length: 50\r\n\r\n{"):
            s = self.tls()
            s.sendall(partial)
            t = time.monotonic()
            self.assertEqual(s.recv(65536), b"")   # closed by the server after its read timeout
            self.assertLess(time.monotonic() - t, 3)


class TestClientUrls(unittest.TestCase):
    """The Python client on the signer's plain-HTTP loopback listener (insecure_loopback), and on a TLS certificate it
    can't verify."""

    def setUp(self):
        self.d = tmpdir(self)
        self.token = os.path.join(self.d, "bearer")
        with open(self.token, "w") as f:
            f.write("t" * 40)
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, authorize={"token:http": ["status"]})
        self.addCleanup(self.s.close)
        self.handle = answering_hello(self.s.handle_frame, hello())

    def client(self, url, **env):
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN_FILE": self.token, **env}):
            c = Client(url, timeout=5)
        self.addCleanup(c.close)
        return c

    def subject(self, c):
        return c.status({})["identity"]["subject"]

    def test_plain_http_on_a_loopback_address_only(self):
        port = serve(self, {"insecure_loopback": True, "authenticators": ["token"], "token_file": self.token},
                     self.handle)
        self.assertEqual(self.subject(self.client(f"http://127.0.0.1:{port}")), "http")
        with self.assertRaisesRegex(SignerUnavailable, "must be on a loopback address"):
            self.client("http://192.0.2.1:8080").status({})

    def test_plain_http_never_leaves_its_loopback_address(self):
        """A run id's replica route (`127-5.`) would name host 127-5.0.0.1 off loopback, the token in clear."""
        h = _Https("http://127.0.0.1:8080")
        self.assertEqual([h._host({"run_id": "127-5.ab"}), h._host({"approval_id": "127-0.ab"})],
                         ["127.0.0.1", "127.0.0.1"])
        self.assertEqual(_Https("https://127.0.0.1:8443")._host({"run_id": "127-5.ab"}), "127-5.0.0.1")   # TLS: routed

    def test_an_api_key_is_the_token_and_a_token_file_wins_over_it(self):
        port = serve(self, {"insecure_loopback": True, "authenticators": ["token"], "token_file": self.token},
                     self.handle)
        url, wrong = f"http://127.0.0.1:{port}", os.path.join(self.d, "wrong")
        with open(wrong, "w") as f:
            f.write("w" * 40)
        sent = mock.patch.object(http.client.HTTPConnection, "request", autospec=True,
                                 side_effect=http.client.HTTPConnection.request)
        with mock.patch.dict(os.environ, {"TRACEKIT_API_KEY": " " + "t" * 40 + "\n"}), sent as request:
            os.environ.pop("TRACEKIT_SIGNER_TOKEN_FILE", None)
            key_only = Client(url, timeout=5)
            argument = Client(url, timeout=5, token_file=wrong)   # an argument wins over the environment
            file_env = self.client(url, TRACEKIT_SIGNER_TOKEN_FILE=wrong)   # the file wins over the key
            self.addCleanup(key_only.close)
            self.addCleanup(argument.close)
            self.assertEqual(self.subject(key_only), "http")
            for c in (file_env, argument):
                with self.assertRaises(RPCError) as cm:
                    c.status({})
                self.assertEqual(cm.exception.code, "unauthenticated")
            os.environ["TRACEKIT_API_KEY"] = "w" * 40   # read per call, as the token file is
            with self.assertRaises(RPCError) as cm:
                key_only.status({})
            self.assertEqual(cm.exception.code, "unauthenticated")
            self.assertEqual(self.subject(self.client(url)), "http")   # the file's token, not the key's
        # the SDK reads errors from the body: it never asks for statuses a proxy in front would act on
        self.assertTrue(request.call_args_list)
        self.assertEqual([c for c in request.call_args_list if "Tracekit-Errors" in c.args[4]], [])

    def test_a_certificate_that_does_not_verify_is_named(self):
        pki = Pki(self.d)
        cert, key = pki.issue("server")
        port = serve(self, {"cert": cert, "key": key, "authenticators": ["token"], "token_file": self.token},
                     self.handle)
        with self.assertRaisesRegex(SignerUnavailable, "certificate of the signer at https://127.0.0.1:[0-9]+ did "
                                                       "not verify .*set TRACEKIT_SIGNER_CA"):
            self.client(f"https://127.0.0.1:{port}").status({})
        self.assertEqual(self.subject(self.client(f"https://127.0.0.1:{port}", TRACEKIT_SIGNER_CA=pki.path)), "http")


TOKEN = "t" * 40
AUTH, ASK = {"Authorization": "Bearer " + TOKEN}, {"Tracekit-Errors": "http-status"}
# the status a client that asks (ASK) gets for each error code; the body is the error frame either way
STATUSES = {"invalid_request": 400, "unauthenticated": 401, "forbidden": 403, "run_token_invalid": 403,
            "unknown_run": 404, "unknown_tool_call": 404, "unknown_decision": 404, "unknown_approval": 404,
            "unknown_incident": 404, "run_exists": 409, "run_closed": 409, "conflict": 409, "client_seq_reused": 409,
            "args_mismatch": 409, "approval_not_pending": 409, "quota_exceeded": 429, "unavailable": 503}


def raw(port, body, headers, path="/v2/rpc"):
    """(status, headers, body) of one request to a plain-HTTP loopback signer, as any HTTP client sends it; `body` None:
    a GET."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request("GET" if body is None else "POST", path, body, headers)
        r = c.getresponse()
        return r.status, r.headers, r.read()
    finally:
        c.close()


class TestStatuses(unittest.TestCase):
    """An error frame comes with its HTTP status to a client that asks for it (ASK: curl and other HTTP clients), and
    with 200 to any other, the SDKs included, as before; a decision (allow, deny, ask) is an answer, 200 either way.
    Every answer has a Request-Id."""

    def setUp(self):
        token = os.path.join(tmpdir(self), "bearer")
        with open(token, "w") as f:
            f.write(TOKEN)
        self.cfg = {"insecure_loopback": True, "authenticators": ["token"], "token_file": token}
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, authorize={
            "token:http": ["status", "register_run", "decide", "approval_get"]})
        self.addCleanup(self.s.close)

    def test_each_error_code_is_its_status_to_a_client_that_asks_and_200_to_any_other(self):
        def refuse(identity, frame):
            raise RPCError(frame["code"], "refused", frame.get("retry_after_ms"))
        port = serve(self, self.cfg, refuse)
        self.assertEqual(set(STATUSES), set(ERROR_CODES))
        for code, status in STATUSES.items():
            body = json.dumps({"method": "x", "code": code, **(
                {"retry_after_ms": 1500} if code in ("quota_exceeded", "unavailable") else {})})
            with self.subTest(code):
                asked, old = raw(port, body, {**AUTH, **ASK}), raw(port, body, AUTH)
                self.assertEqual((asked[0], old[0]), (status, 200))
                self.assertEqual(asked[2], old[2])
                self.assertEqual(json.loads(asked[2])["error"], {"code": code, "message": "refused", **(
                    {"retry_after_ms": 1500} if status in (429, 503) else {})})
                self.assertEqual(asked[1]["Retry-After"], "2" if status in (429, 503) else None)
                self.assertEqual(asked[1]["WWW-Authenticate"], "Bearer" if status == 401 else None)
                self.assertIsNone(old[1]["Retry-After"])
        # a size limit (no retry_after_ms): the same request never fits, so no 429 that tells a client to send it again
        size = raw(port, json.dumps({"method": "x", "code": "quota_exceeded"}), {**AUTH, **ASK})
        self.assertEqual((size[0], size[1]["Retry-After"]), (413, None))

    def test_a_signer_answers_refusals_with_their_status_and_decisions_with_200(self):
        port = serve(self, self.cfg, answering_hello(self.s.handle_frame, hello()))

        def call(frame, headers=None):
            status, _, body = raw(port, frame if isinstance(frame, bytes) else json.dumps(frame),
                                  headers or {**AUTH, **ASK})
            return status, json.loads(body)
        status, reg = call({"method": "register_run", "request_id": "r1", "agent": {"name": "a"}})
        self.assertEqual(status, 200)
        ev = {"method": "decide", "run_id": reg["run_id"], "run_token": reg["run_token"], "stream": "s",
              "tool": "pay", "args_source": "parsed", "args": {"amount": 5}}
        for want, code, frame, headers in [
                (400, "invalid_request", b"{not json", None),
                (400, "invalid_request", {"method": "decide"}, None),
                (401, "unauthenticated", {"method": "status"}, {"Authorization": "Bearer " + "w" * 40, **ASK}),
                (403, "forbidden", {"method": "incident_list"}, None),
                (403, "run_token_invalid", {**ev, "request_id": "d0", "client_seq": 0, "tool_call_id": "c0",
                                            "run_token": reg["run_token"] + "x"}, None),
                (404, "unknown_approval", {"method": "approval_get", "approval_id": "apr-none"}, None),
                (409, "conflict", {"method": "register_run", "request_id": "r1", "agent": {"name": "b"}}, None)]:
            with self.subTest(code):
                status, out = call(frame, headers)
                self.assertEqual((status, out["error"]["code"]), (want, code))
                self.assertEqual(call(frame, {k: v for k, v in (headers or AUTH).items() if k not in ASK}), (200, out))
        status, ask = call({**ev, "request_id": "d1", "client_seq": 0, "tool_call_id": "c1"})
        self.assertEqual((status, ask["decision"]), (200, "ask"))
        status, deny = call({**ev, "request_id": "d2", "client_seq": 1, "tool_call_id": "c2", "args_source": "raw",
                             "args": "{"})
        self.assertEqual((status, deny["decision"], deny["rule_ids"]), (200, "deny", ["TK-ARGS-INVALID"]))

    def test_an_old_style_client_still_gets_200_and_reads_the_error_from_the_body(self):
        """A client that doesn't ask (every SDK, which reads the body whatever the status) gets what it always got."""
        port = serve(self, self.cfg, answering_hello(self.s.handle_frame, hello()))
        status, headers, body = raw(port, json.dumps({"method": "approval_get", "approval_id": "apr-none"}), AUTH)
        self.assertEqual((status, json.loads(body)["error"]["code"]), (200, "unknown_approval"))
        self.assertEqual(headers["Connection"], None)   # kept alive, as before
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN_FILE": self.cfg["token_file"]}):
            c = Client(f"http://127.0.0.1:{port}", timeout=5)
        self.addCleanup(c.close)
        with self.assertRaises(RPCError) as cm:
            c.approval_get({"approval_id": "apr-none"})
        self.assertEqual(cm.exception.code, "unknown_approval")
        self.assertEqual(c.status({})["identity"]["subject"], "http")

    def test_every_answer_has_a_request_id_of_its_own_which_the_log_names(self):
        port = serve(self, self.cfg, answering_hello(self.s.handle_frame, hello()))
        with self.assertLogs("tracekit.transport.http", "INFO") as logs:
            answers = [raw(port, json.dumps({"method": "status"}), AUTH),
                       raw(port, json.dumps({"method": "status"}), ASK),
                       raw(port, b"{", AUTH),
                       raw(port, b"{}", AUTH, path="/v2/other"),
                       raw(port, None, AUTH)]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            self.addCleanup(c.close)
            c.putrequest("POST", "/v2/rpc")
            c.putheader("Content-Length", str(MAX_LINE + 1))
            c.endheaders()
            r = c.getresponse()
            answers.append((r.status, r.headers, r.read()))
        self.assertEqual([a[0] for a in answers], [200, 401, 200, 404, 501, 413])
        ids = [a[1]["Request-Id"] for a in answers]
        self.assertTrue(all(re.fullmatch(r"req_[0-9a-f]{24}", i or "") for i in ids), ids)
        self.assertEqual(len(set(ids)), len(ids))
        for i, line in zip(ids, logs.output):
            self.assertIn(i, line)
        self.assertRegex(logs.output[0], r" 200 status 'token:http' - \d+ms$")
        self.assertRegex(logs.output[1], r" 401 status - unauthenticated \d+ms$")
        self.assertRegex(logs.output[2], r" 200 - - invalid_request \d+ms$")


class Flaky(FileStorage):
    """File storage that fails the append of the next batch holding an event `fail[0](event)` picks, as a disk error
    does: before writing it ("before"), or after ("after", an fsync error: the signer can't tell whether it is on
    disk)."""
    fail = (None, None)

    def append_batch(self, records):
        pick, when = self.fail
        if pick and any(pick(r["event"]) for r in records):
            self.fail = (None, None)
            if when == "before":
                raise StorageUnavailable("No space left on device")
            super().append_batch(records)
            raise StorageUnavailable("fsync failed")
        super().append_batch(records)


class TestRetries(unittest.TestCase):
    """The Python client sends an event call (decide, complete, observe, state_write, model_event) again, with its
    request_id and client_seq, after a rate limit or an outage, and the signer records it once; any other call is not
    sent again."""
    EVENTS = {"decide": "policy.decision", "complete": "tool.result", "observe": "input.observed",
              "state_write": "state.write", "model_event": "model.exchange"}

    def setUp(self):
        token = os.path.join(tmpdir(self), "bearer")
        with open(token, "w") as f:
            f.write(TOKEN)
        self.d = ts.tmpdir(self)
        self.s = svc.SignerService(self.d, policy=ts.PAY_ASKS, authorize={"token:http": [
            "register_run", "close_run", "status", *self.EVENTS]}, gateways=["token:http"],
            fail_modes={"default": "closed", "model": "open"},
            open_storage=lambda: Flaky(os.path.join(self.d, "store")))
        self.addCleanup(self.s.close)
        port = serve(self, {"insecure_loopback": True, "authenticators": ["token"], "token_file": token},
                     answering_hello(self.s.handle_frame, hello()))
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_TOKEN_FILE": token}):
            self.c = Client(f"http://127.0.0.1:{port}", timeout=10)
        self.addCleanup(self.c.close)
        recover = mock.patch.object(pipeline, "RECOVER_S", 0.05)   # an outage's retry_after_ms, and its recovery
        recover.start()
        self.addCleanup(recover.stop)

    def event(self, method):
        """A `method` request in a run of its own (a decided call first, for a complete)."""
        run = self.c.run("a")
        req = {"request_id": uuid.uuid4().hex, "run_id": run.run_id, "run_token": run.run_token}
        if method == "complete":
            d = run.decide("c1", "Bash", {"command": "ls"})
            return {**req, "tool_call_id": "c1", "decision_id": d["decision_id"], "status": "ok",
                    "args_digest": event_hash({"tool": "Bash", "args": {"command": "ls"}})}
        return {**req, **{
            "decide": {"tool_call_id": "c1", "tool": "Bash", "args_source": "parsed", "args": {"command": "ls"}},
            "observe": {"value": "a mail", "source": "mail", "trust": "untrusted"},
            "state_write": {"key": "k", "value_digest": "sha256:" + "0" * 64},
            "model_event": {"provider": "openai", "model": "m", "phase": "request"}}[method]}

    def refuse_once(self, retry_after_ms=5):
        """The signer's rate limit refuses the next call, as it does before writing anything; -> each charge."""
        real, charges = self.s.quotas.take_event, []

        def take(*a):
            charges.append(a)
            if len(charges) == 1:
                raise RPCError("quota_exceeded", "event rate limit", retry_after_ms=retry_after_ms)
            return real(*a)
        patch = mock.patch.object(self.s.quotas, "take_event", take)
        patch.start()
        self.addCleanup(patch.stop)
        return charges

    def recorded(self, req):
        return [r["event"] for r in ts.records(self.d) if r["event"].get("request_id") == req["request_id"]]

    def fail_write(self, req, when):
        """The disk fails the batch holding `req`'s record (Flaky)."""
        self.s.log.storage.fail = (lambda e: e.get("request_id") == req["request_id"], when)

    def test_an_event_call_refused_by_the_rate_limit_is_sent_again_and_recorded_once(self):
        for method, typ in self.EVENTS.items():
            with self.subTest(method):
                req = self.event(method)
                charges = self.refuse_once()
                self.assertIn("run_seq", self.c.call(method, req))
                self.assertEqual(len(charges), 2)
                self.assertEqual([(e["type"], e["client_seq"]) for e in self.recorded(req)], [(typ, mock.ANY)])
                gaps = [r["event"] for r in ts.records(self.d) if r["event"]["type"] == "capture.gap"
                        and r["event"]["run_id"] == req["run_id"]]
                self.assertEqual(gaps, [])   # the same client_seq: no client_counter_gap

    def test_an_event_call_the_disk_refused_is_sent_again_and_recorded_once(self):
        for method, typ in self.EVENTS.items():
            with self.subTest(method):
                req = self.event(method)
                self.fail_write(req, "before")
                self.assertIn("run_seq", self.c.call(method, req))
                self.assertEqual([e["type"] for e in self.recorded(req)], [typ])

    def test_an_event_call_written_before_the_disk_failed_is_never_recorded_twice(self):
        """The signer answered unavailable without knowing the record was on disk: the retry's client_seq is refused
        (client_seq_reused), even though the signer's request_id cache forgot the try, and the caller gets the first
        try's unavailable, as it did before retries: its outage path (a fail mode), never a refusal."""
        for method, typ in self.EVENTS.items():
            with self.subTest(method):
                req = self.event(method)
                self.fail_write(req, "after")
                with self.assertRaises(RPCError) as cm:
                    self.c.call(method, req)
                self.assertEqual(cm.exception.code, "unavailable")
                self.assertIn("fsync failed", cm.exception.message)
                self.assertEqual([e["type"] for e in self.recorded(req)], [typ])
        self.s.close()
        self.assertEqual(svc.fsck(self.d), [])

    def test_a_gateway_takes_its_fail_mode_when_a_written_record_is_answered_unavailable(self):
        """The LLM gateway, the signer's client through the SDK: an exchange record written though the signer answered
        unavailable is the gateway's outage path, so a model call the run's fail mode leaves open goes to the
        provider, as before retries; never "the signer refused the run" (403)."""
        d = tmpdir(self)
        up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), tg.Upstream)
        up.seen, up.reply, up.delay = [], ("json", tg.COMPLETION), 0
        for name, text in (("provider.key", "provider-key\n"), ("bearer", tg.SECRET)):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        with open(os.path.join(d, "gateway.yaml"), "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "upstream": f"http://127.0.0.1:{tg.serve(self, up)}",
                       "api_key_file": "provider.key", "signer": "unused", "max_body": 4096}, f)
        port = tg.serve(self, gateway.serve(gateway.load_config(os.path.join(d, "gateway.yaml")), self.c))
        run = self.c.run("a")

        def post():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            self.addCleanup(c.close)
            c.request("POST", "/v1/chat/completions", json.dumps({"model": "gpt-x", "messages": []}),
                      {"Authorization": "Bearer " + tg.SECRET, "X-Tracekit-Run": f"{run.run_id}.{run.run_token}"})
            r = c.getresponse()
            return r.status, r.read()
        self.assertEqual(post()[0], 200)   # the signer answered for the run: the gateway knows its fail modes
        self.s.log.storage.fail = (lambda e: e["type"] == "model.exchange", "after")
        status, body = post()
        self.assertEqual(status, 200, body)
        self.assertEqual(len(up.seen), 2)
        exchanges = [e["data"]["phase"] for e in (r["event"] for r in ts.records(self.d))
                     if e["type"] == "model.exchange" and e["run_id"] == run.run_id]
        self.assertEqual(exchanges, ["request", "response"] * 2)   # each once

    def test_no_other_call_is_sent_again(self):
        """Other calls' request_ids are kept in memory only, and lost with a batch whose write failed: a retry could
        record them twice. A size limit (quota_exceeded without retry_after_ms) is never sent again either."""
        run, req = self.c.run("a"), self.event("decide")
        for method, fields, retry_after_ms in [("register_run", {"agent": {"name": "b"}}, 5),
                                               ("close_run", {"run_id": run.run_id, "run_token": run.run_token}, 5),
                                               ("decide", req, None)]:
            with self.subTest(method):
                charges = self.refuse_once(retry_after_ms)
                with self.assertRaises(RPCError) as cm:
                    self.c.call(method, {"request_id": uuid.uuid4().hex, **fields})
                self.assertEqual((cm.exception.code, len(charges)), ("quota_exceeded", 1))
        rid = uuid.uuid4().hex
        self.fail_write({"request_id": rid}, "before")
        with self.assertRaises(RPCError) as cm:
            self.c.call("register_run", {"request_id": rid, "agent": {"name": "c"}})
        self.assertEqual(cm.exception.code, "unavailable")
        self.assertEqual(self.recorded({"request_id": rid}), [])


class TestAuthorization(unittest.TestCase):
    def setUp(self):
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, authorize={
            "mtls:spiffe://example.org/a": ["status"], "k8s_sa:system:serviceaccount:acme:*": ["status", "register_run"]})
        self.addCleanup(self.s.close)

    def forbidden(self, identity, method, req):
        with self.assertRaises(RPCError) as cm:
            self.s.call(identity, method, req)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_unconfigured_methods_and_identities_are_denied(self):
        a = CallerIdentity("mtls", "spiffe://example.org/a", True)
        self.s.call(a, "status", {})
        self.forbidden(a, "register_run", {"request_id": "r", "agent": {"name": "x"}})
        self.forbidden(CallerIdentity("mtls", "spiffe://example.org/b", True), "status", {})
        sa = CallerIdentity("k8s_sa", "system:serviceaccount:acme:agent", True)
        self.s.call(sa, "register_run", {"request_id": "r", "agent": {"name": "x"}})
        self.forbidden(sa, "close_run", {"request_id": "r2", "run_id": "x", "run_token": "x.y"})
        self.forbidden(CallerIdentity("token", "http", True), "status", {})
        self.s.call(ts.OTHER, "status", {})   # a uid keeps every method

    def test_tenant_map_takes_prefixes(self):
        self.s.tenants.update({"k8s_sa:system:serviceaccount:acme:*": "acme", "mtls:spiffe://example.org/*": "org",
                               "mtls:spiffe://example.org/x/*": "x"})
        reg = self.s.call(CallerIdentity("k8s_sa", "system:serviceaccount:acme:agent", True), "register_run",
                          {"request_id": "r", "agent": {"name": "x"}})
        self.assertEqual((reg["tenant"], reg["tenant_attested"]), ("acme", True))
        self.assertEqual(svc.lookup(self.s.tenants, "mtls:spiffe://example.org/x/a"), "x")   # longest prefix
        self.assertIsNone(svc.lookup(self.s.tenants, "k8s_sa:system:serviceaccount:acmex:a"))

    def test_prefix_keys_end_at_a_separator(self):
        table = {"uid:100*": "a", "acme*": "b", "uid:*": "c"}
        self.assertEqual(svc.lookup(table, "uid:1000"), "c")
        self.assertIsNone(svc.lookup(table, "acme-evil"))
        d = tmpdir(self)
        path = os.path.join(d, "signer.yaml")
        for table in ("authorize:\n  uid:100*: [status]\n", "tenants:\n  a*b/*: x\n",
                      "approvals:\n  approvers: [acme*]\n"):
            with open(path, "w") as f:
                f.write("data_dir: data\n" + table)
            with self.subTest(table), self.assertRaisesRegex(ValueError, "end in :\\* or /\\*"):
                svc.load_config(path)


class TestCrossTenant(unittest.TestCase):
    """E12 core: an identity of tenant b cannot read, approve, list, complete or close tenant a's runs or approvals."""

    def setUp(self):
        d = tmpdir(self)
        self.pki = Pki(d)
        self.jwks = Jwks(self, self.pki)
        all_methods = sorted(REQUESTS.keys() - {"content_get", "export_run"} - svc.OPERATOR)
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, tenants={
            "k8s_sa:system:serviceaccount:a:*": "a", "k8s_sa:system:serviceaccount:b:*": "b",
            "mtls:spiffe://example.org/a/*": "a", "mtls:spiffe://example.org/b/*": "b"},
            authorize={"k8s_sa:system:serviceaccount:*": all_methods, "mtls:spiffe://example.org/*": all_methods})
        self.addCleanup(self.s.close)
        cert, key = self.pki.issue("server")
        port = serve(self, {"cert": cert, "key": key, "client_ca": {"example.org": self.pki.path},
                            "authenticators": ["k8s_sa", "mtls"],
                            "k8s_sa": self.jwks.config(self.pki)}, answering_hello(self.s.handle_frame, hello()))
        self.url, self.d = f"https://127.0.0.1:{port}", d

    def client(self, scheme, tenant):
        env = {"TRACEKIT_SIGNER_CA": self.pki.path}
        if scheme == "k8s_sa":
            env["TRACEKIT_SIGNER_TOKEN_FILE"] = path = os.path.join(self.d, f"token-{tenant}")
            with open(path, "w") as f:
                f.write(jwt(self.jwks.ec, claims(sub=f"system:serviceaccount:{tenant}:agent")))
        else:
            env["TRACEKIT_SIGNER_CERT"], env["TRACEKIT_SIGNER_KEY"] = self.pki.issue(
                f"client-{tenant}", [x509.UniformResourceIdentifier(f"spiffe://example.org/{tenant}/agent")])
        with mock.patch.dict(os.environ, env):
            c = Client(self.url, timeout=5)
        self.addCleanup(c.close)
        return c

    def test_matrix(self):
        for scheme in ("k8s_sa", "mtls"):
            with self.subTest(scheme):
                a, b = self.client(scheme, "a"), self.client(scheme, "b")
                run = a.run("agent")
                self.assertEqual((run.registered["tenant"], run.registered["tenant_attested"]), ("a", True))
                self.assertEqual(b.status()["identity"]["scheme"], scheme)
                d = run.decide("tc-1", "pay", {"amount": 5})
                self.assertEqual(d["decision"], "ask")
                aid = run.call("approval_request", tool_call_id="tc-1")["approval_id"]
                self.assertIn(aid, [x["approval_id"] for x in a.approval_list()["approvals"]])
                theirs = {"run_id": run.run_id, "run_token": run.run_token}
                for code, method, req in [
                        ("run_token_invalid", "read", theirs),
                        ("run_token_invalid", "complete", {**theirs, "tool_call_id": "tc-1", "status": "ok",
                                                           "decision_id": d["decision_id"],
                                                           "args_digest": "sha256:" + "0" * 64}),
                        ("run_token_invalid", "close_run", theirs),
                        ("run_token_invalid", "approval_wait", {**theirs, "approval_id": aid}),
                        ("unknown_approval", "approval_get", {"approval_id": aid}),
                        ("unknown_approval", "approval_decide", {"approval_id": aid, "decision": "approve"})]:
                    with self.assertRaises(RPCError, msg=method) as cm:
                        b.call(method, req)
                    self.assertEqual(cm.exception.code, code, method)
                self.assertEqual(b.approval_list()["approvals"], [])
                self.assertEqual(a.approval_get({"approval_id": aid})["state"], "requested")
                run.close()


if __name__ == "__main__":
    unittest.main()
