"""Phase 2 tests: transcript tamper detection (C2), model proxy (C3), proxy<->hook cross-check (C4),
stale runs (C5), YAML policy (C7), approvals (C8), redaction (C9).

    python3 -m unittest tests.test_capture -v
"""
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, install, policy, privacy, yamlmini  # noqa: E402
from tracekit.core import read_json, read_text, write_bytes, write_json, write_text  # noqa: E402

_SAVED_POLICY = None


def setUpModule():
    # never inherit a policy path from another suite or the shell
    global _SAVED_POLICY
    _SAVED_POLICY = os.environ.pop("TRACEKIT_POLICY", None)


def tearDownModule():
    if _SAVED_POLICY is not None:
        os.environ["TRACEKIT_POLICY"] = _SAVED_POLICY


PY = sys.executable


def free_port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


class Stack(unittest.TestCase):
    """A dev signer (real daemon process) and helpers to fire hooks at it."""
    checkpoint_every = 50
    extra_cfg = {}

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = dict(os.environ, TRACEKIT_CLIENT_HOME=os.path.join(self.d, "client"), PYTHONPATH=ROOT)
        self.env.pop("TRACEKIT_POLICY", None)
        self.home = os.path.join(self.d, "signer")
        os.environ["TRACEKIT_CLIENT_HOME"] = self.env["TRACEKIT_CLIENT_HOME"]
        install.init_dev(self.home, [f"file:{self.d}/w.jsonl"], self.checkpoint_every, start=False)
        cfg = read_json(os.path.join(self.home, "config.json"))
        cfg.update(self.extra_cfg)
        write_json(os.path.join(self.home, "config.json"), cfg)
        install.start_dev_daemon(self.home)
        self.proj = os.path.join(self.d, "proj"); os.makedirs(self.proj)
        self.transcript = os.path.join(self.d, "transcript.jsonl")
        self.run_id = "run-" + os.path.basename(self.d)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        os.environ.pop("TRACEKIT_CLIENT_HOME", None)

    def hook(self, name, extra=None, env=None, transcript=True, wait=True):
        p = {"hook_event_name": name, "session_id": self.run_id, "cwd": self.proj, **(extra or {})}
        if transcript:
            p["transcript_path"] = self.transcript
        args = dict(input=json.dumps(p), capture_output=True, text=True, env=env or self.env, timeout=60)
        r = subprocess.run([PY, "-m", "tracekit.hook"], **args)
        return r.returncode, r.stderr

    def pre(self, tid, cmd, **kw):
        return self.hook("PreToolUse", {"tool_name": "Bash", "tool_use_id": tid, "tool_input": {"command": cmd}}, **kw)

    def post(self, tid, cmd, out="ok", **kw):
        return self.hook("PostToolUse", {"tool_name": "Bash", "tool_use_id": tid, "tool_input": {"command": cmd},
                                         "tool_response": {"stdout": out}}, **kw)

    def say(self, text):
        with open(self.transcript, "a") as f:
            f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}) + "\n")

    def events(self):
        out = []
        for l in read_text(os.path.join(self.home, "ledger", "ledger.jsonl")).splitlines():
            if l.strip():
                out.append(json.loads(l)["event"])
        return out

    def of(self, typ, **match):
        return [e for e in self.events() if e["type"] == typ and all(e["data"].get(k) == v for k, v in match.items())]


class TranscriptTamper(Stack):
    """C2: deleting, emptying, truncating and selectively editing the transcript mid-session."""

    def start(self):
        self.say("I will fix the test.")
        self.hook("SessionStart")
        self.say("Running pytest.")
        self.pre("t1", "pytest -q")
        self.post("t1", "pytest -q")

    def test_clean_session_has_no_tamper(self):
        self.start()
        self.say("Done.")
        self.hook("SessionEnd")
        self.assertEqual(self.of("trace.tamper"), [])
        marks = [e for e in self.events() if e.get("transcript")]
        self.assertGreaterEqual(len(marks), 4)

    def test_selective_edit_detected(self):
        self.start()
        data = read_text(self.transcript).replace("Running pytest.", "Running lint..")  # same length, different bytes
        write_text(self.transcript, data)
        self.say("Done.")
        self.pre("t2", "ls")
        t = self.of("trace.tamper")
        self.assertEqual([x["data"]["kind"] for x in t], ["edited"])
        self.assertEqual(t[0]["data"]["path"], self.transcript)

    def test_truncation_detected(self):
        self.start()
        lines = read_text(self.transcript).splitlines(True)
        write_text(self.transcript, "".join(lines[:1]))
        self.pre("t2", "ls")
        self.assertEqual([x["data"]["kind"] for x in self.of("trace.tamper")], ["truncated"])

    def test_emptying_detected(self):
        self.start()
        write_text(self.transcript, "")
        self.pre("t2", "ls")
        self.assertEqual([x["data"]["kind"] for x in self.of("trace.tamper")], ["truncated"])

    def test_deletion_detected(self):
        self.start()
        os.remove(self.transcript)
        self.pre("t2", "ls")
        t = self.of("trace.tamper")
        self.assertEqual([x["data"]["kind"] for x in t], ["deleted"])
        self.assertIsNone(t[0]["data"]["after"]["length"])

    def test_rewrite_then_regrow_detected_once(self):
        self.start()
        os.remove(self.transcript)
        self.say("fresh file, as Claude Code recreates it")
        self.pre("t2", "ls")
        self.say("more")
        self.pre("t3", "ls")
        self.assertEqual(len(self.of("trace.tamper")), 1)

    def test_bundle_reports_tampering(self):
        self.start()
        os.remove(self.transcript)
        self.pre("t2", "ls")
        self.hook("SessionEnd")
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out)
        rep, code = bundle.verify(out, [f"file:{self.d}/w.jsonl"])
        chk = {c["check"]: c for c in rep.checks}
        self.assertEqual(chk["harness transcript unchanged"]["status"], "warn")
        self.assertIn("TRACE TAMPERING DETECTED", chk["harness transcript unchanged"]["detail"])
        self.assertEqual(code, 0)  # the bundle itself is intact
        self.assertEqual(bundle.verify(out, [f"file:{self.d}/w.jsonl"], strict=True)[1], 3)

    def test_parallel_hooks_do_not_false_alarm(self):
        self.start()
        procs = []
        for i in range(6):
            self.say(f"parallel {i}")
            p = {"hook_event_name": "PreToolUse", "session_id": self.run_id, "cwd": self.proj, "transcript_path": self.transcript,
                 "tool_name": "Bash", "tool_use_id": f"p{i}", "tool_input": {"command": "ls"}}
            procs.append(subprocess.Popen([PY, "-m", "tracekit.hook"], stdin=subprocess.PIPE, env=self.env,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))  # noqa: SIM115
            procs[-1].stdin.write(json.dumps(p).encode()); procs[-1].stdin.close()
        for p in procs:
            p.wait(30)
        self.pre("t9", "ls")
        self.assertEqual(self.of("trace.tamper"), [])


# ---------------------------------------------------------------- proxy
class FakeAnthropic(http.server.BaseHTTPRequestHandler):
    """Streams an SSE response that asks for one tool call; can also fail on demand."""
    protocol_version = "HTTP/1.1"
    tool_id = "toolu_fake_1"
    mode = "tool"
    delay = 0.3

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        self.rfile.read(n)
        if FakeAnthropic.mode == "429":
            body = b'{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}'
            self.send_response(429); self.send_header("content-type", "application/json")
            self.send_header("retry-after", "7"); self.send_header("content-length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        tid = FakeAnthropic.tool_id
        evs = [{"type": "message_start", "message": {"id": "msg_1", "content": []}},
               {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
               {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Let me run it. key sk-ant-abcdefghijklmnopqrstuvwxyz"}}]
        if FakeAnthropic.mode == "tool":
            evs += [{"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": tid, "name": "Bash", "input": {}}},
                    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"command\":\"ls\"}"}}]
        evs += [{"type": "message_delta", "delta": {"stop_reason": "tool_use" if FakeAnthropic.mode == "tool" else "end_turn"}},
                {"type": "message_stop"}]
        for i, ev in enumerate(evs):
            chunk = f"event: {ev['type']}\ndata: {json.dumps(ev)}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk)); self.wfile.flush()
            if i == 0:
                time.sleep(FakeAnthropic.delay)
        self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class SSEScanBounds(unittest.TestCase):
    def test_compressed_request_expansion_is_bounded(self):
        import gzip
        import zlib
        from tracekit import proxy
        original_limit = proxy.MAX_REQUEST_SIZE
        proxy.MAX_REQUEST_SIZE = 1024
        try:
            payload = b"x" * 2048
            self.assertIsNone(proxy._decode(zlib.compress(payload), "deflate"))
            self.assertIsNone(proxy._decode(gzip.compress(payload), "gzip"))
        finally:
            proxy.MAX_REQUEST_SIZE = original_limit

    def test_malformed_json_shapes_are_ignored(self):
        from tracekit.proxy import SSEScan, tool_results_sent
        scan = SSEScan()
        scan.feed(b"data: []\ndata: {\"type\":\"content_block_start\",\"content_block\":[]}\n")
        scan.json_message({"content": "not-a-list"})
        self.assertEqual(scan.tool_uses, [])
        self.assertEqual(tool_results_sent([]), [])
        self.assertEqual(tool_results_sent({"messages": "not-a-list"}), [])

    def test_oversized_line_is_discarded_and_parser_recovers(self):
        from tracekit.proxy import MAX_SSE_LINE, SSEScan
        scan = SSEScan()
        scan.feed(b"x" * (MAX_SSE_LINE + 1))
        self.assertEqual(scan.buf, b"")
        self.assertTrue(scan.discarding_line)
        event = json.dumps({"type": "content_block_start", "content_block": {"type": "tool_use", "id": "t1", "name": "Bash"}}).encode()
        scan.feed(b"\n" + b"data: " + event + b"\n")
        self.assertEqual(scan.tool_uses, [{"id": "t1", "name": "Bash"}])

    def test_tool_use_tracking_is_bounded(self):
        from tracekit.proxy import MAX_TOOL_USES, SSEScan
        scan = SSEScan()
        events = [json.dumps({"type": "content_block_start", "content_block": {"type": "tool_use", "id": str(i)}}).encode()
                  for i in range(MAX_TOOL_USES + 20)]
        scan.feed(b"\n".join(b"data: " + event for event in events) + b"\n")
        self.assertEqual(len(scan.tool_uses), MAX_TOOL_USES)

    def test_tool_result_tracking_is_bounded(self):
        from tracekit.proxy import tool_results_sent
        content = [{"type": "tool_result", "tool_use_id": str(i)} for i in range(1000)]
        out = tool_results_sent({"messages": [{"role": "user", "content": content}]})
        self.assertEqual(len(out), 200)

    def test_copied_identifiers_are_bounded(self):
        from tracekit.proxy import SSEScan
        identifier = "x" * 10000
        scan = SSEScan()
        scan.json_message({"content": [{"type": "tool_use", "id": identifier}]})
        self.assertEqual(len(scan.tool_uses[0]["id"]), 500)

    def test_proxy_rejects_connections_when_worker_limit_is_reached(self):
        from tracekit.proxy import Handler, MAX_CONCURRENT_REQUESTS, Server

        class FakeSocket:
            def __init__(self):
                self.sent = b""

            def sendall(self, data):
                self.sent += data

            def shutdown(self, _how):
                pass

            def close(self):
                pass

        server = Server(("127.0.0.1", 0), Handler)
        acquired = 0
        try:
            for _ in range(MAX_CONCURRENT_REQUESTS):
                self.assertTrue(server._request_slots.acquire(blocking=False))
                acquired += 1
            request = FakeSocket()
            server.process_request(request, ("127.0.0.1", 1))
            self.assertIn(b"503 Service Unavailable", request.sent)
        finally:
            for _ in range(acquired):
                server._request_slots.release()
            server.server_close()


class ProxyStack(Stack):
    extra_cfg = {"crosscheck_grace_s": 1}
    fail_mode = "open"

    def setUp(self):
        FakeAnthropic.mode, FakeAnthropic.tool_id = "tool", "toolu_fake_1"
        self.up_port, self.px_port = free_port(), free_port()
        self.up = TS(("127.0.0.1", self.up_port), FakeAnthropic)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.extra_cfg = dict(self.extra_cfg, proxy={"port": self.px_port, "upstream": f"http://127.0.0.1:{self.up_port}",
                                                     "fail_mode": self.fail_mode})
        super().setUp()
        cc = read_json(os.path.join(self.env["TRACEKIT_CLIENT_HOME"], "config.json"))
        cc.update(proxy=True, proxy_url=f"http://127.0.0.1:{self.px_port}")
        write_json(os.path.join(self.env["TRACEKIT_CLIENT_HOME"], "config.json"), cc)
        penv = dict(self.env, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        penv.pop("TRACEKIT_CLIENT_HOME")
        self.px = subprocess.Popen([PY, "-m", "tracekit.proxy", "--home", self.home], env=penv,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.px_port}/__tracekit_health", timeout=1); break
            except Exception:
                time.sleep(0.05)

    def tearDown(self):
        self.px.terminate(); self.px.wait(5)
        self.up.shutdown()
        self.up.server_close()
        super().tearDown()

    def call_model(self, session=None):
        body = json.dumps({"model": "claude-test", "stream": True, "messages": [{"role": "user", "content": "hi"}],
                           "metadata": {"user_id": json.dumps({"session_id": session or self.run_id})}}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.px_port}/v1/messages?beta=true", data=body, method="POST",
                                     headers={"content-type": "application/json", "x-api-key": "sk-ant-secretsecretsecret00",
                                              "X-Claude-Code-Session-Id": session or self.run_id})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        t0 = time.perf_counter()
        r = opener.open(req, timeout=30)
        first = r.read1(4096)
        t_first = time.perf_counter() - t0
        rest = r.read()
        return r.status, first + rest, t_first, time.perf_counter() - t0

    def wait_for(self, fn, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(0.2)
        return fn()


class Proxy(ProxyStack):
    def test_oversized_request_body_is_rejected(self):
        from tracekit.proxy import MAX_REQUEST_SIZE
        with socket.create_connection(("127.0.0.1", self.px_port), timeout=3) as conn:
            conn.sendall((f"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {MAX_REQUEST_SIZE + 1}\r\n\r\n").encode())
            response = conn.recv(4096)
        self.assertIn(b"413", response)

    def test_upstream_connect_error_has_valid_content_length_framing(self):
        self.up.shutdown()
        self.up.server_close()
        with socket.create_connection(("127.0.0.1", self.px_port), timeout=3) as conn:
            conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}")
            chunks = []
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
        length = int(next(line.split(b":", 1)[1] for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")))
        self.assertIn(b"502", head.split(b"\r\n", 1)[0])
        self.assertEqual(len(body), length)

    def test_streams_records_and_redacts(self):
        status, body, t_first, total = self.call_model()
        self.assertEqual(status, 200)
        self.assertIn(b"toolu_fake_1", body)
        self.assertLess(t_first, total - 0.2, "first chunk must arrive before the upstream finished (streaming)")
        ex = self.wait_for(lambda: self.of("model.exchange", phase="response"))
        d = ex[0]["data"]
        self.assertEqual(d["tool_uses"], [{"id": "toolu_fake_1", "name": "Bash"}])
        self.assertEqual(d["stop_reason"], "tool_use")
        self.assertTrue(d["response"]["redacted"])   # the sk-ant key in the stream was redacted before hashing
        self.assertIn("hash", d["response"])
        req = self.of("model.exchange", phase="request")[0]
        self.assertLess(req["seq"], ex[0]["seq"])      # recorded before the response
        self.assertEqual(req["run_id"], self.run_id)   # attributed via X-Claude-Code-Session-Id
        raw = read_text(os.path.join(self.home, "ledger", "ledger.jsonl"))
        self.assertNotIn("secretsecretsecret", raw)    # auth headers are never recorded
        self.assertIsNotNone(d["added_latency_ms"])

    def test_errors_pass_through_unchanged(self):
        FakeAnthropic.mode = "429"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://127.0.0.1:{self.px_port}/v1/messages", data=b'{"model":"m"}', method="POST",
                                     headers={"content-type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(req, timeout=10)
        self.assertEqual(cm.exception.code, 429)
        self.assertEqual(cm.exception.headers.get("retry-after"), "7")
        self.assertIn(b"rate_limit_error", cm.exception.read())
        self.assertEqual(self.wait_for(lambda: self.of("model.exchange", phase="response"))[0]["data"]["status"], 429)

    def test_crosscheck_clean(self):
        self.hook("SessionStart")
        self.call_model()
        self.wait_for(lambda: self.of("model.exchange", phase="response"))
        self.pre("toolu_fake_1", "ls"); self.post("toolu_fake_1", "ls")
        FakeAnthropic.mode = "text"
        self.call_model()
        self.wait_for(lambda: len(self.of("model.exchange", phase="response")) == 2)
        self.hook("SessionEnd")
        time.sleep(2.5)
        self.assertEqual([g for g in self.of("capture.gap") if g["data"].get("kind") in ("hook_missing", "proxy_missing")], [])
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out)
        rep, code = bundle.verify(out, [f"file:{self.d}/w.jsonl"])
        chk = {c["check"]: c for c in rep.checks}
        self.assertEqual(chk["capture sources"]["status"], "pass", chk["capture sources"])
        self.assertIn("proxy", chk["capture sources"]["detail"])

    def test_hooks_disabled_mid_session_detected(self):
        self.hook("SessionStart")
        self.call_model()   # model asks for toolu_fake_1 ...
        # ... but the hook never fires (hooks removed / disableAllHooks)
        gaps = self.wait_for(lambda: self.of("capture.gap", kind="hook_missing"))
        self.assertTrue(gaps)
        self.assertEqual(gaps[0]["data"]["tool_use_id"], "toolu_fake_1")
        self.assertEqual(gaps[0]["run_id"], self.run_id)

    def test_proxy_bypass_detected(self):
        self.hook("SessionStart")   # run.start declares capture_sources [hook, proxy]
        # agent unsets ANTHROPIC_BASE_URL: model traffic skips the proxy, hooks still fire
        self.pre("toolu_direct_9", "ls"); self.post("toolu_direct_9", "ls")
        self.hook("SessionEnd")
        gaps = self.wait_for(lambda: self.of("capture.gap", kind="proxy_missing"))
        self.assertEqual(gaps[0]["data"]["tool_use_id"], "toolu_direct_9")


class ProxyFailClosed(ProxyStack):
    fail_mode = "closed"

    def test_signer_down_blocks(self):
        install.stop_dev_daemon.__wrapped__ if hasattr(install.stop_dev_daemon, "__wrapped__") else None
        # stop only the signer, keep the proxy
        install._stop_pidfile(os.path.join(self.home, "tracekitd.pid"))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://127.0.0.1:{self.px_port}/v1/messages", data=b'{"model":"m","stream":true}',
                                     method="POST", headers={"content-type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(req, timeout=10)
        self.assertEqual(cm.exception.code, 503)
        self.assertIn(b"fail_mode=closed", cm.exception.read())


class ProxyFailOpen(ProxyStack):
    fail_mode = "open"

    def test_signer_down_forwards_and_records_gap(self):
        install._stop_pidfile(os.path.join(self.home, "tracekitd.pid"))
        status, body, _, _ = self.call_model()
        self.assertEqual(status, 200)
        install.start_dev_daemon(self.home)
        FakeAnthropic.mode = "text"
        self.call_model()
        gaps = self.wait_for(lambda: [g for g in self.of("capture.gap") if g["data"].get("kind") == "signer_down"])
        self.assertTrue(gaps)
        self.assertEqual(gaps[0]["source"], "proxy")
        self.assertEqual(gaps[0]["data"]["missed_events"], 2)


class StaleRun(Stack):
    extra_cfg = {"stale_after_s": 1}

    def test_run_without_run_end_is_flagged(self):
        self.hook("SessionStart")
        self.pre("t1", "ls")
        gaps = []
        end = time.time() + 12
        while time.time() < end and not gaps:
            time.sleep(0.5)
            gaps = self.of("capture.gap", kind="stale_run")
        self.assertTrue(gaps)
        self.assertEqual(gaps[0]["run_id"], self.run_id)


# ---------------------------------------------------------------- approvals
class Approvals(Stack):
    def setUp(self):
        super().setUp()
        self.pol = os.path.join(self.d, "ask.yaml")
        with open(self.pol, "w") as f:
            f.write("extends: default\napproval_timeout_s: 20\nask:\n  - id: TK-A900\n    tool: Bash\n"
                    "    pattern: '\\bgit\\s+push\\b'\n    reason: pushing\n")
        self.env["TRACEKIT_POLICY"] = self.pol
        # a stand-in "harness" process (the hook's parent) whose name isn't a shell or python
        self.bin = os.path.join(self.d, "bin"); os.makedirs(self.bin)
        self.harness = os.path.join(self.bin, "fakeharness")
        os.symlink(PY, self.harness)

    HARNESS = """
import json, os, subprocess, sys, time
payload = sys.stdin.read()
hook = subprocess.Popen([sys.argv[1], '-m', 'tracekit.hook'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
hook.stdin.write(payload); hook.stdin.close()
ctl = sys.argv[2]
while hook.poll() is None:
    # the 'agent' may run commands inside its own session while the call is held
    for name in sorted(os.listdir(ctl)):
        if name.endswith('.cmd'):
            cmd = open(os.path.join(ctl, name)).read(); os.remove(os.path.join(ctl, name))
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            open(os.path.join(ctl, name[:-4] + '.out'), 'w').write(r.stdout + r.stderr)
    time.sleep(0.1)
sys.stderr.write(hook.stderr.read()); sys.exit(hook.returncode)
"""

    def start_held_call(self, tid="tp1"):
        p = {"hook_event_name": "PreToolUse", "session_id": self.run_id, "cwd": self.proj, "tool_name": "Bash",
             "tool_use_id": tid, "tool_input": {"command": "git push origin main"}}
        self.ctl = os.path.join(self.d, "ctl-" + tid); os.makedirs(self.ctl, exist_ok=True)
        hp = os.path.join(self.d, "harness.py"); write_text(hp, self.HARNESS)
        proc = subprocess.Popen([self.harness, hp, PY, self.ctl], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env, text=True)
        proc.stdin.write(json.dumps(p)); proc.stdin.close()
        self.addCleanup(self._reap, proc)
        return proc

    @staticmethod
    def _reap(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(10)
        for f in (proc.stdout, proc.stderr):
            if f:
                f.close()

    def in_session(self, cmd, name="a"):
        """Run a shell command as a child of the harness (i.e. from inside the agent's session)."""
        write_text(os.path.join(self.ctl, name + ".cmd"), cmd)
        out = os.path.join(self.ctl, name + ".out")
        end = time.time() + 30
        while not os.path.exists(out) and time.time() < end:
            time.sleep(0.1)
        time.sleep(0.2)
        return read_text(out)

    def pending(self):
        from tracekit import client
        return client.rpc({"op": "approval_list"})["pending"]

    def wait_pending(self):
        end = time.time() + 10
        while time.time() < end:
            p = self.pending()
            if p:
                return p
            time.sleep(0.1)
        self.fail("no pending approval")

    def approve_from_terminal(self, aid, decision="approve"):
        """Run `tracekit approve` in a fresh pseudo-terminal, outside the harness's process tree."""
        if not shutil.which("script"):
            self.skipTest("needs `script` for a pty")
        cmd = f"{PY} -m tracekit {decision} {aid}"
        return subprocess.run(["script", "-qec", cmd, "/dev/null"], capture_output=True, text=True, env=self.env, timeout=30)

    def test_action_held_until_approved(self):
        proc = self.start_held_call()
        p = self.wait_pending()
        time.sleep(1.0)
        self.assertIsNone(proc.poll(), "the tool call must not proceed before approval")
        r = self.approve_from_terminal(p[0]["id"])
        self.assertIn("ok: approve", r.stdout + r.stderr)
        self.assertEqual(proc.wait(20), 0)
        ap = self.of("approval", decision="approve")
        self.assertEqual(ap[0]["data"]["tool_use_id"], "tp1")
        self.assertIn("tty=", ap[0]["data"]["channel"])
        # dev mode: allowed, but labelled as untrustworthy in the record
        if hasattr(socket, "SO_PEERCRED"):
            self.assertTrue(ap[0]["data"]["same_user"])
            self.assertIn("not trustworthy", ap[0]["data"]["channel"])
        else:
            self.assertIsNone(ap[0]["data"]["same_user"])
            self.assertIn("peer identity unavailable", ap[0]["data"]["channel"])
        dec = self.of("policy.decision", decision="ask")
        self.assertLess(dec[0]["seq"], ap[0]["seq"])

    def test_reject(self):
        proc = self.start_held_call()
        p = self.wait_pending()
        self.approve_from_terminal(p[0]["id"], "reject")
        self.assertEqual(proc.wait(20), 2)
        self.assertIn("not approved", proc.stderr.read())

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "requires OS peer process credentials")
    def test_self_approval_from_inside_the_session_fails(self):
        proc = self.start_held_call()
        p = self.wait_pending()
        # the agent tries to approve itself from inside its own session ...
        out1 = self.in_session(f"{PY} -m tracekit approve {p[0]['id']}", "a")
        self.assertIn("refused", out1)
        # ... even from a fresh pseudo-terminal inside the session
        out2 = self.in_session(f"script -qec '{PY} -m tracekit approve {p[0]['id']}' /dev/null", "b")
        self.assertIn("refused", out2)
        self.assertIsNone(proc.poll())
        self.assertEqual(len(self.of("approval", decision="self_approval_refused")), 2)
        self.approve_from_terminal(p[0]["id"], "reject")
        proc.wait(20)

    def test_no_tty_is_refused(self):
        proc = self.start_held_call()
        p = self.wait_pending()
        r = subprocess.run([PY, "-m", "tracekit", "approve", p[0]["id"]], capture_output=True, text=True, env=self.env,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertIn("interactive terminal", r.stderr)
        self.approve_from_terminal(p[0]["id"], "reject")
        proc.wait(20)

    def test_timeout_rejects(self):
        with open(self.pol, "a") as f:
            pass
        txt = read_text(self.pol).replace("approval_timeout_s: 20", "approval_timeout_s: 2")
        write_text(self.pol, txt)
        proc = self.start_held_call()
        self.assertEqual(proc.wait(30), 2)
        self.assertTrue(self.of("approval", decision="timeout"))


class ApprovalsSystemMode(Approvals):
    """Outside dev mode an approval from the agent's own OS user is refused however it is started:
    process-tree and terminal checks can be sidestepped by the agent, the OS user cannot."""
    extra_cfg = {"mode": "system", "allow_same_user_approval": False}

    def test_same_user_approval_from_a_fresh_terminal_is_refused(self):
        proc = self.start_held_call()
        p = self.wait_pending()
        r = self.approve_from_terminal(p[0]["id"])  # a new pty, outside the harness's process tree
        self.assertIn("different OS user", r.stdout + r.stderr)
        self.assertIsNone(proc.poll(), "the held call must still be waiting")
        refused = self.of("approval", decision="self_approval_refused")
        self.assertTrue(refused and refused[0]["data"]["same_user"])
        self.assertFalse(self.of("approval", decision="approve"))
        proc.kill(); proc.wait(10)

    # the dev-mode tests do not apply here
    test_action_held_until_approved = test_reject = test_self_approval_from_inside_the_session_fails = None
    test_no_tty_is_refused = test_timeout_rejects = None


class ApprovalIdentity(unittest.TestCase):
    """The signer's approval rule, driven directly with chosen peer credentials."""

    def signer(self, **cfg):
        from tracekit.daemon import Signer, load_config
        home = tempfile.mkdtemp()
        write_json(os.path.join(home, "config.json"), {"checkpoint_every": 100, "witnesses": [], **cfg})
        return Signer(home, load_config(home))

    def request(self, s, agent_uid):
        r = s.handle({"op": "approval_request", "run_id": "r", "tool_use_id": "t", "timeout_s": 30}, agent_uid, 999999)
        return r["approval_id"]

    def test_default_requires_a_different_user(self):
        s = self.signer()
        aid = self.request(s, 1000)
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, 1000, 999998)
        self.assertFalse(r["ok"]); self.assertIn("different OS user", r["error"])
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, None, None)
        self.assertFalse(r["ok"]); self.assertIn("cannot identify", r["error"])
        own_uid = os.getuid() if hasattr(os, "getuid") else 1000
        other_uid = own_uid if own_uid != 1000 else 0
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, other_uid, 999997)
        self.assertTrue(r["ok"]); self.assertFalse(r["same_user"])

    def test_configured_approvers(self):
        s = self.signer(approvers=["4242"])
        aid = self.request(s, 1000)
        self.assertFalse(s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, 1001, 1)["ok"])
        self.assertTrue(s.handle({"op": "approve", "approval_id": aid, "decision": "reject"}, 4242, 1)["ok"])

    def test_invalid_approval_timeouts_are_rejected(self):
        s = self.signer()
        for timeout in (float("nan"), float("inf"), -1, "not-a-number"):
            response = s.handle({"op": "approval_request", "run_id": "r", "tool_use_id": str(timeout),
                                 "timeout_s": timeout}, 1000, 1)
            self.assertFalse(response["ok"])
            self.assertIn("finite positive", response["error"])
        self.assertEqual(s.approvals, {})

    def test_unknown_peer_cannot_send_proxy_events(self):
        s = self.signer()
        r = s.handle({"op": "append", "cseq": 0, "event": {"run_id": "r", "agent_id": "main", "parent_id": None, "source": "proxy",
                                                           "type": "model.exchange", "data": {"exchange_id": "x", "phase": "request",
                                                                                              "streamed": False}}}, None, None)
        self.assertFalse(r["ok"])


class PolicyProvenance(Stack):
    def test_policy_change_during_run_is_bound_and_reported(self):
        self.hook("SessionStart")
        self.pre("t1", "ls")
        other = os.path.join(self.d, "other.yaml")
        with open(other, "w") as f:
            f.write("extends: default\nversion: 'changed-mid-run'\n")
        env = dict(self.env, TRACEKIT_POLICY=other)
        self.pre("t2", "ls", env=env)
        self.hook("SessionEnd")
        decs = self.of("policy.decision")
        self.assertEqual(len({d["data"]["policy_hash"] for d in decs}), 2)
        self.assertEqual(decs[1]["data"]["policy_version"], "changed-mid-run")
        self.assertFalse(self.of("capture.gap", kind="policy_unrecorded"))
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out)
        rep, code = bundle.verify(out, [f"file:{self.d}/w.jsonl"])
        chk = {c["check"]: c for c in rep.checks}
        self.assertEqual(chk["policy hash consistent"]["status"], "pass", chk["policy hash consistent"])
        self.assertEqual(chk["policy unchanged during run"]["status"], "warn")
        self.assertEqual(code, 0)


class TrustRoot(Stack):
    def test_unanchored_pinned_and_wrong_key(self):
        import io
        self.hook("SessionStart"); self.pre("t1", "ls"); self.hook("SessionEnd")
        out = os.path.join(self.d, "b.tkb")
        bundle.export(self.home, out)
        rep, code = bundle.verify(out)
        chk = {c["check"]: c for c in rep.checks}
        self.assertEqual(chk["trust root"]["status"], "warn")
        buf = io.StringIO(); bundle.print_report(rep, code, buf)
        self.assertIn("UNANCHORED", buf.getvalue())
        self.assertEqual(bundle.verify(out, strict=True)[1], 3)
        pub = os.path.join(self.home, "ledger", "signer.pub")
        rep, code = bundle.verify(out, trusted_key=pub)
        self.assertEqual({c["check"]: c for c in rep.checks}["trust root"]["status"], "pass")
        from tracekit import crypto
        wrong = os.path.join(self.d, "wrong.pub")
        write_bytes(wrong, crypto.generate()[1])
        rep, code = bundle.verify(out, trusted_key=wrong)
        self.assertEqual(code, 1)


# ---------------------------------------------------------------- policy + redaction
class PolicyYAML(unittest.TestCase):
    def test_parser_matches_pyyaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        for name in os.listdir(os.path.join(ROOT, "tracekit", "policy")):
            t = read_text(os.path.join(ROOT, "tracekit", "policy", name))
            self.assertEqual(yamlmini.loads(t), yaml.safe_load(t), name)

    def test_parser_rejects_unsupported(self):
        for bad in ["a: &x 1", "a: |\n  text", "a:\n\tb: 1", "a: 'open"]:
            with self.assertRaises(yamlmini.YAMLError, msg=bad):
                yamlmini.loads(bad)

    def test_rules(self):
        pol = policy.load()[0]
        cases = {
            "rm -f ~/.claude/projects/-x/abc.jsonl": "deny", ": > ~/.claude/projects/-x/abc.jsonl": "deny",
            "find ~/.claude/projects -name '*.jsonl' -delete": "deny", "sed -i 's/rm/ls/' ~/.claude/projects/-x/a.jsonl": "deny",
            "truncate -s0 ~/.codex/sessions/a.jsonl": "deny", "cat ~/.claude/projects/-x/abc.jsonl": "flag",
            "systemctl stop tracekitd": "deny", "pkill -f tracekit.daemon": "deny",
        }
        for cmd, want in cases.items():
            self.assertEqual(policy.evaluate(pol, "Bash", {"command": cmd})["decision"], want, cmd)
        self.assertEqual(policy.evaluate(pol, "Write", {"file_path": "/home/u/.claude/projects/x/a.jsonl"})["decision"], "deny")
        for cmd, label in {"ls() { echo; }": "shell_shadowing", "alias git='echo'": "shell_shadowing",
                           "export PATH=/tmp/evil:$PATH": "env_tamper", "unset ANTHROPIC_BASE_URL": "env_tamper",
                           "setsid ./clean.sh": "background_spawn", "while true; do rm -f x; sleep 1; done &": "background_spawn"}.items():
            self.assertIn(label, policy.evaluate(pol, "Bash", {"command": cmd})["flags"], cmd)
        self.assertIn("background_spawn", policy.evaluate(pol, "Bash", {"command": "sleep 1", "run_in_background": True})["flags"])

    def test_ask_only_for_interceptable_tools(self):
        strict = policy.load(os.path.join(ROOT, "tracekit", "policy", "strict.yaml"))[0]
        self.assertEqual(strict["fail_mode"], "closed")
        self.assertEqual(policy.evaluate(strict, "Bash", {"command": "git push"})["decision"], "ask")
        self.assertEqual(policy.evaluate(strict, "WebFetch", {"url": "https://x.example"})["decision"], "ask")
        self.assertNotEqual(policy.evaluate(strict, "WebSearch", {"query": "x"})["decision"], "ask")
        self.assertEqual(policy.evaluate(strict, "Bash", {"command": "sudo git push"})["decision"], "deny")  # deny wins

    def test_bad_policies_raise(self):
        d = tempfile.mkdtemp()
        for i, text in enumerate(["deny:\n  - id: X\n    pattern: '('\n", "deny:\n  - pattern: 'x'\n", "fail_mode: maybe\n",
                                  "deny:\n  - id: A\n    pattern: a\n  - id: A\n    pattern: b\n", "bogus_key: 1\n"]):
            p = os.path.join(d, f"p{i}.yaml"); write_text(p, text)
            with self.assertRaises(policy.PolicyError, msg=text):
                policy.load(p)


class Redaction(unittest.TestCase):
    def test_dotenv_values(self):
        out = privacy.content("DB_HOST=db.internal\nDEBUG=1\nexport SESSION=abc123", "full", dotenv=True)
        self.assertNotIn("db.internal", json.dumps(out)); self.assertNotIn("abc123", json.dumps(out))
        self.assertTrue(privacy.mentions_dotenv("cat ./.env.local"))
        self.assertFalse(privacy.mentions_dotenv("cat environment.py"))

    def test_keys_are_redacted_too(self):
        out, hit = privacy.redact({"sk-ant-abcdefghijklmnopqrstuvwx": 1})
        self.assertTrue(hit); self.assertNotIn("sk-ant-abcdefghijklmnop", json.dumps(out))

    def test_more_token_kinds(self):
        for s in ["Authorization: Bearer abcdefghijklmnop123456", "AIza" + "B" * 35, "sk_live_" + "a" * 24, "npm_" + "a" * 36]:
            self.assertTrue(privacy.redact_text(s)[1], s)


if __name__ == "__main__":
    unittest.main()
