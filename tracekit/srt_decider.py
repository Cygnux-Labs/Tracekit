"""srt-proxy's request decider: the HTTP proxy of Anthropic's sandbox-runtime, run on its own (`srt-proxy`, `srt
proxy`), asks this process about every request before it forwards it, and the v2 signer's policy decides each one, in
one run. docs/integrations/sandbox-runtime.md.

    tracekit srt-decider --allow-domain api.example.com [--allow-domain HOST ...] [--agent NAME] \\
        -- srt-proxy --listen 127.0.0.1:3128 --ca-fd 3 3<ca.pem

It registers the run, starts the command with one end of a socket pair added as `--decider-fd`, and speaks srt's
decider protocol version 1 on it (sandbox-runtime's docs/srt-proxy.md: a 4-byte big-endian length, then one JSON
object; srt-proxy speaks first and waits 5 s for each verdict). The hello's allowedDomains are the --allow-domain hosts:
srt-proxy refuses every other host itself, without asking. It exits with the command's exit code and closes the run;
the command stops when this process does, since srt-proxy forwards nothing without its decider.

Each request is decided as the tool `srt:request` (class http) with {"method", "url"} and, for a request other than a
GET, HEAD or OPTIONS whose headers announce a body, "body": "sha256:<hex>" of the body, which srt-proxy sends when
asked (need_body; a body over MAX_BODY is refused). The URL is https:// when the request came with a TLS server name,
else http:// (the frame has no scheme). allow: forwarded, and completed with a result saying Tracekit doesn't see the
response; deny: 403 naming the rules; ask: an approval is requested and the request refused, and the same request
(method, URL, body) sent again once a person approved it is allowed, once. A signer that can't be reached: 503,
whatever the run's fail mode; any other failure: refused.
"""
import argparse
import base64
import collections
import concurrent.futures
import hashlib
import json
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

from tracekit.format.canon import canonical
from tracekit.sdk.client import Client, SignerUnavailable, named_rules
from tracekit.signer.rpc_schema import RPCError

PROTO = 1
TOOL = "srt:request"
MAX_BODY = 32 << 20   # the most body srt-proxy shows a decider (need_body's max)
MAX_FRAME = MAX_BODY * 4 // 3 + (1 << 20)   # a body frame: MAX_BODY as base64, with its envelope
BODYLESS = ("GET", "HEAD", "OPTIONS")   # srt-proxy refuses need_body for these when they carry a body
BODY_WAIT_S = 360   # srt-proxy closes a tunnel 300 to 360 s after its request last moved
WORKERS = 32
RESULT = ("srt-proxy was answered allow: it forwards the request unless its own checks refuse it or the answer came "
          "after its 5 s wait; Tracekit does not see the response")
CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")   # srt-proxy refuses a reason holding one (tab aside)


def deny(status, reason):
    """A deny verdict as srt-proxy takes it: a reason of 1 to 1024 UTF-8 bytes, no control characters."""
    return {"action": "deny", "status": status,
            "reason": CONTROL.sub(" ", reason).encode(errors="replace")[:1024].decode(errors="ignore")}


class Decider:
    """Answers srt-proxy's frames on `sock`, deciding in `run` (a RunHandle)."""

    def __init__(self, sock, run, allowed):
        self.sock, self.run, self.allowed = sock, run, list(dict.fromkeys(allowed))
        self.rfile, self.wlock, self.lock = sock.makefile("rb"), threading.Lock(), threading.Lock()
        # request id -> (its request frame, when its body stops being waited for), oldest first: no worker waits for a
        # body, so slow uploads never hold the requests after them
        self.bodies = collections.OrderedDict()
        # lean: asks waiting for a person live in this process's memory, so a restarted decider asks again; keep them
        # in the signer (approval_list by run) if deciders restart while people decide
        self.held = {}     # canonical args -> (tool_call_id, approval_id)

    def send(self, msg):
        frame = json.dumps(msg, separators=(",", ":")).encode()
        with self.wlock:
            self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def read(self):
        """The next frame's object, or None once srt-proxy closed the stream; ValueError for a malformed frame."""
        head = self.rfile.read(4)
        if len(head) < 4:
            return None
        n = struct.unpack(">I", head)[0]
        if n > MAX_FRAME:
            raise ValueError(f"a {n}-byte frame")
        data = self.rfile.read(n)
        if len(data) < n:
            return None
        msg = json.loads(data)   # not JSON, not UTF-8: a ValueError
        if not isinstance(msg, dict):
            raise ValueError("a frame that is not a JSON object")
        return msg

    def serve(self):
        """Until srt-proxy closes the stream. ValueError: it broke the protocol, or speaks another version."""
        hello = self.read()
        if hello != {"t": "hello", "proto": PROTO}:
            raise ValueError(f"its hello is {hello!r}, not decider protocol version {PROTO}")
        self.send({"t": "hello", "proto": PROTO, "allowedDomains": self.allowed, "deniedDomains": []})
        pool = concurrent.futures.ThreadPoolExecutor(WORKERS, thread_name_prefix="tracekit-srt")
        try:
            while (msg := self.read()) is not None:
                self.expire()
                if msg.get("t") == "req":
                    pool.submit(self.answer, msg)
                elif msg.get("t") != "body":
                    raise ValueError(f"a {msg.get('t')!r} frame")
                else:   # its request is decided now; a body no one waits for any more (BODY_WAIT_S) is dropped
                    with self.lock:
                        waiting = self.bodies.pop(msg.get("id"), None)
                    if waiting:
                        pool.submit(self.answer, waiting[0], msg)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def expire(self):
        """Refuse each request whose body didn't come within BODY_WAIT_S."""
        now, late = time.monotonic(), []
        with self.lock:
            while self.bodies and next(iter(self.bodies.values()))[1] < now:
                late.append(self.bodies.popitem(last=False)[0])
        for rid in late:
            try:
                self.send({"t": "verdict", "id": rid, **deny(408, "Tracekit: the request's body did not arrive")})
            except OSError:
                pass

    def answer(self, req, body=None):
        """Send the verdict for request frame `req` (with `body`, its body frame), unless its body is asked for."""
        closed = False
        try:
            verdict = self.decide(req, body)
            if verdict is None:   # answered once its body comes (serve)
                return
        except SignerUnavailable as e:
            verdict = deny(503, f"Tracekit: the signer can't be reached, so nothing is allowed: {e}")
        except RPCError as e:
            verdict, closed = deny(403, f"Tracekit: the signer refused the request: {e}"), e.code == "run_closed"
        except (KeyError, TypeError, ValueError) as e:   # a request frame this decider can't read
            verdict = deny(400, f"Tracekit can't read the request ({e!r})")
        try:
            self.send({"t": "verdict", "id": req["id"], **verdict})
            if closed:   # nothing more can be recorded: srt-proxy stops once its decider's stream ends
                print(f"tracekit srt-decider: the signer closed run {self.run.run_id} (idle_s without a request); "
                      "stopping srt-proxy", file=sys.stderr, flush=True)
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:   # srt-proxy is gone
            pass

    def decide(self, req, body=None):
        """The verdict for one request frame, or None once its body is asked for."""
        method, host, port = req["method"], req["host"], req["port"]
        if not req["path"].startswith("/"):   # absolute-form or `*`: glued to the host, it would name another
            return deny(400, f"Tracekit decides an origin-form request target (/path) only, not {req['path'][:200]!r}")
        scheme = "https" if "sni" in req else "http"
        netloc = f"[{host}]" if ":" in host else host
        netloc += "" if port == {"https": 443, "http": 80}[scheme] else f":{port}"
        args = {"method": method,
                "url": f"{scheme}://{netloc}{req['path']}" + (f"?{req['query']}" if "query" in req else "")}
        headers = req.get("headers", {})
        if method not in BODYLESS and ("transfer-encoding" in headers or headers.get("content-length", ["0"]) != ["0"]):
            if body is None:
                with self.lock:
                    self.bodies[req["id"]] = req, time.monotonic() + BODY_WAIT_S
                self.send({"t": "verdict", "id": req["id"], "action": "need_body", "max": MAX_BODY})
                return None
            if body.get("cut"):
                return deny(413, f"Tracekit: a body over {MAX_BODY} bytes can't be bound to a decision")
            args["body"] = "sha256:" + hashlib.sha256(base64.b64decode(body["data"], validate=True)).hexdigest()
        key = canonical(args)
        with self.lock:
            held = self.held.get(key)
        if held is None:
            tcid = f"srt-{uuid.uuid4().hex}"
            d = self.run.decide(tcid, TOOL, args, tool_class_hint="http")
            if d.get("unavailable"):   # denied whatever the run's fail mode says
                return deny(503, f"Tracekit: {d['reason']}")
            if d["decision"] == "deny":
                return deny(403, f"Tracekit {named_rules(d['rule_ids']) or 'deny'}: {d.get('reason') or 'denied'}")
            if d["decision"] == "allow":
                self.run.complete(tcid, "ok", result=RESULT)
                return {"action": "allow"}
            held = tcid, self.run.call("approval_request", tool_call_id=tcid)["approval_id"]
            with self.lock:
                self.held[key] = held
            print(f"[tracekit] {method} {host}: waiting for approval {held[1]} ({named_rules(d['rule_ids'])})",
                  file=sys.stderr, flush=True)
        tcid, aid = held
        state = self.run.call("approval_wait", approval_id=aid, timeout_ms=0)["state"]
        if state == "requested":
            return deny(403, f"Tracekit: held for a person's approval ({aid}); send the same request again once it is "
                             "approved")
        with self.lock:
            self.held.pop(key, None)
        if state != "approved":
            return deny(403, f"Tracekit: approval {aid} was {state}")
        c = self.run.approval_consume(tcid, TOOL, args, approval_id_hint=aid)
        if not c["ok"]:
            return deny(403, f"Tracekit {named_rules(c['rule_ids'])}: {c.get('reason') or 'not approved'}")
        self.run.complete(tcid, "ok", result=RESULT)
        return {"action": "allow"}



def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit srt-decider",
                                 description="Decide and sign every request srt-proxy asks about, in one run.")
    ap.add_argument("--allow-domain", action="append", required=True, metavar="HOST",
                    help="a host srt-proxy may ask about (repeat; `*.example.com` for its subdomains); it refuses "
                         "every other host itself, unrecorded")
    ap.add_argument("--agent", default="srt-proxy", help="the run's agent name (default: srt-proxy)")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- srt-proxy and its flags; --decider-fd is added")
    a = ap.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        ap.error("give the srt-proxy command after --")
    try:
        run = Client().run(a.agent)
    except (SignerUnavailable, RPCError) as e:
        print(f"tracekit srt-decider: no run to record in, so srt-proxy is not started: {e}", file=sys.stderr)
        return 2
    ours, theirs = socket.socketpair()
    theirs.set_inheritable(True)
    try:   # close_fds=False: srt-proxy also gets the descriptors its own flags name (--ca-fd 3 3<ca.pem)
        proc = subprocess.Popen([*cmd, "--decider-fd", str(theirs.fileno())], close_fds=False)
    except OSError as e:
        print(f"tracekit srt-decider: {cmd[0]}: {e}", file=sys.stderr)
        proc = None
    theirs.close()
    if proc:
        print(f"tracekit srt-decider: run {run.run_id} decides srt-proxy's requests", file=sys.stderr, flush=True)
        signal.signal(signal.SIGTERM, signal.default_int_handler)
        try:
            Decider(ours, run, a.allow_domain).serve()
        except (ValueError, OSError) as e:
            print(f"tracekit srt-decider: stopping srt-proxy: {e}", file=sys.stderr)
        except KeyboardInterrupt:
            pass
    ours.close()   # srt-proxy refuses whatever is pending and exits once its decider's stream ends
    if proc:
        try:
            code = proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
    try:
        run.close()
    except (SignerUnavailable, RPCError) as e:
        print(f"tracekit srt-decider: run {run.run_id} not closed: {e}", file=sys.stderr)
    return code if proc else 2
