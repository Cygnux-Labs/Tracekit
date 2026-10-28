"""LLM gateway (04-design §6, tier T2): an HTTP(S) reverse proxy in front of an OpenAI-compatible upstream that records
every model exchange in the v2 signer as source `gateway`. docs/gateway.md.

    tracekit gateway serve --config gateway.yaml

gateway.yaml:
    http: {listen: 0.0.0.0:8080, cert: tls/gw.pem, key: tls/gw.key, client_ca: {acme.org: tls/acme-ca.pem},
           authenticators: [mtls, k8s_sa, token]}   # the signer's `http` section (tracekit/transport/http.py)
    upstream: https://api.openai.com      # POST /v1/chat/completions, /v1/responses and /v1/messages go here
    api_key_file: secrets/provider.key     # the provider credential: the gateway's own, never the client's
    api_key_header: authorization          # sent as `Bearer <key>`; or x-api-key (Anthropic), sent as is
    signer: https://signer.internal:8443   # the gateway's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client)
    max_body: 33554432                     # request and non-streamed response bodies; 413 / 502 beyond
    provider_tools: {deny: [code_execution, mcp_servers, code_interpreter]}   # tools the provider runs itself
                                           # (as parsers.provider_tools names them; `mcp` covers every mcp:<label>):
                                           # a request declaring a denied one, or with `allow`, one not listed, is
                                           # refused (403): they run mid-response, where no decide can hold them
    show_reasoning: true                   # ask the provider to show the reasoning a request has it do but hides

Every request carries an identity the authenticators accept and its run, `X-Tracekit-Run: <run_id>.<run token>` or
that value as `Authorization: Bearer` (then the identity must come from a client certificate). No identity or run: 401.
The signer checks the run token against that identity (signer.yaml `gateways` lists this gateway): a token of another
run, identity or tenant: 403. Nothing is attributed by address or name. Relative paths are from the config file.

For each exchange: model_event phase request (with the tool results it sends back and, unless the signer last said it
doesn't check them, the digests of the values each may have been recorded as, so the signer can compare it with the
tool.result it signed: `tool_results`, Gateway.results) before forwarding; when the signer answers `refused` (a result
differs and its verify_tool_results is refuse), the request is not forwarded: 403, and the exchange's response is
recorded with that error. With the signer unreachable and the run's model class failing open, the request is
forwarded unchecked. The response
streams through, parsed by tracekit.parsers; model_event phase response (tool uses with args digests, usage, stop
reason, error) is recorded before the chunk with the stream's terminal event, or before any of a non-streamed
response. Tools the provider ran itself are recorded with the digest of their input where the provider returns it
(`executed_by: provider`, tracekit.parsers). An upstream error, a broken stream or one that ends before its terminal
event is recorded with an error and
ends, for the client, in an error (an SSE error event and a cut connection once the headers went out), never a clean
end. Signer unreachable: the run's fail mode for class `model`, as the signer last answered it for this run, token and
identity (closed when it has not): closed answers 503. A signer refusal is an error whatever the fail mode. When the
gateway drops a run from memory (MAX_RUNS) or stops (SIGTERM, Ctrl-C), it tells the signer where the run's stream
ended if its last exchanges never got there (close_run `last_client_seq`; the gateway's identity needs the close_run
grant, and a refusal is logged on stderr), so the signer writes their client_counter_gap.

When the signer's `status` says its content vault is on (signer.yaml `content.retain`; the gateway's identity needs the
`status` grant), each model_event also carries the exchange's `body`: the request as sent, the response as received
(a stream: as assembled), only when it fits max_record_bytes and half a frame and is strict JSON (else no body: the
record keeps the raw bytes' digest, as with the vault off). The signer redacts it, commits to it
and keeps it encrypted (docs/privacy.md).

show_reasoning (on unless false): a request that has the model reason but hides the reasoning is sent amended to show
it (show_reasoning(): Anthropic thinking display, OpenAI Responses reasoning summary), and its request record says so
(`amended`: the JSON pointers of the fields changed, signed as the record's ext.amended); the record's digest and body
are of the request as sent. Nothing else in a request changes, and no request gets reasoning it didn't ask for. A 400 or
422 to an amended request is recorded as that exchange's response and not passed on: the request goes again, as the
client sent it, as a new exchange; once that one succeeds, the model's requests are not amended again (until restart).
"""
import argparse
import collections
import hashlib
import http.client
import http.server
import json
import os
import signal
import sys
import threading
import types
import urllib.error
import urllib.request
import uuid

from tracekit import parsers, yamlmini
from tracekit.client import remote_url_error
from tracekit.format.canon import canonical, loads_strict
from tracekit.identity.base import bearer
from tracekit.netserver import Lines, body_length, read_body
from tracekit.proxy import HOP, MAX_SSE_LINE
from tracekit.sdk.client import Client, SignerUnavailable, VaultBody, fail_open
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import MAX_RESULTS_SENT, RPCError
from tracekit.transport import http as transport

KINDS = {"/v1/chat/completions": "openai:chat", "/v1/responses": "openai:responses", "/v1/messages": "anthropic:messages"}
TERMINAL = {"response.completed", "response.incomplete", "message_stop"}   # chat completions: data: [DONE]
FAILED = {"error", "response.failed"}
DROP = HOP | {"authorization", "x-api-key", "x-tracekit-run", "cookie"}   # never forwarded: the client's credentials
KEYS = {"http", "upstream", "api_key_file", "api_key_header", "signer", "max_body", "provider_tools", "show_reasoning"}
MAX_BODY = 32 * 1024 * 1024
MAX_RUNS = 10_000   # runs remembered (stream, counter, fail modes), least recently used dropped first
MAX_RUN_HEADER = 2048   # X-Tracekit-Run: a run id and its token (well under 1 KB)
# the newest tool results a request's record carries digests of (at most ~200 KB, so a half-frame body still fits); the
# agent controls which those are (it can pad a request with results of its own)
MAX_RESULTS_CHECKED = 512
# bytes of tool results (as JSON) a request's digests are computed over, newest first, past those the run's previous
# request sent too: it bounds the pure-Python canonical JSON done before forwarding (15 MB of numbers took 3.4 s). A
# result past it gets no digests, and the signer signs it as unchecked (capture.gap result_unchecked)
MAX_DIGESTED = MAX_LINE
UPSTREAM_TIMEOUT_S = 600
REJECTED = (400, 422)   # what a server answers a request field it doesn't take (422: FastAPI-based servers)
RETRY = object()   # _forward: the amended request was rejected and recorded; send it again as the client sent it
MAX_UNAMENDABLE = 1024   # (kind, model) pairs whose provider rejected the amendment, not amended again


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):   # a redirect would carry the provider credential to wherever it points
        return None


OPEN = urllib.request.build_opener(_NoRedirect).open


class Gateway:
    def __init__(self, upstream, api_key, api_key_header="authorization", client=None, max_body=MAX_BODY,
                 provider_tools=None, show_reasoning=True):
        self.upstream, self.max_body, self.client = upstream.rstrip("/"), max_body, client
        self.provider_tools, self.show_reasoning, self.unamendable = provider_tools or {}, show_reasoning, set()
        self.auth = (api_key_header, "Bearer " + api_key if api_key_header == "authorization" else api_key)
        self.runs, self.lock = collections.OrderedDict(), threading.Lock()
        self.body = VaultBody(lambda: self.client.status({}))   # body(content, size): what a model_event carries
        self.check_results = True   # the signer's last word on whether it checks tool results (verify_tool_results)

    def _run(self, key):
        with self.lock:
            run = self.runs.pop(key, None) or types.SimpleNamespace(
                stream="gx-" + uuid.uuid4().hex, seq=0, acked=-1, modes=None, lock=threading.Lock(), forms={})
            self.runs[key] = run
            evicted = self.runs.popitem(last=False) if len(self.runs) > MAX_RUNS else None
        if evicted:
            self.end(*evicted)
        return run

    def end(self, key, run):
        """Tell the signer where run `key`'s stream ended when its last exchanges never reached it (close_run
        `last_client_seq`, as a gateway: the run stays as it is), so it writes their client_counter_gap."""
        # lean: sent when the run is evicted or the gateway stops (a run already final gets the gap in its tenant's
        # signer run); report on a timer if gateways often lose the signer for long
        with run.lock:
            if run.seq - 1 <= run.acked:
                return
            run_id, token, caller = key
            try:
                self.client.close_run({"run_id": run_id, "run_token": token, "caller": caller,
                                       "last_client_seq": [{"stream": run.stream, "client_seq": run.seq - 1}]})
                run.acked = run.seq - 1
            except SignerUnavailable:
                return False
            except RPCError as e:
                print(f"tracekit gateway: the signer refused the end of run {run_id}'s stream ({e.code}: {e.message}), "
                      "so exchanges it never got leave no gap"
                      + ("; grant this gateway close_run next to model_event in signer.yaml authorize"
                         if e.code == "forbidden" else ""), file=sys.stderr)

    def close(self):
        """End the streams of every run whose last exchanges the signer did not get (the gateway is stopping)."""
        with self.lock:
            runs = list(self.runs.items())
        for key, run in runs:
            if self.end(key, run) is False:   # the signer can't be reached: don't wait out its timeout per run
                print(f"tracekit gateway: the signer is unreachable; {len(runs)} run(s) not told where their streams "
                      "ended", file=sys.stderr)
                return

    def refused_tools(self, kind, req):
        """The provider-run tools `req` declares that provider_tools does not allow (OpenAI tool types the client runs
        are none); an entry names a tool or a type (`mcp` covers `mcp:<server_label>`)."""
        allow, deny = self.provider_tools.get("allow"), self.provider_tools.get("deny", ())

        def listed(n, names):
            return n in names or n.split(":", 1)[0] in names
        return [n for n in parsers.provider_tools(kind, req)
                if not (kind.startswith("openai:") and n in parsers.OPENAI_CLIENT_TOOLS)
                and (listed(n, deny) or allow is not None and not listed(n, allow))]

    def record(self, key, xid, **fields):
        """model_event for run `key` = (run_id, token, caller): the signer's answer once recorded, False when the
        signer can't be reached; RPCError for a refusal. A run's records share one stream whose counter every attempt
        advances, so an exchange the signer never got shows as a client_counter_gap once a later one of the run
        reaches it."""
        # lean: no gap if no later exchange of the run reaches the signer; a gateway-side outbox if that matters
        run_id, token, caller = key
        run = self._run(key)
        with run.lock:   # counter order is arrival order
            seq, run.seq = run.seq, run.seq + 1
            try:
                out = self.client.model_event({"run_id": run_id, "run_token": token, "caller": caller,
                                               "exchange_id": xid, "stream": run.stream, "client_seq": seq, **fields})
            except SignerUnavailable:
                return False
            except RPCError as e:
                if e.code == "unavailable":
                    return False
                if run.acked == -1:   # refused before the signer ever took one (a forged token): not kept
                    with self.lock:
                        if self.runs.get(key) is run:
                            del self.runs[key]
                raise
            run.modes, run.acked = out.get("fail_modes"), seq
            # lean: learned from each answer, so the first request after a signer turns verify_tool_results on goes
            # unchecked
            self.check_results = out.get("check_results", True)
        return out

    def fail_open(self, key):
        return fail_open(self._run(key).modes, "model")

    def results(self, key, sent):
        """model_event's `tool_results` for a request of run `key` that sends the model `sent` ([(tool_call_id,
        content)]): each one's result_forms, newest first while the bytes digested stay within MAX_DIGESTED; a content
        the run's previous request sent too costs a hash. A result past that is left out; its id is still in the
        request's tool_results_sent, so the signer signs it as unchecked."""
        # lean: a run's cache is its last request's forms (~1.4 KB per result, for up to MAX_RUNS runs); bound it by
        # bytes if gateways hold many long runs
        run, budget, forms, out = self._run(key), MAX_DIGESTED, {}, []
        for tcid, content in reversed(sent):
            raw = json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass")
            h = hashlib.sha256(raw).digest()
            f = forms.get(h) or run.forms.get(h)
            if f is None and len(raw) <= budget:
                budget -= len(raw)
                f = result_forms(content)
            if f:
                forms[h] = f
                out.append({"id": tcid, "forms": f})
        run.forms = forms
        return out[::-1]


def show_reasoning(kind, req):
    """(the request to send, the JSON pointers of the fields changed) for `req`, which the client sent: a request that
    has the model reason but hides the reasoning is amended to show it, and nothing else is changed. Anthropic Messages
    `thinking` of type enabled or adaptive with `display` unset or omitted: display summarized (a summary; the API never
    returns the raw thinking). OpenAI Responses `reasoning` with effort other than none and no `summary` (nor the older
    `generate_summary`): summary auto. A request that doesn't turn reasoning on itself (no `thinking`, Anthropic type
    disabled or between_tools, which takes no display) is sent as it is, as is every other kind: chat completions have
    no field for it."""
    if kind == "anthropic:messages":
        t = req.get("thinking")
        if isinstance(t, dict) and t.get("type") in ("enabled", "adaptive") and t.get("display") in (None, "omitted"):
            return {**req, "thinking": {**t, "display": "summarized"}}, ["/thinking/display"]
    if kind == "openai:responses":
        r = req.get("reasoning")
        if isinstance(r, dict) and r.get("effort") != "none" and r.get("summary") is None \
                and r.get("generate_summary") is None:
            return {**req, "reasoning": {**r, "summary": "auto"}}, ["/reasoning/summary"]
    return req, []


EMPTY = (None, "", [])   # no content, as providers and frameworks send a result with none


def result_forms(content):
    """The values a tool result sent to the model may have been recorded as (complete's `result`, itself or as its
    digest): the content as sent; the text of a list of text blocks; the value of a JSON string, or of that text; for
    no content (None, "", no blocks: an Anthropic tool_result may have none, Pydantic AI sends `None` and `[]` as ""),
    each of those. A value JCS can't encode (a lone surrogate, an integer past 2^53, NaN) is taken as its JSON text, as
    tracekit.sdk.client.result_field records it, so every result has a form. Each as {digest, result_digest}:
    event_hash of the value and sha256 of JCS({"result": value})."""
    values = [content] + [v for v in EMPTY if v != content] if content in EMPTY else [content]
    if isinstance(content, list) and content and all(
            isinstance(b, dict) and b.get("type") in ("text", "input_text", "output_text") and isinstance(b.get("text"), str)
            for b in content):
        values.append("".join(b["text"] for b in content))
    if isinstance(values[-1], str) and values[-1]:
        try:
            values.append(loads_strict(values[-1]))
        except ValueError:   # not JSON: the text is the value
            pass
    forms = []
    for v in values:
        try:
            c = canonical(v)
        except ValueError:   # CanonicalizationError
            c = canonical(json.dumps(v))
        form = {"digest": "sha256:" + hashlib.sha256(c).hexdigest(),
                "result_digest": "sha256:" + hashlib.sha256(b'{"result":' + c + b"}").hexdigest()}   # JCS of it
        if form not in forms:
            forms.append(form)
    return forms


class _SSE:
    """Feeds each `data:` line of an SSE stream to a parsers.Stream: `done` once its terminal event came, `error` when
    the upstream sent an error event or a line over MAX_SSE_LINE."""

    def __init__(self, stream):
        self.stream, self.buf, self.done, self.error = stream, b"", False, None

    def feed(self, chunk):
        lines = (self.buf + chunk).split(b"\n")
        self.buf = lines.pop()
        if len(self.buf) > MAX_SSE_LINE:
            self.buf, self.error = b"", f"an SSE line over {MAX_SSE_LINE} bytes"
        for line in lines:
            data = line[5:].strip() if line.startswith(b"data:") else None
            if data == b"[DONE]":
                self.done = True
            if not data or data == b"[DONE]":
                continue
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get("type") in FAILED or ev.get("error"):
                self.error = "upstream error event: " + json.dumps(ev.get("error") or ev.get("type"))[:900]
            self.stream.add(ev)
            self.done = self.done or ev.get("type") in TERMINAL


class _Handler(Lines, http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    NAME = "tracekit gateway"   # in every error the client gets

    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle_one_request(self):
        self.server.restart_deadline()
        super().handle_one_request()

    def parse_request(self):
        """Every method: a body framed otherwise than by one strict Content-Length is refused, and one no route reads
        (only a POST reads its body) closes the connection after the answer, or it would be read as the next request."""
        if not super().parse_request():
            return False
        self.length, why = body_length(self.headers)
        if why:
            self._error(400, why)
            return False
        if self.length and self.command != "POST":
            self.close_connection = True
        return True

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        if self.close_connection:
            self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, msg, close=True):
        body = json.dumps({"error": {"type": self.NAME.replace(" ", "_"), "message": f"{self.NAME}: {msg}"}}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        if close or self.close_connection:
            self.send_header("connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _authenticated(self, max_body):
        """((run_id, run token, the caller as scheme:subject), the JSON object its body holds, the body) of a request
        with an identity the authenticators accept and its run, or None once it is refused."""
        run, conn = self.headers.get("X-Tracekit-Run"), self
        if run is None:   # the run in the bearer: only a client certificate can say who is calling
            run, conn = bearer(self), types.SimpleNamespace(headers={}, connection=self.connection,
                                                             client_address=self.client_address)
        try:
            identity = self.server.authenticate(conn, {"method": "model_event"})
        except RPCError as e:
            return self._error(401, e.message)
        parts = (run or "").rsplit(".", 2)   # a run token is <payload>.<mac>
        if len(parts) != 3 or not all(parts) or len(run) > MAX_RUN_HEADER:
            return self._error(401, "no run: send X-Tracekit-Run: <run_id>.<run token>")
        if self.length is None:   # its framing is checked with the request line (parse_request)
            return self._error(411, "Content-Length required")
        if self.length > max_body:
            return self._error(413, f"request body over {max_body} bytes")
        if self.headers.get("content-encoding", "identity").lower() != "identity":
            return self._error(415, "send the request body uncompressed")
        body = read_body(self, self.length)
        if body is None:
            return None
        self.server.stop_deadline()   # the request is in; the answer may take minutes
        try:
            req = json.loads(body)
        except (ValueError, RecursionError):
            req = None
        if not isinstance(req, dict):
            return self._error(400, "the request body is not a JSON object")
        return (parts[0], f"{parts[1]}.{parts[2]}", f"{identity.scheme}:{identity.subject}"), req, body

    def do_POST(self):
        gw, kind = self.server.gateway, KINDS.get(self.path.split("?")[0])
        if kind is None:
            return self._error(404, f"POST one of {', '.join(KINDS)}")
        got = self._authenticated(gw.max_body)
        if got is None:
            return
        (key, req, body), xid = got, "gx-" + uuid.uuid4().hex
        refused = gw.refused_tools(kind, req)
        if refused:
            return self._error(403, f"provider tool(s) {', '.join(sorted(set(refused)))[:256]} not allowed by this "
                                    "gateway's provider_tools: the provider runs them mid-response, where no policy can "
                                    "hold them; remove them from the request's tools", close=False)
        base = {"provider": kind.split(":")[0], "model": str(req.get("model") or "")[:128],
                "streamed": req.get("stream") is True}
        sent = parsers.parse(kind, None, req)["tool_results_sent"][-MAX_RESULTS_SENT:]
        results = gw.results(key, parsers.tool_results(kind, req)[-MAX_RESULTS_CHECKED:]) if gw.check_results else []
        # (request, its bytes, the pointers amended): amended, then as the client sent it if the provider rejects that
        attempts = [(req, body, [])]
        shown, amended = show_reasoning(kind, req) if gw.show_reasoning and (kind, base["model"]) not in \
            gw.unamendable else (req, [])
        if amended:
            try:
                data = json.dumps(shown, separators=(",", ":"), ensure_ascii=False).encode()
                attempts.insert(0, (shown, data, amended))
            except UnicodeEncodeError:   # a lone surrogate the client sent escaped: the request goes as it came
                pass
        xids = [xid] + ["gx-" + uuid.uuid4().hex for _ in attempts[1:]]
        for i, (sent_req, sent_body, pointers) in enumerate(attempts):
            try:
                ok = gw.record(key, xids[i], phase="request",
                               content_digest="sha256:" + hashlib.sha256(sent_body).hexdigest(),
                               **base, **({"amended": pointers} if pointers else {}),
                               **({"tool_results_sent": sent} if sent else {}),
                               **({"tool_results": results} if results else {}),
                               **gw.body(sent_req, len(sent_body)))
            except RPCError as e:
                return self._error(429 if e.code == "quota_exceeded" else 403,
                                   f"the signer refused the run: {e.message}")
            if not ok and not gw.fail_open(key):
                return self._error(503, "the signer is unreachable and the run's fail mode is closed")
            if ok and ok.get("refused"):
                try:
                    gw.record(key, xids[i], phase="response", error=f"not forwarded: {ok['refused']}"[:1024], **base)
                except RPCError:   # the request record and the signer's reconcile record stand
                    pass
                return self._error(403, ok["refused"], close=False)
            status = self._forward(gw, kind, key, xids[i], base, sent_req, sent_body, (xids[i + 1:] or [None])[0])
            if status is not RETRY:
                if i and status and status < 300 and len(gw.unamendable) < MAX_UNAMENDABLE:
                    gw.unamendable.add((kind, base["model"]))   # lean: per gateway process, until it restarts
                return

    def _forward(self, gw, kind, key, xid, base, req, body, retry=None):
        """Send the request upstream and its response to the client, both recorded; the upstream status (None: not
        reached). `retry`: the exchange id the request goes again under, as the client sent it, if the provider
        rejects this one, amended (REJECTED): that answer is recorded and not passed on (RETRY)."""
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
        headers.update({"Accept-Encoding": "identity", gw.auth[0]: gw.auth[1]})
        up = urllib.request.Request(gw.upstream + self.path, data=body, headers=headers, method="POST")
        stream, h = parsers.Stream(kind), hashlib.sha256()

        def done(err, parsed=None, content=None, size=0):
            """Record the response (`content`: as received, `size` bytes); whether the client may have it."""
            if content is None and stream.seen:
                content = stream.content()
                size = len(json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass"))
            out = parsed or stream.parse(req)
            fields = {"stop_reason": out["finish"] and str(out["finish"])[:100], "usage": out["usage"],
                      "tool_uses": out["tool_uses"][:128],   # lean: the RPC's cap; split the record if models exceed it
                      "error": err and err[:1024]}
            try:
                ok = gw.record(key, xid, phase="response", content_digest="sha256:" + h.hexdigest(),
                               **dict(base, model=str(out["model"] or base["model"])[:128]),
                               **{k: v for k, v in fields.items() if v},
                               **(gw.body(content, size) if content is not None else {}))
            except RPCError:
                return False
            return ok or gw.fail_open(key)

        try:
            try:
                resp = OPEN(up, timeout=UPSTREAM_TIMEOUT_S)
            except urllib.error.HTTPError as e:
                resp = e
        except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
            err = f"upstream unreachable: {e}"
            done(err)
            return self._error(502, err)
        try:
            status, ctype = resp.getcode(), resp.headers.get("content-type", "")
            # lean: any 400 or 422 to an amended request is taken as a rejection of the amendment, so a request bad for
            # another reason is sent twice; match the provider's error text if that costs too much
            if retry and status in REJECTED:
                try:
                    h.update(resp.read(gw.max_body))
                except (http.client.HTTPException, OSError):
                    pass
                done(f"upstream status {status} to the request as amended to show reasoning; sent again without the "
                     f"amendment as exchange {retry}")
                return RETRY
            if status < 300 and "event-stream" in ctype:
                self._stream(resp, status, stream, h, done)
            else:
                self._whole(gw, resp, status, kind, req, h, done)
            return status
        finally:
            resp.close()

    def _send_head(self, resp, status, extra):
        self.send_response(status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP:
                self.send_header(k, v)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()

    def _whole(self, gw, resp, status, kind, req, h, done):
        err, parsed, content = None if status < 300 else f"upstream status {status}", None, None
        try:
            data = resp.read(gw.max_body + 1)
        except (http.client.HTTPException, OSError) as e:
            data, err = b"", f"upstream response broke: {e}"
        h.update(data)
        if len(data) > gw.max_body:
            err = f"upstream response over {gw.max_body} bytes"
        elif err is None:
            try:
                content = json.loads(data)
                parsed = parsers.parse(kind, content, req)
            except ValueError:
                err = "upstream response is not JSON"
        ok = done(err, parsed, content, len(data))
        if not ok:
            return self._error(503, "the response could not be recorded and the run's fail mode is closed")
        if err and status < 400:
            return self._error(502, err)
        self._send_head(resp, status, {"content-length": str(len(data))})
        self.wfile.write(data)

    def _stream(self, resp, status, stream, h, done):
        self._send_head(resp, status, {"transfer-encoding": "chunked"})
        sse, err, last = _SSE(stream), None, b""
        try:
            while not sse.done:   # the chunk with the terminal event waits for the record; anything after it is dropped
                chunk = resp.read1(65536)
                if not chunk:
                    break
                h.update(chunk)
                sse.feed(chunk)
                if sse.done:
                    last = chunk
                else:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
        except (http.client.HTTPException, OSError) as e:
            err = f"stream broke: {e}"
        except Exception as e:   # an event the parser can't take: recorded as an error, never a clean end
            err = f"the upstream stream could not be read: {type(e).__name__}: {str(e)[:200]}"
        err = err or sse.error or (None if sse.done else "upstream stream ended before its terminal event")
        if not done(err):
            err = "the response could not be recorded and the run's fail mode is closed"
        self.close_connection = bool(err)
        try:
            if err:   # an error the SDKs raise, then no last chunk: never a clean end
                ev = b"event: error\ndata: " + json.dumps({"type": "error", "error": {
                    "type": "tracekit_gateway", "message": "tracekit gateway: " + err}}).encode() + b"\n\n"
                self.wfile.write(b"%x\r\n%s\r\n" % (len(ev), ev))
            else:
                self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(last), last))
            self.wfile.flush()
        except OSError:
            pass


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"http", "upstream", "api_key_file", "signer"} <= set(cfg):
        raise ValueError(f"{path}: needs http, upstream, api_key_file and signer; takes {sorted(KEYS)}")
    if remote_url_error(str(cfg["upstream"])):
        raise ValueError(f"{path}: upstream: {remote_url_error(str(cfg['upstream']))}")
    if cfg.get("api_key_header", "authorization") not in ("authorization", "x-api-key"):
        raise ValueError(f"{path}: api_key_header is authorization or x-api-key")
    if not (isinstance(cfg.get("max_body", MAX_BODY), int) and cfg.get("max_body", MAX_BODY) > 0):
        raise ValueError(f"{path}: max_body is a positive integer")
    pt = cfg.get("provider_tools", {})
    if not (isinstance(pt, dict) and set(pt) <= {"allow", "deny"} and all(
            isinstance(v, list) and all(isinstance(n, str) for n in v) for v in pt.values())):
        raise ValueError(f"{path}: provider_tools takes allow and deny, lists of tool names")
    if not isinstance(cfg.get("show_reasoning", True), bool):
        raise ValueError(f"{path}: show_reasoning is true or false")
    base = os.path.dirname(os.path.abspath(path))
    cfg["api_key_file"] = os.path.join(base, cfg["api_key_file"])
    transport.resolve(cfg["http"], base)
    return cfg


def serve(cfg, client=None):
    """The gateway's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    with open(cfg["api_key_file"], encoding="utf-8") as f:
        key = f.read().strip()
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_Handler)
    srv.gateway = Gateway(cfg["upstream"], key, cfg.get("api_key_header", "authorization"),
                          client or Client(cfg["signer"]), cfg.get("max_body", MAX_BODY), cfg.get("provider_tools"),
                          cfg.get("show_reasoning", True))
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the LLM gateway in the foreground").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        srv = serve(load_config(a.config))
    except (OSError, ValueError) as e:
        print(f"tracekit gateway: {e}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"tracekit gateway: {host}:{port} -> {srv.gateway.upstream}", flush=True)
    signal.signal(signal.SIGTERM, signal.default_int_handler)   # systemd, docker, k8s: stop as on Ctrl-C, reporting
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        srv.gateway.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
