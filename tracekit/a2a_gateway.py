"""A2A gateway (tier T2, experimental): a reverse proxy in front of configured A2A servers (the Agent2Agent protocol,
JSON-RPC over HTTP) whose credentials stay in the gateway; every message an agent sends another agent through it, and
every task it reads, is decided, sent and completed in the signer by the gateway, for the calling agent's run.
docs/a2a.md.

    tracekit a2a-gateway serve --config a2a-gateway.yaml

a2a-gateway.yaml:
    http: {listen: 0.0.0.0:8092, cert: tls/a2a.pem, key: tls/a2a.key, authenticators: [mtls, k8s_sa, token]}
                                           # who may call: the signer's `http` section (tracekit/transport/http.py)
    signer: https://signer.internal:8443   # the gateway's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client);
                                           # signer.yaml lists it under `gateways`
    approval_wait_s: 300                   # how long a message the policy asks about waits for a person
    max_body: 1048576                      # request and response bodies; a stream's events in all
    upstreams:
      - name: researcher                   # [a-z0-9-]{1,64}: the agent posts to /a2a/researcher
        url: https://researcher.internal/a2a                   # the A2A server's JSON-RPC endpoint
        card: https://researcher.internal/.well-known/agent-card.json   # default: that path on url's host
        headers: {authorization: secrets/researcher.header}   # header -> the file holding its value (a secret: cut)

The calling agent POSTs JSON-RPC to `/a2a/<upstream>` with its run, as at the LLM gateway (`X-Tracekit-Run:
<run_id>.<run token>` and an identity the authenticators accept). message/send, message/stream and tasks/get are each
decided as tool `a2a:<upstream>/<method>` (a2a:researcher/message/send) with the arguments {sender: the caller the
gateway authenticated, receiver: the upstream's name, agent_card: the sha256 digest of its Agent Card, skills: the ids
of the skills that card lists, params: the JSON-RPC params}, with `caller` under the agent's run token, so the records
are source gateway, tier T2, and the policy's a2a class reads the sender, the receiver, the skills and the message's
parts from them (policy2/classes.a2a_fields). On `ask` the request waits for a person, up to approval_wait_s. The
gateway sends the signer's copy of the params upstream and completes the call with the answer, which the signer
redacts. Any other method is refused and nothing is sent. A denial, any other refusal or the signer unreachable (fail
closed, whatever the run's fail modes) is a JSON-RPC error and the upstream never sees the request.

message/stream passes the upstream's events (server-sent events, each a JSON-RPC response) to the agent as they come,
each recorded first as an input the run observed (source a2a:<upstream>/message/stream#<the call's id>). The final one
(an error, a message, an update marked final, a task in a state that ends the stream) completes the call, with every
event as its result, before the agent gets it. A stream cut short (the upstream ending or breaking before its final
event, an event the signer could not record or that is not JSON-RPC, over max_body bytes in all, STREAM_IDLE_S without
a byte) ends for the agent in an error event, and the call keeps no result, which the signer signs as a
held_call_unresolved gap when the run ends: never a clean end, never silent.

The header values never reach the agent or the signer: each is cut from answers, events and errors before they are
recorded or answered. Relative paths are from the config file.
"""
import collections
import hashlib
import http.client
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

from tracekit import yamlmini
from tracekit.client import remote_url_error
from tracekit.executor import (APPROVAL_WAIT_S, HEADER_NAME, MAX_BODY, UPSTREAM_TIMEOUT_S, Custody, Unsent, _send, cut,
                               main as _main, read_secret, secret_values)
from tracekit.gateway import OPEN, _Handler
from tracekit.sdk.client import Client, SignerUnavailable, result_field
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import http as transport

KEYS = {"http", "signer", "upstreams", "approval_wait_s", "max_body"}
UPSTREAM_KEYS = {"name", "url", "card", "headers"}
NAME = re.compile(r"[a-z0-9-]{1,64}")   # lower case: the policy reads names in any case (policy2/classes.a2a_fields)
PREFIX = "/a2a/"
CARD_PATH = "/.well-known/agent-card.json"
MAX_CARD = 1 << 20
# lean: these three only; tasks/cancel, tasks/resubscribe and the push notification config methods are refused, and
# push notifications an upstream sends anywhere else are not seen. Relay each, decided, once agents need it here
METHODS = {"message/send", "message/stream", "tasks/get"}
ENDS = {"completed", "canceled", "failed", "rejected", "input-required", "auth-required"}   # task states ending a stream
STREAM_IDLE_S = 600   # how long a stream may go without a byte, as at the LLM gateway
TASKS_PER_CALLER = 1024
CALLERS_WITH_TASKS = 1024
MAX_TASK_ID = 1024
MAX_REFERENCE_TASK_IDS = 64
# the fields of message/send's, message/stream's and tasks/get's params by their names folded as a receiver may read
# them: a2a-python reads snake_case names too, and a JSON decoder may match names in any case, or without `-` and `_`
# (Go's encoding/json and json/v2 do); metadata and a data part's data are free-form. lean: A2A 0.3's fields, all the
# gateway and the policy read; add a later version's once they read one of its fields
FIELDS = {f.casefold(): f for f in (
    "message", "configuration", "metadata", "acceptedOutputModes", "historyLength", "pushNotificationConfig",
    "blocking", "id", "url", "token", "authentication", "schemes", "credentials", "role", "parts", "extensions",
    "referenceTaskIds", "messageId", "taskId", "contextId", "kind", "text", "file", "bytes", "uri", "mimeType", "name",
    "data")}
FREE_FORM = {"metadata", "data"}


class _Tasks:
    """The bounded task and context ids each authenticated caller was given through this gateway."""

    def __init__(self):
        self.callers, self.lock = collections.OrderedDict(), threading.Lock()

    def owns(self, caller, task):
        with self.lock:
            tasks = self.callers.get(caller)
            if tasks is None or task not in tasks:
                return False
            self.callers.move_to_end(caller)
            tasks.move_to_end(task)
            return True

    def add(self, caller, task):
        if not isinstance(task, str) or not task:
            return
        with self.lock:
            tasks = self.callers.pop(caller, collections.OrderedDict())
            tasks.pop(task, None)
            tasks[task] = None
            if len(tasks) > TASKS_PER_CALLER:
                tasks.popitem(last=False)
            self.callers[caller] = tasks
            if len(self.callers) > CALLERS_WITH_TASKS:
                self.callers.popitem(last=False)


def _misspelled(params):
    """Why `params` is refused, if it names an A2A field, at any depth, in a spelling other than A2A's: a receiver may
    read it as that field (FIELDS), where the gateway and the policy (policy2/classes.a2a_fields) read only A2A's
    spelling. A key outside ASCII is refused too: a decoder that folds case by Unicode may read `ıd` as `id`."""
    stack = [params]
    while stack:
        value = stack.pop()
        if isinstance(value, list):
            stack += value
        elif isinstance(value, dict):
            for key, v in value.items():
                if not key.isascii():
                    return f"params has a key outside ASCII ({key[:64]!r}); A2A's field names are ASCII"
                field = FIELDS.get(key.replace("_", "").replace("-", "").casefold())
                if field not in (None, key):
                    return (f"params names {field} in a spelling A2A does not use (another case, snake_case or "
                            f"kebab-case); send it as {field}")
                if field is not None and field not in FREE_FORM:
                    stack.append(v)
    return None


def _task_refs(method, params):
    """The existing tasks and contexts a request reads or continues, if it names them."""
    if method == "tasks/get":
        if "id" not in params:
            return ()
        if not _task_id(params["id"]):
            raise ValueError("tasks/get id is a non-empty string of at most %d characters" % MAX_TASK_ID)
        return (params["id"],)
    message = params.get("message")
    if not isinstance(message, dict):
        return ()
    refs = []
    for field in ("taskId", "contextId"):
        if field in message:
            if not _task_id(message[field]):
                raise ValueError(f"message {field} is a non-empty string of at most {MAX_TASK_ID} characters")
            refs.append(message[field])
    if "referenceTaskIds" in message:
        values = message["referenceTaskIds"]
        if not isinstance(values, list) or len(values) > MAX_REFERENCE_TASK_IDS or \
                any(not _task_id(value) for value in values) or len(set(values)) != len(values):
            raise ValueError("message referenceTaskIds is a list of at most %d unique non-empty strings of at most %d "
                             "characters" % (MAX_REFERENCE_TASK_IDS, MAX_TASK_ID))
        refs += values
    return tuple(refs)


def _task_id(value):
    return isinstance(value, str) and bool(value) and len(value) <= MAX_TASK_ID


def _given(value):
    """The task and context ids an A2A result gives its caller: a task's id and context id, a message's context id."""
    kind = value.get("kind") if isinstance(value, dict) else None
    return [value.get(k) for k in {"task": ("id", "contextId"), "message": ("contextId",)}.get(kind, ())]


class _A2aGateway(_Handler):
    NAME = "tracekit a2a-gateway"

    def do_GET(self):   # the Agent Card is the upstream's to serve; every call is a POST
        self._error(405, "POST /a2a/<upstream>", close=False)

    def do_POST(self):
        gw, path = self.server.a2a, self.path.split("?")[0]
        if not path.startswith(PREFIX):
            return self._error(404, "POST /a2a/<upstream>")
        got = self._authenticated(gw["max_body"])   # first: only a caller it accepts learns which upstreams exist
        if got is None:
            return
        up = gw["upstreams"].get(path[len(PREFIX):])
        if up is None:
            return self._error(404, "no such upstream: POST /a2a/<upstream>, one the gateway's config names")
        key, msg, _ = got
        try:
            out = self._call(gw, key, up, msg)
        except _Error as e:
            out = {"error": {"code": e.args[0], "message": e.args[1]}}
        if out is not None:   # None: a stream, answered already
            self._json(200, {"jsonrpc": "2.0", "id": msg.get("id"), **out})

    def _call(self, gw, key, up, msg):
        """The upstream's answer ({result} or {error}) to the JSON-RPC request `msg`, decided, sent and completed as
        tool a2a:<upstream>/<method> (None once a stream was answered); _Error when it may not be sent."""
        method, params = msg.get("method"), msg.get("params")
        if "id" not in msg:
            raise _Error(-32600, "an A2A request has an id")
        if method not in METHODS:
            raise _Error(-32601, f"method not found: {str(method)[:64]}; the gateway relays "
                                 f"{', '.join(sorted(METHODS))}")
        if not isinstance(params, dict):
            raise _Error(-32602, "params is an object")
        misspelled = _misspelled(params)
        if misspelled:
            raise _Error(-32602, misspelled)
        if isinstance(params.get("configuration"), dict) and \
                params["configuration"].get("pushNotificationConfig") is not None:
            raise _Error(-32602, "the gateway does not relay push notification configs; read the task's state with "
                                 "message/stream or tasks/get")
        try:
            refs = _task_refs(method, params)
        except ValueError as e:
            raise _Error(-32602, str(e)) from None
        for task in refs:
            if not gw["tasks"].owns(key[2], task):
                raise _Error(-32001, "task belongs to another caller or was not created through this gateway")
        tool, tcid = f"a2a:{up['name']}/{method}", "a2a-" + uuid.uuid4().hex
        args = {"sender": key[2], "receiver": up["name"], "agent_card": up["card_digest"], "skills": up["skills"],
                "params": params}
        why, d, args = gw["custody"].gate(key, tcid, tool, args)
        if why is not None:
            raise _Error(-32000, "Blocked by Tracekit: " + why[1])
        request = {"jsonrpc": "2.0", "id": msg["id"], "method": method, "params": args["params"]}
        try:
            if method == "message/stream":
                with _open(up, request) as resp:
                    return self._stream(gw, up, resp, (key, tcid, d, tool, args), msg["id"])
            status, value = _send(up["action"], request, gw["max_body"])
        except (http.client.HTTPException, OSError, ValueError) as e:
            err = cut(f"upstream unreachable, the message was not sent: {e.args[0]}" if isinstance(e, Unsent) else
                      f"the message was sent but its answer could not be read ({e}): it may have been acted on; "
                      "check before sending it again", up["action"]["cut"])
            gw["custody"].complete(key, tcid, d, tool, args, "error", error=err[:4096])
            raise _Error(-32603, err) from None
        out = {k: value[k] for k in ("result", "error") if isinstance(value, dict) and k in value}
        if len(out) != 1:
            out = {"error": {"code": -32006, "message": f"upstream answered HTTP {status} without a JSON-RPC "
                                                        "result or error"}}
        gw["custody"].complete(key, tcid, d, tool, args, "ok" if "result" in out else "error",
                               result=result_field(True, value))
        if method == "message/send" and "result" in out:
            for ref in _given(out["result"]):
                gw["tasks"].add(key[2], ref)
        return out

    def _stream(self, gw, up, resp, call, rid):
        """Pass the upstream's message/stream answer `resp` to the client event by event, each recorded first, and
        complete `call` (key, tool call id, decision, tool, args) at its final event; a stream cut short ends in an
        error event and leaves the call without a result (the module docstring)."""
        key, tcid, d, tool, args = call
        events, err = [], None
        try:
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-store")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for data in _events(resp, gw["max_body"]):
                ev = json.loads(data)
                out = cut({k: ev[k] for k in ("result", "error") if isinstance(ev, dict) and k in ev},
                          up["action"]["cut"])
                if len(out) != 1:
                    raise ValueError("an event without a JSON-RPC result or error")
                gw["custody"].client.observe({"run_id": key[0], "run_token": key[1], "caller": key[2],
                                              "source": f"{tool}#{tcid}", "value": result_field(True, out),
                                              "trust": "untrusted"})
                events.append(out)
                for ref in _given(out.get("result")):
                    gw["tasks"].add(key[2], ref)
                if _final(out):   # the call's result is recorded before the client gets its last event
                    gw["custody"].complete(key, tcid, d, tool, args, "error" if "error" in out else "ok",
                                           result=result_field(True, events))
                    return self._chunks(_sse(rid, out), b"")
                self._chunks(_sse(rid, out))
            err = "the upstream ended it before its final event"
        except (SignerUnavailable, RPCError) as e:
            err = f"an event could not be recorded, so it was not passed on ({e})"
        except (http.client.HTTPException, OSError, ValueError, RecursionError) as e:
            err = f"it broke ({e})"
        self.close_connection = True
        try:   # an error event, then no last chunk: never a clean end
            self._chunks(_sse(rid, {"error": {"code": -32603, "message": cut(
                f"{self.NAME}: the stream was cut after {len(events)} event(s): {err}; the task may go on, and "
                "tasks/get reads its state", up["action"]["cut"])[:4096]}}))
        except OSError:   # the client went away
            pass

    def _chunks(self, *parts):
        for p in parts:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(p), p))
        self.wfile.flush()


class _Error(Exception):
    pass


def _open(up, request):
    """The upstream's answer to the JSON-RPC `request`, asked for as an event stream, at any status; Unsent when it was
    not sent."""
    req = urllib.request.Request(up["url"], data=json.dumps(request).encode(), method="POST", headers={
        "content-type": "application/json", "accept": "text/event-stream", "accept-encoding": "identity",
        **up["action"]["headers"]})
    try:
        return OPEN(req, timeout=STREAM_IDLE_S)
    except urllib.error.HTTPError as e:
        return e
    except (urllib.error.URLError, ValueError) as e:   # as executor._send: connecting or sending failed
        raise Unsent(getattr(e, "reason", e)) from None


def _events(resp, max_body):
    """The data of each event of the upstream's answer `resp`: its whole body, as one event, when it is not an event
    stream (an error); ValueError past max_body bytes in all."""
    if resp.headers.get_content_type() != "text/event-stream":
        data = resp.read(max_body + 1)
        if len(data) > max_body:
            raise ValueError(f"an answer over {max_body} bytes")
        yield data
        return
    data, size = [], 0
    while True:
        line = resp.readline(max_body + 1 - size)
        size += len(line)
        if size > max_body:
            raise ValueError(f"over {max_body} bytes in all")
        if not line:
            return
        line = line.rstrip(b"\r\n")
        if line.startswith(b"data:"):
            data.append(line[5:].removeprefix(b" "))
        elif not line and data:
            yield b"\n".join(data)
            data = []


def _final(out):
    """Whether event `out` ({result} or {error}) ends a message/stream: an error, a message, an update marked final or
    a task in a state that ends it."""
    r = out.get("result")
    if not isinstance(r, dict):
        return True
    state = r["status"].get("state") if isinstance(r.get("status"), dict) else None
    return r.get("kind") == "message" or r.get("final") is True or r.get("kind") == "task" and state in ENDS


def _sse(rid, out):
    return b"data: " + json.dumps({"jsonrpc": "2.0", "id": rid, **out}).encode() + b"\n\n"


def _card(url):
    """(the sha256 digest of the Agent Card `url` serves, as bytes; the ids of the skills it lists)."""
    # lean: read once, at start; restart the gateway when a receiver's card changes, or re-read it per call if cards
    # change while it runs
    try:
        with OPEN(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=UPSTREAM_TIMEOUT_S) as r:
            data = r.read(MAX_CARD + 1)
        card = json.loads(data) if len(data) <= MAX_CARD else None
        if not isinstance(card, dict):
            raise ValueError(f"not a JSON object of at most {MAX_CARD} bytes")
    except (OSError, http.client.HTTPException, ValueError, RecursionError) as e:
        raise ValueError(f"{url}: the Agent Card could not be read: {e}") from None
    skills = card.get("skills") if isinstance(card.get("skills"), list) else []
    return ("sha256:" + hashlib.sha256(data).hexdigest(),
            sorted({s["id"] for s in skills if isinstance(s, dict) and isinstance(s.get("id"), str)}))


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"http", "signer", "upstreams"} <= set(cfg):
        raise ValueError(f"{path}: needs http, signer and upstreams; takes {sorted(KEYS)}")
    for k, default in (("approval_wait_s", APPROVAL_WAIT_S), ("max_body", MAX_BODY)):
        if not (isinstance(cfg.get(k, default), int) and cfg.get(k, default) > 0):
            raise ValueError(f"{path}: {k} is a positive integer")
    if not isinstance(cfg["upstreams"], list) or not cfg["upstreams"]:
        raise ValueError(f"{path}: upstreams is a list of {sorted(UPSTREAM_KEYS)}")
    base, upstreams = os.path.dirname(os.path.abspath(path)), {}
    for u in cfg["upstreams"]:
        where = f"{path}: upstream {u.get('name') if isinstance(u, dict) else u!r}"
        if not isinstance(u, dict) or set(u) - UPSTREAM_KEYS or "url" not in u:
            raise ValueError(f"{where}: needs name and url; takes {sorted(UPSTREAM_KEYS)}")
        if not (isinstance(u.get("name"), str) and NAME.fullmatch(u["name"])) or u["name"] in upstreams:
            raise ValueError(f"{where}: name is unique, [a-z0-9-]{{1,64}}")
        for k in ("url", "card"):
            if k in u and (remote_url_error(str(u[k])) or set("{}") & set(str(u[k]))):
                raise ValueError(f"{where}: {k}: {remote_url_error(str(u[k])) or 'no { or } in it'}")
        headers = u.get("headers", {})
        if not (isinstance(headers, dict) and all(isinstance(v, str) and HEADER_NAME.fullmatch(k)
                                                  for k, v in headers.items())):
            raise ValueError(f"{where}: headers maps a header name to the file holding its value")
        upstreams[u["name"]] = {"name": u["name"], "url": u["url"],
                                "card": u.get("card") or urllib.parse.urljoin(u["url"], CARD_PATH),
                                "headers": {k: os.path.join(base, v) for k, v in headers.items()}}
    cfg["upstreams"] = upstreams
    transport.resolve(cfg["http"], base)
    return cfg


def serve(cfg, client=None):
    """The gateway's server for a loaded config, each upstream's Agent Card read, not yet serving; stop it with
    shutdown() and server_close()."""
    addr, auths, tls = transport.configure(cfg["http"])   # first: a listener it refuses reads no card
    ups = {}
    for name, u in cfg["upstreams"].items():
        headers = {k: read_secret(p, header=True) for k, p in u["headers"].items()}
        # what executor._send posts: the JSON-RPC request to url, with the headers, their values cut from the answer
        action = {"method": "POST", "url_template": u["url"], "path_fields": (), "headers": headers,
                  "cut": secret_values(headers.values())}
        digest, skills = _card(u["card"])
        ups[name] = dict(u, card_digest=digest, skills=skills, action=action)
    srv = transport.HttpServer(addr, auths, tls, None, handler=_A2aGateway)
    srv.a2a = {"upstreams": ups, "max_body": cfg.get("max_body", MAX_BODY),
               "custody": Custody(client or Client(cfg["signer"]), cfg.get("approval_wait_s", APPROVAL_WAIT_S)),
               "tasks": _Tasks()}
    return srv


def main(argv=None):
    return _main(argv, "tracekit a2a-gateway", load_config, serve)


if __name__ == "__main__":
    import sys
    sys.exit(main())
