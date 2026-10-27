"""A2A gateway (tier T2): a reverse proxy in front of configured A2A servers (the Agent2Agent protocol, JSON-RPC over
HTTP) whose credentials stay in the gateway; every message an agent sends another agent, and every task call, is
decided, sent and completed in the signer by the gateway, for the calling agent's run. docs/a2a.md.

    tracekit a2a-gateway serve --config a2a-gateway.yaml

a2a-gateway.yaml:
    http: {listen: 0.0.0.0:8092, cert: tls/a2a.pem, key: tls/a2a.key, authenticators: [mtls, k8s_sa, token]}
                                           # who may call: the signer's `http` section (tracekit/transport/http.py)
    signer: https://signer.internal:8443   # the gateway's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client);
                                           # signer.yaml lists it under `gateways`
    approval_wait_s: 300                   # how long a message the policy asks about waits for a person
    max_body: 1048576                      # request and response bodies
    upstreams:
      - name: researcher                   # [A-Za-z0-9-]+: the agent posts to /a2a/researcher
        url: https://researcher.internal/a2a                   # the A2A server's JSON-RPC endpoint
        card: https://researcher.internal/.well-known/agent-card.json   # default: that path on url's host
        headers: {authorization: secrets/researcher.header}   # header -> the file holding its value (a secret: cut)

The calling agent POSTs JSON-RPC to `/a2a/<upstream>` with its run, as at the LLM gateway (`X-Tracekit-Run:
<run_id>.<run token>` and an identity the authenticators accept). Each method of METHODS is decided as tool
`a2a:<upstream>/<method>` (a2a:researcher/message/send) with the arguments {sender: the caller the gateway
authenticated, receiver: the upstream's name, agent_card: the sha256 digest of its Agent Card, params: the JSON-RPC
params}, with `caller` under the agent's run token, so the records are source gateway, tier T2, and the policy's a2a
class reads the sender, the receiver and the message's parts from them (policy2/classes.a2a_fields). On `ask` the
message waits for a person, up to approval_wait_s. The gateway sends the signer's copy of the params upstream and
completes the call with the response, which the signer redacts. A denial, any other refusal or the signer unreachable
(fail closed, whatever the run's fail modes) is a JSON-RPC error and the upstream never sees the message. The header
values never reach the agent or the signer: each is cut from the response and from errors before they are recorded or
answered. Relative paths are from the config file.
"""
import hashlib
import http.client
import json
import os
import re
import urllib.parse
import urllib.request
import uuid

from tracekit import yamlmini
from tracekit.client import remote_url_error
from tracekit.executor import (APPROVAL_WAIT_S, HEADER_NAME, MAX_BODY, UPSTREAM_TIMEOUT_S, Custody, Unsent, _send, cut,
                               main as _main, read_secret, secret_values)
from tracekit.gateway import OPEN, _Handler
from tracekit.sdk.client import Client, result_field
from tracekit.transport import http as transport

KEYS = {"http", "signer", "upstreams", "approval_wait_s", "max_body"}
UPSTREAM_KEYS = {"name", "url", "card", "headers"}
NAME = re.compile(r"[A-Za-z0-9-]+")
PREFIX = "/a2a/"
CARD_PATH = "/.well-known/agent-card.json"
MAX_CARD = 1 << 20
METHODS = {"message/send", "tasks/get", "tasks/cancel", "tasks/pushNotificationConfig/set",
           "tasks/pushNotificationConfig/get", "tasks/pushNotificationConfig/list",
           "tasks/pushNotificationConfig/delete"}
# lean: a streamed answer (SSE) is refused, not relayed; relay it event by event, each recorded, a cut stream a signed
# gap, once agents need message/stream through the gateway
STREAMING = {"message/stream", "tasks/resubscribe"}


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
        self._json(200, {"jsonrpc": "2.0", "id": msg.get("id"), **out})

    def _call(self, gw, key, up, msg):
        """The upstream's answer ({result} or {error}) to the JSON-RPC request `msg`, decided, sent and completed as
        tool a2a:<upstream>/<method>; _Error when it may not be sent."""
        method, params = msg.get("method"), msg.get("params")
        if "id" not in msg:
            raise _Error(-32600, "an A2A request has an id")
        if method in STREAMING:
            raise _Error(-32004, f"{method} is not supported through the gateway yet: use message/send")
        if method not in METHODS:
            raise _Error(-32601, f"method not found: {str(method)[:64]}")
        if not isinstance(params, dict):
            raise _Error(-32602, "params is an object")
        tool, tcid = f"a2a:{up['name']}/{method}", "a2a-" + uuid.uuid4().hex
        args = {"sender": key[2], "receiver": up["name"], "agent_card": up["card_digest"], "params": params}
        why, d, args = gw["custody"].gate(key, tcid, tool, args)
        if why is not None:
            raise _Error(-32000, "Message blocked by Tracekit: " + why[1])
        try:
            status, value = _send(up["action"], {"jsonrpc": "2.0", "id": msg["id"], "method": method,
                                                 "params": args["params"]}, gw["max_body"])
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
        return out


class _Error(Exception):
    pass


def _card(url):
    """The sha256 digest of the Agent Card `url` serves, as bytes."""
    # lean: read once, at start; restart the gateway when a receiver's card changes, or re-read it per call if cards
    # change while it runs
    try:
        with OPEN(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=UPSTREAM_TIMEOUT_S) as r:
            data = r.read(MAX_CARD + 1)
        if len(data) > MAX_CARD or not isinstance(json.loads(data), dict):
            raise ValueError(f"not a JSON object of at most {MAX_CARD} bytes")
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise ValueError(f"{url}: the Agent Card could not be read: {e}") from None
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
            raise ValueError(f"{where}: name is unique, [A-Za-z0-9-]+")
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
    ups = {}
    for name, u in cfg["upstreams"].items():
        headers = {k: read_secret(p, header=True) for k, p in u["headers"].items()}
        # what executor._send posts: the JSON-RPC request to url, with the headers, their values cut from the answer
        action = {"method": "POST", "url_template": u["url"], "path_fields": (), "headers": headers,
                  "cut": secret_values(headers.values())}
        ups[name] = dict(u, card_digest=_card(u["card"]), action=action)
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_A2aGateway)
    srv.a2a = {"upstreams": ups, "max_body": cfg.get("max_body", MAX_BODY),
               "custody": Custody(client or Client(cfg["signer"]), cfg.get("approval_wait_s", APPROVAL_WAIT_S))}
    return srv


def main(argv=None):
    return _main(argv, "tracekit a2a-gateway", load_config, serve)


if __name__ == "__main__":
    import sys
    sys.exit(main())
