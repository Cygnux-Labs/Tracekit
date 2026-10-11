"""Tool executor (tier T2): an HTTP service that runs registered actions with credentials the agent never holds, each
decided, approved and completed in the signer for the agent's run. docs/executor.md.

    tracekit executor serve --config executor.yaml

executor.yaml:
    http: {listen: 0.0.0.0:8090, cert: tls/ex.pem, key: tls/ex.key, authenticators: [mtls, k8s_sa, token]}
                                           # who may call: the signer's `http` section (tracekit/transport/http.py)
    signer: https://signer.internal:8443   # the executor's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client);
                                           # signer.yaml lists it under `gateways`
    approval_wait_s: 300                   # how long a call the policy asks about waits for a person
    max_body: 1048576                      # request and response bodies
    actions:
      - name: create_issue                 # the tool name the signer's policy decides on
        description: Open a GitHub issue   # for the model, via the client helpers
        method: POST
        url_template: https://api.github.com/repos/{owner}/{repo}/issues   # {arg}: that argument, URL-quoted
        headers: {authorization: secrets/github.header}   # header -> the file holding its value
        args: {type: object, required: [owner, repo, title], additionalProperties: false,
               properties: {owner: {type: string}, repo: {type: string}, title: {type: string}}}

`GET /v1/actions` lists the actions (name, description, args schema) to any identity the authenticators accept; the
client helpers (tracekit.integrations.executor_tools, @cygnux/tracekit/v2/executor) build framework tools from it.
The agent calls `POST /v1/actions/<name>` with its run, as at the LLM gateway (`X-Tracekit-Run: <run_id>.<run token>`
and an identity the authenticators accept), and `{"args": {...}, "tool_call_id": "..."}` (the model's id for the call,
optional). The arguments must match the action's `args` schema (400). The executor decides through the signer with
`caller` (the agent's identity) under the agent's run token, so the records are source gateway, tier T2; on `ask` it
holds the call until a person decides or approval_wait_s passes; it consumes the approval (an approval with a T2
executor returns the signer's copy of the arguments, which is what runs); it sends the request, the arguments as its
JSON body (none for GET and DELETE), with the action's headers; and it completes the call with the response, which the
signer redacts. The agent gets `{"status": <the upstream's>, "result": <its JSON or text>}`. A denial or any other
refusal: 403; the signer unreachable: 503 (fail closed, whatever the run's fail modes); the upstream unreachable: 502,
completed as an error. The header values never reach the agent or the signer: each is cut from the response before
it is recorded or answered. Relative paths are from the config file.
"""
import argparse
import http.client
import json
import os
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from tracekit import yamlmini
from tracekit.client import remote_url_error
from tracekit.format.canon import event_hash
from tracekit.gateway import OPEN, _Handler
from tracekit.sdk.client import Client, SignerUnavailable, result_field
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import http as transport

KEYS = {"http", "signer", "actions", "approval_wait_s", "max_body"}
ACTION_KEYS = {"name", "description", "method", "url_template", "headers", "args"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
NO_BODY = {"GET", "DELETE"}
MAX_BODY = 1 << 20
APPROVAL_WAIT_S = 300
UPSTREAM_TIMEOUT_S = 60
REDACTED = "[REDACTED:executor_secret]"


class Custody:
    """The signer's steps for a call this service runs for its client (tier T2): decide, wait for a person on `ask`,
    consume, complete, each naming the client (`caller`) under the client's run token. Fails closed."""

    def __init__(self, client, approval_wait_s=APPROVAL_WAIT_S):
        self.client, self.wait_s = client, approval_wait_s

    def gate(self, key, tcid, tool, args):
        """(None, the decision, the arguments to run) when the call may run, else ((HTTP status, why), None, None)."""
        run_id, token, caller = key
        base = {"run_id": run_id, "run_token": token, "caller": caller}
        call = {**base, "tool_call_id": tcid, "tool": tool, "args_source": "parsed", "args": args}
        try:
            d = self.client.decide(call)
            if d["decision"] == "deny":
                return (403, "denied by policy: " + (", ".join(d["rule_ids"]) or "deny")), None, None
            hint = {}
            if d["decision"] == "ask":
                hint = {"approval_id_hint": self.client.approval_request({**base, "tool_call_id": tcid})["approval_id"]}
                state, end = "requested", time.monotonic() + self.wait_s
                while state == "requested" and end > time.monotonic():
                    state = self.client.approval_wait({**base, "approval_id": hint["approval_id_hint"], "timeout_ms":
                                                       int(min(end - time.monotonic(), 300) * 1000)})["state"]
                if state != "approved":
                    return (403, f"{', '.join(d['rule_ids'])}: approval {state}"), None, None
            c = self.client.approval_consume({**call, **hint})
        except SignerUnavailable as e:
            return (503, f"the signer is unreachable ({e}); nothing ran"), None, None
        except RPCError as e:
            return (503 if e.code == "unavailable" else 403, f"the signer refused the call: {e}"), None, None
        if not c["ok"]:
            return (403, ", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else "")), None, None
        return None, d, c.get("args", args)

    def complete(self, key, tcid, d, tool, args, status, **outcome):
        """Record the outcome; a failure to record warns (the call ran: its result still goes to the client)."""
        run_id, token, caller = key
        try:
            self.client.complete({"run_id": run_id, "run_token": token, "caller": caller, "tool_call_id": tcid,
                                  "decision_id": d["decision_id"], "args_digest": event_hash({"tool": tool, "args": args}),
                                  "status": status, **outcome})
        except (SignerUnavailable, RPCError) as e:
            print(f"tracekit: the outcome of {tool} call {tcid} (run {run_id}) was not recorded: {e}", file=sys.stderr)


class _Executor(_Handler):
    NAME = "tracekit executor"

    def do_GET(self):
        if self.path.split("?")[0] != "/v1/actions":
            return self._error(404, "GET /v1/actions")
        try:
            self.server.authenticate(self, {"method": "status"})
        except RPCError as e:
            return self._error(401, e.message)
        self._json(200, {"actions": [{"name": a["name"], "description": a.get("description", ""), "args": a["args"]}
                                     for a in self.server.executor["actions"].values()]})

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ex, path = self.server.executor, self.path.split("?")[0]
        action = ex["actions"].get(path[len("/v1/actions/"):]) if path.startswith("/v1/actions/") else None
        if action is None:
            return self._error(404, "no such action: GET /v1/actions lists them")
        got = self._authenticated(ex["max_body"])
        if got is None:
            return
        key, req, _ = got
        args, tcid = req.get("args"), req.get("tool_call_id", "ex-" + uuid.uuid4().hex)
        errs = rpc_schema.validate(rpc_schema.ID, tcid) or rpc_schema.validate(action["args"], args)
        if not errs:
            try:
                _url(action, args)
            except ValueError as e:
                errs = [str(e)]
        if errs:
            return self._error(400, "; ".join(errs)[:1024])
        why, d, args = ex["custody"].gate(key, tcid, action["name"], args)
        if why is not None:
            return self._error(*why)
        try:
            status, result = _send(action, args, ex["max_body"])
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            err = f"upstream unreachable: {e}"
            ex["custody"].complete(key, tcid, d, action["name"], args, "error", error=err[:4096])
            return self._error(502, err)
        ex["custody"].complete(key, tcid, d, action["name"], args, "ok" if status < 400 else "error",
                               result=result_field(True, {"status": status, "result": result}))
        self._json(200, {"status": status, "result": result})


def _url(action, args):
    """The action's URL for `args`: each {arg} URL-quoted, so it stays in its path segment or query value."""
    values = {k: urllib.parse.quote(str(v), safe="") for k, v in args.items()}
    if {values.get(f) for f in action["fields"]} & {".", ".."}:
        raise ValueError("an argument in the URL is . or ..")
    return action["url_template"].format_map(values)


def _send(action, args, max_body):
    """(status, the response's JSON or text, with every header value cut out (secret_values)) of the action's request for `args`."""
    url = _url(action, args)
    body = None if action["method"] in NO_BODY else json.dumps(args).encode()
    req = urllib.request.Request(url, data=body, method=action["method"],
                                 headers={"content-type": "application/json", "accept-encoding": "identity",
                                          **action["headers"]})
    try:
        resp = OPEN(req, timeout=UPSTREAM_TIMEOUT_S)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        status, data = resp.getcode(), resp.read(max_body + 1)
    if len(data) > max_body:
        raise ValueError(f"upstream response over {max_body} bytes")
    text = data.decode("utf-8", "replace")
    for v in action["cut"]:
        text = text.replace(v, REDACTED)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def secret_values(values):
    """What to cut from responses: each value and, of an `<auth scheme> <credential>` header, the credential alone;
    longest first."""
    return sorted({x for v in values for x in (v, *v.split()[-1:]) if x}, key=len, reverse=True)


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"http", "signer", "actions"} <= set(cfg):
        raise ValueError(f"{path}: needs http, signer and actions; takes {sorted(KEYS)}")
    for k, default in (("approval_wait_s", APPROVAL_WAIT_S), ("max_body", MAX_BODY)):
        if not (isinstance(cfg.get(k, default), int) and cfg.get(k, default) > 0):
            raise ValueError(f"{path}: {k} is a positive integer")
    base, actions = os.path.dirname(os.path.abspath(path)), {}
    if not isinstance(cfg["actions"], list) or not cfg["actions"]:
        raise ValueError(f"{path}: actions is a list of {sorted(ACTION_KEYS)}")
    for a in cfg["actions"]:
        where = f"{path}: action {a.get('name') if isinstance(a, dict) else a!r}"
        if not isinstance(a, dict) or set(a) - ACTION_KEYS or not {"name", "method", "url_template", "args"} <= set(a):
            raise ValueError(f"{where}: needs name, method, url_template and args; takes {sorted(ACTION_KEYS)}")
        if not (isinstance(a["name"], str) and not rpc_schema.validate(rpc_schema.ID, a["name"])) or a["name"] in actions:
            raise ValueError(f"{where}: name is a unique id ([A-Za-z0-9._:-]+)")
        if not isinstance(a.get("description", ""), str):
            raise ValueError(f"{where}: description is a string")
        if a["method"] not in METHODS:
            raise ValueError(f"{where}: method is one of {sorted(METHODS)}")
        if remote_url_error(str(a["url_template"])):
            raise ValueError(f"{where}: url_template: {remote_url_error(str(a['url_template']))}")
        if "{" in urllib.parse.urlsplit(a["url_template"]).netloc:   # the host carries the credentials: never an arg
            raise ValueError(f"{where}: url_template: no {{arg}} in the host")
        if not isinstance(a["args"], dict) or a["args"].get("type") != "object":
            raise ValueError(f"{where}: args is a JSON Schema of type object")
        try:
            rpc_schema.validate(a["args"], {})
        except ValueError as e:   # a keyword the validator does not implement
            raise ValueError(f"{where}: args: {e}") from None
        fields = {f for _, f, _, _ in string.Formatter().parse(a["url_template"]) if f is not None}
        if fields - set(a["args"].get("required", [])):
            raise ValueError(f"{where}: url_template uses {sorted(fields)}: each must be a required argument")
        headers = a.get("headers", {})
        if not isinstance(headers, dict) or not all(isinstance(v, str) for v in headers.values()):
            raise ValueError(f"{where}: headers maps a header name to the file holding its value")
        actions[a["name"]] = dict(a, fields=fields, headers={k: os.path.join(base, v) for k, v in headers.items()})
    cfg["actions"] = actions
    transport.resolve(cfg["http"], base)
    return cfg


def serve(cfg, client=None):
    """The executor's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    actions = {}
    for name, a in cfg["actions"].items():
        headers = {}
        for k, p in a["headers"].items():
            with open(p, encoding="utf-8") as f:
                headers[k] = f.read().strip()
        actions[name] = dict(a, headers=headers, cut=secret_values(headers.values()))
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_Executor)
    srv.executor = {"actions": actions, "max_body": cfg.get("max_body", MAX_BODY),
                    "custody": Custody(client or Client(cfg["signer"]), cfg.get("approval_wait_s", APPROVAL_WAIT_S))}
    return srv


def main(argv=None, prog="tracekit executor", load=load_config, start=serve):
    ap = argparse.ArgumentParser(prog=prog)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run in the foreground").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        srv = start(load(a.config))
    except (OSError, ValueError) as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"{prog}: {host}:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
