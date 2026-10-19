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
        url_template: https://api.github.com/repos/{owner}/{repo}/issues   # {arg}: that argument (_url)
        headers: {authorization: secrets/github.header}   # header -> the file holding its value (a secret: cut)
        settings: {x-github-api-version: "2022-06-28"}   # headers given inline: not secrets, never cut
        args: {type: object, required: [owner, repo, title], additionalProperties: false,
               properties: {owner: {type: string}, repo: {type: string}, title: {type: string}}}

`GET /v1/actions` lists the actions (name, description, args schema) to any identity the authenticators accept; the
client helpers (tracekit.integrations.executor_tools, @cygnuxlabs/tracekit/v2/executor) build framework tools from it.
The agent calls `POST /v1/actions/<name>` with its run, as at the LLM gateway (`X-Tracekit-Run: <run_id>.<run token>`
and an identity the authenticators accept), and `{"args": {...}, "tool_call_id": "..."}` (the model's id for the call,
optional). The arguments must match the action's `args` schema (400). The executor decides through the signer with
`caller` (the agent's identity) under the agent's run token, so the records are source gateway, tier T2; on `ask` it
holds the call until a person decides or approval_wait_s passes; it consumes the approval (an approval with a T2
executor returns the signer's copy of the arguments, which is what runs); it sends the request, the arguments as its
JSON body (none for GET and DELETE), with the action's headers; and it completes the call with the response, which the
signer redacts. The agent gets `{"status": <the upstream's>, "result": <its JSON or text>}`. A denial or any other
refusal: 403; the signer unreachable: 503 (fail closed, whatever the run's fail modes); the request not sent, or its
response unreadable once sent: 502, completed as an error saying which. The header values never reach the agent or the
signer: each is cut from the response's decoded strings and from errors before they are recorded or answered.
A call it decided is held by it: the signer takes its completion and approval steps from no one else (the agent's own
run token included). Relative paths are from the config file.
"""
import argparse
import base64
import html
import http.client
import json
import os
import re
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
from tracekit.sdk.client import Client, SignerUnavailable, named_rules, result_field
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import http as transport

KEYS = {"http", "signer", "actions", "approval_wait_s", "max_body"}
ACTION_KEYS = {"name", "description", "method", "url_template", "headers", "settings", "args"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
NO_BODY = {"GET", "DELETE"}
MAX_BODY = 1 << 20
APPROVAL_WAIT_S = 300
UPSTREAM_TIMEOUT_S = 60
REDACTED = "[REDACTED:executor_secret]"
SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")   # an {arg} in a URL path
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
HEADER_VALUE = re.compile(r"[\t\x20-\x7e]*")
MIN_SECRET = 8   # characters: a shorter value ("1", "info") is not cut, as it would cut every answer


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
                return (403, "denied by policy: " + (named_rules(d["rule_ids"]) or "deny")), None, None
            hint = {}
            if d["decision"] == "ask":
                hint = {"approval_id_hint": self.client.approval_request({**base, "tool_call_id": tcid})["approval_id"]}
                state, end = "requested", time.monotonic() + self.wait_s
                while state == "requested":   # asked at least once: with no wait, an approval given already counts
                    try:
                        state = self.client.approval_wait({
                            **base, "approval_id": hint["approval_id_hint"],
                            "timeout_ms": int(max(0, min(end - time.monotonic(), 300)) * 1000)})["state"]
                    except RPCError as e:   # this client's other waits hold every slot: still requested, ask again
                        if e.code != "quota_exceeded":
                            raise
                        time.sleep(max(0, min((e.retry_after_ms or 1000) / 1000, end - time.monotonic())))
                    if end <= time.monotonic():
                        break
                if state != "approved":
                    return (403, f"{', '.join(d['rule_ids'])}: approval {state}"), None, None
            c = self.client.approval_consume({**call, **hint})
        except SignerUnavailable as e:
            return (503, f"the signer is unreachable ({e}); nothing ran"), None, None
        except RPCError as e:
            return (503 if e.code == "unavailable" else 403, f"the signer refused the call: {e}"), None, None
        if not c["ok"]:
            return (403, named_rules(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else "")), None, None
        return None, d, c.get("args", args)

    def complete(self, key, tcid, d, tool, args, status, args_digest=None, **outcome):
        """Record the outcome, trying twice under one request_id; a failure to record warns (the call ran: its result
        still goes to the client). `args_digest`: event_hash({tool, args}), for a caller that kept only that."""
        run_id, token, caller = key
        req = {"request_id": uuid.uuid4().hex, "run_id": run_id, "run_token": token, "caller": caller,
               "tool_call_id": tcid, "decision_id": d["decision_id"],
               "args_digest": args_digest or event_hash({"tool": tool, "args": args}), "status": status, **outcome}
        for attempt in (1, 2):
            try:
                self.client.complete(req)
                return
            except SignerUnavailable as e:
                err = e
            except RPCError as e:
                if e.code == "conflict":   # the retry of a first try that was recorded (it took another client_seq)
                    return
                err = e
                if e.code not in ("unavailable", "quota_exceeded"):
                    break
            if attempt == 1:
                time.sleep(min((getattr(err, "retry_after_ms", None) or 1000) / 1000, 5))
        print(f"tracekit: the outcome of {tool} call {tcid} (run {run_id}, decision {d['decision_id']}) was not "
              f"recorded: {err}. It ran and its result went to the client; the run shows the decision without a "
              "tool.result. Check that the signer is reachable and this service may complete calls (authorize).",
              file=sys.stderr)


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

    def do_POST(self):
        ex, path = self.server.executor, self.path.split("?")[0]
        got = self._authenticated(ex["max_body"])   # first: only a caller it accepts learns which actions exist
        if got is None:
            return
        action = ex["actions"].get(path[len("/v1/actions/"):]) if path.startswith("/v1/actions/") else None
        if action is None:
            return self._error(404, "no such action: GET /v1/actions lists them")
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
        except (http.client.HTTPException, OSError, ValueError) as e:
            err = cut(f"upstream unreachable, the request was not sent: {e.args[0]}" if isinstance(e, Unsent) else
                      f"the request was sent but its response could not be read ({e}): the action may have run; "
                      "check before running it again", action["cut"])
            ex["custody"].complete(key, tcid, d, action["name"], args, "error", error=err[:4096])
            return self._error(502, err)
        ex["custody"].complete(key, tcid, d, action["name"], args, "ok" if status < 400 else "error",
                               result=result_field(True, {"status": status, "result": result}))
        self._json(200, {"status": status, "result": result})


def _url(action, args):
    """The action's URL for `args`: an {arg} in the path is one plain segment (a slash, backslash or dot segment
    could leave it once a proxy decodes it), one in the query is URL-quoted."""
    for f in sorted(action["path_fields"]):
        if not (SEGMENT.fullmatch(str(args[f])) and str(args[f]).strip(".")):
            raise ValueError(f"{f}: an argument in the URL path takes letters, digits and . _ ~ - and isn't all dots")
    return action["url_template"].format_map({k: urllib.parse.quote(str(v), safe="") for k, v in args.items()})


class Unsent(OSError):
    """The action's request was not sent: connecting or sending it failed."""


def _send(action, args, max_body):
    """(status, the response's JSON or text, with every header value cut out (secret_values)) of the action's request
    for `args`. Unsent when it wasn't sent; any other error once it was."""
    url = _url(action, args)
    body = None if action["method"] in NO_BODY else json.dumps(args).encode()
    req = urllib.request.Request(url, data=body, method=action["method"],
                                 headers={"content-type": "application/json", "accept-encoding": "identity",
                                          **action["headers"]})
    try:
        resp = OPEN(req, timeout=UPSTREAM_TIMEOUT_S)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, ValueError) as e:   # urllib wraps a failure to connect or send (a ValueError: a
        raise Unsent(getattr(e, "reason", e)) from None   # header it refused); reading the answer raises as is
    with resp:
        status, data = resp.getcode(), resp.read(max_body + 1)
    if len(data) > max_body:
        raise ValueError(f"upstream response over {max_body} bytes")
    text = data.decode("utf-8", "replace")
    try:
        try:
            value = json.loads(text)
        except ValueError:
            value = text
        return status, cut(value, action["cut"])   # from the decoded strings: an escaped value is a value too
    except RecursionError:
        raise ValueError("the response nests too deeply to cut the credentials out of it") from None


def cut(x, values):
    """`x` (JSON) with each of `values` (secret_values) replaced by REDACTED in every string value; keys, its
    structure, are left as they are."""
    if isinstance(x, str):
        for v in values:
            x = x.replace(v, REDACTED)
        return x
    if isinstance(x, list):
        return [cut(v, values) for v in x]
    if isinstance(x, dict):
        return {k: cut(v, values) for k, v in x.items()}
    return x


def read_secret(path, header):
    """The value file `path` holds, stripped; one a header can carry (one line of printable ASCII) when `header`."""
    try:
        with open(path, encoding="utf-8") as f:
            value = f.read().strip()
    except UnicodeDecodeError:
        raise ValueError(f"{path}: not UTF-8 text") from None
    if header and not HEADER_VALUE.fullmatch(value):
        raise ValueError(f"{path}: a header value is one line of printable ASCII; this one has a line break, a control "
                         "character or a non-ASCII character")
    return value


def secret_values(values):
    """What to cut from responses, longest first: each value, of an `<auth scheme> <credential>` value the credential
    alone, and of a Basic credential its decoded user:password and password; each in the forms a response may carry it
    in (JSON-escaped, also with `\\/`, and every character `\\u`-escaped; percent-encoded; HTML-escaped, also with
    `&#x2F;`); none shorter than MIN_SECRET. An encoding beyond these (base64, a hash) isn't recognised."""
    out = set()
    for v in values:
        scheme, _, cred = v.partition(" ")
        parts = [v, *v.split()[-1:]]
        if scheme.lower() == "basic":
            try:
                userpass = base64.b64decode(cred.strip(), validate=True).decode("utf-8")
                parts += [userpass, userpass.partition(":")[2]]
            except ValueError:   # not base64 of UTF-8 text (UnicodeDecodeError is a ValueError)
                pass
        for p in parts:
            if len(p) >= MIN_SECRET:
                escaped = json.dumps(p)[1:-1]
                out |= {p, escaped, escaped.replace("/", "\\/"), "".join(f"\\u{ord(c):04x}" for c in p),
                        urllib.parse.quote(p), urllib.parse.quote(p, safe=""), urllib.parse.quote_plus(p),
                        html.escape(p), html.escape(p).replace("/", "&#x2F;")}
    return sorted(out, key=len, reverse=True)


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
        path = {f for _, f, _, _ in string.Formatter().parse(a["url_template"].split("?", 1)[0]) if f is not None}
        headers, settings = a.get("headers", {}), a.get("settings", {})
        if not (isinstance(headers, dict) and all(isinstance(v, str) and HEADER_NAME.fullmatch(k)
                                                  for k, v in headers.items())):
            raise ValueError(f"{where}: headers maps a header name to the file holding its value")
        if not (isinstance(settings, dict) and all(isinstance(v, str) and HEADER_NAME.fullmatch(k) and
                                                   HEADER_VALUE.fullmatch(v) for k, v in settings.items())) \
                or {k.lower() for k in settings} & {k.lower() for k in headers}:
            raise ValueError(f"{where}: settings maps a header name, not one in headers, to its value (one line of "
                             "printable ASCII)")
        actions[a["name"]] = dict(a, fields=fields, path_fields=path, settings=settings,
                                  headers={k: os.path.join(base, v) for k, v in headers.items()})
    cfg["actions"] = actions
    transport.resolve(cfg["http"], base)
    return cfg


def serve(cfg, client=None):
    """The executor's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    actions = {}
    for name, a in cfg["actions"].items():
        headers = {k: read_secret(p, header=True) for k, p in a["headers"].items()}
        actions[name] = dict(a, headers={**a["settings"], **headers}, cut=secret_values(headers.values()))
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
