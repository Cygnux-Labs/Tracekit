"""MCP gateway (tier T2): an MCP server the agent connects to, proxying configured upstream MCP servers whose
credentials stay in the gateway; every tool call is decided, run and completed in the signer by the gateway, for the
agent's run. docs/mcp-gateway.md.

    tracekit mcp-gateway serve --config mcp-gateway.yaml

mcp-gateway.yaml:
    http: {listen: 0.0.0.0:8091, cert: tls/mcp.pem, key: tls/mcp.key, authenticators: [mtls, k8s_sa, token]}
                                           # who may call: the signer's `http` section (tracekit/transport/http.py)
    signer: https://signer.internal:8443   # the gateway's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client);
                                           # signer.yaml lists it under `gateways`
    approval_wait_s: 300                   # how long a call the policy asks about waits for a person
    max_body: 1048576                      # request bodies
    upstreams:
      - name: notion                       # [A-Za-z0-9-]+: tools are listed as notion__<tool>
        command: [npx, -y, "@notionhq/notion-mcp-server@2.5.2"]   # stdio: the gateway runs it, as its own uid;
        env: {NOTION_TOKEN: secrets/notion.token}                # pin the version. variable -> the file holding it
      - name: linear
        url: https://mcp.linear.app/mcp                              # Streamable HTTP
        headers: {authorization: secrets/linear.header}             # header -> the file holding its value
    trusted: []                            # upstreams whose resources are recorded trusted: only ones whose content
                                           # neither the agent nor outsiders can write

The agent's MCP client connects over Streamable HTTP to `POST /mcp` with its run, as at the LLM gateway
(`X-Tracekit-Run: <run_id>.<run token>` and an identity the authenticators accept); the gateway answers each request
with one JSON response and keeps no session. tools/list passes each upstream's tools through as `<upstream>__<tool>`;
tools/call is decided as `mcp:<upstream>/<tool>` (the name the MCP client adapter records), with `caller` (the agent's
identity) under the agent's run token, so the records are source gateway, tier T2; on `ask` the call waits for a
person, up to approval_wait_s; the gateway consumes the approval (an approval with a T2 executor returns the signer's
copy of the arguments, which is what runs), calls the upstream and completes the call with its result, which the
signer redacts. A denial, a refusal or the signer unreachable (fail closed, whatever the run's fail modes) is a tool
result with `isError: true` and the reason, and the upstream never sees the call. prompts/get sends the agent's
arguments upstream too, so it is decided, run and completed the same way, as `mcp:<upstream>/prompt:<name>` (a refusal
is an error response). Resources (resources/list, read) and prompts (prompts/list, listed as `<upstream>__<prompt>`)
pass through; each resource read and prompt got is recorded as an observed input (`observe`, source
`mcp:<upstream>/resource` or `/prompt`): a prompt untrusted (a template echoes its arguments), a resource untrusted
unless its upstream is in `trusted`. The upstreams' credentials never reach the agent or the signer: each value is cut
from the decoded strings of everything the gateway answers or records. Relative paths are from the config file.
"""
import asyncio
import concurrent.futures
import os
import re
import threading
import uuid

from tracekit import __version__, yamlmini
from tracekit.client import remote_url_error
from tracekit.executor import APPROVAL_WAIT_S, MAX_BODY, Custody, cut, main as _main, read_secret, secret_values
from tracekit.gateway import _Handler
from tracekit.sdk.client import Client, SignerUnavailable, result_field
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import http as transport

KEYS = {"http", "signer", "upstreams", "trusted", "approval_wait_s", "max_body"}
UPSTREAM_KEYS = {"name", "command", "env", "url", "headers"}
NAME = re.compile(r"[A-Za-z0-9-]+")
SEP = "__"
PROTOCOL = "2025-06-18"   # answered to an initialize that names no protocol version
UPSTREAM_TIMEOUT_S = 600
BLOCKED = "Tool call blocked by policy: "
MAX_RESOURCES = 10000   # resource URI -> its upstream, as listed


class Upstreams:
    """One session per upstream MCP server, held open on an event loop of its own; `call(name, method, *a)` runs one
    of the mcp Client's methods on it from any thread."""

    def __init__(self, targets):
        """`targets`: upstream name -> what mcp.Client connects to (StdioServerParameters, a transport, a server)."""
        from mcp import Client
        self.loop, self.clients = asyncio.new_event_loop(), {}
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self._stop = asyncio.Event()

        async def hold(name, target, ready):
            try:
                async with Client(target) as c:
                    self.clients[name] = c
                    ready.set_result(None)
                    await self._stop.wait()
            except BaseException as e:
                if not ready.done():
                    ready.set_exception(e)
                raise
        self._held = []
        for name, target in targets.items():
            ready = concurrent.futures.Future()
            self._held.append(asyncio.run_coroutine_threadsafe(hold(name, target, ready), self.loop))
            ready.result(UPSTREAM_TIMEOUT_S)

    def _run(self, coro, timeout=UPSTREAM_TIMEOUT_S):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def call(self, name, method, *a):
        return self._run(getattr(self.clients[name], method)(*a))

    def close(self):
        self.loop.call_soon_threadsafe(self._stop.set)
        for h in self._held:
            try:
                h.result(10)
            except Exception:   # an upstream that failed or went away: nothing left to close
                pass
        self.loop.call_soon_threadsafe(self.loop.stop)


def _dump(x):
    return x.model_dump(mode="json", by_alias=True, exclude_none=True)


class _McpGateway(_Handler):
    NAME = "tracekit mcp-gateway"

    def do_GET(self):   # no server-initiated stream: every answer is the response to its POST
        self._error(405, "POST /mcp", close=False)

    do_DELETE = do_GET

    def do_POST(self):
        gw = self.server.mcp
        if self.path.split("?")[0] != "/mcp":
            return self._error(404, "POST /mcp")
        got = self._authenticated(gw["max_body"])
        if got is None:
            return
        key, msg, _ = got
        if "id" not in msg:   # a notification (initialized, cancelled): nothing to answer
            self.send_response(202)
            self.send_header("content-length", "0")
            return self.end_headers()
        try:
            out = {"result": self._answer(gw, key, msg.get("method"), msg.get("params") or {})}
        except _Error as e:
            out = {"error": {"code": e.args[0], "message": e.args[1]}}
        except Exception as e:   # an upstream that failed or went away
            out = {"error": {"code": -32603, "message": f"upstream error: {type(e).__name__}: {e}; if the upstream "
                                                        "went away, restart the MCP gateway (it doesn't reconnect)"}}
        self._json(200, gw["cut"]({"jsonrpc": "2.0", "id": msg["id"], **out}))

    def _answer(self, gw, key, method, params):
        ups = gw["upstreams"]
        if method == "initialize":
            return {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "tracekit-mcp-gateway", "version": __version__}}
        if method == "ping":
            return {}
        # lean: the first page of each upstream's tools, resources and prompts; follow nextCursor if one lists more
        if method == "tools/list":
            return {"tools": [dict(_dump(t), name=up + SEP + t.name)
                              for up in ups.clients for t in ups.call(up, "list_tools").tools]}
        if method == "prompts/list":
            return {"prompts": [dict(_dump(p), name=up + SEP + p.name)
                                for up in ups.clients for p in ups.call(up, "list_prompts").prompts]}
        if method == "resources/list":
            listed = []
            for up in ups.clients:
                for r in ups.call(up, "list_resources").resources:
                    if len(gw["resources"]) >= MAX_RESOURCES:   # lean: forgets every listed URI when full, so a read
                        gw["resources"].clear()                 # asks for a new listing; an LRU if that bites
                    gw["resources"][str(r.uri)] = up
                    listed.append(_dump(r))
            return {"resources": listed}
        if method == "tools/call":
            out = self._call(gw, key, "call_tool", *_split(ups, params.get("name")), params.get("arguments") or {})
            if isinstance(out, str):
                return {"content": [{"type": "text", "text": BLOCKED + out}], "isError": True}
            return out
        if method == "prompts/get":
            up, prompt = _split(ups, params.get("name"))
            out = self._call(gw, key, "get_prompt", up, prompt, params.get("arguments") or {})
            if isinstance(out, str):
                raise _Error(-32000, "Prompt blocked: " + out)
            return self._observe(gw, key, up, "prompt", out, trusted=False)
        if method == "resources/read":
            up = gw["resources"].get(str(params.get("uri")))
            if up is None:
                raise _Error(-32602, "unknown resource: list resources first")
            return self._observe(gw, key, up, "resource", _dump(ups.call(up, "read_resource", params["uri"])))
        raise _Error(-32601, f"method not found: {str(method)[:64]}")

    def _call(self, gw, key, method, up, name, args):
        """Upstream `up`'s `method` (call_tool, get_prompt) of `name`, decided, run and completed as tool
        mcp:<up>/<name> (a prompt's: mcp:<up>/prompt:<name>): its answer, or why it may not run (a string)."""
        tool = f"mcp:{up}/" + ("prompt:" if method == "get_prompt" else "") + name
        tcid = "mcp-" + uuid.uuid4().hex
        why, d, args = gw["custody"].gate(key, tcid, tool, args)
        if why is not None:
            return why[1]
        try:
            out = gw["cut"](_dump(gw["upstreams"].call(up, method, name, args)))
        except Exception as e:
            gw["custody"].complete(key, tcid, d, tool, args, "error", error=gw["cut"](f"{type(e).__name__}: {e}")[:4096])
            raise
        gw["custody"].complete(key, tcid, d, tool, args, "error" if out.get("isError") else "ok",
                               result=result_field(True, out))
        return out

    def _observe(self, gw, key, up, kind, out, trusted=True):
        """Record `out` as an input the agent got (trusted when `trusted` and its upstream is in `trusted`); answer it
        only once recorded (fail closed)."""
        out = gw["cut"](out)
        run_id, token, caller = key
        try:
            gw["custody"].client.observe({"run_id": run_id, "run_token": token, "caller": caller,
                                          "source": f"mcp:{up}/{kind}", "value": result_field(True, out),
                                          "trust": "trusted" if trusted and up in gw["trusted"] else "untrusted"})
        except (SignerUnavailable, RPCError) as e:
            raise _Error(-32603, f"the {kind} could not be recorded, so it is withheld: {e}") from None
        return out


class _Error(Exception):
    pass


def _split(ups, name):
    up, _, rest = str(name).partition(SEP)
    if up not in ups.clients or not rest:
        raise _Error(-32602, f"unknown name {str(name)[:128]}: names are <upstream>{SEP}<name>")
    return up, rest


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
    base, seen = os.path.dirname(os.path.abspath(path)), set()
    for u in cfg["upstreams"]:
        where = f"{path}: upstream {u.get('name') if isinstance(u, dict) else u!r}"
        if not isinstance(u, dict) or set(u) - UPSTREAM_KEYS or ("command" in u) == ("url" in u):
            raise ValueError(f"{where}: a name and either command (stdio, with env) or url (with headers)")
        if not (isinstance(u.get("name"), str) and NAME.fullmatch(u["name"]) and SEP not in u["name"]) \
                or u["name"] in seen:
            raise ValueError(f"{where}: name is unique, [A-Za-z0-9-]+ without {SEP!r}")
        seen.add(u["name"])
        if "command" in u and not (isinstance(u["command"], list) and u["command"]
                                   and all(isinstance(c, str) for c in u["command"])):
            raise ValueError(f"{where}: command is a list of strings")
        if "url" in u and remote_url_error(str(u["url"])):
            raise ValueError(f"{where}: url: {remote_url_error(str(u['url']))}")
        files = u.get("env" if "command" in u else "headers", {})
        if set(u) & {"env", "headers"} - {"env" if "command" in u else "headers"} or not isinstance(files, dict) \
                or not all(isinstance(v, str) for v in files.values()):
            raise ValueError(f"{where}: env (stdio) or headers (url) maps a name to the file holding its value")
        u["secrets"] = {k: os.path.join(base, v) for k, v in files.items()}
    if not (isinstance(cfg.get("trusted", []), list) and set(cfg.get("trusted", [])) <= seen):
        raise ValueError(f"{path}: trusted lists upstream names")
    transport.resolve(cfg["http"], base)
    return cfg


def _targets(cfg):
    """What mcp.Client connects to for each upstream, with its secrets read; and every secret value."""
    import httpx2
    from mcp import StdioServerParameters
    from mcp.client.streamable_http import streamable_http_client
    targets, values = {}, []
    for u in cfg["upstreams"]:
        secrets = {k: read_secret(p, header="url" in u) for k, p in u["secrets"].items()}
        values += secrets.values()
        targets[u["name"]] = StdioServerParameters(command=u["command"][0], args=u["command"][1:], env=secrets) \
            if "command" in u else streamable_http_client(u["url"], http_client=httpx2.AsyncClient(headers=secrets))
    return targets, values


def serve(cfg, client=None, targets=None):
    """The gateway's server for a loaded config, its upstreams connected, not yet serving; stop it with shutdown()
    and server_close(). `targets`: upstream name -> an mcp.Client target, instead of the configured ones."""
    configured, values = _targets(cfg)
    values = secret_values(values)
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_McpGateway)
    srv.mcp = {"upstreams": Upstreams(targets or configured), "trusted": set(cfg.get("trusted", [])),
               "cut": lambda x: cut(x, values),
               "max_body": cfg.get("max_body", MAX_BODY), "resources": {},
               "custody": Custody(client or Client(cfg["signer"]), cfg.get("approval_wait_s", APPROVAL_WAIT_S))}
    close = srv.server_close

    def server_close():
        close()
        srv.mcp["upstreams"].close()
    srv.server_close = server_close
    return srv


def main(argv=None):
    return _main(argv, "tracekit mcp-gateway", load_config, serve)


if __name__ == "__main__":
    import sys
    sys.exit(main())
