"""agentgateway's `ext_mcp` processor (experimental): agentgateway calls it over gRPC
(`agentgateway.dev.ext_mcp.ExtMcp`, its crates/protos/proto/ext_mcp.proto) before it forwards each MCP `tools/call` and
with the call's result; Tracekit decides the call in the signer and records the result. docs/integrations/agentgateway.md.

    tracekit ext-mcp serve [--listen 127.0.0.1:9091] [--signer URL]   # needs grpcio; its identity: $TRACEKIT_SIGNER_*

agentgateway's `mcpGuardrails`: a remote processor for `{tools/call: full}`, `failureMode: failClosed` (its default),
with metadata `caller` (the identity agentgateway authenticated, as the signer names it) and `tracekit_call`
(`mcpGuardrails.tracekit_call`, which carries the call's id from the request hook to the response hook).

CheckRequest (tools/call): the run is the agent's `X-Tracekit-Run: <run_id>.<run token>` header, which agentgateway
forwards; the call is decided as `mcp:<service>/<tool>` with its arguments, for `caller`, under that run token, so the
records are source gateway, tier T2, as at the MCP gateway (executor.Custody). Allowed: Pass, with the call's
tool_call_id as metadata `tracekit_call`. Anything else is an AuthorizationError (PERMISSION_DENIED) saying why: a deny,
an unanswered approval, the signer unreachable, no run or caller, params that don't parse (fail closed). agentgateway
gives a processor 10 s, so an `ask` waits APPROVAL_WAIT_S and is then refused as pending; the same call again (same run,
caller, tool and arguments) takes up that approval and passes once a person approved it.
CheckResponse (tools/call): the result completes the call metadata `tracekit_call` names (an `isError` result as an
error) and passes: the call ran. JSON-RPC errors skip this hook, so such a call gets no result here; the signer writes
a held_call_unresolved gap for it when its run ends. Other methods pass undecided.
"""
import argparse
import collections
import concurrent.futures
import json
import sys
import threading
import uuid

from tracekit.executor import Custody
from tracekit.format.canon import event_hash
from tracekit.observe import LOOPBACK_HOSTS
from tracekit.otlp_wire import WireError, _fields, _s, varint
from tracekit.sdk.client import Client, result_field

SERVICE = "agentgateway.dev.ext_mcp.ExtMcp"
RUN_HEADER = "x-tracekit-run"
CALL = "tracekit_call"   # the metadata key that carries a call's tool_call_id to its response
APPROVAL_WAIT_S = 5      # agentgateway gives a processor 10 s (mcp/guardrails/client.rs), decide and consume included
PENDING = ": approval requested"   # how Custody.gate ends the refusal of an ask still waiting for a person
MAX_CALLS = 10_000       # calls awaiting their result, and asks awaiting their retry, each; the least recent go first
PASS = b"\x0a\x00"       # McpRequestResult / McpResponseResult: pass (1), an empty Pass


def _ld(field, data):
    return bytes([field << 3 | 2]) + varint(len(data)) + data


def _refused(why):
    """result error (3): AuthorizationError {code (1) PERMISSION_DENIED, reason (2)}."""
    return _ld(3, b"\x08\x01" + _ld(2, f"tracekit: {why}"[:2048].encode()))


def _passed(tcid):
    """McpRequestResult: pass, metadata (5) Struct {fields (1): {key (1): CALL, value (2): Value {string_value (3)}}}."""
    return PASS + _ld(5, _ld(1, _ld(1, CALL.encode()) + _ld(2, _ld(3, tcid.encode()))))


def _strings(buf):
    """The string values of a google.protobuf.Struct (map<string, Value> fields = 1): {key: value}."""
    out = {}
    for fn, wt, entry in _fields(buf):
        if fn == 1 and wt == 2:
            k = v = None
            for f2, w2, x in _fields(entry):
                if f2 == 1 and w2 == 2:
                    k = _s(x)
                elif f2 == 2 and w2 == 2:
                    v = next((_s(y) for f3, w3, y in _fields(x) if f3 == 3 and w3 == 2), None)
            if k is not None and v is not None:
                out[k] = v
    return out


def _decode(body):
    """McpRequest or McpResponse: service_names (1), method (2), metadata_context (3), the JSON-RPC params or result
    (4), headers (5, McpRequest only: McpHeader {key (1), value (2)}, the first of each name, lowercased)."""
    m = {"service_names": [], "method": "", "metadata": {}, "body": None, "headers": {}}
    for fn, wt, v in _fields(memoryview(body)):
        if wt != 2:
            continue
        if fn == 1:
            m["service_names"].append(_s(v))
        elif fn == 2:
            m["method"] = _s(v)
        elif fn == 3:
            m["metadata"] = _strings(v)
        elif fn == 4:
            m["body"] = bytes(v)
        elif fn == 5:
            h = {f: _s(x) for f, w, x in _fields(v) if w == 2}
            m["headers"].setdefault(h.get(1, "").lower(), h.get(2, ""))
    return m


class ExtMcp:
    def __init__(self, client):
        self.custody, self.lock = Custody(client, APPROVAL_WAIT_S), threading.Lock()
        # lean: in this process's memory, MAX_CALLS each: a restart forgets pending asks (the retry asks again) and the
        # calls awaiting a result (a held_call_unresolved gap); keep them on disk if processors restart mid-run
        self.calls = collections.OrderedDict()   # tool_call_id -> (key, decision, tool, args): passed, no result yet
        self.asked = collections.OrderedDict()   # (key, digest of tool and args) -> tool_call_id of a pending ask

    def _keep(self, d, k, v):
        with self.lock:
            d[k] = v
            d.move_to_end(k)
            while len(d) > MAX_CALLS:
                d.popitem(last=False)

    def check_request(self, body, _context=None):
        try:
            m = _decode(body)
            if m["method"] != "tools/call":
                return PASS
            params = json.loads(m["body"] or b"")
            [service] = m["service_names"]
            tool, args = f"mcp:{service}/{params['name']}", params.get("arguments") or {}
            digest = event_hash({"tool": tool, "args": args})
        except (WireError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
            return _refused(f"a tools/call that doesn't parse ({type(e).__name__}): nothing ran")
        run, caller = m["headers"].get(RUN_HEADER, ""), m["metadata"].get("caller")
        parts = run.rsplit(".", 2)   # a run token is <payload>.<mac>
        if len(parts) != 3 or not all(parts) or not caller:
            return _refused("no run or caller: the agent sends X-Tracekit-Run: <run_id>.<run token>, and agentgateway's "
                            "processor metadata names the caller")
        key = (parts[0], f"{parts[1]}.{parts[2]}", caller)
        with self.lock:
            tcid = self.asked.pop((key, digest), None) or "agw-" + uuid.uuid4().hex
        why, d, _ = self.custody.gate(key, tcid, tool, args)
        if why is None:
            self._keep(self.calls, tcid, (key, d, tool, args))
            return _passed(tcid)
        if why[1].endswith(PENDING):
            self._keep(self.asked, (key, digest), tcid)
            return _refused(f"{why[1]}; make the same call again once a person approves it")
        return _refused(why[1])

    def check_response(self, body, _context=None):
        try:
            m = _decode(body)
        except WireError as e:
            print(f"tracekit ext-mcp: a result that doesn't parse ({e}) was not recorded", file=sys.stderr)
            return PASS
        if m["method"] != "tools/call":
            return PASS
        tcid = m["metadata"].get(CALL)
        with self.lock:
            held = self.calls.pop(tcid, None)
        if held is None:
            print(f"tracekit ext-mcp: a tools/call result was not recorded: {CALL} {str(tcid)[:128]} names no call this "
                  f"processor passed since it started (agentgateway's processor metadata needs {CALL}: "
                  f"'mcpGuardrails.{CALL}')", file=sys.stderr)
            return PASS
        key, d, tool, args = held
        try:
            out = json.loads(m["body"] or b"null")
        except ValueError:
            out = (m["body"] or b"").decode("utf-8", "replace")
        self.custody.complete(key, tcid, d, tool, args, "error" if isinstance(out, dict) and out.get("isError") else "ok",
                              result=result_field(True, out))
        return PASS


def serve(listen="127.0.0.1:9091", client=None, max_workers=16):
    """The processor on gRPC at `listen`, started: (server, bound port). Needs grpcio; requests are decoded by hand
    (no generated stubs), as the OTLP/gRPC receiver does."""
    try:
        import grpc
    except ImportError as e:
        raise RuntimeError("tracekit ext-mcp needs grpcio: pip install 'tracekit-ai[grpc]'") from e
    p = ExtMcp(client or Client())
    handler = grpc.method_handlers_generic_handler(SERVICE, {
        "CheckRequest": grpc.unary_unary_rpc_method_handler(p.check_request),
        "CheckResponse": grpc.unary_unary_rpc_method_handler(p.check_response)})
    srv = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=max_workers))
    srv.add_generic_rpc_handlers((handler,))
    port = srv.add_insecure_port(listen)
    srv.start()
    return srv, port


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit ext-mcp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="answer agentgateway's ext_mcp calls (gRPC, loopback only)")
    s.add_argument("--listen", default="127.0.0.1:9091", help="host:port, on loopback (default 127.0.0.1:9091)")
    s.add_argument("--signer", help="the v2 signer (default: $TRACEKIT_SIGNER or the system config)")
    a = ap.parse_args(argv)
    host = a.listen.rpartition(":")[0].strip("[]")
    # lean: plaintext gRPC on loopback only, for agentgateway on the same host or pod where the agent can't connect; add
    # mTLS (grpc.ssl_server_credentials with require_client_auth) when agentgateway must reach it across hosts
    if host not in LOOPBACK_HOSTS:
        print("tracekit ext-mcp: listens on loopback only (127.0.0.1, ::1): run it next to agentgateway",
              file=sys.stderr)
        return 2
    try:
        srv, port = serve(a.listen, Client(a.signer))
    except RuntimeError as e:
        print(f"tracekit ext-mcp: {e}", file=sys.stderr)
        return 2
    print(f"tracekit ext-mcp: grpc://{a.listen.rpartition(':')[0]}:{port}", flush=True)
    try:
        srv.wait_for_termination()
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop(None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
