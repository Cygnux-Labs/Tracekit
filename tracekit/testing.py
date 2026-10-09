"""`FakeSigner`: an in-memory `SignerAPI` for adapter development and your own tests.

    from tracekit.testing import FakeSigner
    signer = FakeSigner(rule=lambda tool, args: ("ask", ["R1"]) if tool == "pay" else ("allow", []))

It follows the RPC contract (schemas, error codes, idempotency, run tokens, client_seq gaps, approval binding) but
signs nothing, keeps nothing on disk and has one caller identity, so approvals are always self-approvals. Ids are
deterministic.

`serve_fake(runtime_dir)` serves one as a dev signer the way tracekit/sdk/autospawn.py expects; run it as
`TRACEKIT_DEV_SIGNER_CMD="python -m tracekit.testing"` to have clients auto-spawn it.
"""
import argparse
import copy
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import signal
import sys
import threading
import time

import rfc8785

from tracekit import __version__
from tracekit.format.canon import StrictJSONError, event_hash, loads_strict
from tracekit.locking import lock_file
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import RPCError


POLICY_HASH = "sha256:" + "0" * 64


def _allow(tool, args):
    return "allow", []


class FakeSigner:
    def __init__(self, rule=_allow, identity="fake-user", tenant="default"):
        """`rule(tool, args) -> (decision, rule_ids)` with decision allow|deny|ask; args are the parsed value."""
        self.rule, self.identity, self.tenant = rule, identity, tenant
        self._n = 0
        self._done = {}        # (identity, request_id) -> (payload digest, response)
        self._runs = {}
        self._approvals = {}
        self._index = {}       # (run_id, tool_call_id, attempt) -> approval_id

    def _id(self, prefix):
        self._n += 1
        return f"{prefix}-{self._n:04d}"

    def _call(self, method, req, handler):
        errs = rpc_schema.validate(rpc_schema.REQUESTS[method], req)
        if errs:
            raise RPCError("invalid_request", "; ".join(errs))
        rid = (self.identity, req["request_id"]) if "request_id" in req else None
        key = hashlib.sha256(json.dumps([method, req], sort_keys=True, default=repr).encode()).hexdigest()
        if rid in self._done:
            if self._done[rid][0] != key:
                raise RPCError("conflict", f"request_id {rid[1]} was used with another payload")
            return copy.deepcopy(self._done[rid][1])
        out = handler(req)   # handlers raise before changing any state, so refusals are not cached
        if rid is not None:
            self._done[rid] = (key, copy.deepcopy(out))
        return out

    def _run(self, req, open_only=True):
        run = self._runs.get(req["run_id"])
        if run is None:
            raise RPCError("unknown_run", req["run_id"])
        if not hmac.compare_digest(run["token"], req["run_token"]):
            raise RPCError("run_token_invalid", "token does not belong to this run")
        if open_only and run["closed"]:
            raise RPCError("run_closed", req["run_id"])
        return run

    def _check_seq(self, run, req):
        if req["client_seq"] <= run["streams"].get(req["stream"], -1):
            raise RPCError("client_seq_reused", f"{req['stream']}/{req['client_seq']}")

    def _append(self, run, typ, data, req=None):
        if req is not None:   # an event call: record skipped client_seq values as a gap, then advance
            last = run["streams"].get(req["stream"], -1)
            if req["client_seq"] > last + 1:
                self._append(run, "capture.gap", {"kind": "client_counter_gap", "stream": req["stream"],
                                                  "from": last + 1, "to": req["client_seq"] - 1})
            run["streams"][req["stream"]] = req["client_seq"]
        ev = {"run_seq": len(run["events"]), "type": typ, "data": data}
        ev["event_hash"] = event_hash(ev)
        run["events"].append(ev)
        return ev["run_seq"]

    def _approval(self, run_id, approval_id):
        a = self._approvals.get(approval_id)
        if a is None or a["run_id"] != run_id:
            raise RPCError("unknown_approval", approval_id)
        return a

    def register_run(self, req):
        def handle(req):
            run_id = req.get("run_id") or self._id("run")
            if run_id in self._runs:
                raise RPCError("run_exists", run_id)
            tenant = req.get("tenant", self.tenant)
            run = self._runs[run_id] = {"token": self._id("tok"), "closed": False, "events": [], "streams": {},
                                        "calls": {}, "decisions": {}}
            out = {"run_id": run_id, "run_token": run["token"], "tenant": tenant,
                   "tenant_attested": "tenant" not in req, "principal_attested": False}
            if "principal" in req:
                out["principal"] = req["principal"]
            self._append(run, "run.registered", {"agent": req["agent"], "tenant": tenant,
                                                 "tenant_attested": out["tenant_attested"]})
            return out
        return self._call("register_run", req, handle)

    def decide(self, req):
        def handle(req):
            run = self._run(req)
            self._check_seq(run, req)
            args, digest = _digest(req)
            decision, rule_ids = self.rule(req["tool"], args) if digest else ("deny", ["TK-ARGS-INVALID"])
            run["calls"][req["tool_call_id"]] = {"args_digest": digest, "decision": decision, "rule_ids": rule_ids,
                                                 "attempt": req.get("attempt", 0), "tool": req["tool"],
                                                 "args_source": req["args_source"], "args": req["args"]}
            decision_id = self._id("dec")
            run["decisions"][decision_id] = (req["tool_call_id"], req.get("attempt", 0), digest)
            seq = self._append(run, "policy.decision", {"tool_call_id": req["tool_call_id"], "tool": req["tool"],
                                                      "decision_id": decision_id,
                                                      "attempt": req.get("attempt", 0), "args_source": req["args_source"],
                                                      "decision": decision, "rule_ids": rule_ids}, req)
            return {"decision": decision, "decision_id": decision_id, "rule_ids": rule_ids, "run_seq": seq}
        return self._call("decide", req, handle)

    def _event(self, method, typ, fields, req, check=None):
        def handle(req):
            run = self._run(req)
            self._check_seq(run, req)
            if check:
                check(run, req)
            return {"run_seq": self._append(run, typ, {k: req[k] for k in fields if k in req}, req)}
        return self._call(method, req, handle)

    def complete(self, req):
        def consume(run, req):
            d = run["decisions"].get(req["decision_id"])
            if d is None or d[:2] != (req["tool_call_id"], req.get("attempt", 0)):
                raise RPCError("unknown_decision", req["decision_id"])
            if d[2] != req["args_digest"]:
                raise RPCError("args_mismatch", req["tool_call_id"])
            run["decisions"][req["decision_id"]] = None
        return self._event("complete", "tool.result", ("tool_call_id", "decision_id", "attempt", "status", "error"), req,
                           check=consume)

    def state_write(self, req):
        return self._event("state_write", "state.write", ("key", "value_digest"), req)

    def model_event(self, req):
        return self._event("model_event", "model.event", ("provider", "model", "phase", "content_digest", "usage"), req)

    def approval_request(self, req):
        def handle(req):
            run, attempt = self._run(req), req.get("attempt", 0)
            k = (req["run_id"], req["tool_call_id"], attempt)
            if k in self._index:
                a = self._approvals[self._index[k]]
                return {"approval_id": self._index[k], "state": a["state"], "expires_at": a["expires_at"]}
            call = run["calls"].get(req["tool_call_id"])
            if call is None or call["decision"] != "ask" or call["attempt"] != attempt:
                raise RPCError("unknown_tool_call", f"{req['tool_call_id']} has no pending `ask` decision")
            approval_id = self._index[k] = self._id("apr")
            # lean: approvals never expire here; the real signer enforces expires_at
            expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                          ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            a = self._approvals[approval_id] = {
                "run_id": req["run_id"], "tool_call_id": req["tool_call_id"], "attempt": attempt, "tool": call["tool"],
                "args_source": call["args_source"], "args": call["args"], "args_digest": call["args_digest"],
                "rule_ids": call["rule_ids"], "policy_hash": POLICY_HASH, "requester": self.identity,
                "expires_at": expires_at, "state": "requested", **({"reason": req["reason"]} if "reason" in req else {})}
            a["binding_digest"] = event_hash({"v": 1, "approval_id": approval_id, "nonce": self._id("nonce"),
                                              **{k: a[k] for k in ("run_id", "tool_call_id", "attempt", "tool",
                                                                   "args_digest", "args_source", "policy_hash",
                                                                   "expires_at")}})
            self._append(run, "approval.request", {"approval_id": approval_id, "tool_call_id": req["tool_call_id"],
                                                   "rule_ids": call["rule_ids"], "binding_digest": a["binding_digest"]})
            return {"approval_id": approval_id, "state": "requested", "expires_at": expires_at}
        return self._call("approval_request", req, handle)

    def approval_decide(self, req):
        def handle(req):
            a = self._approvals.get(req["approval_id"])
            if a is None:
                raise RPCError("unknown_approval", req["approval_id"])
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            run = self._runs[a["run_id"]]
            if run["closed"]:
                raise RPCError("run_closed", a["run_id"])
            a["state"] = "approved" if req["decision"] == "approve" else "rejected"
            self._append(run, "approval", {"approval_id": req["approval_id"], "decision": req["decision"],
                                           "approver": self.identity, "self_approved": True})
            return {"approval_id": req["approval_id"], "state": a["state"], "self_approved": True}
        return self._call("approval_decide", req, handle)

    def approval_wait(self, req):
        def handle(req):
            self._run(req, open_only=False)
            # lean: answers at once; a real signer blocks up to timeout_ms
            return {"approval_id": req["approval_id"], "state": self._approval(req["run_id"], req["approval_id"])["state"]}
        return self._call("approval_wait", req, handle)

    def approval_consume(self, req):
        def handle(req):
            run, attempt, hint = self._run(req), req.get("attempt", 0), req.get("approval_id_hint")
            aid = self._index.get((req["run_id"], req["tool_call_id"], attempt))
            a, call = self._approvals.get(aid), run["calls"].get(req["tool_call_id"])
            digest = _digest(req)[1]
            if hint is not None and hint != aid:
                code = "TK-APPROVAL-UNBOUND"
            elif digest is None:
                code = "TK-ARGS-INVALID"
            elif a is None:
                if call and call["attempt"] == attempt and call["decision"] == "allow" and call["args_digest"] == digest:
                    return {"ok": True, "rule_ids": []}
                code = "TK-APPROVAL-REQUIRED"
            elif a["args_digest"] != digest:
                self._append(run, "approval.binding_mismatch", {"approval_id": aid, "tool_call_id": req["tool_call_id"]})
                return {"ok": False, "rule_ids": ["TK-APPROVAL-MISMATCH"], "approval_id": aid}
            elif a["state"] != "approved":
                code = "TK-APPROVAL-" + a["state"].upper()
            else:
                a["state"] = "consumed"
                self._append(run, "approval.consumed", {"approval_id": aid})
                return {"ok": True, "rule_ids": ["TK-APPROVED"], "approval_id": aid}
            self._append(run, "approval.refused", {"tool_call_id": req["tool_call_id"], "rule_ids": [code]})
            return {"ok": False, "rule_ids": [code], **({"approval_id": aid} if a else {})}
        return self._call("approval_consume", req, handle)

    def approval_get(self, req):
        def handle(req):
            a = self._approvals.get(req["approval_id"])
            if a is None:
                raise RPCError("unknown_approval", req["approval_id"])
            return {"approval_id": req["approval_id"], **{k: v for k, v in a.items() if k != "args_digest"}}
        return self._call("approval_get", req, handle)

    def approval_list(self, req):
        return self._call("approval_list", req, lambda req: {"approvals": [
            {"approval_id": aid, **{k: a[k] for k in rpc_schema.RESPONSES["approval_list"]["properties"]["approvals"]
                                    ["items"]["required"] if k != "approval_id"}}
            for aid, a in self._approvals.items() if req.get("run_id") in (None, a["run_id"])]})

    def close_run(self, req):
        def handle(req):
            run = self._run(req)
            run["closed"] = True
            return {"run_id": req["run_id"], "state": "closing",
                    "run_seq": self._append(run, "run.closing", {"reason": req.get("reason")})}
        return self._call("close_run", req, handle)

    def status(self, req):
        return self._call("status", req, lambda req: {
            "rpc_version": rpc_schema.RPC_VERSION, "signer": {"name": "tracekit.testing.FakeSigner", "version": __version__},
            "identity": {"scheme": "fake", "subject": self.identity, "attested": False}})

    def read(self, req):
        def handle(req):
            events = self._run(req, open_only=False)["events"]
            start = req.get("from_seq", 0)
            end = start + req.get("limit", 100)
            return {"events": copy.deepcopy(events[start:end]), "next_seq": end if end < len(events) else None}
        return self._call("read", req, handle)

    def checkpoint_nudge(self, req):
        return self._call("checkpoint_nudge", req, lambda req: {"scheduled": True})


def _digest(req):
    """(the parsed arguments, sha256(JCS({tool, args}))), or (None, None) when they are not canonical JSON."""
    try:
        args = loads_strict(req["args"]) if req["args_source"] == "raw" else req["args"]
        return args, event_hash({"tool": req["tool"], "args": args})
    except (StrictJSONError, rfc8785.CanonicalizationError):
        return None, None


def serve_fake(runtime_dir, signer=None, proto=(rpc_schema.RPC_VERSION, rpc_schema.RPC_VERSION), version=__version__,
               idle_s=900):
    """Serve `signer` (a new FakeSigner by default) in `runtime_dir` until SIGTERM or `idle_s` seconds without a
    frame (0: never). Follows decision S3: lock signer.lock first (give up after 1 s), then replace the socket, then
    publish endpoint.json; unpublish before exiting. Call it from the main thread; returns an exit code."""
    from tracekit.deploy import files
    from tracekit.sdk import autospawn
    from tracekit.transport.unix import UnixServer

    lock = open(os.path.join(runtime_dir, autospawn.LOCK), "a")
    deadline = time.monotonic() + 1
    while True:
        try:
            lock_file(lock, blocking=False)
            break
        except OSError:
            if time.monotonic() > deadline:
                print("LOST: another dev signer holds signer.lock", file=sys.stderr)
                return 1
            time.sleep(0.05)
    sock, endpoint = os.path.join(runtime_dir, autospawn.SOCK), os.path.join(runtime_dir, autospawn.ENDPOINT)
    for p in (sock, endpoint):
        pathlib.Path(p).unlink(missing_ok=True)
    signer, mutex, last = signer or FakeSigner(), threading.Lock(), [time.monotonic()]
    hello = {"proto": list(proto), "version": version, "pid": os.getpid()}

    def handle(identity, frame):
        last[0] = time.monotonic()
        method = frame.pop("method", None)
        if method == "hello":
            return hello
        if method not in rpc_schema.REQUESTS:
            raise RPCError("invalid_request", f"unknown method {str(method)[:64]}")
        with mutex:
            return getattr(signer, method)(frame)

    server = UnixServer(sock, handle)
    files.write_json(endpoint, hello)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"SERVING pid {os.getpid()}", file=sys.stderr, flush=True)
    while not stop.wait(0.1):
        if idle_s and time.monotonic() - last[0] > idle_s:
            break
    for p in (endpoint, sock):
        pathlib.Path(p).unlink(missing_ok=True)
    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":
    from tracekit.sdk.autospawn import runtime_dir
    ap = argparse.ArgumentParser(prog="python -m tracekit.testing", description="serve a FakeSigner as the dev signer")
    ap.add_argument("--proto", default=f"{rpc_schema.RPC_VERSION}-{rpc_schema.RPC_VERSION}", help="MIN-MAX")
    ap.add_argument("--version", default=__version__)
    ap.add_argument("--ask", action="append", default=[], metavar="TOOL", help="answer `ask` for this tool")
    a = ap.parse_args()
    signer = FakeSigner(lambda tool, args: ("ask", ["FAKE-ASK"]) if tool in a.ask else ("allow", []))
    sys.exit(serve_fake(runtime_dir(), signer, proto=tuple(map(int, a.proto.split("-"))), version=a.version,
                        idle_s=float(os.environ.get("TRACEKIT_DEV_IDLE", 900))))
