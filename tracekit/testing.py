"""`FakeSigner`: an in-memory `SignerAPI` for adapter development and your own tests.

    from tracekit.testing import FakeSigner
    signer = FakeSigner(rule=lambda tool, args: ("ask", ["R1"]) if tool == "pay" else ("allow", []))

It follows the RPC contract (schemas, error codes, idempotency, run tokens, client_seq gaps) but signs nothing,
keeps nothing on disk and has one caller identity, so approvals are always self-approvals. Ids are deterministic.

`serve_fake(runtime_dir)` serves one as a dev signer the way tracekit/sdk/autospawn.py expects; run it as
`TRACEKIT_DEV_SIGNER_CMD="python -m tracekit.testing"` to have clients auto-spawn it.
"""
import argparse
import copy
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
                                        "calls": {}}
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
            a = self._approval(req["run_id"], req["approval_id"]) if "approval_id" in req else None
            try:
                args = loads_strict(req["args"]) if req["args_source"] == "raw" else req["args"]
                digest = event_hash({"tool": req["tool"], "args": args})
            except (StrictJSONError, rfc8785.CanonicalizationError):
                decision, rule_ids, digest = "deny", ["TK-ARGS-INVALID"], None
            else:
                if a is None:
                    decision, rule_ids = self.rule(req["tool"], args)
                elif a["tool_call_id"] != req["tool_call_id"] or a["args_digest"] != digest:
                    decision, rule_ids = "deny", ["TK-APPROVAL-MISMATCH"]
                else:
                    decision, rule_ids = {"approved": ("allow", ["TK-APPROVED"]), "requested": ("ask", a["rule_ids"])
                                          }.get(a["state"], ("deny", ["TK-APPROVAL-" + a["state"].upper()]))
            run["calls"][req["tool_call_id"]] = {"args_digest": digest, "decision": decision, "rule_ids": rule_ids}
            seq = self._append(run, "tool.decision", {"tool_call_id": req["tool_call_id"], "tool": req["tool"],
                                                      "attempt": req.get("attempt", 0), "args_source": req["args_source"],
                                                      "decision": decision, "rule_ids": rule_ids}, req)
            if decision == "allow" and a is not None:
                a["state"] = "consumed"
                self._append(run, "approval.consumed", {"approval_id": req["approval_id"]})
            return {"decision": decision, "rule_ids": rule_ids, "run_seq": seq}
        return self._call("decide", req, handle)

    def _event(self, method, typ, fields, req, need_call=False):
        def handle(req):
            run = self._run(req)
            self._check_seq(run, req)
            if need_call and req["tool_call_id"] not in run["calls"]:
                raise RPCError("unknown_tool_call", req["tool_call_id"])
            return {"run_seq": self._append(run, typ, {k: req[k] for k in fields if k in req}, req)}
        return self._call(method, req, handle)

    def complete(self, req):
        return self._event("complete", "tool.result", ("tool_call_id", "attempt", "status", "error"), req,
                           need_call=True)

    def state_write(self, req):
        return self._event("state_write", "state.write", ("key", "value_digest"), req)

    def model_event(self, req):
        return self._event("model_event", "model.event", ("provider", "model", "phase", "content_digest", "usage"), req)

    def approval_request(self, req):
        def handle(req):
            run = self._run(req)
            call = run["calls"].get(req["tool_call_id"])
            if call is None or call["decision"] != "ask":
                raise RPCError("unknown_tool_call", f"{req['tool_call_id']} has no pending `ask` decision")
            approval_id = self._id("apr")
            self._approvals[approval_id] = {"run_id": req["run_id"], "tool_call_id": req["tool_call_id"],
                                            "args_digest": call["args_digest"], "rule_ids": call["rule_ids"],
                                            "state": "requested"}
            self._append(run, "approval.request", {"approval_id": approval_id, "tool_call_id": req["tool_call_id"],
                                                   "rule_ids": call["rule_ids"]})
            return {"approval_id": approval_id, "state": "requested"}
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
            self._append(run, "approval", {"approval_id": req["approval_id"],
                                                               "decision": req["decision"], "approver": self.identity})
            return {"approval_id": req["approval_id"], "state": a["state"], "self_approved": True}
        return self._call("approval_decide", req, handle)

    def approval_wait(self, req):
        def handle(req):
            self._run(req, open_only=False)
            # lean: answers at once and never expires approvals; a real signer blocks up to timeout_ms
            return {"approval_id": req["approval_id"], "state": self._approval(req["run_id"], req["approval_id"])["state"]}
        return self._call("approval_wait", req, handle)

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
    a = ap.parse_args()
    sys.exit(serve_fake(runtime_dir(), proto=tuple(map(int, a.proto.split("-"))), version=a.version,
                        idle_s=float(os.environ.get("TRACEKIT_DEV_IDLE", 900))))
