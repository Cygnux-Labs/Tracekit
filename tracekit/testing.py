"""`FakeSigner`: an in-memory `SignerAPI` for adapter development and your own tests.

    from tracekit.testing import FakeSigner
    signer = FakeSigner(rule=lambda tool, args: ("ask", ["R1"]) if tool == "pay" else ("allow", []))

It follows the RPC contract (schemas, error codes, idempotency, run tokens, client_seq gaps, approval binding) but
signs nothing, keeps nothing on disk and has one caller identity, so approvals are always self-approvals. Ids are
deterministic.

`serve_fake(runtime_dir)` serves one as a dev signer the way tracekit/sdk/autospawn.py expects; to have clients
auto-spawn it, set `tracekit.sdk.autospawn.SIGNER_ARGV = [sys.executable, "-m", "tracekit.testing"]` in your test.
"""
import argparse
import copy
import datetime
import hashlib
import hmac
import json
import os
import sys
import threading

import rfc8785

from tracekit import __version__, privacy
from tracekit.format.canon import StrictJSONError, event_hash, loads_strict
from tracekit.signer import rpc_schema
from tracekit.signer.rpc_schema import RPCError


POLICY_HASH = "sha256:" + "0" * 64


def _allow(tool, args):
    return "allow", []


class FakeSigner:
    def __init__(self, rule=_allow, identity="fake-user", tenant="default", t2=()):
        """`rule(tool, args) -> (decision, rule_ids)` with decision allow|deny|ask; args are the parsed value. An
        approval for a call one of the rule ids in `t2` asked about has a T2 executor: its consume returns the args."""
        self.rule, self.identity, self.tenant, self.t2 = rule, identity, tenant, set(t2)
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

    def _may_see(self, a):
        """The real signer's rule: the run's owner, or an identity of the run's tenant (here: this signer's tenant)."""
        run = self._runs[a["run_id"]]
        return run["owner"] == self.identity or run["tenant"] == self.tenant

    def _visible(self, approval_id):
        a = self._approvals.get(approval_id)
        if a is None or not self._may_see(a):
            raise RPCError("unknown_approval", approval_id)
        return a

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
                                        "calls": {}, "decisions": {}, "owner": self.identity, "tenant": tenant}
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
            run["decisions"][decision_id] = (req["tool_call_id"], req.get("attempt", 0), digest, decision)
            seq = self._append(run, "policy.decision", {"tool_call_id": req["tool_call_id"], "tool": req["tool"],
                                                      "decision_id": decision_id,
                                                      "attempt": req.get("attempt", 0), "args_source": req["args_source"],
                                                      "decision": decision, "rule_ids": rule_ids}, req)
            return {"decision": decision, "decision_id": decision_id, "rule_ids": rule_ids, "run_seq": seq}
        return self._call("decide", req, handle)

    def _event(self, method, typ, fields, req, check=None):
        """`check(run, req)` refuses the call, or returns the data of a gap to record after the event."""
        def handle(req):
            run = self._run(req)
            self._check_seq(run, req)
            gap = check(run, req) if check else None
            seq = self._append(run, typ, {k: req[k] for k in fields if k in req}, req)
            if gap:
                self._append(run, "capture.gap", gap)
            return {"run_seq": seq}
        return self._call(method, req, handle)

    def complete(self, req):
        def consume(run, req):
            tcid, attempt = req["tool_call_id"], req.get("attempt", 0)
            d = run["decisions"].get(req["decision_id"])
            if d is None or d[:2] != (tcid, attempt):
                raise RPCError("unknown_decision", req["decision_id"])
            if d[2] != req["args_digest"]:
                raise RPCError("args_mismatch", tcid)
            run["decisions"][req["decision_id"]] = None
            a = self._approvals.get(self._index.get((req["run_id"], tcid, attempt)), {})
            if d[3] == "deny" or (d[3] == "ask" and a.get("state") != "consumed"):
                return {"kind": "executed_against_policy", "tool_use_id": tcid,
                        "reason": f"{tcid} ran after a {d[3]} decision"}
            return None
        return self._event("complete", "tool.result", ("tool_call_id", "decision_id", "attempt", "status", "error"), req,
                           check=consume)

    def state_write(self, req):
        return self._event("state_write", "state.write", ("key", "value_digest", "prev_digest"), req)

    def model_event(self, req):
        return self._event("model_event", "model.event", ("provider", "model", "phase", "content_digest", "usage",
                                                          "exchange_id", "streamed", "stop_reason", "error", "tool_uses",
                                                          "tool_results_sent"), req)

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
            # the approver's copy is redacted as the real signer does it (a raw copy stays valid JSON)
            from tracekit.signer.service import _dotenv
            args = _digest(call)[0]
            dotenv = _dotenv(args)
            shown = privacy.redact(args, dotenv)[0]
            if call["args_source"] == "raw":
                shown = call["args"] if shown == args else rfc8785.dumps(shown).decode()
            a = self._approvals[approval_id] = {
                "run_id": req["run_id"], "tool_call_id": req["tool_call_id"], "attempt": attempt, "tool": call["tool"],
                "args_source": call["args_source"], "args": shown, "args_digest": call["args_digest"],
                "rule_ids": call["rule_ids"], "policy_hash": POLICY_HASH, "requester": self.identity,
                "expires_at": expires_at, "state": "requested",
                **({"reason": privacy.redact(req["reason"], dotenv)[0]} if "reason" in req else {}),
                "executor": "t2" if self.t2 & set(call["rule_ids"]) else "t1"}
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
            a = self._visible(req["approval_id"])
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            run = self._runs[a["run_id"]]
            if run["closed"]:
                raise RPCError("run_closed", a["run_id"])
            a["state"] = "approved" if req["decision"] == "approve" else "rejected"
            same = self.identity in (a["requester"], run["owner"])
            self._append(run, "approval", {"approval_id": req["approval_id"], "decision": req["decision"],
                                           "approver": self.identity, "self_approved": same})
            return {"approval_id": req["approval_id"], "state": a["state"], "self_approved": same}
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
                out = {"ok": True, "rule_ids": ["TK-APPROVED"], "approval_id": aid}
                if a["executor"] == "t2":
                    out["args"] = loads_strict(a["args"]) if a["args_source"] == "raw" else copy.deepcopy(a["args"])
                return out
            self._append(run, "approval.refused", {"tool_call_id": req["tool_call_id"], "rule_ids": [code]})
            return {"ok": False, "rule_ids": [code], **({"approval_id": aid} if a else {})}
        return self._call("approval_consume", req, handle)

    def approval_get(self, req):
        def handle(req):
            a = self._visible(req["approval_id"])
            return {"approval_id": req["approval_id"], **{k: v for k, v in a.items() if k not in ("args_digest", "executor")}}
        return self._call("approval_get", req, handle)

    def approval_list(self, req):
        def handle(req):
            ids = [aid for aid, a in self._approvals.items()
                   if req.get("run_id") in (None, a["run_id"]) and self._may_see(a)]
            start = 0 if req.get("cursor") is None else ids.index(req["cursor"]) + 1 if req["cursor"] in ids else len(ids)
            page, more = ids[start:start + req.get("limit", 100)], ids[start + req.get("limit", 100):]
            keys = rpc_schema.RESPONSES["approval_list"]["properties"]["approvals"]["items"]["required"]
            return {"approvals": [{"approval_id": aid, **{k: self._approvals[aid][k] for k in keys if k != "approval_id"}}
                                  for aid in page], "next_cursor": page[-1] if more else None}
        return self._call("approval_list", req, handle)

    def approval_abandon(self, req):
        def handle(req):
            run = self._run(req)
            a = self._approval(req["run_id"], req["approval_id"])
            if a["state"] not in ("requested", "approved"):
                raise RPCError("approval_not_pending", a["state"])
            a["state"] = "expired"
            self._append(run, "approval.abandoned", {"approval_id": req["approval_id"]})
            return {"approval_id": req["approval_id"], "state": "expired"}
        return self._call("approval_abandon", req, handle)

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
    """Serve `signer` (a new FakeSigner by default) as the dev signer of `runtime_dir`, with the real dev signer's
    lifecycle (tracekit.signer.service.serve_dev). Call it from the main thread; returns an exit code."""
    from tracekit.signer.service import serve_dev

    signer, mutex = signer or FakeSigner(), threading.Lock()

    def handle(identity, frame):
        method = frame.pop("method", None)
        if method not in rpc_schema.REQUESTS:
            raise RPCError("invalid_request", f"unknown method {str(method)[:64]}")
        with mutex:
            return getattr(signer, method)(frame)
    return serve_dev(runtime_dir, lambda: (handle, lambda: None), proto, version, idle_s)


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
