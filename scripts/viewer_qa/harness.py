"""The central viewer's pages (/runs, /approvals) on the real handler and pages, with stub back ends, for the viewer's
browser checks: a Runs with realistic rows (no Postgres) and an approver session with an ApprovalDesk over a fake
signer (cookie tracekit_observe=qa-approver). Placeholder data only.

    python harness.py PORT
"""
import sys
import time

from tracekit import view
from tracekit.signer.rpc_schema import RPCError

OP = view.OPERATOR_SIDE
RUNS = [{"log": 0, "run_id": f"run-{i:04d}-" + "a" * 20, "tenant": "acme", "agent": ["support-agent", "claude-code",
         "billing-bot"][i % 3], "started": f"2026-10-19T0{i % 9}:00:00Z", "ended": f"2026-10-19T0{i % 9}:05:00Z",
         "records": 40 + i, "gaps": i % 4 == 0, "denies": i % 3, "approvals": i % 2, "first": 1000 - i,
         "verdict": {"verdict": ["verified", "failed", "pending"][i % 3], "integrity": ["VERIFIED", "FAILED", "PENDING"][i % 3],
                     "assurance": "dev", "label": OP}} for i in range(60)]


class StubRuns:
    logs = [None]

    def search(self, scope, q):
        rows = [r for r in RUNS if (not q.get("agent") or q["agent"] in r["agent"])
                and (not q.get("verdict") or r["verdict"]["verdict"] == q["verdict"])
                and (not q.get("run") or r["run_id"].startswith(q["run"]))]
        start = int(q.get("after", "0"))
        page = rows[start:start + 50]
        return {"runs": page, "next": str(start + 50) if start + 50 < len(rows) else None}

    def run(self, scope, q):
        r = next((x for x in RUNS if x["run_id"] == q.get("run")), None)
        if not r:
            return None
        start = int(q.get("from", "0"))
        recs = [{"event": {"seq": k, "run_seq": k, "type": "policy.decision", "data": {"tool": "Bash", "decision": "allow"}},
                 "hash": "sha256:" + "0" * 64} for k in range(start, min(start + 500, 1200))] \
            if r["verdict"]["verdict"] == "verified" else []
        return {"log": 0, "tenant": r["tenant"], "run_id": r["run_id"], "verdict": {**r["verdict"], "report":
                "[PASS] manifest\n[FAIL] signatures — seq 2: hash does not match the event\n\nIntegrity: FAILED."
                if r["verdict"]["verdict"] == "failed" else "Integrity: VERIFIED."}, "records": recs,
                "next": start + 500 if start + 500 < 1200 and recs else None}

    def bundle(self, scope, q):
        return b"PK\x03\x04 fake bundle"


class FakeLogin:
    redirect_uri = "http://127.0.0.1/callback"

    def __init__(self):
        self.s = {"tenant": "acme", "role": "approver", "csrf": "csrf-qa", "at": time.time(), "until": time.time() + 3600,
                  "person": {"subject": "oidc|ana", "person": "ana@acme.example", "groups": ["approvers"], "tenant": "acme"}}

    def session(self, sid):
        return self.s if sid == "qa-approver" else None

    def tenant(self, sid):
        return self.session(sid) and "acme"


class FakeSigner:
    def __init__(self):
        self.a = {f"apr-{i}": {"approval_id": f"apr-{i}", "state": "requested", "tool": t, "rule_ids": r,
                               "run_id": "run-0001-" + "a" * 20, "tool_call_id": f"c{i}", "attempt": 1,
                               "requester": "uid:1001", "expires_at": "2026-10-19T12:00:00Z",
                               "binding_digest": "sha256:" + "b" * 64, "passkey": False, "agent": i == 2,
                               "escalated": i == 3, "args": a, "args_source": "parsed",
                               **({"reason": "customer asked for a refund"} if i == 1 else {})}
                  for i, (t, r, a) in enumerate([("Bash", ["TK-A002"], {"command": "git push origin --delete main"}),
                                                 ("issue_refund", ["TK-DEMO-ASK"], {"order": "A-1009", "cents": 4200}),
                                                 ("send_email", ["TK-S010"], {"to": "c.rao@example.com", "body": "Hi"}),
                                                 ("terraform", ["TK-A001"], {"command": "terraform destroy"})])}

    def call(self, method, req):
        if method == "approval_list":
            return {"approvals": [{k: v for k, v in a.items() if k not in ("args",)} for a in self.a.values()]}
        a = self.a.get(req.get("approval_id"))
        if a is None:
            raise RPCError("unknown_approval", "no such approval")
        if method == "approval_get":
            return a
        if method == "approval_decide":
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", f"{a['approval_id']} is {a['state']}")
            a["state"] = {"approve": "approved", "reject": "rejected"}[req["decision"]]
            a["answered"] = {"kind": "person", "by": req["on_behalf"]["person"]}
            return {"approval_id": a["approval_id"], "state": a["state"]}
        raise RPCError("invalid_request", method)


port = int(sys.argv[1])
srv = view.server(None, "127.0.0.1", port, "qa-token", None, FakeLogin(), view.ApprovalDesk(FakeSigner()), StubRuns())
print(f"harness on http://127.0.0.1:{port}/runs", flush=True)
srv.serve_forever()
