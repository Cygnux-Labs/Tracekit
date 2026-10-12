#!/usr/bin/env python3
"""E17 part 2: does containment (docs/incidents.md) hold where an agent, or content it reads, would try to undo it?
Offline: an in-process signer per scenario, nothing executed. Scenarios: the agent's own identity calls every operator
RPC, and a config granting them to it; a policy that would let any trigger suspend an identity; a held run's approvals and
waits next to a healthy run of the same identity; a hold across a restart, a snapshot and a crash, and a storage
recovery; an approval granted before the hold consumed after it; a quarantine against the gateway's model loop; a held
run closed and registered again; a bundle whose signer let a call through after a hold, through both verifiers.
Writes eval/results/e17_containment.json; exit 0 only when every scenario holds."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
import e17_detection as e17  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.quotas import Limits  # noqa: E402
from tracekit.signer.rpc_schema import REQUESTS, RPCError  # noqa: E402
from tracekit.verify import v2  # noqa: E402

ME, OP = e17.ME, CallerIdentity("uid", "424242", True)   # the agent's identity; a person who operates
GATEWAY = CallerIdentity("mtls", "spiffe://acme/gateway", True)
HOLD = {**e17.POLICY, "tools": {**e17.POLICY["tools"], "pay": "payment"},
        "ask": [{"id": "T-PAY", "tool": "pay", "pattern": "^"}],
        "sequences": [{"id": "Q", "steps": ["secret", "egress"], "window": 600}],
        "respond": [{"trigger": "Q", "mode": "enforce", "action": "hold", "cooldown_s": 600}]}
PAY = ("pay", {"to": "acct"})
OPERATOR_CALLS = {"incident_list": {}, "incident_show": {"incident_id": "inc-x"},
                  "incident_resolve": {"incident_id": "inc-x"}, "run_hold": {"run_id": "r"},
                  "run_quarantine": {"run_id": "r"}, "run_resume": {"run_id": "r"}, "response_pause": {},
                  "response_resume": {}, "suspend": {"identity": "uid:1"}, "unsuspend": {"identity": "uid:1"}}


class Signer(e17.Signer):
    """e17's signer with a person approver (OP), a gateway and the given grants and limits."""

    def __init__(self, pol=HOLD, authorize=None, limits=None, approvers=True):
        self.authorize, self.limits, self.approvers = authorize, limits, approvers
        super().__init__(e17.engine(pol))

    def open(self):
        self.s = svc.SignerService(
            self.dir, policy=self.eng, grace_s=0, idle_s=60, gateways=[f"{GATEWAY.scheme}:{GATEWAY.subject}"],
            limits=self.limits or Limits(events_per_s=1e6, burst=10 ** 6),
            approvals={"approvers": [f"uid:{OP.subject}"], "persons": {f"uid:{OP.subject}": "alice"}}
            if self.approvers else {},
            authorize={f"{GATEWAY.scheme}:{GATEWAY.subject}": ["model_event"],
                       **(self.authorize or {f"uid:{OP.subject}": sorted(svc.OPERATOR | {"approval_decide"})})})

    def op(self, method, req):
        self.n += 1
        return self.s.call(OP, method, {"request_id": f"op-{self.n}", **req})

    def hold(self, run):
        self.decide(run, e17.SECRET)
        return self.decide(run, e17.EGRESS)

    def state(self, run):
        r = self.s.log.runs[("default", run["run_id"])]
        return "quarantined" if r.get("quarantined") else "held" if r.get("held") else "open"


def refused(f, code="forbidden", why=""):
    """Whether `f()` is refused with `code`, its message holding `why`."""
    try:
        f()
    except RPCError as e:
        return e.code == code and why in e.message
    return False


def agent_cannot_operate():
    s = Signer()   # unconfigured: the agent's identity has the defaults
    s.register()   # the agent's own open run
    default = sum(refused(lambda: s.s.call(ME, m, {
        **req, **({"request_id": "x"} if "request_id" in REQUESTS[m]["properties"] else {})}), why="is not authorized")
        for m, req in OPERATOR_CALLS.items())
    s.close()
    d = tempfile.mkdtemp()
    try:   # granted every operator call outright next to register_run: the signer doesn't start
        svc.SignerService(d, policy=e17.engine(HOLD),
                          authorize={f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS | svc.OPERATOR)}).close()
        starts = True
    except ValueError as e:
        starts = "both register_run and containment's operator calls" not in str(e)
    finally:
        shutil.rmtree(d, True)
    out = {"default": default, "granted_starts": starts}
    return out == {"default": len(OPERATOR_CALLS), "granted_starts": False}, out


def no_trigger_suspends():
    triggers = ("denied_calls", "provenance", "Q", "executed_against_policy")
    refused_ = [t for t in triggers if any("suspend is an operator's action" in x for x in e17_lint({
        "trigger": t, "mode": "enforce", "action": "quarantine" if t == "executed_against_policy" else "hold",
        "suspend": True, **({"max": 2, "window": 60} if t == "denied_calls" else {})}))]
    return refused_ == list(triggers), {"refused_at_load": refused_}


def e17_lint(entry):
    """The lint errors of HOLD with `entry` as its only respond entry."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "p.json")
        with open(path, "w") as f:
            json.dump({**HOLD, "respond": [entry]}, f)
        return pc.build(path)[1]
    finally:
        shutil.rmtree(d, True)


def held_runs_dont_starve():
    s = Signer(limits=Limits(events_per_s=1e6, burst=10 ** 6, pending_approvals=2, concurrent_waits=1))
    held, healthy = s.register(), s.register()
    s.hold(held)
    for i in range(2):   # the held run uses up its own budget of pending approvals
        s.decide(held, PAY, tcid=f"h{i}")
        s.call("approval_request", {**held, "tool_call_id": f"h{i}"})
    third = (s.decide(held, PAY, tcid="h2"), refused(lambda: s.call("approval_request", {**held, "tool_call_id": "h2"}),
                                                     "quota_exceeded"))[1]
    s.decide(healthy, PAY, tcid="ok")
    fine = s.call("approval_request", {**healthy, "tool_call_id": "ok"})["state"] == "requested"
    s.close()
    return third and fine, {"held_run_capped": third, "healthy_run_asks": fine}


def restarts():
    out = {}
    for how in ("restart", "snapshot_then_crash", "recover"):
        s = Signer()
        run = s.register()
        s.hold(run)
        if how == "restart":
            s.s.close()
            s.open()
        elif how == "snapshot_then_crash":
            s.s.snapshot()
            s.decide(run, e17.SECRET)   # after the snapshot: replayed on open
            s.crash()
            s.open()
        else:
            log = s.s.log
            log.write(lambda tx: setattr(log, "down", ("2026-01-01T00:00:00.000000Z", "seeded outage")))
            log._last_try = 0.0
        out[how] = (s.state(run), s.decide(run, e17.SECRET)["decision"])
        s.close()
    return all(v == ("held", "ask") for v in out.values()), out


def approval_before_hold():
    s = Signer()
    run = s.register()
    s.decide(run, PAY, tcid="p")
    aid = s.call("approval_request", {**run, "tool_call_id": "p"})["approval_id"]
    s.op("approval_decide", {"approval_id": aid, "decision": "approve"})
    s.hold(run)
    out = s.call("approval_consume", {**run, "tool_call_id": "p", "tool": "pay", "args_source": "parsed",
                                      "args": PAY[1]})
    expired = [e["data"].get("reason") for e in s.events(run) if e["type"] == "approval.expired"]
    s.close()
    return not out["ok"] and out["rule_ids"] == ["TK-HOLD"] and expired == ["hold"], {
        "consume": out["rule_ids"], "expired": expired}


def quarantine_stops_gateway():
    s = Signer(approvers=False)   # no person approver: the hold is a quarantine
    run = s.register()
    s.hold(run)
    req = {**run, "caller": f"uid:{ME.subject}", "stream": "gx", "provider": "openai", "model": "m"}
    stopped = refused(lambda: s.s.call(GATEWAY, "model_event", {"request_id": "g1", **req, "client_seq": 0,
                                                                "phase": "request"}), why="is quarantined")
    answered = s.s.call(GATEWAY, "model_event", {"request_id": "g2", **req, "client_seq": 1, "phase": "response"})
    state = s.state(run)
    s.call("close_run", run)
    reason = [e["data"]["reason"] for e in s.events(run) if e["type"] == "run.closing"]
    s.close()
    return state == "quarantined" and stopped and "run_seq" in answered and reason == ["quarantine"], {
        "state": state, "request_refused": stopped, "closing": reason}


def reregistered_inherits():
    s = Signer()
    run = s.register()
    s.hold(run)
    s.call("close_run", run)
    again = s.register()
    out = (s.state(again), s.decide(again, e17.SECRET)["rule_ids"])
    s.close()
    return out == ("held", ["T-SECRET", "TK-HOLD"]), {"state": out[0], "rule_ids": out[1]}


def verifier_catches_allow_after_hold():
    out = {}
    for honest in (True, False):
        s = Signer()
        run = s.register()
        with mock.patch.object(svc.SignerService, "_contained", (lambda self, r, v, ids: (v, ids, None))
                               if not honest else svc.SignerService._contained):
            s.hold(run)
            s.decide(run, e17.SECRET)
        s.call("close_run", run)
        s.s.sweep()
        s.s.checkpoint()
        bundle, trust = os.path.join(s.dir, "b.tkb"), os.path.join(s.dir, "trust.json")
        export(s.s.log.storage, "default", run["run_id"], s.s.log.storage.checkpoint_latest()[1], bundle,
               policy_dir=os.path.join(s.dir, "policies"))
        with open(trust, "w") as f:
            json.dump({"logs": [s.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        line = next((c["status"] for c in rep.checks if c["check"] == "incidents"), None)
        ts = _ts_verify(bundle, trust)
        out["honest" if honest else "allow_after_hold"] = {"python": [code, line], "typescript": ts}
        s.close()
    want = {"honest": [0, "pass"], "allow_after_hold": [1, "fail"]}
    return all(v["python"] == want[k] and v["typescript"] in (None, want[k]) for k, v in out.items()), out


def _ts_verify(bundle, trust):
    """[exit code, incidents status] from the TypeScript verifier, or None where it isn't built."""
    cli = os.path.join(ROOT, "sdk", "typescript", "bin", "tracekit.mjs")
    if not (shutil.which("node") and os.path.exists(os.path.join(ROOT, "sdk", "typescript", "dist", "verify",
                                                                 "index.js"))):
        return None
    p = subprocess.run(["node", cli, "verify", bundle, "--trust", trust, "--json"], capture_output=True, text=True)
    out = json.loads(p.stdout)
    return [out["exit_code"], next((c["status"] for c in out["checks"] if c["check"] == "incidents"), None)]


SCENARIOS = {f.__name__: f for f in (agent_cannot_operate, no_trigger_suspends, held_runs_dont_starve,
                                     restarts, approval_before_hold, quarantine_stops_gateway, reregistered_inherits,
                                     verifier_catches_allow_after_hold)}


def run():
    out = {}
    for name, f in SCENARIOS.items():
        ok, detail = f()
        out[name] = {"ok": ok, **detail}
    return out


def main():
    out = run()
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", "e17_containment.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    for name, r in out.items():
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {name}")
    return 0 if all(r["ok"] for r in out.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
