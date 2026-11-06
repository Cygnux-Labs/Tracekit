#!/usr/bin/env python3
"""E23: intent grants (docs/intent-grants.md): payments within a person's grant run without a stop, and everything
outside it, or that tries to get around it, is still held.

One v2 signer, in process, with the dev pack's shape of payment rule (an ask that opts into payment.send grants) and a
named approver, alice. A payout agent pays a week's invoices; the requesting agent controls every argument. Each part
must hold:

  E23.1 workload   30 payments, 24 within alice's grant and 6 outside it (an unknown payee, over the most for one
                   payment, past the total): the person's stops with the grant are the held call it was issued from
                   plus the 6, against 30 without one; nothing outside the limits runs
  E23.2 attacks    arguments a grant must not read as within it: amounts in other units, payee look-alikes, a second
                   payee, extra arguments that move money, another currency
  E23.3 authority  the agent issuing a grant for its own run, passing one on, or asking for one that lasts past a day
  E23.4 split      100 payments of 7 USDC under a 50 USDC total: what runs stays within the total
  E23.5 ended      a revoked grant and an expired one release nothing
  E23.6 restart    a grant's totals survive a signer restart
  E23.7 verify     the run's bundle verifies, and the verifier re-checks every release against its grant

Writes eval/results/e23_grants.json; exit 0 when every part holds.
"""
import itertools
import json
import os
import shutil
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import write_results  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import RPCError  # noqa: E402
from tracekit.verify import v2  # noqa: E402

AGENT, ALICE = CallerIdentity("uid", "1002", True), CallerIdentity("uid", "1001", True)
POLICY = {"tools": {"mcp__payments__send_money": "mcp"},
          "ask": [{"id": "PAY", "tool": "mcp__payments__send_money", "pattern": "^",
                   "approval": {"grant": "payment.send"}}]}
P1, P2, P3 = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20
USDC = 10 ** 6
_n = itertools.count()


class World:
    def __init__(self, d):
        self.d = d
        self.open()
        r = self.s.call(AGENT, "register_run", {"request_id": f"r{next(_n)}", "agent": {"name": "payouts"}})
        self.run, self.seq = {"run_id": r["run_id"], "run_token": r["run_token"]}, itertools.count()

    def open(self):
        self.s = svc.SignerService(self.d, policy=Engine(POLICY),
                                   approvals={"approvers": ["uid:1001"], "persons": {"uid:1001": "alice"}})

    def call(self, method, who=AGENT, **req):
        return self.s.call(who, method, {"request_id": f"r{next(_n)}", **req})

    def pay(self, args, tcid=None):
        """The decision on one payment: allow (it runs) or ask (a person's stop)."""
        return self.call("decide", **self.run, stream="s", client_seq=next(self.seq), tool_call_id=tcid or
                         f"t{next(_n)}", tool="mcp__payments__send_money", args_source="parsed", args=args)

    def grant(self, who=ALICE, total=500, each=20, payees=(P1, P2), seconds=3600, **kw):
        return self.call("grant_issue", who, run_id=self.run["run_id"], intent="payment.send",
                         caveats=[{"field": "currency", "op": "==", "value": "USDC"},
                                  {"field": "payee", "op": "in", "value": list(payees)},
                                  {"field": "amount", "op": "<=", "value": each * USDC}],
                         limits=[{"op": "sum", "field": "amount", "max": total * USDC}],
                         expires_at=svc._iso(time.time() + seconds), **kw)


def money(amount, to=P1, **kw):
    return {"amount": amount, "currency": "USDC", "to": to, **kw}


def workload():
    """24 invoices within the grant (the first, 4 USDC, held and granted from; then 23 of 5 to 20 USDC to the two
    contractors) and 6 outside it (an unknown payee twice, over 20 USDC twice, and two past the total)."""
    inside = [money((5 + i % 16) * USDC, P1 if i % 2 else P2) for i in range(23)]
    outside = [money(10 * USDC, P3), money(10 * USDC, P3), money(25 * USDC), money(40 * USDC, P2)]
    return [money(4 * USDC)], inside, outside, [money(20 * USDC), money(20 * USDC, P2)]


def e23_1(d):
    first, rest, outside, late = workload()
    plain = World(os.path.join(d, "plain"))
    without = sum(plain.pay(a)["decision"] == "ask" for a in first + rest + outside + late)
    w = World(os.path.join(d, "granted"))
    w.pay(first[0], "first")
    aid = w.call("approval_request", **w.run, tool_call_id="first")["approval_id"]
    w.grant(total=sum(a["amount"] for a in first + rest) // USDC + 9, approval_id=aid)
    w.call("approval_decide", ALICE, approval_id=aid, decision="approve")
    within = [w.pay(a)["decision"] for a in rest]
    held = [w.pay(a)["decision"] for a in outside + late]
    stops = 1 + within.count("ask") + held.count("ask")
    ok = without == 30 and within.count("allow") == len(rest) and held.count("allow") == 0
    return {"payments": 30, "stops_without_grant": without, "stops_with_grant": stops,
            "released": within.count("allow"), "outside_released": held.count("allow"), "ok": ok}


def e23_2(d):
    w = World(d)
    w.grant(total=10 ** 6)
    attacks = {"amount as a string": money("10000000"), "amount as a float": money(10.0), "amount in scientific form":
               money(1e7), "amount true": money(True), "a negative amount": money(-5), "a zero amount": money(0),
               "amount as an object": money({"value": 10, "unit": "USDC"}), "amount and amount_cents":
               {"amount": USDC, "amount_cents": 1, "currency": "USDC", "to": P1}, "no currency":
               {"amount": USDC, "to": P1}, "another currency": money(USDC) | {"currency": "EUR"},
               "a Cyrillic look-alike payee": money(USDC, P1[:5] + "а" + P1[6:]), "a payee with a trailing space":
               money(USDC, P1 + " "), "a zero-width character": money(USDC, "​" + P1),
               "one character off": money(USDC, P1[:-1] + "2"), "a second payee": money(USDC, P1, destination=P3),
               "a payee in an object": {"amount": USDC, "currency": "USDC", "account": {"id": P1}},
               "a fee to another address": money(USDC, fee={"to": P3, "amount": 10 ** 9}),
               "a split": money(USDC, splits=[{"to": P3}]), "a memo object": money(USDC, memo={"to": P3})}
    held = {k: w.pay(v)["decision"] == "ask" for k, v in attacks.items()}
    return {"attacks": len(held), "held": sum(held.values()), "released": sorted(k for k, v in held.items() if not v),
            "ok": all(held.values())}


def e23_3(d):
    w = World(d)
    g = w.grant()["grant"]
    tries = {"the agent issues one": lambda: w.grant(who=AGENT),
             "the agent passes one on": lambda: w.call("pcm_delegate", **w.run, parent=g, subject="uid:1002",
                                                       caveats=g["caveats"], expires_at=g["expires_at"],
                                                       delegable=False),
             "a grant past a day": lambda: w.grant(seconds=25 * 3600)}
    refused = {}
    for k, f in tries.items():
        try:
            f()
            refused[k] = False
        except RPCError:
            refused[k] = True
    return {"tries": len(refused), "refused": sum(refused.values()), "ok": all(refused.values())}


def e23_4(d):
    w = World(d)
    w.grant(total=50, each=50)
    runs = [w.pay(money(7 * USDC))["decision"] == "allow" for _ in range(100)]
    spent = 7 * sum(runs)
    return {"payments": 100, "released": sum(runs), "spent_usdc": spent, "ok": spent <= 50 and sum(runs) == 7}


def e23_5(d):
    w = World(d)
    g = w.grant()["grant_id"]
    w.call("grant_revoke", ALICE, grant_id=g)
    revoked = w.pay(money(USDC))["decision"]
    w.grant(seconds=60)
    with mock.patch.object(svc.time, "time", return_value=time.time() + 120):
        expired = w.pay(money(USDC))["decision"]
    return {"revoked": revoked, "expired": expired, "ok": (revoked, expired) == ("ask", "ask")}


def e23_6(d):
    w = World(d)
    w.grant(total=30)
    before = [w.pay(money(15 * USDC))["decision"] for _ in range(1)]
    w.s.close()
    w.open()
    after = [w.pay(money(15 * USDC))["decision"] for _ in range(2)]
    return {"before": before, "after": after, "ok": before + after == ["allow", "allow", "ask"]}


def e23_7(d):
    w = World(d)
    w.grant()
    for a in (money(10 * USDC), money(20 * USDC, P2), money(5 * USDC, P3)):
        w.pay(a)
    w.s.checkpoint()
    out, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
    with open(trust, "w") as f:
        json.dump({"logs": [w.s.vkey], "algs": ["ed25519"]}, f)
    export(w.s.log.storage, "default", w.run["run_id"], w.s.log.storage.checkpoint_latest()[1], out)
    rep, code = v2.verify(out, trust)
    line = next((c for c in rep.checks if c["check"] == "intent grants"), {})
    return {"exit": code, "integrity": rep.integrity, "intent_grants": line.get("detail"),
            "ok": code == 0 and line.get("status") == "pass"}


def main():
    d = tempfile.mkdtemp(prefix="e23-")
    try:
        with mock.patch.object(svc, "CHECKPOINT_S", 3600.0):
            out = {name: f(os.path.join(d, name)) for name, f in (
                ("E23.1 workload", e23_1), ("E23.2 attacks", e23_2), ("E23.3 authority", e23_3),
                ("E23.4 split", e23_4), ("E23.5 ended", e23_5), ("E23.6 restart", e23_6), ("E23.7 verify", e23_7))}
    finally:
        shutil.rmtree(d, ignore_errors=True)
    for name, r in out.items():
        print(f"{name}: {'ok' if r['ok'] else 'FAILED'}  {json.dumps({k: v for k, v in r.items() if k != 'ok'})}")
    print("wrote", write_results("e23_grants", out))
    return 0 if all(r["ok"] for r in out.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
