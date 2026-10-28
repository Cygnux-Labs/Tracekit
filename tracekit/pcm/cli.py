"""`tracekit pcm` (experimental, #436): check a proof-carrying message offline, or watch two agents use them.

    tracekit pcm verify MSG --trust trust.json --schema refund.request.json [--strict] [--me uid:990102] [--json]
    tracekit pcm demo

`verify` exits 0 for accept, 3 for accept-unproven, 1 for reject and 2 when it can't read its inputs. It checks one
saved message, so it does not check replay: a receiver keeps one pcm.Replay for its life (docs/pcm.md)."""
import argparse
import datetime
import itertools
import json
import shutil
import sys
import tempfile
import time

from tracekit import pcm
from tracekit.format.canon import event_hash, loads_strict
from tracekit.identity.base import CallerIdentity
from tracekit.verify.v2 import load_trust

EXIT = {"accept": 0, "accept-unproven": 3, "reject": 1}
A, ALICE, B = CallerIdentity("uid", "990101", True), CallerIdentity("uid", "990001", True), "uid:990102"
DOC = {"pcm_schema": 0, "name": "refund.request",
       "fields": {"amount": {"type": "money", "currency": "USD", "max": 1000000},
                  "order": {"type": "int", "min": 1, "max": 999999999}},
       "claims": ["approved_by"], "grant": True}


def summary(out):
    """One line for a verify result: its reasons, or for an accept what passed, with what a proven approved_by
    approved; then the checks it skipped."""
    skipped = [f"not checked: {', '.join(out['skipped'])}"] * bool(out["skipped"])
    if out["reasons"]:
        return "; ".join(out["reasons"] + skipped)
    g, parts = out["grants"], ["signature ok"] + ["replay ok"] * bool(out["replay"]["ok"]) + ["schema ok"]
    if g["result"] == "ok":
        parts.append(f"grant ok ({g['root']['person']}, {g['steps']} step{'s' * (g['steps'] > 1)})")
    return " · ".join(parts + [f"{c['type']} {c['result']}" + f" ({c['detail']})" * ("approved" in c)
                               for c in out["claims"]] + skipped)


def freshness(msg, out):
    """What the receiver checks itself after a proven tests_passed or file_written claim (docs/pcm.md#freshness): how
    long before the message the oldest record of its evidence is. None without one, or when a ts is no date."""
    try:
        ages = [pcm._epoch(msg["ts"]) - min(pcm._epoch(r["event"]["ts"]) for r in c["evidence"]["records"])
                for c, r in (zip(msg["claims"], out["claims"]) if out["claims"] else ())
                if r["result"] == "proven" and r["type"] in ("tests_passed", "file_written")]
    except ValueError:   # a hostile pinned log can write a ts in month 13
        return None
    return ages and (f"evidence {max(ages):.0f} s before the message: a claim proves a call happened, not that nothing "
                     "changed since: check its age (docs/pcm.md#freshness)")


def _load(path):
    with open(path, "rb") as f:
        try:
            return loads_strict(f.read())
        except ValueError as e:
            raise ValueError(f"{path}: {e}") from None


def verify(a):
    try:
        msg = _load(a.msg)
        out = pcm.verify(msg, load_trust(a.trust), [_load(p) for p in a.schema], me=a.me, strict=a.strict)
    except (OSError, ValueError) as e:   # a file, a schema document that is not one, or a bad vkey in trust.json
        print(f"tracekit pcm verify: {e}", file=sys.stderr)
        return 2
    # the sender chose parts of the reasons and details: escape what a terminal would act on, and `\` so a `\u001b` the
    # sender wrote can't pass for an escaped ESC
    line = "".join(c if c.isprintable() and c != "\\" else json.dumps(c)[1:-1] for c in summary(out))
    print(json.dumps(out, indent=2) if a.json else f"{out['verdict'].upper()}  {line}")
    if not a.json and (note := freshness(msg, out)):
        print(f"  {note}")
    return EXIT[out["verdict"]]


def _usd(cents):
    return f"${cents // 100}.{cents % 100:02d}"


def demo():
    """Agent A asks agent B for a refund with a grant alice approved, through a real signer in a temp dir; B verifies
    each message as a receiver would. 0 when every verdict is the expected one."""
    from tracekit.policy2.engine import Engine
    from tracekit.signer import service as svc
    from tracekit.signer.rpc_schema import REQUESTS, RPCError
    d = tempfile.mkdtemp(prefix="tk-pcm-")
    s, ids = None, itertools.count()
    try:
        print(f"tracekit pcm demo: two agents negotiate a refund (an in-process signer in {d})")
        s = svc.SignerService(d, policy=Engine({"ask": [{"id": "PCM-GRANT", "tool": "pcm.grant", "pattern": "^"}]}),
                              approvals={"approvers": [f"uid:{ALICE.subject}"],
                                         "persons": {f"uid:{ALICE.subject}": "alice"}}, fsck_every_s=0)

        def call(who, method, **req):
            return s.call(who, method, {**({"request_id": f"demo-{next(ids)}"}
                                           if "request_id" in REQUESTS[method]["properties"] else {}), **req})
        r = call(A, "register_run", agent={"name": "agent-a"})
        run, frm = {"run_id": r["run_id"], "run_token": r["run_token"]}, {
            "agent": f"uid:{A.subject}", "run": r["run_id"], "tenant": r["tenant"]}
        ref, now = pcm.schema_ref(DOC), time.time()
        six = datetime.datetime.now(datetime.timezone.utc).replace(hour=18, minute=0, second=0, microsecond=0)
        exp = six.timestamp() if six.timestamp() - now > 600 else now + 3600
        args = {"subject": frm["agent"], "intent": ref, "expires_at": svc._iso(exp), "delegable": False,
                "caveats": [{"field": "amount", "op": "<=", "value": 20000}, {"field": "order", "op": "==", "value": 81}]}
        print(f"  alice approves agent A's grant: refund.request, amount <= {_usd(20000)}, order == 81, until "
              f"{time.strftime('%H:%MZ', time.gmtime(exp))}, can be passed on: no")
        dec = call(A, "decide", **run, stream="a", client_seq=0, tool_call_id="grant-1", tool="pcm.grant",
                   args_source="parsed", args=args)
        aid = call(A, "approval_request", **run, tool_call_id="grant-1")["approval_id"]
        call(ALICE, "approval_decide", approval_id=aid, decision="approve")
        call(A, "approval_consume", **run, tool_call_id="grant-1", tool="pcm.grant", args_source="parsed", args=args)
        grant = call(A, "pcm_grant", **run, tool_call_id="grant-1", args=args)["grant"]
        call(A, "complete", **run, stream="a", client_seq=1, tool_call_id="grant-1", decision_id=dec["decision_id"],
             args_digest=event_hash({"tool": "pcm.grant", "args": args}), status="ok",
             result={"grant": event_hash(grant)})
        # the approval, the approval.request it answers and the decision that request names: what alice approved
        seqs = [e["run_seq"] for e in call(A, "read", **run, limit=1000)["events"]
                if e["type"] in ("policy.decision", "approval.request", "approval")]
        s.checkpoint()
        ev = call(A, "pcm_evidence", **run, run_seqs=seqs)
        ev = {"checkpoint": ev["checkpoint"], "records": [{k: x[k] for k in ("event", "hash", "proof")}
                                                         for x in ev["records"]]}
        # covers: alice's approval issued the grant these requests are under, so it covers them
        approved = {"type": "approved_by", "args": {"person": "alice", "call": "grant-1", "covers": True},
                    "evidence": ev}
        trust, replay, verdicts = {"logs": [s.vkey], "algs": ["ed25519"]}, pcm.Replay(), []

        def send(what, claims, amount=12000):
            print(f"  A -> B  {what}")
            msg = call(A, "pcm_sign", **run, message={
                "from": frm, "to": {"agent": B}, "grants": [grant], "claims": claims,
                "intent": {"type": ref, "args": {"amount": amount, "order": 81}}})["message"]
            out = pcm.verify(msg, trust, [DOC], replay=replay, me=B)
            verdicts.append(out["verdict"])
            print(f"      B: {out['verdict'].upper():<16} {summary(out)}")
        send(f"refund.request {{amount {_usd(12000)}, order 81}} + approved_by(alice)", [approved])
        send("same request + tests_passed(pytest tests/test_refund.py), no evidence",
             [approved, {"type": "tests_passed", "args": {"suite": "pytest tests/test_refund.py"}}])
        h = ev["records"][0]["hash"]
        send("approved_by with one record hash changed", [dict(approved, evidence=dict(ev, records=[
            dict(ev["records"][0], hash=h[:-1] + ("1" if h[-1] == "0" else "0"))]))])
        send(f"refund.request {{amount {_usd(50000)}, order 81}} + approved_by(alice)", [approved], amount=50000)
        print("  A asks the signer to sign as B")
        try:
            call(A, "pcm_sign", **run, message={"from": dict(frm, agent=B), "to": {"agent": frm["agent"]},
                                                "intent": {"type": ref, "args": {"amount": 12000, "order": 81}}})
            refused = False
            print("      signer: signed it")
        except RPCError as e:
            refused = e.code == "forbidden"
            print(f"      signer: {e.code}: {e.message}")
        return 0 if refused and verdicts == ["accept", "accept-unproven", "reject", "reject"] else 1
    finally:
        if s:
            s.close()
        shutil.rmtree(d, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit pcm", description="PCM 0.1, proof-carrying messages (experimental)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify", help="check a message offline: exit 0 accept, 3 accept-unproven, 1 reject")
    p.add_argument("msg", help="the message, a JSON file")
    p.add_argument("--trust", required=True, help="the receiver's trust.json (it pins the signer's log key)")
    p.add_argument("--schema", action="append", required=True,
                   help="a schema document both sides agreed on (repeatable)")
    p.add_argument("--strict", action="store_true", help="reject when a claim type the schema needs is not proven")
    p.add_argument("--me", help="the receiver's identity (scheme:subject): reject a message addressed to another")
    p.add_argument("--json", action="store_true", help="print the full result")
    sub.add_parser("demo", help="two agents, a grant and five messages through an in-process signer")
    a = ap.parse_args(argv)
    return verify(a) if a.cmd == "verify" else demo()


if __name__ == "__main__":
    sys.exit(main())
