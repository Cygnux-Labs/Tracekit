"""Tracekit demo: a customer-support agent on a server, governed by the server policy pack.

A real v2 signer (keys, store, policy) in a temp dir, a witness that cosigns its checkpoints, and an agent that talks
to the signer over its Unix socket. A person (alice, an ops approver) approves the refund from another identity.
Recorded as server-demo.gif by server-demo.tape (vhs); PACE=0 runs it at full speed.
"""
import os
import shutil
import sys
import tempfile
import time
import zipfile

from tracekit.demo_server import Witness, _serve, export_final
from tracekit.deploy import files
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService, load_policy
from tracekit.verify import v2
import tracekit.policy2 as p2

B, D, G, R, Y, C, X = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m"
PACE = float(os.environ.get("PACE", "0.9"))
ALICE = CallerIdentity("mtls", "spiffe://acme/ops/alice", True)
COLOR = {"allow": G, "deny": R, "ask": Y, "flag": C}


def step(title):
    time.sleep(PACE)
    print(f"\n{B}▶ {title}{X}", flush=True)
    time.sleep(PACE / 2)


def show(tool, args, d):
    a = ", ".join(f"{k}={v!r}" for k, v in args.items())
    rules = " ".join(d["rule_ids"])
    print(f"  {tool}({a[:70]})\n      → {COLOR.get(d['decision'], '')}{d['decision'].upper()}{X} {D}{rules}{X}",
          flush=True)
    time.sleep(PACE)


def edit_drop_table(src, dst):
    """A copy where the DROP TABLE call's decision record says allow."""
    with zipfile.ZipFile(src) as z:
        bundle = {n: z.read(n) for n in z.namelist()}
    name = next(n for n in bundle if n.startswith("runs/"))
    lines = bundle[name].split(b"\n")
    for i, line in enumerate(lines):
        if b'"tool_call_id":"c5"' in line and b'"decision":"deny"' in line:
            lines[i] = line.replace(b'"decision":"deny"', b'"decision":"allow"')
    bundle[name] = b"\n".join(lines)
    with zipfile.ZipFile(dst, "w") as z:
        for n, v in bundle.items():
            z.writestr(n, v)


def main():
    d = tempfile.mkdtemp(prefix="tk-", dir="/tmp")
    service = srv = None
    try:
        step("Start a Tracekit signer: it holds the keys, the log and the policy; the agent holds none of them")
        witness = Witness()
        policy = os.path.join(os.path.dirname(p2.__file__), "packs", "server.yaml")
        service = SignerService(os.path.join(d, "data"), witnesses=[witness], isolation="separate-user", grace_s=0.5,
                                fsck_every_s=0, policy=load_policy(policy),
                                approvals={"self_approval": "deny", "approvers": ["mtls:spiffe://acme/ops/*"]},
                                authorize={"mtls:spiffe://acme/ops/*": ["approval_list", "approval_get",
                                                                       "approval_decide"]})
        path, srv = _serve(d, service)
        print(f"  policy: server.yaml   approvers: spiffe://acme/ops/*   witness: {witness.name}")

        step("The support agent works a ticket: \"Order 4417 arrived broken, please refund\"")
        client = Client(path)
        calls = [
            ("c1", "run_sql", {"sql": "SELECT status, total FROM orders WHERE id = 4417"}),
            ("c2", "http_get", {"url": "https://api.shipping.example/track/4417"}),
            ("c3", "http_get", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}),
            ("c4", "Read", {"file_path": "/home/agent/.aws/credentials"}),
            ("c5", "run_sql", {"sql": "SELECT 1; /* cleanup */ DROP TABLE orders"}),
            ("c6", "create_refund", {"order": 4417, "amount": 129.00, "currency": "USD"}),
            ("c7", "send_email", {"to": ["dana@customer.example"], "subject": "Your refund for order 4417"}),
        ]
        with client.run(agent="support-agent") as run:
            for cid, tool, args in calls:
                dec = run.decide(cid, tool, args)
                show(tool, args, dec)
                hint = None
                if dec["decision"] == "ask":
                    hint = run.call("approval_request", tool_call_id=cid)["approval_id"]
                    print(f"      {Y}held for a person{X}: approval {hint[:16]}…", flush=True)
                    time.sleep(PACE)
                    try:
                        client.approval_decide({"approval_id": hint, "decision": "approve"})
                    except RPCError as e:
                        print(f"      the agent tries to approve its own refund → {R}refused{X}: {e.message}",
                              flush=True)
                    time.sleep(PACE)
                    a = service.call(ALICE, "approval_decide", {"request_id": "ops-1", "approval_id": hint,
                                                                "decision": "approve",
                                                                "reason": "photo of the damage checked"})
                    print(f"      alice (ops, mTLS) approves: {G}{a['state']}{X}, bound to these exact arguments",
                          flush=True)
                    time.sleep(PACE)
                if dec["decision"] != "deny" and run.approval_consume(cid, tool, args, approval_id_hint=hint)["ok"]:
                    run.complete(cid)
            run_id = run.run_id
        client.close()

        step("Export the run as a bundle once a witness has cosigned a checkpoint covering it")
        out, trust = os.path.join(d, "ticket-4417.tkb"), os.path.join(d, "trust.json")
        export_final(os.path.join(d, "data", "store"), run_id, witness, out)
        files.write_json(trust, {"logs": [service.vkey], "witnesses": [{"vkey": witness.vkey, "class": "customer"}],
                                 "algs": ["ed25519"], "witnesses_required": 1}, 0o644)
        print(f"  ticket-4417.tkb  ({os.path.getsize(out)} bytes)   trust.json pins the log key and the witness")

        step("An auditor verifies it offline: `tracekit verify ticket-4417.tkb --trust trust.json`")
        rep, code = v2.verify(out, trust)
        v2.print_report(rep, code)
        time.sleep(PACE * 3)

        step("Someone edits the bundle so the denied DROP TABLE reads as allowed…")
        bad = os.path.join(d, "edited.tkb")
        edit_drop_table(out, bad)
        rep2, code2 = v2.verify(bad, trust)
        for c in rep2.checks:
            if c["status"] == "fail":
                print(f"  {R}[FAIL]{X} {c['check']}")
                for prob in c["problems"]:
                    print(f"        {prob}")
        print(f"\n  Integrity: {R}{B}{rep2.integrity}{X}")
        print(f"\n  original bundle: exit {code}    edited bundle: exit {code2}", flush=True)
        time.sleep(PACE * 3)
        return 0 if code == 0 and code2 else 1
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        if service:
            service.close()
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
