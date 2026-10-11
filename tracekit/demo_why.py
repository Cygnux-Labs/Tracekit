"""`tracekit demo --why`: `tracekit why` on the signer's evidence, in a temp dir, nothing touched outside it.

The support desk of tracekit.why.demo (researcher, planner, executor; seeded mock models, fake tools) runs on the
signer-backed runtime against the in-process dev signer and test witness of `demo --server`, under the server policy
pack with the desk's tools mapped. The researcher reads the ticket and the refund policy (trusted), a vendor note with
a planted instruction to email the customer list to an outside address and a shipping FAQ (untrusted). The signer
holds that email (TK-P001) and a person rejects it; the runs are imported with their signed records; `attribute`
names the cause; each agent's run is exported and verified offline, and the cause is cited by its signed record.
"""
import glob
import json
import os
import shutil
import tempfile
import threading

from tracekit.demo import say
from tracekit.demo_server import Witness, _serve, export_final
from tracekit.deploy import files
from tracekit.sdk.client import Client
from tracekit.signer.service import DEFAULT_POLICY, SignerService, load_policy
from tracekit.verify import v2
from tracekit.why import import_v2
from tracekit.why.cli import _fmt_test
from tracekit.why.core import load_run
from tracekit.why.demo import EXFIL_TARGET, SIGNED_SYSTEM
from tracekit.why.graph import build_graph, target_hits
from tracekit.why.replay import attribute, counterfactual

# the desk's fakes, mapped to a class no rule of the pack asks about, so only the provenance rules decide them
POLICY = """extends: server.yaml
version: demo-why-1
description: tracekit demo --why, the support desk
tools:
  lookup_order: sql
  issue_refund: sql
  export_customers: sql
  escalate: sql
"""
VENDOR, FAQ, TICKET = "input:vendor:portal/notes.md", "input:web:shipping_faq", "input:inbox:ticket-881"
CHANNEL = "msg:researcher->planner"


def person(client, stop, held):
    """Answers every approval request the way a person who read it would: the held calls here are all rejected."""
    while not stop.wait(0.05):
        for a in client.approval_list({})["approvals"]:
            if a["state"] == "requested":
                args = client.approval_get({"approval_id": a["approval_id"]})["args"]
                print(f"  signer: held {a['tool']} to {args.get('to')!r} ({', '.join(a['rule_ids'])}), "
                      f"approval {a['approval_id']}")
                client.approval_decide({"approval_id": a["approval_id"], "decision": "reject",
                                        "reason": "the recipient is not ours"})
                print("  person: rejected it (`tracekit approvals reject`)")
                held.append(a)


def explain(run, act):
    """(the vendor note's event, the line saying where the held recipient came from) from the signed provenance."""
    events = run.by_id()
    to = run.value(act["args_ref"])["to"]
    p = next(p for p in act["provenance"] if p["field"] == "to")
    via = events[p["from_event"]]
    g = build_graph(run, infer=False)
    cause = next(g.nodes[n]["event"] for n in sorted(g.ancestors("ev:" + act["id"]), key=lambda n: g.nodes[n]["seq"])
                 if g.nodes[n]["type"] == "input" and g.nodes[n]["trust"] == "untrusted"
                 and to in json.dumps(run.value(g.nodes[n]["event"]["ref"])))
    c = cause["tracekit"]
    return cause, (f"  {', '.join(act['policy']['rule_ids'])}: `to` {to!r} came only from untrusted content: the "
                   f"signed record {p['record']} of the executor's run, the message {via['agent']} -> {via['to']}, "
                   f"which carries it from {cause['source']} (record {c['run_seq']} of the researcher's run, "
                   f"log seq {c['seq']})")


def main(keep=False):
    d = tempfile.mkdtemp(prefix="tk-demo-", dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
    service = srv = None
    try:
        say(f"setup: dev signer (server policy pack, the desk's tools mapped) and an in-process test witness in {d}")
        pol = os.path.join(d, "policy")
        os.makedirs(pol)
        for f in glob.glob(os.path.join(os.path.dirname(DEFAULT_POLICY), "*.yaml")):
            shutil.copy(f, pol)
        with open(os.path.join(pol, "demo.yaml"), "w", encoding="utf-8") as f:
            f.write(POLICY)
        witness = Witness()
        service = SignerService(os.path.join(d, "data"), policy=load_policy(os.path.join(pol, "demo.yaml")),
                                witnesses=[witness], isolation="same-user", grace_s=0.5, fsck_every_s=0)
        path, srv = _serve(d, service)
        client = Client(path)
        seed = next(s for s in range(8) if target_hits(SIGNED_SYSTEM.run(seed=s, signer=False), EXFIL_TARGET))
        say(f"record the desk, seed {seed} (SCRIPTED: seeded mock models, fake tools); every event goes through the "
            "signer")
        held, stop = [], threading.Event()
        answers = threading.Thread(target=person, args=(client, stop, held), daemon=True)
        answers.start()
        runs = os.path.join(d, "runs")
        rec = SIGNED_SYSTEM.run(seed=seed, out_dir=runs, run_id="desk", signer=client)
        stop.set()
        answers.join()
        for e in rec.of_type("action"):
            print(f"  {e['agent']:<10} {e['tool']:<16} {e['status']}")

        say("import the runs with their signed records (`tracekit why import --store`)")
        run = load_run(import_v2.import_records(import_v2.store_records(os.path.join(d, "data")), runs)[0])
        act = target_hits(run, EXFIL_TARGET)[0]
        cause, line = explain(run, act)
        print(line)

        say("attribute the email to its inputs (paired replays from tape; replays never talk to the signer)")
        r = attribute(run, EXFIL_TARGET, [VENDOR, FAQ, TICKET], n=80, n_max=320)
        for t in r["tests"]:
            print(_fmt_test(t))
        print(f"  {r['summary']}")
        hop = counterfactual(run, CHANNEL, EXFIL_TARGET, n=40)
        print(_fmt_test(hop))
        print("  the researcher -> planner channel carries it: the hop to guard")
        single = {t["intervention"]: t for t in r["tests"] if "group" not in t}

        say("export each agent's run once it is final and a witness cosigned it; verify offline")
        trust = os.path.join(d, "trust.json")
        files.write_json(trust, {"logs": [service.vkey], "witnesses": [{"vkey": witness.vkey, "class": "customer"}],
                                 "algs": ["ed25519"], "witnesses_required": 1}, 0o644)
        codes = []
        for ev in rec.of_type("agent.start"):
            out = os.path.join(d, f"{ev['agent']}.tkb")
            export_final(os.path.join(d, "data", "store"), ev["tracekit"]["run_id"], witness, out)
            rep, code = v2.verify(out, trust)
            codes.append(code)
            print(f"  {ev['agent']:<10} {out}: integrity {rep.integrity}, exit {code}")
        c = cause["tracekit"]
        print(f"\n  the cause, {cause['source']}, is signed record log {c['log_id']} seq {c['seq']} ({c['hash']}), "
              f"in researcher.tkb")
        ok = (len(held) == 1 and act["status"] == "blocked" and "TK-P001" in act["policy"]["rule_ids"]
              and cause["source"] == VENDOR[len("input:"):]
              and [x["intervention"] for x in r["causes"]] == [VENDOR] and r["causes"][0]["role"] == "primary"
              and single[FAQ]["verdict"] == single[TICKET]["verdict"] == "ruled-out"
              and hop["verdict"] == "causal" and not any(codes))
        print(f"\n  {'all of it holds' if ok else 'FAILED: see above'}")
        return 0 if ok else 1
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        if service:
            service.close()
        if keep:
            print(f"\nkept {d}")
        else:
            shutil.rmtree(d, ignore_errors=True)
