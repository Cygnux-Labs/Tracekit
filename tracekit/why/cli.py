"""`tracekit why` command line."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile

from .core import load_run, verify
from .evals import influence_index, influence_matrix, list_runs, structure
from .graph import build_graph, taint, target_hits
from .replay import attribute, counterfactual, decision_test, diff_runs, load_system, replay


def _p(*a):
    """Print, replacing what the console's encoding can't show (a Windows cp1252 console and the arrow in edge labels)."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(" ".join(map(str, a)).encode(enc, "replace").decode(enc), flush=True)


def _fmt_test(r):
    if r.get("p_with") is None:
        return (f"  remove {r['intervention']:<28} target {r['target']:<40} "
                f"changed in {r['effect']:+.0%} more calls than noise ({r.get('noise') or 0:.0%}) "
                f"[{r['ci'][0]:+.2f}, {r['ci'][1]:+.2f}] n={r['n']}  "
                f"{r['verdict'].upper()}")
    return (f"  remove {r['intervention']:<28} target {r['target']:<40} "
            f"P(with)={r['p_with']:.2f} P(without)={r['p_without']:.2f} "
            f"effect={r['effect']:+.2f} [{r['ci'][0]:+.2f}, {r['ci'][1]:+.2f}] n={r['n']}  {r['verdict'].upper()}"
            + (f" ({r['role']})" if r.get("role") else "")
            + (f" (target reproduced in {r['p_with']:.0%} of replays; try n={r['n_needed']})" if r.get("n_needed") else "")
            + (" (budget: raise --max-calls or --max-cost to go on)" if r.get("stopped") == "budget" else ""))


def _records(a):
    """The records of the signed run --run, from --store or a verified --bundle."""
    from . import import_v2
    if a.store:
        records = import_v2.store_records(a.store, a.signed_run).get(a.signed_run)
    elif a.bundle and a.trust:
        found, rep, code = import_v2.bundle_records(a.bundle, a.trust)
        if code:
            raise SystemExit(f"tracekit why: refused {a.bundle}: it does not verify against {a.trust}")
        records = found.get(a.signed_run)
    else:
        raise SystemExit("tracekit why: --run needs --store DIR, or --bundle FILE with --trust FILE")
    if not records:
        raise SystemExit(f"tracekit why: no run {a.signed_run}")
    return records


def _investigation(a):
    """The signed run --run, from --store or a verified --bundle, with the signer ($TRACEKIT_SIGNER) for its content and
    --gateway for its replays."""
    import ssl
    from ..sdk.client import Client
    from ..usage import Prices
    from . import signed
    records = _records(a)
    if not a.gateway:
        raise SystemExit("tracekit why: replays of a signed run go through the Tracekit gateway: pass --gateway URL")
    headers = {}
    if a.gateway_token_file:
        with open(a.gateway_token_file, encoding="utf-8") as f:
            headers["Authorization"] = "Bearer " + f.read().strip()
    ctx = None
    if a.gateway_ca or a.gateway_cert:
        ctx = ssl.create_default_context(cafile=a.gateway_ca)
        if a.gateway_cert:
            ctx.load_cert_chain(a.gateway_cert, a.gateway_key)
    try:
        return signed.Investigation(records, Client(), a.gateway, headers=headers, context=ctx,
                                    investigation=a.investigation, max_calls=a.max_calls, max_cost=a.max_cost,
                                    prices=Prices.load(a.prices) if a.prices else None)
    except signed.EvidenceAlert as e:
        print(f"tracekit why: [HIGH] {e}", file=sys.stderr)
        raise SystemExit(1) from None


def _signed_errors():
    """What a signed-run test reports and exits 2 on: a bad spec or run, the gateway's or the signer's refusal, a budget
    spent before any test finished (the surrogate's ranking)."""
    from ..sdk.client import SignerUnavailable
    from ..signer.rpc_schema import RPCError
    from .signed import Budget
    return ValueError, RuntimeError, OSError, RPCError, SignerUnavailable, Budget


def _signed_error(cmd, e):
    from .signed import Budget
    print(f"tracekit why {cmd}: " + ("inconclusive (budget): the investigation's budget ran out before a test "
                                     "finished; raise --max-calls or --max-cost" if isinstance(e, Budget) else str(e)),
          file=sys.stderr)
    return 2


def _signed_args(p):
    p.add_argument("--run", dest="signed_run", help="a Tracekit v2 run id: test the signed run (with --store or "
                   "--bundle, and --gateway); its content comes from the signer's vault ($TRACEKIT_SIGNER)")
    p.add_argument("--store", metavar="DIR", help="with --run: the signer data dir holding the run")
    p.add_argument("--bundle", metavar="FILE", help="with --run: a v2 bundle holding the run, verified with --trust")
    p.add_argument("--trust", help="with --bundle: the v2 trust config")
    p.add_argument("--gateway", metavar="URL", help="with --run: the Tracekit gateway every replay calls models through")
    p.add_argument("--gateway-token-file", help="the investigator's bearer token for the gateway")
    p.add_argument("--gateway-ca", help="the CA the gateway's certificate must chain to")
    p.add_argument("--gateway-cert", help="the investigator's client certificate for the gateway (mTLS)")
    p.add_argument("--gateway-key", help="the key of --gateway-cert")
    p.add_argument("--investigation", help="the investigation id (default: a new one): content_get's purpose and "
                   "every replay run's investigation")
    p.add_argument("--rung", type=int, choices=(1, 2), help="1: re-send one model call; 2: re-simulate the loop "
                   "from the vault (default: 1 with --decision, else 2)")
    p.add_argument("--max-calls", type=int, help="budget: model calls for the whole investigation")
    p.add_argument("--max-cost", type=float, help="budget: estimated cost (needs --prices)")
    p.add_argument("--prices", help="price table for --max-cost (tracekit/usage.py)")


def _system(a, run):
    """The System to replay `run` with: --system, else the program the run names when --allow-program lists it. A run
    file is data: the program it names is never imported on its say-so alone."""
    if a.system:
        return load_system(a.system)
    prog = run.start.get("program")
    if prog and prog in (a.allow_program or []):
        return load_system(prog)
    raise SystemExit(f"this run names the program {prog!r}: replaying it imports that module, so pass --system {prog} "
                     f"(or --allow-program {prog}) if you trust it" if prog else
                     "this run names no program to replay: pass --system module:ATTR")


def _positive(v):
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def cmd_demo(a):
    from .demo import EXFIL_TARGET, REFUND_TARGET, SYSTEM
    out = a.out or tempfile.mkdtemp(prefix="tracekit-why-")
    _p(f"== record: 8 runs of a 3-agent support system (seeded mock models, fake tools) -> {out}")
    exfil = []
    for s in range(8):
        r = SYSTEM.run(seed=s, out_dir=out, run_id=f"demo-seed{s}", signer=False)   # scripted: no evidence
        hit = bool(target_hits(r, EXFIL_TARGET))
        if hit:
            exfil.append(load_run(r.path))
        _p(f"  demo-seed{s}: {', '.join(a['tool'] for a in r.of_type('action'))}{'   <- exfiltration' if hit else ''}")
    assert exfil, "no exfiltration in 8 seeds"
    run = exfil[0]
    _p(f"\n== investigating {run.run_id}")
    for e in run.of_type("action"):
        _p(f"  {e['agent']:<10} {e['tool']:<16} {json.dumps(run.value(e['args_ref']))}")
    problems = verify(run)
    _p(f"\n== verify: {'hash chain intact, ' + str(len(run.events)) + ' events' if not problems else problems}")

    _p("\n== blast radius (observed edges): what did each untrusted input reach?")
    g = build_graph(run)
    for n in g.nodes.values():
        if n["type"] == "input" and n["trust"] == "untrusted":
            t = taint(run, [f"input:{n['label']}"], graph=g)
            _p(f"  {n['label']:<24} reached {len(t['actions'])} actions: {', '.join(x['tool'] for x in t['actions'])}")
    _p("  Every untrusted input reached the exfiltration email. Reach alone cannot say which one caused it.")

    _p(f"\n== counterfactual tests (n={a.n} paired replays each; tools served from tape)")
    tests = [("input:vendor:portal/notes.md", EXFIL_TARGET), ("input:web:shipping_faq", EXFIL_TARGET),
             ("input:inbox:ticket-881", EXFIL_TARGET), ("msg:researcher->planner", EXFIL_TARGET),
             ("input:kb:refund_policy.md", REFUND_TARGET)]
    for spec, target in tests:
        _p(_fmt_test(counterfactual(run, spec, target, n=a.n, system=SYSTEM)))
    if len(exfil) > 1:  # a second run, so the cross-run influence view has more than one data point
        for spec in ("input:vendor:portal/notes.md", "input:web:shipping_faq"):
            counterfactual(exfil[1], spec, EXFIL_TARGET, n=a.n, system=SYSTEM)
    dec = run.of_type("decision")[0]
    _p("\n== decision-level test (re-call only the researcher's model call; no program re-run needed)")
    _p(_fmt_test(decision_test(run, dec["seq"], "input:vendor:*", n=a.n, contains="vendor-compliance", system=SYSTEM)))

    st = structure(run)
    _p("\n== structure")
    _p("  critical path: " + " -> ".join(st["critical_path"]))
    html = _write_report(out, None)
    _p(f"\nruns:   {out}\nreport: {html}   (static; open in a browser)")
    _p(f"live:   tracekit view --why {out} --allow-program tracekit.why.demo:SYSTEM")


def _write_report(root, output):
    from .view import render_report
    out = output or os.path.join(root, "report.html")
    page = render_report(root)
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    return out


def cmd_report(a):
    _p(_write_report(a.root, a.output))


def cmd_verify(a):
    run = load_run(a.run)
    problems = verify(run)
    if problems:
        for p in problems:
            _p("[FAIL] " + p)
        return 1
    _p(f"[PASS] {len(run.events)} events, chain intact, {len(run.blobs)} blobs match their hashes")
    _p("       (hash-chained, not signed; record with the Tracekit signer to sign and witness it)")
    if not a.salts:
        return 0
    from .import_v2 import check_content
    try:
        with open(a.salts, encoding="utf-8") as f:
            rows = check_content(run, [json.loads(line) for line in f if line.strip()])
    except (OSError, ValueError) as e:   # json's errors are ValueErrors
        print(f"tracekit why verify: {a.salts}: {e}", file=sys.stderr)
        return 2
    for r in rows:
        _p(f"  {r['verdict']:<13} {r['kind']:<8} {r['agent']:<12} log seq {r['seq']} {r['type']}"
           + (f": {r['detail']}" if r.get("detail") else ""))
    n = {v: sum(r["verdict"] == v for r in rows) for v in ("matched", "mismatched", "bad salt row", "not revealed")}
    if not rows:
        _p("  no event cites a record with a commitment: import the run from the signer first (`why import --store`)")
    _p(f"content: {n['matched']} matched, {n['mismatched']} mismatched (content or salt does not match), "
       f"{n['bad salt row']} bad salt rows, {n['not revealed']} not revealed"
       + (" (reveal their salts with `tracekit signer reveal --record SEQ`)" if n["not revealed"] else ""))
    return 1 if n["mismatched"] else 2 if n["bad salt row"] else 0


def cmd_graph(a):
    g = build_graph(load_run(a.run), infer=not a.no_infer)
    if a.json:
        d = g.to_dict()
        for n in d["nodes"]:
            n.pop("event", None)
        _p(json.dumps(d, indent=2, default=str))
        return
    for e in g.edges:
        s, t = g.nodes[e["src"]], g.nodes[e["dst"]]
        extra = "".join(f" {k}={e[k]}" for k in ("reuse", "score", "effect") if k in e)
        _p(f"{s['label']}[{s['agent']}] -> {t['label']}[{t['agent']}]  {e['kind']} ({e['evidence']}){extra}")


def cmd_taint(a):
    r = taint(load_run(a.run), a.source or ["untrusted"], include_inferred=a.inferred)
    if a.json:
        _p(json.dumps(r, indent=2, default=str))
        return
    _p("sources: " + ", ".join(s["label"] for s in r["sources"]))
    _p("agents reached: " + ", ".join(r["agents_reached"]))
    for x in r["actions"]:
        _p(f"  #{x['seq']} {x['agent']}.{x['tool']} {json.dumps(x['args'])}\n      via " + " > ".join(x["path"]))


def cmd_test(a):
    if a.signed_run:
        from .signed import counterfactual_signed
        if not a.target:
            raise SystemExit("--target is required")
        inv = _investigation(a)
        try:
            r = counterfactual_signed(inv, a.remove, a.target, decision=a.decision, rung=a.rung, n=a.n,
                                      n_max=a.n_max, workers=a.workers)
        except _signed_errors() as e:
            return _signed_error("test", e)
        finally:
            inv.finish()
        _p(json.dumps(r, indent=2) if a.json else _fmt_test(r) + _fmt_signed(r))
        return 0
    if not a.run:
        raise SystemExit("tracekit why test needs a why run, or --run with a signed run")
    run = load_run(a.run)
    if a.decision is not None:
        models, system = None, None
        if a.anthropic:  # re-send calls recorded by the Anthropic adapter
            from anthropic import Anthropic
            from .adapters.anthropic import replay_model
            fn = replay_model(Anthropic().messages)
            models = {e["model"]: fn for e in run.of_type("decision")}
        else:
            system = _system(a, run)
        r = decision_test(run, a.decision, a.remove, n=a.n, system=system, models=models, contains=a.contains,
                          n_max=a.n_max)
    else:
        if not a.target:
            raise SystemExit("--target is required unless --decision is given")
        r = counterfactual(run, a.remove, a.target, n=a.n, system=_system(a, run), live_tools=a.live_tools,
                           n_max=a.n_max)
    _p(json.dumps(r, indent=2) if a.json else _fmt_test(r))


def _fmt_signed(r):
    return (f"\n  rung {r['rung']} at record {r['decision']}: {len(r['replay_runs'])} replay runs, "
            f"{r['off_tape_actions']} off-tape actions; assumes {'; '.join(r['assumptions'])}"
            + (f"\n  signed as why.finding (findings run record {r['finding']})" if "finding" in r else ""))


def cmd_attribute(a):
    if a.signed_run:
        from .signed import attribute_signed
        inv = _investigation(a)
        try:
            r = attribute_signed(inv, a.target, a.suspect or None, decision=a.decision, rung=a.rung,
                                 n=a.n, n_max=a.n_max, workers=a.workers, size_roles=not a.no_roles)
        except _signed_errors() as e:
            return _signed_error("attribute", e)
        finally:
            inv.finish()
        if a.json:
            _p(json.dumps(r, indent=2, default=str))
            return 0
        for it in (r["ranking"] or {}).get("items", [])[:8]:
            _p(f"  predicted {it['weight']:+.3f} {it['spec']}  {it['preview'][:60]}")
        _p(f"suspects: {', '.join(r['suspects'])}")
        for t in r["tests"]:
            _p(_fmt_test(t) + _fmt_signed(t))
        _p(f"\n{r['summary']}\n({r['model_calls']} model calls, {len(r['tests'])} tests, corrected for {r['family']})")
        return 0
    if a.langgraph:
        import importlib
        from .langgraph import attribute_thread
        if not a.thread:
            raise SystemExit("--langgraph needs --thread")
        if a.run or a.system or a.workers != 1:
            raise SystemExit("--langgraph replays the thread itself: drop the run folder, --system and --workers")
        mod, _, attr = a.langgraph.partition(":")
        graph = getattr(importlib.import_module(mod), attr or "graph_factory")()
        r = attribute_thread(graph, {"configurable": {"thread_id": a.thread}}, a.target, a.suspect or None,
                             checkpoint_id=a.checkpoint, n=a.n, n_max=a.n_max, size_roles=not a.no_roles,
                             log=a.out, routing=a.routing or ())
    elif a.run:
        run = load_run(a.run)
        r = attribute(run, a.target, a.suspect or None, n=a.n, n_max=a.n_max, system=_system(a, run),
                      workers=a.workers, size_roles=not a.no_roles)
    else:
        raise SystemExit("give a run folder, --run with a signed run, or --langgraph module:graph_factory --thread T")
    if a.json:
        _p(json.dumps(r, indent=2, default=str))
        return
    _p(f"suspects: {', '.join(r['suspects'])}")
    for t in r["tests"]:
        _p(_fmt_test(t))
    _p(f"\n{r['summary']}")
    _p(f"({r['program_runs']} program runs, {len(r['tests'])} tests, corrected for {r['family']})")
    if r.get("rung") == 3:
        _p(f"(rung 3: forked checkpoint {r['fork']['checkpoint_id']} as node {r['fork']['as_node']}; tool results "
           "from the thread, never the real tools)")


def cmd_transfer(a):
    import importlib
    from ..sdk.client import Client
    from .signed import EvidenceAlert
    from .transfer import effect
    mod, _, attr = a.receiver.partition(":")
    receiver = getattr(importlib.import_module(mod), attr or "receiver")
    try:
        r = effect(Client(), _records(a), receiver, a.investigation or "tracekit why transfer", seq=a.transfer)
    except EvidenceAlert as e:
        print(f"tracekit why: [HIGH] {e}", file=sys.stderr)
        return 1
    except _signed_errors() as e:
        return _signed_error("transfer", e)
    _p(json.dumps(r, indent=2) if a.json else
       f"  transfer {r['seq']} {r['sender']} -> {r['receiver']} (names claimed by the caller): "
       f"change {r['change']:.3f}\n  {r['sentence']}")
    return 0


def cmd_matrix(a):
    run = load_run(a.run)
    rows = influence_matrix(run, a.target, n=a.n, system=_system(a, run))
    for r in rows:
        _p(_fmt_test(r))


def cmd_replay(a):
    run = load_run(a.run)
    rep = replay(run, system=_system(a, run), interventions=a.remove or [])
    d = diff_runs(run, rep)
    _p("replay matches the original" if not d else json.dumps(d, indent=2))


def cmd_record(a):
    from .guard import Guard, webhook
    sysm = load_system(a.system)
    guard = None
    if a.guard != "off":
        guard = Guard(a.guard, on_alert=_print_and(webhook(a.webhook) if a.webhook else None))
    r = sysm.run(seed=a.seed, out_dir=a.out, guard=guard)
    _p(r.path)


def _print_and(then):
    def on_alert(al):
        verb = "BLOCKED" if al.get("blocked") else al["severity"].upper()
        _p(f"  [{verb}] {al['agent']}.{al['tool']} #{al['seq']}: {al['title']}. {al.get('detail', '')}")
        if then:
            then(al)
    return on_alert


def cmd_watch(a):
    """Follow a runs folder in the terminal: print new alerts as runs are recorded."""
    from .server import Store
    store = Store(a.root, webhook=a.webhook)
    store.watch(a.interval)
    _p(f"watching {a.root} (Ctrl-C to stop)")
    feed, last = store.out, 0
    try:
        while True:
            with feed.lock:
                feed.lock.wait_for(lambda: len(feed.records) > last, timeout=1)
                new = feed.records[last:]
            last += len(new)
            for m in (r["why"] for r in new):
                if m["type"] != "run":
                    continue
                state = "finished" if m["finished"] else "running"
                if m["alerts"] or m["finished"]:
                    _p(f"{m['run_id']}: {m['events']} events, {state}")
                for al in m["alerts"]:
                    _p(f"  [{al['severity'].upper()}] {al.get('agent') or ''}.{al.get('tool') or ''} "
                       f"#{al.get('seq')}: {al['title']}. {al.get('detail') or ''}")
    except KeyboardInterrupt:
        pass
    finally:
        store.stop()


def cmd_serve(a):
    """The viewer (tracekit view's page and server) on the why logs under ROOT, with no signer store: `tracekit view
    --why ROOT` runs the same."""
    import ssl
    from .. import view
    from ..observe import LOOPBACK_HOSTS
    from .server import Store
    print("tracekit why serve is now part of tracekit view: `tracekit view --why ROOT`; this command keeps working",
          file=sys.stderr, flush=True)
    if bool(a.tls_cert) != bool(a.tls_key):
        print("tracekit why serve: --tls-cert and --tls-key go together", file=sys.stderr)
        return 2
    if a.host not in LOOPBACK_HOSTS and not a.tls_cert and not a.insecure_http:
        print("tracekit why serve: refusing plain HTTP beyond loopback; pass --tls-cert and --tls-key "
              "(or --insecure-http if TLS is terminated in front)", file=sys.stderr)
        return 2
    tls = None
    if a.tls_cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(a.tls_cert, a.tls_key)
    given = a.token or os.environ.get("TRACEKIT_WHY_TOKEN")
    token = given or secrets.token_urlsafe(24)
    store = Store(a.root, a.allow_program or [], webhook=a.webhook, tape=True, ingest_tokens=a.ingest_token or [])
    httpd = view.server(store.out, a.host, a.port, token, tls, why=store)
    store.watch()
    _p(f"tracekit why on {'https' if tls else 'http'}://{a.host}:{httpd.server_address[1]}/"
       + ("" if given else f"?token={token}") + f"  (runs: {a.root})")
    _p("  ingest: POST /v1/ingest with " + ("an --ingest-token" if a.ingest_token else "the token")
       + " as a Bearer token")
    _p(f"  live: the page updates as runs are recorded{'; high alerts POSTed to ' + a.webhook if a.webhook else ''}")
    _p("  FIND THE CAUSE and RUN TEST: " + (f"replay {', '.join(a.allow_program)}" if a.allow_program else
                                          "show the command to run (--allow-program module:SYSTEM to run them here)"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        store.stop()


def cmd_import(a):
    if not a.v1:
        return _import_v2(a)
    if not a.src:
        raise SystemExit("tracekit why import --v1 needs the Tracekit home, ledger directory or ledger.jsonl")
    from . import import_v1 as tk
    if a.list:
        recs = tk.read_ledger(tk.ledger_path(a.src))
        for rid, n in tk.runs_in(recs):
            _p(f"{rid}  ({n} records)")
        return 0
    paths = tk.import_ledger(a.src, a.out, run=a.run, untrusted_tools=a.untrusted_tool or ("*",),
                             trusted_tools=a.trusted_tool or tk.SUBAGENT_TOOLS, sensitive_tools=a.sensitive or ())
    for p in paths:
        run = load_run(p)
        meta = run.start.get("meta") or {}
        sig = meta.get("signatures") or {}
        decs = run.of_type("decision")
        exact = sum(1 for d in decs if d.get("context_mode") == "exact")
        _p(f"{p}: {len(run.events)} events, {len(decs)} model calls ({exact} with exact context), "
           f"{len(run.of_type('action'))} tool calls, content capture: {meta.get('content_capture')}")
        _p("  signatures: " + ("verified" if sig.get("verified") else "FAILED: " + "; ".join(sig.get("problems", []))
                               if sig.get("verified") is False else "; ".join(sig.get("problems", [])) or "not checked"))
        if meta.get("content_capture") == "hashed":
            _p("  content was hashed by Tracekit: argument provenance cannot trace values "
               "(set content_capture: full for untrusted tools)")
        if not decs:
            _p("  no model calls recorded: enable Tracekit autotrace, the SDK or the model proxy for decisions")
    return 0


def _import_v2(a):
    from . import import_v2 as tk
    if a.store:
        try:
            if a.list:
                for rid, n in sorted(tk.store_runs(a.store).items()):
                    _p(f"{rid}  ({n} records)")
                return 0
            records = tk.store_records(a.store, a.run)
        except (OSError, ValueError) as e:
            print(f"tracekit why import: {e}", file=sys.stderr)
            return 2
    else:
        if not a.trust:
            raise SystemExit("tracekit why import --bundle needs --trust, the trust config to verify it against")
        records, rep, code = tk.bundle_records(a.bundle, a.trust)
        if code:
            from ..verify import v2
            v2.print_report(rep, code)
            print(f"tracekit why import: refused {a.bundle}: it does not verify against {a.trust}; nothing imported",
                  file=sys.stderr)
            return code
    if a.list:
        for rid, recs in sorted(records.items()):
            _p(f"{rid}  ({len(recs)} records)")
        return 0
    if a.run:
        records = {k: v for k, v in records.items() if k == a.run}
    if a.run and not records:
        print(f"tracekit why import: no run {a.run} to import", file=sys.stderr)
        return 2
    rechecked = tk.recheck(records, a.out)   # the imports already there, before this one adds its own
    try:
        paths = tk.import_records(records, a.out)
    except FileExistsError as e:
        print(f"tracekit why import: {e}", file=sys.stderr)
        return 2
    for p in paths:
        run = load_run(p)
        meta = run.start.get("meta") or {}
        _p(f"{p}: {len(run.events)} events, {len(run.of_type('action'))} tool calls, from Tracekit runs "
           f"{', '.join(meta.get('tracekit_runs', []))}" + (f" (merged with {meta['merged_from']})"
                                                          if meta.get("merged_from") else ""))
        for al in meta.get("evidence_alerts", []):
            _p(f"  [HIGH] {al['title']}: {al['detail']}")
        if not meta.get("merged_from"):
            _p("  content is committed, not in the signed log: record with the signer-backed runtime for content")
    for p, alerts in rechecked:
        _p(f"{p}: an earlier import that cites these runs does not hold against them")
        for al in alerts:
            _p(f"  [HIGH] {al['title']}: {al['detail']}")
    return 1 if rechecked else 0


def cmd_index(a):
    rows = influence_index(list_runs(a.root), a.target or [])
    if a.json:
        _p(json.dumps(rows, indent=2, default=str))
        return
    for r in rows[: a.top]:
        best = max(r["tested"], key=lambda t: t["effect"], default=None)
        tested = f"max effect {best['effect']:+.2f} on {best['target']}" if best else "untested"
        _p(f"{r['ref'][:19]} {','.join(r['sources']):<28} {r['trust']:<9} in {r['runs']} runs, "
           f"reached actions in {r['reached_action_runs']}, {tested}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit why", description="Causal logs, replay and investigation for multi-agent systems")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("demo", help="record the 3-agent demo, test causes, write the static report")
    p.add_argument("--out"); p.add_argument("--n", type=_positive, default=40); p.set_defaults(f=cmd_demo)

    p = sp.add_parser("record", help="run a System (module:ATTR) and record it")
    p.add_argument("system"); p.add_argument("--out", default="runs"); p.add_argument("--seed", type=int, default=0)
    p.add_argument("--guard", choices=("off", "alert", "block"), default="off",
                   help="check sensitive tool calls before they run")
    p.add_argument("--webhook", help="POST high alerts here (with --guard)")
    p.set_defaults(f=cmd_record)

    p = sp.add_parser("verify", help="check the hash chain and blobs (and with --salts, content against commitments)")
    p.add_argument("run")
    p.add_argument("--salts", help="JSON lines of `tracekit signer reveal` for the records the run cites")
    p.set_defaults(f=cmd_verify)

    p = sp.add_parser("graph", help="print edges with evidence grades")
    p.add_argument("run"); p.add_argument("--json", action="store_true"); p.add_argument("--no-infer", action="store_true")
    p.set_defaults(f=cmd_graph)

    p = sp.add_parser("taint", help="blast radius of sources (default: everything untrusted)")
    p.add_argument("run"); p.add_argument("--source", action="append"); p.add_argument("--inferred", action="store_true")
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_taint)

    p = sp.add_parser("test", help="counterfactual: does removing X change whether target happens?")
    p.add_argument("run", nargs="?"); p.add_argument("--remove", required=True); p.add_argument("--target")
    p.add_argument("--decision", type=int, help="test one recorded model call (seq; with --run: the run_seq of its "
                   "request record) instead of re-running the program")
    p.add_argument("--contains", help="with --decision: measure P(output contains this text)")
    p.add_argument("--anthropic", action="store_true",
                   help="with --decision: re-send a call recorded by the Anthropic adapter (needs ANTHROPIC_API_KEY)")
    p.add_argument("--n", type=_positive, default=30); p.add_argument("--system"); p.add_argument("--live-tools", action="store_true")
    p.add_argument("--allow-program", action="append", metavar="SPEC", help="replay the program the run names if it is this one (repeatable); without it or --system, nothing is imported")
    p.add_argument("--n-max", type=_positive, help="sequential: keep doubling n up to this until the verdict is decisive")
    p.add_argument("--workers", type=int, default=1, help="with --run: replay arms in parallel (1 to 16)")
    _signed_args(p)
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_test)

    p = sp.add_parser("attribute", help="which inputs caused an action: group test first, then narrow down")
    p.add_argument("run", nargs="?", help="run folder (or --langgraph, or --run)"); p.add_argument("--target", required=True)
    p.add_argument("--decision", type=int, help="with --run: the run_seq of the model call's request record (rung 1)")
    _signed_args(p)
    p.add_argument("--suspect", action="append", help="intervention spec, or with --langgraph a message id or tool_call_id "
                   "(default: untrusted inputs upstream)")
    p.add_argument("--langgraph", metavar="MODULE:FACTORY",
                   help="fork replay of a LangGraph thread: imports and calls FACTORY(), which returns the compiled "
                        "graph over the app's checkpointer (only name code you trust, as with --system)")
    p.add_argument("--thread", help="with --langgraph: the thread_id to investigate")
    p.add_argument("--checkpoint", help="with --langgraph: start from this checkpoint_id (default: the thread's latest)")
    p.add_argument("--routing", action="append", metavar="NAME", help="with --langgraph: a call a node of the app "
                   "answers itself, not a ToolNode (a routing schema; repeatable)")
    p.add_argument("--out", default="runs", help="with --langgraph: why log folder; tests go to "
                                                 "OUT/langgraph-<thread>/tests.jsonl")
    p.add_argument("--n", type=_positive, default=10); p.add_argument("--n-max", type=_positive, default=80)
    p.add_argument("--allow-program", action="append", metavar="SPEC", help="replay the program the run names if it is this one (repeatable); without it or --system, nothing is imported")
    p.add_argument("--workers", type=int, default=1, help="parallel replays")
    p.add_argument("--no-roles", action="store_true", help="skip sizing each cause (primary vs contributing): cheaper")
    p.add_argument("--system"); p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_attribute)

    p = sp.add_parser("transfer", help="how much a kept transfer changed its receiver's answer: re-run it with and "
                                       "without what was sent (experimental)")
    p.add_argument("--run", dest="signed_run", required=True, help="a Tracekit v2 run id; the transfer's content comes "
                   "from the signer's vault ($TRACEKIT_SIGNER)")
    p.add_argument("--store", metavar="DIR", help="the signer data dir holding the run")
    p.add_argument("--bundle", metavar="FILE", help="a v2 bundle holding the run, verified with --trust")
    p.add_argument("--trust", help="with --bundle: the v2 trust config")
    p.add_argument("--receiver", required=True, metavar="MODULE:ATTR", help="the receiver: called with what was sent "
                   "(a C2C cache, else bytes) and with None, it returns the answer (only name code you trust)")
    p.add_argument("--transfer", type=int, metavar="SEQ", help="the run_seq of the transfer's decision (default: the "
                   "run's last completed transfer)")
    p.add_argument("--investigation", help="content_get's purpose (default: tracekit why transfer)")
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_transfer)

    p = sp.add_parser("matrix", help="test every channel and input against targets")
    p.add_argument("run"); p.add_argument("--target", action="append", required=True); p.add_argument("--n", type=_positive, default=20)
    p.add_argument("--system"); p.add_argument("--allow-program", action="append", metavar="SPEC", help="replay the program the run names if it is this one (repeatable); without it or --system, nothing is imported"); p.set_defaults(f=cmd_matrix)

    p = sp.add_parser("replay", help="re-run from tape and diff against the original")
    p.add_argument("run"); p.add_argument("--remove", action="append"); p.add_argument("--system")
    p.add_argument("--allow-program", action="append", metavar="SPEC", help="replay the program the run names if it is this one (repeatable); without it or --system, nothing is imported"); p.set_defaults(f=cmd_replay)

    p = sp.add_parser("report", help="the viewer's page with every run under ROOT (or the run ROOT) embedded: a static "
                                     "file, no server")
    p.add_argument("root"); p.add_argument("-o", "--output", help="default: ROOT/report.html"); p.set_defaults(f=cmd_report)

    p = sp.add_parser("serve", help="the viewer on the why logs under ROOT: the page, its API and ingest")
    p.add_argument("root"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=7788)
    p.add_argument("--token", help="token for the page, the API and /v1/ingest (or TRACEKIT_WHY_TOKEN; default: random)")
    p.add_argument("--allow-program", action="append", help="System spec FIND THE CAUSE and RUN TEST may replay (repeatable)")
    p.add_argument("--ingest-token", action="append", help="a bearer token /v1/ingest takes, and nothing else "
                                                           "(repeatable; default: --token)")
    p.add_argument("--webhook", help="POST each new high alert here as JSON (Slack-compatible)")
    p.add_argument("--tls-cert", help="PEM certificate: serve HTTPS (required beyond loopback)")
    p.add_argument("--tls-key", help="PEM private key of --tls-cert")
    p.add_argument("--insecure-http", action="store_true", help="plain HTTP beyond loopback (TLS terminated in front)")
    p.set_defaults(f=cmd_serve)

    p = sp.add_parser("watch", help="follow a runs folder in the terminal and print new alerts live")
    p.add_argument("root"); p.add_argument("--webhook"); p.add_argument("--interval", type=float, default=0.5)
    p.set_defaults(f=cmd_watch)

    p = sp.add_parser("import", help="import runs from a Tracekit v1 ledger, a v2 signer store or a v2 bundle")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--v1", action="store_true", help="the source is a v1 ledger")
    g.add_argument("--store", metavar="DIR", help="a v2 signer data dir (holds store/), read-only")
    g.add_argument("--bundle", metavar="FILE", help="a v2 bundle (.tkb), verified first with --trust")
    p.add_argument("src", nargs="?", help="with --v1: Tracekit home, ledger directory or ledger.jsonl")
    p.add_argument("--trust", help="with --bundle: the v2 trust config")
    p.add_argument("--run", help="Tracekit run id (default: every run in the ledger)")
    p.add_argument("--out", default="runs"); p.add_argument("--list", action="store_true", help="list runs and exit")
    p.add_argument("--untrusted-tool", action="append", help="glob of tools whose results are untrusted (default *)")
    p.add_argument("--trusted-tool", action="append", help="glob of tools whose results are trusted")
    p.add_argument("--sensitive", action="append", help="tool to treat as sensitive (repeatable)")
    p.set_defaults(f=cmd_import)

    p = sp.add_parser("index", help="influence index across runs")
    p.add_argument("root"); p.add_argument("--target", action="append"); p.add_argument("--top", type=int, default=20)
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_index)

    a = ap.parse_args(argv)
    try:
        return a.f(a) or 0
    except (OSError, ValueError, KeyError, ImportError) as e:   # a path, spec, target or System that isn't there
        if os.environ.get("TRACEKIT_DEBUG") == "1":
            raise
        print(f"tracekit why {a.cmd}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
