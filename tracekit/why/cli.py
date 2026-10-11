"""`tracekit why` command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from .core import load_run, verify
from .evals import influence_index, influence_matrix, list_runs, structure
from .graph import build_graph, taint, target_hits
from .replay import attribute, counterfactual, decision_test, diff_runs, load_system, replay
from .view import render_html, render_workspace


def _p(*a):
    print(*a, flush=True)


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
            + (f" (target reproduced in {r['p_with']:.0%} of replays; try n={r['n_needed']})" if r.get("n_needed") else ""))


def cmd_demo(a):
    from .demo import EXFIL_TARGET, REFUND_TARGET, SYSTEM
    out = a.out or tempfile.mkdtemp(prefix="tracekit-why-")
    _p(f"== record: 8 runs of a 3-agent support system (seeded mock models, fake tools) -> {out}")
    exfil = []
    for s in range(8):
        r = SYSTEM.run(seed=s, out_dir=out, run_id=f"demo-seed{s}")
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
        _p(_fmt_test(counterfactual(run, spec, target, n=a.n)))
    if len(exfil) > 1:  # a second run, so the cross-run influence view has more than one data point
        for spec in ("input:vendor:portal/notes.md", "input:web:shipping_faq"):
            counterfactual(exfil[1], spec, EXFIL_TARGET, n=a.n)
    dec = run.of_type("decision")[0]
    _p("\n== decision-level test (re-call only the researcher's model call; no program re-run needed)")
    _p(_fmt_test(decision_test(run, dec["seq"], "input:vendor:*", n=a.n, contains="vendor-compliance")))

    st = structure(run)
    _p("\n== structure")
    _p("  critical path: " + " -> ".join(st["critical_path"]))
    html = os.path.join(out, "report.html")
    with open(html, "w", encoding="utf-8") as f:
        f.write(render_workspace(out))
    _p(f"\nruns:   {out}\nreport: {html}   (static; open in a browser)")
    _p(f"live:   tracekit why serve {out} --allow-program tracekit.why.demo:SYSTEM")


def cmd_verify(a):
    run = load_run(a.run)
    problems = verify(run)
    if problems:
        for p in problems:
            _p("[FAIL] " + p)
        return 1
    _p(f"[PASS] {len(run.events)} events, chain intact, {len(run.blobs)} blobs match their hashes")
    _p("       (hash-chained, not signed)")
    return 0


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
    run = load_run(a.run)
    system = load_system(a.system) if a.system else None
    if a.decision is not None:
        models = None
        if a.anthropic:  # re-send calls recorded by the Anthropic adapter
            from anthropic import Anthropic
            from .adapters.anthropic import replay_model
            fn = replay_model(Anthropic().messages)
            models = {e["model"]: fn for e in run.of_type("decision")}
        r = decision_test(run, a.decision, a.remove, n=a.n, system=system, models=models, contains=a.contains,
                          n_max=a.n_max)
    else:
        if not a.target:
            raise SystemExit("--target is required unless --decision is given")
        r = counterfactual(run, a.remove, a.target, n=a.n, system=system, live_tools=a.live_tools, n_max=a.n_max)
    _p(json.dumps(r, indent=2) if a.json else _fmt_test(r))


def cmd_attribute(a):
    run = load_run(a.run)
    r = attribute(run, a.target, a.suspect or None, n=a.n, n_max=a.n_max,
                  system=load_system(a.system) if a.system else None, workers=a.workers,
                  size_roles=not a.no_roles)
    if a.json:
        _p(json.dumps(r, indent=2, default=str))
        return
    _p(f"suspects: {', '.join(r['suspects'])}")
    for t in r["tests"]:
        _p(_fmt_test(t))
    _p(f"\n{r['summary']}")
    _p(f"({r['program_runs']} program runs, {len(r['tests'])} tests, corrected for {r['family']})")


def cmd_matrix(a):
    run = load_run(a.run)
    rows = influence_matrix(run, a.target, n=a.n, system=load_system(a.system) if a.system else None)
    for r in rows:
        _p(_fmt_test(r))


def cmd_replay(a):
    run = load_run(a.run)
    rep = replay(run, system=load_system(a.system) if a.system else None, interventions=a.remove or [])
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
    store = Store(a.root, None, webhook=a.webhook)
    store.watch(a.interval)
    _p(f"watching {a.root} (Ctrl-C to stop)")
    last = 0
    try:
        while True:
            with store.cond:
                store.cond.wait_for(lambda: store.counter > last, timeout=1)
            for i, m in store.since(last):
                last = i
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


def cmd_view(a):
    run = load_run(a.run)
    out = a.output or os.path.join(a.run, "view.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(render_html(run))
    _p(out)


def cmd_report(a):
    out = a.output or os.path.join(a.root, "report.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(render_workspace(a.root))
    _p(out)


def cmd_serve(a):
    import ssl
    from ..observe import LOOPBACK_HOSTS
    from .server import serve
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
    token = a.token or os.environ.get("TRACEKIT_WHY_TOKEN")
    httpd, store = serve(a.root, a.host, a.port, token, a.allow_program or [], webhook=a.webhook, tls=tls)
    _p(f"tracekit why on {'https' if tls else 'http'}://{a.host}:{httpd.server_address[1]}/"
       + ("" if token else f"?token={store.token}") + f"  (runs: {a.root})")
    _p("  ingest: POST /v1/ingest with the token as a Bearer token")
    _p(f"  live: the app updates as runs are recorded{'; high alerts POSTed to ' + a.webhook if a.webhook else ''}")
    _p(f"  replay from the UI: {', '.join(a.allow_program) if a.allow_program else 'disabled (--allow-program module:SYSTEM)'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def cmd_import(a):
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

    p = sp.add_parser("demo", help="record the 3-agent demo, test causes, write a view")
    p.add_argument("--out"); p.add_argument("--n", type=int, default=40); p.set_defaults(f=cmd_demo)

    p = sp.add_parser("record", help="run a System (module:ATTR) and record it")
    p.add_argument("system"); p.add_argument("--out", default="runs"); p.add_argument("--seed", type=int, default=0)
    p.add_argument("--guard", choices=("off", "alert", "block"), default="off",
                   help="check sensitive tool calls before they run")
    p.add_argument("--webhook", help="POST high alerts here (with --guard)")
    p.set_defaults(f=cmd_record)

    p = sp.add_parser("verify", help="check the hash chain and blobs"); p.add_argument("run"); p.set_defaults(f=cmd_verify)

    p = sp.add_parser("graph", help="print edges with evidence grades")
    p.add_argument("run"); p.add_argument("--json", action="store_true"); p.add_argument("--no-infer", action="store_true")
    p.set_defaults(f=cmd_graph)

    p = sp.add_parser("taint", help="blast radius of sources (default: everything untrusted)")
    p.add_argument("run"); p.add_argument("--source", action="append"); p.add_argument("--inferred", action="store_true")
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_taint)

    p = sp.add_parser("test", help="counterfactual: does removing X change whether target happens?")
    p.add_argument("run"); p.add_argument("--remove", required=True); p.add_argument("--target")
    p.add_argument("--decision", type=int, help="test one recorded model call (seq) instead of re-running the program")
    p.add_argument("--contains", help="with --decision: measure P(output contains this text)")
    p.add_argument("--anthropic", action="store_true",
                   help="with --decision: re-send a call recorded by the Anthropic adapter (needs ANTHROPIC_API_KEY)")
    p.add_argument("--n", type=int, default=30); p.add_argument("--system"); p.add_argument("--live-tools", action="store_true")
    p.add_argument("--n-max", type=int, help="sequential: keep doubling n up to this until the verdict is decisive")
    p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_test)

    p = sp.add_parser("attribute", help="which inputs caused an action: group test first, then narrow down")
    p.add_argument("run"); p.add_argument("--target", required=True)
    p.add_argument("--suspect", action="append", help="intervention spec (default: untrusted inputs upstream)")
    p.add_argument("--n", type=int, default=10); p.add_argument("--n-max", type=int, default=80)
    p.add_argument("--workers", type=int, default=1, help="parallel replays")
    p.add_argument("--no-roles", action="store_true", help="skip sizing each cause (primary vs contributing): cheaper")
    p.add_argument("--system"); p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_attribute)

    p = sp.add_parser("matrix", help="test every channel and input against targets")
    p.add_argument("run"); p.add_argument("--target", action="append", required=True); p.add_argument("--n", type=int, default=20)
    p.add_argument("--system"); p.set_defaults(f=cmd_matrix)

    p = sp.add_parser("replay", help="re-run from tape and diff against the original")
    p.add_argument("run"); p.add_argument("--remove", action="append"); p.add_argument("--system"); p.set_defaults(f=cmd_replay)

    p = sp.add_parser("view", help="write the single-file investigation view")
    p.add_argument("run"); p.add_argument("-o", "--output"); p.set_defaults(f=cmd_view)

    p = sp.add_parser("report", help="static investigation app for every run under a folder")
    p.add_argument("root"); p.add_argument("-o", "--output"); p.set_defaults(f=cmd_report)

    p = sp.add_parser("serve", help="investigation app + API + ingestion endpoint")
    p.add_argument("root"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=7788)
    p.add_argument("--token", help="token for the app, the API and /v1/ingest (or TRACEKIT_WHY_TOKEN; default: random)")
    p.add_argument("--allow-program", action="append", help="System spec the UI may replay (repeatable)")
    p.add_argument("--webhook", help="POST each new high alert here as JSON (Slack-compatible)")
    p.add_argument("--tls-cert", help="PEM certificate: serve HTTPS (required beyond loopback)")
    p.add_argument("--tls-key", help="PEM private key of --tls-cert")
    p.add_argument("--insecure-http", action="store_true", help="plain HTTP beyond loopback (TLS terminated in front)")
    p.set_defaults(f=cmd_serve)

    p = sp.add_parser("watch", help="follow a runs folder in the terminal and print new alerts live")
    p.add_argument("root"); p.add_argument("--webhook"); p.add_argument("--interval", type=float, default=0.5)
    p.set_defaults(f=cmd_watch)

    p = sp.add_parser("import", help="import runs from a Tracekit v1 ledger")
    p.add_argument("--v1", action="store_true", required=True, help="the source is a v1 ledger")
    p.add_argument("src", help="Tracekit home, ledger directory or ledger.jsonl")
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
    return a.f(a) or 0


if __name__ == "__main__":
    sys.exit(main())
