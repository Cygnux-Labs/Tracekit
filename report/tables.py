#!/usr/bin/env python3
"""Generates every results table in report/tracekit-v2.md from eval/results/*.json.

Each table sits between `<!-- table NAME -->` and `<!-- /table -->` in the report.

    python3 report/tables.py           # rewrite the tables in the report
    python3 report/tables.py --check   # exit 1 when a table in the report differs from the results
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(ROOT, "report", "tracekit-v2.md")
BLOCK = re.compile(r"(<!-- table (\S+) -->\n).*?(<!-- /table -->)", re.S)


def table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                     + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def yes(b):
    return "yes" if b else "**no**"


def counts(d):
    return ", ".join(f"{k} {v}" for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0])))


def e1(d):
    n = d["records_per_ledger"]
    rows = [(k.replace("_", " "), f"{round(v['ledger_only'] * v['trials'])}/{v['trials']}",
             f"{round(v['ledger_plus_witness'] * v['trials'])}/{v['trials']}") for k, v in d["mutations"].items()]
    return f"Ledgers of {n} records.\n\n" + table(("Mutation", "Ledger only", "Plus witness"), rows)


def e1_interval(d):
    rows = [(k, f"{v:.2f}") for k, v in d["witness_interval_vs_detection"].items()]
    return table(("Checkpoint every n records", "Detection rate"), rows)


def e4(d):
    rows = [(r["fault"], f"{r['detected_bundle_alone']}/{r['trials']}", f"{r['detected_with_witness']}/{r['trials']}",
             f"{r['detected_with_witness_strict']}/{r['trials']}" if "detected_with_witness_strict" in r else "-")
            for r in d["results"]]
    return (table(("Fault (v1 bundle)", "Bundle alone", "Witness", "Witness + strict"), rows)
            + f"\n\nUntampered control exit codes: {d['control_exit_bundle_alone']} alone, "
              f"{d['control_exit_with_witness']} with witness. Verifier crashes: {d['verifier_crashes']}.")


def e4_v2(d):
    rows = [(r["fault"], f"{r['detected']}/{r['trials']}", counts(r.get("first_failing_check", {})) or "-")
            for r in d["results"]]
    return (table(("Fault (v2 bundle)", "Detected", "First failing check"), rows)
            + f"\n\nUntampered control: exit {d['control_exit']}, {d['control_integrity']}. "
              f"Verifier crashes: {d['verifier_crashes']}. Platform: {d['platform']}, Python {d['python']}.")


def e8(d):
    cases = {k: v for k, v in d.items() if not k.startswith("_")}
    rows = [(k, yes(v["caught"]), v.get("verdict") or f"hook exit {v.get('hook_exit_code')} ({v.get('meaning', '')})")
            for k, v in sorted(cases.items())]
    gates = ", ".join(f"{k[1:]} {'passed' if v['passed'] else 'FAILED'}" for k, v in sorted(d.items())
                      if k.startswith("_"))
    return table(("Case", "Caught", "Verdict or outcome"), rows) + f"\n\nGates: {gates}."


def e9(file, pg):
    rows = []
    for d in filter(None, (file, pg)):
        w, t, f = d["ack_on_write"], d["throughput"], d["ack_on_fsync"]
        rows.append((d["storage"], f"{d['platform']}, {d['cpus']} CPUs, Python {d['python']}",
                     "quick" if d["quick"] else "full", f"{w['p50_ms']} / {w['p99_ms']} ({w['calls']} calls)",
                     f"{t['events_per_s']} ({t['workers']} workers, {t['seconds']} s)",
                     f"{f['p50_ms']} / {f['p99_ms']} ({f['calls']} calls)",
                     ", ".join(f"{k} {yes(v)}" for k, v in sorted(d["gates"].items()))
                     + ("" if d["gated"] else " (informational)")))
    return table(("Storage", "Machine", "Run", "ack-on-write p50 / p99 ms", "events/s", "ack-on-fsync p50 / p99 ms",
                  "Gates"), rows)


def e10(d):
    combos, scenarios = [], {}
    for r in d["rows"]:
        if r["layers"] not in combos:
            combos.append(r["layers"])
        scenarios.setdefault(r["scenario"], {})[r["layers"]] = r
    rows = [(s, *(", ".join(by[c]["flagged"]) or "none" for c in combos), yes(all(r["ok"] for r in by.values())))
            for s, by in scenarios.items()]
    return (table(("Scenario", *(f"Flagged ({c})" for c in combos), "As expected"), rows)
            + f"\n\n{d['runs']} runs; seeded discrepancies flagged: {d['seeded_flagged']}/{d['seeded']}; "
              f"false positives: {d['false_positives']}.")


def e11(d):
    srcs = list(d["sources"])
    cases = list(d["sources"][srcs[0]]["cases"])
    rows = [(c.replace("_", " "), *(yes(d["sources"][s]["cases"][c]["detected"]) for s in srcs)) for c in cases]
    rows.append(("untampered control: gaps", *(len(d["sources"][s]["control_gaps"]) for s in srcs)))
    rows.append(("gap expected", *(f"`{d['sources'][s]['expected']}`" for s in srcs)))
    skipped = ", ".join(sorted(d["skipped"])) or "none"
    return (table(("Tampering", *(s.replace("_", " ") for s in srcs)), rows)
            + f"\n\nSkipped sources: {skipped}. Platform: {d['platform']}, Python {d['python']}.")


def e12(d):
    rows = [(k.replace("_", " "), len(v["attempts"]), yes(v["refused"])) for k, v in d["cross_tenant"].items()
            if k != "control"]
    rows.append(("control: own identity, own run", len(d["cross_tenant"]["control"]["attempts"]),
                 "went through" if d["cross_tenant"]["control"]["refused"] else "**refused**"))
    for k, v in d["in_process"].items():
        rows.append((f"{k.replace('_', ' ')}: {d['workers']} x {d['calls_per_worker']} calls, calls in another run "
                     f"/ runs missing calls", f"{len(v['in_another_run'])} / {len(v['runs_missing_calls'])}", "-"))
    skipped = ", ".join(k.replace("_", " ") for k in sorted(d["skipped"])) or "none"
    return (table(("Attack", "Attempts", "All refused"), rows)
            + f"\n\nSkipped: {skipped}. Platform: {d['platform']}, Python {d['python']}.")


def e14(d):
    rows = []
    for k, v in d["scenarios"].items():
        facts = [f"{x.replace('_', ' ')} {y}" for x, y in v.items()
                 if x != "ok" and isinstance(y, (int, float, str)) and not isinstance(y, bool)]
        facts += [x.replace("_", " ") for x, y in v.items() if x != "ok" and y is True]
        facts.append(f"fsck problems {len(v['fsck_problems'])}" if "fsck_problems" in v else "")
        rows.append((k.replace("_", " "), yes(v["ok"]), "; ".join(f for f in facts if f)))
    return (table(("Scenario", "Passed", "Measured"), rows)
            + f"\n\nRun: {'quick' if d['quick'] else 'full'}. Platform: {d['platform']}, Python {d['python']}.")


def e14_partition(d):
    p = d["scenarios"]["d_partition"]
    rows = [(ph, p[ph]["n"], p[ph]["p50"], p[ph]["p95"], p[ph].get("added_p50", "-"), p[ph].get("added_p99", "-"))
            for ph in ("baseline", "during", "after")]
    return (table(("Phase", "Calls", "p50 ms", "p95 ms", "added p50 ms", "added p99 ms"), rows)
            + f"\n\nClient timeout: {p['client_timeout_ms']} ms.")


def e15(d):
    rows = [(m.replace("_", "-"), f"{v['rounds']} x {v['clients']}", v["acknowledged"], v["acknowledged_lost"],
             v["not_acknowledged"], v["not_acknowledged_but_in_store"], v["not_acknowledged_in_a_signed_gap"],
             v["silent_drops"], len(v["fsck_problems"])) for m, v in d.items() if m.startswith("ack_on_")]
    return (table(("Durability", "kill -9 rounds x clients", "Acknowledged", "Acknowledged lost", "Not acknowledged",
                   "of which in the store", "of which in a signed gap", "Silent drops", "fsck problems"), rows)
            + f"\n\nGates: {', '.join(f'{k} {yes(v)}' for k, v in sorted(d['gates'].items()))}. "
              f"Platform: {d['platform']}, Python {d['python']}.")


def e16(d):
    rows = []
    for name, s in (("system mode layout", d), ("Kubernetes manifests", d["k8s"]), ("Postgres roles", d["postgres"])):
        if "cases" not in s:
            rows.append((name, "-", "-", "-", "-", f"skipped: {s.get('skipped', '')}"))
            continue
        cs = s["cases"].values()
        rows.append((name, len(cs), sum(1 for c in cs if c.get("flagged")), sum(1 for c in cs if "skipped" in c),
                     yes(s["clean"]["passed"]), ", ".join(sorted({c["expect"] for c in cs}))))
    return table(("Suite", "Broken layouts", "Flagged", "Skipped", "Clean layout passes", "Checks exercised"), rows)


def missing(name):
    return f"_No `eval/results/{name}.json` committed: run `eval/{name}.py` (see its docstring)._"


TABLES = {
    "e1": ("e1_integrity", e1),
    "e1-interval": ("e1_integrity", e1_interval),
    "e4": ("e4_seeded_faults", e4),
    "e4-v2": ("e4_seeded_faults_v2", e4_v2),
    "e8": ("e8_insider", e8),
    "e8-v2": ("e8_insider_v2", e8),
    "e9": ("e9_signer_perf", lambda d: e9(d, load("e9_signer_perf_postgres"))),
    "e10": ("e10_reconcile", e10),
    "e11": ("e11_l1_tampering", e11),
    "e12": ("e12_cross_tenant", e12),
    "e14": ("e14_outage", e14),
    "e14-partition": ("e14_outage", e14_partition),
    "e15": ("e15_durability", e15),
    "e16": ("e16_doctor", e16),
}


def load(name):
    path = os.path.join(ROOT, "eval", "results", name + ".json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def generate(name):
    results, fn = TABLES[name]
    d = load(results)
    return missing(results) if d is None else fn(d)


def render(text):
    return BLOCK.sub(lambda m: m.group(1) + generate(m.group(2)) + "\n" + m.group(3), text)


def main(argv):
    with open(REPORT) as f:
        text = f.read()
    new = render(text)
    if "--check" in argv:
        if new != text:
            print("report/tracekit-v2.md: tables differ from eval/results; run python3 report/tables.py")
            return 1
        return 0
    with open(REPORT, "w") as f:
        f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
