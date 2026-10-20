"""The eval numbers README.md, docs/evaluation.md and docs/limits.md quote are the ones eval/results/*.json records.

Each claim renders its text from a results file and the doc must contain it, so a result that moves fails here until
the doc says the new number. CHANGELOG.md is left out: a release's notes quote the numbers as they were then."""
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def res(name):
    with open(os.path.join(ROOT, "eval", "results", name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def pct(x, nd=0):
    return f"{x * 100:.{nd}f}%"


def covers(d):
    return " | ".join(pct(v) for v in d.values())


def claims():
    e1, e3, e9, e10 = res("e1_integrity"), res("e3_policy"), res("e9_signer_perf"), res("e10_reconcile")
    e17, e17d, e17c = res("e17_policy_corpus"), res("e17_detection"), res("e17_containment")
    e18, e20, e21, e21r, e22 = (res("e18_agent_approvers"), res("e20_alignment"), res("e21_policy_robustness"),
                                res("e21_robustness"), res("e22_verifier_agreement"))
    m = e1["mutations"]
    alone = sum(v["ledger_only"] == 1 for v in m.values())
    wit = sum(v["ledger_plus_witness"] == 1 for v in m.values())
    trials = {v["trials"] for v in m.values()}.pop()
    harm, caught, benign, fp = (sum(c[k] for c in e17["classes"].values()) for k in ("deny", "caught", "benign", "fp"))
    approvers = sum(c["caught"] for c in e18["cases"].values())
    dflt, strict = e21["profiles"]["default"], e21["profiles"]["strict"]
    h, sess, se17 = dflt["heldout"]["totals"], dflt["sessions"]["totals"], strict["e17"]["totals"]
    lat = e21["latency"]
    rewrites = sum(v["total"] for k, v in e21r["by_form"].items() if k in e21r["transformations"])
    ho = e20["held_out"]
    f4 = ho["text"]["detection"]["F4"]   # every cover has the same number of sessions
    stress = e3["stress"]

    def row(name, p):
        t, s = p["heldout"]["totals"], p["sessions"]["totals"]
        return (f"| {name} | {t['caught']} / {t['harmful']} ({pct(p['heldout']['recall'], 1)}) | {t['deny']} "
                f"({pct(p['heldout']['deny_recall'], 1)}) | {t['unknown_only']} | {t['fp']} / {t['benign']} "
                f"({pct(p['heldout']['fp_rate'], 1)}) | {s['fp']} / {s['benign']} ({pct(p['sessions']['fp_rate'], 1)}) |")

    readme = [
        f"{wit} of {len(m)}</h3>tamper attacks caught",
        f"{len(m) * trials} trials</a>, with a witness (E1)",
        f"{alone} of {len(m)} caught by the log alone, **{wit} of {len(m)} with a witness**",
        f"{caught} of {harm}</h3>harmful calls stopped",
        f"{len(e17['classes'])} classes</a>, {fp} false alarm in {benign} (E17)",
        f"{harm} harmful and {benign} benign tool calls in {len(e17['classes'])} classes",
        f"{e9['ack_on_write']['p99_ms']} ms at p99</a>, signer round trip (E9)",
        f"**{round(e9['ack_on_write']['p50_ms'], 2)} ms p50, {e9['ack_on_write']['p99_ms']} ms p99** per call; "
        f"{e9['throughput']['events_per_s']:,} events/s",
        f"{len(e10['rows'])} runs, {e10['seeded']} with a seeded discrepancy",
        f"**{e10['seeded_flagged']} of {e10['seeded']} flagged**, {e10['false_positives']} false positives",
        f"**{stress['harmful_total'] - len(stress['harmful_missed'])} of {stress['harmful_total']} caught**, "
        f"{len(stress['benign_blocked'])} false alarm",
        f"{approvers} of {len(e18['cases'])} abuse cases against agent approvers caught (E18)",
        f"{h['caught']} after rules were added that target the pool",
        f"{h['fp']} of {h['benign']} false alarms, {sess['fp']} of {sess['benign']} in sessions; "
        f"p99 {lat['default/re2']['p99_us']} µs",
    ]
    evaluation = [
        f"All {caught} harmful calls are denied or held; one benign call is held",
        f"{fp} in {benign} ({pct(fp / benign, 2)})",
        f"{sum(r['ok'] for r in e17d.values())} of {len(e17d)} hold",
        f"{sum(r['ok'] for r in e17c.values())} of {len(e17c)} hold",
        f"{approvers} of {len(e18['cases'])} caught",
        row("default", dflt),
        row("strict", strict),
        *(f"| {p}, RE2 / regex | {lat[p + '/re2']['p50_us']} / {lat[p + '/regex']['p50_us']} | "
          f"{lat[p + '/re2']['p99_us']} / {lat[p + '/regex']['p99_us']} | {lat[p + '/re2']['max_us']} / "
          f"{lat[p + '/regex']['max_us']} |" for p in ("default", "strict", "dev")),
        f"each of the {e21r['rewritten_cases']} shell",
        f"all {e21r['source_cases']} originals and all {rewrites:,} rewrites are",
        f"| F1c | **pool v3 (held out)** | {covers(ho['detection']['F1c'])} |",
        f"| F2 | **pool v3 (held out)** | {covers(ho['text']['detection']['F2'])} |",
        f"| F3 | **pool v3 (held out)** | {covers(ho['text']['detection']['F3'])} |",
        f"| F5 | **pool v3 (held out)** | {covers(ho['text']['detection']['F5'])} |",
        f"on pool v3 (held out), {pct(sum(f4.values()) / len(f4))} (c0",
        f"exit {pct(ho['text']['F4_by_how']['exit'])}, piped {pct(ho['text']['F4_by_how']['piped'])})",
        f"finds {round(ho['text']['detection']['Fc']['TK-X101'] * 30)} of 30 pool v3 sessions",
        f"(held out, {ho['controls']['calls']:,} honest calls)",
        f"All {e22['bundles']} bundles agree in all three passes",
        f"none of the {e22['forgeries']} forgeries",
    ]
    limits = [
        f"({pct(se17['fp'] / se17['benign'], 1)} of E17's benign calls, {pct(strict['sessions']['fp_rate'], 1)} of "
        f"E21's developer-session calls)",
        f"and {h['caught']} ({h['deny']} denied) after rules were added",
        f"it holds {h['fp']} of {h['benign']} benign ones",
        f"E20 `c5_line`, {round(ho['forged_flagged']['F1'] * 24)} of 24 flagged",
    ]
    return {"README.md": readme, "docs/evaluation.md": evaluation, "docs/limits.md": limits}


class EvalDocs(unittest.TestCase):
    def test_the_docs_quote_the_results(self):
        for doc, texts in claims().items():
            with open(os.path.join(ROOT, doc), encoding="utf-8") as f:
                body = " ".join(f.read().split())
            for t in texts:
                with self.subTest(doc=doc, claim=t):
                    self.assertIn(" ".join(t.split()), body, "update the doc, or re-run the eval that wrote the file")


if __name__ == "__main__":
    unittest.main()
