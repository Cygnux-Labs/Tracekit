"""The eval numbers README.md, docs/evaluation.md and docs/limits.md quote are the ones eval/results/*.json records.

Each claim renders its text from a results file and the doc must contain it, so a result that moves fails here until
the doc says the new number. CHANGELOG.md is left out: a release's notes quote the numbers as they were then."""
import glob
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def quotes(body, text):
    """Whether `body` holds `text` with its whitespace collapsed, and a number at either end of it whole: "18 of 432"
    is not in "118 of 432" or "18 of 4,321" (#500)."""
    t = re.escape(" ".join(text.split()))
    return re.search(r"(?<![\d.,])" * text[:1].isdigit() + t + r"(?![\d]|[.,]\d)" * text[-1:].isdigit(), body) is not None


def res(name):
    with open(os.path.join(ROOT, "eval", "results", name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def pct(x, nd=0):
    return f"{x * 100:.{nd}f}%"


def covers(d):
    return " | ".join(pct(v) for v in d.values())


def claims():
    e1, e8, e9, e10 = res("e1_integrity"), res("e8_insider"), res("e9_signer_perf"), res("e10_reconcile")
    e17, e17d, e17c = res("e17_policy_corpus"), res("e17_detection"), res("e17_containment")
    e18, e20, e21, e21r, e22 = (res("e18_agent_approvers"), res("e20_alignment"), res("e21_policy_robustness"),
                                res("e21_robustness"), res("e22_verifier_agreement"))
    e28 = res("e28_influence")
    ad, dk, wt = e28["agentdojo"], e28["desk"], e28["without_task"]
    ag, ex, un = ad["grades"], ad["attack_value_attribution"], ad["untrusted"]

    def grade(name, g):
        n = g["tp"] + g["fp"]
        return (f"| {name} | {g['tp']} of {n} ({pct(g['tp'] / n, 1 if g['fp'] else 0)}) | "
                f"{g['found']} of {g['calls']} ({pct(g['found'] / g['calls'], 1)}) |")
    m = e1["mutations"]
    alone = sum(v["ledger_only"] == 1 for v in m.values())
    wit = sum(v["ledger_plus_witness"] == 1 for v in m.values())
    trials = {v["trials"] for v in m.values()}.pop()
    harm, caught, benign, fp = (sum(c[k] for c in e17["classes"].values()) for k in ("deny", "caught", "benign", "fp"))
    approvers = sum(c["caught"] for c in e18["cases"].values())
    insider = [v["caught"] for k, v in e8.items() if k.startswith("E8.")]
    dflt, strict = e21["profiles"]["default"], e21["profiles"]["strict"]
    h, se17 = dflt["heldout"]["totals"], strict["e17"]["totals"]
    lat = e21["latency"]
    rewrites = sum(v["total"] for k, v in e21r["by_form"].items() if k in e21r["transformations"])
    ho = e20["held_out"]
    f4 = ho["text"]["detection"]["F4"]   # every cover has the same number of sessions

    def blind(t, rate=None):   # the "now" columns of a blind pool's row; a count of none is not in the totals
        return (f"{t['caught']} ({pct(t['caught'] / t['harmful'], 1)}), {t['deny']} denied | {t.get('fp', 0)}"
                + (f" ({pct(rate, 1)})" if rate is not None else "") + " |")

    def row(name, p):
        t, s = p["heldout"]["totals"], p["sessions"]["totals"]
        return (f"| {name} | {t['caught']} / {t['harmful']} ({pct(p['heldout']['recall'], 1)}) | {t['deny']} "
                f"({pct(p['heldout']['deny_recall'], 1)}) | {t['unknown_only']} | {t['fp']} / {t['benign']} "
                f"({pct(p['heldout']['fp_rate'], 1)}) | {s['fp']} / {s['benign']} ({pct(p['sessions']['fp_rate'], 1)}) |")

    readme = [
        f"{caught} of {harm}</h3>harmful calls stopped",
        f"{len(e17['classes'])} classes</a>, {fp} false alarm in {benign} (E17)",
        f"{wit} of {len(m)}</h3>tamper attacks caught",
        f"{len(m) * trials} trials</a>, with a witness (E1)",
        f"{sum(insider)} of {len(insider)}</h3>insider attacks caught",
        f"{e9['ack_on_write']['p99_ms']} ms at p99</a>, signer round trip (E9)",
        f"**{sum(insider)} of {len(insider)} caught**, on every pull request",
        f"{trials} trials each",
        f"The log alone catches {alone} of {len(m)}. **With a witness, {wit} of {len(m)}.**",
        f"**{e10['seeded_flagged']} of {e10['seeded']} flagged**, {e10['false_positives']} false positives",
        f"**{round(e9['ack_on_write']['p50_ms'], 2)} ms p50, {e9['ack_on_write']['p99_ms']} ms p99** per call; "
        f"{e9['throughput']['events_per_s']:,} events/s",
        f"(E17): {harm} harmful, {benign} benign calls",
        f"{caught} stopped, {fp} false alarm",
        f"(E21): {h['harmful']} harmful, {h['benign']} benign",
        f"({h['caught']} now, with rules added after reading the pool); {h['fp']} benign held",
        f"{approvers} of {len(e18['cases'])} abuse cases against agent approvers caught (E18)",
        f"{sum(r['ok'] for r in e17c.values())} of {len(e17c)} containment and {sum(r['ok'] for r in e17d.values())} "
        f"of {len(e17d)} detection checks (E17)",
        f"(E22): {e22['bundles']} bundles, {e22['forgeries']} of them forged",
        f"**All three agree on all {e22['agree']}**",
        f"A {e22['large']['calls']:,}-call run verifies in the browser in "
        f"{round(next(b['page_s'] for b in e22['large']['bundles'] if 'open' not in b['name']))} s",
    ]
    evaluation = [
        f"All {caught} harmful calls are denied or held; one benign call is held",
        f"{fp} in {benign} ({pct(fp / benign, 2)})",
        f"{sum(r['ok'] for r in e17d.values())} of {len(e17d)} hold",
        f"{sum(r['ok'] for r in e17c.values())} of {len(e17c)} hold",
        f"{approvers} of {len(e18['cases'])} caught",
        row("default", dflt),
        row("strict", strict),
        *(blind(x["totals"]) for p in (dflt, strict) for x in p["blind"]["pools"].values()),
        *(blind(p["blind"]["totals"], p["blind"]["fp_rate"]) for p in (dflt, strict)),
        f"the blind pools (default {pct(dflt['blind']['fp_rate'], 1)}, strict {pct(strict['blind']['fp_rate'], 1)})",
        "E17's benign calls: " + "; ".join(f"{pct(g['heldout'], 1)}, {pct(g['sessions'], 1)}, "
                                            f"{pct(g['e17'], 2 if g['e17'] < 0.01 else 1)} {p}"
                                            for p, g in e21["gates"]["max_fp_rate"].items()),
        *(f"| {p}, RE2 / regex | {lat[p + '/re2']['p50_us']} / {lat[p + '/regex']['p50_us']} | "
          f"{lat[p + '/re2']['p99_us']} / {lat[p + '/regex']['p99_us']} | {lat[p + '/re2']['max_us']} / "
          f"{lat[p + '/regex']['max_us']} | {lat[p + '/re2']['p99_ref']} / {lat[p + '/regex']['p99_ref']} |"
          for p in ("default", "strict", "dev")),
        f"either: {se17['fp']} of {se17['benign']} ({pct(se17['fp'] / se17['benign'], 1)}). All {se17['fp']} are benign",
        f"each of the {e21r['rewritten_cases']} shell",
        f"all {e21r['source_cases']} originals and all {rewrites:,} rewrites are",
        f"| F1c | **pool v3 (held out)** | {covers(ho['detection']['F1c'])} |",
        f"| F2 | pool v3 (read 2026-11-14) | {covers(ho['text']['detection']['F2'])} |",
        f"| F3 | pool v3 (read 2026-11-14) | {covers(ho['text']['detection']['F3'])} |",
        f"| F5 | pool v3 (read 2026-11-14) | {covers(ho['text']['detection']['F5'])} |",
        f"on pool v3 (read 2026-11-14), {pct(sum(f4.values()) / len(f4))} (c0",
        f"exit {pct(ho['text']['F4_by_how']['exit'])}, piped {pct(ho['text']['F4_by_how']['piped'])})",
        f"finds {round(ho['text']['detection']['Fc']['TK-X101'] * 30)} of 30 pool v3 sessions",
        f"(held out, {ho['controls']['calls']:,} honest calls)",
        f"All {e22['bundles']} bundles agree in all three passes",
        f"none of the {e22['forgeries']} forgeries",
        f"Of {ad['runs']['attacked']} attacked runs, {ad['runs']['succeeded']} attacks succeeded and "
        f"{ad['runs']['scored']} were scored",
        *(grade(k, ag[k]) for k in ("exact", "seen", "hint")),
        f"{ex['to_the_injection']} of the {ex['edges']} exact edges on the attacker's own value",
        f"all {sum(v['edges'] for v in ad['exact_claims'].values())} exact claims name a record that holds the value",
        f"marks {un['attack_calls_named']} of the {un['attack_calls']} attack calls, and also {un['clean_calls_named']} "
        f"of the {un['clean_calls']} calls of clean runs, in {un['clean_runs_named']} of {ad['runs']['clean']} clean runs",
        f"the only cause of the {dk['exfil_calls']} exfiltration calls in {dk['exfil_runs']} runs",
        f"Measured: {dk['grades']['measured']['found']} of {dk['exfil_calls']} found",
        f"exact found {dk['grades']['exact']['found']} of {dk['exfil_calls']}",
        f"{dk['exfil_calls_named']} of {dk['exfil_calls']} exfiltration calls and {dk['legit_calls_named']} of "
        f"{dk['legit_calls']} others",
        f"{wt['planted_drift']} of {wt['planted_calls']} planted emails serve no step of the task, "
        f"{wt['asked_drift']} of {wt['asked_calls']} asked ones",
        f"none reads as coming from the task (no replay without the task exists for a published trace), all "
        f"{ad['attack_calls_said']['listed']} are in its list, and each of the {ad['attack_calls_said']['without_exact']} "
        "with no exact edge names",
        f"{dk['exfil_calls_serve_task']} of the {dk['exfil_calls']} read as coming from the task",
        f"In each of the {wt['tool_only_runs']} runs with both emails, a test whose target only names the tool "
        f"(`tool=send_email`, both emails) put its verdict on {wt['tool_only_attached']} calls",
        f"{e28['held']['cases']} built runs where the task gives a value in prose",
        f"named the record in all {e28['held']['exact_from_record']}",
        f"in all {e28['held']['said_task_too']} the words say the task holds the value too",
        f"only untrusted content supplied a value fires on {e28['held']['only_alerts']} of them",
    ]
    limits = [
        f"in {pct(ag['exact']['found'] / ag['exact']['calls'])} of the successful attacks scored",
        f"{pct(ag['seen']['fp'] / (ag['seen']['tp'] + ag['seen']['fp']))} of the labelled seen edges",
        f"{un['clean_runs_named']} of {ad['runs']['clean']} had such a call",
        f"in all {e28['held']['exact_from_record']} of E28's built cases",
        f"E20 `c5_line`, {round(ho['forged_flagged']['F1'] * 24)} of 24 flagged",
        f"{se17['fp']} of E17's {se17['benign']} benign calls, {pct(se17['fp'] / se17['benign'], 1)}, and "
        f"{strict['sessions']['totals']['fp']} of E21's {strict['sessions']['totals']['benign']} developer-session "
        f"calls, {pct(strict['sessions']['fp_rate'])}",
    ]
    return {"README.md": readme, "docs/evaluation.md": evaluation, "docs/limits.md": limits}


def moving_counts():
    """The E17 and E21 counts a policy rule change moves, as docs/evaluation.md quotes them."""
    e17, e21 = res("e17_policy_corpus"), res("e21_policy_robustness")
    harm, caught, benign = (sum(c[k] for c in e17["classes"].values()) for k in ("deny", "caught", "benign"))
    dflt, se17 = e21["profiles"]["default"], e21["profiles"]["strict"]["e17"]["totals"]
    h = dflt["heldout"]["totals"]
    return [f"{caught} of {harm}", f"{harm} harmful and {benign} benign", f"false alarm in {benign}",
            f"{h['caught']} ({pct(dflt['heldout']['recall'], 1)})", f"{h['fp']} of {h['benign']}",
            f"{pct(se17['fp'] / se17['benign'], 1)} of E17's benign"]


class EvalDocs(unittest.TestCase):
    def test_the_docs_quote_the_results(self):
        for doc, texts in claims().items():
            with open(os.path.join(ROOT, doc), encoding="utf-8") as f:
                body = " ".join(f.read().split())
            for t in texts:
                with self.subTest(doc=doc, claim=t):
                    self.assertTrue(quotes(body, t), "update the doc, or re-run the eval that wrote the file")

    def test_other_docs_link_to_the_evaluation_instead_of_copying_its_counts(self):
        """#500: E17's and E21's counts were copied into several pages, so every rule change edited them all. Only
        docs/evaluation.md quotes them (the README too, checked above); another page links to it."""
        counts = moving_counts()
        for path in glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True):
            if os.path.relpath(path, ROOT) == os.path.join("docs", "evaluation.md"):
                continue
            with open(path, encoding="utf-8") as f:
                body = " ".join(f.read().split())
            with self.subTest(doc=os.path.relpath(path, ROOT)):
                self.assertEqual([c for c in counts if quotes(body, c)], [], "link to docs/evaluation.md instead")

    def test_a_count_matches_only_as_a_whole_number(self):
        self.assertTrue(quotes("held 18 of 432 benign", "18 of 432"))
        self.assertTrue(quotes("(18 of 432)", "18 of 432"))
        for body in ("held 118 of 432", "held 18 of 4321", "held 18 of 432.5", "held 1,18 of 432", "held 18 of 432,1"):
            with self.subTest(body=body):
                self.assertFalse(quotes(body, "18 of 432"))


if __name__ == "__main__":
    unittest.main()
