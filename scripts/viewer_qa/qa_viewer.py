"""Browser checks of `tracekit view`: each bug of the viewer QA pass (B01..B39) as a named check that FAILs while the bug
is there, plus a screenshot of each main state with --shots. Run it through run.py, which builds the scratch runs and
starts the viewers it reads (ports below); B40 (a viewer restart under an open page) is in run.py.

    python scripts/viewer_qa/qa_viewer.py [--only B07,B12] [--shots DIR]     # with the viewers of run.py running

Needs Playwright (and its Chromium, or CHROME=<a Chrome binary>); without it, it says so and exits 0. Not part of
`make test` or CI.
"""
import json
import os
import sys
import time
import urllib.request

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("skipped: the viewer's browser checks need Playwright (pip install playwright; playwright install chromium)")
    sys.exit(0)

DEV, WHY, TAMPER, BUNDLE, HARNESS = 7781, 7782, 7786, 7785, 7788
CHROME = os.environ.get("CHROME") or None   # None: Playwright's own Chromium
ONLY = set(sys.argv[sys.argv.index("--only") + 1].split(",")) if "--only" in sys.argv else None
SHOTS = sys.argv[sys.argv.index("--shots") + 1] if "--shots" in sys.argv else None
results = []


def check(cid, title):
    def deco(fn):
        if ONLY and cid not in ONLY:
            return fn
        try:
            ok, detail = fn()
        except Exception as e:   # a check that cannot run is a failure, with why
            ok, detail = False, f"error: {type(e).__name__}: {str(e)[:200]}"
        results.append((cid, ok, title, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {cid}  {title}  {'' if ok else '-- ' + str(detail)[:300]}", flush=True)
        return fn
    return deco


def api(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Authorization": "Bearer qa-token"})
    return urllib.request.urlopen(req, timeout=600).read()


p = sync_playwright().start()
browser = p.chromium.launch(executable_path=CHROME)
console = []


def page(port, w=1920, h=1080, path="/?token=qa-token", tz=None, cookie=None):
    ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme="dark",
                              **({"timezone_id": tz} if tz else {}))
    if cookie:
        ctx.add_cookies([{"name": cookie[0], "value": cookie[1], "url": f"http://127.0.0.1:{port}/"}])
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: console.append(f"{port} pageerror {e}"))
    pg.on("console", lambda m: console.append(f"{port} console.{m.type} {m.text}") if m.type == "error" else None)
    pg.goto(f"http://127.0.0.1:{port}{path}")
    pg.wait_for_timeout(3500)
    return pg


def shot(pg, name, full=False):
    if SHOTS:
        pg.screenshot(path=os.path.join(SHOTS, f"{name}.png"), full_page=full)


def run_sel(agent, calls=None):
    return f".run[data-run]:has(.nm:text-is('{agent}'))" + (f":has-text('{calls} calls')" if calls else "")


def tape_rows(pg):
    return pg.evaluate("[...document.querySelectorAll('#tape tr')].map(r => r.innerText.replace(/\\s+/g, ' ').trim())")


dev = page(DEV)
shot(dev, "01-all-runs")
dev.locator(run_sel("claude-code")).first.click()
dev.wait_for_timeout(800)
shot(dev, "02-claude-review")


@check("B01", "no raw JSON on the tape (input.observed, content.accessed, a findings run's review records)")
def _():
    dev.locator("[data-run='']").first.click(); dev.wait_for_timeout(600)
    bad = [r for r in tape_rows(dev) if " · {\"" in r]
    dev.locator(run_sel("claude-code")).first.click(); dev.wait_for_timeout(600)
    return not bad, bad[:3]


@check("B02", "the viewer's own findings are not labelled SIGNED in ALERTS")
def _():
    bad = dev.evaluate("[...document.querySelectorAll('#alerts .al')].map(a => a.innerText.replace(/\\s+/g,' ')).filter(t => /^\\w+ SIGNED ?FINDING/.test(t))")
    return not bad, bad[:2]


@check("B03", "a FINDING or VERIFY row's detail shows no LEDGER EVIDENCE hash of another record")
def _():
    dev.locator("#alerts .al:has-text('TK-X208')").first.click(); dev.wait_for_timeout(600)
    txt = dev.locator("#detail").inner_text()
    return "LEDGER EVIDENCE" not in txt, txt[txt.find("LEDGER"):][:120]


@check("B04", "a signed findings run (tracekit-analyze) is not analysed again ('0 of 0 actions')")
def _():
    dev.locator(run_sel("tracekit-analyze")).first.click(); dev.wait_for_timeout(800)
    txt = dev.locator("#detail").inner_text()
    dev.locator(run_sel("claude-code")).first.click(); dev.wait_for_timeout(600)
    return "0 of 0 actions" not in txt, txt[txt.find("FINDINGS"):][:120]


@check("B05", "MODEL rows carry no Python None")
def _():
    bad = [r for r in tape_rows(dev) if "None" in r]
    return not bad, bad[:2]


@check("B06", "a held call that was rejected or expired says so (not HELD / REJECT)")
def _():
    rows = [r for r in tape_rows(dev) if r.startswith(tuple("0123456789")) and (" HOLD Edit " in r or "git push origin main" in r)]
    bad = [r for r in rows if r.endswith(" HELD") or r.endswith(" REJECT")]
    return not bad, bad


@check("B07", "the timeline does not draw a rejected / never-run call as running to the right edge")
def _():
    hits = dev.evaluate("laneHits.map(h => ({w: h.x1 - h.x0, end: h.act.end, t: h.act.target.slice(0, 30)}))")
    W = dev.evaluate("document.getElementById('lanewrap').clientWidth")
    bad = [h["t"] for h in hits if h["end"] is None and h["w"] > W / 4]
    return not bad, bad


@check("B08", "a rejection is not marked SELF-APPROVED")
def _():
    bad = [r for r in tape_rows(dev) if "REJECTED" in r and "SELF-APPROVED" in r]
    return not bad, bad[:1]


@check("B09", "TK-CONSTRAINT has a reason (not 'not in a policy this viewer has')")
def _():
    dev.locator("#tape tr:has(td.c-tool:text-is('Edit')):has-text('billing.py')").first.click(); dev.wait_for_timeout(600)
    txt = dev.locator("#detail").inner_text()
    return "TK-CONSTRAINT (not in a policy" not in txt, txt[txt.find("RULES"):][:80]


@check("B10", "a call's detail shows its retained arguments (the dev signer keeps them)")
def _():
    txt = dev.locator("#detail").inner_text()
    return "rate = 2" in txt, "old_string/new_string of the Edit are not in DETAIL"


@check("B11", "text selected in DETAIL survives the live re-render (copy a hash)")
def _():
    dev.evaluate("(() => { const dd = document.querySelector('#detail dd.hash'); const r = document.createRange(); r.selectNodeContents(dd); getSelection().removeAllRanges(); getSelection().addRange(r); })()")
    dev.wait_for_timeout(2200)
    sel = dev.evaluate("getSelection().toString()")
    return bool(sel), "selection cleared"


@check("B12", "a hash in DETAIL can be copied in full (shown truncated with no full value to select)")
def _():
    txt = dev.evaluate("document.querySelector('#detail dd.hash').textContent")
    return not txt.endswith("…"), txt


@check("B13", "'Gaps & alerts' keeps FINDING rows")
def _():
    dev.locator("#fchips [data-kind='gap']").click(); dev.wait_for_timeout(500)
    rows = tape_rows(dev)
    dev.locator("#fchips [data-kind='']").click(); dev.wait_for_timeout(300)
    return any(" FINDING " in r for r in rows), f"{len(rows)} rows, none FINDING"


@check("B17", "NEXT DENY with no deny in the run does not blank the page into replay 0/N")
def _():
    dev.locator(run_sel("bulk-agent", 2700)).first.click(); dev.wait_for_timeout(800)
    dev.keyboard.press("d"); dev.wait_for_timeout(500)
    pos = dev.evaluate("document.getElementById('pos').textContent")
    dev.keyboard.press("l"); dev.wait_for_timeout(300)
    return not pos.startswith("0/"), pos


@check("B18", "replay steps are the run's records, not the viewer's own rows (tk_run, VERIFY, FINDING)")
def _():
    dev.keyboard.press("ArrowRight"); dev.wait_for_timeout(400)
    s = dev.evaluate("document.getElementById('detsum').textContent")
    dev.keyboard.press("l"); dev.wait_for_timeout(300)
    return not s.startswith(("tk_run", "tk_alert")), s


@check("B19", "SEQ n past the ledger does not open a viewer-made row as 'seq N'")
def _():
    dev.locator("#cmd").fill("SEQ 99999"); dev.locator("#cmd").press("Enter"); dev.wait_for_timeout(400)
    s = dev.evaluate("document.getElementById('detsum').textContent")
    dev.keyboard.press("Escape")
    return not s.startswith("tk_"), s


@check("B20", "tape rows older than the newest 600 can be reached")
def _():
    n = dev.evaluate("[document.querySelectorAll('#tape tr').length, S.tape.length]")
    return n[0] >= n[1] or dev.locator("text=/older|load more|show more/i").count() > 0, f"{n[0]} of {n[1]} rows rendered"


@check("B21", "the 2,700-call run's why detail is not quadratic (under 20 MB)")
def _():
    ws = json.loads(api(DEV, "/api/why/workspace"))
    big = max(ws["runs"], key=lambda r: r.get("actions") or 0)
    t = time.time()
    size = len(api(DEV, "/api/why/runs/" + big["run_id"]))
    return size < 20e6, f"{size / 1e6:.0f} MB in {time.time() - t:.1f}s for {big.get('actions')} tool calls"


@check("B22", "the large run's GRAPH draws something visible or says it is too large")
def _():
    dev.locator("#views [data-view='graph']").click(); dev.wait_for_timeout(8000)
    shot(dev, "03-large-graph")
    w = dev.evaluate("(() => { const g = document.querySelector('#whyv g[data-wnode] rect'); return g ? g.getBoundingClientRect().width : -1; })()")
    msg = dev.locator("#whyv").inner_text()
    dev.locator("#views [data-view='desk']").click(); dev.wait_for_timeout(300)
    return w > 20 or "too large" in msg.lower(), f"node width on screen {w:.1f}px"


RUNIDS = json.load(open("runs.json"))


def pick_why_run(pg, run_id):   # the why views' run picker, set to the mirror of signed run `run_id`
    pg.evaluate("""id => { const s = document.getElementById('wrun'); const o = [...s.options].find(o => o.value.startsWith('tk-' + id));
      s.value = o.value; s.dispatchEvent(new Event('change', {bubbles: true})); }""", run_id)
    pg.wait_for_timeout(1200)


@check("B39", "the why views follow the run selected in panel 1")
def _():
    dev.locator(f"[data-run='{RUNIDS['claude']}']").click(); dev.wait_for_timeout(500)
    dev.locator("#views [data-view='graph']").click(); dev.wait_for_timeout(1200)
    dev.locator("#views [data-view='desk']").click(); dev.wait_for_timeout(300)
    dev.locator(f"[data-run='{RUNIDS['support']}']").click(); dev.wait_for_timeout(500)
    dev.locator("#views [data-view='graph']").click(); dev.wait_for_timeout(1200)
    v = dev.evaluate("document.getElementById('wrun').value")
    dev.locator("#views [data-view='desk']").click(); dev.wait_for_timeout(300)
    return v.startswith("tk-" + RUNIDS["support"]), f"support-agent selected, GRAPH shows {v[:40]}"


@check("B23", "a mirrored signed run's why view: no 'unknown' model calls for prompt lines, no commitment 'values'")
def _():
    dev.locator(f"[data-run='{RUNIDS['claude']}']").click(); dev.wait_for_timeout(500)
    dev.locator("#views [data-view='why']").click(); dev.wait_for_timeout(800)
    pick_why_run(dev, RUNIDS["claude"])
    txt = dev.locator("#whyv").inner_text()
    dev.locator("#views [data-view='graph']").click(); dev.wait_for_timeout(1200)
    shot(dev, "04-signed-graph")
    labels = dev.evaluate("[...document.querySelectorAll('#whyv g[data-wnode] text')].map(t => t.textContent)")
    dev.locator("#views [data-view='desk']").click(); dev.wait_for_timeout(300)
    bad = (["hmac-sha256 value traced"] if "hmac-sha256:" in txt.split("VERDICT")[0] else []) + (["unknown model call"] if "unknown" in labels else [])
    return not bad, bad


@check("B24", "graph node sub-labels stay inside their box")
def _():
    dev.locator("#views [data-view='graph']").click(); dev.wait_for_timeout(800)
    pick_why_run(dev, RUNIDS["claude"])
    over = dev.evaluate("[...document.querySelectorAll('#whyv g[data-wnode]')].filter(g => { const r = g.querySelector('rect').getBBox(); return [...g.querySelectorAll('text')].some(t => t.getBBox().x + t.getBBox().width > r.width - 4); }).length")
    dev.locator("#views [data-view='desk']").click(); dev.wait_for_timeout(300)
    return over == 0, f"{over} nodes overflow"


@check("B25", "FIND matches what the TARGET column shows (a rule id)")
def _():
    dev.locator(run_sel("support-agent")).first.click(); dev.wait_for_timeout(500)
    dev.locator("#cmd").fill("FIND TK-F001"); dev.locator("#cmd").press("Enter"); dev.wait_for_timeout(500)
    s = dev.evaluate("document.getElementById('tapesum').textContent")
    dev.locator("#cmd").fill("CLR"); dev.locator("#cmd").press("Enter")
    return not s.startswith("0 of"), s


@check("B26", "PLAY / PAUSE commands drive a selected run's replay")
def _():
    dev.locator("#cmd").fill("PLAY"); dev.locator("#cmd").press("Enter"); dev.wait_for_timeout(1500)
    pos = dev.evaluate("document.getElementById('pos').textContent")
    dev.keyboard.press("l")
    return pos != "live", pos


@check("B27", "FINDINGS does not say 'no problems found' when nothing could be checked")
def _():
    dev.locator(run_sel("bulk-agent", 2700)).first.click(); dev.wait_for_timeout(800)
    txt = dev.locator("#detail").inner_text()
    return not ("no problems found" in txt and "0 of 2700" in txt), txt[txt.find("FINDINGS"):][:90]


@check("B28", "why alerts do not call a held / rejected call 'blocked'")
def _():
    dev.locator(run_sel("claude-code")).first.click(); dev.wait_for_timeout(600)
    bad = dev.evaluate("[...document.querySelectorAll('#alerts .al')].map(a => a.innerText).filter(t => /Edit was blocked/.test(t))")
    return not bad, bad[:1]


@check("B29", "the run list's date is the local date of the local time it shows")
def _():
    pg = page(DEV, tz="Pacific/Pago_Pago")
    shown = pg.evaluate("[...document.querySelectorAll('.run[data-run] .meta')].map(m => m.innerText).find(t => /\\d{4}-\\d\\d-\\d\\d/.test(t))")
    want = pg.evaluate("(() => { const r = [...RUNS.values()][0]; const d = new Date(Date.parse(r.first_ts)); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); })()")
    dates = [x for x in shown.split() if len(x) == 10 and x[4] == "-"]
    pg.context.close()
    return want in dates, f"shown {dates}, local date {want}"


@check("B30", "no horizontal page scroll at 390 px")
def _():
    pg = page(DEV, 390, 844)
    shot(pg, "05-phone", True)
    w = pg.evaluate("document.documentElement.scrollWidth")
    pg.context.close()
    return w <= 390, f"page is {w}px wide"


@check("B31", "a ticker's HIGH ALERTS matches the ALERTS panel's high count")
def _():
    dev.locator("[data-run='']").first.click(); dev.wait_for_timeout(600)
    t = dev.evaluate("document.querySelector('#ticker').innerText.match(/HIGH ALERTS\\n(\\d+)/)[1]")
    a = dev.evaluate("document.getElementById('alsum').textContent.match(/(\\d+) high/)[1]")
    return t == a, f"ticker {t}, panel {a}"


why = page(WHY)
shot(why, "06-why-desk")


@check("B14", "why logs alone: the chain badge does not say ✓ 0 SIGNED RECORDS")
def _():
    c = why.evaluate("document.getElementById('chain').textContent")
    return "0 SIGNED" not in c, c


@check("B15", "ELAPSED of a finished recording does not grow with the wall clock")
def _():
    a = why.evaluate("document.querySelector('#ticker').innerText.match(/ELAPSED\\n(\\S+)/)[1]")
    why.wait_for_timeout(2500)
    b = why.evaluate("document.querySelector('#ticker').innerText.match(/ELAPSED\\n(\\S+)/)[1]")
    return a == b, f"{a} -> {b}"


for view in ("runs", "overview", "timeline", "why", "graph", "agents", "influence"):
    why.locator(f"#views [data-view='{view}']").click(); why.wait_for_timeout(1200)
    if view == "graph":
        why.evaluate("(() => { const s = document.getElementById('wrun'); s.value = 'demo-seed0'; s.dispatchEvent(new Event('change', {bubbles: true})); })()")
        why.wait_for_timeout(1200)
    shot(why, f"07-why-{view}")


@check("B32", "graph effect labels do not run under their node")
def _():
    over = why.evaluate("""(() => { const rects = [...document.querySelectorAll('#whyv g[data-wnode]')].map(g => g.getBoundingClientRect());
      return [...document.querySelectorAll('#whyv svg > text')].filter(t => { const b = t.getBoundingClientRect();
        return rects.some(r => b.right > r.left + 1 && b.left < r.right && b.bottom > r.top && b.top < r.bottom); }).length; })()""")
    return over == 0, f"{over} effect labels overlap a node"


tam = page(TAMPER)
tam.locator(".run[data-run]:not([data-run=''])").first.click(); tam.wait_for_timeout(800)
shot(tam, "08-failed-run")


@check("B33", "a FAILED run's review leads with the failing check, not a 16-line report")
def _():
    txt = tam.locator("#detail").inner_text()
    i, j = txt.find("[FAIL]"), txt.find("[PASS]")
    return 0 <= i < j, "the [FAIL] line is after the [PASS] lines"


@check("B34", "a FAILED run's GRAPH says why there is none (not 'No why logs yet.')")
def _():
    tam.locator("#views [data-view='graph']").click(); tam.wait_for_timeout(1200)
    t = tam.locator("#whyv").inner_text()
    return "No why logs yet" not in t, t[:60]


bun = page(BUNDLE)
shot(bun, "09-v1-bundle")


@check("B35", "a v1 bundle: ELAPSED does not grow with the wall clock")
def _():
    a = bun.evaluate("document.querySelector('#ticker').innerText.match(/ELAPSED\\n(\\S+)/)[1]")
    bun.wait_for_timeout(2500)
    b = bun.evaluate("document.querySelector('#ticker').innerText.match(/ELAPSED\\n(\\S+)/)[1]")
    return a == b, f"{a} -> {b}"


apr = page(HARNESS, 1280, 900, "/approvals", cookie=("tracekit_observe", "qa-approver"))
shot(apr, "10-approvals")


@check("B36", "approvals: the reason typed for one approval is not sent with the next")
def _():
    apr.locator("#list button").nth(0).click(); apr.wait_for_timeout(500)
    apr.locator("#reason").fill("reason for the first one")
    apr.locator("#list button").nth(1).click(); apr.wait_for_timeout(500)
    v = apr.evaluate("document.getElementById('reason').value")
    return v == "", f"reason box still holds {v!r}"


@check("B37", "approvals: an answered approval offers no Approve / Reject")
def _():
    apr.locator("#reason").fill("")
    apr.locator("#approve").click(); apr.wait_for_timeout(600)
    vis = apr.evaluate("!document.getElementById('approve').hidden && !document.getElementById('approve').disabled")
    return not vis, "Approve still offered on an approved approval (a click is a 409)"


runs = page(HARNESS, 1280, 900)
shot(runs, "11-runs")


@check("B38", "runs page: Enter in a search field searches")
def _():
    n0 = runs.evaluate("document.querySelectorAll('#list tr').length")
    runs.locator("#agent").fill("claude"); runs.locator("#agent").press("Enter"); runs.wait_for_timeout(600)
    n1 = runs.evaluate("document.querySelectorAll('#list tr').length")
    return n1 != n0, f"{n0} rows before and after Enter"


print("\nconsole errors:", console[:10])
fails = [r for r in results if not r[1]]
print(f"\n{len(results) - len(fails)} PASS, {len(fails)} FAIL")
browser.close()
p.stop()
sys.exit(1 if fails else 0)
