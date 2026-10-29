"""Check the browser verifier, sdk/typescript/dist/verify.html, in a real browser against both command-line verifiers.

    python scripts/verify_page_check.py [--shots DIR] [--large N]

Run it with a Python that has Playwright (and its Chromium, or Google Chrome installed); it skips cleanly without.
TRACEKIT_PYTHON (default: this Python) runs Tracekit: it exports a fresh corpus from a real signer (clean, tampered,
wrong trust key, findings, sensor effects, an unknown ext name, a too-new bundle, a large run and a zip of tiny
lines) and runs `tracekit verify --json` on it. The page is opened over file:// and over a local HTTP server; for every bundle of that
corpus, tests/golden/ (v2, negative and parts) and docs/sample/ it must give the TypeScript CLI's report and exit
code, line for line, and the Python CLI's (except where that CLI hands a non-v2 file to the v1 verifier, and the
order of the upgrade commands: npx first in TypeScript). It also checks that a worker the page starts can't fetch
either, that the page works by keyboard, logs no error and makes no request, and (with --shots) that no state is wider
than the screen.
Not run by CI: `make test-ts` runs the page's logic under Node.
`python scripts/verify_page_check.py --corpus DIR` (with Tracekit importable) only exports the corpus;
`--samples` writes the page's two embedded samples (sdk/typescript/src/verify/sample/).
"""
import argparse
import base64
import functools
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS = os.path.join(ROOT, "sdk", "typescript")
PAGE = os.path.join(TS, "dist", "verify.html")
SAMPLES = os.path.join(TS, "src", "verify", "sample")
PY = os.environ.get("TRACEKIT_PYTHON", sys.executable)


# ---- the corpus (run with Tracekit importable) ----

def _signer(d, **kw):
    from tracekit.identity.base import CallerIdentity
    from tracekit.signer import service as svc
    from tracekit.signer.quotas import Limits
    s = svc.SignerService(os.path.join(d, "data"), grace_s=0, fsck_every_s=0, observe_grace_s=0,
                          limits=Limits(events_per_s=1e6, burst=10**6), **kw)   # the large run records at full speed
    me = CallerIdentity("uid", "1000", True)

    def call(method, who=me, **req):
        return s.call(who, method, {"request_id": uuid.uuid4().hex, **req})
    return s, me, call


def _run(call, calls=(("read_file", {"path": "README.md"}),), held=None, approver=None, close=True):
    """A run of `calls` (tool, args), each decided and completed; `held`: one more, held for approval and approved by
    `approver`."""
    from tracekit.format.canon import event_hash
    r = call("register_run", agent={"name": "support-bot"})
    ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
    n = 0
    for i, (tool, args) in enumerate([*calls, *([held] if held else [])]):
        tcid = f"call_{i + 1}"
        dec = call("decide", **ids, stream="s1", client_seq=n, tool_call_id=tcid, tool=tool, args_source="parsed",
                   args=args)
        if held and i == len(calls):
            aid = call("approval_request", **ids, tool_call_id=tcid)["approval_id"]
            call("approval_decide", who=approver, approval_id=aid, decision="approve")
            call("approval_consume", **ids, tool_call_id=tcid, tool=tool, args_source="parsed", args=args,
                 approval_id_hint=aid)
        call("complete", **ids, stream="s1", client_seq=n + 1, tool_call_id=tcid, decision_id=dec["decision_id"],
             args_digest=event_hash({"tool": tool, "args": args}), status="ok")
        n += 2
    if close:
        call("close_run", **ids)
    return ids


def _checkpointed(s, witness=None):
    from tracekit.tlog_witness import signed_by
    store = s.log.storage
    deadline = time.monotonic() + 30
    while True:
        s.sweep()
        s.checkpoint()
        size, note = store.checkpoint_latest()
        if size == store.tree.size and (witness is None or signed_by(note.split("\n\n", 1)[1], witness.vkey)):
            return note
        if time.monotonic() > deadline:
            raise TimeoutError("no checkpoint of the whole log")
        time.sleep(0.1)


def _trust(path, logs, witnesses=(), required=0, analyzers=()):
    with open(path, "w") as f:
        json.dump({"logs": logs, "witnesses": [{"vkey": k, "class": c} for k, c in witnesses], "algs": ["ed25519"],
                   "witnesses_required": required, **({"analyzers": list(analyzers)} if analyzers else {})}, f, indent=1)
    return path


PAY = {"ask": [{"id": "PAY", "tool": "pay", "pattern": "^"}]}


def samples(out=SAMPLES):
    """The page's samples: a small closed run of a dev signer (two reads and a payment held for approval, which alice
    approved), its trust config, and a copy in which the approval's person was changed after signing (the manifest
    refreshed, as someone covering their tracks would)."""
    import hashlib
    import zipfile
    from tracekit.bundle_v2 import export
    from tracekit.identity.base import CallerIdentity
    from tracekit.policy2.engine import Engine
    os.makedirs(out, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        alice = CallerIdentity("uid", "1001", True)
        s, _, call = _signer(d, policy=Engine(PAY), approvals={"self_approval": "deny", "approvers": ["uid:1001"],
                                                                "persons": {"uid:1001": "alice"}})
        try:
            run = _run(call, calls=(("read_file", {"path": "invoices/2026-10.csv"}),
                                    ("read_file", {"path": "vendors.json"})),
                       held=("pay", {"vendor": "acme-supplies", "amount_eur": 1200}), approver=alice)
            export(s.log.storage, "default", run["run_id"], _checkpointed(s), os.path.join(out, "sample.tkb"))
            _trust(os.path.join(out, "sample.trust.json"), [s.vkey])
        finally:
            s.close()
    with zipfile.ZipFile(os.path.join(out, "sample.tkb")) as z:
        files = {n: z.read(n) for n in z.namelist()}
    manifest = json.loads(files.pop("manifest.json"))
    name = next(n for n in files if n.startswith("runs/"))
    assert files[name].count(b'"person":"alice"') == 1
    files[name] = files[name].replace(b'"person":"alice"', b'"person":"mallory"')
    manifest["files"][name] = hashlib.sha256(files[name]).hexdigest()
    with zipfile.ZipFile(os.path.join(out, "sample-tampered.tkb"), "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in [("manifest.json", json.dumps(manifest).encode()), *files.items()]:
            z.writestr(zipfile.ZipInfo(n, (2026, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return out


def corpus(d, large=20000):
    """Export the fresh bundles to `d`; returns [(name, bundle, trust or None, what)]."""
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import test_bundle_v2 as b
    from factories import rewrite_bundle
    from tracekit.bundle_v2 import export
    from tracekit.demo_server import Witness
    from tracekit.identity.base import CallerIdentity
    from tracekit.policy2.engine import Engine
    from tracekit.storage.base import registry_tree
    os.makedirs(d, exist_ok=True)
    if os.listdir(d):
        sys.exit(f"{d} is not empty: the corpus is exported into a new directory")
    witness = Witness()
    analyzer, tetragon = CallerIdentity("uid", "2000", True), CallerIdentity("mtls", "spiffe://acme/tetragon", True)
    alice = CallerIdentity("uid", "1001", True)
    s, me, call = _signer(os.path.join(d, "signer"), policy=Engine(PAY), witnesses=[witness],
                          analyzers=["uid:2000"], authorize={"mtls:spiffe://acme/tetragon": ["observe_effect"]},
                          approvals={"self_approval": "deny", "approvers": ["uid:1001"]})
    cases = []
    try:
        clean = _run(call, held=("pay", {"amount": 5}), approver=alice)
        open_ = _run(call, close=False)
        target = _run(call)
        f = call("register_run", who=analyzer, agent={"name": "reviewer"}, analyzes=target["run_id"])
        cites = [{"run_seq": r["event"]["run_seq"], "hash": r["hash"]}
                 for r in s.log.storage.iter_run("default", target["run_id"])]
        call("review_finding", who=analyzer, run_id=f["run_id"], run_token=f["run_token"], review={
            "reviewer": "tracekit-analyze/1.4.0", "cites": cites, "verdict": {
                "kind": "coverage", "rule": "TK-X200", "severity": "info", "partial": False,
                "checks": {"TK-X201": {"checked": 1, "found": 0, "not_checkable": []}},
                "reasoning": {"full": 0, "summary": 0, "withheld": 0, "none": 1}}})
        call("close_run", who=analyzer, run_id=f["run_id"], run_token=f["run_token"])
        sensed = {"sensor": "tetragon", "callers": [f"uid:{me.subject}"]}   # it covers the runs of `me` alone
        call("observe_effect", who=tetragon, instance="i", effects=[], **sensed)
        sensor = call("register_run", agent={"name": "agent"})
        call("decide", run_id=sensor["run_id"], run_token=sensor["run_token"], stream="s1", client_seq=0,
             tool_call_id="call_7", tool="read_file", args_source="parsed", args={})
        proc = {"caller": f"uid:{me.subject}", "ts": "2026-10-12T10:00:00.000000Z", "pid": 7, "binary": "/usr/bin/curl",
                "exec_id": "ZXg6MTo3"}
        call("observe_effect", who=tetragon, instance="i", **sensed, effects=[
            {**proc, "kind": "exec", "args_digest": "sha256:" + "a" * 64, "tool_call_id": "call_7"},
            {**proc, "kind": "file", "path": "/home/agent/.bashrc"}])
        call("close_run", run_id=sensor["run_id"], run_token=sensor["run_token"])
        t0 = time.monotonic()
        big = _run(call, calls=[("read_file", {"path": f"f{i}.txt"}) for i in range(large)])
        print(f"large run: {2 * large} records written in {time.monotonic() - t0:.1f}s", file=sys.stderr)
        note = _checkpointed(s, witness)
        store = s.log.storage
        for name, run, more in (("clean", clean, []), ("open", open_, []), ("findings", target, [f["run_id"]]),
                                ("sensor", sensor, []), ("large", big, [])):
            export(store, "default", run["run_id"], note, os.path.join(d, f"{name}.tkb"), with_runs=more)
        reg = store.checkpoint_latest(registry_tree("default"))
        export(store, "default", None, note, os.path.join(d, "run-set.tkb"), run_set=(0, reg[0]),
               tenant_salt=s.log.tenant_salt("default"))
        log_vkey = s.vkey
    finally:
        s.close()
    trust = _trust(os.path.join(d, "trust.json"), [log_vkey], [(witness.vkey, "customer")], 1, ["uid:2000"])
    dev = _trust(os.path.join(d, "trust-dev.json"), [log_vkey])
    other, _, _ = _signer(os.path.join(d, "other"))
    other.close()
    wrong = _trust(os.path.join(d, "trust-wrong-key.json"), [other.vkey])

    def mutated(name, edit_run=None, edit=None):
        def apply(files, manifest):
            if edit_run:
                run = next(n for n in files if n.startswith("runs/"))
                lines = files[run].splitlines(keepends=True)
                edit_run(lines)
                files[run] = b"".join(lines)
            if edit:
                edit(files, manifest)
        rewrite_bundle(os.path.join(d, "clean.tkb"), os.path.join(d, f"{name}.tkb"), apply)
        return os.path.join(d, f"{name}.tkb")

    def flip(lines):
        lines[3] = lines[3].replace(b'"tool":"pay"', b'"tool":"pey"')

    def swap(lines):
        lines[2], lines[3] = lines[3], lines[2]

    with open(os.path.join(d, "clean.tkb"), "rb") as fh:
        raw = bytearray(fh.read())
    raw[len(raw) // 3] ^= 1   # one bit of the zip, manifest untouched
    with open(os.path.join(d, "bit-flipped.tkb"), "wb") as fh:
        fh.write(raw)
    cases += [("clean", "clean.tkb", trust, "a closed run, a held call a person approved, witnessed"),
              ("clean, dev trust", "clean.tkb", dev, "the same bundle, no witness pinned"),
              ("open run", "open.tkb", trust, "a run still open: verified to its head"),
              ("findings", "findings.tkb", trust, "a run with its findings run (signed review)"),
              ("sensor", "sensor.tkb", trust, "kernel sensor effects"),
              ("run-set", "run-set.tkb", trust, "every run of the tenant"),
              ("large", "large.tkb", trust, f"{2 * large + 3} records"),
              ("edited", mutated("edited", flip), trust, "a recorded argument changed, manifest refreshed"),
              ("deleted", mutated("deleted", lambda ls: ls.pop(2)), trust, "a record deleted"),
              ("reordered", mutated("reordered", swap), trust, "two records swapped"),
              ("bit flipped", "bit-flipped.tkb", trust, "one bit of the file flipped"),
              ("too new", mutated("too-new", edit=lambda fs, m: m.update(verifier_min_version="9.0")), trust,
               "needs a newer verifier"),
              ("wrong trust key", "clean.tkb", wrong, "another signer's trust config"),
              ("no trust file", "clean.tkb", None, "no trust config chosen"),
              ("tampered, no trust file", "edited.tkb", None, "a changed record, no trust config")]
    # 1.3 MB that unzips to 508 MB of 20-byte lines (no signed record is that short): refused before a line is parsed,
    # where it closed the tab without a trust file
    tiny = {"checkpoints/10.note": f"o.example/x\n10\n{base64.b64encode(bytes(32)).decode()}\n\n— o.example/x "
                                   f"{base64.b64encode(bytes([1]) * 69).decode()}\n".encode(),
            "proofs/records.json": b'{"checkpoint":"checkpoints/10.note","tree_size":10,"inclusion":{}}',
            "keys/records.jsonl": b"", "registry/run-set.json": b"{}",
            **{f"runs/r{i:03d}.jsonl": b'{"event":{"seq":1}}\n' * 262144 for i in range(97)}}
    with zipfile.ZipFile(os.path.join(d, "tiny-lines.tkb"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps({"format": "tracekit.bundle.v2", "verifier_min_version": "1.0", "files": {
            n: hashlib.sha256(data).hexdigest() for n, data in tiny.items()}}))
        for n, data in tiny.items():
            z.writestr(n, data)
    cases.append(("tiny lines, no trust file", "tiny-lines.tkb", None, "a zip of millions of lines no record could be"))
    log = b.Log(os.path.join(d, "ext-store"))
    try:
        b.ext_bundle(log, os.path.join(d, "ext.tkb"))
    finally:
        log.store.close()
    cases.append(("unknown ext name", "ext.tkb", _trust(os.path.join(d, "trust-ext.json"), **{
        "logs": b.trust_config()["logs"]}), "format 1.4's ext slot, a name no verifier interprets"))
    return [(n, os.path.join(d, bundle) if not os.path.isabs(bundle) else bundle, t, what)
            for n, bundle, t, what in cases]


# ---- the comparison (run with Playwright) ----

def cli(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
    try:
        out = json.loads(p.stdout)
    except ValueError:
        return {"exit_code": p.returncode, "stderr": p.stderr.strip()}
    assert out["exit_code"] == p.returncode, (cmd, p.returncode)
    return out


def lines(rep):
    """The report's check lines as the CLIs print them."""
    out = []
    for c in rep.get("checks", []):
        out.append(f"[{c['status'].upper()}] {c['check']}" + (f" — {c['detail']}" if c["detail"] else ""))
        out += [f"        {p}" for p in c["problems"]]
    return out


def page_report(page, bundle, trust):
    """What the page shows for `bundle` and `trust` (None: none chosen), both chosen in one file dialog: (report JSON
    as downloaded, check lines as shown, verdict word, seconds, longest main-thread task in ms)."""
    if not trust and page.is_visible("#clear-trust"):
        page.evaluate("document.body.dataset.state = ''")
        page.click("#clear-trust")
        page.wait_for_selector("body[data-state=done]", state="attached", timeout=600_000)
    page.evaluate("document.body.dataset.state = ''; window.__long = 0")
    t0 = time.monotonic()
    page.set_input_files("#bundle", [bundle, trust] if trust else bundle)
    page.wait_for_selector("body[data-state=done]", state="attached", timeout=600_000)
    secs = time.monotonic() - t0
    with page.expect_download() as dl:
        page.click("#download")
    with open(dl.value.path(), encoding="utf-8") as f:
        rep = json.load(f)
    shown = page.eval_on_selector_all("#checks summary .line", "els => els.map(e => e.textContent)")
    problems = page.eval_on_selector_all("#checks details", "els => els.map(d => [...d.querySelectorAll('.problem')]"
                                                            ".map(p => p.textContent))")
    flat = []
    for s, ps in zip(shown, problems):
        flat += [s, *(f"        {p}" for p in ps)]
    return rep, flat, page.text_content("#verdict-word"), secs, page.evaluate("window.__long || 0")


def agree(page, bundle, trust, errors):
    """`bundle` with `trust` (None: none chosen) in the page, the TypeScript CLI and the Python CLI: (each one's exit
    code and seconds, the page's integrity line and longest main-thread task, problems): where the page differs from the
    CLIs, a banner that isn't its exit code's, and the console errors and requests `errors` collected meanwhile. With
    `page` None, the TypeScript CLI's report stands for the page's."""
    cwd = os.path.dirname(bundle)
    rel_b = os.path.basename(bundle)
    rel_t = trust and os.path.relpath(trust, cwd)
    if trust and os.path.dirname(trust) != cwd:   # the page knows only file names: so do the CLIs here
        shutil.copy(bundle, os.path.join(os.path.dirname(trust), rel_b))
        cwd, rel_t = os.path.dirname(trust), os.path.basename(trust)
    if page:
        rep, shown, word, secs, longest = page_report(page, bundle, trust)
    argv = ["verify", rel_b, *(["--trust", rel_t] if trust else []), "--json"]
    t0 = time.monotonic()
    ts = cli(["node", os.path.join(TS, "bin", "tracekit.mjs"), *argv], cwd)
    t1 = time.monotonic()
    py = cli([PY, "-m", "tracekit.cli", *argv], cwd)
    t2 = time.monotonic()
    if not page:
        rep, shown, word, secs, longest = ts, lines(ts), _word(ts), None, None
    # a CLI that printed no report crashed, unless it refused the files (exit 2: no --trust, or --trust for a file that
    # is no v2 bundle)
    problems = [f"{name} CLI printed no report (exit {out['exit_code']}): {out['stderr'][-300:]}"
                for name, out in (("TypeScript", ts), ("Python", py)) if "stderr" in out and out["exit_code"] != 2]
    lacks = any(c["detail"] == "not implemented by this verifier" for c in rep.get("checks", ()))
    v1 = any(p.startswith("a format v1 bundle") for c in rep.get("checks", ()) for p in c["problems"])
    if trust:
        if rep != ts:
            problems.append(f"page JSON != TypeScript CLI: {_diff(rep, ts)}")
        if shown != lines(ts):
            problems.append(f"page lines != TypeScript CLI: {_diff(shown, lines(ts))}")
        # Python checks what TypeScript lacks (UNVERIFIABLE here, never VERIFIED), and its CLI hands a zip without a
        # v2 manifest to the v1 verifier
        if "stderr" not in py and not lacks and _py_order(rep) != py:
            problems.append(f"page JSON != Python CLI: {_diff(_py_order(rep), py)}")
    elif v1:   # the Python CLI verifies v1 bundles; the page names the command that does
        if rep["exit_code"] != 2:
            problems.append(f"v1 bundle: page exit {rep['exit_code']}")
    elif rep["exit_code"] not in (1, 2) or py["exit_code"] != 2:
        # no trust config: the CLIs refuse (exit 2); the page checks what needs no pinned key, never VERIFIED
        problems.append(f"no trust config: page {rep['exit_code']}, Python CLI {py['exit_code']}")
    want = _word(rep)
    if word != want:
        problems.append(f"banner {word!r} for exit {rep['exit_code']}")
    if errors:
        problems.append(f"console/network: {errors[:3]}")
        errors.clear()
    return {"page": rep["exit_code"], "typescript": ts.get("exit_code"), "python": py.get("exit_code"),
            "integrity": rep.get("integrity"), "page_s": secs, "typescript_s": t1 - t0, "python_s": t2 - t1,
            "longest_task_ms": longest}, problems


def compare(shots=None, large=20000):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("skipped: Playwright is not importable (pip install playwright, in a venv of its own)")
        return 0
    if not os.path.exists(PAGE):
        sys.exit(f"no {PAGE}: run `make verify-page` first")
    tmp = tempfile.mkdtemp()
    try:
        p = subprocess.run([PY, os.path.abspath(__file__), "--corpus", tmp, "--large", str(large)], capture_output=True,
                           text=True, env={**os.environ, "PYTHONPATH": ROOT})
        sys.stderr.write(p.stderr)
        if p.returncode:
            sys.exit(f"exporting the corpus failed: {p.stdout}")
        cases = [tuple(c) for c in json.loads(p.stdout)]
        for d in ("v2", "negative", "parts"):
            base = os.path.join(ROOT, "tests", "golden", d)
            cases += [(f"golden {d}/{n}", os.path.join(base, n), os.path.join(base, "trust.json"), "golden")
                      for n in sorted(os.listdir(base)) if n.endswith(".tkb")]
        cases.append(("golden v2/closed.tkb, rekor trust", os.path.join(ROOT, "tests/golden/v2/closed.tkb"),
                      os.path.join(ROOT, "tests/golden/v2/trust-rekor.json"), "a check this verifier lacks"))
        cases += [(f"page {n}", os.path.join(SAMPLES, n), os.path.join(SAMPLES, "sample.trust.json"), "embedded sample")
                  for n in ("sample.tkb", "sample-tampered.tkb")]
        for n in ("demo-run.tkb", "demo-run-tampered.tkb"):
            cases.append((f"v1 {n}", os.path.join(ROOT, "docs", "sample", n), None, "a format v1 bundle"))
        return _browse(sync_playwright, cases, tmp, shots)
    finally:
        shutil.rmtree(tmp, True)


def _browse(sync_playwright, cases, tmp, shots):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=os.path.dirname(PAGE)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    urls = {"file": "file://" + PAGE, "http": f"http://127.0.0.1:{server.server_port}/verify.html"}
    bad, rows = [], []
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(channel="chrome")
        except Exception:
            browser = pw.chromium.launch()
        for how, url in urls.items():
            ctx = browser.new_context(accept_downloads=True)
            page = ctx.new_page()
            errors = []
            page.on("console", lambda m: errors.append(m.text) if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("request", lambda r: errors.append(f"request {r.url}") if not r.url.startswith(
                (url, "blob:", "data:")) else None)
            page.add_init_script("""new PerformanceObserver((l) => { for (const e of l.getEntries())
                window.__long = Math.max(window.__long || 0, e.duration); }).observe({type: 'longtask'});""")
            page.goto(url)
            # the page verifies in a worker from a blob: URL, which inherits its policy: no fetch from there either
            blocked = page.evaluate("""(url) => new Promise((done) => {
                const w = new Worker(URL.createObjectURL(new Blob(
                    [`fetch(${JSON.stringify(url)}).then(() => postMessage('sent'), () => postMessage('blocked'))`])));
                w.onmessage = (e) => done(e.data); w.onerror = () => done('no worker'); })""",
                                    f"http://127.0.0.1:{server.server_port}/verify.html")
            if blocked != "blocked":
                bad.append((how, "a worker's fetch", [blocked]))
            errors.clear()   # the blocked fetch's own console line
            # by keyboard alone: Tab reaches the bundle picker, then the trust file's, then the samples; Enter runs one
            order = []
            for _ in range(3):
                page.keyboard.press("Tab")
                order.append(page.evaluate("document.activeElement.id"))
            page.keyboard.press("Enter")
            page.wait_for_selector("body[data-state=done]", state="attached")
            if order != ["bundle", "trust", "sample-clean"] or page.text_content("#verdict-word") != "VERIFIED":
                bad.append((how, "keyboard", [f"focus order {order}, verdict {page.text_content('#verdict-word')}"]))
            for name, bundle, trust, what in cases:
                row, problems = agree(page, bundle, trust, errors)
                rows.append((how, name, row))
                if problems:
                    bad.append((how, name, problems))
            ctx.close()
        if shots:
            bad += [("file", n, ["wider than the screen"]) for n in _screenshots(browser, urls["file"], cases, shots)]
        browser.close()
    server.shutdown()
    for how, name, r in rows:
        print(f"{how:4} {name:44} page {r['page']} python {r['python']}  {r['page_s']:6.2f}s  longest task "
              f"{r['longest_task_ms']:5.0f}ms  {r['integrity']}")
    for how, name, problems in bad:
        print(f"MISMATCH {how} {name}:", *problems, sep="\n    ")
    print(f"{len(rows)} page runs, {len(bad)} mismatched")
    return 1 if bad else 0


def _word(rep):
    """The banner a report gets: its exit code's word, or the CLIs' UNUSABLE BUNDLE."""
    return "UNUSABLE BUNDLE" if rep.get("integrity") == "UNUSABLE BUNDLE" else \
        {0: "VERIFIED", 1: "FAILED", 2: "UNVERIFIABLE"}.get(rep.get("exit_code"))


def _py_order(rep):
    """The page's report with the upgrade commands in the Python CLI's order (uvx first)."""
    rep = json.loads(json.dumps(rep))
    for c in rep["checks"]:
        if c["check"] == "bundle readable" and c["detail"].startswith("UNVERIFIABLE (needs"):
            c["problems"][:2] = c["problems"][1::-1]
    return rep


def _diff(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: (a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)}
    if isinstance(a, list) and isinstance(b, list):
        return [(x, y) for x, y in zip(a, b) if x != y][:3] or f"lengths {len(a)} and {len(b)}"
    return (a, b)


def _screenshots(browser, url, cases, shots):
    """The page's main states, at a phone's width and a desktop's, light and dark; each page no wider than its
    screen. The samples are chosen with their buttons, the trust file of the first bundle with its own picker."""
    os.makedirs(shots, exist_ok=True)
    pick = {n: (b, t) for n, b, t, _ in cases}
    states = [("start", None, None), ("sample-clean", "#sample-clean", None), ("sample-tampered", "#sample-tampered", None),
              ("verified", *pick["clean"]), ("failed", *pick["edited"]),
              ("unverifiable-no-trust", *pick["no trust file"]), ("unverifiable-newer", *pick["too new"]),
              ("v1", *pick["v1 demo-run.tkb"]), ("findings", *pick["findings"])]
    wide = []
    for scheme in ("light", "dark"):
        for w, h, label in ((390, 844, "phone"), (1280, 900, "desktop")):
            ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme=scheme, accept_downloads=True)
            page = ctx.new_page()
            page.goto(url)
            for state, bundle, trust in states:
                if bundle and bundle.startswith("#"):
                    page.evaluate("document.body.dataset.state = ''")
                    page.click(bundle)
                    page.wait_for_selector("body[data-state=done]", state="attached")
                elif bundle:
                    page_report(page, bundle, trust)
                if page.evaluate("document.documentElement.scrollWidth") > w:
                    wide.append(f"{state}-{label}-{scheme}")
                page.screenshot(path=os.path.join(shots, f"{state}-{label}-{scheme}.png"), full_page=True)
            ctx.close()
    return wide


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", help=argparse.SUPPRESS)
    ap.add_argument("--samples", action="store_true", help="write the page's embedded samples and exit")
    ap.add_argument("--shots", help="also screenshot the page's main states into this directory")
    ap.add_argument("--large", type=int, default=20000, help="tool calls in the large run (two records each; past "
                                                            "about 24,000 export writes it in parts)")
    a = ap.parse_args()
    if a.samples:
        print(samples())
        return 0
    if a.corpus:
        print(json.dumps(corpus(a.corpus, a.large)))
        return 0
    return compare(a.shots, a.large)


if __name__ == "__main__":
    sys.exit(main())
