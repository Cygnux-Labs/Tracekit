#!/usr/bin/env python3
"""Run the viewer's browser checks against scratch viewers, in a temp dir of their own (its own HOME and runtime dir,
so never your dev signer or its runs):

    python scripts/viewer_qa/run.py [--shots DIR] [--only B07,B12] [--large N] [--keep]

It records the runs (gen.py base, `tracekit analyze --v2` of the Claude Code-style run, gen.py large N with N 2700),
the why demo's runs and a `demo --server` store with one record edited, starts five viewers on ports 7781-7788 (the
dev signer's runs, why logs alone, the edited store, the sample v1 bundle, and harness.py's stub /runs and /approvals
pages), runs qa_viewer.py, then B40: a viewer restarted under an open page while records arrive, after which the page
holds the server's records, none missing and none twice. Exit 0 when every check passes, 1 otherwise. Needs
Playwright; without it, it says so and exits 0. PYTHON names an interpreter with Tracekit's dependencies for the
signer, the viewers and the generator when the one running this has only Playwright. Not part of `make test` or CI.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("skipped: the viewer's browser checks need Playwright (pip install playwright; playwright install chromium)")
    sys.exit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOKEN = "qa-token"
PY = os.environ.get("PYTHON") or sys.executable   # Tracekit's interpreter: the signer, the viewers, gen.py


def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def main():
    # a short path: macOS caps a Unix socket's path at 104 bytes, and the dev signer's socket is in the runtime dir
    d = tempfile.mkdtemp(prefix="tkqa-", dir="/tmp" if os.path.isdir("/tmp") else None)
    env = {"HOME": os.path.join(d, "home"), "TMPDIR": os.path.join(d, "t") + "/", "TRACEKIT_RUNTIME_DIR": os.path.join(d, "rt"),
           "TRACEKIT_VIEW_TOKEN": TOKEN, "PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}
    for k in ("HOME", "TMPDIR"):
        os.makedirs(env[k], exist_ok=True)
    procs, kept = {}, None

    def run(*a, check=True):
        return subprocess.run([PY, *a], cwd=d, env=env, capture_output=True, text=True, check=check)

    def start(name, *a):
        procs[name] = subprocess.Popen([PY, *a], cwd=d, env=env, stdout=open(os.path.join(d, name + ".log"), "w"),
                                       stderr=subprocess.STDOUT)

    def up(port, path="/api/verify"):
        for _ in range(120):
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                                              headers={"Authorization": f"Bearer {TOKEN}"}), timeout=5)
                return
            except OSError:
                time.sleep(0.5)
        raise SystemExit(f"the viewer on port {port} did not start: see {d}")

    try:
        run(os.path.join(HERE, "gen.py"), "base")
        claude = json.load(open(os.path.join(d, "runs.json")))["claude"]
        for _ in range(60):   # the run is final once the signer's grace after its close has passed
            if run("-m", "tracekit", "analyze", "--v2", "--run", claude, check=False).returncode in (0, 4):
                break
            time.sleep(1)
        run(os.path.join(HERE, "gen.py"), "large", arg("--large", "2700"))
        run("-m", "tracekit", "why", "demo", "--out", os.path.join(d, "whyruns"))
        kept = re.search(r"kept (\S+)", run("-m", "tracekit", "demo", "--server", "--keep").stdout).group(1)
        records = os.path.join(kept, "data", "store", "records.jsonl")
        with open(records, encoding="utf-8") as f:
            data = f.read()
        with open(records, "w", encoding="utf-8") as f:   # its denied call rewritten as allowed: the run fails
            f.write(data.replace('"decision":"deny"', '"decision":"allow"', 1))
        start("view-dev", "-m", "tracekit", "view", "--dev", "--port", "7781")
        start("view-why", "-m", "tracekit", "view", "--why", "whyruns", "--allow-program", "tracekit.why.demo:SYSTEM",
              "--port", "7782")
        start("view-tamper", "-m", "tracekit", "view", "--data-dir", os.path.join(kept, "data"), "--port", "7786")
        start("view-bundle", "-m", "tracekit", "view", "--bundle", os.path.join(ROOT, "docs", "sample", "demo-run.tkb"),
              "--port", "7785")
        start("harness", os.path.join(HERE, "harness.py"), "7788")
        for port in (7781, 7782, 7786, 7785):
            up(port)
        time.sleep(15)   # every run verified and analysed, its graph imported
        shots = arg("--shots")
        code = subprocess.run([sys.executable, os.path.join(HERE, "qa_viewer.py"),
                               *(["--only", arg("--only")] if "--only" in sys.argv else []),
                               *(["--shots", os.path.abspath(shots)] if shots else [])], cwd=d).returncode
        if not ("--only" in sys.argv and "B40" not in arg("--only").split(",")):
            code |= restart(start, procs, up)
        return code
    finally:
        for p in procs.values():
            p.terminate()
        try:   # the scratch dev signer
            with open(os.path.join(env["TRACEKIT_RUNTIME_DIR"], "endpoint.json")) as f:
                os.kill(json.load(f)["pid"], signal.SIGTERM)
        except (OSError, ValueError, KeyError):
            pass
        if "--keep" in sys.argv:
            print(f"kept {d} and {kept}")
        else:
            shutil.rmtree(d, ignore_errors=True)
            if kept:
                shutil.rmtree(kept, ignore_errors=True)


def restart(start, procs, up):
    """B40: the page open, records arriving, the viewer stopped and started again: the page ends with the server's
    records, none missing and none twice (it used to resume by the old server's positions)."""
    diff = """(async () => { const s = await (await fetch('api/snapshot')).json();
      const key = r => [r.session_id, r.tk_seq, r.event, r.title || '', r.v2 && r.v2.run_seq].join('|');
      const count = l => l.reduce((m, r) => m.set(key(r), (m.get(key(r)) || 0) + 1), new Map());
      const a = count(ALL), b = count(s.records.filter(r => r.event !== 'why'));
      return [[...a].filter(([k, n]) => n > (b.get(k) || 0)).map(([k]) => k), [...b].filter(([k, n]) => n > (a.get(k) || 0)).map(([k]) => k)]; })()"""
    start("drip", os.path.join(HERE, "gen.py"), "live", "20", "1")
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROME") or None)
        pg = b.new_page()
        pg.goto(f"http://127.0.0.1:7781/?token={TOKEN}")
        pg.wait_for_timeout(5000)
        procs.pop("view-dev").terminate()
        pg.wait_for_timeout(4000)
        start("view-dev", "-m", "tracekit", "view", "--dev", "--port", "7781")
        up(7781)
        pg.wait_for_timeout(25000)
        only_page, only_server = pg.evaluate(diff)
        b.close()
    ok = not only_page and not only_server
    print(f"{'PASS' if ok else 'FAIL'}  B40  after a viewer restart the page holds the server's records, none missing "
          f"or twice  {'' if ok else f'-- only on the page {only_page[:5]}, only on the server {only_server[:5]}'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
