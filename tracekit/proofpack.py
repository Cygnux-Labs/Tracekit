"""Proof packs: one zip an auditor can check offline, with a readable report and a verifier that needs only Python.

    tracekit proofpack --run R -o pack.zip [--key signer.pub] [--witness git:/clone]
    tracekit report run.tkb [-o report.md]          # the report alone, for any bundle

pack.zip:
    run.tkb          the signed evidence bundle (unchanged; `tracekit verify` checks it)
    REPORT.md        what the run did, every verification check, findings, coverage, and an evidence-to-control map
    verify.pyz       Tracekit's verifier as a single file: `python3 verify.pyz run.tkb [--key signer.pub]` (stdlib only)
    controls.json    the control map, machine-readable
    SHA256SUMS       hashes of the files above

The control map says which evidence in the bundle is relevant to a requirement and what it does not cover. It is
guidance for a reviewer, not a compliance determination."""
import argparse
import datetime as _dt
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile
import zipapp

CONTROLS = [
    {"framework": "EU AI Act (Regulation (EU) 2024/1689)", "control": "Art. 12 Record-keeping",
     "requirement": "High-risk AI systems shall technically allow for the automatic recording of events (logs) over their lifetime.",
     "evidence": ["automatic capture of tool calls, policy decisions, results and model exchanges", "signed, hash-chained records with timestamps",
                  "capture gaps recorded instead of silently missing"],
     "not_covered": ["whether the system is high-risk", "retention periods (e.g. Art. 19, Art. 26(6)): Tracekit does not enforce retention",
                     "activity outside the capture path (see coverage)"]},
    {"framework": "SOC 2 (AICPA Trust Services Criteria 2017)", "control": "CC7.2 System monitoring",
     "requirement": "The entity monitors system components for anomalies indicative of malicious acts, natural disasters and errors.",
     "evidence": ["policy decisions (deny, hold, flag) with stable rule ids", "signed findings from detectors", "tamper and capture-gap detection"],
     "not_covered": ["response and escalation procedures", "monitoring of systems other than the traced agents"]},
    {"framework": "ISO/IEC 42001:2023", "control": "Annex A, A.6.2.8 AI system recording of event logs",
     "requirement": "Determine at which phases of the AI system life cycle record keeping of event logs should be enabled.",
     "evidence": ["event logs for every traced run, with the policy in force bound to each decision", "offline-verifiable integrity"],
     "not_covered": ["the organisation's decision on which life-cycle phases to log", "management-system processes around the logs"]},
]


def _verify_entry():
    return ('import sys\nfrom tracekit import bundle\n'
            'def main():\n'
            '    import argparse\n'
            '    ap = argparse.ArgumentParser(prog="verify.pyz", description="Verify a Tracekit .tkb bundle offline (stdlib only).")\n'
            '    ap.add_argument("bundle")\n    ap.add_argument("--key")\n    ap.add_argument("--witness", action="append", default=[])\n'
            '    ap.add_argument("--strict", action="store_true")\n    a = ap.parse_args()\n'
            '    rep, code = bundle.verify(a.bundle, a.witness, a.strict, a.key)\n'
            '    bundle.print_report(rep, code)\n    sys.exit(code)\n'
            'main()\n')


def build_verifier(out_path):
    """A zipapp of the tracekit package. Signature checks fall back to pure-Python Ed25519 when `cryptography` is absent."""
    src = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as d:
        dst = os.path.join(d, "tracekit")
        os.makedirs(dst)
        for root, dirs, files in os.walk(src):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            rel = os.path.relpath(root, src)
            for f in files:
                if f.endswith((".py", ".json", ".yaml")):
                    os.makedirs(os.path.join(dst, rel), exist_ok=True)
                    with open(os.path.join(root, f), "rb") as i, open(os.path.join(dst, rel, f), "wb") as o:
                        o.write(i.read())
        with open(os.path.join(d, "__main__.py"), "w") as f:
            f.write(_verify_entry())
        zipapp.create_archive(d, out_path, interpreter="/usr/bin/env python3")


def _md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def report(bundle_path, key=None, witnesses=()):
    """-> (markdown, verification exit code)."""
    from . import bundle as B
    from . import coverage
    rep, code = B.verify(bundle_path, list(witnesses), False, key)
    manifest, blobs = B.load_bundle(bundle_path)
    events = []
    for line in blobs.get("records.jsonl", b"").decode("utf-8", "replace").splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and not r.get("elided"):
            events.append(r["event"])
    runs = [x for x in manifest.get("selection", {}).get("runs", []) if not x.startswith("findings:")]
    sel = [e for e in events if e["run_id"] in runs]
    fnd = [e["data"]["verdict"] for e in events if e["run_id"].startswith("findings:") and e["type"] == "review"]
    start = next((e["data"] for e in sel if e["type"] == "run.start"), {})
    cov = coverage.report(sel)
    tools = [e for e in sel if e["type"] == "tool.call"]
    dec = {e["data"]["tool_use_id"]: e["data"]["decision"] for e in sel if e["type"] == "policy.decision"}
    usage = [e["data"].get("usage") for e in sel if e["type"] == "model.exchange" and e["data"].get("usage")]
    verdict = {0: "VERIFIED", 1: "FAILED", 2: "BAD BUNDLE", 3: "VERIFIED WITH WARNINGS"}.get(code, str(code))
    anchored = any(c["check"] == "trust root" and c["status"] == "pass" for c in rep.checks)
    L = [f"# Evidence report: {', '.join(runs) or '(no run)'}", "",
         f"Generated {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from `{os.path.basename(bundle_path)}`.",
         f"Bundle sha256 `{hashlib.sha256(open(bundle_path, 'rb').read()).hexdigest()}`, signer key `{manifest.get('kid')}`.", "",
         f"**Verification: {verdict}{'' if anchored else ' (unanchored: no trusted key or witness was checked)'}.** "
         "Tracekit proves what its capture path recorded and that it has not changed since it was signed and checkpointed. "
         "It does not prove intent, complete coverage, or that reported results are real.", "",
         "## The run", "", "| | |", "|---|---|",
         f"| Agent | {_md_escape((start.get('agent') or {}).get('name', '?'))} |",
         f"| Model | {_md_escape(start.get('model') or next((e['data'].get('model') for e in sel if e['type'] == 'model.exchange' and e['data'].get('model')), '-'))} |",
         f"| Started / ended | {sel[0]['ts'] if sel else '-'} / {next((e['ts'] for e in sel if e['type'] == 'run.end'), 'not recorded')} |",
         f"| Capture sources | {', '.join(start.get('capture_sources') or []) or '-'} |",
         f"| Signer isolation / fail mode | {start.get('signer_isolation', '-')} / {start.get('fail_mode', '-')} |",
         f"| Policy | {_md_escape((start.get('policy') or {}).get('version', '-'))} (`{(start.get('policy') or {}).get('hash', '-')[:19]}`) |",
         f"| Tool calls | {len(tools)} ({sum(1 for t in tools if dec.get(t['data']['tool_use_id']) == 'deny')} denied, "
         f"{sum(1 for t in tools if dec.get(t['data']['tool_use_id']) == 'flag')} flagged) |",
         f"| Model calls | {sum(1 for e in sel if e['type'] == 'model.exchange' and e['data'].get('phase') == 'response')}"
         + (f" ({sum(u.get('input_tokens', 0) + (u.get('cache_read_tokens') or 0) for u in usage)} input / "
            f"{sum(u.get('output_tokens', 0) for u in usage)} output tokens)" if usage else "") + " |",
         f"| Content capture | {start.get('content_capture', '-')}, reasoning capture {'on' if start.get('reasoning_capture') else 'off'} |", "",
         "## Verification checks", "", "| Check | Result | Detail |", "|---|---|---|"]
    for c in rep.checks:
        L.append(f"| {_md_escape(c['check'])} | {c['status'].upper()} | {_md_escape((c.get('detail') or '') + ('; ' + '; '.join(c.get('problems') or []) if c.get('problems') else ''))[:400]} |")
    L += ["", "## Findings", ""]
    if fnd:
        L += ["| Severity | Rule | Finding | Evidence (seq) |", "|---|---|---|---|"]
        for f in fnd:
            L.append(f"| {f.get('severity')} | {f.get('rule')} | {_md_escape(f.get('title'))}: {_md_escape(f.get('detail', ''))[:300]} | "
                     f"{', '.join(str(x.get('seq')) for x in f.get('evidence') or [])} |")
    else:
        L.append("No signed findings in this bundle (run `tracekit analyze` before exporting to include them).")
    L += ["", "## Coverage", "", "Observed:", ""] + [f"- {x}" for x in cov["observed"]] + ["", "Not observed by design:", ""] + \
         [f"- {x}" for x in cov["unsupported"]] + ([""] + ["Warnings:", ""] + [f"- {x}" for x in cov["warnings"]] if cov["warnings"] else [])
    L += ["", "## Evidence and controls", "",
          "Which evidence in this bundle is relevant to each requirement, and what it does not cover. Guidance for a reviewer, "
          "not a compliance determination.", ""]
    for c in CONTROLS:
        L += [f"### {c['framework']}: {c['control']}", "", f"> {c['requirement']}", "", "Evidence here:", ""] + \
             [f"- {x}" for x in c["evidence"]] + ["", "Not covered:", ""] + [f"- {x}" for x in c["not_covered"]] + [""]
    L += ["## How to check this yourself", "", "```", "python3 verify.pyz run.tkb --key signer.pub      # in a proof pack; stdlib only",
          "tracekit verify run.tkb --key signer.pub --witness git:/path/to/witness-clone", "```", "",
          "Pin the signer's public key you obtained independently (not the one inside the bundle), or check against an external "
          "witness, to turn an unanchored result into an anchored one."]
    return "\n".join(L) + "\n", code


def build(out_path, bundle_path, key=None, witnesses=()):
    md, code = report(bundle_path, key, witnesses)
    with tempfile.TemporaryDirectory() as d:
        pyz = os.path.join(d, "verify.pyz")
        build_verifier(pyz)
        files = {"run.tkb": open(bundle_path, "rb").read(), "REPORT.md": md.encode("utf-8"),
                 "verify.pyz": open(pyz, "rb").read(), "controls.json": json.dumps(CONTROLS, indent=2).encode()}
    files["SHA256SUMS"] = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in files.items()).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files.items():
            z.writestr(n, b)
    with open(out_path, "wb") as f:
        f.write(buf.getvalue())
    return code


def main(argv=None, prog="tracekit proofpack"):
    ap = argparse.ArgumentParser(prog=prog)
    ap.add_argument("bundle", nargs="?", help="an existing .tkb (otherwise one is exported from the ledger)")
    ap.add_argument("--run")
    ap.add_argument("--home")
    ap.add_argument("-o", "--out", default="proofpack.zip")
    ap.add_argument("--key", help="trusted signer public key file (anchors the verification)")
    ap.add_argument("--witness", action="append", default=[])
    ap.add_argument("--report-only", action="store_true", help="write only the markdown report")
    a = ap.parse_args(argv)
    path = a.bundle
    tmp = None
    if not path:
        from . import bundle as B
        from . import client
        home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "run.tkb")
        B.export(home, path, run=a.run, last=not a.run)
    try:
        if a.report_only:
            md, code = report(path, a.key, a.witness)
            if a.out == "proofpack.zip":
                sys.stdout.write(md)
            else:
                with open(a.out, "w", encoding="utf-8") as f:
                    f.write(md)
            return 0 if code in (0, 3) else code
        code = build(a.out, path, a.key, a.witness)
        print(f"wrote {a.out} (verification exit {code}); check it with: unzip {a.out} && python3 verify.pyz run.tkb")
        return 0 if code in (0, 3) else code
    finally:
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def report_main(argv=None):
    argv = list(argv or [])
    return main(argv + ["--report-only"], prog="tracekit report")


if __name__ == "__main__":
    sys.exit(main())
