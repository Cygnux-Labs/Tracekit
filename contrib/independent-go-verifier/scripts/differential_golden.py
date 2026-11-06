#!/usr/bin/env python3
"""Strict, reproducible golden corpus differential gate for Tracekit issue #260.

Run in a FULL Tracekit checkout (with its Python dependencies installed):
  python contrib/independent-go-verifier/scripts/differential_golden.py \
    --report golden-parity.json

A mismatching or unreadable corpus is a test failure, not an implicit skip.
The Go CLI is independent of Python: this script runs both as black boxes.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def cases(golden):
    # The case manifests include trust variants (for example, pinned Rekor)
    # which must be tested separately even when they reuse the same .tkb.
    seen = set()
    for section in ("", "v2"):
        for item in load(golden / section / "expected.json").get("cases", []):
            if item.get("command") != "verify":
                continue  # v0.1 ledger migration is not a .tkb verification
            args = item["args"]
            bundle = next((x for x in args if x.endswith(".tkb")), None)
            if bundle is None:
                raise ValueError(f"verify case without .tkb: {item['name']}")
            directory = golden / item["dir"]
            path = directory / bundle
            seen.add(path.resolve())
            resolved_args = []
            for i, token in enumerate(args):
                previous = args[i - 1] if i else ""
                if token == bundle or previous in ("--trust", "--key", "--v1-key", "--v1-ledger"):
                    token = str((directory / token).resolve())
                elif previous == "--witness" and token.startswith("file:"):
                    token = "file:" + str((directory / token[5:]).resolve())
                resolved_args.append(token)
            yield item["name"], path, resolved_args, item["dir"]
    for section in ("negative", "parts"):
        manifest = load(golden / section / "expected.json")
        for item in manifest["cases"]:
            path = golden / section / item["bundle"]
            seen.add(path.resolve())
            yield item["name"], path, [str(path), "--trust", str(golden / section / "trust.json")], section
    # No .tkb file may be dropped just because a case manifest was incomplete.
    remaining = sorted(p for p in golden.rglob("*.tkb") if p.resolve() not in seen)
    if remaining:
        raise ValueError("golden .tkb files missing from test cases: " + ", ".join(str(p.relative_to(golden)) for p in remaining))


def go_args(args):
    flag_names = {
        "--trust": "-trust",
        "--key": "-key",
        "--witness": "-witness",
        "--v1-key": "-v1-key",
        "--v1-ledger": "-v1-ledger",
    }
    result = ["-bundle", args[0]]
    i = 1
    while i < len(args):
        flag = args[i]
        if flag not in flag_names:
            raise ValueError(f"unsupported verification flag for Go CLI: {flag}")
        if i + 1 >= len(args):
            raise ValueError(f"missing value for verification flag: {flag}")
        result.extend((flag_names[flag], args[i + 1]))
        i += 2
    result.append("-json")
    return result


# The CLI hands a bundle whose manifest names another format to v1, and
# refuses --trust for it without JSON. The repository's test_golden.py deliberately
# invokes v2.verify() directly for the negative and multipart corpus. Invoke
# the same reference entrypoint, in a separate process, for all v2 cases.
PYTHON_V2 = """import json
import sys
from tracekit.verify import v2
report, code = v2.verify(sys.argv[1], sys.argv[2])
print(json.dumps({"exit_code": code, "integrity": report.integrity,
                  "assurance": report.assurance,
                  "checks": [{"check": c["check"], "status": c["status"]}
                             for c in getattr(report, "checks", [])]}))
sys.exit(code)
"""


def python_command(section, python_args):
    if section in ("v2", "negative", "parts"):
        if "--trust" not in python_args:
            raise ValueError(f"v2 case has no --trust: {python_args}")
        trust = python_args[python_args.index("--trust") + 1]
        return [sys.executable, "-c", PYTHON_V2, python_args[0], trust]
    return [sys.executable, "-m", "tracekit", "verify", *python_args, "--json"]


def invoke(command, cwd, env):
    proc = subprocess.run(command, cwd=cwd, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=180)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON from {command[0]} (exit {proc.returncode}): "
                           f"{exc}: stdout={proc.stdout[:400]!r}, stderr={proc.stderr[:400]!r}") from exc
    if not isinstance(result, dict) or not all(k in result for k in ("integrity", "assurance", "exit_code")):
        raise ValueError(f"missing verdict fields from {command[0]}: {result}")
    if proc.returncode != result["exit_code"]:
        raise ValueError(f"exit mismatch between process and JSON from {command[0]}")
    checks = result.get("checks", [])
    names = {status: sorted({c["check"] for c in checks if c.get("status") == status})
             for status in ("warn", "fail")}
    return {key: result[key] for key in ("exit_code", "integrity", "assurance")} | {
        "warning_checks": names["warn"], "failed_checks": names["fail"]}


# The checks the Python verifier reports that the Go verifier doesn't, by format and by the status Python gives them:
# on these the gate compares verdicts only. Verdicts are never exempted. Each is a check Go doesn't perform on evidence
# it accepts, so it can't name it:
KNOWN_GAPS = {
    "v1": {
        "warning_checks": {
            "head matches a witness checkpoint",   # when the selected records run past the last checkpoint; Go names
                                                   # this check's failures, which are compared
            "signing key",   # where the signing key lives, as the checkpoints state it
            "policy unchanged during run", "capture sources", "harness attribution", "approvals", "coverage",
            "opt-in content capture",   # what the run recorded about itself
        },
        "failed_checks": {
            "counter has no gaps",   # Go's chain check reports a missing record under `chain intact`, not on its own
        },
    },
    "v2": {
        "warning_checks": {
            "coverage", "tiers", "fail-open classes", "break-glass approvals",   # what the run recorded
            "log tail",   # whether a run-set's registry range ends in log.closed
        },
        "failed_checks": set(),
    },
}
# Evidence Go doesn't support fails closed, so its verdict differs whatever the names (README.md, "Known differences"):
# the checks of v1 signed findings, record-key issuers and revocations, monitors, the v1-to-v2 format bridge, agent
# approvals, incidents, signed findings, reviews and replays, and ext fields are not compared here.


def compare(python, go, section):
    """(match, known gaps, unexpected names): the same verdict, and the same warning and failed check names outside the
    known gaps. Go's v2 verifier stops at its first failure, so on a v2 bundle that fails it names that one failed
    check, which must be one Python names, and no check Python doesn't."""
    known = KNOWN_GAPS["v1" if section == "v1" else "v2"]
    stops = section != "v1" and python["exit_code"] != 0
    gaps, unexpected = {}, {}
    for field in ("warning_checks", "failed_checks"):
        differences = set(go[field]) - set(python[field]) if stops else set(python[field]) ^ set(go[field])
        gaps[field] = sorted(differences & known[field])
        unexpected[field] = sorted(differences - known[field])
    if stops and not go["failed_checks"]:   # a failure Go gives no name
        unexpected["failed_checks"] = sorted(set(python["failed_checks"]) - known["failed_checks"])
    verdict = all(python[k] == go[k] for k in ("exit_code", "integrity", "assurance"))
    return verdict and not any(unexpected.values()), gaps, unexpected


ADD_ON = "UNVERIFIABLE (not checked by this verifier: "


def compare_ts(python, ts):
    """(match, add-on): the TypeScript verifier runs every check the reference does, so the same verdict and the same
    warning and failed check names; or, on evidence it doesn't implement (format-v2.md §13: SLH-DSA, Rekor anchors,
    record-key certificates, tracekit why findings), UNVERIFIABLE naming it, exit 2, whatever the reference says."""
    if ts["exit_code"] == 2 and ts["integrity"].startswith(ADD_ON):
        return True, True
    return all(python[k] == ts[k] for k in ("exit_code", "integrity", "assurance", "warning_checks",
                                            "failed_checks")), False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3],
                        help="upstream Tracekit checkout root")
    parser.add_argument("--report", type=Path, help="JSON report destination")
    parser.add_argument("--ts", type=Path, help="the built TypeScript CLI (sdk/typescript/bin/tracekit.mjs): a third "
                                                "verifier on the v2 cases, held to the reference's verdict and checks")
    args = parser.parse_args()
    root = args.root.resolve()
    golden = root / "tests" / "golden"
    go_module = root / "contrib" / "independent-go-verifier"
    if not (golden / "v2" / "closed.tkb").is_file():
        parser.error(f"full upstream golden corpus missing under {golden}; cannot claim parity")
    env = {**os.environ, "PYTHONPATH": str(root) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / ("tkverify.exe" if os.name == "nt" else "tkverify")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/tkverify"],
                       cwd=go_module, env=env, check=True)
        for name, path, python_args, section in cases(golden):
            row = {"name": name, "bundle": str(path.relative_to(golden)), "section": section}
            try:
                # A v1 verifier needs its own flags, supplied by expected.json.
                row["python"] = invoke(python_command(section, python_args), golden / section, env)
                row["go"] = invoke([str(binary), *go_args(python_args)], root, env)
                row["match"], row["known_gaps"], row["unexpected_checks"] = compare(
                    row["python"], row["go"], section)
                if args.ts and section != "v1":   # the TypeScript verifier reads v2 bundles only
                    trust = python_args[python_args.index("--trust") + 1]
                    row["ts"] = invoke(["node", str(args.ts), "verify", python_args[0], "--trust", trust, "--json"],
                                       root, env)
                    ts_match, row["ts_add_on"] = compare_ts(row["python"], row["ts"])
                    row["match"] = row["match"] and ts_match
            except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
                row["error"] = str(exc)
                row["match"] = False
            rows.append(row)
            print(("PASS" if row["match"] else "FAIL") + " " + row["bundle"] + " — " + name
                  + (" (TypeScript: UNVERIFIABLE, an add-on)" if row.get("ts_add_on") else ""))
    failures = [r for r in rows if not r["match"]]
    report = {"definition": "exact verdict tuple, and warning/fail check names outside the version-scoped verdict-only "
                            "checks; on a v2 bundle that fails, Go's one failed check is one of Python's (no fixtures "
                            "excluded)" + ("; TypeScript (v2 cases): the same verdict and check names, or UNVERIFIABLE "
                                           "naming an add-on it doesn't implement" if args.ts else ""),
              "cases": len(rows), "matches": len(rows) - len(failures), "mismatches": len(failures),
              "results": rows}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{len(rows)-len(failures)}/{len(rows)} golden cases matched: verdicts, and check names outside the "
          "verdict-only checks" + (" (Python, Go and TypeScript)" if args.ts else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
