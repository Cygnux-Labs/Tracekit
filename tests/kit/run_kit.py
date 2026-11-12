"""Score a v2 verifier against the conformance kit (tests/kit/cases.json, made by make_kit.py):

    python tests/kit/run_kit.py --reference                                   # this checkout's tracekit.verify.v2
    python tests/kit/run_kit.py --cmd 'node sdk/typescript/bin/tracekit.mjs verify {bundle} --trust {trust} --json'
    python tests/kit/run_kit.py --cmd 'tkverify -bundle {bundle} -trust {trust} -json' --format-version 1.4.0

The command runs once per case with {bundle} and {trust} replaced by absolute paths. It prints its report as JSON,
{"exit_code", "integrity", "assurance", "checks": [{"check", "status"}, ...]}, and exits with that exit code. A case
passes when the verifier gives its exit code and verdict, its assurance level when the bundle verifies, and as its first
failed check one the case lists; on an `addon` case UNVERIFIABLE (exit 2) passes too, and on a case that `needs` a
format version above --format-version (the newest row of the format's version table the verifier implements) only
UNVERIFIABLE does. No report text is compared. Cases marked `proposed` hold a rule the format text doesn't state yet:
they are scored and listed, and fail the run only with --proposed. Exit 0 when every other case passes."""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys

KIT = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(KIT)

# the reference verifier as a command (the CLI reads a bundle whose manifest names another format as v1)
REFERENCE = [sys.executable, "-c", """import json, sys
from tracekit.verify import v2
rep, code = v2.verify(sys.argv[1], sys.argv[2])
print(json.dumps({"exit_code": code, "integrity": rep.integrity, "assurance": rep.assurance, "checks": rep.checks}))
sys.exit(code)""", "{bundle}", "{trust}"]


def verdict(integrity):
    """The verdict an integrity line states, without its wording (make_kit.verdict)."""
    m = re.fullmatch(r"VERIFIED TO HEAD (\d+) \(open\)|VERIFIED \((\d+) run\(s\) open\)", integrity)
    return (f"VERIFIED TO HEAD {m[1]}" if m and m[1] else f"VERIFIED, {m[2]} OPEN" if m else
            "UNVERIFIABLE" if integrity.startswith("UNVERIFIABLE") else integrity)


def version(v):
    return tuple(int(x) for x in v.split("."))


def run(cmd, bundle, trust):
    """What the verifier says: {exit, verdict, level, failed}, or {error}."""
    argv = [a.replace("{bundle}", bundle).replace("{trust}", trust) for a in cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        out = json.loads(p.stdout)
        if out["exit_code"] != p.returncode:
            return {"error": f"exit {p.returncode}, but the report says {out['exit_code']}"}
        return {"exit": p.returncode, "verdict": verdict(out["integrity"]),
                "level": out["assurance"].split(";")[0].strip() if p.returncode == 0 else None,
                "failed": [c["check"] for c in out.get("checks") or [] if c.get("status") == "fail"]}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError) as e:
        return {"error": f"{type(e).__name__}: {e}"[:300]}


def score(case, got, implements=None):
    """(passed, how): how the verifier's answer `got` meets `case`; `implements`: its format version (None: all).
    On an `addon` case, and on a case that `needs` a newer format than `implements`, any UNVERIFIABLE (exit 2) passes,
    whatever it names: report text isn't compared, so an UNVERIFIABLE for another reason passes too."""
    if "error" in got:
        return False, got["error"]
    unverifiable = got["exit"] == 2 and got["verdict"] == "UNVERIFIABLE"
    if implements and case.get("needs") and version(case["needs"]) > version(implements):
        return unverifiable, f"needs {case['needs']}: UNVERIFIABLE"
    if case.get("addon") and unverifiable:
        return True, f"UNVERIFIABLE: add-on {case['addon']}"
    want = (case["exit"], case["verdict"], case["level"] if case["exit"] == 0 else None)
    have = (got["exit"], got["verdict"], got["level"] if got["exit"] == 0 else None)
    if want != have:
        return False, f"want {want}, got {have}"
    if case["failed_check"] and (not got["failed"] or got["failed"][0] not in case["failed_check"]):
        return False, f"first failed check {got['failed'][:1]}, want one of {case['failed_check']}"
    return True, "as ruled"


def load(path=os.path.join(KIT, "cases.json")):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["cases"]


def score_all(cmd, implements=None, cases=None):
    """[(case, passed, how, what the verifier said)] of every kit case."""
    out = []
    for c in cases if cases is not None else load():
        got = run(cmd, os.path.join(TESTS, c["input"]), os.path.join(TESTS, c["trust"]))
        out.append((c, *score(c, got, implements), got))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    who = p.add_mutually_exclusive_group(required=True)
    who.add_argument("--cmd", help="the verifier command, with {bundle} and {trust}")
    who.add_argument("--reference", action="store_true", help="this checkout's Python verifier")
    p.add_argument("--format-version", help="the newest format version the verifier implements (default: all)")
    p.add_argument("--proposed", action="store_true", help="fail the run on the proposed rules' cases too")
    p.add_argument("--report", help="write every case's result here as JSON")
    a = p.parse_args(argv)
    rows = score_all(REFERENCE if a.reference else shlex.split(a.cmd), a.format_version)
    for c, ok, how, _ in rows:
        print(f"{'PASS' if ok else 'FAIL'}{' (proposed)' if c.get('proposed') else ''} {c['name']}: {how}")
    core = [r for r in rows if not r[0].get("proposed")]
    proposed = [r for r in rows if r[0].get("proposed")]
    print(f"{sum(r[1] for r in core)}/{len(core)} cases pass; proposed rules: "
          f"{sum(r[1] for r in proposed)}/{len(proposed)}")
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump([{"name": c["name"], "input": c["input"], "passed": ok, "how": how, "got": got,
                        **({"proposed": True} if c.get("proposed") else {})} for c, ok, how, got in rows], f, indent=1)
    return 0 if all(r[1] for r in (rows if a.proposed else core)) else 1


if __name__ == "__main__":
    sys.exit(main())
