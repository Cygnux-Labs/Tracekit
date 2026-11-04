"""Offline verifiers: `v1` for tracekit.bundle.v1 (frozen), `v2` for tracekit.bundle.v2."""
import json
import re
import sys
import zipfile

from tracekit.bundle_v2 import FORMAT
from tracekit.wiki import wiki_url

ISOLATED = ("separate-user", "remote")   # the signer_isolation values of a signer the agent can't reach
_AT = re.compile(r"(?:record )?seq (\d{1,20}): (.+)")   # a failed check's line about one record, in either verifier


def is_v2(path):
    """True when `path` is a zip whose manifest names format v2, False when it names another, None when the file can't
    be read as a zip or has no readable manifest. Standard library only, so checking a v1 bundle needs nothing else
    installed. Never raises."""
    try:
        with zipfile.ZipFile(path) as z, z.open("manifest.json") as f:
            manifest = json.loads(f.read(1 << 20))
    except Exception:
        return None
    return isinstance(manifest, dict) and manifest.get("format") == FORMAT


def summary(rep, code, integrity, assurance, stream=None):
    """The short result `tracekit verify` and `tracekit demo` print by default, for a bundle that verified (exit 0, or 3
    under --strict) or failed (exit 1): the verdict and what it rests on, or the first record it breaks at; the warnings
    by name; and how far the setup protects the record from the agent. It reads the report only: `--detail` prints all
    of it (print_report). Bundle-derived text is printed without control characters, as print_report prints it."""
    from tracekit.verify.v2 import _CONTROL
    s, clean = stream or sys.stdout, lambda x: _CONTROL.sub("", str(x))
    if code == 1:
        failed = [c for c in rep.checks if c["status"] == "fail"]
        at = sorted((int(m[1]), m[2]) for m in (_AT.fullmatch(p) for c in failed for p in c["problems"]) if m)
        first = failed[0] if failed else {"check": "verification", "detail": "", "problems": []}
        s.write(clean(f"TAMPERED at event {at[0][0]}: {at[0][1]}" if at else
                      f"FAILED: {first['check']}: {first['detail'] or (first['problems'] or ['see the checks'])[0]}")
                .rstrip(".") + ".\nAdd --detail to see each check.\n")
        return
    warned = list(dict.fromkeys(c["check"] for c in rep.checks if c["status"] == "warn"))
    said = [f"{rep.events} event{'' if rep.events == 1 else 's'}"] if rep.events is not None else []
    if rep.kids:
        said.append(f"signed by {rep.kids[0]}" if len(rep.kids) == 1 else
                    f"signed by {len(rep.kids)} keys ({', '.join(rep.kids[:3])}{', ...' if len(rep.kids) > 3 else ''})")
    if integrity == "VERIFIED":   # a warning may be about what went unrecorded: then only the records are vouched for
        said.append("nothing edited" if warned else "nothing edited or missing")
    s.write(clean(integrity + (f": {', '.join(said)}" if said else "")) + ".\n")
    if getattr(rep, "findings", None):   # v2's signed findings: an opinion of the run, worth a line of their own
        s.write(clean(f"Findings: {rep.findings}") + ".\n")
    if warned:
        s.write(clean(f"Warnings: {', '.join(warned)}. Add --detail to see why.") + "\n")
    for n in rep.notes:   # as v1's print_report words them: about what the verdict did not use
        s.write(clean(f"warning: {n}") + "\n")
    s.write("".join(clean(line) + "\n" for line in protection(rep, assurance).split("\n")))


def protection(rep, assurance):
    """What the setup protects the record against, from the isolation the signer recorded for each run (v2) or the v1
    assurance, which names it; the level the assurance starts with says whether an independent witness cosigned."""
    iso = set(rep.isolation) or {"same-user" if assurance.startswith("dev") else
                                 assurance.split(" ")[0].split("=", 1)[1] if assurance.startswith("signer_isolation=")
                                 else "unknown"}
    further = f"\nFor real protection, run the signer where the agent can't reach it: {wiki_url('docs/deploy.md')}"
    if "same-user" in iso:
        return ("Protection: none against the agent. Dev mode: the signer ran as the agent's own user, so the agent "
                "could have re-signed this log." + further)
    if not iso <= set(ISOLATED):
        return (f"Protection: not shown. The signer did not record that the agent could not reach its key (isolation: "
                f"{', '.join(sorted(iso))})." + further)
    said = f"Protection: the agent could not reach the signer's key ({', '.join(sorted(iso))})"
    if not rep.isolation:   # v1: no witness classes to rate
        return said + "."
    if "approvals: self" in assurance.split("; "):
        return said + ", but the agent's own user approved a held call (approvals: self)."
    if assurance.startswith("witnessed"):
        return said + ", and an independent witness cosigned the log."
    return (said + f", but no independent witness cosigned the log, so whoever runs the signer could rewrite it: "
            f"{wiki_url('docs/witnesses.md')}")
