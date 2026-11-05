"""Offline verifiers: `v1` for tracekit.bundle.v1 (frozen), `v2` for tracekit.bundle.v2."""
import json
import re
import sys
import zipfile

from tracekit.bundle_v2 import FORMAT
from tracekit.wiki import wiki_url

# signer_isolation, weakest first: a signer the agent could reach, one that recorded nothing or something else (rank 1),
# then ones out of its reach
REACH = {"same-user": 0, "separate-user": 2, "remote": 3}
ORDER = "the record before it is missing, extra or out of order"
# a failed check's line about one record, as either verifier words it: the record's seq, then why
_AT = re.compile(r"(?:record )?seq (\d{1,20}): (.+)|run .* run_seq \d+ \(seq (\d{1,20})\) does not continue the run|"
                 r"record at line \d+: seq (\d{1,20}), expected \d+ \(record deleted, inserted or reordered\)")
# why, in plain words: (the verifier's words, whether they mean the record was changed, what to print)
PLAIN = [(r"hash mismatch \(event content was edited\)|hash does not match the event", True,
          "its content was changed after it was signed"),
         (r"prev_hash does not match the previous record \(chain broken\)", True, ORDER),
         (r"signature invalid \(forged or altered record\)|bad signature", True,
          "its signature does not match: it was forged or altered"),
         (r"signed by \S+, bundle key is \S+", True, "it was signed by another key than the rest of the bundle"),
         (r"unknown kid", True, "it was signed by a key the log never declared"),
         (r"signed by key \S+ after its key\.retire", True, "it was signed by a key after that key was retired"),
         (r"another log's record", True, "it comes from another log"),
         (r"algorithm .* is not allowed", False, "it is signed with an algorithm your trust file does not allow"),
         (r"(event[\w.\[\]]*): .*", False, r"it is not a valid event at \1 (--detail shows the rule)")]
# a failed check that names no record, in plain words
CHECKS = {"files match manifest": "a file in the bundle was changed, added or removed",
          "manifest": "a file in the bundle was changed, added or removed",
          "checkpoint": "its checkpoint does not match a log key your trust file pins, or the bundle's own proofs",
          "bundle structure": "the bundle is malformed, so it could not be fully checked",
          "witness quorum": "fewer witnesses cosigned it than your trust file requires",
          "inclusion": "some of its records are not in the signed checkpoint"}
# v1's gap checks, in plain words (capture gaps are counted)
GAPS = {"run boundaries": "the run's start or end is not in the bundle, so actions before or after it may be missing",
        "run completeness": "some of the run's records were left out of the bundle",
        "rejected writes": "the signer refused writes to this run"}
# a run-set's informational tenant-level gaps (tracekit.signer.pipeline.TENANT_GAPS), in plain words: nothing missed
INFO = {"degraded_unanchored": "for a while no witness anchored the log; the signer ran without one",
        "witness_failed": "for a while a witness did not cosign the log",
        "witness_late": "a witness cosigned the log late",
        "clock_skew": "a witness's clock disagreed with the signer's"}


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


def _short(text, n=100):
    return text if len(text) <= n else text[:n - 3].rstrip() + "..."


def _where(problem):
    """(seq, whether the record was changed, why in plain words) of a problem line that names a record, else None."""
    m = _AT.fullmatch(problem)
    if not m:
        return None
    if m[1] is None:   # the chain breaks at this record
        return int(m[3] or m[4]), True, ORDER
    for words, changed, plain in PLAIN:
        p = re.fullmatch(words, m[2])
        if p:
            return int(m[1]), changed, p.expand(plain)
    return int(m[1]), False, _short(m[2])


def summary(rep, code, integrity, assurance, stream=None):
    """The short result `tracekit verify`, `tracekit last` and `tracekit demo` print by default, in plain words: for a
    bundle that verified (exit 0, or 3 under --strict) the verdict, with the tool calls and signed records it covers,
    the warnings by name and whether the record is proof against the agent; for one that failed (exit 1) where it
    breaks; for one that could not be checked (exit 2) why. It reads the report only: `--detail` prints all of it
    (print_report). Its own words are ASCII; bundle-derived text is printed without control characters."""
    from tracekit.verify.v2 import _CONTROL
    s = stream or sys.stdout
    say = lambda line: s.write(_CONTROL.sub("", str(line)) + "\n")   # noqa: E731
    if code == 2:   # no verdict: why, and what to run (a newer verifier's commands)
        c = next((c for c in rep.checks if c["status"] == "fail"), None) or \
            next((c for c in rep.checks if c["check"] == "revocations"), None) or {"detail": "", "problems": []}
        why = c["detail"].rstrip(".") if c["detail"] != integrity else ""
        say(integrity + (f": {why}" if why else "") + ".")
        for p in c["problems"][:5]:
            say(f"  {p}")
        return
    if code == 1:
        failed = [c for c in rep.checks if c["status"] == "fail"]
        at = sorted((not changed, seq, why) for seq, changed, why in filter(None, (
            _where(p) for c in failed for p in c["problems"])))
        if at:
            say(f"{'TAMPERED' if not at[0][0] else 'FAILED'} at event {at[0][1]}: {at[0][2]}.")
        else:
            c = failed[0] if failed else {"check": "verification", "detail": "", "problems": []}
            say("FAILED: " + CHECKS.get(c["check"], f"{c['check']}: "
                                        + _short((c["problems"] or [c["detail"] or "see the checks"])[0])) + ".")
        say("Add --detail to see each check.")
        return
    warned = list(dict.fromkeys(c["check"] for c in rep.checks if c["status"] == "warn"))
    unanchored = any(c["check"] == "trust root" and c["status"] != "pass" for c in rep.checks)   # v1's
    still_open = "open)" in integrity   # v2: VERIFIED TO HEAD n (open), VERIFIED (k run(s) open)
    gaps = ([f"{rep.gaps} signed gap{'s' if rep.gaps != 1 else ''} (things Tracekit knows it missed)"] if rep.gaps
            else []) + [GAPS[c] for c in warned if c in GAPS]
    # recorded, not missed: a call that ran, or a decision imported, against the signer's
    against = [f"{rep.mismatches} policy mismatch{'es' if rep.mismatches != 1 else ''} recorded (see --detail)"] \
        if rep.mismatches else []
    if unanchored:
        head, said = "VERIFIED BUT UNANCHORED", ["consistent with the bundle's own key"]
    else:
        head = "VERIFIED SO FAR" if still_open else "VERIFIED WITH GAPS" if gaps else \
            "VERIFIED WITH WARNINGS (strict)" if code == 3 else "VERIFIED"
        said = ["none changed after signing" if warned or still_open else
                "none changed, removed or added after signing"]
    if still_open:
        said.append("the run has not ended, so more may follow" if "TO HEAD" in integrity else
                    "not every run has ended, so more may follow")
    counted = ([f"{rep.calls} tool call{'s' if rep.calls != 1 else ''} in "] if rep.calls else []) + (
        [f"{rep.events} signed record{'s' if rep.events != 1 else ''}, "] if rep.events is not None else [])
    say(f"{head}: {''.join(counted)}" + "; ".join(said + gaps + against) + ".")
    if getattr(rep, "findings", None):   # v2's signed findings: an opinion of the run, worth a line of their own
        say(f"Findings: {rep.findings}.")
    if warned:
        say(f"Warnings: {', '.join(warned)}. Add --detail to read them.")
    for note in rep.notes:   # what the verdict did not use (v1's replay.html, v2's format bridge)
        say(f"Note: {note}")
    for kind, n in sorted(rep.info.items(), key=lambda kv: str(kv[0])):
        say(f"Note: {INFO.get(kind, f'the signer recorded {kind}')}" + (f" ({n} times)" if n > 1 else "") + ".")
    for line in protection(rep, assurance, unanchored):
        say(line)
    fingerprint = getattr(rep, "log_fingerprint", None)
    if fingerprint and not unanchored:
        say(f"Pinned log key SHA-256 fingerprint: {fingerprint}.")
    if fingerprint and not unanchored and not str(assurance).startswith("witnessed"):
        say(f"NOT ANCHORED: pin an independent witness or Rekor anchor ({wiki_url('docs/witnesses.md')}).")


def protection(rep, assurance, unanchored):
    """Whether the record is proof against the agent: from the isolation the signer recorded for each run (v2) or that
    v1's assurance names, the weakest of them, and only when something outside the bundle vouches for its key (v1: the
    trust root; v2: always, the trust file). A Tracekit Box box's runs (v2's `boxed agent` check) get that check's
    lines and are never under the general claim: a bundle of them alone gets only those. Lines of plain ASCII."""
    boxed, said = getattr(rep, "boxed", (0, []))
    if boxed and boxed >= sum(rep.isolation.values()):
        return said
    return _general(rep, assurance, unanchored, boxed) + said


def _general(rep, assurance, unanchored, boxed):
    if rep.isolation:
        iso = set(rep.isolation) | ({"unknown"} if boxed else set())
    elif assurance.startswith("signer_isolation="):   # v1: "signer_isolation=a, b (stamped ...)"
        iso = set(assurance[len("signer_isolation="):].split(" (", 1)[0].split(", "))
    else:
        iso = {"same-user" if assurance.startswith("dev") else "unknown"}
    weakest = min(iso, key=lambda v: REACH.get(v, 1))
    shown = weakest if weakest in REACH or weakest == "unknown" else "not recorded"
    fix = f"To make it proof, keep the key away from the agent: {wiki_url('docs/deploy.md')}"
    out = ["NOT SHOWN: nothing outside the bundle vouches for the signing key. Pin it with --key, or use a witness."] \
        if unanchored else []
    if REACH.get(weakest, 1) == 0:
        return out + ["NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could "
                      "have rewritten the record.", fix]
    if REACH.get(weakest, 1) == 1:
        return out + [f"NOT SHOWN: the signer did not record that the signing key was out of the agent's reach "
                      f"(isolation: {shown}).", fix]
    if unanchored:   # the bundle's own word about its signer, which nothing outside it vouches for
        return out
    out.append(f"PROOF AGAINST THE AGENT: the signing key was out of the agent's reach ({shown}).")
    if not rep.isolation:   # v1: no witness classes to rate
        return out
    if "approvals: self" in assurance.split("; "):
        out.append("But a held call was approved by the agent's own user, so that approval proves nothing.")
    elif assurance.startswith("witnessed"):
        out.append("An independent witness cosigned the log too.")
    else:
        out.append("Not proof against whoever runs the signer: no independent witness cosigned the log "
                   f"({wiki_url('docs/witnesses.md')}).")
    return out
