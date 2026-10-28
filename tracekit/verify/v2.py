"""Verifier for `tracekit.bundle.v2` (see `tracekit.bundle_v2` for the layout).

Trust comes only from the verifier's own pinned config (JSON):

    {"logs": ["<log vkey>", ...],                         Ed25519 (0x01) log keys; the key name is the origin; and
                                                          hybrid SLH-DSA (0xff) log keys (tracekit.format.checkpoint)
     "witnesses": [{"vkey": "<cosigner vkey>", "class": "public|customer|tracekit|operator"}, ...],
     "algs": ["ed25519"],                                 record signature algorithms accepted
     "witnesses_required": 0,                             pinned cosignatures a checkpoint must carry
     "rekor": {"trusted_root": {...}, "publishing_key": "<base64 SPKI>", "class": "public"},   optional: a Sigstore
                                                          trusted_root and the signer's P-256 Rekor publishing key
     "monitors": [{"vkey": "<monitor vkey>", "class": "...", "max_age_s": 3600}],   optional: `tracekit monitor` keys
     "issuers": [{"vkey": "<CA vkey>", "issuance_log_vkey": "<log vkey>"}],   optional: record-key issuers
                                                          (tracekit.issuer, `tracekit issuer vkey`)
     "analyzers": ["<scheme:subject>", ...]}              optional: the identities whose signed findings read
                                                          independent (the operator's `tracekit analyze --v2`)

Integrity VERIFIED needs: a checkpoint note signed by the pinned log key of its origin, and by the origin's pinned
hybrid SLH-DSA key when there is one (registry notes too), and cosigned by the required number of pinned witnesses;
with `rekor` pinned, the checkpoint's Rekor anchor (rekor/, tsa/) when the bundle has one
(tracekit.anchor.rekor2: an anchor that does not verify fails the bundle; without `rekor` it is ignored); every record
signed with an allowed algorithm by a key that the log declared in a signer.epoch record before it and had not retired
(key.retire) by then; schema-valid events; one run's chain, contiguous from run_seq 0 to a run.final record; the run's
first and last records and every key record included in the checkpointed tree. A run without run.final verifies only
to its head. The bundle's manifest is an index, never trusted.
A record signed by a key after that key's key.retire fails `signatures`, naming the retired key (keys are valid by
position only). A record after a run's run.final breaks the run chain.
A run in parts (format 1.4, runs/<id>.part-0001.jsonl, ...: bundle_v2.run_files) is checked as the one file its parts
read in order make. A `run parts` line says what is wrong with them: a part missing from part-0001 to the last, a name
outside that numbering, a part with no records, a part whose first record does not follow the last of the part before
it (parts out of order, an extra or repeated part), or the run in one file and in parts. A run with its last part
missing reads open, and fails `inclusion` while the proofs don't include the record now last: a cut-back run reads open
(VERIFIED TO HEAD n), never VERIFIED; only run.final or a run-set proves a run complete. A part over the format's
per-file limit, as any file, is an UNUSABLE BUNDLE.
The assurance line names the algorithms each conclusion rests on (records; the checkpoint: "Ed25519 only" or
"Ed25519 + SLH-DSA-SHA2-128s"; cosignatures; anchors) and the earliest independent anchor time (a cosignature or a
TSA time of a witness or anchor not classed operator).
Report lines (also in --json): tool calls by evidence tier (T1/T2/T3; a call whose records disagree counts as the
weakest, and one whose decision and result came by different capture paths is a `tiers` warning), records by
args_source, the signer_isolation the
signer recorded per run, the harness it attested per run (when any run has one), the tool classes run.registered says
fail open, and key assurance (asserted: the log declares its keys; this format has no key attestation).
Monitor reports (`tracekit monitor`) come from the verifier's side, never the bundle: verify(..., monitor_reports=[path]).
A report signed by a pinned monitor, no older than its max_age_s, for the checkpoint's origin, checked to at least the
checkpoint's size (and to its root at that size) and with no conflicts makes a witnessed assurance witnessed+monitored.
A pinned monitor's report of conflicts for the origin, or of another root at the checkpoint's size, fails `monitor`.
A run with any self-approval (dev mode: the approver was the requester) is reported `approvals: self`, assurance dev.
Approvals answered under the break-glass role are listed, as a warning.
A tool call that ran against a deny, or an ask with no consumed approval, is signed by the signer as a capture.gap
`executed_against_policy`; each is a `policy` warning. A call a gateway or executor decided whose run ended without its
result is a capture.gap `held_call_unresolved`; each is a `held calls` warning.
External decisions: policy.external records (other systems' decisions, imported at tier T3) are counted by system and
by whether the signer verified the system's signature; each signer-written capture.gap `decision_mismatch` (the
import disagreed with the signer's decision or tool, or named a call the signer never decided) makes the
`external decisions` line a warning.
Incidents (docs/incidents.md): every record an incident cites that is in the bundle exists and is one that fires a
trigger; an incident of scope run whose cites are all in its run is recomputed from the run's records under the
compiled policy the bundle carries for the run's policy_hash: one that does not follow from them fails `incidents`
(without that policy they are signer-asserted, an `incident policies` warning); a detector_unavailable incident cites a
decision whose detection state was unavailable. Others (operator incidents, other scopes, cites in other runs, a run
under several policies) are counted signer-asserted; a run.held of an incident opened in another run is its pointer.
Each response must have been honoured: an enforced hold or quarantine of scope run in its own run is followed by its
run.held or run.quarantined before the run's next decision (unless the run is quarantined already); a run may be held by
several incidents, each until its run.resumed; no allow and no ask without the id of an incident holding the run while
held, only deny while quarantined, a held call approved only by a person (never an agent, never self-approved) with
the incident id, no consume under a hold but of an approval asked under an incident still holding the run and none
under a quarantine, and no tool.result while held or quarantined but of a call in flight when the response took effect
or, held, one consumed with such an approval.
Policy snapshots: a policies/ file not named by the SHA-256 of its bytes fails `policy snapshot`; the others are the
one set of snapshots, by policy_hash, that both the incidents and the agent-approval checks read.
Coverage: a run.final that carries `coverage` (the capture layers that reported, calls reconciled, reconcile.* records
by kind) gives a `coverage` line; unreconciled calls and unexplained effects make it a warning, so `--strict` exits 3
on them. Its `matrix` gives the `coverage matrix` line: per action class (model calls, tool calls, network, processes,
services) enforced, observed, reported or not covered, the layers behind it and `asserted` where the status rests on
the operator's posture; across several runs, each class's weakest. It never says a run is complete. Each capture.gap
`observer_lost` (an egress observer or a kernel sensor's import went silent, restarted or lost events while its run was
open) is an `observers` warning.
Gaps: every other signer-written capture.gap in a run (unless its kind is in INFO_GAPS), approval.binding_mismatch and
trace.tamper record is counted by kind on a `gaps` warning; a run that declares a fail-open class makes `fail-open
classes` a warning (calls the agent classed as one of them may have run unrecorded while the signer was down: the
class is the agent's own reading of the tool).

Findings (tracekit why): a bundle may hold one run with its findings runs (run.registered `analyzes` it) and replay
runs (`replay_of` it). Each why.finding's replay runs must be in the bundle as replay runs of the analysed run in the
finding's investigation, each holding its model calls as gateway records (exactly one for rung 1); with a `tool`
target each outcome must agree with the tool uses those records name; the outcomes must count to its n, rates and
effect and give its interval and verdict (recomputed from looks, family, min_effect, applied and stopped); and every
replay run of an investigation with findings must be counted or listed `uncounted` by one; else `findings` fails.
Replay runs of an investigation with no finding are a `replay runs` warning.
Signed findings (`tracekit analyze --v2`, format 1.4): a `review` record with `cites`, in a findings run. Each cite
must be a record of the analysed run, in the bundle, with that run_seq and hash, and its verdict must have the shape
a signed finding has (a kind, rule and severity, and each field review_finding gives it of the values it allows: a
reviewer model's alignment, reason code, asserted model and families, an effect check's window; other fields pass),
else `reviews` fails. Each finding is
labelled by its author, the findings run's registered identity, positive-only: `independent` only when the trust
config's `analyzers` pins it; `self-asserted` (a warning) when it is the analysed run's own identity or either run's
signer_isolation is same-user (the agent could have written it); else `unpinned author <id>`. Without the analysed run
in the bundle, its cites are not counted and its author not checked (`reviews counted`, a warning). A review without
cites (a migrated v1 judge verdict) is `imported`, never checked. The findings themselves are an opinion of the run,
never part of its integrity: they get a `Findings:` line of their own after Integrity and Assurance (how many, by
severity, and their authors' labels); only a cite that does not match fails, as tampered or made-up evidence would.
Live constraints (format 1.4): a policy.decision held by TK-CONSTRAINT must be an ask that comes after a
constraint.added in its run, else `constraints` fails; the line counts the constraints and the calls they held.

Versions (format-v2.md §9): a bundle whose verifier_min_version is above this verifier's is `UNVERIFIABLE (needs
tracekit >= x)` (exit 2), the `bundle readable` line listing the commands that verify it with the user's paths
(`upgrade`). Format 1.4's non-critical slot: an `ext` field on any record and the `ext` record type, whose names a
verifier checks when it interprets them (EXT_CHECKS, each on lines of its own) and otherwise reports on a `not
interpreted` warning each (MAX_UNREAD of them; one more counts the rest); the records are signed, chained and included like any other, and the bundle stays VERIFIED.
This one interprets `amended` (the fields an LLM gateway changed in a request to show reasoning: `gateway amendments`)
and `openshell.policy` (OpenShell's sandbox policy changes, from the OpenShell middleware's OCSF import: `openshell
policy`).

Run-set (a bundle with registry/run-set.json): the tenant's registry notes, signed by the pinned log key under the
origin `<origin>/registry/<id of the bundle's tenant salt>`, cosigned by the required number of pinned witnesses (their
cosignatures cap the assurance level by the same rule as the checkpoint's), and consistent with each other; every
leaf of the range present and in the registry tree; each pointing to a record of the checkpointed tree with that hash,
seq, type and H(tenant_salt ‖ run_id); one run.final per run; every run final in the range in the bundle from its
run.registered (when in the range) to that run.final; every bundled run but the selected one the target of a leaf in
the range, and every bundled run of the tenant the range's run leaves name (the run-set line names it); a range ending
above size 0. Anything else is `run-set: INCOMPLETE` (FAILED). Tenant-level gaps in the range (signer capture.gap
and trace.tamper leaves: witness failures, clock skew, rollbacks) are counted by kind on the run-set line and warned. Every key.retire leaf in the range must be among the key
records, so a withheld retirement fails `keys`; without a range from size 0 that reaches every bundled record, that is
unproven: an assurance note, and a `keys` warning only when the bundle's own key records show a rotation (a bundle
that withholds a retirement and the next key's epoch reads as one key: docs/limits.md). The log tail after the checkpoint is reported
unproven (a warning) unless a log.closed in the range is the checkpoint's last record.

Certified record keys (docs/issuer.md): a signer.epoch key with `cert` is declared only when its certificate is signed
by a pinned issuer, for that key and log, and included in the issuer's issuance log at a checkpoint the issuer's log
key signed and max(1, witnesses_required) pinned witnesses cosigned; else `keys` fails and its records fail
`signatures` (unknown kid). A record under a certified key must have its ts within the certificate's validity and its
tenant in the certificate's tenants (the signer's own records excepted). Revocations come from the verifier's side,
never the bundle: verify(..., revocations=[path]), JSON lines files of revocation documents (an issuer's
issuance.jsonl will do; other lines are ignored). A record of a revoked certificate's key after the revocation's
last_seq makes the bundle `UNVERIFIABLE (key revoked)` (exit 2), not FAILED, unless something else fails.

Format bridge (04-design §1.9): when the log's first record, signer.epoch, has `bridge`, the v1 ledger it continues can
be checked too (verify(..., v1_ledger, v1_key)): its chain verifies by v1 rules up to `v1_last_seq`, that last record
has hash `v1_head` and is the retirement of key `v1_kid`, and no v1 record follows it. The frozen v1 verifier sees the
bridge's two records as ordinary signer capture.gap events (a `capture gaps` warning) and cannot tell a v1 record
appended after them with a copy of the retired key from any other: only this check reports it."""
import base64
import collections
import contextlib
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import zipfile

from tracekit import __version__, crypto
from tracekit.bundle import EXIT_BAD, EXIT_FAIL, EXIT_OK, Report, _load_trusted_key
from tracekit.bundle_v2 import FORMAT, KEY_TYPES, PART, ext_names, run_files, run_name
from tracekit.core import GENESIS
from tracekit.core import event_hash as v1_event_hash
from tracekit.format import cert, checkpoint, registry
from tracekit.format.canon import loads_strict
from tracekit.format.records import RecordError, record_digest, verify_record
from tracekit.ledger import read_records, verify_record_sig
from tracekit.merkle import leaf_hash, verify_consistency, verify_inclusion
from tracekit.schema import V2, validate
from tracekit.signer.format_bridge import retire_data
from tracekit.signer import rpc_schema
from tracekit.signer.pipeline import SIGNER_RUN
from tracekit.storage.base import ZERO_HASH

# capture.gap kinds that say nothing against a run's own records: the witness, anchor, key and bridge lines judge those
# themselves, the args source line counts coerced arguments, and an approval that expired is not a missing record
INFO_GAPS = {"witness_late", "witness_failed", "degraded_unanchored", "clock_skew", "format_upgrade", "key_retired",
             "args_coerced", "approval_expired"}
# capture.gap kinds warned on lines of their own
OWN_LINE = {"executed_against_policy", "held_call_unresolved", "decision_mismatch", "observer_lost"}

MAX_ENTRIES = 10_000
MAX_ENTRY = 64 << 20
MAX_TOTAL = 512 << 20
MAX_LINE = 1 << 20
MIN_RECORD = 256   # no signed record's line is shorter: its hash, signature, ids and timestamp alone are longer
MAX_LINES = MAX_ENTRY // MIN_RECORD   # per JSON lines file
CLASSES = ("public", "customer", "tracekit", "operator")
MATRIX = ("model_calls", "tool_calls", "network", "processes", "services")
COVERED = ("none", "reported", "observed", "enforced")   # weakest first
SEVERITIES = ("critical", "high", "medium", "low", "info")   # a signed finding's, worst first
# the closed fields of a signed finding's verdict (rpc_schema.REVIEW) and the values each may take
VERDICT = {"kind": ("finding", "coverage"), "severity": SEVERITIES, "tier": ("gateway", "harness", "transcript", "sdk"),
           "order": ("signed_before", "transcript_order", "after"), "alignment": tuple(rpc_schema.ALIGNMENTS),
           "reason": tuple(rpc_schema.REVIEW_REASONS)}
_RULE = re.compile(r"TK-[A-Z][0-9]{3}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MODEL = re.compile(r"[A-Za-z0-9._:/@+-]{1,128}")
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*")
_VERSION = re.compile(r"[0-9]{1,9}(\.[0-9]{1,9}){0,2}")
# control characters, and the bidirectional and zero-width format characters that would reorder or hide report text
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_IDENTITY = re.compile(r"[a-z0-9_]+:.+")   # scheme:subject, as run.registered's identity reads
_EOCD, _CEN, _LOC = struct.Struct("<IHHHHIIH"), struct.Struct("<IHHHHHHIIIHHHHHII"), struct.Struct("<IHHHHHIIIHH")
PAGE = "https://cygnux-labs.github.io/Tracekit/verify/"   # the browser verifier of the latest release (RELEASING.md)
_POINTER = re.compile(r"(/([^~/]|~[01])*)+")   # a JSON pointer (RFC 6901) to a field


def _amended(rep, events):
    """ext.amended: the JSON pointers of the fields an LLM gateway changed in a model request before sending it, to show
    the reasoning the request has the model do. The signer writes it on a gateway's request record only, whose content
    digest is of the request as sent; anywhere else, or not a list of pointers, it is a warning."""
    def fields(e):
        v, d = e["ext"].get("amended") if isinstance(e.get("ext"), dict) else None, e.get("data")
        return v if (e.get("type"), e.get("source")) == ("model.exchange", "gateway") and isinstance(d, dict) and \
            d.get("phase") == "request" and isinstance(v, list) and v and all(
                isinstance(p, str) and len(p) <= 256 and _POINTER.fullmatch(p) for p in v) else None
    good, bad = [e for e in events if fields(e)], [e for e in events if not fields(e)]
    n = collections.Counter(p for e in good for p in fields(e))
    rep.check("gateway amendments", not bad, f"gateway amended {len(good)} request(s) to show reasoning"
              + (f" ({', '.join(f'{p}: {c}' for p, c in sorted(n.items())[:8])})" if n else "")
              + "; each record commits to the request as sent",
              [f"seq {e.get('seq')}: ext.amended is not a list of JSON pointers on a gateway's model request"
               for e in bad][:20], warn=True)


_CHANGE = re.compile(r"[a-z0-9_.-]{1,64}")


def _openshell_policy(rep, events):
    """ext.openshell.policy: a change of the sandbox's policy or configuration that OpenShell reported (its name for the
    change, its hash of the policy, who made it; its message committed), an `ext` record the signer writes from the
    OpenShell middleware's OCSF import, that observer's assertion; anything else carrying the name is a warning."""
    def change(e):
        d = e.get("data")
        return d["change"] if (e.get("type"), e.get("source")) == ("ext", "signer") and isinstance(d, dict) and \
            d.get("name") == "openshell.policy" and isinstance(d.get("change"), str) and \
            _CHANGE.fullmatch(d["change"]) and isinstance(d.get("observer"), str) and d["observer"] else None
    good, bad = [e for e in events if change(e)], [e for e in events if not change(e)]
    n = collections.Counter(change(e) for e in good)
    rep.check("openshell policy", not bad, f"OpenShell changed the sandbox policy or configuration {len(good)} time(s)"
              + (f" ({', '.join(f'{c}: {k}' for c, k in sorted(n.items())[:8])})" if n else "")
              + ", as OpenShell reported it",
              [f"seq {e.get('seq')}: ext.openshell.policy is not an OpenShell policy change the signer recorded"
               for e in bad][:20], warn=True)


# the ext names this verifier interprets (bundle_v2.VERSIONS rows' "ext"): name -> check(rep, the events carrying it),
# whose lines are its own: every other line of the report reads the same without them (format-v2.md §9)
EXT_CHECKS = {"amended": _amended, "openshell.policy": _openshell_policy}
MAX_UNREAD = 20   # `not interpreted` lines, one per ext name; the rest on one line


class Unusable(ValueError):
    pass


def _layout(f):
    """The entries of the one zip layout §9 accepts, in order: (name bytes, local offset, compressed size, size, CRC,
    method). The end record ends the file; the central directory sits between the last entry and it; the entries are
    contiguous from offset 0, each local header repeating its central entry; no zip64, comment, extra field or
    general-purpose flag."""
    f.seek(0, 2)
    size = f.tell()
    if size < 22:
        raise Unusable("not a zip file")
    f.seek(size - 22)
    sig, disk, cd_disk, here, count, cd_size, cd_off, comment = _EOCD.unpack(f.read(22))
    if sig != 0x06054b50:
        raise Unusable("not a zip file, or bytes after its end record")
    if disk or cd_disk or here != count or comment or cd_off + cd_size != size - 22:
        raise Unusable("not the canonical zip layout: end record")
    if count > MAX_ENTRIES:
        raise Unusable("too many entries")
    f.seek(cd_off)
    cd, entries, at = f.read(cd_size), [], 0
    while at < cd_size:
        if at + 46 > cd_size:
            raise Unusable("truncated zip")
        sig, _, _, flags, method, _, _, crc, csize, usize, n, extra, comment, _, _, _, off = _CEN.unpack_from(cd, at)
        if sig != 0x02014b50 or extra or comment or at + 46 + n > cd_size:
            raise Unusable("bad central directory entry")
        entries.append((cd[at + 46:at + 46 + n], off, csize, usize, crc, method, flags))
        at += 46 + n
    if len(entries) != count:
        raise Unusable("not the canonical zip layout: entry count")
    pos = 0
    for raw, off, csize, usize, crc, method, flags in entries:
        n = raw.decode("cp437")[:80]
        if 0xffffffff in (off, csize, usize):
            raise Unusable("zip64 is not supported")
        if method not in (0, 8) or method == 0 and csize != usize:
            raise Unusable(f"{n!r}: compression method {method} (only stored and deflate)")
        if flags & 1:
            raise Unusable(f"{n!r} is encrypted")
        if flags:
            raise Unusable(f"{n!r}: general-purpose flags {flags:#x}")
        if off != pos:
            raise Unusable(f"not the canonical zip layout: {n!r} does not follow the entry before it")
        f.seek(off)
        h = f.read(30 + len(raw))
        loc = _LOC.unpack_from(h) if len(h) == 30 + len(raw) else ()
        if h[30:] != raw or (*loc[:1], *loc[2:4], *loc[6:]) != (0x04034b50, flags, method, crc, csize, usize, len(raw), 0):
            raise Unusable(f"bad local header for {n!r}")
        pos = off + 30 + len(raw) + csize
    if pos != cd_off:
        raise Unusable("not the canonical zip layout: bytes before the central directory")
    return [e[:6] for e in entries]


def read_zip(path):
    """{name: bytes} of a zip in the layout of §9 (`_layout`), read entry by entry under count and size caps. Refuses
    names that could escape a directory, symlinks and duplicate entries. `path`: a path or a binary file."""
    files, total = {}, 0
    with open(path, "rb") if isinstance(path, (str, bytes, os.PathLike)) else contextlib.nullcontext(path) as f:
        entries = _layout(f)
        with zipfile.ZipFile(f) as z:
            infos = z.infolist()
            if [(i.filename.encode("cp437"), i.header_offset, i.compress_size, i.file_size, i.CRC, i.compress_type)
                    for i in infos] != entries:
                raise Unusable("not the canonical zip layout: central directory")
            for i in infos:
                n = i.filename
                if not _NAME.fullmatch(n) or any(set(p) == {"."} for p in n.split("/")):
                    raise Unusable(f"bad entry name {n[:80]!r}")
                if n in files:
                    raise Unusable(f"duplicate entry {n}")
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Unusable(f"symlink entry {n}")
                cap = min(MAX_ENTRY, MAX_TOTAL - total)
                with z.open(i) as e:
                    data = e.read(cap + 1)
                if len(data) > cap:
                    raise Unusable(f"{n} is larger than the bundle limits")
                if len(data) != i.file_size:
                    raise Unusable(f"{n}: {len(data)} bytes, not the {i.file_size} its entry says")
                files[n], total = data, total + len(data)
    return files


def load_trust(path):
    with open(path, "rb") as f:
        t = loads_strict(f.read(MAX_LINE))
    r = t.get("rekor", {}) if isinstance(t, dict) else None
    ok = (isinstance(t, dict) and set(t) <= {"logs", "witnesses", "algs", "witnesses_required", "rekor", "monitors",
                                             "issuers", "analyzers"}
          and isinstance(r, dict) and (not r or set(r) == {"trusted_root", "publishing_key", "class"}
                                       and isinstance(r["trusted_root"], dict) and isinstance(r["publishing_key"], str)
                                       and r["class"] in CLASSES)
          and isinstance(t.get("logs"), list) and t["logs"] and all(isinstance(k, str) for k in t["logs"])
          and isinstance(t.get("witnesses", []), list)
          and all(isinstance(w, dict) and set(w) == {"vkey", "class"} and isinstance(w["vkey"], str)
                  and w["class"] in CLASSES for w in t.get("witnesses", []))
          and isinstance(t.get("algs"), list) and t["algs"] and all(isinstance(a, str) for a in t["algs"])
          and type(t.get("witnesses_required", 0)) is int and t.get("witnesses_required", 0) >= 0
          and isinstance(t.get("monitors", []), list)
          and all(isinstance(m, dict) and set(m) == {"vkey", "class", "max_age_s"} and isinstance(m["vkey"], str)
                  and m["class"] in CLASSES and type(m["max_age_s"]) is int and m["max_age_s"] > 0
                  for m in t.get("monitors", []))
          and isinstance(t.get("issuers", []), list)
          and all(isinstance(i, dict) and set(i) == {"vkey", "issuance_log_vkey"}
                  and all(isinstance(v, str) for v in i.values()) for i in t.get("issuers", []))
          and isinstance(t.get("analyzers", []), list)
          and all(isinstance(a, str) and _IDENTITY.fullmatch(a) for a in t.get("analyzers", [])))
    if not ok:
        raise ValueError(f"{path}: not a v2 trust config (logs, witnesses, algs, witnesses_required, rekor, monitors, "
                         "issuers, analyzers)")
    for k in (t["logs"] + [w["vkey"] for w in t.get("witnesses", [])] + [m["vkey"] for m in t.get("monitors", [])]
              + [v for i in t.get("issuers", []) for v in i.values()]):
        checkpoint.parse_vkey(k)
    return {"witnesses": [], "witnesses_required": 0, "monitors": [], "issuers": [], "analyzers": [], **t}


def _jsonl(data, shortest=MIN_RECORD):
    """The JSON texts of a JSON lines file, each line at least `shortest` bytes: checked before any is parsed, so a
    bundle's lines can't outnumber MAX_TOTAL / MIN_RECORD, whatever it unzips to."""
    if data and not data.endswith(b"\n"):
        raise ValueError("a JSON lines file must end in a newline")
    if data.count(b"\n") > MAX_LINES:   # counted before any is parsed: a run of tiny lines costs no memory
        raise ValueError("more lines than the bundle limits")
    lines = data.split(b"\n")[:-1]
    if any(len(line) > MAX_LINE for line in lines):
        raise ValueError("line longer than the bundle limits")
    if any(len(line) < shortest for line in lines):
        raise ValueError("line shorter than a signed record")
    return [loads_strict(line) for line in lines]


def _version(v):
    return tuple(int(x) for x in re.findall(r"[0-9]+", v)[:3])


def verify(path, trust_path, v1_ledger=None, v1_key=None, monitor_reports=(), revocations=(), memo=None):
    """Verify a v2 bundle against the pinned trust config at `trust_path`, with `v1_ledger` (a v1 ledger.jsonl) and
    `v1_key` (its signer.pub) the format bridge into it, with `monitor_reports` (paths) the log's monitoring and with
    `revocations` (paths) the record-key revocations known. `memo`: a set the caller keeps across calls (tracekit
    view, as a run grows): the record_digest of each record whose signature and schema held, so the same record is not
    checked for them again; everything else is. Never raises on a malformed bundle."""
    rep = Report()
    rep.integrity, rep.assurance = "UNUSABLE BUNDLE", "none"
    try:
        trust = load_trust(trust_path)
    except Exception as e:
        rep.check("trust config", False, f"{type(e).__name__}: {e}")
        return rep, EXIT_BAD
    try:
        files = read_zip(path)
        manifest = loads_strict(files.pop("manifest.json"))
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
            raise Unusable(f"format is not {FORMAT}")
        need = manifest.get("verifier_min_version")
        if not (isinstance(need, str) and _VERSION.fullmatch(need)):
            raise Unusable("verifier_min_version is not a version number")
        if _version(need) > _version(__version__):
            rep.integrity = f"UNVERIFIABLE (needs tracekit >= {need})"
            rep.check("bundle readable", False, rep.integrity, upgrade(need, path, trust_path))
            return rep, EXIT_BAD
    except Exception as e:
        rep.check("bundle readable", False, f"cannot read bundle: {type(e).__name__}: {e}")
        return rep, EXIT_BAD
    try:
        _verify(rep, manifest, files, trust, v1_ledger, v1_key, monitor_reports, revocations, memo)
    except Exception as e:
        rep.check("bundle structure", False, "", [f"malformed and could not be fully checked: {type(e).__name__}: {e}"])
    if rep.failures:
        rep.integrity = "FAILED"
    return rep, EXIT_FAIL if rep.failures else EXIT_BAD if rep.integrity.startswith("UNVERIFIABLE") else EXIT_OK


def upgrade(need, bundle, trust):
    """Ways to verify the bundle with a verifier of version `need` or later, as commands with the user's own paths."""
    from tracekit.cli import _quote
    b, t = (_quote(os.fsdecode(p)) if isinstance(p, (str, bytes, os.PathLike)) else n
            for p, n in ((bundle, "BUNDLE"), (trust, "TRUST.json")))
    return [f'uvx --from "tracekit-ai>={need}" tracekit verify {b} --trust {t}',
            f"npx -y @cygnuxlabs/tracekit@latest verify {b} --trust {t}",
            f"or open {PAGE} and choose both files: the page verifies them in your browser and sends nothing"]


def _ext(rep, events, full):
    """A line per ext name the records carry: its EXT_CHECKS check, or a `not interpreted` warning. The records were
    checked like every other (signature, chain, inclusion); `full`: the manifest's advisory verifier_version."""
    carry = {}   # name -> the events carrying it
    for e in events:
        for n in {str(x)[:64] for x in ext_names(e)}:
            carry.setdefault(n, []).append(e)
    later = f"; tracekit >= {full} checks it" if isinstance(full, str) and _VERSION.fullmatch(full) \
        and _version(full) > _version(__version__) else ""
    shown, more = 0, 0
    for n, es in sorted(carry.items()):
        if n in EXT_CHECKS:
            EXT_CHECKS[n](rep, es)
        elif shown < MAX_UNREAD:
            shown += 1
            rep.check("not interpreted", False, f"{len(es)} record(s) carry ext.{n}: their signatures, chain and "
                      f"inclusion are checked above; what ext.{n} means is not checked{later}", warn=True)
        else:   # a line each would bury the report
            more += 1
    if more:
        rep.check("not interpreted", False, f"{more} more ext name(s), on records whose signatures, chain and inclusion "
                  f"are checked above; what they mean is not checked{later}", warn=True)


def _revocations(rep, trust, paths):
    """{(issuer vkey, serial): last_seq} of the revocation documents in `paths` that a pinned issuer signed."""
    out = {}
    for path in paths:
        try:
            with open(path, "rb") as f:
                docs = _jsonl(f.read(MAX_ENTRY), 0)   # revocation documents, not records
        except (OSError, ValueError) as e:
            rep.check("revocations", False, f"{path}: {type(e).__name__}: {e}")
            continue
        for doc in docs:
            try:
                r = cert.revocation(doc, trust["issuers"])
            except ValueError as e:
                rep.check("revocations", False, f"{path}: {e} (ignored)", warn=True)
                continue
            if r is not None:
                out[r[:2]] = min(r[2], out.get(r[:2], r[2]))
    return out


def _ts(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc).timestamp()


def _manifest_detail(listed, hashes, bad):
    """The manifest check's detail: on a failure, the files that differ from the manifest (the first 5) and how."""
    if not isinstance(listed, dict):
        return "the manifest lists no files"
    if not bad:
        return "every file is listed with its SHA-256 and nothing else is in the bundle"
    how = [f"{n} ({'changed' if n in listed and n in hashes else 'missing' if n in listed else 'not listed'})"
           for n in bad[:5]]
    return "files differ from the manifest: " + ", ".join(how) + (f" and {len(bad) - 5} more" if len(bad) > 5 else "")


def _verify(rep, manifest, files, trust, v1_ledger, v1_key, monitor_reports, revocations, memo=None):
    listed, hashes = manifest.get("files"), {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
    bad = sorted(n for n in set(listed) | set(hashes) if n not in listed or n not in hashes or listed[n] != hashes[n]) \
        if isinstance(listed, dict) else []
    rep.check("manifest", isinstance(listed, dict) and not bad, _manifest_detail(listed, hashes, bad))

    # checkpoint: the only thing the records' trust hangs on
    proofs = loads_strict(files["proofs/records.json"])
    name = proofs["checkpoint"]
    if not (isinstance(name, str) and name.startswith("checkpoints/") and name.endswith(".note")):
        raise ValueError("proofs name no checkpoint note")
    witnesses = {w["vkey"]: w["class"] for w in trust["witnesses"]}
    try:
        origin, size, root, cosigs = checkpoint.open_note(files[name], trust["logs"], list(witnesses))
    except checkpoint.NoteError as e:
        rep.check("checkpoint", False, str(e))
        return
    rep.check("checkpoint", size == proofs["tree_size"], f"{origin} at tree size {size}, signed by its pinned log key")
    rep.check("witness quorum", len(cosigs) >= trust["witnesses_required"],
              f"{len(cosigs)} pinned cosignature(s), {trust['witnesses_required']} required")
    anchors = _anchor(rep, files, trust, files[name], origin, size)
    monitored = _monitor(rep, trust, monitor_reports, origin, size, root)

    def included(record):
        seq = record["event"]["seq"]
        seq = int(seq) if isinstance(seq, float) and seq.is_integer() else seq   # as JSON reads it, and the TS verifier
        path = proofs["inclusion"].get(str(seq))
        return isinstance(path, list) and verify_inclusion(seq, size, leaf_hash(bytes.fromhex(record["hash"][7:])),
                                                           [base64.b64decode(p, validate=True) for p in path], root)

    def check_record(r, keys, problems):
        """Signature, schema and log membership of one record; `keys`: the SPKIs the log allows at its position. A
        record valid only under a key retired before it is named as such."""
        try:
            digest = memo is not None and isinstance(r, dict) and record_digest(r)
            known = bool(digest) and digest in memo
            verify_record(r, keys, trust["algs"], known)
        except RecordError as e:
            seq = r["event"].get("seq") if str(e) == "unknown kid" else None   # a well-formed record by then
            retired = [k["spki"] for k in timeline.values()
                       if type(seq) is int and k["until"] is not None and k["until"] < seq]
            try:
                verify_record(r, retired, trust["algs"])
                problems.append(f"seq {seq}: signed by key {r['kid'][:80]} after its key.retire")
            except RecordError:
                problems.append(f"seq {r.get('event', {}).get('seq')!r}: {e}")
            return
        e = r["event"]
        errs = [] if known else validate(e) if e.get("schema_version") == V2 else ["not a tracekit.event.v2 event"]
        if digest and not errs:
            memo.add(digest)
        problems.extend(f"seq {e.get('seq')!r}: {x}" for x in errs)
        if not errs and e.get("log_id") != log_id:
            problems.append(f"seq {e['seq']}: another log's record")
        c = certs.get(r["kid"])
        if errs or c is None:
            return
        if not c["not_before"] <= _ts(e["ts"]) <= c["not_after"]:
            problems.append(f"seq {e['seq']}: at {e['ts']}, outside the validity of key {r['kid'][:80]}'s certificate")
        elif e["tenant"] not in c["tenants"] and (e["tenant"], e["run_id"]) != SIGNER_RUN:
            problems.append(f"seq {e['seq']}: tenant {e['tenant'][:64]!r} is outside key {r['kid'][:80]}'s certificate")
        elif e["seq"] > revoked.get(r["kid"], e["seq"]):
            revoked_records.append(f"seq {e['seq']}: key {r['kid'][:80]} (serial {c['serial'][:64]}) is revoked after "
                                   f"seq {revoked[r['kid']]}")

    # keys: declared and retired by records the checkpointed tree includes, so the log key vouches for them
    key_records, key_problems, timeline = _jsonl(files["keys/records.jsonl"]), [], {}
    log_id = key_records[0]["event"].get("log_id") if key_records else None
    certs, revoked, revoked_records, issued = {}, {}, [], {}   # kid -> certificate; kid -> last valid seq; issuer names
    revocations = _revocations(rep, trust, revocations)

    def keys_at(seq):
        return [k["spki"] for k in timeline.values() if k["from"] <= seq and (k["until"] is None or seq <= k["until"])]

    last = -1
    for r in key_records:
        e = r["event"]
        if e["type"] not in KEY_TYPES or e["seq"] <= last or not included(r):
            key_problems.append(f"seq {e['seq']}: not a key record of the checkpointed tree, in order")
            continue
        last = e["seq"]
        declared = {}
        if e["type"] == "signer.epoch":
            for k in e["data"].get("keys", []):
                der = base64.b64decode(k["spki"], validate=True)
                if crypto.spki_kid(der) != k["kid"] or crypto.key_alg(der) != k["alg"]:
                    key_problems.append(f"seq {e['seq']}: key {k['kid']} does not match its SPKI")
                if "cert" not in k and trust["issuers"] and not e["data"].get("bridge"):
                    key_problems.append(f"seq {e['seq']}: key {k['kid'][:80]} has no certificate, and the trust "
                                        "config pins issuers")
                    continue
                if "cert" in k:
                    try:
                        c, pin = cert.check(k["cert"], trust["issuers"], list(witnesses),
                                            max(1, trust["witnesses_required"]))
                        if (c["kid"], c["spki"], c["log_id"]) != (k["kid"], k["spki"], log_id):
                            raise ValueError("the certificate is for another key or log")
                    except ValueError as x:
                        key_problems.append(f"seq {e['seq']}: key {k['kid'][:80]}: {x}")
                        continue
                    certs[k["kid"]], issued[k["kid"]] = c, pin["vkey"].split("+")[0]
                    if (pin["vkey"], c["serial"]) in revocations:
                        revoked[k["kid"]] = revocations[(pin["vkey"], c["serial"])]
                declared[k["kid"]] = {"spki": der, "from": e["seq"], "until": None}
        check_record(r, keys_at(e["seq"]) + [k["spki"] for k in declared.values()], key_problems)
        if e["type"] == "key.retire":
            if e["data"]["kid"] not in timeline:
                key_problems.append(f"seq {e['seq']}: retires an unknown key")
            else:
                timeline[e["data"]["kid"]]["until"] = e["data"]["last_seq"]
        timeline.update(declared)

    # the runs: one, or with a run-set any number; each in one file or in parts
    names = run_files(files)
    run_set = "registry/run-set.json" in files
    runs, problems, chain, outside, layout, seen = {}, [], [], [], [], set()
    for name, parts in names.items():
        pieces = [_jsonl(files[n]) for n in parts]
        records = runs[name] = [r for p in pieces for r in p]
        layout += _parted(name, parts, pieces)
        if not records:
            raise ValueError("a run has no records")
        head = records[0]["event"]
        key = (head.get("tenant"), head.get("run_id"))
        if all(isinstance(k, str) for k in key):   # a second file of one run would count its records twice
            if key in seen:
                chain.append(f"run {key[1][:200]!r} of tenant {key[0][:64]!r} again in {name}")
            seen.add(key)
        for i, r in enumerate(records):
            check_record(r, keys_at(r["event"]["seq"]), problems)
            e = r["event"]
            if (e.get("run_seq") != i or e.get("run_prev_hash") != (records[i - 1]["hash"] if i else ZERO_HASH)
                    or (e.get("tenant"), e.get("run_id")) != (head.get("tenant"), head.get("run_id"))
                    or (i and (e["seq"] <= records[i - 1]["event"]["seq"]
                               or records[i - 1]["event"].get("type") == "run.final"))):
                chain.append(f"run {str(head.get('run_id'))[:200]!r} run_seq {i} (seq {e.get('seq')!r}) does not "
                             "continue the run")
        if not (included(records[0]) and included(records[-1])):
            outside.append(f"run {str(head.get('run_id'))[:200]!r}" + (
                f": the last record of {parts[-1]} is not in the checkpointed tree, so a later part may be missing"
                if parts != [name] and included(records[0]) else ""))
    if len(runs) != 1 and not run_set and not _about_one(runs):
        raise ValueError("a v2 bundle holds exactly one run, one run with its findings and replay runs, or a run-set")
    retired, proven_to, reg_cosigs = [], -1, []
    if run_set:
        retired, proven_to, reg_cosigs = _run_set(rep, files, trust, witnesses, origin, size, runs, included,
                                                  lambda r, p: check_record(r, keys_at(r["event"]["seq"]), p))
        listed = {(r["event"]["seq"], r["hash"]) for r in key_records}
        key_problems.extend(f"seq {seq}: key.retire withheld (the registry log has it)"
                            for seq, h in retired if (seq, h) not in listed)
    rep.check("keys", bool(timeline) and not key_problems,
              f"{len(timeline)} record key(s) from {len(key_records)} key record(s)", key_problems)
    # a key.retire left out of keys/records.jsonl shows only against a registry range from its start past every record
    # lean: a key.retire written before the tenant's first registry leaf is in no registry of the tenant; add signer
    # leaves to a tenant's registry when it is created if keys are ever retired while tenants are being added
    relied = max(r["event"]["seq"] for r in key_records + [r for rs in runs.values() for r in rs])
    rotated = len(timeline) > 1 or any(r["event"]["type"] == "key.retire" for r in key_records)
    if proven_to < relied and rotated:   # one key never retired: the assurance line notes it, no warning
        rep.check("keys", False, "retirements not proven complete",
                  [f"no run-set from registry size 0 reaches seq {relied}, so a withheld key.retire would not show"],
                  warn=True)
    _bridge(rep, key_records, v1_ledger, v1_key)
    parted = [ps for n, ps in names.items() if ps != [n]]
    if parted:
        rep.check("run parts", not layout, f"{len(parted)} run(s) in {sum(map(len, parted))} parts, each part "
                                           "continuing the one before it", layout)
    count = sum(map(len, runs.values()))
    rep.check("signatures", not problems, f"{count} record(s), keys valid at their position", problems)
    only = len(runs) == 1 and next(iter(runs.values()))[0]["event"]
    rep.check("run chain", not chain, f"run {str(only.get('run_id'))[:200]!r} of tenant {only.get('tenant')!r}, "
                                      "contiguous from run_seq 0" if only else
              f"{len(runs)} run(s), each contiguous from run_seq 0", chain)
    rep.check("inclusion", not outside, f"first and last records of {len(runs)} run(s) are in the checkpointed tree "
                                        f"of size {size}", outside)
    policies = {}   # policy_hash -> the bundled snapshot named by it: the one set _incidents and _approvals read
    for p in sorted(n for n in files if n.startswith("policies/")):
        h = "sha256:" + hashlib.sha256(files[p]).hexdigest()
        rep.check("policy snapshot", p == f"policies/{h[7:]}.json", p)
        if p == f"policies/{h[7:]}.json":
            policies[h] = files[p]

    still_open = [rs for rs in runs.values() if rs[-1]["event"].get("type") != "run.final"]
    rep.integrity = ("VERIFIED" if not still_open else
                     f"VERIFIED TO HEAD {still_open[0][-1]['event'].get('run_seq')} (open)" if only else
                     f"VERIFIED ({len(still_open)} run(s) open)")
    if revoked_records:
        rep.check("revocations", False, f"{len(revoked_records)} record(s) under a revoked key", revoked_records[:20],
                  warn=True)
        rep.integrity = "UNVERIFIABLE (key revoked)"
    every = [r for rs in runs.values() for r in rs]
    self_approved = any(r["event"].get("type") == "approval" and r["event"]["data"].get("self_approved") is True
                        for r in every)
    against = [f"seq {r['event']['seq']}: {str(r['event']['data'].get('reason'))[:200]}" for r in every
               if r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") == "executed_against_policy"]
    if against:
        rep.check("policy", False, f"{len(against)} tool call(s) ran against a deny or an unapproved ask", against[:20],
                  warn=True)
    unresolved = [f"seq {r['event']['seq']}: {str(r['event']['data'].get('reason'))[:200]}" for r in every
                  if r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") == "held_call_unresolved"]
    if unresolved:   # the signer's word that a call a gateway held ended its run without a result
        rep.check("held calls", False, f"{len(unresolved)} tool call(s) a gateway or executor decided have no result",
                  unresolved[:20], warn=True)
    alarms = [r["event"] for r in every if r["event"].get("type") in ("approval.binding_mismatch", "trace.tamper") or (
        r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") not in (*INFO_GAPS, *OWN_LINE))]
    if alarms:
        kind = lambda e: str(e["data"].get("kind"))[:64] if e["type"] == "capture.gap" else e["type"]
        rep.check("gaps", False, f"{len(alarms)} signed gap, tamper or mismatch record(s): "
                  + ", ".join(f"{k} {n}" for k, n in sorted(collections.Counter(map(kind, alarms)).items())),
                  [f"seq {e['seq']}: {kind(e)}: " + (
                      f"approval {str(e['data'].get('approval_id'))[:200]} of call "
                      f"{str(e['data'].get('tool_use_id'))[:200]}: the arguments differ from the approved ones"
                      if e["type"] == "approval.binding_mismatch" else
                      str(e["data"].get("reason", e["data"].get("path")))[:200]) for e in alarms][:20], warn=True)
    external = [r["event"]["data"] for r in every if r["event"].get("type") == "policy.external"]
    mismatched = [f"seq {r['event']['seq']}: {str(r['event']['data'].get('reason'))[:200]}" for r in every
                  if r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") == "decision_mismatch"]
    if external or mismatched:
        systems = collections.Counter(str(d["system"])[:64] for d in external)
        verified = sum(d["signature"] == "verified" for d in external)
        rep.check("external decisions", not mismatched,
                  f"{len(external)} imported: " + (", ".join(f"{k} {n}" for k, n in sorted(systems.items())) or "none")
                  + f"; signatures verified {verified}, unverified {len(external) - verified}; "
                  + f"{len(mismatched)} disagree with the signer", mismatched[:20], warn=True)
    finals = [rs[-1]["event"]["data"]["coverage"] for rs in runs.values()
              if rs[-1]["event"].get("type") == "run.final" and "coverage" in rs[-1]["event"]["data"]]
    paired = sum(rs[-1]["event"]["data"].get("paired_by_args", 0) for rs in runs.values()
                 if rs[-1]["event"].get("type") == "run.final")
    unreconciled = {}   # from the signed reconcile.* records themselves, not run.final's summary of them
    for r in every:
        if str(r["event"].get("type")).startswith("reconcile."):
            k = r["event"]["type"][len("reconcile."):]
            unreconciled[k] = unreconciled.get(k, 0) + 1
    if finals or unreconciled:
        layers = sorted({x for c in finals for x in c["layers"]})
        rep.check("coverage", not unreconciled,
                  f"layers {'+'.join(layers) or 'none'}" + ("" if "L3" in layers else " (L3 absent)")
                  + f"; {sum(c['reconciled'] for c in finals)} call(s) reconciled"
                  + (f" ({paired} paired by arguments: no tool-call id)" if paired else "") + "; unreconciled: "
                  + (", ".join(f"{k} {n}" for k, n in sorted(unreconciled.items())) or "none"),
                  [f"seq {r['event']['seq']}: {r['event']['type']}"
                   + (f" {str(r['event']['tool_call_id'])[:200]}" if "tool_call_id" in r["event"] else "")
                   + f": {str(r['event']['data'].get('detail'))[:200]}" for r in every
                   if str(r["event"].get("type")).startswith("reconcile.")][:20], warn=True)
    matrices = [rs[-1]["event"]["data"]["matrix"] for rs in runs.values()
                if rs[-1]["event"].get("type") == "run.final" and "matrix" in rs[-1]["event"]["data"]]
    if matrices:
        rep.check("coverage matrix", True, (f"weakest of {len(matrices)} runs: " if len(matrices) > 1 else "")
                  + ", ".join(_coverage(matrices, k) for k in MATRIX))
    lost = [f"seq {r['event']['seq']}: {str(r['event']['data'].get('reason'))[:200]}" for r in every
            if r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") == "observer_lost"]
    if lost:
        rep.check("observers", False, f"{len(lost)} observer gap(s): an observer went silent, restarted or lost events "
                                      "while its run was open", lost[:20], warn=True)
    _findings(rep, runs)
    _reviews(rep, runs, trust["analyzers"])
    _constraints(rep, runs)
    _incidents(rep, runs, policies)
    vault = collections.Counter(r["event"]["type"] for r in every if r["event"].get("type") in ("content.accessed",
                                                                                              "content.erased"))
    if vault:   # signer records of the content vault (docs/privacy.md): who read or erased retained content
        rep.check("content vault", True, f"{vault['content.accessed']} access(es), {vault['content.erased']} erasure(s) "
                                         "of retained content, each signed by the signer")
    # a tool call's tier is the weakest its records claim (untiered < T3, receipt only, < T1 < T2): each tier a record
    # names, and untiered for a decision or result that names none, so a call decided at T2 and completed elsewhere
    # isn't T2;
    # paths: the (source, tier)s of its decisions and results, which differ only when another layer answered for it
    order, tiers, claims, paths = (None, "T3", "T1", "T2"), {}, {}, {}
    for r in every:
        e = r["event"]
        if e.get("tool_call_id") is None:
            continue
        # a JSON key: a schema-invalid record's id may be a list or an object, which the TS verifier counts too
        k, decided = json.dumps([e.get("run_id"), e["tool_call_id"]]), e.get("type") in ("policy.decision", "tool.result")
        tier, tiers[k] = e.get("tier") if e.get("tier") in order else None, None
        if tier is not None or decided:
            claims[k] = min(claims.get(k, tier), tier, key=order.index)
        if decided:
            paths.setdefault(k, set()).add((str(e.get("source"))[:64], tier))
    tiers.update(claims)
    split = [f"{str(run)[:200]} {str(tcid)[:200]}: " + ", ".join(sorted(f"{s} {t or 'untiered'}" for s, t in p))
             for (run, tcid), p in ((json.loads(k), p) for k, p in paths.items()) if len(p) > 1]
    if tiers:
        n = collections.Counter(tiers.values())
        rep.check("tiers", not split, f"{len(tiers)} tool call(s): "
                  + ", ".join(f"{t} {n[t]}" for t in ("T1", "T2", "T3")) + (f", untiered {n[None]}" if n[None] else "")
                  + (f"; {len(split)} decided and completed by different capture paths" if split else ""),
                  split[:20], warn=True)
    sources = [r["event"]["args_source"] for r in every if "args_source" in r["event"]]   # schema-invalid: any value
    if sources:
        rep.check("args source", True, f"{len(sources)} record(s): "
                  + ", ".join(f"{s} {sources.count(s)}" for s in ("raw", "parsed", "coerced")))
    registered = [rs[0]["event"]["data"] if rs[0]["event"].get("type") == "run.registered" else {} for rs in runs.values()]
    isolation = collections.Counter(str(d.get("signer_isolation", "unreported"))[:64] for d in registered)
    rep.check("isolation", True, "signer-reported: " + ", ".join(f"{k} {n} run(s)" for k, n in sorted(isolation.items())))
    principals = [f"{str(e['principal'])[:256]} ({'attested' if e.get('principal_attested') is True else 'app-asserted'})"
                  for e in (rs[0]["event"] for rs in runs.values())
                  if e.get("type") == "run.registered" and "principal" in e]
    if principals:
        rep.check("principals", True, ", ".join(principals[:20]) + (", ..." if len(principals) > 20 else ""))
    if any("harness" in d for d in registered):
        bound = [f"{str(rs[0]['event'].get('run_id'))[:200]} " + (
            str(d["harness"].get("name"))[:64] if isinstance(d.get("harness"), dict) else "none")
            for rs, d in zip(runs.values(), registered)]
        rep.check("harness", True, "signer-attested: " + ", ".join(bound[:20]) + (", ..." if len(bound) > 20 else ""))
    fail_open = sorted({str(c)[:64] for d in registered for c, m in (d.get("fail_modes") or {}).items() if m == "open"})
    rep.check("fail-open classes", not fail_open, ", ".join(fail_open) or "none",
              ["calls the agent classed as one of these may have run unrecorded while the signer was down"]
              if fail_open else [],
              warn=True)
    rep.check("key assurance", True, f"certified: {len(issued)} of {len(timeline)} record key(s) by pinned issuer(s) "
                                     f"{', '.join(sorted(set(issued.values())))}" if issued else
              "asserted: the log declares its record keys; none is attested")
    rep.assurance = (_assurance(origin, cosigs, witnesses, trust, {r["alg"] for r in every + key_records}, self_approved,
                                anchors, monitored, reg_cosigs)
                     + ("; key retirements not proven complete" if proven_to < relied else ""))
    _approvals(rep, runs, policies)
    glass = [r["event"] for r in every if r["event"].get("type") == "approval"
             and r["event"]["data"].get("break_glass") is True]
    if glass:
        rep.check("break-glass approvals", False, f"{len(glass)} approval(s) answered under the break-glass role",
                  [f"seq {e['seq']}: {e['data']['decision']} {e['data'].get('approval_id')} by "
                   f"{e['data']['approver'][:256]}: {str(e['data'].get('reason'))[:200]!r}" for e in glass][:20],
                  warn=True)
    pointed = _jsonl(files["registry/records.jsonl"]) if run_set else []   # the records a run-set's leaves name
    _ext(rep, list({r["event"]["seq"]: r["event"] for r in key_records + pointed + every}.values()),
         manifest.get("verifier_version"))


def _approvals(rep, runs, policies):
    """Approvals by people and by agents, each on a line of its own. An agent's approval fails the line unless its run
    holds the approval.request and policy.decision it answered, the signer called the request agent-eligible
    (agent.eligible) and no approval.escalated or approval.revoked of it comes first, the decision has no provenance and
    a complete provenance_state (or none: the signer leaves it out then), its approval needs no passkey, and the agent
    is neither the requester nor the run's owner; with the policy snapshot of the decision's policy_hash in `policies`
    (the bundle's, each named by its SHA-256), every rule the call was held by is an ask rule that permits agents and
    needs no passkey (else a warning: bounds unchecked). Argument bounds are never checkable offline: the records hold
    the arguments as salted commitments."""
    people, agents, problems, unchecked = 0, 0, [], []
    for rs in runs.values():
        events = [r["event"] for r in rs]
        ident = (events[0]["data"].get("identity") or {}) if events[0].get("type") == "run.registered" else {}
        owner = f"{ident.get('scheme')}:{str(ident.get('subject'))[:256]}"
        asked = {e["data"].get("approval_id"): e["data"] for e in events if e.get("type") == "approval.request"}
        decided = {e["data"].get("decision_id"): e["data"] for e in events
                   if e.get("type") == "policy.decision" and "decision_id" in e["data"]}
        to_people = set()   # approval ids escalated or revoked so far: only people answer them
        for e in events:
            d = e["data"]
            if e.get("type") in ("approval.escalated", "approval.revoked"):
                to_people.add(d.get("approval_id"))
            if e.get("type") != "approval" or d.get("decision") != "approve":
                continue
            if d.get("approver_kind") != "agent":
                people += 1
                continue
            agents += 1
            where = f"seq {e['seq']}: {str(d.get('approval_id'))[:128]}"
            req = asked.get(d.get("approval_id")) or {}
            dec = decided.get(req.get("decision_id"))
            if dec is None:
                problems.append(f"{where}: its approval.request and policy.decision are not in the run")
                continue
            ai = d.get("approver_identity") or {}
            if (req.get("agent") or {}).get("eligible") is not True:
                problems.append(f"{where}: the signer did not route its approval.request to agents (agent.eligible)")
            if d.get("approval_id") in to_people:
                problems.append(f"{where}: it was escalated or revoked before the agent approved it")
            if dec.get("provenance") or dec.get("provenance_state", "complete") != "complete":
                problems.append(f"{where}: the decision's arguments carry provenance or it is incomplete")
            if req.get("passkey") is True:
                problems.append(f"{where}: a rule of the call needs a passkey")
            if d.get("approver") == req.get("requester") or f"{ai.get('scheme')}:{str(ai.get('subject'))[:256]}" == owner:
                problems.append(f"{where}: the agent is the requester or the run's owner")
            snap = policies.get(dec.get("policy_hash"))
            if snap is None:
                unchecked.append(f"{where}: no policy snapshot of {str(dec.get('policy_hash'))[:80]}; export the run "
                                 "with the signer's config, which bundles the policies its records cite")
                continue
            try:
                pol = loads_strict(snap)
                asks = {r["id"]: r for r in pol.get("ask", [])}
                flags = {r["id"] for r in pol.get("flag", [])}
            except (ValueError, TypeError, KeyError, AttributeError):
                problems.append(f"{where}: the policy snapshot is not a policy")
                continue
            for rid in dec.get("rule_ids") or []:
                approval = (asks.get(rid) or {}).get("approval") or {}
                if rid not in flags and (not isinstance(approval, dict) or "agent" not in approval
                                         or approval.get("passkey") == "required"):
                    problems.append(f"{where}: rule {str(rid)[:64]} does not permit agents")
    if agents:   # a bundle without agent approvals keeps the report it always had
        rep.check("approvals by people", True, f"{people} approval(s) answered by people")
        rep.check("approvals by agents", not problems and not unchecked,
                  f"{agents} approval(s) answered by agents (model output); argument bounds are not checkable offline "
                  "(salted commitments): audit one with `tracekit signer reveal`"
                  + (f"; agent approval bounds unchecked for {len(unchecked)}" if unchecked else ""),
                  (problems or unchecked)[:20], warn=not problems)


def _coverage(matrices, k):
    """One class of the coverage matrix line: its weakest status in `matrices`, with the layers behind it."""
    cs = [m[k] for m in matrices]
    status = min((c["status"] for c in cs), key=COVERED.index)
    layers = sorted({x for c in cs for x in c["layers"]}) + (["asserted"] if any(c.get("asserted") for c in cs) else [])
    return f"{k.replace('_', ' ')} " + ("not covered" if status == "none" else status + (
        f" ({', '.join(layers)})" if layers else ""))


CONTAINMENT = ("incident.opened", "incident.updated", "run.held", "run.quarantined", "run.resumed")
FIRES = ("policy.decision", "approval.consumed", "capture.gap", "trace.tamper", "refusal.summary",
         "reconcile.unexplained_effect")
RECOMPUTED = ("sequence", "limit", "denied_calls", "provenance", "executed_against_policy", "class_mismatch")


def _detector(policies, h, unbundled):
    """A detect.Detector of the bundled compiled policy whose policy_hash is `h`, or None: `h` goes to `unbundled`
    when `policies` lacks it (its incidents stay signer-asserted)."""
    from tracekit.signer import detect
    if h not in policies:
        unbundled.add(str(h)[:80])
        return None
    return detect.Detector(detect.Rules(loads_strict(policies[h])))


def _incidents(rep, runs, policies):
    """The `incidents` line: cited records, incidents recomputed from their run, responses honoured (module
    docstring)."""
    from tracekit.signer import detect
    by_run = {rs[0]["event"].get("run_id"): [r["event"] for r in rs] for rs in runs.values()}
    if not any(e.get("type") in CONTAINMENT for es in by_run.values() for e in es):
        return
    problems, checked, pointers, unbundled = [], 0, set(), set()
    opened = {e["data"]["incident_id"]: e for es in by_run.values() for e in es if e["type"] == "incident.opened"}
    for rid, events in by_run.items():
        mine = []
        for e in events:
            d = e["data"]
            if e["type"] not in ("incident.opened", "incident.updated"):
                continue
            for c in d["cites"]:
                cited = by_run.get(c["run_id"])
                if cited is not None and (c["run_seq"] >= len(cited) or cited[c["run_seq"]]["type"] not in FIRES):
                    problems.append(f"seq {e['seq']}: incident {d['incident_id']} cites {c['run_id'][:128]} run_seq "
                                    f"{c['run_seq']}, which is not a record that fires a trigger")
            if e["type"] == "incident.updated":
                continue
            if d["trigger"] == "detector_unavailable":
                c = d["cites"][0] if len(d["cites"]) == 1 else {}
                cited = by_run.get(c.get("run_id"), [])
                ok = c.get("run_seq", len(cited)) < len(cited) and cited[c["run_seq"]]["type"] == "policy.decision" \
                    and cited[c["run_seq"]]["data"].get("detect", {}).get("state") == "unavailable"
                checked += ok
                if not ok:
                    problems.append(f"seq {e['seq']}: incident {d['incident_id']} (detector_unavailable) cites no "
                                    "decision whose detection state was unavailable")
            elif d["scope"]["kind"] == "run" and d["trigger"] in RECOMPUTED and \
                    all(c["run_id"] == rid for c in d["cites"]):
                mine.append(e)
        hashes = {e["data"].get("policy_hash") for e in events if e["type"] == "policy.decision"}
        det = mine and len(hashes) == 1 and _detector(policies, next(iter(hashes)), unbundled)
        if det:
            st, expected = detect.new(det.engine.policy_hash), []
            for e in events:
                if any(e is x for x in mine):
                    d = e["data"]
                    hit = next((x for x in expected if (x["trigger"], x["rule_ids"], x["cites"], x["mode"]) ==
                                (d["trigger"], d["rule_ids"], d["cites"], d.get("mode"))), None)
                    if hit:
                        expected.remove(hit)
                        checked += 1
                        if hit["mode"] == "enforce" and hit["would"] and not d.get("actions") and "reason" not in d:
                            problems.append(f"seq {e['seq']}: incident {d['incident_id']} ({d['trigger']}) is enforced "
                                            f"under policy {det.engine.policy_hash[:80]} but records no response "
                                            f"({', '.join(hit['would'])}) and no reason")
                    else:
                        problems.append(f"seq {e['seq']}: incident {d['incident_id']} ({d['trigger']}) does not follow "
                                        f"from the run's records under policy {det.engine.policy_hash[:80]}")
                expected += [d for t, d in det.observe(detect.Plain, st, e)[1] if t == "incident.opened"]
        problems += _honoured(events, pointers)
    n = len(opened) + len(pointers - opened.keys())
    rep.check("incidents", not problems, f"{n} incident(s): {checked} checked against the bundle, {n - checked} "
                                         "signer-asserted (operator, cross-run, under several policies, or under "
                                         "a policy not in the bundle)", problems[:20])
    if unbundled:
        rep.check("incident policies", False, f"{len(unbundled)} cited policy(ies) not in the bundle: their incidents "
                  "are signer-asserted, not recomputed (export the run with the signer's config, which bundles the "
                  "policies its records cite)", sorted(unbundled)[:20], warn=True)


def _honoured(events, pointers):
    """The problems of one run's records with the holds and quarantines they record; adds the incident ids of its
    run.held and run.quarantined records to `pointers`."""
    problems, held, quarantined, flight, asked, consumed, due = [], [], None, set(), {}, set(), {}
    for e in events:
        t, d, where = e["type"], e["data"], f"seq {e['seq']}"
        on = quarantined or " and ".join(held)
        if t == "policy.decision" and due and not quarantined:   # an enforced response is written before the next call
            problems += [f"seq {seq}: incident {i} enforces {a} on this run, which no run.held or run.quarantined "
                         "follows" for i, (seq, a) in due.items()]
            due.clear()
        if t == "incident.opened" and d["scope"] == {"kind": "run", "id": e["run_id"][:256]} and \
                {"hold", "quarantine"} & set(d["actions"]):
            due[d["incident_id"]] = (e["seq"], "quarantine" if "quarantine" in d["actions"] else "hold")
        elif t in ("run.held", "run.quarantined"):
            pointers.add(d["incident_id"])
            due.pop(d["incident_id"], None)
            flight |= {x["decision_id"] for x in d.get("in_flight", ())}
            if t == "run.quarantined":
                quarantined, held = d["incident_id"], []
            elif not quarantined and d["incident_id"] not in held:
                held.append(d["incident_id"])
        elif t == "run.resumed":
            held = [i for i in held if i != d["incident_id"]]
            if sorted(d.get("held_by", held)) != sorted(held):
                problems.append(f"{where}: run.resumed says {' and '.join(d['held_by']) or 'no incident'} still "
                                f"holds the run, its records {' and '.join(held) or 'none'}")
        elif t == "policy.decision" and on and (d["decision"] != "deny" if quarantined else d["decision"] != "deny" and (
                d["decision"] != "ask" or d.get("incident_id") not in held)):
            problems.append(f"{where}: {d['decision']} while the run is {'quarantined' if quarantined else 'held'} by "
                            f"incident {on}")
        elif t == "approval.request":
            asked[d["approval_id"]] = d.get("incident_id")
            if quarantined or held and d.get("incident_id") not in held:
                problems.append(f"{where}: an approval asked while the run is {'quarantined' if quarantined else 'held'}"
                                f" by incident {on}, not as its held call")
        elif t == "approval" and asked.get(d.get("approval_id")) and d["decision"] == "approve" and (
                d.get("approver_kind") == "agent" or d.get("self_approved") or "person" not in d and
                "person" not in d.get("approver_identity", {}) or d.get("incident_id") != asked[d["approval_id"]]):
            problems.append(f"{where}: a held call approved by other than a person, or without its incident id")
        elif t == "approval.consumed":
            if quarantined or held and asked.get(d["approval_id"]) not in held:
                problems.append(f"{where}: an approval consumed while the run is "
                                f"{'quarantined' if quarantined else 'held'} by incident {on}")
            elif asked.get(d["approval_id"]):
                consumed.add(e.get("tool_call_id"))
        elif t == "tool.result" and on and d.get("decision_id") not in flight and (
                quarantined or e.get("tool_call_id") not in consumed):
            problems.append(f"{where}: a result while the run is {'quarantined' if quarantined else 'held'} by incident "
                            f"{on}, of a call neither in flight then nor approved by a person for it")
    if not quarantined:
        problems += [f"seq {seq}: incident {i} enforces {a} on this run, which no run.held or run.quarantined follows"
                     for i, (seq, a) in due.items()]
    return problems


def _parted(run, names, pieces):
    """What is wrong with the parts of `run` (bundle_v2.run_files): `names`, its files in order, and `pieces`, their
    records. A run in one file has none; one in parts has part-0001 to part-n and no other file, each holding records,
    each one's first record the successor of the last of the part before it."""
    if names == [run]:
        return []
    stem, digits = run[:-len(".jsonl")], {n: PART.fullmatch(n)[2] for n in names if n != run}
    numbered = {int(d) for d in digits.values() if len(d) == 4 and d != "0000"}
    gaps = [i for i in range(1, max(numbered, default=0)) if i not in numbered]
    held = [(n, p) for n, p in zip(names, pieces) if p]
    return ([f"{run} and {names[1]}: one run in one file and in parts"] if run in names else []) \
        + [f"{n}: not a part's name (part-0001, part-0002, ...)" for n, d in digits.items()
           if len(d) != 4 or d == "0000"] \
        + ([f"{stem}.part-{gaps[0]:04d}.jsonl is missing" + (f", and {len(gaps) - 1} more part(s)" if gaps[1:] else "")]
           if gaps else []) \
        + [f"{n} holds no records" for n, p in zip(names, pieces) if not p] \
        + [f"{b} does not continue {a}" for (a, x), (b, y) in zip(held, held[1:])
           if y[0]["event"].get("run_prev_hash") != x[-1]["hash"]]


def _about(records):
    """(analyzes, replay_of, investigation) of a run's run.registered (Nones when it is not one)."""
    d = records[0]["event"].get("data") if records[0]["event"].get("type") == "run.registered" else None
    return tuple((d or {}).get(k) for k in ("analyzes", "replay_of", "investigation"))


def _about_one(runs):
    """Whether every run but one of the same tenant is a findings or replay run of that one."""
    main = [rs for rs in runs.values() if _about(rs)[:2] == (None, None)]
    if len(main) != 1:
        return False
    head = main[0][0]["event"]
    return all(rs is main[0] or (rs[0]["event"].get("tenant") == head.get("tenant")
                                 and head.get("run_id") in _about(rs)[:2]) for rs in runs.values())


def _exchanges(records):
    """The tool-use names of each response of a replay run's model calls, when every one is a gateway record and they
    pair up (as many requests as responses, at least one); else None."""
    ex = [r["event"] for r in records if r["event"].get("type") == "model.exchange"]
    phases = [e["data"].get("phase") for e in ex]
    if not ex or any(e.get("source") != "gateway" for e in ex) or phases.count("request") != phases.count("response"):
        return None
    return [[str(t.get("name")) for t in e["data"].get("tool_uses", ())] for e in ex if e["data"].get("phase") == "response"]


def _finding(f, where, about, analyzes, runs_by_id):
    """The problems of one why.finding whose replay runs are all in the bundle."""
    from tracekit.why.replay import clauses, holds, newcombe_diff, verdict_for, z_for
    problems, cited = [], [x["run_id"] for x in f["replay_runs"]] + [x["run_id"] for x in f.get("uncounted", ())]
    if len(set(cited)) != len(cited):
        problems.append(f"{where}: cites a replay run more than once")
    try:
        conds = clauses(f["target"])
    except ValueError:
        conds = []
        problems.append(f"{where}: its target is not a tracekit why target")
    tools = [(op, v) for k, op, v in conds if k == "tool"]
    only_tools = bool(conds) and len(tools) == len(conds)
    arms = {"control": [], "ablated": []}
    for x in [*f["replay_runs"], *f.get("uncounted", ())]:
        rid = x["run_id"][:128]
        if about.get(x["run_id"]) != (None, analyzes, f["investigation"]):
            problems.append(f"{where}: replay run {rid} is not in the bundle as a replay run of {str(analyzes)[:128]} "
                            f"in investigation {f['investigation'][:128]}")
            continue
        names = _exchanges(runs_by_id[x["run_id"]])
        one = f["rung"] == 1 or x.get("reason") == "ranking"
        if names is None or one and len(names) != 1:
            problems.append(f"{where}: replay run {rid} does not hold {'one' if one else 'its'} model call as gateway "
                            "model.exchange request and response records")
            continue
        if "reason" in x:
            if x["reason"] == "budget" and f["stopped"] != "budget":
                problems.append(f"{where}: leaves replay run {rid} uncounted for a budget stop it does not report")
            continue
        arms[x["arm"]].append(x["hit"])
        seen = tools and any(all(holds(op, name, v) for op, v in tools) for ns in names for name in ns)
        if tools and x["hit"] and not seen or only_tools and not x["hit"] and seen:
            problems.append(f"{where}: replay run {rid} is scored a {'hit' if x['hit'] else 'miss'}, but its gateway "
                            f"records {'hold no' if x['hit'] else 'hold a'} tool use the target names")
    n, (c, a) = f["n"], arms.values()
    p = [sum(h) / n if n else 0.0 for h in (c, a)]
    if (len(c), len(a)) != (n, n) or [round(x, 4) for x in p] != [f["p_with"], f["p_without"]] \
            or round(p[0] - p[1], 4) != f["effect"]:
        problems.append(f"{where}: its replay runs count {sum(c)}/{len(c)} with and {sum(a)}/{len(a)} without, not the "
                        f"n={n}, {f['p_with']} and {f['p_without']} (effect {f['effect']}) it reports")
        return problems
    lo, hi = newcombe_diff(sum(c), n, sum(a), n, z_for(f["looks"] * f["family"])) if n else (-1.0, 1.0)
    verdict = "inconclusive" if f["stopped"] == "budget" else verdict_for(lo, hi, f["applied"], f["min_effect"])
    if not f["interval"][0] <= f["interval"][1] or f["interval"] != [round(lo, 4), round(hi, 4)] \
            or f["verdict"] != verdict:
        problems.append(f"{where}: its outcomes give the interval [{lo:.4f}, {hi:.4f}] and the verdict {verdict}, not "
                        f"the {f['interval']} and {f['verdict']} it reports")
    return problems


def _findings(rep, runs):
    """The `findings` line: each why.finding's replay runs are bundled, are distinct replay runs of the run its
    findings run analyses in its investigation, each holding its model calls as gateway records (one for rung 1), a
    `tool` target's outcomes agree with the tool uses those records name, and the outcomes count to its n, rates and
    effect and give its interval and verdict; every replay run of an investigation with findings is counted by one,
    or listed as uncounted (the ranking's calls, arms of a budget stop). Outside a findings bundle (one run with its
    findings and replay runs) a finding whose replay runs are absent is a warning: not counted, not failed."""
    by_id = {rs[0]["event"].get("run_id"): rs for rs in runs.values()}
    about = {rid: _about(rs) for rid, rs in by_id.items()}
    complete = _about_one(runs)
    found, problems, uncounted, named, investigations = 0, [], [], set(), set()
    for rs in runs.values():
        analyzes = _about(rs)[0]
        for r in rs:
            if r["event"].get("type") != "why.finding":
                continue
            found, f, where = found + 1, r["event"]["data"], f"seq {r['event']['seq']}"
            ids = {x["run_id"] for x in [*f["replay_runs"], *f.get("uncounted", ())]}
            if not complete and not ids <= about.keys():
                uncounted.append(f"{where}: its replay runs are not in the bundle")
                continue
            named |= ids
            investigations.add(f["investigation"])
            problems += _finding(f, where, about, analyzes, by_id)
    stray = sorted(rid for rid, a in about.items() if a[1] is not None and rid not in named) if complete else []
    problems += [f"replay run {rid[:128]} of investigation {str(about[rid][2])[:128]} is counted by no finding" for rid in stray
                 if about[rid][2] in investigations]
    if found > len(uncounted):
        rep.check("findings", not problems, f"{found - len(uncounted)} tracekit why finding(s), each counted from its "
                  "replay runs", problems[:20])
    if uncounted:
        rep.check("findings counted", False, f"{len(uncounted)} finding(s) not counted: export the analysed run with "
                  "`tracekit export --v2 --run <run> --with-findings` to count them", uncounted[:20], warn=True)
    orphans = [rid for rid in stray if about[rid][2] not in investigations]
    if orphans:
        rep.check("replay runs", False, f"{len(orphans)} replay run(s) of investigations with no finding in the bundle",
                  [rid[:128] for rid in orphans[:20]], warn=True)


def _seq_hashes(records):
    """{run_seq: record hash} of a run's records."""
    return {r["event"].get("run_seq"): r["hash"] for r in records}


def _author(records):
    """('scheme:subject', signer_isolation) of a run's run.registered (Nones when it is not one)."""
    e = records[0]["event"]
    d = e.get("data") if e.get("type") == "run.registered" else {}
    i = d.get("identity")
    return (f"{i['scheme']}:{i['subject']}" if i else None), d.get("signer_isolation")


def _label(records, target, pinned):
    """(the author label of findings run `records` about run `target`, why it is self-asserted or None) (module
    docstring: Signed findings). `pinned`: the trust config's `analyzers`."""
    (author, isolation), (theirs, their_isolation) = _author(records), _author(target)
    if author == theirs or "same-user" in (isolation, their_isolation):
        return "self-asserted", (f"its author {str(author)[:256]} is the analysed run's identity" if author == theirs
                                 else "the signer runs as the same user as a client (signer_isolation same-user)")
    return ("independent" if author in pinned else f"unpinned author {str(author)[:256]}"), None


def _verdict(v):
    """What is wrong with a signed finding's verdict `v` (VERDICT; its asserted model, families and window), or None."""
    if not isinstance(v, dict) or not isinstance(v.get("rule"), str) or not _RULE.fullmatch(v["rule"]) or any(
            v.get(k) not in VERDICT[k] for k in ("kind", "severity")):
        return "its verdict has no kind, rule and severity of a signed finding"
    a, f, w = v.get("asserted"), v.get("families"), v.get("window")
    fams = (*rpc_schema.MODEL_FAMILIES, None)
    bad = [k for k, allowed in VERDICT.items() if k in v and v[k] not in allowed] + [k for k, ok in (
        ("asserted", isinstance(a, dict) and all(isinstance(a.get(x), str) and _MODEL.fullmatch(a[x]) for x in (
            "model", "version")) and isinstance(a.get("prompt_hash"), str) and _DIGEST.fullmatch(a["prompt_hash"])),
        ("families", isinstance(f, dict) and f.get("reviewer") in fams and isinstance(f.get("agent"), list)
         and all(x in fams[:-1] for x in f["agent"])),
        ("window", isinstance(w, dict) and all(type(w.get(x)) in (int, float) and w[x] >= 0
                                               for x in ("grace_s", "skew_s")))) if k in v and not ok]
    return f"its verdict's {', '.join(bad)} is not what a signed finding holds" if bad else None


def _reviews(rep, runs, pinned):
    """The `reviews` line, and `reviews counted` for signed findings whose analysed run is not in the bundle (module
    docstring: Signed findings). `pinned`: the trust config's `analyzers`."""
    by_id = {rs[0]["event"].get("run_id"): rs for rs in runs.values()}
    total, labels, problems, selfs, uncounted = 0, collections.Counter(), [], [], []
    hashes_of = {}   # analysed run id -> {run_seq: record hash}, built once however many findings runs cite it
    for rs in runs.values():
        reviews = [r["event"] for r in rs if r["event"].get("type") == "review"]
        signed = [e for e in reviews if "cites" in e["data"]]
        total, labels["imported"] = total + len(reviews), labels["imported"] + len(reviews) - len(signed)
        if not signed:
            continue
        problems += [f"seq {e['seq']}: {why}" for e in signed for why in [_verdict(e["data"]["verdict"])] if why]
        rid, analyzes = str(rs[0]["event"].get("run_id"))[:128], _about(rs)[0]
        if analyzes is None:
            problems += [f"seq {e['seq']}: a signed finding outside a findings run" for e in signed]
            continue
        target = by_id.get(analyzes)
        if target is None:
            labels["author not checked"] += len(signed)
            uncounted.append(f"findings run {rid}: run {str(analyzes)[:128]} is not in the bundle")
            continue
        if analyzes not in hashes_of:
            hashes_of[analyzes] = _seq_hashes(target)
        hashes = hashes_of[analyzes]
        # a run_seq of a schema-invalid cite that is no number names no record (as in JavaScript's Map)
        cited = [(e, c, hashes.get(c["run_seq"]) if type(c["run_seq"]) in (int, float) else None)
                 for e in signed for c in e["data"]["cites"]]
        problems += [f"seq {e['seq']}: cites run_seq {c['run_seq']} of run {str(analyzes)[:128]}, "
                     + ("which it does not have" if h is None else "whose hash differs")
                     for e, c, h in cited if h != c["hash"]]
        label, reason = _label(rs, target, pinned)
        if reason:
            selfs.append(f"findings run {rid}: {reason}")
        labels[label] += len(signed)
    if total:
        rep.check("reviews", not problems and not selfs, f"{total} review(s): " + ", ".join(
            f"{n} {k}" for k, n in sorted(labels.items()) if n), (problems or selfs)[:20], warn=not problems)
        verdicts = [r["event"]["data"].get("verdict") for rs in runs.values() for r in rs   # signed findings only: an
                    if r["event"].get("type") == "review" and "cites" in r["event"]["data"]]   # imported one is a label
        sev = collections.Counter(str(v.get("severity"))[:16] for v in verdicts
                                  if isinstance(v, dict) and v.get("kind") == "finding")
        cov = sum(isinstance(v, dict) and v.get("kind") == "coverage" for v in verdicts)
        rep.findings = (f"{sum(sev.values())} finding(s)" + (" (" + ", ".join(
            f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) + ")" if sev else "")
            + (f" and {cov} coverage review(s)" if cov else "") + "; " + ", ".join(
                f"{n} {k}" for k, n in sorted(labels.items()) if n) + " (an opinion of the run, not its integrity)")
    if uncounted:
        rep.check("reviews counted", False, f"{labels['author not checked']} signed finding(s) not counted: export the "
                  "analysed run with `tracekit export --v2 --run <run> --with-findings` to check their citations",
                  uncounted[:20], warn=True)


def _constraints(rep, runs):
    """The `constraints` line: live constraints added, and the calls they held, each after one in its run (module
    docstring: Live constraints)."""
    added, held, problems = 0, 0, []
    for rs in runs.values():
        seen = False
        for r in rs:
            e = r["event"]
            if e.get("type") == "constraint.added":
                added, seen = added + 1, True
            elif e.get("type") == "policy.decision" and isinstance(e["data"].get("rule_ids"), list) \
                    and "TK-CONSTRAINT" in e["data"]["rule_ids"]:   # a schema-invalid string is no list of ids
                held += 1
                if not seen or e["data"].get("decision") != "ask":
                    problems.append(f"seq {e['seq']}: a {str(e['data'].get('decision'))[:16]} held by TK-CONSTRAINT "
                                    + ("before any constraint.added in its run" if not seen else "is no ask"))
    if added or held:
        rep.check("constraints", not problems, f"{added} live constraint(s) added; {held} call(s) held by them",
                  problems[:20])


def _run_set(rep, files, trust, witnesses, origin, size, runs, included, check_record):
    """The run-set line (COMPLETE or INCOMPLETE) and the log tail line. Returns the (seq, hash) of every key.retire
    the registry range points to, the highest seq the range points to when it starts at registry size 0 (else -1):
    every key.retire up to there is in the range, and the pinned cosignatures of each registry note."""
    rs, problems = loads_strict(files["registry/run-set.json"]), []
    tsalt = base64.b64decode(rs["tenant_salt"], validate=True)
    lo, hi, reg_origin = rs["from"], rs["to"], registry.origin(origin, tsalt)
    span = f"registry {lo}..{hi}"
    if type(lo) is not int or type(hi) is not int:
        rep.check("run-set", False, f"INCOMPLETE, {span}", ["the registry range is not two integers"])
        return [], -1, []
    # the registry notes are signed by the record log's own pinned key, under the registry origin
    vkeys = [checkpoint.vkey(reg_origin, *checkpoint.parse_vkey(k)[2:]) for k in trust["logs"]
             if checkpoint.parse_vkey(k)[0] == origin]
    roots, reg_cosigs = {}, []
    for n in sorted({lo, hi} - {0}):
        try:
            _, n2, roots[n], c = checkpoint.open_note(files[f"checkpoints/registry-{n}.note"], vkeys, list(witnesses))
            reg_cosigs.append(c)
            if len(c) < trust["witnesses_required"]:
                problems.append(f"registry checkpoint at size {n}: {len(c)} pinned cosignature(s), "
                                f"{trust['witnesses_required']} required")
        except (checkpoint.NoteError, KeyError) as e:
            n2 = f"unusable ({type(e).__name__}: {e})"
        if n2 != n:
            problems.append(f"registry checkpoint at size {n}: {n2}")
    if problems or not 0 <= lo <= hi or hi == 0:
        rep.check("run-set", False, f"INCOMPLETE, {span}", problems or [f"bad registry range {lo}..{hi}"])
        return [], -1, reg_cosigs
    if 0 < lo < hi and not verify_consistency(lo, hi, roots[lo], roots[hi], [
            base64.b64decode(p, validate=True) for p in rs["consistency"]]):
        problems.append(f"registry checkpoint {lo} is not a prefix of {hi}")
    leaves, pointed = rs["leaves"], {r["event"]["seq"]: r for r in _jsonl(files["registry/records.jsonl"])}
    if len(leaves) != hi - lo:
        problems.append(f"{hi - lo} leaves in {lo}..{hi}, {len(leaves)} in the bundle: a leaf is missing")
    registered, finals, retired, closed, tenant, targets, top, gaps = {}, {}, [], None, None, set(), -1, {}
    for i, x in enumerate(leaves[:hi - lo], lo):
        leaf = base64.b64decode(x["leaf"], validate=True)
        if not verify_inclusion(i, hi, leaf_hash(leaf), [base64.b64decode(p, validate=True) for p in x["inclusion"]],
                                roots.get(hi)):
            problems.append(f"leaf {i} is not in the registry tree of size {hi}")
            continue
        typ, run_hash, log_id, seq, h = registry.parse(leaf)
        r = pointed.get(seq)
        e = r and r["event"]
        if (r is None or r["hash"] != h or e["type"] != typ or e["log_id"] != log_id or not included(r)
                or registry.run_hash(tsalt, e["run_id"]) != run_hash
                or typ not in registry.SIGNER_LEAVES and tenant not in (None, e["tenant"])):
            problems.append(f"leaf {i} points to a missing or different record (seq {seq})")
            continue
        check_record(r, problems)
        top = max(top, seq)
        if typ in ("run.registered", "run.final"):
            targets.add(run_name(e["tenant"], e["run_id"]))
        if typ == "run.registered":
            tenant, registered[e["run_id"]] = e["tenant"], r
        elif typ == "run.final":
            tenant = e["tenant"]
            if e["run_id"] in finals:
                problems.append(f"a second run.final for run {e['run_id'][:200]!r} (seq {seq})")
            finals[e["run_id"]] = r
        elif typ == "key.retire":
            retired.append((seq, h))
        elif typ == "log.closed":
            closed = e
        else:
            gaps[e["data"]["kind"]] = gaps.get(e["data"]["kind"], 0) + 1
    for run_id, final in finals.items():
        recs = runs.get(run_name(tenant, run_id))
        if (not recs or recs[-1]["hash"] != final["hash"]
                or run_id in registered and recs[0]["hash"] != registered[run_id]["hash"]):
            problems.append(f"run {run_id[:200]!r} is final in the range but its records are not in the bundle")
    if any(rs[0]["event"].get("tenant") != tenant for rs in runs.values()):
        problems.append("a run in the bundle is not of the run-set's tenant")
    if len(set(runs) - targets) > 1:
        problems.append(f"{len(set(runs) - targets)} runs in the bundle, but only the selected run may be in no leaf "
                        "of the range")
    if closed and size > closed["data"]["final_seq"] + 1:
        problems.append(f"records after log.closed at seq {closed['seq']}")
    counted = ", ".join(f"{k} {n}" for k, n in sorted(gaps.items()))
    named = "" if tenant is None else f" of tenant {tenant[:64]!r}"
    rep.check("run-set", not problems, f"COMPLETE, {span}{named} ({len(registered)} runs registered, {len(finals)} "
                                       f"final, {len(set(registered) - set(finals))} open"
                                       + (f"; tenant-level gaps: {counted}" if gaps else "") + ")" if not problems else
              f"INCOMPLETE, {span}", problems)
    if gaps:
        rep.check("tenant-level gaps", False, f"{sum(gaps.values())} in the range: {counted}", warn=True)
    rep.check("log tail", bool(closed), f"none: log.closed at seq {closed['seq']} is the last record" if closed else
              f"records after tree size {size} are unproven (no log.closed in the range)", warn=True)
    return retired, top if lo == 0 else -1, reg_cosigs


def _bridge(rep, key_records, v1_ledger, v1_key):
    bridges = [r["event"] for r in key_records if r["event"]["type"] == "signer.epoch" and "bridge" in r["event"]["data"]]
    b = bridges[0]["data"]["bridge"] if bridges else None
    if v1_ledger is None:
        if b:
            rep.notes.append(f"this log continues the v1 ledger of key {b['v1_kid']}; pass the v1 ledger and its "
                             "signer.pub to check the format bridge")
        return
    if b is None or bridges[0]["seq"] != 0 or len(bridges) > 1:
        rep.check("format bridge", False, "", ["the log does not start with one signer.epoch that bridges a v1 ledger"])
        return
    pub, kid = _load_trusted_key(v1_key)
    problems = [] if kid == b["v1_kid"] else [f"the v1 key is {kid}, the bridge retires {b['v1_kid']}"]
    prev, expect, last = GENESIS, 0, None   # last: (seq, hash, data) of the last v1 record up to the bridge
    for _, r, _ in read_records(v1_ledger):
        if not isinstance(r, dict):
            continue   # a torn line the v1 ledger set aside
        e = r.get("event") or {}
        seq = r.get("seq") if r.get("elided") else e.get("seq")
        if not isinstance(seq, int) or seq > b["v1_last_seq"]:
            problems.append(f"seq {seq!r}: v1 record after format bridge")
            continue
        if not r.get("elided"):
            if v1_event_hash(e) != r.get("hash"):
                problems.append(f"v1 seq {seq}: hash mismatch")
            problems.extend(f"v1 seq {seq}: {x}" for x in validate(e))
        if seq != expect or (r.get("prev_hash") if r.get("elided") else e.get("prev_hash")) != prev:
            problems.append(f"v1 seq {seq}: does not continue the chain")
        if r.get("kid") != b["v1_kid"] or not verify_record_sig(r, pub):
            problems.append(f"v1 seq {seq}: signature invalid")
        prev, expect, last = r.get("hash"), seq + 1, (seq, r.get("hash"), e.get("data"))
    if last != (b["v1_last_seq"], b["v1_head"], retire_data(b["v1_kid"], b["v1_last_seq"])):
        problems.append(f"the v1 ledger does not end at seq {b['v1_last_seq']} in the bridge's key retirement")
    rep.check("format bridge", not problems, f"v1 ledger of {b['v1_kid']} verifies to seq {b['v1_last_seq']} and ends "
                                             "in its key retirement", problems[:20])


def _anchor(rep, files, trust, note, origin, size):
    """[(Rekor log, class, time)] of the checkpoint's anchor, checked when the trust config pins Rekor."""
    pinned, tle = trust.get("rekor"), files.get(f"rekor/{size}.json")
    if not pinned or tle is None:
        return []
    from tracekit.anchor import rekor2
    from tracekit.tlog_witness import log_signed
    try:
        signed = []
        for k in trust["logs"]:
            if checkpoint.parse_vkey(k)[0::2] == (origin, checkpoint.ED25519):
                try:
                    signed.append(log_signed(note.decode("utf-8"), k).encode("utf-8"))
                except ValueError:   # another pinned key of the origin
                    pass
        at, log = rekor2.verify({"rekor": loads_strict(tle), "tsa": base64.b64encode(files.get(f"tsa/{size}.tsr", b""))
                                 .decode("ascii")}, signed[0], base64.b64decode(pinned["publishing_key"]),
                                pinned["trusted_root"])
    except (ValueError, IndexError) as e:
        rep.check("rekor anchor", False, f"{type(e).__name__}: {e}")
        return []
    rep.check("rekor anchor", True, f"checkpoint in {log}, timestamped {at:%Y-%m-%dT%H:%M:%SZ} by a pinned TSA")
    return [(log, pinned["class"], at)]


def _monitor(rep, trust, paths, origin, size, root):
    """[(monitor name, class, report time)] of the reports in `paths` by pinned monitors that make the checkpoint
    monitored: fresh, of its origin, checked to its size, without conflicts."""
    from tracekit.monitor import open_report
    pinned, out, now = {m["vkey"]: m for m in trust["monitors"]}, [], datetime.datetime.now(datetime.timezone.utc)
    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_ENTRY)
        except OSError as e:
            rep.check("monitor", False, f"{type(e).__name__}: {e}", warn=True)
            continue
        found = None
        for k in pinned:
            try:
                found = k, open_report(data, k)
                break
            except ValueError:
                pass
        if found is None:
            rep.check("monitor", False, f"{path}: not a report of a pinned monitor (ignored)", warn=True)
            continue
        (k, r), name = found, found[0].split("+")[0]
        if r["origin"] != origin:
            rep.check("monitor", False, f"{name}: a report for {r['origin'][:200]!r}, not {origin} (ignored)", warn=True)
        elif r["conflicts"] or (r["checked_size"] == size and r["checked_root"] != base64.b64encode(root).decode()):
            rep.check("monitor", False, f"{name} ({pinned[k]['class']}) reports conflicts for {origin}",
                      [f"{str(c.get('rule'))[:100]}: {c['detail'][:300]}" for c in r["conflicts"]][:20]
                      or [f"another root at tree size {size}"])
        else:
            try:
                at = datetime.datetime.strptime(r["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                at = None
            if at is None or abs((now - at).total_seconds()) > pinned[k]["max_age_s"]:
                rep.check("monitor", False, f"{name}: the report of {r['time'][:40]!r} is not fresh (ignored)", warn=True)
            # lean: a report past the checkpoint's size is taken without a consistency proof between the two roots (only
            # equal sizes are compared); carry one in the report if a monitored split view must show at any size
            elif r["checked_size"] < size:
                rep.check("monitor", False, f"{name}: checked to size {r['checked_size']}, the checkpoint is of size "
                                            f"{size} (ignored)", warn=True)
            else:
                rep.check("monitor", True, f"{name} ({pinned[k]['class']}) checked {origin} to size {r['checked_size']}"
                                           f" at {r['time']}: no conflicts")
                out.append((name, pinned[k]["class"], r["time"]))
    return out


def _level(cosigs, witnesses, trust, anchors=()):
    independent = [k for k, _ in cosigs if witnesses[k] != "operator"] + [a for a in anchors if a[1] != "operator"]
    return ("witnessed" if len(independent) >= max(1, trust["witnesses_required"])
            else "local" if cosigs or anchors else "dev")


def _assurance(origin, cosigs, witnesses, trust, algs, self_approved=False, anchors=(), monitored=(),
               registry_notes=()):
    """dev: no pinned witness cosigned or anchor verified, or a self-approval in the run; local: only operator-run
    ones; witnessed: enough independent ones (a pinned Rekor anchor counts as one, unless classed operator);
    witnessed+monitored: witnessed, and a pinned monitor's (not classed operator) fresh report covers the checkpoint.
    A run-set's registry notes (`registry_notes`: the cosignatures of each) cap the level by the same rule."""
    hybrid = any(checkpoint.parse_vkey(k)[0::2] == (origin, checkpoint.HYBRID) for k in trust["logs"])
    times = [datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) for k, ts in cosigs if witnesses[k] != "operator"]
    times += [at for _, cls, at in anchors if cls != "operator"]
    order = ("dev", "local", "witnessed")
    level = "dev" if self_approved else _level(cosigs, witnesses, trust, anchors)
    capped = min((_level(c, witnesses, trust) for c in registry_notes), key=order.index, default="witnessed")
    if order.index(capped) < order.index(level):
        level = capped
    else:
        capped = None
    if level == "witnessed" and any(cls != "operator" for _, cls, _ in monitored):
        level = "witnessed+monitored"
    cosigned = ", ".join(f"{k.split('+')[0]} ({witnesses[k]}) at "
                        f"{datetime.datetime.fromtimestamp(ts, datetime.timezone.utc):%Y-%m-%dT%H:%M:%SZ}"
                        for k, ts in sorted(cosigs, key=lambda c: c[1]))
    return (f"{level}; records {'+'.join(sorted(algs))}; checkpoint "
            f"{'Ed25519 + SLH-DSA-SHA2-128s' if hybrid else 'Ed25519 only'} ({origin})"
            + (f"; cosigned ed25519 by {cosigned}" if cosigned else "; no witness cosignature")
            + "".join(f"; anchored in Rekor {log} ({cls}) at {at:%Y-%m-%dT%H:%M:%SZ} (ECDSA P-256 entry, RFC 3161 time)"
                      for log, cls, at in anchors)
            + (f"; earliest independent anchor {min(times):%Y-%m-%dT%H:%M:%SZ}" if times else "")
            + "".join(f"; monitored by {name} ({cls}) at {at}" for name, cls, at in monitored)
            + (f"; capped by the run-set's registry notes ({capped})" if capped else "")
            + ("; approvals: self" if self_approved else ""))


def print_report(rep, code, stream=None):
    """The report as text; control and bidirectional format characters in bundle-derived strings are dropped, so they
    reach no terminal and can't reorder the signer's words around them."""
    s, clean = stream or sys.stdout, lambda x: _CONTROL.sub("", str(x))
    for c in rep.checks:
        s.write(f"[{c['status'].upper()}] {c['check']}" + (f" — {clean(c['detail'])}" if c["detail"] else "") + "\n")
        for p in c["problems"]:
            s.write(f"        {clean(p)}\n")
    s.write(f"\nIntegrity: {clean(rep.integrity)}.\nAssurance: {clean(rep.assurance)}.\n"
            + (f"Findings: {clean(rep.findings)}.\n" if getattr(rep, "findings", None) else ""))
