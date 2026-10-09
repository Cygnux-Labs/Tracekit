"""Verifier for `tracekit.bundle.v2` (see `tracekit.bundle_v2` for the layout).

Trust comes only from the verifier's own pinned config (JSON):

    {"logs": ["<log vkey>", ...],                         Ed25519 (0x01) log keys; the key name is the origin
     "witnesses": [{"vkey": "<cosigner vkey>", "class": "public|customer|tracekit|operator"}, ...],
     "algs": ["ed25519"],                                 record signature algorithms accepted
     "witnesses_required": 0}                             pinned cosignatures a checkpoint must carry

Integrity VERIFIED needs: a checkpoint note signed by the pinned log key of its origin (and cosigned by the required
number of pinned witnesses); every record signed with an allowed algorithm by a key that the log declared in a
signer.epoch record before it and had not retired (key.retire) by then; schema-valid events; one run's chain, contiguous
from run_seq 0 to a run.final record; the run's first and last records and every key record included in the
checkpointed tree. A run without run.final verifies only to its head. The bundle's manifest is an index, never trusted.
A run with any self-approval (dev mode: the approver was the requester) is reported `approvals: self`, assurance dev.
Approvals answered under the break-glass role are listed, as a warning.
A tool call that ran against a deny, or an ask with no consumed approval, is signed by the signer as a capture.gap
`executed_against_policy`; each is a `policy` warning.

Run-set (a bundle with registry/run-set.json): the tenant's registry notes, signed by the pinned log key under the
origin `<origin>/registry/<id of the bundle's tenant salt>`, and consistent with each other; every leaf of the range
present and in the registry tree; each pointing to a record of the checkpointed tree with that hash, seq, type and
H(tenant_salt ‖ run_id); one run.final per run; every run final in the range in the bundle from its run.registered (when
in the range) to that run.final; every bundled run but the selected one the target of a leaf in the range; a range ending
above size 0. Anything else is `run-set: INCOMPLETE` (FAILED). Every key.retire leaf in the range must be among the key
records, so a withheld retirement fails `keys`; without a range from size 0 that reaches every bundled record, that is
unproven (a `keys` warning and an assurance note). The log tail after the checkpoint is reported
unproven (a warning) unless a log.closed in the range is the checkpoint's last record.

Format bridge (04-design §1.9): when the log's first record, signer.epoch, has `bridge`, the v1 ledger it continues can
be checked too (verify(..., v1_ledger, v1_key)): its chain verifies by v1 rules up to `v1_last_seq`, that last record
has hash `v1_head` and is the retirement of key `v1_kid`, and no v1 record follows it. The frozen v1 verifier sees the
bridge's two records as ordinary signer capture.gap events (a `capture gaps` warning) and cannot tell a v1 record
appended after them with a copy of the retired key from any other: only this check reports it."""
import base64
import datetime
import hashlib
import re
import sys
import zipfile

from tracekit import __version__, crypto
from tracekit.bundle import EXIT_BAD, EXIT_FAIL, EXIT_OK, Report, _load_trusted_key
from tracekit.bundle_v2 import FORMAT, KEY_TYPES, run_name
from tracekit.core import GENESIS
from tracekit.core import event_hash as v1_event_hash
from tracekit.format import checkpoint, registry
from tracekit.format.canon import loads_strict
from tracekit.format.records import RecordError, verify_record
from tracekit.ledger import read_records, verify_record_sig
from tracekit.merkle import leaf_hash, verify_consistency, verify_inclusion
from tracekit.schema import V2, validate
from tracekit.signer.format_bridge import retire_data
from tracekit.storage.base import ZERO_HASH

MAX_ENTRIES = 10_000
MAX_ENTRY = 64 << 20
MAX_TOTAL = 512 << 20
MAX_LINE = 1 << 20
CLASSES = ("public", "customer", "tracekit", "operator")
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*")
_VERSION = re.compile(r"\d{1,9}(\.\d{1,9}){0,2}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class Unusable(ValueError):
    pass


def read_zip(path):
    """{name: bytes} of a zip, read entry by entry under count and size caps. Refuses names that could escape a
    directory, symlinks and duplicate entries."""
    files, total = {}, 0
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise Unusable("too many entries")
        for i in infos:
            n = i.filename
            if not _NAME.fullmatch(n) or any(set(p) == {"."} for p in n.split("/")):
                raise Unusable(f"bad entry name {n[:80]!r}")
            if n in files:
                raise Unusable(f"duplicate entry {n}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise Unusable(f"symlink entry {n}")
            cap = min(MAX_ENTRY, MAX_TOTAL - total)
            with z.open(i) as f:
                data = f.read(cap + 1)
            if len(data) > cap:
                raise Unusable(f"{n} is larger than the bundle limits")
            files[n], total = data, total + len(data)
    return files


def load_trust(path):
    with open(path, "rb") as f:
        t = loads_strict(f.read(MAX_LINE))
    ok = (isinstance(t, dict) and set(t) <= {"logs", "witnesses", "algs", "witnesses_required"}
          and isinstance(t.get("logs"), list) and t["logs"] and all(isinstance(k, str) for k in t["logs"])
          and isinstance(t.get("witnesses", []), list)
          and all(isinstance(w, dict) and set(w) == {"vkey", "class"} and isinstance(w["vkey"], str)
                  and w["class"] in CLASSES for w in t.get("witnesses", []))
          and isinstance(t.get("algs"), list) and t["algs"] and all(isinstance(a, str) for a in t["algs"])
          and type(t.get("witnesses_required", 0)) is int and t.get("witnesses_required", 0) >= 0)
    if not ok:
        raise ValueError(f"{path}: not a v2 trust config (logs, witnesses, algs, witnesses_required)")
    for k in t["logs"] + [w["vkey"] for w in t.get("witnesses", [])]:
        checkpoint.parse_vkey(k)
    return {"witnesses": [], "witnesses_required": 0, **t}


def _jsonl(data):
    if data and not data.endswith(b"\n"):
        raise ValueError("a JSON lines file must end in a newline")
    lines = data.split(b"\n")[:-1]
    if any(len(line) > MAX_LINE for line in lines):
        raise ValueError("line longer than the bundle limits")
    return [loads_strict(line) for line in lines]


def _version(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def verify(path, trust_path, v1_ledger=None, v1_key=None):
    """Verify a v2 bundle against the pinned trust config at `trust_path`, and with `v1_ledger` (a v1 ledger.jsonl) and
    `v1_key` (its signer.pub) the format bridge into it. Never raises on a malformed bundle."""
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
            rep.check("bundle readable", False, rep.integrity)
            return rep, EXIT_BAD
    except Exception as e:
        rep.check("bundle readable", False, f"cannot read bundle: {type(e).__name__}: {e}")
        return rep, EXIT_BAD
    try:
        _verify(rep, manifest, files, trust, v1_ledger, v1_key)
    except Exception as e:
        rep.check("bundle structure", False, "", [f"malformed and could not be fully checked: {type(e).__name__}: {e}"])
    if rep.failures:
        rep.integrity = "FAILED"
    return rep, EXIT_FAIL if rep.failures else EXIT_OK


def _verify(rep, manifest, files, trust, v1_ledger, v1_key):
    listed = manifest.get("files")
    rep.check("manifest", isinstance(listed, dict) and listed == {n: hashlib.sha256(b).hexdigest()
                                                                  for n, b in files.items()},
              "every file is listed with its SHA-256 and nothing else is in the bundle")

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

    def included(record):
        seq = record["event"]["seq"]
        path = proofs["inclusion"].get(str(seq))
        return path is not None and verify_inclusion(seq, size, leaf_hash(bytes.fromhex(record["hash"][7:])),
                                                     [base64.b64decode(p, validate=True) for p in path], root)

    def check_record(r, keys, problems):
        """Signature, schema and log membership of one record; `keys`: the SPKIs the log allows at its position."""
        try:
            verify_record(r, keys, trust["algs"])
        except RecordError as e:
            problems.append(f"seq {r.get('event', {}).get('seq')!r}: {e}")
            return
        e = r["event"]
        errs = validate(e) if e.get("schema_version") == V2 else ["not a tracekit.event.v2 event"]
        problems.extend(f"seq {e.get('seq')!r}: {x}" for x in errs)
        if not errs and e.get("log_id") != log_id:
            problems.append(f"seq {e['seq']}: another log's record")

    # keys: declared and retired by records the checkpointed tree includes, so the log key vouches for them
    key_records, key_problems, timeline = _jsonl(files["keys/records.jsonl"]), [], {}
    log_id = key_records[0]["event"].get("log_id") if key_records else None

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
                declared[k["kid"]] = {"spki": der, "from": e["seq"], "until": None}
        check_record(r, keys_at(e["seq"]) + [k["spki"] for k in declared.values()], key_problems)
        if e["type"] == "key.retire":
            if e["data"]["kid"] not in timeline:
                key_problems.append(f"seq {e['seq']}: retires an unknown key")
            else:
                timeline[e["data"]["kid"]]["until"] = e["data"]["last_seq"]
        timeline.update(declared)

    # the runs: one, or with a run-set any number
    names = sorted(n for n in files if n.startswith("runs/"))
    run_set = "registry/run-set.json" in files
    if len(names) != 1 and not run_set:
        raise ValueError("a v2 bundle holds exactly one run, or a run-set")
    runs, problems, chain, outside = {}, [], [], []
    for name in names:
        records = runs[name] = _jsonl(files[name])
        if not records:
            raise ValueError("a run has no records")
        head = records[0]["event"]
        for i, r in enumerate(records):
            check_record(r, keys_at(r["event"]["seq"]), problems)
            e = r["event"]
            if (e.get("run_seq") != i or e.get("run_prev_hash") != (records[i - 1]["hash"] if i else ZERO_HASH)
                    or (e.get("tenant"), e.get("run_id")) != (head.get("tenant"), head.get("run_id"))
                    or (i and e["seq"] <= records[i - 1]["event"]["seq"])):
                chain.append(f"run {str(head.get('run_id'))[:200]!r} run_seq {i} (seq {e.get('seq')!r}) does not "
                             "continue the run")
        if not (included(records[0]) and included(records[-1])):
            outside.append(f"run {str(head.get('run_id'))[:200]!r}")
    retired, proven_to = [], -1
    if run_set:
        retired, proven_to = _run_set(rep, files, trust, origin, size, runs, included, lambda r, p: check_record(
            r, keys_at(r["event"]["seq"]), p))
        listed = {(r["event"]["seq"], r["hash"]) for r in key_records}
        key_problems.extend(f"seq {seq}: key.retire withheld (the registry log has it)"
                            for seq, h in retired if (seq, h) not in listed)
    rep.check("keys", bool(timeline) and not key_problems,
              f"{len(timeline)} record key(s) from {len(key_records)} key record(s)", key_problems)
    # a key.retire left out of keys/records.jsonl shows only against a registry range from its start past every record
    # lean: a key.retire written before the tenant's first registry leaf is in no registry of the tenant; add signer
    # leaves to a tenant's registry when it is created if keys are ever retired while tenants are being added
    relied = max(r["event"]["seq"] for r in key_records + [r for rs in runs.values() for r in rs])
    if proven_to < relied:
        rep.check("keys", False, "retirements not proven complete",
                  [f"no run-set from registry size 0 reaches seq {relied}, so a withheld key.retire would not show"],
                  warn=True)
    _bridge(rep, key_records, v1_ledger, v1_key)
    count = sum(map(len, runs.values()))
    rep.check("signatures", not problems, f"{count} record(s), keys valid at their position", problems)
    only = len(runs) == 1 and next(iter(runs.values()))[0]["event"]
    rep.check("run chain", not chain, f"run {str(only.get('run_id'))[:200]!r} of tenant {only.get('tenant')!r}, "
                                      "contiguous from run_seq 0" if only else
              f"{len(runs)} run(s), each contiguous from run_seq 0", chain)
    rep.check("inclusion", not outside, f"first and last records of {len(runs)} run(s) are in the checkpointed tree "
                                        f"of size {size}", outside)
    for p in sorted(n for n in files if n.startswith("policies/")):
        rep.check("policy snapshot", p == f"policies/{hashlib.sha256(files[p]).hexdigest()}.json", p)

    still_open = [rs for rs in runs.values() if rs[-1]["event"].get("type") != "run.final"]
    rep.integrity = ("VERIFIED" if not still_open else f"VERIFIED TO HEAD {still_open[0][-1]['event'].get('run_seq')} "
                     "(open)" if only else f"VERIFIED ({len(still_open)} run(s) open)")
    every = [r for rs in runs.values() for r in rs]
    self_approved = any(r["event"].get("type") == "approval" and r["event"]["data"].get("self_approved") is True
                        for r in every)
    against = [f"seq {r['event']['seq']}: {str(r['event']['data'].get('reason'))[:200]}" for r in every
               if r["event"].get("type") == "capture.gap" and r["event"]["data"].get("kind") == "executed_against_policy"]
    if against:
        rep.check("policy", False, f"{len(against)} tool call(s) ran against a deny or an unapproved ask", against[:20],
                  warn=True)
    rep.assurance = (_assurance(origin, cosigs, witnesses, trust, {r["alg"] for r in every + key_records}, self_approved)
                     + ("; key retirements not proven complete" if proven_to < relied else ""))
    glass = [r["event"] for r in every if r["event"].get("type") == "approval"
             and r["event"]["data"].get("break_glass") is True]
    if glass:
        rep.check("break-glass approvals", False, f"{len(glass)} approval(s) answered under the break-glass role",
                  [f"seq {e['seq']}: {e['data']['decision']} {e['data'].get('approval_id')} by "
                   f"{e['data']['approver'][:256]}: {str(e['data'].get('reason'))[:200]!r}" for e in glass][:20],
                  warn=True)


def _run_set(rep, files, trust, origin, size, runs, included, check_record):
    """The run-set line (COMPLETE or INCOMPLETE) and the log tail line. Returns the (seq, hash) of every key.retire
    the registry range points to, and the highest seq the range points to when it starts at registry size 0 (else -1):
    every key.retire up to there is in the range."""
    rs, problems = loads_strict(files["registry/run-set.json"]), []
    tsalt = base64.b64decode(rs["tenant_salt"], validate=True)
    lo, hi, reg_origin = rs["from"], rs["to"], registry.origin(origin, tsalt)
    span = f"registry {lo}..{hi}"
    # the registry notes are signed by the record log's own pinned key, under the registry origin
    vkeys = [checkpoint.vkey(reg_origin, checkpoint.ED25519, checkpoint.parse_vkey(k)[3]) for k in trust["logs"]
             if checkpoint.parse_vkey(k)[0] == origin]
    roots = {}
    for n in sorted({lo, hi} - {0}):
        try:
            _, n2, roots[n], _ = checkpoint.open_note(files[f"checkpoints/registry-{n}.note"], vkeys)
        except (checkpoint.NoteError, KeyError) as e:
            n2 = f"unusable ({type(e).__name__}: {e})"
        if n2 != n:
            problems.append(f"registry checkpoint at size {n}: {n2}")
    if problems or not 0 <= lo <= hi or hi == 0:
        rep.check("run-set", False, f"INCOMPLETE, {span}", problems or [f"bad registry range {lo}..{hi}"])
        return [], -1
    if 0 < lo < hi and not verify_consistency(lo, hi, roots[lo], roots[hi], [
            base64.b64decode(p, validate=True) for p in rs["consistency"]]):
        problems.append(f"registry checkpoint {lo} is not a prefix of {hi}")
    leaves, pointed = rs["leaves"], {r["event"]["seq"]: r for r in _jsonl(files["registry/records.jsonl"])}
    if len(leaves) != hi - lo:
        problems.append(f"{hi - lo} leaves in {lo}..{hi}, {len(leaves)} in the bundle: a leaf is missing")
    registered, finals, retired, closed, tenant, targets, top = {}, {}, [], None, None, set(), -1
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
        else:
            closed = e
    for run_id, final in finals.items():
        recs = runs.get(run_name(tenant, run_id))
        if (not recs or recs[-1]["hash"] != final["hash"]
                or run_id in registered and recs[0]["hash"] != registered[run_id]["hash"]):
            problems.append(f"run {run_id[:200]!r} is final in the range but its records are not in the bundle")
    if len(set(runs) - targets) > 1:
        problems.append(f"{len(set(runs) - targets)} runs in the bundle, but only the selected run may be in no leaf "
                        "of the range")
    if closed and size > closed["data"]["final_seq"] + 1:
        problems.append(f"records after log.closed at seq {closed['seq']}")
    rep.check("run-set", not problems, f"COMPLETE, {span} ({len(registered)} runs registered, {len(finals)} final, "
                                       f"{len(set(registered) - set(finals))} open)" if not problems else
              f"INCOMPLETE, {span}", problems)
    rep.check("log tail", bool(closed), f"none: log.closed at seq {closed['seq']} is the last record" if closed else
              f"records after tree size {size} are unproven (no log.closed in the range)", warn=True)
    return retired, top if lo == 0 else -1


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


def _assurance(origin, cosigs, witnesses, trust, algs, self_approved=False):
    """dev: no pinned witness cosigned, or a self-approval in the run; local: only operator-run witnesses; witnessed:
    enough independent ones."""
    independent = [k for k, _ in cosigs if witnesses[k] != "operator"]
    level = ("dev" if self_approved else "witnessed" if len(independent) >= max(1, trust["witnesses_required"])
             else "local" if cosigs else "dev")
    anchors = ", ".join(f"{k.split('+')[0]} ({witnesses[k]}) at "
                        f"{datetime.datetime.fromtimestamp(ts, datetime.timezone.utc):%Y-%m-%dT%H:%M:%SZ}"
                        for k, ts in sorted(cosigs, key=lambda c: c[1]))
    return (f"{level}; records {'+'.join(sorted(algs))}; checkpoint ed25519 ({origin})"
            + (f"; cosigned ed25519 by {anchors}" if anchors else "; no witness cosignature")
            + ("; approvals: self" if self_approved else ""))


def print_report(rep, code, stream=None):
    """The report as text; control characters in bundle-derived strings are dropped so they reach no terminal."""
    s, clean = stream or sys.stdout, lambda x: _CONTROL.sub("", str(x))
    for c in rep.checks:
        s.write(f"[{c['status'].upper()}] {c['check']}" + (f" — {clean(c['detail'])}" if c["detail"] else "") + "\n")
        for p in c["problems"]:
            s.write(f"        {clean(p)}\n")
    s.write(f"\nIntegrity: {clean(rep.integrity)}.\nAssurance: {clean(rep.assurance)}.\n")
