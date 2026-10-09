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
checkpointed tree. A run without run.final verifies only to its head. The bundle's manifest is an index, never trusted."""
import base64
import datetime
import hashlib
import re
import sys
import zipfile

from tracekit import __version__, crypto
from tracekit.bundle import EXIT_BAD, EXIT_FAIL, EXIT_OK, Report
from tracekit.bundle_v2 import FORMAT, KEY_TYPES
from tracekit.format import checkpoint
from tracekit.format.canon import loads_strict
from tracekit.format.records import RecordError, verify_record
from tracekit.merkle import leaf_hash, verify_inclusion
from tracekit.schema import V2, validate
from tracekit.storage.base import ZERO_HASH

MAX_ENTRIES = 10_000
MAX_ENTRY = 64 << 20
MAX_TOTAL = 512 << 20
MAX_LINE = 1 << 20
CLASSES = ("public", "customer", "tracekit", "operator")
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*")


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


def is_v2(path):
    """True when `path` is a zip whose manifest names format v2. Never raises."""
    try:
        with zipfile.ZipFile(path) as z, z.open("manifest.json") as f:
            return loads_strict(f.read(MAX_LINE)).get("format") == FORMAT
    except Exception:
        return False


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


def verify(path, trust_path):
    """Verify a v2 bundle against the pinned trust config at `trust_path`. Never raises on a malformed bundle."""
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
        if not isinstance(need, str) or _version(need) > _version(__version__):
            rep.integrity = f"UNVERIFIABLE (needs tracekit >= {str(need)[:20]})"
            rep.check("bundle readable", False, rep.integrity)
            return rep, EXIT_BAD
    except Exception as e:
        rep.check("bundle readable", False, f"cannot read bundle: {type(e).__name__}: {e}")
        return rep, EXIT_BAD
    try:
        _verify(rep, manifest, files, trust)
    except Exception as e:
        rep.check("bundle structure", False, "", [f"malformed and could not be fully checked: {type(e).__name__}: {e}"])
    if rep.failures:
        rep.integrity = "FAILED"
    return rep, EXIT_FAIL if rep.failures else EXIT_OK


def _verify(rep, manifest, files, trust):
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
    # lean: a withheld key.retire can't be noticed here; the registry log's key.retire leaves prove the full set (M1b)
    rep.check("keys", bool(timeline) and not key_problems,
              f"{len(timeline)} record key(s) from {len(key_records)} key record(s)", key_problems)

    # the run
    runs = [n for n in files if n.startswith("runs/")]
    if len(runs) != 1:
        raise ValueError("a v2 bundle holds exactly one run")
    records, problems, chain = _jsonl(files[runs[0]]), [], []
    if not records:
        raise ValueError("the run has no records")
    head = records[0]["event"]
    for i, r in enumerate(records):
        check_record(r, keys_at(r["event"]["seq"]), problems)
        e = r["event"]
        if (e.get("run_seq") != i or e.get("run_prev_hash") != (records[i - 1]["hash"] if i else ZERO_HASH)
                or (e.get("tenant"), e.get("run_id")) != (head.get("tenant"), head.get("run_id"))
                or (i and e["seq"] <= records[i - 1]["event"]["seq"])):
            chain.append(f"run_seq {i} (seq {e.get('seq')!r}) does not continue the run")
    rep.check("signatures", not problems, f"{len(records)} record(s), keys valid at their position", problems)
    rep.check("run chain", not chain, f"run {str(head.get('run_id'))[:200]!r} of tenant {head.get('tenant')!r}, "
                                      "contiguous from run_seq 0", chain)
    rep.check("inclusion", included(records[0]) and included(records[-1]),
              f"first and last records are in the checkpointed tree of size {size}")
    for p in sorted(n for n in files if n.startswith("policies/")):
        rep.check("policy snapshot", p == f"policies/{hashlib.sha256(files[p]).hexdigest()}.json", p)

    n = records[-1]["event"].get("run_seq")
    rep.integrity = "VERIFIED" if records[-1]["event"].get("type") == "run.final" else f"VERIFIED TO HEAD {n} (open)"
    rep.assurance = _assurance(origin, cosigs, witnesses, trust, {r["alg"] for r in records})


def _assurance(origin, cosigs, witnesses, trust, algs):
    """dev: no pinned witness cosigned; local: only operator-run witnesses; witnessed: enough independent ones."""
    independent = [k for k, _ in cosigs if witnesses[k] != "operator"]
    level = ("witnessed" if len(independent) >= max(1, trust["witnesses_required"])
             else "local" if cosigs else "dev")
    anchors = ", ".join(f"{k.split('+')[0]} ({witnesses[k]}) at "
                        f"{datetime.datetime.fromtimestamp(ts, datetime.timezone.utc):%Y-%m-%dT%H:%M:%SZ}"
                        for k, ts in sorted(cosigs, key=lambda c: c[1]))
    return (f"{level}; records {'+'.join(sorted(algs))}; checkpoint ed25519 ({origin})"
            + (f"; cosigned ed25519 by {anchors}" if anchors else "; no witness cosignature"))


def print_report(rep, code, stream=None):
    s = stream or sys.stdout
    for c in rep.checks:
        s.write(f"[{c['status'].upper()}] {c['check']}" + (f" — {c['detail']}" if c["detail"] else "") + "\n")
        for p in c["problems"]:
            s.write(f"        {p}\n")
    s.write(f"\nIntegrity: {rep.integrity}.\nAssurance: {rep.assurance}.\n")
