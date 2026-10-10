"""Bundle v2 (`tracekit.bundle.v2`): one run's evidence, or a tenant's run-set, from file storage, checked by
`tracekit.verify.v2`.

    manifest.json               untrusted index: format, verifier_min_version, sha256 of every other file
    runs/<id>.jsonl             a run's v2 records in run_seq order, no stubs (id: sha256 of "<tenant>/<run_id>",
                                32 hex, so names never carry caller text)
    keys/records.jsonl          the signer.epoch and key.retire records the checkpoint covers
    proofs/records.json         {"checkpoint", "tree_size", "inclusion": {seq: [base64 hash, ...]}}: RFC 6962
                                inclusion of each run's first and last records, every key record and every record a
                                registry leaf points to
    checkpoints/<size>.note     the C2SP checkpoint note the proofs are against
    rekor/<size>.json           its Rekor v2 TransparencyLogEntry, when the signer anchored that note
    tsa/<size>.tsr              and the RFC 3161 timestamp response of the anchor
    policies/<sha256>.json      policy snapshots, named by the SHA-256 of their bytes

A run-set bundle (export(..., run_set=(a, b))) proves which runs of one tenant were registered and finalised between
two checkpoints of the tenant's registry log (tracekit.format.registry). It adds:

    registry/run-set.json       {"tenant_salt": base64, "from", "to", "consistency": [base64 hash, ...],
                                 "leaves": [{"leaf": base64, "inclusion": [base64 hash, ...]}, ...]}: every leaf
                                a..b-1 with its inclusion in the registry tree at b, and the consistency proof a -> b
    registry/records.jsonl      the record each leaf points to, in leaf order
    checkpoints/registry-<n>.note   the registry notes at a (none when a = 0) and b
    runs/                       every run a run.final leaf in the range ends (and the selected run, if any)

The tenant salt goes into the bundle so its verifier can recompute H(tenant_salt ‖ run_id) for each leaf. Trade-off:
whoever holds the bundle can test guessed run ids against this tenant's leaves (and link this tenant's registry
origin); other tenants' leaves stay opaque, as each tenant has its own salt.

No views, no code, no trust configuration: the verifier pins its own."""
import base64
import hashlib
import json
import os
import zipfile

from tracekit.format import checkpoint, registry
from tracekit.storage.base import registry_tree

FORMAT = "tracekit.bundle.v2"
VERIFIER_MIN_VERSION = "0.4.0"
KEY_TYPES = ("signer.epoch", "key.retire")


def _jsonl(records):
    return b"".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n" for r in records)


def _b64(hashes):
    return [base64.b64encode(h).decode("ascii") for h in hashes]


def run_name(tenant, run_id):
    return f"runs/{hashlib.sha256(f'{tenant}/{run_id}'.encode('utf-8')).hexdigest()[:32]}.jsonl"


def _run_set(storage, tenant, tsalt, origin, size, lo, hi):
    """(files, records the leaves point to) of the run-set a..b of `tenant`'s registry."""
    tree, name, reg_origin = storage.registry_merkle(tenant), registry_tree(tenant), registry.origin(origin, tsalt)
    files = {}
    if not 0 <= lo <= hi or tree is None:
        raise ValueError(f"no registry range {lo}..{hi} for tenant {tenant!r}")
    for n in sorted({lo, hi} - {0}):
        note = storage.checkpoint_at(name, n)
        if note is None or n > tree.size or not note.startswith(checkpoint.body(reg_origin, n, tree.root_at(n)) + "\n"):
            raise ValueError(f"no registry checkpoint of tenant {tenant!r} at size {n}")
        files[f"checkpoints/registry-{n}.note"] = note.encode("utf-8")
    leaves = list(storage.registry_iter(tenant))[lo:hi]
    pointed = []
    for leaf in leaves:
        seq = registry.parse(leaf)[3]
        if seq >= size:
            raise ValueError("the checkpoint does not cover the run-set's records yet; export after the next checkpoint")
        pointed.extend(storage.iter_range(seq, seq + 1))
    files["registry/records.jsonl"] = _jsonl(pointed)
    files["registry/run-set.json"] = json.dumps({
        "tenant_salt": base64.b64encode(tsalt).decode("ascii"), "from": lo, "to": hi,
        "consistency": _b64(tree.consistency_proof(lo, hi)) if 0 < lo < hi else [],
        "leaves": [{"leaf": base64.b64encode(leaf).decode("ascii"), "inclusion": _b64(tree.inclusion_proof(lo + i, hi))}
                   for i, leaf in enumerate(leaves)]}).encode("utf-8")
    return files, pointed


def export(storage, tenant, run_id, note, out_path, policies=(), run_set=None, tenant_salt=None):
    """Write the bundle of run (tenant, run_id) from a store or its reader (FileReader, PostgresReader). `note` is a
    checkpoint of the store's record tree that covers the run's last record; `policies` are policy snapshots (bytes).
    `run_set`: (a, b), two checkpointed sizes of the tenant's registry tree (a may be 0), with `tenant_salt`
    (format.registry.tenant_salt) adds the run-set a..b; `run_id` may then be None."""
    origin, size = note.split("\n", 2)[:2]
    size = int(size)
    if not 0 < size <= storage.tree.size or not note.startswith(
            checkpoint.body(origin, size, storage.tree.root_at(size)) + "\n"):
        raise ValueError("the checkpoint is not of this store's record tree")
    files, run_ids, pointed = {}, [] if run_id is None else [run_id], []
    if run_set is not None:
        files, pointed = _run_set(storage, tenant, tenant_salt, origin, size, *run_set)
        run_ids += [r["event"]["run_id"] for r in pointed if r["event"]["type"] == "run.final"
                    and r["event"]["run_id"] not in run_ids]
    elif run_id is None:
        raise ValueError("export needs a run or a run-set")
    runs = {}
    for rid in run_ids:
        records = runs[run_name(tenant, rid)] = list(storage.iter_run(tenant, rid))
        if not records:
            raise ValueError(f"no run {rid!r} for tenant {tenant!r}")
        if records[-1]["event"]["seq"] >= size:
            raise ValueError("the checkpoint does not cover the run's last record yet; export after the next checkpoint")
    # lean: scans the whole log for key records; index them in storage once logs reach millions of records
    keys = [r for r in storage.iter_range(0, size) if r["event"]["type"] in KEY_TYPES]
    seqs = {r["event"]["seq"] for rs in runs.values() for r in (rs[0], rs[-1])} | {
        r["event"]["seq"] for r in keys + pointed}
    files.update({
        **{n: _jsonl(rs) for n, rs in runs.items()},
        "keys/records.jsonl": _jsonl(keys),
        f"checkpoints/{size}.note": note.encode("utf-8"),
        "proofs/records.json": json.dumps({
            "checkpoint": f"checkpoints/{size}.note", "tree_size": size,
            "inclusion": {str(s): _b64(storage.tree.inclusion_proof(s, size)) for s in sorted(seqs)}}).encode("utf-8"),
        **{f"policies/{hashlib.sha256(p).hexdigest()}.json": p for p in policies},
    })
    anchor = next((x for x in storage.anchors() if x["size"] == size), None)
    if anchor:
        files[f"rekor/{size}.json"] = json.dumps(anchor["rekor"]).encode("utf-8")
        files[f"tsa/{size}.tsr"] = base64.b64decode(anchor["tsa"])
    manifest = {"format": FORMAT, "verifier_min_version": VERIFIER_MIN_VERSION,
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    tmp = out_path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        for n, b in files.items():
            z.writestr(n, b)
    os.replace(tmp, out_path)
    return {"bundle": out_path, "records": sum(map(len, runs.values())), "tree_size": size,
            **({"runs": len(runs), "registry_leaves": run_set[1] - run_set[0]} if run_set else {})}
