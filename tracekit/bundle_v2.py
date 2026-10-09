"""Bundle v2 (`tracekit.bundle.v2`): one run's evidence from file storage, checked by `tracekit.verify.v2`.

    manifest.json               untrusted index: format, verifier_min_version, sha256 of every other file
    runs/<id>.jsonl             the run's v2 records in run_seq order, no stubs (id: sha256 of "<tenant>/<run_id>",
                                32 hex, so names never carry caller text)
    keys/records.jsonl          the signer.epoch and key.retire records the checkpoint covers
    proofs/records.json         {"checkpoint", "tree_size", "inclusion": {seq: [base64 hash, ...]}}: RFC 6962
                                inclusion of the run's first and last records and of every key record
    checkpoints/<size>.note     the C2SP checkpoint note the proofs are against
    policies/<sha256>.json      policy snapshots, named by the SHA-256 of their bytes

No views, no code, no trust configuration: the verifier pins its own."""
import base64
import hashlib
import json
import os
import zipfile

from tracekit.format import checkpoint

FORMAT = "tracekit.bundle.v2"
VERIFIER_MIN_VERSION = "0.3.0"
KEY_TYPES = ("signer.epoch", "key.retire")


def _jsonl(records):
    return b"".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n" for r in records)


def export(storage, tenant, run_id, note, out_path, policies=()):
    """Write the bundle of run (tenant, run_id) from a FileStorage. `note` is a checkpoint of the store's record tree
    that covers the run's last record; `policies` are policy snapshots (bytes)."""
    records = list(storage.iter_run(tenant, run_id))
    if not records:
        raise ValueError(f"no run {run_id!r} for tenant {tenant!r}")
    origin, size = note.split("\n", 2)[:2]
    size = int(size)
    if not 0 < size <= storage.tree.size or not note.startswith(
            checkpoint.body(origin, size, storage.tree.root_at(size)) + "\n"):
        raise ValueError("the checkpoint is not of this store's record tree")
    if records[-1]["event"]["seq"] >= size:
        raise ValueError("the checkpoint does not cover the run's last record yet; export after the next checkpoint")
    # lean: scans the whole log for key records; index them in storage once logs reach millions of records
    keys = [r for r in storage.iter_range(0, size) if r["event"]["type"] in KEY_TYPES]
    seqs = {records[0]["event"]["seq"], records[-1]["event"]["seq"], *(r["event"]["seq"] for r in keys)}
    files = {
        f"runs/{hashlib.sha256(f'{tenant}/{run_id}'.encode('utf-8')).hexdigest()[:32]}.jsonl": _jsonl(records),
        "keys/records.jsonl": _jsonl(keys),
        f"checkpoints/{size}.note": note.encode("utf-8"),
        "proofs/records.json": json.dumps({
            "checkpoint": f"checkpoints/{size}.note", "tree_size": size,
            "inclusion": {str(s): [base64.b64encode(h).decode("ascii") for h in storage.tree.inclusion_proof(s, size)]
                          for s in sorted(seqs)}}).encode("utf-8"),
        **{f"policies/{hashlib.sha256(p).hexdigest()}.json": p for p in policies},
    }
    manifest = {"format": FORMAT, "verifier_min_version": VERIFIER_MIN_VERSION,
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    tmp = out_path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        for n, b in files.items():
            z.writestr(n, b)
    os.replace(tmp, out_path)
    return {"bundle": out_path, "records": len(records), "tree_size": size}
