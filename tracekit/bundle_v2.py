"""Bundle v2 (`tracekit.bundle.v2`): one run's evidence, or a tenant's run-set, from file storage, checked by
`tracekit.verify.v2`.

    manifest.json               untrusted index: format, verifier_min_version, verifier_version (advisory), sha256 of
                                every other file
    runs/<id>.jsonl             a run's v2 records in run_seq order, no stubs (id: sha256 of "<tenant>/<run_id>",
                                32 hex, so names never carry caller text)
    keys/records.jsonl          the signer.epoch and key.retire records the checkpoint covers
    proofs/records.json         {"checkpoint", "tree_size", "inclusion": {seq: [base64 hash, ...]}}: RFC 6962
                                inclusion of each run's first and last records, every key record and every record a
                                registry leaf points to
    checkpoints/<size>.note     the C2SP checkpoint note the proofs are against
    rekor/<size>.json           its Rekor v2 TransparencyLogEntry, when the signer anchored that note
    tsa/<size>.tsr              and the RFC 3161 timestamp response of the anchor
    policies/<sha256>.json      the compiled policies (canonical JSON, so each is named by its policy_hash) the records
                                cite where a verifier checks against one (cited_policies), from the signer's policy_dir

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

With findings (export(..., with_runs=about(...))), the run's findings runs (run.registered `analyzes` the run: `tracekit
analyze --v2` and `tracekit why` findings) and replay runs (`replay_of` the run) are bundled with it, so the verifier
can check each finding's citations and count each `tracekit why` finding's replay runs.

No views, no code, no trust configuration: the verifier pins its own. Never content from the signer's content vault:
records hold commitments only."""
import base64
import hashlib
import json
import os
import zipfile

from tracekit.format import checkpoint, registry
from tracekit.storage.base import registry_tree

FORMAT = "tracekit.bundle.v2"
VERIFIER_MIN_VERSION = "1.0.0"
# what each verifier version added to format 1.0, oldest first: record types, data fields per type and enum values per
# (type, field) (gap kinds: capture.gap and trace.tamper `kind`), and from 1.4.0 the ext names it interprets; a bundle
# needs the newest version whose entries its records use (`needs`)
VERSIONS = {
    "1.1.0": {"types": ["input.observed", "content.accessed", "content.erased", "why.finding"],
              "fields": {"policy.decision": ["provenance", "provenance_state"], "run.registered": ["replay_of"]},
              "values": {}},
    "1.2.0": {"types": ["run.child", "approval.escalated", "approval.revoked", "approval.suggested", "approval.agents",
                        "incident.opened", "incident.updated", "incident.capped", "run.held", "run.resumed",
                        "run.quarantined", "incident.resolved", "incident.response", "identity.suspension",
                        "effect.observed"],
              "fields": {"run.registered": ["parent_run", "session", "posture"], "capture.gap": ["run_id"],
                         "run.final": ["provider_executed", "paired_by_args", "matrix"],
                         "policy.decision": ["via", "caller", "detect", "incident_id"],
                         "approval.request": ["agent", "via", "incident_id", "passkey"], "tool.result": ["via"],
                         "input.observed": ["via"],
                         "approval": ["approver_kind", "asserted", "spent", "not_before", "consume_by", "incident_id"],
                         "approval.expired": ["reason"],
                         "reconcile.unexplained_effect": ["observer", "kind", "host", "port"]},
              "values": {"capture.gap": {"kind": ["decided_not_completed", "late_activity", "concurrent_run",
                                                  "tailer_redelegated", "reask_after_reject", "held_call_unresolved",
                                                  "observer_lost", "effect_outside_run"]},
                         "run.closing": {"reason": ["quarantine"]}}},
    "1.3.0": {"types": ["reconcile.result_mismatch"], "fields": {},
              "values": {"capture.gap": {"kind": ["result_unchecked"]}}},
    "1.4.0": {"types": ["constraint.added"], "fields": {"effect.observed": ["sensor"], "review": ["cites"],
                                                        "model.exchange": ["said_only"]},
              "values": {"capture.gap": {"kind": ["constraint_refused"]}}, "ext": ["amended"]},
}
# the version that added the non-critical slot: an `ext` field on any record, and the `ext` record type. A record that
# uses it needs that version (an older one fails its schema); a verifier from it on checks the record's signature, chain
# and inclusion whatever the ext holds, and interprets the names its rows list (format-v2.md §9)
EXT = "1.4.0"
KEY_TYPES = ("signer.epoch", "key.retire")


def _jsonl(records):
    return b"".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n" for r in records)


def _b64(hashes):
    return [base64.b64encode(h).decode("ascii") for h in hashes]


def run_name(tenant, run_id):
    return f"runs/{hashlib.sha256(f'{tenant}/{run_id}'.encode('utf-8')).hexdigest()[:32]}.jsonl"


def ext_names(event):
    """The ext names an event carries: its `ext` field's keys, and an `ext` record's name."""
    ext = event.get("ext")
    return [*(ext if isinstance(ext, dict) else ()), *([event["data"]["name"]] if event.get("type") == "ext" else [])]


def _entries(event, added):
    """The entries of a VERSIONS row that `event` uses: `type`, `type.field`, `type.field=value` and `ext.<name>`."""
    typ, data = event["type"], event["data"]
    return ([typ] if typ in added["types"] else []) \
        + [f"{typ}.{f}" for f in added["fields"].get(typ, ()) if f in data] \
        + [f"{typ}.{f}={data[f]}" for f, vs in added["values"].get(typ, {}).items() if f in data and data[f] in vs] \
        + [f"ext.{n}" for n in ext_names(event) if n in added.get("ext", ())]


def needs(events):
    """(critical, full) verifier versions of a bundle of `events`. critical, its verifier_min_version: the newest whose
    VERSIONS entries other than ext names one of them uses, EXT at least when one uses the ext slot. full, its
    verifier_version: the newest whose entries, ext names among them, they use. A verifier between the two verifies the
    bundle and says which ext names it did not interpret."""
    order = [VERIFIER_MIN_VERSION, *VERSIONS]
    critical = full = VERIFIER_MIN_VERSION
    for version, added in VERSIONS.items():
        used = [x for e in events for x in _entries(e, added)]
        if any(not x.startswith("ext.") for x in used):
            critical = version
        if used:
            full = version
    if any("ext" in e or e["type"] == "ext" for e in events):
        critical = max(critical, EXT, key=order.index)
    return critical, max(critical, full, key=order.index)


def raised_by(events, version):
    """What makes a bundle of `events` need `version`: each entry of its VERSIONS row they use other than ext names, and
    `ext` (the slot) for EXT, with the seqs of the records that use it (the first five)."""
    seqs = {}
    for e in events:
        used = _entries(e, VERSIONS[version]) if version in VERSIONS else []
        for x in [x for x in used if not x.startswith("ext.")] + (
                ["ext"] if version == EXT and ("ext" in e or e["type"] == "ext") else []):
            seqs.setdefault(x, []).append(e["seq"])
    return [f"{x}: seq {', '.join(map(str, s[:5]))}" + (f" and {len(s) - 5} more" if len(s) > 5 else "")
            for x, s in sorted(seqs.items())]


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


def about(storage, tenant, run_id):
    """The runs of `tenant` whose run.registered analyzes or replays run `run_id`: its findings and replay runs."""
    # lean: reads the first record of every run of the store; index runs by what they analyse if stores grow large
    out = []
    for t, rid in list(storage.runs):
        first = next(iter(storage.iter_run(t, rid)), None) if t == tenant else None
        if first and run_id in (first["event"]["data"].get("analyzes"), first["event"]["data"].get("replay_of")):
            out.append(rid)
    return out


def cited_policies(events):
    """The policy_hashes whose snapshot a verifier checks the records against: the policy.decision's of each approval an
    agent gave (its rules must permit agents), and the one policy each run with an incident.opened was decided under
    (its incidents are recomputed under it; a run decided under several has them signer-asserted)."""
    agent = {e["data"].get("approval_id") for e in events if e["type"] == "approval"
             and e["data"].get("approver_kind") == "agent" and e["data"].get("decision") == "approve"}
    asked = {e["data"].get("decision_id") for e in events if e["type"] == "approval.request"
             and e["data"].get("approval_id") in agent}
    ran = {}   # run_id -> the policy_hashes its decisions name
    for e in events:
        if e["type"] == "policy.decision":
            ran.setdefault(e.get("run_id"), set()).add(e["data"].get("policy_hash"))
    incidents = {e.get("run_id") for e in events if e["type"] == "incident.opened"}
    return ({e["data"]["policy_hash"] for e in events if e["type"] == "policy.decision"
             and e["data"].get("decision_id") in asked and "policy_hash" in e["data"]}
            | {next(iter(hs)) for r, hs in ran.items() if r in incidents and len(hs) == 1}) - {None}


def export(storage, tenant, run_id, note, out_path, run_set=None, tenant_salt=None, with_runs=(), policy_dir=None):
    """Write the bundle of run (tenant, run_id) from a store or its reader (FileReader, PostgresReader). `note` is a
    checkpoint of the store's record tree: a run's records after it are left out (a run still being written verifies to
    its head). `run_set`: (a, b), two checkpointed sizes of the tenant's registry tree (a may be 0), with `tenant_salt`
    (format.registry.tenant_salt) adds the run-set a..b; `run_id` may then be None. `with_runs`: also these runs of the
    tenant (`about`: the run's findings and replay runs). `policy_dir`: where the signer keeps its compiled policies
    (<data_dir>/policies), to bundle those cited_policies names."""
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
    else:
        run_ids += with_runs
    runs = {}
    for rid in run_ids:
        records = list(storage.iter_run(tenant, rid))
        if not records:
            raise ValueError(f"no run {rid!r} for tenant {tenant!r}")
        # a run still being written: its records up to the checkpoint
        records = runs[run_name(tenant, rid)] = [r for r in records if r["event"]["seq"] < size]
        if not records:
            raise ValueError("the checkpoint does not cover the run yet; export after the next checkpoint")
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
    })
    anchor = next((x for x in storage.anchors() if x["size"] == size), None)
    if anchor:
        files[f"rekor/{size}.json"] = json.dumps(anchor["rekor"]).encode("utf-8")
        files[f"tsa/{size}.tsr"] = base64.b64decode(anchor["tsa"])
    events = [r["event"] for r in [*pointed, *(r for rs in runs.values() for r in rs)]]
    for h in sorted(cited_policies(events) if policy_dir else ()):
        try:
            with open(os.path.join(policy_dir, h.removeprefix("sha256:") + ".json"), "rb") as f:
                files[f"policies/{h.removeprefix('sha256:')}.json"] = f.read()
        except (FileNotFoundError, ValueError):   # a policy this signer never ran: the verifier says so
            pass
    need, full = needs(events)
    manifest = {"format": FORMAT, "verifier_min_version": need, "verifier_version": full,
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    tmp = out_path + ".tmp"
    try:
        with open(tmp, "wb") as f:
            with zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("manifest.json", json.dumps(manifest, indent=1))
                for n, b in files.items():
                    z.writestr(n, b)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return {"bundle": out_path, "records": sum(map(len, runs.values())), "tree_size": size,
            **({"runs": len(runs), "registry_leaves": run_set[1] - run_set[0]} if run_set else {}),
            "verifier_min_version": need, "raised_by": raised_by(events, need), "verifier_version": full}
