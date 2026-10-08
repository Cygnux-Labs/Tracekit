"""Evidence bundles (.tkb) — export (I4) and offline verification (I5).

A .tkb is a zip:
  manifest.json      format, selection, seq range, sha256 of every other file
  records.jsonl      every ledger record 0..end; records outside the selection are *elided*
                     (hash, prev_hash, seq, sig kept; event body removed)
  signer.pub         raw Ed25519 public key
  checkpoints.jsonl  signed checkpoints covering the range
  policies/<h>.json  policy snapshots referenced by run.start
  coverage.json      coverage report for the selection
  replay.html        offline viewer that re-runs the checks in the browser
"""
import json
import os
import zipfile

from .core import read_json
from . import __version__, coverage, crypto
from . import schema as schema_mod
from .core import GENESIS, b64e, event_hash, sha256_hex
from .ledger import read_records, verify_record_sig
from .policy import policy_hash
from .witness import from_spec, verify_checkpoint

FORMAT = "tracekit.bundle.v1"
# signer-wide events kept in every bundle: they say whether the signer itself had problems
SIGNER_TYPES = {"capture.gap", "trace.tamper", "checkpoint", "error"}  # 0.2.1: refused writes are evidence too
TRUST = {"hook": "reported by a hook process (any process running as the agent's user can send these)", "proxy": "observed at the model API boundary",
         "transcript": "harness-reported, lower trust", "sdk": "reported by an instrumented app",
         "migrated": "converted from a v0.1 ledger (hash chain only, unsigned origin)", "signer": "written by tracekitd"}
EXIT_OK, EXIT_FAIL, EXIT_BAD, EXIT_WARN = 0, 1, 2, 3
# companion runs (signed findings, causeway anchors) have no run.start/run.end of their own
COMPANION_PREFIXES = ("findings:", "anchors:")


def _elide(rec):
    ev = rec["event"]
    return {"v": 1, "elided": True, "seq": ev["seq"], "prev_hash": ev["prev_hash"], "hash": rec["hash"],
            "sig": rec["sig"], "kid": rec["kid"]}


def select(records, run=None, last=False, since=None):
    """Return the set of selected run_ids."""
    starts = [r["event"] for r in records if r and not r.get("elided") and r["event"]["type"] == "run.start"]
    if run:
        return {run}
    if since:
        return {e["run_id"] for e in starts if e["ts"] >= since}
    if starts:
        return {starts[-1]["run_id"]}
    return set()


def export(signer_home, out_path, run=None, last=True, since=None, otel=False, otel_endpoint=None, otel_headers=None):
    ledger_path = os.path.join(signer_home, "ledger", "ledger.jsonl")
    recs = [r for _, r, _ in read_records(ledger_path) if r]
    if not recs:
        raise SystemExit("ledger is empty")
    runs = select(recs, run, last, since)
    if not runs:
        raise SystemExit("no run matches the selection")
    runs = set(runs)
    present = {r["event"]["run_id"] for r in recs if not r.get("elided")}
    runs |= {"findings:" + x for x in list(runs) if "findings:" + x in present}  # signed findings travel with their run
    runs |= {"findings:causeway:" + x[len("anchors:causeway:"):] for x in list(runs)
             if x.startswith("anchors:causeway:") and "findings:causeway:" + x[len("anchors:causeway:"):] in present}
    def keep(ev):  # 0.2.1: a refused write names the run it targeted in client_run_id, not run_id
        if ev["run_id"] in runs:
            return True
        if ev["run_id"] == "_signer" and ev["type"] in SIGNER_TYPES:
            if ev["type"] == "error":
                return (ev.get("data") or {}).get("client_run_id") in runs
            return True
        return False
    sel_seqs = [r["event"]["seq"] for r in recs if not r.get("elided") and r["event"]["run_id"] in runs]
    if not sel_seqs:
        raise SystemExit(f"no records for run(s) {sorted(runs)}")
    last_sel = max(sel_seqs)
    cp_path = os.path.join(signer_home, "checkpoints.jsonl")

    def read_cps():
        out = []
        if os.path.exists(cp_path):
            with open(cp_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        c = json.loads(line)
                    except ValueError:
                        continue  # a torn last line from a crash; the verifier reports what is missing
                    if isinstance(c, dict) and isinstance(c.get("head_seq"), int):
                        out.append(c)
        return out
    cps = read_cps()
    if not [c for c in cps if c["head_seq"] >= last_sel]:
        # ask the signer for a checkpoint so the bundle ends at a signed, witnessed head
        try:
            from . import client
            cfgp = os.path.join(signer_home, "config.json")
            sock = read_json(cfgp).get("socket") if os.path.exists(cfgp) else None
            old = os.environ.get("TRACEKIT_SOCKET")
            if sock:
                os.environ["TRACEKIT_SOCKET"] = sock
            try:
                client.rpc({"op": "checkpoint"})
            finally:
                if sock:
                    if old is None:
                        os.environ.pop("TRACEKIT_SOCKET", None)
                    else:
                        os.environ["TRACEKIT_SOCKET"] = old
            cps = read_cps()
            recs = [r for _, r, _ in read_records(ledger_path) if r]
        except Exception as e:
            # signer unreachable: the bundle's tail stays unwitnessed and verify says so
            import sys
            print(f"tracekit: warning: could not ask the signer for a checkpoint ({e}); the bundle's tail may be unwitnessed",
                  file=sys.stderr)
    covering = [c for c in cps if c["head_seq"] >= last_sel]
    end = min(c["head_seq"] for c in covering) if covering else last_sel
    end = max(end, last_sel)
    body_recs, sel_events = [], []
    for r in recs:
        seq = r["seq"] if r.get("elided") else r["event"]["seq"]
        if seq > end:
            break
        if not r.get("elided") and keep(r["event"]):
            body_recs.append(r)
            if r["event"]["run_id"] in runs:
                sel_events.append(r["event"])
        else:
            body_recs.append(r if r.get("elided") else _elide(r))
    cps_in = [c for c in cps if c["head_seq"] <= end]
    with open(os.path.join(signer_home, "ledger", "signer.pub"), "rb") as f:
        pub = f.read()
    policies = {}
    for e in sel_events:
        full_h = e["data"]["policy"]["hash"] if e["type"] == "run.start" else \
            (e["data"].get("policy_hash") if e["type"] == "policy.decision" else None)
        if full_h:
            h = full_h.split(":")[1]
            p = os.path.join(signer_home, "blobs", h + ".json")
            if os.path.exists(p) and f"policies/{h}.json" not in policies:
                with open(p, encoding="utf-8") as f:
                    policies[f"policies/{h}.json"] = f.read()
    cov = coverage.report(sel_events)
    files = {
        "records.jsonl": "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in body_recs),
        "checkpoints.jsonl": "".join(json.dumps(c, sort_keys=True) + "\n" for c in cps_in),
        "coverage.json": json.dumps(cov, indent=2),
        **policies,
    }
    blobs = {k: v.encode("utf-8") for k, v in files.items()}
    blobs["signer.pub"] = pub
    blobs.update(_attestations(signer_home, cps_in))
    pushed = None
    if otel or otel_endpoint:
        from .otel import push, to_otlp_json
        payload = to_otlp_json(sel_events, crypto.kid(pub), {r["event"]["seq"]: r["hash"] for r in body_recs if not r.get("elided")})
        blobs["otel.json"] = json.dumps(payload, indent=1).encode("utf-8")
        if otel_endpoint:
            try:
                pushed = push(otel_endpoint, payload, headers=otel_headers)
            except Exception as e:  # a down collector must not cost you the evidence bundle
                import sys
                print(f"tracekit: warning: could not send spans to {otel_endpoint} ({e}); the bundle was still written",
                      file=sys.stderr)
                pushed = ("failed", str(e)[:200])
    manifest = {"format": FORMAT, "tracekit_version": __version__, "created": sel_events[-1]["ts_signed"],
                "selection": {"runs": sorted(runs)}, "seq_range": [0, end], "kid": crypto.kid(pub),
                "public_key_b64": b64e(pub), "files": {k: sha256_hex(v) for k, v in blobs.items()}}
    blobs["replay.html"] = _replay(manifest, blobs).encode("utf-8")
    manifest["files"]["replay.html"] = sha256_hex(blobs["replay.html"])
    tmp_path = f"{out_path}.tmp-{os.getpid()}"
    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            for k, v in blobs.items():
                z.writestr(k, v)
        os.replace(tmp_path, out_path)  # never leave a half-written bundle under the real name
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return {"path": out_path, "runs": sorted(runs), "records": len(body_recs), "selected_events": len(sel_events),
            "checkpoints": len(cps_in), "end_seq": end, **({"otel_push": {"status": pushed[0]}} if pushed else {})}


def _replay(manifest, blobs):
    """replay.html rendered from the bundle files alone, so the verifier can regenerate it and compare."""
    from .replay import render
    jl = lambda n: [json.loads(l) for l in blobs.get(n, b"").decode("utf-8").splitlines() if l.strip()]
    pols = {k: v.decode("utf-8") for k, v in blobs.items() if k.startswith("policies/")}
    files = {k: v for k, v in (manifest.get("files") or {}).items() if k != "replay.html"}
    return render({**manifest, "files": files}, jl("records.jsonl"), jl("checkpoints.jsonl"),
                  json.loads(blobs.get("coverage.json") or b"{}"), pols)


# ------------------------------------------------------------------ verify
class Report:
    def __init__(self):
        self.checks, self.failures, self.warnings, self.notes = [], [], [], []
        self.assurance = None

    def check(self, name, ok, detail="", problems=None, warn=False):
        self.checks.append({"check": name, "status": "pass" if ok else ("warn" if warn else "fail"), "detail": detail,
                            "problems": problems or []})
        if not ok and not warn:
            self.failures.append(name)
        if not ok and warn:
            self.warnings.append(name)


MAX_BUNDLE_BYTES = 512 * 1024 * 1024   # uncompressed; refuses zip bombs before reading anything


def _attestations(signer_home, cps):
    """The key attestation document the checkpoints name (by SHA-256), from the signer config: attestation/<sha>.bin."""
    wanted = {c.get("key_attestation_sha256") for c in cps} - {None}
    if not wanted:
        return {}
    try:
        with open(os.path.join(signer_home, "config.json"), encoding="utf-8") as f:
            path = ((json.load(f).get("signer") or {}).get("attestation"))
        from .extsigner import read_attestation
        data = read_attestation(path) if path else None
    except (OSError, ValueError):
        data = None
    if data is None or sha256_hex(data) not in wanted:
        import sys
        print("tracekit: warning: checkpoints name a key attestation document that is not at the configured path any more; "
              "the bundle will say so", file=sys.stderr)
        return {}
    return {f"attestation/{sha256_hex(data)}.bin": data}


def load_bundle(path):
    with zipfile.ZipFile(path) as z:
        infos = [i for i in z.infolist() if not i.filename.endswith("/")]
        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            raise ValueError("bundle contains duplicate member names")
        if sum(i.file_size for i in infos) > MAX_BUNDLE_BYTES:
            raise ValueError(f"bundle expands to more than {MAX_BUNDLE_BYTES // (1024 * 1024)} MiB")
        manifest = json.loads(z.read("manifest.json"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest.json is not an object")
        blobs = {n: z.read(n) for n in names if n != "manifest.json"}
    return manifest, blobs


def _load_trusted_key(spec):
    """--key: a signer.pub file (32 raw bytes or base64) or a key id 'ed25519:...'. Returns (pub or None, kid)."""
    if spec.startswith("ed25519:"):
        return None, spec
    with open(spec, "rb") as f:
        data = f.read()
    # a raw key is exactly 32 bytes and may legitimately start or end with a whitespace byte (about 5% of
    # keys), so only strip when it is not already the right length (the base64 form, with its newline)
    raw = data if len(data) == 32 else data.strip()
    if len(raw) != 32:
        from .core import b64d
        raw = b64d(raw.decode())
    if len(raw) != 32:
        raise ValueError(f"{spec} is not an Ed25519 public key (expected 32 raw bytes or their base64)")
    return raw, crypto.kid(raw)


def verify(path, witness_specs=(), strict=False, trusted_key=None):
    """Verify a .tkb. Never raises on a malformed bundle: structure problems become failed checks."""
    rep = Report()
    try:
        manifest, blobs = load_bundle(path)
    except Exception as e:
        rep.check("bundle readable", False, f"cannot read bundle: {e}")
        return rep, EXIT_BAD
    if manifest.get("format") != FORMAT:
        rep.check("bundle readable", False, f"unknown format {manifest.get('format')!r}")
        return rep, EXIT_BAD
    try:
        return _verify(rep, manifest, blobs, witness_specs, strict, trusted_key)
    except (KeyError, TypeError, AttributeError, IndexError, ValueError) as e:
        rep.check("bundle structure", False, "", [f"bundle content is malformed and could not be fully checked: "
                                                  f"{type(e).__name__}: {e}"])
        return rep, EXIT_FAIL


def _verify(rep, manifest, blobs, witness_specs, strict, trusted_key):
    # 0. file integrity against the manifest (manifest itself is covered by the signed chain + checkpoints).
    #    replay.html is an untrusted view: it never changes the verdict, a mismatch is only a warning.
    listed = {n: h for n, h in manifest.get("files", {}).items() if n != "replay.html"}
    bad = [n for n, h in listed.items() if n not in blobs or sha256_hex(blobs[n]) != h]
    extra = sorted(n for n in blobs if n not in listed and n != "replay.html")
    if "replay.html" in blobs:
        try:
            same = _replay(manifest, blobs).encode("utf-8") == blobs["replay.html"]
        except (ValueError, TypeError, AttributeError):
            same = False
        if not same:
            rep.notes.append("replay.html differs from the viewer this verifier would generate; the verdict does not use it, "
                             "do not rely on it")
    rep.check("files match manifest", not bad and not extra,
              "all bundle files match their manifest hashes" if not (bad or extra) else "",
              [f"{n}: missing or modified" for n in bad] + [f"{n}: present but not listed in the manifest" for n in extra])
    pub = blobs.get("signer.pub", b"")
    kid = crypto.kid(pub) if len(pub) == 32 else None
    recs = []
    for i, line in enumerate(blobs.get("records.jsonl", b"").decode("utf-8", "replace").splitlines(), 1):
        try:
            rec = json.loads(line)
        except ValueError:
            rec = None
        recs.append(rec if isinstance(rec, dict) else None)

    # 1. chain intact
    probs, prev, expect, events = [], GENESIS, 0, []
    for i, r in enumerate(recs):
        if r is None:
            probs.append(f"line {i + 1}: not valid JSON"); continue
        if r.get("elided"):
            seq, ph, h = r.get("seq"), r.get("prev_hash"), r.get("hash")
        else:
            ev = r.get("event") or {}
            seq, ph, h = ev.get("seq"), ev.get("prev_hash"), r.get("hash")
            if event_hash(ev) != h:
                probs.append(f"record seq {seq}: hash mismatch (event content was edited)")
            events.append(ev)
        if seq != expect:
            probs.append(f"record at line {i + 1}: seq {seq}, expected {expect} (record deleted, inserted or reordered)")
            expect = seq if isinstance(seq, int) else expect
        if ph != prev:
            probs.append(f"record seq {seq}: prev_hash does not match the previous record (chain broken)")
        prev, expect = h, (expect + 1)
    rep.check("chain intact", not probs, f"{len(recs)} records linked from genesis" if not probs else "", probs[:20])

    # 2. signatures valid
    sp = []
    if kid is None:
        sp.append("signer.pub missing or not a 32-byte Ed25519 key")
    else:
        if manifest.get("kid") != kid:
            sp.append(f"manifest kid {manifest.get('kid')} does not match signer.pub ({kid})")
        for r in recs:
            if r is None:
                continue
            seq = r.get("seq") if r.get("elided") else (r.get("event") or {}).get("seq")
            if r.get("kid") != kid:
                sp.append(f"record seq {seq}: signed by {r.get('kid')}, bundle key is {kid}")
            elif not verify_record_sig(r, pub):
                sp.append(f"record seq {seq}: signature invalid (forged or altered record)")
    rep.check("signatures valid", not sp, f"{len(recs)} Ed25519 signatures valid ({kid})" if not sp else "", sp[:20])

    # 2b. schema
    se = []
    for ev in events:
        errs = schema_mod.validate(ev)
        if errs:
            se.append(f"record seq {ev.get('seq')}: {errs[0]}")
    rep.check("events match schema v1", not se, f"{len(events)} events valid" if not se else "", se[:20])

    # 3. counter has no gaps + capture gaps
    hashes = {}
    for r in recs:
        if r:
            s = r.get("seq") if r.get("elided") else (r.get("event") or {}).get("seq")
            hashes[s] = r.get("hash")
    seqs = sorted(k for k in hashes if isinstance(k, int))
    gaps = [f"missing seq {a + 1}..{b - 1}" for a, b in zip(seqs, seqs[1:]) if b != a + 1]
    if seqs and seqs[0] != 0:
        gaps.insert(0, f"records before seq {seqs[0]} missing")
    rep.check("counter has no gaps", not gaps, f"seq 0..{seqs[-1] if seqs else '-'} contiguous" if not gaps else "", gaps)
    # the manifest is not signed, so it cannot narrow what gets checked: every event that is present
    # (not elided) belongs to the selection, whatever the manifest claims
    sel_runs = set(manifest.get("selection", {}).get("runs", []) or []) | \
        {e.get("run_id") for e in events if e.get("run_id") != "_signer"}
    seq_range = manifest.get("seq_range")
    if isinstance(seq_range, list) and len(seq_range) == 2 and seqs and seq_range[1] != seqs[-1]:
        rep.check("manifest range", False, "", [f"manifest says the bundle ends at seq {seq_range[1]} but the last record is {seqs[-1]}"])
    sel = [e for e in events if e.get("run_id") in sel_runs]
    cg = [e for e in events if e.get("type") == "capture.gap" and (e.get("run_id") in sel_runs or e.get("run_id") == "_signer")]
    rep.check("capture gaps", not cg, "no capture.gap events" if not cg else "",
              [f"seq {e['seq']}: {e['data'].get('reason')}" for e in cg][:20], warn=True)
    # 0.2.1: writes the signer refused for these runs (e.g. another user writing into the run) are evidence too
    rj = [e for e in events if e.get("type") == "error" and e.get("run_id") == "_signer"
          and (e.get("data") or {}).get("client_run_id") in sel_runs]
    rep.check("rejected writes", not rj, "none" if not rj else "",
              [f"seq {e['seq']}: {e['data'].get('message')}" for e in rj][:20], warn=True)
    # 3b. run completeness: a v1 stub is signed over (hash, prev_hash, seq) only, so nothing says which run it
    #     belonged to, and a stub of a selected run looks exactly like a stub of another run
    stubs = sum(1 for r in recs if r and r.get("elided"))
    rep.check("run completeness", not stubs, "no elided records: every record in the bundle is whole" if not stubs else "",
              [f"{stubs} elided record(s): v1 signatures do not bind a stub to its run"] +
              [f"run {x}: run completeness unproven (v1 bundle with elided records)" for x in sorted(map(str, sel_runs))][:20],
              warn=True)
    bound_runs = sorted(str(x) for x in sel_runs if not str(x).startswith(COMPANION_PREFIXES))
    run_ends = {x: max((e["seq"] for e in sel if e.get("run_id") == x and e.get("type") == "run.end"), default=None)
                for x in bound_runs}
    rb = [] if sel_runs else ["no selected run has a record in the bundle"]
    for x in bound_runs:
        if not any(e.get("run_id") == x and e.get("type") == "run.start" for e in sel):
            rb.append(f"run {x}: run boundaries unproven (no run.start in the bundle)")
        if run_ends[x] is None:
            rb.append(f"run {x}: tail unproven (no signed run.end in the bundle; the run may have continued)")
    rep.check("run boundaries", not rb, f"run.start and run.end present for {len(bound_runs)} run(s)" if not rb else "",
              rb[:20], warn=True)

    # 4. head matches a witness checkpoint
    cps, cp_probs = [], []
    for l in blobs.get("checkpoints.jsonl", b"").decode("utf-8", "replace").splitlines():
        if not l.strip():
            continue
        try:
            c = json.loads(l)
        except ValueError:
            c = None
        if isinstance(c, dict) and isinstance(c.get("head_seq"), int) and isinstance(c.get("head_hash"), str):
            cps.append(c)
        else:
            cp_probs.append("checkpoints.jsonl contains a line that is not a checkpoint")
    for c in cps:
        if not verify_checkpoint(c, pub) or c.get("kid") != kid:
            cp_probs.append(f"checkpoint seq {c.get('head_seq')}: signature invalid or wrong key (forged or replayed)")
        elif c["head_seq"] not in hashes:
            cp_probs.append(f"checkpoint seq {c['head_seq']} is beyond the last record in the bundle (records truncated)")
        elif hashes[c["head_seq"]] != c["head_hash"]:
            cp_probs.append(f"checkpoint seq {c['head_seq']}: head {c['head_hash'][:12]} does not match record {hashes[c['head_seq']][:12]} (chain rewritten)")
    wit_names, wit_seqs = [], set()
    bundle_end = seqs[-1] if seqs else -1
    bundle_cp_seqs = {c.get("head_seq") for c in cps}
    for spec in witness_specs:
        try:
            w = from_spec(spec)
            allw = w.read(pub) if getattr(w, "needs_public", False) else w.read()
            wcps = [c for c in allw if c.get("kid") == kid]
        except Exception as e:
            cp_probs.append(f"witness {spec}: unreadable ({e})"); continue
        wit_names.append(w.name)
        if allw and not wcps:
            cp_probs.append(f"witness {w.name} holds {len(allw)} checkpoint(s) but none signed by this bundle's key {kid} "
                            "(bundle re-signed with a different key?)")
        later = [c["head_seq"] for c in wcps if c["head_seq"] > bundle_end and verify_checkpoint(c, pub)]
        if later and bundle_end not in bundle_cp_seqs and bundle_end not in {c["head_seq"] for c in wcps}:
            cp_probs.append(f"bundle ends at seq {bundle_end}, between checkpoints, while witness {w.name} shows the ledger "
                            f"continued to seq {max(later)} (records truncated; re-export to get a complete bundle)")
        for c in wcps:
            if not verify_checkpoint(c, pub):
                cp_probs.append(f"witness {w.name} seq {c.get('head_seq')}: invalid checkpoint signature"); continue
            if c["head_seq"] in hashes and hashes[c["head_seq"]] != c["head_hash"]:
                cp_probs.append(f"witness {w.name} holds head {c['head_hash'][:12]} for seq {c['head_seq']} but the bundle has "
                                f"{hashes[c['head_seq']][:12]} (chain rebuilt after checkpointing)")
                continue
            wit_seqs.add(c["head_seq"])
        cps += [c for c in wcps if c not in cps]
    # 4a. with a witness: a bundle that stops before the first witnessed checkpoint at or after a run's run.end hides
    #     how the ledger continued. Only that is evidence of a cut; an open run (no run.end) or a witness that has not
    #     yet seen a checkpoint past run.end is already reported by "run boundaries" or is simply not anchored yet.
    if wit_names:
        tw = []
        for x in bound_runs:
            first = min((s for s in wit_seqs if run_ends[x] is not None and s >= run_ends[x]), default=None)
            if first is not None and first > bundle_end:
                tw.append(f"run {x}: tail not covered by a witnessed checkpoint (run.end at seq {run_ends[x]}; first "
                          f"witnessed checkpoint after it is seq {first}, beyond the bundle's last record {bundle_end})")
        rep.check("run tail witnessed", not tw, "no run.end is followed by a witnessed checkpoint the bundle omits"
                  if not tw else "", tw[:20])
    sel_last = max((e["seq"] for e in sel), default=-1)
    good = [c for c in cps if verify_checkpoint(c, pub) and hashes.get(c["head_seq"]) == c["head_hash"]]
    covered = any(c["head_seq"] >= sel_last for c in good)
    if cp_probs:
        rep.check("head matches a witness checkpoint", False, "", cp_probs[:20])
    elif not covered:
        last_cp = max((c["head_seq"] for c in good), default=None)
        tail = [e for e in sel if last_cp is None or e["seq"] > last_cp]
        rep.check("head matches a witness checkpoint", False, "",
                  [f"selected records up to seq {sel_last}; last valid checkpoint is at "
                   f"{last_cp if last_cp is not None else 'none'}: {len(tail)} selected event(s) are signed but not witnessed, "
                   "so they are not protected against truncation or a rebuild with the key"], warn=True)
    else:
        rep.check("head matches a witness checkpoint", True,
                  f"covered by checkpoint(s) {sorted(c['head_seq'] for c in good if c['head_seq'] >= sel_last)[:3]}"
                  + (f"; checked against {', '.join(wit_names)}" if wit_names else "; bundled checkpoints only (pass --witness to check an independent copy)"))
    # 4b. trust root: the bundle carries its own key and checkpoints, so on its own it only proves
    #     internal consistency. Something outside it must vouch for the signer key.
    anchors, ap = [], []
    if trusted_key:
        try:
            tpub, tkid = _load_trusted_key(trusted_key)
            if tkid != kid or (tpub is not None and tpub != pub):
                ap.append(f"bundle is signed by {kid}, but the trusted key is {tkid}")
            else:
                anchors.append(f"signer key pinned ({tkid})")
        except (OSError, ValueError) as e:
            ap.append(f"trusted key {trusted_key!r} unreadable: {e}")
    if wit_names and not cp_probs:
        anchors.append(f"witness {', '.join(wit_names)} holds checkpoints by this key")
    if ap:
        rep.check("trust root", False, "", ap)
    elif anchors:
        rep.check("trust root", True, "; ".join(anchors))
    else:
        rep.check("trust root", False, "UNANCHORED", [
            "nothing outside the bundle vouches for its signer key or checkpoints: this proves the bundle is internally "
            "consistent, not who signed it or that it matches the real ledger. Pass --key <signer.pub> and/or --witness <copy>."],
            warn=True)

    # 4c. where the signing key lives, as stated (and signed) in the checkpoints: informative, not attested
    valid_cps = [c for c in cps if verify_checkpoint(c, pub) and c.get("kid") == kid]
    if valid_cps:
        kinds = sorted({c.get("key_assurance", "file") for c in valid_cps})
        if kinds == ["file"]:
            rep.check("signing key", False, "file key on the signer host", [
                "the private key is a file: root on the signer host can copy it. Use an external signer (TPM, HSM, enclave) "
                "and an external witness to remove that."], warn=True)
        else:
            att = sorted({c.get("key_attestation_sha256") for c in valid_cps} - {None})
            missing = [h for h in att if sha256_hex(blobs.get(f"attestation/{h}.bin", b"")) != h]
            problems = [] if len(kinds) == 1 else [f"key storage changed within the bundle: {kinds}"]
            problems += [f"checkpoints name attestation document sha256:{h[:16]}… but the bundle does not carry it" for h in missing]
            if att and not missing:
                detail = (f"{', '.join(kinds)}, with the device's attestation document in the bundle (attestation/"
                          f"{att[-1][:16]}….bin, named in the signed checkpoints). Tracekit checked it is that document; check "
                          "its contents (certificate chain, that it binds this public key) with the vendor's tools")
            else:
                detail = f"{', '.join(kinds)} (stated by the signer and signed into its checkpoints; no attestation document)"
            rep.check("signing key", not problems, detail, problems, warn=True)

    # 5. policy hash consistent: every run.start and every decision names a snapshot in the bundle,
    #    the snapshot hashes to that name, and every rule a decision cites exists in its snapshot
    pp, pw, snaps = [], [], {}

    def snapshot(h):
        if h not in snaps:
            blob = blobs.get(f"policies/{h.split(':')[1]}.json")
            pol = None
            if blob is not None:
                try:
                    pol = json.loads(blob)
                    if policy_hash(pol) != h:
                        pp.append(f"policy snapshot {h[:19]} does not hash to its name")
                        pol = None
                except ValueError:
                    pp.append(f"policy snapshot {h[:19]} is not JSON")
            snaps[h] = pol
        return snaps[h]
    start_hash = {}
    for e in sel:
        if e["type"] == "run.start":
            h = e["data"]["policy"]["hash"]
            start_hash[e["run_id"]] = h
            if snapshot(h) is None:
                pp.append(f"run {e['run_id']}: policy snapshot {h[:19]} not in bundle")
    for d in sel:
        if d["type"] != "policy.decision":
            continue
        h = d["data"].get("policy_hash") or start_hash.get(d["run_id"])
        if not h:
            continue
        pol = snapshot(h)
        if pol is None:
            pp.append(f"seq {d['seq']}: decision made under policy {h[:19]}, which is not in the bundle")
            continue
        if d["data"].get("policy_hash") and start_hash.get(d["run_id"]) and h != start_hash[d["run_id"]]:
            pw.append(f"seq {d['seq']}: policy changed during run {d['run_id']} ({start_hash[d['run_id']][:19]} -> {h[:19]})")
        ids = {r["id"] for s in ("deny", "ask", "flag") for r in pol.get(s, []) or []} | {"TK-SCOPE"}
        unknown = [i for i in d["data"]["rule_ids"] if i not in ids]
        if unknown:
            pp.append(f"seq {d['seq']}: decision cites rule(s) {unknown} not in policy {h[:19]}")
    rep.check("policy hash consistent", not pp, "every decision is bound to a policy snapshot in the bundle and cites rules "
              "that exist in it" if not pp else "", pp[:20])
    if pw:
        rep.check("policy unchanged during run", False, "", pw[:20], warn=True)

    # 5b. signed findings must cite evidence that is in the bundle, unaltered
    from .findings import check_bundle
    fnd = [e for e in sel if e.get("type") == "review" and str(e.get("run_id", "")).startswith("findings:")]
    if fnd:
        fp = check_bundle(fnd, hashes)
        sev = {}
        for e in fnd:
            v = e["data"].get("verdict") or {}
            sev[v.get("severity", "?")] = sev.get(v.get("severity", "?"), 0) + 1
        rep.check("findings cite intact evidence", not fp, f"{len(fnd)} signed finding(s) (" +
                  ", ".join(f"{k}: {v}" for k, v in sorted(sev.items())) + "), every cited record present and unaltered"
                  if not fp else "", fp[:20])

    # 6. capture sources used (C1): every event carries its source; say how much each is worth
    counts = {}
    for e in sel:
        counts[e["source"]] = counts.get(e["source"], 0) + 1
    declared = sorted({x for e in sel if e["type"] == "run.start" for x in e["data"].get("capture_sources", [])})
    missing = [x for x in declared if x not in counts]
    rep.check("capture sources", not missing,
              "; ".join(f"{k}: {v} events ({TRUST.get(k, k)})" for k, v in sorted(counts.items())),
              [f"run.start declared capture source {x!r} but no {x} events were recorded" for x in missing], warn=True)

    # 6a. harness attribution (0.3): in system mode, was each hook run started by a registered harness process?
    hook_starts = [e for e in sel if e["type"] == "run.start" and e["source"] in ("hook", "transcript")
                   and e["data"].get("os_user_attested")]
    if hook_starts:
        unbound = [e for e in hook_starts if not (e["data"].get("harness") or {}).get("attested")]
        bound = [e["data"]["harness"] for e in hook_starts if e not in unbound]
        rep.check("harness attribution", not unbound,
                  "; ".join(sorted({f"{h['name']} ({h['exe']}), pid {h['pid']}" for h in bound}))
                  + " (signer-attested from the kernel's process tree)" if not unbound else "",
                  [f"run {e['run_id'][:80]}: no harness binding, so its hook events could have been sent by any process "
                   "running as the agent's user (tracekit init --harness)" for e in unbound][:20], warn=True)

    # 6b. trace tampering (C2) and approvals (C8): findings about the run, not about the bundle
    tt = [e for e in events if e.get("type") == "trace.tamper" and (e.get("run_id") in sel_runs or e.get("run_id") == "_signer")]
    marks = sum(1 for e in sel if e.get("transcript"))
    rep.check("harness transcript unchanged", not tt, (f"prefix matched at all {marks} transcript marks" if marks else
                                                        "no transcript marks recorded (harness sent no transcript_path)") if not tt else
              "TRACE TAMPERING DETECTED", [f"seq {e['seq']}: {e['data'].get('kind', 'changed')} {e['data']['path']} "
                                           f"(length {e['data']['before'].get('length')} -> {e['data']['after'].get('length')})" for e in tt][:20],
              warn=True)
    ap = [e for e in sel if e["type"] == "approval"]
    if ap:
        refused = [e for e in ap if e["data"]["decision"] == "self_approval_refused"]
        weak = [e for e in ap if e["data"]["decision"] == "approve" and e["data"].get("same_user")]
        rep.check("approvals", not refused and not weak, "; ".join(f"{e['data']['tool_use_id']}: {e['data']['decision']} by {e['data']['approver']}"
                                                       for e in ap if e["data"]["decision"] != "self_approval_refused")[:400],
                  [f"seq {e['seq']}: self-approval attempt refused ({e['data']['channel']})" for e in refused] +
                  [f"seq {e['seq']}: approved by the agent's own OS user (same user, not trustworthy)" for e in weak], warn=True)

    # 7. coverage warnings (recomputed, never trusted from the bundle)
    cov = coverage.report(sel)
    rep.check("coverage", not cov["warnings"] and not cov["unsupported_used"], cov["summary"],
              cov["warnings"] + [f"unsupported path used: {u}" for u in cov["unsupported_used"]], warn=True)

    # 8. opt-in capture
    modes = sorted({(e["data"].get("content_capture"), e["data"].get("reasoning_capture")) for e in sel if e["type"] == "run.start"})
    txt = "; ".join(f"content_capture={c}, reasoning_capture={'on' if r else 'off'}" for c, r in modes) or "no run.start"
    full = any(c == "full" or r for c, r in modes)
    rep.check("opt-in content capture", not full, txt, [txt] if full else [], warn=True)

    # 9. assurance: a same-user (dev mode) signer could have been rewritten by the agent, whatever integrity says
    iso = sorted({str(e["data"].get("signer_isolation")) for e in sel if e["type"] == "run.start"})
    rep.assurance = ("dev (signer ran as the agent's own user: the agent could have rewritten the ledger)"
                     if not iso or "same-user" in iso else f"signer_isolation={', '.join(iso)} (as stated in run.start)")

    code = EXIT_FAIL if rep.failures else (EXIT_WARN if strict and rep.warnings else EXIT_OK)
    return rep, code


GAP_CHECKS = ("capture gaps", "rejected writes", "run completeness", "run boundaries")


def print_report(rep, code, stream=None):
    import sys
    s = stream or sys.stdout
    icon = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
    for c in rep.checks:
        s.write(f"[{icon[c['status']]}] {c['check']}" + (f" — {c['detail']}" if c["detail"] else "") + "\n")
        for p in c["problems"]:
            s.write(f"        {p}\n")
    verdict = {EXIT_OK: "VERIFIED", EXIT_FAIL: "VERIFICATION FAILED", EXIT_BAD: "UNUSABLE BUNDLE", EXIT_WARN: "VERIFIED WITH WARNINGS (strict)"}[code]
    gappy = [c["check"] for c in rep.checks if c["check"] in GAP_CHECKS and c["status"] == "warn"]
    if code == EXIT_OK and gappy:  # 0.2.1: a gap in what was captured is never reported as a clean VERIFIED
        verdict = "VERIFIED WITH GAPS (" + ", ".join(gappy) + ")"
    if code in (EXIT_OK, EXIT_WARN) and any(c["check"] == "trust root" and c["status"] != "pass" for c in rep.checks):
        verdict += " BUT UNANCHORED (internally consistent only; no trusted key or witness was checked)"
    for n in rep.notes:
        s.write(f"warning: {n}\n")
    s.write(f"\nIntegrity: {verdict}.\nAssurance: {getattr(rep, 'assurance', None) or 'unknown (no run.start checked)'}.\n"
            f"Tracekit proves what its capture path recorded and that it has not changed since it was "
            f"signed and checkpointed. It does not prove intent, complete coverage, or that reported results are real.\n")
