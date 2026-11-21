"""Regenerate the v2 conformance kit. Run by hand only, like tests/golden/make_golden.py:

    python3 tests/kit/make_kit.py

Writes cases.json: every v2 bundle of tests/golden (with its recorded verdict) and every bundle of vectors/ (built
here from fixed keys, with the verdict docs/format-v2.md rules for it) as a case

    {name, input, trust, exit, verdict, level, failed_check, decided_by}

plus `addon` (a verifier without that add-on may answer UNVERIFIABLE instead), `needs` (the case's manifest asks for
that format version: a verifier implementing an older one answers UNVERIFIABLE) and `proposed` (the format text is
silent and the case holds the rule proposed for it). No report text is compared: `verdict` is the integrity line
without its wording, `level` the first word of the assurance line when the bundle verifies, `failed_check` the checks
of which a failing verifier's first failed one must be one. Paths are relative to tests/. The primitive vectors
(tests/vectors) are listed under `primitives`: each implementation's own tests reproduce them. run_kit.py scores
a verifier against the kit."""
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

KIT = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(KIT)
ROOT = os.path.dirname(TESTS)
VECTORS = os.path.join(KIT, "vectors")
sys.path.insert(0, ROOT)
sys.path.insert(0, TESTS)
import test_bundle_v2 as tb  # noqa: E402
from factories import rewrite_bundle  # noqa: E402
from tracekit import crypto  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.format import checkpoint, registry  # noqa: E402
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.storage.base import registry_tree  # noqa: E402

TSALT = registry.tenant_salt(b"\x01" * 32, "acme")
KID1 = crypto.spki_kid(crypto.spki(tb.pub(tb.KEY1)))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# the section of docs/format-v2.md that decides each golden case, by the check its verdict turns on
SECTION = {"bundle readable": "§9 (zip layout and limits), §11 step 2", "bundle structure": "§9 (JSON lines), §11",
           "manifest": "§9, §11 step 3", "checkpoint": "§6, §11 step 4", "witness quorum": "§10, §11 step 4",
           "keys": "§4 (key epochs and positional retirement), §11 step 5",
           "signatures": "§4, §11 step 6", "run chain": "§11 step 6", "inclusion": "§5, §11 step 6",
           "run parts": "§9 (a run in parts)", "run-set": "§7, §11 step 7", "policy snapshot": "§11 step 9",
           None: "§11 step 11"}
DECIDED = {   # golden cases another section decides
    "json-manifest-duplicate-key.tkb": "§1 (strict JSON), §11 step 2", "json-record-duplicate-key.tkb": "§1, §9",
    "json-manifest-too-deep.tkb": "§1 (strict JSON), §11 step 2", "json-record-too-deep.tkb": "§1, §9",
    "manifest-format-v1.tkb": "§11 step 2", "manifest-newer-verifier.tkb": "§9 (verifier_min_version), §11 step 2",
    "record-schema-invalid.tkb": "§3, §11 step 6", "record-alg-confusion.tkb": "§4 (algorithms)",
    "key-used-after-retire.tkb": "§4 (key epochs and positional retirement)",
    "run-closing-without-final.tkb": "§9 (a run reads open until its run.final), §11 step 11",
    "run-set-float-bound.tkb": "§7 (from and to are integer tokens)",
    "extra-trust-file.tkb": "§9 (no code and no trust configuration in a bundle)",
    "run-second-run.tkb": "§11 step 6 (one run, with its findings, or a run-set)",
    "findings-run-twice.tkb": "§11 step 6 (no two runs share a tenant and run_id)",
    "run-set-run-twice.tkb": "§11 step 6 (no two runs share a tenant and run_id)",
}


GOLDEN_V2 = {("closed.tkb", "trust.json"): "§11 step 11", ("closed.tkb", "trust-rekor.json"): "§8, §11 step 4",
             ("open.tkb", "trust.json"): "§11 step 11 (a run without its run.final reads open)",
             ("approval.tkb", "trust.json"): "§11 step 11 (a self-approval makes the assurance dev)",
             ("run-set.tkb", "trust.json"): "§7, §11 step 7 (the registry notes cap the assurance)"}


def verdict(integrity):
    """The verdict an integrity line states, without its wording."""
    m = re.fullmatch(r"VERIFIED TO HEAD (\d+) \(open\)|VERIFIED \((\d+) run\(s\) open\)", integrity)
    return (f"VERIFIED TO HEAD {m[1]}" if m and m[1] else f"VERIFIED, {m[2]} OPEN" if m else
            "UNVERIFIABLE" if integrity.startswith("UNVERIFIABLE") else integrity)


def rel(path):
    return os.path.relpath(path, TESTS).replace(os.sep, "/")


def reference(bundle, trust):
    """(exit, integrity, assurance level, failed checks in order) of the reference verifier, in process."""
    from tracekit.verify import v2
    rep, code = v2.verify(bundle, trust)
    return code, rep.integrity, rep.assurance.split(";")[0] if code == 0 else None, [
        c["check"] for c in rep.checks if c["status"] == "fail"]


def golden_cases():
    golden, out = os.path.join(TESTS, "golden"), []
    with open(os.path.join(golden, "v2", "expected.json"), encoding="utf-8") as f:
        for c in json.load(f)["cases"]:
            bundle, trust = (os.path.join(golden, "v2", c["args"][i]) for i in (0, 2))
            code, integrity, level, fails = reference(bundle, trust)
            assert (code, f"Integrity: {integrity}.") == (c["expected"]["exit_code"], c["expected"]["integrity"]), \
                c["name"]   # recorded as the CLI prints it
            out.append({"name": c["name"], "input": rel(bundle), "trust": rel(trust), "exit": code,
                        "verdict": verdict(integrity), "level": level, "failed_check": fails or None,
                        "decided_by": GOLDEN_V2[c["args"][0], c["args"][2]],
                        **({"addon": "rekor anchor"} if "rekor" in c["args"][2] else {})})
    for d in ("negative", "parts"):
        with open(os.path.join(golden, d, "expected.json"), encoding="utf-8") as f:
            for c in json.load(f)["cases"]:
                bundle, trust = os.path.join(golden, d, c["bundle"]), os.path.join(golden, d, "trust.json")
                code, integrity, level, fails = reference(bundle, trust)
                want = c["expected"]
                assert (code, integrity, fails[0] if fails else None) == (
                    want["exit_code"], want["integrity"], want["first_failure"]), c["name"]
                need = re.fullmatch(r"UNVERIFIABLE \(needs tracekit >= (.+)\)", integrity)
                out.append({"name": c["name"], "input": rel(bundle), "trust": rel(trust), "exit": code,
                            "verdict": verdict(integrity), "level": level, "failed_check": fails or None,
                            "decided_by": DECIDED.get(c["bundle"], SECTION[want["first_failure"]]),
                            **({"needs": need[1]} if need else {})})
    return out


# ---- the vectors: bundles of test_bundle_v2.Log logs (fixed keys and times) ----

def trust(name, **over):
    path = os.path.join(VECTORS, f"trust-{name}.json" if name else "trust.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({**tb.trust_config(), **over}, f, indent=1)
    return path


def log():
    """A new log whose first record declares KEY1."""
    lg = tb.Log(os.path.join(VECTORS, ".stores", str(len(os.listdir(os.path.join(VECTORS, ".stores"))))))
    lg.epoch(tb.KEY1)
    return lg


def fixed(path):
    """The zip at `path` rewritten with fixed entry times: the kit regenerates to the same bytes."""
    with zipfile.ZipFile(path) as z:
        entries = [(i.filename, z.read(i)) for i in z.infolist()]
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries:
            z.writestr(zipfile.ZipInfo(name, (2026, 10, 9, 12, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return path


def bundle_of(lg, name, run="run-a", witnesses=((tb.WITNESS, tb.WIT_SECRET),), **kw):
    path = os.path.join(VECTORS, name + ".tkb")
    export(lg.store, "acme", run, lg.note(witnesses=witnesses), path, **kw)
    lg.store.close()
    return fixed(path)


def closed(name, *records, **kw):
    """A closed run-a: run.registered, `records` ((type, data, fields)), run.final."""
    lg = log()
    lg.register()
    for typ, data, fields in records:
        lg.add(typ, data, **fields)
    lg.final()
    return bundle_of(lg, name, **kw)


def mutated(name, src, edit):
    path = os.path.join(VECTORS, name + ".tkb")
    rewrite_bundle(src, path, edit)
    return fixed(path)


def run_file(files):
    return next(k for k in files if k.startswith("runs/"))


def respell(pattern, repl, where=None):
    """An edit that writes the first match of `pattern` in the run file (or `where`) as `repl`: the same value."""
    def edit(files, manifest):
        k = where or run_file(files)
        files[k] = re.sub(pattern.encode(), repl.encode(), files[k], count=1)
    return edit


def loose_base64(s):
    """The same bytes as standard base64 `s`, with a spare bit set: not canonical (RFC 4648 §3.5)."""
    pad = len(s) - len(s.rstrip("="))
    i = len(s) - pad - 1
    return s[:i] + ALPHABET[ALPHABET.index(s[i]) | 1] + s[i + 1:]


def loose_sig(files, manifest):
    k = run_file(files)
    lines = files[k].splitlines(keepends=True)
    sig = json.loads(lines[1])["sig"]
    lines[1] = lines[1].replace(sig.encode(), loose_base64(sig).encode())
    files[k] = b"".join(lines)


def loose_proof(files, manifest):
    p = json.loads(files["proofs/records.json"])
    path = next(v for v in p["inclusion"].values() if v)
    path[0] = loose_base64(path[0])
    files["proofs/records.json"] = json.dumps(p).encode()


def malleated(files, manifest):   # S + L: the cofactorless equation still holds, S is not below L (§4)
    L = 2 ** 252 + 27742317777372353535851937790883648493
    k = run_file(files)
    lines = files[k].splitlines(keepends=True)
    for i, line in enumerate(lines):
        sig = json.loads(line)["sig"]
        raw = base64.b64decode(sig)
        s = int.from_bytes(raw[32:], "little") + L
        if s < 2 ** 256:
            lines[i] = line.replace(sig.encode(), base64.b64encode(raw[:32] + s.to_bytes(32, "little")))
            files[k] = b"".join(lines)
            return
    raise ValueError("no record whose S + L fits 32 bytes")


def manifest_version(version):
    return lambda files, manifest: manifest.update(verifier_min_version=version)


def run_set(name, lg, selected=None):
    """A run-set 0..b of acme's registry: a leaf per run.registered and run.final, cosigned like the record note."""
    for r in lg.store.iter_range(0, lg.store.tree.size):
        if r["event"]["type"] in ("run.registered", "run.final"):
            lg.store.registry_append("acme", registry.leaf(r, TSALT))
    reg, origin = lg.store.registry_merkle("acme"), registry.origin(tb.ORIGIN, TSALT)
    text = checkpoint.body(origin, reg.size, reg.root_at(reg.size))
    lg.store.checkpoint_put(reg.size, text + "\n" + checkpoint.sign(text, origin, tb.LOG_SECRET)
                            + tb.cosign(text, tb.WITNESS, tb.WIT_SECRET, 1760000000), registry_tree("acme"))
    return bundle_of(lg, name, run=selected, run_set=(0, reg.size), tenant_salt=TSALT)


def certified(name):
    """run-a under a record key with an issuer's certificate (docs/issuer.md), and the issuer's pin."""
    from unittest import mock

    import test_issuer as ti
    from tracekit import issuer
    from tracekit.signer import logkey
    ca, issuance = (logkey.FileKey(hashlib.sha256(s).digest()) for s in (b"kit issuer", b"kit issuance log"))
    iss = issuer.Issuer(os.path.join(VECTORS, ".stores", "issuer"), ti.NAME, ti.ISSUANCE, ti.scopes(),
                        [ti.StubWitness()], ca_key=ca, log_key=issuance, clock=lambda: ti.T0)
    lg = tb.Log(os.path.join(VECTORS, ".stores", "certified"))
    der = crypto.spki(tb.pub(tb.KEY1))
    with mock.patch.object(issuer.secrets, "token_hex", return_value="5e" * 16):   # the serial: fixed bytes
        entry = iss.issue(ti.SVC, ti.request(tb.KEY1))
    lg.add("signer.epoch", {"keys": [{"kid": KID1, "alg": "ed25519", "spki": base64.b64encode(der).decode(),
                                      "cert": entry}]}, run="signer")
    lg.register()
    lg.call()
    lg.final()
    return bundle_of(lg, name), {"vkey": iss.vkey, "issuance_log_vkey": iss.log_vkey}


TS0, H = "2026-10-09T12:00:00.000000Z", "sha256:" + "d" * 64
ASKED = {"approval_id": "a1", "policy_hash": H, "rule_ids": ["PAY"], "expires_at": TS0, "requester": "uid:1",
         "decision_id": "d1", "binding_digest": H,
         "binding": {"v": 1, "approval_id": "a1", "tenant": "acme", "run_id": "run-a", "tool_call_id": "t1",
                     "attempt": 0, "tool": "pay", "args_commitment": "hmac-sha256:" + "1" * 64, "args_source": "raw",
                     "policy_hash": H, "nonce": "a" * 32, "expires_at": TS0}}


# A minimal schema-valid record of every event type of the core and the agent profile that a run holds (key records
# and log.closed are the signer run's): one closed run of them all
EVERY_TYPE = [
    ("run.start", {"agent": {"name": "x"}, "host": "x", "os_user": "x", "fail_mode": "closed",
                   "policy": {"version": "1", "hash": "sha256:" + "d" * 64}, "capture_sources": [], "sandbox": "none",
                   "content_capture": "hashed", "signer_isolation": "separate-user"}),
    ("run.end", {"reason": "x"}), ("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}),
    ("policy.decision", {"tool_use_id": "t1", "decision": "allow", "rule_ids": []}),
    ("tool.result", {"tool_use_id": "t1", "ok": True, "output": {"value": "x", "redacted": False}}),
    ("error", {"message": "x"}), ("trace.tamper", {"path": "x", "before": {}, "after": {}}),
    ("capture.gap", {"reason": "x"}),
    ("checkpoint", {"head_seq": 0, "head_hash": "b" * 64, "kid": "x", "witnesses": []}),
    ("user.prompt", {"content": {"value": "x", "redacted": False}}),
    ("model.message", {"kind": "text", "content": {"value": "x", "redacted": False}}),
    ("model.exchange", {"exchange_id": "x", "phase": "request", "streamed": False}),
    ("run.closing", {"reason": "close_run"}),
    ("approval.request", ASKED),
    ("approval", {"tool_use_id": "t1", "decision": "approve", "approver": "x", "channel": "x"}),
    ("approval.consumed", {"approval_id": "a1"}), ("approval.expired", {"approval_id": "a1"}),
    ("approval.refused", {"tool_use_id": "t1", "rule_ids": [], "reason": "x"}),
    ("approval.binding_mismatch", {"approval_id": "a1", "tool_use_id": "t1", "approved_commitment":
                                   "hmac-sha256:" + "1" * 64, "args_commitment": "hmac-sha256:" + "2" * 64}),
    ("approval.abandoned", {"approval_id": "a1"}), ("approval.escalated", {"approval_id": "a1", "by": "agent"}),
    ("approval.revoked", {"approval_id": "a1", "by": "x"}),
    ("approval.agents", {"enabled": False, "by": "x"}),
    ("state.write", {"store": "x", "key": "x", "digest": "hmac-sha256:" + "1" * 64}),
    *((f"reconcile.{k}", {"layers": []}) for k in ("hook_missing", "fabricated", "args_mismatch",
                                                    "result_without_call", "args_unparseable", "result_mismatch")),
    ("reconcile.unexplained_effect", {"layers": [], "observer": "x", "kind": "net", "host": "x"}),
    ("refusal.summary", {"code": "x", "count": 1, "from_ts": "2026-10-09T12:00:00.000000Z",
                         "to_ts": "2026-10-09T12:00:00.000000Z"}),
    ("content.accessed", {"principal": "x", "run_id": "x", "seqs": [], "purpose": "x"}),
    ("content.erased", {"run_id": "x", "reason": "x", "by": "x"}), ("run.child", {"run_id": "x"}),
    ("effect.observed", {"observer": "x", "kind": "net", "host": "x", "port": 1, "bytes_out": 0, "bytes_in": 0,
                         "connections": 0, "first_ts": "2026-10-09T12:00:00.000000Z",
                         "last_ts": "2026-10-09T12:00:00.000000Z", "attribution": "identity"}),
    ("constraint.added", {"kind": "no_push"}),
]

# a compiled policy with a run condition (docs/policy-v2.md#run-conditions), as a signer's policies/ keeps it
LABELLED_BYTES = json.dumps({"tools": {"read_file": "fs"},
                             "flag": [{"id": "SECRET", "class": "fs", "pattern": "\\.env", "label": "secrets_access"},
                                      {"id": "EGRESS", "field": "target", "pattern": "://", "label": "egress"}],
                             "ask": [{"id": "SEND", "field": "labels", "pattern": "(?:^| )egress(?: |$)",
                                      "when": {"run_has": ["secrets_access"]}}]},
                            sort_keys=True, separators=(",", ":")).encode()
LABELLED_HASH = "sha256:" + hashlib.sha256(LABELLED_BYTES).hexdigest()
V = "§11 step 11"
VECTOR_CASES = []


def case(name, path, trust_path, exit, verdict, level=None, failed_check=None, decided_by=V, **extra):
    VECTOR_CASES.append({"name": name, "input": rel(path), "trust": rel(trust_path), "exit": exit, "verdict": verdict,
                         "level": level, "failed_check": failed_check, "decided_by": decided_by, **extra})


def vectors():
    shutil.rmtree(VECTORS, ignore_errors=True)
    os.makedirs(os.path.join(VECTORS, ".stores"))
    t = trust(None)
    dev = trust("dev", witnesses_required=0)

    # the core and the agent profile: every record type, levels, key rotation
    every = closed("every-type", *((typ, data, {}) for typ, data in EVERY_TYPE))
    case("every event type of a run, one closed run", every, t, 0, "VERIFIED", "witnessed",
         decided_by="§3, §11 step 6")
    lg = log()
    lg.register()
    lg.call()
    case("no cosignature, none required", bundle_of(lg, "no-witness", witnesses=()), dev, 0, "VERIFIED TO HEAD 1",
         "dev", decided_by="§10, §11 step 11")
    lg = log()
    lg.register()
    lg.final()
    case("cosigned by an operator witness only", bundle_of(lg, "operator-witness",
                                                           witnesses=((tb.OPERATOR, tb.OP_SECRET),)),
         dev, 0, "VERIFIED", "local", decided_by="§10 (classes), §11 step 11")
    lg = log()
    lg.register()
    lg.call()
    lg.key = tb.KEY2   # the signer's order: the new key's epoch, signed by it, then the old key's retirement
    lg.epoch(tb.KEY2)
    lg.add("key.retire", {"kid": KID1, "last_seq": lg.store.tree.size - 2}, run="signer")
    lg.call()
    lg.final()
    case("a rotated record key", bundle_of(lg, "rotated"), t, 0, "VERIFIED", "witnessed",
         decided_by="§4 (key epochs and positional retirement), §11 step 5")
    lg = log()
    lg.register()
    lg.call()
    lg.add("key.retire", {"kid": KID1, "last_seq": lg.store.tree.size - 1}, run="signer")   # signed by KEY1, after it
    lg.key = tb.KEY2
    lg.epoch(tb.KEY2)
    lg.call()
    lg.final()
    case("a key.retire signed by the key it retires, after that key's last_seq", bundle_of(lg, "retire-self-signed"),
         t, 1, "FAILED", failed_check=["keys"],
         decided_by="§4 (a record is valid only under a key valid at its own seq)")
    case("a record whose S is not below L", mutated("signature-s-plus-l", every, malleated), t, 1, "FAILED",
         failed_check=["signatures"], decided_by="§4 (algorithms: S < L)")
    lg = log()
    lg.register()
    lg.final()
    for typ, data in (("content.accessed", {"principal": "x", "run_id": "run-a", "seqs": [1], "purpose": "audit"}),
                      ("capture.gap", {"kind": "late_activity", "run_id": "run-a", "missed_events": 1,
                                       "reason": "x", "from_ts": TS0, "to_ts": TS0})):
        lg.add(typ, data, run="tracekit/signer")
    case("a tenant's signer run as the bundle's run", bundle_of(lg, "signer-run", run="tracekit/signer"), t, 0,
         "VERIFIED TO HEAD 1", "witnessed",
         decided_by="§3 (a tenant's signer records are in its run tracekit/signer, which has no run.registered)")

    # the manifest is an index, never trusted
    v14 = closed("format-1.4", ("constraint.added", {"kind": "no_push"}, {}))
    case("a format 1.4 bundle", v14, t, 0, "VERIFIED", "witnessed", decided_by="§9 (version table)")
    case("its verifier_min_version lowered to 1.0.0", mutated("min-version-lowered", v14, manifest_version("1.0.0")),
         t, 0, "VERIFIED", "witnessed",
         decided_by="§9 (the manifest is never trusted: what a verifier checks follows from the records)")
    case("its verifier_min_version raised to 1.4.1, a version no row has", mutated(
        "min-version-1.4.1", v14, manifest_version("1.4.1")), t, 0, "VERIFIED", "witnessed", needs="1.4.1",
         decided_by="§11 step 2 (not above the version of the format the verifier implements)")

    # non-critical: ext
    ext = closed("ext", ("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}, {"ext": {"acme.note": 1}}),
                 ("ext", {"name": "acme.note", "detail": {"k": "v"}}, {}))
    case("an ext field and an ext record no verifier interprets", ext, t, 0, "VERIFIED", "witnessed",
         decided_by="§9 (criticality: a name not interpreted is a warning; the integrity stays VERIFIED)")

    # open definitions: another field passes their schema
    for name, (typ, data) in {
            "error-data": ("error", {"message": "x", "zz": 1}),
            "run-start-agent": ("run.start", {**EVERY_TYPE[0][1], "agent": {"name": "x", "zz": 1}}),
            "tamper-before": ("trace.tamper", {"path": "x", "before": {"zz": 1}, "after": {}}),
            "tamper-after": ("trace.tamper", {"path": "x", "before": {}, "after": {"zz": 1}})}.items():
        case(f"an unknown field in an open definition ({name})", closed(f"open-{name}", (typ, data, {})), t, 0,
             "VERIFIED", "witnessed", decided_by="§9 (open definitions)")
    for name, data in {"review-data": {"reviewer": "x", "verdict": {}, "zz": 1},
                       "review-verdict": {"reviewer": "x", "verdict": {"zz": 1}}}.items():
        case(f"an unknown field in an open definition ({name})", closed(f"open-{name}", ("review", data, {})), t, 0,
             "VERIFIED", "witnessed", addon="signed findings", decided_by="§9 (open definitions), §11 step 8")

    # the agent profile's checks an implementation may leave to an add-on: UNVERIFIABLE, never VERIFIED unchecked
    case("an incident record", closed("incident", ("incident.opened", {
        "incident_id": "i1", "trigger": "sequence", "rule_ids": [], "scope": {"kind": "run", "id": "run-a"},
        "cites": [], "mode": "shadow", "actions": [], "would": []}, {})), t, 0, "VERIFIED", "witnessed",
         addon="containment", decided_by="§3 (containment), §11 step 9")
    # run labels (format 1.8): replayed under the run's policy when the bundle carries it, signer-asserted without
    secret = ("policy.decision", {"tool_use_id": "t1", "decision": "flag", "rule_ids": ["SECRET"], "tool": "read_file",
                                  "policy_hash": LABELLED_HASH}, {"tool_call_id": "t1"})
    added = ("run.label", {"label": "secrets_access", "action": "add", "by": "signer", "source": 1}, {})
    case("a run label, its policy not in the bundle", closed("run-label", secret, added), t, 0, "VERIFIED",
         "witnessed", addon="run labels", needs="1.8.0", decided_by="§3 (run labels), §11 step 9")
    policies = os.path.join(VECTORS, ".stores", "policies")
    os.makedirs(policies)
    with open(os.path.join(policies, LABELLED_HASH.removeprefix("sha256:") + ".json"), "wb") as f:
        f.write(LABELLED_BYTES)
    case("a run label its cited record doesn't set", closed(
        "run-label-unset", (secret[0], {**secret[1], "rule_ids": []}, secret[2]), added, policy_dir=policies), t, 1,
         "FAILED", failed_check=["run labels"], addon="run labels", needs="1.8.0",
         decided_by="§3 (run labels: a record sets the labels of a call it lets run), §11 step 9")
    sent = ("policy.decision", {"tool_use_id": "t2", "decision": "ask", "rule_ids": ["EGRESS", "SEND"],
                                "tool": "read_file", "policy_hash": LABELLED_HASH, "run_labels": ["secrets_access"]},
            {"tool_call_id": "t2"})
    case("a label its record sets, no run.label adds", closed("run-label-omitted", secret, sent, policy_dir=policies),
         t, 1, "FAILED", failed_check=["run labels"], addon="run labels", needs="1.8.0",
         decided_by="§3 (run labels: added before the run's next decision), §11 step 9")
    case("a label left out, its policy only in the trust config", closed("run-label-omitted-trusted", secret, sent),
         trust("policy", policies=[LABELLED_BYTES.decode()]), 1, "FAILED", failed_check=["run labels"],
         addon="run labels", needs="1.8.0",
         decided_by="§10 (a trust config's policies: known by their hash), §11 step 9")
    inherited = ("run.label", {"label": "secrets_access", "action": "add", "by": "signer",
                               "inherited": {"run_id": "run-z", "run_seq": 2}}, {})
    case("a label inherited from another run of the requester", closed("run-label-inherited", inherited, sent,
                                                                       policy_dir=policies),
         t, 0, "VERIFIED", "witnessed", addon="run labels", needs="1.8.0",
         decided_by="§3 (run labels: a requester's, signer-asserted), §11 step 9")
    untracked = ("run.label", {**inherited[1], "label": "untrusted_content"}, {})
    plain = ("policy.decision", {"tool_use_id": "t3", "decision": "allow", "rule_ids": [], "tool": "read_file",
                                 "policy_hash": LABELLED_HASH}, {"tool_call_id": "t3"})
    case("an inherited label no run condition reads", closed("run-label-inherited-untracked", untracked, plain,
                                                             policy_dir=policies),
         t, 1, "FAILED", failed_check=["run labels"], addon="run labels", needs="1.8.0",
         decided_by="§3 (run labels: only those the policy's run conditions read), §11 step 9")
    case("an agent's approval", closed(
        "agent-approval",
        ("policy.decision", {"tool_use_id": "t1", "decision": "ask", "rule_ids": ["PAY"], "decision_id": "d1",
                             "policy_hash": H}, {"tool_call_id": "t1"}),
        ("approval.request", {**ASKED, "agent": {"eligible": True, "reason": "x", "rules": ["PAY"],
                                                 "conditions_hash": H, "args_key": "hmac-sha256:" + "2" * 64}},
         {"tool_call_id": "t1"}),
        ("approval", {"tool_use_id": "t1", "approval_id": "a1", "decision": "approve", "approver": "agent:x",
                      "channel": "x", "approver_kind": "agent",
                      "approver_identity": {"scheme": "token", "subject": "approver", "attested": True}},
         {"tool_call_id": "t1"})), t, 0, "VERIFIED", "witnessed", addon="agent approvals",
         decided_by="§11 step 9 (approvals by agents: without the policy snapshot, a warning)")
    # the AI approver (format 1.8.0): a person's answer, then an AI yes that names it as its precedent
    def ai_run(name, answers=2, other_kind=False, listed=None, labels=(), person=None, rejected=False):
        """`listed`: bundle a policy snapshot whose approval_agent lists these rules (None: no snapshot); `labels`: the
        run's labels the AI's answer relied on; `person`: fields of the person's answer a0 (and its record's `ts`);
        `rejected`: a person's rejection of a call like it (a2), named by no precedent list, before the AI's yes."""
        pol = {"tools": {"Bash": "shell"}, "ask": [{"id": "TK-A025", "class": "shell", "field": "package_index",
                                                   "pattern": "^"}],
               "approval_agent": {"mode": "enforce", "rules": listed or [], "run": {"clean": ["secrets_access"]}}}
        ph = H if listed is None else pc.policy_hash(pol)
        kw = {}
        if listed is not None:
            pdir = os.path.join(VECTORS, ".stores", "policies-" + name)
            os.makedirs(pdir)
            with open(os.path.join(pdir, ph.removeprefix("sha256:") + ".json"), "w", encoding="utf-8") as f:
                f.write(pc.canonical(pol))
            kw["policy_dir"] = pdir
        key = {"rules": ["TK-A025"], "tool": "Bash", "target": {"TK-A025": ["pip --index-url https://pypi.internal/…"]},
               "project": "api (17978b62)"}
        ai = {"key": key, "digest": "hmac-sha256:" + "5" * 64, "labels": [], "clean": True,
              "precedents": {"approve": [], "reject": []}}
        asked = [{**ASKED, "approval_id": aid, "decision_id": did, "rule_ids": ["TK-A025"], "policy_hash": ph,
                  "binding": {**ASKED["binding"], "approval_id": aid, "tool_call_id": tc, "tool": "Bash",
                              "policy_hash": ph}}
                 for aid, did, tc in (("a0", "d0", "t0"), ("a1", "d1", "t1"), ("a2", "d2", "t2"))]
        person = dict(person or {})
        when = {"ts": person.pop("ts")} if "ts" in person else {}
        no = [("policy.decision", {"tool_use_id": "t2", "decision": "ask", "rule_ids": ["TK-A025"],
                                   "decision_id": "d2", "policy_hash": ph}, {"tool_call_id": "t2"}),
              ("approval.request", {**asked[2], "ai": ai}, {"tool_call_id": "t2"}),
              ("approval", {"tool_use_id": "t2", "approval_id": "a2", "decision": "reject", "approver": "uid:502",
                            "channel": "rpc", "run_clean": True}, {"tool_call_id": "t2"})] if rejected else []
        if rejected == "revoked":
            no.append(("precedent.revoked", {"approval_id": "a2", "by": "uid:502", "reason": "the index is ours"}, {}))
        return closed(
            name,
            ("policy.decision", {"tool_use_id": "t0", "decision": "ask", "rule_ids": ["TK-A025"], "decision_id": "d0",
                                 "policy_hash": ph}, {"tool_call_id": "t0"}),
            ("approval.request", {**asked[0], "ai": dict(ai, digest="hmac-sha256:" + "6" * 64) if other_kind else ai},
             {"tool_call_id": "t0"}),
            ("approval", {"tool_use_id": "t0", "approval_id": "a0", "decision": "approve", "approver": "uid:502",
                          "channel": "rpc", "run_clean": True, **person}, {"tool_call_id": "t0", **when}),
            *no,
            ("policy.decision", {"tool_use_id": "t1", "decision": "ask", "rule_ids": ["TK-A025"], "decision_id": "d1",
                                 "policy_hash": ph}, {"tool_call_id": "t1"}),
            ("approval.request", {**asked[1], "agent": {"eligible": True, "reason": "x", "rules": ["TK-A025"],
                                                        "conditions_hash": H, "args_key": "hmac-sha256:" + "2" * 64},
                                  "ai": dict(ai, precedents={"approve": ["a0"], "reject": []})},
             {"tool_call_id": "t1"}),
            ("approval", {"tool_use_id": "t1", "approval_id": "a1", "decision": "approve", "approver": "uid:299",
                          "channel": "rpc", "approver_kind": "agent",
                          "approver_identity": {"scheme": "uid", "subject": "299", "attested": True},
                          "relied_on": {"precedents": {"approve": ["a0"], "reject": []},
                                        "playbook": {"version": 0, "digest": H}, "policy_hash": ph,
                                        "labels": list(labels), "view": "hmac-sha256:" + "7" * 64, "mode": "enforce",
                                        "answers": [{"model": "m", "decision": "approve"}] * answers}},
             {"tool_call_id": "t1"}), **kw)
    case("an AI approver's yes on a person's precedent in the run", ai_run("ai-approval"), t, 0, "VERIFIED",
         "witnessed", addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: an AI yes carries two answers that approve and a person's precedent)")
    case("an AI approver's yes with one answer", ai_run("ai-approval-one-key", answers=1), t, 1, "FAILED",
         failed_check=["AI approvals"], addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a yes needs two answers that approve)")
    case("an AI approver's yes on a precedent of another kind of call", ai_run("ai-approval-other-kind",
                                                                              other_kind=True), t, 1, "FAILED",
         failed_check=["AI approvals"], addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a precedent is a person's approval of a request with the same digest)")
    case("an AI approver's yes, its rule listed in the policy snapshot", ai_run("ai-approval-listed",
                                                                               listed=["TK-A025"]), t, 0, "VERIFIED",
         "witnessed", addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0), §11 step 9 (a rule the snapshot's approval_agent lists permits agents)")
    case("an AI approver's yes, its rule not listed in the policy snapshot", ai_run("ai-approval-unlisted",
                                                                                   listed=["TK-A062"]), t, 1, "FAILED",
         failed_check=["approvals by agents"], addon="AI approvals", needs="1.8.0",
         decided_by="§11 step 9 (a rule neither with approval.agent nor listed by approval_agent doesn't permit agents)")
    case("an AI approver's yes in a run carrying a label of the snapshot's run bound", ai_run(
        "ai-approval-run-bound", listed=["TK-A025"], labels=["secrets_access"]), t, 1, "FAILED",
         failed_check=["AI run bound"], addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: none of an AI yes's run labels is one the policy's run bound names)")
    case("an AI approver's yes in a labelled run, its policy snapshot left out of the bundle", ai_run(
        "ai-approval-run-bound-no-snapshot", labels=["secrets_access"]), t, 1, "FAILED",
         failed_check=["AI run bound"], addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: an AI yes in a labelled run needs the snapshot of the policy it cites)")
    case("an AI approver's yes on a precedent more than 30 days older", ai_run(
        "ai-approval-old-precedent", person={"ts": "2026-09-09T11:59:59.000000Z"}), t, 1, "FAILED",
         failed_check=["AI approvals"], addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a precedent is at most 30 days older than the answer)")
    case("an AI approver's yes on a precedent exactly 30 days older", ai_run(
        "ai-approval-30-day-precedent", person={"ts": "2026-09-09T12:00:00.000000Z"}), t, 0, "VERIFIED", "witnessed",
         addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a precedent is at most 30 days older than the answer)")
    case("an AI approver's yes on a break-glass answer", ai_run("ai-approval-break-glass", person={
        "break_glass": True, "reason": "on call"}), t, 1, "FAILED", failed_check=["AI approvals"],
         addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a break-glass answer is no precedent)")
    case("an AI approver's yes on an answer made once the run wasn't clean", ai_run(
        "ai-approval-answered-unclean", person={"run_clean": False}), t, 1, "FAILED", failed_check=["AI approvals"],
         addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a precedent is an answer made in a run clean when it was answered)")
    case("an AI approver's yes with a person's rejection of a call like it in the bundle", ai_run(
        "ai-approval-unnamed-rejection", rejected=True), t, 1, "FAILED", failed_check=["AI approvals"],
         addon="AI approvals", needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: no rejection of a call like it counts when the AI says yes)")
    case("an AI approver's yes after a person's rejection of a call like it was revoked as a precedent", ai_run(
        "ai-approval-revoked-rejection", rejected="revoked"), t, 0, "VERIFIED", "witnessed", addon="AI approvals",
         needs="1.8.0",
         decided_by="§9 (version table, 1.8.0: a precedent revoked before the answer doesn't count, a rejection too)")
    case("a signed finding outside a findings run", closed("review-outside-findings-run", (
        "review", {"reviewer": "x", "verdict": {"kind": "finding", "rule": "TK-X200", "severity": "info"},
                   "cites": [{"run_seq": 0, "hash": "sha256:" + "0" * 64}]}, {})), t, 1, "FAILED",
         failed_check=["reviews"], addon="signed findings",
         decided_by="§11 step 8 (a review with cites must be in a findings run)")

    # add-ons
    bundle, pin = certified("certified-key")
    case("a certified record key, no issuer pinned", bundle, t, 1, "FAILED", failed_check=["keys"],
         decided_by="§11 step 5 (a key with cert is declared only if its certificate verifies under a pinned issuer)")
    case("a certified record key, its issuer pinned", bundle, trust("issuer", issuers=[pin]), 0, "VERIFIED",
         "witnessed", addon="record-key certificates", decided_by="§11 step 5, docs/issuer.md")

    # run-sets
    lg = log()
    lg.register()
    lg.call()
    case("a run-set of open runs only, no run selected", run_set("run-set-open-only", lg), t, 0, "VERIFIED",
         "witnessed", decided_by="§9 (a run-set bundles the runs final in its range and the selected run, if any)")

    # trust configs
    for name, over, why in (
            ("empty-lists", {"monitors": [], "issuers": [], "analyzers": []}, "§10 (optional lists, none pinned)"),
            ("extra-alg", {"algs": ["ed25519", "ml-dsa-44"]}, "§4 (algorithms: a pinned allow-list), §10"),
            ("two-logs", {"logs": tb.trust_config()["logs"] + [checkpoint.vkey(
                "other.example.org/log", checkpoint.ED25519, tb.pub(tb.KEY2))]},
             "§6 (a note needs a pinned log key named after its origin), §10")):
        case(f"a trust config: {name}", every, trust(name, **over), 0, "VERIFIED", "witnessed", decided_by=why)
    case("a trust config whose only algorithm is not the records'", every, trust("other-alg", algs=["ml-dsa-44"]), 1,
         "FAILED", failed_check=["keys", "signatures"], decided_by="§4 (algorithms), §10")

    # spellings of the same values: §4 and §3 decide v; the rest is the proposed rule (strict where the signer never
    # writes the loose form)
    case("v written 2.0", mutated("v-float", every, respell(r'"v": ?2,', '"v": 2.0,')), t, 1, "FAILED",
         failed_check=["signatures", "bundle structure"],
         decided_by="§4 (v is the integer 2), §3 (integer: a token without fraction or exponent)")
    for name, edit, checks in (
            ("tree_size written 4.0", respell(r'"tree_size": ?(\d+)', r'"tree_size": \1.0', "proofs/records.json"),
             ["checkpoint", "bundle structure"]),
            ("run_seq written -0", respell(r'"run_seq": ?0,', '"run_seq": -0,'),
             ["bundle structure", "signatures", "run chain"]),
            ("a signature in non-canonical base64", loose_sig, ["signatures"]),
            ("an inclusion proof node in non-canonical base64", loose_proof, ["keys", "inclusion", "run-set"])):
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        case(name, mutated(slug, every, edit), t, 1, "FAILED", failed_check=checks, proposed=True,
             decided_by="proposed: integer tokens and canonical base64 in every bundle file (§1, §6, §7 do so for "
                        "JSON, notes and run-set bounds)")
    lg = log()
    lg.call()
    lg.final()
    case("an agent run with no run.registered", bundle_of(lg, "no-registration"), t, 1, "FAILED",
         failed_check=["run chain"], proposed=True,
         decided_by="proposed: a run other than the signer's own starts with its run.registered (§3 lifecycle)")
    shutil.rmtree(os.path.join(VECTORS, ".stores"))


PRIMITIVES = [
    {"input": "vectors/jcs.jsonl", "decided_by": "§1", "pins": "canonical JSON: input, canonical bytes, SHA-256"},
    {"input": "vectors/sig_v2.jsonl", "decided_by": "§4",
     "pins": "records (event, signature message, signed record) and the Ed25519 acceptance rules"},
    {"input": "vectors/c2sp_checkpoint.json", "decided_by": "§6",
     "pins": "a checkpoint note, its log signature and a witness cosignature"},
    {"input": "vectors/slh_dsa_note.json", "decided_by": "§6 (hybrid checkpoint signature)", "addon": "SLH-DSA",
     "pins": "a hybrid checkpoint note: Ed25519 and SLH-DSA-SHA2-128s lines, keys, key ids"},
]


def main():
    vectors()
    sample = os.path.join(ROOT, "sdk", "typescript", "src", "verify", "sample")
    shipped = [{"name": "the browser page's sample", "input": rel(os.path.join(sample, "sample.tkb")),
                "trust": rel(os.path.join(sample, "sample.trust.json")), "exit": 0, "verdict": "VERIFIED",
                "level": "dev", "failed_check": None, "decided_by": "§11 step 11"},
               {"name": "the browser page's tampered sample", "input": rel(os.path.join(sample, "sample-tampered.tkb")),
                "trust": rel(os.path.join(sample, "sample.trust.json")), "exit": 1, "verdict": "FAILED", "level": None,
                "failed_check": reference(os.path.join(sample, "sample-tampered.tkb"),
                                          os.path.join(sample, "sample.trust.json"))[3],
                "decided_by": "§4, §11 step 6"}]
    cases = golden_cases() + shipped + VECTOR_CASES
    files = {c[k]: hashlib.sha256(open(os.path.join(TESTS, c[k]), "rb").read()).hexdigest()
             for c in cases for k in ("input", "trust")}
    with open(os.path.join(KIT, "cases.json"), "w", encoding="utf-8") as f:
        json.dump({"format": "tracekit.bundle.v2", "spec": "docs/format-v2.md", "files": dict(sorted(files.items())),
                   "cases": cases, "primitives": PRIMITIVES}, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"{len(cases)} cases ({len(VECTOR_CASES)} vectors), {len(PRIMITIVES)} primitive vector files")


if __name__ == "__main__":
    main()
