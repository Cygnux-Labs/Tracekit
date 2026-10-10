"""`tracekit monitor` (04-design §2.9): follows a v2 signer's logs, checks the rules witnesses can't, and publishes a
signed report that the verifier uses for `witnessed+monitored` (docs/monitor.md).

    tracekit monitor --log URL --log-key VKEY --state DIR [--rekor TRUSTED_ROOT --publishing-key SPKI]
                     [--key monitor.key] [--allow KID ...] [--every S | --once]

Each poll reads the record log at URL (the signer's metrics port, `SignerService.tlog`): its checkpoint, verified under
VKEY and against the last one seen (a smaller tree is a rollback, another root at a size seen before a fork: both are
conflicts that keep both notes), then every new record from the entry bundles, bound to the checkpoint by rebuilding
its tree. Then the same for each registry log the logs list (/logs/v0) names, signed by the same key. Rules, over every
record seen so far:
- log chain: seq and prev_hash continue the log; a record's hash is its event's
- run chain: run_seq and run_prev_hash continue the run; one run.registered per run; one run.final per run and nothing
  after it; a run.final's head is the run's record before it
- keys: a signer.epoch key after seq 0, or a key.retire, is of a kid passed with --allow
- registry: each leaf points to a record of the log with its type and hash, once per registry, with one run hash per
  run; every run.registered and run.final has a leaf by the poll after the one that saw it
With --rekor: every anchor the signer serves (/anchors) verifies (`rekor2.verify`) and is of a checkpoint of the log,
and every entry under the publishing key in the Rekor shards those anchors are in (read as tlog-tiles) is one of the
anchors by the poll after the one that saw it.

State (DIR/state.json, and each log's tree in DIR/tiles/) is saved after each poll, so a restart resumes there. The
report, DIR/report.json, is {"report": {format, origin, checked_size, checked_root, time, conflicts, rules_checked},
"sig"}: Ed25519 by the monitor key over "tracekit monitor report v1\\n" ‖ JCS(report). DIR/monitor.vkey is the key to
pin; serve DIR/report.json as a static file for auditors."""
import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.request

from tracekit import crypto, merkle
from tracekit.anchor import rekor2
from tracekit.format import checkpoint, registry
from tracekit.format.canon import canonical, event_hash, loads_strict
from tracekit.merkle import tiles
from tracekit.storage.base import ZERO_HASH
from tracekit.tlog_witness import log_signed

FORMAT = "tracekit.monitor.report.v1"
CONTEXT = b"tracekit monitor report v1\n"
NAME = "tracekit-monitor"
TIMEOUT_S = 30.0
MAX_TILE = 256 << 20   # a full record bundle: 256 records of at most 1 MiB
REPORT_KEYS = {"format", "origin", "checked_size", "checked_root", "time", "conflicts", "rules_checked"}
RULES = ["checkpoint consistency", "log chain", "run chain", "one run.registered per run",
         "one run.final per run, nothing after it", "run.final head", "key announcements", "registry leaves"]
LEAFED = ("run.registered", "run.final")


class MonitorError(Exception):
    """A poll that could not finish (unreachable, a bad note, entries that are not the checkpoint's tree)."""


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_S) as r:
            return r.read(MAX_TILE)
    except (OSError, ValueError) as e:
        raise MonitorError(f"{url}: {e}") from None


def _index(n):
    """A tile index as tlog-tiles path elements: 1234067 -> x001/x234/067."""
    parts = [f"{n % 1000:03d}"]
    while n >= 1000:
        n //= 1000
        parts.append(f"x{n % 1000:03d}")
    return "/".join(parts[::-1])


def _c2sp(data):
    """The entries of a C2SP entry bundle (uint16 length ‖ entry, ...)."""
    out, i = [], 0
    while i < len(data):
        n = int.from_bytes(data[i:i + 2], "big")
        out.append(data[i + 2:i + 2 + n])
        if len(out[-1]) != n:
            raise ValueError("truncated entry bundle")
        i += 2 + n
    return [(x, x) for x in out]


def _records(data):
    out = [loads_strict(line) for line in data.split(b"\n")[:-1]]
    return [(r, bytes.fromhex(r["hash"][len("sha256:"):])) for r in out]


def _conflict(state, rule, detail, notes=None):
    c = {"rule": rule, "detail": detail, **({"notes": notes} if notes else {})}
    if c not in state["conflicts"]:
        state["conflicts"].append(c)


def _follow(state, d, name, url, open_note, entries):
    """(tree, new entries) of the log `name` at `url` since the last poll: its checkpoint opens (`open_note(note)` ->
    (size, root)), extends the last one seen and is the tree of the entries. `entries(bundle)` -> [(entry, leaf data)]."""
    note = _get(url + "/checkpoint").decode("utf-8", "replace")
    try:
        size, root = open_note(note)
    except ValueError as e:   # NoteError, AnchorError
        raise MonitorError(f"{name}: {e}") from None
    last = state["logs"].get(name, {"size": 0, "root": _b64(merkle.root([])), "note": None})
    tree = tiles.Tree(tiles.DirTileStore(os.path.join(d, "tiles", hashlib.sha256(name.encode()).hexdigest()[:32])),
                      last["size"])
    if size < last["size"]:
        _conflict(state, "checkpoint consistency", f"{name}: a checkpoint of size {size} after one of size "
                                                   f"{last['size']} (rollback)", [last["note"], note])
        return tree, []
    if size == last["size"]:
        if _b64(root) != last["root"]:
            _conflict(state, "checkpoint consistency", f"{name}: two checkpoints of size {size} with different roots "
                                                       "(fork)", [last["note"], note])
        return tree, []
    new = []
    for n in range(last["size"] // 256, (size + 255) // 256):
        w = min(256, size - n * 256)
        try:
            got = entries(_get(f"{url}/tile/entries/{_index(n)}" + (f".p/{w}" if w < 256 else "")))
        except (ValueError, KeyError, TypeError) as e:
            raise MonitorError(f"{name}: entry bundle {n}: {type(e).__name__}: {e}") from None
        if len(got) != w:
            raise MonitorError(f"{name}: entry bundle {n} holds {len(got)} entries, not {w}")
        new += got[max(0, last["size"] - n * 256):]
    for _, data in new:
        tree.append(merkle.leaf_hash(data))
    if tree.root() != root:
        raise MonitorError(f"{name}: the entries are not the tree of the checkpoint of size {size}")
    tree.flush()
    state["logs"][name] = {"size": size, "root": _b64(root), "note": note}
    return tree, [e for e, _ in new]


def _check_records(state, records, allowed):
    head = state["head"]
    for r in records:
        e = r.get("event") or {}
        seq, typ = e.get("seq"), e.get("type")
        if seq == 0:
            state["log_id"] = e.get("log_id")
        if event_hash(e) != r.get("hash"):
            _conflict(state, "log chain", f"seq {seq}: the record's hash is not its event's")
        if seq != head["seq"] or e.get("prev_hash") != head["hash"]:
            _conflict(state, "log chain", f"seq {seq}: does not continue the log at seq {head['seq']}")
        head = {"seq": head["seq"] + 1, "hash": r.get("hash")}
        key = json.dumps([e.get("tenant"), e.get("run_id")])
        run = state["runs"].setdefault(key, {"run_seq": -1, "head": ZERO_HASH, "registered": False, "final": False})
        name = f"run {str(e.get('run_id'))[:200]!r} of tenant {str(e.get('tenant'))[:200]!r}"
        if run["final"]:
            _conflict(state, "one run.final per run, nothing after it",
                      f"seq {seq}: {'a second run.final' if typ == 'run.final' else 'a record after the run.final'} "
                      f"of {name}")
        if e.get("run_seq") != run["run_seq"] + 1 or e.get("run_prev_hash") != run["head"]:
            _conflict(state, "run chain", f"seq {seq}: does not continue {name}")
        if typ == "run.registered":
            if run["registered"]:
                _conflict(state, "one run.registered per run", f"seq {seq}: a second run.registered of {name}")
            run["registered"] = True
        elif typ == "run.final":
            d = e.get("data") or {}
            if (d.get("head_run_seq"), d.get("head_hash")) != (run["run_seq"], run["head"]):
                _conflict(state, "run.final head", f"seq {seq}: the run.final of {name} names another head")
            run["final"] = True
        elif typ in ("signer.epoch", "key.retire") and seq != 0:
            d = e.get("data") or {}
            for kid in [k.get("kid") for k in d.get("keys", [])] if typ == "signer.epoch" else [d.get("kid")]:
                if kid not in allowed:
                    _conflict(state, "key announcements", f"seq {seq}: {typ} of key {str(kid)[:80]}, not announced")
        run.update(run_seq=e.get("run_seq") if isinstance(e.get("run_seq"), int) else run["run_seq"], head=r.get("hash"))
        if typ in registry.LEAF_TYPES:
            state["life"][str(seq)] = [typ, r.get("hash"), key]
    state["head"] = head


def _check_leaves(state, origin, leaves):
    """Registry leaves [(index, leaf)]; those pointing past the records checked wait for the next poll."""
    for i, leaf in leaves:
        try:
            typ, run_hash, log_id, seq, h = registry.parse(leaf)
        except ValueError:
            _conflict(state, "registry leaves", f"{origin} leaf {i}: not a registry leaf")
            continue
        if seq >= state["head"]["seq"]:
            state["pending"].append([origin, i, _b64(leaf)])
            continue
        life = state["life"].get(str(seq))
        if life is None or life[:2] != [typ, h] or log_id != state["log_id"]:
            _conflict(state, "registry leaves", f"{origin} leaf {i} points to no {typ} record of the log at seq {seq}")
            continue
        where = state["leafed"].setdefault(str(seq), [])
        if origin in where:
            _conflict(state, "registry leaves", f"{origin} leaf {i}: a second leaf for seq {seq}")
        where.append(origin)
        if typ in LEAFED and state["runs"][life[2]].setdefault("run_hash", run_hash.hex()) != run_hash.hex():
            _conflict(state, "registry leaves", f"{origin} leaf {i}: another run hash for the run of seq {seq}")


def _check_rekor(state, d, url, vkey, tree, trusted_root, spki):
    """Each anchor the signer serves is in Rekor and of the log; every entry under `spki` in their shards is one of them."""
    digests, shards = set(), {}
    for a in [loads_strict(line) for line in _get(url + "/anchors").split(b"\n")[:-1]]:
        # lean: verifies every anchor on every poll (at most 24 a day); keep the verified ones in state past ~10k
        try:
            data = log_signed(a["note"], vkey).encode("utf-8")
            digests.add(_b64(hashlib.sha256(data).digest()))
            rekor2.verify(a, data, spki, trusted_root)
            _, size, root, _ = checkpoint.open_note(data, [vkey])
            if size <= tree.size and tree.root_at(size) != root:
                raise ValueError(f"its checkpoint of size {size} is not the log's")
            shards[a["rekor"]["logId"]["keyId"]] = None
        except (ValueError, KeyError, TypeError) as e:
            _conflict(state, "rekor anchors", f"the anchor of size {a.get('size')!r}: {type(e).__name__}: {e}")
    unknown = []
    # lean: scans only the shards the signer's anchors are in, from index 0; scan every Rekor v2 shard of the trusted
    # root, from the log's creation, once v1 logs (no tiles) leave it
    for t in trusted_root.get("tlogs") or ():
        if t["logId"]["keyId"] not in shards:
            continue
        name = "rekor " + t["baseUrl"]
        _, bodies = _follow(state, d, name, t["baseUrl"].rstrip("/") + "/api/v2",
                            lambda note: rekor2._rekor_checkpoint(note, t), _c2sp)
        base = state["logs"][name]["size"] - len(bodies)
        for i, body in enumerate(bodies, base):
            try:
                spec = json.loads(body)["spec"]["hashedRekordV002"]
                ours = base64.b64decode(spec["signature"]["verifier"]["publicKey"]["rawBytes"]) == spki
            except (ValueError, KeyError, TypeError):
                continue   # another kind of entry
            if ours:
                unknown.append([name, i, spec["data"]["digest"]])
    for name, i, digest in state["rekor_unknown"] + unknown:
        if digest in digests:
            continue
        if [name, i, digest] in state["rekor_unknown"]:
            _conflict(state, "rekor anchors", f"{name} entry {i}: under the publishing key, but of no checkpoint the "
                                              "signer anchored")
    state["rekor_unknown"] = [u for u in unknown if u[2] not in digests]


def poll(d, url, log_vkey, secret, allowed=(), rekor=None):
    """One poll of the log at `url` with state in `d`; writes d/state.json and d/report.json and returns the signed
    report. `rekor`: (trusted_root, publishing key DER SPKI) to scan Rekor."""
    url, path = url.rstrip("/"), os.path.join(d, "state.json")
    try:
        with open(path, "rb") as f:
            state = loads_strict(f.read())
    except FileNotFoundError:
        state = {"logs": {}, "head": {"seq": 0, "hash": ZERO_HASH}, "log_id": None, "runs": {}, "life": {},
                 "leafed": {}, "unleafed": [], "pending": [], "rekor_unknown": [], "conflicts": []}
    origin, _, _, public = checkpoint.parse_vkey(log_vkey)
    tree, records = _follow(state, d, origin, url, lambda n: checkpoint.open_note(n, [log_vkey])[1:3], _records)
    _check_records(state, records, set(allowed))
    for line in _get(url + "/logs/v0").decode("utf-8", "replace").splitlines():
        name = line[len("vkey "):].split("+", 1)[0] if line.startswith("vkey ") else ""
        if not name.startswith(origin + "/registry/"):
            continue
        k = checkpoint.vkey(name, checkpoint.ED25519, public)
        reg_tree, leaves = _follow(state, d, name, url + name[len(origin):],
                                   lambda n, k=k: checkpoint.open_note(n, [k])[1:3], _c2sp)
        waiting = [(i, base64.b64decode(x)) for o, i, x in state["pending"] if o == name]
        state["pending"] = [p for p in state["pending"] if p[0] != name]
        _check_leaves(state, name, waiting + list(enumerate(leaves, reg_tree.size - len(leaves))))
    # lean: walks every run.registered and run.final each poll; index the unleafed ones if a log holds ~1M runs
    missing = [s for s, (typ, _, _) in state["life"].items() if typ in LEAFED and s not in state["leafed"]]
    for s in missing:
        if s in state["unleafed"]:
            _conflict(state, "registry leaves", f"seq {s}: {state['life'][s][0]} has no registry leaf")
    state["unleafed"] = missing
    if rekor:
        _check_rekor(state, d, url, log_vkey, tree, *rekor)
    report = {"format": FORMAT, "origin": origin, "checked_size": tree.size, "checked_root": _b64(tree.root()),
              "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "conflicts": state["conflicts"], "rules_checked": RULES + (["rekor anchors"] if rekor else [])}
    signed = {"report": report, "sig": _b64(crypto.sign(secret, CONTEXT + canonical(report)))}
    for name, doc in (("state.json", state), ("report.json", signed)):
        with open(os.path.join(d, name + ".tmp"), "w") as f:
            json.dump(doc, f)
        os.replace(os.path.join(d, name + ".tmp"), os.path.join(d, name))
    return signed


def open_report(data, vkey):
    """The report of a signed monitor report (bytes) under the monitor's pinned `vkey`; ValueError otherwise."""
    _, _, type_, public = checkpoint.parse_vkey(vkey)
    doc = loads_strict(data)
    r = doc.get("report") if isinstance(doc, dict) and set(doc) == {"report", "sig"} else None
    if not (type_ == checkpoint.ED25519 and isinstance(r, dict) and set(r) == REPORT_KEYS and r["format"] == FORMAT
            and isinstance(doc["sig"], str) and crypto.verify_v2("ed25519", crypto.spki(public), CONTEXT + canonical(r),
                                                                base64.b64decode(doc["sig"], validate=True))):
        raise ValueError("not a monitor report signed by this key")
    if not (isinstance(r["origin"], str) and type(r["checked_size"]) is int and isinstance(r["checked_root"], str)
            and isinstance(r["time"], str) and isinstance(r["conflicts"], list)
            and all(isinstance(c, dict) and isinstance(c.get("detail"), str) for c in r["conflicts"])):
        raise ValueError("malformed monitor report")
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit monitor", description="Follow a v2 signer's logs, check their rules "
                                                                      "and publish a signed monitor report.")
    ap.add_argument("--log", required=True, help="the signer's metrics port, e.g. http://127.0.0.1:9464")
    ap.add_argument("--log-key", required=True, help="the record log's vkey (`tracekit signer vkey`)")
    ap.add_argument("--state", required=True, help="the monitor's state directory (state, report, key)")
    ap.add_argument("--rekor", help="a Sigstore trusted_root.json: scan the Rekor shards the signer anchors in")
    ap.add_argument("--publishing-key", help="with --rekor: the signer's publishing key (base64 SPKI, its rekor.pub)")
    ap.add_argument("--key", help="the monitor's Ed25519 key (default DIR/monitor.key, created on first use)")
    ap.add_argument("--allow", action="append", default=[], metavar="KID",
                    help="a record key the log may declare after seq 0 or retire")
    ap.add_argument("--every", type=float, default=60.0, help="seconds between polls (default 60)")
    ap.add_argument("--once", action="store_true", help="poll once; exit 1 when the report has conflicts")
    a = ap.parse_args(argv)
    if bool(a.rekor) != bool(a.publishing_key):
        ap.error("--rekor and --publishing-key go together")
    os.makedirs(a.state, exist_ok=True)
    key = a.key or os.path.join(a.state, "monitor.key")
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(crypto.generate()[0])
    with open(key, "rb") as f:
        secret = f.read()
    vkey = checkpoint.vkey(NAME, checkpoint.ED25519, crypto.public_from_secret(secret))
    with open(os.path.join(a.state, "monitor.vkey"), "w") as f:
        f.write(vkey + "\n")
    rekor = None
    if a.rekor:
        with open(a.rekor, "rb") as f:
            rekor = loads_strict(f.read()), base64.b64decode(a.publishing_key, validate=True)
    print(f"monitor {vkey}", file=sys.stderr)
    while True:
        try:
            r = poll(a.state, a.log, a.log_key, secret, a.allow, rekor)["report"]
            print(f"{r['time']} {r['origin']} checked to size {r['checked_size']}: {len(r['conflicts'])} conflict(s)",
                  file=sys.stderr)
            code = 1 if r["conflicts"] else 0
        except MonitorError as e:
            print(f"tracekit monitor: {e}", file=sys.stderr)
            code = 2
        if a.once:
            return code
        time.sleep(a.every)
