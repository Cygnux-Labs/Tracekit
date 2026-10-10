"""The v1 → v2 format bridge (04-design §1.9), run once per v1 ledger by `tracekit signer bridge`. Nothing is rewritten:

1. the v1 ledger gets two last records, signed with the v1 key through `Ledger.append`: capture.gap{format_upgrade},
   then the key's retirement. The frozen v1 schema has no key.retire type, so the retirement is a v1-valid
   capture.gap{kind: key_retire, reason: "key.retire kid=<v1 kid> last_seq=<its own seq>"};
2. the v2 store's first record is signer.epoch{bridge: {v1_kid, v1_last_seq, v1_head}} (v1_head: the hash of 1's last
   record); a store that already has other records is refused;
3. the v1 signer.key is overwritten and unlinked (signer.pub stays).

Each step is fsync'd before the next. A re-run on a ledger that already ends in the bridge finishes steps 2-3 only.
"""
import os

from tracekit.core import SCHEMA_VERSION, new_id, now_ts
from tracekit.ledger import Keys, Ledger, read_records
from tracekit.storage.base import ACK_ON_FSYNC
from tracekit.storage.file import FileStorage, _sync_dir

class BridgeError(Exception):
    pass


def retire_data(kid, seq):
    return {"kind": "key_retire", "reason": f"key.retire kid={kid} last_seq={seq}"}


def is_retire(rec):
    """True for the bridge's key retirement record (signer-written, retiring the key that signed it at its own seq)."""
    e = rec.get("event") or {}
    return (e.get("type") == "capture.gap" and e.get("source") == "signer" and e.get("run_id") == "_signer"
            and e.get("data") == retire_data(rec.get("kid"), e.get("seq")))


def _gap(data):
    return {"schema_version": SCHEMA_VERSION, "id": new_id(), "ts": now_ts(), "ts_signed": now_ts(), "run_id": "_signer",
            "agent_id": "tracekitd", "parent_id": None, "source": "signer", "type": "capture.gap", "data": data}


def bridge(v1_home, data_dir, storage_config=None):
    """Bridge the v1 ledger of `v1_home` into the v2 store of `data_dir` (or of `storage_config`, the signer config's
    storage section); returns the signer.epoch `bridge`."""
    from tracekit.signer.service import SignerService   # here: the verifier imports this module for retire_data
    if hasattr(os, "geteuid") and os.stat(v1_home).st_uid != os.geteuid():
        raise BridgeError(f"run the bridge as the owner of {v1_home}")
    path = os.path.join(v1_home, "ledger", "ledger.jsonl")
    if not os.path.exists(path):
        raise BridgeError(f"no v1 ledger at {path}")
    try:
        ledger = Ledger(path, None)   # takes the daemon's ledger lock: no tracekitd can run on this home meanwhile
    except RuntimeError as e:
        raise BridgeError(f"a tracekitd is running on {v1_home}; stop it first") from e
    try:
        retire = None
        for _, r, _ in read_records(path):
            if not isinstance(r, dict):
                continue
            if retire is not None:
                raise BridgeError(f"{path} has records after its format bridge")
            if is_retire(r):
                retire = r
        keydir = os.path.join(v1_home, "keys")
        sk = os.path.join(keydir, "signer.key")
        if retire is None:
            if not os.path.exists(sk):
                raise BridgeError(f"no v1 file key at {sk}")
            if storage_config:
                from tracekit.storage import postgres
                store = postgres.PostgresStorage(postgres.read_dsn(storage_config["postgres"]))
            else:
                store = FileStorage(os.path.join(data_dir, "store"))
            try:
                if store.tree.size:
                    raise BridgeError(f"the v2 store in {data_dir} already has records: the bridge must be its first")
            finally:
                store.close()
            ledger.keys = Keys.load_or_create(keydir)
            ledger.append(_gap({"kind": "format_upgrade", "reason": "v1 ledger closed: continued in the v2 signer's log"}))
            retire = ledger.append(_gap(retire_data(ledger.keys.kid, ledger.seq + 1)))
        out = {"v1_kid": retire["kid"], "v1_last_seq": retire["event"]["seq"], "v1_head": retire["hash"]}
        try:
            SignerService(data_dir, durability=ACK_ON_FSYNC, bridge=out, storage_config=storage_config).close()
        except ValueError as e:
            raise BridgeError(str(e)) from None
        if os.path.exists(sk):
            with open(sk, "r+b") as f:
                f.write(b"\0" * os.fstat(f.fileno()).st_size)
                f.flush()
                os.fsync(f.fileno())
            os.unlink(sk)
            _sync_dir(keydir)
        return out
    finally:
        ledger.close()
