"""Registry log leaves (04-design §1.5): each tenant's log of lifecycle records, in a fixed-width encoding

    type u8 ‖ H(tenant_salt ‖ run_id) 32B ‖ record log_id 16B ‖ seq u64 ‖ record_hash 32B

tenant_salt = HMAC-SHA256(the signer's registry salt, tenant). run.registered and run.final get a leaf in their run's
tenant's registry; log.closed and key.retire (signer-level) one in every tenant's registry. The registry's checkpoint
origin is `<record log origin>/registry/<id>`, where id is derived from the tenant salt, never the tenant's name."""
import hashlib
import hmac

LEAF_TYPES = {"run.registered": 1, "run.final": 2, "log.closed": 3, "key.retire": 4}
SIGNER_LEAVES = ("log.closed", "key.retire")
LEAF_SIZE = 89
_NAMES = {v: k for k, v in LEAF_TYPES.items()}


def tenant_salt(salt, tenant):
    return hmac.new(salt, tenant.encode("utf-8"), hashlib.sha256).digest()


def run_hash(tsalt, run_id):
    return hashlib.sha256(tsalt + run_id.encode("utf-8")).digest()


def origin(log_origin, tsalt):
    return f"{log_origin}/registry/{hashlib.sha256(b'registry ' + tsalt).hexdigest()[:32]}"


def leaf(record, tsalt):
    e = record["event"]
    return (bytes([LEAF_TYPES[e["type"]]]) + run_hash(tsalt, e["run_id"]) + bytes.fromhex(e["log_id"])
            + e["seq"].to_bytes(8, "big") + bytes.fromhex(record["hash"][7:]))


def parse(data):
    """(record type, run hash, log_id hex, seq, record hash "sha256:..."); ValueError for anything else."""
    if len(data) != LEAF_SIZE or data[0] not in _NAMES:
        raise ValueError("not a registry leaf")
    return _NAMES[data[0]], data[1:33], data[33:49].hex(), int.from_bytes(data[49:57], "big"), "sha256:" + data[57:].hex()
