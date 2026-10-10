"""The log key (04-design §3): the per-log Ed25519 key that signs checkpoint notes only. It lives in keys/log.key, or in
AWS KMS with `log_key: {aws_kms: {key_id, region}}` in signer.yaml (boto3, the `aws` extra). A key has `public` (32 raw
bytes) and `sign(msg)`; a KMS key raises KeyUnavailable rather than return a signature its public key does not verify.

Key hygiene of the signer process: harden() at start (no core dumps, not dumpable) and mlock() of each key file's
buffer; HYGIENE records what held, for `tracekit doctor` (<data_dir>/hygiene.json)."""
import ctypes
import logging
import os
import sys

from tracekit import crypto

KEY_SPEC, KEY_USAGE, ALGORITHM = "ECC_NIST_EDWARDS25519", "SIGN_VERIFY", "ED25519_SHA_512"
PR_SET_DUMPABLE = 4
HYGIENE = {"core_limit": None, "dumpable": None, "mlock": None}   # None: not tried, or not possible here


class KeyUnavailable(Exception):
    pass


class FileKey:
    def __init__(self, secret):
        self.public, self.sign = crypto.public_from_secret(secret), crypto.sign_fn(secret)


class AwsKmsKey:
    """An AWS KMS ECC_NIST_EDWARDS25519 key. `client` is a boto3 KMS client (default: one for `region`)."""

    def __init__(self, key_id, region, client=None):
        if client is None:
            import boto3
            client = boto3.client("kms", region_name=region)
        self._client, self._key_id = client, key_id
        r = client.get_public_key(KeyId=key_id)
        if r.get("KeySpec") != KEY_SPEC or r.get("KeyUsage") != KEY_USAGE or crypto.key_alg(r.get("PublicKey", b"")) != "ed25519":
            raise ValueError(f"KMS key {key_id} is {r.get('KeySpec')}/{r.get('KeyUsage')}: the log key must be a "
                             f"{KEY_SPEC} {KEY_USAGE} key")
        self.public = r["PublicKey"][-32:]

    def sign(self, msg):
        try:
            sig = self._client.sign(KeyId=self._key_id, Message=msg, MessageType="RAW",
                                    SigningAlgorithm=ALGORITHM)["Signature"]
        except Exception as e:   # botocore's errors: network, throttling, access, a disabled key
            raise KeyUnavailable(f"KMS Sign: {type(e).__name__}: {str(e)[:512]}") from None
        if not crypto.verify_v2("ed25519", crypto.spki(self.public), msg, sig):
            raise KeyUnavailable(f"KMS Sign: {self._key_id} returned a signature its public key does not verify")
        return sig


def from_config(section):
    """The key the `log_key` config section names (load_config validated it)."""
    kms = section["aws_kms"]
    return AwsKmsKey(kms["key_id"], kms["region"])


def _libc():
    return ctypes.CDLL(None, use_errno=True) if os.name == "posix" else None


def harden():
    """No core dumps and, on Linux, not dumpable (no ptrace or /proc/<pid>/mem by the same user); best effort."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        HYGIENE["core_limit"] = 0
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        HYGIENE["dumpable"] = _libc().prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0


def mlock(buf):
    """Keep the pages of the bytes `buf` out of swap; skipped with a debug log when RLIMIT_MEMLOCK is too low."""
    # lean: locks the Python copy only, not the copies cryptography and OpenSSL keep; mlockall once the signer's
    # resident size fits RLIMIT_MEMLOCK
    libc = _libc()
    if libc is None:
        return
    if libc.mlock(ctypes.c_char_p(buf), ctypes.c_size_t(len(buf))) == 0:
        HYGIENE["mlock"] = HYGIENE["mlock"] is not False
    else:
        HYGIENE["mlock"] = False
        logging.getLogger(__name__).debug("mlock of a key failed (%s): RLIMIT_MEMLOCK too low?",
                                          os.strerror(ctypes.get_errno()))
