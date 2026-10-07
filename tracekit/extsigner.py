"""External signers: keep the signing key out of the signer host's filesystem (TPM, HSM, smart card, enclave, KMS).

config.json of the signer home:

    "signer": {"type": "external", "argv": ["/usr/local/bin/tk-hsm-signer", "--slot", "0"],
               "public_key": "/etc/tracekit/hsm-signer.pub", "assurance": "hsm"}

The helper is started once and kept running. Protocol, one request per line on stdin, one reply per line on stdout:

    request:  sign <hex message>\n          reply:  ok <hex 64-byte Ed25519 signature>\n   or   err <text>\n

Every signature the helper returns is verified against the configured public key before it is used, so a helper that
signs with the wrong key, or returns garbage, stops the signer instead of writing an unverifiable ledger. If the helper
dies it is restarted once per request; if it still fails the write fails (retryable for clients), it is never skipped.

``assurance`` is your statement of where the key lives (e.g. "tpm", "hsm", "tee", "kms"). It is signed into every
checkpoint and shown by the verifier, but Tracekit cannot attest it: pair it with the device's own attestation where
the hardware offers one. A reference helper that keeps a key in a separate process is in examples/ext_signer.py.

``attestation`` (optional) is the path of that attestation document: a TPM quote, an enclave attestation document, a KMS
key's metadata export. Its SHA-256 is signed into every checkpoint and `tracekit export` puts the document itself in the
bundle, so a reviewer gets the evidence with the run. Tracekit checks that the document is the one the checkpoints name;
checking what it says (the vendor's certificate chain, PCR values, that it binds this public key) is the reviewer's step,
with the vendor's tools."""
import hashlib
import binascii
import subprocess
import threading

from . import crypto

ASSURANCES = {"file", "external", "tpm", "hsm", "tee", "kms", "smartcard"}


class SignerError(OSError):
    """An OSError so the signer reports it like a failed disk write: retryable for the client, ledger unchanged."""


class ExternalKeys:
    def __init__(self, argv, public, assurance="external", timeout=10.0):
        if len(public) != 32:
            raise SignerError("external signer public key must be the raw 32-byte Ed25519 key")
        if assurance not in ASSURANCES:
            raise SignerError(f"assurance must be one of {sorted(ASSURANCES)}")
        self.argv, self.public, self.kid, self.assurance = list(argv), public, crypto.kid(public), assurance
        self.attestation_sha256 = None
        self.secret = None  # never in this process
        self.timeout = timeout
        self._p = None
        self._lock = threading.Lock()

    def _start(self):
        self._p = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, bufsize=1)

    def _ask(self, msg):
        if self._p is None or self._p.poll() is not None:
            self._start()
        self._p.stdin.write("sign " + binascii.hexlify(msg).decode() + "\n")
        self._p.stdin.flush()
        reply = [None]
        t = threading.Thread(target=lambda: reply.__setitem__(0, self._p.stdout.readline()), daemon=True)
        t.start()
        t.join(self.timeout)
        if t.is_alive():
            self._p.kill()
            self._p = None
            raise SignerError(f"external signer did not answer within {self.timeout:.0f}s")
        line = (reply[0] or "").strip()
        if not line:
            raise SignerError("external signer exited")
        if line.startswith("err "):
            raise SignerError("external signer refused: " + line[4:200])
        if not line.startswith("ok "):
            raise SignerError("external signer protocol error")
        return binascii.unhexlify(line[3:].strip())

    def sign(self, msg):
        with self._lock:
            sig, last = None, None
            for _ in range(2):  # one restart of a dead or confused helper, then give up
                try:
                    sig = self._ask(msg)
                    break
                except (OSError, ValueError, binascii.Error) as e:
                    last = e
                    if self._p is not None and self._p.poll() is None:
                        self._p.kill()
                    self._p = None
            if sig is None:
                raise SignerError(f"external signer failed: {last}")
        if len(sig) != 64 or not crypto.verify(self.public, msg, sig):
            raise SignerError("external signer returned a signature that does not verify with the configured public key")
        return sig

    def close(self):
        if self._p is not None and self._p.poll() is None:
            self._p.terminate()


def load(cfg, default_loader):
    """cfg: the signer config. -> keys object (file key unless cfg['signer'] says otherwise)."""
    sc = cfg.get("signer") or {}
    if sc.get("type", "file") == "file":
        return default_loader()
    if sc.get("type") != "external":
        raise SignerError(f"unknown signer type {sc.get('type')!r}")
    with open(sc["public_key"], "rb") as f:
        pub = f.read()
    k = ExternalKeys(sc["argv"], pub, sc.get("assurance", "external"), float(sc.get("timeout_s", 10)))
    if sc.get("attestation"):
        k.attestation_sha256 = hashlib.sha256(read_attestation(sc["attestation"])).hexdigest()
    k.sign(b"tracekit external signer self-test")  # fail at start, not at the first event
    return k


MAX_ATTESTATION = 1 << 20


def read_attestation(path):
    with open(path, "rb") as f:
        data = f.read(MAX_ATTESTATION + 1)
    if not data or len(data) > MAX_ATTESTATION:
        raise SignerError(f"attestation document {path} must be 1 byte to 1 MiB")
    return data
