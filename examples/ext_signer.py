"""Reference external signer helper for Tracekit (see tracekit/extsigner.py for the protocol).

It holds an Ed25519 key in its own process, reading it from a file only it can read. Replace the two marked lines with a
call to your TPM, HSM, smart card or KMS to keep the key in hardware; the protocol stays the same.

    python3 examples/ext_signer.py --key /etc/tracekit/hsm-sim.key            # run by tracekitd, not by hand
    python3 examples/ext_signer.py --key /etc/tracekit/hsm-sim.key --init     # create the key, print the public key path"""
import argparse
import binascii
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--init", action="store_true")
    a = ap.parse_args()
    if a.init:
        k = Ed25519PrivateKey.generate()
        fd = os.open(a.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        with open(a.key + ".pub", "wb") as f:
            f.write(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        print(a.key + ".pub")
        return 0
    with open(a.key, "rb") as f:
        key = Ed25519PrivateKey.from_private_bytes(f.read())          # <- hardware: open a session to the device instead
    for line in sys.stdin:
        try:
            op, _, arg = line.strip().partition(" ")
            if op != "sign":
                raise ValueError("unknown op")
            sig = key.sign(binascii.unhexlify(arg))                  # <- hardware: ask the device to sign
            sys.stdout.write("ok " + binascii.hexlify(sig).decode() + "\n")
        except Exception as e:  # never crash on a bad request; say why
            sys.stdout.write("err " + str(e).replace("\n", " ")[:200] + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
