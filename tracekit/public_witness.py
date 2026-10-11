"""The Cygnux public witness (tracekit.public_witness_server), opted into with signer.yaml `witnesses: [public]` or
`tracekit init --v2 --public-witness`. Its URL and cosignature vkey are set once it is deployed
(deploy/public-witness/README.md)."""
import re

URL = ""
VKEY = ""
ORIGIN = re.compile(r"[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?(/[A-Za-z0-9._~-]+)+")   # a log origin it takes: host/path
ORIGIN_FORMAT = "host/path: a lower-case host and at least one path segment, such as tracekit.example.com/log"


def entry():
    """The signer.yaml witness entry of the public witness."""
    if not (URL and VKEY):
        raise ValueError("the public witness is not deployed yet (tracekit.public_witness has no URL and vkey): "
                         "list your own witness instead, {url, vkey, class} (docs/witnesses.md)")
    return {"url": URL, "vkey": VKEY, "class": "public"}
