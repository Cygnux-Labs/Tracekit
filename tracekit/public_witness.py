"""The Cygnux public witness (tracekit.public_witness_server): every v2 signer's witness by default once URL and VKEY
below name its deployment (docs/public-witness.md). Until then both are
empty and nothing is anchored by default: `tracekit init --v2`, `tracekit up --wait` and `tracekit doctor` say so. Opt
out with `--no-witness` (init --v2, up); a signer.yaml lists it as `witnesses: [public]`, which `tracekit init --v2`
writes once it is configured."""
import re

from .wiki import wiki_url

URL = ""    # https://<the deployment's domain>
VKEY = ""   # its cosignature vkey, as `tracekit public-witness init` prints it
ORIGIN = re.compile(r"[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?(/[A-Za-z0-9._~-]+)+")   # a log origin it takes: host/path
ORIGIN_FORMAT = "host/path: a lower-case host and at least one path segment, such as tracekit.example.com/log"
NOT_CONFIGURED = ("not anchored yet: the public witness is not deployed yet (tracekit.public_witness has no URL and "
                  "vkey)")
LOST = ("with no witness, whoever holds the signing key can rewrite and re-sign the log unseen, and its bundles verify "
        "as NOT ANCHORED")


def configured():
    return bool(URL and VKEY)


def entry():
    """The signer.yaml witness entry of the public witness."""
    if not configured():
        raise ValueError("the public witness is not deployed yet (tracekit.public_witness has no URL and vkey): "
                         f"list your own witness instead, {{url, vkey, class}} ({wiki_url('docs/witnesses.md')})")
    return {"url": URL, "vkey": VKEY, "class": "public"}

