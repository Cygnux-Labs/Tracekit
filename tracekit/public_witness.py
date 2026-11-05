"""The Cygnux public witness (tracekit.public_witness_server): every v2 signer's witness by default once URL and VKEY
below name its deployment (docs/public-witness.md). Until then both are empty and the default is no witness: `tracekit
init --v2`, `tracekit up` and `tracekit doctor` say the public witness isn't configured yet. Opt out with `--no-witness`
(init --v2, up); a signer.yaml lists it as `witnesses: [public]`, which `tracekit init --v2` writes."""
import re

from .wiki import wiki_url

URL = ""    # https://<the deployment's domain>
VKEY = ""   # its cosignature vkey, as `tracekit public-witness init` prints it
ORIGIN = re.compile(r"[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?(/[A-Za-z0-9._~-]+)+")   # a log origin it takes: host/path
ORIGIN_FORMAT = "host/path: a lower-case host and at least one path segment, such as tracekit.example.com/log"
NOT_CONFIGURED = "the public witness isn't configured yet (tracekit.public_witness has no URL and key)"
LOST = ("with no witness, whoever holds the signing key can rewrite and re-sign the log unseen, and its bundles verify "
        "as NOT ANCHORED")


def configured():
    return bool(URL and VKEY)


def entry():
    """The signer.yaml witness entry of the public witness."""
    if not configured():
        raise ValueError(f"{NOT_CONFIGURED}: list your own witness instead, {{url, vkey, class}} "
                         f"({wiki_url('docs/witnesses.md')})")
    return {"url": URL, "vkey": VKEY, "class": "public"}
