"""The Cygnux public witness (tracekit.public_witness_server): the dev signer's and system mode's witness by default
once URL and VKEY below name its deployment (docs/public-witness.md; what it sees: docs/public-witness-privacy.md). A
signer.yaml lists it as `witnesses: [public]`, which `tracekit init --v2` writes then. Until both are set nothing is
anchored by default: `tracekit init --v2` and `tracekit up --wait` say so (NOT_CONFIGURED), and doctor's witness check
fails. `--no-witness` (init --v2, up) opts out until an init with `--public-witness`."""
import re

from .wiki import wiki_url

URL = ""    # https://<the deployment's domain>
VKEY = ""   # its cosignature vkey, as `tracekit public-witness init` prints it
ORIGIN = re.compile(r"[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?(/[A-Za-z0-9._~-]+)+")   # a log origin it takes: host/path
ORIGIN_FORMAT = "host/path: a lower-case host and at least one path segment, such as tracekit.example.com/log"
RANDOM_ORIGIN = re.compile(r"tracekit\.local/[0-9a-f]{32}")   # a signer's default origin: its random log id
NOT_CONFIGURED = "not anchored: the public witness isn't deployed yet, so no witness cosigns this log"
LOST = ("not anchored: --no-witness is on, so whoever holds the signing key can rewrite the log unseen (an init with "
        "--public-witness turns the public witness back on)")


def configured():
    return bool(URL and VKEY)


def entry():
    """The signer.yaml witness entry of the public witness."""
    if not configured():
        raise ValueError("the public witness is not deployed yet (tracekit.public_witness has no URL and vkey): "
                         f"list your own witness instead, {{url, vkey, class}} ({wiki_url('docs/witnesses.md')})")
    return {"url": URL, "vkey": VKEY, "class": "public"}


def named_origin(cfg):
    """The warning for a loaded signer.yaml `cfg` whose chosen origin (not the default random one) goes to the public
    witness with every checkpoint, or None: an origin like acme.com/agents tells the witness's operator whose log it is."""
    origin = cfg.get("origin")
    if not (configured() and origin and not RANDOM_ORIGIN.fullmatch(origin)
            and any(w["vkey"] == VKEY for w in cfg.get("witnesses") or ())):
        return None
    return (f"origin {origin} goes to the public witness with every checkpoint, so its operator can tell whose log "
            "this is. For a new log, leave origin unset (a random tracekit.local/<log id>), or use your own witness "
            f"({wiki_url('docs/public-witness-privacy.md')})")
