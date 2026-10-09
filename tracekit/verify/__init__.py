"""Offline verifiers: `v1` for tracekit.bundle.v1 (frozen), `v2` for tracekit.bundle.v2."""
import json
import zipfile

from tracekit.bundle_v2 import FORMAT


def is_v2(path):
    """True when `path` is a zip whose manifest names format v2. Standard library only, so checking a v1 bundle needs
    nothing else installed. Never raises."""
    try:
        with zipfile.ZipFile(path) as z, z.open("manifest.json") as f:
            return json.loads(f.read(1 << 20)).get("format") == FORMAT
    except Exception:
        return False
