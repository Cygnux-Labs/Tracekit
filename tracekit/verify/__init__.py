"""Offline verifiers: `v1` for tracekit.bundle.v1 (frozen), `v2` for tracekit.bundle.v2."""
import json
import zipfile

from tracekit.bundle_v2 import FORMAT


def is_v2(path):
    """True when `path` is a zip whose manifest names format v2, False when it names another, None when the file can't
    be read as a zip or has no readable manifest. Standard library only, so checking a v1 bundle needs nothing else
    installed. Never raises."""
    try:
        with zipfile.ZipFile(path) as z, z.open("manifest.json") as f:
            manifest = json.loads(f.read(1 << 20))
    except Exception:
        return None
    return isinstance(manifest, dict) and manifest.get("format") == FORMAT
