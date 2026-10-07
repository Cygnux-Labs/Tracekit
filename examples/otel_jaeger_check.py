#!/usr/bin/env python3
"""Check that every span Jaeger holds for Tracekit points at a record of a verified bundle.

    tracekit otel push --endpoint http://localhost:4318 --all       # send the runs to Jaeger
    tracekit export --out run.tkb                                   # the same runs as evidence
    python3 examples/otel_jaeger_check.py run.tkb http://localhost:16686

Runs `tracekit verify` on the bundle, reads the spans back from Jaeger's query API (v3), and matches each span's
`tracekit.entry_hash` to a signed record in the bundle. Exit 0 only if the bundle verifies and every span matches."""
import json
import os
import sys
import urllib.parse
import urllib.request
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tracekit import bundle  # noqa: E402


def main(tkb, jaeger="http://localhost:16686", service="tracekit"):
    _rep, code = bundle.verify(tkb)
    print("tracekit verify exit:", code)
    with zipfile.ZipFile(tkb) as z:
        hashes = {json.loads(line)["hash"] for line in z.read("records.jsonl").decode().splitlines() if line.strip()}
    q = urllib.parse.urlencode({"query.service_name": service, "query.start_time_min": "2000-01-01T00:00:00Z",
                                "query.start_time_max": "2100-01-01T00:00:00Z"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # Jaeger is local: never via a proxy
    with opener.open(f"{jaeger.rstrip('/')}/api/v3/traces?{q}", timeout=10) as r:
        data = json.load(r)
    spans = [s for rs in data["result"]["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]
    matched = 0
    for s in spans:
        attrs = {a["key"]: next(iter(a["value"].values()), None) for a in s.get("attributes", [])}
        h = str(attrs.get("tracekit.entry_hash") or "")
        hit = h.split(":")[-1] in hashes
        matched += hit
        print(f"  {s['name']:<32} seq {attrs.get('tracekit.seq')!s:>4}  {h[:23]}  {'in bundle' if hit else 'NOT IN BUNDLE'}")
    print(f"{matched}/{len(spans)} spans resolve to a signed record in the verified bundle")
    return 0 if code == 0 and spans and matched == len(spans) else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
