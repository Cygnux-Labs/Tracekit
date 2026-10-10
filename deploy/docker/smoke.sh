#!/bin/sh
# Smoke test of the signer image: build it, run it read-only with fresh volumes, register a run and decide a call from
# a second container (another uid) through the shared socket dir, mounted read-only, check the signer's uid and that it
# can write only its volumes, then run `tracekit doctor --config` in the image (the server policy pack). Needs docker; tests/test_container.py runs it.
set -eu
cd "$(dirname "$0")/../.."
image=${IMAGE:-tracekit-signer:smoke}
tag=tk-smoke-$$
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' tracekit/__init__.py)
revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)

docker build -q -f deploy/docker/Dockerfile --build-arg VERSION="$version" --build-arg REVISION="$revision" \
    -t "$image" . >/dev/null
cleanup() {
    docker rm -f "$tag" >/dev/null 2>&1 || true
    docker volume rm "$tag-data" "$tag-run" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$tag-data" >/dev/null
docker volume create "$tag-run" >/dev/null
docker run -d --name "$tag" --read-only --cap-drop ALL --security-opt no-new-privileges --health-interval 1s \
    -v "$tag-data:/var/lib/tracekit-signer" -v "$tag-run:/run/tracekit-signer" "$image" >/dev/null

i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$tag")" = healthy ]; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        docker logs "$tag"
        echo "smoke: signer not healthy after 60 s" >&2
        exit 1
    fi
    sleep 1
done

docker run --rm --read-only --cap-drop ALL --user 1000:1000 -v "$tag-run:/run/tracekit-signer:ro" \
    --entrypoint python "$image" -c '
from tracekit.sdk.client import Client
with Client("/run/tracekit-signer/signer.sock").run(agent="smoke") as run:
    d = run.decide("c1", "Bash", {"command": "ls"})
    assert d["decision"] == "allow", d
    run.complete("c1")
print("smoke: run registered, call decided allow")'

docker exec "$tag" python -c '
import os, re
uid = re.search(r"Uid:\s+(\d+)", open("/proc/1/status").read()).group(1)
assert uid == "10001", f"signer runs as uid {uid}"
for d in ("/", "/etc/tracekit", "/usr/local/lib", "/tmp", "/home"):
    try:
        open(os.path.join(d, "smoke-probe"), "x").close()
    except OSError:
        continue
    raise SystemExit(f"smoke: the signer can write {d}")
for d in ("/var/lib/tracekit-signer", "/run/tracekit-signer"):
    p = os.path.join(d, "smoke-probe")
    open(p, "x").close()
    os.unlink(p)
print("smoke: signer is uid 10001 and writes only its volumes")'

# doctor exits 1 here (no witnesses, no /opt/tracekit venv in the image); the checks it can run in a container must pass
docker run --rm --read-only -v "$tag-data:/var/lib/tracekit-signer" --entrypoint tracekit "$image" \
    doctor --json --config /etc/tracekit/signer.yaml | docker run --rm -i --entrypoint python "$image" -c '
import json, sys
results = {r["id"]: r for r in json.load(sys.stdin)}
bad = [results.get(i, {"id": i, "status": "missing"}) for i in
       ("D-CONFIG", "D-PROCESS-BOUNDARY", "D-KEYS-MODE", "D-KEYS-DISTINCT", "D-POLICY-TRUST", "D-POLICY-ENGINE", "D-DURABILITY", "D-DATA-FS")
       if results.get(i, {}).get("status") != "ok"]
if bad:
    raise SystemExit(f"smoke: doctor: {bad}")
policy = results["D-POLICY-ENGINE"]["detail"]
if not policy.startswith("/etc/tracekit/packs/server.yaml "):
    raise SystemExit(f"smoke: not the server pack: {policy}")
print("smoke: doctor:", results["D-POLICY-ENGINE"]["detail"])'
echo "smoke: ok ($image)"
