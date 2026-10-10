#!/bin/sh
# End-to-end test of the Helm chart on a throwaway kind cluster: build the signer image, install the chart with the
# image as the agent too, register a run and decide a call from the agent container, check the agent cannot read the
# signer's files, then run `tracekit doctor` in the sidecar. Needs docker, kind, kubectl and helm.
set -eu
cd "$(dirname "$0")/../.."
image=tracekit-signer:e2e
cluster=tk-e2e-$$
release=tk

docker build -q -f deploy/docker/Dockerfile -t "$image" . >/dev/null
trap 'kind delete cluster --name "$cluster" >/dev/null 2>&1 || true' EXIT
kind create cluster --name "$cluster" --wait 120s >/dev/null
kind load docker-image "$image" --name "$cluster" >/dev/null
helm install "$release" deploy/helm/tracekit-signer --wait --timeout 5m \
    --set signer.image="$image" --set agent.image="$image" --set-json 'agent.command=["sleep","infinity"]' >/dev/null

kubectl exec "deploy/$release" -c agent -- python -c '
import os
from tracekit.sdk.client import Client
with Client(os.environ["TRACEKIT_SIGNER"]).run(agent="e2e") as run:
    d = run.decide("c1", "Bash", {"command": "ls"})
    assert d["decision"] == "allow", d
    run.complete("c1")
print("e2e: run registered, call decided allow")'

if kubectl exec "deploy/$release" -c agent -- ls /var/lib/tracekit-signer/data/keys >/dev/null 2>&1; then
    echo "e2e: the agent can list the signer's keys" >&2
    exit 1
fi
echo "e2e: the agent cannot read the signer's files"

# doctor exits 1 here (no witnesses, no /opt/tracekit venv in the image); the checks it can run in a pod must pass
kubectl exec "deploy/$release" -c tracekit-signer -- tracekit doctor --json --config /etc/tracekit/signer.yaml \
    | python3 -c '
import json, sys
results = {r["id"]: r for r in json.load(sys.stdin)}
bad = [results.get(i, {"id": i, "status": "missing"}) for i in
       ("D-CONFIG", "D-PROCESS-BOUNDARY", "D-KEYS-MODE", "D-KEYS-DISTINCT", "D-POLICY-TRUST", "D-POLICY-ENGINE", "D-DURABILITY", "D-DATA-FS")
       if results.get(i, {}).get("status") != "ok"]
if bad:
    raise SystemExit(f"e2e: doctor: {bad}")
print("e2e: doctor clean")'
echo "e2e: ok"
