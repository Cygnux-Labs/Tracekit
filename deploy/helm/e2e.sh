#!/bin/sh
# End-to-end test of the Helm chart on a throwaway kind cluster: build the signer image, install the chart with the
# image as the agent too, register a run and decide a call from the agent container, check the agent cannot read the
# signer's files, run `tracekit doctor` in the sidecar, then stop the signer mid-run: a fail-open (fs) call made while
# it is down must show up as a signed client_counter_gap once it is back. Needs docker, kind, kubectl and helm.
set -eu
cd "$(dirname "$0")/../.."
image=tracekit-signer:e2e
cluster=tk-e2e-$$
release=tk
dir=$(mktemp -d)

docker build -q -f deploy/docker/Dockerfile -t "$image" . >/dev/null
trap 'rm -rf "$dir"; kind delete cluster --name "$cluster" >/dev/null 2>&1 || true' EXIT
kind create cluster --name "$cluster" --wait 120s >/dev/null
kind load docker-image "$image" --name "$cluster" >/dev/null
helm install "$release" deploy/helm/tracekit-signer --wait --timeout 5m \
    --set signer.image="$image" --set agent.image="$image" --set-json 'agent.command=["sleep","infinity"]' \
    --set-json 'signer.config={"fail_modes":{"default":"closed","fs":"open"}}' >/dev/null

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
if kubectl exec "deploy/$release" -c agent -- rm /run/tracekit-signer/signer.sock >/dev/null 2>&1; then
    echo "e2e: the agent can remove the signer's socket" >&2
    exit 1
fi
echo "e2e: the agent cannot read the signer's files or replace its socket"

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

# The agent registers a run, prints its id and drops its connection; the script then stops the signer (SIGTERM to the
# sidecar's pid 1, which the native sidecar's restartPolicy brings back). Call c1 is made while it is down and runs per
# the fs fail mode; c2, once it is back, makes the signer write the gap for c1's client_seq.
kubectl exec "deploy/$release" -c agent -- python -c '
import os, socket, sys, time
from tracekit.sdk.client import Client, SignerUnavailable, fail_open
path, read = os.environ["TRACEKIT_SIGNER"], ("Read", {"file_path": "a.txt"})

def wait_until(up):
    deadline = time.monotonic() + 120
    while True:
        s = socket.socket(socket.AF_UNIX)
        try:
            s.connect(path)
            if up:
                return
        except OSError:
            if not up:
                return
        finally:
            s.close()
        if time.monotonic() > deadline:
            sys.exit("e2e: the signer did not " + ("come back" if up else "stop") + " within 120 s")
        time.sleep(0.05)

c = Client(path, timeout=10)
run = c.run("e2e-outage")
assert fail_open(run.registered["fail_modes"], "fs"), run.registered
run.decide("c0", *read)
run.complete("c0")
print(run.run_id, flush=True)
c.close()
wait_until(False)
try:
    run.decide("c1", *read)
    sys.exit("e2e: a call was decided while the signer was down")
except SignerUnavailable:
    pass
wait_until(True)
run.decide("c2", *read)
run.complete("c2")
run.close()' >"$dir/agent.out" &
agent=$!
i=0
until [ -s "$dir/agent.out" ]; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "e2e: the agent registered no run within 60 s" >&2
        exit 1
    fi
    sleep 1
done
kubectl exec "deploy/$release" -c tracekit-signer -- sh -c 'kill 1'
wait "$agent" || { echo "e2e: the agent's run across the signer restart failed" >&2; exit 1; }
run=$(head -n 1 "$dir/agent.out")
echo "e2e: signer stopped and back mid-run; the fail-open call ran while it was down"

signer() { kubectl exec "deploy/$release" -c tracekit-signer -- sh -c "cd /var/lib/tracekit-signer && $1"; }
signer "tracekit signer trust --config /etc/tracekit/signer.yaml -o e2e-trust.json >/dev/null &&
        tracekit export --v2 --run $run --config /etc/tracekit/signer.yaml -o e2e.tkb >/dev/null"
signer "cat e2e.tkb" >"$dir/run.tkb"
signer "tracekit verify e2e.tkb --trust e2e-trust.json --json; rm -f e2e.tkb e2e-trust.json" | python3 -c '
import json, sys, zipfile
report = json.load(sys.stdin)
if not report["integrity"].startswith("VERIFIED"):   # VERIFIED TO HEAD n (open): exported before run.final
    raise SystemExit(f"e2e: run bundle: {report}")
z = zipfile.ZipFile(sys.argv[1])
evs = [json.loads(line)["event"] for n in z.namelist() if n.startswith("runs/") for line in z.read(n).splitlines()]
seqs = [e["client_seq"] for e in evs if "client_seq" in e]
gaps = [e["data"]["missed_events"] for e in evs if e["type"] == "capture.gap" and e["data"]["kind"] == "client_counter_gap"]
if gaps != [1] or seqs[:3] != [0, 1, 3]:
    raise SystemExit(f"e2e: want one client_counter_gap for client_seq 2; gaps {gaps}, client_seqs {seqs}")
print("e2e: a signed client_counter_gap covers the call made while the signer was down")' "$dir/run.tkb"
echo "e2e: ok"
