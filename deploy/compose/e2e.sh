#!/bin/sh
# End to end: write the stack with `tracekit deploy compose`, its witness classed customer (as when someone else runs
# it), bring it up, register a run from the agent service, wait until the witness has cosigned a checkpoint covering
# it, export the run, verify it with the signer's trust config at `witnessed`, take the stack down. Needs docker, and
# root or passwordless sudo (each secret is owned by its container's uid). WITNESS=litewitness builds litewitness.
# tests/test_compose.py runs it.
set -eu
cd "$(dirname "$0")/../.."
py=$(command -v "${PYTHON:-python3}")
sudo=
[ "$(id -u)" = 0 ] || sudo="sudo -n"
dir=$(mktemp -d)
dc() { docker compose -f "$dir/stack/docker-compose.yaml" -p "tk-e2e-$$" "$@"; }
cleanup() {
    dc --profile agent down -v >/dev/null 2>&1 || true
    $sudo rm -rf "$dir"
}
trap cleanup EXIT

$sudo "$py" -m tracekit deploy compose --dir "$dir/stack" --witness-class customer >/dev/null
dc build -q --build-arg WITNESS="${WITNESS:-omniwitness}"
dc up -d --wait --wait-timeout 180
run=$(dc run --rm -T agent | tail -n 1 | cut -d' ' -f1)
echo "e2e: run $run registered and closed by the agent service"

signer() { dc exec -T signer sh -c "$1 >/dev/null && cat /tmp/out"; }
signer "tracekit signer trust --config /etc/tracekit/signer.yaml -o /tmp/out" >"$dir/trust.json"
i=0
until signer "tracekit export --v2 --run $run --config /etc/tracekit/signer.yaml -o /tmp/out" >"$dir/run.tkb" \
        && "$py" -m tracekit verify "$dir/run.tkb" --trust "$dir/trust.json" --json >"$dir/report.json" \
        && "$py" -c 'import json, sys; r = json.load(open(sys.argv[1]))
sys.exit(not (r["integrity"] == "VERIFIED" and r["assurance"].startswith("witnessed;")))' "$dir/report.json"; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
        cat "$dir/report.json" >&2 || true
        dc logs signer witness >&2
        echo "e2e: no witnessed checkpoint of run $run after 180 s" >&2
        exit 1
    fi
    sleep 2
done
"$py" -c 'import json, sys; print("e2e:", json.load(open(sys.argv[1]))["assurance"])' "$dir/report.json"
echo "e2e: ok (${WITNESS:-omniwitness})"
