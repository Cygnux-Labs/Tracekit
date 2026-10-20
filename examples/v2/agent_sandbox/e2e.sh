#!/bin/sh
# End-to-end run of this example on a throwaway kind cluster (docs/integrations/agent-sandbox.md): install
# agent-sandbox, start the signer in namespace tracekit and pin its keys, run the agent in a Sandbox in namespace
# agents, delete the Sandbox, then export the agent's run from the signer and verify it here, offline. Needs docker,
# kind, kubectl, and a python with tracekit and its dependencies ($PY, default python3). kubectl uses a kubeconfig of
# its own, never yours.
set -eu
cd "$(dirname "$0")"
root=../../..
py=${PY:-python3}
image=tracekit-signer:local
cluster=tk-sandbox-$$
version=${AGENT_SANDBOX_VERSION:-v1.0.7}
dir=$(mktemp -d)
export KUBECONFIG="$dir/kubeconfig"

docker build -q -f "$root/deploy/docker/Dockerfile" -t "$image" "$root" >/dev/null
trap 'kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
kind create cluster --name "$cluster" --wait 120s >/dev/null
kind load docker-image "$image" --name "$cluster" >/dev/null
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$version/sandbox.yaml" >/dev/null
kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout 180s >/dev/null
echo "e2e: agent-sandbox $version installed"

# a throwaway CA, and the signer's certificate for tk.tracekit.svc
"$py" - "$dir" <<'EOF'
import datetime, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def issue(cn, key, ca_key=None, ca_name=None):
    name, now = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]), datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name or name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca_key is None, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if ca_key:
        b = (b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    return b.sign(ca_key or key, hashes.SHA256())


def write(name, data):
    with open(os.path.join(sys.argv[1], name), "wb") as f:
        f.write(data)


ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
ca = issue("tk-e2e-ca", ca_key)
write("ca.crt", ca.public_bytes(serialization.Encoding.PEM))
write("tls.crt", issue("tk.tracekit.svc", key, ca_key, ca.subject).public_bytes(serialization.Encoding.PEM))
write("tls.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
EOF

kubectl create namespace tracekit >/dev/null
kubectl -n tracekit create secret tls tk-tls --cert "$dir/tls.crt" --key "$dir/tls.key" >/dev/null
kubectl apply -f signer.yaml >/dev/null
kubectl -n tracekit rollout status deploy/tk --timeout 180s >/dev/null
signer() { kubectl -n tracekit exec deploy/tk -- sh -c "cd /var/lib/tracekit-signer && $1"; }
signer "tracekit signer trust --config /etc/tracekit/signer.yaml -o trust.json >/dev/null && cat trust.json &&
        rm trust.json" >"$dir/trust.json"
echo "e2e: signer up in namespace tracekit, its keys pinned"

kubectl create namespace agents >/dev/null
kubectl -n agents create configmap support-agent --from-file=agent.py >/dev/null
kubectl -n agents create configmap tracekit-ca --from-file=ca.crt="$dir/ca.crt" >/dev/null
kubectl apply -f sandbox.yaml >/dev/null
kubectl -n agents wait --for=condition=Ready sandbox/support-agent --timeout 180s >/dev/null
i=0
until kubectl -n agents logs support-agent -c agent 2>/dev/null | grep -q "waiting to be deleted"; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        kubectl -n agents logs support-agent -c agent >&2 || true
        echo "e2e: the agent did not finish its calls within 60 s" >&2
        exit 1
    fi
    sleep 1
done
kubectl -n agents logs support-agent -c agent | sed 's/^/e2e: agent: /'
run=$(kubectl -n agents logs support-agent -c agent | sed -n 's/^run //p')

kubectl -n agents delete sandbox support-agent --wait=true >/dev/null
kubectl -n agents wait --for=delete pod/support-agent --timeout 120s >/dev/null 2>&1 || true
if kubectl -n agents get pod support-agent >/dev/null 2>&1; then
    echo "e2e: the Sandbox's pod is still there" >&2
    exit 1
fi
echo "e2e: Sandbox and pod deleted with the run still open"

signer "tracekit export --v2 --run $run --tenant agents --config /etc/tracekit/signer.yaml -o run.tkb >/dev/null &&
        cat run.tkb && rm run.tkb" >"$dir/run.tkb"
"$py" -m tracekit verify "$dir/run.tkb" --trust "$dir/trust.json" --json | "$py" -c '
import json, sys, zipfile
report = json.load(sys.stdin)
if not report["integrity"].startswith("VERIFIED"):   # VERIFIED TO HEAD n (open): the deleted pod never closed it
    raise SystemExit(f"e2e: run bundle: {report}")
z = zipfile.ZipFile(sys.argv[1])
evs = [json.loads(line)["event"] for n in z.namelist() if n.startswith("runs/") for line in z.read(n).splitlines()]
reg = next(e["data"] for e in evs if e["type"] == "run.registered")
want = {"scheme": "k8s_sa", "subject": "system:serviceaccount:agents:support-agent", "attested": True}
if reg["identity"] != want or reg["signer_isolation"] != "remote":
    raise SystemExit(f"e2e: run registered as {reg}")
decided = {e["data"]["tool_use_id"]: (e["data"]["decision"], e["data"]["rule_ids"]) for e in evs
           if e["type"] == "policy.decision"}
if decided.get("c1", ("",))[0] != "allow" or decided.get("c2", ("",))[0] != "deny":
    raise SystemExit(f"e2e: decisions {decided}")
print("e2e:", report["integrity"], "offline; run registered by", want["subject"], "(attested); c2 denied by",
      *decided["c2"][1])
' "$dir/run.tkb"
echo "e2e: ok"
