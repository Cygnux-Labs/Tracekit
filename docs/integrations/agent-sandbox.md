# Kubernetes agent-sandbox

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested: end to end on a kind cluster with agent-sandbox v1.0.7 (`examples/v2/agent_sandbox/e2e.sh`); not yet with a gVisor or Kata RuntimeClass ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

[agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) runs an agent in a `Sandbox`
(`agents.x-k8s.io/v1beta1`): one stateful pod the controller creates from the Sandbox's `podTemplate` and keeps running,
suspends or deletes. It leaves isolation to the pod's RuntimeClass (gVisor, Kata Containers, Kata with Firecracker).
Put the Tracekit signer outside the Sandbox, in its own namespace with its own volume and keys, and the record of what
the agent did survives the pod: a compromised agent can't rewrite it, and deleting the Sandbox doesn't take it along.

| | agent-sandbox | Tracekit |
|---|---|---|
| What it does | Runs the agent in an isolated, stateful pod and manages its lifecycle | Decides each call before it runs and signs a record of every call and decision |
| Where | The Sandbox's pod, in the agents' namespace | A signer Deployment in namespace `tracekit`, reached over HTTPS |
| When the Sandbox is deleted | Its pod, Service and volume claims go with it (it owns them) | The signed log stays: export any run and verify it offline |

The example is [examples/v2/agent_sandbox/](../../examples/v2/agent_sandbox/).

## How it fits together

- **The signer** (`signer.yaml`): one replica of the signer image ([container](../deploy-container.md)) as a Deployment
  with the `Recreate` strategy, its keys and log on a PersistentVolumeClaim only it mounts, serving HTTPS on
  `tk.tracekit.svc:8443`. It is the [central config](../deploy.md#central) with the file store: agents authenticate with
  `k8s_sa`, their projected service-account tokens checked by TokenReview (its ServiceAccount is bound to
  `system:auth-delegator`).
- **The agent** (`sandbox.yaml`): a Sandbox whose pod runs as ServiceAccount `support-agent` with
  `automountServiceAccountToken: false`, so it holds no API token. A projected token of audience `tracekit-signer` is
  the only credential it has, and the API server doesn't take a token of that audience as its own. The agent sets
  `TRACEKIT_SIGNER`, `TRACEKIT_SIGNER_TOKEN_FILE` and `TRACEKIT_SIGNER_CA` and uses the Python client; the
  [integrations](../quickstart-v2.md) and the TypeScript client read the same variables.
- **Identity**: the signer knows the agent as `k8s_sa:system:serviceaccount:agents:support-agent`, attested by the API
  server, and records it in the run. signer.yaml maps every service account in namespace `agents` to tenant `agents`
  and grants them `register_run`, `decide`, `complete` and `close_run` (add what your integration needs:
  [limits](../limits.md#deployment)).

The Sandbox uses `spec.podTemplate` with its `metadata.labels` and `spec` (a PodSpec). Nothing else is needed; a
RuntimeClass goes in `podTemplate.spec.runtimeClassName`, volumes in `spec.volumeClaimTemplates`.

## Run it

`examples/v2/agent_sandbox/e2e.sh` does all of this on a throwaway kind cluster (docker, kind, kubectl, and a python with
tracekit). By hand, on a cluster with agent-sandbox installed and the signer image in a registry it can pull from
(replace `tracekit-signer:local` in both manifests):

```sh
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.7/sandbox.yaml
cd examples/v2/agent_sandbox

kubectl create namespace tracekit
kubectl create secret tls tk-tls --cert tls.crt --key tls.key -n tracekit   # a certificate for tk.tracekit.svc
kubectl apply -f signer.yaml
kubectl exec deploy/tk -n tracekit -- sh -c 'cd /var/lib/tracekit-signer &&
    tracekit signer trust --config /etc/tracekit/signer.yaml -o trust.json >/dev/null && cat trust.json' > trust.json

kubectl create namespace agents
kubectl -n agents create configmap support-agent --from-file=agent.py
kubectl -n agents create configmap tracekit-ca --from-file=ca.crt   # the CA that issued tls.crt
kubectl apply -f sandbox.yaml
kubectl -n agents logs -f support-agent
```

Pin `trust.json` before the agent runs: it is what an auditor checks the bundle against. The agent prints its run id
and what the signer decided, then waits:

```text
run bc331339a17c0e7c7ee0433bc04331e4
c1 Bash: allow
c2 WebFetch: deny TK-N001 TK-S001 TK-F002 TK-F012
waiting to be deleted
```

Delete the Sandbox (its pod goes with it), then export the run from the signer and verify it anywhere, offline:

```sh
kubectl -n agents delete sandbox support-agent
kubectl exec deploy/tk -n tracekit -- sh -c 'cd /var/lib/tracekit-signer &&
    tracekit export --v2 --run <run id> --tenant agents --config /etc/tracekit/signer.yaml -o run.tkb >/dev/null &&
    cat run.tkb' > run.tkb
tracekit verify run.tkb --trust trust.json
```

The run reads `VERIFIED TO HEAD n (open)`: the pod was deleted before it closed its run. The signer closes it itself
once it has had no calls for `idle_s` (an hour by default) with a signed `run.closing` of reason `idle_timeout`; a
bundle exported after that reads `VERIFIED`. With no witness configured the assurance is `dev`: add a witness outside
the cluster ([witnesses](../witnesses.md)) so a rolled-back log is detected too.

## What the bundle shows and doesn't

- **Shows:** the run's `run.registered` with identity `k8s_sa` / `system:serviceaccount:agents:support-agent`
  (`attested: true`) and isolation `remote`, each decision with its rules (`c2` denied by `TK-S001`, the cloud metadata
  address, and `TK-N001`, an internal address; `TK-F002` and `TK-F012` are labels), each completed call, and the
  signed chain up to the last record the pod caused. Records commit to the arguments rather than store them
  ([privacy](../privacy.md)).
- **Doesn't show which pod:** the run records the service account, not the Sandbox or pod name. Give each Sandbox its
  own ServiceAccount when runs must be told apart by Sandbox.
- **Doesn't show the isolation:** the Sandbox's spec and RuntimeClass are not recorded. `isolation: remote` says the
  signer runs apart from the agent, not how the agent's pod is isolated.
- **Doesn't see what the agent doesn't ask about:** the agent calls `decide` from its own process, so a compromised one
  can act without asking. Run its tools, MCP servers and model calls through the custody services and allow the
  Sandbox's pod to reach only those ([custody](../deploy-kubernetes.md#custody)).

[Limits](../limits.md) lists these with what to do.
