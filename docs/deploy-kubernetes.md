# The signer on Kubernetes

## Sidecar

`deploy/helm/tracekit-signer` renders one agent Deployment with the signer (the image of
[deploy-container.md](deploy-container.md)) as a native sidecar: an init container with `restartPolicy: Always`, so it
is up before the agent starts and outlives it. Kubernetes 1.29 or later.

```sh
helm install my-agent deploy/helm/tracekit-signer \
    --set agent.image=registry.example/agent@sha256:... \
    --set signer.image=ghcr.io/cygnux-labs/tracekit-signer@sha256:...
kubectl exec deploy/my-agent -c tracekit-signer -- tracekit doctor --config /etc/tracekit/signer.yaml
```

What the chart sets up:

| | Signer (sidecar) | Agent |
|---|---|---|
| user | uid/gid 10001 (`signer.uid`) | uid 1000 (`agent.uid`); the chart refuses 0 and the signer's uid |
| socket dir `/run/tracekit-signer` (emptyDir, 1 MiB) | mounted | mounted, `TRACEKIT_SIGNER=/run/tracekit-signer/signer.sock` |
| keys and log (PVC, `persistence`) | mounted | not mounted |
| `signer.yaml` (ConfigMap, `subPath`, root-owned) | mounted | not mounted |
| record key Secret (`recordKey.secretName`) | mounted | not mounted |

The socket directory is the only volume the two share. The signer knows the agent by its peer uid: signer.yaml's
`tenants` maps `uid:<agent.uid>` to `signer.tenant`. Both containers run with `runAsNonRoot`, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, all capabilities dropped and the `RuntimeDefault` seccomp profile. If your agent
needs a writable path, mount an emptyDir of its own.

Values (`values.yaml` documents each):

- `signer.config`: more signer.yaml keys, e.g. `witnesses`. The chart's own keys (`data_dir`, `socket`, `socket_mode`,
  `durability`, `tenants`, `metrics`) win over them.
- `persistence`: the chart makes a `ReadWriteOnce` PVC kept on uninstall, or uses `existingClaim`. The volume's root
  must be writable by uid 10001; the signer keeps its data in a 0700 `data/` directory it makes there. The chart sets no
  `fsGroup`: that would add the signer's group to the agent's container too. `persistence.enabled: false` keeps the log
  in an emptyDir that dies with the pod: for development only (the install notes warn).
- `recordKey.secretName`: a Secret whose `record.key` (32 bytes) becomes the signer's record key on first start. A
  later start with a different Secret is refused. Without it the signer makes its own key in the data volume.
- `metrics.remote` serves metrics on the pod IP (port 9464) instead of loopback; `networkPolicy.enabled` then admits
  ingress to the pod only on 9464 from `networkPolicy.monitoringNamespace`. That policy covers the whole pod, the
  agent's ports included.
- `automountServiceAccountToken` is `false`: the pod gets no API token unless you turn it on.

No cloud credentials in the pod. GKE Workload Identity, EKS Pod Identity and the like give a pod's credentials to every
container in it, the agent's too, so a KMS log key in the sidecar would be one the agent can use. A KMS log key belongs
to the central signer, where the agent's pod holds no credentials for it.

The deployment runs one replica with the `Recreate` strategy: the signer holds its data volume's storage lock.

`deploy/helm/e2e.sh` installs the chart on a throwaway kind cluster, registers a run and decides a call from the agent
container, checks the agent cannot list the signer's keys, and runs doctor in the sidecar. It needs docker, kind,
kubectl and helm. `tests/test_helm.py` checks the rendered manifests where `helm` is installed.
