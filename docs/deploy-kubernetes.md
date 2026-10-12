# The signer on Kubernetes

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

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
| socket dir `/run/tracekit-signer` (emptyDir, 1 MiB) | mounted | mounted read-only, `TRACEKIT_SIGNER=/run/tracekit-signer/signer.sock` |
| keys and log (PVC, `persistence`) | mounted | not mounted |
| `signer.yaml` and `policy.yaml` (ConfigMap, `subPath`, root-owned) | mounted | not mounted |
| record key Secret (`recordKey.secretName`) | mounted | not mounted |

The socket directory is the only volume the two share, read-only in the agent's container: connecting needs write
access to the 0666 socket only, so the agent can't unlink or replace the socket or put anything at its path. The signer knows the agent by its peer uid: signer.yaml's
`tenants` maps `uid:<agent.uid>` to `signer.tenant`. Both containers run with `runAsNonRoot`, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, all capabilities dropped and the `RuntimeDefault` seccomp profile. If your agent
needs a writable path, mount an emptyDir of its own.

Values (`values.yaml` documents each):

- `signer.config`: more signer.yaml keys, e.g. `witnesses`. The chart's own keys (`data_dir`, `socket`, `socket_mode`,
  `durability`, `tenants`, `metrics`, `policy`) win over them.
- `signer.policy`: the signer's policy file, mounted at `/etc/tracekit/policy.yaml`. The default, `extends:
  packs/server.yaml`, runs the server pack the image ships in `/etc/tracekit/packs`
  ([policy-v2.md](policy-v2.md#packs-shipped)); replace it with your own, extending `packs/server.yaml` to keep its
  rules. The same value in the central chart sets every replica's policy.
- `signer.resources`, `agent.resources` (central: `signer`, `viewer`, `monitor`, `issuer` `.resources`): CPU and memory
  requests and limits; the defaults suit a light load, so size them for yours.
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
container, checks the agent cannot list the signer's keys, and runs doctor in the sidecar. Then it stops the signer
mid-run and checks that a fail-open call made while it was down shows as a signed `client_counter_gap` once it is back.
It needs docker, kind, kubectl and helm. `tests/test_helm.py` checks the rendered manifests where `helm` is installed.

## Central

`deploy/helm/tracekit-central` runs the signer as a service that agents in other pods reach over HTTPS. It is a
StatefulSet: replica n is the only writer of log n. Its config (`signer-<n>.yaml`, picked by the pod's ordinal), its
Postgres schema, its log key and its volume are n's alone, and Postgres holds the log's advisory lock for it, so two pods
never write one log.

```sh
helm install tk deploy/helm/tracekit-central --namespace tracekit \
    --set signer.image=ghcr.io/cygnux-labs/tracekit-signer@sha256:... \
    --set tls.secretName=tk-tls \
    --set awsKms.region=eu-west-1 --set 'awsKms.keyIds={alias/tk-log-0,alias/tk-log-1}' \
    --set serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::...:role/tk-signer
```

Before installing, for each replica n (0 up to `replicas`, or `autoscaling.maxReplicas` with the HPA):

- a Postgres schema, migrated with `tracekit signer migrate` as a migration role, and a signer role holding
  `tracekit.storage.postgres.GRANTS` on it;
- Secret `tracekit-log-<n>` (`postgres.dsnSecretPrefix`) whose `dsn` key is that role's DSN, its search_path the schema
  (`options=-csearch_path=tk_log_n`);
- with `awsKms`, an Ed25519 KMS key (`awsKms.keyIds[n]`) the signers' role may sign with. Without it, the log key is a
  file in the replica's volume.

`tls.secretName` is a `kubernetes.io/tls` Secret whose certificate names `tk.tracekit.svc` and `tk-<n>.tracekit.svc` for
every replica.

| | |
|---|---|
| identity | HTTPS (`:8443`) with `k8s_sa`: agents send a projected service-account token of audience `tracekit-signer` (`audience`), checked by TokenReview (the signers are bound to `system:auth-delegator`). Map identities to tenants and grants in `signer.config` (`tenants`, `authorize`). |
| routing | a new run goes to any ready replica (Service `tk`); its run id, and its approvals' ids, start with the replica's name, `tk-<n>.`, and the Python and TypeScript clients send every later call for them to Service `tk-<n>`. A run stays on the replica that registered it, also when another process resumes it. A client's own run_id must carry the prefix of the replica it names. Calls that name no run or approval (`status`, `approval_list` without a run) reach one replica: list each replica's approvals through its own Service (`tk-<n>`). `replicas` is at least 1: a replica scaled away closes its log for good. |
| containment | holds, quarantines and a paused response engine are each replica's own ([incidents](incidents.md)); suspensions are shared through `suspensions:`, a file on a volume every replica mounts. Send `tracekit signer incidents list`, `pause` and `unpause` to every replica (`--signer` per `tk-<n>`). |
| cloud credentials | only on the signers' ServiceAccount (`serviceAccount.annotations`, for workload identity to the KMS keys). Agent pods, the viewer and the monitor get none. |
| metrics | `:9464` on each replica: Prometheus, and with the monitor the record entries it reads. The chart's NetworkPolicy admits it only from `networkPolicy.monitoringNamespace` and the monitor. |

Agents:

```yaml
env:
  - {name: TRACEKIT_SIGNER, value: "https://tk.tracekit.svc:8443"}
  - {name: TRACEKIT_SIGNER_TOKEN_FILE, value: /var/run/secrets/tracekit/token}
  - {name: TRACEKIT_SIGNER_CA, value: /etc/tracekit-ca/ca.crt}
volumes:
  - name: tracekit-token
    projected: {sources: [{serviceAccountToken: {audience: tracekit-signer, expirationSeconds: 3600, path: token}}]}
```

Scaling. Scaling up adds replica n and with it log n. Scaling down closes the last replica's log for good: its preStop
hook sees its ordinal past the StatefulSet's replicas, and on SIGTERM the signer (`serve --close-on-stop`) writes
`log.closed` and the final notes, and waits up to 60 s for every witness to cosign them, so the log ends in a cosigned
note with no unproven tail. `signer.terminationGracePeriodSeconds` (120) covers it. A restart, an upgrade or an
uninstall closes nothing. A closed log takes no more records, and a signer refuses to serve one: before ordinal n runs
again, give it a new log (a new schema and DSN Secret, a new KMS key and `origin`). That is why the HPA only scales up
unless `autoscaling.scaleDown` is set.

The HPA scales on `tracekit_signer_queue_depth` averaged over the replicas, through
[prometheus-adapter](https://github.com/kubernetes-sigs/prometheus-adapter), for example:

```yaml
rules:
  custom:
    - seriesQuery: 'tracekit_signer_queue_depth{namespace!="",pod!=""}'
      resources: {overrides: {namespace: {resource: namespace}, pod: {resource: pod}}}
      metricsQuery: 'max_over_time(<<.Series>>{<<.LabelMatchers>>}[1m])'
```

Optional parts:

- `issuer.enabled`: the record-key issuer ([issuer.md](issuer.md)) with `issuer.config` (its issuer.yaml without
  `data_dir` and `http`), on `:8444` with `k8s_sa`. Point the signers' `record_key` at `https://tk-issuer.tracekit.svc:8444`
  in `signer.config`. Its own ServiceAccount takes the workload identity of a KMS `ca_key`.
- `viewer.enabled`: one `tracekit view` of every log on port 7778 ([viewer.md](viewer.md)), read with the DSNs of
  Secrets `tracekit-log-read-<n>`: a role holding `READ_GRANTS` only (SELECT). `viewer.config` adds to its
  viewer.yaml, such as `view.oidc` and the `http` section whose `oidc` issuers it names, for OIDC logins.
- `monitor.enabled`: `tracekit monitor` of each log, `monitor.logKeys[n]` being replica n's vkey
  (`kubectl exec tk-<n> -- tracekit signer vkey --config /etc/tracekit/central/signer-<n>.yaml`).

## Custody

The central chart also runs the services that hold credentials for the agents, each in its own pod with its own
ServiceAccount, its credentials from a Secret mounted only there:

| values | service | port | Secret (`secretName`, at `/etc/tracekit/secrets/`) |
|---|---|---|---|
| `gateway` | [LLM gateway](gateway.md) | 8080 | the provider key, as `api_key` |
| `executor` | [tool executor](executor.md) | 8090 | the files the actions' `headers` name |
| `mcpGateway` | [MCP gateway](mcp-gateway.md) | 8091 | the files the upstreams' `env` and `headers` name |

Each takes its config in `config` (without `http` and `signer`, which the chart sets), serves the agents on HTTPS with
`k8s_sa` (`tlsSecretName`: a certificate for `tk-<name>.tracekit.svc`; the pods are bound to `system:auth-delegator`
for TokenReview), and reaches the signers with a projected token of `audience` and the `ca.crt` of `tls.secretName`
(only that key is mounted). In `signer.config`, list their identities under `gateways` and grant them their calls:

```yaml
signer:
  config:
    gateways: ["k8s_sa:system:serviceaccount:tracekit:tk-gateway", "k8s_sa:system:serviceaccount:tracekit:tk-executor",
               "k8s_sa:system:serviceaccount:tracekit:tk-mcp-gateway"]
    authorize:
      "k8s_sa:system:serviceaccount:tracekit:tk-gateway": [model_event]
      "k8s_sa:system:serviceaccount:tracekit:tk-executor": [decide, complete, approval_request, approval_wait, approval_consume]
      "k8s_sa:system:serviceaccount:tracekit:tk-mcp-gateway": [decide, complete, approval_request, approval_wait, approval_consume, observe]
```

Each takes the agents' service-account tokens of its own audience, `<audience>-<name>` (`tracekit-signer-executor`
for the executor by default), never the signers' `audience`, so a token a custody service receives can't be replayed at
the signers. An agent pod mounts a projected token per service it calls, next to the one it sends the signers:

```yaml
volumes:
  - name: executor-token
    projected: {sources: [{serviceAccountToken: {audience: tracekit-signer-executor, expirationSeconds: 3600, path: token}}]}
```

Custody holds only if the agents can't reach the APIs around these services. `agentEgress.enabled` adds a
NetworkPolicy for the agent pods (`agentEgress.podSelector`, in `agentEgress.namespace`) that lets them reach only the
signers, the enabled custody services, the egress proxy (`agentEgress.egressProxy`) and DNS. `egress.enabled` runs
the chart's own [egress observer](egress.md) as `<release>-egress` on 3128, which the policy then allows too: the
agents' outside traffic goes through it and each run records the hosts it reached. Clients name their run with its
[`proxy_env`](egress.md#attribution) (`TRACEKIT_EGRESS_PROXY=https://<release>-egress.<namespace>.svc:3128`, with
`NO_PROXY=.svc,.cluster.local`); a plain `HTTPS_PROXY` without a run token is refused (407), since the observer
knows a networked client only by what it sends. Grant its identity `observe_effect` and set
`posture: {network: enforced}` in signer.config:

```yaml
agentEgress:
  enabled: true
  namespace: agents
  podSelector: {app: support-agent}
```

It is off by default: turning it on cuts every other connection the agents make. A NetworkPolicy's egress rules hold
only on a CNI that enforces them (Calico and Cilium do; some managed defaults don't): check from an agent pod that an
outside address is refused, for example `kubectl exec -n agents deploy/support-agent -- python -c
"import socket; socket.create_connection(('api.github.com', 443), 3)"` must time out. Keep the provider keys and action
secrets out of the agents' namespace altogether. The policy lets the agents reach kube-dns, which a DNS tunnel can carry
data through: filter DNS (a DNS-aware policy, a CoreDNS allow-list) where that matters. With NodeLocal DNSCache the
agents resolve through `169.254.20.10`, which the policy doesn't allow: add an egress rule for `169.254.20.10/32` on
port 53.

`tests/test_helm.py` checks the rendered manifests, `tests/test_central.py` the routing and the close on scale-down.
