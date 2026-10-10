# The signer as a container

`deploy/docker/Dockerfile` builds the v2 signer (`tracekit-ai[signer]`, with google-re2 where it has a wheel) on a
digest-pinned `python:3.12-slim` base. It runs `tracekit signer serve --config /etc/tracekit/signer.yaml` as uid/gid
10001 and works with a read-only root filesystem.

```sh
docker build -f deploy/docker/Dockerfile --build-arg VERSION=0.4.0 --build-arg REVISION=$(git rev-parse HEAD) \
    -t tracekit-signer .
sh deploy/docker/smoke.sh     # build, run, decide a call over the socket, check uid and writes, run doctor
```

| Path | What | Mount |
|---|---|---|
| `/etc/tracekit/signer.yaml` | config; the image ships `deploy/docker/signer.yaml.example` (sidecar) | read-only, root-owned (ConfigMap) |
| `/var/lib/tracekit-signer` | keys and log (`data_dir`), 0700 uid 10001 | a volume only the signer mounts (PVC) |
| `/run/tracekit-signer` | the Unix socket (sidecar) | shared with the agent's container |

Ports: 8443 (the `http` listener, central) and 9464 (metrics; the `HEALTHCHECK` reads `/metrics` there, so keep a
`metrics` section in signer.yaml). Run it with `--read-only --cap-drop ALL --security-opt no-new-privileges`.

Doctor runs in the image: `docker run --rm -v DATA:/var/lib/tracekit-signer --entrypoint tracekit tracekit-signer
doctor --config /etc/tracekit/signer.yaml`. Expect `D-CODE-TRUST` (no `/opt/tracekit` venv) and the systemd/launchd
check to fail or warn there: they are about laptop system mode. The image is your code trust: pin it by digest.

## Sidecar

The signer runs next to the agent in the same pod, as a different user. The agent reaches it only through the socket
and is identified by its peer uid (`tenants: {"uid:1000": ...}` in signer.yaml).

```yaml
spec:
  automountServiceAccountToken: false     # no cloud or API credentials in the pod
  initContainers:
    - name: tracekit-signer               # a native sidecar (Kubernetes 1.29+)
      image: tracekit-signer@sha256:...
      restartPolicy: Always
      securityContext: {runAsUser: 10001, runAsGroup: 10001, runAsNonRoot: true, readOnlyRootFilesystem: true,
                        allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: signer-data, mountPath: /var/lib/tracekit-signer}
        - {name: signer-socket, mountPath: /run/tracekit-signer}
        - {name: signer-config, mountPath: /etc/tracekit, readOnly: true}
  containers:
    - name: agent
      securityContext: {runAsUser: 1000, runAsNonRoot: true, allowPrivilegeEscalation: false}
      env: [{name: TRACEKIT_SIGNER, value: /run/tracekit-signer/signer.sock}]
      volumeMounts:
        - {name: signer-socket, mountPath: /run/tracekit-signer}
  volumes:
    - {name: signer-data, persistentVolumeClaim: {claimName: tracekit-signer-data}}
    - {name: signer-socket, emptyDir: {}}
    - {name: signer-config, configMap: {name: tracekit-signer}}
```

The data volume's root must belong to uid 10001 with mode 0700 (doctor's `D-KEYS-MODE` checks it): prepare the PVC
for that uid. Don't use `fsGroup: 10001` for it: that makes the volume group-writable and adds group 10001 to every
container of the pod, the agent's too.

## Central

One signer Deployment serves many agents over HTTPS. Use the central block of `signer.yaml.example`: an `http` listener
with a TLS certificate and `k8s_sa` (service-account tokens checked by TokenReview) or `mtls` (SPIFFE ids) identity,
`tenants` and `authorize` keyed by those identities, and metrics on `0.0.0.0:9464` with `allow_remote: true`. Agents set
`TRACEKIT_SIGNER=https://signer.example:8443`. Mount the TLS key and the data volume into the signer only.

## Never mount into the agent's container

- the signer's data volume (`/var/lib/tracekit-signer`): its keys and log;
- `signer.yaml`, the policy and the TLS key, or anything that lets the agent change them;
- the signer's service-account token, or cloud credentials (KMS, storage) the signer uses.

The agent shares only the socket directory, and its user must not be uid 10001 or root.
