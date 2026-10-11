# Deploying the signer

One signer program, `tracekit signer serve`, runs in every mode. The agent's code doesn't change between modes:
`TRACEKIT_SIGNER` points it at the signer (a socket path or an `https://` URL), and without it the client starts a
dev signer of its own. What changes is **who can reach the signer's keys and store**, and that decides what a bundle
can prove.

| Mode | Platforms | Agent reaches the signer by | Who can reach the keys and store | Recorded `isolation` |
|---|---|---|---|---|
| [Laptop dev](#laptop-dev) | Linux, macOS, Windows | auto-spawned Unix socket (Windows: loopback TCP) | the agent's own user | `same-user` |
| [Laptop system mode](#laptop-system-mode) | Linux; macOS experimental | `/run/tracekit-signer/signer.sock` | root and the signer's OS user | `separate-user` |
| [Container sidecar](#container-and-kubernetes-sidecar) | Linux containers, Kubernetes 1.29+ | a socket in a shared directory | the signer's uid and whoever runs the node | `separate-user` |
| [Central](#central) | Linux containers | HTTPS (`k8s_sa`, `mtls` or `token` identity) | whoever administers the signer's host and storage | `remote` |
| [Compose](#compose) | Docker Compose | HTTPS on a private network | whoever administers the Docker host | `remote` |

What each mode defends, and against whom: [threat model: laptop](threat-model-laptop.md) (attackers A1–A4) and
[threat model: server](threat-model-server.md) (adversaries S1–S6). How to read the report a bundle gets:
[verdicts](verdicts.md).

## What decides a bundle's assurance

`tracekit verify` prints two lines ([verdicts](verdicts.md)). `Integrity` is the same in every mode: a bundle whose
records were signed by the log key you pinned, in one unbroken chain covered by a checkpoint, reads `VERIFIED`.
`Assurance` depends on who vouches for the checkpoint, not on the mode:

- `dev`: no pinned witness cosigned the checkpoint, or a run holds a self-approval.
- `local`: only `operator`-class witnesses (ones you run yourself) cosigned it.
- `witnessed`: enough independent witnesses cosigned it, or a pinned Rekor anchor verified ([witnesses](witnesses.md)).
- `witnessed+monitored`: `witnessed`, plus a fresh, conflict-free report of a monitor your trust config pins
  ([monitor](monitor.md)).

The mode shows up as each run's `isolation` (from the signer, never from the agent). So a system-mode signer with no
witness verifies as `Assurance: dev` with `isolation: separate-user`: the agent couldn't reach the keys, but nothing
outside the host shows the log wasn't rolled back. Add a witness the operator doesn't run to reach `witnessed`.

Every mode is checked the same way: `tracekit doctor` ([doctor](doctor.md)) lists each check with its fix and exits 0
(all ok), 1 (a check failed) or 2 (warnings only). Doctor output is advice about the host, not evidence.

## Laptop dev

For trying Tracekit and catching mistakes, not attacks. Prerequisites: Python 3.9+.

```sh
pip install tracekit-ai
tracekit up --wait                 # optional: the first client starts it anyway
tracekit init --dev --v2           # optional: wire Claude Code's hooks to it
tracekit doctor                    # dev profile: a same-user signer and no witness are warnings
```

Then follow a [framework quickstart](quickstart-v2.md) and export and verify a run:

```sh
tracekit signer trust -o trust.json
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json
```

- **Protects against:** mistakes, and an agent that follows its tools: the policy gate decides before each call, and
  every call is signed and chained by a process that holds the key.
- **Doesn't protect against:** an agent that runs commands as you. It can read the signer's key, stop the signer or
  rewrite its store ([what dev assurance means](quickstart-v2.md#what-dev-assurance-means)).
- **Bundles reach:** `Integrity: VERIFIED`, `Assurance: dev`, `isolation: same-user`, `approvals: self`. A witness
  in signer.yaml raises the assurance level, never the isolation.

## Laptop system mode

The signer runs as its own OS user from a root-owned install, so the agent's user can't reach its keys, store, policy
or approvals. Prerequisites: Linux with systemd (macOS: launchd, experimental, `--experimental-macos`), root, a
root-owned Python, and an agent user that is not root and not in a sudo, wheel, admin, docker or similar group.

```bash
sudo /usr/bin/python3 -m tracekit init --v2 --user AGENT --approver ADMIN \
    --harness claude=/usr/local/bin/claude [--policy /etc/tracekit/policy.yaml]
sudo tracekit doctor
```

What `init --v2` sets up ([system mode](quickstart-v2.md#system-mode-linux-macos-experimental) has the details):

- the root-owned venv `/opt/tracekit`, the `tracekit-signer` user and its 0700 data dir `/var/lib/tracekit-signer`,
  and the hardened `tracekit-signer` systemd unit (no capabilities, `ProtectSystem=strict`, a system-call filter);
- `/etc/tracekit/signer.yaml` (root-owned): AGENT's uid in its own tenant, approvals only from ADMIN's uid
  (self-approval refused), the policy;
- AGENT's v2 Claude Code hook, and `/etc/tracekit/client.json` naming the system socket, so dev auto-spawn is off and
  a `TRACEKIT_SIGNER` pointing elsewhere is refused;
- **harness binding** (`--harness [NAME=]PATH`, repeatable; the binary must be root-owned): the signer accepts a run
  from AGENT's uid only from below that program's process tree, attested by `tracekit-harness-helper`, a root service
  that holds only `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`. Without `--harness` there is no binding;
- the **transcript tailer**: the `tracekit-tailer` user reads AGENT's Claude Code transcripts through an ACL and
  reports them to the signer, which lets that uid make only `model_event`, `state_write`, `tailer_lost` and `status`
  calls. An edited, truncated or replaced transcript becomes a signed `tailer_lost` gap. When the ACL or the sudo rule
  can't be set up, init says so and each run records a `tailer_lost` gap instead.

Add witnesses on another host to signer.yaml (`witnesses:`, [witnesses](witnesses.md#v2-c2sp-tlog-witnesses)) and
restart the unit. Approve from ADMIN's account with `tracekit approvals list` and `tracekit approvals approve <id>`.
`sudo tracekit uninstall --v2` removes it (`--purge` also deletes the keys and log).

- **Protects against:** the agent's user reading or changing the keys, store, sequence numbers or policy, answering
  its own approvals, or pointing the hook at a decoy signer (A1, A2; `eval/e8_insider_v2.py` checks these as real
  users).
- **Doesn't protect against:** root on the machine (A4: a witness on another host is the defence), the agent removing
  the hook from its own `~/.claude/settings.json` or acting outside Claude Code (no record, no gap), or a same-user
  process that starts the registered harness itself ([what binding does not stop](faq.md#what-does-harness-binding-not-stop)).
- **Bundles reach:** `isolation: separate-user`, approvals by another user; `Assurance: dev` without a witness,
  `local` with your own, `witnessed` with an independent one.

## Container and Kubernetes sidecar

The [signer image](deploy-container.md) runs next to the agent in the same pod, as uid 10001. They share only the
socket directory; the agent is identified by its peer uid. Prerequisites: the image (built from
`deploy/docker/Dockerfile`, pinned by digest), Kubernetes 1.29+ for native sidecars, Helm 3, and a PVC whose root
uid 10001 can write.

```sh
docker build -f deploy/docker/Dockerfile -t tracekit-signer .
sh deploy/docker/smoke.sh                      # builds, runs, decides a call over the socket, runs doctor
helm install my-agent deploy/helm/tracekit-signer \
    --set agent.image=registry.example/agent@sha256:... \
    --set signer.image=ghcr.io/cygnux-labs/tracekit-signer@sha256:...
kubectl exec deploy/my-agent -c tracekit-signer -- tracekit doctor --config /etc/tracekit/signer.yaml
helm template my-agent deploy/helm/tracekit-signer --set agent.image=... --output-dir rendered
tracekit doctor --k8s --manifests rendered     # the pod's isolation, from the manifests
```

The chart's values, and what it refuses: [Kubernetes](deploy-kubernetes.md). Witnesses go in `signer.config`.
Export from inside the signer container (`tracekit export --v2 --config /etc/tracekit/signer.yaml ...`) and verify
anywhere else.

- **Protects against:** the agent's container reading or changing the signer's keys, log or config (S1, S2): they
  are on volumes only the signer mounts, and doctor's `D-K8S-*` checks flag a shared volume, a host path, a root
  container or cloud credentials in the pod.
- **Doesn't protect against:** whoever administers the node or the PVC (S3: a witness detects rollback), and keys
  in a cloud KMS: workload identity gives the pod's credentials to every container, the agent's too, so a KMS log key
  belongs to the central signer only.
- **Bundles reach:** `isolation: separate-user`; assurance from the witnesses in `signer.config`.

## Central

One signer serves many agents over HTTPS; agents set `TRACEKIT_SIGNER=https://signer.example:8443`. The chart in
`deploy/helm` renders the sidecar only: run the same image as your own Deployment (one replica per data volume; the
signer holds its storage lock) with the central config below. Prerequisites: a TLS certificate, an identity source
(Kubernetes TokenReview, a SPIFFE CA for mTLS, or named tokens), and optionally Postgres
(`storage: {postgres: {dsn_file}}`), an AWS KMS log key (`log_key: {aws_kms: {key_id, region}}`) and a
[record-key issuer](issuer.md).

```yaml
# signer.yaml: central, agents identified by their Kubernetes service account
data_dir: /var/lib/tracekit-signer
durability: ack-on-fsync
http:
  listen: 0.0.0.0:8443
  cert: /etc/tracekit/tls/tls.crt
  key: /etc/tracekit/tls/tls.key
  authenticators: [k8s_sa]
  k8s_sa:
    audience: tracekit-signer
    tokenreview: https://kubernetes.default.svc
    token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    ca: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
tenants: {"k8s_sa:system:serviceaccount:acme:*": acme}
authorize: {"k8s_sa:system:serviceaccount:acme:*": [register_run, decide, complete, close_run]}
metrics: {listen: 0.0.0.0:9464, allow_remote: true}
```

```sh
tracekit signer migrate --config signer.yaml   # with storage: postgres, create the tables first
tracekit doctor --config signer.yaml           # on the signer host; add --issuer-key KEY_ID with an issuer
tracekit signer serve --config signer.yaml
tracekit signer vkey --config signer.yaml > log.vkey   # pin it in trust configs; give it to the monitor's host
tracekit monitor --log http://signer.internal:9464 --log-key "$(cat log.vkey)" --state /var/lib/tracekit-monitor
```

Run the monitor on a host the operator doesn't control, with `serve_records: true` in `metrics` ([monitor](monitor.md)).

Remote agents outside Kubernetes use named tokens: [remote clients](remote-ingest.md). Metrics and alerts:
[observability](observability.md). Model calls through the [LLM gateway](gateway.md) and tool calls run by a T2
[executor](approvals.md#tiers-t1-and-t2-executors) are recorded out of the agent's process.

- **Protects against:** everything the sidecar does, plus a compromised agent writing another workload's runs (S5:
  identities, tenants and `authorize` come from the signer's config) and, with an independent witness and a monitor,
  the operator rewriting, forking or selectively exporting the log (S3, S4: detected, not prevented).
- **Doesn't protect against:** an operator with no independent witness or monitor (detection needs both), and the
  cloud provider (S6, out of scope).
- **Bundles reach:** `isolation: remote`; `witnessed` with an independent witness; `witnessed+monitored` with a
  pinned monitor's report (`tracekit verify --monitor-report`).

## Compose

A ready-made stack ships in `deploy/compose/` ([the compose stack](deploy-compose.md)). The layout below builds the
same idea by hand: the signer and the agent as separate services on a private network, the agent with a token and the
CA only.

```yaml
# signer.yaml: compose, agents identified by named tokens
data_dir: /var/lib/tracekit-signer
durability: ack-on-fsync
http:
  listen: 0.0.0.0:8443
  cert: /etc/tracekit/tls/tls.crt
  key: /etc/tracekit/tls/tls.key
  authenticators: [token]
  tokens: /var/lib/tracekit-signer/tokens.json
tenants: {"token:*": default}
authorize: {"token:*": [register_run, decide, complete, state_write, model_event, close_run, status]}
metrics: {listen: 127.0.0.1:9464}
```

```yaml
# compose.yaml
services:
  signer:
    image: tracekit-signer@sha256:...        # deploy/docker/Dockerfile
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - signer-data:/var/lib/tracekit-signer
      - ./signer.yaml:/etc/tracekit/signer.yaml:ro
      - ./tls:/etc/tracekit/tls:ro
    networks: [tracekit]
  agent:
    image: registry.example/agent@sha256:...
    user: "1000:1000"
    environment:
      TRACEKIT_SIGNER: https://signer:8443
      TRACEKIT_SIGNER_TOKEN_FILE: /run/secrets/tracekit-token
      TRACEKIT_SIGNER_CA: /run/secrets/signer-ca
    secrets: [tracekit-token, signer-ca]
    networks: [tracekit]
volumes:
  signer-data: {}
networks:
  tracekit: {internal: true}
secrets:
  tracekit-token: {file: ./agent.token}
  signer-ca: {file: ./tls/ca.pem}
```

```sh
docker compose run --rm --entrypoint tracekit signer signer token add agent --config /etc/tracekit/signer.yaml > agent.token
docker compose up -d
docker compose exec signer tracekit doctor --config /etc/tracekit/signer.yaml
```

The certificate must name `signer` (the service name the agent connects to) and be readable by uid 10001. Never
mount `signer-data`, `signer.yaml` or the TLS key into the agent. For Postgres, add a `postgres` service on the same
network and `storage: {postgres: {dsn_file: ...}}`; for witnesses, run [omniwitness or
litewitness](witnesses.md#v2-c2sp-tlog-witnesses) on another host, not in this compose project, or they vouch for
nothing beyond `local`.

- **Protects against:** the same as central, for the agents on this host.
- **Doesn't protect against:** whoever administers the Docker host (root on it is the operator).
- **Bundles reach:** `isolation: remote`; assurance from the witnesses you add.
