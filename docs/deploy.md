# Deploying the signer

One signer program, `tracekit signer serve`, runs in every mode. The agent's code doesn't change between modes:
`TRACEKIT_SIGNER` points it at the signer (a socket path, an `https://` URL, or `http://` on a loopback address for
the `insecure_loopback` listener), and without it the client starts a
dev signer of its own. What changes is **who can reach the signer's keys and store**, and that decides what a bundle
can prove.

| Mode | Platforms | Agent reaches the signer by | Who can reach the keys and store | Recorded `isolation` |
|---|---|---|---|---|
| [Laptop dev](#laptop-dev) | Linux, macOS, Windows | auto-spawned Unix socket (Windows: loopback TCP) | the agent's own user | `same-user` |
| [Laptop system mode](#laptop-system-mode) | Linux; macOS experimental | `/run/tracekit-signer/signer.sock` | root and the signer's OS user | `separate-user` |
| [Container sidecar](#container-and-kubernetes-sidecar) | Linux containers, Kubernetes 1.29+ | a socket in a shared directory | the signer's uid and whoever runs the node | `separate-user` |
| [Central](#central) | Linux containers | HTTPS (`k8s_sa`, `mtls` or `token` identity) | whoever administers the signer's host and storage | `remote` |
| [Compose by hand, over HTTPS](#compose) | Docker Compose | HTTPS on a private network | whoever administers the Docker host | `remote` |

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
outside the host shows the log wasn't rolled back. Add a witness the operator doesn't run to reach `witnessed`: your own or a partner's
([witnesses](witnesses.md)); the free [public witness](witnesses.md#the-public-witness) is not deployed yet.

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
root-owned Python 3.9+ with its `venv` module (Debian, Ubuntu: `sudo apt install python3-venv`), and an agent user
that is not root and not in a sudo, wheel, admin, docker or similar group.

Init runs from root's Python, so Tracekit must be installed there first. The package is `tracekit-ai`; `tracekit` on
PyPI is another project. Which way depends on `/usr/bin/python3 --version`. With Python 3.11 or later, install it
into `/opt/tracekit`, the root-owned venv that init builds anyway. Debian 12, Ubuntu 23.04 and later refuse
`sudo pip install` (PEP 668: `error: externally-managed-environment`), but pip installs into a venv:

```bash
sudo /usr/bin/python3 -m venv /opt/tracekit
sudo /opt/tracekit/bin/python -m pip install -U tracekit-ai
sudo /opt/tracekit/bin/python -I -m tracekit init --v2 --user AGENT --approver ADMIN \
    [--harness claude=/usr/local/bin/claude] [--policy /etc/tracekit/policy.yaml]
sudo /opt/tracekit/bin/python -I -m tracekit doctor
```

With Python 3.9 or 3.10 (Ubuntu 22.04, Debian 11, macOS's `/usr/bin/python3`), don't run init from that venv: it
fails and leaves a broken `/opt/tracekit` (`Too many levels of symbolic links`). Run init from the system Python
instead. These systems don't refuse `sudo pip`, so you can install Tracekit there. But that puts it and the packages
it needs (cryptography, regex, rfc8785, google-re2 on 3.10, and what they need) into the system Python, for every
program that uses it. Where your distribution ships one of them, as Ubuntu 22.04 ships python3-cryptography 3.4.8, pip
adds a newer copy that those programs then load instead. That can break programs written for the distribution's
version; PEP 668 is there to stop it.

```bash
sudo /usr/bin/python3 -m pip install -U tracekit-ai      # Debian, Ubuntu: sudo apt install python3-pip first
sudo /usr/bin/python3 -I -m tracekit init --v2 --user AGENT --approver ADMIN \
    [--harness claude=/usr/local/bin/claude] [--policy /etc/tracekit/policy.yaml]
sudo /opt/tracekit/bin/python -I -m tracekit doctor
```

To leave the system Python alone, run init from a root-owned clone of the release instead. `python3 -m` without `-I`
runs the copy in the current directory, and init builds `/opt/tracekit` from it:

```bash
# v1.5.0 is the latest release's tag. Debian, Ubuntu: sudo apt install git first
sudo git clone --depth 1 --branch v1.5.0 https://github.com/Cygnux-Labs/Tracekit /usr/local/src/tracekit-1.5.0
cd /usr/local/src/tracekit-1.5.0
sudo /usr/bin/python3 -m tracekit init --v2 --user AGENT --approver ADMIN \
    [--harness claude=/usr/local/bin/claude] [--policy /etc/tracekit/policy.yaml]
sudo /opt/tracekit/bin/python -I -m tracekit doctor
```

Each way, init then builds a fresh `/opt/tracekit` with the version it runs. Run every later `tracekit` command
through `/opt/tracekit/bin/python -I -m tracekit`, the copy the signer runs: init puts no `tracekit` command on root's
`PATH`. `-I` leaves the current directory out of the import path, so a Tracekit checkout you happen to be in is not
the code that runs.

What `init --v2` sets up ([system mode](quickstart-v2.md#system-mode-linux-macos-experimental) has the details):

- the root-owned venv `/opt/tracekit`, the `tracekit-signer` user and its 0700 data dir `/var/lib/tracekit-signer`,
  and the hardened `tracekit-signer` systemd unit (no capabilities, `ProtectSystem=strict`, a system-call filter);
- `/etc/tracekit/signer.yaml` (root-owned): AGENT's uid in its own tenant, approvals only from ADMIN's uid
  (self-approval refused), the policy;
- AGENT's v2 hook for the coding agent `--agent` names (default: Claude Code; none with `--no-hooks`), and
  `/etc/tracekit/client.json` naming the system socket, so dev auto-spawn is off and a `TRACEKIT_SIGNER` pointing
  elsewhere is refused;
- **harness binding**, only with `--harness [NAME=]PATH` (optional, repeatable; the binary must be root-owned): the
  signer accepts a run from AGENT's uid only from below that program's process tree, attested by
  `tracekit-harness-helper`, a root service that holds only `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`. Without
  `--harness` there is no binding and no helper. Init and doctor say nothing about it (v2 init doesn't look for the
  agent's CLI on `PATH`), and any process of AGENT's user can start a run;
- the **transcript tailer** (with `--agent claude`, the default, even with `--no-hooks`): the `tracekit-tailer` user
  reads AGENT's Claude Code transcripts (the session's and its subagents') through an ACL and reports them to the
  signer, which lets that uid make only `model_event`, `state_write`, `tailer_lost`, `tailer_heartbeat` and `status`
  calls. The Claude Code hook (init's or the plugin's) starts it for each session through a sudo rule
  (`/etc/sudoers.d/tracekit-tailer`). An edited, truncated or replaced transcript, or a tailer that stops its
  heartbeats while the run is open (killed), becomes a signed `tailer_lost` gap. When the ACL or the sudo rule can't
  be set up, init says so and each Claude Code session's run records a `tailer_lost` gap instead.

An agent that runs through the SDK, such as a daemon that calls `tracekit.instrument()`, needs no hook: add
`--no-hooks`. Another coding agent gets its own hook with `--agent` (`codex`, `cursor`, `gemini`, `opencode`, `goose`,
`qwen`, `droid`, `antigravity`; [coding agents](coding-agents.md)). The SDK finds the system signer through
`/etc/tracekit/client.json`. Init still sets up the tailer's user, ACL and sudo rule, but only the Claude Code hook
starts the tailer, so the SDK's runs record no `tailer_lost` gap. Doctor's `D-HOOKS-PRESENT` check warns `no hooks
recorded in client.json`; that is expected.

Add witnesses on another host to signer.yaml (`witnesses:`, [witnesses](witnesses.md#v2-c2sp-tlog-witnesses)) and
restart the unit. Approve from ADMIN's account with `/opt/tracekit/bin/python -I -m tracekit approvals list` and
`/opt/tracekit/bin/python -I -m tracekit approvals approve <id>`.
`sudo /opt/tracekit/bin/python -I -m tracekit uninstall --v2` removes it (`--purge` also deletes the keys and log).
On the system-pip route, `sudo /usr/bin/python3 -m pip uninstall tracekit-ai` removes the system copy (pip leaves its
dependencies); on the clone route, delete the clone.

Each init run writes `/etc/tracekit/signer.yaml` again from its flags. It drops anything you added by hand, such as
`witnesses:` or `content:` (without `content:`, new runs keep no content), and doesn't say so. To upgrade:

1. Stop the signer: `sudo systemctl stop tracekit-signer` (with `--harness` also `tracekit-harness-helper`, with
   `--egress` also `tracekit-egress`). Until init starts it again, AGENT's tool calls are blocked.
2. Keep a copy of the config: `sudo cp /etc/tracekit/signer.yaml /root/signer.yaml.bak`.
3. Run the same commands again, with the same init flags. `-U` installs the newer version; on the clone route, clone
   the new release's tag into a new directory.
4. Add your lines back to `/etc/tracekit/signer.yaml`, then `sudo systemctl restart tracekit-signer`, and
   `tracekit-harness-helper` / `tracekit-egress` if you use them. A run that starts before this keeps no content.

Export and the trust config read the signer's data dir, which only root and the signer's user can open. So AGENT
can't export its own runs; only root can. Export as root, and name AGENT's tenant: init puts AGENT's runs in a tenant
named after the user, and without `--tenant` export looks in `local` (`no run '...' of tenant 'local' in the store`).

```bash
sudo /opt/tracekit/bin/python -I -m tracekit signer trust --config /etc/tracekit/signer.yaml -o trust.json
sudo /opt/tracekit/bin/python -I -m tracekit export --v2 --config /etc/tracekit/signer.yaml --tenant AGENT \
    --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json      # anyone, on any machine: no access to this host needed
```

Running export as root leaves no root-owned files in the store: it opens the store read-only.

- **Protects against:** the agent's user reading or changing the keys, store, sequence numbers or policy, answering
  its own approvals, or pointing the hook at a decoy signer (A1, A2; `eval/e8_insider_v2.py` checks these as real
  users).
- **Doesn't protect against:** root on the machine (A4: a witness on another host is the defence), the agent removing
  the hook from its own settings (`~/.claude/settings.json` for Claude Code) or acting outside the hook or the SDK (no
  record, no gap), or a same-user process that starts the registered harness itself
  ([what binding does not stop](faq.md#what-does-harness-binding-not-stop)).
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
authorize: {"k8s_sa:system:serviceaccount:acme:*": [register_run, decide, approval_consume, complete, close_run,
                                                    model_event, approval_request, approval_wait, status]}
# + approval_list for the TypeScript OpenAI Agents and Vercel AI adapters
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
authorize: {"token:*": [register_run, decide, approval_consume, complete, close_run, model_event, approval_request, approval_wait,
                       state_write, status, observe, constraint_add]}   # observe, constraint_add: the coding-agent hooks
# + approval_list for the TypeScript OpenAI Agents and Vercel AI adapters
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

## Keeping content for investigations

Records hold commitments only. To replay runs later (`tracekit why`), turn on the signer's
[content vault](privacy.md#the-content-vault) in any of the setups above:

```yaml
# signer.yaml (Helm: signer.content; compose: the content line tracekit deploy compose writes)
data_dir: /var/lib/tracekit-signer
content: {retain: true, retention_days: 30, max_record_bytes: 1048576}
authorize: {"mtls:spiffe://acme/investigator": [content_read, status]}   # who may read it: never an agent
```

On Postgres, run `tracekit signer migrate --config signer.yaml` first: the vault adds two tables (schema version 2),
and a signer with the vault on refuses to start on an older store ([upgrading](#upgrading)).
`migrate` grants nothing: on an existing database, apply `tracekit.storage.postgres.GRANTS` to the signer's role
again after it, or every item reads back `not_retained` and the signer logs the failed write.

Key handling: the signer creates `keys/content.key` on its first start with the vault on, 0600 and owned by the
signer's user, next to its other keys. Back it up with them: without it the vault can't be read, and a restored
backup of the vault needs the key it was written under. Deleting it destroys every retained item at once. The vault
stays readable and erasable while the key exists, even after you turn `retain` off. `tracekit doctor` reports the
vault's state, its retention and whether the key is readable only by the signer (`D-CONTENT-VAULT`). Each read is a
signed `content.accessed` record and each erasure a `content.erased` record, in the tenant's `tracekit/signer` run.

Erasure reaches the live store only: a backup, WAL archive or replica taken before it still holds the run's wrapped key
and blobs, and opens with `keys/content.key`. Keep those shorter than `retention_days`
([limits](limits.md#content-vault-11)).

## Upgrading

Stop the signer, install the new version and start it again; records, keys and bundles carry over. A Postgres store
keeps its schema version until you run `tracekit signer migrate`, and a new version runs on the older schema as long
as it needs nothing the schema lacks:

- **1.1** adds the content vault's tables (schema version 2). A version 1 store keeps working for a signer with
  `content.retain` off and for every reader (export, view, reveal, the central viewer). Before turning the vault on,
  run `tracekit signer migrate --config signer.yaml` as the migration role, then apply
  `tracekit.storage.postgres.GRANTS` to the signer's role again. A signer with the vault on refuses to start on a
  version 1 store, with an error that names `tracekit signer migrate`.
- **1.3** speaks signer protocol 17. A 1.3 signer serves clients and gateways of 1.2 and 1.3, but a 1.3 client or
  gateway refuses a 1.2 signer: upgrade the signer first, then the agents' Tracekit and the gateway. A bundle that
  holds a `reconcile.result_mismatch` record (verified tool results) needs a 1.3 verifier; every other bundle verifies
  with 1.2 too. A same-user dev signer from 1.2 is replaced by the first 1.3 client that finds it.
- **1.4** speaks signer protocol 19. A 1.4 signer serves clients and gateways from protocol 15 up (1.2 and 1.3
  included), but a 1.4 client or gateway refuses a 1.3 signer: upgrade the signer first. A bundle whose records use
  1.4's additions (live constraints, signed findings that cite records, kernel sensor or OpenShell effects, `said_only`
  model messages, the `ext` slot), or that holds a run exported in parts (past 64 MiB of records), needs a 1.4 verifier; an older one reports it `UNVERIFIABLE (needs tracekit >=
  1.4.0)`. A same-user dev signer from 1.3 is replaced by the first 1.4 client that finds it. The store's schema is
  unchanged.
- **1.5** speaks signer protocol 20. A 1.5 signer serves clients and gateways from protocol 15 up (1.2 to 1.4
  included), but a 1.5 client or gateway refuses a 1.4 signer: upgrade the signer first. Bundles are unchanged: a 1.4
  verifier reads them. A same-user dev signer from 1.4 is replaced by the first 1.5 client that finds it. The store's
  schema is unchanged.

Helm (`tracekit-central`): migrate each replica's schema before upgrading the release with `signer.content.retain`
set. Compose: the stack's init script runs only on an empty database, so on an existing stack run
`docker compose exec signer tracekit signer migrate --config /etc/tracekit/signer.yaml` with a DSN that may create
tables.
